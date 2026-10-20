// SPDX-License-Identifier: MIT
#ifndef VEIL_VIDEO_FRAME_BUDGET_H_
#define VEIL_VIDEO_FRAME_BUDGET_H_

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>
#include "veil_diag_log.h"

namespace veil_media {

// The low-rate fallback controls average bits/s, but a VP8 keyframe may spend
// several frames' credit. Pacing that frame's fragments into a whole-frame SDK
// ingress can then exceed its 200 ms oldest-fragment lifetime. Request fewer
// source pixels after an actual encoded overshoot. Never discard an encoded
// reference frame here, extend its lifetime, or alter audio/transport budgets.
class VideoFrameBudget {
 public:
  VideoFrameBudget() : trace_enabled_(diag::enabled()),
      trace_id_(trace_enabled_ ? ++next_trace_id_ : 0) {
    if (trace_enabled_) images_.reserve(kImageLimit);
  }
  // The owner stops its encoder/source before releasing their shared budget.
  // Only teardown writes these opt-in metadata rows; Encode never does I/O.
  ~VideoFrameBudget() {
    if (!trace_enabled_) return;
    const auto* path = diag::path();
    if (!path) return;
    std::lock_guard lock(mu_);
    FILE* file = std::fopen(path, "a");
    if (!file) return;
    std::fprintf(file, "video.frame_budget.begin id=%llu count=%zu seen=%llu\n",
        (unsigned long long)trace_id_, images_.size(), (unsigned long long)images_seen_);
    for (const auto& r : images_)
      std::fprintf(file,
          "video.frame_budget.image id=%llu timestamp=%u at_us=%lld bytes=%zu width=%u height=%u budget=%zu cap_before=%d cap_after=%d rate_bps=%u\n",
          (unsigned long long)trace_id_, r.timestamp, (long long)r.at_us, r.bytes,
          r.width, r.height, r.budget, r.before, r.after, r.rate);
    const bool ok = std::fflush(file) == 0 && !std::ferror(file);
    std::fprintf(file, "video.frame_budget.end id=%llu write_ok=%d\n",
        (unsigned long long)trace_id_, int(ok));
    std::fclose(file);
  }
  struct Snapshot {
    size_t bytes;
    int max_pixels;
    uint64_t oversize_frames;
    int last_pixels;
    size_t last_bytes;
    int audio_state;
    uint64_t audio_cuts;
    uint64_t audio_recoveries;
    uint64_t growth_holds;
  };

  // Local measured audio feedback: -1 unknown, 0 healthy, 1 pressured.
  // No worker invocation or network work: safe while video is stalled.
  void SetAudioPressure(int state, int64_t at_us) {
    if (state < -1 || state > 1 || at_us <= 0) return;
    std::lock_guard lock(mu_);
    FinishGrowthHold(at_us);
    ApplyAudioPressure(state, at_us);
  }

  // Known current health with a separate original hold deadline. Receipt
  // freezes achieved recovery; neither samples nor frames bank growth here.
  void HoldGrowth(int64_t sampled_us, int64_t until_us, int64_t received_us) {
    if (sampled_us <= 0 || sampled_us > received_us || until_us <= received_us ||
        until_us - received_us > kFeedbackLifetimeUs) return;
    std::lock_guard lock(mu_);
    FinishGrowthHold(received_us);
    if (!growth_held_since_us_) growth_held_since_us_ = received_us;
    if (until_us > growth_hold_until_us_) ++growth_holds_;
    growth_hold_until_us_ = std::max(growth_hold_until_us_, until_us);
    ApplyAudioPressure(0, sampled_us);
  }

  void SetProfile(int selected_bps) {
    std::lock_guard lock(mu_);
    selected_bps_ = selected_bps;
    // Either the selected profile or an actual low encoder allocation needs
    // bounded frames. A large requested profile is not proof that the video
    // controller can fund its keyframes. The host still owns bitrate and fps.
    if (!enabled()) {
      if (!audio_feedback_enabled_) max_pixels_ = 0;
      bytes_ = 0;
    } else {
      UpdateBytes();
    }
  }

  void SetRate(uint32_t payload_bps) {
    std::lock_guard lock(mu_);
    // A suspended encoder emits no frames. Preserve its last positive budget
    // rather than reopening a large keyframe window when capture resumes.
    if (payload_bps) payload_bps_ = payload_bps;
    UpdateBytes();
  }

  void SetPacketPayload(size_t max_payload) {
    std::lock_guard lock(mu_);
    // InitEncode gets the stream's RTP payload ceiling after header reserve.
    // Leave room for VP8 descriptors/packetizer reductions; a one-packet frame
    // has no first-to-marker assembly wait, even at the slowest pacing rate.
    single_packet_bytes_ = max_payload > 64 ? max_payload - 64 : 1;
    UpdateBytes();
  }

  void Observe(size_t bytes, uint32_t width, uint32_t height,
               uint32_t timestamp = 0, int64_t at_us = 0) {
    if (!bytes || !width || !height || width > 4096 || height > 4096) return;
    std::lock_guard lock(mu_);
    last_pixels_ = static_cast<int>(uint64_t(width) * height);
    largest_pixels_ = std::max(largest_pixels_, last_pixels_);
    ++encoded_frames_;
    last_encoded_us_ = std::max(last_encoded_us_, at_us);
    last_bytes_ = bytes;
    FinishGrowthHold(at_us);
    const int before = max_pixels_;
    if (audio_state_ == 1 && FreshAudio(at_us)) CutForAudio(at_us);
    if (enabled() && bytes > bytes_) ++oversize_frames_;
    if (ShouldContract(bytes, at_us)) {
      const uint64_t pixels = uint64_t(width) * height;
      // Scale pixel area from the actual encoded result, retaining margin for
      // the keyframe caused by resizing. In-flight frames at the old resolution
      // recompute the same bound, rather than multiplying it down repeatedly.
      const int desired = static_cast<int>(std::max<uint64_t>(
          6144, pixels * bytes_ / bytes * 3 / 4));
      if (desired < static_cast<int>(pixels) &&
          (!max_pixels_ || desired < max_pixels_)) max_pixels_ = desired;
    }
    if (trace_enabled_) {
      ++images_seen_;
      if (images_.size() < kImageLimit)
        images_.push_back({timestamp, at_us, bytes, width, height, bytes_,
                           before, max_pixels_, effective_rate()});
    }
  }

  Snapshot snapshot() const {
    std::lock_guard lock(mu_);
    return {bytes_, max_pixels_, oversize_frames_, last_pixels_, last_bytes_,
            audio_state_, audio_cuts_, audio_recoveries_, growth_holds_};
  }

 private:
  void FinishGrowthHold(int64_t at_us) {
    if (!growth_held_since_us_ || at_us < growth_hold_until_us_) return;
    if (healthy_since_us_) {
      healthy_since_us_ += std::max<int64_t>(0,
          growth_hold_until_us_ - std::max(growth_held_since_us_, healthy_since_us_));
    }
    growth_held_since_us_ = 0;
    growth_hold_until_us_ = 0;
  }
  void ApplyAudioPressure(int state, int64_t at_us) {
    audio_feedback_enabled_ = true;
    if (at_us <= audio_feedback_us_) return;
    if (at_us - audio_feedback_us_ >= kFeedbackLifetimeUs || state != 0 ||
        audio_state_ != 0) {
      healthy_since_us_ = 0;
      healthy_samples_ = 0;
    }
    audio_state_ = state;
    audio_feedback_us_ = at_us;
    if (state == 1) {
      CutForAudio(at_us);
    } else if (state == 0) {
      // Healthy audio alone must not bank pixel probes while video is paused.
      if (!last_encoded_us_ || at_us < last_encoded_us_ ||
          at_us - last_encoded_us_ >= kFeedbackLifetimeUs) {
        healthy_since_us_ = 0;
        healthy_samples_ = 0;
        return;
      }
      if (growth_held_since_us_) return;
      if (encoded_frames_ == last_healthy_frame_) return;
      last_healthy_frame_ = encoded_frames_;
      if (!healthy_since_us_) healthy_since_us_ = at_us;
      ++healthy_samples_;
      if (healthy_samples_ >= 4 && at_us - healthy_since_us_ >= 3'000'000) {
        if (max_pixels_ > 0 && largest_pixels_ > max_pixels_) {
          max_pixels_ = std::min(largest_pixels_, max_pixels_ + max_pixels_ / 4);
          if (max_pixels_ == largest_pixels_) max_pixels_ = 0;
          ++audio_recoveries_;
        }
        healthy_since_us_ = at_us;
        healthy_samples_ = 0;
      }
    }
  }
  uint32_t effective_rate() const {
    if (selected_bps_ <= 0) return 0;
    return payload_bps_ ? std::min<uint32_t>(payload_bps_, selected_bps_)
                        : static_cast<uint32_t>(selected_bps_);
  }
  bool enabled() const { return effective_rate() > 0 && effective_rate() <= 30000; }
  bool FreshAudio(int64_t at_us) const {
    return audio_feedback_enabled_ && at_us >= audio_feedback_us_ &&
        at_us - audio_feedback_us_ < kFeedbackLifetimeUs;
  }
  void CutForAudio(int64_t at_us) {
    if (last_pixels_ <= 6144 ||
        (last_audio_cut_us_ && at_us - last_audio_cut_us_ < 3'000'000)) return;
    const int desired = std::max(6144, last_pixels_ / 2);
    if (!max_pixels_ || desired < max_pixels_) {
      max_pixels_ = desired;
      last_audio_cut_us_ = at_us;
      ++audio_cuts_;
    }
  }
  bool ShouldContract(size_t bytes, int64_t at_us) {
    if (!enabled() || bytes <= bytes_) {
      oversize_since_us_ = 0;
      oversize_samples_ = 0;
      last_observed_us_ = std::max(last_observed_us_, at_us);
      return false;
    }
    // Legacy/unknown/impaired audio keeps its existing protection. A fresh
    // healthy report lets one moderately oversized keyframe pass without
    // pinning the camera to a tiny source for the rest of the call.
    if (audio_state_ != 0 || !FreshAudio(at_us) || bytes >= bytes_ * 4 || at_us <= 0)
      return true;
    if (at_us <= last_observed_us_) return false;
    if (bytes_ != observed_budget_ ||
        (last_observed_us_ && at_us - last_observed_us_ >= 6'000'000)) {
      oversize_since_us_ = 0;
      oversize_samples_ = 0;
    }
    observed_budget_ = bytes_;
    last_observed_us_ = at_us;
    if (!oversize_since_us_) oversize_since_us_ = at_us;
    ++oversize_samples_;
    return oversize_samples_ >= 3 && at_us - oversize_since_us_ >= 3'000'000;
  }
  void UpdateBytes() {
    if (!enabled()) {
      bytes_ = 0;
      // Recover source resolution even if the host is already at its maximum
      // profile and cannot select a larger one. Require twice the low-rate
      // threshold to avoid resizing on every small allocation fluctuation.
      if (!audio_feedback_enabled_ && effective_rate() >= 60000) max_pixels_ = 0;
      return;
    }
    const uint32_t rate = effective_rate();
    // Existing video pacing factor 4 x 100 ms leaves half the SDK's lifetime
    // for scheduling, IPC and admission. This is an encoder sizing hint, not a
    // new admission cap or a guarantee that a codec can always meet it.
    bytes_ = std::max(single_packet_bytes_, size_t(rate) / 20);
  }

  mutable std::mutex mu_;
  int selected_bps_ = 0;
  uint32_t payload_bps_ = 0;
  size_t single_packet_bytes_ = 1;
  size_t bytes_ = 0;
  int max_pixels_ = 0;
  uint64_t oversize_frames_ = 0;
  int last_pixels_ = 0;
  int largest_pixels_ = 0;
  size_t last_bytes_ = 0;
  static constexpr int64_t kFeedbackLifetimeUs = 3'000'000;
  bool audio_feedback_enabled_ = false;
  int audio_state_ = -1;
  int64_t audio_feedback_us_ = 0, last_audio_cut_us_ = 0;
  int64_t healthy_since_us_ = 0;
  unsigned healthy_samples_ = 0;
  uint64_t audio_cuts_ = 0, audio_recoveries_ = 0;
  int64_t growth_held_since_us_ = 0, growth_hold_until_us_ = 0;
  uint64_t growth_holds_ = 0;
  int64_t last_encoded_us_ = 0;
  uint64_t encoded_frames_ = 0, last_healthy_frame_ = 0;
  int64_t last_observed_us_ = 0, oversize_since_us_ = 0;
  size_t observed_budget_ = 0;
  unsigned oversize_samples_ = 0;
  struct Image {
    uint32_t timestamp;
    int64_t at_us;
    size_t bytes;
    uint32_t width, height;
    size_t budget;
    int before, after;
    uint32_t rate;
  };
  static constexpr size_t kImageLimit = 8192;
  inline static std::atomic<uint64_t> next_trace_id_{0};
  const bool trace_enabled_;
  const uint64_t trace_id_;
  uint64_t images_seen_ = 0;
  std::vector<Image> images_;
};

}  // namespace veil_media
#endif
