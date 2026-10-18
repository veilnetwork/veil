// SPDX-License-Identifier: MIT
#ifndef VEIL_VIDEO_FRAME_BUDGET_H_
#define VEIL_VIDEO_FRAME_BUDGET_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace veil_media {

// The low-rate fallback controls average bits/s, but a VP8 keyframe may spend
// several frames' credit. Pacing that frame's fragments into a whole-frame SDK
// ingress can then exceed its 200 ms oldest-fragment lifetime. Request fewer
// source pixels after an actual encoded overshoot. Never discard an encoded
// reference frame here, extend its lifetime, or alter audio/transport budgets.
class VideoFrameBudget {
 public:
  struct Snapshot {
    size_t bytes;
    int max_pixels;
    uint64_t oversize_frames;
    int last_pixels;
    size_t last_bytes;
  };

  void SetProfile(int selected_bps) {
    std::lock_guard lock(mu_);
    selected_bps_ = selected_bps;
    // Either the selected profile or an actual low encoder allocation needs
    // bounded frames. A large requested profile is not proof that the video
    // controller can fund its keyframes. The host still owns bitrate and fps.
    if (!enabled()) {
      max_pixels_ = 0;
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

  void Observe(size_t bytes, uint32_t width, uint32_t height) {
    if (!bytes || !width || !height || width > 4096 || height > 4096) return;
    std::lock_guard lock(mu_);
    last_pixels_ = static_cast<int>(uint64_t(width) * height);
    last_bytes_ = bytes;
    if (!enabled() || bytes <= bytes_) return;
    ++oversize_frames_;
    const uint64_t pixels = uint64_t(width) * height;
    // Scale pixel area from the actual encoded result, retaining margin for
    // the keyframe caused by resizing. In-flight frames at the old resolution
    // recompute the same bound, rather than multiplying it down repeatedly.
    const int desired = static_cast<int>(std::max<uint64_t>(
        6144, pixels * bytes_ / bytes * 3 / 4));
    if (desired < static_cast<int>(pixels) &&
        (!max_pixels_ || desired < max_pixels_)) max_pixels_ = desired;
  }

  Snapshot snapshot() const {
    std::lock_guard lock(mu_);
    return {bytes_, max_pixels_, oversize_frames_, last_pixels_, last_bytes_};
  }

 private:
  uint32_t effective_rate() const {
    if (selected_bps_ <= 0) return 0;
    return payload_bps_ ? std::min<uint32_t>(payload_bps_, selected_bps_)
                        : static_cast<uint32_t>(selected_bps_);
  }
  bool enabled() const { return effective_rate() > 0 && effective_rate() <= 30000; }
  void UpdateBytes() {
    if (!enabled()) {
      bytes_ = 0;
      // Recover source resolution even if the host is already at its maximum
      // profile and cannot select a larger one. Require twice the low-rate
      // threshold to avoid resizing on every small allocation fluctuation.
      if (effective_rate() >= 60000) max_pixels_ = 0;
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
  size_t last_bytes_ = 0;
};

}  // namespace veil_media
#endif
