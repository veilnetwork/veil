// SPDX-License-Identifier: MIT
#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <optional>

namespace veil_media {
// Serialized by the owning NetEq caller. All clocks are local monotonic time;
// the sender contributes only its Opus RTP clock. No allocation or wire data.
// A recent arrival floor removes constant path delay and clock offset.
// Age still includes upstream excess delay, unlike NetEq's storage size. It is
// not absolute one-way latency, an available-capacity estimate or a trim limit.
class AudioRtpLag {
 public:
  void Reset() { *this = AudioRtpLag(); }

  bool Packet(uint32_t ssrc, uint32_t stamp, int64_t now_us,
              std::optional<uint16_t> sequence = std::nullopt) {
    if (!ssrc || now_us <= 0) { Reset(); return true; }
    const bool sequence_known = sequence && sequence_;
    const int16_t sequence_step = sequence_known
        ? static_cast<int16_t>(*sequence - *sequence_) : 0;
    bool restarted = false, advances_clock = false;
    int64_t supported_floor_us = INT64_MAX;
    if (!ssrc_ || ssrc != ssrc_ || now_us < last_evidence_us_ ||
        now_us - last_evidence_us_ > kHistoryUs ||
        std::abs(sequence_step) > 128) {
      Reset();
      restarted = true;
      advances_clock = true;
      ssrc_ = ssrc;
      anchor_stamp_ = stamp;
      anchor_us_ = first_us_ = now_us;
      distinct_packets_ = 1;
    } else {
      const int32_t delta = static_cast<int32_t>(stamp - anchor_stamp_);
      // A queued packet from before a backwards clock reset can have a
      // higher timestamp. Its older sequence must not advance the new clock.
      if (delta > 0 && sequence_known && sequence_step <= 0) return false;
      // A clock restart or a wildly discontinuous timestamp must not turn a
      // previous stream's floor into invented congestion. An Opus packet
      // with a newer sequence and an older timestamp has reset its clock.
      if ((delta < 0 && sequence_step > 0) || delta < -5 * kHz ||
          (delta > 0 && std::llabs(TickUs(delta) - (now_us-anchor_us_)) > 5'000'000)) {
        Reset();
        Packet(ssrc, stamp, now_us, sequence);
        return true;
      }
      if (delta > 0) {
        const int64_t media_step_us = TickUs(delta);
        const int64_t arrival_step_us = now_us - anchor_us_;
        const int64_t previous_intercept = anchor_us_ - TickUs(anchor_ticks_);
        anchor_ticks_ += delta;
        // A dispatch batch or a stalled receive clock can tag RTP packets
        // several media intervals apart with nearly the same receipt time.
        // Lower the floor only to a value supported by two advancing
        // arrivals with time between them on the receive clock.
        if (arrival_step_us > 0 &&
            arrival_step_us >= (media_step_us + 1) / 2) {
          supported_floor_us = std::max(previous_intercept,
                                        now_us - TickUs(anchor_ticks_));
        }
        anchor_stamp_ = stamp;
        anchor_us_ = now_us;
        ++distinct_packets_;
        advances_clock = true;
      }
    }
    const bool fills_sequence_gap = ObserveSequence(sequence, sequence_step);
    const int32_t delta = static_cast<int32_t>(stamp - anchor_stamp_);
    const bool recent_reorder = fills_sequence_gap && delta < 0 &&
        delta >= -kReorderSpanMs * kHz && now_us - anchor_us_ <= kReorderSpanMs * 1000;
    // Only advancing media or a first arrival within the reorder window can
    // keep the arrival clock fresh. Duplicates otherwise extend an RTP age
    // estimate even though the receiver has stopped getting new speech.
    if (!advances_clock && !recent_reorder) return restarted;
    last_evidence_us_ = now_us;
    const int64_t intercept = now_us - TickUs(anchor_ticks_ + delta);
    const int64_t epoch = now_us / kBucketUs;
    auto& bucket = buckets_[epoch % buckets_.size()];
    if (bucket.epoch != epoch) bucket = {epoch, intercept};
    else bucket.minimum_us = std::min(bucket.minimum_us, intercept);
    bucket.maximum_us = std::max(bucket.maximum_us, intercept);
    bucket.supported_floor_us = std::min(bucket.supported_floor_us,
                                         supported_floor_us);
    return restarted;
  }

  // Preserve real arrival variation before dropping decoded audio. Use a
  // short window so a single burst cannot lengthen later catch-up. Ordered
  // packets and first arrivals that fill a recent sequence gap are evidence.
  // Duplicates and packets from before the observed stream never renew it.
  int RecentArrivalVariationMs(int64_t now_us) const {
    if (distinct_packets_ < 3 || now_us < last_evidence_us_) return 0;
    const int64_t epoch = now_us / kBucketUs;
    int64_t earliest = INT64_MAX, latest = INT64_MIN;
    for (int64_t back = 0; back < 4 && back <= epoch; ++back) {
      const auto& bucket = buckets_[(epoch - back) % buckets_.size()];
      if (bucket.epoch != epoch - back || bucket.maximum_us == INT64_MIN)
        continue;
      earliest = std::min(earliest, bucket.minimum_us);
      latest = std::max(latest, bucket.maximum_us);
    }
    return latest > earliest
        ? static_cast<int>(std::min<int64_t>(60000, (latest - earliest) / 1000))
        : 0;
  }

  bool MatchesPacket(uint32_t ssrc, uint32_t stamp, uint16_t sequence) const {
    if (ssrc != ssrc_ || !sequence_) return false;
    const int16_t step = static_cast<int16_t>(sequence - *sequence_);
    return step <= 0 && step >= -128 &&
        std::llabs(static_cast<int32_t>(stamp - anchor_stamp_)) <= 5 * kHz;
  }

  std::optional<int> Output(uint32_t stamp, int64_t now_us,
                            int* arrival_excess_ms = nullptr) const {
    if (arrival_excess_ms) *arrival_excess_ms = -1;
    if (!ssrc_ || distinct_packets_ < 3 || now_us < last_evidence_us_ ||
        now_us - last_evidence_us_ > 3'000'000 || now_us - first_us_ < 100'000)
      return std::nullopt;
    const int64_t epoch = now_us / kBucketUs;
    int64_t raw_floor_us = INT64_MAX;
    int64_t supported_floor_us = INT64_MAX;
    for (const auto& bucket : buckets_) {
      if (bucket.epoch < 0 || bucket.epoch > epoch ||
          epoch - bucket.epoch >= static_cast<int64_t>(buckets_.size())) {
        continue;
      }
      raw_floor_us = std::min(raw_floor_us, bucket.minimum_us);
      supported_floor_us = std::min(supported_floor_us,
                                    bucket.supported_floor_us);
    }
    // Sparse or wholly batched input can have only raw observations.
    const int64_t floor_us =
        supported_floor_us == INT64_MAX ? raw_floor_us : supported_floor_us;
    if (floor_us == INT64_MAX) return std::nullopt;
    const int32_t delta = static_cast<int32_t>(stamp - anchor_stamp_);
    if (delta > kHz || delta < -60 * kHz) return std::nullopt;
    const int64_t age_us = now_us - TickUs(anchor_ticks_ + delta) - floor_us;
    if (age_us < 0) return std::nullopt;
    if (arrival_excess_ms) {
      // Compare the latest advancing packet's arrival with the same arrival
      // floor. The remainder is media distance to that packet plus time
      // since its arrival, not a direct wall-time measurement of the queue.
      const int64_t excess_us = anchor_us_ - TickUs(anchor_ticks_) - floor_us;
      if (excess_us >= 0 && excess_us <= age_us) {
        *arrival_excess_ms = static_cast<int>(
            std::min<int64_t>(60000, excess_us / 1000));
      }
    }
    return static_cast<int>(std::min<int64_t>(60000, age_us / 1000));
  }

 private:
  static constexpr int kHz = 48000;  // Opus RTP clock, independent of decoder output rate.
  static constexpr int kSequenceWindow = 32;
  static constexpr int kReorderSpanMs = 500;
  static constexpr int64_t kBucketUs = 500'000, kHistoryUs = 30'000'000;
  bool ObserveSequence(std::optional<uint16_t> sequence, int16_t step) {
    if (!sequence) return false;
    if (!sequence_) {
      sequence_ = sequence;
    } else if (step > 0) {
      sequence_window_ = step < kSequenceWindow ? (sequence_window_ << step) | 1u : 1u;
      sequence_ = sequence;
    } else if (step < 0 && -step < kSequenceWindow) {
      const uint32_t bit = uint32_t{1} << -step;
      const bool first = (sequence_window_ & bit) == 0;
      sequence_window_ |= bit;
      return first;
    }
    return false;
  }
  static int64_t TickUs(int64_t ticks) {
    return (ticks / kHz) * 1'000'000 + (ticks % kHz) * 1'000'000 / kHz;
  }
  struct Bucket {
    int64_t epoch = -1;
    int64_t minimum_us = 0;
    int64_t maximum_us = INT64_MIN;
    int64_t supported_floor_us = INT64_MAX;
  };
  std::array<Bucket, 60> buckets_{};
  uint32_t ssrc_ = 0, anchor_stamp_ = 0;
  int64_t anchor_ticks_ = 0, anchor_us_ = 0, first_us_ = 0, last_evidence_us_ = 0;
  uint64_t distinct_packets_ = 0;
  std::optional<uint16_t> sequence_;
  // Mark pre-observation sequence numbers as unavailable until replaced by
  // an observed advance. Zero bits identify holes in this stream's history.
  uint32_t sequence_window_ = UINT32_MAX;
};
}  // namespace veil_media
