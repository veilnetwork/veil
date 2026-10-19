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
// The recent minimum arrival intercept removes constant path delay/clock offset.
// Age still includes upstream excess delay, unlike NetEq's storage size. It is
// not absolute one-way latency, an available-capacity estimate or a trim limit.
class AudioRtpLag {
 public:
  void Reset() { *this = AudioRtpLag(); }

  bool Packet(uint32_t ssrc, uint32_t stamp, int64_t now_us,
              std::optional<uint16_t> sequence = std::nullopt) {
    if (!ssrc || now_us <= 0) { Reset(); return true; }
    bool restarted = false;
    if (!ssrc_ || ssrc != ssrc_ || now_us < last_seen_us_ ||
        now_us - last_seen_us_ > kHistoryUs ||
        (sequence && sequence_ &&
         std::abs(static_cast<int16_t>(*sequence - *sequence_)) > 128)) {
      Reset();
      restarted = true;
      ssrc_ = ssrc;
      anchor_stamp_ = stamp;
      anchor_us_ = first_us_ = now_us;
      distinct_packets_ = 1;
    } else {
      const int32_t delta = static_cast<int32_t>(stamp - anchor_stamp_);
      // A clock restart or a wildly discontinuous timestamp must not turn a
      // previous stream's floor into invented congestion. Reorder is retained;
      // old duplicates do not advance the clock or warm up a new baseline.
      if (delta < -5 * kHz ||
          (delta > 0 && std::llabs(TickUs(delta) - (now_us-anchor_us_)) > 5'000'000)) {
        Reset();
        Packet(ssrc, stamp, now_us, sequence);
        return true;
      }
      if (delta > 0) {
        anchor_ticks_ += delta;
        anchor_stamp_ = stamp;
        anchor_us_ = now_us;
        ++distinct_packets_;
      }
    }
    if (sequence && (!sequence_ || static_cast<int16_t>(*sequence - *sequence_) > 0))
      sequence_ = sequence;
    last_seen_us_ = now_us;
    const int32_t delta = static_cast<int32_t>(stamp - anchor_stamp_);
    if (delta < -5 * kHz) return restarted;
    const int64_t intercept = now_us - TickUs(anchor_ticks_ + delta);
    const int64_t epoch = now_us / kBucketUs;
    auto& bucket = buckets_[epoch % buckets_.size()];
    if (bucket.epoch != epoch) bucket = {epoch, intercept};
    else bucket.minimum_us = std::min(bucket.minimum_us, intercept);
    return restarted;
  }

  bool MatchesPacket(uint32_t ssrc, uint32_t stamp, uint16_t sequence) const {
    if (ssrc != ssrc_ || !sequence_) return false;
    const int16_t step = static_cast<int16_t>(sequence - *sequence_);
    return step <= 0 && step >= -128 &&
        std::llabs(static_cast<int32_t>(stamp - anchor_stamp_)) <= 5 * kHz;
  }

  std::optional<int> Output(uint32_t stamp, int64_t now_us) const {
    if (!ssrc_ || distinct_packets_ < 3 || now_us < last_seen_us_ ||
        now_us - last_seen_us_ > 3'000'000 || now_us - first_us_ < 100'000)
      return std::nullopt;
    const int64_t epoch = now_us / kBucketUs;
    std::optional<int64_t> floor;
    for (const auto& bucket : buckets_) {
      if (bucket.epoch >= 0 && bucket.epoch <= epoch &&
          epoch - bucket.epoch < static_cast<int64_t>(buckets_.size()))
        floor = floor ? std::min(*floor, bucket.minimum_us) : bucket.minimum_us;
    }
    if (!floor) return std::nullopt;
    const int32_t delta = static_cast<int32_t>(stamp - anchor_stamp_);
    if (delta > kHz || delta < -60 * kHz) return std::nullopt;
    const int64_t age_us = now_us - TickUs(anchor_ticks_ + delta) - *floor;
    if (age_us < 0) return std::nullopt;
    return static_cast<int>(std::min<int64_t>(60000, age_us / 1000));
  }

 private:
  static constexpr int kHz = 48000;  // Opus RTP clock, independent of decoder output rate.
  static constexpr int64_t kBucketUs = 500'000, kHistoryUs = 30'000'000;
  static int64_t TickUs(int64_t ticks) {
    return (ticks / kHz) * 1'000'000 + (ticks % kHz) * 1'000'000 / kHz;
  }
  struct Bucket { int64_t epoch = -1, minimum_us = 0; };
  std::array<Bucket, 60> buckets_{};
  uint32_t ssrc_ = 0, anchor_stamp_ = 0;
  int64_t anchor_ticks_ = 0, anchor_us_ = 0, first_us_ = 0, last_seen_us_ = 0;
  uint64_t distinct_packets_ = 0;
  std::optional<uint16_t> sequence_;
};
}  // namespace veil_media
