// SPDX-License-Identifier: MIT
#ifndef VEIL_AUDIO_RECOVERY_FEEDBACK_H_
#define VEIL_AUDIO_RECOVERY_FEEDBACK_H_
#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>

#include "veil_audio_recovery.h"

namespace veil_media {
constexpr uint32_t kAudioRecoveryAppName =
    0x56415032u;  // VAP2, optional RTCP APP
constexpr uint32_t kUnknownRecoveryAge = 0xffffffffu;
struct AudioRecoveryReport {
  uint32_t target_ssrc = 0;
  uint64_t sequence = 0, origin = 0, discarded_ms = 0;
  uint32_t age_ms = kUnknownRecoveryAge;
  bool known = false;
};
inline uint32_t RecoveryRead32(const uint8_t* p) {
  return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 |
         p[3];
}
inline uint64_t RecoveryRead64(const uint8_t* p) {
  return uint64_t(RecoveryRead32(p)) << 32 | RecoveryRead32(p + 4);
}
inline void RecoveryWrite32(uint8_t* p, uint32_t n) {
  for (int i = 0; i < 4; ++i) p[i] = n >> (24 - 8 * i);
}
inline void RecoveryWrite64(uint8_t* p, uint64_t n) {
  RecoveryWrite32(p, n >> 32);
  RecoveryWrite32(p + 4, n);
}
inline std::array<uint8_t, 48> EncodeAudioRecovery(
    uint32_t sender, uint32_t target, uint64_t sequence,
    const AudioRecoverySample& sample, int64_t sampled_us, int64_t now_us) {
  std::array<uint8_t, 48> wire{};
  wire[0] = 0x80;
  wire[1] = 204;
  wire[3] = 11;
  RecoveryWrite32(wire.data() + 4, sender);
  RecoveryWrite32(wire.data() + 8, kAudioRecoveryAppName);
  RecoveryWrite32(wire.data() + 12, target);
  RecoveryWrite64(wire.data() + 16, sequence);
  const bool fresh = sampled_us > 0 && sampled_us <= now_us &&
                     now_us - sampled_us <= 3'000'000;
  const bool known = fresh && sample.known && sample.origin != 0;
  RecoveryWrite64(wire.data() + 24, known ? sample.origin : 0);
  RecoveryWrite64(wire.data() + 32, known ? sample.discarded_ms : 0);
  uint32_t age = kUnknownRecoveryAge;
  if (known && sample.discarded_ms && sample.last_discard_us > 0 &&
      sample.last_discard_us <= now_us &&
      now_us - sample.last_discard_us <= 3'000'000)
    age = static_cast<uint32_t>((now_us - sample.last_discard_us) / 1000);
  RecoveryWrite32(wire.data() + 40, age);
  RecoveryWrite32(wire.data() + 44, known ? 1 : 0);
  return wire;
}
// CommonHeader has already stripped the four-byte RTCP header and any padding.
inline std::optional<AudioRecoveryReport> DecodeAudioRecovery(
    std::span<const uint8_t> payload, uint8_t subtype) {
  if (subtype != 0 || payload.size() != 44 ||
      RecoveryRead32(payload.data() + 4) != kAudioRecoveryAppName)
    return std::nullopt;
  AudioRecoveryReport report{
      RecoveryRead32(payload.data() + 8),  RecoveryRead64(payload.data() + 12),
      RecoveryRead64(payload.data() + 20), RecoveryRead64(payload.data() + 28),
      RecoveryRead32(payload.data() + 36), false};
  const auto flags = RecoveryRead32(payload.data() + 40);
  if (flags > 1 || !report.target_ssrc || !report.sequence ||
      (report.age_ms != kUnknownRecoveryAge && report.age_ms > 3000))
    return std::nullopt;
  report.known = flags == 1;
  if ((!report.known && (report.origin || report.discarded_ms ||
                         report.age_ms != kUnknownRecoveryAge)) ||
      (report.known && !report.origin) ||
      (!report.discarded_ms && report.age_ms != kUnknownRecoveryAge))
    return std::nullopt;
  return report;
}
class AudioRecoveryCursor {
 public:
  void Observe(const AudioRecoveryReport& report, uint32_t local_ssrc,
               int64_t arrived_us) {
    if (!local_ssrc || report.target_ssrc != local_ssrc || arrived_us <= 0)
      return;
    supported_ = true;
    // Unknown reports carry no decoder origin. A delayed unknown report from
    // a retired engine must not move the new decoder's sequence high water.
    if (!report.known || report.origin < origin_) return;
    const bool new_origin = report.known && report.origin > origin_;
    if (!new_origin && report.sequence <= sequence_) return;
    sequence_ = report.sequence;
    if (report.origin > origin_) {
      origin_ = report.origin;
      discarded_ms_ = 0;
    }
    if (report.discarded_ms < discarded_ms_) return;
    const bool advanced = report.discarded_ms > discarded_ms_;
    discarded_ms_ = report.discarded_ms;
    // A newer report repeating the same event never refreshes its witness.
    // Stale newly observed counters are consumed without producing fresh loss.
    if (advanced && report.age_ms != kUnknownRecoveryAge &&
        report.age_ms <= 3000)
      reported_us_ = std::max(reported_us_, arrived_us);
  }
  bool supported() const { return supported_; }
  AudioRecoverySample Sample() const {
    return {origin_ != 0, origin_, discarded_ms_, 0};
  }
  int64_t FreshReportUs(int64_t now_us) const {
    return reported_us_ > 0 && reported_us_ <= now_us &&
                   now_us - reported_us_ <= 15'000'000
               ? reported_us_
               : 0;
  }

 private:
  bool supported_ = false;
  uint64_t sequence_ = 0, origin_ = 0, discarded_ms_ = 0;
  int64_t reported_us_ = 0;
};
}  // namespace veil_media
#endif
