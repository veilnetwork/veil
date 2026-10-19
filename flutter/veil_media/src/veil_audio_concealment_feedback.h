// SPDX-License-Identifier: MIT
#ifndef VEIL_AUDIO_CONCEALMENT_FEEDBACK_H_
#define VEIL_AUDIO_CONCEALMENT_FEEDBACK_H_

#include "veil_audio_recovery_feedback.h"

namespace veil_media {
// Separate from VAP2: non-silent decoder concealment is neither discarded
// speech nor proof of network packet loss. Only authenticated endpoints see it.
constexpr uint32_t kAudioConcealmentAppName = 0x56415033u;  // VAP3
struct AudioConcealmentReport {
  uint32_t target_ssrc = 0;
  uint64_t sequence = 0, origin = 0, concealed_samples = 0;
  uint32_t age_ms = kUnknownRecoveryAge;
  bool known = false;
};

class LocalAudioConcealment {
 public:
  // Counter baselines are taken on the receive worker. No event is inferred
  // across a decoder replacement, unknown/muted sample or sampling gap.
  bool Observe(uint32_t target, uint64_t sequence, uint64_t origin,
               uint64_t concealed, uint64_t silent, int64_t at_us) {
    if (!target || !sequence || at_us <= 0) return false;
    if (target == target_ && origin && origin < origin_)
      return false;
    const bool same = target == target_ && origin && origin == origin_;
    if (target == target_ && origin <= origin_ && sequence <= sequence_)
      return false;
    if (target == target_ && sampled_us_ > 0 && at_us <= sampled_us_)
      return false;
    const bool known = origin && silent <= concealed;
    const bool contiguous = same && report_.known && known &&
        sampled_us_ > 0 && at_us - sampled_us_ <= 3'000'000 &&
        concealed >= concealed_ && silent >= silent_ &&
        concealed - silent >= report_.concealed_samples;
    const auto non_silent = known ? concealed - silent : 0;
    const bool event = contiguous && non_silent > report_.concealed_samples;
    if (!contiguous) event_us_ = 0;
    if (event) event_us_ = at_us;  // detection time, not an RTP/PCM timestamp
    report_ = {target, sequence, known ? origin : 0, non_silent,
               kUnknownRecoveryAge, known};
    if (target != target_) origin_ = 0;
    target_ = target;
    if (known) origin_ = origin;
    sequence_ = sequence;
    sampled_us_ = at_us;
    concealed_ = concealed;
    silent_ = silent;
    enabled_ = true;
    return event;
  }
  bool enabled() const { return enabled_; }
  AudioConcealmentReport Report(int64_t now_us) const {
    auto report = report_;
    if (sampled_us_ <= 0 || sampled_us_ > now_us ||
        now_us - sampled_us_ > 3'000'000) {
      report.known = false;
      report.origin = report.concealed_samples = 0;
    } else if (report.known && event_us_ > 0 && event_us_ <= now_us &&
               now_us - event_us_ <= 3'000'000) {
      report.age_ms = static_cast<uint32_t>((now_us - event_us_) / 1000);
    }
    return report;
  }

 private:
  bool enabled_ = false;
  AudioConcealmentReport report_;
  uint64_t concealed_ = 0, silent_ = 0;
  uint32_t target_ = 0;
  uint64_t origin_ = 0, sequence_ = 0;
  int64_t sampled_us_ = 0, event_us_ = 0;
};

inline std::array<uint8_t, 48> EncodeAudioConcealment(
    uint32_t sender, const AudioConcealmentReport& report) {
  std::array<uint8_t, 48> wire{};
  wire[0] = 0x80;
  wire[1] = 204;
  wire[3] = 11;
  RecoveryWrite32(wire.data() + 4, sender);
  RecoveryWrite32(wire.data() + 8, kAudioConcealmentAppName);
  RecoveryWrite32(wire.data() + 12, report.target_ssrc);
  RecoveryWrite64(wire.data() + 16, report.sequence);
  RecoveryWrite64(wire.data() + 24, report.origin);
  RecoveryWrite64(wire.data() + 32, report.concealed_samples);
  RecoveryWrite32(wire.data() + 40, report.age_ms);
  RecoveryWrite32(wire.data() + 44, report.known ? 1 : 0);
  return wire;
}
inline std::optional<AudioConcealmentReport> DecodeAudioConcealment(
    std::span<const uint8_t> payload, uint8_t subtype) {
  if (subtype != 0 || payload.size() != 44 ||
      RecoveryRead32(payload.data() + 4) != kAudioConcealmentAppName)
    return std::nullopt;
  AudioConcealmentReport r{
      RecoveryRead32(payload.data() + 8), RecoveryRead64(payload.data() + 12),
      RecoveryRead64(payload.data() + 20), RecoveryRead64(payload.data() + 28),
      RecoveryRead32(payload.data() + 36), false};
  const auto flags = RecoveryRead32(payload.data() + 40);
  if (!r.target_ssrc || !r.sequence || flags > 1 ||
      (r.age_ms != kUnknownRecoveryAge && r.age_ms > 3000))
    return std::nullopt;
  r.known = flags == 1;
  if ((!r.known && (r.origin || r.concealed_samples ||
                     r.age_ms != kUnknownRecoveryAge)) ||
      (r.known && !r.origin) ||
      (!r.concealed_samples && r.age_ms != kUnknownRecoveryAge))
    return std::nullopt;
  return r;
}

class AudioConcealmentCursor {
 public:
  void Observe(const AudioConcealmentReport& r, uint32_t local,
               int64_t arrived_us) {
    if (!local || r.target_ssrc != local || arrived_us <= 0) return;
    supported_ = true;
    if (!r.known || r.origin < origin_) return;
    if (r.origin == origin_ && r.sequence <= sequence_) return;
    sequence_ = r.sequence;
    if (r.origin > origin_) {
      origin_ = r.origin;
      concealed_samples_ = 0;
    }
    if (r.concealed_samples < concealed_samples_) return;
    const bool advanced = r.concealed_samples > concealed_samples_;
    concealed_samples_ = r.concealed_samples;
    if (advanced && r.age_ms != kUnknownRecoveryAge && r.age_ms <= 3000)
      reported_us_ = std::max(reported_us_, arrived_us);
  }
  bool supported() const { return supported_; }
  int64_t FreshReportUs(int64_t now_us) const {
    return reported_us_ > 0 && reported_us_ <= now_us &&
                   now_us - reported_us_ <= 15'000'000 ? reported_us_ : 0;
  }

 private:
  bool supported_ = false;
  uint64_t sequence_ = 0, origin_ = 0, concealed_samples_ = 0;
  int64_t reported_us_ = 0;
};
}  // namespace veil_media
#endif
