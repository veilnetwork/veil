// SPDX-License-Identifier: MIT
#ifndef VEIL_VIDEO_DELIVERY_FEEDBACK_H_
#define VEIL_VIDEO_DELIVERY_FEEDBACK_H_
#include <array>
#include <optional>
#include <span>
#include <string>
#include "veil_audio_recovery_feedback.h"
namespace veil_media {
// Optional RTCP APP, inside the authenticated encrypted media channel. These
// counters describe the remote decoder, never first-hop queue admission.
constexpr uint32_t kVideoDeliveryAppName = 0x56564431;  // VVD1
constexpr uint32_t kVideoDeliveryTargetAppName = 0x56564432;  // VVD2
struct VideoDeliveryReport {
  uint32_t target_ssrc = 0;
  uint64_t origin = 0, sampled_us = 0, bytes = 0, frames = 0;
  uint32_t timestamp = 0, delay_ms = 0;
  std::optional<uint32_t> target_delay_ms;
};
inline std::array<uint8_t, 64> EncodeVideoDelivery(
    uint32_t sender, const VideoDeliveryReport& r) {
  std::array<uint8_t, 64> b{};
  b[0] = 0x80; b[1] = 204; b[3] = 15;
  RecoveryWrite32(b.data()+4, sender);
  RecoveryWrite32(b.data()+8, r.target_delay_ms ?
      kVideoDeliveryTargetAppName : kVideoDeliveryAppName);
  RecoveryWrite32(b.data()+12, r.target_ssrc);
  RecoveryWrite64(b.data()+16, r.origin);
  RecoveryWrite64(b.data()+24, r.sampled_us);
  RecoveryWrite64(b.data()+32, r.bytes);
  RecoveryWrite64(b.data()+40, r.frames);
  RecoveryWrite32(b.data()+48, r.timestamp);
  RecoveryWrite32(b.data()+52, r.delay_ms);
  // VVD1 reserves eight zero bytes; VVD2 uses the first four for the
  // receiver's measured playout target. Packet size/cadence is unchanged.
  if (r.target_delay_ms) RecoveryWrite32(b.data()+56, *r.target_delay_ms);
  return b;
}
inline std::optional<VideoDeliveryReport> DecodeVideoDelivery(
    std::span<const uint8_t> p, uint8_t subtype) {
  if (subtype || p.size()!=60) return std::nullopt;
  const auto app = RecoveryRead32(p.data()+4);
  if ((app != kVideoDeliveryAppName && app != kVideoDeliveryTargetAppName) ||
      (app == kVideoDeliveryAppName && RecoveryRead64(p.data()+52)!=0) ||
      (app == kVideoDeliveryTargetAppName &&
          (RecoveryRead32(p.data()+52)>60000 || RecoveryRead32(p.data()+56)!=0)))
    return std::nullopt;
  VideoDeliveryReport r{RecoveryRead32(p.data()+8), RecoveryRead64(p.data()+12),
      RecoveryRead64(p.data()+20), RecoveryRead64(p.data()+28),
      RecoveryRead64(p.data()+36), RecoveryRead32(p.data()+44),
      RecoveryRead32(p.data()+48), std::nullopt};
  if (app == kVideoDeliveryTargetAppName)
    r.target_delay_ms = RecoveryRead32(p.data()+52);
  if (!r.target_ssrc || !r.origin || r.sampled_us < r.origin ||
      r.sampled_us > INT64_MAX || r.bytes > INT64_MAX || r.frames > INT64_MAX ||
      r.delay_ms > 60000) return std::nullopt;
  return r;
}
class VideoDeliveryCursor {
 public:
  void Observe(const VideoDeliveryReport& r, uint32_t local, int64_t arrived) {
    if (!local || r.target_ssrc!=local || arrived<=0 || r.origin<report_.origin) return;
    if (r.origin==report_.origin && (r.sampled_us<=report_.sampled_us ||
        r.bytes<report_.bytes || r.frames<report_.frames)) return;
    report_=r; arrived_us_=arrived;
  }
  std::string Json(int64_t now, uint32_t sent_timestamp, uint64_t sent_bytes) const {
    if (arrived_us_<=0 || now<arrived_us_ || now-arrived_us_>3'000'000) return "{}";
    auto json = "{\"origin\":"+std::to_string(report_.origin)+
        ",\"sample_us\":"+std::to_string(report_.sampled_us)+
        ",\"arrival_us\":"+std::to_string(arrived_us_)+
        ",\"bytes\":"+std::to_string(report_.bytes)+
        ",\"frames\":"+std::to_string(report_.frames)+
        ",\"timestamp\":"+std::to_string(report_.timestamp)+
        ",\"delay_ms\":"+std::to_string(report_.delay_ms)+
        ",\"sent_timestamp\":"+std::to_string(sent_timestamp)+
        ",\"sent_bytes\":"+std::to_string(sent_bytes);
    if (report_.target_delay_ms)
      json += ",\"target_delay_ms\":"+std::to_string(*report_.target_delay_ms);
    return json + "}";
  }
  const VideoDeliveryReport& report() const { return report_; }
 private:
  VideoDeliveryReport report_;
  int64_t arrived_us_ = 0;
};
}  // namespace veil_media
#endif
