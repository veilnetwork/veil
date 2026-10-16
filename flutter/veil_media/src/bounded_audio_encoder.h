#ifndef VEIL_BOUNDED_AUDIO_ENCODER_H_
#define VEIL_BOUNDED_AUDIO_ENCODER_H_

#include <algorithm>
#include <array>
#include <atomic>
#include <memory>
#include <utility>

#include "api/audio_codecs/audio_encoder.h"
#include "api/audio_codecs/audio_encoder_factory.h"
#include "api/audio_codecs/builtin_audio_encoder_factory.h"
#include "api/make_ref_counted.h"
#include "rtc_base/time_utils.h"
#include "veil_audio_encode_timing.h"
#include "veil_audio_adaptor_config.h"

namespace veil_media {

// ANA receives a gross allocation, including per-packet overhead. The ordinary
// allocator's maximum uses the shortest supported duration; after ANA chooses
// longer packets that maximum can buy more payload than the codec ceiling.
// Bound the allocation for the duration ANA will choose, without replacing the
// Opus encoder, changing timestamps, or implementing another codec.
class BoundedAudioEncoder final : public webrtc::AudioEncoder {
 public:
  explicit BoundedAudioEncoder(
      std::unique_ptr<webrtc::AudioEncoder> inner,
      std::shared_ptr<std::atomic<int>> packet_duration = {}, uint32_t trace_ssrc = 0)
      : inner_(std::move(inner)), packet_duration_(std::move(packet_duration)),
        timing_(trace_ssrc, inner_->RtpTimestampRateHz()) {}

  int SampleRateHz() const override { return inner_->SampleRateHz(); }
  size_t NumChannels() const override { return inner_->NumChannels(); }
  int RtpTimestampRateHz() const override { return inner_->RtpTimestampRateHz(); }
  size_t Num10MsFramesInNextPacket() const override {
    return inner_->Num10MsFramesInNextPacket();
  }
  size_t Max10MsFramesInAPacket() const override {
    return inner_->Max10MsFramesInAPacket();
  }
  int GetTargetBitrate() const override { return inner_->GetTargetBitrate(); }
  void Reset() override {
    inner_->Reset();
    ClampPayloadTarget();
  }
  bool SetFec(bool on) override { return inner_->SetFec(on); }
  bool SetDtx(bool on) override { return inner_->SetDtx(on); }
  bool GetDtx() const override { return inner_->GetDtx(); }
  bool SetApplication(Application app) override { return inner_->SetApplication(app); }
  void SetMaxPlaybackRate(int hz) override { inner_->SetMaxPlaybackRate(hz); }
  bool EnableAudioNetworkAdaptor(absl::string_view config) override {
    const bool enabled = inner_->EnableAudioNetworkAdaptor(config);
    if (enabled && config == kFramingAudioAdaptorConfig)
      min_payload_bps_ = kFramingAudioMinPayloadBps;
    ClampPayloadTarget();
    return enabled;
  }
  void DisableAudioNetworkAdaptor() override { inner_->DisableAudioNetworkAdaptor(); }
  void OnReceivedUplinkPacketLossFraction(float fraction) override {
    inner_->OnReceivedUplinkPacketLossFraction(fraction);
    ClampPayloadTarget();
  }
  void OnReceivedRtt(int ms) override {
    inner_->OnReceivedRtt(ms);
    ClampPayloadTarget();
  }
  void OnReceivedOverhead(size_t bytes) override {
    overhead_bytes_ = bytes;
    inner_->OnReceivedOverhead(bytes);
    ClampPayloadTarget();
  }
  void OnReceivedTargetAudioBitrate(int bps) override {
    inner_->OnReceivedTargetAudioBitrate(std::clamp(bps, min_payload_bps_, kMaxPayloadBps));
  }
  void SetTargetBitrate(int bps) override { OnReceivedTargetAudioBitrate(bps); }
  void OnReceivedUplinkAllocation(webrtc::BitrateAllocationUpdate update) override {
    const int64_t raw_allocation_bps = update.target_bitrate.bps<int64_t>();
    // Leave endpoint headroom for RTCP and transport control/framing not
    // represented by a payload-only audio allocation. No relay priority.
    const int64_t budget = update.target_bitrate.bps<int64_t>() / 4 * 3;
    const auto range = inner_->GetFrameLengthRange();
    int duration_ms = range ? static_cast<int>(range->second.ms()) : 60;
    // Matches the configured fast FrameLengthControllerV2's strict comparison
    // and supported durations. Limits apply to payload, not the gross budget.
    for (int candidate : std::array{20, 40, 60}) {
      // Receiver/codec constraints can narrow the range. Budgeting for a
      // longer, unavailable packet undercounts overhead and breaks the
      // payload floor when ANA subtracts the actual packet's overhead.
      if (range && (candidate < range->first.ms() ||
                    candidate > range->second.ms())) {
        continue;
      }
      if (budget - OverheadBps(candidate) > min_payload_bps_) {
        duration_ms = candidate;
        break;
      }
    }
    const int64_t overhead = OverheadBps(duration_ms);
    update.target_bitrate = webrtc::DataRate::BitsPerSec(std::clamp<int64_t>(
        budget, overhead + min_payload_bps_,
        overhead + kMaxPayloadBps));
    if (timing_.enabled())
      timing_.Allocation(webrtc::TimeMicros(), raw_allocation_bps,
                         update.target_bitrate.bps<int64_t>(), overhead_bytes_);
    inner_->OnReceivedUplinkAllocation(update);
    ClampPayloadTarget();
  }
  void SetReceiverFrameLengthRange(int min_ms, int max_ms) override {
    inner_->SetReceiverFrameLengthRange(min_ms, max_ms);
  }
  webrtc::ANAStats GetANAStats() const override { return inner_->GetANAStats(); }
  std::optional<std::pair<webrtc::TimeDelta, webrtc::TimeDelta>>
  GetFrameLengthRange() const override { return inner_->GetFrameLengthRange(); }
  std::optional<std::pair<webrtc::DataRate, webrtc::DataRate>>
  GetBitrateRange() const override { return inner_->GetBitrateRange(); }

 private:
  void ClampPayloadTarget() {
    // ANA can apply a bitrate before it has the uplink estimate required to
    // select a longer packet. Its gross budget then buys less than the speech
    // floor at the current duration. Loss/RTT/overhead updates also rerun ANA.
    // Clamp the actual codec target after those decisions; do not change ANA's
    // metrics, packet-duration choice, timestamps, or transport allocation.
    const int target = inner_->GetTargetBitrate();
    const int bounded = std::clamp(target, min_payload_bps_, kMaxPayloadBps);
    if (target != bounded) inner_->OnReceivedTargetAudioBitrate(bounded);
  }
  EncodedInfo EncodeImpl(uint32_t timestamp, std::span<const int16_t> audio,
                         webrtc::Buffer* encoded) override {
    if (timing_.enabled()) timing_.Input(timestamp, webrtc::TimeMicros());
    // Opus may select the next duration at this packet's boundary. Sample
    // before Encode, and publish only when an encoded packet actually exists.
    // A pending 10-ms input block or DTX suppression is not a new packet.
    const size_t blocks = inner_->Num10MsFramesInNextPacket();
    auto info = inner_->Encode(timestamp, audio, encoded);
    if (timing_.enabled() && info.encoded_bytes > 0)
      timing_.Encoded(info.encoded_timestamp, webrtc::TimeMicros(), blocks,
                      info.encoded_bytes);
    if (packet_duration_ && info.encoded_bytes > 0 && blocks > 0 && blocks <= 12) {
      packet_duration_->store(static_cast<int>(blocks * 10),
                              std::memory_order_relaxed);
    }
    return info;
  }
  int64_t OverheadBps(int duration_ms) const {
    return static_cast<int64_t>(overhead_bytes_) * 8 * 1000 / duration_ms;
  }
  // Fixed group budgets retain the established 16..32-kbit API. The
  // unicast framing adaptor raises its floor before accepting PCM/feedback.
  int min_payload_bps_ = 16'000;
  static constexpr int kMaxPayloadBps = 32'000;
  size_t overhead_bytes_ = 0;
  std::unique_ptr<webrtc::AudioEncoder> inner_;
  std::shared_ptr<std::atomic<int>> packet_duration_;
  AudioEncodeTiming timing_;
};

class BoundedAudioEncoderFactory : public webrtc::AudioEncoderFactory {
 public:
  explicit BoundedAudioEncoderFactory(
      std::shared_ptr<std::atomic<int>> packet_duration = {}, uint32_t trace_ssrc = 0)
      : inner_(webrtc::CreateBuiltinAudioEncoderFactory()),
        packet_duration_(std::move(packet_duration)), trace_ssrc_(trace_ssrc) {}
  std::vector<webrtc::AudioCodecSpec> GetSupportedEncoders() override {
    return inner_->GetSupportedEncoders();
  }
  std::optional<webrtc::AudioCodecInfo> QueryAudioEncoder(
      const webrtc::SdpAudioFormat& format) override {
    return inner_->QueryAudioEncoder(format);
  }
  std::unique_ptr<webrtc::AudioEncoder> Create(const webrtc::Environment& env,
      const webrtc::SdpAudioFormat& format, Options options) override {
    auto encoder = inner_->Create(env, format, options);
    if (!encoder || format.name != "opus") return encoder;
    return std::make_unique<BoundedAudioEncoder>(std::move(encoder),
                                                packet_duration_, trace_ssrc_);
  }
 private:
  webrtc::scoped_refptr<webrtc::AudioEncoderFactory> inner_;
  std::shared_ptr<std::atomic<int>> packet_duration_;
  const uint32_t trace_ssrc_;
};

}  // namespace veil_media
#endif
