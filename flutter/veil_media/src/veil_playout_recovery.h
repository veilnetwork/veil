// Endpoint-only bounded catch-up. NetEq remains responsible for decoding,
// FEC, PLC and ordinary time stretching; this discards decoded old audio only
// when actual queued samples exceed the live-call latency budget.
#ifndef VEIL_PLAYOUT_RECOVERY_H_
#define VEIL_PLAYOUT_RECOVERY_H_
#include <atomic>
#include <memory>
#include "api/audio/audio_frame.h"
#include "api/neteq/default_neteq_factory.h"

namespace veil_media {
struct PlayoutRecoveryStats {
  std::atomic<uint64_t> count{0};
  std::atomic<uint64_t> discarded_ms{0};
  std::atomic<uint64_t> fallback_frames{0};
};
class RecoveringNetEq final : public webrtc::NetEq {
 public:
  RecoveringNetEq(std::unique_ptr<webrtc::NetEq> inner,
                 std::shared_ptr<PlayoutRecoveryStats> stats)
      : inner_(std::move(inner)), stats_(std::move(stats)) {}
  int GetAudio(webrtc::AudioFrame* frame, bool* muted, int* rate,
               std::optional<Operation> action) override {
    bool silent = false;
    int sample_rate = 0;
    const int result = inner_->GetAudio(frame, &silent, &sample_rate, action);
    unsigned skipped = 0;
    bool fallback = false;
    if (result == kOK && !silent &&
        frame->speech_type_ == webrtc::AudioFrame::kNormalSpeech && !action) {
      // Bound work on the audio callback. Never force PLC/underrun to discard
      // audio that is not actually available. Keep the last good output if a
      // subsequent decoder call fails.
      for (; skipped < 16;) {
        const auto state = inner_->GetOperationsAndState();
        if (state.current_buffer_size_ms <= 120 ||
            (inner_->SyncBufferSizeMs() < 20 && !state.next_packet_available))
          break;
        bool next_muted = false;
        int next_rate = 0;
        if (inner_->GetAudio(&scratch_, &next_muted, &next_rate) != kOK) break;
        // GetAudio can succeed with PLC/CNG even when a packet was available.
        // An extra catch-up pull must not replace usable speech with a muted
        // or generated frame. Keep the last actual speech block instead.
        if (next_muted || scratch_.speech_type_ != webrtc::AudioFrame::kNormalSpeech) {
          fallback = true;
          break;
        }
        frame->CopyFrom(scratch_);
        silent = next_muted;
        sample_rate = next_rate;
        ++skipped;
      }
    }
    if (skipped || fallback) {
      stats_->discarded_ms.fetch_add(skipped * 10, std::memory_order_relaxed);
      if (fallback) stats_->fallback_frames.fetch_add(1, std::memory_order_relaxed);
      stats_->count.fetch_add(1, std::memory_order_release);
    }
    if (muted) *muted = silent;
    if (rate) *rate = sample_rate;
    return result;
  }
  int InsertPacket(const webrtc::RTPHeader& h, std::span<const uint8_t> p,
                   const webrtc::RtpPacketInfo& info) override {
    return inner_->InsertPacket(h, p, info);
  }
  void SetCodecs(const std::map<int, webrtc::SdpAudioFormat>& c) override { inner_->SetCodecs(c); }
  bool RegisterPayloadType(int p, const webrtc::SdpAudioFormat& f) override { return inner_->RegisterPayloadType(p, f); }
  bool CreateDecoder(int p) override { return inner_->CreateDecoder(p); }
  int RemovePayloadType(uint8_t p) override { return inner_->RemovePayloadType(p); }
  void SetMaximumBufferPackets(size_t n) override { inner_->SetMaximumBufferPackets(n); }
  void SetFastAccelerate(bool v) override { inner_->SetFastAccelerate(v); }
  void RemoveAllPayloadTypes() override { inner_->RemoveAllPayloadTypes(); }
  bool SetMinimumDelay(int n) override { return inner_->SetMinimumDelay(n); }
  bool SetMaximumDelay(int n) override { return inner_->SetMaximumDelay(n); }
  bool SetBaseMinimumDelayMs(int n) override { return inner_->SetBaseMinimumDelayMs(n); }
  int GetBaseMinimumDelayMs() const override { return inner_->GetBaseMinimumDelayMs(); }
  int TargetDelayMs() const override { return inner_->TargetDelayMs(); }
  int FilteredCurrentDelayMs() const override { return inner_->FilteredCurrentDelayMs(); }
  int NetworkStatistics(webrtc::NetEqNetworkStatistics* s) override { return inner_->NetworkStatistics(s); }
  webrtc::NetEqNetworkStatistics CurrentNetworkStatistics() const override { return inner_->CurrentNetworkStatistics(); }
  webrtc::NetEqLifetimeStatistics GetLifetimeStatistics() const override { return inner_->GetLifetimeStatistics(); }
  webrtc::NetEqOperationsAndState GetOperationsAndState() const override { return inner_->GetOperationsAndState(); }
  std::optional<uint32_t> GetPlayoutTimestamp() const override { return inner_->GetPlayoutTimestamp(); }
  int last_output_sample_rate_hz() const override { return inner_->last_output_sample_rate_hz(); }
  std::optional<DecoderFormat> GetCurrentDecoderFormat() const override { return inner_->GetCurrentDecoderFormat(); }
  void FlushBuffers() override { inner_->FlushBuffers(); }
  int SyncBufferSizeMs() const override { return inner_->SyncBufferSizeMs(); }
 private:
  std::unique_ptr<webrtc::NetEq> inner_;
  std::shared_ptr<PlayoutRecoveryStats> stats_;
  webrtc::AudioFrame scratch_;
};
class RecoveringNetEqFactory final : public webrtc::NetEqFactory {
 public:
  explicit RecoveringNetEqFactory(std::shared_ptr<PlayoutRecoveryStats> stats)
      : stats_(std::move(stats)) {}
  std::unique_ptr<webrtc::NetEq> Create(const webrtc::Environment& env,
      const webrtc::NetEq::Config& config,
      webrtc::scoped_refptr<webrtc::AudioDecoderFactory> decoder) const override {
    return std::make_unique<RecoveringNetEq>(
        base_.Create(env, config, std::move(decoder)), stats_);
  }
 private:
  webrtc::DefaultNetEqFactory base_;
  std::shared_ptr<PlayoutRecoveryStats> stats_;
};
}  // namespace veil_media
#endif
