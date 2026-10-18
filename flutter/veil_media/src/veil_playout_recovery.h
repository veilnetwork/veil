// Endpoint-only bounded catch-up. NetEq remains responsible for decoding,
// FEC, PLC and ordinary time stretching; this discards decoded old audio only
// when actual queued samples exceed the live-call latency budget.
#ifndef VEIL_PLAYOUT_RECOVERY_H_
#define VEIL_PLAYOUT_RECOVERY_H_
#include <algorithm>
#include <atomic>
#include <memory>
#include "api/audio/audio_frame.h"
#include "api/neteq/default_neteq_controller_factory.h"
#include "api/neteq/neteq_factory.h"
#include "api/neteq/tick_timer.h"
#include "modules/audio_coding/neteq/neteq_impl.h"
#include "veil_playout_trace.h"
#include "veil_audio_recovery.h"

namespace veil_media {
struct PlayoutRecoveryStats {
  AudioRecoveryRegistry receivers;
  std::atomic<uint64_t> count{0};
  std::atomic<uint64_t> discarded_ms{0};
  std::atomic<uint64_t> fallback_frames{0};
};
class RecoveringNetEq final : public webrtc::NetEq {
 public:
  RecoveringNetEq(std::unique_ptr<webrtc::NetEq> inner,
                 std::shared_ptr<PlayoutRecoveryStats> stats,
                 std::unique_ptr<webrtc::TickTimer> arrival_clock = nullptr,
                 int requested_maximum_delay_ms = 0)
      : requested_maximum_delay_ms_(std::max(0, requested_maximum_delay_ms)),
        arrival_clock_(std::move(arrival_clock)), inner_(std::move(inner)),
        stats_(std::move(stats)), receiver_recovery_(stats_->receivers.NewStream()) {
    ApplyTargetCeiling();
  }
  int GetAudio(webrtc::AudioFrame* frame, bool* muted, int* rate,
               std::optional<Operation> action) override {
    const auto entered_us = trace_.enabled() ? webrtc::TimeMicros() : 0;
    const auto before_ms = trace_.enabled()
        ? inner_->GetOperationsAndState().current_buffer_size_ms : 0;
    bool silent = false;
    int sample_rate = 0;
    // Packet arrival estimation measures real render callbacks, not the extra
    // decoded blocks intentionally discarded within one callback. Otherwise
    // catch-up invents network jitter and the estimator repeatedly rebuilds
    // the backlog we just removed, including across an Opus DTX interval.
    if (arrival_clock_) arrival_clock_->Increment();
    const int result = inner_->GetAudio(frame, &silent, &sample_rate, action);
    if (result == kOK && !silent &&
        frame->speech_type_ == webrtc::AudioFrame::kNormalSpeech) {
      // PLC/CNG/muted output does not establish a new encoded packet size.
      const int frame_ms = inner_->GetOperationsAndState().current_frame_size_ms;
      if (frame_ms > 0) {
        frame_headroom_ms_ = std::clamp(frame_ms, 10, 100);
        ApplyTargetCeiling();
      }
    }
    unsigned skipped = 0;
    bool fallback = false;
    if (result == kOK && !silent &&
        frame->speech_type_ == webrtc::AudioFrame::kNormalSpeech && !action) {
      // Bound work on the audio callback. Never force PLC/underrun to discard
      // audio that is not actually available. Keep the last good output if a
      // subsequent decoder call fails.
      for (; skipped < 16;) {
        const auto state = inner_->GetOperationsAndState();
        if (state.current_buffer_size_ms <= static_cast<uint64_t>(RecoveryBudgetMs()) ||
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
    if (skipped) receiver_recovery_->Record(skipped * 10, webrtc::TimeMicros());
    if (skipped || fallback) {
      stats_->discarded_ms.fetch_add(skipped * 10, std::memory_order_relaxed);
      if (fallback) stats_->fallback_frames.fetch_add(1, std::memory_order_relaxed);
      stats_->count.fetch_add(1, std::memory_order_release);
    }
    if (muted) *muted = silent;
    if (rate) *rate = sample_rate;
    if (trace_.enabled()) {
      trace_.Record(entered_us, before_ms,
          inner_->GetOperationsAndState().current_buffer_size_ms,
          inner_->TargetDelayMs(), skipped, fallback,
          frame_headroom_ms_, applied_target_ceiling_ms_,
          result == kOK ? frame->timestamp_ : 0,
          result == kOK ? static_cast<int>(frame->speech_type_) : -1,
          silent);
    }
    return result;
  }
  int InsertPacket(const webrtc::RTPHeader& h, std::span<const uint8_t> p,
                   const webrtc::RtpPacketInfo& info) override {
    const auto received_us = trace_.enabled() ? webrtc::TimeMicros() : 0;
    const int result = inner_->InsertPacket(h, p, info);
    if (result == kOK && trace_.enabled())
      trace_.RecordPacket(received_us, h.ssrc, h.sequenceNumber, h.timestamp);
    if (result == kOK && h.ssrc && !registered_ssrc_) {
      stats_->receivers.Attach(h.ssrc, receiver_recovery_);
      registered_ssrc_ = h.ssrc;
    }
    return result;
  }
  void SetCodecs(const std::map<int, webrtc::SdpAudioFormat>& c) override { inner_->SetCodecs(c); }
  bool RegisterPayloadType(int p, const webrtc::SdpAudioFormat& f) override { return inner_->RegisterPayloadType(p, f); }
  bool CreateDecoder(int p) override { return inner_->CreateDecoder(p); }
  int RemovePayloadType(uint8_t p) override { return inner_->RemovePayloadType(p); }
  void SetMaximumBufferPackets(size_t n) override { inner_->SetMaximumBufferPackets(n); }
  void SetFastAccelerate(bool v) override { inner_->SetFastAccelerate(v); }
  void RemoveAllPayloadTypes() override { inner_->RemoveAllPayloadTypes(); }
  bool SetMinimumDelay(int n) override { return inner_->SetMinimumDelay(n); }
  bool SetMaximumDelay(int n) override {
    if (n < 0) return inner_->SetMaximumDelay(n);
    const int previous = requested_maximum_delay_ms_;
    requested_maximum_delay_ms_ = n;
    if (ApplyTargetCeiling()) return true;
    requested_maximum_delay_ms_ = previous;
    return false;
  }
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
  // NetEq's target and the hard catch-up must have compatible budgets.
  // Leave room for one ordinary decoded packet arrival; otherwise NetEq
  // refills toward a level that this wrapper discards on every render tick.
  // This caps the desired level, not actual storage, FEC or usable catch-up.
  // Long Opus packets need additional reorder headroom: cutting 60-ms
  // packets at 120 ms repeatedly discards usable speech on a lossless path
  // with 100-ms arrival variation. Short packets retain the original 120-ms
  // recovery bound; applying 200 ms to them delays group-mixer recovery.
  // Never exceed the endpoint's 200-ms video-pressure ceiling. These are
  // maximum queue budgets, not a fixed playout delay or network RTT.
  int RecoveryBudgetMs() const {
    return std::clamp(80 + 2 * frame_headroom_ms_, 120, 200);
  }
  bool ApplyTargetCeiling() {
    int ceiling = RecoveryBudgetMs() - frame_headroom_ms_;
    if (requested_maximum_delay_ms_ > 0)
      ceiling = std::min(ceiling, requested_maximum_delay_ms_);
    if (ceiling == applied_target_ceiling_ms_) return true;
    if (!inner_->SetMaximumDelay(ceiling)) return false;
    applied_target_ceiling_ms_ = ceiling;
    return true;
  }
  int frame_headroom_ms_ = 20;
  int requested_maximum_delay_ms_ = 0;
  int applied_target_ceiling_ms_ = -1;
  // Outlives the controller inside inner_. Its other NetEq dependencies keep
  // their original timer for decoding/packet bookkeeping.
  std::unique_ptr<webrtc::TickTimer> arrival_clock_;
  std::unique_ptr<webrtc::NetEq> inner_;
  std::shared_ptr<PlayoutRecoveryStats> stats_;
  std::shared_ptr<StreamAudioRecovery> receiver_recovery_;
  uint32_t registered_ssrc_ = 0;
  webrtc::AudioFrame scratch_;
  PlayoutTrace trace_;
};
class ArrivalClockControllerFactory final : public webrtc::NetEqControllerFactory {
 public:
  explicit ArrivalClockControllerFactory(webrtc::TickTimer* clock) : clock_(clock) {}
  std::unique_ptr<webrtc::NetEqController> Create(const webrtc::Environment& env,
      const webrtc::NetEqController::Config& config) const override {
    auto timed_config = config;
    timed_config.tick_timer = clock_;
    return base_.Create(env, timed_config);
  }
 private:
  webrtc::TickTimer* clock_;
  webrtc::DefaultNetEqControllerFactory base_;
};
class RecoveringNetEqFactory final : public webrtc::NetEqFactory {
 public:
  explicit RecoveringNetEqFactory(std::shared_ptr<PlayoutRecoveryStats> stats)
      : stats_(std::move(stats)) {}
  std::unique_ptr<webrtc::NetEq> Create(const webrtc::Environment& env,
      const webrtc::NetEq::Config& config,
      webrtc::scoped_refptr<webrtc::AudioDecoderFactory> decoder) const override {
    auto clock = std::make_unique<webrtc::TickTimer>();
    ArrivalClockControllerFactory controller(clock.get());
    auto inner = std::make_unique<webrtc::NetEqImpl>(config,
        webrtc::NetEqImpl::Dependencies(env, config, std::move(decoder), controller));
    return std::make_unique<RecoveringNetEq>(
        std::move(inner), stats_, std::move(clock), config.max_delay_ms);
  }
 private:
  std::shared_ptr<PlayoutRecoveryStats> stats_;
};
}  // namespace veil_media
#endif
