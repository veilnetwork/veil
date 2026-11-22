// Endpoint-only bounded catch-up. NetEq remains responsible for decoding,
// FEC, PLC and ordinary time stretching; this discards decoded old audio only
// when actual storage or a validated decoded RTP age exceeds its budget.
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
#include "modules/audio_coding/neteq/packet_buffer.h"
#include "veil_playout_trace.h"
#include "veil_audio_recovery.h"
#include "veil_audio_rtp_lag.h"
#include "veil_conversation_neteq_controller.h"

namespace veil_media {
// NetEq limits its target to 75% of the packet capacity in time. Keep room
// above the 500-ms target for 20-ms Opus packets released in a batch.
inline constexpr size_t kCallAudioPacketCapacity = 36;

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
    // Packet arrival and queue waiting time measure real render callbacks,
    // not the extra decoded blocks discarded within one callback. Otherwise
    // catch-up invents network jitter and the estimator repeatedly rebuilds
    // the backlog we just removed, including across an Opus DTX interval.
    if (arrival_clock_) arrival_clock_->Increment();
    const int result = inner_->GetAudio(frame, &silent, &sample_rate, action);
    const auto flushes = inner_->GetOperationsAndState().packet_buffer_flushes;
    if (flushes != packet_buffer_flushes_) {
      ResetLag();
      packet_buffer_flushes_ = flushes;
    }
    const bool normal_speech = result == kOK && !silent &&
        frame->speech_type_ == webrtc::AudioFrame::kNormalSpeech;
    if (normal_speech) {
      // PLC/CNG/muted output does not establish a new encoded packet size.
      const int frame_ms = inner_->GetOperationsAndState().current_frame_size_ms;
      if (frame_ms > 0) {
        frame_headroom_ms_ = std::clamp(frame_ms, 10, 100);
        ApplyTargetCeiling();
      }
    }
    unsigned skipped = 0;
    bool fallback = false;
    if (normal_speech && !action) {
      // Bound work on the audio callback. Never force PLC/underrun to discard
      // audio that is not actually available. Keep the last good output if a
      // subsequent decoder call fails.
      for (; skipped < 16;) {
        const auto state = inner_->GetOperationsAndState();
        // Storage alone misses time already spent upstream. Use only an
        // aligned decoded-packet clock and preserve the packet-sized jitter
        // reserve before an extra 10-ms pull. PLC/error guards remain below.
        const int64_t now_us = webrtc::TimeMicros();
        const auto lag = UpdateDecodedClock(*frame)
            ? rtp_lag_.Output(frame->timestamp_, now_us) : std::nullopt;
        // RTP age also includes time spent upstream. Do not repeatedly cut a
        // local queue below NetEq's own jitter reserve: it will refill toward
        // that target and manufacture another catch-up event. Arrival/decoder
        // headroom must be the same for age-only and storage-driven catch-up.
        const int jitter_reserve_ms = JitterReserveMs(now_us);
        const int recovery_budget_ms = std::max(
            NominalRecoveryBudgetMs(), jitter_reserve_ms);
        const int local_reserve_ms = std::max(frame_headroom_ms_ + 30, jitter_reserve_ms);
        // Extra pulls consume a whole render block. A smaller apparent
        // surplus cannot fund a pull without spending the reserve itself.
        const bool storage_excess = state.current_buffer_size_ms >=
            static_cast<uint64_t>(recovery_budget_ms + kRenderBlockMs);
        const bool age_excess = lag && *lag > recovery_budget_ms - 20 &&
            state.current_buffer_size_ms >= static_cast<uint64_t>(local_reserve_ms + kRenderBlockMs);
        if ((!age_excess && !storage_excess) ||
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
    if (skipped) receiver_recovery_->Record(skipped * kRenderBlockMs, webrtc::TimeMicros());
    if (skipped || fallback) {
      stats_->discarded_ms.fetch_add(skipped * kRenderBlockMs, std::memory_order_relaxed);
      if (fallback) stats_->fallback_frames.fetch_add(1, std::memory_order_relaxed);
      stats_->count.fetch_add(1, std::memory_order_release);
    }
    // NetEq can keep an old output RTP origin across a sender rebuild even
    // while PCM is prompt. Require an actual decoded-packet clock witness;
    // never infer a timestamp offset from packet order or tone phase.
    // A failed or synthetic block can still carry packet metadata. It does
    // not extend the timestamp witness to the next block without metadata.
    if (!normal_speech) decoded_stamp_.reset();
    receiver_recovery_->SetLag(
        normal_speech && UpdateDecodedClock(*frame)
            ? rtp_lag_.Output(frame->timestamp_, webrtc::TimeMicros()) : std::nullopt,
        webrtc::TimeMicros());
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
    const auto received_us = webrtc::TimeMicros();
    const int result = inner_->InsertPacket(h, p, info);
    if (result == kOK && trace_.enabled())
      trace_.RecordPacket(received_us, h.ssrc, h.sequenceNumber, h.timestamp);
    if (result == kOK && h.ssrc && !registered_ssrc_) {
      stats_->receivers.Attach(h.ssrc, receiver_recovery_);
      registered_ssrc_ = h.ssrc;
    }
    if (result == kOK && !p.empty()) {
      if (h.ssrc == registered_ssrc_ && h.payloadType < opus_payloads_.size() &&
          opus_payloads_[h.payloadType]) {
        if (rtp_lag_.Packet(h.ssrc, h.timestamp, received_us, h.sequenceNumber)) {
          arrival_reserve_ms_ = 0;
          decoded_stamp_.reset();
          receiver_recovery_->SetLag(std::nullopt, 0);
        }
      } else {
        ResetLag();
      }
    }
    return result;
  }
  void SetCodecs(const std::map<int, webrtc::SdpAudioFormat>& c) override {
    inner_->SetCodecs(c);
    opus_payloads_.fill(false);
    for (const auto& [p, f] : c) TrackCodec(p, f);
    ResetLag();
  }
  bool RegisterPayloadType(int p, const webrtc::SdpAudioFormat& f) override {
    if (!inner_->RegisterPayloadType(p, f)) return false;
    TrackCodec(p, f);
    ResetLag();
    return true;
  }
  bool CreateDecoder(int p) override { return inner_->CreateDecoder(p); }
  int RemovePayloadType(uint8_t p) override {
    const int result = inner_->RemovePayloadType(p);
    if (result == kOK) {
      if (p < opus_payloads_.size()) opus_payloads_[p] = false;
      ResetLag();
    }
    return result;
  }
  void SetMaximumBufferPackets(size_t n) override { inner_->SetMaximumBufferPackets(n); }
  void SetFastAccelerate(bool v) override { inner_->SetFastAccelerate(v); }
  void RemoveAllPayloadTypes() override {
    inner_->RemoveAllPayloadTypes(); opus_payloads_.fill(false); ResetLag();
  }
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
  void FlushBuffers() override { inner_->FlushBuffers(); ResetLag(); }
  int SyncBufferSizeMs() const override { return inner_->SyncBufferSizeMs(); }
 private:
  void ResetLag() {
    rtp_lag_.Reset();
    arrival_reserve_ms_ = 0;
    decoded_stamp_.reset();
    receiver_recovery_->SetLag(std::nullopt, 0);
  }
  void TrackCodec(int payload, const webrtc::SdpAudioFormat& f) {
    if (payload >= 0 && static_cast<size_t>(payload) < opus_payloads_.size())
      opus_payloads_[payload] = f.clockrate_hz == 48000 &&
          (f.name == "opus" || f.name == "OPUS" || f.name == "Opus");
  }
  // NetEq may attach packet metadata only to its first 10-ms block. Carry
  // that real witness across subsequent blocks, bounded to the packet span;
  // never infer an output clock from arrival order or a periodic tone.
  bool UpdateDecodedClock(const webrtc::AudioFrame& frame) {
    if (!frame.packet_infos_.empty()) {
      decoded_stamp_.reset();
      for (const auto& info : frame.packet_infos_) {
        if (rtp_lag_.MatchesPacket(info.ssrc(), info.rtp_timestamp(), info.sequence_number()) &&
            std::llabs(static_cast<int32_t>(frame.timestamp_ - info.rtp_timestamp())) <=
                (frame_headroom_ms_ + 20) * 48) {
          decoded_stamp_ = info.rtp_timestamp();
          break;
        }
      }
    }
    return decoded_stamp_ &&
        std::llabs(static_cast<int32_t>(frame.timestamp_ - *decoded_stamp_)) <=
            (frame_headroom_ms_ + 20) * 48;
  }
  // A short nominal queue must not erase the reserve NetEq actually needs
  // for network jitter. Otherwise an arrival burst is trimmed, NetEq refills
  // that reserve, and the following burst creates another underrun. Preserve
  // the adaptive target plus packet-arrival/decoder headroom. On healthy paths
  // the old packet-sized budget still bounds device-stall catch-up.
  // The ceiling permits adaptation; it does not force a 500-ms target, change
  // packetization or relax a stricter caller-supplied maximum. The packet
  // buffer and the 16-pull callback limit remain bounded independently.
  static constexpr int kMaximumAdaptiveTargetMs = 500;
  static constexpr int kRenderBlockMs = 10;
  int JitterReserveMs(int64_t now_us) {
    const int target = std::clamp(inner_->TargetDelayMs(), 0, kMaximumAdaptiveTargetMs);
    const int headroom_ms = 2 * frame_headroom_ms_;
    const int target_reserve_ms = target + headroom_ms;
    // A late batch can already contain the speech needed to bridge the next
    // arrival gap while NetEq still reports the old target. When the target
    // is low, use that evidence only for a gap that fits the reserve. When
    // NetEq is already using a large reserve, cap the extra headroom instead
    // of dropping it abruptly on an even later arrival.
    const int ceiling_ms = applied_target_ceiling_ms_ > 0
        ? applied_target_ceiling_ms_ : kMaximumAdaptiveTargetMs;
    // A burst that drains through a paced link can overlap one more encoded
    // packet while decoder/render headroom is occupied. Bound the measured
    // arrival allowance separately from the two packets of decoder headroom.
    const int max_reserve_ms = ceiling_ms + 2 * headroom_ms;
    const int recent_ms = rtp_lag_.RecentArrivalVariationMs(now_us);
    const bool adaptive = target_reserve_ms > NominalRecoveryBudgetMs();
    // A paced release can temporarily report more variation than we can
    // retain. Allow a bounded overshoot to inform the first reserve without
    // retaining that overshoot or treating long stalls as sustained jitter.
    const int max_onset_variation_ms = max_reserve_ms + 2 * headroom_ms;
    const int measured_ms = !adaptive && recent_ms > max_onset_variation_ms
        ? target_reserve_ms
        : std::max(target_reserve_ms, std::min(recent_ms + headroom_ms, max_reserve_ms));
    // The recent arrival maximum expires in 500-ms buckets. Removing the
    // full allowance at that boundary can skip several speech blocks in
    // one callback. Retire it at 200 ms of reserve per second so NetEq can
    // time-scale available speech first. Smooth at most 100 ms of excess
    // (500 ms of render time). New jitter takes effect at once, and low-target
    // device-stall catch-up keeps its immediate budget.
    constexpr int64_t kUsPerMsOfRetiredReserve = 5000;
    constexpr int kMaximumRetiringReserveMs = 100;
    if (adaptive && now_us >= arrival_reserve_at_us_) {
      const int64_t retired_ms = (now_us - arrival_reserve_at_us_) /
          kUsPerMsOfRetiredReserve;
      const int64_t remaining_ms = std::min({max_reserve_ms, arrival_reserve_ms_,
          measured_ms + kMaximumRetiringReserveMs}) - retired_ms;
      if (remaining_ms > measured_ms) return static_cast<int>(remaining_ms);
    }
    arrival_reserve_ms_ = measured_ms;
    arrival_reserve_at_us_ = now_us;
    return measured_ms;
  }
  int NominalRecoveryBudgetMs() const {
    return std::clamp(80 + 2 * frame_headroom_ms_, 120, 200);
  }
  bool ApplyTargetCeiling() {
    int ceiling = kMaximumAdaptiveTargetMs;
    if (requested_maximum_delay_ms_ > 0)
      ceiling = std::min(ceiling, requested_maximum_delay_ms_);
    if (ceiling == applied_target_ceiling_ms_) return true;
    if (!inner_->SetMaximumDelay(ceiling)) return false;
    applied_target_ceiling_ms_ = ceiling;
    return true;
  }
  int frame_headroom_ms_ = 20;
  int arrival_reserve_ms_ = 0;
  int64_t arrival_reserve_at_us_ = 0;
  int requested_maximum_delay_ms_ = 0;
  int applied_target_ceiling_ms_ = -1;
  // Outlives the controller and packet-buffer stopwatches inside inner_.
  // The decoder's own timer still counts all decoded blocks.
  std::unique_ptr<webrtc::TickTimer> arrival_clock_;
  std::unique_ptr<webrtc::NetEq> inner_;
  std::shared_ptr<PlayoutRecoveryStats> stats_;
  std::shared_ptr<StreamAudioRecovery> receiver_recovery_;
  uint32_t registered_ssrc_ = 0;
  webrtc::AudioFrame scratch_;
  PlayoutTrace trace_;
  AudioRtpLag rtp_lag_;
  std::array<bool, 128> opus_payloads_{};
  uint64_t packet_buffer_flushes_ = 0;
  std::optional<uint32_t> decoded_stamp_;
};
class ArrivalClockControllerFactory final : public webrtc::NetEqControllerFactory {
 public:
  explicit ArrivalClockControllerFactory(webrtc::TickTimer* clock) : clock_(clock) {}
  std::unique_ptr<webrtc::NetEqController> Create(const webrtc::Environment& env,
      const webrtc::NetEqController::Config& config) const override {
    auto timed_config = config;
    timed_config.tick_timer = clock_;
    return MakeConversationNetEqController(env, timed_config);
  }
 private:
  webrtc::TickTimer* clock_;
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
    webrtc::NetEqImpl::Dependencies deps(env, config, std::move(decoder), controller);
    // NetEq's default packet buffer shares its decoder tick timer. Catch-up
    // performs several decoder pulls within one render callback; counting
    // those as elapsed waiting time invents queue delay and feeds it back to
    // the controller. Use the same render clock as packet-arrival history.
    deps.packet_buffer = std::make_unique<webrtc::PacketBuffer>(
        env.field_trials(), config.max_packets_in_buffer, clock.get(), deps.stats.get());
    auto inner = std::make_unique<webrtc::NetEqImpl>(config, std::move(deps));
    return std::make_unique<RecoveringNetEq>(
        std::move(inner), stats_, std::move(clock), config.max_delay_ms);
  }
 private:
  std::shared_ptr<PlayoutRecoveryStats> stats_;
};
}  // namespace veil_media
#endif
