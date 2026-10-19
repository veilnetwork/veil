// Endpoint conversation policy over the pinned WebRTC decision tree.
#ifndef VEIL_CONVERSATION_NETEQ_CONTROLLER_H_
#define VEIL_CONVERSATION_NETEQ_CONTROLLER_H_
#include <memory>
#include "api/environment/environment.h"
#include "modules/audio_coding/neteq/buffer_level_filter.h"
#include "modules/audio_coding/neteq/decision_logic.h"
#include "modules/audio_coding/neteq/delay_manager.h"
#include "modules/audio_coding/neteq/packet_arrival_history.h"

namespace veil_media {
class ConversationNetEqController final : public webrtc::DecisionLogic {
 public:
  ConversationNetEqController(
      webrtc::NetEqController::Config config,
      std::unique_ptr<webrtc::DelayManagerInterface> delay,
      std::unique_ptr<webrtc::PacketArrivalHistory> history,
      webrtc::PacketArrivalHistory* history_view)
      : webrtc::DecisionLogic(config, std::move(delay),
            std::make_unique<webrtc::BufferLevelFilter>(), std::move(history)),
        history_(history_view), clock_(config.tick_timer),
        stretching_(config.allow_time_stretching),
        countdown_(clock_->GetNewCountdown(6)) {}

  void SetSampleRate(int hz, size_t samples) override {
    webrtc::DecisionLogic::SetSampleRate(hz, samples);
    khz_ = hz / 1000;
  }
  void SoftReset() override {
    webrtc::DecisionLogic::SoftReset();
    previous_scale_ = false;
    countdown_ = clock_->GetNewCountdown(6);
  }
  void set_prev_time_scale(bool value) override {
    previous_scale_ = value;
    webrtc::DecisionLogic::set_prev_time_scale(value);
  }
  webrtc::NetEq::Operation GetDecision(const NetEqStatus& status,
                                      bool* reset) override {
    // Match the pinned decision tree's successful-timescale cooldown. A
    // requested but failed operation cannot pretend to have removed samples.
    if (previous_scale_ && IsScale(status.last_mode))
      countdown_ = clock_->GetNewCountdown(5);
    previous_scale_ = false;
    return webrtc::DecisionLogic::GetDecision(status, reset);
  }

 private:
  static bool IsScale(webrtc::NetEq::Mode mode) {
    using Mode = webrtc::NetEq::Mode;
    return mode == Mode::kAccelerateSuccess || mode == Mode::kAccelerateLowEnergy ||
        mode == Mode::kPreemptiveExpandSuccess || mode == Mode::kPreemptiveExpandLowEnergy;
  }
  webrtc::NetEq::Operation ExpectedPacketAvailable(NetEqStatus status) override {
    using Mode = webrtc::NetEq::Mode;
    using Op = webrtc::NetEq::Operation;
    // The base tree retains missing/future packets, decoder resets, CNG and
    // merge/FEC decisions. This hook runs only with the expected packet ready.
    if (stretching_ && status.last_mode != Mode::kExpand && !status.play_dtmf) {
      const auto stamp = status.target_timestamp -
          static_cast<uint32_t>(status.sync_buffer_samples);
      const int delay = history_->GetDelayMs(stamp);
      const int target = TargetLevelMs();
      const bool speech = status.next_packet && !status.next_packet->is_dtx &&
          !status.next_packet->is_cng &&
          (status.last_mode == Mode::kNormal || IsScale(status.last_mode));
      // Relative RTP age includes upstream delay. It cannot by itself prove
      // that speech is queued here: draining an almost empty receiver during
      // a late arrival/reorder burst manufactures concealment. Count actual
      // available samples, not a timestamp span which can include holes.
      const size_t samples = status.sync_buffer_samples +
          status.packet_buffer_info.num_samples;
      const int packet_ms = khz_ > 0
          ? static_cast<int>(packet_length_samples() / static_cast<size_t>(khz_)) : 0;
      // Preserve one complete packet and the actual recent arrival variation
      // before borrowing local queue headroom. Future packets beyond a hole
      // cannot fund speech acceleration ahead of that hole.
      const int reserve = std::max(target, history_->GetMaxDelayMs() + packet_ms) + 20;
      const bool contiguous = !status.packet_buffer_info.dtx_or_cng &&
          status.packet_buffer_info.num_packets > 0 &&
          status.packet_buffer_info.span_samples == status.packet_buffer_info.num_samples;
      const bool excess_samples = khz_ > 0 &&
          packet_ms > 0 && contiguous &&
          samples / static_cast<size_t>(khz_) >= static_cast<size_t>(reserve);
      // The target ALREADY includes the measured jitter quantile. The stock
      // target + maximum recent jitter + 20-ms guard kept ordinary speech
      // queued around 197 ms with a 140-ms target. Keep the real arrival
      // history and target, but do not charge that jitter twice for speech.
      // DTX/concealment transitions keep the stock guard and behavior.
      const int high = target + 20 +
          (speech && excess_samples ? 0 : history_->GetMaxDelayMs());
      if (delay >= high * 4) return Op::kFastAccelerate;
      if (!countdown_ || countdown_->Finished()) {
        if (delay >= high) return Op::kAccelerate;
        if (delay < target) return Op::kPreemptiveExpand;
      }
    }
    return Op::kNormal;
  }
  // The base owns this exact history and resets it on codec changes. No
  // substituted timestamps/delay statistics are fed to its delay estimator.
  webrtc::PacketArrivalHistory* history_;
  const webrtc::TickTimer* clock_;
  bool stretching_, previous_scale_ = false;
  int khz_ = 0;
  std::unique_ptr<webrtc::TickTimer::Countdown> countdown_;
};

inline std::unique_ptr<webrtc::NetEqController> MakeConversationNetEqController(
    const webrtc::Environment& env, webrtc::NetEqController::Config config) {
  auto history = std::make_unique<webrtc::PacketArrivalHistory>(config.tick_timer, 2000);
  auto* history_view = history.get();
  return std::make_unique<ConversationNetEqController>(config,
      std::make_unique<webrtc::DelayManager>(
          webrtc::DelayManager::Config(env.field_trials()), config.tick_timer),
      std::move(history), history_view);
}
}  // namespace veil_media
#endif
