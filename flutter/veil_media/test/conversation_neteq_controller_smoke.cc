#undef NDEBUG
#include "veil_playout_recovery.h"
#include "api/environment/environment_factory.h"
#include <cassert>
#include <cstdio>

using Op = webrtc::NetEq::Operation;
using Mode = webrtc::NetEq::Mode;
struct Fixture {
  webrtc::TickTimer clock;
  webrtc::Environment env = webrtc::CreateEnvironment();
  std::unique_ptr<webrtc::NetEqController> controller;
  webrtc::NetEqController::NetEqStatus status{};
  bool reset = false;
  explicit Fixture(bool conversation = true, int hz = 48000, bool stretch = true) {
    webrtc::NetEqController::Config config{stretch, false, 30, 0, &clock};
    if (conversation) {
      veil_media::ArrivalClockControllerFactory factory(&clock);
      controller = factory.Create(env, config);
    } else {
      webrtc::DefaultNetEqControllerFactory factory;
      controller = factory.Create(env, config);
    }
    controller->SetSampleRate(hz, hz / 100);
    webrtc::NetEqController::PacketArrivedInfo packet{};
    packet.packet_length_samples = hz / 50;
    packet.main_timestamp = 0;
    controller->PacketArrived(hz, true, packet);
    for (int i = 0; i < 12; ++i) clock.Increment();
    packet.main_timestamp = hz / 50;
    packet.main_sequence_number = 1;
    assert(controller->PacketArrived(hz, true, packet) == 100);
    for (int i = 0; i < 7; ++i) clock.Increment();
    status.target_timestamp = hz / 50;
    status.next_packet = webrtc::NetEqController::PacketInfo{status.target_timestamp, false, false};
    status.last_mode = Mode::kNormal;
    status.last_packet_samples = hz / 50;
    status.sync_buffer_samples = hz / 100;
    status.packet_buffer_info = {false, size_t(hz / 5), size_t(hz / 5), size_t(hz / 5), 10};
  }
  Op decide() { return controller->GetDecision(status, &reset); }
};

int main() {
  // Real history sees 100 ms arrival variation. The real delay manager still
  // starts at80ms. Stock WebRTC tolerates180ms here (80+100+20), even though
  // the expected speech is ready. Production wiring must gently accelerate.
  for (int hz : {8000, 16000, 32000, 48000}) {
    Fixture stock(false, hz), conversation(true, hz);
    assert(stock.controller->TargetLevelMs() == 80);
    assert(conversation.controller->TargetLevelMs() == 80);
    assert(stock.decide() == Op::kNormal);
    assert(conversation.decide() == Op::kAccelerate);
    assert(!conversation.reset);
  }
  for (int kind = 0; kind < 7; ++kind) {
    Fixture stock(false), conversation;
    for (auto* f : {&stock, &conversation}) {
      if (kind == 0) f->status.next_packet.reset();
      if (kind == 1) f->status.next_packet->timestamp += 960;
      if (kind == 2) f->status.play_dtmf = true;
      if (kind == 3) f->status.next_packet->is_dtx = true;
      if (kind == 4) f->status.next_packet->is_cng = true;
      if (kind == 5) f->status.last_mode = Mode::kExpand;
      if (kind == 6) f->status.last_mode = Mode::kCodecPlc;
    }
    assert(stock.decide() == conversation.decide());
  }
  {
    Fixture disabled(true, 48000, false);
    assert(disabled.decide() == Op::kNormal);
  }
  {
    // Old upstream delay with only30ms actually available is not a local
    // backlog. Accelerating it would create PLC in lossless reordered speech.
    Fixture stock(false), conversation;
    for (auto* f : {&stock, &conversation})
      f->status.packet_buffer_info = {false, 960, 4800, 4800, 1};
    assert(stock.decide() == Op::kNormal);
    assert(conversation.decide() == Op::kNormal);
  }
  {
    Fixture stock(false), conversation;
    for (auto* f : {&stock, &conversation})
      f->status.packet_buffer_info.span_samples = 19200;
    assert(stock.decide() == Op::kNormal);
    assert(conversation.decide() == Op::kNormal);
  }
  {
    Fixture f;
    assert(f.decide() == Op::kAccelerate);
    f.controller->set_prev_time_scale(true);
    f.status.last_mode = Mode::kAccelerateSuccess;
    assert(f.decide() == Op::kNormal);
    f.status.last_mode = Mode::kNormal;
    for (int i = 0; i < 4; ++i) f.clock.Increment();
    assert(f.decide() == Op::kNormal);
    f.clock.Increment();
    assert(f.decide() == Op::kAccelerate);
    f.controller->SoftReset();
    assert(f.decide() == Op::kNormal);
  }
  std::puts("conversation NetEq: real history/target retained, speech drains, loss/DTX/DTMF and timescale cooldown preserved");
}
