// SPDX-License-Identifier: MIT
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <vector>

#include "modules/rtp_rtcp/source/rtcp_packet/receiver_report.h"
#include "rtc_base/time_utils.h"
#include "veil_transport_shim.h"

static std::vector<uint8_t> sent;
static unsigned sends = 0;
extern "C" int veil_media_send_datagram(uint64_t, const uint8_t* p, size_t n) {
  sent.assign(p, p + n);
  ++sends;
  return 0;
}
extern "C" int veil_media_send_video_control_datagram(uint64_t,
                                                      const uint8_t* p,
                                                      size_t n) {
  sent.assign(p, p + n);
  return 0;
}
extern "C" int veil_media_set_recv_callback(
    uint64_t, void (*)(void*, const uint8_t*, size_t), void*) {
  return 0;
}
static void require(bool ok, const char* message) {
  if (!ok) {
    std::fprintf(stderr, "%s\n", message);
    std::exit(1);
  }
}
namespace veil_media {
// The production parser is entered after SDK authentication. Exercise it
// directly without constructing hardware devices or posting fake RTP.
class AudioRecoveryFeedbackTest {
 public:
  static void Observe(VeilTransportShim& shim, std::span<const uint8_t> bytes,
                      int64_t at) {
    shim.ObserveReceiverFeedback(bytes, at);
  }
};
}  // namespace veil_media
int main() {
  using namespace veil_media;
  webrtc::rtcp::ReceiverReport rr;
  rr.SetSenderSsrc(22);
  const auto bytes = rr.Build();
  const std::vector<uint8_t> original(bytes.data(),
                                      bytes.data() + bytes.size());
  VeilTransportShim receiver(1, nullptr, nullptr, nullptr, nullptr);
  receiver.SetLocalAudioSsrc(22);
  receiver.Start();
  const int64_t now = webrtc::TimeMicros();
  {
    VeilTransportShim measured(99, nullptr, nullptr, nullptr, nullptr);
    measured.SetLocalAudioSsrc(11);
    measured.Start();
    auto conceal = [&](uint64_t seq, uint64_t samples, uint32_t age, int64_t at) {
      const auto app = EncodeAudioConcealment(22, {11, seq, 19, samples, age, true});
      auto packet = original;
      packet.insert(packet.end(), app.begin(), app.end());
      AudioRecoveryFeedbackTest::Observe(measured, packet, at);
    };
    conceal(1, 10000, kUnknownRecoveryAge, now);
    conceal(2, 10000 + 11*48, 0, now + 1000);
    conceal(3, 10000 + 38*48, 0, now + 2000);
    require(measured.peer_audio_soft_loss(now + 2000).samples == 38*48 &&
                measured.peer_audio_soft_loss(now + 2000).report_us == 0,
            "real shim promoted small concealment to significant loss");
    auto recovery = [&](uint64_t seq, uint64_t ms, int64_t at) {
      const auto app = EncodeAudioRecovery(22, 11, seq, {true, 19, ms, at}, at, at);
      auto packet = original;
      packet.insert(packet.end(), app.begin(), app.end());
      AudioRecoveryFeedbackTest::Observe(measured, packet, at);
    };
    recovery(1, 0, now + 3000);
    recovery(2, 85, now + 4000);
    const auto damage = measured.peer_audio_soft_loss(now + 4000);
    require(damage.supported && damage.samples == 123*48 && damage.report_us == 0,
            "real shim promoted a short moderate burst to a video cut");
    recovery(2, 85, now + 3'001'000);
    require(measured.peer_audio_soft_loss(now + 3'001'000).report_us == 0,
            "real shim replay manufactured sustained loss");
    recovery(3, 86, now + 3'002'000);
    const auto sustained = measured.peer_audio_soft_loss(now + 3'002'000);
    require(sustained.samples == 124*48 && sustained.report_us == now + 3'002'000,
            "real shim lost sustained authenticated damage");
    recovery(3, 86, now + 3'003'000);
    require(measured.peer_audio_soft_loss(now + 3'003'000).report_us == sustained.report_us,
            "real shim replay renewed significant loss");
    measured.Stop();
  }
  receiver.SetLocalAudioPlayout(11, 1, 80, now);
  receiver.SetLocalAudioRecovery(11, 1, {true, 1, 20, now}, now);
  require(receiver.SendRtcp(original, {}), "source RTCP refused");
  const auto compound = sent;
  require(compound.size() == original.size() + 28 + 48,
          "VAP1 prefix or VAP2 framing changed");
  VeilTransportShim sender(2, nullptr, nullptr, nullptr, nullptr);
  sender.SetLocalAudioSsrc(11);
  sender.Start();
  AudioRecoveryFeedbackTest::Observe(sender, compound, now + 1000);
  require(sender.audio_playout_feedback().delay_ms == 80,
          "old VAP1 feedback disappeared");
  require(sender.peer_audio_recovery_supported(),
          "new feedback was not recognized");
  require(sender.peer_audio_recovery_report_us(now + 1000) == now + 1000,
          "fresh receiver event disappeared");
  AudioRecoveryFeedbackTest::Observe(sender, compound, now + 2000);
  require(sender.peer_audio_recovery_report_us(now + 2000) == now + 1000,
          "compound replay renewed loss");
  receiver.SetLocalAudioPlayout(11, 2, 75, now);
  receiver.SetLocalAudioRecovery(11, 2, {true, 1, 20, now}, now);
  receiver.SendRtcp(original, {});
  AudioRecoveryFeedbackTest::Observe(sender, sent, now + 3000);
  require(sender.peer_audio_recovery_report_us(now + 3000) == now + 1000,
          "cached event in fresh report renewed loss");
  const auto snapshot = sender.peer_audio_recovery_snapshot();
  receiver.SetLocalAudioRecovery(11, 3, {true, 1, 40, now}, now);
  receiver.SendRtcp(original, {});
  AudioRecoveryFeedbackTest::Observe(sender, sent, now + 4000);
  const auto next_snapshot = sender.peer_audio_recovery_snapshot();
  require(snapshot.Sample().origin == 1 && snapshot.Sample().discarded_ms == 20 &&
              snapshot.FreshReportUs(now + 4000) == now + 1000 &&
              next_snapshot.Sample().discarded_ms == 40 &&
              next_snapshot.FreshReportUs(now + 4000) == now + 4000,
          "event counter and witness timestamp are not one stable snapshot");
  VeilTransportShim untouched(3, nullptr, nullptr, nullptr, nullptr);
  untouched.SetLocalAudioSsrc(11);
  untouched.Start();
  auto malformed = compound;
  malformed.insert(malformed.end(), {0x80, 204, 0, 1});
  AudioRecoveryFeedbackTest::Observe(untouched, malformed, now + 1000);
  require(!untouched.peer_audio_recovery_supported() &&
              !untouched.audio_playout_feedback().supported,
          "truncated compound partially applied feedback");
  malformed = compound;
  malformed.insert(malformed.end(), compound.end() - 48, compound.end());
  AudioRecoveryFeedbackTest::Observe(untouched, malformed, now + 1000);
  require(!untouched.peer_audio_recovery_supported(),
          "duplicate recovery blocks partially applied");
  const std::vector<uint8_t> legacy(compound.begin(), compound.end() - 48);
  AudioRecoveryFeedbackTest::Observe(untouched, legacy, now + 1000);
  require(untouched.audio_playout_feedback().delay_ms == 80 &&
              !untouched.peer_audio_recovery_supported(),
          "legacy report enabled decoded-loss feedback");
  receiver.SendVideoRtcp(original, {});
  require(sent == original, "recovery was appended to video RTCP");
  // Concealment has its own APP and witness; it never changes VAP2 counters.
  const auto before_baseline = sends;
  receiver.SetLocalAudioConcealment(11, 1, 9, 1000, 100, webrtc::TimeMicros());
  require(receiver.local_audio_concealment_report_us(webrtc::TimeMicros()) == 0,
          "local native history appeared as fresh damage");
  require(sends == before_baseline, "historical concealment sent an impulse");
  std::this_thread::sleep_for(std::chrono::milliseconds(1));
  receiver.SetLocalAudioConcealment(11, 2, 9, 1480, 100, webrtc::TimeMicros());
  const auto local_event = receiver.local_audio_concealment_report_us(webrtc::TimeMicros());
  require(local_event > 0 &&
              receiver.local_audio_concealment_report_us(webrtc::TimeMicros()) == local_event,
          "local incoming event missing or renewed by a read");
  require(sends == before_baseline + 1, "fresh concealment waited for periodic RTCP");
  const auto concealed = sent;
  require(concealed.size() == 8 + 28 + 48 + 48,
          "supplemental concealment compound framing changed");
  AudioRecoveryFeedbackTest::Observe(sender, concealed, now + 5000);
  require(sender.peer_audio_concealment_report_us(now + 5000) == now + 5000 &&
              sender.peer_audio_recovery_snapshot().Sample().discarded_ms == 40,
          "concealment was lost or mislabeled as discarded speech");
  AudioRecoveryFeedbackTest::Observe(sender, concealed, now + 6000);
  std::this_thread::sleep_for(std::chrono::milliseconds(1));
  receiver.SetLocalAudioConcealment(11, 3, 9, 1960, 100, webrtc::TimeMicros());
  require(sends == before_baseline + 1, "supplemental reports are not rate bounded");
  receiver.SendRtcp(original, {});
  const auto next_concealed = sent;
  AudioRecoveryFeedbackTest::Observe(sender, next_concealed, now + 7000);
  require(sender.peer_audio_concealment_report_us(now + 7000) == now + 7000,
          "rate-limited event was absent from regular RTCP");
  receiver.SendRtcp(original, {});
  AudioRecoveryFeedbackTest::Observe(sender, sent, now + 8000);
  require(sender.peer_audio_concealment_report_us(now + 8000) == now + 7000,
          "cached concealment renewed its witness");
  for (bool duplicate : {false, true}) {
    VeilTransportShim clean(4, nullptr, nullptr, nullptr, nullptr);
    clean.SetLocalAudioSsrc(11);
    clean.Start();
    auto bad = next_concealed;
    if (duplicate) bad.insert(bad.end(), next_concealed.end() - 48, next_concealed.end());
    else bad[bad.size() - 1] = 2;  // invalid VAP3 flags, after valid VAP1/VAP2
    AudioRecoveryFeedbackTest::Observe(clean, bad, now + 9000);
    require(!clean.audio_playout_feedback().supported &&
                !clean.peer_audio_recovery_supported() &&
                clean.peer_audio_concealment_report_us(now + 9000) == 0,
            "malformed/duplicate concealment partially published compound");
    clean.Stop();
  }
  receiver.SendVideoRtcp(original, {});
  require(sent == original, "concealment was appended to video RTCP");
  receiver.Stop();
  receiver.SendRtcp(original, {});
  require(sent == original, "stopped source appended recovery");
  std::puts(
      "ok production shim compound parsing, legacy feedback, freshness, replay "
      "and stopped/video sources");
}
