// SPDX-License-Identifier: MIT
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "modules/rtp_rtcp/source/rtcp_packet/receiver_report.h"
#include "rtc_base/time_utils.h"
#include "veil_transport_shim.h"

static std::vector<uint8_t> sent;
extern "C" int veil_media_send_datagram(uint64_t, const uint8_t* p, size_t n) {
  sent.assign(p, p + n);
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
  receiver.Stop();
  receiver.SendRtcp(original, {});
  require(sent == original, "stopped source appended recovery");
  std::puts(
      "ok production shim compound parsing, legacy feedback, freshness, replay "
      "and stopped/video sources");
}
