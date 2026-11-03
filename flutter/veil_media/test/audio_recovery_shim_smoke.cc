// SPDX-License-Identifier: MIT
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <vector>

#include "modules/rtp_rtcp/source/rtcp_packet/receiver_report.h"
#include "modules/rtp_rtcp/source/rtcp_packet/transport_feedback.h"
#include "rtc_base/time_utils.h"
#include "veil_transport_shim.h"

static std::vector<uint8_t> sent;
static unsigned sends = 0;
static int send_result = 0;
extern "C" int veil_media_send_datagram(uint64_t, const uint8_t* p, size_t n) {
  sent.assign(p, p + n);
  ++sends;
  return send_result;
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
  {
    VeilTransportShim source(199, nullptr, nullptr, nullptr, nullptr);
    source.SetLocalVideoSsrc(33);
    source.Start();
    std::vector<uint8_t> rtp{0x80, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 33, 7};
    webrtc::PacketOptions options;
    options.is_media = true;
    require(source.SendRtp(rtp, options), "original RTP not admitted");
    send_result = 1;
    options.is_media = false;  // Real WebRTC excludes NACK repair and padding.
    require(!source.SendRtp(rtp, options), "repair admission failure hidden");
    auto snapshot = source.video_send_stats();
    require(snapshot.dropped == 1 && snapshot.source_dropped == 0,
            "repair failure counted as new original loss");
    options.is_media = true;
    rtp[3] = 2;
    require(!source.SendRtp(rtp, options), "original admission failure hidden");
    snapshot = source.video_send_stats();
    require(snapshot.dropped == 2 && snapshot.source_dropped == 1,
            "original admission failure not distinguished");
    send_result = 0;
    source.Stop();
  }
  // Exact TWCC says only a padding probe was lost: it must not become an
  // application-level persistent image-loss event. Raw RR remains unchanged.
  for (int scenario = 0; scenario < 9; ++scenario) {
    VeilTransportShim probe(198, nullptr, nullptr, nullptr, nullptr);
    probe.SetLocalVideoSsrc(33);
    probe.SetIndependentTransportFeedback(true);
    probe.Start();
    const auto began = webrtc::TimeMicros();
    for (int seq = 1; seq <= 5; ++seq) {
      std::vector<uint8_t> packet{0x90, 96, 0, uint8_t(seq), 0, 0, 0, 1,
          0, 0, 0, 33, 0xbe, 0xde, 0, 1, 0x11, 0, uint8_t(seq), 0, 7};
      if (seq == 2 && scenario != 1 && scenario != 2 && scenario != 8) {
        packet[0] |= 0x20; packet.back() = 1;
      }
      webrtc::PacketOptions options;
      require(probe.SendRtp(packet, options), "TWCC fixture not sent");
    }
    const auto report = [&](int high, int lost, bool twcc, int64_t at) {
      webrtc::rtcp::ReceiverReport rr;
      rr.SetSenderSsrc(44);
      webrtc::rtcp::ReportBlock block;
      block.SetMediaSsrc(33);
      block.SetCumulativeLost(lost);
      block.SetFractionLost(lost ? 32 : 0);
      block.SetExtHighestSeqNum(high);
      rr.AddReportBlock(block);
      const auto built = rr.Build();
      std::vector<uint8_t> compound(built.data(), built.data()+built.size());
      if (twcc) {
        webrtc::rtcp::TransportFeedback feedback;
        feedback.SetSenderSsrc(44);
        feedback.SetMediaSsrc(scenario == 3 ? 11 : 33);
        feedback.SetBase(1, webrtc::Timestamp::Micros(began));
        const int feedback_high = scenario == 4 ? 6 : high;
        for (int n=1; n<=feedback_high; ++n) {
          if (n != 2 || (scenario == 2 && high >= 4))
            feedback.AddReceivedPacket(n, webrtc::Timestamp::Micros(began+n*1000));
        }
        const auto bytes = feedback.Build();
        compound.insert(compound.end(), bytes.data(), bytes.data()+bytes.size());
      }
      if (scenario == 5) compound.insert(compound.end(), {0x80, 204, 0, 1});
      AudioRecoveryFeedbackTest::Observe(probe, compound, at);
    };
    report(1, 0, false, began+100'000);
    if (scenario == 6) probe.SetIndependentTransportFeedback(false);
    report(3, 1, scenario != 7, began+200'000);
    if (scenario == 8) {
      // A new transport sequence carrying the same original RTP packet is
      // a successful NACK retransmission, not a new image or a new gap.
      std::vector<uint8_t> repair{0x90, 96, 0, 2, 0, 0, 0, 1,
          0, 0, 0, 33, 0xbe, 0xde, 0, 1, 0x11, 0, 6, 0, 7};
      webrtc::PacketOptions options;
      require(probe.SendRtp(repair, options), "repair fixture not sent");
    }
    report(scenario == 8 ? 6 : 4, 1, scenario != 7, began+3'300'000);
    const bool expect_event = scenario == 1 || scenario == 3 || scenario == 4 ||
                              scenario == 6 || scenario == 7;
    require((probe.video_feedback().persistent_loss_report_us > 0) == expect_event,
            "TWCC payload loss / padding / fallback / retransmission classification failed");
    require(scenario == 5 || probe.video_feedback().loss_pct > 0,
            "raw RR loss was erased instead of classifying application evidence");
    probe.Stop();
  }
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
  // Video source probes require remote decoded frames, not padding or an
  // audio report. Verify the real send and compound parser together.
  receiver.SetLocalVideoSsrc(44);
  sender.SetLocalVideoSsrc(33);
  const auto video_now = webrtc::TimeMicros();
  receiver.SetLocalVideoDelivery(33, 1200, 1, 0xfffffff0u, 70, video_now);
  const auto video_compound = sent;
  require(video_compound.size() == 8 + 64, "video delivery compound missing");
  AudioRecoveryFeedbackTest::Observe(sender, video_compound, video_now + 10);
  const auto delivery = sender.video_delivery_json(video_now + 10);
  require(delivery.find("\"frames\":1") != std::string::npos,
          "decoded video delivery report missing");
  require(delivery.find("\"sent_timestamp_valid\":false") != std::string::npos,
          "an unstarted source invented a timestamp watermark");
  const auto zero_clock = sender.video_delivery_json(video_now + 10, 0, 1200, true);
  require(zero_clock.find("\"sent_timestamp_valid\":true") != std::string::npos &&
          zero_clock.find("\"sent_timestamp\":0") != std::string::npos,
          "a valid zero RTP clock was confused with an unstarted source");
  AudioRecoveryFeedbackTest::Observe(sender, video_compound, video_now + 20);
  require(sender.video_delivery_json(video_now + 20) == delivery,
          "replayed delivery renewed freshness");
  require(sender.video_delivery_json(video_now + 3'000'011) == "{}",
          "stale video ACK earned source capacity");
  for (bool duplicate : {false, true}) {
    VeilTransportShim clean(88, nullptr, nullptr, nullptr, nullptr);
    clean.SetLocalVideoSsrc(33);
    clean.Start();
    auto bad = video_compound;
    if (duplicate) bad.insert(bad.end(), video_compound.end()-64, video_compound.end());
    else bad.insert(bad.end(), {0x80, 204, 0, 1});
    AudioRecoveryFeedbackTest::Observe(clean, bad, video_now + 30);
    require(clean.video_delivery_json(video_now + 30) == "{}",
            "bad compound partially published video ACK");
    clean.SetLocalVideoSsrc(55);
    AudioRecoveryFeedbackTest::Observe(clean, video_compound, video_now + 40);
    require(clean.video_delivery_json(video_now + 40) == "{}", "foreign video ACK applied");
    clean.Stop();
  }
  auto bad_video = video_compound;
  bad_video.back() = 1;
  AudioRecoveryFeedbackTest::Observe(sender, bad_video, video_now + 50);
  require(sender.video_delivery_json(video_now + 50) == delivery,
          "reserved video fields were accepted");
  // The send path rejects future samples and retains its 950-ms cadence.
  std::this_thread::sleep_for(std::chrono::milliseconds(960));
  const auto target_now = webrtc::TimeMicros();
  receiver.SetLocalVideoDelivery(33, 2400, 2, 0x10u, 290, target_now, 260);
  const auto with_target = sent;
  require(with_target.size() == video_compound.size() &&
          veil_media::RecoveryRead32(with_target.data()+16) == veil_media::kVideoDeliveryTargetAppName,
          "measured target did not select fixed-size VVD2");
  for (const auto* packet : {&video_compound, &with_target}) {
    for (size_t length = 0; length < 60; ++length) {
      require(!veil_media::DecodeVideoDelivery({packet->data()+12, length}, 0),
              "truncated delivery report was accepted");
    }
  }
  AudioRecoveryFeedbackTest::Observe(sender, with_target, target_now + 10);
  require(sender.video_delivery_json(target_now + 10).find("\"target_delay_ms\":260") != std::string::npos,
          "VVD2 target did not cross the real compound parser");
  for (int variant = 0; variant < 6; ++variant) {
    VeilTransportShim clean(89, nullptr, nullptr, nullptr, nullptr);
    clean.SetLocalVideoSsrc(33);
    clean.Start();
    auto packet = with_target;
    if (variant == 0 || variant == 1)
      veil_media::RecoveryWrite32(packet.data()+64, variant == 0 ? 0 : 60000);
    if (variant == 2) veil_media::RecoveryWrite32(packet.data()+64, 60001);
    if (variant == 3) packet.back() = 1;
    if (variant == 4) packet[8] = 0x81;  // Unsupported APP subtype.
    if (variant == 5) packet.insert(packet.end(), video_compound.end()-64, video_compound.end());
    AudioRecoveryFeedbackTest::Observe(clean, packet, target_now + 20);
    const auto json = clean.video_delivery_json(target_now + 20);
    require(variant < 2 ? json.find(std::string("\"target_delay_ms\":") +
              (variant == 0 ? "0" : "60000")) != std::string::npos : json == "{}",
            "VVD2 bounds/reserved/subtype/mixed-duplicate check failed");
    clean.Stop();
  }
  receiver.Stop();
  receiver.SendRtcp(original, {});
  require(sent == original, "stopped source appended recovery");
  std::puts(
      "ok production shim compound parsing, legacy feedback, freshness, replay "
      "and stopped/video sources");
}
