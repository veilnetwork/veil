/* SPDX-License-Identifier: MIT */
// Deterministic real Opus/NetEq: identical packets and render deadlines for
// stock and production. No device/network, wall-time gates or PCM export.
// PLC played by the renderer is distinct from concealed samples decoded by
// extra catch-up pulls. A startup warmup is excluded from both metrics.
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <memory>
#include <random>
#include <vector>
#include "api/audio_codecs/builtin_audio_decoder_factory.h"
#include "api/environment/environment_factory.h"
#include "api/neteq/default_neteq_factory.h"
#include "rtc_base/time_utils.h"
#include "system_wrappers/include/clock.h"
#include "third_party/opus/src/include/opus.h"
#include "veil_playout_recovery.h"

static void need(bool valid, const char* message) {
  if (!valid) {
    std::fprintf(stderr, "%s\n", message);
    std::exit(1);
  }
}
struct Wall : webrtc::ClockInterface {
  int64_t us = 1000000;
  int64_t TimeNanos() const override { return us * 1000; }
};
constexpr uint32_t origin = 0xf1234000;
struct Packet {
  int at, begin;
  uint16_t sequence;
  std::vector<uint8_t> bytes;
};
static std::vector<Packet> encode(const std::vector<int16_t>& speech, int ms) {
  int error = 0;
  std::unique_ptr<OpusEncoder, decltype(&opus_encoder_destroy)> enc(
      opus_encoder_create(48000, 1, OPUS_APPLICATION_VOIP, &error), opus_encoder_destroy);
  need(enc && error == OPUS_OK, "Opus creation");
  need(opus_encoder_ctl(enc.get(), OPUS_SET_BITRATE(24000)) == 0, "bitrate");
  need(opus_encoder_ctl(enc.get(), OPUS_SET_DTX(0)) == 0, "dtx");
  need(opus_encoder_ctl(enc.get(), OPUS_SET_INBAND_FEC(1)) == 0, "fec");
  need(opus_encoder_ctl(enc.get(), OPUS_SET_PACKET_LOSS_PERC(5)) == 0, "loss hint");
  std::vector<Packet> result;
  std::vector<int16_t> pcm(ms*48);
  std::array<uint8_t, 1500> data{};
  for (int at = 0; at < 33000; at += ms) {
    // Sample-and-hold 16 -> 48 kHz, identical for every receiver. This is a
    // packet/decoder regression, not a resampler or speech-quality benchmark.
    for (int i = 0; i < ms*48; ++i) pcm[i] = speech[((at*48+i)/3) % speech.size()];
    const int size = opus_encode(enc.get(), pcm.data(), pcm.size(), data.data(), data.size());
    need(size > 0, "Opus encode");
    // Include a real sequence wrap in the steady-state observation window.
    result.push_back({at + ms + 60, at, static_cast<uint16_t>(65000 + result.size()),
                      {data.begin(),data.begin()+size}});
  }
  return result;
}
static std::vector<Packet> network(const std::vector<Packet>& encoded, int profile, int seed) {
  std::mt19937 rng(seed);
  std::vector<Packet> result;
  for (auto p : encoded) {
    // 0 is the fixed 60-ms path; 1/2 add uniform jitter and reorder.
    if (profile == 1) p.at += rng()%101;
    if (profile == 2) p.at += rng()%201;
    // A route step, then periodic buffered bursts after a clean start.
    if (profile == 3 && p.begin >= 8000 && p.begin < 18000) p.at += 180;
    if (profile == 4 && p.begin >= 4000 && p.begin % 1000 < 200) p.at += 250;
    if (profile == 5) {
      // The only profile that actually removes packets from the network.
      p.at += rng()%121;
      if (rng()%100 < 3) continue;
    }
    result.push_back(std::move(p));
  }
  std::stable_sort(result.begin(),result.end(),[](auto& a, auto& b){return a.at<b.at;});
  return result;
}
struct Metrics {
  uint64_t played_plc = 0, conceal = 0, discarded = 0, packet_discarded = 0, events = 0, accelerate = 0;
  int max_gap = 0, q95 = 0, max_target = 0;
};
static Metrics run(const std::vector<Packet>& packets, bool custom) {
  Wall wall;
  auto* prior = webrtc::SetClockForTesting(&wall);
  Metrics result;
  {
    webrtc::SimulatedClock clock(1000000);
    const auto env = webrtc::CreateEnvironment(&clock);
    webrtc::NetEq::Config config;
    config.sample_rate_hz = 48000;
    config.max_packets_in_buffer = 30;
    config.enable_fast_accelerate = true;
    auto recovery = std::make_shared<veil_media::PlayoutRecoveryStats>();
    std::unique_ptr<webrtc::NetEq> neteq;
    if (custom) neteq = veil_media::RecoveringNetEqFactory(recovery).Create(
        env, config, webrtc::CreateBuiltinAudioDecoderFactory());
    else neteq = webrtc::DefaultNetEqFactory().Create(
        env, config, webrtc::CreateBuiltinAudioDecoderFactory());
    need(neteq && neteq->RegisterPayloadType(111,
        webrtc::SdpAudioFormat("opus",48000,2,{{"stereo","0"},{"useinbandfec","1"}})),"decoder");
    size_t index = 0;
    std::vector<int> queues;
    webrtc::NetEqLifetimeStatistics base{};
    uint64_t discard_base = 0;
    uint64_t output_energy = 0;
    int gap = 0;
    for (int at = 0; at < 30000; at += 10) {
      wall.us = 1000000 + at*1000;
      while (index < packets.size() && packets[index].at <= at) {
        const auto& p = packets[index++];
        webrtc::RTPHeader h{};
        h.ssrc=17; h.payloadType=111; h.sequenceNumber=p.sequence;
        h.timestamp=origin + static_cast<uint32_t>(p.begin*48);
        need(neteq->InsertPacket(h,p.bytes,webrtc::RtpPacketInfo(h,
            webrtc::Timestamp::Micros(wall.us))) == 0, "packet insertion");
      }
      webrtc::AudioFrame frame;
      bool muted=false;
      need(neteq->GetAudio(&frame,&muted) == 0,"decode");
      need(frame.samples_per_channel_ == 480 && frame.num_channels_ == 1,"format");
      if (at == 1500) { base=neteq->GetLifetimeStatistics(); discard_base=recovery->discarded_ms.load(); }
      if (at > 1500) {
        for (size_t i = 0; i < frame.samples_per_channel_; ++i) {
          const int64_t sample = frame.data()[i];
          output_energy += static_cast<uint64_t>(sample * sample);
        }
        if (frame.speech_type_ == webrtc::AudioFrame::kPLC ||
            frame.speech_type_ == webrtc::AudioFrame::kPLCCNG || muted) { gap += 10; result.played_plc += 10; }
        else gap = 0;
        result.max_gap=std::max(result.max_gap,gap);
        const auto state=neteq->GetOperationsAndState();
        queues.push_back(state.current_buffer_size_ms);
        result.max_target=std::max(result.max_target,neteq->TargetDelayMs());
      }
      clock.AdvanceTimeMilliseconds(10);
    }
    const auto end=neteq->GetLifetimeStatistics();
    need(index > 300 && output_energy > 0 && queues.size() > 1000,
         "missing packet/PCM/render witnesses");
    result.conceal=(end.concealed_samples-base.concealed_samples)/48;
    result.events=end.concealment_events-base.concealment_events;
    result.discarded=recovery->discarded_ms.load()-discard_base;
    result.packet_discarded=end.packets_discarded-base.packets_discarded;
    result.accelerate=(end.removed_samples_for_acceleration-base.removed_samples_for_acceleration)/48;
    std::sort(queues.begin(),queues.end());
    result.q95=queues[queues.size()*95/100];
  }
  webrtc::SetClockForTesting(prior);
  return result;
}
int main(int argc,char**argv) {
  need(argc==2,"speech fixture");
  std::ifstream f(argv[1],std::ios::binary);
  std::vector<char> bytes((std::istreambuf_iterator<char>(f)),{});
  need(bytes.size()>32000 && bytes.size()%2==0,"fixture bytes");
  std::vector<int16_t> speech(bytes.size()/2);
  for(size_t i=0;i<speech.size();++i) speech[i]=static_cast<int16_t>(
      static_cast<unsigned char>(bytes[2*i]) | (static_cast<unsigned char>(bytes[2*i+1])<<8));
  std::puts("packet_ms,profile,custom,played_plc_ms,concealed_ms,max_plc_ms,conceal_events,hard_discard_ms,packet_discarded,accelerated_ms,queue_p95_ms,max_target_ms");
  bool passed = true;
  for (int seed : {197, 17, 41}) {
    std::printf("seed=%d\n", seed);
    for (int ms : {20, 40, 60}) {
      const auto encoded = encode(speech, ms);
      for (int profile = 0; profile < 6; ++profile) {
        const auto trace = network(encoded, profile, seed);
        std::array<Metrics, 2> pair{};
        for (bool custom : {false, true}) {
          const auto m = run(trace, custom);
          pair[custom] = m;
          std::printf("%d,%d,%d,%llu,%llu,%d,%llu,%llu,%llu,%llu,%d,%d\n",
              ms, profile, custom, (unsigned long long)m.played_plc,
              (unsigned long long)m.conceal, m.max_gap,
              (unsigned long long)m.events, (unsigned long long)m.discarded,
              (unsigned long long)m.packet_discarded,
              (unsigned long long)m.accelerate, m.q95, m.max_target);
          std::fflush(stdout);
        }
        // Lossless traces must not create repeated concealment just to hold
        // the old fixed queue ceiling. A route step still has a causal gap;
        // compare with the same decoder receiving the very same packets.
        if (profile != 5)
          passed &= pair[1].played_plc <= pair[0].played_plc;
        if (profile == 0)
          passed &= pair[0].played_plc == 0 && pair[1].discarded == 0;
      }
    }
  }
  need(passed, "jitter reserve policy created extra played concealment on lossless traffic");
  std::puts("PASS lossless jitter/reorder speech reserve across 20/40/60-ms Opus");
}
