#include <array>
#include <cstdio>

#include "api/call/bitrate_allocation.h"
#include "api/environment/environment_factory.h"
#include "bounded_audio_encoder.h"
#include "veil_audio_adaptor_config.h"
#include "modules/rtp_rtcp/include/rtp_header_extension_map.h"
#include "modules/rtp_rtcp/source/rtp_header_extensions.h"
#include "modules/rtp_rtcp/source/rtp_packet.h"
#include "system_wrappers/include/clock.h"
#include "third_party/opus/src/include/opus.h"

static int check_framing_budget() {
  webrtc::RtpHeaderExtensionMap extensions;
  if (!extensions.Register<webrtc::TransportSequenceNumber>(
          webrtc::RtpHeaderExtensionId(1))) return 20;
  webrtc::RtpPacket rtp(&extensions);
  if (!rtp.SetExtension<webrtc::TransportSequenceNumber>(0)) return 21;
  // Characterize actual allocation/duration behavior, not a production
  // controller policy. Raising its ceiling alone failed mixed-call quality.
  for (const auto& profile : std::array<std::array<int, 3>, 9>{{
           {209, 160000, 20}, {360, 160000, 40},
           {509, 160000, 60}, {509, 183736, 40},
           // The observed allocation funds 24-kbit speech plus 40-ms
           // framing. A second 25% discount must not force 60-ms packets.
           {360, 131840, 40}, {360, 96000, 60},
           {509, 165000, 40},
           // The short packet must still leave transport/RTCP headroom.
           {360, 120000, 60}, {209, 120000, 40}}}) {
    const int route_overhead = profile[0];
    webrtc::SimulatedClock clock(0);
    const auto env = webrtc::CreateEnvironment(&clock);
    auto factory = webrtc::make_ref_counted<veil_media::BoundedAudioEncoderFactory>();
    auto encoder = factory->Create(env,
        webrtc::SdpAudioFormat("opus", 48000, 2,
            {{"minptime", "20"}, {"maxptime", "60"}, {"stereo", "0"},
             {"useinbandfec", "1"}, {"usedtx", "1"}}), {.payload_type = 111});
    if (!encoder) return 22;
    encoder->SetReceiverFrameLengthRange(20, 60);
    if (!encoder->EnableAudioNetworkAdaptor(veil_media::kFramingAudioAdaptorConfig)) return 23;
    const size_t overhead = route_overhead + rtp.headers_size();
    encoder->OnReceivedOverhead(overhead);
    const int ceiling = profile[1];
    const int healthy_duration = profile[2];
    std::array<int16_t, 480> pcm{};
    uint32_t timestamp = 0;
    int phase = 0;
    for (int budget : std::array{ceiling, 64000, ceiling}) {
      const int expected = phase == 1 ? 60 : healthy_duration;
      int verified_packets = 0;
      for (int block = 0; block < 600; ++block) {
        webrtc::BitrateAllocationUpdate update;
        update.target_bitrate = webrtc::DataRate::BitsPerSec(budget);
        encoder->OnReceivedUplinkAllocation(update);
        webrtc::Buffer packet;
        const auto info = encoder->Encode(timestamp, pcm, &packet);
        if (encoder->GetTargetBitrate() < 24000 ||
            encoder->GetTargetBitrate() > 32000) return 24;
        const int64_t maximum_gross = static_cast<int64_t>(overhead) * 8 * 1000 /
            healthy_duration + 32000;
        if (block >= 400 && phase != 1 && ceiling / 4 * 3 >= maximum_gross &&
            encoder->GetTargetBitrate() != 32000) return 27;
        if (block >= 400 && info.encoded_bytes > 0) {
          const int actual = opus_packet_get_nb_samples(packet.data(), packet.size(), 48000) / 48;
          if (actual != expected) {
            std::fprintf(stderr,
                "framing=%d RTP=%zu ceiling=%d phase=%d: Opus packet=%d expected=%d ms\n",
                route_overhead, rtp.headers_size(), ceiling, phase, actual, expected);
            return 25;
          }
          ++verified_packets;
        }
        timestamp += 480;
        clock.AdvanceTimeMilliseconds(10);
      }
      if (verified_packets < 2) return 26;
      ++phase;
    }
    std::printf("ok: framing=%d RTP=%zu ceiling=%d, actual Opus %d/60/%d ms\n",
        route_overhead, rtp.headers_size(), ceiling, healthy_duration, healthy_duration);
  }
  // Live framing changes on ONE encoder. Decode the actual Opus packet's
  // duration: a changed atomic hint or requested next duration cannot pass.
  webrtc::SimulatedClock clock(0);
  const auto env = webrtc::CreateEnvironment(&clock);
  auto factory = webrtc::make_ref_counted<veil_media::BoundedAudioEncoderFactory>();
  auto encoder = factory->Create(env, webrtc::SdpAudioFormat("opus", 48000, 2,
      {{"minptime", "20"}, {"maxptime", "60"}, {"stereo", "0"},
       {"useinbandfec", "1"}, {"usedtx", "1"}}), {.payload_type = 111});
  if (!encoder) return 28;
  encoder->SetReceiverFrameLengthRange(20, 60);
  if (!encoder->EnableAudioNetworkAdaptor(veil_media::kFramingAudioAdaptorConfig)) return 29;
  uint32_t timestamp = 0;
  std::array<int16_t, 480> pcm{};
  for (const auto& profile : std::array<std::array<int, 2>, 3>{{
           {209, 20}, {360, 40}, {209, 20}}}) {
    encoder->OnReceivedOverhead(profile[0] + rtp.headers_size());
    int verified = 0;
    for (int block = 0; block < 600; ++block) {
      webrtc::BitrateAllocationUpdate update;
      update.target_bitrate = webrtc::DataRate::BitsPerSec(160000);
      encoder->OnReceivedUplinkAllocation(update);
      webrtc::Buffer packet;
      const auto info = encoder->Encode(timestamp, pcm, &packet);
      if (encoder->GetTargetBitrate() < 24000 || encoder->GetTargetBitrate() > 32000) return 30;
      if (block >= 400 && info.encoded_bytes) {
        if (opus_packet_get_nb_samples(packet.data(), packet.size(), 48000) / 48 != profile[1]) return 31;
        ++verified;
      }
      timestamp += 480;
      clock.AdvanceTimeMilliseconds(10);
    }
    if (verified < 2) return 32;
  }
  std::puts("ok: one live Opus encoder, framing 209/360/209, actual packets 20/40/20 ms, payload 24..32 kbit/s");
  return 0;
}

// Real Opus/ANA regression: check startup and every feedback transition, not
// just the settled allocation. A future longer packet cannot justify lowering
// the speech bitrate of the current short packet.
int main() {
  webrtc::SimulatedClock clock(0);
  const auto env = webrtc::CreateEnvironment(&clock);
  for (int maximum_ms : std::array{20, 40, 60}) {
    auto duration = std::make_shared<std::atomic<int>>(0);
    auto factory =
        webrtc::make_ref_counted<veil_media::BoundedAudioEncoderFactory>(duration);
    webrtc::SdpAudioFormat format("opus", 48000, 2,
        {{"minptime", "20"}, {"maxptime", std::to_string(maximum_ms)},
         {"stereo", "0"}, {"useinbandfec", "1"}, {"usedtx", "1"}});
    auto encoder = factory->Create(env, format, {.payload_type = 111});
    if (!encoder) return 1;
    if (duration->load() != 0) return 4;
    encoder->SetReceiverFrameLengthRange(20, maximum_ms);
    if (!encoder->EnableAudioNetworkAdaptor(veil_media::kFramingAudioAdaptorConfig)) return 2;
    encoder->OnReceivedOverhead(209);
    const auto payload_in_bounds = [&] {
      return encoder->GetTargetBitrate() >= 24000 &&
             encoder->GetTargetBitrate() <= 32000;
    };
    if (!payload_in_bounds()) return 9;
    std::array<int16_t, 480> pcm{};
    uint32_t timestamp = 0;
    for (int allocation : std::array{6000, 16000, 30000, 64000, 96000, 160000}) {
      webrtc::BitrateAllocationUpdate update;
      update.target_bitrate = webrtc::DataRate::BitsPerSec(allocation);
      // Give ANA both allocation and its periodic uplink estimate; changes
      // then take effect at a packet boundary, as in the real send stream.
      for (int i = 0; i < 120; ++i) {
        encoder->OnReceivedUplinkAllocation(update);
        if (!payload_in_bounds()) {
          std::fprintf(stderr,
                       "allocation maxptime=%d allocation=%d block=%d: payload=%d\n",
                       maximum_ms, allocation, i, encoder->GetTargetBitrate());
          return 7;
        }
        if (i == 0) {
          encoder->OnReceivedRtt(120);
          if (!payload_in_bounds()) return 10;
          encoder->OnReceivedUplinkPacketLossFraction(0.1f);
          if (!payload_in_bounds()) return 11;
          encoder->OnReceivedOverhead(211);
          if (!payload_in_bounds()) return 12;
          encoder->OnReceivedOverhead(209);
          if (!payload_in_bounds()) return 13;
        }
        webrtc::Buffer packet;
        const int before = duration->load();
        const auto info = encoder->Encode(timestamp, pcm, &packet);
        if (!payload_in_bounds()) return 8;
        // Check the actual Opus payload, independently of the wrapper's
        // Num10MsFramesInNextPacket observation. Release builds use NDEBUG.
        const int expected = info.encoded_bytes > 0
            ? opus_packet_get_nb_samples(packet.data(), packet.size(), 48000) / 48
            : before;
        if (duration->load() != expected) return 5;
        timestamp += 480;
        clock.AdvanceTimeMilliseconds(10);
      }
      const int bitrate = encoder->GetTargetBitrate();
      const size_t packet_ms = encoder->Num10MsFramesInNextPacket() * 10;
      if (bitrate < 24000 || bitrate > 32000 ||
          packet_ms < 20 || packet_ms > static_cast<size_t>(maximum_ms)) {
        std::fprintf(stderr, "maxptime=%d allocation=%d: payload=%d packet=%zu ms\n",
                     maximum_ms, allocation, bitrate, packet_ms);
        return 3;
      }
      if (duration->load() < 20 || duration->load() > maximum_ms) return 6;
    }
    std::printf("ok: real Opus/ANA maxptime=%d, payload stays 24–32 kbit/s\n", maximum_ms);
  }
  return check_framing_budget();
}
