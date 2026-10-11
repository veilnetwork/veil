#include <array>
#include <cstdio>

#include "api/call/bitrate_allocation.h"
#include "api/environment/environment_factory.h"
#include "bounded_audio_encoder.h"
#include "modules/audio_coding/audio_network_adaptor/config.pb.h"
#include "system_wrappers/include/clock.h"

// Real Opus/ANA regression: a peer that permits only short packets must not
// lower speech bitrate because allocation accounting assumes longer packets.
int main() {
  webrtc::SimulatedClock clock(0);
  const auto env = webrtc::CreateEnvironment(&clock);
  auto factory = webrtc::make_ref_counted<veil_media::BoundedAudioEncoderFactory>();
  for (int maximum_ms : std::array{20, 40, 60}) {
    webrtc::SdpAudioFormat format("opus", 48000, 2,
        {{"minptime", "20"}, {"maxptime", std::to_string(maximum_ms)},
         {"stereo", "0"}, {"useinbandfec", "1"}});
    auto encoder = factory->Create(env, format, {.payload_type = 111});
    if (!encoder) return 1;
    encoder->SetReceiverFrameLengthRange(20, maximum_ms);
    webrtc::audio_network_adaptor::config::ControllerManager manager;
    if (maximum_ms > 20) {
      auto* frames = manager.add_controllers()->mutable_frame_length_controller_v2();
      frames->set_min_payload_bitrate_bps(16000);
      frames->set_use_slow_adaptation(false);
    }
    manager.add_controllers()->mutable_bitrate_controller();
    if (!encoder->EnableAudioNetworkAdaptor(manager.SerializeAsString())) return 2;
    encoder->OnReceivedOverhead(209);
    std::array<int16_t, 480> pcm{};
    uint32_t timestamp = 0;
    for (int allocation : std::array{6000, 16000, 30000, 64000, 96000, 160000}) {
      webrtc::BitrateAllocationUpdate update;
      update.target_bitrate = webrtc::DataRate::BitsPerSec(allocation);
      // Give ANA both allocation and its periodic uplink estimate; changes
      // then take effect at a packet boundary, as in the real send stream.
      for (int i = 0; i < 120; ++i) {
        encoder->OnReceivedUplinkAllocation(update);
        webrtc::Buffer packet;
        encoder->Encode(timestamp, pcm, &packet);
        timestamp += 480;
        clock.AdvanceTimeMilliseconds(10);
      }
      const int bitrate = encoder->GetTargetBitrate();
      const size_t packet_ms = encoder->Num10MsFramesInNextPacket() * 10;
      if (bitrate < 16000 || bitrate > 32000 ||
          packet_ms < 20 || packet_ms > static_cast<size_t>(maximum_ms)) {
        std::fprintf(stderr, "maxptime=%d allocation=%d: payload=%d packet=%zu ms\n",
                     maximum_ms, allocation, bitrate, packet_ms);
        return 3;
      }
    }
    std::printf("ok: real Opus/ANA maxptime=%d, payload stays 16–32 kbit/s\n", maximum_ms);
  }
}
