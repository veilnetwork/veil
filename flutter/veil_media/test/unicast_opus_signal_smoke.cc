// Real production Opus/ANA signal check, independent of transport and NetEq.
// No speech, PCM or encoded payload is retained. This does not replace the
// complete contention gate or physical continuous-speech verification.
#undef NDEBUG
#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cstdio>

#include "api/call/bitrate_allocation.h"
#include "api/environment/environment_factory.h"
#include "bounded_audio_encoder.h"
#include "system_wrappers/include/clock.h"
#include "third_party/opus/src/include/opus.h"
#include "veil_audio_adaptor_config.h"

static double band(const int16_t* pcm, int frequency) {
  double real = 0, imag = 0;
  for (int i = 0; i < 480; ++i) {
    const double angle = 2 * 3.14159265358979323846 * frequency * i / 48000;
    real += pcm[i] * std::cos(angle);
    imag += pcm[i] * std::sin(angle);
  }
  return std::sqrt(2 * (real * real + imag * imag) / (480.0 * 480.0));
}

int main() {
  bool preserved = true;
  for (int overhead : {209, 509}) for (bool dtx : {true, false}) {
    webrtc::SimulatedClock clock(0);
    const auto env = webrtc::CreateEnvironment(&clock);
    auto factory = webrtc::make_ref_counted<veil_media::BoundedAudioEncoderFactory>();
    auto encoder = factory->Create(env,
        webrtc::SdpAudioFormat("opus", 48000, 2,
            {{"minptime", "20"}, {"maxptime", "60"}, {"stereo", "0"},
             {"useinbandfec", "1"}, {"usedtx", dtx ? "1" : "0"}}),
        {.payload_type = 111});
    assert(encoder);
    encoder->SetReceiverFrameLengthRange(20, 60);
    assert(encoder->EnableAudioNetworkAdaptor(veil_media::kFramingAudioAdaptorConfig));
    encoder->OnReceivedOverhead(overhead);
    int error = 0;
    OpusDecoder* decoder = opus_decoder_create(48000, 1, &error);
    assert(decoder && error == OPUS_OK);
    std::array<int16_t, 480> input;
    std::array<int16_t, 5760> output;
    int quiet = 0, longest = 0, first_quiet = -1;
    int minimum_payload = 32000, maximum_packet_ms = 0;
    for (int tick = 0; tick <= 36000; ++tick) {
      webrtc::BitrateAllocationUpdate update;
      update.target_bitrate = webrtc::DataRate::BitsPerSec(tick < 100 ? 160000 : 30000);
      encoder->OnReceivedUplinkAllocation(update);
      minimum_payload = std::min(minimum_payload, encoder->GetTargetBitrate());
      const int frequency = ((tick * 10) / 1010) % 2 ? 1700 : 1300;
      for (int i = 0; i < 480; ++i)
        input[i] = static_cast<int16_t>(12000 * std::sin(
            2 * 3.14159265358979323846 * frequency * (tick * 480LL + i) / 48000));
      webrtc::Buffer payload;
      const auto info = encoder->Encode(tick * 480, input, &payload);
      clock.AdvanceTimeMilliseconds(10);
      if (!info.encoded_bytes) continue;
      const int count = opus_decode(decoder, payload.data(), payload.size(),
                                    output.data(), output.size(), 0);
      assert(count > 0 && count % 480 == 0);
      maximum_packet_ms = std::max(maximum_packet_ms, count / 48);
      for (int block = 0; block < count / 480; ++block) {
        const auto* pcm = output.data() + block * 480;
        const auto at = info.encoded_timestamp / 480 + block;
        if (std::max(band(pcm, 1300), band(pcm, 1700)) < 500) {
          if (first_quiet < 0) first_quiet = at;
          longest = std::max(longest, ++quiet);
        } else quiet = 0;
      }
    }
    preserved &= longest == 0;
    assert(maximum_packet_ms == 60);  // Actual pressure must exercise framing.
    opus_decoder_destroy(decoder);
    std::printf("unicast overhead=%d dtx=%d minimum_payload=%d maximum_packet_ms=%d first_quiet_tick=%d longest_quiet_blocks=%d\n",
                overhead, dtx, minimum_payload, maximum_packet_ms, first_quiet, longest);
    std::fflush(stdout);
  }
  return preserved ? 0 : 2;
}
