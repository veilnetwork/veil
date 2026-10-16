// Characterize the real Opus codec independently of routing and NetEq.
// This is a component regression; the unchanged full contention gate still
// decides end-to-end qualification. No PCM or encoded payload is retained.
#undef NDEBUG
#include <array>
#include <cassert>
#include <cmath>
#include <cstdio>
#include "api/environment/environment_factory.h"
#include "bounded_audio_encoder.h"
#include "system_wrappers/include/clock.h"
#include "third_party/opus/src/include/opus.h"

double band(const int16_t* pcm, int frequency) {
  double real = 0, imag = 0;
  for (int i = 0; i < 480; ++i) {
    const double angle = 2 * 3.14159265358979323846 * frequency * i / 48000;
    real += pcm[i] * std::cos(angle);
    imag += pcm[i] * std::sin(angle);
  }
  return std::sqrt(2 * (real * real + imag * imag) / (480.0 * 480.0));
}

int main() {
  for (int bitrate : {16000, 24000, 32000}) for (bool dtx : {true, false}) {
    webrtc::SimulatedClock clock(0);
    auto env = webrtc::CreateEnvironment(&clock);
    auto factory = webrtc::make_ref_counted<veil_media::BoundedAudioEncoderFactory>();
    std::unique_ptr<webrtc::AudioEncoder> encoder;
    int error = 0;
    OpusDecoder* decoder = opus_decoder_create(48000, 1, &error);
    assert(decoder && error == OPUS_OK);
    std::array<int16_t, 480> input;
    std::array<int16_t, 5760> output;
    int quiet_blocks = 0, first_quiet = -1, longest = 0;
    for (int tick = 0; tick <= 36000; ++tick) {
      if (tick == 0 || tick == 2101) {
        webrtc::SdpAudioFormat format("opus", 48000, 2,
            {{"stereo", "0"}, {"useinbandfec", "1"},
             {"usedtx", dtx ? "1" : "0"},
             {"ptime", tick < 2101 ? "40" : "60"}});
        encoder = factory->Create(env, format, {.payload_type = 111});
        assert(encoder);
        encoder->OnReceivedTargetAudioBitrate(tick == 0 ? 32000 : bitrate);
      }
      // A bitrate-only retune preserves the encoder; a ptime change creates
      // a new one, as AudioSendStream does for the same SDP codec changes.
      if (tick == 100) encoder->OnReceivedTargetAudioBitrate(bitrate);
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
      for (int block = 0; block < count / 480; ++block) {
        const auto* pcm = output.data() + block * 480;
        const double low = band(pcm, 1300), high = band(pcm, 1700);
        const auto at = info.encoded_timestamp / 480 + block;
        if (std::max(low, high) < 500) {
          if (first_quiet < 0) first_quiet = at;
          longest = std::max(longest, ++quiet_blocks);
        } else quiet_blocks = 0;
      }
    }
    // The old 16-kbit profile remains diagnostic evidence, never a required
    // failure of a future codec. Only the protected payload profiles gate.
    if (bitrate >= 24000) assert(longest == 0);
    opus_decoder_destroy(decoder);
    std::printf("summary requested_bitrate=%d actual_bitrate=%d dtx=%d first_quiet_tick=%d longest_quiet_blocks=%d\n",
                bitrate, encoder->GetTargetBitrate(), dtx, first_quiet, longest);
  }
}
