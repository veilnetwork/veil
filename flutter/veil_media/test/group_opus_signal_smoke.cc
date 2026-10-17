// Characterize the real Opus codec independently of routing and NetEq.
// This is a component regression; the unchanged full contention gate still
// decides end-to-end qualification. No PCM or encoded payload is retained.
#undef NDEBUG
#include <array>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <vector>
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

// Keep transition ordinals from the first input block, including startup and
// the encoder replacement. A periodic nearest-phase match could hide an
// entire missing tone. These are sample positions and synchronous codec emit
// ticks, not network/acoustic latency or a substitute for the full PCM gate.
struct ToneTransition {
  int frequency;
  int sample_tick;
  int emitted_tick;
};

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
    std::vector<ToneTransition> transitions;
    int previous = 0, pending = 0, pending_tick = 0, pending_emit = 0, run = 0;
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
        const int decoded_frequency = std::max(low, high) >= 500
            ? (high > low ? 1700 : 1300) : 0;
        if (!decoded_frequency || decoded_frequency == previous) {
          pending = run = 0;
        } else {
          if (decoded_frequency != pending) {
            pending = decoded_frequency;
            pending_tick = at;
            pending_emit = tick;
            run = 1;
          } else {
            ++run;
          }
          if (run >= 2) {
            transitions.push_back({pending, pending_tick, pending_emit});
            previous = pending;
            pending = run = 0;
          }
        }
      }
    }
    // The old 16-kbit profile remains diagnostic evidence, never a required
    // failure of a future codec. Only the protected payload profiles gate.
    if (bitrate >= 24000) assert(longest == 0);
    const int expected_transitions = 36000 / 101 + 1;
    int matched = 0, missing = 0, max_sample_lag_ms = 0, max_emit_lag_ms = 0;
    for (int ordinal = 0; ordinal < expected_transitions; ++ordinal) {
      const int source_tick = ordinal * 101;
      const int expected_frequency = ordinal % 2 ? 1700 : 1300;
      if (ordinal >= static_cast<int>(transitions.size()) ||
          transitions[ordinal].frequency != expected_frequency ||
          transitions[ordinal].sample_tick < source_tick ||
          transitions[ordinal].emitted_tick < source_tick) {
        ++missing;
        continue;
      }
      ++matched;
      max_sample_lag_ms = std::max(max_sample_lag_ms,
          (transitions[ordinal].sample_tick - source_tick) * 10);
      max_emit_lag_ms = std::max(max_emit_lag_ms,
          (transitions[ordinal].emitted_tick - source_tick) * 10);
    }
    // The diagnostic 16-kbit profile can lose signal; the protected profiles
    // must preserve every original transition, without trimming startup.
    if (bitrate >= 24000) {
      assert(missing == 0);
      assert(static_cast<int>(transitions.size()) == expected_transitions);
    }
    opus_decoder_destroy(decoder);
    std::printf("summary requested_bitrate=%d actual_bitrate=%d dtx=%d first_quiet_tick=%d longest_quiet_blocks=%d transition_matched=%d transition_missing=%d transition_decoded=%zu max_sample_lag_ms=%d max_emit_lag_ms=%d\n",
                bitrate, encoder->GetTargetBitrate(), dtx, first_quiet, longest,
                matched, missing, transitions.size(), max_sample_lag_ms, max_emit_lag_ms);
  }
}
