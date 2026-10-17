/* SPDX-License-Identifier: MIT */
// Real WebRTC APM: quiet speech must become audible without amplifying silence
// or hard-clipping louder speech. No microphone, speakers or network is opened.
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <random>
#include <vector>

#include "api/audio/builtin_audio_processing_builder.h"
#include "api/environment/environment_factory.h"
#include "veil_call_audio_processing.h"

static void require(bool ok, const char* message) {
  if (!ok) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
struct Measurement {
  double input_dbfs; double output_dbfs; int peak; size_t clipped;
  size_t clipped_frames; size_t last_clipped_frame;
  size_t longest_clipped_run;
};
static Measurement measure(const std::vector<int16_t>& speech, double scale,
                           bool configured, int kind = 0) {
  const auto env = webrtc::CreateEnvironment();
  const auto config = configured ? veil_media::CallAudioProcessingConfig()
                                 : webrtc::AudioProcessing::Config{};
  const auto apm = webrtc::BuiltinAudioProcessingBuilder(config).Build(env);
  require(apm != nullptr, "APM unavailable");
  const webrtc::StreamConfig stream(16000, 1);
  std::array<int16_t, 160> input{}, output{};
  double in_energy = 0, out_energy = 0;
  size_t counted = 0, clipped = 0;
  size_t clipped_frames = 0, last_clipped_frame = 0;
  size_t clipped_run = 0, longest_clipped_run = 0;
  int peak = 0;
  int source_peak = 1;
  for (int16_t sample : speech)
    source_peak = std::max(source_peak, std::abs(static_cast<int>(sample)));
  std::mt19937 rng(42);
  std::uniform_int_distribution<int> noise(-18, 18);
  // Repeated real speech gives the adaptive estimator time to converge. Only
  // the second half contributes to RMS; every frame contributes to clipping.
  for (size_t tick = 0; tick < 3000; ++tick) {
    const double capture_scale = kind == 3 && tick >= 1500
        ? 28000.0 / source_peak : scale;
    const size_t before_clipped = clipped;
    for (size_t i = 0; i < input.size(); ++i) {
      input[i] = kind == 1 ? 0 : kind == 2 ? noise(rng) :
          static_cast<int16_t>(std::clamp(
              speech[(tick * input.size() + i) % speech.size()] * capture_scale,
              -32767.0, 32767.0));
    }
    // AudioTransportImpl uses in-place capture processing. APM can bypass all
    // work when disabled; preserve that exact contract in the control too.
    output = input;
    require(apm->ProcessStream(output.data(), stream, stream, output.data()) == 0,
            "real APM processing failed");
    for (size_t i = 0; i < input.size(); ++i) {
      const int amplitude = std::abs(static_cast<int>(output[i]));
      peak = std::max(peak, amplitude);
      clipped += amplitude >= 32767;
      clipped_run = amplitude >= 32767 ? clipped_run + 1 : 0;
      longest_clipped_run = std::max(longest_clipped_run, clipped_run);
      if (tick >= 1500) {
        in_energy += static_cast<double>(input[i]) * input[i];
        out_energy += static_cast<double>(output[i]) * output[i];
        ++counted;
      }
    }
    if (clipped > before_clipped) { ++clipped_frames; last_clipped_frame = tick; }
  }
  auto dbfs = [counted](double energy) {
    return energy == 0 ? -200.0 :
        10 * std::log10(energy / counted / (32768.0 * 32768.0));
  };
  return {dbfs(in_energy), dbfs(out_energy), peak, clipped,
          clipped_frames, last_clipped_frame, longest_clipped_run};
}
int main(int argc, char** argv) {
  require(argc >= 2, "provide WebRTC resources/voice_engine/audio_long16.pcm");
  std::ifstream file(argv[1], std::ios::binary);
  const std::vector<char> bytes((std::istreambuf_iterator<char>(file)), {});
  require(bytes.size() > 32000 && bytes.size() % 2 == 0, "speech fixture missing");
  std::vector<int16_t> speech(bytes.size() / 2);
  for (size_t i = 0; i < speech.size(); ++i)
    speech[i] = static_cast<int16_t>(static_cast<unsigned char>(bytes[2*i]) |
        (static_cast<unsigned char>(bytes[2*i+1]) << 8));
  // --bare is a negative control: the previous production configuration must
  // fail the same quiet-speech gate, using exactly the same source samples.
  const bool configured = argc < 3;
  const auto quiet = measure(speech, 0.03, configured);
  int source_peak = 0;
  for (int16_t sample : speech)
    source_peak = std::max(source_peak, std::abs(static_cast<int>(sample)));
  const auto loud = measure(speech, 28000.0 / source_peak, configured);
  const auto silence = measure(speech, 0, configured, 1);
  const auto noise = measure(speech, 0, configured, 2);
  const auto transition = measure(speech, 0.03, configured, 3);
  std::printf("quiet input=%.2f output=%.2f gain=%.2f dB; loud peak=%d "
              "clipped=%zu; silence peak=%d; noise=%.2f dBFS; "
              "quiet-to-loud peak=%d clipped=%zu frames=%zu last_frame=%zu "
              "longest_run=%zu\n",
              quiet.input_dbfs, quiet.output_dbfs,
              quiet.output_dbfs - quiet.input_dbfs, loud.peak, loud.clipped,
              silence.peak, noise.output_dbfs, transition.peak, transition.clipped,
              transition.clipped_frames, transition.last_clipped_frame,
              transition.longest_clipped_run);
  require(quiet.input_dbfs > -90, "speech source was silent");
  require(quiet.output_dbfs - quiet.input_dbfs >= 10,
          "quiet speech was not raised by at least 10 dB");
  require(quiet.output_dbfs - quiet.input_dbfs <= 31,
          "quiet speech exceeded the gain budget");
  require(loud.clipped == 0, "loud speech hard-clipped");
  // A sudden 30-dB increase after adaptation can hit AGC2's native limiter.
  // Bound the distortion (<0.1% of the loud half, no 1-ms clipped plateau),
  // instead of requiring an integer full-scale sample to be impossible.
  require(transition.clipped < 240 && transition.longest_clipped_run < 16,
          "quiet-to-loud speech has sustained saturation");
  require(silence.peak == 0, "silence became audible");
  require(noise.output_dbfs < -49, "room noise amplified above AGC noise bound");
  std::puts("PASS real APM quiet speech, limiter, silence and noise bounds");
}
