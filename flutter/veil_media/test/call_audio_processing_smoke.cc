/* SPDX-License-Identifier: MIT */
// Real AudioTransportImpl, render reference and production APM. No device,
// sockets, PCM export or network timing. An acoustic path is synthesized from
// the actual rendered output, not separately fed to ProcessReverseStream.
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <iterator>
#include <memory>
#include <random>
#include <vector>
#include "api/audio/audio_frame.h"
#include "api/audio/audio_mixer.h"
#include "api/audio/builtin_audio_processing_builder.h"
#include "api/environment/environment_factory.h"
#include "api/make_ref_counted.h"
#include "audio/audio_transport_impl.h"
#include "call/audio_sender.h"
#include "veil_call_audio_processing.h"

static void require(bool ok, const char* why) {
  if (!ok) { std::fprintf(stderr, "%s\n", why); std::exit(1); }
}
constexpr int kRate = 16000, kSamples = 160;
using Block = std::array<int16_t, kSamples>;
class Render : public webrtc::AudioMixer {
 public:
  Block block{};
  bool AddSource(Source*) override { return false; }
  void RemoveSource(Source*) override {}
  void Mix(size_t channels, webrtc::AudioFrame* frame) override {
    std::array<int16_t, kSamples * 2> samples{};
    for (int i = 0; i < kSamples; ++i)
      for (size_t ch = 0; ch < channels; ++ch)
        samples[i * channels + ch] = block[i];
    frame->UpdateFrame(0, samples.data(), kSamples, kRate,
        webrtc::AudioFrame::kNormalSpeech, webrtc::AudioFrame::kVadActive,
        channels);
  }
};
class Captured final : public webrtc::AudioSender {
 public:
  Block block{};
  size_t frames = 0;
  void SendAudioData(std::unique_ptr<webrtc::AudioFrame> frame) override {
    require(frame->samples_per_channel_ == kSamples && frame->num_channels_ == 1,
            "unexpected capture format");
    std::copy_n(frame->data(), kSamples, block.begin());
    ++frames;
  }
};
struct Result {
  double input, output;
  std::vector<double> processed;
};
static Result measure(const std::vector<int16_t>& speech, int kind,
                      bool disable_aec, bool disable_ns, int channels) {
  const auto env = webrtc::CreateEnvironment();
  auto config = veil_media::CallAudioProcessingConfig();
  if (disable_aec) config.echo_canceller.enabled = false;
  if (disable_ns) config.noise_suppression.enabled = false;
  auto apm = webrtc::BuiltinAudioProcessingBuilder(config).Build(env);
  require(apm != nullptr, "APM unavailable");
  auto render = webrtc::make_ref_counted<Render>();
  webrtc::AudioTransportImpl transport(render.get(), apm.get(), nullptr);
  Captured sink;
  transport.UpdateAudioSenders({&sink}, kRate, 1);
  std::mt19937 rng(42);
  std::uniform_int_distribution<int> noise(-400, 400);
  std::deque<Block> history(10);
  double input = 0, output = 0;
  std::vector<double> captured_output;
  size_t counted = 0;
  for (int tick = 0; tick < 3000; ++tick) {
    for (int i = 0; i < kSamples; ++i)
      render->block[i] = (kind == 0 || kind == 3) ?
          speech[(tick * kSamples + i) % speech.size()] : 0;
    std::array<int16_t, kSamples * 2> playout{};
    size_t out = 0;
    int64_t elapsed = -1, ntp = -1;
    require(transport.NeedMorePlayData(kSamples, sizeof(int16_t) * channels,
        channels, kRate, playout.data(), out, &elapsed, &ntp) == 0,
        "render callback failed");
    require(out == kSamples * static_cast<size_t>(channels), "short render");
    Block rendered{};
    for (int i = 0; i < kSamples; ++i) rendered[i] = playout[i * channels];
    history.push_back(rendered);
    history.pop_front();
    Block capture{};
    for (int i = 0; i < kSamples; ++i) {
      const auto near = static_cast<int16_t>(speech[
          (tick * kSamples + i + speech.size() / 3) % speech.size()] * .3);
      if (kind == 0 || kind == 3)
        capture[i] = static_cast<int16_t>(history[3][i] * .45 + history[0][i] * .1 + (kind == 3 ? near : 0));
      else if (kind == 1) capture[i] = noise(rng);
      else capture[i] = near;
    }
    uint32_t level = 0;
    require(transport.RecordedDataIsAvailable(capture.data(), kSamples,
        sizeof(int16_t), 1, kRate, 60, 0, 0, false, level) == 0,
        "capture callback failed");
    if (tick >= 1500) for (int i = 0; i < kSamples; ++i) {
      input += double(capture[i]) * capture[i];
      output += double(sink.block[i]) * sink.block[i];
      ++counted;
      if (kind == 2 || kind == 3) captured_output.push_back(sink.block[i]);
    }
  }
  transport.UpdateAudioSenders({}, kRate, 1);
  require(sink.frames == 3000, "capture did not traverse the real sender");
  auto db = [counted](double e) {
    return 10 * std::log10(std::max(e, 1e-12) / counted / (32768.0 * 32768.0));
  };
  return {db(input), db(output), std::move(captured_output)};
}
// Compare against near speech passed through the SAME processing chain.
// Raw speech is not a waveform oracle after the enforced HPF, NS and AGC.
static double compare_near(const Result& clean, const Result& mixed) {
  const auto& x = clean.processed;
  const auto& y = mixed.processed;
  require(x.size() == y.size() && x.size() > 10000, "near control missing");
  double best = 0;
  for (int lag = -8; lag <= 8; ++lag) {
    double score = 0, total = 0;
    for (size_t begin = 16; begin + 3200 + 16 < x.size(); begin += 3200) {
      double xy = 0, xx = 0, yy = 0;
      for (size_t i = begin; i < begin + 3200; ++i) {
        xy += x[i] * y[i + lag]; xx += x[i] * x[i]; yy += y[i + lag] * y[i + lag];
      }
      score += xx * std::abs(xy) / std::sqrt(std::max(xx * yy, 1e-20));
      total += xx;
    }
    best = std::max(best, score / std::max(total, 1e-20));
  }
  return best;
}
static void verify_runtime_toggle() {
  auto apm = webrtc::BuiltinAudioProcessingBuilder(
      veil_media::CallAudioProcessingConfig()).Build(webrtc::CreateEnvironment());
  const webrtc::StreamConfig stream(kRate, 1);
  std::mt19937 rng(123);
  std::uniform_int_distribution<int> noise(-400, 400);
  std::array<double, 3> energy{};
  std::array<size_t, 3> counts{};
  Block block{};
  for (int tick = 0; tick < 6000; ++tick) {
    if (tick == 2000 || tick == 4000) {
      require(veil_media::SetCallNoiseSuppression(apm.get(), tick == 4000), "runtime NS toggle refused");
      const auto config = apm->GetConfig();
      require(config.echo_canceller.enabled && config.gain_controller2.enabled,
              "NS toggle changed echo/gain policy");
    }
    for (auto& sample : block) sample = noise(rng);
    require(apm->ProcessStream(block.data(), stream, stream, block.data()) == 0, "toggle processing failed");
    if (tick % 2000 >= 1000) for (auto value : block) {
      energy[tick / 2000] += double(value) * value;
      ++counts[tick / 2000];
    }
  }
  std::array<double, 3> db{};
  for (int i = 0; i < 3; ++i) db[i] = 10 * std::log10(energy[i] / counts[i] / (32768.0 * 32768.0));
  std::printf("runtime_ns_on_off_on_dbfs=%.2f/%.2f/%.2f\n", db[0], db[1], db[2]);
  require(db[1] - db[0] >= 6 && db[1] - db[2] >= 6,
          "runtime NS toggle has no measured suppression effect");
}
int main(int argc, char** argv) {
  require(argc == 2, "provide WebRTC speech fixture");
  std::ifstream f(argv[1], std::ios::binary);
  const std::vector<char> bytes((std::istreambuf_iterator<char>(f)), {});
  require(bytes.size() > 32000 && bytes.size() % 2 == 0, "invalid speech fixture");
  std::vector<int16_t> speech(bytes.size() / 2);
  for (size_t i = 0; i < speech.size(); ++i)
    speech[i] = static_cast<int16_t>(static_cast<unsigned char>(bytes[2*i]) |
        (static_cast<unsigned char>(bytes[2*i+1]) << 8));
  bool ok = true;
  for (int channels : {1, 2}) {
    const auto old_echo = measure(speech, 0, true, true, channels);
    const auto echo = measure(speech, 0, false, false, channels);
    std::printf("render_channels=%d echo_input_dbfs=%.2f old_output_dbfs=%.2f "
                "output_dbfs=%.2f echo_reduction_db=%.2f\n", channels,
                echo.input, old_echo.output, echo.output,
                old_echo.output - echo.output);
    ok &= old_echo.output - echo.output >= 15;
  }
  const auto noisy = measure(speech, 1, false, true, 1);
  const auto clean = measure(speech, 1, false, false, 1);
  const auto near = measure(speech, 2, false, false, 1);
  std::printf("noise_off_dbfs=%.2f noise_on_dbfs=%.2f suppression_db=%.2f "
              "near_input_dbfs=%.2f near_output_dbfs=%.2f\n",
              noisy.output, clean.output, noisy.output - clean.output,
              near.input, near.output);
  ok &= noisy.output - clean.output >= 6;
  ok &= near.output >= near.input - 3;
  const auto doubletalk = measure(speech, 3, false, false, 2);
  const auto mixed_control = measure(speech, 3, true, true, 2);
  const auto near_control = measure(speech, 2, true, true, 2);
  const auto old_score = compare_near(near_control, mixed_control);
  const auto score = compare_near(near, doubletalk);
  std::printf("processed_near_reference_correlation old=%.3f new=%.3f doubletalk_level_change_db=%.2f\n",
              old_score, score, doubletalk.output - near.output);
  // A processed near-only positive control accounts for APM filtering and
  // gain. Gate relative improvement over the old AGC-only configuration and
  // avoid a muted-near-end false success. Correlation is a regression metric
  // for this fixture, not a perceptual quality or real-room echo score.
  require(compare_near(near, near) > .999, "invalid near-speech reference");
  ok &= doubletalk.output >= near.output - 3 && score > old_score;
  verify_runtime_toggle();
  require(ok, "production capture does not cancel echo / suppress noise / preserve near speech");
  std::puts("PASS real AudioTransport render-reference echo and capture-noise processing");
}
