// Stand only: the real WebRTC AudioState controls this device, but no physical
// input/output is opened. Counts expose implicit StartRecording from streams.
#include "modules/audio_device/audio_device_impl.h"
#include <array>
#include <cmath>

namespace {
bool g_call_plane_recording_adm = false;
class StandRecordingAdm : public webrtc::AudioDeviceModuleImpl {
 public:
  explicit StandRecordingAdm(const webrtc::Environment& env)
      : AudioDeviceModuleImpl(env, kDummyAudio) {}
  int32_t Init() override { return 0; }
  int32_t Terminate() override { return 0; }
  bool Initialized() const override { return true; }
  int32_t RegisterAudioCallback(webrtc::AudioTransport* callback) override {
    callback_ = callback;
    return 0;
  }
  int32_t RecordingIsAvailable(bool* available) override {
    *available = true;
    return 0;
  }
  int32_t PlayoutIsAvailable(bool* available) override {
    *available = true;
    return 0;
  }
  int16_t RecordingDevices() override { return 0; }
  int16_t PlayoutDevices() override { return 0; }
  int32_t InitRecording() override { return 0; }
  int32_t InitPlayout() override { return 0; }
  bool RecordingIsInitialized() const override { return true; }
  bool PlayoutIsInitialized() const override { return true; }
  int32_t StartRecording() override {
    ++recording_starts;
    recording_.store(true);
    return 0;
  }
  int32_t StopRecording() override { recording_.store(false); return 0; }
  bool Recording() const override { return recording_.load(); }
  int32_t StartPlayout() override { playing_.store(true); return 0; }
  int32_t StopPlayout() override { playing_.store(false); return 0; }
  bool Playing() const override { return playing_.load(); }
  void CaptureTone(int frequency_hz) {
    if (!Recording() || !callback_) return;
    std::array<int16_t, 480> pcm;
    constexpr double pi = 3.14159265358979323846;
    for (size_t i = 0; i < pcm.size(); ++i)
      pcm[i] = static_cast<int16_t>(12000 * std::sin(
          2 * pi * frequency_hz * (tone_samples_ + i) / 48000));
    tone_samples_ += pcm.size();
    uint32_t level = 0;
    callback_->RecordedDataIsAvailable(pcm.data(), pcm.size(), sizeof(int16_t),
                                       1, 48000, 0, 0, 0, false, level);
  }
  size_t Playout(int16_t* pcm, size_t capacity) {
    if (!Playing() || !callback_ || capacity < 480) return 0;
    size_t samples = 0;
    int64_t elapsed_ms = -1, ntp_ms = -1;
    const auto rc = callback_->NeedMorePlayData(
        480, sizeof(int16_t), 1, 48000, pcm, samples, &elapsed_ms, &ntp_ms);
    return rc == 0 ? samples : 0;
  }
  void Capture(size_t ticks) {
    std::vector<int16_t> pcm(480);
    for (size_t i = 0; i < pcm.size(); ++i)
      pcm[i] = (i / 24) % 2 ? 12000 : -12000;
    for (size_t i = 0; i < ticks; ++i) {
      if (Recording() && callback_) {
        uint32_t level = 0;
        callback_->RecordedDataIsAvailable(pcm.data(), pcm.size(), sizeof(int16_t),
                                           1, 48000, 0, 0, 0, false, level);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }
  std::atomic<int> recording_starts{0};
 private:
  std::atomic<bool> recording_{false};
  std::atomic<bool> playing_{false};
  webrtc::AudioTransport* callback_ = nullptr;
  uint64_t tone_samples_ = 0;
};
}  // namespace
