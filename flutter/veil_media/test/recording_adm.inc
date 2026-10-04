// Stand only: the real WebRTC AudioState controls this device, but no physical
// input/output is opened. Counts expose implicit StartRecording from streams.
#include "modules/audio_device/audio_device_impl.h"

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
};
}  // namespace
