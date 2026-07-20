/* SPDX-License-Identifier: MIT
 *
 * veil_aaudio_adm.cc — AAudio-backed AudioDeviceModule (see veil_aaudio_adm.h).
 *
 * Capture:  AAudio INPUT stream --dataCallback(int16 PCM)-->
 *           FineAudioBuffer::DeliverRecordedData --> AudioDeviceBuffer -->
 *           AudioTransport (send stream / Opus).
 * Playout:  AudioTransport (mixed recv) --> AudioDeviceBuffer -->
 *           FineAudioBuffer::GetPlayoutData --> AAudio OUTPUT stream dataCallback.
 *
 * AAudio data callbacks run on dedicated high-priority audio threads. Stream
 * open/start/stop is serialized with a mutex; StartRecording/StartPlayout are
 * called by AudioState on the Call worker queue and return quickly.
 */
#include "veil_aaudio_adm.h"

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
#include <aaudio/AAudio.h>
#include <android/log.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>

#include "api/audio/audio_device_defines.h"
#include "api/make_ref_counted.h"
#include "modules/audio_device/audio_device_buffer.h"
#include "modules/audio_device/fine_audio_buffer.h"
#include "modules/audio_device/include/audio_device_default.h"

namespace veil_media {
namespace {

constexpr uint32_t kSampleRate = 48000;
constexpr int32_t kChannels = 1;
constexpr int kRecordDelayMs = 10;
constexpr int kPlayoutDelayMs = 40;

#define ALOG(...) __android_log_print(ANDROID_LOG_INFO, "veil_media", __VA_ARGS__)

class VeilAAudioAdm : public webrtc::webrtc_impl::AudioDeviceModuleDefault<
                          webrtc::AudioDeviceModule> {
 public:
  explicit VeilAAudioAdm(const webrtc::Environment& env)
      : env_(env), audio_device_buffer_(env, /*create_detached=*/true) {}
  ~VeilAAudioAdm() override { Terminate(); }

  int32_t RegisterAudioCallback(webrtc::AudioTransport* cb) override {
    return audio_device_buffer_.RegisterAudioCallback(cb);
  }

  int32_t Init() override {
    if (initialized_) return 0;
    audio_device_buffer_.SetRecordingSampleRate(kSampleRate);
    audio_device_buffer_.SetRecordingChannels(kChannels);
    audio_device_buffer_.SetPlayoutSampleRate(kSampleRate);
    audio_device_buffer_.SetPlayoutChannels(kChannels);
    rec_fine_ = std::make_unique<webrtc::FineAudioBuffer>(&audio_device_buffer_);
    play_fine_ =
        std::make_unique<webrtc::FineAudioBuffer>(&audio_device_buffer_);
    initialized_ = true;
    ALOG("aaudio_adm: Init ok");
    return 0;
  }
  bool Initialized() const override { return initialized_; }

  int32_t Terminate() override {
    if (!initialized_) return 0;
    StopRecording();
    StopPlayout();
    rec_fine_.reset();
    play_fine_.reset();
    initialized_ = false;
    return 0;
  }

  int16_t PlayoutDevices() override { return 1; }
  int16_t RecordingDevices() override { return 1; }
  int32_t PlayoutIsAvailable(bool* available) override {
    *available = true;
    return 0;
  }
  int32_t RecordingIsAvailable(bool* available) override {
    *available = true;
    return 0;
  }
  int32_t RecordingDeviceName(uint16_t /*index*/,
                              char name[webrtc::kAdmMaxDeviceNameSize],
                              char guid[webrtc::kAdmMaxGuidSize]) override {
    std::snprintf(name, webrtc::kAdmMaxDeviceNameSize, "AAudio Input");
    guid[0] = '\0';
    return 0;
  }
  int32_t PlayoutDeviceName(uint16_t /*index*/,
                            char name[webrtc::kAdmMaxDeviceNameSize],
                            char guid[webrtc::kAdmMaxGuidSize]) override {
    std::snprintf(name, webrtc::kAdmMaxDeviceNameSize, "AAudio Output");
    guid[0] = '\0';
    return 0;
  }

  // Android supplies real AudioDeviceInfo ids through the app MethodChannel.
  // The WebRTC ADM interface only carries uint16 ids, which is sufficient for
  // Android's session-local device identifiers; AAudio applies them when the
  // stream is reopened by the engine's stop/select/restart sequence.
  int32_t SetRecordingDevice(uint16_t index) override {
    recording_device_id_.store(index);
    return 0;
  }
  int32_t SetPlayoutDevice(uint16_t index) override {
    playout_device_id_.store(index);
    return 0;
  }

  int32_t InitPlayout() override {
    playout_initialized_ = true;
    return 0;
  }
  bool PlayoutIsInitialized() const override { return playout_initialized_; }
  int32_t InitRecording() override {
    recording_initialized_ = true;
    return 0;
  }
  bool RecordingIsInitialized() const override { return recording_initialized_; }

  int32_t StartRecording() override {
    if (!initialized_) Init();
    std::lock_guard<std::mutex> l(lock_);
    if (recording_.load()) return 0;
    if (!OpenRecordStreamLocked()) return -1;
    rec_fine_->ResetRecord();
    audio_device_buffer_.StartRecording();
    recording_.store(true);
    const aaudio_result_t r = AAudioStream_requestStart(rec_stream_);
    ALOG("aaudio_adm: StartRecording requestStart=%d", (int)r);
    return 0;
  }
  int32_t StopRecording() override {
    std::lock_guard<std::mutex> l(lock_);
    if (!recording_.exchange(false)) return 0;
    audio_device_buffer_.StopRecording();
    CloseRecordStreamLocked();
    return 0;
  }
  bool Recording() const override { return recording_.load(); }

  int32_t StartPlayout() override {
    if (!initialized_) Init();
    std::lock_guard<std::mutex> l(lock_);
    if (playing_.load()) return 0;
    if (!OpenPlayStreamLocked()) return -1;
    play_fine_->ResetPlayout();
    audio_device_buffer_.StartPlayout();
    playing_.store(true);
    const aaudio_result_t r = AAudioStream_requestStart(play_stream_);
    ALOG("aaudio_adm: StartPlayout requestStart=%d", (int)r);
    return 0;
  }
  int32_t StopPlayout() override {
    std::lock_guard<std::mutex> l(lock_);
    if (!playing_.exchange(false)) return 0;
    audio_device_buffer_.StopPlayout();
    ClosePlayStreamLocked();
    return 0;
  }
  bool Playing() const override { return playing_.load(); }

 private:
  bool OpenRecordStreamLocked() {
    AAudioStreamBuilder* b = nullptr;
    if (AAudio_createStreamBuilder(&b) != AAUDIO_OK) return false;
    AAudioStreamBuilder_setDirection(b, AAUDIO_DIRECTION_INPUT);
    AAudioStreamBuilder_setSampleRate(b, kSampleRate);
    AAudioStreamBuilder_setChannelCount(b, kChannels);
    AAudioStreamBuilder_setFormat(b, AAUDIO_FORMAT_PCM_I16);
    AAudioStreamBuilder_setSharingMode(b, AAUDIO_SHARING_MODE_SHARED);
    AAudioStreamBuilder_setPerformanceMode(b,
                                           AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
    const int32_t device_id = recording_device_id_.load();
    if (device_id > 0) AAudioStreamBuilder_setDeviceId(b, device_id);
    AAudioStreamBuilder_setDataCallback(b, &VeilAAudioAdm::RecordCallback, this);
    const aaudio_result_t r = AAudioStreamBuilder_openStream(b, &rec_stream_);
    AAudioStreamBuilder_delete(b);
    if (r != AAUDIO_OK || rec_stream_ == nullptr) {
      ALOG("aaudio_adm: rec openStream failed r=%d", (int)r);
      rec_stream_ = nullptr;
      return false;
    }
    const int32_t sr = AAudioStream_getSampleRate(rec_stream_);
    const int32_t ch = AAudioStream_getChannelCount(rec_stream_);
    const aaudio_format_t fmt = AAudioStream_getFormat(rec_stream_);
    rec_channels_ = ch > 0 ? ch : kChannels;
    audio_device_buffer_.SetRecordingSampleRate(sr > 0 ? sr : kSampleRate);
    audio_device_buffer_.SetRecordingChannels(rec_channels_);
    ALOG("aaudio_adm: rec stream sr=%d ch=%d fmt=%d(9=i16)", sr, ch, (int)fmt);
    return true;
  }
  void CloseRecordStreamLocked() {
    if (rec_stream_) {
      AAudioStream_requestStop(rec_stream_);
      AAudioStream_close(rec_stream_);
      rec_stream_ = nullptr;
    }
  }
  bool OpenPlayStreamLocked() {
    AAudioStreamBuilder* b = nullptr;
    if (AAudio_createStreamBuilder(&b) != AAUDIO_OK) return false;
    AAudioStreamBuilder_setDirection(b, AAUDIO_DIRECTION_OUTPUT);
    AAudioStreamBuilder_setSampleRate(b, kSampleRate);
    AAudioStreamBuilder_setChannelCount(b, kChannels);
    AAudioStreamBuilder_setFormat(b, AAUDIO_FORMAT_PCM_I16);
    AAudioStreamBuilder_setSharingMode(b, AAUDIO_SHARING_MODE_SHARED);
    AAudioStreamBuilder_setPerformanceMode(b,
                                           AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
    const int32_t device_id = playout_device_id_.load();
    if (device_id > 0) AAudioStreamBuilder_setDeviceId(b, device_id);
    AAudioStreamBuilder_setDataCallback(b, &VeilAAudioAdm::PlayCallback, this);
    const aaudio_result_t r = AAudioStreamBuilder_openStream(b, &play_stream_);
    AAudioStreamBuilder_delete(b);
    if (r != AAUDIO_OK || play_stream_ == nullptr) {
      ALOG("aaudio_adm: play openStream failed r=%d", (int)r);
      play_stream_ = nullptr;
      return false;
    }
    const int32_t sr = AAudioStream_getSampleRate(play_stream_);
    const int32_t ch = AAudioStream_getChannelCount(play_stream_);
    play_channels_ = ch > 0 ? ch : kChannels;
    audio_device_buffer_.SetPlayoutSampleRate(sr > 0 ? sr : kSampleRate);
    audio_device_buffer_.SetPlayoutChannels(play_channels_);
    ALOG("aaudio_adm: play stream sr=%d ch=%d", sr, ch);
    return true;
  }
  void ClosePlayStreamLocked() {
    if (play_stream_) {
      AAudioStream_requestStop(play_stream_);
      AAudioStream_close(play_stream_);
      play_stream_ = nullptr;
    }
  }

  // AAudio audio-thread callbacks.
  static aaudio_data_callback_result_t RecordCallback(AAudioStream* /*s*/,
                                                      void* ud,
                                                      void* audio_data,
                                                      int32_t num_frames) {
    auto* self = static_cast<VeilAAudioAdm*>(ud);
    if (self->recording_.load() && self->rec_fine_ && num_frames > 0) {
      const int16_t* data = static_cast<const int16_t*>(audio_data);
      const size_t n = (size_t)num_frames * self->rec_channels_;
      self->rec_fine_->DeliverRecordedData(std::span<const int16_t>(data, n),
                                           kRecordDelayMs);
    }
    return AAUDIO_CALLBACK_RESULT_CONTINUE;
  }
  static aaudio_data_callback_result_t PlayCallback(AAudioStream* /*s*/,
                                                    void* ud,
                                                    void* audio_data,
                                                    int32_t num_frames) {
    auto* self = static_cast<VeilAAudioAdm*>(ud);
    int16_t* out = static_cast<int16_t*>(audio_data);
    const size_t n = (size_t)num_frames * self->play_channels_;
    if (self->playing_.load() && self->play_fine_) {
      self->play_fine_->GetPlayoutData(std::span<int16_t>(out, n),
                                       kPlayoutDelayMs);
    } else {
      std::memset(out, 0, n * sizeof(int16_t));
    }
    return AAUDIO_CALLBACK_RESULT_CONTINUE;
  }

  webrtc::Environment env_;
  webrtc::AudioDeviceBuffer audio_device_buffer_;
  std::unique_ptr<webrtc::FineAudioBuffer> rec_fine_;
  std::unique_ptr<webrtc::FineAudioBuffer> play_fine_;
  std::mutex lock_;
  bool initialized_ = false;
  bool playout_initialized_ = false;
  bool recording_initialized_ = false;
  std::atomic<bool> recording_{false};
  std::atomic<bool> playing_{false};
  std::atomic<int32_t> recording_device_id_{0};
  std::atomic<int32_t> playout_device_id_{0};
  AAudioStream* rec_stream_ = nullptr;
  AAudioStream* play_stream_ = nullptr;
  int32_t rec_channels_ = kChannels;
  int32_t play_channels_ = kChannels;
};

}  // namespace

webrtc::scoped_refptr<webrtc::AudioDeviceModule> CreateVeilAAudioAdm(
    const webrtc::Environment& env) {
  return webrtc::make_ref_counted<VeilAAudioAdm>(env);
}

}  // namespace veil_media
#endif  // VEIL_MEDIA_HAVE_WEBRTC
