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
#include <dlfcn.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <thread>

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

// These setters were added in API 28. Resolve them at runtime so loading this
// ADM still works on API 26/27 (no new undefined API-28 symbols in the ELF).
// AAudio otherwise defaults to MEDIA/MUSIC and VOICE_RECOGNITION: call routing
// and the volume controlled by the phone's buttons can disagree with playback.
void SetVoiceAttribute(AAudioStreamBuilder* builder, const char* symbol,
                       int32_t value) {
  using Setter = void (*)(AAudioStreamBuilder*, int32_t);
  const auto setter = reinterpret_cast<Setter>(dlsym(RTLD_DEFAULT, symbol));
  if (setter) setter(builder, value);
}

class VeilAAudioAdm : public webrtc::webrtc_impl::AudioDeviceModuleDefault<
                          webrtc::AudioDeviceModule> {
 public:
  explicit VeilAAudioAdm(const webrtc::Environment& env)
      : env_(env), audio_device_buffer_(env, /*create_detached=*/true) {
    recovery_thread_ = std::thread([this] { RecoverDisconnectedStreams(); });
  }
  ~VeilAAudioAdm() override {
    // Close joins AAudio callbacks before their userdata or fine buffers die.
    Terminate();
    recovery_stopping_.store(true);
    recovery_cv_.notify_one();
    recovery_thread_.join();
  }

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
    rec_fine_ = std::make_unique<webrtc::FineAudioBuffer>(&audio_device_buffer_);
    audio_device_buffer_.StartRecording();
    recording_.store(true);
    const aaudio_result_t r = AAudioStream_requestStart(rec_stream_);
    ALOG("aaudio_adm: StartRecording requestStart=%d", (int)r);
    if (r != AAUDIO_OK) {
      recording_.store(false);
      CloseRecordStreamLocked();
      audio_device_buffer_.StopRecording();
      return -1;
    }
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
    play_fine_ = std::make_unique<webrtc::FineAudioBuffer>(&audio_device_buffer_);
    audio_device_buffer_.StartPlayout();
    playing_.store(true);
    const aaudio_result_t r = AAudioStream_requestStart(play_stream_);
    ALOG("aaudio_adm: StartPlayout requestStart=%d", (int)r);
    if (r != AAUDIO_OK) {
      playing_.store(false);
      ClosePlayStreamLocked();
      audio_device_buffer_.StopPlayout();
      return -1;
    }
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
    SetVoiceAttribute(b, "AAudioStreamBuilder_setInputPreset",
                      AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION);
    AAudioStreamBuilder_setSampleRate(b, kSampleRate);
    AAudioStreamBuilder_setChannelCount(b, kChannels);
    AAudioStreamBuilder_setFormat(b, AAUDIO_FORMAT_PCM_I16);
    AAudioStreamBuilder_setSharingMode(b, AAUDIO_SHARING_MODE_SHARED);
    AAudioStreamBuilder_setPerformanceMode(b,
                                           AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
    const int32_t device_id = recording_device_id_.load();
    if (device_id > 0) AAudioStreamBuilder_setDeviceId(b, device_id);
    rec_generation_.fetch_add(1);
    AAudioStreamBuilder_setDataCallback(b, &VeilAAudioAdm::RecordCallback, this);
    AAudioStreamBuilder_setErrorCallback(b, &VeilAAudioAdm::RecordErrorCallback, this);
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
    rec_generation_.fetch_add(1);
    rec_recovery_.store(0);
    if (rec_stream_) {
      AAudioStream_requestStop(rec_stream_);
      AAudioStream_close(rec_stream_);
      rec_stream_ = nullptr;
    }
    rec_recovery_.store(0);
  }
  bool OpenPlayStreamLocked() {
    AAudioStreamBuilder* b = nullptr;
    if (AAudio_createStreamBuilder(&b) != AAUDIO_OK) return false;
    AAudioStreamBuilder_setDirection(b, AAUDIO_DIRECTION_OUTPUT);
    SetVoiceAttribute(b, "AAudioStreamBuilder_setUsage",
                      AAUDIO_USAGE_VOICE_COMMUNICATION);
    SetVoiceAttribute(b, "AAudioStreamBuilder_setContentType",
                      AAUDIO_CONTENT_TYPE_SPEECH);
    AAudioStreamBuilder_setSampleRate(b, kSampleRate);
    AAudioStreamBuilder_setChannelCount(b, kChannels);
    AAudioStreamBuilder_setFormat(b, AAUDIO_FORMAT_PCM_I16);
    AAudioStreamBuilder_setSharingMode(b, AAUDIO_SHARING_MODE_SHARED);
    AAudioStreamBuilder_setPerformanceMode(b,
                                           AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
    const int32_t device_id = playout_device_id_.load();
    if (device_id > 0) AAudioStreamBuilder_setDeviceId(b, device_id);
    play_generation_.fetch_add(1);
    AAudioStreamBuilder_setDataCallback(b, &VeilAAudioAdm::PlayCallback, this);
    AAudioStreamBuilder_setErrorCallback(b, &VeilAAudioAdm::PlayErrorCallback, this);
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
    play_generation_.fetch_add(1);
    play_recovery_.store(0);
    if (play_stream_) {
      AAudioStream_requestStop(play_stream_);
      AAudioStream_close(play_stream_);
      play_stream_ = nullptr;
    }
    play_recovery_.store(0);
  }

  // AAudio forbids close/reopen on its error callback thread. The callback
  // only publishes the current generation. One owned worker serializes all
  // recovery with ordinary stop/device/start operations using lock_. No detached
  // thread captures this ADM, and retired generations cannot revive a stream.
  static void RecordErrorCallback(AAudioStream*, void* ud, aaudio_result_t error) {
    auto* self = static_cast<VeilAAudioAdm*>(ud);
    self->rec_error_.store(error);
    self->rec_recovery_.store(self->rec_generation_.load());
    self->recovery_cv_.notify_one();
  }
  static void PlayErrorCallback(AAudioStream*, void* ud, aaudio_result_t error) {
    auto* self = static_cast<VeilAAudioAdm*>(ud);
    self->play_error_.store(error);
    self->play_recovery_.store(self->play_generation_.load());
    self->recovery_cv_.notify_one();
  }
  void RecoverDisconnectedStreams() {
    std::unique_lock<std::mutex> wait_lock(recovery_wait_lock_);
    while (!recovery_stopping_.load()) {
      // A timed wait also covers a notification racing entry to the wait.
      recovery_cv_.wait_for(wait_lock, std::chrono::milliseconds(100), [this] {
        return recovery_stopping_.load() || rec_recovery_.load() != 0 ||
               play_recovery_.load() != 0;
      });
      if (recovery_stopping_.load()) break;
      const auto rec = rec_recovery_.exchange(0);
      const auto play = play_recovery_.exchange(0);
      bool retry = false;
      {
        std::lock_guard<std::mutex> lock(lock_);
        if (rec != 0 && rec == rec_generation_.load() && recording_.load()) {
          ALOG("aaudio_adm: recover recording error=%d", (int)rec_error_.load());
          CloseRecordStreamLocked();
          bool started = OpenRecordStreamLocked();
          if (started) {
            // A reopened device can negotiate different rate/channel settings.
            // Its old callback has exited before this buffer is replaced.
            // AudioDeviceBuffer remains started on its original control
            // sequence; recovery only replaces the native device and adapter.
            rec_fine_ = std::make_unique<webrtc::FineAudioBuffer>(&audio_device_buffer_);
            started = AAudioStream_requestStart(rec_stream_) == AAUDIO_OK;
          }
          ALOG("aaudio_adm: recover recording started=%d", (int)started);
          if (!started) {
            CloseRecordStreamLocked();
            rec_recovery_.store(rec_generation_.load());
            retry = true;
          }
        }
        if (play != 0 && play == play_generation_.load() && playing_.load()) {
          ALOG("aaudio_adm: recover playout error=%d", (int)play_error_.load());
          ClosePlayStreamLocked();
          bool started = OpenPlayStreamLocked();
          if (started) {
            play_fine_ = std::make_unique<webrtc::FineAudioBuffer>(&audio_device_buffer_);
            started = AAudioStream_requestStart(play_stream_) == AAUDIO_OK;
          }
          ALOG("aaudio_adm: recover playout started=%d", (int)started);
          if (!started) {
            ClosePlayStreamLocked();
            play_recovery_.store(play_generation_.load());
            retry = true;
          }
        }
      }
      // Device removal can outlast one open. Avoid a busy retry loop; stop and
      // destruction still wake immediately and clear the desired active flags.
      if (retry) recovery_cv_.wait_for(wait_lock, std::chrono::milliseconds(250),
                                      [this] { return recovery_stopping_.load(); });
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
  std::atomic<uint64_t> rec_generation_{0}, play_generation_{0};
  std::atomic<uint64_t> rec_recovery_{0}, play_recovery_{0};
  std::atomic<int32_t> rec_error_{0}, play_error_{0};
  std::atomic<bool> recovery_stopping_{false};
  std::mutex recovery_wait_lock_;
  std::condition_variable recovery_cv_;
  std::thread recovery_thread_;
};

}  // namespace

webrtc::scoped_refptr<webrtc::AudioDeviceModule> CreateVeilAAudioAdm(
    const webrtc::Environment& env) {
  return webrtc::make_ref_counted<VeilAAudioAdm>(env);
}

}  // namespace veil_media
#endif  // VEIL_MEDIA_HAVE_WEBRTC
