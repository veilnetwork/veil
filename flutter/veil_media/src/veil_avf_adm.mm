/* SPDX-License-Identifier: MIT
 *
 * veil_avf_adm.mm — AVAudioEngine-backed AudioDeviceModule (see veil_avf_adm.h).
 *
 * Capture:  engine.inputNode --tap--> AVAudioConverter(-> 48k int16 mono)
 *           --> FineAudioBuffer::DeliverRecordedData --> AudioDeviceBuffer
 *           --> AudioTransport (send stream / Opus).
 * Playout:  AudioTransport (mixed recv) --> AudioDeviceBuffer
 *           --> FineAudioBuffer::GetPlayoutData --> AVAudioSourceNode render
 *           --> mainMixerNode --> output.
 *
 * All AVAudioEngine graph mutations + start/stop are serialized on a dedicated
 * GCD queue so StartRecording/StartPlayout (called by AudioState on the Call
 * worker queue) never block the caller for long and never race the graph.
 */
#import <AVFoundation/AVFoundation.h>
#import <Foundation/Foundation.h>
#import <TargetConditionals.h>

#include "veil_avf_adm.h"

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <vector>

#include "api/audio/audio_device_defines.h"
#include "api/make_ref_counted.h"
#include "modules/audio_device/audio_device_buffer.h"
#include "modules/audio_device/fine_audio_buffer.h"
#include "modules/audio_device/include/audio_device_default.h"

namespace veil_media {
namespace {

constexpr uint32_t kSampleRate = 48000;
constexpr size_t kChannels = 1;
constexpr int kRecordDelayMs = 10;
constexpr int kPlayoutDelayMs = 40;
constexpr size_t kPlayTmpSamples = 8192;  // render blocks are ~512-4096 frames

void alog(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
#if TARGET_OS_IPHONE
  // iOS has no process-global writable /tmp. Keep diagnostics in the unified
  // device log; values are structural only (permission/state/frame counts),
  // never PCM or identity material.
  char line[512];
  vsnprintf(line, sizeof(line), fmt, ap);
  NSLog(@"veil_media: %s", line);
#else
  FILE* f = fopen("/tmp/veil_media_diag.log", "a");
  if (!f) {
    va_end(ap);
    return;
  }
  vfprintf(f, fmt, ap);
  fputc('\n', f);
  fclose(f);
#endif
  va_end(ap);
}

class VeilAvfAdm : public webrtc::webrtc_impl::AudioDeviceModuleDefault<
                       webrtc::AudioDeviceModule> {
 public:
  explicit VeilAvfAdm(const webrtc::Environment& env)
      : env_(env),
        audio_device_buffer_(env, /*create_detached=*/true) {
    engine_queue_ = dispatch_queue_create("veil.avf.adm", DISPATCH_QUEUE_SERIAL);
    play_tmp_.resize(kPlayTmpSamples, 0);
  }
  ~VeilAvfAdm() override { Terminate(); }

  // --- AudioTransport plumbing --------------------------------------------
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
    play_fine_ = std::make_unique<webrtc::FineAudioBuffer>(&audio_device_buffer_);
    initialized_ = true;
    alog("avf_adm: Init ok (48k mono)");
    return 0;
  }
  bool Initialized() const override { return initialized_; }

  int32_t Terminate() override {
    if (!initialized_) return 0;
    recording_.store(false);
    playing_.store(false);
    dispatch_sync(engine_queue_, ^{
      TeardownEngineLocked();
    });
    rec_fine_.reset();
    play_fine_.reset();
    initialized_ = false;
    return 0;
  }

  // --- availability / device enumeration (single virtual device) ----------
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
    std::snprintf(name, webrtc::kAdmMaxDeviceNameSize, "AVAudioEngine Input");
    guid[0] = '\0';
    return 0;
  }
  int32_t PlayoutDeviceName(uint16_t /*index*/,
                            char name[webrtc::kAdmMaxDeviceNameSize],
                            char guid[webrtc::kAdmMaxGuidSize]) override {
    std::snprintf(name, webrtc::kAdmMaxDeviceNameSize, "AVAudioEngine Output");
    guid[0] = '\0';
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

  // --- start / stop (called by AudioState on the Call worker queue) --------
  int32_t StartRecording() override {
    if (!initialized_) Init();
    recording_.store(true);
    // dispatch_ASYNC (not sync): StartRecording is invoked synchronously from the
    // FFI caller — the Flutter UI isolate (engine.cc calls adm->StartRecording()
    // straight from veil_media_engine_start_audio). The reconfigure it drives can
    // block on a cold CoreAudio setup or a denied/absent mic
    // ([AVAudioEngine startAndReturnError:] can wedge), and a dispatch_sync there
    // freezes the WHOLE app (device-observed: desktop UI hangs on accept). The
    // serial engine_queue_ still preserves start/stop order; audio just comes up a
    // beat later instead of taking the UI thread down with it.
    dispatch_async(engine_queue_, ^{
      if (rec_fine_) rec_fine_->ResetRecord();
      audio_device_buffer_.StartRecording();
      ReconfigureLocked();
    });
    alog("avf_adm: StartRecording (async)");
    return 0;
  }
  int32_t StopRecording() override {
    recording_.store(false);
    dispatch_sync(engine_queue_, ^{
      audio_device_buffer_.StopRecording();
      ReconfigureLocked();
    });
    return 0;
  }
  bool Recording() const override { return recording_.load(); }

  int32_t StartPlayout() override {
    if (!initialized_) Init();
    playing_.store(true);
    // dispatch_ASYNC — same reason as StartRecording: never block the FFI/UI
    // isolate on the CoreAudio engine start (it can wedge when the mic is denied).
    dispatch_async(engine_queue_, ^{
      if (play_fine_) play_fine_->ResetPlayout();
      audio_device_buffer_.StartPlayout();
      ReconfigureLocked();
    });
    alog("avf_adm: StartPlayout (async)");
    return 0;
  }
  int32_t StopPlayout() override {
    playing_.store(false);
    dispatch_sync(engine_queue_, ^{
      audio_device_buffer_.StopPlayout();
      ReconfigureLocked();
    });
    return 0;
  }
  bool Playing() const override { return playing_.load(); }

 private:
  // Rebuild engine run-state to match recording_/playing_. Runs on engine_queue_.
  void ReconfigureLocked() {
    EnsureEngineLocked();
    if (engine_ == nil) return;
    if (engine_.isRunning) [engine_ stop];

    AVAudioInputNode* input = engine_.inputNode;
    [input removeTapOnBus:0];
    if (recording_.load()) {
      AVAuthorizationStatus mic_auth =
          [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeAudio];
      alog("avf_adm: mic auth=%ld (0=notDetermined 2=denied 3=authorized)",
           (long)mic_auth);
      // Only attempt mic capture when it can actually work: authorization must
      // not be denied/restricted (a denied mic makes installTapOnBus throw or
      // deliver silence) and the input node must report a usable format.
      const bool mic_ok = (mic_auth != AVAuthorizationStatusDenied &&
                           mic_auth != AVAuthorizationStatusRestricted);
      AVAudioFormat* tap_fmt = [input outputFormatForBus:0];
      if (mic_ok && tap_fmt.sampleRate > 0 && tap_fmt.channelCount > 0) {
        int16_format_ = [[AVAudioFormat alloc]
            initWithCommonFormat:AVAudioPCMFormatInt16
                      sampleRate:kSampleRate
                        channels:(AVAudioChannelCount)kChannels
                     interleaved:YES];
        capture_converter_ = [[AVAudioConverter alloc] initFromFormat:tap_fmt
                                                             toFormat:int16_format_];
        const double ratio = (double)kSampleRate / tap_fmt.sampleRate;
        InstallCaptureTapLocked(input, tap_fmt, ratio);
      } else if (!mic_ok) {
        alog("avf_adm: mic not authorized (auth=%ld) — playout only, no capture",
             (long)mic_auth);
      } else {
        alog("avf_adm: input format not ready (sr=%.0f ch=%u) — mic ungranted?",
             tap_fmt.sampleRate, (unsigned)tap_fmt.channelCount);
      }
    }

    if (recording_.load() || playing_.load()) {
      // prepare/start can also throw (not just return an error) on a bad graph
      // or a mid-call route change — guard the same way so audio trouble never
      // aborts the app.
      @try {
        [engine_ prepare];
        NSError* err = nil;
        if (![engine_ startAndReturnError:&err]) {
          alog("avf_adm: engine start FAILED: %s",
               err ? err.localizedDescription.UTF8String : "?");
        } else {
          alog("avf_adm: engine running (rec=%d play=%d)",
               (int)recording_.load(), (int)playing_.load());
        }
      } @catch (NSException* e) {
        alog("avf_adm: engine prepare/start threw (%s)",
             e.reason.UTF8String ? e.reason.UTF8String : "?");
      }
    }
  }

  void InstallCaptureTapLocked(AVAudioInputNode* input,
                               AVAudioFormat* tap_fmt,
                               double ratio) {
    VeilAvfAdm* self = this;
    // AVAudioEngine THROWS (does not return an error) if the tap format no
    // longer matches the input node's hardware format — e.g. the audio route
    // switches mid-call (Bluetooth/headset connect, default device change)
    // between reading outputFormatForBus and installing the tap. An uncaught
    // ObjC exception across this ObjC++/C++ boundary calls std::terminate and
    // aborts the whole app. Catch it and degrade to "no mic this cycle"; a
    // later Reconfigure re-tries with the current format.
    @try {
      [input installTapOnBus:0
                  bufferSize:1024
                      format:tap_fmt
                       block:^(AVAudioPCMBuffer* buffer, AVAudioTime* /*when*/) {
                         self->OnCaptureBuffer(buffer, ratio);
                       }];
    } @catch (NSException* e) {
      alog("avf_adm: installTapOnBus threw (%s) — skipping mic capture",
           e.reason.UTF8String ? e.reason.UTF8String : "?");
      capture_converter_ = nil;
    }
  }

  // Runs on a CoreAudio capture thread.
  void OnCaptureBuffer(AVAudioPCMBuffer* buffer, double ratio) {
    if (!recording_.load() || capture_converter_ == nil || !rec_fine_) return;
    const AVAudioFrameCount cap =
        (AVAudioFrameCount)(buffer.frameLength * ratio) + 256;
    AVAudioPCMBuffer* out =
        [[AVAudioPCMBuffer alloc] initWithPCMFormat:int16_format_
                                      frameCapacity:cap];
    if (out == nil) return;
    __block BOOL fed = NO;
    NSError* err = nil;
    [capture_converter_
        convertToBuffer:out
                  error:&err
     withInputFromBlock:^AVAudioBuffer*(AVAudioPacketCount /*n*/,
                                        AVAudioConverterInputStatus* status) {
       if (fed) {
         *status = AVAudioConverterInputStatus_NoDataNow;
         return (AVAudioBuffer*)nil;
       }
       fed = YES;
       *status = AVAudioConverterInputStatus_HaveData;
       return (AVAudioBuffer*)buffer;
     }];
    const AVAudioFrameCount n = out.frameLength;
    if (n == 0 || out.int16ChannelData == nullptr) return;
    const int16_t* data = out.int16ChannelData[0];
    rec_fine_->DeliverRecordedData(
        std::span<const int16_t>(data, (size_t)n * kChannels), kRecordDelayMs);
    // Diagnostic: is the tap firing, and is it real audio (maxAbs>0) or silence?
    const uint64_t c = cap_count_.fetch_add(1);
    if (c % 100 == 0) {
      int16_t mx = 0;
      for (AVAudioFrameCount i = 0; i < n; ++i) {
        int16_t v = data[i];
        int16_t a = v < 0 ? (int16_t)-v : v;
        if (a > mx) mx = a;
      }
      alog("avf_adm: capture #%llu frames=%u maxAbs=%d",
           (unsigned long long)c, (unsigned)n, (int)mx);
    }
  }

  void EnsureEngineLocked() {
    if (engine_ != nil) return;
#if TARGET_OS_IPHONE
    // AVAudioEngine does not choose a bidirectional voice route on iOS by
    // itself. Configure the process audio session before touching inputNode:
    // VoiceChat enables the platform AEC path, Bluetooth headsets remain
    // available, and the built-in speaker is the safe default for a call.
    AVAudioSession* session = [AVAudioSession sharedInstance];
    NSError* session_error = nil;
    const AVAudioSessionCategoryOptions options =
        AVAudioSessionCategoryOptionAllowBluetoothHFP |
        AVAudioSessionCategoryOptionDefaultToSpeaker;
    if (![session setCategory:AVAudioSessionCategoryPlayAndRecord
                         mode:AVAudioSessionModeVoiceChat
                      options:options
                        error:&session_error]) {
      alog("avf_adm: setCategory failed: %s",
           session_error ? session_error.localizedDescription.UTF8String : "?");
    }
    session_error = nil;
    [session setPreferredSampleRate:kSampleRate error:&session_error];
    if (session_error) {
      alog("avf_adm: preferred sample rate failed: %s",
           session_error.localizedDescription.UTF8String);
    }
    session_error = nil;
    [session setPreferredIOBufferDuration:0.01 error:&session_error];
    if (session_error) {
      alog("avf_adm: preferred IO duration failed: %s",
           session_error.localizedDescription.UTF8String);
    }
    session_error = nil;
    if (![session setActive:YES error:&session_error]) {
      alog("avf_adm: audio session activation failed: %s",
           session_error ? session_error.localizedDescription.UTF8String : "?");
    }
#endif
    engine_ = [[AVAudioEngine alloc] init];
    AVAudioFormat* src_fmt = [[AVAudioFormat alloc]
        initWithCommonFormat:AVAudioPCMFormatFloat32
                  sampleRate:kSampleRate
                    channels:(AVAudioChannelCount)kChannels
                 interleaved:NO];
    VeilAvfAdm* self = this;
    source_node_ = [[AVAudioSourceNode alloc]
        initWithFormat:src_fmt
           renderBlock:^OSStatus(BOOL* is_silence,
                                 const AudioTimeStamp* /*ts*/,
                                 AVAudioFrameCount frame_count,
                                 AudioBufferList* out) {
             return self->OnRenderPlayout(is_silence, frame_count, out);
           }];
    // attach/connect can throw on a format mismatch with the mixer; guard so a
    // graph-build failure degrades instead of aborting the app.
    @try {
      [engine_ attachNode:source_node_];
      [engine_ connect:source_node_ to:engine_.mainMixerNode format:src_fmt];
    } @catch (NSException* e) {
      alog("avf_adm: attach/connect threw (%s)",
           e.reason.UTF8String ? e.reason.UTF8String : "?");
      engine_ = nil;  // leave un-built; ReconfigureLocked bails on engine_==nil
      source_node_ = nil;
    }
  }

  // Runs on the CoreAudio render thread.
  OSStatus OnRenderPlayout(BOOL* is_silence,
                           AVAudioFrameCount frame_count,
                           AudioBufferList* out) {
    if (out == nullptr || out->mNumberBuffers < 1) return noErr;
    float* dst = (float*)out->mBuffers[0].mData;
    const size_t need = (size_t)frame_count * kChannels;
    if (!playing_.load() || !play_fine_ || dst == nullptr ||
        need > play_tmp_.size()) {
      if (dst != nullptr) std::memset(dst, 0, frame_count * sizeof(float));
      *is_silence = YES;
      return noErr;
    }
    play_fine_->GetPlayoutData(std::span<int16_t>(play_tmp_.data(), need),
                               kPlayoutDelayMs);
    const float inv = 1.0f / 32768.0f;
    for (AVAudioFrameCount i = 0; i < frame_count; ++i) {
      dst[i] = (float)play_tmp_[i] * inv;
    }
    return noErr;
  }

  void TeardownEngineLocked() {
    if (engine_ == nil) return;
    if (engine_.isRunning) [engine_ stop];
    [engine_.inputNode removeTapOnBus:0];
    engine_ = nil;
    source_node_ = nil;
    capture_converter_ = nil;
    int16_format_ = nil;
#if TARGET_OS_IPHONE
    NSError* session_error = nil;
    [[AVAudioSession sharedInstance]
        setActive:NO
      withOptions:AVAudioSessionSetActiveOptionNotifyOthersOnDeactivation
            error:&session_error];
    if (session_error) {
      alog("avf_adm: audio session deactivation failed: %s",
           session_error.localizedDescription.UTF8String);
    }
#endif
  }

  webrtc::Environment env_;
  webrtc::AudioDeviceBuffer audio_device_buffer_;
  std::unique_ptr<webrtc::FineAudioBuffer> rec_fine_;
  std::unique_ptr<webrtc::FineAudioBuffer> play_fine_;
  std::vector<int16_t> play_tmp_;

  bool initialized_ = false;
  bool playout_initialized_ = false;
  bool recording_initialized_ = false;
  std::atomic<bool> recording_{false};
  std::atomic<bool> playing_{false};
  std::atomic<uint64_t> cap_count_{0};

  dispatch_queue_t engine_queue_ = nil;
  AVAudioEngine* engine_ = nil;
  AVAudioSourceNode* source_node_ = nil;
  AVAudioConverter* capture_converter_ = nil;
  AVAudioFormat* int16_format_ = nil;
};

}  // namespace

webrtc::scoped_refptr<webrtc::AudioDeviceModule> CreateVeilAvfAdm(
    const webrtc::Environment& env) {
  return webrtc::make_ref_counted<VeilAvfAdm>(env);
}

}  // namespace veil_media
#endif  // VEIL_MEDIA_HAVE_WEBRTC
