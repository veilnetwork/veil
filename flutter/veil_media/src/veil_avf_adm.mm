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
#if TARGET_OS_OSX
#import <CoreAudio/CoreAudio.h>
#endif

#include "veil_avf_adm.h"
#include "veil_diag_log.h"

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <span>
#include <string>
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

#if TARGET_OS_OSX
struct CoreAudioDeviceInfo {
  AudioDeviceID id = kAudioObjectUnknown;
  std::string name;
  std::string uid;
};

std::string CfStringUtf8(CFStringRef value) {
  if (value == nullptr) return {};
  const CFIndex size = CFStringGetMaximumSizeForEncoding(
                           CFStringGetLength(value), kCFStringEncodingUTF8) +
                       1;
  std::vector<char> text(static_cast<size_t>(size), 0);
  if (!CFStringGetCString(value, text.data(), size, kCFStringEncodingUTF8)) {
    return {};
  }
  return text.data();
}

std::vector<CoreAudioDeviceInfo> CoreAudioDevices(bool input) {
  AudioObjectPropertyAddress all_addr = {
      kAudioHardwarePropertyDevices, kAudioObjectPropertyScopeGlobal,
      kAudioObjectPropertyElementMain};
  UInt32 size = 0;
  if (AudioObjectGetPropertyDataSize(kAudioObjectSystemObject, &all_addr, 0,
                                     nullptr, &size) != noErr ||
      size == 0) {
    return {};
  }
  std::vector<AudioDeviceID> ids(size / sizeof(AudioDeviceID));
  if (AudioObjectGetPropertyData(kAudioObjectSystemObject, &all_addr, 0,
                                 nullptr, &size, ids.data()) != noErr) {
    return {};
  }

  const AudioObjectPropertyScope scope = input
      ? kAudioDevicePropertyScopeInput
      : kAudioDevicePropertyScopeOutput;
  std::vector<CoreAudioDeviceInfo> result;
  for (AudioDeviceID id : ids) {
    AudioObjectPropertyAddress stream_addr = {
        kAudioDevicePropertyStreamConfiguration, scope,
        kAudioObjectPropertyElementMain};
    UInt32 stream_size = 0;
    if (AudioObjectGetPropertyDataSize(id, &stream_addr, 0, nullptr,
                                       &stream_size) != noErr ||
        stream_size < sizeof(AudioBufferList)) {
      continue;
    }
    std::vector<uint8_t> stream_bytes(stream_size);
    auto* streams = reinterpret_cast<AudioBufferList*>(stream_bytes.data());
    if (AudioObjectGetPropertyData(id, &stream_addr, 0, nullptr, &stream_size,
                                   streams) != noErr) {
      continue;
    }
    UInt32 channels = 0;
    for (UInt32 i = 0; i < streams->mNumberBuffers; ++i) {
      channels += streams->mBuffers[i].mNumberChannels;
    }
    if (channels == 0) continue;

    CFStringRef name = nullptr;
    UInt32 string_size = sizeof(name);
    AudioObjectPropertyAddress name_addr = {
        kAudioObjectPropertyName, kAudioObjectPropertyScopeGlobal,
        kAudioObjectPropertyElementMain};
    AudioObjectGetPropertyData(id, &name_addr, 0, nullptr, &string_size, &name);
    CFStringRef uid = nullptr;
    string_size = sizeof(uid);
    AudioObjectPropertyAddress uid_addr = {
        kAudioDevicePropertyDeviceUID, kAudioObjectPropertyScopeGlobal,
        kAudioObjectPropertyElementMain};
    AudioObjectGetPropertyData(id, &uid_addr, 0, nullptr, &string_size, &uid);
    CoreAudioDeviceInfo info;
    info.id = id;
    info.name = CfStringUtf8(name);
    info.uid = CfStringUtf8(uid);
    if (name != nullptr) CFRelease(name);
    if (uid != nullptr) CFRelease(uid);
    if (info.name.empty()) info.name = input ? "Audio input" : "Audio output";
    // AVAudioEngine creates a private aggregate around its selected device.
    // CoreAudio exposes that aggregate globally while the call is running;
    // offering it back to the user produces a recursive/unstable route and a
    // duplicate-looking microphone. Only enumerate physical/system routes.
    if (info.name.rfind("CADefaultDeviceAggregate-", 0) == 0) continue;
    result.push_back(std::move(info));
  }

  AudioDeviceID default_id = kAudioObjectUnknown;
  UInt32 default_size = sizeof(default_id);
  AudioObjectPropertyAddress default_addr = {
      input ? kAudioHardwarePropertyDefaultInputDevice
            : kAudioHardwarePropertyDefaultOutputDevice,
      kAudioObjectPropertyScopeGlobal, kAudioObjectPropertyElementMain};
  if (AudioObjectGetPropertyData(kAudioObjectSystemObject, &default_addr, 0,
                                 nullptr, &default_size, &default_id) == noErr) {
    const auto it = std::find_if(result.begin(), result.end(),
                                 [default_id](const auto& item) {
                                   return item.id == default_id;
                                 });
    if (it != result.end() && it != result.begin()) {
      std::rotate(result.begin(), it, it + 1);
    }
  }
  return result;
}
#endif

void alog(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
#if TARGET_OS_IPHONE && !defined(NDEBUG)
  // iOS has no process-global writable /tmp. Keep diagnostics in the unified
  // device log; values are structural only (permission/state/frame counts),
  // never PCM or identity material.
  char line[512];
  vsnprintf(line, sizeof(line), fmt, ap);
  NSLog(@"veil_media: %s", line);
#else
  veil_media::diag::vlog(fmt, ap);
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

  // --- availability / device enumeration ----------------------------------
  int16_t PlayoutDevices() override {
#if TARGET_OS_OSX
    std::lock_guard<std::mutex> lock(devices_mu_);
    playout_devices_ = CoreAudioDevices(false);
    return static_cast<int16_t>(playout_devices_.size());
#else
    return 1;
#endif
  }
  int16_t RecordingDevices() override {
#if TARGET_OS_OSX
    std::lock_guard<std::mutex> lock(devices_mu_);
    recording_devices_ = CoreAudioDevices(true);
    return static_cast<int16_t>(recording_devices_.size());
#else
    return 1;
#endif
  }
  int32_t PlayoutIsAvailable(bool* available) override {
    *available = true;
    return 0;
  }
  int32_t RecordingIsAvailable(bool* available) override {
    *available = true;
    return 0;
  }
  int32_t RecordingDeviceName(uint16_t index,
                              char name[webrtc::kAdmMaxDeviceNameSize],
                              char guid[webrtc::kAdmMaxGuidSize]) override {
#if TARGET_OS_OSX
    std::lock_guard<std::mutex> lock(devices_mu_);
    if (index >= recording_devices_.size()) return -1;
    std::snprintf(name, webrtc::kAdmMaxDeviceNameSize, "%s",
                  recording_devices_[index].name.c_str());
    std::snprintf(guid, webrtc::kAdmMaxGuidSize, "%s",
                  recording_devices_[index].uid.c_str());
#else
    (void)index;
    std::snprintf(name, webrtc::kAdmMaxDeviceNameSize, "AVAudioEngine Input");
    guid[0] = '\0';
#endif
    return 0;
  }
  int32_t PlayoutDeviceName(uint16_t index,
                            char name[webrtc::kAdmMaxDeviceNameSize],
                            char guid[webrtc::kAdmMaxGuidSize]) override {
#if TARGET_OS_OSX
    std::lock_guard<std::mutex> lock(devices_mu_);
    if (index >= playout_devices_.size()) return -1;
    std::snprintf(name, webrtc::kAdmMaxDeviceNameSize, "%s",
                  playout_devices_[index].name.c_str());
    std::snprintf(guid, webrtc::kAdmMaxGuidSize, "%s",
                  playout_devices_[index].uid.c_str());
#else
    (void)index;
    std::snprintf(name, webrtc::kAdmMaxDeviceNameSize, "AVAudioEngine Output");
    guid[0] = '\0';
#endif
    return 0;
  }

  int32_t SetRecordingDevice(uint16_t index) override {
#if TARGET_OS_OSX
    std::lock_guard<std::mutex> lock(devices_mu_);
    if (index >= recording_devices_.size()) return -1;
    recording_device_id_.store(recording_devices_[index].id);
    return 0;
#else
    return index == 0 ? 0 : -1;
#endif
  }

  int32_t SetPlayoutDevice(uint16_t index) override {
#if TARGET_OS_OSX
    std::lock_guard<std::mutex> lock(devices_mu_);
    if (index >= playout_devices_.size()) return -1;
    playout_device_id_.store(playout_devices_[index].id);
    return 0;
#else
    return index == 0 ? 0 : -1;
#endif
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
    if (recording_.exchange(true)) return 0;
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
    if (!recording_.exchange(false)) return 0;
    dispatch_sync(engine_queue_, ^{
      audio_device_buffer_.StopRecording();
      ReconfigureLocked();
    });
    return 0;
  }
  bool Recording() const override { return recording_.load(); }

  int32_t StartPlayout() override {
    if (!initialized_) Init();
    if (playing_.exchange(true)) return 0;
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
    if (!playing_.exchange(false)) return 0;
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

    if (!recording_.load()) CancelMicAuthorizationTimerLocked();

    // `engine_.inputNode` is not a harmless getter on macOS: while microphone
    // access is still undetermined it may synchronously bind the HAL input
    // device and wedge inside CoreAudio. That used to strand engine_queue_ and
    // make the later StopRecording dispatch_sync freeze the entire Flutter UI.
    // Only touch the input graph after TCC is explicitly authorized, or when
    // removing a tap we know was installed earlier.
    if (capture_tap_installed_) {
      @try {
        [engine_.inputNode removeTapOnBus:0];
      } @catch (NSException* e) {
        alog("avf_adm: removeTapOnBus threw (%s)",
             e.reason.UTF8String ? e.reason.UTF8String : "?");
      }
      capture_tap_installed_ = false;
    }
    if (recording_.load()) {
      AVAuthorizationStatus mic_auth =
          [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeAudio];
      alog("avf_adm: mic auth=%ld (0=notDetermined 2=denied 3=authorized)",
           (long)mic_auth);
      // `notDetermined` is not usable permission: requesting input in that
      // state is exactly the blocking HAL path above. Stay playout-only until
      // the user grants access; a later media start/reconfigure will attach it.
      if (mic_auth == AVAuthorizationStatusAuthorized) {
        CancelMicAuthorizationTimerLocked();
        AVAudioInputNode* input = engine_.inputNode;
#if TARGET_OS_OSX
        const AudioDeviceID requested = recording_device_id_.load();
        if (requested != kAudioObjectUnknown) {
          NSError* device_error = nil;
          if (![input.AUAudioUnit setDeviceID:requested error:&device_error]) {
            alog("avf_adm: input device switch failed: %s",
                 device_error
                     ? device_error.localizedDescription.UTF8String
                     : "?");
          }
        }
#endif
        AVAudioFormat* tap_fmt = [input outputFormatForBus:0];
        if (tap_fmt.sampleRate <= 0 || tap_fmt.channelCount <= 0) {
          alog("avf_adm: input format not ready (sr=%.0f ch=%u)",
               tap_fmt.sampleRate, (unsigned)tap_fmt.channelCount);
        } else {
          int16_format_ = [[AVAudioFormat alloc]
              initWithCommonFormat:AVAudioPCMFormatInt16
                        sampleRate:kSampleRate
                          channels:(AVAudioChannelCount)kChannels
                       interleaved:YES];
          capture_converter_ =
              [[AVAudioConverter alloc] initFromFormat:tap_fmt
                                              toFormat:int16_format_];
          const double ratio = (double)kSampleRate / tap_fmt.sampleRate;
          InstallCaptureTapLocked(input, tap_fmt, ratio);
        }
      } else {
        alog("avf_adm: mic not authorized (auth=%ld) — playout only, no capture",
             (long)mic_auth);
        if (mic_auth == AVAuthorizationStatusNotDetermined) {
          EnsureMicAuthorizationTimerLocked();
        } else {
          CancelMicAuthorizationTimerLocked();
        }
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

  // A call must not wait indefinitely for the system permission sheet, but an
  // AVAudioEngine configured while TCC is still undetermined comes up
  // playout-only. Watch the authorization state on the same serial graph queue
  // and attach capture as soon as the user answers, without requiring another
  // call or rebuilding the media route. The timer is owned/cancelled on
  // engine_queue_, so no delayed block can outlive this ADM.
  void EnsureMicAuthorizationTimerLocked() {
    if (mic_auth_timer_ != nil) return;
    mic_auth_timer_ = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_TIMER, 0, 0, engine_queue_);
    if (mic_auth_timer_ == nil) return;
    dispatch_source_set_timer(
        mic_auth_timer_, dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC),
        250 * NSEC_PER_MSEC, 25 * NSEC_PER_MSEC);
    VeilAvfAdm* self = this;
    dispatch_source_set_event_handler(mic_auth_timer_, ^{
      if (!self->recording_.load()) {
        self->CancelMicAuthorizationTimerLocked();
        return;
      }
      const AVAuthorizationStatus status =
          [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeAudio];
      if (status == AVAuthorizationStatusNotDetermined) return;
      self->CancelMicAuthorizationTimerLocked();
      if (status == AVAuthorizationStatusAuthorized) {
        alog("avf_adm: mic permission granted mid-call — attaching capture");
        self->ReconfigureLocked();
      }
    });
    dispatch_resume(mic_auth_timer_);
  }

  void CancelMicAuthorizationTimerLocked() {
    if (mic_auth_timer_ == nil) return;
    dispatch_source_set_event_handler(mic_auth_timer_, nil);
    dispatch_source_cancel(mic_auth_timer_);
    mic_auth_timer_ = nil;
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
      capture_tap_installed_ = true;
    } @catch (NSException* e) {
      alog("avf_adm: installTapOnBus threw (%s) — skipping mic capture",
           e.reason.UTF8String ? e.reason.UTF8String : "?");
      capture_converter_ = nil;
      capture_tap_installed_ = false;
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
#if TARGET_OS_OSX
    const AudioDeviceID requested_output = playout_device_id_.load();
    if (requested_output != kAudioObjectUnknown) {
      NSError* device_error = nil;
      if (![engine_.outputNode.AUAudioUnit setDeviceID:requested_output
                                                error:&device_error]) {
        alog("avf_adm: output device switch failed: %s",
             device_error ? device_error.localizedDescription.UTF8String : "?");
      }
    }
#endif
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
    CancelMicAuthorizationTimerLocked();
    if (engine_ == nil) return;
    if (engine_.isRunning) [engine_ stop];
    if (capture_tap_installed_) {
      @try {
        [engine_.inputNode removeTapOnBus:0];
      } @catch (NSException* e) {
        alog("avf_adm: teardown removeTap threw (%s)",
             e.reason.UTF8String ? e.reason.UTF8String : "?");
      }
      capture_tap_installed_ = false;
    }
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
  dispatch_source_t mic_auth_timer_ = nil;
  AVAudioEngine* engine_ = nil;
  AVAudioSourceNode* source_node_ = nil;
  AVAudioConverter* capture_converter_ = nil;
  AVAudioFormat* int16_format_ = nil;
  bool capture_tap_installed_ = false;
#if TARGET_OS_OSX
  std::mutex devices_mu_;
  std::vector<CoreAudioDeviceInfo> recording_devices_;
  std::vector<CoreAudioDeviceInfo> playout_devices_;
  std::atomic<AudioDeviceID> recording_device_id_{kAudioObjectUnknown};
  std::atomic<AudioDeviceID> playout_device_id_{kAudioObjectUnknown};
#endif
};

}  // namespace

webrtc::scoped_refptr<webrtc::AudioDeviceModule> CreateVeilAvfAdm(
    const webrtc::Environment& env) {
  return webrtc::make_ref_counted<VeilAvfAdm>(env);
}

}  // namespace veil_media
#endif  // VEIL_MEDIA_HAVE_WEBRTC
