/* SPDX-License-Identifier: MIT
 *
 * veil_video_note.cc — implementation of the video-note recorder (VNOTE1).
 *
 * Audio: the exact mic->Opus->RAM pipeline of veil_audio_record.cc (its
 * CaptureSink, minus the waveform) — the audio section IS a VOICE_OPUS block,
 * so the voice playback/decode bricks consume it unchanged.
 *
 * Video: camera I420 frames (platform capturer on macOS/Linux, Dart push on
 * Android) -> center square crop -> scale to the target square ->
 * webrtc::CreateVp8Encoder DIRECTLY (no Call/VideoSendStream — the modular
 * CreateVp8Encoder/Decoder are linked in libwebrtc.a, unlike the header-only
 * builtin factories that crashed the call engine) -> timestamped VP8 frames
 * in RAM. First frame + every ~2 s is a forced keyframe.
 */

#include "veil_video_note.h"
#include "veil_diag_log.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
#include <cstdarg>

#include "api/audio/audio_device.h"
#include "api/audio/audio_device_defines.h"
#include "api/audio_codecs/audio_encoder.h"
#include "api/audio_codecs/audio_encoder_factory.h"
#include "api/audio_codecs/audio_format.h"
#include "api/audio_codecs/builtin_audio_encoder_factory.h"
#include "api/environment/environment.h"
#include "api/environment/environment_factory.h"
#include "api/scoped_refptr.h"
#include "api/video/encoded_image.h"
#include "api/video/i420_buffer.h"
#include "api/video/video_bitrate_allocation.h"
#include "api/video/video_frame.h"
#include "api/video/video_frame_type.h"
#include "api/video_codecs/video_codec.h"
#include "api/video_codecs/video_decoder.h"
#include "api/video_codecs/video_encoder.h"
#include "modules/video_coding/codecs/vp8/include/vp8.h"
#include "rtc_base/buffer.h"
#include "third_party/libyuv/include/libyuv/convert_argb.h"  // I420ToABGR

#if defined(__APPLE__) || (defined(__linux__) && !defined(__ANDROID__))
#define VEIL_VNOTE_HAVE_NATIVE_CAMERA 1
#include "veil_camera.h"
#endif

#if defined(__APPLE__)
#include "veil_avf_adm.h"
#elif defined(__ANDROID__)
#include "veil_aaudio_adm.h"
#else
#include "api/audio/create_audio_device_module.h"
#endif

namespace {

constexpr int kSampleRate = 48000;
constexpr int kOpusSdpChannels = 2;  // SDP convention (see veil_audio_record)
constexpr int kOpusPayloadType = 111;
constexpr int kDefaultSquare = 480;
constexpr int kDefaultFps = 24;
constexpr int kKeyframeEveryMs = 2000;
constexpr int kTargetBitrateBps = 500000;
// Bound RAM: a video note is short. 90 s @ 500 kbps VP8 + Opus is ~6 MB.
constexpr int kMaxDurationMs = 90 * 1000;

void vnlog(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  veil_media::diag::vlog(fmt, ap);
  va_end(ap);
}

void put_u16le(std::vector<uint8_t>& v, uint16_t x) {
  v.push_back(x & 0xff);
  v.push_back((x >> 8) & 0xff);
}
void put_u32le(std::vector<uint8_t>& v, uint32_t x) {
  v.push_back(x & 0xff);
  v.push_back((x >> 8) & 0xff);
  v.push_back((x >> 16) & 0xff);
  v.push_back((x >> 24) & 0xff);
}

// Mic -> Opus -> RAM (the voice recorder's CaptureSink without the waveform).
// finish() emits a complete VOICE_OPUS block — byte-compatible with the voice
// bricks, so decode-to-WAV consumes the audio section unchanged.
class VnoteAudioSink : public webrtc::AudioTransport {
 public:
  explicit VnoteAudioSink(std::unique_ptr<webrtc::AudioEncoder> enc)
      : encoder_(std::move(enc)),
        enc_rate_(encoder_->SampleRateHz()),
        enc_channels_((int)encoder_->NumChannels()),
        frame_mono_(enc_rate_ / 100),
        frame_samples_(frame_mono_ * enc_channels_) {}

  int32_t RecordedDataIsAvailable(const void* audioSamples, size_t nSamples,
                                  size_t nBytesPerSample, size_t nChannels,
                                  uint32_t /*samplesPerSec*/,
                                  uint32_t /*delayMS*/, int32_t /*clockDrift*/,
                                  uint32_t /*micLevel*/, bool /*keyPressed*/,
                                  uint32_t& newMicLevel) override {
    newMicLevel = 0;
    if (audioSamples == nullptr || nBytesPerSample != sizeof(int16_t)) {
      return 0;
    }
    const int16_t* in = static_cast<const int16_t*>(audioSamples);
    std::lock_guard<std::mutex> lk(mu_);
    if (finished_ ||
        total_samples_ >= (int64_t)enc_rate_ * kMaxDurationMs / 1000) {
      return 0;
    }
    const size_t ch = nChannels == 0 ? 1 : nChannels;
    float peak = 0.f;
    for (size_t i = 0; i < nSamples; i++) {
      int32_t acc = 0;
      for (size_t c = 0; c < ch; c++) acc += in[i * ch + c];
      int16_t s = (int16_t)(acc / (int32_t)ch);
      pending_.push_back(s);
      float a = (s < 0 ? -(float)s : (float)s) / 32768.f;
      if (a > peak) peak = a;
    }
    float lv = level_.load(std::memory_order_relaxed);
    lv = peak > lv ? peak : lv * 0.85f + peak * 0.15f;
    level_.store(lv, std::memory_order_relaxed);

    std::vector<int16_t> frame(frame_samples_);
    while ((int)pending_.size() >= frame_mono_) {
      for (int i = 0; i < frame_mono_; i++) {
        int16_t s = pending_[i];
        for (int c = 0; c < enc_channels_; c++) {
          frame[i * enc_channels_ + c] = s;
        }
      }
      webrtc::Buffer encoded;
      auto info = encoder_->Encode(
          rtp_ts_, std::span<const int16_t>(frame.data(), frame_samples_),
          &encoded);
      rtp_ts_ += frame_mono_;
      total_samples_ += frame_mono_;
      if (info.encoded_bytes > 0) {
        put_u16le(stream_, (uint16_t)info.encoded_bytes);
        stream_.insert(stream_.end(), encoded.data(),
                       encoded.data() + info.encoded_bytes);
        packet_count_++;
      }
      pending_.erase(pending_.begin(), pending_.begin() + frame_mono_);
    }
    return 0;
  }

  int32_t NeedMorePlayData(size_t nSamples, size_t nBytesPerSample,
                           size_t nChannels, uint32_t /*samplesPerSec*/,
                           void* audioSamples, size_t& nSamplesOut,
                           int64_t* elapsed_time_ms,
                           int64_t* ntp_time_ms) override {
    if (audioSamples) {
      std::memset(audioSamples, 0, nSamples * nBytesPerSample * nChannels);
    }
    nSamplesOut = nSamples;
    if (elapsed_time_ms) *elapsed_time_ms = -1;
    if (ntp_time_ms) *ntp_time_ms = -1;
    return 0;
  }
  void PullRenderData(int /*bits_per_sample*/, int /*sample_rate*/,
                      size_t number_of_channels, size_t number_of_frames,
                      void* audio_data, int64_t* elapsed_time_ms,
                      int64_t* ntp_time_ms) override {
    if (audio_data) {
      std::memset(audio_data, 0,
                  number_of_frames * number_of_channels * sizeof(int16_t));
    }
    if (elapsed_time_ms) *elapsed_time_ms = -1;
    if (ntp_time_ms) *ntp_time_ms = -1;
  }

  float level() const { return level_.load(std::memory_order_relaxed); }

  // Finalize: a complete VOICE_OPUS block (or empty when nothing captured).
  void finish(std::vector<uint8_t>* out, int* duration_ms) {
    std::lock_guard<std::mutex> lk(mu_);
    finished_ = true;
    const int dur = (int)(total_samples_ * 1000 / enc_rate_);
    if (duration_ms) *duration_ms = dur;
    out->clear();
    if (packet_count_ > 0) {
      const char magic[4] = {'V', 'O', 'P', '1'};
      out->insert(out->end(), magic, magic + 4);
      out->push_back(1);
      out->push_back((uint8_t)enc_channels_);
      put_u32le(*out, (uint32_t)enc_rate_);
      put_u32le(*out, (uint32_t)dur);
      put_u32le(*out, (uint32_t)packet_count_);
      out->insert(out->end(), stream_.begin(), stream_.end());
    }
  }

 private:
  std::unique_ptr<webrtc::AudioEncoder> encoder_;
  const int enc_rate_;
  const int enc_channels_;
  const int frame_mono_;
  const int frame_samples_;
  std::mutex mu_;
  std::vector<int16_t> pending_;
  std::vector<uint8_t> stream_;  // [u16 len][opus] packets
  std::atomic<float> level_{0.f};
  int64_t total_samples_ = 0;
  int64_t rtp_ts_ = 0;
  uint32_t packet_count_ = 0;
  bool finished_ = false;
};

struct VideoRec {
  uint32_t ts_ms;
  bool key;
  std::vector<uint8_t> bytes;
};

// Receives encoded VP8 frames synchronously from Encode() (libvpx calls the
// callback on the encoding thread) and stores them for the container.
class VnoteEncodeSink : public webrtc::EncodedImageCallback {
 public:
  Result OnEncodedImage(const webrtc::EncodedImage& img,
                        const webrtc::CodecSpecificInfo*) override {
    VideoRec r;
    r.ts_ms = img.RtpTimestamp() / 90;  // we stamp input frames at ts_ms * 90
    r.key = img.FrameType() == webrtc::VideoFrameType::kVideoFrameKey;
    r.bytes.assign(img.data(), img.data() + img.size());
    recs.push_back(std::move(r));
    return Result(Result::OK);
  }
  void OnFrameDropped(uint32_t /*rtp_timestamp*/, int /*spatial_id*/,
                      bool /*is_end_of_temporal_unit*/) override {}
  std::vector<VideoRec> recs;  // guarded by the recorder's video mutex
};

// Latest-decoded-frame sink (the VeilVideoSink pattern from the call engine):
// Decoded() runs on the decode call stack; the RGBA copy is pulled by the app.
class VnoteDecodeSink : public webrtc::DecodedImageCallback {
 public:
  int32_t Decoded(webrtc::VideoFrame& frame) override {
    auto buf = frame.video_frame_buffer()->ToI420();
    if (buf == nullptr) return 0;
    const int w = buf->width(), h = buf->height();
    if (w <= 0 || h <= 0) return 0;
    const size_t need = (size_t)w * h * 4;
    std::lock_guard<std::mutex> lk(mu_);
    if (rgba_.size() < need) rgba_.resize(need);
    libyuv::I420ToABGR(buf->DataY(), buf->StrideY(), buf->DataU(),
                       buf->StrideU(), buf->DataV(), buf->StrideV(),
                       rgba_.data(), w * 4, w, h);
    w_ = w;
    h_ = h;
    ++seq_;
    return 0;
  }

  // Direct I420 store (the recorder's self-preview uses the same sink).
  void store_i420(const uint8_t* y, const uint8_t* u, const uint8_t* v, int w,
                  int h, int sy, int su, int sv) {
    if (!y || !u || !v || w <= 0 || h <= 0) return;
    const size_t need = (size_t)w * h * 4;
    std::lock_guard<std::mutex> lk(mu_);
    if (rgba_.size() < need) rgba_.resize(need);
    libyuv::I420ToABGR(y, sy, u, su, v, sv, rgba_.data(), w * 4, w, h);
    w_ = w;
    h_ = h;
    ++seq_;
  }

  int get_frame(uint8_t* dst, int dst_cap, int* out_w, int* out_h) {
    std::lock_guard<std::mutex> lk(mu_);
    if (seq_ == 0 || w_ <= 0) return 0;
    if (out_w) *out_w = w_;
    if (out_h) *out_h = h_;
    const size_t need = (size_t)w_ * h_ * 4;
    if (dst == nullptr || dst_cap < 0 || (size_t)dst_cap < need) return -1;
    std::memcpy(dst, rgba_.data(), need);
    return (int)seq_;
  }

 private:
  std::mutex mu_;
  std::vector<uint8_t> rgba_;
  int w_ = 0, h_ = 0;
  uint32_t seq_ = 0;
};

uint32_t rd_u32le(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}
uint16_t rd_u16le(const uint8_t* p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

struct VnoteFrameRef {
  uint32_t ts_ms;
  bool key;
  size_t off;  // into the player's owned container copy
  uint32_t len;
};

}  // namespace
#endif  // VEIL_MEDIA_HAVE_WEBRTC

struct VeilVnoteRecorder {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  webrtc::Environment env;
  int square;
  int fps;

  // Audio (mirrors the voice recorder).
  webrtc::scoped_refptr<webrtc::AudioDeviceModule> adm;
  std::unique_ptr<VnoteAudioSink> audio;
  bool mic_recording = false;

  bool want_native_camera = true;
  VnoteDecodeSink preview;  // latest captured frame (live self-preview)
  // Video. All encoder state is guarded by video_mu — camera frames arrive on
  // the capture queue, push_frame on the FFI thread, stop() on control.
  std::mutex video_mu;
  std::unique_ptr<webrtc::VideoEncoder> enc;
  VnoteEncodeSink enc_sink;
  bool enc_ready = false;
  bool encoding = false;
  int enc_w = 0, enc_h = 0;
  int64_t last_key_ms = -kKeyframeEveryMs;
  std::chrono::steady_clock::time_point started_at;

#if defined(VEIL_VNOTE_HAVE_NATIVE_CAMERA)
  std::unique_ptr<veil_media::CameraCapturer> camera;
#endif

  VeilVnoteRecorder(webrtc::Environment e, int sq, int f)
      : env(std::move(e)), square(sq), fps(f) {}
#endif
};

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
namespace {

// Lazy-init the VP8 encoder once the (cropped, scaled) square size is known.
// Called under video_mu.
bool ensure_encoder(VeilVnoteRecorder* rec, int w, int h) {
  if (rec->enc_ready) return true;
  rec->enc = webrtc::CreateVp8Encoder(rec->env);
  if (!rec->enc) {
    vnlog("vnote: CreateVp8Encoder failed");
    return false;
  }
  webrtc::VideoCodec codec = {};
  codec.codecType = webrtc::kVideoCodecVP8;
  codec.width = (uint16_t)w;
  codec.height = (uint16_t)h;
  codec.maxFramerate = (uint32_t)rec->fps;
  codec.startBitrate = kTargetBitrateBps / 1000;  // kbps
  codec.maxBitrate = kTargetBitrateBps * 2 / 1000;
  codec.minBitrate = 50;
  codec.active = true;
  codec.numberOfSimulcastStreams = 0;  // singlecast
  *codec.VP8() = webrtc::VideoEncoder::GetDefaultVp8Settings();
  codec.VP8()->keyFrameInterval = rec->fps * 10;  // we force keys ourselves
  webrtc::VideoEncoder::Capabilities caps(/*loss_notification=*/false);
  webrtc::VideoEncoder::Settings settings(caps, /*number_of_cores=*/2,
                                          /*max_payload_size=*/1 << 20);
  if (rec->enc->InitEncode(&codec, settings) < 0) {
    vnlog("vnote: InitEncode failed %dx%d", w, h);
    rec->enc.reset();
    return false;
  }
  rec->enc->RegisterEncodeCompleteCallback(&rec->enc_sink);
  webrtc::VideoBitrateAllocation alloc;
  alloc.SetBitrate(0, 0, kTargetBitrateBps);
  rec->enc->SetRates(webrtc::VideoEncoder::RateControlParameters(
      alloc, (double)rec->fps));
  rec->enc_ready = true;
  rec->enc_w = w;
  rec->enc_h = h;
  vnlog("vnote: encoder ready %dx%d@%d", w, h, rec->fps);
  return true;
}

// Center-crop to an even square, scale to the recorder's target square, then
// VP8-encode. Called from the camera callback / push_frame; takes video_mu.
void encode_i420(VeilVnoteRecorder* rec, const uint8_t* y, const uint8_t* u,
                 const uint8_t* v, int w, int h, int sy, int su, int sv) {
  if (w <= 1 || h <= 1) return;
  std::lock_guard<std::mutex> lk(rec->video_mu);
  if (!rec->encoding) return;
  const int64_t ts_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - rec->started_at)
                            .count();
  if (ts_ms > kMaxDurationMs) return;

  const int s = std::min(w, h) & ~1;
  const int ox = ((w - s) / 2) & ~1;
  const int oy = ((h - s) / 2) & ~1;
  const uint8_t* cy = y + (size_t)oy * sy + ox;
  const uint8_t* cu = u + (size_t)(oy / 2) * su + ox / 2;
  const uint8_t* cv = v + (size_t)(oy / 2) * sv + ox / 2;

  const int target = std::min(rec->square, s) & ~1;
  if (target < 2) return;
  if (!ensure_encoder(rec, target, target)) return;

  webrtc::scoped_refptr<webrtc::I420Buffer> buf =
      webrtc::I420Buffer::Create(rec->enc_w, rec->enc_h);
  // ScaleFrom handles both the downscale and the plain copy (same size).
  webrtc::scoped_refptr<webrtc::I420Buffer> cropped =
      webrtc::I420Buffer::Copy(s, s, cy, sy, cu, su, cv, sv);
  buf->ScaleFrom(*cropped);

  rec->preview.store_i420(buf->DataY(), buf->DataU(), buf->DataV(),
                          buf->width(), buf->height(), buf->StrideY(),
                          buf->StrideU(), buf->StrideV());
  const bool want_key = ts_ms - rec->last_key_ms >= kKeyframeEveryMs;
  if (want_key) rec->last_key_ms = ts_ms;
  webrtc::VideoFrame frame = webrtc::VideoFrame::Builder()
                                 .set_video_frame_buffer(buf)
                                 .set_rtp_timestamp((uint32_t)(ts_ms * 90))
                                 .set_timestamp_us(ts_ms * 1000)
                                 .build();
  std::vector<webrtc::VideoFrameType> types{
      want_key ? webrtc::VideoFrameType::kVideoFrameKey
               : webrtc::VideoFrameType::kVideoFrameDelta};
  rec->enc->Encode(frame, &types);
}

}  // namespace
#endif  // VEIL_MEDIA_HAVE_WEBRTC

extern "C" {

VeilVnoteRecorder* veil_media_vnote_recorder_create(int width, int fps,
                                                    int native_camera) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  webrtc::Environment env = webrtc::CreateEnvironment();
  auto rec = new VeilVnoteRecorder(env, width > 0 ? width & ~1 : kDefaultSquare,
                                   fps > 0 ? fps : kDefaultFps);
  rec->want_native_camera = native_camera != 0;
#if defined(__APPLE__)
  rec->adm = veil_media::CreateVeilAvfAdm(rec->env);
#elif defined(__ANDROID__)
  rec->adm = veil_media::CreateVeilAAudioAdm(rec->env);
#else
  rec->adm = webrtc::CreateAudioDeviceModule(
      rec->env, webrtc::AudioDeviceModule::kPlatformDefaultAudio);
#endif
  if (!rec->adm) {
    vnlog("vnote: no ADM");
    delete rec;
    return nullptr;
  }
  rec->adm->Init();
  auto factory = webrtc::CreateBuiltinAudioEncoderFactory();
  webrtc::AudioEncoderFactory::Options opts;
  opts.payload_type = kOpusPayloadType;
  auto enc = factory->Create(
      rec->env, webrtc::SdpAudioFormat("opus", kSampleRate, kOpusSdpChannels),
      opts);
  if (!enc) {
    vnlog("vnote: no Opus encoder");
    delete rec;
    return nullptr;
  }
  rec->audio = std::make_unique<VnoteAudioSink>(std::move(enc));
  return rec;
#else
  (void)width;
  (void)fps;
  (void)native_camera;
  return nullptr;
#endif
}

int veil_media_vnote_recorder_start(VeilVnoteRecorder* rec) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!rec || !rec->adm || !rec->audio) return VEIL_VNOTE_ERR_ARG;
  {
    std::lock_guard<std::mutex> lk(rec->video_mu);
    if (rec->encoding) return VEIL_VNOTE_OK;
    rec->started_at = std::chrono::steady_clock::now();
    rec->encoding = true;
  }
  // Microphone — identical to the voice recorder, but NOT fatal: the app
  // layer gates the permission before recording, so a missing mic here is a
  // transient (device busy) — a silent video note beats a hard refusal. The
  // audio flag in the container reflects what was actually captured.
  bool rec_avail = false;
  rec->adm->RecordingIsAvailable(&rec_avail);
  if (rec_avail) {
    rec->adm->RegisterAudioCallback(rec->audio.get());
    if (rec->adm->InitRecording() == 0 && rec->adm->StartRecording() == 0) {
      rec->mic_recording = true;
    } else {
      vnlog("vnote: mic start failed — recording video-only");
    }
  } else {
    vnlog("vnote: mic unavailable (permission?) — recording video-only");
  }
#if defined(VEIL_VNOTE_HAVE_NATIVE_CAMERA)
  // Platform camera; frames flow into the VP8 encoder. Android has no native
  // backend — its Dart capturer pushes via veil_media_vnote_recorder_push_frame.
  if (rec->want_native_camera)
  rec->camera.reset(veil_media::CreatePlatformCamera(
      [rec](const uint8_t* y, const uint8_t* u, const uint8_t* v, int w, int h,
            int sy, int su, int sv, int64_t /*ts_us*/) {
        encode_i420(rec, y, u, v, w, h, sy, su, sv);
      }));
  if (rec->camera && !rec->camera->Start(rec->square, rec->square, rec->fps)) {
    vnlog("vnote: camera start failed (frames only from push)");
    rec->camera.reset();
  }
#endif
  vnlog("vnote: started square=%d fps=%d", rec->square, rec->fps);
  return VEIL_VNOTE_OK;
#else
  (void)rec;
  return VEIL_VNOTE_ERR;
#endif
}

int veil_media_vnote_recorder_push_frame(VeilVnoteRecorder* rec,
                                         const uint8_t* y, const uint8_t* u,
                                         const uint8_t* v, int width,
                                         int height, int stride_y,
                                         int stride_u, int stride_v,
                                         int64_t /*ts_us*/) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!rec || !y || !u || !v) return VEIL_VNOTE_ERR_ARG;
  encode_i420(rec, y, u, v, width, height, stride_y, stride_u, stride_v);
  return VEIL_VNOTE_OK;
#else
  (void)rec; (void)y; (void)u; (void)v; (void)width; (void)height;
  (void)stride_y; (void)stride_u; (void)stride_v;
  return VEIL_VNOTE_ERR;
#endif
}

float veil_media_vnote_recorder_level(VeilVnoteRecorder* rec) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return (rec && rec->audio) ? rec->audio->level() : 0.f;
#else
  (void)rec;
  return 0.f;
#endif
}

int veil_media_vnote_recorder_frame(VeilVnoteRecorder* rec, uint8_t* dst,
                                    int dst_cap, int* out_w, int* out_h) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!rec) return 0;
  return rec->preview.get_frame(dst, dst_cap, out_w, out_h);
#else
  (void)rec; (void)dst; (void)dst_cap; (void)out_w; (void)out_h;
  return 0;
#endif
}

int veil_media_vnote_recorder_elapsed_ms(VeilVnoteRecorder* rec) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!rec) return 0;
  std::lock_guard<std::mutex> lk(rec->video_mu);
  if (!rec->encoding) return 0;
  return (int)std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - rec->started_at)
      .count();
#else
  (void)rec;
  return 0;
#endif
}

int veil_media_vnote_recorder_stop(VeilVnoteRecorder* rec, uint8_t** out_bytes,
                                   size_t* out_len, int* out_duration_ms) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!rec) return VEIL_VNOTE_ERR_ARG;
  if (out_bytes) *out_bytes = nullptr;
  if (out_len) *out_len = 0;
  // Stop accepting frames BEFORE tearing sources down (an in-flight camera
  // callback finishes under video_mu; new ones bail on !encoding).
  {
    std::lock_guard<std::mutex> lk(rec->video_mu);
    rec->encoding = false;
  }
#if defined(VEIL_VNOTE_HAVE_NATIVE_CAMERA)
  if (rec->camera) {
    rec->camera->Stop();
    rec->camera.reset();
  }
#endif
  if (rec->mic_recording && rec->adm) {
    if (rec->adm->Recording()) rec->adm->StopRecording();
    rec->mic_recording = false;
  }

  std::vector<uint8_t> audio_block;
  int audio_dur = 0;
  rec->audio->finish(&audio_block, &audio_dur);

  std::lock_guard<std::mutex> lk(rec->video_mu);
  if (rec->enc_ready && rec->enc) {
    rec->enc->Release();
  }
  auto& recs = rec->enc_sink.recs;
  uint32_t video_dur = 0;
  if (!recs.empty()) {
    // Last frame's timestamp plus one nominal frame interval.
    video_dur = recs.back().ts_ms + (uint32_t)(1000 / std::max(1, rec->fps));
  }
  const uint32_t dur =
      std::max<uint32_t>((uint32_t)std::max(0, audio_dur), video_dur);
  if (out_duration_ms) *out_duration_ms = (int)dur;
  if (recs.empty() && audio_block.empty()) {
    return VEIL_VNOTE_OK;  // empty clip
  }

  std::vector<uint8_t> out;
  const char magic[4] = {'V', 'N', '0', '1'};
  out.insert(out.end(), magic, magic + 4);
  out.push_back(1);  // version
  uint8_t flags = 0;
  if (!audio_block.empty()) flags |= 1;
  if (!recs.empty()) flags |= 2;
  out.push_back(flags);
  put_u16le(out, (uint16_t)rec->enc_w);
  put_u16le(out, (uint16_t)rec->enc_h);
  out.push_back((uint8_t)std::min(rec->fps, 255));
  out.push_back(0);  // reserved
  put_u32le(out, dur);
  put_u32le(out, (uint32_t)audio_block.size());
  put_u32le(out, (uint32_t)recs.size());
  out.insert(out.end(), audio_block.begin(), audio_block.end());
  for (const auto& r : recs) {
    put_u32le(out, r.ts_ms);
    out.push_back(r.key ? 1 : 0);
    put_u32le(out, (uint32_t)r.bytes.size());
    out.insert(out.end(), r.bytes.begin(), r.bytes.end());
  }
  vnlog("vnote: stop — %zu bytes, %zu frames, audio %zu B, dur %u ms",
        out.size(), recs.size(), audio_block.size(), dur);

  if (out_bytes && out_len) {
    uint8_t* buf = (uint8_t*)malloc(out.size());
    if (!buf) return VEIL_VNOTE_ERR;
    std::memcpy(buf, out.data(), out.size());
    *out_bytes = buf;
    *out_len = out.size();
  }
  return VEIL_VNOTE_OK;
#else
  (void)rec; (void)out_bytes; (void)out_len; (void)out_duration_ms;
  return VEIL_VNOTE_ERR;
#endif
}

void veil_media_vnote_free_bytes(uint8_t* bytes) {
  if (bytes) free(bytes);
}

// ── Player ──────────────────────────────────────────────────────────────────

struct VeilVnotePlayer {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  webrtc::Environment env;
  std::vector<uint8_t> bytes;        // owned copy of the container
  std::vector<VnoteFrameRef> frames; // offsets into `bytes`
  size_t audio_off = 0;
  uint32_t audio_len = 0;
  int width = 0, height = 0, fps = 0;
  uint32_t duration_ms = 0;

  std::unique_ptr<webrtc::VideoDecoder> dec;
  VnoteDecodeSink sink;
  std::mutex mu;          // decode-position state below
  size_t next_idx = 0;    // next frame to decode
  int64_t last_ts = -1;   // ts of the last decoded frame (-1 = none)

  explicit VeilVnotePlayer(webrtc::Environment e) : env(std::move(e)) {}
#endif
};

extern "C" VeilVnotePlayer* veil_media_vnote_player_create(
    const uint8_t* vnote, size_t len) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  // Strict parse — the clip arrives over the network. Every offset is
  // bounds-checked; any inconsistency rejects the whole container.
  if (vnote == nullptr || len < 24) return nullptr;
  if (std::memcmp(vnote, "VN01", 4) != 0 || vnote[4] != 1) return nullptr;
  const uint8_t flags = vnote[5];
  const uint16_t w = rd_u16le(vnote + 6);
  const uint16_t h = rd_u16le(vnote + 8);
  const uint8_t fps = vnote[10];
  const uint32_t dur = rd_u32le(vnote + 12);
  const uint32_t audio_len = rd_u32le(vnote + 16);
  const uint32_t frame_count = rd_u32le(vnote + 20);
  if ((uint64_t)24 + audio_len > len) return nullptr;
  if ((flags & 1) && audio_len == 0) return nullptr;

  auto p = new VeilVnotePlayer(webrtc::CreateEnvironment());
  p->bytes.assign(vnote, vnote + len);
  p->audio_off = 24;
  p->audio_len = audio_len;
  p->width = w;
  p->height = h;
  p->fps = fps;
  p->duration_ms = dur;

  size_t off = 24 + audio_len;
  p->frames.reserve(frame_count);
  uint32_t last_ts = 0;
  for (uint32_t i = 0; i < frame_count; i++) {
    if (off + 9 > len) { delete p; return nullptr; }
    VnoteFrameRef f;
    f.ts_ms = rd_u32le(p->bytes.data() + off);
    f.key = (p->bytes[off + 4] & 1) != 0;
    f.len = rd_u32le(p->bytes.data() + off + 5);
    off += 9;
    if (f.len == 0 || off + f.len > len) { delete p; return nullptr; }
    if (f.ts_ms < last_ts) { delete p; return nullptr; }  // monotonic
    last_ts = f.ts_ms;
    f.off = off;
    off += f.len;
    p->frames.push_back(f);
  }
  if (off != len) { delete p; return nullptr; }  // trailing garbage
  if (!p->frames.empty() && !p->frames.front().key) { delete p; return nullptr; }

  if (!p->frames.empty()) {
    p->dec = webrtc::CreateVp8Decoder(p->env);
    if (!p->dec) { delete p; return nullptr; }
    webrtc::VideoDecoder::Settings s;
    s.set_codec_type(webrtc::kVideoCodecVP8);
    s.set_number_of_cores(2);
    if (!p->dec->Configure(s)) { delete p; return nullptr; }
    p->dec->RegisterDecodeCompleteCallback(&p->sink);
  }
  return p;
#else
  (void)vnote;
  (void)len;
  return nullptr;
#endif
}

extern "C" int veil_media_vnote_player_duration_ms(VeilVnotePlayer* p) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return p ? (int)p->duration_ms : 0;
#else
  (void)p;
  return 0;
#endif
}

extern "C" int veil_media_vnote_player_width(VeilVnotePlayer* p) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return p ? p->width : 0;
#else
  (void)p;
  return 0;
#endif
}

extern "C" int veil_media_vnote_player_height(VeilVnotePlayer* p) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return p ? p->height : 0;
#else
  (void)p;
  return 0;
#endif
}

extern "C" int veil_media_vnote_player_has_audio(VeilVnotePlayer* p) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return (p && p->audio_len > 0) ? 1 : 0;
#else
  (void)p;
  return 0;
#endif
}

extern "C" int veil_media_vnote_player_audio(VeilVnotePlayer* p,
                                             uint8_t** out_bytes,
                                             size_t* out_len) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!p || !out_bytes || !out_len) return VEIL_VNOTE_ERR_ARG;
  *out_bytes = nullptr;
  *out_len = 0;
  if (p->audio_len == 0) return VEIL_VNOTE_ERR;
  uint8_t* buf = (uint8_t*)malloc(p->audio_len);
  if (!buf) return VEIL_VNOTE_ERR;
  std::memcpy(buf, p->bytes.data() + p->audio_off, p->audio_len);
  *out_bytes = buf;
  *out_len = p->audio_len;
  return VEIL_VNOTE_OK;
#else
  (void)p; (void)out_bytes; (void)out_len;
  return VEIL_VNOTE_ERR;
#endif
}

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
namespace {
// Decode one indexed frame into the sink. Caller holds p->mu.
void vnote_decode_one(VeilVnotePlayer* p, const VnoteFrameRef& f) {
  webrtc::EncodedImage img;
  img.SetEncodedData(
      webrtc::EncodedImageBuffer::Create(p->bytes.data() + f.off, f.len));
  img.SetRtpTimestamp(f.ts_ms * 90);
  img.SetFrameType(f.key ? webrtc::VideoFrameType::kVideoFrameKey
                         : webrtc::VideoFrameType::kVideoFrameDelta);
  img._encodedWidth = (uint32_t)p->width;
  img._encodedHeight = (uint32_t)p->height;
  p->dec->Decode(img, /*render_time_ms=*/f.ts_ms);
}
}  // namespace
#endif

extern "C" int veil_media_vnote_player_frame_at(VeilVnotePlayer* p, int ms,
                                                uint8_t* dst, int dst_cap,
                                                int* out_w, int* out_h) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!p) return 0;
  if (ms < 0) ms = 0;
  if (!p->frames.empty() && p->dec) {
    std::lock_guard<std::mutex> lk(p->mu);
    // Rewind: restart from the nearest keyframe at/before [ms]. (The VP8
    // reference chain resets at a keyframe, so decoding forward from there
    // reproduces the exact frame.)
    if ((int64_t)ms < p->last_ts) {
      size_t k = 0;
      for (size_t i = 0; i < p->frames.size(); i++) {
        if (p->frames[i].ts_ms > (uint32_t)ms) break;
        if (p->frames[i].key) k = i;
      }
      p->next_idx = k;
      p->last_ts = -1;
    }
    while (p->next_idx < p->frames.size() &&
           p->frames[p->next_idx].ts_ms <= (uint32_t)ms) {
      const auto& f = p->frames[p->next_idx];
      vnote_decode_one(p, f);
      p->last_ts = f.ts_ms;
      p->next_idx++;
    }
    // Nothing decoded yet (ms before the first frame) — prime with frame 0 so
    // the bubble shows the opening frame immediately.
    if (p->last_ts < 0 && !p->frames.empty()) {
      vnote_decode_one(p, p->frames[0]);
      p->last_ts = p->frames[0].ts_ms;
      p->next_idx = 1;
    }
  }
  return p->sink.get_frame(dst, dst_cap, out_w, out_h);
#else
  (void)p; (void)ms; (void)dst; (void)dst_cap; (void)out_w; (void)out_h;
  return 0;
#endif
}

extern "C" void veil_media_vnote_player_destroy(VeilVnotePlayer* p) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!p) return;
  if (p->dec) p->dec->Release();
  delete p;
#else
  (void)p;
#endif
}

void veil_media_vnote_recorder_destroy(VeilVnoteRecorder* rec) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!rec) return;
  {
    std::lock_guard<std::mutex> lk(rec->video_mu);
    rec->encoding = false;
  }
#if defined(VEIL_VNOTE_HAVE_NATIVE_CAMERA)
  if (rec->camera) {
    rec->camera->Stop();
    rec->camera.reset();
  }
#endif
  if (rec->mic_recording && rec->adm && rec->adm->Recording()) {
    rec->adm->StopRecording();
  }
  if (rec->adm) rec->adm->Terminate();
  {
    std::lock_guard<std::mutex> lk(rec->video_mu);
    if (rec->enc_ready && rec->enc) rec->enc->Release();
    rec->enc.reset();
  }
  delete rec;
#else
  (void)rec;
#endif
}

}  // extern "C"
