/* SPDX-License-Identifier: MIT
 *
 * veil_audio_record.cc — implementation of the standalone voice recorder.
 *
 * Pipeline: platform ADM (mic) -> custom AudioTransport (CaptureSink) -> Opus
 * encoder -> RAM byte stream. Reuses the exact ADM factories + bundled Opus the
 * call engine uses (veil_media_engine.cc), but with no Call/AudioState/RTP.
 *
 * VOICE_OPUS container (self-describing, decoded by the playback brick):
 *   offset 0 : "VOP1" magic (4 bytes)
 *   offset 4 : u8  version = 1
 *   offset 5 : u8  channels
 *   offset 6 : u32 LE sample_rate
 *   offset 10: u32 LE duration_ms
 *   offset 14: u32 LE packet_count
 *   offset 18: packet_count x [ u16 LE len ][ len Opus bytes ]
 * Raw Opus packets are NOT a standard container, but this stays in-app: playback
 * decodes with the same bundled Opus, so no Ogg/WebM muxer (and no reliance on
 * AVFoundation, which cannot decode Opus at all) is needed.
 */

#include "veil_audio_record.h"
#include "veil_diag_log.h"

#include <atomic>
#include <cstring>
#include <mutex>
#include <optional>
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
#include "rtc_base/buffer.h"

#if defined(__APPLE__)
#include "veil_avf_adm.h"
#elif defined(__ANDROID__)
#include "veil_aaudio_adm.h"
#else
#include "api/audio/create_audio_device_module.h"
#endif

namespace {

constexpr int kSampleRate = 48000;
// Opus's SDP format is ALWAYS declared 48000/2 (an RTP convention — the "2" is
// not the encode channel count); passing 1 makes the builtin factory reject the
// config and Create() returns null. So we request (48000, 2) exactly like the
// call engine, then read the encoder's ACTUAL NumChannels()/SampleRateHz() and
// build frames to match.
constexpr int kOpusSdpChannels = 2;
constexpr int kOpusPayloadType = 111;
// Bound RAM: a voice message is short. 6 min @ ~24 kbps Opus is ~1 MB.
constexpr int kMaxDurationMs = 6 * 60 * 1000;
constexpr size_t kMaxWaveformPeaks = 64 * 1024;  // ~10 min of 10 ms peaks

void rlog(const char* fmt, ...) {
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

// Custom AudioTransport that receives captured PCM and Opus-encodes it. The ADM
// calls RecordedDataIsAvailable on the audio thread; playout methods are
// never driven (this recorder has no playout) but must exist (pure virtual).
class CaptureSink : public webrtc::AudioTransport {
 public:
  explicit CaptureSink(std::unique_ptr<webrtc::AudioEncoder> enc)
      : encoder_(std::move(enc)),
        enc_rate_(encoder_->SampleRateHz()),
        enc_channels_((int)encoder_->NumChannels()),
        frame_mono_(enc_rate_ / 100),                       // 10 ms mono
        frame_samples_(frame_mono_ * enc_channels_) {}      // 10 ms interleaved

  int32_t RecordedDataIsAvailable(const void* audioSamples, size_t nSamples,
                                  size_t nBytesPerSample, size_t nChannels,
                                  uint32_t samplesPerSec, uint32_t /*delayMS*/,
                                  int32_t /*clockDrift*/, uint32_t /*micLevel*/,
                                  bool /*keyPressed*/,
                                  uint32_t& newMicLevel) override {
    newMicLevel = 0;
    if (audioSamples == nullptr || nBytesPerSample != sizeof(int16_t)) {
      return 0;
    }
    const int16_t* in = static_cast<const int16_t*>(audioSamples);
    std::lock_guard<std::mutex> lk(mu_);
    if (finished_ || total_samples_ >= (int64_t)enc_rate_ * kMaxDurationMs / 1000) {
      return 0;
    }
    // Downmix the captured audio to MONO (the ADM delivers 48k mono, but stay
    // defensive if a platform hands interleaved stereo).
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
    // Smooth level for the UI meter (fast attack, slow release).
    float lv = level_.load(std::memory_order_relaxed);
    lv = peak > lv ? peak : lv * 0.85f + peak * 0.15f;
    level_.store(lv, std::memory_order_relaxed);

    // Emit as many whole 10 ms frames as we have buffered. The encoder wants
    // `frame_samples_` INTERLEAVED samples (mono replicated across the encoder's
    // channel count); duration/waveform track the mono sample count.
    (void)samplesPerSec;  // ADM contract fixes this at 48k.
    std::vector<int16_t> frame(frame_samples_);
    while ((int)pending_.size() >= frame_mono_) {
      float fpeak = 0.f;
      for (int i = 0; i < frame_mono_; i++) {
        int16_t s = pending_[i];
        float a = std::abs((int)s) / 32768.f;
        if (a > fpeak) fpeak = a;
        for (int c = 0; c < enc_channels_; c++) frame[i * enc_channels_ + c] = s;
      }
      if (peaks_.size() < kMaxWaveformPeaks) peaks_.push_back(fpeak);

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

  // Unused playout side — supply safe zeros (pure virtual in AudioTransport).
  int32_t NeedMorePlayData(size_t nSamples, size_t nBytesPerSample,
                           size_t nChannels, uint32_t /*samplesPerSec*/,
                           void* audioSamples, size_t& nSamplesOut,
                           int64_t* elapsed_time_ms,
                           int64_t* ntp_time_ms) override {
    if (audioSamples) std::memset(audioSamples, 0, nSamples * nBytesPerSample * nChannels);
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
      std::memset(audio_data, 0, number_of_frames * number_of_channels * sizeof(int16_t));
    }
    if (elapsed_time_ms) *elapsed_time_ms = -1;
    if (ntp_time_ms) *ntp_time_ms = -1;
  }

  float level() const { return level_.load(std::memory_order_relaxed); }
  int elapsed_ms() {
    std::lock_guard<std::mutex> lk(mu_);
    return (int)(total_samples_ * 1000 / enc_rate_);
  }

  // Finalize under the lock: build the VOICE_OPUS byte stream + waveform. After
  // this the sink accepts no more audio.
  void finish(std::vector<uint8_t>* out, int* duration_ms,
              std::vector<uint8_t>* waveform, int bars) {
    std::lock_guard<std::mutex> lk(mu_);
    finished_ = true;
    const int dur = (int)(total_samples_ * 1000 / enc_rate_);
    if (duration_ms) *duration_ms = dur;

    out->clear();
    if (packet_count_ > 0) {
      const char magic[4] = {'V', 'O', 'P', '1'};
      out->insert(out->end(), magic, magic + 4);
      out->push_back(1);                       // version
      out->push_back((uint8_t)enc_channels_);  // decode channel count
      put_u32le(*out, (uint32_t)enc_rate_);
      put_u32le(*out, (uint32_t)dur);
      put_u32le(*out, (uint32_t)packet_count_);
      out->insert(out->end(), stream_.begin(), stream_.end());
    }
    if (waveform && bars > 0) {
      downsample_peaks(waveform, bars);
    }
  }

 private:
  // Peak-of-window downsample + peak-normalize to 0..255 (mirrors the Dart
  // downsampleWaveform, so live and stored waveforms read identically).
  void downsample_peaks(std::vector<uint8_t>* out, int bars) {
    out->assign(bars, 0);
    if (peaks_.empty()) return;
    const int n = (int)peaks_.size();
    float gpeak = 0.f;
    std::vector<float> tmp(bars, 0.f);
    for (int i = 0; i < bars; i++) {
      int lo = (int)((int64_t)i * n / bars);
      int hi = (int)((int64_t)(i + 1) * n / bars);
      if (hi <= lo) hi = lo + 1;
      float m = 0.f;
      for (int j = lo; j < hi && j < n; j++)
        if (peaks_[j] > m) m = peaks_[j];
      tmp[i] = m;
      if (m > gpeak) gpeak = m;
    }
    for (int i = 0; i < bars; i++) {
      float v = gpeak > 0 ? tmp[i] / gpeak : 0.f;
      int q = (int)(v * 255.f + 0.5f);
      (*out)[i] = (uint8_t)(q < 0 ? 0 : (q > 255 ? 255 : q));
    }
  }

  std::unique_ptr<webrtc::AudioEncoder> encoder_;
  const int enc_rate_;
  const int enc_channels_;
  const int frame_mono_;      // 10 ms of mono samples
  const int frame_samples_;   // 10 ms interleaved (frame_mono_ * enc_channels_)
  std::mutex mu_;
  std::vector<int16_t> pending_;   // MONO sub-frame remainder awaiting a full 10 ms
  std::vector<uint8_t> stream_;    // [u16 len][opus] packets (no header yet)
  std::vector<float> peaks_;       // one peak per 10 ms frame, for the waveform
  std::atomic<float> level_{0.f};
  int64_t total_samples_ = 0;
  int64_t rtp_ts_ = 0;
  uint32_t packet_count_ = 0;
  bool finished_ = false;
};

}  // namespace
#endif  // VEIL_MEDIA_HAVE_WEBRTC

struct VeilAudioRecorder {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  webrtc::Environment env;
  webrtc::scoped_refptr<webrtc::AudioDeviceModule> adm;
  std::unique_ptr<CaptureSink> sink;
  bool recording = false;
  explicit VeilAudioRecorder(webrtc::Environment e) : env(std::move(e)) {}
#endif
};

extern "C" {

VeilAudioRecorder* veil_media_recorder_create(void) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  webrtc::Environment env = webrtc::CreateEnvironment();
  auto rec = new VeilAudioRecorder(env);
#if defined(__APPLE__)
  rec->adm = veil_media::CreateVeilAvfAdm(rec->env);
#elif defined(__ANDROID__)
  rec->adm = veil_media::CreateVeilAAudioAdm(rec->env);
#else
  rec->adm = webrtc::CreateAudioDeviceModule(
      rec->env, webrtc::AudioDeviceModule::kPlatformDefaultAudio);
#endif
  if (!rec->adm) {
    rlog("recorder: no ADM");
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
    rlog("recorder: no Opus encoder");
    delete rec;
    return nullptr;
  }
  rec->sink = std::make_unique<CaptureSink>(std::move(enc));
  return rec;
#else
  return nullptr;
#endif
}

int veil_media_recorder_start(VeilAudioRecorder* rec) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!rec || !rec->adm || !rec->sink) return VEIL_REC_ERR_ARG;
  if (rec->recording) return VEIL_REC_OK;
  bool rec_avail = false;
  rec->adm->RecordingIsAvailable(&rec_avail);
  if (!rec_avail) {
    rlog("recorder: recording unavailable (permission?)");
    return VEIL_REC_ERR_DEVICE;
  }
  rec->adm->RegisterAudioCallback(rec->sink.get());
  if (rec->adm->InitRecording() != 0) {
    rlog("recorder: InitRecording failed");
    return VEIL_REC_ERR_DEVICE;
  }
  if (rec->adm->StartRecording() != 0) {
    rlog("recorder: StartRecording failed");
    return VEIL_REC_ERR_DEVICE;
  }
  rec->recording = true;
  return VEIL_REC_OK;
#else
  (void)rec;
  return VEIL_REC_ERR;
#endif
}

float veil_media_recorder_level(VeilAudioRecorder* rec) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return (rec && rec->sink) ? rec->sink->level() : 0.f;
#else
  (void)rec;
  return 0.f;
#endif
}

int veil_media_recorder_elapsed_ms(VeilAudioRecorder* rec) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return (rec && rec->sink) ? rec->sink->elapsed_ms() : 0;
#else
  (void)rec;
  return 0;
#endif
}

int veil_media_recorder_stop(VeilAudioRecorder* rec, uint8_t** out_bytes,
                             size_t* out_len, int* out_duration_ms,
                             uint8_t* waveform_out, int waveform_bars) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!rec || !rec->sink) return VEIL_REC_ERR_ARG;
  if (out_bytes) *out_bytes = nullptr;
  if (out_len) *out_len = 0;
  if (rec->recording && rec->adm) {
    if (rec->adm->Recording()) rec->adm->StopRecording();
    rec->recording = false;
  }
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> wf;
  int dur = 0;
  rec->sink->finish(&bytes, &dur, waveform_out ? &wf : nullptr, waveform_bars);
  if (out_duration_ms) *out_duration_ms = dur;
  if (waveform_out && waveform_bars > 0) {
    for (int i = 0; i < waveform_bars; i++)
      waveform_out[i] = i < (int)wf.size() ? wf[i] : 0;
  }
  if (!bytes.empty() && out_bytes && out_len) {
    uint8_t* buf = (uint8_t*)malloc(bytes.size());
    if (!buf) return VEIL_REC_ERR;
    std::memcpy(buf, bytes.data(), bytes.size());
    *out_bytes = buf;
    *out_len = bytes.size();
  }
  return VEIL_REC_OK;
#else
  (void)rec; (void)out_bytes; (void)out_len; (void)out_duration_ms;
  (void)waveform_out; (void)waveform_bars;
  return VEIL_REC_ERR;
#endif
}

void veil_media_recorder_free_bytes(uint8_t* bytes) {
  if (bytes) free(bytes);
}

void veil_media_recorder_destroy(VeilAudioRecorder* rec) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!rec) return;
  if (rec->recording && rec->adm && rec->adm->Recording()) {
    rec->adm->StopRecording();
  }
  if (rec->adm) rec->adm->Terminate();
  delete rec;
#else
  (void)rec;
#endif
}

}  // extern "C"
