/* SPDX-License-Identifier: MIT
 *
 * veil_audio_play.cc — VOICE_OPUS playback via the platform ADM speaker.
 *
 * On create: parse the VOICE_OPUS container, decode every Opus packet to mono
 * int16 PCM held in RAM. On start: build the platform ADM, register a custom
 * AudioTransport whose NeedMorePlayData copies from the PCM buffer (mono ->
 * playout channels, at the current speed), and StartPlayout. Position + state
 * are atomic for UI polling.
 */

#include "veil_audio_play.h"
#include "veil_diag_log.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <vector>

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
#include <cstdarg>

#include "api/audio/audio_device.h"
#include "api/audio/audio_device_defines.h"
#include "api/audio_codecs/audio_decoder.h"
#include "api/audio_codecs/audio_decoder_factory.h"
#include "api/audio_codecs/audio_format.h"
#include "api/audio_codecs/builtin_audio_decoder_factory.h"
#include "api/environment/environment.h"
#include "api/environment/environment_factory.h"
#include "api/scoped_refptr.h"

#if defined(__APPLE__)
#include "veil_avf_adm.h"
#elif defined(__ANDROID__)
#include "veil_aaudio_adm.h"
#else
#include "api/audio/create_audio_device_module.h"
#endif

namespace {

constexpr int kSampleRate = 48000;
constexpr int kOpusSdpChannels = 2;  // SDP convention (see recorder)

void plog(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  veil_media::diag::vlog(fmt, ap);
  va_end(ap);
}

uint32_t rd_u32le(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

// Decode the whole VOICE_OPUS stream to mono int16 PCM. Returns false on a bad
// container. `out_rate` receives the stream's sample rate.
bool decode_voice_opus(const uint8_t* data, size_t len,
                       const webrtc::Environment& env,
                       std::vector<int16_t>* pcm, int* out_rate) {
  if (data == nullptr || len < 18) return false;
  if (!(data[0] == 'V' && data[1] == 'O' && data[2] == 'P' && data[3] == '1')) {
    return false;
  }
  const int rate = (int)rd_u32le(data + 6);
  if (rate <= 0) return false;
  *out_rate = rate;
  const uint32_t packet_count = rd_u32le(data + 14);

  auto factory = webrtc::CreateBuiltinAudioDecoderFactory();
  auto dec = factory->Create(
      env, webrtc::SdpAudioFormat("opus", kSampleRate, kOpusSdpChannels));
  if (!dec) {
    plog("player: no Opus decoder");
    return false;
  }
  const int dec_ch = (int)dec->Channels() <= 0 ? 1 : (int)dec->Channels();
  // Opus max frame is 120 ms; scratch for the widest packet at this rate/chan.
  const size_t max_frame = (size_t)(rate / 1000) * 120 * dec_ch;
  std::vector<int16_t> scratch(max_frame);

  size_t off = 18;
  for (uint32_t i = 0; i < packet_count; i++) {
    if (off + 2 > len) break;
    const uint16_t plen = (uint16_t)data[off] | ((uint16_t)data[off + 1] << 8);
    off += 2;
    if (off + plen > len) break;
    webrtc::AudioDecoder::SpeechType st;
    const int n = dec->Decode(data + off, plen, rate,
                              scratch.size() * sizeof(int16_t),
                              scratch.data(), &st);
    off += plen;
    if (n <= 0) continue;
    const int frames = n / dec_ch;
    for (int f = 0; f < frames; f++) {
      int32_t acc = 0;
      for (int c = 0; c < dec_ch; c++) acc += scratch[f * dec_ch + c];
      pcm->push_back((int16_t)(acc / dec_ch));
    }
  }
  return true;
}

// Feeds decoded PCM to the ADM speaker at the current speed.
class PlaybackSink : public webrtc::AudioTransport {
 public:
  PlaybackSink(std::vector<int16_t> pcm, int rate)
      : pcm_(std::move(pcm)), rate_(rate) {}

  int32_t RecordedDataIsAvailable(const void*, size_t, size_t, size_t, uint32_t,
                                  uint32_t, int32_t, uint32_t, bool,
                                  uint32_t& newMicLevel) override {
    newMicLevel = 0;
    return 0;  // playback-only; no capture
  }

  int32_t NeedMorePlayData(size_t nSamples, size_t nBytesPerSample,
                           size_t nChannels, uint32_t /*samplesPerSec*/,
                           void* audioSamples, size_t& nSamplesOut,
                           int64_t* elapsed_time_ms,
                           int64_t* ntp_time_ms) override {
    nSamplesOut = nSamples;
    if (elapsed_time_ms) *elapsed_time_ms = -1;
    if (ntp_time_ms) *ntp_time_ms = -1;
    if (audioSamples == nullptr) return 0;
    int16_t* out = static_cast<int16_t*>(audioSamples);
    const size_t ch = nChannels == 0 ? 1 : nChannels;
    (void)nBytesPerSample;

    std::lock_guard<std::mutex> lk(mu_);
    const float speed = speed_.load(std::memory_order_relaxed);
    const bool paused = paused_.load(std::memory_order_relaxed);
    const size_t total = pcm_.size();
    for (size_t i = 0; i < nSamples; i++) {
      int16_t s = 0;
      if (!paused && cursor_ < total) {
        s = pcm_[cursor_];
        // Advance the source cursor by `speed` frames per output frame (naive
        // time-compression). Accumulate the fraction so 1.5x is exact over time.
        frac_ += speed;
        const size_t step = (size_t)frac_;
        frac_ -= (float)step;
        cursor_ += step;
      }
      for (size_t c = 0; c < ch; c++) out[i * ch + c] = s;
    }
    if (cursor_ >= total) finished_.store(true, std::memory_order_relaxed);
    pos_frames_.store(cursor_ < total ? cursor_ : total,
                      std::memory_order_relaxed);
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

  int duration_ms() const {
    return rate_ > 0 ? (int)((int64_t)pcm_.size() * 1000 / rate_) : 0;
  }
  int position_ms() const {
    return rate_ > 0
               ? (int)((int64_t)pos_frames_.load(std::memory_order_relaxed) *
                       1000 / rate_)
               : 0;
  }
  bool finished() const { return finished_.load(std::memory_order_relaxed); }
  bool paused() const { return paused_.load(std::memory_order_relaxed); }
  void set_paused(bool p) { paused_.store(p, std::memory_order_relaxed); }
  void set_speed(float s) {
    if (s < 0.5f) s = 0.5f;
    if (s > 3.0f) s = 3.0f;
    speed_.store(s, std::memory_order_relaxed);
  }
  void seek_ms(int ms) {
    std::lock_guard<std::mutex> lk(mu_);
    if (ms < 0) ms = 0;
    size_t frame = (size_t)((int64_t)ms * rate_ / 1000);
    if (frame > pcm_.size()) frame = pcm_.size();
    cursor_ = frame;
    frac_ = 0;
    finished_.store(frame >= pcm_.size(), std::memory_order_relaxed);
    pos_frames_.store(cursor_, std::memory_order_relaxed);
  }

 private:
  std::mutex mu_;
  std::vector<int16_t> pcm_;  // mono
  const int rate_;
  size_t cursor_ = 0;   // source frame index
  float frac_ = 0;      // fractional-step accumulator for non-integer speeds
  std::atomic<float> speed_{1.0f};
  std::atomic<bool> paused_{false};
  std::atomic<bool> finished_{false};
  std::atomic<size_t> pos_frames_{0};
};

}  // namespace
#endif  // VEIL_MEDIA_HAVE_WEBRTC

struct VeilAudioPlayer {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  webrtc::Environment env;
  webrtc::scoped_refptr<webrtc::AudioDeviceModule> adm;
  std::unique_ptr<PlaybackSink> sink;
  bool playing = false;
  explicit VeilAudioPlayer(webrtc::Environment e) : env(std::move(e)) {}
#endif
};

extern "C" {

VeilAudioPlayer* veil_media_player_create(const uint8_t* voice_opus,
                                          size_t len) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  webrtc::Environment env = webrtc::CreateEnvironment();
  std::vector<int16_t> pcm;
  int rate = kSampleRate;
  if (!decode_voice_opus(voice_opus, len, env, &pcm, &rate) || pcm.empty()) {
    plog("player: decode failed / empty");
    return nullptr;
  }
  auto p = new VeilAudioPlayer(env);
#if defined(__APPLE__)
  p->adm = veil_media::CreateVeilAvfAdm(p->env);
#elif defined(__ANDROID__)
  p->adm = veil_media::CreateVeilAAudioAdm(p->env);
#else
  p->adm = webrtc::CreateAudioDeviceModule(
      p->env, webrtc::AudioDeviceModule::kPlatformDefaultAudio);
#endif
  if (!p->adm) {
    delete p;
    return nullptr;
  }
  p->adm->Init();
  p->sink = std::make_unique<PlaybackSink>(std::move(pcm), rate);
  return p;
#else
  (void)voice_opus;
  (void)len;
  return nullptr;
#endif
}

int veil_media_player_start(VeilAudioPlayer* p) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!p || !p->adm || !p->sink) return VEIL_PLAY_ERR_ARG;
  if (p->playing) return VEIL_PLAY_OK;
  p->adm->RegisterAudioCallback(p->sink.get());
  if (p->adm->InitPlayout() != 0) return VEIL_PLAY_ERR;
  if (p->adm->StartPlayout() != 0) return VEIL_PLAY_ERR;
  p->sink->set_paused(false);
  p->playing = true;
  return VEIL_PLAY_OK;
#else
  (void)p;
  return VEIL_PLAY_ERR;
#endif
}

int veil_media_player_pause(VeilAudioPlayer* p) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!p || !p->sink) return VEIL_PLAY_ERR_ARG;
  p->sink->set_paused(true);
  return VEIL_PLAY_OK;
#else
  (void)p;
  return VEIL_PLAY_ERR;
#endif
}

int veil_media_player_resume(VeilAudioPlayer* p) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!p || !p->sink) return VEIL_PLAY_ERR_ARG;
  p->sink->set_paused(false);
  return VEIL_PLAY_OK;
#else
  (void)p;
  return VEIL_PLAY_ERR;
#endif
}

int veil_media_player_seek(VeilAudioPlayer* p, int ms) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!p || !p->sink) return VEIL_PLAY_ERR_ARG;
  p->sink->seek_ms(ms);
  return VEIL_PLAY_OK;
#else
  (void)p;
  (void)ms;
  return VEIL_PLAY_ERR;
#endif
}

int veil_media_player_set_speed(VeilAudioPlayer* p, float speed) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!p || !p->sink) return VEIL_PLAY_ERR_ARG;
  p->sink->set_speed(speed);
  return VEIL_PLAY_OK;
#else
  (void)p;
  (void)speed;
  return VEIL_PLAY_ERR;
#endif
}

int veil_media_player_position_ms(VeilAudioPlayer* p) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return (p && p->sink) ? p->sink->position_ms() : 0;
#else
  (void)p;
  return 0;
#endif
}

int veil_media_player_duration_ms(VeilAudioPlayer* p) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return (p && p->sink) ? p->sink->duration_ms() : 0;
#else
  (void)p;
  return 0;
#endif
}

int veil_media_player_is_playing(VeilAudioPlayer* p) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!p || !p->sink || !p->playing) return 0;
  return (!p->sink->paused() && !p->sink->finished()) ? 1 : 0;
#else
  (void)p;
  return 0;
#endif
}

int veil_media_decode_pcm16k(const uint8_t* voice_opus, size_t len,
                             float** out_pcm, int* out_samples) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (out_pcm) *out_pcm = nullptr;
  if (out_samples) *out_samples = 0;
  webrtc::Environment env = webrtc::CreateEnvironment();
  std::vector<int16_t> pcm;  // mono @ the clip's rate (48k)
  int rate = kSampleRate;
  if (!decode_voice_opus(voice_opus, len, env, &pcm, &rate) || pcm.empty()) {
    return VEIL_PLAY_ERR;
  }
  // Downsample to 16 kHz mono float32 by averaging each rate/16000 group
  // (48k -> /3). Averaging is a cheap anti-alias; whisper is robust.
  const int decim = rate / 16000;
  const int step = decim < 1 ? 1 : decim;
  const int out_n = (int)(pcm.size() / step);
  if (out_n <= 0) return VEIL_PLAY_ERR;
  float* buf = (float*)malloc((size_t)out_n * sizeof(float));
  if (!buf) return VEIL_PLAY_ERR;
  for (int i = 0; i < out_n; i++) {
    int32_t acc = 0;
    for (int j = 0; j < step; j++) acc += pcm[(size_t)i * step + j];
    buf[i] = (float)(acc / step) / 32768.f;
  }
  if (out_pcm) *out_pcm = buf; else free(buf);
  if (out_samples) *out_samples = out_n;
  return VEIL_PLAY_OK;
#else
  (void)voice_opus; (void)len; (void)out_pcm; (void)out_samples;
  return VEIL_PLAY_ERR;
#endif
}

void veil_media_free_pcm(float* pcm) {
  if (pcm) free(pcm);
}

int veil_media_decode_wav(const uint8_t* voice_opus, size_t len,
                          uint8_t** out_wav, size_t* out_len) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (out_wav) *out_wav = nullptr;
  if (out_len) *out_len = 0;
  if (!out_wav || !out_len) return VEIL_PLAY_ERR_ARG;
  webrtc::Environment env = webrtc::CreateEnvironment();
  std::vector<int16_t> pcm;  // mono @ the clip's rate
  int rate = kSampleRate;
  if (!decode_voice_opus(voice_opus, len, env, &pcm, &rate) || pcm.empty()) {
    plog("player: wav decode failed / empty");
    return VEIL_PLAY_ERR;
  }
  const size_t data_len = pcm.size() * sizeof(int16_t);
  const size_t total = 44 + data_len;
  uint8_t* buf = (uint8_t*)malloc(total);
  if (!buf) return VEIL_PLAY_ERR;
  const auto wr_u32 = [](uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
  };
  const auto wr_u16 = [](uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
  };
  std::memcpy(buf, "RIFF", 4);
  wr_u32(buf + 4, (uint32_t)(36 + data_len));
  std::memcpy(buf + 8, "WAVE", 4);
  std::memcpy(buf + 12, "fmt ", 4);
  wr_u32(buf + 16, 16);                   // fmt chunk size
  wr_u16(buf + 20, 1);                    // PCM
  wr_u16(buf + 22, 1);                    // mono
  wr_u32(buf + 24, (uint32_t)rate);
  wr_u32(buf + 28, (uint32_t)rate * 2u);  // byte rate (rate * ch * 16/8)
  wr_u16(buf + 32, 2);                    // block align
  wr_u16(buf + 34, 16);                   // bits per sample
  std::memcpy(buf + 36, "data", 4);
  wr_u32(buf + 40, (uint32_t)data_len);
  std::memcpy(buf + 44, pcm.data(), data_len);
  *out_wav = buf;
  *out_len = total;
  return VEIL_PLAY_OK;
#else
  (void)voice_opus; (void)len; (void)out_wav; (void)out_len;
  return VEIL_PLAY_ERR;
#endif
}

void veil_media_free_wav(uint8_t* wav) {
  if (wav) free(wav);
}

void veil_media_player_destroy(VeilAudioPlayer* p) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!p) return;
  if (p->playing && p->adm) {
    if (p->adm->Playing()) p->adm->StopPlayout();
  }
  if (p->adm) p->adm->Terminate();
  delete p;
#else
  (void)p;
#endif
}

}  // extern "C"
