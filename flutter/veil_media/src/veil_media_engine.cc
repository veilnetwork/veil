/* SPDX-License-Identifier: MIT
 *
 * veil_media_engine.cc — implements the veil_media_engine_* control ABI
 * (veil_media_engine.h) on top of webrtc::Call + AudioState + the
 * VeilTransportShim. Built from source, codec-stripped (Opus only).
 *
 * Guarded by VEIL_MEDIA_HAVE_WEBRTC so the ABI + shim compile/link before the
 * trimmed WebRTC is vendored per platform. Construction runs on the FFI caller
 * thread; for the device test it should move onto the Call worker queue (see
 * THREADING notes) — release builds compile out the thread DCHECKs, so a first
 * single-control-thread run is workable.
 */

#include "veil_media_engine.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
#include "api/audio/audio_device.h"
#include "api/audio/builtin_audio_processing_builder.h"
#include "api/audio/create_audio_device_module.h"
#include "api/audio_codecs/audio_format.h"
#include "api/audio_codecs/builtin_audio_decoder_factory.h"
#include "api/audio_codecs/builtin_audio_encoder_factory.h"
#include "api/environment/environment.h"
#include "api/environment/environment_factory.h"
#include "api/media_types.h"
#include "api/rtp_header_extension_id.h"
#include "api/rtp_headers.h"
#include "api/rtp_parameters.h"
#include "api/scoped_refptr.h"
#include "api/task_queue/task_queue_base.h"
#include "api/task_queue/task_queue_factory.h"
#include "api/units/time_delta.h"
#include "rtc_base/event.h"
#include "call/audio_receive_stream.h"
#include "call/audio_send_stream.h"
#include "call/audio_state.h"
#include "call/call.h"
#include "call/call_config.h"
#include "modules/audio_mixer/audio_mixer_impl.h"
// --- Video (Phase 4): VP8 send/recv over the same veil channel ---
#include "call/video_send_stream.h"
#include "call/video_receive_stream.h"
#include "video/config/video_encoder_config.h"
// Header-only template factories (VP8 only): CreateBuiltin*Video*Factory live in
// separate GN targets that `ninja webrtc` does NOT pull into libwebrtc.a, so
// calling them crashes (undefined -> null under -undefined dynamic_lookup). The
// templates instantiate in this TU and reference the VP8 impls that ARE in
// libwebrtc.a.
#include "api/video_codecs/video_encoder_factory_template.h"
#include "api/video_codecs/video_encoder_factory_template_libvpx_vp8_adapter.h"
#include "api/video_codecs/video_decoder_factory_template.h"
#include "api/video_codecs/video_decoder_factory_template_libvpx_vp8_adapter.h"
#include "api/video/builtin_video_bitrate_allocator_factory.h"
#include "api/video_codecs/sdp_video_format.h"
#include "api/video/video_codec_type.h"
#include "api/video/video_frame.h"
#include "api/video/i420_buffer.h"
#include "api/video/video_rotation.h"
#include "api/video/video_source_interface.h"
#include "api/video/video_sink_interface.h"
#include "api/video/video_broadcaster.h"
#include "third_party/libyuv/include/libyuv/convert_argb.h"  // I420ToABGR
#include "rtc_base/time_utils.h"  // webrtc::TimeMicros

#if defined(__APPLE__)
#include "veil_avf_adm.h"
#elif defined(__ANDROID__)
#include "veil_aaudio_adm.h"
#endif
#include "veil_camera.h"
#include "veil_transport_shim.h"
#endif

namespace {

const char* kVersion = "veil_media 0.0.1 (phase3)";
constexpr int kOpusPayloadType = 111;  // SDP convention (Opus, 48k, stereo)

// Diagnostic log to a file (a GUI app's stderr is not captured by the unified
// log). Best-effort; append.
void vlog(const char* fmt, ...) {
  FILE* f = fopen("/tmp/veil_media_diag.log", "a");
  if (!f) return;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(f, fmt, ap);
  va_end(ap);
  fputc('\n', f);
  fclose(f);
}

char* dup_cstr(const std::string& s) {
  char* out = static_cast<char*>(std::malloc(s.size() + 1));
  if (out) std::memcpy(out, s.c_str(), s.size() + 1);
  return out;
}

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
// Run `f` synchronously on `tq` and block until it finishes. webrtc::Call and
// its streams must be created/destroyed on the worker task queue (they call
// TaskQueueBase::Current(), which is null on the FFI caller thread → crash).
template <typename F>
void run_on(webrtc::TaskQueueBase* tq, F f) {
  if (tq == nullptr || tq->IsCurrent()) {
    f();
    return;
  }
  webrtc::Event done;
  tq->PostTask([&f, &done]() mutable {
    f();
    done.Set();
  });
  done.Wait(webrtc::TimeDelta::Seconds(10));
}

// SSRC from the first 4 bytes of a node id (never 0 — 0 is an invalid SSRC).
uint32_t ssrc_of(const uint8_t id[32]) {
  uint32_t s = (uint32_t(id[0]) << 24) | (uint32_t(id[1]) << 16) |
               (uint32_t(id[2]) << 8) | uint32_t(id[3]);
  return s == 0 ? 1u : s;
}

// Video SSRC — derived from the node id but distinct from the audio SSRC so the
// far side (and our shim) can demux audio vs video on the one datagram channel.
uint32_t video_ssrc_of(const uint8_t id[32]) {
  uint32_t s = ssrc_of(id) ^ 0x000000FFu ^ 0x56440000u;  // "VD" tag
  return s == 0 ? 2u : s;
}

// Sink for decoded remote video frames: converts each to RGBA and holds the
// latest so Dart can pull it at the display rate (a pull avoids the async
// callback's stale-buffer race). OnFrame runs on a webrtc decode thread.
class VeilVideoSink : public webrtc::VideoSinkInterface<webrtc::VideoFrame> {
 public:
  void OnFrame(const webrtc::VideoFrame& frame) override {
    auto buf = frame.video_frame_buffer()->ToI420();
    if (buf == nullptr) return;
    const int w = buf->width(), h = buf->height();
    if (w <= 0 || h <= 0) return;
    const size_t need = static_cast<size_t>(w) * h * 4;
    std::lock_guard<std::mutex> l(m_);
    if (rgba_.size() < need) rgba_.resize(need);
    // I420 -> tightly packed RGBA (libyuv "ABGR" word == R,G,B,A bytes in memory,
    // which is what a Flutter rgba8888 texture / decodeImageFromPixels expects).
    libyuv::I420ToABGR(buf->DataY(), buf->StrideY(), buf->DataU(),
                       buf->StrideU(), buf->DataV(), buf->StrideV(),
                       rgba_.data(), w * 4, w, h);
    w_ = w;
    h_ = h;
    ++seq_;
  }
  // Copy the latest frame into dst. Returns seq (>0) if copied, 0 if none yet,
  // -1 if dst_cap too small (out_w/out_h still set).
  int get_frame(uint8_t* dst, int dst_cap, int* out_w, int* out_h) {
    std::lock_guard<std::mutex> l(m_);
    if (seq_ == 0 || w_ <= 0) return 0;
    if (out_w) *out_w = w_;
    if (out_h) *out_h = h_;
    const size_t need = static_cast<size_t>(w_) * h_ * 4;
    if (dst == nullptr || dst_cap < 0 || static_cast<size_t>(dst_cap) < need)
      return -1;
    std::memcpy(dst, rgba_.data(), need);
    return static_cast<int>(seq_);
  }

 private:
  std::mutex m_;
  std::vector<uint8_t> rgba_;  // latest frame, RGBA (guarded by m_)
  int w_ = 0, h_ = 0;
  uint32_t seq_ = 0;
};

// Copy a (possibly strided) I420 frame into the broadcaster (encoder source).
void push_i420(webrtc::VideoBroadcaster* source, const uint8_t* y,
               const uint8_t* u, const uint8_t* v, int width, int height,
               int stride_y, int stride_u, int stride_v, int64_t ts_us) {
  if (source == nullptr || width <= 0 || height <= 0) return;
  auto buf = webrtc::I420Buffer::Create(width, height);
  const int cw = (width + 1) / 2, ch = (height + 1) / 2;
  for (int r = 0; r < height; ++r)
    std::memcpy(buf->MutableDataY() + r * buf->StrideY(), y + r * stride_y,
                width);
  for (int r = 0; r < ch; ++r)
    std::memcpy(buf->MutableDataU() + r * buf->StrideU(), u + r * stride_u, cw);
  for (int r = 0; r < ch; ++r)
    std::memcpy(buf->MutableDataV() + r * buf->StrideV(), v + r * stride_v, cw);
  webrtc::VideoFrame frame = webrtc::VideoFrame::Builder()
                                 .set_video_frame_buffer(buf)
                                 .set_timestamp_us(ts_us ? ts_us
                                                         : webrtc::TimeMicros())
                                 .set_rotation(webrtc::kVideoRotation_0)
                                 .build();
  source->OnFrame(frame);
}

// All webrtc state, constructed together in create() (Environment has no
// default ctor, so it can't be a bare member of the C-ABI handle).
struct WebrtcState {
  explicit WebrtcState(webrtc::Environment e) : env(std::move(e)) {}
  webrtc::Environment env;
  std::unique_ptr<webrtc::TaskQueueBase, webrtc::TaskQueueDeleter> worker_tq;
  std::unique_ptr<webrtc::TaskQueueBase, webrtc::TaskQueueDeleter> network_tq;
  webrtc::scoped_refptr<webrtc::AudioDeviceModule> adm;
  webrtc::scoped_refptr<webrtc::AudioProcessing> apm;
  webrtc::scoped_refptr<webrtc::AudioState> audio_state;
  std::unique_ptr<webrtc::Call> call;
  std::unique_ptr<veil_media::VeilTransportShim> shim;
  webrtc::AudioSendStream* send_stream = nullptr;             // owned by Call
  webrtc::AudioReceiveStreamInterface* recv_stream = nullptr;  // owned by Call
  // Video (Phase 4) — factories + source/sink outlive the streams.
  std::unique_ptr<webrtc::VideoEncoderFactory> video_encoder_factory;
  std::unique_ptr<webrtc::VideoDecoderFactory> video_decoder_factory;
  std::unique_ptr<webrtc::VideoBitrateAllocatorFactory> video_bitrate_alloc_factory;
  std::unique_ptr<webrtc::VideoBroadcaster> video_source;  // pushable
  std::unique_ptr<VeilVideoSink> video_sink;               // renderer
  webrtc::VideoSendStream* video_send_stream = nullptr;              // owned by Call
  webrtc::VideoReceiveStreamInterface* video_recv_stream = nullptr;  // owned by Call
  std::thread test_video_thread;         // synthetic source (VEIL_MEDIA_TEST_VIDEO)
  std::atomic<bool> test_video_run{false};
  std::unique_ptr<veil_media::CameraCapturer> camera;  // real capture source
};
#endif

}  // namespace

struct VeilMediaEngine {
  uint64_t veil_chan = 0;
  uint8_t local[32] = {0};
  uint8_t peer[32] = {0};
  std::atomic<bool> audio_running{false};
  bool mic_muted = false;
  bool speaker_muted = false;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  std::unique_ptr<WebrtcState> ws;
#endif
};

extern "C" {

VeilMediaEngine* veil_media_engine_create(uint64_t veil_chan,
                                          const uint8_t* local_id,
                                          const uint8_t* peer_id) {
  if (local_id == nullptr || peer_id == nullptr) return nullptr;
  auto engine = std::make_unique<VeilMediaEngine>();
  engine->veil_chan = veil_chan;
  std::memcpy(engine->local, local_id, 32);
  std::memcpy(engine->peer, peer_id, 32);

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  webrtc::Environment env = webrtc::CreateEnvironment();
  auto ws = std::make_unique<WebrtcState>(env);
  // THREADING: worker + network queues own the Call's threads. Post Call/stream
  // ops onto worker_tq for the device test; direct construction is fine to
  // compile and to run single-threaded in a release build (no DCHECKs).
  ws->worker_tq = ws->env.task_queue_factory().CreateTaskQueue(
      "veil-worker", webrtc::TaskQueueFactory::Priority::kNormal);
  ws->network_tq = ws->env.task_queue_factory().CreateTaskQueue(
      "veil-net", webrtc::TaskQueueFactory::Priority::kHigh);

  // AVAudioEngine-backed ADM: the platform HAL ADM (kPlatformDefaultAudio)
  // reports RecordingIsAvailable=0 and hangs InitRecording inside this dylib
  // embed, so no mic audio reaches the send stream. The custom ADM captures via
  // AVAudioEngine (clean TCC integration) and is the portable path.
#if defined(__APPLE__)
  ws->adm = veil_media::CreateVeilAvfAdm(ws->env);
#elif defined(__ANDROID__)
  ws->adm = veil_media::CreateVeilAAudioAdm(ws->env);
#else
  ws->adm = webrtc::CreateAudioDeviceModule(
      ws->env, webrtc::AudioDeviceModule::kPlatformDefaultAudio);
#endif
  if (ws->adm) {
    const int32_t init_rc = ws->adm->Init();
    bool rec_avail = false, play_avail = false;
    ws->adm->RecordingIsAvailable(&rec_avail);
    ws->adm->PlayoutIsAvailable(&play_avail);
    vlog("adm: Init=%d Initialized=%d recDevs=%d playDevs=%d recAvail=%d "
         "playAvail=%d",
         init_rc, ws->adm->Initialized(), (int)ws->adm->RecordingDevices(),
         (int)ws->adm->PlayoutDevices(), rec_avail, play_avail);
  }
  ws->apm = webrtc::BuiltinAudioProcessingBuilder().Build(ws->env);

  webrtc::AudioState::Config asc;
  asc.audio_mixer = webrtc::AudioMixerImpl::Create();
  asc.audio_processing = ws->apm;
  asc.audio_device_module = ws->adm;
  ws->audio_state = webrtc::AudioState::Create(asc);
  // Route the ADM's recorded audio into the AudioState's transport. In the
  // PeerConnection path WebRtcVoiceEngine does this; on the direct Call path we
  // must — without it the mic records but no audio reaches the send stream (only
  // RTCP flows).
  if (ws->adm && ws->audio_state) {
    ws->adm->RegisterAudioCallback(ws->audio_state->audio_transport());
  }

  webrtc::CallConfig call_cfg(ws->env, ws->worker_tq.get(),
                              ws->network_tq.get());
  call_cfg.audio_state = ws->audio_state;
  ws->call = webrtc::Call::Create(std::move(call_cfg));

  ws->shim = std::make_unique<veil_media::VeilTransportShim>(
      veil_chan, ws->call.get(), ws->network_tq.get());
  ws->shim->Start();

  ws->video_sink = std::make_unique<VeilVideoSink>();

  engine->ws = std::move(ws);
#endif
  return engine.release();
}

void veil_media_engine_destroy(VeilMediaEngine* engine) {
  if (engine == nullptr) return;
  veil_media_engine_stop_video(engine);
  veil_media_engine_stop_audio(engine);
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws) {
    if (engine->ws->shim) engine->ws->shim->Stop();
    engine->ws->call.reset();  // after streams (stop_audio) + shim->Stop()
    if (engine->ws->adm) engine->ws->adm->Terminate();
  }
#endif
  delete engine;
}

int veil_media_engine_start_audio(VeilMediaEngine* engine, int send, int recv) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  if (engine->audio_running.load()) return VEIL_MEDIA_OK;  // idempotent
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  WebrtcState* ws = engine->ws.get();
  const uint32_t local_ssrc = ssrc_of(engine->local);
  const uint32_t remote_ssrc = ssrc_of(engine->peer);

  // Streams must be created on the Call's worker queue.
  run_on(ws->worker_tq.get(), [&]() {
    // The Call's audio network state defaults to kNetworkDown, which makes the
    // send transport hold every RTP packet in the pacer (only RTCP leaks out on
    // its own path). Bring the audio channel up so mic audio actually flows.
    ws->call->SignalChannelNetworkState(webrtc::MediaType::AUDIO,
                                        webrtc::kNetworkUp);
    if (send && ws->send_stream == nullptr) {
      webrtc::AudioSendStream::Config sc(ws->shim.get());  // sets send_transport
      sc.rtp.ssrc = local_ssrc;
      // TWCC: the send-side bandwidth estimator needs this both ways.
      sc.rtp.extensions.emplace_back(
          webrtc::RtpExtension::kTransportSequenceNumberUri,
          webrtc::RtpHeaderExtensionId(1));
      sc.encoder_factory = webrtc::CreateBuiltinAudioEncoderFactory();
      sc.send_codec_spec = webrtc::AudioSendStream::Config::SendCodecSpec(
          kOpusPayloadType, webrtc::SdpAudioFormat("opus", 48000, 2));
      ws->send_stream = ws->call->CreateAudioSendStream(sc);
      if (ws->send_stream) ws->send_stream->Start();
    }
    if (recv && ws->recv_stream == nullptr) {
      webrtc::AudioReceiveStreamInterface::Config rc;
      rc.rtp.remote_ssrc = remote_ssrc;
      rc.rtp.local_ssrc = local_ssrc;
      rc.rtcp_send_transport = ws->shim.get();
      rc.decoder_factory = webrtc::CreateBuiltinAudioDecoderFactory();
      // SdpAudioFormat has no default ctor, so operator[] won't work — emplace.
      rc.decoder_map.emplace(kOpusPayloadType,
                             webrtc::SdpAudioFormat("opus", 48000, 2));
      ws->recv_stream = ws->call->CreateAudioReceiveStream(rc);
      if (ws->recv_stream) ws->recv_stream->Start();
    }
  });
  // webrtc::Call does NOT drive the AudioDeviceModule the way PeerConnection
  // does — start capture/playout explicitly, else the send stream has no audio
  // frames (only RTCP flows) and the recv stream is never played out. The
  // AVAudioEngine ADM's start is non-blocking + idempotent (all engine work is
  // serialized on its own GCD queue), so this is safe on the calling thread and
  // AudioState toggling it too on the worker queue just no-ops.
  if (ws->adm) {
    if (send) {
      ws->adm->InitRecording();
      ws->adm->StartRecording();
    }
    if (recv) {
      ws->adm->InitPlayout();
      ws->adm->StartPlayout();
    }
    vlog("adm start: recording=%d playing=%d", ws->adm->Recording(),
         ws->adm->Playing());
  }
  // A few seconds in, log the send stream's packet counters — the definitive
  // "is audio actually going out" check.
  if (ws->send_stream) {
    ws->worker_tq->PostDelayedTask(
        [ws]() {
          if (ws->send_stream) {
            const auto s = ws->send_stream->GetStats();
            vlog("sendstream @3s: packets_sent=%lld bytes=%lld",
                 (long long)s.packets_sent, (long long)s.payload_bytes_sent);
          }
        },
        webrtc::TimeDelta::Seconds(3));
  }
  engine->audio_running.store(true);
  return VEIL_MEDIA_OK;
#else
  (void)send;
  (void)recv;
  return VEIL_MEDIA_ERR_STATE;  // no WebRTC linked yet
#endif
}

int veil_media_engine_stop_audio(VeilMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  if (!engine->audio_running.exchange(false)) return VEIL_MEDIA_OK;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->call) {
    WebrtcState* ws = engine->ws.get();
    // Stop the ADM off the worker queue (see start_audio — StartRecording/
    // StopRecording can block CoreAudio and must not wedge the Call worker).
    if (ws->adm) {
      if (ws->adm->Recording()) ws->adm->StopRecording();
      if (ws->adm->Playing()) ws->adm->StopPlayout();
    }
    run_on(ws->worker_tq.get(), [&]() {
      if (ws->send_stream) {
        ws->send_stream->Stop();
        ws->call->DestroyAudioSendStream(ws->send_stream);
        ws->send_stream = nullptr;
      }
      if (ws->recv_stream) {
        ws->recv_stream->Stop();
        ws->call->DestroyAudioReceiveStream(ws->recv_stream);
        ws->recv_stream = nullptr;
      }
    });
  }
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_start_video(VeilMediaEngine* engine, int send, int recv) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  WebrtcState* ws = engine->ws.get();
  const uint32_t local_v = video_ssrc_of(engine->local);
  const uint32_t remote_v = video_ssrc_of(engine->peer);
  constexpr int kVp8Pt = 96;

  run_on(ws->worker_tq.get(), [&]() {
    // Video has its own network state (defaults kNetworkDown); bring it up.
    ws->call->SignalChannelNetworkState(webrtc::MediaType::VIDEO,
                                        webrtc::kNetworkUp);
    if (!ws->video_encoder_factory)
      ws->video_encoder_factory =
          std::make_unique<webrtc::VideoEncoderFactoryTemplate<
              webrtc::LibvpxVp8EncoderTemplateAdapter>>();
    if (!ws->video_decoder_factory)
      ws->video_decoder_factory =
          std::make_unique<webrtc::VideoDecoderFactoryTemplate<
              webrtc::LibvpxVp8DecoderTemplateAdapter>>();
    if (!ws->video_bitrate_alloc_factory)
      ws->video_bitrate_alloc_factory =
          webrtc::CreateBuiltinVideoBitrateAllocatorFactory();
    if (!ws->video_source)
      ws->video_source = std::make_unique<webrtc::VideoBroadcaster>();

    if (send && ws->video_send_stream == nullptr) {
      webrtc::VideoSendStream::Config sc(ws->shim.get());  // sets send_transport
      sc.rtp.ssrcs = {local_v};                            // NOTE: vector
      sc.rtp.payload_name = "VP8";
      sc.rtp.payload_type = kVp8Pt;
      sc.rtp.extensions.emplace_back(
          webrtc::RtpExtension::kTransportSequenceNumberUri,
          webrtc::RtpHeaderExtensionId(1));  // TWCC, same id as audio
      sc.encoder_settings.encoder_factory = ws->video_encoder_factory.get();
      sc.encoder_settings.bitrate_allocator_factory =
          ws->video_bitrate_alloc_factory.get();  // REQUIRED (deref, no null-check)

      // Bitrate/framerate are kept LOW for now: the veil media datagram path
      // pads every packet to a 16KB onion cell, so VP8's packet rate otherwise
      // floods the circuit and starves audio. Until RTP is batched into cells,
      // cap the rate so audio + video coexist. (VEIL_MEDIA_VIDEO_KBPS overrides.)
      int kbps = 150;
      if (const char* e = std::getenv("VEIL_MEDIA_VIDEO_KBPS")) {
        int v = std::atoi(e);
        if (v > 0) kbps = v;
      }
      const int bps = kbps * 1000;
      webrtc::VideoEncoderConfig ec;
      ec.codec_type = webrtc::kVideoCodecVP8;
      ec.video_format = webrtc::SdpVideoFormat::VP8();
      ec.content_type = webrtc::VideoEncoderConfig::ContentType::kRealtimeVideo;
      ec.number_of_streams = 1;
      ec.max_bitrate_bps = bps;
      webrtc::VideoStream layer;  // ≥1 layer REQUIRED (default factory DCHECK)
      layer.active = true;
      layer.min_bitrate_bps = 30000;
      layer.target_bitrate_bps = bps * 2 / 3;
      layer.max_bitrate_bps = bps;
      layer.max_framerate = 15;
      layer.max_qp = 63;
      ec.simulcast_layers.push_back(layer);

      ws->video_send_stream =
          ws->call->CreateVideoSendStream(std::move(sc), std::move(ec));
      vlog("video: send stream=%p", (void*)ws->video_send_stream);
      if (ws->video_send_stream) {
        ws->video_send_stream->SetSource(
            ws->video_source.get(),
            webrtc::DegradationPreference::MAINTAIN_FRAMERATE);
        ws->video_send_stream->Start();
      }
    }
    if (recv && ws->video_recv_stream == nullptr) {
      webrtc::VideoReceiveStreamInterface::Config rc(
          ws->shim.get(), ws->video_decoder_factory.get());
      rc.rtp.remote_ssrc = remote_v;    // do NOT set local_ssrc (deprecated)
      rc.renderer = ws->video_sink.get();
      rc.decoders.emplace_back(webrtc::SdpVideoFormat::VP8(), kVp8Pt);
      ws->video_recv_stream = ws->call->CreateVideoReceiveStream(std::move(rc));
      if (ws->video_recv_stream) ws->video_recv_stream->Start();
    }
  });
  // Route inbound video RTP (this SSRC) to the video demuxer in the shim.
  ws->shim->SetRemoteVideoSsrc(remote_v);
  vlog("video: start send=%d recv=%d ssrc(local=%u remote=%u)", send, recv,
       local_v, remote_v);

  // Built-in synthetic source (VEIL_MEDIA_TEST_VIDEO) — a moving gradient at
  // ~30fps into the broadcaster, so video RTP flows without a real capturer.
  if (send && std::getenv("VEIL_MEDIA_TEST_VIDEO") != nullptr &&
      !ws->test_video_run.load()) {
    ws->test_video_run.store(true);
    ws->test_video_thread = std::thread([ws]() {
      const int w = 320, h = 240;
      const int cw = (w + 1) / 2, chh = (h + 1) / 2;
      std::vector<uint8_t> yb(w * h), ub(cw * chh), vb(cw * chh);
      uint32_t f = 0;
      while (ws->test_video_run.load()) {
        for (int j = 0; j < h; ++j)
          for (int i = 0; i < w; ++i)
            yb[j * w + i] = static_cast<uint8_t>(i + j + f);
        std::fill(ub.begin(), ub.end(), static_cast<uint8_t>(128));
        std::fill(vb.begin(), vb.end(), static_cast<uint8_t>(128 + f));
        push_i420(ws->video_source.get(), yb.data(), ub.data(), vb.data(), w, h,
                  w, cw, cw, 0);
        if ((f % 60) == 0) vlog("test video: pushed %u frames", f);
        ++f;
        std::this_thread::sleep_for(std::chrono::milliseconds(33));
      }
    });
  }
  return VEIL_MEDIA_OK;
#else
  (void)send;
  (void)recv;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_stop_video(VeilMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws) return VEIL_MEDIA_OK;
  WebrtcState* ws = engine->ws.get();
  // Stop the sources first so no OnFrame races the stream teardown.
  if (ws->camera) {
    ws->camera->Stop();
    ws->camera.reset();
  }
  if (ws->test_video_run.exchange(false) && ws->test_video_thread.joinable())
    ws->test_video_thread.join();
  if (ws->call) {
    run_on(ws->worker_tq.get(), [&]() {
      if (ws->video_send_stream) {
        ws->video_send_stream->Stop();
        ws->call->DestroyVideoSendStream(ws->video_send_stream);
        ws->video_send_stream = nullptr;
      }
      if (ws->video_recv_stream) {
        ws->video_recv_stream->Stop();
        ws->call->DestroyVideoReceiveStream(ws->video_recv_stream);
        ws->video_recv_stream = nullptr;
      }
    });
  }
  if (ws->shim) ws->shim->SetRemoteVideoSsrc(0);
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_start_camera(VeilMediaEngine* engine, int width,
                                   int height, int fps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && (defined(__APPLE__) || defined(__linux__))
  WebrtcState* ws = engine->ws.get();
  if (!ws || !ws->video_source) return VEIL_MEDIA_ERR_STATE;
  if (ws->camera) return VEIL_MEDIA_OK;  // already capturing
  if (width <= 0) width = 352;
  if (height <= 0) height = 288;
  if (fps <= 0) fps = 15;
  // Feed each captured I420 frame straight into the VP8 send source. The
  // callback runs on the capture queue; push_i420 copies synchronously.
  webrtc::VideoBroadcaster* src = ws->video_source.get();
  ws->camera.reset(veil_media::CreatePlatformCamera(
      [src](const uint8_t* y, const uint8_t* u, const uint8_t* v, int w, int h,
            int sy, int su, int sv, int64_t ts_us) {
        push_i420(src, y, u, v, w, h, sy, su, sv, ts_us);
      }));
  if (!ws->camera) return VEIL_MEDIA_ERR_STATE;
  if (!ws->camera->Start(width, height, fps)) {
    ws->camera.reset();
    return VEIL_MEDIA_ERR_STATE;
  }
  vlog("camera: started %dx%d@%d", width, height, fps);
  return VEIL_MEDIA_OK;
#else
  (void)width;
  (void)height;
  (void)fps;
  return VEIL_MEDIA_ERR_STATE;  // no camera backend on this platform yet
#endif
}

int veil_media_engine_stop_camera(VeilMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->camera) {
    engine->ws->camera->Stop();
    engine->ws->camera.reset();
  }
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_push_video_frame(VeilMediaEngine* engine,
                                       const uint8_t* y, const uint8_t* u,
                                       const uint8_t* v, int width, int height,
                                       int stride_y, int stride_u, int stride_v,
                                       int64_t ts_us) {
  if (engine == nullptr || y == nullptr || u == nullptr || v == nullptr)
    return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->video_source) return VEIL_MEDIA_ERR_STATE;
  push_i420(engine->ws->video_source.get(), y, u, v, width, height, stride_y,
            stride_u, stride_v, ts_us);
  return VEIL_MEDIA_OK;
#else
  (void)width; (void)height; (void)stride_y; (void)stride_u; (void)stride_v;
  (void)ts_us;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_get_video_frame(VeilMediaEngine* engine, uint8_t* dst,
                                      int dst_cap, int* out_w, int* out_h) {
  if (engine == nullptr) return 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->video_sink)
    return engine->ws->video_sink->get_frame(dst, dst_cap, out_w, out_h);
#else
  (void)dst;
  (void)dst_cap;
  (void)out_w;
  (void)out_h;
#endif
  return 0;
}

int veil_media_engine_set_mic_muted(VeilMediaEngine* engine, int muted) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  engine->mic_muted = muted != 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->send_stream)
    engine->ws->send_stream->SetMuted(engine->mic_muted);
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_set_speaker_muted(VeilMediaEngine* engine, int muted) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  engine->speaker_muted = muted != 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->recv_stream)
    engine->ws->recv_stream->SetGain(engine->speaker_muted ? 0.f : 1.f);
#endif
  return VEIL_MEDIA_OK;
}

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
namespace {
// JSON [{"id","label","kind"}] from the ADM. `recording` = inputs.
char* adm_devices_json(webrtc::AudioDeviceModule* adm, bool recording) {
  std::string out = "[";
  if (adm) {
    const int16_t n = recording ? adm->RecordingDevices() : adm->PlayoutDevices();
    for (int16_t i = 0; i < n; ++i) {
      char name[webrtc::kAdmMaxDeviceNameSize] = {0};
      char guid[webrtc::kAdmMaxGuidSize] = {0};
      const int32_t rc = recording ? adm->RecordingDeviceName(i, name, guid)
                                   : adm->PlayoutDeviceName(i, name, guid);
      if (rc != 0) continue;
      if (out.size() > 1) out += ",";
      out += "{\"id\":\"";
      out += std::to_string(i);
      out += "\",\"label\":\"";
      for (const char* p = name; *p; ++p) {  // minimal JSON string escaping
        if (*p == '"' || *p == '\\') out += '\\';
        out += *p;
      }
      out += "\",\"kind\":\"";
      out += recording ? "input" : "output";
      out += "\"}";
    }
  }
  out += "]";
  return dup_cstr(out);
}
}  // namespace
#endif

char* veil_media_engine_list_audio_inputs(VeilMediaEngine* engine) {
  if (engine == nullptr) return nullptr;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return adm_devices_json(engine->ws ? engine->ws->adm.get() : nullptr, true);
#else
  return dup_cstr("[]");
#endif
}

char* veil_media_engine_list_audio_outputs(VeilMediaEngine* engine) {
  if (engine == nullptr) return nullptr;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return adm_devices_json(engine->ws ? engine->ws->adm.get() : nullptr, false);
#else
  return dup_cstr("[]");
#endif
}

int veil_media_engine_select_audio_input(VeilMediaEngine* engine,
                                         const char* id) {
  if (engine == nullptr || id == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->adm) return VEIL_MEDIA_ERR_DEVICE;
  const uint16_t idx = static_cast<uint16_t>(std::atoi(id));
  // Stop -> switch -> restart so the change takes effect mid-call.
  webrtc::AudioDeviceModule* adm = engine->ws->adm.get();
  adm->StopRecording();
  if (adm->SetRecordingDevice(idx) != 0) return VEIL_MEDIA_ERR_DEVICE;
  adm->InitRecording();
  adm->StartRecording();
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_select_audio_output(VeilMediaEngine* engine,
                                          const char* id) {
  if (engine == nullptr || id == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->adm) return VEIL_MEDIA_ERR_DEVICE;
  const uint16_t idx = static_cast<uint16_t>(std::atoi(id));
  webrtc::AudioDeviceModule* adm = engine->ws->adm.get();
  adm->StopPlayout();
  if (adm->SetPlayoutDevice(idx) != 0) return VEIL_MEDIA_ERR_DEVICE;
  adm->InitPlayout();
  adm->StartPlayout();
#endif
  return VEIL_MEDIA_OK;
}

char* veil_media_engine_get_stats(VeilMediaEngine* engine) {
  if (engine == nullptr) return nullptr;
  // Aggregate from AudioSendStream::GetStats()/AudioReceiveStreamInterface::
  // GetStats() — wired in a later pass; placeholder shape for now.
  return dup_cstr(
      "{\"tx_pkts\":0,\"rx_pkts\":0,\"tx_bytes\":0,\"rx_bytes\":0,\"rtt_ms\":0,"
      "\"jitter_ms\":0,\"loss_pct\":0,\"target_bitrate_bps\":0}");
}

void veil_media_free_string(char* s) {
  if (s) std::free(s);
}

const char* veil_media_version(void) { return kVersion; }

}  // extern "C"
