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

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
#include "api/audio/audio_device.h"
#include "api/audio/builtin_audio_processing_builder.h"
#include "api/audio/create_audio_device_module.h"
#include "api/audio_codecs/audio_format.h"
#include "api/audio_codecs/builtin_audio_decoder_factory.h"
#include "api/audio_codecs/builtin_audio_encoder_factory.h"
#include "api/environment/environment.h"
#include "api/environment/environment_factory.h"
#include "api/rtp_header_extension_id.h"
#include "api/rtp_parameters.h"
#include "api/scoped_refptr.h"
#include "api/task_queue/task_queue_base.h"
#include "api/task_queue/task_queue_factory.h"
#include "call/audio_receive_stream.h"
#include "call/audio_send_stream.h"
#include "call/audio_state.h"
#include "call/call.h"
#include "call/call_config.h"
#include "modules/audio_mixer/audio_mixer_impl.h"

#include "veil_transport_shim.h"
#endif

namespace {

const char* kVersion = "veil_media 0.0.1 (phase3)";
constexpr int kOpusPayloadType = 111;  // SDP convention (Opus, 48k, stereo)

char* dup_cstr(const std::string& s) {
  char* out = static_cast<char*>(std::malloc(s.size() + 1));
  if (out) std::memcpy(out, s.c_str(), s.size() + 1);
  return out;
}

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
// SSRC from the first 4 bytes of a node id (never 0 — 0 is an invalid SSRC).
uint32_t ssrc_of(const uint8_t id[32]) {
  uint32_t s = (uint32_t(id[0]) << 24) | (uint32_t(id[1]) << 16) |
               (uint32_t(id[2]) << 8) | uint32_t(id[3]);
  return s == 0 ? 1u : s;
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

  ws->adm = webrtc::CreateAudioDeviceModule(
      ws->env, webrtc::AudioDeviceModule::kPlatformDefaultAudio);
  if (ws->adm) ws->adm->Init();
  ws->apm = webrtc::BuiltinAudioProcessingBuilder().Build(ws->env);

  webrtc::AudioState::Config asc;
  asc.audio_mixer = webrtc::AudioMixerImpl::Create();
  asc.audio_processing = ws->apm;
  asc.audio_device_module = ws->adm;
  ws->audio_state = webrtc::AudioState::Create(asc);

  webrtc::CallConfig call_cfg(ws->env, ws->worker_tq.get(),
                              ws->network_tq.get());
  call_cfg.audio_state = ws->audio_state;
  ws->call = webrtc::Call::Create(std::move(call_cfg));

  ws->shim = std::make_unique<veil_media::VeilTransportShim>(
      veil_chan, ws->call.get(), ws->network_tq.get());
  ws->shim->Start();

  engine->ws = std::move(ws);
#endif
  return engine.release();
}

void veil_media_engine_destroy(VeilMediaEngine* engine) {
  if (engine == nullptr) return;
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
  }
#endif
  return VEIL_MEDIA_OK;
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
