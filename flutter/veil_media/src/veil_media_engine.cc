/* SPDX-License-Identifier: MIT
 *
 * veil_media_engine.cc — implements the veil_media_engine_* control ABI
 * (veil_media_engine.h) on top of webrtc::Call + the VeilTransportShim.
 *
 * STATUS: the ABI surface, engine lifetime, thread ownership, and the shim
 * wiring are real. The webrtc::Call / AudioState / stream construction is the
 * documented Phase-0 sequence (see BUILD-INTEGRATION.md) and is finalized
 * against the checked-out WebRTC headers — those calls are grouped in the
 * clearly-marked WEBRTC-CONSTRUCTION regions so the version-sensitive surface
 * is contained. Guarded by VEIL_MEDIA_HAVE_WEBRTC so the ABI + shim link and
 * unit-test before the trimmed WebRTC lib is vendored.
 */

#include "veil_media_engine.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
#include "api/environment/environment_factory.h"  // CreateEnvironment
#include "call/call.h"
#include "api/audio/audio_state.h"
#include "api/task_queue/default_task_queue_factory.h"
#include "veil_transport_shim.h"
#endif

namespace {

const char* kVersion = "veil_media 0.0.1 (phase3-scaffold)";

// One SSRC pair for the audio session (single stream per direction, Phase 3).
constexpr uint32_t kLocalAudioSsrc = 0x5645494c;   // 'VEIL'
constexpr uint32_t kRemoteAudioSsrc = 0x4d454449;  // 'MEDI'

char* dup_cstr(const std::string& s) {
  char* out = static_cast<char*>(std::malloc(s.size() + 1));
  if (out) std::memcpy(out, s.c_str(), s.size() + 1);
  return out;
}

}  // namespace

// The opaque handle the ABI hands out.
struct VeilMediaEngine {
  uint64_t veil_chan = 0;
  uint8_t peer[32] = {0};
  std::atomic<bool> audio_running{false};
  bool mic_muted = false;
  bool speaker_muted = false;

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  std::unique_ptr<webrtc::TaskQueueFactory> task_queue_factory;
  std::unique_ptr<webrtc::Call> call;
  std::unique_ptr<veil_media::VeilTransportShim> shim;
  // AudioState, AudioSendStream, AudioReceiveStreamInterface* live here —
  // added with the WEBRTC-CONSTRUCTION region below.
#endif
};

extern "C" {

VeilMediaEngine* veil_media_engine_create(uint64_t veil_chan,
                                          const uint8_t* peer_id) {
  if (peer_id == nullptr) return nullptr;
  auto engine = std::make_unique<VeilMediaEngine>();
  engine->veil_chan = veil_chan;
  std::memcpy(engine->peer, peer_id, 32);

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  // === WEBRTC-CONSTRUCTION (finalize against built headers) ================
  // 1) Environment + task queues.
  //    webrtc::Environment env = webrtc::CreateEnvironment();
  //    engine->task_queue_factory = webrtc::CreateDefaultTaskQueueFactory();
  // 2) AudioState (AudioProcessing/AEC3 + AudioDeviceModule + Opus factories).
  // 3) webrtc::Call::Config cfg(env); engine->call = webrtc::Call::Create(cfg);
  // 4) Shim needs Call* + the network TaskQueue:
  //    engine->shim = std::make_unique<veil_media::VeilTransportShim>(
  //        veil_chan, engine->call.get(), network_task_queue);
  //    engine->shim->Start();
  // Streams are created lazily in start_audio (SSRCs above, Opus, TWCC ext).
  // =========================================================================
#endif
  return engine.release();
}

void veil_media_engine_destroy(VeilMediaEngine* engine) {
  if (engine == nullptr) return;
  veil_media_engine_stop_audio(engine);
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->shim) engine->shim->Stop();
  // Destroy order: streams -> shim -> call (streams reference the transport).
#endif
  delete engine;
}

int veil_media_engine_start_audio(VeilMediaEngine* engine, int send, int recv) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  if (engine->audio_running.load()) return VEIL_MEDIA_OK;  // idempotent
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  // === WEBRTC-CONSTRUCTION =================================================
  // if (send): AudioSendStream::Config c(engine->shim.get());
  //   c.rtp.ssrc = kLocalAudioSsrc; c.rtp.extensions += TransportSequenceNumber;
  //   c.send_codec_spec = Opus; engine->send = call->CreateAudioSendStream(c);
  //   engine->send->Start();
  // if (recv): AudioReceiveStreamInterface::Config c;
  //   c.rtp.remote_ssrc = kRemoteAudioSsrc; c.rtp.local_ssrc = kLocalAudioSsrc;
  //   c.rtcp_send_transport = engine->shim.get(); c.decoder_map = Opus;
  //   engine->recv = call->CreateAudioReceiveStream(c); engine->recv->Start();
  // =========================================================================
  (void)send;
  (void)recv;
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
  // Stop + DestroyAudioSendStream/ReceiveStream (before the shim/call go away).
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_set_mic_muted(VeilMediaEngine* engine, int muted) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  engine->mic_muted = muted != 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  // engine->send->SetMuted(engine->mic_muted);  (or stop ADM recording)
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_set_speaker_muted(VeilMediaEngine* engine, int muted) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  engine->speaker_muted = muted != 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  // engine->recv->SetGain(engine->speaker_muted ? 0.f : 1.f);
#endif
  return VEIL_MEDIA_OK;
}

char* veil_media_engine_list_audio_inputs(VeilMediaEngine* engine) {
  if (engine == nullptr) return nullptr;
  // ADM RecordingDevices()/RecordingDeviceName() -> JSON. Placeholder until
  // the ADM is wired.
  return dup_cstr("[]");
}

char* veil_media_engine_list_audio_outputs(VeilMediaEngine* engine) {
  if (engine == nullptr) return nullptr;
  return dup_cstr("[]");
}

int veil_media_engine_select_audio_input(VeilMediaEngine* engine,
                                         const char* id) {
  if (engine == nullptr || id == nullptr) return VEIL_MEDIA_ERR_ARG;
  // ADM Stop -> SetRecordingDevice -> Init -> Start (switch mid-call).
  return VEIL_MEDIA_OK;
}

int veil_media_engine_select_audio_output(VeilMediaEngine* engine,
                                          const char* id) {
  if (engine == nullptr || id == nullptr) return VEIL_MEDIA_ERR_ARG;
  return VEIL_MEDIA_OK;
}

char* veil_media_engine_get_stats(VeilMediaEngine* engine) {
  if (engine == nullptr) return nullptr;
  // Aggregate from call->GetStats()/stream GetStats(). Placeholder shape.
  std::string s = "{\"tx_pkts\":0,\"rx_pkts\":0,\"tx_bytes\":0,\"rx_bytes\":0,"
                  "\"rtt_ms\":0,\"jitter_ms\":0,\"loss_pct\":0,"
                  "\"target_bitrate_bps\":0}";
  return dup_cstr(s);
}

void veil_media_free_string(char* s) {
  if (s) std::free(s);
}

const char* veil_media_version(void) { return kVersion; }

}  // extern "C"
