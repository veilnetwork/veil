// Compiled only into the stand dylib, never the production engine ABI.
namespace {
using PlaneInjector = int (*)(void*, uint64_t, uint32_t, uint32_t);
uint64_t sent_audio_packets(WebrtcState* ws) {
  uint64_t count = 0;
  run_on(ws->worker_tq.get(), [&] {
    if (ws->send_stream) count = ws->send_stream->GetStats().packets_sent;
  });
  return count;
}
struct HeldQueues {
  struct Gate {
    std::atomic<bool> entered{false};
    std::atomic<bool> released{false};
  };
  std::shared_ptr<Gate> first = std::make_shared<Gate>();
  std::shared_ptr<Gate> second = std::make_shared<Gate>();
  HeldQueues(webrtc::TaskQueueBase* net, webrtc::TaskQueueBase* work) {
    const auto hold = [](webrtc::TaskQueueBase* q, std::shared_ptr<Gate> g) {
      q->PostTask([g] {
        g->entered.store(true);
        while (!g->released.load())
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
      });
    };
    hold(net, first);
    hold(work, second);
  }
  void Release() {
    first->released.store(true);
    second->released.store(true);
  }
  ~HeldQueues() { Release(); }
};
int check_call_planes(webrtc::Call* audio, webrtc::Call* video,
                      webrtc::TaskQueueBase* audio_worker,
                      webrtc::TaskQueueBase* audio_net,
                      webrtc::TaskQueueBase* video_worker,
                      webrtc::TaskQueueBase* video_net,
                      webrtc::AudioReceiveStreamInterface* recv,
                      veil_media::VeilTransportShim* shim, uint64_t chan,
                      uint32_t audio_ssrc, uint32_t video_ssrc,
                      PlaneInjector inject, void* ctx) {
  if (!recv || !shim || audio == video || audio_worker == video_worker ||
      audio_net == video_net) return 1;
  uint32_t before = 0;
  if (!veil_media::run_on_with_timeout(audio_worker, [&] {
        before = recv->GetStats(false).packets_received;
      }, std::chrono::seconds(1))) return 2;
  const auto video_before = shim->delivered_video_cadence().frames;
  HeldQueues held(video_net, video_worker);
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (!held.first->entered.load() || !held.second->entered.load()) {
    if (std::chrono::steady_clock::now() >= deadline) return 3;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  if (inject(ctx, chan, audio_ssrc, video_ssrc) != 0) return 4;
  bool received = false;
  deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (std::chrono::steady_clock::now() < deadline) {
    if (!veil_media::run_on_with_timeout(audio_worker, [&] {
          received = recv->GetStats(false).packets_received >= before + 4;
        }, std::chrono::milliseconds(200))) return 5;
    if (received) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  if (!received || shim->delivered_video_cadence().frames != video_before)
    return 6;
  held.Release();
  deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (shim->delivered_video_cadence().frames == video_before) {
    if (std::chrono::steady_clock::now() >= deadline) return 7;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  if (!veil_media::run_on_with_timeout(video_net, [] {}, std::chrono::seconds(1)) ||
      !veil_media::run_on_with_timeout(video_worker, [] {}, std::chrono::seconds(1)))
    return 8;
  return 0;
}
}
#pragma GCC visibility push(default)
extern "C" int veil_media_test_direct_call_planes(
    VeilMediaEngine* e, PlaneInjector inject, void* ctx) {
  auto* ws = e->ws.get();
  return check_call_planes(ws->call.get(), ws->video_call.get(),
      ws->worker_tq.get(), ws->network_tq.get(), ws->video_worker_tq.get(),
      ws->video_network_tq.get(), ws->recv_stream, ws->shim.get(), e->veil_chan,
      ssrc_of(e->peer), video_ssrc_of(e->peer), inject, ctx);
}
// The same stats API must remain usable when the audio worker itself stops.
// Both holds are released even if the checker reports an error.
extern "C" int veil_media_test_blocked_audio_stats(
    VeilMediaEngine* e, PlaneInjector check, void* ctx) {
  auto* ws = e->ws.get();
  HeldQueues held(ws->worker_tq.get(), ws->video_worker_tq.get());
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (!held.first->entered.load() || !held.second->entered.load()) {
    if (std::chrono::steady_clock::now() >= deadline) return 1;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return check(ctx, e->veil_chan, ssrc_of(e->peer), video_ssrc_of(e->peer));
}

extern "C" int veil_media_test_group_blocked_audio_stats(
    VeilGroupMediaEngine* e, PlaneInjector check, void* ctx) {
  auto* ws = e->ws.get();
  HeldQueues held(ws->worker_tq.get(), ws->video_worker_tq.get());
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (!held.first->entered.load() || !held.second->entered.load()) {
    if (std::chrono::steady_clock::now() >= deadline) return 1;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return check(ctx, 0, 0, 0);
}

// Exercise the production RTCP encoder using the real cached receive sample,
// without waiting for WebRTC's randomized report timer.
extern "C" int veil_media_test_group_emit_rtcp(VeilGroupMediaEngine* e) {
  std::array<uint8_t, 8> packet{0x80, 201, 0, 1};
  const uint32_t source = group_audio_ssrc_of(e->local);
  for (int i = 0; i < 4; ++i) packet[4 + i] = source >> (24 - i * 8);
  webrtc::PacketOptions options;
  return e->ws->peers.begin()->second->shim->SendRtcp(packet, options) ? 0 : 1;
}

// The audio-only controller must not inherit the video-sized startup budget.
// Run the real Opus sender and independent video controller against a counting
// ADM and synthetic camera, with no hardware capture or network endpoint.
extern "C" int veil_media_test_audio_probe_budget() {
  struct ResetFactory {
    const char* prior = std::getenv("VEIL_MEDIA_TEST_VIDEO");
    std::string saved = prior ? prior : "";
    ResetFactory() {
      g_call_plane_recording_adm = true;
      setenv("VEIL_MEDIA_TEST_VIDEO", "1", 1);
    }
    ~ResetFactory() {
      g_call_plane_recording_adm = false;
      if (prior) setenv("VEIL_MEDIA_TEST_VIDEO", saved.c_str(), 1);
      else unsetenv("VEIL_MEDIA_TEST_VIDEO");
    }
  } reset;
  uint8_t local[32] = {0x71}, peer[32] = {0x72};
  for (bool room : {false, true}) {
    std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)> one(
        room ? nullptr : veil_media_engine_create(99, local, peer),
        veil_media_engine_destroy);
    std::unique_ptr<VeilGroupMediaEngine, decltype(&veil_media_group_engine_destroy)> group(
        room ? veil_media_group_engine_create(local) : nullptr,
        veil_media_group_engine_destroy);
    if ((!room && !one) || (room && !group)) return 1;
    if (room && veil_media_group_engine_add_peer(group.get(), 99, peer) != VEIL_MEDIA_OK)
      return 2;
    if ((room ? veil_media_group_engine_start_audio(group.get())
              : veil_media_engine_start_audio(one.get(), 1, 1)) != VEIL_MEDIA_OK)
      return 3;
    if ((room ? veil_media_group_engine_start_video(group.get())
              : veil_media_engine_start_video(one.get(), 1, 0, 900, 15)) != VEIL_MEDIA_OK)
      return 4;
    if (room && veil_media_group_engine_set_video_bitrate(group.get(), 900, 15) != VEIL_MEDIA_OK)
      return 4;
    auto check = [room](auto* ws) {
      static_cast<StandRecordingAdm*>(ws->adm.get())->Capture(60);
      int audio = 0, video = 0;
      uint64_t packets = 0;
      if (!run_on(ws->worker_tq.get(), [&] {
            audio = ws->call->GetStats().send_bandwidth_bps;
            if (ws->send_stream) packets = ws->send_stream->GetStats().packets_sent;
          }) || !run_on(ws->video_worker_tq.get(), [&] {
            video = ws->video_call->GetStats().send_bandwidth_bps;
          })) return 5;
      std::fprintf(stderr, "audio probe budget room=%d: audio=%d video=%d packets=%llu\n",
                   room, audio, video, (unsigned long long)packets);
      if (packets == 0 || audio <= 0 || audio > 96000 || video <= 96000)
        return 6;
      return 0;
    };
    const int result = room ? check(group->ws.get()) : check(one->ws.get());
    if (result) return result;
  }
  return 0;
}

// Two engine generations reproduce starting/rebuilding an already-muted call.
// The real AudioState, stream and Opus encoder run against a counting ADM.
extern "C" int veil_media_test_muted_capture_lifecycle() {
  struct ResetFactory {
    ResetFactory() { g_call_plane_recording_adm = true; }
    ~ResetFactory() { g_call_plane_recording_adm = false; }
  } reset;
  uint8_t local[32] = {0x61}, peer[32] = {0x62};
  for (int generation = 0; generation < 2; ++generation) {
    std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)> e(
        veil_media_engine_create(81, local, peer), veil_media_engine_destroy);
    if (!e) return 1;
    auto* device = static_cast<StandRecordingAdm*>(e->ws->adm.get());
    if (veil_media_engine_set_mic_muted(e.get(), 1) != VEIL_MEDIA_OK ||
        veil_media_engine_start_audio(e.get(), 1, 1) != VEIL_MEDIA_OK) return 2;
    if (device->Recording() || device->recording_starts.load() != 0) return 3;
    device->Capture(20);
    if (sent_audio_packets(e->ws.get()) != 0) return 4;
    if (veil_media_engine_set_mic_muted(e.get(), 0) != VEIL_MEDIA_OK ||
        !device->Recording()) return 5;
    device->Capture(60);
    if (sent_audio_packets(e->ws.get()) == 0) return 6;
    HeldQueues held(e->ws->worker_tq.get(), e->ws->video_worker_tq.get());
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (!held.first->entered.load() || !held.second->entered.load()) {
      if (std::chrono::steady_clock::now() >= deadline) return 7;
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    int mute_rc = VEIL_MEDIA_ERR_STATE;
    std::thread muter([&] { mute_rc = veil_media_engine_set_mic_muted(e.get(), 1); });
    deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
    while (device->Recording() && std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    const bool stopped = !device->Recording();
    held.Release();
    muter.join();
    if (!stopped || mute_rc != VEIL_MEDIA_OK) return 7;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const auto before = sent_audio_packets(e->ws.get());
    device->Capture(20);
    if (sent_audio_packets(e->ws.get()) != before) return 8;
  }
  for (int generation = 0; generation < 2; ++generation) {
    std::unique_ptr<VeilGroupMediaEngine, decltype(&veil_media_group_engine_destroy)> e(
        veil_media_group_engine_create(local), veil_media_group_engine_destroy);
    if (!e) return 9;
    auto* device = static_cast<StandRecordingAdm*>(e->ws->adm.get());
    if (veil_media_group_engine_set_mic_muted(e.get(), 1) != VEIL_MEDIA_OK ||
        veil_media_group_engine_start_audio(e.get()) != VEIL_MEDIA_OK) return 10;
    if (device->Recording() || device->recording_starts.load() != 0) return 11;
    if (veil_media_group_engine_set_mic_muted(e.get(), 0) != VEIL_MEDIA_OK ||
        !device->Recording()) return 12;
    if (veil_media_group_engine_set_mic_muted(e.get(), 1) != VEIL_MEDIA_OK ||
        device->Recording()) return 13;
  }
  return 0;
}

extern "C" int veil_media_test_group_call_planes(
    VeilGroupMediaEngine* e, PlaneInjector inject, void* ctx) {
  auto* ws = e->ws.get();
  auto* peer = ws->peers.begin()->second.get();
  return check_call_planes(ws->call.get(), ws->video_call.get(),
      ws->worker_tq.get(), ws->network_tq.get(), ws->video_worker_tq.get(),
      ws->video_network_tq.get(), peer->recv_stream, peer->shim.get(), peer->chan,
      peer->audio_ssrc, peer->video_ssrc, inject, ctx);
}

extern "C" int veil_media_test_video_bandwidth(VeilMediaEngine* e) {
  int bandwidth = -1;
  auto* ws = e->ws.get();
  if (!veil_media::run_on_with_timeout(ws->video_worker_tq.get(), [&] {
        bandwidth = ws->video_call->GetStats().send_bandwidth_bps;
      }, std::chrono::seconds(1))) return -1;
  return bandwidth;
}

// Exercises the production fanout independently of codec pacing. The mocked
// Veil callback can stall video while a second thread submits audio.
extern "C" int veil_media_test_group_fanout_packet(VeilGroupMediaEngine* e,
                                                   int secondary) {
  if (secondary == 2) {
    std::array<uint8_t, 8> rr{0x80, 201, 0, 1};
    webrtc::PacketOptions options;
    return e->ws->fanout->video_transport()->SendRtcp(rr, options) ? 0 : 1;
  }
  std::array<uint8_t, 15> packet{0x80, uint8_t(secondary ? 96 : 111)};
  webrtc::PacketOptions options;
  return e->ws->fanout->SendRtp(packet, options) ? 0 : 1;
}

// Exercise queued/retransmitted RTP at the final plaintext send boundary.
extern "C" int veil_media_test_direct_packet(VeilMediaEngine* e, int kind) {
  std::array<uint8_t, 15> packet{0x80, uint8_t(kind == 1 ? 96 : 111)};
  webrtc::PacketOptions options;
  if (kind == 2) {
    std::array<uint8_t, 8> rtcp{0x80, 201, 0, 1};
    return e->ws->shim->SendRtcp(rtcp, options) ? 0 : 1;
  }
  return e->ws->shim->SendRtp(packet, options) ? 0 : 1;
}

extern "C" int veil_media_test_pause_with_held_video_worker(
    VeilMediaEngine* one, VeilGroupMediaEngine* room) {
  auto* work = room ? room->ws->video_worker_tq.get() : one->ws->video_worker_tq.get();
  auto* net = room ? room->ws->video_network_tq.get() : one->ws->video_network_tq.get();
  HeldQueues held(net, work);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (!held.first->entered.load() || !held.second->entered.load()) {
    if (std::chrono::steady_clock::now() >= deadline) return 1;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  const auto pause = [&](int value) {
    return room ? veil_media_group_engine_set_video_send_paused(room, value)
                : veil_media_engine_set_video_send_paused(one, value);
  };
  const auto started = std::chrono::steady_clock::now();
  if (pause(1) != VEIL_MEDIA_OK) return 2;
  if (std::chrono::steady_clock::now() - started > std::chrono::milliseconds(20)) return 3;
  if (pause(0) != VEIL_MEDIA_ERR_STATE) return 4;
  held.Release();
  return 0;
}

// Count actual encoding independently of the final send gate.
extern "C" uint64_t veil_media_test_direct_encoded_frames(VeilMediaEngine* e) {
  uint64_t frames = 0;
  auto* ws = e->ws.get();
  if (!veil_media::run_on_with_timeout(ws->video_worker_tq.get(), [&] {
    if (ws->video_send_stream) frames = ws->video_send_stream->GetStats().frames_encoded;
  }, std::chrono::seconds(1))) return UINT64_MAX;
  return frames;
}

#pragma GCC visibility pop
