// Compiled only into the stand dylib, never the production engine ABI.
// The actual sender offset supplies an exact encoder/RTP join, not a guessed
// alignment between two regular packet sequences. This hook never sends data.
#pragma GCC visibility push(default)
extern "C" int veil_media_test_route_restarts(VeilMediaEngine* e, int video) {
  if (!e || !e->ws) return -1;
  return (video ? e->ws->video_route_restarts : e->ws->audio_route_restarts)->load();
}
extern "C" int veil_media_test_with_held_video_worker(
    VeilMediaEngine* e, int (*check)(void*), void* context) {
  struct Hold { std::atomic<bool> entered{false}, release{false}; };
  auto hold = std::make_shared<Hold>();
  e->ws->video_worker_tq->PostTask([hold] {
    hold->entered.store(true);
    while (!hold->release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
  });
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (!hold->entered.load()) {
    if (std::chrono::steady_clock::now() >= deadline) { hold->release.store(true); return -1; }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  const int result = check(context);
  hold->release.store(true);
  return result;
}

extern "C" char* veil_media_test_group_audio_send_stats(VeilGroupMediaEngine* e) {
  if (!e || !e->ws) return nullptr;
  webrtc::AudioSendStream::Stats sample;
  uint32_t origin = 0, timestamp = 0;
  uint16_t sequence = 0;
  bool found = false;
  const bool ran = run_on(e->ws->worker_tq.get(), [&] {
    if (!e->ws->send_stream) return;
    sample = e->ws->send_stream->GetStats();
    const auto state = static_cast<const webrtc::internal::AudioSendStream*>(
        e->ws->send_stream)->GetRtpState();
    origin = state.start_timestamp;
    timestamp = state.timestamp;
    sequence = state.sequence_number;
    found = true;
  });
  if (!ran || !found) return nullptr;
  char json[512];
  const int size = std::snprintf(json, sizeof(json),
      "{\"packets\":%d,\"payload_bytes\":%lld,\"header_padding_bytes\":%lld,"
      "\"target_bps\":%lld,\"rtp_origin\":%u,\"rtp_timestamp\":%u,"
      "\"rtp_sequence\":%u}", sample.packets_sent,
      static_cast<long long>(sample.payload_bytes_sent),
      static_cast<long long>(sample.header_and_padding_bytes_sent),
      static_cast<long long>(sample.target_bitrate_bps), origin, timestamp,
      static_cast<unsigned>(sequence));
  if (size <= 0 || static_cast<size_t>(size) >= sizeof(json)) return nullptr;
  return dup_cstr(json);
}
extern "C" int veil_media_test_audio_timing_anchor(VeilMediaEngine* e, int source) {
  if (!e || !e->ws || source < 0 || source > 1 || !veil_media::diag::enabled())
    return VEIL_MEDIA_ERR_ARG;
  bool found = false;
  const bool ran = run_on(e->ws->worker_tq.get(), [&] {
    if (!e->ws->send_stream) return;
    const auto* stream = static_cast<const webrtc::internal::AudioSendStream*>(
        e->ws->send_stream);
    const auto state = stream->GetRtpState();
    veil_media::diag::log("audio.rtp.anchor source=%d ssrc=%u offset=%u",
                          source, ssrc_of(e->local), state.start_timestamp);
    found = true;
  });
  return ran && found ? VEIL_MEDIA_OK : VEIL_MEDIA_ERR_STATE;
}
#pragma GCC visibility pop

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
#if defined(__APPLE__)
extern "C" int veil_media_test_avf_configuration_recovery(VeilMediaEngine* e,
                                                          int pending_teardown) {
  return veil_media::TestVeilAvfConfigurationRecovery(e->ws->adm.get(),
                                                     pending_teardown != 0);
}
#endif
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
    const bool had_video_budget = std::getenv("VEIL_MEDIA_VIDEO_KBPS") != nullptr;
    std::string saved_video_budget = had_video_budget
        ? std::getenv("VEIL_MEDIA_VIDEO_KBPS") : "";
    ResetFactory() {
      g_call_plane_recording_adm = true;
      setenv("VEIL_MEDIA_TEST_VIDEO", "1", 1);
      // Explicitly request a large STARTUP video budget. A subsequent ceiling
      // increase must not reset GCC's live estimate, so retuning a cold room
      // alone cannot establish the distinct estimates this test compares.
      setenv("VEIL_MEDIA_VIDEO_KBPS", "900", 1);
    }
    ~ResetFactory() {
      g_call_plane_recording_adm = false;
      if (prior) setenv("VEIL_MEDIA_TEST_VIDEO", saved.c_str(), 1);
      else unsetenv("VEIL_MEDIA_TEST_VIDEO");
      if (had_video_budget) setenv("VEIL_MEDIA_VIDEO_KBPS", saved_video_budget.c_str(), 1);
      else unsetenv("VEIL_MEDIA_VIDEO_KBPS");
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

// Exercise the real Call allocator -> ChannelSend -> Opus path, not a copy
// of its config. Legacy peers without negotiated TWCC retain their bitrate.
extern "C" int veil_media_test_audio_bandwidth() {
  struct ResetFactory {
    ResetFactory() { g_call_plane_recording_adm = true; }
    ~ResetFactory() { g_call_plane_recording_adm = false; }
  } reset;
  uint8_t local[32] = {0x81}, peer[32] = {0x82};
  for (int feedback : {0, 1}) {
    std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)> e(
        veil_media_engine_create(100 + feedback, local, peer),
        veil_media_engine_destroy);
    if (!e || veil_media_engine_set_independent_transport_feedback(e.get(), feedback) != VEIL_MEDIA_OK ||
        veil_media_engine_start_audio(e.get(), 1, 1) != VEIL_MEDIA_OK) return 1;
    auto* ws = e->ws.get();
    const auto target = [&](int transport_bps) {
      webrtc::BitrateSettings settings;
      settings.min_bitrate_bps = 6000;
      settings.start_bitrate_bps = transport_bps;
      settings.max_bitrate_bps = transport_bps;
      if (!run_on(ws->worker_tq.get(), [&] {
            ws->call->SetClientBitratePreferences(settings);
          })) return int64_t(-1);
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
      int64_t bitrate = -1;
      do {
        static_cast<StandRecordingAdm*>(ws->adm.get())->CaptureTone(440);
        if (!run_on(ws->worker_tq.get(), [&] {
              bitrate = ws->send_stream->GetStats().target_bitrate_bps;
            })) return int64_t(-1);
        if ((!feedback && bitrate > 0) ||
            (feedback && (transport_bps == 12000 ? bitrate == 24000 : bitrate == 32000))) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      } while (std::chrono::steady_clock::now() < deadline);
      return bitrate;
    };
    const auto high = target(48000);
    const auto low = target(12000);
    const auto restored = target(48000);
    std::fprintf(stderr, "Opus allocation feedback=%d: %lld -> %lld -> %lld\n",
                 feedback, (long long)high, (long long)low, (long long)restored);
    // The same low transport estimate must now preserve the protected speech
    // floor, then recover the original ceiling. No-feedback peers stay fixed.
    if (high != 32000 || low != (feedback ? 24000 : 32000) || restored != 32000) return 2;
  }
  return 0;
}

// Exercises the production fanout independently of codec pacing. The mocked
// Veil callback can stall video while a second thread submits audio.
extern "C" int veil_media_test_group_fanout_packet(VeilGroupMediaEngine* e,
                                                   int secondary) {
  if (secondary >= 4 && secondary <= 8) {
    std::vector<uint8_t> packet(64);
    const auto word = [&](size_t at, uint32_t value) {
      for (int i=0;i<4;++i) packet[at+i]=value>>(24-i*8);
    };
    packet[0]=0x80;packet[1]=200;packet[3]=6;word(4,9);
    packet[28]=0x81;packet[29]=202;packet[31]=2;word(32,9);packet[36]=1;
    packet[40]=0x8f;packet[41]=206;packet[43]=5;word(44,9);
    packet[52]='R';packet[53]='E';packet[54]='M';packet[55]='B';packet[56]=1;
    const uint32_t rate=secondary==6?16000:secondary==8?8000:32000;
    packet[57]=(rate>>16)&3;packet[58]=rate>>8;packet[59]=rate;word(60,10);
    if (secondary == 7) {
      const size_t at=packet.size();packet.resize(at+16);
      packet[at]=0x81;packet[at+1]=205;packet[at+3]=3;word(at+4,9);word(at+8,10);
    }
    webrtc::PacketOptions options;
    auto* transport=secondary==5?e->ws->fanout.get():e->ws->fanout->video_transport();
    return transport->SendRtcp(packet,options)?0:1;
  }
  if (secondary == 2 || secondary == 3) {
    std::array<uint8_t, 8> rr{0x80, 201, 0, 1};
    webrtc::PacketOptions options;
    auto* transport = secondary == 2 ? e->ws->fanout->video_transport()
                                     : e->ws->fanout.get();
    return transport->SendRtcp(rr, options) ? 0 : 1;
  }
  std::array<uint8_t, 15> packet{0x80, uint8_t(secondary ? 96 : 111)};
  const uint32_t ssrc = secondary ? group_video_ssrc_of(e->local)
                                  : group_audio_ssrc_of(e->local);
  for (int i = 0; i < 4; ++i) packet[8+i] = ssrc >> (24-i*8);
  webrtc::PacketOptions options;
  return e->ws->fanout->SendRtp(packet, options) ? 0 : 1;
}

// Exercise queued/retransmitted RTP at the final plaintext send boundary.
extern "C" int veil_media_test_direct_packet(VeilMediaEngine* e, int kind) {
  std::array<uint8_t, 15> packet{0x80, uint8_t(kind == 1 ? 96 : 111)};
  if (kind == 3 || kind == 4) {
    const auto ssrc = ssrc_of(e->local);
    for (int i = 0; i < 4; ++i) packet[8+i] = ssrc >> (24-i*8);
    if (kind == 4) { packet[0] |= 0x20; packet.back() = 3; }
  }
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

extern "C" VeilMediaEngine* veil_media_test_audio_playout_create(
    uint64_t chan, const uint8_t local[32], const uint8_t peer[32],
    int send, size_t buffer_packets) {
  g_call_plane_recording_adm = true;
  g_call_plane_audio_buffer_packets = buffer_packets;
  auto* e = veil_media_engine_create(chan, local, peer);
  if (e) {
    veil_media_engine_set_mic_muted(e, send ? 0 : 1);
    if (veil_media_engine_start_audio(e, send, 1) != VEIL_MEDIA_OK) {
      veil_media_engine_destroy(e);
      e = nullptr;
    }
  }
  g_call_plane_recording_adm = false;
  g_call_plane_audio_buffer_packets = 0;
  return e;
}

extern "C" int veil_media_test_audio_capture_tone(
    VeilMediaEngine* e, int frequency_hz) {
  // Zero supplies exact silent PCM through the same capture/Opus pipeline.
  if (!e || !e->ws || frequency_hz < 0 || frequency_hz > 8000)
    return VEIL_MEDIA_ERR_ARG;
  static_cast<StandRecordingAdm*>(e->ws->adm.get())->CaptureTone(frequency_hz);
  return VEIL_MEDIA_OK;
}

// The host chooses its own pre-start route controls. Anonymous routes must
// not inherit the non-onion helper's packet-overhead/1000-byte RTP overrides.
extern "C" VeilMediaEngine* veil_media_test_codec_create_unstarted(
    uint64_t chan, const uint8_t local[32], const uint8_t peer[32]) {
  g_call_plane_recording_adm = true;
  auto* e = veil_media_engine_create(chan, local, peer);
  g_call_plane_recording_adm = false;
  return e;
}

// Production codec/Call wiring with a deterministic duplex ADM and the
// negotiated v4 transport settings. These controls must precede StartAudio,
// which freezes transport feedback; the older playout helper starts at once.
extern "C" VeilMediaEngine* veil_media_test_duplex_codec_create(
    uint64_t chan, const uint8_t local[32], const uint8_t peer[32]) {
  g_call_plane_recording_adm = true;
  auto* e = veil_media_engine_create(chan, local, peer);
  g_call_plane_recording_adm = false;
  if (!e) return nullptr;
  if (veil_media_engine_set_independent_transport_feedback(e, 1) != VEIL_MEDIA_OK ||
      veil_media_engine_set_max_rtp_packet_size(e, 1000) != VEIL_MEDIA_OK ||
      veil_media_engine_start_audio(e, 1, 1) != VEIL_MEDIA_OK) {
    veil_media_engine_destroy(e);
    return nullptr;
  }
  return e;
}

extern "C" int veil_media_test_audio_transport_budget(VeilMediaEngine* e,
                                                      int bitrate_bps) {
  if (!e || !e->ws || bitrate_bps < 6000) return VEIL_MEDIA_ERR_ARG;
  webrtc::BitrateSettings settings;
  settings.min_bitrate_bps = 6000;
  settings.start_bitrate_bps = bitrate_bps;
  settings.max_bitrate_bps = bitrate_bps;
  return run_on(e->ws->worker_tq.get(), [&] {
    e->ws->call->SetClientBitratePreferences(settings);
  }) ? VEIL_MEDIA_OK : VEIL_MEDIA_ERR_STATE;
}

// Keep the network allocation fixed while testing framing changes. This is
// separate from the upper-bound hook above: real GCC is otherwise allowed to
// lower the estimate, making a 40-ms packet on a recovered route legitimate.
extern "C" int veil_media_test_audio_fixed_transport_budget(VeilMediaEngine* e,
                                                            int bitrate_bps) {
  if (!e || !e->ws || bitrate_bps < 6000) return VEIL_MEDIA_ERR_ARG;
  webrtc::BitrateSettings settings;
  settings.min_bitrate_bps = bitrate_bps;
  settings.start_bitrate_bps = bitrate_bps;
  settings.max_bitrate_bps = bitrate_bps;
  return run_on(e->ws->worker_tq.get(), [&] {
    e->ws->call->SetClientBitratePreferences(settings);
  }) ? VEIL_MEDIA_OK : VEIL_MEDIA_ERR_STATE;
}

extern "C" int veil_media_test_audio_playout_pcm(
    VeilMediaEngine* e, int16_t* pcm, size_t capacity) {
  if (!e || !e->ws || !pcm || capacity < 480) return VEIL_MEDIA_ERR_ARG;
  return static_cast<int>(
      static_cast<StandRecordingAdm*>(e->ws->adm.get())->Playout(pcm, capacity));
}

// Exercise the production group mixer and its per-peer Opus receivers without
// opening host input/output devices. Membership and start remain public ABI.
extern "C" VeilGroupMediaEngine* veil_media_test_group_codec_create(
    const uint8_t local[32]) {
  if (!local) return nullptr;
  const bool previous = g_call_plane_recording_adm;
  g_call_plane_recording_adm = true;
  auto* e = veil_media_group_engine_create(local);
  g_call_plane_recording_adm = previous;
  return e;
}

extern "C" int veil_media_test_group_capture_tone(
    VeilGroupMediaEngine* e, int frequency_hz) {
  if (!e || !e->ws || frequency_hz < 0 || frequency_hz > 8000)
    return VEIL_MEDIA_ERR_ARG;
  static_cast<StandRecordingAdm*>(e->ws->adm.get())->CaptureTone(frequency_hz);
  return VEIL_MEDIA_OK;
}

extern "C" int veil_media_test_group_playout_pcm(
    VeilGroupMediaEngine* e, int16_t* pcm, size_t capacity) {
  if (!e || !e->ws || !pcm || capacity < 480) return VEIL_MEDIA_ERR_ARG;
  return static_cast<int>(
      static_cast<StandRecordingAdm*>(e->ws->adm.get())->Playout(pcm, capacity));
}

extern "C" int veil_media_test_group_with_held_video(
    VeilGroupMediaEngine* e, int (*drive)(void*), void* ctx) {
  if (!e || !e->ws || !drive) return VEIL_MEDIA_ERR_ARG;
  HeldQueues held(e->ws->video_network_tq.get(), e->ws->video_worker_tq.get());
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (!held.first->entered.load() || !held.second->entered.load()) {
    if (std::chrono::steady_clock::now() >= deadline) return VEIL_MEDIA_ERR_STATE;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  // RAII releases both queues on every callback result before engine teardown.
  return drive(ctx);
}

extern "C" int veil_media_test_group_with_held_audio(
    VeilGroupMediaEngine* e, int (*drive)(void*), void* ctx) {
  if (!e || !e->ws || !drive) return VEIL_MEDIA_ERR_ARG;
  HeldQueues held(e->ws->network_tq.get(), e->ws->worker_tq.get());
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (!held.first->entered.load() || !held.second->entered.load()) {
    if (std::chrono::steady_clock::now() >= deadline) return VEIL_MEDIA_ERR_STATE;
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return drive(ctx);
}

#pragma GCC visibility pop

// Build the synthetic ADM around the same pre-start API used by the host.
#pragma GCC visibility push(default)
extern "C" VeilMediaEngine* veil_media_test_adaptive_codec_create(
    uint64_t chan, const uint8_t local[32], const uint8_t peer[32], int overhead) {
  g_call_plane_recording_adm = true;
  auto* e = veil_media_engine_create(chan, local, peer);
  g_call_plane_recording_adm = false;
  if (!e) return nullptr;
  if (veil_media_engine_set_independent_transport_feedback(e, 1) != VEIL_MEDIA_OK ||
      veil_media_engine_set_audio_packet_overhead(e, overhead) != VEIL_MEDIA_OK ||
      veil_media_engine_set_max_rtp_packet_size(e, 1000) != VEIL_MEDIA_OK ||
      veil_media_engine_start_audio(e, 1, 1) != VEIL_MEDIA_OK) {
    veil_media_engine_destroy(e);
    return nullptr;
  }
  return e;
}

// Optional framing experiment for the owned relay fixture. This changes only
// the stand's video controller/pacer; it sends no role or priority to Veil.
extern "C" VeilMediaEngine* veil_media_test_dual_overhead_codec_create(
    uint64_t chan, const uint8_t local[32], const uint8_t peer[32],
    int audio_overhead, int video_overhead) {
  if (video_overhead < 1 || video_overhead > 4096) return nullptr;
  auto* e = veil_media_test_adaptive_codec_create(chan, local, peer, audio_overhead);
  if (!e) return nullptr;
  if (!run_on(e->ws->video_worker_tq.get(), [&] {
        auto* controller = e->ws->video_call->GetTransportControllerSend();
        webrtc::NetworkRoute route;
        route.connected = true;
        route.packet_overhead = video_overhead;
        controller->OnNetworkRouteChanged("opaque", route);
        controller->IncludeOverheadInPacedSender();
      })) {
    veil_media_engine_destroy(e);
    return nullptr;
  }
  return e;
}

extern "C" int veil_media_test_video_transport_overhead(VeilMediaEngine* e) {
  if (!e || !e->ws || !e->ws->video_call) return -1;
  int bytes = -1;
  if (!run_on(e->ws->video_worker_tq.get(), [&] {
        bytes = e->ws->video_call->GetTransportControllerSend()
                    ->GetTransportOverhead().bytes<int>();
      })) return -1;
  return bytes;
}

extern "C" int veil_media_test_audio_transport_overhead(VeilMediaEngine* e) {
  if (!e || !e->ws || !e->ws->call) return -1;
  int bytes = -1;
  if (!run_on(e->ws->worker_tq.get(), [&] {
        bytes = e->ws->call->GetTransportControllerSend()
                    ->GetTransportOverhead().bytes<int>();
      })) return -1;
  return bytes;
}
#pragma GCC visibility pop
