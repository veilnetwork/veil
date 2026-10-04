// Compiled only into the stand dylib, never the production engine ABI.
namespace {
using PlaneInjector = int (*)(void*, uint64_t, uint32_t, uint32_t);
struct HeldVideoQueues {
  struct Gate {
    std::atomic<bool> entered{false};
    std::atomic<bool> released{false};
  };
  std::shared_ptr<Gate> network = std::make_shared<Gate>();
  std::shared_ptr<Gate> worker = std::make_shared<Gate>();
  HeldVideoQueues(webrtc::TaskQueueBase* net, webrtc::TaskQueueBase* work) {
    const auto hold = [](webrtc::TaskQueueBase* q, std::shared_ptr<Gate> g) {
      q->PostTask([g] {
        g->entered.store(true);
        while (!g->released.load())
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
      });
    };
    hold(net, network);
    hold(work, worker);
  }
  void Release() {
    network->released.store(true);
    worker->released.store(true);
  }
  ~HeldVideoQueues() { Release(); }
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
  HeldVideoQueues held(video_net, video_worker);
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (!held.network->entered.load() || !held.worker->entered.load()) {
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

#pragma GCC visibility pop
