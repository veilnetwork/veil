#include "veil_media_engine.h"
#include <array>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>

using Injector = int (*)(void*, uint64_t, uint32_t, uint32_t);
extern "C" int veil_media_test_direct_call_planes(VeilMediaEngine*, Injector, void*);
extern "C" int veil_media_test_group_call_planes(VeilGroupMediaEngine*, Injector, void*);
struct Callback { void (*fn)(void*, const uint8_t*, size_t); void* ctx; };
static std::mutex callback_mu;
static std::map<uint64_t, Callback> callbacks;
extern "C" int veil_media_send_datagram(uint64_t, const uint8_t*, size_t) { return 0; }
extern "C" int veil_media_set_recv_callback(
    uint64_t chan, void (*cb)(void*, const uint8_t*, size_t), void* ctx) {
  std::lock_guard lock(callback_mu);
  if (cb) callbacks[chan] = {cb, ctx};
  else callbacks.erase(chan);
  return 0;
}
static int inject(void* ctx, uint64_t chan, uint32_t audio, uint32_t video) {
  Callback cb;
  {
    std::lock_guard lock(callback_mu);
    cb = callbacks.at(chan);
  }
  const auto feed = [&](bool secondary, uint16_t seq) {
    std::array<uint8_t, 15> p{0x80, uint8_t(secondary ? 0xe0 : 111)};
    p[2] = seq >> 8; p[3] = seq;
    const uint32_t timestamp = seq * 960;
    const uint32_t ssrc = secondary ? video : audio;
    for (int i = 0; i < 4; ++i) {
      p[4+i] = timestamp >> (24-i*8);
      p[8+i] = ssrc >> (24-i*8);
    }
    // Opus silence; video uses a small invalid payload (decoder must drop it).
    p[12] = 0xf8; p[13] = 0xff; p[14] = 0xfe;
    cb.fn(cb.ctx, p.data(), p.size());
  };
  for (uint16_t i = 0; i < 20; ++i) feed(true, i);
  for (uint16_t i = 0; i < 4; ++i) feed(false, i);
  if (ctx) {
    const auto start = std::chrono::steady_clock::now();
    char* stats = veil_media_engine_get_stats(static_cast<VeilMediaEngine*>(ctx));
    const bool valid = stats && std::strstr(stats, "\"worker_stalled\":0") &&
                       std::strstr(stats, "\"video_worker_stalled\":1");
    std::free(stats);
    if (!valid || std::chrono::steady_clock::now() - start >
        std::chrono::milliseconds(250)) return 1;
  }
  return 0;
}
int main() {
  uint8_t local[32] = {1}, peer[32] = {2};
  {
    std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)> e(
        veil_media_engine_create(21, local, peer), veil_media_engine_destroy);
    assert(e);
    assert(veil_media_engine_set_mic_muted(e.get(), 1) == VEIL_MEDIA_OK);
    assert(veil_media_engine_start_audio(e.get(), 0, 1) == VEIL_MEDIA_OK);
    assert(veil_media_engine_start_video(e.get(), 0, 1, 150, 15) == VEIL_MEDIA_OK);
    const int result = veil_media_test_direct_call_planes(e.get(), inject, e.get());
    if (result) { std::fprintf(stderr, "direct isolation failed: %d\n", result); return 1; }
  }
  {
    std::unique_ptr<VeilGroupMediaEngine, decltype(&veil_media_group_engine_destroy)> e(
        veil_media_group_engine_create(local), veil_media_group_engine_destroy);
    assert(e);
    assert(veil_media_group_engine_set_mic_muted(e.get(), 1) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_add_peer(e.get(), 22, peer) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_start_audio(e.get()) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_start_video(e.get()) == VEIL_MEDIA_OK);
    const int result = veil_media_test_group_call_planes(e.get(), inject, nullptr);
    if (result) { std::fprintf(stderr, "group isolation failed: %d\n", result); return 2; }
    assert(veil_media_group_engine_remove_peer(e.get(), peer) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_add_peer(e.get(), 23, peer) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_stop_video(e.get()) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_stop_audio(e.get()) == VEIL_MEDIA_OK);
  }
  assert(callbacks.empty());
  std::puts("direct/group: Opus delivered with both video queues stalled; telemetry bounded; restart/teardown ok");
}
