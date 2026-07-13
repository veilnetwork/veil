#include "../src/veil_media_engine.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <thread>

namespace {
std::atomic<int> registered_callbacks{0};
std::atomic<uint64_t> sent_datagrams{0};
}

extern "C" int veil_media_send_datagram(uint64_t, const uint8_t*, size_t) {
  sent_datagrams.fetch_add(1);
  return 0;
}

using VeilMediaRecvFn = void (*)(void*, const uint8_t*, size_t);
extern "C" int veil_media_set_recv_callback(uint64_t, VeilMediaRecvFn cb,
                                              void*) {
  registered_callbacks.fetch_add(cb == nullptr ? -1 : 1);
  return 0;
}

int main() {
  uint8_t local[32] = {1};
  uint8_t alice[32] = {2};
  uint8_t bob[32] = {3};
  VeilGroupMediaEngine* engine = veil_media_group_engine_create(local);
  if (engine == nullptr) return 1;
  if (veil_media_group_engine_add_peer(engine, 11, alice) != VEIL_MEDIA_OK)
    return 2;
  if (veil_media_group_engine_add_peer(engine, 12, bob) != VEIL_MEDIA_OK)
    return 3;
  if (registered_callbacks.load() != 2) return 4;
  if (veil_media_group_engine_set_mic_muted(engine, 1) != VEIL_MEDIA_OK)
    return 5;
  if (veil_media_group_engine_start_audio(engine) != VEIL_MEDIA_OK) return 6;
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  if (veil_media_group_engine_remove_peer(engine, alice) != VEIL_MEDIA_OK)
    return 7;
  if (veil_media_group_engine_add_peer(engine, 13, alice) != VEIL_MEDIA_OK)
    return 8;
  if (registered_callbacks.load() != 2) return 9;
  if (veil_media_group_engine_stop_audio(engine) != VEIL_MEDIA_OK) return 10;
  veil_media_group_engine_destroy(engine);
  if (registered_callbacks.load() != 0) return 11;
  std::printf("group-audio smoke ok; native datagrams=%llu\n",
              static_cast<unsigned long long>(sent_datagrams.load()));
  return 0;
}
