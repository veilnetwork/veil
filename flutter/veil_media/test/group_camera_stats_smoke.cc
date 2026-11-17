/* SPDX-License-Identifier: MIT */
// C ABI smoke for a full media component. No physical capture, audio startup,
// peer, transport or GUI. Missing camera status must not masquerade as stopped.
#include "../src/veil_media_engine.h"

#include <cstdio>
#include <cstring>

extern "C" int veil_media_send_datagram(uint64_t, const uint8_t*, size_t) {
  return 0;
}
extern "C" int veil_media_send_video_control_datagram(
    uint64_t, const uint8_t*, size_t) {
  return 0;
}
using Recv = void (*)(void*, const uint8_t*, size_t);
extern "C" int veil_media_set_recv_callback(uint64_t, Recv, void*) { return 0; }

bool UnknownCamera(VeilGroupMediaEngine* engine) {
  char* stats = veil_media_group_engine_get_stats(engine);
  if (!stats) return false;
  const bool correct = std::strstr(stats, "\"camera_capturing\":-1,") != nullptr;
  veil_media_free_string(stats);
  return correct;
}

int main() {
  const uint8_t local[32] = {1};
  auto* engine = veil_media_group_engine_create(local);
  if (!engine) return 1;
  bool ok = UnknownCamera(engine);
  ok = (veil_media_group_engine_start_video(engine) == VEIL_MEDIA_OK) && ok;
  ok = UnknownCamera(engine) && ok;
  ok = (veil_media_group_engine_stop_camera(engine) == VEIL_MEDIA_OK) && ok;
  ok = UnknownCamera(engine) && ok;
  ok = (veil_media_group_engine_stop_video(engine) == VEIL_MEDIA_OK) && ok;
  ok = UnknownCamera(engine) && ok;
  veil_media_group_engine_destroy(engine);
  std::printf("group camera absence across video lifecycle: %s\n", ok ? "PASS" : "FAIL");
  return ok ? 0 : 2;
}
