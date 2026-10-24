// No physical ADM/camera/network. Each fatal-baseline case runs separately.
#include "veil_media_engine.h"
#include <cstdio>
#include <cstring>

extern "C" int veil_media_test_destroy_with_held_worker(int, int);
extern "C" int veil_media_send_datagram(uint64_t, const uint8_t*, size_t) { return 0; }
extern "C" int veil_media_send_video_control_datagram(uint64_t, const uint8_t*, size_t) {
  return 0;
}
extern "C" int veil_media_set_recv_callback(
    uint64_t, void (*)(void*, const uint8_t*, size_t), void*) { return 0; }

int main(int argc, char** argv) {
  if (argc != 3 || (std::strcmp(argv[1], "direct") && std::strcmp(argv[1], "group")) ||
      (std::strcmp(argv[2], "audio") && std::strcmp(argv[2], "video"))) return 64;
  const int result = veil_media_test_destroy_with_held_worker(
      std::strcmp(argv[1], "group") == 0, std::strcmp(argv[2], "video") == 0);
  if (result) std::fprintf(stderr, "media destroy retry failed: %d\n", result);
  return result;
}
