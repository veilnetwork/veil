// Real Call/Opus stream lifecycle, fake ADM, no devices or network endpoints.
#include "veil_media_engine.h"
#include <cstdio>

extern "C" int veil_media_test_audio_stop_retry();
extern "C" int veil_media_send_datagram(uint64_t, const uint8_t*, size_t) { return 0; }
extern "C" int veil_media_send_video_control_datagram(uint64_t, const uint8_t*, size_t) {
  return 0;
}
extern "C" int veil_media_set_recv_callback(
    uint64_t, void (*)(void*, const uint8_t*, size_t), void*) { return 0; }

int main() {
  const int result = veil_media_test_audio_stop_retry();
  if (result) {
    std::fprintf(stderr, "audio stop retry failed: %d\n", result);
    return result;
  }
  std::puts("direct/group stop retries report stalled workers, remove live streams, "
            "and preserve restart and idempotence");
}
