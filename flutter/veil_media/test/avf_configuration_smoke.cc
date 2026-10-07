// Real AVAudioEngine playout with silence. No network, identity or microphone.
#include "veil_media_engine.h"
#include <cassert>
#include <chrono>
#include <cstdio>
#include <memory>
#include <thread>
extern "C" int veil_media_test_avf_configuration_recovery(VeilMediaEngine*, int);
extern "C" void veil_media_set_recv_callback(uint64_t,
    void (*)(void*, const uint8_t*, size_t), void*) {}
extern "C" int veil_media_send_datagram(uint64_t, const uint8_t*, size_t) { return 0; }
extern "C" int veil_media_send_video_control_datagram(uint64_t, const uint8_t*, size_t) {
  return 0;
}
int main() {
  const uint8_t local[32] = {1}, peer[32] = {2};
  for (int pending_teardown : {0, 1}) {
    std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)> e(
        veil_media_engine_create(200 + pending_teardown, local, peer),
        veil_media_engine_destroy);
    assert(e);
    assert(veil_media_engine_set_mic_muted(e.get(), 1) == VEIL_MEDIA_OK);
    assert(veil_media_engine_start_audio(e.get(), 0, 1) == VEIL_MEDIA_OK);
    const int result = veil_media_test_avf_configuration_recovery(e.get(), pending_teardown);
    std::printf("AVAudioEngine configuration recovery pending_teardown=%d result=%d\n",
                pending_teardown, result);
    std::fflush(stdout);
    assert(result == 0);
    e.reset();
    // A queued notification must finish safely after its owner has been freed.
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
  }
}
