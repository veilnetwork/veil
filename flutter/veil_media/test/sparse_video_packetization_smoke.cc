// Real Opus and VP8 through the public source APIs; no physical devices.
#include "veil_media_engine.h"
#include <array>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

extern "C" VeilMediaEngine* veil_media_test_adaptive_codec_create(
    uint64_t, const uint8_t*, const uint8_t*, int);
extern "C" int veil_media_test_audio_fixed_transport_budget(VeilMediaEngine*, int);
extern "C" int veil_media_test_audio_capture_tone(VeilMediaEngine*, int);
extern "C" int veil_media_test_audio_playout_pcm(VeilMediaEngine*, int16_t*, size_t);
struct Callback { void (*fn)(void*, const uint8_t*, size_t); void* ctx; };
struct Packet { std::chrono::steady_clock::time_point due; uint64_t chan; std::vector<uint8_t> bytes; };
std::mutex wire_mutex;
std::map<uint64_t, Callback> callbacks;
std::vector<Packet> wire;
extern "C" int veil_media_set_recv_callback(
    uint64_t chan, void (*fn)(void*, const uint8_t*, size_t), void* ctx) {
  std::lock_guard lock(wire_mutex);
  if (fn) callbacks[chan] = {fn, ctx}; else callbacks.erase(chan);
  return 0;
}
extern "C" int veil_media_send_datagram(uint64_t chan, const uint8_t* p, size_t size) {
  std::lock_guard lock(wire_mutex);
  wire.push_back({std::chrono::steady_clock::now() + std::chrono::milliseconds(20),
                 chan == 200 ? 300u : 200u, std::vector<uint8_t>(p, p + size)});
  return 0;
}
extern "C" int veil_media_send_video_control_datagram(
    uint64_t chan, const uint8_t* p, size_t size) {
  return veil_media_send_datagram(chan, p, size);
}
void deliver() {
  std::vector<Packet> ready;
  {
    std::lock_guard lock(wire_mutex);
    for (auto it = wire.begin(); it != wire.end();) {
      if (it->due <= std::chrono::steady_clock::now()) {
        ready.push_back(std::move(*it)); it = wire.erase(it);
      } else ++it;
    }
  }
  for (const auto& packet : ready) {
    Callback cb;
    { std::lock_guard lock(wire_mutex); cb = callbacks.at(packet.chan); }
    cb.fn(cb.ctx, packet.bytes.data(), packet.bytes.size());
  }
}

uint64_t metric(VeilMediaEngine* engine, const char* name) {
  char* json = veil_media_engine_get_stats(engine);
  assert(json);
  const std::string key = std::string("\"") + name + "\":";
  const char* at = std::strstr(json, key.c_str());
  assert(at); // Missing telemetry must fail, rather than silently read zero.
  const auto value = std::strtoull(at + key.size(), nullptr, 10);
  veil_media_free_string(json);
  return value;
}

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  const uint8_t local[32] = {1}, peer[32] = {2};
  std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)> engine(
      veil_media_test_adaptive_codec_create(200, local, peer, 209),
      veil_media_engine_destroy);
  assert(engine);
  std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)> receiver(
      veil_media_test_adaptive_codec_create(300, peer, local, 209),
      veil_media_engine_destroy);
  assert(receiver);
  auto* e = engine.get();
  assert(veil_media_test_audio_fixed_transport_budget(e, 48000) == 0);
  assert(veil_media_test_audio_fixed_transport_budget(receiver.get(), 48000) == 0);
  assert(veil_media_engine_start_video(receiver.get(), 0, 1, 30, 1) == 0);
  std::vector<uint8_t> y(320 * 240, 128), uv(320 * 240 / 4, 128);
  std::array<int16_t, 480> pcm{};
  const auto drive = [&](int ticks, bool video) {
    const auto start = std::chrono::steady_clock::now();
    for (int tick = 0; tick < ticks; ++tick) {
      std::this_thread::sleep_until(start + std::chrono::milliseconds(tick * 10));
      assert(veil_media_test_audio_capture_tone(e, 600) == 0);
      assert(veil_media_test_audio_capture_tone(receiver.get(), 900) == 0);
      deliver();
      assert(veil_media_test_audio_playout_pcm(e, pcm.data(), pcm.size()) == 480);
      assert(veil_media_test_audio_playout_pcm(receiver.get(), pcm.data(), pcm.size()) == 480);
      if (video) assert(veil_media_engine_push_video_frame(e,
          y.data(), uv.data(), uv.data(), 320, 240, 320, 160, 160, 0) == 0);
    }
  };
  for (int warm = 0; warm < 20 && metric(e, "audio_tx_packet_duration_ms") != 60; ++warm)
    drive(50, false);
  std::printf("audio warm-up: packet=%llu ms, bandwidth=%llu bps\n",
      static_cast<unsigned long long>(metric(e, "audio_tx_packet_duration_ms")),
      static_cast<unsigned long long>(metric(e, "audio_send_bandwidth_bps")));
  assert(metric(e, "audio_tx_packet_duration_ms") == 60);
  assert(veil_media_engine_start_video(e, 1, 0, 30, 1) == 0);
  drive(300, true);
  const auto first = metric(e, "video_tx_frames");
  std::printf("sparse source with real 60-ms Opus: %llu video frames\n",
              static_cast<unsigned long long>(first));
  assert(first >= 2 && first <= 4);
  assert(metric(receiver.get(), "video_rx_deliver_frames") >= 2);
  assert(metric(e, "audio_tx_packet_duration_ms") == 60);
  assert(metric(e, "audio_packetization_video_hold") == 0);
  assert(veil_media_engine_set_video_send_paused(e, 1) == 0);
  drive(30, true); // Drain a frame already handed to the asynchronous encoder.
  const auto paused = metric(e, "video_tx_frames");
  drive(150, true);
  assert(metric(e, "video_tx_frames") == paused);
  assert(veil_media_engine_set_video_send_paused(e, 0) == 0);
  drive(300, true);
  assert(metric(e, "video_tx_frames") >= paused + 2);
  assert(veil_media_engine_set_video_budget(e, 30, 3) == 0);
  drive(30, true);
  const auto held = metric(e, "video_tx_frames");
  drive(150, true);
  assert(metric(e, "video_tx_frames") == held);
  assert(metric(e, "audio_packetization_video_hold") == 1);
  assert(veil_media_engine_set_video_budget(e, 30, 1) == 0);
  drive(300, true);
  assert(metric(e, "video_tx_frames") >= held + 2);
  assert(metric(e, "audio_tx_packet_duration_ms") == 60);
  std::puts("sparse VP8 survives long Opus; explicit pause and larger-source protection retained");
}
