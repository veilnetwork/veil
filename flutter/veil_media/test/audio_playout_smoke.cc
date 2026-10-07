// Real Opus/NetEq and production Call wiring, synthetic ADM and plaintext
// Veil boundary. No physical microphone/speaker, app profile or relay is used.
#include "veil_media_engine.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
using Clock = std::chrono::steady_clock;
extern "C" VeilMediaEngine* veil_media_test_audio_playout_create(
    uint64_t, const uint8_t[32], const uint8_t[32], int, size_t);
extern "C" int veil_media_test_audio_capture_tone(VeilMediaEngine*, int);
extern "C" int veil_media_test_audio_playout_pcm(VeilMediaEngine*, int16_t*, size_t);
struct Callback { void (*fn)(void*, const uint8_t*, size_t); void* ctx; };
struct Packet { Clock::time_point due; std::vector<uint8_t> bytes; };
static std::mutex mu;
static std::map<uint64_t, Callback> callbacks;
static std::vector<Packet> pending;
static Clock::time_point origin;
static uint64_t source_channel = 0, receiver_channel = 0;
static size_t sent_packets = 0;
static double milliseconds(Clock::time_point t) {
  return std::chrono::duration<double, std::milli>(t - origin).count();
}
extern "C" void veil_media_set_recv_callback(uint64_t chan,
    void (*fn)(void*, const uint8_t*, size_t), void* ctx) {
  std::lock_guard lock(mu);
  if (fn) callbacks[chan] = {fn, ctx}; else callbacks.erase(chan);
}
extern "C" int veil_media_send_datagram(uint64_t chan, const uint8_t* p, size_t len) {
  std::lock_guard lock(mu);
  if (chan != source_channel || len < 12 || (p[1] & 0x7f) != 111) return 0;
  const auto now = Clock::now();
  const double at = milliseconds(now);
  // Reproducible short jitter bursts, then ten seconds of a recovered path.
  const int delay = at >= 2000 && at < 4000
      ? (static_cast<int>(at) / 200 % 2 ? 300 : 40) : 40;
  pending.push_back({now + std::chrono::milliseconds(delay), {p, p + len}});
  ++sent_packets;
  return 0;
}
extern "C" int veil_media_send_video_control_datagram(uint64_t,
    const uint8_t*, size_t) { return 0; }
static void deliver() {
  std::vector<Packet> ready;
  Callback callback{};
  {
    std::lock_guard lock(mu);
    callback = callbacks.at(receiver_channel);
    const auto now = Clock::now();
    for (auto it = pending.begin(); it != pending.end();) {
      if (it->due <= now) { ready.push_back(std::move(*it)); it = pending.erase(it); }
      else ++it;
    }
  }
  std::sort(ready.begin(), ready.end(), [](const auto& a, const auto& b) {
    return a.due < b.due;
  });
  for (const auto& p : ready) callback.fn(callback.ctx, p.bytes.data(), p.bytes.size());
}
static uint64_t metric(VeilMediaEngine* e, const char* name) {
  char* json = veil_media_engine_get_stats(e); assert(json);
  const auto key = std::string("\"") + name + "\":";
  const auto* at = std::strstr(json, key.c_str()); assert(at);
  const auto value = std::strtoull(at + key.size(), nullptr, 10);
  veil_media_free_string(json); return value;
}
int main() {
  const uint8_t local[32] = {1}, peer[32] = {2};
  for (size_t capacity : {size_t{30}, size_t{0}}) {
    {
      std::lock_guard lock(mu);
      pending.clear(); sent_packets = 0;
      source_channel = 200 + capacity; receiver_channel = 300 + capacity;
    }
    using Engine = std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)>;
    Engine receiver(veil_media_test_audio_playout_create(
        receiver_channel, peer, local, 0, capacity), veil_media_engine_destroy);
    Engine source(veil_media_test_audio_playout_create(
        source_channel, local, peer, 1, capacity), veil_media_engine_destroy);
    assert(source && receiver);
    {
      std::lock_guard lock(mu);
      origin = Clock::now();
    }
    std::vector<double> high_edges, source_edges;
    bool was_high = false;
    double max_tick_lateness = 0;
    uint64_t max_delay = 0, max_buffer = 0;
    size_t nonsilent_ticks = 0;
    std::array<int16_t, 480> pcm{};
    for (int tick = 0; tick < 1400; ++tick) {
      std::this_thread::sleep_until(origin + std::chrono::milliseconds(10 * tick));
      const double now = milliseconds(Clock::now());
      max_tick_lateness = std::max(max_tick_lateness, now - 10 * tick);
      const bool source_high = (tick / 100) % 2;
      if (source_high && tick % 100 == 0) source_edges.push_back(now);
      assert(veil_media_test_audio_capture_tone(source.get(), source_high ? 1200 : 440) == 0);
      deliver();
      const auto count = veil_media_test_audio_playout_pcm(receiver.get(), pcm.data(), pcm.size());
      assert(count == 480);
      int crossings = 0; double power = 0;
      for (size_t i = 0; i < pcm.size(); ++i) {
        power += static_cast<double>(pcm[i]) * pcm[i];
        if (i && ((pcm[i] > 0) != (pcm[i - 1] > 0))) ++crossings;
      }
      const bool nonsilent = power / pcm.size() > 500 * 500;
      if (nonsilent) ++nonsilent_ticks;
      const bool high = nonsilent && crossings >= 17;
      if (high && !was_high) high_edges.push_back(milliseconds(Clock::now()));
      was_high = high;
      if (tick % 10 == 0) {
        max_delay = std::max(max_delay, metric(receiver.get(), "audio_delay_ms"));
        max_buffer = std::max(max_buffer, metric(receiver.get(), "audio_jb_ms"));
      }
    }
    assert(max_tick_lateness < 30); // overloaded host invalidates the experiment
    size_t packet_count;
    { std::lock_guard lock(mu); packet_count = sent_packets; }
    assert(packet_count > 300 && nonsilent_ticks > 900);
    assert(metric(receiver.get(), "audio_rx_pkts") > 300);
    std::printf("{\"buffer_packets\":%zu,\"rtp_packets\":%zu,\"nonsilent_ticks\":%zu,"
                "\"max_tick_lateness_ms\":%.2f,\"max_filtered_delay_ms\":%llu,"
                "\"max_current_buffer_ms\":%llu,\"marker_latency_ms\":[",
        capacity ? capacity : 12, packet_count, nonsilent_ticks, max_tick_lateness,
        static_cast<unsigned long long>(max_delay), static_cast<unsigned long long>(max_buffer));
    for (size_t i = 0; i < source_edges.size(); ++i) {
      const auto edge = std::find_if(high_edges.begin(), high_edges.end(), [&](double at) {
        return at >= source_edges[i] && at < source_edges[i] + 800;
      });
      assert(edge != high_edges.end());
      const auto latency = *edge - source_edges[i];
      if (i == 2 || i == 3) { // 1 and 3 seconds after the path recovers
        if (capacity) assert(latency > 300); // old policy reproduced the tail
        // Includes the 40-ms network path and Opus packetization, on top of
        // the 180-ms receiver target. Actual PCM, not the filtered estimate.
        else assert(latency < 240);
      }
      if (i) std::printf(",");
      std::printf("%.2f", latency);
    }
    std::printf("],\"concealed_samples\":%llu,\"interruption_count\":%llu}\n",
        static_cast<unsigned long long>(metric(receiver.get(), "audio_concealed_samples")),
        static_cast<unsigned long long>(metric(receiver.get(), "audio_interruption_count")));
    std::fflush(stdout);
  }
}
