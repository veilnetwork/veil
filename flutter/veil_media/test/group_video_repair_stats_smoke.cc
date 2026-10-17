// Real VP8 streams with a mocked plaintext Veil boundary. No SDK, network,
// hardware capture or profiles. Drop selected originals once and let native
// RTCP/NACK repair them; distinguish observed zero from unavailable statistics.
#include "veil_media_engine.h"
#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace {
struct Callback {
  void (*fn)(void*, const uint8_t*, size_t);
  void* ctx;
};
std::mutex boundary_mu;
std::map<uint64_t, Callback> callbacks;
std::set<std::pair<uint32_t, uint16_t>> dropped;
bool delivering = true, inject_loss = false;
uint64_t video_packets = 0;

int send(uint64_t channel, const uint8_t* packet, size_t size) {
  std::lock_guard lock(boundary_mu);
  const auto found = callbacks.find(channel == 101 ? 102 : 101);
  if (!delivering || found == callbacks.end()) return 1;
  if (channel == 101 && size >= 12 && (packet[1] & 127) == 96 && inject_loss) {
    const uint32_t ssrc = uint32_t(packet[8]) << 24 | uint32_t(packet[9]) << 16 |
                          uint32_t(packet[10]) << 8 | packet[11];
    const uint16_t sequence = uint16_t(packet[2]) << 8 | packet[3];
    // A repair of an already dropped packet is always admitted. Returning
    // success models network loss after native transport admission.
    if (++video_packets % 11 == 0 && dropped.insert({ssrc, sequence}).second)
      return 0;
  }
  found->second.fn(found->second.ctx, packet, size);
  return 0;
}

int64_t stat(VeilGroupMediaEngine* engine, const char* name) {
  char* json = veil_media_group_engine_get_stats(engine);
  assert(json);
  const std::string key = std::string("\"") + name + "\":";
  const char* at = std::strstr(json, key.c_str());
  assert(at);
  const int64_t value = std::strtoll(at + key.size(), nullptr, 10);
  veil_media_free_string(json);
  return value;
}

uint64_t hash(const std::vector<uint8_t>& bytes, int size) {
  uint64_t value = 14695981039346656037ULL;
  for (int i = 0; i < size; ++i) value = (value ^ bytes[i]) * 1099511628211ULL;
  return value;
}
}  // namespace

extern "C" int veil_media_send_datagram(uint64_t c, const uint8_t* p, size_t n) {
  return send(c, p, n);
}
extern "C" int veil_media_send_video_control_datagram(
    uint64_t c, const uint8_t* p, size_t n) {
  return send(c, p, n);
}
extern "C" int veil_media_set_recv_callback(
    uint64_t c, void (*fn)(void*, const uint8_t*, size_t), void* ctx) {
  std::lock_guard lock(boundary_mu);
  if (fn) callbacks[c] = {fn, ctx};
  else callbacks.erase(c);
  return 0;
}

int main() {
  setenv("VEIL_MEDIA_TEST_VIDEO", "1", 1);
  std::array<uint8_t, 32> a{31}, b{32};
  using Engine = std::unique_ptr<VeilGroupMediaEngine,
                                 decltype(&veil_media_group_engine_destroy)>;
  Engine x(veil_media_group_engine_create(a.data()), veil_media_group_engine_destroy);
  Engine y(veil_media_group_engine_create(b.data()), veil_media_group_engine_destroy);
  assert(x && y);
  assert(veil_media_group_engine_add_peer(x.get(), 101, b.data()) == 0);
  assert(veil_media_group_engine_add_peer(y.get(), 102, a.data()) == 0);
  assert(stat(x.get(), "video_tx_retransmitted_pkts") == -1);
  assert(veil_media_group_engine_set_video_budget(x.get(), 100, 15) == 0);
  assert(veil_media_group_engine_set_video_budget(y.get(), 100, 15) == 0);
  assert(veil_media_group_engine_start_video(x.get()) == 0);
  assert(veil_media_group_engine_start_video(y.get()) == 0);
  std::array<std::vector<uint8_t>, 2> images{
      std::vector<uint8_t>(640 * 480 * 4), std::vector<uint8_t>(640 * 480 * 4)};
  std::array<uint64_t, 2> previous{};
  int64_t repairs_after_loss = 0;
  for (int phase = 0; phase < 3; ++phase) {
    {
      std::lock_guard lock(boundary_mu);
      inject_loss = phase == 1;
    }
    std::array<int, 2> changes{};
    const auto start = std::chrono::steady_clock::now();
    const auto duration = std::chrono::seconds(phase == 1 ? 4 : 2);
    while (std::chrono::steady_clock::now() - start < duration) {
      for (int i = 0; i < 2; ++i) {
        int width = 0, height = 0;
        const int size = veil_media_group_engine_get_peer_video_frame(
            i == 0 ? x.get() : y.get(), i == 0 ? b.data() : a.data(),
            images[i].data(), images[i].size(), &width, &height);
        assert(size <= static_cast<int>(images[i].size()));
        if (size > 0) {
          const uint64_t value = hash(images[i], size);
          if (value != previous[i]) { ++changes[i]; previous[i] = value; }
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    assert(changes[0] > 0 && changes[1] > 0);
    const int64_t repairs = stat(x.get(), "video_tx_retransmitted_pkts");
    assert(repairs >= 0);
    assert(stat(y.get(), "video_tx_retransmitted_pkts") == 0);
    assert(stat(y.get(), "video_rx_nack_requests") == 0);
    if (phase == 0) {
      assert(repairs == 0);
      assert(stat(x.get(), "video_rx_nack_requests") == 0);
    } else {
      {
        std::lock_guard lock(boundary_mu);
        assert(!dropped.empty());
      }
      assert(repairs > 0 && repairs >= repairs_after_loss);
      assert(stat(x.get(), "video_tx_retransmitted_bytes") > 0);
      assert(stat(x.get(), "video_rx_nack_packets") > 0);
      assert(stat(x.get(), "video_rx_nack_requests") > 0);
      assert(stat(x.get(), "video_rx_unique_nack_requests") > 0);
      repairs_after_loss = repairs;
    }
    assert(stat(x.get(), "video_tx_key_frames") > 0);
    assert(stat(x.get(), "video_rx_pli_packets") >= 0);
    assert(stat(x.get(), "video_rx_fir_packets") >= 0);
    std::printf("phase=%d decoded_changes=%d/%d repairs=%lld\n", phase,
                changes[0], changes[1], static_cast<long long>(repairs));
  }
  {
    std::lock_guard lock(boundary_mu);
    delivering = false;
  }
  veil_media_group_engine_stop_video(x.get());
  veil_media_group_engine_stop_video(y.get());
  x.reset(); y.reset();
  std::lock_guard lock(boundary_mu);
  assert(callbacks.empty());
  std::puts("group video repair statistics and owned-engine cleanup OK");
}
