#include "veil_media_engine.h"
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cmath>
#include <limits>
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

using Injector = int (*)(void*, uint64_t, uint32_t, uint32_t);
extern "C" int veil_media_test_direct_call_planes(VeilMediaEngine*, Injector, void*);
extern "C" int veil_media_test_blocked_audio_stats(VeilMediaEngine*, Injector, void*);
extern "C" int veil_media_test_muted_capture_lifecycle();
extern "C" int veil_media_test_group_call_planes(VeilGroupMediaEngine*, Injector, void*);
extern "C" int veil_media_test_group_blocked_audio_stats(VeilGroupMediaEngine*, Injector, void*);
extern "C" int veil_media_test_group_emit_rtcp(VeilGroupMediaEngine*);
extern "C" int veil_media_test_group_fanout_packet(VeilGroupMediaEngine*, int);
extern "C" int veil_media_test_video_bandwidth(VeilMediaEngine*);
extern "C" int veil_media_test_direct_packet(VeilMediaEngine*, int);
extern "C" uint64_t veil_media_test_direct_encoded_frames(VeilMediaEngine*);
extern "C" int veil_media_test_pause_with_held_video_worker(VeilMediaEngine*, VeilGroupMediaEngine*);
struct Callback { void (*fn)(void*, const uint8_t*, size_t); void* ctx; };
static std::atomic<bool> hold_fanout_video{false};
static std::atomic<bool> fanout_video_entered{false};
static std::atomic<bool> fanout_audio_passed{false};
static std::mutex callback_mu;
static std::map<uint64_t, Callback> callbacks;
static std::map<uint64_t, std::set<std::pair<uint32_t, uint16_t>>> feedback;
static std::map<uint64_t, std::pair<uint32_t, uint32_t>> expected_ssrcs;
static std::map<uint64_t, std::vector<uint8_t>> playout_wire;
extern "C" int veil_media_send_datagram(uint64_t chan, const uint8_t* p, size_t len) {
  if (chan == 90 && len >= 12) {
    if ((p[1] & 0x7f) == 96 && hold_fanout_video.load()) {
      fanout_video_entered.store(true);
      while (hold_fanout_video.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } else if ((p[1] & 0x7f) == 111) {
      fanout_audio_passed.store(true);
    }
  }
  std::lock_guard lock(callback_mu);
  for (size_t offset = 0; offset + 4 <= len;) {
    const uint8_t* b = p + offset;
    const size_t size = 4 * (size_t(b[2]) * 256 + b[3] + 1);
    if ((b[0] >> 6) != 2 || size < 4 || size > len - offset) break;
    if (b[1] == 205 && (b[0] & 31) == 15 && size >= 20) {
      const uint32_t ssrc = uint32_t(b[8]) << 24 | uint32_t(b[9]) << 16 |
                            uint32_t(b[10]) << 8 | b[11];
      const uint16_t base = uint16_t(b[12]) << 8 | b[13];
      feedback[chan].insert({ssrc, base});
    }
    if (b[1] == 204 && size == 28 && std::memcmp(b + 8, "VAP1", 4) == 0)
      playout_wire[chan] = std::vector<uint8_t>(p, p + len);
    offset += size;
  }
  return 0;
}
extern "C" int veil_media_set_recv_callback(
    uint64_t chan, void (*cb)(void*, const uint8_t*, size_t), void* ctx) {
  std::lock_guard lock(callback_mu);
  if (cb) callbacks[chan] = {cb, ctx};
  else callbacks.erase(chan);
  return 0;
}
static uint64_t stat(VeilMediaEngine* engine, const char* name) {
  char* json = veil_media_engine_get_stats(engine);
  assert(json);
  const std::string key = std::string("\"") + name + "\":";
  const char* at = std::strstr(json, key.c_str());
  assert(at);
  const uint64_t value = std::strtoull(at + key.size(), nullptr, 10);
  std::free(json);
  return value;
}
static int inject(void* ctx, uint64_t chan, uint32_t audio, uint32_t video) {
  Callback cb;
  {
    std::lock_guard lock(callback_mu);
    cb = callbacks.at(chan);
    expected_ssrcs[chan] = {audio, video};
  }
  const auto feed = [&](bool secondary, uint16_t seq) {
    std::array<uint8_t, 23> p{0x90, uint8_t(secondary ? 0xe0 : 111)};
    p[2] = seq >> 8; p[3] = seq;
    const uint32_t timestamp = seq * 960;
    const uint32_t ssrc = secondary ? video : audio;
    for (int i = 0; i < 4; ++i) {
      p[4+i] = timestamp >> (24-i*8);
      p[8+i] = ssrc >> (24-i*8);
    }
    // Opus silence; video uses a small invalid payload (decoder must drop it).
    p[12] = 0xbe; p[13] = 0xde; p[14] = 0; p[15] = 1;
    p[16] = 0x11; // extension id 1, two-byte transport sequence
    const uint16_t transport_seq = (secondary ? 2000 : 1000) + seq;
    p[17] = transport_seq >> 8; p[18] = transport_seq; p[19] = 0;
    p[20] = 0xf8; p[21] = 0xff; p[22] = 0xfe;
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
    const auto retune_start = std::chrono::steady_clock::now();
    if (veil_media_engine_set_video_budget(
            static_cast<VeilMediaEngine*>(ctx), 2, 0.02) != VEIL_MEDIA_ERR_STATE ||
        std::chrono::steady_clock::now() - retune_start >
            std::chrono::milliseconds(250)) return 2;
  }
  return 0;
}
static int check_blocked_audio_stats(void* ctx, uint64_t, uint32_t, uint32_t) {
  const auto start = std::chrono::steady_clock::now();
  char* json = veil_media_engine_get_stats(static_cast<VeilMediaEngine*>(ctx));
  const auto elapsed = std::chrono::steady_clock::now() - start;
  const bool valid = json && std::strstr(json, "\"worker_stalled\":1") &&
                     std::strstr(json, "\"video_worker_stalled\":1") &&
                     std::strstr(json, "\"audio_rx_pkts\":0");
  std::free(json);
  std::fprintf(stderr, "blocked audio stats: %.1f ms\n",
               std::chrono::duration<double, std::milli>(elapsed).count());
  return valid && elapsed < std::chrono::milliseconds(250) ? 0 : 2;
}

static uint64_t group_stat(VeilGroupMediaEngine* engine, const char* name) {
  char* json = veil_media_group_engine_get_stats(engine);
  assert(json);
  const std::string key = std::string("\"") + name + "\":";
  const char* at = std::strstr(json, key.c_str());
  assert(at);
  const uint64_t value = std::strtoull(at + key.size(), nullptr, 10);
  veil_media_free_string(json);
  return value;
}
static int inject_group(void* ctx, uint64_t chan, uint32_t audio, uint32_t video) {
  if (inject(nullptr, chan, audio, video) != 0) return 1;
  auto* engine = static_cast<VeilGroupMediaEngine*>(ctx);
  const auto start = std::chrono::steady_clock::now();
  char* json = veil_media_group_engine_get_stats(engine);
  const bool valid = json && std::strstr(json, "\"worker_stalled\":0") &&
                     std::strstr(json, "\"video_worker_stalled\":1");
  veil_media_free_string(json);
  if (!valid || veil_media_group_engine_set_video_budget(engine, 8, 0.3) != VEIL_MEDIA_ERR_STATE)
    return 2;
  return std::chrono::steady_clock::now() - start < std::chrono::milliseconds(250) ? 0 : 3;
}
static int check_group_blocked_audio_stats(void* ctx, uint64_t, uint32_t, uint32_t) {
  const auto start = std::chrono::steady_clock::now();
  char* json = veil_media_group_engine_get_stats(static_cast<VeilGroupMediaEngine*>(ctx));
  const bool valid = json && std::strstr(json, "\"worker_stalled\":1") &&
                     std::strstr(json, "\"audio_rx_supported\":1") &&
                     std::strstr(json, "\"audio_receivers\":{}");
  veil_media_free_string(json);
  return valid && std::chrono::steady_clock::now() - start <
      std::chrono::milliseconds(250) ? 0 : 1;
}
static uint64_t group_audio_packets(VeilGroupMediaEngine* engine, const uint8_t peer[32]) {
  constexpr char hex[] = "0123456789abcdef";
  std::string id;
  for (size_t i = 0; i < 32; ++i) {
    id += hex[peer[i] >> 4]; id += hex[peer[i] & 15];
  }
  char* json = veil_media_group_engine_get_stats(engine);
  assert(json && std::strstr(json, "\"audio_rx_supported\":1"));
  const auto prefix = "\"" + id + "\":{\"audio_rx_pkts\":";
  const char* at = std::strstr(json, prefix.c_str());
  assert(at);
  const auto packets = std::strtoull(at + prefix.size(), nullptr, 10);
  veil_media_free_string(json);
  return packets;
}
static void inject_non_audio(uint64_t chan, uint32_t audio, uint32_t video) {
  Callback cb;
  { std::lock_guard lock(callback_mu); cb = callbacks.at(chan); }
  for (const uint32_t source : {audio ^ 1u, video}) {
    for (uint16_t seq = 20; seq < 40; ++seq) {
      std::array<uint8_t, 15> p{0x80, uint8_t(source == video ? 96 : 111)};
      p[2] = seq >> 8; p[3] = seq;
      for (int i = 0; i < 4; ++i) {
        p[4 + i] = (uint32_t(seq) * 960) >> (24 - i * 8);
        p[8 + i] = source >> (24 - i * 8);
      }
      p[12] = 0xf8; p[13] = 0xff; p[14] = 0xfe;
      cb.fn(cb.ctx, p.data(), p.size());
    }
  }
}
static uint32_t group_ssrc(const uint8_t id[32], uint32_t domain = 0x47415544u) {
  uint32_t hash = 2166136261u;
  for (size_t i = 0; i < 32; ++i) { hash ^= id[i]; hash *= 16777619u; }
  hash ^= domain;
  return hash == 0 ? 1 : hash;
}
static void report(uint64_t chan, uint32_t reporter, uint32_t source,
                   uint8_t lost, uint32_t jitter) {
  std::array<uint8_t, 32> packet{0x81, 201, 0, 7};
  const auto word = [&](size_t at, uint32_t value) {
    for (int i = 0; i < 4; ++i) packet[at+i] = value >> (24-i*8);
  };
  word(4, reporter); word(8, source); packet[12] = lost;
  word(16, 100); word(20, jitter);
  Callback callback;
  { std::lock_guard lock(callback_mu); callback = callbacks.at(chan); }
  callback.fn(callback.ctx, packet.data(), packet.size());
}
static void inject_raw(uint64_t chan, const std::vector<uint8_t>& packet) {
  Callback cb;
  { std::lock_guard lock(callback_mu); cb = callbacks.at(chan); }
  cb.fn(cb.ctx, packet.data(), packet.size());
}
static std::vector<uint8_t> playout_report(uint32_t target, uint64_t seq,
                                          uint32_t delay) {
  std::vector<uint8_t> p(36);
  p[0] = 0x80; p[1] = 201; p[3] = 1;  // original empty RR
  p[8] = 0x80; p[9] = 204; p[11] = 6;
  std::memcpy(p.data() + 16, "VAP1", 4);
  const auto word = [&](size_t at, uint32_t value) {
    for (int i = 0; i < 4; ++i) p[at + i] = value >> (24 - i * 8);
  };
  word(20, target); word(24, static_cast<uint32_t>(seq >> 32));
  word(28, static_cast<uint32_t>(seq)); word(32, delay);
  return p;
}
static void wait_playout(VeilGroupMediaEngine* e, uint64_t reports, uint64_t delay) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while ((group_stat(e, "audio_playout_reports") != reports ||
          (reports && group_stat(e, "audio_playout_ms") != delay)) &&
         std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  assert(group_stat(e, "audio_playout_reports") == reports);
  if (reports) assert(group_stat(e, "audio_playout_ms") == delay);
}
int main() {
  const int capture_result = veil_media_test_muted_capture_lifecycle();
  if (capture_result != 0) {
    std::fprintf(stderr, "muted capture lifecycle failed: %d\n", capture_result);
    return 1;
  }
  std::fprintf(stderr, "direct/group: muted start/rebuild opens no capture; unmute encodes Opus\n");
  uint8_t local[32] = {1}, peer[32] = {2};
  for (int enabled : {0, 1}) {
    const uint64_t chan = 21 + enabled;
    std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)> e(
        veil_media_engine_create(chan, local, peer), veil_media_engine_destroy);
    assert(e);
    assert(veil_media_engine_set_independent_transport_feedback(e.get(), enabled) == VEIL_MEDIA_OK);
    assert(veil_media_engine_set_mic_muted(e.get(), 1) == VEIL_MEDIA_OK);
    assert(veil_media_engine_start_audio(e.get(), 0, 1) == VEIL_MEDIA_OK);
    assert(veil_media_engine_start_video(e.get(), 1, 1, 150, 15) == VEIL_MEDIA_OK);
    const int result = veil_media_test_direct_call_planes(e.get(), inject, e.get());
    if (result) { std::fprintf(stderr, "direct isolation failed: %d\n", result); return 1; }
    if (veil_media_test_blocked_audio_stats(e.get(), check_blocked_audio_stats, e.get()) != 0) {
      std::fprintf(stderr, "audio statistics blocked the host control loop\n");
      return 1;
    }
    // Shim ingress includes video/RTCP; the new counter counts only packets
    // accepted by the real audio receive stream. A blocked sample above must
    // report unknown via worker_stalled rather than reuse a cached success.
    assert(stat(e.get(), "audio_rx_pkts") == 4);
    assert(stat(e.get(), "rx_pkts") > stat(e.get(), "audio_rx_pkts"));
    const auto age_before = stat(e.get(), "audio_rx_native_age_ms");
    assert(age_before >= 0 && age_before < 10000);
    const auto wait_started = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(160));
    // RTCP arriving during the gap must not reset the audio RTP timestamp.
    report(chan, 2, 1, 0, 0);
    assert(stat(e.get(), "audio_rx_pkts") == 4);
    const auto age_after = stat(e.get(), "audio_rx_native_age_ms");
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - wait_started).count();
    assert(age_after >= age_before + 150);
    assert(age_after <= age_before + elapsed_ms + 100);
    // The abandoned retune must not run after the held queue is released.
    // An explicit retry may then update both bitrate and source cadence.
    assert(stat(e.get(), "max_fps") == 15);
    assert(stat(e.get(), "target_bitrate_bps") == 150000);
    assert(veil_media_engine_set_video_bitrate(e.get(), 45, 2) == VEIL_MEDIA_OK);
    assert(stat(e.get(), "max_fps") == 2);
    assert(stat(e.get(), "target_bitrate_bps") == 45000);
    assert(veil_media_engine_set_video_bitrate(e.get(), 150, 15) == VEIL_MEDIA_OK);
    assert(veil_media_engine_set_independent_transport_feedback(e.get(), !enabled) == VEIL_MEDIA_ERR_STATE);
    bool audio_feedback = false, video_feedback = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    do {
      {
        std::lock_guard lock(callback_mu);
        const auto [audio, video] = expected_ssrcs.at(chan);
        for (const auto& [ssrc, base] : feedback[chan]) {
          audio_feedback |= ssrc == audio && base >= 1000 && base < 1004;
          video_feedback |= ssrc == video && base >= 2000 && base < 2020;
        }
      }
      if (enabled && audio_feedback && video_feedback) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    } while (std::chrono::steady_clock::now() < deadline);
    if (enabled) {
      assert(audio_feedback && video_feedback);
    } else {
      std::lock_guard lock(callback_mu);
      assert(feedback[chan].empty());
    }
  }
  {
    std::unique_ptr<VeilGroupMediaEngine, decltype(&veil_media_group_engine_destroy)> e(
        veil_media_group_engine_create(local), veil_media_group_engine_destroy);
    assert(e);
    assert(veil_media_group_engine_set_mic_muted(e.get(), 1) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_add_peer(e.get(), 22, peer) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_start_audio(e.get()) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_start_video(e.get()) == VEIL_MEDIA_OK);
    const int result = veil_media_test_group_call_planes(e.get(), inject_group, e.get());
    if (result) { std::fprintf(stderr, "group isolation failed: %d\n", result); return 2; }
    assert(group_audio_packets(e.get(), peer) == 4);
    assert(veil_media_group_engine_peer_rx_packets(e.get(), peer) > 4);
    std::unique_ptr<VeilGroupMediaEngine, decltype(&veil_media_group_engine_destroy)> receiver(
        veil_media_group_engine_create(peer), veil_media_group_engine_destroy);
    assert(receiver);
    assert(veil_media_group_engine_set_mic_muted(receiver.get(), 1) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_add_peer(receiver.get(), 24, local) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_start_audio(receiver.get()) == VEIL_MEDIA_OK);
    assert(group_stat(receiver.get(), "audio_playout_peers") == 0); // legacy starts unknown
    assert(veil_media_test_group_emit_rtcp(e.get()) == 0);
    std::vector<uint8_t> measured;
    { std::lock_guard lock(callback_mu); measured = playout_wire.at(22); }
    assert(measured.size() >= 28);
    const size_t delay_at = measured.size() - 4;
    const uint32_t measured_delay = uint32_t(measured[delay_at]) << 24 |
        uint32_t(measured[delay_at + 1]) << 16 | uint32_t(measured[delay_at + 2]) << 8 |
        measured[delay_at + 3];
    assert(measured_delay <= 60000); // measured from real accepted Opus
    inject_raw(24, measured);
    wait_playout(receiver.get(), 1, measured_delay);
    assert(group_stat(receiver.get(), "audio_playout_peers") == 1);
    inject_non_audio(22, group_ssrc(peer), group_ssrc(peer, 0x47564944u));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(group_audio_packets(e.get(), peer) == 4);
    assert(veil_media_test_group_blocked_audio_stats(
        e.get(), check_group_blocked_audio_stats, e.get()) == 0);
    assert(veil_media_test_group_emit_rtcp(e.get()) == 0);
    std::vector<uint8_t> unknown;
    { std::lock_guard lock(callback_mu); unknown = playout_wire.at(22); }
    inject_raw(24, unknown);
    wait_playout(receiver.get(), 0, 0);
    inject_raw(24, measured); // replay cannot restore a superseded measurement
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(group_stat(receiver.get(), "audio_playout_reports") == 0);
    assert(group_stat(receiver.get(), "audio_playout_peers") == 1);
    assert(group_audio_packets(e.get(), peer) == 4);
    assert(veil_media_group_engine_remove_peer(e.get(), peer) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_add_peer(e.get(), 23, peer) == VEIL_MEDIA_OK);
    assert(group_audio_packets(e.get(), peer) == 0);
    assert(veil_media_group_engine_stop_video(e.get()) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_stop_audio(e.get()) == VEIL_MEDIA_OK);
  }
  {
    std::unique_ptr<VeilGroupMediaEngine, decltype(&veil_media_group_engine_destroy)> e(
        veil_media_group_engine_create(local), veil_media_group_engine_destroy);
    assert(e);
    assert(veil_media_group_engine_set_mic_muted(e.get(), 1) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_add_peer(e.get(), 125, peer) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_start_audio(e.get()) == VEIL_MEDIA_OK);
    const uint32_t target = group_ssrc(local);
    // Wrong target, invalid delay, malformed compound and unsupported subtype
    // must not advertise support or manufacture healthy estimates.
    inject_raw(125, playout_report(target ^ 1u, 1, 150));
    inject_raw(125, playout_report(target, 2, 60001));
    auto malformed = playout_report(target, 3, 150); malformed.push_back(0);
    inject_raw(125, malformed);
    auto subtype = playout_report(target, 4, 150); subtype[8] = 0x81;
    inject_raw(125, subtype);
    auto old_app = playout_report(target, 5, 150); old_app[19] = '2';
    inject_raw(125, old_app);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(group_stat(e.get(), "audio_playout_peers") == 0);
    constexpr uint64_t sequence = 0x100000010ull;
    inject_raw(125, playout_report(target, sequence, 450));
    wait_playout(e.get(), 1, 450);
    inject_raw(125, playout_report(target, sequence, 0));
    inject_raw(125, playout_report(target, sequence - 1, 0));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(group_stat(e.get(), "audio_playout_ms") == 450);
    inject_raw(125, playout_report(target, sequence + 1, UINT32_MAX));
    wait_playout(e.get(), 0, 0);
    assert(group_stat(e.get(), "audio_playout_peers") == 1);
    inject_raw(125, playout_report(target, sequence + 2, 140));
    wait_playout(e.get(), 1, 140);
    const auto received = std::chrono::steady_clock::now();
    std::this_thread::sleep_until(received + std::chrono::seconds(6));
    inject_raw(125, playout_report(target, sequence + 2, 140));
    std::this_thread::sleep_until(received + std::chrono::milliseconds(12100));
    assert(group_stat(e.get(), "audio_playout_reports") == 0);
    assert(group_stat(e.get(), "audio_playout_peers") == 1);
    assert(veil_media_group_engine_remove_peer(e.get(), peer) == VEIL_MEDIA_OK);
    assert(group_stat(e.get(), "audio_playout_peers") == 0);
    std::puts("group playout: real receive sample/unknown worker, target binding, replay and expiry verified");
  }
  {
    const uint64_t chan = 60;
    std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)> e(
        veil_media_engine_create(chan, local, peer), veil_media_engine_destroy);
    assert(e);
    assert(veil_media_engine_set_mic_muted(e.get(), 1) == VEIL_MEDIA_OK);
    assert(veil_media_engine_start_audio(e.get(), 1, 1) == VEIL_MEDIA_OK);
    assert(stat(e.get(), "audio_feedback_reports") == 0);
    // A video report must not create an audio-quality measurement.
    constexpr uint32_t local_audio = 0x01000000u, peer_audio = 0x02000000u;
    report(chan, peer_audio, local_audio ^ 0x000000FFu ^ 0x56440000u, 255, 900000);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(stat(e.get(), "audio_feedback_reports") == 0);
    const auto report_time = std::chrono::steady_clock::now();
    report(chan, peer_audio, local_audio, 32, 4800);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (stat(e.get(), "audio_feedback_reports") == 0 && std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    assert(stat(e.get(), "audio_feedback_reports") == 1);
    assert(stat(e.get(), "audio_rx_pkts") == 0);  // reports are not received audio

    assert(stat(e.get(), "tx_loss_pct") == 13);
    assert(stat(e.get(), "tx_jitter_ms") == 100);
    // Cached WebRTC values can outlive the last peer report. The explicit
    // freshness flag must expire instead of turning their zeros into health.
    std::this_thread::sleep_until(report_time + std::chrono::milliseconds(15500));
    assert(stat(e.get(), "audio_feedback_reports") == 0);
    assert(stat(e.get(), "tx_loss_pct") == 0);
    assert(stat(e.get(), "tx_jitter_ms") == 0);
    std::printf("unicast audio feedback: absent, video-only, fresh RR and expired RR verified\n");
  }
  setenv("VEIL_MEDIA_TEST_VIDEO", "1", 1);
  for (int enabled : {0, 1}) {
    std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)> e(
        veil_media_engine_create(50 + enabled, local, peer), veil_media_engine_destroy);
    assert(e);
    assert(veil_media_engine_set_independent_transport_feedback(e.get(), enabled) == VEIL_MEDIA_OK);
    assert(veil_media_engine_start_video(e.get(), 1, 0, 150, 15) == VEIL_MEDIA_OK);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    int before = 0;
    while (before == 0 && std::chrono::steady_clock::now() < deadline) {
      before = veil_media_test_video_bandwidth(e.get());
      assert(before >= 0);
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    assert(before > 0 && before <= 200000);
    assert(veil_media_engine_set_video_bitrate(e.get(), 900, 15) == VEIL_MEDIA_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    const int after = veil_media_test_video_bandwidth(e.get());
    std::printf("video estimate enabled=%d: %d -> %d after 900-kbit profile\n", enabled, before, after);
    if (enabled) assert(after > 0 && after <= 200000);
    else assert(after >= 900000);
  }
  {
    std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)> e(
        veil_media_engine_create(70, local, peer), veil_media_engine_destroy);
    assert(e);
    assert(veil_media_engine_start_video(e.get(), 1, 0, 150, 2) == VEIL_MEDIA_OK);
    assert(stat(e.get(), "max_fps") == 2);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto before = stat(e.get(), "video_tx_frames");
    std::this_thread::sleep_for(std::chrono::milliseconds(2200));
    const auto low = stat(e.get(), "video_tx_frames") - before;
    assert(low >= 1 && low <= 6);
    assert(veil_media_engine_set_video_bitrate(e.get(), 150, 12) == VEIL_MEDIA_OK);
    assert(stat(e.get(), "max_fps") == 12);
    const auto recovered_start = stat(e.get(), "video_tx_frames");
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    const auto recovered = stat(e.get(), "video_tx_frames") - recovered_start;
    assert(recovered >= 8);
    assert(veil_media_engine_set_video_bitrate(e.get(), 150, 1) == VEIL_MEDIA_OK);
    assert(stat(e.get(), "max_fps") == 1);
    // Encoder reconfigure is asynchronous; exclude work queued at 12 fps.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto floor_start = stat(e.get(), "video_tx_frames");
    std::this_thread::sleep_for(std::chrono::milliseconds(2200));
    const auto floor = stat(e.get(), "video_tx_frames") - floor_start;
    assert(floor >= 1 && floor <= 3);
    std::printf("actual encoded video frames: 2-fps=%llu/2.2s, recovered=%llu/1.2s, 1-fps=%llu/2.2s\n",
        static_cast<unsigned long long>(low), static_cast<unsigned long long>(recovered),
        static_cast<unsigned long long>(floor));
  }
  {
    uint8_t other[32] = {3};
    std::unique_ptr<VeilGroupMediaEngine, decltype(&veil_media_group_engine_destroy)> e(
        veil_media_group_engine_create(local), veil_media_group_engine_destroy);
    assert(e);
    assert(veil_media_group_engine_set_mic_muted(e.get(), 1) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_add_peer(e.get(), 80, peer) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_add_peer(e.get(), 81, other) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_start_audio(e.get()) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_start_video(e.get()) == VEIL_MEDIA_OK);
    // No audio feedback exists yet: do not fill the route with video first.
    assert(group_stat(e.get(), "max_fps") == 1);
    assert(group_stat(e.get(), "video_kbps") == 30);
    const auto report_time = std::chrono::steady_clock::now();
    // The good participant's later RR must not hide the bad participant.
    report(80, group_ssrc(peer), group_ssrc(local), 32, 4800);
    report(81, group_ssrc(other), group_ssrc(local), 0, 48);
    // A video report cannot inflate the audio quality sample.
    report(81, group_ssrc(other, 0x47564944u), group_ssrc(local, 0x47564944u), 255, 900000);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (group_stat(e.get(), "audio_feedback_reports") != 2 && std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    assert(group_stat(e.get(), "audio_feedback_reports") == 2);
    assert(group_stat(e.get(), "tx_loss_pct") == 13);
    assert(group_stat(e.get(), "tx_jitter_ms") == 100);
    inject_raw(80, playout_report(group_ssrc(local), 1, 400));
    inject_raw(81, playout_report(group_ssrc(local), 1, 120));
    wait_playout(e.get(), 2, 400);
    assert(group_stat(e.get(), "audio_playout_peers") == 2);
    inject_raw(80, playout_report(group_ssrc(local), 2, UINT32_MAX));
    wait_playout(e.get(), 1, 120);
    assert(group_stat(e.get(), "audio_playout_peers") == 2);
    // Audio and video report blocks do not count as accepted audio. One
    // participant's accepted packets cannot keep another participant alive.
    assert(group_audio_packets(e.get(), peer) == 0);
    assert(group_audio_packets(e.get(), other) == 0);
    assert(inject(nullptr, 80, group_ssrc(peer), group_ssrc(peer, 0x47564944u)) == 0);
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (group_audio_packets(e.get(), peer) != 4 && std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    assert(group_audio_packets(e.get(), peer) == 4);
    assert(group_audio_packets(e.get(), other) == 0);
    assert(veil_media_group_engine_set_video_bitrate(e.get(), 45, 2) == VEIL_MEDIA_OK);
    assert(group_stat(e.get(), "max_fps") == 2);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto before = group_stat(e.get(), "video_tx_frames");
    std::this_thread::sleep_for(std::chrono::milliseconds(2200));
    const auto low = group_stat(e.get(), "video_tx_frames") - before;
    assert(low >= 1 && low <= 6);
    assert(veil_media_group_engine_set_video_bitrate(e.get(), 150, 12) == VEIL_MEDIA_OK);
    // Reconfigure is asynchronous inside WebRTC; let earlier encoder work
    // drain before measuring the steady capture cadence of the new target.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto recovered_start = group_stat(e.get(), "video_tx_frames");
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    const auto recovered = group_stat(e.get(), "video_tx_frames") - recovered_start;
    assert(recovered >= 8);
    assert(veil_media_group_engine_set_video_bitrate(e.get(), 30, 1) == VEIL_MEDIA_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto floor_start = group_stat(e.get(), "video_tx_frames");
    std::this_thread::sleep_for(std::chrono::milliseconds(2200));
    const auto floor = group_stat(e.get(), "video_tx_frames") - floor_start;
    assert(floor >= 1 && floor <= 3);
    std::printf("group actual encoded frames: 2-fps=%llu/2.2s, 12-fps=%llu/1.2s, 1-fps=%llu/2.2s\n",
        static_cast<unsigned long long>(low), static_cast<unsigned long long>(recovered),
        static_cast<unsigned long long>(floor));
    // No repeated reports were injected. Cached poor quality must expire.
    std::this_thread::sleep_until(report_time + std::chrono::milliseconds(15500));
    assert(group_stat(e.get(), "audio_feedback_reports") == 0);
    assert(veil_media_group_engine_stop_video(e.get()) == VEIL_MEDIA_OK);
    assert(veil_media_group_engine_set_video_bitrate(e.get(), 150, 15) == VEIL_MEDIA_ERR_STATE);
  }
  // Same real source gate for unicast and room capture. Keep bitrate high
  // while testing cadence, so codec starvation cannot make this pass falsely.
  for (bool room : {false, true}) {
    std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)> one(
        room ? nullptr : veil_media_engine_create(71, local, peer), veil_media_engine_destroy);
    std::unique_ptr<VeilGroupMediaEngine, decltype(&veil_media_group_engine_destroy)> group(
        room ? veil_media_group_engine_create(local) : nullptr, veil_media_group_engine_destroy);
    if (room) {
      assert(group);
      assert(veil_media_group_engine_add_peer(group.get(), 82, peer) == VEIL_MEDIA_OK);
      assert(veil_media_group_engine_set_mic_muted(group.get(), 1) == VEIL_MEDIA_OK);
      assert(veil_media_group_engine_start_audio(group.get()) == VEIL_MEDIA_OK);
      assert(veil_media_group_engine_start_video(group.get()) == VEIL_MEDIA_OK);
    } else {
      assert(one);
      assert(veil_media_engine_start_audio(one.get(), 0, 1) == VEIL_MEDIA_OK);
      assert(veil_media_engine_start_video(one.get(), 1, 1, 150, 15) == VEIL_MEDIA_OK);
    }
    const auto budget = [&](int kbps, double fps) {
      return room ? veil_media_group_engine_set_video_budget(group.get(), kbps, fps)
                  : veil_media_engine_set_video_budget(one.get(), kbps, fps);
    };
    const auto metric = [&](const char* name) {
      return room ? group_stat(group.get(), name) : stat(one.get(), name);
    };
    const auto fps = [&] {
      char* json = room ? veil_media_group_engine_get_stats(group.get())
                        : veil_media_engine_get_stats(one.get());
      assert(json);
      const char* at = std::strstr(json, "\"max_fps\":");
      assert(at);
      const double value = std::strtod(at + std::strlen("\"max_fps\":"), nullptr);
      veil_media_free_string(json);
      return value;
    };
    assert(budget(150, 12) == VEIL_MEDIA_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto initial = metric("video_tx_frames");
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    assert(metric("video_tx_frames") - initial >= 8);
    const auto pause = [&](int value) {
      return room ? veil_media_group_engine_set_video_send_paused(group.get(), value)
                  : veil_media_engine_set_video_send_paused(one.get(), value);
    };
    assert(pause(2) == VEIL_MEDIA_ERR_ARG);
    assert(veil_media_test_pause_with_held_video_worker(one.get(), group.get()) == 0);
    assert(metric("video_send_paused") == 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto paused_frames = metric("video_tx_frames");
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    assert(metric("video_tx_frames") == paused_frames);
    // Sending remains closed even for video already encoded by the pacer.
    assert((room ? veil_media_test_group_fanout_packet(group.get(), 1)
                 : veil_media_test_direct_packet(one.get(), 1)) == 1);
    assert((room ? veil_media_test_group_fanout_packet(group.get(), 0)
                 : veil_media_test_direct_packet(one.get(), 0)) == 0);
    assert((room ? veil_media_test_group_emit_rtcp(group.get())
                 : veil_media_test_direct_packet(one.get(), 2)) == 0);
    // Resume is retried after the held worker was released; recovery keeps
    // the same streams/SSRCs and generates a fresh keyframe.
    auto resume_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (pause(0) != VEIL_MEDIA_OK && std::chrono::steady_clock::now() < resume_deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    assert(metric("video_send_paused") == 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto after_resume = metric("video_tx_frames");
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    assert(metric("video_tx_frames") - after_resume >= 8);
    assert(pause(1) == VEIL_MEDIA_OK);
    assert(budget(150, 0.02) == VEIL_MEDIA_OK);
    assert(std::abs(fps() - 0.02) < 0.0001);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto sparse_start = metric("video_tx_frames");
    std::this_thread::sleep_for(std::chrono::milliseconds(2200));
    assert(metric("video_tx_frames") == sparse_start);

    // Cadence gate must not freeze self-preview. Feed two visibly different
    // local frames before the next 50-second encoder slot, then pull RGBA.
    std::array<uint8_t, 16 * 16> y;
    std::array<uint8_t, 8 * 8> uv;
    std::array<uint8_t, 16 * 16 * 4> preview;
    uv.fill(128);
    uint8_t first_pixel = 0;
    for (int brightness : {32, 220}) {
      y.fill(static_cast<uint8_t>(brightness));
      const int pushed = room
          ? veil_media_group_engine_push_video_frame(group.get(), y.data(), uv.data(), uv.data(),
                16, 16, 16, 8, 8, 0)
          : veil_media_engine_push_video_frame(one.get(), y.data(), uv.data(), uv.data(),
                16, 16, 16, 8, 8, 0);
      assert(pushed == VEIL_MEDIA_OK);
      int width = 0, height = 0;
      const int got = room
          ? veil_media_group_engine_get_local_video_frame(group.get(), preview.data(), preview.size(), &width, &height)
          : veil_media_engine_get_local_video_frame(one.get(), preview.data(), preview.size(), &width, &height);
      assert(got > 0 && width == 16 && height == 16);
      if (brightness == 32) first_pixel = preview[0];
      else assert(preview[0] > first_pixel + 100);
    }
    assert(inject(nullptr, room ? 82 : 71,
        room ? group_ssrc(peer) : 0x02000000u,
        room ? group_ssrc(peer, 0x47564944u) : (0x02000000u ^ 0x000000FFu ^ 0x56440000u)) == 0);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while ((room ? group_audio_packets(group.get(), peer) : metric("audio_rx_pkts")) != 4 &&
           std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    assert((room ? group_audio_packets(group.get(), peer) : metric("audio_rx_pkts")) == 4);

    assert(pause(0) == VEIL_MEDIA_OK);
    // The portable Android420 push has its own conversion branch. A closed
    // RTP gate alone must not hide continuing expensive encoder work.
    if (!room) {
      assert(pause(1) == VEIL_MEDIA_OK);
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      const auto encoded = veil_media_test_direct_encoded_frames(one.get());
      for (int i = 0; i < 30; ++i) {
        assert(veil_media_engine_push_android420_frame(one.get(), y.data(), uv.data(), uv.data(),
            16, 16, 16, 8, 8, 1, 0, 0) == VEIL_MEDIA_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      assert(veil_media_test_direct_encoded_frames(one.get()) == encoded);
      assert(pause(0) == VEIL_MEDIA_OK);
    }
    assert(budget(8, 0.3) == VEIL_MEDIA_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    assert(metric(room ? "video_kbps" : "target_bitrate_bps") == (room ? 8 : 8000));
    const auto allocated = metric("video_encoder_target_bps");
    std::printf("low-rate %s: encoder target=%llu bps, cadence=%.3f fps\n",
        room ? "room" : "unicast", static_cast<unsigned long long>(allocated), fps());
    assert(allocated > 0 && allocated <= 8000);
    assert(std::abs(fps() - 0.3) < 0.0001);
    assert(budget(1, 0.02) == VEIL_MEDIA_OK);
    assert(metric(room ? "video_kbps" : "target_bitrate_bps") == (room ? 1 : 1000));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto minimum_allocated = metric("video_encoder_target_bps");
    assert(minimum_allocated > 0 && minimum_allocated <= 1000);
    assert(budget(8, 0) == VEIL_MEDIA_ERR_ARG);
    assert(budget(8, -1) == VEIL_MEDIA_ERR_ARG);
    assert(budget(0, 0.3) == VEIL_MEDIA_ERR_ARG);
    assert(budget(8, std::numeric_limits<double>::quiet_NaN()) == VEIL_MEDIA_ERR_ARG);
    assert(budget(8, std::numeric_limits<double>::infinity()) == VEIL_MEDIA_ERR_ARG);
    assert(std::abs(fps() - 0.02) < 0.0001);
    assert(budget(150, 12) == VEIL_MEDIA_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto resumed = metric("video_tx_frames");
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    assert(metric("video_tx_frames") - resumed >= 8);
    // An old zero/default integer call must still mean 150 kbit/s, 15 fps.
    assert((room ? veil_media_group_engine_set_video_bitrate(group.get(), 0, 0)
                 : veil_media_engine_set_video_bitrate(one.get(), 0, 0)) == VEIL_MEDIA_OK);
    assert(fps() == 15);
    std::printf("low-rate %s: actual sparse encoding, fresh preview, accepted audio, recovery and legacy defaults verified\n",
        room ? "room" : "unicast");
  }
  {
    std::unique_ptr<VeilGroupMediaEngine, decltype(&veil_media_group_engine_destroy)> e(
        veil_media_group_engine_create(local), veil_media_group_engine_destroy);
    assert(e);
    assert(veil_media_group_engine_add_peer(e.get(), 90, peer) == VEIL_MEDIA_OK);
    hold_fanout_video.store(true);
    int video_result = -1, audio_result = -1;
    std::thread video([&] { video_result = veil_media_test_group_fanout_packet(e.get(), 1); });
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (!fanout_video_entered.load() && std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    const bool video_held = fanout_video_entered.load();
    std::thread audio([&] { audio_result = veil_media_test_group_fanout_packet(e.get(), 0); });
    deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
    while (!fanout_audio_passed.load() && std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    const bool audio_while_held = fanout_audio_passed.load();
    hold_fanout_video.store(false);
    video.join(); audio.join();
    assert(video_held && audio_while_held && video_result == 0 && audio_result == 0);
    assert(veil_media_group_engine_remove_peer(e.get(), peer) == VEIL_MEDIA_OK);
    assert(veil_media_test_group_fanout_packet(e.get(), 0) != 0);
    std::puts("group fanout: audio passed while video send was held; removed peer excluded");
  }
  unsetenv("VEIL_MEDIA_TEST_VIDEO");
  assert(callbacks.empty());
  std::puts("unicast: negotiated TWCC confirms separate audio/video SSRCs and counters; legacy mode sends none");
  std::puts("direct/group: Opus delivered with both video queues stalled; telemetry bounded; restart/teardown ok");
}
