// Three real group mixers/Opus pipelines; a mocked Veil boundary forwards
// every packet FIFO. No physical microphone, speaker or network is opened.
#undef NDEBUG
#include "veil_media_engine.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

extern "C" VeilGroupMediaEngine *
veil_media_test_group_codec_create(const uint8_t *);
extern "C" int veil_media_test_group_capture_tone(VeilGroupMediaEngine *, int);
extern "C" int veil_media_test_group_playout_pcm(VeilGroupMediaEngine *,
                                                 int16_t *, size_t);
extern "C" int veil_media_test_group_with_held_video(VeilGroupMediaEngine *,
                                                     int (*)(void *), void *);

namespace {
using Clock = std::chrono::steady_clock;
struct Callback {
  void (*fn)(void *, const uint8_t *, size_t);
  void *ctx;
};
struct Packet {
  uint64_t channel;
  std::vector<uint8_t> bytes;
};
std::mutex transport_mu;
std::map<uint64_t, Callback> callbacks;
std::deque<Packet> packets;
size_t packet_count = 0;
constexpr int kPauseTick = 200;
constexpr int kResumeTick = 250;
constexpr int kSwitchTick = 235;
constexpr std::array<int, 3> old_tones{600, 1100, 1600};
constexpr std::array<int, 3> new_tones{900, 1400, 1900};

int Send(uint64_t channel, const uint8_t *bytes, size_t size) {
  std::lock_guard lock(transport_mu);
  assert(packets.size() < 8192);
  // Directional channels are paired; the forwarding boundary interprets no
  // RTP payload, media kind or priority.
  packets.push_back({channel ^ 1, {bytes, bytes + size}});
  ++packet_count;
  return 0;
}

void Deliver() {
  std::deque<Packet> pending;
  {
    std::lock_guard lock(transport_mu);
    pending.swap(packets);
  }
  for (const auto &packet : pending) {
    Callback cb{};
    {
      std::lock_guard lock(transport_mu);
      const auto found = callbacks.find(packet.channel);
      assert(found != callbacks.end());
      cb = found->second;
    }
    cb.fn(cb.ctx, packet.bytes.data(), packet.bytes.size());
  }
}

double Energy(const std::array<int16_t, 480> &pcm, int frequency) {
  constexpr double pi = 3.14159265358979323846;
  double real = 0, imaginary = 0;
  for (size_t i = 0; i < pcm.size(); ++i) {
    const double phase = 2 * pi * frequency * i / 48000;
    real += pcm[i] * std::cos(phase);
    imaginary += pcm[i] * std::sin(phase);
  }
  return (real * real + imaginary * imaginary) / (pcm.size() * pcm.size());
}

bool Contains(const std::array<int16_t, 480> &pcm, int wanted, int stale) {
  // Check each remote source independently in the MIXED decoded output.
  // Both expected bands must be present, with old speech no longer dominant.
  return Energy(pcm, wanted) > 10000 &&
         Energy(pcm, wanted) > 4 * Energy(pcm, stale);
}

uint64_t Counter(const char *json, const char *key) {
  const auto marker = std::string("\"") + key + "\":";
  const auto *value = std::strstr(json, marker.c_str());
  return value ? std::strtoull(value + marker.size(), nullptr, 10) : 0;
}
} // namespace

extern "C" int veil_media_send_datagram(uint64_t c, const uint8_t *p,
                                        size_t n) {
  return Send(c, p, n);
}
extern "C" int
veil_media_send_video_control_datagram(uint64_t c, const uint8_t *p, size_t n) {
  return Send(c, p, n);
}
extern "C" int veil_media_set_recv_callback(
    uint64_t c, void (*fn)(void *, const uint8_t *, size_t), void *ctx) {
  std::lock_guard lock(transport_mu);
  if (fn)
    callbacks[c] = {fn, ctx};
  else
    callbacks.erase(c);
  return 0;
}

int main() {
  std::array<std::array<uint8_t, 32>, 3> ids{};
  using Engine = std::unique_ptr<VeilGroupMediaEngine,
                                 decltype(&veil_media_group_engine_destroy)>;
  std::vector<Engine> engines;
  for (size_t i = 0; i < ids.size(); ++i) {
    ids[i][0] = static_cast<uint8_t>(i + 1);
    engines.emplace_back(veil_media_test_group_codec_create(ids[i].data()),
                         veil_media_group_engine_destroy);
    assert(engines.back());
  }
  uint64_t channel = 10;
  for (size_t a = 0; a < engines.size(); ++a) {
    for (size_t z = a + 1; z < engines.size(); ++z) {
      assert(veil_media_group_engine_add_peer(engines[a].get(), channel,
                                              ids[z].data()) == VEIL_MEDIA_OK);
      assert(veil_media_group_engine_add_peer(engines[z].get(), channel ^ 1,
                                              ids[a].data()) == VEIL_MEDIA_OK);
      channel += 2;
    }
  }
  for (auto &e : engines)
    assert(veil_media_group_engine_start_audio(e.get()) == VEIL_MEDIA_OK);
  for (auto &e : engines)
    assert(veil_media_group_engine_start_video(e.get()) == VEIL_MEDIA_OK);

  std::array<uint8_t, 64 * 64> y{};
  std::array<uint8_t, 32 * 32> u{}, v{};
  u.fill(128);
  v.fill(128);

  auto deadline = Clock::now();
  double max_interval_ms = 0;
  auto previous = deadline;
  size_t warm_mixed = 0, recovered_mixed = 0;
  int first_recovered_tick = -1;
  auto switched_at = deadline;
  double first_fresh_age_ms = -1;
  auto drive = [&]() {
    for (int tick = 0; tick < 350; ++tick) {
      std::this_thread::sleep_until(deadline);
      const auto now = Clock::now();
      max_interval_ms = std::max(
          max_interval_ms,
          std::chrono::duration<double, std::milli>(now - previous).count());
      previous = now;
      if (tick == kSwitchTick)
        switched_at = now;
      const auto &tones = tick < kSwitchTick ? old_tones : new_tones;
      for (size_t i = 0; i < engines.size(); ++i)
        assert(veil_media_test_group_capture_tone(engines[i].get(), tones[i]) ==
               VEIL_MEDIA_OK);
      if (tick % 7 == 0) {
        for (size_t i = 0; i < engines.size(); ++i) {
          y.fill(static_cast<uint8_t>(40 + (tick + i * 30) % 150));
          assert(veil_media_group_engine_push_video_frame(
                     engines[i].get(), y.data(), u.data(), v.data(), 64, 64, 64,
                     32, 32,
                     std::chrono::duration_cast<std::chrono::microseconds>(
                         Clock::now().time_since_epoch())
                         .count()) == VEIL_MEDIA_OK);
        }
      }
      Deliver();
      for (size_t i = 0; i < engines.size(); ++i) {
        // Model a delayed device render callback while packets continue to
        // arrive and the other two group participants remain active.
        if (i == 0 && tick >= kPauseTick && tick < kResumeTick)
          continue;
        std::array<int16_t, 480> pcm{};
        assert(veil_media_test_group_playout_pcm(engines[i].get(), pcm.data(),
                                                 pcm.size()) == 480);
        if (i != 0)
          continue;
        if (tick >= 150 && tick < kPauseTick &&
            Contains(pcm, old_tones[1], new_tones[1]) &&
            Contains(pcm, old_tones[2], new_tones[2]))
          ++warm_mixed;
        if (tick >= kResumeTick && Contains(pcm, new_tones[1], old_tones[1]) &&
            Contains(pcm, new_tones[2], old_tones[2])) {
          if (first_recovered_tick < 0) {
            first_recovered_tick = tick;
            first_fresh_age_ms = std::chrono::duration<double, std::milli>(
                                     Clock::now() - switched_at)
                                     .count();
          }
          if (tick >= kResumeTick + 5 && tick < kResumeTick + 20)
            ++recovered_mixed;
        }
      }
      deadline += std::chrono::milliseconds(10);
    }
    return 0;
  };
  using Drive = decltype(drive);
  // Hold both video Call queues for the entire decoded-audio observation.
  // Other peers continue real VP8 production into the receiver's bounded lane.
  assert(veil_media_test_group_with_held_video(
             engines[0].get(),
             [](void *ctx) { return (*static_cast<Drive *>(ctx))(); },
             &drive) == 0);
  char *stats = veil_media_group_engine_get_stats(engines[0].get());
  assert(stats);
  const auto recoveries = Counter(stats, "audio_latency_recovery_count");
  const auto discarded = Counter(stats, "audio_latency_discarded_ms");
  const auto fallbacks = Counter(stats, "audio_latency_fallback_frames");
  veil_media_free_string(stats);
  for (auto &e : engines)
    assert(veil_media_group_engine_stop_audio(e.get()) == VEIL_MEDIA_OK);
  engines.clear();
  {
    std::lock_guard lock(transport_mu);
    assert(callbacks.empty());
    packets.clear();
  }
  std::printf("group decoded mix: warm=%zu recovered=%zu first_tick=%d "
              "resume_tick=%d packets=%zu max_clock_gap_ms=%.3f "
              "fresh_marker_age_ms=%.3f recoveries=%llu discarded_ms=%llu "
              "fallback=%llu\n",
              warm_mixed, recovered_mixed, first_recovered_tick, kResumeTick,
              packet_count, max_interval_ms, first_fresh_age_ms,
              static_cast<unsigned long long>(recoveries),
              static_cast<unsigned long long>(discarded),
              static_cast<unsigned long long>(fallbacks));
  std::fflush(stdout);
  if (max_interval_ms >= 40)
    return 2; // Invalid fixture clock.
  if (warm_mixed < 40)
    return 3; // Both tones must reach the mixer first.
  // Both new tones first existed 150 ms before playout resumes. Recognizing
  // them before their measured marker age reaches 200 ms bounds the age of
  // actual useful output from BOTH remote sources, not just queue counters.
  if (first_recovered_tick < kResumeTick ||
      first_recovered_tick > kResumeTick + 5)
    return 4;
  if (first_fresh_age_ms < 0 || first_fresh_age_ms >= 200)
    return 6;
  return recovered_mixed >= 12 && recoveries > 0 && discarded > 0 ? 0 : 5;
}
