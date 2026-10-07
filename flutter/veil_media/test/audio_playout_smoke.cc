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
#include <set>
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
static bool perfect_network = false;
static bool handover_network = false;
static bool delivery_stall = false;
static bool drop_during_stall = false;
static size_t dropped_packets = 0;
static size_t max_delivery_batch = 0;
static const std::set<uint64_t> handover_sources{200, 201, 202};
static std::vector<std::pair<uint64_t, uint16_t>> handover_sequences;
static double milliseconds(Clock::time_point t) {
  return std::chrono::duration<double, std::milli>(t - origin).count();
}
extern "C" int veil_media_set_recv_callback(uint64_t chan,
    void (*fn)(void*, const uint8_t*, size_t), void* ctx) {
  std::lock_guard lock(mu);
  if (fn && chan == 999) return -1; // unknown native candidate, no replacement
  if (fn) callbacks[chan] = {fn, ctx}; else callbacks.erase(chan);
  return 0;
}
extern "C" int veil_media_send_datagram(uint64_t chan, const uint8_t* p, size_t len) {
  std::lock_guard lock(mu);
  if ((handover_network ? !handover_sources.contains(chan) : chan != source_channel) ||
      len < 12 || (p[1] & 0x7f) != 111) return 0;
  if (handover_network)
    handover_sequences.emplace_back(chan, uint16_t(p[2]) << 8 | p[3]);
  const auto now = Clock::now();
  const double at = milliseconds(now);
  // Reproducible short jitter bursts, then ten seconds of a recovered path.
  const int delay = !perfect_network && at >= 2000 && at < 4000
      ? (static_cast<int>(at) / 200 % 2 ? 300 : 40) : 40;
  ++sent_packets;
  auto due = now + std::chrono::milliseconds(delay);
  if (delivery_stall) {
    // Stall before the receiver, matching the observed kernel-receipt boundary.
    // Release old packets together in send order, beside newly arriving audio.
    const int release_at = at >= 2000 && at < 3000 ? 3040
        : at >= 6000 && at < 8700 ? 8740 : 0;
    if (release_at && drop_during_stall) { ++dropped_packets; return 0; }
    due = release_at ? origin + std::chrono::milliseconds(release_at)
                     : now + std::chrono::milliseconds(40);
  }
  pending.push_back({due, {p, p + len}});
  return 0;
}
extern "C" int veil_media_send_video_control_datagram(uint64_t,
    const uint8_t*, size_t) { return 0; }
static void deliver() {
  std::vector<Packet> ready;
  Callback callback{};
  {
    std::lock_guard lock(mu);
    const auto target = callbacks.find(receiver_channel);
    if (target != callbacks.end()) callback = target->second;
    const auto now = Clock::now();
    for (auto it = pending.begin(); it != pending.end();) {
      if (it->due <= now) { ready.push_back(std::move(*it)); it = pending.erase(it); }
      else ++it;
    }
  }
  std::stable_sort(ready.begin(), ready.end(), [](const auto& a, const auto& b) {
    return a.due < b.due;
  });
  max_delivery_batch = std::max(max_delivery_batch, ready.size());
  for (const auto& p : ready) {
    if (callback.fn) callback.fn(callback.ctx, p.bytes.data(), p.bytes.size());
  }
}
static uint64_t metric(VeilMediaEngine* e, const char* name) {
  char* json = veil_media_engine_get_stats(e); assert(json);
  const auto key = std::string("\"") + name + "\":";
  const auto* at = std::strstr(json, key.c_str()); assert(at);
  const auto value = std::strtoull(at + key.size(), nullptr, 10);
  veil_media_free_string(json); return value;
}

static void verify_handover(bool asymmetric = false) {
  perfect_network = true;
  handover_network = true;
  const uint8_t local[32] = {1}, peer[32] = {2};
  source_channel = 200; receiver_channel = 300;
  using Engine = std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)>;
  {
    Engine receiver(veil_media_test_audio_playout_create(300, peer, local, 0, 0), veil_media_engine_destroy);
    Engine source(veil_media_test_audio_playout_create(200, local, peer, 1, 0), veil_media_engine_destroy);
    assert(source && receiver);
    origin = Clock::now();
    std::array<int16_t, 480> pcm{};
    std::vector<double> source_edges, rendered_edges;
    bool was_high = false;
    double max_lateness = 0;
    size_t nonsilent_ticks = 0;
    uint64_t baseline_interruptions = 0, baseline_concealed = 0;
    for (int tick = 0; tick < 1000; ++tick) {
      std::this_thread::sleep_until(origin + std::chrono::milliseconds(10 * tick));
      const double now = milliseconds(Clock::now());
      max_lateness = std::max(max_lateness, now - 10 * tick);
      if (tick == 200 || tick == 600) {
        const uint64_t source_next = tick == 200 ? 201 : 202;
        const uint64_t receive_next = tick == 200 ? 301 : 302;
        const auto before_rx = metric(receiver.get(), "audio_rx_pkts");
        if (!asymmetric)
          assert(veil_media_engine_rebind_channel(source.get(), source_next) == VEIL_MEDIA_OK);
        const auto rebind_receiver = asymmetric
            ? veil_media_engine_rebind_channel_keep_receiver
            : veil_media_engine_rebind_channel;
        assert(rebind_receiver(receiver.get(), receive_next) == VEIL_MEDIA_OK);
        assert(rebind_receiver(receiver.get(), receive_next) == VEIL_MEDIA_OK);
        assert(metric(receiver.get(), "audio_rx_pkts") >= before_rx);
        {
          std::lock_guard lock(mu);
          if (!asymmetric) {
            assert(callbacks.size() == 2 && callbacks.contains(source_next) && callbacks.contains(receive_next));
            source_channel = source_next; receiver_channel = receive_next;
          }
        }
      }
      if (asymmetric && tick == 300) {
        assert(veil_media_engine_rebind_channel_keep_receiver(receiver.get(), 0) == VEIL_MEDIA_ERR_ARG);
        assert(veil_media_engine_rebind_channel_keep_receiver(receiver.get(), 999) != VEIL_MEDIA_OK);
        assert(veil_media_engine_release_receive_channel(receiver.get(), 301) != VEIL_MEDIA_OK);
        std::lock_guard lock(mu);
        assert(callbacks.contains(300) && callbacks.contains(301));
      }
      if (asymmetric && tick == 900) {
        // Teardown must fence a retained leg whose peer never switched.
        assert(veil_media_engine_rebind_channel_keep_receiver(receiver.get(), 303) == VEIL_MEDIA_OK);
      }
      if (asymmetric && (tick == 400 || tick == 800)) {
        const uint64_t source_next = tick == 400 ? 201 : 202;
        const uint64_t receive_next = tick == 400 ? 301 : 302;
        assert(veil_media_engine_rebind_channel(source.get(), source_next) == VEIL_MEDIA_OK);
        const uint64_t retired = tick == 400 ? 300 : 301;
        assert(veil_media_engine_release_receive_channel(receiver.get(), receive_next) != VEIL_MEDIA_OK);
        assert(veil_media_engine_release_receive_channel(receiver.get(), retired) == VEIL_MEDIA_OK);
        assert(veil_media_engine_release_receive_channel(receiver.get(), retired) == VEIL_MEDIA_OK);
        std::lock_guard lock(mu);
        source_channel = source_next; receiver_channel = receive_next;
      }
      if (tick == 400) {
        assert(veil_media_engine_rebind_channel(source.get(), 0) == VEIL_MEDIA_ERR_ARG);
        assert(veil_media_engine_rebind_channel(source.get(), 999) != VEIL_MEDIA_OK);
        assert(veil_media_engine_rebind_channel(receiver.get(), 999) != VEIL_MEDIA_OK);
        std::lock_guard lock(mu);
        assert(callbacks.size() == 2 && callbacks.contains(201) && callbacks.contains(301));
      }
      if (tick == 150) {
        baseline_interruptions = metric(receiver.get(), "audio_interruption_count");
        baseline_concealed = metric(receiver.get(), "audio_concealed_samples");
      }
      const bool high = (tick / 100) % 2;
      if (high && tick % 100 == 0) source_edges.push_back(now);
      assert(veil_media_test_audio_capture_tone(source.get(), high ? 1200 : 440) == 0);
      deliver();
      assert(veil_media_test_audio_playout_pcm(receiver.get(), pcm.data(), pcm.size()) == 480);
      double power = 0; int crossings = 0;
      for (size_t i = 0; i < pcm.size(); ++i) {
        power += static_cast<double>(pcm[i]) * pcm[i];
        if (i && ((pcm[i] > 0) != (pcm[i - 1] > 0))) ++crossings;
      }
      const bool nonsilent = power / pcm.size() > 500 * 500;
      if (nonsilent) ++nonsilent_ticks;
      const bool rendered_high = nonsilent && crossings >= 17;
      if (rendered_high && !was_high) rendered_edges.push_back(milliseconds(Clock::now()));
      was_high = rendered_high;
    }
    std::fprintf(stderr, "handover%s rendered %zu/1000 nonsilent PCM ticks; max timer lateness %.2f ms\n",
        asymmetric ? " asynchronous" : "", nonsilent_ticks, max_lateness);
    assert(max_lateness < 30 && nonsilent_ticks > 950);
    for (double sent : source_edges) {
      const auto rendered = std::find_if(rendered_edges.begin(), rendered_edges.end(),
          [&](double at) { return at >= sent && at < sent + 180; });
      assert(rendered != rendered_edges.end());
    }
    assert(metric(receiver.get(), "audio_interruption_count") == baseline_interruptions);
    assert(metric(receiver.get(), "audio_concealed_samples") == baseline_concealed);
    std::lock_guard lock(mu);
    assert(handover_sequences.size() > 400);
    std::set<uint64_t> used;
    for (size_t i = 0; i < handover_sequences.size(); ++i) {
      used.insert(handover_sequences[i].first);
      if (i) assert(uint16_t(handover_sequences[i].second - handover_sequences[i - 1].second) == 1);
    }
    assert(used == handover_sources);
    std::printf("handover%s: channel switches, failed candidate preserved, continuous RTP/PCM, no added concealment or interruptions; lateness %.2f ms\n", asymmetric ? " asynchronous" : "", max_lateness);
  }
  { std::lock_guard lock(mu); assert(callbacks.empty()); }
}
static void verify_silence() {
  perfect_network = true;
  const uint8_t local[32] = {1}, peer[32] = {2};
  source_channel = 200; receiver_channel = 300;
  using Engine = std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)>;
  Engine receiver(veil_media_test_audio_playout_create(receiver_channel, peer, local, 0, 30), veil_media_engine_destroy);
  Engine source(veil_media_test_audio_playout_create(source_channel, local, peer, 1, 30), veil_media_engine_destroy);
  assert(source && receiver);
  origin = Clock::now();
  std::array<int16_t, 480> pcm{};
  uint64_t before_interruptions = 0, before_concealed = 0, max_age = 0;
  size_t silent_start_packets = 0, silent_end_packets = 0, recovered_ticks = 0;
  double max_lateness = 0;
  for (int tick = 0; tick < 1600; ++tick) {
    std::this_thread::sleep_until(origin + std::chrono::milliseconds(10 * tick));
    max_lateness = std::max(max_lateness, milliseconds(Clock::now()) - 10 * tick);
    assert(veil_media_test_audio_capture_tone(source.get(), tick < 200 ? 440 : tick < 1200 ? 0 : 1200) == 0);
    deliver();
    assert(veil_media_test_audio_playout_pcm(receiver.get(), pcm.data(), pcm.size()) == 480);
    if (tick >= 1250) {
      double power = 0;
      for (const auto sample : pcm) power += static_cast<double>(sample) * sample;
      if (power / pcm.size() > 500 * 500) ++recovered_ticks;
    }
    if (tick == 200) { before_interruptions = metric(receiver.get(), "audio_interruption_count"); before_concealed = metric(receiver.get(), "audio_concealed_samples"); silent_start_packets = sent_packets; }
    if (tick == 1200) silent_end_packets = sent_packets;
    if (tick % 10 == 0 && tick >= 300 && tick < 1200) max_age = std::max(max_age, metric(receiver.get(), "audio_rx_native_age_ms"));
  }
  std::printf("{\"silence_rtp_packets\":%zu,\"max_silence_rx_age_ms\":%llu,\"interruption_delta\":%llu,\"concealed_delta\":%llu,\"max_tick_lateness_ms\":%.2f}\n", silent_end_packets - silent_start_packets, (unsigned long long)max_age, (unsigned long long)(metric(receiver.get(), "audio_interruption_count") - before_interruptions), (unsigned long long)(metric(receiver.get(), "audio_concealed_samples") - before_concealed), max_lateness);
  std::fflush(stdout);
  assert(max_lateness < 30);
  assert(silent_end_packets - silent_start_packets > 20);
  assert(silent_end_packets - silent_start_packets < 150); // Opus DTX is exercised
  assert(max_age < 500); // intentional silence must not trigger receive repair
  assert(recovered_ticks > 250); // real decoded tone resumes after silence
  assert(metric(receiver.get(), "audio_concealed_samples") == before_concealed);
  assert(metric(receiver.get(), "audio_interruption_count") == before_interruptions);
}

static void verify_delivery_stall(bool drop) {
  delivery_stall = true;
  drop_during_stall = drop;
  const uint8_t local[32] = {1}, peer[32] = {2};
  source_channel = 200; receiver_channel = 300;
  using Engine = std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)>;
  {
    Engine receiver(veil_media_test_audio_playout_create(300, peer, local, 0, 0), veil_media_engine_destroy);
    Engine source(veil_media_test_audio_playout_create(200, local, peer, 1, 0), veil_media_engine_destroy);
    assert(source && receiver);
    { std::lock_guard lock(mu); origin = Clock::now(); }
    std::array<int16_t, 480> pcm{};
    std::vector<double> source_edges, rendered_edges;
    bool was_high = false;
    double max_lateness = 0;
    size_t recovered_ticks = 0;
    uint64_t max_buffer = 0;
    for (int tick = 0; tick < 2000; ++tick) {
      std::this_thread::sleep_until(origin + std::chrono::milliseconds(10 * tick));
      const double now = milliseconds(Clock::now());
      max_lateness = std::max(max_lateness, now - 10 * tick);
      const bool high = (tick / 100) % 2;
      if (high && tick % 100 == 0) source_edges.push_back(now);
      assert(veil_media_test_audio_capture_tone(source.get(), high ? 1200 : 440) == 0);
      deliver();
      assert(veil_media_test_audio_playout_pcm(receiver.get(), pcm.data(), pcm.size()) == 480);
      double power = 0; int crossings = 0;
      for (size_t i = 0; i < pcm.size(); ++i) {
        power += static_cast<double>(pcm[i]) * pcm[i];
        if (i && ((pcm[i] > 0) != (pcm[i - 1] > 0))) ++crossings;
      }
      const bool nonsilent = power / pcm.size() > 500 * 500;
      if (tick >= 1700 && nonsilent) ++recovered_ticks;
      const bool rendered_high = nonsilent && crossings >= 17;
      if (rendered_high && !was_high) rendered_edges.push_back(milliseconds(Clock::now()));
      was_high = rendered_high;
      if (tick % 10 == 0)
        max_buffer = std::max(max_buffer, metric(receiver.get(), "audio_jb_ms"));
    }
    size_t sent, dropped, batch;
    { std::lock_guard lock(mu); sent = sent_packets; dropped = dropped_packets; batch = max_delivery_batch; }
    std::printf("{\"delivery_stall_drop\":%s,\"sent_packets\":%zu,\"dropped_packets\":%zu,"
                "\"max_delivery_batch\":%zu,\"max_tick_lateness_ms\":%.2f,"
                "\"final_nonsilent_ticks\":%zu,\"max_buffer_ms\":%llu,\"post_stall_marker_latency_ms\":[",
        drop ? "true" : "false", sent, dropped, batch,
        max_lateness, recovered_ticks, static_cast<unsigned long long>(max_buffer));
    bool recovered = true;
    size_t markers = 0;
    for (double sent : source_edges) {
      if (sent < 9000) continue; // speech during the outage cannot be timely
      const auto rendered = std::find_if(rendered_edges.begin(), rendered_edges.end(),
          [&](double at) { return at >= sent && at < sent + 800; });
      const double latency = rendered == rendered_edges.end() ? -1 : *rendered - sent;
      if (markers++) std::printf(",");
      std::printf("%.2f", latency);
      // Measure genuine decoded PCM recovery, not only a falling jitter gauge.
      recovered &= latency >= 0 && latency < (sent < 11000 ? 300 : 180);
    }
    std::printf("],\"concealed_samples\":%llu,\"interruption_count\":%llu,\"buffer_flushes\":%llu}\n",
        static_cast<unsigned long long>(metric(receiver.get(), "audio_concealed_samples")),
        static_cast<unsigned long long>(metric(receiver.get(), "audio_interruption_count")),
        static_cast<unsigned long long>(metric(receiver.get(), "audio_jb_flushes")));
    std::fflush(stdout);
    assert(max_lateness < 30 && sent > 800 && markers == 6);
    assert(drop ? dropped > 150 && batch < 10
                : dropped == 0 && batch > 100);
    assert(recovered && recovered_ticks > 290);
  }
  { std::lock_guard lock(mu); assert(callbacks.empty()); }
}

int main(int argc, char** argv) {
  if (argc == 2 && std::strcmp(argv[1], "--delivery-stall") == 0) {
    verify_delivery_stall(false);
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--delivery-loss") == 0) {
    verify_delivery_stall(true);
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--asymmetric-handover") == 0) {
    verify_handover(true);
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--handover") == 0) {
    verify_handover();
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--silence") == 0) {
    verify_silence();
    return 0;
  }
  const uint8_t local[32] = {1}, peer[32] = {2};
  uint64_t baseline_concealed = 0;
  uint64_t baseline_flushes = 0;
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
    std::printf("{\"buffer_packets_override\":%zu,\"rtp_packets\":%zu,\"nonsilent_ticks\":%zu,"
                "\"max_tick_lateness_ms\":%.2f,\"max_filtered_delay_ms\":%llu,"
                "\"max_current_buffer_ms\":%llu,\"marker_latency_ms\":[",
        capacity, packet_count, nonsilent_ticks, max_tick_lateness,
        static_cast<unsigned long long>(max_delay), static_cast<unsigned long long>(max_buffer));
    bool recovered = true;
    for (size_t i = 0; i < source_edges.size(); ++i) {
      const auto edge = std::find_if(high_edges.begin(), high_edges.end(), [&](double at) {
        return at >= source_edges[i] && at < source_edges[i] + 800;
      });
      assert(edge != high_edges.end());
      const auto latency = *edge - source_edges[i];
      // A packet-capacity reduction must not masquerade as a latency win by
      // flushing audio. Keep PCM recovery within the measured control budget,
      // then check actual concealed samples as well as the rendered markers.
      if (!capacity && (i == 2 || i == 3)) recovered &= latency < 400;
      // The 9-second marker of the unchanged control ranged from 170 to
      // 252 ms; its final 11/13-second markers returned below 180 ms.
      if (!capacity && i == 4) recovered &= latency < 300;
      if (!capacity && i >= 5) recovered &= latency < 180;
      if (i) std::printf(",");
      std::printf("%.2f", latency);
    }
    std::printf("],\"concealed_samples\":%llu,\"interruption_count\":%llu,\"buffer_flushes\":%llu}\n",
        static_cast<unsigned long long>(metric(receiver.get(), "audio_concealed_samples")),
        static_cast<unsigned long long>(metric(receiver.get(), "audio_interruption_count")),
        static_cast<unsigned long long>(metric(receiver.get(), "audio_jb_flushes")));
    std::fflush(stdout);
    assert(recovered); // Print the complete PCM trace before rejecting a policy.
    const auto concealed = metric(receiver.get(), "audio_concealed_samples");
    const auto flushes = metric(receiver.get(), "audio_jb_flushes");
    if (capacity) { baseline_concealed = concealed; baseline_flushes = flushes; }
    else {
      assert(concealed <= baseline_concealed + 2400); // <=50 ms extra at 48 kHz
      assert(flushes <= baseline_flushes);
    }

  }
}
