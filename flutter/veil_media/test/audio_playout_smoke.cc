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
extern "C" VeilMediaEngine* veil_media_test_duplex_codec_create(
    uint64_t, const uint8_t[32], const uint8_t[32]);
extern "C" int veil_media_test_audio_transport_budget(VeilMediaEngine*, int);
extern "C" int veil_media_test_audio_adaptation(VeilMediaEngine*, int);
struct Callback { void (*fn)(void*, const uint8_t*, size_t); void* ctx; };
struct Packet { Clock::time_point due; std::vector<uint8_t> bytes; uint64_t destination = 0; };
static std::mutex mu;
static std::map<uint64_t, Callback> callbacks;
static std::vector<Packet> pending;
static Clock::time_point origin;
static uint64_t source_channel = 0, receiver_channel = 0;
static size_t sent_packets = 0;
static bool charged_link=false,charged_duplex=false;
static std::map<uint64_t,Clock::time_point> wire_free;
static size_t wire_drops=0,wire_admissions=0;
static std::vector<std::array<long long,5>> source_packets;
static std::array<size_t,3> packets_by_phase{},drops_by_phase{},wire_bytes_by_phase{},control_drops{},control_admissions{};
static bool perfect_network = false;
static bool duplex_feedback = false;
static bool handover_network = false;
static bool delivery_stall = false;
static bool recurring_jitter = false;
static bool mature_jitter = false;
static bool padding_only = false;
static bool foreign_audio_only = false;
static Clock::time_point mature_last_due;
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
  if(charged_link) {
    const auto now=Clock::now();
    const int phase=std::clamp(int(milliseconds(now)/4000),0,2);
    const bool control=len>=4 && p[1]>=192 && p[1]<=223;
    if(!control && ((!charged_duplex && chan!=source_channel) || len<12 || (p[1]&0x7f)!=111)) return 0;
    const int capacity=phase==1 ? 64000 : 160000;
    const size_t cost=len+209;
    const auto finish=std::max(now,wire_free[chan])+std::chrono::microseconds(cost*8000000/capacity);
    // Bounded, lossy source queue; admission remains asynchronous to RTP.
    if(finish-now>std::chrono::milliseconds(200)) {
      ++wire_drops;if(!control)++drops_by_phase[phase];else ++control_drops[phase];return 0;
    }
    wire_free[chan]=finish;++wire_admissions;if(control)++control_admissions[phase];
    if(!control){++packets_by_phase[phase];wire_bytes_by_phase[phase]+=cost;source_packets.push_back({(long long)(milliseconds(now)*1000),(long long)(uint16_t(p[2])<<8|p[3]),(long long)(uint32_t(p[4])<<24|uint32_t(p[5])<<16|uint32_t(p[6])<<8|p[7]),(long long)len,(long long)chan});}
    pending.push_back({finish+std::chrono::milliseconds(40),std::vector<uint8_t>(p,p+len),chan==source_channel ? receiver_channel : source_channel});
    return 0;
  }
  if (duplex_feedback && len >= 4 && p[1] >= 192 && p[1] <= 223) {
    pending.push_back({Clock::now() + std::chrono::milliseconds(40),
                      std::vector<uint8_t>(p, p + len),
                      chan == source_channel ? receiver_channel : source_channel});
    return 0;
  }
  if ((handover_network ? !handover_sources.contains(chan) : chan != source_channel) ||
      len < 12 || (p[1] & 0x7f) != 111) return 0;
  if (handover_network)
    handover_sequences.emplace_back(chan, uint16_t(p[2]) << 8 | p[3]);
  const auto now = Clock::now();
  const double at = milliseconds(now);
  // Exercise both a short burst and repeated bursts across ten seconds.
  // Each is followed by a healthy path; PCM must shed the old playout tail.
  const int delay = !perfect_network && at >= (mature_jitter ? 70000 : 2000) &&
      at < (mature_jitter ? 80000 : recurring_jitter ? 12000 : 4000)
      ? (static_cast<int>(at) / 200 % 2 ? 300 : 40) : 40;
  ++sent_packets;
  auto due = now + std::chrono::milliseconds(delay);
  if (mature_jitter) {
    // Captured ingress is overwhelmingly ordered: model a delivery pause
    // holding later packets behind it. Delaying alternate packets lets them
    // overtake each other and exercises the reorder estimator instead of underruns.
    due = std::max(due, mature_last_due);
    mature_last_due = due;
  }
  if (delivery_stall) {
    // Stall before the receiver, matching the observed kernel-receipt boundary.
    // Release old packets together in send order, beside newly arriving audio.
    const int release_at = at >= 2000 && at < 3000 ? 3040
        : at >= 6000 && at < 8700 ? 8740 : 0;
    if (release_at && drop_during_stall) { ++dropped_packets; return 0; }
    due = release_at ? origin + std::chrono::milliseconds(release_at)
                     : now + std::chrono::milliseconds(40);
  }
  std::vector<uint8_t> packet(p, p + len);
  if (padding_only) {
    // Valid RTP padding for the same audio SSRC, with no encoded audio.
    packet.resize(13);
    packet[0] = 0xa0;  // V=2, padding, no CSRCs or extensions.
    packet[12] = 1;
  } else if (foreign_audio_only) {
    packet[8] ^= 0x80;  // Encoded audio for an unregistered SSRC.
  }
  pending.push_back({due, std::move(packet)});
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
    auto target = callback;
    if (p.destination) {
      std::lock_guard lock(mu);
      target = callbacks.at(p.destination);
    }
    if (target.fn) target.fn(target.ctx, p.bytes.data(), p.bytes.size());
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
static void verify_sender_restart() {
  perfect_network = true;
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
    uint64_t max_delay = 0, max_buffer = 0;
    size_t nonsilent_ticks = 0;
    bool was_high = false;
    for (int tick = 0; tick < 1200; ++tick) {
      std::this_thread::sleep_until(origin + std::chrono::milliseconds(10 * tick));
      if (tick == 300 || tick == 700) {
        // The peer keeps receiving on the same authenticated channel/SSRC.
        // Queued old RTP is deliberately retained across the sender rebuild.
        source.reset();
        source.reset(veil_media_test_audio_playout_create(200, local, peer, 1, 0));
        assert(source);
      }
      const bool high = (tick / 100) % 2;
      if (high && tick % 100 == 0) source_edges.push_back(milliseconds(Clock::now()));
      assert(veil_media_test_audio_capture_tone(source.get(), high ? 1200 : 440) == 0);
      deliver();
      assert(veil_media_test_audio_playout_pcm(receiver.get(), pcm.data(), pcm.size()) == 480);
      double power = 0; int crossings = 0;
      for (size_t i = 0; i < pcm.size(); ++i) {
        power += double(pcm[i]) * pcm[i];
        if (i && ((pcm[i] > 0) != (pcm[i - 1] > 0))) ++crossings;
      }
      const bool nonsilent = power / pcm.size() > 500 * 500;
      if (nonsilent) ++nonsilent_ticks;
      const bool rendered_high = nonsilent && crossings >= 17;
      if (rendered_high && !was_high) rendered_edges.push_back(milliseconds(Clock::now()));
      was_high = rendered_high;
      if (tick % 10 == 0) {
        max_delay = std::max(max_delay, metric(receiver.get(), "audio_delay_ms"));
        max_buffer = std::max(max_buffer, metric(receiver.get(), "audio_jb_ms"));
      }
    }
    std::printf("sender rebuilds: nonsilent=%zu/1200 delay_max=%llu buffer_max=%llu marker_latency_ms=[",
        nonsilent_ticks, static_cast<unsigned long long>(max_delay),
        static_cast<unsigned long long>(max_buffer));
    bool rendered_promptly = true;
    for (size_t i = 0; i < source_edges.size(); ++i) {
      const auto sent = source_edges[i];
      const auto rendered = std::find_if(rendered_edges.begin(), rendered_edges.end(),
          [&](double at) { return at >= sent && at < sent + 800; });
      const double latency = rendered == rendered_edges.end() ? -1 : *rendered - sent;
      if (i) std::printf(",");
      std::printf("%.2f", latency);
      rendered_promptly &= latency >= 0 && latency < 180;
    }
    std::printf("]\n");
    std::fflush(stdout);
    // Actual PCM and the exported control signal must both recover. A random
    // RTP timestamp restart formerly produced up to ~174,780 ms here while
    // the genuine decoded speech and buffered samples remained prompt.
    assert(source_edges.size() == 6 && rendered_promptly && nonsilent_ticks > 1100);
    assert(max_buffer < 180 && max_delay < 200);
  }
  { std::lock_guard lock(mu); assert(callbacks.empty()); }
}

static void verify_silence(bool after_jitter = false) {
  perfect_network = !after_jitter;
  // The ordinary injected burst ends at four seconds. Start silence after
  // that burst and require actual PCM recovery after ten healthy DTX seconds.
  const int silent_tick = after_jitter ? 400 : 200;
  const int resume_tick = silent_tick + 1000;
  const uint8_t local[32] = {1}, peer[32] = {2};
  source_channel = 200; receiver_channel = 300;
  using Engine = std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)>;
  Engine receiver(veil_media_test_audio_playout_create(receiver_channel, peer, local, 0, 30), veil_media_engine_destroy);
  Engine source(veil_media_test_audio_playout_create(source_channel, local, peer, 1, 30), veil_media_engine_destroy);
  assert(source && receiver);
  origin = Clock::now();
  std::array<int16_t, 480> pcm{};
  uint64_t before_interruptions = 0, before_concealed = 0, max_age = 0;
  uint64_t max_silence_delay = 0, max_silence_buffer = 0;
  uint64_t max_recovered_delay = 0;
  int first_resumed_tick = -1;
  size_t silent_start_packets = 0, silent_end_packets = 0, recovered_ticks = 0;
  double max_lateness = 0;
  for (int tick = 0; tick < resume_tick + 400; ++tick) {
    std::this_thread::sleep_until(origin + std::chrono::milliseconds(10 * tick));
    max_lateness = std::max(max_lateness, milliseconds(Clock::now()) - 10 * tick);
    assert(veil_media_test_audio_capture_tone(source.get(), tick < silent_tick ? 440 : tick < resume_tick ? 0 : 1200) == 0);
    deliver();
    assert(veil_media_test_audio_playout_pcm(receiver.get(), pcm.data(), pcm.size()) == 480);
    if (tick >= resume_tick) {
      double power = 0;
      for (const auto sample : pcm) power += static_cast<double>(sample) * sample;
      if (power / pcm.size() > 500 * 500) {
        if (first_resumed_tick < 0) first_resumed_tick = tick;
        if (tick >= resume_tick + 50) ++recovered_ticks;
      }
    }
    if (tick == silent_tick) { before_interruptions = metric(receiver.get(), "audio_interruption_count"); before_concealed = metric(receiver.get(), "audio_concealed_samples"); silent_start_packets = sent_packets; }
    if (tick == resume_tick) silent_end_packets = sent_packets;
    if (tick % 10 == 0 && tick >= silent_tick + 100 && tick < resume_tick) {
      max_age = std::max(max_age, metric(receiver.get(), "audio_rx_native_age_ms"));
      max_silence_delay = std::max(max_silence_delay, metric(receiver.get(), "audio_delay_ms"));
      max_silence_buffer = std::max(max_silence_buffer, metric(receiver.get(), "audio_jb_ms"));
      if (tick >= resume_tick - 200)
        max_recovered_delay = std::max(max_recovered_delay, metric(receiver.get(), "audio_delay_ms"));
    }
  }
  std::printf("{\"silence_rtp_packets\":%zu,\"max_silence_rx_age_ms\":%llu,\"interruption_delta\":%llu,\"concealed_delta\":%llu,\"max_tick_lateness_ms\":%.2f}\n", silent_end_packets - silent_start_packets, (unsigned long long)max_age, (unsigned long long)(metric(receiver.get(), "audio_interruption_count") - before_interruptions), (unsigned long long)(metric(receiver.get(), "audio_concealed_samples") - before_concealed), max_lateness);
  std::printf("{\"after_jitter\":%s,\"max_silence_delay_ms\":%llu,\"max_recovered_delay_ms\":%llu,\"max_silence_buffer_ms\":%llu,\"resumed_tone_delay_ms\":%d}\n", after_jitter ? "true" : "false", (unsigned long long)max_silence_delay, (unsigned long long)max_recovered_delay, (unsigned long long)max_silence_buffer, first_resumed_tick < 0 ? -1 : (first_resumed_tick - resume_tick) * 10);
  std::fflush(stdout);
  assert(max_lateness < 30);
  assert(silent_end_packets - silent_start_packets > 20);
  assert(silent_end_packets - silent_start_packets < 150); // Opus DTX is exercised
  assert(max_age < 500); // intentional silence must not trigger receive repair
  // Healthy DTX must also retain valid low-delay feedback for video recovery.
  // Packet activity alone would pass with a falsely inflated delay/buffer
  // gauge. Check real decoded PCM too, rather than trusting the gauges alone.
  if (!after_jitter) assert(max_silence_delay < 120);
  assert(max_recovered_delay < 120 && max_silence_buffer < 120);
  assert(first_resumed_tick >= resume_tick && first_resumed_tick < resume_tick + 16);
  assert(recovered_ticks > 250); // real decoded tone resumes after silence
  assert(metric(receiver.get(), "audio_concealed_samples") == before_concealed);
  assert(metric(receiver.get(), "audio_interruption_count") == before_interruptions);
}

static void verify_padding_liveness() {
  perfect_network = true;
  const uint8_t local[32] = {1}, peer[32] = {2};
  source_channel = 200; receiver_channel = 300;
  using Engine = std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)>;
  Engine receiver(veil_media_test_audio_playout_create(300, peer, local, 0, 0), veil_media_engine_destroy);
  Engine source(veil_media_test_audio_playout_create(200, local, peer, 1, 0), veil_media_engine_destroy);
  assert(source && receiver);
  origin = Clock::now();
  std::array<int16_t, 480> pcm{};
  uint64_t before_padding = 0, after_padding = 0, padding_age = 0;
  uint64_t initial_age = 0, foreign_age = 0;
  for (int tick = 0; tick < 500; ++tick) {
    std::this_thread::sleep_until(origin + std::chrono::milliseconds(10 * tick));
    {
      std::lock_guard lock(mu);
      padding_only = tick < 80 || (tick >= 200 && tick < 350);
      foreign_audio_only = tick >= 350 && tick < 400;
    }
    assert(veil_media_test_audio_capture_tone(source.get(), 1200) == 0);
    deliver();
    assert(veil_media_test_audio_playout_pcm(receiver.get(), pcm.data(), pcm.size()) == 480);
    if (tick == 79) initial_age = metric(receiver.get(), "audio_rx_native_age_ms");
    if (tick == 199) before_padding = metric(receiver.get(), "audio_rx_pkts");
    if (tick == 349) {
      after_padding = metric(receiver.get(), "audio_rx_pkts");
      padding_age = metric(receiver.get(), "audio_rx_native_age_ms");
    }
    if (tick == 399) foreign_age = metric(receiver.get(), "audio_rx_native_age_ms");
  }
  const auto recovered_age = metric(receiver.get(), "audio_rx_native_age_ms");
  std::printf("{\"padding_packets_received\":%llu,\"payload_age_after_padding_ms\":%llu,"
              "\"payload_age_after_recovery_ms\":%llu}\n",
      static_cast<unsigned long long>(after_padding - before_padding),
      static_cast<unsigned long long>(padding_age),
      static_cast<unsigned long long>(recovered_age));
  std::fflush(stdout);
  assert(before_padding > 20 && after_padding > before_padding + 50);
  assert(initial_age == static_cast<uint64_t>(-1));
  // Padding may advance RTP/RTCP statistics, never audio liveness or the
  // evidence that allows video to compete with an interrupted audio source.
  assert(padding_age >= 1400);
  assert(foreign_age >= 1900);
  assert(recovered_age < 100);
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
    uint64_t max_delay = 0;
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
      if (tick % 10 == 0) {
        max_buffer = std::max(max_buffer, metric(receiver.get(), "audio_jb_ms"));
        max_delay = std::max(max_delay, metric(receiver.get(), "audio_delay_ms"));
      }
    }
    size_t sent, dropped, batch;
    { std::lock_guard lock(mu); sent = sent_packets; dropped = dropped_packets; batch = max_delivery_batch; }
    std::printf("{\"delivery_stall_drop\":%s,\"sent_packets\":%zu,\"dropped_packets\":%zu,"
                "\"max_delivery_batch\":%zu,\"max_tick_lateness_ms\":%.2f,"
                "\"final_nonsilent_ticks\":%zu,\"max_buffer_ms\":%llu,"
                "\"max_playout_delay_ms\":%llu,\"post_stall_marker_latency_ms\":[",
        drop ? "true" : "false", sent, dropped, batch,
        max_lateness, recovered_ticks, static_cast<unsigned long long>(max_buffer),
        static_cast<unsigned long long>(max_delay));
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
    // A real backlog must still be visible to the adaptation loop; replacing
    // the invalid RTP-span estimate must not hide delay with a fixed ceiling.
    if (!drop) assert(max_buffer > 300 && max_delay > 300);
  }
  { std::lock_guard lock(mu); assert(callbacks.empty()); }
}

static void verify_adaptive_bitrate() {
  perfect_network = true;
  duplex_feedback = true;
  const uint8_t local[32] = {1}, peer[32] = {2};
  source_channel = 200; receiver_channel = 300;
  using Engine = std::unique_ptr<VeilMediaEngine, decltype(&veil_media_engine_destroy)>;
  Engine receiver(veil_media_test_duplex_codec_create(300, peer, local), veil_media_engine_destroy);
  Engine source(veil_media_test_duplex_codec_create(200, local, peer), veil_media_engine_destroy);
  assert(source && receiver);
  origin = Clock::now();
  std::array<int16_t, 480> pcm{};
  std::array<size_t, 3> voiced_ticks{};
  uint64_t baseline_interruptions = 0, baseline_concealed = 0;
  uint64_t max_delay = 0;
  double max_lateness = 0;
  for (int tick = 0; tick < 1200; ++tick) {
    std::this_thread::sleep_until(origin + std::chrono::milliseconds(10 * tick));
    max_lateness = std::max(max_lateness, milliseconds(Clock::now()) - 10 * tick);
    const int phase = tick / 400;
    if (tick % 400 == 0)
      assert(veil_media_test_audio_transport_budget(source.get(), phase == 1 ? 12000 : 48000) == 0);
    assert(veil_media_test_audio_capture_tone(source.get(), 440) == 0);
    assert(veil_media_test_audio_capture_tone(receiver.get(), 0) == 0);
    deliver();
    assert(veil_media_test_audio_playout_pcm(receiver.get(), pcm.data(), pcm.size()) == 480);
    if (tick == 100) {
      baseline_interruptions = metric(receiver.get(), "audio_interruption_count");
      baseline_concealed = metric(receiver.get(), "audio_concealed_samples");
    }
    if (tick % 400 >= 100) {
      double power = 0;
      for (const auto sample : pcm) power += double(sample) * sample;
      if (power / pcm.size() > 500 * 500) ++voiced_ticks[phase];
      if (tick % 10 == 0) {
        const auto target_bps = metric(source.get(), "audio_encoder_target_bps");
        // Real TWCC can trim the healthy estimate below its configured ceiling.
        // Require recovery of codec bitrate, not an artificially fixed estimate.
        const bool target_ok = phase == 1 ? target_bps == 12000
                                         : target_bps >= 24000 && target_bps <= 32000;
        if (!target_ok) std::fprintf(stderr, "adaptive PCM failed tick=%d phase=%d codec=%llu estimate=%llu\n",
            tick, phase, (unsigned long long)target_bps,
            (unsigned long long)metric(source.get(), "audio_send_bandwidth_bps"));
        assert(target_ok);
        max_delay = std::max(max_delay, metric(receiver.get(), "audio_delay_ms"));
      }
    }
  }
  std::printf("adaptive Opus PCM: voiced=%zu/%zu/%zu delay_max=%llu tick_lateness=%.2f\n",
      voiced_ticks[0], voiced_ticks[1], voiced_ticks[2], (unsigned long long)max_delay, max_lateness);
  assert(max_lateness < 30 && max_delay < 120);
  for (const auto ticks : voiced_ticks) assert(ticks >= 290);
  assert(metric(receiver.get(), "audio_interruption_count") == baseline_interruptions);
  assert(metric(receiver.get(), "audio_concealed_samples") == baseline_concealed);
}

// Model direct-flow framing; IP/UDP/QUIC and packet packing are excluded.
// Requires a private native library built with rtc_enable_protobuf=true.
static void verify_adaptive_encapsulation(bool source_pause = false) {
  perfect_network=true;duplex_feedback=true;charged_link=true;charged_duplex=true;
  const uint8_t local[32]={1},peer[32]={2};source_channel=200;receiver_channel=300;
  using Engine=std::unique_ptr<VeilMediaEngine,decltype(&veil_media_engine_destroy)>;
  Engine receiver(veil_media_test_duplex_codec_create(300,peer,local),veil_media_engine_destroy);
  Engine source(veil_media_test_duplex_codec_create(200,local,peer),veil_media_engine_destroy);
  assert(source && receiver);
  assert(veil_media_test_audio_adaptation(source.get(),209)==0);
  assert(veil_media_test_audio_adaptation(receiver.get(),209)==0);
  origin=Clock::now();
  std::array<int16_t,480> pcm{},reverse_pcm{};std::array<size_t,3> voiced{},reverse_voiced{};std::array<uint64_t,3> reverse_delay{};
  std::array<uint64_t,3> max_delay{},max_interruptions{};
  double max_lateness=0, resume_delay=-1;
  std::vector<double> sent_edges,rendered_edges,reverse_sent_edges,reverse_edges;
  bool was_high=false,reverse_was_high=false;
  for(int tick=0;tick<1200;++tick) {
    std::this_thread::sleep_until(origin+std::chrono::milliseconds(10*tick));
    max_lateness=std::max(max_lateness,milliseconds(Clock::now())-10*tick);
    const int phase=tick/400;
    if(tick%400==0) {
      assert(veil_media_test_audio_transport_budget(source.get(),phase==1 ? 48000 : 160000)==0);
      assert(veil_media_test_audio_transport_budget(receiver.get(),phase==1 ? 48000 : 160000)==0);
    }
    const bool high=(tick/100)%2;
    const bool paused=source_pause && tick>=500 && tick<620;
    if(high && tick%100==0) {
      if(!paused)sent_edges.push_back(milliseconds(Clock::now()));
      reverse_sent_edges.push_back(milliseconds(Clock::now()));
    }
    assert(veil_media_test_audio_capture_tone(source.get(),paused ? 0 : high ? 1200 : 440)==0);
    assert(veil_media_test_audio_capture_tone(receiver.get(),charged_duplex ? (high ? 1500 : 660) : 0)==0);
    deliver();assert(veil_media_test_audio_playout_pcm(receiver.get(),pcm.data(),pcm.size())==480);
    double power=0;int crossings=0;
    for(size_t i=0;i<pcm.size();++i){power+=double(pcm[i])*pcm[i];if(i && ((pcm[i]>0)!=(pcm[i-1]>0)))++crossings;}
    const bool nonsilent=power/pcm.size()>500*500;
    const bool rendered_high=nonsilent && crossings>=17;
    if(rendered_high && !was_high)rendered_edges.push_back(milliseconds(Clock::now()));
    was_high=rendered_high;
    assert(veil_media_test_audio_playout_pcm(source.get(),reverse_pcm.data(),reverse_pcm.size())==480);
    double reverse_power=0;
    int reverse_crossings=0;
    for(size_t i=0;i<reverse_pcm.size();++i) {
      reverse_power+=double(reverse_pcm[i])*reverse_pcm[i];
      if(i && ((reverse_pcm[i]>0)!=(reverse_pcm[i-1]>0)))++reverse_crossings;
    }
    const bool reverse_nonsilent=reverse_power/reverse_pcm.size()>500*500;
    const bool reverse_high=reverse_nonsilent && reverse_crossings>=23;
    if(reverse_high && !reverse_was_high)reverse_edges.push_back(milliseconds(Clock::now()));
    reverse_was_high=reverse_high;
    if(tick%400>=100) {
      if(reverse_nonsilent)++reverse_voiced[phase];
      if(tick%10==0)reverse_delay[phase]=std::max(reverse_delay[phase],metric(source.get(),"audio_delay_ms"));
    }
    if(source_pause && tick>=620 && nonsilent && resume_delay<0)
      resume_delay=milliseconds(Clock::now())-6200;
    if(tick%400>=100) {
      if(nonsilent)++voiced[phase];
      if(tick%100==0) std::printf("observe tick=%d codec=%llu estimate=%llu packets=%zu drops=%zu delay=%llu\n",tick,(unsigned long long)metric(source.get(),"audio_encoder_target_bps"),(unsigned long long)metric(source.get(),"audio_send_bandwidth_bps"),packets_by_phase[phase],drops_by_phase[phase],(unsigned long long)metric(receiver.get(),"audio_delay_ms"));
      if(tick%10==0){max_delay[phase]=std::max(max_delay[phase],metric(receiver.get(),"audio_delay_ms"));max_interruptions[phase]=metric(receiver.get(),"audio_interruption_count");}
    }
  }
  std::printf("adaptive encapsulation voiced=%zu/%zu/%zu delay_max=%llu/%llu/%llu interruptions=%llu/%llu/%llu packets=%zu/%zu/%zu drops=%zu/%zu/%zu wire_bytes=%zu/%zu/%zu lateness=%.2f markers=[",voiced[0],voiced[1],voiced[2],(unsigned long long)max_delay[0],(unsigned long long)max_delay[1],(unsigned long long)max_delay[2],(unsigned long long)max_interruptions[0],(unsigned long long)max_interruptions[1],(unsigned long long)max_interruptions[2],packets_by_phase[0],packets_by_phase[1],packets_by_phase[2],drops_by_phase[0],drops_by_phase[1],drops_by_phase[2],wire_bytes_by_phase[0],wire_bytes_by_phase[1],wire_bytes_by_phase[2],max_lateness);
  for(size_t i=0;i<sent_edges.size();++i){auto it=std::find_if(rendered_edges.begin(),rendered_edges.end(),[&](double x){return x>=sent_edges[i] && x<sent_edges[i]+800;});if(i)std::printf(",");std::printf("%.2f",it==rendered_edges.end() ? -1 : *it-sent_edges[i]);}
  std::puts("]");
  if(charged_duplex)std::printf("reverse voiced=%zu/%zu/%zu delay=%llu/%llu/%llu\n",reverse_voiced[0],reverse_voiced[1],reverse_voiced[2],(unsigned long long)reverse_delay[0],(unsigned long long)reverse_delay[1],(unsigned long long)reverse_delay[2]);
  std::printf("control admissions=%zu/%zu/%zu drops=%zu/%zu/%zu total_drops=%zu\n",control_admissions[0],control_admissions[1],control_admissions[2],control_drops[0],control_drops[1],control_drops[2],wire_drops);
  for(const auto& p:source_packets)std::printf("rtp at_us=%lld seq=%lld ts=%lld len=%lld source=%lld\n",p[0],p[1],p[2],p[3],p[4]);
  assert(max_lateness<30);
  for (size_t phase=0; phase<3; ++phase) {
    if(source_pause && phase==1)assert(voiced[phase]>=160 && voiced[phase]<=230);
    else assert(voiced[phase]==300);
    assert(reverse_voiced[phase]==300);
    assert(drops_by_phase[phase]==0 && control_drops[phase]==0);
    assert(max_delay[phase]<200 && reverse_delay[phase]<200);
    assert(max_interruptions[phase]==0);
  }
  std::printf("reverse PCM markers_ms=[");
  for(size_t i=0;i<reverse_sent_edges.size();++i) {
    auto next=std::find_if(reverse_edges.begin(),reverse_edges.end(),
                          [&](double rendered){return rendered>=reverse_sent_edges[i];});
    assert(next!=reverse_edges.end());
    double delay=*next-reverse_sent_edges[i];
    std::printf("%s%.2f",i ? "," : "",delay);
    assert(delay<300);
  }
  std::puts("]");
  if(source_pause) {
    std::printf("DTX resume_ms=%.2f\n",resume_delay);
    assert(resume_delay>=0 && resume_delay<300);
  }
  assert(metric(source.get(),"audio_interruption_count")==0);
  for (double edge:sent_edges) {
    auto next=std::find_if(rendered_edges.begin(),rendered_edges.end(),
                         [&](double rendered){return rendered>=edge;});
    assert(next!=rendered_edges.end() && *next-edge<300);
  }
}

int main(int argc, char** argv) {
  if (argc == 2 && std::strcmp(argv[1], "--adaptive-encapsulation-silence") == 0) {
    verify_adaptive_encapsulation(true);
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--adaptive-encapsulation") == 0) {
    verify_adaptive_encapsulation();
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--adaptive-bitrate") == 0) {
    verify_adaptive_bitrate();
    return 0;
  }
  recurring_jitter = argc == 2 && std::strcmp(argv[1], "--recurring-jitter") == 0;
  mature_jitter = argc == 2 && std::strcmp(argv[1], "--mature-jitter") == 0;
  if (argc == 2 && std::strcmp(argv[1], "--padding-liveness") == 0) {
    verify_padding_liveness();
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--sender-restart") == 0) {
    verify_sender_restart();
    return 0;
  }
  if (argc == 2 && std::strcmp(argv[1], "--silence-after-jitter") == 0) {
    verify_silence(true);
    return 0;
  }
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
    if (mature_jitter && capacity) continue;
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
    // Histogram startup gives recent arrivals extra weight. Warm the actual
    // receiver for 70 seconds before the same radio bursts, then measure 30
    // seconds of healthy PCM. A short startup test misses a mature tail.
    const int ticks = mature_jitter ? 11000 : recurring_jitter ? 3000 : 1400;
    for (int tick = 0; tick < ticks; ++tick) {
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
    if (max_tick_lateness >= 30)
      std::fprintf(stderr, "invalid PCM timing: maximum tick lateness %.2f ms\n",
          max_tick_lateness);
    assert(max_tick_lateness < 30); // overloaded host invalidates the experiment
    size_t packet_count;
    { std::lock_guard lock(mu); packet_count = sent_packets; }
    assert(packet_count > 300 && nonsilent_ticks > size_t(ticks - 500));
    assert(metric(receiver.get(), "audio_rx_pkts") > 300);
    std::printf("{\"mature_jitter\":%s,\"recurring_jitter\":%s,\"buffer_packets_override\":%zu,\"rtp_packets\":%zu,\"nonsilent_ticks\":%zu,"
                "\"max_tick_lateness_ms\":%.2f,\"max_filtered_delay_ms\":%llu,"
                "\"max_current_buffer_ms\":%llu,\"marker_latency_ms\":[",
        mature_jitter ? "true" : "false", recurring_jitter ? "true" : "false", capacity, packet_count, nonsilent_ticks, max_tick_lateness,
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
      if (!capacity) {
        if (mature_jitter) {
          // The healthy path resumes at 80 seconds. Bound the real PCM tail
          // after 15/17/19 seconds; merely reporting a lower gauge is not enough.
          if (source_edges[i] >= 95000) recovered &= latency < 300;
          if (source_edges[i] >= 97000) recovered &= latency < 220;
          if (source_edges[i] >= 99000) recovered &= latency < 180;
        } else if (recurring_jitter) {
          // The healthy path resumes at 12 seconds. Measure spoken markers
          // at 13/15/17 seconds and beyond, including the long recovery tail.
          if (i == 6) recovered &= latency < 400;
          if (i == 7) recovered &= latency < 300;
          if (i >= 8) recovered &= latency < 180;
        } else {
          if (i == 2 || i == 3) recovered &= latency < 400;
          // The 9-second marker of the unchanged control ranged from 170 to
          // 252 ms; its final 11/13-second markers returned below 180 ms.
          if (i == 4) recovered &= latency < 300;
          if (i >= 5) recovered &= latency < 180;
        }
      }
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
    else if (mature_jitter) {
      // The preceding policy concealed 11,336 samples in this ordered burst.
      // Give real PCM a 300-ms concealment budget, independently of the delay
      // gauge, and reject recovery by repeated buffer flushing/interruptions.
      assert(concealed < 14400);
      assert(flushes <= 1);
      assert(metric(receiver.get(), "audio_interruption_count") <= 1);
    } else {
      assert(concealed <= baseline_concealed + 2400); // <=50 ms extra at 48 kHz
      assert(flushes <= baseline_flushes);
    }

  }
}
