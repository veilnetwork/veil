#include "veil_inbound_packet_queue.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <thread>
#include <vector>

using veil_media::InboundPacketQueue;
using Admission = InboundPacketQueue::Admission;

static std::vector<uint8_t> packet(bool video, uint32_t seq = 0,
                                   size_t size = 64) {
  assert(size >= 12);
  std::vector<uint8_t> p(size, 0);
  p[0] = 0x80;
  p[1] = video ? 96 : 111;
  for (int i = 0; i < 4; ++i) p[8 + i] = seq >> (24 - 8 * i);
  return p;
}

static uint32_t sequence(const std::vector<uint8_t>& p) {
  return uint32_t(p[8]) << 24 | uint32_t(p[9]) << 16 |
         uint32_t(p[10]) << 8 | p[11];
}

static void video_flood_leaves_audio_and_rtcp_space() {
  InboundPacketQueue q;
  for (size_t i = 0; i < InboundPacketQueue::kSecondaryPackets; ++i) {
    assert(q.Push(packet(true, i)) ==
           (i == 0 ? Admission::ScheduleDrain : Admission::Queued));
  }
  assert(q.Push(packet(true)) == Admission::Dropped);
  // This control packet arrives after the entire video burst. It and audio
  // must still be admitted, even before the network task can run.
  auto rtcp = packet(false);
  rtcp[1] = 200;
  assert(q.Push(rtcp) == Admission::Queued);
  for (size_t i = 1; i < InboundPacketQueue::kPrimaryPackets; ++i)
    assert(q.Push(packet(false, i)) == Admission::Queued);
  assert(q.Push(packet(false)) == Admission::Dropped);

  size_t primary = 0, secondary = 0, burst = 0;
  while (auto p = q.Pop()) {
    if (veil_media::IsSecondaryInboundRtp(*p)) {
      // Video also gets a turn under a sustained control/audio burst.
      if (primary < InboundPacketQueue::kPrimaryPackets)
        assert(burst == InboundPacketQueue::kPrimaryBurst);
      assert(sequence(*p) == secondary++);
      burst = 0;
    } else {
      if (primary == 0) assert(*p == rtcp);
      assert(sequence(*p) == primary++);
      ++burst;
    }
  }
  assert(primary == InboundPacketQueue::kPrimaryPackets);
  assert(secondary == InboundPacketQueue::kSecondaryPackets);
  assert(q.Push(packet(false)) == Admission::ScheduleDrain);
}

static void byte_limits_are_separate_and_rejection_does_not_arm_a_task() {
  InboundPacketQueue q;
  assert(q.Push(packet(false, 0, InboundPacketQueue::kPrimaryBytes + 1)) ==
         Admission::Dropped);
  assert(q.Push(packet(true, 0, InboundPacketQueue::kSecondaryBytes + 1)) ==
         Admission::Dropped);
  assert(q.Push(packet(true, 0, InboundPacketQueue::kSecondaryBytes)) ==
         Admission::ScheduleDrain);
  assert(q.Push(packet(true)) == Admission::Dropped);
  assert(q.Push(packet(false, 0, InboundPacketQueue::kPrimaryBytes)) ==
         Admission::Queued);
  assert(q.Push(packet(false)) == Admission::Dropped);
  assert(q.Pop()->size() == InboundPacketQueue::kPrimaryBytes);
  assert(q.Pop()->size() == InboundPacketQueue::kSecondaryBytes);
  assert(!q.Pop());
}

static void stop_and_restart_keep_one_drain_owner() {
  InboundPacketQueue q;
  assert(q.Push(packet(true)) == Admission::ScheduleDrain);
  q.Clear();  // the already posted network task is still stalled
  assert(q.Push(packet(false, 7)) == Admission::Queued);
  assert(sequence(*q.Pop()) == 7);  // that task consumes only the new session
  assert(!q.Pop());
  q.Clear();
  assert(q.Push(packet(true, 9)) == Admission::ScheduleDrain);
  q.Clear();
  assert(!q.Pop());
  assert(q.Push(packet(false, 11)) == Admission::ScheduleDrain);
}

static void parallel_circuit_feeds_cannot_overshoot_limits() {
  InboundPacketQueue q;
  std::atomic<size_t> accepted{0}, scheduled{0};
  std::vector<std::thread> producers;
  for (int i = 0; i < 16; ++i) {
    producers.emplace_back([&] {
      for (int j = 0; j < 128; ++j) {
        const auto result = q.Push(packet(true, j));
        if (result != Admission::Dropped) accepted.fetch_add(1);
        if (result == Admission::ScheduleDrain) scheduled.fetch_add(1);
      }
    });
  }
  for (auto& thread : producers) thread.join();
  assert(accepted == InboundPacketQueue::kSecondaryPackets);
  assert(scheduled == 1);
  size_t drained = 0;
  while (q.Pop()) ++drained;
  assert(drained == accepted);
  assert(q.Push(packet(false)) == Admission::ScheduleDrain);
}

static void concurrent_empty_transitions_do_not_lose_wakeups() {
  InboundPacketQueue q;
  std::mutex mu;
  std::condition_variable cv;
  size_t wakeups = 0;
  bool done = false;
  std::atomic<size_t> accepted{0};
  size_t received = 0;
  std::thread consumer([&] {
    int64_t previous[2] = {-1, -1};
    for (;;) {
      {
        std::unique_lock<std::mutex> lock(mu);
        assert(cv.wait_for(lock, std::chrono::seconds(2), [&] {
          return wakeups != 0 || done;
        }));
        if (wakeups == 0) break;
        assert(wakeups == 1);  // exactly one outstanding consumer claim
        --wakeups;
      }
      while (auto p = q.Pop()) {
        const size_t lane = veil_media::IsSecondaryInboundRtp(*p) ? 1 : 0;
        const auto seq = sequence(*p);
        assert(seq > previous[lane]);
        previous[lane] = seq;
        ++received;
        std::this_thread::yield();
      }
    }
  });
  auto produce = [&](bool video) {
    for (uint32_t seq = 0; seq < 20000; ++seq) {
      const auto result = q.Push(packet(video, seq));
      if (result != Admission::Dropped) accepted.fetch_add(1);
      if (result == Admission::ScheduleDrain) {
        std::lock_guard<std::mutex> lock(mu);
        ++wakeups;
        cv.notify_one();
      }
      if (seq % 4 == 0) std::this_thread::yield();
    }
  };
  std::thread audio(produce, false), video(produce, true);
  audio.join();
  video.join();
  {
    std::lock_guard<std::mutex> lock(mu);
    done = true;
    cv.notify_one();
  }
  consumer.join();
  assert(received == accepted);
  assert(!q.Pop());
}

int main() {
  auto video = packet(true);
  video[1] |= 0x80;
  assert(veil_media::IsSecondaryInboundRtp(video));
  video[0] = 0;
  assert(!veil_media::IsSecondaryInboundRtp(video));
  video[0] = 0x80;
  video.resize(11);
  assert(!veil_media::IsSecondaryInboundRtp(video));
  assert(!veil_media::IsSecondaryInboundRtp(packet(false)));
  for (int type = 192; type <= 223; ++type) {
    auto control = packet(false);
    control[1] = type;
    assert(!veil_media::IsSecondaryInboundRtp(control));
  }
  video_flood_leaves_audio_and_rtcp_space();
  byte_limits_are_separate_and_rejection_does_not_arm_a_task();
  stop_and_restart_keep_one_drain_owner();
  parallel_circuit_feeds_cannot_overshoot_limits();
  concurrent_empty_transitions_do_not_lose_wakeups();
  std::puts("inbound queue: audio/control reserve, bounded video, FIFO, fairness, restart and concurrent wakeups ok");
}
