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
  assert(q.Push(rtcp) == Admission::ScheduleDrain);
  for (size_t i = 1; i < InboundPacketQueue::kPrimaryPackets; ++i)
    assert(q.Push(packet(false, i)) == Admission::Queued);
  assert(q.Push(packet(false)) == Admission::Dropped);

  size_t primary = 0, secondary = 0;
  while (auto p = q.PopLane(false)) {
    if (primary == 0) assert(p->bytes == rtcp);
    assert(sequence(p->bytes) == primary++);
  }
  while (auto p = q.PopLane(true)) assert(sequence(p->bytes) == secondary++);
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
         Admission::ScheduleDrain);
  assert(q.Push(packet(false)) == Admission::Dropped);
  assert(q.PopLane(false)->bytes.size() == InboundPacketQueue::kPrimaryBytes);
  assert(q.PopLane(true)->bytes.size() == InboundPacketQueue::kSecondaryBytes);
  assert(!q.PopLane(false));
  assert(!q.PopLane(true));
}

static void stop_and_restart_keep_one_drain_owner() {
  InboundPacketQueue q;
  assert(q.Push(packet(true)) == Admission::ScheduleDrain);
  q.Clear();  // the already posted network task is still stalled
  assert(q.Push(packet(true, 7)) == Admission::Queued);
  assert(sequence(q.PopLane(true)->bytes) == 7);  // that task consumes only the new session
  assert(!q.PopLane(true));
  q.Clear();
  assert(q.Push(packet(true, 9)) == Admission::ScheduleDrain);
  q.Clear();
  assert(!q.PopLane(true));
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
  while (q.PopLane(true)) ++drained;
  assert(drained == accepted);
  assert(q.Push(packet(false)) == Admission::ScheduleDrain);
}

static void concurrent_empty_transitions_do_not_lose_wakeups() {
  InboundPacketQueue q;
  std::mutex mu;
  std::condition_variable cv;
  size_t wakeups[2] = {0, 0};
  bool done = false;
  std::atomic<size_t> accepted{0};
  std::atomic<size_t> received{0};
  auto consume = [&](size_t lane) {
    int64_t previous = -1;
    for (;;) {
      {
        std::unique_lock<std::mutex> lock(mu);
        assert(cv.wait_for(lock, std::chrono::seconds(2), [&] {
          return wakeups[lane] != 0 || done;
        }));
        if (wakeups[lane] == 0) break;
        assert(wakeups[lane] == 1);  // exactly one outstanding consumer claim
        --wakeups[lane];
      }
      while (auto p = q.PopLane(lane == 1)) {
        assert(veil_media::IsSecondaryInboundRtp(p->bytes) == (lane == 1));
        const auto seq = sequence(p->bytes);
        assert(seq > previous);
        previous = seq;
        ++received;
        std::this_thread::yield();
      }
    }
  };
  std::thread primary(consume, 0), secondary(consume, 1);
  auto produce = [&](bool video) {
    for (uint32_t seq = 0; seq < 20000; ++seq) {
      const auto result = q.Push(packet(video, seq));
      if (result != Admission::Dropped) accepted.fetch_add(1);
      if (result == Admission::ScheduleDrain) {
        std::lock_guard<std::mutex> lock(mu);
        ++wakeups[video ? 1 : 0];
        cv.notify_all();
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
    cv.notify_all();
  }
  primary.join();
  secondary.join();
  assert(received == accepted);
  assert(!q.PopLane(false));
  assert(!q.PopLane(true));
}

static void independent_drains_survive_a_stalled_secondary_and_restart() {
  InboundPacketQueue q;
  assert(q.Push(packet(true, 1)) == Admission::ScheduleDrain);
  assert(q.Push(packet(true, 2)) == Admission::Queued);
  assert(q.Push(packet(false, 3)) == Admission::ScheduleDrain);
  assert(sequence(q.PopLane(false)->bytes) == 3);
  assert(!q.PopLane(false));
  // Secondary still owns its queued drain; new primary work arms its own.
  assert(q.Push(packet(false, 4)) == Admission::ScheduleDrain);
  q.Clear();
  assert(q.Push(packet(false, 5)) == Admission::Queued);
  assert(q.Push(packet(true, 6)) == Admission::Queued);
  assert(sequence(q.PopLane(false)->bytes) == 5);
  assert(!q.PopLane(false));
  assert(sequence(q.PopLane(true)->bytes) == 6);
  assert(!q.PopLane(true));
  auto rtcp = packet(false, 7);
  rtcp[1] = 201;
  for (size_t i = 0; i < InboundPacketQueue::kSecondaryPackets; ++i) {
    const auto a = q.PushToLane(rtcp, true);
    assert(a == (i == 0 ? Admission::ScheduleDrain : Admission::Queued));
  }
  assert(q.PushToLane(rtcp, true) == Admission::Dropped);
  assert(q.Push(rtcp) == Admission::ScheduleDrain);
  assert(sequence(q.PopLane(false)->bytes) == 7);
  assert(!q.PopLane(false));
  size_t count = 0;
  while (q.PopLane(true)) ++count;
  assert(count == InboundPacketQueue::kSecondaryPackets);
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
  {
    InboundPacketQueue q;
    assert(q.Push(packet(true, 1), 12345) == Admission::ScheduleDrain);
    assert(q.Push(packet(false, 2), 12346) == Admission::ScheduleDrain);
    assert(q.PopLane(false)->arrived_us == 12346);
    assert(q.PopLane(true)->arrived_us == 12345);
  }
  independent_drains_survive_a_stalled_secondary_and_restart();
  video_flood_leaves_audio_and_rtcp_space();
  byte_limits_are_separate_and_rejection_does_not_arm_a_task();
  stop_and_restart_keep_one_drain_owner();
  parallel_circuit_feeds_cannot_overshoot_limits();
  concurrent_empty_transitions_do_not_lose_wakeups();
  std::puts("inbound queue: audio/control reserve, bounded video, FIFO, independent drains, restart and concurrent wakeups ok");
}
