/* SPDX-License-Identifier: MIT */
#ifndef VEIL_INBOUND_PACKET_QUEUE_H
#define VEIL_INBOUND_PACKET_QUEUE_H

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace veil_media {

// Endpoint-only scheduling, after the call's AEAD has opened the datagram.
// Nothing in this queue, including its lane choice, is sent to a relay.
// The native engine uses VP8 PT 96, Opus PT 111, and rtcp-mux. RTCP's full
// second byte is in 192..223, so it cannot match VP8 even with the RTP marker.
inline bool IsSecondaryInboundRtp(std::span<const uint8_t> packet) {
  return packet.size() >= 12 && (packet[0] >> 6) == 2 &&
         (packet[1] & 0x7f) == 96;
}

// Own the bounded packets separately from the WebRTC task queue: posting a
// task for every video packet would still put audio behind that entire FIFO.
// At most one drain task is outstanding. Pop releases that claim atomically
// with observing both queues empty, so a concurrent producer cannot lose its
// wakeup. Admission and copying also share this lock: multiple circuit feeds
// cannot collectively overshoot the memory limit.
class InboundPacketQueue {
 public:
  enum class Admission { Dropped, Queued, ScheduleDrain };
  static constexpr size_t kPrimaryPackets = 64;
  static constexpr size_t kSecondaryPackets = 192;
  static constexpr size_t kPrimaryBytes = 64 * 1024;
  static constexpr size_t kSecondaryBytes = 4 * 1024 * 1024 - kPrimaryBytes;
  static constexpr size_t kPrimaryBurst = 8;

  Admission Push(std::span<const uint8_t> packet) {
    const bool secondary = IsSecondaryInboundRtp(packet);
    std::lock_guard<std::mutex> lock(mu_);
    auto& lane = secondary ? secondary_ : primary_;
    const size_t max_packets = secondary ? kSecondaryPackets : kPrimaryPackets;
    const size_t max_bytes = secondary ? kSecondaryBytes : kPrimaryBytes;
    if (packet.empty() || lane.packets.size() >= max_packets ||
        packet.size() > max_bytes - lane.bytes) {
      return Admission::Dropped;
    }
    lane.packets.emplace_back(packet.begin(), packet.end());
    lane.bytes += packet.size();
    if (scheduled_) return Admission::Queued;
    scheduled_ = true;
    return Admission::ScheduleDrain;
  }

  // Called by the one scheduled consumer. Preserve FIFO within each lane and
  // bound primary bursts so continuous audio/control cannot starve video.
  std::optional<std::vector<uint8_t>> Pop() {
    std::lock_guard<std::mutex> lock(mu_);
    if (primary_.packets.empty() && secondary_.packets.empty()) {
      scheduled_ = false;
      primary_burst_ = 0;
      return std::nullopt;
    }
    const bool secondary = !secondary_.packets.empty() &&
                           (primary_.packets.empty() ||
                            primary_burst_ >= kPrimaryBurst);
    auto& lane = secondary ? secondary_ : primary_;
    auto packet = std::move(lane.packets.front());
    lane.packets.pop_front();
    lane.bytes -= packet.size();
    if (secondary) {
      primary_burst_ = 0;
    } else if (primary_burst_ < kPrimaryBurst) {
      ++primary_burst_;
    }
    return packet;
  }

  // Stop discards pending packets without waiting for a stalled network task.
  // Keep its scheduling claim: if Start happens before that task runs, it
  // consumes the new packets instead of creating a second drain chain.
  void Clear() {
    std::lock_guard<std::mutex> lock(mu_);
    primary_.packets.clear();
    secondary_.packets.clear();
    primary_.bytes = secondary_.bytes = primary_burst_ = 0;
  }

 private:
  struct Lane {
    std::deque<std::vector<uint8_t>> packets;
    size_t bytes = 0;
  };
  std::mutex mu_;
  Lane primary_;
  Lane secondary_;
  size_t primary_burst_ = 0;
  bool scheduled_ = false;
};

}  // namespace veil_media
#endif  // VEIL_INBOUND_PACKET_QUEUE_H
