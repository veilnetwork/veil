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
// Each lane has one outstanding drain task. PopLane releases its claim
// atomically with observing that lane empty, so a concurrent producer cannot lose its
// wakeup. Admission and copying also share this lock: multiple circuit feeds
// cannot collectively overshoot the memory limit.
class InboundPacketQueue {
 public:
  struct Packet {
    std::vector<uint8_t> bytes;
    int64_t arrived_us;
  };
  enum class Admission { Dropped, Queued, ScheduleDrain };
  static constexpr size_t kPrimaryPackets = 64;
  static constexpr size_t kSecondaryPackets = 192;
  static constexpr size_t kPrimaryBytes = 64 * 1024;
  static constexpr size_t kSecondaryBytes = 4 * 1024 * 1024 - kPrimaryBytes;

  Admission Push(std::span<const uint8_t> packet, int64_t arrived_us = 0) {
    return PushToLane(packet, IsSecondaryInboundRtp(packet), arrived_us);
  }

  // RTCP copies have independent bounds; the shim filters REMB targets before
  // delivery, while each Call selects its own ordinary report blocks/TWCC.
  Admission PushToLane(std::span<const uint8_t> packet, bool secondary,
                       int64_t arrived_us = 0) {
    std::lock_guard<std::mutex> lock(mu_);
    auto& lane = secondary ? secondary_ : primary_;
    const size_t max_packets = secondary ? kSecondaryPackets : kPrimaryPackets;
    const size_t max_bytes = secondary ? kSecondaryBytes : kPrimaryBytes;
    if (packet.empty() || lane.packets.size() >= max_packets ||
        packet.size() > max_bytes - lane.bytes) {
      return Admission::Dropped;
    }
    lane.packets.push_back(Packet{
        std::vector<uint8_t>(packet.begin(), packet.end()), arrived_us});
    lane.bytes += packet.size();
    if (lane.scheduled) return Admission::Queued;
    lane.scheduled = true;
    return Admission::ScheduleDrain;
  }

  // Independent consumers never wait for work in the other local lane.
  std::optional<Packet> PopLane(bool secondary) {
    std::lock_guard<std::mutex> lock(mu_);
    auto& lane = secondary ? secondary_ : primary_;
    if (lane.packets.empty()) {
      lane.scheduled = false;
      return std::nullopt;
    }
    auto packet = std::move(lane.packets.front());
    lane.packets.pop_front();
    lane.bytes -= packet.bytes.size();
    return packet;
  }

  // Stop discards pending packets without waiting for a stalled network task.
  // Keep its scheduling claim: if Start happens before that task runs, it
  // consumes the new packets instead of creating a second drain chain.
  void Clear() {
    std::lock_guard<std::mutex> lock(mu_);
    primary_.packets.clear();
    secondary_.packets.clear();
    primary_.bytes = secondary_.bytes = 0;
  }

 private:
  struct Lane {
    std::deque<Packet> packets;
    size_t bytes = 0;
    bool scheduled = false;
  };
  std::mutex mu_;
  Lane primary_;
  Lane secondary_;
};

}  // namespace veil_media
#endif  // VEIL_INBOUND_PACKET_QUEUE_H
