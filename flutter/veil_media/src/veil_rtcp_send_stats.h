// Endpoint-only counters, shared by the group's fanout and peer receivers.
// Each accepted copy counts once; no role or counter is added to the wire.
#ifndef VEIL_RTCP_SEND_STATS_H_
#define VEIL_RTCP_SEND_STATS_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace veil_media {
struct RtcpSendSnapshot {
  uint64_t audio_packets, audio_bytes, video_packets, video_bytes;
};

class RtcpSendStats {
 public:
  void Record(size_t bytes, bool video) {
    auto& plane = planes_[video ? 1 : 0];
    plane.bytes.fetch_add(bytes, std::memory_order_relaxed);
    plane.packets.fetch_add(1, std::memory_order_relaxed);
  }

  RtcpSendSnapshot Snapshot() const {
    return {planes_[0].packets.load(std::memory_order_relaxed),
            planes_[0].bytes.load(std::memory_order_relaxed),
            planes_[1].packets.load(std::memory_order_relaxed),
            planes_[1].bytes.load(std::memory_order_relaxed)};
  }

 private:
  struct Plane {
    std::atomic<uint64_t> packets{0}, bytes{0};
  };
  std::array<Plane, 2> planes_;
};
}  // namespace veil_media
#endif
