// Endpoint-only counters, shared by the group's fanout and peer receivers.
// Each accepted copy counts once; no role or counter is added to the wire.
#ifndef VEIL_RTCP_SEND_STATS_H_
#define VEIL_RTCP_SEND_STATS_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>

namespace veil_media {
inline constexpr size_t kRtcpKinds = 12;
inline constexpr std::array<const char*, kRtcpKinds> kRtcpKindNames = {
    "sr", "rr", "sdes", "bye", "app", "nack", "pli", "fir", "twcc",
    "remb", "xr", "other"};
struct RtcpSendSnapshot {
  uint64_t audio_packets, audio_bytes, video_packets, video_bytes;
  std::array<std::array<uint64_t, kRtcpKinds>, 2> blocks{};
  std::array<uint64_t, 2> malformed{};
};

class RtcpSendStats {
 public:
  void Record(size_t bytes, bool video) {
    auto& plane = planes_[video ? 1 : 0];
    plane.bytes.fetch_add(bytes, std::memory_order_relaxed);
    plane.packets.fetch_add(1, std::memory_order_relaxed);
  }

  // Compound blocks, not transport copies. Validate the complete common-header
  // framing before publishing any type count; retain no packet contents.
  void Record(std::span<const uint8_t> packet, bool video) {
    Record(packet.size(), video);
    auto& plane = planes_[video ? 1 : 0];
    std::array<uint64_t, kRtcpKinds> counts{};
    size_t at = 0, blocks = 0;
    bool valid = !packet.empty() && packet.size() <= 65536;
    while (valid && at < packet.size()) {
      if (packet.size() - at < 4 || packet[at] >> 6 != 2 ||
          packet[at + 1] < 192 || packet[at + 1] > 223 || ++blocks > 64) {
        valid = false;
        break;
      }
      const size_t bytes = (size_t(packet[at + 2]) * 256 + packet[at + 3] + 1) * 4;
      if (bytes > packet.size() - at ||
          ((packet[at] & 0x20) &&
           (at + bytes != packet.size() || packet[at + bytes - 1] == 0 ||
            packet[at + bytes - 1] > bytes - 4))) {
        valid = false;
        break;
      }
      const auto type = packet[at + 1];
      const auto fmt = packet[at] & 31;
      size_t kind = 11;
      if (type >= 200 && type <= 204) kind = type - 200;
      else if (type == 205 && fmt == 1) kind = 5;
      else if (type == 206 && fmt == 1) kind = 6;
      else if (type == 206 && fmt == 4) kind = 7;
      else if (type == 205 && fmt == 15) kind = 8;
      else if (type == 206 && fmt == 15 && bytes >= 16 &&
               packet[at + 12] == 'R' && packet[at + 13] == 'E' &&
               packet[at + 14] == 'M' && packet[at + 15] == 'B') kind = 9;
      else if (type == 207) kind = 10;
      ++counts[kind];
      at += bytes;
    }
    if (!valid) {
      plane.malformed.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    for (size_t i = 0; i < counts.size(); ++i)
      plane.blocks[i].fetch_add(counts[i], std::memory_order_relaxed);
  }

  RtcpSendSnapshot Snapshot() const {
    RtcpSendSnapshot out{planes_[0].packets.load(std::memory_order_relaxed),
            planes_[0].bytes.load(std::memory_order_relaxed),
            planes_[1].packets.load(std::memory_order_relaxed),
            planes_[1].bytes.load(std::memory_order_relaxed)};
    for (size_t p = 0; p < planes_.size(); ++p) {
      for (size_t k = 0; k < kRtcpKinds; ++k)
        out.blocks[p][k] = planes_[p].blocks[k].load(std::memory_order_relaxed);
      out.malformed[p] = planes_[p].malformed.load(std::memory_order_relaxed);
    }
    return out;
  }

 private:
  struct Plane {
    std::atomic<uint64_t> packets{0}, bytes{0};
    std::array<std::atomic<uint64_t>, kRtcpKinds> blocks{};
    std::atomic<uint64_t> malformed{0};
  };
  std::array<Plane, 2> planes_;
};
}  // namespace veil_media
#endif
