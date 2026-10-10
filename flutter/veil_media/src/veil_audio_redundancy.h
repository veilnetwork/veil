#ifndef VEIL_MEDIA_AUDIO_REDUNDANCY_H_
#define VEIL_MEDIA_AUDIO_REDUNDANCY_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace veil_media {

// Endpoint-only selection. Nothing below is a relay-visible traffic class.
// The key identifies one packet in the pinned Opus RTP stream; padding and
// malformed/foreign packets must not enter either the mirror or its history.
inline std::optional<uint64_t> AudioPayloadKey(
    std::span<const uint8_t> packet, uint32_t expected_ssrc) {
  if (!expected_ssrc || packet.size() < 12 || packet[0] >> 6 != 2 ||
      (packet[1] & 0x7f) != 111) return std::nullopt;
  const auto be32 = [](const uint8_t* p) {
    return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 |
           uint32_t(p[2]) << 8 | uint32_t(p[3]);
  };
  if (be32(packet.data() + 8) != expected_ssrc) return std::nullopt;
  size_t header = 12 + (packet[0] & 15) * 4;
  if (header > packet.size()) return std::nullopt;
  if (packet[0] & 16) {
    if (packet.size() - header < 4) return std::nullopt;
    const size_t words = size_t(packet[header + 2]) * 256 + packet[header + 3];
    header += 4 + words * 4;
    if (header > packet.size()) return std::nullopt;
  }
  const size_t padding = packet[0] & 32 ? packet.back() : 0;
  if ((packet[0] & 32) && (!padding || padding > packet.size() - header))
    return std::nullopt;
  if (packet.size() - header - padding == 0) return std::nullopt;
  return uint64_t(be32(packet.data() + 4)) << 16 |
         uint64_t(packet[2]) << 8 | packet[3];
}

// Audio network-queue ownership only. Bounded by packet count, independent of
// arrival order, sequence/timestamp wrap, and cipher epochs on two routes.
// Keep the last 4096 distinct packets (~82 s at 50 payload packets/s). Older
// copies are also subject to the encrypted replay window and NetEq's buffer.
class AudioPacketHistory {
 public:
  static constexpr size_t capacity = 4096;
  bool accept(uint64_t key) {
    if (std::find(keys_.begin(), keys_.begin() + count_, key) !=
        keys_.begin() + count_) return false;
    keys_[next_] = key;
    next_ = (next_ + 1) % capacity;
    if (count_ < capacity) ++count_;
    return true;
  }
 private:
  std::array<uint64_t, capacity> keys_{};
  size_t count_ = 0, next_ = 0;
};

}  // namespace veil_media
#endif
