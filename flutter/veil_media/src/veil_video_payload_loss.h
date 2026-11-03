#ifndef VEIL_VIDEO_PAYLOAD_LOSS_H_
#define VEIL_VIDEO_PAYLOAD_LOSS_H_

#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace veil_media {

// Sender-local bounded metadata, shared by fanout recipients, never put on the
// wire or in user reports. TWCC's transport sequence is not the RTP sequence:
// padding and retransmissions each consume it. A missing/expired slot makes
// classification unavailable; it must never be interpreted as padding.
class VideoPacketHistory {
 public:
  static constexpr size_t kCapacity = 4096;
  struct Packet {
    uint16_t transport_sequence = 0;
    uint64_t picture_packet = 0;  // RTP timestamp + sequence, not picture data.
    uint64_t ordinal = 0;
    int64_t sent_us = 0;
    bool payload = false;
  };
  void Record(uint16_t transport, uint16_t rtp, uint32_t timestamp,
              bool payload, int64_t now_us) {
    if (now_us <= 0) return;
    std::lock_guard lock(mu_);
    slots_[transport % kCapacity] = {transport,
        (uint64_t(timestamp) << 16) | rtp, ++ordinal_, now_us, payload};
  }
  std::optional<Packet> Find(uint16_t transport, int64_t now_us) const {
    std::lock_guard lock(mu_);
    const auto& p = slots_[transport % kCapacity];
    if (p.sent_us <= 0 || p.transport_sequence != transport ||
        now_us < p.sent_us || now_us - p.sent_us > 15'000'000) return {};
    return p;
  }
 private:
  mutable std::mutex mu_;
  std::array<Packet, kCapacity> slots_{};
  uint64_t ordinal_ = 0;
};

// Exact per-authenticated-peer TWCC evidence for the application quality
// ladder only. Padding still reaches GCC unchanged, including all its losses.
// Late originals or a successful same-RTP retransmission resolve a hole.
class VideoPayloadLoss {
 public:
  struct Status { VideoPacketHistory::Packet packet; bool received; };
  void Reset(int64_t began_us = 0) {
    *this = VideoPayloadLoss();
    began_us_ = began_us;
  }
  void Observe(const std::vector<Status>& statuses, bool all_known, int64_t now_us) {
    if (now_us <= 0) return;
    if (last_us_ > now_us) { Reset(now_us); return; }
    // Once a part of the report cannot be assigned, continuity is unknown.
    // Stay with RR until the next explicit source/route epoch. A later healthy
    // short TWCC must not conceal the unclassified earlier payload hole.
    if (!all_known) trusted_ = false;
    if (!trusted_) return;
    last_us_ = now_us;
    uint64_t high = high_;
    for (const auto& s : statuses) {
      if (s.packet.sent_us < began_us_) continue;
      high = std::max(high, s.packet.ordinal);
      if (!s.packet.payload || !s.received) continue;
      pending_.erase(s.packet.picture_packet);
      if (received_.insert(s.packet.picture_packet).second) {
        received_order_.push_back(s.packet.picture_packet);
        if (received_order_.size() > VideoPacketHistory::kCapacity) {
          received_.erase(received_order_.front());
          received_order_.pop_front();
        }
      }
    }
    for (const auto& s : statuses) {
      if (s.packet.sent_us < began_us_ || !s.packet.payload || s.received ||
          received_.contains(s.packet.picture_packet)) continue;
      pending_.try_emplace(s.packet.picture_packet, Pending{now_us, false});
    }
    if (pending_.size() > VideoPacketHistory::kCapacity) {
      trusted_ = false;
      pending_.clear();
      return;
    }
    // Replayed/reordered feedback may fill a hole, but cannot renew freshness
    // or turn the passage of wall time into a new loss confirmation.
    if (high <= high_) return;
    high_ = high;
    fresh_us_ = now_us;
    for (auto& [key, p] : pending_) {
      if (!p.reported && now_us - p.since_us >= 3'000'000) {
        p.reported = true;
        event_us_ = now_us;
      }
    }
  }
  bool FreshAt(int64_t now_us) const {
    return trusted_ && fresh_us_ > 0 && fresh_us_ <= now_us &&
           now_us - fresh_us_ <= 3'000'000;
  }
  int64_t event_us() const { return event_us_; }
 private:
  struct Pending { int64_t since_us; bool reported; };
  bool trusted_ = true;
  int64_t began_us_ = 0, last_us_ = 0, fresh_us_ = 0, event_us_ = 0;
  uint64_t high_ = 0;
  std::unordered_map<uint64_t, Pending> pending_;
  std::unordered_set<uint64_t> received_;
  std::deque<uint64_t> received_order_;
};

}  // namespace veil_media
#endif
