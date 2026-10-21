#ifndef VEIL_MEDIA_AUDIO_SEND_STATS_H_
#define VEIL_MEDIA_AUDIO_SEND_STATS_H_

#include <atomic>
#include <cstdint>
#include <span>

namespace veil_media {

struct RtpSendSnapshot {
  uint64_t attempts = 0;
  uint64_t queued = 0;
  uint64_t payload_packets = 0;
  uint64_t padding_packets = 0;
  uint64_t payload_bytes = 0;
  uint64_t padding_bytes = 0;
  uint64_t unclassified_packets = 0;
  int64_t payload_age_ms = -1;
  int64_t max_payload_gap_ms = 0;
  int64_t age_ms = -1;
  int64_t queue_age_ms = -1;
  int64_t max_gap_ms = 0;
  int64_t max_admission_ms = 0;
  uint64_t dropped = 0;
  // Complete RTP bytes for payload-carrying attempts, including their actual
  // CSRC/extensions/padding. Excludes padding-only and malformed packets.
  // Group fanout counts one attempt per peer; this is not an encoder total.
  uint64_t payload_rtp_bytes = 0;
  uint32_t payload_timestamp = 0;
  bool payload_timestamp_valid = false;
};

// Endpoint-only observations, before and after local Veil queue admission.
// A gap can be DTX silence or a capture/encoder pause; it is not a loss claim.
// No packet contents or roles are exposed to the underlying network transport.
class RtpSendStats {
 public:
  bool mark_attempt(std::span<const uint8_t> packet, uint32_t local_ssrc,
                    int64_t now_ns, uint8_t payload_type = 111) {
    if (local_ssrc == 0 || now_ns <= 0 || packet.size() < 12 ||
        (packet[0] >> 6) != 2 || (packet[1] & 0x7f) != payload_type) {
      return false;
    }
    const uint32_t ssrc = uint32_t(packet[8]) << 24 | uint32_t(packet[9]) << 16 |
                          uint32_t(packet[10]) << 8 | uint32_t(packet[11]);
    if (ssrc != local_ssrc) return false;
    const int64_t previous = last_attempt_ns_.exchange(now_ns, std::memory_order_relaxed);
    if (previous > 0 && now_ns >= previous) raise(max_gap_ns_, now_ns - previous);
    attempts_.fetch_add(1, std::memory_order_relaxed);
    // BWE padding shares the stream's payload type and SSRC, but contains no
    // encoded media. Count it separately so probes cannot make the encoder
    // appear active or hide a real capture gap. No payload data is retained.
    size_t header = 12 + (packet[0] & 0x0f) * 4;
    bool valid = header <= packet.size();
    if (valid && (packet[0] & 0x10)) {
      if (packet.size() - header < 4) {
        valid = false;
      } else {
        const size_t words = size_t(packet[header + 2]) * 256 + packet[header + 3];
        header += 4 + words * 4;
        valid = header <= packet.size();
      }
    }
    const size_t padding = (packet[0] & 0x20) ? packet.back() : 0;
    if (valid && (packet[0] & 0x20))
      valid = padding > 0 && padding <= packet.size() - header;
    if (!valid) {
      unclassified_packets_.fetch_add(1, std::memory_order_relaxed);
    } else {
      const size_t payload = packet.size() - header - padding;
      padding_bytes_.fetch_add(padding, std::memory_order_relaxed);
      if (payload == 0) {
        padding_packets_.fetch_add(1, std::memory_order_relaxed);
      } else {
        const uint32_t timestamp = uint32_t(packet[4]) << 24 | uint32_t(packet[5]) << 16 |
                                   uint32_t(packet[6]) << 8 | packet[7];
        uint64_t clock = payload_timestamp_.load(std::memory_order_relaxed);
        while ((!clock || (timestamp != uint32_t(clock) &&
                    uint32_t(timestamp - uint32_t(clock)) < 0x80000000u)) &&
               !payload_timestamp_.compare_exchange_weak(clock, (uint64_t(1) << 32) | timestamp,
                    std::memory_order_relaxed)) {}
        payload_packets_.fetch_add(1, std::memory_order_relaxed);
        payload_bytes_.fetch_add(payload, std::memory_order_relaxed);
        payload_rtp_bytes_.fetch_add(packet.size(), std::memory_order_relaxed);
        const int64_t previous_payload =
            last_payload_ns_.exchange(now_ns, std::memory_order_relaxed);
        if (previous_payload > 0 && now_ns >= previous_payload)
          raise(max_payload_gap_ns_, now_ns - previous_payload);
      }
    }
    return true;
  }

  void reset_payload_clock() { payload_timestamp_.store(0, std::memory_order_relaxed); }

  void mark_result(int64_t started_ns, int64_t now_ns, bool queued) {
    if (started_ns <= 0 || now_ns < started_ns) return;
    raise(max_admission_ns_, now_ns - started_ns);
    if (queued) {
      last_queued_ns_.store(now_ns, std::memory_order_relaxed);
      queued_.fetch_add(1, std::memory_order_relaxed);
    } else {
      // Count completed RTP failures directly. attempts - queued can include
      // a still-running admission; each stream uses its own counters.
      dropped_.fetch_add(1, std::memory_order_relaxed);
    }
  }

  RtpSendSnapshot snapshot(int64_t now_ns) const {
    const uint64_t payload_clock = payload_timestamp_.load(std::memory_order_relaxed);
    return {
        attempts_.load(std::memory_order_relaxed),
        queued_.load(std::memory_order_relaxed),
        payload_packets_.load(std::memory_order_relaxed),
        padding_packets_.load(std::memory_order_relaxed),
        payload_bytes_.load(std::memory_order_relaxed),
        padding_bytes_.load(std::memory_order_relaxed),
        unclassified_packets_.load(std::memory_order_relaxed),
        age(last_payload_ns_.load(std::memory_order_relaxed), now_ns),
        max_payload_gap_ns_.load(std::memory_order_relaxed) / 1'000'000,
        age(last_attempt_ns_.load(std::memory_order_relaxed), now_ns),
        age(last_queued_ns_.load(std::memory_order_relaxed), now_ns),
        max_gap_ns_.load(std::memory_order_relaxed) / 1'000'000,
        max_admission_ns_.load(std::memory_order_relaxed) / 1'000'000,
        dropped_.load(std::memory_order_relaxed),
        payload_rtp_bytes_.load(std::memory_order_relaxed),
        uint32_t(payload_clock),
        (payload_clock >> 32) != 0,
    };
  }

 private:
  static int64_t age(int64_t last_ns, int64_t now_ns) {
    return last_ns > 0 && now_ns >= last_ns ? (now_ns - last_ns) / 1'000'000 : -1;
  }
  static void raise(std::atomic<int64_t>& maximum, int64_t value) {
    int64_t old = maximum.load(std::memory_order_relaxed);
    while (value > old && !maximum.compare_exchange_weak(
                             old, value, std::memory_order_relaxed)) {}
  }
  std::atomic<uint64_t> attempts_{0};
  std::atomic<uint64_t> queued_{0};
  std::atomic<uint64_t> dropped_{0};
  std::atomic<uint64_t> payload_packets_{0}, padding_packets_{0};
  std::atomic<uint64_t> payload_bytes_{0}, padding_bytes_{0}, unclassified_packets_{0};
  std::atomic<uint64_t> payload_rtp_bytes_{0};
  std::atomic<uint64_t> payload_timestamp_{0};
  std::atomic<int64_t> last_payload_ns_{0}, max_payload_gap_ns_{0};
  std::atomic<int64_t> last_attempt_ns_{0};
  std::atomic<int64_t> last_queued_ns_{0};
  std::atomic<int64_t> max_gap_ns_{0};
  std::atomic<int64_t> max_admission_ns_{0};
};

using AudioSendSnapshot = RtpSendSnapshot;
using AudioSendStats = RtpSendStats;

}  // namespace veil_media
#endif
