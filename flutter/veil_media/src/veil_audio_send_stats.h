#ifndef VEIL_MEDIA_AUDIO_SEND_STATS_H_
#define VEIL_MEDIA_AUDIO_SEND_STATS_H_

#include <atomic>
#include <cstdint>
#include <span>

namespace veil_media {

struct AudioSendSnapshot {
  uint64_t attempts = 0;
  uint64_t queued = 0;
  int64_t age_ms = -1;
  int64_t queue_age_ms = -1;
  int64_t max_gap_ms = 0;
  int64_t max_admission_ms = 0;
};

// Endpoint-only observations, before and after local Veil queue admission.
// A gap can be DTX silence or a capture/encoder pause; it is not a loss claim.
// No packet contents, SSRCs, timestamps or roles are sent on the network.
class AudioSendStats {
 public:
  bool mark_attempt(std::span<const uint8_t> packet, uint32_t audio_ssrc,
                    int64_t now_ns) {
    if (audio_ssrc == 0 || now_ns <= 0 || packet.size() < 12 ||
        (packet[0] >> 6) != 2 || (packet[1] & 0x7f) != 111) {
      return false;
    }
    const uint32_t ssrc = uint32_t(packet[8]) << 24 | uint32_t(packet[9]) << 16 |
                          uint32_t(packet[10]) << 8 | uint32_t(packet[11]);
    if (ssrc != audio_ssrc) return false;
    const int64_t previous = last_attempt_ns_.exchange(now_ns, std::memory_order_relaxed);
    if (previous > 0 && now_ns >= previous) raise(max_gap_ns_, now_ns - previous);
    attempts_.fetch_add(1, std::memory_order_relaxed);
    return true;
  }

  void mark_result(int64_t started_ns, int64_t now_ns, bool queued) {
    if (started_ns <= 0 || now_ns < started_ns) return;
    raise(max_admission_ns_, now_ns - started_ns);
    if (queued) {
      last_queued_ns_.store(now_ns, std::memory_order_relaxed);
      queued_.fetch_add(1, std::memory_order_relaxed);
    }
  }

  AudioSendSnapshot snapshot(int64_t now_ns) const {
    return {
        attempts_.load(std::memory_order_relaxed),
        queued_.load(std::memory_order_relaxed),
        age(last_attempt_ns_.load(std::memory_order_relaxed), now_ns),
        age(last_queued_ns_.load(std::memory_order_relaxed), now_ns),
        max_gap_ns_.load(std::memory_order_relaxed) / 1'000'000,
        max_admission_ns_.load(std::memory_order_relaxed) / 1'000'000,
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
  std::atomic<int64_t> last_attempt_ns_{0};
  std::atomic<int64_t> last_queued_ns_{0};
  std::atomic<int64_t> max_gap_ns_{0};
  std::atomic<int64_t> max_admission_ns_{0};
};

}  // namespace veil_media
#endif
