// SPDX-License-Identifier: MIT
#ifndef VEIL_AUDIO_RECOVERY_H_
#define VEIL_AUDIO_RECOVERY_H_
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace veil_media {
struct AudioRecoverySample {
  bool known = false;
  uint64_t origin = 0;
  uint64_t discarded_ms = 0;
  int64_t last_discard_us = 0;
};

// One writer: this NetEq's render callback. No allocation or registry lock is
// taken while dropping decoded speech. Publish time before the counter so an
// acquiring reader never sees a new count with an older event timestamp.
class StreamAudioRecovery {
 public:
  explicit StreamAudioRecovery(uint64_t origin) : origin_(origin) {}
  void Record(uint64_t ms, int64_t now_us) {
    if (!ms || now_us <= 0) return;
    last_discard_us_.store(now_us, std::memory_order_relaxed);
    discarded_ms_.fetch_add(ms, std::memory_order_release);
  }
  AudioRecoverySample Snapshot() const {
    const auto ms = discarded_ms_.load(std::memory_order_acquire);
    return {true, origin_, ms,
            last_discard_us_.load(std::memory_order_relaxed)};
  }

 private:
  const uint64_t origin_;
  std::atomic<uint64_t> discarded_ms_{0};
  std::atomic<int64_t> last_discard_us_{0};
};

// A call's configured receive streams, keyed after their first accepted RTP
// packet. Weak ownership retires counters with the actual decoder. Recreated
// receivers get a new origin; one participant never inherits another's loss.
class AudioRecoveryRegistry {
 public:
  std::shared_ptr<StreamAudioRecovery> NewStream() {
    return std::make_shared<StreamAudioRecovery>(next_origin_.fetch_add(1));
  }
  void Attach(uint32_t ssrc,
              const std::shared_ptr<StreamAudioRecovery>& stream) {
    std::lock_guard lock(mutex_);
    for (auto it = streams_.begin(); it != streams_.end();) {
      if (it->second.expired())
        it = streams_.erase(it);
      else
        ++it;
    }
    if (ssrc && (streams_.contains(ssrc) || streams_.size() < 128))
      streams_[ssrc] = stream;
  }
  AudioRecoverySample Snapshot(uint32_t ssrc) const {
    std::shared_ptr<StreamAudioRecovery> stream;
    {
      std::lock_guard lock(mutex_);
      const auto it = streams_.find(ssrc);
      if (it != streams_.end()) stream = it->second.lock();
    }
    return stream ? stream->Snapshot() : AudioRecoverySample{};
  }

 private:
  mutable std::mutex mutex_;
  std::unordered_map<uint32_t, std::weak_ptr<StreamAudioRecovery>> streams_;
  std::atomic<uint64_t> next_origin_{1};
};
}  // namespace veil_media
#endif
