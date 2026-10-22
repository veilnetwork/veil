#ifndef VEIL_AUDIO_PACKET_PRIORITY_H_
#define VEIL_AUDIO_PACKET_PRIORITY_H_

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>

namespace veil_media {

// One endpoint's encoder/source coordination. No network role, relay service
// class or bandwidth estimate is created here. Readers never block a worker.
class AudioPacketPriority {
 public:
  static constexpr int64_t kQuietUs = 2'000'000;

  void Enable() { enabled_.store(true, std::memory_order_release); }
  void Disable() { enabled_.store(false, std::memory_order_release); }
  // A source capped at <=1 fps may measure its sparse recovery trial while
  // Opus still needs 60-ms packets. Measured audio trouble can pause that
  // source normally; packet duration alone is not evidence of congestion.
  void AllowSparseVideo(bool allowed) { sparse_video_.store(allowed); }
  bool WantsLongPackets() const { return want_long_.load(); }
  void ExpectVideo(bool expected, int64_t now_us) {
    const bool old = expected_.exchange(expected);
    if (old && !expected) BeginQuiet(now_us);
  }
  void PauseVideo(bool paused, int64_t now_us) {
    const bool old = paused_.exchange(paused);
    if (!old && paused) BeginQuiet(now_us);
    if (old && !paused && !hold_.load()) quiet_us_.store(-1);
  }
  void WantLongPackets(bool wanted, int64_t now_us) {
    want_long_.store(wanted);
    (void)now_us;
    // A short allocation is not proof that Opus has emitted a short packet.
  }
  bool TryGrantLongPackets(int64_t now_us) {
    if (SparseVideoAllowed()) {
      hold_.store(true, std::memory_order_release);
      return true;
    }
    if (expected_.load() && !paused_.load() && !hold_.load() &&
        last_video_us_.load() >= 0) return false;
    const bool old_hold = hold_.exchange(true, std::memory_order_acq_rel);
    // Close the video admission gate before checking its last admission. A
    // concurrent resume cannot reopen video between proof and codec update.
    if ((expected_.load() && !paused_.load() && !old_hold &&
         last_video_us_.load() >= 0) ||
        !LongPacketsAllowed(now_us)) {
      hold_.store(old_hold, std::memory_order_release);
      return false;
    }
    return true;
  }
  void Encoded(int packet_ms) {
    audio_ms_.store(packet_ms);
    if (packet_ms > 0 && packet_ms <= 40 && !want_long_.load()) {
      hold_.store(false, std::memory_order_release);
      if (expected_.load() && !paused_.load()) quiet_us_.store(-1);
    }
  }
  void ResetAudio() { audio_ms_.store(0); }
  bool VideoHeldForAudio() const {
    return enabled_.load(std::memory_order_acquire) && expected_.load() &&
        (audio_ms_.load() == 0 ||
         (!sparse_video_.load() &&
          (hold_.load(std::memory_order_acquire) || audio_ms_.load() > 40)));
  }
  bool VideoBlocked() const {
    return (enabled_.load() && expected_.load() && paused_.load()) || VideoHeldForAudio();
  }
  bool LongPacketsAllowed(int64_t now_us) const {
    if (!enabled_.load(std::memory_order_acquire)) return true;
    if (SparseVideoAllowed()) return true;
    if (expected_.load() && !paused_.load() && !hold_.load()) return false;
    if (video_in_flight_.load(std::memory_order_acquire) != 0) return false;
    const int64_t last = last_video_us_.load(std::memory_order_acquire);
    // No video has ever entered this transport. A requested-but-blocked
    // first frame cannot require wasting two seconds of an audio-only call.
    if (last < 0) return true;
    const int64_t since = std::max(last, quiet_us_.load());
    return now_us >= since && now_us - since >= kQuietUs;
  }
  bool BeginVideo() {
    video_in_flight_.fetch_add(1, std::memory_order_acq_rel);
    if (enabled_.load(std::memory_order_acquire) &&
        (!expected_.load() || VideoBlocked())) {
      video_in_flight_.fetch_sub(1, std::memory_order_release);
      return false;
    }
    return true;
  }
  void EndVideo(bool admitted, int64_t now_us) {
    if (admitted) last_video_us_.store(now_us, std::memory_order_release);
    video_in_flight_.fetch_sub(1, std::memory_order_release);
  }

 private:
  bool SparseVideoAllowed() const {
    return sparse_video_.load() && expected_.load() && !paused_.load();
  }
  void BeginQuiet(int64_t now_us) {
    int64_t empty = -1;
    quiet_us_.compare_exchange_strong(empty, now_us);
  }
  std::atomic<bool> enabled_{false}, expected_{false}, paused_{false};
  std::atomic<bool> want_long_{false}, hold_{false};
  std::atomic<bool> sparse_video_{false};
  std::atomic<int> audio_ms_{0};
  std::atomic<unsigned> video_in_flight_{0};
  std::atomic<int64_t> quiet_us_{-1}, last_video_us_{-1};
};

// Opus synchronously constructs its ANA controllers during Enable. Keep this
// binding local to that stack, then let the created controller own its context.
// The trivial TLS pointer has no process-global registry or exit destructor.
inline thread_local const std::shared_ptr<AudioPacketPriority>*
    current_audio_packet_priority = nullptr;

class AudioPacketPriorityScope {
 public:
  explicit AudioPacketPriorityScope(const std::shared_ptr<AudioPacketPriority>& value)
      : previous_(current_audio_packet_priority) { current_audio_packet_priority = &value; }
  ~AudioPacketPriorityScope() { current_audio_packet_priority = previous_; }
  AudioPacketPriorityScope(const AudioPacketPriorityScope&) = delete;
  AudioPacketPriorityScope& operator=(const AudioPacketPriorityScope&) = delete;
 private:
  const std::shared_ptr<AudioPacketPriority>* previous_;
};

}  // namespace veil_media
#endif
