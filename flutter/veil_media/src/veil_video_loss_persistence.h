#ifndef VEIL_VIDEO_LOSS_PERSISTENCE_H_
#define VEIL_VIDEO_LOSS_PERSISTENCE_H_

#include <cstdint>

namespace veil_media {

// Application-level evidence only. Raw RR/SR still reaches native GCC/NACK.
// Cumulative loss can fall again when reordered RTP arrives. An interval's
// fractional loss alone must not immediately cut an otherwise usable camera.
class VideoLossPersistence {
 public:
  static constexpr int64_t kSettleUs = 3'000'000;

  // Returns a new event time only after an unrecovered increase survives the
  // settling interval AND a later sequence-progress report. Identical/replayed
  // reports cannot confirm it; historical loss starts a baseline.
  int64_t Observe(int32_t lost, uint32_t highest, int64_t now_us) {
    if (now_us <= 0) return 0;
    if (initialized_ && (now_us < last_us_ || now_us - last_us_ > 15'000'000)) Reset();
    if (initialized_ && static_cast<int32_t>(highest - highest_) < 0) return 0;
    const bool advanced = !initialized_ || static_cast<int32_t>(highest - highest_) > 0;
    if (!initialized_) {
      initialized_ = true;
      baseline_ = lost;
    }
    if (advanced || lost != last_lost_) last_us_ = now_us;
    highest_ = highest;
    last_lost_ = lost;
    if (lost <= baseline_) {
      baseline_ = lost;
      pending_us_ = 0;
      return 0;
    }
    if (!pending_us_) {
      pending_us_ = now_us;
      pending_highest_ = highest;
      return 0;
    }
    if (!advanced || now_us - pending_us_ < kSettleUs ||
        static_cast<int32_t>(highest - pending_highest_) <= 0) return 0;
    baseline_ = lost;
    pending_us_ = 0;
    return now_us;
  }

  void RouteChanged() {
    // Keep the live RTP sequence space and consume the old route's gap. A new
    // path must establish its own persistent increase before another cut.
    baseline_ = last_lost_;
    pending_us_ = 0;
  }
  void Reset() { *this = VideoLossPersistence(); }

 private:
  bool initialized_ = false;
  int32_t baseline_ = 0, last_lost_ = 0;
  uint32_t highest_ = 0, pending_highest_ = 0;
  int64_t last_us_ = 0, pending_us_ = 0;
};

}  // namespace veil_media
#endif
