#ifndef VEIL_VIDEO_LOSS_PERSISTENCE_H_
#define VEIL_VIDEO_LOSS_PERSISTENCE_H_

#include <cstdint>
#include <optional>

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
    if (now_us <= resumed_us_) return 0;
    if (resume_sequence_) {
      // A report ending within the pre-pause sequence range can arrive
      // after the source restarts. Baseline on the first report that
      // covers the resumed stream, where cumulative loss may include gaps
      // the peer could not observe before the pause. Once the serial-number
      // witness is too old to use, fall back to the normal first-report rule.
      const auto advance = static_cast<int16_t>(
          static_cast<uint16_t>(highest - *resume_sequence_));
      if (now_us - resumed_us_ <= kExpiryUs && advance <= 0) return 0;
      resume_sequence_.reset();
    }
    if (initialized_ && (now_us < last_us_ || now_us - last_us_ > kExpiryUs)) Reset();
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
  void ResumeAfter(std::optional<uint16_t> sent, int64_t now_us) {
    // WebRTC can allocate sequence numbers to packets the transport held
    // during the pause, after the last visible send. Even a report covering
    // every earlier transmission cannot attribute that transition's gaps.
    Reset();
    resume_sequence_ = sent;
    resumed_us_ = now_us;
  }
  void Reset() { *this = VideoLossPersistence(); }

 private:
  static constexpr int64_t kExpiryUs = 15'000'000;
  bool initialized_ = false;
  int32_t baseline_ = 0, last_lost_ = 0;
  uint32_t highest_ = 0, pending_highest_ = 0;
  int64_t last_us_ = 0, pending_us_ = 0;
  std::optional<uint16_t> resume_sequence_;
  int64_t resumed_us_ = 0;
};

}  // namespace veil_media
#endif
