// Opt-in endpoint timing only. Never records PCM or writes on the audio thread.
#ifndef VEIL_PLAYOUT_TRACE_H_
#define VEIL_PLAYOUT_TRACE_H_
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include "rtc_base/time_utils.h"
#include "veil_diag_log.h"

namespace veil_media {
class PlayoutTrace {
 public:
  static constexpr size_t kLimit = 65536;
  PlayoutTrace() {
    const char* setting = std::getenv("VEIL_MEDIA_PLAYOUT_TRACE");
    if (setting && std::string(setting) == "1") {
      if (const char* path = diag::path()) {
        path_ = path;
        samples_.reserve(kLimit);
      }
    }
  }
  bool enabled() const { return !path_.empty(); }
  void Record(int64_t entered_us, int before_ms, int after_ms, int target_ms,
              unsigned skipped, bool fallback,
              int frame_headroom_ms = 0, int target_ceiling_ms = 0) {
    if (!enabled()) return;
    ++observed_;
    if (samples_.size() < kLimit) {
      samples_.push_back({entered_us, webrtc::TimeMicros(), before_ms, after_ms,
                          target_ms, skipped, fallback, frame_headroom_ms, target_ceiling_ms});
    }
  }
  ~PlayoutTrace() {
    if (!enabled()) return;
    // The NetEq owner destroys this only after its render calls have stopped.
    // Open once at teardown; never format, allocate or write during Record.
    FILE* file = std::fopen(path_.c_str(), "a");
    if (!file) return;
    std::fprintf(file, "audio.playout.begin count=%zu observed=%llu limit=%zu\n",
                 samples_.size(), (unsigned long long)observed_, kLimit);
    for (const auto& sample : samples_) {
      std::fprintf(file,
          "audio.playout entered_us=%lld exited_us=%lld before_ms=%d after_ms=%d target_ms=%d skipped=%u fallback=%d frame_headroom_ms=%d target_ceiling_ms=%d\n",
          (long long)sample.entered_us, (long long)sample.exited_us,
          sample.before_ms, sample.after_ms, sample.target_ms, sample.skipped,
          sample.fallback ? 1 : 0, sample.frame_headroom_ms, sample.target_ceiling_ms);
    }
    std::fclose(file);
  }
 private:
  struct Sample {
    int64_t entered_us, exited_us;
    int before_ms, after_ms, target_ms;
    unsigned skipped;
    bool fallback;
    int frame_headroom_ms, target_ceiling_ms;
  };
  std::string path_;
  std::vector<Sample> samples_;
  uint64_t observed_ = 0;
};
}  // namespace veil_media
#endif
