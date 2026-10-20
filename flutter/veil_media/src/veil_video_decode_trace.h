/* SPDX-License-Identifier: MIT */
#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <vector>
#include "veil_diag_log.h"

namespace veil_media {
// Opt-in decoder output metadata, never pixels or file I/O on OnFrame.
// The owner fences its receive stream before releasing this recorder.
class VideoDecodeTrace {
 public:
  explicit VideoDecodeTrace(uint32_t ssrc = 0)
      : ssrc_(ssrc), enabled_(ssrc && diag::enabled()),
        id_(enabled_ ? ++next_id_ : 0) {
    if (enabled_) frames_.reserve(kLimit);
  }
  void Record(uint32_t timestamp, int64_t at_us, int width, int height) {
    if (!enabled_) return;
    std::lock_guard lock(mu_);
    ++seen_;
    if (frames_.size() < kLimit)
      frames_.push_back({timestamp, at_us, width, height});
  }
  ~VideoDecodeTrace() {
    if (!enabled_) return;
    const auto* path = diag::path();
    if (!path) return;
    std::lock_guard lock(mu_);
    FILE* file = std::fopen(path, "a");
    if (!file) return;
    std::fprintf(file, "video.decode.begin id=%llu ssrc=%u count=%zu seen=%llu\n",
        (unsigned long long)id_, ssrc_, frames_.size(), (unsigned long long)seen_);
    for (const auto& f : frames_)
      std::fprintf(file, "video.decode.frame id=%llu ssrc=%u timestamp=%u at_us=%lld width=%d height=%d\n",
          (unsigned long long)id_, ssrc_, f.timestamp, (long long)f.at_us, f.width, f.height);
    const bool ok = std::fflush(file) == 0 && !std::ferror(file);
    std::fprintf(file, "video.decode.end id=%llu write_ok=%d\n",
        (unsigned long long)id_, int(ok));
    std::fclose(file);
  }
 private:
  struct Frame { uint32_t timestamp; int64_t at_us; int width, height; };
  static constexpr size_t kLimit = 32768;
  inline static std::atomic<uint64_t> next_id_{0};
  const uint32_t ssrc_;
  const bool enabled_;
  const uint64_t id_;
  std::mutex mu_;
  uint64_t seen_ = 0;
  std::vector<Frame> frames_;
};
}  // namespace veil_media
