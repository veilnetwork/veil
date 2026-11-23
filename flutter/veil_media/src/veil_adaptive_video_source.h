// SPDX-License-Identifier: MIT
#ifndef VEIL_ADAPTIVE_VIDEO_SOURCE_H_
#define VEIL_ADAPTIVE_VIDEO_SOURCE_H_

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <limits>
#include <mutex>
#include <utility>
#include <memory>
#include "veil_video_frame_budget.h"
#include "api/video/i420_buffer.h"
#include "api/video/video_adapter.h"
#include "api/video/video_broadcaster.h"
#include "rtc_base/time_utils.h"

namespace veil_media {

inline bool TryAdvanceVideoCadence(std::atomic<int64_t>& last_slot_us,
                                   double fps, int64_t now_us) {
  if (fps <= 0) return true;
  const int64_t min_interval_us = static_cast<int64_t>(std::ceil(1'000'000.0 / fps));
  // Keep an ideal send timeline. A plain `now - last >= interval` gate turns a 60 Hz
  // source into 30 fps for every target between 31 and 59 because the first
  // 16 ms frame misses the threshold and the next accepted frame restarts the
  // interval. Advancing by exactly one interval preserves the fractional
  // credit and converges on targets such as 45 or 18 fps without bursts.
  const int64_t timing_tolerance_us =
      std::min<int64_t>(2'000, min_interval_us / 20);
  int64_t previous = last_slot_us.load(std::memory_order_relaxed);
  for (;;) {
    int64_t next = now_us;
    if (previous > 0) {
      // An early frame can already own a slot slightly in the future.
      const auto elapsed_us = now_us - previous + timing_tolerance_us;
      if (elapsed_us < min_interval_us) return false;
      // Once a full slot was missed, resume from this frame. Do not repay
      // missed slots with a burst of old credit when capture recovers.
      if (elapsed_us < min_interval_us * 2) next = previous + min_interval_us;
    }
    if (last_slot_us.compare_exchange_weak(
            previous, next, std::memory_order_relaxed,
            std::memory_order_relaxed)) {
      return true;
    }
  }
}

// Pushable camera/screen source. Preview owns the original capture separately.
class AdaptiveVideoSource final : public webrtc::VideoBroadcaster {
 public:
  explicit AdaptiveVideoSource(std::shared_ptr<VideoFrameBudget> budget = {})
      : budget_(std::move(budget)) {}
  void PushI420(webrtc::scoped_refptr<webrtc::I420Buffer> buffer, int64_t time_us) {
    if (!buffer || !frame_wanted()) return;
    time_us = time_us ? time_us : webrtc::TimeMicros();
    if (time_us < 0 || time_us > std::numeric_limits<int64_t>::max() / 1000) return;
    int cropped_width, cropped_height, width, height;
    bool wanted;
    {
      // Sink requests arrive on encoder/worker queues. Snapshot the current
      // combined request on capture, and serialize only the adapter decision;
      // never hold this lock while scaling pixels or calling an encoder sink.
      std::lock_guard<std::mutex> lock(adapter_mutex_);
      auto request = wants();
      const int cap = budget_ ? budget_->snapshot().max_pixels : 0;
      if (cap) {
        request.max_pixel_count = std::min(request.max_pixel_count, cap);
        if (request.target_pixel_count) {
          request.target_pixel_count = std::min(*request.target_pixel_count, cap);
        }
      }
      adapter_.OnSinkWants(request);
      wanted = adapter_.AdaptFrameResolution(buffer->width(), buffer->height(),
          time_us * 1000, &cropped_width, &cropped_height, &width, &height);
    }
    if (!wanted) {
      OnDiscardedFrame();
      return;
    }
    if (width != buffer->width() || height != buffer->height() ||
        cropped_width != buffer->width() || cropped_height != buffer->height()) {
      auto scaled = webrtc::I420Buffer::Create(width, height);
      scaled->CropAndScaleFrom(*buffer, (buffer->width() - cropped_width) / 2,
          (buffer->height() - cropped_height) / 2, cropped_width, cropped_height);
      buffer = std::move(scaled);
    }
    const auto frame = webrtc::VideoFrame::Builder()
                           .set_video_frame_buffer(buffer)
                           .set_timestamp_us(time_us)
                           .set_rotation(webrtc::kVideoRotation_0)
                           .build();
    OnFrame(frame);
  }

 private:
  const std::shared_ptr<VideoFrameBudget> budget_;
  std::mutex adapter_mutex_;
  webrtc::VideoAdapter adapter_{2};  // I420 chroma alignment, plus sink alignment.
};

}  // namespace veil_media
#endif
