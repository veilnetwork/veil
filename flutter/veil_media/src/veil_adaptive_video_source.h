// SPDX-License-Identifier: MIT
#ifndef VEIL_ADAPTIVE_VIDEO_SOURCE_H_
#define VEIL_ADAPTIVE_VIDEO_SOURCE_H_

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
