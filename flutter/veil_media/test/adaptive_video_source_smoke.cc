// SPDX-License-Identifier: MIT
// Exercise real bundled sink requests and pixel/frame adaptation, no devices.
#include "veil_adaptive_video_source.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>

static void require(bool value, const char* message) {
  if (!value) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
class Sink final : public webrtc::VideoSinkInterface<webrtc::VideoFrame> {
 public:
  void OnFrame(const webrtc::VideoFrame& frame) override { last = frame; ++frames; }
  std::optional<webrtc::VideoFrame> last;
  int frames = 0;
};
int main() {
  auto input = webrtc::I420Buffer::Create(640, 480);
  std::memset(input->MutableDataY(), 90, input->StrideY() * input->height());
  std::memset(input->MutableDataU(), 128, input->StrideU() * input->ChromaHeight());
  std::memset(input->MutableDataV(), 200, input->StrideV() * input->ChromaHeight());
  veil_media::AdaptiveVideoSource source;
  Sink sink;
  webrtc::VideoSinkWants wants;
  source.AddOrUpdateSink(&sink, wants);
  source.PushI420(input, 1'000'000);
  require(sink.frames == 1 && sink.last->width() == 640, "unrestricted capture changed");
  require(sink.last->video_frame_buffer().get() == input.get(), "unrestricted capture copied pixels");
  wants.max_pixel_count = 320 * 240;
  wants.target_pixel_count = wants.max_pixel_count;
  source.AddOrUpdateSink(&sink, wants);
  source.PushI420(input, 2'000'000);
  require(sink.frames == 2 && sink.last->width() == 320 && sink.last->height() == 240,
          "source ignored encoder resolution reduction");
  require(sink.last->timestamp_us() == 2'000'000, "adaptation renewed capture timestamp");
  require(input->width() == 640 && input->DataY()[0] == 90, "adaptation changed preview pixels");
  wants.max_pixel_count = 160 * 120;
  wants.target_pixel_count = wants.max_pixel_count;
  wants.resolution_alignment = 8;
  source.AddOrUpdateSink(&sink, wants);
  source.PushI420(input, 3'000'000);
  require(sink.last->width() * sink.last->height() <= 160 * 120 &&
              sink.last->width() % 8 == 0 && sink.last->height() % 8 == 0,
          "repeated reduction ignored pixel bound or encoder alignment");
  require(sink.last->video_frame_buffer()->ToI420()->DataY()[0] == 90,
          "scaling damaged constant pixels");
  wants = webrtc::VideoSinkWants{};
  source.AddOrUpdateSink(&sink, wants);
  source.PushI420(input, 4'000'000);
  require(sink.last->width() == 640 && sink.last->height() == 480,
          "recovered source retained stale resolution restriction");
  source.RemoveSink(&sink);

  veil_media::AdaptiveVideoSource cadence;
  Sink limited;
  wants.max_framerate_fps = 10;
  cadence.AddOrUpdateSink(&limited, wants);
  for (int i = 0; i < 30; ++i) cadence.PushI420(input, 10'000'000 + i * 33'334);
  require(limited.frames >= 9 && limited.frames <= 11, "source ignored encoder cadence request");
  cadence.RemoveSink(&limited);
  std::puts("ok real video sink requests, reduction, alignment, recovery, cadence and preview ownership");
}
