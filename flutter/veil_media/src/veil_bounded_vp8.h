/* SPDX-License-Identifier: MIT
 *
 * veil_bounded_vp8.h — a VP8 decoder that reads a keyframe's declared size
 * before libvpx allocates from it.
 *
 * The call path bounds a decoded frame where it arrives (`VeilVideoSink`
 * refuses anything past `kMaxVideoSide`), and that is the wrong end for this
 * question: libvpx reads the keyframe's own 14-bit dimensions and sizes four
 * YV12 reference buffers from them BEFORE any callback of ours runs, and a
 * frame that fails to decode never reaches one at all. At the codec's maximum
 * of 16383 square that is about 1.5 GiB of allocation requests, chosen by
 * whoever sent the frame, in builds compiled `-fno-exceptions` where a refused
 * allocation aborts (report24 MEDIA-3).
 *
 * So the size is read from the frame and refused here, in the one place that
 * sees an ASSEMBLED encoded frame and still sits above the codec — not on a
 * single RTP fragment, which is not a frame, and not after the decode, which
 * is the guard that already exists. The sink keeps its own check: a decoder
 * may also report a size that disagrees with the keyframe it read.
 */

#ifndef VEIL_BOUNDED_VP8_H_
#define VEIL_BOUNDED_VP8_H_

#if defined(VEIL_MEDIA_HAVE_WEBRTC)

#include <memory>
#include <utility>
#include <vector>

#include "api/environment/environment.h"
#include "api/video_codecs/sdp_video_format.h"
#include "api/video_codecs/video_decoder.h"
#include "api/video_codecs/video_decoder_factory.h"
#include "modules/video_coding/include/video_error_codes.h"

#include "veil_vp8_header.h"

namespace veil_media {

/// Wraps one decoder and refuses a keyframe that declares more than
/// `max_side` on either edge.
class BoundedVp8Decoder : public webrtc::VideoDecoder {
 public:
  BoundedVp8Decoder(std::unique_ptr<webrtc::VideoDecoder> inner, int max_side)
      : inner_(std::move(inner)), max_side_(max_side) {}

  bool Configure(const Settings& settings) override {
    return inner_->Configure(settings);
  }

  int32_t Decode(const webrtc::EncodedImage& input_image,
                 int64_t render_time_ms) override {
    if (!admissible(input_image)) return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
    return inner_->Decode(input_image, render_time_ms);
  }

  int32_t Decode(const webrtc::EncodedImage& input_image, bool missing_frames,
                 int64_t render_time_ms) override {
    if (!admissible(input_image)) return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
    return inner_->Decode(input_image, missing_frames, render_time_ms);
  }

  int32_t RegisterDecodeCompleteCallback(
      webrtc::DecodedImageCallback* callback) override {
    return inner_->RegisterDecodeCompleteCallback(callback);
  }

  int32_t Release() override { return inner_->Release(); }

  DecoderInfo GetDecoderInfo() const override {
    return inner_->GetDecoderInfo();
  }

 private:
  /// Only a keyframe carries a size, and only a keyframe can change one: a
  /// delta frame is decoded against the reference buffers a keyframe already
  /// sized. A keyframe whose bytes are not a keyframe header is refused too —
  /// no reference chain can start from it, so nothing is lost by not trying.
  bool admissible(const webrtc::EncodedImage& image) const {
    if (image.FrameType() != webrtc::VideoFrameType::kVideoFrameKey) {
      return true;
    }
    const VeilVp8Size declared =
        veil_vp8_keyframe_size(image.data(), image.size());
    return declared.ok && declared.w <= max_side_ && declared.h <= max_side_;
  }

  std::unique_ptr<webrtc::VideoDecoder> inner_;
  int max_side_;
};

/// Wraps a factory so every decoder it hands out carries the bound.
class BoundedVp8DecoderFactory : public webrtc::VideoDecoderFactory {
 public:
  BoundedVp8DecoderFactory(std::unique_ptr<webrtc::VideoDecoderFactory> inner,
                           int max_side)
      : inner_(std::move(inner)), max_side_(max_side) {}

  std::vector<webrtc::SdpVideoFormat> GetSupportedFormats() const override {
    return inner_->GetSupportedFormats();
  }

  std::unique_ptr<webrtc::VideoDecoder> Create(
      const webrtc::Environment& env,
      const webrtc::SdpVideoFormat& format) override {
    std::unique_ptr<webrtc::VideoDecoder> inner = inner_->Create(env, format);
    if (inner == nullptr) return nullptr;
    return std::make_unique<BoundedVp8Decoder>(std::move(inner), max_side_);
  }

 private:
  std::unique_ptr<webrtc::VideoDecoderFactory> inner_;
  int max_side_;
};

}  // namespace veil_media

#endif  // VEIL_MEDIA_HAVE_WEBRTC
#endif  // VEIL_BOUNDED_VP8_H_
