// SPDX-License-Identifier: MIT
#ifndef VEIL_FRAME_SIZING_VP8_H_
#define VEIL_FRAME_SIZING_VP8_H_

#include <atomic>
#include <memory>
#include <utility>
#include "api/video_codecs/video_encoder.h"
#include "api/video_codecs/video_encoder_factory.h"
#include "rtc_base/time_utils.h"
#include "veil_video_frame_budget.h"

namespace veil_media {

// Observes complete encoded images before RTP packetization. Every image and
// callback result is forwarded unchanged, preserving the VP8 reference chain.
class FrameSizingVp8Encoder final : public webrtc::VideoEncoder,
                                    private webrtc::EncodedImageCallback {
 public:
  FrameSizingVp8Encoder(std::unique_ptr<webrtc::VideoEncoder> inner,
                        std::shared_ptr<VideoFrameBudget> budget)
      : inner_(std::move(inner)), budget_(std::move(budget)) {}

  void SetFecControllerOverride(webrtc::FecControllerOverride* controller) override {
    inner_->SetFecControllerOverride(controller);
  }
  int32_t InitEncode(const webrtc::VideoCodec* codec, int32_t cores,
                     size_t payload) override {
    budget_->SetPacketPayload(payload);
    return inner_->InitEncode(codec, cores, payload);
  }
  int InitEncode(const webrtc::VideoCodec* codec,
                 const Settings& settings) override {
    budget_->SetPacketPayload(settings.max_payload_size);
    return inner_->InitEncode(codec, settings);
  }
  int32_t RegisterEncodeCompleteCallback(webrtc::EncodedImageCallback* callback) override {
    callback_.store(callback, std::memory_order_release);
    return inner_->RegisterEncodeCompleteCallback(callback ? this : nullptr);
  }
  int32_t Release() override { return inner_->Release(); }
  int32_t Encode(const webrtc::VideoFrame& frame,
                 const std::vector<webrtc::VideoFrameType>* types) override {
    return inner_->Encode(frame, types);
  }
  void SetRates(const RateControlParameters& rates) override {
    budget_->SetRate(rates.bitrate.get_sum_bps(), rates.framerate_fps);
    inner_->SetRates(rates);
  }
  void OnPacketLossRateUpdate(float rate) override { inner_->OnPacketLossRateUpdate(rate); }
  void OnRttUpdate(int64_t rtt) override { inner_->OnRttUpdate(rtt); }
  void OnLossNotification(const LossNotification& notification) override {
    inner_->OnLossNotification(notification);
  }
  EncoderInfo GetEncoderInfo() const override { return inner_->GetEncoderInfo(); }

 private:
  Result OnEncodedImage(const webrtc::EncodedImage& image,
                        const webrtc::CodecSpecificInfo* info) override {
    budget_->Observe(image.size(), image._encodedWidth, image._encodedHeight,
                     image.RtpTimestamp(), webrtc::TimeMicros());
    auto* callback = callback_.load(std::memory_order_acquire);
    return callback ? callback->OnEncodedImage(image, info) : Result(Result::ERROR_SEND_FAILED);
  }
  void OnFrameDropped(uint32_t timestamp, int spatial_id, bool end) override {
    if (auto* callback = callback_.load(std::memory_order_acquire))
      callback->OnFrameDropped(timestamp, spatial_id, end);
  }
  std::unique_ptr<webrtc::VideoEncoder> inner_;
  const std::shared_ptr<VideoFrameBudget> budget_;
  std::atomic<webrtc::EncodedImageCallback*> callback_{nullptr};
};

class FrameSizingVp8EncoderFactory final : public webrtc::VideoEncoderFactory {
 public:
  FrameSizingVp8EncoderFactory(std::unique_ptr<webrtc::VideoEncoderFactory> inner,
                               std::shared_ptr<VideoFrameBudget> budget)
      : inner_(std::move(inner)), budget_(std::move(budget)) {}
  std::vector<webrtc::SdpVideoFormat> GetSupportedFormats() const override {
    return inner_->GetSupportedFormats();
  }
  std::vector<webrtc::SdpVideoFormat> GetImplementations() const override {
    return inner_->GetImplementations();
  }
  CodecSupport QueryCodecSupport(const webrtc::SdpVideoFormat& format,
      std::optional<std::string> mode, std::optional<webrtc::Resolution> resolution) const override {
    return inner_->QueryCodecSupport(format, mode, resolution);
  }
  std::unique_ptr<webrtc::VideoEncoder> Create(const webrtc::Environment& env,
      const webrtc::SdpVideoFormat& format) override {
    auto encoder = inner_->Create(env, format);
    return encoder ? std::make_unique<FrameSizingVp8Encoder>(std::move(encoder), budget_)
                   : nullptr;
  }
 private:
  std::unique_ptr<webrtc::VideoEncoderFactory> inner_;
  const std::shared_ptr<VideoFrameBudget> budget_;
};

}  // namespace veil_media
#endif
