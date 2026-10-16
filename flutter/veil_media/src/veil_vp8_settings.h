// SPDX-License-Identifier: MIT
#ifndef VEIL_VP8_SETTINGS_H_
#define VEIL_VP8_SETTINGS_H_

#include <string>
#include "api/video_codecs/video_codec.h"
#include "api/video_codecs/video_encoder.h"
#include "video/config/video_encoder_config.h"
#include "api/make_ref_counted.h"

namespace veil_media {

inline webrtc::VideoCodecVP8 vp8_codec_settings() {
  auto vp8 = webrtc::VideoEncoder::GetDefaultVp8Settings();
#if defined(__ANDROID__)
  // Camera2 already applies ISP noise reduction; avoid a second software pass.
  vp8.denoisingOn = false;
#endif
  // NACK repairs ordinary loss. A 60-frame interval repeatedly burst into the
  // uplink; 240 frames retains recovery without a full intra-frame every 2 s.
  vp8.keyFrameInterval = 240;
  // QualityScaler needs both this permission and codec frame dropping. The
  // default VP8 settings disable scaling even with MAINTAIN_FRAMERATE.
  vp8.automaticResizeOn = true;
  return vp8;
}

inline webrtc::VideoEncoderConfig vp8_encoder_config() {
  webrtc::VideoEncoderConfig config;
  config.codec_type = webrtc::kVideoCodecVP8;
  config.video_format = webrtc::SdpVideoFormat::VP8();
  config.encoder_specific_settings = webrtc::make_ref_counted<
      webrtc::VideoEncoderConfig::Vp8EncoderSpecificSettings>(vp8_codec_settings());
  config.content_type = webrtc::VideoEncoderConfig::ContentType::kRealtimeVideo;
  config.number_of_streams = 1;
  // Let the codec shed over-budget input before packetization, then request
  // fewer pixels through the adaptive source instead of growing RTP bursts.
  config.frame_drop_enabled = true;
  return config;
}

// A live-call fallback can operate far below the normal 320x180 floor.
// This permits (rather than forces) coarse frames while audio needs the link.
// Healthy encoders retain their full source resolution and original QP rails.
inline std::string vp8_rate_control_trial() { return "vp8_min_pixels:6144"; }

}  // namespace veil_media
#endif
