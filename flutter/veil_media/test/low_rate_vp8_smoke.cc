// SPDX-License-Identifier: MIT
// Real encoder initialization verifies quality scaling on the bundled codec.
#include "veil_vp8_settings.h"
#include "api/environment/environment_factory.h"
#include "api/field_trials_view.h"
#include "modules/video_coding/codecs/vp8/include/vp8.h"
#include <cstdio>
#include <cstdlib>

static void require(bool value, const char* message) {
  if (!value) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
class Trials final : public webrtc::FieldTrialsView {
 public:
  std::string Lookup(absl::string_view key) const override {
    return key == "WebRTC-VideoRateControl" ? veil_media::vp8_rate_control_trial() : "";
  }
};
int main() {
  auto env = webrtc::CreateEnvironment(std::make_unique<Trials>());
  auto encoder = webrtc::CreateVp8Encoder(env);
  webrtc::VideoCodec codec;
  codec.codecType = webrtc::kVideoCodecVP8;
  codec.width = 320;
  codec.height = 240;
  codec.maxFramerate = 1;
  codec.startBitrate = 8;
  codec.minBitrate = 1;
  codec.maxBitrate = 8;
  codec.qpMax = 63;
  codec.active = true;
  codec.numberOfSimulcastStreams = 0;
  const auto config = veil_media::vp8_encoder_config();
  codec.SetFrameDropEnabled(config.frame_drop_enabled);
  config.encoder_specific_settings->FillEncoderSpecificSettings(&codec);
  require(codec.VP8()->keyFrameInterval == 240, "periodic keyframe recovery changed");
  webrtc::VideoEncoder::Settings settings(webrtc::VideoEncoder::Capabilities(false), 2, 1000);
  require(encoder->InitEncode(&codec, settings) == 0, "real low-rate VP8 initialization failed");
  const auto info = encoder->GetEncoderInfo();
  require(info.scaling_settings.thresholds.has_value(), "real VP8 quality scaling remains disabled");
  require(info.scaling_settings.min_pixels_per_frame < 320 * 180 &&
              info.scaling_settings.min_pixels_per_frame >= 64 * 48,
          "low-rate VP8 cannot reduce below the normal-resolution floor");
  require(info.requested_resolution_alignment > 0, "codec alignment disappeared");
  require(encoder->Release() == 0, "codec release failed");
  std::puts("ok real bundled VP8 low-rate quality scaling, pixel floor and recovery interval");
}
