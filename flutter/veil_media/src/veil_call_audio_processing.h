/* SPDX-License-Identifier: MIT */
#ifndef VEIL_CALL_AUDIO_PROCESSING_H_
#define VEIL_CALL_AUDIO_PROCESSING_H_

#include "api/audio/audio_processing.h"

namespace veil_media {
// The direct Call API does not run WebRtcVoiceEngine::ApplyOptions. A bare
// BuiltinAudioProcessingBuilder leaves both gain controllers disabled. Our
// custom ADMs do not implement microphone-volume control, so requesting analog
// AGC cannot raise a quiet microphone either. Normalize capture in software,
// before Opus, for both direct and group calls. AGC2 includes a peak limiter;
// its noise estimate bounds amplification of room noise between words.
inline webrtc::AudioProcessing::Config CallAudioProcessingConfig(bool suppress_noise = true) {
  webrtc::AudioProcessing::Config config;
  // Direct Call does not apply VoiceEngine's normal voice options. Without
  // these flags loudspeaker audio is sent back as microphone capture, and
  // AGC alone may raise room noise. AudioState supplies the render reference.
  config.echo_canceller.enabled = true;
  config.noise_suppression.enabled = suppress_noise;
  config.noise_suppression.level =
      webrtc::AudioProcessing::Config::NoiseSuppression::kHigh;
  config.gain_controller2.enabled = true;
  config.gain_controller2.adaptive_digital.enabled = true;
  config.gain_controller2.adaptive_digital.max_gain_db = 30.0f;
  config.gain_controller2.adaptive_digital.initial_gain_db = 6.0f;
  return config;
}
// Control-thread configuration, serialized with APM's render/capture locks.
// Change only NS: disabling it must not disable AEC or reset the gain policy.
inline bool SetCallNoiseSuppression(webrtc::AudioProcessing* apm, bool enabled) {
  if (apm == nullptr) return false;
  auto config = apm->GetConfig();
  if (config.noise_suppression.enabled != enabled) {
    config.noise_suppression.enabled = enabled;
    apm->ApplyConfig(config);
  }
  return apm->GetConfig().noise_suppression.enabled == enabled;
}
}  // namespace veil_media

#endif  // VEIL_CALL_AUDIO_PROCESSING_H_
