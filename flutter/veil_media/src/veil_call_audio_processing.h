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
inline webrtc::AudioProcessing::Config CallAudioProcessingConfig() {
  webrtc::AudioProcessing::Config config;
  config.gain_controller2.enabled = true;
  config.gain_controller2.adaptive_digital.enabled = true;
  config.gain_controller2.adaptive_digital.max_gain_db = 30.0f;
  config.gain_controller2.adaptive_digital.initial_gain_db = 6.0f;
  return config;
}
}  // namespace veil_media

#endif  // VEIL_CALL_AUDIO_PROCESSING_H_
