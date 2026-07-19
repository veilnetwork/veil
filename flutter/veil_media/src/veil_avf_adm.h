/* SPDX-License-Identifier: MIT
 *
 * veil_avf_adm.h — a custom Apple webrtc::AudioDeviceModule backed by
 * AVAudioEngine (AVFoundation).
 *
 * This is the production iOS path because it owns the AVAudioSession voice
 * posture there. macOS normally uses WebRTC's lower-level CoreAudio HAL ADM:
 * recent macOS releases can wedge forever while constructing
 * AVAudioEngine.inputNode, so this implementation is only an explicit
 * diagnostic fallback on desktop.
 *
 * Pure-C++ header (no ObjC) so veil_media_engine.cc can call the factory; the
 * implementation lives in veil_avf_adm.mm.
 */
#ifndef VEIL_MEDIA_VEIL_AVF_ADM_H_
#define VEIL_MEDIA_VEIL_AVF_ADM_H_

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
#include "api/audio/audio_device.h"
#include "api/environment/environment.h"
#include "api/scoped_refptr.h"

namespace veil_media {

// Returns an AudioDeviceModule that captures the mic and renders playout via
// AVAudioEngine. 48 kHz, mono, 16-bit into WebRTC. Never null.
webrtc::scoped_refptr<webrtc::AudioDeviceModule> CreateVeilAvfAdm(
    const webrtc::Environment& env);

}  // namespace veil_media
#endif  // VEIL_MEDIA_HAVE_WEBRTC

#endif  // VEIL_MEDIA_VEIL_AVF_ADM_H_
