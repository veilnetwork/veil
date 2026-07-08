/* SPDX-License-Identifier: MIT
 *
 * veil_avf_adm.h — a custom webrtc::AudioDeviceModule for macOS backed by
 * AVAudioEngine (AVFoundation) instead of the low-level CoreAudio HAL.
 *
 * The built-in macOS HAL ADM (kPlatformDefaultAudio) reports
 * RecordingIsAvailable=0 / PlayoutIsAvailable=0 and hangs in
 * InitRecording/InitPlayout inside this dylib embed, so no mic audio ever
 * reaches the send stream. AVAudioEngine integrates cleanly with the TCC mic
 * grant and device changes, and is the portable path (the same shape maps to
 * AVAudioEngine on iOS and AAudio/OpenSLES on Android later).
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
