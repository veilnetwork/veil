/* SPDX-License-Identifier: MIT
 *
 * veil_aaudio_adm.h — a custom webrtc::AudioDeviceModule for Android backed by
 * AAudio (NDK, JNI-free), mirroring veil_avf_adm on macOS.
 *
 * WebRTC's built-in Android ADM needs a JavaVM + application Context (JNI) for
 * AudioManager; wiring that through the Flutter FFI plugin is fragile. AAudio is
 * a pure-NDK C API (API 26+) so a custom ADM stays self-contained inside the
 * .so — same shape as the macOS AVAudioEngine ADM (AudioDeviceModuleDefault +
 * AudioDeviceBuffer + FineAudioBuffer), just with AAudio input/output streams.
 *
 * Pure-C++ header so veil_media_engine.cc can call the factory.
 */
#ifndef VEIL_MEDIA_VEIL_AAUDIO_ADM_H_
#define VEIL_MEDIA_VEIL_AAUDIO_ADM_H_

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
#include "api/audio/audio_device.h"
#include "api/environment/environment.h"
#include "api/scoped_refptr.h"

namespace veil_media {

// Returns an AudioDeviceModule that captures the mic and renders playout via
// AAudio. 48 kHz, mono, 16-bit into WebRTC (the actual stream rate/channels are
// read back from AAudio and pushed into the AudioDeviceBuffer). Never null.
webrtc::scoped_refptr<webrtc::AudioDeviceModule> CreateVeilAAudioAdm(
    const webrtc::Environment& env);

}  // namespace veil_media
#endif  // VEIL_MEDIA_HAVE_WEBRTC

#endif  // VEIL_MEDIA_VEIL_AAUDIO_ADM_H_
