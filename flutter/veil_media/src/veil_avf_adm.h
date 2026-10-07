/* SPDX-License-Identifier: MIT
 *
 * veil_avf_adm.h — a custom Apple webrtc::AudioDeviceModule backed by
 * AVAudioEngine (AVFoundation).
 *
 * This is the production iOS path because it owns the AVAudioSession voice
 * posture there and the normal macOS capture/playout path. Input is accessed
 * only after microphone authorization; hardware configuration changes are
 * recovered on the driver's serial queue.
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
#if defined(VEIL_MEDIA_TEST_HOOKS)
int TestVeilAvfConfigurationRecovery(webrtc::AudioDeviceModule* adm,
                                    bool pending_teardown);
#endif

}  // namespace veil_media
#endif  // VEIL_MEDIA_HAVE_WEBRTC

#endif  // VEIL_MEDIA_VEIL_AVF_ADM_H_
