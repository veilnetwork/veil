/* SPDX-License-Identifier: MIT
 *
 * veil_screen.h — a platform screen capturer that emits I420 frames.
 *
 * The screen-share twin of veil_camera.h: opens the main display and delivers
 * each captured frame as strided I420 via the same CameraFrameCb shape, on the
 * capture queue. veil_media_engine.cc feeds the planes into the SAME VP8 send
 * source the camera uses — screen share is a source switch, not a new track,
 * so the receiving side needs nothing new to render it.
 *
 * macOS backs this with AVCaptureSession + AVCaptureScreenInput
 * (veil_avf_screen.mm); other platforms return null from the factory until
 * their capturer lands (Android needs the MediaProjection consent flow, which
 * lives app-side — see the engine's push_video_frame path).
 *
 * Pure-C++ header (no ObjC) so veil_media_engine.cc can call the factory.
 */
#ifndef VEIL_MEDIA_VEIL_SCREEN_H_
#define VEIL_MEDIA_VEIL_SCREEN_H_

#include "veil_camera.h"  // CameraFrameCb — the shared I420 frame callback

namespace veil_media {

class ScreenCapturer {
 public:
  virtual ~ScreenCapturer() = default;
  // Start delivering frames downscaled to <= width (aspect-preserved) at fps.
  // Returns false if capture can't start (no permission, no display).
  // Idempotent. NOTE: on macOS the first ever start triggers the OS
  // Screen Recording consent prompt; until granted the session runs but
  // delivers no usable frames — not a crash.
  virtual bool Start(int width, int fps) = 0;
  // Stop delivering frames and release the capture. Idempotent.
  virtual void Stop() = 0;
};

// Creates the platform screen capturer, or null if this platform has none.
// The callback is retained for the capturer's lifetime.
ScreenCapturer* CreatePlatformScreen(CameraFrameCb cb);

}  // namespace veil_media

#endif  // VEIL_MEDIA_VEIL_SCREEN_H_
