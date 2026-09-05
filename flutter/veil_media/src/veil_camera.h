/* SPDX-License-Identifier: MIT
 *
 * veil_camera.h — a platform camera capturer that emits I420 frames.
 *
 * The capturer opens the default video camera and delivers each frame as a
 * (possibly strided) I420 buffer via the supplied callback, on the capture
 * queue. veil_media_engine.cc feeds those planes into the VP8 send stream with
 * push_i420, so the capturer stays free of any WebRTC types — only libyuv (for
 * the pixel-format conversion) which is already inside libwebrtc.a.
 *
 * macOS backs this with AVCaptureSession (veil_avf_camera.mm); other platforms
 * return null from the factory until their capturer lands (the caller then just
 * has no local video source — receive/render is unaffected).
 *
 * Pure-C++ header (no ObjC) so veil_media_engine.cc can call the factory.
 */
#ifndef VEIL_MEDIA_VEIL_CAMERA_H_
#define VEIL_MEDIA_VEIL_CAMERA_H_

#include <cstdint>
#include <functional>
#include <string>

namespace veil_media {

// Receives one captured frame as strided I420. Invoked on the capture queue;
// the planes are only valid for the duration of the call (copy synchronously).
using CameraFrameCb =
    std::function<void(const uint8_t* y, const uint8_t* u, const uint8_t* v,
                       int width, int height, int stride_y, int stride_u,
                       int stride_v, int64_t ts_us)>;

class CameraCapturer {
 public:
  virtual ~CameraCapturer() = default;
  // Start delivering frames near width x height at fps. The camera picks the
  // closest supported format; frames may differ in size. Returns false if the
  // camera can't be opened (no device, permission denied). Idempotent.
  virtual bool Start(int width, int height, int fps,
                     const char* device_id = nullptr) = 0;
  // Stop delivering frames and release the device. Idempotent.
  virtual void Stop() = 0;
  // Whether frames are actually flowing right now.
  //
  // NOT "was Start called and did it succeed". A capturer stops on its own
  // when the device goes away — the Media Foundation read returns
  // MF_E_VIDEO_RECORDING_DEVICE_INVALIDATED, v4l2 fails a select or a dequeue
  // — and the object outlives that with nothing behind it. Callers that keep
  // a capturer across a call have to be able to tell the two apart, or a
  // camera that died can never be restarted: the retry looks like a no-op
  // because the pointer is still there (report19 V19-M6, measured on Windows
  // 11 ARM64 2026-09-05).
  //
  // Pure, so a new backend cannot forget to answer it.
  virtual bool Capturing() const = 0;
};

// Creates the platform camera capturer, or null if this platform has none.
// The callback is retained for the capturer's lifetime.
CameraCapturer* CreatePlatformCamera(CameraFrameCb cb);

// Enumerate platform video inputs as a JSON array of MediaDevice-compatible
// objects. Device ids are opaque and may be passed back to Start().
std::string ListPlatformCamerasJson();

}  // namespace veil_media

#endif  // VEIL_MEDIA_VEIL_CAMERA_H_
