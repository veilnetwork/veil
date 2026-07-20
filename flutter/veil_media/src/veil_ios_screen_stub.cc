/* SPDX-License-Identifier: MIT
 *
 * iOS has no unattended screen-capture surface equivalent to the macOS
 * AVCaptureScreenInput path. A future ReplayKit integration must be driven by
 * explicit user consent in the host app, so the native engine advertises no
 * screen capturer until that UI exists.
 */
#include "veil_screen.h"

namespace veil_media {

ScreenCapturer* CreatePlatformScreen(CameraFrameCb cb, const char* source_id) {
  (void)cb;
  (void)source_id;
  return nullptr;
}

std::string ListPlatformScreensJson() { return "[]"; }

}  // namespace veil_media
