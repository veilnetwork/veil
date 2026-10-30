/* SPDX-License-Identifier: MIT */
#pragma once

namespace veil_media {
// WebRTC RMS level (0..32767) -> coarse amplitude bands only. No PCM, raw
// energy or per-frame envelope is exported. -1 unavailable; 0 digital silence;
// 1 <= -60 dBFS; 2 <= -45; 3 <= -30; 4 <= -15; 5 above -15.
constexpr int AudioLevelBand(int level) {
  if (level < 0 || level > 32767) return -1;
  if (level == 0) return 0;
  if (level <= 32) return 1;
  if (level <= 184) return 2;
  if (level <= 1036) return 3;
  if (level <= 5827) return 4;
  return 5;
}
}  // namespace veil_media
