// SPDX-License-Identifier: MIT
#ifndef VEIL_VIDEO_BITRATE_SETTINGS_H_
#define VEIL_VIDEO_BITRATE_SETTINGS_H_

#include <algorithm>
#include "api/transport/bitrate_settings.h"

namespace veil_media {

// GCC's maximum is also a bandwidth-probe ceiling. An extra fixed allowance
// for RTX/RTCP here authorizes probes above the endpoint's selected video
// budget, especially at low rates. RTX history and RTCP remain enabled by the
// streams; their actual egress still needs to fit the chosen transport budget.
inline webrtc::BitrateSettings video_bitrate_settings(
    int selected_bps, bool independent_feedback, bool seed_estimate) {
  webrtc::BitrateSettings settings;
  settings.min_bitrate_bps = independent_feedback
      ? std::min(30'000, selected_bps) : selected_bps;
  if (seed_estimate) settings.start_bitrate_bps = selected_bps;
  settings.max_bitrate_bps = selected_bps;
  return settings;
}

}  // namespace veil_media
#endif
