// SPDX-License-Identifier: MIT
// Real bundled GCC: discovery remains enabled within the chosen video budget.
#include "video_bitrate_settings.h"
#include "api/field_trials_view.h"
#include "api/rtc_event_log/rtc_event_log.h"
#include "modules/congestion_controller/goog_cc/probe_controller.h"
#include <cstdio>
#include <cstdlib>

static void require(bool value, const char* message) {
  if (!value) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}

class DefaultTrials final : public webrtc::FieldTrialsView {
 public:
  std::string Lookup(absl::string_view) const override { return ""; }
};

static void bounded(const std::vector<webrtc::ProbeClusterConfig>& probes,
                    int selected_bps) {
  for (const auto& probe : probes) {
    require(probe.target_data_rate <= webrtc::DataRate::BitsPerSec(selected_bps),
            "video discovery exceeded the selected ceiling");
  }
}

int main() {
  using webrtc::DataRate;
  using webrtc::Timestamp;
  DefaultTrials trials;
  webrtc::RtcEventLogNull log;
  webrtc::ProbeController controller(&trials, &log);
  auto now = Timestamp::Millis(0);
  (void)controller.OnNetworkAvailability({.at_time = now, .network_available = true});
  auto settings = veil_media::video_bitrate_settings(60'000, true, true);
  auto probes = controller.SetBitrates(DataRate::BitsPerSec(*settings.min_bitrate_bps),
      DataRate::BitsPerSec(*settings.start_bitrate_bps),
      DataRate::BitsPerSec(*settings.max_bitrate_bps), now);
  require(!probes.empty(), "initial video discovery disappeared");
  bounded(probes, 60'000);
  (void)controller.SetEstimatedBitrate(DataRate::BitsPerSec(60'000),
      webrtc::BandwidthLimitedCause::kDelayBasedLimited, now);
  now = Timestamp::Millis(2000);
  (void)controller.Process(now);
  settings = veil_media::video_bitrate_settings(90'000, true, false);
  require(!settings.start_bitrate_bps.has_value(), "retune reset the live estimate");
  probes = controller.SetBitrates(DataRate::BitsPerSec(*settings.min_bitrate_bps),
      DataRate::Zero(), DataRate::BitsPerSec(*settings.max_bitrate_bps), now);
  require(!probes.empty(), "profile growth no longer discovers available capacity");
  bounded(probes, 90'000);
  require(probes.front().target_data_rate == DataRate::BitsPerSec(90'000),
          "profile growth used retransmission headroom as probing permission");
  now = Timestamp::Millis(4000);
  (void)controller.Process(now);
  controller.SetAlrStartTime(now);
  probes = controller.OnMaxTotalAllocatedBitrate(DataRate::BitsPerSec(90'000), now);
  require(!probes.empty(), "allocation-driven discovery disappeared");
  bounded(probes, 90'000);
  for (int bps : {1000, 8000, 30'000, 900'000, 2'500'000}) {
    settings = veil_media::video_bitrate_settings(bps, true, false);
    require(*settings.min_bitrate_bps <= *settings.max_bitrate_bps, "invalid sparse-video bounds");
    auto legacy = veil_media::video_bitrate_settings(bps, false, true);
    require(*legacy.min_bitrate_bps == bps && *legacy.start_bitrate_bps == bps,
            "legacy no-feedback profile floor changed");
  }
  // The helper is never used by audio. Default audio discovery is unchanged.
  webrtc::ProbeController audio(&trials, &log);
  (void)audio.OnNetworkAvailability({.at_time = now, .network_available = true});
  probes = audio.SetBitrates(DataRate::KilobitsPerSec(30),
      DataRate::KilobitsPerSec(100), DataRate::KilobitsPerSec(1000), now);
  require(!probes.empty() && probes.front().target_data_rate > DataRate::KilobitsPerSec(100),
          "default audio discovery was accidentally capped");
  std::puts("ok real GCC initial, allocation and profile-growth video probe ceilings");
}
