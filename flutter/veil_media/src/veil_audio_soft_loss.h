// SPDX-License-Identifier: MIT
#ifndef VEIL_AUDIO_SOFT_LOSS_H_
#define VEIL_AUDIO_SOFT_LOSS_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <optional>

namespace veil_media {
// Endpoint-only damage accounting. Both native receive counters and the
// authenticated VAP2/VAP3 reports already contain these cumulative amounts.
// One decoder's concealment and discarded speech share a six-second window;
// separate peers never dilute each other. Units are 48-kHz output samples.
class AudioSoftLossWindow {
 public:
  enum class Kind { Concealment, Catchup };
  static constexpr int64_t kWindowUs = 6'000'000;
  static constexpr int64_t kProbeWindowUs = 3'000'000;
  static constexpr int64_t kProbeSampleLifetimeUs = 2'000'000;
  // Moderate damage needs fresh losses spanning three seconds. A shorter
  // burst holds growth unless it reaches 4% of this six-second window.
  // RTP loss, interruption and sustained buffer guards remain independent.
  static constexpr uint64_t kThresholdSamples = 120 * 48;
  static constexpr uint64_t kProbeThresholdSamples = 60 * 48;
  static constexpr uint64_t kBurstThresholdSamples = 240 * 48;
  static constexpr int64_t kSustainedUs = 3'000'000;
  static constexpr uint64_t kMaximumSamples = 6000 * 48;

  void Observe(Kind kind, uint64_t origin, uint64_t sequence,
               uint64_t cumulative, bool known, bool fresh, int64_t at_us) {
    if (!known || !origin || !sequence || at_us <= 0 || origin < origin_) return;
    supported_ = true;
    if (origin > origin_) {
      origin_ = origin;
      baselines_ = {};
      events_.clear();
      qualified_at_us_ = 0;
    }
    auto& before = baselines_[static_cast<size_t>(kind)];
    if (before.sequence && (sequence <= before.sequence || at_us <= before.at_us)) return;
    if (before.sequence && cumulative < before.counter) {
      // Retain the counter and sequence high water: a lower report followed
      // by the previous value must not manufacture another increment.
      before.sequence = sequence;
      before.probe_since_us = 0;
      return;
    }
    const bool contiguous = before.sequence && cumulative >= before.counter &&
        at_us - before.at_us < kWindowUs;
    const uint64_t delta = contiguous ? cumulative - before.counter : 0;
    // A new unchanged cumulative counter proves no additional damage
    // across a missing feedback tick. When it increased, retain the short
    // interval limit: a long gap does not locate the damage within it.
    const bool probe_contiguous = contiguous && before.probe_since_us > 0 &&
        (delta == 0 || (fresh && at_us - before.at_us <= kProbeWindowUs));
    before = {sequence, cumulative, at_us,
              probe_contiguous ? before.probe_since_us : at_us};
    Prune(at_us);
    // A startup/replacement/gap baseline and old newly observed counters are
    // consumed without assigning their history to the current window.
    if (!fresh || !delta) return;
    events_.push_back({at_us, std::min(delta, kMaximumSamples)});
    if (events_.size() > 4096) events_.pop_front();
    // Keep the full duration for diagnostics. A report for the controller
    // needs enough new damage since the last report, so a small catch-up
    // cannot requalify an already reported outage still in the window.
    uint64_t damage = 0;
    int64_t first_us = at_us;
    for (const auto& event : events_) {
      if (event.reported || event.at_us > at_us || at_us - event.at_us >= kWindowUs)
        continue;
      damage = std::min(kMaximumSamples, damage + event.samples);
      first_us = std::min(first_us, event.at_us);
    }
    if (damage >= kBurstThresholdSamples ||
        (damage >= kThresholdSamples && at_us - first_us >= kSustainedUs)) {
      for (auto& event : events_) {
        if (event.at_us <= at_us) event.reported = true;
      }
      qualified_at_us_ = std::max(qualified_at_us_, at_us);
    }
  }
  bool supported() const { return supported_; }
  bool FreshAt(int64_t now_us) const {
    return std::any_of(baselines_.begin(), baselines_.end(), [&](const auto& sample) {
      return sample.sequence && sample.at_us <= now_us &&
          now_us - sample.at_us < kWindowUs;
    });
  }
  uint64_t Samples(int64_t now_us) const {
    return now_us > 0 ? SamplesAfter(now_us - kWindowUs, now_us) : 0;
  }
  // A quiet period must be witnessed by fresh cumulative reports covering
  // both counters. Polling a retained report does not retire its own damage.
  struct ProbeWindow {
    uint64_t samples;
    int64_t start_us;
  };
  std::optional<ProbeWindow> Probe(int64_t now_us) const {
    const auto common_us = std::min(baselines_[0].at_us, baselines_[1].at_us);
    const auto start_us = common_us - kProbeWindowUs;
    for (const auto& sample : baselines_) {
      if (!sample.sequence || !sample.probe_since_us ||
          sample.probe_since_us > start_us || sample.at_us > now_us ||
          now_us - sample.at_us >= kProbeSampleLifetimeUs) {
        return std::nullopt;
      }
    }
    return ProbeWindow{SamplesAfter(start_us, now_us), start_us};
  }
  std::optional<uint64_t> ProbeSamples(int64_t now_us) const {
    const auto window = Probe(now_us);
    return window ? std::optional{window->samples} : std::nullopt;
  }
  int64_t FreshReportUs(int64_t now_us) const {
    return qualified_at_us_ > 0 && qualified_at_us_ <= now_us &&
        now_us - qualified_at_us_ < kWindowUs &&
        Samples(now_us) >= kThresholdSamples ? qualified_at_us_ : 0;
  }
  static uint64_t CatchupSamples(uint64_t ms) {
    // An impossible peer counter cannot overflow a diagnostic or the window.
    constexpr auto max = std::numeric_limits<uint64_t>::max();
    return ms > max / 48 ? max : ms * 48;
  }
 private:
  uint64_t SamplesAfter(int64_t start_us, int64_t now_us) const {
    uint64_t total = 0;
    for (const auto& event : events_) {
      if (event.at_us <= now_us && event.at_us > start_us)
        total = std::min(kMaximumSamples, total + event.samples);
    }
    return total;
  }
  struct Baseline {
    uint64_t sequence = 0, counter = 0;
    int64_t at_us = 0, probe_since_us = 0;
  };
  struct Event { int64_t at_us; uint64_t samples; bool reported = false; };
  void Prune(int64_t now_us) {
    while (!events_.empty() && now_us - events_.front().at_us >= kWindowUs)
      events_.pop_front();
  }
  bool supported_ = false;
  uint64_t origin_ = 0;
  std::array<Baseline, 2> baselines_{};
  std::deque<Event> events_;
  int64_t qualified_at_us_ = 0;
};

struct AudioSoftLossSnapshot {
  bool supported = false;
  uint64_t samples = 0;
  int64_t report_us = 0;
  std::optional<AudioSoftLossWindow::ProbeWindow> probe;
};
}  // namespace veil_media
#endif
