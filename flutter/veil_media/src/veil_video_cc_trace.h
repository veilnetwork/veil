// SPDX-License-Identifier: MIT
#pragma once

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#include "api/transport/network_control.h"
#include "veil_diag_log.h"

#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

namespace veil_media {

// This header is included by the engine only in the separate CC-trace build.
// Android app processes cannot inherit an operator's shell environment; the
// explicit debug property is its equivalent runtime opt-in. A diagnostic path
// is still required, and an explicit environment value takes precedence.
inline bool video_cc_trace_enabled() {
  if (!diag::enabled()) return false;
  if (const char* value = std::getenv("VEIL_MEDIA_TRACE_VIDEO_CC"))
    return std::strcmp(value, "1") == 0;
#if defined(__ANDROID__)
  char value[PROP_VALUE_MAX] = {};
  return __system_property_get("debug.veil_media.video_cc", value) > 0 &&
         std::strcmp(value, "1") == 0;
#else
  return false;
#endif
}

// Stand-only observation of the real controller. No packet/feedback contents
// are retained and no file I/O occurs on a network-controller callback.
// The controller interface requires all calls on one worker queue.
class VideoCcTrace final : public webrtc::NetworkControllerInterface {
 public:
  VideoCcTrace(std::unique_ptr<webrtc::NetworkControllerInterface> inner,
               size_t capacity = 8192)
      : inner_(std::move(inner)), capacity_(std::min(capacity, size_t(8192))),
        id_(next_id_.fetch_add(1) + 1) {
    rows_.reserve(capacity_);
  }
  ~VideoCcTrace() override {
    const char* path = diag::path();
    if (!path) return;
    FILE* file = std::fopen(path, "a");
    if (!file) return;
    std::fprintf(file, "video.cc.begin id=%llu rows=%zu seen=%llu\n",
                 (unsigned long long)id_, rows_.size(), (unsigned long long)seen_);
    for (const auto& r : rows_)
      std::fprintf(file, "video.cc.sample id=%llu at_us=%lld available=%d route=%llu cwnd_bytes=%lld inflight_bytes=%lld pacer_queue_bytes=%lld target_bps=%lld pacing_bps=%lld feedback_at_us=%lld feedback_packets=%llu sent_packets=%llu constraints_at_us=%lld constraints_min_bps=%lld constraints_max_bps=%lld\n",
                   (unsigned long long)id_, (long long)r.at, r.available,
                   (unsigned long long)r.route, (long long)r.cwnd,
                   (long long)r.inflight, (long long)r.queue, (long long)r.target,
                   (long long)r.pacing, (long long)r.feedback_at,
                   (unsigned long long)r.feedback_packets,
                   (unsigned long long)r.sent_packets,
                   (long long)r.constraints_at, (long long)r.constraints_min,
                   (long long)r.constraints_max);
    const bool ok = std::fflush(file) == 0 && !std::ferror(file);
    std::fprintf(file, "video.cc.end id=%llu write_ok=%d\n",
                 (unsigned long long)id_, int(ok));
    std::fclose(file);
  }

  webrtc::NetworkControlUpdate OnNetworkAvailability(webrtc::NetworkAvailability m) override {
    state_.available = m.network_available;
    return Apply(inner_->OnNetworkAvailability(std::move(m)));
  }
  webrtc::NetworkControlUpdate OnNetworkRouteChange(webrtc::NetworkRouteChange m) override {
    ++state_.route;
    return Apply(inner_->OnNetworkRouteChange(std::move(m)));
  }
  webrtc::NetworkControlUpdate OnProcessInterval(webrtc::ProcessInterval m) override {
    const auto at = m.at_time;
    state_.queue = m.pacer_queue ? m.pacer_queue->bytes_or(int64_t{-1}) : -1;
    auto update = Apply(inner_->OnProcessInterval(std::move(m)));
    if (at.IsFinite() &&
        (last_at_.IsInfinite() || at < last_at_ ||
         at - last_at_ >= webrtc::TimeDelta::Millis(100))) {
      last_at_ = at;
      state_.at = at.us();
      ++seen_;
      if (rows_.size() < capacity_) rows_.push_back(state_);
    }
    return update;
  }
  webrtc::NetworkControlUpdate OnSentPacket(webrtc::SentPacket m) override {
    state_.inflight = m.data_in_flight.bytes_or(int64_t{-1});
    ++state_.sent_packets;
    return Apply(inner_->OnSentPacket(std::move(m)));
  }
  webrtc::NetworkControlUpdate OnTransportPacketsFeedback(webrtc::TransportPacketsFeedback m) override {
    state_.inflight = m.data_in_flight.bytes_or(int64_t{-1});
    state_.feedback_at = m.feedback_time.us_or(int64_t{-1});
    state_.feedback_packets += m.packet_feedbacks.size();
    return Apply(inner_->OnTransportPacketsFeedback(std::move(m)));
  }
  webrtc::NetworkControlUpdate OnTargetRateConstraints(webrtc::TargetRateConstraints m) override {
    state_.constraints_at = m.at_time.us_or(int64_t{-1});
    state_.constraints_min = m.min_data_rate ? m.min_data_rate->bps_or(int64_t{-1}) : -1;
    state_.constraints_max = m.max_data_rate ? m.max_data_rate->bps_or(int64_t{-1}) : -1;
    return Apply(inner_->OnTargetRateConstraints(std::move(m)));
  }
#define VEIL_CC_FORWARD(Method, Type) \
  webrtc::NetworkControlUpdate Method(webrtc::Type m) override { \
    return Apply(inner_->Method(std::move(m))); \
  }
  VEIL_CC_FORWARD(OnRemoteBitrateReport, RemoteBitrateReport)
  VEIL_CC_FORWARD(OnRoundTripTimeUpdate, RoundTripTimeUpdate)
  VEIL_CC_FORWARD(OnReceivedPacket, ReceivedPacket)
  VEIL_CC_FORWARD(OnStreamsConfig, StreamsConfig)
  VEIL_CC_FORWARD(OnTransportLossReport, TransportLossReport)
  VEIL_CC_FORWARD(OnNetworkStateEstimate, NetworkStateEstimate)
#undef VEIL_CC_FORWARD
  bool SupportsEcnAdaptation() const override { return inner_->SupportsEcnAdaptation(); }

 private:
  webrtc::NetworkControlUpdate Apply(webrtc::NetworkControlUpdate update) {
    if (update.congestion_window) state_.cwnd = update.congestion_window->bytes_or(int64_t{-1});
    if (update.target_rate) state_.target = update.target_rate->target_rate.bps_or(int64_t{-1});
    if (update.pacer_config) state_.pacing = update.pacer_config->data_rate().bps_or(int64_t{-1});
    return update;
  }
  struct Row {
    int64_t at = -1, cwnd = -1, inflight = -1, queue = -1;
    int64_t target = -1, pacing = -1, feedback_at = -1;
    int64_t constraints_at = -1, constraints_min = -1, constraints_max = -1;
    uint64_t route = 0, feedback_packets = 0, sent_packets = 0;
    int available = -1;
  } state_;
  std::unique_ptr<webrtc::NetworkControllerInterface> inner_;
  const size_t capacity_;
  const uint64_t id_;
  uint64_t seen_ = 0;
  webrtc::Timestamp last_at_ = webrtc::Timestamp::MinusInfinity();
  std::vector<Row> rows_;
  inline static std::atomic<uint64_t> next_id_{0};
};

class VideoCcTraceFactory final : public webrtc::NetworkControllerFactoryInterface {
 public:
  explicit VideoCcTraceFactory(std::unique_ptr<webrtc::NetworkControllerFactoryInterface> inner)
      : inner_(std::move(inner)) {}
  std::unique_ptr<webrtc::NetworkControllerInterface> Create(webrtc::NetworkControllerConfig config) override {
    auto controller = inner_->Create(std::move(config));
    return controller ? std::make_unique<VideoCcTrace>(std::move(controller)) : nullptr;
  }
  webrtc::TimeDelta GetProcessInterval() const override { return inner_->GetProcessInterval(); }
 private:
  std::unique_ptr<webrtc::NetworkControllerFactoryInterface> inner_;
};
}  // namespace veil_media
