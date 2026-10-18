// Test-only observer around the real GoogCC controller, not a replacement BWE.
#pragma once
#include <atomic>
#include <memory>
#include <utility>
#include "api/transport/goog_cc_factory.h"
#include "api/transport/network_control.h"

namespace veil_media::test {
class RouteObserver final : public webrtc::NetworkControllerInterface {
 public:
  RouteObserver(std::unique_ptr<webrtc::NetworkControllerInterface> inner,
                std::shared_ptr<std::atomic<int>> restarts)
      : inner_(std::move(inner)), restarts_(std::move(restarts)) {}
  webrtc::NetworkControlUpdate OnNetworkRouteChange(webrtc::NetworkRouteChange m) override {
    auto result = inner_->OnNetworkRouteChange(m);
    if (m.restart_bwe) restarts_->fetch_add(1);
    return result;
  }
#define VEIL_ROUTE_FORWARD(Method, Type) \
  webrtc::NetworkControlUpdate Method(webrtc::Type m) override { \
    return inner_->Method(std::move(m)); \
  }
  VEIL_ROUTE_FORWARD(OnNetworkAvailability, NetworkAvailability)
  VEIL_ROUTE_FORWARD(OnProcessInterval, ProcessInterval)
  VEIL_ROUTE_FORWARD(OnRemoteBitrateReport, RemoteBitrateReport)
  VEIL_ROUTE_FORWARD(OnRoundTripTimeUpdate, RoundTripTimeUpdate)
  VEIL_ROUTE_FORWARD(OnSentPacket, SentPacket)
  VEIL_ROUTE_FORWARD(OnReceivedPacket, ReceivedPacket)
  VEIL_ROUTE_FORWARD(OnStreamsConfig, StreamsConfig)
  VEIL_ROUTE_FORWARD(OnTargetRateConstraints, TargetRateConstraints)
  VEIL_ROUTE_FORWARD(OnTransportLossReport, TransportLossReport)
  VEIL_ROUTE_FORWARD(OnTransportPacketsFeedback, TransportPacketsFeedback)
  VEIL_ROUTE_FORWARD(OnNetworkStateEstimate, NetworkStateEstimate)
#undef VEIL_ROUTE_FORWARD
  bool SupportsEcnAdaptation() const override { return inner_->SupportsEcnAdaptation(); }
 private:
  std::unique_ptr<webrtc::NetworkControllerInterface> inner_;
  std::shared_ptr<std::atomic<int>> restarts_;
};
class RouteObserverFactory final : public webrtc::NetworkControllerFactoryInterface {
 public:
  explicit RouteObserverFactory(std::shared_ptr<std::atomic<int>> restarts)
      : restarts_(std::move(restarts)) {}
  std::unique_ptr<webrtc::NetworkControllerInterface> Create(webrtc::NetworkControllerConfig c) override {
    return std::make_unique<RouteObserver>(inner_.Create(std::move(c)), restarts_);
  }
  webrtc::TimeDelta GetProcessInterval() const override { return inner_.GetProcessInterval(); }
 private:
  webrtc::GoogCcNetworkControllerFactory inner_;
  std::shared_ptr<std::atomic<int>> restarts_;
};
}  // namespace veil_media::test
