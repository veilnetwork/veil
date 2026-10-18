// SPDX-License-Identifier: MIT
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include "veil_video_cc_trace.h"

namespace {
void Require(bool ok) { if (!ok) std::abort(); }
struct Spy final : webrtc::NetworkControllerInterface {
  int calls = 0;
  webrtc::NetworkControlUpdate Result() {
    ++calls;
    webrtc::NetworkControlUpdate u;
    u.congestion_window = webrtc::DataSize::Bytes(4096);
    u.target_rate.emplace();
    u.target_rate->target_rate = webrtc::DataRate::BitsPerSec(42000);
    u.pacer_config = webrtc::PacerConfig::Create(
        webrtc::Timestamp::Micros(1), webrtc::DataRate::BitsPerSec(96000),
        webrtc::DataRate::BitsPerSec(2000));
    u.probe_cluster_configs.emplace_back();
    u.probe_cluster_configs.back().id = 42;
    return u;
  }
#define SPY_METHOD(Method, Type) \
  webrtc::NetworkControlUpdate Method(webrtc::Type) override { return Result(); }
  SPY_METHOD(OnNetworkAvailability, NetworkAvailability)
  SPY_METHOD(OnNetworkRouteChange, NetworkRouteChange)
  SPY_METHOD(OnProcessInterval, ProcessInterval)
  SPY_METHOD(OnRemoteBitrateReport, RemoteBitrateReport)
  SPY_METHOD(OnRoundTripTimeUpdate, RoundTripTimeUpdate)
  SPY_METHOD(OnReceivedPacket, ReceivedPacket)
  SPY_METHOD(OnStreamsConfig, StreamsConfig)
  SPY_METHOD(OnTargetRateConstraints, TargetRateConstraints)
  SPY_METHOD(OnTransportLossReport, TransportLossReport)
  SPY_METHOD(OnNetworkStateEstimate, NetworkStateEstimate)
#undef SPY_METHOD
  webrtc::NetworkControlUpdate OnSentPacket(webrtc::SentPacket m) override {
    Require(m.sequence_number == 7 && m.data_in_flight.bytes() == 5000);
    return Result();
  }
  webrtc::NetworkControlUpdate OnTransportPacketsFeedback(webrtc::TransportPacketsFeedback m) override {
    Require(m.packet_feedbacks.size() == 2 && m.data_in_flight.bytes() == 900);
    Require(m.packet_feedbacks[0].sent_packet.sequence_number == 7);
    return Result();
  }
  bool SupportsEcnAdaptation() const override { return true; }
};
void Same(const webrtc::NetworkControlUpdate& u) {
  Require(u.congestion_window->bytes() == 4096);
  Require(u.target_rate->target_rate.bps() == 42000);
  Require(u.pacer_config->data_rate().bps() == 96000);
  Require(u.pacer_config->pad_rate().bps() == 2000);
  Require(u.probe_cluster_configs.size() == 1 && u.probe_cluster_configs[0].id == 42);
}
}  // namespace

int main(int argc, char** argv) {
  Require(argc == 2);
  setenv("VEIL_MEDIA_DIAG_PATH", argv[1], 1);
  std::remove(argv[1]);
  {
    auto spy = std::make_unique<Spy>();
    auto* raw = spy.get();
    veil_media::VideoCcTrace trace(std::move(spy), 2);
    Same(trace.OnNetworkAvailability({.network_available = true}));
    Same(trace.OnNetworkRouteChange({}));
    Same(trace.OnRemoteBitrateReport({}));
    Same(trace.OnRoundTripTimeUpdate({}));
    Same(trace.OnReceivedPacket({}));
    Same(trace.OnStreamsConfig({}));
    Same(trace.OnTargetRateConstraints({}));
    Same(trace.OnTransportLossReport({}));
    Same(trace.OnNetworkStateEstimate({}));
    webrtc::SentPacket sent;
    sent.sequence_number = 7;
    sent.data_in_flight = webrtc::DataSize::Bytes(5000);
    Same(trace.OnSentPacket(sent));
    webrtc::ProcessInterval tick;
    // Real host monotonic values exceed 32 bits; do not narrow to int.
    tick.at_time = webrtc::Timestamp::Micros(166214345949LL);
    Same(trace.OnProcessInterval(tick));
    webrtc::TransportPacketsFeedback feedback;
    feedback.feedback_time = tick.at_time + webrtc::TimeDelta::Millis(10);
    feedback.data_in_flight = webrtc::DataSize::Bytes(900);
    feedback.packet_feedbacks.resize(2);
    feedback.packet_feedbacks[0].sent_packet.sequence_number = 7;
    Same(trace.OnTransportPacketsFeedback(feedback));
    tick.at_time += webrtc::TimeDelta::Millis(100);
    Same(trace.OnProcessInterval(tick));
    tick.at_time += webrtc::TimeDelta::Millis(100);
    Same(trace.OnProcessInterval(tick));
    Require(trace.SupportsEcnAdaptation());
    Require(raw->calls == 14);
    Require(!std::ifstream(argv[1]).good());  // no callback file I/O
  }
  std::ifstream stream(argv[1]);
  const std::string text((std::istreambuf_iterator<char>(stream)), {});
  Require(text.find("rows=2 seen=3") != std::string::npos);  // visible truncation
  Require(text.find("at_us=166214345949") != std::string::npos);
  Require(text.find("inflight_bytes=5000") != std::string::npos);
  Require(text.find("inflight_bytes=900") != std::string::npos);
  Require(text.find("feedback_at_us=166214355949") != std::string::npos);
  Require(text.find("write_ok=1") != std::string::npos);
  std::remove(argv[1]);
}
