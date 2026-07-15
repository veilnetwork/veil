/* SPDX-License-Identifier: MIT
 *
 * veil_transport_shim.h — the no-ICE seam: a webrtc::Transport that carries
 * RTP/RTCP over the veil media datagram channel instead of WebRTC's own
 * networking. This is the whole point of the "libwebrtc without PeerConnection"
 * design (Phase 0 spike): webrtc::Call gives us NetEQ / AEC3 / GoogCc / pacer /
 * NACK/RTX/FEC / TWCC, and we feed/drain it through this shim.
 *
 * Outbound  : webrtc::Transport::SendRtp/SendRtcp  -> veil_media_send_datagram.
 * Inbound   : veil_media recv callback (a tokio worker thread) -> POSTED to
 *             WebRTC's network TaskQueue -> Call::Receiver()->DeliverRtpPacket /
 *             DeliverRtcpPacket.
 * GCC clock : after every SendRtp we call Call::OnSentPacket (else the
 *             send-side bandwidth estimator never advances).
 *
 * rtcp-mux: RTP and RTCP share the one datagram channel and are demuxed on
 * receipt by webrtc::IsRtcpPacket (RFC 5761) — no extra framing byte.
 *
 * Signatures verified against the checked-out branch (2026-07): SendRtp/SendRtcp
 * take std::span + webrtc::PacketOptions; OnSentPacket takes SentPacketInfo;
 * DeliverRtpPacket is (MediaType, RtpPacketReceived, AnyInvocable handler);
 * rtc:: was collapsed into webrtc::.
 */

#ifndef VEIL_TRANSPORT_SHIM_H
#define VEIL_TRANSPORT_SHIM_H

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>

#include "api/call/transport.h"  // webrtc::Transport, webrtc::PacketOptions

namespace webrtc {
class Call;
class TaskQueueBase;
}  // namespace webrtc

namespace veil_media {

// Bridges one webrtc::Call to one veil media datagram channel. Construct after
// the Call exists (needs Call* for OnSentPacket + Receiver()); register the
// inbound callback via Start().
class VeilTransportShim : public webrtc::Transport {
 public:
  // `veil_chan` is a veil_media_open_channel id. `network_queue` is the
  // TaskQueue WebRTC expects DeliverRtp/RtcpPacket to run on. `call` is used
  // for OnSentPacket + Receiver(); it must outlive the shim.
  VeilTransportShim(uint64_t veil_chan,
                    webrtc::Call* call,
                    webrtc::TaskQueueBase* network_queue);
  ~VeilTransportShim() override;

  VeilTransportShim(const VeilTransportShim&) = delete;
  VeilTransportShim& operator=(const VeilTransportShim&) = delete;

  // Register the inbound veil_media recv callback. Call once, after `call` is
  // fully constructed and its receiver is ready.
  void Start();
  // Unregister the inbound callback. Call before destroying the Call so no late
  // datagram is delivered to a half-torn-down receiver.
  void Stop();

  // webrtc::Transport.
  bool SendRtp(std::span<const uint8_t> packet,
               const webrtc::PacketOptions& options) override;
  bool SendRtcp(std::span<const uint8_t> packet,
                const webrtc::PacketOptions& options) override;

  // Tell the shim which inbound RTP SSRC is video, so DeliverRtpPacket is called
  // with MediaType::VIDEO (the Call routes to the audio vs video demuxer BY the
  // media type — a wrong type black-holes the packet). 0 = no video (all audio).
  void SetRemoteVideoSsrc(uint32_t ssrc) { remote_video_ssrc_.store(ssrc); }

  // Monotonic count of accepted inbound datagrams. Group-call control uses it
  // as a per-peer media-liveness signal without moving packet bytes into Dart.
  uint64_t inbound_packet_count() const {
    return inbound_packet_count_.load(std::memory_order_relaxed);
  }
  uint64_t inbound_byte_count() const {
    return inbound_byte_count_.load(std::memory_order_relaxed);
  }
  uint64_t outbound_packet_count() const {
    return outbound_packet_count_.load(std::memory_order_relaxed);
  }
  uint64_t outbound_byte_count() const {
    return outbound_byte_count_.load(std::memory_order_relaxed);
  }
  uint64_t outbound_dropped_count() const {
    return outbound_dropped_count_.load(std::memory_order_relaxed);
  }
  uint64_t inbound_dropped_count() const {
    return inbound_dropped_overload_.load(std::memory_order_relaxed);
  }

 private:
  // C trampoline for veil_media_set_recv_callback(cb(ctx,ptr,len)).
  static void OnVeilDatagram(void* ctx, const uint8_t* ptr, size_t len);
  // Runs on `network_queue_`: demux RTP vs RTCP and deliver into the Call.
  void DeliverOnNetworkThread(std::span<const uint8_t> packet);

  const uint64_t veil_chan_;
  webrtc::Call* const call_;
  webrtc::TaskQueueBase* const network_queue_;
  std::atomic<uint32_t> remote_video_ssrc_{0};
  std::atomic<bool> started_{false};
  std::atomic<size_t> inbound_pending_packets_{0};
  std::atomic<size_t> inbound_pending_bytes_{0};
  std::atomic<uint64_t> inbound_dropped_overload_{0};
  std::atomic<uint64_t> inbound_packet_count_{0};
  std::atomic<uint64_t> inbound_byte_count_{0};
  std::atomic<uint64_t> outbound_packet_count_{0};
  std::atomic<uint64_t> outbound_byte_count_{0};
  std::atomic<uint64_t> outbound_dropped_count_{0};
};

}  // namespace veil_media

#endif  // VEIL_TRANSPORT_SHIM_H
