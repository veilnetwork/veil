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
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>

#include "api/call/transport.h"  // webrtc::Transport, webrtc::PacketOptions
#include "veil_inbound_packet_queue.h"
#include "veil_audio_send_stats.h"

namespace webrtc {
class Call;
class TaskQueueBase;
}  // namespace webrtc

namespace veil_media {

// Endpoint-local audio RR/SR observation for this authenticated peer channel.
struct AudioFeedbackSnapshot {
  int64_t arrived_us = 0;
  int64_t rtt_ms = 0;
  int loss_pct = 0;
  int jitter_ms = 0;

  bool fresh_at(int64_t now_us) const {
    return arrived_us > 0 && arrived_us <= now_us &&
           now_us - arrived_us <= 15'000'000;
  }
};

// Optional endpoint feedback carried inside the encrypted media channel.
// Unknown/stale playout is not a zero delay. Receipt time is local and replay
// cannot renew it; support remains known until this peer channel is replaced.
struct AudioPlayoutSnapshot {
  bool supported = false;
  uint64_t sequence = 0;
  int64_t arrived_us = 0;
  int delay_ms = -1;

  bool fresh_at(int64_t now_us) const {
    return supported && delay_ms >= 0 && arrived_us > 0 &&
           arrived_us <= now_us && now_us - arrived_us <= 12'000'000;
  }
};

struct VideoCadenceSnapshot {
  uint64_t frames = 0;
  int64_t first_ns = 0;
  int64_t last_ns = 0;
  int64_t max_gap_ns = 0;
  uint64_t holds_75ms = 0;
};

// Bridges separate local audio/video Calls to one Veil media handle. Both
// Calls and their queues must outlive the shim; register the
// inbound callback via Start().
class VeilTransportShim : public webrtc::Transport {
 public:
  // `veil_chan` is a veil_media_open_channel id. Each Call has its own
  // network queue for DeliverRtp/RtcpPacket and its own sent-packet clock.
  VeilTransportShim(uint64_t veil_chan,
                    webrtc::Call* call,
                    webrtc::TaskQueueBase* network_queue,
                    webrtc::Call* video_call,
                    webrtc::TaskQueueBase* video_network_queue);
  ~VeilTransportShim() override;

  VeilTransportShim(const VeilTransportShim&) = delete;
  VeilTransportShim& operator=(const VeilTransportShim&) = delete;

  // Register the inbound veil_media recv callback. Call once, after `call` is
  // fully constructed and its receiver is ready.
  void Start();
  // Unregister the inbound callback. Call before destroying the Call so no late
  // datagram is delivered to a half-torn-down receiver.
  void Stop();

  // Endpoint-local shedding. Keep audio, RTCP and remote video live; do not
  // enqueue video already encoded or retransmitted by the pacer while paused.
  void SetVideoSendPaused(bool paused) { video_send_paused_.store(paused); }

  // webrtc::Transport.
  bool SendRtp(std::span<const uint8_t> packet,
               const webrtc::PacketOptions& options) override;
  bool SendRtcp(std::span<const uint8_t> packet,
                const webrtc::PacketOptions& options) override;

  // Tell the shim which inbound RTP SSRC is video, so DeliverRtpPacket is called
  // with MediaType::VIDEO (the Call routes to the audio vs video demuxer BY the
  // media type — a wrong type black-holes the packet). 0 = no video (all audio).
  void SetRemoteVideoSsrc(uint32_t ssrc) { remote_video_ssrc_.store(ssrc); }

  // Group calls use one send SSRC for all peers. Keep their reports separate
  // before WebRTC's per-source cache overwrites one participant with another.
  void SetLocalAudioSsrc(uint32_t ssrc) { local_audio_ssrc_.store(ssrc); }
  AudioFeedbackSnapshot audio_feedback() const;
  AudioPlayoutSnapshot audio_playout_feedback() const;
  // Group receive-worker samples only. Setting an unknown sample still
  // advertises support; unicast uses its negotiated call-health feedback.
  void SetLocalAudioPlayout(uint32_t remote_audio_ssrc, uint64_t sequence,
                           int delay_ms, int64_t sampled_us);

  // Enable only when both endpoints have independent audio/video counters.
  // Older engines used one sequence space and cannot consume split feedback.
  void SetIndependentTransportFeedback(bool enabled) {
    independent_transport_feedback_.store(enabled);
  }
  bool independent_transport_feedback() const {
    return independent_transport_feedback_.load();
  }

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
  uint64_t outbound_rtcp_packet_count() const {
    return outbound_rtcp_packet_count_.load(std::memory_order_relaxed);
  }
  uint64_t outbound_rtcp_byte_count() const {
    return outbound_rtcp_byte_count_.load(std::memory_order_relaxed);
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
  VideoCadenceSnapshot outbound_video_cadence() const;
  VideoCadenceSnapshot inbound_video_cadence() const;
  VideoCadenceSnapshot delivered_video_cadence() const;
  AudioSendSnapshot audio_send_stats() const;

 private:
  std::atomic<bool> video_send_paused_{false};
  struct AtomicVideoCadence {
    std::atomic<uint64_t> frames{0};
    std::atomic<int64_t> first_ns{0};
    std::atomic<int64_t> last_ns{0};
    std::atomic<int64_t> max_gap_ns{0};
    std::atomic<uint64_t> holds_75ms{0};
  };

  static void MarkVideoFrame(std::span<const uint8_t> packet,
                             AtomicVideoCadence* cadence);
  static VideoCadenceSnapshot Snapshot(const AtomicVideoCadence& cadence);

  // C trampoline for veil_media_set_recv_callback(cb(ctx,ptr,len)).
  static void OnVeilDatagram(void* ctx, const uint8_t* ptr, size_t len);
  // Post one bounded drain turn. The packet buffers stay in separate local
  // queues, allowing newly arrived audio to pass already queued video.
  void PostInboundDrain(bool secondary);
  void ObserveAudioFeedback(std::span<const uint8_t> packet, int64_t arrived_us);
  // Runs on the selected local network queue and delivers into its Call.
  void DeliverOnNetworkThread(std::span<const uint8_t> packet, bool secondary,
                              int64_t arrived_us);

  // WHAT A QUEUED TASK IS ALLOWED TO TOUCH AFTER THIS OBJECT IS GONE.
  //
  // A drain task holds a raw `this`. Stop clears the packet queues and fences
  // a currently running delivery, but a posted task can remain on a stalled
  // network queue. That task must safely detect a destroyed shim before
  // touching any member (report27 V23).
  //
  // Each lane has its own guard. The destructor clears both flags, so a task either
  // completes while the destructor waits, or sees `alive == false` and touches
  // nothing. Held across the delivery, which is bounded by one packet.
  struct TaskGuard {
    std::mutex mu;
    bool alive = true;
  };
  const std::array<std::shared_ptr<TaskGuard>, 2> task_guards_ = {
      std::make_shared<TaskGuard>(), std::make_shared<TaskGuard>()};

  const uint64_t veil_chan_;
  webrtc::Call* const call_;
  webrtc::TaskQueueBase* const network_queue_;
  webrtc::Call* const video_call_;
  webrtc::TaskQueueBase* const video_network_queue_;
  std::atomic<uint32_t> remote_video_ssrc_{0};
  std::atomic<uint32_t> local_audio_ssrc_{0};
  AudioSendStats audio_send_stats_;
  mutable std::mutex audio_feedback_mu_;
  AudioFeedbackSnapshot audio_feedback_;
  AudioPlayoutSnapshot audio_playout_feedback_;
  struct LocalAudioPlayout {
    bool enabled = false;
    uint32_t remote_ssrc = 0;
    uint64_t sequence = 0;
    int delay_ms = -1;
    int64_t sampled_us = 0;
  };
  LocalAudioPlayout local_audio_playout_;
  std::atomic<bool> independent_transport_feedback_{false};
  std::atomic<bool> started_{false};
  InboundPacketQueue inbound_queue_;
  std::atomic<uint64_t> inbound_dropped_overload_{0};
  std::atomic<uint64_t> inbound_packet_count_{0};
  std::atomic<uint64_t> inbound_byte_count_{0};
  std::atomic<uint64_t> outbound_packet_count_{0};
  std::atomic<uint64_t> outbound_rtcp_packet_count_{0}, outbound_rtcp_byte_count_{0};
  std::atomic<uint64_t> outbound_byte_count_{0};
  std::atomic<uint64_t> outbound_dropped_count_{0};
  AtomicVideoCadence outbound_video_cadence_;
  AtomicVideoCadence inbound_video_cadence_;
  AtomicVideoCadence delivered_video_cadence_;
};

}  // namespace veil_media

#endif  // VEIL_TRANSPORT_SHIM_H
