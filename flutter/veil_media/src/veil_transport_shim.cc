/* SPDX-License-Identifier: MIT
 *
 * veil_transport_shim.cc — see veil_transport_shim.h.
 *
 * Depends on the veilclient-ffi media datagram ABI (linked into the host app):
 * the channel is already open; we only send + set the recv callback.
 */

#include "veil_transport_shim.h"
#include "veil_diag_log.h"

#include <atomic>
#include <cstdarg>
#include <cstddef>
#include <span>
#include <utility>
#include <vector>

#include "api/task_queue/task_queue_base.h"
#include "call/call.h"
#include "call/packet_receiver.h"
#include "modules/rtp_rtcp/include/rtp_rtcp_defines.h"  // kVideoPayloadTypeFrequency
#include "modules/rtp_rtcp/include/rtp_header_extension_map.h"
#include "modules/rtp_rtcp/source/rtp_header_extensions.h"
#include "modules/rtp_rtcp/source/ntp_time_util.h"
#include "modules/rtp_rtcp/source/rtcp_packet/common_header.h"
#include "modules/rtp_rtcp/source/rtcp_packet/receiver_report.h"
#include "modules/rtp_rtcp/source/rtcp_packet/sender_report.h"
#include "system_wrappers/include/clock.h"
#include "modules/rtp_rtcp/source/rtp_packet_received.h"
#include "modules/rtp_rtcp/source/rtp_util.h"  // webrtc::IsRtcpPacket
#include "rtc_base/copy_on_write_buffer.h"
#include "rtc_base/network/sent_packet.h"  // webrtc::SentPacketInfo
#include "rtc_base/time_utils.h"           // webrtc::TimeMillis

// veilclient-ffi ABI (crates/veilclient-ffi/include/veil_media_abi.h). The
// symbols are statically present in the host process (veilclient_ffi is linked
// into the app), so we declare them here rather than crossing the crate include.
extern "C" {
int veil_media_send_datagram(uint64_t chan, const uint8_t* ptr, size_t len);
int veil_media_send_video_control_datagram(uint64_t chan, const uint8_t* ptr, size_t len);
typedef void (*VeilMediaRecvFn)(void* ctx, const uint8_t* ptr, size_t len);
int veil_media_set_recv_callback(uint64_t chan, VeilMediaRecvFn cb, void* ctx);
}

namespace veil_media {
namespace {
constexpr uint8_t kVp8PayloadType = 96;
constexpr int64_t kHoldThresholdNs = 75 * 1000 * 1000;
constexpr uint32_t kAudioPlayoutAppName = 0x56415031u;  // "VAP1"
constexpr uint32_t kUnknownPlayout = 0xffffffffu;

uint32_t read_be32(const uint8_t* p) {
  return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 |
         uint32_t(p[2]) << 8 | uint32_t(p[3]);
}
void write_be32(uint8_t* p, uint32_t value) {
  for (int i = 0; i < 4; ++i) p[i] = value >> (24 - i * 8);
}

void slog(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  veil_media::diag::vlog(fmt, ap);
  va_end(ap);
}
}  // namespace

VeilTransportShim::VeilTransportShim(uint64_t veil_chan,
                                     webrtc::Call* call,
                                     webrtc::TaskQueueBase* network_queue,
                                     webrtc::Call* video_call,
                                     webrtc::TaskQueueBase* video_network_queue)
    : veil_chan_(veil_chan), call_(call), network_queue_(network_queue),
      video_call_(video_call), video_network_queue_(video_network_queue) {}

VeilTransportShim::~VeilTransportShim() {
  Stop();
  // A task posted to the network queue may still be waiting to run after
  // Stop cleared its buffers. Clearing this flag makes that task harmless
  // — it either already finished (the destructor waited for it here) or it
  // will find `alive == false` and touch nothing (report27 V23).
  for (const auto& guard : task_guards_) {
    std::lock_guard<std::mutex> lock(guard->mu);
    guard->alive = false;
  }
}

void VeilTransportShim::MarkVideoFrame(std::span<const uint8_t> packet,
                                       AtomicVideoCadence* cadence) {
  if (cadence == nullptr || packet.size() < 12 || (packet[0] >> 6) != 2 ||
      (packet[1] & 0x7f) != kVp8PayloadType || (packet[1] & 0x80) == 0) {
    return;
  }
  const int64_t now_ns = webrtc::TimeMicros() * 1000;
  int64_t expected_first = 0;
  cadence->first_ns.compare_exchange_strong(expected_first, now_ns,
                                             std::memory_order_relaxed);
  const int64_t previous =
      cadence->last_ns.exchange(now_ns, std::memory_order_relaxed);
  if (previous != 0) {
    const int64_t gap = now_ns - previous;
    int64_t old_max = cadence->max_gap_ns.load(std::memory_order_relaxed);
    while (gap > old_max &&
           !cadence->max_gap_ns.compare_exchange_weak(
               old_max, gap, std::memory_order_relaxed)) {
    }
    if (gap >= kHoldThresholdNs) {
      cadence->holds_75ms.fetch_add(1, std::memory_order_relaxed);
    }
  }
  cadence->frames.fetch_add(1, std::memory_order_relaxed);
}

VideoCadenceSnapshot VeilTransportShim::Snapshot(
    const AtomicVideoCadence& cadence) {
  return {
      cadence.frames.load(std::memory_order_relaxed),
      cadence.first_ns.load(std::memory_order_relaxed),
      cadence.last_ns.load(std::memory_order_relaxed),
      cadence.max_gap_ns.load(std::memory_order_relaxed),
      cadence.holds_75ms.load(std::memory_order_relaxed),
  };
}

VideoCadenceSnapshot VeilTransportShim::outbound_video_cadence() const {
  return Snapshot(outbound_video_cadence_);
}

VideoCadenceSnapshot VeilTransportShim::inbound_video_cadence() const {
  return Snapshot(inbound_video_cadence_);
}

VideoCadenceSnapshot VeilTransportShim::delivered_video_cadence() const {
  return Snapshot(delivered_video_cadence_);
}

AudioSendSnapshot VeilTransportShim::audio_send_stats() const {
  return audio_send_stats_.snapshot(webrtc::TimeMicros() * 1000);
}

void VeilTransportShim::Start() {
  bool expected = false;
  if (!started_.compare_exchange_strong(expected, true)) return;
  const int rc = veil_media_set_recv_callback(
      veil_chan_, &VeilTransportShim::OnVeilDatagram, this);
  // A failed registration is a silently dead inbound leg — surface it.
  slog("shim Start chan=%llu recv_cb rc=%d", (unsigned long long)veil_chan_,
       rc);
}

void VeilTransportShim::Stop() {
  bool expected = true;
  if (!started_.compare_exchange_strong(expected, false)) return;
  veil_media_set_recv_callback(veil_chan_, nullptr, nullptr);
  slog("shim Stop chan=%llu recv_cb cleared", (unsigned long long)veil_chan_);
  // Fence a delivery already in progress before the owner destroys Call.
  // Pending tasks need not run: release their packets here, with no one-second
  // wait on a busy WebRTC network queue.
  std::scoped_lock lock(task_guards_[0]->mu, task_guards_[1]->mu);
  inbound_queue_.Clear();
}

bool VeilTransportShim::SendRtp(std::span<const uint8_t> packet,
                                const webrtc::PacketOptions& options) {
  if (video_send_paused_.load() && IsSecondaryInboundRtp(packet)) return false;
  MarkVideoFrame(packet, &outbound_video_cadence_);
  const int64_t started_ns = webrtc::TimeMicros() * 1000;
  const bool audio = audio_send_stats_.mark_attempt(
      packet, local_audio_ssrc_.load(std::memory_order_relaxed), started_ns);
  const int rc =
      veil_media_send_datagram(veil_chan_, packet.data(), packet.size());
  if (audio) {
    audio_send_stats_.mark_result(started_ns, webrtc::TimeMicros() * 1000, rc == 0);
  }
  static const bool diagnostics_enabled = diag::enabled();
  if (diagnostics_enabled) {
    static std::atomic<uint64_t> n{0};
    const uint64_t c = n.fetch_add(1);
    if (c % 100 == 0)
      slog("shim SendRtp #%llu chan=%llu len=%zu rc=%d",
           (unsigned long long)c, (unsigned long long)veil_chan_,
           packet.size(), rc);
  }
  // rc: 0 queued, 1 dropped (queue full), -1 invalid. Queue-full means this
  // packet already lost its real-time slot; report it as unsent so WebRTC does
  // not treat local buffering as healthy delivery and build a stale tail.
  const bool sent = rc == 0;
  if (sent) {
    outbound_packet_count_.fetch_add(1, std::memory_order_relaxed);
    outbound_byte_count_.fetch_add(packet.size(), std::memory_order_relaxed);
  } else {
    outbound_dropped_count_.fetch_add(1, std::memory_order_relaxed);
  }

  // Close the send-side GCC timing loop. Our datagram send is synchronous on
  // the network thread, so stamp "now" and report immediately.
  if (sent && options.packet_id != -1) {
    (IsSecondaryInboundRtp(packet) ? video_call_ : call_)->OnSentPacket(
        webrtc::SentPacketInfo(options.packet_id, webrtc::TimeMillis()));
  }
  return sent;
}

bool VeilTransportShim::SendRtcp(std::span<const uint8_t> packet,
                                 const webrtc::PacketOptions& options) {
  return SendRtcpOnSource(packet, options, false);
}

bool VeilTransportShim::SendVideoRtcp(std::span<const uint8_t> packet,
                                      const webrtc::PacketOptions& options) {
  return SendRtcpOnSource(packet, options, true);
}

bool VeilTransportShim::SendRtcpOnSource(std::span<const uint8_t> packet,
                                         const webrtc::PacketOptions& options,
                                         bool video) {
  (void)options;  // RTCP carries no packet_id to feed back.
  std::vector<uint8_t> compound;
  LocalAudioPlayout sample;
  if (!video) {
    std::lock_guard lock(audio_feedback_mu_);
    sample = local_audio_playout_;
  }
  bool append = !video && sample.enabled && started_.load(std::memory_order_acquire);
  // Keep RTCP's original report/SDES framing and do not append after BYE or
  // padding. Old endpoints can ignore the optional APP name (RFC 3550 §6.7).
  for (size_t offset = 0; append && offset < packet.size();) {
    webrtc::rtcp::CommonHeader header;
    if (!header.Parse(packet.data() + offset, packet.size() - offset) ||
        header.type() == 203 || (packet[offset] & 0x20) != 0) {
      append = false;
      break;
    }
    offset += header.packet_size();
  }
  if (append && !packet.empty()) {
    compound.assign(packet.begin(), packet.end());
    const size_t at = compound.size();
    compound.resize(at + 28);
    auto* app = compound.data() + at;
    app[0] = 0x80; app[1] = 204; app[2] = 0; app[3] = 6;
    write_be32(app + 4, local_audio_ssrc_.load(std::memory_order_relaxed));
    write_be32(app + 8, kAudioPlayoutAppName);
    write_be32(app + 12, sample.remote_ssrc);
    write_be32(app + 16, static_cast<uint32_t>(sample.sequence >> 32));
    write_be32(app + 20, static_cast<uint32_t>(sample.sequence));
    const int64_t now_us = webrtc::TimeMicros();
    const bool fresh = sample.sampled_us > 0 && sample.sampled_us <= now_us &&
                       now_us - sample.sampled_us <= 3'000'000;
    write_be32(app + 24, fresh && sample.delay_ms >= 0
                            ? static_cast<uint32_t>(sample.delay_ms)
                            : kUnknownPlayout);
    packet = std::span<const uint8_t>(compound);
  }
  const int rc = video
      ? veil_media_send_video_control_datagram(veil_chan_, packet.data(), packet.size())
      : veil_media_send_datagram(veil_chan_, packet.data(), packet.size());
  if (rc == 0) {
    if (video) {
      outbound_video_rtcp_packet_count_.fetch_add(1, std::memory_order_relaxed);
      outbound_video_rtcp_byte_count_.fetch_add(packet.size(), std::memory_order_relaxed);
    }
    outbound_rtcp_packet_count_.fetch_add(1, std::memory_order_relaxed);
    outbound_rtcp_byte_count_.fetch_add(packet.size(), std::memory_order_relaxed);
    outbound_packet_count_.fetch_add(1, std::memory_order_relaxed);
    outbound_byte_count_.fetch_add(packet.size(), std::memory_order_relaxed);
    return true;
  }
  outbound_dropped_count_.fetch_add(1, std::memory_order_relaxed);
  return false;
}

// static — invoked on a tokio worker thread (foreign to WebRTC). Queue a copy;
// the borrowed `ptr` is only valid for this call. Only authenticated plaintext
// reaches this callback; lane selection is private to this endpoint.
void VeilTransportShim::OnVeilDatagram(void* ctx, const uint8_t* ptr,
                                       size_t len) {
  auto* self = static_cast<VeilTransportShim*>(ctx);
  if (self == nullptr || ptr == nullptr || len == 0) return;
  if (!self->started_.load(std::memory_order_acquire)) return;
  MarkVideoFrame(std::span<const uint8_t>(ptr, len),
                 &self->inbound_video_cadence_);
  const int64_t arrived_us = webrtc::TimeMicros();
  const auto enqueue = [self, ptr, len, arrived_us](bool secondary) {
    const auto admission = self->inbound_queue_.PushToLane(
        std::span<const uint8_t>(ptr, len), secondary, arrived_us);
    if (admission == InboundPacketQueue::Admission::Dropped) {
      const auto dropped = self->inbound_dropped_overload_.fetch_add(
          1, std::memory_order_relaxed) + 1;
      if (dropped == 1 || dropped % 500 == 0)
        slog("shim drop inbound overload chan=%llu len=%zu drops=%llu",
             (unsigned long long)self->veil_chan_, len, (unsigned long long)dropped);
      return false;
    }
    if (admission == InboundPacketQueue::Admission::ScheduleDrain)
      self->PostInboundDrain(secondary);
    return true;
  };
  const bool rtcp = webrtc::IsRtcpPacket(std::span<const uint8_t>(ptr, len));
  const bool accepted = enqueue(IsSecondaryInboundRtp(std::span<const uint8_t>(ptr, len)));
  // Each Call owns independent SSRC/TWCC state. The upstream RTCP receiver
  // filters report blocks and transport feedback by its registered SSRCs.
  // A slow video network/worker queue cannot hold the audio copy.
  if (rtcp) enqueue(true);
  if (accepted) {
    if (self->inbound_packet_count_.load(std::memory_order_relaxed) == 0)
      slog("shim first inbound chan=%llu len=%zu", (unsigned long long)self->veil_chan_, len);
    self->inbound_packet_count_.fetch_add(1, std::memory_order_relaxed);
    self->inbound_byte_count_.fetch_add(len, std::memory_order_relaxed);
  }
}

void VeilTransportShim::PostInboundDrain(bool secondary) {
  auto* queue = secondary ? video_network_queue_ : network_queue_;
  queue->PostTask(
      [self = this, secondary, guard = task_guards_[secondary]]() {
        // The guard outlives the shim; the shim does not outlive the guard's
        // flag. Everything below touches `self`, so all of it is inside.
        std::lock_guard<std::mutex> lock(guard->mu);
        if (!guard->alive) return;
        auto packet = self->inbound_queue_.PopLane(secondary);
        if (!packet) return;
        if (self->started_.load(std::memory_order_acquire)) {
          self->DeliverOnNetworkThread(std::span<const uint8_t>(packet->bytes),
                                       secondary, packet->arrived_us);
        }
        // Yield after every packet so this shim cannot monopolize the shared
        // network queue or another peer in a group call. The guard also covers
        // posting the successor: no raw self access can outlive destruction.
        self->PostInboundDrain(secondary);
      });
}

AudioFeedbackSnapshot VeilTransportShim::audio_feedback() const {
  if (!started_.load(std::memory_order_acquire)) return {};
  std::lock_guard lock(audio_feedback_mu_);
  return audio_feedback_;
}

AudioPlayoutSnapshot VeilTransportShim::audio_playout_feedback() const {
  if (!started_.load(std::memory_order_acquire)) return {};
  std::lock_guard lock(audio_feedback_mu_);
  return audio_playout_feedback_;
}

void VeilTransportShim::SetLocalAudioPlayout(uint32_t remote_audio_ssrc,
                                            uint64_t sequence, int delay_ms,
                                            int64_t sampled_us) {
  std::lock_guard lock(audio_feedback_mu_);
  local_audio_playout_ = {true, remote_audio_ssrc, sequence,
                        delay_ms >= 0 && delay_ms <= 60000 ? delay_ms : -1,
                        sampled_us};
}

void VeilTransportShim::ObserveAudioFeedback(std::span<const uint8_t> packet,
                                             int64_t arrived_us) {
  const uint32_t local = local_audio_ssrc_.load(std::memory_order_relaxed);
  if (local == 0) return;
  AudioFeedbackSnapshot candidate;
  AudioPlayoutSnapshot playout;
  const auto observe = [&](const auto& blocks) {
    for (const auto& block : blocks) {
      if (block.source_ssrc() != local) continue;
      candidate.arrived_us = arrived_us;
      candidate.loss_pct = (int(block.fraction_lost()) * 100 + 128) / 256;
      candidate.jitter_ms = static_cast<int>(uint64_t(block.jitter()) * 1000 / 48000);
      if (block.last_sr() != 0) {
        auto* clock = webrtc::Clock::GetRealTimeClock();
        const uint32_t now = webrtc::CompactNtp(clock->ConvertTimestampToNtpTime(
            webrtc::Timestamp::Micros(arrived_us)));
        candidate.rtt_ms = webrtc::CompactNtpRttToTimeDelta(
            now - block.delay_since_last_sr() - block.last_sr()).ms();
      }
    }
  };
  // Parse the entire compound packet before publishing any observation. The
  // channel, rather than the claimed RTCP sender SSRC, identifies the peer.
  for (size_t offset = 0; offset < packet.size();) {
    webrtc::rtcp::CommonHeader header;
    if (!header.Parse(packet.data() + offset, packet.size() - offset)) return;
    if (header.type() == webrtc::rtcp::ReceiverReport::kPacketType) {
      webrtc::rtcp::ReceiverReport report;
      if (!report.Parse(header)) return;
      observe(report.report_blocks());
    } else if (header.type() == webrtc::rtcp::SenderReport::kPacketType) {
      webrtc::rtcp::SenderReport report;
      if (!report.Parse(header)) return;
      observe(report.report_blocks());
    } else if (header.type() == 204 && header.payload_size_bytes() >= 8 &&
               read_be32(header.payload() + 4) == kAudioPlayoutAppName) {
      if (header.count() != 0 || header.payload_size_bytes() != 24) return;
      const auto* app = header.payload();
      const uint32_t delay = read_be32(app + 20);
      if (delay != kUnknownPlayout && delay > 60000) return;
      // The authenticated channel identifies the participant; the target
      // SSRC binds the measurement to OUR audio, independently of video.
      if (read_be32(app + 8) == local) {
        const uint64_t sequence = uint64_t(read_be32(app + 12)) << 32 |
                                  read_be32(app + 16);
        if (!playout.supported || sequence > playout.sequence)
          playout = {true, sequence, arrived_us,
                     delay == kUnknownPlayout ? -1 : static_cast<int>(delay)};
      }
    }
    offset += header.packet_size();
  }
  if (candidate.arrived_us > 0 || playout.supported) {
    std::lock_guard lock(audio_feedback_mu_);
    if (candidate.arrived_us > 0 && candidate.arrived_us >= audio_feedback_.arrived_us)
      audio_feedback_ = candidate;
    if (playout.supported && (!audio_playout_feedback_.supported ||
        playout.sequence > audio_playout_feedback_.sequence))
      audio_playout_feedback_ = playout;
  }
}

void VeilTransportShim::DeliverOnNetworkThread(
    std::span<const uint8_t> packet, bool secondary, int64_t arrived_us) {
  MarkVideoFrame(packet, &delivered_video_cadence_);
  webrtc::PacketReceiver* receiver = (secondary ? video_call_ : call_)->Receiver();
  if (receiver == nullptr) return;

  // rtcp-mux demux (RFC 5761): route by packet type.
  if (webrtc::IsRtcpPacket(packet)) {
    if (!secondary) ObserveAudioFeedback(packet, arrived_us);
    receiver->DeliverRtcpPacket(
        webrtc::CopyOnWriteBuffer(packet.data(), packet.size()));
    return;
  }

  // RTP: parse then deliver. Call::DeliverRtpPacket routes to the audio vs video
  // demuxer BY the MediaType (not a hint) — so pick it from the SSRC. Audio and
  // video share this one datagram channel; the video SSRC is registered via
  // SetRemoteVideoSsrc when a video recv stream is created.
  webrtc::RtpHeaderExtensionMap extensions;
  if (independent_transport_feedback()) {
    extensions.Register<webrtc::TransportSequenceNumber>(webrtc::RtpHeaderExtensionId(1));
  }
  webrtc::RtpPacketReceived rtp(&extensions);
  if (!rtp.Parse(packet)) return;
  // The default is -infinity. Preserve ingress time rather than stamping the
  // later drain turn: local queueing is not network jitter.
  rtp.set_arrival_time(webrtc::Timestamp::Micros(arrived_us));
  const uint32_t vssrc = remote_video_ssrc_.load();
  const bool is_video = (vssrc != 0 && rtp.Ssrc() == vssrc);
  if (secondary != is_video) return;
  if (is_video) {
    // Video RTP uses the fixed 90 kHz clock. The audio path gets its clock from
    // the registered Opus codec, but nothing sets it for video on our custom
    // DeliverRtpPacket route, so the receive-statistics RTC_CHECK_GT(frequency,
    // 0) aborts (SIGABRT on the worker thread). Set it here.
    rtp.set_payload_type_frequency(webrtc::kVideoPayloadTypeFrequency);
  }
  receiver->DeliverRtpPacket(
      is_video ? webrtc::MediaType::VIDEO : webrtc::MediaType::AUDIO,
      std::move(rtp),
      /*undemuxable_packet_handler=*/
      [](const webrtc::RtpPacketReceived& /*parsed*/) {
        return false;  // drop packets we can't demux (no SSRC match)
      });
}

}  // namespace veil_media
