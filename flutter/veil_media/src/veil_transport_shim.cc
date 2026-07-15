/* SPDX-License-Identifier: MIT
 *
 * veil_transport_shim.cc — see veil_transport_shim.h.
 *
 * Depends on the veilclient-ffi media datagram ABI (linked into the host app):
 * the channel is already open; we only send + set the recv callback.
 */

#include "veil_transport_shim.h"

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <span>
#include <thread>
#include <utility>
#include <vector>

#include "api/task_queue/task_queue_base.h"
#include "call/call.h"
#include "call/packet_receiver.h"
#include "modules/rtp_rtcp/include/rtp_rtcp_defines.h"  // kVideoPayloadTypeFrequency
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
typedef void (*VeilMediaRecvFn)(void* ctx, const uint8_t* ptr, size_t len);
int veil_media_set_recv_callback(uint64_t chan, VeilMediaRecvFn cb, void* ctx);
}

namespace veil_media {
namespace {
constexpr size_t kMaxInboundPendingPackets = 256;
constexpr size_t kMaxInboundPendingBytes = 4 * 1024 * 1024;

void slog(const char* fmt, ...) {
  FILE* f = fopen("/tmp/veil_media_diag.log", "a");
  if (!f) return;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(f, fmt, ap);
  va_end(ap);
  fputc('\n', f);
  fclose(f);
}
}  // namespace

VeilTransportShim::VeilTransportShim(uint64_t veil_chan,
                                     webrtc::Call* call,
                                     webrtc::TaskQueueBase* network_queue)
    : veil_chan_(veil_chan), call_(call), network_queue_(network_queue) {}

VeilTransportShim::~VeilTransportShim() { Stop(); }

void VeilTransportShim::Start() {
  bool expected = false;
  if (!started_.compare_exchange_strong(expected, true)) return;
  veil_media_set_recv_callback(veil_chan_, &VeilTransportShim::OnVeilDatagram,
                               this);
}

void VeilTransportShim::Stop() {
  bool expected = true;
  if (!started_.compare_exchange_strong(expected, false)) return;
  veil_media_set_recv_callback(veil_chan_, nullptr, nullptr);
  for (int i = 0; i < 200; ++i) {
    if (inbound_pending_packets_.load(std::memory_order_acquire) == 0) return;
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  slog("shim Stop timed out with pending inbound packets=%zu bytes=%zu",
       inbound_pending_packets_.load(), inbound_pending_bytes_.load());
}

bool VeilTransportShim::SendRtp(std::span<const uint8_t> packet,
                                const webrtc::PacketOptions& options) {
  const int rc =
      veil_media_send_datagram(veil_chan_, packet.data(), packet.size());
  {
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
    call_->OnSentPacket(
        webrtc::SentPacketInfo(options.packet_id, webrtc::TimeMillis()));
  }
  return sent;
}

bool VeilTransportShim::SendRtcp(std::span<const uint8_t> packet,
                                 const webrtc::PacketOptions& options) {
  (void)options;  // RTCP carries no packet_id to feed back.
  const int rc =
      veil_media_send_datagram(veil_chan_, packet.data(), packet.size());
  if (rc == 0) {
    outbound_packet_count_.fetch_add(1, std::memory_order_relaxed);
    outbound_byte_count_.fetch_add(packet.size(), std::memory_order_relaxed);
    return true;
  }
  outbound_dropped_count_.fetch_add(1, std::memory_order_relaxed);
  return false;
}

// static — invoked on a tokio worker thread (foreign to WebRTC). Copy the bytes
// and hop to the network queue; the borrowed `ptr` is only valid for this call.
void VeilTransportShim::OnVeilDatagram(void* ctx, const uint8_t* ptr,
                                       size_t len) {
  auto* self = static_cast<VeilTransportShim*>(ctx);
  if (self == nullptr || ptr == nullptr || len == 0) return;
  if (!self->started_.load(std::memory_order_acquire)) return;
  const size_t pending_packets =
      self->inbound_pending_packets_.load(std::memory_order_relaxed);
  const size_t pending_bytes =
      self->inbound_pending_bytes_.load(std::memory_order_relaxed);
  if (pending_packets >= kMaxInboundPendingPackets ||
      pending_bytes + len > kMaxInboundPendingBytes) {
    const uint64_t dropped =
        self->inbound_dropped_overload_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (dropped == 1 || dropped % 500 == 0) {
      slog("shim drop inbound overload chan=%llu pending=%zu bytes=%zu len=%zu drops=%llu",
           (unsigned long long)self->veil_chan_, pending_packets,
           pending_bytes, len, (unsigned long long)dropped);
    }
    return;
  }
  std::vector<uint8_t> owned(ptr, ptr + len);
  self->inbound_packet_count_.fetch_add(1, std::memory_order_relaxed);
  self->inbound_byte_count_.fetch_add(len, std::memory_order_relaxed);
  self->inbound_pending_packets_.fetch_add(1, std::memory_order_release);
  self->inbound_pending_bytes_.fetch_add(owned.size(), std::memory_order_release);
  self->network_queue_->PostTask(
      [self, buf = std::move(owned)]() mutable {
        if (self->started_.load(std::memory_order_acquire)) {
          self->DeliverOnNetworkThread(std::span<const uint8_t>(buf));
        }
        self->inbound_pending_bytes_.fetch_sub(buf.size(),
                                               std::memory_order_release);
        self->inbound_pending_packets_.fetch_sub(1, std::memory_order_release);
      });
}

void VeilTransportShim::DeliverOnNetworkThread(
    std::span<const uint8_t> packet) {
  webrtc::PacketReceiver* receiver = call_->Receiver();
  if (receiver == nullptr) return;

  // rtcp-mux demux (RFC 5761): route by packet type.
  if (webrtc::IsRtcpPacket(packet)) {
    receiver->DeliverRtcpPacket(
        webrtc::CopyOnWriteBuffer(packet.data(), packet.size()));
    return;
  }

  // RTP: parse then deliver. Call::DeliverRtpPacket routes to the audio vs video
  // demuxer BY the MediaType (not a hint) — so pick it from the SSRC. Audio and
  // video share this one datagram channel; the video SSRC is registered via
  // SetRemoteVideoSsrc when a video recv stream is created.
  webrtc::RtpPacketReceived rtp;
  if (!rtp.Parse(packet)) return;
  const uint32_t vssrc = remote_video_ssrc_.load();
  const bool is_video = (vssrc != 0 && rtp.Ssrc() == vssrc);
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
