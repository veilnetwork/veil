/* SPDX-License-Identifier: MIT
 *
 * veil_transport_shim.cc — see veil_transport_shim.h.
 *
 * Depends on the veilclient-ffi media datagram ABI (linked into the host app):
 * the channel is already open; we only send + set the recv callback.
 */

#include "veil_transport_shim.h"

#include <atomic>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <span>
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
  if (started_) return;
  veil_media_set_recv_callback(veil_chan_, &VeilTransportShim::OnVeilDatagram,
                               this);
  started_ = true;
}

void VeilTransportShim::Stop() {
  if (!started_) return;
  veil_media_set_recv_callback(veil_chan_, nullptr, nullptr);
  started_ = false;
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
  // rc: 0 queued, 1 dropped (queue full), -1 invalid. A media transport is
  // lossy by design, so report success even on a local drop — the congestion
  // controller reacts to TWCC feedback, not to our queue depth, and returning
  // false here would trip spurious send failures inside the pacer.
  const bool sent = rc >= 0;

  // Close the send-side GCC timing loop. Our datagram send is synchronous on
  // the network thread, so stamp "now" and report immediately.
  if (options.packet_id != -1) {
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
  return rc >= 0;
}

// static — invoked on a tokio worker thread (foreign to WebRTC). Copy the bytes
// and hop to the network queue; the borrowed `ptr` is only valid for this call.
void VeilTransportShim::OnVeilDatagram(void* ctx, const uint8_t* ptr,
                                       size_t len) {
  auto* self = static_cast<VeilTransportShim*>(ctx);
  if (self == nullptr || ptr == nullptr || len == 0) return;
  std::vector<uint8_t> owned(ptr, ptr + len);
  self->network_queue_->PostTask(
      [self, buf = std::move(owned)]() mutable {
        self->DeliverOnNetworkThread(std::span<const uint8_t>(buf));
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
