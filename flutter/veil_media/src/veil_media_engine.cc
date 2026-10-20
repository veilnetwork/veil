/* SPDX-License-Identifier: MIT
 *
 * veil_media_engine.cc — implements the veil_media_engine_* control ABI
 * (veil_media_engine.h) on top of webrtc::Call + AudioState + the
 * VeilTransportShim. Built from source, codec-stripped (Opus only).
 *
 * Guarded by VEIL_MEDIA_HAVE_WEBRTC so the ABI + shim compile/link before the
 * trimmed WebRTC is vendored per platform. Construction runs on the FFI caller
 * thread; for the device test it should move onto the Call worker queue (see
 * THREADING notes) — release builds compile out the thread DCHECKs, so a first
 * single-control-thread run is workable.
 */

#include "veil_bounded_vp8.h"
#include "veil_media_engine.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// Deliberately outside the VEIL_MEDIA_HAVE_WEBRTC block: the lifetime rule it
// carries is about closures, not about media, and keeping it WebRTC-free is
// what lets test/run_on_smoke.cc check it on any host in under a second.
#include "veil_run_on.h"

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
// WIN32_LEAN_AND_MEAN drops the OLE half of windows.h, and CoGetApartmentType
// lives there. Only the apartment query below needs it.
#include <objbase.h>
#endif

#if defined(__ANDROID__)
#include <jni.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>
#endif

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
#include "api/audio/audio_device.h"
#include "api/audio/builtin_audio_processing_builder.h"
#include "api/audio/create_audio_device_module.h"

#include "api/audio_codecs/audio_format.h"
#include "api/audio_codecs/builtin_audio_decoder_factory.h"
#include "api/audio_codecs/builtin_audio_encoder_factory.h"
#include "bounded_audio_encoder.h"
#include "veil_audio_adaptor_config.h"
#include "veil_call_audio_processing.h"
#include "veil_group_audio_send_trace.h"
#include "call/rtp_transport_controller_send_interface.h"
#include "rtc_base/network_route.h"
#if defined(VEIL_MEDIA_TEST_HOOKS)
#include "../test/route_controller_observer.h"
#endif
#include "api/environment/environment.h"
#include "api/environment/environment_factory.h"
#if defined(VEIL_MEDIA_CC_TRACE)
#include "api/transport/goog_cc_factory.h"
#include "veil_video_cc_trace.h"
#endif
#include "api/field_trials_view.h"
#include "api/media_types.h"
#include "api/make_ref_counted.h"
#include "api/rtp_header_extension_id.h"
#include "api/rtp_headers.h"
#include "api/rtp_parameters.h"
#include "api/scoped_refptr.h"
#include "api/task_queue/task_queue_base.h"
#include "api/task_queue/task_queue_factory.h"
#include "api/units/time_delta.h"
#include "call/audio_receive_stream.h"
#include "call/audio_send_stream.h"
#include "call/audio_state.h"
#include "call/call.h"
#include "call/call_config.h"
#include "video_bitrate_settings.h"
#include "modules/audio_mixer/audio_mixer_impl.h"
// --- Video (Phase 4): VP8 send/recv over the same veil channel ---
#include "call/video_send_stream.h"
#include "call/video_receive_stream.h"
#include "video/config/video_encoder_config.h"
// Header-only template factories (VP8 only): CreateBuiltin*Video*Factory live in
// separate GN targets that `ninja webrtc` does NOT pull into libwebrtc.a, so
// calling them crashes (undefined -> null under -undefined dynamic_lookup). The
// templates instantiate in this TU and reference the VP8 impls that ARE in
// libwebrtc.a.
#include "api/video_codecs/video_encoder_factory_template.h"
#include "api/video_codecs/video_encoder_factory_template_libvpx_vp8_adapter.h"
#include "api/video_codecs/video_decoder_factory_template.h"
#include "api/video_codecs/video_decoder_factory_template_libvpx_vp8_adapter.h"
#include "api/video/builtin_video_bitrate_allocator_factory.h"
#include "api/video_codecs/sdp_video_format.h"
#include "api/video_codecs/video_encoder.h"
#include "api/video/video_codec_type.h"
#include "api/video/video_frame.h"
#include "api/video/i420_buffer.h"
#include "api/video/video_rotation.h"
#include "api/video/video_source_interface.h"
#include "api/video/video_sink_interface.h"
#include "veil_adaptive_video_source.h"
#include "veil_frame_sizing_vp8.h"
#include "veil_vp8_settings.h"
#include "third_party/libyuv/include/libyuv/convert_argb.h"  // I420ToABGR
#include "third_party/libyuv/include/libyuv/rotate.h"  // Android420ToI420Rotate
#include "rtc_base/time_utils.h"  // webrtc::TimeMicros
#include "system_wrappers/include/clock.h"
#include "rtc_base/network/sent_packet.h"  // webrtc::SentPacketInfo

#if defined(__APPLE__)
#include "veil_avf_adm.h"
#elif defined(__ANDROID__)
#include "veil_aaudio_adm.h"
#endif
#include "veil_camera.h"
#include "veil_diag_log.h"
#include "veil_screen.h"
#include "veil_transport_shim.h"
#include "veil_video_loss_trace.h"
#include "veil_video_decode_trace.h"
#include "veil_playout_recovery.h"
#endif

extern "C" int veil_media_send_datagram(uint64_t chan, const uint8_t* ptr,
                                         size_t len);
extern "C" int veil_media_send_video_control_datagram(uint64_t chan, const uint8_t* ptr,
                                                       size_t len);

namespace {

const char* kVersion = "veil_media 0.0.3 (group-video)";
constexpr int kOpusPayloadType = 111;  // SDP convention (Opus, 48k, stereo)

// What the encoder is ASKED for, in one place, because the default is not the
// right answer for a call.
//
// `SdpAudioFormat("opus", 48000, 2)` with no parameters gets WebRTC's Opus
// defaults: FEC off, DTX off, stereo negotiated. For a voice call on a mobile
// link every one of those is wrong:
//
//  * `stereo=0` — a microphone is one channel. Offering two doubled the bill
//    and carried nothing.
//  * `useinbandfec=1` — Opus LBRR embeds a low-rate copy of the PREVIOUS frame
//    in each packet, so one lost packet is reconstructed from the next rather
//    than concealed. This is the direct answer to dropouts, and it costs bitrate
//    only in proportion to the loss the encoder is told about (WebRTC feeds it
//    the RTCP loss fraction). Measured on the stand 2026-09-19, a link losing
//    a third of its packets in 0.6-2s bursts drove NetEQ's buffer to 1.1-1.4s
//    — the "strong delay" a listener hears is the jitter buffer growing to
//    cover holes that FEC would have filled.
//  * `usedtx=1` — silence stops costing ~35 kbit/s.
//
// NOT a flag day: these are encoder-side choices carried inside a
// self-describing Opus bitstream. A peer on an older build decodes mono, LBRR
// and DTX without knowing anything changed, and nothing here alters what WE
// accept. `ptime` is deliberately left at 20 ms: a longer frame would cut the
// packet rate further but adds its own latency, and latency is the complaint.
webrtc::SdpAudioFormat VeilOpusSendFormat() {
  return webrtc::SdpAudioFormat("opus", 48000, 2,
                                {{"stereo", "0"},
                                 {"useinbandfec", "1"},
                                 {"usedtx", "1"}});
}

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
// This Call carries only Opus and its feedback. WebRTC's default 300-kbit
// prior with no ceiling generated video-sized padding probes on the audio
// source connection. Keep room for Opus/FEC/RTP overhead without competing
// with real audio for a budget that only the separate video Call can use.
// This caps estimator/probe traffic; codec and Veil/relay policies are unchanged.
void configure_call_audio_transport(webrtc::CallConfig& config) {
  config.bitrate_config.start_bitrate_bps = 48'000;
  config.bitrate_config.max_bitrate_bps = 96'000;
}

// Call's bandwidth estimate does not reach Opus unless the stream joins its
// allocator. Use negotiated TWCC only: legacy peers cannot supply this feedback.
// Keep the existing mono ceiling and 20-ms duration by default. Opt-in ANA
// accounts for framing separately and retains the codec while durations change.
void configure_call_audio_send(webrtc::AudioSendStream::Config& config,
                               bool transport_feedback, int packet_overhead = 0,
                               std::shared_ptr<std::atomic<int>> packet_duration = {},
                               std::shared_ptr<veil_media::AudioPacketPriority> priority = {}) {
  if (!transport_feedback) return;
  config.min_bitrate_bps = veil_media::kFramingAudioMinPayloadBps;
  config.max_bitrate_bps = 32'000;
  config.include_in_congestion_control_allocation = true;
  if (packet_overhead > 0) {
    config.min_bitrate_bps = veil_media::kFramingAudioMinPayloadBps;
    // Gross allocation ceiling, not the codec ceiling. The bounded encoder
    // retains a 32-kbit payload cap and leaves room for control traffic.
    config.max_bitrate_bps = 80'000;
    config.send_codec_spec->format.parameters["minptime"] = "20";
    config.send_codec_spec->format.parameters["maxptime"] = "60";
    config.encoder_factory =
        webrtc::make_ref_counted<veil_media::BoundedAudioEncoderFactory>(
            std::move(packet_duration), config.rtp.ssrc, std::move(priority));
    config.audio_network_adaptor_config = veil_media::kFramingAudioAdaptorConfig;
  }
}

// Preserve room for 600-ms Opus bursts. A smaller 12-packet capacity reduced
// decoded PCM latency but flushed useful audio and substantially increased
// physical call interruptions. A target-delay cap alone also failed the PCM
// recovery gate. Keep fast time stretching without that lossy capacity change.
#if defined(VEIL_MEDIA_TEST_HOOKS)
size_t g_call_plane_audio_buffer_packets = 0;
#endif
void configure_call_audio_receive(
    webrtc::AudioReceiveStreamInterface::Config& config) {
  config.jitter_buffer_max_packets = 30;
#if defined(VEIL_MEDIA_TEST_HOOKS)
  if (g_call_plane_audio_buffer_packets)
    config.jitter_buffer_max_packets = g_call_plane_audio_buffer_packets;
#endif
  config.jitter_buffer_fast_accelerate = true;
}

// Sample on the audio worker, like ChannelReceive::UpdatePlayoutTimestamp.
// NetEq's filtered level uses the span of RTP timestamps. Recreating a peer's
// sender keeps its identity-derived SSRC but chooses a new timestamp origin;
// overlapping old/new packets can saturate that filter (~174 seconds) even
// while decoded PCM remains prompt. Count actual queued samples instead of
// using that timestamp span as the endpoint's video-adaptation signal. This
// does not change NetEq, discard audio, or cap a genuinely growing queue.
uint32_t current_audio_playout_delay(uint32_t buffered_ms,
                                     webrtc::AudioDeviceModule* adm) {
  uint16_t device_ms = 0;
  if (adm && adm->PlayoutDelay(&device_ms) == 0)
    return buffered_ms + device_ms;
  // An ADM without a delay reading also contributes zero to WebRTC's initial
  // estimate. The queue measurement and worker/packet freshness remain real.
  return buffered_ms;
}

constexpr int kVideoNackHistoryMs = 1000;
#endif

// Best-effort diagnostic log. File I/O is fail-closed unless the operator
// explicitly sets VEIL_MEDIA_DIAG_PATH; see veil_diag_log.h.
void vlog(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  veil_media::diag::vlog(fmt, ap);
  va_end(ap);
}

char* dup_cstr(const std::string& s) {
  char* out = static_cast<char*>(std::malloc(s.size() + 1));
  if (out) std::memcpy(out, s.c_str(), s.size() + 1);
  return out;
}

#if defined(__ANDROID__)
void update_atomic_max(std::atomic<int64_t>* target, int64_t value) {
  int64_t old = target->load(std::memory_order_relaxed);
  while (value > old && !target->compare_exchange_weak(
                            old, value, std::memory_order_relaxed)) {
  }
}
#endif

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
// Run `f` synchronously on `tq` and block until it finishes. webrtc::Call and
// its streams must be created/destroyed on the worker task queue (they call
// TaskQueueBase::Current(), which is null on the FFI caller thread → crash).
//
// Returns false if the queue never scheduled the task within the deadline. In
// that case `f` did NOT run and never will -- see veil_run_on.h for why that
// guarantee, and not the deadline, is the point.
//
// Every caller below passes a `[&]` lambda over its own frame, and a closure
// temporary dies at the semicolon of the call that created it. The shape this
// replaces -- post, wait ten seconds, return regardless -- therefore left the
// queue holding a reference to a dead closure over a dead frame, and the
// engine writing stream pointers into freed memory whenever the worker queue
// was wedged or already shut down (audit report8 H-07; ASan calls it
// stack-use-after-scope).
//
// `[[nodiscard]]`, because "the operation did not happen" is not a diagnostic
// this file can afford to drop on the floor: report9 V-02 was one call site
// that ignored it and destroyed a transport underneath the streams still
// configured with it. Every caller below now either propagates the failure or
// says in one line why it cannot happen there.
template <typename F>
[[nodiscard]] bool run_on(webrtc::TaskQueueBase* tq, F&& f) {
  const bool ran = veil_media::run_on_with_timeout(tq, std::forward<F>(f),
                                                   std::chrono::seconds(10));
  if (!ran) {
    // Not a diagnostic nicety: the operation the caller asked for did not
    // happen, and every callsite here is written as though it did.
    vlog("media: worker task queue did not schedule within 10s; "
         "operation skipped");
  }
  return ran;
}

// SSRC from the first 4 bytes of a node id (never 0 — 0 is an invalid SSRC).
uint32_t ssrc_of(const uint8_t id[32]) {
  uint32_t s = (uint32_t(id[0]) << 24) | (uint32_t(id[1]) << 16) |
               (uint32_t(id[2]) << 8) | uint32_t(id[3]);
  return s == 0 ? 1u : s;
}

// Video SSRC — derived from the node id but distinct from the audio SSRC so the
// far side (and our shim) can demux audio vs video on the one datagram channel.
uint32_t video_ssrc_of(const uint8_t id[32]) {
  uint32_t s = ssrc_of(id) ^ 0x000000FFu ^ 0x56440000u;  // "VD" tag
  return s == 0 ? 2u : s;
}

// Group receive streams share one webrtc::Call, so derive from the whole node
// id rather than the first four bytes used by the legacy 1:1 engine. A room
// rejects the extremely unlikely collision instead of binding media to the
// wrong authenticated participant.
uint32_t group_audio_ssrc_of(const uint8_t id[32]) {
  uint32_t hash = 2166136261u;  // FNV-1a
  for (size_t i = 0; i < 32; ++i) {
    hash ^= id[i];
    hash *= 16777619u;
  }
  hash ^= 0x47415544u;  // "GAUD"
  return hash == 0 ? 1u : hash;
}

uint32_t group_video_ssrc_of(const uint8_t id[32]) {
  uint32_t hash = 2166136261u;  // FNV-1a over the complete authenticated id
  for (size_t i = 0; i < 32; ++i) {
    hash ^= id[i];
    hash *= 16777619u;
  }
  hash ^= 0x47564944u;  // "GVID", distinct from the group-audio domain
  return hash == 0 ? 2u : hash;
}

std::string node_key(const uint8_t id[32]) {
  return std::string(reinterpret_cast<const char*>(id), 32);
}

// One encoded RTP stream is copied to every current peer channel. WebRTC gets
// one OnSentPacket notification per RTP packet (not one per fanout copy), so
// its pacer/BWE clock cannot be inflated by room size.
class GroupFanoutTransport : public webrtc::Transport {
 public:
  GroupFanoutTransport(webrtc::Call* call, webrtc::Call* video_call,
                       uint32_t audio_ssrc, uint32_t video_ssrc,
                       std::shared_ptr<veil_media::RtcpSendStats> rtcp_stats)
      : rtcp_stats_(std::move(rtcp_stats)), video_ssrc_(video_ssrc),
        audio_send_trace_(audio_ssrc),
        call_(call), video_call_(video_call) {}

  void Add(uint64_t chan) {
    std::lock_guard<std::mutex> lock(mu_);
    if (std::find(channels_.begin(), channels_.end(), chan) == channels_.end()) {
      channels_.push_back(chan);
      ++membership_epoch_;
    }
  }

  void Remove(uint64_t chan) {
    std::lock_guard<std::mutex> lock(mu_);
    const auto before = channels_.size();
    channels_.erase(std::remove(channels_.begin(), channels_.end(), chan),
                    channels_.end());
    if (channels_.size() != before) ++membership_epoch_;
  }

  void SetVideoSendPaused(bool paused) {
    if (!paused) video_remb_cadence_.Reset();
    video_send_paused_.store(paused);
  }

  bool SendRtp(std::span<const uint8_t> packet,
               const webrtc::PacketOptions& options) override {
    if (video_send_paused_.load() && veil_media::IsSecondaryInboundRtp(packet))
      return false;
    // Membership is caller-owned opaque handles, not raw engine pointers.
    // Snapshot under a short lock; video/RTCP sends must not hold audio here.
    // A removed/closed handle rejects a late already-selected send in Veil.
    const auto channels = Snapshot();
    bool any = false;
    for (const uint64_t chan : channels) {
      const int64_t began_ns = webrtc::TimeMicros() * 1000;
      const bool video = video_stats_.mark_attempt(packet, video_ssrc_, began_ns, 96);
      const int rc = veil_media_send_datagram(chan, packet.data(), packet.size());
      const bool sent = rc == 0;
      if (video)
        video_stats_.mark_result(began_ns, webrtc::TimeMicros() * 1000, sent);
      if (video)
        video_send_trace_.Rtp(packet, video_ssrc_, 's', began_ns / 1000, rc, chan);
      if (audio_send_trace_.enabled())
        audio_send_trace_.Record(chan, packet, began_ns / 1000,
                                 webrtc::TimeMicros(), sent);
      if (!sent && !veil_media::IsSecondaryInboundRtp(packet))
        audio_drops_.fetch_add(1, std::memory_order_relaxed);
      any = sent || any;
    }
    if (any && options.packet_id != -1) {
      (veil_media::IsSecondaryInboundRtp(packet) ? video_call_ : call_)->OnSentPacket(
          webrtc::SentPacketInfo(options.packet_id, webrtc::TimeMillis()));
    }
    return any;
  }

  bool SendRtcp(std::span<const uint8_t> packet,
                const webrtc::PacketOptions& options) override {
    return SendRtcpOnSource(packet, options, false);
  }

  bool SendVideoRtcp(std::span<const uint8_t> packet,
                     const webrtc::PacketOptions& options) {
    return SendRtcpOnSource(packet, options, true);
  }

  webrtc::Transport* video_transport() { return &video_transport_; }

 private:
  bool SendRtcpOnSource(std::span<const uint8_t> packet,
                        const webrtc::PacketOptions& options, bool video) {
    (void)options;
    // Membership is caller-owned opaque handles, not raw engine pointers.
    // Snapshot under a short lock; video/RTCP sends must not hold audio here.
    // A removed/closed handle rejects a late already-selected send in Veil.
    uint64_t epoch = 0;
    const auto channels = Snapshot(&epoch);
    const auto sent_us = video ? webrtc::TimeMicros() : 0;
    if (video && !channels.empty() && !video_remb_cadence_.Allow(packet, sent_us, epoch)) {
      rtcp_stats_->Coalesced(channels.size());
      return true;
    }
    bool any = false;
    bool all = !channels.empty();
    for (const uint64_t chan : channels) {
      const int rc = video
          ? veil_media_send_video_control_datagram(chan, packet.data(), packet.size())
          : veil_media_send_datagram(chan, packet.data(), packet.size());
      if (rc == 0) rtcp_stats_->Record(packet, video);
      all = rc == 0 && all;
      any = rc == 0 || any;
    }
    if (video && all) video_remb_cadence_.Accepted(packet, sent_us, epoch);
    return any;
  }

 public:
  uint64_t audio_drops() const { return audio_drops_.load(std::memory_order_relaxed); }
  veil_media::RtpSendSnapshot video_send_stats() const {
    return video_stats_.snapshot(webrtc::TimeMicros() * 1000);
  }

 private:
  veil_media::VideoControlTransport<GroupFanoutTransport> video_transport_{*this};
  std::shared_ptr<veil_media::RtcpSendStats> rtcp_stats_;
  std::vector<uint64_t> Snapshot(uint64_t* epoch = nullptr) {
    std::lock_guard<std::mutex> lock(mu_);
    if (epoch) *epoch = membership_epoch_;
    return channels_;
  }
  std::atomic<uint64_t> audio_drops_{0};
  const uint32_t video_ssrc_;
  veil_media::RtpSendStats video_stats_;
  veil_media::VideoLossTrace video_send_trace_;
  veil_media::GroupAudioSendTrace audio_send_trace_;
  std::atomic<bool> video_send_paused_{false};
  webrtc::Call* const call_;
  webrtc::Call* const video_call_;
  std::mutex mu_;
  std::vector<uint64_t> channels_;
  uint64_t membership_epoch_ = 0;
  veil_media::RembCadence video_remb_cadence_;
};

// The largest frame this engine will hold, per side.
//
// A decoded frame's dimensions come from the VP8 keyframe, and on the receive
// path that stream is the PEER's — the size is theirs to choose and nothing
// here bounded it. `rgba_.resize(w * h * 4)` at libvpx's own 16383 ceiling is
// 1.07 GB from a few crafted bytes, and these builds are `-fno-exceptions`,
// where a refused allocation is an abort rather than something a caller can
// handle. Calls here negotiate 352x288 by default and never ask for more than
// a 4K width, so this refuses only what no call would send.
constexpr int kMaxVideoSide = 4096;

// Sink for decoded remote video frames. Android can attach a native texture:
// OnFrame then retains only the latest I420 buffer and a dedicated worker
// coalesces/converts/posts it without blocking WebRTC's decode thread. Other
// platforms retain the RGBA pull path; Android diagnostics can still request
// one on-demand conversion. OnFrame runs on a WebRTC decode thread.
class VeilVideoSink : public webrtc::VideoSinkInterface<webrtc::VideoFrame> {
 public:
  explicit VeilVideoSink(uint32_t ssrc = 0) : decode_trace_(ssrc) {}
  ~VeilVideoSink() override {
#if defined(__ANDROID__)
    set_native_window(nullptr);
    {
      std::lock_guard<std::mutex> l(m_);
      render_stop_ = true;
    }
    render_cv_.notify_all();
    if (render_thread_.joinable()) render_thread_.join();
#endif
  }

  void OnFrame(const webrtc::VideoFrame& frame) override {
    auto buf = frame.video_frame_buffer()->ToI420();
    if (buf == nullptr) return;
    // The peer's number, checked before anything is sized from it.
    if (buf->width() <= 0 || buf->height() <= 0 ||
        buf->width() > kMaxVideoSide || buf->height() > kMaxVideoSide) {
      return;
    }
    decode_trace_.Record(frame.rtp_timestamp(), webrtc::TimeMicros(),
                         buf->width(), buf->height());
    std::lock_guard<std::mutex> l(m_);
#if defined(__ANDROID__)
    if (native_window_ != nullptr) {
      latest_i420_ = buf;
      rgba_.clear();
      w_ = buf->width();
      h_ = buf->height();
      mark_frame_locked();
      render_cv_.notify_one();
      return;
    }
#endif
    latest_i420_ = nullptr;
    store_i420_locked(buf->DataY(), buf->DataU(), buf->DataV(), buf->width(),
                      buf->height(), buf->StrideY(), buf->StrideU(),
                      buf->StrideV());
  }

  void store_i420(const uint8_t* y, const uint8_t* u, const uint8_t* v, int w,
                  int h, int stride_y, int stride_u, int stride_v) {
    if (y == nullptr || u == nullptr || v == nullptr) return;
    // The local capture path reaches this one, where the size comes from a
    // camera rather than from a peer — bounded all the same, so the buffer
    // below has one rule and not two.
    if (w <= 0 || h <= 0 || w > kMaxVideoSide || h > kMaxVideoSide) return;
    std::lock_guard<std::mutex> l(m_);
    latest_i420_ = nullptr;
    store_i420_locked(y, u, v, w, h, stride_y, stride_u, stride_v);
  }

#if defined(__ANDROID__)
  // Takes ownership of the ANativeWindow reference returned by
  // ANativeWindow_fromSurface. Passing null detaches and releases it.
  void set_native_window(ANativeWindow* window) {
    // Fence the render worker before replacing/releasing the Surface. Taking
    // render_m_ first guarantees that once detach returns no already-selected
    // old window can be locked or posted by the worker.
    bool start_worker = false;
    {
      std::lock_guard<std::mutex> render_l(render_m_);
      std::lock_guard<std::mutex> l(m_);
      if (native_window_ != nullptr) ANativeWindow_release(native_window_);
      native_window_ = window;
      native_window_width_ = 0;
      native_window_height_ = 0;
      rendered_seq_ = 0;
      rendered_frames_ = 0;
      rendered_w_ = 0;
      rendered_h_ = 0;
      first_render_ns_ = 0;
      last_render_ns_ = 0;
      max_render_gap_ns_ = 0;
      render_holds_75ms_ = 0;
      max_render_work_ns_ = 0;
      render_work_holds_16ms_ = 0;
      render_work_holds_33ms_ = 0;
      start_worker = window != nullptr && !render_thread_.joinable();
    }
    if (start_worker)
      render_thread_ = std::thread([this]() { render_loop(); });
    render_cv_.notify_all();
  }
#endif

#if defined(__ANDROID__)
  void frame_stats(int* out_w, int* out_h, uint64_t* out_frames,
                   int64_t* out_first_ns, int64_t* out_last_ns,
                   int64_t* out_max_gap_ns, uint64_t* out_holds_75ms,
                   uint64_t* out_decoded_frames,
                   int64_t* out_decoded_first_ns,
                   int64_t* out_decoded_last_ns,
                   int64_t* out_decoded_max_gap_ns,
                   uint64_t* out_decoded_holds_75ms,
                   int64_t* out_max_render_work_ns,
                   uint64_t* out_render_work_holds_16ms,
                   uint64_t* out_render_work_holds_33ms) {
    std::lock_guard<std::mutex> l(m_);
    if (out_w) *out_w = rendered_w_;
    if (out_h) *out_h = rendered_h_;
    if (out_frames) *out_frames = rendered_frames_;
    if (out_first_ns) *out_first_ns = first_render_ns_;
    if (out_last_ns) *out_last_ns = last_render_ns_;
    if (out_max_gap_ns) *out_max_gap_ns = max_render_gap_ns_;
    if (out_holds_75ms) *out_holds_75ms = render_holds_75ms_;
    if (out_decoded_frames) *out_decoded_frames = seq_;
    if (out_decoded_first_ns) *out_decoded_first_ns = first_frame_ns_;
    if (out_decoded_last_ns) *out_decoded_last_ns = last_frame_ns_;
    if (out_decoded_max_gap_ns)
      *out_decoded_max_gap_ns = max_frame_gap_ns_;
    if (out_decoded_holds_75ms)
      *out_decoded_holds_75ms = frame_holds_75ms_;
    if (out_max_render_work_ns)
      *out_max_render_work_ns = max_render_work_ns_;
    if (out_render_work_holds_16ms)
      *out_render_work_holds_16ms = render_work_holds_16ms_;
    if (out_render_work_holds_33ms)
      *out_render_work_holds_33ms = render_work_holds_33ms_;
  }
#endif

 private:
  void store_i420_locked(const uint8_t* y, const uint8_t* u,
                         const uint8_t* v, int w, int h, int stride_y,
                         int stride_u, int stride_v) {
    const size_t need = static_cast<size_t>(w) * h * 4;
    if (rgba_.size() < need) rgba_.resize(need);
    // I420 -> tightly packed RGBA (libyuv "ABGR" word == R,G,B,A bytes in memory,
    // which is what a Flutter rgba8888 texture / decodeImageFromPixels expects).
    libyuv::I420ToABGR(y, stride_y, u, stride_u, v, stride_v, rgba_.data(),
                       w * 4, w, h);
    w_ = w;
    h_ = h;
    mark_frame_locked();
  }

  void mark_frame_locked() {
    const int64_t now_ns = webrtc::TimeMicros() * 1000;
    if (first_frame_ns_ == 0) first_frame_ns_ = now_ns;
    if (last_frame_ns_ != 0) {
      const int64_t gap_ns = now_ns - last_frame_ns_;
      if (gap_ns > max_frame_gap_ns_) max_frame_gap_ns_ = gap_ns;
      if (gap_ns >= 75000000) ++frame_holds_75ms_;
    }
    last_frame_ns_ = now_ns;
    ++seq_;
  }

#if defined(__ANDROID__)
  // The decoder callback only replaces latest_i420_ and wakes this worker.
  // Surface backpressure and I420->RGBA conversion therefore never stall the
  // WebRTC decode thread; if rendering falls behind, intermediate frames are
  // deliberately coalesced and the newest decoded frame wins.
  void render_loop() {
    for (;;) {
      {
        std::unique_lock<std::mutex> l(m_);
        render_cv_.wait(l, [this]() {
          return render_stop_ ||
                 (native_window_ != nullptr && latest_i420_ != nullptr &&
                  seq_ != rendered_seq_);
        });
        if (render_stop_) return;
      }

      std::lock_guard<std::mutex> render_l(render_m_);
      webrtc::scoped_refptr<webrtc::I420BufferInterface> frame;
      ANativeWindow* window = nullptr;
      uint32_t selected_seq = 0;
      {
        std::lock_guard<std::mutex> l(m_);
        if (render_stop_) return;
        if (native_window_ == nullptr || latest_i420_ == nullptr ||
            seq_ == rendered_seq_) {
          continue;
        }
        frame = latest_i420_;
        window = native_window_;
        ANativeWindow_acquire(window);
        selected_seq = seq_;
        rendered_seq_ = selected_seq;
      }

      const int64_t work_started_ns = webrtc::TimeMicros() * 1000;
      const bool posted = render_native(window, frame.get());
      const int64_t work_ns = webrtc::TimeMicros() * 1000 - work_started_ns;
      ANativeWindow_release(window);
      if (!posted) continue;
      {
        std::lock_guard<std::mutex> l(m_);
        rendered_w_ = frame->width();
        rendered_h_ = frame->height();
        mark_render_locked(work_ns);
      }
    }
  }

  bool render_native(ANativeWindow* window,
                     const webrtc::I420BufferInterface* frame) {
    if (window == nullptr || frame == nullptr) return false;
    const int w = frame->width();
    const int h = frame->height();
    if (w != native_window_width_ || h != native_window_height_) {
      if (ANativeWindow_setBuffersGeometry(window, w, h,
                                            WINDOW_FORMAT_RGBA_8888) != 0) {
        return false;
      }
      native_window_width_ = w;
      native_window_height_ = h;
    }
    ANativeWindow_Buffer target{};
    if (ANativeWindow_lock(window, &target, nullptr) != 0) return false;
    const int rc = libyuv::I420ToABGR(
        frame->DataY(), frame->StrideY(), frame->DataU(), frame->StrideU(),
        frame->DataV(), frame->StrideV(),
        static_cast<uint8_t*>(target.bits), target.stride * 4, w, h);
    const int post_rc = ANativeWindow_unlockAndPost(window);
    return rc == 0 && post_rc == 0;
  }

  void mark_render_locked(int64_t work_ns) {
    const int64_t now_ns = webrtc::TimeMicros() * 1000;
    if (first_render_ns_ == 0) first_render_ns_ = now_ns;
    if (last_render_ns_ != 0) {
      const int64_t gap_ns = now_ns - last_render_ns_;
      if (gap_ns > max_render_gap_ns_) max_render_gap_ns_ = gap_ns;
      if (gap_ns >= 75000000) ++render_holds_75ms_;
    }
    if (work_ns > max_render_work_ns_) max_render_work_ns_ = work_ns;
    if (work_ns >= 16000000) ++render_work_holds_16ms_;
    if (work_ns >= 33000000) ++render_work_holds_33ms_;
    last_render_ns_ = now_ns;
    ++rendered_frames_;
  }
#endif

 public:
  // Copy the latest frame into dst. Returns seq (>0) if copied, 0 if none yet,
  // -1 if dst_cap too small (out_w/out_h still set).
  int get_frame(uint8_t* dst, int dst_cap, int* out_w, int* out_h) {
    std::lock_guard<std::mutex> l(m_);
    if (seq_ == 0 || seq_ == pulled_seq_ || w_ <= 0) return 0;
    if (out_w) *out_w = w_;
    if (out_h) *out_h = h_;
    const size_t need = static_cast<size_t>(w_) * h_ * 4;
    if (dst == nullptr || dst_cap < 0 || static_cast<size_t>(dst_cap) < need)
      return -1;
    if (latest_i420_ != nullptr) {
      if (libyuv::I420ToABGR(
              latest_i420_->DataY(), latest_i420_->StrideY(),
              latest_i420_->DataU(), latest_i420_->StrideU(),
              latest_i420_->DataV(), latest_i420_->StrideV(), dst, w_ * 4, w_,
              h_) != 0) {
        return 0;
      }
    } else {
      if (rgba_.size() < need) return 0;
      std::memcpy(dst, rgba_.data(), need);
    }
    pulled_seq_ = seq_;
    return static_cast<int>(seq_);
  }

 private:
  veil_media::VideoDecodeTrace decode_trace_;
  std::mutex m_;
  std::vector<uint8_t> rgba_;  // latest frame, RGBA (guarded by m_)
  webrtc::scoped_refptr<webrtc::I420BufferInterface> latest_i420_;
  int w_ = 0, h_ = 0;
  uint32_t seq_ = 0;
  uint32_t pulled_seq_ = 0;
  int64_t first_frame_ns_ = 0;
  int64_t last_frame_ns_ = 0;
  int64_t max_frame_gap_ns_ = 0;
  uint64_t frame_holds_75ms_ = 0;
#if defined(__ANDROID__)
  ANativeWindow* native_window_ = nullptr;
  int native_window_width_ = 0;
  int native_window_height_ = 0;
  std::condition_variable render_cv_;
  std::mutex render_m_;
  std::thread render_thread_;
  bool render_stop_ = false;
  uint32_t rendered_seq_ = 0;
  uint64_t rendered_frames_ = 0;
  int rendered_w_ = 0;
  int rendered_h_ = 0;
  int64_t first_render_ns_ = 0;
  int64_t last_render_ns_ = 0;
  int64_t max_render_gap_ns_ = 0;
  uint64_t render_holds_75ms_ = 0;
  int64_t max_render_work_ns_ = 0;
  uint64_t render_work_holds_16ms_ = 0;
  uint64_t render_work_holds_33ms_ = 0;
#endif
};

void broadcast_i420(veil_media::AdaptiveVideoSource* source,
                    webrtc::scoped_refptr<webrtc::I420Buffer> buf,
                    int64_t ts_us) {
  if (source != nullptr) source->PushI420(std::move(buf), ts_us);
}

// Copy a (possibly strided) I420 frame into the broadcaster (encoder source).
void push_i420(veil_media::AdaptiveVideoSource* source, const uint8_t* y,
               const uint8_t* u, const uint8_t* v, int width, int height,
               int stride_y, int stride_u, int stride_v, int64_t ts_us) {
  if (source == nullptr || width <= 0 || height <= 0) return;
  auto buf = webrtc::I420Buffer::Create(width, height);
  const int cw = (width + 1) / 2, ch = (height + 1) / 2;
  for (int r = 0; r < height; ++r)
    std::memcpy(buf->MutableDataY() + r * buf->StrideY(), y + r * stride_y,
                width);
  for (int r = 0; r < ch; ++r)
    std::memcpy(buf->MutableDataU() + r * buf->StrideU(), u + r * stride_u, cw);
  for (int r = 0; r < ch; ++r)
    std::memcpy(buf->MutableDataV() + r * buf->StrideV(), v + r * stride_v, cw);
  broadcast_i420(source, buf, ts_us);
}

#if defined(__ANDROID__)
struct Android420DispatchStats {
  std::atomic<int64_t> convert_max_ns{0};
  std::atomic<int64_t> broadcast_max_ns{0};
  std::atomic<uint64_t> convert_holds_16ms{0};
  std::atomic<uint64_t> convert_holds_33ms{0};
  std::atomic<uint64_t> broadcast_holds_16ms{0};
  std::atomic<uint64_t> broadcast_holds_33ms{0};
  std::atomic<uint64_t> submitted{0};
  std::atomic<uint64_t> processed{0};
  std::atomic<uint64_t> replaced{0};
};

// Camera2 owns only three ImageReader buffers. Doing Android420 conversion and
// the WebRTC source handoff inside its callback occasionally held one for
// 40--87 ms on the physical phone, which back-pressured the whole capture
// session (including the SurfaceTexture self-preview). Copy the three direct
// planes promptly, close the Image in Kotlin, and process only the newest
// pending frame on a native worker. A late camera frame is worthless; replacing
// it bounds latency and memory instead of building another video FIFO.
class Android420FrameDispatcher {
 public:
  explicit Android420FrameDispatcher(Android420DispatchStats* stats)
      : stats_(stats), worker_([this] { Run(); }) {}

  ~Android420FrameDispatcher() { Stop(); }

  bool Submit(veil_media::AdaptiveVideoSource* source, const uint8_t* y,
              const uint8_t* u, const uint8_t* v, int width, int height,
              int stride_y, int stride_u, int stride_v, int pixel_stride_uv,
              int rotation, int64_t ts_us) {
    const int chroma_width = (width + 1) / 2;
    const int chroma_height = (height + 1) / 2;
    const int64_t y_len = static_cast<int64_t>(height - 1) * stride_y + width;
    const int64_t u_len = static_cast<int64_t>(chroma_height - 1) * stride_u +
                          static_cast<int64_t>(chroma_width - 1) *
                              pixel_stride_uv +
                          1;
    const int64_t v_len = static_cast<int64_t>(chroma_height - 1) * stride_v +
                          static_cast<int64_t>(chroma_width - 1) *
                              pixel_stride_uv +
                          1;
    // This is a call-camera path (normally well under 1 MiB), but its C ABI is
    // public. Keep malformed strides from turning the latest-only copy into an
    // allocator attack.
    constexpr int64_t kMaxCopiedBytes = 32 * 1024 * 1024;
    if (source == nullptr || y_len <= 0 || u_len <= 0 || v_len <= 0 ||
        y_len > kMaxCopiedBytes || u_len > kMaxCopiedBytes ||
        v_len > kMaxCopiedBytes || y_len + u_len + v_len > kMaxCopiedBytes) {
      return false;
    }

    std::unique_ptr<Job> job;
    {
      std::lock_guard<std::mutex> lock(mu_);
      if (stop_) return false;
      job = std::move(spare_);
    }
    if (!job) job = std::make_unique<Job>();
    job->source = source;
    job->y.resize(static_cast<size_t>(y_len));
    job->u.resize(static_cast<size_t>(u_len));
    job->v.resize(static_cast<size_t>(v_len));
    std::memcpy(job->y.data(), y, job->y.size());
    std::memcpy(job->u.data(), u, job->u.size());
    std::memcpy(job->v.data(), v, job->v.size());
    job->width = width;
    job->height = height;
    job->stride_y = stride_y;
    job->stride_u = stride_u;
    job->stride_v = stride_v;
    job->pixel_stride_uv = pixel_stride_uv;
    job->rotation = rotation;
    job->ts_us = ts_us;

    {
      std::lock_guard<std::mutex> lock(mu_);
      if (stop_) {
        if (!spare_) spare_ = std::move(job);
        return false;
      }
      if (pending_) {
        stats_->replaced.fetch_add(1, std::memory_order_relaxed);
        if (!spare_) spare_ = std::move(pending_);
      }
      pending_ = std::move(job);
      stats_->submitted.fetch_add(1, std::memory_order_relaxed);
    }
    cv_.notify_one();
    return true;
  }

  void Stop() {
    bool was_stopped = false;
    {
      std::lock_guard<std::mutex> lock(mu_);
      was_stopped = stop_;
      stop_ = true;
      pending_.reset();
    }
    if (!was_stopped) cv_.notify_one();
    if (worker_.joinable()) worker_.join();
  }

 private:
  struct Job {
    veil_media::AdaptiveVideoSource* source = nullptr;
    std::vector<uint8_t> y;
    std::vector<uint8_t> u;
    std::vector<uint8_t> v;
    int width = 0;
    int height = 0;
    int stride_y = 0;
    int stride_u = 0;
    int stride_v = 0;
    int pixel_stride_uv = 0;
    int rotation = 0;
    int64_t ts_us = 0;
  };

  void Run() {
    for (;;) {
      std::unique_ptr<Job> job;
      {
        std::unique_lock<std::mutex> lock(mu_);
        cv_.wait(lock, [this] { return stop_ || pending_ != nullptr; });
        if (stop_) return;
        job = std::move(pending_);
      }
      Process(*job);
      {
        std::lock_guard<std::mutex> lock(mu_);
        if (!spare_) spare_ = std::move(job);
      }
    }
  }

  void Process(const Job& job) {
    const int64_t convert_started_ns = webrtc::TimeMicros() * 1000;
    const bool swap = job.rotation == 90 || job.rotation == 270;
    const int out_width = swap ? job.height : job.width;
    const int out_height = swap ? job.width : job.height;
    auto buf = webrtc::I420Buffer::Create(out_width, out_height);
    int rc = libyuv::Android420ToI420Rotate(
        job.y.data(), job.stride_y, job.u.data(), job.stride_u,
        job.v.data(), job.stride_v, job.pixel_stride_uv,
        buf->MutableDataY(), buf->StrideY(), buf->MutableDataU(),
        buf->StrideU(), buf->MutableDataV(), buf->StrideV(), job.width,
        job.height, static_cast<libyuv::RotationMode>(job.rotation));
    if (rc != 0 && job.rotation != 0) {
      auto unrotated = webrtc::I420Buffer::Create(job.width, job.height);
      rc = libyuv::Android420ToI420Rotate(
          job.y.data(), job.stride_y, job.u.data(), job.stride_u,
          job.v.data(), job.stride_v, job.pixel_stride_uv,
          unrotated->MutableDataY(), unrotated->StrideY(),
          unrotated->MutableDataU(), unrotated->StrideU(),
          unrotated->MutableDataV(), unrotated->StrideV(), job.width,
          job.height, libyuv::kRotate0);
      if (rc == 0) {
        rc = libyuv::I420Rotate(
            unrotated->DataY(), unrotated->StrideY(), unrotated->DataU(),
            unrotated->StrideU(), unrotated->DataV(), unrotated->StrideV(),
            buf->MutableDataY(), buf->StrideY(), buf->MutableDataU(),
            buf->StrideU(), buf->MutableDataV(), buf->StrideV(), job.width,
            job.height, static_cast<libyuv::RotationMode>(job.rotation));
      }
    }
    const int64_t converted_ns = webrtc::TimeMicros() * 1000;
    const int64_t convert_work_ns = converted_ns - convert_started_ns;
    update_atomic_max(&stats_->convert_max_ns, convert_work_ns);
    if (convert_work_ns >= 16'000'000)
      stats_->convert_holds_16ms.fetch_add(1, std::memory_order_relaxed);
    if (convert_work_ns >= 33'000'000)
      stats_->convert_holds_33ms.fetch_add(1, std::memory_order_relaxed);
    if (rc != 0) return;

    broadcast_i420(job.source, buf, job.ts_us);
    const int64_t broadcast_work_ns = webrtc::TimeMicros() * 1000 - converted_ns;
    update_atomic_max(&stats_->broadcast_max_ns, broadcast_work_ns);
    if (broadcast_work_ns >= 16'000'000)
      stats_->broadcast_holds_16ms.fetch_add(1, std::memory_order_relaxed);
    if (broadcast_work_ns >= 33'000'000)
      stats_->broadcast_holds_33ms.fetch_add(1, std::memory_order_relaxed);
    stats_->processed.fetch_add(1, std::memory_order_relaxed);
  }

  Android420DispatchStats* const stats_;
  std::mutex mu_;
  std::condition_variable cv_;
  std::unique_ptr<Job> pending_;
  std::unique_ptr<Job> spare_;
  bool stop_ = false;
  std::thread worker_;
};
#endif

// All webrtc state, constructed together in create() (Environment has no
// default ctor, so it can't be a bare member of the C-ABI handle).
struct WebrtcState {
  explicit WebrtcState(webrtc::Environment e) : env(std::move(e)) {}
  webrtc::Environment env;
  std::unique_ptr<webrtc::TaskQueueBase, webrtc::TaskQueueDeleter> worker_tq;
  std::unique_ptr<webrtc::TaskQueueBase, webrtc::TaskQueueDeleter> network_tq;
  std::unique_ptr<webrtc::TaskQueueBase, webrtc::TaskQueueDeleter> video_worker_tq;
  std::unique_ptr<webrtc::TaskQueueBase, webrtc::TaskQueueDeleter> video_network_tq;
  webrtc::scoped_refptr<webrtc::AudioDeviceModule> adm;
  webrtc::scoped_refptr<webrtc::AudioProcessing> apm;
  webrtc::scoped_refptr<webrtc::AudioState> audio_state;
  std::shared_ptr<veil_media::PlayoutRecoveryStats> recovery_stats =
      std::make_shared<veil_media::PlayoutRecoveryStats>();
  std::atomic<uint64_t> recovery_sample_sequence{0};
  std::unique_ptr<webrtc::NetEqFactory> recovery_factory;
  std::unique_ptr<webrtc::Call> call;  // audio only
  std::unique_ptr<webrtc::Call> video_call;
  // Local opaque path generation; never transmitted or used as a relay role.
  // Each controller consumes it on its own worker. A busy video worker cannot
  // delay the audio route update, and cancelled work retries at the next poll.
  std::atomic<uint64_t> route_generation{0};
  std::atomic<uint64_t> audio_route_applied{0}, video_route_applied{0};
  std::atomic<int> video_packet_overhead{0};
#if defined(VEIL_MEDIA_TEST_HOOKS)
  std::shared_ptr<std::atomic<int>> audio_route_restarts = std::make_shared<std::atomic<int>>(0);
  std::shared_ptr<std::atomic<int>> video_route_restarts = std::make_shared<std::atomic<int>>(0);
#endif
  std::unique_ptr<veil_media::VeilTransportShim> shim;
  webrtc::AudioSendStream* send_stream = nullptr;             // owned by Call
  webrtc::AudioReceiveStreamInterface* recv_stream = nullptr;  // owned by Call
  // Per-engine encoder observation; zero means no actual adaptive packet yet.
  // Atomics bridge encoder and diagnostic threads without a worker round trip.
  std::shared_ptr<std::atomic<int>> audio_packet_duration =
      std::make_shared<std::atomic<int>>(0);
  std::shared_ptr<veil_media::AudioPacketPriority> audio_packet_priority =
      std::make_shared<veil_media::AudioPacketPriority>();
  // Video (Phase 4) — factories + source/sink outlive the streams.
  std::shared_ptr<veil_media::VideoFrameBudget> video_frame_budget =
      std::make_shared<veil_media::VideoFrameBudget>();
  std::unique_ptr<webrtc::VideoEncoderFactory> video_encoder_factory;
  std::unique_ptr<webrtc::VideoDecoderFactory> video_decoder_factory;
  std::unique_ptr<webrtc::VideoBitrateAllocatorFactory> video_bitrate_alloc_factory;
  std::unique_ptr<veil_media::AdaptiveVideoSource> video_source;  // pushable
  std::unique_ptr<VeilVideoSink> video_sink;               // renderer
  std::unique_ptr<VeilVideoSink> local_video_sink;         // self-preview
  webrtc::VideoSendStream* video_send_stream = nullptr;              // owned by Call
  webrtc::VideoReceiveStreamInterface* video_recv_stream = nullptr;  // owned by Call
  std::thread test_video_thread;         // synthetic source (VEIL_MEDIA_TEST_VIDEO)
  std::atomic<bool> test_video_run{false};
  std::unique_ptr<veil_media::CameraCapturer> camera;  // real capture source
  std::unique_ptr<veil_media::ScreenCapturer> screen;  // screen-share source
  int video_target_bitrate_bps = 0;
  std::atomic<double> video_max_fps{0};
  std::atomic<bool> video_send_paused{false};
  // Route-specific RTP packet ceiling configured before the send stream is
  // created. Relay compact mode uses 1000 so the symmetrically sealed Delivery
  // frame remains one QUIC DATAGRAM instead of a loss-amplifying fragment pair.
  int video_max_rtp_packet_size = 0;
  // Camera2/AVFoundation are external sources. Reconfiguring libwebrtc's
  // encoder advertises a lower max_framerate but does not reliably make those
  // sources shed frames, so a congested relay kept emitting at the physical
  // camera's 30 fps. Gate only the encoder handoff; local preview remains at
  // capture/display cadence.
  std::atomic<int64_t> video_last_encoded_frame_us{0};
#if defined(__ANDROID__)
  // Camera2's ImageReader callback must not be held by hidden work in the
  // native push. Split the synchronous JNI duration into pixel conversion and
  // VideoBroadcaster handoff so physical-call telemetry can prove which side
  // needs decoupling; all counters are single-writer atomics because get_stats
  // reads them from the Dart/UI side concurrently.
  Android420DispatchStats android420_stats;
  std::unique_ptr<Android420FrameDispatcher> android420_dispatcher;
#endif
};

template <typename VideoState>
bool should_encode_video_frame(VideoState* ws) {
  if (ws == nullptr) return false;
  if (ws->video_send_paused.load()) return false;
  if (ws->audio_packet_priority && ws->audio_packet_priority->VideoBlocked()) return false;
  const double fps = ws->video_max_fps.load(std::memory_order_relaxed);
  if (fps <= 0) return true;
  const int64_t now_us = webrtc::TimeMicros();
  const int64_t min_interval_us = static_cast<int64_t>(std::ceil(1'000'000.0 / fps));
  // Keep an ideal send timeline instead of storing the wall-clock time of the
  // last accepted frame.  A plain `now - last >= interval` gate turns a 60 Hz
  // source into 30 fps for every target between 31 and 59 because the first
  // 16 ms frame misses the threshold and the next accepted frame restarts the
  // interval. Advancing by exactly one interval preserves the fractional
  // credit and converges on targets such as 45 or 18 fps without bursts.
  const int64_t timing_tolerance_us =
      std::min<int64_t>(2'000, min_interval_us / 20);
  int64_t previous =
      ws->video_last_encoded_frame_us.load(std::memory_order_relaxed);
  for (;;) {
    if (previous > 0 && now_us >= previous &&
        now_us - previous + timing_tolerance_us < min_interval_us) {
      return false;
    }
    int64_t next = now_us;
    if (previous > 0 && now_us >= previous &&
        now_us - previous <= min_interval_us * 4) {
      next = previous + min_interval_us;
    }
    if (ws->video_last_encoded_frame_us.compare_exchange_weak(
            previous, next, std::memory_order_relaxed,
            std::memory_order_relaxed)) {
      return true;
    }
  }
}

struct GroupPeerState {
  uint64_t chan = 0;
  uint8_t id[32] = {0};
  uint32_t audio_ssrc = 0;
  uint32_t video_ssrc = 0;
  uint64_t observed_playout_sequence = 0;
  bool observed_playout_supported = false;
  bool observed_playout_fresh = false;
  std::unique_ptr<veil_media::VeilTransportShim> shim;
  webrtc::AudioReceiveStreamInterface* recv_stream = nullptr;  // owned by Call
  std::unique_ptr<VeilVideoSink> video_sink;
  webrtc::VideoReceiveStreamInterface* video_recv_stream = nullptr;
};

struct GroupWebrtcState {
  explicit GroupWebrtcState(webrtc::Environment e) : env(std::move(e)) {}
  webrtc::Environment env;
  std::unique_ptr<webrtc::TaskQueueBase, webrtc::TaskQueueDeleter> worker_tq;
  std::unique_ptr<webrtc::TaskQueueBase, webrtc::TaskQueueDeleter> network_tq;
  std::unique_ptr<webrtc::TaskQueueBase, webrtc::TaskQueueDeleter> video_worker_tq;
  std::unique_ptr<webrtc::TaskQueueBase, webrtc::TaskQueueDeleter> video_network_tq;
  webrtc::scoped_refptr<webrtc::AudioDeviceModule> adm;
  webrtc::scoped_refptr<webrtc::AudioProcessing> apm;
  webrtc::scoped_refptr<webrtc::AudioState> audio_state;
  std::shared_ptr<veil_media::PlayoutRecoveryStats> recovery_stats =
      std::make_shared<veil_media::PlayoutRecoveryStats>();
  std::unique_ptr<webrtc::NetEqFactory> recovery_factory;
  std::unique_ptr<webrtc::Call> call;  // audio only
  std::unique_ptr<webrtc::Call> video_call;
  // Includes both sender fanout and receiver-shim RTCP; peer removal cannot
  // erase previously admitted copies from these call-wide diagnostics.
  std::shared_ptr<veil_media::RtcpSendStats> rtcp_send_stats =
      std::make_shared<veil_media::RtcpSendStats>();
  std::unique_ptr<GroupFanoutTransport> fanout;
  webrtc::AudioSendStream* send_stream = nullptr;  // owned by Call
  webrtc::scoped_refptr<webrtc::AudioEncoderFactory> audio_encoder_factory;
  std::shared_ptr<std::atomic<int>> audio_packet_duration =
      std::make_shared<std::atomic<int>>(0);
  int audio_packet_ms = 20;  // Audio-worker owned requested configuration.
  // Group packet lengths are explicitly coordinated by the room controller.
  std::shared_ptr<veil_media::AudioPacketPriority> audio_packet_priority;
  int audio_payload_bps = 32'000;
  bool audio_config_valid = true;
  std::shared_ptr<veil_media::VideoFrameBudget> video_frame_budget =
      std::make_shared<veil_media::VideoFrameBudget>();
  std::unique_ptr<webrtc::VideoEncoderFactory> video_encoder_factory;
  std::unique_ptr<webrtc::VideoDecoderFactory> video_decoder_factory;
  std::unique_ptr<webrtc::VideoBitrateAllocatorFactory>
      video_bitrate_alloc_factory;
  std::unique_ptr<veil_media::AdaptiveVideoSource> video_source;
  std::unique_ptr<VeilVideoSink> local_video_sink;
  webrtc::VideoSendStream* video_send_stream = nullptr;
  std::thread test_video_thread;
  std::atomic<bool> test_video_run{false};
  int video_target_bitrate_bps = 0;
  std::atomic<double> video_max_fps{0};
  std::atomic<bool> video_send_paused{false};
  std::atomic<int64_t> video_last_encoded_frame_us{0};
  std::unique_ptr<veil_media::CameraCapturer> camera;
  std::unique_ptr<veil_media::ScreenCapturer> screen;
  std::map<std::string, std::unique_ptr<GroupPeerState>> peers;
  int prepared_video_bps = 0;  // Video-worker owned, consumed by next start.
  double prepared_video_fps = 1;
  uint64_t audio_sample_sequence = 0;
  uint64_t audio_playout_revision = 0;
  size_t observed_playout_peer_count = 0;
};

constexpr int kGroupVp8PayloadType = 96;

webrtc::AudioSendStream::Config group_audio_send_config(
    GroupWebrtcState* ws, uint32_t ssrc, int packet_ms, int payload_bps) {
  webrtc::AudioSendStream::Config config(ws->fanout.get());
  config.rtp.ssrc = ssrc;
  config.rtp.extensions.emplace_back(
      webrtc::RtpExtension::kTransportSequenceNumberUri,
      webrtc::RtpHeaderExtensionId(1));
  if (!ws->audio_encoder_factory)
    ws->audio_encoder_factory =
        webrtc::make_ref_counted<veil_media::BoundedAudioEncoderFactory>(
            ws->audio_packet_duration, ssrc);
  config.encoder_factory = ws->audio_encoder_factory;
  auto format = VeilOpusSendFormat();
  format.parameters["ptime"] = std::to_string(packet_ms);
  config.send_codec_spec = webrtc::AudioSendStream::Config::SendCodecSpec(
      kOpusPayloadType, format);
  config.send_codec_spec->target_bitrate_bps = payload_bps;
  // Each listener has its own feedback domain. Do not feed multiple listeners'
  // TWCC into a shared sender allocator or pretend a local policy is BWE.
  return config;
}

bool reconfigure_group_audio(GroupWebrtcState* ws,
                             const webrtc::AudioSendStream::Config& config) {
  // The pinned WebRTC invokes this on the worker before Reconfigure returns.
  // Shared storage also keeps a deferred error callback safe, and a subsequent
  // OK callback cannot overwrite an earlier codec-creation error.
  auto outcome = std::make_shared<std::atomic<int>>(0);
  ws->send_stream->Reconfigure(config, [outcome](webrtc::RTCError error) {
    if (!error.ok()) {
      outcome->store(-1, std::memory_order_release);
    } else {
      int pending = 0;
      outcome->compare_exchange_strong(pending, 1, std::memory_order_acq_rel);
    }
  });
  return outcome->load(std::memory_order_acquire) == 1;
}

// Real-time conversation should recover from a network spike by dropping late
// video, not by retaining an ever-growing playout tail. The app already pulls
// latest-only decoded frames, so cap WebRTC's adaptive video delay while still
// leaving enough room for ordinary relay jitter. This is receiver-local and
// therefore also protects calls from older peers that send no playout-delay
// RTP extension.
class LowLatencyFieldTrials final : public webrtc::FieldTrialsView {
 public:
  explicit LowLatencyFieldTrials(bool video = false) : video_(video) {}
  std::string Lookup(absl::string_view key) const override {
    // Start each estimator at its selected budget, including after handover.
    // The default 3x/6x bursts can queue audio's own padded probes on a newly
    // selected narrow path. Keep feedback and subsequent probes; neither Call
    // needs to overrun its initial allocation to announce the new route.
    // This is local production control, not relay-visible prioritization.
    if (key == "WebRTC-Bwe-InitialProbing")
      return "p1:1,p2:0";
    // Reordering history advances only on received packets. With Opus DTX,
    // the default 0.9993 factor can preserve a short radio burst throughout
    // a long silent interval and delay the next spoken syllable. Ordered
    // bursts need separate handling: after histogram startup, the default
    // underrun factor 0.983 keeps a 10-second burst in the target long after
    // delivery recovers. Forget that history faster while retaining its
    // 95th-percentile/500-ms estimator and the 30-packet capacity. Neither
    // estimator caps current delay or discards queued speech. This is entirely
    // receiver-local; no media role or priority is disclosed to the network.
    if (key == "WebRTC-Audio-NetEqDelayManagerConfig")
      return "forget_factor:0.90,reorder_forget_factor:0.95";
    if (key == "WebRTC-ForcePlayoutDelay") {
      // A small receiver-side floor lets WebRTC schedule through isolated
      // phone-radio bursts instead of presenting every arrival gap. Physical
      // relay A/B at 30 fps turned 10 >=75 ms network gaps into only 2 decoded
      // holds (versus 8/11 without the floor), while actual video delay moved
      // from 37--43 ms to 60 ms. The environment override keeps zero-floor and
      // larger-floor stand comparisons possible without changing the wire.
      // The hard 200 ms ceiling is unchanged, so no mode can accumulate a long
      // playout tail.
      int min_ms = 60;
      if (const char* value = std::getenv("VEIL_MEDIA_PLAYOUT_MIN_MS")) {
        min_ms = std::clamp(std::atoi(value), 0, 200);
      }
      return "min_ms:" + std::to_string(min_ms) + ",max_ms:200";
    }
    // VideoSendStreamImpl otherwise raises even an explicit low-rate layer
    // back to its 30-kbit/s registration floor. The per-stream layer and Call
    // budgets still set their own minima; allow the endpoint policy to go
    // down to 1 kbit/s without altering audio or any transport/relay metadata.
    if (key == "WebRTC-Video-MinVideoBitrate") return "Enabled,br:1kbps";
    if (video_ && key == "WebRTC-VideoRateControl")
      return veil_media::vp8_rate_control_trial();
    // Small frames still need at least one RTP packet each. A payload/MTU
    // ratio alone undercounts framing as capture cadence increases. Let the
    // video allocator charge at least the observed encoder frame rate.
    if (video_ && key == "WebRTC-Video-UseFrameRateForOverhead") return "Enabled";
    // libwebrtc's send-side feedback profile paces at only 1.1x and permits a
    // two-second queue by default. That is appropriate for a UDP transport
    // whose congestion controller receives TWCC, but our authenticated veil
    // datagram is already rate-limited by the route profile and has no TWCC
    // feedback loop. Physical-call cadence instrumentation showed the result:
    // a perfectly regular 30 fps camera developed 75--270 ms gaps at SendRtp,
    // with the receiver reproducing those gaps byte-for-byte and adding none
    // between arrival and WebRTC delivery. Keep the encoder's average bitrate
    // unchanged, but drain each encoded-frame burst promptly. There is no
    // timer/prefill here: the pacer may send immediately, while max_delay only
    // bounds how long an already-queued packet may wait. A 4x burst budget and
    // 25 ms queue target keep that recovery comfortably inside one 30 fps
    // frame interval; the outer veil sender still yields after eight queued
    // RTP packets, so video cannot monopolize its transport writer.
    if (key == "WebRTC-Video-Pacing") return "factor:4.0,max_delay:25ms";
#if defined(__ANDROID__)
    // libvpx otherwise chooses three encoder workers on >=4-core Android
    // devices. Two comfortably sustain the measured 640x360@30 input while
    // leaving thermal and scheduling headroom for decode, audio and the veil
    // node. This is a local implementation choice, not a wire-format change.
    if (key == "WebRTC-VideoEncoderSettings")
      return "encoder_thread_limit:2";
#endif
    return {};
  }

  std::unique_ptr<webrtc::FieldTrialsView> CreateCopy() const override {
    return std::make_unique<LowLatencyFieldTrials>(video_);
  }

 private:
  const bool video_;
};

webrtc::Environment create_low_latency_environment(bool video = false) {
  // The trimmed libwebrtc archive does not contain the concrete FieldTrials
  // parser implementation. Supplying the tiny immutable view directly keeps
  // all Environment defaults (clock/task queues/event log) and avoids leaving
  // an unresolved constructor for permissive Apple dynamic linking to turn
  // into a null call at engine creation.
  return webrtc::CreateEnvironment(
      std::make_unique<LowLatencyFieldTrials>(video));
}

void ensure_group_video_codecs(GroupWebrtcState* ws) {
  if (!ws->video_encoder_factory)
    ws->video_encoder_factory =
        std::make_unique<veil_media::FrameSizingVp8EncoderFactory>(
            std::make_unique<webrtc::VideoEncoderFactoryTemplate<
                webrtc::LibvpxVp8EncoderTemplateAdapter>>(), ws->video_frame_budget);
  if (!ws->video_decoder_factory)
    ws->video_decoder_factory =
        // BOUNDED. `VeilVideoSink` refuses an oversized frame where it
        // arrives, and libvpx has already sized four reference buffers from the
        // keyframe by then — see `veil_bounded_vp8.h` (report24 MEDIA-3).
        std::make_unique<veil_media::BoundedVp8DecoderFactory>(
            std::make_unique<webrtc::VideoDecoderFactoryTemplate<
                  webrtc::LibvpxVp8DecoderTemplateAdapter>>(),
            kMaxVideoSide);
  if (!ws->video_bitrate_alloc_factory)
    ws->video_bitrate_alloc_factory =
        webrtc::CreateBuiltinVideoBitrateAllocatorFactory();
  if (!ws->video_source)
    ws->video_source = std::make_unique<veil_media::AdaptiveVideoSource>(ws->video_frame_budget);
  if (!ws->local_video_sink)
    ws->local_video_sink = std::make_unique<VeilVideoSink>();
}

bool start_group_peer_video(GroupWebrtcState* ws, GroupPeerState* peer) {
  if (peer->video_recv_stream) return true;
  if (!ws->video_decoder_factory || !peer->video_sink) return false;
  webrtc::VideoReceiveStreamInterface::Config rc(
      peer->shim->video_transport(), ws->video_decoder_factory.get());
  rc.rtp.remote_ssrc = peer->video_ssrc;
  rc.rtp.nack.rtp_history_ms = kVideoNackHistoryMs;
  rc.renderer = peer->video_sink.get();
  rc.decoders.emplace_back(webrtc::SdpVideoFormat::VP8(),
                           kGroupVp8PayloadType);
  peer->video_recv_stream = ws->video_call->CreateVideoReceiveStream(std::move(rc));
  if (!peer->video_recv_stream) return false;
  peer->video_recv_stream->Start();
  peer->shim->SetRemoteVideoSsrc(peer->video_ssrc);
  return true;
}

void stop_group_peer_video(GroupWebrtcState* ws, GroupPeerState* peer) {
  peer->shim->SetRemoteVideoSsrc(0);
  if (!peer->video_recv_stream) return;
  peer->video_recv_stream->Stop();
  ws->video_call->DestroyVideoReceiveStream(peer->video_recv_stream);
  peer->video_recv_stream = nullptr;
}
#endif

}  // namespace

struct VeilMediaEngine {
  std::mutex config_mu;
  bool config_frozen = false;
  std::atomic<int> audio_packet_overhead{0};
  uint64_t veil_chan = 0;
  uint8_t local[32] = {0};
  uint8_t peer[32] = {0};
  std::atomic<bool> audio_running{false};
  bool mic_muted = false;
  bool speaker_muted = false;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  std::unique_ptr<WebrtcState> ws;
#endif
};

struct VeilGroupMediaEngine {
  uint8_t local[32] = {0};
  std::atomic<bool> audio_running{false};
  std::atomic<bool> video_running{false};
  bool mic_muted = false;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  std::unique_ptr<GroupWebrtcState> ws;
#endif
};

#if defined(VEIL_MEDIA_HAVE_WEBRTC)

namespace {
webrtc::NetworkRoute opaque_route(uint64_t generation, int overhead) {
  webrtc::NetworkRoute route;
  route.connected = true;
  // Set both ids: pinned WebRTC may select adapter or network identity. Split
  // the local generation over two endpoints so the 16-bit id rollover does
  // not make a still-recent path look identical. No interface/address leaks.
  const uint16_t low = static_cast<uint16_t>(generation);
  const uint16_t high = static_cast<uint16_t>(generation >> 16);
  route.local = webrtc::RouteEndpoint(webrtc::ADAPTER_TYPE_UNKNOWN, low, low, false);
  route.remote = webrtc::RouteEndpoint(webrtc::ADAPTER_TYPE_UNKNOWN, high, high, false);
  route.packet_overhead = overhead;
  return route;
}
// Caller is the relevant Call's worker queue. Initial registration uses zero;
// subsequent genuine channel commits reset that Call's path estimates, without
// replacing streams, RTP sequence spaces, the ADM or the receive jitter buffer.
void apply_audio_route(VeilMediaEngine* engine, bool force = false) {
  auto* ws = engine->ws.get();
  const auto generation = ws->route_generation.load();
  if (!force && ws->audio_route_applied.load() == generation) return;
  ws->call->GetTransportControllerSend()->OnNetworkRouteChanged(
      "opaque", opaque_route(generation, engine->audio_packet_overhead.load()));
  ws->audio_route_applied.store(generation);
}
void apply_video_route(WebrtcState* ws, bool force = false) {
  const auto generation = ws->route_generation.load();
  if (!force && ws->video_route_applied.load() == generation) return;
  auto* controller = ws->video_call->GetTransportControllerSend();
  controller->OnNetworkRouteChanged(
      "opaque", opaque_route(generation, ws->video_packet_overhead.load()));
  ws->video_route_applied.store(generation);
}
void update_committed_route(VeilMediaEngine* engine) {
  auto* ws = engine->ws.get();
  ws->route_generation.fetch_add(1);
  // Commit already succeeded in the SDK. A stalled queue may postpone its
  // estimator update, not undo that binding or hold another Call's queue.
  // The cancellation handshake prevents late stack captures; get_stats retries.
  (void)veil_media::run_on_with_timeout(ws->worker_tq.get(), [&] {
    apply_audio_route(engine);
  }, std::chrono::milliseconds(50));
  (void)veil_media::run_on_with_timeout(ws->video_worker_tq.get(), [&] {
    apply_video_route(ws);
  }, std::chrono::milliseconds(20));
}
}  // namespace

#if defined(_WIN32)
// The Windows audio device module is built on a thread THIS FILE created.
//
// `kPlatformDefaultAudio` gives `AudioDeviceWindowsCore`, whose FIRST member is
// `ScopedCOMInitializer _comInit` — default-constructed, i.e. STA. On a thread
// already in the MTA that request returns RPC_E_CHANGED_MODE, and
// ScopedCOMInitializer turns that into an `RTC_CHECK`: it KILLS THE PROCESS.
//
//   Fatal error in ..\..\rtc_base\win\scoped_com_initializer.cc, line 43
//   Check failed: ((HRESULT)0x80010106L) != hr_
//   Invalid COM thread model change (MTA->STA)
//
// Measured on Windows 11: answering a call killed the app on 0.13.4 and again
// on 0.13.7 — the second time with this library's camera backend already fixed
// and the shipped DLL confirmed by sha256, which is what ruled the camera out.
//
// The process HAS an MTA and cannot not have one: Media Foundation needs it,
// and a thread that touches COM without initialising it is placed in that
// MTA implicitly. So asking the calling thread what apartment it is in and
// hoping cannot work — the answer depends on when you ask, and the ADM's own
// ScopedCOMInitializer asks after we do.
//
// A thread nobody has touched yet belongs to NO apartment. Create the ADM
// there and `_comInit` establishes the STA it wants, on its first try, with
// nothing to collide with. This file deliberately does NOT initialise COM on
// this thread: the apartment is the ADM's to choose, and choosing it here is
// how the two disagree again.
//
// The thread is never joined, because `_comInit` lives as long as the ADM and
// its CoUninitialize belongs to the thread that initialised. Later ADM calls
// still happen on whatever thread the engine is driven from, exactly as
// before: the MMDevice and WASAPI objects it holds are registered
// ThreadingModel="Both", which is what makes WebRTC's own design work.
//
// WebRTC's other Windows ADM — `CreateWindowsCoreAudioAudioDeviceModule`,
// whose header asks for the MTA and returns nullptr instead of aborting —
// would have suited this process better. It is not in the prebuilt library:
// checked with llvm-nm against webrtc-win-x64.lib, which defines
// `CreateAudioDeviceModule` and `AudioDeviceWindowsCore::CoreAudioIsSupported`
// but not that factory, and carries the string "Use the
// CreateWindowsCoreAudioAudioDeviceModule() factory method instead" only as
// the message that rejects the option.
class AdmHostThread {
 public:
  AdmHostThread() {
    std::unique_lock<std::mutex> lock(m_);
    std::thread([this] { Serve(); }).detach();
    ready_cv_.wait(lock, [this] { return ready_; });
  }

  void Run(std::function<void()> fn) {
    std::mutex done_m;
    std::condition_variable done_cv;
    bool done = false;
    {
      std::lock_guard<std::mutex> lock(m_);
      queue_.push_back([&] {
        fn();
        {
          std::lock_guard<std::mutex> l(done_m);
          done = true;
        }
        done_cv.notify_one();
      });
    }
    task_cv_.notify_one();
    std::unique_lock<std::mutex> l(done_m);
    done_cv.wait(l, [&] { return done; });
  }

 private:
  [[noreturn]] void Serve() {
    {
      std::lock_guard<std::mutex> lock(m_);
      ready_ = true;
    }
    ready_cv_.notify_all();
    for (;;) {
      std::function<void()> task;
      {
        std::unique_lock<std::mutex> lock(m_);
        task_cv_.wait(lock, [this] { return !queue_.empty(); });
        task = std::move(queue_.front());
        queue_.pop_front();
      }
      task();
    }
  }

  std::mutex m_;
  std::condition_variable ready_cv_;
  std::condition_variable task_cv_;
  std::deque<std::function<void()>> queue_;
  bool ready_ = false;
};

// LEAKED ON PURPOSE, and the leak is what makes the paragraph above true.
//
// A function-local static of a type with a non-trivial destructor is NOT
// "never destroyed": the compiler registers `~AdmHostThread` with the exit
// handler list, and it runs while `Serve()` is parked in `task_cv_.wait`
// holding `m_`. Destroying a mutex someone holds and a condition variable
// someone waits on is undefined, and on the MSVC runtime the observed shape
// is a process that stops exiting — the window is gone, the tray icon is
// gone, and xveil.exe is still in the task list.
//
// The pointer form registers nothing, so exit reaches `ExitProcess` and the
// OS reclaims the thread. The object's storage is never reclaimed, which is
// the intent: it is process-lifetime state.
AdmHostThread& adm_host_thread() {
  static AdmHostThread* const instance = new AdmHostThread();
  return *instance;
}

// Every call into the ADM goes to the thread that CREATED it.
//
// `AudioDeviceWindowsCore` establishes an STA on its creating thread and holds
// COM interfaces from it. STA objects have thread affinity: reached from
// another apartment without marshalling they answer RPC_E_WRONG_THREAD, which
// this ADM surfaces as -1. Measured on Windows 11 after the crash was fixed —
// the module built and initialised fine and then
//
//   adm: Init=0 Initialized=1 recDevs=3 playDevs=4 recAvail=0 playAvail=0
//   adm start: capture start FAILED init=-1 start=-1
//
// so the call carried video and no sound. One thread creates it, the same
// thread drives it.
void run_on_adm_thread(std::function<void()> fn) { adm_host_thread().Run(std::move(fn)); }
#else
// Elsewhere the ADM has no apartment to belong to; the call runs where it was
// made, exactly as it always did.
void run_on_adm_thread(std::function<void()> fn) { fn(); }
#endif  // _WIN32

// Start playout, and SAY WHY when it does not.
//
// Both return codes used to be discarded. A device that refuses is then
// completely silent: the call connects, the microphone works, packets go out,
// and the other side is never heard. Measured on Windows 2026-08-29 —
// `adm start: recording=1 playing=0`, with nothing in the log to explain the
// zero.
//
// And on Windows a playout device has to be CHOSEN before playout can be
// initialised. Nothing here ever chose one: `SetPlayoutDevice` was called only
// from the explicit device picker, and the call UI offers a microphone and a
// camera and NO audio output at all — so on every machine where nobody had
// picked one by hand, playout was initialised against no device.
//
// THE PLAIN DEFAULT, not the communications one.
//
// Windows keeps two separate defaults for output, and they are routinely
// different devices. Measured on a live machine 2026-08-29:
//
//   eConsole / eMultimedia : Динамики (RSQ-319)   <- headphones; the browser
//   eCommunications        : Динамики (2- ME6S)   <- where this call went
//
// Asking for the communications default is defensible on paper — it is the
// role Windows names for calls — and it is wrong in practice: almost nobody
// sets it deliberately, so Windows fills it with whatever it likes, and the
// call comes out of a device the person is not wearing. Everything looked
// healthy from inside: the module reported playing=1, packets arrived and
// decoded with zero loss, and there was silence.
//
// So take the output the person means by "my output" — the one their browser
// uses — and keep the communications default only as a fallback. Whoever wants
// the other one has the picker.
// What the person CHOSE, if they chose anything.
//
// Every start reset the device to a default. So the picker worked exactly
// once: mute and unmute, or any restart of the stream, and the call went back
// to whatever Windows nominates — silently, because a reset looks like a
// successful start (report19 V19-M2).
//
// Indices, not names, because that is what the ADM takes, and -1 for "nobody
// has said". Only ever touched on the ADM thread, which is where both the
// selection and the starts below run, so no lock is needed. One value rather
// than one per engine: the device holds one call at a time — that exclusion is
// what the call slot exists for — and the choice belongs to the person, not to
// the call they happened to make it during.
int g_chosen_playout = -1;
int g_chosen_recording = -1;

// Start playout on the ADM's own thread, and SAY whether it worked.
//
// This returned `void` and only logged, while `start_capture` beside it
// returned a bool the callers acted on. So a call whose playout refused —
// no output device, a driver that would not initialise, an ADM that was
// never created — reported success, set `audio_running`, and the person
// heard nothing while the interface showed a live call. A second start was
// then a no-op, because running was already true (report19 V19-M3).
bool start_playout(webrtc::AudioDeviceModule* adm) {
  if (adm == nullptr) return false;
  int32_t set_rc = 0, init_rc = 0, start_rc = 0;
  run_on_adm_thread([&] {
#if defined(_WIN32)
    set_rc = -1;
    if (g_chosen_playout >= 0) {
      set_rc = adm->SetPlayoutDevice(
          static_cast<uint16_t>(g_chosen_playout));
      if (set_rc != 0) {
        // The chosen device is gone — unplugged between the choice and this
        // start. Fall through to the defaults rather than refusing to play.
        vlog("adm start: chosen playout device %d is unavailable (rc=%d)",
             g_chosen_playout, (int)set_rc);
        g_chosen_playout = -1;
      }
    }
    if (set_rc != 0) {
      set_rc = adm->SetPlayoutDevice(webrtc::AudioDeviceModule::kDefaultDevice);
    }
    if (set_rc != 0) {
      set_rc = adm->SetPlayoutDevice(
          webrtc::AudioDeviceModule::kDefaultCommunicationDevice);
    }
#endif
    init_rc = adm->InitPlayout();
    start_rc = init_rc == 0 ? adm->StartPlayout() : -1;
  });
  if (init_rc != 0 || start_rc != 0) {
    vlog("adm start: PLAYOUT FAILED set=%d init=%d start=%d — the call carries "
         "our voice and none of theirs",
         (int)set_rc, (int)init_rc, (int)start_rc);
    return false;
  }
  vlog("adm start: playout ok (device set rc=%d)", (int)set_rc);
  return true;
}

// Start capture on the ADM's own thread, reporting every code.
//
// The INPUT is chosen here for the same reason the output is. Nothing ever
// chose one: recording was started against whatever the module defaulted to,
// and on a machine with a webcam, a headset and a monitor that is a coin toss.
// Measured on Windows 2026-08-29: with the microphone left to the default, the
// call sent 153 packets carrying 4917 bytes — the same packet count as a
// working call and HALF its bytes, which is the signature of a codec sending
// silence, not of a broken stream. Nothing in the log said which microphone
// that was, because nothing had asked.
//
// The communications default, like the output: it is what Windows reserves for
// calls, and a person who has plugged in a headset expects a call to use it.
bool start_capture(webrtc::AudioDeviceModule* adm, const char* who) {
  int32_t set_rc = 0, init_rc = 0, start_rc = 0;
  run_on_adm_thread([&] {
#if defined(_WIN32)
    set_rc = -1;
    if (g_chosen_recording >= 0) {
      set_rc = adm->SetRecordingDevice(
          static_cast<uint16_t>(g_chosen_recording));
      if (set_rc != 0) {
        vlog("%s: chosen recording device %d is unavailable (rc=%d)", who,
             g_chosen_recording, (int)set_rc);
        g_chosen_recording = -1;
      }
    }
    if (set_rc != 0) {
      set_rc = adm->SetRecordingDevice(
          webrtc::AudioDeviceModule::kDefaultCommunicationDevice);
    }
    if (set_rc != 0) {
      set_rc =
          adm->SetRecordingDevice(webrtc::AudioDeviceModule::kDefaultDevice);
    }
#endif
    init_rc = adm->InitRecording();
    start_rc = init_rc == 0 ? adm->StartRecording() : -1;
  });
  if (init_rc != 0 || start_rc != 0) {
    vlog("%s: capture start FAILED set=%d init=%d start=%d", who, (int)set_rc,
         (int)init_rc, (int)start_rc);
    return false;
  }
  vlog("%s: capture ok (device set rc=%d)", who, (int)set_rc);
  return true;
}

#if defined(VEIL_MEDIA_TEST_HOOKS)
#include "../test/recording_adm.inc"
#endif

webrtc::scoped_refptr<webrtc::AudioDeviceModule> create_audio_device(
    const webrtc::Environment& env) {
#if defined(VEIL_MEDIA_TEST_HOOKS)
  if (g_call_plane_recording_adm)
    return webrtc::make_ref_counted<StandRecordingAdm>(env);
#endif
#if defined(_WIN32)
  webrtc::scoped_refptr<webrtc::AudioDeviceModule> adm;
  adm_host_thread().Run([&env, &adm] {
    adm = webrtc::CreateAudioDeviceModule(
        env, webrtc::AudioDeviceModule::kPlatformDefaultAudio);
  });
  vlog("adm: windows module created on the engine's own thread: %s",
       adm ? "ok" : "NULL (no audio in this call)");
  return adm;
#elif defined(__APPLE__)
#if TARGET_OS_IPHONE
  // The custom ADM also owns AVAudioSession/VoiceChat posture on iOS.
  return veil_media::CreateVeilAvfAdm(env);
#else
  // The platform CoreAudio ADM reports devices but returns both availability
  // flags false in this dylib embed; StartRecording/StartPlayout then remain
  // false and an otherwise healthy NetEq grows into seconds of silent audio.
  // The AVFoundation ADM has working capture + playout and completed physical
  // call teardown after permission was granted. Keep the broken platform path
  // only as an explicit diagnostic escape hatch.
  const char* use_platform = std::getenv("VEIL_MEDIA_USE_PLATFORM_ADM");
  if (use_platform != nullptr && std::strcmp(use_platform, "1") == 0)
    return webrtc::CreateAudioDeviceModule(
        env, webrtc::AudioDeviceModule::kPlatformDefaultAudio);
  return veil_media::CreateVeilAvfAdm(env);
#endif
#elif defined(__ANDROID__)
  return veil_media::CreateVeilAAudioAdm(env);
#else
  return webrtc::CreateAudioDeviceModule(
      env, webrtc::AudioDeviceModule::kPlatformDefaultAudio);
#endif
}
#endif

extern "C" {

VeilMediaEngine* veil_media_engine_create(uint64_t veil_chan,
                                          const uint8_t* local_id,
                                          const uint8_t* peer_id) {
  if (local_id == nullptr || peer_id == nullptr) return nullptr;
  auto engine = std::make_unique<VeilMediaEngine>();
  engine->veil_chan = veil_chan;
  std::memcpy(engine->local, local_id, 32);
  std::memcpy(engine->peer, peer_id, 32);

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  webrtc::Environment env = create_low_latency_environment();
  auto ws = std::make_unique<WebrtcState>(env);
  // THREADING: worker + network queues own the Call's threads. Post Call/stream
  // ops onto worker_tq for the device test; direct construction is fine to
  // compile and to run single-threaded in a release build (no DCHECKs).
  ws->worker_tq = ws->env.task_queue_factory().CreateTaskQueue(
      "veil-audio-worker", webrtc::TaskQueueFactory::Priority::kHigh);
  ws->network_tq = ws->env.task_queue_factory().CreateTaskQueue(
      "veil-net", webrtc::TaskQueueFactory::Priority::kHigh);
  ws->video_worker_tq = ws->env.task_queue_factory().CreateTaskQueue(
      "veil-video-worker", webrtc::TaskQueueFactory::Priority::kNormal);
  ws->video_network_tq = ws->env.task_queue_factory().CreateTaskQueue(
      "veil-video-net", webrtc::TaskQueueFactory::Priority::kNormal);

  // Per-platform ADM selection lives in one helper so direct and group calls
  // cannot silently diverge. In particular, macOS uses WebRTC's CoreAudio HAL
  // path while iOS retains the AVAudioSession-aware custom ADM.
  ws->adm = create_audio_device(ws->env);
  if (ws->adm) {
    int32_t init_rc = 0;
    bool rec_avail = false, play_avail = false;
    int initialized = 0, rec_devs = 0, play_devs = 0;
    run_on_adm_thread([&] {
      init_rc = ws->adm->Init();
      ws->adm->RecordingIsAvailable(&rec_avail);
      ws->adm->PlayoutIsAvailable(&play_avail);
      initialized = ws->adm->Initialized();
      rec_devs = static_cast<int>(ws->adm->RecordingDevices());
      play_devs = static_cast<int>(ws->adm->PlayoutDevices());
    });
    vlog("adm: Init=%d Initialized=%d recDevs=%d playDevs=%d recAvail=%d "
         "playAvail=%d",
         init_rc, initialized, rec_devs, play_devs, rec_avail, play_avail);
    // WHICH devices, by name. "playing=1" and silence are the same line
    // otherwise: the engine can be playing correctly into an output nobody is
    // listening to, and no counter can tell those apart. Names can.
    run_on_adm_thread([&] {
      for (int i = 0; i < play_devs; ++i) {
        char name[webrtc::kAdmMaxDeviceNameSize] = {0};
        char guid[webrtc::kAdmMaxGuidSize] = {0};
        if (ws->adm->PlayoutDeviceName(static_cast<uint16_t>(i), name, guid) ==
            0) {
          vlog("adm: playout device %d: %s", i, name);
        }
      }
      for (int i = 0; i < rec_devs; ++i) {
        char name[webrtc::kAdmMaxDeviceNameSize] = {0};
        char guid[webrtc::kAdmMaxGuidSize] = {0};
        if (ws->adm->RecordingDeviceName(static_cast<uint16_t>(i), name,
                                         guid) == 0) {
          vlog("adm: recording device %d: %s", i, name);
        }
      }
    });
  }
  ws->apm = webrtc::BuiltinAudioProcessingBuilder(
      veil_media::CallAudioProcessingConfig()).Build(ws->env);

  webrtc::AudioState::Config asc;
  asc.audio_mixer = webrtc::AudioMixerImpl::Create();
  asc.audio_processing = ws->apm;
  asc.audio_device_module = ws->adm;
  ws->audio_state = webrtc::AudioState::Create(asc);
  // Route the ADM's recorded audio into the AudioState's transport. In the
  // PeerConnection path WebRtcVoiceEngine does this; on the direct Call path we
  // must — without it the mic records but no audio reaches the send stream (only
  // RTCP flows).
  if (ws->adm && ws->audio_state) {
    ws->adm->RegisterAudioCallback(ws->audio_state->audio_transport());
  }

  webrtc::CallConfig call_cfg(ws->env, ws->worker_tq.get(),
                              ws->network_tq.get());
  call_cfg.audio_state = ws->audio_state;
  bool recover_playout = true;
#if defined(VEIL_MEDIA_TEST_HOOKS)
  recover_playout = std::getenv("VEIL_MEDIA_TEST_DISABLE_AUDIO_DRAIN") == nullptr;
#endif
  if (recover_playout) {
    ws->recovery_factory = std::make_unique<veil_media::RecoveringNetEqFactory>(
        ws->recovery_stats);
    call_cfg.neteq_factory = ws->recovery_factory.get();
  }
  configure_call_audio_transport(call_cfg);
#if defined(VEIL_MEDIA_TEST_HOOKS)
  if (std::getenv("VEIL_MEDIA_TEST_ROUTE_OBSERVER"))
    call_cfg.per_call_network_controller_factory =
        std::make_unique<veil_media::test::RouteObserverFactory>(ws->audio_route_restarts);
#endif
  ws->call = webrtc::Call::Create(std::move(call_cfg));
  webrtc::CallConfig video_cfg(create_low_latency_environment(true),
                              ws->video_worker_tq.get(),
                              ws->video_network_tq.get());
#if defined(VEIL_MEDIA_CC_TRACE)
  if (veil_media::video_cc_trace_enabled())
    video_cfg.per_call_network_controller_factory =
        std::make_unique<veil_media::VideoCcTraceFactory>(
            std::make_unique<webrtc::GoogCcNetworkControllerFactory>());
#endif
#if defined(VEIL_MEDIA_TEST_HOOKS)
  if (std::getenv("VEIL_MEDIA_TEST_ROUTE_OBSERVER"))
    video_cfg.per_call_network_controller_factory =
        std::make_unique<veil_media::test::RouteObserverFactory>(ws->video_route_restarts);
#endif
  ws->video_call = webrtc::Call::Create(std::move(video_cfg));

  ws->shim = std::make_unique<veil_media::VeilTransportShim>(
      veil_chan, ws->call.get(), ws->network_tq.get(),
      ws->video_call.get(), ws->video_network_tq.get(), nullptr,
      ws->audio_packet_priority);
  ws->shim->SetLocalAudioSsrc(ssrc_of(local_id));
  ws->shim->SetRemoteAudioSsrc(ssrc_of(peer_id));
  ws->shim->SetLocalVideoSsrc(video_ssrc_of(local_id));
  ws->shim->Start();

  ws->video_sink = std::make_unique<VeilVideoSink>(video_ssrc_of(peer_id));
  ws->local_video_sink = std::make_unique<VeilVideoSink>();
#if defined(__ANDROID__)
  ws->android420_dispatcher =
      std::make_unique<Android420FrameDispatcher>(&ws->android420_stats);
#endif

  engine->ws = std::move(ws);
  if (!run_on(engine->ws->worker_tq.get(), [&] { apply_audio_route(engine.get(), true); }) ||
      !run_on(engine->ws->video_worker_tq.get(), [&] { apply_video_route(engine->ws.get(), true); })) {
    veil_media_engine_destroy(engine.release());
    return nullptr;
  }
#endif
  return engine.release();
}

int veil_media_engine_rebind_channel(VeilMediaEngine* engine, uint64_t veil_chan) {
  if (!engine || !veil_chan) return VEIL_MEDIA_ERR_ARG;
  std::lock_guard<std::mutex> lock(engine->config_mu);
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  auto* ws = engine->ws.get();
  if (!ws || !ws->shim) return VEIL_MEDIA_ERR_STATE;
  const bool changed = engine->veil_chan != veil_chan;
  if (!ws->shim->RebindChannel(veil_chan)) return VEIL_MEDIA_ERR_STATE;
  engine->veil_chan = veil_chan;
  if (changed) update_committed_route(engine);
  return VEIL_MEDIA_OK;
#else
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_rebind_channel_keep_receiver(VeilMediaEngine* engine, uint64_t veil_chan) {
  if (!engine || !veil_chan) return VEIL_MEDIA_ERR_ARG;
  std::lock_guard<std::mutex> lock(engine->config_mu);
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  auto* ws = engine->ws.get();
  if (!ws || !ws->shim) return VEIL_MEDIA_ERR_STATE;
  const bool changed = engine->veil_chan != veil_chan;
  if (!ws->shim->RebindChannel(veil_chan, true)) return VEIL_MEDIA_ERR_STATE;
  engine->veil_chan = veil_chan;
  if (changed) update_committed_route(engine);
  return VEIL_MEDIA_OK;
#else
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_set_audio_mirror_channel(VeilMediaEngine* engine, uint64_t veil_chan) {
  if (!engine) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  auto* ws = engine->ws.get();
  return ws && ws->shim && ws->shim->SetAudioMirrorChannel(veil_chan)
      ? VEIL_MEDIA_OK : VEIL_MEDIA_ERR_STATE;
#else
  (void)veil_chan;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_release_receive_channel(VeilMediaEngine* engine, uint64_t veil_chan) {
  if (!engine || !veil_chan) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  auto* ws = engine->ws.get();
  return ws && ws->shim && ws->shim->ReleaseReceiveChannel(veil_chan)
      ? VEIL_MEDIA_OK : VEIL_MEDIA_ERR_STATE;
#else
  return VEIL_MEDIA_ERR_STATE;
#endif
}

void veil_media_engine_destroy(VeilMediaEngine* engine) {
  if (engine == nullptr) return;
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && defined(__ANDROID__)
  // Fence the latest-only Camera2 worker before the video stream/source it
  // feeds can be detached. Kotlin has already drained its ImageReader handler,
  // and this join closes the native half of the pointer lifetime.
  if (engine->ws && engine->ws->android420_dispatcher)
    engine->ws->android420_dispatcher->Stop();
#endif
  veil_media_engine_stop_video(engine);
  veil_media_engine_stop_audio(engine);
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws) {
    if (engine->ws->shim) engine->ws->shim->Stop();
    engine->ws->video_call.reset();
    engine->ws->call.reset();  // after streams (stop_audio) + shim->Stop()
    if (engine->ws->adm) {
      auto* adm = engine->ws->adm.get();
      run_on_adm_thread([adm] { adm->Terminate(); });
    }
  }
#endif
  delete engine;
}

VeilGroupMediaEngine* veil_media_group_engine_create(
    const uint8_t* local_id) {
  if (local_id == nullptr) return nullptr;
  auto engine = std::make_unique<VeilGroupMediaEngine>();
  std::memcpy(engine->local, local_id, 32);
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  webrtc::Environment env = create_low_latency_environment();
  auto ws = std::make_unique<GroupWebrtcState>(env);
  ws->worker_tq = ws->env.task_queue_factory().CreateTaskQueue(
      "veil-group-audio-worker", webrtc::TaskQueueFactory::Priority::kHigh);
  ws->network_tq = ws->env.task_queue_factory().CreateTaskQueue(
      "veil-group-net", webrtc::TaskQueueFactory::Priority::kHigh);
  ws->video_worker_tq = ws->env.task_queue_factory().CreateTaskQueue(
      "veil-group-video-worker", webrtc::TaskQueueFactory::Priority::kNormal);
  ws->video_network_tq = ws->env.task_queue_factory().CreateTaskQueue(
      "veil-group-video-net", webrtc::TaskQueueFactory::Priority::kNormal);
  ws->adm = create_audio_device(ws->env);
  if (ws->adm) run_on_adm_thread([&] { ws->adm->Init(); });
  ws->apm = webrtc::BuiltinAudioProcessingBuilder(
      veil_media::CallAudioProcessingConfig()).Build(ws->env);
  webrtc::AudioState::Config asc;
  asc.audio_mixer = webrtc::AudioMixerImpl::Create();
  asc.audio_processing = ws->apm;
  asc.audio_device_module = ws->adm;
  ws->audio_state = webrtc::AudioState::Create(asc);
  if (ws->adm && ws->audio_state)
    ws->adm->RegisterAudioCallback(ws->audio_state->audio_transport());
  webrtc::CallConfig call_cfg(ws->env, ws->worker_tq.get(),
                              ws->network_tq.get());
  call_cfg.audio_state = ws->audio_state;
  // Each remote source has its own NetEq, and every source in the mixer must
  // discard stale decoded speech using the same bounded callback work as 1:1.
  // The shared counters account for recovery anywhere in this room. Keep the
  // factory alive through Call teardown and all receive-stream destruction.
  bool recover_playout = true;
#if defined(VEIL_MEDIA_TEST_HOOKS)
  recover_playout = std::getenv("VEIL_MEDIA_TEST_DISABLE_AUDIO_DRAIN") == nullptr;
#endif
  if (recover_playout) {
    ws->recovery_factory = std::make_unique<veil_media::RecoveringNetEqFactory>(
        ws->recovery_stats);
    call_cfg.neteq_factory = ws->recovery_factory.get();
  }
  configure_call_audio_transport(call_cfg);
  ws->call = webrtc::Call::Create(std::move(call_cfg));
  webrtc::CallConfig video_cfg(create_low_latency_environment(true),
                              ws->video_worker_tq.get(),
                              ws->video_network_tq.get());
#if defined(VEIL_MEDIA_CC_TRACE)
  if (veil_media::video_cc_trace_enabled())
    video_cfg.per_call_network_controller_factory =
        std::make_unique<veil_media::VideoCcTraceFactory>(
            std::make_unique<webrtc::GoogCcNetworkControllerFactory>());
#endif
  ws->video_call = webrtc::Call::Create(std::move(video_cfg));
  ws->fanout = std::make_unique<GroupFanoutTransport>(
      ws->call.get(), ws->video_call.get(), group_audio_ssrc_of(engine->local),
      group_video_ssrc_of(engine->local),
      ws->rtcp_send_stats);
  engine->ws = std::move(ws);
#endif
  return engine.release();
}

int veil_media_group_engine_add_peer(VeilGroupMediaEngine* engine,
                                     uint64_t veil_chan,
                                     const uint8_t* peer_id) {
  if (engine == nullptr || peer_id == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  GroupWebrtcState* ws = engine->ws.get();
  const std::string key = node_key(peer_id);
  if (key == node_key(engine->local)) return VEIL_MEDIA_ERR_STATE;
  auto existing = ws->peers.find(key);
  if (existing != ws->peers.end())
    return existing->second->chan == veil_chan ? VEIL_MEDIA_OK
                                                : VEIL_MEDIA_ERR_STATE;
  const uint32_t remote_ssrc = group_audio_ssrc_of(peer_id);
  const uint32_t remote_video_ssrc = group_video_ssrc_of(peer_id);
  const uint32_t local_audio_ssrc = group_audio_ssrc_of(engine->local);
  const uint32_t local_video_ssrc = group_video_ssrc_of(engine->local);
  if (remote_ssrc == remote_video_ssrc || remote_ssrc == local_audio_ssrc ||
      remote_ssrc == local_video_ssrc ||
      remote_video_ssrc == local_audio_ssrc ||
      remote_video_ssrc == local_video_ssrc)
    return VEIL_MEDIA_ERR_STATE;
  for (const auto& entry : ws->peers) {
    const GroupPeerState* other = entry.second.get();
    if (other->audio_ssrc == remote_ssrc ||
        other->video_ssrc == remote_ssrc ||
        other->audio_ssrc == remote_video_ssrc ||
        other->video_ssrc == remote_video_ssrc)
      return VEIL_MEDIA_ERR_STATE;
  }
  auto peer = std::make_unique<GroupPeerState>();
  peer->chan = veil_chan;
  peer->audio_ssrc = remote_ssrc;
  peer->video_ssrc = remote_video_ssrc;
  std::memcpy(peer->id, peer_id, 32);
  peer->shim = std::make_unique<veil_media::VeilTransportShim>(
      veil_chan, ws->call.get(), ws->network_tq.get(),
      ws->video_call.get(), ws->video_network_tq.get(), ws->rtcp_send_stats);
  peer->shim->SetLocalAudioSsrc(local_audio_ssrc);
  peer->shim->SetRemoteAudioSsrc(remote_ssrc);
  peer->shim->SetLocalVideoSsrc(local_video_ssrc);
  peer->shim->Start();
  peer->video_sink = std::make_unique<VeilVideoSink>(remote_video_ssrc);
  ws->fanout->Add(veil_chan);
  if (engine->audio_running.load()) {
    // Discarded because the next line checks the OUTCOME, which is stricter: a
    // queue that never scheduled leaves `recv_stream` null and takes the same
    // failure path as a stream that failed to create.
    (void)run_on(ws->worker_tq.get(), [&]() {
      webrtc::AudioReceiveStreamInterface::Config rc;
      configure_call_audio_receive(rc);
      rc.rtp.remote_ssrc = remote_ssrc;
      rc.rtcp_send_transport = peer->shim.get();
      rc.decoder_factory = webrtc::CreateBuiltinAudioDecoderFactory();
      rc.decoder_map.emplace(kOpusPayloadType,
                             webrtc::SdpAudioFormat("opus", 48000, 2));
      peer->recv_stream = ws->call->CreateAudioReceiveStream(rc);
      if (peer->recv_stream) peer->recv_stream->Start();
    });
    if (peer->recv_stream == nullptr) {
      ws->fanout->Remove(veil_chan);
      peer->shim->Stop();
      return VEIL_MEDIA_ERR_STATE;
    }
  }
  if (engine->video_running.load()) {
    // Discarded for the same reason: `video_recv_stream` stays null.
    (void)run_on(ws->video_worker_tq.get(), [&]() {
      ensure_group_video_codecs(ws);
      start_group_peer_video(ws, peer.get());
    });
    if (peer->video_recv_stream == nullptr) {
      if (peer->recv_stream) {
        const bool rolled_back = run_on(ws->worker_tq.get(), [&]() {
          peer->recv_stream->Stop();
          ws->call->DestroyAudioReceiveStream(peer->recv_stream);
          peer->recv_stream = nullptr;
        });
        if (!rolled_back) {
          // The audio receive stream this rollback exists to destroy is still
          // in the Call, and `peer->shim` is the transport it was configured
          // with. Returning here would destroy `peer` — a local unique_ptr —
          // and take the shim with it: report9 V-02's use-after-free, reached
          // through the add path rather than the remove one.
          //
          // So the peer is KEPT, exactly as `remove_peer` keeps it, and it
          // carries the streams it really has. Delivery is already stopped
          // below, both stops are idempotent, and a later `remove_peer`
          // retries the teardown.
          ws->fanout->Remove(veil_chan);
          peer->shim->SetRemoteVideoSsrc(0);
          peer->shim->Stop();
          ws->peers.emplace(key, std::move(peer));
          vlog("group media: add peer ROLLBACK DEFERRED — worker queue did "
               "not schedule; the peer keeps its audio stream and transport");
          return VEIL_MEDIA_ERR_STATE;
        }
      }
      ws->fanout->Remove(veil_chan);
      peer->shim->Stop();
      return VEIL_MEDIA_ERR_STATE;
    }
  }
  ws->peers.emplace(key, std::move(peer));
  vlog("group media: add peer audio_ssrc=%u video_ssrc=%u peers=%zu",
       remote_ssrc, remote_video_ssrc, ws->peers.size());
  return VEIL_MEDIA_OK;
#else
  (void)veil_chan;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_group_engine_remove_peer(VeilGroupMediaEngine* engine,
                                        const uint8_t* peer_id) {
  if (engine == nullptr || peer_id == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  GroupWebrtcState* ws = engine->ws.get();
  const auto it = ws->peers.find(node_key(peer_id));
  if (it == ws->peers.end()) return VEIL_MEDIA_OK;
  GroupPeerState* peer = it->second.get();
  ws->fanout->Remove(peer->chan);
  peer->shim->SetRemoteVideoSsrc(0);
  peer->shim->Stop();
  const bool video_torn_down = run_on(ws->video_worker_tq.get(), [&]() {
    stop_group_peer_video(ws, peer);
  });
  const bool torn_down = run_on(ws->worker_tq.get(), [&]() {
    if (peer->recv_stream) {
      peer->recv_stream->Stop();
      ws->call->DestroyAudioReceiveStream(peer->recv_stream);
      peer->recv_stream = nullptr;
    }
  });
  if (!torn_down || !video_torn_down) {
    // The worker queue never scheduled, so the receive streams are still
    // live — and `peer->shim` is the transport they were configured with
    // (`rc.rtcp_send_transport`). Erasing the peer here destroys that shim
    // underneath streams that still hold it: the exact use-after-free the
    // result of `run_on` exists to report (report9 V-02).
    //
    // The peer stays, which is the truth: its streams are still in the Call.
    // `fanout->Remove` and `shim->Stop()` above already stopped delivery, and
    // both are idempotent, so a later attempt picks up where this left off.
    vlog("group media: remove peer DEFERRED — worker queue did not schedule; "
         "the peer keeps its streams and its transport");
    return VEIL_MEDIA_ERR_STATE;
  }
  ws->peers.erase(it);
  vlog("group media: remove peer peers=%zu", ws->peers.size());
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_group_engine_start_audio(VeilGroupMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  if (engine->audio_running.load()) return VEIL_MEDIA_OK;
#if defined(VEIL_MEDIA_TEST_HOOKS)
  const char* test_ptime = std::getenv("VEIL_MEDIA_TEST_GROUP_PTIME");
  if (test_ptime && std::strcmp(test_ptime, "20") != 0 &&
      std::strcmp(test_ptime, "40") != 0 && std::strcmp(test_ptime, "60") != 0)
    return VEIL_MEDIA_ERR_ARG;
#endif
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  GroupWebrtcState* ws = engine->ws.get();
  const uint32_t local_ssrc = group_audio_ssrc_of(engine->local);
  // Discarded: `ws->send_stream == nullptr` below is the stricter check — a
  // queue that never scheduled leaves it null.
  (void)run_on(ws->worker_tq.get(), [&]() {
    // AudioState can start the ADM implicitly from AudioSendStream::Start.
    // Disable that path before registering an already-muted sender.
    if (ws->audio_state && ws->adm)
      ws->audio_state->SetRecording(!engine->mic_muted);
    ws->call->SignalChannelNetworkState(webrtc::MediaType::AUDIO,
                                        webrtc::kNetworkUp);
    if (ws->send_stream == nullptr) {
#if defined(VEIL_MEDIA_TEST_HOOKS)
      if (test_ptime) ws->audio_packet_ms = std::atoi(test_ptime);
#endif
      auto sc = group_audio_send_config(ws, local_ssrc,
          ws->audio_packet_ms, ws->audio_payload_bps);
      ws->send_stream = ws->call->CreateAudioSendStream(sc);
      if (ws->send_stream) {
        ws->send_stream->SetMuted(engine->mic_muted);
        ws->send_stream->Start();
      }
    }
    for (auto& entry : ws->peers) {
      GroupPeerState* peer = entry.second.get();
      if (peer->recv_stream) continue;
      webrtc::AudioReceiveStreamInterface::Config rc;
      configure_call_audio_receive(rc);
      rc.rtp.remote_ssrc = peer->audio_ssrc;
      rc.rtcp_send_transport = peer->shim.get();
      rc.decoder_factory = webrtc::CreateBuiltinAudioDecoderFactory();
      rc.decoder_map.emplace(kOpusPayloadType,
                             webrtc::SdpAudioFormat("opus", 48000, 2));
      peer->recv_stream = ws->call->CreateAudioReceiveStream(rc);
      if (peer->recv_stream) peer->recv_stream->Start();
    }
  });
  if (ws->send_stream == nullptr) return VEIL_MEDIA_ERR_STATE;
  bool capture_failed = false;
  bool playout_failed = false;
  if (ws->adm) {
    if (!engine->mic_muted) {
      // Align with set_mic_muted: a capture device that cannot start must be
      // loud, not a silently dead microphone. Playout still comes up below so
      // the room stays audible while the caller decides what to do.
      if (!start_capture(ws->adm.get(), "group audio")) capture_failed = true;
    }
    // A playout that refused is reported exactly as a capture that refused.
    // Ignoring it said the room was audible when it was not (report19
    // V19-M3).
    if (!start_playout(ws->adm.get())) playout_failed = true;
  }
  engine->audio_running.store(true);
  if (capture_failed || playout_failed) return VEIL_MEDIA_ERR_DEVICE;
  vlog("group audio: started peers=%zu", ws->peers.size());
  return VEIL_MEDIA_OK;
#else
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_group_engine_set_audio_budget(VeilGroupMediaEngine* engine,
                                             int packet_ms, int payload_bps) {
  if (!engine || (packet_ms != 20 && packet_ms != 40 && packet_ms != 60) ||
      payload_bps < 16'000 || payload_bps > 32'000) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  auto* ws = engine->ws.get();
  int result = VEIL_MEDIA_ERR_STATE;
  const bool ran = veil_media::run_on_with_timeout(ws->worker_tq.get(), [&] {
    if (!ws->audio_config_valid) return;
    if (ws->audio_packet_ms == packet_ms && ws->audio_payload_bps == payload_bps) {
      result = VEIL_MEDIA_OK;
      return;
    }
    if (ws->send_stream) {
      auto config = group_audio_send_config(ws, group_audio_ssrc_of(engine->local),
                                            packet_ms, payload_bps);
      if (!reconfigure_group_audio(ws, config)) {
        // WebRTC may have stored the failed config while retaining the old
        // encoder. Restore the previous known config before allowing retries.
        auto previous = group_audio_send_config(ws, group_audio_ssrc_of(engine->local),
            ws->audio_packet_ms, ws->audio_payload_bps);
        ws->audio_config_valid = reconfigure_group_audio(ws, previous);
        return;
      }
    }
    ws->audio_packet_ms = packet_ms;
    ws->audio_payload_bps = payload_bps;
    result = VEIL_MEDIA_OK;
  }, std::chrono::milliseconds(20));
  return ran ? result : VEIL_MEDIA_ERR_STATE;
#else
  (void)packet_ms;
  (void)payload_bps;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_group_engine_stop_audio(VeilGroupMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  if (!engine->audio_running.exchange(false)) return VEIL_MEDIA_OK;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->call) {
    GroupWebrtcState* ws = engine->ws.get();
    if (ws->adm) {
      run_on_adm_thread([&] {
        if (ws->adm->Recording()) ws->adm->StopRecording();
        if (ws->adm->Playing()) ws->adm->StopPlayout();
      });
    }
    if (!run_on(ws->worker_tq.get(), [&]() {
          if (ws->send_stream) {
            ws->send_stream->Stop();
            ws->call->DestroyAudioSendStream(ws->send_stream);
            ws->send_stream = nullptr;
          }
          for (auto& entry : ws->peers) {
            GroupPeerState* peer = entry.second.get();
            if (peer->recv_stream) {
              peer->recv_stream->Stop();
              ws->call->DestroyAudioReceiveStream(peer->recv_stream);
              peer->recv_stream = nullptr;
            }
          }
          ws->audio_config_valid = true;
          ws->audio_packet_duration->store(0, std::memory_order_relaxed);
        })) {
      // The streams are still in the Call. The flag says stopped, which is
      // what the caller asked for and what the capture devices above already
      // did; the streams are what did not happen, and saying OK here is how
      // that becomes invisible.
      vlog("group audio: stop INCOMPLETE — worker queue did not schedule; "
           "the streams are still live");
      return VEIL_MEDIA_ERR_STATE;
    }
  }
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_group_engine_set_mic_muted(VeilGroupMediaEngine* engine,
                                          int muted) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  engine->mic_muted = muted != 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws) {
    GroupWebrtcState* ws = engine->ws.get();
    // Stop physical capture before waiting for a possibly busy audio worker.
    // Source mute and implicit ADM control still belong to that worker.
    if (engine->mic_muted && engine->audio_running.load() && ws->adm) {
      run_on_adm_thread([&] {
        if (ws->adm->Recording()) ws->adm->StopRecording();
      });
    }
    const bool configured = run_on(ws->worker_tq.get(), [&] {
      if (ws->send_stream) ws->send_stream->SetMuted(engine->mic_muted);
      if (ws->audio_state && ws->adm)
        ws->audio_state->SetRecording(!engine->mic_muted);
    });
    if (!engine->mic_muted) {
      if (!configured) return VEIL_MEDIA_ERR_STATE;
      bool needs_start = false;
      if (engine->audio_running.load() && ws->adm) {
        run_on_adm_thread([&] { needs_start = !ws->adm->Recording(); });
      }
      if (needs_start && !start_capture(ws->adm.get(), "mic unmute")) {
        return VEIL_MEDIA_ERR_DEVICE;
      }
    }
    if (!configured) return VEIL_MEDIA_ERR_STATE;
  }
#endif
  return VEIL_MEDIA_OK;
}

uint64_t veil_media_group_engine_peer_rx_packets(
    VeilGroupMediaEngine* engine, const uint8_t* peer_id) {
  if (engine == nullptr || peer_id == nullptr) return 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws) return 0;
  const auto it = engine->ws->peers.find(node_key(peer_id));
  if (it == engine->ws->peers.end() || !it->second->shim) return 0;
  return it->second->shim->inbound_packet_count();
#else
  return 0;
#endif
}

int veil_media_group_engine_start_video(VeilGroupMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  if (engine->video_running.load()) return VEIL_MEDIA_OK;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->video_call) return VEIL_MEDIA_ERR_STATE;
  GroupWebrtcState* ws = engine->ws.get();
  const uint32_t local_ssrc = group_video_ssrc_of(engine->local);
  bool peers_ready = true;
  // Discarded: the `!ws->video_send_stream || !peers_ready` check below is
  // stricter — a queue that never scheduled leaves both untouched.
  (void)run_on(ws->video_worker_tq.get(), [&]() {
    ws->video_call->SignalChannelNetworkState(webrtc::MediaType::VIDEO,
                                        webrtc::kNetworkUp);
    ensure_group_video_codecs(ws);
    if (ws->video_send_stream == nullptr) {
      webrtc::VideoSendStream::Config sc(ws->fanout->video_transport());
      sc.rtp.ssrcs = {local_ssrc};
      sc.rtp.payload_name = "VP8";
      sc.rtp.payload_type = kGroupVp8PayloadType;
      sc.rtp.nack.rtp_history_ms = kVideoNackHistoryMs;
      sc.rtp.extensions.emplace_back(
          webrtc::RtpExtension::kTransportSequenceNumberUri,
          webrtc::RtpHeaderExtensionId(1));
      sc.encoder_settings.encoder_factory = ws->video_encoder_factory.get();
      sc.encoder_settings.bitrate_allocator_factory =
          ws->video_bitrate_alloc_factory.get();

      // A new room has no measured audio feedback yet. Keep its initial video
      // load small; endpoint adaptation earns more only after healthy audio.
      const bool prepared = ws->prepared_video_bps > 0;
      const double initial_fps = prepared ? ws->prepared_video_fps : 1;
      int kbps = prepared ? ws->prepared_video_bps / 1000 : 30;
      if (const char* value = std::getenv("VEIL_MEDIA_VIDEO_KBPS")) {
        const int configured = std::atoi(value);
        if (configured > 0) kbps = configured;
      }
      kbps = std::clamp(kbps, prepared ? 1 : 30, 2500);
      const int bps = kbps * 1000;
      ws->video_frame_budget->SetProfile(bps);
      ws->video_call->SetClientBitratePreferences(
          veil_media::video_bitrate_settings(bps, true, true));
      auto ec = veil_media::vp8_encoder_config();
      ec.max_bitrate_bps = bps;
      webrtc::VideoStream layer;
      layer.active = true;
      layer.min_bitrate_bps = std::min(30000, bps);
      layer.target_bitrate_bps = std::max(layer.min_bitrate_bps, bps * 2 / 3);
      layer.max_bitrate_bps = bps;
      layer.max_framerate = static_cast<int>(std::ceil(initial_fps));
      layer.max_qp = 63;
      ec.simulcast_layers.push_back(layer);
      ws->video_send_stream =
          ws->video_call->CreateVideoSendStream(std::move(sc), std::move(ec));
      if (ws->video_send_stream) {
        for (const auto& entry : ws->peers) entry.second->shim->ResetVideoLossEvidence();
        ws->video_send_stream->SetSource(
            ws->video_source.get(),
            webrtc::DegradationPreference::MAINTAIN_FRAMERATE);
        ws->video_send_stream->Start();
        ws->video_target_bitrate_bps = bps;
        ws->video_max_fps.store(initial_fps, std::memory_order_relaxed);
        ws->prepared_video_bps = 0;
        ws->video_last_encoded_frame_us.store(0, std::memory_order_relaxed);
      }
    }
    for (auto& entry : ws->peers) {
      if (!start_group_peer_video(ws, entry.second.get())) peers_ready = false;
    }
  });
  if (!ws->video_send_stream || !peers_ready) {
    engine->video_running.store(true);
    veil_media_group_engine_stop_video(engine);
    return VEIL_MEDIA_ERR_STATE;
  }
  engine->video_running.store(true);

  if (std::getenv("VEIL_MEDIA_TEST_VIDEO") != nullptr &&
      !ws->test_video_run.load()) {
    ws->test_video_run.store(true);
    ws->test_video_thread = std::thread([ws]() {
      const int width = 320, height = 240;
      const int chroma_width = (width + 1) / 2;
      const int chroma_height = (height + 1) / 2;
      std::vector<uint8_t> y(width * height);
      std::vector<uint8_t> u(chroma_width * chroma_height, 128);
      std::vector<uint8_t> v(chroma_width * chroma_height, 128);
      uint32_t frame = 0;
      while (ws->test_video_run.load()) {
        for (int row = 0; row < height; ++row)
          for (int col = 0; col < width; ++col)
            y[row * width + col] =
                static_cast<uint8_t>(row + col + frame);
        std::fill(v.begin(), v.end(), static_cast<uint8_t>(128 + frame));
        if (should_encode_video_frame(ws))
          push_i420(ws->video_source.get(), y.data(), u.data(), v.data(), width,
                    height, width, chroma_width, chroma_width, 0);
        ++frame;
        std::this_thread::sleep_for(std::chrono::milliseconds(66));
      }
    });
  }
  vlog("group video: started peers=%zu ssrc=%u", ws->peers.size(),
       local_ssrc);
  return VEIL_MEDIA_OK;
#else
  return VEIL_MEDIA_ERR_STATE;
#endif
}

static int veil_media_group_engine_apply_video_budget(VeilGroupMediaEngine* engine,
    int max_bitrate_kbps, double max_fps, int minimum_kbps) {
  if (!engine) return VEIL_MEDIA_ERR_ARG;
  if (max_bitrate_kbps <= 0 || !std::isfinite(max_fps) || max_fps <= 0)
    return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws) return VEIL_MEDIA_ERR_STATE;
  GroupWebrtcState* ws = engine->ws.get();
  int rc = VEIL_MEDIA_ERR_STATE;
  const bool scheduled = veil_media::run_on_with_timeout(ws->video_worker_tq.get(), [&] {
    int kbps = max_bitrate_kbps > 0 ? max_bitrate_kbps : 150;
    if (const char* value = std::getenv("VEIL_MEDIA_VIDEO_KBPS")) {
      const int configured = std::atoi(value);
      if (configured > 0) kbps = configured;
    }
    kbps = std::clamp(kbps, minimum_kbps, 2500);
    const double fps = std::clamp(max_fps, 0.02, 60.0);
    const int bps = kbps * 1000;
    ws->video_frame_budget->SetProfile(bps);
    if (!ws->video_send_stream) {
      if (!engine->video_running.load()) {
        ws->prepared_video_bps = bps;
        ws->prepared_video_fps = fps;
        rc = VEIL_MEDIA_OK;
      }
      return;
    }
    if (ws->video_target_bitrate_bps != bps || ws->video_max_fps.load() != fps) {
      auto ec = veil_media::vp8_encoder_config();
      ec.max_bitrate_bps = bps;
      webrtc::VideoStream layer;
      layer.active = true;
      layer.min_bitrate_bps = std::min(30000, bps);
      layer.target_bitrate_bps = std::max(layer.min_bitrate_bps, bps * 2 / 3);
      layer.max_bitrate_bps = bps;
      layer.max_framerate = static_cast<int>(std::ceil(fps));
      layer.max_qp = 63;
      ec.simulcast_layers.push_back(layer);
      ws->video_send_stream->ReconfigureVideoEncoder(std::move(ec));
      ws->video_call->SetClientBitratePreferences(
          veil_media::video_bitrate_settings(bps, true, false));
      ws->video_target_bitrate_bps = bps;
      ws->video_max_fps.store(fps, std::memory_order_relaxed);
      ws->video_last_encoded_frame_us.store(0, std::memory_order_relaxed);
    }
    rc = VEIL_MEDIA_OK;
  }, std::chrono::milliseconds(20));
  return scheduled ? rc : VEIL_MEDIA_ERR_STATE;
#else
  (void)max_bitrate_kbps;
  (void)max_fps;
  (void)minimum_kbps;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_group_engine_set_video_send_paused(VeilGroupMediaEngine* engine, int paused) {
  if (!engine || (paused != 0 && paused != 1)) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws) return VEIL_MEDIA_ERR_STATE;
  GroupWebrtcState* ws = engine->ws.get();
  if (paused) {
    ws->video_send_paused.store(true);
    ws->fanout->SetVideoSendPaused(true);
    return VEIL_MEDIA_OK;
  }
  if (!ws->video_send_paused.load()) return VEIL_MEDIA_OK;
  const bool scheduled = veil_media::run_on_with_timeout(ws->video_worker_tq.get(), [&] {
    if (ws->video_send_stream) ws->video_send_stream->GenerateKeyFrame({});
    ws->video_last_encoded_frame_us.store(0, std::memory_order_relaxed);
    ws->fanout->SetVideoSendPaused(false);
    ws->video_send_paused.store(false);
  }, std::chrono::milliseconds(20));
  return scheduled ? VEIL_MEDIA_OK : VEIL_MEDIA_ERR_STATE;
#else
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_group_engine_set_video_budget(VeilGroupMediaEngine* engine,
    int max_bitrate_kbps, double max_fps) {
  return veil_media_group_engine_apply_video_budget(engine, max_bitrate_kbps, max_fps, 1);
}

int veil_media_group_engine_set_video_bitrate(VeilGroupMediaEngine* engine,
                                        int max_bitrate_kbps, int max_fps) {
  // Preserve integer ABI defaults for older callers.
  if (!engine) return VEIL_MEDIA_ERR_ARG;
  if (!engine->video_running.load()) return VEIL_MEDIA_ERR_STATE;
  return veil_media_group_engine_apply_video_budget(engine,
      std::clamp(max_bitrate_kbps > 0 ? max_bitrate_kbps : 150, 30, 2500),
      std::clamp(max_fps > 0 ? max_fps : 15, 1, 60), 30);
}

char* veil_media_group_engine_get_stats(VeilGroupMediaEngine* engine) {
  if (!engine) return nullptr;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws) return nullptr;
  GroupWebrtcState* ws = engine->ws.get();
  int reports = 0, loss = 0, jitter = 0;
  int video_reports = 0, video_loss = 0, video_jitter = 0;
  int64_t video_rtt = 0;
  int64_t audio_loss_report_us = 0, video_loss_report_us = 0;
  int64_t video_persistent_loss_report_us = 0;
  int64_t peer_audio_recovery_report_us = 0;
  int64_t peer_audio_concealment_report_us = 0;
  int64_t local_audio_concealment_report_us = 0;
  veil_media::AudioSoftLossSnapshot local_soft_loss;
  veil_media::AudioSoftLossSnapshot peer_soft_loss{!ws->peers.empty(), 0, 0};
  int peer_audio_recovery_peers = 0;
  int playout_peers = 0, playout_reports = 0, playout_ms = -1;
  int64_t rtt = 0;
  uint64_t video_frames = 0;
  double fps = 0;
  int kbps = 0, encoder_target_bps = 0;
  // Sender-stream counters are logical RTP work, BEFORE peer fanout and the
  // encrypted transport. Unknown is distinct from an observed zero.
  int64_t video_retransmitted_packets = -1, video_retransmitted_bytes = -1;
  int64_t video_nack_packets = -1, video_nack_requests = -1;
  int64_t video_unique_nack_requests = -1, video_pli_packets = -1;
  int64_t video_fir_packets = -1, video_key_frames = -1;
  const int64_t now_us = webrtc::TimeMicros();
  bool playout_changed = ws->observed_playout_peer_count != ws->peers.size();
  ws->observed_playout_peer_count = ws->peers.size();
  for (const auto& entry : ws->peers) {
    const auto soft = entry.second->shim->peer_audio_soft_loss(now_us);
    peer_soft_loss.supported = peer_soft_loss.supported && soft.supported;
    peer_soft_loss.samples = std::max(peer_soft_loss.samples, soft.samples);
    peer_soft_loss.report_us = std::max(peer_soft_loss.report_us, soft.report_us);
    if (entry.second->shim->peer_audio_recovery_supported()) ++peer_audio_recovery_peers;
    peer_audio_recovery_report_us = std::max(peer_audio_recovery_report_us,
        entry.second->shim->peer_audio_recovery_report_us(now_us));
    peer_audio_concealment_report_us = std::max(peer_audio_concealment_report_us,
        entry.second->shim->peer_audio_concealment_report_us(now_us));
    const auto playout = entry.second->shim->audio_playout_feedback();
    auto* peer = entry.second.get();
    const bool fresh = playout.fresh_at(now_us);
    playout_changed |= peer->observed_playout_sequence != playout.sequence ||
        peer->observed_playout_supported != playout.supported ||
        peer->observed_playout_fresh != fresh;
    peer->observed_playout_sequence = playout.sequence;
    peer->observed_playout_supported = playout.supported;
    peer->observed_playout_fresh = fresh;
    if (playout.supported) ++playout_peers;
    if (fresh) {
      ++playout_reports;
      playout_ms = std::max(playout_ms, playout.delay_ms);
    }
    const auto video_report = entry.second->shim->video_feedback();
    video_loss_report_us = std::max(video_loss_report_us,
        video_report.fresh_loss_report_us(now_us));
    video_persistent_loss_report_us = std::max(video_persistent_loss_report_us,
        video_report.fresh_persistent_loss_report_us(now_us));
    if (video_report.fresh_at(now_us)) {
      ++video_reports;
      video_loss = std::max(video_loss, video_report.loss_pct);
      video_jitter = std::max(video_jitter, video_report.jitter_ms);
      video_rtt = std::max(video_rtt, video_report.rtt_ms);
    }
    const auto report = entry.second->shim->audio_feedback();
    audio_loss_report_us = std::max(audio_loss_report_us,
        report.fresh_loss_report_us(now_us));
    if (!report.fresh_at(now_us)) continue;
    ++reports;
    loss = std::max(loss, report.loss_pct);
    jitter = std::max(jitter, report.jitter_ms);
    rtt = std::max(rtt, report.rtt_ms);
  }
  // Local snapshot revision, not another wire counter. Repeated stats reads
  // cannot turn cached RTCP into fresh buffer-trend observations.
  if (playout_changed) ++ws->audio_playout_revision;
  // Count packets accepted by each real audio receive stream. Shim ingress
  // also includes video, RTCP and packets rejected by the audio demuxer; it
  // must not keep a silent participant's audio watchdog alive.
  std::string audio_receivers;
  int requested_packet_ms = -1, requested_payload_bps = -1, audio_config_valid = -1;
  int64_t audio_packets = -1, audio_payload_bytes = -1, audio_header_padding_bytes = -1;
  int64_t audio_target_bps = -1;
  const uint64_t sample_sequence = ++ws->audio_sample_sequence;
  const bool audio_sampled = veil_media::run_on_with_timeout(
      ws->worker_tq.get(), [&] {
        requested_packet_ms = ws->audio_packet_ms;
        requested_payload_bps = ws->audio_payload_bps;
        audio_config_valid = ws->audio_config_valid ? 1 : 0;
        if (ws->send_stream) {
          const auto sender = ws->send_stream->GetStats();
          audio_packets = sender.packets_sent;
          audio_payload_bytes = sender.payload_bytes_sent;
          audio_header_padding_bytes = sender.header_and_padding_bytes_sent;
          audio_target_bps = sender.target_bitrate_bps;
        }
        constexpr char hex[] = "0123456789abcdef";
        for (const auto& entry : ws->peers) {
          if (!entry.second->recv_stream) continue;
          const auto sample = entry.second->recv_stream->GetStats(false);
          auto* peer = entry.second.get();
          const int64_t native_age_ms = peer->shim->audio_payload_receive_age_ms();
          const bool active = sample.packets_received > 0 &&
              native_age_ms >= 0 && native_age_ms <= 3000;
          const uint32_t delay_ms = current_audio_playout_delay(
              sample.jitter_buffer_ms, ws->adm.get());
          const int rtp_lag_ms = active ? ws->recovery_stats->receivers.LagMs(
              peer->audio_ssrc, webrtc::TimeMicros()) : -1;
          const uint32_t pressure_delay_ms = current_audio_playout_delay(
              std::max(sample.jitter_buffer_ms, static_cast<uint32_t>(std::max(0, rtp_lag_ms))),
              ws->adm.get());
          peer->shim->SetLocalAudioPlayout(peer->audio_ssrc, sample_sequence,
              active ? static_cast<int>(pressure_delay_ms) : -1, now_us);
          const auto recovery = ws->recovery_stats->receivers.Snapshot(peer->audio_ssrc);
          peer->shim->SetLocalAudioRecovery(peer->audio_ssrc, sample_sequence,
              active ? recovery : veil_media::AudioRecoverySample{}, now_us);
          peer->shim->SetLocalAudioConcealment(peer->audio_ssrc, sample_sequence,
              active && recovery.known ? recovery.origin : 0,
              sample.concealed_samples, sample.silent_concealed_samples, now_us);
          char id[65];
          for (size_t i = 0; i < 32; ++i) {
            id[2 * i] = hex[entry.second->id[i] >> 4];
            id[2 * i + 1] = hex[entry.second->id[i] & 15];
          }
          id[64] = '\0';
          char receiver[1024];
          const int size = std::snprintf(receiver, sizeof(receiver),
              "\"%s\":{\"audio_rx_pkts\":%llu,\"audio_delay_ms\":%u,"
              "\"audio_rtp_lag_ms\":%d,\"audio_pressure_delay_ms\":%u,"
              "\"audio_filtered_delay_ms\":%u,"
              "\"audio_rx_native_age_ms\":%lld,\"audio_interruption_count\":%d,"
              "\"audio_interruption_duration_ms\":%d,"
              "\"audio_concealed_samples\":%llu,\"audio_silent_concealed_samples\":%llu,"
              "\"audio_local_concealment_report_us\":%lld,\"audio_concealment_events\":%llu,"
              "\"audio_output_emitted_samples\":%llu,\"audio_total_samples_received\":%llu,"
              "\"audio_discarded_packets\":%llu,\"audio_jb_target_ms\":%u,"
              "\"audio_recovery_known\":%d,\"audio_latency_discarded_ms\":%llu}", id,
              static_cast<unsigned long long>(sample.packets_received),
              delay_ms, rtp_lag_ms, pressure_delay_ms,
              sample.delay_estimate_ms, static_cast<long long>(native_age_ms),
              sample.interruption_count, sample.total_interruption_duration_ms,
              static_cast<unsigned long long>(sample.concealed_samples),
              static_cast<unsigned long long>(sample.silent_concealed_samples),
              static_cast<long long>(peer->shim->local_audio_concealment_report_us(now_us)),
              static_cast<unsigned long long>(sample.concealment_events),
              static_cast<unsigned long long>(sample.jitter_buffer_emitted_count),
              static_cast<unsigned long long>(sample.total_samples_received),
              static_cast<unsigned long long>(sample.packets_discarded),
              sample.jitter_buffer_preferred_ms, recovery.known ? 1 : 0,
              static_cast<unsigned long long>(recovery.discarded_ms));
          if (size <= 0 || static_cast<size_t>(size) >= sizeof(receiver)) continue;
          if (!audio_receivers.empty()) audio_receivers += ',';
          audio_receivers.append(receiver, static_cast<size_t>(size));
        }
      }, std::chrono::milliseconds(20));
  if (!audio_sampled) {
    for (const auto& entry : ws->peers) {
      entry.second->shim->SetLocalAudioPlayout(
          entry.second->audio_ssrc, sample_sequence, -1, now_us);
      entry.second->shim->SetLocalAudioRecovery(
          entry.second->audio_ssrc, sample_sequence, {}, now_us);
      entry.second->shim->SetLocalAudioConcealment(
          entry.second->audio_ssrc, sample_sequence, 0, 0, 0, now_us);
    }
  }
  if (audio_sampled) {
    for (const auto& entry : ws->peers) {
      const auto soft = entry.second->shim->local_audio_soft_loss(now_us);
      local_soft_loss.samples = std::max(local_soft_loss.samples, soft.samples);
      local_soft_loss.report_us = std::max(local_soft_loss.report_us, soft.report_us);
      local_audio_concealment_report_us = std::max(local_audio_concealment_report_us,
          entry.second->shim->local_audio_concealment_report_us(now_us));
    }
  }
  const bool video_sampled = veil_media::run_on_with_timeout(ws->video_worker_tq.get(), [&] {
    if (ws->video_send_stream) {
      const auto video = ws->video_send_stream->GetStats();
      video_frames = video.frames_encoded;
      encoder_target_bps = video.target_media_bitrate_bps;
      video_retransmitted_packets = video_retransmitted_bytes = 0;
      video_nack_packets = video_nack_requests = video_unique_nack_requests = 0;
      video_pli_packets = video_fir_packets = video_key_frames = 0;
      for (const auto& entry : video.substreams) {
        const auto& stream = entry.second;
        video_retransmitted_packets += stream.rtp_stats.retransmitted.packets;
        video_retransmitted_bytes += stream.rtp_stats.retransmitted.TotalBytes();
        video_nack_packets += stream.rtcp_packet_type_counts.nack_packets;
        video_nack_requests += stream.rtcp_packet_type_counts.nack_requests;
        video_unique_nack_requests += stream.rtcp_packet_type_counts.unique_nack_requests;
        video_pli_packets += stream.rtcp_packet_type_counts.pli_packets;
        video_fir_packets += stream.rtcp_packet_type_counts.fir_packets;
        video_key_frames += stream.frame_counts.key_frames;
      }
    }
    fps = ws->video_max_fps.load(std::memory_order_relaxed);
    kbps = ws->video_target_bitrate_bps / 1000;
  }, std::chrono::milliseconds(20));
  char json[1024];
  const int written = std::snprintf(json, sizeof(json),
      "{\"video_feedback_reports\":%d,\"video_feedback_rtt_ms\":%lld,"
      "\"video_feedback_loss_pct\":%d,\"video_feedback_jitter_ms\":%d,"
      "\"audio_feedback_reports\":%d,\"rtt_ms\":%lld,\"tx_loss_pct\":%d,"
      "\"tx_jitter_ms\":%d,\"tx_drops\":%llu,\"video_tx_frames\":%llu,"
      "\"max_fps\":%.3f,\"video_kbps\":%d,\"video_encoder_target_bps\":%d,\"worker_stalled\":%d,\"video_worker_stalled\":%d}",
      video_reports, static_cast<long long>(video_rtt), video_loss, video_jitter,
      reports, static_cast<long long>(rtt), loss, jitter,
      static_cast<unsigned long long>(ws->fanout->audio_drops()),
      static_cast<unsigned long long>(video_frames), fps, kbps, encoder_target_bps,
      audio_sampled ? 0 : 1, video_sampled ? 0 : 1);
  if (written <= 0 || static_cast<size_t>(written) >= sizeof(json)) return nullptr;
  // Capability remains explicit on a stalled worker: unknown audio never
  // falls back to video ingress. These fields are endpoint-local JSON only.
  std::string snapshot(json, static_cast<size_t>(written) - 1);
  const auto frame_budget = ws->video_frame_budget->snapshot();
  snapshot += ",\"video_frame_budget_bytes\":" + std::to_string(frame_budget.bytes) +
              ",\"video_frame_pixel_cap\":" + std::to_string(frame_budget.max_pixels) +
              ",\"video_frame_oversize_count\":" + std::to_string(frame_budget.oversize_frames) +
              ",\"video_frame_encoded_pixels\":" + std::to_string(frame_budget.last_pixels) +
              ",\"video_frame_encoded_bytes\":" + std::to_string(frame_budget.last_bytes);
  snapshot += ",\"video_tx_retransmitted_pkts\":" + std::to_string(video_retransmitted_packets) +
              ",\"video_tx_retransmitted_bytes\":" + std::to_string(video_retransmitted_bytes) +
              ",\"video_rx_nack_packets\":" + std::to_string(video_nack_packets) +
              ",\"video_rx_nack_requests\":" + std::to_string(video_nack_requests) +
              ",\"video_rx_unique_nack_requests\":" + std::to_string(video_unique_nack_requests) +
              ",\"video_rx_pli_packets\":" + std::to_string(video_pli_packets) +
              ",\"video_rx_fir_packets\":" + std::to_string(video_fir_packets) +
              ",\"video_tx_key_frames\":" + std::to_string(video_key_frames);
  snapshot += ",\"audio_max_packet_ms\":60,\"audio_requested_packet_ms\":" + std::to_string(requested_packet_ms) +
              ",\"audio_requested_payload_bps\":" + std::to_string(requested_payload_bps) +
              ",\"audio_config_valid\":" + std::to_string(audio_config_valid) +
              ",\"audio_tx_packet_duration_ms\":" + std::to_string(
                  ws->audio_packet_duration->load(std::memory_order_relaxed)) +
              ",\"audio_tx_payload_pkts\":" + std::to_string(audio_packets) +
              ",\"audio_tx_payload_bytes\":" + std::to_string(audio_payload_bytes) +
              ",\"audio_tx_header_padding_bytes\":" + std::to_string(audio_header_padding_bytes) +
              ",\"audio_tx_target_bps\":" + std::to_string(audio_target_bps) +
              ",\"audio_tx_rtp_drops\":" + std::to_string(ws->fanout->audio_drops());
  const auto rtcp_send = ws->rtcp_send_stats->Snapshot();
  // Successful per-peer copies, before encryption/padding. Unlike encoder
  // RTP stats these already include fanout, including peers since removed.
  snapshot += ",\"audio_rtcp_tx_pkts\":" + std::to_string(rtcp_send.audio_packets) +
              ",\"audio_rtcp_tx_bytes\":" + std::to_string(rtcp_send.audio_bytes) +
              ",\"video_rtcp_tx_pkts\":" + std::to_string(rtcp_send.video_packets) +
              ",\"video_rtcp_tx_bytes\":" + std::to_string(rtcp_send.video_bytes);
  for (size_t plane = 0; plane < 2; ++plane) {
    const std::string prefix = plane ? "video_rtcp_" : "audio_rtcp_";
    for (size_t kind = 0; kind < veil_media::kRtcpKinds; ++kind)
      snapshot += ",\"" + prefix + veil_media::kRtcpKindNames[kind] +
                  "_blocks\":" + std::to_string(rtcp_send.blocks[plane][kind]);
    snapshot += ",\"" + prefix + "malformed\":" + std::to_string(rtcp_send.malformed[plane]);
  }
  snapshot += ",\"video_rtcp_remb_coalesced_copies\":" +
              std::to_string(rtcp_send.video_remb_coalesced_copies);
  snapshot += ",\"audio_loss_report_us\":" + std::to_string(audio_loss_report_us) +
              ",\"video_loss_report_us\":" + std::to_string(video_loss_report_us);
  snapshot += ",\"audio_local_concealment_report_us\":" +
              std::to_string(local_audio_concealment_report_us);
  snapshot += ",\"audio_soft_loss_duration_supported\":1,\"audio_peer_soft_loss_duration_supported\":" +
      std::to_string(peer_soft_loss.supported ? 1 : 0) +
      ",\"audio_local_soft_loss_report_us\":" + std::to_string(local_soft_loss.report_us) +
      ",\"audio_peer_soft_loss_report_us\":" + std::to_string(peer_soft_loss.report_us) +
      ",\"audio_local_soft_loss_window_ms\":" + std::to_string(local_soft_loss.samples / 48.0) +
      ",\"audio_peer_soft_loss_window_ms\":" + std::to_string(peer_soft_loss.samples / 48.0);
  snapshot += ",\"video_persistent_loss_report_us\":" +
              std::to_string(video_persistent_loss_report_us);
  snapshot += ",\"audio_playout_peers\":" + std::to_string(playout_peers) +
              ",\"audio_playout_sequence\":" + std::to_string(ws->audio_playout_revision) +
              ",\"audio_playout_reports\":" + std::to_string(playout_reports) +
              ",\"audio_playout_ms\":" + std::to_string(playout_ms);
  snapshot += ",\"video_send_paused\":" + std::to_string(ws->video_send_paused.load() ? 1 : 0);
  const auto video_send = ws->fanout->video_send_stats();
  // Per-peer attempted copies, unlike video_tx_frames (one logical encoder).
  // Includes payload, padding and rejected copies; no media role leaves host.
  snapshot += ",\"video_tx_rtp_attempts\":" + std::to_string(video_send.attempts) +
              ",\"video_tx_rtp_queued\":" + std::to_string(video_send.queued) +
              ",\"video_tx_payload_pkts\":" + std::to_string(video_send.payload_packets) +
              ",\"video_tx_payload_rtp_bytes\":" + std::to_string(video_send.payload_rtp_bytes) +
              ",\"video_tx_payload_counter_scope\":\"fanout_attempts\"" +
              ",\"video_tx_payload_bytes\":" + std::to_string(video_send.payload_bytes) +
              ",\"video_tx_padding_bytes\":" + std::to_string(video_send.padding_bytes) +
              ",\"video_tx_rtp_drops\":" + std::to_string(video_send.dropped);
  snapshot += ",\"audio_peer_recovery_report_us\":" +
      std::to_string(peer_audio_recovery_report_us);
  snapshot += ",\"audio_peer_recovery_peers\":" + std::to_string(peer_audio_recovery_peers);
  snapshot += ",\"audio_peer_concealment_report_us\":" +
      std::to_string(peer_audio_concealment_report_us);
  snapshot += ",\"audio_latency_recovery_count\":" +
      std::to_string(ws->recovery_stats->count.load(std::memory_order_acquire));
  snapshot += ",\"audio_latency_discarded_ms\":" +
      std::to_string(ws->recovery_stats->discarded_ms.load(std::memory_order_relaxed));
  snapshot += ",\"audio_latency_fallback_frames\":" +
      std::to_string(ws->recovery_stats->fallback_frames.load(std::memory_order_relaxed));
  snapshot += ",\"audio_rx_supported\":1,\"audio_rx_native_age_supported\":1,\"audio_receivers\":{";
  if (audio_sampled) snapshot += audio_receivers;
  snapshot += "}}";
  return dup_cstr(snapshot.c_str());
#else
  return dup_cstr("{}");
#endif
}

int veil_media_group_engine_stop_video(VeilGroupMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  engine->video_running.store(false);
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws) return VEIL_MEDIA_OK;
  GroupWebrtcState* ws = engine->ws.get();
  if (ws->camera) {
    ws->camera->Stop();
    ws->camera.reset();
  }
  if (ws->screen) {
    ws->screen->Stop();
    ws->screen.reset();
  }
  if (ws->test_video_run.exchange(false) && ws->test_video_thread.joinable())
    ws->test_video_thread.join();
  if (ws->video_call) {
    if (!run_on(ws->video_worker_tq.get(), [&]() {
          if (ws->video_send_stream) {
            ws->video_send_stream->Stop();
            ws->video_call->DestroyVideoSendStream(ws->video_send_stream);
            ws->video_send_stream = nullptr;
          }
          for (auto& entry : ws->peers)
            stop_group_peer_video(ws, entry.second.get());
        })) {
      vlog("group video: stop INCOMPLETE — worker queue did not schedule; "
           "the streams are still live");
      return VEIL_MEDIA_ERR_STATE;
    }
  }
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_group_engine_start_camera(VeilGroupMediaEngine* engine,
                                         int width, int height, int fps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && \
    (defined(__APPLE__) || (defined(__linux__) && !defined(__ANDROID__)) || \
     defined(_WIN32))
  GroupWebrtcState* ws = engine->ws.get();
  if (!ws || !ws->video_source || !engine->video_running.load())
    return VEIL_MEDIA_ERR_STATE;
  // EXISTENCE IS NOT CAPTURE. The capturer's loop ends on its own when the
  // device goes away, and the object stays behind holding nothing. Answering
  // OK on the pointer alone meant a camera that had died could never be
  // started again for the rest of the call: every retry reported success and
  // no frame ever came. Measured on a Windows 11 ARM64 stand 2026-09-05 —
  // disabling the camera mid-capture returns
  // MF_E_VIDEO_RECORDING_DEVICE_INVALIDATED (0xc00d3ea2) from the pending
  // synchronous read in 292 ms, so this is the ordinary unplug (report19
  // V19-M6).
  if (ws->camera && ws->camera->Capturing()) return VEIL_MEDIA_OK;
  if (ws->camera) {
    // Reap the finished capture thread before the object is dropped.
    ws->camera->Stop();
    ws->camera.reset();
  }
  if (width <= 0) width = 352;
  if (height <= 0) height = 198;
  if (fps <= 0) fps = 15;
  veil_media::AdaptiveVideoSource* source = ws->video_source.get();
  VeilVideoSink* local_sink = ws->local_video_sink.get();
  ws->camera.reset(veil_media::CreatePlatformCamera(
      [ws, source, local_sink](const uint8_t* y, const uint8_t* u,
                           const uint8_t* v, int w, int h, int sy, int su,
                           int sv, int64_t ts_us) {
        if (local_sink)
          local_sink->store_i420(y, u, v, w, h, sy, su, sv);
        if (should_encode_video_frame(ws))
          push_i420(source, y, u, v, w, h, sy, su, sv, ts_us);
      }));
  if (!ws->camera || !ws->camera->Start(width, height, fps)) {
    ws->camera.reset();
    return VEIL_MEDIA_ERR_STATE;
  }
  return VEIL_MEDIA_OK;
#else
  (void)width;
  (void)height;
  (void)fps;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_group_engine_stop_camera(VeilGroupMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->camera) {
    engine->ws->camera->Stop();
    engine->ws->camera.reset();
  }
#endif
  return VEIL_MEDIA_OK;
}

// The five screen entry points below are macOS + Windows, not the camera's
// macOS + Linux + Windows. That asymmetry is real: this tree has no X11
// capturer, so CreatePlatformScreen has no definition to link against on
// Linux. Widening these to __linux__ produces an unresolved symbol, not a
// working share.
int veil_media_group_engine_start_screen_source(VeilGroupMediaEngine* engine,
                                                const char* source_id,
                                                int width, int fps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && (defined(__APPLE__) || defined(_WIN32))
  GroupWebrtcState* ws = engine->ws.get();
  if (!ws || !ws->video_source || !engine->video_running.load())
    return VEIL_MEDIA_ERR_STATE;
  if (ws->screen) return VEIL_MEDIA_OK;
  if (width <= 0) width = 640;
  if (fps <= 0) fps = 10;
  if (ws->camera) {
    ws->camera->Stop();
    ws->camera.reset();
  }
  veil_media::AdaptiveVideoSource* source = ws->video_source.get();
  VeilVideoSink* local_sink = ws->local_video_sink.get();
  ws->screen.reset(veil_media::CreatePlatformScreen(
      [ws, source, local_sink](const uint8_t* y, const uint8_t* u,
                           const uint8_t* v, int w, int h, int sy, int su,
                           int sv, int64_t ts_us) {
        if (local_sink)
          local_sink->store_i420(y, u, v, w, h, sy, su, sv);
        if (should_encode_video_frame(ws))
          push_i420(source, y, u, v, w, h, sy, su, sv, ts_us);
      },
      source_id));
  if (!ws->screen || !ws->screen->Start(width, fps)) {
    ws->screen.reset();
    return VEIL_MEDIA_ERR_STATE;
  }
  return VEIL_MEDIA_OK;
#else
  (void)source_id;
  (void)width;
  (void)fps;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_group_engine_start_screen(VeilGroupMediaEngine* engine,
                                         int width, int fps) {
  return veil_media_group_engine_start_screen_source(engine, nullptr, width,
                                                     fps);
}

int veil_media_group_engine_stop_screen(VeilGroupMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->screen) {
    engine->ws->screen->Stop();
    engine->ws->screen.reset();
  }
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_group_engine_push_video_frame(
    VeilGroupMediaEngine* engine, const uint8_t* y, const uint8_t* u,
    const uint8_t* v, int width, int height, int stride_y, int stride_u,
    int stride_v, int64_t ts_us) {
  if (engine == nullptr || y == nullptr || u == nullptr || v == nullptr)
    return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->video_source ||
      !engine->video_running.load())
    return VEIL_MEDIA_ERR_STATE;
  if (engine->ws->local_video_sink)
    engine->ws->local_video_sink->store_i420(
        y, u, v, width, height, stride_y, stride_u, stride_v);
  if (should_encode_video_frame(engine->ws.get()))
    push_i420(engine->ws->video_source.get(), y, u, v, width, height, stride_y,
              stride_u, stride_v, ts_us);
  return VEIL_MEDIA_OK;
#else
  (void)width;
  (void)height;
  (void)stride_y;
  (void)stride_u;
  (void)stride_v;
  (void)ts_us;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_group_engine_get_peer_video_frame(
    VeilGroupMediaEngine* engine, const uint8_t* peer_id, uint8_t* dst,
    int dst_cap, int* out_w, int* out_h) {
  if (engine == nullptr || peer_id == nullptr) return 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws) return 0;
  const auto it = engine->ws->peers.find(node_key(peer_id));
  if (it == engine->ws->peers.end() || !it->second->video_sink) return 0;
  return it->second->video_sink->get_frame(dst, dst_cap, out_w, out_h);
#else
  (void)dst;
  (void)dst_cap;
  (void)out_w;
  (void)out_h;
  return 0;
#endif
}

int veil_media_group_engine_get_local_video_frame(
    VeilGroupMediaEngine* engine, uint8_t* dst, int dst_cap, int* out_w,
    int* out_h) {
  if (engine == nullptr) return 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->local_video_sink)
    return engine->ws->local_video_sink->get_frame(dst, dst_cap, out_w, out_h);
#else
  (void)dst;
  (void)dst_cap;
  (void)out_w;
  (void)out_h;
#endif
  return 0;
}

void veil_media_group_engine_destroy(VeilGroupMediaEngine* engine) {
  if (engine == nullptr) return;
  veil_media_group_engine_stop_video(engine);
  veil_media_group_engine_stop_audio(engine);
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws) {
    for (auto& entry : engine->ws->peers) {
      engine->ws->fanout->Remove(entry.second->chan);
      entry.second->shim->Stop();
    }
    engine->ws->peers.clear();
    engine->ws->video_call.reset();
    engine->ws->call.reset();
    if (engine->ws->adm) {
      auto* adm = engine->ws->adm.get();
      run_on_adm_thread([adm] { adm->Terminate(); });
    }
  }
#endif
  delete engine;
}

int veil_media_engine_start_audio(VeilMediaEngine* engine, int send, int recv) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  {
    std::lock_guard<std::mutex> lock(engine->config_mu);
    engine->config_frozen = true;
  }
  if (engine->audio_running.load()) return VEIL_MEDIA_OK;  // idempotent
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  WebrtcState* ws = engine->ws.get();
  const uint32_t local_ssrc = ssrc_of(engine->local);
  const uint32_t remote_ssrc = ssrc_of(engine->peer);

  // Streams must be created on the Call's worker queue.
  const bool created = run_on(ws->worker_tq.get(), [&]() {
    if (ws->audio_state && ws->adm)
      ws->audio_state->SetRecording(!engine->mic_muted);
    // The Call's audio network state defaults to kNetworkDown, which makes the
    // send transport hold every RTP packet in the pacer (only RTCP leaks out on
    // its own path). Bring the audio channel up so mic audio actually flows.
    ws->call->SignalChannelNetworkState(webrtc::MediaType::AUDIO,
                                        webrtc::kNetworkUp);
    if (send && ws->send_stream == nullptr) {
      ws->audio_packet_duration->store(0, std::memory_order_relaxed);
      webrtc::AudioSendStream::Config sc(ws->shim.get());  // sets send_transport
      sc.rtp.ssrc = local_ssrc;
      // TWCC: the send-side bandwidth estimator needs this both ways.
      sc.rtp.extensions.emplace_back(
          webrtc::RtpExtension::kTransportSequenceNumberUri,
          webrtc::RtpHeaderExtensionId(1));
      sc.encoder_factory = webrtc::CreateBuiltinAudioEncoderFactory();
      sc.send_codec_spec = webrtc::AudioSendStream::Config::SendCodecSpec(
          kOpusPayloadType, VeilOpusSendFormat());
      configure_call_audio_send(sc, ws->shim->independent_transport_feedback(),
                                engine->audio_packet_overhead.load(),
                                ws->audio_packet_duration, ws->audio_packet_priority);
      if (engine->audio_packet_overhead.load() > 0) {
        webrtc::BitrateConstraints limits;
        limits.start_bitrate_bps = 48'000;
        limits.max_bitrate_bps = 160'000;
        ws->call->GetTransportControllerSend()->SetSdpBitrateParameters(limits);
        apply_audio_route(engine, true);
      }
      ws->send_stream = ws->call->CreateAudioSendStream(sc);
      if (ws->send_stream) {
        ws->send_stream->SetMuted(engine->mic_muted);
        ws->send_stream->Start();
      }
    }
    if (recv && ws->recv_stream == nullptr) {
      webrtc::AudioReceiveStreamInterface::Config rc;
      configure_call_audio_receive(rc);
      rc.rtp.remote_ssrc = remote_ssrc;
      rc.rtcp_send_transport = ws->shim.get();
      rc.decoder_factory = webrtc::CreateBuiltinAudioDecoderFactory();
      // SdpAudioFormat has no default ctor, so operator[] won't work — emplace.
      rc.decoder_map.emplace(kOpusPayloadType,
                             webrtc::SdpAudioFormat("opus", 48000, 2));
      ws->recv_stream = ws->call->CreateAudioReceiveStream(rc);
      if (ws->recv_stream) ws->recv_stream->Start();
    }
  });
  if (!created) {
    // Nothing was created, and `audio_running` is set unconditionally further
    // down — so without this the engine reports a running call with no
    // streams, and the ADM below starts a microphone whose audio goes nowhere.
    vlog("audio: start FAILED — worker queue did not schedule; no streams");
    return VEIL_MEDIA_ERR_STATE;
  }
  // webrtc::Call does NOT drive the AudioDeviceModule the way PeerConnection
  // does — start capture/playout explicitly, else the send stream has no audio
  // frames (only RTCP flows) and the recv stream is never played out. The
  // AVAudioEngine ADM's start is non-blocking + idempotent (all engine work is
  // serialized on its own GCD queue), so this is safe on the calling thread and
  // AudioState toggling it too on the worker queue just no-ops.
  // What was ASKED for, before anything acts on it. The playout branch below
  // is conditional, and a conditional that does not fire leaves no trace at
  // all: measured on Windows 2026-08-29, `recording=1 playing=0` with not one
  // line from start_playout, which cannot distinguish "playout refused" from
  // "playout never attempted". Now it can.
  vlog("adm start: asked send=%d recv=%d micMuted=%d adm=%s", (int)send,
       (int)recv, (int)engine->mic_muted, ws->adm ? "yes" : "NULL");
  bool capture_failed = false;
  bool playout_failed = false;
  if (ws->adm) {
    if (send && !engine->mic_muted) {
      // Same contract as set_mic_muted/group start: surface a capture device
      // that refuses to start instead of silently sending nothing.
      if (!start_capture(ws->adm.get(), "adm start")) capture_failed = true;
    }
    // Same contract as capture: a playout that refused is a device failure
    // the caller has to hear about, not a line in a log (report19 V19-M3).
    if (recv && !start_playout(ws->adm.get())) playout_failed = true;
    int recording = 0, playing = 0;
    run_on_adm_thread([&] {
      recording = ws->adm->Recording();
      playing = ws->adm->Playing();
    });
    vlog("adm start: recording=%d playing=%d", recording, playing);
  }
  // A few seconds in, log BOTH directions' packet counters.
  //
  // Only the send side was logged, and that cannot answer the question a
  // person actually asks — "I cannot hear them". Sending is ours to see;
  // hearing depends on packets ARRIVING, and the log said nothing about those
  // beyond a single "first inbound" marker. So a silent call looked identical
  // whether the peer sent nothing or we failed to play what it sent.
  if (ws->send_stream || ws->recv_stream) {
    ws->worker_tq->PostDelayedTask(
        [ws]() {
          if (ws->send_stream) {
            const auto s = ws->send_stream->GetStats();
            // audio_level and input energy are what separate "the microphone
            // is silent" from "the stream is broken". Byte counts cannot: a
            // codec sending silence produces the same packet count and half
            // the bytes, which reads as a healthy stream until someone weighs
            // it against a working call.
            vlog("sendstream @3s: packets_sent=%lld bytes=%lld level=%d "
                 "input_energy=%.4f input_seconds=%.1f",
                 (long long)s.packets_sent, (long long)s.payload_bytes_sent,
                 (int)s.audio_level, s.total_input_energy,
                 s.total_input_duration);
          }
          if (ws->recv_stream) {
            const auto r = ws->recv_stream->GetStats(false);
            vlog("recvstream @3s: packets_received=%u bytes=%lld lost=%d "
                 "jitter_ms=%u concealed_samples=%llu",
                 (unsigned)r.packets_received,
                 (long long)r.payload_bytes_received, (int)r.packets_lost,
                 (unsigned)r.jitter_ms,
                 (unsigned long long)r.concealed_samples);
          } else {
            vlog("recvstream @3s: NO RECEIVE STREAM — nothing can be heard");
          }
        },
        webrtc::TimeDelta::Seconds(3));
  }
  engine->audio_running.store(true);
  if (capture_failed || playout_failed) return VEIL_MEDIA_ERR_DEVICE;
  return VEIL_MEDIA_OK;
#else
  (void)send;
  (void)recv;
  return VEIL_MEDIA_ERR_STATE;  // no WebRTC linked yet
#endif
}

int veil_media_engine_stop_audio(VeilMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->shim)
    engine->ws->shim->SetAudioMirrorChannel(0);
#endif
  if (!engine->audio_running.exchange(false)) return VEIL_MEDIA_OK;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->call) {
    WebrtcState* ws = engine->ws.get();
    // Stop the ADM off the worker queue (see start_audio — StartRecording/
    // StopRecording can block CoreAudio and must not wedge the Call worker).
    if (ws->adm) {
      run_on_adm_thread([&] {
        if (ws->adm->Recording()) ws->adm->StopRecording();
        if (ws->adm->Playing()) ws->adm->StopPlayout();
      });
    }
    if (!run_on(ws->worker_tq.get(), [&]() {
          if (ws->send_stream) {
            ws->send_stream->Stop();
            ws->call->DestroyAudioSendStream(ws->send_stream);
            ws->send_stream = nullptr;
          }
          if (ws->recv_stream) {
            ws->recv_stream->Stop();
            ws->call->DestroyAudioReceiveStream(ws->recv_stream);
            ws->recv_stream = nullptr;
          }
        })) {
      vlog("audio: stop INCOMPLETE — worker queue did not schedule; "
           "the streams are still live");
      return VEIL_MEDIA_ERR_STATE;
    }
  }
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_set_independent_transport_feedback(VeilMediaEngine* engine,
                                                         int enabled) {
  if (!engine || (enabled != 0 && enabled != 1)) return VEIL_MEDIA_ERR_ARG;
  std::lock_guard<std::mutex> lock(engine->config_mu);
  if (engine->config_frozen) return VEIL_MEDIA_ERR_STATE;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->shim) return VEIL_MEDIA_ERR_STATE;
  engine->ws->shim->SetIndependentTransportFeedback(enabled != 0);
  if (enabled == 0) engine->audio_packet_overhead.store(0);
  return VEIL_MEDIA_OK;
#else
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_set_audio_packet_overhead(VeilMediaEngine* engine, int bytes) {
  if (!engine || bytes < 0 || bytes > 4096) return VEIL_MEDIA_ERR_ARG;
  std::lock_guard<std::mutex> lock(engine->config_mu);
  // Selecting the encoder factory remains a pre-start decision. Once enabled,
  // route framing can change without replacing the encoder, RTP sender or
  // receive buffer. Do not enable/disable ANA underneath a live stream.
  if (engine->config_frozen &&
      (bytes == 0 || engine->audio_packet_overhead.load() == 0)) {
    return VEIL_MEDIA_ERR_STATE;
  }
  if (bytes == 0) {
    engine->audio_packet_overhead.store(0);
    return VEIL_MEDIA_OK;
  }
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->shim ||
      !engine->ws->shim->independent_transport_feedback()) return VEIL_MEDIA_ERR_STATE;
  if (engine->config_frozen) {
    auto* ws = engine->ws.get();
    if (!ws->call) return VEIL_MEDIA_ERR_STATE;
    // OnNetworkRouteChanged updates the audio allocator and pacer; its next
    // allocation delivers the new overhead to the existing Opus/ANA encoder.
    // Keep the same route identity: this corrects framing, not connectivity.
    // The cancellation handshake fences this reference on timeout. A blocked
    // audio worker must not hold up host route control for the usual 10 s.
    const bool applied = veil_media::run_on_with_timeout(ws->worker_tq.get(), [&] {
      const auto generation = ws->route_generation.load();
      ws->call->GetTransportControllerSend()->OnNetworkRouteChanged(
          "opaque", opaque_route(generation, bytes));
      ws->audio_route_applied.store(generation);
      engine->audio_packet_overhead.store(bytes);
    }, std::chrono::milliseconds(50));
    return applied ? VEIL_MEDIA_OK : VEIL_MEDIA_ERR_STATE;
  }
  engine->audio_packet_overhead.store(bytes);
  return VEIL_MEDIA_OK;
#else
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_set_video_packet_overhead(VeilMediaEngine* engine, int bytes) {
  // The pinned video RTP sender subtracts this from its 1500-byte path MTU.
  // Bound the hint before that subtraction, leaving room for RTP headers.
  if (!engine || bytes < 0 || bytes > 1024) return VEIL_MEDIA_ERR_ARG;
  std::lock_guard<std::mutex> lock(engine->config_mu);
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  auto* ws = engine->ws.get();
  if (!ws || !ws->video_call || !ws->shim ||
      !ws->shim->independent_transport_feedback()) return VEIL_MEDIA_ERR_STATE;
  const bool applied = veil_media::run_on_with_timeout(ws->video_worker_tq.get(), [&] {
    auto* controller = ws->video_call->GetTransportControllerSend();
    controller->IncludeOverheadInPacedSender();
    controller->OnNetworkRouteChanged(
        "opaque", opaque_route(ws->route_generation.load(), bytes));
    ws->video_packet_overhead.store(bytes);
    ws->video_route_applied.store(ws->route_generation.load());
  }, std::chrono::milliseconds(20));
  return applied ? VEIL_MEDIA_OK : VEIL_MEDIA_ERR_STATE;
#else
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_set_max_rtp_packet_size(VeilMediaEngine* engine,
                                              int max_packet_size) {
  if (engine == nullptr || max_packet_size < 0) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  WebrtcState* ws = engine->ws.get();
  // Pre-set to the failure: `run_on` not scheduling means the size was NOT
  // applied, and an initial OK here would report a setting that never landed.
  int result = VEIL_MEDIA_ERR_STATE;
  const bool applied = run_on(ws->worker_tq.get(), [&]() {
    if (ws->video_send_stream != nullptr) {
      return;
    }
    ws->video_max_rtp_packet_size =
        max_packet_size == 0 ? 0 : std::clamp(max_packet_size, 576, 1460);
    result = VEIL_MEDIA_OK;
  });
  (void)applied;  // folded into `result`, which starts at the failure
  return result;
#else
  (void)max_packet_size;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_start_video(VeilMediaEngine* engine, int send, int recv,
                                  int max_bitrate_kbps, int max_fps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  {
    std::lock_guard<std::mutex> lock(engine->config_mu);
    engine->config_frozen = true;
  }
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->video_call) return VEIL_MEDIA_ERR_STATE;
  WebrtcState* ws = engine->ws.get();
  const uint32_t local_v = video_ssrc_of(engine->local);
  const uint32_t remote_v = video_ssrc_of(engine->peer);
  constexpr int kVp8Pt = 96;

  const bool created = run_on(ws->video_worker_tq.get(), [&]() {
    // Video has its own network state (defaults kNetworkDown); bring it up.
    ws->video_call->SignalChannelNetworkState(webrtc::MediaType::VIDEO,
                                        webrtc::kNetworkUp);
    if (!ws->video_encoder_factory)
      ws->video_encoder_factory =
          std::make_unique<veil_media::FrameSizingVp8EncoderFactory>(
              std::make_unique<webrtc::VideoEncoderFactoryTemplate<
                  webrtc::LibvpxVp8EncoderTemplateAdapter>>(), ws->video_frame_budget);
    if (!ws->video_decoder_factory)
      ws->video_decoder_factory =
          // BOUNDED. `VeilVideoSink` refuses an oversized frame where it
          // arrives, and libvpx has already sized four reference buffers from the
          // keyframe by then — see `veil_bounded_vp8.h` (report24 MEDIA-3).
          std::make_unique<veil_media::BoundedVp8DecoderFactory>(
              std::make_unique<webrtc::VideoDecoderFactoryTemplate<
                      webrtc::LibvpxVp8DecoderTemplateAdapter>>(),
              kMaxVideoSide);
    if (!ws->video_bitrate_alloc_factory)
      ws->video_bitrate_alloc_factory =
          webrtc::CreateBuiltinVideoBitrateAllocatorFactory();
    if (!ws->video_source)
      ws->video_source = std::make_unique<veil_media::AdaptiveVideoSource>(ws->video_frame_budget);

    if (send && ws->video_send_stream == nullptr) {
      webrtc::VideoSendStream::Config sc(ws->shim->video_transport());  // sets send_transport
      sc.rtp.ssrcs = {local_v};                            // NOTE: vector
      sc.rtp.payload_name = "VP8";
      sc.rtp.payload_type = kVp8Pt;
      if (ws->video_max_rtp_packet_size > 0)
        sc.rtp.max_packet_size = ws->video_max_rtp_packet_size;
      sc.rtp.nack.rtp_history_ms = kVideoNackHistoryMs;
      sc.rtp.extensions.emplace_back(
          webrtc::RtpExtension::kTransportSequenceNumberUri,
          webrtc::RtpHeaderExtensionId(1));  // TWCC, same id as audio
      sc.encoder_settings.encoder_factory = ws->video_encoder_factory.get();
      sc.encoder_settings.bitrate_allocator_factory =
          ws->video_bitrate_alloc_factory.get();  // REQUIRED (deref, no null-check)

      // The caller selects a route-aware budget: direct P2P can spend more,
      // while the onion fallback stays conservative even though several RTP
      // packets now share each padded cell. (VEIL_MEDIA_VIDEO_KBPS overrides.)
      int kbps = max_bitrate_kbps > 0 ? max_bitrate_kbps : 150;
      if (const char* e = std::getenv("VEIL_MEDIA_VIDEO_KBPS")) {
        int v = std::atoi(e);
        if (v > 0) kbps = v;
      }
      kbps = std::clamp(kbps, 30, 2500);
      const int fps = std::clamp(max_fps > 0 ? max_fps : 15, 1, 60);
      const int bps = kbps * 1000;
      ws->video_frame_budget->SetProfile(bps);
      ws->video_target_bitrate_bps = bps;
      ws->video_max_fps.store(fps, std::memory_order_relaxed);
      ws->video_last_encoded_frame_us.store(0, std::memory_order_relaxed);
      // Start at the route budget. Negotiated feedback subsequently owns the
      // estimate; older peers still need the profile floor to keep the encoder
      // and pacer budgets aligned without usable transport feedback.
      {
        // Negotiated feedback lets GCC lower video below the profile under
        // congestion. Older peers supply no usable split transport feedback;
        // retain their profile floor and app-level adaptation.
        ws->video_call->SetClientBitratePreferences(
            veil_media::video_bitrate_settings(
                bps, ws->shim->independent_transport_feedback(), true));
      }
      auto ec = veil_media::vp8_encoder_config();
      ec.max_bitrate_bps = bps;
      webrtc::VideoStream layer;  // ≥1 layer REQUIRED (default factory DCHECK)
      layer.active = true;
      layer.min_bitrate_bps = 30000;
      layer.target_bitrate_bps = bps * 2 / 3;
      layer.max_bitrate_bps = bps;
      layer.max_framerate = fps;
      layer.max_qp = 63;
      ec.simulcast_layers.push_back(layer);

      ws->video_send_stream =
          ws->video_call->CreateVideoSendStream(std::move(sc), std::move(ec));
      vlog("video: send stream=%p", (void*)ws->video_send_stream);
      if (ws->video_send_stream) {
        ws->shim->ResetVideoLossEvidence();
        ws->audio_packet_priority->ExpectVideo(true, webrtc::TimeMicros());
        ws->video_send_stream->SetSource(
            ws->video_source.get(),
            kbps > 150 ? webrtc::DegradationPreference::BALANCED
                       : webrtc::DegradationPreference::MAINTAIN_FRAMERATE);
        ws->video_send_stream->Start();
      }
    }
    if (recv && ws->video_recv_stream == nullptr) {
      webrtc::VideoReceiveStreamInterface::Config rc(
          ws->shim->video_transport(), ws->video_decoder_factory.get());
      rc.rtp.remote_ssrc = remote_v;    // do NOT set local_ssrc (deprecated)
      rc.rtp.nack.rtp_history_ms = kVideoNackHistoryMs;
      rc.renderer = ws->video_sink.get();
      rc.decoders.emplace_back(webrtc::SdpVideoFormat::VP8(), kVp8Pt);
      ws->video_recv_stream = ws->video_call->CreateVideoReceiveStream(std::move(rc));
      if (ws->video_recv_stream) ws->video_recv_stream->Start();
    }
  });
  if (!created) {
    // No streams were created, and everything below — the SSRC routing, the
    // synthetic source, the OK — is written as though they were.
    vlog("video: start FAILED — worker queue did not schedule; no streams");
    return VEIL_MEDIA_ERR_STATE;
  }
  // Route inbound video RTP (this SSRC) to the video demuxer in the shim.
  ws->shim->SetRemoteVideoSsrc(remote_v);
  vlog("video: start send=%d recv=%d ssrc(local=%u remote=%u)", send, recv,
       local_v, remote_v);

  // Built-in synthetic source (VEIL_MEDIA_TEST_VIDEO) — a moving gradient at
  // ~30fps into the broadcaster, so video RTP flows without a real capturer.
  if (send && std::getenv("VEIL_MEDIA_TEST_VIDEO") != nullptr &&
      !ws->test_video_run.load()) {
    ws->test_video_run.store(true);
    ws->test_video_thread = std::thread([ws]() {
      const int w = 320, h = 240;
      const int cw = (w + 1) / 2, chh = (h + 1) / 2;
      std::vector<uint8_t> yb(w * h), ub(cw * chh), vb(cw * chh);
      uint32_t f = 0;
      while (ws->test_video_run.load()) {
        for (int j = 0; j < h; ++j)
          for (int i = 0; i < w; ++i)
            yb[j * w + i] = static_cast<uint8_t>(i + j + f);
        std::fill(ub.begin(), ub.end(), static_cast<uint8_t>(128));
        std::fill(vb.begin(), vb.end(), static_cast<uint8_t>(128 + f));
        if (should_encode_video_frame(ws))
          push_i420(ws->video_source.get(), yb.data(), ub.data(), vb.data(), w, h,
                    w, cw, cw, 0);
        if ((f % 60) == 0) vlog("test video: pushed %u frames", f);
        ++f;
        std::this_thread::sleep_for(std::chrono::milliseconds(33));
      }
    });
  }
  return VEIL_MEDIA_OK;
#else
  (void)send;
  (void)recv;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

static int veil_media_engine_apply_video_budget(VeilMediaEngine* engine,
    int max_bitrate_kbps, double max_fps, int minimum_kbps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  if (max_bitrate_kbps <= 0 || !std::isfinite(max_fps) || max_fps <= 0)
    return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->video_call) return VEIL_MEDIA_ERR_STATE;
  WebrtcState* ws = engine->ws.get();
  // Discarded: `rc` starts at the failure and is only raised to OK by the
  // last line INSIDE the closure, so a queue that never scheduled returns the
  // failure by construction.
  int rc = VEIL_MEDIA_ERR_STATE;
  // This is a per-second control-loop operation, not stream teardown. A busy
  // video worker must not park the UI/audio control loop for ten seconds.
  // Abandon before execution with the existing lifetime-safe handshake; the
  // host retries the latest budget. Work that already started is waited out.
  (void)veil_media::run_on_with_timeout(ws->video_worker_tq.get(), [&]() {
    if (ws->video_send_stream == nullptr) return;
    // The explicit debug pin wins. Low rates are a sender policy; capture
    // remains live and every route/relay sees the same opaque media bytes.
    int kbps = max_bitrate_kbps > 0 ? max_bitrate_kbps : 150;
    if (const char* e = std::getenv("VEIL_MEDIA_VIDEO_KBPS")) {
      int v = std::atoi(e);
      if (v > 0) kbps = v;
    }
    kbps = std::clamp(kbps, minimum_kbps, 2500);
    const double fps = std::clamp(max_fps, 0.02, 60.0);
    const int bps = kbps * 1000;
    ws->video_frame_budget->SetProfile(bps);
    if (bps == ws->video_target_bitrate_bps &&
        fps == ws->video_max_fps.load(std::memory_order_relaxed)) {
      rc = VEIL_MEDIA_OK;
      return;
    }
    auto ec = veil_media::vp8_encoder_config();
    ec.max_bitrate_bps = bps;
    webrtc::VideoStream layer;
    layer.active = true;
    layer.min_bitrate_bps = std::min(30000, bps);
    layer.target_bitrate_bps = std::max(layer.min_bitrate_bps, bps * 2 / 3);
    layer.max_bitrate_bps = bps;
    layer.max_framerate = static_cast<int>(std::ceil(fps));
    layer.max_qp = 63;
    ec.simulcast_layers.push_back(layer);
    ws->video_send_stream->ReconfigureVideoEncoder(std::move(ec));
    // Update bounds without resetting GCC's current estimate on a profile
    // change. The legacy no-feedback mode still tracks the whole profile.
    {
      const bool independent_feedback = ws->shim->independent_transport_feedback();
      ws->video_call->SetClientBitratePreferences(
          veil_media::video_bitrate_settings(bps, independent_feedback,
                                            !independent_feedback));
    }
    ws->video_target_bitrate_bps = bps;
    ws->video_max_fps.store(fps, std::memory_order_relaxed);
    ws->video_last_encoded_frame_us.store(0, std::memory_order_relaxed);
    vlog("video: retuned to %d kbps @ %.3f fps", kbps, fps);
    rc = VEIL_MEDIA_OK;
  }, std::chrono::milliseconds(20));
  return rc;
#else
  (void)max_bitrate_kbps;
  (void)max_fps;
  (void)minimum_kbps;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_set_video_send_paused(VeilMediaEngine* engine, int paused) {
  if (!engine || (paused != 0 && paused != 1)) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws) return VEIL_MEDIA_ERR_STATE;
  WebrtcState* ws = engine->ws.get();
  if (paused) {
    ws->video_send_paused.store(true);
    ws->shim->SetVideoSendPaused(true);
    return VEIL_MEDIA_OK;
  }
  if (!ws->video_send_paused.load()) return VEIL_MEDIA_OK;
  const bool scheduled = veil_media::run_on_with_timeout(ws->video_worker_tq.get(), [&] {
    if (ws->video_send_stream) ws->video_send_stream->GenerateKeyFrame({});
    ws->video_last_encoded_frame_us.store(0, std::memory_order_relaxed);
    ws->shim->SetVideoSendPaused(false);
    ws->video_send_paused.store(false);
  }, std::chrono::milliseconds(20));
  return scheduled ? VEIL_MEDIA_OK : VEIL_MEDIA_ERR_STATE;
#else
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_set_video_budget(VeilMediaEngine* engine,
    int max_bitrate_kbps, double max_fps) {
  return veil_media_engine_apply_video_budget(engine, max_bitrate_kbps, max_fps, 1);
}

int veil_media_engine_set_video_bitrate(VeilMediaEngine* engine,
                                        int max_bitrate_kbps, int max_fps) {
  // Preserve integer ABI defaults for older callers.
  return veil_media_engine_apply_video_budget(engine,
      std::clamp(max_bitrate_kbps > 0 ? max_bitrate_kbps : 150, 30, 2500),
      std::clamp(max_fps > 0 ? max_fps : 15, 1, 60), 30);
}

int veil_media_engine_stop_video(VeilMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws) return VEIL_MEDIA_OK;
  WebrtcState* ws = engine->ws.get();
  // Stop the sources first so no OnFrame races the stream teardown.
  if (ws->camera) {
    ws->camera->Stop();
    ws->camera.reset();
  }
  if (ws->screen) {
    ws->screen->Stop();
    ws->screen.reset();
  }
  if (ws->test_video_run.exchange(false) && ws->test_video_thread.joinable())
    ws->test_video_thread.join();
  if (ws->video_call) {
    if (!run_on(ws->video_worker_tq.get(), [&]() {
          if (ws->video_send_stream) {
            ws->video_send_stream->Stop();
            ws->video_call->DestroyVideoSendStream(ws->video_send_stream);
            ws->video_send_stream = nullptr;
          }
          if (ws->video_recv_stream) {
            ws->video_recv_stream->Stop();
            ws->video_call->DestroyVideoReceiveStream(ws->video_recv_stream);
            ws->video_recv_stream = nullptr;
          }
        })) {
      // Routing stays as it is on purpose: the receive stream is still in the
      // Call, and cutting its SSRC would leave it alive and starved rather
      // than gone.
      vlog("video: stop INCOMPLETE — worker queue did not schedule; "
           "the streams are still live");
      return VEIL_MEDIA_ERR_STATE;
    }
  }
  if (ws->shim) ws->shim->SetRemoteVideoSsrc(0);
  ws->audio_packet_priority->ExpectVideo(false, webrtc::TimeMicros());
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_start_camera(VeilMediaEngine* engine, int width,
                                   int height, int fps) {
  return veil_media_engine_start_camera_device(engine, nullptr, width, height,
                                               fps);
}

int veil_media_engine_start_camera_device(VeilMediaEngine* engine,
                                          const char* device_id, int width,
                                          int height, int fps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && \
    (defined(__APPLE__) || (defined(__linux__) && !defined(__ANDROID__)) || \
     defined(_WIN32))
  WebrtcState* ws = engine->ws.get();
  if (!ws || !ws->video_source) return VEIL_MEDIA_ERR_STATE;
  // EXISTENCE IS NOT CAPTURE. The capturer's loop ends on its own when the
  // device goes away, and the object stays behind holding nothing. Answering
  // OK on the pointer alone meant a camera that had died could never be
  // started again for the rest of the call: every retry reported success and
  // no frame ever came. Measured on a Windows 11 ARM64 stand 2026-09-05 —
  // disabling the camera mid-capture returns
  // MF_E_VIDEO_RECORDING_DEVICE_INVALIDATED (0xc00d3ea2) from the pending
  // synchronous read in 292 ms, so this is the ordinary unplug (report19
  // V19-M6).
  if (ws->camera && ws->camera->Capturing()) return VEIL_MEDIA_OK;
  if (ws->camera) {
    ws->camera->Stop();
    ws->camera.reset();
  }
  if (width <= 0) width = 352;
  if (height <= 0) height = 288;
  if (fps <= 0) fps = 15;
  // Feed each captured I420 frame straight into the VP8 send source. The
  // callback runs on the capture queue; push_i420 copies synchronously.
  veil_media::AdaptiveVideoSource* src = ws->video_source.get();
  VeilVideoSink* local_sink = ws->local_video_sink.get();
  ws->camera.reset(veil_media::CreatePlatformCamera(
      [ws, src, local_sink](const uint8_t* y, const uint8_t* u,
                            const uint8_t* v, int w, int h, int sy, int su,
                            int sv, int64_t ts_us) {
        if (local_sink)
          local_sink->store_i420(y, u, v, w, h, sy, su, sv);
        if (should_encode_video_frame(ws))
          push_i420(src, y, u, v, w, h, sy, su, sv, ts_us);
      }));
  if (!ws->camera) return VEIL_MEDIA_ERR_STATE;
  if (!ws->camera->Start(width, height, fps, device_id)) {
    ws->camera.reset();
    return VEIL_MEDIA_ERR_STATE;
  }
  vlog("camera: started %dx%d@%d", width, height, fps);
  return VEIL_MEDIA_OK;
#else
  (void)width;
  (void)height;
  (void)fps;
  (void)device_id;
  return VEIL_MEDIA_ERR_STATE;  // no camera backend on this platform yet
#endif
}

int veil_media_engine_stop_camera(VeilMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->camera) {
    engine->ws->camera->Stop();
    engine->ws->camera.reset();
  }
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_start_screen_source(VeilMediaEngine* engine,
                                          const char* source_id, int width,
                                          int fps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && (defined(__APPLE__) || defined(_WIN32))
  WebrtcState* ws = engine->ws.get();
  if (!ws || !ws->video_source) return VEIL_MEDIA_ERR_STATE;
  if (ws->screen) return VEIL_MEDIA_OK;  // already sharing
  if (width <= 0) width = 640;
  if (fps <= 0) fps = 10;
  // One source at a time: the screen replaces the camera on the SAME VP8 send
  // source (interleaved frames from two sources would fight over the encoder).
  // The app layer restores the camera when the share ends.
  if (ws->camera) {
    ws->camera->Stop();
    ws->camera.reset();
  }
  veil_media::AdaptiveVideoSource* src = ws->video_source.get();
  VeilVideoSink* local_sink = ws->local_video_sink.get();
  ws->screen.reset(veil_media::CreatePlatformScreen(
      [ws, src, local_sink](const uint8_t* y, const uint8_t* u,
                            const uint8_t* v, int w, int h, int sy, int su,
                            int sv, int64_t ts_us) {
        if (local_sink)
          local_sink->store_i420(y, u, v, w, h, sy, su, sv);
        if (should_encode_video_frame(ws))
          push_i420(src, y, u, v, w, h, sy, su, sv, ts_us);
      },
      source_id));
  if (!ws->screen) return VEIL_MEDIA_ERR_STATE;
  if (!ws->screen->Start(width, fps)) {
    ws->screen.reset();
    return VEIL_MEDIA_ERR_STATE;
  }
  vlog("screen: started w<=%d@%d", width, fps);
  return VEIL_MEDIA_OK;
#else
  (void)source_id;
  (void)width;
  (void)fps;
  return VEIL_MEDIA_ERR_STATE;  // no screen backend on this platform yet
#endif
}

int veil_media_engine_start_screen(VeilMediaEngine* engine, int width,
                                   int fps) {
  return veil_media_engine_start_screen_source(engine, nullptr, width, fps);
}

int veil_media_engine_stop_screen(VeilMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->screen) {
    engine->ws->screen->Stop();
    engine->ws->screen.reset();
    vlog("screen: stopped");
  }
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_push_video_frame(VeilMediaEngine* engine,
                                       const uint8_t* y, const uint8_t* u,
                                       const uint8_t* v, int width, int height,
                                       int stride_y, int stride_u, int stride_v,
                                       int64_t ts_us) {
  if (engine == nullptr || y == nullptr || u == nullptr || v == nullptr)
    return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->video_source) return VEIL_MEDIA_ERR_STATE;
  if (engine->ws->local_video_sink)
    engine->ws->local_video_sink->store_i420(y, u, v, width, height, stride_y,
                                             stride_u, stride_v);
  if (!should_encode_video_frame(engine->ws.get())) return VEIL_MEDIA_OK;
  push_i420(engine->ws->video_source.get(), y, u, v, width, height, stride_y,
            stride_u, stride_v, ts_us);
  return VEIL_MEDIA_OK;
#else
  (void)width; (void)height; (void)stride_y; (void)stride_u; (void)stride_v;
  (void)ts_us;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_push_android420_frame(
    VeilMediaEngine* engine, const uint8_t* y, const uint8_t* u,
    const uint8_t* v, int width, int height, int stride_y, int stride_u,
    int stride_v, int pixel_stride_uv, int rotation, int64_t ts_us) {
  if (engine == nullptr || y == nullptr || u == nullptr || v == nullptr ||
      width <= 0 || height <= 0 || stride_y <= 0 || stride_u <= 0 ||
      stride_v <= 0 || pixel_stride_uv <= 0 ||
      (rotation != 0 && rotation != 90 && rotation != 180 && rotation != 270))
    return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->video_source) return VEIL_MEDIA_ERR_STATE;
  WebrtcState* ws = engine->ws.get();
#if defined(__ANDROID__)
  if (!ws->android420_dispatcher) return VEIL_MEDIA_ERR_STATE;
  if (!should_encode_video_frame(ws)) return VEIL_MEDIA_OK;
  return ws->android420_dispatcher->Submit(
             ws->video_source.get(), y, u, v, width, height, stride_y,
             stride_u, stride_v, pixel_stride_uv, rotation, ts_us)
             ? VEIL_MEDIA_OK
             : VEIL_MEDIA_ERR_STATE;
#else
  if (!should_encode_video_frame(ws)) return VEIL_MEDIA_OK;
  const bool swap = rotation == 90 || rotation == 270;
  const int out_width = swap ? height : width;
  const int out_height = swap ? width : height;
  auto buf = webrtc::I420Buffer::Create(out_width, out_height);
  int rc = libyuv::Android420ToI420Rotate(
      y, stride_y, u, stride_u, v, stride_v, pixel_stride_uv,
      buf->MutableDataY(), buf->StrideY(), buf->MutableDataU(), buf->StrideU(),
      buf->MutableDataV(), buf->StrideV(), width, height,
      static_cast<libyuv::RotationMode>(rotation));
  // Flutter's Camera2 channel serializes the U and V planes independently.
  // For semi-planar Android420 their original +/-1 pointer relationship is
  // therefore lost, and libyuv cannot combine de-interleaving with a non-zero
  // rotation in one call. Keep both operations native: normalize to I420 first,
  // then rotate the tightly packed planes with SIMD instead of falling back to
  // Dart's per-pixel loop.
  if (rc != 0 && rotation != 0) {
    auto unrotated = webrtc::I420Buffer::Create(width, height);
    rc = libyuv::Android420ToI420Rotate(
        y, stride_y, u, stride_u, v, stride_v, pixel_stride_uv,
        unrotated->MutableDataY(), unrotated->StrideY(),
        unrotated->MutableDataU(), unrotated->StrideU(),
        unrotated->MutableDataV(), unrotated->StrideV(), width, height,
        libyuv::kRotate0);
    if (rc == 0) {
      rc = libyuv::I420Rotate(
          unrotated->DataY(), unrotated->StrideY(), unrotated->DataU(),
          unrotated->StrideU(), unrotated->DataV(), unrotated->StrideV(),
          buf->MutableDataY(), buf->StrideY(), buf->MutableDataU(),
          buf->StrideU(), buf->MutableDataV(), buf->StrideV(), width, height,
          static_cast<libyuv::RotationMode>(rotation));
    }
  }
  if (rc != 0) return VEIL_MEDIA_ERR_ARG;
  broadcast_i420(ws->video_source.get(), buf, ts_us);
  return VEIL_MEDIA_OK;
#endif
#else
  (void)width; (void)height; (void)stride_y; (void)stride_u; (void)stride_v;
  (void)pixel_stride_uv; (void)rotation; (void)ts_us;
  return VEIL_MEDIA_ERR_STATE;
#endif
}

int veil_media_engine_get_video_frame(VeilMediaEngine* engine, uint8_t* dst,
                                      int dst_cap, int* out_w, int* out_h) {
  if (engine == nullptr) return 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->video_sink)
    return engine->ws->video_sink->get_frame(dst, dst_cap, out_w, out_h);
#else
  (void)dst;
  (void)dst_cap;
  (void)out_w;
  (void)out_h;
#endif
  return 0;
}

int veil_media_engine_get_local_video_frame(VeilMediaEngine* engine,
                                            uint8_t* dst, int dst_cap,
                                            int* out_w, int* out_h) {
  if (engine == nullptr) return 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->local_video_sink)
    return engine->ws->local_video_sink->get_frame(dst, dst_cap, out_w, out_h);
#else
  (void)dst;
  (void)dst_cap;
  (void)out_w;
  (void)out_h;
#endif
  return 0;
}

int veil_media_engine_set_mic_muted(VeilMediaEngine* engine, int muted) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  engine->mic_muted = muted != 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws) {
    WebrtcState* ws = engine->ws.get();
    if (engine->mic_muted && engine->audio_running.load() && ws->adm) {
      run_on_adm_thread([&] {
        if (ws->adm->Recording()) ws->adm->StopRecording();
      });
    }
    const bool configured = run_on(ws->worker_tq.get(), [&] {
      if (ws->send_stream) ws->send_stream->SetMuted(engine->mic_muted);
      if (ws->audio_state && ws->adm)
        ws->audio_state->SetRecording(!engine->mic_muted);
    });
    if (!engine->mic_muted) {
      if (!configured) return VEIL_MEDIA_ERR_STATE;
      bool needs_start = false;
      if (engine->audio_running.load() && ws->adm) {
        run_on_adm_thread([&] { needs_start = !ws->adm->Recording(); });
      }
      if (needs_start && !start_capture(ws->adm.get(), "mic unmute")) {
        return VEIL_MEDIA_ERR_DEVICE;
      }
    }
    if (!configured) return VEIL_MEDIA_ERR_STATE;
  }
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_set_speaker_muted(VeilMediaEngine* engine, int muted) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  engine->speaker_muted = muted != 0;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->recv_stream)
    engine->ws->recv_stream->SetGain(engine->speaker_muted ? 0.f : 1.f);
#endif
  return VEIL_MEDIA_OK;
}

#if defined(VEIL_MEDIA_HAVE_WEBRTC)
namespace {
// JSON [{"id","label","kind"}] from the ADM. `recording` = inputs.
// Enumerating is an ADM call like any other, and on Windows the module is
// bound to the thread that created it: asked from anywhere else,
// PlayoutDeviceName answers an error, every device is skipped, and the caller
// gets an empty list. That is what an empty output picker looked like —
// "Audio has no output" — while `playDevs=4` sat in the same log.
char* adm_devices_json(webrtc::AudioDeviceModule* adm, bool recording) {
  std::string out = "[";
  if (adm) {
    run_on_adm_thread([&] {
    const int16_t n = recording ? adm->RecordingDevices() : adm->PlayoutDevices();
    for (int16_t i = 0; i < n; ++i) {
      char name[webrtc::kAdmMaxDeviceNameSize] = {0};
      char guid[webrtc::kAdmMaxGuidSize] = {0};
      const int32_t rc = recording ? adm->RecordingDeviceName(i, name, guid)
                                   : adm->PlayoutDeviceName(i, name, guid);
      if (rc != 0) continue;
      if (out.size() > 1) out += ",";
      out += "{\"id\":\"";
      out += std::to_string(i);
      out += "\",\"label\":\"";
      for (const char* p = name; *p; ++p) {  // minimal JSON string escaping
        if (*p == '"' || *p == '\\') out += '\\';
        out += *p;
      }
      out += "\",\"kind\":\"";
      out += recording ? "input" : "output";
      out += "\"}";
    }
    });
  }
  out += "]";
  return dup_cstr(out);
}
}  // namespace
#endif

char* veil_media_engine_list_audio_inputs(VeilMediaEngine* engine) {
  if (engine == nullptr) return nullptr;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return adm_devices_json(engine->ws ? engine->ws->adm.get() : nullptr, true);
#else
  return dup_cstr("[]");
#endif
}

char* veil_media_engine_list_audio_outputs(VeilMediaEngine* engine) {
  if (engine == nullptr) return nullptr;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  return adm_devices_json(engine->ws ? engine->ws->adm.get() : nullptr, false);
#else
  return dup_cstr("[]");
#endif
}

char* veil_media_engine_list_video_inputs(VeilMediaEngine* engine) {
  if (engine == nullptr) return nullptr;
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && \
    (defined(__APPLE__) || (defined(__linux__) && !defined(__ANDROID__)) || \
     defined(_WIN32))
  return dup_cstr(veil_media::ListPlatformCamerasJson());
#else
  return dup_cstr("[]");
#endif
}

char* veil_media_list_screen_inputs(void) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && (defined(__APPLE__) || defined(_WIN32))
  return dup_cstr(veil_media::ListPlatformScreensJson());
#else
  return dup_cstr("[]");
#endif
}

int veil_media_screen_capture_access(void) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && (defined(__APPLE__) || defined(_WIN32))
  return veil_media::PlatformScreenAccessGranted() ? 1 : 0;
#else
  return -1;
#endif
}

int veil_media_request_screen_capture_access(void) {
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && (defined(__APPLE__) || defined(_WIN32))
  return veil_media::RequestPlatformScreenAccess() ? 1 : 0;
#else
  return -1;
#endif
}

int veil_media_engine_select_audio_input(VeilMediaEngine* engine,
                                         const char* id) {
  if (engine == nullptr || id == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->adm) return VEIL_MEDIA_ERR_DEVICE;
  const uint16_t idx = static_cast<uint16_t>(std::atoi(id));
  // Stop -> switch -> restart so the change takes effect mid-call.
  webrtc::AudioDeviceModule* adm = engine->ws->adm.get();
  bool ok = true;
  run_on_adm_thread([&] {
    const bool was_recording = adm->Recording();
    adm->StopRecording();
    if (adm->SetRecordingDevice(idx) != 0) {
      ok = false;
      return;
    }
    // Remembered, so the next start does not undo it.
    g_chosen_recording = idx;
    adm->InitRecording();
    if (was_recording) adm->StartRecording();
  });
  if (!ok) return VEIL_MEDIA_ERR_DEVICE;
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_select_audio_output(VeilMediaEngine* engine,
                                          const char* id) {
  if (engine == nullptr || id == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->adm) return VEIL_MEDIA_ERR_DEVICE;
  const uint16_t idx = static_cast<uint16_t>(std::atoi(id));
  webrtc::AudioDeviceModule* adm = engine->ws->adm.get();
  bool ok = true;
  run_on_adm_thread([&] {
    const bool was_playing = adm->Playing();
    adm->StopPlayout();
    if (adm->SetPlayoutDevice(idx) != 0) {
      ok = false;
      return;
    }
    g_chosen_playout = idx;
    adm->InitPlayout();
    if (was_playing) adm->StartPlayout();
  });
  if (!ok) return VEIL_MEDIA_ERR_DEVICE;
#endif
  return VEIL_MEDIA_OK;
}

char* veil_media_engine_get_stats(VeilMediaEngine* engine) {
  if (engine == nullptr) return nullptr;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  WebrtcState* ws = engine->ws.get();
  if (ws && ws->shim) {
    // RTCP-derived link quality. Call and its streams may only be touched on
    // the worker queue (stream create/destroy runs there too, so the raw
    // pointers stay valid for the duration of the task). The shim counters
    // below are atomics and safe from this FFI thread.
    int64_t rtt_ms = -1;
    uint32_t jitter_ms = 0;
    int loss_pct = 0;
    int tx_jitter_ms = 0;
    int tx_loss_pct = 0;
    // Perceived-latency creep instrumentation: RTCP rtt/jitter stay flat while
    // delay accumulates in the RECEIVE pipeline, so export the direct playout
    // measurements — current queued audio samples + ADM playout delay and the
    // video render delay target. Keep the RTP-span filter as a diagnostic.
    uint64_t audio_rx_pkts = 0;
    int64_t audio_rx_native_age_ms = -1;
    uint64_t audio_concealed_samples = 0;
    uint64_t audio_silent_concealed_samples = 0;
    uint64_t audio_output_emitted_samples = 0;
    uint64_t audio_total_samples_received = 0;
    uint64_t audio_output_duration_ms = 0;
    uint64_t audio_concealment_events = 0;
    uint64_t audio_jb_flushes = 0;
    uint64_t audio_discarded_packets = 0;
    veil_media::AudioRecoverySample receiver_recovery;
    int audio_interruption_count = 0;
    int audio_interruption_duration_ms = 0;
    uint64_t audio_tx_pkts = 0;
    uint64_t audio_tx_retransmitted_pkts = 0;
    int64_t audio_encoder_target_bps = 0;
    int audio_send_bandwidth_bps = 0;
    uint32_t audio_delay_ms = 0;
    int audio_rtp_lag_ms = -1, audio_pressure_delay_ms = -1;
    uint32_t audio_filtered_delay_ms = 0;
    uint32_t audio_jb_ms = 0;
    uint32_t audio_jb_target_ms = 0;
    int video_delay_ms = 0;
    int video_encoder_target_bps = 0;
    int video_jb_ms = 0;
    // Sender-side standing queue: RTCP bypasses the pacer, so a video RTP
    // packet can wait SECONDS in the pacer while rtt_ms stays flat — the
    // exact signature of the live "2-3 s stable lag, all metrics clean"
    // report. Export it so the creep is attributable.
    int64_t pacer_delay_ms = 0;
#if defined(VEIL_MEDIA_CC_TRACE)
    int64_t video_cc_stats_at_us = -1;
#endif
    int64_t android420_convert_max_ns = 0;
    int64_t android420_broadcast_max_ns = 0;
    uint64_t android420_convert_holds_16ms = 0;
    uint64_t android420_convert_holds_33ms = 0;
    uint64_t android420_broadcast_holds_16ms = 0;
    uint64_t android420_broadcast_holds_33ms = 0;
    uint64_t android420_submitted = 0;
    uint64_t android420_processed = 0;
    uint64_t android420_replaced = 0;
#if defined(__ANDROID__)
    android420_convert_max_ns =
        ws->android420_stats.convert_max_ns.load(std::memory_order_relaxed);
    android420_broadcast_max_ns =
        ws->android420_stats.broadcast_max_ns.load(std::memory_order_relaxed);
    android420_convert_holds_16ms =
        ws->android420_stats.convert_holds_16ms.load(std::memory_order_relaxed);
    android420_convert_holds_33ms =
        ws->android420_stats.convert_holds_33ms.load(std::memory_order_relaxed);
    android420_broadcast_holds_16ms =
        ws->android420_stats.broadcast_holds_16ms.load(std::memory_order_relaxed);
    android420_broadcast_holds_33ms =
        ws->android420_stats.broadcast_holds_33ms.load(std::memory_order_relaxed);
    android420_submitted =
        ws->android420_stats.submitted.load(std::memory_order_relaxed);
    android420_processed =
        ws->android420_stats.processed.load(std::memory_order_relaxed);
    android420_replaced =
        ws->android420_stats.replaced.load(std::memory_order_relaxed);
#endif
    const uint64_t recovery_sequence = ws->recovery_sample_sequence.fetch_add(1) + 1;
    const int64_t recovery_sampled_us = webrtc::TimeMicros();
    const bool sampled = veil_media::run_on_with_timeout(ws->worker_tq.get(), [&] {
      apply_audio_route(engine);
      if (ws->send_stream) {
        const auto sent = ws->send_stream->GetStats();
        audio_tx_pkts = sent.packets_sent;
        audio_tx_retransmitted_pkts = sent.retransmitted_packets_sent;
        audio_encoder_target_bps = sent.target_bitrate_bps;
      }
      if (ws->call) {
        const auto cs = ws->call->GetStats();
        audio_send_bandwidth_bps = cs.send_bandwidth_bps;
        if (cs.rtt_ms >= 0) rtt_ms = cs.rtt_ms;
        pacer_delay_ms = cs.pacer_delay_ms;
      }
      if (ws->recv_stream) {
        const auto r =
            ws->recv_stream->GetStats(/*get_and_clear_legacy_stats=*/false);
        audio_rx_pkts = r.packets_received;
        // WebRTC's last packet includes padding probes. They still advance
        // RTCP counters, but cannot prove that encoded audio is arriving.
        audio_rx_native_age_ms = ws->shim->audio_payload_receive_age_ms();
        const uint32_t remote_ssrc = ssrc_of(engine->peer);
        receiver_recovery = r.packets_received > 0 && audio_rx_native_age_ms >= 0 && audio_rx_native_age_ms <= 3000
                ? ws->recovery_stats->receivers.Snapshot(remote_ssrc)
                : veil_media::AudioRecoverySample{};
        ws->shim->SetLocalAudioRecovery(remote_ssrc, recovery_sequence,
                                       receiver_recovery, recovery_sampled_us);
        ws->shim->SetLocalAudioConcealment(remote_ssrc, recovery_sequence,
            receiver_recovery.known ? receiver_recovery.origin : 0,
            r.concealed_samples, r.silent_concealed_samples, recovery_sampled_us);
        audio_concealed_samples = r.concealed_samples;
        audio_silent_concealed_samples = r.silent_concealed_samples;
        // Lifetime sample counters distinguish delivery jitter from a slow
        // playout clock. They are endpoint diagnostics, never wire metadata.
        audio_output_emitted_samples = r.jitter_buffer_emitted_count;
        audio_total_samples_received = r.total_samples_received;
        audio_output_duration_ms = static_cast<uint64_t>(r.total_output_duration * 1000);
        audio_concealment_events = r.concealment_events;
        audio_jb_flushes = r.jitter_buffer_flushes;
        audio_discarded_packets = r.packets_discarded;
        audio_interruption_count = r.interruption_count;
        audio_interruption_duration_ms = r.total_interruption_duration_ms;
        jitter_ms = r.jitter_ms;
        audio_filtered_delay_ms = r.delay_estimate_ms;
        audio_delay_ms = current_audio_playout_delay(r.jitter_buffer_ms, ws->adm.get());
        audio_rtp_lag_ms = audio_rx_native_age_ms >= 0 && audio_rx_native_age_ms <= 3000
            ? ws->recovery_stats->receivers.LagMs(remote_ssrc, webrtc::TimeMicros()) : -1;
        audio_pressure_delay_ms = static_cast<int>(current_audio_playout_delay(
            std::max(r.jitter_buffer_ms, static_cast<uint32_t>(std::max(0, audio_rtp_lag_ms))),
            ws->adm.get()));
        audio_jb_ms = r.jitter_buffer_ms;
        // Diagnostic only: distinguish the controller's chosen buffer from
        // current packet accumulation and the filtered playout estimate.
        // Existing worker freshness and receive-packet checks still apply.
        audio_jb_target_ms = r.jitter_buffer_preferred_ms;
        // packets_lost is cumulative and may go negative on duplicates.
        if (r.packets_lost > 0) {
          const int64_t expected =
              int64_t(r.packets_received) + int64_t(r.packets_lost);
          if (expected > 0) {
            loss_pct =
                static_cast<int>(int64_t(r.packets_lost) * 100 / expected);
          }
        }
      }
    }, std::chrono::milliseconds(20));
    if (!sampled) {
      ws->shim->SetLocalAudioRecovery(ssrc_of(engine->peer), recovery_sequence, {}, recovery_sampled_us);
      ws->shim->SetLocalAudioConcealment(ssrc_of(engine->peer), recovery_sequence,
                                       0, 0, 0, recovery_sampled_us);
    }
    // A stalled video worker must not block audio telemetry or the UI's
    // control loop for the ten-second stream-operation timeout.
    const bool video_sampled = veil_media::run_on_with_timeout(
        ws->video_worker_tq.get(), [&] {
          apply_video_route(ws);
#if defined(VEIL_MEDIA_CC_TRACE)
          video_cc_stats_at_us = webrtc::TimeMicros();
#endif
          if (ws->video_call)
            pacer_delay_ms = ws->video_call->GetStats().pacer_delay_ms;
          if (ws->video_send_stream)
            video_encoder_target_bps = ws->video_send_stream->GetStats().target_media_bitrate_bps;
          if (ws->video_recv_stream) {
            const auto v = ws->video_recv_stream->GetStats();
            video_delay_ms = v.current_delay_ms;
            video_jb_ms = v.jitter_buffer_ms;
          }
        }, std::chrono::milliseconds(20));
    // Cached WebRTC stats have no report age. Only an authenticated peer's
    // fresh RR/SR block for our audio SSRC can drive outbound adaptation.
    // Call-level RTT remains diagnostic when no such block is available.
    const auto video_report = ws->shim->video_feedback();
    const bool video_feedback_available = video_report.fresh_at(webrtc::TimeMicros());
    const auto audio_report = ws->shim->audio_feedback();
    const bool audio_feedback_available = audio_report.fresh_at(webrtc::TimeMicros());
    if (audio_feedback_available) {
      rtt_ms = audio_report.rtt_ms;
      tx_loss_pct = audio_report.loss_pct;
      tx_jitter_ms = audio_report.jitter_ms;
    }
    if (rtt_ms < 0) rtt_ms = 0;  // unknown yet — keep the legacy "0" shape
    // Everything the closure above fills stays at its initialiser when the
    // worker queue never schedules, and a caller cannot tell a zero that was
    // measured from a zero that was never asked for. This flag is that
    // difference; it is additive, so a reader that does not know it is
    // unaffected.
    if (!sampled)
      vlog("stats: worker queue did not schedule; call/stream figures are "
           "defaults, not measurements");
    const auto tx_video = ws->shim->outbound_video_cadence();
    const auto tx_audio = ws->shim->audio_send_stats();
    const auto rx_video = ws->shim->inbound_video_cadence();
    const auto delivered_video = ws->shim->delivered_video_cadence();
    const auto cadence_fps = [](const veil_media::VideoCadenceSnapshot& c) {
      const int64_t elapsed = c.last_ns - c.first_ns;
      return c.frames > 1 && elapsed > 0
                 ? static_cast<double>(c.frames - 1) * 1000000000.0 /
                       static_cast<double>(elapsed)
                 : 0.0;
    };
    // Grown with the `worker_stalled` field below. `snprintf` truncates in
    // silence, and a truncated object is not a smaller answer — it is one the
    // Dart side cannot parse at all, so the return is checked below rather
    // than trusted.
    char json[4096];
    const int written = std::snprintf(
        json, sizeof(json),
        "{\"tx_pkts\":%llu,\"rx_pkts\":%llu,\"audio_rx_pkts\":%llu,"
        "\"audio_rx_native_age_ms\":%lld,\"audio_concealed_samples\":%llu,"
        "\"audio_mirror_enabled\":%d,\"audio_mirror_tx_attempts\":%llu,"
        "\"audio_mirror_tx_queued\":%llu,\"audio_rx_duplicate_packets\":%llu,"
        "\"audio_mirror_tx_bytes\":%llu,"
        "\"audio_concealment_events\":%llu,\"audio_interruption_count\":%d,"
        "\"audio_jb_flushes\":%llu,\"audio_discarded_packets\":%llu,"
        "\"audio_interruption_duration_ms\":%d,"
        "\"audio_tx_pkts\":%llu,\"mic_muted\":%d,\"tx_bytes\":%llu,"
        "\"audio_tx_rtp_attempts\":%llu,\"audio_tx_rtp_queued\":%llu,"
        "\"audio_tx_payload_pkts\":%llu,\"audio_tx_padding_pkts\":%llu,"
        "\"audio_tx_payload_bytes\":%llu,\"audio_tx_padding_bytes\":%llu,"
        "\"audio_tx_unclassified_pkts\":%llu,\"audio_tx_payload_age_ms\":%lld,"
        "\"audio_tx_payload_max_gap_ms\":%lld,\"audio_tx_retransmitted_pkts\":%llu,"
        "\"audio_encoder_target_bps\":%lld,\"audio_send_bandwidth_bps\":%d,"
        "\"audio_packet_adaptation\":%d,\"audio_packet_overhead_bytes\":%d,"
        "\"audio_tx_packet_duration_ms\":%d,"
        "\"rtcp_tx_pkts\":%llu,\"rtcp_tx_bytes\":%llu,"
        "\"video_rtcp_tx_pkts\":%llu,\"video_rtcp_tx_bytes\":%llu,"
        "\"audio_tx_rtp_age_ms\":%lld,\"audio_tx_rtp_queue_age_ms\":%lld,"
        "\"audio_tx_rtp_max_gap_ms\":%lld,\"audio_tx_rtp_admission_max_ms\":%lld,"
        "\"rx_bytes\":%llu,\"tx_drops\":%llu,\"rx_drops\":%llu,"
        "\"rtt_ms\":%lld,\"jitter_ms\":%u,\"loss_pct\":%d,"
        "\"tx_jitter_ms\":%d,\"tx_loss_pct\":%d,\"audio_feedback_reports\":%d,"
        "\"video_feedback_reports\":%d,\"video_feedback_rtt_ms\":%lld,"
        "\"video_feedback_loss_pct\":%d,\"video_feedback_jitter_ms\":%d,"
        "\"audio_delay_ms\":%u,\"audio_jb_ms\":%u,\"audio_jb_target_ms\":%u,"
        "\"audio_rtp_lag_ms\":%d,\"audio_pressure_delay_ms\":%d,"
        "\"audio_filtered_delay_ms\":%u,"
        "\"video_delay_ms\":%d,\"video_jb_ms\":%d,"
        "\"pacer_delay_ms\":%lld,\"worker_stalled\":%d,\"video_worker_stalled\":%d,"
        "\"video_tx_frames\":%llu,\"video_tx_fps\":%.1f,"
        "\"video_tx_max_gap_ms\":%lld,\"video_tx_holds_75ms\":%llu,"
        "\"video_rx_arrival_frames\":%llu,\"video_rx_arrival_fps\":%.1f,"
        "\"video_rx_arrival_max_gap_ms\":%lld,"
        "\"video_rx_arrival_holds_75ms\":%llu,"
        "\"video_rx_deliver_frames\":%llu,\"video_rx_deliver_fps\":%.1f,"
        "\"video_rx_deliver_max_gap_ms\":%lld,"
        "\"video_rx_deliver_holds_75ms\":%llu,"
        "\"android420_convert_max_ms\":%.3f,"
        "\"android420_convert_holds_16ms\":%llu,"
        "\"android420_convert_holds_33ms\":%llu,"
        "\"android420_broadcast_max_ms\":%.3f,"
        "\"android420_broadcast_holds_16ms\":%llu,"
        "\"android420_broadcast_holds_33ms\":%llu,"
        "\"android420_submitted\":%llu,"
        "\"android420_processed\":%llu,"
        "\"android420_replaced\":%llu,"
        "\"target_bitrate_bps\":%d,\"video_encoder_target_bps\":%d,\"max_fps\":%.3f}",
        static_cast<unsigned long long>(ws->shim->outbound_packet_count()),
        static_cast<unsigned long long>(ws->shim->inbound_packet_count()),
        static_cast<unsigned long long>(audio_rx_pkts),
        static_cast<long long>(audio_rx_native_age_ms),
        static_cast<unsigned long long>(audio_concealed_samples),
        ws->shim->audio_mirror_channel() != 0 ? 1 : 0,
        static_cast<unsigned long long>(ws->shim->audio_mirror_attempts()),
        static_cast<unsigned long long>(ws->shim->audio_mirror_queued()),
        static_cast<unsigned long long>(ws->shim->audio_duplicate_packets()),
        static_cast<unsigned long long>(ws->shim->audio_mirror_bytes()),
        static_cast<unsigned long long>(audio_concealment_events),
        audio_interruption_count,
        static_cast<unsigned long long>(audio_jb_flushes),
        static_cast<unsigned long long>(audio_discarded_packets),
        audio_interruption_duration_ms,
        static_cast<unsigned long long>(audio_tx_pkts), engine->mic_muted ? 1 : 0,
        static_cast<unsigned long long>(ws->shim->outbound_byte_count()),
        static_cast<unsigned long long>(tx_audio.attempts),
        static_cast<unsigned long long>(tx_audio.queued),
        static_cast<unsigned long long>(tx_audio.payload_packets),
        static_cast<unsigned long long>(tx_audio.padding_packets),
        static_cast<unsigned long long>(tx_audio.payload_bytes),
        static_cast<unsigned long long>(tx_audio.padding_bytes),
        static_cast<unsigned long long>(tx_audio.unclassified_packets),
        static_cast<long long>(tx_audio.payload_age_ms),
        static_cast<long long>(tx_audio.max_payload_gap_ms),
        static_cast<unsigned long long>(audio_tx_retransmitted_pkts),
        static_cast<long long>(audio_encoder_target_bps), audio_send_bandwidth_bps,
        engine->audio_packet_overhead.load() > 0 ? 1 : 0, engine->audio_packet_overhead.load(),
        ws->audio_packet_duration->load(std::memory_order_relaxed),
        static_cast<unsigned long long>(ws->shim->outbound_rtcp_packet_count()),
        static_cast<unsigned long long>(ws->shim->outbound_rtcp_byte_count()),
        static_cast<unsigned long long>(ws->shim->outbound_video_rtcp_packet_count()),
        static_cast<unsigned long long>(ws->shim->outbound_video_rtcp_byte_count()),
        static_cast<long long>(tx_audio.age_ms),
        static_cast<long long>(tx_audio.queue_age_ms),
        static_cast<long long>(tx_audio.max_gap_ms),
        static_cast<long long>(tx_audio.max_admission_ms),
        static_cast<unsigned long long>(ws->shim->inbound_byte_count()),
        static_cast<unsigned long long>(ws->shim->outbound_dropped_count()),
        static_cast<unsigned long long>(ws->shim->inbound_dropped_count()),
        static_cast<long long>(rtt_ms), jitter_ms, loss_pct, tx_jitter_ms,
        tx_loss_pct, audio_feedback_available ? 1 : 0,
        video_feedback_available ? 1 : 0,
        static_cast<long long>(video_feedback_available ? video_report.rtt_ms : 0),
        video_feedback_available ? video_report.loss_pct : 0,
        video_feedback_available ? video_report.jitter_ms : 0,
        audio_delay_ms, audio_jb_ms, audio_jb_target_ms,
        audio_rtp_lag_ms, audio_pressure_delay_ms, audio_filtered_delay_ms,
        video_delay_ms, video_jb_ms,
        static_cast<long long>(pacer_delay_ms), sampled ? 0 : 1, video_sampled ? 0 : 1,
        static_cast<unsigned long long>(tx_video.frames),
        cadence_fps(tx_video),
        static_cast<long long>(tx_video.max_gap_ns / 1000000),
        static_cast<unsigned long long>(tx_video.holds_75ms),
        static_cast<unsigned long long>(rx_video.frames),
        cadence_fps(rx_video),
        static_cast<long long>(rx_video.max_gap_ns / 1000000),
        static_cast<unsigned long long>(rx_video.holds_75ms),
        static_cast<unsigned long long>(delivered_video.frames),
        cadence_fps(delivered_video),
        static_cast<long long>(delivered_video.max_gap_ns / 1000000),
        static_cast<unsigned long long>(delivered_video.holds_75ms),
        static_cast<double>(android420_convert_max_ns) / 1000000.0,
        static_cast<unsigned long long>(android420_convert_holds_16ms),
        static_cast<unsigned long long>(android420_convert_holds_33ms),
        static_cast<double>(android420_broadcast_max_ns) / 1000000.0,
        static_cast<unsigned long long>(android420_broadcast_holds_16ms),
        static_cast<unsigned long long>(android420_broadcast_holds_33ms),
        static_cast<unsigned long long>(android420_submitted),
        static_cast<unsigned long long>(android420_processed),
        static_cast<unsigned long long>(android420_replaced),
        ws->video_target_bitrate_bps, video_encoder_target_bps,
        ws->video_max_fps.load(std::memory_order_relaxed));
    if (written < 0 || static_cast<size_t>(written) >= sizeof(json)) {
      vlog("stats: JSON did not fit in %zu bytes (needed %d) — returning the "
           "minimal shape rather than a truncated object",
           sizeof(json), written);
    } else {
      std::string snapshot(json, static_cast<size_t>(written) - 1);
      snapshot += ",\"media_route_generation\":" + std::to_string(ws->route_generation.load()) +
                  ",\"audio_bwe_route_generation\":" + std::to_string(ws->audio_route_applied.load()) +
                  ",\"video_bwe_route_generation\":" + std::to_string(ws->video_route_applied.load());

#if defined(VEIL_MEDIA_CC_TRACE)
      if (veil_media::video_cc_trace_enabled())
        snapshot += ",\"video_cc_stats_at_us\":" +
            std::to_string(video_cc_stats_at_us);
#endif
      const auto frame_budget = ws->video_frame_budget->snapshot();
      snapshot += ",\"video_frame_budget_bytes\":" + std::to_string(frame_budget.bytes) +
                  ",\"video_frame_pixel_cap\":" + std::to_string(frame_budget.max_pixels) +
                  ",\"video_frame_oversize_count\":" + std::to_string(frame_budget.oversize_frames) +
                  ",\"video_frame_encoded_pixels\":" + std::to_string(frame_budget.last_pixels) +
                  ",\"video_frame_encoded_bytes\":" + std::to_string(frame_budget.last_bytes);
      snapshot += ",\"audio_latency_recovery_count\":" +
          std::to_string(ws->recovery_stats->count.load(std::memory_order_acquire));
      snapshot += ",\"audio_latency_discarded_ms\":" +
          std::to_string(ws->recovery_stats->discarded_ms.load(std::memory_order_relaxed));
      snapshot += ",\"audio_latency_fallback_frames\":" +
          std::to_string(ws->recovery_stats->fallback_frames.load(std::memory_order_relaxed));
      // Counter identity and witness time must describe ONE cursor snapshot:
      // a report arriving between separate reads must not consume unseen loss
      // under the preceding report's already-consumed timestamp.
      const auto peer_recovery_snapshot = ws->shim->peer_audio_recovery_snapshot();
      const int64_t loss_now_us = webrtc::TimeMicros();
      snapshot += ",\"audio_peer_recovery_report_us\":" +
          std::to_string(peer_recovery_snapshot.FreshReportUs(loss_now_us));
      snapshot += ",\"audio_peer_recovery_peers\":" +
          std::to_string(peer_recovery_snapshot.supported() ? 1 : 0);
      snapshot += ",\"audio_peer_concealment_report_us\":" +
          std::to_string(ws->shim->peer_audio_concealment_report_us(loss_now_us));
      snapshot += ",\"audio_local_concealment_report_us\":" +
          std::to_string(sampled ? ws->shim->local_audio_concealment_report_us(loss_now_us) : 0);
      snapshot += ",\"audio_silent_concealed_samples\":" +
          std::to_string(audio_silent_concealed_samples);
      const auto local_soft_loss = sampled ? ws->shim->local_audio_soft_loss(loss_now_us)
          : veil_media::AudioSoftLossSnapshot{};
      const auto peer_soft_loss = ws->shim->peer_audio_soft_loss(loss_now_us);
      snapshot += ",\"audio_soft_loss_duration_supported\":1,\"audio_peer_soft_loss_duration_supported\":" +
          std::to_string(peer_soft_loss.supported ? 1 : 0) +
          ",\"audio_local_soft_loss_report_us\":" + std::to_string(local_soft_loss.report_us) +
          ",\"audio_peer_soft_loss_report_us\":" + std::to_string(peer_soft_loss.report_us) +
          ",\"audio_local_soft_loss_window_ms\":" + std::to_string(local_soft_loss.samples / 48.0) +
          ",\"audio_peer_soft_loss_window_ms\":" + std::to_string(peer_soft_loss.samples / 48.0);
      // Event identity shared by native RTCP and encrypted call-health feedback.
      // These are local JSON stats, not additional RTCP or relay header fields.
      const auto peer_recovery = peer_recovery_snapshot.Sample();
      if (peer_recovery.known) {
        snapshot += ",\"audio_peer_recovery_origin\":" + std::to_string(peer_recovery.origin);
        snapshot += ",\"audio_peer_recovery_discarded_ms\":" + std::to_string(peer_recovery.discarded_ms);
      }
      if (sampled && receiver_recovery.known) {
        snapshot += ",\"audio_receiver_recovery_origin\":" + std::to_string(receiver_recovery.origin);
        snapshot += ",\"audio_receiver_recovery_discarded_ms\":" + std::to_string(receiver_recovery.discarded_ms);
      }
      snapshot += ",\"audio_loss_report_us\":" +
          std::to_string(audio_report.fresh_loss_report_us(loss_now_us));
      snapshot += ",\"audio_rtt_route_epoch\":" + std::to_string(audio_report.route_epoch);
      snapshot += ",\"video_rtt_route_epoch\":" + std::to_string(video_report.route_epoch);
      snapshot += ",\"video_loss_report_us\":" +
          std::to_string(video_report.fresh_loss_report_us(loss_now_us));
      snapshot += ",\"video_persistent_loss_report_us\":" +
          std::to_string(video_report.fresh_persistent_loss_report_us(loss_now_us));
      snapshot += ",\"audio_output_emitted_samples\":" + std::to_string(audio_output_emitted_samples);
      snapshot += ",\"audio_total_samples_received\":" + std::to_string(audio_total_samples_received);
      snapshot += ",\"audio_output_duration_ms\":" + std::to_string(audio_output_duration_ms);
      snapshot += ",\"audio_tx_rtp_drops\":" + std::to_string(tx_audio.dropped);
      const auto video_send = ws->shim->video_send_stats();
      snapshot += ",\"video_packet_overhead_bytes\":" +
          std::to_string(ws->video_packet_overhead.load());
      snapshot += ",\"video_tx_rtp_attempts\":" + std::to_string(video_send.attempts);
      snapshot += ",\"video_tx_rtp_queued\":" + std::to_string(video_send.queued);
      snapshot += ",\"video_tx_payload_pkts\":" + std::to_string(video_send.payload_packets);
      snapshot += ",\"video_tx_padding_pkts\":" + std::to_string(video_send.padding_packets);
      snapshot += ",\"video_tx_payload_bytes\":" + std::to_string(video_send.payload_bytes);
      snapshot += ",\"video_tx_padding_bytes\":" + std::to_string(video_send.padding_bytes);
      snapshot += ",\"video_tx_unclassified_pkts\":" + std::to_string(video_send.unclassified_packets);
      snapshot += ",\"video_tx_rtp_admission_max_ms\":" + std::to_string(video_send.max_admission_ms);
      snapshot += ",\"video_tx_rtp_drops\":" + std::to_string(video_send.dropped);
      snapshot += ",\"audio_rx_foreign_remb_blocks\":" + std::to_string(ws->shim->foreign_remb_blocks(false));
      snapshot += ",\"video_rx_foreign_remb_blocks\":" + std::to_string(ws->shim->foreign_remb_blocks(true));
      snapshot += ",\"audio_packetization_video_hold\":" +
          std::to_string(ws->audio_packet_priority->VideoHeldForAudio() ? 1 : 0);
      snapshot += ",\"audio_packetization_long_requested\":" +
          std::to_string(ws->audio_packet_priority->WantsLongPackets() ? 1 : 0);
      snapshot += ",\"video_send_paused\":" +
          std::to_string(ws->video_send_paused.load() ||
                         ws->audio_packet_priority->VideoBlocked() ? 1 : 0) + "}";
      return dup_cstr(snapshot.c_str());
    }
  }
#endif
  return dup_cstr(
      "{\"tx_pkts\":0,\"rx_pkts\":0,\"tx_bytes\":0,\"rx_bytes\":0,"
      "\"tx_drops\":0,\"rx_drops\":0,\"rtt_ms\":0,\"jitter_ms\":0,"
      "\"loss_pct\":0,\"tx_jitter_ms\":0,\"tx_loss_pct\":0,\"audio_feedback_reports\":0,"
      "\"video_tx_frames\":0,\"video_rx_arrival_frames\":0,"
      "\"video_rx_deliver_frames\":0,"
      "\"target_bitrate_bps\":0,\"max_fps\":0}");
}

void veil_media_free_string(char* s) {
  if (s) std::free(s);
}

const char* veil_media_version(void) { return kVersion; }

}  // extern "C"

#if defined(__ANDROID__)
extern "C" JNIEXPORT jint JNICALL
Java_network_veil_xveil_NativeCallCamera_nativePushAndroid420(
    JNIEnv* env, jobject /* self */, jlong engine_address, jobject y_buffer,
    jobject u_buffer, jobject v_buffer, jint width, jint height, jint y_stride,
    jint u_stride, jint v_stride, jint uv_pixel_stride, jint rotation,
    jlong timestamp_us) {
  if (engine_address == 0 || y_buffer == nullptr || u_buffer == nullptr ||
      v_buffer == nullptr || width <= 0 || height <= 0 || y_stride <= 0 ||
      u_stride <= 0 || v_stride <= 0 || uv_pixel_stride <= 0) {
    return VEIL_MEDIA_ERR_ARG;
  }
  auto* y = static_cast<uint8_t*>(env->GetDirectBufferAddress(y_buffer));
  auto* u = static_cast<uint8_t*>(env->GetDirectBufferAddress(u_buffer));
  auto* v = static_cast<uint8_t*>(env->GetDirectBufferAddress(v_buffer));
  const jlong y_capacity = env->GetDirectBufferCapacity(y_buffer);
  const jlong u_capacity = env->GetDirectBufferCapacity(u_buffer);
  const jlong v_capacity = env->GetDirectBufferCapacity(v_buffer);
  const int chroma_width = (width + 1) / 2;
  const int chroma_height = (height + 1) / 2;
  const int64_t y_needed =
      static_cast<int64_t>(height - 1) * y_stride + width;
  const int64_t u_needed = static_cast<int64_t>(chroma_height - 1) * u_stride +
                           static_cast<int64_t>(chroma_width - 1) *
                               uv_pixel_stride +
                           1;
  const int64_t v_needed = static_cast<int64_t>(chroma_height - 1) * v_stride +
                           static_cast<int64_t>(chroma_width - 1) *
                               uv_pixel_stride +
                           1;
  if (y == nullptr || u == nullptr || v == nullptr || y_capacity < y_needed ||
      u_capacity < u_needed || v_capacity < v_needed) {
    return VEIL_MEDIA_ERR_ARG;
  }
  return veil_media_engine_push_android420_frame(
      reinterpret_cast<VeilMediaEngine*>(
          static_cast<uintptr_t>(engine_address)),
      y, u, v, width, height, y_stride, u_stride, v_stride, uv_pixel_stride,
      rotation, timestamp_us);
}

extern "C" JNIEXPORT jint JNICALL
Java_network_veil_xveil_NativeCallVideoRenderer_nativeAttachRemoteSurface(
    JNIEnv* env, jobject /* self */, jlong engine_address, jobject surface) {
  if (engine_address == 0 || surface == nullptr) return VEIL_MEDIA_ERR_ARG;
  auto* engine = reinterpret_cast<VeilMediaEngine*>(
      static_cast<uintptr_t>(engine_address));
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->video_sink) return VEIL_MEDIA_ERR_STATE;
  ANativeWindow* window = ANativeWindow_fromSurface(env, surface);
  if (window == nullptr) return VEIL_MEDIA_ERR_DEVICE;
  engine->ws->video_sink->set_native_window(window);
  return VEIL_MEDIA_OK;
#else
  return VEIL_MEDIA_ERR_STATE;
#endif
}

extern "C" JNIEXPORT jint JNICALL
Java_network_veil_xveil_NativeCallVideoRenderer_nativeDetachRemoteSurface(
    JNIEnv* /* env */, jobject /* self */, jlong engine_address) {
  if (engine_address == 0) return VEIL_MEDIA_ERR_ARG;
  auto* engine = reinterpret_cast<VeilMediaEngine*>(
      static_cast<uintptr_t>(engine_address));
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->video_sink) return VEIL_MEDIA_ERR_STATE;
  engine->ws->video_sink->set_native_window(nullptr);
  return VEIL_MEDIA_OK;
#else
  return VEIL_MEDIA_ERR_STATE;
#endif
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_network_veil_xveil_NativeCallVideoRenderer_nativeRemoteVideoStats(
    JNIEnv* env, jobject /* self */, jlong engine_address) {
  // Rendered cadence and decoded cadence are deliberately separate. If decode
  // stalls while Surface work stays cheap, the gap is upstream (transport /
  // jitter buffer). If decoded frames stay smooth but rendering stalls, the
  // bottleneck is local Surface backpressure/conversion. This avoids tuning
  // the wrong queue based on one blended counter.
  jlong values[15] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  if (engine_address != 0) {
    auto* engine = reinterpret_cast<VeilMediaEngine*>(
        static_cast<uintptr_t>(engine_address));
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
    if (engine->ws && engine->ws->video_sink) {
      int w = 0;
      int h = 0;
      uint64_t frames = 0;
      int64_t first_ns = 0;
      int64_t last_ns = 0;
      int64_t max_gap_ns = 0;
      uint64_t holds_75ms = 0;
      uint64_t decoded_frames = 0;
      int64_t decoded_first_ns = 0;
      int64_t decoded_last_ns = 0;
      int64_t decoded_max_gap_ns = 0;
      uint64_t decoded_holds_75ms = 0;
      int64_t max_render_work_ns = 0;
      uint64_t render_work_holds_16ms = 0;
      uint64_t render_work_holds_33ms = 0;
      engine->ws->video_sink->frame_stats(&w, &h, &frames, &first_ns,
                                           &last_ns, &max_gap_ns,
                                           &holds_75ms, &decoded_frames,
                                           &decoded_first_ns, &decoded_last_ns,
                                           &decoded_max_gap_ns,
                                           &decoded_holds_75ms,
                                           &max_render_work_ns,
                                           &render_work_holds_16ms,
                                           &render_work_holds_33ms);
      values[0] = static_cast<jlong>(frames);
      values[1] = static_cast<jlong>(w);
      values[2] = static_cast<jlong>(h);
      values[3] = static_cast<jlong>(first_ns);
      values[4] = static_cast<jlong>(last_ns);
      values[5] = static_cast<jlong>(max_gap_ns);
      values[6] = static_cast<jlong>(holds_75ms);
      values[7] = static_cast<jlong>(decoded_frames);
      values[8] = static_cast<jlong>(decoded_first_ns);
      values[9] = static_cast<jlong>(decoded_last_ns);
      values[10] = static_cast<jlong>(decoded_max_gap_ns);
      values[11] = static_cast<jlong>(decoded_holds_75ms);
      values[12] = static_cast<jlong>(max_render_work_ns);
      values[13] = static_cast<jlong>(render_work_holds_16ms);
      values[14] = static_cast<jlong>(render_work_holds_33ms);
    }
#endif
  }
  jlongArray result = env->NewLongArray(15);
  if (result != nullptr) env->SetLongArrayRegion(result, 0, 15, values);
  return result;
}
#endif

#if defined(VEIL_MEDIA_TEST_HOOKS) && defined(VEIL_MEDIA_HAVE_WEBRTC)
#include "audio/audio_send_stream.h"
#include "call/rtp_transport_controller_send_interface.h"
#include "rtc_base/network_route.h"
#include "../test/call_plane_hooks.inc"
#endif
