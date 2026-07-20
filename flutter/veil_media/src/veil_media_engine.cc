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

#include "veil_media_engine.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <TargetConditionals.h>
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
#include "api/environment/environment.h"
#include "api/environment/environment_factory.h"
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
#include "rtc_base/event.h"
#include "call/audio_receive_stream.h"
#include "call/audio_send_stream.h"
#include "call/audio_state.h"
#include "call/call.h"
#include "call/call_config.h"
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
#include "api/video/video_broadcaster.h"
#include "third_party/libyuv/include/libyuv/convert_argb.h"  // I420ToABGR
#include "third_party/libyuv/include/libyuv/rotate.h"  // Android420ToI420Rotate
#include "rtc_base/time_utils.h"  // webrtc::TimeMicros
#include "rtc_base/network/sent_packet.h"  // webrtc::SentPacketInfo

#if defined(__APPLE__)
#include "veil_avf_adm.h"
#elif defined(__ANDROID__)
#include "veil_aaudio_adm.h"
#endif
#include "veil_camera.h"
#include "veil_screen.h"
#include "veil_transport_shim.h"
#endif

extern "C" int veil_media_send_datagram(uint64_t chan, const uint8_t* ptr,
                                         size_t len);

namespace {

const char* kVersion = "veil_media 0.0.3 (group-video)";
constexpr int kOpusPayloadType = 111;  // SDP convention (Opus, 48k, stereo)
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
constexpr int kVideoNackHistoryMs = 1000;
// A 60-frame interval produced a full VP8 intra-frame burst every ~2 seconds
// on the 30-fps physical cameras. Those bursts repeatedly filled the short
// realtime QUIC window and showed up as 0.6--1.0 s freezes despite a steady
// average frame rate. NACK keeps ordinary packet loss recoverable, so request
// a periodic keyframe every 240 frames (~8 s at 30 fps) instead. This is still
// dramatically faster recovery than libwebrtc's 3000-frame default.
constexpr int kVp8KeyFrameIntervalFrames = 240;

webrtc::scoped_refptr<
    webrtc::VideoEncoderConfig::EncoderSpecificSettings>
resilient_vp8_settings() {
  webrtc::VideoCodecVP8 vp8 = webrtc::VideoEncoder::GetDefaultVp8Settings();
#if defined(__ANDROID__)
  // Camera2's TEMPLATE_RECORD pipeline already applies the sensor/ISP noise
  // reduction selected by the device. Running libvpx's temporal denoiser over
  // that 640x360 frame repeats the work in software and was a measurable part
  // of the phone's sustained call heat, without a visible benefit on the
  // physical front camera.
  vp8.denoisingOn = false;
#endif
  // The default is 3000 frames (50-100 seconds at call rates). A single lost
  // inter-frame then left the receiver frozen until that very distant keyframe.
  vp8.keyFrameInterval = kVp8KeyFrameIntervalFrames;
  return webrtc::make_ref_counted<
      webrtc::VideoEncoderConfig::Vp8EncoderSpecificSettings>(vp8);
}
#endif

// Diagnostic log to a file (a GUI app's stderr is not captured by the unified
// log). Best-effort; append.
void vlog(const char* fmt, ...) {
  FILE* f = fopen("/tmp/veil_media_diag.log", "a");
  if (!f) return;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(f, fmt, ap);
  va_end(ap);
  fputc('\n', f);
  fclose(f);
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
template <typename F>
void run_on(webrtc::TaskQueueBase* tq, F f) {
  if (tq == nullptr || tq->IsCurrent()) {
    f();
    return;
  }
  webrtc::Event done;
  tq->PostTask([&f, &done]() mutable {
    f();
    done.Set();
  });
  done.Wait(webrtc::TimeDelta::Seconds(10));
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
  explicit GroupFanoutTransport(webrtc::Call* call) : call_(call) {}

  void Add(uint64_t chan) {
    std::lock_guard<std::mutex> lock(mu_);
    if (std::find(channels_.begin(), channels_.end(), chan) == channels_.end())
      channels_.push_back(chan);
  }

  void Remove(uint64_t chan) {
    std::lock_guard<std::mutex> lock(mu_);
    channels_.erase(std::remove(channels_.begin(), channels_.end(), chan),
                    channels_.end());
  }

  bool SendRtp(std::span<const uint8_t> packet,
               const webrtc::PacketOptions& options) override {
    std::lock_guard<std::mutex> lock(mu_);
    bool any = false;
    for (const uint64_t chan : channels_) {
      any = veil_media_send_datagram(chan, packet.data(), packet.size()) == 0 ||
            any;
    }
    if (any && options.packet_id != -1) {
      call_->OnSentPacket(
          webrtc::SentPacketInfo(options.packet_id, webrtc::TimeMillis()));
    }
    return any;
  }

  bool SendRtcp(std::span<const uint8_t> packet,
                const webrtc::PacketOptions& options) override {
    (void)options;
    std::lock_guard<std::mutex> lock(mu_);
    bool any = false;
    for (const uint64_t chan : channels_) {
      any = veil_media_send_datagram(chan, packet.data(), packet.size()) == 0 ||
            any;
    }
    return any;
  }

 private:
  webrtc::Call* const call_;
  std::mutex mu_;
  std::vector<uint64_t> channels_;
};

// Sink for decoded remote video frames. Android can attach a native texture:
// OnFrame then retains only the latest I420 buffer and a dedicated worker
// coalesces/converts/posts it without blocking WebRTC's decode thread. Other
// platforms retain the RGBA pull path; Android diagnostics can still request
// one on-demand conversion. OnFrame runs on a WebRTC decode thread.
class VeilVideoSink : public webrtc::VideoSinkInterface<webrtc::VideoFrame> {
 public:
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
    if (w <= 0 || h <= 0) return;
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

void broadcast_i420(webrtc::VideoBroadcaster* source,
                    webrtc::scoped_refptr<webrtc::I420Buffer> buf,
                    int64_t ts_us) {
  if (source == nullptr || !buf) return;
  webrtc::VideoFrame frame = webrtc::VideoFrame::Builder()
                                 .set_video_frame_buffer(buf)
                                 .set_timestamp_us(ts_us ? ts_us
                                                         : webrtc::TimeMicros())
                                 .set_rotation(webrtc::kVideoRotation_0)
                                 .build();
  source->OnFrame(frame);
}

// Copy a (possibly strided) I420 frame into the broadcaster (encoder source).
void push_i420(webrtc::VideoBroadcaster* source, const uint8_t* y,
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

  bool Submit(webrtc::VideoBroadcaster* source, const uint8_t* y,
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
    webrtc::VideoBroadcaster* source = nullptr;
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
  webrtc::scoped_refptr<webrtc::AudioDeviceModule> adm;
  webrtc::scoped_refptr<webrtc::AudioProcessing> apm;
  webrtc::scoped_refptr<webrtc::AudioState> audio_state;
  std::unique_ptr<webrtc::Call> call;
  std::unique_ptr<veil_media::VeilTransportShim> shim;
  webrtc::AudioSendStream* send_stream = nullptr;             // owned by Call
  webrtc::AudioReceiveStreamInterface* recv_stream = nullptr;  // owned by Call
  // Video (Phase 4) — factories + source/sink outlive the streams.
  std::unique_ptr<webrtc::VideoEncoderFactory> video_encoder_factory;
  std::unique_ptr<webrtc::VideoDecoderFactory> video_decoder_factory;
  std::unique_ptr<webrtc::VideoBitrateAllocatorFactory> video_bitrate_alloc_factory;
  std::unique_ptr<webrtc::VideoBroadcaster> video_source;  // pushable
  std::unique_ptr<VeilVideoSink> video_sink;               // renderer
  std::unique_ptr<VeilVideoSink> local_video_sink;         // self-preview
  webrtc::VideoSendStream* video_send_stream = nullptr;              // owned by Call
  webrtc::VideoReceiveStreamInterface* video_recv_stream = nullptr;  // owned by Call
  std::thread test_video_thread;         // synthetic source (VEIL_MEDIA_TEST_VIDEO)
  std::atomic<bool> test_video_run{false};
  std::unique_ptr<veil_media::CameraCapturer> camera;  // real capture source
  std::unique_ptr<veil_media::ScreenCapturer> screen;  // screen-share source
  int video_target_bitrate_bps = 0;
  std::atomic<int> video_max_fps{0};
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

bool should_encode_video_frame(WebrtcState* ws) {
  if (ws == nullptr) return false;
  const int fps = ws->video_max_fps.load(std::memory_order_relaxed);
  if (fps <= 0) return true;
  const int64_t now_us = webrtc::TimeMicros();
  const int64_t min_interval_us = 1'000'000 / fps;
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
  webrtc::scoped_refptr<webrtc::AudioDeviceModule> adm;
  webrtc::scoped_refptr<webrtc::AudioProcessing> apm;
  webrtc::scoped_refptr<webrtc::AudioState> audio_state;
  std::unique_ptr<webrtc::Call> call;
  std::unique_ptr<GroupFanoutTransport> fanout;
  webrtc::AudioSendStream* send_stream = nullptr;  // owned by Call
  std::unique_ptr<webrtc::VideoEncoderFactory> video_encoder_factory;
  std::unique_ptr<webrtc::VideoDecoderFactory> video_decoder_factory;
  std::unique_ptr<webrtc::VideoBitrateAllocatorFactory>
      video_bitrate_alloc_factory;
  std::unique_ptr<webrtc::VideoBroadcaster> video_source;
  std::unique_ptr<VeilVideoSink> local_video_sink;
  webrtc::VideoSendStream* video_send_stream = nullptr;
  std::thread test_video_thread;
  std::atomic<bool> test_video_run{false};
  std::unique_ptr<veil_media::CameraCapturer> camera;
  std::unique_ptr<veil_media::ScreenCapturer> screen;
  std::map<std::string, std::unique_ptr<GroupPeerState>> peers;
};

constexpr int kGroupVp8PayloadType = 96;

// Real-time conversation should recover from a network spike by dropping late
// video, not by retaining an ever-growing playout tail. The app already pulls
// latest-only decoded frames, so cap WebRTC's adaptive video delay while still
// leaving enough room for ordinary relay jitter. This is receiver-local and
// therefore also protects calls from older peers that send no playout-delay
// RTP extension.
class LowLatencyFieldTrials final : public webrtc::FieldTrialsView {
 public:
  std::string Lookup(absl::string_view key) const override {
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
    return std::make_unique<LowLatencyFieldTrials>();
  }
};

webrtc::Environment create_low_latency_environment() {
  // The trimmed libwebrtc archive does not contain the concrete FieldTrials
  // parser implementation. Supplying the tiny immutable view directly keeps
  // all Environment defaults (clock/task queues/event log) and avoids leaving
  // an unresolved constructor for permissive Apple dynamic linking to turn
  // into a null call at engine creation.
  return webrtc::CreateEnvironment(
      std::make_unique<LowLatencyFieldTrials>());
}

void ensure_group_video_codecs(GroupWebrtcState* ws) {
  if (!ws->video_encoder_factory)
    ws->video_encoder_factory =
        std::make_unique<webrtc::VideoEncoderFactoryTemplate<
            webrtc::LibvpxVp8EncoderTemplateAdapter>>();
  if (!ws->video_decoder_factory)
    ws->video_decoder_factory =
        std::make_unique<webrtc::VideoDecoderFactoryTemplate<
            webrtc::LibvpxVp8DecoderTemplateAdapter>>();
  if (!ws->video_bitrate_alloc_factory)
    ws->video_bitrate_alloc_factory =
        webrtc::CreateBuiltinVideoBitrateAllocatorFactory();
  if (!ws->video_source)
    ws->video_source = std::make_unique<webrtc::VideoBroadcaster>();
  if (!ws->local_video_sink)
    ws->local_video_sink = std::make_unique<VeilVideoSink>();
}

bool start_group_peer_video(GroupWebrtcState* ws, GroupPeerState* peer) {
  if (peer->video_recv_stream) return true;
  if (!ws->video_decoder_factory || !peer->video_sink) return false;
  webrtc::VideoReceiveStreamInterface::Config rc(
      peer->shim.get(), ws->video_decoder_factory.get());
  rc.rtp.remote_ssrc = peer->video_ssrc;
  rc.rtp.nack.rtp_history_ms = kVideoNackHistoryMs;
  rc.renderer = peer->video_sink.get();
  rc.decoders.emplace_back(webrtc::SdpVideoFormat::VP8(),
                           kGroupVp8PayloadType);
  peer->video_recv_stream = ws->call->CreateVideoReceiveStream(std::move(rc));
  if (!peer->video_recv_stream) return false;
  peer->video_recv_stream->Start();
  peer->shim->SetRemoteVideoSsrc(peer->video_ssrc);
  return true;
}

void stop_group_peer_video(GroupWebrtcState* ws, GroupPeerState* peer) {
  peer->shim->SetRemoteVideoSsrc(0);
  if (!peer->video_recv_stream) return;
  peer->video_recv_stream->Stop();
  ws->call->DestroyVideoReceiveStream(peer->video_recv_stream);
  peer->video_recv_stream = nullptr;
}
#endif

}  // namespace

struct VeilMediaEngine {
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
webrtc::scoped_refptr<webrtc::AudioDeviceModule> create_audio_device(
    const webrtc::Environment& env) {
#if defined(__APPLE__)
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
      "veil-worker", webrtc::TaskQueueFactory::Priority::kNormal);
  ws->network_tq = ws->env.task_queue_factory().CreateTaskQueue(
      "veil-net", webrtc::TaskQueueFactory::Priority::kHigh);

  // Per-platform ADM selection lives in one helper so direct and group calls
  // cannot silently diverge. In particular, macOS uses WebRTC's CoreAudio HAL
  // path while iOS retains the AVAudioSession-aware custom ADM.
  ws->adm = create_audio_device(ws->env);
  if (ws->adm) {
    const int32_t init_rc = ws->adm->Init();
    bool rec_avail = false, play_avail = false;
    ws->adm->RecordingIsAvailable(&rec_avail);
    ws->adm->PlayoutIsAvailable(&play_avail);
    vlog("adm: Init=%d Initialized=%d recDevs=%d playDevs=%d recAvail=%d "
         "playAvail=%d",
         init_rc, ws->adm->Initialized(), (int)ws->adm->RecordingDevices(),
         (int)ws->adm->PlayoutDevices(), rec_avail, play_avail);
  }
  ws->apm = webrtc::BuiltinAudioProcessingBuilder().Build(ws->env);

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
  ws->call = webrtc::Call::Create(std::move(call_cfg));

  ws->shim = std::make_unique<veil_media::VeilTransportShim>(
      veil_chan, ws->call.get(), ws->network_tq.get());
  ws->shim->Start();

  ws->video_sink = std::make_unique<VeilVideoSink>();
  ws->local_video_sink = std::make_unique<VeilVideoSink>();
#if defined(__ANDROID__)
  ws->android420_dispatcher =
      std::make_unique<Android420FrameDispatcher>(&ws->android420_stats);
#endif

  engine->ws = std::move(ws);
#endif
  return engine.release();
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
    engine->ws->call.reset();  // after streams (stop_audio) + shim->Stop()
    if (engine->ws->adm) engine->ws->adm->Terminate();
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
      "veil-group-worker", webrtc::TaskQueueFactory::Priority::kNormal);
  ws->network_tq = ws->env.task_queue_factory().CreateTaskQueue(
      "veil-group-net", webrtc::TaskQueueFactory::Priority::kHigh);
  ws->adm = create_audio_device(ws->env);
  if (ws->adm) ws->adm->Init();
  ws->apm = webrtc::BuiltinAudioProcessingBuilder().Build(ws->env);
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
  ws->call = webrtc::Call::Create(std::move(call_cfg));
  ws->fanout = std::make_unique<GroupFanoutTransport>(ws->call.get());
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
      veil_chan, ws->call.get(), ws->network_tq.get());
  peer->shim->Start();
  peer->video_sink = std::make_unique<VeilVideoSink>();
  ws->fanout->Add(veil_chan);
  if (engine->audio_running.load()) {
    run_on(ws->worker_tq.get(), [&]() {
      webrtc::AudioReceiveStreamInterface::Config rc;
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
    run_on(ws->worker_tq.get(), [&]() {
      ensure_group_video_codecs(ws);
      start_group_peer_video(ws, peer.get());
    });
    if (peer->video_recv_stream == nullptr) {
      if (peer->recv_stream) {
        run_on(ws->worker_tq.get(), [&]() {
          peer->recv_stream->Stop();
          ws->call->DestroyAudioReceiveStream(peer->recv_stream);
          peer->recv_stream = nullptr;
        });
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
  run_on(ws->worker_tq.get(), [&]() {
    stop_group_peer_video(ws, peer);
    if (peer->recv_stream) {
      peer->recv_stream->Stop();
      ws->call->DestroyAudioReceiveStream(peer->recv_stream);
      peer->recv_stream = nullptr;
    }
  });
  ws->peers.erase(it);
  vlog("group media: remove peer peers=%zu", ws->peers.size());
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_group_engine_start_audio(VeilGroupMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  if (engine->audio_running.load()) return VEIL_MEDIA_OK;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  GroupWebrtcState* ws = engine->ws.get();
  const uint32_t local_ssrc = group_audio_ssrc_of(engine->local);
  run_on(ws->worker_tq.get(), [&]() {
    ws->call->SignalChannelNetworkState(webrtc::MediaType::AUDIO,
                                        webrtc::kNetworkUp);
    if (ws->send_stream == nullptr) {
      webrtc::AudioSendStream::Config sc(ws->fanout.get());
      sc.rtp.ssrc = local_ssrc;
      sc.rtp.extensions.emplace_back(
          webrtc::RtpExtension::kTransportSequenceNumberUri,
          webrtc::RtpHeaderExtensionId(1));
      sc.encoder_factory = webrtc::CreateBuiltinAudioEncoderFactory();
      sc.send_codec_spec = webrtc::AudioSendStream::Config::SendCodecSpec(
          kOpusPayloadType, webrtc::SdpAudioFormat("opus", 48000, 2));
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
  if (ws->adm) {
    if (!engine->mic_muted) {
      ws->adm->InitRecording();
      ws->adm->StartRecording();
    }
    ws->adm->InitPlayout();
    ws->adm->StartPlayout();
  }
  engine->audio_running.store(true);
  vlog("group audio: started peers=%zu", ws->peers.size());
  return VEIL_MEDIA_OK;
#else
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
      if (ws->adm->Recording()) ws->adm->StopRecording();
      if (ws->adm->Playing()) ws->adm->StopPlayout();
    }
    run_on(ws->worker_tq.get(), [&]() {
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
    });
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
    // Mute the RTP source before stopping capture. On unmute, do the inverse:
    // make the device live first and only then expose its frames to the send
    // stream. This prevents both a stale-frame leak and muted AudioRecord CPU.
    if (engine->mic_muted) {
      if (ws->send_stream) ws->send_stream->SetMuted(true);
      if (engine->audio_running.load() && ws->adm && ws->adm->Recording())
        ws->adm->StopRecording();
    } else {
      if (engine->audio_running.load() && ws->adm && !ws->adm->Recording()) {
        ws->adm->InitRecording();
        if (ws->adm->StartRecording() != 0) return VEIL_MEDIA_ERR_DEVICE;
      }
      if (ws->send_stream) ws->send_stream->SetMuted(false);
    }
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
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  GroupWebrtcState* ws = engine->ws.get();
  const uint32_t local_ssrc = group_video_ssrc_of(engine->local);
  bool peers_ready = true;
  run_on(ws->worker_tq.get(), [&]() {
    ws->call->SignalChannelNetworkState(webrtc::MediaType::VIDEO,
                                        webrtc::kNetworkUp);
    ensure_group_video_codecs(ws);
    if (ws->video_send_stream == nullptr) {
      webrtc::VideoSendStream::Config sc(ws->fanout.get());
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

      int kbps = 150;
      if (const char* value = std::getenv("VEIL_MEDIA_VIDEO_KBPS")) {
        const int configured = std::atoi(value);
        if (configured > 0) kbps = configured;
      }
      const int bps = kbps * 1000;
      webrtc::VideoEncoderConfig ec;
      ec.codec_type = webrtc::kVideoCodecVP8;
      ec.video_format = webrtc::SdpVideoFormat::VP8();
      ec.encoder_specific_settings = resilient_vp8_settings();
      ec.content_type = webrtc::VideoEncoderConfig::ContentType::kRealtimeVideo;
      ec.number_of_streams = 1;
      ec.max_bitrate_bps = bps;
      webrtc::VideoStream layer;
      layer.active = true;
      layer.min_bitrate_bps = 30000;
      layer.target_bitrate_bps = bps * 2 / 3;
      layer.max_bitrate_bps = bps;
      layer.max_framerate = 15;
      layer.max_qp = 63;
      ec.simulcast_layers.push_back(layer);
      ws->video_send_stream =
          ws->call->CreateVideoSendStream(std::move(sc), std::move(ec));
      if (ws->video_send_stream) {
        ws->video_send_stream->SetSource(
            ws->video_source.get(),
            webrtc::DegradationPreference::MAINTAIN_FRAMERATE);
        ws->video_send_stream->Start();
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
  if (ws->call) {
    run_on(ws->worker_tq.get(), [&]() {
      if (ws->video_send_stream) {
        ws->video_send_stream->Stop();
        ws->call->DestroyVideoSendStream(ws->video_send_stream);
        ws->video_send_stream = nullptr;
      }
      for (auto& entry : ws->peers)
        stop_group_peer_video(ws, entry.second.get());
    });
  }
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_group_engine_start_camera(VeilGroupMediaEngine* engine,
                                         int width, int height, int fps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && \
    (defined(__APPLE__) || (defined(__linux__) && !defined(__ANDROID__)))
  GroupWebrtcState* ws = engine->ws.get();
  if (!ws || !ws->video_source || !engine->video_running.load())
    return VEIL_MEDIA_ERR_STATE;
  if (ws->camera) return VEIL_MEDIA_OK;
  if (width <= 0) width = 352;
  if (height <= 0) height = 198;
  if (fps <= 0) fps = 15;
  webrtc::VideoBroadcaster* source = ws->video_source.get();
  VeilVideoSink* local_sink = ws->local_video_sink.get();
  ws->camera.reset(veil_media::CreatePlatformCamera(
      [source, local_sink](const uint8_t* y, const uint8_t* u,
                           const uint8_t* v, int w, int h, int sy, int su,
                           int sv, int64_t ts_us) {
        if (local_sink)
          local_sink->store_i420(y, u, v, w, h, sy, su, sv);
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

int veil_media_group_engine_start_screen(VeilGroupMediaEngine* engine,
                                         int width, int fps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && defined(__APPLE__)
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
  webrtc::VideoBroadcaster* source = ws->video_source.get();
  VeilVideoSink* local_sink = ws->local_video_sink.get();
  ws->screen.reset(veil_media::CreatePlatformScreen(
      [source, local_sink](const uint8_t* y, const uint8_t* u,
                           const uint8_t* v, int w, int h, int sy, int su,
                           int sv, int64_t ts_us) {
        if (local_sink)
          local_sink->store_i420(y, u, v, w, h, sy, su, sv);
        push_i420(source, y, u, v, w, h, sy, su, sv, ts_us);
      }));
  if (!ws->screen || !ws->screen->Start(width, fps)) {
    ws->screen.reset();
    return VEIL_MEDIA_ERR_STATE;
  }
  return VEIL_MEDIA_OK;
#else
  (void)width;
  (void)fps;
  return VEIL_MEDIA_ERR_STATE;
#endif
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
    engine->ws->call.reset();
    if (engine->ws->adm) engine->ws->adm->Terminate();
  }
#endif
  delete engine;
}

int veil_media_engine_start_audio(VeilMediaEngine* engine, int send, int recv) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  if (engine->audio_running.load()) return VEIL_MEDIA_OK;  // idempotent
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  WebrtcState* ws = engine->ws.get();
  const uint32_t local_ssrc = ssrc_of(engine->local);
  const uint32_t remote_ssrc = ssrc_of(engine->peer);

  // Streams must be created on the Call's worker queue.
  run_on(ws->worker_tq.get(), [&]() {
    // The Call's audio network state defaults to kNetworkDown, which makes the
    // send transport hold every RTP packet in the pacer (only RTCP leaks out on
    // its own path). Bring the audio channel up so mic audio actually flows.
    ws->call->SignalChannelNetworkState(webrtc::MediaType::AUDIO,
                                        webrtc::kNetworkUp);
    if (send && ws->send_stream == nullptr) {
      webrtc::AudioSendStream::Config sc(ws->shim.get());  // sets send_transport
      sc.rtp.ssrc = local_ssrc;
      // TWCC: the send-side bandwidth estimator needs this both ways.
      sc.rtp.extensions.emplace_back(
          webrtc::RtpExtension::kTransportSequenceNumberUri,
          webrtc::RtpHeaderExtensionId(1));
      sc.encoder_factory = webrtc::CreateBuiltinAudioEncoderFactory();
      sc.send_codec_spec = webrtc::AudioSendStream::Config::SendCodecSpec(
          kOpusPayloadType, webrtc::SdpAudioFormat("opus", 48000, 2));
      ws->send_stream = ws->call->CreateAudioSendStream(sc);
      if (ws->send_stream) ws->send_stream->Start();
    }
    if (recv && ws->recv_stream == nullptr) {
      webrtc::AudioReceiveStreamInterface::Config rc;
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
  // webrtc::Call does NOT drive the AudioDeviceModule the way PeerConnection
  // does — start capture/playout explicitly, else the send stream has no audio
  // frames (only RTCP flows) and the recv stream is never played out. The
  // AVAudioEngine ADM's start is non-blocking + idempotent (all engine work is
  // serialized on its own GCD queue), so this is safe on the calling thread and
  // AudioState toggling it too on the worker queue just no-ops.
  if (ws->adm) {
    if (send && !engine->mic_muted) {
      ws->adm->InitRecording();
      ws->adm->StartRecording();
    }
    if (recv) {
      ws->adm->InitPlayout();
      ws->adm->StartPlayout();
    }
    vlog("adm start: recording=%d playing=%d", ws->adm->Recording(),
         ws->adm->Playing());
  }
  // A few seconds in, log the send stream's packet counters — the definitive
  // "is audio actually going out" check.
  if (ws->send_stream) {
    ws->worker_tq->PostDelayedTask(
        [ws]() {
          if (ws->send_stream) {
            const auto s = ws->send_stream->GetStats();
            vlog("sendstream @3s: packets_sent=%lld bytes=%lld",
                 (long long)s.packets_sent, (long long)s.payload_bytes_sent);
          }
        },
        webrtc::TimeDelta::Seconds(3));
  }
  engine->audio_running.store(true);
  return VEIL_MEDIA_OK;
#else
  (void)send;
  (void)recv;
  return VEIL_MEDIA_ERR_STATE;  // no WebRTC linked yet
#endif
}

int veil_media_engine_stop_audio(VeilMediaEngine* engine) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
  if (!engine->audio_running.exchange(false)) return VEIL_MEDIA_OK;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (engine->ws && engine->ws->call) {
    WebrtcState* ws = engine->ws.get();
    // Stop the ADM off the worker queue (see start_audio — StartRecording/
    // StopRecording can block CoreAudio and must not wedge the Call worker).
    if (ws->adm) {
      if (ws->adm->Recording()) ws->adm->StopRecording();
      if (ws->adm->Playing()) ws->adm->StopPlayout();
    }
    run_on(ws->worker_tq.get(), [&]() {
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
    });
  }
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_start_video(VeilMediaEngine* engine, int send, int recv,
                                  int max_bitrate_kbps, int max_fps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  WebrtcState* ws = engine->ws.get();
  const uint32_t local_v = video_ssrc_of(engine->local);
  const uint32_t remote_v = video_ssrc_of(engine->peer);
  constexpr int kVp8Pt = 96;

  run_on(ws->worker_tq.get(), [&]() {
    // Video has its own network state (defaults kNetworkDown); bring it up.
    ws->call->SignalChannelNetworkState(webrtc::MediaType::VIDEO,
                                        webrtc::kNetworkUp);
    if (!ws->video_encoder_factory)
      ws->video_encoder_factory =
          std::make_unique<webrtc::VideoEncoderFactoryTemplate<
              webrtc::LibvpxVp8EncoderTemplateAdapter>>();
    if (!ws->video_decoder_factory)
      ws->video_decoder_factory =
          std::make_unique<webrtc::VideoDecoderFactoryTemplate<
              webrtc::LibvpxVp8DecoderTemplateAdapter>>();
    if (!ws->video_bitrate_alloc_factory)
      ws->video_bitrate_alloc_factory =
          webrtc::CreateBuiltinVideoBitrateAllocatorFactory();
    if (!ws->video_source)
      ws->video_source = std::make_unique<webrtc::VideoBroadcaster>();

    if (send && ws->video_send_stream == nullptr) {
      webrtc::VideoSendStream::Config sc(ws->shim.get());  // sets send_transport
      sc.rtp.ssrcs = {local_v};                            // NOTE: vector
      sc.rtp.payload_name = "VP8";
      sc.rtp.payload_type = kVp8Pt;
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
      const int fps = std::clamp(max_fps > 0 ? max_fps : 15, 5, 60);
      const int bps = kbps * 1000;
      ws->video_target_bitrate_bps = bps;
      ws->video_max_fps.store(fps, std::memory_order_relaxed);
      ws->video_last_encoded_frame_us.store(0, std::memory_order_relaxed);
      // Anchor the Call's bandwidth estimate to the route budget. Without
      // this the BWE starts at webrtc's 300 kbps default and — on the veil
      // datagram channel, where no transport feedback ever raises it — the
      // PACER budget stays pinned near that default while the encoder runs
      // at the profile rate. The overshoot then stands in the pacer queue:
      // live-observed as video (audio has pacer priority, RTCP bypasses it)
      // arriving a stable 2-3 s late with every RTCP metric clean.
      {
        webrtc::BitrateSettings bs;
        // Pin min = start: anchoring only the START is not enough — the
        // delay-based BWE then sags below the profile on the TCP-like veil
        // channel (it reacts to the queue it itself builds) and the pacer
        // budget drops under the encoder rate again (live-measured 1.4-1.6 s
        // standing pacer queue with a 900 kbps profile). Congestion response
        // on this transport belongs to the app's own bitrate ladder, which
        // moves this whole anchor when it retunes.
        bs.min_bitrate_bps = bps;
        bs.start_bitrate_bps = bps;
        bs.max_bitrate_bps = bps + 128'000;  // audio + RTCP headroom
        ws->call->SetClientBitratePreferences(bs);
      }
      webrtc::VideoEncoderConfig ec;
      ec.codec_type = webrtc::kVideoCodecVP8;
      ec.video_format = webrtc::SdpVideoFormat::VP8();
      ec.encoder_specific_settings = resilient_vp8_settings();
      ec.content_type = webrtc::VideoEncoderConfig::ContentType::kRealtimeVideo;
      ec.number_of_streams = 1;
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
          ws->call->CreateVideoSendStream(std::move(sc), std::move(ec));
      vlog("video: send stream=%p", (void*)ws->video_send_stream);
      if (ws->video_send_stream) {
        ws->video_send_stream->SetSource(
            ws->video_source.get(),
            kbps > 150 ? webrtc::DegradationPreference::BALANCED
                       : webrtc::DegradationPreference::MAINTAIN_FRAMERATE);
        ws->video_send_stream->Start();
      }
    }
    if (recv && ws->video_recv_stream == nullptr) {
      webrtc::VideoReceiveStreamInterface::Config rc(
          ws->shim.get(), ws->video_decoder_factory.get());
      rc.rtp.remote_ssrc = remote_v;    // do NOT set local_ssrc (deprecated)
      rc.rtp.nack.rtp_history_ms = kVideoNackHistoryMs;
      rc.renderer = ws->video_sink.get();
      rc.decoders.emplace_back(webrtc::SdpVideoFormat::VP8(), kVp8Pt);
      ws->video_recv_stream = ws->call->CreateVideoReceiveStream(std::move(rc));
      if (ws->video_recv_stream) ws->video_recv_stream->Start();
    }
  });
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

int veil_media_engine_set_video_bitrate(VeilMediaEngine* engine,
                                        int max_bitrate_kbps, int max_fps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->call) return VEIL_MEDIA_ERR_STATE;
  WebrtcState* ws = engine->ws.get();
  int rc = VEIL_MEDIA_ERR_STATE;
  run_on(ws->worker_tq.get(), [&]() {
    if (ws->video_send_stream == nullptr) return;
    // Same budget rules as start_video: the explicit debug pin wins, and the
    // clamps keep the encoder inside the padded-onion / direct envelopes.
    int kbps = max_bitrate_kbps > 0 ? max_bitrate_kbps : 150;
    if (const char* e = std::getenv("VEIL_MEDIA_VIDEO_KBPS")) {
      int v = std::atoi(e);
      if (v > 0) kbps = v;
    }
    kbps = std::clamp(kbps, 30, 2500);
    const int fps = std::clamp(max_fps > 0 ? max_fps : 15, 5, 60);
    const int bps = kbps * 1000;
    if (bps == ws->video_target_bitrate_bps &&
        fps == ws->video_max_fps.load(std::memory_order_relaxed)) {
      rc = VEIL_MEDIA_OK;
      return;
    }
    webrtc::VideoEncoderConfig ec;
    ec.codec_type = webrtc::kVideoCodecVP8;
    ec.video_format = webrtc::SdpVideoFormat::VP8();
    ec.encoder_specific_settings = resilient_vp8_settings();
    ec.content_type = webrtc::VideoEncoderConfig::ContentType::kRealtimeVideo;
    ec.number_of_streams = 1;
    ec.max_bitrate_bps = bps;
    webrtc::VideoStream layer;
    layer.active = true;
    layer.min_bitrate_bps = 30000;
    layer.target_bitrate_bps = bps * 2 / 3;
    layer.max_bitrate_bps = bps;
    layer.max_framerate = fps;
    layer.max_qp = 63;
    ec.simulcast_layers.push_back(layer);
    ws->video_send_stream->ReconfigureVideoEncoder(std::move(ec));
    // Move the Call-level estimate anchor WITH the retune (see start_video):
    // the pacer budget must track the encoder budget in both directions, or
    // an upward retune re-opens the standing-queue gap.
    {
      webrtc::BitrateSettings bs;
      bs.min_bitrate_bps = bps;  // pinned floor — see start_video
      bs.start_bitrate_bps = bps;
      bs.max_bitrate_bps = bps + 128'000;
      ws->call->SetClientBitratePreferences(bs);
    }
    ws->video_target_bitrate_bps = bps;
    ws->video_max_fps.store(fps, std::memory_order_relaxed);
    ws->video_last_encoded_frame_us.store(0, std::memory_order_relaxed);
    vlog("video: retuned to %d kbps @ %d fps", kbps, fps);
    rc = VEIL_MEDIA_OK;
  });
  return rc;
#else
  (void)max_bitrate_kbps;
  (void)max_fps;
  return VEIL_MEDIA_ERR_STATE;
#endif
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
  if (ws->call) {
    run_on(ws->worker_tq.get(), [&]() {
      if (ws->video_send_stream) {
        ws->video_send_stream->Stop();
        ws->call->DestroyVideoSendStream(ws->video_send_stream);
        ws->video_send_stream = nullptr;
      }
      if (ws->video_recv_stream) {
        ws->video_recv_stream->Stop();
        ws->call->DestroyVideoReceiveStream(ws->video_recv_stream);
        ws->video_recv_stream = nullptr;
      }
    });
  }
  if (ws->shim) ws->shim->SetRemoteVideoSsrc(0);
#endif
  return VEIL_MEDIA_OK;
}

int veil_media_engine_start_camera(VeilMediaEngine* engine, int width,
                                   int height, int fps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && \
    (defined(__APPLE__) || (defined(__linux__) && !defined(__ANDROID__)))
  WebrtcState* ws = engine->ws.get();
  if (!ws || !ws->video_source) return VEIL_MEDIA_ERR_STATE;
  if (ws->camera) return VEIL_MEDIA_OK;  // already capturing
  if (width <= 0) width = 352;
  if (height <= 0) height = 288;
  if (fps <= 0) fps = 15;
  // Feed each captured I420 frame straight into the VP8 send source. The
  // callback runs on the capture queue; push_i420 copies synchronously.
  webrtc::VideoBroadcaster* src = ws->video_source.get();
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
  if (!ws->camera->Start(width, height, fps)) {
    ws->camera.reset();
    return VEIL_MEDIA_ERR_STATE;
  }
  vlog("camera: started %dx%d@%d", width, height, fps);
  return VEIL_MEDIA_OK;
#else
  (void)width;
  (void)height;
  (void)fps;
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

int veil_media_engine_start_screen(VeilMediaEngine* engine, int width,
                                   int fps) {
  if (engine == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC) && defined(__APPLE__)
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
  webrtc::VideoBroadcaster* src = ws->video_source.get();
  VeilVideoSink* local_sink = ws->local_video_sink.get();
  ws->screen.reset(veil_media::CreatePlatformScreen(
      [ws, src, local_sink](const uint8_t* y, const uint8_t* u,
                            const uint8_t* v, int w, int h, int sy, int su,
                            int sv, int64_t ts_us) {
        if (local_sink)
          local_sink->store_i420(y, u, v, w, h, sy, su, sv);
        if (should_encode_video_frame(ws))
          push_i420(src, y, u, v, w, h, sy, su, sv, ts_us);
      }));
  if (!ws->screen) return VEIL_MEDIA_ERR_STATE;
  if (!ws->screen->Start(width, fps)) {
    ws->screen.reset();
    return VEIL_MEDIA_ERR_STATE;
  }
  vlog("screen: started w<=%d@%d", width, fps);
  return VEIL_MEDIA_OK;
#else
  (void)width;
  (void)fps;
  return VEIL_MEDIA_ERR_STATE;  // no screen backend on this platform yet
#endif
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
    if (engine->mic_muted) {
      if (ws->send_stream) ws->send_stream->SetMuted(true);
      if (engine->audio_running.load() && ws->adm && ws->adm->Recording())
        ws->adm->StopRecording();
    } else {
      if (engine->audio_running.load() && ws->adm && !ws->adm->Recording()) {
        ws->adm->InitRecording();
        if (ws->adm->StartRecording() != 0) return VEIL_MEDIA_ERR_DEVICE;
      }
      if (ws->send_stream) ws->send_stream->SetMuted(false);
    }
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
char* adm_devices_json(webrtc::AudioDeviceModule* adm, bool recording) {
  std::string out = "[";
  if (adm) {
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

int veil_media_engine_select_audio_input(VeilMediaEngine* engine,
                                         const char* id) {
  if (engine == nullptr || id == nullptr) return VEIL_MEDIA_ERR_ARG;
#if defined(VEIL_MEDIA_HAVE_WEBRTC)
  if (!engine->ws || !engine->ws->adm) return VEIL_MEDIA_ERR_DEVICE;
  const uint16_t idx = static_cast<uint16_t>(std::atoi(id));
  // Stop -> switch -> restart so the change takes effect mid-call.
  webrtc::AudioDeviceModule* adm = engine->ws->adm.get();
  adm->StopRecording();
  if (adm->SetRecordingDevice(idx) != 0) return VEIL_MEDIA_ERR_DEVICE;
  adm->InitRecording();
  adm->StartRecording();
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
  adm->StopPlayout();
  if (adm->SetPlayoutDevice(idx) != 0) return VEIL_MEDIA_ERR_DEVICE;
  adm->InitPlayout();
  adm->StartPlayout();
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
    // measurements — NetEq's total audio path estimate (jitter buffer + ADM
    // playout) and the video render delay target.
    uint32_t audio_delay_ms = 0;
    uint32_t audio_jb_ms = 0;
    int video_delay_ms = 0;
    int video_jb_ms = 0;
    // Sender-side standing queue: RTCP bypasses the pacer, so a video RTP
    // packet can wait SECONDS in the pacer while rtt_ms stays flat — the
    // exact signature of the live "2-3 s stable lag, all metrics clean"
    // report. Export it so the creep is attributable.
    int64_t pacer_delay_ms = 0;
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
    run_on(ws->worker_tq.get(), [&] {
      if (ws->call) {
        const auto cs = ws->call->GetStats();
        if (cs.rtt_ms >= 0) rtt_ms = cs.rtt_ms;
        pacer_delay_ms = cs.pacer_delay_ms;
      }
      if (ws->send_stream) {
        // Per-stream RTCP report-block RTT is fresher than the call-level
        // aggregate when both are available. The report block also carries
        // what the REMOTE receiver measured on our outbound leg — that is the
        // signal the sender-side bitrate adaptation acts on.
        const auto s = ws->send_stream->GetStats();
        if (s.rtt_ms >= 0) rtt_ms = s.rtt_ms;
        if (s.jitter_ms >= 0) tx_jitter_ms = s.jitter_ms;
        if (s.fraction_lost >= 0.0f) {
          tx_loss_pct = static_cast<int>(s.fraction_lost * 100.0f + 0.5f);
        }
      }
      if (ws->recv_stream) {
        const auto r =
            ws->recv_stream->GetStats(/*get_and_clear_legacy_stats=*/false);
        jitter_ms = r.jitter_ms;
        audio_delay_ms = r.delay_estimate_ms;
        audio_jb_ms = r.jitter_buffer_ms;
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
      if (ws->video_recv_stream) {
        const auto v = ws->video_recv_stream->GetStats();
        video_delay_ms = v.current_delay_ms;
        video_jb_ms = v.jitter_buffer_ms;
      }
    });
    if (rtt_ms < 0) rtt_ms = 0;  // unknown yet — keep the legacy "0" shape
    const auto tx_video = ws->shim->outbound_video_cadence();
    const auto rx_video = ws->shim->inbound_video_cadence();
    const auto delivered_video = ws->shim->delivered_video_cadence();
    const auto cadence_fps = [](const veil_media::VideoCadenceSnapshot& c) {
      const int64_t elapsed = c.last_ns - c.first_ns;
      return c.frames > 1 && elapsed > 0
                 ? static_cast<double>(c.frames - 1) * 1000000000.0 /
                       static_cast<double>(elapsed)
                 : 0.0;
    };
    char json[1664];
    std::snprintf(
        json, sizeof(json),
        "{\"tx_pkts\":%llu,\"rx_pkts\":%llu,\"tx_bytes\":%llu,"
        "\"rx_bytes\":%llu,\"tx_drops\":%llu,\"rx_drops\":%llu,"
        "\"rtt_ms\":%lld,\"jitter_ms\":%u,\"loss_pct\":%d,"
        "\"tx_jitter_ms\":%d,\"tx_loss_pct\":%d,"
        "\"audio_delay_ms\":%u,\"audio_jb_ms\":%u,"
        "\"video_delay_ms\":%d,\"video_jb_ms\":%d,"
        "\"pacer_delay_ms\":%lld,"
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
        "\"target_bitrate_bps\":%d,\"max_fps\":%d}",
        static_cast<unsigned long long>(ws->shim->outbound_packet_count()),
        static_cast<unsigned long long>(ws->shim->inbound_packet_count()),
        static_cast<unsigned long long>(ws->shim->outbound_byte_count()),
        static_cast<unsigned long long>(ws->shim->inbound_byte_count()),
        static_cast<unsigned long long>(ws->shim->outbound_dropped_count()),
        static_cast<unsigned long long>(ws->shim->inbound_dropped_count()),
        static_cast<long long>(rtt_ms), jitter_ms, loss_pct, tx_jitter_ms,
        tx_loss_pct, audio_delay_ms, audio_jb_ms, video_delay_ms, video_jb_ms,
        static_cast<long long>(pacer_delay_ms),
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
        ws->video_target_bitrate_bps,
        ws->video_max_fps.load(std::memory_order_relaxed));
    return dup_cstr(json);
  }
#endif
  return dup_cstr(
      "{\"tx_pkts\":0,\"rx_pkts\":0,\"tx_bytes\":0,\"rx_bytes\":0,"
      "\"tx_drops\":0,\"rx_drops\":0,\"rtt_ms\":0,\"jitter_ms\":0,"
      "\"loss_pct\":0,\"tx_jitter_ms\":0,\"tx_loss_pct\":0,"
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
