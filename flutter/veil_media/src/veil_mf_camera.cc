/* SPDX-License-Identifier: MIT
 *
 * veil_mf_camera.cc — Media Foundation CameraCapturer for Windows desktop.
 *
 * The Windows twin of veil_v4l2_camera.cc: opens a video capture device via
 * IMFSourceReader, pulls samples on a dedicated capture thread, converts each
 * to I420, downscales to the requested width (libyuv::I420Scale — the veil path
 * caps VP8 bitrate and pads every RTP packet into a 16KB onion cell, so
 * full-res keyframes fan out into hundreds of cells and add seconds of
 * latency) and hands the planes to the CameraFrameCb.
 *
 * MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING is the load-bearing attribute: with
 * it the reader inserts a converter and will hand us NV12 whatever the camera
 * natively produces (MJPG on most USB webcams, YUY2 on others). Without it a
 * SetCurrentMediaType asking for NV12 fails on any device that does not
 * already emit it, which is most of them. The YUY2 and RGB32 branches below
 * are kept anyway: the converter is not present on every SKU (server images
 * ship without the media feature pack), and falling back beats no camera.
 *
 * Pure C++ + libyuv (already inside libwebrtc.a) — no WebRTC types.
 *
 * ⚠️ Written without a Windows host to compile on: see the header comment in
 * windows/build_veil_media_dll_windows.ps1. The structure mirrors the V4L2
 * backend that is known good; the MF specifics are from the documented API and
 * have never been run. Treat the first successful call as the real test.
 */
#include "veil_camera.h"
#include "veil_diag_log.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

// WIN32_LEAN_AND_MEAN is what drops the OLE half of windows.h, and that is
// where CoInitializeEx, CoTaskMemFree and IID_PPV_ARGS live. The Media
// Foundation headers happen to pull parts of COM in transitively, but that is
// an accident of their include graph rather than a promise.
#include <objbase.h>

#include <mfapi.h>
#include <mferror.h>
#include <mfidl.h>
#include <mfobjects.h>
#include <mfreadwrite.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "third_party/libyuv/include/libyuv/convert.h"  // NV12ToI420, YUY2ToI420, ARGBToI420
#include "third_party/libyuv/include/libyuv/scale.h"    // I420Scale

namespace veil_media {
namespace {

void vcam_log(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  veil_media::diag::vlog(fmt, ap);
  va_end(ap);
}

int64_t now_us() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

// Minimal COM smart pointer. <wrl/client.h> would do this, but it is not
// guaranteed present in every toolchain this .dll is built with and the whole
// need here is AddRef-free ownership of a handful of interfaces.
template <typename T>
class ComPtr {
 public:
  ComPtr() = default;
  ~ComPtr() { Reset(); }
  ComPtr(const ComPtr&) = delete;
  ComPtr& operator=(const ComPtr&) = delete;
  ComPtr(ComPtr&& other) noexcept : p_(other.p_) { other.p_ = nullptr; }

  T** operator&() { return &p_; }
  T* operator->() const { return p_; }
  T* Get() const { return p_; }
  explicit operator bool() const { return p_ != nullptr; }
  void Reset() {
    if (p_ != nullptr) {
      p_->Release();
      p_ = nullptr;
    }
  }

 private:
  T* p_ = nullptr;
};

// MFStartup/MFShutdown are refcounted per process by MF itself, but calling
// Startup once per capturer and Shutdown on teardown races the video-note
// recorder, which owns its own capturer. Hold the platform up for the life of
// the module instead: the cost is one idle MF instance, the alternative is a
// shutdown under a live ReadSample on another thread.
//
// ON A THREAD THIS FILE STARTS, always. A COM apartment is per-thread, and
// `CoInitializeEx` on a thread we did not create changes it for everything
// else that thread will ever do. This was a function-local static, so the
// FIRST caller to touch a camera — an FFI call arriving from Dart, on whatever
// thread the app happened to use — was moved to MTA and left there.
//
// WebRTC's Windows audio device module then asks for STA on that same thread,
// and treats the mismatch as fatal rather than as an error to report:
//
//   Fatal error in ..\..\rtc_base\win\scoped_com_initializer.cc, line 43
//   Check failed: ((HRESULT)0x80010106L) != hr_
//   Invalid COM thread model change (MTA->STA)
//
// Measured on Windows 11 with 0.13.4: the answering side accepted a call and
// the process died before a frame. Whoever ran first won the apartment — which
// is why the caller survived and the answerer did not. The old code also threw
// the `CoInitializeEx` result away (`com_ok_` was assigned and never read), so
// the other direction — our MTA refused on an already-STA thread — was silent.
//
// MTA rather than STA: the reader is pumped from a capture thread of ours with
// no message loop, and an STA apartment without one deadlocks the first
// cross-apartment call MF makes internally.
class MfPlatform {
 public:
  MfPlatform() {
    std::unique_lock<std::mutex> lock(m_);
    std::thread([this] { Serve(); }).detach();
    ready_cv_.wait(lock, [this] { return ready_; });
  }

  bool ok() const { return started_.load(); }

  // Run `fn` on the MF thread and block until it has finished. Never call this
  // FROM the MF thread — nothing here does, and it would deadlock.
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
  // Never returns: the platform is held up for the life of the module, so this
  // thread is never joined and the object is never destroyed. That is the same
  // lifetime the static had — only the apartment it touches has moved.
  [[noreturn]] void Serve() {
    const bool com_ok = SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED));
    if (!com_ok) vcam_log("CoInitializeEx(MTA) failed on the MF thread");
    started_.store(com_ok && SUCCEEDED(MFStartup(MF_VERSION, MFSTARTUP_LITE)));
    if (!started_.load()) vcam_log("MFStartup failed — no camera on this host");
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
  std::atomic<bool> started_{false};
};

MfPlatform& mf() {
  static MfPlatform instance;
  return instance;
}

std::string wide_to_utf8(const wchar_t* value, int len) {
  if (value == nullptr || len <= 0) return std::string();
  const int need =
      WideCharToMultiByte(CP_UTF8, 0, value, len, nullptr, 0, nullptr, nullptr);
  if (need <= 0) return std::string();
  std::string out(static_cast<size_t>(need), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value, len, out.data(), need, nullptr,
                      nullptr);
  return out;
}

std::wstring utf8_to_wide(const char* value) {
  if (value == nullptr || *value == '\0') return std::wstring();
  const int need = MultiByteToWideChar(CP_UTF8, 0, value, -1, nullptr, 0);
  if (need <= 0) return std::wstring();
  std::wstring out(static_cast<size_t>(need), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value, -1, out.data(), need);
  if (!out.empty() && out.back() == L'\0') out.pop_back();
  return out;
}

void append_json_string(std::string& out, const std::string& value) {
  out.push_back('"');
  for (const char c : value) {
    if (c == '"' || c == '\\') out.push_back('\\');
    // Device names come from the driver; a control character would produce
    // invalid JSON that the Dart side then fails to decode as "no cameras".
    if (static_cast<unsigned char>(c) < 0x20) continue;
    out.push_back(c);
  }
  out.push_back('"');
}

// Activate the capture device matching `symlink`, or the first one when it is
// empty. Returns null when there is no camera at all.
IMFMediaSource* activate_source(const std::wstring& symlink) {
  ComPtr<IMFAttributes> attrs;
  if (FAILED(MFCreateAttributes(&attrs, 1))) return nullptr;
  if (FAILED(attrs->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                            MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID))) {
    return nullptr;
  }
  IMFActivate** devices = nullptr;
  UINT32 count = 0;
  if (FAILED(MFEnumDeviceSources(attrs.Get(), &devices, &count)) ||
      count == 0) {
    if (devices != nullptr) CoTaskMemFree(devices);
    vcam_log("no video capture devices");
    return nullptr;
  }

  IMFMediaSource* source = nullptr;
  for (UINT32 i = 0; i < count; ++i) {
    if (source == nullptr) {
      bool match = symlink.empty();
      if (!match) {
        wchar_t* link = nullptr;
        UINT32 link_len = 0;
        if (SUCCEEDED(devices[i]->GetAllocatedString(
                MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK, &link,
                &link_len))) {
          match = symlink == std::wstring(link, link_len);
          CoTaskMemFree(link);
        }
      }
      if (match && FAILED(devices[i]->ActivateObject(IID_PPV_ARGS(&source)))) {
        source = nullptr;
      }
    }
    devices[i]->Release();
  }
  CoTaskMemFree(devices);
  return source;
}

class MfCameraCapturer : public CameraCapturer {
 public:
  explicit MfCameraCapturer(CameraFrameCb cb) : cb_(std::move(cb)) {}
  ~MfCameraCapturer() override { Stop(); }

  // The reader is CREATED, pumped and released on one thread — this object's
  // own capture thread, whose apartment it initialises itself.
  //
  // It used to be created here, on the caller's thread, and only pumped on the
  // capture thread. That is two faults in one: an MF object crossing an
  // apartment boundary, and — because opening a source is what first touches
  // [MfPlatform] — the caller's thread being moved to MTA behind its back. See
  // the note above [MfPlatform] for what that cost.
  bool Start(int width, int height, int fps,
             const char* device_id) override {
    if (running_.load()) return true;
    if (!mf().ok()) return false;
    if (width <= 0) width = 352;
    if (height <= 0) height = 288;
    if (fps <= 0) fps = 15;
    target_w_ = width;
    min_interval_us_ = 1000000 / fps;

    // Copied, not borrowed: the capture thread outlives this call, and
    // `device_id` belongs to the caller.
    const char* dev = device_id;
    if (dev == nullptr || *dev == '\0') dev = std::getenv("VEIL_MEDIA_CAMERA");
    const std::string device = dev != nullptr ? std::string(dev) : std::string();

    // Opening happens on the capture thread, so `Start` has to wait for its
    // verdict to keep answering the same question it always did: did the
    // camera open? The thread touches these locals only before it signals,
    // and this function does not return until then.
    std::mutex m;
    std::condition_variable cv;
    bool settled = false;
    bool opened = false;

    running_.store(true);
    thread_ = std::thread([this, device, width, height, &m, &cv, &settled,
                           &opened] {
      const bool com_ok =
          SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED));
      if (!com_ok) vcam_log("CoInitializeEx(MTA) failed on the capture thread");
      const bool ok = com_ok && OpenReader(device, width, height);
      {
        std::lock_guard<std::mutex> lock(m);
        opened = ok;
        settled = true;
      }
      cv.notify_one();
      if (ok) CaptureLoop();
      // Released inside the apartment that created it, before it goes away.
      reader_.Reset();
      if (com_ok) CoUninitialize();
    });
    {
      std::unique_lock<std::mutex> lock(m);
      cv.wait(lock, [&] { return settled; });
    }
    if (!opened) {
      running_.store(false);
      if (thread_.joinable()) thread_.join();
      return false;
    }
    vcam_log("started MF camera: capture %dx%d (stride %d, fmt %d) -> target %d",
             cap_w_, cap_h_, cap_stride_, static_cast<int>(fmt_), target_w_);
    return true;
  }

  void Stop() override {
    running_.store(false);
    // The thread releases the reader itself. Doing it here would touch a COM
    // object from a thread in another apartment — the very thing this class
    // now exists to avoid.
    if (thread_.joinable()) thread_.join();
  }

 private:
  // Everything Media Foundation, on the capture thread. Returns false with
  // nothing held.
  bool OpenReader(const std::string& device, int width, int height) {
    ComPtr<IMFMediaSource> source;
    // utf8_to_wide answers an empty string for both nullptr and "", and
    // activate_source reads an empty symlink as "the first camera".
    *(&source) = activate_source(utf8_to_wide(device.c_str()));
    if (!source) return false;

    // ENABLE_VIDEO_PROCESSING is what makes the NV12 request below succeed on
    // an MJPG-only webcam; see the file header.
    ComPtr<IMFAttributes> reader_attrs;
    if (FAILED(MFCreateAttributes(&reader_attrs, 1)) ||
        FAILED(reader_attrs->SetUINT32(
            MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, TRUE))) {
      return false;
    }
    if (FAILED(MFCreateSourceReaderFromMediaSource(
            source.Get(), reader_attrs.Get(), &reader_))) {
      vcam_log("MFCreateSourceReaderFromMediaSource failed");
      return false;
    }
    if (!NegotiateFormat(width, height)) {
      reader_.Reset();
      return false;
    }
    return true;
  }

  enum class Fmt { kUnknown, kNv12, kYuy2, kRgb32 };

  // Ask for NV12 at the requested size, then read back what we actually got.
  // The camera picks the closest geometry it supports; the engine is told the
  // real size through the frame callback, so a mismatch is not an error.
  bool NegotiateFormat(int width, int height) {
    ComPtr<IMFMediaType> want;
    if (FAILED(MFCreateMediaType(&want))) return false;
    want->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    want->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
    MFSetAttributeSize(want.Get(), MF_MT_FRAME_SIZE,
                       static_cast<UINT32>(width),
                       static_cast<UINT32>(height));
    HRESULT hr = reader_->SetCurrentMediaType(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM, nullptr, want.Get());
    if (FAILED(hr)) {
      // No converter available: take whatever the device offers natively and
      // convert here, if it is one of the packed formats libyuv covers.
      vcam_log("NV12 request refused (0x%08lx) — using the native format",
               static_cast<unsigned long>(hr));
    }

    ComPtr<IMFMediaType> got;
    if (FAILED(reader_->GetCurrentMediaType(MF_SOURCE_READER_FIRST_VIDEO_STREAM,
                                            &got))) {
      return false;
    }
    // Not GUID_NULL: that name is an extern defined in uuid.lib, and pulling a
    // library in for a zeroed struct is a link error waiting for the one build
    // that does not happen to already carry it.
    GUID subtype = {};
    if (FAILED(got->GetGUID(MF_MT_SUBTYPE, &subtype))) return false;
    if (subtype == MFVideoFormat_NV12) {
      fmt_ = Fmt::kNv12;
    } else if (subtype == MFVideoFormat_YUY2) {
      fmt_ = Fmt::kYuy2;
    } else if (subtype == MFVideoFormat_RGB32 ||
               subtype == MFVideoFormat_ARGB32) {
      fmt_ = Fmt::kRgb32;
    } else {
      vcam_log("unsupported capture subtype; no local video");
      return false;
    }

    UINT32 w = 0, h = 0;
    if (FAILED(MFGetAttributeSize(got.Get(), MF_MT_FRAME_SIZE, &w, &h)) ||
        w == 0 || h == 0) {
      return false;
    }
    cap_w_ = static_cast<int>(w);
    cap_h_ = static_cast<int>(h);

    // MF_MT_DEFAULT_STRIDE is optional and often absent on capture types. The
    // packed default is right for a contiguous buffer, which is what
    // ConvertToContiguousBuffer hands us. Negative strides mean bottom-up
    // RGB — handled at conversion time, so keep the sign.
    //
    // The attribute is stored as UINT32 holding a signed value, and
    // IMFAttributes has no GetINT32 at all — the round-trip through UINT32 is
    // the documented way to read it, not a shortcut.
    UINT32 stride_bits = 0;
    if (SUCCEEDED(got->GetUINT32(MF_MT_DEFAULT_STRIDE, &stride_bits)) &&
        stride_bits != 0) {
      cap_stride_ = static_cast<int>(static_cast<INT32>(stride_bits));
    } else {
      cap_stride_ = fmt_ == Fmt::kYuy2   ? cap_w_ * 2
                    : fmt_ == Fmt::kRgb32 ? cap_w_ * 4
                                          : cap_w_;
    }
    return true;
  }

  // Runs on the capture thread, inside the apartment [Start]'s thread body
  // established — and which that body also tears down. Nothing here touches
  // COM setup: one thread, one apartment, one owner.
  void CaptureLoop() {
    int64_t last_us = 0;
    while (running_.load()) {
      DWORD stream_index = 0, flags = 0;
      LONGLONG timestamp = 0;
      ComPtr<IMFSample> sample;
      const HRESULT hr = reader_->ReadSample(
          MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, &stream_index, &flags,
          &timestamp, &sample);
      if (FAILED(hr)) {
        vcam_log("ReadSample failed: 0x%08lx",
                 static_cast<unsigned long>(hr));
        break;
      }
      if ((flags & MF_SOURCE_READERF_ENDOFSTREAM) != 0) break;
      if ((flags & MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED) != 0) {
        // The device renegotiated under us (a format change or a resume from
        // sleep). Re-read the geometry rather than converting the next frame
        // with stale dimensions, which reads past the buffer.
        if (!NegotiateFormat(cap_w_, cap_h_)) break;
      }
      // A null sample with no error is a gap, not a failure: MF returns one
      // whenever the timeout elapses with nothing captured.
      if (!sample) continue;

      const int64_t t = now_us();
      if (cb_ != nullptr && t - last_us >= min_interval_us_) {
        last_us = t;
        Deliver(sample.Get());
      }
    }
  }

  void Deliver(IMFSample* sample) {
    ComPtr<IMFMediaBuffer> buffer;
    if (FAILED(sample->ConvertToContiguousBuffer(&buffer))) return;
    BYTE* data = nullptr;
    DWORD len = 0;
    if (FAILED(buffer->Lock(&data, nullptr, &len)) || data == nullptr) return;

    const int w = cap_w_, h = cap_h_;
    const int cw = (w + 1) / 2, ch = (h + 1) / 2;
    y_.resize(static_cast<size_t>(w) * h);
    u_.resize(static_cast<size_t>(cw) * ch);
    v_.resize(static_cast<size_t>(cw) * ch);

    int rc = -1;
    switch (fmt_) {
      case Fmt::kNv12: {
        const int stride = cap_stride_ > 0 ? cap_stride_ : w;
        // The chroma plane follows the luma plane in a contiguous NV12 buffer.
        const size_t luma = static_cast<size_t>(stride) * h;
        if (len < luma) break;  // truncated sample; drop it
        rc = libyuv::NV12ToI420(data, stride, data + luma, stride, y_.data(), w,
                                u_.data(), cw, v_.data(), cw, w, h);
        break;
      }
      case Fmt::kYuy2: {
        const int stride = cap_stride_ > 0 ? cap_stride_ : w * 2;
        if (len < static_cast<DWORD>(stride) * h) break;
        rc = libyuv::YUY2ToI420(data, stride, y_.data(), w, u_.data(), cw,
                                v_.data(), cw, w, h);
        break;
      }
      case Fmt::kRgb32: {
        // A negative default stride is MF's way of saying bottom-up. libyuv
        // takes that convention directly, so pass the sign through and point
        // at the last row when it is negative.
        const int stride = cap_stride_ != 0 ? cap_stride_ : w * 4;
        const size_t need = static_cast<size_t>(stride < 0 ? -stride : stride) *
                            static_cast<size_t>(h);
        if (len < need) break;
        const uint8_t* src =
            stride < 0 ? data + static_cast<size_t>(-stride) * (h - 1) : data;
        rc = libyuv::ARGBToI420(src, stride, y_.data(), w, u_.data(), cw,
                                v_.data(), cw, w, h);
        break;
      }
      case Fmt::kUnknown:
        break;
    }
    buffer->Unlock();
    if (rc != 0) return;

    if (target_w_ > 0 && w > target_w_) {
      const int ow = target_w_ & ~1;             // even width
      int oh = ((h * ow / w) + 1) & ~1;          // aspect-preserved, even
      if (oh < 2) oh = 2;
      const int ocw = (ow + 1) / 2, och = (oh + 1) / 2;
      sy_.resize(static_cast<size_t>(ow) * oh);
      su_.resize(static_cast<size_t>(ocw) * och);
      sv_.resize(static_cast<size_t>(ocw) * och);
      libyuv::I420Scale(y_.data(), w, u_.data(), cw, v_.data(), cw, w, h,
                        sy_.data(), ow, su_.data(), ocw, sv_.data(), ocw, ow,
                        oh, libyuv::kFilterBilinear);
      cb_(sy_.data(), su_.data(), sv_.data(), ow, oh, ow, ocw, ocw,
          /*ts_us=*/0);
    } else {
      cb_(y_.data(), u_.data(), v_.data(), w, h, w, cw, cw, /*ts_us=*/0);
    }
  }

  CameraFrameCb cb_;
  std::atomic<bool> running_{false};
  std::thread thread_;
  ComPtr<IMFSourceReader> reader_;
  Fmt fmt_ = Fmt::kUnknown;
  int cap_w_ = 0, cap_h_ = 0, cap_stride_ = 0;
  int target_w_ = 0;
  int64_t min_interval_us_ = 0;
  std::vector<uint8_t> y_, u_, v_;     // I420 at capture resolution
  std::vector<uint8_t> sy_, su_, sv_;  // downscaled I420 (encoder input)
};

// Runs on the MF thread only.
std::string EnumerateCamerasJson() {
  ComPtr<IMFAttributes> attrs;
  if (FAILED(MFCreateAttributes(&attrs, 1))) return "[]";
  if (FAILED(attrs->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                            MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID))) {
    return "[]";
  }
  IMFActivate** devices = nullptr;
  UINT32 count = 0;
  if (FAILED(MFEnumDeviceSources(attrs.Get(), &devices, &count))) return "[]";

  std::string out = "[";
  bool first = true;
  for (UINT32 i = 0; i < count; ++i) {
    wchar_t* link = nullptr;
    UINT32 link_len = 0;
    wchar_t* name = nullptr;
    UINT32 name_len = 0;
    const bool has_link = SUCCEEDED(devices[i]->GetAllocatedString(
        MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_SYMBOLIC_LINK, &link,
        &link_len));
    const bool has_name = SUCCEEDED(devices[i]->GetAllocatedString(
        MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME, &name, &name_len));
    if (has_link) {
      if (!first) out.push_back(',');
      first = false;
      out += "{\"id\":";
      append_json_string(out, wide_to_utf8(link, static_cast<int>(link_len)));
      out += ",\"label\":";
      append_json_string(out, has_name ? wide_to_utf8(
                                             name, static_cast<int>(name_len))
                                       : std::string("Camera"));
      out += ",\"kind\":\"camera\",\"facing\":\"external\"}";
    }
    if (has_link) CoTaskMemFree(link);
    if (has_name) CoTaskMemFree(name);
    devices[i]->Release();
  }
  if (devices != nullptr) CoTaskMemFree(devices);
  out.push_back(']');
  return out;
}


}  // namespace

CameraCapturer* CreatePlatformCamera(CameraFrameCb cb) {
  return new MfCameraCapturer(std::move(cb));
}

// Enumeration is Media Foundation work, so it runs on the MF thread — the
// only thread in this module whose apartment is ours. Called from an FFI
// thread it would either fail with CO_E_NOTINITIALIZED or, as it used to,
// silently move that thread to MTA and take the audio device module down
// with it later.
std::string ListPlatformCamerasJson() {
  if (!mf().ok()) return "[]";
  std::string result = "[]";
  mf().Run([&result] { result = EnumerateCamerasJson(); });
  return result;
}


}  // namespace veil_media
