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
 * Source Reader can decode compressed capture formats and its basic video
 * processor supports YUV -> RGB32 conversion. It does not promise resizing or
 * arbitrary conversion to NV12. Negotiate an uncompressed output independently
 * of our target geometry when the exact NV12 request fails; scale in libyuv.
 *
 * Pure C++ + libyuv (already inside libwebrtc.a) — no WebRTC types.
 *
 * Native capture is qualified separately from transport/remote rendering;
 * camera enumeration alone is not proof that frames can be captured.
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
#include "veil_mf_camera_format.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <functional>
#include <limits>
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

  HRESULT startup_result() const { return startup_result_.load(); }

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
    HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(result)) {
      vcam_log("CoInitializeEx(MTA) failed on the MF thread");
    } else {
      result = MFStartup(MF_VERSION, MFSTARTUP_LITE);
      if (FAILED(result)) vcam_log("MFStartup failed — no camera on this host");
    }
    startup_result_.store(result);
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
  std::atomic<HRESULT> startup_result_{E_UNEXPECTED};
};

// LEAKED ON PURPOSE — see the same note on `adm_host_thread()`.
//
// `Serve()` above says "the object is never destroyed", and as a by-value
// function-local static that was simply false: every member here is
// non-trivially destructible, so the compiler registered `~MfPlatform` for
// exit and it ran against a detached thread waiting on `task_cv_` under
// `m_`. The pointer form registers no destructor, which is the lifetime the
// comment always claimed.
MfPlatform& mf() {
  static MfPlatform* const instance = new MfPlatform();
  return *instance;
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
// empty. Keep the native failure distinct from a missing device.
HRESULT activate_source(const std::wstring& symlink, IMFMediaSource** source) {
  ComPtr<IMFAttributes> attrs;
  HRESULT hr = MFCreateAttributes(&attrs, 1);
  if (FAILED(hr)) return hr;
  hr = attrs->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                      MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
  if (FAILED(hr)) return hr;
  IMFActivate** devices = nullptr;
  UINT32 count = 0;
  hr = MFEnumDeviceSources(attrs.Get(), &devices, &count);
  if (FAILED(hr) || count == 0) {
    if (devices != nullptr) CoTaskMemFree(devices);
    vcam_log("no video capture devices");
    return FAILED(hr) ? hr : MF_E_NOT_FOUND;
  }

  HRESULT activation = MF_E_NOT_FOUND;
  for (UINT32 i = 0; i < count; ++i) {
    if (*source == nullptr) {
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
      if (match) {
        activation = devices[i]->ActivateObject(IID_PPV_ARGS(source));
        if (FAILED(activation)) {
          vcam_log("camera: source activation refused (0x%08lx)",
                   static_cast<unsigned long>(activation));
          *source = nullptr;
        } else if (*source == nullptr) {
          activation = E_UNEXPECTED;
        }
      }
    }
    devices[i]->Release();
  }
  CoTaskMemFree(devices);
  if (*source == nullptr && !symlink.empty()) {
    vcam_log("camera: selected source unavailable");
  }
  return activation;
}

class MfCameraCapturer : public CameraCapturer {
#if defined(VEIL_MEDIA_MF_CAMERA_TEST)
  friend struct MfCameraTestPeer;
#endif
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
    // A PREVIOUS run that ended on its own. [CaptureLoop] returns without
    // anybody asking when the device is invalidated, when the stream ends, or
    // when a renegotiated format cannot be read, and the thread then finishes
    // — but stays JOINABLE. Assigning over a joinable `std::thread` below is
    // `std::terminate`, so the corpse has to be reaped first.
    if (thread_.joinable()) thread_.join();
    {
      std::lock_guard<std::mutex> lock(diagnostic_mutex_);
      diagnostic_ = {};
      diagnostic_.status = 1;
    }
    const HRESULT platform_result = mf().startup_result();
    if (FAILED(platform_result)) {
      SetDiagnosticStatus(5, static_cast<uint32_t>(platform_result));
      return false;
    }
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
      const HRESULT com_result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
      const bool com_ok = SUCCEEDED(com_result);
      if (!com_ok) SetDiagnosticStatus(5, static_cast<uint32_t>(com_result));
      if (!com_ok) vcam_log("CoInitializeEx(MTA) failed on the capture thread");
      const bool ok = com_ok && OpenReader(device, width, height);
      {
        std::lock_guard<std::mutex> lock(m);
        opened = ok;
        settled = true;
      }
      cv.notify_one();
      if (ok) CaptureLoop();
      // CAPTURE HAS ENDED, and not necessarily because anyone asked. The loop
      // also returns when ReadSample fails, when the stream ends, or when a
      // format renegotiation cannot be read — and `running_` was left standing
      // in all three. `Start` answers `true` on that flag, so a camera that
      // had stopped reported itself as already running: video could never come
      // back for the life of this capturer, and the caller was told the
      // restart had worked.
      //
      // Measured on a Windows 11 ARM64 stand, 2026-09-05: disabling the camera
      // mid-capture returns MF_E_VIDEO_RECORDING_DEVICE_INVALIDATED
      // (0xc00d3ea2) from a pending synchronous ReadSample in 292 ms, so this
      // is the ordinary unplug, not a corner. With the flag left set, a
      // restart after the device came back captured zero frames and said it
      // had succeeded; with it cleared, video comes back.
      running_.store(false);
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

  bool Capturing() const override { return running_.load(); }

  CameraCaptureDiagnostics Diagnostics() const override {
    std::lock_guard<std::mutex> lock(diagnostic_mutex_);
    return diagnostic_;
  }

  void Stop() override {
    running_.store(false);
    // The thread releases the reader itself. Doing it here would touch a COM
    // object from a thread in another apartment — the very thing this class
    // now exists to avoid.
    if (thread_.joinable()) thread_.join();
    std::lock_guard<std::mutex> lock(diagnostic_mutex_);
    // An explicit stop must not erase the terminal cause of an earlier exit.
    if (diagnostic_.status == 1 || diagnostic_.status == 2) {
      diagnostic_.status = 3;
      diagnostic_.hresult = -1;
    }
  }

 private:
  void SetDiagnosticStatus(int status, int64_t hresult = -1) {
    std::lock_guard<std::mutex> lock(diagnostic_mutex_);
    diagnostic_.status = status;
    diagnostic_.hresult = hresult;
  }

  // Everything Media Foundation, on the capture thread. Returns false with
  // nothing held.
  bool OpenReader(const std::string& device, int width, int height) {
    ComPtr<IMFMediaSource> source;
    // utf8_to_wide answers an empty string for both nullptr and "", and
    // activate_source reads an empty symlink as "the first camera".
    HRESULT hr = activate_source(utf8_to_wide(device.c_str()), &source);
    if (FAILED(hr)) {
      SetDiagnosticStatus(4, static_cast<uint32_t>(hr));
      return false;
    }

    // Enable the basic YUV -> RGB32 fallback, without depending on advanced
    // video processors or asking Media Foundation to resize camera modes.
    ComPtr<IMFAttributes> reader_attrs;
    hr = MFCreateAttributes(&reader_attrs, 1);
    if (SUCCEEDED(hr)) hr = reader_attrs->SetUINT32(
        MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, TRUE);
    if (FAILED(hr)) {
      SetDiagnosticStatus(5, static_cast<uint32_t>(hr));
      return false;
    }
    hr = MFCreateSourceReaderFromMediaSource(
        source.Get(), reader_attrs.Get(), &reader_);
    if (FAILED(hr)) {
      SetDiagnosticStatus(5, static_cast<uint32_t>(hr));
      vcam_log("MFCreateSourceReaderFromMediaSource failed");
      return false;
    }
    if (!NegotiateFormat(width, height, 6)) {
      reader_.Reset();
      return false;
    }
    SetDiagnosticStatus(2);
    return true;
  }

  enum class Fmt { kUnknown, kNv12, kYuy2, kRgb32 };

  // Prefer exact NV12, then negotiate a readable format at camera geometry.
  // Read back dimensions/stride instead of assuming the request was honoured.
  bool NegotiateFormat(int width, int height, int failure_status) {
    HRESULT hr = mf_camera::RequestCaptureFormat(reader_.Get(), width, height);
    if (FAILED(hr)) {
      // Some systems have no suitable decoder/converter. An unchanged native
      // format is still usable if the conversion branches below support it.
      vcam_log("uncompressed capture requests refused (0x%08lx) — inspecting native format",
               static_cast<unsigned long>(hr));
    }
    hr = ReadCurrentFormat();
    if (FAILED(hr)) {
      SetDiagnosticStatus(failure_status, static_cast<uint32_t>(hr));
      return false;
    }
    return true;
  }

  // Observe the output type describing the sample just returned by ReadSample.
  // Re-requesting the old profile here would change the reader for FUTURE
  // samples, while interpreting the current one with that new geometry/stride.
  // Negotiation for a future sample remains separate from this observation.
  HRESULT ReadCurrentFormat() {
    ComPtr<IMFMediaType> got;
    HRESULT hr = reader_->GetCurrentMediaType(
        static_cast<DWORD>(MF_SOURCE_READER_FIRST_VIDEO_STREAM), &got);
    if (FAILED(hr)) return hr;
    // Not GUID_NULL: that name is an extern defined in uuid.lib, and pulling a
    // library in for a zeroed struct is a link error waiting for the one build
    // that does not happen to already carry it.
    GUID subtype = {};
    hr = got->GetGUID(MF_MT_SUBTYPE, &subtype);
    if (FAILED(hr)) return hr;
    Fmt format = Fmt::kUnknown;
    if (subtype == MFVideoFormat_NV12) {
      format = Fmt::kNv12;
    } else if (subtype == MFVideoFormat_YUY2) {
      format = Fmt::kYuy2;
    } else if (subtype == MFVideoFormat_RGB32 ||
               subtype == MFVideoFormat_ARGB32) {
      format = Fmt::kRgb32;
    } else {
      vcam_log("unsupported capture subtype; no local video");
      return MF_E_INVALIDMEDIATYPE;
    }

    UINT32 w = 0, h = 0;
    hr = MFGetAttributeSize(got.Get(), MF_MT_FRAME_SIZE, &w, &h);
    if (FAILED(hr)) return hr;
    if (w == 0 || h == 0 ||
        w > static_cast<UINT32>((std::numeric_limits<int>::max)()) ||
        h > static_cast<UINT32>((std::numeric_limits<int>::max)())) {
      return MF_E_INVALIDMEDIATYPE;
    }
    // libyuv receives signed dimensions/strides. A source must have room for
    // the whole row, including the final UV pair of an odd-width YUV image.
    // A stride-sized buffer is not safe if the converter reads a wider row.
    const uint64_t chroma_width = (static_cast<uint64_t>(w) + 1) / 2;
    const uint64_t minimum_stride = format == Fmt::kNv12 ? chroma_width * 2
        : format == Fmt::kYuy2 ? chroma_width * 4
                              : static_cast<uint64_t>(w) * 4;
    if (minimum_stride > static_cast<uint64_t>((std::numeric_limits<int>::max)())) {
      return MF_E_INVALIDMEDIATYPE;
    }

    // MF_MT_DEFAULT_STRIDE is optional and often absent on capture types. The
    // packed default is right for a contiguous buffer, which is what
    // ConvertToContiguousBuffer hands us. Negative strides mean bottom-up
    // RGB — handled at conversion time, so keep the sign.
    //
    // The attribute is stored as UINT32 holding a signed value, and
    // IMFAttributes has no GetINT32 at all — the round-trip through UINT32 is
    // the documented way to read it, not a shortcut.
    UINT32 stride_bits = 0;
    int64_t stride = static_cast<int64_t>(minimum_stride);
    if (SUCCEEDED(got->GetUINT32(MF_MT_DEFAULT_STRIDE, &stride_bits)) &&
        stride_bits != 0) {
      stride = static_cast<INT32>(stride_bits);
    }
    const uint64_t absolute_stride = static_cast<uint64_t>(stride < 0 ? -stride : stride);
    if (absolute_stride < minimum_stride ||
        absolute_stride > static_cast<uint64_t>((std::numeric_limits<int>::max)())) {
      return MF_E_INVALIDMEDIATYPE;
    }
    // Publish only a fully checked layout. Failed observation must not poison
    // the previous geometry used by bounded format-recovery negotiation.
    fmt_ = format;
    cap_w_ = static_cast<int>(w);
    cap_h_ = static_cast<int>(h);
    cap_stride_ = static_cast<int>(stride);
    return S_OK;
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
          static_cast<DWORD>(MF_SOURCE_READER_FIRST_VIDEO_STREAM), 0,
          &stream_index, &flags, &timestamp, &sample);
      {
        std::lock_guard<std::mutex> lock(diagnostic_mutex_);
        ++diagnostic_.reads;
      }
      if (FAILED(hr)) {
        SetDiagnosticStatus(7, static_cast<uint32_t>(hr));
        vcam_log("ReadSample failed: 0x%08lx",
                 static_cast<unsigned long>(hr));
        break;
      }
      if ((flags & MF_SOURCE_READERF_ERROR) != 0) {
        SetDiagnosticStatus(8, static_cast<uint32_t>(hr));
        // This flag invalidates the reader even when ReadSample returned S_OK.
        // Do not query a changed type, convert its sample or ask for another
        // frame after a fatal reader event. The owning thread retires capture
        // and clears running_ through its normal teardown after this return.
        vcam_log("ReadSample reported a fatal source-reader flag");
        break;
      }
      if ((flags & MF_SOURCE_READERF_ENDOFSTREAM) != 0) {
        SetDiagnosticStatus(9, static_cast<uint32_t>(hr));
        break;
      }
      if ((flags & MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED) != 0) {
        // The device renegotiated under us (a format change or a resume from
        // sleep). Re-read the geometry rather than converting the next frame
        // with stale dimensions, which reads past the buffer.
        if (FAILED(ReadCurrentFormat())) {
          // Preserve the existing converter recovery for an unreadable output,
          // but discard THIS sample: it predates the newly negotiated format.
          // Only a subsequent ReadSample may use those conversion parameters.
          if (!NegotiateFormat(cap_w_, cap_h_, 10)) break;
          continue;
        }
      }
      // A null sample with no error is a gap, not a failure: MF returns one
      // whenever the timeout elapses with nothing captured.
      if (!sample) continue;
      {
        std::lock_guard<std::mutex> lock(diagnostic_mutex_);
        ++diagnostic_.samples;
      }

      const int64_t t = now_us();
      if (cb_ != nullptr && t - last_us >= min_interval_us_) {
        last_us = t;
        const bool delivered = Deliver(sample.Get());
        std::lock_guard<std::mutex> lock(diagnostic_mutex_);
        if (delivered) ++diagnostic_.frames;
        else ++diagnostic_.dropped;
      }
    }
  }

  bool Deliver(IMFSample* sample) {
    ComPtr<IMFMediaBuffer> buffer;
    if (FAILED(sample->ConvertToContiguousBuffer(&buffer))) return false;
    BYTE* data = nullptr;
    DWORD len = 0;
    if (FAILED(buffer->Lock(&data, nullptr, &len))) return false;
    if (data == nullptr) {
      buffer->Unlock();
      return false;
    }

    const int w = cap_w_, h = cap_h_;
    const int cw = w / 2 + w % 2, ch = h / 2 + h % 2;
    const int stride = fmt_ == Fmt::kRgb32 ? cap_stride_
        : cap_stride_ > 0 ? cap_stride_
        : fmt_ == Fmt::kYuy2 ? cw * 4 : cw * 2;
    const uint64_t absolute_stride = static_cast<uint64_t>(
        stride < 0 ? -static_cast<int64_t>(stride) : stride);
    const uint64_t rows = static_cast<uint64_t>(h) + (fmt_ == Fmt::kNv12 ? ch : 0);
    // Check source extent in wide arithmetic BEFORE allocating I420 planes.
    // The old packed-YUY2 DWORD product could wrap and admit a short buffer.
    if (absolute_stride * rows > len) {
      buffer->Unlock();
      return false;
    }
    y_.resize(static_cast<size_t>(w) * h);
    u_.resize(static_cast<size_t>(cw) * ch);
    v_.resize(static_cast<size_t>(cw) * ch);

    int rc = -1;
    switch (fmt_) {
      case Fmt::kNv12: {
        // The chroma plane follows the luma plane in a contiguous NV12 buffer,
        // interleaved UV at the same stride over half the rows.
        const size_t luma = static_cast<size_t>(stride) * h;
        // The common extent check covers both luma and interleaved chroma.
        rc = libyuv::NV12ToI420(data, stride, data + luma, stride, y_.data(), w,
                                u_.data(), cw, v_.data(), cw, w, h);
        break;
      }
      case Fmt::kYuy2: {
        rc = libyuv::YUY2ToI420(data, stride, y_.data(), w, u_.data(), cw,
                                v_.data(), cw, w, h);
        break;
      }
      case Fmt::kRgb32: {
        // A negative default stride is MF's way of saying bottom-up. libyuv
        // takes that convention directly, so pass the sign through and point
        // at the last row when it is negative.
        const uint8_t* src =
            stride < 0 ? data + static_cast<size_t>(absolute_stride) * (h - 1) : data;
        rc = libyuv::ARGBToI420(src, stride, y_.data(), w, u_.data(), cw,
                                v_.data(), cw, w, h);
        break;
      }
      case Fmt::kUnknown:
        break;
    }
    buffer->Unlock();
    if (rc != 0) return false;

    if (target_w_ > 0 && w > target_w_) {
      const int ow = target_w_ & ~1;             // even width
      int oh = static_cast<int>(((static_cast<int64_t>(h) * ow / w) + 1) & ~int64_t{1});
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
    return true;
  }

  CameraFrameCb cb_;
  mutable std::mutex diagnostic_mutex_;
  CameraCaptureDiagnostics diagnostic_;
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
  if (FAILED(mf().startup_result())) return "[]";
  std::string result = "[]";
  mf().Run([&result] { result = EnumerateCamerasJson(); });
  return result;
}


}  // namespace veil_media
