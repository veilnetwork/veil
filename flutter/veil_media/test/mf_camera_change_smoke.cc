/* SPDX-License-Identifier: MIT */
// Exercise the actual production CaptureLoop with real MF media-type objects
// and a controlled reader. No physical source, image, codec or GUI is opened.
#include <cstring>
#define VEIL_MEDIA_MF_CAMERA_TEST
#include "../src/veil_mf_camera.cc"

namespace veil_media {
namespace {
enum class ChangeOutcome { kReadable, kRecovered, kStopped };

class ChangedReader final : public IMFSourceReader {
 public:
  ChangedReader(GUID subtype, UINT32 width, UINT32 height, INT32 stride,
                bool query_fails, bool notify, bool offer_sample, bool refuse,
                DWORD extra_flags = 0, HRESULT read_result = S_OK)
      : subtype_(subtype), width_(width), height_(height), stride_(stride),
        query_fails_(query_fails), notify_(notify), offer_sample_(offer_sample),
        refuse_(refuse), extra_flags_(extra_flags), read_result_(read_result) {
    MFCreateMediaType(&current_);
  }
  ~ChangedReader() { current_->Release(); }
  int sets = 0, reads = 0, after_error = 0;
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void**) override { return E_NOINTERFACE; }
  ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
  ULONG STDMETHODCALLTYPE Release() override { return 1; }
  HRESULT STDMETHODCALLTYPE GetStreamSelection(DWORD, BOOL*) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE SetStreamSelection(DWORD, BOOL) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE GetNativeMediaType(DWORD, DWORD, IMFMediaType**) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE GetCurrentMediaType(DWORD, IMFMediaType** out) override {
    if (reads > 0 && (extra_flags_ & MF_SOURCE_READERF_ERROR)) ++after_error;
    *out = nullptr;
    if (reads > 0 && query_fails_) return E_FAIL;
    *out = current_; current_->AddRef(); return S_OK;
  }
  HRESULT STDMETHODCALLTYPE SetCurrentMediaType(DWORD, DWORD*, IMFMediaType* type) override {
    if (reads > 0 && (extra_flags_ & MF_SOURCE_READERF_ERROR)) ++after_error;
    ++sets;
    if (reads > 0 && refuse_) return MF_E_INVALIDMEDIATYPE;
    current_->DeleteAllItems(); type->CopyAllItems(current_);
    // Initial negotiation succeeds. Later SetCurrentMediaType is also legal,
    // but changes the output AFTER the event already observed by CaptureLoop.
    UINT32 w = 0, h = 0;
    if (FAILED(MFGetAttributeSize(current_, MF_MT_FRAME_SIZE, &w, &h))) {
      MFSetAttributeSize(current_, MF_MT_FRAME_SIZE, 352, 198);
    }
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE SetCurrentPosition(REFGUID, REFPROPVARIANT) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE ReadSample(DWORD, DWORD, DWORD* stream, DWORD* flags,
                                       LONGLONG* timestamp, IMFSample** sample) override {
    if (reads > 0 && (extra_flags_ & MF_SOURCE_READERF_ERROR)) ++after_error;
    ++reads; *stream = 0; *timestamp = 0; *sample = nullptr;
    if (reads == 1) {
      *flags = 0;
      if (FAILED(read_result_)) return read_result_;
      if (!notify_) {
        *flags = MF_SOURCE_READERF_STREAMTICK | extra_flags_;
        return S_OK;
      }
      current_->DeleteAllItems();
      current_->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
      current_->SetGUID(MF_MT_SUBTYPE, subtype_);
      MFSetAttributeSize(current_, MF_MT_FRAME_SIZE, width_, height_);
      current_->SetUINT32(MF_MT_DEFAULT_STRIDE, static_cast<UINT32>(stride_));
      *flags = MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED | extra_flags_;
      if (offer_sample_) {
        // Opaque synthetic bytes, deliberately not an image. The old loop can
        // misroute this changed-type sample into the NV12 converter after it
        // renegotiates the reader. Conversion stand-ins count/refuse that call.
        constexpr DWORD bytes = 352 * 198 * 3 / 2;
        ComPtr<IMFMediaBuffer> buffer;
        if (FAILED(MFCreateMemoryBuffer(bytes, &buffer))) return E_FAIL;
        BYTE* data = nullptr;
        if (FAILED(buffer->Lock(&data, nullptr, nullptr))) return E_FAIL;
        std::memset(data, 0, bytes);
        buffer->Unlock();
        buffer->SetCurrentLength(bytes);
        if (FAILED(MFCreateSample(sample))) return E_FAIL;
        (*sample)->AddBuffer(buffer.Get());
      }
    } else {
      *flags = MF_SOURCE_READERF_ENDOFSTREAM;
    }
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE Flush(DWORD) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE GetServiceForStream(DWORD, REFGUID, REFIID, LPVOID*) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE GetPresentationAttribute(DWORD, REFGUID, PROPVARIANT*) override { return E_NOTIMPL; }
 private:
  GUID subtype_;
  UINT32 width_, height_;
  INT32 stride_;
  bool query_fails_;
  bool notify_, offer_sample_, refuse_;
  DWORD extra_flags_;
  HRESULT read_result_;
  IMFMediaType* current_ = nullptr;
};

struct MfCameraTestPeer {
  static bool BufferLayout(const char* label, GUID subtype, UINT32 width,
                           UINT32 height, INT32 stride, DWORD bytes,
                           bool expected_format, bool expected_conversion,
                           bool deliver = true) {
    ChangedReader reader(subtype, width, height, stride, false, false, false, false);
    ComPtr<IMFMediaType> type;
    reader.GetCurrentMediaType(0, &type);
    type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    type->SetGUID(MF_MT_SUBTYPE, subtype);
    MFSetAttributeSize(type.Get(), MF_MT_FRAME_SIZE, width, height);
    type->SetUINT32(MF_MT_DEFAULT_STRIDE, static_cast<UINT32>(stride));
    MfCameraCapturer camera{CameraFrameCb()};
    *(&camera.reader_) = &reader;
    const bool readable = SUCCEEDED(camera.ReadCurrentFormat());
    libyuv::metadata_conversion_calls = 0;
    if (readable && deliver) {
      // Real MF sample/buffer containing opaque bytes. Stand-ins never read or
      // convert pixels: count whether the production admission reaches libyuv.
      ComPtr<IMFSample> sample;
      ComPtr<IMFMediaBuffer> buffer;
      if (FAILED(MFCreateSample(&sample)) ||
          FAILED(MFCreateMemoryBuffer(bytes, &buffer))) return false;
      BYTE* data = nullptr;
      if (FAILED(buffer->Lock(&data, nullptr, nullptr))) return false;
      std::memset(data, 0, bytes);
      buffer->Unlock();
      buffer->SetCurrentLength(bytes);
      sample->AddBuffer(buffer.Get());
      camera.Deliver(sample.Get());
    }
    camera.reader_.Reset();
    const bool ok = readable == expected_format &&
        libyuv::metadata_conversion_calls == (expected_conversion ? 1 : 0);
    std::printf("%s: %s (format=%d conversions=%d)\n", label,
                ok ? "PASS" : "FAIL", readable ? 1 : 0,
                libyuv::metadata_conversion_calls);
    return ok;
  }

  static bool FatalFlag(bool with_type_change) {
    ChangedReader reader(MFVideoFormat_NV12, 352, 198, 352, false,
                         with_type_change, with_type_change, false,
                         MF_SOURCE_READERF_ERROR);
    MfCameraCapturer camera(CameraFrameCb([](const uint8_t*, const uint8_t*,
        const uint8_t*, int, int, int, int, int, int64_t) {}));
    *(&camera.reader_) = &reader;
    const bool opened = camera.NegotiateFormat(352, 198, 6);
    reader.sets = 0;
    libyuv::metadata_conversion_calls = 0;
    camera.running_.store(true);
    camera.CaptureLoop();
    camera.running_.store(false);
    camera.Stop();
    const auto diagnostic = camera.Diagnostics();
    const bool ok = opened && reader.reads == 1 && reader.sets == 0 &&
                    reader.after_error == 0 && libyuv::metadata_conversion_calls == 0 &&
                    diagnostic.status == 8 && diagnostic.hresult == S_OK &&
                    diagnostic.reads == 1 && diagnostic.samples == 0 &&
                    diagnostic.frames == 0 && diagnostic.dropped == 0;
    camera.reader_.Reset();
    std::printf("fatal flag%s: %s (reads=%d after_error=%d conversions=%d)\n",
                with_type_change ? " with changed sample" : " with null sample",
                ok ? "PASS" : "FAIL", reader.reads, reader.after_error,
                libyuv::metadata_conversion_calls);
    return ok;
  }

  static bool CaptureEvidence(bool failed_read) {
    ChangedReader reader(MFVideoFormat_NV12, 352, 198, 352, false,
                         true, true, false, 0,
                         failed_read ? MF_E_VIDEO_RECORDING_DEVICE_INVALIDATED : S_OK);
    MfCameraCapturer camera(CameraFrameCb([](const uint8_t*, const uint8_t*,
        const uint8_t*, int, int, int, int, int, int64_t) {}));
    *(&camera.reader_) = &reader;
    const bool opened = camera.NegotiateFormat(352, 198, 6);
    libyuv::metadata_conversion_calls = 0;
    camera.running_.store(true);
    camera.CaptureLoop();
    camera.running_.store(false);
    camera.Stop();
    const auto diagnostic = camera.Diagnostics();
    const bool ok = opened && diagnostic.status == (failed_read ? 7 : 9) &&
        diagnostic.hresult == (failed_read
          ? static_cast<uint32_t>(MF_E_VIDEO_RECORDING_DEVICE_INVALIDATED) : 0) &&
        diagnostic.reads == (failed_read ? 1u : 2u) &&
        diagnostic.samples == (failed_read ? 0u : 1u) &&
        diagnostic.frames == 0 && diagnostic.dropped == (failed_read ? 0u : 1u) &&
        libyuv::metadata_conversion_calls == (failed_read ? 0 : 1);
    camera.reader_.Reset();
    std::printf("capture evidence %s: %s\n", failed_read ? "read refusal" : "conversion refusal",
                ok ? "PASS" : "FAIL");
    return ok;
  }

  static bool StoppedEvidence() {
    MfCameraCapturer camera{CameraFrameCb()};
    camera.SetDiagnosticStatus(2);
    camera.Stop();
    const auto diagnostic = camera.Diagnostics();
    const bool ok = diagnostic.status == 3 && diagnostic.hresult == -1 &&
        diagnostic.reads == 0 && diagnostic.samples == 0 &&
        diagnostic.frames == 0 && diagnostic.dropped == 0;
    std::printf("explicit stop evidence: %s\n", ok ? "PASS" : "FAIL");
    return ok;
  }

  static bool MissingSourceEvidence() {
    MfCameraCapturer camera{CameraFrameCb()};
    const bool opened = camera.OpenReader("fixture-nonexistent-camera", 352, 198);
    const auto diagnostic = camera.Diagnostics();
    const bool ok = !opened && diagnostic.status == 4 &&
        diagnostic.hresult == static_cast<uint32_t>(MF_E_NOT_FOUND) &&
        diagnostic.reads == 0 && diagnostic.frames == 0;
    std::printf("missing source evidence: %s (stage=%d has_hresult=%d)\n",
                ok ? "PASS" : "FAIL", diagnostic.status,
                diagnostic.hresult >= 0 ? 1 : 0);
    return ok;
  }

  static bool Run(const char* label, GUID subtype, UINT32 width, UINT32 height,
                  INT32 stride, ChangeOutcome outcome, bool query_fails = false,
                  bool notify = true) {
    const bool readable = outcome == ChangeOutcome::kReadable;
    const bool recovered = outcome == ChangeOutcome::kRecovered;
    ChangedReader reader(subtype, width, height, stride, query_fails, notify,
                         recovered, !readable && !recovered && !query_fails);
    MfCameraCapturer camera(recovered ? CameraFrameCb([](const uint8_t*,
        const uint8_t*, const uint8_t*, int, int, int, int, int, int64_t) {})
                                     : CameraFrameCb());
    *(&camera.reader_) = &reader;
    const bool opened = camera.NegotiateFormat(352, 198, 6);
    reader.sets = 0;
    libyuv::metadata_conversion_calls = 0;
    camera.running_.store(true);
    camera.CaptureLoop();
    camera.running_.store(false);
    const bool refreshed = !readable ||
        (camera.cap_w_ == static_cast<int>(width) &&
         camera.cap_h_ == static_cast<int>(height) && camera.cap_stride_ == stride);
    const bool subtype_matches = !readable ||
        (subtype == MFVideoFormat_NV12 && camera.fmt_ == MfCameraCapturer::Fmt::kNv12) ||
        (subtype == MFVideoFormat_YUY2 && camera.fmt_ == MfCameraCapturer::Fmt::kYuy2) ||
        (subtype == MFVideoFormat_RGB32 && camera.fmt_ == MfCameraCapturer::Fmt::kRgb32);
    const bool recovery_format = !recovered ||
        (camera.cap_w_ == 352 && camera.cap_h_ == 198 && camera.cap_stride_ == 352 &&
         camera.fmt_ == MfCameraCapturer::Fmt::kNv12);
    const auto diagnostic = camera.Diagnostics();
    const bool refusal_diagnosed = outcome != ChangeOutcome::kStopped ||
        (diagnostic.status == 10 &&
         diagnostic.hresult == static_cast<uint32_t>(
             query_fails ? E_FAIL : MF_E_INVALIDMEDIATYPE));
    const int expected_sets = readable ? 0 : (recovered || query_fails ? 1 : 4);
    const bool ok = opened && reader.sets == expected_sets && refreshed &&
                    subtype_matches && recovery_format && refusal_diagnosed &&
                    libyuv::metadata_conversion_calls == 0 &&
                    reader.reads == (readable || recovered ? 2 : 1);
    camera.reader_.Reset();
    std::printf("%s: %s (sets=%d reads=%d conversions=%d evidence=%d)\n", label,
                ok ? "PASS" : "FAIL", reader.sets, reader.reads,
                libyuv::metadata_conversion_calls, refusal_diagnosed ? 1 : 0);
    return ok;
  }
};
}  // namespace
}  // namespace veil_media

int main() {
  int result = 2;
  std::thread([&] {
    if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) return;
    if (FAILED(MFStartup(MF_VERSION))) { CoUninitialize(); return; }
    using veil_media::MfCameraTestPeer;
    using veil_media::ChangeOutcome;
    int failed = 0;
    failed += !MfCameraTestPeer::BufferLayout("NV12 packed layout", MFVideoFormat_NV12,
        4, 4, 4, 24, true, true);
    failed += !MfCameraTestPeer::BufferLayout("NV12 padded layout", MFVideoFormat_NV12,
        4, 4, 8, 48, true, true);
    failed += !MfCameraTestPeer::BufferLayout("YUY2 packed layout", MFVideoFormat_YUY2,
        4, 4, 8, 32, true, true);
    failed += !MfCameraTestPeer::BufferLayout("RGB32 packed layout", MFVideoFormat_RGB32,
        4, 4, 16, 64, true, true);
    failed += !MfCameraTestPeer::BufferLayout("RGB32 bottom-up layout", MFVideoFormat_RGB32,
        4, 4, -16, 64, true, true);
    failed += !MfCameraTestPeer::BufferLayout("NV12 short row", MFVideoFormat_NV12,
        4, 4, 2, 12, false, false);
    failed += !MfCameraTestPeer::BufferLayout("YUY2 short row", MFVideoFormat_YUY2,
        4, 4, 4, 16, false, false);
    failed += !MfCameraTestPeer::BufferLayout("RGB32 short row", MFVideoFormat_RGB32,
        4, 4, 8, 32, false, false);
    failed += !MfCameraTestPeer::BufferLayout("NV12 odd chroma short row", MFVideoFormat_NV12,
        3, 4, 3, 18, false, false);
    failed += !MfCameraTestPeer::BufferLayout("NV12 odd chroma padded row", MFVideoFormat_NV12,
        3, 4, 4, 24, true, true);
    failed += !MfCameraTestPeer::BufferLayout("NV12 truncated chroma", MFVideoFormat_NV12,
        4, 4, 4, 23, true, false);
    failed += !MfCameraTestPeer::BufferLayout("YUY2 truncated rows", MFVideoFormat_YUY2,
        4, 4, 8, 31, true, false);
    failed += !MfCameraTestPeer::BufferLayout("RGB32 truncated rows", MFVideoFormat_RGB32,
        4, 4, 16, 63, true, false);
    // Metadata-only adversarial controls: do not allocate from these sizes on
    // the old implementation. Rejection is checked before calling Deliver.
    failed += !MfCameraTestPeer::BufferLayout("width outside signed conversion API", MFVideoFormat_NV12,
        0x80000000u, 4, 4, 1, false, false, false);
    failed += !MfCameraTestPeer::BufferLayout("height outside signed conversion API", MFVideoFormat_NV12,
        4, 0x80000000u, 4, 1, false, false, false);
    failed += !MfCameraTestPeer::BufferLayout("minimum signed RGB stride", MFVideoFormat_RGB32,
        4, 4, static_cast<INT32>(0x80000000u), 1, false, false, false);
    failed += !MfCameraTestPeer::FatalFlag(false);
    failed += !MfCameraTestPeer::FatalFlag(true);
    failed += !MfCameraTestPeer::CaptureEvidence(true);
    failed += !MfCameraTestPeer::CaptureEvidence(false);
    failed += !MfCameraTestPeer::StoppedEvidence();
    failed += !MfCameraTestPeer::MissingSourceEvidence();
    failed += !MfCameraTestPeer::Run("unchanged stream control", MFVideoFormat_NV12,
                                   352, 198, 352, ChangeOutcome::kReadable, false, false);
    failed += !MfCameraTestPeer::Run("NV12 geometry change", MFVideoFormat_NV12,
                                   640, 480, 640, ChangeOutcome::kReadable);
    failed += !MfCameraTestPeer::Run("YUY2 geometry and stride", MFVideoFormat_YUY2,
                                   320, 240, 672, ChangeOutcome::kReadable);
    failed += !MfCameraTestPeer::Run("RGB32 bottom-up stride", MFVideoFormat_RGB32,
                                   640, 360, -2560, ChangeOutcome::kReadable);
    failed += !MfCameraTestPeer::Run("recovery skips old sample", MFVideoFormat_MJPG,
                                   640, 480, 640, ChangeOutcome::kRecovered);
    failed += !MfCameraTestPeer::Run("unsupported recovery refusal", MFVideoFormat_MJPG,
                                   640, 480, 640, ChangeOutcome::kStopped);
    failed += !MfCameraTestPeer::Run("unreadable type failure", MFVideoFormat_NV12,
                                   640, 480, 640, ChangeOutcome::kStopped, true);
    MFShutdown(); CoUninitialize(); result = failed ? 1 : 0;
  }).join();
  return result;
}
