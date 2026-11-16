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
                bool query_fails, bool notify, bool offer_sample, bool refuse)
      : subtype_(subtype), width_(width), height_(height), stride_(stride),
        query_fails_(query_fails), notify_(notify), offer_sample_(offer_sample),
        refuse_(refuse) {
    MFCreateMediaType(&current_);
  }
  ~ChangedReader() { current_->Release(); }
  int sets = 0, reads = 0;
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void**) override { return E_NOINTERFACE; }
  ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
  ULONG STDMETHODCALLTYPE Release() override { return 1; }
  HRESULT STDMETHODCALLTYPE GetStreamSelection(DWORD, BOOL*) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE SetStreamSelection(DWORD, BOOL) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE GetNativeMediaType(DWORD, DWORD, IMFMediaType**) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE GetCurrentMediaType(DWORD, IMFMediaType** out) override {
    *out = nullptr;
    if (reads > 0 && query_fails_) return E_FAIL;
    *out = current_; current_->AddRef(); return S_OK;
  }
  HRESULT STDMETHODCALLTYPE SetCurrentMediaType(DWORD, DWORD*, IMFMediaType* type) override {
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
    ++reads; *stream = 0; *timestamp = 0; *sample = nullptr;
    if (reads == 1) {
      if (!notify_) {
        *flags = MF_SOURCE_READERF_STREAMTICK;
        return S_OK;
      }
      current_->DeleteAllItems();
      current_->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
      current_->SetGUID(MF_MT_SUBTYPE, subtype_);
      MFSetAttributeSize(current_, MF_MT_FRAME_SIZE, width_, height_);
      current_->SetUINT32(MF_MT_DEFAULT_STRIDE, static_cast<UINT32>(stride_));
      *flags = MF_SOURCE_READERF_CURRENTMEDIATYPECHANGED;
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
  IMFMediaType* current_ = nullptr;
};

struct MfCameraTestPeer {
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
    const bool opened = camera.NegotiateFormat(352, 198);
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
    const int expected_sets = readable ? 0 : (recovered || query_fails ? 1 : 4);
    const bool ok = opened && reader.sets == expected_sets && refreshed &&
                    subtype_matches && recovery_format &&
                    libyuv::metadata_conversion_calls == 0 &&
                    reader.reads == (readable || recovered ? 2 : 1);
    camera.reader_.Reset();
    std::printf("%s: %s (sets=%d reads=%d conversions=%d)\n", label,
                ok ? "PASS" : "FAIL", reader.sets, reader.reads,
                libyuv::metadata_conversion_calls);
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
