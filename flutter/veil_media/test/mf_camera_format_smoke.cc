/* SPDX-License-Identifier: MIT */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <mferror.h>
#include <cstdio>
#include <vector>
#include <thread>

#include "veil_mf_camera_format.h"

namespace {
struct Attempt { GUID subtype; bool sized; UINT32 width, height; };

// Models a camera whose native default is compressed MJPEG. A refused exact
// size leaves that default in place; our I420 converter cannot consume it.
class Reader final : public IMFSourceReader {
 public:
  Reader(GUID accepted, bool exact) : accepted_(accepted), exact_(exact) {
    MFCreateMediaType(&current_);
    current_->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    current_->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_MJPG);
    MFSetAttributeSize(current_, MF_MT_FRAME_SIZE, 1280, 720);
  }
  ~Reader() { current_->Release(); }
  std::vector<Attempt> attempts;
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void**) override { return E_NOINTERFACE; }
  ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
  ULONG STDMETHODCALLTYPE Release() override { return 1; }
  HRESULT STDMETHODCALLTYPE GetStreamSelection(DWORD, BOOL*) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE SetStreamSelection(DWORD, BOOL) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE GetNativeMediaType(DWORD, DWORD, IMFMediaType**) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE GetCurrentMediaType(DWORD stream, IMFMediaType** out) override {
    if (stream != static_cast<DWORD>(MF_SOURCE_READER_FIRST_VIDEO_STREAM)) return E_INVALIDARG;
    *out = current_; current_->AddRef(); return S_OK;
  }
  HRESULT STDMETHODCALLTYPE SetCurrentMediaType(DWORD stream, DWORD*, IMFMediaType* type) override {
    if (stream != static_cast<DWORD>(MF_SOURCE_READER_FIRST_VIDEO_STREAM)) return E_INVALIDARG;
    GUID major = {}, subtype = {}; UINT32 w = 0, h = 0;
    if (FAILED(type->GetGUID(MF_MT_MAJOR_TYPE, &major)) || major != MFMediaType_Video ||
        FAILED(type->GetGUID(MF_MT_SUBTYPE, &subtype))) return E_INVALIDARG;
    const bool sized = SUCCEEDED(MFGetAttributeSize(type, MF_MT_FRAME_SIZE, &w, &h));
    attempts.push_back({subtype, sized, w, h});
    if (subtype != accepted_ || sized != exact_) return MF_E_INVALIDMEDIATYPE;
    current_->DeleteAllItems(); type->CopyAllItems(current_);
    if (!sized) MFSetAttributeSize(current_, MF_MT_FRAME_SIZE, 1280, 720);
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE SetCurrentPosition(REFGUID, REFPROPVARIANT) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE ReadSample(DWORD, DWORD, DWORD*, DWORD*, LONGLONG*, IMFSample**) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE Flush(DWORD) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE GetServiceForStream(DWORD, REFGUID, REFIID, LPVOID*) override { return E_NOTIMPL; }
  HRESULT STDMETHODCALLTYPE GetPresentationAttribute(DWORD, REFGUID, PROPVARIANT*) override { return E_NOTIMPL; }
 private:
  GUID accepted_;
  bool exact_;
  IMFMediaType* current_ = nullptr;
};

bool select(const char* name, GUID subtype, bool exact, size_t calls) {
  Reader reader(subtype, exact);
  const HRESULT hr = veil_media::mf_camera::RequestCaptureFormat(&reader, 352, 198);
  IMFMediaType* got = nullptr;
  reader.GetCurrentMediaType(static_cast<DWORD>(MF_SOURCE_READER_FIRST_VIDEO_STREAM), &got);
  GUID actual = {}; UINT32 w = 0, h = 0;
  got->GetGUID(MF_MT_SUBTYPE, &actual);
  MFGetAttributeSize(got, MF_MT_FRAME_SIZE, &w, &h); got->Release();
  const bool first = !reader.attempts.empty() && reader.attempts[0].sized &&
      reader.attempts[0].width == 352 && reader.attempts[0].height == 198;
  bool fallback_unsized = true;
  for (size_t i = 1; i < reader.attempts.size(); ++i) {
    fallback_unsized &= !reader.attempts[i].sized;
  }
  const bool ok = SUCCEEDED(hr) && actual == subtype && first &&
      fallback_unsized && reader.attempts.size() == calls &&
      w == (exact ? 352u : 1280u) && h == (exact ? 198u : 720u);
  std::printf("%s: %s\n", name, ok ? "PASS" : "FAIL"); return ok;
}
}

int RunFormatFixture() {
  if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) return 2;
  if (FAILED(MFStartup(MF_VERSION))) return 2;
  int failed = 0;
  failed += !select("exact NV12 remains first", MFVideoFormat_NV12, true, 1);
  failed += !select("NV12 with camera geometry", MFVideoFormat_NV12, false, 2);
  failed += !select("YUY2 fallback", MFVideoFormat_YUY2, false, 3);
  failed += !select("RGB32 converter fallback", MFVideoFormat_RGB32, false, 4);
  {
    Reader refused(MFVideoFormat_MJPG, false);
    const HRESULT hr = veil_media::mf_camera::RequestCaptureFormat(&refused, 352, 198);
    const bool bounded = FAILED(hr) && refused.attempts.size() == 4;
    std::printf("bounded refusal: %s\n", bounded ? "PASS" : "FAIL");
    failed += !bounded;
  }
  std::printf("failed=%d\n", failed);
  MFShutdown(); CoUninitialize(); return failed ? 1 : 0;
}

int main() {
  int result = 2;
  // Exercise COM and Media Foundation on an explicitly owned thread, using
  // the same ownership rule as the production capture backend.
  std::thread([&] { result = RunFormatFixture(); }).join();
  return result;
}
