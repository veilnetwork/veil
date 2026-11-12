/* SPDX-License-Identifier: MIT */
#ifndef VEIL_MEDIA_MF_CAMERA_FORMAT_H_
#define VEIL_MEDIA_MF_CAMERA_FORMAT_H_

#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>

namespace veil_media::mf_camera {

inline HRESULT RequestFormat(IMFSourceReader* reader, const GUID& subtype,
                             int width, int height) {
  IMFMediaType* type = nullptr;
  HRESULT hr = MFCreateMediaType(&type);
  if (FAILED(hr)) return hr;
  hr = type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
  if (SUCCEEDED(hr)) hr = type->SetGUID(MF_MT_SUBTYPE, subtype);
  if (SUCCEEDED(hr) && width > 0 && height > 0) {
    hr = MFSetAttributeSize(type, MF_MT_FRAME_SIZE,
                            static_cast<UINT32>(width),
                            static_cast<UINT32>(height));
  }
  if (SUCCEEDED(hr)) {
    hr = reader->SetCurrentMediaType(static_cast<DWORD>(MF_SOURCE_READER_FIRST_VIDEO_STREAM),
                                      nullptr, type);
  }
  type->Release();
  return hr;
}

inline HRESULT RequestCaptureFormat(IMFSourceReader* reader, int width,
                                    int height) {
  HRESULT hr = RequestFormat(reader, MFVideoFormat_NV12, width, height);
  if (SUCCEEDED(hr)) return hr;
  // Source Reader's basic video processing does not resize camera modes.
  // Refusing our send profile's dimensions must not strand the reader in a
  // compressed native default (e.g. MJPEG), which our I420 path cannot read.
  // Keep the selected device and let it supply its supported geometry; the
  // capturer already scales after conversion. RGB32 is the basic processor's
  // documented YUV conversion output when NV12/YUY2 cannot be negotiated.
  const GUID* formats[] = {
      &MFVideoFormat_NV12, &MFVideoFormat_YUY2, &MFVideoFormat_RGB32};
  for (const GUID* format : formats) {
    hr = RequestFormat(reader, *format, 0, 0);
    if (SUCCEEDED(hr)) return hr;
  }
  // Caller can still inspect a supported, unchanged native default. Never
  // hand compressed bytes to the uncompressed frame converter.
  return hr;
}

}  // namespace veil_media::mf_camera
#endif
