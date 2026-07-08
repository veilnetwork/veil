/* SPDX-License-Identifier: MIT
 *
 * veil_avf_camera.mm — AVCaptureSession-backed CameraCapturer for macOS.
 *
 * Opens the default video camera, requests NV12 output, converts each frame to
 * I420 (libyuv::NV12ToI420) and hands the planes to the CameraFrameCb on the
 * capture serial queue. veil_media_engine.cc pushes those into the VP8 send
 * stream. Camera TCC is granted by the app (AVCaptureDevice prompt) before this
 * runs; if permission is absent startRunning yields no frames (not a crash).
 */
#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <Foundation/Foundation.h>

#include "veil_camera.h"

#include <cstdint>
#include <vector>

#include "third_party/libyuv/include/libyuv/convert.h"  // NV12ToI420
#include "third_party/libyuv/include/libyuv/scale.h"     // I420Scale

// ---- ObjC sample-buffer delegate: NV12 -> I420 -> callback ----------------
@interface VeilCamDelegate : NSObject <AVCaptureVideoDataOutputSampleBufferDelegate> {
 @public
  veil_media::CameraFrameCb cb_;
  int target_w_;             // downscale captured frames to <= this width (0 = off)
  std::vector<uint8_t> y_, u_, v_;     // NV12->I420 at capture resolution
  std::vector<uint8_t> sy_, su_, sv_;  // scaled-down I420 (encoder input)
}
@end

@implementation VeilCamDelegate
- (void)captureOutput:(AVCaptureOutput*)output
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
           fromConnection:(AVCaptureConnection*)connection {
  if (!cb_) return;
  CVImageBufferRef pb = CMSampleBufferGetImageBuffer(sampleBuffer);
  if (!pb) return;
  if (CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly) != kCVReturnSuccess)
    return;
  const int w = (int)CVPixelBufferGetWidth(pb);
  const int h = (int)CVPixelBufferGetHeight(pb);
  const OSType fmt = CVPixelBufferGetPixelFormatType(pb);
  const bool biplanar =
      (fmt == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange ||
       fmt == kCVPixelFormatType_420YpCbCr8BiPlanarFullRange);
  if (w > 0 && h > 0 && biplanar && CVPixelBufferGetPlaneCount(pb) >= 2) {
    const uint8_t* srcY = (const uint8_t*)CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    const int srcYStride = (int)CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
    const uint8_t* srcUV = (const uint8_t*)CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    const int srcUVStride = (int)CVPixelBufferGetBytesPerRowOfPlane(pb, 1);
    const int cw = (w + 1) / 2, ch = (h + 1) / 2;
    y_.resize((size_t)w * h);
    u_.resize((size_t)cw * ch);
    v_.resize((size_t)cw * ch);
    libyuv::NV12ToI420(srcY, srcYStride, srcUV, srcUVStride, y_.data(), w,
                       u_.data(), cw, v_.data(), cw, w, h);

    // Downscale before handing to the encoder: cameras hand us 720p/1080p, but
    // the veil path caps VP8 at a low bitrate (every RTP packet is padded to a
    // 16KB onion cell), so a full-res keyframe fans out into hundreds of cells
    // and adds seconds of latency. Scaling to <= target_w_ (aspect-preserved,
    // even dims) keeps keyframes small and the pipeline responsive.
    if (target_w_ > 0 && w > target_w_) {
      int ow = target_w_ & ~1;                       // even width
      int oh = ((h * ow / w) + 1) & ~1;              // aspect-preserved even height
      if (oh < 2) oh = 2;
      const int ocw = (ow + 1) / 2, och = (oh + 1) / 2;
      sy_.resize((size_t)ow * oh);
      su_.resize((size_t)ocw * och);
      sv_.resize((size_t)ocw * och);
      libyuv::I420Scale(y_.data(), w, u_.data(), cw, v_.data(), cw, w, h,
                        sy_.data(), ow, su_.data(), ocw, sv_.data(), ocw, ow, oh,
                        libyuv::kFilterBilinear);
      cb_(sy_.data(), su_.data(), sv_.data(), ow, oh, ow, ocw, ocw, /*ts_us=*/0);
    } else {
      cb_(y_.data(), u_.data(), v_.data(), w, h, w, cw, cw, /*ts_us=*/0);
    }
  }
  CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
}
@end

namespace veil_media {
namespace {

// Pick a session preset whose resolution is closest to (>=) the request while
// staying small — the veil path caps bitrate, so smaller frames encode cleaner.
NSString* PresetFor(int width) {
  if (width <= 192) return AVCaptureSessionPresetLow;      // ~192x144
  if (width <= 352) return AVCaptureSessionPreset352x288;  // CIF
  return AVCaptureSessionPreset640x480;
}

class AvfCameraCapturer : public CameraCapturer {
 public:
  explicit AvfCameraCapturer(CameraFrameCb cb) : cb_(std::move(cb)) {}
  ~AvfCameraCapturer() override { Stop(); }

  bool Start(int width, int height, int fps) override {
    (void)height;
    (void)fps;
    if (session_) return true;
    @autoreleasepool {
      AVCaptureDevice* dev =
          [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];
      if (!dev) return false;
      NSError* err = nil;
      AVCaptureDeviceInput* input =
          [AVCaptureDeviceInput deviceInputWithDevice:dev error:&err];
      if (!input) return false;

      AVCaptureSession* session = [[AVCaptureSession alloc] init];
      [session beginConfiguration];
      NSString* preset = PresetFor(width);
      if ([session canSetSessionPreset:preset]) session.sessionPreset = preset;
      if ([session canAddInput:input]) [session addInput:input];

      VeilCamDelegate* delegate = [[VeilCamDelegate alloc] init];
      delegate->cb_ = cb_;
      delegate->target_w_ = width;  // downscale capture to this width before encode
      AVCaptureVideoDataOutput* out = [[AVCaptureVideoDataOutput alloc] init];
      out.videoSettings = @{
        (id)kCVPixelBufferPixelFormatTypeKey :
            @(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange)
      };
      out.alwaysDiscardsLateVideoFrames = YES;
      dispatch_queue_t q =
          dispatch_queue_create("network.veil.camera", DISPATCH_QUEUE_SERIAL);
      [out setSampleBufferDelegate:delegate queue:q];
      if ([session canAddOutput:out]) [session addOutput:out];
      [session commitConfiguration];
      [session startRunning];

      session_ = session;
      output_ = out;
      delegate_ = delegate;
      queue_ = q;
    }
    return true;
  }

  void Stop() override {
    @autoreleasepool {
      if (delegate_) delegate_->cb_ = nullptr;  // stop delivering before teardown
      if (session_) {
        [session_ stopRunning];
        if (output_) [session_ removeOutput:output_];
      }
      session_ = nil;
      output_ = nil;
      delegate_ = nil;
      queue_ = nil;
    }
  }

 private:
  CameraFrameCb cb_;
  AVCaptureSession* session_ = nil;
  AVCaptureVideoDataOutput* output_ = nil;
  VeilCamDelegate* delegate_ = nil;
  dispatch_queue_t queue_ = nil;
};

}  // namespace

CameraCapturer* CreatePlatformCamera(CameraFrameCb cb) {
  return new AvfCameraCapturer(std::move(cb));
}

}  // namespace veil_media
