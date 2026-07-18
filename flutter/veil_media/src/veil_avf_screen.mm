/* SPDX-License-Identifier: MIT
 *
 * veil_avf_screen.mm — AVCaptureScreenInput-backed ScreenCapturer for macOS.
 *
 * Mirrors veil_avf_camera.mm: one AVCaptureSession whose input is the main
 * display instead of a camera device. Frames arrive as NV12 (requested) or
 * BGRA (the screen input's native format when conversion is unavailable),
 * are converted to I420 with libyuv, downscaled to the requested width (a
 * Retina display is 2560+ px wide — the veil path pads every RTP packet to a
 * 16KB onion cell, so full-res keyframes would fan out into hundreds of
 * cells), and handed to the CameraFrameCb on the capture serial queue.
 *
 * Screen Recording TCC: the FIRST capture attempt makes the OS show the
 * consent prompt (and requires an app restart after granting). Until granted
 * the session runs but delivers no frames — callers see a started-but-black
 * share, not a crash.
 */
#import <AVFoundation/AVFoundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <Foundation/Foundation.h>

#include "veil_screen.h"

#include <cstdint>
#include <vector>

#include "third_party/libyuv/include/libyuv/convert.h"  // NV12ToI420, ARGBToI420
#include "third_party/libyuv/include/libyuv/scale.h"    // I420Scale

// ---- ObjC sample-buffer delegate: NV12/BGRA -> I420 -> downscale -> cb ----
@interface VeilScreenDelegate
    : NSObject <AVCaptureVideoDataOutputSampleBufferDelegate> {
 @public
  veil_media::CameraFrameCb cb_;
  int target_w_;  // downscale captured frames to <= this width (0 = off)
  std::vector<uint8_t> y_, u_, v_;     // I420 at capture resolution
  std::vector<uint8_t> sy_, su_, sv_;  // scaled-down I420 (encoder input)
}
@end

@implementation VeilScreenDelegate
- (void)captureOutput:(AVCaptureOutput*)output
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
           fromConnection:(AVCaptureConnection*)connection {
  if (!cb_) return;
  CVImageBufferRef pb = CMSampleBufferGetImageBuffer(sampleBuffer);
  if (!pb) return;
  if (CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly) !=
      kCVReturnSuccess) {
    return;
  }
  const int w = (int)CVPixelBufferGetWidth(pb);
  const int h = (int)CVPixelBufferGetHeight(pb);
  const OSType fmt = CVPixelBufferGetPixelFormatType(pb);
  bool have_i420 = false;
  if (w > 0 && h > 0) {
    const int cw = (w + 1) / 2, ch = (h + 1) / 2;
    if ((fmt == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange ||
         fmt == kCVPixelFormatType_420YpCbCr8BiPlanarFullRange) &&
        CVPixelBufferGetPlaneCount(pb) >= 2) {
      const uint8_t* srcY =
          (const uint8_t*)CVPixelBufferGetBaseAddressOfPlane(pb, 0);
      const int srcYStride = (int)CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
      const uint8_t* srcUV =
          (const uint8_t*)CVPixelBufferGetBaseAddressOfPlane(pb, 1);
      const int srcUVStride = (int)CVPixelBufferGetBytesPerRowOfPlane(pb, 1);
      y_.resize((size_t)w * h);
      u_.resize((size_t)cw * ch);
      v_.resize((size_t)cw * ch);
      libyuv::NV12ToI420(srcY, srcYStride, srcUV, srcUVStride, y_.data(), w,
                         u_.data(), cw, v_.data(), cw, w, h);
      have_i420 = true;
    } else if (fmt == kCVPixelFormatType_32BGRA) {
      // The screen input's native format when the output can't convert.
      // libyuv's "ARGB" is byte order B,G,R,A little-endian == CV 32BGRA.
      const uint8_t* src = (const uint8_t*)CVPixelBufferGetBaseAddress(pb);
      const int srcStride = (int)CVPixelBufferGetBytesPerRow(pb);
      y_.resize((size_t)w * h);
      u_.resize((size_t)cw * ch);
      v_.resize((size_t)cw * ch);
      libyuv::ARGBToI420(src, srcStride, y_.data(), w, u_.data(), cw,
                         v_.data(), cw, w, h);
      have_i420 = true;
    }
    if (have_i420) {
      if (target_w_ > 0 && w > target_w_) {
        int ow = target_w_ & ~1;           // even width
        int oh = ((h * ow / w) + 1) & ~1;  // aspect-preserved even height
        if (oh < 2) oh = 2;
        const int ocw = (ow + 1) / 2, och = (oh + 1) / 2;
        sy_.resize((size_t)ow * oh);
        su_.resize((size_t)ocw * och);
        sv_.resize((size_t)ocw * och);
        libyuv::I420Scale(y_.data(), w, u_.data(), cw, v_.data(), cw, w, h,
                          sy_.data(), ow, su_.data(), ocw, sv_.data(), ocw,
                          ow, oh, libyuv::kFilterBilinear);
        cb_(sy_.data(), su_.data(), sv_.data(), ow, oh, ow, ocw, ocw,
            /*ts_us=*/0);
      } else {
        cb_(y_.data(), u_.data(), v_.data(), w, h, w, cw, cw, /*ts_us=*/0);
      }
    }
  }
  CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
}
@end

namespace veil_media {
namespace {

class AvfScreenCapturer : public ScreenCapturer {
 public:
  explicit AvfScreenCapturer(CameraFrameCb cb) : cb_(std::move(cb)) {}
  ~AvfScreenCapturer() override { Stop(); }

  bool Start(int width, int fps) override {
    if (session_) return true;
    if (fps <= 0) fps = 10;
    @autoreleasepool {
      AVCaptureScreenInput* input = [[AVCaptureScreenInput alloc]
          initWithDisplayID:CGMainDisplayID()];
      if (input == nil) return false;
      input.minFrameDuration = CMTimeMake(1, fps);
      input.capturesCursor = YES;

      AVCaptureSession* session = [[AVCaptureSession alloc] init];
      [session beginConfiguration];
      if ([session canAddInput:input]) [session addInput:input];

      VeilScreenDelegate* delegate = [[VeilScreenDelegate alloc] init];
      delegate->cb_ = cb_;
      delegate->target_w_ = width;
      AVCaptureVideoDataOutput* out = [[AVCaptureVideoDataOutput alloc] init];
      out.videoSettings = @{
        (id)kCVPixelBufferPixelFormatTypeKey :
            @(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange)
      };
      out.alwaysDiscardsLateVideoFrames = YES;
      dispatch_queue_t q =
          dispatch_queue_create("network.veil.screen", DISPATCH_QUEUE_SERIAL);
      [out setSampleBufferDelegate:delegate queue:q];
      if ([session canAddOutput:out]) [session addOutput:out];
      [session commitConfiguration];
      session_ = session;
      output_ = out;
      delegate_ = delegate;
      queue_ = q;
      // startRunning blocks (and triggers the Screen Recording TCC prompt on
      // first use) — keep it off the FFI/UI thread, same as the camera.
      dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
          if (session_ == session) [session startRunning];
        }
      });
    }
    return true;
  }

  void Stop() override {
    @autoreleasepool {
      AVCaptureSession* session = session_;
      AVCaptureVideoDataOutput* output = output_;
      VeilScreenDelegate* delegate = delegate_;
      dispatch_queue_t q = queue_;
      session_ = nil;
      output_ = nil;
      delegate_ = nil;
      queue_ = nil;
      // Same hangup-time teardown race as the camera capturer (see
      // veil_avf_camera.mm Stop()): clear the callback synchronously ON the
      // capture queue so no captureOutput: is mid-flight when the caller
      // proceeds to destroy the frame sink.
      if (delegate != nil && q != nil) {
        dispatch_sync(q, ^{
          delegate->cb_ = nullptr;
        });
      } else if (delegate != nil) {
        delegate->cb_ = nullptr;
      }
      if (session) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
          @autoreleasepool {
            if (session.running) [session stopRunning];
            if (output) [session removeOutput:output];
          }
        });
      }
    }
  }

 private:
  CameraFrameCb cb_;
  AVCaptureSession* session_ = nil;
  AVCaptureVideoDataOutput* output_ = nil;
  VeilScreenDelegate* delegate_ = nil;
  dispatch_queue_t queue_ = nil;
};

}  // namespace

ScreenCapturer* CreatePlatformScreen(CameraFrameCb cb) {
  return new AvfScreenCapturer(std::move(cb));
}

}  // namespace veil_media
