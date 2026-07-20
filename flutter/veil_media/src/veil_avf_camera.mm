/* SPDX-License-Identifier: MIT
 *
 * veil_avf_camera.mm — AVCaptureSession-backed CameraCapturer for Apple.
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
#import <TargetConditionals.h>

#include "veil_camera.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
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

NSArray<AVCaptureDevice*>* VideoDevices() {
  // devicesWithMediaType is intentionally used here: unlike a discovery
  // session with a hand-maintained device-type list it also includes new
  // built-in lenses and third-party/virtual cameras introduced by the OS.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  return [AVCaptureDevice devicesWithMediaType:AVMediaTypeVideo];
#pragma clang diagnostic pop
}

void AppendJsonString(std::string* out, NSString* value) {
  const char* text = value.UTF8String ? value.UTF8String : "";
  out->push_back('"');
  for (const unsigned char* p =
           reinterpret_cast<const unsigned char*>(text);
       *p; ++p) {
    switch (*p) {
      case '"': *out += "\\\""; break;
      case '\\': *out += "\\\\"; break;
      case '\b': *out += "\\b"; break;
      case '\f': *out += "\\f"; break;
      case '\n': *out += "\\n"; break;
      case '\r': *out += "\\r"; break;
      case '\t': *out += "\\t"; break;
      default:
        if (*p < 0x20) {
          char escaped[7];
          std::snprintf(escaped, sizeof(escaped), "\\u%04x", *p);
          *out += escaped;
        } else {
          out->push_back(static_cast<char>(*p));
        }
    }
  }
  out->push_back('"');
}

class AvfCameraCapturer : public CameraCapturer {
 public:
  explicit AvfCameraCapturer(CameraFrameCb cb) : cb_(std::move(cb)) {}
  ~AvfCameraCapturer() override { Stop(); }

  bool Start(int width, int height, int fps,
             const char* device_id) override {
    (void)height;
    if (session_) return true;
    @autoreleasepool {
      AVCaptureDevice* dev = nil;
      if (device_id != nullptr && *device_id != '\0') {
        NSString* wanted = [NSString stringWithUTF8String:device_id];
        for (AVCaptureDevice* d in VideoDevices()) {
          if ([d.uniqueID isEqualToString:wanted]) {
            dev = d;
            break;
          }
        }
      }
#if TARGET_OS_OSX
      // With no explicit choice prefer the built-in camera, then the system
      // default. Explicit but stale ids also degrade to an available camera.
      for (AVCaptureDevice* d in VideoDevices()) {
        if (dev != nil) break;
        if ([d.deviceType isEqualToString:AVCaptureDeviceTypeBuiltInWideAngleCamera]) {
          dev = d;
          break;
        }
      }
      if (dev == nil) dev = VideoDevices().firstObject;
      if (dev == nil) {
        dev = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];
      }
#else
      if (dev == nil) dev = [AVCaptureDevice
          defaultDeviceWithDeviceType:AVCaptureDeviceTypeBuiltInWideAngleCamera
                             mediaType:AVMediaTypeVideo
                              position:AVCaptureDevicePositionFront];
      if (dev == nil) {
        dev = [AVCaptureDevice
            defaultDeviceWithDeviceType:AVCaptureDeviceTypeBuiltInWideAngleCamera
                               mediaType:AVMediaTypeVideo
                                position:AVCaptureDevicePositionBack];
      }
#endif
      if (dev == nil) return false;
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

      // AVCaptureSession's preset controls resolution but not cadence. Honour
      // the route profile by selecting the closest rate supported by the
      // active format (for example 60 when available, otherwise 30) instead of
      // silently using the platform default.
      NSError* rate_err = nil;
      if (fps > 0 && [dev lockForConfiguration:&rate_err]) {
        double best_rate = 0.0;
        double best_distance = std::numeric_limits<double>::max();
        for (AVFrameRateRange* range in
             dev.activeFormat.videoSupportedFrameRateRanges) {
          const double candidate =
              std::min(std::max((double)fps, range.minFrameRate),
                       range.maxFrameRate);
          const double distance = std::abs(candidate - (double)fps);
          if (distance < best_distance) {
            best_rate = candidate;
            best_distance = distance;
          }
        }
        if (best_rate > 0.0) {
          const CMTime duration =
              CMTimeMake(1000, (int32_t)std::lround(best_rate * 1000.0));
          dev.activeVideoMinFrameDuration = duration;
          dev.activeVideoMaxFrameDuration = duration;
        }
        [dev unlockForConfiguration];
      }
      session_ = session;
      output_ = out;
      delegate_ = delegate;
      queue_ = q;
      // [session startRunning] can block for a while (camera warm-up, and it can
      // wedge harder when permission is not yet granted). Start() runs
      // synchronously on the FFI/UI isolate (engine.cc drives start_camera from
      // the Flutter caller), so kick startRunning OFF that thread — otherwise the
      // whole app freezes on accept. Guard with session_==session so a Stop()
      // that raced in first doesn't leave an orphaned running session.
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
      VeilCamDelegate* delegate = delegate_;
      dispatch_queue_t q = queue_;
      session_ = nil;
      output_ = nil;
      delegate_ = nil;
      queue_ = nil;
      // Clear the frame callback ON the capture queue, synchronously. The
      // delegate fires on that serial queue; the old off-queue clear raced an
      // in-flight captureOutput: between its `if (!cb_)` entry check and the
      // actual invoke — a hangup-time teardown crashed the app with SIGSEGV
      // at 0x0 inside captureOutput: (and could equally call into a frame
      // sink the engine was already destroying). After this dispatch_sync
      // returns, no callback is mid-flight and none will fire again, so the
      // caller may safely tear down the sink. Stop() runs on engine/FFI
      // threads, never on the capture queue itself, so the sync can't
      // deadlock.
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
  VeilCamDelegate* delegate_ = nil;
  dispatch_queue_t queue_ = nil;
};

}  // namespace

CameraCapturer* CreatePlatformCamera(CameraFrameCb cb) {
  return new AvfCameraCapturer(std::move(cb));
}

std::string ListPlatformCamerasJson() {
  @autoreleasepool {
    std::string out = "[";
    bool first = true;
    for (AVCaptureDevice* device in VideoDevices()) {
      if (!first) out.push_back(',');
      first = false;
      out += "{\"id\":";
      AppendJsonString(&out, device.uniqueID);
      out += ",\"label\":";
      AppendJsonString(&out, device.localizedName);
      out += ",\"kind\":\"camera\",\"facing\":\"";
      switch (device.position) {
        case AVCaptureDevicePositionFront: out += "front"; break;
        case AVCaptureDevicePositionBack: out += "back"; break;
        default: out += "external"; break;
      }
      out += "\"}";
    }
    out.push_back(']');
    return out;
  }
}

}  // namespace veil_media
