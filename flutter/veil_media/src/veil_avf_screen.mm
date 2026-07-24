/* SPDX-License-Identifier: MIT
 *
 * veil_avf_screen.mm — source-aware macOS screen/window capture.
 *
 * macOS 12.3+ uses ScreenCaptureKit for both displays and individual windows.
 * The 10.15–12.2 compatibility path keeps AVCaptureScreenInput for displays;
 * those systems cannot expose window capture through this ABI. Both paths emit
 * I420 into the same VideoBroadcaster used by camera capture. Source ids and
 * window titles remain process-local and never enter call signalling.
 */
#import <AVFoundation/AVFoundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <Foundation/Foundation.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>

#include "veil_screen.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include "third_party/libyuv/include/libyuv/convert.h"
#include "third_party/libyuv/include/libyuv/scale.h"

namespace {

struct I420Scratch {
  std::vector<uint8_t> y;
  std::vector<uint8_t> u;
  std::vector<uint8_t> v;
  std::vector<uint8_t> scaled_y;
  std::vector<uint8_t> scaled_u;
  std::vector<uint8_t> scaled_v;
};

void EmitPixelBuffer(CVImageBufferRef pixel_buffer,
                     int target_width,
                     const veil_media::CameraFrameCb& callback,
                     I420Scratch* scratch) {
  if (pixel_buffer == nullptr || !callback || scratch == nullptr) return;
  if (CVPixelBufferLockBaseAddress(pixel_buffer,
                                   kCVPixelBufferLock_ReadOnly) !=
      kCVReturnSuccess) {
    return;
  }

  const int width = static_cast<int>(CVPixelBufferGetWidth(pixel_buffer));
  const int height = static_cast<int>(CVPixelBufferGetHeight(pixel_buffer));
  const OSType format = CVPixelBufferGetPixelFormatType(pixel_buffer);
  bool have_i420 = false;
  if (width > 0 && height > 0) {
    const int chroma_width = (width + 1) / 2;
    const int chroma_height = (height + 1) / 2;
    scratch->y.resize(static_cast<size_t>(width) * height);
    scratch->u.resize(static_cast<size_t>(chroma_width) * chroma_height);
    scratch->v.resize(static_cast<size_t>(chroma_width) * chroma_height);
    if ((format == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange ||
         format == kCVPixelFormatType_420YpCbCr8BiPlanarFullRange) &&
        CVPixelBufferGetPlaneCount(pixel_buffer) >= 2) {
      const auto* source_y = static_cast<const uint8_t*>(
          CVPixelBufferGetBaseAddressOfPlane(pixel_buffer, 0));
      const int source_y_stride = static_cast<int>(
          CVPixelBufferGetBytesPerRowOfPlane(pixel_buffer, 0));
      const auto* source_uv = static_cast<const uint8_t*>(
          CVPixelBufferGetBaseAddressOfPlane(pixel_buffer, 1));
      const int source_uv_stride = static_cast<int>(
          CVPixelBufferGetBytesPerRowOfPlane(pixel_buffer, 1));
      have_i420 =
          source_y != nullptr && source_uv != nullptr &&
          libyuv::NV12ToI420(
              source_y, source_y_stride, source_uv, source_uv_stride,
              scratch->y.data(), width, scratch->u.data(), chroma_width,
              scratch->v.data(), chroma_width, width, height) == 0;
    } else if (format == kCVPixelFormatType_32BGRA) {
      // libyuv ARGB is byte-order B,G,R,A on little-endian macOS.
      const auto* source = static_cast<const uint8_t*>(
          CVPixelBufferGetBaseAddress(pixel_buffer));
      const int source_stride =
          static_cast<int>(CVPixelBufferGetBytesPerRow(pixel_buffer));
      have_i420 =
          source != nullptr &&
          libyuv::ARGBToI420(
              source, source_stride, scratch->y.data(), width,
              scratch->u.data(), chroma_width, scratch->v.data(),
              chroma_width, width, height) == 0;
    }

    if (have_i420) {
      if (target_width > 0 && width > target_width) {
        const int output_width = std::max(2, target_width & ~1);
        const int output_height =
            std::max(2, ((height * output_width / width) + 1) & ~1);
        const int output_chroma_width = (output_width + 1) / 2;
        const int output_chroma_height = (output_height + 1) / 2;
        scratch->scaled_y.resize(
            static_cast<size_t>(output_width) * output_height);
        scratch->scaled_u.resize(
            static_cast<size_t>(output_chroma_width) * output_chroma_height);
        scratch->scaled_v.resize(
            static_cast<size_t>(output_chroma_width) * output_chroma_height);
        if (libyuv::I420Scale(
                scratch->y.data(), width, scratch->u.data(), chroma_width,
                scratch->v.data(), chroma_width, width, height,
                scratch->scaled_y.data(), output_width,
                scratch->scaled_u.data(), output_chroma_width,
                scratch->scaled_v.data(), output_chroma_width, output_width,
                output_height, libyuv::kFilterBilinear) == 0) {
          callback(scratch->scaled_y.data(), scratch->scaled_u.data(),
                   scratch->scaled_v.data(), output_width, output_height,
                   output_width, output_chroma_width, output_chroma_width,
                   /*ts_us=*/0);
        }
      } else {
        callback(scratch->y.data(), scratch->u.data(), scratch->v.data(),
                 width, height, width, chroma_width, chroma_width,
                 /*ts_us=*/0);
      }
    }
  }
  CVPixelBufferUnlockBaseAddress(pixel_buffer,
                                 kCVPixelBufferLock_ReadOnly);
}

bool ParseUint32(const char* text, uint32_t* value) {
  if (text == nullptr || text[0] == '\0' || value == nullptr) return false;
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(text, &end, 10);
  if (end == text || *end != '\0' || parsed > UINT32_MAX) return false;
  *value = static_cast<uint32_t>(parsed);
  return true;
}

enum class SourceKind { kDisplay, kWindow };

struct SourceSelector {
  SourceKind kind = SourceKind::kDisplay;
  uint32_t id = 0;
  bool use_main_display = true;
};

bool ParseSource(const char* source_id, SourceSelector* selector) {
  if (selector == nullptr) return false;
  *selector = SourceSelector{};
  if (source_id == nullptr || source_id[0] == '\0') return true;
  constexpr char kDisplayPrefix[] = "display:";
  constexpr char kWindowPrefix[] = "window:";
  if (std::string(source_id).rfind(kDisplayPrefix, 0) == 0) {
    selector->kind = SourceKind::kDisplay;
    selector->use_main_display = false;
    return ParseUint32(source_id + sizeof(kDisplayPrefix) - 1, &selector->id);
  }
  if (std::string(source_id).rfind(kWindowPrefix, 0) == 0) {
    selector->kind = SourceKind::kWindow;
    selector->use_main_display = false;
    return ParseUint32(source_id + sizeof(kWindowPrefix) - 1, &selector->id);
  }
  // Backward compatibility with the display-only ids shipped before the
  // source type became explicit.
  selector->kind = SourceKind::kDisplay;
  selector->use_main_display = false;
  return ParseUint32(source_id, &selector->id);
}

std::string JsonEscape(NSString* value) {
  if (value == nil) return "";
  const char* utf8 = [value UTF8String];
  if (utf8 == nullptr) return "";
  std::string escaped;
  for (const unsigned char* cursor =
           reinterpret_cast<const unsigned char*>(utf8);
       *cursor != '\0'; ++cursor) {
    switch (*cursor) {
      case '"':
        escaped += "\\\"";
        break;
      case '\\':
        escaped += "\\\\";
        break;
      case '\b':
        escaped += "\\b";
        break;
      case '\f':
        escaped += "\\f";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        if (*cursor < 0x20) {
          static constexpr char kHex[] = "0123456789abcdef";
          escaped += "\\u00";
          escaped += kHex[*cursor >> 4];
          escaped += kHex[*cursor & 0x0f];
        } else {
          escaped += static_cast<char>(*cursor);
        }
    }
  }
  return escaped;
}

std::string DisplayLabel(CGDirectDisplayID display_id,
                         NSInteger width,
                         NSInteger height,
                         size_t position) {
  std::string label =
      CGDisplayIsMain(display_id) ? "Main display"
                                  : "Display " + std::to_string(position + 1);
  label += " (" + std::to_string(width) + "x" + std::to_string(height) + ")";
  return label;
}

std::string PlatformSourcesJson() {
  CGDirectDisplayID displays[32] = {};
  uint32_t count = 0;
  if (CGGetActiveDisplayList(32, displays, &count) != kCGErrorSuccess) {
    return "[]";
  }
  std::string json = "[";
  size_t emitted = 0;
  for (uint32_t index = 0; index < count; ++index) {
    if (emitted++ != 0) json += ',';
    const CGDirectDisplayID id = displays[index];
    const CGRect bounds = CGDisplayBounds(id);
    json += "{\"id\":\"display:" + std::to_string(id) +
            "\",\"label\":\"" +
            DisplayLabel(id, static_cast<NSInteger>(bounds.size.width),
                         static_cast<NSInteger>(bounds.size.height), index) +
            "\",\"kind\":\"screen\"}";
  }

  // CGWindowListCopyWindowInfo remains the synchronous, non-obsolete metadata
  // API on current macOS. It keeps opening the picker responsive while
  // ScreenCaptureKit content is prefetched below. Before Screen Recording
  // consent, titles may be redacted by the OS; application + geometry still
  // gives a useful local choice without logging or signalling either value.
  NSArray<NSDictionary*>* windows = CFBridgingRelease(
      CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly |
                                     kCGWindowListExcludeDesktopElements,
                                 kCGNullWindowID));
  size_t window_count = 0;
  constexpr size_t kMaxWindows = 128;
  for (NSDictionary* row in windows) {
    if (window_count >= kMaxWindows) break;
    NSNumber* layer = row[(id)kCGWindowLayer];
    NSNumber* number = row[(id)kCGWindowNumber];
    NSNumber* alpha = row[(id)kCGWindowAlpha];
    NSDictionary* bounds = row[(id)kCGWindowBounds];
    CGRect frame = CGRectZero;
    if (layer == nil || layer.integerValue != 0 || number == nil ||
        (alpha != nil && alpha.doubleValue <= 0) || bounds == nil ||
        !CGRectMakeWithDictionaryRepresentation(
            (__bridge CFDictionaryRef)bounds, &frame) ||
        frame.size.width < 64 || frame.size.height < 64) {
      continue;
    }
    NSString* application = row[(id)kCGWindowOwnerName] ?: @"";
    NSString* title = row[(id)kCGWindowName] ?: @"";
    if (application.length == 0 && title.length == 0) continue;
    NSString* label =
        title.length == 0
            ? application
            : (application.length == 0
                   ? title
                   : [NSString stringWithFormat:@"%@ — %@", application,
                                                title]);
    if (emitted++ != 0) json += ',';
    json += "{\"id\":\"window:" +
            std::to_string(number.unsignedIntValue) + "\",\"label\":\"" +
            JsonEscape(label) + " (" +
            std::to_string(static_cast<int>(frame.size.width)) + "x" +
            std::to_string(static_cast<int>(frame.size.height)) +
            ")\",\"kind\":\"window\"}";
    ++window_count;
  }
  json += ']';
  return json;
}

SCShareableContent* g_shareable_content = nil;

NSObject* ShareableContentLock() {
  static NSObject* lock = nil;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    lock = [[NSObject alloc] init];
  });
  return lock;
}

SCShareableContent* FetchShareableContent() API_AVAILABLE(macos(12.3)) {
  __block SCShareableContent* content = nil;
  dispatch_semaphore_t done = dispatch_semaphore_create(0);
  [SCShareableContent
      getShareableContentExcludingDesktopWindows:YES
                             onScreenWindowsOnly:YES
                               completionHandler:^(
                                   SCShareableContent* value, NSError* error) {
                                 if (error == nil) content = value;
                                 dispatch_semaphore_signal(done);
                               }];
  const dispatch_time_t timeout =
      dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC);
  if (dispatch_semaphore_wait(done, timeout) != 0) return nil;
  if (content != nil) {
    @synchronized(ShareableContentLock()) {
      g_shareable_content = content;
    }
  }
  return content;
}

void RefreshShareableContentAsync() API_AVAILABLE(macos(12.3)) {
  [SCShareableContent
      getShareableContentExcludingDesktopWindows:YES
                             onScreenWindowsOnly:YES
                               completionHandler:^(
                                   SCShareableContent* value, NSError* error) {
                                 if (error != nil || value == nil) return;
                                 @synchronized(ShareableContentLock()) {
                                   g_shareable_content = value;
                                 }
                               }];
}

SCShareableContent* CachedShareableContent() API_AVAILABLE(macos(12.3)) {
  @synchronized(ShareableContentLock()) {
    return g_shareable_content;
  }
}

SCDisplay* ResolveDisplay(SCShareableContent* content,
                          const SourceSelector& selector)
    API_AVAILABLE(macos(12.3)) {
  if (content == nil) return nil;
  for (SCDisplay* display in content.displays) {
    if ((selector.use_main_display && CGDisplayIsMain(display.displayID)) ||
        (!selector.use_main_display && display.displayID == selector.id)) {
      return display;
    }
  }
  return nil;
}

SCWindow* ResolveWindow(SCShareableContent* content, uint32_t window_id)
    API_AVAILABLE(macos(12.3)) {
  if (content == nil) return nil;
  for (SCWindow* window in content.windows) {
    if (window.windowID == window_id) return window;
  }
  return nil;
}

}  // namespace

// ---- AVCapture fallback for macOS 10.15–12.2 displays --------------------

@interface VeilAvfScreenDelegate
    : NSObject <AVCaptureVideoDataOutputSampleBufferDelegate> {
 @public
  veil_media::CameraFrameCb callback_;
  int target_width_;
  I420Scratch scratch_;
}
@end

@implementation VeilAvfScreenDelegate
- (void)captureOutput:(AVCaptureOutput*)output
    didOutputSampleBuffer:(CMSampleBufferRef)sample_buffer
           fromConnection:(AVCaptureConnection*)connection {
  EmitPixelBuffer(CMSampleBufferGetImageBuffer(sample_buffer), target_width_,
                  callback_, &scratch_);
}
@end

namespace veil_media {
namespace {

class AvfScreenCapturer final : public ScreenCapturer {
 public:
  AvfScreenCapturer(CameraFrameCb callback, CGDirectDisplayID display_id)
      : callback_(std::move(callback)), display_id_(display_id) {}
  ~AvfScreenCapturer() override { Stop(); }

  bool Start(int width, int fps) override {
    if (session_ != nil) return true;
    if (!PlatformScreenAccessGranted() && !RequestPlatformScreenAccess()) {
      return false;
    }
    if (fps <= 0) fps = 10;
    @autoreleasepool {
      AVCaptureScreenInput* input =
          [[AVCaptureScreenInput alloc] initWithDisplayID:display_id_];
      if (input == nil) return false;
      input.minFrameDuration = CMTimeMake(1, fps);
      input.capturesCursor = YES;

      AVCaptureSession* session = [[AVCaptureSession alloc] init];
      [session beginConfiguration];
      if (![session canAddInput:input]) return false;
      [session addInput:input];

      VeilAvfScreenDelegate* delegate =
          [[VeilAvfScreenDelegate alloc] init];
      delegate->callback_ = callback_;
      delegate->target_width_ = width;
      AVCaptureVideoDataOutput* output =
          [[AVCaptureVideoDataOutput alloc] init];
      output.videoSettings = @{
        (id)kCVPixelBufferPixelFormatTypeKey :
            @(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange)
      };
      output.alwaysDiscardsLateVideoFrames = YES;
      dispatch_queue_t queue =
          dispatch_queue_create("network.veil.screen.avf",
                                DISPATCH_QUEUE_SERIAL);
      [output setSampleBufferDelegate:delegate queue:queue];
      if (![session canAddOutput:output]) return false;
      [session addOutput:output];
      [session commitConfiguration];
      session_ = session;
      output_ = output;
      delegate_ = delegate;
      queue_ = queue;
      dispatch_async(
          dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
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
      VeilAvfScreenDelegate* delegate = delegate_;
      dispatch_queue_t queue = queue_;
      session_ = nil;
      output_ = nil;
      delegate_ = nil;
      queue_ = nil;
      if (delegate != nil && queue != nil) {
        dispatch_sync(queue, ^{
          delegate->callback_ = nullptr;
        });
      } else if (delegate != nil) {
        delegate->callback_ = nullptr;
      }
      if (session != nil) {
        dispatch_async(
            dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
              @autoreleasepool {
                if (session.running) [session stopRunning];
                if (output != nil) [session removeOutput:output];
              }
            });
      }
    }
  }

 private:
  CameraFrameCb callback_;
  CGDirectDisplayID display_id_ = 0;
  AVCaptureSession* session_ = nil;
  AVCaptureVideoDataOutput* output_ = nil;
  VeilAvfScreenDelegate* delegate_ = nil;
  dispatch_queue_t queue_ = nil;
};

}  // namespace
}  // namespace veil_media

// ---- ScreenCaptureKit backend for displays and windows --------------------

API_AVAILABLE(macos(12.3))
@interface VeilScScreenDelegate : NSObject <SCStreamOutput, SCStreamDelegate> {
 @public
  veil_media::CameraFrameCb callback_;
  int target_width_;
  I420Scratch scratch_;
}
@end

@implementation VeilScScreenDelegate
- (void)stream:(SCStream*)stream
    didOutputSampleBuffer:(CMSampleBufferRef)sample_buffer
                  ofType:(SCStreamOutputType)type API_AVAILABLE(macos(12.3)) {
  if (type != SCStreamOutputTypeScreen ||
      !CMSampleBufferDataIsReady(sample_buffer)) {
    return;
  }
  EmitPixelBuffer(CMSampleBufferGetImageBuffer(sample_buffer), target_width_,
                  callback_, &scratch_);
}

- (void)stream:(SCStream*)stream
    didStopWithError:(NSError*)error API_AVAILABLE(macos(12.3)) {
  callback_ = nullptr;
}
@end

namespace veil_media {
namespace {

class ScScreenCapturer final : public ScreenCapturer {
 public:
  ScScreenCapturer(CameraFrameCb callback, SourceSelector selector)
      : callback_(std::move(callback)), selector_(selector) {}
  ~ScScreenCapturer() override { Stop(); }

  bool Start(int width, int fps) override {
    if (stream_ != nil) return true;
    if (!PlatformScreenAccessGranted() && !RequestPlatformScreenAccess()) {
      return false;
    }
    if (@available(macOS 12.3, *)) {
      SCShareableContent* content = CachedShareableContent();
      if (content == nil) content = FetchShareableContent();
      if (content == nil) return false;

      SCContentFilter* filter = nil;
      NSInteger source_width = 0;
      NSInteger source_height = 0;
      if (selector_.kind == SourceKind::kWindow) {
        SCWindow* window = ResolveWindow(content, selector_.id);
        if (window == nil || window.frame.size.width < 1 ||
            window.frame.size.height < 1) {
          return false;
        }
        filter =
            [[SCContentFilter alloc] initWithDesktopIndependentWindow:window];
        source_width = static_cast<NSInteger>(window.frame.size.width);
        source_height = static_cast<NSInteger>(window.frame.size.height);
      } else {
        SCDisplay* display = ResolveDisplay(content, selector_);
        if (display == nil || display.width < 1 || display.height < 1) {
          return false;
        }
        filter = [[SCContentFilter alloc] initWithDisplay:display
                                        excludingWindows:@[]];
        source_width = display.width;
        source_height = display.height;
      }

      if (fps <= 0) fps = 10;
      if (width <= 0) width = 640;
      int output_width =
          std::max(2, std::min<int>(width, source_width) & ~1);
      int output_height = std::max(
          2, static_cast<int>(
                 (static_cast<int64_t>(source_height) * output_width /
                      source_width +
                  1) &
                 ~int64_t{1}));
      SCStreamConfiguration* configuration =
          [[SCStreamConfiguration alloc] init];
      configuration.width = static_cast<size_t>(output_width);
      configuration.height = static_cast<size_t>(output_height);
      configuration.minimumFrameInterval = CMTimeMake(1, fps);
      configuration.pixelFormat =
          kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange;
      configuration.scalesToFit = YES;
      configuration.showsCursor = YES;
      configuration.queueDepth = 2;
      if (@available(macOS 13.0, *)) configuration.capturesAudio = NO;
      if (@available(macOS 14.0, *)) configuration.preservesAspectRatio = YES;

      VeilScScreenDelegate* delegate =
          [[VeilScScreenDelegate alloc] init];
      delegate->callback_ = callback_;
      delegate->target_width_ = width;
      dispatch_queue_t queue =
          dispatch_queue_create("network.veil.screen.sck",
                                DISPATCH_QUEUE_SERIAL);
      SCStream* stream = [[SCStream alloc] initWithFilter:filter
                                           configuration:configuration
                                                delegate:delegate];
      NSError* error = nil;
      if (![stream addStreamOutput:delegate
                             type:SCStreamOutputTypeScreen
               sampleHandlerQueue:queue
                            error:&error]) {
        delegate->callback_ = nullptr;
        return false;
      }
      stream_ = stream;
      delegate_ = delegate;
      queue_ = queue;
      [stream startCaptureWithCompletionHandler:^(NSError* start_error) {
        if (start_error != nil) delegate->callback_ = nullptr;
      }];
      return true;
    }
    return false;
  }

  void Stop() override {
    if (@available(macOS 12.3, *)) {
      SCStream* stream = stream_;
      VeilScScreenDelegate* delegate = delegate_;
      dispatch_queue_t queue = queue_;
      stream_ = nil;
      delegate_ = nil;
      queue_ = nil;
      if (delegate != nil && queue != nil) {
        dispatch_sync(queue, ^{
          delegate->callback_ = nullptr;
        });
      } else if (delegate != nil) {
        delegate->callback_ = nullptr;
      }
      if (stream != nil) {
        [stream stopCaptureWithCompletionHandler:^(NSError* error) {
          NSError* remove_error = nil;
          [stream removeStreamOutput:delegate
                                type:SCStreamOutputTypeScreen
                               error:&remove_error];
        }];
      }
    }
  }

 private:
  CameraFrameCb callback_;
  SourceSelector selector_;
  SCStream* stream_ = nil;
  VeilScScreenDelegate* delegate_ = nil;
  dispatch_queue_t queue_ = nil;
};

}  // namespace

ScreenCapturer* CreatePlatformScreen(CameraFrameCb callback,
                                     const char* source_id) {
  SourceSelector selector;
  if (!ParseSource(source_id, &selector)) return nullptr;
  if (@available(macOS 12.3, *)) {
    return new ScScreenCapturer(std::move(callback), selector);
  }
  if (selector.kind != SourceKind::kDisplay) return nullptr;
  CGDirectDisplayID display_id = CGMainDisplayID();
  if (!selector.use_main_display) {
    display_id = static_cast<CGDirectDisplayID>(selector.id);
    if (!CGDisplayIsActive(display_id)) return nullptr;
  }
  return new AvfScreenCapturer(std::move(callback), display_id);
}

std::string ListPlatformScreensJson() {
  if (@available(macOS 12.3, *)) {
    RefreshShareableContentAsync();
  }
  return PlatformSourcesJson();
}

bool PlatformScreenAccessGranted() {
  return CGPreflightScreenCaptureAccess();
}

bool RequestPlatformScreenAccess() {
  return CGPreflightScreenCaptureAccess() || CGRequestScreenCaptureAccess();
}

}  // namespace veil_media
