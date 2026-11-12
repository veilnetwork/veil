// Exercise the actual capturer lifecycle, replacing only AVCaptureSession's
// hardware operations. No camera, sample buffers, permissions, or network.
#define VEIL_MEDIA_TEST_HOOKS 1
#include "../src/veil_avf_camera.mm"

#include <atomic>
#include <cassert>
#include <cstring>
#include <memory>

@interface VeilLifecycleSession : AVCaptureSession {
 @public
  std::atomic<int> starts_;
  std::atomic<int> stops_;
  std::atomic<int> removals_;
  std::atomic<bool> running_;
  dispatch_semaphore_t entered_;
  dispatch_semaphore_t proceed_;
}
@end

@implementation VeilLifecycleSession
- (instancetype)init {
  self = [super init];
  if (self) {
    starts_.store(0);
    stops_.store(0);
    removals_.store(0);
    running_.store(false);
  }
  return self;
}
- (void)startRunning {
  starts_.fetch_add(1);
  if (entered_) dispatch_semaphore_signal(entered_);
  if (proceed_) dispatch_semaphore_wait(proceed_, DISPATCH_TIME_FOREVER);
  running_.store(true);
}
- (void)stopRunning {
  stops_.fetch_add(1);
  running_.store(false);
}
- (BOOL)isRunning { return running_.load(); }
- (void)removeOutput:(AVCaptureOutput*)output {
  (void)output;
  removals_.fetch_add(1);
}
@end

static void Wait(dispatch_semaphore_t semaphore) {
  // Watchdog only: assertions use queue order and gates, not elapsed time.
  assert(dispatch_semaphore_wait(semaphore,
      dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0);
}

static void Drain(dispatch_queue_t queue) { dispatch_sync(queue, ^{}); }

int main(int argc, char** argv) {
  assert(argc == 2);
  @autoreleasepool {
    dispatch_queue_t control = veil_media::CameraControlQueue();
    VeilLifecycleSession* first = [[VeilLifecycleSession alloc] init];
    AVCaptureVideoDataOutput* output = [[AVCaptureVideoDataOutput alloc] init];
    auto camera = std::make_unique<veil_media::AvfCameraCapturer>(
        veil_media::CameraFrameCb{});
    if (std::strcmp(argv[1], "destroy-before-start") == 0 ||
        std::strcmp(argv[1], "replace-pending-session") == 0) {
      dispatch_semaphore_t held = dispatch_semaphore_create(0);
      dispatch_semaphore_t release = dispatch_semaphore_create(0);
      dispatch_async(control, ^{
        dispatch_semaphore_signal(held);
        dispatch_semaphore_wait(release, DISPATCH_TIME_FOREVER);
      });
      Wait(held);
      camera->PublishSessionForTesting(first, output);
      if (std::strcmp(argv[1], "destroy-before-start") == 0) {
        camera.reset();
        dispatch_semaphore_signal(release);
        Drain(control);
        assert(first->starts_.load() == 0);
        assert(!first.running);
        assert(first->removals_.load() == 1);
      } else {
        camera.reset();
        camera = std::make_unique<veil_media::AvfCameraCapturer>(
            veil_media::CameraFrameCb{});
        VeilLifecycleSession* next = [[VeilLifecycleSession alloc] init];
        camera->PublishSessionForTesting(next, output);
        dispatch_semaphore_signal(release);
        Drain(control);
        assert(first->starts_.load() == 0);
        assert(first->removals_.load() == 1);
        assert(next->starts_.load() == 1 && next.running);
        camera.reset();
        Drain(control);
        assert(next->stops_.load() == 1 && !next.running);
        assert(next->removals_.load() == 1);
      }
    } else {
      assert(std::strcmp(argv[1], "stop-during-start") == 0);
      first->entered_ = dispatch_semaphore_create(0);
      first->proceed_ = dispatch_semaphore_create(0);
      camera->PublishSessionForTesting(first, output);
      Wait(first->entered_);
      camera.reset();
      dispatch_semaphore_signal(first->proceed_);
      Drain(control);
      assert(first->starts_.load() == 1);
      assert(first->stops_.load() == 1 && !first.running);
      assert(first->removals_.load() == 1);
    }
  }
  return 0;
}
