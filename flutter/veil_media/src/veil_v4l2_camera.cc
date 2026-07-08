/* SPDX-License-Identifier: MIT
 *
 * veil_v4l2_camera.cc — V4L2-backed CameraCapturer for Linux desktop.
 *
 * Opens the default V4L2 video device (/dev/video0, override with
 * VEIL_MEDIA_CAMERA), streams YUYV (packed 4:2:2) frames via mmap, converts
 * each to I420 (libyuv::YUY2ToI420), downscales to the requested width
 * (libyuv::I420Scale — same rationale as the macOS capturer: the veil path caps
 * VP8 bitrate and pads every RTP packet into a 16KB onion cell, so full-res
 * keyframes fan out into hundreds of cells and add seconds of latency) and
 * hands the planes to the CameraFrameCb on a dedicated capture thread.
 * veil_media_engine.cc pushes those into the VP8 send stream.
 *
 * Pure C++ + libyuv (already inside libwebrtc.a) — no WebRTC types, no GTK.
 * YUYV is the near-universal UVC webcam format at low resolutions; if the
 * driver cannot deliver it, Start() returns false and the engine simply has no
 * local video source (receive/render is unaffected — see start_camera).
 */
#include "veil_camera.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <unistd.h>

#include <time.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

#include "third_party/libyuv/include/libyuv/convert.h"  // YUY2ToI420
#include "third_party/libyuv/include/libyuv/scale.h"     // I420Scale

namespace veil_media {
namespace {

void vcam_log(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stderr, "[veil_v4l2] ");
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}

int64_t now_us() {
  timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<int64_t>(ts.tv_sec) * 1000000 + ts.tv_nsec / 1000;
}

// ioctl that retries on EINTR.
int xioctl(int fd, unsigned long req, void* arg) {
  int r;
  do {
    r = ioctl(fd, req, arg);
  } while (r == -1 && errno == EINTR);
  return r;
}

struct MmapBuf {
  void* start = nullptr;
  size_t length = 0;
};

class V4l2CameraCapturer : public CameraCapturer {
 public:
  explicit V4l2CameraCapturer(CameraFrameCb cb) : cb_(std::move(cb)) {}
  ~V4l2CameraCapturer() override { Stop(); }

  bool Start(int width, int height, int fps) override {
    if (running_.load()) return true;
    if (width <= 0) width = 352;
    if (height <= 0) height = 288;
    if (fps <= 0) fps = 15;
    target_w_ = width;

    const char* dev = getenv("VEIL_MEDIA_CAMERA");
    if (dev == nullptr || *dev == '\0') dev = "/dev/video0";

    fd_ = open(dev, O_RDWR | O_CLOEXEC, 0);
    if (fd_ < 0) {
      vcam_log("open(%s) failed: %s", dev, strerror(errno));
      return false;
    }

    v4l2_capability cap{};
    if (xioctl(fd_, VIDIOC_QUERYCAP, &cap) < 0) {
      vcam_log("%s: VIDIOC_QUERYCAP failed: %s", dev, strerror(errno));
      return CleanupFail();
    }
    // On multi-node devices `capabilities` is the union across all nodes; the
    // caps of THIS node live in device_caps when V4L2_CAP_DEVICE_CAPS is set.
    const __u32 caps = (cap.capabilities & V4L2_CAP_DEVICE_CAPS)
                           ? cap.device_caps
                           : cap.capabilities;
    if (!(caps & V4L2_CAP_VIDEO_CAPTURE) || !(caps & V4L2_CAP_STREAMING)) {
      vcam_log("%s: not a streaming capture device", dev);
      return CleanupFail();
    }

    // Request YUYV at the target size; the driver rounds to the nearest it
    // supports and reports back the actual geometry.
    v4l2_format fmt{};
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = static_cast<__u32>(width);
    fmt.fmt.pix.height = static_cast<__u32>(height);
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
    fmt.fmt.pix.field = V4L2_FIELD_NONE;
    if (xioctl(fd_, VIDIOC_S_FMT, &fmt) < 0) {
      vcam_log("%s: VIDIOC_S_FMT failed: %s", dev, strerror(errno));
      return CleanupFail();
    }
    if (fmt.fmt.pix.pixelformat != V4L2_PIX_FMT_YUYV) {
      vcam_log("%s: driver refused YUYV (got 0x%08x); no local video",
               dev, fmt.fmt.pix.pixelformat);
      return CleanupFail();
    }
    cap_w_ = static_cast<int>(fmt.fmt.pix.width);
    cap_h_ = static_cast<int>(fmt.fmt.pix.height);
    cap_stride_ = fmt.fmt.pix.bytesperline > 0
                      ? static_cast<int>(fmt.fmt.pix.bytesperline)
                      : cap_w_ * 2;

    // Best-effort frame rate.
    v4l2_streamparm parm{};
    parm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (xioctl(fd_, VIDIOC_G_PARM, &parm) == 0 &&
        (parm.parm.capture.capability & V4L2_CAP_TIMEPERFRAME)) {
      parm.parm.capture.timeperframe.numerator = 1;
      parm.parm.capture.timeperframe.denominator = static_cast<__u32>(fps);
      xioctl(fd_, VIDIOC_S_PARM, &parm);  // ignore failure
    }

    // mmap streaming buffers.
    v4l2_requestbuffers req{};
    req.count = 4;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    if (xioctl(fd_, VIDIOC_REQBUFS, &req) < 0 || req.count < 2) {
      vcam_log("%s: VIDIOC_REQBUFS failed: %s", dev, strerror(errno));
      return CleanupFail();
    }
    bufs_.resize(req.count);
    for (unsigned i = 0; i < req.count; ++i) {
      v4l2_buffer buf{};
      buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
      buf.memory = V4L2_MEMORY_MMAP;
      buf.index = i;
      if (xioctl(fd_, VIDIOC_QUERYBUF, &buf) < 0) {
        vcam_log("%s: VIDIOC_QUERYBUF[%u] failed", dev, i);
        return CleanupFail();
      }
      bufs_[i].length = buf.length;
      bufs_[i].start = mmap(nullptr, buf.length, PROT_READ | PROT_WRITE,
                            MAP_SHARED, fd_, buf.m.offset);
      if (bufs_[i].start == MAP_FAILED) {
        bufs_[i].start = nullptr;
        vcam_log("%s: mmap[%u] failed: %s", dev, i, strerror(errno));
        return CleanupFail();
      }
      if (xioctl(fd_, VIDIOC_QBUF, &buf) < 0) {
        vcam_log("%s: VIDIOC_QBUF[%u] failed", dev, i);
        return CleanupFail();
      }
    }

    v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (xioctl(fd_, VIDIOC_STREAMON, &type) < 0) {
      vcam_log("%s: VIDIOC_STREAMON failed: %s", dev, strerror(errno));
      return CleanupFail();
    }

    running_.store(true);
    min_interval_us_ = 1000000 / fps;
    thread_ = std::thread([this] { CaptureLoop(); });
    vcam_log("started %s: capture %dx%d (stride %d) -> target %d, %dfps",
             dev, cap_w_, cap_h_, cap_stride_, target_w_, fps);
    return true;
  }

  void Stop() override {
    if (!running_.exchange(false)) {
      // Never started (or already stopped): still release a half-open fd.
      if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
      }
      return;
    }
    if (thread_.joinable()) thread_.join();
    if (fd_ >= 0) {
      v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
      xioctl(fd_, VIDIOC_STREAMOFF, &type);
    }
    for (auto& b : bufs_) {
      if (b.start != nullptr) munmap(b.start, b.length);
    }
    bufs_.clear();
    if (fd_ >= 0) {
      close(fd_);
      fd_ = -1;
    }
  }

 private:
  bool CleanupFail() {
    for (auto& b : bufs_) {
      if (b.start != nullptr) munmap(b.start, b.length);
    }
    bufs_.clear();
    if (fd_ >= 0) {
      close(fd_);
      fd_ = -1;
    }
    return false;
  }

  void CaptureLoop() {
    int64_t last_us = 0;
    while (running_.load()) {
      fd_set fds;
      FD_ZERO(&fds);
      FD_SET(fd_, &fds);
      timeval tv{};
      tv.tv_sec = 1;
      tv.tv_usec = 0;
      int r = select(fd_ + 1, &fds, nullptr, nullptr, &tv);
      if (r < 0) {
        if (errno == EINTR) continue;
        vcam_log("select failed: %s", strerror(errno));
        break;
      }
      if (r == 0) continue;  // timeout, re-check running_

      v4l2_buffer buf{};
      buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
      buf.memory = V4L2_MEMORY_MMAP;
      if (xioctl(fd_, VIDIOC_DQBUF, &buf) < 0) {
        if (errno == EAGAIN) continue;
        vcam_log("VIDIOC_DQBUF failed: %s", strerror(errno));
        break;
      }
      // Throttle delivery to the requested fps even if the driver ignores
      // S_PARM and streams faster — the bitrate-capped VP8 encoder over onion
      // can't use the extra frames and every one adds encode + fan-out cost.
      const int64_t t = now_us();
      if (buf.index < bufs_.size() && bufs_[buf.index].start != nullptr &&
          cb_ != nullptr && t - last_us >= min_interval_us_) {
        last_us = t;
        DeliverYuyv(static_cast<const uint8_t*>(bufs_[buf.index].start));
      }
      xioctl(fd_, VIDIOC_QBUF, &buf);  // requeue
    }
  }

  // Convert one YUYV buffer to I420, optionally downscale, deliver.
  void DeliverYuyv(const uint8_t* yuyv) {
    const int w = cap_w_, h = cap_h_;
    const int cw = (w + 1) / 2, ch = (h + 1) / 2;
    y_.resize(static_cast<size_t>(w) * h);
    u_.resize(static_cast<size_t>(cw) * ch);
    v_.resize(static_cast<size_t>(cw) * ch);
    if (libyuv::YUY2ToI420(yuyv, cap_stride_, y_.data(), w, u_.data(), cw,
                           v_.data(), cw, w, h) != 0) {
      return;
    }

    if (target_w_ > 0 && w > target_w_) {
      const int ow = target_w_ & ~1;                  // even width
      int oh = ((h * ow / w) + 1) & ~1;               // aspect-preserved, even
      if (oh < 2) oh = 2;
      const int ocw = (ow + 1) / 2, och = (oh + 1) / 2;
      sy_.resize(static_cast<size_t>(ow) * oh);
      su_.resize(static_cast<size_t>(ocw) * och);
      sv_.resize(static_cast<size_t>(ocw) * och);
      libyuv::I420Scale(y_.data(), w, u_.data(), cw, v_.data(), cw, w, h,
                        sy_.data(), ow, su_.data(), ocw, sv_.data(), ocw, ow, oh,
                        libyuv::kFilterBilinear);
      cb_(sy_.data(), su_.data(), sv_.data(), ow, oh, ow, ocw, ocw, /*ts_us=*/0);
    } else {
      cb_(y_.data(), u_.data(), v_.data(), w, h, w, cw, cw, /*ts_us=*/0);
    }
  }

  CameraFrameCb cb_;
  std::atomic<bool> running_{false};
  std::thread thread_;
  int fd_ = -1;
  int cap_w_ = 0, cap_h_ = 0, cap_stride_ = 0;
  int target_w_ = 0;
  int64_t min_interval_us_ = 0;
  std::vector<MmapBuf> bufs_;
  std::vector<uint8_t> y_, u_, v_;     // I420 at capture resolution
  std::vector<uint8_t> sy_, su_, sv_;  // downscaled I420 (encoder input)
};

}  // namespace

CameraCapturer* CreatePlatformCamera(CameraFrameCb cb) {
  return new V4l2CameraCapturer(std::move(cb));
}

}  // namespace veil_media
