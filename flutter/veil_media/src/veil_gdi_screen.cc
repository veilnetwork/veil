/* SPDX-License-Identifier: MIT
 *
 * veil_gdi_screen.cc — GDI-backed ScreenCapturer for Windows desktop.
 *
 * BitBlt's the selected display into a top-down 32-bit DIB, converts to I420
 * (libyuv::ARGBToI420 — a Windows 32bpp DIB is BGRA in memory, which is what
 * libyuv calls ARGB), downscales to the requested width and hands the planes
 * to the shared CameraFrameCb. Screen share reuses the camera's VP8 source, so
 * the receiving side needs nothing new — see veil_screen.h.
 *
 * GDI rather than DXGI Desktop Duplication or Windows.Graphics.Capture on
 * purpose. Duplication is markedly faster and is the right long-term backend,
 * but it is also a D3D11 device, a keyed mutex and a lost-access recovery path
 * — none of which can be got right without a machine to run them on. The veil
 * path caps VP8 bitrate and pads every RTP packet into a 16KB onion cell, so
 * screen share is bounded by the network long before it is bounded by BitBlt.
 * Correctness first; the upgrade is a drop-in replacement of this one class.
 *
 * Windows has no screen-recording consent gate, so the permission calls below
 * answer honestly rather than pretending a prompt exists.
 *
 * ⚠️ Written without a Windows host to compile on — see the note in
 * veil_mf_camera.cc. Never run.
 */
#include "veil_screen.h"
#include "veil_diag_log.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "third_party/libyuv/include/libyuv/convert.h"  // ARGBToI420
#include "third_party/libyuv/include/libyuv/scale.h"    // I420Scale

namespace veil_media {
namespace {

void scr_log(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  veil_media::diag::vlog(fmt, ap);
  va_end(ap);
}

struct MonitorInfo {
  std::string device_name;  // \\.\DISPLAY1
  RECT bounds{};
  bool primary = false;
};

BOOL CALLBACK collect_monitor(HMONITOR monitor, HDC, LPRECT, LPARAM param) {
  auto* out = reinterpret_cast<std::vector<MonitorInfo>*>(param);
  MONITORINFOEXA info{};
  info.cbSize = sizeof(info);
  if (GetMonitorInfoA(monitor, &info) == 0) return TRUE;  // skip, keep going
  MonitorInfo entry;
  entry.device_name = info.szDevice;
  entry.bounds = info.rcMonitor;
  entry.primary = (info.dwFlags & MONITORINFOF_PRIMARY) != 0;
  out->push_back(std::move(entry));
  return TRUE;
}

std::vector<MonitorInfo> monitors() {
  std::vector<MonitorInfo> out;
  EnumDisplayMonitors(nullptr, nullptr, collect_monitor,
                      reinterpret_cast<LPARAM>(&out));
  return out;
}

// `display:2`, a bare `2` (the pre-`display:` ABI) or empty for the primary.
// Out of range falls back to the primary rather than failing: a stale id from
// a screen that has since been unplugged should not break sharing.
int index_from_source_id(const char* source_id, size_t count) {
  if (source_id == nullptr || *source_id == '\0' || count == 0) return -1;
  const char* digits = source_id;
  const char* colon = std::strchr(source_id, ':');
  if (colon != nullptr) {
    if (std::strncmp(source_id, "display:", 8) != 0) return -1;
    digits = colon + 1;
  }
  char* end = nullptr;
  const long value = std::strtol(digits, &end, 10);
  if (end == digits || value < 0 || static_cast<size_t>(value) >= count) {
    return -1;
  }
  return static_cast<int>(value);
}

class GdiScreenCapturer : public ScreenCapturer {
 public:
  GdiScreenCapturer(CameraFrameCb cb, std::string source_id)
      : cb_(std::move(cb)), source_id_(std::move(source_id)) {}
  ~GdiScreenCapturer() override { Stop(); }

  bool Start(int width, int fps) override {
    if (running_.load()) return true;
    if (fps <= 0) fps = 10;
    target_w_ = width > 0 ? width : 0;

    const std::vector<MonitorInfo> screens = monitors();
    if (screens.empty()) {
      scr_log("no displays");
      return false;
    }
    int index = index_from_source_id(source_id_.c_str(), screens.size());
    if (index < 0) {
      index = 0;
      for (size_t i = 0; i < screens.size(); ++i) {
        if (screens[i].primary) {
          index = static_cast<int>(i);
          break;
        }
      }
    }
    const MonitorInfo& screen = screens[static_cast<size_t>(index)];
    origin_x_ = screen.bounds.left;
    origin_y_ = screen.bounds.top;
    cap_w_ = screen.bounds.right - screen.bounds.left;
    cap_h_ = screen.bounds.bottom - screen.bounds.top;
    if (cap_w_ <= 0 || cap_h_ <= 0) return false;

    // A DC on the whole virtual desktop plus the monitor's origin, rather than
    // a per-device CreateDC: mirrored and duplicated displays share a device
    // name, and blitting from the desktop with an offset is the one form that
    // is right in every arrangement.
    screen_dc_ = GetDC(nullptr);
    if (screen_dc_ == nullptr) return false;
    mem_dc_ = CreateCompatibleDC(screen_dc_);
    if (mem_dc_ == nullptr) return CleanupFail();

    BITMAPINFO bmi{};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = cap_w_;
    bmi.bmiHeader.biHeight = -cap_h_;  // negative = top-down rows
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    bitmap_ = CreateDIBSection(mem_dc_, &bmi, DIB_RGB_COLORS, &bits_, nullptr,
                               0);
    if (bitmap_ == nullptr || bits_ == nullptr) return CleanupFail();
    old_bitmap_ = static_cast<HBITMAP>(SelectObject(mem_dc_, bitmap_));

    running_.store(true);
    interval_us_ = 1000000 / fps;
    thread_ = std::thread([this] { CaptureLoop(); });
    scr_log("started GDI screen %d: %dx%d at (%d,%d) -> target %d", index,
            cap_w_, cap_h_, origin_x_, origin_y_, target_w_);
    return true;
  }

  void Stop() override {
    if (!running_.exchange(false)) {
      Release();
      return;
    }
    if (thread_.joinable()) thread_.join();
    Release();
  }

 private:
  bool CleanupFail() {
    Release();
    return false;
  }

  void Release() {
    if (mem_dc_ != nullptr && old_bitmap_ != nullptr) {
      SelectObject(mem_dc_, old_bitmap_);
      old_bitmap_ = nullptr;
    }
    if (bitmap_ != nullptr) {
      DeleteObject(bitmap_);
      bitmap_ = nullptr;
    }
    if (mem_dc_ != nullptr) {
      DeleteDC(mem_dc_);
      mem_dc_ = nullptr;
    }
    if (screen_dc_ != nullptr) {
      ReleaseDC(nullptr, screen_dc_);
      screen_dc_ = nullptr;
    }
    bits_ = nullptr;
  }

  void CaptureLoop() {
    while (running_.load()) {
      const auto started = std::chrono::steady_clock::now();
      // CAPTUREBLT includes layered windows; without it transparent and
      // hardware-composited surfaces come out as black rectangles, which reads
      // to the person sharing as "it did not capture my app".
      if (BitBlt(mem_dc_, 0, 0, cap_w_, cap_h_, screen_dc_, origin_x_,
                 origin_y_, SRCCOPY | CAPTUREBLT) != 0 &&
          cb_ != nullptr) {
        Deliver();
      }
      // Sleep the remainder of the frame interval rather than a flat interval:
      // BitBlt on a 4K display is not free, and adding it to the period drifts
      // the frame rate well below what was asked for.
      const auto spent = std::chrono::duration_cast<std::chrono::microseconds>(
                             std::chrono::steady_clock::now() - started)
                             .count();
      if (spent < interval_us_) {
        std::this_thread::sleep_for(
            std::chrono::microseconds(interval_us_ - spent));
      }
    }
  }

  void Deliver() {
    const int w = cap_w_, h = cap_h_;
    const int cw = (w + 1) / 2, ch = (h + 1) / 2;
    y_.resize(static_cast<size_t>(w) * h);
    u_.resize(static_cast<size_t>(cw) * ch);
    v_.resize(static_cast<size_t>(cw) * ch);
    if (libyuv::ARGBToI420(static_cast<const uint8_t*>(bits_), w * 4, y_.data(),
                           w, u_.data(), cw, v_.data(), cw, w, h) != 0) {
      return;
    }

    if (target_w_ > 0 && w > target_w_) {
      const int ow = target_w_ & ~1;
      int oh = ((h * ow / w) + 1) & ~1;
      if (oh < 2) oh = 2;
      const int ocw = (ow + 1) / 2, och = (oh + 1) / 2;
      sy_.resize(static_cast<size_t>(ow) * oh);
      su_.resize(static_cast<size_t>(ocw) * och);
      sv_.resize(static_cast<size_t>(ocw) * och);
      libyuv::I420Scale(y_.data(), w, u_.data(), cw, v_.data(), cw, w, h,
                        sy_.data(), ow, su_.data(), ocw, sv_.data(), ocw, ow,
                        oh, libyuv::kFilterBilinear);
      cb_(sy_.data(), su_.data(), sv_.data(), ow, oh, ow, ocw, ocw,
          /*ts_us=*/0);
    } else {
      cb_(y_.data(), u_.data(), v_.data(), w, h, w, cw, cw, /*ts_us=*/0);
    }
  }

  CameraFrameCb cb_;
  std::string source_id_;
  std::atomic<bool> running_{false};
  std::thread thread_;
  HDC screen_dc_ = nullptr;
  HDC mem_dc_ = nullptr;
  HBITMAP bitmap_ = nullptr;
  HBITMAP old_bitmap_ = nullptr;
  void* bits_ = nullptr;
  int origin_x_ = 0, origin_y_ = 0;
  int cap_w_ = 0, cap_h_ = 0;
  int target_w_ = 0;
  int64_t interval_us_ = 100000;
  std::vector<uint8_t> y_, u_, v_;
  std::vector<uint8_t> sy_, su_, sv_;
};

}  // namespace

ScreenCapturer* CreatePlatformScreen(CameraFrameCb cb, const char* source_id) {
  return new GdiScreenCapturer(std::move(cb),
                               source_id != nullptr ? source_id : "");
}

std::string ListPlatformScreensJson() {
  const std::vector<MonitorInfo> screens = monitors();
  std::string out = "[";
  for (size_t i = 0; i < screens.size(); ++i) {
    if (i != 0) out.push_back(',');
    const int width = screens[i].bounds.right - screens[i].bounds.left;
    const int height = screens[i].bounds.bottom - screens[i].bounds.top;
    out += "{\"id\":\"display:" + std::to_string(i) + "\",\"label\":\"";
    out += screens[i].primary ? "Primary display" : "Display";
    out += " " + std::to_string(i + 1) + " (" + std::to_string(width) + "x" +
           std::to_string(height) + ")";
    out += "\",\"kind\":\"screen\"}";
  }
  out.push_back(']');
  return out;
}

// Windows grants desktop capture to any process in the user's session; there
// is no consent gate to report on and none to request. Saying "granted" here
// is the truth, not a stub — the macOS pair exists because ScreenCaptureKit
// has a real prompt behind it.
bool PlatformScreenAccessGranted() { return true; }
bool RequestPlatformScreenAccess() { return true; }

}  // namespace veil_media
