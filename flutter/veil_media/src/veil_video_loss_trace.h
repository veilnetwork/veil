/* SPDX-License-Identifier: MIT */
#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <span>
#include <vector>

#include "veil_diag_log.h"

namespace veil_media {

// Endpoint-only metadata. Reserve before streams start; never retain media or
// perform file I/O on a packet callback. Audio RTP does not enter this recorder.
// The owner destroys it after stopping streams and fencing receive callbacks.
class VideoLossTrace {
 public:
  explicit VideoLossTrace(bool enabled = diag::enabled(),
                          size_t packets = 131072, size_t reports = 8192)
      : enabled_(enabled), packet_limit_(std::min(packets, size_t(131072))),
        report_limit_(std::min(reports, size_t(8192))), id_(enabled ? NextId() : 0) {
    if (enabled_) { packets_.reserve(packet_limit_); reports_.reserve(report_limit_); }
  }
  ~VideoLossTrace() { Flush(); }

  void Rtp(std::span<const uint8_t> p, uint32_t expected_ssrc,
           char stage, int64_t at_us, int result) {
    if (!enabled_ || expected_ssrc == 0 || p.size() < 12 || p[0] >> 6 != 2 ||
        (p[1] & 127) != 96 || Word(p.data()+8) != expected_ssrc) return;
    size_t header = 12 + (p[0] & 15)*4;
    if (header > p.size()) return;
    if (p[0] & 16) {
      if (p.size()-header < 4) return;
      const size_t extension = 4 + size_t(Half(p.data()+header+2))*4;
      if (extension > p.size()-header) return;
      header += extension;
    }
    const size_t padding = (p[0] & 32) ? p.back() : 0;
    if ((p[0] & 32) && (padding == 0 || padding > p.size()-header)) return;
    std::lock_guard lock(mu_);
    if (flushed_) return;
    ++packet_seen_;
    if (packets_.size() < packet_limit_)
      packets_.push_back({at_us, Word(p.data()+8), Word(p.data()+4),
                         uint32_t(p.size()), uint32_t(p.size()-header-padding),
                         Half(p.data()+2), stage, bool(p[1]&128), result});
  }

  void Rtcp(std::span<const uint8_t> p, char stage, int64_t at_us, int result) {
    if (!enabled_) return;
    // Validate the whole compound before publishing even its first report.
    // Unknown types are skipped; invalid/truncated compounds yield no rows.
    bool valid = !p.empty() && p.size() <= 65536;
    size_t blocks = 0;
    for (size_t at = 0; valid && at < p.size();) {
      const auto bytes = BlockSize(p, at);
      if (!bytes || ++blocks > 64) { valid = false; break; }
      const size_t padding = (p[at]&32) ? p[at+bytes-1] : 0;
      if ((p[at]&32) && (at+bytes != p.size() || padding == 0 || padding > bytes-4)) {
        valid = false; break;
      }
      const size_t base = p[at+1] == 200 ? 28 : p[at+1] == 201 ? 8 : 0;
      if (base && bytes-padding < base + size_t(p[at]&31)*24) {
        valid = false; break;
      }
      at += bytes;
    }
    std::lock_guard lock(mu_);
    if (flushed_) return;
    if (!valid) { ++malformed_; return; }
    for (size_t at = 0; at < p.size(); at += BlockSize(p, at)) {
      const size_t base = p[at+1] == 200 ? 28 : p[at+1] == 201 ? 8 : 0;
      if (!base) continue;
      for (size_t i = 0; i < (p[at]&31); ++i) {
        const auto* b = p.data()+at+base+i*24;
        const uint32_t loss = uint32_t(b[5])<<16 | uint32_t(b[6])<<8 | b[7];
        const int32_t signed_loss = loss & 0x800000 ? int32_t(loss)-0x1000000 : int32_t(loss);
        ++report_seen_;
        if (reports_.size() < report_limit_)
          reports_.push_back({at_us, Word(p.data()+at+4), Word(b),
                             signed_loss, Word(b+8), Word(b+12), Word(b+16),
                             Word(b+20), stage, b[4], result});
      }
    }
  }

  void Flush() {
    if (!enabled_) return;
    std::lock_guard lock(mu_);
    if (flushed_) return;
    flushed_ = true;
    const auto* path = diag::path();
    if (!path) return;
    FILE* file = std::fopen(path, "a");
    if (!file) return;
    // A unique recorder id disambiguates retained peer shims in a group log.
    const auto id = static_cast<unsigned long long>(id_);
    std::fprintf(file, "video.loss.begin id=%llu packets=%zu packet_seen=%llu reports=%zu report_seen=%llu malformed=%llu\n",
                 id, packets_.size(), (unsigned long long)packet_seen_, reports_.size(),
                 (unsigned long long)report_seen_, (unsigned long long)malformed_);
    for (const auto& p : packets_)
      std::fprintf(file, "video.loss.rtp id=%llu stage=%c at_us=%lld ssrc=%u seq=%u timestamp=%u bytes=%u payload=%u marker=%d result=%d\n",
                   id, p.stage, (long long)p.at_us, p.ssrc, unsigned(p.sequence),
                   p.timestamp, p.bytes, p.payload, int(p.marker), p.result);
    for (const auto& r : reports_)
      std::fprintf(file, "video.loss.rr id=%llu stage=%c at_us=%lld reporter=%u ssrc=%u fraction=%u lost=%d highest=%u jitter=%u lsr=%u dlsr=%u result=%d\n",
                   id, r.stage, (long long)r.at_us, r.reporter, r.ssrc,
                   unsigned(r.fraction), r.lost, r.highest, r.jitter, r.lsr,
                   r.dlsr, r.result);
    const bool ok = std::fflush(file) == 0 && !std::ferror(file);
    std::fprintf(file, "video.loss.end id=%llu write_ok=%d\n", id, int(ok));
    std::fclose(file);
  }

 private:
  static uint64_t NextId() {
    static std::atomic<uint64_t> next{0};
    return next.fetch_add(1, std::memory_order_relaxed)+1;
  }
  static uint16_t Half(const uint8_t* p) { return uint16_t(p[0])<<8 | p[1]; }
  static uint32_t Word(const uint8_t* p) {
    return uint32_t(p[0])<<24 | uint32_t(p[1])<<16 | uint32_t(p[2])<<8 | p[3];
  }
  static size_t BlockSize(std::span<const uint8_t> p, size_t at) {
    if (p.size()-at < 4 || p[at]>>6 != 2) return 0;
    const size_t n = (size_t(Half(p.data()+at+2))+1)*4;
    return n <= p.size()-at ? n : 0;
  }
  struct Packet {
    int64_t at_us;
    uint32_t ssrc, timestamp, bytes, payload;
    uint16_t sequence;
    char stage;
    bool marker;
    int result;
  };
  struct Report {
    int64_t at_us;
    uint32_t reporter, ssrc;
    int32_t lost;
    uint32_t highest, jitter, lsr, dlsr;
    char stage;
    uint8_t fraction;
    int result;
  };
  const bool enabled_;
  const size_t packet_limit_, report_limit_;
  const uint64_t id_;
  std::mutex mu_;
  bool flushed_ = false;
  uint64_t packet_seen_ = 0, report_seen_ = 0, malformed_ = 0;
  std::vector<Packet> packets_;
  std::vector<Report> reports_;
};
}  // namespace veil_media
