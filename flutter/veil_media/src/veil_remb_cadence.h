#pragma once
// Endpoint-only cadence for redundant video bandwidth growth announcements.
// Reports containing loss blocks or any other feedback always pass through.
#include <array>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>

namespace veil_media {
class RembCadence {
 public:
  bool Allow(std::span<const uint8_t> packet, int64_t now_us, uint64_t scope) {
    const auto next = Parse(packet);
    if (!next || next->rate == 0) return true;
    std::lock_guard lock(mu_);
    return !last_ || scope != scope_ || now_us < sent_us_ ||
           now_us - sent_us_ >= 1'000'000 || next->sender != last_->sender ||
           next->ssrcs != last_->ssrcs || next->cname != last_->cname ||
           next->has_sdes != last_->has_sdes || next->rate < last_->rate;
  }

  // Failed local admission must not consume the next feedback opportunity.
  void Accepted(std::span<const uint8_t> packet, int64_t now_us, uint64_t scope) {
    auto next = Parse(packet);
    if (!next) return;
    std::lock_guard lock(mu_);
    last_ = next; sent_us_ = now_us; scope_ = scope;
  }

  void Reset() { std::lock_guard lock(mu_); last_.reset(); }

 private:
  struct Estimate {
    uint32_t sender = 0;
    uint64_t rate = 0;
    // Include count and wire order. Any target-list change passes immediately.
    std::array<uint32_t, 33> ssrcs{};
    std::array<uint8_t, 256> cname{};
    bool has_sdes = false;
  };
  static uint32_t Word(const uint8_t* p) {
    return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 |
           uint32_t(p[2]) << 8 | p[3];
  }
  static std::optional<Estimate> Parse(std::span<const uint8_t> p) {
    if (p.empty() || p.size() > 8192) return {};
    Estimate out;
    bool remb = false;
    std::optional<uint32_t> reporter;
    std::optional<uint32_t> sdes_sender;
    size_t at = 0, blocks = 0;
    while (at < p.size()) {
      if (p.size() - at < 4 || p[at] >> 6 != 2 || (p[at] & 0x20) || ++blocks > 64)
        return {};
      const size_t bytes = (size_t(p[at + 2]) * 256 + p[at + 3] + 1) * 4;
      if (bytes > p.size() - at) return {};
      const auto type = p[at + 1];
      const auto count = p[at] & 31;
      if (type == 200 || type == 201) {
        // A report carrying receiver/loss/RTT blocks is never coalesced.
        if (count != 0 || bytes != (type == 200 ? 28u : 8u) || reporter) return {};
        reporter = Word(p.data() + at + 4);
      } else if (type == 202) {
        // Leave unknown or malformed SDES framing untouched too.
        if (bytes < 12 || count != 1 || sdes_sender) return {};
        sdes_sender = Word(p.data() + at + 4);
        size_t item = 8;
        if (p[at+item] != 1) return {};  // Only the stable CNAME item.
        const size_t length = p[at+item+1];
        if (length + 11 > bytes) return {};
        out.cname[0] = length;
        for (size_t i = 0; i < length; ++i) out.cname[i+1] = p[at+item+2+i];
        item += 2 + length;
        for (; item < bytes; ++item) if (p[at+item] != 0) return {};
        out.has_sdes = true;
      } else if (type == 206 && count == 15) {
        if (remb || bytes < 24 || p[at+12] != 'R' || p[at+13] != 'E' ||
            p[at+14] != 'M' || p[at+15] != 'B') return {};
        const size_t n = p[at + 16];
        if (n == 0 || n > 32 || bytes != 20 + 4*n) return {};
        out.sender = Word(p.data() + at + 4);
        const unsigned exp = p[at + 17] >> 2;
        const uint64_t mantissa = uint64_t(p[at+17] & 3) << 16 |
                                  uint64_t(p[at+18]) << 8 | p[at+19];
        if (exp > 46) return {};  // Unusual/overflowing encodings pass through.
        out.rate = mantissa << exp;
        out.ssrcs[0] = n;
        for (size_t i = 0; i < n; ++i) out.ssrcs[i+1] = Word(p.data()+at+20+4*i);
        remb = true;
      } else {
        return {};  // NACK, PLI, FIR, APP, XR, BYE and future types stay immediate.
      }
      at += bytes;
    }
    if (!remb || (reporter && *reporter != out.sender) ||
        (sdes_sender && *sdes_sender != out.sender)) return {};
    return out;
  }
  std::mutex mu_;
  std::optional<Estimate> last_;
  int64_t sent_us_ = 0;
  uint64_t scope_ = 0;
};
}  // namespace veil_media
