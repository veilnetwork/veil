/* SPDX-License-Identifier: MIT */
#pragma once

#include <cstdint>

namespace veil_media {

// RTCP LSR echoes this endpoint's compact NTP clock, so no remote clock offset
// is involved. After an outbound handover, a report about an older local SR
// cannot establish the new route's propagation floor. Caller owns locking.
class RtcpRouteClock {
 public:
  void Reset(uint32_t compact_ntp) {
    floor_ = compact_ntp;
    ++epoch_;
  }

  uint64_t epoch() const { return epoch_; }

  bool Accepts(uint32_t last_sr) const {
    if (last_sr == 0) return false;  // RFC 3550: no sender report received.
    if (epoch_ == 0) return true;
    const uint32_t since = last_sr - floor_;
    // Compact NTP wraps every ~18 hours. Reports are fresh for seconds, well
    // inside the half range. Equal quantized timestamps are conservative:
    // they cannot prove that the SR was generated after the route switch.
    return since != 0 && since < 0x80000000u;
  }

 private:
  uint32_t floor_ = 0;
  uint64_t epoch_ = 0;
};

}  // namespace veil_media
