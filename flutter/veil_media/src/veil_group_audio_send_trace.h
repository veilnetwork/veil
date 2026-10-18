/* SPDX-License-Identifier: MIT */
#pragma once

#include <cstdint>
#include <mutex>
#include <span>
#include <vector>

#include "veil_audio_redundancy.h"
#include "veil_diag_log.h"

namespace veil_media {

// Endpoint-only, opt-in metadata for each fanout copy of real audio RTP.
// Reserve before streams start. Recording performs no allocation or file I/O;
// the owner must stop its send streams before destroying this recorder.
class GroupAudioSendTrace {
 public:
  explicit GroupAudioSendTrace(uint32_t ssrc)
      : enabled_(diag::enabled() && ssrc != 0),
        capacity_(diag::rtp_trace_capacity()), ssrc_(ssrc) {
    if (enabled_) packets_.reserve(capacity_);
  }

  bool enabled() const { return enabled_; }

  ~GroupAudioSendTrace() {
    if (!enabled_) return;
    const char* path = diag::path();
    if (path == nullptr) return;
    FILE* file = std::fopen(path, "a");
    if (file == nullptr) return;
    std::fprintf(file,
        "audio.group.send.begin ssrc=%u count=%zu limit=%zu seen=%llu\n",
        ssrc_, packets_.size(), capacity_, (unsigned long long)seen_);
    for (const auto& packet : packets_) {
      std::fprintf(file,
          "audio.group.send channel=%llu seq=%u timestamp=%u attempted_us=%lld admitted_us=%lld packet_bytes=%zu accepted=%d\n",
          (unsigned long long)packet.channel, unsigned(packet.key & 0xffff),
          unsigned(packet.key >> 16), (long long)packet.attempted_us,
          (long long)packet.admitted_us, packet.bytes, int(packet.accepted));
    }
    std::fclose(file);
  }

  void Record(uint64_t channel, std::span<const uint8_t> packet,
              int64_t attempted_us, int64_t admitted_us, bool accepted) {
    if (!enabled_) return;
    const auto key = AudioPayloadKey(packet, ssrc_);
    if (!key) return;
    // Independent of the membership mutex and all transport operations.
    // Video and RTCP never take this diagnostic lock.
    std::lock_guard lock(mu_);
    ++seen_;
    if (packets_.size() < capacity_)
      packets_.push_back({channel, *key, attempted_us, admitted_us,
                          packet.size(), accepted});
  }

 private:
  struct Packet {
    uint64_t channel, key;
    int64_t attempted_us, admitted_us;
    size_t bytes;
    bool accepted;
  };
  const bool enabled_;
  const size_t capacity_;
  const uint32_t ssrc_;
  std::mutex mu_;
  uint64_t seen_ = 0;
  std::vector<Packet> packets_;
};

}  // namespace veil_media
