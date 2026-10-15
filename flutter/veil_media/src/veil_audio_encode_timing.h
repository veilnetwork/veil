/* SPDX-License-Identifier: MIT */
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

#include "veil_diag_log.h"

namespace veil_media {

// Opt-in metadata on the encoder's serialized queue. No samples or payloads
// are retained, and file I/O happens only after the owner stops the encoder.
class AudioEncodeTiming {
 public:
  explicit AudioEncodeTiming(uint32_t ssrc, int rtp_hz = 48000)
      : enabled_(diag::enabled() && ssrc != 0),
        capacity_(diag::rtp_trace_capacity()), ssrc_(ssrc), rtp_hz_(rtp_hz) {
    if (enabled_) packets_.reserve(capacity_);
  }
  ~AudioEncodeTiming() { Flush(); }
  bool enabled() const { return enabled_; }

  void Allocation(int64_t now_us, int64_t raw_bps, int64_t ana_bps,
                  size_t overhead_bytes) {
    if (enabled_) allocation_ = {now_us, raw_bps, ana_bps, overhead_bytes};
  }

  void Input(uint32_t timestamp, int64_t now_us) {
    if (!enabled_) return;
    inputs_[input_count_ % inputs_.size()] = {timestamp, now_us, input_count_};
    ++input_count_;
  }

  void Encoded(uint32_t timestamp, int64_t now_us, size_t blocks, size_t bytes) {
    if (!enabled_ || bytes == 0) return;
    ++packets_seen_;
    if (packets_.size() >= capacity_) return;
    int64_t first_us = -1, first_index = -1;
    for (size_t i = 0; i < std::min<uint64_t>(input_count_, inputs_.size()); ++i) {
      const auto& input = inputs_[(input_count_ - i - 1) % inputs_.size()];
      if (input.timestamp == timestamp) {
        first_us = input.at_us;
        first_index = static_cast<int64_t>(input.index);
        break;
      }
    }
    packets_.push_back({timestamp, first_us, first_index, now_us, blocks, bytes,
                        allocation_});
  }

 private:
  void Flush() const {
    if (!enabled_) return;
    const char* path = diag::path();
    if (path == nullptr) return;
    FILE* file = std::fopen(path, "a");
    if (file == nullptr) return;
    std::fprintf(file,
        "audio.encode.begin ssrc=%u count=%zu limit=%zu inputs=%llu seen=%llu rtp_hz=%d\n",
        ssrc_, packets_.size(), capacity_, (unsigned long long)input_count_,
        (unsigned long long)packets_seen_, rtp_hz_);
    for (const auto& packet : packets_) {
      std::fprintf(file,
          "audio.encode ssrc=%u timestamp=%u first_us=%lld first_index=%lld encoded_us=%lld blocks=%zu bytes=%zu allocation_us=%lld allocation_raw_bps=%lld allocation_ana_bps=%lld allocation_overhead_bytes=%zu\n",
          ssrc_, packet.timestamp, (long long)packet.first_us,
          (long long)packet.first_index, (long long)packet.encoded_us,
          packet.blocks, packet.bytes, (long long)packet.allocation.at_us,
          (long long)packet.allocation.raw_bps,
          (long long)packet.allocation.ana_bps, packet.allocation.overhead_bytes);
    }
    std::fclose(file);
  }

  struct InputSample { uint32_t timestamp; int64_t at_us; uint64_t index; };
  struct AllocationSample {
    int64_t at_us = -1, raw_bps = 0, ana_bps = 0;
    size_t overhead_bytes = 0;
  };
  struct Packet {
    uint32_t timestamp;
    int64_t first_us, first_index, encoded_us;
    size_t blocks, bytes;
    AllocationSample allocation;
  };
  const bool enabled_;
  const size_t capacity_;
  const uint32_t ssrc_;
  const int rtp_hz_;
  uint64_t input_count_ = 0, packets_seen_ = 0;
  std::array<InputSample, 32> inputs_{};
  std::vector<Packet> packets_;
  AllocationSample allocation_;
};

}  // namespace veil_media
