/* SPDX-License-Identifier: MIT
 *
 * Explicitly enabled native-media diagnostics.
 *
 * Media events can reveal call timing and device state. Distribution builds
 * therefore perform no file I/O unless the operator supplies an explicit
 * VEIL_MEDIA_DIAG_PATH. The helper is header-only so every small media target
 * shares the same fail-closed policy without adding another link dependency.
 */
#pragma once

#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>

namespace veil_media::diag {

inline const char* path() {
  const char* value = std::getenv("VEIL_MEDIA_DIAG_PATH");
  return value != nullptr && value[0] != '\0' ? value : nullptr;
}

inline bool enabled() { return path() != nullptr; }

inline constexpr size_t kDefaultRtpTraceCapacity = 4096;
inline constexpr size_t kMaxRtpTraceCapacity = 32768;

inline size_t rtp_trace_capacity() {
  if (!enabled()) return kDefaultRtpTraceCapacity;
  const char* value = std::getenv("VEIL_MEDIA_RTP_TRACE_LIMIT");
  if (value == nullptr || *value == '\0') return kDefaultRtpTraceCapacity;
  size_t count = 0;
  for (; *value != '\0'; ++value) {
    if (*value < '0' || *value > '9' || count > kMaxRtpTraceCapacity / 10)
      return kDefaultRtpTraceCapacity;
    count = count * 10 + static_cast<size_t>(*value - '0');
    if (count > kMaxRtpTraceCapacity) return kDefaultRtpTraceCapacity;
  }
  return count > 0 ? count : kDefaultRtpTraceCapacity;
}

inline void vlog(const char* fmt, va_list ap) {
  const char* output_path = path();
  if (output_path == nullptr) return;
  FILE* file = std::fopen(output_path, "a");
  if (file == nullptr) return;
  std::vfprintf(file, fmt, ap);
  std::fputc('\n', file);
  std::fclose(file);
}

inline void log(const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vlog(fmt, ap);
  va_end(ap);
}

}  // namespace veil_media::diag
