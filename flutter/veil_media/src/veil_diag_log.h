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
#include <cstdio>
#include <cstdlib>

namespace veil_media::diag {

inline const char* path() {
  const char* value = std::getenv("VEIL_MEDIA_DIAG_PATH");
  return value != nullptr && value[0] != '\0' ? value : nullptr;
}

inline bool enabled() { return path() != nullptr; }

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
