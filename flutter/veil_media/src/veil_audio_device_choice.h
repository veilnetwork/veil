#pragma once

#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>

namespace veil_media {

inline constexpr char kSystemAudioDeviceId[] = "system-default";

struct AudioDeviceChoice {
  bool system_default;
  uint16_t index;
};

inline std::optional<AudioDeviceChoice> ParseAudioDeviceChoice(const char* id) {
  if (id == nullptr || *id == '\0') return std::nullopt;
  if (std::strcmp(id, kSystemAudioDeviceId) == 0) {
    return AudioDeviceChoice{true, 0};
  }
  unsigned index = 0;
  for (const char* p = id; *p; ++p) {
    if (*p < '0' || *p > '9') return std::nullopt;
    index = index * 10 + static_cast<unsigned>(*p - '0');
    if (index > std::numeric_limits<uint16_t>::max()) return std::nullopt;
  }
  return AudioDeviceChoice{false, static_cast<uint16_t>(index)};
}

}  // namespace veil_media
