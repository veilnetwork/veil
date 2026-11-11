#pragma once

#include "veil_audio_device_choice.h"

namespace veil_media {

inline constexpr const auto& kSystemAudioOutputDeviceId = kSystemAudioDeviceId;
using AudioOutputChoice = AudioDeviceChoice;

inline std::optional<AudioOutputChoice> ParseAudioOutputChoice(const char* id) {
  return ParseAudioDeviceChoice(id);
}

// Caller serializes ADM access. An idle module is only configured here: its
// audio-start path owns initialization. An active switch either restarts on
// the new device or attempts to restore the old output, and reports failure.
template <class Adm, class SetDefault>
bool SelectAudioOutput(Adm* adm, const char* id, int& remembered,
                       SetDefault set_default) {
  const auto choice = ParseAudioOutputChoice(id);
  if (!choice || adm == nullptr) return false;
  const bool was_playing = adm->Playing();
  if (adm->StopPlayout() != 0) return false;
  const auto set = [&](int index) {
    return index < 0 ? set_default()
                     : adm->SetPlayoutDevice(static_cast<uint16_t>(index));
  };
  const int next = choice->system_default ? -1 : choice->index;
  const auto start_if_needed = [&] {
    return !was_playing || (adm->InitPlayout() == 0 && adm->StartPlayout() == 0);
  };
  if (set(next) != 0 || !start_if_needed()) {
    // A successful SetDevice alone says nothing about audible playout. Keep
    // the saved choice unchanged even if restoring the old driver also fails.
    if (adm->StopPlayout() == 0 && set(remembered) == 0) start_if_needed();
    return false;
  }
  remembered = next;
  return true;
}

}  // namespace veil_media
