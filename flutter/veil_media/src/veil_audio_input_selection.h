#pragma once

#include "veil_audio_device_choice.h"

namespace veil_media {

// Caller serializes ADM access. Saving a selection means every required step
// succeeded, not just SetDevice. On failure, attempt the previous device with
// the same capture posture. An idle/muted module stays physically unopened;
// audio startup or an explicit unmute owns InitRecording/StartRecording.
template <class Adm, class SetDefault>
bool SelectAudioInput(Adm* adm, const char* id, int& remembered,
                      SetDefault set_default) {
  const auto choice = ParseAudioDeviceChoice(id);
  if (!choice || adm == nullptr) return false;
  const bool was_recording = adm->Recording();
  if (adm->StopRecording() != 0) return false;
  const auto set = [&](int index) {
    return index < 0 ? set_default()
                     : adm->SetRecordingDevice(static_cast<uint16_t>(index));
  };
  const int next = choice->system_default ? -1 : choice->index;
  const auto start_if_needed = [&] {
    return !was_recording ||
           (adm->InitRecording() == 0 && adm->StartRecording() == 0);
  };
  if (set(next) != 0 || !start_if_needed()) {
    if (adm->StopRecording() == 0 && set(remembered) == 0) start_if_needed();
    return false;
  }
  remembered = next;
  return true;
}

}  // namespace veil_media
