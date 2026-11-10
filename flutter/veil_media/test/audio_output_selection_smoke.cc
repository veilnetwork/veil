#include "veil_audio_output_selection.h"

#include <cstdio>
#include <string>
#include <vector>

struct Adm {
  bool playing = true;
  int current = 5;
  int stop_result = 0;
  int rejected_index = -2;
  int init_failures = 0;
  int start_failures = 0;
  int init_calls = 0;
  int start_calls = 0;
  int default_calls = 0;
  std::vector<int> selections;
  bool Playing() { return playing; }
  int StopPlayout() {
    if (stop_result == 0) playing = false;
    return stop_result;
  }
  int SetPlayoutDevice(uint16_t index) {
    selections.push_back(index);
    if (index == rejected_index) return -1;
    current = index;
    return 0;
  }
  int InitPlayout() {
    ++init_calls;
    if (init_failures > 0) { --init_failures; return -1; }
    return 0;
  }
  int StartPlayout() {
    ++start_calls;
    if (start_failures > 0) { --start_failures; return -1; }
    playing = true;
    return 0;
  }
  int SetDefault() { ++default_calls; current = -1; return 0; }
};

int main() {
  int checks = 0, failures = 0;
  const auto check = [&](bool ok, const char* label) {
    ++checks;
    if (!ok) { ++failures; std::fprintf(stderr, "FAIL: %s\n", label); }
  };
  const auto select = [](Adm& adm, const char* id, int& remembered) {
    return veil_media::SelectAudioOutput(
        &adm, id, remembered, [&] { return adm.SetDefault(); });
  };
  {
    Adm adm; int remembered = 5;
    check(select(adm, "system-default", remembered), "default selection succeeds");
    check(adm.default_calls == 1 && adm.selections.empty() && remembered == -1,
          "default uses the OS role, not device zero");
    check(adm.playing, "active default selection restarts playout");
  }
  {
    Adm adm; int remembered = 5;
    check(select(adm, "2", remembered) && remembered == 2 && adm.current == 2 &&
          adm.playing && adm.init_calls == 1 && adm.start_calls == 1,
          "active explicit selection remains supported");
  }
  {
    Adm adm; adm.playing = false; int remembered = 5;
    check(select(adm, "2", remembered) && remembered == 2 && adm.current == 2 &&
          !adm.playing && adm.init_calls == 0 && adm.start_calls == 0,
          "idle selection leaves initialization to audio startup");
  }
  for (const std::string stage : {"set", "init", "start"}) {
    Adm adm; int remembered = 5;
    if (stage == "set") adm.rejected_index = 2;
    if (stage == "init") adm.init_failures = 1;
    if (stage == "start") adm.start_failures = 1;
    check(!select(adm, "2", remembered), "a failed switch is reported");
    check(remembered == 5 && adm.current == 5 && adm.playing,
          "a failed switch resumes the previous output");
  }
  for (const char* id : {"", "-1", "2extra", "65536", "default", " 2"}) {
    Adm adm; int remembered = 5;
    check(!select(adm, id, remembered), "malformed ID is refused");
    check(adm.playing && adm.selections.empty() && adm.init_calls == 0 &&
          remembered == 5, "invalid ID cannot interrupt the current output");
  }
  {
    Adm adm; adm.stop_result = -1; int remembered = 5;
    check(!select(adm, "2", remembered) && remembered == 5 && adm.playing &&
          adm.selections.empty(), "stop failure leaves the choice unchanged");
  }
  {
    Adm adm; adm.init_failures = 5; int remembered = 5;
    check(!select(adm, "2", remembered) && remembered == 5 && adm.init_calls == 2,
          "failed rollback is bounded and never reported as success");
  }
  std::printf("checks=%d failures=%d\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
