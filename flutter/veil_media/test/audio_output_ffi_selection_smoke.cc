// The runner includes the unchanged production FFI function in this fixture.
#include "veil_audio_output_selection.h"
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

namespace webrtc {
struct AudioDeviceModule {
  bool playing = true;
  int current = 5;
  std::string fail;
  bool Playing() const { return playing; }
  bool refuse(const char* step) {
    if (fail != step) return false;
    fail.clear();
    return true;
  }
  int StopPlayout() {
    if (refuse("stop")) return -1;
    playing = false; return 0;
  }
  int SetPlayoutDevice(uint16_t index) {
    if (refuse("set")) return -1;
    current = index; return 0;
  }
  int InitPlayout() { return refuse("init") ? -1 : 0; }
  int StartPlayout() {
    if (refuse("start")) return -1;
    playing = true; return 0;
  }
};
}
struct State { std::shared_ptr<webrtc::AudioDeviceModule> adm; };
struct VeilMediaEngine { std::shared_ptr<State> ws; };
int g_chosen_playout = 5;
constexpr int VEIL_MEDIA_OK = 0;
constexpr int VEIL_MEDIA_ERR_ARG = -1;
constexpr int VEIL_MEDIA_ERR_DEVICE = -2;
template <class F> void run_on_adm_thread(F f) { f(); }
#define VEIL_MEDIA_HAVE_WEBRTC 1
// Exercise this branch on every CI host; system headers were included above.
#ifdef _WIN32
#undef _WIN32
#endif
#include "selected_output.inc"

int main() {
  int checks = 0, failures = 0;
  for (const std::string stage : {"set", "init", "start", "stop", "none"}) {
    auto adm = std::make_shared<webrtc::AudioDeviceModule>();
    adm->fail = stage;
    VeilMediaEngine engine{std::make_shared<State>(State{adm})};
    g_chosen_playout = 5;
    const int result = veil_media_engine_select_audio_output(&engine, "2");
    const bool success = stage == "none";
    const auto check = [&](bool ok) { ++checks; if (!ok) ++failures; };
    check(result == (success ? VEIL_MEDIA_OK : VEIL_MEDIA_ERR_DEVICE));
    check(adm->playing);
    check(adm->current == (success ? 2 : 5));
    check(g_chosen_playout == (success ? 2 : 5));
  }
  std::cout << "nonwindows_ffi_checks=" << checks << " failures=" << failures << '\n';
  return failures ? 1 : 0;
}
