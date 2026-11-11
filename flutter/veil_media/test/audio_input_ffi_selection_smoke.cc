// The runner extracts the exact production FFI body. The ADM only supplies
// controlled failures; selection/restart/rollback decisions remain production.
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#if __has_include("veil_audio_input_selection.h")
#include "veil_audio_input_selection.h"
#endif

namespace webrtc {
inline constexpr int kAdmMaxDeviceNameSize = 128;
inline constexpr int kAdmMaxGuidSize = 128;
struct AudioDeviceModule {
  enum WindowsDeviceType { kDefaultDevice = -1, kDefaultCommunicationDevice = -2 };
  int16_t device_count = 3;
  int16_t RecordingDevices() const { return device_count; }
  int16_t PlayoutDevices() const { return device_count; }
  int RecordingDeviceName(int16_t i, char* name, char*) {
    if (i < 0 || i >= device_count) return -1;
    std::strcpy(name, ("input-" + std::to_string(i)).c_str()); return 0;
  }
  int PlayoutDeviceName(int16_t i, char* name, char*) {
    if (i < 0 || i >= device_count) return -1;
    std::strcpy(name, ("output-" + std::to_string(i)).c_str()); return 0;
  }
  bool recording = true;
  bool initialized = true;
  int current = 5;
  int stops = 0, sets = 0, inits = 0, starts = 0;
  std::string fail;
  bool persistent_failure = false;
  int refused_communications_defaults = 0;
  bool Recording() const { return recording; }
  bool refuse(const char* step) {
    if (fail != step) return false;
    if (!persistent_failure) fail.clear();
    return true;
  }
  int StopRecording() {
    ++stops;
    if (refuse("stop")) return -1;
    recording = false; initialized = false; return 0;
  }
  int select(int next) {
    ++sets;
    if (recording || initialized || refuse("set")) return -1;
    current = next; return 0;
  }
  int SetRecordingDevice(uint16_t next) { return select(next); }
  int SetRecordingDevice(WindowsDeviceType next) {
    if (next == kDefaultCommunicationDevice && refused_communications_defaults > 0) {
      --refused_communications_defaults; ++sets; return -1;
    }
    return select(next);
  }
  int InitRecording() {
    ++inits;
    if (refuse("init")) return -1;
    initialized = true; return 0;
  }
  int StartRecording() {
    ++starts;
    if (!initialized || refuse("start")) return -1;
    recording = true; return 0;
  }
};
}
struct State { std::shared_ptr<webrtc::AudioDeviceModule> adm; };
struct VeilMediaEngine { std::shared_ptr<State> ws; };
int g_chosen_recording = 5;
constexpr int VEIL_MEDIA_OK = 0;
constexpr int VEIL_MEDIA_ERR_ARG = -1;
constexpr int VEIL_MEDIA_ERR_DEVICE = -2;
template <class F> void run_on_adm_thread(F f) { f(); }
#define VEIL_MEDIA_HAVE_WEBRTC 1
// No Windows system headers are involved. This selects the real FFI's Windows
// role-default branch on any build host, without claiming a physical driver.
#if defined(INPUT_FIXTURE_WINDOWS) && !defined(_WIN32)
#define _WIN32 1
#elif !defined(INPUT_FIXTURE_WINDOWS) && defined(_WIN32)
#undef _WIN32
#endif
#include "selected_input.inc"
char* dup_cstr(const std::string& s) {
  auto* p = static_cast<char*>(std::malloc(s.size() + 1));
  std::memcpy(p, s.c_str(), s.size() + 1); return p;
}
#include "listed_inputs.inc"


int main() {
  int checks = 0, failures = 0;
  const auto check = [&](bool ok, const char* scenario) {
    ++checks;
    if (!ok) { ++failures; std::cerr << "failed: " << scenario << '\n'; }
  };
  {
    auto adm = std::make_shared<webrtc::AudioDeviceModule>();
    VeilMediaEngine engine{std::make_shared<State>(State{adm})};
    char* raw = veil_media_engine_list_audio_inputs(&engine);
    const std::string listed(raw); std::free(raw);
#if defined(INPUT_FIXTURE_WINDOWS)
    check(listed.find("\"id\":\"system-default\",\"label\":\"System default\",\"kind\":\"input\"") != std::string::npos,
          "Windows enumerates an explicit dynamic input role");
#else
    check(listed.find("system-default") == std::string::npos,
          "non-Windows does not invent role metadata");
#endif
    check(listed.find("\"id\":\"0\"") != std::string::npos, "numeric input identifiers retained");
    adm->device_count = 0;
    raw = veil_media_engine_list_audio_inputs(&engine);
    check(std::string(raw) == "[]", "no microphone means no offered role");
    std::free(raw);
  }
  for (const std::string stage : {"set", "init", "start", "stop", "none"}) {
    auto adm = std::make_shared<webrtc::AudioDeviceModule>();
    adm->fail = stage;
    VeilMediaEngine engine{std::make_shared<State>(State{adm})};
    g_chosen_recording = 5;
    const int result = veil_media_engine_select_audio_input(&engine, "2");
    const bool success = stage == "none";
    check(result == (success ? VEIL_MEDIA_OK : VEIL_MEDIA_ERR_DEVICE), "transaction verdict");
    check(adm->recording, "capture survives failed switch");
    check(adm->current == (success ? 2 : 5), "previous device restored");
    check(g_chosen_recording == (success ? 2 : 5), "failed choice not saved");
    if (stage == "stop") check(adm->sets == 0, "failed stop forbids device switch");
  }
  for (const char* id : {"", "-1", "+2", "1x", "x1", " 2", "2 ", "65536", "99999999999999999999999999"}) {
    auto adm = std::make_shared<webrtc::AudioDeviceModule>();
    VeilMediaEngine engine{std::make_shared<State>(State{adm})};
    g_chosen_recording = 5;
    check(veil_media_engine_select_audio_input(&engine, id) == VEIL_MEDIA_ERR_DEVICE, "invalid identifier refused");
    check(adm->recording && adm->current == 5 && g_chosen_recording == 5, "invalid identifier leaves capture alone");
    check(adm->stops == 0 && adm->sets == 0 && adm->inits == 0 && adm->starts == 0, "parse before hardware access");
  }
  for (const bool initialized : {false, true}) {
    auto adm = std::make_shared<webrtc::AudioDeviceModule>();
    adm->recording = false; adm->initialized = initialized;
    VeilMediaEngine engine{std::make_shared<State>(State{adm})};
    g_chosen_recording = 5;
    check(veil_media_engine_select_audio_input(&engine, "2") == VEIL_MEDIA_OK, "idle choice accepted");
    check(g_chosen_recording == 2 && adm->current == 2, "idle choice remembered");
    check(!adm->recording && !adm->initialized && adm->inits == 0 && adm->starts == 0, "idle selection does not open the microphone");
  }
  {
    auto adm = std::make_shared<webrtc::AudioDeviceModule>();
#if defined(INPUT_FIXTURE_WINDOWS)
    adm->current = webrtc::AudioDeviceModule::kDefaultCommunicationDevice;
#else
    adm->current = 0;
#endif
    const int before = adm->current;
    adm->fail = "init";
    VeilMediaEngine engine{std::make_shared<State>(State{adm})};
    g_chosen_recording = -1;
    check(veil_media_engine_select_audio_input(&engine, "2") == VEIL_MEDIA_ERR_DEVICE, "default restoration reports refusal");
    check(adm->recording && adm->current == before && g_chosen_recording == -1, "restore OS default role");
  }
  {
    auto adm = std::make_shared<webrtc::AudioDeviceModule>();
    adm->fail = "start"; adm->persistent_failure = true;
    VeilMediaEngine engine{std::make_shared<State>(State{adm})};
    g_chosen_recording = 5;
    check(veil_media_engine_select_audio_input(&engine, "2") == VEIL_MEDIA_ERR_DEVICE, "failed rollback cannot become success");
    check(g_chosen_recording == 5 && adm->current == 5 && !adm->recording, "failed rollback keeps saved choice");
    check(adm->inits == 2 && adm->starts == 2, "rollback has one bounded attempt");
  }
  {
    auto adm = std::make_shared<webrtc::AudioDeviceModule>();
    VeilMediaEngine engine{std::make_shared<State>(State{adm})};
    g_chosen_recording = 5;
    check(veil_media_engine_select_audio_input(&engine, "system-default") == VEIL_MEDIA_OK, "system default is a role selection");
#if defined(INPUT_FIXTURE_WINDOWS)
    check(adm->current == webrtc::AudioDeviceModule::kDefaultCommunicationDevice, "input default uses communications role");
#else
    check(adm->current == 0, "nonwindows default uses its numeric ADM default");
#endif
    check(g_chosen_recording == -1 && adm->recording, "default remains dynamic and active");
  }
#if defined(INPUT_FIXTURE_WINDOWS)
  {
    auto adm = std::make_shared<webrtc::AudioDeviceModule>();
    adm->current = webrtc::AudioDeviceModule::kDefaultDevice;
    adm->fail = "init"; adm->refused_communications_defaults = 1;
    VeilMediaEngine engine{std::make_shared<State>(State{adm})};
    g_chosen_recording = -1;
    check(veil_media_engine_select_audio_input(&engine, "2") == VEIL_MEDIA_ERR_DEVICE, "failed switch reports error with default fallback");
    check(adm->recording && adm->current == webrtc::AudioDeviceModule::kDefaultDevice && g_chosen_recording == -1,
          "unavailable communications role falls back to OS default");
  }
#endif
  std::cout << "input_ffi_checks=" << checks << " failures=" << failures << '\n';
  return failures ? 1 : 0;
}
