#include "veil_owner_thread_ref.h"

#include <atomic>
#include <cstdio>
#include <stdexcept>
#include <thread>

namespace {
struct Observation {
  int destructions = 0;
  bool destroyed_on_owner = false;
  bool environment_alive = true;
  bool destroyed_before_environment = false;
};

// The dispatch closure is intentionally destroyed on the caller after execution.
// A ref-counted lambda capture must therefore not own the final reference.
void Dispatch(std::function<void()> fn) {
  std::thread worker([&] { fn(); });
  worker.join();
}

struct Device {
  explicit Device(Observation& observation) : observation(observation) {}
  std::atomic<int> refs{0};
  Observation& observation;
  void AddRef() { ++refs; }
  void Release() { if (--refs == 0) delete this; }
  static std::thread::id caller;
  ~Device() {
    ++observation.destructions;
    observation.destroyed_on_owner = std::this_thread::get_id() != caller;
    observation.destroyed_before_environment = observation.environment_alive;
  }
};
std::thread::id Device::caller;

struct Ref {
  Ref() = default;
  explicit Ref(Device* device) : device(device) { if (device) device->AddRef(); }
  Ref(const Ref& other) : Ref(other.device) {}
  Ref& operator=(const Ref& other) {
    if (other.device) other.device->AddRef();
    if (device) device->Release();
    device = other.device;
    return *this;
  }
  ~Ref() { if (device) device->Release(); }
  explicit operator bool() const { return device != nullptr; }
  Device* release() { auto* result = device; device = nullptr; return result; }
  Device* device = nullptr;
};

struct Environment {
  Observation& observation;
  ~Environment() { observation.environment_alive = false; }
};
struct State {
  explicit State(Observation& observation) : env{observation} {}
  Environment env;
  veil_media::OwnerThreadRef<Ref> lifetime{Dispatch};
  Ref adm;
  Ref audio_state;
  Ref call;
};
}  // namespace

int main() {
  Device::caller = std::this_thread::get_id();
  int checks = 0, failures = 0;
  auto check = [&](bool ok, const char* label) {
    ++checks;
    if (!ok) { ++failures; std::fprintf(stderr, "FAIL: %s\n", label); }
  };
  for (bool fail_construction : {false, true}) {
    Observation observation;
    try {
      State state(observation);
      state.adm = Ref(new Device(observation));
      state.lifetime.Retain(state.adm);
      if (fail_construction) throw std::runtime_error("construction failed");
      state.audio_state = state.adm;
      state.call = state.adm;
      check(observation.destructions == 0, "device survives while state is live");
    } catch (const std::runtime_error&) {}
    check(observation.destructions == 1, "all references release exactly once");
    check(observation.destroyed_on_owner, "last release is dispatched off caller");
    check(observation.destroyed_before_environment,
          "device destruction precedes environment destruction");
  }
  {
    Observation observation;
    State state(observation);
    state.lifetime.Retain(state.adm);
    check(observation.destructions == 0, "null device needs no final release");
  }
  std::printf("checks=%d failures=%d\n", checks, failures);
  return failures ? 1 : 0;
}
