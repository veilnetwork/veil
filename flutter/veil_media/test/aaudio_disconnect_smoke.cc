#undef NDEBUG
#include <aaudio/AAudio.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <memory>
#include <mutex>
#include <thread>
#include <string_view>
#include <vector>
#include "api/environment/environment_factory.h"
#include "veil_aaudio_adm.h"

using namespace std::chrono_literals;
struct AAudioStreamBuilder {
  int direction = 0;
  AAudioStream_dataCallback data = nullptr;
  AAudioStream_errorCallback error = nullptr;
  void* ud = nullptr;
};
struct AAudioStream : AAudioStreamBuilder {
  bool started = false, closed = false;
};
struct MockState {
  std::mutex lock;
  std::vector<std::unique_ptr<AAudioStream>> streams;
};
static MockState* mock;
static std::atomic<int> fail_start{0}, fail_open{0};
static thread_local bool inside_error = false;
static std::atomic<bool> error_while_closing{false};
aaudio_result_t AAudio_createStreamBuilder(AAudioStreamBuilder** b) { *b = new AAudioStreamBuilder; return 0; }
aaudio_result_t AAudioStreamBuilder_delete(AAudioStreamBuilder* b) { delete b; return 0; }
void AAudioStreamBuilder_setDirection(AAudioStreamBuilder* b, int32_t d) { b->direction = d; }
void AAudioStreamBuilder_setSampleRate(AAudioStreamBuilder*, int32_t) {}
void AAudioStreamBuilder_setChannelCount(AAudioStreamBuilder*, int32_t) {}
void AAudioStreamBuilder_setFormat(AAudioStreamBuilder*, int32_t) {}
void AAudioStreamBuilder_setSharingMode(AAudioStreamBuilder*, int32_t) {}
void AAudioStreamBuilder_setPerformanceMode(AAudioStreamBuilder*, int32_t) {}
void AAudioStreamBuilder_setDeviceId(AAudioStreamBuilder*, int32_t) {}
void AAudioStreamBuilder_setDataCallback(AAudioStreamBuilder* b, AAudioStream_dataCallback f, void* ud) { b->data = f; b->ud = ud; }
void AAudioStreamBuilder_setErrorCallback(AAudioStreamBuilder* b, AAudioStream_errorCallback f, void* ud) { b->error = f; b->ud = ud; }
aaudio_result_t AAudioStreamBuilder_openStream(AAudioStreamBuilder* b, AAudioStream** s) {
  assert(!inside_error);
  if (fail_open.load() > 0) { --fail_open; *s = nullptr; return AAUDIO_ERROR_DISCONNECTED; }
  auto stream = std::make_unique<AAudioStream>();
  static_cast<AAudioStreamBuilder&>(*stream) = *b;
  *s = stream.get();
  std::lock_guard lock(mock->lock); mock->streams.push_back(std::move(stream)); return 0;
}
aaudio_result_t AAudioStream_requestStart(AAudioStream* s) {
  assert(!inside_error);
  if (fail_start.exchange(0)) return AAUDIO_ERROR_DISCONNECTED;
  std::lock_guard lock(mock->lock); assert(!s->closed); s->started = true; return 0;
}
aaudio_result_t AAudioStream_requestStop(AAudioStream* s) {
  assert(!inside_error);
  std::lock_guard lock(mock->lock); s->started = false; return 0;
}
aaudio_result_t AAudioStream_close(AAudioStream* s) {
  assert(!inside_error);
  // Exercise a callback racing an explicit stop. It must only enqueue and
  // cannot block on the ADM lifecycle mutex that the caller already holds.
  if (error_while_closing.exchange(false) && s->error) {
    inside_error = true; s->error(s, s->ud, AAUDIO_ERROR_DISCONNECTED); inside_error = false;
  }
  std::lock_guard lock(mock->lock); assert(!s->closed); s->closed = true; return 0;
}
int32_t AAudioStream_getSampleRate(AAudioStream*) { return 48000; }
int32_t AAudioStream_getChannelCount(AAudioStream*) { return 1; }
aaudio_format_t AAudioStream_getFormat(AAudioStream*) { return AAUDIO_FORMAT_PCM_I16; }
static size_t Count() { std::lock_guard lock(mock->lock); return mock->streams.size(); }
static AAudioStream* Latest(int direction) {
  std::lock_guard lock(mock->lock);
  for (auto it = mock->streams.rbegin(); it != mock->streams.rend(); ++it)
    if ((*it)->direction == direction && (*it)->started && !(*it)->closed) return it->get();
  return nullptr;
}
template <class F> static void Wait(F f) {
  const auto end = std::chrono::steady_clock::now() + 3s;
  while (!f() && std::chrono::steady_clock::now() < end) std::this_thread::sleep_for(1ms);
  assert(f());
}
static void Disconnect(AAudioStream* s) {
  assert(s && s->error);  // fails immediately on the old callback-less ADM
  { std::lock_guard lock(mock->lock); s->started = false; }
  inside_error = true; s->error(s, s->ud, AAUDIO_ERROR_DISCONNECTED); inside_error = false;
}
int main(int argc, char** argv) {
  assert(argc == 1 || (argc == 2 && std::string_view(argv[1]) == "--disconnect-only"));
  MockState state;
  mock = &state;
  auto adm = veil_media::CreateVeilAAudioAdm(webrtc::CreateEnvironment());
  assert(adm->Init() == 0);
  if (argc == 1) {
    fail_start = 1;
    assert(adm->StartRecording() == -1 && !adm->Recording());
    assert(Latest(AAUDIO_DIRECTION_INPUT) == nullptr);
    fail_start = 1;
    assert(adm->StartPlayout() == -1 && !adm->Playing());
    assert(Latest(AAUDIO_DIRECTION_OUTPUT) == nullptr);
  }
  assert(adm->StartRecording() == 0 && adm->StartPlayout() == 0);
  auto* rec = Latest(AAUDIO_DIRECTION_INPUT);
  auto* play = Latest(AAUDIO_DIRECTION_OUTPUT);
  Disconnect(rec);
  Wait([&] { auto* next = Latest(AAUDIO_DIRECTION_INPUT); return next && next != rec; });
  assert(Latest(AAUDIO_DIRECTION_OUTPUT) == play);
  Disconnect(play);
  Wait([&] { auto* next = Latest(AAUDIO_DIRECTION_OUTPUT); return next && next != play; });
  // PCM callbacks still run after recovery; playout without a transport is
  // defined silence, not an access to the retired fine buffer.
  int16_t pcm[480]{};
  rec = Latest(AAUDIO_DIRECTION_INPUT); play = Latest(AAUDIO_DIRECTION_OUTPUT);
  rec->data(rec, rec->ud, pcm, 480); play->data(play, play->ud, pcm, 480);
  fail_open = 2;
  Disconnect(rec);
  Wait([&] { auto* next = Latest(AAUDIO_DIRECTION_INPUT); return next && next != rec; });
  // An open can succeed while requestStart fails. Close that failed stream
  // and retry without losing the other live direction.
  play = Latest(AAUDIO_DIRECTION_OUTPUT);
  fail_start = 1;
  Disconnect(play);
  Wait([&] { auto* next = Latest(AAUDIO_DIRECTION_OUTPUT); return next && next != play; });
  assert(adm->Recording() && adm->Playing());
  error_while_closing = true;
  assert(adm->StopRecording() == 0);
  const auto stopped = Count();
  std::this_thread::sleep_for(350ms);
  assert(Count() == stopped && Latest(AAUDIO_DIRECTION_INPUT) == nullptr);
  assert(adm->StartRecording() == 0);
  // Teardown with a pending failure must join the worker and cannot reopen
  // after Terminate/destruction. Closed mock streams retain no live callback.
  fail_open = 20;
  Disconnect(Latest(AAUDIO_DIRECTION_INPUT));
  adm->Terminate(); adm = nullptr;
  const auto terminated = Count();
  std::this_thread::sleep_for(300ms);
  assert(Count() == terminated);
  for (const auto& stream : mock->streams) assert(stream->closed);
  std::puts("AAudio capture/playout disconnect, retry, start failure and teardown passed");
}

#ifndef VEIL_AAUDIO_SOURCE
#define VEIL_AAUDIO_SOURCE "../src/veil_aaudio_adm.cc"
#endif
#include VEIL_AAUDIO_SOURCE
