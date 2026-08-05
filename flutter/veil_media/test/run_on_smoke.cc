// Lifetime contract of `run_on_with_timeout` (audit report8 H-07).
//
// The engine's 15 callsites all pass `[&]` lambdas capturing their own stack.
// The only thing standing between that and a use-after-free is the promise
// that the callback never runs after the call returns. These tests hold that
// promise to the fire; they need no task queue implementation and no
// sanitizer to fail.
//
// Build/run: test/run_run_on_smoke.sh

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <memory>
#include <thread>
#include <utility>

#include "veil_run_on.h"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  std::printf("%s  %s\n", ok ? "ok  " : "FAIL", what);
  if (!ok) ++g_failures;
}

// A queue that does exactly what a wedged worker queue does: accepts the task
// and does not run it until told to.
class HeldQueue {
 public:
  bool IsCurrent() const { return false; }

  template <typename T>
  void PostTask(T&& t) {
    task_ = std::function<void()>(std::forward<T>(t));
  }

  void RunPending() {
    if (!task_) return;
    auto t = std::move(task_);
    task_ = nullptr;
    t();
  }

  bool has_pending() const { return static_cast<bool>(task_); }

 private:
  std::function<void()> task_;
};

// A queue that runs the task on another thread, like a live worker queue.
class ThreadedQueue {
 public:
  ~ThreadedQueue() {
    if (t_.joinable()) t_.join();
  }

  bool IsCurrent() const { return false; }

  template <typename T>
  void PostTask(T&& t) {
    t_ = std::thread(std::function<void()>(std::forward<T>(t)));
  }

 private:
  std::thread t_;
};

class InlineQueue {
 public:
  bool IsCurrent() const { return true; }
  template <typename T>
  void PostTask(T&&) {
    std::abort();  // must never be reached: IsCurrent() short-circuits
  }
};

// Stands in for the caller's stack frame. Heap-allocated so that a callback
// which fires after abandonment is a genuine use-after-free -- the counter
// below makes it deterministic without a sanitizer, and ASan makes it loud
// with one.
struct Frame {
  int value = 0;
};

// ---------------------------------------------------------------------------

// The finding itself: a queue that does not schedule in time, a caller that
// gives up, and a task that surfaces afterwards.
void abandoned_task_must_never_run() {
  HeldQueue q;
  std::atomic<int> invocations{0};
  auto frame = std::make_unique<Frame>();
  // Deliberately a raw pointer, not the owner: after `frame` is released the
  // write below is a real use-after-free rather than a null dereference. A
  // null deref would abort the process before the check that matters could
  // print, which is the difference between a test that reports and a test
  // that merely dies.
  Frame* raw = frame.get();

  const bool ran = veil_media::run_on_with_timeout(
      &q,
      [&]() {
        invocations.fetch_add(1);
        raw->value = 42;  // writes into the caller's frame
      },
      std::chrono::milliseconds(50));

  check(!ran, "a task the queue never scheduled reports false, not success");
  check(invocations.load() == 0, "the callback did not run while we waited");

  // The caller has returned; its frame is gone.
  frame.reset();

  // Now the wedged queue wakes up. This is the moment the old shape corrupted
  // memory.
  q.RunPending();

  check(invocations.load() == 0,
        "the callback did NOT run after the call returned (H-07)");
}

// A task that starts before the deadline but outlives it must be waited out,
// not abandoned -- it already holds references into the frame.
void started_task_is_waited_out() {
  ThreadedQueue q;
  std::atomic<bool> finished{false};

  const bool ran = veil_media::run_on_with_timeout(
      &q,
      [&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        finished.store(true);
      },
      std::chrono::milliseconds(20));

  check(ran, "a callback slower than the timeout still reports success");
  check(finished.load(),
        "the call did not return until the callback had finished");
}

void completed_task_reports_success() {
  ThreadedQueue q;
  std::atomic<int> invocations{0};

  const bool ran = veil_media::run_on_with_timeout(
      &q, [&]() { invocations.fetch_add(1); },
      std::chrono::milliseconds(2000));

  check(ran, "a callback the queue ran reports success");
  check(invocations.load() == 1, "it ran exactly once");
}

void current_queue_runs_inline() {
  InlineQueue q;
  std::atomic<int> invocations{0};
  const bool ran = veil_media::run_on_with_timeout(
      &q, [&]() { invocations.fetch_add(1); }, std::chrono::milliseconds(50));
  check(ran && invocations.load() == 1,
        "already on the queue: runs inline, never posts");
}

void null_queue_runs_inline() {
  std::atomic<int> invocations{0};
  const bool ran = veil_media::run_on_with_timeout(
      static_cast<HeldQueue*>(nullptr), [&]() { invocations.fetch_add(1); },
      std::chrono::milliseconds(50));
  check(ran && invocations.load() == 1, "null queue: runs inline");
}

}  // namespace

int main() {
  // Unbuffered: if a regression turns a check into a crash, the checks that
  // already ran must still have reached the operator.
  std::setvbuf(stdout, nullptr, _IONBF, 0);

  abandoned_task_must_never_run();
  started_task_is_waited_out();
  completed_task_reports_success();
  current_queue_runs_inline();
  null_queue_runs_inline();

  if (g_failures != 0) {
    std::printf("\n%d check(s) failed\n", g_failures);
    return 1;
  }
  std::printf("\nall run_on lifetime checks passed\n");
  return 0;
}
