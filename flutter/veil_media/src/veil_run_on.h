// Blocking "run this on that task queue" with a cancel handshake.
//
// This header is deliberately free of WebRTC types: the rule it enforces is
// about object lifetime, not about media, and it must be unit-testable
// without a task queue implementation. `veil_media_engine.cc` wraps it for
// `webrtc::TaskQueueBase`.
#ifndef VEIL_RUN_ON_H_
#define VEIL_RUN_ON_H_

#include <cassert>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <utility>

namespace veil_media {

// Run `f` on `tq` and block until it has either finished or been abandoned.
//
// **The contract is the whole point.** When this function returns, `f` will
// never run again. Every caller in the engine passes a `[&]` lambda that
// captures its own stack frame by reference; a task that runs after that
// frame is gone writes into freed memory. A plain `Post` + timed `Wait` --
// the shape this replaces -- gives no such guarantee: on timeout the frame
// unwinds while the task is still queued, and the queue then invokes a
// dangling lambda over dangling captures.
//
// Returns true if `f` ran to completion, false if it was abandoned before it
// started. False means the operation did NOT happen and no state was
// touched; it never means "maybe".
//
// A slow `f` is deliberately waited out past `timeout`: once `f` has started
// it holds references into the caller's frame, so returning would be exactly
// the bug this exists to prevent. The timeout bounds *scheduling* latency (a
// task queue that is wedged or already shut down), not `f` itself.
template <typename TaskQueue, typename F>
bool run_on_with_timeout(TaskQueue* tq, F&& f, std::chrono::milliseconds timeout) {
  if (tq == nullptr || tq->IsCurrent()) {
    f();
    return true;
  }

  struct Gate {
    std::mutex m;
    std::condition_variable cv;
    bool ran = false;
    bool abandoned = false;

    // Abandonment is sound only while the gate is held: the task takes this
    // same mutex before it consults the flag, and that -- not the flag
    // itself -- is what stops a task from slipping past the decision.
    //
    // The lock is taken by reference so the requirement is written into the
    // signature, and asserted so that an edit which releases it early fails
    // loudly. That window cannot be reached by any test which does not
    // instrument this function, so a guard here is what stands in for one.
    void abandon(std::unique_lock<std::mutex>& held) {
      assert(held.owns_lock() && held.mutex() == &m &&
             "abandonment must be decided under the gate");
      abandoned = true;
    }
  };
  auto gate = std::make_shared<Gate>();

  // `f` travels as a bare pointer on purpose -- copying it would copy a
  // closure whose captures are references into the caller's frame, which
  // buys nothing. What makes the pointer safe is the handshake below, not
  // the storage class.
  tq->PostTask([gate, fp = &f]() mutable {
    std::lock_guard<std::mutex> lock(gate->m);
    if (gate->abandoned) {
      // The caller gave up and has returned; its frame -- and everything
      // `*fp` captured by reference -- may already be gone. Touching `*fp`
      // here is the use-after-free.
      return;
    }
    (*fp)();
    gate->ran = true;
    gate->cv.notify_all();
  });

  std::unique_lock<std::mutex> lock(gate->m);
  if (gate->cv.wait_for(lock, timeout, [&] { return gate->ran; })) {
    return true;
  }

  // Timed out -- and we hold the gate. That is what makes the next line
  // race-free: a task that had already begun would be holding this same
  // mutex, so `wait_for` could not have re-acquired it and would have
  // observed `ran` on the recheck. Reaching here proves the task has not
  // started, and marking it abandoned means it never will.
  gate->abandon(lock);
  return false;
}

}  // namespace veil_media

#endif  // VEIL_RUN_ON_H_
