//! Making a foreign callback safe to unregister.
//!
//! Every callback here is a raw function pointer plus a `ctx` the host owns.
//! Two requirements pull against each other:
//!
//! * The registry mutex must NOT be held across the call. A callback that logs,
//!   or that installs another callback, would take the lock its own caller is
//!   holding, and nothing unwinds that (report14 V14-L5).
//! * But releasing it opens a window: between copying the callback out and
//!   calling it, the host may unregister and free `ctx`. The call then lands on
//!   freed memory — a use-after-free this side hands to the host, on a
//!   contract that never said when `ctx` stops being used (report20 V18-M10).
//!
//! The way through is to stop treating "unregister" as an assignment. It is a
//! HANDOVER: the setter publishes the new callback and then waits until no
//! thread is inside the old one, so by the time it returns the host may free
//! what it passed. That is the guarantee `ctx` needs and never had.
//!
//! Re-entrancy survives it. A callback that installs another is itself
//! in-flight, so a naive "wait for zero" would wait for itself; the wait skips
//! the calling thread, which is exactly the case the deadlock fix exists for.

use std::sync::atomic::{AtomicUsize, Ordering};

thread_local! {
    /// Whether THIS thread is currently inside a foreign callback.
    ///
    /// A callback that reaches back in to register another must not wait for
    /// itself to finish.
    static INSIDE_CALLBACK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many threads are inside a callback taken from one registry.
pub(crate) struct InFlight(AtomicUsize);

impl InFlight {
    pub(crate) const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    /// Mark a call in progress. The guard's drop marks it finished.
    pub(crate) fn enter(&'static self) -> InFlightGuard {
        self.0.fetch_add(1, Ordering::AcqRel);
        INSIDE_CALLBACK.with(|c| c.set(c.get() + 1));
        InFlightGuard(self)
    }

    /// Wait until no OTHER thread is inside a callback from this registry.
    ///
    /// Called after the new callback is published, so what it waits for is the
    /// tail of the old one. Yields rather than spins hard: a callback is
    /// foreign code of unknown length and this thread has nothing to do until
    /// it returns.
    pub(crate) fn wait_for_quiet(&self) {
        let mine = INSIDE_CALLBACK.with(std::cell::Cell::get);
        while self.0.load(Ordering::Acquire) > mine {
            std::thread::yield_now();
        }
    }
}

pub(crate) struct InFlightGuard(&'static InFlight);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        INSIDE_CALLBACK.with(|c| c.set(c.get() - 1));
        self.0.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ONE STATIC PER TEST. The counter is process-global while the recursion
    // marker is thread-local, so two tests sharing a registry would see each
    // other's calls and the assertions below would depend on the harness's
    // thread scheduling.
    static QUIET: InFlight = InFlight::new();
    static REENTRANT: InFlight = InFlight::new();
    static COUNTED: InFlight = InFlight::new();

    /// A registry with nobody inside it is quiet immediately.
    #[test]
    fn nothing_in_flight_is_already_quiet() {
        QUIET.wait_for_quiet();
    }

    /// And a thread inside a callback does not wait for ITSELF.
    ///
    /// This is the re-entrant case the deadlock fix exists for: a callback that
    /// installs another callback reaches the setter while it is still counted
    /// as in flight. Waiting for zero there is the deadlock, arriving by a
    /// different door.
    #[test]
    fn a_thread_inside_a_callback_does_not_wait_for_itself() {
        let guard = REENTRANT.enter();
        // Would hang if the wait counted this thread's own call.
        REENTRANT.wait_for_quiet();
        drop(guard);
        REENTRANT.wait_for_quiet();
    }

    /// The count really does track entry and exit, or the wait above is about
    /// nothing.
    #[test]
    fn the_count_rises_and_falls() {
        assert_eq!(COUNTED.0.load(Ordering::Acquire), 0);
        let a = COUNTED.enter();
        assert_eq!(COUNTED.0.load(Ordering::Acquire), 1);
        let b = COUNTED.enter();
        assert_eq!(COUNTED.0.load(Ordering::Acquire), 2);
        drop(b);
        drop(a);
        assert_eq!(COUNTED.0.load(Ordering::Acquire), 0);
    }
}
