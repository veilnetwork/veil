//! Close is a protocol, and these exercise the real one.
//!
//! Moved verbatim out of `lib.rs`, which was fourteen thousand lines with four
//! thousand of them test code interleaved with the production surface
//! (report24 RUNTIME-3). Nothing here is compiled into the library — the
//! module keeps the same `cfg`, the same name and the same `use super::*`, so
//! every test still runs under the path it ran under before.
//!
//! The production code was deliberately NOT moved. cbindgen emits this crate's
//! header in parse order and skips `pub` items it finds in a private module,
//! so moving a section of `lib.rs` into a submodule rewrote the header and
//! DROPPED declarations from it — measured, then reverted. Tests are the part
//! that can move without the header noticing, and this checks that it did not.

//! Audit V-01: closing the native side must leave the host's callback
//! trampolines provably unreachable *before* it returns, because the host
//! deallocates them on the very next line.
//!
//! These exercise the REAL dispatch loops (`run_recv_dispatch_loop` /
//! `run_event_dispatch_loop`) and the REAL close protocol
//! (`retire_dispatch_callback` + join) that `veil_close` / `veil_app_close`
//! are now two-line wrappers around — not re-implementations of them.
//!
//! The proof asked for is positive: a frame in flight at close time is
//! *carried to completion*, and a frame behind it is *deterministically
//! dropped*. "Didn't crash" is not evidence — a use-after-free on a freed
//! trampoline is exactly the kind of bug that usually doesn't.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Stand-in for a host trampoline. Reached through the `user` pointer the
/// dispatch loops carry, so nothing here is global state shared between
/// tests.
struct CbProbe {
    /// Dispatches that entered the callback.
    entered: AtomicUsize,
    /// Dispatches that ran to completion (entered AND returned).
    completed: AtomicUsize,
    /// Callee-owned buffers reclaimed. Must equal `entered`, else the
    /// loop handed out a buffer nobody owns any more.
    freed: AtomicUsize,
    /// How long the callback occupies the dispatch section — the stretch
    /// from the slot read to the return which contains no `.await` and so
    /// cannot be interrupted by `abort()`.
    dwell: Duration,
}

impl CbProbe {
    fn new(dwell: Duration) -> Self {
        Self {
            entered: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            freed: AtomicUsize::new(0),
            dwell,
        }
    }
    fn spin(&self) {
        let t0 = Instant::now();
        while t0.elapsed() < self.dwell {
            std::hint::spin_loop();
        }
    }
}

unsafe extern "C" fn probe_recv_cb(
    user: *mut std::ffi::c_void,
    node_id: *const u8,
    _app_id: *const u8,
    _provenance: u8,
    _reply_id: u64,
    _data: *const u8,
    data_len: size_t,
) {
    let probe = unsafe { &*(user as *const CbProbe) };
    probe.entered.fetch_add(1, Ordering::SeqCst);
    probe.spin();
    // Callee owns the `[node_id(32)|app_id(32)|data]` buffer.
    unsafe { veil_free_buf(node_id as *mut u8, 64 + data_len) };
    probe.freed.fetch_add(1, Ordering::SeqCst);
    probe.completed.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn probe_event_cb(
    user: *mut std::ffi::c_void,
    _kind: u8,
    payload: *const u8,
    payload_len: size_t,
) {
    let probe = unsafe { &*(user as *const CbProbe) };
    probe.entered.fetch_add(1, Ordering::SeqCst);
    probe.spin();
    unsafe { veil_free_buf(payload as *mut u8, payload_len) };
    probe.freed.fetch_add(1, Ordering::SeqCst);
    probe.completed.fetch_add(1, Ordering::SeqCst);
}

fn frame(n: u8) -> IncomingMessage {
    IncomingMessage {
        src_node_id: [n; 32],
        provenance: veilclient::SenderProvenance::SessionPeer,
        src_app_id: [n; 32],
        data: vec![n; 8],
        reply_id: 0,
    }
}

/// CONTROL probe for the two "nothing was dispatched" tests below: with a
/// LIVE slot the very same harness DOES observe dispatches, so a green
/// result there is the retire arm working, not the harness being blind.
#[test]
fn v01_control_live_slot_dispatches_every_frame() {
    let rt = build_runtime().expect("runtime");
    let probe = Box::new(CbProbe::new(Duration::ZERO));
    let cb_cell = Arc::new(StdMutex::new(Some(RecvCbSlot {
        cb: probe_recv_cb,
        user_addr: (&*probe as *const CbProbe) as usize,
    })));
    let (tx, rx) = mpsc::channel::<IncomingMessage>(8);
    let task = rt.spawn(run_recv_dispatch_loop(rx, Arc::clone(&cb_cell)));
    rt.block_on(async move {
        for i in 0..4u8 {
            tx.send(frame(i)).await.expect("send");
        }
        drop(tx);
        let _ = task.await;
    });
    assert_eq!(probe.entered.load(Ordering::SeqCst), 4);
    assert_eq!(
        probe.freed.load(Ordering::SeqCst),
        4,
        "every callee-owned buffer must be reclaimed"
    );
}

/// Close must not RETURN while a host callback is still executing.
///
/// `abort()` alone cannot deliver that: the dispatch section has no
/// `.await`, so cancellation lands only at the next one — after the
/// callback already ran. Awaiting the aborted `JoinHandle` is the
/// observation that the task has actually stopped.
///
/// Frame 1 is deliberately mid-callback when the close runs; frame 2 is
/// queued behind it. Post-conditions: frame 1 completed (not abandoned
/// mid-flight), frame 2 dropped (not dispatched after close), and the
/// buffer ledger balances.
#[test]
fn v01_close_does_not_return_while_a_dispatch_is_in_flight() {
    // Long enough that "close returned early" is unmistakable, short
    // enough not to slow the suite.
    const DWELL: Duration = Duration::from_millis(400);

    let rt = build_runtime().expect("runtime");
    let probe = Box::new(CbProbe::new(DWELL));
    let cb_cell = Arc::new(StdMutex::new(Some(RecvCbSlot {
        cb: probe_recv_cb,
        user_addr: (&*probe as *const CbProbe) as usize,
    })));
    let (tx, rx) = mpsc::channel::<IncomingMessage>(8);
    let task_slot: StdMutex<Option<tokio::task::JoinHandle<()>>> = StdMutex::new(Some(
        rt.spawn(run_recv_dispatch_loop(rx, Arc::clone(&cb_cell))),
    ));

    rt.block_on(async {
        tx.send(frame(1)).await.expect("send 1");
        tx.send(frame(2)).await.expect("send 2");
    });

    // Park until the loop is INSIDE frame 1's dispatch — past the slot
    // read, inside the uninterruptible section.
    let t0 = Instant::now();
    while probe.entered.load(Ordering::SeqCst) == 0 {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "recv loop never entered a dispatch — harness broken"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        probe.completed.load(Ordering::SeqCst),
        0,
        "the dispatch already finished before close ran — dwell too short \
         to observe the window this test exists for"
    );

    // ── The production close protocol — the exact two calls that
    // `veil_close` / `veil_app_close` are now built out of. ──
    let task = retire_dispatch_callback(&cb_cell, &task_slot);
    assert!(
        cb_cell.lock().unwrap().is_none(),
        "step 1 must retire the callback slot"
    );
    let synchronous = await_retired_task(&rt, task, std::future::ready(()));
    assert!(
        synchronous,
        "a caller outside any runtime must join synchronously, not defer"
    );

    assert_eq!(
        probe.completed.load(Ordering::SeqCst),
        1,
        "close returned while a host callback was still running: the host \
         frees the trampoline on the next line, so this is a jump into \
         freed executable memory"
    );
    assert_eq!(
        probe.entered.load(Ordering::SeqCst),
        1,
        "the frame queued behind the in-flight one must be dropped, not \
         dispatched"
    );
    assert_eq!(
        probe.freed.load(Ordering::SeqCst),
        probe.entered.load(Ordering::SeqCst),
        "a buffer was handed out as callee-owned but never reclaimed"
    );

    // Give the runtime real time to misbehave after close returned.
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        probe.entered.load(Ordering::SeqCst),
        1,
        "a dispatch started AFTER close returned"
    );
    drop(tx);
}

/// Step 1 in isolation: once the slot is retired the recv loop drops every
/// frame it dequeues without entering the trampoline — and therefore
/// without allocating the callee-owned buffer that a retired trampoline
/// would never free.
///
/// Deliberately run with NO task registered, so `abort()` contributes
/// nothing and the retire is the only thing under test. That is also the
/// exact shape of the deferred (reentrant-caller) close path, where the
/// join is skipped and the retire is all the protection there is.
#[test]
fn v01_retired_slot_drops_frames_without_entering_the_trampoline() {
    let rt = build_runtime().expect("runtime");
    let probe = Box::new(CbProbe::new(Duration::ZERO));
    let cb_cell = Arc::new(StdMutex::new(Some(RecvCbSlot {
        cb: probe_recv_cb,
        user_addr: (&*probe as *const CbProbe) as usize,
    })));
    let (tx, rx) = mpsc::channel::<IncomingMessage>(8);
    let task = rt.spawn(run_recv_dispatch_loop(rx, Arc::clone(&cb_cell)));

    let no_task: StdMutex<Option<tokio::task::JoinHandle<()>>> = StdMutex::new(None);
    assert!(retire_dispatch_callback(&cb_cell, &no_task).is_none());

    rt.block_on(async move {
        for i in 0..4u8 {
            tx.send(frame(i)).await.expect("send");
        }
        // Closing the channel makes the loop drain then exit, so the join
        // below proves every frame was CONSUMED, not merely still queued.
        drop(tx);
        let _ = task.await;
    });

    assert_eq!(
        probe.entered.load(Ordering::SeqCst),
        0,
        "a frame reached the trampoline after the slot was retired"
    );
    assert_eq!(probe.freed.load(Ordering::SeqCst), 0);
}

/// Same property on the EVENT loop — `veil_close`'s side of the finding.
/// Without its own coverage the event loop's `continue` arm could be
/// deleted with the recv-side tests still green.
#[test]
fn v01_retired_slot_drops_events_without_entering_the_trampoline() {
    let rt = build_runtime().expect("runtime");
    let probe = Box::new(CbProbe::new(Duration::ZERO));
    let cb_cell = Arc::new(StdMutex::new(Some(EventCbSlot {
        cb: probe_event_cb,
        user_addr: (&*probe as *const CbProbe) as usize,
    })));
    let (tx, rx) = mpsc::channel::<veilclient::VeilEvent>(8);
    let task = rt.spawn(run_event_dispatch_loop(rx, Arc::clone(&cb_cell)));

    // Control first: a live slot DOES dispatch through this harness.
    rt.block_on(async {
        tx.send(veilclient::VeilEvent {
            kind: 1,
            payload: vec![7u8; 16],
        })
        .await
        .expect("send");
    });
    let t0 = Instant::now();
    while probe.entered.load(Ordering::SeqCst) == 0 {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "event loop never dispatched — harness broken"
        );
        std::thread::sleep(Duration::from_millis(1));
    }

    let no_task: StdMutex<Option<tokio::task::JoinHandle<()>>> = StdMutex::new(None);
    retire_dispatch_callback(&cb_cell, &no_task);

    rt.block_on(async move {
        for _ in 0..4 {
            tx.send(veilclient::VeilEvent {
                kind: 2,
                payload: vec![9u8; 16],
            })
            .await
            .expect("send");
        }
        drop(tx);
        let _ = task.await;
    });

    assert_eq!(
        probe.entered.load(Ordering::SeqCst),
        1,
        "an event reached the trampoline after the slot was retired"
    );
    assert_eq!(
        probe.freed.load(Ordering::SeqCst),
        1,
        "buffer ledger must balance across the retire boundary"
    );
}

/// Audit V-02 / `guard.rs` re-evaluation criterion 4: the close path grew a
/// `block_on`, so a caller that is ALREADY inside the runtime must be
/// detected and deferred. Waiting there would park a worker on a task that
/// same worker is meant to drive — a hang with no diagnostic, in a
/// destructor that has no `err_out` to report one through.
///
/// This asserts the DECISION at the call site (`await_retired_task`
/// returns `false` = deferred), not merely that `in_tokio_runtime()`
/// answers correctly, and that the call still returns promptly rather than
/// wedging the test.
#[test]
fn v01_reentrant_caller_defers_instead_of_deadlocking() {
    let rt = build_runtime().expect("runtime");
    let probe = Box::new(CbProbe::new(Duration::ZERO));
    let cb_cell = Arc::new(StdMutex::new(Some(RecvCbSlot {
        cb: probe_recv_cb,
        user_addr: (&*probe as *const CbProbe) as usize,
    })));
    let (tx, rx) = mpsc::channel::<IncomingMessage>(8);
    let task_slot: StdMutex<Option<tokio::task::JoinHandle<()>>> = StdMutex::new(Some(
        rt.spawn(run_recv_dispatch_loop(rx, Arc::clone(&cb_cell))),
    ));

    // Control: outside a runtime the same inputs join synchronously — so
    // the `false` below is the reentrancy branch, not a broken harness.
    assert!(!in_tokio_runtime());

    let done = std::sync::Arc::new(AtomicUsize::new(0));
    let done_probe = std::sync::Arc::clone(&done);
    // `block_on` puts this thread inside the runtime, which is exactly the
    // situation a recv-callback re-entering the FFI would create.
    rt.block_on(async {
        assert!(in_tokio_runtime());
        let task = retire_dispatch_callback(&cb_cell, &task_slot);
        let synchronous = await_retired_task(&rt, task, async move {
            done_probe.fetch_add(1, Ordering::SeqCst);
        });
        assert!(
            !synchronous,
            "a reentrant caller must DEFER the join; joining here parks the \
             worker on a task it is itself responsible for driving"
        );
    });

    // The deferred work still runs — deferral is a degradation, not a drop.
    let t0 = Instant::now();
    while done.load(Ordering::SeqCst) == 0 {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "deferred close tail never ran"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // Step 1 still applied synchronously on the deferred path — that is
    // the whole reason it comes first.
    assert_eq!(
        probe.entered.load(Ordering::SeqCst),
        0,
        "the retire must take effect synchronously even when the join is \
         deferred"
    );
    drop(tx);
}
