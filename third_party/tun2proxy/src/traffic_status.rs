use crate::error::{Error, Result};
use std::os::raw::c_void;
use std::sync::{LazyLock, Mutex};

/// # Safety
///
/// set traffic status callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tun2proxy_set_traffic_status_callback(
    send_interval_secs: u32,
    callback: Option<unsafe extern "C" fn(*const TrafficStatus, *mut c_void)>,
    ctx: *mut c_void,
) {
    if let Ok(mut cb) = TRAFFIC_STATUS_CALLBACK.lock() {
        *cb = Some(TrafficStatusCallback(callback, ctx));
    } else {
        log::error!("set traffic status callback failed");
    }
    // AND THEN WAIT for the previous one to finish — see the same wait in
    // `tun2proxy_set_log_callback`. `send_traffic_stat` calls with the registry
    // lock released, which it must, and that leaves a window where the host can
    // unregister and free a `ctx` a thread is about to hand back to it
    // (report20 V18-M10).
    IN_FLIGHT.wait_for_quiet();
    if send_interval_secs > 0 {
        SEND_INTERVAL_SECS.store(send_interval_secs as u64, std::sync::atomic::Ordering::Relaxed);
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct TrafficStatus {
    pub tx: u64,
    pub rx: u64,
}

#[derive(Clone)]
struct TrafficStatusCallback(Option<unsafe extern "C" fn(*const TrafficStatus, *mut c_void)>, *mut c_void);

impl TrafficStatusCallback {
    unsafe fn call(self, info: &TrafficStatus) {
        if let Some(cb) = self.0 {
            unsafe { cb(info, self.1) };
        }
    }
}

unsafe impl Send for TrafficStatusCallback {}
unsafe impl Sync for TrafficStatusCallback {}

static TRAFFIC_STATUS_CALLBACK: std::sync::Mutex<Option<TrafficStatusCallback>> = std::sync::Mutex::new(None);
static SEND_INTERVAL_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Threads currently inside the traffic callback. See [`crate::ffi_callback`].
static IN_FLIGHT: crate::ffi_callback::InFlight = crate::ffi_callback::InFlight::new();

/// The running totals AND when they were last reported, under one lock.
///
/// They used to be two: `TRAFFIC_STATUS` and `TIME_STAMP`, taken one after the
/// other. Two threads updating at once could therefore each copy their own
/// totals, then each read the timestamp and each decide to report — and the
/// one that copied the SMALLER total could reach the callback second. The
/// consumer saw a counter that went backwards, and anything computing a delta
/// from it got a negative one. The same check-then-act also let both of them
/// report inside a single interval (report21 V18-L2).
struct TrafficState {
    totals: TrafficStatus,
    last_sent: std::time::Instant,
}

static TRAFFIC_STATE: LazyLock<Mutex<TrafficState>> = LazyLock::new(|| {
    Mutex::new(TrafficState {
        totals: TrafficStatus::default(),
        last_sent: std::time::Instant::now(),
    })
});

/// Add a delta and, if the interval has passed, CLAIM the report slot.
///
/// One critical section decides everything: the totals to report are read at
/// the moment the slot is claimed, and claiming moves the timestamp, so a
/// second thread arriving behind this one adds to the totals and is told to
/// stay quiet. `None` means somebody else has the interval.
fn claim_report(
    state: &mut TrafficState,
    delta_tx: usize,
    delta_rx: usize,
    now: std::time::Instant,
    interval_secs: u64,
) -> Option<TrafficStatus> {
    state.totals.tx += delta_tx as u64;
    state.totals.rx += delta_rx as u64;
    if now.duration_since(state.last_sent).as_secs() >= interval_secs {
        state.last_sent = now;
        Some(state.totals)
    } else {
        None
    }
}

pub(crate) fn traffic_status_update(delta_tx: usize, delta_rx: usize) -> Result<()> {
    {
        let is_none_or_error = TRAFFIC_STATUS_CALLBACK.lock().map(|guard| guard.is_none()).unwrap_or_else(|e| {
            log::error!("Failed to acquire lock: {e}");
            true
        });
        if is_none_or_error {
            return Ok(());
        }
    }
    let interval_secs = SEND_INTERVAL_SECS.load(std::sync::atomic::Ordering::Relaxed);
    let due = {
        let mut state = TRAFFIC_STATE.lock().map_err(|e| Error::from(e.to_string()))?;
        claim_report(&mut state, delta_tx, delta_rx, std::time::Instant::now(), interval_secs)
    };
    // The lock is released before the callback runs, which is the other half of
    // this function's history: foreign code may reach back in here, and holding
    // anything across it is a deadlock (report14 V14-L5).
    //
    // What that leaves is a residual this does not claim to fix: two claims an
    // interval apart could still, in principle, reach the callback out of
    // order if the scheduler parks the first between claiming and calling.
    // Closing that means serialising the calls themselves, which is the thing
    // V14-L5 forbids.
    if let Some(status) = due {
        send_traffic_stat(&status)?;
    }
    Ok(())
}

fn send_traffic_stat(traffic_status: &TrafficStatus) -> Result<()> {
    // Copied out and the lock RELEASED before the call.
    //
    // The callback is foreign code, and foreign code may do anything —
    // including install a new callback, which takes this very mutex. Calling
    // while the guard is alive makes that a deadlock: the callback waits for a
    // lock its own caller is holding, and nothing unwinds it (report14
    // V14-L5). Nothing about a registry needs to stay locked while the thing
    // it registered runs.
    let cb = TRAFFIC_STATUS_CALLBACK.lock().ok().and_then(|g| g.clone());
    if let Some(cb) = cb {
        // Counted for the whole call, so an unregister that starts now waits
        // for this to return before it lets the host free `ctx`.
        let _in_flight = IN_FLIGHT.enter();
        unsafe { cb.call(traffic_status) };
    }
    Ok(())
}

#[cfg(test)]
mod claim_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn state(at: Instant) -> TrafficState {
        TrafficState {
            totals: TrafficStatus::default(),
            last_sent: at,
        }
    }

    /// report21 V18-L2: what gets reported never goes backwards, and one
    /// interval yields one report.
    ///
    /// The totals and the timestamp were separate mutexes taken one after the
    /// other. Two threads updating at once each copied their own totals, then
    /// each read the timestamp and each decided to report — so the one holding
    /// the SMALLER total could reach the callback second, and a consumer saw a
    /// monotonic counter go down. The same check-then-act let both report
    /// inside one interval.
    #[test]
    fn a_reported_total_never_goes_backwards() {
        let t0 = Instant::now();
        let mut st = state(t0);

        // First update, an interval later: it claims, and reports what the
        // totals are AT THE CLAIM.
        let first = claim_report(&mut st, 100, 10, t0 + Duration::from_secs(1), 1);
        assert_eq!(first.map(|s| (s.tx, s.rx)), Some((100, 10)));

        // A second update in the SAME interval adds to the totals and is told
        // to stay quiet: the interval belongs to the claim above.
        let second = claim_report(&mut st, 50, 5, t0 + Duration::from_secs(1), 1);
        assert!(
            second.is_none(),
            "two reports landed in one interval, which is how the older total \
             could arrive after the newer one"
        );

        // The next interval reports the accumulated total, which includes the
        // delta the quiet update contributed. Never smaller than the last.
        let third = claim_report(&mut st, 1, 1, t0 + Duration::from_secs(2), 1);
        let third = third.expect("the next interval reports");
        assert_eq!((third.tx, third.rx), (151, 16));
        let firsts = first.expect("claimed");
        assert!(third.tx >= firsts.tx && third.rx >= firsts.rx);
    }

    /// The interleaving that used to produce the regression, driven directly:
    /// two updates whose claims are decided one after the other must not both
    /// be granted, and the granted one must carry the larger total.
    #[test]
    fn the_thread_that_claims_carries_the_larger_total() {
        let t0 = Instant::now();
        let mut st = state(t0);
        let due = t0 + Duration::from_secs(1);

        // "Thread A" adds first, "thread B" adds second; whichever reaches the
        // lock first claims, and it holds the total including its own delta.
        let a = claim_report(&mut st, 10, 1, due, 1);
        let b = claim_report(&mut st, 90, 9, due, 1);

        assert!(a.is_some() ^ b.is_some(), "exactly one of them may report");
        let reported = a.or(b).expect("one claim");
        assert_eq!(
            (reported.tx, reported.rx),
            (10, 1),
            "the claim carries the totals as of the moment it was granted"
        );
        // And the delta that lost the race is not lost: it is in the totals
        // the next claim reports.
        let next = claim_report(&mut st, 0, 0, t0 + Duration::from_secs(2), 1).expect("the next interval reports");
        assert_eq!((next.tx, next.rx), (100, 10), "a delta was dropped");
    }

    /// Vacuity: with the interval not yet elapsed, nothing is claimed at all —
    /// otherwise every assertion above would pass on a function that always
    /// reports.
    #[test]
    fn nothing_is_claimed_before_the_interval() {
        let t0 = Instant::now();
        let mut st = state(t0);
        assert!(claim_report(&mut st, 7, 7, t0 + Duration::from_millis(999), 1).is_none());
        assert_eq!((st.totals.tx, st.totals.rx), (7, 7), "the delta still landed");
    }
}

#[cfg(test)]
mod reentrancy_tests {
    use super::*;

    /// A callback that installs another callback must not deadlock.
    ///
    /// The registry mutex was held ACROSS the call, so foreign code that
    /// reached back into `tun2proxy_set_traffic_status_callback` waited for a
    /// lock its own caller was holding. Nothing unwinds that (report14
    /// V14-L5).
    ///
    /// Reverting the fix does not make this red — it makes it HANG, which is
    /// what a deadlock is. A test harness cannot time out a thread parked in
    /// `Mutex::lock`.
    static REENTERED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    unsafe extern "C" fn reinstalling_cb(_status: *const TrafficStatus, _ctx: *mut c_void) {
        REENTERED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // The whole point: from inside the callback, register another one.
        unsafe {
            tun2proxy_set_traffic_status_callback(0, Some(quiet_cb), std::ptr::null_mut());
        }
    }

    unsafe extern "C" fn quiet_cb(_status: *const TrafficStatus, _ctx: *mut c_void) {}

    /// report20 V18-M10: unregistering WAITS for the call in flight.
    ///
    /// The call runs with the registry lock released — it has to, or a
    /// callback that registers another takes the lock its own caller holds —
    /// and that left a window where the host could unregister and free the
    /// `ctx` a thread was about to pass back to it. The setter returning is
    /// what tells the host its ctx is free to release, and it used to return
    /// while a call was still holding one.
    static SLOW_CB_ENTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static SLOW_CB_LEFT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static RELEASE_SLOW_CB: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    unsafe extern "C" fn slow_cb(_status: *const TrafficStatus, _ctx: *mut c_void) {
        SLOW_CB_ENTERED.store(true, std::sync::atomic::Ordering::SeqCst);
        while !RELEASE_SLOW_CB.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::yield_now();
        }
        SLOW_CB_LEFT.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn unregistering_waits_for_the_call_already_running() {
        unsafe {
            tun2proxy_set_traffic_status_callback(0, Some(slow_cb), std::ptr::null_mut());
        }

        // A reporting thread enters the callback and parks inside it.
        let reporter = std::thread::spawn(|| {
            send_traffic_stat(&TrafficStatus { tx: 1, rx: 2 }).expect("send");
        });
        while !SLOW_CB_ENTERED.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::yield_now();
        }
        assert!(
            !SLOW_CB_LEFT.load(std::sync::atomic::Ordering::SeqCst),
            "premise: the callback is still inside"
        );

        // The host unregisters from ANOTHER thread and would free its ctx the
        // moment this returns.
        let unregister = std::thread::spawn(|| unsafe {
            tun2proxy_set_traffic_status_callback(0, None, std::ptr::null_mut());
        });

        // Let the parked callback finish, then the unregister may return.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            !unregister.is_finished(),
            "the unregister returned while a thread was still inside the old \
             callback: the host frees its ctx there, and the call lands on \
             freed memory"
        );
        RELEASE_SLOW_CB.store(true, std::sync::atomic::Ordering::SeqCst);
        unregister.join().expect("unregister");
        reporter.join().expect("reporter");
        assert!(SLOW_CB_LEFT.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn a_callback_that_registers_another_does_not_deadlock() {
        unsafe {
            tun2proxy_set_traffic_status_callback(0, Some(reinstalling_cb), std::ptr::null_mut());
        }
        send_traffic_stat(&TrafficStatus { tx: 1, rx: 2 }).expect("send");
        assert_eq!(
            REENTERED.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the callback must have run — and returned"
        );

        // The re-registration took effect, which is what proves the lock was
        // actually free while the callback held the floor.
        let now = TRAFFIC_STATUS_CALLBACK.lock().unwrap().clone();
        assert!(now.is_some());

        unsafe {
            tun2proxy_set_traffic_status_callback(0, None, std::ptr::null_mut());
        }
    }
}
