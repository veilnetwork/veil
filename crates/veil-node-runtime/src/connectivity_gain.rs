//! Connectivity-gain hook (P2P Stage B mobility slice).
//!
//! An OUTBOUND session completing its handshake is the runtime's own
//! evidence that egress connectivity works — on a mobile network flip
//! (Wi-Fi ↔ LTE) it is the first veil-internal signal that the NEW
//! path is usable. This hook fans that signal out to the two consumers
//! that otherwise ride long periodic timers:
//!
//! 1. **srflx probe task** — re-observes our server-reflexive address
//!    immediately (instead of the 300 s periodic tick), so
//!    `listen_transports` / `own_external_addrs` carry the NEW external
//!    IP by the time the app's next direct-endpoint exchange mints URIs.
//! 2. **outbound-connector loops** — `force_reconnect_notify` wakes
//!    every loop parked in a backoff / pre-check sleep so peers that
//!    were unreachable on the OLD network get re-dialed promptly (the
//!    woken loop also resets its exponential backoff — the failure
//!    streak belonged to the old path).
//!
//! Inbound sessions deliberately do NOT fire the hook: on a busy
//! relay/seed node inbound opens are constant background noise, and
//! "someone reached us" is not evidence that OUR egress changed.
//!
//! Debounce: the reconnect fan-out fires at most once per
//! [`GAIN_DEBOUNCE`] — the burst of session-opens right after a network
//! flip collapses into one wake. The srflx wake needs no debounce here;
//! the probe task enforces its own minimum probe gap.

use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use veil_util::lock;

/// Minimum spacing between reconnect fan-outs. Long enough that a seed
/// with steady outbound churn does not defeat exponential backoff for
/// genuinely-dead peers; short enough that a mobile network flip
/// (reconnection burst lasts a few seconds) is served by the first fire.
pub const GAIN_DEBOUNCE: Duration = Duration::from_secs(15);

/// Shared connectivity-gain state. One per runtime; `Arc`-cloned into
/// `NodeServices` (outbound connector) and the srflx probe task.
pub struct ConnectivityGain {
    /// Single-consumer wake for the srflx probe task. `notify_one` so a
    /// fire while the task is mid-probe leaves a stored permit — the
    /// wake is consumed on the task's next `notified().await` instead
    /// of being lost.
    srflx_probe_wake: tokio::sync::Notify,
    /// The runtime-wide outbound-connector wake handle (same object the
    /// mobile `NetworkChanged` IPC event fires).
    force_reconnect_notify: std::sync::Arc<tokio::sync::Notify>,
    last_reconnect_fanout: Mutex<Option<Instant>>,
}

impl ConnectivityGain {
    pub fn new(force_reconnect_notify: std::sync::Arc<tokio::sync::Notify>) -> Self {
        Self {
            srflx_probe_wake: tokio::sync::Notify::new(),
            force_reconnect_notify,
            last_reconnect_fanout: Mutex::new(None),
        }
    }

    /// Called by the outbound connector right after a session finishes
    /// registration. Cheap: one mutex-guarded Instant compare + up to
    /// two `Notify` fires.
    pub fn on_outbound_session_established(&self) {
        // Fresh egress evidence — let the srflx task re-observe our
        // external address right away (it applies its own min-gap).
        self.srflx_probe_wake.notify_one();
        let now = Instant::now();
        let fire = {
            let mut last = lock!(self.last_reconnect_fanout);
            if should_fire_reconnect_fanout(*last, now, GAIN_DEBOUNCE) {
                *last = Some(now);
                true
            } else {
                false
            }
        };
        if fire {
            self.force_reconnect_notify.notify_waiters();
        }
    }

    /// Await the next srflx wake (single consumer: the probe task).
    pub async fn srflx_wake(&self) {
        self.srflx_probe_wake.notified().await;
    }
}

/// Pure debounce decision: fire when never fired before OR the debounce
/// window has fully elapsed.
fn should_fire_reconnect_fanout(last: Option<Instant>, now: Instant, debounce: Duration) -> bool {
    match last {
        None => true,
        Some(t) => now.duration_since(t) >= debounce,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn debounce_first_fire_always_passes() {
        let now = Instant::now();
        assert!(should_fire_reconnect_fanout(None, now, GAIN_DEBOUNCE));
    }

    #[tokio::test]
    async fn debounce_suppresses_inside_window_and_reopens_after() {
        let t0 = Instant::now();
        assert!(!should_fire_reconnect_fanout(
            Some(t0),
            t0 + GAIN_DEBOUNCE - Duration::from_millis(1),
            GAIN_DEBOUNCE
        ));
        assert!(should_fire_reconnect_fanout(
            Some(t0),
            t0 + GAIN_DEBOUNCE,
            GAIN_DEBOUNCE
        ));
    }

    #[tokio::test]
    async fn gain_hook_fires_reconnect_once_per_window() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let gain = ConnectivityGain::new(Arc::clone(&notify));

        // Arm a waiter BEFORE firing (notify_waiters stores no permit).
        let waiter = {
            let notify = Arc::clone(&notify);
            tokio::spawn(async move { notify.notified().await })
        };
        tokio::task::yield_now().await;

        gain.on_outbound_session_established();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("first gain must wake reconnect waiters")
            .unwrap();

        // Second fire inside the window: reconnect fan-out suppressed.
        let waiter2 = {
            let notify = Arc::clone(&notify);
            tokio::spawn(async move { notify.notified().await })
        };
        tokio::task::yield_now().await;
        gain.on_outbound_session_established();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), waiter2)
                .await
                .is_err(),
            "debounced second fire must NOT wake reconnect waiters"
        );
    }

    #[tokio::test]
    async fn gain_hook_srflx_wake_has_permit_semantics() {
        let gain = ConnectivityGain::new(Arc::new(tokio::sync::Notify::new()));
        // Fire BEFORE anyone awaits — notify_one must store the permit.
        gain.on_outbound_session_established();
        tokio::time::timeout(Duration::from_secs(1), gain.srflx_wake())
            .await
            .expect("stored srflx permit must complete a later await");
    }
}
