//! Genuine receive liveness shared by a session's authenticated opaque channels.
//! The parent stream may be idle while independently running DATAGRAM receivers
//! carry application data. Keep the actual receive instant, not the time the
//! parent eventually observes it: an old sample must never renew a dead peer.

use crate::timers::SessionTimers;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::Instant;

pub(crate) struct AuthenticatedDatagramActivity {
    base: Instant,
    latest_data: AtomicU64,
    latest_direct: AtomicU64,
}

impl AuthenticatedDatagramActivity {
    pub(crate) fn new() -> Self {
        Self {
            base: Instant::now(),
            latest_data: AtomicU64::new(0),
            latest_direct: AtomicU64::new(0),
        }
    }

    // Called only after authenticated reassembly and exact frame eligibility.
    pub(crate) fn note(&self, at: Instant, direct: bool) {
        let tick = at
            .saturating_duration_since(self.base)
            .as_nanos()
            .min(u128::from(u64::MAX - 1)) as u64
            + 1;
        self.latest_data.fetch_max(tick, Ordering::Relaxed);
        if direct {
            self.latest_direct.fetch_max(tick, Ordering::Relaxed);
        }
    }

    pub(crate) fn apply(&self, timers: &mut SessionTimers) {
        let tick = self.latest_data.load(Ordering::Relaxed);
        if tick != 0 {
            timers.note_frame_received(self.base + std::time::Duration::from_nanos(tick - 1));
        }
        let direct = self.latest_direct.load(Ordering::Relaxed);
        if direct != 0 {
            timers.note_realtime_activity(self.base + std::time::Duration::from_nanos(direct - 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn child_data_protects_parent_but_old_sample_cannot_renew_dead_peer() {
        let activity = AuthenticatedDatagramActivity::new();
        let mut timers = SessionTimers::new(Duration::from_secs(30), Duration::from_secs(90));
        let received = activity.base + Duration::from_secs(10);
        activity.note(received, true);
        activity.apply(&mut timers);
        assert_eq!(timers.genuine_rx_age(received), Duration::ZERO);
        assert!(timers.realtime_active(received));
        // The main task resumes much later. Reading the same sample must not
        // credit the observation time as new traffic.
        activity.apply(&mut timers);
        let later = received + Duration::from_secs(100);
        assert_eq!(timers.genuine_rx_age(later), Duration::from_secs(100));
        assert!(timers.idle_timeout_elapsed(later));
        assert!(!timers.realtime_active(later));
    }

    #[tokio::test]
    async fn a_delayed_child_sample_does_not_regress_newer_ordered_receive() {
        let activity = AuthenticatedDatagramActivity::new();
        let mut timers = SessionTimers::new(Duration::from_secs(30), Duration::from_secs(90));
        let old = activity.base + Duration::from_secs(5);
        let fresh = old + Duration::from_secs(5);
        timers.note_frame_received(fresh);
        activity.note(old, true);
        activity.apply(&mut timers);
        assert_eq!(timers.genuine_rx_age(fresh), Duration::ZERO);
        assert_eq!(timers.last_rx(), fresh);
    }

    #[tokio::test]
    async fn relay_or_circuit_data_does_not_enable_direct_acceleration() {
        let activity = AuthenticatedDatagramActivity::new();
        let mut timers = SessionTimers::new(Duration::from_secs(30), Duration::from_secs(90));
        activity.apply(&mut timers);
        let received = activity.base + Duration::from_secs(10);
        activity.note(received, false);
        activity.apply(&mut timers);
        assert_eq!(timers.genuine_rx_age(received), Duration::ZERO);
        assert!(!timers.realtime_active(received));
    }
}
