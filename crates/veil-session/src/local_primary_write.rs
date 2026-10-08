//! Connection-local primary bytes waiting in the scheduler or writer.
//! Only trusted local source metadata acquires leases; nothing is serialized.
use crate::local_source_activity::LocalSourceActivity;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};
use veil_util::lock;

pub(super) struct PrimaryWriteState {
    source: Arc<LocalSourceActivity>,
    pending: AtomicUsize,
    observations: AtomicU64,
    queued_until: Mutex<Option<Instant>>,
}

impl PrimaryWriteState {
    pub(super) fn new(source: Arc<LocalSourceActivity>) -> Arc<Self> {
        Arc::new(Self {
            source,
            pending: AtomicUsize::new(0),
            observations: AtomicU64::new(0),
            queued_until: Mutex::new(None),
        })
    }

    pub(super) fn retain(self: &Arc<Self>) -> PrimaryWriteLease {
        self.pending.fetch_add(1, Ordering::AcqRel);
        PrimaryWriteLease(Arc::clone(self))
    }

    /// A scheduler wait expires with the frame's existing freshness bound,
    /// even if that runner receives no event with which to clear it.
    pub(super) fn note_queued(&self, until: Option<Instant>) {
        *lock!(self.queued_until) = until;
    }

    pub(super) fn observations(&self) -> u64 {
        self.observations.load(Ordering::Relaxed)
    }

    pub(super) fn observe_stalled(&self, now: Instant) {
        if self.pending.load(Ordering::Acquire) > 0
            || lock!(self.queued_until).is_some_and(|until| now < until)
        {
            self.source.note_pressure(now);
            self.observations.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub(super) struct PrimaryWriteLease(Arc<PrimaryWriteState>);
impl Drop for PrimaryWriteLease {
    fn drop(&mut self) {
        let old = self.0.pending.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(old > 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_source_activity::NETWORK_CONTROL_BYTES;

    fn assert_no_pressure(source: &LocalSourceActivity, now: Instant) {
        // Reliable data has a budget even during healthy primary activity.
        // Pressure additionally restrains lossy probes and recovery RPCs.
        assert!(source.allow_secondary(now));
        assert!(source.allow_secondary(now));
        assert!(
            source
                .admit_network_control(NETWORK_CONTROL_BYTES, now)
                .is_ok()
        );
        assert!(
            source
                .admit_network_control(NETWORK_CONTROL_BYTES, now)
                .is_ok()
        );
    }

    #[test]
    fn discarded_primary_lease_cannot_pressure_another_live_neighbor() {
        let activity = Arc::new(LocalSourceActivity::default());
        let state = PrimaryWriteState::new(Arc::clone(&activity));
        let lease = state.retain();
        drop(lease);
        let now = Instant::now();
        activity.note(now);
        state.observe_stalled(now);
        assert_no_pressure(&activity, now);
    }

    #[test]
    fn expired_scheduler_mark_cannot_pressure_another_live_neighbor() {
        let activity = Arc::new(LocalSourceActivity::default());
        let state = PrimaryWriteState::new(Arc::clone(&activity));
        let now = Instant::now();
        state.note_queued(Some(now));
        activity.note(now);
        state.observe_stalled(now);
        assert_no_pressure(&activity, now);
    }

    #[test]
    fn retired_connection_does_not_share_pending_state_with_its_replacement() {
        let activity = Arc::new(LocalSourceActivity::default());
        let retired = PrimaryWriteState::new(Arc::clone(&activity));
        let replacement = PrimaryWriteState::new(Arc::clone(&activity));
        let _old_lease = retired.retain();
        let now = Instant::now();
        activity.note(now);
        replacement.observe_stalled(now);
        assert_no_pressure(&activity, now);
    }
}
