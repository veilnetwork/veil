//! Node-local producer activity and pressure shared across session runners.
//! No remote priority, payload role or wire metadata enters this state.
use std::sync::Mutex;
use std::time::{Duration, Instant};
use veil_util::lock;

pub(crate) const IDLE_GRACE: Duration = Duration::from_secs(3);
pub(crate) const PRESSURE_GRACE: Duration = Duration::from_secs(2);
const SECONDARY_PROBE_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Default)]
struct SourceState {
    last_primary: Option<Instant>,
    pressure_until: Option<Instant>,
    secondary_next: Option<Instant>,
}

#[derive(Debug, Default)]
pub(crate) struct LocalSourceActivity(Mutex<SourceState>);

impl LocalSourceActivity {
    pub(crate) fn note(&self, now: Instant) {
        let mut state = lock!(self.0);
        // Runners can publish observations in a different order. An older
        // observation must not retire a newer producer's activity.
        state.last_primary = Some(state.last_primary.map_or(now, |last| last.max(now)));
    }

    pub(crate) fn active(&self, now: Instant) -> bool {
        lock!(self.0)
            .last_primary
            .is_some_and(|at| now.saturating_duration_since(at) < IDLE_GRACE)
    }

    /// Only a locally authored primary's authenticated path can publish this.
    /// Other runners consume it exclusively for their own secondary producers.
    pub(crate) fn note_pressure(&self, now: Instant) {
        let mut state = lock!(self.0);
        let until = now + PRESSURE_GRACE;
        state.pressure_until = Some(state.pressure_until.map_or(until, |old| old.max(until)));
    }

    /// One sparse probe across this endpoint, including different neighbors.
    /// Callers must exclude primary, control and neutral transit beforehand.
    pub(crate) fn allow_secondary(&self, now: Instant) -> bool {
        let mut state = lock!(self.0);
        let active = state
            .last_primary
            .is_some_and(|at| now.saturating_duration_since(at) < IDLE_GRACE);
        let pressured = state.pressure_until.is_some_and(|until| now < until);
        if !active || !pressured {
            state.secondary_next = None;
            return true;
        }
        if state.secondary_next.is_some_and(|next| now < next) {
            return false;
        }
        state.secondary_next = Some(now + SECONDARY_PROBE_INTERVAL);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn simultaneous_neighbors_share_one_probe_and_grace_expires() {
        let activity = Arc::new(LocalSourceActivity::default());
        let now = Instant::now();
        activity.note_pressure(now);
        assert!(
            activity.allow_secondary(now),
            "pressure without a local producer cannot change scheduling"
        );
        assert!(activity.allow_secondary(now));
        activity.note(now);
        let barrier = Arc::new(Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let activity = Arc::clone(&activity);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    usize::from(activity.allow_secondary(now))
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .sum::<usize>(),
            1
        );
        assert!(activity.allow_secondary(now + SECONDARY_PROBE_INTERVAL));
        assert!(!activity.allow_secondary(now + SECONDARY_PROBE_INTERVAL));
        assert!(activity.allow_secondary(now + PRESSURE_GRACE));
        assert!(activity.allow_secondary(now + PRESSURE_GRACE));
    }

    #[test]
    fn old_observations_cannot_shorten_activity_or_pressure() {
        let activity = LocalSourceActivity::default();
        let old = Instant::now();
        let current = old + Duration::from_secs(1);
        activity.note(current);
        activity.note(old);
        activity.note_pressure(current);
        activity.note_pressure(old);
        assert!(activity.active(old + IDLE_GRACE));
        let later = old + PRESSURE_GRACE;
        assert!(activity.allow_secondary(later));
        assert!(!activity.allow_secondary(later));
        // Even recently noted pressure cannot hold secondary traffic once the
        // actual primary has gone idle.
        activity.note_pressure(current + IDLE_GRACE);
        assert!(!activity.active(current + IDLE_GRACE));
        assert!(activity.allow_secondary(current + IDLE_GRACE));
        assert!(activity.allow_secondary(current + IDLE_GRACE));
    }
}
