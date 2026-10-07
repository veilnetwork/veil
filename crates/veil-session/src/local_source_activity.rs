//! Node-local producer activity and pressure shared across session runners.
//! No remote priority, payload role or wire metadata enters this state.
use std::sync::Mutex;
use std::time::{Duration, Instant};
use veil_util::lock;

pub(crate) const IDLE_GRACE: Duration = Duration::from_secs(3);
pub(crate) const PRESSURE_GRACE: Duration = Duration::from_secs(2);
pub(crate) const RELIABLE_SECONDARY_BYTES: usize = 4096;
const SECONDARY_PROBE_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Default)]
struct SourceState {
    last_primary: Option<Instant>,
    pressure_until: Option<Instant>,
    secondary_next: Option<Instant>,
    reliable_window: Option<(Instant, usize)>,
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

    /// Only a locally authored primary's authenticated path or trusted writer can publish this.
    /// Other runners consume it exclusively for their own secondary producers.
    pub(crate) fn note_pressure(&self, now: Instant) {
        let mut state = lock!(self.0);
        let until = now + PRESSURE_GRACE;
        state.pressure_until = Some(state.pressure_until.map_or(until, |old| old.max(until)));
    }

    /// Hold reliable local producers before encryption, never discard their
    /// bytes. All neighbors of this endpoint share the same bounded allowance.
    /// Whole oversized compatibility frames may progress alone. The caller
    /// must retain FIFO and admission credits while waiting for the deadline.
    pub(crate) fn admit_reliable_secondary(
        &self,
        bytes: usize,
        now: Instant,
    ) -> Result<(), Instant> {
        let mut state = lock!(self.0);
        let active_until = state.last_primary.map(|at| at + IDLE_GRACE);
        let pressure_until = state.pressure_until;
        let (Some(active_until), Some(pressure_until)) = (active_until, pressure_until) else {
            state.reliable_window = None;
            return Ok(());
        };
        if now >= active_until || now >= pressure_until {
            state.reliable_window = None;
            return Ok(());
        }
        let (deadline, used) = state
            .reliable_window
            .get_or_insert((now + SECONDARY_PROBE_INTERVAL, 0));
        if now >= *deadline {
            *deadline = now + SECONDARY_PROBE_INTERVAL;
            *used = 0;
        }
        if *used == 0
            || used
                .checked_add(bytes)
                .is_some_and(|n| n <= RELIABLE_SECONDARY_BYTES)
        {
            *used = used.saturating_add(bytes);
            Ok(())
        } else {
            Err((*deadline).min(active_until).min(pressure_until))
        }
    }

    /// One sparse probe across this endpoint, including different neighbors.
    /// Callers must exclude primary, control and neutral transit beforehand.
    pub(crate) fn allow_secondary(&self, now: Instant) -> bool {
        self.admit_lossy_secondary(now).is_ok()
    }

    /// Ordered compatibility needs the wake deadline while retaining its
    /// plaintext frame. The sparse probe is shared with DATAGRAM senders.
    pub(crate) fn admit_lossy_secondary(&self, now: Instant) -> Result<(), Instant> {
        let mut state = lock!(self.0);
        let active = state
            .last_primary
            .is_some_and(|at| now.saturating_duration_since(at) < IDLE_GRACE);
        let pressured = state.pressure_until.is_some_and(|until| now < until);
        if !active || !pressured {
            state.secondary_next = None;
            return Ok(());
        }
        if let Some(next) = state.secondary_next.filter(|next| now < *next) {
            return Err(next
                .min(state.last_primary.unwrap() + IDLE_GRACE)
                .min(state.pressure_until.unwrap()));
        }
        state.secondary_next = Some(now + SECONDARY_PROBE_INTERVAL);
        Ok(())
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
    fn reliable_neighbors_share_bytes_and_resume_at_pressure_or_idle_expiry() {
        let activity = Arc::new(LocalSourceActivity::default());
        let now = Instant::now();
        activity.note(now);
        activity.note_pressure(now);
        let barrier = Arc::new(Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let activity = Arc::clone(&activity);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    usize::from(
                        activity
                            .admit_reliable_secondary(RELIABLE_SECONDARY_BYTES, now)
                            .is_ok(),
                    )
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
        assert_eq!(
            activity.admit_reliable_secondary(1, now),
            Err(now + SECONDARY_PROBE_INTERVAL)
        );
        // Old compatibility frames stay whole rather than becoming a deadlock.
        let next = now + SECONDARY_PROBE_INTERVAL;
        assert!(activity.admit_reliable_secondary(60_000, next).is_ok());
        assert_eq!(
            activity.admit_reliable_secondary(1, next),
            Err(next + SECONDARY_PROBE_INTERVAL)
        );
        assert!(
            activity
                .admit_reliable_secondary(60_000, now + PRESSURE_GRACE)
                .is_ok()
        );
        assert!(
            activity
                .admit_reliable_secondary(60_000, now + PRESSURE_GRACE)
                .is_ok()
        );
        activity.note_pressure(now + IDLE_GRACE);
        assert!(
            activity
                .admit_reliable_secondary(60_000, now + IDLE_GRACE)
                .is_ok()
        );
        assert!(
            activity
                .admit_reliable_secondary(60_000, now + IDLE_GRACE)
                .is_ok()
        );
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
