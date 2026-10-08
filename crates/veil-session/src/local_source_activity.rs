//! Node-local producer activity and pressure shared across session runners.
//! No remote priority, payload role or wire metadata enters this state.
use std::sync::Mutex;
use std::time::{Duration, Instant};
use veil_util::lock;

pub(crate) const IDLE_GRACE: Duration = Duration::from_secs(3);
pub(crate) const PRESSURE_GRACE: Duration = Duration::from_secs(2);
pub(crate) const RELIABLE_SECONDARY_BYTES: usize = 4096;
pub(crate) const PRESSURED_RELIABLE_BYTES: usize = 1024;
pub(crate) const NETWORK_CONTROL_BYTES: usize = 1024;
const SECONDARY_PROBE_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Default)]
struct SourceState {
    last_primary: Option<Instant>,
    pressure_until: Option<Instant>,
    secondary_next: Option<Instant>,
    reliable_next: Option<Instant>,
    network_window: Option<(Instant, usize)>,
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

    /// Hold reliable local producers before encryption whenever a local
    /// primary is active, never discard bytes. Waiting for pressure first
    /// permits a file burst to fill a fast relay's slower downstream path.
    /// All neighbors of this endpoint share the same bounded allowance.
    /// Whole oversized compatibility frames may progress alone, but spend
    /// proportional future time to pay for their bytes. The caller must retain
    /// FIFO and admission credits while waiting for the deadline.
    pub(crate) fn admit_reliable_secondary(
        &self,
        bytes: usize,
        now: Instant,
    ) -> Result<(), Instant> {
        self.admit_reliable(bytes, now, false)
    }

    /// Own network queries have an independent small allowance, so a held
    /// file burst cannot prevent route/certificate recovery under pressure.
    pub(crate) fn admit_network_control(&self, bytes: usize, now: Instant) -> Result<(), Instant> {
        self.admit_reliable(bytes, now, true)
    }

    fn admit_reliable(
        &self,
        bytes: usize,
        now: Instant,
        network_control: bool,
    ) -> Result<(), Instant> {
        let mut state = lock!(self.0);
        let active_until = state.last_primary.map(|at| at + IDLE_GRACE);
        // DATA is paced even during healthy primary activity. Charge exact
        // wire bytes, rather than rounding each frame up to a 200-ms bucket:
        // that wastes the remainder and emits each bucket as a short burst.
        // No unused allowance accumulates while the source is idle.
        if !network_control {
            let Some(until) = active_until.filter(|until| now < *until) else {
                state.reliable_next = None;
                return Ok(());
            };
            if let Some(next) = state.reliable_next.filter(|next| now < *next) {
                return Err(next.min(until));
            }
            // Pressure must release bandwidth beyond the healthy-source
            // ceiling. Retain existing debt through feedback transitions;
            // only a newly admitted frame earns the current rate.
            let budget = if state.pressure_until.is_some_and(|until| now < until) {
                PRESSURED_RELIABLE_BYTES
            } else {
                RELIABLE_SECONDARY_BYTES
            };
            let nanos = (bytes as u128)
                .saturating_mul(SECONDARY_PROBE_INTERVAL.as_nanos())
                .div_ceil(budget as u128)
                .min(SECONDARY_PROBE_INTERVAL.as_nanos() * u32::MAX as u128);
            let charge = Duration::new(
                (nanos / 1_000_000_000) as u64,
                (nanos % 1_000_000_000) as u32,
            );
            state.reliable_next = Some(now + charge);
            return Ok(());
        }
        // Recovery RPCs keep a separate pressure-only allowance. DATA debt
        // must never prevent route/certificate recovery.
        let limited_until = active_until
            .zip(state.pressure_until)
            .map(|(active, pressure)| active.min(pressure));
        let window = &mut state.network_window;
        let budget = NETWORK_CONTROL_BYTES;
        let Some(limited_until) = limited_until.filter(|until| now < *until) else {
            *window = None;
            return Ok(());
        };
        let (deadline, used) = window.get_or_insert((now + SECONDARY_PROBE_INTERVAL, 0));
        if now >= *deadline {
            *deadline = now + SECONDARY_PROBE_INTERVAL;
            *used = 0;
        }
        if *used == 0 || used.checked_add(bytes).is_some_and(|n| n <= budget) {
            if bytes > budget {
                // A whole legacy frame must not deadlock on a smaller budget.
                // Charge its size across future windows instead of granting
                // another oversized frame every probe interval. Fresh audio
                // observations extend pressure, never replenish this debt.
                let windows = u32::try_from(bytes.div_ceil(budget)).unwrap_or(u32::MAX);
                *deadline = now + SECONDARY_PROBE_INTERVAL * windows;
            }
            *used = used.saturating_add(bytes);
            Ok(())
        } else {
            Err((*deadline).min(limited_until))
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
    fn healthy_primary_already_bounds_file_bursts_but_not_recovery_rpcs() {
        let source = LocalSourceActivity::default();
        let now = Instant::now();
        source.note(now);
        assert!(
            source
                .admit_reliable_secondary(RELIABLE_SECONDARY_BYTES, now)
                .is_ok()
        );
        assert_eq!(
            source.admit_reliable_secondary(1, now),
            Err(now + SECONDARY_PROBE_INTERVAL)
        );
        assert!(source.admit_network_control(60000, now).is_ok());
        assert!(source.admit_network_control(60000, now).is_ok());
        assert!(
            source
                .admit_reliable_secondary(60000, now + IDLE_GRACE)
                .is_ok()
        );
        assert!(
            source
                .admit_reliable_secondary(60000, now + IDLE_GRACE)
                .is_ok()
        );
    }

    #[test]
    fn data_pacing_preserves_partial_frame_credit_without_catch_up_bursts() {
        let activity = LocalSourceActivity::default();
        let now = Instant::now();
        activity.note(now);
        // Two half-budget frames take one interval, never two rounded ones.
        assert!(activity.admit_reliable_secondary(2048, now).is_ok());
        assert_eq!(
            activity.admit_reliable_secondary(2048, now),
            Err(now + Duration::from_millis(100))
        );
        let half = now + Duration::from_millis(100);
        assert!(activity.admit_reliable_secondary(2048, half).is_ok());
        assert_eq!(
            activity.admit_reliable_secondary(2048, half),
            Err(now + Duration::from_millis(200))
        );
        // A stalled sender does not accumulate a bucket to flush on wake.
        let late = now + Duration::from_secs(1);
        activity.note(late);
        assert!(activity.admit_reliable_secondary(2048, late).is_ok());
        assert_eq!(
            activity.admit_reliable_secondary(2048, late),
            Err(late + Duration::from_millis(100))
        );
    }

    #[test]
    fn pressure_reduces_data_rate_without_erasing_debt_or_blocking_recovery() {
        let source = LocalSourceActivity::default();
        let now = Instant::now();
        source.note(now);
        assert!(source.admit_reliable_secondary(4096, now).is_ok());
        source.note_pressure(now + Duration::from_millis(50));
        let next = now + Duration::from_millis(200);
        assert_eq!(
            source.admit_reliable_secondary(1, now + Duration::from_millis(50)),
            Err(next)
        );
        assert!(source.admit_reliable_secondary(4096, next).is_ok());
        assert_eq!(
            source.admit_reliable_secondary(1, next),
            Err(now + Duration::from_secs(1))
        );
        // DATA's longer debt does not consume route-recovery credits.
        assert!(source.admit_network_control(1024, next).is_ok());
        // Once the pressure lease expires, new DATA recovers its healthy rate.
        let healthy = now + Duration::from_millis(2100);
        source.note(healthy);
        assert!(source.admit_reliable_secondary(4096, healthy).is_ok());
        assert_eq!(
            source.admit_reliable_secondary(1, healthy),
            Err(healthy + Duration::from_millis(200))
        );
    }

    #[test]
    fn oversized_reliable_frames_pay_their_byte_budget_across_refreshes() {
        for network_control in [false, true] {
            let activity = LocalSourceActivity::default();
            let now = Instant::now();
            let budget = if network_control {
                NETWORK_CONTROL_BYTES
            } else {
                PRESSURED_RELIABLE_BYTES
            };
            let bytes = budget * 15 + 1;
            activity.note(now);
            activity.note_pressure(now);
            assert!(activity.admit_reliable(bytes, now, network_control).is_ok());
            // Different runners keep publishing fresh primary activity and
            // pressure. They must not replenish a large frame's spent bytes
            // every 200 ms, even though that frame had to stay whole.
            let charged_until = if network_control {
                now + SECONDARY_PROBE_INTERVAL * 16
            } else {
                now + SECONDARY_PROBE_INTERVAL * 15 + Duration::from_nanos(195_313)
            };
            for tick in 1..16 {
                let at = now + SECONDARY_PROBE_INTERVAL * tick;
                activity.note(at);
                activity.note_pressure(at);
                let retry = activity
                    .admit_reliable(1, at, network_control)
                    .expect_err("oversized frame bypassed endpoint byte budget");
                // The runner may wake earlier to recheck activity/pressure
                // expiry. That wake must retain the unpaid bytes when fresh
                // primary observations extend those lifetimes.
                assert!(retry > at && retry <= charged_until);
            }
            activity.note(charged_until);
            activity.note_pressure(charged_until);
            assert!(
                activity
                    .admit_reliable(budget, charged_until, network_control)
                    .is_ok()
            );
            assert_eq!(
                activity.admit_reliable(1, charged_until, network_control),
                Err(charged_until + SECONDARY_PROBE_INTERVAL)
            );
        }
    }

    #[test]
    fn own_rpc_neighbors_share_a_separate_byte_allowance() {
        let activity = Arc::new(LocalSourceActivity::default());
        let now = Instant::now();
        activity.note(now);
        activity.note_pressure(now);
        assert!(
            activity
                .admit_reliable_secondary(PRESSURED_RELIABLE_BYTES, now)
                .is_ok()
        );
        assert!(activity.admit_reliable_secondary(1, now).is_err());
        let barrier = Arc::new(Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let activity = Arc::clone(&activity);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    usize::from(
                        activity
                            .admit_network_control(NETWORK_CONTROL_BYTES, now)
                            .is_ok(),
                    )
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .sum::<usize>(),
            1
        );
        assert_eq!(
            activity.admit_network_control(1, now),
            Err(now + SECONDARY_PROBE_INTERVAL)
        );
        let next = now + SECONDARY_PROBE_INTERVAL;
        assert!(activity.admit_network_control(60000, next).is_ok());
        assert_eq!(
            activity.admit_network_control(1, next),
            Err(now + PRESSURE_GRACE)
        );
        assert!(
            activity
                .admit_reliable_secondary(PRESSURED_RELIABLE_BYTES, next)
                .is_ok()
        );
        for end in [PRESSURE_GRACE, IDLE_GRACE] {
            assert!(activity.admit_network_control(60000, now + end).is_ok());
            assert!(activity.admit_network_control(60000, now + end).is_ok());
        }
        activity.note_pressure(now + IDLE_GRACE);
        assert!(
            activity
                .admit_network_control(60000, now + IDLE_GRACE)
                .is_ok()
        );
        assert!(
            activity
                .admit_network_control(60000, now + IDLE_GRACE)
                .is_ok()
        );
    }

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
    fn reliable_neighbors_share_bytes_and_resume_only_at_primary_idle_expiry() {
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
                            .admit_reliable_secondary(PRESSURED_RELIABLE_BYTES, now)
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
            Err(now + IDLE_GRACE)
        );
        assert!(
            activity
                .admit_reliable_secondary(60_000, now + PRESSURE_GRACE)
                .is_err()
        );
        assert!(
            activity
                .admit_reliable_secondary(60_000, now + PRESSURE_GRACE)
                .is_err()
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
