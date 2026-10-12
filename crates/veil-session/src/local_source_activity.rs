//! Node-local producer activity and pressure shared across session runners.
//! No remote priority, payload role or wire metadata enters this state.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use veil_util::lock;

pub(crate) const IDLE_GRACE: Duration = Duration::from_secs(3);
pub(crate) const PRESSURE_GRACE: Duration = Duration::from_secs(2);
pub(crate) const RELIABLE_SECONDARY_BYTES: usize = 4096;
pub(crate) const PRESSURED_RELIABLE_BYTES: usize = 1024;
pub(crate) const NETWORK_CONTROL_BYTES: usize = 1024;
const SIGNALING_BYTES: usize = 4096;
// One maximum-sized local datagram work item, shared by all neighbors. Small
// control packets must not consume an entire allowance and corrupt a following
// packetized frame. Reliable files retain their separate, smaller byte budget.
pub(crate) const LOSSY_SECONDARY_BYTES: usize = 8192;
const SECONDARY_PROBE_INTERVAL: Duration = Duration::from_millis(200);
const RELIABLE_RAMP_STEP: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
struct SourceState {
    last_primary: Option<Instant>,
    pressure_until: Option<Instant>,
    secondary_window: Option<(Instant, usize)>,
    reliable_next: Option<Instant>,
    source_feedback_seen: bool,
    last_healthy_feedback: Option<Instant>,
    reliable_ramp_since: Option<Instant>,
    last_reliable_progress: Option<Instant>,
    reliable_sequence: u64,
    reliable_waiters: VecDeque<u64>,
    network_window: Option<(Instant, usize)>,
    signaling_next: Option<Instant>,
}

#[derive(Debug, Default)]
pub(crate) struct LocalSourceActivity(Mutex<SourceState>);

/// A runner's local reliable admission turn. Neither its identity nor its
/// position is transmitted. Dropping a runner releases any outstanding turn.
pub(crate) struct ReliableSource {
    activity: Arc<LocalSourceActivity>,
    id: u64,
}

impl ReliableSource {
    pub(crate) fn admit(&self, bytes: usize, now: Instant) -> Result<(), Instant> {
        self.activity
            .admit_reliable(bytes, now, false, Some(self.id))
    }

    /// Release a turn when this runner has no eligible local write. Keep the
    /// shared byte debt: cancellation must not refund already admitted bytes.
    pub(crate) fn cancel(&self) {
        lock!(self.activity.0)
            .reliable_waiters
            .retain(|id| *id != self.id);
    }
}

impl Drop for ReliableSource {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl LocalSourceActivity {
    pub(crate) fn reliable_source(self: &Arc<Self>) -> ReliableSource {
        let mut state = lock!(self.0);
        state.reliable_sequence = state
            .reliable_sequence
            .checked_add(1)
            .expect("local reliable source counter exhausted");
        ReliableSource {
            activity: Arc::clone(self),
            id: state.reliable_sequence,
        }
    }

    pub(crate) fn note(&self, now: Instant) {
        let mut state = lock!(self.0);
        if state
            .last_primary
            .is_some_and(|last| now.saturating_duration_since(last) >= IDLE_GRACE)
        {
            // A new producer after inactivity must not inherit a previous
            // call's oversized compatibility-control debt.
            state.signaling_next = None;
            state.source_feedback_seen = false;
            state.last_healthy_feedback = None;
            state.reliable_ramp_since = None;
            state.last_reliable_progress = None;
        }
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
        state.reliable_ramp_since = None;
    }

    /// A validated local observation enables gradual admission of own DATA.
    /// Reports do not grant byte credit or erase another source's pressure.
    pub(crate) fn note_feedback(&self, pressured: bool, now: Instant) {
        if pressured {
            self.note_pressure(now);
        }
        let mut state = lock!(self.0);
        state.source_feedback_seen = true;
        if !pressured {
            state.last_healthy_feedback =
                Some(state.last_healthy_feedback.map_or(now, |old| old.max(now)));
        }
    }

    /// Hold reliable local producers before encryption whenever a local
    /// primary is active, never discard bytes. Waiting for pressure first
    /// permits a file burst to fill a fast relay's slower downstream path.
    /// All neighbors of this endpoint share the same bounded allowance.
    /// Whole oversized compatibility frames may progress alone, but spend
    /// proportional future time to pay for their bytes. The caller must retain
    /// FIFO and admission credits while waiting for the deadline.
    #[cfg(test)]
    pub(crate) fn admit_reliable_secondary(
        &self,
        bytes: usize,
        now: Instant,
    ) -> Result<(), Instant> {
        self.admit_reliable(bytes, now, false, None)
    }

    /// Locally authored signaling is independent of both reliable DATA debt
    /// and network recovery. A periodic fan-out must not become a byte burst
    /// on the common uplink while a primary producer is active. The first
    /// frame is immediate; subsequent whole frames pay proportional time.
    pub(crate) fn signaling_wait(&self, now: Instant) -> Option<Instant> {
        let state = lock!(self.0);
        let until = state.last_primary.map(|at| at + IDLE_GRACE)?;
        if now >= until {
            return None;
        }
        state
            .signaling_next
            .filter(|next| now < *next)
            .map(|next| next.min(until))
    }

    pub(crate) fn admit_signaling(&self, bytes: usize, now: Instant) -> Result<(), Instant> {
        let mut state = lock!(self.0);
        let Some(until) = state
            .last_primary
            .map(|at| at + IDLE_GRACE)
            .filter(|until| now < *until)
        else {
            state.signaling_next = None;
            return Ok(());
        };
        if let Some(next) = state.signaling_next.filter(|next| now < *next) {
            return Err(next.min(until));
        }
        let nanos = (bytes.max(1) as u128)
            .saturating_mul(SECONDARY_PROBE_INTERVAL.as_nanos())
            .div_ceil(SIGNALING_BYTES as u128)
            .min(SECONDARY_PROBE_INTERVAL.as_nanos() * u32::MAX as u128);
        let charge = Duration::new(
            (nanos / 1_000_000_000) as u64,
            (nanos % 1_000_000_000) as u32,
        );
        // Charge from the actual admission time. Idle time and fresh feedback
        // neither accrue catch-up credit nor refund an already sent frame.
        state.signaling_next = Some(now + charge);
        Ok(())
    }

    /// Own network queries have an independent small allowance, so a held
    /// file burst cannot prevent route/certificate recovery under pressure.
    pub(crate) fn admit_network_control(&self, bytes: usize, now: Instant) -> Result<(), Instant> {
        self.admit_reliable(bytes, now, true, None)
    }

    fn admit_reliable(
        &self,
        bytes: usize,
        now: Instant,
        network_control: bool,
        source: Option<u64>,
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
                state.reliable_waiters.clear();
                state.reliable_ramp_since = None;
                state.last_reliable_progress = None;
                return Ok(());
            };
            // Register before waiting for byte debt. The first runner to wake
            // at every deadline must not consume every turn while another
            // neighbor has an eligible local frame waiting. This affects only
            // authored data; neutral transit and recovery RPCs never join.
            if let Some(id) = source
                && !state.reliable_waiters.contains(&id)
            {
                state.reliable_waiters.push_back(id);
            }
            if let Some(next) = state.reliable_next.filter(|next| now < *next) {
                return Err(next.min(until));
            }
            if let Some(id) = source {
                if state.reliable_waiters.front() != Some(&id) {
                    // A canceled/blocked head releases its turn separately.
                    // Poll briefly without granting catch-up credit or changing
                    // the node-wide rate; no per-application priority is used.
                    return Err((now + Duration::from_millis(10)).min(until));
                }
                state.reliable_waiters.pop_front();
            }
            // Pressure must release bandwidth beyond the healthy-source
            // ceiling. Retain existing debt through feedback transitions;
            // only a newly admitted frame earns the current rate.
            let budget = if state.pressure_until.is_some_and(|until| now < until) {
                state.reliable_ramp_since = None;
                PRESSURED_RELIABLE_BYTES
            } else if state.source_feedback_seen {
                let fresh = state
                    .last_healthy_feedback
                    .is_some_and(|at| now.saturating_duration_since(at) < PRESSURE_GRACE);
                if !fresh
                    || state
                        .last_reliable_progress
                        .is_none_or(|at| now.saturating_duration_since(at) >= IDLE_GRACE)
                {
                    state.reliable_ramp_since = None;
                }
                let since = if fresh {
                    *state.reliable_ramp_since.get_or_insert(now)
                } else {
                    now
                };
                let steps =
                    now.saturating_duration_since(since).as_nanos() / RELIABLE_RAMP_STEP.as_nanos();
                let max_steps = (RELIABLE_SECONDARY_BYTES / PRESSURED_RELIABLE_BYTES - 1) as u128;
                PRESSURED_RELIABLE_BYTES.saturating_mul(
                    1 + steps.min(max_steps) as usize,
                )
            } else {
                // Legacy callers without negotiated local feedback retain
                // their existing allowance. No remote frame enables ramping.
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
            state.last_reliable_progress = Some(now);
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

    /// A bounded byte allowance across this endpoint, including all neighbors.
    /// Callers must exclude primary, control and neutral transit beforehand.
    pub(crate) fn allow_secondary(&self, bytes: usize, now: Instant) -> bool {
        self.admit_lossy_secondary(bytes, now).is_ok()
    }

    /// Ordered compatibility needs the wake deadline while retaining its
    /// plaintext frame. Its byte allowance is shared with DATAGRAM senders.
    pub(crate) fn admit_lossy_secondary(&self, bytes: usize, now: Instant) -> Result<(), Instant> {
        let mut state = lock!(self.0);
        let active = state
            .last_primary
            .is_some_and(|at| now.saturating_duration_since(at) < IDLE_GRACE);
        let pressured = state.pressure_until.is_some_and(|until| now < until);
        if !active || !pressured {
            state.secondary_window = None;
            return Ok(());
        }
        let bytes = bytes.max(1);
        let (deadline, used) = state
            .secondary_window
            .get_or_insert((now + SECONDARY_PROBE_INTERVAL, 0));
        if now >= *deadline {
            *deadline = now + SECONDARY_PROBE_INTERVAL;
            *used = 0;
        }
        if *used == 0
            || used
                .checked_add(bytes)
                .is_some_and(|n| n <= LOSSY_SECONDARY_BYTES)
        {
            // Admit an oversized compatibility item alone and charge its
            // size across future windows. Fresh pressure never refunds debt.
            if bytes > LOSSY_SECONDARY_BYTES {
                let windows =
                    u32::try_from(bytes.div_ceil(LOSSY_SECONDARY_BYTES)).unwrap_or(u32::MAX);
                *deadline = now + SECONDARY_PROBE_INTERVAL * windows;
            }
            *used = used.saturating_add(bytes);
            Ok(())
        } else {
            Err((*deadline)
                .min(state.last_primary.unwrap() + IDLE_GRACE)
                .min(state.pressure_until.unwrap()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn negotiated_data_starts_small_and_recovers_only_after_actual_healthy_sending() {
        let source = LocalSourceActivity::default();
        let now = Instant::now();
        source.note(now);
        source.note_feedback(false, now);
        // Good observations before DATA starts do not accrue startup credit.
        for seconds in 1..=10 {
            let at = now + Duration::from_secs(seconds);
            source.note(at);
            source.note_feedback(false, at);
        }
        let start = now + Duration::from_secs(10);
        for (seconds, charge_ns) in [
            (0, 200_000_000),
            (2, 100_000_000),
            (4, 66_666_667),
            (6, 50_000_000),
        ] {
            let at = start + Duration::from_secs(seconds);
            source.note(at);
            source.note_feedback(false, at);
            assert!(source.admit_reliable_secondary(1024, at).is_ok());
            assert_eq!(
                source.admit_reliable_secondary(1, at),
                Err(at + Duration::from_nanos(charge_ns))
            );
        }
    }

    #[test]
    fn stale_feedback_idle_sending_and_pressure_reset_ramp_without_refunding_debt() {
        let source = LocalSourceActivity::default();
        let now = Instant::now();
        source.note(now);
        source.note_feedback(false, now);
        assert!(source.admit_reliable_secondary(1024, now).is_ok());
        let stale = now + PRESSURE_GRACE;
        source.note(stale);
        assert!(source.admit_reliable_secondary(1024, stale).is_ok());
        let deadline = stale + SECONDARY_PROBE_INTERVAL;
        // A new healthy report cannot refund the previous DATA byte debt.
        source.note_feedback(false, stale + Duration::from_millis(1));
        assert_eq!(source.admit_reliable_secondary(1, stale), Err(deadline));
        assert!(source.admit_reliable_secondary(1024, deadline).is_ok());
        let recover = deadline + RELIABLE_RAMP_STEP;
        source.note(recover);
        source.note_feedback(false, recover);
        assert!(source.admit_reliable_secondary(1024, recover).is_ok());
        let next = recover + Duration::from_millis(100);
        source.note_feedback(true, recover + Duration::from_millis(1));
        assert_eq!(source.admit_reliable_secondary(1, recover), Err(next));
        assert!(source.admit_reliable_secondary(1024, next).is_ok());
        assert_eq!(
            source.admit_reliable_secondary(1, next),
            Err(next + SECONDARY_PROBE_INTERVAL)
        );
        // Keep primary activity alive while DATA itself is idle. Restart
        // remains conservative even with a fresh healthy report.
        for second in 1..=6 {
            let at = next + Duration::from_secs(second);
            source.note(at);
            source.note_feedback(false, at);
        }
        let resumed = next + Duration::from_secs(6);
        assert!(source.admit_reliable_secondary(1024, resumed).is_ok());
        assert_eq!(
            source.admit_reliable_secondary(1, resumed),
            Err(resumed + SECONDARY_PROBE_INTERVAL)
        );
    }

    #[test]
    fn expired_pressure_feedback_cannot_jump_to_legacy_data_rate() {
        let source = LocalSourceActivity::default();
        let now = Instant::now();
        source.note(now);
        source.note_feedback(true, now);
        let expired = now + PRESSURE_GRACE;
        source.note(expired);
        assert!(source.admit_reliable_secondary(1024, expired).is_ok());
        assert_eq!(
            source.admit_reliable_secondary(1, expired),
            Err(expired + SECONDARY_PROBE_INTERVAL)
        );
        // Without an active primary, ordinary data remains unrestricted.
        let idle = expired + IDLE_GRACE;
        assert!(source.admit_reliable_secondary(60000, idle).is_ok());
        assert!(source.admit_reliable_secondary(60000, idle).is_ok());
    }

    #[test]
    fn signaling_fanout_is_paced_across_producers_without_idle_credit() {
        let activity = Arc::new(LocalSourceActivity::default());
        let peer = activity.clone();
        let now = Instant::now();
        activity.note(now);
        assert_eq!(activity.admit_signaling(1024, now), Ok(()));
        let next = now + Duration::from_millis(50);
        assert_eq!(peer.admit_signaling(1024, now), Err(next));
        activity.note(now + Duration::from_millis(10));
        activity.note_pressure(now + Duration::from_millis(10));
        assert_eq!(
            activity.signaling_wait(now + Duration::from_millis(10)),
            Some(next)
        );
        assert_eq!(peer.admit_signaling(2048, next), Ok(()));
        assert_eq!(
            activity.admit_signaling(1024, next),
            Err(next + Duration::from_millis(100))
        );
        let later = now + Duration::from_secs(1);
        assert_eq!(activity.admit_signaling(1024, later), Ok(()));
        assert_eq!(
            peer.admit_signaling(1024, later),
            Err(later + Duration::from_millis(50))
        );
    }

    #[test]
    fn signaling_debt_does_not_block_data_recovery_or_idle_call_setup() {
        let activity = LocalSourceActivity::default();
        let now = Instant::now();
        assert_eq!(activity.admit_signaling(usize::MAX, now), Ok(()));
        assert_eq!(activity.admit_signaling(1024, now), Ok(()));
        activity.note(now);
        activity.note_pressure(now);
        assert_eq!(activity.admit_signaling(8192, now), Ok(()));
        assert_eq!(activity.admit_reliable_secondary(1024, now), Ok(()));
        assert_eq!(activity.admit_network_control(1024, now), Ok(()));
        assert_eq!(
            activity.admit_signaling(1, now),
            Err(now + Duration::from_millis(400))
        );
        assert_eq!(activity.signaling_wait(now + IDLE_GRACE), None);
        assert_eq!(activity.admit_signaling(1024, now + IDLE_GRACE), Ok(()));
        let resumed = now + IDLE_GRACE;
        activity.note(resumed);
        assert_eq!(
            activity.admit_signaling(SIGNALING_BYTES * 100, resumed),
            Ok(())
        );
        activity.note(resumed + IDLE_GRACE);
        assert_eq!(activity.admit_signaling(1024, resumed + IDLE_GRACE), Ok(()));
    }

    #[test]
    fn short_control_and_packetized_frame_fit_one_pressure_allowance() {
        let activity = LocalSourceActivity::default();
        let now = Instant::now();
        activity.note(now);
        activity.note_pressure(now);
        // Representative encrypted work items from the physical camera call:
        // a short RTCP item followed by four MTU-sized RTP items. Packet count
        // throttling would admit only the first item, leaving this frame incomplete.
        assert!(activity.allow_secondary(96, now));
        for _ in 0..4 {
            assert!(activity.allow_secondary(1200, now + Duration::from_millis(1)));
        }
        let remaining = LOSSY_SECONDARY_BYTES - 96 - 4 * 1200;
        assert!(activity.allow_secondary(remaining, now));
        assert!(!activity.allow_secondary(1, now));
        // Reporting poor audio again cannot replenish the shared allowance.
        activity.note_pressure(now + Duration::from_millis(100));
        assert!(!activity.allow_secondary(1, now + Duration::from_millis(100)));
        assert!(activity.allow_secondary(1200, now + SECONDARY_PROBE_INTERVAL));
    }

    #[test]
    fn pressured_packet_bursts_share_a_byte_ceiling_across_neighbors() {
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
                    usize::from(activity.allow_secondary(1024, now))
                })
            })
            .collect();
        let admitted = threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .sum::<usize>();
        assert_eq!(admitted * 1024, LOSSY_SECONDARY_BYTES);
        assert!(!activity.allow_secondary(1024, now));
    }

    #[test]
    fn oversized_lossy_work_is_charged_without_overflow_or_pressure_refund() {
        let activity = LocalSourceActivity::default();
        let now = Instant::now();
        activity.note(now);
        activity.note_pressure(now);
        assert!(activity.allow_secondary(LOSSY_SECONDARY_BYTES + 1, now));
        let one_window = now + SECONDARY_PROBE_INTERVAL;
        activity.note_pressure(one_window);
        assert_eq!(
            activity.admit_lossy_secondary(1, one_window),
            Err(now + SECONDARY_PROBE_INTERVAL * 2)
        );
        assert!(activity.allow_secondary(usize::MAX, now + SECONDARY_PROBE_INTERVAL * 2));
        assert!(!activity.allow_secondary(1, now + SECONDARY_PROBE_INTERVAL * 2));
        // Without active primary traffic no producer retains the pressure cap.
        assert!(activity.allow_secondary(1, now + IDLE_GRACE));
    }

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
            assert!(
                activity
                    .admit_reliable(bytes, now, network_control, None)
                    .is_ok()
            );
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
                    .admit_reliable(1, at, network_control, None)
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
                    .admit_reliable(budget, charged_until, network_control, None)
                    .is_ok()
            );
            assert_eq!(
                activity.admit_reliable(1, charged_until, network_control, None),
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
    fn simultaneous_neighbors_share_one_full_allowance_and_grace_expires() {
        let activity = Arc::new(LocalSourceActivity::default());
        let now = Instant::now();
        activity.note_pressure(now);
        assert!(
            activity.allow_secondary(LOSSY_SECONDARY_BYTES, now),
            "pressure without a local producer cannot change scheduling"
        );
        assert!(activity.allow_secondary(LOSSY_SECONDARY_BYTES, now));
        activity.note(now);
        let barrier = Arc::new(Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let activity = Arc::clone(&activity);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    usize::from(activity.allow_secondary(LOSSY_SECONDARY_BYTES, now))
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
        assert!(activity.allow_secondary(LOSSY_SECONDARY_BYTES, now + SECONDARY_PROBE_INTERVAL));
        assert!(!activity.allow_secondary(LOSSY_SECONDARY_BYTES, now + SECONDARY_PROBE_INTERVAL));
        assert!(activity.allow_secondary(LOSSY_SECONDARY_BYTES, now + PRESSURE_GRACE));
        assert!(activity.allow_secondary(LOSSY_SECONDARY_BYTES, now + PRESSURE_GRACE));
    }

    #[test]
    fn reliable_waiting_neighbor_cannot_lose_every_deadline_to_a_hot_runner() {
        let activity = Arc::new(LocalSourceActivity::default());
        let hot = activity.reliable_source();
        let cold = activity.reliable_source();
        let now = Instant::now();
        activity.note(now);
        activity.note_pressure(now);
        assert!(hot.admit(PRESSURED_RELIABLE_BYTES, now).is_ok());
        assert!(cold.admit(PRESSURED_RELIABLE_BYTES, now).is_err());
        assert!(hot.admit(PRESSURED_RELIABLE_BYTES, now).is_err());

        // Deliberately wake the busy runner FIRST at every deadline. Both
        // continue to have data; admission must alternate without multiplying
        // the shared endpoint allowance or postponing the quieter runner.
        for turn in 1..=16 {
            let at = now + SECONDARY_PROBE_INTERVAL * turn;
            activity.note(at);
            activity.note_pressure(at);
            if turn % 2 == 1 {
                assert!(hot.admit(PRESSURED_RELIABLE_BYTES, at).is_err());
                assert!(cold.admit(PRESSURED_RELIABLE_BYTES, at).is_ok());
                assert!(cold.admit(PRESSURED_RELIABLE_BYTES, at).is_err());
            } else {
                assert!(hot.admit(PRESSURED_RELIABLE_BYTES, at).is_ok());
                assert!(hot.admit(PRESSURED_RELIABLE_BYTES, at).is_err());
                assert!(cold.admit(PRESSURED_RELIABLE_BYTES, at).is_err());
            }
            assert!(hot.admit(1, at).is_err());
            assert!(cold.admit(1, at).is_err());
        }
    }

    #[test]
    fn abandoned_reliable_turn_releases_neighbor_without_refunding_bytes() {
        let activity = Arc::new(LocalSourceActivity::default());
        let first = activity.reliable_source();
        let abandoned = activity.reliable_source();
        let waiting = activity.reliable_source();
        let now = Instant::now();
        activity.note(now);
        activity.note_pressure(now);
        assert!(first.admit(PRESSURED_RELIABLE_BYTES, now).is_ok());
        assert!(abandoned.admit(1, now).is_err());
        assert!(waiting.admit(1, now).is_err());
        abandoned.cancel();
        assert_eq!(waiting.admit(1, now), Err(now + SECONDARY_PROBE_INTERVAL));
        assert!(
            waiting
                .admit(PRESSURED_RELIABLE_BYTES, now + SECONDARY_PROBE_INTERVAL)
                .is_ok()
        );

        let next = now + SECONDARY_PROBE_INTERVAL;
        assert!(abandoned.admit(1, next).is_err());
        assert!(waiting.admit(1, next).is_err());
        // Session exit/cancellation drops its guard even on an early return.
        drop(abandoned);
        assert!(waiting.admit(1, next + SECONDARY_PROBE_INTERVAL).is_ok());
    }

    #[test]
    fn reliable_turns_do_not_capture_recovery_or_survive_primary_idle() {
        let activity = Arc::new(LocalSourceActivity::default());
        let first = activity.reliable_source();
        let waiting = activity.reliable_source();
        let now = Instant::now();
        activity.note(now);
        activity.note_pressure(now);
        assert!(first.admit(PRESSURED_RELIABLE_BYTES, now).is_ok());
        assert!(waiting.admit(1, now).is_err());
        assert!(
            activity
                .admit_network_control(NETWORK_CONTROL_BYTES, now)
                .is_ok()
        );
        assert!(activity.admit_network_control(1, now).is_err());
        let idle = now + IDLE_GRACE;
        // A stale waiting turn cannot impose scheduling on unrelated traffic
        // after the local primary stops. Unused credit is not accumulated.
        assert!(first.admit(60_000, idle).is_ok());
        assert!(first.admit(60_000, idle).is_ok());
        assert!(waiting.admit(60_000, idle).is_ok());
        activity.note(idle);
        activity.note_pressure(idle);
        assert!(first.admit(PRESSURED_RELIABLE_BYTES, idle).is_ok());
        assert!(waiting.admit(1, idle).is_err());
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
        assert!(activity.allow_secondary(LOSSY_SECONDARY_BYTES, later));
        assert!(!activity.allow_secondary(LOSSY_SECONDARY_BYTES, later));
        // Even recently noted pressure cannot hold secondary traffic once the
        // actual primary has gone idle.
        activity.note_pressure(current + IDLE_GRACE);
        assert!(!activity.active(current + IDLE_GRACE));
        assert!(activity.allow_secondary(LOSSY_SECONDARY_BYTES, current + IDLE_GRACE));
        assert!(activity.allow_secondary(LOSSY_SECONDARY_BYTES, current + IDLE_GRACE));
    }
}
