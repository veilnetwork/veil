//! Session-local congestion advisories and paced recovery for ordinary private routes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use veil_types::NodeIdBytes;

const MAX_DESTINATIONS: usize = 64;
const NOTICE_INTERVAL: Duration = Duration::from_secs(1);
const INITIAL_HOLD: Duration = Duration::from_secs(5);
const MAX_HOLD: Duration = Duration::from_secs(20);
const RECOVERY_EXPIRY: Duration = Duration::from_secs(90);
const SAMPLE_PERIOD: Duration = Duration::from_secs(1);
const INITIAL_BYTES_PER_SEC: usize = 8 * 1024;
const RECOVERY_STEPS: u32 = 8;
const MAX_TRIAL_BYTES: usize = 32 * 1024;

#[derive(Debug, Default)]
pub(crate) struct RoutePressure {
    received: HashMap<NodeIdBytes, Recovery>,
    sent: HashMap<NodeIdBytes, Instant>,
}

#[derive(Debug)]
struct Recovery {
    last_notice: Instant,
    hold: Duration,
    next_trial: Instant,
    sample_since: Option<Instant>,
    sampled_bytes: usize,
    step: u32,
}

impl Recovery {
    fn new(now: Instant, hold: Duration) -> Self {
        Self {
            last_notice: now,
            hold,
            next_trial: now + hold,
            sample_since: None,
            sampled_bytes: 0,
            step: 0,
        }
    }

    fn active(&self, now: Instant) -> bool {
        now.duration_since(self.last_notice) < RECOVERY_EXPIRY
    }

    fn take_trial(&mut self, now: Instant, wire_bytes: usize) -> bool {
        if wire_bytes > MAX_TRIAL_BYTES || now < self.next_trial {
            return false;
        }
        let charge = wire_bytes.max(1024);
        let mut rate = INITIAL_BYTES_PER_SEC << self.step;
        // Require both elapsed time and traffic at the current rate. An idle
        // route resumes sampling at its last observed rate when traffic returns.
        if self.sample_since.is_some_and(|since| {
            now.duration_since(since) >= SAMPLE_PERIOD && self.sampled_bytes >= rate / 2
        }) {
            self.step += 1;
            if self.step == RECOVERY_STEPS {
                return true;
            }
            rate <<= 1;
            self.sample_since = None;
            self.sampled_bytes = 0;
        }
        self.sample_since.get_or_insert(now);
        self.sampled_bytes = self.sampled_bytes.saturating_add(charge);
        self.next_trial =
            now + Duration::from_nanos((charge as u64 * 1_000_000_000).div_ceil(rate as u64));
        true
    }
}

impl RoutePressure {
    pub(crate) fn receive(&mut self, dst: NodeIdBytes, now: Instant) -> bool {
        if let Some(state) = self.received.get_mut(&dst) {
            if now.duration_since(state.last_notice) < NOTICE_INTERVAL {
                return false;
            }
            let hold = if !state.active(now) {
                INITIAL_HOLD
            } else if state.sample_since.is_some() {
                (state.hold * 2).min(MAX_HOLD)
            } else {
                state.hold
            };
            *state = Recovery::new(now, hold);
            return true;
        }
        if self.received.len() == MAX_DESTINATIONS {
            self.received.retain(|_, state| state.active(now));
            if self.received.len() == MAX_DESTINATIONS {
                return false;
            }
        }
        self.received.insert(dst, Recovery::new(now, INITIAL_HOLD));
        true
    }

    pub(crate) fn reserve_notice(&mut self, dst: NodeIdBytes, now: Instant) -> bool {
        if let Some(last) = self.sent.get_mut(&dst) {
            if now.duration_since(*last) < NOTICE_INTERVAL {
                return false;
            }
            *last = now;
            return true;
        }
        if self.sent.len() == MAX_DESTINATIONS {
            self.sent
                .retain(|_, last| now.duration_since(*last) < NOTICE_INTERVAL);
            if self.sent.len() == MAX_DESTINATIONS {
                return false;
            }
        }
        self.sent.insert(dst, now);
        true
    }

    pub(crate) fn is_pressured(&self, dst: &NodeIdBytes, now: Instant) -> bool {
        self.received
            .get(dst)
            .is_some_and(|state| state.active(now))
    }

    pub(crate) fn recently_reported(&self, dst: &NodeIdBytes, now: Instant) -> bool {
        self.received
            .get(dst)
            .is_some_and(|state| now.duration_since(state.last_notice) < NOTICE_INTERVAL)
    }

    pub(crate) fn reserve_trial(
        &mut self,
        dst: &NodeIdBytes,
        now: Instant,
        wire_bytes: usize,
    ) -> bool {
        let Some(state) = self.received.get_mut(dst) else {
            return false;
        };
        if !state.active(now) || !state.take_trial(now, wire_bytes) {
            return false;
        }
        if state.step == RECOVERY_STEPS {
            self.received.remove(dst);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_are_bounded_and_rate_limited_in_both_directions() {
        let mut pressure = RoutePressure::default();
        let now = Instant::now();
        for index in 0..MAX_DESTINATIONS {
            assert!(pressure.receive([index as u8; 32], now));
            assert!(pressure.reserve_notice([index as u8; 32], now));
        }
        let dst = [0; 32];
        let extra = [255; 32];
        let soon = now + NOTICE_INTERVAL / 2;
        assert!(!pressure.receive(dst, soon));
        assert!(!pressure.receive(extra, soon));
        assert!(!pressure.reserve_notice(dst, soon));
        assert!(!pressure.reserve_notice(extra, soon));
        let renewed = now + NOTICE_INTERVAL;
        assert!(pressure.receive(dst, renewed));
        assert!(pressure.reserve_notice(extra, renewed));
        assert!(pressure.receive(extra, now + RECOVERY_EXPIRY));
        assert_eq!(pressure.received.len(), 2);
    }

    #[test]
    fn a_recovery_hold_cannot_refresh_upstream_pressure() {
        let mut pressure = RoutePressure::default();
        let now = Instant::now();
        let dst = [1; 32];
        assert!(pressure.receive(dst, now));
        assert!(pressure.recently_reported(&dst, now));
        assert!(!pressure.recently_reported(&dst, now + NOTICE_INTERVAL));
        let upstream_trial = now + INITIAL_HOLD;
        assert!(pressure.is_pressured(&dst, upstream_trial));
        assert!(!pressure.recently_reported(&dst, upstream_trial));
        assert!(pressure.receive(dst, upstream_trial));
        assert!(pressure.recently_reported(&dst, upstream_trial));
    }

    #[test]
    fn trials_require_live_samples_and_spread_bytes_across_time() {
        let mut pressure = RoutePressure::default();
        let now = Instant::now();
        let dst = [1; 32];
        assert!(pressure.receive(dst, now));
        let start = now + INITIAL_HOLD;
        assert!(!pressure.reserve_trial(&dst, start - Duration::from_millis(1), 1024));
        assert!(!pressure.reserve_trial(&dst, start, MAX_TRIAL_BYTES + 1));
        let later = start + Duration::from_secs(30);
        assert!(pressure.reserve_trial(&dst, later, 1024));
        assert!(!pressure.reserve_trial(&dst, later + Duration::from_millis(124), 1024));
        assert!(pressure.reserve_trial(&dst, later + Duration::from_millis(125), 1024));
        assert_eq!(pressure.received[&dst].step, 0);
        assert!(pressure.is_pressured(&dst, later));
    }

    #[test]
    fn continuing_trials_plan_full_recovery_and_repeat_pressure_increases_the_hold() {
        let mut pressure = RoutePressure::default();
        let now = Instant::now();
        let dst = [1; 32];
        assert!(pressure.receive(dst, now));
        let first = now + INITIAL_HOLD;
        assert!(pressure.reserve_trial(&dst, first, 4096));
        let renewed = first + SAMPLE_PERIOD;
        assert!(pressure.receive(dst, renewed));
        assert!(!pressure.reserve_trial(&dst, renewed + INITIAL_HOLD, 4096));
        let mut trial_at = renewed + INITIAL_HOLD * 2;
        for _ in 0..5000 {
            if !pressure.is_pressured(&dst, trial_at) {
                break;
            }
            assert!(pressure.reserve_trial(&dst, trial_at, 4096));
            if let Some(state) = pressure.received.get(&dst) {
                trial_at = state.next_trial;
            }
        }
        assert!(!pressure.is_pressured(&dst, trial_at));
        assert!(trial_at < renewed + RECOVERY_EXPIRY);
        assert!(pressure.receive(dst, trial_at));
        assert!(pressure.reserve_trial(&dst, trial_at + INITIAL_HOLD, 4096));
    }
}
