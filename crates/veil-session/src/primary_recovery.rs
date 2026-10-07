//! Bounded endpoint-only replacement of a primary whose ACK progress stopped.
//! This neither resets congestion state nor changes receiver authorization.
use std::time::{Duration, Instant};
use veil_transport::QuicDatagramPathStats;

// A PTO and actual expired datagrams are also required; ACK silence alone,
// including idle producers, cannot trigger connection churn.
const STALLED_FOR: Duration = Duration::from_millis(500);
const ATTEMPT_SPACING: Duration = Duration::from_secs(2);

#[derive(Default)]
pub(super) struct PrimaryRecovery {
    last_ack: Option<u64>,
    last_expired: u64,
    observed_at: Option<Instant>,
    expired_at_progress: u64,
    next_attempt: Option<Instant>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Action {
    None,
    Progress,
    Probe,
}

impl PrimaryRecovery {
    pub(super) fn reset(&mut self) {
        // Keep attempt spacing even when a sender is replaced or fails.
        self.last_ack = None;
        self.observed_at = None;
    }

    pub(super) fn attempted(&mut self, now: Instant) {
        self.next_attempt = Some(now + ATTEMPT_SPACING);
    }

    pub(super) fn observe(&mut self, stats: QuicDatagramPathStats, now: Instant) -> Action {
        let progress = self
            .last_ack
            .is_none_or(|last| stats.acknowledgments_received != last)
            || stats.expired_outgoing_datagrams < self.last_expired;
        self.last_ack = Some(stats.acknowledgments_received);
        self.last_expired = stats.expired_outgoing_datagrams;
        if progress || stats.pto_count == 0 || stats.in_flight_bytes == 0 {
            self.observed_at = Some(now);
            self.expired_at_progress = stats.expired_outgoing_datagrams;
            return if progress && stats.pto_count == 0 {
                Action::Progress
            } else {
                Action::None
            };
        }
        if self
            .observed_at
            .is_some_and(|at| now.saturating_duration_since(at) >= STALLED_FOR)
            && stats.expired_outgoing_datagrams > self.expired_at_progress
            && self.next_attempt.is_none_or(|at| now >= at)
        {
            Action::Probe
        } else {
            Action::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stats() -> QuicDatagramPathStats {
        QuicDatagramPathStats {
            rtt_us: 60_000,
            congestion_window_bytes: 12000,
            in_flight_bytes: 12000,
            pto_count: 1,
            lost_packets: 0,
            congestion_events: 0,
            udp_sent: 30,
            udp_received: 20,
            acknowledgments_received: 20,
            expired_outgoing_datagrams: 0,
            residual_window_transmits: 0,
            event_queue_last_us: 0,
            event_queue_max_us: 0,
            event_queue_stalls: 0,
            timer_late_last_us: 0,
            timer_late_max_us: 0,
            timer_stalls: 0,
        }
    }

    #[test]
    fn requires_stalled_ack_and_actual_expiry_and_bounds_attempts() {
        let mut p = PrimaryRecovery::default();
        let t = Instant::now();
        let mut s = stats();
        assert!(matches!(p.observe(s, t), Action::None));
        assert!(matches!(
            p.observe(s, t + Duration::from_secs(1)),
            Action::None
        ));
        s.expired_outgoing_datagrams = 1;
        assert!(matches!(
            p.observe(s, t + Duration::from_secs(1)),
            Action::Probe
        ));
        p.attempted(t + Duration::from_secs(1));
        assert!(matches!(
            p.observe(s, t + Duration::from_millis(2999)),
            Action::None
        ));
        assert!(matches!(
            p.observe(s, t + Duration::from_secs(3)),
            Action::Probe
        ));
        p.attempted(t + Duration::from_secs(3));
        s.acknowledgments_received += 1;
        s.pto_count = 0;
        assert!(matches!(
            p.observe(s, t + Duration::from_millis(3100)),
            Action::Progress
        ));
        s.pto_count = 1;
        s.expired_outgoing_datagrams += 1;
        assert!(matches!(
            p.observe(s, t + Duration::from_millis(3900)),
            Action::None
        ));
        p.reset();
        assert!(matches!(
            p.observe(s, t + Duration::from_secs(4)),
            Action::None
        ));
        s.expired_outgoing_datagrams += 1;
        assert!(matches!(
            p.observe(s, t + Duration::from_millis(4800)),
            Action::None
        ));
        assert!(matches!(
            p.observe(s, t + Duration::from_secs(5)),
            Action::Probe
        ));
    }
}
