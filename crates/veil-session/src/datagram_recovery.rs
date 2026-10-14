//! Bounded replacement of an active opaque channel whose ACK progress stopped.
//! This neither resets congestion state nor changes receiver authorization.
use std::time::{Duration, Instant};
use veil_transport::QuicDatagramPathStats;

// A PTO and actual expired datagrams are also required; ACK silence alone,
// including idle producers, cannot trigger connection churn.
const STALLED_FOR: Duration = Duration::from_millis(500);
const ATTEMPT_SPACING: Duration = Duration::from_secs(2);
pub(super) const ACTIVE_FOR: Duration = Duration::from_secs(2);

#[derive(Default)]
pub(super) struct ChannelRecovery {
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

impl ChannelRecovery {
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

/// One spare connection, shared fairly without any application/queue hint.
#[derive(Default)]
pub(super) struct RecoverySchedule {
    cursor: usize,
    next_attempt: Option<Instant>,
}

impl RecoverySchedule {
    pub(super) fn choose<const N: usize>(
        &mut self,
        eligible: [bool; N],
        replacing: bool,
        now: Instant,
    ) -> Option<usize> {
        if replacing || self.next_attempt.is_some_and(|at| now < at) {
            return None;
        }
        let selected = (0..N)
            .map(|offset| (self.cursor + offset) % N)
            .find(|&index| eligible[index])?;
        self.cursor = (selected + 1) % N;
        self.next_attempt = Some(now + ATTEMPT_SPACING);
        Some(selected)
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
            udp_sent_bytes: 0,
            udp_received_bytes: 0,
            udp_socket_sent_bytes: 0,
            acknowledgments_received: 20,
            stream_frames_sent: 0,
            stream_frames_received: 0,
            max_data_received: 0,
            max_stream_data_received: 0,
            data_blocked_sent: 0,
            stream_data_blocked_sent: 0,
            expired_outgoing_datagrams: 0,
            datagram_queue_max_us: 0,
            datagram_cwnd_blocked_max_age_us: 0,
            datagram_cwnd_blocked_window: 0,
            datagram_cwnd_blocked_inflight: 0,
            datagram_cwnd_blocked_untracked: 0,
            datagram_cwnd_blocked_payload_bytes: 0,
            datagram_cwnd_blocked_pto: 0,
            datagram_cwnd_blocked_rtt_us: 0,
            datagram_pacing_blocked_max_age_us: 0,
            datagram_pacing_max_delay_us: 0,
            datagram_amplification_blocked_max_age_us: 0,

            residual_window_transmits: 0,
            event_queue_last_us: 0,
            event_queue_max_us: 0,
            event_queue_stalls: 0,
            timer_late_last_us: 0,
            timer_late_max_us: 0,
            timer_stalls: 0,
            udp_send_wait_last_us: 0,
            udp_send_wait_max_us: 0,
            udp_send_stalls: 0,
            udp_send_pending_us: 0,
        }
    }

    #[test]
    fn requires_stalled_ack_and_actual_expiry_and_bounds_attempts() {
        let mut p = ChannelRecovery::default();
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

    #[test]
    fn all_opaque_channels_share_one_spare_and_attempt_budget_fairly() {
        let mut schedule = RecoverySchedule::default();
        let start = Instant::now();
        for turn in 0..18usize {
            let now = start + ATTEMPT_SPACING * turn as u32;
            assert_eq!(schedule.choose([true; 6], true, now), None);
            assert_eq!(schedule.choose([true; 6], false, now), Some(turn % 6));
            // A quick ACK cancellation cannot give another channel a fresh
            // session-wide handshake budget in the same interval.
            assert_eq!(
                schedule.choose([true; 6], false, now + Duration::from_millis(1)),
                None
            );
        }
        let now = start + ATTEMPT_SPACING * 18;
        assert_eq!(schedule.choose([false; 6], false, now), None);
        assert_eq!(
            schedule.choose([false, false, false, false, false, true], false, now),
            Some(5)
        );
    }
}
