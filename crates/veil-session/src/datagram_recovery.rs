//! Bounded replacement of an active opaque channel whose delivery stopped.
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
    last_delivery: Option<DeliveryCounter>,
    last_expired: u64,
    observed_at: Option<Instant>,
    expired_at_progress: u64,
    next_attempt: Option<Instant>,
}

#[derive(Clone, Copy)]
enum DeliveryCounter {
    Confirmed {
        epoch: u64,
        bytes: u64,
        packets: u64,
    },
    // Fallback only for transports without confirmed-delivery observations.
    AckFrames(u64),
}

impl DeliveryCounter {
    /// (new delivery, baseline changed). A reset or route change establishes a
    /// fresh baseline; it does not prove that a stalled connection recovered.
    fn compare(self, previous: Option<Self>) -> (bool, bool) {
        match (self, previous) {
            (
                Self::Confirmed {
                    epoch,
                    bytes,
                    packets,
                },
                Some(Self::Confirmed {
                    epoch: old_epoch,
                    bytes: old_bytes,
                    packets: old_packets,
                }),
            ) if epoch == old_epoch && bytes >= old_bytes && packets >= old_packets => {
                (bytes > old_bytes || packets > old_packets, false)
            }
            (Self::AckFrames(acks), Some(Self::AckFrames(old))) if acks >= old => {
                (acks > old, false)
            }
            _ => (false, true),
        }
    }
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
        self.last_delivery = None;
        self.observed_at = None;
    }

    pub(super) fn attempted(&mut self, now: Instant) {
        self.next_attempt = Some(now + ATTEMPT_SPACING);
    }

    pub(super) fn observe(&mut self, stats: QuicDatagramPathStats, now: Instant) -> Action {
        // ACK-frame counts include duplicate ranges which free no flight. When
        // available, use newly wire-confirmed current-route Data packet bytes /
        // packets, not ACK arrival, to reset the stall or cancel a replacement.
        // This is transport progress, not proof of application/media delivery.
        let delivery = stats.confirmed_delivery.map_or(
            DeliveryCounter::AckFrames(stats.acknowledgments_received),
            |d| DeliveryCounter::Confirmed {
                epoch: d.epoch,
                bytes: d.bytes,
                packets: d.packets,
            },
        );
        let (progress, rebased) = delivery.compare(self.last_delivery);
        let rebased = rebased || stats.expired_outgoing_datagrams < self.last_expired;
        self.last_delivery = Some(delivery);
        self.last_expired = stats.expired_outgoing_datagrams;
        if rebased || progress || stats.pto_count == 0 || stats.in_flight_bytes == 0 {
            self.observed_at = Some(now);
            self.expired_at_progress = stats.expired_outgoing_datagrams;
            return if !rebased
                && progress
                && stats.pto_count == 0
                && stats
                    .confirmed_delivery
                    .is_none_or(|d| !d.validation_pending)
            {
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
            confirmed_delivery: None,
            rtt_us: 60_000,
            congestion_window_bytes: 12000,
            in_flight_bytes: 12000,
            stream_retained_bytes: 0,
            stream_send_window_bytes: 0,
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

    fn with_delivery(now: Instant) -> QuicDatagramPathStats {
        let mut s = stats();
        s.confirmed_delivery = Some(veil_transport::quic::QuicConfirmedDelivery {
            epoch: 1,
            validation_pending: false,
            bytes: 2400,
            packets: 2,
            first_sent: Some(now),
            last_sent: Some(now),
            last_ack: Some(now),
            observed_at: now,
        });
        s
    }

    #[test]
    fn duplicate_wire_acks_do_not_postpone_stalled_delivery_probe() {
        let mut p = ChannelRecovery::default();
        let t = Instant::now();
        let mut s = with_delivery(t);
        assert!(matches!(p.observe(s, t), Action::None));
        // FrameStats counts every ACK frame, including a repeated range that
        // removes no retained Data packet from flight. No delivery was proved.
        for tick in 1..5 {
            s.acknowledgments_received += 1;
            s.expired_outgoing_datagrams += 1;
            assert!(matches!(
                p.observe(s, t + Duration::from_millis(100 * tick)),
                Action::None
            ));
        }
        s.acknowledgments_received += 1;
        s.expired_outgoing_datagrams += 1;
        assert!(matches!(p.observe(s, t + STALLED_FOR), Action::Probe));
    }

    #[test]
    fn duplicate_ack_cannot_cancel_pending_replacement() {
        let mut p = ChannelRecovery::default();
        let t = Instant::now();
        let mut s = with_delivery(t);
        assert!(matches!(p.observe(s, t), Action::None));
        s.acknowledgments_received += 1;
        s.pto_count = 0;
        assert!(matches!(
            p.observe(s, t + Duration::from_secs(1)),
            Action::None
        ));
        let d = s.confirmed_delivery.as_mut().unwrap();
        d.bytes += 1200;
        d.packets += 1;
        assert!(matches!(
            p.observe(s, t + Duration::from_secs(2)),
            Action::Progress
        ));
    }

    #[test]
    fn new_route_and_unvalidated_delivery_do_not_cancel_replacement() {
        let mut p = ChannelRecovery::default();
        let t = Instant::now();
        let mut s = with_delivery(t);
        assert!(matches!(p.observe(s, t), Action::None));
        s.pto_count = 0;
        s.acknowledgments_received += 1;
        let d = s.confirmed_delivery.as_mut().unwrap();
        d.epoch += 1;
        d.bytes = 0;
        d.packets = 0;
        assert!(matches!(
            p.observe(s, t + Duration::from_secs(1)),
            Action::None
        ));
        s.acknowledgments_received += 1;
        let d = s.confirmed_delivery.as_mut().unwrap();
        d.bytes = 1200;
        d.packets = 1;
        d.validation_pending = true;
        assert!(matches!(
            p.observe(s, t + Duration::from_secs(2)),
            Action::None
        ));
    }

    #[test]
    fn confirmed_progress_preserves_retry_spacing_and_reset_baselines() {
        let mut p = ChannelRecovery::default();
        let t = Instant::now();
        let mut s = with_delivery(t);
        assert!(matches!(p.observe(s, t), Action::None));
        s.expired_outgoing_datagrams = 1;
        assert!(matches!(p.observe(s, t + STALLED_FOR), Action::Probe));
        p.attempted(t + STALLED_FOR);
        // Confirmation does not have to arrive in a new ACK frame between
        // snapshots to be authoritative; raw frame counts are not the oracle.
        s.confirmed_delivery.as_mut().unwrap().bytes += 1200;
        s.confirmed_delivery.as_mut().unwrap().packets += 1;
        s.pto_count = 0;
        assert!(matches!(
            p.observe(s, t + Duration::from_secs(1)),
            Action::Progress
        ));
        p.reset();
        s.pto_count = 1;
        assert!(matches!(
            p.observe(s, t + Duration::from_millis(1200)),
            Action::None
        ));
        s.expired_outgoing_datagrams += 1;
        assert!(matches!(
            p.observe(s, t + Duration::from_millis(1800)),
            Action::None
        ));
        assert!(matches!(
            p.observe(s, t + Duration::from_millis(2500)),
            Action::Probe
        ));
    }

    #[test]
    fn counter_rollbacks_and_observation_changes_only_rebase() {
        let t = Instant::now();
        let mut initial = with_delivery(t);
        initial.pto_count = 0;
        let mut rollback_bytes = initial;
        rollback_bytes.confirmed_delivery.as_mut().unwrap().bytes -= 1;
        let mut rollback_packets = initial;
        rollback_packets
            .confirmed_delivery
            .as_mut()
            .unwrap()
            .packets -= 1;
        let mut legacy = initial;
        legacy.confirmed_delivery = None;
        for (before, after) in [
            (initial, rollback_bytes),
            (initial, rollback_packets),
            (initial, legacy),
            (legacy, initial),
        ] {
            let mut p = ChannelRecovery::default();
            assert!(matches!(p.observe(before, t), Action::None));
            assert!(matches!(
                p.observe(after, t + Duration::from_secs(1)),
                Action::None
            ));
        }
    }

    #[test]
    fn expiry_without_loss_or_flight_does_not_start_replacement() {
        for (pto_count, in_flight_bytes) in [(0, 12000), (1, 0)] {
            let mut p = ChannelRecovery::default();
            let t = Instant::now();
            let mut s = with_delivery(t);
            s.pto_count = pto_count;
            s.in_flight_bytes = in_flight_bytes;
            assert!(matches!(p.observe(s, t), Action::None));
            for tick in 1..10 {
                s.expired_outgoing_datagrams += 1;
                assert!(matches!(
                    p.observe(s, t + Duration::from_secs(tick)),
                    Action::None
                ));
            }
        }
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
