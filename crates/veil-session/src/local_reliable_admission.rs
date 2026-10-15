//! A temporary endpoint budget for new reliable writes, while its local
//! primary producer is active. Transit traffic never selects this policy.

use crate::local_source_activity::{IDLE_GRACE, PRESSURE_GRACE};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use veil_transport::{DEFAULT_RELIABLE_SEND_WINDOW_BYTES, QuicDatagramHandle};
use veil_util::lock;

pub(super) const ACTIVE_RELIABLE_BYTES: u64 = 1024;
// Small bounded control writes on the parent must not inherit child pressure.
pub(super) const INDEPENDENT_RELIABLE_BYTES: u64 = 16 * 1024;
const PRIMARY_PRESSURE_RTT: Duration = Duration::from_millis(150);

#[derive(Default)]
struct PrimaryPathFeedback {
    last_expired: u64,
    last_lost: u64,
    last_congestion_events: u64,
}

impl PrimaryPathFeedback {
    fn observe(&mut self, rtt_us: u64, expired: u64, lost: u64, congestion_events: u64) -> bool {
        // Loss can grow before the smoothed RTT crosses the delay threshold.
        // Keep competing local producers restrained during that congestion,
        // rather than waiting for the primary's packets to expire as well.
        let degraded = rtt_us > PRIMARY_PRESSURE_RTT.as_micros() as u64
            || expired > self.last_expired
            || lost > self.last_lost
            || congestion_events > self.last_congestion_events;
        // Repeated historical loss must not pin the budget forever. A replaced
        // child starts fresh counters, so retain the new snapshot, not maxima.
        self.last_expired = expired;
        self.last_lost = lost;
        self.last_congestion_events = congestion_events;
        degraded
    }
}

pub(super) struct LocalReliableAdmission {
    writes: Arc<ReliableWriteAdmission>,
    source_activity: Arc<crate::local_source_activity::LocalSourceActivity>,
    active_until: Option<Instant>,
    pressure_until: Option<Instant>,
    feedback: PrimaryPathFeedback,
}

impl LocalReliableAdmission {
    pub(super) fn new(handle: QuicDatagramHandle) -> Self {
        Self {
            writes: Arc::new(ReliableWriteAdmission::new(handle)),
            source_activity: Arc::default(),
            active_until: None,
            pressure_until: None,
            feedback: PrimaryPathFeedback::default(),
        }
    }

    pub(super) fn for_source(
        handle: QuicDatagramHandle,
        source_activity: Arc<crate::local_source_activity::LocalSourceActivity>,
    ) -> Self {
        let mut admission = Self::new(handle);
        admission.source_activity = source_activity;
        admission
    }

    pub(super) fn writer_admission(&self) -> Arc<ReliableWriteAdmission> {
        Arc::clone(&self.writes)
    }

    pub(super) fn observe(
        &mut self,
        local_priority: u8,
        frame: &[u8],
        now: Instant,
        independent: bool,
    ) {
        if local_priority != veil_proto::priority::REALTIME
            || super::decode_realtime_lane_frame(frame).is_none()
        {
            return;
        }
        let window = if independent && !self.pressured(now) {
            INDEPENDENT_RELIABLE_BYTES
        } else {
            ACTIVE_RELIABLE_BYTES
        };
        self.source_activity.note(now);
        let until = now + IDLE_GRACE;
        self.writes.update(window, independent.then_some(until));
        self.active_until = Some(until);
    }

    /// Called only for the local primary's authenticated independent sender.
    /// Feedback remains local: relays receive no role, deadline or priority hint.
    pub(super) fn observe_primary_path(
        &mut self,
        handle: &QuicDatagramHandle,
        now: Instant,
    ) -> bool {
        let stats = handle.path_stats();
        // RTT remains the last successful sample while ACKs stop arriving.
        // Pause competing local producers before queued primary cells expire.
        let ack_blocked = stats.pto_count > 0
            || (stats.congestion_window_bytes > 0
                && stats.in_flight_bytes >= stats.congestion_window_bytes);
        self.observe_pressure(
            stats.rtt_us,
            stats.expired_outgoing_datagrams,
            stats.lost_packets,
            stats.congestion_events,
            ack_blocked,
            now,
        )
    }

    /// The caller checked the trusted local slot and complete primary frame.
    /// Publish ordered-path feedback without shrinking the shared parent
    /// window: the primary itself needs that window to carry its stream bytes.
    pub(super) fn observe_ordered_primary(&mut self, now: Instant) -> bool {
        self.restore();
        self.source_activity.note(now);
        self.observe_primary_path(&self.writes.handle.clone(), now)
    }

    fn observe_pressure(
        &mut self,
        rtt_us: u64,
        expired: u64,
        lost: u64,
        congestion_events: u64,
        ack_blocked: bool,
        now: Instant,
    ) -> bool {
        // Pressure limits bulk admission and competing local lossy production.
        // The writer grants a separate bounded budget only while actually
        // writing locally authored control; bulk and transit never acquire it.
        let delayed = self
            .feedback
            .observe(rtt_us, expired, lost, congestion_events);
        if ack_blocked || delayed {
            self.source_activity.note_pressure(now);
            // The parent writer must consume the same pressure observation as
            // other local producers. A low/stale RTT during blocked ACKs must
            // not leave a larger file window open while video alone is held.
            self.pressure_until = Some(now + PRESSURE_GRACE);
        }
        ack_blocked || delayed
    }

    fn pressured(&self, now: Instant) -> bool {
        self.pressure_until.is_some_and(|until| now < until)
    }

    /// Reduce this endpoint's secondary production on any neighbor under local
    /// primary pressure. All runners share one bounded recovery byte budget.
    pub(super) fn allow_secondary(
        &mut self,
        local_priority: u8,
        bytes: usize,
        now: Instant,
    ) -> bool {
        if !matches!(
            local_priority,
            veil_proto::priority::BULK
                | veil_proto::priority::BACKGROUND
                | veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE
        ) {
            return true;
        }
        self.source_activity.allow_secondary(bytes, now)
    }

    pub(super) fn expire(&mut self, now: Instant) {
        if self.active_until.is_some_and(|until| now >= until) {
            self.restore();
        }
    }

    fn restore(&mut self) {
        if self.active_until.take().is_some() {
            self.pressure_until = None;
            self.writes.update(DEFAULT_RELIABLE_SEND_WINDOW_BYTES, None);
        }
    }
}

impl Drop for LocalReliableAdmission {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Endpoint-local write metadata never changes a frame or travels over QUIC.
/// Holding a control lease through every partial write prevents concurrent
/// primary observations from shrinking its window before the blob is admitted.
pub(super) struct ReliableWriteAdmission {
    handle: QuicDatagramHandle,
    state: Mutex<WriteState>,
}

struct WriteState {
    bulk_window: u64,
    independent_until: Option<Instant>,
    control_writes: usize,
    applied_window: u64,
}

impl ReliableWriteAdmission {
    fn new(handle: QuicDatagramHandle) -> Self {
        Self {
            handle,
            state: Mutex::new(WriteState {
                bulk_window: DEFAULT_RELIABLE_SEND_WINDOW_BYTES,
                independent_until: None,
                control_writes: 0,
                applied_window: DEFAULT_RELIABLE_SEND_WINDOW_BYTES,
            }),
        }
    }

    fn apply(&self, state: &mut WriteState) {
        let window = if state.control_writes > 0 {
            state.bulk_window.max(INDEPENDENT_RELIABLE_BYTES)
        } else {
            state.bulk_window
        };
        if state.applied_window != window {
            self.handle.set_reliable_send_window(window);
            state.applied_window = window;
        }
    }

    fn update(&self, window: u64, until: Option<Instant>) {
        let mut state = lock!(&self.state);
        state.bulk_window = window;
        state.independent_until = until;
        self.apply(&mut state);
    }

    pub(super) fn begin_control(self: &Arc<Self>) -> Option<ControlWrite> {
        let mut state = lock!(&self.state);
        if !state
            .independent_until
            .is_some_and(|until| Instant::now() < until)
        {
            return None;
        }
        state.control_writes += 1;
        self.apply(&mut state);
        Some(ControlWrite(Arc::clone(self)))
    }
}

pub(super) struct ControlWrite(Arc<ReliableWriteAdmission>);

impl Drop for ControlWrite {
    fn drop(&mut self) {
        let mut state = lock!(&self.0.state);
        state.control_writes -= 1;
        self.0.apply(&mut state);
    }
}

#[cfg(test)]
mod feedback_tests {
    use super::*;

    #[test]
    fn new_primary_loss_and_congestion_are_pressure_even_with_low_rtt() {
        let mut feedback = PrimaryPathFeedback::default();
        assert!(!feedback.observe(10_000, 0, 0, 0));
        assert!(feedback.observe(10_000, 0, 1, 0));
        assert!(!feedback.observe(10_000, 0, 1, 0));
        assert!(feedback.observe(10_000, 0, 1, 1));
        assert!(!feedback.observe(10_000, 0, 1, 1));
        // A retired connection's counters are not a high-water mark for the
        // fresh path. Its first newly observed loss must still restrain video.
        assert!(!feedback.observe(10_000, 0, 0, 0));
        assert!(feedback.observe(10_000, 0, 1, 0));
    }

    #[test]
    fn historical_loss_does_not_extend_shared_secondary_pressure() {
        let mut feedback = PrimaryPathFeedback::default();
        let activity = crate::local_source_activity::LocalSourceActivity::default();
        let now = Instant::now();
        activity.note(now);
        if feedback.observe(10_000, 0, 1, 0) {
            activity.note_pressure(now);
        }
        assert!(activity.allow_secondary(crate::local_source_activity::LOSSY_SECONDARY_BYTES, now)); // One sparse recovery probe.
        assert!(!activity.allow_secondary(
            crate::local_source_activity::LOSSY_SECONDARY_BYTES,
            now + Duration::from_millis(1)
        ));
        let renewed = now + PRESSURE_GRACE;
        activity.note(renewed);
        if feedback.observe(10_000, 0, 1, 0) {
            activity.note_pressure(renewed);
        }
        assert!(
            activity.allow_secondary(crate::local_source_activity::LOSSY_SECONDARY_BYTES, renewed)
        );
        assert!(activity.allow_secondary(
            crate::local_source_activity::LOSSY_SECONDARY_BYTES,
            renewed + Duration::from_millis(1)
        ));
    }
}
