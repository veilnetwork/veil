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

pub(super) struct LocalReliableAdmission {
    writes: Arc<ReliableWriteAdmission>,
    source_activity: Arc<crate::local_source_activity::LocalSourceActivity>,
    active_until: Option<Instant>,
    pressure_until: Option<Instant>,
    last_expired: u64,
}

impl LocalReliableAdmission {
    pub(super) fn new(handle: QuicDatagramHandle) -> Self {
        Self {
            writes: Arc::new(ReliableWriteAdmission::new(handle)),
            source_activity: Arc::default(),
            active_until: None,
            pressure_until: None,
            last_expired: 0,
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
    pub(super) fn observe_primary_path(&mut self, handle: &QuicDatagramHandle, now: Instant) {
        let stats = handle.path_stats();
        // RTT remains the last successful sample while ACKs stop arriving.
        // Pause competing local producers before queued primary cells expire.
        let ack_blocked = stats.pto_count > 0
            || (stats.congestion_window_bytes > 0
                && stats.in_flight_bytes >= stats.congestion_window_bytes);
        self.observe_pressure(
            stats.rtt_us,
            stats.expired_outgoing_datagrams,
            ack_blocked,
            now,
        );
    }

    fn observe_pressure(&mut self, rtt_us: u64, expired: u64, ack_blocked: bool, now: Instant) {
        // Pressure limits bulk admission and competing local lossy production.
        // The writer grants a separate bounded budget only while actually
        // writing locally authored control; bulk and transit never acquire it.
        let delayed =
            rtt_us > PRIMARY_PRESSURE_RTT.as_micros() as u64 || expired > self.last_expired;
        if ack_blocked || delayed {
            self.source_activity.note_pressure(now);
        }
        if delayed {
            self.pressure_until = Some(now + PRESSURE_GRACE);
        }
        // A retired child can be replaced by a fresh connection with zero counters.
        self.last_expired = expired;
    }

    fn pressured(&self, now: Instant) -> bool {
        self.pressure_until.is_some_and(|until| now < until)
    }

    /// Reduce this endpoint's secondary production on any neighbor under local
    /// primary pressure. All runners share one sparse recovery-probe budget.
    pub(super) fn allow_secondary(&mut self, local_priority: u8, now: Instant) -> bool {
        if !matches!(
            local_priority,
            veil_proto::priority::BULK
                | veil_proto::priority::BACKGROUND
                | veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE
        ) {
            return true;
        }
        self.source_activity.allow_secondary(now)
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
