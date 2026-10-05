//! A temporary endpoint budget for new reliable writes, while its local
//! primary producer is active. Transit traffic never selects this policy.

use std::time::{Duration, Instant};
use veil_transport::{DEFAULT_RELIABLE_SEND_WINDOW_BYTES, QuicDatagramHandle};

pub(super) const ACTIVE_RELIABLE_BYTES: u64 = 1024;
// Independent congestion controllers still share the endpoint's physical path.
pub(super) const INDEPENDENT_RELIABLE_BYTES: u64 = 16 * 1024;
const IDLE_GRACE: Duration = Duration::from_secs(3);
const PRIMARY_PRESSURE_RTT: Duration = Duration::from_millis(150);
const PRESSURE_GRACE: Duration = Duration::from_secs(2);
const SECONDARY_PROBE_INTERVAL: Duration = Duration::from_millis(200);

pub(super) struct LocalReliableAdmission {
    handle: QuicDatagramHandle,
    active_until: Option<Instant>,
    active_window: Option<u64>,
    pressure_until: Option<Instant>,
    ack_pressure_until: Option<Instant>,
    last_expired: u64,
    secondary_next: Option<Instant>,
}

impl LocalReliableAdmission {
    pub(super) fn new(handle: QuicDatagramHandle) -> Self {
        Self {
            handle,
            active_until: None,
            active_window: None,
            pressure_until: None,
            ack_pressure_until: None,
            last_expired: 0,
            secondary_next: None,
        }
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
        if self.active_window != Some(window) {
            self.handle.set_reliable_send_window(window);
            self.active_window = Some(window);
        }
        self.active_until = Some(now + IDLE_GRACE);
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
        // An independent primary's missing ACK must curb lossy secondary
        // production without also shrinking the reliable parent carrying
        // session control/rekeys. Retain that path's previous window policy.
        if ack_blocked {
            self.ack_pressure_until = Some(now + PRESSURE_GRACE);
        }
        if rtt_us > PRIMARY_PRESSURE_RTT.as_micros() as u64 || expired > self.last_expired {
            self.pressure_until = Some(now + PRESSURE_GRACE);
        }
        // A retired child can be replaced by a fresh connection with zero counters.
        self.last_expired = expired;
    }

    fn pressured(&self, now: Instant) -> bool {
        self.pressure_until.is_some_and(|until| now < until)
    }

    /// Reduce only this endpoint's loss-tolerant secondary producer under
    /// primary pressure. A sparse probe permits recovery without total starvation.
    pub(super) fn allow_secondary(&mut self, local_priority: u8, now: Instant) -> bool {
        if local_priority != veil_proto::priority::BULK {
            return true;
        }
        let secondary_pressured =
            self.pressured(now) || self.ack_pressure_until.is_some_and(|until| now < until);
        if !self.active_until.is_some_and(|until| now < until) || !secondary_pressured {
            self.secondary_next = None;
            return true;
        }
        if self.secondary_next.is_some_and(|next| now < next) {
            return false;
        }
        self.secondary_next = Some(now + SECONDARY_PROBE_INTERVAL);
        true
    }

    pub(super) fn expire(&mut self, now: Instant) {
        if self.active_until.is_some_and(|until| now >= until) {
            self.restore();
        }
    }

    fn restore(&mut self) {
        if self.active_until.take().is_some() {
            self.active_window = None;
            self.pressure_until = None;
            self.ack_pressure_until = None;
            self.secondary_next = None;
            self.handle
                .set_reliable_send_window(DEFAULT_RELIABLE_SEND_WINDOW_BYTES);
        }
    }
}

impl Drop for LocalReliableAdmission {
    fn drop(&mut self) {
        self.restore();
    }
}
