//! A temporary endpoint budget for new reliable writes, while its local
//! primary producer is active. Transit traffic never selects this policy.

use std::time::{Duration, Instant};
use veil_transport::{DEFAULT_RELIABLE_SEND_WINDOW_BYTES, QuicDatagramHandle};

pub(super) const ACTIVE_RELIABLE_BYTES: u64 = 1024;
const IDLE_GRACE: Duration = Duration::from_secs(3);

pub(super) struct LocalReliableAdmission {
    handle: QuicDatagramHandle,
    active_until: Option<Instant>,
}

impl LocalReliableAdmission {
    pub(super) fn new(handle: QuicDatagramHandle) -> Self {
        Self {
            handle,
            active_until: None,
        }
    }

    pub(super) fn observe(&mut self, local_priority: u8, frame: &[u8], now: Instant) {
        if local_priority != veil_proto::priority::REALTIME
            || super::decode_realtime_lane_frame(frame).is_none()
        {
            return;
        }
        if self.active_until.is_none() {
            self.handle.set_reliable_send_window(ACTIVE_RELIABLE_BYTES);
        }
        self.active_until = Some(now + IDLE_GRACE);
    }

    pub(super) fn expire(&mut self, now: Instant) {
        if self.active_until.is_some_and(|until| now >= until) {
            self.restore();
        }
    }

    fn restore(&mut self) {
        if self.active_until.take().is_some() {
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
