//! A temporary endpoint budget for new reliable writes, while its local
//! primary producer is active. Transit traffic never selects this policy.

use std::time::{Duration, Instant};
use veil_transport::{DEFAULT_RELIABLE_SEND_WINDOW_BYTES, QuicDatagramHandle};

pub(super) const ACTIVE_RELIABLE_BYTES: u64 = 1024;
// A prepared independent primary never sits behind this canonical stream.
pub(super) const INDEPENDENT_RELIABLE_BYTES: u64 = 16 * 1024;
const IDLE_GRACE: Duration = Duration::from_secs(3);

pub(super) struct LocalReliableAdmission {
    handle: QuicDatagramHandle,
    active_until: Option<Instant>,
    active_window: Option<u64>,
}

impl LocalReliableAdmission {
    pub(super) fn new(handle: QuicDatagramHandle) -> Self {
        Self {
            handle,
            active_until: None,
            active_window: None,
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
        let window = if independent {
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

    pub(super) fn expire(&mut self, now: Instant) {
        if self.active_until.is_some_and(|until| now >= until) {
            self.restore();
        }
    }

    fn restore(&mut self) {
        if self.active_until.take().is_some() {
            self.active_window = None;
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
