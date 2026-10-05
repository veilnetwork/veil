//! Local receive stages on a generic authenticated datagram connection.
//! Opt-in diagnostics only: no scheduling, wire metadata or application parsing.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub(super) struct ReceiveWindow {
    pub datagrams: u64,
    pub fragments_pending: u64,
    pub decode_rejected: u64,
    pub ineligible: u64,
    pub dispatched: u64,
    pub rate_limited: u64,
    pub violations: u64,
    pub unexpected: u64,
    pub max_dispatch_us: u64,
}

pub(super) struct ReceiveTrace {
    // Process-local ordinal, not a pointer, exporter or remote role.
    pub id: u64,
    pub window: ReceiveWindow,
}

impl ReceiveTrace {
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self {
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            window: ReceiveWindow::default(),
        }
    }

    pub fn take(&mut self) -> ReceiveWindow {
        std::mem::take(&mut self.window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_windows_are_independent_and_reset_without_reusing_ordinals() {
        let mut a = ReceiveTrace::new();
        let b = ReceiveTrace::new();
        assert_ne!(a.id, b.id);
        a.window.datagrams = 10;
        a.window.fragments_pending = 2;
        a.window.decode_rejected = 3;
        a.window.dispatched = 5;
        a.window.rate_limited = 1;
        a.window.max_dispatch_us = 500;
        let previous = a.take();
        assert_eq!(previous.datagrams, 10);
        assert_eq!(previous.fragments_pending, 2);
        assert_eq!(previous.decode_rejected, 3);
        assert_eq!(previous.dispatched, 5);
        assert_eq!(previous.rate_limited, 1);
        assert_eq!(previous.max_dispatch_us, 500);
        assert_eq!(a.window.datagrams, 0);
        assert_eq!(a.window.max_dispatch_us, 0);
        assert_eq!(b.window.datagrams, 0);
    }
}
