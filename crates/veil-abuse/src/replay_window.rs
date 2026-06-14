//! Replay attack protection via a sliding nonce window.
//!
//! `ReplayWindow` tracks recently seen `request_id` values from a single peer.
//! A duplicate `request_id` within the window is rejected. The window evicts
//! the oldest entries when it exceeds `window_size`.
//!
//! ## Security trade-off: choosing `window_size`
//!
//! Once a nonce is evicted from the window it is forgotten, so an attacker can
//! replay a packet whose nonce has been evicted. The window is therefore a
//! **time-bounded** guarantee, not a permanent one:
//!
//! * At *P* packets/second a window of *W* nonces covers ≈ *W/P* seconds.
//! * Example: `window_size = 1024` at 100 pkt/s → ~10 s replay protection.
//!
//! **Minimum recommended value**: set `window_size` to at least the number of
//! packets that can arrive in the expected worst-case network delay (e.g. 2 ×
//! RTT × peak_pps). Values below ~256 are generally unsafe for any non-trivial
//! traffic rate.

use std::collections::{BTreeSet, VecDeque};

// ── ReplayWindow ──────────────────────────────────────────────────────────────

/// Per-peer sliding nonce window.
///
/// `window_size` controls how many unique nonces are remembered. When a new
/// nonce is accepted and the window is full, the oldest accepted nonce is
/// evicted.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    seen: BTreeSet<u64>,
    order: VecDeque<u64>,
    window_size: usize,
}

impl ReplayWindow {
    pub fn new(window_size: usize) -> Self {
        let window_size = window_size.max(1);
        Self {
            seen: BTreeSet::new(),
            order: VecDeque::new(),
            window_size,
        }
    }

    /// Attempt to accept a `request_id`.
    ///
    /// Returns `true` if the nonce is fresh (first time seen within the window).
    /// Returns `false` if the nonce was already seen (replay detected).
    ///
    /// When a fresh nonce fills the window, the oldest nonce is evicted.
    pub fn check_and_insert(&mut self, request_id: u64) -> bool {
        if self.seen.contains(&request_id) {
            return false;
        }
        // Evict oldest if at capacity
        if self.order.len() >= self.window_size
            && let Some(evicted) = self.order.pop_front()
        {
            self.seen.remove(&evicted);
        }
        self.seen.insert(request_id);
        self.order.push_back(request_id);
        true
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_nonce_accepted() {
        let mut w = ReplayWindow::new(10);
        assert!(w.check_and_insert(42));
    }

    #[test]
    fn duplicate_nonce_rejected() {
        let mut w = ReplayWindow::new(10);
        assert!(w.check_and_insert(7));
        assert!(!w.check_and_insert(7));
    }

    #[test]
    fn window_evicts_oldest() {
        let mut w = ReplayWindow::new(3);
        w.check_and_insert(1);
        w.check_and_insert(2);
        w.check_and_insert(3);
        assert_eq!(w.len(), 3);

        // Inserting 4 evicts the oldest (1). Window: {2, 3, 4}.
        assert!(w.check_and_insert(4));
        assert_eq!(w.len(), 3);

        // Nonce 1 was evicted — it is accepted (and evicts 2). Window: {3, 4, 1}.
        assert!(w.check_and_insert(1));

        // Nonces 3 and 4 are still in window — duplicates rejected.
        assert!(!w.check_and_insert(3));
        assert!(!w.check_and_insert(4));

        // Nonce 2 was evicted — accepted again.
        assert!(w.check_and_insert(2));
    }

    #[test]
    fn window_size_of_one() {
        let mut w = ReplayWindow::new(1);
        assert!(w.check_and_insert(10));
        assert!(!w.check_and_insert(10));
        assert!(w.check_and_insert(11)); // 10 evicted
        assert!(w.check_and_insert(10)); // 11 evicted
    }

    #[test]
    fn many_sequential_nonces() {
        let mut w = ReplayWindow::new(100);
        for i in 0..200u64 {
            assert!(w.check_and_insert(i), "nonce {i} should be fresh");
        }
        assert_eq!(w.len(), 100);
    }
}
