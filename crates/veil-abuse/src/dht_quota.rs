//! Per-peer DHT operation quota with a true sliding window.
//!
//! Limits how many STORE and FIND_NODE frames a single peer may send within
//! a rolling time window.
//!
//! **Why sliding window?** The previous reset-based design (count + window_start)
//! allowed a 2× burst at window boundaries: `max_per_window` operations just before
//! the window expires, then another `max_per_window` immediately after the reset.
//! A `VecDeque<Instant>` per peer records each operation's timestamp; on each
//! `allow` call, entries older than `window` are drained first, so the effective
//! limit is always `max_per_window` operations in any contiguous `window`-sized
//! interval.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

// ── DhtQuota ──────────────────────────────────────────────────────────────────

/// Number of `allow` calls between automatic `evict_stale` sweeps.
const EVICT_INTERVAL: u32 = 1_000;

/// Per-peer DHT operation counter with sliding-window rate limiting.
#[derive(Debug, Clone)]
pub struct DhtQuota {
    /// peer_id → ring buffer of recent operation timestamps within the window.
    entries: HashMap<[u8; 32], VecDeque<Instant>>,
    /// Maximum allowed operations per peer in any contiguous `window` interval.
    max_per_window: u32,
    window: Duration,
    /// Counts `allow` calls since the last `evict_stale` sweep.
    calls_since_evict: u32,
}

impl DhtQuota {
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        let max_per_window = max_per_window.max(1);
        Self {
            entries: HashMap::new(),
            max_per_window,
            window,
            calls_since_evict: 0,
        }
    }

    /// Try to consume one operation slot for `peer`.
    ///
    /// Returns `true` if allowed (timestamp recorded), `false` if the sliding
    /// window already contains `max_per_window` operations.
    ///
    /// Automatically evicts stale entries every `EVICT_INTERVAL` calls so the
    /// `entries` map does not grow unboundedly with distinct peer IDs.
    pub fn allow(&mut self, peer: [u8; 32]) -> bool {
        let now = Instant::now();
        self.calls_since_evict += 1;
        if self.calls_since_evict >= EVICT_INTERVAL {
            self.evict_stale(now);
            self.calls_since_evict = 0;
        }
        let window = self.window;
        let max = self.max_per_window;
        // Cap distinct peer entries to prevent Sybil-rotation memory growth.
        if !self.entries.contains_key(&peer)
            && self.entries.len() >= veil_proto::budget::MAX_PER_PEER_LIMITER_SIZE
        {
            self.evict_stale(now);
            if self.entries.len() >= veil_proto::budget::MAX_PER_PEER_LIMITER_SIZE {
                return false; // at cap even after eviction — reject newcomer
            }
        }
        let deque = self.entries.entry(peer).or_default();
        // Drain timestamps older than the sliding window.
        while deque
            .front()
            .is_some_and(|t| now.duration_since(*t) >= window)
        {
            deque.pop_front();
        }
        if deque.len() >= max as usize {
            return false;
        }
        deque.push_back(now);
        true
    }

    /// Remove entries with no recent activity (empty deques) to prevent
    /// unbounded growth when distinct peer IDs accumulate over time.
    pub fn evict_stale(&mut self, now: Instant) {
        let window = self.window;
        self.entries.retain(|_, deque| {
            // Drain expired timestamps first.
            while deque
                .front()
                .is_some_and(|t| now.duration_since(*t) >= window)
            {
                deque.pop_front();
            }
            !deque.is_empty()
        });
    }

    /// Number of currently tracked peers.
    pub fn peer_count(&self) -> usize {
        self.entries.len()
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_up_to_limit() {
        let mut q = DhtQuota::new(3, Duration::from_secs(60));
        let peer = [1u8; 32];
        assert!(q.allow(peer));
        assert!(q.allow(peer));
        assert!(q.allow(peer));
        assert!(!q.allow(peer)); // quota exceeded
    }

    #[test]
    fn different_peers_independent() {
        let mut q = DhtQuota::new(1, Duration::from_secs(60));
        assert!(q.allow([1u8; 32]));
        assert!(!q.allow([1u8; 32])); // first peer at limit
        assert!(q.allow([2u8; 32])); // second peer gets own quota
    }

    #[test]
    fn window_expiry_resets_count() {
        let mut q = DhtQuota::new(2, Duration::from_millis(100));
        let peer = [3u8; 32];
        assert!(q.allow(peer));
        assert!(q.allow(peer));
        assert!(!q.allow(peer)); // at limit
        std::thread::sleep(Duration::from_millis(110));
        // Window has expired — sliding window drains old timestamps
        assert!(q.allow(peer));
    }

    #[test]
    fn evict_stale_removes_old_entries() {
        let mut q = DhtQuota::new(5, Duration::from_millis(50));
        q.allow([4u8; 32]);
        assert_eq!(q.peer_count(), 1);
        std::thread::sleep(Duration::from_millis(60));
        q.evict_stale(Instant::now());
        assert_eq!(q.peer_count(), 0);
    }

    /// Sliding window must NOT allow 2× burst at the window boundary.
    /// With reset-based design: max ops just before expiry + max ops just after = 2×.
    /// With sliding window: the old timestamps are drained individually, so only
    /// `max_per_window` ops are permitted in any contiguous interval.
    #[test]
    fn no_double_burst_at_window_boundary() {
        let mut q = DhtQuota::new(3, Duration::from_millis(50));
        let peer = [5u8; 32];
        // Consume full quota at t=0.
        assert!(q.allow(peer));
        assert!(q.allow(peer));
        assert!(q.allow(peer));
        assert!(!q.allow(peer)); // blocked

        // Wait just past the window so all 3 timestamps expire.
        std::thread::sleep(Duration::from_millis(55));

        // Now we can send 3 more — but NOT 6 (the old 2× burst).
        assert!(q.allow(peer));
        assert!(q.allow(peer));
        assert!(q.allow(peer));
        assert!(!q.allow(peer)); // still capped at 3, not 6
    }
}
