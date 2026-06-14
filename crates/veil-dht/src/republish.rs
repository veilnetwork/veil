//! Staggered DHT republish scheduler.
//!
//! The naive approach — republish all stored keys every N seconds — creates a
//! network spike when many keys expire simultaneously. `RepublishScheduler`
//! assigns each key an individual next-due time derived from a hash of the key
//! itself, spreading load evenly across the republish interval.
//!
//! # Algorithm
//!
//! ```text
//! jitter(key) = FNV-1a(key) % (interval / 4) [in seconds]
//! next_due(key) = last_published + interval + jitter
//! first_due(key) = now + jitter (no history yet)
//! ```
//!
//! At `vivaldi_weight = 0.0` (i.e. when every call is a first-time call) the
//! first publication is staggered by up to `interval / 4` seconds from `now`
//! preventing a thundering-herd burst at startup.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

// ── FNV-1a hash ───────────────────────────────────────────────────────────────

/// Compute a 64-bit FNV-1a hash of a 32-byte key.
///
/// Used as a deterministic, fast, dependency-free jitter seed so that the same
/// key always maps to the same offset within a republish interval on a given
/// node restart — preventing accidental synchronisation with other nodes that
/// use different key sets.
fn fnv1a(key: &[u8; 32]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for &byte in key {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

// ── RepublishScheduler ────────────────────────────────────────────────────────

/// Per-key republish scheduler with built-in jitter.
///
/// Maintains a `HashMap<key, next_due_instant>` so each key is published
/// independently at its own scheduled time.
#[derive(Debug, Default)]
pub struct RepublishScheduler {
    schedule: HashMap<[u8; 32], Instant>,
}

impl RepublishScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `key` is due for republication right now.
    ///
    /// On the first call for a given key (no history), the due time is set to
    /// `now + jitter` so keys newly added to the store are not all published
    /// in the same tick. This means the first call always returns `false` —
    /// the key will be published in at most `interval / 4` seconds.
    ///
    /// When `true` is returned the next due time is updated to
    /// `now + interval + jitter`, distributing future publications evenly.
    pub fn next_due(&mut self, key: [u8; 32], interval: Duration) -> bool {
        let now = Instant::now();
        let jitter = self.jitter_for(key, interval);

        match self.schedule.get_mut(&key) {
            Some(due) if now >= *due => {
                // Due — reschedule and signal the caller.
                *due = now + interval + jitter;
                true
            }
            Some(_) => false, // not yet due
            None => {
                // First time — schedule without publishing immediately.
                self.schedule.insert(key, now + jitter);
                false
            }
        }
    }

    /// Remove a key from the schedule (e.g. after it is deleted from the store).
    pub fn remove(&mut self, key: &[u8; 32]) {
        self.schedule.remove(key);
    }

    /// drop every scheduled key that
    /// is NOT in `live_keys`. Caller passes the current set of
    /// keys present in the underlying store; this caps the
    /// scheduler's memory at O(live_keys) rather than
    /// O(keys_seen_lifetime).
    pub fn retain_keys(&mut self, live_keys: &std::collections::HashSet<[u8; 32]>) {
        self.schedule.retain(|k, _| live_keys.contains(k));
    }

    /// Number of keys currently tracked.
    pub fn len(&self) -> usize {
        self.schedule.len()
    }

    pub fn is_empty(&self) -> bool {
        self.schedule.is_empty()
    }

    // ── helpers ───────────────────────────────────────────────────────────

    fn jitter_for(&self, key: [u8; 32], interval: Duration) -> Duration {
        let quarter = interval / 4;
        if quarter.is_zero() {
            return Duration::ZERO;
        }
        let quarter_secs = quarter.as_secs().max(1);
        let offset_secs = fnv1a(&key) % quarter_secs;
        Duration::from_secs(offset_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_never_returns_true() {
        let mut sched = RepublishScheduler::new();
        let key = [0x01u8; 32];
        let interval = Duration::from_secs(1800);
        // First call: key has no history — should not publish yet.
        assert!(
            !sched.next_due(key, interval),
            "first call must not trigger immediate publish"
        );
    }

    #[test]
    fn returns_true_after_due_time() {
        let mut sched = RepublishScheduler::new();
        let key = [0x02u8; 32];
        // Use a very short interval so jitter is tiny.
        let interval = Duration::from_millis(4);
        // Register the key.
        sched.next_due(key, interval);
        // Manually set the due time to the past.
        *sched.schedule.get_mut(&key).unwrap() = Instant::now() - Duration::from_millis(1);
        assert!(
            sched.next_due(key, interval),
            "should return true when past due time"
        );
    }

    #[test]
    fn reschedules_after_publish() {
        let mut sched = RepublishScheduler::new();
        let key = [0x03u8; 32];
        let interval = Duration::from_millis(4);
        sched.next_due(key, interval);
        // Force due.
        *sched.schedule.get_mut(&key).unwrap() = Instant::now() - Duration::from_millis(1);
        assert!(sched.next_due(key, interval));
        // Next due should now be in the future (interval + jitter away).
        assert!(
            !sched.next_due(key, interval),
            "should not be due again immediately after publish"
        );
    }

    #[test]
    fn different_keys_get_different_jitter() {
        let sched = RepublishScheduler::new();
        let interval = Duration::from_secs(1800);
        // Two distinct keys should (with overwhelming probability) have different jitters.
        let j1 = sched.jitter_for([0x01u8; 32], interval);
        let j2 = sched.jitter_for([0x02u8; 32], interval);
        // Same key must always give the same jitter (deterministic).
        let j1b = sched.jitter_for([0x01u8; 32], interval);
        assert_eq!(j1, j1b, "jitter must be deterministic for same key");
        // Different keys will almost certainly differ.
        assert_ne!(j1, j2, "different keys should get different jitter offsets");
    }

    #[test]
    fn remove_clears_schedule() {
        let mut sched = RepublishScheduler::new();
        let key = [0x04u8; 32];
        sched.next_due(key, Duration::from_secs(60));
        assert_eq!(sched.len(), 1);
        sched.remove(&key);
        assert!(sched.is_empty());
    }

    /// `retain_keys` keeps live entries
    /// and drops the rest, capping memory growth as the underlying
    /// store evicts old keys.
    #[test]
    fn phase647_dht_med1_retain_keys_drops_dead_entries() {
        let mut sched = RepublishScheduler::new();
        let interval = Duration::from_secs(60);
        sched.next_due([0x01u8; 32], interval);
        sched.next_due([0x02u8; 32], interval);
        sched.next_due([0x03u8; 32], interval);
        assert_eq!(sched.len(), 3);
        let live: std::collections::HashSet<[u8; 32]> =
            [[0x01u8; 32], [0x03u8; 32]].into_iter().collect();
        sched.retain_keys(&live);
        assert_eq!(
            sched.len(),
            2,
            "retain_keys must drop entries whose key is not in `live`"
        );
    }
}
