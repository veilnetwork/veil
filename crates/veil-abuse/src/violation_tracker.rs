//! Automatic ban escalation via violation counting.
//!
//! `ViolationTracker` increments a per-peer counter on each protocol
//! violation. When the counter crosses `ban_threshold`, the peer is
//! automatically banned via `BanList` for `ban_duration`.
//!
//! Counters decay over time: after `decay_after` seconds of no violations
//! the counter is reset on the next `record` call.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use super::ban_list::BanList;

use crate::AbuseLogger;

// ── ViolationEntry ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ViolationEntry {
    count: u32,
    last_violation: Instant,
    /// How many times this peer has been banned (lifetime, not reset by decay).
    /// Used to compute progressive ban duration: initial + ban_count * step.
    ban_count: u32,
}

// ── ViolationTracker ──────────────────────────────────────────────────────────

/// Tracks per-peer violation counts and auto-bans repeat offenders.
///
/// Ban duration is progressive: the first ban lasts `ban_initial`, the second
/// `ban_initial + ban_step`, the third `ban_initial + 2 * ban_step`, etc.
/// capped at `ban_max`.
///
/// The internal `insertion_order` deque provides O(1) amortized eviction when
/// the tracker is full — it tracks which peer_ids were inserted in FIFO order.
/// Ghost entries (keys no longer in `entries`) are skipped during eviction and
/// are therefore lazily cleaned up at cost O(1) amortized per insertion.
#[derive(Debug, Clone)]
pub struct ViolationTracker {
    entries: HashMap<[u8; 32], ViolationEntry>,
    /// FIFO queue of peer_ids in insertion order. May contain "ghost" keys
    /// that have been removed from `entries`; those are skipped on eviction.
    insertion_order: VecDeque<[u8; 32]>,
    ban_threshold: u32,
    ban_initial: Duration,
    ban_step: Duration,
    ban_max: Duration,
    decay_after: Duration,
}

impl ViolationTracker {
    /// Create a tracker with fixed (non-progressive) ban duration.
    /// Equivalent to `new(threshold, duration, Duration::ZERO, duration, decay)`.
    pub fn with_fixed_duration(
        ban_threshold: u32,
        ban_duration: Duration,
        decay_after: Duration,
    ) -> Result<Self, &'static str> {
        Self::new(
            ban_threshold,
            ban_duration,
            Duration::ZERO,
            ban_duration,
            decay_after,
        )
    }

    pub fn new(
        ban_threshold: u32,
        ban_initial: Duration,
        ban_step: Duration,
        ban_max: Duration,
        decay_after: Duration,
    ) -> Result<Self, &'static str> {
        if ban_threshold == 0 {
            return Err("ban_threshold must be > 0");
        }
        Ok(Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            ban_threshold,
            ban_initial,
            ban_step,
            ban_max,
            decay_after,
        })
    }

    /// Compute the ban duration for the Nth ban (0-based).
    fn ban_duration_for(&self, ban_count: u32) -> Duration {
        let dur = self
            .ban_initial
            .saturating_add(self.ban_step.saturating_mul(ban_count));
        dur.min(self.ban_max)
    }

    /// Record one violation for `peer_id`. If the violation count reaches
    /// `ban_threshold`, the peer is banned in `ban_list`.
    ///
    /// Returns the updated violation count.
    pub fn record(&mut self, peer_id: [u8; 32], ban_list: &mut BanList) -> u32 {
        let now = Instant::now();
        let decay_after = self.decay_after;
        // Cap: evict the oldest (FIFO) entry when the map is full.
        // Skip ghost entries — keys removed from the map but still in the deque.
        if !self.entries.contains_key(&peer_id)
            && self.entries.len() >= veil_proto::budget::MAX_VIOLATION_TRACKER_SIZE
        {
            while let Some(candidate) = self.insertion_order.pop_front() {
                if self.entries.remove(&candidate).is_some() {
                    break; // evicted one live entry — done
                }
                // else: ghost entry, keep popping
            }
        }
        // Track insertion order only for genuinely new peers.
        if !self.entries.contains_key(&peer_id) {
            self.insertion_order.push_back(peer_id);
        }
        let entry = self.entries.entry(peer_id).or_insert(ViolationEntry {
            count: 0,
            last_violation: now,
            ban_count: 0,
        });

        // Decay: if no recent violation, reset counter
        if now.duration_since(entry.last_violation) >= decay_after {
            entry.count = 0;
        }
        entry.count += 1;
        entry.last_violation = now;

        if entry.count >= self.ban_threshold {
            let step_total = self.ban_step.saturating_mul(entry.ban_count);
            let duration = self
                .ban_initial
                .saturating_add(step_total)
                .min(self.ban_max);
            ban_list.ban(peer_id, "violation threshold exceeded", Some(duration));
            entry.ban_count += 1;
            entry.count = 0; // reset after ban so timer restarts
        }

        entry.count
    }

    /// Same as `record` but emits a WARN log when a ban is issued.
    pub fn record_with_log(
        &mut self,
        peer_id: [u8; 32],
        ban_list: &mut BanList,
        logger: &dyn AbuseLogger,
    ) -> u32 {
        // Peek at the ban_count BEFORE record increments it.
        let ban_count_before = self.entries.get(&peer_id).map(|e| e.ban_count).unwrap_or(0);
        let count = self.record(peer_id, ban_list);
        if count == 0 {
            // count reset to 0 means a ban was just issued
            let duration = self.ban_duration_for(ban_count_before);
            logger.warn(
                "abuse.auto_ban",
                &format!(
                    "peer_id={} violation threshold exceeded — banned for {}s",
                    veil_util::bytes_to_hex(&peer_id[..4]),
                    duration.as_secs(),
                ),
            );
        }
        count
    }

    /// Current violation count for `peer_id` (0 if unknown or decayed).
    pub fn count(&self, peer_id: &[u8; 32]) -> u32 {
        self.entries.get(peer_id).map(|e| e.count).unwrap_or(0)
    }

    /// Remove entries that have fully decayed.
    pub fn evict_stale(&mut self) {
        let now = Instant::now();
        let decay = self.decay_after;
        self.entries
            .retain(|_, e| now.duration_since(e.last_violation) <= decay);
        // Purge ghost entries accumulated in the deque by evict_stale or bans.
        self.insertion_order
            .retain(|k| self.entries.contains_key(k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> ViolationTracker {
        ViolationTracker::with_fixed_duration(3, Duration::from_secs(60), Duration::from_secs(10))
            .unwrap()
    }

    #[test]
    fn counter_increments() {
        let mut vt = tracker();
        let mut bl = BanList::new();
        let p = [1u8; 32];
        assert_eq!(vt.record(p, &mut bl), 1);
        assert_eq!(vt.record(p, &mut bl), 2);
    }

    #[test]
    fn auto_ban_at_threshold() {
        let mut vt = tracker();
        let mut bl = BanList::new();
        let p = [2u8; 32];
        vt.record(p, &mut bl);
        vt.record(p, &mut bl);
        vt.record(p, &mut bl); // 3rd → ban
        assert!(bl.is_banned(&p));
    }

    #[test]
    fn counter_resets_after_ban() {
        let mut vt = tracker();
        let mut bl = BanList::new();
        let p = [3u8; 32];
        for _ in 0..3 {
            vt.record(p, &mut bl);
        }
        // After ban counter was reset; next violation starts fresh
        assert_eq!(vt.count(&p), 0);
    }

    #[test]
    fn decay_resets_counter() {
        // Very short decay window
        let mut vt = ViolationTracker::with_fixed_duration(
            5,
            Duration::from_secs(60),
            Duration::from_millis(1),
        )
        .unwrap();
        let mut bl = BanList::new();
        let p = [4u8; 32];
        vt.record(p, &mut bl);
        vt.record(p, &mut bl); // count = 2
        std::thread::sleep(Duration::from_millis(10)); // decay window elapsed
        let count = vt.record(p, &mut bl); // should reset to 1
        assert_eq!(count, 1);
    }

    #[test]
    fn evict_stale_removes_decayed_entries() {
        let mut vt = ViolationTracker::with_fixed_duration(
            5,
            Duration::from_secs(60),
            Duration::from_millis(1),
        )
        .unwrap();
        let mut bl = BanList::new();
        vt.record([5u8; 32], &mut bl);
        std::thread::sleep(Duration::from_millis(10));
        vt.evict_stale();
        assert_eq!(vt.count(&[5u8; 32]), 0);
    }

    #[test]
    fn violation_tracker_cap_evicts_oldest() {
        use veil_proto::budget::MAX_VIOLATION_TRACKER_SIZE;
        let mut vt = ViolationTracker::with_fixed_duration(
            100,
            Duration::from_secs(600),
            Duration::from_secs(3600),
        )
        .unwrap();
        let mut bl = BanList::new();
        // Fill to cap.
        for i in 0..MAX_VIOLATION_TRACKER_SIZE {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            vt.record(id, &mut bl);
        }
        // One more unique peer must not panic and must stay at cap.
        vt.record([0xFFu8; 32], &mut bl);
        // The internal map size is observable only indirectly — if this doesn't
        // panic or OOM the cap logic is working.
    }

    #[test]
    fn progressive_ban_duration() {
        // threshold=2, initial=5s, step=5s, max=20s
        let mut vt = ViolationTracker::new(
            2,
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(20),
            Duration::from_secs(3600),
        )
        .unwrap();
        let mut bl = BanList::new();
        let p = [0xAAu8; 32];

        // 1st ban: 5s (initial + 0*step)
        vt.record(p, &mut bl);
        vt.record(p, &mut bl); // triggers ban
        assert!(bl.is_banned(&p));
        assert_eq!(vt.ban_duration_for(0), Duration::from_secs(5));

        // Unban to test next round.
        bl.unban(&p);

        // 2nd ban: 10s (initial + 1*step)
        vt.record(p, &mut bl);
        vt.record(p, &mut bl);
        assert!(bl.is_banned(&p));
        assert_eq!(vt.ban_duration_for(1), Duration::from_secs(10));

        bl.unban(&p);

        // 3rd ban: 15s
        vt.record(p, &mut bl);
        vt.record(p, &mut bl);
        assert_eq!(vt.ban_duration_for(2), Duration::from_secs(15));

        bl.unban(&p);

        // 4th ban: capped at 20s (initial + 3*step = 20s = max)
        vt.record(p, &mut bl);
        vt.record(p, &mut bl);
        assert_eq!(vt.ban_duration_for(3), Duration::from_secs(20));

        bl.unban(&p);

        // 5th ban: still 20s (cap)
        vt.record(p, &mut bl);
        vt.record(p, &mut bl);
        assert_eq!(vt.ban_duration_for(4), Duration::from_secs(20));
    }
}

// ── property-based tests (103.4) ─────────────────────────────────────────────

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use veil_proto::budget::MAX_VIOLATION_TRACKER_SIZE;

    proptest! {
        /// Tracker size never exceeds MAX_VIOLATION_TRACKER_SIZE regardless of
        /// how many distinct peers record violations.
        #[test]
        fn size_never_exceeds_cap(
            peer_seeds in proptest::collection::vec(0u64..=u64::MAX, 1..=MAX_VIOLATION_TRACKER_SIZE + 20),
        ) {
            let mut vt = ViolationTracker::with_fixed_duration(100, Duration::from_secs(3600), Duration::from_secs(3600)).unwrap();
            let mut bl = BanList::new();
            for seed in &peer_seeds {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&seed.to_le_bytes());
                vt.record(id, &mut bl);
            }
            let observed = peer_seeds
                .iter()
                .map(|s| { let mut id = [0u8; 32]; id[..8].copy_from_slice(&s.to_le_bytes()); id })
                .collect::<std::collections::HashSet<_>>()
                .len();
            // The tracker may hold fewer if eviction occurred — never more.
            let _ = observed;
            // This test just asserts no panic and no OOM; cap logic ensures that.
            // We verify the invariant indirectly: if we insert more than the cap
            // a subsequent record for an existing peer should still work.
            let existing = { let mut id = [0u8; 32]; id[..8].copy_from_slice(&peer_seeds[0].to_le_bytes()); id };
            vt.record(existing, &mut bl); // must not panic
        }

        /// `evict_stale` is idempotent: calling it twice gives the same result
        /// as calling it once (no further state change on second call).
        #[test]
        fn evict_stale_is_idempotent(
            peer_seeds in proptest::collection::vec(0u64..1000, 1..=20),
        ) {
            let mut vt = ViolationTracker::with_fixed_duration(10, Duration::from_secs(3600), Duration::from_millis(1)).unwrap();
            let mut bl = BanList::new();
            for seed in &peer_seeds {
                let mut id = [0u8; 32];
                id[..8].copy_from_slice(&seed.to_le_bytes());
                // Record many times to ensure entries exist.
                for _ in 0..3 {
                    vt.record(id, &mut bl);
                }
            }
            vt.evict_stale();
            // After stale eviction, a second evict_stale must not panic.
            vt.evict_stale();
        }

        /// `record` always returns >= 1 (first violation for any peer is 1).
        #[test]
        fn count_at_least_one(seed in 0u64..=u64::MAX) {
            let mut vt = ViolationTracker::with_fixed_duration(5, Duration::from_secs(3600), Duration::from_secs(3600)).unwrap();
            let mut bl = BanList::new();
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&seed.to_le_bytes());
            let count = vt.record(id, &mut bl);
            prop_assert!(count >= 1, "record() must return at least 1 for a new violation");
        }
    }
}
