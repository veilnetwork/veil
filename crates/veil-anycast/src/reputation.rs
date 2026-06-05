//! Per-resolver-local anycast reputation slice.
//!
//! Phase A of the "Anycast quorum" mitigation: every resolver keeps а
//! local count of (node_id, service_tag) → failure counter и applies it
//! as а penalty during sort in [`crate::AnycastService::resolve`]. There
//! is no wire protocol change и no cross-resolver gossip — а sybil that
//! poisons one resolver's view does not affect any other resolver.
//!
//! ## Threat model addressed
//!
//! [`crate::AnycastService`] already breaks deterministic "score=0 wins"
//! via XOR-distance tiebreak. That helps against а universal eclipse but
//! does nothing against а sybil close к а particular resolver in XOR space.
//! With reputation в the loop, even an XOR-close sybil pays а penalty per
//! observed failure — after enough failures the sybil drops below honest
//! candidates regardless of XOR proximity.
//!
//! ## What we deliberately do NOT do
//!
//! **No successes are tracked.** "I served the request" is peer-controlled
//! at the wire level; counting successes lets а sybil rapid-fire 1-byte
//! responses к inflate its own reputation. Failures are observable end-to-
//! end (timeout, conn-refused, validation failure) и can't be self-faked.
//!
//! **No decay over wall-clock time.** Failure counters are bounded only by
//! LRU eviction — а stale node that hasn't been queried in days gets evicted
//! as new entries flow in. Decay-on-time would let а sybil "wait out" its
//! penalty between attack waves; LRU-only means the entry persists as long
//! as that resolver keeps querying that tag, which is what we want.
//!
//! **No cross-resolver sharing.** Phase B (gossip / signed reputation
//! attestations) is out of scope. Per-resolver-local is а conservative
//! starting point: zero wire surface, zero new attack vectors, but still
//! materially raises the cost of poisoning any individual resolver.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use veil_util::lock;

/// Max number of (node_id, service_tag) entries kept in memory before LRU
/// eviction kicks in. Each entry is ~48 bytes (32 + 4 + 12 counter), so
/// 4096 ≈ 200 KiB which is а fine bound even on resource-constrained nodes.
pub const REPUTATION_LRU_CAP: usize = 4096;

/// Score penalty added per recorded failure. The penalty is applied
/// **linearly** к the existing peer-claimed `AnycastRecord.score` during
/// sort, so honest operators advertising scores в the low-100s outrank
/// а sybil after ~2–3 observed failures.
///
/// Tuning rationale: scores are u16 (range 0..=65535) but real deployments
/// typically advertise в the 0..1000 range (latency-derived). 500 per
/// failure pushes а compromised peer past most honest tiers within а
/// handful of observed misbehaviours without saturating the u32 offset
/// even at adversarial-counter levels.
pub const FAILURE_PENALTY_PER: u32 = 500;

/// In-memory counter for one (node_id, service_tag) pair.
///
/// `last_touch` is а monotonic logical tick — incremented on every
/// `record_failure` или offset query — used purely for LRU eviction
/// ordering. It is NOT а timestamp и has no semantics beyond "more
/// recently touched > less recently touched".
#[derive(Default, Debug, Clone, Copy)]
struct Counter {
    failures: u32,
    last_touch: u64,
}

#[derive(Default)]
struct Inner {
    by_key: HashMap<([u8; 32], [u8; 4]), Counter>,
}

/// Bounded, in-memory failure ledger.
///
/// Cloneable not. Wrap in [`std::sync::Arc`] for sharing.
pub struct AnycastReputation {
    inner: Mutex<Inner>,
    cap: usize,
    tick: AtomicU64,
}

impl Default for AnycastReputation {
    fn default() -> Self {
        Self::with_capacity(REPUTATION_LRU_CAP)
    }
}

impl AnycastReputation {
    /// Reputation slice with the default LRU capacity.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reputation slice with а custom LRU capacity. Use in tests or in
    /// memory-constrained environments. Capacity of 0 disables tracking
    /// entirely (every insert is а no-op; offset always returns 0).
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            cap,
            tick: AtomicU64::new(0),
        }
    }

    fn next_tick(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::Relaxed)
    }

    /// Record one observed failure (timeout, conn-refused, validation
    /// reject) for the candidate `node_id` under `service_tag`.
    ///
    /// Caller responsibility: only invoke after а concrete failure signal
    /// — not for "request slow" or "client cancelled". False positives
    /// here directly hurt honest operators.
    pub fn record_failure(&self, node_id: [u8; 32], service_tag: [u8; 4]) {
        if self.cap == 0 {
            return;
        }
        let tick = self.next_tick();
        let mut inner = lock!(self.inner);
        let entry = inner.by_key.entry((node_id, service_tag)).or_default();
        entry.failures = entry.failures.saturating_add(1);
        entry.last_touch = tick;

        if inner.by_key.len() > self.cap {
            // Evict the single oldest entry. O(n) scan but only on insert-
            // past-cap, which is rare на typical workloads.
            if let Some(victim_key) = inner
                .by_key
                .iter()
                .min_by_key(|(_, c)| c.last_touch)
                .map(|(k, _)| *k)
            {
                inner.by_key.remove(&victim_key);
            }
        }
    }

    /// Score offset for `node_id` under `service_tag`. Zero if no failures
    /// have been recorded. The offset is added to the peer-claimed score
    /// during sort in [`crate::AnycastService::resolve`].
    ///
    /// Querying the offset touches the entry для LRU purposes так что
    /// frequently-consulted entries stay resident.
    pub fn score_offset(&self, node_id: [u8; 32], service_tag: [u8; 4]) -> u32 {
        if self.cap == 0 {
            return 0;
        }
        let tick = self.next_tick();
        let mut inner = lock!(self.inner);
        match inner.by_key.get_mut(&(node_id, service_tag)) {
            Some(c) => {
                c.last_touch = tick;
                c.failures.saturating_mul(FAILURE_PENALTY_PER)
            }
            None => 0,
        }
    }

    /// Test/diag: current entry count.
    pub fn entry_count(&self) -> usize {
        lock!(self.inner).by_key.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_offset_is_zero() {
        let rep = AnycastReputation::new();
        assert_eq!(rep.score_offset([0xAA; 32], *b"mbox"), 0);
    }

    #[test]
    fn single_failure_yields_one_penalty() {
        let rep = AnycastReputation::new();
        rep.record_failure([0xAA; 32], *b"mbox");
        assert_eq!(rep.score_offset([0xAA; 32], *b"mbox"), FAILURE_PENALTY_PER);
    }

    #[test]
    fn multiple_failures_compound_linearly() {
        let rep = AnycastReputation::new();
        for _ in 0..5 {
            rep.record_failure([0xAA; 32], *b"mbox");
        }
        assert_eq!(
            rep.score_offset([0xAA; 32], *b"mbox"),
            5 * FAILURE_PENALTY_PER
        );
    }

    #[test]
    fn separate_tags_are_independent() {
        let rep = AnycastReputation::new();
        rep.record_failure([0xAA; 32], *b"mbox");
        rep.record_failure([0xAA; 32], *b"mbox");
        rep.record_failure([0xAA; 32], *b"gate");
        assert_eq!(
            rep.score_offset([0xAA; 32], *b"mbox"),
            2 * FAILURE_PENALTY_PER
        );
        assert_eq!(rep.score_offset([0xAA; 32], *b"gate"), FAILURE_PENALTY_PER);
        assert_eq!(rep.score_offset([0xAA; 32], *b"none"), 0);
    }

    #[test]
    fn separate_nodes_are_independent() {
        let rep = AnycastReputation::new();
        rep.record_failure([0xAA; 32], *b"mbox");
        rep.record_failure([0xBB; 32], *b"mbox");
        rep.record_failure([0xBB; 32], *b"mbox");
        assert_eq!(rep.score_offset([0xAA; 32], *b"mbox"), FAILURE_PENALTY_PER);
        assert_eq!(
            rep.score_offset([0xBB; 32], *b"mbox"),
            2 * FAILURE_PENALTY_PER
        );
    }

    #[test]
    fn lru_evicts_oldest_when_over_cap() {
        let rep = AnycastReputation::with_capacity(3);
        // Insert 3 entries — все остаются.
        rep.record_failure([0x01; 32], *b"mbox");
        rep.record_failure([0x02; 32], *b"mbox");
        rep.record_failure([0x03; 32], *b"mbox");
        assert_eq!(rep.entry_count(), 3);

        // Touch the first to bump its last_touch к the most recent tick.
        let _ = rep.score_offset([0x01; 32], *b"mbox");

        // Insert а 4th — over cap. Victim should be 0x02 (oldest now что
        // 0x01 was just touched).
        rep.record_failure([0x04; 32], *b"mbox");
        assert_eq!(rep.entry_count(), 3);
        assert!(
            rep.score_offset([0x01; 32], *b"mbox") > 0,
            "freshly touched 0x01 survived"
        );
        assert_eq!(
            rep.score_offset([0x02; 32], *b"mbox"),
            0,
            "0x02 was the least-recently-touched, must be evicted"
        );
        assert!(rep.score_offset([0x03; 32], *b"mbox") > 0);
        assert!(rep.score_offset([0x04; 32], *b"mbox") > 0);
    }

    #[test]
    fn zero_capacity_disables_tracking() {
        let rep = AnycastReputation::with_capacity(0);
        rep.record_failure([0xAA; 32], *b"mbox");
        assert_eq!(rep.score_offset([0xAA; 32], *b"mbox"), 0);
        assert_eq!(rep.entry_count(), 0);
    }

    #[test]
    fn saturation_does_not_panic() {
        let rep = AnycastReputation::new();
        // Stamp the entry near u32::MAX to confirm saturating math.
        for _ in 0..10 {
            rep.record_failure([0xAA; 32], *b"mbox");
        }
        // Direct poke into the counter to push it close к saturation.
        {
            let mut inner = lock!(rep.inner);
            let c = inner.by_key.get_mut(&([0xAA; 32], *b"mbox")).unwrap();
            c.failures = u32::MAX - 1;
        }
        rep.record_failure([0xAA; 32], *b"mbox");
        rep.record_failure([0xAA; 32], *b"mbox");
        rep.record_failure([0xAA; 32], *b"mbox");
        // Should not have wrapped (saturating_add); offset stays at u32::MAX.
        let off = rep.score_offset([0xAA; 32], *b"mbox");
        assert_eq!(
            off,
            u32::MAX,
            "saturating_mul gives u32::MAX since failures ≈ u32::MAX"
        );
    }
}
