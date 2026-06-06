//! Per-resolver-local anycast reputation slice.
//!
//! Phase A of the "Anycast quorum" mitigation: every resolver keeps a
//! local count of (node_id, service_tag) → failure counter and applies it
//! as a penalty during sort in [`crate::AnycastService::resolve`]. There
//! is no wire protocol change and no cross-resolver gossip — a sybil that
//! poisons one resolver's view does not affect any other resolver.
//!
//! ## Threat model addressed
//!
//! [`crate::AnycastService`] already breaks deterministic "score=0 wins"
//! via XOR-distance tiebreak. That helps against a universal eclipse but
//! does nothing against a sybil close to a particular resolver in XOR space.
//! With reputation in the loop, even an XOR-close sybil pays a penalty per
//! observed failure — after enough failures the sybil drops below honest
//! candidates regardless of XOR proximity.
//!
//! ## What we deliberately do NOT do
//!
//! **No successes are tracked.** "I served the request" is peer-controlled
//! at the wire level; counting successes lets a sybil rapid-fire 1-byte
//! responses to inflate its own reputation. Failures are observable end-to-
//! end (timeout, conn-refused, validation failure) and can't be self-faked.
//!
//! **No decay over wall-clock time.** Failure counters are bounded only by
//! LRU eviction — a stale node that hasn't been queried in days gets evicted
//! as new entries flow in. Decay-on-time would let a sybil "wait out" its
//! penalty between attack waves; LRU-only means the entry persists as long
//! as that resolver keeps querying that tag, which is what we want.
//!
//! **No cross-resolver sharing.** Phase B (gossip / signed reputation
//! attestations) is out of scope. Per-resolver-local is a conservative
//! starting point: zero wire surface, zero new attack vectors, but still
//! materially raises the cost of poisoning any individual resolver.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use veil_util::lock;

/// Max number of (node_id, service_tag) entries kept in memory before LRU
/// eviction kicks in. Each entry is ~48 bytes (32 + 4 + 12 counter), so
/// 4096 ≈ 200 KiB which is a fine bound even on resource-constrained nodes.
pub const REPUTATION_LRU_CAP: usize = 4096;

/// Score penalty added per recorded failure. The penalty is applied
/// **linearly** to the existing peer-claimed `AnycastRecord.score` during
/// sort, so honest operators advertising scores in the low-100s outrank
/// a sybil after ~2–3 observed failures.
///
/// Tuning rationale: scores are u16 (range 0..=65535) but real deployments
/// typically advertise in the 0..1000 range (latency-derived). 500 per
/// failure pushes a compromised peer past most honest tiers within a
/// handful of observed misbehaviours without saturating the u32 offset
/// even at adversarial-counter levels.
pub const FAILURE_PENALTY_PER: u32 = 500;

/// How long a candidate stays "recently issued". Only candidates the daemon
/// actually returned to a client within this window may be the subject of an
/// app-reported failure — this binds [`AnycastReputation::record_failure_if_issued`]
/// to a real resolve so a local IPC app cannot penalize an arbitrary honest
/// node it was never offered.
const ISSUED_TTL: Duration = Duration::from_secs(600);
/// Cap on the issued-candidate ledger (≈ 8192 × ~48 B).
const ISSUED_CAP: usize = 8192;
/// Global rate-limit for app-reported failures: at most `MAX_REPORTS_PER_WINDOW`
/// honored reports per `REPORT_WINDOW`, so a local app can't rapidly poison the
/// ledger even for legitimately-issued candidates.
const REPORT_WINDOW: Duration = Duration::from_secs(60);
const MAX_REPORTS_PER_WINDOW: u32 = 128;

/// In-memory counter for one (node_id, service_tag) pair.
///
/// `last_touch` is a monotonic logical tick — incremented on every
/// `record_failure` or offset query — used purely for LRU eviction
/// ordering. It is NOT a timestamp and has no semantics beyond "more
/// recently touched > less recently touched".
#[derive(Default, Debug, Clone, Copy)]
struct Counter {
    failures: u32,
    last_touch: u64,
}

#[derive(Default)]
struct Inner {
    by_key: HashMap<([u8; 32], [u8; 4]), Counter>,
    /// Candidates recently RETURNED to a client (`(node_id, tag)` → expiry).
    /// A failure report is honored only for a key present + unexpired here.
    issued: HashMap<([u8; 32], [u8; 4]), Instant>,
    /// Global token-bucket window for app-reported failures.
    reports_window_start: Option<Instant>,
    reports_in_window: u32,
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

    /// Reputation slice with a custom LRU capacity. Use in tests or in
    /// memory-constrained environments. Capacity of 0 disables tracking
    /// entirely (every insert is a no-op; offset always returns 0).
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
    /// Caller responsibility: only invoke after a concrete failure signal
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
            // past-cap, which is rare on typical workloads.
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

    /// Note that `node_id` was just RETURNED to a client as a candidate for
    /// `service_tag`. Only candidates the daemon actually handed out (within
    /// [`ISSUED_TTL`]) may later be the subject of a failure report — this binds
    /// app-reported failures to a real resolve (see
    /// [`Self::record_failure_if_issued`]). Bounded ledger with TTL pruning.
    pub fn note_issued(&self, node_id: [u8; 32], service_tag: [u8; 4]) {
        if self.cap == 0 {
            return;
        }
        let now = Instant::now();
        let mut inner = lock!(self.inner);
        inner
            .issued
            .insert((node_id, service_tag), now + ISSUED_TTL);
        if inner.issued.len() > ISSUED_CAP {
            // Drop expired first; if still over cap, drop the soonest-to-expire.
            inner.issued.retain(|_, exp| *exp > now);
            while inner.issued.len() > ISSUED_CAP {
                if let Some(k) = inner
                    .issued
                    .iter()
                    .min_by_key(|(_, e)| **e)
                    .map(|(k, _)| *k)
                {
                    inner.issued.remove(&k);
                } else {
                    break;
                }
            }
        }
    }

    /// Record an APP-REPORTED failure, but ONLY if (a) `node_id` was recently
    /// issued to a client for `service_tag` (so a local IPC app cannot penalize
    /// a node it was never offered) AND (b) the global report rate-limit allows
    /// it. Returns `true` if the failure was recorded, `false` if the report was
    /// rejected (unknown/expired candidate or rate-limited).
    ///
    /// This is the gate for the IPC `AnycastReportFailure` opcode. Trusted
    /// internal callers that have already attributed a failure end-to-end should
    /// use [`Self::record_failure`] directly.
    #[must_use]
    pub fn record_failure_if_issued(&self, node_id: [u8; 32], service_tag: [u8; 4]) -> bool {
        if self.cap == 0 {
            return false;
        }
        let now = Instant::now();
        {
            let mut inner = lock!(self.inner);
            // (a) issued-binding: must have been handed out + not expired.
            match inner.issued.get(&(node_id, service_tag)) {
                Some(exp) if *exp > now => {}
                _ => return false,
            }
            // (b) global rate-limit (token bucket over REPORT_WINDOW).
            let reset = match inner.reports_window_start {
                Some(start) => now.duration_since(start) >= REPORT_WINDOW,
                None => true,
            };
            if reset {
                inner.reports_window_start = Some(now);
                inner.reports_in_window = 0;
            }
            if inner.reports_in_window >= MAX_REPORTS_PER_WINDOW {
                return false;
            }
            inner.reports_in_window += 1;
        }
        // Lock released above; `record_failure` re-locks (std Mutex is not
        // reentrant). The brief gap is acceptable for this local-trust path.
        self.record_failure(node_id, service_tag);
        true
    }

    /// Score offset for `node_id` under `service_tag`. Zero if no failures
    /// have been recorded. The offset is added to the peer-claimed score
    /// during sort in [`crate::AnycastService::resolve`].
    ///
    /// Querying the offset touches the entry for LRU purposes so that
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
    fn report_failure_requires_issued_candidate() {
        // M-3 (audit): an app-reported failure is only honored for a candidate
        // the daemon actually issued — a local IPC app cannot penalize an
        // arbitrary honest node it was never offered.
        let rep = AnycastReputation::new();
        let node = [0xCC; 32];
        let tag = *b"mbox";
        // Never issued → report rejected, no penalty.
        assert!(!rep.record_failure_if_issued(node, tag));
        assert_eq!(rep.score_offset(node, tag), 0);
        // Issued → report honored, penalty applied.
        rep.note_issued(node, tag);
        assert!(rep.record_failure_if_issued(node, tag));
        assert_eq!(rep.score_offset(node, tag), FAILURE_PENALTY_PER);
        // A different, never-issued node still can't be penalized.
        let other = [0xDD; 32];
        assert!(!rep.record_failure_if_issued(other, tag));
        assert_eq!(rep.score_offset(other, tag), 0);
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
        // Insert 3 entries — all remain.
        rep.record_failure([0x01; 32], *b"mbox");
        rep.record_failure([0x02; 32], *b"mbox");
        rep.record_failure([0x03; 32], *b"mbox");
        assert_eq!(rep.entry_count(), 3);

        // Touch the first to bump its last_touch to the most recent tick.
        let _ = rep.score_offset([0x01; 32], *b"mbox");

        // Insert a 4th — over cap. Victim should be 0x02 (oldest now that
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
        // Direct poke into the counter to push it close to saturation.
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
