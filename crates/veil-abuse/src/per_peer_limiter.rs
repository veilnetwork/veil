//! Per-peer rate limiting using individual token buckets.
//!
//! `PerPeerLimiter` maintains one `TokenBucket` per peer and creates a fresh
//! bucket lazily on first contact. Buckets for inactive peers are evicted
//! periodically via `evict_stale`.
//!
//! # Invariant (audit batch 2026-05-24, L3)
//!
//! **The defence depends on `peer_id` being authenticated at the session /
//! dispatcher layer.**  `PerPeerLimiter` keys its HashMap by `[u8; 32]`
//! peer_id — if а malicious peer could forge that ID per-frame, it would
//! get а fresh token bucket per fake ID и trivially bypass the limit.
//!
//! Authentication invariant: every frame delivered к а handler с а
//! `peer_id` argument must come от а session that completed OVL1 handshake
//! и signature verification (см. `SessionRunner::run`).  Tests / fixtures
//! that bypass this MUST not leak into production code paths.

use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, Instant},
};

use super::rate_limiter::TokenBucket;

// ── PerPeerEntry ──────────────────────────────────────────────────────────────

struct PerPeerEntry {
    bucket: TokenBucket,
    last_seen: Instant,
    /// Recency sequence number — reassigned on every `allow` touch and used
    /// as the key in `eviction_order` so the BTreeMap is ordered LRU.
    /// Eviction picks the smallest seq = least-recently-touched.
    /// was insertion-order (FIFO) — Sybil flood evicted legit
    /// long-running peers because their insert seq was lowest.
    seq: u64,
}

// ── PerPeerLimiter ────────────────────────────────────────────────────────────

struct PerPeerByteEntry {
    bucket: TokenBucket,
    last_seen: Instant,
    /// Recency sequence — reassigned on every `allow_bytes` touch. See
    /// `PerPeerEntry::seq` for full rationale.
    seq: u64,
}

/// Manages per-peer `TokenBucket`s with configurable defaults.
#[derive(Debug)]
pub struct PerPeerLimiter {
    entries: HashMap<[u8; 32], PerPeerEntry>,
    /// Secondary index: seq → peer_id, ordered by insertion time.
    /// Lets us evict the oldest-inserted peer in O(log n) instead of O(n).
    eviction_order: BTreeMap<u64, [u8; 32]>,
    /// Monotonically increasing counter for insertion order.
    next_seq: u64,
    /// Tokens per second for newly created buckets.
    default_rate: f64,
    /// Burst capacity for newly created buckets.
    capacity: f64,
    /// Remove entries not seen for longer than this duration.
    idle_timeout: Duration,
    /// Optional per-peer byte-rate buckets.
    /// `bytes_per_sec` = None means byte-rate enforcement is disabled.
    byte_entries: HashMap<[u8; 32], PerPeerByteEntry>,
    /// Secondary index: seq → peer_id for O(log n) eviction of byte-rate entries.
    byte_eviction_order: BTreeMap<u64, [u8; 32]>,
    /// Monotonically increasing counter for byte-entry insertion order.
    byte_next_seq: u64,
    bytes_per_sec: Option<f64>,
    /// Burst capacity in bytes (max bytes before throttling).
    bytes_capacity: f64,
    /// b drop-counter: cumulative bytes admitted by
    /// `allow_bytes` since this limiter was created (or reload).
    /// Pure observability — not used for enforcement. Saturating
    /// add so a long-running node doesn't wrap at u64::MAX (would
    /// take ~5 EB at typical mobile rates, but defensive anyway).
    bytes_allowed_total: u64,
    /// Cumulative bytes REJECTED by `allow_bytes` for being over
    /// the per-peer cap. Operator looks at this to decide if the
    /// cap is "well-tuned" (low/zero drops) или "breaking legit
    /// traffic" (constant drops).
    bytes_dropped_total: u64,
}

impl std::fmt::Debug for PerPeerByteEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerPeerByteEntry")
            .field("bucket", &self.bucket)
            .field("seq", &self.seq)
            .finish()
    }
}

impl PerPeerLimiter {
    /// Create a limiter.
    ///
    /// * `default_rate` — tokens per second (steady-state allow rate).
    /// * `capacity` — burst size (initial fill and maximum).
    /// * `idle_timeout` — evict peer entries that haven't been seen for this long.
    pub fn new(default_rate: f64, capacity: f64, idle_timeout: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            eviction_order: BTreeMap::new(),
            next_seq: 0,
            default_rate,
            capacity,
            idle_timeout,
            byte_entries: HashMap::new(),
            byte_eviction_order: BTreeMap::new(),
            byte_next_seq: 0,
            bytes_per_sec: None,
            bytes_capacity: 0.0,
            bytes_allowed_total: 0,
            bytes_dropped_total: 0,
        }
    }

    /// Enable per-peer byte-rate enforcement.
    ///
    /// * `bytes_per_sec` — steady-state byte throughput per peer.
    /// * `burst_bytes` — maximum burst in bytes.
    pub fn with_byte_rate(mut self, bytes_per_sec: f64, burst_bytes: f64) -> Self {
        self.bytes_per_sec = Some(bytes_per_sec);
        self.bytes_capacity = burst_bytes;
        self
    }

    /// Attempt to pass `byte_count` bytes for `peer_id` through the byte-rate limiter.
    ///
    /// Returns `true` if allowed; `false` if the byte budget is exhausted.
    /// Always returns `true` if byte-rate enforcement has not been enabled via
    /// [`with_byte_rate`].
    pub fn allow_bytes(&mut self, peer_id: [u8; 32], byte_count: usize) -> bool {
        let bps = match self.bytes_per_sec {
            Some(r) => r,
            // Enforcement disabled: bytes pass через без accounting
            // которое обновлялось бы конкурентно with (more
            // visible) node-aggregate `BandwidthGate.total_bytes`
            // counter. Avoid double-counting на the audit surface.
            None => return true,
        };
        // Cap byte_entries to the same limit as frame-rate entries.
        // O(log n) eviction via `byte_eviction_order` BTreeMap.
        // switched FIFO → LRU — see `allow` for rationale.
        if !self.byte_entries.contains_key(&peer_id)
            && self.byte_entries.len() >= veil_proto::budget::MAX_PER_PEER_LIMITER_SIZE
            && let Some((&seq, &victim_id)) = self.byte_eviction_order.iter().next()
        {
            self.byte_eviction_order.remove(&seq);
            self.byte_entries.remove(&victim_id);
        }
        let cap = self.bytes_capacity;
        let now = Instant::now();
        let new_seq = self.byte_next_seq;
        self.byte_next_seq += 1;
        let order = &mut self.byte_eviction_order;
        let entry = self
            .byte_entries
            .entry(peer_id)
            .or_insert_with(|| PerPeerByteEntry {
                bucket: TokenBucket::new(cap, bps),
                last_seen: now,
                seq: new_seq,
            });
        if entry.seq != new_seq {
            order.remove(&entry.seq);
            entry.seq = new_seq;
        }
        order.insert(new_seq, peer_id);
        entry.last_seen = now;
        // `TokenBucket::allow_n_at` is `u32`-wide internally, so
        // anything above `u32::MAX` bytes (~4.29 GiB) would overflow. Real
        // veil frames are bounded by `MAX_FRAME_BODY` (16 MiB) — 256× below
        // the limit — so this cast can never truncate. Assert the invariant
        // in debug builds; release keeps the cheap direct cast.
        debug_assert!(
            byte_count <= veil_proto::codec::MAX_FRAME_BODY as usize,
            "per-peer byte count {byte_count} exceeds MAX_FRAME_BODY \
             ({}); frames should have been rejected upstream",
            veil_proto::codec::MAX_FRAME_BODY,
        );
        let allowed = entry.bucket.allow_n_at(byte_count as f64, now);
        // b: cumulative drop-counter for operator
        // observability. Saturating add so a long-running node
        // doesn't wrap at u64::MAX (would take ~5 EB at typical
        // mobile rates, but defensive anyway).
        if allowed {
            self.bytes_allowed_total = self.bytes_allowed_total.saturating_add(byte_count as u64);
        } else {
            self.bytes_dropped_total = self.bytes_dropped_total.saturating_add(byte_count as u64);
        }
        allowed
    }

    /// Cumulative bytes admitted by `allow_bytes` since this
    /// limiter was created OR last reload. `0` when byte-rate
    /// enforcement is not enabled (the early-return `true` path
    /// doesn't account, к avoid double-counting с node-aggregate
    /// `BandwidthGate.total_bytes`).
    pub fn bytes_allowed_total(&self) -> u64 {
        self.bytes_allowed_total
    }

    /// Cumulative bytes REJECTED by `allow_bytes` for being over
    /// the per-peer cap. Operator-facing — looks at this to decide
    /// if the cap is "well-tuned" (low/zero drops) или "breaking
    /// legit traffic" (constant drops). `0` when byte-rate
    /// enforcement is not enabled.
    pub fn bytes_dropped_total(&self) -> u64 {
        self.bytes_dropped_total
    }

    /// Attempt to allow one token for `peer_id`.
    pub fn allow(&mut self, peer_id: [u8; 32]) -> bool {
        let now = Instant::now();
        let rate = self.default_rate;
        let cap = self.capacity;

        // Cap: evict the LEAST-RECENTLY-TOUCHED entry when the map is full
        // (was FIFO oldest-inserted, which let a Sybil flood
        // evict legitimate long-lived peers whose insertion seqs were lowest).
        // O(log n) via the `eviction_order` BTreeMap.
        if !self.entries.contains_key(&peer_id)
            && self.entries.len() >= veil_proto::budget::MAX_PER_PEER_LIMITER_SIZE
            && let Some((&seq, &victim_id)) = self.eviction_order.iter().next()
        {
            self.eviction_order.remove(&seq);
            self.entries.remove(&victim_id);
        }

        // Allocate a fresh seq for this touch and re-key the eviction index.
        // Both new and existing entries get the latest seq, so the BTreeMap
        // ordering reflects recency rather than insertion order.
        let new_seq = self.next_seq;
        self.next_seq += 1;
        let eviction_order = &mut self.eviction_order;
        let entry = self.entries.entry(peer_id).or_insert_with(|| PerPeerEntry {
            bucket: TokenBucket::new(cap, rate),
            last_seen: now,
            seq: new_seq,
        });
        if entry.seq != new_seq {
            // Existing entry — relocate its eviction key.
            eviction_order.remove(&entry.seq);
            entry.seq = new_seq;
        }
        eviction_order.insert(new_seq, peer_id);
        entry.last_seen = now;
        entry.bucket.allow_at(now)
    }

    /// Remove entries that have been idle for longer than `idle_timeout`.
    pub fn evict_stale(&mut self) {
        let now = Instant::now();
        let timeout = self.idle_timeout;
        // Collect seqs of stale entries first, then remove from both maps.
        let stale_seqs: Vec<u64> = self
            .entries
            .values()
            .filter(|e| now.duration_since(e.last_seen) >= timeout)
            .map(|e| e.seq)
            .collect();
        for seq in &stale_seqs {
            self.eviction_order.remove(seq);
        }
        self.entries
            .retain(|_, e| now.duration_since(e.last_seen) < timeout);

        // also evict stale byte-rate entries and prune their
        // eviction_order index.
        let stale_byte_seqs: Vec<u64> = self
            .byte_entries
            .values()
            .filter(|e| now.duration_since(e.last_seen) >= timeout)
            .map(|e| e.seq)
            .collect();
        for seq in &stale_byte_seqs {
            self.byte_eviction_order.remove(seq);
        }
        self.byte_entries
            .retain(|_, e| now.duration_since(e.last_seen) < timeout);
    }

    pub fn peer_count(&self) -> usize {
        self.entries.len()
    }
}

impl std::fmt::Debug for PerPeerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerPeerEntry")
            .field("bucket", &self.bucket)
            .field("last_seen", &self.last_seen)
            .field("seq", &self.seq)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_peers_are_isolated() {
        let mut lim = PerPeerLimiter::new(1.0, 1.0, Duration::from_secs(60));
        let p1 = [1u8; 32];
        let p2 = [2u8; 32];
        assert!(lim.allow(p1));
        assert!(!lim.allow(p1)); // p1 drained
        assert!(lim.allow(p2)); // p2 has its own bucket, still full
    }

    #[test]
    fn burst_capacity_respected() {
        let mut lim = PerPeerLimiter::new(1.0, 3.0, Duration::from_secs(60));
        let p = [5u8; 32];
        assert!(lim.allow(p));
        assert!(lim.allow(p));
        assert!(lim.allow(p));
        assert!(!lim.allow(p)); // burst exhausted
    }

    #[test]
    fn evict_stale_removes_idle_peers() {
        let mut lim = PerPeerLimiter::new(10.0, 10.0, Duration::from_millis(1));
        lim.allow([1u8; 32]);
        lim.allow([2u8; 32]);
        assert_eq!(lim.peer_count(), 2);
        // Sleep more than idle_timeout
        std::thread::sleep(Duration::from_millis(5));
        lim.evict_stale();
        assert_eq!(lim.peer_count(), 0);
    }

    #[test]
    fn new_peer_created_lazily() {
        let mut lim = PerPeerLimiter::new(5.0, 5.0, Duration::from_secs(60));
        assert_eq!(lim.peer_count(), 0);
        lim.allow([7u8; 32]);
        assert_eq!(lim.peer_count(), 1);
    }

    #[test]
    fn per_peer_limiter_cap_does_not_grow_beyond_max() {
        use veil_proto::budget::MAX_PER_PEER_LIMITER_SIZE;
        let mut lim = PerPeerLimiter::new(1000.0, 1000.0, Duration::from_secs(3600));
        for i in 0..MAX_PER_PEER_LIMITER_SIZE {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            lim.allow(id);
        }
        assert_eq!(lim.peer_count(), MAX_PER_PEER_LIMITER_SIZE);
        // One more — must evict an entry and stay at cap.
        lim.allow([0xFFu8; 32]);
        assert_eq!(lim.peer_count(), MAX_PER_PEER_LIMITER_SIZE);
    }

    #[test]
    fn eviction_order_stays_consistent_with_entries() {
        let mut lim = PerPeerLimiter::new(1000.0, 1000.0, Duration::from_secs(3600));
        for i in 0..10u8 {
            lim.allow([i; 32]);
        }
        assert_eq!(lim.eviction_order.len(), lim.entries.len());
        lim.evict_stale(); // nothing stale yet
        assert_eq!(lim.eviction_order.len(), lim.entries.len());
    }

    #[test]
    fn lru_eviction_keeps_active_peer_alive_under_sybil_flood() {
        // with FIFO eviction, an active long-running peer would
        // be evicted as soon as MAX_PER_PEER_LIMITER_SIZE Sybil peer_ids
        // were inserted (its insertion seq was lowest). With LRU, ongoing
        // touches keep it at the top of the recency order.
        use veil_proto::budget::MAX_PER_PEER_LIMITER_SIZE;
        let mut lim = PerPeerLimiter::new(1_000_000.0, 1_000_000.0, Duration::from_secs(3600));

        let active = [0xAAu8; 32];
        // Touch active first (oldest insert seq).
        lim.allow(active);

        // Sybil flood: fill the limiter with fake peer_ids. After each
        // fake, re-touch the active peer to keep it recent.
        for i in 0..MAX_PER_PEER_LIMITER_SIZE * 2 {
            let mut sybil = [0u8; 32];
            sybil[..8].copy_from_slice(&(i as u64).to_le_bytes());
            sybil[31] = 0xFF; // distinguish from `active` even on collision
            lim.allow(sybil);
            // Active peer keeps doing real work, so its seq stays freshest.
            lim.allow(active);
        }

        assert_eq!(lim.peer_count(), MAX_PER_PEER_LIMITER_SIZE);
        // The active peer must still be in the table — LRU should have
        // evicted older Sybil entries instead.
        assert!(
            lim.entries.contains_key(&active),
            "active peer was evicted under Sybil flood — LRU regression"
        );
    }

    // ── b: per-peer byte-rate drop counters ────────────────────

    #[test]
    fn epic483_6b_byte_counters_zero_when_enforcement_disabled() {
        // Enforcement off (no with_byte_rate call) → allow_bytes
        // returns true unconditionally AND counters stay at zero
        // (avoid double-counting с node-aggregate BandwidthGate).
        let mut lim = PerPeerLimiter::new(1.0, 1.0, Duration::from_secs(60));
        assert!(lim.allow_bytes([1u8; 32], 1024));
        assert!(lim.allow_bytes([1u8; 32], 1024));
        assert_eq!(
            lim.bytes_allowed_total(),
            0,
            "enforcement off → no per-peer accounting (avoid double-counting)"
        );
        assert_eq!(lim.bytes_dropped_total(), 0);
    }

    #[test]
    fn epic483_6b_byte_counters_accumulate_when_enforcement_enabled() {
        // Cap = 1 KB/sec, burst = 2 KB. Sending 2 KB consumes
        // burst; next 100 bytes gets dropped (no time для refill).
        let mut lim =
            PerPeerLimiter::new(1.0, 1.0, Duration::from_secs(60)).with_byte_rate(1024.0, 2048.0);
        let p = [1u8; 32];
        assert!(lim.allow_bytes(p, 2048), "burst should pass");
        assert!(!lim.allow_bytes(p, 100), "post-burst must drop");
        assert_eq!(
            lim.bytes_allowed_total(),
            2048,
            "first call admitted 2048 bytes"
        );
        assert_eq!(
            lim.bytes_dropped_total(),
            100,
            "second call dropped 100 bytes — counter ticks even on tiny rejected frame"
        );
    }

    #[test]
    fn epic483_6b_byte_counters_per_peer_isolated_in_aggregate() {
        // Two peers each send 2 KB through 2 KB burst → both
        // succeed. Aggregate counter sums across peers (это
        // node-wide stat, not per-peer).
        let mut lim =
            PerPeerLimiter::new(1.0, 1.0, Duration::from_secs(60)).with_byte_rate(1024.0, 2048.0);
        let p1 = [1u8; 32];
        let p2 = [2u8; 32];
        assert!(lim.allow_bytes(p1, 2048));
        assert!(lim.allow_bytes(p2, 2048));
        assert_eq!(
            lim.bytes_allowed_total(),
            4096,
            "both peers admitted 2 KB each → aggregate = 4 KB"
        );
        assert_eq!(lim.bytes_dropped_total(), 0);
    }

    #[test]
    fn epic483_6b_byte_counters_track_drops_separately_from_admits() {
        // Burst exhausted by first call; subsequent drops accumulate
        // separately. Lock в the separation so a renaming refactor
        // (e.g. swap allowed/dropped fields) gets caught.
        let mut lim =
            PerPeerLimiter::new(1.0, 1.0, Duration::from_secs(60)).with_byte_rate(1024.0, 1024.0);
        let p = [1u8; 32];
        assert!(lim.allow_bytes(p, 1024)); // exhaust burst
        assert!(!lim.allow_bytes(p, 500));
        assert!(!lim.allow_bytes(p, 300));
        assert!(!lim.allow_bytes(p, 200));
        assert_eq!(lim.bytes_allowed_total(), 1024, "only first call admitted");
        assert_eq!(
            lim.bytes_dropped_total(),
            500 + 300 + 200,
            "subsequent drops accumulate cleanly: 1000 bytes total dropped"
        );
    }

    #[test]
    fn lru_evicts_silent_peer_first() {
        // A peer that stops sending becomes the LRU victim once the table
        // fills up — opposite of FIFO, where it would survive only by
        // happening to have a high insertion seq.
        use veil_proto::budget::MAX_PER_PEER_LIMITER_SIZE;
        let mut lim = PerPeerLimiter::new(1_000_000.0, 1_000_000.0, Duration::from_secs(3600));

        let silent = [0xBBu8; 32];
        lim.allow(silent); // Touched once, then never again.

        // Fill the table after the silent peer. Each new entry is fresher.
        for i in 0..MAX_PER_PEER_LIMITER_SIZE {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            id[31] = 0xCC;
            lim.allow(id);
        }

        // Cap reached + silent's seq is the lowest, so the next allow on a
        // brand-new peer must evict the silent one.
        assert_eq!(lim.peer_count(), MAX_PER_PEER_LIMITER_SIZE);
        let evictor = [0xDDu8; 32];
        lim.allow(evictor);
        assert!(
            !lim.entries.contains_key(&silent),
            "LRU should have evicted the silent peer first"
        );
        assert!(lim.entries.contains_key(&evictor));
    }
}
