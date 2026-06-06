//! Per-identity DHT write quota.
//!
//! Complements the existing per-peer [`dht_quota`](super::dht_quota)
//! with a
//! quota indexed by `node_id` on the DHT node. A compromised
//! `identity_sk` could otherwise flood the DHT with rapid
//! `document_version++` updates — the per-peer limiter alone would
//! not catch it if the attacker spreads those writes across many
//! peers.
//!
//! ## Policy
//!
//! Default `MAX_WRITES_PER_HOUR = 10`. Legitimate flows (rotate
//! freshness refresh, name claim, instance registry, periodic
//! app-state sync) sit well below this even on busy days.
//! Sliding window: each `try_allow` trims entries older than
//! `window` before counting.
//! Exceeding the quota returns [`QuotaDecision::RateLimited`] —
//! **not** `Violation`, per spec: a user recovering from
//! compromise may genuinely need to push several updates in a
//! short window (rotate + revoke + re-publish), and auto-banning
//! would compound the incident.
//!
//! ## Memory cap
//!
//! Each identity's bucket stores timestamps of its recent writes.
//! The worst case is `MAX_WRITES_PER_HOUR` timestamps per identity
//! so every bucket is at most a few hundred bytes.
//!
//! Audit cycle-5 (#6): the number of *identities* is also bounded. The
//! `node_id` key is attacker-controlled and UNVERIFIED at the DHT store gate
//! (recursive STORE of NameClaim/IdentityDocument/InstanceRegistry/MlKemKeyCert
//! is structurally decoded, not signature-checked), so a peer rotating `node_id`
//! could otherwise grow the map without limit. [`try_allow_at`] therefore
//! evicts the least-recently-touched identity whenever a NEW identity would
//! exceed [`veil_proto::budget::MAX_IDENTITY_WRITE_QUOTA_SIZE`] — the map
//! stays bounded with NO dependence on a GC scheduler. [`IdentityWriteQuota::gc_at`]
//! remains available for an optional idle sweep but is no longer required for
//! the memory bound (it is currently not wired to a production tick).

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ── Defaults ─────────────────────────────────────────────────────────────────

/// Default spec cap: 10 writes per identity per rolling hour.
pub const DEFAULT_MAX_WRITES_PER_HOUR: u32 = 10;
/// Default sliding-window length.
pub const DEFAULT_WINDOW_SECS: u64 = 3600;
/// Default GC age: idle buckets older than this are dropped by `gc`.
pub const DEFAULT_IDLE_CLEANUP_SECS: u64 = 6 * 3600;

// ── Types ────────────────────────────────────────────────────────────────────

/// Result of a `try_allow` call.
///
/// cleanup: production callers chain `.is_allowed` (bool
/// extractor) and never pattern-match the payload fields (`current`, `cap`
/// `retry_after`). Fields are intentionally kept so that tests can introspect
/// quota arithmetic AND so that a future `RATE_LIMITED` wire response can
/// carry retry-after hints without a breaking change. When the wire response
/// lands, switch dispatcher call sites from `if!try_allow.is_allowed` to
/// matching `QuotaDecision::RateLimited { retry_after.. }` and plumb
/// `retry_after` in the response carrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaDecision {
    /// Write is within the quota and has been recorded.
    Allowed {
        /// Number of writes (including this one) in the current
        /// window, for telemetry.
        current: u32,
        /// Quota cap the operator has configured.
        cap: u32,
    },
    /// Write exceeds the cap and is rejected. Caller should return
    /// a protocol-level rate-limit response, NOT a ban.
    RateLimited {
        /// How many writes already used the quota in the current
        /// window.
        current: u32,
        /// Configured cap.
        cap: u32,
        /// Earliest moment at which one token will free up.
        retry_after: Duration,
    },
}

impl QuotaDecision {
    /// Convenience: `matches!(self, Allowed {.. })`.
    pub fn is_allowed(&self) -> bool {
        matches!(self, QuotaDecision::Allowed { .. })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IdentityQuotaConfig {
    pub max_writes_per_window: u32,
    pub window: Duration,
    pub cleanup_idle_after: Duration,
    /// Audit cycle-5 (#6): hard cap on the number of distinct identities
    /// tracked, so the (attacker-controlled) `node_id` key cannot grow the map
    /// without limit. When full, the least-recently-touched identity is evicted.
    pub max_identities: usize,
}

impl Default for IdentityQuotaConfig {
    fn default() -> Self {
        Self {
            max_writes_per_window: DEFAULT_MAX_WRITES_PER_HOUR,
            window: Duration::from_secs(DEFAULT_WINDOW_SECS),
            cleanup_idle_after: Duration::from_secs(DEFAULT_IDLE_CLEANUP_SECS),
            max_identities: veil_proto::budget::MAX_IDENTITY_WRITE_QUOTA_SIZE,
        }
    }
}

/// Sliding-window write counter indexed by `node_id`.
#[derive(Debug)]
pub struct IdentityWriteQuota {
    cfg: IdentityQuotaConfig,
    state: Mutex<QuotaState>,
}

#[derive(Debug, Default)]
struct QuotaState {
    buckets: HashMap<[u8; 32], Bucket>,
    /// Secondary LRU index ordered by `(last_touched, node_id)`. Audit cycle-6
    /// (P9): eviction of the least-recently-touched identity at capacity is now
    /// O(log n) (`lru.iter().next()`) instead of an O(n) `min_by_key` scan over
    /// up to `MAX_IDENTITY_WRITE_QUOTA_SIZE` buckets under the lock — that scan,
    /// triggered on every fresh attacker-rotated `node_id` once the map is full,
    /// was the cost the cycle-5 (#6) bound introduced. Invariant: holds exactly
    /// one `(bucket.last_touched, node_id)` entry per bucket.
    lru: BTreeSet<(Instant, [u8; 32])>,
}

#[derive(Debug, Clone)]
struct Bucket {
    timestamps: VecDeque<Instant>,
    last_touched: Instant,
}

// ── Impl ─────────────────────────────────────────────────────────────────────

impl IdentityWriteQuota {
    pub fn new(cfg: IdentityQuotaConfig) -> Self {
        Self {
            cfg,
            state: Mutex::new(QuotaState::default()),
        }
    }

    pub fn default_policy() -> Self {
        Self::new(IdentityQuotaConfig::default())
    }

    /// Check whether a DHT write from `node_id` is permitted
    /// **at `now`** and, if so, record the write. Injected `now`
    /// makes tests deterministic; production uses [`Instant::now`].
    pub fn try_allow_at(&self, node_id: &[u8; 32], now: Instant) -> QuotaDecision {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let QuotaState { buckets, lru } = &mut *guard;

        // Audit cycle-5 (#6): bound the map. The `node_id` key is
        // attacker-controlled and unverified at the DHT store gate, and `gc_at`
        // is not scheduled in production, so without this an attacker rotating
        // `node_id` grows the map without limit. When inserting a NEW identity at
        // capacity, evict the least-recently-touched bucket (an abandoned rotated
        // entry or a genuinely-idle identity).
        //
        // Audit cycle-6 (P9): pick the victim via the `lru` BTreeSet's minimum
        // (O(log n)) instead of an O(n) `min_by_key` scan under the lock.
        let is_new = !buckets.contains_key(node_id);
        if is_new
            && buckets.len() >= self.cfg.max_identities
            && let Some(&(victim_touched, victim_id)) = lru.iter().next()
        {
            lru.remove(&(victim_touched, victim_id));
            buckets.remove(&victim_id);
        }

        // Keep the LRU index in sync: drop the bucket's previous position before
        // re-inserting at `now` (invariant: one entry per bucket).
        if let Some(existing) = buckets.get(node_id) {
            lru.remove(&(existing.last_touched, *node_id));
        }
        let bucket = buckets.entry(*node_id).or_insert_with(|| Bucket {
            timestamps: VecDeque::new(),
            last_touched: now,
        });
        bucket.last_touched = now;
        lru.insert((now, *node_id));

        // Trim entries older than the window.
        while let Some(oldest) = bucket.timestamps.front().copied() {
            if now.duration_since(oldest) >= self.cfg.window {
                bucket.timestamps.pop_front();
            } else {
                break;
            }
        }

        let current = bucket.timestamps.len() as u32;
        if current >= self.cfg.max_writes_per_window {
            // The earliest entry is the one that, when it falls out
            // of the window, frees a slot.
            let earliest = bucket.timestamps.front().copied().unwrap_or(now);
            let elapsed_since_earliest = now.duration_since(earliest);
            let retry_after = if elapsed_since_earliest >= self.cfg.window {
                Duration::from_secs(0)
            } else {
                self.cfg.window - elapsed_since_earliest
            };
            QuotaDecision::RateLimited {
                current,
                cap: self.cfg.max_writes_per_window,
                retry_after,
            }
        } else {
            bucket.timestamps.push_back(now);
            QuotaDecision::Allowed {
                current: current + 1,
                cap: self.cfg.max_writes_per_window,
            }
        }
    }

    /// Wall-clock wrapper for production call sites.
    pub fn try_allow(&self, node_id: &[u8; 32]) -> QuotaDecision {
        self.try_allow_at(node_id, Instant::now())
    }

    /// Drop buckets for identities that have been idle longer than
    /// `cleanup_idle_after`. Service calls this periodically (e.g.
    /// once an hour) from the runtime housekeeping loop.
    pub fn gc_at(&self, now: Instant) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let QuotaState { buckets, lru } = &mut *guard;
        let threshold = self.cfg.cleanup_idle_after;
        buckets.retain(|_, bucket| {
            // Trim old timestamps first so a bucket with nothing in
            // the window but recent `last_touched` can still be
            // evicted once it's been quiet long enough.
            while let Some(front) = bucket.timestamps.front().copied() {
                if now.duration_since(front) >= threshold {
                    bucket.timestamps.pop_front();
                } else {
                    break;
                }
            }
            // Keep if the identity was active within the threshold OR
            // it still has entries within the window.
            now.duration_since(bucket.last_touched) < threshold || !bucket.timestamps.is_empty()
        });
        // Rebuild the LRU index from the surviving buckets so it stays in sync
        // (gc is infrequent / not wired to a production tick, so the O(n log n)
        // rebuild is fine and keeps the invariant trivially correct).
        *lru = buckets.iter().map(|(k, b)| (b.last_touched, *k)).collect();
    }

    /// Number of identities tracked. cleanup: was `pub`
    /// claiming "metrics", but no AdminCommand / metrics gauge / IPC consumer
    /// surfaced this; downgraded to `#[cfg(test)]` test-only. Re-promote to
    /// pub when an actual consumer ships.
    #[cfg(test)]
    pub(crate) fn tracked_identities(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .buckets
            .len()
    }

    /// Drop every bucket — cleanup: doc claimed "for tests
    /// and emergency operator intervention" but no production callers
    /// ever existed. Test-only until `AdminCommand::ResetQuotas`
    /// lands.
    #[cfg(test)]
    pub(crate) fn reset(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.buckets.clear();
        guard.lru.clear();
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(cap: u32, window_secs: u64) -> IdentityQuotaConfig {
        IdentityQuotaConfig {
            max_writes_per_window: cap,
            window: Duration::from_secs(window_secs),
            cleanup_idle_after: Duration::from_secs(window_secs * 4),
            max_identities: veil_proto::budget::MAX_IDENTITY_WRITE_QUOTA_SIZE,
        }
    }

    /// Audit cycle-5 (#6): the identity map must stay bounded under attacker
    /// node_id rotation, with NO dependence on a GC scheduler.
    #[test]
    fn identity_map_is_bounded_by_max_identities_6() {
        let mut c = cfg(10, 3600);
        c.max_identities = 4; // small cap for the test
        let q = IdentityWriteQuota::new(c);
        let mut now = Instant::now();
        for i in 0..100u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            q.try_allow_at(&id, now);
            now += Duration::from_millis(1); // distinct last_touched for LRU
        }
        assert!(
            q.tracked_identities() <= 4,
            "map must stay bounded at max_identities, got {}",
            q.tracked_identities()
        );
    }

    /// Audit cycle-6 (P9): the BTreeSet LRU index must evict the genuinely
    /// least-recently-*touched* identity — including the case where an old
    /// identity is re-touched and must then survive a later eviction. This
    /// proves the O(log n) index reproduces the old `min_by_key` choice and
    /// that the touch-refresh keeps the index in sync.
    #[test]
    fn lru_index_evicts_least_recently_touched_p9() {
        let mut c = cfg(10, 3600);
        c.max_identities = 3;
        let q = IdentityWriteQuota::new(c);
        let id = |n: u8| {
            let mut x = [0u8; 32];
            x[0] = n;
            x
        };
        let t0 = Instant::now();
        // Fill: A@t0, B@t0+1, C@t0+2. LRU order: A < B < C.
        q.try_allow_at(&id(0xA), t0);
        q.try_allow_at(&id(0xB), t0 + Duration::from_millis(1));
        q.try_allow_at(&id(0xC), t0 + Duration::from_millis(2));
        // Re-touch A at t0+3 → A is now the MOST recent; B is the oldest.
        q.try_allow_at(&id(0xA), t0 + Duration::from_millis(3));
        // Insert D at t0+4 → at capacity, must evict the LRU = B (not A).
        q.try_allow_at(&id(0xD), t0 + Duration::from_millis(4));

        assert_eq!(q.tracked_identities(), 3);
        // B must be gone; A (re-touched), C, D survive. Verify by checking that
        // B starts a fresh quota (allowed) while A is still tracked.
        let st = q.state.lock().unwrap();
        assert!(
            !st.buckets.contains_key(&id(0xB)),
            "LRU victim B must be evicted"
        );
        assert!(
            st.buckets.contains_key(&id(0xA)),
            "re-touched A must survive"
        );
        assert!(st.buckets.contains_key(&id(0xC)));
        assert!(st.buckets.contains_key(&id(0xD)));
        // Index invariant: exactly one lru entry per bucket.
        assert_eq!(st.lru.len(), st.buckets.len());
    }

    #[test]
    fn allows_writes_up_to_cap() {
        let q = IdentityWriteQuota::new(cfg(3, 3600));
        let id = [0x11u8; 32];
        let now = Instant::now();
        assert!(matches!(
            q.try_allow_at(&id, now),
            QuotaDecision::Allowed { current: 1, cap: 3 }
        ));
        assert!(matches!(
            q.try_allow_at(&id, now),
            QuotaDecision::Allowed { current: 2, cap: 3 }
        ));
        assert!(matches!(
            q.try_allow_at(&id, now),
            QuotaDecision::Allowed { current: 3, cap: 3 }
        ));
    }

    #[test]
    fn rate_limits_the_excess_write() {
        let q = IdentityWriteQuota::new(cfg(2, 3600));
        let id = [0x11u8; 32];
        let now = Instant::now();
        assert!(q.try_allow_at(&id, now).is_allowed());
        assert!(q.try_allow_at(&id, now).is_allowed());
        match q.try_allow_at(&id, now) {
            QuotaDecision::RateLimited {
                current: 2, cap: 2, ..
            } => {}
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn window_slide_releases_quota() {
        let q = IdentityWriteQuota::new(cfg(2, 10));
        let id = [0x11u8; 32];
        let t0 = Instant::now();
        assert!(q.try_allow_at(&id, t0).is_allowed());
        assert!(q.try_allow_at(&id, t0).is_allowed());
        assert!(matches!(
            q.try_allow_at(&id, t0),
            QuotaDecision::RateLimited { .. }
        ));

        // Advance past the window — both entries slide out.
        let later = t0 + Duration::from_secs(11);
        assert!(q.try_allow_at(&id, later).is_allowed());
    }

    #[test]
    fn retry_after_reflects_earliest_entry_age() {
        let q = IdentityWriteQuota::new(cfg(1, 100));
        let id = [0x11u8; 32];
        let t0 = Instant::now();
        q.try_allow_at(&id, t0);
        // 40 s later we're still over cap; retry_after should be ~60 s.
        let later = t0 + Duration::from_secs(40);
        match q.try_allow_at(&id, later) {
            QuotaDecision::RateLimited { retry_after, .. } => {
                // Allow a 1-second tolerance for Instant math.
                let expected = Duration::from_secs(60);
                let delta = retry_after.abs_diff(expected);
                assert!(delta <= Duration::from_secs(1), "{retry_after:?}");
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn identities_are_tracked_independently() {
        let q = IdentityWriteQuota::new(cfg(1, 3600));
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let now = Instant::now();
        assert!(q.try_allow_at(&a, now).is_allowed());
        // a is exhausted; b must still get one.
        assert!(q.try_allow_at(&b, now).is_allowed());
        assert!(matches!(
            q.try_allow_at(&a, now),
            QuotaDecision::RateLimited { .. }
        ));
        assert!(matches!(
            q.try_allow_at(&b, now),
            QuotaDecision::RateLimited { .. }
        ));
    }

    #[test]
    fn default_policy_uses_ten_per_hour() {
        let q = IdentityWriteQuota::default_policy();
        let id = [0u8; 32];
        let now = Instant::now();
        let mut allowed = 0;
        for _ in 0..15 {
            if q.try_allow_at(&id, now).is_allowed() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, DEFAULT_MAX_WRITES_PER_HOUR);
    }

    #[test]
    fn gc_evicts_idle_buckets() {
        let q = IdentityWriteQuota::new(cfg(5, 100));
        let id = [0x11u8; 32];
        let t0 = Instant::now();
        q.try_allow_at(&id, t0);
        assert_eq!(q.tracked_identities(), 1);
        // Well past cleanup_idle_after (= 400 s).
        let way_later = t0 + Duration::from_secs(1000);
        q.gc_at(way_later);
        assert_eq!(q.tracked_identities(), 0);
    }

    #[test]
    fn gc_retains_recently_touched_buckets() {
        let q = IdentityWriteQuota::new(cfg(5, 100));
        let id = [0x11u8; 32];
        let t0 = Instant::now();
        q.try_allow_at(&id, t0);
        // Touch recently (just past window but inside cleanup threshold).
        let recent = t0 + Duration::from_secs(200);
        q.try_allow_at(&id, recent);
        q.gc_at(recent + Duration::from_secs(1));
        assert_eq!(q.tracked_identities(), 1);
    }

    #[test]
    fn reset_clears_all_state() {
        let q = IdentityWriteQuota::default_policy();
        let id = [0x11u8; 32];
        let now = Instant::now();
        q.try_allow_at(&id, now);
        assert_eq!(q.tracked_identities(), 1);
        q.reset();
        assert_eq!(q.tracked_identities(), 0);
    }

    #[test]
    fn bursts_are_correctly_accounted_as_window_slides_in_pieces() {
        // Scenario: 5 writes spaced 1s apart starting at t=0, quota
        // is 5 per 30 s. Between t=5 and t=29 we're at cap (5 ≤ 5)
        // so further attempts rate-limit. At t=31 s the first
        // write has aged out, giving back exactly one slot.
        let q = IdentityWriteQuota::new(cfg(5, 30));
        let id = [0u8; 32];
        let t0 = Instant::now();
        for i in 0..5 {
            let at = t0 + Duration::from_secs(i);
            assert!(q.try_allow_at(&id, at).is_allowed(), "burst {i} failed");
        }
        for t in 5..30 {
            let at = t0 + Duration::from_secs(t);
            assert!(
                matches!(q.try_allow_at(&id, at), QuotaDecision::RateLimited { .. }),
                "expected rate-limit at t={t}s"
            );
        }
        // At t=31 s: entries at t=0 and t=1 are now outside the
        // 30 s window (age 31 and 30), so they've aged out. The
        // remaining entries are at t=2,3,4 → count=3, cap=5, so two
        // more writes are allowed, then the next is rate-limited.
        let at_31 = t0 + Duration::from_secs(31);
        assert!(q.try_allow_at(&id, at_31).is_allowed()); // count 4
        assert!(q.try_allow_at(&id, at_31).is_allowed()); // count 5
        assert!(matches!(
            q.try_allow_at(&id, at_31),
            QuotaDecision::RateLimited { .. }
        ));
    }

    #[test]
    fn config_default_is_ten_per_hour() {
        let c = IdentityQuotaConfig::default();
        assert_eq!(c.max_writes_per_window, 10);
        assert_eq!(c.window, Duration::from_secs(3600));
    }

    #[test]
    fn wallclock_wrapper_does_not_panic() {
        // Smoke test: exercise the `try_allow` (wall-clock) path to
        // ensure the wiring compiles and doesn't panic.
        let q = IdentityWriteQuota::default_policy();
        let id = [0xFFu8; 32];
        assert!(q.try_allow(&id).is_allowed());
    }
}
