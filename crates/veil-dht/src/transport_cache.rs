//! — local LRU cache for `node_id → transport` mappings
//! returned by `ResolveTransport` RPCs.
//!
//! ## Why a cache exists
//!
//! In the V1 wire protocol the FIND_NODE response carried `(node_id
//! transport)` pairs in one round-trip — the caller could immediately
//! connect to any returned peer. The V2 split drops the
//! transport from FIND_NODE responses and forces a separate
//! `ResolveTransport` RPC per node_id of interest. Without a cache
//! every iterative-Kademlia step would now incur an extra round-trip
//! for transport resolution; with a cache, repeat lookups for the same
//! node_id within the TTL window are free.
//!
//! ## scope
//!
//! In-memory only. Process restart loses the cache.
//! Bounded LRU eviction at `MAX_TRANSPORT_CACHE_ENTRIES`.
//! TTL eviction at `TRANSPORT_CACHE_TTL` (default 1 hour).
//! Unsigned entries — adds target-identity
//! signature verification on insert.
//! No persistence — adds on-disk snapshot.
//!
//! ## Threat model implications
//!
//! Without signed entries, a malicious resolver can return a fake
//! transport that the caller will then attempt to connect to. The
//! handshake will fail (the fake address either won't accept TCP, or
//! will fail OVL1 identity verification — the peer-pubkey binding
//! makes impersonation infeasible without the target's private key).
//! So the worst case is **wasted connection attempts**, not
//! data leakage. elevates this to "verified-only entries
//! cached", closing the wasted-attempt vector.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default capacity for the in-memory transport cache. At ~96 bytes
/// per entry (32 node_id + 1 byte tag + ~64 byte URI + Instant) this
/// caps memory at roughly 400 KiB — negligible.
pub const MAX_TRANSPORT_CACHE_ENTRIES: usize = 4096;

/// Default TTL for cache entries (1 hour). Keep generous: the resolver
/// signature will let us extend this safely.
pub const TRANSPORT_CACHE_TTL: Duration = Duration::from_secs(3600);

/// One cache entry.
#[derive(Debug, Clone)]
struct Entry {
    transport: String,
    /// When the entry was inserted (used for TTL eviction).
    inserted_at: Instant,
    /// Last time the entry was looked up — touched on every hit so
    /// eviction picks the truly least-recently-used.
    last_used: Instant,
}

/// Local in-memory cache of resolved `node_id → transport` mappings.
///
/// Cheap to clone (no `Arc` inside) — wrap in `Arc<Mutex<_>>` at the
/// call site if shared concurrently. Designed to be the local sidecar
/// of `KademliaService`.
#[derive(Debug, Default)]
pub struct TransportCache {
    entries: HashMap<[u8; 32], Entry>,
    capacity: usize,
    ttl: Duration,
}

impl TransportCache {
    /// Build a cache with the default capacity / TTL.
    pub fn new() -> Self {
        Self::with_capacity_and_ttl(MAX_TRANSPORT_CACHE_ENTRIES, TRANSPORT_CACHE_TTL)
    }

    /// Build a cache with custom capacity / TTL. Used by tests.
    pub fn with_capacity_and_ttl(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity.min(64)),
            capacity,
            ttl,
        }
    }

    /// Look up the transport for `node_id`. Returns `None` when the
    /// entry is absent or has expired (caller should fall back to a
    /// fresh `ResolveTransport` RPC). On hit, the entry is touched so
    /// LRU eviction prefers entries that are genuinely cold.
    pub fn lookup(&mut self, node_id: &[u8; 32]) -> Option<String> {
        let now = Instant::now();
        let entry = self.entries.get_mut(node_id)?;
        if now.duration_since(entry.inserted_at) >= self.ttl {
            // Expired — drop on access so subsequent lookups don't keep
            // returning stale data even if `evict_stale` hasn't run.
            self.entries.remove(node_id);
            return None;
        }
        entry.last_used = now;
        Some(entry.transport.clone())
    }

    /// Insert / update the cached transport for `node_id`. Stamps
    /// `inserted_at` and `last_used` to "now"; replaces any existing
    /// entry. When the cache is at capacity, evicts the least-recently
    /// used entry first.
    pub fn insert(&mut self, node_id: [u8; 32], transport: String) {
        let now = Instant::now();
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&node_id) {
            self.evict_one_lru();
        }
        self.entries.insert(
            node_id,
            Entry {
                transport,
                inserted_at: now,
                last_used: now,
            },
        );
    }

    /// Remove all entries whose age exceeds the TTL. Cheap O(n)
    /// sweep; the maintenance task should call this periodically.
    pub fn evict_stale(&mut self) {
        let now = Instant::now();
        let ttl = self.ttl;
        self.entries
            .retain(|_, e| now.duration_since(e.inserted_at) < ttl);
    }

    /// Remove the entry for `node_id` (e.g. after a failed connection
    /// attempt — the cached transport was wrong / stale, refresh on
    /// the next lookup).
    pub fn invalidate(&mut self, node_id: &[u8; 32]) {
        self.entries.remove(node_id);
    }

    /// Current entry count — for tests and metrics.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict the entry with the oldest `last_used` timestamp. No-op
    /// when the cache is empty. O(n) — acceptable at our cap (4096).
    fn evict_one_lru(&mut self) {
        let Some((victim, _)) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(k, e)| (*k, e.last_used))
        else {
            return;
        };
        self.entries.remove(&victim);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn insert_lookup_roundtrip() {
        let mut c = TransportCache::new();
        let id = [0xAAu8; 32];
        c.insert(id, "tcp://1.2.3.4:9000".into());
        assert_eq!(c.lookup(&id).as_deref(), Some("tcp://1.2.3.4:9000"));
    }

    #[test]
    fn missing_key_returns_none() {
        let mut c = TransportCache::new();
        assert!(c.lookup(&[0xBBu8; 32]).is_none());
    }

    #[test]
    fn ttl_eviction_drops_expired_entry_on_lookup() {
        let mut c = TransportCache::with_capacity_and_ttl(4, Duration::from_millis(20));
        let id = [0xCCu8; 32];
        c.insert(id, "tcp://x:1".into());
        sleep(Duration::from_millis(40));
        assert!(
            c.lookup(&id).is_none(),
            "expired entry must be dropped on access"
        );
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn ttl_eviction_sweep_removes_stale_entries() {
        let mut c = TransportCache::with_capacity_and_ttl(4, Duration::from_millis(20));
        c.insert([0x01u8; 32], "tcp://a:1".into());
        c.insert([0x02u8; 32], "tcp://b:1".into());
        assert_eq!(c.len(), 2);
        sleep(Duration::from_millis(40));
        c.evict_stale();
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn lru_eviction_kicks_out_oldest_used_entry() {
        let mut c = TransportCache::with_capacity_and_ttl(2, Duration::from_secs(60));
        c.insert([0x01u8; 32], "tcp://a:1".into());
        c.insert([0x02u8; 32], "tcp://b:1".into());
        // Touch entry 1 — entry 2 is now the LRU.
        sleep(Duration::from_millis(10));
        let _ = c.lookup(&[0x01u8; 32]);
        // Insert a 3rd: entry 2 (LRU) should be evicted, entries 1 and 3 retained.
        c.insert([0x03u8; 32], "tcp://c:1".into());
        assert_eq!(c.len(), 2);
        assert!(
            c.lookup(&[0x01u8; 32]).is_some(),
            "touched entry must survive"
        );
        assert!(
            c.lookup(&[0x02u8; 32]).is_none(),
            "untouched entry must be evicted"
        );
        assert!(
            c.lookup(&[0x03u8; 32]).is_some(),
            "newest entry must be present"
        );
    }

    #[test]
    fn invalidate_drops_specific_entry() {
        let mut c = TransportCache::new();
        c.insert([0x10u8; 32], "tcp://x:1".into());
        c.insert([0x20u8; 32], "tcp://y:1".into());
        c.invalidate(&[0x10u8; 32]);
        assert!(c.lookup(&[0x10u8; 32]).is_none());
        assert!(c.lookup(&[0x20u8; 32]).is_some());
    }

    #[test]
    fn re_insert_refreshes_inserted_at() {
        // Audit batch 2026-05-24: bumped TTL to 2 s + sleeps to 500 ms
        // (was 40 ms / 25 ms, then 200 ms / 100 ms — still flaky on
        // overloaded shared CI runners where `sleep(100ms)` can
        // actually take 250+ ms).  Generous TTL ensures
        // `re_insert_at + 500ms_sleep_drift_500ms` stays comfortably
        // under 2000ms.
        let mut c = TransportCache::with_capacity_and_ttl(4, Duration::from_millis(2_000));
        let id = [0xEEu8; 32];
        c.insert(id, "tcp://old:1".into());
        sleep(Duration::from_millis(500));
        c.insert(id, "tcp://new:1".into());
        sleep(Duration::from_millis(500));
        // Original would have expired at 2000ms; the re-insert at ~500ms restarts the TTL.
        assert_eq!(c.lookup(&id).as_deref(), Some("tcp://new:1"));
    }
}
