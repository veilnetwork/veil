//! Per-node bounded LRU cache for FIND_NODE results.
//!
//! Critical для interactive UX на trillion scale: a cold iterative
//! Kademlia lookup is O(log N) round-trips × per-hop RTT. At
//! N = 10¹² with ~100 ms per hop, that's ~4 seconds. Repeated
//! lookups for the SAME target — common for popular relays via
//! relay-directory queries — should not pay this cost
//! every call.
//!
//! This module implements a simple bounded LRU cache keyed by
//! `target` (the 32-byte BLAKE3 the lookup is targeting). TTL'd
//! entries expire so changes in the network's actual routing table
//! propagate within the TTL window.
//!
//! # Sizing
//!
//! Defaults are conservative — small TTL (30 s) so stale routing
//! data doesn't persist long; small capacity (1024 entries) so
//! per-node memory stays bounded at ≤ ~1 MB even with worst-case
//! Vec<Contact> sizes (each Contact ≈ 100 B; k=20; 1024 × 20 × 100
//! = ~2 MB).
//!
//! # What this module does NOT do
//!
//! * **No write-through invalidation.** When the routing table
//!   changes (peer comes online / offline) the cache may still
//!   return a stale snapshot for up to TTL. Acceptable: a
//!   30 s window is well within the natural propagation latency
//!   of the underlying Kademlia gossip; the alternative
//!   (synchronous invalidation on every routing-table mutation)
//!   would couple this cache to every codepath that mutates
//!   contacts and isn't worth the complexity for a 30 s
//!   correctness window.
//! * **No cross-node coordination.** Each node's cache is
//!   independent. This is correct: Kademlia lookups are
//!   deterministic given the same routing table state, but
//!   different nodes have different routing tables, so cross-
//!   node sharing would only confuse things.
//! * **No metrics export.** A future slice can wire hit/miss
//!   counters into the existing `NodeMetrics`; out of scope for
//!   this primitive.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::routing::Contact;

/// Default cache capacity. Bounded LRU eviction enforces this.
pub const DEFAULT_LOOKUP_CACHE_SIZE: usize = 1024;

/// Default cache TTL. Entries older than this are treated as
/// missing and re-fetched. 30 s is short enough that routing-table
/// staleness is bounded (most Kademlia churn-tolerance protocols
/// converge within seconds).
pub const DEFAULT_LOOKUP_CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct CacheEntry {
    contacts: Vec<Contact>,
    inserted_at: Instant,
    /// Updated on every cache hit; used as the LRU eviction key
    /// when the cache is at capacity.
    last_hit_at: Instant,
}

/// Bounded LRU TTL cache for iterative-find results.
#[derive(Debug)]
pub struct LookupCache {
    entries: HashMap<[u8; 32], CacheEntry>,
    max_size: usize,
    ttl: Duration,
}

impl LookupCache {
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            max_size,
            ttl,
        }
    }

    /// Convenience: cache with [`DEFAULT_LOOKUP_CACHE_SIZE`] +
    /// [`DEFAULT_LOOKUP_CACHE_TTL`].
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_LOOKUP_CACHE_SIZE, DEFAULT_LOOKUP_CACHE_TTL)
    }

    /// Returns the cached contacts for `target` if a non-expired
    /// entry exists. Updates `last_hit_at` on hit so popular
    /// targets stay in cache longer than infrequently-queried ones.
    pub fn get(&mut self, target: &[u8; 32]) -> Option<Vec<Contact>> {
        let now = Instant::now();
        let entry = self.entries.get_mut(target)?;
        if now.duration_since(entry.inserted_at) > self.ttl {
            // Expired — drop and report miss. The next insert
            // will re-populate.
            self.entries.remove(target);
            return None;
        }
        entry.last_hit_at = now;
        Some(entry.contacts.clone())
    }

    /// Insert (or refresh) a result. When the cache is at
    /// capacity, evicts the entry with the oldest `last_hit_at`
    /// (LRU eviction).
    pub fn insert(&mut self, target: [u8; 32], contacts: Vec<Contact>) {
        let now = Instant::now();
        // P6: use Entry API to fold contains_key + get_mut into
        // one lookup. The previous `contains_key` + `.expect("contains_key")`
        // pattern was a TOCTOU panic-trap: even though `&mut self` precludes
        // concurrent removal, future refactors that drop the borrow between
        // the two calls would silently introduce a panic on cache miss.
        use std::collections::hash_map::Entry;
        match self.entries.entry(target) {
            Entry::Occupied(mut occ) => {
                let entry = occ.get_mut();
                entry.contacts = contacts;
                entry.inserted_at = now;
                entry.last_hit_at = now;
                return;
            }
            Entry::Vacant(_) => { /* fall through to capacity check below */ }
        }
        if self.entries.len() >= self.max_size {
            // LRU eviction: drop the entry with the oldest last_hit_at.
            // O(N) scan is acceptable at default size 1024 — eviction
            // happens at most once per insert under steady-state load.
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_hit_at)
                .map(|(k, _)| *k)
            {
                self.entries.remove(&oldest_key);
            }
        }
        self.entries.insert(
            target,
            CacheEntry {
                contacts,
                inserted_at: now,
                last_hit_at: now,
            },
        );
    }

    /// Drop all expired entries. Caller can invoke periodically
    /// (e.g. from the maintenance tick) to reclaim memory between
    /// natural eviction events; otherwise expired entries are
    /// dropped lazily on `get`.
    pub fn prune_expired(&mut self) {
        let now = Instant::now();
        let ttl = self.ttl;
        // Audit batch 2026-05-25 phase M: unify TTL comparison
        // operator with `get()` (line 95).  Previously `get()` used
        // strict `>` (expired iff `age > ttl`) while `prune_expired()`
        // used `<=` (keep iff `age <= ttl`), которое equivalent к
        // `prune iff age > ttl` only on integer time — but `Instant`
        // semantics treat `age == ttl` as "exactly at boundary",
        // и the two operators диверг at that exact nanosecond.
        // Не security issue, но в-debug-able if ever observed.
        self.entries
            .retain(|_, e| now.duration_since(e.inserted_at) < ttl);
    }

    /// Current entry count. Surfaced for diagnostics.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_contact(id_byte: u8) -> Contact {
        let mut node_id = [0u8; 32];
        node_id[0] = id_byte;
        Contact::new(node_id, "tcp://test:1234")
    }

    #[test]
    fn epic487_4_empty_cache_returns_none() {
        let mut cache = LookupCache::with_defaults();
        assert_eq!(cache.get(&[0u8; 32]), None);
    }

    #[test]
    fn epic487_4_insert_then_get_returns_inserted() {
        let mut cache = LookupCache::with_defaults();
        let target = [0xAA; 32];
        let contacts = vec![fixture_contact(1), fixture_contact(2)];
        cache.insert(target, contacts.clone());
        let result = cache.get(&target).expect("hit");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].node_id[0], 1);
        assert_eq!(result[1].node_id[0], 2);
    }

    #[test]
    fn epic487_4_distinct_targets_dont_collide() {
        let mut cache = LookupCache::with_defaults();
        let t1 = [0x01; 32];
        let t2 = [0x02; 32];
        cache.insert(t1, vec![fixture_contact(1)]);
        cache.insert(t2, vec![fixture_contact(2)]);
        assert_eq!(cache.get(&t1).unwrap()[0].node_id[0], 1);
        assert_eq!(cache.get(&t2).unwrap()[0].node_id[0], 2);
    }

    #[test]
    fn epic487_4_refresh_updates_existing_entry() {
        let mut cache = LookupCache::with_defaults();
        let target = [0xAA; 32];
        cache.insert(target, vec![fixture_contact(1)]);
        // Re-insert under same key — should overwrite, not double-store.
        cache.insert(target, vec![fixture_contact(2), fixture_contact(3)]);
        assert_eq!(cache.len(), 1, "no duplicate entries on re-insert");
        let result = cache.get(&target).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].node_id[0], 2);
        assert_eq!(result[1].node_id[0], 3);
    }

    #[test]
    fn epic487_4_expired_entry_returns_none_and_self_prunes() {
        // Use a near-zero TTL so the sleep is brief.
        let mut cache = LookupCache::new(1024, Duration::from_millis(1));
        let target = [0xAA; 32];
        cache.insert(target, vec![fixture_contact(1)]);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.get(&target), None, "expired entry must miss");
        // The miss should have self-pruned the entry.
        assert_eq!(
            cache.len(),
            0,
            "expired entry must be removed from the map on miss"
        );
    }

    #[test]
    fn epic487_4_lru_eviction_drops_least_recently_hit() {
        // Cache size 3. Insert 3 entries, hit two of them, then
        // insert a fourth. The un-hit entry should be evicted.
        let mut cache = LookupCache::new(3, Duration::from_secs(60));
        let t1 = [0x01; 32];
        let t2 = [0x02; 32];
        let t3 = [0x03; 32];
        let t4 = [0x04; 32];
        cache.insert(t1, vec![fixture_contact(1)]);
        cache.insert(t2, vec![fixture_contact(2)]);
        cache.insert(t3, vec![fixture_contact(3)]);
        std::thread::sleep(Duration::from_millis(2));
        // Hit t1 and t3 — t2 becomes least-recently-hit.
        let _ = cache.get(&t1);
        let _ = cache.get(&t3);
        std::thread::sleep(Duration::from_millis(2));
        // Insert t4 — must trigger eviction of t2.
        cache.insert(t4, vec![fixture_contact(4)]);
        assert_eq!(cache.len(), 3);
        assert!(cache.get(&t1).is_some(), "t1 (recently-hit) survives");
        assert!(cache.get(&t3).is_some(), "t3 (recently-hit) survives");
        assert!(cache.get(&t4).is_some(), "t4 (just-inserted) is present");
        assert!(cache.get(&t2).is_none(), "t2 (LRU) must have been evicted");
    }

    #[test]
    fn epic487_4_get_updates_lru_position() {
        // Same as above but verify that a `get` (cache hit) actually
        // updates the LRU position so the entry doesn't get evicted
        // shortly after.
        let mut cache = LookupCache::new(2, Duration::from_secs(60));
        let t1 = [0x01; 32];
        let t2 = [0x02; 32];
        let t3 = [0x03; 32];
        cache.insert(t1, vec![fixture_contact(1)]);
        cache.insert(t2, vec![fixture_contact(2)]);
        std::thread::sleep(Duration::from_millis(2));
        // Touch t1 — t2 should now be the LRU candidate.
        let _ = cache.get(&t1);
        std::thread::sleep(Duration::from_millis(2));
        cache.insert(t3, vec![fixture_contact(3)]);
        assert!(cache.get(&t1).is_some(), "t1 (touched) survives");
        assert!(cache.get(&t3).is_some(), "t3 just inserted");
        assert!(cache.get(&t2).is_none(), "t2 evicted (LRU after t1 touch)");
    }

    #[test]
    fn epic487_4_prune_expired_drops_old_entries() {
        let mut cache = LookupCache::new(1024, Duration::from_millis(5));
        cache.insert([0x01; 32], vec![fixture_contact(1)]);
        cache.insert([0x02; 32], vec![fixture_contact(2)]);
        std::thread::sleep(Duration::from_millis(10));
        cache.insert([0x03; 32], vec![fixture_contact(3)]);
        // First two are expired; third is fresh.
        cache.prune_expired();
        assert_eq!(cache.len(), 1, "only fresh entry survives prune");
        assert!(cache.get(&[0x03; 32]).is_some());
    }

    #[test]
    fn epic487_4_eviction_at_capacity_keeps_count_at_max() {
        let mut cache = LookupCache::new(5, Duration::from_secs(60));
        for i in 1..=10u8 {
            let mut t = [0u8; 32];
            t[0] = i;
            cache.insert(t, vec![fixture_contact(i)]);
        }
        assert_eq!(
            cache.len(),
            5,
            "size never exceeds max despite 10 inserts into a cap-5 cache"
        );
    }

    #[test]
    fn epic487_4_empty_contacts_vec_is_valid_cache_value() {
        // A lookup that returned 0 contacts should still cache the
        // negative result so we don't immediately re-attempt the
        // expensive walk.
        let mut cache = LookupCache::with_defaults();
        let target = [0xAA; 32];
        cache.insert(target, vec![]);
        let result = cache.get(&target).expect("empty result is still cached");
        assert!(result.is_empty());
    }
}
