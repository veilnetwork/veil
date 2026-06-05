pub mod abuse;
pub mod anonymity;
pub mod anycast;
pub mod app;
pub mod bootstrap;
// Phase 3 prep: `CongestionMonitor` → `veil-congestion` sibling crate.
pub use veil_congestion as congestion;
pub mod dht;
pub use veil_node_runtime::dht_glue;
pub mod discovery;
// Phase 3: `dispatcher` → `veil-dispatcher` sibling crate.
pub use veil_dispatcher as dispatcher;
pub mod gateway;
pub mod gateway_list;
// Phase 4: identity re-export shim moved к veil-node-runtime as identity_local
// (publisher_dht + anonymity_x25519 stayed с runtime).  Existing
// `crate::node::identity::*` users continue via this re-export of veil-
// identity at the same path.
pub mod identity {
    pub use veil_identity::*;
    pub use veil_node_runtime::identity_local::{anonymity_x25519, publisher_dht};
}
pub use veil_node_runtime::memory;
pub mod mesh;
pub use veil_node_runtime::mesh_glue;
pub mod nat;
// Phase 2 session 2 prep: `NetworkAccessGate` → `veil-identity::network_access`.
pub use veil_identity::network_access;
pub mod observability;
pub use veil_node_runtime::proxy;
// Phase 2 session 2 prep: `rendezvous` → `session::rendezvous` (session-domain).
pub use session::rendezvous;
// Phase 3 prep: `ReputationTracker` → `veil-reputation` sibling crate.
pub use veil_reputation as reputation;
pub mod routing;
// Phase 4 prep: `ScannerShield` → `veil-abuse::scanner_shield`.
pub mod session;
pub mod session_glue;
pub mod transfer;
pub mod transport_hints;
pub mod update;

// Phase 4 (veilcore extraction): runtime + admin + adapters moved к
// `veil-node-runtime` sibling crate.  Audit batch 2026-05-21 Phase
// D12 pruned the 25+ shim re-exports here; consumers use direct
// `veil_node_runtime::*` paths.  Only the top-level trio kept as а
// convenience because it's used by veil-cli error-mapping and
// runtime-entry glue everywhere.

pub use veil_node_runtime::{NodeError, NodeRuntime, Result};

// ── LRU peer cache tests ──────────────────────────────────────────
#[cfg(test)]
mod peer_lru_cache_tests {
    use crate::proto::budget::MAX_PEER_PUBKEYS_CACHE;
    use veil_types::PeerLruCache;

    #[test]
    fn insert_max_plus_one_evicts_oldest() {
        let mut cache = PeerLruCache::<u8>::with_capacity(16);
        let first_key = [0u8; 32];

        // Fill to capacity.
        for i in 0..MAX_PEER_PUBKEYS_CACHE {
            let mut key = [0u8; 32];
            key[0] = (i & 0xFF) as u8;
            key[1] = ((i >> 8) & 0xFF) as u8;
            cache.insert_lru(key, i as u8, MAX_PEER_PUBKEYS_CACHE);
        }
        assert!(
            cache.contains_key(&first_key),
            "first key must be present before eviction"
        );

        // One more insert — must evict the oldest (first_key).
        let last_key = [0xFF; 32];
        cache.insert_lru(last_key, 99u8, MAX_PEER_PUBKEYS_CACHE);

        assert!(
            !cache.contains_key(&first_key),
            "oldest key must have been evicted"
        );
        assert!(
            cache.contains_key(&last_key),
            "newly inserted key must be present"
        );
    }

    #[test]
    fn re_insert_same_key_does_not_duplicate_order() {
        let mut cache = PeerLruCache::<u8>::with_capacity(16);
        let key = [1u8; 32];

        cache.insert_lru(key, 1, 4);
        cache.insert_lru(key, 2, 4); // re-insert same key

        // Value is updated.
        assert_eq!(cache.get(&key), Some(&2));

        // Fill 3 more entries — key from above should NOT be evicted until 4th new key.
        for i in 0u8..3 {
            let mut k = [0u8; 32];
            k[0] = i + 10;
            cache.insert_lru(k, i, 4);
        }
        // Cache at capacity=4; original key still present.
        assert!(cache.contains_key(&key));
    }
}

// LRU peer cache: canonical impl lives в `veil_types::PeerLruCache` since
// Phase 3 prep (veilcore extraction); consumers import от there directly.
// `NodeState`, `LinkId`, `PeerSource`, и other runtime-side types likewise
// больше не re-exported here (audit batch 2026-05-21 Phase D12) — consumers
// use `veil_node_runtime::{state,types}::*` directly.
