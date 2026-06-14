//! Trait surfaces that veilcore must implement to wire its concrete
//! services into the DHT.
//!
//! Also hosts [`DhtRuntimeConfig`] — the subset of veilcore's
//! `cfg::DhtConfig` that DHT internals actually consume. Veilcore
//! provides a `From<&DhtConfig>` impl so existing call sites still
//! pass a full config; the conversion drops the persistence-path fields
//! that DHT itself does not touch.

use tokio::sync::oneshot;

/// Dispatch a request frame to a specific peer over an established session.
///
/// Implemented by `veilcore::node::session::outbox::SessionOutbox`.
/// Returns the receiver for the matching response, or `None` if no
/// session is registered for `peer`.
pub trait FrameRouter: Send + Sync {
    fn send_request(
        &self,
        peer: [u8; 32],
        request_id: u32,
        frame: Vec<u8>,
    ) -> Option<oneshot::Receiver<Option<Vec<u8>>>>;

    /// Snapshot of currently-connected peer ids — used by the DHT
    /// republish path to multicast STORE frames to every active session.
    fn peer_ids(&self) -> Vec<[u8; 32]>;
}

/// Per-peer smoothed-RTT hint used by [`crate::routing`] as a tie-breaker
/// when XOR distance ties.
///
/// Implemented by `veilcore::node::routing::probe::RttTable`.
pub trait RttHint: Send + Sync {
    /// Smoothed RTT for `peer` in milliseconds, or `None` if unknown.
    fn rtt_ms(&self, peer: &[u8; 32]) -> Option<u32>;
}

/// Per-peer Vivaldi-distance estimator. Returns the
/// network-distance estimate from this node to `peer` when both
/// coordinates are known.
///
/// Implemented by an veilcore adapter wrapping the local
/// `Arc<Mutex<VivaldiCoord>>` and the per-peer cache.
pub trait CoordinateOracle: Send + Sync {
    /// Estimated network distance to `peer` (Vivaldi units). `None` if
    /// either the local coordinate or the peer's coordinate is unknown.
    fn estimated_distance(&self, peer: &[u8; 32]) -> Option<f64>;
}

/// Counters incremented by the DHT at notable events. Implemented by
/// `veilcore::node::observability::NodeMetrics`.
pub trait DhtMetrics: Send + Sync {
    fn inc_dht_store(&self);
    fn inc_dht_lookup(&self);
}

/// Verifier for P-Net DHT-replicated authentication records. Implemented
/// by an veilcore adapter wrapping `NetworkAccessGate` — veil-dht
/// stays oblivious to the cert / ban schema, just routes incoming STOREs
/// here when the value carries the P-Net authentication magic prefix.
///
/// Returns `true` if the STORE is allowed (record decoded + verified +
/// key matches the derived ban-DHT key). Returns `false` for any failure
/// — the DHT layer rejects with [`crate::kademlia::KademliaError::InvalidNetworkRecord`].
pub trait NetworkAuthGate: Send + Sync {
    /// Verify a STORE payload that carries the P-Net `PBAN` magic.
    /// `key` is the DHT key (must derive of the ban target); `value` is
    /// the encoded ban blob (including the magic prefix).
    fn verify_ban_record(&self, key: &[u8; 32], value: &[u8]) -> bool;
}

/// Subset of `cfg::DhtConfig` consumed by the DHT internals. Mirror
/// kept here so this crate doesn't import the full config schema.
///
/// `Default` matches the defaults baked into `cfg::DhtConfig::default_*`
/// (k = 20, α = 3, max_rounds = 20, find_node_timeout_ms = 2000
/// vivaldi_weight = 0.3, max_store_entries = 25_000, …). Veilcore
/// provides a `From<&DhtConfig>` impl in `cfg::dht_glue`.
/// (audit doc-sync: the default is 25_000 × 16 KiB values, not the stale
/// 100_000 × 4 KiB this comment used to quote.)
#[derive(Clone, Debug, PartialEq)]
pub struct DhtRuntimeConfig {
    pub republish_interval_secs: u64,
    pub cleanup_interval_secs: u64,
    pub participate: bool,
    pub k: u8,
    pub alpha: u8,
    pub max_rounds: u8,
    pub find_node_timeout_ms: u64,
    pub vivaldi_weight: f64,
    pub max_store_entries: usize,
    /// Optional global byte budget for the TieredStore.  See
    /// `veil_cfg::DhtConfig::max_store_bytes` (audit batch 2026-05-23).
    /// `None` = no byte cap, only the entry cap applies.
    pub max_store_bytes: Option<u64>,
    /// Per-signer byte budget (Phase 11e).  See
    /// `veil_cfg::DhtConfig::per_origin_max_bytes`.  `None` = no
    /// per-origin cap; a single misbehaving signer can still saturate
    /// up to the global cap (or the entry cap when the global cap is
    /// `None`).
    pub per_origin_max_bytes: Option<u64>,
    /// Optional filesystem path for a disk-backed **RocksDB cold tier**.
    /// When `Some(path)` AND the node binary is built with the
    /// `rocksdb-cold` feature, DHT values that age out of the in-memory hot
    /// tier are demoted to a persistent on-disk store instead of the bounded
    /// in-memory cold map — letting a dedicated DHT node hold > 1M entries
    /// without the RAM cost, and surviving restarts. `None` (default) keeps
    /// the all-in-memory tiered store. See `veil_cfg::DhtConfig::cold_store_path`.
    /// Ignored (with a startup log line) when the feature is absent or the
    /// RocksDB open fails — the store falls back to the in-memory cold tier.
    pub cold_store_path: Option<String>,
    pub shard_filtering: bool,
    /// allow `StorePayload` ingestion that
    /// carries no `(ed25519_pubkey, ed25519_sig)` tuple.
    ///
    /// Default `false` — production deployments require every STORE to
    /// be signed by the key whose `BLAKE3(pubkey)` equals the DHT key
    /// so a misbehaving peer cannot fill the `TieredStore` with
    /// arbitrary `(key, value)` entries that evict honest records.
    ///
    /// Set `true` only for development / unit-test fixtures that mint
    /// raw records (e.g. test-only mailbox envelopes) without the
    /// signing infrastructure. The runtime's production configuration
    /// pins this off.
    pub allow_unsigned_store: bool,
}

impl Default for DhtRuntimeConfig {
    fn default() -> Self {
        Self {
            republish_interval_secs: 1800,
            cleanup_interval_secs: 60,
            participate: true,
            k: 20,
            alpha: 3,
            max_rounds: 20,
            find_node_timeout_ms: 2000,
            vivaldi_weight: 0.3,
            // ≈400 MB worst-case (25_000 × MAX_DHT_VALUE_BYTES 16 KiB); kept
            // in sync with veil_cfg::DhtConfig::default_max_store_entries.
            max_store_entries: 25_000,
            // Mirror veil_cfg::DhtConfig::default_max_store_bytes (Some(400 MB)).
            // Production wires this via `runtime_config_from`; keeping the cap
            // here too means the public `KademliaService::new()` is byte-bounded
            // by default rather than silently unbounded against its own docs.
            // The cap is large enough that no unit test / bench trips it.
            max_store_bytes: Some(400_000_000),
            per_origin_max_bytes: None,
            cold_store_path: None,
            shard_filtering: false,
            // secure default — unsigned STOREs
            // are rejected. Tests / dev-fixtures override to `true`.
            allow_unsigned_store: false,
        }
    }
}
