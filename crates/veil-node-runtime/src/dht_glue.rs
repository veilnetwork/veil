//! Glue layer between veilcore's concrete services and the
//! `veil-dht` trait surfaces (`FrameRouter`, `RttHint`
//! `CoordinateOracle`, `DhtMetrics`).
//!
//! extraction kept veil-dht free of `node::session::outbox`
//! `node::routing::{probe, vivaldi}`, and `node::observability` by
//! inverting those deps into traits. This module owns the corresponding
//! adapters.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use veil_util::{lock, rlock};

use crate::types::NodeIdBytes;
use veil_routing::{probe::RttTable, vivaldi::VivaldiCoord};

/// Type alias mirror of veilcore's per-peer Vivaldi cache. Lives in
/// `node::dispatcher` originally; re-named here so the adapter can hold
/// it without re-importing the dispatcher.
pub type PeerVivaldiCache = Arc<RwLock<HashMap<NodeIdBytes, (VivaldiCoord, Instant)>>>;

// ── FrameRouter ───────────────────────────────────────────────────────────────
// `impl veil_dht::FrameRouter for SessionOutbox` moved к
// `veil_session::outbox` после Phase 2 session 2 — see
// `crates/veil-session/src/outbox.rs`.  Orphan-rule consequence:
// neither trait nor struct is local к veilcore after the move.

// ── RttHint ───────────────────────────────────────────────────────────────────

/// `Arc<Mutex<RttTable>>` adapter that exposes the trait method `&self`.
pub struct RttHintAdapter {
    inner: Arc<Mutex<RttTable>>,
}

impl RttHintAdapter {
    pub fn new(inner: Arc<Mutex<RttTable>>) -> Self {
        Self { inner }
    }
}

impl veil_dht::RttHint for RttHintAdapter {
    fn rtt_ms(&self, peer: &[u8; 32]) -> Option<u32> {
        lock!(self.inner).get(peer).map(|p| p.rtt_ms)
    }
}

// ── CoordinateOracle ──────────────────────────────────────────────────────────

/// Combines the local Vivaldi coordinate and a per-peer cache into a
/// single `estimated_distance(peer)` query.
pub struct VivaldiOracle {
    local: Arc<Mutex<VivaldiCoord>>,
    peers: PeerVivaldiCache,
}

impl VivaldiOracle {
    pub fn new(local: Arc<Mutex<VivaldiCoord>>, peers: PeerVivaldiCache) -> Self {
        Self { local, peers }
    }
}

impl veil_dht::CoordinateOracle for VivaldiOracle {
    fn estimated_distance(&self, peer: &[u8; 32]) -> Option<f64> {
        let local = lock!(self.local).clone();
        rlock!(self.peers)
            .get(peer)
            .map(|(coord, _)| local.distance_estimate(coord))
    }
}

// ── DhtMetrics ────────────────────────────────────────────────────────────────

// `impl DhtMetrics for NodeMetrics` moved to veil-observability
// alongside the type to satisfy the orphan rule.

// ── DhtRuntimeConfig converter ────────────────────────────────────────────────

/// Drop the persistence-path fields and pass the runtime knobs through
/// to veil-dht.
pub fn runtime_config_from(cfg: &veil_cfg::DhtConfig) -> veil_dht::DhtRuntimeConfig {
    veil_dht::DhtRuntimeConfig {
        republish_interval_secs: cfg.republish_interval_secs,
        cleanup_interval_secs: cfg.cleanup_interval_secs,
        participate: cfg.participate,
        k: cfg.k,
        alpha: cfg.alpha,
        max_rounds: cfg.max_rounds,
        find_node_timeout_ms: cfg.find_node_timeout_ms,
        vivaldi_weight: cfg.vivaldi_weight,
        max_store_entries: cfg.max_store_entries,
        max_store_bytes: cfg.max_store_bytes,
        per_origin_max_bytes: cfg.per_origin_max_bytes,
        cold_store_path: cfg.cold_store_path.clone(),
        shard_filtering: cfg.shard_filtering,
        allow_unsigned_store: cfg.allow_unsigned_store,
    }
}
