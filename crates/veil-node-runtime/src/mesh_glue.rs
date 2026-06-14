//! Glue layer between veilcore's concrete services and the
//! `veil-mesh` trait surfaces (`BandwidthGuard`, `BatterySink`
//! `NextHopCache`).
//!
//! extraction kept veil-mesh free of `node::abuse`
//! `node::observability`, and `node::routing` by inverting those deps
//! into traits. This module owns the corresponding adapters.

use std::sync::{Arc, Mutex};
use veil_util::lock;

use veil_abuse::per_peer_limiter::PerPeerLimiter;
use veil_routing::probe::RttTable;

// ── BandwidthGuard ────────────────────────────────────────────────────────────

/// `BandwidthGuard` adapter wrapping the mutable `PerPeerLimiter`. Holds
/// the limiter behind a `Mutex` so the trait method can stay `&self`.
pub struct LeafBandwidthGuard {
    inner: Arc<Mutex<PerPeerLimiter>>,
}

impl LeafBandwidthGuard {
    /// Build a leaf-byte-quota guard from (kbps, burst) tuple that the
    /// pre-extraction `with_leaf_bandwidth_quota(kbps, burst_bytes)` API
    /// previously synthesised inline.
    pub fn from_kbps_burst(kbps: f64, burst_bytes: f64) -> Self {
        let mut limiter = PerPeerLimiter::new(
            f64::INFINITY,
            f64::INFINITY,
            std::time::Duration::from_secs(300),
        );
        limiter = limiter.with_byte_rate(kbps * 1024.0, burst_bytes);
        Self {
            inner: Arc::new(Mutex::new(limiter)),
        }
    }

    /// Wrap an externally-owned limiter (production runtime path).
    pub fn from_limiter(inner: Arc<Mutex<PerPeerLimiter>>) -> Self {
        Self { inner }
    }
}

impl veil_mesh::BandwidthGuard for LeafBandwidthGuard {
    fn allow_bytes(&self, peer: [u8; 32], bytes: usize) -> bool {
        lock!(self.inner).allow_bytes(peer, bytes)
    }
}

// ── BatterySink ───────────────────────────────────────────────────────────────

/// `BatterySink` adapter wrapping `Arc<Mutex<RttTable>>` so the trait
/// method stays `&self` while the underlying `update_battery` takes `&mut self`.
pub struct RttBatterySink {
    inner: Arc<Mutex<RttTable>>,
}

impl RttBatterySink {
    pub fn new(inner: Arc<Mutex<RttTable>>) -> Self {
        Self { inner }
    }
}

impl veil_mesh::beacon::BatterySink for RttBatterySink {
    fn update_battery(&self, peer: [u8; 32], battery_level: u8) {
        lock!(self.inner).update_battery(peer, battery_level)
    }
}

// ── NextHopCache ──────────────────────────────────────────────────────────────
//
// `impl NextHopCache for RouteCache` lives in veil-routing (alongside
// RouteCache itself) to satisfy the orphan rule once both the trait and the
// type became foreign to veilcore. The former `RouteCacheLookup` adapter
// here was superseded by that direct impl and had zero callers — removed in
// audit cycle-6 dead-code cleanup.
