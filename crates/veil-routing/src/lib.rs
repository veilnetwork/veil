//! Veil routing primitives.
//!
//! Pure data-plane routing without session/dispatcher coupling:
//!
//! [`cache`] — `RouteCache` LRU keyed by destination + via.
//! [`vivaldi`] — Vivaldi network coordinates.
//! [`probe`] — RTT probe table (smoothed RTT, jitter, congestion).
//! [`score`] — `NeighborScorer` for adaptive route ranking.
//! [`pow`] — route-discovery proof-of-work primitive.
//! [`loss_tracker`] — per-peer in-line loss-rate tracker.
//! [`discovery_forwarder`] — route-discovery rate-gate + PoW verifier.
//! [`discovery_initiator`] — adaptive discovery-cadence controller.
//! [`miss_handler`] — route-miss handler (flood ROUTE_REQUEST, retry, partition warn).
//!
//! Cross-crate observability is supplied by [`RoutingLogger`] and
//! [`RoutingMetrics`] trait surfaces, mirroring the AbuseLogger /
//! MeshMetrics pattern. `veilcore::node::observability::{NodeLogger
//! NodeMetrics}` implement these traits via thin bridge impls so we don't
//! pull observability concretes into routing.

pub mod cache;
pub mod control_plane;
pub mod discovery_forwarder;
pub mod discovery_initiator;
pub mod loss_tracker;
pub mod miss_handler;
pub mod pow;
pub mod probe;
pub mod score;
pub mod vivaldi;

pub use cache::RouteCache;
pub use discovery_forwarder::{DiscoveryForwarder, DiscoveryNeighbor, DropReason, ForwardDecision};
pub use discovery_initiator::DiscoveryInitiator;
pub use loss_tracker::LossTracker;
pub use miss_handler::{MissHandlerCtx, spawn as spawn_miss_handler};
pub use probe::RttTable;
pub use score::NeighborScorer;
pub use vivaldi::VivaldiCoord;

/// Logger surface for the route-miss handler. Implemented by
/// `veilcore::node::observability::NodeLogger` via a tiny bridge so
/// veil-routing stays free of observability concretes.
pub trait RoutingLogger: Send + Sync {
    /// Emit a warn-level event with category `event` and a free-form `message`.
    fn warn(&self, event: &str, message: &str);

    /// Emit an info-level event. Default impl forwards to `warn` for existing
    /// callers that haven't migrated; overriding lets concretes use their
    /// native log level. : added for iterative-DHT fallback
    /// observability.
    fn info(&self, event: &str, message: &str) {
        self.warn(event, message);
    }
}

/// Metrics surface for the route-miss handler. Implemented by
/// `veilcore::node::observability::NodeMetrics`.
pub trait RoutingMetrics: Send + Sync {
    fn inc_discovery_triggered(&self);
    fn inc_route_recovery(&self);

    /// iterative-DHT fallback was triggered (legacy
    /// `RouteRequest` flood exhausted; fall through to `RecursiveQuery`).
    /// Default no-op for backward-compatible impls.
    fn inc_dht_fallback_triggered(&self) {}
    /// iterative-DHT fallback resolved — response arrived
    /// and `route_cache` got populated. Default no-op.
    fn inc_dht_fallback_resolved(&self) {}
    /// iterative-DHT fallback timed out without a response.
    /// Default no-op.
    fn inc_dht_fallback_miss(&self) {}
    /// Push a reachability event into the sliding window and return the
    /// current score in `0.0..=1.0`.
    fn record_reachability_event(&self, success: bool) -> f64;
}

// orphan-rule fix — `NextHopCache` lives in veil-mesh
// `RouteCache` lives here. Co-located in this crate so veil-routing
// remains the single owner of all RouteCache APIs.
impl veil_mesh::forwarder::NextHopCache for RouteCache {
    fn lookup(&self, dst_node_id: &[u8; 32]) -> Option<[u8; 32]> {
        RouteCache::lookup(self, dst_node_id)
    }
}
