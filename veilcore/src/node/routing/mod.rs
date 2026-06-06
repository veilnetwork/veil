//! Routing layer. complete: every routing primitive — including
//! the rate-limited `miss_handler` — now lives in `veil-routing`.
//! This module is now a pure re-export shim so existing call sites
//! (`crate::node::routing::RouteCache`, `…::miss_handler::*`, etc.)
//! continue to compile unchanged.

// iterative-DHT route-discovery fallback.
// Phase 4: dht_fallback moved to veil-node-runtime

// Re-exports so existing call sites compile unchanged.
pub use veil_routing::cache::{self, RouteCache, RouteCacheEntry};
pub use veil_routing::discovery_forwarder::{
    self, DiscoveryForwarder, DiscoveryNeighbor, DropReason, ForwardDecision,
};
pub use veil_routing::discovery_initiator::{self, DiscoveryInitiator};
pub use veil_routing::loss_tracker::{self, LossTracker};
pub use veil_routing::miss_handler::{self, MissHandlerCtx};
pub use veil_routing::pow::{
    self, discovery_pow_window_secs, solve_discovery_pow, solve_pow, verify_discovery_pow,
    verify_pow,
};
pub use veil_routing::probe::{self, PeerReportedRtt, RttProbe, RttTable};
pub use veil_routing::score::{self, NeighborScore, NeighborScorer};
pub use veil_routing::vivaldi::{self, VivaldiCoord};
pub use veil_routing::{RoutingLogger, RoutingMetrics};
