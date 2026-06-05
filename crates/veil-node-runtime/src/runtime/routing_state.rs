//! decomposition PR4: routing-domain state
//! extracted into а dedicated [`Arc<RoutingState>`].
//!
//! ## Why а dedicated struct
//!
//! Pre-PR4, `NodeRuntime` held four routing-domain fields directly
//! (`rtt_table`, `route_cache`, `neighbor_scorer`, `vivaldi`) sprinkled
//! amongst session/dispatcher/anonymity state. Each is wrapped в its
//! own lock primitive (`Mutex` / `RwLock`); lock-order across them is
//! documented но not enforced by the compiler.
//!
//! Bundling here:
//! 1. Reduces `NodeRuntime`'s field count by 3 (4 fields → 1 Arc field).
//! 2. Groups logically-related state for code-navigation.
//! 3. Mirrors the PR1-3 pattern (AnonymityState / MailboxState /
//!    MobileState).
//!
//! ## Reload semantics
//!
//! Each inner field stays а distinct `Arc<Mutex<...>>` / `Arc<RwLock<...>>`.
//! Reload mutates the inner value (`*lock!(self.routing.rtt_table) =...`)
//! rather than swapping the `Arc<RoutingState>` itself, so downstream
//! contexts that hold а cloned inner Arc (e.g. `NodeServices.rtt_table`
//! `SessionRuntimeContext.rtt_table`, `FrameDispatcher.route_cache`)
//! observe the new value automatically without needing к re-fetch through
//! the parent.
//!
//! ## What's NOT in here
//!
//! `FrameDispatcher` carries its OWN `route_cache: Arc<RwLock<RouteCache>>`
//! field, populated by Arc-clone от `NodeRuntime` at startup. Same Arc
//! → same in-memory cache; the dispatcher's field is а separate
//! ownership handle, not а duplicate. PR4 does not touch dispatcher's
//! routing fields.

use std::sync::{Arc, Mutex, RwLock};

use veil_routing::{NeighborScorer, RouteCache, RttTable, VivaldiCoord};

/// Routing-domain state owned by [`crate::node::NodeRuntime`]. All
/// fields are `pub` so callsites can `lock!` / `rlock!` / `wlock!` через
/// the bundle (`runtime.routing.rtt_table` etc.) с no extra accessor
/// surface.
pub struct RoutingState {
    /// RTT probe table — latest latency + congestion samples
    /// per peer. Used by routing decisions, dispatcher metrics, и
    /// per-session battery-aware probe scheduling.
    pub rtt_table: Arc<Mutex<RttTable>>,

    /// Route cache — preferred next-hop hints keyed by destination
    /// node_id. Populated by routing-protocol hop announcements, read
    /// by `FrameDispatcher::deliver` для forwarding decisions. Shared
    /// (Arc-clone) с `FrameDispatcher.route_cache` — same cache, two
    /// owners.
    pub route_cache: Arc<RwLock<RouteCache>>,

    /// Neighbor scorer — ranks peers по RTT + reachability for the
    /// next-hop selector. Read on every route resolution.
    pub neighbor_scorer: Arc<Mutex<NeighborScorer>>,

    /// Vivaldi coordinate — local synthetic latency coordinate.
    /// Updated periodically на the maintenance tick от RTT probes.
    pub vivaldi: Arc<Mutex<VivaldiCoord>>,
}

impl RoutingState {
    pub fn new(
        rtt_table: Arc<Mutex<RttTable>>,
        route_cache: Arc<RwLock<RouteCache>>,
        neighbor_scorer: Arc<Mutex<NeighborScorer>>,
        vivaldi: Arc<Mutex<VivaldiCoord>>,
    ) -> Self {
        Self {
            rtt_table,
            route_cache,
            neighbor_scorer,
            vivaldi,
        }
    }
}
