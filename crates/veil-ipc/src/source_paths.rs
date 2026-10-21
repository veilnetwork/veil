//! Snapshot the same first-hop order used by sealed local lossy sends.
use std::sync::RwLock;
use veil_types::FrameBroadcaster;

pub fn sealed_relay_hops(
    destination: &[u8; 32],
    cache: Option<&RwLock<veil_routing::RouteCache>>,
    registry: &dyn FrameBroadcaster,
) -> Vec<[u8; 32]> {
    let mut hops =
        crate::handlers::send::ordinary_relay_hops(None, destination, cache, registry, true);
    prefer_datagrams(&mut hops, registry);
    hops
}

pub(crate) fn prefer_datagrams(hops: &mut [[u8; 32]], registry: &dyn FrameBroadcaster) {
    hops.sort_by_cached_key(|hop| !registry.has_neutral_forward_datagram_transport(hop));
}

/// Source-specific sibling retaining the generic public snapshot for callers
/// which do not own an independent local producer.
pub fn sealed_relay_hops_for_source(
    destination: &[u8; 32],
    cache: Option<&RwLock<veil_routing::RouteCache>>,
    registry: &dyn FrameBroadcaster,
    local_lane: u8,
) -> Vec<[u8; 32]> {
    let mut hops = sealed_relay_hops(destination, cache, registry);
    prefer_ready_sources(&mut hops, registry, local_lane);
    hops
}

pub(crate) fn prefer_ready_sources(
    hops: &mut [[u8; 32]],
    registry: &dyn FrameBroadcaster,
    local_lane: u8,
) {
    use veil_types::LocalDatagramChannelState as State;
    // Queue admission does not prove the negotiated child can send. Keep
    // existing ready alternatives ahead of cached hops whose independent
    // source is still warming; the runner otherwise discards their packets.
    // Unsupported retains the old transport fallback. Nothing opens a new
    // connection, promotes a direct peer, or changes a relay's wire policy.
    // Cache one snapshot per hop: readiness can change concurrently, so the
    // comparator must not query live state repeatedly during the sort.
    hops.sort_by_cached_key(|hop| {
        let readiness = match registry.local_datagram_channel_state(hop, local_lane) {
            State::Ready => 0,
            State::Unsupported => 1,
            State::Warming => 2,
        };
        (
            readiness,
            !registry.has_neutral_forward_datagram_transport(hop),
        )
    });
}

/// Prepare only the existing preferred pair, without clearing a usable child
/// or admitting a data packet. Sending can meanwhile keep its ready fallback.
/// Framing/readiness snapshots deliberately do not call this side-effecting
/// sibling: merely observing costs must never initiate a connection.
pub(crate) fn warm_preferred_sources(
    hops: &[[u8; 32]],
    registry: &dyn FrameBroadcaster,
    local_lane: u8,
) {
    if registry.supports_local_datagram_preparation() {
        for hop in hops.iter().take(2) {
            registry.prepare_local_datagram_channel(hop, local_lane, false);
        }
    }
}
