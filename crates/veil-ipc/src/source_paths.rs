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
    hops.sort_by_key(|hop| !registry.has_neutral_forward_datagram_transport(hop));
}
