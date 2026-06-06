//! `MeshForwarder` — local mesh packet forwarder.
//!
//! The forwarder is the core relay logic: it accepts a `MeshFrame`, decrements
//! the TTL, and either:
//!
//! * delivers to a directly connected neighbour (unicast), or
//! * floods to all neighbours (broadcast, TTL > 1), or
//! * drops the frame (TTL = 0 or destination unreachable).
//!
//! Only `Core` nodes participate as active forwarders.
//! `Leaf` nodes only originate and receive, they do not forward transit traffic.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use veil_proto::mesh::{MeshFrame, RealmId};
use veil_types::NodeRole;

/// Next-hop lookup surface used by [`MeshForwarder::forward_with_cache`].
///
/// implemented by `veilcore::node::routing::cache::RouteCache` so
/// the mesh layer can consult veil routes without depending on the routing
/// crate.
pub trait NextHopCache: Send + Sync {
    /// Return the chosen next hop for `dst_node_id`, or `None` if no route is
    /// known.
    fn lookup(&self, dst_node_id: &[u8; 32]) -> Option<[u8; 32]>;
}

/// Dedup seen-set for mesh broadcasts to prevent O(N×TTL) amplification.
/// Keyed by `BLAKE3(src_node_id || payload)[..16]`, TTL = 10 seconds.
#[derive(Debug, Default)]
struct BroadcastSeenSet {
    entries: HashMap<[u8; 16], Instant>,
}

/// typed TTL. Migrated from `BROADCAST_SEEN_TTL_SECS: u64`
/// to `Ttl`-typed constant to prevent accidental seconds/millis mix-ups
/// at consumer sites (the duplicate check below previously had two
/// separate `Duration::from_secs(BROADCAST_SEEN_TTL_SECS)` constructions
/// — easy to get the unit wrong on either, the same exposure for new
/// consumers added later). Now: single `BROADCAST_SEEN_TTL` constant
/// callers use `.as_duration` to interop with `Duration` arithmetic.
const BROADCAST_SEEN_TTL: veil_util::Ttl = veil_util::Ttl::from_secs(10);
/// bumped from 4096 → 65_536. At the
/// stated 80K pkt/s envelope the previous cap collapsed the
/// effective de-dup TTL to ~50 ms (cap reached in 50 ms, then
/// retain-prune evicts on every insert). 64K entries × ~64 B each
/// = ~4 MiB of memory — acceptable on any production-class node;
/// preserves the documented 10 s TTL even at peak load.
const BROADCAST_SEEN_CAP: usize = 65_536;

impl BroadcastSeenSet {
    /// Returns `true` if already seen (duplicate). Inserts if new.
    fn check_and_insert(&mut self, frame: &MeshFrame) -> bool {
        let key = Self::frame_key(frame);
        let now = Instant::now();
        // Lazy eviction: prune expired entries when at capacity.
        if self.entries.len() >= BROADCAST_SEEN_CAP {
            let ttl = BROADCAST_SEEN_TTL.as_duration();
            self.entries.retain(|_, t| now.duration_since(*t) < ttl);
        }
        if let Some(t) = self.entries.get(&key)
            && now.duration_since(*t) < BROADCAST_SEEN_TTL.as_duration()
        {
            return true; // duplicate
        }
        self.entries.insert(key, now);
        false
    }

    fn frame_key(frame: &MeshFrame) -> [u8; 16] {
        let mut h = blake3::Hasher::new();
        h.update(&frame.src_node_id);
        h.update(&frame.payload);
        let hash = h.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash.as_bytes()[..16]);
        key
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Encode a `MeshFrame` once into a ref-counted byte buffer for broadcast.
fn encode_arc(frame: &MeshFrame) -> Arc<[u8]> {
    frame.encode().into()
}

use super::neighbor::MeshNeighborProvider;

// ── ForwardResult ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardResult {
    /// Frame delivered to one or more links.
    Forwarded { hops: usize },
    /// Destination not found in neighbour table.
    NoRoute,
    /// TTL hit zero — frame dropped.
    TtlExpired,
    /// Role does not allow forwarding transit traffic.
    NotRelay,
    /// Frame dropped due to policy (e.g. src_node_id spoofing our own identity).
    Dropped,
}

// ── MeshForwarder ─────────────────────────────────────────────────────────────

/// Forwards mesh frames toward their destination.
///
/// Clone-cheap: neighbours table is behind `Arc`.
#[derive(Clone)]
pub struct MeshForwarder {
    local_id: [u8; 32],
    role: NodeRole,
    neighbors: Arc<dyn MeshNeighborProvider>,
    /// If set, only frames matching this realm_id are forwarded.
    /// Frames with a different realm_id are silently dropped.
    local_realm_id: Option<RealmId>,
    /// Broadcast dedup to prevent O(N×TTL) amplification.
    broadcast_seen: Arc<Mutex<BroadcastSeenSet>>,
}

impl MeshForwarder {
    pub fn new(
        local_id: [u8; 32],
        role: NodeRole,
        neighbors: Arc<dyn MeshNeighborProvider>,
    ) -> Self {
        Self {
            local_id,
            role,
            neighbors,
            local_realm_id: None,
            broadcast_seen: Arc::new(Mutex::new(BroadcastSeenSet::default())),
        }
    }

    /// Restrict this forwarder to only relay frames within `realm_id`.
    pub fn with_realm_id(mut self, realm_id: RealmId) -> Self {
        self.local_realm_id = Some(realm_id);
        self
    }

    /// Can this node forward transit mesh frames?
    fn can_relay(&self) -> bool {
        matches!(self.role, NodeRole::Core)
    }

    /// Forward a received `MeshFrame`.
    ///
    /// Returns the forward result. Does not modify the input frame — returns
    /// the outgoing (TTL-decremented) frame on success so the caller can log it.
    pub fn forward(&self, frame: &MeshFrame) -> (ForwardResult, Option<MeshFrame>) {
        if !self.can_relay() {
            return (ForwardResult::NotRelay, None);
        }
        if frame.ttl == 0 {
            return (ForwardResult::TtlExpired, None);
        }
        // Drop frames that claim to originate from this node — a peer spoofing
        // our src_node_id would cause us to re-broadcast our own traffic.
        if frame.src_node_id == self.local_id {
            return (ForwardResult::Dropped, None);
        }
        // realm isolation — drop cross-realm frames.
        if let Some(local_realm) = &self.local_realm_id
            && &frame.realm_id != local_realm
        {
            return (ForwardResult::Dropped, None);
        }
        let out = MeshFrame {
            ttl: frame.ttl - 1,
            ..frame.clone()
        };
        if frame.is_broadcast() {
            // Dedup: skip if we already forwarded this broadcast.
            if self
                .broadcast_seen
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .check_and_insert(frame)
            {
                return (ForwardResult::Dropped, None);
            }
            let neighbors = self.neighbors.all_neighbors();
            let mut sent = 0usize;
            // Pre-encode once; share the buffer across all links via Arc.
            let encoded = encode_arc(&out);
            for nid in &neighbors {
                if nid == &self.local_id {
                    continue; // never echo back to self
                }
                if let Some(link) = self.neighbors.link_to(nid) {
                    let _ = link.send_encoded(&encoded);
                    sent += 1;
                }
            }
            (ForwardResult::Forwarded { hops: sent }, Some(out))
        } else if frame.dst_node_id == self.local_id {
            // Frame reached its final destination — caller should consume payload.
            (ForwardResult::Forwarded { hops: 0 }, Some(out))
        } else if let Some(link) = self.neighbors.link_to(&frame.dst_node_id) {
            let _ = link.send(&out);
            (ForwardResult::Forwarded { hops: 1 }, Some(out))
        } else {
            (ForwardResult::NoRoute, None)
        }
    }

    /// Forward using an optional `RouteCache` hint, with prefer-local semantics.
    ///
    /// Priority order:
    /// 1. Direct local-mesh link (always preferred — lowest latency, no relay cost).
    /// 2. Cache-suggested next-hop link (veil relay path).
    /// 3. Fallback to plain `forward`.
    ///
    /// This ensures that when the same destination is reachable both via a local
    /// mesh transport (BLE / UDP / Wi-Fi Direct) and via an internet relay, the
    /// local path wins.
    pub fn forward_with_cache(
        &self,
        frame: &MeshFrame,
        cache: &dyn NextHopCache,
    ) -> (ForwardResult, Option<MeshFrame>) {
        if !self.can_relay() {
            return (ForwardResult::NotRelay, None);
        }
        if frame.ttl == 0 {
            return (ForwardResult::TtlExpired, None);
        }
        if frame.src_node_id == self.local_id {
            return (ForwardResult::Dropped, None);
        }
        // realm isolation.
        if let Some(local_realm) = &self.local_realm_id
            && &frame.realm_id != local_realm
        {
            return (ForwardResult::Dropped, None);
        }
        if frame.is_broadcast() || frame.dst_node_id == self.local_id {
            return self.forward(frame);
        }
        // 1. Prefer direct local-mesh link (prefer-local).
        if let Some(link) = self.neighbors.link_to(&frame.dst_node_id) {
            let out = MeshFrame {
                ttl: frame.ttl - 1,
                ..frame.clone()
            };
            let _ = link.send(&out);
            return (ForwardResult::Forwarded { hops: 1 }, Some(out));
        }
        // 2. Consult route cache for veil relay path.
        if let Some(next_hop) = cache.lookup(&frame.dst_node_id)
            && let Some(link) = self.neighbors.link_to(&next_hop)
        {
            let out = MeshFrame {
                ttl: frame.ttl - 1,
                ..frame.clone()
            };
            let _ = link.send(&out);
            return (ForwardResult::Forwarded { hops: 1 }, Some(out));
        }
        // 3. Fall back to plain forward (flood or no-route).
        self.forward(frame)
    }

    pub fn local_id(&self) -> [u8; 32] {
        self.local_id
    }

    /// Number of directly reachable neighbors.
    pub fn neighbor_count(&self) -> usize {
        self.neighbors.all_neighbors().len()
    }

    /// Remove dead neighbor links. Call periodically from the maintenance loop.
    pub fn prune_neighbors(&self) {
        self.neighbors.prune_dead();
    }
}

// cleanup: `forward_result_to_ack_status` removed — pub fn with
// zero callers workspace-wide. Mesh ack-byte build now happens inline at the
// callers that emit ack frames. Re-introduce from git history if a new mesh-ack
// emitter shows up.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{link::InMemoryLink, neighbor::NeighborTable};
    use veil_proto::mesh::{MeshFrame, RealmId};

    fn make_forwarder(local_id: [u8; 32], role: NodeRole) -> (MeshForwarder, NeighborTable) {
        let table = NeighborTable::new();
        let fwd = MeshForwarder::new(local_id, role, Arc::new(table.clone()));
        (fwd, table)
    }

    fn add_neighbor(
        table: &NeighborTable,
        remote_id: [u8; 32],
    ) -> Arc<std::sync::Mutex<Vec<MeshFrame>>> {
        let (link, inbox) = InMemoryLink::pair(remote_id);
        table.add(remote_id, Arc::new(link) as Arc<dyn crate::link::LocalLink>);
        inbox
    }

    fn frame(src: u8, dst: u8, ttl: u8) -> MeshFrame {
        MeshFrame::new(
            RealmId([0u8; 16]),
            [src; 32],
            [dst; 32],
            ttl,
            b"data".to_vec(),
        )
    }

    #[test]
    fn ttl_zero_drops() {
        let (fwd, _) = make_forwarder([1u8; 32], NodeRole::Core);
        let (res, out) = fwd.forward(&frame(2, 3, 0));
        assert_eq!(res, ForwardResult::TtlExpired);
        assert!(out.is_none());
    }

    #[test]
    fn leaf_cannot_relay() {
        let (fwd, _) = make_forwarder([1u8; 32], NodeRole::Leaf);
        let (res, _) = fwd.forward(&frame(2, 3, 4));
        assert_eq!(res, ForwardResult::NotRelay);
    }

    #[test]
    fn unicast_forward_decrements_ttl() {
        let (fwd, table) = make_forwarder([1u8; 32], NodeRole::Core);
        let inbox = add_neighbor(&table, [3u8; 32]);
        let f = frame(2, 3, 5);
        let (res, out) = fwd.forward(&f);
        assert_eq!(res, ForwardResult::Forwarded { hops: 1 });
        assert_eq!(out.unwrap().ttl, 4);
        assert_eq!(inbox.lock().unwrap().len(), 1);
        assert_eq!(inbox.lock().unwrap()[0].ttl, 4);
    }

    #[test]
    fn no_route_when_destination_unknown() {
        let (fwd, _) = make_forwarder([1u8; 32], NodeRole::Core);
        let (res, _) = fwd.forward(&frame(2, 9, 5));
        assert_eq!(res, ForwardResult::NoRoute);
    }

    #[test]
    fn local_delivery_no_hop() {
        // Frame addressed to this node itself
        let local = [1u8; 32];
        let (fwd, _) = make_forwarder(local, NodeRole::Core);
        let f = MeshFrame::new(RealmId([0u8; 16]), [2u8; 32], local, 3, b"hi".to_vec());
        let (res, _) = fwd.forward(&f);
        assert_eq!(res, ForwardResult::Forwarded { hops: 0 });
    }

    #[test]
    fn broadcast_floods_to_all_neighbors() {
        use veil_proto::mesh::BROADCAST_NODE_ID;
        let (fwd, table) = make_forwarder([1u8; 32], NodeRole::Core);
        let inbox_a = add_neighbor(&table, [2u8; 32]);
        let inbox_b = add_neighbor(&table, [3u8; 32]);
        // src=[0xAAu8;32] — a remote peer, not local_id=[1u8;32]
        let f = MeshFrame::new(
            RealmId([0u8; 16]),
            [0xAAu8; 32],
            BROADCAST_NODE_ID,
            2,
            b"bc".to_vec(),
        );
        let (res, _) = fwd.forward(&f);
        assert_eq!(res, ForwardResult::Forwarded { hops: 2 });
        assert_eq!(inbox_a.lock().unwrap().len(), 1);
        assert_eq!(inbox_b.lock().unwrap().len(), 1);
    }

    /// A frame arriving with src_node_id == our own local_id must be dropped —
    /// it is a spoofed frame that would cause us to re-broadcast our own traffic.
    #[test]
    fn spoofed_src_node_id_dropped() {
        use veil_proto::mesh::BROADCAST_NODE_ID;
        let local = [1u8; 32];
        let (fwd, table) = make_forwarder(local, NodeRole::Core);
        add_neighbor(&table, [2u8; 32]);

        // Unicast spoofed src
        let unicast = MeshFrame::new(RealmId([0u8; 16]), local, [2u8; 32], 5, b"x".to_vec());
        let (res, _) = fwd.forward(&unicast);
        assert_eq!(
            res,
            ForwardResult::Dropped,
            "unicast with spoofed src must be dropped"
        );

        // Broadcast spoofed src
        let bc = MeshFrame::new(
            RealmId([0u8; 16]),
            local,
            BROADCAST_NODE_ID,
            5,
            b"x".to_vec(),
        );
        let (res2, _) = fwd.forward(&bc);
        assert_eq!(
            res2,
            ForwardResult::Dropped,
            "broadcast with spoofed src must be dropped"
        );
    }

    #[test]
    fn gateway_can_relay() {
        let (fwd, table) = make_forwarder([1u8; 32], NodeRole::Core);
        add_neighbor(&table, [5u8; 32]);
        let (res, _) = fwd.forward(&frame(2, 5, 3));
        assert_eq!(res, ForwardResult::Forwarded { hops: 1 });
    }

    // ── realm isolation ─────────────────────────────────────────────

    /// A forwarder with `local_realm_id = A` must drop frames whose `realm_id = B`.
    #[test]
    fn realm_mismatch_drops_frame() {
        let realm_a = RealmId([0xAAu8; 16]);
        let realm_b = RealmId([0xBBu8; 16]);
        let (fwd, table) = make_forwarder([1u8; 32], NodeRole::Core);
        let fwd = fwd.with_realm_id(realm_a);
        add_neighbor(&table, [3u8; 32]);

        // Frame carrying realm_b — must be dropped.
        let f = MeshFrame::new(realm_b, [2u8; 32], [3u8; 32], 5, b"x".to_vec());
        let (res, out) = fwd.forward(&f);
        assert_eq!(
            res,
            ForwardResult::Dropped,
            "cross-realm frame must be dropped"
        );
        assert!(out.is_none());
    }

    /// A forwarder with `local_realm_id = A` must forward frames with `realm_id = A`.
    #[test]
    fn realm_match_forwards_frame() {
        let realm_a = RealmId([0xAAu8; 16]);
        let (fwd, table) = make_forwarder([1u8; 32], NodeRole::Core);
        let fwd = fwd.with_realm_id(realm_a);
        add_neighbor(&table, [3u8; 32]);

        let f = MeshFrame::new(realm_a, [2u8; 32], [3u8; 32], 5, b"x".to_vec());
        let (res, _) = fwd.forward(&f);
        assert_eq!(res, ForwardResult::Forwarded { hops: 1 });
    }

    /// A forwarder with no `local_realm_id` must forward any realm (open relay).
    #[test]
    fn no_realm_filter_forwards_any_realm() {
        let realm_b = RealmId([0xBBu8; 16]);
        let (fwd, table) = make_forwarder([1u8; 32], NodeRole::Core);
        // No with_realm_id call — open relay.
        add_neighbor(&table, [3u8; 32]);

        let f = MeshFrame::new(realm_b, [2u8; 32], [3u8; 32], 5, b"x".to_vec());
        let (res, _) = fwd.forward(&f);
        assert_eq!(res, ForwardResult::Forwarded { hops: 1 });
    }

    /// Duplicate broadcast frames are detected and dropped.
    #[test]
    fn broadcast_dedup_drops_duplicate() {
        use veil_proto::mesh::BROADCAST_NODE_ID;
        let (fwd, table) = make_forwarder([1u8; 32], NodeRole::Core);
        add_neighbor(&table, [2u8; 32]);

        let f = MeshFrame::new(
            RealmId([0u8; 16]),
            [0xAAu8; 32],
            BROADCAST_NODE_ID,
            5,
            b"bc".to_vec(),
        );
        let (res1, _) = fwd.forward(&f);
        assert_eq!(
            res1,
            ForwardResult::Forwarded { hops: 1 },
            "first forward must succeed"
        );

        // Same frame again — should be deduped.
        let (res2, _) = fwd.forward(&f);
        assert_eq!(
            res2,
            ForwardResult::Dropped,
            "duplicate broadcast must be dropped"
        );
    }

    /// Different broadcasts from same source are NOT deduped.
    #[test]
    fn broadcast_dedup_allows_different_payloads() {
        use veil_proto::mesh::BROADCAST_NODE_ID;
        let (fwd, table) = make_forwarder([1u8; 32], NodeRole::Core);
        add_neighbor(&table, [2u8; 32]);

        let f1 = MeshFrame::new(
            RealmId([0u8; 16]),
            [0xAAu8; 32],
            BROADCAST_NODE_ID,
            5,
            b"msg1".to_vec(),
        );
        let f2 = MeshFrame::new(
            RealmId([0u8; 16]),
            [0xAAu8; 32],
            BROADCAST_NODE_ID,
            5,
            b"msg2".to_vec(),
        );
        let (res1, _) = fwd.forward(&f1);
        let (res2, _) = fwd.forward(&f2);
        assert_eq!(res1, ForwardResult::Forwarded { hops: 1 });
        assert_eq!(res2, ForwardResult::Forwarded { hops: 1 });
    }
}
