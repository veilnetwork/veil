//! `InMemoryRealm` — simulated local mesh realm for testing.
//!
//! An `InMemoryRealm` wires together N `MeshNode` instances that can forward
//! frames to each other through a shared channel bus. No real networking is
//! involved — frames are delivered synchronously via `InMemoryLink`s.
//!
//! # Topology
//!
//! The realm maintains a full-mesh link table: every node has a direct link to
//! every other node. This simplifies testing of relay chains by controlling
//! which links are alive.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use veil_util::lock;

use veil_proto::mesh::{MeshFrame, RealmId};

use super::{forwarder::MeshForwarder, neighbor::NeighborTable};

// ── RealmNode ─────────────────────────────────────────────────────────────────

/// A single node registered in an `InMemoryRealm`.
#[derive(Clone)]
pub struct RealmNode {
    pub node_id: [u8; 32],
    pub forwarder: MeshForwarder,
    pub neighbors: NeighborTable,
    /// Frames addressed to this node that have arrived at their final destination.
    pub inbox: Arc<Mutex<Vec<MeshFrame>>>,
}

// ── InMemoryRealm ─────────────────────────────────────────────────────────────

/// Simulated realm — an in-process mesh segment.
pub struct InMemoryRealm {
    pub realm_id: RealmId,
    nodes: HashMap<[u8; 32], RealmNode>,
}

impl InMemoryRealm {
    pub fn new(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            nodes: HashMap::new(),
        }
    }

    /// Add a node to the realm. Wires bidirectional links to all existing nodes.
    pub fn add_node(&mut self, node_id: [u8; 32], role: veil_types::NodeRole) {
        let neighbors = NeighborTable::new();
        let inbox = Arc::new(Mutex::new(Vec::new()));

        // Wire links to all existing nodes
        for (existing_id, existing_node) in &self.nodes {
            // Link: new_node → existing
            let inbox_existing = Arc::clone(&existing_node.inbox);
            let link_out = DirectInboxLink::new(*existing_id, Arc::clone(&inbox_existing));
            neighbors.add(*existing_id, Arc::new(link_out));

            // Link: existing → new_node
            let link_in = DirectInboxLink::new(node_id, Arc::clone(&inbox));
            existing_node.neighbors.add(node_id, Arc::new(link_in));
        }

        let forwarder = MeshForwarder::new(node_id, role, Arc::new(neighbors.clone()));
        let node = RealmNode {
            node_id,
            forwarder,
            neighbors,
            inbox,
        };
        self.nodes.insert(node_id, node);
    }

    /// Get a node by id.
    pub fn node(&self, id: &[u8; 32]) -> Option<&RealmNode> {
        self.nodes.get(id)
    }

    /// Deliver a frame from `src` to the realm — simulates the src node sending.
    ///
    /// Returns how many nodes received the frame (after forwarding).
    pub fn send(&self, src_id: &[u8; 32], frame: MeshFrame) -> usize {
        let Some(node) = self.nodes.get(src_id) else {
            return 0;
        };
        let (result, _out) = node.forwarder.forward(&frame);
        match result {
            super::forwarder::ForwardResult::Forwarded { hops } => hops,
            _ => 0,
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

// ── DirectInboxLink ───────────────────────────────────────────────────────────

/// A link that places frames directly into a node's inbox `Vec`.
#[derive(Clone)]
struct DirectInboxLink {
    remote_id: [u8; 32],
    inbox: Arc<Mutex<Vec<MeshFrame>>>,
    alive: Arc<Mutex<bool>>,
}

impl DirectInboxLink {
    fn new(remote_id: [u8; 32], inbox: Arc<Mutex<Vec<MeshFrame>>>) -> Self {
        Self {
            remote_id,
            inbox,
            alive: Arc::new(Mutex::new(true)),
        }
    }
}

impl super::link::LocalLink for DirectInboxLink {
    fn remote_node_id(&self) -> [u8; 32] {
        self.remote_id
    }

    fn send(&self, frame: &MeshFrame) -> super::link::SendResult {
        if !*lock!(self.alive) {
            return super::link::SendResult::Disconnected;
        }
        lock!(self.inbox).push(frame.clone());
        super::link::SendResult::Ok
    }

    fn is_alive(&self) -> bool {
        *lock!(self.alive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::mesh::{BROADCAST_NODE_ID, MeshFrame, RealmId};
    use veil_types::NodeRole;

    fn realm_with_nodes() -> InMemoryRealm {
        let mut realm = InMemoryRealm::new(RealmId([1u8; 16]));
        realm.add_node([1u8; 32], NodeRole::Leaf);
        realm.add_node([2u8; 32], NodeRole::Core);
        realm.add_node([3u8; 32], NodeRole::Core);
        realm
    }

    #[test]
    fn nodes_registered() {
        let realm = realm_with_nodes();
        assert_eq!(realm.node_count(), 3);
    }

    #[test]
    fn relay_forwards_unicast_to_destination() {
        let realm = realm_with_nodes();

        // Relay [2] forwards a frame to Gateway [3]
        let frame = MeshFrame::new(
            RealmId([1u8; 16]),
            [1u8; 32], // src = leaf
            [3u8; 32], // dst = gateway
            4,
            b"payload".to_vec(),
        );
        let hops = realm.send(&[2u8; 32], frame);
        assert_eq!(hops, 1);

        // Gateway inbox should have one frame
        let gw = realm.node(&[3u8; 32]).unwrap();
        assert_eq!(gw.inbox.lock().unwrap().len(), 1);
        assert_eq!(gw.inbox.lock().unwrap()[0].ttl, 3); // TTL decremented
    }

    #[test]
    fn gateway_broadcasts_to_all() {
        let realm = realm_with_nodes();
        // src=[0xAAu8;32] — a remote peer, not the gateway's own local_id=[3u8;32].
        // The gateway relays a broadcast received from this peer.
        let frame = MeshFrame::new(
            RealmId([1u8; 16]),
            [0xAAu8; 32],
            BROADCAST_NODE_ID,
            3,
            b"bc".to_vec(),
        );
        let hops = realm.send(&[3u8; 32], frame);
        // Gateway has 2 neighbours → 2 hops
        assert_eq!(hops, 2);
    }

    #[test]
    fn leaf_does_not_forward_transit() {
        let realm = realm_with_nodes();
        let frame = MeshFrame::new(
            RealmId([1u8; 16]),
            [1u8; 32], // src=leaf
            [3u8; 32], // dst=gateway
            4,
            b"data".to_vec(),
        );
        // Leaf [1] tries to forward — should get NotRelay → 0 hops
        let hops = realm.send(&[1u8; 32], frame);
        assert_eq!(hops, 0);
    }
}
