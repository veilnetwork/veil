//! Veil-network local-LAN mesh layer.
//!
//! extraction. Pure mesh logic — beacons, realm-scoped UDP
//! broadcast, neighbour table, gateway-bridge for cross-realm traffic —
//! plus two trait surfaces ([`BandwidthGuard`], [`MeshMetrics`]) so
//! veilcore can inject its concrete `PerPeerLimiter` and `NodeMetrics`
//! without this crate reverse-importing them.

pub mod auth;
pub mod beacon;
pub mod bridge;
pub mod forwarder;
pub mod link;
pub mod neighbor;
pub mod realm;
pub mod transport;
pub mod udp;

/// Per-peer byte-quota gate. Implemented by
/// `veilcore::node::abuse::per_peer_limiter::PerPeerLimiter`.
pub trait BandwidthGuard: Send + Sync {
    /// Charge `bytes` to the bucket for `peer`. Returns `true` if the
    /// peer had enough budget; `false` triggers a silent drop in the
    /// gateway-bridge lift path.
    fn allow_bytes(&self, peer: [u8; 32], bytes: usize) -> bool;
}

/// Counters the gateway-bridge increments at notable events
///. Implemented by
/// `veilcore::node::observability::NodeMetrics`.
pub trait MeshMetrics: Send + Sync {
    /// Increment the counter that tracks `lift_seen` cache evictions —
    /// fires whenever the dedup cache hits its hard cap.
    fn inc_gateway_lift_seen_evicted(&self);
}

pub use auth::verify_mesh_beacon_auth;
// Trait surfaces re-exported at root for ergonomic `veil_mesh::MeshMetrics`.
pub use beacon::{
    AutoDiscoveredGateway, AutoDiscoveredPeers, AutoDiscoveredSnapshot, BeaconReceiver,
    BeaconSender, DEFAULT_BEACON_INTERVAL, MAX_AUTODISCOVERED_GATEWAYS,
};
pub use bridge::{BridgeError, GatewayBridge, LiftedEnvelope};
pub use forwarder::{ForwardResult, MeshForwarder};
pub use link::{InMemoryLink, LocalLink, SendResult};
pub use neighbor::{MeshNeighborProvider, NeighborTable};
pub use realm::{InMemoryRealm, RealmNode};
pub use transport::{LocalTransport, MultiTransportNeighborTable};
pub use udp::{UdpLink, UdpRealm};

#[cfg(test)]
mod tests {
    use veil_proto::{
        delivery::DeliveryEnvelope,
        mesh::{MeshFrame, RealmId},
    };
    use veil_types::NodeRole;

    #[allow(unused_imports)]
    use super::*;

    /// Integration test: leaf → relay → gateway chain.
    ///
    /// A leaf originates a `DeliveryEnvelope`-bearing mesh frame. A relay in
    /// the middle forwards it to the gateway. The gateway lifts it out of the
    /// realm. removed the mailbox subsystem, so the post-lift step
    /// is now an assertion on the lifted envelope contents only.
    #[test]
    fn leaf_relay_gateway_delivery() {
        let realm_id = RealmId([0xAB; 16]);
        let leaf_id = [1u8; 32];
        let relay_id = [2u8; 32];
        let gateway_id = [3u8; 32];

        // ── Setup realm ──────────────────────────────────────────────────────
        let mut realm = InMemoryRealm::new(realm_id);
        realm.add_node(leaf_id, NodeRole::Leaf);
        realm.add_node(relay_id, NodeRole::Core);
        realm.add_node(gateway_id, NodeRole::Core);

        // ── Build DeliveryEnvelope ───────────────────────────────────────────
        let env = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(gateway_id),
            sender_node_id: [0u8; 32],
            src_app_id: [0u8; 32],
            app_id: [9u8; 32],
            endpoint_id: 1,
            content_id: [8u8; 32],
            created_at: 12345,
            ttl_secs: 120,
            payload: b"from leaf".to_vec(),
            trace_id: 0,
            require_ack: false,
        };

        // ── Leaf sends a mesh frame carrying the envelope to the gateway ─────
        let frame_from_leaf = MeshFrame::new(realm_id, leaf_id, gateway_id, 3, env.encode());

        // Relay forwards the leaf's frame
        let relay_node = realm.node(&relay_id).unwrap().clone();
        let (res, out_frame) = relay_node.forwarder.forward(&frame_from_leaf);
        assert!(matches!(res, ForwardResult::Forwarded { hops: 1 }));

        // ── Gateway receives the frame ───────────────────────────────────────
        let received = {
            let gw_inbox = realm.node(&gateway_id).unwrap().inbox.lock().unwrap();
            assert_eq!(gw_inbox.len(), 1);
            assert_eq!(gw_inbox[0].ttl, 2); // decremented by relay
            gw_inbox[0].clone()
        };

        // ── Gateway bridge lifts it ──────────────────────────────────────────
        let bridge = GatewayBridge::new(gateway_id, NodeRole::Core);
        bridge.lift(realm_id, &received).unwrap();
        let lifted = bridge.drain_lifted();
        assert_eq!(lifted.len(), 1);
        assert_eq!(lifted[0].envelope.recipient_node_id(), gateway_id);
        assert_eq!(&lifted[0].envelope.payload, b"from leaf");

        let _ = out_frame;
    }

    /// Integration test: inject from veil into realm.
    #[test]
    fn gateway_injects_into_realm() {
        let realm_id = RealmId([0x10; 16]);
        let gateway_id = [3u8; 32];
        let leaf_id = [1u8; 32];

        let bridge = GatewayBridge::new(gateway_id, NodeRole::Core);
        let env = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(leaf_id),
            sender_node_id: [0u8; 32],
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0u8; 32],
            created_at: 0,
            ttl_secs: 60,
            payload: b"veil-mesh".to_vec(),
            trace_id: 0,
            require_ack: false,
        };

        let frame = bridge.inject(realm_id, &env, 6).unwrap();
        assert_eq!(frame.dst_node_id, leaf_id);
        assert_eq!(frame.src_node_id, gateway_id);
        assert_eq!(frame.ttl, 6);

        // Verify envelope survives roundtrip through the frame payload

        let (decoded, _) = veil_proto::delivery::DeliveryEnvelope::decode(&frame.payload).unwrap();
        assert_eq!(&decoded.payload, b"veil-mesh");
    }
}
