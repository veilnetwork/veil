pub mod announcement_sig;
pub mod directory;
pub mod service;

pub use announcement_sig::{sign_announcement, verify_announcement_signature};
pub use directory::{AppEndpointEntry, StaticDirectory};
pub use service::{DiscoveryError, DiscoveryService};

#[cfg(test)]
mod integration_tests {
    //! End-to-end test: a leaf node announces its attachment through a gateway;
    //! another peer later looks up the attachment via the same gateway's directory.

    use crate::service::DiscoveryService;
    use veil_proto::discovery::{AnnounceAttachmentPayload, GatewayRef, GetAttachmentPayload};
    use veil_types::NodeRole;

    fn leaf_announce(leaf_id: u8, gw_id: u8) -> AnnounceAttachmentPayload {
        // Far-future expires_at so the announcement passes the freshness check.
        AnnounceAttachmentPayload {
            node_id: [leaf_id; 32],
            role: 1, // leaf
            realm_id: 1,
            epoch: 1,
            expires_at: 9_999_999_999,
            gateways: vec![GatewayRef {
                gateway_node_id: [gw_id; 32],
                priority: 1,
                weight: 1,
                flags: 0,
            }],
            seq_no: 0,
            signature: vec![],
            ephemeral_endpoint: None,
        }
    }

    #[test]
    fn leaf_announces_through_gateway_another_peer_finds_it() {
        let gateway = DiscoveryService::new(NodeRole::Core);

        // Leaf sends ANNOUNCE_ATTACHMENT to gateway
        gateway
            .handle_announce_attachment(leaf_announce(0xAA, 0xBB))
            .unwrap();

        // Another peer looks up the leaf
        let resp = gateway.handle_get_attachment(GetAttachmentPayload {
            node_id: [0xAAu8; 32],
        });
        assert!(resp.found);
        let rec = resp.record.unwrap();
        assert_eq!(rec.node_id, [0xAAu8; 32]);
        assert_eq!(rec.gateways.len(), 1);
        assert_eq!(rec.gateways[0].gateway_node_id, [0xBBu8; 32]);
    }

    #[test]
    fn relay_cannot_announce() {
        let leaf = DiscoveryService::new(NodeRole::Leaf);
        let err = leaf
            .handle_announce_attachment(leaf_announce(1, 2))
            .unwrap_err();
        assert_eq!(err, super::service::DiscoveryError::NotAllowed);
    }
}
