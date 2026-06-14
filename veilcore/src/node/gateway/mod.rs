//! Re-export shim for the extracted [`veil-gateway`](veil_gateway) crate.
//!
//! Phase 3 prep (veilcore extraction): the gateway service (ATTACH /
//! DETACH / KEEPALIVE handlers for Core-node leaves) and its sub-modules
//! (attachment / endpoint / lease) moved to the veil-gateway sibling
//! crate alongside the existing `GatewayList` scoring/failover code.
//! Existing call sites use `crate::node::gateway::*` — preserved via
//! re-export.

pub use veil_gateway::*;
pub use veil_gateway::{attachment, endpoint, lease, service};

#[cfg(test)]
mod integration_tests {
    //! End-to-end test: leaf attaches to gateway, sends keepalives, then
    //! detaches. Validates the full attach→renew→detach lifecycle.

    use std::time::{Duration, Instant};

    use veil_gateway::GatewayService;

    use crate::{
        cfg::NodeRole,
        proto::session::{AttachPayload, DetachPayload, KeepalivePayload, detach_reason},
    };

    fn leaf_attach_payload() -> AttachPayload {
        AttachPayload {
            role: 1, // leaf
            realm_id: 100,
            attach_epoch: 42,
            mailbox_preference_count: 1,
            gateway_preference_count: 1,
            flags: 0,
        }
    }

    #[test]
    fn leaf_attach_keepalive_detach_lifecycle() {
        let gateway = GatewayService::new(NodeRole::Core);
        let leaf_id = [0xAAu8; 32];

        gateway
            .handle_attach(leaf_id, &leaf_attach_payload())
            .unwrap();
        assert!(gateway.is_attached(&leaf_id));
        assert_eq!(gateway.attachment_count(), 1);

        let ka = KeepalivePayload {
            timestamp_secs: veil_util::unix_secs_now_u64(),
        };
        gateway.handle_keepalive(&leaf_id, &ka).unwrap();
        assert!(gateway.is_attached(&leaf_id));

        let detach = DetachPayload {
            reason: detach_reason::NORMAL,
        };
        gateway.handle_detach(&leaf_id, &detach).unwrap();
        assert!(!gateway.is_attached(&leaf_id));
        assert_eq!(gateway.attachment_count(), 0);
    }

    #[test]
    fn expired_attachment_cleaned_up_by_background_task() {
        let gateway = GatewayService::new(NodeRole::Core);
        {
            let mut table = gateway.table.lock().unwrap();
            table.lease_ttl = Duration::from_nanos(1);
        }

        let leaf_id = [0xBBu8; 32];
        gateway
            .handle_attach(leaf_id, &leaf_attach_payload())
            .unwrap();

        std::thread::sleep(Duration::from_millis(5));
        gateway.cleanup_expired(Instant::now());

        assert!(!gateway.is_attached(&leaf_id));
        assert_eq!(gateway.attachment_count(), 0);
    }

    #[test]
    fn multiple_leaves_attach_independently() {
        let gateway = GatewayService::new(NodeRole::Core);
        for i in 0u8..5 {
            gateway
                .handle_attach([i; 32], &leaf_attach_payload())
                .unwrap();
        }
        assert_eq!(gateway.attachment_count(), 5);

        gateway
            .handle_detach(
                &[2u8; 32],
                &DetachPayload {
                    reason: detach_reason::SHUTDOWN,
                },
            )
            .unwrap();
        assert_eq!(gateway.attachment_count(), 4);
        assert!(!gateway.is_attached(&[2u8; 32]));
    }
}
