//! Integration test moved from `veil_discovery::service` (
//! crate-extraction). Verifies the 248.1 auto-publish flow end-to-end:
//! `AppEndpointRegistry::register` triggers
//! `DiscoveryService::announce_app_endpoint`, and a subsequent
//! `handle_get_app_endpoint` lookup finds the freshly-stored entry.
//!
//! Lives at the integration-test layer because it spans
//! `veil-discovery` (DiscoveryService) and `veilcore::node::app::registry`
//! (AppEndpointRegistry).

use std::sync::Arc;

use veil_discovery::DiscoveryService;
use veil_proto::discovery::GetAppEndpointPayload;
use veil_types::NodeRole;

use veil_app::registry::AppEndpointRegistry;

#[test]
fn auto_publish_on_register() {
    let discovery = Arc::new(DiscoveryService::new(NodeRole::Core));
    let node_id = [0x77u8; 32];
    let app_id = [0x88u8; 32];

    let registry =
        AppEndpointRegistry::new().with_auto_publish(node_id, Arc::clone(&discovery), 3600);

    let (_handle, _rx) = registry.register(app_id, 55, 4);

    let resp = discovery.handle_get_app_endpoint(GetAppEndpointPayload {
        node_id,
        app_id,
        endpoint_id: 55,
    });
    assert!(resp.found, "auto-publish must store endpoint in discovery");
}
