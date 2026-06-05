//! Application-endpoint registry.
//!
//! extraction. Implements per-app endpoint addressing, per-endpoint
//! mpsc message channels, stream-window tracking, and (optional) auto-publish
//! into a `DiscoveryService`.

pub mod address;
pub mod registry;
pub mod streams;

/// Counters incremented when an inbound application message can't be queued
/// (channel full / closed). Implemented by veilcore's `NodeMetrics`.
pub trait AppMetrics: Send + Sync {
    fn inc_app_msg_channel_full(&self);
    fn inc_app_msg_channel_closed(&self);
}

pub use address::{AppAddress, app_id};
pub use registry::{AppEndpointRegistry, AppMessage, EndpointHandle};
pub use streams::{
    APP_STREAM_INITIAL_WINDOW, AppStreamSnapshot, AppStreamState, AppStreamTable, OpenResult,
};

#[cfg(test)]
mod integration_tests {
    //! End-to-end test: two distinct application endpoints on the same node
    //! receive only the messages addressed to them, routed through the registry.

    use crate::{
        address::{AppAddress, app_id},
        registry::AppEndpointRegistry,
    };
    use veil_proto::app::{AppDataPayload, AppSendPayload};

    #[test]
    fn two_apps_same_node_receive_independently() {
        let node_id = [0x10u8; 32];
        let chat_id = app_id(&node_id, "veil.chat", "main");
        let files_id = app_id(&node_id, "veil.files", "upload");

        assert_ne!(chat_id, files_id, "different apps must have different ids");

        let registry = AppEndpointRegistry::new();
        let (_h_chat, mut rx_chat) = registry.register(chat_id, 1, 8);
        let (_h_files, mut rx_files) = registry.register(files_id, 1, 8);

        registry.route_data(AppDataPayload {
            app_id: chat_id,
            endpoint_id: 1,
            seq: 1,
            data: b"hi".to_vec(),
        });
        registry.route_data(AppDataPayload {
            app_id: files_id,
            endpoint_id: 1,
            seq: 1,
            data: b"file".to_vec(),
        });

        let chat_msg = rx_chat.try_recv().unwrap();
        let files_msg = rx_files.try_recv().unwrap();

        if let super::registry::AppMessage::Data(d) = chat_msg {
            assert_eq!(d.data, b"hi");
        } else {
            panic!();
        }

        if let super::registry::AppMessage::Data(d) = files_msg {
            assert_eq!(d.data, b"file");
        } else {
            panic!();
        }
    }

    #[test]
    fn app_address_derive_matches_registry_route() {
        let node_id = [0x20u8; 32];
        let addr = AppAddress::derive(node_id, "test.service", "grpc", 8080);

        let registry = AppEndpointRegistry::new();
        let (_h, mut rx) = registry.register(addr.app_id, addr.endpoint_id, 4);

        let routed = registry.route_send(AppSendPayload {
            src_app_id: [0u8; 32],
            app_id: addr.app_id,
            endpoint_id: addr.endpoint_id,
            data: veil_bufpool::pooled_shared_from_vec(b"rpc call".to_vec()),
        });
        assert!(routed);

        if let super::registry::AppMessage::Send(s) = rx.try_recv().unwrap() {
            assert_eq!(s.data.as_ref(), b"rpc call");
        } else {
            panic!();
        }
    }
}
