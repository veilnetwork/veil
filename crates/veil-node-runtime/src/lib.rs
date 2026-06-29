//! OVL1 node runtime crate — Phase 4 of veilcore extraction.

pub mod admin;
pub mod admin_audit;
pub mod admin_transport;
pub mod bootstrap_invite_create;
pub mod bootstrap_join;
pub mod builtin;
pub mod dht_fallback;
pub mod dht_glue;
pub mod error;
pub mod identity_local;
pub mod key_passphrase;
pub mod lazy_miner;
pub mod listener_supervisor;
pub mod local_identity;
pub mod memory;
pub mod mesh_glue;
pub mod metrics_http;
pub mod mlkem_resolver;
pub mod mobile_sink;
pub mod mobile_status_provider;
pub mod outbound_connector;
pub mod pairing_forwarder;
pub mod peer_list_provider;
pub mod pnet_status_provider;
pub mod proxy;
pub mod runtime;
pub mod socks_fallback;
pub mod state;
pub mod task_registry;
#[cfg(test)]
pub mod test_support;
pub mod types;

pub use error::{NodeError, Result};
pub use runtime::NodeRuntime;
// onion-stream Phase 1d: embedded-node bridge so veilclient-ffi can drive pinned
// stream circuits in-process (the IPC surface has no circuit path).
pub use runtime::services::{embedded_services, publish_embedded_services};
pub use state::NodeState;
pub use types::{
    LinkId, ListenConfigEntry, ListenId, ListenerHandle, NodeId, NodeIdBytes, NodeSummary,
    PeerConfigEntry, PeerId, PeerSource, SessionInfo, SessionSource, SessionState,
};
