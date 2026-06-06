//! Adapter that exposes [`SessionTxRegistry`] as the cross-crate
//! [`veil_types::FrameBroadcaster`] trait.
//!
//! Phase 3 prep (veilcore extraction): moved here from
//! `veilcore/src/node/session_glue.rs` so dispatcher can dep on
//! veil-session directly without a glue-layer detour through veilcore.
//! Consumed by `veil_routing::miss_handler` + future Tier-3 crates
//! (veil-pex, veil-proxy, veil-ipc) that accept any
//! `Arc<dyn FrameBroadcaster>` instead of importing `SessionTxRegistry`.

use std::sync::{Arc, RwLock};

use veil_util::rlock;

use crate::tx_registry::SessionTxRegistry;

/// Wraps `Arc<RwLock<SessionTxRegistry>>` so the trait method can stay
/// `&self` while the underlying registry mutates the senders map under
/// `&mut self`.
pub struct SessionTxBroadcaster {
    inner: Arc<RwLock<SessionTxRegistry>>,
}

impl SessionTxBroadcaster {
    pub fn new(inner: Arc<RwLock<SessionTxRegistry>>) -> Self {
        Self { inner }
    }
}

impl veil_types::FrameBroadcaster for SessionTxBroadcaster {
    fn send_to(&self, peer_id: &[u8; 32], priority: u8, bytes: Vec<u8>) -> bool {
        rlock!(self.inner).send_to(peer_id, priority, bytes)
    }

    fn send_to_all_with_priority(&self, priority: u8, bytes: Arc<[u8]>) {
        // SessionTxRegistry consumes PooledShared, but the
        // veil-types trait passes Arc<[u8]> (changing it cascades to
        // every consumer — pex, gossip, identity, etc.). Convert via Vec copy
        // here. Hot-path callers that want zero-copy use the impl directly
        // through SessionTxRegistry without going through this trait.
        let v = bytes.to_vec();
        rlock!(self.inner)
            .send_to_all_with_priority(priority, veil_bufpool::pooled_shared_from_vec(v));
    }

    fn active_node_ids(&self) -> Vec<[u8; 32]> {
        rlock!(self.inner).active_node_ids().into_iter().collect()
    }
}
