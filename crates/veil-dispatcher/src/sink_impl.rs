//! `impl DispatcherSink for FrameDispatcher` block.
//!
//! Phase 2 session 2 (veilcore extraction): trait moved к
//! [`veil_session::dispatcher_sink::DispatcherSink`] sibling crate;
//! impl stays here next к [`FrameDispatcher`]'s definition (Rust
//! orphan rule: impl block must live в the crate where one of the
//! involved types is local).

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock, Weak};

use tokio::sync::Semaphore;
use veil_observability::NodeLogger;
use veil_proto::header::FrameHeader;
use veil_session::dispatcher_sink::{DispatchResult, DispatcherSink};
use veil_session::rendezvous::RendezvousController;
use veil_session::tx_registry::SessionTxRegistry;
use veil_types::NodeIdBytes;

use crate::FrameDispatcher;

impl DispatcherSink for FrameDispatcher {
    fn dispatch(&self, header: &FrameHeader, body: &[u8], peer_id: NodeIdBytes) -> DispatchResult {
        FrameDispatcher::dispatch(self, header, body, peer_id)
    }

    fn capture_outbound(&self, peer_id: NodeIdBytes, frame: &[u8]) {
        FrameDispatcher::capture_outbound(self, peer_id, frame)
    }

    fn allow_outbound_bandwidth(&self, bytes: usize) -> bool {
        veil_util::lock!(self.abuse.outbound_bandwidth).allow_bytes(bytes)
    }

    fn logger(&self) -> &Arc<NodeLogger> {
        &self.logger
    }

    fn session_tx_registry(&self) -> Option<Arc<RwLock<SessionTxRegistry>>> {
        self.session_tx_registry.clone()
    }

    fn dht(&self) -> &Arc<veil_dht::KademliaService> {
        &self.dht
    }

    fn rendezvous_weak(&self) -> Arc<Mutex<Option<Weak<RendezvousController>>>> {
        Arc::clone(&self.rendezvous_weak)
    }

    fn pow_solver_semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(&self.pow_solver_semaphore)
    }

    fn pow_active_difficulty(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.pow_active_difficulty)
    }

    fn route_cache(&self) -> Arc<RwLock<veil_routing::RouteCache>> {
        Arc::clone(&self.route_cache)
    }

    fn register_session_aliases(
        &self,
        local_alias: [u8; 8],
        local_node_id: NodeIdBytes,
        remote_alias: [u8; 8],
        remote_node_id: NodeIdBytes,
    ) {
        FrameDispatcher::register_session_aliases(
            self,
            local_alias,
            local_node_id,
            remote_alias,
            remote_node_id,
        )
    }

    fn unregister_session_aliases(&self, local_alias: [u8; 8], remote_alias: [u8; 8]) {
        FrameDispatcher::unregister_session_aliases(self, local_alias, remote_alias)
    }
}
