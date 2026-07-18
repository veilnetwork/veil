//! RAII guard ensuring session teardown invariants run regardless of how
//! the owning struct (`AttachedDebugSession`) is dropped — normal close,
//! panic, or async cancellation.
//!
//! ## Canonical lock-acquisition order
//!
//! All paths that need more than one of these MUST acquire them in this
//! exact order; deviation risks a runtime deadlock under load.
//!
//! 1. `route_cache`                  (RwLock)
//! 2. `live_sessions`                (Mutex)
//! 3. `session_registry`             (Mutex)
//! 4. `session_tx_registry`          (Mutex)
//! 5. `peer_sovereign_identities`    (Mutex)
//! 6. `peer_pubkeys` / `peer_roles`  (LRU caches; per-call lock, never held over await)
//! 7. `sessions_per_ip`              (Mutex)
//! 8. `reputation`                   (Mutex; admin paths)
//!
//! `SessionGuard::drop` follows a strict subset:
//! `live_sessions → session_registry → session_tx_registry → sessions_per_ip
//! → reputation`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use veil_util::{lock, wlock};

use crate::types::{LinkId, SessionInfo};
use veil_reputation::ReputationTracker;
use veil_session::{SessionRegistry, SessionTxRegistry};

use super::ip_slot::IpSlotTable;
use super::{NodeLogger, NodeMetrics};

pub struct SessionGuard {
    live_sessions: Arc<Mutex<BTreeMap<LinkId, SessionInfo>>>,
    link_id: LinkId,
    logger: Arc<NodeLogger>,
    metrics: Option<Arc<NodeMetrics>>,
    /// OVL1 session_id — always present after a successful OVL1 handshake.
    /// Removed from the `SessionRegistry` on drop.
    session_id: [u8; 32],
    session_registry: Arc<Mutex<SessionRegistry>>,
    /// Source IP address (inbound connections only).  Used to decrement
    /// the per-IP session counter when this session ends.
    source_ip: Option<IpAddr>,
    /// Shared per-IP session counter map.
    sessions_per_ip: Arc<IpSlotTable>,
    /// Peer node_id for reputation tracking on session close. Also the key
    /// under which this session's outbox sender lives in `session_tx_registry`.
    peer_node_id: [u8; 32],
    /// Per-session outbox registry (node_id-keyed). On drop we remove only the
    /// sender whose owner token equals this guard's `session_id`. A reconnect
    /// may already have installed a newer sender under the same stable node id;
    /// owner-aware removal makes late old-runner teardown harmless.
    session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
    /// Shared reputation tracker — `session_closed` called on drop.
    reputation: Option<Arc<Mutex<ReputationTracker>>>,
    /// Shared push-event bus — publish `SESSIONS_CHANGED` on drop so
    /// connected apps see live counts decrement in real time.
    event_bus: Arc<veil_ipc::EventBus>,
}

impl SessionGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        live_sessions: Arc<Mutex<BTreeMap<LinkId, SessionInfo>>>,
        link_id: LinkId,
        logger: Arc<NodeLogger>,
        metrics: Option<Arc<NodeMetrics>>,
        session_id: [u8; 32],
        session_registry: Arc<Mutex<SessionRegistry>>,
        source_ip: Option<IpAddr>,
        sessions_per_ip: Arc<IpSlotTable>,
        peer_node_id: [u8; 32],
        session_tx_registry: Arc<RwLock<SessionTxRegistry>>,
        reputation: Option<Arc<Mutex<ReputationTracker>>>,
        event_bus: Arc<veil_ipc::EventBus>,
    ) -> Self {
        Self {
            live_sessions,
            link_id,
            logger,
            metrics,
            session_id,
            session_registry,
            source_ip,
            sessions_per_ip,
            peer_node_id,
            session_tx_registry,
            reputation,
            event_bus,
        }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        // Snapshot-then-publish: take each lock briefly to mutate its
        // map, then release before doing observable side-effects
        // (event_bus.publish, reputation notify, log).  Keeps the
        // teardown latency tail bounded: a slow event-bus subscriber or
        // a panic in reputation cannot stall live_sessions /
        // session_registry / sessions_per_ip past the snapshot point.

        // ── state mutations under locks (canonical order) ──────

        // live_sessions: remove this entry and observe the new total for the
        // SESSIONS_CHANGED publish below.
        let new_count = {
            let mut sessions = lock!(self.live_sessions);
            sessions.remove(&self.link_id);
            sessions.len()
        };

        // session_registry: resolve sovereign identity for reputation
        // BEFORE removing the session entry — the registry is the only
        // holder of the peer→identity binding, and the reputation tracker
        // keys on node_id (rotation-stable), not the per-device peer_id.
        // Legacy peers without a sovereign identity fall back to peer_id
        // as a degenerate identifier so legacy reputation behaviour is
        // unchanged.  Single lock acquisition.
        let identity_for_rep = {
            let mut reg = lock!(self.session_registry);
            let id = reg
                .node_id_for_peer(&self.peer_node_id.into())
                .unwrap_or(self.peer_node_id);
            reg.remove(&self.session_id);
            id
        };

        // session_tx_registry: remove THIS session's sender, but never a fresh
        // reconnect that has already replaced it under the same node id.
        // Canonical order slot 4 (after session_registry, before sessions_per_ip).
        wlock!(self.session_tx_registry).unregister_owned(&self.peer_node_id, &self.session_id);

        // sessions_per_ip: decrement counter for inbound connections.
        // Released via IpSlotTable::release which atomically decrements
        // both per_ip and per_subnet maps under one Mutex.
        if let Some(ip) = self.source_ip {
            self.sessions_per_ip.release(ip);
        }

        // ── side-effects (no session-state locks held) ─────────

        if let Some(metrics) = &self.metrics {
            metrics.dec_active_sessions();
        }

        // event_bus.publish is `tokio::sync::broadcast::send` — non-
        // blocking, drops to slow subscribers rather than backpressuring
        // us.  Still, keep it outside the map locks so a subscriber
        // observation re-entering our locks via a handler sees a
        // consistent state.
        let count_u16 = new_count.min(u16::MAX as usize) as u16;
        self.event_bus.publish(veil_proto::EventPayload {
            kind: veil_proto::event_kind::SESSIONS_CHANGED,
            payload: count_u16.to_be_bytes().to_vec(),
        });

        // Reputation tracker keys on sovereign node_id (rotation-stable).
        // Last so a panic inside `session_closed` poisons only the
        // reputation mutex, not the more critical state mutexes above.
        if let Some(ref rep) = self.reputation {
            lock!(rep).session_closed(identity_for_rep.into());
        }

        self.logger
            .info("session.close", format!("link_id={}", self.link_id));
    }
}
