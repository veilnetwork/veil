//! IPC → runtime adapter for peer-list snapshots.
//!
//! Implements [`veil_ipc::PeerListProvider`] over the runtime's
//! `live_sessions` map. Constructed in `spawn_ipc_server` and handed
//! [`veil_ipc::IpcServer::with_peer_list_provider`].

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use veil_util::lock;

use veil_ipc::PeerListProvider;
use veil_proto::{
    MAX_PEERS_LIST_ENTRIES, PeersListEntry, PeersListPayload, peer_direction, peer_state,
};

use crate::types::{LinkId, SessionInfo, SessionSource, SessionState};

/// Snapshots `live_sessions` on demand for IPC `GetPeers` queries.
pub struct LiveSessionsPeerList {
    live_sessions: Arc<Mutex<BTreeMap<LinkId, SessionInfo>>>,
}

impl LiveSessionsPeerList {
    pub fn new(live_sessions: Arc<Mutex<BTreeMap<LinkId, SessionInfo>>>) -> Self {
        Self { live_sessions }
    }
}

impl PeerListProvider for LiveSessionsPeerList {
    fn list_peers(&self) -> PeersListPayload {
        let sessions = lock!(self.live_sessions);
        let mut peers = Vec::with_capacity(sessions.len().min(MAX_PEERS_LIST_ENTRIES));

        for session in sessions.values() {
            // Skip sessions whose peer hasn't completed handshake yet —
            // a `node_id == None` entry means we don't know who's on the
            // other end, which is useless for UI display and unsafe to
            // surface (would let UI render "?" rows that confuse users).
            let Some(node_id) = session.node_id else {
                continue;
            };
            // Skip duplicate node_ids — sessions map can transiently
            // hold a closing+opening pair for the same peer during a
            // reconnect. UI wants distinct-peer rows, not link rows.
            if peers
                .iter()
                .any(|p: &PeersListEntry| p.node_id == *node_id.as_bytes())
            {
                continue;
            }
            // Hard cap defensively at MAX_PEERS_LIST_ENTRIES even though
            // the IPC handler also trims — saves a clone per overflow.
            if peers.len() >= MAX_PEERS_LIST_ENTRIES {
                break;
            }
            let direction = match session.source {
                SessionSource::Inbound(_) => peer_direction::INBOUND,
                SessionSource::Outbound(_) => peer_direction::OUTBOUND,
            };
            let state_byte = match session.state {
                // Both Active and DebugAttached map to "ACTIVE" for UI —
                // DebugAttached is an operator-internal mode where session
                // is bridged to admin debug stream, but the peer is still
                // online from the user's perspective.
                SessionState::Active | SessionState::DebugAttached => peer_state::ACTIVE,
            };
            peers.push(PeersListEntry {
                node_id: *node_id.as_bytes(),
                state: state_byte,
                direction,
                transport: session.transport.as_bytes().to_vec(),
            });
        }

        PeersListPayload { peers }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ListenerHandle, NodeId, PeerId};

    fn make_session(
        link_id: u64,
        node_id_byte: u8,
        outbound: bool,
        transport: &str,
    ) -> SessionInfo {
        let nid = NodeId::from([node_id_byte; 32]);
        let source = if outbound {
            SessionSource::Outbound(PeerId::new(0u32))
        } else {
            SessionSource::Inbound(crate::types::ListenId::new(1u32))
        };
        SessionInfo {
            link_id: LinkId::new(link_id),
            node_id: Some(nid),
            nonce: None,
            matched_peer_id: None,
            source,
            listener_handle: outbound.then_some(ListenerHandle::new(0)),
            state: SessionState::Active,
            transport: transport.to_string(),
            remote_addr: None,
            description: String::new(),
        }
    }

    #[test]
    fn empty_sessions_returns_empty_list() {
        let sessions = Arc::new(Mutex::new(BTreeMap::new()));
        let provider = LiveSessionsPeerList::new(sessions);
        let payload = provider.list_peers();
        assert!(payload.peers.is_empty());
    }

    #[test]
    fn single_outbound_session_appears_once() {
        let mut map = BTreeMap::new();
        map.insert(
            LinkId::new(1),
            make_session(1, 0xAB, true, "tcp://1.2.3.4:5555"),
        );
        let sessions = Arc::new(Mutex::new(map));
        let provider = LiveSessionsPeerList::new(sessions);
        let payload = provider.list_peers();
        assert_eq!(payload.peers.len(), 1);
        assert_eq!(payload.peers[0].node_id, [0xAB; 32]);
        assert_eq!(payload.peers[0].direction, peer_direction::OUTBOUND);
        assert_eq!(payload.peers[0].state, peer_state::ACTIVE);
        assert_eq!(payload.peers[0].transport, b"tcp://1.2.3.4:5555");
    }

    #[test]
    fn skip_session_without_node_id() {
        // Mid-handshake session — node_id not yet known.
        let mut map = BTreeMap::new();
        let mut s = make_session(1, 0, true, "tcp://1.2.3.4:5555");
        s.node_id = None;
        map.insert(LinkId::new(1), s);
        let sessions = Arc::new(Mutex::new(map));
        let provider = LiveSessionsPeerList::new(sessions);
        let payload = provider.list_peers();
        assert!(
            payload.peers.is_empty(),
            "session without node_id must not appear in peer list"
        );
    }

    #[test]
    fn dedup_same_node_id_across_links() {
        // Reconnect storm — two link entries for the same peer node_id.
        let mut map = BTreeMap::new();
        map.insert(
            LinkId::new(1),
            make_session(1, 0xCD, true, "tcp://1.2.3.4:5555"),
        );
        map.insert(
            LinkId::new(2),
            make_session(2, 0xCD, true, "tcp://1.2.3.4:5555"),
        );
        let sessions = Arc::new(Mutex::new(map));
        let provider = LiveSessionsPeerList::new(sessions);
        let payload = provider.list_peers();
        assert_eq!(
            payload.peers.len(),
            1,
            "duplicate node_ids must be folded — UI displays per-peer not per-link"
        );
    }

    #[test]
    fn inbound_session_marked_inbound() {
        let mut map = BTreeMap::new();
        map.insert(
            LinkId::new(1),
            make_session(1, 0xEF, false, "tcp://10.0.0.1:5555"),
        );
        let sessions = Arc::new(Mutex::new(map));
        let provider = LiveSessionsPeerList::new(sessions);
        let payload = provider.list_peers();
        assert_eq!(payload.peers[0].direction, peer_direction::INBOUND);
    }
}
