//! `PnetStatusProvider` implementation that exposes the daemon's
//! per-peer verified-cert cache to IPC consumers (ogate / oproxy).
//!
//! Lookup is a brief read-lock against the `verified_peer_certs`
//! HashMap shared with the rest of the runtime.  When P-Net is not
//! enabled (gate=None), the cache stays empty and all queries reply
//! `admitted=false / has_cert=false`.
//!
//! `admitted` is derived from `live_sessions`: even if a cert is
//! cached, the peer might have disconnected since; surfacing a
//! stale admission status would break failover semantics on
//! the IPC consumer side.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use veil_ipc::PnetStatusProvider;
use veil_proto::PnetStatusResultPayload;
use veil_types::MembershipCert;

use crate::types::{LinkId, SessionInfo};

/// Snapshot of `live_sessions` keyed by peer node_id for fast
/// `admitted=?` lookups (the live_sessions map is keyed by `LinkId`
/// so a direct query is O(N) — acceptable for testnet but not for
/// production IPC traffic).
pub type LiveSessionsArc = Arc<std::sync::Mutex<std::collections::BTreeMap<LinkId, SessionInfo>>>;

pub struct DaemonPnetStatus {
    verified_peer_certs: Arc<RwLock<HashMap<[u8; 32], MembershipCert>>>,
    live_sessions: LiveSessionsArc,
}

impl DaemonPnetStatus {
    pub fn new(
        verified_peer_certs: Arc<RwLock<HashMap<[u8; 32], MembershipCert>>>,
        live_sessions: LiveSessionsArc,
    ) -> Self {
        Self {
            verified_peer_certs,
            live_sessions,
        }
    }

    fn is_admitted(&self, peer_node_id: &[u8; 32]) -> bool {
        // O(N) scan through live_sessions — N ≈ active session count
        // (testnet: ≤ 100, production sessions plane uses up to 65K
        // per Epic 302 sizing).  Acceptable for a per-stream IPC query
        // since ogate / oproxy cache the result aggressively.
        let g = match self.live_sessions.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.values().any(|info| {
            // EITHER NAME OF THE SAME PEER.
            //
            // `node_id` is the device the handshake proved; `sovereign_node_id`
            // is the identity that device proved it belongs to. An app asks
            // about its CONTACT, and a contact is published as an identity —
            // so matching only the device answered "no session" while a live
            // direct session to that very person sat in this map. Measured on
            // the stand 2026-09-19: `session.open state=active` under
            // `fe9c1b06…`, `admitted=false` for `56d3769d…`, and the call
            // negotiated to relay on the strength of that false.
            //
            // Both are checked, not one substituted for the other: a peer
            // dialled BY device id must still answer to that id, and a legacy
            // peer has no identity to answer to at all.
            info.node_id
                .as_ref()
                .map(|n| n.as_bytes() == peer_node_id)
                .unwrap_or(false)
                || info
                    .sovereign_node_id
                    .as_ref()
                    .map(|n| n.as_bytes() == peer_node_id)
                    .unwrap_or(false)
        })
    }
}

impl PnetStatusProvider for DaemonPnetStatus {
    fn peer_status(&self, peer_node_id: &[u8; 32]) -> PnetStatusResultPayload {
        let admitted = self.is_admitted(peer_node_id);
        let cert_opt = self
            .verified_peer_certs
            .read()
            .ok()
            .and_then(|g| g.get(peer_node_id).cloned());
        match cert_opt {
            Some(cert) => PnetStatusResultPayload {
                admitted,
                has_cert: true,
                admin: cert.admin,
                valid_until_unix: cert.valid_until_unix,
                network_id: cert.network_id,
                peer_node_id: *peer_node_id,
            },
            None => PnetStatusResultPayload {
                admitted,
                has_cert: false,
                admin: false,
                valid_until_unix: 0,
                network_id: [0u8; 32],
                peer_node_id: *peer_node_id,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SessionSource, SessionState};
    use veil_cfg::{NodeId, PeerId};

    const DEVICE: [u8; 32] = [0xfeu8; 32];
    const IDENTITY: [u8; 32] = [0x56u8; 32];
    const STRANGER: [u8; 32] = [0x11u8; 32];

    /// One live direct session, proved as `device` and belonging to
    /// `sovereign` — the shape a sovereign install actually produces.
    fn provider(device: [u8; 32], sovereign: Option<[u8; 32]>) -> DaemonPnetStatus {
        let mut sessions = std::collections::BTreeMap::new();
        sessions.insert(
            LinkId::new(1),
            SessionInfo {
                link_id: LinkId::new(1),
                node_id: Some(NodeId::from(device)),
                sovereign_node_id: sovereign.map(NodeId::from),
                nonce: None,
                matched_peer_id: None,
                source: SessionSource::Outbound(PeerId::new(0x8800_0000)),
                listener_handle: None,
                state: SessionState::Active,
                transport: "quic://192.168.1.111:9000".to_owned(),
                remote_addr: None,
                description: String::new(),
            },
        );
        DaemonPnetStatus::new(
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(std::sync::Mutex::new(sessions)),
        )
    }

    /// The question an APP asks is about a CONTACT, and a contact is an
    /// identity. A live session to that person's device must answer it.
    #[test]
    fn a_session_to_a_device_admits_its_identity() {
        let p = provider(DEVICE, Some(IDENTITY));
        assert!(
            p.is_admitted(&IDENTITY),
            "a live direct session to this identity's device must admit the identity",
        );
    }

    /// Widening must not cost the narrow answer: a peer dialled by device id
    /// still answers to that id.
    #[test]
    fn the_device_still_admits_itself() {
        let p = provider(DEVICE, Some(IDENTITY));
        assert!(p.is_admitted(&DEVICE), "the device must still admit itself");
    }

    /// Neither name may admit a third party.
    #[test]
    fn a_stranger_is_not_admitted() {
        let p = provider(DEVICE, Some(IDENTITY));
        assert!(
            !p.is_admitted(&STRANGER),
            "an unrelated node must not be admitted"
        );
    }

    /// A legacy peer proves no identity; there is nothing to widen to, and
    /// an identity must not become admitted on the strength of its absence.
    #[test]
    fn no_proof_admits_only_the_device() {
        let p = provider(DEVICE, None);
        assert!(p.is_admitted(&DEVICE));
        assert!(
            !p.is_admitted(&IDENTITY),
            "without a proof the identity has nothing to be admitted by",
        );
    }
}
