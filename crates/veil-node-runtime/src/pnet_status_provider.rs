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
            info.node_id
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
