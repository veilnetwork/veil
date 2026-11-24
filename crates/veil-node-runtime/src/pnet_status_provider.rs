//! `PnetStatusProvider` implementation that exposes the daemon's
//! per-peer verified-cert cache to IPC consumers (ogate / oproxy).
//!
//! Certificate lookup is a brief read-lock against `verified_peer_certs`.
//! When P-Net is not enabled the certificate cache stays empty, so queries
//! reply `has_cert=false`; a live public-mode session can still be admitted.
//!
//! `admitted` requires a completed handshake and its current TX owner. The
//! sender can be retired before the runner finishes tearing down, or reserved
//! before the successor commits its handshake. A P-Net certificate also
//! has to remain current, and a ban overrides a live private session.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use veil_abuse::BanList;
use veil_cfg::NodeId;
use veil_ipc::PnetStatusProvider;
use veil_proto::PnetStatusResultPayload;
use veil_session::{SessionEntry, SessionRegistry, SessionTxRegistry};
use veil_types::MembershipCert;
use veil_util::{lock, rlock, unix_secs_now_u64};

pub struct DaemonPnetStatus {
    verified_peer_certs: Arc<RwLock<HashMap<[u8; 32], MembershipCert>>>,
    sessions: Arc<Mutex<SessionRegistry>>,
    tx: Arc<RwLock<SessionTxRegistry>>,
    bans: Option<Arc<Mutex<BanList>>>,
}

impl DaemonPnetStatus {
    pub fn new(
        verified_peer_certs: Arc<RwLock<HashMap<[u8; 32], MembershipCert>>>,
        sessions: Arc<Mutex<SessionRegistry>>,
        tx: Arc<RwLock<SessionTxRegistry>>,
    ) -> Self {
        Self {
            verified_peer_certs,
            sessions,
            tx,
            bans: None,
        }
    }

    pub(crate) fn with_bans(mut self, bans: Arc<Mutex<BanList>>) -> Self {
        self.bans = Some(bans);
        self
    }

    pub(crate) fn is_admitted(&self, peer_node_id: &[u8; 32]) -> bool {
        // Match the runtime lock order and require the same owner in both
        // registries. An old committed entry cannot admit a reserved successor.
        let sessions = lock!(self.sessions);
        let tx = rlock!(self.tx);
        let name = NodeId::from(*peer_node_id);
        let owns_sender =
            |entry: &SessionEntry| tx.owns_live_session(&entry.remote_node_id, &entry.session_id);
        sessions.get_by_peer_id(&name).is_some_and(owns_sender)
            || sessions.sessions_for_identity(&name).any(owns_sender)
    }
}

impl PnetStatusProvider for DaemonPnetStatus {
    fn peer_status(&self, peer_node_id: &[u8; 32]) -> PnetStatusResultPayload {
        let admitted = self.is_admitted(peer_node_id);
        let cert = self.verified_peer_certs.read().ok().and_then(|cached| {
            cached
                .get(peer_node_id)
                .map(|cert| (cert.admin, cert.valid_until_unix, cert.network_id))
        });
        match cert {
            Some((admin, valid_until_unix, network_id)) => {
                let now = unix_secs_now_u64();
                let current = valid_until_unix == 0 || (now != 0 && now < valid_until_unix);
                let banned = self
                    .bans
                    .as_ref()
                    .is_some_and(|bans| lock!(bans).is_banned(peer_node_id));
                PnetStatusResultPayload {
                    admitted: admitted && current && !banned,
                    has_cert: true,
                    admin,
                    valid_until_unix,
                    network_id,
                    peer_node_id: *peer_node_id,
                }
            }
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
    use veil_identity::verify::ValidatedIdentity;
    use veil_proto::session::{AttachPayload, CapabilitiesPayload, IdentityPayload};
    use veil_session::{FrameOutbox, RemoteRole};

    const DEVICE: [u8; 32] = [0xfeu8; 32];
    const IDENTITY: [u8; 32] = [0x56u8; 32];
    const STRANGER: [u8; 32] = [0x11u8; 32];
    const OWNER: [u8; 32] = [0x42; 32];

    /// One live direct session, proved as `device` and belonging to
    /// `sovereign` — the shape a sovereign install actually produces.
    fn entry(device: [u8; 32], sovereign: Option<[u8; 32]>, owner: [u8; 32]) -> SessionEntry {
        SessionEntry {
            session_id: owner,
            remote_node_id: device,
            remote_identity: IdentityPayload {
                algo: 1,
                public_key: vec![5; 32],
                nonce: vec![3; 16],
                node_id: device,
                mlkem_pubkey: None,
            },
            remote_capabilities: CapabilitiesPayload {
                roles_supported: 0,
                flags: 0,
                extra_flags: 0,
                extra_flags2: 0,
                discovery_mode: 0,
            },
            remote_attach: AttachPayload {
                role: 0,
                realm_id: 0,
                attach_epoch: 1,
                mailbox_preference_count: 0,
                gateway_preference_count: 0,
                flags: 0,
            },
            remote_role: RemoteRole::Leaf,
            validated_sovereign_identity: sovereign.map(|node_id| ValidatedIdentity {
                node_id,
                master_algo: 1,
                master_pubkey: vec![1; 32],
                active_identity_pubkey: vec![2; 32],
                active_identity_algo: 1,
                active_key_idx: 0,
                active_device_id: device,
                active_instance_id: [device[0]; 16],
            }),
        }
    }

    fn provider(device: [u8; 32], sovereign: Option<[u8; 32]>) -> (DaemonPnetStatus, FrameOutbox) {
        let mut sessions = SessionRegistry::new();
        sessions.insert(entry(device, sovereign, OWNER));
        let mut tx = SessionTxRegistry::new();
        let outbox = tx.register_owned(device, OWNER);
        let status = DaemonPnetStatus::new(
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(std::sync::Mutex::new(sessions)),
            Arc::new(RwLock::new(tx)),
        );
        (status, outbox)
    }

    /// The question an APP asks is about a CONTACT, and a contact is an
    /// identity. A live session to that person's device must answer it.
    #[test]
    fn a_session_to_a_device_admits_its_identity() {
        let (p, _outbox) = provider(DEVICE, Some(IDENTITY));
        assert!(
            p.is_admitted(&IDENTITY),
            "a live direct session to this identity's device must admit the identity",
        );
    }

    /// Widening must not cost the narrow answer: a peer dialled by device id
    /// still answers to that id.
    #[test]
    fn the_device_still_admits_itself() {
        let (p, _outbox) = provider(DEVICE, Some(IDENTITY));
        assert!(p.is_admitted(&DEVICE), "the device must still admit itself");
    }

    /// Neither name may admit a third party.
    #[test]
    fn a_stranger_is_not_admitted() {
        let (p, _outbox) = provider(DEVICE, Some(IDENTITY));
        assert!(
            !p.is_admitted(&STRANGER),
            "an unrelated node must not be admitted"
        );
    }

    /// A legacy peer proves no identity; there is nothing to widen to, and
    /// an identity must not become admitted on the strength of its absence.
    #[test]
    fn no_proof_admits_only_the_device() {
        let (p, _outbox) = provider(DEVICE, None);
        assert!(p.is_admitted(&DEVICE));
        assert!(
            !p.is_admitted(&IDENTITY),
            "without a proof the identity has nothing to be admitted by",
        );
    }

    fn cache_cert(status: &DaemonPnetStatus, valid_until_unix: u64) {
        status.verified_peer_certs.write().unwrap().insert(
            DEVICE,
            MembershipCert {
                version: veil_types::MEMBERSHIP_CERT_VERSION,
                network_id: [3; 32],
                member_node_id: DEVICE,
                issued_at_unix: 0,
                valid_until_unix,
                admin: false,
                algo: veil_types::SignatureAlgorithm::Ed25519,
                owner_signature: vec![],
            },
        );
    }

    #[test]
    fn pnet_ban_overrides_a_live_committed_session() {
        let (status, _outbox) = provider(DEVICE, None);
        let bans = Arc::new(Mutex::new(BanList::new()));
        let status = status.with_bans(Arc::clone(&bans));
        cache_cert(&status, 0);
        assert!(status.peer_status(&DEVICE).admitted);

        bans.lock().unwrap().ban_manual(DEVICE, "test ban");
        let banned = status.peer_status(&DEVICE);
        assert!(banned.has_cert);
        assert!(!banned.admitted);
        assert!(status.is_admitted(&DEVICE));

        bans.lock().unwrap().unban(&DEVICE);
        assert!(status.peer_status(&DEVICE).admitted);
    }

    #[test]
    fn expiry_disables_pnet_admission_and_keeps_cert_metadata() {
        let (status, _outbox) = provider(DEVICE, None);
        assert!(status.peer_status(&DEVICE).admitted);

        cache_cert(&status, 1);
        let expired = status.peer_status(&DEVICE);
        assert!(expired.has_cert);
        assert_eq!(expired.valid_until_unix, 1);
        assert!(!expired.admitted);
    }

    #[test]
    fn old_committed_owner_cannot_admit_an_uncommitted_replacement() {
        let (p, _old) = provider(DEVICE, Some(IDENTITY));
        let successor = [0x43; 32];
        let new = p.tx.write().unwrap().register_owned(DEVICE, successor);
        assert!(!p.is_admitted(&DEVICE));
        assert!(!p.is_admitted(&IDENTITY));

        p.sessions
            .lock()
            .unwrap()
            .insert(entry(DEVICE, None, successor));
        assert!(p.is_admitted(&DEVICE));
        assert!(!p.is_admitted(&IDENTITY));
        drop(new);
        assert!(!p.is_admitted(&DEVICE));
    }

    #[test]
    fn a_retired_device_does_not_hide_its_committed_sibling() {
        let (p, _old) = provider(DEVICE, Some(IDENTITY));
        let sibling = [0xfa; 32];
        let sibling_owner = [0x44; 32];
        let _new = p.tx.write().unwrap().register_owned(sibling, sibling_owner);
        p.sessions
            .lock()
            .unwrap()
            .insert(entry(sibling, Some(IDENTITY), sibling_owner));
        p.tx.write().unwrap().unregister(&DEVICE);
        assert!(!p.is_admitted(&DEVICE));
        assert!(p.is_admitted(&sibling));
        assert!(p.is_admitted(&IDENTITY));
    }
}
