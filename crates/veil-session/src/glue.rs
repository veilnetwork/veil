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
    /// The session registry, when this adapter was given one — the only place
    /// that knows which DEVICES an identity currently has sessions on.
    ///
    /// Optional because most of the seven construction sites are wrappers that
    /// never resolve an identity (proxy frame routing, test doubles), and a
    /// required parameter would have made every one of them carry a registry
    /// they do not use. Absent means `devices_of` answers empty, which is the
    /// documented "I cannot answer this" — the pre-existing behaviour.
    sessions: Option<Arc<std::sync::Mutex<crate::SessionRegistry>>>,
}

impl SessionTxBroadcaster {
    pub fn new(inner: Arc<RwLock<SessionTxRegistry>>) -> Self {
        Self {
            inner,
            sessions: None,
        }
    }

    /// Give this adapter the session registry, so an identity address can be
    /// resolved to the devices currently holding sessions for it.
    pub fn with_sessions(
        mut self,
        sessions: Arc<std::sync::Mutex<crate::SessionRegistry>>,
    ) -> Self {
        self.sessions = Some(sessions);
        self
    }
}

impl veil_types::FrameBroadcaster for SessionTxBroadcaster {
    fn send_to(&self, peer_id: &[u8; 32], priority: u8, bytes: Vec<u8>) -> bool {
        rlock!(self.inner).send_to(peer_id, priority, bytes)
    }

    fn devices_of(&self, identity: &[u8; 32]) -> Vec<[u8; 32]> {
        let Some(sessions) = self.sessions.as_ref() else {
            return Vec::new();
        };
        let guard = match sessions.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .peer_ids_for_identity(&veil_cfg::NodeId::from(*identity))
            .into_iter()
            .map(|(_instance_id, peer_id)| peer_id)
            .collect()
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

/// Adapter exposing [`SessionRegistry`](crate::manager::SessionRegistry) as
/// [`veil_types::SessionInstanceLookup`] — the same shape as
/// [`SessionTxBroadcaster`], for the same reason: veil-ipc's send path needs
/// one answer ("which DEVICE is at the far end of the session to this
/// identity?") without importing the registry concretely, which its crate
/// tier forbids.
pub struct SessionInstanceDirectory {
    inner: Arc<std::sync::Mutex<crate::manager::SessionRegistry>>,
}

impl SessionInstanceDirectory {
    pub fn new(inner: Arc<std::sync::Mutex<crate::manager::SessionRegistry>>) -> Self {
        Self { inner }
    }
}

impl veil_types::SessionInstanceLookup for SessionInstanceDirectory {
    fn session_instance(&self, peer_node_id: &[u8; 32]) -> Option<[u8; 16]> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_by_peer_id(&veil_cfg::NodeId::from(*peer_node_id))
            .and_then(|e| e.validated_sovereign_identity.as_ref())
            // The instance the handshake's identity proof named — the one
            // answer that is about THIS session rather than about whatever
            // the peer's registry happened to list.
            .map(|v| v.active_instance_id)
    }

    fn session_pairing(&self, peer_node_id: &[u8; 32]) -> Option<veil_types::SessionPairing> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_by_peer_id(&veil_cfg::NodeId::from(*peer_node_id))
            .and_then(|e| e.validated_sovereign_identity.as_ref())
            // Both from the SAME proof, so they cannot disagree: taking the
            // identity from one place and the device from another is how the
            // two halves of one formula ended up on different inputs before.
            .map(|v| veil_types::SessionPairing {
                identity: v.node_id,
                instance: v.active_instance_id,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use veil_types::FrameBroadcaster;

    const DEVICE_A: [u8; 32] = [0xaau8; 32];
    const DEVICE_B: [u8; 32] = [0xbbu8; 32];
    const IDENTITY: [u8; 32] = [0x56u8; 32];

    fn tx() -> Arc<RwLock<SessionTxRegistry>> {
        Arc::new(RwLock::new(SessionTxRegistry::with_capacity(8)))
    }

    /// An adapter given no registry keeps the behaviour it had before this
    /// existed: it answers "I cannot tell you", not "there are none".
    #[test]
    fn without_a_registry_devices_of_is_empty() {
        let b = SessionTxBroadcaster::new(tx());
        assert!(b.devices_of(&IDENTITY).is_empty());
    }

    /// The default path must be untouched: a device address still goes
    /// straight out, and a destination nobody knows still fails.
    #[test]
    fn a_device_address_still_sends_directly() {
        let reg = tx();
        let mut rx = { wlock_for_test(&reg).register(veil_cfg::NodeId::from(DEVICE_A)) };
        let b = SessionTxBroadcaster::new(Arc::clone(&reg));
        assert!(
            b.send_to_peer_or_identity(&DEVICE_A, 1, vec![7u8]),
            "a device we hold a session with must still be reachable by its own id",
        );
        assert!(rx.try_recv().is_ok(), "the frame must reach that device");
        assert!(
            !b.send_to_peer_or_identity(&IDENTITY, 1, vec![7u8]),
            "an identity with no devices must not appear deliverable",
        );
    }

    fn wlock_for_test(
        reg: &Arc<RwLock<SessionTxRegistry>>,
    ) -> std::sync::RwLockWriteGuard<'_, SessionTxRegistry> {
        reg.write().unwrap_or_else(|p| p.into_inner())
    }

    /// The defect this exists for: the app addresses an IDENTITY, the session
    /// is registered under a DEVICE, and the frame must still arrive.
    #[test]
    fn an_identity_address_reaches_its_device() {
        let reg = tx();
        let mut rx = { wlock_for_test(&reg).register(veil_cfg::NodeId::from(DEVICE_A)) };
        let sessions = Arc::new(Mutex::new(crate::SessionRegistry::new()));
        lock_sessions(&sessions).insert(sovereign_entry(DEVICE_A, IDENTITY, [0x01u8; 16], 1));

        let b = SessionTxBroadcaster::new(Arc::clone(&reg)).with_sessions(Arc::clone(&sessions));
        assert_eq!(b.devices_of(&IDENTITY), vec![DEVICE_A]);
        assert!(
            b.send_to_peer_or_identity(&IDENTITY, 1, vec![9u8]),
            "an identity with a live device must be deliverable",
        );
        assert!(rx.try_recv().is_ok(), "the frame must reach the device");
    }

    /// EVERY device, not the first one that takes it. Two devices of one
    /// person are two app instances, and both are meant to receive.
    #[test]
    fn an_identity_address_reaches_every_device() {
        let reg = tx();
        let (mut rx_a, mut rx_b) = {
            let mut g = wlock_for_test(&reg);
            (
                g.register(veil_cfg::NodeId::from(DEVICE_A)),
                g.register(veil_cfg::NodeId::from(DEVICE_B)),
            )
        };
        let sessions = Arc::new(Mutex::new(crate::SessionRegistry::new()));
        lock_sessions(&sessions).insert(sovereign_entry(DEVICE_A, IDENTITY, [0x01u8; 16], 1));
        lock_sessions(&sessions).insert(sovereign_entry(DEVICE_B, IDENTITY, [0x02u8; 16], 2));

        let b = SessionTxBroadcaster::new(Arc::clone(&reg)).with_sessions(sessions);
        assert_eq!(b.devices_of(&IDENTITY).len(), 2);
        assert!(b.send_to_peer_or_identity(&IDENTITY, 1, vec![5u8]));
        assert!(rx_a.try_recv().is_ok(), "first device must receive");
        assert!(rx_b.try_recv().is_ok(), "second device must receive too");
    }

    fn lock_sessions(
        s: &Arc<Mutex<crate::SessionRegistry>>,
    ) -> std::sync::MutexGuard<'_, crate::SessionRegistry> {
        s.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// One live session: the wire proved `device`, and the sovereign proof
    /// said that device belongs to `identity`.
    fn sovereign_entry(
        device: [u8; 32],
        identity: [u8; 32],
        instance: [u8; 16],
        session: u8,
    ) -> crate::SessionEntry {
        crate::SessionEntry {
            session_id: [session; 32],
            remote_node_id: device,
            remote_identity: veil_proto::session::IdentityPayload {
                algo: 1,
                public_key: device.to_vec(),
                nonce: b"nonce".to_vec(),
                node_id: device,
                mlkem_pubkey: None,
            },
            remote_capabilities: veil_proto::session::CapabilitiesPayload {
                roles_supported: veil_proto::session::role_bits::CORE,
                flags: veil_proto::session::cap_flags::CAN_RELAY,
                discovery_mode: 0,
            },
            remote_attach: veil_proto::session::AttachPayload {
                role: 3,
                realm_id: 0,
                attach_epoch: 1,
                mailbox_preference_count: 0,
                gateway_preference_count: 0,
                flags: 0,
            },
            remote_role: crate::RemoteRole::Core,
            validated_sovereign_identity: Some(veil_identity::verify::ValidatedIdentity {
                node_id: identity,
                master_algo: 0,
                master_pubkey: vec![0xEE; 32],
                active_identity_pubkey: vec![0xFF; 32],
                active_identity_algo: 0,
                active_key_idx: 0,
                active_device_id: device,
                active_instance_id: instance,
            }),
        }
    }
}
