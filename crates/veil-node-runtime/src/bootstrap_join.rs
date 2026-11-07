//! IPC → runtime adapter for `JoinBootstrapUri`.
//!
//! Implements [`veil_ipc::BootstrapJoinSink`] over the runtime's
//! peer-state map + outbound-connector spawn. Constructed in
//! `spawn_ipc_server`.
//!
//! The decode pipeline mirrors the CLI dispatch in
//! [`crate::cmd::bootstrap_cmd`] — same scheme-prefix routing, same
//! error mapping — so a Flutter app pasting an `veil:` URL into the
//! deep-link handler hits the same trust semantics as an operator
//! running `veil-cli bootstrap join`.

use std::sync::{Arc, Mutex};

use veil_ipc::{BootstrapJoinOutcome, BootstrapJoinSink};

use crate::state::NodeState;
use crate::types::{PeerConfigEntry, PeerSource};
use veil_bootstrap::{
    BOOTSTRAP_URI_SCHEME, ENCRYPTED_INVITE_SCHEME, EncryptedInviteError, SIGNED_INVITE_SCHEME,
    decode_bootstrap_uri, decode_signed_invite, decrypt_invite, verify_signed_invite,
};
use veil_cfg::{BootstrapPeer, NodeId};
use veil_observability::NodeLogger;

/// Runtime-owned drain shared by IPC bootstrap joins and endpoint refreshes.
pub(crate) fn spawn_dial_drain(
    access: crate::runtime::NodeServices,
    shutdown: tokio::sync::watch::Sender<bool>,
    mut entries: tokio::sync::mpsc::Receiver<PeerConfigEntry>,
) -> tokio::task::JoinHandle<()> {
    let mut shutdown_rx = shutdown.subscribe();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                entry = entries.recv() => match entry {
                    Some(entry) => {
                        // The per-peer refresh watch already wakes that peer's
                        // idle retry and invalidates a changed dial target.
                        // A global network-change wake would also cancel
                        // unrelated, still-valid in-flight handshakes.
                        access.spawn_owned_outbound_peers(vec![entry], &shutdown);
                    }
                    None => break,
                }
            }
        }
    })
}

/// Synthetic peer-id range for apps-added bootstrap peers. Distinct from
/// configured peers (small u32), DNS bootstrap, and HTTPS seeds. Each new
/// app-added peer claims the next slot via an atomic counter. Single source of
/// truth lives in [`crate::types::synthetic_peer_id`] (cycle-7 M3).
pub const APP_ADDED_PEER_ID_BASE: u32 = crate::types::synthetic_peer_id::APP_ADDED_BASE;

/// Bridges `JoinBootstrapUri` IPC requests to runtime peer-state +
/// outbound-connector machinery.
pub struct BootstrapJoinForwarder {
    logger: Arc<NodeLogger>,
    state: Arc<Mutex<NodeState>>,
    /// Counter for synthetic peer_ids assigned to app-added peers.
    /// Atomic so concurrent IPC requests don't collide.
    next_peer_id_offset: Arc<std::sync::atomic::AtomicU32>,
    /// Same DHT routing table the bootstrap-task adds contacts to —
    /// app-added peers get the same treatment so iterative lookups
    /// can route through them.
    dht: Arc<veil_dht::KademliaService>,
    /// Runtime-owned dial queue. The forwarder cannot spawn an
    /// outbound-connector itself (that needs `&NodeServices` + the shutdown
    /// `watch::Sender`, neither of which an IPC sink holds), so a registered
    /// app-added peer is handed to a drain task in `spawn_ipc_server` that owns
    /// those handles and calls `spawn_outbound_peers`. (audit cycle-10: replaces
    /// the previous `gateway_failover_notify` kick, which woke a loop that only
    /// ever dials `live_gateways()` and filters `state.peers` to
    /// `peer_id >= 0xC000_0000` — so an app-added peer at `0x8800_0000` was
    /// never actually dialed despite the "dial in flight" success reply.)
    /// Bounded (diff-audit Rep-B-2): an app looping `BootstrapJoin` would
    /// otherwise enqueue dials without limit. On a full queue `try_send` drops
    /// the dial (registration still succeeds; reported as "dial deferred").
    dial_tx: tokio::sync::mpsc::Sender<PeerConfigEntry>,
}

impl BootstrapJoinForwarder {
    pub fn new(
        logger: Arc<NodeLogger>,
        state: Arc<Mutex<NodeState>>,
        dht: Arc<veil_dht::KademliaService>,
        dial_tx: tokio::sync::mpsc::Sender<PeerConfigEntry>,
    ) -> Self {
        Self {
            logger,
            state,
            next_peer_id_offset: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            dht,
            dial_tx,
        }
    }

    /// Decode the URI through the appropriate bootstrap-invite path.
    /// Mirrors `crate::cmd::bootstrap_cmd::decode_any_uri` but returns
    /// `BootstrapJoinOutcome` directly so the IPC handler can map to
    /// wire status codes without a translation layer.
    fn decode_any(
        &self,
        uri: &str,
        password: Option<&str>,
        expected_issuer_pk: Option<&str>,
    ) -> Result<BootstrapPeer, BootstrapJoinOutcome> {
        if uri.starts_with(SIGNED_INVITE_SCHEME) {
            if password.is_some() {
                return Err(BootstrapJoinOutcome::InvalidUri(
                    "password supplied but URI is signed-invite — pass only one".into(),
                ));
            }
            // Signed-invite without expected_issuer_pk would be accepted
            // based on the envelope's claimed issuer — meaningless.
            // Refuse loudly so the app surfaces an actionable error
            // instead of silently trusting an attacker-signed URI.
            if expected_issuer_pk.is_none() {
                return Err(BootstrapJoinOutcome::SignatureInvalid(
                    "URI is signed-invite; expected_issuer_pk is required \
                     (verify against pubkey learned out-of-band)"
                        .into(),
                ));
            }
            let envelope = decode_signed_invite(uri).map_err(|e| {
                BootstrapJoinOutcome::InvalidUri(format!("decode signed invite: {e}"))
            })?;
            // Audit cycle-5 (#4): fail CLOSED on a clock before UNIX_EPOCH
            // (matches the veil-bootstrap https.rs "M-20" behaviour). The
            // previous `now_unix_secs()` collapsed to 0 via `unwrap_or(0)`,
            // making the `now > expiry` freshness check in verify_signed_invite
            // trivially false — so an expired (but validly-signed, pinned-issuer)
            // invite was accepted. Refuse to evaluate freshness on an unusable
            // clock instead.
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .map_err(|_| {
                    BootstrapJoinOutcome::SignatureInvalid(
                        "system clock is before UNIX_EPOCH — refusing to verify invite freshness"
                            .into(),
                    )
                })?;
            verify_signed_invite(&envelope, expected_issuer_pk, now_unix).map_err(|e| {
                BootstrapJoinOutcome::SignatureInvalid(format!("verify signed invite: {e}"))
            })
        } else if uri.starts_with(ENCRYPTED_INVITE_SCHEME) {
            if expected_issuer_pk.is_some() {
                return Err(BootstrapJoinOutcome::InvalidUri(
                    "expected_issuer_pk supplied but URI is encrypted — pass only one".into(),
                ));
            }
            let pw = password.ok_or(BootstrapJoinOutcome::PasswordRequired)?;
            decrypt_invite(uri, pw).map_err(|e| match e {
                EncryptedInviteError::Aead => BootstrapJoinOutcome::PasswordWrong,
                _ => BootstrapJoinOutcome::InvalidUri(format!("decrypt invite: {e}")),
            })
        } else if uri.starts_with(BOOTSTRAP_URI_SCHEME) {
            if password.is_some() {
                return Err(BootstrapJoinOutcome::InvalidUri(
                    "password supplied but URI is plain bootstrap — drop the password".into(),
                ));
            }
            if expected_issuer_pk.is_some() {
                return Err(BootstrapJoinOutcome::InvalidUri(
                    "expected_issuer_pk supplied but URI is plain bootstrap — drop the issuer key"
                        .into(),
                ));
            }
            decode_bootstrap_uri(uri)
                .map_err(|e| BootstrapJoinOutcome::InvalidUri(format!("decode uri: {e}")))
        } else {
            Err(BootstrapJoinOutcome::InvalidUri(format!(
                "unrecognised scheme — must start with `{BOOTSTRAP_URI_SCHEME}`, \
                 `{ENCRYPTED_INVITE_SCHEME}`, or `{SIGNED_INVITE_SCHEME}`"
            )))
        }
    }
}

impl BootstrapJoinSink for BootstrapJoinForwarder {
    fn join_uri(
        &self,
        uri: &str,
        password: Option<&str>,
        expected_issuer_pk: Option<&str>,
    ) -> BootstrapJoinOutcome {
        let peer = match self.decode_any(uri, password, expected_issuer_pk) {
            Ok(p) => p,
            Err(outcome) => return outcome,
        };

        // Derive node_id from pubkey + algo. This re-runs the same
        // BLAKE3-of-pubkey computation `NodeId::from_public_key` does.
        let node_id = match NodeId::from_public_key(peer.algo, &peer.public_key) {
            Ok(n) => n,
            Err(e) => {
                return BootstrapJoinOutcome::InvalidUri(format!(
                    "derive node_id from peer pubkey: {e}"
                ));
            }
        };
        let node_id_bytes = *node_id.as_bytes();

        // Idempotent: if a peer with this node_id is already in state
        // return ALREADY_REGISTERED instead of double-registering.
        // Holding the state lock for the entire op avoids a TOCTOU
        // race with a concurrent join request for the same peer.
        let mut st = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let already_known = st.peers.values().any(|entry| entry.node_id == node_id);
        if already_known {
            // P2P direct-session epic: a repeated join for a known peer is a
            // REFRESH, not a no-op. The caller (endpoint exchange, network
            // change) may carry a NEW dial address, and the previous session
            // may be long gone — so refresh runtime-discovered addresses and
            // re-enqueue a dial. Configured/pinned addresses remain owned by
            // the operator. Idempotence is preserved downstream: the
            // connector's per-node-id slot refresh wakes the existing loop
            // instead of spawning another, and its `has_session` pre-check
            // skips dialing a peer whose session is up.
            let refreshed = st
                .peers
                .values_mut()
                .find(|entry| entry.node_id == node_id)
                .map(|entry| {
                    let may_refresh = entry.peer_id.get() >= APP_ADDED_PEER_ID_BASE
                        && !matches!(
                            entry.source,
                            PeerSource::Configured | PeerSource::PinnedRelay
                        );
                    if may_refresh {
                        entry.transport = peer.transport.clone();
                        entry.tls_cert = peer.tls_cert.clone();
                        entry.tls_ca_cert = peer.tls_ca_cert.clone();
                    }
                    // A configured peer still needs the same bounded redial
                    // wake, using its operator-owned entry. Ignoring invite
                    // overrides must not turn an explicit retry into a no-op.
                    (entry.clone(), may_refresh)
                });
            drop(st);
            let mut redialed = false;
            let mut dial_transport = peer.transport.clone();
            if let Some((entry, may_refresh)) = refreshed {
                // Keep the DHT contact's address current too (add_contact
                // updates in place for a known node_id). Only a refreshed
                // runtime-discovered address may replace this routing metadata.
                if may_refresh {
                    self.dht.add_contact(veil_dht::routing::Contact::new(
                        node_id_bytes,
                        &entry.transport,
                    ));
                }
                dial_transport = entry.transport.clone();
                redialed = self.dial_tx.try_send(entry).is_ok();
            }
            self.logger.info(
                "ipc.bootstrap_join.already_known",
                format!(
                    "node_id={} transport={} redialed={}",
                    veil_util::hex_short(&node_id_bytes),
                    veil_util::redact_addr_for_log(&dial_transport),
                    redialed,
                ),
            );
            return BootstrapJoinOutcome::AlreadyRegistered {
                peer_node_id: node_id_bytes,
            };
        }

        // Allocate a synthetic peer_id from the app-added range.
        let offset = self
            .next_peer_id_offset
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let peer_id = veil_cfg::PeerId::new(APP_ADDED_PEER_ID_BASE.wrapping_add(offset));

        let entry = PeerConfigEntry {
            peer_id,
            node_id,
            public_key: peer.public_key.clone(),
            nonce: peer.nonce.clone(),
            transport: peer.transport.clone(),
            algo: peer.algo,
            tls_cert: peer.tls_cert.clone(),
            tls_key: None,
            tls_ca_cert: peer.tls_ca_cert.clone(),
            // Bootstrap-only — after first FIND_NODE the session may
            // be closed; if the peer is genuinely useful (responds to
            // queries, gets selected by routing layer) it stays via
            // discovered-peer cache. Apps that want a
            // sticky pinned peer should use a different IPC path
            // (currently not exposed; future follow-up).
            bootstrap_only: true,
            source: PeerSource::Bootstrap,
        };

        // Insert into state.peers. Once inserted, `connect_peer_active`
        // can resolve peer_id → entry; without this insert the
        // outbound-connector task spawned below would fail to find the
        // peer config and exit immediately.
        st.peers.insert(peer_id, entry.clone());
        drop(st);

        // Add to DHT routing table — same as bootstrap-task does for
        // configured peers. Lets iterative FIND_NODE walks through
        // this peer work.
        self.dht.add_contact(veil_dht::routing::Contact::new(
            node_id_bytes,
            &peer.transport,
        ));

        // Hand the peer to the runtime-owned dial drain (spawn_ipc_server),
        // which holds the `&NodeServices` + shutdown `watch::Sender` an IPC sink
        // cannot, and spawns the actual reconnect loop via `spawn_outbound_peers`.
        // A closed OR full channel (Rep-B-2: the queue is bounded) means the dial
        // can't be enqueued now — registration in state still succeeded, so
        // report success but say the dial was deferred rather than in flight.
        let dial_started = self.dial_tx.try_send(entry).is_ok();

        self.logger.info(
            "ipc.bootstrap_join.registered",
            format!(
                "node_id={} transport={} peer_id={} dial_started={}",
                veil_util::hex_short(&node_id_bytes),
                veil_util::redact_addr_for_log(&peer.transport),
                peer_id,
                dial_started,
            ),
        );

        BootstrapJoinOutcome::Ok {
            peer_node_id: node_id_bytes,
            detail: if dial_started {
                format!("registered; outbound dial in flight (peer_id={peer_id})")
            } else {
                format!("registered; dial deferred — daemon stopping (peer_id={peer_id})")
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::NodeState;

    fn empty_state() -> Arc<Mutex<NodeState>> {
        let kp = veil_crypto::generate_keypair(veil_cfg::SignatureAlgorithm::Ed25519);
        let node_id =
            NodeId::from_public_key(veil_cfg::SignatureAlgorithm::Ed25519, &kp.public_key).unwrap();
        Arc::new(Mutex::new(NodeState::new(
            node_id,
            crate::types::NodeRole::default(),
            std::path::PathBuf::from("/tmp/test-config.toml"),
            true,
            std::time::Instant::now(),
            false,
            None,
            std::iter::empty(),
            std::iter::empty(),
        )))
    }

    /// cycle-10 regression: a registered app-added bootstrap peer must be
    /// ENQUEUED for an actual outbound dial (the runtime drain in
    /// spawn_ipc_server spawns the connector), not silently dropped. Pre-fix
    /// the forwarder only kicked gateway_failover_notify, a loop that never
    /// dials state.peers entries, so the peer was registered but never dialed
    /// despite the "dial in flight" reply.
    #[test]
    fn join_uri_registers_peer_and_enqueues_dial() {
        let kp = veil_crypto::generate_keypair(veil_cfg::SignatureAlgorithm::Ed25519);
        let peer = BootstrapPeer {
            transport: "tcp://10.9.8.7:9000".to_owned(),
            public_key: kp.public_key.clone(),
            nonce: "AAAAAAAA".to_owned(),
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        };
        let uri = veil_bootstrap::encode_bootstrap_uri(&peer).expect("encode bootstrap uri");

        let state = empty_state();
        let dht = Arc::new(veil_dht::KademliaService::new([7u8; 32]));
        let (dial_tx, mut dial_rx) = tokio::sync::mpsc::channel(8);
        let forwarder = BootstrapJoinForwarder::new(
            Arc::new(NodeLogger::new_noop()),
            Arc::clone(&state),
            dht,
            dial_tx,
        );

        let outcome = forwarder.join_uri(&uri, None, None);
        assert!(
            matches!(outcome, BootstrapJoinOutcome::Ok { .. }),
            "join must succeed, got {outcome:?}",
        );

        // The peer is enqueued for a REAL dial (the core regression).
        let dialed = dial_rx
            .try_recv()
            .expect("app-added peer must be enqueued for dial");
        assert_eq!(dialed.transport, "tcp://10.9.8.7:9000");
        assert!(
            dialed.peer_id.get() >= APP_ADDED_PEER_ID_BASE,
            "dialed entry must use the app-added synthetic peer_id range",
        );

        // ...and registered in state.
        let st = state.lock().unwrap();
        assert!(
            st.peers
                .values()
                .any(|e| e.transport == "tcp://10.9.8.7:9000"),
            "peer must be registered in state.peers",
        );
    }

    /// P2P direct-session epic: joining the SAME peer again with a NEW
    /// transport (endpoint exchange after a network change) must refresh the
    /// stored dial address and enqueue a fresh dial — not silently no-op.
    #[test]
    fn repeat_join_refreshes_transport_and_redials() {
        let kp = veil_crypto::generate_keypair(veil_cfg::SignatureAlgorithm::Ed25519);
        let mk = |transport: &str| BootstrapPeer {
            transport: transport.to_owned(),
            public_key: kp.public_key.clone(),
            nonce: "AAAAAAAA".to_owned(),
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        };
        let uri_a = veil_bootstrap::encode_bootstrap_uri(&mk("tcp://192.168.1.70:9000")).unwrap();
        let uri_b = veil_bootstrap::encode_bootstrap_uri(&mk("tcp://192.168.0.11:9000")).unwrap();

        let state = empty_state();
        let dht = Arc::new(veil_dht::KademliaService::new([7u8; 32]));
        let (dial_tx, mut dial_rx) = tokio::sync::mpsc::channel(8);
        let forwarder = BootstrapJoinForwarder::new(
            Arc::new(NodeLogger::new_noop()),
            Arc::clone(&state),
            dht,
            dial_tx,
        );

        assert!(matches!(
            forwarder.join_uri(&uri_a, None, None),
            BootstrapJoinOutcome::Ok { .. }
        ));
        let first = dial_rx.try_recv().expect("first join enqueues a dial");
        assert_eq!(first.transport, "tcp://192.168.1.70:9000");

        let outcome = forwarder.join_uri(&uri_b, None, None);
        assert!(
            matches!(outcome, BootstrapJoinOutcome::AlreadyRegistered { .. }),
            "second join stays AlreadyRegistered, got {outcome:?}",
        );
        // The stored entry now carries the new address...
        let st = state.lock().unwrap();
        assert!(
            st.peers
                .values()
                .any(|e| e.transport == "tcp://192.168.0.11:9000"),
            "entry transport must be refreshed",
        );
        drop(st);
        // ...and a re-dial was enqueued for it.
        let redial = dial_rx
            .try_recv()
            .expect("repeat join must re-enqueue a dial");
        assert_eq!(redial.transport, "tcp://192.168.0.11:9000");
    }

    fn configured_join_fixture(
        source: PeerSource,
        peer_id: veil_cfg::PeerId,
    ) -> (
        BootstrapJoinForwarder,
        Arc<Mutex<NodeState>>,
        tokio::sync::mpsc::Receiver<PeerConfigEntry>,
        BootstrapPeer,
        PeerConfigEntry,
    ) {
        let kp = veil_crypto::generate_keypair(veil_cfg::SignatureAlgorithm::Ed25519);
        let peer = BootstrapPeer {
            transport: "tcp://192.0.2.25:9010".to_owned(),
            public_key: kp.public_key.clone(),
            nonce: "AAAAAAAA".to_owned(),
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        };
        let entry = PeerConfigEntry {
            peer_id,
            node_id: NodeId::from_public_key(peer.algo, &peer.public_key).unwrap(),
            public_key: peer.public_key.clone(),
            nonce: peer.nonce.clone(),
            transport: peer.transport.clone(),
            algo: peer.algo,
            tls_cert: Some("operator certificate".to_owned()),
            tls_key: Some("operator private key".to_owned()),
            tls_ca_cert: Some("operator CA".to_owned()),
            bootstrap_only: false,
            source,
        };
        let state = empty_state();
        state
            .lock()
            .unwrap()
            .peers
            .insert(entry.peer_id, entry.clone());
        let dht = Arc::new(veil_dht::KademliaService::new([7u8; 32]));
        let (dial_tx, dial_rx) = tokio::sync::mpsc::channel(1);
        let forwarder = BootstrapJoinForwarder::new(
            Arc::new(NodeLogger::new_noop()),
            Arc::clone(&state),
            dht,
            dial_tx,
        );
        (forwarder, state, dial_rx, peer, entry)
    }

    #[test]
    fn repeat_join_redials_configured_peer_without_replacing_operator_state() {
        let (forwarder, state, mut dial_rx, peer, entry) =
            configured_join_fixture(PeerSource::Configured, veil_cfg::PeerId::new(7));
        let uri = veil_bootstrap::encode_bootstrap_uri(&peer).unwrap();
        assert!(matches!(
            forwarder.join_uri(&uri, None, None),
            BootstrapJoinOutcome::AlreadyRegistered { .. }
        ));
        assert_eq!(
            dial_rx
                .try_recv()
                .expect("known configured peer must be re-enqueued"),
            entry
        );
        let state = state.lock().unwrap();
        assert_eq!(state.peers.len(), 1);
        assert_eq!(state.peers[&entry.peer_id], entry);
    }

    #[test]
    fn repeat_join_configured_peer_ignores_invite_address_nonce_and_certificates() {
        let (forwarder, state, mut dial_rx, mut peer, entry) =
            configured_join_fixture(PeerSource::Configured, veil_cfg::PeerId::new(7));
        peer.transport = "tcp://198.51.100.11:9999".to_owned();
        peer.nonce = "BBBBBBBB".to_owned();
        let uri = veil_bootstrap::encode_bootstrap_uri(&peer).unwrap();
        assert!(matches!(
            forwarder.join_uri(&uri, None, None),
            BootstrapJoinOutcome::AlreadyRegistered { .. }
        ));
        assert_eq!(
            dial_rx
                .try_recv()
                .expect("redial must retain the configured target"),
            entry
        );
        assert_eq!(state.lock().unwrap().peers[&entry.peer_id], entry);
    }

    #[test]
    fn repeat_join_pinned_peer_can_retry_after_dial_queue_backpressure() {
        let (forwarder, state, mut dial_rx, peer, entry) = configured_join_fixture(
            PeerSource::PinnedRelay,
            veil_cfg::PeerId::new(crate::types::synthetic_peer_id::PINNED_RELAY_BASE + 7),
        );
        let uri = veil_bootstrap::encode_bootstrap_uri(&peer).unwrap();
        for _ in 0..2 {
            assert!(matches!(
                forwarder.join_uri(&uri, None, None),
                BootstrapJoinOutcome::AlreadyRegistered { .. }
            ));
        }
        assert_eq!(
            dial_rx
                .try_recv()
                .expect("first retry fills the bounded queue"),
            entry
        );
        assert!(
            dial_rx.try_recv().is_err(),
            "backpressure must not duplicate entries"
        );
        assert!(matches!(
            forwarder.join_uri(&uri, None, None),
            BootstrapJoinOutcome::AlreadyRegistered { .. }
        ));
        assert_eq!(
            dial_rx
                .try_recv()
                .expect("retry after capacity returns must wake dial"),
            entry
        );
        assert_eq!(state.lock().unwrap().peers[&entry.peer_id], entry);
    }

    #[test]
    fn invalid_repeat_invite_does_not_wake_configured_peer() {
        let (forwarder, state, mut dial_rx, _, entry) =
            configured_join_fixture(PeerSource::Configured, veil_cfg::PeerId::new(7));
        assert!(!matches!(
            forwarder.join_uri("veil:bootstrap?bad=1", None, None),
            BootstrapJoinOutcome::AlreadyRegistered { .. } | BootstrapJoinOutcome::Ok { .. }
        ));
        assert!(dial_rx.try_recv().is_err());
        assert_eq!(state.lock().unwrap().peers[&entry.peer_id], entry);
    }

    #[test]
    fn repeat_join_configured_source_protects_even_an_app_range_id() {
        let (forwarder, state, mut dial_rx, mut peer, entry) = configured_join_fixture(
            PeerSource::Configured,
            veil_cfg::PeerId::new(APP_ADDED_PEER_ID_BASE + 7),
        );
        peer.transport = "tcp://198.51.100.11:9999".to_owned();
        let uri = veil_bootstrap::encode_bootstrap_uri(&peer).unwrap();
        assert!(matches!(
            forwarder.join_uri(&uri, None, None),
            BootstrapJoinOutcome::AlreadyRegistered { .. }
        ));
        assert_eq!(dial_rx.try_recv().unwrap(), entry);
        assert_eq!(state.lock().unwrap().peers[&entry.peer_id], entry);
    }

    #[test]
    fn repeat_join_discovered_rendezvous_peer_keeps_endpoint_refresh() {
        let (forwarder, state, mut dial_rx, mut peer, entry) = configured_join_fixture(
            PeerSource::Rendezvous,
            veil_cfg::PeerId::new(crate::types::synthetic_peer_id::RENDEZVOUS_BASE + 7),
        );
        peer.transport = "tcp://198.51.100.11:9999".to_owned();
        let uri = veil_bootstrap::encode_bootstrap_uri(&peer).unwrap();
        assert!(matches!(
            forwarder.join_uri(&uri, None, None),
            BootstrapJoinOutcome::AlreadyRegistered { .. }
        ));
        let expected = PeerConfigEntry {
            transport: peer.transport,
            tls_cert: peer.tls_cert,
            tls_ca_cert: peer.tls_ca_cert,
            ..entry
        };
        assert_eq!(dial_rx.try_recv().unwrap(), expected);
        assert_eq!(state.lock().unwrap().peers[&expected.peer_id], expected);
    }
}
