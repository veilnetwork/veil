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
    /// Notify shared with the gateway-failover loop — kicked after a
    /// successful join so the failover task picks up the new peer
    /// immediately rather than waiting for its periodic poll.
    gateway_failover_notify: Arc<tokio::sync::Notify>,
}

impl BootstrapJoinForwarder {
    pub fn new(
        logger: Arc<NodeLogger>,
        state: Arc<Mutex<NodeState>>,
        dht: Arc<veil_dht::KademliaService>,
        gateway_failover_notify: Arc<tokio::sync::Notify>,
    ) -> Self {
        Self {
            logger,
            state,
            next_peer_id_offset: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            dht,
            gateway_failover_notify,
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
            self.logger.info(
                "ipc.bootstrap_join.already_known",
                format!(
                    "node_id={} transport={}",
                    veil_util::hex_short(&node_id_bytes),
                    veil_util::redact_addr_for_log(&peer.transport),
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

        // Note: the actual outbound-connector task is NOT spawned here.
        // Spawning requires `&NodeServices` + `&watch::Sender`, neither
        // of which the sink holds (would create circular deps).
        // Instead we kick `gateway_failover_notify` — the failover loop
        // already polls state.peers periodically and spawns connector
        // tasks for entries it hasn't seen, so the new peer gets dialed
        // within ~5 s rather than ~60 s without the kick. Tradeoff:
        // saves a complex sink → runtime upcall; cost is up to 5 s
        // latency before first dial attempt.
        self.gateway_failover_notify.notify_waiters();

        self.logger.info(
            "ipc.bootstrap_join.registered",
            format!(
                "node_id={} transport={} peer_id={}",
                veil_util::hex_short(&node_id_bytes),
                veil_util::redact_addr_for_log(&peer.transport),
                peer_id,
            ),
        );

        BootstrapJoinOutcome::Ok {
            peer_node_id: node_id_bytes,
            detail: format!("registered; outbound dial in flight (peer_id={})", peer_id),
        }
    }
}
