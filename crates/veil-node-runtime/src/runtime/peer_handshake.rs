//! Peer-handshake plumbing: drive a raw transport stream through `OVL1`
//! handshake, install per-peer state into the session registry / caches,
//! and attach the surviving session to the runtime as an
//! [`AttachedDebugSession`][].
//!
//! Three entry points:
//!
//! - [`register_connection_session`][] — main async pipeline that
//!   handshakes a freshly-accepted (or freshly-dialed) transport stream,
//!   verifies expected-peer invariants when applicable, and yields an
//!   `AttachedDebugSession`.  Drives RAII slot tracking via `IpSlotGuard`
//!   and delegates teardown to `SessionGuard`.
//! - [`prepare_peer_handshake_state`][] / [`PendingPeerState::commit`][]
//!   — the derive-then-publish pair for one completed
//!   `OvlHandshakeResult`. `prepare` mutates nothing; `commit` writes the
//!   per-peer caches and is called only past the admission gates.
//! - [`peer_transport_context`][] — TLS-context fork-and-augment helper
//!   used at outbound dial time.
//!
//! Plus three small private helpers ([`verify_remote_peer_identity`],
//! [`match_configured_peer`], the [`PeerVerificationError`] enum) that
//! split out classification work from `register_connection_session`.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use veil_util::{lock, rlock, wlock};

use tokio::io::AsyncWriteExt;

use crate::error::{NodeError, Result};
use crate::state::NodeState;
use crate::types::{
    LinkId, ListenerHandle, PeerConfigEntry, PeerId, PeerSource, SessionInfo, SessionSource,
    SessionState,
};
use veil_cfg;
use veil_routing::VivaldiCoord;
use veil_session::handshake::{OvlHandshakeResult, SovereignHandshakeCtx, perform_ovl1_handshake};
use veil_transport::{TransportConnection, TransportContext};

use veil_cfg::{DiscoveryMode, NodeId};
use veil_crypto::session_kdf::SessionKeys;

use super::ip_slot::{IpSlotGuard, check_and_reserve_ip_slot};
use super::uri_helpers::{uri_has_port_zero, uri_scheme};
use super::{AttachedDebugSession, SessionGuard, SessionRuntimeContext, lock_state, persistence};

/// Common remote peer identity gathered during the OVL1 handshake.
pub struct RemoteHandshakeInfo {
    pub node_id: NodeId,
    /// Base64-encoded public key (same encoding as `PeerConfigEntry.public_key`).
    pub public_key: String,
    pub nonce: String,
    /// Session keying material derived from the X25519/ML-KEM shared secret.
    pub session_keys: SessionKeys,
    /// Peer's last-known DHT discoverability preference extracted from
    /// `CapabilitiesPayload.discovery_mode`.
    pub remote_discovery_mode: DiscoveryMode,
    /// False when the peer advertised `NO_DHT_SERVICE`: keep the session,
    /// keep it resolvable, but never pick it as a DHT candidate.
    ///
    /// Meaningless unless [`Self::remote_caps_stated`] is true — a resumed
    /// handshake synthesizes "serves" without asking the peer.
    pub remote_dht_service: bool,
    /// Whether [`Self::remote_discovery_mode`] and [`Self::remote_dht_service`]
    /// were STATED by the peer in this handshake. False on the fast-resume
    /// path, which invents a zero capabilities payload. Callers that write
    /// these into shared state must leave the stored values alone when this is
    /// false — see `veil_dht::routing::Contact::caps_known`.
    pub remote_caps_stated: bool,
    /// Peer explicitly advertised the authenticated realtime DATAGRAM lane.
    /// False on legacy and fast-resumed handshakes.
    pub supports_realtime_datagrams: bool,
    /// Whether the peer rotates the realtime lane's key at a session rekey.
    /// Both sides must, or the one that does leaves the other unable to open
    /// anything past the first rekey (report12 V-M12).
    pub supports_realtime_rekey: bool,
    /// Bounded UDP reflector port advertised by this authenticated peer.
    /// The runtime combines it with transport metadata only after all session
    /// admission gates pass.
    pub udp_reflector_port: Option<u16>,
    /// Public endpoints this peer relayed from other authenticated peers.
    pub shared_udp_reflectors: Vec<std::net::SocketAddr>,
}

/// Per-peer identity invariants asserted by outbound dialers — the peer
/// the operator configured to connect to (peer_id, public_key, node_id,
/// nonce).  Compared against the actual handshake result by
/// [`verify_remote_peer_identity`][].
#[derive(Clone)]
pub struct ExpectedPeerIdentity {
    pub peer_id: PeerId,
    pub public_key: String,
    pub node_id: NodeId,
    pub nonce: String,
    /// The row's address as it stood when this dial started.
    ///
    /// A `PeerId` is a local slot, and a slot outlives the row in it: an
    /// endpoint refresh rewrites the address, and an eviction plus a
    /// rediscovery can put a different peer entirely at the same number. A
    /// handshake that started before either then carried a verdict about a row
    /// that no longer exists — and the identity-mismatch path acted on it,
    /// deleting the refreshed row (report16 V16-M6). Carried so the verdict
    /// can be matched to the row it was actually about.
    pub row_transport_at_dial: String,
}

pub enum PeerVerificationError {
    IdentityMismatch(String),
    NonceMismatch,
}

/// Everything one completed OVL1 handshake wants to publish about its
/// peer, held until the session has cleared every admission gate.
///
/// ## Why this is not written straight through
///
/// Completing a handshake proves the peer holds the private key for the
/// `node_id` it claims. It does **not** mean we will keep the session:
/// the expected-peer check, the listener allowlist, the ban list, the
/// concurrency cap, directional dedup and the over-cap re-check all run
/// afterwards, and each can reject. Writing the per-peer caches at
/// handshake completion meant a peer that every one of those gates
/// rejected still got its pubkey, roles, cap-flags, ML-KEM key, battery,
/// Vivaldi coordinate, alt-URI and membership cert into node-wide state
/// — and, because each of those caches is capped, evicted an entry
/// belonging to a peer we *did* accept. An authenticated Sybil could not
/// forge another node's `node_id`, but it could handshake in a loop and
/// churn the caches of the nodes we actually talk to.
///
/// So the derivation is separated from the publish:
/// [`prepare_peer_handshake_state`] reads and computes, mutating
/// nothing; [`PendingPeerState::commit`] writes, and the caller invokes
/// it at exactly one point — past the last gate. A reject path simply
/// drops this value.
pub struct PendingPeerState {
    /// The registry entry, handed back by [`Self::commit`] so the caller
    /// registers it in the same post-admission step.
    entry: veil_session::SessionEntry,
    /// The sovereign binding to publish. `Some` only on the full-handshake
    /// path — the resumption path reads the cache (in `prepare`) but has
    /// nothing new to write.
    sovereign_to_cache: Option<veil_identity::verify::ValidatedIdentity>,
    /// Battery level from the ATTACH TLV.
    battery: Option<u8>,
    /// Raw Vivaldi triple as advertised; validated at commit time.
    vivaldi: Option<(f64, f64, f64)>,
    /// Transport URIs the peer advertised, for hot-standby alt-URI pickup.
    advertised_transports: Vec<String>,
    /// URI this session came in on, the alt-URI picker's reference point.
    primary_uri: String,
    /// Verified P-Net membership cert, for IPC status consumers.
    membership_cert: Option<veil_types::MembershipCert>,
    /// The address the peer says it saw us as (STUN-style discovery).
    observed_addr: Option<std::net::SocketAddr>,
}

/// Which of a peer's device bindings a RESUMED session is allowed to adopt.
///
/// A resumption skips the IdentityProof exchange, so nothing in the exchange
/// itself says which device answered. Every device of one identity connects
/// under that identity's `node_id` — that is precisely the shape the
/// delegation check in the handshake exists to permit — so "the binding for
/// this peer" names a FAMILY. Picking the wrong member is not cosmetic:
/// the session registry indexes the session under that device, and a
/// direct-session seal asks the session which device it is talking to, so a
/// wrong answer keys mail to a sibling and the recipient refuses it.
///
/// `resumed_instance` is the ticket's answer. `Some(non-zero)` addresses one
/// row exactly. Otherwise — the initiator half of a resumption, whose ticket
/// names IT to the responder rather than the responder to it, or a ticket
/// minted before tickets carried the instance — a binding is adopted only when
/// the identity has exactly ONE known device. With two, any pick is a coin
/// flip, and a session that claims no device is strictly better than one that
/// claims the wrong one.
pub(crate) fn binding_for_resumed_session(
    bindings: &std::collections::HashMap<
        ([u8; 32], [u8; 16]),
        veil_identity::verify::ValidatedIdentity,
    >,
    peer_id: [u8; 32],
    resumed_instance: Option<[u8; 16]>,
) -> Option<veil_identity::verify::ValidatedIdentity> {
    if let Some(instance) = resumed_instance
        && instance != [0u8; 16]
    {
        return bindings.get(&(peer_id, instance)).cloned();
    }
    let mut rows = bindings.iter().filter(|((id, _), _)| *id == peer_id);
    match (rows.next(), rows.next()) {
        (Some((_, only)), None) => Some(only.clone()),
        _ => None,
    }
}

/// Derive [`PendingPeerState`] from a completed OVL1 handshake **without
/// mutating any shared state**.
///
/// The one lock taken here is a read of `peer_sovereign_identities`, and
/// only on the resumption path, where the binding this session should
/// carry was recorded by an earlier full handshake.
///
/// Extracted from `register_connection_session`. Its counterpart is
/// [`PendingPeerState::commit`]; all work in both is synchronous — the
/// caller remains responsible for any `await` points.
#[must_use]
pub fn prepare_peer_handshake_state(
    runtime: &SessionRuntimeContext,
    r: &OvlHandshakeResult,
    primary_uri: &str,
) -> PendingPeerState {
    let peer_id = r.remote_identity_payload.node_id;
    // LOCK ORDER: canonical workspace-wide order (see session_guard.rs) is
    // `session_registry` (#3) → `peer_sovereign_identities` (#5).  The
    // SessionEntry needs the `validated` value computed from the sovereign
    // cache, and holding both locks simultaneously in inverted order would
    // create a deadlock cycle against code that takes them in canonical
    // order.
    //
    // The two are never held together: `validated` is resolved here, the
    // sovereign cache is written in `commit`, and `session_registry` is
    // written by the caller — three sequential critical sections. A reader
    // racing between them sees either old-registry + old-sovereign OR
    // new-registry + new-sovereign, never a cross-generation pair, because
    // the `validated` snapshot is captured here and applied throughout.
    let (validated, sovereign_to_cache) = match r.validated_sovereign_identity.clone() {
        // Full handshake completed — this binding is both what the session
        // carries and what the cache should learn for future resumptions.
        Some(v) => (Some(v.clone()), Some(v)),
        None => {
            // Resumption path — look up the binding an earlier full handshake
            // recorded.  Cached sovereign bindings from the resumption fast
            // path are trusted unconditionally; a compromised subkey is
            // mitigated by the document's short `valid_until_unix` window.
            // Read-only: nothing to publish back.
            //
            // WHICH binding is the whole question. Every device of one
            // identity connects under that identity's `node_id`, so "the
            // binding for this peer" names a FAMILY, not a device. The ticket
            // carries the device, and the responder half of a resumption reads
            // it straight off: the pair addresses one row exactly.
            let cached = binding_for_resumed_session(
                &lock!(runtime.identity.peer_sovereign_identities),
                peer_id,
                r.resumed_peer_instance_id,
            );
            (cached, None)
        }
    };

    PendingPeerState {
        entry: veil_session::SessionEntry {
            session_id: r.session_keys.session_id,
            remote_node_id: peer_id,
            remote_identity: r.remote_identity_payload.clone(),
            remote_capabilities: r.remote_capabilities.clone(),
            remote_attach: r.remote_attach.clone(),
            remote_role: r.remote_role,
            validated_sovereign_identity: validated,
        },
        sovereign_to_cache,
        battery: r.remote_battery,
        vivaldi: r.remote_vivaldi,
        advertised_transports: r.remote_advertised_transports.clone(),
        primary_uri: primary_uri.to_string(),
        membership_cert: r.verified_membership_cert.clone(),
        observed_addr: r.remote_observed_addr,
    }
}

impl PendingPeerState {
    /// Publish the per-peer caches (sovereign binding, pubkey, role bits,
    /// cap-flags, ML-KEM EK, battery, Vivaldi, hot-standby alt URI,
    /// membership cert) and hand back the [`veil_session::SessionEntry`]
    /// for the caller to register.
    ///
    /// **Call this only once every admission gate has passed.** Taking
    /// `self` by value is the enforcement: a reject path cannot have
    /// committed, because committing consumes the value it would have had
    /// to drop.
    ///
    /// The `SessionEntry` is returned rather than inserted so the caller
    /// keeps `session_registry` in its own critical section — see the
    /// lock-order note in [`prepare_peer_handshake_state`], and audit
    /// cycle-9 CRIT-6 for why the insert is post-admission at all.
    #[must_use]
    pub fn commit(self, runtime: &SessionRuntimeContext) -> veil_session::SessionEntry {
        let peer_id = self.entry.remote_node_id;
        // Publish the sovereign binding learned by a full handshake, so a
        // later resumption can key the peer by it.
        if let Some(v) = self.sovereign_to_cache {
            use veil_proto::budget::MAX_PEER_SOVEREIGN_IDENTITIES;
            // Keyed by (identity, device). A peer-keyed slot let each device of
            // a multi-device identity overwrite its siblings, and the loser's
            // next resumption then restored the winner's binding.
            let key = (peer_id, v.active_instance_id);
            let mut sovereign_g = lock!(runtime.identity.peer_sovereign_identities);
            // Cap unbounded HashMap growth. Random eviction (HashMap iter
            // is non-deterministic) is acceptable here — cache hit/miss
            // only affects the resumption fast-path; missed entries
            // trigger a full handshake.
            if sovereign_g.len() >= MAX_PEER_SOVEREIGN_IDENTITIES
                && !sovereign_g.contains_key(&key)
                && let Some(k) = sovereign_g.keys().next().copied()
            {
                sovereign_g.remove(&k);
            }
            sovereign_g.insert(key, v);
        }
        // Cache the peer's raw public key for signature verification.  Skip
        // if public_key is empty — this happens during session resumption
        // (fast-path reconnect via ticket) where the synthetic IdentityPayload
        // has no key.  Overwriting with empty would break routing-sig verify.
        if !self.entry.remote_identity.public_key.is_empty() {
            lock!(runtime.identity.peer_pubkeys).insert_lru(
                peer_id,
                (
                    self.entry.remote_identity.algo,
                    self.entry.remote_identity.public_key.clone(),
                ),
                veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
            );
        }
        // Cache peer's role bits.
        lock!(runtime.identity.peer_roles).insert_lru(
            peer_id,
            self.entry.remote_capabilities.roles_supported,
            veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
        );
        // Cache peer capability flags for relay filtering.
        {
            let mut flags_cache = runtime
                .dispatcher
                .crypto
                .peer_cap_flags
                .write()
                .unwrap_or_else(|p| p.into_inner());
            // Only evict when inserting a NEW peer (matches the sibling caches), so
            // an existing peer re-handshaking can't churn out a different live
            // peer's flags.
            if flags_cache.len() >= veil_proto::budget::MAX_PEER_PUBKEYS_CACHE
                && !flags_cache.contains_key(&peer_id)
                && let Some(evict_key) = flags_cache.keys().next().copied()
            {
                flags_cache.remove(&evict_key);
            }
            flags_cache.insert(peer_id, self.entry.remote_capabilities.flags);
        }
        // Cache the peer's ML-KEM-768 encapsulation key.  Enforce
        // `MAX_PEER_MLKEM_CACHE` hard-cap with oldest-entry LRU eviction to
        // prevent unbounded growth under peer-churn flood (TTL-only eviction
        // could let the map reach ~12 MiB with a 1-hour TTL).
        if let Some(ref ek) = self.entry.remote_identity.mlkem_pubkey {
            let mut cache = wlock!(runtime.identity.peer_mlkem_keys);
            if cache.len() >= veil_proto::budget::MAX_PEER_MLKEM_CACHE
                && let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, (_, ts))| *ts)
                    .map(|(id, _)| *id)
            {
                cache.remove(&oldest);
            }
            cache.insert(peer_id, (ek.clone(), std::time::Instant::now()));
        }
        // Update peer battery level from ATTACH TLV.
        if let Some(bat) = self.battery {
            lock!(runtime.rtt_table).update_battery(peer_id, bat);
        }
        // Store the peer's Vivaldi coordinate for RTT-aware routing.  Reject
        // non-finite coordinates — a malicious peer could send NaN/∞ to poison
        // the local Vivaldi estimate and corrupt routing.
        if let Some((vx, vy, vh)) = self.vivaldi {
            if vx.is_finite() && vy.is_finite() && vh.is_finite() && vh >= 0.0 {
                let now = std::time::Instant::now();
                let mut viv = wlock!(runtime.dispatcher.peer_vivaldi);
                // LRU eviction of the oldest-used entry.
                if viv.len() >= veil_proto::budget::MAX_PEER_VIVALDI_CACHE
                    && let Some(evict_key) = viv
                        .iter()
                        .min_by_key(|(_, (_, last_used))| *last_used)
                        .map(|(k, _)| *k)
                {
                    viv.remove(&evict_key);
                }
                viv.insert(
                    peer_id,
                    (
                        VivaldiCoord {
                            x: vx,
                            y: vy,
                            height: vh,
                            error: 1.0,
                        },
                        now,
                    ),
                );
            } else {
                log::warn!(
                    "peer {} sent non-finite Vivaldi coord ({vx}, {vy}, {vh}) — ignored",
                    veil_util::hex_short(&peer_id),
                );
            }
        }
        // Hot-standby: record an auto-discovered alt URI from the peer's
        // advertised-transports AttachPayload TLV.  Only used by `alt_uri_for`
        // when no operator-configured alt_uri exists — explicit config always
        // wins.
        if !self.advertised_transports.is_empty()
            && let Some(picked) = runtime.handoff.controller.auto_set_alt_uri_from_transports(
                peer_id.into(),
                &self.advertised_transports,
                &self.primary_uri,
            )
        {
            runtime.logger.debug(
                "session.hot_standby.alt_uri_auto_discovered",
                format!(
                    "peer={} picked={picked} primary_uri={}",
                    veil_util::hex_short(&peer_id),
                    self.primary_uri,
                ),
            );
        }
        // S2.A part 3: stash the verified MembershipCert (if any) so
        // PnetStatusProvider can surface it to IPC consumers (ogate / oproxy).
        // Hard-cap with arbitrary eviction (matching the sibling peer caches
        // above) so the map can't grow unbounded across the process lifetime —
        // it was previously never reclaimed, a slow leak on long-lived P-Net
        // relays. Best-effort status: evicting a still-live peer only drops it
        // from IPC status until its next handshake re-populates the entry.
        if let Some(cert) = self.membership_cert
            && let Ok(mut g) = runtime.verified_peer_certs.write()
        {
            if g.len() >= veil_proto::budget::MAX_VERIFIED_PEER_CERTS
                && !g.contains_key(&peer_id)
                && let Some(evict) = g.keys().next().copied()
            {
                g.remove(&evict);
            }
            g.insert(peer_id, cert);
        }
        // S3: surface the remote-side's observation of our public address
        // (STUN-style auto-IP-discovery).  Logged at info so operators
        // running behind NAT can copy-paste this into their `advertise = "..."`
        // config without external STUN.  `None` ⇒ peer is legacy / didn't
        // emit the TLV.
        if let Some(addr) = self.observed_addr {
            runtime.logger.info(
                "session.observed_addr",
                format!(
                    "peer={} reported our public address as {addr}",
                    veil_util::hex_short(&peer_id),
                ),
            );
        }

        self.entry
    }
}

pub async fn register_connection_session(
    runtime: SessionRuntimeContext,
    source: SessionSource,
    expected_peer: Option<ExpectedPeerIdentity>,
    listener_handle: Option<ListenerHandle>,
    session_state: SessionState,
    connection: Box<dyn TransportConnection>,
    // E20: force the directional-dedup bypass regardless of the bootstrap_only
    // heuristic below. Set by no-glare recovery dials (NAT-traversal / SOCKS
    // fallback) where the primary URI was unreachable and the peer is NOT
    // reciprocally dialing — so the canonical-direction session would never
    // materialise and the larger-node_id side would be wrongly stranded.
    bypass_directional_override: bool,
) -> Result<Option<AttachedDebugSession>> {
    let link_id = LinkId::new(runtime.next_link_id.fetch_add(1, Ordering::Relaxed));
    let peer = connection.peer_meta().clone();
    let transport = peer.uri.to_string();
    let remote_addr = peer.remote_addr.map(|addr| addr.to_string());
    let description = peer.description.clone();

    // Per-source-IP session limit — applies only to inbound connections.
    let source_ip: Option<std::net::IpAddr> = if matches!(source, SessionSource::Inbound(_)) {
        peer.remote_addr.map(|sa| sa.ip())
    } else {
        None
    };
    if let Some(ip) = source_ip
        && let Err(err) = check_and_reserve_ip_slot(&runtime, ip, link_id)
    {
        drop(connection);
        return Err(err);
    }

    // Arm the RAII guard so a future cancellation between
    // `check_and_reserve_ip_slot` and `SessionGuard` construction cannot
    // leak the slot.
    let mut _ip_slot_guard =
        source_ip.map(|ip| IpSlotGuard::arm(ip, Arc::clone(&runtime.sessions_per_ip)));

    runtime.logger.debug(
        "handshake.start",
        format!("link_id={} source={}", link_id, source),
    );

    // Clone QUIC's DATAGRAM side channel before consuming the transport into
    // its primary byte stream. Non-QUIC transports return None and preserve
    // the ordered-stream-only behavior exactly.
    let quic_datagrams = connection.quic_datagrams();
    let mut stream = match connection.into_stream() {
        Ok(stream) => stream,
        Err(err) => {
            return Err(NodeError::Transport(err));
        }
    };

    // On inbound connections, peek the first 24 bytes before kicking off
    // the OVL1 handshake.  If they form a `SessionMsg::HandoffAttach`
    // header and the HMAC verifies against a pending handoff in
    // `handoff_registry`, this socket is the warm-standby continuation of
    // an existing session — we push it into the matching runner's
    // `swap_rx` and return without touching handshake.  Otherwise
    // `peek_and_dispatch` hands us back a `PrefixedStream` that replays
    // the peeked bytes so the handshake sees its normal input.
    if matches!(source, SessionSource::Inbound(_)) {
        use crate::runtime::handoff::{PeekOutcome, peek_and_dispatch};
        let peek_timeout_secs = veil_proto::budget::HANDSHAKE_TIMEOUT_SECS;
        match peek_and_dispatch(
            stream,
            &runtime.handoff.registry,
            &runtime.handoff.swap_registry,
            peek_timeout_secs,
        )
        .await
        {
            PeekOutcome::HandoffBound => {
                runtime.logger.info(
                    "session.handoff.accept_bound",
                    format!(
                        "link_id={} source={} bound to existing session via HandoffAttach",
                        link_id, source
                    ),
                );
                return Ok(None);
            }
            PeekOutcome::Handshake(new_stream) => {
                stream = new_stream;
            }
            PeekOutcome::Drop(reason) => {
                return Err(NodeError::Handshake(format!(
                    "handoff peek rejected connection: {reason}"
                )));
            }
        }
    }

    // `pending_peer_state` is derived during the handshake but published —
    // per-peer caches and the `session_registry` entry alike — only after the
    // accept gates pass (audit cycle-9 CRIT-6, and the caches likewise).
    let (remote_identity, pending_peer_state): (RemoteHandshakeInfo, PendingPeerState) = {
        let role = runtime.dispatcher.role;
        let mlkem_ek_bytes: Vec<u8> = runtime.identity.mlkem_keys.current_ek().to_vec();
        let capture_tx = Arc::clone(&runtime.dispatcher.capture_tx);
        let local_id: [u8; 32] = *runtime.identity.local_identity.node_id.as_bytes();
        let hs_capture =
            move |inbound: bool, family: u8, msg_type: u16, body: &[u8], peer_id: [u8; 32]| {
                let guard = lock!(capture_tx);
                if let Some(ref tx) = *guard {
                    let ts_us = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_micros() as u64;
                    let ev = veil_dispatcher::CaptureEvent::new_truncated(
                        ts_us,
                        inbound,
                        peer_id,
                        local_id,
                        family,
                        msg_type,
                        body.len() as u32,
                        body,
                        false, // not e2e_plaintext
                    );
                    let _ = tx.send(ev);
                }
            };
        let known_remote_id: Option<[u8; 32]> =
            expected_peer.as_ref().map(|ep| *ep.node_id.as_bytes());
        // Session-resumption fast-path. RE-ENABLED (audit cycle-2): the prior
        // CRITICAL — resumption restored the ORIGINAL session's tx/rx keys into a
        // counter-0 `SessionCipher`, repeating the original session's exact
        // (key, nonce) per frame — is now closed at the handshake layer.
        // Resumption derives FRESH keys via `veil_crypto::session_kdf::
        // derive_resume_keys` from the original keys + a per-resumption nonce
        // minted by EACH side (carried in the HELLO and the ATTACH trailer), so
        // every resumed session has unique keys even if one peer reuses its
        // nonce. A peer that sends a ticket WITHOUT a resume nonce is NOT resumed
        // (the handshake falls back to the full path), so the fix is atomic.
        //
        // Outbound: replay any stored ticket for this peer (the initiator mints
        // its own nonce internally). Inbound: offer the issuer so a presented
        // ticket can be verified (the responder mints + returns its nonce).
        // Fast resumption predates per-session capability persistence and
        // therefore synthesizes `remote_capabilities.flags = 0`. On QUIC that
        // would permanently hide the newly negotiated realtime DATAGRAM lane
        // after the first reconnect. Force the ordinary authenticated
        // capabilities exchange whenever this transport exposes DATAGRAMs;
        // TCP/obfs4/TLS keep their existing 1-RTT fast path unchanged. A future
        // versioned ticket can carry capability flags and remove this gate.
        let allow_fast_resumption = quic_datagrams.is_none();
        let (resume_ticket, ticket_verifier) = match source {
            SessionSource::Outbound(_) => {
                let ticket = allow_fast_resumption
                    .then(|| {
                        known_remote_id
                            .and_then(|id| lock!(runtime.resumption.peer_tickets).get(&id).cloned())
                    })
                    .flatten();
                (ticket, None)
            }
            SessionSource::Inbound(_) => {
                let verifier =
                    allow_fast_resumption.then(|| Arc::clone(&runtime.resumption.ticket_issuer));
                (None, verifier)
            }
        };
        let hs_timeout = std::time::Duration::from_secs(veil_proto::budget::HANDSHAKE_TIMEOUT_SECS);
        // Read the CURRENT document from the shared cell (it advances when
        // the maintenance loop re-issues the delegation at half-validity);
        // the Arc binding keeps it alive for the borrow in the ctx below.
        let sovereign_current = runtime.identity.sovereign_identity.get();
        let sovereign_ctx = sovereign_current.as_ref().map(|sov| SovereignHandshakeCtx {
            sovereign: sov.as_ref(),
            now_unix_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            local_mlkem_dk_seed: None,
        });
        let listener_advertisements: Vec<String> = {
            let state = lock_state(&runtime.state);
            state
                .listens
                .values()
                .filter(|l| l.active)
                .map(|l| {
                    if let Some(adv) = &l.advertise {
                        return adv.clone();
                    }
                    if let Some(addr) = &l.local_addr
                        && uri_has_port_zero(&l.transport)
                        && let Some(scheme) = uri_scheme(&l.transport)
                    {
                        return format!("{scheme}://{addr}");
                    }
                    l.transport.clone()
                })
                .collect()
        };
        let mut local_advertised_transports = Vec::with_capacity(8);
        let local_reflector_port = runtime
            .dispatcher
            .local_udp_reflector_port
            .load(std::sync::atomic::Ordering::Acquire);
        if let Some(advertisement) = veil_nat::udp_reflector_advertisement(local_reflector_port) {
            // The ATTACH transport list is capped at eight entries. Put the
            // service advertisement first so a many-listener Core cannot
            // accidentally trim it; TransportUri parsing deliberately skips
            // this reserved non-dial scheme in hot-standby selection.
            local_advertised_transports.push(advertisement);
        }
        // Share a small, de-duplicated sample learned from our other live
        // peers. This lets a reflector-only Core reach clients through their
        // normal bootstrap Core without putting its address in a seed bundle.
        // Only numeric public endpoints can be serialized by the helper.
        for endpoint in rlock!(runtime.dispatcher.peer_udp_reflectors)
            .values()
            .flatten()
            .copied()
        {
            let Some(advertisement) = veil_nat::udp_reflector_endpoint_advertisement(endpoint)
            else {
                continue;
            };
            if !local_advertised_transports.contains(&advertisement) {
                local_advertised_transports.push(advertisement);
            }
            if local_advertised_transports.len() == 4 {
                break;
            }
        }
        local_advertised_transports.extend(listener_advertisements);
        let discovery_mode = runtime.dispatcher.discovery_mode;
        let anonymity_relay_capable = runtime.anonymity.relay_capable;
        let dht_service = runtime.dispatcher.dht_service;
        let ban_list_arc = Arc::clone(&runtime.dispatcher.abuse.ban_list);
        let is_banned_fn = move |peer_id: [u8; 32]| -> bool {
            ban_list_arc
                .lock()
                .map(|g| g.is_banned(&peer_id))
                .unwrap_or(false)
        };
        // S3: peer's source SocketAddr (on the inbound side) drives the
        // outbound ATTACH frame's OBSERVED_ADDR_TLV — STUN-style auto-IP
        // discovery so remote learns its public address. Outbound side
        // doesn't emit (irrelevant: we initiated the dial and already know
        // our partner's address).
        let peer_observed_addr_for_attach = if matches!(source, SessionSource::Inbound(_)) {
            peer.remote_addr
        } else {
            None
        };
        let hs_result = tokio::time::timeout(
            hs_timeout,
            perform_ovl1_handshake(
                &mut stream,
                &runtime.identity.local_identity,
                role,
                discovery_mode,
                None,
                Some(&mlkem_ek_bytes),
                Some(&hs_capture),
                known_remote_id,
                resume_ticket,
                ticket_verifier,
                sovereign_ctx,
                &local_advertised_transports,
                anonymity_relay_capable,
                dht_service,
                Some(&is_banned_fn),
                // P-Net Phase 2d: pass the loaded gate from
                // SessionRuntimeContext. None when public-mode.
                runtime.network_gate.as_deref(),
                peer_observed_addr_for_attach,
            ),
        )
        .await
        .unwrap_or_else(|_| {
            Err(veil_session::handshake::HandshakeError(format!(
                "handshake timed out after {}s (link_id={})",
                veil_proto::budget::HANDSHAKE_TIMEOUT_SECS,
                link_id,
            )))
        });
        match hs_result {
            Ok(r) => {
                if !runtime.allowed_peer_algos.is_empty() {
                    let decoded = veil_cfg::SignatureAlgorithm::from_wire_byte(
                        r.remote_identity_payload.algo,
                    );
                    let accepted = decoded.is_some_and(|a| runtime.allowed_peer_algos.contains(&a));
                    if !accepted {
                        runtime.logger.warn(
                            "handshake.policy.algo_rejected",
                            format!(
                                "link_id={} peer_algo_byte=0x{:02x} decoded={:?} allow_list={:?}",
                                link_id,
                                r.remote_identity_payload.algo,
                                decoded,
                                runtime.allowed_peer_algos,
                            ),
                        );
                        let _ = stream.shutdown().await;
                        return Err(NodeError::Handshake(format!(
                            "peer algo {:?} (byte=0x{:02x}) not in operator allow-list {:?}",
                            decoded, r.remote_identity_payload.algo, runtime.allowed_peer_algos,
                        )));
                    }
                }
                // Derived only — nothing reaches a shared cache until
                // `commit` below the accept gates.
                let pending_peer_state = prepare_peer_handshake_state(&runtime, &r, &transport);
                let remote_discovery_mode = r.remote_capabilities.parse_discovery_mode();
                let remote_dht_service = r.remote_capabilities.dht_service();
                let mut udp_reflector_port = None;
                let mut shared_udp_reflectors = Vec::with_capacity(4);
                for advertisement in r
                    .remote_advertised_transports
                    .iter()
                    .filter_map(|value| veil_nat::parse_udp_reflector_advertisement(value))
                {
                    match advertisement {
                        veil_nat::UdpReflectorAdvertisement::PeerPort(port) => {
                            udp_reflector_port.get_or_insert(port);
                        }
                        veil_nat::UdpReflectorAdvertisement::Endpoint(endpoint) => {
                            if !shared_udp_reflectors.contains(&endpoint) {
                                shared_udp_reflectors.push(endpoint);
                            }
                            if shared_udp_reflectors.len() == 4 {
                                break;
                            }
                        }
                    }
                }
                (
                    RemoteHandshakeInfo {
                        node_id: r.node_id,
                        public_key: r.public_key,
                        nonce: r.nonce,
                        session_keys: r.session_keys,
                        remote_discovery_mode,
                        remote_dht_service,
                        remote_caps_stated: r.remote_caps_stated,
                        supports_realtime_datagrams: r
                            .remote_capabilities
                            .supports_realtime_datagrams(),
                        supports_realtime_rekey: r.remote_capabilities.supports_realtime_rekey(),
                        udp_reflector_port,
                        shared_udp_reflectors,
                    },
                    pending_peer_state,
                )
            }
            Err(err) => {
                runtime.logger.warn(
                    "handshake.failure",
                    format!("link_id={} source={} error={}", link_id, source, err),
                );
                if let Some(metrics) = &runtime.metrics {
                    metrics.inc_session_handshake_failures();
                }
                if matches!(source, SessionSource::Inbound(_))
                    && let Some(ip) = source_ip
                    && veil_abuse::scanner_shield::is_pre_protocol_garbage(&err.to_string())
                    && runtime.scanner_shield.record_garbage_failure(ip)
                {
                    runtime.logger.warn(
                        "scanner_shield.banned",
                        format!("ip={} reason=invalid_magic_threshold", ip),
                    );
                }
                let _ = stream.shutdown().await;
                return Err(err.into());
            }
        }
    };

    runtime.logger.debug(
        "handshake.success",
        format!(
            "link_id={} source={} node_id={}",
            link_id, source, remote_identity.node_id
        ),
    );

    if let Some(ref expected_peer) = expected_peer {
        match verify_remote_peer_identity(&remote_identity, expected_peer) {
            Ok(()) => {}
            Err(PeerVerificationError::IdentityMismatch(message)) => {
                runtime.logger.warn(
                    "peer.identity_mismatch",
                    format!(
                        "peer_id={} link_id={} source={} error={}",
                        expected_peer.peer_id, link_id, source, message
                    ),
                );
                if let Some(metrics) = &runtime.metrics {
                    metrics.inc_outbound_connect_failures();
                }
                // A DISCOVERED record whose address now answers as a different
                // node is a fossil: that identity is not there any more, and no
                // number of retries will bring it back. It stays in the map
                // otherwise, so the reconnect scheduler dials it forever —
                // observed on a production seed, which had two records for one
                // transport (the node had been redeployed with a new identity)
                // and warned on every reconnect for days.
                //
                // Only what we learned OURSELVES. An operator's `[[peers]]`
                // line is not ours to delete: a stranger answering at a
                // configured address is a security signal, and the right
                // response there is exactly what happens now — refuse, shout,
                // and leave the operator's file alone. Bootstrap entries stay
                // too; they are the operator's list of ways in.
                let dropped_node_id = {
                    let mut state = lock_state(&runtime.state);
                    match state.peers.get(&expected_peer.peer_id) {
                        Some(entry) if identity_mismatch_removes_row(entry, expected_peer) => {
                            let node_id = *entry.node_id.as_bytes();
                            state.peers.remove(&expected_peer.peer_id);
                            // Out of the proof set as well, or the next
                            // snapshot writes it back the moment anything else
                            // re-adds the id.
                            state.handshaked.remove(&node_id);
                            Some(node_id)
                        }
                        _ => None,
                    }
                };
                if let Some(node_id) = dropped_node_id {
                    runtime.logger.info(
                        "peer.discovered_dropped",
                        format!(
                            "peer_id={} node_id={} reason=identity_mismatch — the \
                             address answers as someone else now",
                            expected_peer.peer_id,
                            node_id
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<String>()
                        ),
                    );
                    let config_path = runtime.config_path.clone();
                    let state_for_persist = Arc::clone(&runtime.state);
                    tokio::task::spawn_blocking(move || {
                        persistence::persist_discovered_peers(&state_for_persist, &config_path);
                    });
                }
                let _ = stream.shutdown().await;
                return Err(NodeError::Handshake(message));
            }
            Err(PeerVerificationError::NonceMismatch) => {
                let new_nonce = remote_identity.nonce.clone();
                runtime.logger.info(
                    "peer.nonce_updated",
                    format!(
                        "peer_id={} link_id={} source={} old={} new={}",
                        expected_peer.peer_id, link_id, source, expected_peer.nonce, new_nonce,
                    ),
                );
                {
                    let mut state = lock_state(&runtime.state);
                    if let Some(entry) = state.peers.get_mut(&expected_peer.peer_id) {
                        entry.nonce = new_nonce.clone();
                    }
                }
                let config_path = runtime.config_path.clone();
                let peer_key_for_persist = expected_peer.public_key.clone();
                let nonce_for_persist = new_nonce;
                let state_for_persist = Arc::clone(&runtime.state);
                tokio::task::spawn_blocking(move || {
                    // audit V-03/V-05: a relearned peer nonce is state we picked
                    // up off the wire, not policy the operator wrote, so it goes
                    // to the runtime-state sidecar. It used to be written back
                    // into `config.toml`, which invalidated the operator's
                    // signature and made the next enforced boot refuse to start.
                    // Keyed by public key, not `peer_id`: peer ids are positional
                    // and an operator reordering `[[peers]]` would otherwise hand
                    // this nonce to a different peer.
                    let _ = veil_cfg::runtime_state::record_peer_nonce(
                        &config_path,
                        &peer_key_for_persist,
                        &nonce_for_persist,
                    );
                    persistence::persist_discovered_peers(&state_for_persist, &config_path);
                });
            }
        }
    }

    let matched_peer_id = {
        let state = lock_state(&runtime.state);
        match source {
            SessionSource::Inbound(_) => match_configured_peer(&state, &remote_identity),
            SessionSource::Outbound(peer_id) => Some(peer_id),
        }
    };

    if let Some(peer_id) = matched_peer_id
        && matches!(source, SessionSource::Inbound(_))
    {
        runtime.logger.debug(
            "session.peer_matched",
            format!("link_id={} source={} peer_id={}", link_id, source, peer_id),
        );
    }

    // **Phase 4 allowlist check**: for inbound connections, if the
    // hitting listener has a non-empty `allowlist_node_ids` config, the
    // remote peer's node_id MUST be present.  Independent of PSK/TLS —
    // raises the bar even if those credentials leak.  Outbound
    // connections skip this check (we already validated identity through
    // configured `peer_pubkey`).
    if let (SessionSource::Inbound(_), Some(handle)) = (&source, listener_handle) {
        let remote_nid_hex: String = remote_identity
            .node_id
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let allowlist_check = {
            let state = lock_state(&runtime.state);
            state.listens.values().find_map(|entry| {
                if entry.listener_handle == Some(handle) {
                    Some(entry.allowlist_node_ids.clone())
                } else {
                    None
                }
            })
        };
        if let Some(allowlist) = allowlist_check
            && !allowlist.is_empty()
            && !allowlist
                .iter()
                .any(|hex| hex.eq_ignore_ascii_case(&remote_nid_hex))
        {
            let _ = stream.shutdown().await;
            runtime.logger.info(
                "session.allowlist_reject",
                format!(
                    "link_id={} listener_handle={} remote_node_id={} — not in listener allowlist",
                    link_id, handle, remote_nid_hex,
                ),
            );
            return Err(NodeError::Handshake(format!(
                "remote node {} not in listener {} allowlist — rejected link_id={}",
                remote_nid_hex, handle, link_id,
            )));
        }
    }

    // OVL1 is done and the listener's allowlist (if any) accepted this peer:
    // this is the moment we know the endpoint we hold for them actually
    // works. `persist_discovered_peers` writes only peers that reach this
    // line, so gossip we never dialled — or dialled and never reached —
    // stops being handed to the next cold start as a bootstrap candidate.
    let newly_proven = lock_state(&runtime.state)
        .handshaked
        .insert(*remote_identity.node_id.as_bytes());
    if newly_proven {
        // And write it out here. The only other caller on this path is the
        // nonce-relearn branch above, which fires rarely; without this a peer
        // we just reached would wait for the next peer-exchange round to be
        // recorded, and a node that gets little gossip — a phone — could keep
        // an empty cache and cold-start with nothing but the builtin seeds.
        // Guarded on `newly_proven` so a reconnect to a peer already in the
        // file does not rewrite it.
        let state_for_persist = Arc::clone(&runtime.state);
        let config_path = runtime.config_path.clone();
        tokio::task::spawn_blocking(move || {
            persistence::persist_discovered_peers(&state_for_persist, &config_path);
        });
    }

    let (reserved_outbox_rx, referral_session) = {
        // Hard-reject only when even the referral headroom above the data cap
        // is full; otherwise accept (a session at/above max_concurrent is a
        // transient referral — the establish-time peer-gossip steers the
        // client to freer nodes rather than stranding it).
        let at_limit = {
            lock!(runtime.live_sessions).len()
                >= runtime
                    .defaults
                    .max_concurrent
                    .saturating_add(runtime.defaults.referral_headroom)
        };
        let remote_nid = *remote_identity.node_id.as_bytes();
        let session_owner = remote_identity.session_keys.session_id;
        if lock!(runtime.dispatcher.abuse.ban_list).is_banned(&remote_nid) {
            let _ = stream.shutdown().await;
            runtime.logger.debug(
                "session.banned",
                format!(
                    "link_id={} node_id={} — banned peer rejected",
                    link_id,
                    veil_util::hex_short(&remote_nid),
                ),
            );
            return Err(NodeError::Handshake(format!(
                "banned peer {} — rejected link_id={}",
                veil_util::hex_short(&remote_nid),
                link_id,
            )));
        }
        if at_limit {
            let _ = stream.shutdown().await;
            return Err(NodeError::Handshake(format!(
                "session limit reached ({} concurrent sessions); rejecting link_id={}",
                runtime.defaults.max_concurrent, link_id,
            )));
        }
        // Atomic cap+dup+reserve with deterministic direction policy.
        //
        // The legacy `try_register_unique` had a symmetric race: when both
        // peers A and B dialed each other simultaneously, both completed
        // handshake → both saw "duplicate" on inbound → both rejected →
        // BOTH sides killed their outbounds (peer closed our outbound
        // FROM ITS OWN inbound rejection).  Net: 0 sessions, immediate
        // reconnect storm.
        //
        // Phase E20 fix: `try_register_directional` enforces a deterministic
        // policy — for pair (A, B) with hex(A) < hex(B), the A→B connection
        // survives.  Smaller node accepts only its outbound; larger node
        // accepts only its inbound.  Both sides converge on the same
        // surviving TCP connection without an explicit negotiation step.
        let remote_nid = *remote_identity.node_id.as_bytes();
        let local_nid = *runtime.identity.local_identity.node_id.as_bytes();
        let new_is_outbound = matches!(source, SessionSource::Outbound(_));
        // Source of the matched peer record (if any). Drives BOTH the directional
        // bypass and reconnect-eviction eligibility below: Configured/Bootstrap is
        // the mutually-dialing mesh; Exchanged/Autodiscovered is a LEARNED peer we
        // may be unable to dial back (e.g. a NAT'd client behind symmetric NAT).
        let matched_source = matched_peer_id
            .and_then(|pid| lock_state(&runtime.state).peers.get(&pid).map(|e| e.source));
        // E20 directional-dedup is only sound when BOTH peers may dial each
        // other (real glare). Bypass it for one-sided connections, otherwise
        // the larger-node_id side is stranded at zero sessions:
        //   * outbound to a bootstrap — it has no prior knowledge of us and
        //     never dials back (observed: any node whose node_id sorted after
        //     every bootstrap node_id could never join the mesh);
        //   * inbound from a learned/no-record peer — we will never dial them,
        //     so no glare is possible. See `inbound_bypasses_directional`; the
        //     configured mesh (Configured/Bootstrap) still gets the tiebreak.
        let bypass_directional = bypass_directional_override
            || if new_is_outbound {
                matched_peer_id
                    .map(|pid| {
                        lock_state(&runtime.state)
                            .peers
                            .get(&pid)
                            .is_some_and(|e| e.bootstrap_only)
                    })
                    .unwrap_or(false)
            } else {
                inbound_bypasses_directional(matched_source)
            };
        // A LEARNED inbound (a NAT'd client re-dialing) may EVICT a stale
        // same-node_id session instead of being deduped against it. The peer only
        // reconnects once ITS side abandoned the old link, so latest-wins is
        // correct AND immediately releases an M5 zombie's tx (otherwise every
        // reconnect is deduped until the liveness ceiling reaps it). Gated by the
        // SAME `inbound_bypasses_directional` classifier (6d390ef) that excludes
        // the mutually-dialing mesh, so this cannot reintroduce the seed-mesh
        // glare loop that the un-gated replace-on-dedup caused (reverted f053067).
        let evict_stale_on_dedup = !new_is_outbound && inbound_bypasses_directional(matched_source);
        let reserved_outbox_rx = {
            let mut reg = runtime
                .session_tx_registry
                .write()
                .unwrap_or_else(|p| p.into_inner());
            let evicted_open = evict_stale_on_dedup && reg.has_session(&remote_nid);
            let rx = reg.try_register_directional(
                remote_nid,
                &local_nid,
                new_is_outbound,
                bypass_directional,
                evict_stale_on_dedup,
                session_owner,
            );
            if evicted_open && rx.is_some() {
                runtime.logger.info(
                    "session.reconnect_evict",
                    format!(
                        "node_id={} — learned inbound reconnect evicted a stale \
                         session's tx (fast M5-zombie clear)",
                        veil_util::hex_short(&remote_nid),
                    ),
                );
            }
            rx
        };
        let reserved_outbox_rx = match reserved_outbox_rx {
            Some(rx) => rx,
            None => {
                let _ = stream.shutdown().await;
                let direction = if matches!(source, SessionSource::Outbound(_)) {
                    "outbound"
                } else {
                    "inbound"
                };
                runtime.logger.info(
                    "session.dedup",
                    format!(
                        "link_id={} node_id={} direction={} — duplicate session rejected",
                        link_id,
                        veil_util::hex_short(&remote_nid),
                        direction,
                    ),
                );
                return Err(NodeError::Handshake(format!(
                    "duplicate session to node {} — rejected link_id={}",
                    veil_util::hex_short(&remote_nid),
                    link_id,
                )));
            }
        };
        // Authoritative cap check INSIDE the same critical section as the
        // insert. The early `at_limit` read above is only a fast-path: it and
        // the insert took the `live_sessions` lock separately, so N concurrent
        // handshakes could each observe room before any of them inserted and
        // collectively overshoot `max_concurrent`. Re-checking under the insert
        // lock closes that TOCTOU. The `!Send` guard must not span the reject
        // path's `.await`, so decide-and-insert under the lock, then handle the
        // over-limit branch (rollback + shutdown) after the lock scope closes.
        let inserted_count = {
            let mut sessions = lock!(runtime.live_sessions);
            if sessions.len()
                >= runtime
                    .defaults
                    .max_concurrent
                    .saturating_add(runtime.defaults.referral_headroom)
            {
                None
            } else {
                sessions.insert(
                    link_id,
                    SessionInfo {
                        link_id,
                        node_id: Some(remote_identity.node_id),
                        nonce: Some(remote_identity.nonce.clone()),
                        matched_peer_id,
                        source,
                        listener_handle,
                        state: session_state,
                        transport,
                        remote_addr,
                        description,
                    },
                );
                Some(sessions.len())
            }
        };
        let new_count = match inserted_count {
            Some(n) => n,
            None => {
                // Over cap: roll back the directional reservation we took above
                // (we own it — `try_register_directional` returned `Some`).
                runtime
                    .session_tx_registry
                    .write()
                    .unwrap_or_else(|p| p.into_inner())
                    .unregister_owned(&remote_nid, &session_owner);
                let _ = stream.shutdown().await;
                return Err(NodeError::Handshake(format!(
                    "session limit reached ({} concurrent sessions); rejecting link_id={}",
                    runtime.defaults.max_concurrent, link_id,
                )));
            }
        };
        let count_u16 = new_count.min(u16::MAX as usize) as u16;
        runtime.event_bus.publish(veil_proto::EventPayload {
            kind: veil_proto::event_kind::SESSIONS_CHANGED,
            payload: count_u16.to_be_bytes().to_vec(),
        });
        // referral = accepted past the data cap (into the headroom only).
        (
            reserved_outbox_rx,
            new_count > runtime.defaults.max_concurrent,
        )
    };
    // All accept gates (identity-mismatch / allowlist / banned / at-limit /
    // dedup / over-cap) have passed — NOW publish everything this handshake
    // learned about the peer, and register the session in `session_registry`
    // (audit cycle-9 CRIT-6). Every reject path above this point drops
    // `pending_peer_state` without committing, so a rejected peer leaves no
    // trace in the per-peer caches and evicts nothing from them. The matching
    // SessionGuard below removes the registry entry on session end.
    let session_entry = pending_peer_state.commit(&runtime);
    // Which DEVICE of the peer this session ends at, for the resumption ticket
    // the inbound spawner is about to mint. Read before the entry moves into
    // the registry.
    let peer_instance_id = session_entry
        .validated_sovereign_identity
        .as_ref()
        .map(|v| v.active_instance_id);
    lock!(runtime.session_registry).insert(session_entry);
    runtime.logger.info(
        "session.open",
        format!(
            "link_id={} source={} state={} node_id={}",
            link_id, source, session_state, remote_identity.node_id
        ),
    );
    // Notify reputation tracker of session open, keyed on sovereign node_id.
    // The session was just registered above, so `node_id_for_peer` returns
    // `Some(...)` for sovereign peers; legacy peers fall back to peer_id.
    if let Some(ref rep) = runtime.dispatcher.reputation {
        let peer_id = *remote_identity.node_id.as_bytes();
        let identity_for_rep = lock!(runtime.session_registry)
            .node_id_for_peer(&peer_id.into())
            .unwrap_or(peer_id);
        lock!(rep).session_opened(identity_for_rep.into());
    }
    if let Some(metrics) = &runtime.metrics {
        metrics.inc_active_sessions();
        if matches!(source, SessionSource::Inbound(_)) {
            metrics.inc_inbound_sessions();
        }
    };

    // Extract session_id before moving session_keys into AttachedDebugSession.
    let session_id = remote_identity.session_keys.session_id;
    let session = AttachedDebugSession {
        link_id,
        source,
        stream,
        // Never send media into a side channel an older peer does not read.
        // Fast-resumed handshakes currently synthesize zero capabilities, so
        // they also preserve the ordered-stream fallback conservatively.
        // The lane at all needs both sides to speak it; rotating its key needs
        // both sides again, separately — a peer can understand the lane and
        // still keep the handshake-derived key for the session's life
        // (report12 V-M12).
        quic_datagrams: quic_datagrams
            .filter(|_| remote_identity.supports_realtime_datagrams)
            .map(|handle| veil_session::runner::RealtimeLaneOffer {
                handle,
                peer_rotates: remote_identity.supports_realtime_rekey,
            }),
        metrics: runtime.metrics.clone(),
        peer_id: remote_identity.node_id,
        peer_instance_id,
        session_keys: remote_identity.session_keys,
        observed_addr: peer.remote_addr,
        udp_reflector_port: remote_identity.udp_reflector_port,
        shared_udp_reflectors: remote_identity.shared_udp_reflectors,
        public_key: remote_identity.public_key,
        nonce: remote_identity.nonce,
        remote_discovery_mode: remote_identity.remote_discovery_mode,
        remote_dht_service: remote_identity.remote_dht_service,
        remote_caps_stated: remote_identity.remote_caps_stated,
        // Transient when accepted past the data cap (into the headroom only).
        referral: referral_session,
        reserved_outbox_rx,
        _guard: SessionGuard::new(
            runtime.live_sessions,
            link_id,
            runtime.logger,
            runtime.metrics,
            session_id,
            runtime.session_registry,
            source_ip,
            runtime.sessions_per_ip,
            *remote_identity.node_id.as_bytes(),
            runtime.session_tx_registry.clone(),
            runtime.dispatcher.reputation.clone(),
            runtime.event_bus,
            Some(runtime.outbound_connector_refresh),
        ),
    };
    // SessionGuard now owns the slot — disarm our IpSlotGuard so its
    // Drop is a no-op.  SessionGuard's Drop will decrement on session
    // close, exactly as before the RAII refactor.
    if let Some(g) = _ip_slot_guard.as_mut() {
        g.disarm();
    }
    Ok(Some(session))
}

pub fn verify_remote_peer_identity(
    remote_identity: &RemoteHandshakeInfo,
    expected_peer: &ExpectedPeerIdentity,
) -> std::result::Result<(), PeerVerificationError> {
    // When `public_key` is empty the peer was discovered dynamically
    // (e.g. via mesh beacon) and we perform node-id-only verification:
    // confirm that `blake3(handshake_public_key) == expected node_id`.
    // This is TOFU (trust on first use) — sufficient for autodiscovered
    // local-mesh gateways.
    if !expected_peer.public_key.is_empty()
        && remote_identity.public_key != expected_peer.public_key
    {
        return Err(PeerVerificationError::IdentityMismatch(format!(
            "peer identity mismatch for {}: expected configured public_key/node_id {}, got {}",
            expected_peer.peer_id, expected_peer.node_id, remote_identity.node_id
        )));
    }

    if remote_identity.node_id != expected_peer.node_id {
        return Err(PeerVerificationError::IdentityMismatch(format!(
            "peer identity mismatch for {}: expected node_id {}, got {}",
            expected_peer.peer_id, expected_peer.node_id, remote_identity.node_id
        )));
    }

    // Skip nonce check for dynamically-discovered peers (no nonce in beacon).
    if !expected_peer.nonce.is_empty() && remote_identity.nonce != expected_peer.nonce {
        return Err(PeerVerificationError::NonceMismatch);
    }

    Ok(())
}

pub fn match_configured_peer(
    state: &NodeState,
    remote_identity: &RemoteHandshakeInfo,
) -> Option<PeerId> {
    state
        .peers
        .values()
        .find(|peer| {
            peer.public_key == remote_identity.public_key || peer.node_id == remote_identity.node_id
        })
        .map(|peer| peer.peer_id)
}

/// Whether an INBOUND handshake should BYPASS the E20 directional glare
/// tiebreak (i.e. be accepted unconditionally instead of obeying the
/// smaller→larger canonical-direction rule).
///
/// `matched_source` is the `PeerSource` of our `state.peers` record for the
/// remote, or `None` if we have no record.
///
/// The directional convention deterministically picks ONE surviving direction
/// for a glaring pair without negotiation — but it only works when BOTH peers
/// can actually dial each other. That holds for the CONFIGURED mesh
/// (`Configured`/`Bootstrap` — mutual dialers). It does NOT hold for a
/// dynamically-learned peer (`Exchanged` via PEX, `Autodiscovered` via beacon):
/// such a peer may be undialable by us (e.g. a NAT'd client behind a symmetric
/// NAT). For it, the convention can assign "we keep the outbound to them" — a
/// direction that never materialises because our seed→peer dial dies in the NAT
/// — and then its inbound is rejected FOREVER (observed in prod: a NAT'd client
/// could never hold a session to its mailbox-relay seed; `session.open=0`,
/// endless `session.dedup direction=inbound` on an otherwise-empty registry).
/// So: bypass the tiebreak for a no-record or learned-source peer; keep it only
/// for the configured mutual-dial mesh.
pub fn inbound_bypasses_directional(matched_source: Option<PeerSource>) -> bool {
    !matches!(
        matched_source,
        Some(PeerSource::Configured) | Some(PeerSource::Bootstrap)
    )
}

/// Whether an identity mismatch should DROP our record of this peer.
///
/// A record we learned OURSELVES (`Exchanged` via PEX, `Autodiscovered` via
/// beacon) names a node at an address. When that address answers as somebody
/// else, the node it named is not there any more and no number of retries
/// brings it back — the record is a fossil, and the reconnect scheduler dials
/// it forever. Observed on a production seed: two records for one transport,
/// because the machine had been redeployed with a new identity, and a
/// `peer.identity_mismatch` warning on every reconnect for days.
///
/// An operator's `[[peers]]` line is NOT ours to delete. A stranger answering
/// at a configured address is a security signal — an address takeover, a
/// misdirected DNS name — and deleting the line would erase the evidence and
/// silently accept the new occupant at the next opportunity. Refuse, shout,
/// leave the file alone. `Bootstrap` is the operator's list of ways in and is
/// treated the same.
pub fn identity_mismatch_drops_record(source: PeerSource) -> bool {
    !matches!(source, PeerSource::Configured | PeerSource::Bootstrap)
}

/// Whether an identity mismatch should remove THIS row.
///
/// Two questions, and only the first used to be asked.
///
/// Is the record ours to delete — see [`identity_mismatch_drops_record`].
///
/// And is it still the record this handshake was about. A `PeerId` is a local
/// slot that outlives the row occupying it: between the dial and the verdict an
/// endpoint refresh can rewrite the address, or an eviction plus a rediscovery
/// can put a different peer at the same number. The verdict was applied to
/// whatever was at the slot when it arrived, so a stale handshake deleted a row
/// that had already been corrected — and the correction is exactly what would
/// have made the next dial work (report16 V16-M6).
///
/// The node id and the address at dial time are the fingerprint. Neither is
/// rewritten in place for a row that stayed the same thing.
pub fn identity_mismatch_removes_row(
    entry: &PeerConfigEntry,
    expected: &ExpectedPeerIdentity,
) -> bool {
    identity_mismatch_drops_record(entry.source)
        && entry.node_id == expected.node_id
        && entry.transport == expected.row_transport_at_dial
}

pub fn peer_transport_context(
    base: &TransportContext,
    peer: &PeerConfigEntry,
) -> Result<TransportContext> {
    let mut ctx = base.clone();
    if let Some(path) = peer.tls_ca_cert.as_deref() {
        ctx = ctx.with_trusted_certificates_from_file(Path::new(path))?;
    }
    if let (Some(cert), Some(key)) = (peer.tls_cert.as_deref(), peer.tls_key.as_deref()) {
        ctx = ctx.with_client_identity_from_files(Path::new(cert), Path::new(key))?;
    }
    Ok(ctx)
}

#[cfg(test)]
mod identity_mismatch_drop_tests {
    use super::{
        ExpectedPeerIdentity, identity_mismatch_drops_record, identity_mismatch_removes_row,
    };
    use crate::types::{PeerConfigEntry, PeerId, PeerSource};

    const ADDR: &str = "tcp://10.0.0.7:5555";

    fn row(source: PeerSource, node: u8, transport: &str) -> PeerConfigEntry {
        PeerConfigEntry {
            peer_id: PeerId::new(7),
            node_id: veil_cfg::NodeId::from([node; 32]),
            public_key: String::new(),
            nonce: String::new(),
            transport: transport.to_owned(),
            algo: veil_cfg::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            bootstrap_only: false,
            source,
        }
    }

    fn expectation(node: u8, transport: &str) -> ExpectedPeerIdentity {
        ExpectedPeerIdentity {
            peer_id: PeerId::new(7),
            public_key: String::new(),
            node_id: veil_cfg::NodeId::from([node; 32]),
            nonce: String::new(),
            row_transport_at_dial: transport.to_owned(),
        }
    }

    /// A verdict applies to the row it was about, and to no other.
    ///
    /// The removal looked the slot up by `PeerId` and deleted whatever was
    /// there. A `PeerId` is a local slot that outlives its occupant: an
    /// endpoint refresh rewrites the address, and an eviction plus a
    /// rediscovery can put a different peer at the same number. So a handshake
    /// that started before either came back and deleted the CORRECTED row —
    /// the one that would have made the next dial work (report16 V16-M6).
    #[test]
    fn a_stale_verdict_does_not_delete_the_row_that_replaced_it() {
        let expected = expectation(0xAA, ADDR);

        assert!(
            identity_mismatch_removes_row(&row(PeerSource::Exchanged, 0xAA, ADDR), &expected),
            "premise: the unchanged row is still removed"
        );

        assert!(
            !identity_mismatch_removes_row(
                &row(PeerSource::Exchanged, 0xAA, "tcp://10.0.0.9:5555"),
                &expected
            ),
            "the address was refreshed while this handshake was in flight, and \
             the refresh was deleted"
        );

        assert!(
            !identity_mismatch_removes_row(&row(PeerSource::Exchanged, 0xBB, ADDR), &expected),
            "the slot was reused by a different peer, and that peer was deleted"
        );
    }

    /// And the source rule still governs: a matching fingerprint does not make
    /// an operator's line deletable.
    #[test]
    fn a_matching_fingerprint_does_not_override_the_operators_line() {
        let expected = expectation(0xAA, ADDR);
        for source in [PeerSource::Configured, PeerSource::Bootstrap] {
            assert!(
                !identity_mismatch_removes_row(&row(source, 0xAA, ADDR), &expected),
                "{source} row deleted"
            );
        }
        for source in [PeerSource::Exchanged, PeerSource::Autodiscovered] {
            assert!(
                identity_mismatch_removes_row(&row(source, 0xAA, ADDR), &expected),
                "{source} row kept"
            );
        }
    }

    #[test]
    fn a_record_we_learned_ourselves_is_dropped() {
        // The address answers as someone else: the node this record names is
        // gone, and retrying it can never succeed.
        assert!(identity_mismatch_drops_record(PeerSource::Exchanged));
        assert!(identity_mismatch_drops_record(PeerSource::Autodiscovered));
    }

    #[test]
    fn the_operators_own_lines_are_never_deleted() {
        // A stranger at a configured address is a SIGNAL — an address
        // takeover, a misdirected name. Deleting the line would erase the
        // evidence and accept the new occupant at the next opportunity.
        assert!(!identity_mismatch_drops_record(PeerSource::Configured));
        assert!(!identity_mismatch_drops_record(PeerSource::Bootstrap));
    }

    #[test]
    fn the_two_answers_do_not_collapse() {
        // Vacuity guard: a predicate returning one answer for everything would
        // satisfy exactly one of the tests above and look fine in isolation.
        assert_ne!(
            identity_mismatch_drops_record(PeerSource::Exchanged),
            identity_mismatch_drops_record(PeerSource::Configured)
        );
    }
}

#[cfg(test)]
mod resumed_binding_tests {
    use super::binding_for_resumed_session;
    use std::collections::HashMap;
    use veil_identity::verify::ValidatedIdentity;

    const IDENTITY: [u8; 32] = [0xAA; 32];
    const LAPTOP: [u8; 16] = [0x01; 16];
    const PHONE: [u8; 16] = [0x02; 16];

    fn device(instance: [u8; 16]) -> ValidatedIdentity {
        ValidatedIdentity {
            node_id: IDENTITY,
            master_algo: 0,
            master_pubkey: vec![0xEE; 32],
            active_identity_pubkey: instance.to_vec(),
            active_identity_algo: 0,
            active_key_idx: 0,
            active_device_id: [instance[0]; 32],
            active_instance_id: instance,
        }
    }

    fn family() -> HashMap<([u8; 32], [u8; 16]), ValidatedIdentity> {
        HashMap::from([
            ((IDENTITY, LAPTOP), device(LAPTOP)),
            ((IDENTITY, PHONE), device(PHONE)),
        ])
    }

    /// THE DEFECT, in one assertion. Both devices of an identity hand out the
    /// SAME `node_id` in their HELLO, so a per-peer binding cache held one
    /// slot for the family and the later full handshake overwrote the earlier
    /// one. The laptop's resumption then restored the phone's binding, the
    /// registry indexed the session under the phone, and a direct-session seal
    /// keyed its mail to a device at the other end of the room. The ticket
    /// names the device; the lookup must use it.
    #[test]
    fn a_resumption_takes_the_binding_of_the_device_its_ticket_names() {
        let bindings = family();
        let picked = binding_for_resumed_session(&bindings, IDENTITY, Some(LAPTOP))
            .expect("the laptop's own binding");
        assert_eq!(picked.active_instance_id, LAPTOP);
        let picked = binding_for_resumed_session(&bindings, IDENTITY, Some(PHONE))
            .expect("the phone's own binding");
        assert_eq!(picked.active_instance_id, PHONE);
    }

    /// A ticket that names a device this node holds no binding for gets
    /// nothing — never a sibling's row as a consolation.
    #[test]
    fn a_named_device_we_do_not_know_yields_no_binding() {
        let mut bindings = family();
        bindings.remove(&(IDENTITY, PHONE));
        assert!(binding_for_resumed_session(&bindings, IDENTITY, Some(PHONE)).is_none());
    }

    /// No device named — the initiator half of a resumption, or a ticket
    /// minted before tickets carried the instance. One known device is
    /// unambiguous and may be adopted; a family may not, because any pick
    /// would be a coin flip.
    #[test]
    fn an_unnamed_device_is_adopted_only_when_the_identity_has_exactly_one() {
        let solo = HashMap::from([((IDENTITY, LAPTOP), device(LAPTOP))]);
        assert_eq!(
            binding_for_resumed_session(&solo, IDENTITY, None)
                .expect("the only device there is")
                .active_instance_id,
            LAPTOP,
        );
        assert!(
            binding_for_resumed_session(&family(), IDENTITY, None).is_none(),
            "with two devices and nothing naming one, no binding is the only honest answer"
        );
        assert!(
            binding_for_resumed_session(&family(), IDENTITY, Some([0u8; 16])).is_none(),
            "the all-zero sentinel means unspecified, not device zero"
        );
    }

    /// Another identity's rows are not candidates, however few of ours exist.
    #[test]
    fn a_different_identitys_devices_are_never_borrowed() {
        let bindings = HashMap::from([((IDENTITY, LAPTOP), device(LAPTOP))]);
        assert!(binding_for_resumed_session(&bindings, [0xBB; 32], None).is_none());
        assert!(binding_for_resumed_session(&bindings, [0xBB; 32], Some(LAPTOP)).is_none());
    }
}

#[cfg(test)]
mod bypass_tests {
    use super::inbound_bypasses_directional;
    use crate::types::PeerSource;

    #[test]
    fn inbound_bypass_keeps_directional_only_for_configured_mesh() {
        // No record of the peer → bypass (one-sided inbound, no glare).
        assert!(inbound_bypasses_directional(None));

        // Dynamically-learned peers (PEX / mesh beacon) — possibly NAT'd /
        // undialable → bypass so the convention can't strand them on an
        // unreachable canonical direction. This is the prod NAT'd-client fix.
        assert!(inbound_bypasses_directional(Some(PeerSource::Exchanged)));
        assert!(inbound_bypasses_directional(Some(
            PeerSource::Autodiscovered
        )));

        // The CONFIGURED mutual-dial mesh ([[peers]] / [[bootstrap_peers]])
        // still gets the deterministic E20 glare tiebreak — NOT bypassed —
        // so seed↔seed glare resolution stays intact.
        assert!(!inbound_bypasses_directional(Some(PeerSource::Configured)));
        assert!(!inbound_bypasses_directional(Some(PeerSource::Bootstrap)));
    }
}
