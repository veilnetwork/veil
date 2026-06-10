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
//! - [`cache_peer_handshake_state`][] — synchronous "commit" of one
//!   completed `OvlHandshakeResult` into the seven per-peer caches.
//! - [`peer_transport_context`][] — TLS-context fork-and-augment helper
//!   used at outbound dial time.
//!
//! Plus three small private helpers ([`verify_remote_peer_identity`],
//! [`match_configured_peer`], the [`PeerVerificationError`] enum) that
//! split out classification work from `register_connection_session`.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use veil_util::{lock, wlock};

use tokio::io::AsyncWriteExt;

use crate::error::{NodeError, Result};
use crate::state::NodeState;
use crate::types::{
    LinkId, ListenerHandle, PeerConfigEntry, PeerId, SessionInfo, SessionSource, SessionState,
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
}

pub enum PeerVerificationError {
    IdentityMismatch(String),
    NonceMismatch,
}

/// commit per-peer state from a completed OVL1 handshake.
///
/// Extracted from `register_connection_session`.  Populates the session
/// registry entry and seven per-peer caches (pubkey, role bits with
/// reputation-aware role downgrade, cap-flags, ML-KEM EK, battery,
/// Vivaldi, hot-standby alt URI) from a single handshake result.  All work
/// is synchronous — the caller remains responsible for any `await` points.
pub fn cache_peer_handshake_state(
    runtime: &SessionRuntimeContext,
    r: &OvlHandshakeResult,
    primary_uri: &str,
) {
    let peer_id = r.remote_identity_payload.node_id;
    // LOCK ORDER: canonical workspace-wide order (see session_guard.rs) is
    // `session_registry` (#3) → `peer_sovereign_identities` (#5).  However
    // the SessionEntry insert needs the `validated` value computed from
    // the sovereign cache, and holding both locks simultaneously in inverted
    // order would create a deadlock cycle against future code that takes
    // them in canonical order.
    //
    // We split the work into two sequential critical sections instead:
    //   (1) take `peer_sovereign_identities`, compute `validated`, drop.
    //   (2) take `session_registry`, insert SessionEntry with `validated`.
    //
    // A reader racing between (1) and (2) sees either old-registry +
    // old-sovereign OR new-registry + new-sovereign — never a cross-
    // generation pair, because `validated` snapshot is captured at (1)
    // and applied at (2).
    let validated = {
        use veil_proto::budget::MAX_PEER_SOVEREIGN_IDENTITIES;
        let mut sovereign_g = lock!(runtime.identity.peer_sovereign_identities);
        match r.validated_sovereign_identity.clone() {
            Some(v) => {
                // Full handshake completed — update the cache for future
                // resumption events.  Cap unbounded HashMap growth.
                // Random eviction (HashMap iter is non-deterministic) is
                // acceptable here — cache hit/miss only affects resumption
                // fast-path; missed entries trigger a full handshake.
                if sovereign_g.len() >= MAX_PEER_SOVEREIGN_IDENTITIES
                    && !sovereign_g.contains_key(&peer_id)
                    && let Some(k) = sovereign_g.keys().next().copied()
                {
                    sovereign_g.remove(&k);
                }
                sovereign_g.insert(peer_id, v.clone());
                Some(v)
            }
            None => {
                // Resumption path — look up the cached binding if we
                // recorded one earlier.  Cached sovereign bindings from the
                // resumption fast path are trusted unconditionally; a
                // compromised subkey is mitigated by the document's short
                // `valid_until_unix` window.
                sovereign_g.get(&peer_id).cloned()
            }
        }
        // sovereign_g released here.
    };
    lock!(runtime.session_registry).insert(veil_session::SessionEntry {
        session_id: r.session_keys.session_id,
        remote_node_id: peer_id,
        remote_identity: r.remote_identity_payload.clone(),
        remote_capabilities: r.remote_capabilities.clone(),
        remote_attach: r.remote_attach.clone(),
        remote_role: r.remote_role,
        validated_sovereign_identity: validated,
    });
    // Cache the peer's raw public key for signature verification.  Skip
    // if public_key is empty — this happens during session resumption
    // (fast-path reconnect via ticket) where the synthetic IdentityPayload
    // has no key.  Overwriting with empty would break routing-sig verify.
    if !r.remote_identity_payload.public_key.is_empty() {
        lock!(runtime.identity.peer_pubkeys).insert_lru(
            r.remote_identity_payload.node_id,
            (
                r.remote_identity_payload.algo,
                r.remote_identity_payload.public_key.clone(),
            ),
            veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
        );
    }
    // Cache peer's role bits.
    {
        let role_bits = r.remote_capabilities.roles_supported;
        lock!(runtime.identity.peer_roles).insert_lru(
            r.remote_identity_payload.node_id,
            role_bits,
            veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
        );
    }
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
            && !flags_cache.contains_key(&r.remote_identity_payload.node_id)
            && let Some(evict_key) = flags_cache.keys().next().copied()
        {
            flags_cache.remove(&evict_key);
        }
        flags_cache.insert(
            r.remote_identity_payload.node_id,
            r.remote_capabilities.flags,
        );
    }
    // Cache the peer's ML-KEM-768 encapsulation key.  Enforce
    // `MAX_PEER_MLKEM_CACHE` hard-cap with oldest-entry LRU eviction to
    // prevent unbounded growth under peer-churn flood (TTL-only eviction
    // could let the map reach ~12 MiB with a 1-hour TTL).
    if let Some(ref ek) = r.remote_identity_payload.mlkem_pubkey {
        let mut cache = wlock!(runtime.identity.peer_mlkem_keys);
        if cache.len() >= veil_proto::budget::MAX_PEER_MLKEM_CACHE
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(id, _)| *id)
        {
            cache.remove(&oldest);
        }
        cache.insert(
            r.remote_identity_payload.node_id,
            (ek.clone(), std::time::Instant::now()),
        );
    }
    // Update peer battery level from ATTACH TLV.
    if let Some(bat) = r.remote_battery {
        lock!(runtime.rtt_table).update_battery(r.remote_identity_payload.node_id, bat);
    }
    // Store the peer's Vivaldi coordinate for RTT-aware routing.  Reject
    // non-finite coordinates — a malicious peer could send NaN/∞ to poison
    // the local Vivaldi estimate and corrupt routing.
    if let Some((vx, vy, vh)) = r.remote_vivaldi {
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
                r.remote_identity_payload.node_id,
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
                veil_util::hex_short(&r.remote_identity_payload.node_id),
            );
        }
    }
    // Hot-standby: record an auto-discovered alt URI from the peer's
    // advertised-transports AttachPayload TLV.  Only used by `alt_uri_for`
    // when no operator-configured alt_uri exists — explicit config always
    // wins.
    if !r.remote_advertised_transports.is_empty()
        && let Some(picked) = runtime.handoff.controller.auto_set_alt_uri_from_transports(
            r.remote_identity_payload.node_id.into(),
            &r.remote_advertised_transports,
            primary_uri,
        )
    {
        runtime.logger.debug(
            "session.hot_standby.alt_uri_auto_discovered",
            format!(
                "peer={} picked={picked} primary_uri={primary_uri}",
                veil_util::hex_short(&r.remote_identity_payload.node_id),
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
    if let Some(cert) = &r.verified_membership_cert
        && let Ok(mut g) = runtime.verified_peer_certs.write()
    {
        if g.len() >= veil_proto::budget::MAX_VERIFIED_PEER_CERTS
            && !g.contains_key(&peer_id)
            && let Some(evict) = g.keys().next().copied()
        {
            g.remove(&evict);
        }
        g.insert(peer_id, cert.clone());
    }
    // S3: surface the remote-side's observation of our public address
    // (STUN-style auto-IP-discovery).  Logged at info so operators
    // running behind NAT can copy-paste this into their `advertise = "..."`
    // config without external STUN.  `None` ⇒ peer is legacy / didn't
    // emit the TLV.
    if let Some(addr) = r.remote_observed_addr {
        runtime.logger.info(
            "session.observed_addr",
            format!(
                "peer={} reported our public address as {addr}",
                veil_util::hex_short(&r.remote_identity_payload.node_id),
            ),
        );
    }
}

pub async fn register_connection_session(
    runtime: SessionRuntimeContext,
    source: SessionSource,
    expected_peer: Option<ExpectedPeerIdentity>,
    listener_handle: Option<ListenerHandle>,
    session_state: SessionState,
    connection: Box<dyn TransportConnection>,
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

    let remote_identity: RemoteHandshakeInfo = {
        let role = runtime.dispatcher.role;
        let mlkem_ek_bytes: Vec<u8> = runtime.identity.mlkem_ek.as_ref().to_vec();
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
        let (resume_ticket, ticket_verifier) = match source {
            SessionSource::Outbound(_) => {
                let ticket = known_remote_id
                    .and_then(|id| lock!(runtime.resumption.peer_tickets).get(&id).cloned());
                (ticket, None)
            }
            SessionSource::Inbound(_) => {
                let verifier = Some(Arc::clone(&runtime.resumption.ticket_issuer));
                (None, verifier)
            }
        };
        let hs_timeout = std::time::Duration::from_secs(veil_proto::budget::HANDSHAKE_TIMEOUT_SECS);
        let sovereign_ctx =
            runtime
                .identity
                .sovereign_identity
                .as_ref()
                .map(|sov| SovereignHandshakeCtx {
                    sovereign: sov.as_ref(),
                    now_unix_secs: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    local_mlkem_dk_seed: None,
                });
        let local_advertised_transports: Vec<String> = {
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
        let discovery_mode = runtime.dispatcher.discovery_mode;
        let anonymity_relay_capable = runtime.anonymity.relay_capable;
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
                cache_peer_handshake_state(&runtime, &r, &transport);
                let remote_discovery_mode = r.remote_capabilities.parse_discovery_mode();
                RemoteHandshakeInfo {
                    node_id: r.node_id,
                    public_key: r.public_key,
                    nonce: r.nonce,
                    session_keys: r.session_keys,
                    remote_discovery_mode,
                }
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
                let peer_id_for_persist = expected_peer.peer_id;
                let nonce_for_persist = new_nonce;
                let state_for_persist = Arc::clone(&runtime.state);
                tokio::task::spawn_blocking(move || {
                    // audit cycle-8 H5: hold the config-write guard across the
                    // whole load-modify-save so a concurrent lazy-miner
                    // identity-nonce upgrade cannot clobber this peer-nonce
                    // persist (last-writer-wins on the other's field).
                    {
                        let _guard = veil_cfg::config_write_guard();
                        if let Ok(mut cfg) = veil_cfg::load_config(&config_path)
                            && let Some(p) = cfg
                                .peers
                                .iter_mut()
                                .find(|p| p.peer_id == peer_id_for_persist)
                        {
                            p.nonce = nonce_for_persist;
                            let _ = veil_cfg::save_config(&config_path, &cfg);
                        }
                    }
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
        // E20 directional-dedup is only sound when BOTH peers may dial each
        // other (real glare). Bypass it for one-sided connections, otherwise
        // the larger-node_id side is stranded at zero sessions:
        //   * outbound to a bootstrap — it has no prior knowledge of us and
        //     never dials back (observed: any node whose node_id sorted after
        //     every bootstrap node_id could never join the mesh);
        //   * inbound from a peer we have no configured entry for — we will
        //     never dial them, so no glare is possible.
        let bypass_directional = if new_is_outbound {
            matched_peer_id
                .map(|pid| {
                    lock_state(&runtime.state)
                        .peers
                        .get(&pid)
                        .is_some_and(|e| e.bootstrap_only)
                })
                .unwrap_or(false)
        } else {
            matched_peer_id.is_none()
        };
        let reserved_outbox_rx = {
            let mut reg = runtime
                .session_tx_registry
                .write()
                .unwrap_or_else(|p| p.into_inner());
            reg.try_register_directional(
                remote_nid,
                &local_nid,
                new_is_outbound,
                bypass_directional,
            )
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
                    .unregister(&remote_nid);
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
    runtime.logger.info(
        "session.open",
        format!(
            "link_id={} source={} state={} node_id={}",
            link_id, source, session_state, remote_identity.node_id
        ),
    );
    // Notify reputation tracker of session open, keyed on sovereign
    // node_id.  At this point the session has just been registered via
    // `cache_peer_handshake_state`, so `node_id_for_peer` returns
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
        metrics: runtime.metrics.clone(),
        peer_id: remote_identity.node_id,
        session_keys: remote_identity.session_keys,
        observed_addr: peer.remote_addr,
        public_key: remote_identity.public_key,
        nonce: remote_identity.nonce,
        remote_discovery_mode: remote_identity.remote_discovery_mode,
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
            runtime.dispatcher.reputation.clone(),
            runtime.event_bus,
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
