//! Outbound peer connector.
//!
//! Maintains a persistent, auto-reconnecting connection to each configured
//! peer. Connection attempts use exponential back-off with jitter:
//! min=1 s, max=300 s, ±20% jitter. The counter resets after a successful
//! handshake so a brief outage does not permanently degrade reconnect rate.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use veil_util::{lock, rlock, wlock};

use rand_core::{OsRng, RngCore};

use tokio::{io::AsyncWriteExt, sync::watch, task::JoinHandle};

use veil_cfg::NodeRole;
use veil_dht::iterative::PeerQuerier;
use veil_proto::{
    codec::encode_header,
    control::RouteProbePayload,
    family::{ControlMsg, FrameFamily, SessionMsg},
    header::FrameHeader,
    session::{AttachPayload, KeepalivePayload},
};
use veil_session::manager::RemoteRole;

use crate::runtime::NodeServices;
use crate::types::PeerConfigEntry;

// ── frame builders ────────────────────────────────────────────────────────────

/// Build an immediate `ROUTE_PROBE` frame for the startup probe.
pub fn build_startup_route_probe_frame() -> Vec<u8> {
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let payload = RouteProbePayload {
        probe_id: 0,
        timestamp_ms,
    };
    let body = payload.encode();
    let mut hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::RouteProbe as u16);
    hdr.body_len = body.len() as u32;
    hdr.set_priority(veil_proto::priority::INTERACTIVE);
    let mut frame = encode_header(&hdr).to_vec();
    frame.extend_from_slice(&body);
    frame
}

/// Build a `SessionMsg::Attach` frame for a leaf node announcing itself to a
/// gateway. Uses role bits from `local_role`.
pub fn build_attach_frame(local_role: NodeRole) -> Vec<u8> {
    let attach = AttachPayload {
        role: local_role.to_role_bits(),
        realm_id: 0,
        attach_epoch: 0,
        mailbox_preference_count: 0,
        gateway_preference_count: 0,
        flags: 0,
    };
    let body = attach.encode();
    let mut hdr = FrameHeader::new(FrameFamily::Session as u8, SessionMsg::Attach as u16);
    hdr.body_len = body.len() as u32;
    let mut frame = encode_header(&hdr).to_vec();
    frame.extend_from_slice(&body);
    frame
}

/// Build a `SessionMsg::Keepalive` frame carrying the current Unix timestamp.
pub fn build_session_keepalive_frame() -> Vec<u8> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let payload = KeepalivePayload { timestamp_secs: ts };
    let body = payload.encode();
    let mut hdr = FrameHeader::new(FrameFamily::Session as u8, SessionMsg::Keepalive as u16);
    hdr.body_len = body.len() as u32;
    let mut frame = encode_header(&hdr).to_vec();
    frame.extend_from_slice(&body);
    frame
}

/// Return `base` with ±20 % random jitter using `OsRng`.
pub fn jittered(base: Duration) -> Duration {
    // OsRng is cryptographically secure and avoids the low-entropy bias of
    // SystemTime::subsec_nanos when many connections start simultaneously.
    let rnd = OsRng.next_u32();
    // Map [0, 2^32) → [-20, +20] percent.
    let pct: i64 = (rnd % 41) as i64 - 20;
    let base_ms = i64::try_from(base.as_millis()).unwrap_or(i64::MAX);
    let adjusted_ms = (base_ms + base_ms * pct / 100).max(1) as u64;
    Duration::from_millis(adjusted_ms)
}

// ── spawn_outbound_peers ──────────────────────────────────────────────────────

/// Spawn one reconnect loop per configured peer.
///
/// Returns handles for all spawned tasks so the caller can abort them on
/// shutdown.
pub fn spawn_outbound_peers(
    peers: Vec<PeerConfigEntry>,
    access: &NodeServices,
    shutdown_tx: &watch::Sender<bool>,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::with_capacity(peers.len());
    for peer in peers {
        // per-node-id slot claim. Each connector task owns
        // its `node_id` until it exits — duplicates from different
        // `PeerSource` (configured / bootstrap / PEX / gateway-failover /
        // pinned-relay) silently no-op so we keep exactly one reconnect
        // loop per peer. Surfaced by 50-node hub-kill stress test:
        // gateway-failover poll spawned a fresh task every 10 s when its
        // peer was offline, accumulating ≥ 20 parallel tasks within 4 min
        // (~290 connect-attempts/sec aggregate across 49 surviving nodes
        // vs ~1.5/sec under correct per-peer exponential backoff).
        let peer_node_id = *peer.node_id.as_bytes();
        let claimed = lock!(access.outbound_connector_node_ids).insert(peer_node_id);
        if !claimed {
            continue;
        }
        let access = access.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        let handle = tokio::spawn(async move {
            // RAII guard: releases the slot on every exit path (shutdown
            // ban, panic). Inlined so the slot lifecycle is visible
            // alongside the task body without crossing a module boundary.
            struct SlotGuard {
                set: Arc<Mutex<std::collections::HashSet<[u8; 32]>>>,
                node_id: [u8; 32],
            }
            impl Drop for SlotGuard {
                fn drop(&mut self) {
                    lock!(self.set).remove(&self.node_id);
                }
            }
            let _slot_guard = SlotGuard {
                set: Arc::clone(&access.outbound_connector_node_ids),
                node_id: peer_node_id,
            };
            let backoff_min = access.defaults.reconnect_backoff_min;
            let backoff_max = access.defaults.reconnect_backoff_max;
            let quiet_after = access.defaults.reconnect_quiet_after_failures;
            let mut backoff = backoff_min;
            // count consecutive failures so we can downgrade the
            // log level after `quiet_after` strikes (still retrying — the
            // peer might come back — just not spamming WARN every cycle).
            let mut consecutive_failures: u32 = 0;
            // Time of the first failure in the current streak; used to
            // report total downtime in the eventual `peer.recovered` line.
            let mut first_failure_at: Option<std::time::Instant> = None;
            let peer_node_id = *peer.node_id.as_bytes();
            // Audit batch 2026-05-25 phase I: Phase E20 directional dedup
            // policy — for pair (A, B) with `hex(A) < hex(B)`, the A→B
            // outbound is the canonical session.  Larger-hex side (B)
            // keeps INBOUND and rejects its own outbound attempts with
            // `session.dedup direction=outbound`.  Pre-fix the outbound_
            // connector dialed regardless of policy: B would hammer A
            // every 30 s, A would dedup-reject, B would sleep 30 s
            // (duplicate-session backoff), repeat — visible as steady
            // 500+/min handshake failures across the cluster even with
            // chaos-ban stopped.  Worse, if A's own outbound to B got
            // race-rejected by a stale tx_registry entry, the pair
            // ended up in a wedge state since B never recovered the
            // session even on its own (every dial doomed by policy).
            //
            // Fix: pre-flight the policy check.  When we are the keep-
            // inbound side for this peer (`hex(local) > hex(peer)`),
            // skip dialing entirely — sit on `force_reconnect_notify`
            // and `has_session` polling, waiting for the canonical-
            // direction inbound to arrive.  Saves CPU/PoW-challenge
            // load on the peer, eliminates the dedup-reject loop, and
            // gives the lower-hex side a clean path to register.
            let we_keep_outbound = access.local_node_id.as_slice() < peer_node_id.as_slice();

            loop {
                // Check if this peer was banned.  Audit batch 2026-05-25
                // phase J: previously `break` exited the entire
                // outbound_connector task, dropping the slot_guard and
                // unregistering the peer from
                // `outbound_connector_node_ids`.  When the ban expired
                // (or was lifted), nothing re-spawned the task — peer
                // remained un-dialed indefinitely.  Visible under
                // chaos-ban stress: target-host's outbound_connector
                // died mid-cycle, and when the peer's ban_list entry
                // expired (~15 min later) the canonical-direction dial
                // never resumed even though policy said we
                // should dial.  Fix: sleep + recheck instead of
                // exiting; ban expiration naturally pulls us back into
                // the dial path.  `force_reconnect_notify` wakes us
                // immediately on operator-initiated unban (admin tear-
                // down keeps stale entries from out of the registry).
                if lock!(access.dispatcher.abuse.ban_list).is_banned(&peer_node_id) {
                    tokio::select! {
                        _ = shutdown_rx.changed() => break,
                        _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                        _ = access.force_reconnect_notify.notified() => {}
                    }
                    continue;
                }
                // skip the outbound connect entirely when an
                // inbound session for this peer is already registered (the
                // remote won the symmetric handshake race). Prior code
                // detected this *after* connect via the `duplicate session`
                // error and slept 30 s, but each cycle still produced a real
                // handshake on the peer — visible as steady +1
                // `session_handshake_failures_total` per peer-pair every
                // 30 s on bootstrap nodes (testnet). A pre-check
                // lets us poll cheaply: if the inbound is still up, we just
                // sleep and re-poll; if it dies, the next iteration sees
                // `has_session=false` and connects normally.
                if rlock!(access.session_tx_registry).has_session(&peer_node_id) {
                    // also wake on `force_reconnect_notify` so a
                    // network-change event short-circuits the 30-s pre-check
                    // sleep. Pair this with `force_reconnect_all_peers` —
                    // that method unregisters stale entries first, so when we
                    // re-evaluate `has_session` on the next loop iteration it
                    // returns false and we proceed to `connect_peer_active`
                    // (which will use SESSION_TICKET fast-resume if available).
                    tokio::select! {
                        _ = shutdown_rx.changed() => break,
                        _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                        _ = access.force_reconnect_notify.notified() => {}
                    }
                    continue;
                }
                // Bootstrap peers are exempt from the directional-dedup skip:
                // a bootstrap has no prior knowledge of us and never dials IN,
                // so the larger-node_id side MUST still initiate or it can
                // never join. tx_registry mirrors this bypass on both sides.
                // No glare: once our outbound lands the bootstrap sees it as
                // inbound and dedups any later dial via the has_session check.
                if !we_keep_outbound && !peer.bootstrap_only {
                    // Phase E20 policy violation guard: skip dial and
                    // wait for peer-initiated inbound.  Same wake set
                    // as the `has_session` branch — `force_reconnect_
                    // notify` fires on network-change, and a periodic
                    // wakeup re-evaluates ban state + has_session.
                    tokio::select! {
                        _ = shutdown_rx.changed() => break,
                        _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                        _ = access.force_reconnect_notify.notified() => {}
                    }
                    continue;
                }
                tokio::select! {
                    _ = shutdown_rx.changed() => break,
                    result = access.connect_peer_active(peer.peer_id) => {
                        match result {
                            Ok(session) => {
                                // Reset backoff on a successful connection.
                                backoff = backoff_min;
                                // if this success follows a streak
                                // of failures we silenced via quiet-mode
                                // emit a single INFO line so operators see
                                // the recovery without scrolling logs.
                                if consecutive_failures > 0 {
                                    let down_for = first_failure_at
                                        .map(|t| t.elapsed())
                                        .unwrap_or_default();
                                    access.logger.info(
                                        "peer.recovered",
                                        format!(
                                            "peer_id={} after_failures={} down_for_ms={}",
                                            peer.peer_id,
                                            consecutive_failures,
                                            down_for.as_millis(),
                                        ),
                                    );
                                }
                                consecutive_failures = 0;
                                first_failure_at = None;
                                // Build AEAD ciphers from handshake key material.
                                // Also capture raw keys for ticket storage.
                                let (tx_cipher, rx_cipher, session_id, raw_tx_key, raw_rx_key) = {
                                    let keys = session.session_keys;
                                    let tx = keys.tx_key;
                                    let rx = keys.rx_key;
                                    (
                                        Some(veil_crypto::session_cipher::SessionCipher::new(&tx, true)),
                                        Some(veil_crypto::session_cipher::SessionCipher::new(&rx, true)),
                                        keys.session_id,
                                        tx,
                                        rx,
                                    )
                                };
                                let peer_id = session.peer_id;
                                // Consume the tx-registry receiver pre-reserved by
                                // `try_register_directional` inside
                                // `register_connection_session` (the directional
                                // glare policy already ran there). The old code
                                // called `.register(peer_id)` a SECOND time here,
                                // which overwrote that reservation with a fresh
                                // channel — orphaning the reserved one (wasted
                                // mpsc allocation) and opening a frame-loss window
                                // where a send between the two registrations landed
                                // in the discarded channel. Mirror the inbound path
                                // (mod.rs), which consumes `reserved_outbox_rx`.
                                let outbox_rx = session.reserved_outbox_rx;
                                let rpc_rx = access.session_outbox.register(peer_id);

                                // if we're a Leaf connecting to a Gateway
                                // send a post-handshake ATTACH to register the lease
                                // and start a periodic keepalive loop.
                                let local_role = access.dispatcher.role;
                                let remote_is_gateway = {
                                    let reg = access.session_registry
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner());
                                    matches!(
                                        reg.get_by_peer_id(&peer_id).map(|e| e.remote_role),
                                        Some(RemoteRole::Core)
                                    )
                                };
                                if local_role == NodeRole::Leaf && remote_is_gateway {
                                    // 76.4: Send ATTACH to re-register the lease.
                                    let attach_frame = build_attach_frame(local_role);
                                    access.session_tx_registry
                                        .write()
                                        .unwrap_or_else(|p| p.into_inner())
                                        .send_to(
                                            peer_id.as_bytes(),
                                            veil_proto::priority::INTERACTIVE,
                                            attach_frame,
                                        );

                                    // 76.3: Spawn a gateway keepalive loop.
                                    let ka_interval = access.defaults.gateway_keepalive_interval;
                                    if ka_interval.as_secs() > 0 {
                                        let ka_tx_registry = Arc::clone(&access.session_tx_registry);
                                        let ka_peer_id = *peer_id.as_bytes();
                                        tokio::spawn(async move {
                                            let mut ticker = tokio::time::interval(ka_interval);
                                            loop {
                                                ticker.tick().await;
                                                let frame = build_session_keepalive_frame();
                                                let sent = ka_tx_registry
                                                    .read()
                                                    .unwrap_or_else(|p| p.into_inner())
                                                    .send_to(
                                                        &ka_peer_id,
                                                        veil_proto::priority::INTERACTIVE,
                                                        frame,
                                                    );
                                                // Exit when the session is gone.
                                                if !sent {
                                                    break;
                                                }
                                            }
                                        });
                                    }
                                }

                                let dispatcher = Arc::clone(&access.dispatcher);
                                let ban_list = Arc::clone(&dispatcher.abuse.ban_list);
                                let violation_tracker = Arc::clone(&dispatcher.abuse.violation_tracker);
                                let mut runner = veil_session::runner::SessionRunner {
                                    stream:                         session.stream,
                                    peer_id:                        *peer_id.as_bytes(),
                                    dispatcher,
                                    logger:                         Arc::clone(&access.logger),
                                    metrics:                        access.metrics.clone(),
                                    ban_list,
                                    violation_tracker,
                                    crypto: veil_session::runner::CryptoState {
                                        tx_cipher,
                                        rx_cipher,
                                        peer_mlkem_keys: Some(Arc::clone(&access.identity.peer_mlkem_keys)),
                                        per_session_mlkem_dk: Some(Arc::clone(&access.identity.per_session_mlkem_dk)),
                                    },
                                    outbox:                         Some(outbox_rx),
                                    rpc_outbox:                     Some(rpc_rx),
                                    keepalive_interval:             access.defaults.keepalive_interval,
                                    idle_timeout:                   access.defaults.idle_timeout,
                                    max_pending_responses:          access.defaults.max_pending_responses,
                                    pending_response_ttl:           access.defaults.pending_response_ttl,
                                    max_frame_body:                 access.defaults.max_frame_body,
                                    rekey: veil_session::runner::RekeyConfig {
                                        bytes_threshold: access.defaults.rekey_bytes_threshold,
                                        time_threshold_secs: access.defaults.rekey_time_threshold_secs,
                                    },
                                    qos_weights:                    access.defaults.qos_weights,
                                    session_id,
                                    local_node_id:                  access.local_node_id,
                                    mobile: veil_session::runner::MobileConfig {
                                        base_keepalive_interval: access.defaults.keepalive_interval,
                                        battery_keepalive_scale_low: access.mobile.battery_keepalive_scale_low,
                                        battery_keepalive_scale_medium: access.mobile.battery_keepalive_scale_medium,
                                        battery_threshold_low: access.mobile.battery_threshold_low,
                                        battery_threshold_medium: access.mobile.battery_threshold_medium,
                                    },
                                    // client role — server issues the ticket; we receive and store it.
                                    ticket_to_send:                 None,
                                    peer_tickets:                   Some(Arc::clone(&access.resumption.peer_tickets)),
                                    // Store raw keys so SESSION_TICKET handler can build ClientTicketEntry.
                                    raw_session_keys:               Some((raw_tx_key, raw_rx_key, session_id)),
                                    // Store peer identity so ClientTicketEntry can reconstruct OvlHandshakeResult.
                                    peer_public_key:                Some(session.public_key.clone()),
                                    peer_nonce:                     Some(session.nonce.clone()),
                                    hot_standby: veil_session::runner::HotStandbyState {
                                        swap_rx: None,
                                        handoff_registry: Some(Arc::clone(&access.handoff.registry)),
                                        handoff_ack_waiters: Some(Arc::clone(&access.handoff.ack_waiters)),
                                        controller: Some(Arc::clone(&access.handoff.controller)),
                                        auto_trigger_after_write_errors: access.handoff.auto_trigger_after_write_errors,
                                    },
                                    // Outbound side: pass the URI we just dialed so
                                    // the rotation-deadline trigger can do same-URI
                                    // make-before-break without requiring a separate
                                    // alt_uri (Q.7 audit batch).
                                    primary_uri: Some(peer.transport.clone()),
                                };
                                // bootstrap-only peers — send FIND_NODE(self)
                                // and collect contacts into the local DHT, then let
                                // the session run to completion before breaking.
                                if peer.bootstrap_only {
                                    let dht_cfg = access.dht.dht_config().clone();
                                    // share the runtime's TransportCache so
                                    // bootstrap-driven `find_node` benefits (and warms up)
                                    // the same client-side cache as subsequent DHT-walks.
                                    let local_node_id = access.local_node_id;
                                    let querier = veil_dht::network_querier::NetworkPeerQuerier::with_cache(
                                        Arc::clone(&access.session_outbox) as Arc<dyn veil_dht::FrameRouter>,
                                        dht_cfg.k,
                                        tokio::time::Duration::from_millis(dht_cfg.find_node_timeout_ms),
                                        access.dht.transport_cache(),
                                        local_node_id,
                                    );
                                    let dht = Arc::clone(&access.dht);
                                    let logger = Arc::clone(&access.logger);
                                    let peer_node_id = *peer.node_id.as_bytes();

                                    let session_outbox = Arc::clone(&access.session_outbox);
                                    tokio::spawn(async move {
                                        // Wait for SessionRunner to register the outbox
                                        // channel. Retry a few times rather than relying
                                        // on a single fixed delay.
                                        for _ in 0..5 {
                                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                            if session_outbox.peer_ids().contains(&peer_node_id) { break; }
                                        }

                                        let contacts: Vec<veil_dht::routing::Contact> = querier.find_node(peer_node_id, local_node_id).await;
                                        logger.info(
                                            "bootstrap.find_node_done",
                                            format!(
                                                "peer={} contacts_received={}",
                                                veil_util::hex_short(&peer_node_id),
                                                contacts.len()
                                            ),
                                        );
                                        // contacts from a FIND_NODE response body
                                        // are peer-controlled — a malicious peer can stuff the
                                        // reply with arbitrary (node_id, transport) pairs to
                                        // eclipse our routing view. Route them through the
                                        // 2-tier unverified pool; they get promoted only after
                                        // we successfully complete an OVL1 handshake with the
                                        // claimed node_id (proves key ownership).
                                        // attribute to the responding bootstrap
                                        // peer (`peer_node_id`) so a single Sybil bootstrap
                                        // can't fill the pending-contact pool past its quota.
                                        for contact in contacts {
                                            dht.add_contact_unverified_from(peer_node_id, contact);
                                        }
                                    });
                                }

                                // add the just-handshaken peer to our DHT
                                // routing table so recursive FIND_NODE queries treat it as
                                // a k-closest candidate. Without this, `find_closest_nodes`
                                // on this node excludes its own direct-session peers from
                                // the answer, and split-horizon then empties the next_hop
                                // list — recursive queries for `target=peer` die with
                                // `next_hops=0` even when the target is one TCP hop away.
                                //
                                // stamp the peer's last-known
                                // `discovery_mode` from their CAPABILITIES so
                                // `handle_find_node_v2` can filter them out of
                                // FIND_NODE responses if they prefer to stay
                                // hidden from DHT-walks.
                                access.dht.add_contact_trusted(
                                    veil_dht::routing::Contact::with_mode(
                                        *peer.node_id.as_bytes(),
                                        &peer.transport,
                                        session.remote_discovery_mode,
                                    ),
                                );
                                // promote any unverified candidate
                                // for this peer into the verified routing
                                // table — handshake completion is the proof of
                                // key ownership the 2-tier scheme requires.
                                let _ = access.dht.promote_contact_if_pending(
                                    peer.node_id.as_bytes(),
                                );
                                access.logger.info(
                                    "dht.peer_added",
                                    format!(
                                        "outbound handshake → peer={} transport={}",
                                        veil_util::hex_short(peer.node_id.as_bytes()),
                                        veil_util::redact_addr_for_log(&peer.transport),
                                    ),
                                );
                                access.dispatcher.on_session_opened(*peer_id.as_bytes(), session.observed_addr);
                                //gossip our self-signed
                                // transport announcement to the new peer (mirror of
                                // the inbound path) so resolves of `local_node_id`
                                // via this peer return a verified bundle.
                                crate::runtime::send_local_announcement(
                                    &access.dht,
                                    &access.session_outbox,
                                    *peer_id.as_bytes(),
                                );
                                // cache this peer for the next cold
                                // start. We just proved a successful OVL1
                                // handshake at `peer.transport` with their pubkey
                                // — perfect bootstrap candidate when operator
                                // config / builtin seeds are blocked. Skip the
                                // synthetic-range entries (auto-discovered
                                // gateways from mesh, peer_id ≥ 0xC000_0000)
                                // because their `peer.transport` came from a
                                // beacon (already cached separately by
                                // `AutoDiscoveredPeers`).
                                if peer.peer_id.get() < 0xC000_0000 {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map(|d| d.as_secs())
                                        .unwrap_or(0);
                                    let bp = veil_cfg::BootstrapPeer {
                                        transport: peer.transport.clone(),
                                        public_key: peer.public_key.clone(),
                                        nonce: peer.nonce.clone(),
                                        algo: peer.algo,
                                        tls_cert: peer.tls_cert.clone(),
                                        tls_ca_cert: peer.tls_ca_cert.clone(),
                                    };
                                    lock!(access.discovered_peers_cache).upsert(bp, now);
                                }
                                // immediately probe configured outbound peers.
                                access.session_tx_registry
                                    .write()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .send_to(peer_id.as_bytes(), veil_proto::priority::INTERACTIVE, build_startup_route_probe_frame());
                                // stage (d) Task 4a: register
                                // swap_rx keyed by session_id; guard auto-
                                // unregisters on runner exit.
                                let _swap_guard = runner.register_swap_channel(&access.handoff.swap_registry);
                                runner.run().await;
                                drop(_swap_guard);
                                access.dispatcher.on_session_closed(peer_id);
                                // Evict ML-KEM key for this peer.
                                wlock!(access.identity.peer_mlkem_keys).remove(peer_id.as_bytes());
                                // Evict per-session ephemeral DK.
                                lock!(access.identity.per_session_mlkem_dk).remove(peer_id.as_bytes());
                                access.session_tx_registry
                                    .write()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .unregister(peer_id.as_bytes());
                                access.session_outbox.unregister(peer_id);
                                let _ = runner.stream.shutdown().await;

                                // trip the gateway-failover notify
                                // when a synthetic-range gateway session ends
                                // (peer_id ≥ 0xC000_0000). Wakes the auto-
                                // discover loop immediately so it back-fills
                                // the slot in < 1 s instead of waiting for
                                // the next periodic poll (~5 s).
                                if peer.peer_id.get() >= 0xC000_0000 {
                                    access.gateway_failover_notify.notify_waiters();
                                }

                                // Phase E20-fix (2026-05-22): previously
                                // `bootstrap_only` connectors broke after the
                                // first session ended, relying on the
                                // bootstrap-watchdog to re-spawn on full session
                                // loss.  Combined with the new lexicographic dedup
                                // policy, the smaller-node-id side's `outbound_
                                // connector` exits after a deploy-race-caused
                                // session-loss, and the watchdog never fires
                                // (sessions to other peers remain).  Result:
                                // permanent split.
                                //
                                // Fix: let bootstrap-only connectors loop just
                                // like regular peers.  The single-shot FIND_NODE
                                // burst above already ran on the first success;
                                // subsequent reconnects are cheap (TCP+handshake
                                // only, no DHT seed work).
                            }
                            Err(err) => {
                                // scale backoff when local battery is low.
                                let battery = crate::runtime::local_battery_level();
                                let bat_scale = if battery < access.mobile.battery_threshold_low {
                                    access.mobile.battery_keepalive_scale_low as f64
                                } else {
                                    1.0_f64
                                };
                                // per-failure streak bookkeeping.
                                // (The previous `nat.relay_activated` block
                                // here was cargo-cult — it constructed a
                                // throwaway `NatCoordinator`, called
                                // `activate_relay` on it, then dropped
                                // the coordinator immediately. Nothing
                                // routed through any relay; the operator
                                // just got a misleading INFO line on every
                                // single failure. Removed.)
                                consecutive_failures = consecutive_failures.saturating_add(1);
                                if first_failure_at.is_none() {
                                    first_failure_at = Some(std::time::Instant::now());
                                }
                                let quiet =
                                    quiet_after > 0 && consecutive_failures > quiet_after;
                                // Symmetric handshake race: if the remote won and
                                // registered an inbound session from us, our
                                // outbound finishes with `duplicate session`.
                                // The peer is **already reachable** via that
                                // inbound so exponential backoff makes no sense.
                                //
                                // But we can't retry too aggressively either —
                                // every outbound attempt generates a fresh
                                // `PowChallenge` on the peer, and the peer's
                                // per-session PoW rate limiter
                                // (`PowConfig::challenge_rate = 1/s`) will trip
                                // after a handful of rapid retries and auto-ban
                                // us for 5–20 s, cutting off all traffic in both
                                // directions. So: use a fixed long sleep that
                                // stays well under the rate limit.
                                let err_str = err.to_string();
                                let is_duplicate = err_str.contains("duplicate session")
                                    || rlock!(access.session_tx_registry)
                                        .has_session(&peer_node_id);
                                // Apply battery scale to (jittered) sleep delay.
                                let (sleep_dur, reason) = if is_duplicate {
                                    // 30 s — long enough that even if the inbound
                                    // drops mid-sleep we recover within a minute
                                    // yet nowhere near aggressive enough to trip
                                    // `challenge_rate=1/s` + 5-violation auto-ban.
                                    (std::time::Duration::from_secs(30), None)
                                } else {
                                    let raw = jittered(backoff);
                                    let ms = (raw.as_millis() as f64 * bat_scale).round() as u64;
                                    let dur = std::time::Duration::from_millis(ms.max(1));
                                    (dur, Some(err_str.clone()))
                                };
                                if let Some(err_str) = reason {
                                    // when streak is longer than
                                    // `quiet_after`, drop to DEBUG so the
                                    // log doesn't keep screaming about a
                                    // long-dead peer. At streak == quiet+1
                                    // emit one final WARN announcing the
                                    // quiet-mode transition (so the operator
                                    // knows logs aren't lying about the
                                    // problem going away).
                                    if !quiet {
                                        access.logger.warn(
                                            "peer.reconnect.scheduled",
                                            format!(
                                                "peer_id={} delay_ms={} reason={}",
                                                peer.peer_id,
                                                sleep_dur.as_millis(),
                                                err_str
                                            ),
                                        );
                                    } else if consecutive_failures == quiet_after + 1 {
                                        access.logger.warn(
                                            "peer.reconnect.quiet",
                                            format!(
                                                "peer_id={} consecutive_failures={} — further \
                                                 reconnect attempts will be logged at DEBUG \
                                                 (set connection.reconnect_quiet_after_failures = 0 \
                                                 to keep WARN)",
                                                peer.peer_id,
                                                consecutive_failures,
                                            ),
                                        );
                                    } else {
                                        access.logger.debug(
                                            "peer.reconnect.scheduled",
                                            format!(
                                                "peer_id={} delay_ms={} streak={} reason={}",
                                                peer.peer_id,
                                                sleep_dur.as_millis(),
                                                consecutive_failures,
                                                err_str
                                            ),
                                        );
                                    }
                                }
                                // wake on network-change notify so
                                // a forced reconnect after WiFi → 4G flip
                                // doesn't wait out (typically multi-second)
                                // exponential backoff sleep.
                                tokio::select! {
                                    _ = shutdown_rx.changed() => break,
                                    _ = tokio::time::sleep(sleep_dur) => {}
                                    _ = access.force_reconnect_notify.notified() => {}
                                }
                                if is_duplicate {
                                    // Peer is already reachable via the inbound
                                    // that won the race; don't grow backoff.
                                    backoff = backoff_min;
                                } else {
                                    backoff = std::cmp::min(
                                        backoff.saturating_mul(2),
                                        backoff_max,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });
        handles.push(handle);
    }
    handles
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::{
        codec::decode_header,
        family::{FrameFamily, SessionMsg},
        header::HEADER_SIZE,
        session::{AttachPayload, KeepalivePayload},
    };

    #[test]
    fn backoff_grows_to_max_and_stops() {
        let backoff_min = veil_cfg::ConnectionConfig::default().reconnect_backoff_min_ms;
        let backoff_max = veil_cfg::ConnectionConfig::default().reconnect_backoff_max_ms;
        let min = Duration::from_millis(backoff_min);
        let max = Duration::from_millis(backoff_max);
        let mut b = min;
        let mut prev = b;
        for _ in 0..20 {
            b = std::cmp::min(b.saturating_mul(2), max);
            assert!(b >= prev);
            prev = b;
        }
        assert_eq!(b, max);
    }

    /// `reconnect_quiet_after_failures` defaults to a small
    /// non-zero value — operators see a few WARN lines, then logs go quiet.
    #[test]
    fn reconnect_quiet_after_failures_default_is_small_nonzero() {
        let q = veil_cfg::ConnectionConfig::default().reconnect_quiet_after_failures;
        assert!(
            q > 0 && q < 30,
            "default should be small enough to feel responsive but >0 to actually quiet down: got {q}"
        );
    }

    /// simulate the gating logic — `quiet` becomes true only
    /// after `consecutive_failures > quiet_after`, so the operator sees
    /// exactly `quiet_after` WARN lines plus a single transition WARN
    /// (`peer.reconnect.quiet`) before the stream switches to DEBUG.
    #[test]
    fn quiet_mode_gating_matches_streak_threshold() {
        let quiet_after: u32 = 5;
        let mut warnings = 0;
        let mut transitions = 0;
        let mut debugs = 0;
        for streak in 1..=12u32 {
            let quiet = quiet_after > 0 && streak > quiet_after;
            if !quiet {
                warnings += 1;
            } else if streak == quiet_after + 1 {
                transitions += 1;
            } else {
                debugs += 1;
            }
        }
        assert_eq!(warnings, 5, "first {quiet_after} attempts must WARN");
        assert_eq!(
            transitions, 1,
            "exactly one transition WARN at streak == quiet_after + 1"
        );
        assert_eq!(debugs, 6, "remaining attempts must be DEBUG");
    }

    /// `quiet_after = 0` disables quiet mode entirely (operator
    /// can opt out and keep the WARN spam if they prefer it).
    #[test]
    fn quiet_mode_disabled_when_threshold_is_zero() {
        let quiet_after: u32 = 0;
        for streak in 1..=20u32 {
            let quiet = quiet_after > 0 && streak > quiet_after;
            assert!(!quiet, "streak {streak} must stay loud when quiet_after=0");
        }
    }

    #[test]
    fn jittered_stays_within_bounds() {
        let base = Duration::from_secs(60);
        for _ in 0..100 {
            let j = jittered(base);
            // ±20% means [48s, 72s] — add small epsilon for rounding
            assert!(j >= Duration::from_secs(47), "jitter too low: {j:?}");
            assert!(j <= Duration::from_secs(73), "jitter too high: {j:?}");
        }
    }

    // ── tests ─────────────────────────────────────────────────────────

    /// — `build_attach_frame` produces a valid `SessionMsg::Attach`
    /// frame that the gateway dispatcher can decode.
    #[test]
    fn build_attach_frame_is_valid() {
        let frame = build_attach_frame(NodeRole::Leaf);
        assert!(
            frame.len() >= HEADER_SIZE,
            "frame must include at least a header"
        );
        let hdr = decode_header(&frame).expect("valid header");
        assert_eq!(hdr.family, FrameFamily::Session as u8);
        assert_eq!(hdr.msg_type, SessionMsg::Attach as u16);
        let body = &frame[HEADER_SIZE..];
        let attach = AttachPayload::decode(body).expect("valid AttachPayload");
        assert_eq!(attach.role, NodeRole::Leaf.to_role_bits());
    }

    /// — `build_session_keepalive_frame` produces a valid
    /// `SessionMsg::Keepalive` frame that the gateway dispatcher can decode.
    #[test]
    fn build_session_keepalive_frame_is_valid() {
        let frame = build_session_keepalive_frame();
        assert!(frame.len() >= HEADER_SIZE);
        let hdr = decode_header(&frame).expect("valid header");
        assert_eq!(hdr.family, FrameFamily::Session as u8);
        assert_eq!(hdr.msg_type, SessionMsg::Keepalive as u16);
        let body = &frame[HEADER_SIZE..];
        let _ka = KeepalivePayload::decode(body).expect("valid KeepalivePayload");
    }

    /// — verify that the reattach frame carries the correct role bits
    /// and would be accepted by the gateway's `handle_attach`.
    #[test]
    fn leaf_reattach_frame_accepted_by_gateway() {
        use veil_cfg::NodeRole;
        use veil_gateway::GatewayService;

        let gw = GatewayService::new(NodeRole::Core);
        let leaf_id = [0x11u8; 32];

        // Simulate what the outbound connector does on reconnect.
        let frame = build_attach_frame(NodeRole::Leaf);
        let body = &frame[HEADER_SIZE..];
        let attach = AttachPayload::decode(body).expect("valid AttachPayload");

        // The gateway should accept this ATTACH without error.
        gw.handle_attach(leaf_id, &attach).unwrap();
        assert!(
            gw.is_attached(&leaf_id),
            "gateway must record the reattached leaf"
        );
    }

    // ── low-battery reconnect backoff ────────────────────────────

    /// Low battery (< threshold_low) multiplies the reconnect sleep by
    /// `battery_keepalive_scale_low` (default 4.0).
    #[test]
    fn low_battery_increases_backoff() {
        let base = Duration::from_secs(5);
        let scale_low: f64 = 4.0;
        let battery: u8 = 10; // below threshold_low (20)
        let threshold_low: u8 = 20;

        let bat_scale = if battery < threshold_low {
            scale_low
        } else {
            1.0
        };
        // Simulate: raw_sleep = base (no jitter for determinism), then apply scale.
        let sleep_ms = (base.as_millis() as f64 * bat_scale).round() as u64;
        let sleep_dur = Duration::from_millis(sleep_ms.max(1));

        assert_eq!(
            sleep_dur,
            Duration::from_secs(20),
            "low battery must 4× the backoff"
        );
    }

    /// Normal battery (≥ threshold_low) leaves backoff unchanged.
    #[test]
    fn normal_battery_no_backoff_scaling() {
        let base = Duration::from_secs(5);
        let battery: u8 = 80;
        let threshold_low: u8 = 20;

        let bat_scale = if battery < threshold_low {
            4.0_f64
        } else {
            1.0_f64
        };
        let sleep_ms = (base.as_millis() as f64 * bat_scale).round() as u64;
        let sleep_dur = Duration::from_millis(sleep_ms.max(1));

        assert_eq!(
            sleep_dur,
            Duration::from_secs(5),
            "normal battery must not scale backoff"
        );
    }
}
