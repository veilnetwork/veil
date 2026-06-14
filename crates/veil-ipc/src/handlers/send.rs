//! `APP_SEND` / `APP_RT_SEND` handlers + supporting helpers.
//!
//! Local-app → veil datagram pathway.  Decodes the IPC payload, applies
//! the per-client rate limiter, then either delivers locally (when
//! `dst_node_id` matches the daemon's own node-id), sends directly over an
//! authenticated session, or relays through the route cache (with reactive
//! route discovery when the cache is empty).
//!
//! E2E encryption: when a ML-KEM encapsulation key is cached for the
//! recipient, the payload is sealed before relay.  `meta_encrypt` is used
//! for `anonymous=true` sends so outer envelope fields are zeroed and
//! relays cannot learn sender identity.
//!
//! Large payloads (>`MAX_ENVELOPE_PAYLOAD`) are split into relay-preserving
//! chunk-envelopes: each piece travels as its own ordinary `Forward` envelope
//! and the destination reassembles them into the original envelope before
//! addressed delivery (see `ChunkedEnvelopePayload` + the dispatcher's
//! `handle_chunk_envelope`).
//!
//! Pre-encryption capture: when the operator enables live-capture, a
//! plaintext `CaptureEvent` is emitted before E2E sealing so operators
//! see what the app intended to send in addition to the encrypted envelope.

use std::sync::{Mutex, RwLock};

use tokio::io::AsyncWriteExt;
use veil_abuse::rate_limiter::{RateLimiter, TokenBucket};
use veil_app::registry::AppEndpointRegistry;
use veil_proto::{
    AppIpcRtSendPayload, AppIpcSendPayload, AppRtDataPayload, AppSendPayload, FrameFamily,
    FrameHeader, LocalAppMsg, codec, ipc_send_err,
};
use veil_types::FrameBroadcaster;
use veil_util::{lock, rlock, wlock};

use crate::IpcMetrics;

async fn try_lookup_or_discover(
    dst: &[u8; 32],
    local_node_id: &[u8; 32],
    route_cache: Option<&RwLock<veil_routing::RouteCache>>,
    session_tx_registry: Option<&dyn FrameBroadcaster>,
    route_updated: Option<&tokio::sync::Notify>,
    peer_mlkem_keys: Option<&std::sync::RwLock<veil_e2e::PeerMlKemCache>>,
    pending_recursive: Option<
        &Mutex<std::collections::HashMap<[u8; 16], veil_dispatcher_state::PendingRecursive>>,
    >,
) -> Option<[u8; 32]> {
    use veil_proto::{
        codec::encode_header,
        family::{FrameFamily, RoutingMsg},
        header::FrameHeader,
    };

    // Fast path: route already cached AND (no E2E infrastructure OR ML-KEM key cached).
    // If the route is known but the ML-KEM key is absent (e.g. route came from a
    // RouteAnnounce gossip that carries no ML-KEM key), fall through to reactive
    // discovery so a RouteRequest triggers a RouteResponse that brings both the
    // confirmed route and the ML-KEM encapsulation key in one atomic step.
    let mlkem_ready = peer_mlkem_keys
        .map(|k| rlock!(k).get(dst).is_some())
        .unwrap_or(true); // if no E2E infrastructure, route alone is sufficient
    if mlkem_ready
        && let Some(cache) = route_cache
        && let Some(hop) = rlock!(cache).lookup(dst)
    {
        return Some(hop);
    }

    // No route cached — try reactive discovery if we have the infrastructure.
    let notify = route_updated?;
    let reg = session_tx_registry?;
    let cache = route_cache?;

    let discovery_start = std::time::Instant::now();
    log::debug!(
        "route.discovery.start dst={}",
        veil_util::bytes_to_hex(&dst[..4])
    );

    // Register for notification BEFORE sending the request so we don't miss
    // a very fast reply.
    let notified = notify.notified();
    // Oneshot receiver for the matching RecursiveResponse. Set
    // inside the send block below when `pending_recursive` is available.
    let rq_rx: Option<tokio::sync::oneshot::Receiver<Vec<u8>>>;

    // the legacy ROUTE_REQUEST flood-to-all path has been
    // removed; discovery now goes solely through RecursiveQuery
    // which is O(log N) vs O(N²) amplification of the old path.
    {
        // send RecursiveQuery(FindNode) to top-2 closest in DHT.
        // This finds the target via greedy forwarding (O(log N) hops, pipelined)
        // while ROUTE_REQUEST provides backward-compatible discovery.
        let query_id: [u8; 16] = {
            use rand_core::RngCore;
            let mut id = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut id);
            id
        };
        let rq = veil_proto::routing::RecursiveQueryPayload {
            query_id,
            target_key: *dst,
            reply_to: *local_node_id,
            ttl: 40,
            query_type: veil_proto::routing::recursive_query_type::FIND_NODE,
            reply_port: 0,
            payload: vec![],
        };
        let rq_bytes = rq.encode();
        let mut rq_hdr = FrameHeader::new(
            FrameFamily::Routing as u8,
            RoutingMsg::RecursiveQuery as u16,
        );
        rq_hdr.body_len = rq_bytes.len() as u32;
        let mut rq_frame = encode_header(&rq_hdr).to_vec();
        rq_frame.extend_from_slice(&rq_bytes);
        // Register a oneshot so the dispatcher's response handler can wake us
        // the moment it has parsed the response and populated the cache.
        rq_rx = pending_recursive.map(|map| {
            use veil_proto::budget::MAX_PENDING_RECURSIVE;
            let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
            let mut m = map.lock().unwrap_or_else(|p| p.into_inner());
            m.retain(|_, p| !p.tx.is_closed());
            if m.len() < MAX_PENDING_RECURSIVE {
                m.insert(
                    query_id,
                    veil_dispatcher_state::PendingRecursive {
                        target_key: *dst,
                        query_type: veil_proto::routing::recursive_query_type::FIND_NODE,
                        tx,
                    },
                );
            }
            rx
        });
        // Send to the 2 closest peers by XOR distance to `dst` (
        // — greedy start). Previously this was a bare `peer_ids.take(2)`
        // which picked peers in arbitrary HashMap iteration order — under
        // fragmented topology it frequently forwarded *away* from `dst`
        // wasting a whole discovery round on the unlucky direction.
        let mut peers = reg.active_node_ids();
        peers.sort_by_key(|pid| {
            let mut xor = [0u8; 32];
            for i in 0..32 {
                xor[i] = pid[i] ^ dst[i];
            }
            xor
        });
        for pid in peers.iter().take(2) {
            reg.send_to(
                pid,
                veil_proto::header::priority::INTERACTIVE,
                rq_frame.clone(),
            );
        }
    }

    // Wait for the first of: parsed RecursiveResponse (populates cache), any
    // route_updated notification (RouteResponse or gossip), or the 500 ms cap.
    let deadline = std::time::Duration::from_millis(500);
    tokio::pin!(notified);
    if let Some(rx) = rq_rx {
        tokio::select! {
            _ = rx => {}
            _ = &mut notified => {}
            _ = tokio::time::sleep(deadline) => {}
        }
    } else {
        let _ = tokio::time::timeout(deadline, &mut notified).await;
    }

    // Retry the cache lookup.
    let result = rlock!(cache).lookup(dst);
    let elapsed = discovery_start.elapsed();
    if result.is_some() {
        log::debug!(
            "route.discovery.found dst={} elapsed_ms={}",
            veil_util::bytes_to_hex(&dst[..4]),
            elapsed.as_millis()
        );
    } else {
        log::warn!(
            "route.discovery.miss dst={} elapsed_ms={}",
            veil_util::bytes_to_hex(&dst[..4]),
            elapsed.as_millis()
        );
    }
    result
}

/// Write an `APP_SEND_FAILED(RATE_LIMITED)` frame and return `true`.
///
/// Returns `false` without writing anything when `rate_limiter` is `None`
/// or the token bucket allows the request. The `true` / `false` return
/// lets callers early-return immediately:
///
/// ```ignore
/// if rate_limited(wh, &mut rate_limiter).await? { return Ok; }
/// ```
async fn rate_limited(
    wh: &mut crate::transport::IpcWriteHalf,
    rate_limiter: &mut Option<TokenBucket>,
) -> std::io::Result<bool> {
    if let Some(rl) = rate_limiter
        && !rl.allow()
    {
        let err_code = ipc_send_err::RATE_LIMITED.to_be_bytes();
        let mut hdr = FrameHeader::new(
            FrameFamily::LocalApp as u8,
            LocalAppMsg::AppSendFailed as u16,
        );
        hdr.body_len = 2;
        let mut frame = codec::encode_header(&hdr).to_vec();
        frame.extend_from_slice(&err_code);
        wh.write_all(&frame).await?;
        return Ok(true);
    }
    Ok(false)
}

/// Infrastructure references bundled [`handle_ipc_send`].
///
/// Reduces the raw parameter count to 4 while keeping all fields
/// individually named so call-sites remain readable.
pub(crate) struct IpcSendContext<'a> {
    pub(crate) app_registry: &'a AppEndpointRegistry,
    pub(crate) local_node_id: &'a [u8; 32],
    pub(crate) session_tx_registry: Option<&'a dyn FrameBroadcaster>,
    pub(crate) route_cache: Option<&'a RwLock<veil_routing::RouteCache>>,
    pub(crate) route_updated: Option<&'a tokio::sync::Notify>,
    pub(crate) peer_mlkem_keys: Option<&'a std::sync::RwLock<veil_e2e::PeerMlKemCache>>,
    /// Epic 486.1 slice 3: cold-start ML-KEM EK resolver.  When the cache
    /// lookup misses in the relay-encrypted path, the handler invokes this
    /// resolver to fetch + verify + cache the recipient's EK from the DHT.
    /// `None` preserves legacy behaviour exactly (test fixtures + setups
    /// without full NodeRuntime).
    pub(crate) mlkem_ek_resolver: Option<&'a (dyn veil_types::MlKemEkResolver + 'a)>,
    /// Authenticated anonymous (onion/rendezvous) sender. `Some` only when the
    /// full NodeRuntime is wired; the `anonymous_authenticated` flag fails with
    /// `NO_RENDEZVOUS` when this is `None` (test fixtures / minimal setups).
    pub(crate) anon_onion_sender: Option<&'a (dyn veil_types::AnonOnionSender + 'a)>,
    pub(crate) capture_tx: Option<
        &'a Mutex<Option<tokio::sync::broadcast::Sender<veil_dispatcher_state::CaptureEvent>>>,
    >,
    pub(crate) pending_recursive: Option<
        &'a Mutex<std::collections::HashMap<[u8; 16], veil_dispatcher_state::PendingRecursive>>,
    >,
    /// Trace sampling rate.
    pub(crate) trace_sample_rate: f64,
    /// Pending-ACK tracker.
    pub(crate) pending_ack: Option<&'a Mutex<veil_pending_ack::PendingAckTracker>>,
}

pub(crate) async fn handle_ipc_send(
    wh: &mut crate::transport::IpcWriteHalf,
    body: &[u8],
    ctx: &IpcSendContext<'_>,
    rate_limiter: &mut Option<TokenBucket>,
) -> std::io::Result<()> {
    let app_registry = ctx.app_registry;
    let local_node_id = ctx.local_node_id;
    let session_tx_registry = ctx.session_tx_registry;
    let route_cache = ctx.route_cache;
    let route_updated = ctx.route_updated;
    let peer_mlkem_keys = ctx.peer_mlkem_keys;
    let capture_tx = ctx.capture_tx;
    if rate_limited(wh, rate_limiter).await? {
        return Ok(());
    }

    let send = match AppIpcSendPayload::decode(body) {
        Ok(s) => s,
        Err(_) => return Ok(()), // drop malformed
    };

    // explicit application-payload size cap before
    // any E2E encryption / fragmentation work. Frame body is already
    // bounded by `MAX_FRAME_BODY` at the codec layer, but enforcing the
    // cap here makes the bound explicit at the e2e branch and protects
    // against a malicious local app that bypasses the FFI's
    // `VEIL_MAX_DATA_LEN` check by speaking IPC directly.
    if send.data.len() > veil_proto::budget::MAX_APP_PAYLOAD_BYTES {
        let mut hdr = FrameHeader::new(
            FrameFamily::LocalApp as u8,
            LocalAppMsg::AppSendFailed as u16,
        );
        hdr.body_len = 2;
        let mut frame = codec::encode_header(&hdr).to_vec();
        frame.extend_from_slice(&ipc_send_err::PAYLOAD_TOO_LARGE.to_be_bytes());
        wh.write_all(&frame).await?;
        return Ok(());
    }

    // Authenticated anonymous send (onion/rendezvous) — a distinct transport
    // from the meta-E2E `anonymous` flag, and mutually exclusive with it. The
    // onion hides the sender's location from every relay; the recipient
    // cryptographically verifies WHO sent it. Fire-and-forget: a returned
    // AppSendOk (only when require_ack) means "handed to the first hop", not
    // "delivered". All surfaced errors are local / pre-transmit.
    // `is_reply` rides the same onion/rendezvous transport but routes via the
    // opaque reply_id (no explicit destination), so it shares this branch.
    if send.anonymous_authenticated || send.is_reply {
        let err_code = if send.anonymous || (send.is_reply && send.anonymous_authenticated) {
            // meta-E2E `anonymous` conflicts with the onion transport, and
            // `is_reply` already implies the authenticated reply path.
            Some(ipc_send_err::INVALID_FLAGS)
        } else if let Some(sender) = ctx.anon_onion_sender {
            let result = if send.is_reply {
                // Reply: the daemon takes the one-time block by id; the explicit
                // destination fields are ignored. A consumed/expired/unknown id
                // surfaces as NoRendezvous → REPLY_UNKNOWN below.
                sender
                    .send_reply(send.reply_id, &send.data, send.src_app_id)
                    .await
            } else if send.expect_reply {
                // Attach a one-time reply block addressed to our own
                // (src_app_id, reply_endpoint_id) — no public ad published.
                sender
                    .send_authenticated_with_reply(
                        send.dst_node_id,
                        send.app_id,
                        send.endpoint_id,
                        &send.data,
                        send.src_app_id,
                        send.reply_endpoint_id,
                    )
                    .await
            } else {
                sender
                    .send_authenticated(send.dst_node_id, send.app_id, send.endpoint_id, &send.data)
                    .await
            };
            match result {
                Ok(()) => None,
                Err(veil_types::AnonOnionSendError::NoIdentity) => Some(ipc_send_err::NO_IDENTITY),
                Err(veil_types::AnonOnionSendError::NoRendezvous) => {
                    // For a reply, "no rendezvous path" means the reply_id is
                    // unknown/consumed/expired — a distinct, actionable error.
                    if send.is_reply {
                        Some(ipc_send_err::REPLY_UNKNOWN)
                    } else {
                        Some(ipc_send_err::NO_RENDEZVOUS)
                    }
                }
                Err(veil_types::AnonOnionSendError::NoRelays) => Some(ipc_send_err::NO_ROUTE),
                Err(veil_types::AnonOnionSendError::PayloadTooLarge) => {
                    Some(ipc_send_err::PAYLOAD_TOO_LARGE)
                }
            }
        } else {
            // No sender wired (test / minimal setup) — fail rather than
            // silently succeed on an undelivered message.
            Some(ipc_send_err::NO_RENDEZVOUS)
        };
        match err_code {
            Some(code) => {
                let mut hdr = FrameHeader::new(
                    FrameFamily::LocalApp as u8,
                    LocalAppMsg::AppSendFailed as u16,
                );
                hdr.body_len = 2;
                let mut frame = codec::encode_header(&hdr).to_vec();
                frame.extend_from_slice(&code.to_be_bytes());
                wh.write_all(&frame).await?;
            }
            None if send.require_ack => {
                let ok_hdr =
                    FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppSendOk as u16);
                wh.write_all(&codec::encode_header(&ok_hdr)).await?;
            }
            None => {}
        }
        return Ok(());
    }

    if send.dst_node_id == *local_node_id {
        // Local delivery — route directly through the app registry.
        app_registry.route_ipc_deliver(
            *local_node_id,
            send.src_app_id,
            send.app_id,
            send.endpoint_id,
            send.data,
        );
    } else if let Some(reg) = session_tx_registry {
        // Remote delivery — encode an OVL1 APP_SEND frame and push it to
        // the outbox of the session that leads to dst_node_id.
        let ovl1_payload = AppSendPayload {
            src_app_id: send.src_app_id,
            app_id: send.app_id,
            endpoint_id: send.endpoint_id,
            data: send.data.clone(),
        };
        let payload_bytes = ovl1_payload.encode();
        // before fragmenting large payloads, the session's
        // `negotiated_caps.chunking` flag must be checked. When chunking is not
        // negotiated, payloads exceeding the single-frame limit must be rejected
        // with an error rather than silently truncated or forwarded oversized.
        // This guard will be enforced here once introduces fragmentation.
        let mut hdr = FrameHeader::new(
            veil_proto::family::FrameFamily::App as u8,
            veil_proto::family::AppMsg::AppSend as u16,
        );
        hdr.body_len = payload_bytes.len() as u32;
        let mut frame = codec::encode_header(&hdr).to_vec();
        frame.extend_from_slice(&payload_bytes);

        let sent = reg.send_to(
            &send.dst_node_id,
            veil_proto::header::priority::INTERACTIVE,
            frame,
        );

        if !sent {
            // No direct session. Try relay via RouteCache next-hop.
            // If the cache is empty, attempt reactive route discovery:
            // flood a ROUTE_REQUEST and wait up to 500 ms for a response.
            let hop = try_lookup_or_discover(
                &send.dst_node_id,
                local_node_id,
                route_cache,
                session_tx_registry,
                route_updated,
                peer_mlkem_keys,
                ctx.pending_recursive,
            )
            .await;

            if let Some(hop) = hop {
                use veil_proto::delivery::DeliveryEnvelope;
                use veil_proto::family::DeliveryMsg;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // ── E2E / meta-E2E encryption ───────────────────────────────
                // Attempt E2E encryption using the recipient's cached ML-KEM
                // encapsulation key. The key may be absent if the target peer
                // has not yet advertised one (e.g. old client, key rotation
                // in progress, or route was cached before the key arrived).
                // In that case we return an error rather than falling back to
                // plaintext, so the caller is made aware that E2E is unavailable.
                //
                // If `send.anonymous` is set we use meta-E2E: the sender node-id
                // src_app_id, app_id, endpoint_id, and data are all encrypted
                // inside a META_E2E_MARKER envelope so that relays cannot learn
                // who sent the message.
                // C-09: per-message delivery-ACK key, captured from the standard
                // E2E encryption below (stays zero for meta-E2E / no-E2E). It is
                // stored in the pending-ack entry so the originator can verify
                // the recipient's DELIVERED MAC and a forged ACK earns nothing.
                let mut ack_key = [0u8; 32];
                let final_payload = if let Some(keys) = peer_mlkem_keys {
                    let mut recipient_ek = rlock!(keys)
                        .get(&send.dst_node_id)
                        .map(|(ek, _)| ek.clone());

                    // Epic 486.1 slice 3 (audit batch 2026-05-23): cold-start
                    // cache miss → attempt DHT-based EK resolution.  The
                    // resolver walks `IdentityDocument` → `InstanceRegistry`
                    // → `MlKemKeyCert` under the canonical DHT keys and writes
                    // back to `peer_mlkem_keys` on success, so subsequent
                    // sends to the same peer hit the fast path.  `None` after
                    // this still surfaces as `NO_E2E_KEY` (legacy behaviour
                    // preserved).
                    if recipient_ek.is_none()
                        && let Some(resolver) = ctx.mlkem_ek_resolver
                        && let Some(ek) = resolver.resolve_ek(send.dst_node_id).await
                    {
                        recipient_ek = Some(ek);
                    }

                    if let Some(ek) = recipient_ek {
                        if send.anonymous {
                            // meta-E2E: hide sender identity inside ciphertext.
                            match veil_e2e::meta_encrypt(
                                &ek,
                                local_node_id,
                                &send.src_app_id,
                                &send.app_id,
                                send.endpoint_id,
                                &send.dst_node_id,
                                &send.data,
                            ) {
                                Ok(ciphertext) => {
                                    let mut payload = vec![veil_proto::META_E2E_MARKER];
                                    payload.extend_from_slice(&ciphertext);
                                    payload
                                }
                                Err(_) => {
                                    let mut hdr = FrameHeader::new(
                                        FrameFamily::LocalApp as u8,
                                        LocalAppMsg::AppSendFailed as u16,
                                    );
                                    hdr.body_len = 2;
                                    let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
                                    frame
                                        .extend_from_slice(&ipc_send_err::NO_E2E_KEY.to_be_bytes());
                                    return wh.write_all(&frame).await;
                                }
                            }
                        } else {
                            match veil_e2e::encrypt_with_ack(
                                &ek,
                                local_node_id,
                                &send.dst_node_id,
                                &send.data,
                            ) {
                                Ok((envelope, k)) => {
                                    ack_key = k; // C-09: bind the DELIVERED ACK to this message
                                    emit_e2e_plaintext_capture(
                                        capture_tx,
                                        local_node_id,
                                        &send.dst_node_id,
                                        &send.data,
                                    );
                                    let mut payload = vec![veil_proto::E2E_MARKER];
                                    payload.extend_from_slice(&envelope.encode());
                                    payload
                                }
                                Err(_) => {
                                    // Encryption error — abort rather than send plaintext.
                                    let mut hdr = FrameHeader::new(
                                        FrameFamily::LocalApp as u8,
                                        LocalAppMsg::AppSendFailed as u16,
                                    );
                                    hdr.body_len = 2;
                                    let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
                                    frame
                                        .extend_from_slice(&ipc_send_err::NO_E2E_KEY.to_be_bytes());
                                    return wh.write_all(&frame).await;
                                }
                            }
                        }
                    } else {
                        // No E2E key available — cannot send encrypted, abort.
                        let mut hdr = FrameHeader::new(
                            FrameFamily::LocalApp as u8,
                            LocalAppMsg::AppSendFailed as u16,
                        );
                        hdr.body_len = 2;
                        let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
                        frame.extend_from_slice(&ipc_send_err::NO_E2E_KEY.to_be_bytes());
                        return wh.write_all(&frame).await;
                    }
                } else {
                    // No E2E infrastructure — send plaintext. send.data is
                    // PooledShared; copy to Vec for the relay-send
                    // path which needs owned bytes for hashing + signing.
                    (*send.data).to_vec()
                };

                // ── Relay send (always happens when a hop is found) ──────────
                // content_id = BLAKE3(rand32 || sender_node_id || dst_node_id || payload)
                // Unique per message; used by relays for dedup/replay prevention.
                let content_id: [u8; 32] = {
                    use rand_core::RngCore;
                    let mut nonce = [0u8; 32];
                    rand_core::OsRng.fill_bytes(&mut nonce);
                    let mut h = blake3::Hasher::new();
                    h.update(&nonce);
                    h.update(local_node_id);
                    h.update(&send.dst_node_id);
                    h.update(&final_payload);
                    *h.finalize().as_bytes()
                };

                // optionally sample this frame for distributed tracing.
                let trace_id: u64 = {
                    use rand_core::RngCore;
                    let sample_rate = ctx.trace_sample_rate;
                    if sample_rate > 0.0 {
                        let u = rand_core::OsRng.next_u64() as f64 / u64::MAX as f64;
                        if u < sample_rate {
                            // Guarantee non-zero (non-zero = sampled).
                            let v = rand_core::OsRng.next_u64();
                            if v == 0 { 1 } else { v }
                        } else {
                            0
                        }
                    } else {
                        0
                    }
                };
                // For anonymous sends the real sender identity is hidden inside
                // the meta-E2E ciphertext; zero-out outer envelope fields so that
                // relays cannot learn who originated the message.
                let envelope = DeliveryEnvelope {
                    recipient: veil_proto::recipient::Recipient::any(send.dst_node_id),
                    sender_node_id: if send.anonymous {
                        [0u8; 32]
                    } else {
                        *local_node_id
                    },
                    src_app_id: if send.anonymous {
                        [0u8; 32]
                    } else {
                        send.src_app_id
                    },
                    app_id: if send.anonymous {
                        [0u8; 32]
                    } else {
                        send.app_id
                    },
                    endpoint_id: if send.anonymous { 0 } else { send.endpoint_id },
                    content_id,
                    created_at: now,
                    ttl_secs: 30,
                    payload: final_payload,
                    trace_id,
                    require_ack: send.require_ack,
                };
                // Oversized payload → relay-preserving chunking. Split the
                // (already-E2E) payload into ≤ MAX_CHUNK_PAYLOAD pieces, each
                // carried in its OWN relayable `DeliveryEnvelope` (same addressing
                // metadata, a unique per-chunk content_id, payload = the chunk
                // wrapper). Every chunk rides the proven Forward relay path; the
                // destination reassembles them into the original envelope before
                // E2E-decrypt + addressed delivery + ACK (dispatcher
                // `handle_chunk_envelope`). This replaces the old path that sent
                // raw Chunk frames to a dst we have no session with (always
                // NO_ROUTE on the relay path) and reassembled via a metadata-
                // losing epidemic broadcast.
                //
                // NOTE: sender-side ACK *retransmit* is not wired for chunked
                // messages (the pending-ack tracker is single-frame); the
                // destination still emits an end-to-end ACK on `orig_content_id`.
                if envelope.payload.len() > veil_proto::delivery::MAX_ENVELOPE_PAYLOAD {
                    use veil_proto::budget::{MAX_CHUNK_PAYLOAD, MAX_REASSEMBLY_BYTES};
                    use veil_proto::delivery::{ChunkedEnvelopePayload, DeliveryEnvelope};
                    use veil_proto::family::DeliveryMsg;

                    let total_size = envelope.payload.len();
                    // Bounded by the receiver's reassembly cap — refuse early.
                    if total_size > MAX_REASSEMBLY_BYTES {
                        let mut hdr = FrameHeader::new(
                            FrameFamily::LocalApp as u8,
                            LocalAppMsg::AppSendFailed as u16,
                        );
                        hdr.body_len = 2;
                        let mut frame = codec::encode_header(&hdr).to_vec();
                        frame.extend_from_slice(&ipc_send_err::NO_ROUTE.to_be_bytes());
                        return wh.write_all(&frame).await;
                    }

                    let pieces: Vec<Vec<u8>> = envelope
                        .payload
                        .chunks(MAX_CHUNK_PAYLOAD)
                        .map(|c| c.to_vec())
                        .collect();
                    let chunk_count = pieces.len() as u32;
                    let mut transfer_id = [0u8; 16];
                    {
                        use rand_core::RngCore;
                        rand_core::OsRng.fill_bytes(&mut transfer_id);
                    }
                    let orig_content_id = envelope.content_id;
                    let want_ack = send.require_ack;
                    let trace_bytes = trace_id.to_be_bytes();

                    // Candidate relay hops: primary then cached alternatives.
                    let hops_to_try: Vec<[u8; 32]> = {
                        let mut v = vec![hop];
                        if let Some(cache) = route_cache {
                            for alt in rlock!(cache).lookup_all(&send.dst_node_id) {
                                if alt != hop {
                                    v.push(alt);
                                }
                            }
                        }
                        v
                    };

                    // Build one relayable chunk-envelope Forward frame for `next_hop`.
                    let make_chunk_frame =
                        |next_hop: [u8; 32], index: u32, data: &[u8]| -> Vec<u8> {
                            let mut cid = [0u8; 32];
                            {
                                use rand_core::RngCore;
                                rand_core::OsRng.fill_bytes(&mut cid);
                            }
                            let chunk_env = DeliveryEnvelope {
                                recipient: envelope.recipient,
                                sender_node_id: envelope.sender_node_id,
                                src_app_id: envelope.src_app_id,
                                app_id: envelope.app_id,
                                endpoint_id: envelope.endpoint_id,
                                content_id: cid,
                                created_at: envelope.created_at,
                                ttl_secs: envelope.ttl_secs,
                                payload: ChunkedEnvelopePayload {
                                    transfer_id,
                                    chunk_index: index,
                                    chunk_count,
                                    total_size: total_size as u32,
                                    orig_content_id,
                                    require_ack: want_ack,
                                    data: data.to_vec(),
                                }
                                .encode(),
                                trace_id,
                                require_ack: false,
                            };
                            let env_bytes = chunk_env.encode();
                            let body_len = 32 + env_bytes.len() + 8 + 1;
                            let mut hdr = FrameHeader::new(
                                FrameFamily::Delivery as u8,
                                DeliveryMsg::Forward as u16,
                            );
                            hdr.body_len = body_len as u32;
                            let mut frame = codec::encode_header(&hdr).to_vec();
                            frame.extend_from_slice(&next_hop);
                            frame.extend_from_slice(&env_bytes);
                            frame.extend_from_slice(&trace_bytes);
                            frame.push(0u8); // relay_hops = 0 at origin
                            frame
                        };

                    // Stream every chunk to the first hop that accepts them all.
                    // (Reassembly is index-deduped, so the partial chunks left on
                    // a hop that dies mid-stream are harmless on retry.)
                    let mut delivered = false;
                    for next_hop in &hops_to_try {
                        let mut all_ok = true;
                        for (i, piece) in pieces.iter().enumerate() {
                            let frame = make_chunk_frame(*next_hop, i as u32, piece);
                            if !reg.send_to(
                                next_hop,
                                veil_proto::header::priority::INTERACTIVE,
                                frame,
                            ) {
                                all_ok = false;
                                break;
                            }
                        }
                        if all_ok {
                            delivered = true;
                            break;
                        }
                        if let Some(cache) = route_cache {
                            wlock!(cache).invalidate_hop(&send.dst_node_id, next_hop);
                        }
                    }

                    if delivered {
                        if want_ack {
                            let ok_hdr = FrameHeader::new(
                                FrameFamily::LocalApp as u8,
                                LocalAppMsg::AppSendOk as u16,
                            );
                            return wh.write_all(&codec::encode_header(&ok_hdr)).await;
                        }
                        return Ok(());
                    }
                    if let Some(cache) = route_cache {
                        wlock!(cache).invalidate(&send.dst_node_id);
                    }
                    let mut hdr = FrameHeader::new(
                        FrameFamily::LocalApp as u8,
                        LocalAppMsg::AppSendFailed as u16,
                    );
                    hdr.body_len = 2;
                    let mut frame = codec::encode_header(&hdr).to_vec();
                    frame.extend_from_slice(&ipc_send_err::NO_ROUTE.to_be_bytes());
                    return wh.write_all(&frame).await;
                }

                // Pre-encode the envelope once; reused for all hop attempts.
                let env_bytes = envelope.encode();
                let trace_bytes = trace_id.to_be_bytes();
                // ForwardPayload wire layout: next_hop || envelope || trace_id || relay_hops.
                // TransitFrame is used relay-to-relay when both peers negotiate
                // transit_relay capability; the IPC originator uses ForwardPayload for now.
                let make_fwd_frame = |next_hop: [u8; 32]| -> Vec<u8> {
                    let body_len = 32 + env_bytes.len() + 8 + 1;
                    let mut hdr = FrameHeader::new(
                        veil_proto::family::FrameFamily::Delivery as u8,
                        DeliveryMsg::Forward as u16,
                    );
                    hdr.body_len = body_len as u32;
                    let mut frame = codec::encode_header(&hdr).to_vec();
                    frame.extend_from_slice(&next_hop);
                    frame.extend_from_slice(&env_bytes);
                    frame.extend_from_slice(&trace_bytes);
                    frame.push(0u8); // relay_hops = 0 at origin
                    frame
                };

                // Try primary hop first; on failure fall back to cached alternatives.
                let hops_to_try: Vec<[u8; 32]> = {
                    let mut v = vec![hop];
                    if let Some(cache) = route_cache {
                        for alt in rlock!(cache).lookup_all(&send.dst_node_id) {
                            if alt != hop {
                                v.push(alt);
                            }
                        }
                    }
                    v
                };
                let mut any_send_failed = false;
                for next_hop in hops_to_try {
                    let fwd_frame = make_fwd_frame(next_hop);
                    let relayed = reg.send_to(
                        &next_hop,
                        veil_proto::header::priority::INTERACTIVE,
                        fwd_frame.clone(),
                    );
                    if relayed {
                        // register for ACK tracking if requested.
                        // Pass `next_hop` (the direct relay peer) so that
                        // retransmits use the same session path, not the final
                        // dst which may not be directly connected (B2 fix).
                        if send.require_ack
                            && let Some(tracker) = ctx.pending_ack
                        {
                            let _ = lock!(tracker).register(
                                content_id,
                                next_hop,
                                send.dst_node_id,
                                send.src_app_id,
                                ack_key,
                                fwd_frame,
                            );
                        }
                        if send.require_ack {
                            let ok_hdr = FrameHeader::new(
                                FrameFamily::LocalApp as u8,
                                LocalAppMsg::AppSendOk as u16,
                            );
                            return wh.write_all(&codec::encode_header(&ok_hdr)).await;
                        }
                        return Ok(());
                    }
                    // send_to returned false: session is closed or full.
                    // Evict this dead hop from the cache so future lookups
                    // don't return the same unreachable next-hop (254.3).
                    if let Some(cache) = route_cache {
                        wlock!(cache).invalidate_hop(&send.dst_node_id, &next_hop);
                    }
                    any_send_failed = true;
                }
                // All cached hops were dead. Flush the entire dst bucket so
                // that the next try_lookup_or_discover call finds nothing and
                // fires a fresh ROUTE_REQUEST instead of looping over stale
                // entries (254.4).
                if any_send_failed && let Some(cache) = route_cache {
                    wlock!(cache).invalidate(&send.dst_node_id);
                }
            }

            // No route found — return NO_ROUTE error.
            let err_code = ipc_send_err::NO_ROUTE.to_be_bytes();
            let mut hdr = FrameHeader::new(
                FrameFamily::LocalApp as u8,
                LocalAppMsg::AppSendFailed as u16,
            );
            hdr.body_len = 2;
            let mut err_frame = codec::encode_header(&hdr).to_vec();
            err_frame.extend_from_slice(&err_code);
            return wh.write_all(&err_frame).await;
        }
    }

    // APP_SEND_OK — fire-and-forget clients (e.g. ogate) skip the ack.
    // Phase E24 (2026-05-22): writing AppSendOk per APP_SEND added a full
    // IPC frame syscall round-trip per IP packet on the hot path —
    // single-stream throughput cap measured ~150 Mbps (12K pps) before
    // and after this fix.  Honoring `require_ack=false` halves the IPC
    // syscall count per send and frees enough budget to push pps higher.
    if send.require_ack {
        let ok_hdr = FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppSendOk as u16);
        wh.write_all(&codec::encode_header(&ok_hdr)).await
    } else {
        Ok(())
    }
}

// ── APP_RT_SEND handler ──────────────────────────────────────────────────────

/// Handle an `APP_RT_SEND` request from an IPC client.
///
/// Decodes the `AppIpcRtSendPayload`, wraps it in an `AppMsg::AppRtData` wire
/// frame, and dispatches it at `REALTIME` priority via the session registry.
/// On success the metric counter is incremented and `APP_SEND_OK` is written
/// back to the client. If no session to the destination exists, `APP_SEND_FAILED`
/// with error code [`ipc_send_err::NO_SESSION`] is returned.
pub(crate) async fn handle_rt_send(
    wh: &mut crate::transport::IpcWriteHalf,
    body: &[u8],
    session_tx_registry: Option<&dyn FrameBroadcaster>,
    metrics: Option<&dyn IpcMetrics>,
    rate_limiter: &mut Option<TokenBucket>,
) -> std::io::Result<()> {
    // Rate check — shared bucket with APP_SEND to prevent RT flooding.
    if rate_limited(wh, rate_limiter).await? {
        return Ok(());
    }

    let send = match AppIpcRtSendPayload::decode(body) {
        Ok(s) => s,
        Err(_) => return Ok(()), // drop malformed — no response
    };

    let reg = match session_tx_registry {
        Some(r) => r,
        None => {
            // No session registry configured — node is in offline/test mode.
            let err_code = ipc_send_err::NO_SESSION.to_be_bytes();
            let mut hdr = FrameHeader::new(
                FrameFamily::LocalApp as u8,
                LocalAppMsg::AppSendFailed as u16,
            );
            hdr.body_len = 2;
            let mut frame = codec::encode_header(&hdr).to_vec();
            frame.extend_from_slice(&err_code);
            return wh.write_all(&frame).await;
        }
    };

    let rt_payload = AppRtDataPayload {
        app_id: send.dst_app_id,
        endpoint_id: send.endpoint_id,
        seq: send.seq,
        timestamp_us: send.timestamp_us,
        marker: send.marker,
        payload_type: send.payload_type,
        payload: send.data,
    };
    let payload_bytes = rt_payload.encode();
    let mut hdr = FrameHeader::new(
        veil_proto::family::FrameFamily::App as u8,
        veil_proto::family::AppMsg::AppRtData as u16,
    );
    hdr.body_len = payload_bytes.len() as u32;
    let mut frame = codec::encode_header(&hdr).to_vec();
    frame.extend_from_slice(&payload_bytes);

    let sent = reg.send_to(
        &send.dst_node_id,
        veil_proto::header::priority::REALTIME,
        frame,
    );

    if sent {
        if let Some(m) = metrics {
            m.inc_rt_frames_tx();
        }
        let ok_hdr = FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppSendOk as u16);
        wh.write_all(&codec::encode_header(&ok_hdr)).await
    } else {
        let err_code = ipc_send_err::NO_SESSION.to_be_bytes();
        let mut err_hdr = FrameHeader::new(
            FrameFamily::LocalApp as u8,
            LocalAppMsg::AppSendFailed as u16,
        );
        err_hdr.body_len = 2;
        let mut err_frame = codec::encode_header(&err_hdr).to_vec();
        err_frame.extend_from_slice(&err_code);
        wh.write_all(&err_frame).await
    }
}

// ── E2E plaintext capture helper ────────────────────────────────────────────

/// Emit a capture event carrying the **plaintext** application payload that is
/// about to be E2E-encrypted. The event is marked with `e2e_plaintext = true`
/// so the CLI can show it as a separate "pre-encryption" record alongside the
/// encrypted `DELIVERY_FORWARD` frame that the session runner will also capture.
///
/// No-op when `capture_tx` is `None` or has no active subscribers.
fn emit_e2e_plaintext_capture(
    capture_tx: Option<
        &Mutex<Option<tokio::sync::broadcast::Sender<veil_dispatcher_state::CaptureEvent>>>,
    >,
    src_id: &[u8; 32],
    dst_id: &[u8; 32],
    plaintext: &[u8],
) {
    let Some(slot) = capture_tx else { return };
    let guard = slot.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(ref tx) = *guard {
        let ts_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        // e2e plaintext capture also gets the
        // 256 B truncation. The IPC site doesn't go through the
        // dispatcher rate limiter (this is a pre-encryption preview
        // emitted once per delivery — not per-frame), so per-peer
        // rate limit is unnecessary here.
        let ev = veil_dispatcher_state::CaptureEvent::new_truncated(
            ts_us,
            false, // outbound from this node's POV
            *dst_id,
            *src_id,
            veil_proto::family::FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
            plaintext.len() as u32,
            plaintext,
            true, // e2e_plaintext
        );
        let _ = tx.send(ev);
    }
}
