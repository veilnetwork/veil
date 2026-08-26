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

use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;

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

/// Return live first-hop candidates for an explicitly relay-only send.
///
/// A realtime relay fallback must never silently collapse back to the final
/// peer's direct session.  Cached multi-hop routes are preferred; when route
/// discovery has only learned the direct peer (or has not populated the cache
/// yet), any other live overlay session is already a valid first relay hop.
/// This avoids putting the 500 ms reactive-discovery wait on every RTP packet.
fn relay_hops_to_try(
    dst: &[u8; 32],
    route_cache: Option<&RwLock<veil_routing::RouteCache>>,
    session_tx_registry: &dyn FrameBroadcaster,
) -> Vec<[u8; 32]> {
    let mut hops = Vec::new();

    if let Some(cache) = route_cache {
        for hop in rlock!(cache).lookup_all(dst) {
            if &hop != dst && !hops.contains(&hop) {
                hops.push(hop);
            }
        }
    }

    // Prefer peers closest to the destination in XOR space, matching the
    // recursive routing start policy.  Cached routes above remain first.
    let mut active = session_tx_registry.active_node_ids();
    active.sort_by_key(|peer| {
        let mut xor = [0u8; 32];
        for i in 0..32 {
            xor[i] = peer[i] ^ dst[i];
        }
        xor
    });
    for peer in active {
        if &peer != dst && !hops.contains(&peer) {
            hops.push(peer);
        }
    }

    hops
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
/// Where an app send's reply frame goes.
///
/// A send answers only when something went wrong, and it used to write that
/// straight to the socket — which meant it had to run inside the IPC read
/// loop, holding it for the length of a DHT key resolve (measured: 3.5 s) and
/// expiring every unrelated request queued behind it. Off the loop there is no
/// exclusive writer to hand out, so the frame goes to the same reply channel
/// the other seconds-class handlers already use.
pub(crate) enum SendReply<'a> {
    /// Straight to the socket — the caller owns the write half. The tests drive
    /// the handler this way so they can read the reply frame back without a
    /// loop to run; no production path constructs it, which is the point of the
    /// change above.
    #[allow(dead_code)]
    Inline(&'a mut crate::transport::IpcWriteHalf),
    /// Handed to the loop's writer. Owned, so the send can outlive the frame
    /// that started it.
    Offloop(mpsc::Sender<crate::server::LoopReply>),
}

impl SendReply<'_> {
    pub(crate) async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            SendReply::Inline(wh) => wh.write_all(bytes).await,
            SendReply::Offloop(tx) => {
                // A closed channel means the client is gone; its error frame
                // has nowhere to go and nothing is owed to it.
                let _ = tx
                    .send(crate::server::LoopReply::Frame(bytes.to_vec()))
                    .await;
                Ok(())
            }
        }
    }
}

pub(crate) async fn rate_limited(
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
/// Everything one app send needs, OWNED.
///
/// Borrowed before, which forced the send to run inside the IPC read loop —
/// and that loop serves one client strictly in order. A send waits on a key
/// resolve that walks the DHT, measured at 3.5 s, so every later request on
/// that connection waited with it: `node_identity` and `pnet_status` expired,
/// and the host's ratchet sat DEGRADED because its flush could not read the
/// node identity. Owning the context is what lets the send leave the loop.
///
/// Every field was ALREADY an `Arc` where the server keeps it, so this costs
/// a refcount bump per send, not a copy of anything.
pub(crate) struct IpcSendContext {
    pub(crate) app_registry: Arc<AppEndpointRegistry>,
    pub(crate) local_node_id: [u8; 32],
    pub(crate) session_tx_registry: Option<Arc<dyn FrameBroadcaster>>,
    pub(crate) route_cache: Option<Arc<RwLock<veil_routing::RouteCache>>>,
    pub(crate) route_updated: Option<Arc<tokio::sync::Notify>>,
    pub(crate) peer_mlkem_keys: Option<Arc<std::sync::RwLock<veil_e2e::PeerMlKemCache>>>,
    /// Epic 486.1 slice 3: cold-start ML-KEM EK resolver.  When the cache
    /// lookup misses in the relay-encrypted path, the handler invokes this
    /// resolver to fetch + verify + cache the recipient's EK from the DHT.
    /// `None` preserves legacy behaviour exactly (test fixtures + setups
    /// without full NodeRuntime).
    pub(crate) mlkem_ek_resolver: Option<Arc<dyn veil_types::MlKemEkResolver>>,
    /// Authenticated anonymous (onion/rendezvous) sender. `Some` only when the
    /// full NodeRuntime is wired; the `anonymous_authenticated` flag fails with
    /// `NO_RENDEZVOUS` when this is `None` (test fixtures / minimal setups).
    pub(crate) anon_onion_sender: Option<Arc<dyn veil_types::AnonOnionSender>>,
    pub(crate) capture_tx: Option<
        Arc<Mutex<Option<tokio::sync::broadcast::Sender<veil_dispatcher_state::CaptureEvent>>>>,
    >,
    pub(crate) pending_recursive: Option<veil_dispatcher_state::PendingRecursiveMap>,
    /// Trace sampling rate.
    pub(crate) trace_sample_rate: f64,
    /// Pending-ACK tracker.
    pub(crate) pending_ack: Option<Arc<Mutex<veil_pending_ack::PendingAckTracker>>>,
    /// One-to-one ratchet conversations, shared with the frame dispatcher.
    ///
    /// `None` on a node with no sovereign device identity (a supported
    /// configuration) and in fixtures without a full runtime; both keep the
    /// pre-existing ML-KEM behaviour exactly.
    pub(crate) ratchet: Option<veil_e2e::RatchetRuntime>,
    /// Which DEVICE is at the far end of the live session to a peer identity
    /// (defect №35). `None` (tests / minimal setups) keeps the singular,
    /// identity-addressed cert resolve exactly.
    pub(crate) session_instance_lookup: Option<Arc<dyn veil_types::SessionInstanceLookup>>,
}

/// Seal `data` through the ratchet, if everything it needs is in hand.
///
/// Returns the payload and its per-message delivery-ACK key, or `None` when
/// this node has no device identity, no resolver, or the recipient publishes no
/// certificate that verifies. `None` is not a downgrade of anything the ratchet
/// was doing — it is the message taking the path it took before this existed,
/// which is still an ML-KEM seal to a published key. What the recipient loses
/// is the sender proof, and it loses it visibly: the message arrives as
/// `Claimed` rather than `Signed`.
///
/// Failing closed instead was considered and rejected: a node may legitimately
/// run with no sovereign identity, and a recipient may legitimately have no
/// certificate published yet, and refusing to talk to either would break
/// first contact for exactly the people who need it.
async fn try_ratchet_seal(
    ctx: &IpcSendContext,
    dst_node_id: &[u8; 32],
    data: &[u8],
) -> Option<(Vec<u8>, [u8; 32])> {
    let ratchet = ctx.ratchet.as_ref()?;
    // Cheap gate before anything expensive: no device identity, no ratchet.
    ratchet.identity()?;
    let resolver = ctx.mlkem_ek_resolver.as_deref()?;

    // Which device of the recipient's family? Before defect №35 two answers
    // to that question were given independently: the cert below by the
    // resolver's `max_by_key(last_seen_unix_ms)` over registry rows that all
    // publish 0 — i.e. by whichever row the iterator happened to end on,
    // cached for 30 minutes — and the transport by the one live session to
    // the identity, terminating at whichever device rendezvous happened to
    // resolve. In a five-device family they disagree 4/5 of the time; the
    // receiving device refuses the frame (`NotForThisDevice`), the sender is
    // never told, and it re-sends its prologue every ~9 s forever. The
    // session's validated identity proof names the device it actually ends
    // at, so when the send is session-backed that instance — not the cache's
    // tie accident — is the authoritative pairing.
    let session_instance = ctx
        .session_instance_lookup
        .as_deref()
        .and_then(|lookup| lookup.session_instance(dst_node_id));
    let paired = match session_instance {
        Some(instance) => match resolver.resolve_cert_for_instance_cached(*dst_node_id, instance) {
            Some(c) => Some(c),
            None => {
                resolver
                    .resolve_cert_for_instance(*dst_node_id, instance)
                    .await
            }
        },
        // No live session, or a legacy handshake that proved no instance:
        // nothing named a device, so the singular resolve below stays the
        // answer — which is today's behaviour, and exact for the
        // single-instance peer.
        None => None,
    };

    // Local records first. The full walk is three DHT rounds and this is the
    // ordinary send path; the 30-minute verified-cert cache above it means a
    // peer costs that walk once, not once per message.
    //
    // Also the fallback when the SESSION named a device but its cert did not
    // resolve — fail-open to the singular row rather than refusing to seal:
    // a wrong-device seal now earns an `AppSendUnopenable` reply that drops
    // the cached row and re-keys, where an unsealed message would silently
    // lose its sender proof.
    let cert = match paired {
        Some(c) => c,
        None => match resolver.resolve_cert_cached(*dst_node_id) {
            Some(c) => c,
            None => resolver.resolve_cert(*dst_node_id).await?,
        },
    };

    match ratchet.seal_for(
        veil_e2e::PeerRatchetKeys {
            node_id: &cert.node_id,
            instance_id: &cert.instance_id,
            mlkem_ek: &cert.mlkem_ek,
            ratchet_pk: &cert.ratchet_x25519_pk,
        },
        data,
        veil_util::unix_secs_now_u64(),
    ) {
        Ok(sealed) => Some(sealed),
        Err(e) => {
            log::debug!(
                "ratchet.seal_failed dst={} {e}",
                veil_util::bytes_to_hex(&dst_node_id[..4])
            );
            None
        }
    }
}

pub(crate) async fn handle_ipc_send(
    sink: &mut SendReply<'_>,
    body: &[u8],
    ctx: &IpcSendContext,
) -> std::io::Result<()> {
    // Borrowed out of the now-owned context so the body below reads exactly as
    // it did when the context itself was borrowed.
    let app_registry = &*ctx.app_registry;
    let local_node_id = &ctx.local_node_id;
    let session_tx_registry = ctx.session_tx_registry.as_deref();
    let route_cache = ctx.route_cache.as_deref();
    let route_updated = ctx.route_updated.as_deref();
    let peer_mlkem_keys = ctx.peer_mlkem_keys.as_deref();
    let capture_tx = ctx.capture_tx.as_deref();

    // This additive flag is intentionally read from the stable raw flags word:
    // AppIpcSendPayload ignores unknown bits, so old clients/servers remain
    // compatible without growing its public struct and every literal user.
    let raw_flags = body
        .get(100..104)
        .and_then(|v| <[u8; 4]>::try_from(v).ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0);
    let relay_wire_realtime = raw_flags & veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME != 0;
    let relay_control_compat = raw_flags & veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT != 0;
    let relay_realtime = relay_wire_realtime || relay_control_compat;
    let relay_media_sealed = raw_flags & veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED != 0;
    let send = match AppIpcSendPayload::decode(body) {
        Ok(s) => s,
        Err(_) => return Ok(()), // drop malformed
    };

    // PRESEALED is deliberately a narrow call-media optimization, not a
    // general "skip E2E" switch. Requiring the realtime relay flag, no ACK,
    // and a versioned ciphertext marker makes malformed/miscombined local IPC
    // fail closed before routing. An old daemon ignores the additive flag and
    // safely adds its ordinary ML-KEM envelope instead.
    if relay_media_sealed
        && (!relay_wire_realtime
            || send.require_ack
            || !send
                .data
                .starts_with(&veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC))
    {
        return Ok(());
    }

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
        sink.write_all(&frame).await?;
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
        } else if let Some(sender) = ctx.anon_onion_sender.as_deref() {
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
                sink.write_all(&frame).await?;
            }
            None if send.require_ack => {
                let ok_hdr =
                    FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppSendOk as u16);
                sink.write_all(&codec::encode_header(&ok_hdr)).await?;
            }
            None => {}
        }
        return Ok(());
    }

    // ── Ratchet, once, for whichever path this message ends up taking ────────
    //
    // Sealed here rather than inside each branch because the direct-session
    // send is tried first and falls through to the relay path when there is no
    // live session. Sealing in both places would advance the chain twice for
    // one message: harmless (the skipped key is cached) but it would mean the
    // recipient banking a key nothing will ever arrive for, on every fallback.
    //
    // Excluded, and each for its own reason:
    //
    // * `anonymous` — the meta-E2E path is the ANONYMOUS one, and it is
    //   supposed to work. A ratchet is a named two-party object; running one
    //   would put both device identities in front of the recipient and destroy
    //   the property the path exists for.
    // * `relay_realtime` / `relay_control_compat` — call media and call
    //   signalling, which are already sealed under their own per-call keys and
    //   cannot afford a certificate resolve on the packet path.
    // * `relay_media_sealed` — already authenticated and encrypted end to end
    //   by the media codec; the whole point of that flag is to pass the cell
    //   through untouched.
    let ratchet_ok = !send.anonymous && !relay_realtime && !relay_media_sealed;
    let sealed = if ratchet_ok && send.dst_node_id != *local_node_id {
        try_ratchet_seal(ctx, &send.dst_node_id, &send.data).await
    } else {
        None
    };

    if send.dst_node_id == *local_node_id && !send.my_other_devices {
        // Local delivery — route directly through the app registry. The
        // message never left this node: it came in over the local IPC socket
        // and `src_node_id` is our own id.
        //
        // NOT taken for a device sync. Every device of an identity answers to
        // this same id, so the address alone cannot say whether "me" means
        // this process or the rest of my devices. Taken blindly it swallowed
        // the frame: the outbox saw a delivery, acknowledged it, and the
        // mailbox copy -- the only path that reaches a sibling -- was never
        // deposited. Measured on a two-device stand as a deposit that stayed
        // deferred forever.
        app_registry.route_ipc_deliver(
            *local_node_id,
            veil_app::registry::SenderProvenance::LocalIpc,
            send.src_app_id,
            send.app_id,
            send.endpoint_id,
            send.data,
        );
    } else if let Some(reg) = session_tx_registry {
        // Remote delivery — encode an OVL1 APP_SEND frame and push it to
        // the outbox of the session that leads to dst_node_id.
        //
        // With a ratchet payload this becomes an APP_SEND_SEALED, a distinct
        // frame type rather than the same one carrying different bytes. It has
        // to be: `data` is whatever the application put there, so no marker
        // byte inside it could be reserved without stealing a byte some app
        // legitimately sends.
        //
        // Before this, a message to an online peer left the node with NO
        // end-to-end sealing whatsoever — the session's hop cipher was the
        // whole of its confidentiality, and it stopped at the far end of that
        // one link. The relay path was E2E-sealed and this one was not, which
        // is the opposite of where the traffic is.
        let app_msg_type = match &sealed {
            Some(_) => veil_proto::family::AppMsg::AppSendSealed,
            None => veil_proto::family::AppMsg::AppSend,
        };
        let ovl1_payload = AppSendPayload {
            src_app_id: send.src_app_id,
            app_id: send.app_id,
            endpoint_id: send.endpoint_id,
            data: match &sealed {
                Some((payload, _)) => veil_bufpool::pooled_shared_from_vec(payload.clone()),
                None => send.data.clone(),
            },
        };
        let payload_bytes = ovl1_payload.encode();
        // before fragmenting large payloads, the session's
        // `negotiated_caps.chunking` flag must be checked. When chunking is not
        // negotiated, payloads exceeding the single-frame limit must be rejected
        // with an error rather than silently truncated or forwarded oversized.
        // This guard will be enforced here once introduces fragmentation.
        let mut hdr = FrameHeader::new(
            veil_proto::family::FrameFamily::App as u8,
            app_msg_type as u16,
        );
        hdr.body_len = payload_bytes.len() as u32;
        let mut frame = codec::encode_header(&hdr).to_vec();
        frame.extend_from_slice(&payload_bytes);

        let sent = !relay_realtime
            && reg.send_to(
                &send.dst_node_id,
                veil_proto::header::priority::INTERACTIVE,
                frame,
            );
        if sent && sealed.is_some() {
            emit_e2e_plaintext_capture(capture_tx, local_node_id, &send.dst_node_id, &send.data);
        }

        if !sent {
            // No direct session. Try relay via RouteCache next-hop.
            // If the cache is empty, attempt reactive route discovery:
            // flood a ROUTE_REQUEST and wait up to 500 ms for a response.
            let forced_relay_hops = if relay_realtime {
                relay_hops_to_try(&send.dst_node_id, route_cache, reg)
            } else {
                Vec::new()
            };
            let hop = if relay_realtime {
                forced_relay_hops.first().copied()
            } else {
                try_lookup_or_discover(
                    &send.dst_node_id,
                    local_node_id,
                    route_cache,
                    session_tx_registry,
                    route_updated,
                    peer_mlkem_keys,
                    ctx.pending_recursive.as_deref(),
                )
                .await
            };

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
                let final_payload = if let Some((payload, key)) = sealed {
                    // Already sealed above, marker byte and all, so nothing is
                    // prepended here. The ACK key came out of the same seal:
                    // it is 32 random bytes carried INSIDE the ciphertext
                    // rather than derived from a key-encapsulation secret, so
                    // it survives a later compromise of our decapsulation seed
                    // and a relay still cannot forge a DELIVERED with it.
                    ack_key = key;
                    emit_e2e_plaintext_capture(
                        capture_tx,
                        local_node_id,
                        &send.dst_node_id,
                        &send.data,
                    );
                    payload
                } else if relay_media_sealed {
                    // The call-media codec already authenticated and encrypted
                    // this payload under a per-call directional key delivered
                    // inside the normal ML-KEM-protected call signaling.
                    // Preserve the compact cell verbatim so a single RTP
                    // packet can fit one hop-level QUIC DATAGRAM.
                    (*send.data).to_vec()
                } else if let Some(keys) = peer_mlkem_keys {
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
                        && let Some(resolver) = ctx.mlkem_ek_resolver.as_deref()
                    {
                        // Call control cannot sit behind the resolver's three
                        // multi-replica DHT freshness rounds (up to 9 s after
                        // every node restart). Its compatibility relay copy is
                        // best-effort and deduplicated, so a locally stored,
                        // signature-verified, unexpired cert is safe: if it is
                        // stale after key rotation this copy merely fails to
                        // decrypt, while the parallel ordinary/durable lane
                        // performs the full fresh resolve and retries.
                        recipient_ek = if relay_control_compat {
                            resolver.resolve_ek_cached(send.dst_node_id)
                        } else {
                            resolver.resolve_ek(send.dst_node_id).await
                        };
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
                                    return sink.write_all(&frame).await;
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
                                    return sink.write_all(&frame).await;
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
                        return sink.write_all(&frame).await;
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
                    ttl_secs: if relay_realtime {
                        veil_proto::delivery::FORWARD_REALTIME_TTL_SECS
                    } else {
                        30
                    },
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
                if envelope.payload.len() > veil_proto::delivery::ENVELOPE_CHUNKING_THRESHOLD {
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
                        return sink.write_all(&frame).await;
                    }

                    let chunk_count = total_size.div_ceil(MAX_CHUNK_PAYLOAD) as u32;
                    let mut transfer_id = [0u8; 16];
                    {
                        use rand_core::RngCore;
                        rand_core::OsRng.fill_bytes(&mut transfer_id);
                    }
                    let orig_content_id = envelope.content_id;
                    let want_ack = send.require_ack;
                    let trace_bytes = trace_id.to_be_bytes();

                    // Candidate relay hops: primary then cached alternatives.
                    let hops_to_try: Vec<[u8; 32]> = if relay_realtime {
                        forced_relay_hops.clone()
                    } else {
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
                        let frames: Vec<Vec<u8>> = envelope
                            .payload
                            .chunks(MAX_CHUNK_PAYLOAD)
                            .enumerate()
                            .map(|(i, piece)| make_chunk_frame(*next_hop, i as u32, piece))
                            .collect();
                        let all_ok = frames.iter().all(|frame| {
                            reg.send_to(
                                next_hop,
                                veil_proto::header::priority::INTERACTIVE,
                                frame.clone(),
                            )
                        });
                        if all_ok {
                            delivered = true;
                            if want_ack && let Some(tracker) = ctx.pending_ack.as_deref() {
                                let _ = lock!(tracker).register_batch(
                                    orig_content_id,
                                    *next_hop,
                                    send.dst_node_id,
                                    send.src_app_id,
                                    ack_key,
                                    frames,
                                );
                            }
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
                            return sink.write_all(&codec::encode_header(&ok_hdr)).await;
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
                    return sink.write_all(&frame).await;
                }

                // Pre-encode the envelope once; reused for all hop attempts.
                let env_bytes = envelope.encode();
                let trace_bytes = trace_id.to_be_bytes();
                // ForwardPayload wire layout: next_hop || envelope || trace_id || relay_hops.
                // TransitFrame is used relay-to-relay when both peers negotiate
                // transit_relay capability; the IPC originator uses ForwardPayload for now.
                let make_fwd_frame = |next_hop: [u8; 32]| -> Vec<u8> {
                    let attempt_suffix_len = if send.require_ack { 2 } else { 0 };
                    // Real-time media stamps its class so every relay on the
                    // path re-queues it in the REALTIME lane instead of
                    // behind bulk delivery chatter (legacy relays ignore the
                    // optional tail and forward unchanged).
                    let class_suffix_len = if relay_wire_realtime { 2 } else { 0 };
                    let body_len =
                        32 + env_bytes.len() + 8 + 1 + attempt_suffix_len + class_suffix_len;
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
                    if send.require_ack {
                        frame.push(veil_proto::delivery::FORWARD_DELIVERY_ATTEMPT_MARKER);
                        frame.push(1); // initial delivery attempt
                    }
                    if relay_wire_realtime {
                        frame.push(veil_proto::delivery::FORWARD_TRAFFIC_CLASS_MARKER);
                        frame.push(veil_proto::header::priority::REALTIME);
                    }
                    frame
                };

                // Try primary hop first; on failure fall back to cached alternatives.
                let hops_to_try: Vec<[u8; 32]> = if relay_realtime {
                    forced_relay_hops.clone()
                } else {
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
                let mut any_compat_sent = false;
                for (compat_attempts, next_hop) in hops_to_try.into_iter().enumerate() {
                    if relay_control_compat && compat_attempts >= 3 {
                        break;
                    }
                    let fwd_frame = make_fwd_frame(next_hop);
                    let relayed = reg.send_to(
                        &next_hop,
                        if relay_realtime {
                            veil_proto::header::priority::REALTIME
                        } else {
                            veil_proto::header::priority::INTERACTIVE
                        },
                        fwd_frame.clone(),
                    );
                    if relayed {
                        // Call lifecycle frames are tiny and rare. Fan them to
                        // up to three independently-operated legacy relays so
                        // one stale route/overloaded operator cannot add a
                        // whole retry interval. Stable content_id dedup at the
                        // recipient makes the copies harmless. ACK-mode keeps
                        // its existing single-hop tracker semantics.
                        if relay_control_compat && !send.require_ack {
                            any_compat_sent = true;
                            continue;
                        }
                        // register for ACK tracking if requested.
                        // Pass `next_hop` (the direct relay peer) so that
                        // retransmits use the same session path, not the final
                        // dst which may not be directly connected (B2 fix).
                        if send.require_ack
                            && let Some(tracker) = ctx.pending_ack.as_deref()
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
                            return sink.write_all(&codec::encode_header(&ok_hdr)).await;
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
                if any_compat_sent {
                    return Ok(());
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
            return sink.write_all(&err_frame).await;
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
        sink.write_all(&codec::encode_header(&ok_hdr)).await
    } else {
        Ok(())
    }
}

// ── APP_RT_SEND handler ──────────────────────────────────────────────────────

/// Handle an `APP_RT_SEND` request from an IPC client.
///
/// Decodes the `AppIpcRtSendPayload`, wraps it in an `AppMsg::AppRtData` wire
/// frame, and dispatches it at `REALTIME` priority via the session registry.
/// Success is deliberately fire-and-forget: the client-side API has no reply
/// waiter and an `APP_SEND_OK` per RTP packet only creates reverse IPC traffic
/// and reader work. If no session to the destination exists,
/// `APP_SEND_FAILED` with error code [`ipc_send_err::NO_SESSION`] is returned.
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
        src_app_id: send.src_app_id,
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
        Ok(())
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

// ── Slow onion-send status jobs (request-id concurrency) ──────────────────────
//
// The slow halves of the standalone onion-send arcs: only the `Arc` sender is
// touched, so the connection loop can spawn them off-loop when the request
// carries a non-zero `request_id`. Sync validation (rate limit, decode,
// `src_app_id` ownership against per-connection state) stays inline with the
// caller, BEFORE the spawn.

/// `SendToOnionService` after validation: resolve + send, return the wire
/// status (0 = ok).
pub(crate) async fn send_to_onion_service_status(
    anon_onion_sender: Option<std::sync::Arc<dyn veil_types::AnonOnionSender>>,
    p: veil_proto::ipc::SendToOnionServicePayload,
) -> u16 {
    match anon_onion_sender.as_deref() {
        Some(s) => {
            // anonymous → service sees src=[0;32]; else the daemon signs
            // with our sovereign id.
            let send = if p.anonymous {
                s.send_to_onion_service_anonymous(
                    p.service_identity_vk,
                    p.target_app_id,
                    p.target_endpoint_id,
                    p.src_app_id,
                    &p.data,
                    p.hop_count as usize,
                )
                .await
            } else {
                s.send_to_onion_service(
                    p.service_identity_vk,
                    p.target_app_id,
                    p.target_endpoint_id,
                    &p.data,
                    p.hop_count as usize,
                )
                .await
            };
            match send {
                Ok(()) => 0,
                Err(veil_types::AnonOnionSendError::NoRelays) => ipc_send_err::NO_ROUTE,
                Err(veil_types::AnonOnionSendError::NoIdentity) => ipc_send_err::NO_IDENTITY,
                Err(veil_types::AnonOnionSendError::PayloadTooLarge) => {
                    ipc_send_err::PAYLOAD_TOO_LARGE
                }
                // NoRendezvous → no resolvable/decryptable descriptor for
                // that identity.
                Err(_) => ipc_send_err::NO_RENDEZVOUS,
            }
        }
        None => ipc_send_err::NO_RENDEZVOUS,
    }
}

/// `SendAuthenticatedDirectWithReply` (the KEM-key-given direct send — mailbox
/// FETCH and ACK) after validation: send + await the relay leg, return the wire
/// status (0 = ok).
///
/// This is where the wire's `reply_endpoint_id == 0` sentinel is read, and the
/// only place it exists: below this line "no answer wanted" is a typed `None`.
/// A zero endpoint can never receive one anyway — a reply block addressed there
/// is a circuit built to deliver to nobody.
pub(crate) async fn send_authenticated_direct_with_reply_status(
    anon_onion_sender: Option<std::sync::Arc<dyn veil_types::AnonOnionSender>>,
    p: veil_proto::ipc::SendAuthenticatedDirectWithReplyPayload,
) -> u16 {
    let reply = (p.reply_endpoint_id != 0).then_some((p.src_app_id, p.reply_endpoint_id));
    match anon_onion_sender.as_deref() {
        Some(s) => {
            match s
                .send_authenticated_direct_with_reply(
                    p.target_node_id,
                    p.target_x25519_pk,
                    p.target_app_id,
                    p.target_endpoint_id,
                    &p.data,
                    reply,
                )
                .await
            {
                Ok(()) => 0,
                Err(veil_types::AnonOnionSendError::NoRelays) => ipc_send_err::NO_ROUTE,
                Err(veil_types::AnonOnionSendError::PayloadTooLarge) => {
                    ipc_send_err::PAYLOAD_TOO_LARGE
                }
                Err(_) => ipc_send_err::NO_ROUTE,
            }
        }
        None => ipc_send_err::NO_ROUTE,
    }
}

#[cfg(test)]
mod relay_hop_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    struct ActivePeers(Vec<[u8; 32]>);

    impl FrameBroadcaster for ActivePeers {
        fn send_to(&self, _peer_id: &[u8; 32], _priority: u8, _bytes: Vec<u8>) -> bool {
            true
        }

        fn send_to_all_with_priority(&self, _priority: u8, _bytes: Arc<[u8]>) {}

        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            self.0.clone()
        }
    }

    #[test]
    fn forced_relay_never_selects_the_destination_direct_session() {
        let dst = [0x10; 32];
        let relay = [0x20; 32];
        let mut cache = veil_routing::RouteCache::new(Duration::from_secs(60));
        cache.insert(dst, dst, 1, 1);
        cache.insert(dst, relay, 2, 2);
        let cache = RwLock::new(cache);
        let peers = ActivePeers(vec![dst, relay]);

        assert_eq!(relay_hops_to_try(&dst, Some(&cache), &peers), vec![relay]);
    }

    #[test]
    fn forced_relay_uses_live_overlay_peer_without_waiting_for_discovery() {
        let dst = [0x10; 32];
        let nearest = [0x11; 32];
        let farther = [0x30; 32];
        let peers = ActivePeers(vec![farther, dst, nearest, nearest]);

        assert_eq!(
            relay_hops_to_try(&dst, None, &peers),
            vec![nearest, farther]
        );
    }
}

// ── The ratchet on the send path ─────────────────────────────────────────────
//
// These drive the real `handle_ipc_send`, not a helper beside it, because
// everything interesting here is a decision that function makes: which of the
// two transports the message takes, whether the ratchet applies to it at all,
// and — for the anonymous flag — that it deliberately does not.

#[cfg(all(test, unix))]
mod ratchet_send_tests {
    use super::*;
    use std::sync::Arc;
    use veil_proto::AppIpcSendPayload;

    const ME: [u8; 32] = [0xA0u8; 32];
    const PEER: [u8; 32] = [0xB0u8; 32];
    const RELAY: [u8; 32] = [0xE0u8; 32];
    const PEER_INSTANCE: [u8; 16] = [0xB1u8; 16];
    const MY_INSTANCE: [u8; 16] = [0xA1u8; 16];

    /// Captures everything the handler hands to a session.
    #[derive(Default)]
    struct Outbox {
        live: Vec<[u8; 32]>,
        sent: Mutex<Vec<([u8; 32], Vec<u8>)>>,
    }

    impl FrameBroadcaster for Outbox {
        fn send_to(&self, peer_id: &[u8; 32], _priority: u8, bytes: Vec<u8>) -> bool {
            if !self.live.contains(peer_id) {
                return false;
            }
            lock!(self.sent).push((*peer_id, bytes));
            true
        }
        fn send_to_all_with_priority(&self, _priority: u8, _bytes: Arc<[u8]>) {}
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            self.live.clone()
        }
    }

    /// A resolver that already holds the peer's verified certificate — the
    /// steady state after one DHT walk.
    struct Certs(veil_types::VerifiedPeerCert);

    impl veil_types::MlKemEkResolver for Certs {
        fn resolve_cert_cached(&self, target: [u8; 32]) -> Option<veil_types::VerifiedPeerCert> {
            (target == self.0.node_id).then(|| self.0.clone())
        }
        fn resolve_cert(
            &self,
            target: [u8; 32],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<veil_types::VerifiedPeerCert>> + Send + '_>,
        > {
            let out = self.resolve_cert_cached(target);
            Box::pin(async move { out })
        }
    }

    /// What the session layer would answer to "which device does the live
    /// session to PEER terminate at?". `None` = no session / legacy handshake.
    struct PinnedInstance(Option<[u8; 16]>);

    impl veil_types::SessionInstanceLookup for PinnedInstance {
        fn session_instance(&self, peer: &[u8; 32]) -> Option<[u8; 16]> {
            (*peer == PEER).then_some(self.0).flatten()
        }
    }

    /// A resolver holding one verified row per device of a peer — the steady
    /// state for a multi-device family after the fan-out paths have walked it.
    struct FamilyCerts(Vec<veil_types::VerifiedPeerCert>);

    impl veil_types::MlKemEkResolver for FamilyCerts {
        fn resolve_cert_cached(&self, target: [u8; 32]) -> Option<veil_types::VerifiedPeerCert> {
            // The singular question has no honest answer for a family; the
            // production resolver's zero-valued freshness tie hands back an
            // arbitrary row. Modeled here as "the last one", which is what an
            // all-zero `max_by_key` over an iterator returns.
            self.0.iter().rfind(|c| c.node_id == target).cloned()
        }
        fn resolve_cert(
            &self,
            target: [u8; 32],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<veil_types::VerifiedPeerCert>> + Send + '_>,
        > {
            let out = self.resolve_cert_cached(target);
            Box::pin(async move { out })
        }
        fn resolve_cert_for_instance_cached(
            &self,
            target: [u8; 32],
            instance: [u8; 16],
        ) -> Option<veil_types::VerifiedPeerCert> {
            self.0
                .iter()
                .find(|c| c.node_id == target && c.instance_id == instance)
                .cloned()
        }
    }

    struct Fixture {
        outbox: Arc<Outbox>,
        route_cache: Arc<RwLock<veil_routing::RouteCache>>,
        peer_mlkem: Arc<std::sync::RwLock<veil_e2e::PeerMlKemCache>>,
        certs: Arc<dyn veil_types::MlKemEkResolver>,
        registry: Arc<veil_app::registry::AppEndpointRegistry>,
        me: veil_e2e::RatchetRuntime,
        /// The peer's side, for opening what we sealed.
        peer: veil_e2e::RatchetRuntime,
        /// What [`PinnedInstance`] answers for PEER in [`Fixture::ctx`].
        session_instance: Option<[u8; 16]>,
    }

    fn ratchet_runtime(
        node_id: [u8; 32],
        instance: [u8; 16],
        ring: Arc<veil_e2e::MlKemSeedRing>,
    ) -> veil_e2e::RatchetRuntime {
        veil_e2e::RatchetRuntime {
            store: Arc::new(veil_e2e::RatchetStore::new()),
            seed_ring: Arc::new(std::sync::RwLock::new(ring)),
            local_node_id: Arc::new(std::sync::RwLock::new(node_id)),
            local_instance_id: Arc::new(std::sync::RwLock::new(Some(instance))),
            peer_ratchet_keys: Arc::new(std::sync::RwLock::new(
                veil_e2e::PeerRatchetKeyCache::new(),
            )),
        }
    }

    fn ring(tag: u8) -> Arc<veil_e2e::MlKemSeedRing> {
        let seed = [tag; veil_e2e::DK_SEED_BYTES];
        let (ek, _) = veil_e2e::keypair_from_dk_seed(&seed).expect("keypair");
        Arc::new(veil_e2e::MlKemSeedRing::new(0, seed, ek))
    }

    /// `live_peers` decides which transport the handler picks: with PEER live
    /// it takes the direct session, with only RELAY live it falls through to
    /// the relay path.
    fn fixture(live_peers: Vec<[u8; 32]>) -> Fixture {
        let my_ring = ring(0xA5);
        let peer_ring = ring(0xB5);
        let cert = veil_types::VerifiedPeerCert {
            node_id: PEER,
            instance_id: PEER_INSTANCE,
            mlkem_ek: peer_ring.current_ek().to_vec(),
            ratchet_x25519_pk: peer_ring.current_ratchet_pk(),
            cert_version: 1,
        };
        let route_cache = RwLock::new(veil_routing::RouteCache::new(
            std::time::Duration::from_secs(60),
        ));
        wlock!(route_cache).insert(PEER, RELAY, 10_000, 2);
        let peer_mlkem = std::sync::RwLock::new(veil_e2e::PeerMlKemCache::new());
        wlock!(peer_mlkem).insert(
            PEER,
            (peer_ring.current_ek().to_vec(), std::time::Instant::now()),
        );
        // The peer knows our device key, as it would after resolving us.
        let peer_rt = ratchet_runtime(PEER, PEER_INSTANCE, peer_ring);
        wlock!(peer_rt.peer_ratchet_keys)
            .entry(ME)
            .or_default()
            .remember(MY_INSTANCE, my_ring.current_ratchet_pk(), u64::MAX);
        Fixture {
            outbox: Arc::new(Outbox {
                live: live_peers,
                sent: Mutex::new(Vec::new()),
            }),
            route_cache: Arc::new(route_cache),
            peer_mlkem: Arc::new(peer_mlkem),
            certs: Arc::new(Certs(cert)),
            registry: Arc::new(veil_app::registry::AppEndpointRegistry::new()),
            me: ratchet_runtime(ME, MY_INSTANCE, my_ring),
            peer: peer_rt,
            session_instance: None,
        }
    }

    /// PEER as a two-device family: the live session ends at PEER_INSTANCE,
    /// while the resolver's singular answer is the OTHER device — the №35
    /// mismatch, on purpose. Returns the fixture and the sibling's runtime so
    /// tests can prove where a frame is (and is not) openable.
    fn family_fixture() -> (Fixture, veil_e2e::RatchetRuntime) {
        const SIBLING_INSTANCE: [u8; 16] = [0xB2u8; 16];
        let mut fx = fixture(vec![PEER, RELAY]);
        let sibling_ring = ring(0xC5);
        let peer_ring = std::sync::Arc::clone(&fx.peer.seed_ring.read().expect("ring"));
        let session_row = veil_types::VerifiedPeerCert {
            node_id: PEER,
            instance_id: PEER_INSTANCE,
            mlkem_ek: peer_ring.current_ek().to_vec(),
            ratchet_x25519_pk: peer_ring.current_ratchet_pk(),
            cert_version: 1,
        };
        let sibling_row = veil_types::VerifiedPeerCert {
            node_id: PEER,
            instance_id: SIBLING_INSTANCE,
            mlkem_ek: sibling_ring.current_ek().to_vec(),
            ratchet_x25519_pk: sibling_ring.current_ratchet_pk(),
            cert_version: 1,
        };
        let my_ratchet_pk = fx.me.seed_ring.read().expect("ring").current_ratchet_pk();
        let sibling_rt = ratchet_runtime(PEER, SIBLING_INSTANCE, sibling_ring);
        wlock!(sibling_rt.peer_ratchet_keys)
            .entry(ME)
            .or_default()
            .remember(MY_INSTANCE, my_ratchet_pk, u64::MAX);
        // Singular answer = the LAST row = the sibling: the accident row and
        // the session's device must differ for the test to say anything.
        fx.certs = Arc::new(FamilyCerts(vec![session_row, sibling_row]));
        (fx, sibling_rt)
    }

    impl Fixture {
        fn ctx(&self, with_ratchet: bool) -> IpcSendContext {
            IpcSendContext {
                app_registry: Arc::clone(&self.registry),
                local_node_id: ME,
                session_tx_registry: Some(Arc::clone(&self.outbox) as Arc<dyn FrameBroadcaster>),
                route_cache: Some(Arc::clone(&self.route_cache)),
                route_updated: None,
                peer_mlkem_keys: Some(Arc::clone(&self.peer_mlkem)),
                mlkem_ek_resolver: Some(Arc::clone(&self.certs)),
                anon_onion_sender: None,
                capture_tx: None,
                pending_recursive: None,
                trace_sample_rate: 0.0,
                pending_ack: None,
                ratchet: with_ratchet.then(|| self.me.clone()),
                // Always present, answering `self.session_instance`: `None`
                // through it must behave exactly like no lookup at all, and
                // every pre-existing test exercises that leg for free.
                session_instance_lookup: Some(Arc::new(PinnedInstance(self.session_instance))),
            }
        }

        fn taken(&self) -> Vec<([u8; 32], Vec<u8>)> {
            std::mem::take(&mut lock!(self.outbox.sent))
        }
    }

    fn payload(anonymous: bool, data: &[u8]) -> Vec<u8> {
        AppIpcSendPayload {
            my_other_devices: false,
            src_app_id: [0x11u8; 32],
            dst_node_id: PEER,
            app_id: [0x22u8; 32],
            endpoint_id: 7,
            data: veil_bufpool::pooled_shared_from_vec(data.to_vec()),
            require_ack: false,
            anonymous,
            anonymous_authenticated: false,
            expect_reply: false,
            is_reply: false,
            reply_id: 0,
            reply_endpoint_id: 0,
        }
        .encode()
    }

    /// A write half over a socket pair — the handler writes status frames to
    /// it and nothing here reads them back.
    async fn sink() -> crate::transport::IpcWriteHalf {
        let (a, b) = tokio::net::UnixStream::pair().expect("socketpair");
        // Keep the far end alive for the length of the test so writes do not
        // fail with EPIPE and mask a real assertion.
        Box::leak(Box::new(b));
        let (_r, w) = a.into_split();
        veil_local_transport::LocalWriteHalf::Unix(w)
    }

    /// The blocker this slice existed for: a message to an ONLINE peer used to
    /// leave the node with no end-to-end sealing at all — the session's own hop
    /// cipher was the whole of it. Most one-to-one traffic goes this way, so
    /// ratcheting the relay path alone would have ratcheted the minority.
    ///
    /// Positive assertion: the frame on the wire is an APP_SEND_SEALED whose
    /// payload the peer opens through the ratchet.
    #[tokio::test]
    async fn a_direct_session_send_goes_out_through_the_ratchet() {
        let fx = fixture(vec![PEER, RELAY]);
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"hello over a session"),
            &fx.ctx(true),
        )
        .await
        .expect("send");

        let sent = fx.taken();
        assert_eq!(sent.len(), 1);
        let (peer, frame) = &sent[0];
        assert_eq!(peer, &PEER, "the direct session, not a relay");

        let hdr = veil_proto::codec::decode_header(frame).expect("header");
        assert_eq!(
            hdr.msg_type,
            veil_proto::family::AppMsg::AppSendSealed as u16,
            "a sealed send must be its own frame type — `data` is whatever the \
             app put there, so no byte inside it could have been reserved"
        );
        let body = veil_proto::app::AppSendPayload::decode(&frame[veil_proto::HEADER_SIZE..])
            .expect("body");
        assert_eq!(
            body.data.first().copied(),
            Some(veil_proto::RATCHET_E2E_MARKER)
        );

        // And it really is readable by the peer, as the peer.
        let opened = fx
            .peer
            .open_payload(&ME, &body.data, veil_util::unix_secs_now_u64())
            .expect("the peer opens it");
        assert_eq!(opened.plaintext, b"hello over a session");
        assert!(
            opened.authenticated,
            "and knows who wrote it, which an unsealed APP_SEND never told it"
        );
    }

    /// Defect №35, the sender's half. For a multi-device peer the cert cache
    /// and the live session each name a device INDEPENDENTLY — the cache by an
    /// all-zero freshness tie, the session by rendezvous accident — and they
    /// disagree 4/5 of the time in a five-device family. When the session says
    /// which device it terminates at, the seal must be keyed to THAT device.
    ///
    /// Proven by where the frame opens: at the session's device, and refused
    /// by the sibling the singular cache would have picked.
    #[tokio::test]
    async fn a_session_backed_send_is_sealed_for_the_sessions_device_not_the_cache_accident() {
        let (mut fx, sibling) = family_fixture();
        fx.session_instance = Some(PEER_INSTANCE);
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"to the device the session ends at"),
            &fx.ctx(true),
        )
        .await
        .expect("send");

        let sent = fx.taken();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, PEER, "down the direct session");
        let body = veil_proto::app::AppSendPayload::decode(&sent[0].1[veil_proto::HEADER_SIZE..])
            .expect("body");
        let now = veil_util::unix_secs_now_u64();
        assert!(
            matches!(
                sibling.open_payload(&ME, &body.data, now),
                Err(veil_e2e::RatchetSpliceError::NotForThisDevice)
            ),
            "the sibling — the row the singular resolve hands back — must \
             refuse it, or this test is not about the pairing rule"
        );
        let opened = fx
            .peer
            .open_payload(&ME, &body.data, now)
            .expect("the device the session terminates at opens it");
        assert_eq!(opened.plaintext, b"to the device the session ends at");
        assert!(opened.authenticated);
    }

    /// The fail-open half of the rule: no session-named instance (no live
    /// session, or a legacy handshake that proved none) keeps the singular
    /// resolve deciding — exactly the pre-№35 behaviour, which is correct for
    /// every single-instance peer.
    #[tokio::test]
    async fn without_a_session_instance_the_singular_row_still_decides() {
        let (fx, sibling) = family_fixture(); // session_instance: None
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"addressed to the identity"),
            &fx.ctx(true),
        )
        .await
        .expect("send");

        let sent = fx.taken();
        assert_eq!(sent.len(), 1);
        let body = veil_proto::app::AppSendPayload::decode(&sent[0].1[veil_proto::HEADER_SIZE..])
            .expect("body");
        let now = veil_util::unix_secs_now_u64();
        let opened = sibling
            .open_payload(&ME, &body.data, now)
            .expect("the singular row's device opens it — unchanged behaviour");
        assert_eq!(opened.plaintext, b"addressed to the identity");
    }

    /// Without the ratchet wired the same send is the plaintext APP_SEND it
    /// always was. Stated so the assertion above is about the ratchet and not
    /// about the fixture.
    #[tokio::test]
    async fn without_the_ratchet_a_direct_session_send_is_unchanged() {
        let fx = fixture(vec![PEER, RELAY]);
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"plain"),
            &fx.ctx(false),
        )
        .await
        .expect("send");

        let sent = fx.taken();
        assert_eq!(sent.len(), 1);
        let hdr = veil_proto::codec::decode_header(&sent[0].1).expect("header");
        assert_eq!(hdr.msg_type, veil_proto::family::AppMsg::AppSend as u16);
        let body = veil_proto::app::AppSendPayload::decode(&sent[0].1[veil_proto::HEADER_SIZE..])
            .expect("body");
        assert_eq!(&*body.data, b"plain", "in the clear, exactly as before");
    }

    /// The relay path carries the same payload, under the delivery envelope.
    #[tokio::test]
    async fn a_relayed_send_carries_the_ratchet_payload() {
        let fx = fixture(vec![RELAY]); // no direct session to PEER
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"through a relay"),
            &fx.ctx(true),
        )
        .await
        .expect("send");

        let sent = fx.taken();
        assert_eq!(sent.len(), 1);
        let (hop, frame) = &sent[0];
        assert_eq!(hop, &RELAY);
        let fwd = veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
            .expect("forward");
        assert_eq!(
            fwd.envelope.payload.first().copied(),
            Some(veil_proto::RATCHET_E2E_MARKER),
            "not the 0xE2 encapsulation-to-a-published-key envelope"
        );
        let opened = fx
            .peer
            .open_payload(&ME, &fwd.envelope.payload, veil_util::unix_secs_now_u64())
            .expect("the peer opens it");
        assert_eq!(opened.plaintext, b"through a relay");
        assert!(opened.authenticated);
    }

    /// The anonymous path is standard traffic and must keep working. Gating it
    /// behind the ratchet would have been the easy mistake: a ratchet is a
    /// NAMED two-party object, so running one here would put both device
    /// identities in front of the recipient and destroy the property the path
    /// exists for.
    #[tokio::test]
    async fn an_anonymous_send_stays_on_the_anonymous_path_and_stays_anonymous() {
        let fx = fixture(vec![RELAY]);
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(true, b"anonymously yours"),
            &fx.ctx(true),
        )
        .await
        .expect("send");

        let sent = fx.taken();
        assert_eq!(sent.len(), 1);
        let fwd =
            veil_proto::delivery::ForwardPayload::decode(&sent[0].1[veil_proto::HEADER_SIZE..])
                .expect("forward");
        assert_eq!(
            fwd.envelope.payload.first().copied(),
            Some(veil_proto::META_E2E_MARKER),
            "the anonymous path must not have been rerouted through the ratchet"
        );
        assert_eq!(fwd.envelope.sender_node_id, [0u8; 32]);
        assert_eq!(fwd.envelope.src_app_id, [0u8; 32]);
        assert_eq!(fwd.envelope.app_id, [0u8; 32]);
        assert_eq!(fwd.envelope.endpoint_id, 0);
        assert!(
            fx.me.store.is_empty(),
            "and must not have opened a named conversation on the way past"
        );
    }

    /// One message, one chain step, whichever transport it took. The direct
    /// send is tried first and falls through to the relay when there is no
    /// session; sealing inside each branch instead would advance the chain
    /// twice and leave the recipient banking a key nothing ever arrives for.
    #[tokio::test]
    async fn a_fallback_from_direct_to_relay_seals_once() {
        let fx = fixture(vec![RELAY]);
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"once"),
            &fx.ctx(true),
        )
        .await
        .expect("send");
        assert_eq!(
            fx.me.store.version(),
            1,
            "exactly one committed ratchet operation for one message"
        );
    }

    /// The host's cue to write. A send it does not persist is a message key it
    /// cannot rebuild, so the store names the conversation on every committed
    /// operation and clears the notice only when it is read.
    #[tokio::test]
    async fn every_send_names_the_conversation_the_host_must_persist() {
        let fx = fixture(vec![PEER]);
        let mut wh = sink().await;
        assert_eq!(fx.me.store.version(), 0);
        assert!(fx.me.store.drain_dirty().is_empty());

        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"one"),
            &fx.ctx(true),
        )
        .await
        .expect("send");
        assert_eq!(fx.me.store.version(), 1);
        let dirty = fx.me.store.drain_dirty();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].peer_node_id, PEER);
        assert_eq!(dirty[0].peer_instance_id, PEER_INSTANCE);
        assert_eq!(dirty[0].local_instance_id, MY_INSTANCE);

        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"two"),
            &fx.ctx(true),
        )
        .await
        .expect("send");
        assert_eq!(fx.me.store.version(), 2);
        assert_eq!(fx.me.store.drain_dirty().len(), 1, "named again");
    }
}

/// The `reply_endpoint_id == 0` reading on the KEM-key-given direct send.
///
/// The mailbox drain builds SIX onion circuits per round against three relays —
/// a forward and a reply circuit each for FETCH and for ACK. Half of them were
/// the ACK's: the ack endpoint never answers, so every reply circuit it built
/// registered a cookie at a relay, waited for its `CircuitBuilt`, and carried
/// nothing. Zero now means "no answer wanted", and the ack sends with it.
///
/// Both directions are asserted. A handler that simply never attached a reply
/// block would pass the first test and break every mailbox FETCH.
#[cfg(test)]
mod direct_reply_sentinel_tests {
    use std::sync::Mutex;

    type AnonFut<'a> = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), veil_types::AnonOnionSendError>>
                + Send
                + 'a,
        >,
    >;

    /// What the sender trait carries as a reply path: `(src_app_id,
    /// reply_endpoint_id)`, absent when the caller wants no reply.
    type ReplyPath = Option<([u8; 32], u32)>;

    /// Records the `reply` argument of every direct send; every other method is
    /// off this path and panics rather than silently passing.
    #[derive(Default)]
    struct RecordingSender {
        replies: Mutex<Vec<ReplyPath>>,
    }

    impl veil_types::AnonOnionSender for RecordingSender {
        fn send_authenticated_direct_with_reply<'a>(
            &'a self,
            _target_node_id: [u8; 32],
            _target_x25519_pk: [u8; 32],
            _app_id: [u8; 32],
            _endpoint_id: u32,
            _data: &'a [u8],
            reply: Option<([u8; 32], u32)>,
        ) -> AnonFut<'a> {
            self.replies.lock().unwrap().push(reply);
            Box::pin(async { Ok(()) })
        }
        fn send_authenticated<'a>(
            &'a self,
            _: [u8; 32],
            _: [u8; 32],
            _: u32,
            _: &'a [u8],
        ) -> AnonFut<'a> {
            unimplemented!()
        }
        fn send_authenticated_with_reply<'a>(
            &'a self,
            _: [u8; 32],
            _: [u8; 32],
            _: u32,
            _: &'a [u8],
            _: [u8; 32],
            _: u32,
        ) -> AnonFut<'a> {
            unimplemented!()
        }
        fn send_reply<'a>(&'a self, _: u64, _: &'a [u8], _: [u8; 32]) -> AnonFut<'a> {
            unimplemented!()
        }
        fn register_onion_service<'a>(&'a self, _: usize) -> AnonFut<'a> {
            unimplemented!()
        }
        fn register_rendezvous_publisher(
            &self,
            _: [u8; 32],
            _: [u8; 16],
            _: u64,
            _: u8,
            _: Vec<u8>,
        ) {
            unimplemented!()
        }
        fn send_to_onion_service<'a>(
            &'a self,
            _: [u8; 32],
            _: [u8; 32],
            _: u32,
            _: &'a [u8],
            _: usize,
        ) -> AnonFut<'a> {
            unimplemented!()
        }
        fn send_to_onion_service_anonymous<'a>(
            &'a self,
            _: [u8; 32],
            _: [u8; 32],
            _: u32,
            _: [u8; 32],
            _: &'a [u8],
            _: usize,
        ) -> AnonFut<'a> {
            unimplemented!()
        }
        fn send_anonymous_direct<'a>(
            &'a self,
            _: [u8; 32],
            _: [u8; 32],
            _: [u8; 32],
            _: u32,
            _: [u8; 32],
            _: &'a [u8],
            _: usize,
        ) -> AnonFut<'a> {
            unimplemented!()
        }
    }

    const SRC_APP: [u8; 32] = [0xA1; 32];

    fn payload(reply_endpoint_id: u32) -> veil_proto::ipc::SendAuthenticatedDirectWithReplyPayload {
        veil_proto::ipc::SendAuthenticatedDirectWithReplyPayload {
            target_node_id: [0x01; 32],
            target_x25519_pk: [0x02; 32],
            target_app_id: [0x03; 32],
            src_app_id: SRC_APP,
            target_endpoint_id: 3,
            reply_endpoint_id,
            hop_count: 0,
            data: vec![0x7Eu8; 32],
        }
    }

    async fn reply_arg_for(reply_endpoint_id: u32) -> Option<([u8; 32], u32)> {
        let sender = std::sync::Arc::new(RecordingSender::default());
        let status = super::send_authenticated_direct_with_reply_status(
            Some(sender.clone() as std::sync::Arc<dyn veil_types::AnonOnionSender>),
            payload(reply_endpoint_id),
        )
        .await;
        assert_eq!(status, 0, "the send itself must succeed");
        let seen = sender.replies.lock().unwrap().clone();
        assert_eq!(seen.len(), 1, "exactly one direct send");
        seen[0]
    }

    #[tokio::test]
    async fn a_zero_reply_endpoint_attaches_no_reply_block() {
        assert_eq!(
            reply_arg_for(0).await,
            None,
            "endpoint 0 can receive nothing, so a reply block addressed there \
             only costs an ephemeral circuit — the ACK must not pay for one",
        );
    }

    #[tokio::test]
    async fn a_real_reply_endpoint_still_gets_one() {
        assert_eq!(
            reply_arg_for(9).await,
            Some((SRC_APP, 9)),
            "the mailbox FETCH depends on the reply block; dropping it for \
             every send would silence the drain",
        );
    }
}
