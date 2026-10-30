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
//! Reliable sealed payloads are split into small existing chunk-envelopes
//! on direct and relay paths: each piece is an ordinary `Forward` envelope
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

#[path = "source_envelope.rs"]
mod source_envelope;
use source_envelope::{
    DirectAdmission, EnvelopeChunks, admit_direct_plain, admit_direct_sealed,
    send_packetized_control, source_segment_bytes,
};

/// How long a discovery that found no route is believed.
///
/// Each discovery sends a query toward the destination and waits up to half a
/// second for an answer, and nothing remembered an unanswered one: every send
/// to a destination nobody can reach paid the half second and sent its query
/// again. Measured on a stand as 0.5 s of every 6–15 s send to an absent
/// device, for each of the hundreds the app re-drove after a restart. Short:
/// a route that appears must be used soon, and a send inside the window still
/// has the live-session relays to fall back on.
const ROUTE_MISS_TTL: std::time::Duration = std::time::Duration::from_secs(10);

// Keep relay-only misses independent of ordinary/direct discovery. A usable
// direct route is neither a successful relay lookup nor a relay miss.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum RouteDiscoveryKind {
    Any,
    RelayOnly,
}
type RouteMisses =
    std::collections::HashMap<([u8; 32], [u8; 32], RouteDiscoveryKind), std::time::Instant>;
static ROUTE_MISSES: std::sync::LazyLock<std::sync::Mutex<RouteMisses>> =
    std::sync::LazyLock::new(Default::default);

// Concurrent local sends share a lookup, then recheck its cache/miss result.
// The key includes the local node and policy: neither another identity nor a
// direct-only result may settle a relay-only caller. No state reaches a peer.
type DiscoveryGateKey = ([u8; 32], [u8; 32], RouteDiscoveryKind);
type DiscoveryGates =
    std::collections::HashMap<DiscoveryGateKey, std::sync::Weak<tokio::sync::Mutex<()>>>;
static ROUTE_DISCOVERY_GATES: std::sync::LazyLock<Mutex<DiscoveryGates>> =
    std::sync::LazyLock::new(Default::default);

fn discovery_gate(key: DiscoveryGateKey) -> Option<Arc<tokio::sync::Mutex<()>>> {
    let mut gates = lock!(ROUTE_DISCOVERY_GATES);
    if let Some(gate) = gates.get(&key).and_then(std::sync::Weak::upgrade) {
        return Some(gate);
    }
    gates.retain(|_, gate| gate.strong_count() > 0);
    // Preserve route recovery if every slot serves a different live lookup.
    if gates.len() >= 128 {
        return None;
    }
    let gate = Arc::new(tokio::sync::Mutex::new(()));
    gates.insert(key, Arc::downgrade(&gate));
    Some(gate)
}

// A missing media route is probed in the background, once per node/destination.
// Never hold RTP/RTCP for the 500 ms discovery deadline, nor launch a walk for
// each packet in the 50 Hz audio stream. Bound outstanding probes globally.
type MediaProbeKey = ([u8; 32], [u8; 32]);
static MEDIA_ROUTE_PROBES: std::sync::LazyLock<Mutex<std::collections::HashSet<MediaProbeKey>>> =
    std::sync::LazyLock::new(Default::default);
struct MediaRouteProbe(MediaProbeKey);

impl Drop for MediaRouteProbe {
    fn drop(&mut self) {
        lock!(MEDIA_ROUTE_PROBES).remove(&self.0);
    }
}

fn warm_media_route(ctx: &IpcSendContext, dst: [u8; 32]) {
    let (Some(cache), Some(reg), Some(notify)) = (
        ctx.route_cache.as_ref(),
        ctx.session_tx_registry.as_ref(),
        ctx.route_updated.as_ref(),
    ) else {
        return;
    };
    if cached_discovery_hop(
        &rlock!(cache),
        &dst,
        Some(reg.as_ref()),
        RouteDiscoveryKind::RelayOnly,
    )
    .is_some()
        || route_recently_missed(&ctx.local_node_id, &dst, RouteDiscoveryKind::RelayOnly)
    {
        return;
    }
    let key = (ctx.local_node_id, dst);
    {
        let mut probes = lock!(MEDIA_ROUTE_PROBES);
        if probes.len() >= 128 || !probes.insert(key) {
            return;
        }
    }
    let probe = MediaRouteProbe(key);
    let cache = Arc::clone(cache);
    let reg = Arc::clone(reg);
    let notify = Arc::clone(notify);
    let pending = ctx.pending_recursive.clone();
    tokio::spawn(async move {
        let _probe = probe;
        let _ = discover_route(
            &dst,
            &key.0,
            Some(&cache),
            Some(reg.as_ref()),
            Some(&notify),
            None, // the call cipher already sealed the packet
            pending.as_deref(),
            RouteDiscoveryKind::RelayOnly,
        )
        .await;
    });
}

fn route_recently_missed(local: &[u8; 32], dst: &[u8; 32], kind: RouteDiscoveryKind) -> bool {
    ROUTE_MISSES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&(*local, *dst, kind))
        .is_some_and(|at| at.elapsed() < ROUTE_MISS_TTL)
}

fn note_route_miss(local: &[u8; 32], dst: &[u8; 32], kind: RouteDiscoveryKind) {
    let mut misses = ROUTE_MISSES.lock().unwrap_or_else(|p| p.into_inner());
    if misses.len() >= 4_096 {
        misses.retain(|_, at| at.elapsed() < ROUTE_MISS_TTL);
    }
    misses.insert((*local, *dst, kind), std::time::Instant::now());
}

fn cached_discovery_hop(
    cache: &veil_routing::RouteCache,
    dst: &[u8; 32],
    reg: Option<&dyn FrameBroadcaster>,
    kind: RouteDiscoveryKind,
) -> Option<[u8; 32]> {
    if kind == RouteDiscoveryKind::Any {
        return cache.lookup(dst);
    }
    let active = reg?.active_node_ids();
    cache
        .lookup_all(dst)
        .into_iter()
        .find(|hop| hop != dst && active.contains(hop))
}

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
    discover_route(
        dst,
        local_node_id,
        route_cache,
        session_tx_registry,
        route_updated,
        peer_mlkem_keys,
        pending_recursive,
        RouteDiscoveryKind::Any,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn discover_route(
    dst: &[u8; 32],
    local_node_id: &[u8; 32],
    route_cache: Option<&RwLock<veil_routing::RouteCache>>,
    session_tx_registry: Option<&dyn FrameBroadcaster>,
    route_updated: Option<&tokio::sync::Notify>,
    peer_mlkem_keys: Option<&std::sync::RwLock<veil_e2e::PeerMlKemCache>>,
    pending_recursive: Option<
        &Mutex<std::collections::HashMap<[u8; 16], veil_dispatcher_state::PendingRecursive>>,
    >,
    kind: RouteDiscoveryKind,
) -> Option<[u8; 32]> {
    use veil_proto::{
        codec::encode_header,
        family::{FrameFamily, RoutingMsg},
        header::FrameHeader,
    };

    let gate = discovery_gate((*local_node_id, *dst, kind));
    let _lookup = match gate.as_ref() {
        Some(gate) => Some(gate.lock().await),
        None => None,
    };
    // Cancellation releases the gate; waiters retry the ordinary verified
    // cache path and can perform discovery if the first caller never finished.
    // Fast path: route already cached AND (no E2E infrastructure OR ML-KEM key cached).
    // If the route is known but the ML-KEM key is absent (e.g. route came from a
    // RouteAnnounce gossip that carries no ML-KEM key), fall through to reactive
    // discovery so a RouteRequest triggers a RouteResponse that brings both the
    // confirmed route and the ML-KEM encapsulation key in one atomic step.
    // A key past its signed window is not a key: treating it as one meant
    // taking the cached route and sealing to a certificate its owner had
    // stopped standing behind (report20 V18-M12). Not ready means the
    // reactive discovery below, which fetches a current one.
    let mlkem_ready = || {
        let now_unix = veil_util::unix_secs_now_u64();
        peer_mlkem_keys
            .map(|k| {
                rlock!(k)
                    .get(dst)
                    .is_some_and(|(key, _)| key.usable_at(now_unix).is_some())
            })
            .unwrap_or(true) // if no E2E infrastructure, route alone is sufficient
    };
    if mlkem_ready()
        && let Some(cache) = route_cache
        && let Some(hop) = cached_discovery_hop(&rlock!(cache), dst, session_tx_registry, kind)
    {
        return Some(hop);
    }

    // A discovery that just found nothing is not repeated: the cache is what
    // it would have filled, and it has been asked above.
    if route_recently_missed(local_node_id, dst, kind) {
        return route_cache.and_then(|cache| {
            cached_discovery_hop(&rlock!(cache), dst, session_tx_registry, kind)
        });
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
        if kind == RouteDiscoveryKind::RelayOnly {
            // A direct reply would only refresh the direct route that cannot
            // carry this relay-only send. Discover through ordinary mesh peers.
            peers.retain(|peer| peer != dst);
        }
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

    // The small RecursiveResponse can precede its larger signed key proof.
    // Keep the shared lookup until BOTH are ready, so a waiter cannot launch
    // another proof while the first one is still in flight. Unrelated route
    // notifications are only wakeups, never evidence for this destination.
    // Keep one fixed deadline and the legacy route-only fallback on expiry.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
    let mut rq_rx = rq_rx;
    tokio::pin!(notified);
    loop {
        // Register before checking the caches, including after each wakeup.
        notified.as_mut().enable();
        if mlkem_ready()
            && cached_discovery_hop(&rlock!(cache), dst, session_tx_registry, kind).is_some()
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::select! {
            _ = &mut notified => {}
            _ = async { let _ = rq_rx.as_mut().expect("guarded receiver").await; },
                if rq_rx.is_some() => { rq_rx = None; }
            _ = tokio::time::sleep_until(deadline) => { break; }
        }
        notified.set(notify.notified());
    }

    // Retry the cache lookup.
    let result = cached_discovery_hop(&rlock!(cache), dst, session_tx_registry, kind);
    let elapsed = discovery_start.elapsed();
    if result.is_some() {
        log::debug!(
            "route.discovery.found dst={} elapsed_ms={}",
            veil_util::bytes_to_hex(&dst[..4]),
            elapsed.as_millis()
        );
    } else {
        note_route_miss(local_node_id, dst, kind);
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

/// Relay hops found BEFORE the seal: what discovery returned, and the full
/// ordered list built on it (see [`ordinary_relay_hops`]).
type PlannedRelay = (Option<[u8; 32]>, Vec<[u8; 32]>);

/// Next hops for an ORDINARY (non-realtime) send that has no direct session.
///
/// The discovered route first, then its cached alternatives — as before. What
/// is new is the tail: any live overlay session, XOR-closest to `dst` first,
/// the same fallback the realtime path already takes. Measured on a two-device
/// stand (2026-09-23): both devices held sessions with the same relays, the
/// relays announced each to the other, and still an ordinary send between them
/// answered NO_ROUTE whenever discovery came back empty inside its 500 ms —
/// minutes, after both restarted — while the realtime lane crossed the same
/// relays at once. A relay that holds a session with `dst` delivers straight
/// to it (`relay_forward`); one that does not falls back to its own routing.
///
/// Only when the payload WILL be sealed end to end. A relay reads whatever it
/// forwards, so a frame that would go in the clear is never handed to an
/// arbitrary session on the strength of it being alive: `will_seal` false keeps
/// exactly the old behaviour, including its NO_ROUTE.
/// The instance a live DEVICE session is proven to end at, when the session
/// named one; otherwise the one its id derives
/// (`SovereignIdentity::active_instance_id`: the first sixteen bytes).
fn device_instance(ctx: &IpcSendContext, device: &[u8; 32]) -> [u8; 16] {
    ctx.session_instance_lookup
        .as_deref()
        .and_then(|lookup| {
            lookup
                .session_pairing(device)
                .map(|p| p.instance)
                .or_else(|| lookup.session_instance(device))
        })
        .unwrap_or_else(|| {
            let mut prefix = [0u8; 16];
            prefix.copy_from_slice(&device[..16]);
            prefix
        })
}

/// A resolved family slot must still belong to the identity being addressed.
/// Check again after certificate resolution, which may yield across reconnect.
fn device_matches_identity(ctx: &IpcSendContext, device: &[u8; 32], identity: &[u8; 32]) -> bool {
    ctx.session_instance_lookup
        .as_deref()
        .and_then(|lookup| lookup.session_pairing(device))
        .is_none_or(|pairing| pairing.identity == *identity)
}

/// Reuse the same sealed bytes over reliable relay hops, including after a
/// direct source closes mid-transfer. Only outer routing metadata is renewed.
async fn forward_ordinary_family_copy(
    reg: &dyn FrameBroadcaster,
    send: &AppIpcSendPayload,
    sender: [u8; 32],
    instance: [u8; 16],
    payload: Vec<u8>,
    hops: Vec<[u8; 32]>,
    family_deadline: tokio::time::Instant,
) -> DirectAdmission {
    use veil_proto::delivery::DeliveryEnvelope;
    use veil_proto::family::DeliveryMsg;
    use veil_proto::recipient::Recipient;
    let now = veil_util::unix_secs_now_u64();
    let envelope = DeliveryEnvelope {
        recipient: Recipient::specific(send.dst_node_id, instance),
        sender_node_id: sender,
        src_app_id: send.src_app_id,
        app_id: send.app_id,
        endpoint_id: send.endpoint_id,
        content_id: {
            let mut id = [0u8; 32];
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut id);
            id
        },
        created_at: now,
        ttl_secs: 30,
        payload,
        trace_id: 0,
        require_ack: false,
    };
    // Use the normal reliable source and shared deadline for all
    // chunks, never the call-control datagram lane. The encrypted
    // envelope has no media/application priority visible to relays.
    for hop in hops.into_iter().take(3) {
        if tokio::time::Instant::now() >= family_deadline {
            return DirectAdmission::TimedOut;
        }
        let segment = source_segment_bytes(reg, envelope.payload.len());
        let frames = if envelope.payload.len() > segment
            || envelope.payload.len() > veil_proto::delivery::ENVELOPE_CHUNKING_THRESHOLD
        {
            let Some(chunks) = EnvelopeChunks::new(&envelope, false, segment) else {
                return DirectAdmission::Rejected;
            };
            chunks.frames_for(hop).collect::<Vec<_>>()
        } else {
            let bytes = envelope.encode();
            let mut header =
                FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
            header.set_priority(veil_proto::priority::INTERACTIVE);
            header.body_len = (32 + bytes.len() + 9) as u32;
            let mut frame = codec::encode_header(&header).to_vec();
            frame.extend_from_slice(&hop);
            frame.extend_from_slice(&bytes);
            frame.extend_from_slice(&0u64.to_be_bytes());
            frame.push(0);
            vec![frame]
        };
        let admitted = tokio::time::timeout_at(family_deadline, async {
            for frame in frames {
                if !reg.send_reliable_to(&hop, frame).await {
                    return false;
                }
            }
            true
        })
        .await;
        match admitted {
            Ok(true) => return DirectAdmission::Accepted,
            Ok(false) => {} // a closed hop may use an alternate path
            Err(_) => return DirectAdmission::TimedOut, // source pressure keeps the same deadline
        }
    }
    DirectAdmission::Missing
}

/// Already targeted live instances must not spend a second ratchet step on
/// the relay leg. Physical endpoint addresses are last-choice relay candidates.
#[derive(Default)]
struct DirectFamilyRecipients {
    devices: std::collections::HashSet<[u8; 32]>,
    instances: std::collections::HashSet<[u8; 16]>,
}

#[derive(Default)]
struct FamilyRelayResult {
    accepted: bool,
    source_failed: bool,
    host_failed: bool,
    timing: FamilySendTiming,
}

#[derive(Clone, Copy, Default)]
struct FamilySendTiming {
    resolve_ms: u128,
    seal_ms: u128,
    admission_ms: u128,
    certificates: usize,
    evidence: FamilySendEvidence,
}

/// Source-local outcomes, never destination receipts. No peer/instance IDs.
#[derive(Clone, Copy, Debug, Default)]
struct FamilySendEvidence {
    filtered_local: usize,
    filtered_identity: usize,
    filtered_pairing: usize,
    filtered_direct: usize,
    no_hops: usize,
    seal_attempts: usize,
    sealed: usize,
    seal_failed: usize,
    host_failed: usize,
    source_attempts: usize,
    source_accepted: usize,
    source_rejected: usize,
    source_timed_out: usize,
}

/// One ordinary reliable copy, or the existing control copies, per verified
/// family instance. In a mixed send, bounded family discovery runs alongside
/// direct admission. Use its verified result even when a cold local registry
/// has not retained the new rows. No background tail outlives this operation.
async fn send_family_relay_copies(
    ctx: &IpcSendContext,
    send: &AppIpcSendPayload,
    request_host_epoch: u64,
    family_deadline: tokio::time::Instant,
    relay_control_compat: bool,
    local_priority: u8,
    direct: Option<&DirectFamilyRecipients>,
) -> FamilyRelayResult {
    use veil_proto::delivery::DeliveryEnvelope;
    use veil_proto::family::DeliveryMsg;
    let (Some(ratchet), Some(resolver), Some(reg)) = (
        ctx.ratchet.as_ref(),
        ctx.mlkem_ek_resolver.as_deref(),
        ctx.session_tx_registry.as_deref(),
    ) else {
        return FamilyRelayResult::default();
    };
    let Some(me) = ratchet.identity() else {
        return FamilyRelayResult::default();
    };
    let local_node_id = &ctx.local_node_id;
    let route_cache = ctx.route_cache.as_deref();
    let now = veil_util::unix_secs_now_u64();
    let mut any_sent = false;
    let mut source_failed = false;
    let mut host_failed = false;
    let mut timing = FamilySendTiming::default();
    let resolve_started = std::time::Instant::now();
    let family = tokio::time::timeout_at(
        family_deadline,
        resolver.resolve_device_certs(send.dst_node_id),
    )
    .await
    .unwrap_or_else(|_| resolver.resolve_device_certs_cached(send.dst_node_id));
    timing.resolve_ms = resolve_started.elapsed().as_millis();
    timing.certificates = family.len();
    for (device, cert) in family {
        if !relay_control_compat && tokio::time::Instant::now() >= family_deadline {
            timing.evidence.source_timed_out += 1;
            source_failed = true;
            break;
        }
        if device == *local_node_id {
            timing.evidence.filtered_local += 1;
            continue;
        }
        if cert.node_id != send.dst_node_id {
            timing.evidence.filtered_identity += 1;
            continue;
        }
        if !device_matches_identity(ctx, &device, &send.dst_node_id) {
            timing.evidence.filtered_pairing += 1;
            continue;
        }
        if direct.is_some_and(|targets| targets.instances.contains(&cert.instance_id)) {
            timing.evidence.filtered_direct += 1;
            continue;
        }
        let mut hops = ordinary_relay_hops(None, &device, route_cache, reg, true);
        // A cached device route can accept frames while its attachment is
        // stale. Also use the identity's current attachment, restricted to
        // this same verified instance. Queue admission on either path is
        // not receipt. No DHT wait or new alias authority is introduced.
        let mut identity_hops = if device != send.dst_node_id {
            ordinary_relay_hops(None, &send.dst_node_id, route_cache, reg, true)
        } else {
            Vec::new()
        };
        if let Some(targets) = direct {
            // Prefer an independent relay to an endpoint that may be a leaf.
            // Keep the endpoint as a last candidate: a core family member can
            // legitimately be the only remaining route to its sibling.
            hops.sort_by_key(|hop| targets.devices.contains(hop));
            identity_hops.sort_by_key(|hop| targets.devices.contains(hop));
        }
        if hops.is_empty() && identity_hops.is_empty() {
            timing.evidence.no_hops += 1;
            continue;
        }
        let seal_started = std::time::Instant::now();
        timing.evidence.seal_attempts += 1;
        let sealed = seal_with_host_floor(
            &ratchet.store,
            request_host_epoch,
            family_deadline,
            &me,
            veil_e2e::PeerRatchetKeys {
                node_id: &cert.node_id,
                instance_id: &cert.instance_id,
                mlkem_ek: &cert.mlkem_ek,
                ratchet_pk: &cert.ratchet_x25519_pk,
                authorized_until_unix: cert.valid_until_unix,
            },
            &send.data,
        )
        .await;
        timing.seal_ms += seal_started.elapsed().as_millis();
        let (payload, _) = match sealed {
            Ok(sealed) => sealed,
            Err(
                veil_e2e::RatchetSpliceError::HostReservationRequired
                | veil_e2e::RatchetSpliceError::HostPublicationClosed,
            ) => {
                timing.evidence.host_failed += 1;
                host_failed = true;
                continue;
            }
            Err(_) => {
                timing.evidence.seal_failed += 1;
                continue;
            }
        };
        timing.evidence.sealed += 1;
        use veil_proto::recipient::Recipient;
        if !relay_control_compat {
            let generic_hops = if identity_hops.is_empty() {
                hops
            } else {
                identity_hops
            };
            let admission_started = std::time::Instant::now();
            timing.evidence.source_attempts += 1;
            let outcome = forward_ordinary_family_copy(
                reg,
                send,
                me.local_node_id,
                cert.instance_id,
                payload,
                generic_hops,
                family_deadline,
            )
            .await;
            timing.admission_ms += admission_started.elapsed().as_millis();
            any_sent |= outcome == DirectAdmission::Accepted;
            match outcome {
                DirectAdmission::Accepted => timing.evidence.source_accepted += 1,
                DirectAdmission::TimedOut => timing.evidence.source_timed_out += 1,
                _ => timing.evidence.source_rejected += 1,
            }
            if matches!(
                outcome,
                DirectAdmission::TimedOut | DirectAdmission::Rejected
            ) {
                source_failed = true;
                break;
            }
            continue;
        }
        for (recipient, hops) in [
            (Recipient::any(device), hops),
            (
                Recipient::specific(send.dst_node_id, cert.instance_id),
                identity_hops,
            ),
        ] {
            // Relay dedup precedes recipient resolution. Each addressing
            // path needs its own outer id, retaining identical ciphertext
            // sealed once for the same device. Ratchet/app replay authority
            // still admits the first logical signal only.
            let mut nonce = [0u8; 32];
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut nonce);
            let envelope = DeliveryEnvelope {
                recipient,
                sender_node_id: me.local_node_id,
                src_app_id: send.src_app_id,
                app_id: send.app_id,
                endpoint_id: send.endpoint_id,
                content_id: *blake3::hash(&nonce).as_bytes(),
                created_at: now,
                ttl_secs: veil_proto::delivery::FORWARD_REALTIME_TTL_SECS,
                payload: payload.clone(),
                trace_id: 0,
                require_ack: false,
            };
            let bytes = envelope.encode();
            for hop in hops.into_iter().take(3) {
                timing.evidence.source_attempts += 1;
                let admission_started = std::time::Instant::now();
                let packetized =
                    send_packetized_control(reg, &envelope, &hop, local_priority, family_deadline)
                        .await;
                timing.admission_ms += admission_started.elapsed().as_millis();
                if let Some(sent) = packetized {
                    if sent {
                        timing.evidence.source_accepted += 1;
                    } else {
                        timing.evidence.source_rejected += 1;
                    }
                    any_sent |= sent;
                    continue;
                }
                let datagram = reg.has_neutral_forward_datagram_transport(&hop);
                let mut header =
                    FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
                header.set_priority(veil_proto::priority::INTERACTIVE);
                header.body_len = (32 + bytes.len() + 8 + 1 + usize::from(datagram) * 2) as u32;
                let mut frame = codec::encode_header(&header).to_vec();
                frame.extend_from_slice(&hop);
                frame.extend_from_slice(&bytes);
                frame.extend_from_slice(&0u64.to_be_bytes());
                frame.push(0);
                if datagram {
                    frame.push(veil_proto::delivery::FORWARD_TRAFFIC_CLASS_MARKER);
                    frame.push(veil_proto::priority::INTERACTIVE);
                }
                // Keep the endpoint's signaling producer separate from its
                // primary media producer. The relay header remains neutral.
                let sent = reg.send_to(&hop, local_priority, frame);
                if sent {
                    timing.evidence.source_accepted += 1;
                } else {
                    timing.evidence.source_rejected += 1;
                }
                any_sent |= sent;
            }
        }
    }
    FamilyRelayResult {
        accepted: any_sent,
        source_failed,
        host_failed,
        timing,
    }
}

/// Hand `frame`, sealed for the instance `sealed_for`, to the device it is
/// sealed for — and to no other.
///
/// An identity-addressed send used to go to every live device of the
/// identity (`send_to_peer_or_identity`), whatever the frame was sealed for;
/// all but one could only refuse it. A frame with no seal, or one addressed to
/// a device rather than an identity, keeps that path unchanged. The sealed
/// device having no live session is `false`: the caller then relays it, and
/// [`without_other_devices`] keeps the relay from taking it through a
/// sibling.
fn hand_to_sealed_device(
    reg: &dyn FrameBroadcaster,
    dst: &[u8; 32],
    sealed_for: Option<[u8; 16]>,
    instance_of: &dyn Fn(&[u8; 32]) -> [u8; 16],
    priority: u8,
    frame: Vec<u8>,
) -> bool {
    let Some(instance) = sealed_for else {
        return reg.send_to_peer_or_identity(dst, priority, frame);
    };
    let devices = reg.devices_of(dst);
    if devices.is_empty() {
        return reg.send_to_peer_or_identity(dst, priority, frame);
    }
    match devices
        .iter()
        .find(|device| instance_of(device) == instance)
    {
        Some(device) => reg.send_to(device, priority, frame),
        None => false,
    }
}

/// Relay hops for a frame sealed for one device of `dst`, without the
/// identity's OTHER live devices: relayed through a sibling, the frame is
/// delivered to that sibling as its own identity's, which refuses it.
fn without_other_devices(
    hops: Vec<[u8; 32]>,
    reg: &dyn FrameBroadcaster,
    dst: &[u8; 32],
    sealed_for: Option<[u8; 16]>,
    instance_of: &dyn Fn(&[u8; 32]) -> [u8; 16],
) -> Vec<[u8; 32]> {
    let Some(instance) = sealed_for else {
        return hops;
    };
    let devices = reg.devices_of(dst);
    hops.into_iter()
        .filter(|hop| !devices.contains(hop) || instance_of(hop) == instance)
        .collect()
}

pub(crate) fn ordinary_relay_hops(
    discovered: Option<[u8; 32]>,
    dst: &[u8; 32],
    route_cache: Option<&RwLock<veil_routing::RouteCache>>,
    session_tx_registry: &dyn FrameBroadcaster,
    will_seal: bool,
) -> Vec<[u8; 32]> {
    let mut hops = Vec::new();
    if let Some(hop) = discovered {
        hops.push(hop);
    }
    if let Some(cache) = route_cache {
        for alt in rlock!(cache).lookup_all(dst) {
            if &alt != dst && !hops.contains(&alt) {
                hops.push(alt);
            }
        }
    }
    if will_seal {
        for peer in relay_hops_to_try(dst, route_cache, session_tx_registry) {
            if !hops.contains(&peer) {
                hops.push(peer);
            }
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
    ///
    /// The allow is narrowed to the builds where it is TRUE. A blanket one
    /// covers the test build too, where this variant does have constructors —
    /// so if those ever go, nothing would say the variant had stopped being a
    /// seam and started being dead (report24, dead-code table).
    #[cfg_attr(not(test), allow(dead_code))]
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
    pub(crate) source_received_at: std::time::Instant,
    /// Sender scheduling only; never copied into a network header or payload.
    pub local_priority: u8,
    pub(crate) local_work: Option<veil_types::local_lossy_work::LocalLossyCell>,
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

// Payload, ACK key, and the identity snapshot that supplied AEAD context.
type RatchetSeal = (Vec<u8>, [u8; 32], [u8; 32]);

/// Seal `data` through the ratchet, if everything it needs is in hand.
///
/// Returns the payload, per-message delivery-ACK key and sealing identity,
/// or `None` when
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
// The final admission check and key consumption share the native store lock.
// A blocked host floor never grants unratcheted/plaintext fallback.
async fn seal_with_host_floor(
    store: &veil_e2e::RatchetStore,
    expected_epoch: u64,
    deadline: tokio::time::Instant,
    me: &veil_e2e::RatchetIdentity,
    peer: veil_e2e::PeerRatchetKeys<'_>,
    data: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), veil_e2e::RatchetSpliceError> {
    let key = veil_e2e::ConversationKey {
        local_instance_id: me.local_instance_id,
        peer_node_id: *peer.node_id,
        peer_instance_id: *peer.instance_id,
    };
    let mut waiting = false;
    loop {
        let pending = store
            .host_publication_pending(expected_epoch, &key)
            .map_err(|_| veil_e2e::RatchetSpliceError::HostPublicationClosed)?;
        if waiting && tokio::time::Instant::now() >= deadline {
            return Err(veil_e2e::RatchetSpliceError::HostReservationRequired);
        }
        if waiting && pending {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            continue;
        }
        let keys = veil_e2e::PeerRatchetKeys {
            node_id: peer.node_id,
            instance_id: peer.instance_id,
            mlkem_ek: peer.mlkem_ek,
            ratchet_pk: peer.ratchet_pk,
            authorized_until_unix: peer.authorized_until_unix,
        };
        match veil_e2e::ratchet::seal_for_host(
            store,
            me,
            keys,
            data,
            veil_util::unix_secs_now_u64(),
            expected_epoch,
        ) {
            Err(veil_e2e::RatchetSpliceError::HostReservationRequired)
                if tokio::time::Instant::now() < deadline =>
            {
                waiting = true;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            result => return result,
        }
    }
}

async fn try_ratchet_seal_checked(
    ctx: &IpcSendContext,
    dst_node_id: &[u8; 32],
    data: &[u8],
    cached_only: bool,
    expected_epoch: u64,
    host_deadline: tokio::time::Instant,
) -> Result<Option<RatchetSeal>, ()> {
    let resolved = async {
        let ratchet = ctx.ratchet.as_ref()?;
        // Cheap gate before anything expensive: no device identity, no ratchet.
        let me = ratchet.identity()?;
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
        //
        // AND UNDER WHICH NAME IS ITS CERTIFICATE PUBLISHED? Not necessarily the
        // one this send addressed. A certificate lives at
        // `dht_key(identity, instance_id)`, while a send names a transport
        // destination — an identity for a contact, a DEVICE for a sibling or for
        // any peer we reach by one of its devices. The two coincide on a
        // single-device peer, which is why keying the lookup on the destination
        // went unnoticed, and diverge on exactly the multi-device case. The same
        // correction is already recorded in `offline_seal.rs` for our own
        // devices: asking under a device id computes a key nobody ever wrote to.
        //
        // The session's proof carries BOTH names, from one validation, so they
        // cannot disagree.
        // No live session: if the destination is one of OUR devices, the pair
        // comes from our own document instead — the identity the sibling's frames
        // arrive under, so the conversation we seal in is the one we open in.
        // How long finding the recipient's certificate took. A send that has to
        // walk the DHT for it waits seconds, and the sends behind it in the same
        // burst wait too — a slow seal is logged so a stall has a name.
        let resolve_started = std::time::Instant::now();
        let session_pairing = ctx.session_instance_lookup.as_deref().and_then(|lookup| {
            // Linking preserves the physical key while replacing the temporary
            // identity. A still-live pre-link session can retain that old identity
            // until its next handshake. Our current master-authorized document is
            // authoritative for our siblings, before any stale session snapshot.
            lookup
                .own_device_pairing(dst_node_id)
                .or_else(|| lookup.session_pairing(dst_node_id))
        });
        // After a cold restart the peer can answer over relays, without a direct
        // session. Its verified certificate still binds physical device, identity
        // and instance. An old certificate under the physical address is not a
        // replacement for this identity binding.
        let may_use_delegation =
            session_pairing.is_none_or(|pairing| pairing.identity == *dst_node_id);
        let mut certificate_pairing = may_use_delegation
            .then(|| {
                ratchet.verified_pairing_for_device(dst_node_id, veil_util::unix_secs_now_u64())
            })
            .flatten();
        let mut cold_cert = None;
        if may_use_delegation
            && certificate_pairing.is_none()
            && let Some(identity) = resolver.identity_hint_for_device(dst_node_id)
        {
            let certs = if cached_only {
                resolver.resolve_device_certs_cached(identity)
            } else {
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    resolver.resolve_device_certs(identity),
                )
                .await
                .ok()?
            };
            let now = veil_util::unix_secs_now_u64();
            let mut matching = certs.into_iter().filter(|(device, cert)| {
                device == dst_node_id && cert.node_id == identity && now <= cert.valid_until_unix
            });
            let (_, cert) = matching.next()?;
            if matching.any(|(_, other)| other.instance_id != cert.instance_id) {
                return None;
            }
            certificate_pairing = Some((identity, cert.instance_id));
            cold_cert = Some(cert);
        }
        // A session can still describe the pre-link self identity. A current
        // verified delegation replaces that self name, but never another
        // identity's authenticated session or our current own-device document.
        let pairing = certificate_pairing
            .map(|(identity, instance)| veil_types::SessionPairing { identity, instance })
            .or(session_pairing);
        let session_instance = pairing
            .map(|p| p.instance)
            .or_else(|| {
                ctx.session_instance_lookup
                    .as_deref()
                    .and_then(|lookup| lookup.session_instance(dst_node_id))
            })
            .or_else(|| ratchet.reply_instance(dst_node_id, veil_util::unix_secs_now_u64()));
        // What a CERTIFICATE is looked up under. The destination remains what the
        // frame is routed to; only the key changes, and only when a session or a
        // current verified device certificate has proved the identity binding.
        let cert_key = pairing.map_or(*dst_node_id, |p| p.identity);
        let paired = if cold_cert.is_some() {
            cold_cert
        } else {
            match session_instance {
                Some(instance) => {
                    match resolver.resolve_cert_for_instance_cached(cert_key, instance) {
                        Some(c) => Some(c),
                        None if cached_only => None,
                        None => resolver.resolve_cert_for_instance(cert_key, instance).await,
                    }
                }
                // No live session, or a legacy handshake that proved no instance:
                // nothing named a device, so the singular resolve below stays the
                // answer — which is today's behaviour, and exact for the
                // single-instance peer.
                None => None,
            }
        };

        // Local records first. The full walk is three DHT rounds and this is the
        // ordinary send path; the 30-minute verified-cert cache above it means a
        // peer costs that walk once, not once per message.
        //
        // Prefer the named endpoint. The compatibility fallback stays sealed;
        // direct fan-out verifies the resulting target before handing it to a
        // session. Returning no seal here would instead lose sender proof.
        let cert = match paired {
            Some(c) => c,
            // This address was bound to ONE instance by a current certificate.
            // A failed refresh must not replace it with another sibling's key.
            None if certificate_pairing.is_some() => return None,
            None => match resolver.resolve_cert_cached(cert_key) {
                Some(c) => c,
                None if cached_only => return None,
                None => resolver.resolve_cert(cert_key).await?,
            },
        };
        let resolve_ms = resolve_started.elapsed().as_millis();
        if resolve_ms >= 1_000 {
            log::warn!(
                "ratchet.seal_slow dst={} resolve_ms={resolve_ms} device_named={}",
                veil_util::bytes_to_hex(&dst_node_id[..4]),
                session_instance.is_some(),
            );
        }

        Some((ratchet, me, cert))
    }
    .await;
    if let Some(ratchet) = &ctx.ratchet {
        let state = ratchet.store.host_publication_state();
        if state.epoch != expected_epoch || (state.epoch != 0 && !state.active) {
            return Err(());
        }
    }
    let Some((ratchet, me, cert)) = resolved else {
        return Ok(None);
    };
    match seal_with_host_floor(
        &ratchet.store,
        expected_epoch,
        host_deadline,
        &me,
        veil_e2e::PeerRatchetKeys {
            node_id: &cert.node_id,
            instance_id: &cert.instance_id,
            mlkem_ek: &cert.mlkem_ek,
            ratchet_pk: &cert.ratchet_x25519_pk,
            authorized_until_unix: cert.valid_until_unix,
        },
        data,
    )
    .await
    {
        Ok((payload, ack_key)) => Ok(Some((payload, ack_key, me.local_node_id))),
        Err(
            veil_e2e::RatchetSpliceError::HostReservationRequired
            | veil_e2e::RatchetSpliceError::HostPublicationClosed,
        ) => Err(()),
        Err(veil_e2e::RatchetSpliceError::CertificateExpired { .. }) if expected_epoch != 0 => {
            Err(())
        }
        Err(e) => {
            log::debug!(
                "ratchet.seal_failed dst={} {e}",
                veil_util::bytes_to_hex(&dst_node_id[..4])
            );
            Ok(None)
        }
    }
}

/// Where the time of one send went, written when the send ends if it took a
/// second or more. A burst of sends after a restart was measured waiting over a
/// minute inside the node with nothing in the log to say which step held it.
struct SendTiming {
    started: std::time::Instant,
    dst: std::cell::Cell<[u8; 4]>,
    plan_ms: std::cell::Cell<u128>,
    seal_ms: std::cell::Cell<u128>,
    path: std::cell::Cell<&'static str>,
    family: std::cell::Cell<FamilySendTiming>,
}

impl SendTiming {
    fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            dst: std::cell::Cell::new([0; 4]),
            plan_ms: std::cell::Cell::new(0),
            seal_ms: std::cell::Cell::new(0),
            path: std::cell::Cell::new("unknown"),
            family: std::cell::Cell::new(FamilySendTiming::default()),
        }
    }
}

impl Drop for SendTiming {
    fn drop(&mut self) {
        let total = self.started.elapsed().as_millis();
        let family = self.family.get();
        if total >= 1_000 || (crate::route_trace::is_enabled() && family.certificates > 0) {
            let (event, level) = if total >= 1_000 {
                ("ipc.send_slow", log::Level::Warn)
            } else {
                ("ipc.send_sample", log::Level::Info)
            };
            log::log!(
                level,
                "{event} at={} dst={} total_ms={total} plan_ms={} seal_ms={} path={} family_resolve_ms={} family_seal_ms={} family_admission_ms={} family_certificates={} family_evidence={:?}",
                veil_util::unix_secs_now_u64(),
                veil_util::bytes_to_hex(&self.dst.get()),
                self.plan_ms.get(),
                self.seal_ms.get(),
                self.path.get(),
                family.resolve_ms,
                family.seal_ms,
                family.admission_ms,
                family.certificates,
                family.evidence,
            );
        }
    }
}

pub(crate) async fn handle_ipc_send(
    sink: &mut SendReply<'_>,
    body: &[u8],
    ctx: &IpcSendContext,
) -> std::io::Result<()> {
    let timing = SendTiming::new();
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
        .get(veil_proto::AppIpcSendPayload::FLAGS_RANGE)
        .and_then(|v| <[u8; 4]>::try_from(v).ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0);
    let relay_wire_realtime = raw_flags & veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME != 0;
    let relay_control_compat = raw_flags & veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT != 0;
    let request_host_epoch = ctx
        .ratchet
        .as_ref()
        .map_or(0, |r| r.store.host_publication_state().epoch);
    let short_control = raw_flags & veil_proto::ipc::IPC_SEND_FLAG_LOCAL_SHORT_CONTROL != 0;
    let short_deadline = ctx.source_received_at + veil_proto::ipc::LOCAL_SHORT_DATAGRAM_MAX_AGE;
    let relay_realtime = relay_wire_realtime || relay_control_compat;
    // One bounded ingress wait for the entire control request, not another
    // five seconds for every recipient/hop if ordinary source ingress stalls.
    let control_source_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    // Only a locally parsed application request selects this source channel.
    // RelayForward's wire class remains neutral, and a peer cannot request it.
    let local_priority = if (relay_control_compat || short_control)
        && ctx.local_priority == veil_proto::priority::INTERACTIVE
    {
        veil_proto::ipc::LOCAL_SIGNALING_LANE
    } else {
        ctx.local_priority
    };
    let relay_media_sealed = raw_flags & veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED != 0;
    let send = match AppIpcSendPayload::decode(body) {
        Ok(s) => s,
        Err(_) => return Ok(()), // drop malformed
    };

    if short_control
        && (!relay_media_sealed
            || !relay_wire_realtime
            || send.require_ack
            || ctx.local_priority != veil_proto::priority::INTERACTIVE)
    {
        return Ok(());
    }
    if short_control && std::time::Instant::now() >= short_deadline {
        return app_send_ok(sink, false).await;
    }

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

    crate::route_trace::sealed_local_sample("handler_enter", local_priority, body);

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
                    .send_authenticated_on_local_lane(
                        ctx.local_priority,
                        send.dst_node_id,
                        send.app_id,
                        send.endpoint_id,
                        &send.data,
                    )
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
    // * `relay_wire_realtime` — call media is sealed under per-call keys.
    //   Compatibility call control needs ratchet origin authentication too:
    //   an ML-KEM-only offer is a claim and the app correctly refuses it.
    //   That lane uses only cached certificates so it never waits for DHT.
    // * `relay_media_sealed` — already authenticated and encrypted end to end
    //   by the media codec; the whole point of that flag is to pass the cell
    //   through untouched.
    let ratchet_ok = !send.anonymous && !relay_wire_realtime && !relay_media_sealed;
    let remote = send.dst_node_id != *local_node_id;
    // Keep this binding across async resolution: an ordinary device reply
    // without its exact delegated certificate must not fall back to its old
    // standalone physical key or plaintext.
    let delegated_device = !relay_control_compat
        && ratchet_ok
        && remote
        && !send.my_other_devices
        && ctx
            .session_instance_lookup
            .as_deref()
            .and_then(|lookup| lookup.own_device_pairing(&send.dst_node_id))
            .is_none()
        && ctx.ratchet.as_ref().is_some_and(|ratchet| {
            ratchet.identity().is_some()
                && (ratchet
                    .verified_pairing_for_device(&send.dst_node_id, veil_util::unix_secs_now_u64())
                    .is_some()
                    || ctx
                        .mlkem_ek_resolver
                        .as_deref()
                        .and_then(|resolver| resolver.identity_hint_for_device(&send.dst_node_id))
                        .is_some())
        });

    // THE PATH BEFORE THE SEAL. A ratchet seal spends a step of the sending
    // chain and the host persists it, whether or not the frame then goes
    // anywhere. It used to come first, so every send that ended in NO_ROUTE
    // still burned a step — and an outbox re-driving a frame to an unreachable
    // peer burned hundreds an hour. The receiver skips at most MAX_SKIP unseen
    // steps; past that nothing opens and the conversation has to start over.
    // Measured on a two-device stand (2026-09-23): one sending chain at 26 240
    // after a day of re-drives into no route, the other side at single digits.
    //
    // So a send with no live direct session finds its relay hops FIRST, and
    // one with none answers NO_ROUTE having sealed nothing. A direct session
    // that dies between this check and the send still falls back to the relay
    // with the very same sealed bytes, as before.
    let direct_live = remote
        && !relay_realtime
        && session_tx_registry.is_some_and(|reg| {
            let active = reg.active_node_ids();
            let devices = reg.devices_of(&send.dst_node_id);
            if devices.is_empty() {
                active.contains(&send.dst_node_id)
            } else {
                devices.iter().any(|device| active.contains(device))
            }
        });
    timing
        .dst
        .set(send.dst_node_id[..4].try_into().unwrap_or([0; 4]));
    let plan_started = std::time::Instant::now();
    let mut planned: Option<PlannedRelay> = None;
    if ratchet_ok
        && remote
        && !direct_live
        && !send.my_other_devices
        && let Some(reg) = session_tx_registry
    {
        let discovered = if relay_control_compat {
            None
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
        // Tentatively sealed: the ratchet is about to seal it. If it then does
        // not, the list is rebuilt below without the live-session tail.
        let hops = ordinary_relay_hops(discovered, &send.dst_node_id, route_cache, reg, true);
        if hops.is_empty() {
            let mut hdr = FrameHeader::new(
                FrameFamily::LocalApp as u8,
                LocalAppMsg::AppSendFailed as u16,
            );
            hdr.body_len = 2;
            let mut frame = codec::encode_header(&hdr).to_vec();
            frame.extend_from_slice(&ipc_send_err::NO_ROUTE.to_be_bytes());
            return sink.write_all(&frame).await;
        }
        planned = Some((discovered, hops));
    }

    // A relay cannot turn ciphertext for an offline sibling into ciphertext
    // for the online endpoint. Resolve and seal each recipient separately.
    // Ordinary sends keep their direct-session path when one exists; control
    // retains its existing fan-out. ACK-tracked legacy requests keep their
    // existing single-envelope tracker contract below.
    if ratchet_ok
        && remote
        && !send.require_ack
        && ctx.ratchet.is_some()
        && ctx.mlkem_ek_resolver.is_some()
        && let Some(reg) = session_tx_registry
        && (relay_control_compat && send.data.len() <= 4096
            || !relay_control_compat
                && !send.my_other_devices
                // A physical reply target is not a family identity. Treating
                // it as one resolves its old self certificate and bypasses
                // try_ratchet_seal's delegated identity binding entirely.
                && !delegated_device
                && ctx
                    .session_instance_lookup
                    .as_deref()
                    .and_then(|lookup| lookup.own_device_pairing(&send.dst_node_id))
                    .is_none()
                && {
                    let active = reg.active_node_ids();
                    !active.contains(&send.dst_node_id)
                        && !reg
                            .devices_of(&send.dst_node_id)
                            .iter()
                            .any(|device| active.contains(device))
                })
    {
        let family_deadline = if relay_control_compat {
            control_source_deadline
        } else {
            tokio::time::Instant::now() + std::time::Duration::from_secs(30)
        };
        // Record attempted paths too: a failed family send used to report
        // path=unknown with zero stage times, hiding the entire source wait.
        timing.path.set(if relay_control_compat {
            "call_device_fanout"
        } else {
            "relay_device_fanout"
        });
        let outcome = send_family_relay_copies(
            ctx,
            &send,
            request_host_epoch,
            family_deadline,
            relay_control_compat,
            local_priority,
            None,
        )
        .await;
        timing.family.set(outcome.timing);
        if outcome.accepted {
            timing.path.set(if relay_control_compat {
                "call_device_fanout"
            } else {
                "relay_device_fanout"
            });
            return app_send_ok(sink, false).await;
        }
        if outcome.host_failed {
            return app_send_error(sink, ipc_send_err::RATCHET_NOT_DURABLE).await;
        }
        if outcome.source_failed {
            return app_send_error(sink, ipc_send_err::NO_ROUTE).await;
        }
    }

    // ONE SEAL PER DEVICE when the address is an identity (defect №35, its
    // identity-addressed half). The transport below hands one frame to EVERY
    // live device of an identity, and a ratchet payload is keyed to exactly
    // one of them: sealed once, it opened at one device and every other one
    // refused it as `NotForThisDevice`, answered "cannot open", and the sender
    // dropped the conversation that was working. Measured on a three-node
    // stand (2026-09-24): 82 such refusals at one device in the three minutes
    // after a restart. And the pairing that keeps a seal on the session's own
    // device never applied here at all — it is looked up by the session's
    // device id, which an identity is not — so even a single live device was
    // sealed to whichever row the certificate cache happened to hold.
    //
    // Each device is sealed under the pairing its own handshake proved, so
    // each frame opens where it lands. Only live devices: a seal spends a
    // chain step, and a device that cannot be handed the frame must not cost
    // one (see "the path before the seal" above). If none of them takes it,
    // the ordinary path below still runs, relay and all.
    if ratchet_ok
        && remote
        && ctx.ratchet.is_some()
        && let Some(reg) = session_tx_registry
    {
        let active = reg.active_node_ids();
        let mut devices: Vec<[u8; 32]> = reg
            .devices_of(&send.dst_node_id)
            .into_iter()
            .filter(|d| active.contains(d))
            .collect();
        if !delegated_device
            && !send.my_other_devices
            && !send.require_ack
            && !relay_control_compat
            && active.contains(&send.dst_node_id)
            && device_matches_identity(ctx, &send.dst_node_id, &send.dst_node_id)
            && !devices.contains(&send.dst_node_id)
            && ctx
                .session_instance_lookup
                .as_deref()
                .and_then(|lookup| lookup.session_instance(&send.dst_node_id))
                .is_some()
        {
            devices.push(send.dst_node_id);
        }
        let mut direct = DirectFamilyRecipients::default();
        for device in &devices {
            if device_matches_identity(ctx, device, &send.dst_node_id) {
                direct.devices.insert(*device);
                direct.instances.insert(device_instance(ctx, device));
            }
        }
        use futures::{StreamExt, stream};
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        timing.plan_ms.set(plan_started.elapsed().as_millis());
        let mut any_sent = false;
        let mut admission_failed = false;
        let mut host_failed = false;
        let mut seal_ms = 0;
        // Scope all admission futures to this IPC request. A full sibling's
        // background queue must not hold up another live device's ciphertext.
        let request = &send;
        let direct_family = &direct;
        let mut copies = stream::iter(devices)
            .map(|device| async move {
                let device = &device;
                if !device_matches_identity(ctx, device, &request.dst_node_id) {
                    return (*device, false, ipc_send_err::NO_ROUTE, 0);
                }
                let seal_started = std::time::Instant::now();
                let sealed = match try_ratchet_seal_checked(
                    ctx,
                    device,
                    &request.data,
                    false,
                    request_host_epoch,
                    deadline,
                )
                .await
                {
                    Ok(sealed) => sealed,
                    Err(()) => return (*device, false, ipc_send_err::RATCHET_NOT_DURABLE, 0),
                };
                let seal_ms = seal_started.elapsed().as_millis();
                if !device_matches_identity(ctx, device, &request.dst_node_id) {
                    return (*device, false, ipc_send_err::NO_ROUTE, seal_ms);
                }
                let copy_for = sealed
                    .as_ref()
                    .and_then(|(payload, _, _)| veil_e2e::payload_instances(payload))
                    .map(|(_, to)| to);
                if copy_for.is_some_and(|to| to != device_instance(ctx, device)) {
                    log::info!(
                        "ratchet.sealed_for_another_device dst={} device={} — copy not sent",
                        veil_util::bytes_to_hex(&request.dst_node_id[..4]),
                        veil_util::bytes_to_hex(&device[..4]),
                    );
                    return (*device, false, 0, seal_ms);
                }
                let mut outcome = if let Some((payload, _, _)) = &sealed
                    && payload.len() > veil_proto::budget::LOCAL_ENVELOPE_SEGMENT_DATA_BYTES
                {
                    admit_direct_sealed(ctx, request, *device, payload, deadline).await
                } else if sealed.is_none()
                    && request.data.len() > veil_proto::budget::LOCAL_ENVELOPE_SEGMENT_DATA_BYTES
                    && ctx
                        .session_instance_lookup
                        .as_deref()
                        .is_some_and(|lookup| lookup.supports_direct_app_chunks(device))
                {
                    admit_direct_plain(ctx, request, *device, deadline).await
                } else if reg.send_to(
                    device,
                    local_priority,
                    app_send_frame(request, sealed.as_ref().map(|(p, _, _)| p.as_slice())),
                ) {
                    DirectAdmission::Accepted
                } else {
                    DirectAdmission::Missing
                };
                if outcome == DirectAdmission::Missing
                    && !relay_control_compat
                    && !request.my_other_devices
                    && !request.require_ack
                    && !delegated_device
                    && let Some((payload, _, sender)) = &sealed
                    && let Some(instance) = copy_for
                {
                    // A closed path is distinct from source backpressure.
                    // Reuse this device's seal, never a singular sibling's row.
                    let mut hops =
                        ordinary_relay_hops(None, &request.dst_node_id, route_cache, reg, true);
                    hops.retain(|hop| hop != device);
                    hops.sort_by_key(|hop| direct_family.devices.contains(hop));
                    let forwarded = forward_ordinary_family_copy(
                        reg,
                        request,
                        *sender,
                        instance,
                        payload.clone(),
                        hops,
                        deadline,
                    )
                    .await;
                    if forwarded != DirectAdmission::Missing {
                        outcome = forwarded;
                    }
                }
                let accepted = outcome == DirectAdmission::Accepted;
                if accepted && sealed.is_some() {
                    emit_e2e_plaintext_capture(capture_tx, local_node_id, device, &request.data);
                }
                (
                    *device,
                    accepted,
                    if matches!(
                        outcome,
                        DirectAdmission::TimedOut | DirectAdmission::Rejected
                    ) {
                        ipc_send_err::NO_ROUTE
                    } else {
                        0
                    },
                    seal_ms,
                )
            })
            .buffer_unordered(8);
        let relay_copies = async {
            if !send.require_ack
                && !relay_control_compat
                && !send.my_other_devices
                && !delegated_device
                && !direct.instances.is_empty()
                && ctx
                    .session_instance_lookup
                    .as_deref()
                    .and_then(|lookup| lookup.own_device_pairing(&send.dst_node_id))
                    .is_none()
            {
                send_family_relay_copies(
                    ctx,
                    &send,
                    request_host_epoch,
                    deadline,
                    false,
                    local_priority,
                    Some(&direct),
                )
                .await
            } else {
                FamilyRelayResult::default()
            }
        };
        let direct_copies = async {
            while let Some((_, accepted, failed, elapsed)) = copies.next().await {
                any_sent |= accepted;
                admission_failed |= failed == ipc_send_err::NO_ROUTE;
                host_failed |= failed == ipc_send_err::RATCHET_NOT_DURABLE;
                seal_ms += elapsed;
            }
        };
        let (_, relayed) = tokio::join!(direct_copies, relay_copies);
        timing.family.set(relayed.timing);
        any_sent |= relayed.accepted;
        admission_failed |= relayed.source_failed;
        host_failed |= relayed.host_failed;
        timing.seal_ms.set(seal_ms);
        if any_sent {
            timing.path.set("identity_fanout");
            return app_send_ok(sink, send.require_ack).await;
        }
        if host_failed {
            return app_send_error(sink, ipc_send_err::RATCHET_NOT_DURABLE).await;
        }
        if admission_failed {
            return app_send_error(sink, ipc_send_err::NO_ROUTE).await;
        }
    }

    if timing.plan_ms.get() == 0 {
        timing.plan_ms.set(plan_started.elapsed().as_millis());
    }
    let seal_started = std::time::Instant::now();
    let sealed = if ratchet_ok && remote {
        match try_ratchet_seal_checked(
            ctx,
            &send.dst_node_id,
            &send.data,
            relay_control_compat,
            request_host_epoch,
            if relay_control_compat {
                control_source_deadline
            } else {
                tokio::time::Instant::now() + std::time::Duration::from_secs(30)
            },
        )
        .await
        {
            Ok(sealed) => sealed,
            Err(()) => return app_send_error(sink, ipc_send_err::RATCHET_NOT_DURABLE).await,
        }
    } else {
        None
    };
    if delegated_device && sealed.is_none() {
        return app_send_error(sink, ipc_send_err::NO_E2E_KEY).await;
    }
    // Ratchet associated data names the stable identity, not this transport
    // device. Carry the exact identity snapshot used by the seal: a cold peer
    // cannot recover it from an unknown sending instance or physical address.
    let sealed_sender = sealed.as_ref().map(|(_, _, sender)| *sender);
    timing.seal_ms.set(seal_started.elapsed().as_millis());
    timing.path.set(if planned.is_some() {
        "relay_planned"
    } else {
        "direct_or_fallback"
    });

    // WHICH DEVICE THIS SEAL IS FOR (defect №35, its fallback half). The
    // per-device fan-out above did not take the frame, so it was sealed once,
    // to whichever instance the identity's certificate lookup named — chosen
    // with no regard for which devices are live to hand it to. Measured on a
    // stand after a session between two sibling devices flapped: 160 frames a
    // device had sealed to ITS OWN instance, handed to its sibling, which
    // could only refuse them; and a contact's frames sealed to one device of
    // an identity, handed to the other.
    let sealed_for: Option<[u8; 16]> = sealed
        .as_ref()
        .and_then(|(payload, _, _)| veil_e2e::payload_instances(payload))
        .map(|(_, to)| to);
    let own_instance = ctx
        .ratchet
        .as_ref()
        .and_then(|r| r.identity())
        .map(|i| i.local_instance_id);
    if sealed_for.is_some() && sealed_for == own_instance {
        // Nobody but this device can open it. Refuse the send instead: the
        // outbox keeps the frame and re-drives it, by which time the fan-out
        // has a live device to seal for.
        log::info!(
            "ratchet.sealed_for_self dst={} — the fallback seal named this device; not sent",
            veil_util::bytes_to_hex(&send.dst_node_id[..4])
        );
        let mut hdr = FrameHeader::new(
            FrameFamily::LocalApp as u8,
            LocalAppMsg::AppSendFailed as u16,
        );
        hdr.body_len = 2;
        let mut frame = codec::encode_header(&hdr).to_vec();
        frame.extend_from_slice(&ipc_send_err::NO_ROUTE.to_be_bytes());
        return sink.write_all(&frame).await;
    }

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
        let mut direct_admission_failed = false;
        let sent = if !relay_realtime
            && let Some((payload, _, _)) = &sealed
            && payload.len() > source_segment_bytes(reg, payload.len())
        {
            let devices = reg.devices_of(&send.dst_node_id);
            let selected = if devices.is_empty() {
                Some(send.dst_node_id)
            } else {
                devices
                    .into_iter()
                    .find(|device| sealed_for == Some(device_instance(ctx, device)))
            };
            if let Some(device) = selected {
                match admit_direct_sealed(
                    ctx,
                    &send,
                    device,
                    payload,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                )
                .await
                {
                    DirectAdmission::Accepted => true,
                    DirectAdmission::Missing => false,
                    DirectAdmission::TimedOut | DirectAdmission::Rejected => {
                        direct_admission_failed = true;
                        false
                    }
                }
            } else {
                false
            }
        } else if !relay_realtime
            && sealed.is_none()
            && send.data.len() > veil_proto::budget::LOCAL_ENVELOPE_SEGMENT_DATA_BYTES
        {
            use futures::{StreamExt, stream};
            let mut devices = reg.devices_of(&send.dst_node_id);
            if devices.is_empty() {
                devices.push(send.dst_node_id);
            }
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            let request = &send;
            let mut copies = stream::iter(devices)
                .map(|device| async move {
                    if device != request.dst_node_id
                        && !device_matches_identity(ctx, &device, &request.dst_node_id)
                    {
                        return DirectAdmission::Rejected;
                    }
                    if ctx
                        .session_instance_lookup
                        .as_deref()
                        .is_some_and(|lookup| lookup.supports_direct_app_chunks(&device))
                    {
                        admit_direct_plain(ctx, request, device, deadline).await
                    } else if reg.send_to(&device, local_priority, app_send_frame(request, None)) {
                        // Old decoders retain their existing typed whole-frame contract.
                        DirectAdmission::Accepted
                    } else {
                        DirectAdmission::Missing
                    }
                })
                .buffer_unordered(8);
            let mut accepted = false;
            while let Some(outcome) = copies.next().await {
                accepted |= outcome == DirectAdmission::Accepted;
                direct_admission_failed |= matches!(
                    outcome,
                    DirectAdmission::TimedOut | DirectAdmission::Rejected
                );
            }
            if accepted {
                direct_admission_failed = false;
            }
            accepted
        } else {
            !relay_realtime
                && hand_to_sealed_device(
                    reg,
                    &send.dst_node_id,
                    sealed_for,
                    &|device| device_instance(ctx, device),
                    local_priority,
                    app_send_frame(&send, sealed.as_ref().map(|(p, _, _)| p.as_slice())),
                )
        };
        if direct_admission_failed {
            // Queue pressure is not a broken route. Never inject the original
            // large frame or another full copy after a source admission timeout.
            return app_send_error(sink, ipc_send_err::NO_ROUTE).await;
        }
        if sent && sealed.is_some() {
            emit_e2e_plaintext_capture(capture_tx, local_node_id, &send.dst_node_id, &send.data);
        }

        if !sent {
            // No direct session. Try relay via RouteCache next-hop.
            // If the cache is empty, attempt reactive route discovery:
            // flood a ROUTE_REQUEST and wait up to 500 ms for a response.
            let forced_relay_hops = if let Some((discovered, hops)) = planned.take() {
                // Found before the seal. Kept as found only if the payload is
                // in fact sealed; otherwise the live-session tail goes.
                if sealed.is_some() || relay_media_sealed || peer_mlkem_keys.is_some() {
                    hops
                } else {
                    ordinary_relay_hops(discovered, &send.dst_node_id, route_cache, reg, false)
                }
            } else if relay_realtime {
                if relay_media_sealed {
                    // Use the current relay immediately. A discovered route
                    // improves subsequent packets without pausing this one.
                    warm_media_route(ctx, send.dst_node_id);
                }
                relay_hops_to_try(&send.dst_node_id, route_cache, reg)
            } else {
                // Sealed below whichever way it goes: by the ratchet already
                // (`sealed`), verbatim when the media codec sealed it, or by
                // the ML-KEM branch — which either seals or answers
                // NO_E2E_KEY, never plaintext. Only the no-E2E-infrastructure
                // node would relay in the clear, and it gets no fallback.
                let will_seal = sealed.is_some() || relay_media_sealed || peer_mlkem_keys.is_some();
                let discovered = try_lookup_or_discover(
                    &send.dst_node_id,
                    local_node_id,
                    route_cache,
                    session_tx_registry,
                    route_updated,
                    peer_mlkem_keys,
                    ctx.pending_recursive.as_deref(),
                )
                .await;
                ordinary_relay_hops(discovered, &send.dst_node_id, route_cache, reg, will_seal)
            };
            let source_lane =
                if relay_wire_realtime && local_priority == veil_proto::priority::INTERACTIVE {
                    veil_proto::header::priority::REALTIME
                } else {
                    local_priority
                };
            let mut forced_relay_hops = without_other_devices(
                forced_relay_hops,
                reg,
                &send.dst_node_id,
                sealed_for,
                &|device| device_instance(ctx, device),
            );
            // Preserve working source channels when discovery changes cached
            // hop order. Negotiated generic datagrams alone do not prove an
            // independent source child is ready. Keep all fallback hops and
            // route order within equal readiness/transport groups.
            // This does not change relay policy or independent-flow consent.
            if relay_media_sealed {
                crate::source_paths::prefer_datagrams(&mut forced_relay_hops, reg);
                crate::source_paths::warm_preferred_sources(&forced_relay_hops, reg, source_lane);
                crate::source_paths::prefer_ready_sources(&mut forced_relay_hops, reg, source_lane);
            }
            if !forced_relay_hops.is_empty() {
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
                let final_payload = if let Some((payload, key, _)) = sealed {
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
                    // Only while its owner still vouches for it; an expired
                    // one is a miss, and a miss walks the DHT for a current
                    // certificate (report20 V18-M12).
                    let now_unix = veil_util::unix_secs_now_u64();
                    let mut recipient_ek = rlock!(keys)
                        .get(&send.dst_node_id)
                        .and_then(|(key, _)| key.usable_at(now_unix).map(<[u8]>::to_vec));

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
                    // Ratchet ciphertext belongs to one exact endpoint. Do
                    // not hand it to an arbitrary sibling, which cannot open
                    // it and would request a needless reset of healthy chains.
                    recipient: sealed_for.map_or_else(
                        || veil_proto::recipient::Recipient::any(send.dst_node_id),
                        |instance| {
                            veil_proto::recipient::Recipient::specific(send.dst_node_id, instance)
                        },
                    ),
                    sender_node_id: if send.anonymous {
                        [0u8; 32]
                    } else {
                        sealed_sender.unwrap_or(*local_node_id)
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
                // (already-E2E) payload into small endpoint-owned pieces, each
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
                if (!relay_realtime
                    && envelope.payload.len() > source_segment_bytes(reg, envelope.payload.len()))
                    || envelope.payload.len() > veil_proto::delivery::ENVELOPE_CHUNKING_THRESHOLD
                {
                    let segment_size = if relay_realtime {
                        veil_proto::budget::MAX_CHUNK_PAYLOAD
                    } else {
                        source_segment_bytes(reg, envelope.payload.len())
                    };
                    let want_ack = send.require_ack;
                    let orig_content_id = envelope.content_id;
                    let Some(chunks) = EnvelopeChunks::new(&envelope, want_ack, segment_size)
                    else {
                        return app_send_error(sink, ipc_send_err::NO_ROUTE).await;
                    };
                    let hops_to_try = forced_relay_hops.clone();

                    // Stream every chunk to the first hop that accepts them all.
                    // (Reassembly is index-deduped, so the partial chunks left on
                    // a hop that dies mid-stream are harmless on retry.)
                    let mut delivered = false;
                    let remaining_secs = envelope
                        .created_at
                        .saturating_add(envelope.ttl_secs as u64)
                        .saturating_sub(veil_util::unix_secs_now_u64())
                        .min(30);
                    let admission_deadline = tokio::time::Instant::now()
                        + std::time::Duration::from_secs(remaining_secs);
                    if !relay_realtime && remaining_secs == 0 {
                        return app_send_error(sink, ipc_send_err::NO_ROUTE).await;
                    }
                    for next_hop in &hops_to_try {
                        let frames: Vec<_> = chunks.frames_for(*next_hop).collect();
                        // Await the endpoint's background source credits. Relay
                        // headers stay neutral; only a missing/closed hop tries
                        // an alternative, using the same indexed transfer.
                        let admitted = tokio::time::timeout_at(admission_deadline, async {
                            for frame in &frames {
                                let accepted = if relay_realtime {
                                    reg.send_to(next_hop, local_priority, frame.clone())
                                } else {
                                    reg.send_reliable_to(next_hop, frame.clone()).await
                                };
                                if !accepted {
                                    return false;
                                }
                            }
                            true
                        })
                        .await;
                        let all_ok = admitted.as_ref().is_ok_and(|accepted| *accepted);
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
                        if admitted.is_err() {
                            // A slow source queue is not evidence of a dead hop.
                            // Do not spray another full copy after the deadline.
                            return app_send_error(sink, ipc_send_err::NO_ROUTE).await;
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
                    // Neutral loss-tolerant data never asks a relay for a
                    // faster queue. Older relays use their ordered ordinary
                    // transport; new peers explicitly negotiate datagram support.
                    // An agreed generic datagram connection keeps control out
                    // of a stalled reliable writer. Preserve the old suffix-
                    // free format when the next hop did not negotiate it.
                    let datagram = relay_wire_realtime
                        || (relay_control_compat
                            && reg.has_neutral_forward_datagram_transport(&next_hop));
                    let class_suffix_len = if datagram { 2 } else { 0 };
                    let body_len =
                        32 + env_bytes.len() + 8 + 1 + attempt_suffix_len + class_suffix_len;
                    let mut hdr = FrameHeader::new(
                        veil_proto::family::FrameFamily::Delivery as u8,
                        DeliveryMsg::Forward as u16,
                    );
                    hdr.set_priority(veil_proto::priority::INTERACTIVE);
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
                    if datagram {
                        frame.push(veil_proto::delivery::FORWARD_TRAFFIC_CLASS_MARKER);
                        frame.push(veil_proto::header::priority::INTERACTIVE);
                    }
                    frame
                };

                // Try primary hop first; on failure fall back to cached alternatives.
                // Primary then alternatives — computed once above, the
                // live-session tail included when the payload is sealed.
                let hops_to_try: Vec<[u8; 32]> = forced_relay_hops.clone();
                let mut any_send_failed = false;
                // Queue admission at a first hop is not end-to-end receipt.
                // Small, locally primary lossy cells take a second path so a
                // black-holed/slow accepted hop cannot silence the endpoint.
                // Keep ciphertext and content_id identical: the receiver's
                // existing replay/dedup gates admit only the first arrival.
                // This is an origin decision, with no new wire metadata or
                // relay scheduling policy. Secondary/bulk keeps one copy.
                let diverse_primary = relay_media_sealed
                    && local_priority == veil_proto::priority::REALTIME
                    && send.data.len() <= 512;
                let fanout_limit = if relay_control_compat {
                    3
                } else if diverse_primary {
                    2
                } else {
                    1
                };
                let mut accepted_copies = 0;
                let mut accepted_datagram_copy = false;
                for (compat_attempts, next_hop) in hops_to_try.into_iter().enumerate() {
                    if relay_control_compat && compat_attempts >= 3 {
                        break;
                    }
                    // Datagram hops precede ordered hops. Once a primary copy
                    // is admitted to a negotiated datagram hop, do not also feed
                    // a legacy canonical writer: a stale duplicate there can
                    // pressure the endpoint even when the other path progresses.
                    // If every datagram admission fails, retain ordered fallback.
                    let datagram_hop = reg.has_neutral_forward_datagram_transport(&next_hop);
                    if diverse_primary && accepted_datagram_copy && !datagram_hop {
                        break;
                    }
                    let fwd_frame = make_fwd_frame(next_hop);
                    // Only legacy media calls use the default primary slot.
                    // Compatibility control retains its local signaling slot,
                    // just like the per-device copies above.
                    let packetized = if relay_control_compat {
                        send_packetized_control(
                            reg,
                            &envelope,
                            &next_hop,
                            source_lane,
                            control_source_deadline,
                        )
                        .await
                    } else {
                        None
                    };
                    let relayed = packetized.unwrap_or_else(|| match ctx.local_work.as_ref() {
                        Some(cell) => reg.send_local_lossy_work(
                            &next_hop,
                            source_lane,
                            fwd_frame.clone(),
                            cell.clone(),
                        ),
                        None if short_control => reg.send_to_before(
                            &next_hop,
                            source_lane,
                            fwd_frame.clone(),
                            short_deadline,
                        ),
                        None => reg.send_to(&next_hop, source_lane, fwd_frame.clone()),
                    });
                    if relay_media_sealed {
                        if relayed {
                            crate::route_trace::sealed_relay_hop_sample(
                                "relay_queued",
                                local_priority,
                                &next_hop,
                                body,
                            );
                        } else {
                            crate::route_trace::sealed_relay_hop_sample(
                                "relay_refused",
                                local_priority,
                                &next_hop,
                                body,
                            );
                        }
                        crate::route_trace::observe(
                            *local_node_id,
                            send.dst_node_id,
                            local_priority,
                            next_hop,
                            relayed,
                            reg.has_neutral_forward_datagram_transport(&next_hop),
                        );
                    }
                    if relayed {
                        // Bounded origin fan-out for lifecycle controls and
                        // small primary cells. ACK-mode keeps its existing
                        // single-hop tracker semantics.
                        if fanout_limit > 1 && !send.require_ack {
                            accepted_copies += 1;
                            accepted_datagram_copy |= datagram_hop;
                            if accepted_copies >= fanout_limit {
                                return Ok(());
                            }
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
                    // A packetized source can time out on local backpressure.
                    // That is not evidence that the cached route is dead.
                    if packetized.is_some() {
                        continue;
                    }
                    // send_to returned false: session is closed or full.
                    // Evict this dead hop from the cache so future lookups
                    // don't return the same unreachable next-hop (254.3).
                    if let Some(cache) = route_cache {
                        wlock!(cache).invalidate_hop(&send.dst_node_id, &next_hop);
                    }
                    any_send_failed = true;
                }
                if accepted_copies != 0 {
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

    app_send_ok(sink, send.require_ack).await
}

/// APP_SEND_OK — fire-and-forget clients (e.g. ogate) skip the ack.
///
/// Phase E24 (2026-05-22): writing AppSendOk per APP_SEND added a full
/// IPC frame syscall round-trip per IP packet on the hot path —
/// single-stream throughput cap measured ~150 Mbps (12K pps) before
/// and after this fix.  Honoring `require_ack=false` halves the IPC
/// syscall count per send and frees enough budget to push pps higher.
async fn app_send_error(sink: &mut SendReply<'_>, code: u16) -> std::io::Result<()> {
    let mut header = FrameHeader::new(
        FrameFamily::LocalApp as u8,
        LocalAppMsg::AppSendFailed as u16,
    );
    header.body_len = 2;
    let mut frame = codec::encode_header(&header).to_vec();
    frame.extend_from_slice(&code.to_be_bytes());
    sink.write_all(&frame).await
}

async fn app_send_ok(sink: &mut SendReply<'_>, require_ack: bool) -> std::io::Result<()> {
    if require_ack {
        let ok_hdr = FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppSendOk as u16);
        sink.write_all(&codec::encode_header(&ok_hdr)).await
    } else {
        Ok(())
    }
}

/// The OVL1 frame one direct session is handed: APP_SEND_SEALED around a
/// ratchet payload, or the app's bytes as a plain APP_SEND.
///
/// A distinct frame type rather than the same one carrying different bytes:
/// `data` is whatever the application put there, so no marker byte inside it
/// could be reserved without stealing a byte some app legitimately sends.
fn app_send_frame(send: &AppIpcSendPayload, sealed: Option<&[u8]>) -> Vec<u8> {
    let app_msg_type = match sealed {
        Some(_) => veil_proto::family::AppMsg::AppSendSealed,
        None => veil_proto::family::AppMsg::AppSend,
    };
    let ovl1_payload = AppSendPayload {
        src_app_id: send.src_app_id,
        app_id: send.app_id,
        endpoint_id: send.endpoint_id,
        data: match sealed {
            Some(payload) => veil_bufpool::pooled_shared_from_vec(payload.to_vec()),
            None => send.data.clone(),
        },
    };
    let payload_bytes = ovl1_payload.encode();
    // Large sealed sends use existing addressed Forward chunks before this
    // builder. Unsealed bytes retain their typed AppSend path: interpreting
    // their first byte as an envelope marker would corrupt legitimate binary
    // data. Packetizing those requires a distinct negotiated wire format.
    let mut hdr = FrameHeader::new(
        veil_proto::family::FrameFamily::App as u8,
        app_msg_type as u16,
    );
    hdr.body_len = payload_bytes.len() as u32;
    let mut frame = codec::encode_header(&hdr).to_vec();
    frame.extend_from_slice(&payload_bytes);
    frame
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
    local_priority: u8,
    short_control: bool,
) -> std::io::Result<()> {
    // Rate check — shared bucket with APP_SEND to prevent RT flooding.
    if rate_limited(wh, rate_limiter).await? {
        return Ok(());
    }

    let send = match AppIpcRtSendPayload::decode(body) {
        Ok(s) => s,
        Err(_) => return Ok(()), // drop malformed — no response
    };
    crate::route_trace::sealed_rt_local_sample("handler_enter", local_priority, body);

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

    // Same reason as the interactive path: the destination may name an
    // identity, and the session is registered under a device of it.
    let source_lane = if local_priority == veil_proto::priority::INTERACTIVE {
        veil_proto::ipc::LOCAL_SIGNALING_LANE
    } else {
        local_priority.min(3)
    };
    let sent = if short_control {
        if local_priority != veil_proto::priority::INTERACTIVE {
            return Ok(());
        }
        reg.send_to_peer_or_identity_before(
            &send.dst_node_id,
            source_lane,
            frame,
            std::time::Instant::now() + veil_proto::ipc::LOCAL_SHORT_DATAGRAM_MAX_AGE,
        )
    } else {
        reg.send_to_peer_or_identity(&send.dst_node_id, source_lane, frame)
    };
    crate::route_trace::sealed_rt_local_sample(
        if sent {
            "direct_queued"
        } else {
            "direct_refused"
        },
        local_priority,
        body,
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

    /// An ordinary send with no route still has somewhere to go: any live
    /// session, nearest first — but only for a payload that will be sealed.
    #[test]
    fn an_ordinary_send_falls_back_to_a_live_session_only_when_sealed() {
        let dst = [0x10; 32];
        let nearest = [0x11; 32];
        let farther = [0x30; 32];
        let peers = ActivePeers(vec![farther, nearest]);

        assert_eq!(
            ordinary_relay_hops(None, &dst, None, &peers, true),
            vec![nearest, farther],
            "no discovered route and no cache: the live sessions carry it",
        );
        assert!(
            ordinary_relay_hops(None, &dst, None, &peers, false).is_empty(),
            "a frame that would travel in the clear is never handed to an \
             arbitrary session",
        );
    }

    /// The discovered route and its cached alternatives keep their place in
    /// front; the live-session tail only follows them.
    #[test]
    fn an_ordinary_send_tries_the_known_route_first() {
        let dst = [0x10; 32];
        let routed = [0x40; 32];
        let cached = [0x50; 32];
        let live = [0x11; 32];
        let mut cache = veil_routing::RouteCache::new(Duration::from_secs(60));
        cache.insert(dst, cached, 1, 2);
        let cache = RwLock::new(cache);
        let peers = ActivePeers(vec![live, dst]);

        assert_eq!(
            ordinary_relay_hops(Some(routed), &dst, Some(&cache), &peers, true),
            vec![routed, cached, live],
        );
        assert_eq!(
            ordinary_relay_hops(Some(routed), &dst, Some(&cache), &peers, false),
            vec![routed, cached],
            "unsealed keeps exactly the old list",
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
    async fn try_ratchet_seal(
        ctx: &super::IpcSendContext,
        dst: &[u8; 32],
        data: &[u8],
        cached: bool,
    ) -> Option<super::RatchetSeal> {
        super::try_ratchet_seal_checked(
            ctx,
            dst,
            data,
            cached,
            ctx.ratchet
                .as_ref()
                .map_or(0, |r| r.store.host_publication_state().epoch),
            tokio::time::Instant::now() + std::time::Duration::from_secs(30),
        )
        .await
        .expect("fixture has no blocked host publication")
    }

    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use veil_proto::AppIpcSendPayload;

    const ME: [u8; 32] = [0xA0u8; 32];
    const PEER: [u8; 32] = [0xB0u8; 32];
    const RELAY: [u8; 32] = [0xE0u8; 32];
    const PEER_INSTANCE: [u8; 16] = [0xB1u8; 16];
    const MY_INSTANCE: [u8; 16] = [0xA1u8; 16];
    /// PEER's second device in [`family_fixture`].
    const SIBLING_INSTANCE: [u8; 16] = [0xB2u8; 16];

    /// Captures everything the handler hands to a session.
    #[derive(Default)]
    struct Outbox {
        live: Vec<[u8; 32]>,
        datagram: Vec<[u8; 32]>,
        sent: Mutex<Vec<([u8; 32], Vec<u8>)>>,
        /// The devices the session layer knows under identity `PEER`. Empty
        /// for every single-name fixture, which keeps them on the path they
        /// always took.
        family: Vec<[u8; 32]>,
    }

    struct LaneCapture(Mutex<Vec<(u8, Vec<u8>)>>, Vec<[u8; 32]>);

    impl Default for LaneCapture {
        fn default() -> Self {
            Self(Mutex::new(Vec::new()), vec![RELAY])
        }
    }

    impl FrameBroadcaster for LaneCapture {
        fn send_to(&self, peer: &[u8; 32], priority: u8, bytes: Vec<u8>) -> bool {
            if !self.1.contains(peer) {
                return false;
            }
            lock!(self.0).push((priority, bytes));
            true
        }
        fn send_direct_app_chunk_to<'a>(
            &'a self,
            peer: &'a [u8; 32],
            frame: Vec<u8>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
            self.send_reliable_to(peer, frame)
        }
        fn send_to_all_with_priority(&self, _priority: u8, _bytes: Arc<[u8]>) {}
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            self.1.clone()
        }
    }

    struct ExpiringCapture(LaneCapture, Mutex<Vec<std::time::Instant>>);
    impl FrameBroadcaster for ExpiringCapture {
        fn send_to(&self, _: &[u8; 32], _: u8, _: Vec<u8>) -> bool {
            panic!("short control must preserve its expiry")
        }
        fn send_to_before(
            &self,
            peer: &[u8; 32],
            lane: u8,
            bytes: Vec<u8>,
            expires_at: std::time::Instant,
        ) -> bool {
            if std::time::Instant::now() >= expires_at {
                return false;
            }
            lock!(self.1).push(expires_at);
            self.0.send_to(peer, lane, bytes)
        }
        fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {}
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            self.0.active_node_ids()
        }
    }

    #[tokio::test]
    async fn short_control_deadlines_are_local_on_direct_and_relay_and_expire_before_routing() {
        let capture = Arc::new(ExpiringCapture(
            LaneCapture(Mutex::new(Vec::new()), vec![PEER, RELAY]),
            Mutex::new(Vec::new()),
        ));
        let mut wh = sink().await;
        let direct = AppIpcRtSendPayload {
            dst_node_id: PEER,
            src_app_id: [1; 32],
            dst_app_id: [2; 32],
            endpoint_id: 13,
            seq: 0,
            timestamp_us: 0,
            marker: 0,
            payload_type: 0,
            data: vec![9; 32],
        }
        .encode();
        handle_rt_send(
            &mut wh,
            &direct,
            Some(&*capture),
            None,
            &mut None,
            veil_proto::priority::INTERACTIVE,
            true,
        )
        .await
        .unwrap();
        let (lane, frame) = lock!(capture.0.0).pop().unwrap();
        assert_eq!(lane, veil_proto::ipc::LOCAL_SIGNALING_LANE);
        assert_eq!(codec::decode_header(&frame).unwrap().flags, 0);
        let direct_deadline = lock!(capture.1).pop().unwrap();
        assert!(
            direct_deadline.duration_since(std::time::Instant::now())
                <= veil_proto::ipc::LOCAL_SHORT_DATAGRAM_MAX_AGE
        );

        let fx = fixture(vec![RELAY]);
        let mut ctx = fx.ctx(false);
        ctx.session_tx_registry = Some(capture.clone());
        let sealed = [
            veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC.as_slice(),
            &[7; 48],
        ]
        .concat();
        let mut body = payload(false, &sealed);
        let flags = veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
            | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED
            | veil_proto::ipc::IPC_SEND_FLAG_LOCAL_SHORT_CONTROL;
        body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
        handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
            .await
            .unwrap();
        let (lane, frame) = lock!(capture.0.0).pop().unwrap();
        assert_eq!(lane, veil_proto::ipc::LOCAL_SIGNALING_LANE);
        assert_eq!(
            codec::decode_header(&frame).unwrap().priority(),
            veil_proto::priority::INTERACTIVE
        );
        let forward =
            veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                .unwrap();
        assert_eq!(forward.envelope.payload, sealed);
        assert_eq!(
            lock!(capture.1).pop().unwrap(),
            ctx.source_received_at + veil_proto::ipc::LOCAL_SHORT_DATAGRAM_MAX_AGE
        );
        ctx.source_received_at -= std::time::Duration::from_millis(201);
        handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
            .await
            .unwrap();
        assert!(lock!(capture.0.0).is_empty());
        assert!(lock!(capture.1).is_empty());
    }

    #[tokio::test]
    async fn relay_local_lane_does_not_change_the_inter_node_packet() {
        let fx = fixture(vec![RELAY]);
        let capture = Arc::new(LaneCapture::default());
        let mut ctx = fx.ctx(false);
        ctx.session_tx_registry = Some(Arc::clone(&capture) as Arc<dyn FrameBroadcaster>);
        let sealed = [
            veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC.as_slice(),
            &[7; 48],
        ]
        .concat();
        let mut body = payload_to(PEER, &sealed);
        let flags = veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
            | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED;
        body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
        let mut wh = sink().await;
        let mut previous = None;
        for lane in [
            veil_proto::priority::REALTIME,
            veil_proto::priority::BULK,
            veil_proto::priority::BACKGROUND,
            veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
        ] {
            ctx.local_priority = lane;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                .await
                .unwrap();
            let (priority, bytes) = lock!(capture.0).pop().expect("forward queued");
            assert_eq!(
                priority, lane,
                "only the sender's local scheduler sees the choice"
            );
            let header = codec::decode_header(&bytes).unwrap();
            assert_eq!(
                header.priority(),
                veil_proto::priority::INTERACTIVE,
                "relay wire is neutral for every local lane"
            );
            let mut forward =
                veil_proto::delivery::ForwardPayload::decode(&bytes[veil_proto::HEADER_SIZE..])
                    .unwrap();
            assert_eq!(forward.envelope.payload, sealed);
            assert_eq!(
                forward.traffic_class,
                Some(veil_proto::priority::INTERACTIVE)
            );
            // Delivery bookkeeping may vary; transport/application fields may not.
            forward.envelope.content_id = [0; 32];
            forward.envelope.created_at = 0;
            if let Some(previous) = previous {
                assert_eq!(forward, previous);
            }
            previous = Some(forward);
        }
        // Compact call state uses the local signaling source while retaining
        // the same presealed payload and neutral inter-node representation.
        body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(
            &(flags | veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT).to_be_bytes(),
        );
        ctx.local_priority = veil_proto::priority::INTERACTIVE;
        handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
            .await
            .unwrap();
        let (priority, bytes) = lock!(capture.0).pop().expect("compact control queued");
        assert_eq!(priority, veil_proto::ipc::LOCAL_SIGNALING_LANE);
        assert_eq!(
            codec::decode_header(&bytes).unwrap().priority(),
            veil_proto::priority::INTERACTIVE
        );
        let mut forward =
            veil_proto::delivery::ForwardPayload::decode(&bytes[veil_proto::HEADER_SIZE..])
                .unwrap();
        forward.envelope.content_id = [0; 32];
        forward.envelope.created_at = 0;
        assert_eq!(Some(forward), previous);
    }

    #[tokio::test]
    async fn loss_tolerant_relay_payload_keeps_its_existing_cell_and_lane() {
        let fx = fixture(vec![RELAY]);
        let capture = Arc::new(LaneCapture::default());
        let mut ctx = fx.ctx(false);
        ctx.session_tx_registry = Some(capture.clone());
        ctx.local_priority = veil_proto::priority::BULK;
        for size in [5000, 70_000] {
            let sealed = [
                veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC.as_slice(),
                vec![7; size].as_slice(),
            ]
            .concat();
            let mut body = payload(false, &sealed);
            let flags = veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
                | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED;
            body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                .await
                .unwrap();
            let mut frames = lock!(capture.0);
            assert_eq!(frames.len(), if size == 5000 { 1 } else { 2 });
            for (lane, frame) in frames.drain(..) {
                assert_eq!(lane, veil_proto::priority::BULK);
                let f =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                if size == 5000 {
                    assert_eq!(f.envelope.payload, sealed);
                } else {
                    assert!(
                        veil_proto::delivery::ChunkedEnvelopePayload::decode(&f.envelope.payload)
                            .unwrap()
                            .data
                            .len()
                            <= veil_proto::budget::MAX_CHUNK_PAYLOAD
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn routed_envelope_segments_keep_crypto_metadata_ack_and_wire_bound() {
        for size in [12_000, 100_000] {
            let fx = fixture(vec![RELAY]);
            let capture = Arc::new(LaneCapture::default());
            let mut ctx = fx.ctx(true);
            ctx.session_tx_registry = Some(capture.clone());
            let tracker = Arc::new(Mutex::new(veil_pending_ack::PendingAckTracker::default()));
            ctx.pending_ack = Some(tracker.clone());
            let data: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut request = AppIpcSendPayload::decode(&payload(false, &data)).unwrap();
            request.require_ack = true;
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &request.encode(), &ctx)
                .await
                .unwrap();
            let frames = lock!(capture.0);
            assert!(
                frames.len() > 1,
                "even a sub-64KiB payload must be packetized"
            );
            let mut joined = Vec::new();
            let mut transfer = None;
            let mut cids = std::collections::HashSet::new();
            for (index, (lane, frame)) in frames.iter().enumerate() {
                assert_eq!(*lane, veil_proto::priority::BACKGROUND);
                assert_eq!(
                    codec::decode_header(frame).unwrap().priority(),
                    veil_proto::priority::INTERACTIVE
                );
                assert!(
                    frame.len() + 16 + 40 <= 4096,
                    "oversized source chunk: {}",
                    frame.len()
                );
                let f =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                assert_eq!(f.next_hop_node_id, RELAY);
                assert_eq!(f.envelope.recipient.node_id, PEER);
                assert_eq!(f.envelope.sender_node_id, ME);
                assert_eq!(f.envelope.src_app_id, request.src_app_id);
                assert_eq!(f.envelope.app_id, request.app_id);
                assert_eq!(f.envelope.endpoint_id, request.endpoint_id);
                assert!(!f.envelope.require_ack);
                assert!(cids.insert(f.envelope.content_id));
                let chunk =
                    veil_proto::delivery::ChunkedEnvelopePayload::decode(&f.envelope.payload)
                        .unwrap();
                assert_eq!(chunk.chunk_index, index as u32);
                assert_eq!(chunk.chunk_count as usize, frames.len());
                assert!(chunk.require_ack);
                let identity = (chunk.transfer_id, chunk.orig_content_id, chunk.total_size);
                assert_eq!(*transfer.get_or_insert(identity), identity);
                joined.extend(chunk.data);
            }
            let (_, original, total) = transfer.unwrap();
            assert_eq!(joined.len(), total as usize);
            assert_eq!(
                lock!(tracker).tracked_frame_count(&original),
                Some(frames.len())
            );
            assert_ne!(lock!(tracker).peek_ack_info(&original).unwrap().2, [0; 32]);
            let opened = fx
                .peer
                .open_payload(&ME, &joined, veil_util::unix_secs_now_u64())
                .unwrap();
            assert!(opened.authenticated);
            assert_eq!(opened.plaintext, data);
        }
    }

    #[tokio::test]
    async fn routed_envelope_waits_for_source_capacity_without_invalidating_route() {
        struct BoundedSource(tokio::sync::mpsc::Sender<Vec<u8>>);
        impl FrameBroadcaster for BoundedSource {
            fn send_to(&self, peer: &[u8; 32], _: u8, _: Vec<u8>) -> bool {
                assert_ne!(*peer, RELAY, "chunk producer must await source credit");
                false
            }
            fn send_reliable_to<'a>(
                &'a self,
                peer: &'a [u8; 32],
                frame: Vec<u8>,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>
            {
                Box::pin(async move { *peer == RELAY && self.0.send(frame).await.is_ok() })
            }
            fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {}
            fn active_node_ids(&self) -> Vec<[u8; 32]> {
                vec![RELAY]
            }
        }
        let fx = fixture(vec![RELAY]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.send(vec![]).await.unwrap();
        let mut ctx = fx.ctx(true);
        ctx.session_tx_registry = Some(Arc::new(BoundedSource(tx)));
        let data = vec![9; 12_000];
        let body = payload(false, &data);
        let mut wh = sink().await;
        let mut sink = SendReply::Inline(&mut wh);
        let mut send = Box::pin(handle_ipc_send(&mut sink, &body, &ctx));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut send)
                .await
                .is_err()
        );
        assert_eq!(
            fx.route_cache.try_write().unwrap().lookup(&PEER),
            Some(RELAY)
        );
        assert!(rx.recv().await.unwrap().is_empty());
        let mut frames = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    result = &mut send => { result.unwrap(); break; }
                    frame = rx.recv() => { frames.push(frame.unwrap()); }
                }
            }
        })
        .await
        .unwrap();
        while let Ok(frame) = rx.try_recv() {
            frames.push(frame);
        }
        let joined: Vec<u8> = frames
            .iter()
            .flat_map(|frame| {
                let f =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                veil_proto::delivery::ChunkedEnvelopePayload::decode(&f.envelope.payload)
                    .unwrap()
                    .data
            })
            .collect();
        assert_eq!(
            fx.peer
                .open_payload(&ME, &joined, veil_util::unix_secs_now_u64())
                .unwrap()
                .plaintext,
            data
        );
        assert_eq!(rlock!(fx.route_cache).lookup(&PEER), Some(RELAY));
    }

    #[tokio::test]
    async fn background_application_send_keeps_sealing_on_direct_and_relay_routes() {
        for direct in [true, false] {
            let fx = fixture(if direct {
                vec![PEER, RELAY]
            } else {
                vec![RELAY]
            });
            let capture = Arc::new(LaneCapture(Mutex::new(Vec::new()), fx.outbox.live.clone()));
            let mut ctx = fx.ctx(true);
            ctx.local_priority = veil_proto::priority::BACKGROUND;
            ctx.session_tx_registry = Some(capture.clone() as Arc<dyn FrameBroadcaster>);
            let mut wh = sink().await;
            handle_ipc_send(
                &mut SendReply::Inline(&mut wh),
                &payload(false, b"file chunk"),
                &ctx,
            )
            .await
            .unwrap();
            let sent = lock!(capture.0);
            assert_eq!(sent.len(), 1);
            let (priority, frame) = &sent[0];
            assert_eq!(*priority, veil_proto::priority::BACKGROUND);
            let header = codec::decode_header(frame).unwrap();
            assert_eq!(
                header.priority(),
                if direct {
                    0
                } else {
                    veil_proto::priority::INTERACTIVE
                },
                "local lane is never a relay priority"
            );
            let sealed = if direct {
                veil_proto::app::AppSendPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                    .unwrap()
                    .data
                    .to_vec()
            } else {
                let forward =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                assert_ne!(
                    forward.traffic_class,
                    Some(veil_proto::priority::BACKGROUND)
                );
                forward.envelope.payload
            };
            let opened = fx
                .peer
                .open_payload(&ME, &sealed, veil_util::unix_secs_now_u64())
                .unwrap();
            assert!(opened.authenticated);
            assert_eq!(opened.plaintext, b"file chunk");
        }
    }

    #[tokio::test]
    async fn background_anonymous_send_uses_only_the_onion_sender() {
        let fx = fixture(vec![PEER, RELAY]);
        let sender = Arc::new(super::direct_reply_sentinel_tests::RecordingSender::default());
        let mut ctx = fx.ctx(true);
        ctx.local_priority = veil_proto::priority::BACKGROUND;
        ctx.anon_onion_sender = Some(sender.clone());
        let mut body = AppIpcSendPayload::decode(&payload(false, b"private chunk")).unwrap();
        body.anonymous_authenticated = true;
        let mut wh = sink().await;
        handle_ipc_send(&mut SendReply::Inline(&mut wh), &body.encode(), &ctx)
            .await
            .unwrap();
        assert!(
            fx.taken().is_empty(),
            "no direct or ordinary relay fallback"
        );
        assert_eq!(
            *sender.lanes.lock().unwrap(),
            vec![(
                veil_proto::priority::BACKGROUND,
                PEER,
                body.app_id,
                body.endpoint_id,
                b"private chunk".to_vec()
            )]
        );
    }

    #[tokio::test]
    async fn direct_local_lane_is_stripped_before_network_encoding() {
        let capture = LaneCapture(Mutex::new(Vec::new()), vec![PEER]);
        let mut wh = sink().await;
        let send = AppIpcRtSendPayload {
            dst_node_id: PEER,
            src_app_id: [1; 32],
            dst_app_id: [2; 32],
            endpoint_id: 13,
            seq: 9,
            timestamp_us: 100,
            marker: 0,
            payload_type: 0,
            data: vec![8; 64],
        }
        .encode();
        let mut previous = None;
        for lane in [
            veil_proto::priority::REALTIME,
            veil_proto::priority::INTERACTIVE,
            veil_proto::priority::BULK,
            veil_proto::priority::BACKGROUND,
        ] {
            handle_rt_send(&mut wh, &send, Some(&capture), None, &mut None, lane, false)
                .await
                .unwrap();
            let (priority, bytes) = lock!(capture.0).pop().unwrap();
            assert_eq!(
                priority,
                if lane == veil_proto::priority::INTERACTIVE {
                    veil_proto::ipc::LOCAL_SIGNALING_LANE
                } else {
                    lane
                }
            );
            assert_eq!(codec::decode_header(&bytes).unwrap().flags, 0);
            if let Some(previous) = previous {
                assert_eq!(bytes, previous);
            }
            previous = Some(bytes);
        }
    }

    impl FrameBroadcaster for Outbox {
        fn has_datagram_transport(&self, peer: &[u8; 32]) -> bool {
            // All live fixture peers offer generic QUIC; only the explicit
            // subset negotiated the neutral forwarding format.
            self.live.contains(peer)
        }
        fn has_neutral_forward_datagram_transport(&self, peer: &[u8; 32]) -> bool {
            self.datagram.contains(peer)
        }
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
        fn devices_of(&self, identity: &[u8; 32]) -> Vec<[u8; 32]> {
            if *identity == PEER {
                self.family.clone()
            } else {
                Vec::new()
            }
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

    /// A session to a DEVICE whose handshake proved it belongs to `PEER`.
    ///
    /// The shape a multi-device peer actually produces, and the one a
    /// single-device fixture cannot show: the transport destination and the
    /// name the certificate is published under are DIFFERENT values.
    struct PairedDevice {
        device: [u8; 32],
        pairing: veil_types::SessionPairing,
    }

    impl veil_types::SessionInstanceLookup for PairedDevice {
        fn session_instance(&self, peer: &[u8; 32]) -> Option<[u8; 16]> {
            (*peer == self.device).then_some(self.pairing.instance)
        }
        fn session_pairing(&self, peer: &[u8; 32]) -> Option<veil_types::SessionPairing> {
            (*peer == self.device).then_some(self.pairing)
        }
    }

    struct AdoptedSiblingSession {
        device: [u8; 32],
        current: veil_types::SessionPairing,
    }
    impl veil_types::SessionInstanceLookup for AdoptedSiblingSession {
        fn session_instance(&self, peer: &[u8; 32]) -> Option<[u8; 16]> {
            (*peer == self.device).then_some(self.current.instance)
        }
        fn session_pairing(&self, peer: &[u8; 32]) -> Option<veil_types::SessionPairing> {
            (*peer == self.device).then_some(veil_types::SessionPairing {
                identity: [0xEE; 32],
                instance: self.current.instance,
            })
        }
        fn own_device_pairing(&self, peer: &[u8; 32]) -> Option<veil_types::SessionPairing> {
            (*peer == self.device).then_some(self.current)
        }
    }

    #[tokio::test]
    async fn current_own_device_document_overrides_a_pre_link_session_identity() {
        let mut fx = fixture(vec![RELAY]);
        // The same physical device and instance have just adopted our identity;
        // a still-open session describes its discarded temporary identity.
        let physical = [0xD9; 32];
        let peer_ring = fx.peer.seed_ring.read().unwrap().clone();
        fx.peer.adopt_identity(ME, peer_ring.clone());
        fx.certs = Arc::new(Certs(veil_types::VerifiedPeerCert {
            node_id: ME,
            instance_id: PEER_INSTANCE,
            mlkem_ek: peer_ring.current_ek().to_vec(),
            ratchet_x25519_pk: peer_ring.current_ratchet_pk(),
            cert_version: 1,
            valid_until_unix: u64::MAX,
        }));
        let mut ctx = fx.ctx(true);
        ctx.session_instance_lookup = Some(Arc::new(AdoptedSiblingSession {
            device: physical,
            current: veil_types::SessionPairing {
                identity: ME,
                instance: PEER_INSTANCE,
            },
        }));
        let sealed = try_ratchet_seal(&ctx, &physical, b"first linked-device history", false).await;
        let (payload, _, sender) =
            sealed.expect("seal under the current identity, not its old name");
        assert_eq!(sender, ME);
        assert_eq!(
            fx.peer
                .open_payload(&ME, &payload, veil_util::unix_secs_now_u64())
                .unwrap()
                .plaintext,
            b"first linked-device history"
        );
    }

    /// Several live sessions, each to a device whose handshake proved it
    /// belongs to `PEER` — what a person with two devices online looks like
    /// from a contact's node.
    struct FamilySessions(Vec<([u8; 32], veil_types::SessionPairing)>);

    impl veil_types::SessionInstanceLookup for FamilySessions {
        fn session_instance(&self, peer: &[u8; 32]) -> Option<[u8; 16]> {
            self.session_pairing(peer).map(|p| p.instance)
        }
        fn session_pairing(&self, peer: &[u8; 32]) -> Option<veil_types::SessionPairing> {
            self.0.iter().find(|(d, _)| d == peer).map(|(_, p)| *p)
        }
    }

    /// A resolver holding one verified row per device of a peer — the steady
    /// state for a multi-device family after the fan-out paths have walked it.
    struct FamilyCerts(Vec<veil_types::VerifiedPeerCert>);

    impl veil_types::MlKemEkResolver for FamilyCerts {
        fn resolve_device_certs_cached(
            &self,
            target: [u8; 32],
        ) -> Vec<([u8; 32], veil_types::VerifiedPeerCert)> {
            self.0
                .iter()
                .filter(|c| c.node_id == target)
                .map(|c| {
                    let mut device = [0u8; 32];
                    device[..16].copy_from_slice(&c.instance_id);
                    (device, c.clone())
                })
                .collect()
        }

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

    /// A linked device has learned only the offline sibling's certificate.
    /// The bounded family lookup must fill the missing endpoint before sealing.
    struct WarmingFamilyCerts {
        rows: FamilyCerts,
        ready: std::sync::atomic::AtomicBool,
    }
    impl veil_types::MlKemEkResolver for WarmingFamilyCerts {
        fn resolve_device_certs_cached(
            &self,
            target: [u8; 32],
        ) -> Vec<([u8; 32], veil_types::VerifiedPeerCert)> {
            let rows = self.rows.resolve_device_certs_cached(target);
            if self.ready.load(std::sync::atomic::Ordering::Relaxed) {
                rows
            } else {
                rows.into_iter().rev().take(1).collect()
            }
        }
        fn resolve_device_certs(&self, target: [u8; 32]) -> veil_types::DeviceCertsFuture<'_> {
            Box::pin(async move {
                self.ready.store(true, std::sync::atomic::Ordering::Relaxed);
                self.resolve_device_certs_cached(target)
            })
        }
        fn resolve_cert_cached(&self, target: [u8; 32]) -> Option<veil_types::VerifiedPeerCert> {
            self.rows.resolve_cert_cached(target)
        }
        fn resolve_cert(
            &self,
            target: [u8; 32],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<veil_types::VerifiedPeerCert>> + Send + '_>,
        > {
            Box::pin(async move { self.resolve_cert_cached(target) })
        }
    }

    struct Fixture {
        /// When set, the session lookup proves that device belongs to `PEER`.
        pairing_device: Option<[u8; 32]>,
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
            valid_until_unix: u64::MAX,
        };
        let route_cache = RwLock::new(veil_routing::RouteCache::new(
            std::time::Duration::from_secs(60),
        ));
        wlock!(route_cache).insert(PEER, RELAY, 10_000, 2);
        let peer_mlkem = std::sync::RwLock::new(veil_e2e::PeerMlKemCache::new());
        wlock!(peer_mlkem).insert(
            PEER,
            (
                veil_e2e::PeerMlKemKey::unattested(peer_ring.current_ek().to_vec()),
                std::time::Instant::now(),
            ),
        );
        // The peer knows our device key, as it would after resolving us.
        let peer_rt = ratchet_runtime(PEER, PEER_INSTANCE, peer_ring);
        wlock!(peer_rt.peer_ratchet_keys)
            .entry(ME)
            .or_default()
            .remember(MY_INSTANCE, my_ring.current_ratchet_pk(), u64::MAX);
        Fixture {
            pairing_device: None,
            outbox: Arc::new(Outbox {
                live: live_peers,
                datagram: Vec::new(),
                sent: Mutex::new(Vec::new()),
                family: Vec::new(),
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

    #[tokio::test]
    async fn journaled_direct_and_relay_sends_wait_for_a_committed_native_floor() {
        for direct in [true, false] {
            let fx = fixture(if direct {
                vec![PEER, RELAY]
            } else {
                vec![RELAY]
            });
            let ctx = fx.ctx(true);
            let epoch = fx.me.store.begin_host_publication();
            let mut wh = sink().await;
            let request = payload(false, b"held until commit");
            let mut reply = SendReply::Inline(&mut wh);
            let sending = handle_ipc_send(&mut reply, &request, &ctx);
            let committing = async {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while fx.me.store.host_publication_state().required == 0 {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
                assert!(
                    fx.taken().is_empty(),
                    "not even an unratcheted carrier may escape"
                );
                let key = fx.me.store.keys()[0];
                let at = fx.me.store.send_position(&key).unwrap();
                tokio::time::sleep(Duration::from_millis(65)).await;
                assert_eq!(fx.me.store.send_position(&key).unwrap(), at);
                assert!(fx.taken().is_empty());
                fx.me
                    .store
                    .allow_host_publication(
                        epoch,
                        &key,
                        &[veil_e2e::ratchet::SendPosition {
                            chain: at.chain,
                            next: at.next + 32,
                        }],
                    )
                    .unwrap();
            };
            let (sent, ()) = tokio::join!(sending, committing);
            sent.unwrap();
            let frames = fx.taken();
            assert_eq!(frames.len(), 1);
            let frame = &frames[0].1;
            let sealed = if direct {
                veil_proto::app::AppSendPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                    .unwrap()
                    .data
                    .to_vec()
            } else {
                veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                    .unwrap()
                    .envelope
                    .payload
            };
            let opened = fx
                .peer
                .open_payload(&ME, &sealed, veil_util::unix_secs_now_u64())
                .unwrap();
            assert!(opened.authenticated);
            assert_eq!(opened.plaintext, b"held until commit");
        }
    }

    #[tokio::test]
    async fn a_journaled_wait_deadline_or_retired_owner_never_downgrades() {
        let fx = fixture(vec![PEER, RELAY]);
        let ctx = fx.ctx(true);
        let epoch = fx.me.store.begin_host_publication();
        let result = try_ratchet_seal_checked(
            &ctx,
            &PEER,
            b"deadline",
            false,
            epoch,
            tokio::time::Instant::now() + Duration::from_millis(45),
        )
        .await;
        assert!(result.is_err());
        let key = fx.me.store.keys()[0];
        let before = fx.me.store.send_position(&key).unwrap();
        assert_eq!(
            before.next, 1,
            "only the unpublished initial handshake may consume a key"
        );
        let successor = fx.me.store.begin_host_publication();
        fx.me
            .store
            .allow_host_publication(
                successor,
                &key,
                &[veil_e2e::ratchet::SendPosition {
                    chain: before.chain,
                    next: before.next + 32,
                }],
            )
            .unwrap();
        assert!(
            try_ratchet_seal_checked(
                &ctx,
                &PEER,
                b"old queued request",
                false,
                epoch,
                tokio::time::Instant::now() + Duration::from_secs(1)
            )
            .await
            .is_err()
        );
        assert_eq!(fx.me.store.send_position(&key).unwrap(), before);
        fx.me.store.end_host_publication(successor);
        assert!(
            try_ratchet_seal_checked(
                &ctx,
                &PEER,
                b"closed request",
                false,
                successor,
                tokio::time::Instant::now() + Duration::from_secs(1)
            )
            .await
            .is_err()
        );
        assert_eq!(fx.me.store.send_position(&key).unwrap(), before);
        assert!(fx.taken().is_empty());
    }

    /// PEER as a two-device family: the live session ends at PEER_INSTANCE,
    /// while the resolver's singular answer is the OTHER device — the №35
    /// mismatch, on purpose. Returns the fixture and the sibling's runtime so
    /// tests can prove where a frame is (and is not) openable.
    fn family_fixture() -> (Fixture, veil_e2e::RatchetRuntime) {
        let mut fx = fixture(vec![PEER, RELAY]);
        let sibling_ring = ring(0xC5);
        let peer_ring = std::sync::Arc::clone(&fx.peer.seed_ring.read().expect("ring"));
        let session_row = veil_types::VerifiedPeerCert {
            node_id: PEER,
            instance_id: PEER_INSTANCE,
            mlkem_ek: peer_ring.current_ek().to_vec(),
            ratchet_x25519_pk: peer_ring.current_ratchet_pk(),
            cert_version: 1,
            valid_until_unix: u64::MAX,
        };
        let sibling_row = veil_types::VerifiedPeerCert {
            node_id: PEER,
            instance_id: SIBLING_INSTANCE,
            mlkem_ek: sibling_ring.current_ek().to_vec(),
            ratchet_x25519_pk: sibling_ring.current_ratchet_pk(),
            cert_version: 1,
            valid_until_unix: u64::MAX,
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

    #[tokio::test]
    async fn a_relayed_reply_uses_the_authenticated_speaker_not_an_offline_sibling() {
        let (fx, sibling) = family_fixture();
        let now = veil_util::unix_secs_now_u64();
        for endpoint in [&fx.peer, &sibling] {
            let ring = endpoint.seed_ring.read().unwrap();
            wlock!(fx.me.peer_ratchet_keys)
                .entry(PEER)
                .or_default()
                .remember(
                    endpoint.identity().unwrap().local_instance_id,
                    ring.current_ratchet_pk(),
                    u64::MAX,
                );
        }
        let my_ring = fx.me.seed_ring.read().unwrap().clone();
        let incoming = veil_e2e::ratchet::seal(
            &fx.peer.store,
            &fx.peer.identity().unwrap(),
            veil_e2e::PeerRatchetKeys {
                node_id: &ME,
                instance_id: &MY_INSTANCE,
                mlkem_ek: &my_ring.current_ek(),
                ratchet_pk: &my_ring.current_ratchet_pk(),
                authorized_until_unix: u64::MAX,
            },
            b"online A to D",
            now,
        )
        .unwrap()
        .0;
        assert!(
            fx.me
                .open_payload(&PEER, &incoming, now)
                .unwrap()
                .authenticated
        );
        assert_eq!(fx.me.reply_instance(&PEER, now), Some(PEER_INSTANCE));
        assert_eq!(fx.session_instance, None); // No direct path names an endpoint.
        let (reply, _, _) = try_ratchet_seal(&fx.ctx(true), &PEER, b"D replies to A", true)
            .await
            .unwrap();
        assert_eq!(
            veil_e2e::payload_instances(&reply).unwrap().1,
            PEER_INSTANCE
        );
        assert_eq!(
            fx.peer.open_payload(&ME, &reply, now).unwrap().plaintext,
            b"D replies to A"
        );
        assert!(sibling.open_payload(&ME, &reply, now).is_err());
        wlock!(fx.me.peer_ratchet_keys).remove(&PEER);
        assert_eq!(
            fx.me.reply_instance(&PEER, now),
            None,
            "old held authorization cannot choose a revoked endpoint"
        );
    }

    struct PlainChunkPeers(Vec<[u8; 32]>);
    impl veil_types::SessionInstanceLookup for PlainChunkPeers {
        fn session_instance(&self, _: &[u8; 32]) -> Option<[u8; 16]> {
            None
        }
        fn supports_direct_app_chunks(&self, peer: &[u8; 32]) -> bool {
            self.0.contains(peer)
        }
    }

    fn feed_plain(dispatcher: &veil_dispatcher::FrameDispatcher, frame: &[u8]) {
        let header = codec::decode_header(frame).unwrap();
        assert_eq!(header.family, FrameFamily::App as u8);
        assert_eq!(
            header.msg_type,
            veil_proto::family::AppMsg::AppSendChunk as u16
        );
        assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
        assert!(
            frame.len() + 16 + 40 <= 4096,
            "plain source chunk must fit a 4 KiB bucket"
        );
        let result = dispatcher.dispatch(
            &header,
            &frame[veil_proto::HEADER_SIZE..],
            veil_cfg::NodeId::from(ME),
        );
        assert!(
            matches!(result, veil_dispatcher::DispatchResult::NoResponse),
            "plain dispatch: {result:?}"
        );
    }

    fn take_plain(
        receiver: &mut tokio::sync::mpsc::Receiver<veil_app::registry::AppMessage>,
    ) -> Vec<u8> {
        match receiver.try_recv().expect("real dispatcher must deliver") {
            veil_app::registry::AppMessage::Deliver {
                src_node_id,
                provenance,
                origin_device,
                src_app_id,
                data,
                ..
            } => {
                assert_eq!(src_node_id, ME);
                assert_eq!(src_app_id, [0x11; 32]);
                assert_eq!(origin_device, Some(ME));
                assert_eq!(
                    provenance,
                    veil_app::registry::SenderProvenance::SessionPeer
                );
                data.to_vec()
            }
            other => panic!("unexpected delivery: {other:?}"),
        }
    }

    #[tokio::test]
    async fn direct_plain_chunks_preserve_every_first_byte_metadata_and_once_only_delivery() {
        let fx = fixture(vec![PEER, RELAY]);
        let capture = Arc::new(LaneCapture(Mutex::new(Vec::new()), vec![PEER, RELAY]));
        let mut ctx = fx.ctx(false);
        ctx.session_tx_registry = Some(capture.clone());
        ctx.session_instance_lookup = Some(Arc::new(PlainChunkPeers(vec![PEER])));
        let tracker = Arc::new(Mutex::new(veil_pending_ack::PendingAckTracker::new()));
        ctx.pending_ack = Some(tracker.clone());
        for first in 0..=255u8 {
            // Independent byte-shape cases; do not mistake the ordinary 1000/s
            // abuse limit for a wire codec failure in a 2048-frame test burst.
            let dispatcher = veil_dispatcher::make_test_dispatcher(veil_cfg::NodeRole::Core);
            let (_endpoint, mut receiver) = dispatcher.app_registry.register([0x22; 32], 7, 16);
            let mut data: Vec<_> = (0..12_000).map(|i| (i % 251) as u8).collect();
            data[0] = first;
            let mut request = AppIpcSendPayload::decode(&payload(false, &data)).unwrap();
            request.require_ack = true;
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &request.encode(), &ctx)
                .await
                .unwrap();
            let frames = std::mem::take(&mut *lock!(capture.0));
            assert!(frames.len() > 1, "negotiated plain send must be packetized");
            for (lane, frame) in frames {
                assert_eq!(lane, veil_proto::priority::BACKGROUND);
                feed_plain(&dispatcher, &frame);
                feed_plain(&dispatcher, &frame);
            }
            assert_eq!(take_plain(&mut receiver), data);
            assert!(receiver.try_recv().is_err());
        }
        assert!(lock!(tracker).is_empty());
    }

    #[tokio::test]
    async fn direct_plain_legacy_peer_keeps_existing_typed_frame() {
        let fx = fixture(vec![PEER]);
        let data = vec![0x83; 12_000];
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, &data),
            &fx.ctx(false),
        )
        .await
        .unwrap();
        let sent = fx.taken();
        assert_eq!(sent.len(), 1);
        let header = codec::decode_header(&sent[0].1).unwrap();
        assert_eq!(header.msg_type, veil_proto::family::AppMsg::AppSend as u16);
        assert_eq!(
            veil_proto::app::AppSendPayload::decode(&sent[0].1[veil_proto::HEADER_SIZE..])
                .unwrap()
                .data
                .as_ref(),
            data
        );
    }

    fn direct_receiver(
        runtime: &veil_e2e::RatchetRuntime,
        device: [u8; 32],
        instance: [u8; 16],
    ) -> (
        veil_dispatcher::FrameDispatcher,
        veil_app::registry::EndpointHandle,
        tokio::sync::mpsc::Receiver<veil_app::registry::AppMessage>,
    ) {
        let mut dispatcher = veil_dispatcher::make_test_dispatcher(veil_cfg::NodeRole::Core);
        dispatcher.local_node_id = device;
        dispatcher.local_recipient = Some(Arc::new(move || {
            Some(veil_proto::recipient::Recipient::specific(PEER, instance))
        }));
        dispatcher.crypto = Arc::new(veil_dispatcher::CryptoContext {
            ratchet: Some(runtime.clone()),
            mlkem_keys: rlock!(runtime.seed_ring).clone(),
            ..(*dispatcher.crypto).clone()
        });
        let (endpoint, receiver) = dispatcher.app_registry.register([0x22; 32], 7, 16);
        (dispatcher, endpoint, receiver)
    }

    fn identity_first_relay(
        sender_device: [u8; 32],
        receiver_device: [u8; 32],
    ) -> (veil_dispatcher::FrameDispatcher, veil_session::FrameOutbox) {
        identity_first_relay_instance(sender_device, receiver_device, PEER_INSTANCE)
    }

    fn identity_first_relay_instance(
        sender_device: [u8; 32],
        receiver_device: [u8; 32],
        receiver_instance: [u8; 16],
    ) -> (veil_dispatcher::FrameDispatcher, veil_session::FrameOutbox) {
        use veil_identity::verify::ValidatedIdentity;
        use veil_proto::session::{AttachPayload, CapabilitiesPayload, IdentityPayload, role_bits};
        use veil_session::{RemoteRole, SessionEntry, SessionRegistry, SessionTxRegistry};

        let mut relay = veil_dispatcher::make_test_dispatcher(veil_cfg::NodeRole::Core);
        relay.local_node_id = RELAY;
        let mut sessions = SessionRegistry::new();
        for (device, identity, instance) in [
            (sender_device, ME, MY_INSTANCE),
            (receiver_device, PEER, receiver_instance),
        ] {
            sessions.insert(SessionEntry {
                session_id: device,
                remote_node_id: device,
                remote_identity: IdentityPayload {
                    algo: 0,
                    public_key: vec![0; 32],
                    nonce: vec![],
                    node_id: device,
                    mlkem_pubkey: None,
                },
                remote_capabilities: CapabilitiesPayload {
                    extra_flags2: 0,
                    roles_supported: role_bits::CORE,
                    flags: 0,
                    extra_flags: 0,
                    discovery_mode: 0,
                },
                remote_attach: AttachPayload {
                    role: 1,
                    realm_id: 0,
                    attach_epoch: 0,
                    mailbox_preference_count: 0,
                    gateway_preference_count: 0,
                    flags: 0,
                },
                remote_role: RemoteRole::Core,
                validated_sovereign_identity: Some(ValidatedIdentity {
                    node_id: identity,
                    master_algo: 0,
                    master_pubkey: vec![0; 32],
                    active_identity_pubkey: vec![0; 32],
                    active_identity_algo: 0,
                    active_key_idx: 0,
                    active_device_id: device,
                    active_instance_id: instance,
                }),
            });
        }
        relay.session_registry = Some(Arc::new(Mutex::new(sessions)));
        let mut tx = SessionTxRegistry::new();
        let receiver = tx.register(receiver_device);
        relay.session_tx_registry = Some(Arc::new(RwLock::new(tx)));
        (relay, receiver)
    }

    fn feed_direct(dispatcher: &veil_dispatcher::FrameDispatcher, frame: &[u8]) {
        let header = codec::decode_header(frame).unwrap();
        assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
        assert!(
            frame.len() + 16 + 40 <= 4096,
            "direct source frame exceeds a 4 KiB bucket"
        );
        assert!(
            !veil_proto::delivery::ForwardPayload::is_realtime_datagram_eligible(
                &frame[veil_proto::HEADER_SIZE..]
            ),
            "reliable chunks must not become lossy datagrams"
        );
        assert_eq!(header.family, FrameFamily::Delivery as u8);
        assert_eq!(
            header.msg_type,
            veil_proto::family::DeliveryMsg::Forward as u16
        );
        dispatcher.dispatch(
            &header,
            &frame[veil_proto::HEADER_SIZE..],
            veil_cfg::NodeId::from(ME),
        );
    }

    fn take_direct(
        receiver: &mut tokio::sync::mpsc::Receiver<veil_app::registry::AppMessage>,
    ) -> Vec<u8> {
        take_direct_with_origin(receiver, None)
    }

    fn take_direct_with_origin(
        receiver: &mut tokio::sync::mpsc::Receiver<veil_app::registry::AppMessage>,
        expected_origin: Option<[u8; 32]>,
    ) -> Vec<u8> {
        match receiver.try_recv().expect("actual dispatcher delivered") {
            veil_app::registry::AppMessage::Deliver {
                src_node_id,
                provenance,
                origin_device,
                src_app_id,
                data,
                ..
            } => {
                assert_eq!(src_node_id, ME);
                assert_eq!(src_app_id, [0x11; 32]);
                assert_eq!(origin_device, expected_origin);
                assert_eq!(provenance, veil_app::registry::SenderProvenance::Signed);
                data.to_vec()
            }
            other => panic!("unexpected app message: {other:?}"),
        }
    }

    #[tokio::test]
    async fn direct_sealed_chunks_reach_the_real_dispatcher_once_with_metadata_and_authentication()
    {
        for (size, certified_origin) in [(12_000, true), (100_000, false)] {
            let fx = fixture(vec![PEER, RELAY]);
            if certified_origin {
                wlock!(fx.peer.peer_ratchet_keys)
                    .entry(ME)
                    .or_default()
                    .remember_with_device(
                        MY_INSTANCE,
                        rlock!(fx.me.seed_ring).current_ratchet_pk(),
                        u64::MAX,
                        Some(ME),
                    );
            }
            let capture = Arc::new(LaneCapture(Mutex::new(Vec::new()), vec![PEER, RELAY]));
            let mut ctx = fx.ctx(true);
            ctx.session_tx_registry = Some(capture.clone());
            let tracker = Arc::new(Mutex::new(veil_pending_ack::PendingAckTracker::new()));
            ctx.pending_ack = Some(tracker.clone());
            let data: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
            let mut request = AppIpcSendPayload::decode(&payload(false, &data)).unwrap();
            request.require_ack = true;
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &request.encode(), &ctx)
                .await
                .unwrap();
            let frames = lock!(capture.0);
            assert!(frames.len() > 1, "direct large envelope must be packetized");
            let (dispatcher, _endpoint, mut receiver) =
                direct_receiver(&fx.peer, PEER, PEER_INSTANCE);
            let mut transfer = None;
            for (lane, frame) in frames.iter() {
                assert_eq!(*lane, veil_proto::priority::BACKGROUND);
                let forward =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                assert_eq!(forward.next_hop_node_id, PEER, "never a relay");
                assert_eq!(forward.envelope.recipient.node_id, PEER);
                assert_eq!(forward.envelope.sender_node_id, ME);
                assert_eq!(forward.envelope.src_app_id, request.src_app_id);
                assert_eq!(forward.envelope.app_id, request.app_id);
                assert_eq!(forward.envelope.endpoint_id, request.endpoint_id);
                let chunk =
                    veil_proto::delivery::ChunkedEnvelopePayload::decode(&forward.envelope.payload)
                        .unwrap();
                assert!(
                    !chunk.require_ack,
                    "direct source reply semantics unchanged"
                );
                assert_eq!(
                    *transfer.get_or_insert(chunk.transfer_id),
                    chunk.transfer_id
                );
                feed_direct(&dispatcher, frame);
                feed_direct(&dispatcher, frame); // retained prefix / completed replay
            }
            assert_eq!(
                take_direct_with_origin(&mut receiver, certified_origin.then_some(ME)),
                data
            );
            assert!(
                receiver.try_recv().is_err(),
                "one logical message, not one per chunk/replay"
            );
            assert!(
                lock!(tracker).is_empty(),
                "packetization must not add an ACK tracker protocol to direct sends"
            );
        }
    }

    #[tokio::test]
    async fn direct_plain_source_waits_for_credit_and_preserves_primary() {
        use std::time::Duration;
        let fx = fixture(vec![PEER, RELAY]);
        let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::with_capacity(
            1,
        )));
        let mut outbox = wlock!(registry).register_owned(PEER, [1; 32]);
        assert!(wlock!(registry).set_direct_app_chunks_owned(&PEER, &[1; 32], true));
        let mut relay = wlock!(registry).register(RELAY);
        let mut ctx = fx.ctx(false);
        ctx.session_instance_lookup = Some(Arc::new(PlainChunkPeers(vec![PEER])));
        ctx.session_tx_registry = Some(Arc::new(veil_session::glue::SessionTxBroadcaster::new(
            registry.clone(),
        )));
        assert!(rlock!(registry).send_to(&PEER, veil_proto::priority::BACKGROUND, vec![0]));
        let data = vec![0x39; 12_000];
        let body = payload(false, &data);
        let mut wh = sink().await;
        let mut reply = SendReply::Inline(&mut wh);
        let mut admission = Box::pin(handle_ipc_send(&mut reply, &body, &ctx));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut admission)
                .await
                .is_err(),
            "direct source must wait for credit"
        );
        assert!(
            registry.try_write().is_ok(),
            "no registry guard spans source wait"
        );
        assert!(rlock!(registry).send_to(&PEER, veil_proto::priority::REALTIME, vec![1]));
        assert_eq!(
            &*outbox.recv().await.unwrap().1,
            [1],
            "reserved primary overtakes full background"
        );
        assert_eq!(&*outbox.recv().await.unwrap().1, [0]);
        let mut frames = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    result=&mut admission => {result.unwrap();break;}
                    frame=outbox.recv() => {frames.push(frame.unwrap());}
                }
            }
        })
        .await
        .unwrap();
        while let Ok(frame) = outbox.try_recv() {
            frames.push(frame);
        }
        assert!(frames.len() > 1);
        assert!(
            relay.try_recv().is_err(),
            "a full healthy direct queue must not spray an alternate copy"
        );
        let (dispatcher, _endpoint, mut receiver) = direct_receiver(&fx.peer, PEER, PEER_INSTANCE);
        for (lane, frame) in frames {
            assert_eq!(lane, veil_proto::priority::BACKGROUND);
            feed_plain(&dispatcher, &frame);
        }
        assert_eq!(take_plain(&mut receiver), data);
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn direct_source_waits_for_credit_without_losing_a_suffix_or_blocking_primary() {
        use std::time::Duration;
        let fx = fixture(vec![PEER, RELAY]);
        let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::with_capacity(
            1,
        )));
        let mut outbox = wlock!(registry).register(PEER);
        let mut relay = wlock!(registry).register(RELAY);
        let mut ctx = fx.ctx(true);
        ctx.session_tx_registry = Some(Arc::new(veil_session::glue::SessionTxBroadcaster::new(
            registry.clone(),
        )));
        assert!(rlock!(registry).send_to(&PEER, veil_proto::priority::BACKGROUND, vec![0]));
        rlock!(registry).note_local_source_feedback(false, std::time::Instant::now());
        let data = vec![0x39; 12_000];
        let body = payload(false, &data);
        let mut wh = sink().await;
        let mut reply = SendReply::Inline(&mut wh);
        let mut admission = Box::pin(handle_ipc_send(&mut reply, &body, &ctx));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut admission)
                .await
                .is_err(),
            "direct source must wait for credit"
        );
        assert!(
            registry.try_write().is_ok(),
            "no registry guard spans source wait"
        );
        assert!(rlock!(registry).send_to(&PEER, veil_proto::priority::REALTIME, vec![1]));
        assert_eq!(
            &*outbox.recv().await.unwrap().1,
            [1],
            "reserved primary overtakes full background"
        );
        assert_eq!(&*outbox.recv().await.unwrap().1, [0]);
        let mut frames = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    result=&mut admission => {result.unwrap();break;}
                    frame=outbox.recv() => {frames.push(frame.unwrap());}
                }
            }
        })
        .await
        .unwrap();
        while let Ok(frame) = outbox.try_recv() {
            frames.push(frame);
        }
        assert!(frames.len() > 1);
        assert!(
            relay.try_recv().is_err(),
            "a full healthy direct queue must not spray an alternate copy"
        );
        let (dispatcher, _endpoint, mut receiver) = direct_receiver(&fx.peer, PEER, PEER_INSTANCE);
        for (lane, frame) in frames {
            // The sealed transfer retains a packet-sized source piece plus hop AEAD.
            assert!(frame.len() + 16 <= 1200);
            assert_eq!(lane, veil_proto::priority::BACKGROUND);
            feed_direct(&dispatcher, &frame);
        }
        assert_eq!(take_direct(&mut receiver), data);
        assert!(receiver.try_recv().is_err());
    }

    struct DirectFamilySource {
        inner: veil_session::glue::SessionTxBroadcaster,
        devices: Vec<[u8; 32]>,
    }
    impl FrameBroadcaster for DirectFamilySource {
        fn send_to(&self, peer: &[u8; 32], priority: u8, frame: Vec<u8>) -> bool {
            self.inner.send_to(peer, priority, frame)
        }
        fn send_reliable_to<'a>(
            &'a self,
            peer: &'a [u8; 32],
            frame: Vec<u8>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
            self.inner.send_reliable_to(peer, frame)
        }
        fn send_direct_app_chunk_to<'a>(
            &'a self,
            peer: &'a [u8; 32],
            frame: Vec<u8>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
            self.inner.send_direct_app_chunk_to(peer, frame)
        }
        fn send_to_all_with_priority(&self, priority: u8, frames: Arc<[u8]>) {
            self.inner.send_to_all_with_priority(priority, frames)
        }
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            self.inner.active_node_ids()
        }
        fn devices_of(&self, identity: &[u8; 32]) -> Vec<[u8; 32]> {
            if *identity == PEER {
                self.devices.clone()
            } else {
                Vec::new()
            }
        }
    }

    #[tokio::test]
    async fn direct_plain_family_source_delivers_a_sibling_while_other_credit_is_full() {
        const ONE: [u8; 32] = [0xb7; 32];
        const TWO: [u8; 32] = [0xb8; 32];
        let fx = fixture(vec![ONE, TWO]);
        let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::with_capacity(
            1,
        )));
        let mut first = wlock!(registry).register_owned(ONE, [1; 32]);
        let mut second = wlock!(registry).register_owned(TWO, [2; 32]);
        assert!(wlock!(registry).set_direct_app_chunks_owned(&ONE, &[1; 32], true));
        assert!(wlock!(registry).set_direct_app_chunks_owned(&TWO, &[2; 32], true));
        let mut ctx = fx.ctx(false);
        ctx.session_instance_lookup = Some(Arc::new(PlainChunkPeers(vec![ONE, TWO])));
        ctx.session_tx_registry = Some(Arc::new(DirectFamilySource {
            inner: veil_session::glue::SessionTxBroadcaster::new(registry.clone()),
            devices: vec![ONE, TWO],
        }));
        assert!(rlock!(registry).send_to(&ONE, veil_proto::priority::BACKGROUND, vec![0]));
        let data = vec![0x83; 12_000];
        let body = payload(false, &data);
        let mut wh = sink().await;
        let mut reply = SendReply::Inline(&mut wh);
        let mut admission = Box::pin(handle_ipc_send(&mut reply, &body, &ctx));
        let mut frames = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while frames.len() < data.len().div_ceil(veil_proto::budget::LOCAL_ENVELOPE_SEGMENT_DATA_BYTES) {
                tokio::select! {
                    result = &mut admission => panic!("request ended before blocked sibling was released: {result:?}"),
                    frame = second.recv() => frames.push(frame.unwrap()),
                }
            }
        }).await.expect("second plain sibling progresses independently");
        let dispatcher = veil_dispatcher::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let (_endpoint, mut receiver) = dispatcher.app_registry.register([0x22; 32], 7, 16);
        for (lane, frame) in frames {
            assert_eq!(lane, veil_proto::priority::BACKGROUND);
            feed_plain(&dispatcher, &frame);
        }
        assert_eq!(take_plain(&mut receiver), data);
        assert!(receiver.try_recv().is_err());
        assert_eq!(&*first.recv().await.unwrap().1, [0]);
        let mut frames = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    result = &mut admission => {result.unwrap();break;},
                    frame = first.recv() => frames.push(frame.unwrap()),
                }
            }
        })
        .await
        .unwrap();
        while let Ok(frame) = first.try_recv() {
            frames.push(frame);
        }
        let other = veil_dispatcher::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let (_endpoint, mut receiver) = other.app_registry.register([0x22; 32], 7, 16);
        for (_, frame) in frames {
            feed_plain(&other, &frame);
        }
        assert_eq!(take_plain(&mut receiver), data);
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn direct_family_source_does_not_starve_a_sibling_or_cross_device_key_authority() {
        use std::time::Duration;
        const ONE: [u8; 32] = [0xB7; 32];
        const TWO: [u8; 32] = [0xB8; 32];
        let (fx, sibling) = family_fixture();
        let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::with_capacity(
            1,
        )));
        let mut first = wlock!(registry).register(ONE);
        let mut second = wlock!(registry).register(TWO);
        let mut ctx = fx.ctx(true);
        ctx.session_tx_registry = Some(Arc::new(DirectFamilySource {
            inner: veil_session::glue::SessionTxBroadcaster::new(registry.clone()),
            devices: vec![ONE, TWO],
        }));
        ctx.session_instance_lookup = Some(Arc::new(FamilySessions(vec![
            (
                ONE,
                veil_types::SessionPairing {
                    identity: PEER,
                    instance: PEER_INSTANCE,
                },
            ),
            (
                TWO,
                veil_types::SessionPairing {
                    identity: PEER,
                    instance: SIBLING_INSTANCE,
                },
            ),
        ])));
        assert!(rlock!(registry).send_to(&ONE, veil_proto::priority::BACKGROUND, vec![0]));
        let data = vec![0x49; 12_000];
        let body = payload(false, &data);
        let mut wh = sink().await;
        let mut reply = SendReply::Inline(&mut wh);
        let mut admission = Box::pin(handle_ipc_send(&mut reply, &body, &ctx));
        let mut second_frames = Vec::new();
        tokio::time::timeout(Duration::from_secs(2),async {
            loop {
                tokio::select! {
                    result=&mut admission=>panic!("full first device unexpectedly completes: {result:?}"),
                    frame=second.recv()=>{
                        second_frames.push(frame.unwrap());
                        let f=veil_proto::delivery::ForwardPayload::decode(&second_frames.last().unwrap().1[veil_proto::HEADER_SIZE..]).unwrap();
                        let chunk=veil_proto::delivery::ChunkedEnvelopePayload::decode(&f.envelope.payload).unwrap();
                        if chunk.chunk_index+1==chunk.chunk_count {break;}
                    }
                }
            }
        }).await.expect("second sibling must finish while the first remains blocked");
        assert!(registry.try_write().is_ok());
        assert!(rlock!(registry).send_to(&ONE, veil_proto::priority::REALTIME, vec![1]));
        assert_eq!(&*first.recv().await.unwrap().1, [1]);
        assert_eq!(&*first.recv().await.unwrap().1, [0]);
        let mut first_frames = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    result=&mut admission=>{result.unwrap();break;}
                    frame=first.recv()=>{first_frames.push(frame.unwrap());}
                }
            }
        })
        .await
        .unwrap();
        while let Ok(frame) = first.try_recv() {
            first_frames.push(frame);
        }
        let (one, _h1, mut rx1) = direct_receiver(&fx.peer, ONE, PEER_INSTANCE);
        let (two, _h2, mut rx2) = direct_receiver(&sibling, TWO, SIBLING_INSTANCE);
        for (target, instance, frames, dispatcher) in [
            (ONE, PEER_INSTANCE, &first_frames, &one),
            (TWO, SIBLING_INSTANCE, &second_frames, &two),
        ] {
            assert!(frames.len() > 1);
            for (lane, frame) in frames {
                assert_eq!(*lane, veil_proto::priority::BACKGROUND);
                let f =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                assert_eq!(f.next_hop_node_id, target);
                assert_eq!(
                    f.envelope.recipient,
                    veil_proto::recipient::Recipient::specific(PEER, instance)
                );
                feed_direct(dispatcher, frame);
            }
        }
        assert_eq!(take_direct(&mut rx1), data);
        assert_eq!(take_direct(&mut rx2), data);
        // Even a correctly hop-authenticated sibling cannot open ciphertext
        // addressed/sealed to the other instance of this same identity.
        let (wrong, _h, mut wrong_rx) = direct_receiver(&sibling, TWO, SIBLING_INSTANCE);
        for (_, frame) in &first_frames {
            feed_direct(&wrong, frame);
        }
        assert!(wrong_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn direct_family_source_refuses_a_foreign_identity_before_any_plaintext_fallback() {
        const DEVICE: [u8; 32] = [0xB7; 32];
        for size in [100, 12_000] {
            let (mut fx, _) = family_fixture();
            fx.outbox = Arc::new(Outbox {
                live: vec![DEVICE, RELAY],
                family: vec![DEVICE],
                ..Default::default()
            });
            let mut ctx = fx.ctx(true);
            // A stale family index names a device whose current authenticated
            // session belongs elsewhere, even though the instance id matches.
            ctx.session_instance_lookup = Some(Arc::new(FamilySessions(vec![(
                DEVICE,
                veil_types::SessionPairing {
                    identity: [0xCF; 32],
                    instance: PEER_INSTANCE,
                },
            )])));
            let body = payload(false, &vec![0x72; size]);
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                .await
                .unwrap();
            assert!(
                fx.taken().is_empty(),
                "a foreign device must receive neither a seal nor the legacy unsealed fallback"
            );
            assert!(
                fx.me.store.is_empty(),
                "do not seal private data to the wrong identity in the first place"
            );
        }
    }

    #[tokio::test]
    async fn direct_closed_after_prefix_reuses_the_seal_over_relay_and_delivers_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct ClosedAfterPrefix {
            direct_attempts: AtomicUsize,
            frames: Mutex<Vec<([u8; 32], Vec<u8>)>>,
        }
        impl FrameBroadcaster for ClosedAfterPrefix {
            fn send_to(&self, peer: &[u8; 32], _: u8, frame: Vec<u8>) -> bool {
                assert_eq!(*peer, RELAY, "never fall back to a whole direct AppSend");
                lock!(self.frames).push((*peer, frame));
                true
            }
            fn send_reliable_to<'a>(
                &'a self,
                peer: &'a [u8; 32],
                frame: Vec<u8>,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>
            {
                Box::pin(async move {
                    if *peer == PEER {
                        if self.direct_attempts.fetch_add(1, Ordering::SeqCst) > 0 {
                            return false;
                        }
                        lock!(self.frames).push((*peer, frame));
                        true
                    } else {
                        self.send_to(peer, veil_proto::priority::BACKGROUND, frame)
                    }
                })
            }
            fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {
                panic!("no discovery fanout needed");
            }
            fn active_node_ids(&self) -> Vec<[u8; 32]> {
                vec![PEER, RELAY]
            }
        }
        for proven_session in [false, true] {
            let mut fx = fixture(vec![PEER, RELAY]);
            if proven_session {
                fx.session_instance = Some(PEER_INSTANCE);
            }
            let source = Arc::new(ClosedAfterPrefix {
                direct_attempts: AtomicUsize::new(0),
                frames: Mutex::new(Vec::new()),
            });
            let mut ctx = fx.ctx(true);
            ctx.session_tx_registry = Some(source.clone());
            let data = vec![0x62; 12_000];
            let mut wh = sink().await;
            handle_ipc_send(
                &mut SendReply::Inline(&mut wh),
                &payload(false, &data),
                &ctx,
            )
            .await
            .unwrap();
            let frames = lock!(source.frames);
            assert!(frames.len() > 2);
            assert_eq!(frames[0].0, PEER);
            assert!(frames[1..].iter().all(|(hop, _)| *hop == RELAY));
            let (dispatcher, _endpoint, mut receiver) =
                direct_receiver(&fx.peer, PEER, PEER_INSTANCE);
            let mut first_piece = None;
            for (hop, frame) in frames.iter() {
                let f =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                let chunk =
                    veil_proto::delivery::ChunkedEnvelopePayload::decode(&f.envelope.payload)
                        .unwrap();
                if *hop == PEER {
                    first_piece = Some(chunk.data);
                } else if chunk.chunk_index == 0 {
                    assert_eq!(
                        first_piece.as_ref().unwrap(),
                        &chunk.data,
                        "partial failure must not spend another ratchet seal"
                    );
                }
                let header = codec::decode_header(frame).unwrap();
                dispatcher.dispatch(
                    &header,
                    &frame[veil_proto::HEADER_SIZE..],
                    veil_cfg::NodeId::from(ME),
                );
            }
            assert_eq!(take_direct(&mut receiver), data);
            assert!(receiver.try_recv().is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn direct_plain_source_deadline_does_not_fallback_or_leak_credit() {
        use tokio::io::AsyncReadExt;
        let fx = fixture(vec![PEER, RELAY]);
        let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::with_capacity(
            1,
        )));
        let mut outbox = wlock!(registry).register_owned(PEER, [1; 32]);
        assert!(wlock!(registry).set_direct_app_chunks_owned(&PEER, &[1; 32], true));
        let mut relay = wlock!(registry).register(RELAY);
        let mut ctx = fx.ctx(false);
        ctx.session_instance_lookup = Some(Arc::new(PlainChunkPeers(vec![PEER])));
        ctx.session_tx_registry = Some(Arc::new(veil_session::glue::SessionTxBroadcaster::new(
            registry.clone(),
        )));
        assert!(rlock!(registry).send_to(&PEER, veil_proto::priority::BACKGROUND, vec![0]));
        let (writer, mut reader) = tokio::net::UnixStream::pair().unwrap();
        let (_, wh) = writer.into_split();
        let mut wh = veil_local_transport::LocalWriteHalf::Unix(wh);
        let mut reply = SendReply::Inline(&mut wh);
        let body = payload(false, &vec![9; 12_000]);
        let mut admission = Box::pin(handle_ipc_send(&mut reply, &body, &ctx));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut admission)
                .await
                .is_err()
        );
        tokio::time::advance(std::time::Duration::from_secs(31)).await;
        admission.await.unwrap();
        let mut status = vec![0; veil_proto::HEADER_SIZE + 2];
        reader.read_exact(&mut status).await.unwrap();
        assert_eq!(
            codec::decode_header(&status).unwrap().msg_type,
            LocalAppMsg::AppSendFailed as u16
        );
        assert_eq!(
            &status[veil_proto::HEADER_SIZE..],
            &ipc_send_err::NO_ROUTE.to_be_bytes()
        );
        assert!(relay.try_recv().is_err());
        assert!(registry.try_write().is_ok());
        assert_eq!(&*outbox.recv().await.unwrap().1, [0]);
        assert!(
            ctx.session_tx_registry
                .as_ref()
                .unwrap()
                .send_reliable_to(&PEER, vec![2])
                .await
        );
        assert_eq!(
            &*outbox.recv().await.unwrap().1,
            [2],
            "timed-out source released its credit"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn direct_source_deadline_does_not_fallback_or_leak_credit() {
        use tokio::io::AsyncReadExt;
        let fx = fixture(vec![PEER, RELAY]);
        let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::with_capacity(
            1,
        )));
        let mut outbox = wlock!(registry).register(PEER);
        let mut relay = wlock!(registry).register(RELAY);
        let mut ctx = fx.ctx(true);
        ctx.session_tx_registry = Some(Arc::new(veil_session::glue::SessionTxBroadcaster::new(
            registry.clone(),
        )));
        assert!(rlock!(registry).send_to(&PEER, veil_proto::priority::BACKGROUND, vec![0]));
        let (writer, mut reader) = tokio::net::UnixStream::pair().unwrap();
        let (_, wh) = writer.into_split();
        let mut wh = veil_local_transport::LocalWriteHalf::Unix(wh);
        let mut reply = SendReply::Inline(&mut wh);
        let body = payload(false, &vec![9; 12_000]);
        let mut admission = Box::pin(handle_ipc_send(&mut reply, &body, &ctx));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut admission)
                .await
                .is_err()
        );
        tokio::time::advance(std::time::Duration::from_secs(31)).await;
        admission.await.unwrap();
        let mut status = vec![0; veil_proto::HEADER_SIZE + 2];
        reader.read_exact(&mut status).await.unwrap();
        assert_eq!(
            codec::decode_header(&status).unwrap().msg_type,
            LocalAppMsg::AppSendFailed as u16
        );
        assert_eq!(
            &status[veil_proto::HEADER_SIZE..],
            &ipc_send_err::NO_ROUTE.to_be_bytes()
        );
        assert!(relay.try_recv().is_err());
        assert!(registry.try_write().is_ok());
        assert_eq!(&*outbox.recv().await.unwrap().1, [0]);
        assert!(
            ctx.session_tx_registry
                .as_ref()
                .unwrap()
                .send_reliable_to(&PEER, vec![2])
                .await
        );
        assert_eq!(
            &*outbox.recv().await.unwrap().1,
            [2],
            "timed-out source released its credit"
        );
    }

    fn mixed_family_fixture(
        registry_knows_relayed_device: bool,
    ) -> (
        Fixture,
        veil_e2e::RatchetRuntime,
        [u8; 32],
        [u8; 32],
        IpcSendContext,
    ) {
        let (mut fx, sibling) = family_fixture();
        let mut direct_device = [0u8; 32];
        direct_device[..16].copy_from_slice(&PEER_INSTANCE);
        let mut relayed_device = [0u8; 32];
        relayed_device[..16].copy_from_slice(&SIBLING_INSTANCE);
        fx.outbox = Arc::new(Outbox {
            live: vec![direct_device, RELAY],
            datagram: Vec::new(),
            sent: Mutex::new(Vec::new()),
            family: if registry_knows_relayed_device {
                vec![direct_device, relayed_device]
            } else {
                vec![direct_device]
            },
        });
        let mut ctx = fx.ctx(true);
        ctx.session_instance_lookup = Some(Arc::new(FamilySessions(vec![
            (
                direct_device,
                veil_types::SessionPairing {
                    identity: PEER,
                    instance: PEER_INSTANCE,
                },
            ),
            (
                relayed_device,
                veil_types::SessionPairing {
                    identity: PEER,
                    instance: SIBLING_INSTANCE,
                },
            ),
        ])));
        (fx, sibling, direct_device, relayed_device, ctx)
    }

    fn feed_mixed_family_frame(
        hop: [u8; 32],
        frame: &[u8],
        direct_device: [u8; 32],
        direct: &veil_dispatcher::FrameDispatcher,
        relay: &veil_dispatcher::FrameDispatcher,
        forwarded: &mut veil_session::FrameOutbox,
        relayed: &veil_dispatcher::FrameDispatcher,
    ) {
        if hop == direct_device {
            feed_direct(direct, frame);
        } else {
            assert_eq!(hop, RELAY);
            let header = codec::decode_header(frame).unwrap();
            assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
            assert!(
                !veil_proto::delivery::ForwardPayload::is_realtime_datagram_eligible(
                    &frame[veil_proto::HEADER_SIZE..]
                )
            );
            relay.dispatch(
                &header,
                &frame[veil_proto::HEADER_SIZE..],
                veil_cfg::NodeId::from(ME),
            );
            while let Ok((_, frame)) = forwarded.try_recv() {
                let header = codec::decode_header(&frame).unwrap();
                relayed.dispatch(
                    &header,
                    &frame[veil_proto::HEADER_SIZE..],
                    veil_cfg::NodeId::from(RELAY),
                );
            }
        }
    }

    #[tokio::test]
    async fn ordinary_mixed_family_keeps_direct_and_relayed_recipients() {
        for registry_knows_relayed_device in [false, true] {
            let (fx, sibling, direct_device, _relayed_device, ctx) =
                mixed_family_fixture(registry_knows_relayed_device);
            let plaintext = b"mixed transport family delivery";
            let mut wh = sink().await;
            handle_ipc_send(
                &mut SendReply::Inline(&mut wh),
                &payload(false, plaintext),
                &ctx,
            )
            .await
            .unwrap();
            let sent = fx.taken();
            let mut direct = None;
            let mut relayed = None;
            for (hop, bytes) in sent {
                let header = codec::decode_header(&bytes).unwrap();
                if hop == direct_device
                    && header.msg_type == veil_proto::family::AppMsg::AppSendSealed as u16
                {
                    let body =
                        veil_proto::app::AppSendPayload::decode(&bytes[veil_proto::HEADER_SIZE..])
                            .unwrap();
                    assert!(
                        direct.replace(body.data).is_none(),
                        "do not duplicate the direct recipient"
                    );
                } else if hop == RELAY && header.family == FrameFamily::Delivery as u8 {
                    let forward = veil_proto::delivery::ForwardPayload::decode(
                        &bytes[veil_proto::HEADER_SIZE..],
                    )
                    .unwrap();
                    assert_eq!(
                        forward.envelope.recipient,
                        veil_proto::recipient::Recipient::specific(PEER, SIBLING_INSTANCE)
                    );
                    if let Some(prior) = relayed.replace(forward.envelope.payload) {
                        assert_eq!(
                            relayed.as_ref().unwrap(),
                            &prior,
                            "alternate paths reuse one ciphertext"
                        );
                    }
                }
            }
            let now = veil_util::unix_secs_now_u64();
            assert_eq!(
                fx.peer
                    .open_payload(
                        &ME,
                        &direct.expect("direct device receives its own ciphertext"),
                        now
                    )
                    .unwrap()
                    .plaintext,
                plaintext
            );
            let wire =
                relayed.expect("a direct sibling must not suppress the relayed sibling's copy");
            let opened = sibling.open_payload(&ME, &wire, now).unwrap();
            assert!(opened.authenticated);
            assert_eq!(opened.plaintext, plaintext);
        }
    }

    #[tokio::test]
    async fn family_stage_evidence_distinguishes_filter_route_and_admission() {
        for mode in 0..3 {
            let (_fx, _sibling, one, two, mut ctx) = mixed_family_fixture(false);
            let direct = DirectFamilyRecipients {
                devices: [one].into_iter().collect(),
                instances: [PEER_INSTANCE].into_iter().collect(),
            };
            if mode == 1 {
                ctx.session_instance_lookup = Some(Arc::new(FamilySessions(vec![(
                    two,
                    veil_types::SessionPairing {
                        identity: [0xd9; 32],
                        instance: SIBLING_INSTANCE,
                    },
                )])));
            } else if mode == 2 {
                ctx.session_tx_registry = Some(Arc::new(Outbox {
                    live: vec![],
                    datagram: vec![],
                    sent: Mutex::new(vec![]),
                    family: vec![],
                }));
                ctx.route_cache = None;
            }
            let request = AppIpcSendPayload::decode(&payload(false, b"private test body")).unwrap();
            let epoch = ctx
                .ratchet
                .as_ref()
                .unwrap()
                .store
                .host_publication_state()
                .epoch;
            let got = send_family_relay_copies(
                &ctx,
                &request,
                epoch,
                tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                false,
                veil_proto::priority::INTERACTIVE,
                Some(&direct),
            )
            .await;
            assert_eq!(got.timing.certificates, 2);
            let e = got.timing.evidence;
            assert_eq!(e.filtered_direct, 1);
            assert_eq!(e.filtered_pairing, usize::from(mode == 1));
            assert_eq!(e.no_hops, usize::from(mode == 2));
            assert_eq!(e.seal_attempts, usize::from(mode == 0));
            assert_eq!(e.sealed, usize::from(mode == 0));
            assert_eq!(e.source_attempts, usize::from(mode == 0));
            assert_eq!(e.source_accepted, usize::from(mode == 0));
            assert_eq!(got.accepted, mode == 0);
            let exported = format!("{e:?}");
            assert!(!exported.contains("private test body"));
            assert!(!exported.contains(&veil_util::bytes_to_hex(&two)));
        }
    }

    #[tokio::test]
    async fn mixed_family_never_uses_expired_or_foreign_sibling_authority() {
        for foreign in [false, true] {
            let (fx, _sibling, one, two, mut ctx) = mixed_family_fixture(false);
            if foreign {
                ctx.session_instance_lookup = Some(Arc::new(FamilySessions(vec![
                    (
                        one,
                        veil_types::SessionPairing {
                            identity: PEER,
                            instance: PEER_INSTANCE,
                        },
                    ),
                    (
                        two,
                        veil_types::SessionPairing {
                            identity: [0xd9; 32],
                            instance: SIBLING_INSTANCE,
                        },
                    ),
                ])));
            } else {
                let mut rows = fx
                    .certs
                    .resolve_device_certs_cached(PEER)
                    .into_iter()
                    .map(|(_, cert)| cert)
                    .collect::<Vec<_>>();
                rows.iter_mut()
                    .find(|cert| cert.instance_id == SIBLING_INSTANCE)
                    .unwrap()
                    .valid_until_unix = 0;
                ctx.mlkem_ek_resolver = Some(Arc::new(FamilyCerts(rows)));
            }
            let mut wh = sink().await;
            handle_ipc_send(
                &mut SendReply::Inline(&mut wh),
                &payload(false, b"only the authorized endpoint"),
                &ctx,
            )
            .await
            .unwrap();
            let frames = fx.taken();
            assert_eq!(
                frames.len(),
                1,
                "no relay copy for unusable sibling authority"
            );
            assert_eq!(frames[0].0, one);
            let direct =
                veil_proto::app::AppSendPayload::decode(&frames[0].1[veil_proto::HEADER_SIZE..])
                    .unwrap();
            assert_eq!(
                fx.peer
                    .open_payload(&ME, &direct.data, veil_util::unix_secs_now_u64())
                    .unwrap()
                    .plaintext,
                b"only the authorized endpoint"
            );
        }
    }

    #[tokio::test]
    async fn mixed_family_resolve_does_not_park_direct_or_discard_fresh_rows() {
        struct ResolvingFamily {
            rows: FamilyCerts,
            release: tokio::sync::Notify,
        }
        impl veil_types::MlKemEkResolver for ResolvingFamily {
            fn resolve_device_certs_cached(
                &self,
                target: [u8; 32],
            ) -> Vec<([u8; 32], veil_types::VerifiedPeerCert)> {
                self.rows
                    .resolve_device_certs_cached(target)
                    .into_iter()
                    .take(1)
                    .collect()
            }
            fn resolve_device_certs(&self, target: [u8; 32]) -> veil_types::DeviceCertsFuture<'_> {
                Box::pin(async move {
                    self.release.notified().await;
                    // Resolution returns a fresh verified row without relying
                    // on the transport's pre-existing family registry cache.
                    self.rows.resolve_device_certs_cached(target)
                })
            }
            fn resolve_cert_cached(
                &self,
                target: [u8; 32],
            ) -> Option<veil_types::VerifiedPeerCert> {
                self.rows.resolve_cert_cached(target)
            }
            fn resolve_cert(
                &self,
                target: [u8; 32],
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = Option<veil_types::VerifiedPeerCert>>
                        + Send
                        + '_,
                >,
            > {
                self.rows.resolve_cert(target)
            }
            fn resolve_cert_for_instance_cached(
                &self,
                target: [u8; 32],
                instance: [u8; 16],
            ) -> Option<veil_types::VerifiedPeerCert> {
                self.rows.resolve_cert_for_instance_cached(target, instance)
            }
        }
        let (fx, sibling, one, _two, mut ctx) = mixed_family_fixture(false);
        let rows = fx
            .certs
            .resolve_device_certs_cached(PEER)
            .into_iter()
            .map(|(_, cert)| cert)
            .collect();
        let resolver = Arc::new(ResolvingFamily {
            rows: FamilyCerts(rows),
            release: tokio::sync::Notify::new(),
        });
        ctx.mlkem_ek_resolver = Some(resolver.clone());
        let body = payload(false, b"the newly discovered sibling gets its copy too");
        let mut wh = sink().await;
        let mut reply = SendReply::Inline(&mut wh);
        let mut send = Box::pin(handle_ipc_send(&mut reply, &body, &ctx));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut send)
                .await
                .is_err()
        );
        let direct = fx.taken();
        assert_eq!(direct.len(), 1);
        assert_eq!(
            direct[0].0, one,
            "direct admission does not wait on family discovery"
        );
        resolver.release.notify_one();
        send.await.unwrap();
        let relayed = fx.taken();
        assert_eq!(relayed.len(), 1);
        assert_eq!(relayed[0].0, RELAY);
        let envelope =
            veil_proto::delivery::ForwardPayload::decode(&relayed[0].1[veil_proto::HEADER_SIZE..])
                .unwrap()
                .envelope;
        assert_eq!(
            sibling
                .open_payload(&ME, &envelope.payload, veil_util::unix_secs_now_u64())
                .unwrap()
                .plaintext,
            b"the newly discovered sibling gets its copy too"
        );
    }

    #[tokio::test]
    async fn mixed_family_large_copies_cross_a_real_relay_and_deliver_once() {
        for size in [12_000, 100_000] {
            let (fx, sibling, one, two, ctx) = mixed_family_fixture(true);
            let data = (0..size).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            let mut wh = sink().await;
            handle_ipc_send(
                &mut SendReply::Inline(&mut wh),
                &payload(false, &data),
                &ctx,
            )
            .await
            .unwrap();
            let frames = fx.taken();
            assert!(frames.iter().any(|(hop, _)| *hop == one));
            assert!(frames.iter().any(|(hop, _)| *hop == RELAY));
            let (first, _a, mut a_rx) = direct_receiver(&fx.peer, one, PEER_INSTANCE);
            let (second, _b, mut b_rx) = direct_receiver(&sibling, two, SIBLING_INSTANCE);
            let (relay, mut forwarded) = identity_first_relay_instance(ME, two, SIBLING_INSTANCE);
            for (hop, frame) in &frames {
                feed_mixed_family_frame(*hop, frame, one, &first, &relay, &mut forwarded, &second);
            }
            assert_eq!(take_direct(&mut a_rx), data);
            assert_eq!(take_direct(&mut b_rx), data);
            for (hop, frame) in &frames {
                feed_mixed_family_frame(*hop, frame, one, &first, &relay, &mut forwarded, &second);
            }
            assert!(a_rx.try_recv().is_err());
            assert!(b_rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn mixed_family_real_source_credit_keeps_the_other_recipient_moving() {
        for blocked_direct in [false, true] {
            let (fx, sibling, one, two, mut ctx) = mixed_family_fixture(true);
            let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::with_capacity(
                1,
            )));
            let mut direct = wlock!(registry).register(one);
            let mut relay_source = wlock!(registry).register(RELAY);
            ctx.session_tx_registry = Some(Arc::new(DirectFamilySource {
                inner: veil_session::glue::SessionTxBroadcaster::new(registry.clone()),
                devices: vec![one],
            }));
            let blocked = if blocked_direct { one } else { RELAY };
            assert!(rlock!(registry).send_to(&blocked, veil_proto::priority::BACKGROUND, vec![0]));
            let (first, _a, mut a_rx) = direct_receiver(&fx.peer, one, PEER_INSTANCE);
            let (second, _b, mut b_rx) = direct_receiver(&sibling, two, SIBLING_INSTANCE);
            let (relay, mut forwarded) = identity_first_relay_instance(ME, two, SIBLING_INSTANCE);
            let data = vec![0x6d; 12_000];
            let body = payload(false, &data);
            let mut wh = sink().await;
            let mut reply = SendReply::Inline(&mut wh);
            let mut admission = Box::pin(handle_ipc_send(&mut reply, &body, &ctx));
            tokio::time::timeout(Duration::from_secs(2), async {
                while if blocked_direct { b_rx.is_empty() } else { a_rx.is_empty() } {
                    tokio::select! {
                        result = &mut admission => panic!("blocked source completed before release: {result:?}"),
                        frame = async {
                            if blocked_direct { relay_source.recv().await } else { direct.recv().await }
                        } => {
                            let (_, frame) = frame.unwrap();
                            let hop = if blocked_direct { RELAY } else { one };
                            feed_mixed_family_frame(hop, &frame, one, &first, &relay, &mut forwarded, &second);
                        }
                    }
                }
            }).await.expect("the independent recipient progresses while its sibling is full");
            assert!(
                registry.try_write().is_ok(),
                "no session lock spans admission"
            );
            let first_data = if blocked_direct {
                take_direct(&mut b_rx)
            } else {
                take_direct(&mut a_rx)
            };
            assert_eq!(first_data, data);
            let placeholder = if blocked_direct {
                direct.recv().await
            } else {
                relay_source.recv().await
            };
            assert_eq!(&*placeholder.unwrap().1, [0]);
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    tokio::select! {
                        result = &mut admission => { result.unwrap(); break; },
                        frame = direct.recv() => feed_mixed_family_frame(one, &frame.unwrap().1, one, &first, &relay, &mut forwarded, &second),
                        frame = relay_source.recv() => feed_mixed_family_frame(RELAY, &frame.unwrap().1, one, &first, &relay, &mut forwarded, &second),
                    }
                }
            }).await.unwrap();
            while let Ok((_, frame)) = direct.try_recv() {
                feed_mixed_family_frame(one, &frame, one, &first, &relay, &mut forwarded, &second);
            }
            while let Ok((_, frame)) = relay_source.try_recv() {
                feed_mixed_family_frame(
                    RELAY,
                    &frame,
                    one,
                    &first,
                    &relay,
                    &mut forwarded,
                    &second,
                );
            }
            let later = if blocked_direct {
                take_direct(&mut a_rx)
            } else {
                take_direct(&mut b_rx)
            };
            assert_eq!(later, data);
            assert!(a_rx.try_recv().is_err());
            assert!(b_rx.try_recv().is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn family_relay_source_deadline_does_not_restart_legacy_fallback() {
        use tokio::io::AsyncReadExt;
        let (mut fx, _sibling) = family_fixture();
        fx.outbox = Arc::new(Outbox {
            live: vec![RELAY],
            ..Outbox::default()
        });
        let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::with_capacity(
            1,
        )));
        let mut relay = wlock!(registry).register(RELAY);
        let mut ctx = fx.ctx(true);
        ctx.session_tx_registry = Some(Arc::new(veil_session::glue::SessionTxBroadcaster::new(
            registry.clone(),
        )));
        assert!(rlock!(registry).send_to(&RELAY, veil_proto::priority::BACKGROUND, vec![0]));
        let (writer, mut reader) = tokio::net::UnixStream::pair().unwrap();
        let (_, wh) = writer.into_split();
        let mut wh = veil_local_transport::LocalWriteHalf::Unix(wh);
        let mut reply = SendReply::Inline(&mut wh);
        let body = payload(false, &vec![9; 12_000]);
        let mut admission = Box::pin(handle_ipc_send(&mut reply, &body, &ctx));
        let began = tokio::time::Instant::now();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut admission)
                .await
                .is_err()
        );
        tokio::time::advance(Duration::from_secs(31)).await;
        admission.await.unwrap();
        assert!(
            began.elapsed() < Duration::from_secs(32),
            "no fresh deadline after a family source timeout"
        );
        let mut status = vec![0; veil_proto::HEADER_SIZE + 2];
        reader.read_exact(&mut status).await.unwrap();
        assert_eq!(
            &status[veil_proto::HEADER_SIZE..],
            &ipc_send_err::NO_ROUTE.to_be_bytes()
        );
        assert_eq!(&*relay.recv().await.unwrap().1, [0]);
        assert!(
            relay.try_recv().is_err(),
            "no later full copy after admission timeout"
        );
        assert!(
            ctx.session_tx_registry
                .as_ref()
                .unwrap()
                .send_reliable_to(&RELAY, vec![2])
                .await
        );
        assert_eq!(
            &*relay.recv().await.unwrap().1,
            [2],
            "source credit released"
        );
    }

    #[tokio::test]
    async fn ordinary_relay_send_seals_each_device_even_without_a_direct_session() {
        let (mut fx, sibling) = family_fixture();
        fx.outbox = Arc::new(Outbox {
            live: vec![RELAY],
            datagram: Vec::new(),
            sent: Mutex::new(Vec::new()),
            family: Vec::new(),
        });
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"ordinary message to the online sibling"),
            &fx.ctx(true),
        )
        .await
        .unwrap();
        let sent = fx.taken();
        assert_eq!(
            sent.len(),
            2,
            "one normal reliable copy per verified instance"
        );
        let mut instances = std::collections::HashSet::new();
        for (hop, bytes) in sent {
            assert_eq!(hop, RELAY);
            let f = veil_proto::delivery::ForwardPayload::decode(&bytes[veil_proto::HEADER_SIZE..])
                .unwrap();
            let (_, instance) = veil_e2e::payload_instances(&f.envelope.payload).unwrap();
            assert!(instances.insert(instance));
            assert_eq!(
                f.envelope.recipient,
                veil_proto::recipient::Recipient::specific(PEER, instance)
            );
            let endpoint = if instance == PEER_INSTANCE {
                &fx.peer
            } else {
                &sibling
            };
            assert_eq!(
                endpoint
                    .open_payload(&ME, &f.envelope.payload, veil_util::unix_secs_now_u64())
                    .unwrap()
                    .plaintext,
                b"ordinary message to the online sibling"
            );
        }
    }

    #[tokio::test]
    async fn relay_call_control_warms_missing_device_certificates_before_fanout() {
        use veil_proto::delivery::DeliveryEnvelope;
        let (mut fx, sibling) = family_fixture();
        let rows = fx
            .certs
            .resolve_device_certs_cached(PEER)
            .into_iter()
            .map(|(_, cert)| cert)
            .collect();
        fx.certs = Arc::new(WarmingFamilyCerts {
            rows: FamilyCerts(rows),
            ready: std::sync::atomic::AtomicBool::new(false),
        });
        assert_eq!(fx.certs.resolve_device_certs_cached(PEER).len(), 1);
        fx.outbox = Arc::new(Outbox {
            live: vec![RELAY],
            datagram: Vec::new(),
            sent: Mutex::new(Vec::new()),
            family: Vec::new(),
        });
        let mut body = payload(false, b"answer from the online phone");
        body[veil_proto::AppIpcSendPayload::FLAGS_RANGE]
            .copy_from_slice(&veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT.to_be_bytes());
        let mut wh = sink().await;
        handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &fx.ctx(true))
            .await
            .expect("send");
        let frames = fx.taken();
        assert_eq!(
            frames.len(),
            4,
            "device and identity-instance copy per device without P2P sessions"
        );
        for (hop, frame) in frames {
            assert_eq!(hop, RELAY);
            let (envelope, _) = DeliveryEnvelope::decode(&frame[veil_proto::HEADER_SIZE + 32..])
                .expect("relay envelope");
            let (_, instance) = veil_e2e::payload_instances(&envelope.payload).expect("sealed");
            if envelope.recipient.node_id != PEER {
                assert_eq!(&envelope.recipient.node_id[..16], &instance);
                continue; // alternate addressing of the same sealed payload
            }
            assert_eq!(
                envelope.recipient,
                veil_proto::recipient::Recipient::specific(PEER, instance)
            );
            let receiver = if instance == PEER_INSTANCE {
                &fx.peer
            } else {
                &sibling
            };
            let wrong_receiver = if instance == PEER_INSTANCE {
                &sibling
            } else {
                &fx.peer
            };
            assert!(matches!(
                wrong_receiver.open_payload(&ME, &envelope.payload, veil_util::unix_secs_now_u64()),
                Err(veil_e2e::RatchetSpliceError::NotForThisDevice)
            ));
            let opened = receiver
                .open_payload(&ME, &envelope.payload, veil_util::unix_secs_now_u64())
                .expect("the device opens its own copy");
            assert!(opened.authenticated);
            assert_eq!(opened.plaintext, b"answer from the online phone");
        }
    }

    impl Fixture {
        fn ctx(&self, with_ratchet: bool) -> IpcSendContext {
            IpcSendContext {
                source_received_at: std::time::Instant::now(),
                local_work: None,
                local_priority: veil_proto::priority::INTERACTIVE,
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
                session_instance_lookup: match self.pairing_device {
                    Some(device) => Some(Arc::new(PairedDevice {
                        device,
                        pairing: veil_types::SessionPairing {
                            identity: PEER,
                            instance: PEER_INSTANCE,
                        },
                    })),
                    None => Some(Arc::new(PinnedInstance(self.session_instance))),
                },
            }
        }

        fn taken(&self) -> Vec<([u8; 32], Vec<u8>)> {
            std::mem::take(&mut lock!(self.outbox.sent))
        }
    }

    /// [`payload`] with the destination spelled out — the multi-device case
    /// needs a destination that is NOT the name certificates live under.
    fn payload_to(dst: [u8; 32], data: &[u8]) -> Vec<u8> {
        let mut p = AppIpcSendPayload::decode(&payload(false, data)).expect("payload");
        p.dst_node_id = dst;
        p.encode()
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

    /// A SEND ADDRESSED TO A DEVICE STILL FINDS ITS CERTIFICATE.
    ///
    /// A certificate lives at `dht_key(identity, instance_id)`; a send names a
    /// TRANSPORT destination, which for anything reached by one of its devices
    /// is that device. The two coincide on a single-device peer — which is why
    /// keying the cert lookup on the destination went unnoticed for so long —
    /// and diverge on exactly the multi-device case. Asking under a device id
    /// computes a key nobody ever wrote to, and the same correction is already
    /// recorded in `offline_seal.rs` for our own devices; this is the live
    /// path's half of it.
    ///
    /// Positive assertion, not an absence: the peer OPENS what came out.
    #[tokio::test]
    async fn a_send_addressed_to_a_device_seals_under_the_identity() {
        const PEER_DEVICE: [u8; 32] = [0xB7u8; 32];
        let mut fx = fixture(vec![PEER_DEVICE, RELAY]);
        fx.pairing_device = Some(PEER_DEVICE);

        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload_to(PEER_DEVICE, b"addressed to a device"),
            &fx.ctx(true),
        )
        .await
        .expect("send");

        let sent = fx.taken();
        assert_eq!(sent.len(), 1);
        let (peer, frame) = &sent[0];
        assert_eq!(
            peer, &PEER_DEVICE,
            "the DEVICE is still what the frame is routed to — only the \
             certificate lookup moves to the identity",
        );
        let hdr = veil_proto::codec::decode_header(frame).expect("header");
        assert_eq!(
            hdr.msg_type,
            veil_proto::family::AppMsg::AppSendSealed as u16,
            "with the cert resolved under the device id there is no cert at \
             all, and the frame leaves unsealed — losing its sender proof",
        );
        let body = veil_proto::app::AppSendPayload::decode(&frame[veil_proto::HEADER_SIZE..])
            .expect("body");
        let opened = fx
            .peer
            .open_payload(&ME, &body.data, veil_util::unix_secs_now_u64())
            .expect("the peer opens it");
        assert_eq!(opened.plaintext, b"addressed to a device");
        assert!(opened.authenticated);
    }

    #[tokio::test]
    async fn a_cold_device_reply_uses_its_verified_identity_without_a_session() {
        const DEVICE: [u8; 32] = [0xB7; 32];
        let fx = fixture(vec![RELAY]);
        assert!(fx.pairing_device.is_none());
        let cert = fx.certs.resolve_cert_cached(PEER).unwrap();
        wlock!(fx.me.peer_ratchet_keys)
            .entry(PEER)
            .or_default()
            .remember_with_device(
                cert.instance_id,
                cert.ratchet_x25519_pk,
                cert.valid_until_unix,
                Some(DEVICE),
            );
        let ctx = fx.ctx(true);
        let (payload, _, _) = try_ratchet_seal(&ctx, &DEVICE, b"cold reply", false)
            .await
            .expect("a verified device certificate supplies the identity binding");
        let opened = fx
            .peer
            .open_payload(&ME, &payload, veil_util::unix_secs_now_u64())
            .expect("the current identity opens the reply");
        assert_eq!(opened.plaintext, b"cold reply");
        assert!(opened.authenticated);
    }

    #[tokio::test]
    async fn a_delegated_device_reply_does_not_use_its_old_self_identity() {
        const DEVICE: [u8; 32] = [0xB7; 32];
        let fx = fixture(vec![RELAY]);
        let cert = fx.certs.resolve_cert_cached(PEER).unwrap();
        wlock!(fx.me.peer_ratchet_keys)
            .entry(PEER)
            .or_default()
            .remember_with_device(
                cert.instance_id,
                cert.ratchet_x25519_pk,
                cert.valid_until_unix,
                Some(DEVICE),
            );
        let mut ctx = fx.ctx(true);
        ctx.session_instance_lookup = Some(Arc::new(PairedDevice {
            device: DEVICE,
            pairing: veil_types::SessionPairing {
                identity: DEVICE,
                instance: cert.instance_id,
            },
        }));
        let (payload, _, _) = try_ratchet_seal(&ctx, &DEVICE, b"delegated reply", false)
            .await
            .expect("current delegation precedes the device's old self identity");
        assert_eq!(
            fx.peer
                .open_payload(&ME, &payload, veil_util::unix_secs_now_u64())
                .unwrap()
                .plaintext,
            b"delegated reply"
        );
        ctx.session_instance_lookup = Some(Arc::new(PairedDevice {
            device: DEVICE,
            pairing: veil_types::SessionPairing {
                identity: [0xE9; 32],
                instance: cert.instance_id,
            },
        }));
        assert!(
            try_ratchet_seal(&ctx, &DEVICE, b"a different authenticated identity", false)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_cold_device_reply_never_substitutes_a_siblings_certificate() {
        const DEVICE: [u8; 32] = [0xB7; 32];
        let (mut fx, _) = family_fixture();
        let key = fx.peer.seed_ring.read().unwrap().current_ratchet_pk();
        wlock!(fx.me.peer_ratchet_keys)
            .entry(PEER)
            .or_default()
            .remember_with_device(PEER_INSTANCE, key, u64::MAX, Some(DEVICE));
        // The current lookup only has the OTHER device's certificate.
        let wrong = fx.certs.resolve_cert_cached(PEER).unwrap();
        assert_eq!(wrong.instance_id, SIBLING_INSTANCE);
        fx.certs = Arc::new(Certs(wrong));
        let ctx = fx.ctx(true);
        assert!(
            try_ratchet_seal(&ctx, &DEVICE, b"not for the sibling", false)
                .await
                .is_none()
        );
        assert!(
            try_ratchet_seal(&ctx, &DEVICE, b"cached only", true)
                .await
                .is_none()
        );
    }

    struct ColdDeviceDirectory {
        device: [u8; 32],
        certs: Vec<([u8; 32], veil_types::VerifiedPeerCert)>,
    }
    impl veil_types::MlKemEkResolver for ColdDeviceDirectory {
        fn identity_hint_for_device(&self, device: &[u8; 32]) -> Option<[u8; 32]> {
            (*device == self.device).then_some(PEER)
        }
        fn resolve_device_certs_cached(
            &self,
            target: [u8; 32],
        ) -> Vec<([u8; 32], veil_types::VerifiedPeerCert)> {
            assert_eq!(target, PEER);
            self.certs.clone()
        }
        fn resolve_cert(
            &self,
            _: [u8; 32],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<veil_types::VerifiedPeerCert>> + Send + '_>,
        > {
            Box::pin(async { None })
        }
    }

    #[tokio::test]
    async fn a_cold_document_hint_requires_the_exact_current_device_certificate() {
        const DEVICE: [u8; 32] = [0xB7; 32];
        let mut fx = fixture(vec![RELAY]);
        let cert = fx.certs.resolve_cert_cached(PEER).unwrap();
        assert!(rlock!(fx.me.peer_ratchet_keys).is_empty());
        fx.certs = Arc::new(ColdDeviceDirectory {
            device: DEVICE,
            certs: vec![(DEVICE, cert.clone())],
        });
        let mut ctx = fx.ctx(true);
        ctx.session_instance_lookup = Some(Arc::new(PairedDevice {
            device: DEVICE,
            pairing: veil_types::SessionPairing {
                identity: DEVICE,
                instance: cert.instance_id,
            },
        }));
        let (payload, _, _) = try_ratchet_seal(&ctx, &DEVICE, b"first cold reply", false)
            .await
            .unwrap();
        assert_eq!(
            fx.peer
                .open_payload(&ME, &payload, veil_util::unix_secs_now_u64())
                .unwrap()
                .plaintext,
            b"first cold reply"
        );
        for certs in [
            vec![],
            vec![([0xE9; 32], cert.clone())],
            vec![(
                DEVICE,
                veil_types::VerifiedPeerCert {
                    node_id: [0xE9; 32],
                    ..cert.clone()
                },
            )],
            vec![(
                DEVICE,
                veil_types::VerifiedPeerCert {
                    valid_until_unix: 1,
                    ..cert.clone()
                },
            )],
            vec![
                (DEVICE, cert.clone()),
                (
                    DEVICE,
                    veil_types::VerifiedPeerCert {
                        instance_id: [0x92; 16],
                        ..cert.clone()
                    },
                ),
            ],
        ] {
            fx.certs = Arc::new(ColdDeviceDirectory {
                device: DEVICE,
                certs,
            });
            let ctx = fx.ctx(true);
            for cached in [false, true] {
                assert!(
                    try_ratchet_seal(&ctx, &DEVICE, b"no valid exact certificate", cached)
                        .await
                        .is_none()
                );
            }
        }
    }

    #[tokio::test]
    async fn a_targeted_device_relay_reply_keeps_its_identity_binding() {
        const DEVICE: [u8; 32] = [0xB7; 32];
        let mut fx = fixture(vec![RELAY]);
        let cert = fx.certs.resolve_cert_cached(PEER).unwrap();
        fx.certs = Arc::new(ColdDeviceDirectory {
            device: DEVICE,
            certs: vec![(DEVICE, cert)],
        });
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload_to(DEVICE, b"targeted relay reply"),
            &fx.ctx(true),
        )
        .await
        .unwrap();
        let sent = fx.taken();
        assert_eq!(sent.len(), 1);
        let (hop, bytes) = &sent[0];
        assert_eq!(*hop, RELAY);
        let frame = veil_proto::delivery::ForwardPayload::decode(&bytes[veil_proto::HEADER_SIZE..])
            .unwrap();
        assert_eq!(frame.envelope.recipient.node_id, DEVICE);
        assert_eq!(
            fx.peer
                .open_payload(&ME, &frame.envelope.payload, veil_util::unix_secs_now_u64())
                .unwrap()
                .plaintext,
            b"targeted relay reply"
        );
    }

    #[tokio::test]
    async fn an_unresolved_delegated_reply_cannot_fall_back_to_an_old_physical_key() {
        const DEVICE: [u8; 32] = [0xB7; 32];
        let mut fx = fixture(vec![RELAY]);
        fx.certs = Arc::new(ColdDeviceDirectory {
            device: DEVICE,
            certs: vec![],
        });
        let old_key = fx.peer.seed_ring.read().unwrap().current_ek().to_vec();
        wlock!(fx.peer_mlkem).insert(
            DEVICE,
            (
                veil_e2e::PeerMlKemKey::unattested(old_key),
                std::time::Instant::now(),
            ),
        );
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload_to(DEVICE, b"wait for the exact delegated key"),
            &fx.ctx(true),
        )
        .await
        .unwrap();
        assert!(
            fx.taken().is_empty(),
            "a missing delegated certificate must not select the old standalone physical key"
        );
    }

    #[tokio::test]
    async fn a_pending_own_device_can_still_receive_its_encrypted_link_bootstrap() {
        const DEVICE: [u8; 32] = [0xB7; 32];
        let mut fx = fixture(vec![RELAY]);
        fx.certs = Arc::new(ColdDeviceDirectory {
            device: DEVICE,
            certs: vec![],
        });
        let old_key = fx.peer.seed_ring.read().unwrap().current_ek().to_vec();
        wlock!(fx.peer_mlkem).insert(
            DEVICE,
            (
                veil_e2e::PeerMlKemKey::unattested(old_key),
                std::time::Instant::now(),
            ),
        );
        let mut ctx = fx.ctx(true);
        ctx.session_instance_lookup = Some(Arc::new(AdoptedSiblingSession {
            device: DEVICE,
            current: veil_types::SessionPairing {
                identity: ME,
                instance: PEER_INSTANCE,
            },
        }));
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload_to(DEVICE, b"encrypted link bootstrap"),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(
            fx.taken().len(),
            1,
            "the own document names a pending sibling before it has adopted our identity; its bootstrap still uses its temporary key"
        );
    }

    #[test]
    fn cold_device_binding_requires_unique_current_certificate_evidence() {
        const DEVICE: [u8; 32] = [0xB7; 32];
        let fx = fixture(vec![RELAY]);
        let now = veil_util::unix_secs_now_u64();
        let cert = fx.certs.resolve_cert_cached(PEER).unwrap();
        let remember = |identity, instance, key, until, physical| {
            wlock!(fx.me.peer_ratchet_keys)
                .entry(identity)
                .or_default()
                .remember_with_device(instance, key, until, physical);
        };
        assert_eq!(fx.me.verified_pairing_for_device(&DEVICE, now), None);
        remember(
            PEER,
            cert.instance_id,
            cert.ratchet_x25519_pk,
            now - 1,
            Some(DEVICE),
        );
        assert_eq!(fx.me.verified_pairing_for_device(&DEVICE, now), None);
        remember(
            PEER,
            cert.instance_id,
            cert.ratchet_x25519_pk,
            now + 10,
            None,
        );
        assert_eq!(fx.me.verified_pairing_for_device(&DEVICE, now), None);
        remember(
            PEER,
            cert.instance_id,
            cert.ratchet_x25519_pk,
            now + 10,
            Some(DEVICE),
        );
        assert_eq!(
            fx.me.verified_pairing_for_device(&DEVICE, now),
            Some((PEER, cert.instance_id))
        );
        // A rotation of the same instance is the same binding.
        remember(PEER, cert.instance_id, [0x91; 32], now + 10, Some(DEVICE));
        assert_eq!(
            fx.me.verified_pairing_for_device(&DEVICE, now),
            Some((PEER, cert.instance_id))
        );
        remember(DEVICE, cert.instance_id, [0x94; 32], now + 10, Some(DEVICE));
        assert_eq!(
            fx.me.verified_pairing_for_device(&DEVICE, now),
            Some((PEER, cert.instance_id)),
            "the old self certificate is not another delegation"
        );
        // Neither a matching prefix nor a different identity is authority.
        let mut other = DEVICE;
        other[31] ^= 1;
        assert_eq!(fx.me.verified_pairing_for_device(&other, now), None);
        remember(
            [0xE9; 32],
            cert.instance_id,
            [0x91; 32],
            now + 10,
            Some(DEVICE),
        );
        assert_eq!(fx.me.verified_pairing_for_device(&DEVICE, now), None);
        wlock!(fx.me.peer_ratchet_keys).remove(&[0xE9; 32]);
        remember(PEER, [0x92; 16], [0x93; 32], now + 10, Some(DEVICE));
        assert_eq!(fx.me.verified_pairing_for_device(&DEVICE, now), None);
        wlock!(fx.me.peer_ratchet_keys).clear();
        assert_eq!(fx.me.verified_pairing_for_device(&DEVICE, now), None);
    }

    /// CONTROL: with no session to prove an identity, the destination is still
    /// what a certificate is looked up under.
    ///
    /// Without this the guard above also passes for an implementation that
    /// ignores the destination entirely — and a peer we have never paired with
    /// would then be sealed to whatever the last pairing happened to name.
    #[tokio::test]
    async fn without_a_pairing_the_destination_still_keys_the_lookup() {
        let fx = fixture(vec![PEER, RELAY]);
        assert!(
            fx.pairing_device.is_none(),
            "vacuity guard: this fixture must offer no pairing, or the \
             control proves nothing",
        );
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"no pairing here"),
            &fx.ctx(true),
        )
        .await
        .expect("send");
        let sent = fx.taken();
        assert_eq!(sent.len(), 1);
        let hdr = veil_proto::codec::decode_header(&sent[0].1).expect("header");
        assert_eq!(
            hdr.msg_type,
            veil_proto::family::AppMsg::AppSendSealed as u16,
            "the ordinary single-name peer must keep sealing exactly as before",
        );
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
        let direct = sent
            .iter()
            .filter(|(device, _)| *device == PEER)
            .collect::<Vec<_>>();
        assert_eq!(direct.len(), 1, "one seal down the direct session");
        let body = veil_proto::app::AppSendPayload::decode(&direct[0].1[veil_proto::HEADER_SIZE..])
            .expect("body");
        let relayed = sent
            .iter()
            .find(|(hop, _)| *hop == RELAY)
            .expect("the cached sibling has its independent relay copy");
        let forward =
            veil_proto::delivery::ForwardPayload::decode(&relayed.1[veil_proto::HEADER_SIZE..])
                .unwrap();
        assert_eq!(
            sibling
                .open_payload(
                    &ME,
                    &forward.envelope.payload,
                    veil_util::unix_secs_now_u64()
                )
                .unwrap()
                .plaintext,
            b"to the device the session ends at"
        );
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

    /// Defect №35, the identity-addressed half. A contact addresses a PERSON,
    /// and the transport hands the frame to every live device of that person.
    /// Sealed once, it was keyed to one device — whichever row the certificate
    /// cache held, since the session pairing is looked up by device id and an
    /// identity is not one — so every other device refused it, said so, and
    /// the sender dropped the conversation that worked. Measured on the stand
    /// as 82 refusals in three minutes at one device.
    ///
    /// Proven where it matters: EACH device opens the frame it was handed.
    #[tokio::test]
    async fn an_identity_send_is_sealed_separately_for_each_live_device() {
        const DEVICE_ONE: [u8; 32] = [0xB7u8; 32];
        const DEVICE_TWO: [u8; 32] = [0xB8u8; 32];
        let (mut fx, sibling) = family_fixture();
        fx.outbox = Arc::new(Outbox {
            live: vec![DEVICE_ONE, DEVICE_TWO, RELAY],
            datagram: Vec::new(),
            sent: Mutex::new(Vec::new()),
            family: vec![DEVICE_ONE, DEVICE_TWO],
        });
        let mut ctx = fx.ctx(true);
        ctx.session_instance_lookup = Some(Arc::new(FamilySessions(vec![
            (
                DEVICE_ONE,
                veil_types::SessionPairing {
                    identity: PEER,
                    instance: PEER_INSTANCE,
                },
            ),
            (
                DEVICE_TWO,
                veil_types::SessionPairing {
                    identity: PEER,
                    instance: SIBLING_INSTANCE,
                },
            ),
        ])));

        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"to every device of a person"),
            &ctx,
        )
        .await
        .expect("send");

        let sent = fx.taken();
        let mut devices: Vec<[u8; 32]> = sent.iter().map(|(d, _)| *d).collect();
        devices.sort_unstable();
        assert_eq!(
            devices,
            vec![DEVICE_ONE, DEVICE_TWO],
            "every live device of the person is still handed the message",
        );
        let now = veil_util::unix_secs_now_u64();
        for (device, frame) in &sent {
            let hdr = veil_proto::codec::decode_header(frame).expect("header");
            assert_eq!(
                hdr.msg_type,
                veil_proto::family::AppMsg::AppSendSealed as u16,
                "each copy is sealed, not sent in the clear to make it fit",
            );
            let body = veil_proto::app::AppSendPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                .expect("body");
            let at = if *device == DEVICE_ONE {
                &fx.peer
            } else {
                &sibling
            };
            let opened = at
                .open_payload(&ME, &body.data, now)
                .unwrap_or_else(|e| panic!("device {:02x} cannot open its copy: {e}", device[0]));
            assert_eq!(opened.plaintext, b"to every device of a person");
            assert!(opened.authenticated);
        }
    }

    /// A fan-out copy whose seal fell back to another device's certificate is
    /// not handed to the device it was meant for: that device could only refuse
    /// it. Here the session proves DEVICE_ONE is `PEER_INSTANCE`, but only the
    /// sibling's certificate is known, so its seal falls back to the sibling.
    #[tokio::test]
    async fn a_fan_out_copy_sealed_for_another_device_is_not_sent() {
        const DEVICE_ONE: [u8; 32] = [0xB7u8; 32];
        const DEVICE_TWO: [u8; 32] = [0xB8u8; 32];
        let (mut fx, sibling) = family_fixture();
        let sibling_row = {
            let ring = sibling.seed_ring.read().expect("ring");
            veil_types::VerifiedPeerCert {
                node_id: PEER,
                instance_id: SIBLING_INSTANCE,
                mlkem_ek: ring.current_ek().to_vec(),
                ratchet_x25519_pk: ring.current_ratchet_pk(),
                cert_version: 1,
                valid_until_unix: u64::MAX,
            }
        };
        fx.certs = Arc::new(FamilyCerts(vec![sibling_row]));
        fx.outbox = Arc::new(Outbox {
            live: vec![DEVICE_ONE, DEVICE_TWO, RELAY],
            datagram: Vec::new(),
            sent: Mutex::new(Vec::new()),
            family: vec![DEVICE_ONE, DEVICE_TWO],
        });
        let mut ctx = fx.ctx(true);
        ctx.session_instance_lookup = Some(Arc::new(FamilySessions(vec![
            (
                DEVICE_ONE,
                veil_types::SessionPairing {
                    identity: PEER,
                    instance: PEER_INSTANCE,
                },
            ),
            (
                DEVICE_TWO,
                veil_types::SessionPairing {
                    identity: PEER,
                    instance: SIBLING_INSTANCE,
                },
            ),
        ])));

        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"one copy, to the device it opens on"),
            &ctx,
        )
        .await
        .expect("send");

        let devices: Vec<[u8; 32]> = fx.taken().iter().map(|(d, _)| *d).collect();
        assert_eq!(
            devices,
            vec![DEVICE_TWO],
            "the device whose copy was sealed for its sibling is not handed it"
        );
    }

    /// A frame sealed for one device of an identity goes to that device and to
    /// no other live one (defect №35, the fallback half); with that device
    /// offline it goes nowhere directly rather than to a sibling that can only
    /// refuse it. A frame with no seal keeps the fan-out it always had.
    #[test]
    fn a_sealed_frame_is_handed_only_to_the_device_it_is_sealed_for() {
        const E: [u8; 32] = [0xB7u8; 32];
        const F: [u8; 32] = [0xB8u8; 32];
        let f_instance = [0xB8u8; 16];
        let prio = veil_proto::header::priority::INTERACTIVE;
        let prefix = |d: &[u8; 32]| {
            let mut i = [0u8; 16];
            i.copy_from_slice(&d[..16]);
            i
        };
        let both = Outbox {
            live: vec![E, F],
            datagram: Vec::new(),
            sent: Mutex::new(Vec::new()),
            family: vec![E, F],
        };
        assert!(hand_to_sealed_device(
            &both,
            &PEER,
            Some(f_instance),
            &prefix,
            prio,
            vec![1]
        ));
        let to: Vec<[u8; 32]> = lock!(both.sent).iter().map(|(d, _)| *d).collect();
        assert_eq!(to, vec![F], "only the device the frame is sealed for");

        let only_e = Outbox {
            live: vec![E],
            datagram: Vec::new(),
            sent: Mutex::new(Vec::new()),
            family: vec![E],
        };
        assert!(!hand_to_sealed_device(
            &only_e,
            &PEER,
            Some(f_instance),
            &prefix,
            prio,
            vec![2]
        ));
        assert!(
            lock!(only_e.sent).is_empty(),
            "a sibling that cannot open it is not handed it"
        );

        let unsealed = Outbox {
            live: vec![E, F],
            datagram: Vec::new(),
            sent: Mutex::new(Vec::new()),
            family: vec![E, F],
        };
        assert!(hand_to_sealed_device(
            &unsealed,
            &PEER,
            None,
            &prefix,
            prio,
            vec![3]
        ));
        assert_eq!(
            lock!(unsealed.sent).len(),
            2,
            "no seal, every device, as before"
        );
    }

    /// The send path itself uses both, and refuses a seal for this device. Held
    /// in the source because the fallback they sit on runs only when the
    /// per-device fan-out did not take the frame — a race no fixture drives.
    #[test]
    fn the_fallback_send_path_steers_its_seal() {
        let src = include_str!("send.rs");
        let handler = &src[src
            .find("pub(crate) async fn handle_ipc_send(")
            .expect("handler")
            ..src.find("#[cfg(test)]").expect("tests")];
        assert!(
            handler.contains("sealed_for == own_instance"),
            "a seal for this device must not be sent"
        );
        assert!(
            handler.contains("hand_to_sealed_device("),
            "the direct hand-off must go to the sealed device only"
        );
        assert!(
            handler.contains("without_other_devices("),
            "the relay must not go through a sibling"
        );
    }

    /// Relayed, the same frame does not go through a sibling of the device it
    /// is sealed for: delivered there as that sibling's own identity's, it is
    /// refused.
    #[test]
    fn a_sealed_frame_is_not_relayed_through_a_sibling() {
        const E: [u8; 32] = [0xB7u8; 32];
        const F: [u8; 32] = [0xB8u8; 32];
        let prefix = |d: &[u8; 32]| {
            let mut i = [0u8; 16];
            i.copy_from_slice(&d[..16]);
            i
        };
        let reg = Outbox {
            live: vec![E, F, RELAY],
            datagram: Vec::new(),
            sent: Mutex::new(Vec::new()),
            family: vec![E, F],
        };
        assert_eq!(
            without_other_devices(vec![RELAY, E, F], &reg, &PEER, Some([0xB8u8; 16]), &prefix),
            vec![RELAY, F]
        );
        assert_eq!(
            without_other_devices(vec![RELAY, E, F], &reg, &PEER, None, &prefix),
            vec![RELAY, E, F],
            "nothing sealed, nothing to steer"
        );
    }

    #[tokio::test]
    async fn relay_warming_discovers_through_mesh_despite_a_cached_direct_route() {
        const LOCAL: [u8; 32] = [0x61; 32];
        const DST: [u8; 32] = [0x62; 32];
        const NEAR: [u8; 32] = [0x63; 32];
        const FAR: [u8; 32] = [0x70; 32];
        const DEAD: [u8; 32] = [0x80; 32];
        let fx = fixture(vec![DST, FAR, NEAR]);
        let notify = Arc::new(tokio::sync::Notify::new());
        let mut ctx = fx.ctx(false);
        ctx.local_node_id = LOCAL;
        ctx.route_updated = Some(Arc::clone(&notify));
        wlock!(fx.route_cache).insert(DST, DST, 1, 1);
        wlock!(fx.route_cache).insert(DST, DEAD, 2, 2);
        // The ordinary path may still use the direct session. Do not delete
        // that route merely to discover an independent fallback.
        assert_eq!(
            try_lookup_or_discover(
                &DST,
                &LOCAL,
                Some(&fx.route_cache),
                Some(fx.outbox.as_ref()),
                Some(&notify),
                None,
                None,
            )
            .await,
            Some(DST),
        );
        assert!(fx.taken().is_empty());
        let started = std::time::Instant::now();
        warm_media_route(&ctx, DST);
        assert!(started.elapsed() < Duration::from_millis(100));
        tokio::task::yield_now().await;
        let sent = fx.taken();
        assert_eq!(
            sent.len(),
            2,
            "direct-only/dead cached routes must not suppress discovery"
        );
        assert_eq!(
            sent.iter().map(|(peer, _)| *peer).collect::<Vec<_>>(),
            vec![NEAR, FAR]
        );
        for (_, frame) in sent {
            let header = codec::decode_header(&frame).expect("routing header");
            assert_eq!(
                header.family,
                veil_proto::family::FrameFamily::Routing as u8
            );
            assert_eq!(
                header.msg_type,
                veil_proto::family::RoutingMsg::RecursiveQuery as u16
            );
            let query = veil_proto::routing::RecursiveQueryPayload::decode(
                &frame[veil_proto::header::HEADER_SIZE..],
            )
            .expect("ordinary recursive query");
            assert_eq!(query.target_key, DST);
        }
        warm_media_route(&ctx, DST);
        tokio::task::yield_now().await;
        assert!(
            fx.taken().is_empty(),
            "one probe per destination while in flight"
        );
        wlock!(fx.route_cache).insert(DST, NEAR, 3, 2);
        notify.notify_waiters();
        tokio::task::yield_now().await;
        assert!(!lock!(MEDIA_ROUTE_PROBES).contains(&(LOCAL, DST)));
        assert_eq!(rlock!(fx.route_cache).lookup(&DST), Some(DST));
        assert_eq!(
            cached_discovery_hop(
                &rlock!(fx.route_cache),
                &DST,
                Some(fx.outbox.as_ref()),
                RouteDiscoveryKind::RelayOnly
            ),
            Some(NEAR),
        );
        warm_media_route(&ctx, DST);
        tokio::task::yield_now().await;
        assert!(
            fx.taken().is_empty(),
            "a live cached relay needs no new discovery"
        );
    }

    #[tokio::test]
    async fn simultaneous_local_sends_share_one_route_discovery() {
        const LOCAL: [u8; 32] = [0xA1; 32];
        const DST: [u8; 32] = [0xA2; 32];
        let fx = fixture(vec![RELAY]);
        let notify = tokio::sync::Notify::new();
        let ask = || {
            try_lookup_or_discover(
                &DST,
                &LOCAL,
                Some(&fx.route_cache),
                Some(fx.outbox.as_ref()),
                Some(&notify),
                None,
                None,
            )
        };
        let answer = async {
            tokio::task::yield_now().await;
            assert_eq!(
                fx.taken().len(),
                1,
                "concurrent sends must not multiply route/key proofs"
            );
            wlock!(fx.route_cache).insert(DST, RELAY, 10, 2);
            notify.notify_waiters();
        };
        let (a, b, c, ()) = tokio::join!(ask(), ask(), ask(), answer);
        assert_eq!([a, b, c], [Some(RELAY); 3]);
        assert!(fx.taken().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn shared_discovery_waits_for_the_key_after_the_route_reply() {
        const LOCAL: [u8; 32] = [0xA7; 32];
        const DST: [u8; 32] = [0xA8; 32];
        let fx = fixture(vec![RELAY]);
        let notify = tokio::sync::Notify::new();
        let pending = Mutex::new(std::collections::HashMap::new());
        let ask = || {
            try_lookup_or_discover(
                &DST,
                &LOCAL,
                Some(&fx.route_cache),
                Some(fx.outbox.as_ref()),
                Some(&notify),
                Some(&fx.peer_mlkem),
                Some(&pending),
            )
        };
        let answer = async {
            tokio::task::yield_now().await;
            let sent = fx.taken();
            assert_eq!(sent.len(), 1);
            let query = veil_proto::routing::RecursiveQueryPayload::decode(
                &sent[0].1[veil_proto::HEADER_SIZE..],
            )
            .unwrap();
            // The small route answer precedes its larger signed key proof.
            wlock!(fx.route_cache).insert(DST, RELAY, 10, 2);
            lock!(pending)
                .remove(&query.query_id)
                .unwrap()
                .tx
                .send(vec![])
                .unwrap();
            notify.notify_waiters();
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            assert!(
                fx.taken().is_empty(),
                "a split reply must not launch another key proof"
            );
            wlock!(fx.peer_mlkem).insert(
                DST,
                (
                    veil_e2e::PeerMlKemKey::unattested(ring(0xC5).current_ek().to_vec()),
                    std::time::Instant::now(),
                ),
            );
            notify.notify_waiters();
        };
        let start = tokio::time::Instant::now();
        let (a, b, ()) = tokio::join!(ask(), ask(), answer);
        assert_eq!([a, b], [Some(RELAY); 2]);
        assert!(start.elapsed() >= std::time::Duration::from_millis(80));
        assert!(fx.taken().is_empty());
        assert!(lock!(pending).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn unrelated_route_notifications_do_not_finish_discovery() {
        const LOCAL: [u8; 32] = [0xA9; 32];
        const DST: [u8; 32] = [0xAA; 32];
        let fx = fixture(vec![RELAY]);
        let notify = tokio::sync::Notify::new();
        let answer = async {
            tokio::task::yield_now().await;
            assert_eq!(fx.taken().len(), 1);
            // An answer for a different target is not this caller's result.
            wlock!(fx.route_cache).insert([0xAB; 32], RELAY, 10, 2);
            notify.notify_waiters();
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            wlock!(fx.route_cache).insert(DST, RELAY, 10, 2);
            notify.notify_waiters();
        };
        let (result, ()) = tokio::join!(
            try_lookup_or_discover(
                &DST,
                &LOCAL,
                Some(&fx.route_cache),
                Some(fx.outbox.as_ref()),
                Some(&notify),
                None,
                None,
            ),
            answer
        );
        assert_eq!(result, Some(RELAY));
        assert!(fx.taken().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn route_notifications_cannot_extend_the_key_wait_deadline() {
        const LOCAL: [u8; 32] = [0xAC; 32];
        const DST: [u8; 32] = [0xAD; 32];
        let fx = fixture(vec![RELAY]);
        let notify = tokio::sync::Notify::new();
        wlock!(fx.route_cache).insert(DST, RELAY, 10, 2);
        let start = tokio::time::Instant::now();
        let lookup = async {
            let route = try_lookup_or_discover(
                &DST,
                &LOCAL,
                Some(&fx.route_cache),
                Some(fx.outbox.as_ref()),
                Some(&notify),
                Some(&fx.peer_mlkem),
                None,
            )
            .await;
            // Legacy recovery can still use the route at the fixed deadline.
            assert_eq!(route, Some(RELAY));
            assert_eq!(start.elapsed(), std::time::Duration::from_millis(500));
        };
        let noise = async {
            for _ in 0..10 {
                tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                notify.notify_waiters();
            }
        };
        tokio::join!(lookup, noise);
        assert_eq!(fx.taken().len(), 1);
    }

    #[tokio::test]
    async fn cancelled_discovery_allows_a_waiter_to_recover_the_route() {
        const LOCAL: [u8; 32] = [0xA3; 32];
        const DST: [u8; 32] = [0xA4; 32];
        let fx = fixture(vec![RELAY]);
        let notify = tokio::sync::Notify::new();
        let ask = || {
            try_lookup_or_discover(
                &DST,
                &LOCAL,
                Some(&fx.route_cache),
                Some(fx.outbox.as_ref()),
                Some(&notify),
                None,
                None,
            )
        };
        let mut first = Box::pin(ask());
        tokio::select! {
            result = &mut first => panic!("lookup finished before an answer: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }
        assert_eq!(fx.taken().len(), 1);
        let mut waiter = Box::pin(ask());
        tokio::select! {
            result = &mut waiter => panic!("waiter finished before an answer: {result:?}"),
            _ = tokio::task::yield_now() => {}
        }
        // A queued caller survives cancellation of the one that sent the query.
        drop(first);
        let answer = async {
            tokio::task::yield_now().await;
            assert_eq!(
                fx.taken().len(),
                1,
                "waiter performs its own recovery query"
            );
            wlock!(fx.route_cache).insert(DST, RELAY, 10, 2);
            notify.notify_waiters();
        };
        let (result, ()) = tokio::join!(waiter, answer);
        assert_eq!(result, Some(RELAY));
    }

    /// A discovery that found no route is not repeated at once: the next send
    /// to the same unreachable destination neither waits the half second nor
    /// sends another query.
    #[tokio::test]
    async fn an_unanswered_route_discovery_is_not_repeated_at_once() {
        const NOWHERE: [u8; 32] = [0x4Du8; 32];
        let fx = fixture(vec![RELAY]);
        let notify = tokio::sync::Notify::new();
        let reg: &dyn FrameBroadcaster = &*fx.outbox;
        let ask = || {
            try_lookup_or_discover(
                &NOWHERE,
                &ME,
                Some(&*fx.route_cache),
                Some(reg),
                Some(&notify),
                None,
                None,
            )
        };
        let started = std::time::Instant::now();
        assert_eq!(ask().await, None);
        assert!(started.elapsed() >= std::time::Duration::from_millis(400));
        let queries = fx.taken().len();
        assert!(queries >= 1, "vacuity: the first discovery sent its query");

        let again = std::time::Instant::now();
        assert_eq!(ask().await, None);
        assert!(
            again.elapsed() < std::time::Duration::from_millis(100),
            "the second send did not wait out another discovery"
        );
        assert!(fx.taken().is_empty(), "and sent no second query");
    }

    /// A remembered miss lapses: a route that appears is looked for again.
    #[test]
    fn a_remembered_route_miss_lapses() {
        let (local, dst) = ([0x5Au8; 32], [0x5Bu8; 32]);
        note_route_miss(&local, &dst, RouteDiscoveryKind::Any);
        assert!(route_recently_missed(&local, &dst, RouteDiscoveryKind::Any));
        assert!(
            !route_recently_missed(&local, &dst, RouteDiscoveryKind::RelayOnly),
            "a direct-route miss must not suppress an independent relay discovery",
        );
        assert!(
            !route_recently_missed(&[0x5Cu8; 32], &dst, RouteDiscoveryKind::Any),
            "per asking node"
        );
        let long_ago = std::time::Instant::now()
            .checked_sub(ROUTE_MISS_TTL + std::time::Duration::from_secs(1))
            .expect("the clock runs further back than the window");
        ROUTE_MISSES
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((local, dst, RouteDiscoveryKind::Any), long_ago);
        assert!(
            !route_recently_missed(&local, &dst, RouteDiscoveryKind::Any),
            "past the window it is not believed"
        );
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

    #[tokio::test]
    async fn small_authored_data_retains_its_local_lane_without_disclosing_it() {
        for direct in [true, false] {
            let fx = fixture(vec![if direct { PEER } else { RELAY }]);
            let capture = Arc::new(LaneCapture(
                Mutex::new(Vec::new()),
                vec![if direct { PEER } else { RELAY }],
            ));
            let mut ctx = fx.ctx(true);
            ctx.local_priority = veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE;
            ctx.session_tx_registry = Some(capture.clone());
            let mut wh = sink().await;
            handle_ipc_send(
                &mut SendReply::Inline(&mut wh),
                &payload(false, b"small authored message"),
                &ctx,
            )
            .await
            .unwrap();
            let (lane, frame) = lock!(capture.0).pop().unwrap();
            assert!(lock!(capture.0).is_empty());
            assert_eq!(lane, veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE);
            let header = codec::decode_header(&frame).unwrap();
            let mut expected_header = FrameHeader::new(header.family, header.msg_type);
            if !direct {
                expected_header.set_priority(veil_proto::priority::INTERACTIVE);
            }
            assert_eq!(
                header.flags, expected_header.flags,
                "retain the existing direct/relay wire header, never the local source selector"
            );
            let sealed = if direct {
                veil_proto::app::AppSendPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                    .unwrap()
                    .data
                    .to_vec()
            } else {
                let forward =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                assert_eq!(forward.traffic_class, None);
                forward.envelope.payload
            };
            let opened = fx
                .peer
                .open_payload(&ME, &sealed, veil_util::unix_secs_now_u64())
                .unwrap();
            assert!(opened.authenticated);
            assert_eq!(opened.plaintext, b"small authored message");
        }
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
        assert_eq!(
            fwd.envelope.recipient,
            veil_proto::recipient::Recipient::specific(PEER, PEER_INSTANCE),
            "routing must name the same instance as the ciphertext"
        );
        let opened = fx
            .peer
            .open_payload(&ME, &fwd.envelope.payload, veil_util::unix_secs_now_u64())
            .expect("the peer opens it");
        assert_eq!(opened.plaintext, b"through a relay");
        assert!(opened.authenticated);
    }

    #[tokio::test]
    async fn relay_seal_names_the_sender_identity_when_transport_is_a_device() {
        for (control, fanout, cold) in [(false, false), (true, false), (true, true)]
            .into_iter()
            .flat_map(|(control, fanout)| [(control, fanout, true), (control, fanout, false)])
        {
            let mut fx = fixture(vec![RELAY]);
            if fanout {
                let cert = fx.certs.resolve_cert_cached(PEER).unwrap();
                fx.certs = Arc::new(FamilyCerts(vec![cert]));
            }
            let mut ctx = fx.ctx(true);
            ctx.local_node_id = [0xD7; 32];
            let mut body = payload(false, b"identity-bound relay control");
            if control {
                body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(
                    &veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT.to_be_bytes(),
                );
            }
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                .await
                .unwrap();
            if cold {
                wlock!(fx.peer.peer_ratchet_keys).clear();
            }
            let (dispatcher, _endpoint, mut receiver) =
                direct_receiver(&fx.peer, [0xE7; 32], PEER_INSTANCE);
            let (first_relay, mut relay_receiver) =
                identity_first_relay(ctx.local_node_id, [0xE7; 32]);
            let mut delivered = false;
            for (hop, frame) in fx.taken() {
                assert_eq!(hop, RELAY);
                let header = codec::decode_header(&frame).unwrap();
                let forward =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                if forward.envelope.recipient.node_id != PEER {
                    continue;
                }
                assert_eq!(forward.relay_hops, 0);
                let result = first_relay.dispatch(
                    &header,
                    &frame[veil_proto::HEADER_SIZE..],
                    veil_cfg::NodeId::from(ctx.local_node_id),
                );
                assert!(
                    matches!(result, veil_dispatcher::DispatchResult::NoResponse),
                    "a proved sender identity must pass the first relay: {result:?}"
                );
                let (lane, frame) = relay_receiver
                    .try_recv()
                    .expect("first relay must forward to the receiver's live device");
                assert_eq!(lane, veil_proto::priority::INTERACTIVE);
                let header = codec::decode_header(&frame).unwrap();
                let forwarded =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                assert_eq!(forwarded.relay_hops, 1);
                assert_eq!(forwarded.envelope.sender_node_id, ME);
                dispatcher.dispatch(
                    &header,
                    &frame[veil_proto::HEADER_SIZE..],
                    veil_cfg::NodeId::from(RELAY),
                );
                match receiver
                    .try_recv()
                    .expect("cold relay seal reached the real dispatcher")
                {
                    veil_app::registry::AppMessage::Deliver {
                        src_node_id,
                        provenance,
                        data,
                        ..
                    } => {
                        assert_eq!(src_node_id, ME);
                        assert_eq!(data.as_ref(), b"identity-bound relay control");
                        assert_eq!(
                            provenance,
                            if cold {
                                veil_app::registry::SenderProvenance::Claimed
                            } else {
                                veil_app::registry::SenderProvenance::Signed
                            },
                            "identity selection never manufactures sender authentication"
                        );
                    }
                    other => panic!("unexpected app message: {other:?}"),
                }
                assert_eq!(forward.envelope.sender_node_id, ME);
                assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                delivered = true;
            }
            assert!(delivered);
        }
    }

    #[tokio::test]
    async fn first_relay_requires_the_origin_devices_verified_identity_binding() {
        let fx = fixture(vec![RELAY]);
        let mut ctx = fx.ctx(true);
        ctx.local_node_id = [0xD7; 32];
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"identity-bound relay control"),
            &ctx,
        )
        .await
        .unwrap();
        let (_, frame) = fx.taken().pop().unwrap();
        let header = codec::decode_header(&frame).unwrap();
        let original =
            veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                .unwrap();
        assert_eq!(original.relay_hops, 0);
        assert_eq!(original.envelope.sender_node_id, ME);

        for case in [
            "no registry",
            "no origin proof",
            "another identity",
            "another device",
        ] {
            let (mut relay, mut rx) = identity_first_relay(ctx.local_node_id, [0xE7; 32]);
            let mut forward = original.clone();
            let mut arrived_from = ctx.local_node_id;
            match case {
                "no registry" => relay.session_registry = None,
                "no origin proof" => {
                    let mut sessions = relay.session_registry.as_ref().unwrap().lock().unwrap();
                    let mut entry = sessions.remove(&ctx.local_node_id).unwrap();
                    entry.validated_sovereign_identity = None;
                    sessions.insert(entry);
                }
                "another identity" => forward.envelope.sender_node_id = [0xD8; 32],
                "another device" => arrived_from = [0xD8; 32],
                _ => unreachable!(),
            }
            let result = relay.dispatch(&header, &forward.encode(), arrived_from);
            assert!(
                matches!(result, veil_dispatcher::DispatchResult::Violation(_)),
                "{case}: {result:?}"
            );
            assert!(
                rx.try_recv().is_err(),
                "{case} must not forward a claimed identity"
            );
        }

        // A legacy origin still has its transport address without a
        // sovereign entry for it. This does not authenticate the ciphertext
        // at the recipient or rename its sender.
        let (relay, mut rx) = identity_first_relay(ctx.local_node_id, [0xE7; 32]);
        let mut legacy = original;
        legacy.envelope.sender_node_id = ctx.local_node_id;
        relay
            .session_registry
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .remove(&ctx.local_node_id);
        let result = relay.dispatch(&header, &legacy.encode(), ctx.local_node_id);
        assert!(
            matches!(result, veil_dispatcher::DispatchResult::NoResponse),
            "legacy: {result:?}"
        );
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn relay_control_uses_negotiated_datagrams_and_preserves_legacy_fallback() {
        const LEGACY: [u8; 32] = [0xb8; 32];
        for device_fanout in [false, true] {
            let mut fx = fixture(vec![RELAY, LEGACY]);
            Arc::get_mut(&mut fx.outbox).unwrap().datagram = vec![RELAY];
            if device_fanout {
                let cert = fx.certs.resolve_cert_cached(PEER).unwrap();
                fx.certs = Arc::new(FamilyCerts(vec![cert]));
            }
            let mut ctx = fx.ctx(true);
            ctx.local_priority = veil_proto::priority::INTERACTIVE;
            let mut body = payload(false, b"call answer");
            body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(
                &veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT.to_be_bytes(),
            );
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                .await
                .unwrap();
            let sent = fx.taken();
            assert!(sent.iter().any(|(hop, _)| *hop == RELAY));
            assert!(sent.iter().any(|(hop, _)| *hop == LEGACY));
            let mut sealed = None;
            for (hop, bytes) in sent {
                assert_eq!(
                    codec::decode_header(&bytes).unwrap().priority(),
                    veil_proto::priority::INTERACTIVE
                );
                let body = &bytes[veil_proto::HEADER_SIZE..];
                assert_eq!(
                    veil_proto::delivery::ForwardPayload::is_realtime_datagram_eligible(body),
                    hop == RELAY,
                    "only negotiated peers may use independent datagrams"
                );
                let forward = veil_proto::delivery::ForwardPayload::decode(body).unwrap();
                assert_eq!(
                    forward.traffic_class,
                    (hop == RELAY).then_some(veil_proto::priority::INTERACTIVE)
                );
                assert!(!forward.envelope.require_ack);
                if let Some(first) = &sealed {
                    assert_eq!(&forward.envelope.payload, first);
                } else {
                    let opened = fx
                        .peer
                        .open_payload(
                            &ME,
                            &forward.envelope.payload,
                            veil_util::unix_secs_now_u64(),
                        )
                        .unwrap();
                    assert!(opened.authenticated);
                    assert_eq!(opened.plaintext, b"call answer");
                    sealed = Some(forward.envelope.payload);
                }
            }
        }
    }

    #[tokio::test]
    async fn packetized_control_preserves_authenticated_reassembly_and_legacy_hops() {
        struct ActiveControlSource(Arc<Outbox>);
        impl FrameBroadcaster for ActiveControlSource {
            fn local_source_segment_data_bytes(&self) -> Option<usize> {
                Some(768)
            }
            fn has_neutral_forward_datagram_transport(&self, peer: &[u8; 32]) -> bool {
                self.0.has_neutral_forward_datagram_transport(peer)
            }
            fn send_to(&self, peer: &[u8; 32], lane: u8, bytes: Vec<u8>) -> bool {
                assert_eq!(lane, veil_proto::ipc::LOCAL_SIGNALING_LANE);
                self.0.send_to(peer, lane, bytes)
            }
            fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {}
            fn active_node_ids(&self) -> Vec<[u8; 32]> {
                self.0.active_node_ids()
            }
        }
        const LEGACY: [u8; 32] = [0xb8; 32];
        for device_fanout in [false, true] {
            let mut fx = fixture(vec![RELAY, LEGACY]);
            Arc::get_mut(&mut fx.outbox).unwrap().datagram = vec![RELAY];
            if device_fanout {
                fx.certs = Arc::new(FamilyCerts(vec![
                    fx.certs.resolve_cert_cached(PEER).unwrap(),
                ]));
            }
            let mut ctx = fx.ctx(true);
            ctx.session_tx_registry = Some(Arc::new(ActiveControlSource(fx.outbox.clone())));
            let data = vec![0xa6; 1024];
            let mut body = payload(false, &data);
            body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(
                &veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT.to_be_bytes(),
            );
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                .await
                .unwrap();
            let sent = fx.taken();
            let modern: Vec<_> = sent.iter().filter(|(hop, _)| *hop == RELAY).collect();
            assert!(modern.len() > 2, "actual origin packetization required");
            assert!(sent.iter().any(|(hop, _)| *hop == LEGACY));
            let (dispatcher, _endpoint, mut receiver) =
                direct_receiver(&fx.peer, PEER, PEER_INSTANCE);
            for (hop, bytes) in sent.iter().rev() {
                let header = codec::decode_header(bytes).unwrap();
                assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                let wire_body = &bytes[veil_proto::HEADER_SIZE..];
                let forward = veil_proto::delivery::ForwardPayload::decode(wire_body).unwrap();
                assert!(!forward.envelope.require_ack);
                if *hop == LEGACY {
                    assert_eq!(forward.traffic_class, None);
                    assert_eq!(forward.envelope.payload[0], veil_proto::RATCHET_E2E_MARKER);
                    continue;
                }
                assert!(bytes.len() + 40 + 16 <= 1200);
                assert!(
                    veil_proto::delivery::ForwardPayload::is_realtime_datagram_eligible(wire_body)
                );
                assert_eq!(
                    forward.traffic_class,
                    Some(veil_proto::priority::INTERACTIVE)
                );
                assert_eq!(
                    forward.envelope.payload[0],
                    veil_proto::delivery::CHUNKED_ENVELOPE_MARKER
                );
                // The device-addressed fanout has a different physical target.
                // Deliver the identity-addressed path to this identity fixture.
                if forward.envelope.recipient_node_id() == PEER {
                    for _ in 0..2 {
                        dispatcher.dispatch(&header, wire_body, veil_cfg::NodeId::from(ME));
                    }
                }
            }
            assert_eq!(take_direct(&mut receiver), data);
            assert!(
                receiver.try_recv().is_err(),
                "one authenticated logical control"
            );
        }
    }

    #[tokio::test]
    async fn relay_call_control_uses_signaling_queue_when_primary_is_full() {
        for device_fanout in [false, true] {
            let mut fx = fixture(vec![RELAY]);
            if device_fanout {
                let cert = fx.certs.resolve_cert_cached(PEER).unwrap();
                fx.certs = Arc::new(FamilyCerts(vec![cert]));
            }
            let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::with_capacity(
                2,
            )));
            let mut relay = wlock!(registry).register(RELAY);
            let mut ctx = fx.ctx(true);
            ctx.session_tx_registry = Some(Arc::new(
                veil_session::glue::SessionTxBroadcaster::new(registry.clone()),
            ));
            // Leave the endpoint's primary producer full and undrained. Control
            // must use its own source queue, even on the cached per-device path.
            for byte in [7, 8] {
                assert!(rlock!(registry).send_to(
                    &RELAY,
                    veil_proto::priority::REALTIME,
                    vec![byte],
                ));
            }
            let mut body = payload(false, b"call answer");
            body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(
                &veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT.to_be_bytes(),
            );
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                .await
                .unwrap();
            for byte in [7, 8] {
                let (lane, bytes) = relay.try_recv().unwrap();
                assert_eq!(lane, veil_proto::priority::REALTIME);
                assert_eq!(&*bytes, [byte], "primary payloads remain untouched");
            }
            let copies = if device_fanout { 2 } else { 1 };
            let mut first_payload = None;
            for _ in 0..copies {
                let (lane, bytes) = relay
                    .try_recv()
                    .expect("call control must survive a full primary queue");
                assert_eq!(lane, veil_proto::ipc::LOCAL_SIGNALING_LANE);
                assert_eq!(
                    codec::decode_header(&bytes).unwrap().priority(),
                    veil_proto::priority::INTERACTIVE,
                    "the local source channel must not become a relay priority",
                );
                let forward =
                    veil_proto::delivery::ForwardPayload::decode(&bytes[veil_proto::HEADER_SIZE..])
                        .unwrap();
                assert_eq!(forward.traffic_class, None, "legacy neutral wire shape");
                if let Some(first) = &first_payload {
                    assert_eq!(&forward.envelope.payload, first);
                } else {
                    let opened = fx
                        .peer
                        .open_payload(
                            &ME,
                            &forward.envelope.payload,
                            veil_util::unix_secs_now_u64(),
                        )
                        .unwrap();
                    assert!(opened.authenticated);
                    assert_eq!(opened.plaintext, b"call answer");
                    first_payload = Some(forward.envelope.payload);
                }
            }
            assert!(relay.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn relay_call_control_proves_its_sender_without_route_discovery() {
        let fx = fixture(vec![RELAY]);
        wlock!(fx.route_cache).invalidate(&PEER);
        let mut body = payload(false, b"call offer");
        let flags = u32::from_be_bytes(
            body[veil_proto::AppIpcSendPayload::FLAGS_RANGE]
                .try_into()
                .unwrap(),
        ) | veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT;
        body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
        let mut wh = sink().await;
        handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &fx.ctx(true))
            .await
            .expect("send");
        let sent = fx.taken();
        assert_eq!(
            sent.len(),
            1,
            "control must not wait for or emit route discovery"
        );
        let fwd =
            veil_proto::delivery::ForwardPayload::decode(&sent[0].1[veil_proto::HEADER_SIZE..])
                .expect("forward");
        let opened = fx
            .peer
            .open_payload(&ME, &fwd.envelope.payload, veil_util::unix_secs_now_u64())
            .expect("opens");
        assert_eq!(opened.plaintext, b"call offer");
        assert!(
            opened.authenticated,
            "a relay offer needs origin proof, not only confidentiality"
        );
    }

    #[tokio::test]
    async fn relay_call_control_keeps_identity_instance_copy_when_device_queue_accepts() {
        use veil_proto::recipient::{InstanceTag, Recipient};
        let mut fx = fixture(vec![RELAY]);
        let cert = fx.certs.resolve_cert_cached(PEER).unwrap();
        let device = {
            let mut device = [0; 32];
            device[..16].copy_from_slice(&cert.instance_id);
            device
        };
        fx.certs = Arc::new(FamilyCerts(vec![cert]));
        // The first hop accepts a stale device route but knows the current
        // identity route. Admission to that queue cannot prove delivery.
        wlock!(fx.route_cache).insert(device, RELAY, 10_000, 2);
        let mut body = payload(false, b"call answer");
        let flags = u32::from_be_bytes(
            body[veil_proto::AppIpcSendPayload::FLAGS_RANGE]
                .try_into()
                .unwrap(),
        ) | veil_proto::ipc::IPC_SEND_FLAG_RELAY_CONTROL_COMPAT;
        body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
        let mut wh = sink().await;
        handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &fx.ctx(true))
            .await
            .unwrap();
        let forwards: Vec<_> = fx
            .taken()
            .into_iter()
            .map(|(hop, frame)| {
                assert_eq!(hop, RELAY);
                assert_eq!(
                    codec::decode_header(&frame).unwrap().priority(),
                    veil_proto::priority::INTERACTIVE
                );
                veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                    .unwrap()
            })
            .collect();
        let physical = forwards
            .iter()
            .find(|f| f.envelope.recipient == Recipient::any(device))
            .expect("physical device copy");
        let identity = forwards
            .iter()
            .find(|f| f.envelope.recipient == Recipient::specific(PEER, PEER_INSTANCE))
            .expect("accepted device queue must not suppress current identity route");
        assert_eq!(forwards.len(), 2, "one bounded copy per addressing path");
        assert_eq!(
            identity.envelope.recipient.instance_tag,
            InstanceTag::Specific(PEER_INSTANCE)
        );
        assert_eq!(
            physical.envelope.payload, identity.envelope.payload,
            "seal once per device"
        );
        assert_ne!(
            physical.envelope.content_id, identity.envelope.content_id,
            "relay dedup must not discard the alternate recipient before routing"
        );
        assert!(
            forwards
                .iter()
                .all(|f| f.traffic_class.is_none() && !f.envelope.require_ack)
        );
        let opened = fx
            .peer
            .open_payload(
                &ME,
                &identity.envelope.payload,
                veil_util::unix_secs_now_u64(),
            )
            .unwrap();
        assert!(opened.authenticated);
        assert_eq!(opened.plaintext, b"call answer");
        assert_eq!(
            veil_e2e::payload_instances(&identity.envelope.payload)
                .unwrap()
                .1,
            PEER_INSTANCE
        );
        let duplicate = fx.peer.open_payload(
            &ME,
            &physical.envelope.payload,
            veil_util::unix_secs_now_u64(),
        );
        assert!(
            matches!(&duplicate, Err(error) if error.is_unavailable_message_key()),
            "alternate addressing must be a benign cryptographic replay: {duplicate:?}"
        );
        assert_eq!(fx.peer.peer_entry_authenticated(&ME), Some(true));
    }

    #[tokio::test]
    async fn relay_media_uses_a_discovered_route_without_holding_the_first_packet() {
        use std::time::Duration;
        const DEVICE: [u8; 32] = [0xB8; 32];
        const NEARBY: [u8; 32] = [0xB9; 32];
        let fx = fixture(vec![NEARBY, RELAY]);
        let mut ctx = fx.ctx(false);
        ctx.peer_mlkem_keys = None; // call media needs no encapsulation certificate
        let notify = Arc::new(tokio::sync::Notify::new());
        ctx.route_updated = Some(Arc::clone(&notify));
        let cache = Arc::clone(&fx.route_cache);
        let discovered = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            wlock!(cache).insert(DEVICE, RELAY, 10_000, 2);
            notify.notify_waiters();
        });
        let sealed = veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC.to_vec();
        let mut body = payload_to(DEVICE, &sealed);
        let flags = veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
            | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED;
        body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
        let mut wh = sink().await;
        handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
            .await
            .expect("send");
        fx.taken(); // the first packet uses the available fallback immediately
        discovered.await.unwrap();
        handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
            .await
            .expect("send after discovery");
        let forwards: Vec<_> = fx
            .taken()
            .into_iter()
            .filter(|(_, frame)| {
                veil_proto::codec::decode_header(frame).is_ok_and(|h| {
                    h.family == veil_proto::family::FrameFamily::Delivery as u8
                        && h.msg_type == veil_proto::family::DeliveryMsg::Forward as u16
                })
            })
            .collect();
        assert_eq!(forwards.len(), 1);
        assert_eq!(forwards[0].0, RELAY, "XOR-near is not the reachable route");
        let fwd =
            veil_proto::delivery::ForwardPayload::decode(&forwards[0].1[veil_proto::HEADER_SIZE..])
                .unwrap();
        assert_eq!(fwd.envelope.payload, sealed);
    }

    #[tokio::test]
    async fn relay_media_prefers_usable_datagrams_and_keeps_ordered_fallback() {
        const DATAGRAM: [u8; 32] = [0xB8; 32];
        for ready in [true, false] {
            let mut fx = fixture(vec![RELAY, DATAGRAM]);
            Arc::get_mut(&mut fx.outbox).unwrap().datagram =
                if ready { vec![DATAGRAM] } else { Vec::new() };
            let mut ctx = fx.ctx(false);
            ctx.local_priority = veil_proto::priority::BULK; // one copy
            assert!(fx.outbox.has_datagram_transport(&RELAY));
            assert!(!fx.outbox.has_neutral_forward_datagram_transport(&RELAY));
            let sealed = veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC.to_vec();
            let mut body = payload_to(PEER, &sealed);
            let flags = veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
                | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED;
            body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                .await
                .unwrap();
            let sent = fx.taken();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].0, if ready { DATAGRAM } else { RELAY });
            assert_eq!(
                codec::decode_header(&sent[0].1).unwrap().priority(),
                veil_proto::priority::INTERACTIVE
            );
        }
    }

    #[tokio::test]
    async fn relay_source_keeps_ready_alternatives_when_cached_hops_are_warming() {
        use veil_types::LocalDatagramChannelState as State;
        const WARM: [u8; 32] = [0xB8; 32];
        const READY_A: [u8; 32] = [0xBA; 32];
        const READY_B: [u8; 32] = [0xBB; 32];
        struct Sources {
            outbox: Arc<Outbox>,
            lane: u8,
            preferred_ready: std::sync::atomic::AtomicBool,
            requests: Mutex<Vec<[u8; 32]>>,
        }
        impl FrameBroadcaster for Sources {
            fn local_datagram_channel_state(&self, peer: &[u8; 32], lane: u8) -> State {
                assert_eq!(
                    lane, self.lane,
                    "readiness must match the actual local source"
                );
                if *peer == READY_A
                    || *peer == READY_B
                    || self
                        .preferred_ready
                        .load(std::sync::atomic::Ordering::Relaxed)
                {
                    State::Ready
                } else {
                    State::Warming
                }
            }
            fn supports_local_datagram_preparation(&self) -> bool {
                true
            }
            fn prepare_local_datagram_channel(
                &self,
                peer: &[u8; 32],
                lane: u8,
                refresh: bool,
            ) -> State {
                assert!(
                    !refresh,
                    "make-before-break cannot clear an existing ready lease"
                );
                self.requests.lock().unwrap().push(*peer);
                self.local_datagram_channel_state(peer, lane)
            }
            fn has_neutral_forward_datagram_transport(&self, _: &[u8; 32]) -> bool {
                true
            }
            fn send_to(&self, peer: &[u8; 32], priority: u8, frame: Vec<u8>) -> bool {
                assert_eq!(priority, self.lane);
                // Mirrors ingress which accepts a frame even when its
                // independent child is not ready to send it yet.
                self.outbox.send_to(peer, priority, frame)
            }
            fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {
                panic!("no broadcast")
            }
            fn active_node_ids(&self) -> Vec<[u8; 32]> {
                self.outbox.active_node_ids()
            }
        }
        for (lane, expected) in [
            (veil_proto::priority::REALTIME, vec![READY_A, READY_B]),
            (veil_proto::priority::BULK, vec![READY_A]),
            (veil_proto::priority::INTERACTIVE, vec![READY_A]),
        ] {
            let fx = fixture(vec![RELAY, WARM, READY_A, READY_B]);
            {
                let mut cache = wlock!(fx.route_cache);
                cache.insert(PEER, RELAY, 10000, 1);
                cache.insert(PEER, WARM, 10000, 2);
                cache.insert(PEER, READY_A, 10000, 3);
                cache.insert(PEER, READY_B, 10000, 4);
            }
            let mut ctx = fx.ctx(false);
            ctx.local_priority = lane;
            let source_lane = if lane == veil_proto::priority::INTERACTIVE {
                veil_proto::priority::REALTIME
            } else {
                lane
            };
            let sources = Arc::new(Sources {
                outbox: fx.outbox.clone(),
                lane: source_lane,
                preferred_ready: std::sync::atomic::AtomicBool::new(false),
                requests: Mutex::new(vec![]),
            });
            ctx.session_tx_registry = Some(sources.clone());
            let mut sealed = veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC.to_vec();
            sealed.resize(128, 0xA5);
            let mut body = payload_to(PEER, &sealed);
            let flags = veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
                | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED;
            body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                .await
                .unwrap();
            let sent = fx.taken();
            assert_eq!(
                sent.iter().map(|(hop, _)| *hop).collect::<Vec<_>>(),
                expected
            );
            let mut replay_id = None;
            for (_, frame) in sent {
                let header = codec::decode_header(&frame).unwrap();
                assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                let fwd =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                assert_eq!(fwd.envelope.payload, sealed);
                assert!(!fwd.envelope.require_ack);
                if let Some(id) = replay_id {
                    assert_eq!(fwd.envelope.content_id, id);
                }
                replay_id = Some(fwd.envelope.content_id);
            }
            assert_eq!(
                *sources.requests.lock().unwrap(),
                vec![RELAY, WARM],
                "warm preferred cached routes, not only the already-ready fallback"
            );
            sources
                .preferred_ready
                .store(true, std::sync::atomic::Ordering::Relaxed);
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                .await
                .unwrap();
            let next = fx.taken();
            let preferred = if lane == veil_proto::priority::REALTIME {
                vec![RELAY, WARM]
            } else {
                vec![RELAY]
            };
            assert_eq!(
                next.iter().map(|(hop, _)| *hop).collect::<Vec<_>>(),
                preferred,
                "promote the preferred routes only after they become ready"
            );
        }
    }

    #[tokio::test]
    async fn primary_relay_diversity_does_not_add_ordered_copies_after_datagram_admission() {
        const DATAGRAM: [u8; 32] = [0xB8; 32];
        const SECOND_DATAGRAM: [u8; 32] = [0xBA; 32];
        const ORDERED: [u8; 32] = [0xBB; 32];
        struct RefuseHop(Arc<Outbox>, Option<[u8; 32]>);
        impl FrameBroadcaster for RefuseHop {
            fn has_neutral_forward_datagram_transport(&self, peer: &[u8; 32]) -> bool {
                self.0.has_neutral_forward_datagram_transport(peer)
            }
            fn send_to(&self, peer: &[u8; 32], priority: u8, frame: Vec<u8>) -> bool {
                Some(*peer) != self.1 && self.0.send_to(peer, priority, frame)
            }
            fn send_to_all_with_priority(&self, _priority: u8, _bytes: Arc<[u8]>) {}
            fn active_node_ids(&self) -> Vec<[u8; 32]> {
                self.0.active_node_ids()
            }
        }
        for (datagrams, refused, expected) in [
            (vec![DATAGRAM], None, vec![DATAGRAM]),
            (
                vec![DATAGRAM, SECOND_DATAGRAM],
                None,
                vec![DATAGRAM, SECOND_DATAGRAM],
            ),
            (
                vec![DATAGRAM, SECOND_DATAGRAM],
                Some(DATAGRAM),
                vec![SECOND_DATAGRAM],
            ),
            (vec![DATAGRAM], Some(DATAGRAM), vec![RELAY, SECOND_DATAGRAM]),
            (vec![], None, vec![RELAY, DATAGRAM]),
        ] {
            let mut fx = fixture(vec![RELAY, DATAGRAM, SECOND_DATAGRAM, ORDERED]);
            Arc::get_mut(&mut fx.outbox).unwrap().datagram = datagrams;
            let mut ctx = fx.ctx(false);
            ctx.session_tx_registry = Some(Arc::new(RefuseHop(fx.outbox.clone(), refused)));
            ctx.local_priority = veil_proto::priority::REALTIME;
            let mut sealed = veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC.to_vec();
            sealed.resize(128, 0xA5);
            let mut body = payload_to(PEER, &sealed);
            let flags = veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
                | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED;
            body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                .await
                .unwrap();
            let sent = fx.taken();
            assert_eq!(
                sent.iter().map(|(hop, _)| *hop).collect::<Vec<_>>(),
                expected
            );
            let mut replay_id = None;
            for (_, frame) in sent {
                let header = codec::decode_header(&frame).unwrap();
                assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                let forward =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                assert_eq!(forward.envelope.payload, sealed);
                if let Some(id) = replay_id {
                    assert_eq!(forward.envelope.content_id, id);
                } else {
                    replay_id = Some(forward.envelope.content_id);
                }
            }
        }
    }

    #[tokio::test]
    async fn small_primary_relay_cells_have_a_second_path_with_the_same_replay_id() {
        const ALTERNATE: [u8; 32] = [0xB8; 32];
        const OTHER: [u8; 32] = [0xBA; 32];
        // The preferred hop accepts into its queue even when it will not
        // deliver. A successful admission there must not prevent the second
        // hop from receiving a copy. Never use the final peer as a relay.
        for (lane, size, expected) in [
            (veil_proto::priority::REALTIME, 512, 2),
            (veil_proto::priority::REALTIME, 513, 1),
            (veil_proto::priority::INTERACTIVE, 128, 1),
            (veil_proto::priority::BULK, 128, 1),
            (veil_proto::priority::BACKGROUND, 128, 1),
        ] {
            let fx = fixture(vec![PEER, RELAY, ALTERNATE, OTHER]);
            let mut ctx = fx.ctx(false);
            ctx.local_priority = lane;
            let mut sealed = veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC.to_vec();
            sealed.resize(size, 0xA5);
            let mut body = payload_to(PEER, &sealed);
            let flags = veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
                | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED;
            body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
            let mut wh = sink().await;
            handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                .await
                .unwrap();
            let sent = fx.taken();
            assert_eq!(sent.len(), expected, "lane {lane}, size {size}");
            assert_eq!(sent[0].0, RELAY, "cached path remains first");
            let mut replay_id = None;
            let mut hops = std::collections::HashSet::new();
            for (hop, frame) in sent {
                assert_ne!(hop, PEER);
                assert!(hops.insert(hop), "copies require distinct first hops");
                let header = veil_proto::codec::decode_header(&frame).unwrap();
                assert_eq!(
                    header.priority(),
                    veil_proto::priority::INTERACTIVE,
                    "local lane is not a relay priority"
                );
                let fwd =
                    veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
                        .unwrap();
                assert_eq!(fwd.envelope.payload, sealed);
                if let Some(id) = replay_id {
                    assert_eq!(fwd.envelope.content_id, id, "earliest arrival wins");
                } else {
                    replay_id = Some(fwd.envelope.content_id);
                }
            }
        }
    }

    #[tokio::test]
    async fn stalled_media_discovery_does_not_hold_packets_or_start_a_query_per_packet() {
        use std::time::Duration;
        const DEVICE: [u8; 32] = [0xB7; 32];
        let fx = fixture(vec![RELAY]);
        let mut ctx = fx.ctx(false);
        ctx.route_updated = Some(Arc::new(tokio::sync::Notify::new()));
        let sealed = veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC.to_vec();
        let mut body = payload_to(DEVICE, &sealed);
        let flags = veil_proto::ipc::IPC_SEND_FLAG_RELAY_REALTIME
            | veil_proto::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED;
        body[veil_proto::AppIpcSendPayload::FLAGS_RANGE].copy_from_slice(&flags.to_be_bytes());
        let mut wh = sink().await;
        tokio::time::timeout(Duration::from_millis(100), async {
            for _ in 0..25 {
                handle_ipc_send(&mut SendReply::Inline(&mut wh), &body, &ctx)
                    .await
                    .unwrap();
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("media cannot wait for the half-second discovery timeout");
        let frames = fx.taken();
        let forwards = frames
            .iter()
            .filter(|(_, frame)| {
                codec::decode_header(frame).is_ok_and(|h| h.family == FrameFamily::Delivery as u8)
            })
            .count();
        let queries = frames
            .iter()
            .filter(|(_, frame)| {
                codec::decode_header(frame).is_ok_and(|h| h.family == FrameFamily::Routing as u8)
            })
            .count();
        assert_eq!(
            forwards, 25,
            "every packet leaves while discovery is pending"
        );
        assert_eq!(queries, 1, "one probe, not 25 parallel walks");
    }

    /// NO ROUTE AT ALL, only a live session to some relay: the send still goes,
    /// through that relay, sealed so the relay cannot read it and the peer
    /// knows who sent it. Before, this answered NO_ROUTE and the frame waited
    /// for a route that, between two devices that had both restarted, could
    /// take minutes to be announced.
    #[tokio::test]
    async fn with_no_route_a_sealed_send_goes_through_a_live_session() {
        let fx = fixture(vec![RELAY]);
        wlock!(fx.route_cache).invalidate(&PEER);
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"no route, one relay"),
            &fx.ctx(true),
        )
        .await
        .expect("send");

        let forwards: Vec<_> = fx
            .taken()
            .into_iter()
            .filter(|(_, frame)| {
                veil_proto::codec::decode_header(frame).is_ok_and(|h| {
                    h.family == veil_proto::family::FrameFamily::Delivery as u8
                        && h.msg_type == veil_proto::family::DeliveryMsg::Forward as u16
                })
            })
            .collect();
        assert_eq!(forwards.len(), 1, "the send never went out");
        let (hop, frame) = &forwards[0];
        assert_eq!(hop, &RELAY);
        let fwd = veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::HEADER_SIZE..])
            .expect("forward");
        let opened = fx
            .peer
            .open_payload(&ME, &fwd.envelope.payload, veil_util::unix_secs_now_u64())
            .expect("sealed to the peer, not readable by the relay");
        assert_eq!(opened.plaintext, b"no route, one relay");
        assert!(opened.authenticated, "the peer can tell who sent it");
    }

    /// And never in the clear: a node with no end-to-end sealing at all does
    /// not hand its frame to whichever session happens to be alive.
    #[tokio::test]
    async fn with_no_route_an_unsealed_send_is_not_relayed() {
        let fx = fixture(vec![RELAY]);
        wlock!(fx.route_cache).invalidate(&PEER);
        let mut ctx = fx.ctx(false);
        ctx.peer_mlkem_keys = None;
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload(false, b"would be plaintext"),
            &ctx,
        )
        .await
        .expect("send");

        let forwards = fx
            .taken()
            .into_iter()
            .filter(|(_, frame)| {
                veil_proto::codec::decode_header(frame).is_ok_and(|h| {
                    h.family == veil_proto::family::FrameFamily::Delivery as u8
                        && h.msg_type == veil_proto::family::DeliveryMsg::Forward as u16
                })
            })
            .count();
        assert_eq!(forwards, 0, "a plaintext frame was handed to a relay");
    }

    /// What our own document says about one of our devices — no session.
    struct OwnDevice {
        device: [u8; 32],
        pairing: veil_types::SessionPairing,
    }

    impl veil_types::SessionInstanceLookup for OwnDevice {
        fn session_instance(&self, _peer: &[u8; 32]) -> Option<[u8; 16]> {
            None
        }
        fn own_device_pairing(&self, device: &[u8; 32]) -> Option<veil_types::SessionPairing> {
            (*device == self.device).then_some(self.pairing)
        }
    }

    /// ONE CONVERSATION WITH A SIBLING, whatever path the frame takes. With no
    /// session the sibling was sealed to under its DEVICE id, while its frames
    /// come back under the IDENTITY: two conversations, and the one we sent in
    /// never turned (26 240 steps on the stand, 2026-09-23).
    #[tokio::test]
    async fn a_sibling_with_no_session_is_sealed_under_the_identity() {
        let sibling_device = [0xB9u8; 32];
        let fx = fixture(vec![RELAY]);
        let mut ctx = fx.ctx(true);
        ctx.session_instance_lookup = Some(Arc::new(OwnDevice {
            device: sibling_device,
            pairing: veil_types::SessionPairing {
                identity: PEER,
                instance: PEER_INSTANCE,
            },
        }));
        let mut wh = sink().await;
        handle_ipc_send(
            &mut SendReply::Inline(&mut wh),
            &payload_to(sibling_device, b"to my other device"),
            &ctx,
        )
        .await
        .expect("send");

        let keys = fx.me.store.keys();
        assert!(
            keys.contains(&veil_e2e::ConversationKey {
                local_instance_id: MY_INSTANCE,
                peer_node_id: PEER,
                peer_instance_id: PEER_INSTANCE,
            }),
            "the conversation is not keyed by the identity: {keys:?}",
        );
        assert!(
            keys.iter().all(|k| k.peer_node_id != sibling_device),
            "a second conversation was keyed by the device id",
        );
    }

    /// NOWHERE TO GO, NOTHING SPENT. With no session and no hop the frame goes
    /// nowhere, and it used to burn a step of the sending chain anyway: an
    /// outbox re-driving into no route walked one conversation 26 240 steps
    /// ahead of a receiver that can skip 1 000 (stand, 2026-09-23).
    #[tokio::test]
    async fn a_send_with_no_path_spends_no_ratchet_step() {
        let fx = fixture(vec![]);
        wlock!(fx.route_cache).invalidate(&PEER);
        for _ in 0..3 {
            let mut wh = sink().await;
            handle_ipc_send(
                &mut SendReply::Inline(&mut wh),
                &payload(false, b"into the void"),
                &fx.ctx(true),
            )
            .await
            .expect("send");
        }
        assert!(fx.taken().is_empty(), "premise: nothing had anywhere to go");
        assert_eq!(
            fx.me.store.version(),
            0,
            "a send that went nowhere advanced the ratchet",
        );
        assert!(fx.me.store.is_empty(), "and opened no conversation either");
    }

    /// The anonymous path is standard traffic and must keep working. Gating it    /// The anonymous path is standard traffic and must keep working. Gating it
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

    type CapturedDatagram = (u8, [u8; 32], [u8; 32], u32, Vec<u8>);

    /// Records the `reply` argument of every direct send; every other method is
    /// off this path and panics rather than silently passing.
    #[derive(Default)]
    pub(super) struct RecordingSender {
        replies: Mutex<Vec<ReplyPath>>,
        pub(super) lanes: Mutex<Vec<CapturedDatagram>>,
    }

    impl veil_types::AnonOnionSender for RecordingSender {
        fn send_authenticated_on_local_lane<'a>(
            &'a self,
            lane: u8,
            target: [u8; 32],
            app: [u8; 32],
            endpoint: u32,
            data: &'a [u8],
        ) -> AnonFut<'a> {
            self.lanes
                .lock()
                .unwrap()
                .push((lane, target, app, endpoint, data.to_vec()));
            Box::pin(async { Ok(()) })
        }
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
            _: u64,
        ) -> bool {
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
