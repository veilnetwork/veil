//! `NetworkPeerQuerier` — sends real OVL1 FIND_NODE requests over active sessions.
//!
//! Uses `SessionOutbox` to route pre-encoded frames to the `SessionRunner` for a
//! given peer. The runner writes the frame, stores the `request_id` → oneshot
//! mapping, and fulfils the oneshot when a matching `FIND_NODE_RESPONSE` arrives.
//!
//! ## — V2 + ResolveTransport flow
//!
//! `find_node` now uses the V2 wire path internally:
//!
//! 1. Send `FindNodeV2` to the peer; receive `FindNodeV2Response` (node_ids only).
//! 2. For each returned `node_id`, check `TransportCache` first.
//! 3. On cache miss, send `ResolveTransport(node_id)` to the **same peer** that
//!    gave us the node_id (they have the routing-table entry).
//! 4. Insert resolved transports into the cache (TTL ~1h).
//! 5. Build `Vec<Contact>` from {node_id, transport, mode=Public} pairs.
//!
//! The trait return type (`Vec<Contact>`) is unchanged so the iterative
//! walker (`find_node_iterative`) consumes V2 transparently. Peers that
//! don't yet implement V2 (pre-) reject the message-type with a
//! `Violation`; the outbox times out, returns empty, and the iterative
//! walker drops the peer naturally. Migration support (capability
//! negotiation) is /.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use tokio::time::{Duration, timeout};

use crate::iterative::{FindValueResult, PeerQuerier};
use crate::routing::Contact;
use crate::traits::FrameRouter;
use crate::transport_cache::TransportCache;
use veil_proto::codec::encode_header;
use veil_proto::discovery::{
    FindNodeV2Payload, FindNodeV2Response, FindValuePayload, ResolveTransportPayload,
    ResolveTransportResponse,
};
use veil_proto::family::{DiscoveryMsg, FrameFamily};
use veil_proto::header::FrameHeader;

/// Implements [`PeerQuerier`] by sending actual OVL1 FIND_NODE / V2 frames.
///
/// Owns (or shares) a [`TransportCache`] used to skip the
/// [`ResolveTransport`] round-trip when a previously-resolved transport
/// is still warm.
pub struct NetworkPeerQuerier {
    outbox: Arc<dyn FrameRouter>,
    next_request_id: AtomicU32,
    /// Number of closest nodes to request per FIND_NODE query.
    k: u8,
    /// Timeout for a single FIND_NODE / FIND_VALUE / ResolveTransport
    /// RPC round-trip.
    find_node_timeout: Duration,
    /// 2: local LRU+TTL cache for `node_id → transport`
    /// mappings observed from prior `ResolveTransport` responses. Cache
    /// hits skip a round-trip on the V2 lookup path.
    cache: Arc<Mutex<TransportCache>>,
    ///our own node id, bound into every
    /// `ResolveTransport` PoW solution we mine. The responder pulls
    /// the same id from its OVL1 session context (peer_id) and verifies
    /// the PoW under the matching pair, so a forged or reused PoW
    /// never satisfies anyone else's check.
    local_node_id: [u8; 32],
    /// Memoised resolve-PoW solutions: target node_id → (time_bucket, nonce).
    /// A 16-bit PoW is ~65 k BLAKE3 hashes (~7 ms); re-mining it for the SAME
    /// target on every `ResolveTransport` — which the outbound-connector and
    /// onion-circuit retry loops do continuously when a peer/hop is unreachable
    /// — was the dominant CPU cost on a stalled embedded node (profiled ~92%,
    /// starving the IPC handler so app FFI calls hit their 12 s timeout and the
    /// UI froze). A solution stays valid for its whole time bucket
    /// (`RESOLVE_POW_BUCKET_SECONDS`), so reuse it within that window instead of
    /// re-mining. Reuse is sound — the verifier only checks leading-zero-bits +
    /// bucket freshness, not nonce uniqueness — and the map self-bounds to the
    /// current bucket's targets.
    resolve_pow_cache: Arc<Mutex<HashMap<[u8; 32], (u32, [u8; 16])>>>,
}

impl NetworkPeerQuerier {
    /// Build a querier with its own private transport cache. Production
    /// code that wants to share a cache across multiple querier instances
    /// uses [`Self::with_cache`].
    pub fn new(
        outbox: Arc<dyn FrameRouter>,
        k: u8,
        find_node_timeout: Duration,
        local_node_id: [u8; 32],
    ) -> Self {
        Self::with_cache(
            outbox,
            k,
            find_node_timeout,
            Arc::new(Mutex::new(TransportCache::new())),
            local_node_id,
        )
    }

    /// Build a querier that shares its [`TransportCache`] with other
    /// callers — used by the runtime to give every DHT-walk consistent
    /// warm-cache hits.
    pub fn with_cache(
        outbox: Arc<dyn FrameRouter>,
        k: u8,
        find_node_timeout: Duration,
        cache: Arc<Mutex<TransportCache>>,
        local_node_id: [u8; 32],
    ) -> Self {
        Self {
            outbox,
            next_request_id: AtomicU32::new(1),
            k,
            find_node_timeout,
            cache,
            local_node_id,
            resolve_pow_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Direct accessor to the shared cache — exposed so the runtime's
    /// maintenance task can call `evict_stale` on it periodically.
    pub fn cache(&self) -> Arc<Mutex<TransportCache>> {
        Arc::clone(&self.cache)
    }

    fn build_frame(&self, msg_type: DiscoveryMsg, request_id: u32, body: Vec<u8>) -> Vec<u8> {
        let mut hdr = FrameHeader::new(FrameFamily::Discovery as u8, msg_type as u16);
        hdr.body_len = body.len() as u32;
        hdr.request_id = request_id;
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&body);
        frame
    }

    fn build_find_node_v2_frame(&self, request_id: u32, target: [u8; 32]) -> Vec<u8> {
        let body = FindNodeV2Payload { target, k: self.k }.encode().to_vec();
        self.build_frame(DiscoveryMsg::FindNodeV2, request_id, body)
    }

    /// Build a `ResolveTransport` frame with a freshly mined PoW
    /// solution. Returns `None` if the solver fails to find a valid
    /// nonce in the current minute (vanishingly unlikely at 16 bits —
    /// 1 M attempts > 2^20 ≫ 2^16); caller should treat it like an RPC
    /// failure and skip the lookup.
    async fn build_resolve_transport_frame(
        &self,
        request_id: u32,
        node_id: [u8; 32],
    ) -> Option<Vec<u8>> {
        let (time_bucket, pow_nonce) = self.resolve_pow_for(node_id).await?;
        let body = ResolveTransportPayload {
            node_id,
            time_bucket,
            pow_nonce,
        }
        .encode()
        .to_vec();
        Some(self.build_frame(DiscoveryMsg::ResolveTransport, request_id, body))
    }

    /// Return a resolve-PoW for `node_id`, reusing a memoised solution from the
    /// current time bucket if present, else mining a fresh one and caching it.
    /// This collapses the repeated ~7 ms mines that a resolve-retry loop would
    /// otherwise pay for the same target every attempt. The map is pruned to the
    /// current bucket on each fresh mine so it can't grow unbounded.
    ///
    /// A cache MISS mines on `spawn_blocking`, NOT inline: a 16-bit BLAKE3 grind
    /// must never run on a tokio runtime worker (it would block that worker's
    /// async tasks — IPC + session I/O — for the mine's duration, the same
    /// starvation that timed out app FFI calls + hung the UI). PEX + lazy PoW
    /// already do this; this is the last inline PoW moved off the hot path.
    async fn resolve_pow_for(&self, node_id: [u8; 32]) -> Option<(u32, [u8; 16])> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let current_bucket = (now / veil_proto::discovery::RESOLVE_POW_BUCKET_SECONDS) as u32;
        {
            let cache = self
                .resolve_pow_cache
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(&(bucket, nonce)) = cache.get(&node_id)
                && bucket == current_bucket
            {
                return Some((bucket, nonce));
            }
        } // release the lock BEFORE the await — never hold a std Mutex across .await
        let local_node_id = self.local_node_id;
        let mined = tokio::task::spawn_blocking(move || {
            veil_proto::discovery::mine_resolve_pow_now(&local_node_id, &node_id)
        })
        .await
        .ok()??;
        let mut cache = self
            .resolve_pow_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // Drop stale-bucket entries before inserting → bounded by this bucket's
        // distinct resolve targets.
        cache.retain(|_, &mut (b, _)| b == mined.0);
        cache.insert(node_id, mined);
        Some(mined)
    }

    fn build_find_value_frame(&self, request_id: u32, key: [u8; 32]) -> Vec<u8> {
        let body = FindValuePayload { key }.encode().to_vec();
        self.build_frame(DiscoveryMsg::FindValue, request_id, body)
    }

    /// Send `ResolveTransport(node_id)` to `peer_id`; return the
    /// **verified** transport URL on success, `None` on timeout
    /// decode error, `not_found` reply, OR signature-verification
    /// failure. Cache-on-success is the caller's responsibility (so
    /// failed resolutions don't pollute the cache).
    ///
    /// b: mines a PoW solution before sending — this is
    /// where the censor-resistance cost shows up on the client side.
    /// Median ~7 ms on a modern x86 core; bounded by `mine_resolve_pow`'s
    /// `max_attempts` cap.
    ///
    /// c: the response carries a `SignedTransportAnnouncement`
    /// signed by the **target node's** identity key — we verify the
    /// signature, the `BLAKE3(pubkey) == node_id` binding, and the
    /// non-expiry before extracting the transport URL. A malicious
    /// resolver that returned a forged transport (or one for the
    /// wrong node_id) is silently rejected here.
    async fn resolve_transport_rpc(&self, peer_id: [u8; 32], node_id: [u8; 32]) -> Option<String> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let frame = self.build_resolve_transport_frame(request_id, node_id).await?;
        let rx = self.outbox.send_request(peer_id, request_id, frame)?;
        let body = match timeout(self.find_node_timeout, rx).await {
            Ok(Ok(Some(body))) => body,
            _ => return None,
        };
        let resp = ResolveTransportResponse::decode(&body).ok()?;
        if resp.node_id != node_id {
            return None;
        }
        let announcement = resp.announcement?;
        // Defence-in-depth: the responder is supposed to send only
        // announcements where `announcement.node_id == requested node_id`
        // but verify it ourselves before trusting the cache.
        if announcement.node_id != node_id {
            return None;
        }
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if !veil_proto::discovery::verify_transport_announcement(&announcement, now_unix) {
            return None;
        }
        Some(announcement.transport)
    }

    /// Resolve a list of node_ids (vouched for by `via_peer`) to reachable
    /// `Contact`s: transport cache hit, else a PoW-gated `ResolveTransport`
    /// RPC to `via_peer`. node_ids that can't be resolved (peer says
    /// not_found / RPC fails) are dropped — we have no way to reach them.
    /// Shared by `find_node` (V2) and `find_value` so neither relies on
    /// transports being present in the wire response (C-06).
    async fn resolve_node_ids(&self, via_peer: [u8; 32], node_ids: Vec<[u8; 32]>) -> Vec<Contact> {
        // Sequential per-node_id lookups. K is small (default 20) and most
        // calls hit cache after a brief warm-up; parallel resolution is an
        // optimisation.
        let mut contacts = Vec::with_capacity(node_ids.len());
        for nid in node_ids {
            // Skip self (the routing table never returns self, but be defensive).
            if nid == via_peer {
                continue;
            }
            // Cache hit?
            if let Some(transport) = self
                .cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .lookup(&nid)
            {
                contacts.push(Contact::with_mode(
                    nid,
                    transport,
                    veil_types::DiscoveryMode::Public,
                ));
                continue;
            }
            // Cache miss → ResolveTransport from the peer that vouched for nid.
            let Some(transport) = self.resolve_transport_rpc(via_peer, nid).await else {
                continue;
            };
            self.cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(nid, transport.clone());
            contacts.push(Contact::with_mode(
                nid,
                transport,
                veil_types::DiscoveryMode::Public,
            ));
        }
        contacts
    }
}

impl PeerQuerier for NetworkPeerQuerier {
    /// V2 + per-id transport resolution flow.
    ///
    /// 1. `FindNodeV2(target)` → `Vec<node_id>`.
    /// 2. For each `node_id`: cache lookup → `ResolveTransport` on miss.
    /// 3. Build `Vec<Contact>` for the ones we resolved. Drops node_ids
    ///    whose transport could not be resolved (peer hides them as
    ///    `not_found` — typically because they're non-Public).
    fn find_node<'a>(
        &'a self,
        peer_id: [u8; 32],
        target: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Vec<Contact>> + Send + 'a>> {
        Box::pin(async move {
            // ── Step 1: FindNodeV2 ─────────────────────────────────────
            // wrapping_add: u32 counter wraps after ~4B requests. The
            // pending map is bounded (`max_pending_responses`) and entries
            // are TTL-evicted long before any realistic wraparound, so
            // collision risk is negligible in practice.
            let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
            let frame = self.build_find_node_v2_frame(request_id, target);
            let Some(rx) = self.outbox.send_request(peer_id, request_id, frame) else {
                return vec![];
            };
            let v2_resp = match timeout(self.find_node_timeout, rx).await {
                Ok(Ok(Some(body))) => match FindNodeV2Response::decode(&body) {
                    Ok(r) => r,
                    Err(_) => return vec![],
                },
                _ => return vec![],
            };

            // ── Step 2-3: resolve each node_id to a reachable Contact ──
            // (transport cache → PoW-gated ResolveTransport). Shared with
            // find_value so neither path relies on transports being present
            // in the wire response (C-06).
            self.resolve_node_ids(peer_id, v2_resp.node_ids).await
        })
    }

    fn find_value<'a>(
        &'a self,
        peer_id: [u8; 32],
        key: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = FindValueResult> + Send + 'a>> {
        Box::pin(async move {
            let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed); // see find_node for wraparound rationale
            let frame = self.build_find_value_frame(request_id, key);

            let Some(rx) = self.outbox.send_request(peer_id, request_id, frame) else {
                return FindValueResult::Nodes(vec![]);
            };

            let t = self.find_node_timeout;
            match timeout(t, rx).await {
                Ok(Ok(Some(body))) => {
                    use veil_proto::discovery::FindValueResponse;
                    match FindValueResponse::decode(&body) {
                        Ok(FindValueResponse::Value(v)) => FindValueResult::Value(v),
                        Ok(FindValueResponse::Nodes(nodes)) => {
                            // C-06: the response now carries node_ids only (no
                            // transports). Resolve each to a reachable Contact
                            // via the PoW-gated ResolveTransport path, exactly
                            // as find_node does — so the walk can still dial on.
                            let node_ids: Vec<[u8; 32]> =
                                nodes.into_iter().map(|n| n.node_id).collect();
                            FindValueResult::Nodes(self.resolve_node_ids(peer_id, node_ids).await)
                        }
                        Err(_) => FindValueResult::Nodes(vec![]),
                    }
                }
                _ => FindValueResult::Nodes(vec![]),
            }
        })
    }
}
