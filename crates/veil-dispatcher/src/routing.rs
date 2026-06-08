use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use veil_cfg::NodeId;
use veil_types::NodeIdBytes;
use veil_util::{lock, rlock, wlock};

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

use super::{DispatchResult, FrameDispatcher, encode_routing_frame};
use veil_proto::{
    family::RoutingMsg,
    header::FrameHeader,
    routing::{
        PowAcceptPayload, PowChallengePayload, PowResponsePayload, RecursiveQueryPayload,
        RecursiveResponsePayload, RouteAnnounceAliasedPayload, RouteAnnouncePayload,
        RouteRequestPayload, RouteResponsePayload, RouteUpdatePayload, RouteWithdrawAliasedPayload,
        RouteWithdrawPayload, VersionVectorSyncPayload, recursive_query_type, route_update_action,
    },
};

// ── Route-score constants ────────────────────────────────────────────────────
//
// Route score = (hop_count × HOP_SCORE_UNIT / reachability) × SCORE_MILLIUNIT_SCALE
//
// Lower score is better (RouteCache evicts highest-score entries).
//
// `HOP_SCORE_UNIT = 10` means each additional hop adds 10 score-points before
// reachability adjustment. The value is chosen so that a 1-hop route through
// a 50%-reachable peer (score ≈ 20 000) still beats a 3-hop route through a
// perfect peer (score = 30 000), but a flaky peer is penalised appropriately.
//
// `SCORE_MILLIUNIT_SCALE = 1000` converts the float result to an integer with
// three decimal digits of resolution, avoiding NaN / partial_cmp issues in
// RouteCache comparisons.
//
// `MAX_GOSSIP_HOPS = 7` is the TTL-decremented hop limit at which a gossip
// frame is *forwarded*. A value of 8 is accepted but not re-propagated
// limiting the gossip diameter to 8 relay hops (covers ~256-node fan-out
// with a branching factor of 2).
//
// `MIN_REACHABILITY = 0.01` prevents division by zero for unreachable peers
// and caps the score at `HOP_SCORE_UNIT × 8 × SCORE_MILLIUNIT_SCALE / 0.01 = 800 000`
// well inside u32::MAX (≈ 4.2 × 10⁹).
pub const HOP_SCORE_UNIT: f32 = 10.0;
pub const SCORE_MILLIUNIT_SCALE: f32 = 1_000.0;
pub const MIN_REACHABILITY: f32 = 0.01;
/// Minimum score for a relay announce from a direct peer (via_node_id == peer_id
/// hop_count > 1). Matches the score inserted by `handle_route_response` (20_000)
/// so that a direct relay-hop is never cheaper than a freshly-confirmed RouteResponse
/// for the same destination.
pub const MIN_DIRECT_RELAY_SCORE: u32 = 20_000;

/// Number of `NeighborOffer` hints emitted per peer-gossip exchange (on
/// session establish/drop and the periodic heartbeat). Small + bounded so the
/// exchange stays O(degree) regardless of routing-table size.
pub const PEER_GOSSIP_SAMPLE: usize = 8;

impl FrameDispatcher {
    pub fn dispatch_routing(
        &self,
        _header: &FrameHeader,
        body: &[u8],
        peer_id: NodeId,
    ) -> DispatchResult {
        let msg = match RoutingMsg::try_from(_header.msg_type) {
            Ok(m) => m,
            Err(_) => {
                return DispatchResult::Violation(format!(
                    "unknown routing msg_type {}",
                    _header.msg_type
                ));
            }
        };
        match msg {
            RoutingMsg::RouteAnnounce => self.handle_route_announce(body, peer_id),
            RoutingMsg::RouteWithdraw => self.handle_route_withdraw(body, peer_id),
            RoutingMsg::RouteRequest => self.handle_route_request(body, peer_id),
            RoutingMsg::RouteResponse => self.handle_route_response(body, peer_id),
            RoutingMsg::PowChallenge => self.handle_pow_challenge(body, peer_id),
            RoutingMsg::PowResponse => self.handle_pow_response(body, peer_id),
            RoutingMsg::PowAccept => self.handle_pow_accept(body, peer_id),
            RoutingMsg::RouteAnnounceAliased => self.handle_route_announce_aliased(body, peer_id),
            RoutingMsg::RouteWithdrawAliased => self.handle_route_withdraw_aliased(body, peer_id),
            // 290: route discovery — handled by DiscoveryForwarder.
            RoutingMsg::RouteDiscover => {
                use veil_proto::routing::RouteDiscoveryPacket;
                use veil_routing::discovery_forwarder::{DiscoveryNeighbor, ForwardDecision};

                let pkt = match RouteDiscoveryPacket::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad RouteDiscover: {e}")),
                };

                // Build neighbor list from active sessions.
                let neighbors: Vec<DiscoveryNeighbor> =
                    if let Some(ref reg) = self.session_tx_registry {
                        wlock!(reg)
                            .active_node_ids()
                            .into_iter()
                            .filter(|id| id != peer_id.as_bytes())
                            .map(|id| DiscoveryNeighbor {
                                node_id: id,
                                role: veil_cfg::NodeRole::Core,
                            })
                            .collect()
                    } else {
                        vec![]
                    };

                let now_secs = veil_util::unix_secs_now_u64();
                let decision = lock!(self.discovery_forwarder).handle(
                    &pkt,
                    peer_id.as_bytes(),
                    &neighbors,
                    now_secs,
                );

                match decision {
                    ForwardDecision::Forward(next_hop) => {
                        // Re-encode with decremented TTL and forward.
                        let mut fwd_pkt = pkt;
                        fwd_pkt.ttl = fwd_pkt.ttl.saturating_sub(1);
                        let frame =
                            encode_routing_frame(RoutingMsg::RouteDiscover, &fwd_pkt.encode());
                        if let Some(ref reg) = self.session_tx_registry {
                            wlock!(reg).send_to(&next_hop, veil_proto::priority::BACKGROUND, frame);
                        }
                    }
                    ForwardDecision::Respond => {
                        // TTL reached 0 and we can accept connections — send offer back.
                        let transports = self.listen_transports_snapshot();
                        let offer = veil_proto::routing::RouteDiscoverOfferPayload {
                            responder_node_id: self.local_node_id,
                            transports,
                        };
                        let frame =
                            encode_routing_frame(RoutingMsg::RouteDiscoverOffer, &offer.encode());
                        if let Some(ref reg) = self.session_tx_registry {
                            wlock!(reg).send_to(
                                peer_id.as_bytes(),
                                veil_proto::priority::INTERACTIVE,
                                frame,
                            );
                        }
                    }
                    ForwardDecision::Drop(_) => {} // silently drop (rate-limited, invalid PoW, etc.)
                }
                DispatchResult::NoResponse
            }

            RoutingMsg::RouteDiscoverOffer => {
                // An offer from a remote node in response to our RouteDiscover.
                // Extract the responder's transport URIs and attempt to connect.
                use veil_proto::routing::RouteDiscoverOfferPayload;
                let offer = match RouteDiscoverOfferPayload::decode(body) {
                    Ok(o) => o,
                    Err(e) => {
                        return DispatchResult::Violation(format!("bad RouteDiscoverOffer: {e}"));
                    }
                };
                let redacted_transports: Vec<_> = offer
                    .transports
                    .iter()
                    .map(|t| veil_util::redact_addr_for_log(t).into_owned())
                    .collect();
                self.logger.info(
                    "route.discover_offer",
                    format!(
                        "responder={} transports={:?}",
                        veil_util::hex_short(&offer.responder_node_id),
                        redacted_transports,
                    ),
                );
                // Add the responder to the DHT routing table so future lookups
                // can reach it directly. : NeighborOffer bodies are
                // peer-controlled — route via the unverified pool so malicious
                // peers can't eclipse our view with forged (node_id, transport)
                // pairs. Promotion to the verified routing table happens only
                // after a real OVL1 handshake with this node_id succeeds.
                if let Some(transport) = offer.transports.first() {
                    // attribute to the sending peer so a
                    // Sybil source can't fill the pending pool with forged
                    // (node_id, transport) pairs.
                    self.dht.add_contact_unverified_from(
                        *peer_id.as_bytes(),
                        veil_dht::routing::Contact::new(offer.responder_node_id, transport),
                    );
                }
                DispatchResult::NoResponse
            }
            // recursive DHT routing
            RoutingMsg::RecursiveQuery => self.handle_recursive_query(body, peer_id),
            RoutingMsg::RecursiveResponse => self.handle_recursive_response(body, peer_id),
            // event-driven route sync
            RoutingMsg::RouteUpdate => self.handle_route_update_event(body, peer_id),
            RoutingMsg::VersionVectorSync => self.handle_version_vector_sync(body, peer_id),
        }
    }

    fn handle_route_announce(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        if let Some(m) = &self.metrics {
            m.inc_gossip_announces_rx();
        }
        let p = match RouteAnnouncePayload::decode(body) {
            Ok(p) => p,
            Err(e) => return DispatchResult::Violation(format!("bad RouteAnnounce: {e}")),
        };
        // Timestamp freshness check.
        //
        // The timestamp is signed (included in `signable_bytes`) so it cannot
        // be altered by a relay. We still check it to prevent:
        // (a) Stale route injection: an old (expired) announcement gossipped
        // long after the original node went offline — the receiver has no
        // way to know the route is dead.
        // (b) Far-future timestamps: an attacker crafts a legitimate-looking
        // announcement with `timestamp = now + days`, making the route
        // appear "fresh" indefinitely.
        //
        // A generous age window (MAX_ROUTE_ANNOUNCE_AGE_SECS = 300 s) covers
        // worst-case gossip propagation latency (max_gossip_hops × per-hop RTT).
        {
            let now_ts = veil_util::unix_secs_now_u32();
            let age = now_ts.saturating_sub(p.timestamp);
            if age > veil_proto::budget::MAX_ROUTE_ANNOUNCE_AGE_SECS {
                return DispatchResult::NoResponse; // stale
            }
            let skew = p.timestamp.saturating_sub(now_ts);
            if skew > veil_proto::budget::MAX_ROUTE_ANNOUNCE_SKEW_SECS {
                return DispatchResult::NoResponse; // far-future timestamp
            }
        }
        // Dedup check.
        let already_seen = lock!(self.route_seen_set).check_and_insert(
            p.origin_node_id,
            p.via_node_id,
            p.sequence,
        );
        if already_seen {
            return DispatchResult::NoResponse;
        }
        // NOTE (audit M6): the sequence-monotonicity guard is deliberately NOT
        // here. It mutates durable per-(origin, via) state, so it must run only
        // AFTER the via==peer and signature checks below — otherwise a forged
        // or unauthenticated frame could poison the counter before being
        // dropped. See the relocated block further down.
        // every forwarder in the gossip chain calls
        // `build_announce_forward`, which rewrites `via_node_id` to its own
        // id and re-signs. So on the wire `p.via_node_id` MUST equal the
        // transport-layer `peer_id` — any divergence is an attacker
        // spoofing the via-field to impersonate another relay. Rejecting
        // this case kills the "unknown origin gossip forward" Sybil path
        // without needing a wire-format change (the old `else` branch that
        // handled via!= peer is now dead by construction).
        if &p.via_node_id != peer_id.as_bytes() {
            if let Some(m) = &self.metrics {
                m.inc_unknown_origin_gossip_rejected();
            }
            return DispatchResult::Violation(
                "RouteAnnounce: via_node_id does not match transport sender".to_owned(),
            );
        }
        // verify the via-hop signer. Post-461.7 invariant
        // (`via_node_id == peer_id` checked above) means the signer is
        // always the directly-connected peer — we have their pubkey from
        // the handshake, so sig verification is reliable. The former
        // `else` branch that tried to verify gossip hops against
        // `origin_node_id`'s pubkey was dead code — relays re-sign with
        // their own key in `build_announce_forward`, so origin's
        // signature never reaches second-hop receivers.
        match self.check_routing_sig(peer_id.as_bytes(), &p.signable_bytes(), &p.signature) {
            SigResult::Valid => {}
            SigResult::UnknownKey => {
                // Key not yet cached — race between session registration
                // and first RouteAnnounce. Drop the frame silently; the
                // next periodic announce will succeed once the key is cached.
                return DispatchResult::NoResponse;
            }
            SigResult::Invalid => {
                return DispatchResult::Violation(
                    "RouteAnnounce: invalid signature from direct peer".to_owned(),
                );
            }
        }
        // a direct peer must never claim hop_count=0 for a foreign
        // origin. hop_count=0 means "I AM the origin", so if origin_node_id ≠
        // peer_id the frame is self-contradictory — a single peer identity
        // cannot both be the via-node and a different origin simultaneously.
        // hop_count=1 (and higher) are legitimate: they mean "the origin is 1+
        // hops away from me", which is normal relay advertising.
        if p.hop_count == 0 && &p.origin_node_id != peer_id.as_bytes() {
            return DispatchResult::Violation(
                "RouteAnnounce: direct peer claims hop_count=0 for a foreign origin".to_owned(),
            );
        }
        // Sequence-monotonicity guard (audit M6: relocated here, after the
        // via==peer + signature checks, and keyed by (origin, via)).
        //
        // After the RouteSeenSet TTL expires (~60 s) the same (origin, via, seq)
        // would pass the dedup check above, allowing replay of old gossip.
        // Tracking the highest sequence per (origin, via) rejects replays
        // indefinitely — a valid announce always carries a sequence strictly
        // greater than any previously accepted one for that (origin, via).
        // Running it only after authentication means a forged frame cannot
        // poison the counter; keying by (origin, via) bounds an
        // authenticated-but-malicious relay to suppressing only routes through
        // its own via, not every route to the origin.
        {
            let key = (p.origin_node_id, p.via_node_id);
            let mut seq_cache = lock!(self.route_origin_seq);
            let last = seq_cache.get(&key).copied().unwrap_or(0);
            if p.sequence <= last {
                return DispatchResult::NoResponse; // old or replayed sequence
            }
            // Evict the entry with the *lowest* known sequence number when the
            // cache is full. Evicting the lowest-seq entry is safest: it is the
            // most "stale" and the one most likely to be successfully replayed
            // if evicted. Evicting an arbitrary entry (HashMap iteration order)
            // would let an attacker fill the cache with Sybil keys and force
            // eviction of a real node's seq, re-opening a replay window.
            if !seq_cache.contains_key(&key)
                && seq_cache.len() >= veil_proto::budget::MAX_ROUTE_ORIGIN_SEQ_CACHE
                && let Some(evict) = seq_cache.iter().min_by_key(|(_, s)| *s).map(|(k, _)| *k)
            {
                seq_cache.remove(&evict);
            }
            seq_cache.insert(key, p.sequence);
        }
        // For direct relay announces (hop_count > 1, origin ≠ peer), clamp the
        // score floor to MIN_DIRECT_RELAY_SCORE so the RouteCache doesn't consider
        // a relay hop artificially better than a short multi-hop path confirmed by
        // a signed RouteResponse.
        // Update local RouteCache: dst=origin, next_hop=(=peer_id), score by hops.
        // penalise routes through unreliable neighbors by dividing
        // by their reachability fraction, inflating the score.
        // score = (hop_count × HOP_SCORE_UNIT / reachability) × SCORE_MILLIUNIT_SCALE
        // Cast to u32 truncates — acceptable because SCORE_MILLIUNIT_SCALE keeps
        // the sub-unit remainder < 1/1000 of a hop unit, which is negligible for
        // route comparison purposes.
        //
        // Post-461.7: `via_node_id == peer_id` is now an invariant (the
        // else branch that applied `INDIRECT_ROUTE_SCORE_MULT` was dead code
        // because relays always re-sign, making "indirect" announces
        // indistinguishable from direct ones on the wire). The relay-hop
        // clamp below still protects against a peer self-reporting a
        // spoofed low hop-count to hijack traffic.
        let base_score_f = p.hop_count as f32 * HOP_SCORE_UNIT;
        let reachability = lock!(self.neighbor_scorer)
            .reachability(&p.via_node_id)
            .max(MIN_REACHABILITY);
        let raw_score = (base_score_f / reachability * SCORE_MILLIUNIT_SCALE)
            .clamp(0.0, u32::MAX as f32) as u32;
        let score = if p.hop_count > 1 && &p.origin_node_id != peer_id.as_bytes() {
            // for relay hops (hop_count > 1, i.e., peer is
            // acting as a multi-hop relay), clamp the score to
            // MIN_DIRECT_RELAY_SCORE so a spoofed low hop-count claim
            // cannot appear cheaper than a confirmed RouteResponse (which
            // scores 20_000). hop_count=1 announces are NOT clamped —
            // they represent a direct peer-to-origin connection and their
            // lower score is accurate.
            raw_score.max(MIN_DIRECT_RELAY_SCORE)
        } else {
            raw_score
        };
        wlock!(self.route_cache).insert(p.origin_node_id, p.via_node_id, score, p.hop_count);
        // Forward if TTL allows.
        if p.ttl > 0
            && p.hop_count < self.max_gossip_hops
            && let Some(frame) = self.build_announce_forward(&p)
            && let Some(reg) = &self.session_tx_registry
        {
            wlock!(reg).send_to_all_except_with_priority(
                peer_id.as_bytes(),
                veil_proto::header::priority::BACKGROUND,
                veil_bufpool::pooled_shared_from_vec(frame),
            );
        }
        DispatchResult::NoResponse
    }

    fn handle_route_withdraw(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        let p = match RouteWithdrawPayload::decode(body) {
            Ok(p) => p,
            Err(e) => return DispatchResult::Violation(format!("bad RouteWithdraw: {e}")),
        };
        // Dedup check using same seen-set (seq=p.sequence, via=p.via_node_id).
        let already_seen = lock!(self.route_seen_set)
            // Use a "withdraw marker" via same key space as announce.
            .check_and_insert(p.origin_node_id, p.via_node_id, p.sequence);
        if already_seen {
            return DispatchResult::NoResponse;
        }
        // NOTE (audit M6): the sequence-monotonicity guard runs only after the
        // via==peer + signature checks below — see the relocated block.
        // enforce same via==peer invariant as RouteAnnounce.
        // See the matching comment in `handle_route_announce` — relays
        // re-sign with their own key, so `via_node_id!= peer_id` is a
        // spoofing attempt.
        if &p.via_node_id != peer_id.as_bytes() {
            if let Some(m) = &self.metrics {
                m.inc_unknown_origin_gossip_rejected();
            }
            return DispatchResult::Violation(
                "RouteWithdraw: via_node_id does not match transport sender".to_owned(),
            );
        }
        match self.check_routing_sig(peer_id.as_bytes(), &p.signable_bytes(), &p.signature) {
            SigResult::Valid => {}
            SigResult::UnknownKey => return DispatchResult::NoResponse,
            SigResult::Invalid => {
                return DispatchResult::Violation(
                    "RouteWithdraw: invalid signature from direct peer".to_owned(),
                );
            }
        }
        // Sequence-monotonicity guard (audit M6: relocated after the via==peer +
        // signature checks, keyed by (origin, via) to match RouteAnnounce).
        // Without it a replay after RouteSeenSet TTL could remove a valid live
        // route. Read-only — a withdraw does NOT advance the counter, so a
        // genuinely newer announce with the same sequence is still accepted;
        // only Announce updates the cache (it carries fresh route info).
        {
            let key = (p.origin_node_id, p.via_node_id);
            let seq_cache = lock!(self.route_origin_seq);
            let last = seq_cache.get(&key).copied().unwrap_or(0);
            if p.sequence <= last {
                return DispatchResult::NoResponse; // old or replayed sequence
            }
        }
        // Remove the specific hop from RouteCache.
        wlock!(self.route_cache).invalidate_hop(&p.origin_node_id, &p.via_node_id);
        // Forward withdrawal to other peers (hop_count gate prevents O(N²) amplification).
        if p.hop_count < self.max_gossip_hops
            && let Some(frame) = self.build_withdraw_forward(&p)
            && let Some(reg) = &self.session_tx_registry
        {
            wlock!(reg).send_to_all_except_with_priority(
                peer_id.as_bytes(),
                veil_proto::header::priority::BACKGROUND,
                veil_bufpool::pooled_shared_from_vec(frame),
            );
        }
        DispatchResult::NoResponse
    }

    /// Build a `RouteResponsePayload` describing this node, signed with the
    /// local Ed25519 key and including our ML-KEM EK. Honours
    /// `discovery_mode == IntroductionOnly` by clearing `transports` so the
    /// requester must reach us via `relay_ids`. Used by both the no-PoW
    /// fast path in `handle_route_request` and the deferred PoW-gated
    /// reply path in `handle_pow_response`.
    fn build_signed_route_response(
        &self,
        request_id: u32,
        requester_node_id: [u8; 32],
    ) -> RouteResponsePayload {
        let ed25519_pubkey = self
            .crypto
            .local_signing_key
            .as_ref()
            .map(|key| key.verifying_key().to_bytes().to_vec());
        let transports = if matches!(
            self.discovery_mode,
            veil_cfg::DiscoveryMode::IntroductionOnly,
        ) {
            Vec::new()
        } else {
            self.listen_transports_snapshot()
        };
        let mut response = RouteResponsePayload {
            target_node_id: self.local_node_id,
            requester_node_id,
            request_id,
            transports,
            relay_ids: self.relay_node_ids.clone(),
            mlkem_pubkey: Some(self.crypto.mlkem_ek.as_ref().to_vec()),
            signature: [0u8; 64],
            ed25519_pubkey,
            target_labels: self.target_labels.clone(),
        };
        if let Some(ref key) = self.crypto.local_signing_key {
            response.signature = key.sign(&response.signable_bytes()).to_bytes();
        }
        response
    }

    fn handle_route_request(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        let p = match RouteRequestPayload::decode(body) {
            Ok(p) => p,
            Err(e) => return DispatchResult::Violation(format!("bad RouteRequest: {e}")),
        };
        // Dedup: treat (target, requester, request_id) as the seen-key.
        {
            let already_seen = lock!(self.route_seen_set).check_and_insert(
                p.target_node_id,
                p.requester_node_id,
                p.request_id,
            );
            if already_seen {
                return DispatchResult::NoResponse;
            }
        }
        if p.target_node_id == self.local_node_id {
            // ── Level 2: contacts-only discovery filter ─────
            // In `ContactsOnly` mode, silently drop probes from peers
            // we have no prior handshake with — no PowChallenge, no
            // RouteResponse. An attacker scanning random target_ids
            // learns nothing about whether the target exists.
            if matches!(self.discovery_mode, veil_cfg::DiscoveryMode::ContactsOnly) {
                let known = lock!(self.crypto.peer_pubkeys).contains_key(&p.requester_node_id);
                if !known {
                    return DispatchResult::NoResponse;
                }
            }

            // ── Level 1: PoW-gate transport disclosure ──────
            // When PoW is configured, defer the `RouteResponse` (which
            // carries our listen transports) until the requester has
            // returned a valid `PowResponse`. Without this gate, a single
            // unsigned `RouteRequest` extracted our transports for free —
            // letting an attacker probe arbitrary node_ids and de-anonymise
            // them. See `handle_pow_response` for the deferred reply path.
            if self.pow_difficulty > 0 {
                use rand_core::{OsRng, RngCore};
                let mut challenge_nonce = [0u8; 32];
                OsRng.fill_bytes(&mut challenge_nonce);
                let mut challenge = PowChallengePayload {
                    requester_node_id: p.requester_node_id,
                    acceptor_node_id: self.local_node_id,
                    challenge_nonce,
                    difficulty: self.pow_difficulty,
                    signature: [0u8; 64],
                };
                if let Some(ref key) = self.crypto.local_signing_key {
                    challenge.signature = key.sign(&challenge.signable_bytes()).to_bytes();
                }
                {
                    use veil_proto::budget::{MAX_POW_PENDING, POW_CHALLENGE_TTL_SECS};
                    let ttl = Duration::from_secs(POW_CHALLENGE_TTL_SECS);
                    let now = Instant::now();
                    let mut map = lock!(self.pow_pending);
                    map.evict_stale(now, ttl);
                    map.evict_if_full(MAX_POW_PENDING);
                    map.insert(
                        challenge_nonce,
                        p.requester_node_id,
                        self.pow_difficulty,
                        p.request_id,
                        now,
                    );
                }
                let cf = encode_routing_frame(RoutingMsg::PowChallenge, &challenge.encode());
                if let Some(ref reg) = self.session_tx_registry {
                    // LOCK ORDER: snapshot route_cache lookup BEFORE wlock!(reg)
                    // per canonical order `route_cache → session_tx_registry`.
                    let route_cache_fallback =
                        rlock!(self.route_cache).lookup(&p.requester_node_id);
                    let guard = wlock!(reg);
                    if !guard.send_to(
                        &p.requester_node_id,
                        veil_proto::header::priority::INTERACTIVE,
                        cf.clone(),
                    ) {
                        let dest = route_cache_fallback.unwrap_or(*peer_id.as_bytes());
                        guard.send_to(&dest, veil_proto::header::priority::INTERACTIVE, cf);
                    }
                }
                // RouteResponse intentionally deferred — sent only after
                // PowResponse verifies in `handle_pow_response`.
                return DispatchResult::NoResponse;
            }

            // ── No-PoW path: legacy fast-reply with full RouteResponse. ───
            // Operator opted out of PoW gating (`abuse.pow_min_difficulty
            // = 0`); this is the original behaviour. In
            // `IntroductionOnly` mode we still strip `transports` so the
            // requester is forced through one of our `relay_ids`.
            return DispatchResult::Response(encode_routing_frame(
                RoutingMsg::RouteResponse,
                &self
                    .build_signed_route_response(p.request_id, p.requester_node_id)
                    .encode(),
            ));
        }
        // Forward if TTL allows.
        if p.ttl > 0 {
            // Rate-limit fan-out: a peer that sends RouteRequests faster than
            // MAX_DHT_OPS_PER_PEER_PER_WINDOW cannot amplify traffic to all peers.
            // Audit batch 2026-05-24: emit Violation instead of silent drop so
            // persistent abuse escalates through violation_tracker to a ban; silent
            // drop alone leaves the attacker invisible to escalation logic.
            if !lock!(self.abuse.dht_quota).allow(*peer_id.as_bytes()) {
                return DispatchResult::Violation("RouteRequest DHT quota exceeded".to_string());
            }
            let fwd = RouteRequestPayload {
                ttl: p.ttl - 1,
                ..p
            };
            let frame = encode_routing_frame(RoutingMsg::RouteRequest, &fwd.encode());
            if let Some(reg) = &self.session_tx_registry {
                wlock!(reg).send_to_all_except_with_priority(
                    peer_id.as_bytes(),
                    veil_proto::header::priority::BACKGROUND,
                    veil_bufpool::pooled_shared_from_vec(frame),
                );
            }
        }
        DispatchResult::NoResponse
    }

    fn handle_route_response(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        let p = match RouteResponsePayload::decode(body) {
            Ok(p) => p,
            Err(e) => return DispatchResult::Violation(format!("bad RouteResponse: {e}")),
        };
        if p.requester_node_id == self.local_node_id {
            // Reject any RouteResponse whose signature is absent or
            // invalid. Previously the code accepted the first response from an
            // unknown node without verification (TOFU), allowing a relay to
            // substitute its own ML-KEM key and decrypt E2E traffic.
            //
            // Now: `sig_valid` is required for the response to be acted upon.
            //
            // For targets whose pubkey is already in `peer_pubkeys` (direct
            // peers), we verify against the cached key as before.
            //
            // For unknown targets (indirect / multi-hop peers), the response
            // may carry the target's Ed25519 verifying key in `ed25519_pubkey`.
            // We verify it by checking BLAKE3(pubkey) == target_node_id — a
            // relay cannot forge this because a hash pre-image attack is
            // infeasible. If the subsequent signature check passes, we trust
            // the ML-KEM key and cache both keys.
            let key_known = lock!(self.crypto.peer_pubkeys).contains_key(&p.target_node_id);
            let sig_valid = if key_known {
                // Fast path: use cached pubkey.
                self.check_routing_sig(&p.target_node_id, &p.signable_bytes(), &p.signature)
                    == SigResult::Valid
            } else if let Some(ref ek_bytes) = p.ed25519_pubkey
                && ek_bytes.len() == 32
            {
                // Unknown target with included pubkey: verify binding and sig.
                let node_id_from_pk: [u8; 32] = *blake3::hash(ek_bytes).as_bytes();
                if node_id_from_pk != p.target_node_id {
                    return DispatchResult::Violation(
                        "RouteResponse: ed25519_pubkey does not match target_node_id".to_owned(),
                    );
                }
                let Ok(arr): Result<[u8; 32], _> = ek_bytes.as_slice().try_into() else {
                    return DispatchResult::NoResponse;
                };
                let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&arr) else {
                    return DispatchResult::NoResponse;
                };
                let Ok(sig) = ed25519_dalek::Signature::from_slice(&p.signature) else {
                    return DispatchResult::NoResponse;
                };
                use ed25519_dalek::Verifier as _;
                let valid = vk.verify(&p.signable_bytes(), &sig).is_ok();
                if valid {
                    // Cache the pubkey for future use (e.g. RouteAnnounce verification).
                    // Oldest entry is evicted (FIFO-LRU) when the cache is full.
                    lock!(self.crypto.peer_pubkeys).insert_lru(
                        p.target_node_id,
                        (0u8, ek_bytes.clone()),
                        veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
                    );
                }
                valid
            } else {
                false
            };

            if !sig_valid {
                // Unknown target with no verifiable pubkey → drop silently.
                // Known target with bad sig → Violation.
                if key_known {
                    return DispatchResult::Violation(
                        "RouteResponse: invalid signature from known target".to_owned(),
                    );
                }
                return DispatchResult::NoResponse;
            }
            // rate-limit new route insertions per peer.
            // Each RouteResponse contributes one new destination. Without this
            // check an attacker can flood the RouteCache with sybil entries by
            // sending many RouteResponse frames with distinct target_node_ids.
            if !lock!(self.abuse.dht_contact_quota).allow(*peer_id.as_bytes()) {
                return DispatchResult::NoResponse;
            }
            // Cache the route: target is reachable via the peer who forwarded this.
            // b: persist the target's signed `target_labels` alongside
            // so `RouteCache::lookup_with_labels` can later filter cached routes
            // by capability tag. Empty labels are fine — they just match nothing
            // when a label-filter is requested.
            wlock!(self.route_cache).insert_labelled(
                p.target_node_id,
                *peer_id.as_bytes(),
                20_000,
                2,
                p.target_labels.clone(),
            );
            // Cache ML-KEM key only when signature is verified.
            if let Some(ref ek) = p.mlkem_pubkey
                && ek.len() == veil_e2e::EK_BYTES
            {
                wlock!(self.crypto.peer_mlkem_keys)
                    .insert(p.target_node_id, (ek.clone(), Instant::now()));
            }
            // Wake up any IPC send that is waiting for this route.
            self.route_updated.notify_waiters();
        } else {
            // Route toward requester.
            let frame = encode_routing_frame(RoutingMsg::RouteResponse, &p.encode());
            if let Some(reg) = &self.session_tx_registry {
                // LOCK ORDER: snapshot route_cache fallback BEFORE wlock!(reg)
                // per canonical `route_cache → session_tx_registry`.
                let route_cache_fallback = rlock!(self.route_cache).lookup(&p.requester_node_id);
                let guard = wlock!(reg);
                // Try direct session to requester first.
                if !guard.send_to(
                    &p.requester_node_id,
                    veil_proto::header::priority::INTERACTIVE,
                    frame.clone(),
                ) {
                    // Fallback: route via cache, excluding peer_id (split-horizon).
                    if let Some(hop) = route_cache_fallback
                        && &hop != peer_id.as_bytes()
                    {
                        guard.send_to(&hop, veil_proto::header::priority::INTERACTIVE, frame);
                    }
                }
            }
        }
        DispatchResult::NoResponse
    }

    fn handle_pow_challenge(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        let p = match PowChallengePayload::decode(body) {
            Ok(p) => p,
            Err(e) => return DispatchResult::Violation(format!("bad PowChallenge: {e}")),
        };
        if p.requester_node_id == self.local_node_id {
            // SEC-004a: Rate-limit PowChallenge per sender before any CPU work.
            if !lock!(self.abuse.pow_challenge_limiter).allow(*peer_id.as_bytes()) {
                return DispatchResult::Violation("PowChallenge: rate limit exceeded".to_owned());
            }
            // SEC-004c: Reject absurdly high difficulty values before any CPU work.
            // A malicious acceptor setting difficulty=255 would lock the solver
            // for 2^255 iterations — effectively a permanent denial-of-service.
            if p.difficulty > veil_proto::budget::MAX_POW_DIFFICULTY {
                return DispatchResult::Violation(format!(
                    "PowChallenge: difficulty {} exceeds maximum {}",
                    p.difficulty,
                    veil_proto::budget::MAX_POW_DIFFICULTY,
                ));
            }
            // SEC-004b: Verify acceptor's signature before spawning solver.
            // The signature covers requester||acceptor||nonce||difficulty and
            // is signed by acceptor_privkey. We must have acceptor's pubkey
            // in our peer_pubkeys cache (set during handshake with acceptor).
            // UnknownKey treated as Violation: we must have exchanged keys with
            // the acceptor during the session handshake before a challenge arrives.
            match self.check_routing_sig(&p.acceptor_node_id, &p.signable_bytes(), &p.signature) {
                SigResult::Valid => {}
                _ => {
                    return DispatchResult::Violation(
                        "PowChallenge: invalid acceptor signature".to_owned(),
                    );
                }
            }
            // Deduplicate challenge nonces to prevent replay flooding.
            // A single acceptor can issue the same nonce to hundreds of relays;
            // only solve it once per TTL window.
            if lock!(self.pow_challenge_seen).check_and_insert(p.challenge_nonce) {
                return DispatchResult::NoResponse;
            }
            // The challenge is addressed to us and passes auth — solve it.
            return DispatchResult::SolvePow(p);
        }
        // Relay toward requester.
        let frame = encode_routing_frame(RoutingMsg::PowChallenge, body);
        if let Some(ref reg) = self.session_tx_registry {
            // LOCK ORDER: snapshot route_cache fallback BEFORE wlock!(reg).
            let route_cache_fallback = rlock!(self.route_cache).lookup(&p.requester_node_id);
            let guard = wlock!(reg);
            if !guard.send_to(
                &p.requester_node_id,
                veil_proto::header::priority::INTERACTIVE,
                frame.clone(),
            ) && let Some(hop) = route_cache_fallback
                && &hop != peer_id.as_bytes()
            {
                guard.send_to(&hop, veil_proto::header::priority::INTERACTIVE, frame);
            }
        }
        DispatchResult::NoResponse
    }

    fn handle_pow_response(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        let p = match PowResponsePayload::decode(body) {
            Ok(p) => p,
            Err(e) => return DispatchResult::Violation(format!("bad PowResponse: {e}")),
        };
        if p.acceptor_node_id == self.local_node_id {
            // We are the acceptor — look up and verify the challenge.
            let pending = lock!(self.pow_pending).remove(&p.challenge_nonce);
            let Some((expected_requester, difficulty, request_id)) = pending else {
                return DispatchResult::Violation(
                    "PowResponse: unknown challenge nonce".to_owned(),
                );
            };
            if expected_requester != p.requester_node_id {
                return DispatchResult::Violation("PowResponse: requester_id mismatch".to_owned());
            }
            use veil_routing::pow::verify_pow;
            if !verify_pow(
                &p.requester_node_id,
                &p.challenge_nonce,
                &p.solution_nonce,
                difficulty,
            ) {
                return DispatchResult::Violation("PowResponse: invalid PoW solution".to_owned());
            }

            // ── Level 1: deferred RouteResponse ──
            // The PoW solution proves the requester paid CPU cost for
            // discovery; only now do we disclose our listen transports
            // (or relay_ids in IntroductionOnly mode). `request_id`
            // is echoed from `pow_pending` so the requester can
            // correlate this RouteResponse with the original
            // RouteRequest.
            let response = self.build_signed_route_response(request_id, p.requester_node_id);
            let rf = encode_routing_frame(RoutingMsg::RouteResponse, &response.encode());
            if let Some(ref reg) = self.session_tx_registry {
                // LOCK ORDER: snapshot route_cache fallback BEFORE wlock!(reg).
                let route_cache_fallback = rlock!(self.route_cache).lookup(&p.requester_node_id);
                let guard = wlock!(reg);
                if !guard.send_to(
                    &p.requester_node_id,
                    veil_proto::header::priority::INTERACTIVE,
                    rf.clone(),
                ) && let Some(hop) = route_cache_fallback
                    && &hop != peer_id.as_bytes()
                {
                    guard.send_to(&hop, veil_proto::header::priority::INTERACTIVE, rf);
                }
            }

            // PoW accepted — also send PowAccept with first listen
            // transport for backward compatibility (signals "PoW
            // bootstrap complete; you may initiate session").
            // In IntroductionOnly mode we have no transport to
            // disclose, so PowAccept is skipped — the requester
            // uses the relay_ids carried in RouteResponse instead.
            let transport = if matches!(
                self.discovery_mode,
                veil_cfg::DiscoveryMode::IntroductionOnly,
            ) {
                None
            } else {
                self.listen_transports_snapshot()
                    .into_iter()
                    .find(|t| !t.is_empty())
            };
            if let Some(transport) = transport {
                let accept = PowAcceptPayload {
                    requester_node_id: p.requester_node_id,
                    challenge_nonce: p.challenge_nonce,
                    transport,
                };
                let af = encode_routing_frame(RoutingMsg::PowAccept, &accept.encode());
                if let Some(ref reg) = self.session_tx_registry {
                    // LOCK ORDER: snapshot route_cache fallback BEFORE wlock!(reg).
                    let route_cache_fallback =
                        rlock!(self.route_cache).lookup(&p.requester_node_id);
                    let guard = wlock!(reg);
                    if !guard.send_to(
                        &p.requester_node_id,
                        veil_proto::header::priority::INTERACTIVE,
                        af.clone(),
                    ) && let Some(hop) = route_cache_fallback
                        && &hop != peer_id.as_bytes()
                    {
                        guard.send_to(&hop, veil_proto::header::priority::INTERACTIVE, af);
                    }
                }
            }
        } else {
            // Relay toward acceptor.
            let frame = encode_routing_frame(RoutingMsg::PowResponse, body);
            if let Some(ref reg) = self.session_tx_registry {
                // LOCK ORDER: snapshot route_cache fallback BEFORE wlock!(reg).
                let route_cache_fallback = rlock!(self.route_cache).lookup(&p.acceptor_node_id);
                let guard = wlock!(reg);
                if !guard.send_to(
                    &p.acceptor_node_id,
                    veil_proto::header::priority::INTERACTIVE,
                    frame.clone(),
                ) && let Some(hop) = route_cache_fallback
                    && &hop != peer_id.as_bytes()
                {
                    guard.send_to(&hop, veil_proto::header::priority::INTERACTIVE, frame);
                }
            }
        }
        DispatchResult::NoResponse
    }

    fn handle_pow_accept(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        let p = match PowAcceptPayload::decode(body) {
            Ok(p) => p,
            Err(e) => return DispatchResult::Violation(format!("bad PowAccept: {e}")),
        };
        if p.requester_node_id == self.local_node_id {
            // We completed the PoW bootstrap — the acceptor's transport is available.
            self.logger.debug(
                "routing.pow_accept",
                format!(
                    "PoW bootstrap complete: acceptor transport={}",
                    veil_util::redact_addr_for_log(&p.transport),
                ),
            );
            self.route_updated.notify_waiters();
        } else {
            // Relay toward requester.
            let frame = encode_routing_frame(RoutingMsg::PowAccept, body);
            if let Some(ref reg) = self.session_tx_registry {
                // LOCK ORDER: snapshot route_cache fallback BEFORE wlock!(reg).
                let route_cache_fallback = rlock!(self.route_cache).lookup(&p.requester_node_id);
                let guard = wlock!(reg);
                if !guard.send_to(
                    &p.requester_node_id,
                    veil_proto::header::priority::INTERACTIVE,
                    frame.clone(),
                ) && let Some(hop) = route_cache_fallback
                    && &hop != peer_id.as_bytes()
                {
                    guard.send_to(&hop, veil_proto::header::priority::INTERACTIVE, frame);
                }
            }
        }
        DispatchResult::NoResponse
    }

    // ── Route gossip helpers ─────────────────────────────────────────────────

    /// Broadcast `ROUTE_ANNOUNCE(origin=new_peer, via=self, hop=1)` to all
    /// currently connected peers, and announce all current peers to `new_peer`.
    ///
    /// Called immediately after a new session is registered in `SessionTxRegistry`.
    /// Active peer-gossip: queue up to `limit` `NeighborOffer` hints (sampled
    /// from our DHT routing table, which carry transports) into `target`'s
    /// session. The offer path was otherwise dormant — nothing emitted it — so
    /// this is what makes neighbours cross-pollinate peer knowledge on session
    /// churn and the periodic heartbeat, and what lets a capacity-referred
    /// client learn freer nodes to dial. Best-effort; no-ops without a tx
    /// registry or contacts. The recipient routes the offers into its
    /// source-quota'd pending pool (see `handle_neighbor_offer`), so this
    /// cannot be used to eclipse its verified routing table.
    pub fn gossip_peer_sample_to(&self, target: &[u8; 32], limit: usize) {
        let Some(reg) = &self.session_tx_registry else {
            return;
        };
        let contacts = self.dht.routing_table_contacts();
        if contacts.is_empty() {
            return;
        }
        let guard = rlock!(reg);
        let mut sent = 0usize;
        for c in &contacts {
            if sent >= limit {
                break;
            }
            if &c.node_id == target || c.node_id == self.local_node_id || c.transport.is_empty() {
                continue;
            }
            let body = veil_proto::control::NeighborOfferPayload {
                node_id: c.node_id,
                addr: c.transport.clone().into_bytes(),
                flags: 0,
            }
            .encode();
            let mut hdr = veil_proto::header::FrameHeader::new(
                veil_proto::family::FrameFamily::Control as u8,
                veil_proto::family::ControlMsg::NeighborOffer as u16,
            );
            hdr.body_len = body.len() as u32;
            if guard.send_to(
                target,
                veil_proto::header::priority::INTERACTIVE,
                veil_proto::codec::encode_frame(&hdr, &body),
            ) {
                sent += 1;
            }
        }
    }

    /// Gossip a fresh peer sample to every active session — the 300 s exchange
    /// heartbeat and the on-session-drop re-spread.
    pub fn gossip_peer_sample_to_all(&self, limit: usize) {
        let Some(reg) = &self.session_tx_registry else {
            return;
        };
        let targets: Vec<[u8; 32]> = rlock!(reg).active_node_ids().into_iter().collect();
        for target in targets {
            self.gossip_peer_sample_to(&target, limit);
        }
    }

    pub fn on_session_opened(
        &self,
        new_peer: [u8; 32],
        observed_addr: Option<std::net::SocketAddr>,
    ) {
        if let Some(addr) = observed_addr {
            use veil_proto::budget::MAX_PEER_OBSERVED_ADDRS;
            let mut map = wlock!(self.peer_observed_addrs);
            if map.len() < MAX_PEER_OBSERVED_ADDRS {
                map.insert(new_peer, addr);
            }
        }
        let Some(ref reg_arc) = self.session_tx_registry else {
            return;
        };
        let Some(ref key) = self.crypto.local_signing_key else {
            return;
        };

        let now_ts = veil_util::unix_secs_now_u32();

        // 1. Tell all OTHER peers about new_peer.
        {
            let seq = self.announce_seq.fetch_add(1, Ordering::Relaxed);
            let mut p = RouteAnnouncePayload {
                origin_node_id: new_peer,
                via_node_id: self.local_node_id,
                hop_count: 1,
                ttl: 7,
                sequence: seq,
                timestamp: now_ts,
                signature: [0u8; 64],
            };
            let sig_bytes = key.sign(&p.signable_bytes()).to_bytes();
            p.signature = sig_bytes;
            let frame = encode_routing_frame(RoutingMsg::RouteAnnounce, &p.encode());
            wlock!(reg_arc).send_to_all_except_with_priority(
                &new_peer,
                veil_proto::header::priority::BACKGROUND,
                veil_bufpool::pooled_shared_from_vec(frame),
            );

            // also send RouteUpdate(ADD) for event-driven sync.
            let mut ru = RouteUpdatePayload {
                origin_node_id: new_peer,
                via_node_id: self.local_node_id,
                action: route_update_action::ADD,
                version: seq as u64,
                hop_count: 1,
                signature: [0u8; 64],
            };
            ru.signature = key.sign(&ru.signable_bytes()).to_bytes();
            let ru_frame = encode_routing_frame(RoutingMsg::RouteUpdate, &ru.encode());
            wlock!(reg_arc).send_to_all_except_with_priority(
                &new_peer,
                veil_proto::header::priority::BACKGROUND,
                veil_bufpool::pooled_shared_from_vec(ru_frame),
            );
        }

        // 2. Tell new_peer about all existing DIRECT peers.
        let existing_peers = wlock!(reg_arc).peer_ids();
        for existing in &existing_peers {
            if *existing == new_peer || *existing == self.local_node_id {
                continue;
            }
            let seq = self.announce_seq.fetch_add(1, Ordering::Relaxed);
            let mut p = RouteAnnouncePayload {
                origin_node_id: *existing,
                via_node_id: self.local_node_id,
                hop_count: 1,
                ttl: 7,
                sequence: seq,
                timestamp: now_ts,
                signature: [0u8; 64],
            };
            let sig_bytes = key.sign(&p.signable_bytes()).to_bytes();
            p.signature = sig_bytes;
            let frame = encode_routing_frame(RoutingMsg::RouteAnnounce, &p.encode());
            wlock!(reg_arc).send_to(&new_peer, veil_proto::header::priority::INTERACTIVE, frame);
        }

        // Update DHT routing table: new peer is now reachable via a direct session.
        self.dht
            .add_contact(veil_dht::routing::Contact::new(new_peer, ""));

        // update total and relay session counts in the congestion monitor.
        if let Some(cm) = &self.congestion_monitor {
            let total = wlock!(reg_arc).len();
            cm.set_total_sessions(total);
            // For core/relay nodes every session may carry relayed traffic.
            if matches!(self.role, veil_cfg::NodeRole::Core) {
                cm.set_relay_sessions(total);
            }
        }

        // 3. Tell new_peer about all INDIRECT routes currently in our RouteCache
        // (routes learned via gossip from other peers). This bootstraps the
        // new peer's routing table immediately without waiting for the next
        // periodic refresh cycle.
        let indirect_routes = wlock!(self.route_cache).all_routes();
        for (dst, _next_hop, hop_count) in indirect_routes {
            // Skip if dst is a direct peer (already announced in step 2) or self.
            if existing_peers.contains(&dst) || dst == self.local_node_id || dst == new_peer {
                continue;
            }
            let seq = self.announce_seq.fetch_add(1, Ordering::Relaxed);
            let mut p = RouteAnnouncePayload {
                origin_node_id: dst,
                via_node_id: self.local_node_id,
                hop_count: hop_count.saturating_add(1),
                ttl: 7,
                sequence: seq,
                timestamp: now_ts,
                signature: [0u8; 64],
            };
            let sig_bytes = key.sign(&p.signable_bytes()).to_bytes();
            p.signature = sig_bytes;
            let frame = encode_routing_frame(RoutingMsg::RouteAnnounce, &p.encode());
            wlock!(reg_arc).send_to(&new_peer, veil_proto::header::priority::INTERACTIVE, frame);
        }

        // 4. : removed eager MAILBOX_FETCH on session establishment
        // and the piggybacked SleepAdvertisement emission — both were
        // mailbox-subsystem features that no longer exist. Async-delivery
        // semantics belong to the application layer now.

        // 5. : event-driven push of locally-owned signed DHT
        // records. Without this, a new peer would wait up to
        // `dht.republish_interval_secs` (30 min default) before seeing our
        // AppEndpoint / AnnounceAttachment records — that delays cross-
        // node discovery unacceptably after short-lived reconnects.
        //
        // Strategy: iterate the local DHT store, inspect magic prefixes
        // and push records we're the *owner* (our node_id matches the
        // record's node_id). Replicated records (magic present but we're
        // not the owner) are skipped — the real owner will push them to
        // the new peer when *they* open a session.
        self.push_owned_dht_records(new_peer, reg_arc);

        // Peer-exchange on session ESTABLISH: hand the new neighbour a sample
        // of our known peers so it can widen its own dial set. Fires on both
        // sides of every new session (inbound + outbound), so the exchange is
        // mutual. Also the delivery path for capacity-referral: a node at the
        // session ceiling accepts a transient session, and this gives the
        // would-be client freer nodes to dial before that session closes.
        self.gossip_peer_sample_to(&new_peer, PEER_GOSSIP_SAMPLE);
    }

    /// scan local DHT store for owned signed records (magic "AP"
    /// for AppEndpointEntry, "AT" for AnnounceAttachmentPayload) and STORE
    /// each one on the freshly connected peer at `BACKGROUND` priority so
    /// routine traffic is never delayed.
    fn push_owned_dht_records(
        &self,
        new_peer: [u8; 32],
        reg_arc: &std::sync::Arc<std::sync::RwLock<veil_session::SessionTxRegistry>>,
    ) {
        use veil_discovery::directory::{
            APP_ENDPOINT_DHT_MAGIC, ATTACHMENT_DHT_MAGIC, AppEndpointEntry,
            decode_and_verify_signed_attachment,
        };
        use veil_proto::{
            codec::encode_header,
            discovery::StorePayload,
            family::{DiscoveryMsg, FrameFamily},
            header::{FrameHeader, HEADER_SIZE, TrafficClass},
        };

        let local_id = self.local_node_id;
        let entries = self.dht.stored_entries();
        let mut pushed = 0usize;
        for (key, value) in entries {
            // Only self-authenticating records are safe to propagate unsigned.
            let is_ap = value.get(..2) == Some(&APP_ENDPOINT_DHT_MAGIC[..]);
            let is_at = value.get(..2) == Some(&ATTACHMENT_DHT_MAGIC[..]);
            if !is_ap && !is_at {
                continue;
            }

            // Only push records we own — hence the decode-to-check. Verify
            // step is cheap and also protects us from pushing tampered data
            // we might have accepted earlier.
            let owned = if is_ap {
                AppEndpointEntry::decode_and_verify_signed_from_dht(&value)
                    .map(|e| e.node_id == local_id)
                    .unwrap_or(false)
            } else {
                decode_and_verify_signed_attachment(&value)
                    .map(|p| p.node_id == local_id)
                    .unwrap_or(false)
            };
            if !owned {
                continue;
            }

            // Build an unsigned STORE frame. The recipient will still verify
            // the inner signature via the magic-prefix branch of dispatcher
            // STORE acceptance.
            let payload = StorePayload::unsigned(key, value);
            let body = payload.encode();
            let mut hdr =
                FrameHeader::new(FrameFamily::Discovery as u8, DiscoveryMsg::Store as u16);
            hdr.body_len = body.len() as u32;
            hdr.set_priority(TrafficClass::Background as u8);
            let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
            frame.extend_from_slice(&encode_header(&hdr));
            frame.extend_from_slice(&body);
            wlock!(reg_arc).send_to(&new_peer, veil_proto::header::priority::BACKGROUND, frame);
            pushed += 1;
        }
        if pushed > 0 {
            self.logger.info(
                "dht.owned_push",
                format!(
                    "peer_id={} records={}",
                    veil_util::hex_short(&new_peer),
                    pushed,
                ),
            );
        }
    }

    /// Broadcast `ROUTE_WITHDRAW(origin=closed_peer, via=self)` to all remaining peers.
    ///
    /// Called immediately before a session is unregistered from `SessionTxRegistry`.
    pub fn on_session_closed(&self, closed_peer: NodeId) {
        let closed_peer = *closed_peer.as_bytes();
        wlock!(self.peer_observed_addrs).remove(&closed_peer);
        // Release any relay tunnels where the closing peer was an endpoint.
        // Leaving stale entries would grow the map unboundedly over peer churn.
        lock!(self.relay_tunnels).retain(|_, (a, b)| *a != closed_peer && *b != closed_peer);
        // Audit L-7: drop the closing peer from the NeighborScorer reachability
        // map. It gains an entry per distinct ROUTE_REPLY sender and otherwise
        // has no eviction, so without this it grows one-per-peer over the
        // process lifetime. An absent peer scores the default 1.0, so this is safe.
        lock!(self.neighbor_scorer).remove(&closed_peer);

        // (deferred slice cleanup): drop every rendezvous-
        // subscription registered FROM this peer. Without this, when
        // a receiver's OVL1 session to the rendezvous closes — process
        // restart, network blip, peer revoke — their cookies stay in
        // RendezvousRegistry forever (until manual unregister or
        // process restart). Senders trying to deliver via that cookie
        // would have their Introduce silently forwarded to a dead
        // session, materializing as `send_to` failures and payload loss.
        // After this hook, stale subscriptions get reaped with the closing
        // session itself, eliminating the leak. No-op when this node
        // isn't running a rendezvous-registry (only relay-capable nodes
        // hold one).
        if let Some(ref reg) = self.rendezvous_registry {
            let dropped = reg.drop_subscriber(&closed_peer);
            if dropped > 0 {
                self.logger.info(
                    "rendezvous.subscriber.dropped",
                    format!(
                        "peer_id={} cookies_removed={}",
                        veil_util::hex_short(&closed_peer),
                        dropped,
                    ),
                );
            }
        }

        // fast path demotion. Routes via `closed_peer` were
        // valid until this exact moment; the periodic RTT-probe scoring
        // (every 5–120 s) won't notice the breakage for tens of seconds.
        // Multiplying the score by 4× immediately pushes them out of the
        // ECMP / multi-path band so alternative `next_hop`s win on the
        // very next `lookup_all`. The routes stay in the cache as
        // last-resort fallback in case nothing else works.
        wlock!(self.route_cache).demote_via(&closed_peer, 4.0);
        let Some(ref reg_arc) = self.session_tx_registry else {
            return;
        };
        let Some(ref key) = self.crypto.local_signing_key else {
            return;
        };

        let seq = self.announce_seq.fetch_add(1, Ordering::Relaxed);
        let mut p = RouteWithdrawPayload {
            origin_node_id: closed_peer,
            via_node_id: self.local_node_id,
            sequence: seq,
            signature: [0u8; 64],
            hop_count: 0,
        };
        let sig_bytes = key.sign(&p.signable_bytes()).to_bytes();
        p.signature = sig_bytes;
        let frame = encode_routing_frame(RoutingMsg::RouteWithdraw, &p.encode());
        wlock!(reg_arc).send_to_all_except_with_priority(
            &closed_peer,
            veil_proto::header::priority::BACKGROUND,
            veil_bufpool::pooled_shared_from_vec(frame),
        );

        // also send RouteUpdate(REMOVE) for event-driven sync.
        {
            let mut ru = RouteUpdatePayload {
                origin_node_id: closed_peer,
                via_node_id: self.local_node_id,
                action: route_update_action::REMOVE,
                version: seq as u64,
                hop_count: 0,
                signature: [0u8; 64],
            };
            ru.signature = key.sign(&ru.signable_bytes()).to_bytes();
            let ru_frame = encode_routing_frame(RoutingMsg::RouteUpdate, &ru.encode());
            wlock!(reg_arc).send_to_all_except_with_priority(
                &closed_peer,
                veil_proto::header::priority::BACKGROUND,
                veil_bufpool::pooled_shared_from_vec(ru_frame),
            );
        }

        // Remove from our own RouteCache too.
        // Use invalidate_all_via so that every destination previously routed
        // through `closed_peer` is evicted immediately — the old call to
        // invalidate_hop(&closed_peer, &local_node_id) removed a nonexistent
        // entry (the node never routes through itself) and left all stale
        // via-closed_peer routes intact until their TTL expired (up to 60 s).
        wlock!(self.route_cache).invalidate_all_via(&closed_peer);

        // Update DHT routing table: this peer is no longer reachable.
        self.dht.remove_contact(&closed_peer);

        // update session counts after closing.
        if let Some(cm) = &self.congestion_monitor {
            let total = wlock!(reg_arc).len();
            cm.set_total_sessions(total);
            if matches!(self.role, veil_cfg::NodeRole::Core) {
                cm.set_relay_sessions(total);
            }
        }

        // replica quorum / fetch entries removed with the mailbox
        // subsystem; nothing per-peer to evict here.
        let _ = closed_peer;

        // Peer-exchange on session DROP: a neighbour just left, so re-spread a
        // fresh peer sample to the remaining sessions to help the mesh re-knit
        // around the loss. Bounded by our (capped) session degree.
        self.gossip_peer_sample_to_all(PEER_GOSSIP_SAMPLE);
    }

    /// Re-announce every currently-connected peer to all other peers.
    ///
    /// Called periodically (~30 s) so that `RouteCache` entries on remote nodes
    /// are refreshed before they expire (TTL = 120 s). Each connected peer is
    /// announced with `hop_count = 1, via = self`, signed fresh.
    pub fn refresh_all_routes(&self) {
        let Some(ref reg_arc) = self.session_tx_registry else {
            return;
        };
        let Some(ref key) = self.crypto.local_signing_key else {
            return;
        };

        let now_ts = veil_util::unix_secs_now_u32();

        let peers = wlock!(reg_arc).peer_ids();

        for peer in &peers {
            let seq = self.announce_seq.fetch_add(1, Ordering::Relaxed);
            let mut p = RouteAnnouncePayload {
                origin_node_id: *peer,
                via_node_id: self.local_node_id,
                hop_count: 1,
                ttl: 7,
                sequence: seq,
                timestamp: now_ts,
                signature: [0u8; 64],
            };
            p.signature = key.sign(&p.signable_bytes()).to_bytes();
            let frame = encode_routing_frame(RoutingMsg::RouteAnnounce, &p.encode());
            wlock!(reg_arc).send_to_all_except_with_priority(
                peer,
                veil_proto::header::priority::BACKGROUND,
                veil_bufpool::pooled_shared_from_vec(frame),
            );
        }
    }

    /// Withdraw `local_node_id` from the routing tables of all connected peers.
    ///
    /// Called by when `CongestionMonitor::is_admitting` transitions
    /// to `false` — tells neighbours to stop routing traffic through this node.
    pub fn withdraw_self(&self, local_node_id: NodeId) {
        let Some(ref reg_arc) = self.session_tx_registry else {
            return;
        };
        let Some(ref key) = self.crypto.local_signing_key else {
            return;
        };
        let seq = self.announce_seq.fetch_add(1, Ordering::Relaxed);
        let local_bytes = *local_node_id.as_bytes();
        let mut p = RouteWithdrawPayload {
            origin_node_id: local_bytes,
            via_node_id: local_bytes,
            sequence: seq,
            signature: [0u8; 64],
            hop_count: 0,
        };
        p.signature = key.sign(&p.signable_bytes()).to_bytes();
        let frame = encode_routing_frame(RoutingMsg::RouteWithdraw, &p.encode());
        wlock!(reg_arc).send_to_all(veil_bufpool::pooled_shared_from_vec(frame));
    }

    /// Re-announce `local_node_id` to all connected peers with `hop_count = 0`.
    ///
    /// Called by when `CongestionMonitor::is_admitting` transitions
    /// back to `true` — re-registers this node as a viable relay in the network.
    pub fn reannounce_self(&self, local_node_id: NodeId) {
        let Some(ref reg_arc) = self.session_tx_registry else {
            return;
        };
        let Some(ref key) = self.crypto.local_signing_key else {
            return;
        };
        let now_ts = veil_util::unix_secs_now_u32();
        let seq = self.announce_seq.fetch_add(1, Ordering::Relaxed);
        let local_bytes = *local_node_id.as_bytes();
        let mut p = RouteAnnouncePayload {
            origin_node_id: local_bytes,
            via_node_id: local_bytes,
            hop_count: 0,
            ttl: 7,
            sequence: seq,
            timestamp: now_ts,
            signature: [0u8; 64],
        };
        p.signature = key.sign(&p.signable_bytes()).to_bytes();
        let frame = encode_routing_frame(RoutingMsg::RouteAnnounce, &p.encode());
        wlock!(reg_arc).send_to_all(veil_bufpool::pooled_shared_from_vec(frame));
    }

    /// Refresh route-cache scores for all entries that use `peer_id` as their
    /// next-hop, using the peer's current reachability from `NeighborScorer`.
    ///
    /// Called on every `ROUTE_REPLY` receipt (137.6): a successful reply is
    /// evidence of reachability, so the scorer is updated first and then the
    /// cache is re-sorted to reflect the new effective cost.
    pub fn update_scores_for_peer(&self, peer_id: NodeId) {
        // A successful ROUTE_REPLY = one successful probe.
        lock!(self.neighbor_scorer).record_probe(*peer_id.as_bytes(), true);
        let reachability = lock!(self.neighbor_scorer)
            .reachability(peer_id.as_bytes())
            .max(MIN_REACHABILITY);
        wlock!(self.route_cache).rescore_via(peer_id.as_bytes(), |hop_count| {
            let base = hop_count as f32 * HOP_SCORE_UNIT;
            (base / reachability * SCORE_MILLIUNIT_SCALE).clamp(0.0, u32::MAX as f32) as u32
        });
    }

    // ── Private routing helpers ──────────────────────────────────────────────

    /// Build a forwarded ROUTE_ANNOUNCE re-signed by the local node.
    fn build_announce_forward(&self, received: &RouteAnnouncePayload) -> Option<Vec<u8>> {
        let key = self.crypto.local_signing_key.as_ref()?;
        let seq = self.announce_seq.fetch_add(1, Ordering::Relaxed);
        let now_ts = veil_util::unix_secs_now_u32();
        let mut p = RouteAnnouncePayload {
            origin_node_id: received.origin_node_id,
            via_node_id: self.local_node_id,
            hop_count: received.hop_count.saturating_add(1),
            ttl: received.ttl - 1,
            sequence: seq,
            timestamp: now_ts,
            signature: [0u8; 64],
        };
        p.signature = key.sign(&p.signable_bytes()).to_bytes();
        Some(encode_routing_frame(RoutingMsg::RouteAnnounce, &p.encode()))
    }

    /// Build a forwarded ROUTE_WITHDRAW re-signed by the local node.
    fn build_withdraw_forward(&self, received: &RouteWithdrawPayload) -> Option<Vec<u8>> {
        let key = self.crypto.local_signing_key.as_ref()?;
        let seq = self.announce_seq.fetch_add(1, Ordering::Relaxed);
        let mut p = RouteWithdrawPayload {
            origin_node_id: received.origin_node_id,
            via_node_id: self.local_node_id,
            sequence: seq,
            signature: [0u8; 64],
            hop_count: received.hop_count.saturating_add(1),
        };
        p.signature = key.sign(&p.signable_bytes()).to_bytes();
        Some(encode_routing_frame(RoutingMsg::RouteWithdraw, &p.encode()))
    }

    // ── Aliased gossip handlers ─────────────────────────────────

    fn handle_route_announce_aliased(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        let p = match RouteAnnounceAliasedPayload::decode(body) {
            Ok(p) => p,
            Err(e) => return DispatchResult::Violation(format!("bad RouteAnnounceAliased: {e}")),
        };
        // Resolve aliases → node_ids. Both aliases must be known.
        let origin_node_id = match self.resolve_alias(p.origin_alias) {
            Some(id) => id,
            None => {
                return DispatchResult::Violation(
                    "RouteAnnounceAliased: unknown origin alias".to_owned(),
                );
            }
        };
        let via_node_id = match self.resolve_alias(p.via_alias) {
            Some(id) => id,
            None => {
                return DispatchResult::Violation(
                    "RouteAnnounceAliased: unknown via alias".to_owned(),
                );
            }
        };
        // Reconstruct a full RouteAnnouncePayload and reuse existing handling logic.
        let full = RouteAnnouncePayload {
            origin_node_id,
            via_node_id,
            hop_count: p.hop_count,
            ttl: p.ttl,
            sequence: p.sequence,
            timestamp: p.timestamp,
            signature: p.signature,
        };
        let full_bytes = full.encode();
        self.handle_route_announce(&full_bytes, peer_id)
    }

    fn handle_route_withdraw_aliased(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        let p = match RouteWithdrawAliasedPayload::decode(body) {
            Ok(p) => p,
            Err(e) => return DispatchResult::Violation(format!("bad RouteWithdrawAliased: {e}")),
        };
        let origin_node_id = match self.resolve_alias(p.origin_alias) {
            Some(id) => id,
            None => {
                return DispatchResult::Violation(
                    "RouteWithdrawAliased: unknown origin alias".to_owned(),
                );
            }
        };
        let via_node_id = match self.resolve_alias(p.via_alias) {
            Some(id) => id,
            None => {
                return DispatchResult::Violation(
                    "RouteWithdrawAliased: unknown via alias".to_owned(),
                );
            }
        };
        let full = RouteWithdrawPayload {
            origin_node_id,
            via_node_id,
            sequence: p.sequence,
            signature: p.signature,
            hop_count: p.hop_count,
        };
        let full_bytes = full.encode();
        self.handle_route_withdraw(&full_bytes, peer_id)
    }

    // ── Version vector reconciliation ────────────────────────────
    fn handle_version_vector_sync(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        let vv = match VersionVectorSyncPayload::decode(body) {
            Ok(v) => v,
            Err(e) => return DispatchResult::Violation(format!("bad VersionVectorSync: {e}")),
        };

        // per-peer rate limit. Drop if this peer already triggered
        // a VVSync response within `VVSYNC_MIN_INTERVAL_SECS` — their previous
        // RouteUpdate fan-out is still in flight. Prevents amplification loops
        // where a compromised peer repeatedly asks for a full catch-up.
        if lock!(self.vvsync_seen).check_and_insert(*peer_id.as_bytes()) {
            return DispatchResult::NoResponse;
        }

        // Compare received versions with our local route_versions.
        // For each origin where our version > received, send a RouteUpdate with
        // current route info so the peer can catch up.
        let local_versions = rlock!(self.route_cache).version_summary();
        let received: std::collections::HashMap<NodeIdBytes, u64> =
            vv.entries.into_iter().collect();

        let Some(ref key) = self.crypto.local_signing_key else {
            return DispatchResult::NoResponse;
        };
        let Some(ref reg_arc) = self.session_tx_registry else {
            return DispatchResult::NoResponse;
        };

        for (origin, local_ver) in &local_versions {
            let peer_ver = received.get(origin).copied().unwrap_or(0);
            if *local_ver > peer_ver {
                // We have newer info — send a RouteUpdate(ADD) to bring peer up to date.
                if let Some(_hop) = rlock!(self.route_cache).lookup(origin) {
                    let mut ru = RouteUpdatePayload {
                        origin_node_id: *origin,
                        via_node_id: self.local_node_id,
                        action: route_update_action::ADD,
                        version: *local_ver,
                        hop_count: 1,
                        signature: [0u8; 64],
                    };
                    ru.signature = key.sign(&ru.signable_bytes()).to_bytes();
                    let frame = encode_routing_frame(RoutingMsg::RouteUpdate, &ru.encode());
                    wlock!(reg_arc).send_to(
                        peer_id.as_bytes(),
                        veil_proto::header::priority::BACKGROUND,
                        frame,
                    );
                }
            }
        }

        DispatchResult::NoResponse
    }

    pub fn check_routing_sig(
        &self,
        peer_id: &NodeIdBytes,
        msg: &[u8],
        sig_bytes: &[u8; 64],
    ) -> SigResult {
        let cache = lock!(self.crypto.peer_pubkeys);
        let Some((algo_byte, pubkey_bytes)) = cache.get(peer_id) else {
            return SigResult::UnknownKey;
        };
        // Only ed25519 (algo_byte!= 2) is supported for routing sigs.
        if *algo_byte == 2 {
            self.logger.warn(
                "routing.sig_fail",
                format!(
                    "peer={} reason=falcon512_not_supported",
                    veil_util::hex_short(peer_id)
                ),
            );
            return SigResult::Invalid;
        }
        let Ok(pubkey_arr): Result<&[u8; 32], _> = pubkey_bytes.as_slice().try_into() else {
            self.logger.warn(
                "routing.sig_fail",
                format!(
                    "peer={} reason=bad_pubkey_len len={}",
                    veil_util::hex_short(peer_id),
                    pubkey_bytes.len()
                ),
            );
            return SigResult::Invalid;
        };
        let Ok(vk) = VerifyingKey::from_bytes(pubkey_arr) else {
            self.logger.warn(
                "routing.sig_fail",
                format!(
                    "peer={} reason=invalid_pubkey_bytes",
                    veil_util::hex_short(peer_id)
                ),
            );
            return SigResult::Invalid;
        };
        let Ok(sig) = Signature::from_slice(sig_bytes) else {
            self.logger.warn(
                "routing.sig_fail",
                format!(
                    "peer={} reason=invalid_sig_bytes",
                    veil_util::hex_short(peer_id)
                ),
            );
            return SigResult::Invalid;
        };
        if vk.verify(msg, &sig).is_ok() {
            SigResult::Valid
        } else {
            self.logger.warn(
                "routing.sig_fail",
                format!(
                    "peer={} reason=ed25519_verify_failed msg_len={}",
                    veil_util::hex_short(peer_id),
                    msg.len()
                ),
            );
            SigResult::Invalid
        }
    }

    // ── Recursive DHT routing ─────────────────────────────────────

    fn handle_recursive_query(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        // Per-peer rate limit BEFORE decode: a flood of malformed queries should
        // also be quenched. Distinct `query_id` values bypass the dedup below
        // but each one still costs sig-verify, lookup, and TTL-slot work — so
        // throttle the SOURCE of the queries, not just the deduplicated set.
        if !lock!(self.abuse.recursive_query_limiter).allow(*peer_id.as_bytes()) {
            return DispatchResult::NoResponse;
        }

        let q = match RecursiveQueryPayload::decode(body) {
            Ok(q) => q,
            Err(e) => return DispatchResult::Violation(format!("bad RecursiveQuery: {e}")),
        };

        // Dedup: prevent loops in recursive forwarding.
        if lock!(self.recursive_query_seen).check_and_insert(q.query_id) {
            return DispatchResult::NoResponse;
        }

        // j: demoted to DEBUG. Recursive DHT queries fire
        // every routing fallback under chaos-ban-driven route_cache misses
        // (~10/sec on bootstrap). Aggregate visibility saved through
        // `veil_dht_lookup_total` / `veil_dht_fallback_*` counters.
        self.logger.debug(
            "recursive.query",
            format!(
                "type={} target={} from={} ttl={} reply_to={}",
                q.query_type,
                veil_util::hex_short(&q.target_key),
                veil_util::hex_short(peer_id.as_bytes()),
                q.ttl,
                veil_util::hex_short(&q.reply_to),
            ),
        );

        // build a RecursiveResponse signed with our long-term
        // Ed25519 key so the initiator can verify the responder identity.
        // Returns `None` when we have no signing key (unit-test dispatcher).
        let build_signed = |payload: Vec<u8>| -> Option<RecursiveResponsePayload> {
            use ed25519_dalek::Signer as _;
            let key = self.crypto.local_signing_key.as_ref()?;
            let pk_bytes: [u8; 32] = key.verifying_key().to_bytes();
            let mut signable = Vec::with_capacity(16 + payload.len());
            signable.extend_from_slice(&q.query_id);
            signable.extend_from_slice(&payload);
            let sig = key.sign(&signable).to_bytes();
            Some(RecursiveResponsePayload {
                query_id: q.query_id,
                payload,
                responder_pubkey: pk_bytes,
                signature: sig,
            })
        };
        let send_response = |resp: RecursiveResponsePayload| {
            let frame = encode_routing_frame(RoutingMsg::RecursiveResponse, &resp.encode());
            let Some(reg) = &self.session_tx_registry else {
                self.logger
                    .warn("recursive.response.no_registry", "no session_tx_registry");
                return;
            };
            let prio = veil_proto::header::priority::INTERACTIVE;
            // snapshot the route_cache lookup
            // BEFORE taking the registry lock. Canonical order
            // `route_cache → session_tx_registry`.
            let cached_hop = rlock!(self.route_cache).lookup(&q.reply_to);
            let guard = wlock!(reg);
            // 0. e: PREFER the immediate query sender (peer_id).
            // The query reached us through them, so they hold a
            // `recursive_reverse_path[query_id]` entry pointing at the
            // originator and will relay the response correctly. Pure
            // DHT-greedy by XOR distance picks "closest to reply_to" —
            // which in fragmented topologies often loops back to the
            // responder itself (e.g. responder picks neighbour A → A's
            // closest-to-reply_to is the responder again).
            if peer_id.as_bytes() != &self.local_node_id
                && guard.send_to(peer_id.as_bytes(), prio, frame.clone())
            {
                // l: demoted to DEBUG (high-freq under DHT fallback).
                self.logger.debug(
                    "recursive.response.sent",
                    format!(
                        "via=sender hop={} reply_to={}",
                        veil_util::hex_short(peer_id.as_bytes()),
                        veil_util::hex_short(&q.reply_to)
                    ),
                );
                return;
            }
            // 1. Direct session to originator — fast path.
            if guard.send_to(&q.reply_to, prio, frame.clone()) {
                // l: demoted to DEBUG (high-freq under DHT fallback).
                self.logger.debug(
                    "recursive.response.sent",
                    format!("via=direct reply_to={}", veil_util::hex_short(&q.reply_to)),
                );
                return;
            }
            // 2. Route-cache hop toward originator (snapshot taken above).
            if let Some(hop) = cached_hop
                && hop != self.local_node_id
                && &hop != peer_id.as_bytes()
                && guard.send_to(&hop, prio, frame.clone())
            {
                // l: demoted to DEBUG (high-freq under DHT fallback).
                self.logger.debug(
                    "recursive.response.sent",
                    format!(
                        "via=cache hop={} reply_to={}",
                        veil_util::hex_short(&hop),
                        veil_util::hex_short(&q.reply_to)
                    ),
                );
                return;
            }
            // 3. follow-up: DHT k-closest greedy. Excludes
            // both `local_node_id` (self) and `peer_id` (query sender —
            // see step 0 — they already saw the query and would loop).
            let closest = self.dht.find_closest_nodes(&q.reply_to, 4);
            let closest_count = closest.len();
            for next_hop in closest {
                if next_hop == self.local_node_id {
                    continue;
                }
                if &next_hop == peer_id.as_bytes() {
                    continue;
                }
                if guard.send_to(&next_hop, prio, frame.clone()) {
                    // l: demoted to DEBUG.
                    self.logger.debug(
                        "recursive.response.sent",
                        format!(
                            "via=dht hop={} reply_to={}",
                            veil_util::hex_short(&next_hop),
                            veil_util::hex_short(&q.reply_to)
                        ),
                    );
                    return;
                }
            }
            self.logger.warn(
                "recursive.response.dropped",
                format!(
                    "no path to reply_to={} (sender={} cache_hop={:?} dht_candidates={})",
                    veil_util::hex_short(&q.reply_to),
                    veil_util::hex_short(peer_id.as_bytes()),
                    cached_hop.map(|h| veil_util::hex_short(&h)),
                    closest_count
                ),
            );
        };

        // Try to answer locally.
        match q.query_type {
            recursive_query_type::FIND_VALUE => {
                if let Some(value) = self.dht.get_local(&q.target_key) {
                    // l: demoted to DEBUG.
                    self.logger.debug(
                        "recursive.answer.local",
                        format!(
                            "type=FIND_VALUE target={}",
                            veil_util::hex_short(&q.target_key)
                        ),
                    );
                    if let Some(resp) = build_signed(value) {
                        send_response(resp);
                    }
                    return DispatchResult::NoResponse;
                }
            }
            recursive_query_type::FIND_NODE => {
                // If this node IS the target (or close), respond with K closest contacts.
                if q.target_key == self.local_node_id {
                    // filter to Public-only + half-cap, same as
                    // direct FIND_NODE. Internal routing (find_closest_nodes
                    // for next-hop selection on lines below) stays unfiltered.
                    let closest = self.dht.find_closest_public_node_ids(&q.target_key, 20);
                    // l: demoted to DEBUG.
                    self.logger.debug(
                        "recursive.answer.find_node",
                        format!(
                            "target=self contacts={} reply_to={}",
                            closest.len(),
                            veil_util::hex_short(&q.reply_to)
                        ),
                    );
                    let mut payload = Vec::with_capacity(closest.len() * 32);
                    for nid in &closest {
                        payload.extend_from_slice(nid);
                    }
                    if let Some(resp) = build_signed(payload) {
                        send_response(resp);
                    } else {
                        self.logger.warn(
                            "recursive.answer.no_signing_key",
                            "FIND_NODE response not built — no local_signing_key",
                        );
                    }
                    // regression repair: FIND_NODE alone carries no
                    // ML-KEM encapsulation key, so a multi-hop IPC_SEND to this
                    // node would fail with `NO_E2E_KEY` even after the route
                    // was learnt. Piggy-back a signed `RouteResponse` with our
                    // own `mlkem_pubkey` + `ed25519_pubkey` on every self-
                    // addressed FIND_NODE — the requester's existing
                    // `handle_route_response` path verifies the signature
                    // (known-pubkey fast path OR `BLAKE3(pubkey) == node_id`
                    // binding for unknown peers) and populates
                    // `peer_mlkem_keys` so E2E encryption works without a
                    // direct session.
                    if let Some(ref key) = self.crypto.local_signing_key {
                        use ed25519_dalek::Signer as _;
                        let ek_bytes = self.crypto.mlkem_ek.as_ref().to_vec();
                        let has_ek = ek_bytes.iter().any(|b| *b != 0);
                        if has_ek {
                            let request_id =
                                u32::from_be_bytes(q.query_id[..4].try_into().unwrap_or([0; 4]));
                            let mut route_resp = veil_proto::routing::RouteResponsePayload {
                                target_node_id: self.local_node_id,
                                requester_node_id: q.reply_to,
                                request_id,
                                transports: Vec::new(),
                                relay_ids: Vec::new(),
                                mlkem_pubkey: Some(ek_bytes),
                                signature: [0u8; 64],
                                ed25519_pubkey: Some(key.verifying_key().to_bytes().to_vec()),
                                target_labels: self.target_labels.clone(),
                            };
                            route_resp.signature =
                                key.sign(&route_resp.signable_bytes()).to_bytes();
                            let frame = encode_routing_frame(
                                RoutingMsg::RouteResponse,
                                &route_resp.encode(),
                            );
                            // f: piggy-back RouteResponse needs the
                            // same multi-hop fallback as send_response — direct
                            // and route_cache alone fail in fragmented topologies
                            // when the originator banned us. Without this
                            // chat works ONCE (some path stale-cached the key)
                            // and then falls into NO_E2E_KEY on every subsequent
                            // send because the piggy-back was never delivered.
                            // Same fallback chain: 0=via=sender (peer_id holds
                            // reverse_path), 1=direct, 2=route_cache, 3=DHT-greedy.
                            if let Some(reg) = &self.session_tx_registry {
                                let prio = veil_proto::header::priority::INTERACTIVE;
                                // snapshot
                                // the route_cache lookup BEFORE taking
                                // the registry lock — canonical order
                                // `route_cache → session_tx_registry`.
                                let cached_hop = rlock!(self.route_cache).lookup(&q.reply_to);
                                let guard = wlock!(reg);
                                let mut sent_via: Option<&'static str> = None;
                                if peer_id.as_bytes() != &self.local_node_id
                                    && guard.send_to(peer_id.as_bytes(), prio, frame.clone())
                                {
                                    sent_via = Some("sender");
                                } else if guard.send_to(&q.reply_to, prio, frame.clone()) {
                                    sent_via = Some("direct");
                                } else if let Some(hop) = cached_hop
                                    && hop != self.local_node_id
                                    && &hop != peer_id.as_bytes()
                                    && guard.send_to(&hop, prio, frame.clone())
                                {
                                    sent_via = Some("cache");
                                } else {
                                    let closest = self.dht.find_closest_nodes(&q.reply_to, 4);
                                    for next_hop in closest {
                                        if next_hop == self.local_node_id {
                                            continue;
                                        }
                                        if &next_hop == peer_id.as_bytes() {
                                            continue;
                                        }
                                        if guard.send_to(&next_hop, prio, frame.clone()) {
                                            sent_via = Some("dht");
                                            break;
                                        }
                                    }
                                }
                                if let Some(via) = sent_via {
                                    // l: demoted to DEBUG.
                                    self.logger.debug(
                                        "recursive.answer.piggyback_sent",
                                        format!(
                                            "via={via} reply_to={}",
                                            veil_util::hex_short(&q.reply_to)
                                        ),
                                    );
                                } else {
                                    self.logger.warn("recursive.answer.piggyback_dropped",
                                        format!("reply_to={} — RouteResponse with mlkem_pubkey not delivered",
                                            veil_util::hex_short(&q.reply_to)));
                                }
                            }
                        }
                    }
                    return DispatchResult::NoResponse;
                }
            }
            recursive_query_type::STORE => {
                // Reject oversized payloads before storing.
                if q.payload.len() > veil_proto::budget::MAX_DHT_VALUE_BYTES {
                    return DispatchResult::Violation(format!(
                        "RecursiveQuery STORE: payload too large ({} > {} bytes)",
                        q.payload.len(),
                        veil_proto::budget::MAX_DHT_VALUE_BYTES,
                    ));
                }
                // store if this node is in the K-closest
                // set for `target_key` (or *is* the target). Previously
                // only the single closest node stored the value, which
                // gave a single replica that vanished as soon as that
                // node went offline. K-closest replication means
                // up to `DHT_REPLICATION_K` independent peers each hold
                // a copy. Falls through to greedy forwarding if this
                // node is not in the set, so the publisher's STORE
                // eventually reaches the K-closest cluster regardless
                // of where it entered the network.
                //
                // fix: `find_closest_nodes` returns nodes
                // from the routing table, which by Kademlia convention
                // excludes self. The previous check
                // `closest.contains(&local_node_id)` therefore always
                // failed → no replicas were ever stored on receivers.
                // Correct semantics: the local node is "in the K
                // closest" iff EITHER the RT has fewer than K
                // candidates (we're trivially among the closest, since
                // RT-size + 1 ≤ K), OR our XOR distance to `target_key`
                // is strictly less than the K-th candidate's distance
                // (we'd displace it from the K-closest set if self were
                // a candidate).
                let k = veil_proto::budget::DHT_REPLICATION_K;
                let closest = self.dht.find_closest_nodes(&q.target_key, k);
                let xor_dist = |a: &[u8; 32]| -> [u8; 32] {
                    let mut out = [0u8; 32];
                    for i in 0..32 {
                        out[i] = a[i] ^ q.target_key[i];
                    }
                    out
                };
                let in_k_closest = closest.contains(&self.local_node_id)
                    || closest.len() < k
                    || closest
                        .last()
                        .map(|furthest| xor_dist(&self.local_node_id) < xor_dist(furthest))
                        .unwrap_or(true);
                if in_k_closest || q.target_key == self.local_node_id {
                    // SECURITY: validate the payload against the magic-prefix
                    // authenticator policy BEFORE writing to the local DHT.
                    // The direct STORE path runs the same validation in
                    // dispatch_discovery; without this gate, a recursive
                    // STORE could write arbitrary (key, value) pairs into
                    // the local TieredStore, bypassing the signed-store
                    // ownership invariants.
                    let origin = match self.validate_store_value_by_magic(&q.payload) {
                        Ok(origin) => origin,
                        Err(violation) => return violation,
                    };
                    // audit cycle-7 (HIGH — DHT key-binding): same canonical-key
                    // binding as the direct STORE arm (dispatch_discovery). An
                    // owner-verified AP/AT/SB record may only be written under its
                    // own canonical key, never an attacker-chosen `q.target_key`,
                    // else a valid record of the attacker's identity poisons the
                    // victim key. `mirror_cache_key_ok` passes nc/id/ir/mc through
                    // (re-verified on the resolver read path).
                    if !self.mirror_cache_key_ok(&q.payload, &q.target_key) {
                        return DispatchResult::Violation(
                            "Store: self-authenticating record stored under non-canonical DHT key"
                                .to_owned(),
                        );
                    }
                    // Audit N1: write through the per-origin-capped path, NOT
                    // store_local (which writes as ORIGIN_INTERNAL and is exempt
                    // from per_origin_max_bytes). A single signer can no longer
                    // flood the local store past its per-origin byte cap via the
                    // recursive plane — the same accounting the direct STORE path
                    // (handle_store) enforces.
                    if !self
                        .dht
                        .store_with_origin(q.target_key, q.payload.clone(), origin)
                    {
                        // per-origin byte cap exceeded — drop silently
                        // (DoS-resistance: do not sign a failure response).
                        return DispatchResult::NoResponse;
                    }
                    if let Some(resp) = build_signed(vec![1]) {
                        send_response(resp);
                    }
                    return DispatchResult::NoResponse;
                }
            }
            veil_proto::routing::recursive_query_type::RENDEZVOUS_REQUEST => {
                // PoW-Gated Rendezvous request — Slice 6b of the epic.
                // Only act locally when `target_key == self.local_node_id`;
                // otherwise fall through to greedy forwarding so the request
                // reaches the actual target (we're a relay hop).
                if q.target_key == self.local_node_id {
                    // Upgrade the dispatcher's Weak ref to the controller.
                    // None ⇒ no stealth listener configured locally —
                    // request was misrouted; drop silently (don't sign a
                    // failure response: DoS-resistance).
                    let controller = {
                        let lock = match self.rendezvous_weak.lock() {
                            Ok(g) => g,
                            Err(p) => p.into_inner(),
                        };
                        lock.as_ref().and_then(|w| w.upgrade())
                    };
                    let Some(controller) = controller else {
                        self.logger.debug(
                            "rendezvous.recursive.no_controller",
                            format!(
                                "target=self reply_to={} dropped (no stealth listener)",
                                veil_util::hex_short(&q.reply_to),
                            ),
                        );
                        return DispatchResult::NoResponse;
                    };

                    // Spawn a task so the async controller call doesn't
                    // block the dispatch hot path.  send_response moves
                    // through the closure capture above.
                    let body = q.payload.clone();
                    let logger = Arc::clone(&self.logger);
                    let metrics = self.metrics.clone();
                    let query_id = q.query_id;
                    let reply_to = q.reply_to;
                    let local_signing_key = self.crypto.local_signing_key.clone();
                    let session_tx = self.session_tx_registry.clone();
                    let route_cache = Arc::clone(&self.route_cache);
                    let local_node_id = self.local_node_id;
                    let sender_peer_id: [u8; 32] = *peer_id.as_bytes();
                    tokio::spawn(async move {
                        use veil_session::rendezvous::{RejectReason, RequestOutcome};
                        let outcome = controller.handle_request(&body).await;
                        let response_bytes = match outcome {
                            RequestOutcome::Granted { response_bytes, .. } => response_bytes,
                            RequestOutcome::Rejected(reason) => {
                                let kind = match reason {
                                    RejectReason::Decode(_) => "decode",
                                    RejectReason::Verify(_) => "verify",
                                    RejectReason::NotOurTarget => "not_our_target",
                                    RejectReason::RateLimited => "rate_limited",
                                    RejectReason::ConcurrencyExhausted => "concurrency_exhausted",
                                    RejectReason::BindFailed(_) => "bind_failed",
                                };
                                logger.info(
                                    "rendezvous.recursive.rejected",
                                    format!(
                                        "reply_to={} reason={kind}",
                                        veil_util::hex_short(&reply_to),
                                    ),
                                );
                                // DoS-resistant: don't ship a rejection
                                // response.  Initiator times out.
                                return;
                            }
                        };
                        // Sign the recursive-response envelope with the local
                        // identity key.  Initiator validates
                        // `BLAKE3(responder_pubkey) == target_node_id`.
                        let Some(key) = local_signing_key.as_ref() else {
                            logger.warn(
                                "rendezvous.recursive.no_signing_key",
                                "cannot sign response — no local_signing_key",
                            );
                            return;
                        };
                        use ed25519_dalek::Signer as _;
                        let pk_bytes: [u8; 32] = key.verifying_key().to_bytes();
                        let mut signable = Vec::with_capacity(16 + response_bytes.len());
                        signable.extend_from_slice(&query_id);
                        signable.extend_from_slice(&response_bytes);
                        let sig = key.sign(&signable).to_bytes();
                        let resp = veil_proto::routing::RecursiveResponsePayload {
                            query_id,
                            payload: response_bytes,
                            responder_pubkey: pk_bytes,
                            signature: sig,
                        };
                        let frame = encode_routing_frame(
                            veil_proto::family::RoutingMsg::RecursiveResponse,
                            &resp.encode(),
                        );
                        // Reverse-path resolver: 0=sender, 1=direct,
                        // 2=route_cache hop.  Same as FIND_NODE arm.
                        let Some(reg) = session_tx else {
                            return;
                        };
                        let prio = veil_proto::header::priority::INTERACTIVE;
                        let cached_hop = rlock!(route_cache).lookup(&reply_to);
                        let guard = wlock!(reg);
                        if sender_peer_id != local_node_id
                            && guard.send_to(&sender_peer_id, prio, frame.clone())
                        {
                            logger.debug(
                                "rendezvous.recursive.response.sent",
                                format!(
                                    "via=sender hop={} reply_to={}",
                                    veil_util::hex_short(&sender_peer_id),
                                    veil_util::hex_short(&reply_to),
                                ),
                            );
                            return;
                        }
                        if guard.send_to(&reply_to, prio, frame.clone()) {
                            logger.debug(
                                "rendezvous.recursive.response.sent",
                                format!("via=direct reply_to={}", veil_util::hex_short(&reply_to),),
                            );
                            return;
                        }
                        if let Some(hop) = cached_hop
                            && hop != local_node_id
                            && hop != sender_peer_id
                            && guard.send_to(&hop, prio, frame.clone())
                        {
                            logger.debug(
                                "rendezvous.recursive.response.sent",
                                format!(
                                    "via=cache hop={} reply_to={}",
                                    veil_util::hex_short(&hop),
                                    veil_util::hex_short(&reply_to),
                                ),
                            );
                            return;
                        }
                        logger.warn(
                            "rendezvous.recursive.response.no_route",
                            format!(
                                "reply_to={} — granted but cannot route response",
                                veil_util::hex_short(&reply_to),
                            ),
                        );
                        // Metrics: successful grant is considered through
                        // controller's own counters; routing-failure
                        // here is a partial-success — counted via
                        // existing send_to_failed_total through the
                        // session_tx_registry's drop path.
                        let _ = metrics; // counters incremented in-controller
                    });
                    return DispatchResult::NoResponse;
                }
                // target_key ≠ local — fall through to greedy-forwarding.
            }
            _ => {
                return DispatchResult::Violation(format!(
                    "unknown recursive query_type {}",
                    q.query_type
                ));
            }
        }

        // Not answered locally — greedy forward to closest contact.
        if q.ttl == 0 {
            self.logger.warn(
                "recursive.ttl_exhausted",
                format!("target={}", veil_util::hex_short(&q.target_key)),
            );
            return DispatchResult::NoResponse;
        }

        // rate-limit recursive forwards per source peer. Every
        // forwarded query fans out to top-2 closest contacts, so without
        // this an attacker spinning new query_ids at line rate amplifies
        // their bandwidth ~2× per recursive hop (up to TTL=20 deep).
        // RouteRequest forwarding (line 478) already has the same gate.
        if !lock!(self.abuse.dht_quota).allow(*peer_id.as_bytes()) {
            self.logger.warn(
                "recursive.forward.rate_limited",
                format!(
                    "peer={} target={}",
                    veil_util::hex_short(peer_id.as_bytes()),
                    veil_util::hex_short(&q.target_key)
                ),
            );
            // Audit batch 2026-05-24: emit Violation so persistent abuse
            // escalates through violation_tracker to a ban.
            return DispatchResult::Violation("RecursiveQuery DHT quota exceeded".to_string());
        }

        let closest = self.dht.find_closest_nodes(&q.target_key, 2);
        // j: demoted to DEBUG (pairs with recursive.query above).
        self.logger.debug(
            "recursive.forward",
            format!(
                "target={} next_hops={} ttl={}",
                veil_util::hex_short(&q.target_key),
                closest.len(),
                q.ttl - 1
            ),
        );
        // follow-up: remember the originator so the eventual
        // RecursiveResponse can be relayed back along this path. Without
        // this, responders in fragmented topologies have no way to reach
        // `reply_to` (no direct session, route_cache wiped after bans)
        // and the response is silently dropped at the responder.
        {
            use std::time::{Duration, Instant};
            const REVERSE_PATH_TTL: Duration = Duration::from_secs(30);
            const REVERSE_PATH_CAP: usize = 4096;
            // Per-peer sub-quota (audit cycle-8): one forwarding peer may hold
            // at most this many live reverse-path entries, so it cannot evict
            // every other peer's entries by spraying distinct query_ids. 1/16
            // of the global cap — generous for honest multi-query peers.
            const REVERSE_PATH_PER_PEER_CAP: usize = REVERSE_PATH_CAP / 16;
            let this_peer = *peer_id.as_bytes();
            let mut path = lock!(self.recursive_reverse_path);
            // Cheap O(n) eviction on insert — bounded by REVERSE_PATH_CAP.
            let now = Instant::now();
            path.retain(|_, (_, _, t)| now.duration_since(*t) < REVERSE_PATH_TTL);
            let this_peer_count = path.values().filter(|(_, p, _)| *p == this_peer).count();
            if path.len() < REVERSE_PATH_CAP && this_peer_count < REVERSE_PATH_PER_PEER_CAP {
                path.insert(q.query_id, (q.reply_to, this_peer, now));
            }
        }
        let forwarded = RecursiveQueryPayload {
            ttl: q.ttl - 1,
            ..q
        };
        let frame = encode_routing_frame(RoutingMsg::RecursiveQuery, &forwarded.encode());

        if let Some(reg) = &self.session_tx_registry {
            let guard = wlock!(reg);
            // Forward to top-2 closest (parallel routing).
            for next_hop in &closest {
                if next_hop == peer_id.as_bytes() {
                    continue;
                } // split-horizon
                if *next_hop == self.local_node_id {
                    continue;
                }
                guard.send_to(
                    next_hop,
                    veil_proto::header::priority::INTERACTIVE,
                    frame.clone(),
                );
            }
        }

        DispatchResult::NoResponse
    }

    fn handle_recursive_response(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        let resp = match RecursiveResponsePayload::decode(body) {
            Ok(r) => r,
            Err(e) => return DispatchResult::Violation(format!("bad RecursiveResponse: {e}")),
        };

        // verify the responder's authenticator before trusting the
        // payload. A passive relay that observed the `query_id` mid-flight
        // cannot forge this signature without the claimed responder's long-term
        // key. Two checks: (a) `BLAKE3(responder_pubkey)` binds the key to a
        // node_id; (b) Ed25519 signature covers `query_id || payload`.
        let claimed_responder_id: [u8; 32] = *blake3::hash(&resp.responder_pubkey).as_bytes();
        {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let vk = match VerifyingKey::from_bytes(&resp.responder_pubkey) {
                Ok(vk) => vk,
                Err(_) => {
                    self.logger.warn(
                        "recursive.response.bad_pubkey",
                        "malformed responder_pubkey",
                    );
                    return DispatchResult::NoResponse;
                }
            };
            let sig = Signature::from_bytes(&resp.signature);
            if vk.verify(&resp.signable_bytes(), &sig).is_err() {
                self.logger.warn(
                    "recursive.response.bad_sig",
                    format!(
                        "invalid signature from claimed responder={}",
                        veil_util::hex_short(&claimed_responder_id)
                    ),
                );
                return DispatchResult::NoResponse;
            }
        }

        // Correlate with the pending query, parse the payload according to the
        // original query_type, then signal the initiator.
        let pending = lock!(self.pending_recursive).remove(&resp.query_id);
        if let Some(p) = pending {
            // follow-up: a valid signature only proves the responder
            // owns their long-term key — it does not prove they are close to
            // `target_key`. Without a proximity check an attacker with a
            // single valid PoW identity, observing `query_id` mid-flight
            // could forge a reply claiming their own node_id as "closest" and
            // get inserted into the initiator's route_cache (MITM vector).
            //
            // Require the responder to either BE the target or share at least
            // `REQUIRED_RESPONDER_PREFIX_BITS` with it — that is, XOR-distance
            // top bits must be zero. Attackers must now grind a pubkey whose
            // BLAKE3 hash matches the target's prefix (2^PREFIX_BITS extra
            // work per forged identity). Legitimate close nodes naturally
            // satisfy this.
            //
            // bumped 8 → 16 bits. At 8 bits an attacker only
            // needs 2^8 = 256 attempts per forged response (cheap). At 16
            // bits = 65 536 attempts, on top of the per-identity PoW.
            // 16 bits is still very loose — legitimate K=20 closest peers
            // share many more high bits with target_key on average.
            //
            // replaced the cfg-gated `const 16 / 0` flip with
            // an adaptive lookup against `dispatcher.adaptive_params`
            // recomputed every reload tick from
            // `estimate_network_size(routing_table_size, active_sessions)`
            // → `AdaptiveParams::from_network_size`. Formula
            // `min(16, max(0, ceil(log2(N)) - 4))` floors at 0 for small
            // networks (so a 100-node testnet's random-key recursive
            // lookups don't get rejected as "responder too far") and
            // saturates at 16 for N ≥ 2^20 (preserves the production
            // anti-amplification floor that set). See
            // `cfg/adaptive.rs::min_responder_prefix_bits` for the full
            // derivation.
            //
            // The `test-low-difficulty` feature is no longer consulted
            // here — for tests the formula naturally floors at 0 because
            // sim networks are small (the `Default::default` value
            // computed from `from_network_size(100)` already gives 3
            // bits, and `RwLock::default` initializes the dispatcher
            // field to), and the actual production gate kicks in
            // only after enough reload ticks have updated the dispatcher
            // params from the live routing table.
            let required_prefix_bits = self
                .adaptive_params
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .min_responder_prefix_bits;
            if claimed_responder_id != p.target_key {
                let xor = veil_dht::routing::xor_distance(&claimed_responder_id, &p.target_key);
                let mut lz = 0u32;
                for b in xor.iter() {
                    if *b == 0 {
                        lz += 8;
                    } else {
                        lz += b.leading_zeros();
                        break;
                    }
                }
                let too_far = lz < required_prefix_bits;
                if too_far {
                    self.logger.warn(
                        "recursive.response.far_responder",
                        format!(
                            "responder={} is too far from target={} (shared_bits={})",
                            veil_util::hex_short(&claimed_responder_id),
                            veil_util::hex_short(&p.target_key),
                            lz,
                        ),
                    );
                    // Re-insert the pending entry so a legitimate late
                    // response can still fulfil it — but only if the map
                    // is below `MAX_PENDING_RECURSIVE`. Without this cap
                    // an attacker who observes `query_id`s mid-flight can
                    // race forged-too-far responses against legitimate
                    // queries: every (remove + reinsert) pair lets one
                    // concurrent legitimate insert slip past the cap
                    // check at `runtime/mod.rs:try_recursive_get`, so the
                    // map can drift past the cap by N where N is the
                    // attacker's concurrent-response rate. Drop the
                    // re-insert when full; the originating future will
                    // time out and either retry or surface the failure.
                    use veil_proto::budget::MAX_PENDING_RECURSIVE;
                    let mut m = lock!(self.pending_recursive);
                    if m.len() < MAX_PENDING_RECURSIVE {
                        m.insert(resp.query_id, p);
                    } else {
                        self.logger.warn(
                            "recursive.response.reinsert_dropped",
                            format!("pending_recursive at cap {MAX_PENDING_RECURSIVE} — dropping re-insert for query_id"),
                        );
                    }
                    return DispatchResult::NoResponse;
                }
            }
            match p.query_type {
                recursive_query_type::FIND_NODE => {
                    // payload = concatenated 32-byte node_ids, closest to target_key.
                    // Insert each candidate as a next-hop for `target_key`.  The
                    // dedicated hop_count is unknown (recursive queries do not
                    // report per-candidate distance on the wire); we use 2 as a
                    // conservative default so direct RouteAnnounce(1-hop)
                    // learnings still outrank these inserts.
                    //
                    // SECURITY: gate the bulk insert through `dht_contact_quota`
                    // so a single attacker cannot inject up to 32 sybil hops
                    // per response (MAX_NODES_PER_RESPONSE), churning the
                    // 1024-slot route_cache in seconds.  Direct RouteResponse
                    // (line 661) already uses the same quota — symmetry.
                    if !lock!(self.abuse.dht_contact_quota).allow(*peer_id.as_bytes()) {
                        return DispatchResult::NoResponse;
                    }
                    const RECURSIVE_LEARNED_SCORE: u32 = 50_000;
                    const RECURSIVE_LEARNED_HOPS: u8 = 2;
                    let mut cache = wlock!(self.route_cache);
                    for chunk in resp.payload.chunks_exact(32) {
                        let mut hop = [0u8; 32];
                        hop.copy_from_slice(chunk);
                        if hop == [0u8; 32] {
                            continue;
                        }
                        cache.insert(
                            p.target_key,
                            hop,
                            RECURSIVE_LEARNED_SCORE,
                            RECURSIVE_LEARNED_HOPS,
                        );
                    }
                }
                recursive_query_type::FIND_VALUE
                    if !resp.payload.is_empty()
                        // SECURITY: the responder's `claimed_responder_id` is
                        // signature-verified above, but that only proves the
                        // *responder* signed `query_id || payload` — it does NOT
                        // bind the payload to `p.target_key`.  An attacker that
                        // observes a `query_id` can race the legitimate holder
                        // with a forged payload and poison our local DHT cache under
                        // an attacker-chosen key.  Apply the same magic-prefix
                        // authenticator gate that direct STORE uses so only
                        // self-authenticating record types are mirror-cached…
                        && self.validate_store_value_by_magic(&resp.payload).is_ok()
                        // …AND (audit cycle-6 A8) verify the record's CANONICAL
                        // DHT key equals `target_key` for derivable record types
                        // (AppEndpoint / Attachment / SignedBundle), closing the
                        // bind-to-target_key gap above: a valid record of the
                        // responder's OWN can no longer be cached under a victim's
                        // key. (Structurally-decoded nc/id/ir/mc keep prior
                        // behaviour; they are re-verified on the resolver path.)
                        && self.mirror_cache_key_ok(&resp.payload, &p.target_key) =>
                {
                    // payload = raw value bytes; mirror into the local DHT so
                    // subsequent lookups resolve without another round-trip.
                    self.dht.store_local(p.target_key, resp.payload.clone());
                }
                recursive_query_type::STORE => {
                    // payload = `[1]` on success; nothing to cache — just signal.
                }
                _ => {}
            }
            let _ = p.tx.send(resp.payload);
            // Originator processed — no need to relay back.
            self.route_updated.notify_waiters();
            return DispatchResult::NoResponse;
        }

        // follow-up: this node is an INTERMEDIATE forwarder
        // not the originator. Look up the reverse path recorded when we
        // forwarded the matching RecursiveQuery, and relay the response
        // toward `reply_to`. Three fallbacks: direct session, route_cache
        // hop, DHT k-closest greedy. Without this, responses generated
        // by deep peers in fragmented topologies never reach the originator.
        let reply_to_opt = lock!(self.recursive_reverse_path)
            .remove(&resp.query_id)
            .map(|(r, _, _)| r);
        if let Some(reply_to) = reply_to_opt {
            let frame = encode_routing_frame(RoutingMsg::RecursiveResponse, &resp.encode());
            if let Some(ref reg_arc) = self.session_tx_registry {
                // take `route_cache` BEFORE
                // `session_tx_registry` so the canonical lock order is
                // `route_cache → session_tx_registry`. The legacy
                // pattern took `reg_arc` then `route_cache` while
                // other dispatcher paths take `route_cache` then
                // `reg_arc` — opposing orders → potential deadlock.
                // Snapshot the cache lookup as a plain `Option<[u8;32]>`
                // so the read-guard drops before we take the registry
                // lock.
                let cached_hop = rlock!(self.route_cache).lookup(&reply_to);
                let guard = wlock!(reg_arc);
                let prio = veil_proto::header::priority::INTERACTIVE;
                // 1. Direct session to originator.
                if guard.send_to(&reply_to, prio, frame.clone()) {
                    // j: demoted to DEBUG (high-frequency under fallback).
                    self.logger.debug(
                        "recursive.response.relayed",
                        format!(
                            "via=direct reply_to={} responder={}",
                            veil_util::hex_short(&reply_to),
                            veil_util::hex_short(&claimed_responder_id)
                        ),
                    );
                    self.route_updated.notify_waiters();
                    return DispatchResult::NoResponse;
                }
                // 2. Route-cache next-hop (avoid sending back to the
                // immediate sender of the response — that's the way it
                // came from, sending back is a guaranteed loop).
                if let Some(hop) = cached_hop
                    && hop != self.local_node_id
                    && &hop != peer_id.as_bytes()
                    && guard.send_to(&hop, prio, frame.clone())
                {
                    // j: demoted to DEBUG (high-frequency under fallback).
                    self.logger.debug(
                        "recursive.response.relayed",
                        format!(
                            "via=cache hop={} reply_to={}",
                            veil_util::hex_short(&hop),
                            veil_util::hex_short(&reply_to)
                        ),
                    );
                    self.route_updated.notify_waiters();
                    return DispatchResult::NoResponse;
                }
                // 3. DHT k-closest greedy — exclude self AND peer_id
                // (split-horizon). Without the split-horizon, two
                // adjacent forwarders bounce the response between each
                // other when both consider the other "closest by XOR"
                // to the originator.
                let closest = self.dht.find_closest_nodes(&reply_to, 4);
                for next_hop in closest {
                    if next_hop == self.local_node_id {
                        continue;
                    }
                    if &next_hop == peer_id.as_bytes() {
                        continue;
                    }
                    if guard.send_to(&next_hop, prio, frame.clone()) {
                        // j: demoted to DEBUG.
                        self.logger.debug(
                            "recursive.response.relayed",
                            format!(
                                "via=dht hop={} reply_to={}",
                                veil_util::hex_short(&next_hop),
                                veil_util::hex_short(&reply_to)
                            ),
                        );
                        self.route_updated.notify_waiters();
                        return DispatchResult::NoResponse;
                    }
                }
                self.logger.warn(
                    "recursive.response.relay_dropped",
                    format!(
                        "no path back to reply_to={} — response from responder={} dropped",
                        veil_util::hex_short(&reply_to),
                        veil_util::hex_short(&claimed_responder_id),
                    ),
                );
            }
        } else {
            // Response arrived but neither for us nor a query we forwarded.
            // Could be: query_id reverse_path expired (>30s old), or
            // duplicate response after timeout, or cross-talk.
            // j: demoted to DEBUG. Orphan responses fire under
            // route-cache TTL expiry; high-volume under chaos-ban churn.
            self.logger.debug(
                "recursive.response.orphan",
                format!(
                    "query_id={} responder={} — no pending nor reverse_path",
                    veil_util::bytes_to_hex(&resp.query_id),
                    veil_util::hex_short(&claimed_responder_id),
                ),
            );
        }

        // Also notify route_updated for any IPC waiters that are polling on
        // the Notify instead of holding a oneshot.
        self.route_updated.notify_waiters();

        DispatchResult::NoResponse
    }

    // ── Event-driven route update ─────────────────────────────────

    fn handle_route_update_event(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        let p = match RouteUpdatePayload::decode(body) {
            Ok(p) => p,
            Err(e) => return DispatchResult::Violation(format!("bad RouteUpdate: {e}")),
        };

        // Signature verification: via_node_id must be the direct peer.
        if &p.via_node_id == peer_id.as_bytes() {
            match self.check_routing_sig(peer_id.as_bytes(), &p.signable_bytes(), &p.signature) {
                SigResult::Valid => {}
                SigResult::UnknownKey => return DispatchResult::NoResponse,
                SigResult::Invalid => {
                    return DispatchResult::Violation("RouteUpdate: invalid signature".to_owned());
                }
            }
        } else {
            // Gossip-relayed update: verify origin signature.
            match self.check_routing_sig(&p.origin_node_id, &p.signable_bytes(), &p.signature) {
                SigResult::Valid => {}
                SigResult::Invalid => {
                    return DispatchResult::Violation(
                        "RouteUpdate: invalid origin signature".to_owned(),
                    );
                }
                SigResult::UnknownKey => {
                    // Unknown origin: forward but don't apply.
                    return DispatchResult::NoResponse;
                }
            }
        }

        // audit cycle-6 (A7) — analysis, intentionally NOT version-gated/deduped:
        // The audit flagged that REMOVE applies before any version check and that
        // (unlike RouteAnnounce/RouteWithdraw) there is no dedup. Both candidate
        // fixes are unsafe here:
        //  * A version-MONOTONICITY gate (reject `version <=` the per-origin max)
        //    is wrong because `version` carries the ANNOUNCER's `announce_seq`
        //    (a per-node counter), NOT a per-origin authenticated sequence — two
        //    different nodes announcing routes to the same origin carry
        //    independent, non-comparable versions, so gating on origin-max would
        //    drop a second announcer's legitimate update.
        //  * Reusing `route_seen_set` is wrong because its per-(origin, seq)
        //    replay layer is shared with RouteAnnounce, and the emit path uses
        //    the SAME `announce_seq` for the RouteAnnounce and its paired
        //    RouteUpdate (see ~routing.rs:976/996) — so every legitimate
        //    RouteUpdate would be dropped as a "replay" of its own announce.
        // The residual is LOW and partly by-design: a peer can only REMOVE
        // routes where it is itself the `via` (suppressing its own reachability),
        // not arbitrary routes through other peers. A correct dedup would need a
        // dedicated (origin, via, version) seen-set distinct from RouteAnnounce's;
        // deferred as not worth the added hot-path state for this residual.

        // h: demoted to DEBUG. Under chaos-ban-style
        // network churn this fires 40k+ times per second per bootstrap
        // (5.5 M lines in 2 h on b1), spamming /var/log/veil/ at
        // ~630 MiB per hourly rotation and contributing measurable
        // alloc/free churn in the daemon's hot path. Operational
        // visibility is preserved via metrics gauges (route_cache
        // destinations/routes) and via the `RouteUpdate` action counter
        // — both bounded and diff-able by Prometheus.
        self.logger.debug(
            "route_update",
            format!(
                "action={} origin={} via={} hop={}",
                if p.action == route_update_action::ADD {
                    "ADD"
                } else {
                    "REMOVE"
                },
                veil_util::hex_short(&p.origin_node_id),
                veil_util::hex_short(&p.via_node_id),
                p.hop_count,
            ),
        );

        // Apply to route cache.
        match p.action {
            route_update_action::ADD => {
                wlock!(self.route_cache).insert(
                    p.origin_node_id,
                    p.via_node_id,
                    20_000, // default score for gossip-learned routes
                    p.hop_count.saturating_add(1),
                );
            }
            route_update_action::REMOVE => {
                wlock!(self.route_cache).invalidate_hop(&p.origin_node_id, &p.via_node_id);
            }
            _ => {
                return DispatchResult::Violation(format!(
                    "unknown RouteUpdate action {}",
                    p.action
                ));
            }
        }

        // Track version for reconciliation.
        wlock!(self.route_cache).update_version(p.origin_node_id, p.version);

        // Re-forward if hop_count allows (bounded propagation).
        if p.hop_count < self.max_gossip_hops
            && let Some(ref key) = self.crypto.local_signing_key
            && let Some(reg) = &self.session_tx_registry
        {
            let mut fwd = RouteUpdatePayload {
                origin_node_id: p.origin_node_id,
                via_node_id: self.local_node_id,
                action: p.action,
                version: p.version,
                hop_count: p.hop_count.saturating_add(1),
                signature: [0u8; 64],
            };
            fwd.signature = key.sign(&fwd.signable_bytes()).to_bytes();
            let frame = encode_routing_frame(RoutingMsg::RouteUpdate, &fwd.encode());
            wlock!(reg).send_to_all_except_with_priority(
                peer_id.as_bytes(),
                veil_proto::header::priority::BACKGROUND,
                veil_bufpool::pooled_shared_from_vec(frame),
            );
        }

        DispatchResult::NoResponse
    }
}

// ── SigResult ────────────────────────────────────────────────────────────────

/// Result [`FrameDispatcher::check_routing_sig`].
///
/// Using a 3-state result instead of `bool` lets callers distinguish "the key is
/// not yet cached" from "the signature is cryptographically wrong", which require
/// different responses: an unknown key on a gossip path is a soft miss (forward
/// but skip cache insertion), while a bad signature on a known key is a hard
/// protocol violation that should increment the peer's violation score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigResult {
    /// Signature is cryptographically valid.
    Valid,
    /// Key was found but the signature did not verify.
    Invalid,
    /// The peer's public key is not in the local cache.
    UnknownKey,
}

#[cfg(test)]
mod push_owned_tests {
    //! direct unit tests [`FrameDispatcher::push_owned_dht_records`].
    //!
    //! Avoiding the sim network here because `net.connect` reloads the runtime
    //! (wiping the DHT), which would make an end-to-end test impossible to set
    //! up without racing the reload against the announce. Driving the method
    //! directly gives a deterministic signal.

    use ed25519_dalek::SigningKey;
    use std::sync::{Arc, RwLock};

    use veil_cfg::NodeId;
    use veil_dht::KademliaService;
    use veil_discovery::directory::{
        APP_ENDPOINT_DHT_MAGIC, ATTACHMENT_DHT_MAGIC, AppEndpointEntry, encode_signed_attachment,
    };
    use veil_session::SessionTxRegistry;
    use veil_types::NodeIdBytes;

    use crate::make_test_dispatcher;
    use veil_cfg::NodeRole;
    use veil_discovery::sign_announcement;
    use veil_proto::{
        codec::decode_header,
        discovery::{AnnounceAttachmentPayload, StorePayload, app_endpoint_key},
        family::{DiscoveryMsg, FrameFamily},
    };

    fn new_signer() -> (SigningKey, [u8; 32], [u8; 32]) {
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let pk = sk.verifying_key().to_bytes();
        let node_id: NodeIdBytes = *blake3::hash(&pk).as_bytes();
        (sk, pk, node_id)
    }

    /// Signed AppEndpoint record owned by this node is pushed to the new peer.
    #[test]
    fn pushes_owned_app_endpoint_record() {
        let (sk, _pk, local_id) = new_signer();
        let mut disp = make_test_dispatcher(NodeRole::Core);
        disp.local_node_id = local_id;
        disp.dht = Arc::new(KademliaService::with_config(
            local_id,
            veil_dht::DhtRuntimeConfig {
                allow_unsigned_store: true,
                ..Default::default()
            },
        ));

        let entry = AppEndpointEntry {
            node_id: local_id,
            app_id: [0xA5u8; 32],
            endpoint_id: 7,
            gateway_node_id: None,
            epoch: 1,
            expires_at: u64::MAX / 2,
            max_concurrent_streams: 4,
            protocol_version: 1,
            bandwidth_hint_kbps: 64,
        };
        let key = app_endpoint_key(&entry.node_id, &entry.app_id, entry.endpoint_id);
        let value = entry.encode_for_dht_signed(&sk);
        disp.dht
            .handle_store(StorePayload::unsigned(key, value.clone()))
            .unwrap();

        let reg = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let peer: [u8; 32] = [0x11; 32];
        let mut rx = reg.write().unwrap().register(peer);
        disp.session_tx_registry = Some(Arc::clone(&reg));

        Arc::new(disp).push_owned_dht_records(peer, &reg);

        let (_prio, frame) = rx.try_recv().expect("STORE frame must be delivered");
        let hdr = decode_header(&frame).expect("valid header");
        assert_eq!(hdr.family, FrameFamily::Discovery as u8);
        assert_eq!(hdr.msg_type, DiscoveryMsg::Store as u16);
        let body = &frame[veil_proto::header::HEADER_SIZE..];
        let sp = StorePayload::decode(body).expect("decode StorePayload");
        assert_eq!(sp.key, key);
        assert_eq!(&sp.value[..2], &APP_ENDPOINT_DHT_MAGIC[..]);
        assert_eq!(sp.value, value);
    }

    /// Signed attachment record owned by this node is pushed to the new peer.
    #[test]
    fn pushes_owned_attachment_record() {
        let (sk, pk, local_id) = new_signer();
        let mut disp = make_test_dispatcher(NodeRole::Core);
        disp.local_node_id = local_id;
        disp.dht = Arc::new(KademliaService::with_config(
            local_id,
            veil_dht::DhtRuntimeConfig {
                allow_unsigned_store: true,
                ..Default::default()
            },
        ));

        let mut payload = AnnounceAttachmentPayload {
            node_id: local_id,
            role: 1,
            realm_id: 0,
            epoch: 1,
            expires_at: u64::MAX / 2,
            gateways: vec![],
            seq_no: 1,
            signature: vec![],
            ephemeral_endpoint: None,
        };
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let pk_b64 = STANDARD.encode(pk);
        let sk_b64 = STANDARD.encode(sk.to_bytes());
        sign_announcement(
            &mut payload,
            veil_cfg::SignatureAlgorithm::Ed25519,
            &pk_b64,
            &sk_b64,
        )
        .expect("sign attachment");
        let value = encode_signed_attachment(&payload, veil_cfg::SignatureAlgorithm::Ed25519, &pk);
        let key: [u8; 32] = *blake3::hash(&local_id).as_bytes();
        disp.dht
            .handle_store(StorePayload::unsigned(key, value.clone()))
            .unwrap();

        let reg = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let peer: [u8; 32] = [0x22; 32];
        let mut rx = reg.write().unwrap().register(peer);
        disp.session_tx_registry = Some(Arc::clone(&reg));

        Arc::new(disp).push_owned_dht_records(peer, &reg);

        let (_prio, frame) = rx.try_recv().expect("STORE frame must be delivered");
        let body = &frame[veil_proto::header::HEADER_SIZE..];
        let sp = StorePayload::decode(body).expect("decode StorePayload");
        assert_eq!(&sp.value[..2], &ATTACHMENT_DHT_MAGIC[..]);
        assert_eq!(sp.value, value);
    }

    /// Records this node does not own (a replica held for another node) must
    /// not be pushed: only the real owner should propagate on reconnect, else
    /// replicas could multiply across the network.
    #[test]
    fn skips_replicated_records_owned_by_others() {
        let (sk_other, _pk_other, other_id) = new_signer();
        let (_sk_local, _pk_local, local_id) = new_signer();
        let mut disp = make_test_dispatcher(NodeRole::Core);
        disp.local_node_id = local_id;
        disp.dht = Arc::new(KademliaService::with_config(
            local_id,
            veil_dht::DhtRuntimeConfig {
                allow_unsigned_store: true,
                ..Default::default()
            },
        ));

        let entry = AppEndpointEntry {
            node_id: other_id,
            app_id: [0xEEu8; 32],
            endpoint_id: 1,
            gateway_node_id: None,
            epoch: 1,
            expires_at: u64::MAX / 2,
            max_concurrent_streams: 1,
            protocol_version: 1,
            bandwidth_hint_kbps: 1,
        };
        let key = app_endpoint_key(&entry.node_id, &entry.app_id, entry.endpoint_id);
        let value = entry.encode_for_dht_signed(&sk_other);
        disp.dht
            .handle_store(StorePayload::unsigned(key, value))
            .unwrap();

        let reg = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let peer: [u8; 32] = [0x33; 32];
        let mut rx = reg.write().unwrap().register(peer);
        disp.session_tx_registry = Some(Arc::clone(&reg));

        Arc::new(disp).push_owned_dht_records(peer, &reg);

        assert!(
            rx.try_recv().is_err(),
            "must not push records owned by a different node_id",
        );
    }

    ///round 7 / : when `handle_recursive_response`
    /// rejects a too-far-from-target responder it re-inserts the
    /// pending entry so a legitimate late response can still fulfil it
    /// (routing.rs:1884). Pre-fix that re-insert had no cap check, so
    /// a concurrent legitimate insert sneaking in between the handler's
    /// `remove` (L1818) and re-insert could push `pending_recursive`
    /// past `MAX_PENDING_RECURSIVE`. Repeated forged-too-far responses
    /// against observed query_ids amplified the leak proportionally to
    /// the attacker's response rate. Post-fix: cap-check on re-insert.
    ///
    /// This test simulates the post-race state directly by manually
    /// loading the map to MAX+1 (one entry for our test query_id, MAX
    /// other entries simulating concurrent inserts that filled the gap)
    /// and verifies the handler's re-insert is dropped. Pre-fix the
    /// final size would be MAX+1; post-fix it's MAX.
    #[test]
    fn audit_round7_recursive_reinsert_respects_pending_cap() {
        use crate::DispatchResult;
        use ed25519_dalek::Signer;
        use veil_proto::budget::MAX_PENDING_RECURSIVE;
        use veil_proto::routing::{RecursiveResponsePayload, recursive_query_type};

        let disp = make_test_dispatcher(NodeRole::Core);
        // Force a tight proximity gate so any random pubkey is "too far".
        {
            let mut params = disp.adaptive_params.write().unwrap();
            params.min_responder_prefix_bits = 16;
        }

        // Far-from-target responder: pick a keypair whose BLAKE3(pk)
        // has a high bit different from `target_key`'s — guarantees
        // shared leading bits < 16.
        let target_key = [0xAAu8; 32];
        let (sk, pk_bytes) = loop {
            let sk = SigningKey::generate(&mut rand_core::OsRng);
            let pk: [u8; 32] = sk.verifying_key().to_bytes();
            let id: [u8; 32] = *blake3::hash(&pk).as_bytes();
            if (id[0] & 0x80) != (target_key[0] & 0x80) {
                break (sk, pk);
            }
        };

        let our_query_id: [u8; 16] = [0x77; 16];
        let (our_tx, _our_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

        // Pre-load the map with MAX entries simulating concurrent
        // inserts that filled the slot freed by the handler's remove
        // PLUS our query entry — total MAX+1. Without this manual
        // setup the race state can't be triggered deterministically.
        let mut keepalive = Vec::with_capacity(MAX_PENDING_RECURSIVE);
        {
            let mut m = disp.pending_recursive.lock().unwrap();
            for i in 0..MAX_PENDING_RECURSIVE {
                let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
                keepalive.push(rx); // keep tx alive (else `is_closed` reaper trims)
                let mut qid = [0u8; 16];
                qid[..8].copy_from_slice(&(i as u64).to_le_bytes());
                qid[15] = 0xff; // disambiguate from `our_query_id`
                m.insert(
                    qid,
                    crate::PendingRecursive {
                        target_key: [0u8; 32],
                        query_type: recursive_query_type::FIND_VALUE,
                        tx,
                    },
                );
            }
            m.insert(
                our_query_id,
                crate::PendingRecursive {
                    target_key,
                    query_type: recursive_query_type::FIND_VALUE,
                    tx: our_tx,
                },
            );
            assert_eq!(
                m.len(),
                MAX_PENDING_RECURSIVE + 1,
                "test setup: map at MAX+1 (race already won by attacker)"
            );
        }

        // Build a forged-too-far response with a valid Ed25519 sig.
        let mut resp = RecursiveResponsePayload {
            query_id: our_query_id,
            payload: vec![],
            responder_pubkey: pk_bytes,
            signature: [0u8; 64],
        };
        resp.signature = sk.sign(&resp.signable_bytes()).to_bytes();
        let body = resp.encode();

        let result = disp.handle_recursive_response(&body, NodeId::from([0xCCu8; 32]));
        assert!(matches!(result, DispatchResult::NoResponse));

        // Post-fix: handler removes our entry (MAX) then declines to
        // re-insert because the map is already at cap → final size MAX.
        // Pre-fix: re-insert succeeded, leaving the map at MAX+1.
        let final_len = disp.pending_recursive.lock().unwrap().len();
        assert_eq!(
            final_len,
            MAX_PENDING_RECURSIVE,
            "re-insert must respect the cap; pre-fix would leave {} = MAX+1",
            MAX_PENDING_RECURSIVE + 1
        );
    }
}

// ── Slice 8: PoW-Gated Rendezvous end-to-end integration ──────────

#[cfg(test)]
#[allow(clippy::type_complexity)] // test fixtures use Arc<Mutex<Vec<(String, [u8; 32])>>>
mod slice8_rendezvous_integration_tests {
    //! End-to-end integration tests for the PoW-Gated Rendezvous epic.
    //! Drives the full path through the wire bytes:
    //!
    //! 1. Initiator builds a signed PoW request (Slice 4)
    //! 2. Wraps it in a `RecursiveQuery` envelope (Slice 6c)
    //! 3. Dispatcher's `handle_recursive_query` arm processes (Slice 6b)
    //! 4. Controller does verify+rate-limit+concurrent+bind dispatch (Slice 3)
    //! 5. Recording binder captures (URI, PSK) (test-only — production
    //!    binder does the real `registry.bind` + accept-task spawn)
    //! 6. Controller signs the response (Slice 1)
    //! 7. Dispatcher arm packs the response in a `RecursiveResponse`
    //!    with outer envelope sig'd by the target's identity key
    //! 8. Sends back through `session_tx_registry.send_to(reply_to, ...)`
    //! 9. Initiator drains the mpsc receiver, decodes the frame,
    //!    parses + verifies the recursive response (Slice 6c client)
    //! 10. Asserts the recovered `EphemeralEndpoint` (URI + PSK + TTL)
    //!     matches what the binder recorded.

    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use veil_proto::routing::{
        RecursiveQueryPayload, RecursiveResponsePayload, recursive_query_type,
    };
    use veil_transport::on_demand::{OnDemandConfig, OnDemandLifecycle};

    use crate::{DispatchResult, FrameDispatcher, make_test_dispatcher};
    use veil_cfg::NodeId;
    use veil_cfg::NodeRole;
    use veil_proto::codec::decode_header;
    use veil_proto::family::{FrameFamily, RoutingMsg};
    use veil_proto::header::HEADER_SIZE;
    use veil_session::SessionTxRegistry;
    use veil_session::rendezvous::{BindClosure, RendezvousController, RendezvousPolicy};

    /// Recording binder — captures (uri, psk) and resolves immediately
    /// with Ok.  No real bind work.
    #[derive(Default)]
    struct RecordingBinder {
        calls: Arc<Mutex<Vec<(String, [u8; 32])>>>,
    }
    impl BindClosure for RecordingBinder {
        fn bind(
            &self,
            uri: String,
            psk: [u8; 32],
            _lifecycle: Arc<OnDemandLifecycle>,
        ) -> Pin<Box<dyn Future<Output = std::result::Result<(), String>> + Send + 'static>>
        {
            self.calls.lock().unwrap().push((uri, psk));
            Box::pin(async move { Ok(()) })
        }
    }

    /// Construct a FrameDispatcher with the target's identity wired into
    /// `crypto.local_signing_key`, a fresh `session_tx_registry`, and a
    /// rendezvous controller attached via `rendezvous_weak`.  Returns
    /// the strong Arc<Controller> separately so the test can keep it
    /// alive across the dispatch call.
    fn dispatcher_with_rendezvous(
        target_sk: SigningKey,
        target_node_id: [u8; 32],
        bind_calls: Arc<Mutex<Vec<(String, [u8; 32])>>>,
    ) -> (
        FrameDispatcher,
        Arc<RendezvousController>,
        Arc<RwLock<SessionTxRegistry>>,
    ) {
        let mut dispatcher = make_test_dispatcher(NodeRole::Core);
        // Install the target's identity into crypto (used to sign the
        // outer recursive-response envelope).
        let crypto = Arc::get_mut(&mut dispatcher.crypto)
            .expect("test dispatcher crypto must be uniquely held");
        crypto.local_signing_key = Some(Arc::new(target_sk.clone()));
        // Fix local_node_id to match the controller's expected target.
        dispatcher.local_node_id = target_node_id;

        // Wire a real session_tx_registry so the dispatcher can send
        // responses through it.
        let tx_registry = Arc::new(RwLock::new(SessionTxRegistry::new()));
        dispatcher.session_tx_registry = Some(Arc::clone(&tx_registry));

        // Build the controller with recording binder.
        let binder = Arc::new(RecordingBinder { calls: bind_calls });
        let policy = RendezvousPolicy {
            min_pow_difficulty: 8,
            rate_window: Duration::from_secs(60),
            rate_burst: 10,
            max_concurrent_slots: 4,
            slot_config: OnDemandConfig {
                host: "127.0.0.1".to_owned(),
                port_range: 30000..=60000,
                bind_retries: 64,
                ttl: Duration::from_secs(60),
                max_accepts: 1,
            },
            advertise_host: "stealth.example.com".to_owned(),
            scheme: "obfs4-tcp".to_owned(),
            extra_destinations: Vec::new(),
        };
        let controller =
            Arc::new(RendezvousController::new(policy, target_node_id, target_sk, binder).unwrap());
        {
            let mut weak_slot = dispatcher.rendezvous_weak.lock().unwrap();
            *weak_slot = Some(Arc::downgrade(&controller));
        }
        (dispatcher, controller, tx_registry)
    }

    /// Full end-to-end: signed request → dispatcher → controller → bind
    /// → signed response → wire → client parse + verify.
    #[tokio::test]
    async fn slice8_full_recursive_rendezvous_round_trip() {
        use veil_proto::rendezvous::{
            MIN_POW_DIFFICULTY, RequestEphemeralEndpointPayload, mine_pow_nonce,
            sign_request_ephemeral_endpoint,
        };
        // ── Identities ──────────────────────────────────────────
        let target_sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let target_pk = target_sk.verifying_key().to_bytes();
        let target_node_id = *blake3::hash(&target_pk).as_bytes();

        let requester_sk = SigningKey::from_bytes(&[0x55u8; 32]);
        let requester_pk = requester_sk.verifying_key().to_bytes();
        let requester_node_id = *blake3::hash(&requester_pk).as_bytes();

        // Sender peer_id — represents the "previous-hop" relay through
        // which the recursive query arrived.  Per the reverse-path
        // resolver, the response will be sent back to this peer first.
        let sender_peer_id = [0x77u8; 32];

        // ── Setup ───────────────────────────────────────────────
        let bind_calls: Arc<Mutex<Vec<(String, [u8; 32])>>> = Arc::new(Mutex::new(Vec::new()));
        let (dispatcher, _controller_keepalive, tx_registry) =
            dispatcher_with_rendezvous(target_sk.clone(), target_node_id, Arc::clone(&bind_calls));

        // Register both the sender peer (reverse-path first hop) and the
        // requester (reverse-path final destination) in session_tx_registry.
        let mut sender_rx = {
            let mut reg = tx_registry.write().unwrap();
            reg.register(sender_peer_id)
        };
        let mut requester_rx = {
            let mut reg = tx_registry.write().unwrap();
            reg.register(requester_node_id)
        };

        // ── Build initiator request (Slice 4 + Slice 1) ─────────
        let timestamp_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut draft = RequestEphemeralEndpointPayload {
            target_node_id,
            requester_pubkey: requester_pk,
            timestamp_unix,
            pow_difficulty: MIN_POW_DIFFICULTY,
            pow_nonce: 0,
            requester_sig: [0u8; 64],
        };
        mine_pow_nonce(&mut draft).unwrap();
        let signed = sign_request_ephemeral_endpoint(
            target_node_id,
            requester_pk,
            timestamp_unix,
            MIN_POW_DIFFICULTY,
            draft.pow_nonce,
            &requester_sk,
        );
        let request_bytes = signed.encode().to_vec();

        // Wrap in recursive envelope (Slice 6c).
        let query_id = [0xC0u8; 16];
        let recursive = RecursiveQueryPayload {
            query_id,
            target_key: target_node_id,
            reply_to: requester_node_id,
            ttl: 20,
            query_type: recursive_query_type::RENDEZVOUS_REQUEST,
            reply_port: 0,
            payload: request_bytes,
        };
        let recursive_bytes = recursive.encode();

        // ── Dispatch (Slice 6b arm) ─────────────────────────────
        let result =
            dispatcher.handle_recursive_query(&recursive_bytes, NodeId::from(sender_peer_id));
        assert!(matches!(result, DispatchResult::NoResponse));

        // The dispatcher's arm spawns a tokio task; give it air to
        // run + the controller's permit-watchdog task too.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // ── Reverse-path: sender_peer (priority 0 in the resolver) ─
        // Drain the sender peer's mpsc first — the arm sends to sender
        // before falling to direct/cache.  Once it succeeds at sender,
        // it returns.
        let frame_to_sender = tokio::time::timeout(Duration::from_secs(2), sender_rx.recv())
            .await
            .expect("sender_rx must receive the response within timeout")
            .expect("sender_rx channel closed");

        // requester_rx should NOT have received anything (sender path
        // won).
        assert!(
            requester_rx.try_recv().is_err(),
            "response must route through sender (reverse-path first hop), not direct to requester",
        );

        // ── Decode + verify (Slice 6c client) ───────────────────
        let bytes: &[u8] = frame_to_sender.1.as_ref();
        assert!(
            bytes.len() >= HEADER_SIZE,
            "frame must be at least HEADER_SIZE bytes",
        );
        let hdr = decode_header(&bytes[..HEADER_SIZE]).expect("response frame header must decode");
        assert_eq!(hdr.family, FrameFamily::Routing as u8);
        assert_eq!(hdr.msg_type, RoutingMsg::RecursiveResponse as u16);
        let body = &bytes[HEADER_SIZE..HEADER_SIZE + hdr.body_len as usize];
        let outer =
            RecursiveResponsePayload::decode(body).expect("recursive response body must decode");

        // Outer sig must be by the target's identity.
        assert_eq!(outer.query_id, query_id);
        assert_eq!(outer.responder_pubkey, target_pk);

        // Manual full verify mirroring the Slice 6c client primitive
        // (cannot import veilclient::rendezvous from veilcore —
        // would create a dep cycle).  Steps:
        //   1. query_id echo
        //   2. responder_pubkey == target_pk
        //   3. outer envelope sig verify
        //   4. inner sig + identity + TTL
        assert_eq!(outer.query_id, query_id);
        assert_eq!(outer.responder_pubkey, target_pk);
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let outer_vk = VerifyingKey::from_bytes(&outer.responder_pubkey).unwrap();
        let mut outer_signable = Vec::with_capacity(16 + outer.payload.len());
        outer_signable.extend_from_slice(&outer.query_id);
        outer_signable.extend_from_slice(&outer.payload);
        let outer_sig = Signature::from_bytes(&outer.signature);
        outer_vk
            .verify(&outer_signable, &outer_sig)
            .expect("outer envelope sig must verify under target identity");

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let inner =
            veil_proto::rendezvous::EphemeralEndpointResponsePayload::decode(&outer.payload)
                .expect("inner response must decode");
        veil_proto::rendezvous::verify_ephemeral_endpoint_response(
            &inner,
            &target_pk,
            &requester_pk,
            now_unix,
        )
        .expect("inner response must verify");
        let endpoint = (
            inner.transport_uri.clone(),
            inner.psk,
            inner.valid_until_unix,
        );

        // ── Assert binder captured the same URI + PSK ───────────
        let (recovered_uri, recovered_psk, recovered_valid_until) = endpoint;
        let calls = bind_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "binder must be called exactly once");
        let (recorded_uri, recorded_psk) = &calls[0];
        assert_eq!(*recorded_uri, recovered_uri);
        assert_eq!(*recorded_psk, recovered_psk);
        assert!(
            recovered_uri.starts_with("obfs4-tcp://stealth.example.com:"),
            "URI must use the configured advertise template, got: {recovered_uri}",
        );
        assert!(recovered_valid_until > now_unix);
    }

    /// Misrouted request (target_key ≠ local_node_id) must fall
    /// through to greedy-forwarding without invoking the controller.
    #[tokio::test]
    async fn slice8_misrouted_request_does_not_invoke_controller() {
        use veil_proto::rendezvous::{
            MIN_POW_DIFFICULTY, RequestEphemeralEndpointPayload, mine_pow_nonce,
            sign_request_ephemeral_endpoint,
        };
        let target_sk = SigningKey::from_bytes(&[0xAAu8; 32]);
        let target_pk = target_sk.verifying_key().to_bytes();
        let target_node_id = *blake3::hash(&target_pk).as_bytes();
        let requester_sk = SigningKey::from_bytes(&[0xBBu8; 32]);
        let requester_pk = requester_sk.verifying_key().to_bytes();

        let bind_calls: Arc<Mutex<Vec<(String, [u8; 32])>>> = Arc::new(Mutex::new(Vec::new()));
        let (dispatcher, _ctrl, _tx) =
            dispatcher_with_rendezvous(target_sk, target_node_id, Arc::clone(&bind_calls));

        // Build a request addressed to a DIFFERENT target.
        let other_target = [0xFFu8; 32];
        let timestamp_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut draft = RequestEphemeralEndpointPayload {
            target_node_id: other_target,
            requester_pubkey: requester_pk,
            timestamp_unix,
            pow_difficulty: MIN_POW_DIFFICULTY,
            pow_nonce: 0,
            requester_sig: [0u8; 64],
        };
        mine_pow_nonce(&mut draft).unwrap();
        let signed = sign_request_ephemeral_endpoint(
            other_target,
            requester_pk,
            timestamp_unix,
            MIN_POW_DIFFICULTY,
            draft.pow_nonce,
            &requester_sk,
        );
        let recursive = RecursiveQueryPayload {
            query_id: [0xC0u8; 16],
            target_key: other_target, // NOT us
            reply_to: [0xC1u8; 32],
            ttl: 20,
            query_type: recursive_query_type::RENDEZVOUS_REQUEST,
            reply_port: 0,
            payload: signed.encode().to_vec(),
        };

        let _ = dispatcher.handle_recursive_query(&recursive.encode(), NodeId::from([0xD0u8; 32]));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The binder must NOT have been called — controller's arm
        // only runs when `target_key == local_node_id`.
        let calls = bind_calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            0,
            "misrouted request must not trigger a bind (would fall through to forwarding)",
        );

        // Suppress unused warning.
        let _ = target_pk;
    }

    /// Request to self without a configured controller (rendezvous_weak
    /// resolves to None) must drop silently.  No bind, no response.
    #[tokio::test]
    async fn slice8_no_controller_drops_silently() {
        use veil_proto::rendezvous::{
            MIN_POW_DIFFICULTY, RequestEphemeralEndpointPayload, mine_pow_nonce,
            sign_request_ephemeral_endpoint,
        };
        // Build a dispatcher without attaching the controller.
        let target_sk = SigningKey::from_bytes(&[0xCCu8; 32]);
        let target_pk = target_sk.verifying_key().to_bytes();
        let target_node_id = *blake3::hash(&target_pk).as_bytes();
        let requester_sk = SigningKey::from_bytes(&[0xDDu8; 32]);
        let requester_pk = requester_sk.verifying_key().to_bytes();

        let mut dispatcher = make_test_dispatcher(NodeRole::Core);
        dispatcher.local_node_id = target_node_id;
        let tx_registry = Arc::new(RwLock::new(SessionTxRegistry::new()));
        dispatcher.session_tx_registry = Some(Arc::clone(&tx_registry));
        // NB: rendezvous_weak left at None (no controller installed).

        let mut sender_rx = {
            let mut reg = tx_registry.write().unwrap();
            reg.register([0x55u8; 32])
        };

        let timestamp_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut draft = RequestEphemeralEndpointPayload {
            target_node_id,
            requester_pubkey: requester_pk,
            timestamp_unix,
            pow_difficulty: MIN_POW_DIFFICULTY,
            pow_nonce: 0,
            requester_sig: [0u8; 64],
        };
        mine_pow_nonce(&mut draft).unwrap();
        let signed = sign_request_ephemeral_endpoint(
            target_node_id,
            requester_pk,
            timestamp_unix,
            MIN_POW_DIFFICULTY,
            draft.pow_nonce,
            &requester_sk,
        );
        let recursive = RecursiveQueryPayload {
            query_id: [0xC0u8; 16],
            target_key: target_node_id,
            reply_to: [0xC1u8; 32],
            ttl: 20,
            query_type: recursive_query_type::RENDEZVOUS_REQUEST,
            reply_port: 0,
            payload: signed.encode().to_vec(),
        };
        let _ = dispatcher.handle_recursive_query(&recursive.encode(), NodeId::from([0x55u8; 32]));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            sender_rx.try_recv().is_err(),
            "no-controller path must NOT ship a response",
        );
    }
}
