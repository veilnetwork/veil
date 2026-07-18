use super::{DispatchResult, FrameDispatcher, encode_response};
use veil_cfg::NodeId;
use veil_cfg::NodeRole;
use veil_proto::{
    codec::encode_header,
    control::{
        NatCandidate, NatProbeReplyPayload, NatProbeRequestPayload, NatRelayRequestPayload,
        NeighborOfferPayload, RouteProbePayload, RouteReplyPayload, candidate_type,
    },
    epidemic::EpidemicPayload,
    family::{ControlMsg, FrameFamily, MeshMsg},
    header::FrameHeader,
};
use veil_util::{lock, rlock, wlock};

impl FrameDispatcher {
    pub fn dispatch_control(
        &self,
        header: &FrameHeader,
        body: &[u8],
        node_id: NodeId,
    ) -> DispatchResult {
        let msg = match ControlMsg::try_from(header.msg_type) {
            Ok(m) => m,
            Err(_) => {
                return DispatchResult::Violation(format!(
                    "unknown control msg_type {}",
                    header.msg_type
                ));
            }
        };

        match msg {
            ControlMsg::Ping => {
                // Reply with an empty Pong carrying the same request_id.
                DispatchResult::Response(encode_response(
                    header,
                    FrameFamily::Control as u8,
                    ControlMsg::Pong as u16,
                    &[],
                ))
            }
            ControlMsg::Pong => DispatchResult::NoResponse,

            ControlMsg::NeighborOffer => {
                let payload = match NeighborOfferPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad NeighborOffer: {e}")),
                };
                // Pass the authenticated peer as the contact source so the
                // unverified offer lands in the source-quota'd pending pool.
                self.dht
                    .handle_neighbor_offer(*node_id.as_bytes(), &payload);
                DispatchResult::NoResponse
            }

            ControlMsg::RouteProbe => {
                let payload = match RouteProbePayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad RouteProbe: {e}")),
                };
                let mut reply = self.control_plane.handle_probe(&payload);
                // fill congestion score so the requester can factor
                // our current load into its routing decisions.
                if let Some(cm) = &self.congestion_monitor {
                    reply.congestion = cm.score_u8();
                }
                DispatchResult::Response(encode_response(
                    header,
                    FrameFamily::Control as u8,
                    ControlMsg::RouteReply as u16,
                    &reply.encode(),
                ))
            }

            ControlMsg::RouteReply => {
                let payload = match RouteReplyPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad RouteReply: {e}")),
                };
                self.control_plane
                    .handle_reply(node_id.as_bytes(), &payload);
                // 137.6: A successful reply proves the peer is reachable — refresh
                // route-cache scores for all entries that go via this peer.
                self.update_scores_for_peer(node_id);
                // update local Vivaldi coordinate using the measured RTT
                // and the peer's coordinate (received during handshake, if available).
                if let (Some(local_viv), Some(remote_coord)) = (
                    &self.local_vivaldi,
                    rlock!(self.peer_vivaldi)
                        .get(node_id.as_bytes())
                        .map(|(c, _)| c.clone()),
                ) && payload.rtt_ms > 0
                {
                    // record Vivaldi prediction error before updating coord.
                    let estimate = lock!(local_viv).distance_estimate(&remote_coord);
                    if let Some(m) = &self.metrics {
                        m.record_vivaldi_prediction_error(estimate, payload.rtt_ms);
                    }
                    lock!(local_viv).update(payload.rtt_ms as f64, &remote_coord);
                    // Publish the post-update coord so Prometheus / admin metrics
                    // see every change, not just the moving-average error.
                    if let Some(m) = &self.metrics {
                        {
                            let c = lock!(local_viv);
                            m.record_vivaldi_coord(c.x, c.y, c.height, c.error);
                        };
                    }
                }
                DispatchResult::NoResponse
            }

            ControlMsg::Error => DispatchResult::NoResponse,

            // NAT traversal: any node with an observed-addr table entry acts as
            // a STUN echo server — reply with the observed source address as a
            // server-reflexive (SRFLX) candidate.
            //
            // This intentionally does NOT restrict to Core/Gateway roles: a
            // Relay-role Gateway in an internet-isolated mesh must also be able
            // to respond to NAT_PROBE_REQUEST so that local leaf nodes can
            // discover their external addresses and perform hole-punching
            // without a global Core.
            ControlMsg::NatProbeRequest => {
                let request = match NatProbeRequestPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => {
                        return DispatchResult::Violation(format!("bad NatProbeRequest: {e}"));
                    }
                };

                // relay-mode dispatch. Three cases:
                // 1. target == [0; 32] sentinel → STUN-echo (legacy).
                // 2. target == self_node_id → addressed to us (also
                // STUN-echo in practice — answer locally).
                // 3. target!= self → forward via existing
                // session to that peer. Receiver will respond with
                // `final_target_node_id == request.initiator_node_id`
                // so WE can route the reply back without state.
                let is_relay_target = request.target_node_id != [0u8; 32]
                    && request.target_node_id != self.local_node_id;
                if is_relay_target {
                    //round 7 / : per-peer rate limit on
                    // relay forwards. Without this, a peer firing unique
                    // `query_id`s at line rate gets us to forward each
                    // one outbound — ~2× bandwidth amplification on a
                    // budget Android coordinator. Mirrors the existing
                    // `dht_quota` gate on `RecursiveQuery` forwards
                    // (routing.rs:1733). Drop is silent because the
                    // initiator naturally times out and tries a different
                    // coordinator (graceful degradation, not violation).
                    if !lock!(self.abuse.nat_probe_forward_quota).allow(*node_id.as_bytes()) {
                        self.logger.warn(
                            "nat.probe.forward.rate_limited",
                            format!(
                                "peer={} target={}",
                                veil_util::hex_short(node_id.as_bytes()),
                                veil_util::hex_short(&request.target_node_id),
                            ),
                        );
                        return DispatchResult::NoResponse;
                    }
                    // Forward request unchanged to target. Greedy: only
                    // direct-session forward (no recursive walk yet —
                    // matches the dispatcher's RecursiveQuery direct-
                    // session-first policy). If the target isn't a
                    // session peer, drop the request silently — the
                    // initiator will time out and try a different
                    // coordinator.
                    if let Some(ref reg_arc) = self.session_tx_registry {
                        let guard = wlock!(reg_arc);
                        let frame = build_control_frame(
                            ControlMsg::NatProbeRequest as u16,
                            &request.encode(),
                        );
                        let prio = veil_proto::header::priority::INTERACTIVE;
                        if guard.send_to(&request.target_node_id, prio, frame) {
                            self.logger.info(
                                "nat.probe.forwarded",
                                format!(
                                    "target={} initiator={} session_token=0x{:08x}",
                                    veil_util::hex_short(&request.target_node_id),
                                    veil_util::hex_short(&request.initiator_node_id),
                                    request.session_token,
                                ),
                            );
                        } else {
                            self.logger.warn(
                                "nat.probe.forward_failed",
                                format!(
                                    "no session to target={} for initiator={}",
                                    veil_util::hex_short(&request.target_node_id),
                                    veil_util::hex_short(&request.initiator_node_id),
                                ),
                            );
                        }
                    }
                    return DispatchResult::NoResponse;
                }

                // bug-fix follow-up: srflx echo is ONLY valid
                // in the legacy pure-STUN-echo path (target == [0; 32]).
                // In the relay-forwarded path (target == self_node_id)
                // `peer_id` is the COORDINATOR who forwarded the request
                // — NOT the original initiator. Echoing
                // `peer_observed_addrs[peer_id]` would put the coordinator's
                // IP into the reply as if it were the initiator's srflx
                // and the initiator (Alice) would then incorrectly publish
                // the coordinator's (Charlie's) IP as her own external
                // address. Symmetric: in this branch we know the request
                // was forwarded if `target_node_id == self_node_id` AND
                // `initiator_node_id!= peer_id` (we received it from
                // someone other than the initiator they claim to be).
                let is_pure_stun_echo = request.target_node_id == [0u8; 32];
                // bugfix: in the relay-
                // arrived-at-target branch (target == self_node_id AND
                // initiator!= peer_id), responding with
                // `request.candidates.clone` would echo the INITIATOR's
                // candidates back to themselves — useless to the
                // initiator (they already know those) and contradicts
                // the wire-format doc on `NatProbeReplyPayload.candidates`
                // which is "Responder's ICE candidates". The initiator
                // needs OUR host candidates so they can punch / dial the
                // addresses we actually listen on. Pure-STUN-echo path
                // (target == [0; 32]) keeps the legacy semantics: echo
                // back what we received + add our srflx observation, so
                // the initiator can compare "what I sent" vs "what you
                // saw" and learn its NAT mapping.
                let mut candidates = if is_pure_stun_echo {
                    request.candidates.clone()
                } else {
                    crate::build_own_host_candidates(
                        &self
                            .listen_transports
                            .read()
                            .unwrap_or_else(|p| p.into_inner()),
                    )
                };
                if is_pure_stun_echo {
                    // RFC 8445 §5.1.2 srflx priority: type_pref=100
                    // local_pref=65535, component=1. Echo what we observed
                    // for the immediate sender (= the initiator on this
                    // pure-STUN path; they came directly to us).
                    const SRFLX_PRIORITY: u32 = 1_694_498_815;
                    let observed = rlock!(self.peer_observed_addrs)
                        .get(node_id.as_bytes())
                        .copied();
                    if let Some(addr) = observed {
                        use std::net::SocketAddr;
                        let srflx = match addr {
                            SocketAddr::V4(v4) => NatCandidate {
                                atyp: 4,
                                candidate_type: candidate_type::SRFLX,
                                priority: SRFLX_PRIORITY,
                                addr: v4.ip().octets().to_vec(),
                                port: v4.port(),
                            },
                            SocketAddr::V6(v6) => NatCandidate {
                                atyp: 6,
                                candidate_type: candidate_type::SRFLX,
                                priority: SRFLX_PRIORITY,
                                addr: v6.ip().octets().to_vec(),
                                port: v6.port(),
                            },
                        };
                        candidates.push(srflx);
                    }
                }
                // Set `final_target_node_id` to the initiator IFF the
                // request was relay-forwarded (target == self AND
                // initiator!= immediate sender). In the pure-STUN-echo
                // path keep `[0; 32]` so the legacy reply path (direct
                // response to sender + listen-transport srflx update on
                // the initiator side) keeps working unchanged.
                let final_target_node_id = if request.target_node_id == self.local_node_id
                    && &request.initiator_node_id != node_id.as_bytes()
                {
                    request.initiator_node_id
                } else {
                    [0u8; 32]
                };
                let reply = NatProbeReplyPayload {
                    responder_node_id: self.local_node_id,
                    final_target_node_id,
                    session_token: request.session_token,
                    candidates,
                };
                DispatchResult::Response(encode_response(
                    header,
                    FrameFamily::Control as u8,
                    ControlMsg::NatProbeReply as u16,
                    &reply.encode(),
                ))
            }

            // NatProbeReply is consumed by the NatCoordinator out-of-band.
            // Additionally, if the reply carries a server-reflexive (srflx)
            // candidate, we update any wildcard listen transports so peers
            // in RouteResponse receive a routable address.
            //
            // relay-mode reply forwarding. When
            // `final_target_node_id!= [0; 32]` AND it isn't us, we are
            // the coordinator that originally forwarded the request —
            // send the reply on to the initiator over an existing
            // session. Stateless: the reply carries its own destination.
            ControlMsg::NatProbeReply => {
                if let Ok(reply) = NatProbeReplyPayload::decode(body) {
                    use veil_nat::discovery::candidate_to_socket_addr;
                    use veil_proto::control::candidate_type;

                    // Step 1: relay-forward if not addressed to us.
                    let is_relay_target = reply.final_target_node_id != [0u8; 32]
                        && reply.final_target_node_id != self.local_node_id;
                    if is_relay_target {
                        //round 7 / : per-peer rate limit
                        // on reply-relay forwards. Symmetric with the
                        // request-side gate above — closes the second
                        // half of the amplification surface (every
                        // request that gets through generates a reply
                        // that we'd also have to forward). Same drop-
                        // silently semantics as the request side.
                        if !lock!(self.abuse.nat_probe_forward_quota).allow(*node_id.as_bytes()) {
                            self.logger.warn(
                                "nat.probe.reply_forward.rate_limited",
                                format!(
                                    "peer={} to_initiator={}",
                                    veil_util::hex_short(node_id.as_bytes()),
                                    veil_util::hex_short(&reply.final_target_node_id),
                                ),
                            );
                            return DispatchResult::NoResponse;
                        }
                        if let Some(ref reg_arc) = self.session_tx_registry {
                            let guard = wlock!(reg_arc);
                            let frame = build_control_frame(
                                ControlMsg::NatProbeReply as u16,
                                &reply.encode(),
                            );
                            let prio = veil_proto::header::priority::INTERACTIVE;
                            if guard.send_to(&reply.final_target_node_id, prio, frame) {
                                self.logger.info(
                                    "nat.probe.reply_forwarded",
                                    format!(
                                        "to_initiator={} responder={} session_token=0x{:08x}",
                                        veil_util::hex_short(&reply.final_target_node_id),
                                        veil_util::hex_short(&reply.responder_node_id),
                                        reply.session_token,
                                    ),
                                );
                            } else {
                                self.logger.warn(
                                    "nat.probe.reply_forward_failed",
                                    format!(
                                        "no session to initiator={} (responder={})",
                                        veil_util::hex_short(&reply.final_target_node_id),
                                        veil_util::hex_short(&reply.responder_node_id),
                                    ),
                                );
                            }
                        }
                        return DispatchResult::NoResponse;
                    }

                    // Step 2: addressed to us — wake any pending NAT-traversal
                    // waiter.
                    {
                        let mut waiters = lock!(self.nat_probe_waiters);
                        if let Some(tx) = waiters.remove(&reply.session_token) {
                            let _ = tx.send(reply.clone());
                        }
                    }

                    // Step 3: update wildcard listen transports IFF this is
                    // a legacy direct STUN-echo response (final_target ==
                    // [0; 32]) AND the responder is the immediate sender.
                    //
                    // bug-fix follow-up: in the relay-forwarded
                    // path the candidates belong to the RESPONDER (Bob)
                    // not to us (Alice). Bob's srflx is Bob's external IP;
                    // updating our listen transports with that would publish
                    // Bob's IP as our own — an obvious wire-level bug that
                    // would land in production unless caught here. The
                    // original STUN-echo semantics hold only when peer_id
                    // (immediate sender) == reply.responder_node_id (the
                    // peer who actually observed our srflx and echoed it
                    // back); in the relay path peer_id is the coordinator
                    // and responder is the target, distinct identities.
                    let is_direct_stun_echo = reply.final_target_node_id == [0u8; 32]
                        && node_id.as_bytes() == &reply.responder_node_id;
                    if is_direct_stun_echo {
                        for candidate in &reply.candidates {
                            if candidate.candidate_type != candidate_type::SRFLX {
                                continue;
                            }
                            if let Some(addr) = candidate_to_socket_addr(candidate) {
                                let ip = addr.ip();
                                if !ip.is_loopback() && !ip.is_unspecified() {
                                    self.update_wildcard_listen_addr(ip);
                                    // real-P2P Stage B: `listen_transports`
                                    // excludes wildcard binds entirely (PEX
                                    // hygiene), so ALSO record the raw srflx
                                    // observation in its own slot — the
                                    // direct-endpoint exchange mines it for
                                    // the external-address candidate.
                                    self.record_own_external_addr(addr);
                                    break;
                                }
                            }
                        }
                    }
                }
                DispatchResult::NoResponse
            }

            // NAT relay: core registers the tunnel and acks with an empty NatProbeReply.
            ControlMsg::NatRelayRequest => {
                // Only Core and Gateway nodes should relay NAT traffic.
                if !matches!(self.role, NodeRole::Core) {
                    return DispatchResult::NoResponse;
                }
                let request = match NatRelayRequestPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => {
                        return DispatchResult::Violation(format!("bad NatRelayRequest: {e}"));
                    }
                };
                // tighten session-identity check.
                //
                // The puncher protocol designates `node_a` as the initiator —
                // it is the side that asked the coordinator to relay traffic
                // toward `node_b`. The previous check (`peer_id ∈ {a, b}`)
                // was too permissive: any authenticated peer that knew of
                // a tuple `(A, B)` could register itself as `node_b` and
                // claim a relay tunnel to the unrelated `A` *without `A`'s
                // consent*. This let an attacker burn a victim's relay
                // accounting (`MAX_RELAY_TUNNELS`) and coupling A to spoofed
                // tokens / cleanup races.
                //
                // Strict rule: `peer_id == request.node_a`. This binds
                // tunnel ownership to the session-authenticated initiator
                // and rejects spoofed counter-party registrations.
                if node_id.as_bytes() != &request.node_a {
                    return DispatchResult::Violation(
                        "NatRelayRequest: sender is not the tunnel initiator (node_a)".to_owned(),
                    );
                }
                // Register relay tunnel so delivery-forward accounting can track it.
                {
                    use veil_proto::budget::MAX_RELAY_TUNNELS;
                    // A3: per-initiator cap inside the global one.
                    // `MAX_RELAY_TUNNELS` (typically a few hundred) caps the
                    // table overall, but a single hostile `node_a` could fill
                    // it alone by issuing N requests with distinct session
                    // tokens — locking out every other peer's relay needs.
                    // Cap each initiator's share at 1/16 of the table (≥ 4)
                    // so even a worst-case Sybil farm is bounded.
                    const MAX_RELAY_TUNNELS_PER_INITIATOR: usize = 16;
                    let mut tunnels = lock!(self.relay_tunnels);
                    if tunnels.len() >= MAX_RELAY_TUNNELS {
                        return DispatchResult::Violation(
                            "NatRelayRequest: relay tunnel table full".to_owned(),
                        );
                    }
                    let initiator_count = tunnels
                        .values()
                        .filter(|(a, _)| a == &request.node_a)
                        .count();
                    if initiator_count >= MAX_RELAY_TUNNELS_PER_INITIATOR {
                        return DispatchResult::Violation(
                            "NatRelayRequest: per-initiator relay tunnel cap reached".to_owned(),
                        );
                    }
                    tunnels.insert(request.session_token, (request.node_a, request.node_b));
                }
                // Ack with an empty NatProbeReply carrying the session_token.
                let ack = NatProbeReplyPayload {
                    responder_node_id: self.local_node_id,
                    final_target_node_id: [0u8; 32],
                    session_token: request.session_token,
                    candidates: vec![],
                };
                DispatchResult::Response(encode_response(
                    header,
                    FrameFamily::Control as u8,
                    ControlMsg::NatProbeReply as u16,
                    &ack.encode(),
                ))
            }

            // OVL1-level keepalive. Reply immediately with KeepaliveAck.
            // Keepalive/ack frames are REALTIME class (lowest queue latency).
            ControlMsg::Keepalive => {
                let mut hdr =
                    FrameHeader::new(FrameFamily::Control as u8, ControlMsg::KeepaliveAck as u16);
                hdr.body_len = 0;
                hdr.set_priority(veil_proto::header::TrafficClass::RealTime as u8);
                DispatchResult::Response(encode_header(&hdr).to_vec())
            }

            // KeepaliveAck — the runner updates last_rx on frame receipt;
            // nothing further is required at the dispatcher level.
            ControlMsg::KeepaliveAck => DispatchResult::NoResponse,

            // epidemic flood broadcast.
            // congestion backpressure signal.
            // The peer is overloaded and asks us to slow down / redistribute.
            // We mark this peer as congested so the weighted route selection
            // naturally shifts traffic to alternative hops.
            ControlMsg::Backpressure => {
                lock!(self.control_plane.rtt_table()).apply_backpressure(*node_id.as_bytes());
                if let Some(m) = &self.metrics {
                    m.inc_backpressure_received();
                }
                // j: demoted to DEBUG. Backpressure signals fire
                // every congestion window adjustment under heavy load; aggregate
                // visibility via `veil_backpressure_received_total` counter.
                self.logger.debug(
                    "session.backpressure_received",
                    format!(
                        "peer_id={} — marking congested, redistributing traffic",
                        veil_util::hex_short(node_id.as_bytes()),
                    ),
                );
                DispatchResult::NoResponse
            }

            ControlMsg::EpidemicBroadcast => {
                let ep = match EpidemicPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => {
                        return DispatchResult::Violation(format!("bad EpidemicBroadcast: {e}"));
                    }
                };
                // Enforce configured max payload size.
                if ep.payload.len() > self.epidemic_max_payload {
                    return DispatchResult::Violation(format!(
                        "EpidemicBroadcast payload too large: {} > {}",
                        ep.payload.len(),
                        self.epidemic_max_payload,
                    ));
                }
                // Dedup: if already seen, drop silently.
                if lock!(self.epidemic_seen).check_and_insert(ep.msg_id) {
                    return DispatchResult::NoResponse;
                }
                // Deliver to all locally registered app endpoints.
                self.app_registry
                    .broadcast_epidemic(ep.origin, ep.payload.clone());
                // Forward to K random neighbours (excluding the sender) if ttl > 0.
                if ep.ttl > 0
                    && let Some(ref reg_arc) = self.session_tx_registry
                {
                    use rand_core::{OsRng, RngCore};
                    let forward_ep = EpidemicPayload {
                        msg_id: ep.msg_id,
                        ttl: ep.ttl - 1,
                        origin: ep.origin,
                        payload: ep.payload,
                    };
                    let fwd_body = forward_ep.encode();
                    let mut fwd_hdr = FrameHeader::new(
                        FrameFamily::Control as u8,
                        ControlMsg::EpidemicBroadcast as u16,
                    );
                    fwd_hdr.body_len = fwd_body.len() as u32;
                    fwd_hdr.set_priority(veil_proto::priority::BACKGROUND);
                    let mut fwd_frame =
                        Vec::with_capacity(veil_proto::header::HEADER_SIZE + fwd_body.len());
                    fwd_frame.extend_from_slice(&encode_header(&fwd_hdr));
                    fwd_frame.extend_from_slice(&fwd_body);
                    // Single shared frame across all K sends.
                    let fwd_arc = veil_bufpool::pooled_shared_from_vec(fwd_frame);

                    let mut peers = wlock!(reg_arc).peer_ids();
                    peers.retain(|id| id != node_id.as_bytes());
                    // reduce fan-out under congestion.
                    let effective_fanout = if let Some(ref cm) = self.congestion_monitor
                        && cm.score_u8() > 128
                    {
                        // Halve fan-out when >50% congested; minimum 1.
                        (self.epidemic_fanout / 2).max(1)
                    } else {
                        self.epidemic_fanout
                    };
                    let k = effective_fanout.min(peers.len());
                    if k > 0 {
                        for i in 0..k {
                            let j = i + (OsRng.next_u64() as usize % (peers.len() - i));
                            peers.swap(i, j);
                        }
                        let reg = wlock!(reg_arc);
                        for hop in &peers[..k] {
                            if let Some(tx) = reg.get_sender(hop) {
                                let _ = tx
                                    .try_send((veil_proto::priority::BACKGROUND, fwd_arc.clone()));
                            }
                        }
                    }
                }
                DispatchResult::NoResponse
            }
        }
    }

    pub fn dispatch_mesh(
        &self,
        _header: &FrameHeader,
        body: &[u8],
        _node_id: NodeId,
    ) -> DispatchResult {
        let msg = match MeshMsg::try_from(_header.msg_type) {
            Ok(m) => m,
            Err(_) => {
                return DispatchResult::Violation(format!(
                    "unknown mesh msg_type {}",
                    _header.msg_type
                ));
            }
        };

        match msg {
            MeshMsg::Forward => {
                let frame = match veil_proto::mesh::MeshFrame::decode(body) {
                    Ok(f) => f,
                    Err(e) => return DispatchResult::Violation(format!("bad MeshFrame: {e}")),
                };
                // Drop broadcast frames that originated from this node — they have
                // looped back through a neighbour and re-forwarding would cycle.
                if frame.is_broadcast() && frame.src_node_id == self.mesh_forwarder.local_id() {
                    return DispatchResult::NoResponse;
                }
                let cache = wlock!(self.route_cache);
                let (result, _out) = self.mesh_forwarder.forward_with_cache(&frame, &*cache);
                if let veil_mesh::ForwardResult::Forwarded { hops } = result
                    && let Some(m) = &self.metrics
                {
                    m.inc_mesh_relay_hops();
                    let _ = hops; // hops > 1 accounted per-frame
                }
                DispatchResult::NoResponse
            }
            MeshMsg::Beacon | MeshMsg::Ack => DispatchResult::NoResponse,
        }
    }
}

/// build a fresh Control-family frame (header + body) for
/// forwarding NAT probe / reply payloads to a peer that isn't the
/// original sender. Distinct from `encode_response` (which echoes the
/// trigger frame's request_id/stream_id for reply correlation): a
/// forwarded frame is a new outbound message addressed to a different
/// peer, so it gets fresh ids. The session_token in the body is what
/// the recipient correlates against — header ids are not used by the
/// NAT-traversal protocol.
pub fn build_control_frame(msg_type: u16, body: &[u8]) -> Vec<u8> {
    use veil_proto::header::HEADER_SIZE;
    let mut hdr = FrameHeader::new(FrameFamily::Control as u8, msg_type);
    hdr.body_len = body.len() as u32;
    let mut out = Vec::with_capacity(HEADER_SIZE + body.len());
    out.extend_from_slice(&encode_header(&hdr));
    out.extend_from_slice(body);
    out
}
