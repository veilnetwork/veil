//! Getting a session through a NAT, and what to try when it will not go.
//!
//! An ordered list of attempts, and the ORDER is the content: each step costs
//! more, or gives away more, than the one before it.
//!
//!  * ask a connected peer to coordinate, and punch — cheap, and nothing
//!    outside the two nodes learns anything;
//!  * the same with a punch token, when the coordinator wants one;
//!  * promote whatever URIs the punch produced into dialable ones;
//!  * fall back to relaying through a peer — works, and the relay now knows
//!    two nodes are talking;
//!  * fall back to SOCKS — works, and an operator outside the network is in
//!    the path.
//!
//! Keeping them in one file is what keeps that order visible. Spread across a
//! six-thousand-line module, the fallbacks read as alternatives rather than as
//! a descent, and the cheapest step is the one a reader has to go looking for.
//!
//! [`NodeServices::available_udp_reflectors`] sits here because it answers the
//! question the first step asks: who can tell us what address our packets
//! arrive from. The serving half of that is `nat_traversal.rs`.
//!
//! Moved verbatim out of `node_services.rs` (report24 RUNTIME-3); the same
//! inherent methods on the same type.

use std::sync::Arc;

use super::*;

impl NodeServices {
    /// try NAT traversal toward `target_node_id`
    /// using ANY currently-connected peer as the signaling coordinator.
    /// See `NodeRuntime::try_nat_traversal` for the full doc-comment;
    /// the actual logic lives here on `NodeServices` so the
    /// auto-trigger path (`nat_fallback_dial`) can call it directly
    /// without going through a public-API forwarder.
    pub async fn try_nat_traversal(
        &self,
        target_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        per_coordinator_timeout: std::time::Duration,
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        self.try_nat_traversal_with_punch_token(
            target_node_id,
            local_candidates,
            per_coordinator_timeout,
            None,
        )
        .await
    }

    pub(crate) async fn try_nat_traversal_with_punch_token(
        &self,
        target_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        per_coordinator_timeout: std::time::Duration,
        punch_token: Option<[u8; 16]>,
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        let local_node_id = *self.identity.local_identity.node_id.as_bytes();
        let mut candidates: Vec<[u8; 32]> = rlock!(self.session_tx_registry)
            .peer_ids()
            .into_iter()
            .filter(|p| *p != local_node_id && *p != target_node_id)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        candidates.sort_by_key(|pid| {
            let mut xor = [0u8; 32];
            for i in 0..32 {
                xor[i] = pid[i] ^ target_node_id[i];
            }
            xor
        });
        const MAX_COORDINATOR_ATTEMPTS: usize = 4;
        // Give up on a target that will not answer. See `nat_probe_backoff`
        // for what this cost in production before it existed.
        if !lock!(self.nat_probe_backoff).allow(target_node_id) {
            self.logger.debug(
                "nat.probe.backoff",
                format!(
                    "target {} is in probe back-off — not asking any coordinator",
                    veil_util::hex_short(&target_node_id),
                ),
            );
            return None;
        }

        for coordinator in candidates.into_iter().take(MAX_COORDINATOR_ATTEMPTS) {
            if let Some(reply) = self
                .attempt_nat_traversal_via_with_punch_token(
                    target_node_id,
                    coordinator,
                    local_candidates.clone(),
                    per_coordinator_timeout,
                    punch_token,
                )
                .await
            {
                // Mixed-version resilience: a coordinator built before the
                // punch-token wire extension decodes-then-re-encodes the
                // frames and strips the token in flight, so the reply comes
                // back without it. Such a reply cannot authenticate a punch —
                // it must not poison the whole attempt while a newer
                // coordinator later in the ladder would preserve the token.
                if punch_token.is_some() && reply.punch_token != punch_token {
                    self.logger.debug(
                        "nat.udp_punch.signaling_no_token",
                        format!(
                            "reply via coordinator {} lacks our punch token \
                             (coordinator or peer build too old?) — trying next",
                            veil_util::hex_short(&coordinator),
                        ),
                    );
                    continue;
                }
                return Some(reply);
            }
        }
        None
    }

    /// signaling driver — see `NodeRuntime::attempt_nat_traversal_via`.
    pub async fn attempt_nat_traversal_via(
        &self,
        target_node_id: [u8; 32],
        coordinator_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        timeout: std::time::Duration,
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        self.attempt_nat_traversal_via_with_punch_token(
            target_node_id,
            coordinator_node_id,
            local_candidates,
            timeout,
            None,
        )
        .await
    }

    pub(crate) async fn attempt_nat_traversal_via_with_punch_token(
        &self,
        target_node_id: [u8; 32],
        coordinator_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        timeout: std::time::Duration,
        punch_token: Option<[u8; 16]>,
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        use veil_proto::codec::encode_header;
        use veil_proto::control::NatProbeRequestPayload;
        use veil_proto::family::{ControlMsg, FrameFamily};
        use veil_proto::header::{FrameHeader, HEADER_SIZE};

        let local_node_id = *self.identity.local_identity.node_id.as_bytes();

        let (tx, rx) = tokio::sync::oneshot::channel::<veil_proto::control::NatProbeReplyPayload>();
        // oncurrency-allocate a session_token
        // that does not collide with any in-flight waiter. Without
        // this, two concurrent NAT-probe requests landing on the same
        // u32 random value silently overwrite each other in
        // `nat_probe_waiters` — the prior requester's `tx` is dropped
        // and they time out without diagnostic. Birthday-bound at
        // u32 means ~65K concurrent waiters before 50% collision risk;
        // production-class relays can hit that under sustained load.
        // The retry loop is bounded — at MAX_NAT_PROBE_WAITERS we
        // refuse the request rather than spin forever.
        let session_token: u32 = {
            use rand_core::RngCore;
            use veil_proto::budget::MAX_NAT_PROBE_WAITERS;
            let mut waiters = lock!(self.dispatcher.nat_probe_waiters);
            waiters.retain(|_, sender| !sender.is_closed());
            if waiters.len() >= MAX_NAT_PROBE_WAITERS {
                return None;
            }
            // Try a random value; on the off chance of a collision
            // re-roll up to MAX_NAT_PROBE_WAITERS times (the cap above
            // means at least one slot is free, so we WILL find one).
            let mut tok = rand_core::OsRng.next_u32();
            for _ in 0..MAX_NAT_PROBE_WAITERS {
                if !waiters.contains_key(&tok) {
                    break;
                }
                tok = rand_core::OsRng.next_u32();
            }
            waiters.insert(tok, tx);
            tok
        };

        let request = NatProbeRequestPayload {
            initiator_node_id: local_node_id,
            target_node_id,
            session_token,
            punch_token,
            candidates: local_candidates,
        };
        let body = request.encode();
        let mut hdr = FrameHeader::new(
            FrameFamily::Control as u8,
            ControlMsg::NatProbeRequest as u16,
        );
        hdr.body_len = body.len() as u32;
        let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
        frame.extend_from_slice(&encode_header(&hdr));
        frame.extend_from_slice(&body);

        {
            let guard = rlock!(self.session_tx_registry);
            if !guard.send_to(
                &coordinator_node_id,
                veil_proto::header::priority::INTERACTIVE,
                frame,
            ) {
                lock!(self.dispatcher.nat_probe_waiters).remove(&session_token);
                return None;
            }
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(reply)) => Some(reply),
            _ => {
                lock!(self.dispatcher.nat_probe_waiters).remove(&session_token);
                None
            }
        }
    }

    /// Collect live reflector announcements from authenticated direct peers,
    /// nearest to the intended destination first. Static config entries are
    /// appended only as a backward-compatible fallback. A peer's own endpoint
    /// is bound to its transport IP; transitively shared endpoints are numeric,
    /// public-only and bounded before they enter this map.
    pub(crate) fn available_udp_reflectors(
        &self,
        target_node_id: [u8; 32],
        configured: &[String],
    ) -> Vec<std::net::SocketAddr> {
        let mut announced = rlock!(self.dispatcher.peer_udp_reflectors)
            .iter()
            .map(|(node_id, endpoints)| (*node_id, endpoints.clone()))
            .collect::<Vec<_>>();
        announced.sort_by_key(|(node_id, _)| {
            let mut distance = [0u8; 32];
            for i in 0..32 {
                distance[i] = node_id[i] ^ target_node_id[i];
            }
            distance
        });

        let mut out = Vec::with_capacity(8);
        // Round-robin across independent announcers before accepting a second
        // endpoint from one peer, so one connected peer cannot eclipse every
        // other live reflector by filling the eight-entry fan-out.
        for index in 0..4 {
            for (_, endpoints) in &announced {
                let Some(endpoint) = endpoints.get(index).copied() else {
                    continue;
                };
                if !out.contains(&endpoint) {
                    out.push(endpoint);
                }
                if out.len() == 8 {
                    return out;
                }
            }
        }
        for endpoint in configured
            .iter()
            .filter_map(|value| value.parse::<std::net::SocketAddr>().ok())
        {
            if !out.contains(&endpoint) {
                out.push(endpoint);
            }
            if out.len() == 8 {
                break;
            }
        }
        out
    }

    /// signaling + URI promotion — see
    /// `NodeRuntime::try_nat_traversal_promote_uris`.
    pub async fn try_nat_traversal_promote_uris(
        &self,
        target_node_id: [u8; 32],
        template_uri: &veil_transport::TransportUri,
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        per_coordinator_timeout: std::time::Duration,
    ) -> Vec<veil_transport::TransportUri> {
        let Some(reply) = self
            .try_nat_traversal(target_node_id, local_candidates, per_coordinator_timeout)
            .await
        else {
            return Vec::new();
        };
        let mut sorted = reply.candidates;
        sorted.sort_by_key(|c| std::cmp::Reverse(c.priority));
        sorted
            .iter()
            .filter_map(|c| nat_candidate_to_transport_uri(c, template_uri))
            .collect()
    }

    /// drive NAT-traversal signaling on the
    /// initiator side and try each promoted candidate URI as a real
    /// transport dial. Returns `Some(connection)` on the first
    /// success, `None` if signaling fails or every candidate fails to
    /// dial. Cheap-bail conditions (no connected peers / unsupported
    /// URI variant) are checked before signaling so we don't waste a
    /// 5-second round-trip on a doomed attempt.
    ///
    /// Why this lives in `NodeServices` and not inline in
    /// `connect_peer_with_state`:
    /// * Encapsulates the policy (timeout, candidate cap
    ///   coordinator-availability check) in one place so it's
    ///   reviewable + tunable independently of the dial state
    ///   machine.
    /// * Lets future tests stub it out via the runtime's existing
    ///   debug accessors if needed.
    ///
    /// Per-attempt timeout: signaling is bounded at 3s (
    /// auto-coordinator default); each candidate dial is bounded
    /// implicitly by the registry's own connect timeout — we don't
    /// add a second layer. Total worst-case latency for the
    /// fallback path is ~3s + (N candidates × per-dial timeout)
    /// which sits inside the outbound-connector's exponential-
    /// backoff loop without blowing past its `backoff_max`.
    ///
    /// Candidate cap: at most 4 promoted URIs are attempted, in RFC
    /// 8445 priority order (host → srflx → relay). Without a cap a
    /// peer that advertises 50 host candidates (e.g., a server with
    /// many interfaces) would burn the full backoff window on
    /// fallback attempts and starve the next real backoff cycle.
    async fn udp_hole_punch_dial(
        &self,
        target_node_id: [u8; 32],
        peer_ctx: Arc<veil_transport::TransportContext>,
    ) -> Option<Box<dyn TransportConnection>> {
        let config = veil_cfg::load_config(&self.config_path).ok()?;
        let budget = std::time::Duration::from_millis(config.nat.punch_timeout_ms);
        if budget.is_zero() {
            return None;
        }
        self.udp_hole_punch_dial_stages(target_node_id, peer_ctx, &config, budget)
            .await
            .ok()
    }

    /// Staged core of the initiator-side UDP hole punch. Same orchestration
    /// as the historical `udp_hole_punch_dial`, but every early exit names
    /// the stage that ended the attempt so the explicit call-path API
    /// (`attempt_p2p_hole_punch`) can surface a structured outcome instead
    /// of a bare miss. Strict stage order: reflector selection → mapping
    /// discovery → coordinator signaling (candidate + one-time punch token)
    /// → simultaneous punch → same-socket QUIC promotion.
    async fn udp_hole_punch_dial_stages(
        &self,
        target_node_id: [u8; 32],
        peer_ctx: Arc<veil_transport::TransportContext>,
        config: &veil_cfg::Config,
        budget: std::time::Duration,
    ) -> std::result::Result<Box<dyn TransportConnection>, HolePunchDialFailure> {
        if !config.nat.enabled {
            return Err(HolePunchDialFailure::NoReflector);
        }
        let mut reflectors =
            self.available_udp_reflectors(target_node_id, &config.nat.udp_reflectors);
        let Some(first_reflector) = reflectors.first().copied() else {
            return Err(HolePunchDialFailure::NoReflector);
        };
        reflectors.retain(|value| value.is_ipv4() == first_reflector.is_ipv4());
        if budget.is_zero() {
            return Err(HolePunchDialFailure::PunchTimeout);
        }
        let deadline = tokio::time::Instant::now() + budget;
        let bind_addr = match first_reflector {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };
        let socket = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .map_err(|_| HolePunchDialFailure::MappingUnusable)?;
        veil_util::outbound_interface::configure_outbound_socket(
            &socket,
            if first_reflector.is_ipv4() {
                veil_util::outbound_interface::SocketFamilies::V4
            } else {
                veil_util::outbound_interface::SocketFamilies::V6
            },
        )
        .map_err(|_| HolePunchDialFailure::MappingUnusable)?;
        let (discovery_token, punch_token) = {
            use rand_core::RngCore;
            let mut discovery = [0u8; 16];
            let mut punch = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut discovery);
            rand_core::OsRng.fill_bytes(&mut punch);
            (discovery, punch)
        };
        let discovery_timeout = budget.min(std::time::Duration::from_millis(500));
        let mapping = veil_nat::discover_udp_mapping_any_for_punch(
            &socket,
            &reflectors,
            discovery_token,
            discovery_timeout,
        )
        .await
        // An I/O error here means no reflector was even sendable — a
        // reflector-availability failure, not a mapping verdict.
        .map_err(|_| HolePunchDialFailure::NoReflector)?;
        let Some((mapping, _)) = mapping else {
            self.logger.debug(
                "nat.udp_punch.discovery_unusable",
                "no non-hairpin UDP mapping from peer-announced reflectors",
            );
            return Err(HolePunchDialFailure::MappingUnusable);
        };
        let mut candidate = veil_nat::socket_addr_to_candidate(mapping);
        candidate.candidate_type = veil_proto::control::candidate_type::SRFLX;
        candidate.priority = 1_694_498_815;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(HolePunchDialFailure::SignalingTimeout);
        }
        let signaling_timeout = remaining.min(std::time::Duration::from_millis(1_500));
        let reply = self
            .try_nat_traversal_with_punch_token(
                target_node_id,
                vec![candidate],
                signaling_timeout,
                Some(punch_token),
            )
            .await
            .ok_or(HolePunchDialFailure::SignalingTimeout)?;
        if reply.punch_token != Some(punch_token) {
            // Reply came back without our one-time token — an older peer
            // build that cannot run the punch responder. Signaling-stage
            // failure; the log carries the precise cause.
            self.logger.debug(
                "nat.udp_punch.signaling_no_token",
                "NAT probe reply lacks our punch token (peer build too old?)",
            );
            return Err(HolePunchDialFailure::SignalingTimeout);
        }
        let candidates = reply
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.candidate_type == veil_proto::control::candidate_type::SRFLX
            })
            .filter_map(veil_nat::candidate_to_socket_addr)
            .filter(|candidate| veil_nat::is_public_punch_addr(*candidate))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            // The peer answered but could not offer any public
            // server-reflexive candidate — its mapping is unusable, so a
            // punch can never converge. Distinct from our own mapping
            // failure only in the log line.
            self.logger.debug(
                "nat.udp_punch.peer_mapping_unusable",
                "peer reply carried no public srflx candidate",
            );
            return Err(HolePunchDialFailure::MappingUnusable);
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        // Reserve up to 750 ms (and at least half this remaining slice) for
        // QUIC so a doomed punch cannot consume the entire direct-path budget.
        let quic_reserve = (remaining / 2).min(std::time::Duration::from_millis(750));
        let punch_timeout = remaining.saturating_sub(quic_reserve);
        if punch_timeout.is_zero() {
            return Err(HolePunchDialFailure::PunchTimeout);
        }
        // The punch is bound to this node's veil, so a peer on a different
        // deployment cannot converge with us and be promoted into a session.
        let network_tag = veil_nat::network_tag(self.transport_ctx.obfs4_psk.as_deref());
        let punched = veil_nat::punch_udp(
            &socket,
            &candidates,
            punch_token,
            &network_tag,
            punch_timeout,
        )
        .await
        .unwrap_or_default();
        if punched.peer.is_none() && punched.foreign_tokens > 0 {
            // A cross-veil punch fails by timing out, exactly like a NAT that
            // never opened. Say which one it was.
            self.logger.debug(
                "nat.udp_punch.foreign_network",
                format!(
                    "{} punch packet(s) carried a token from another veil",
                    punched.foreign_tokens
                ),
            );
        }
        let peer = punched.peer.ok_or(HolePunchDialFailure::PunchTimeout)?;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(HolePunchDialFailure::PunchTimeout);
        }
        let promoted = tokio::time::timeout(
            remaining,
            veil_transport::promote_punched_quic(
                socket,
                peer,
                peer_ctx,
                veil_transport::PunchedQuicRole::Initiator,
            ),
        )
        .await;
        match promoted {
            Ok(Ok(connection)) => {
                self.logger.info(
                    "nat.udp_punch.connected",
                    format!(
                        "peer={} role=initiator",
                        veil_util::hex_short(&target_node_id)
                    ),
                );
                Ok(connection)
            }
            Ok(Err(error)) => {
                self.logger
                    .warn("nat.udp_punch.quic_failed", error.to_string());
                Err(HolePunchDialFailure::QuicFailed)
            }
            Err(_) => {
                self.logger.warn(
                    "nat.udp_punch.quic_failed",
                    "overall NAT traversal deadline elapsed",
                );
                Err(HolePunchDialFailure::QuicFailed)
            }
        }
    }

    /// Explicit, bounded call-path hole-punch attempt toward a registered
    /// peer (real-P2P epic, Stage B; exposed over IPC as
    /// `LocalAppMsg::AttemptHolePunch`).
    ///
    /// Contract (mirrors [`veil_ipc::HolePunchDriver`]):
    /// * **Anonymity posture never enters this path** — a node booted with
    ///   `[anonymity].onion_service` refuses immediately
    ///   ([`veil_ipc::HolePunchOutcome::RefusedAnonymous`]) before any
    ///   socket, reflector, or signaling side effect.
    /// * **Idempotent** — an existing live direct session short-circuits to
    ///   `Connected` without network work; a repeat call after a successful
    ///   punch takes the same short-circuit.
    /// * **Single-flight per peer** — a call that finds an attempt already
    ///   in flight subscribes to its outcome instead of racing a second
    ///   socket/punch toward the same peer.
    /// * **One shared budget** ([`veil_proto::budget::
    ///   HOLE_PUNCH_ATTEMPT_BUDGET_MS`], 5 s) covers every stage including
    ///   the session handshake on the punched QUIC connection.
    ///
    /// On `Connected` the punched session is registered through the normal
    /// outbound path (`register_connection_session` + session runner), so
    /// `peer_pnet_status().admitted` flips the standard way and REALTIME
    /// media rides the session's QUIC DATAGRAM lane exactly like any other
    /// admitted direct QUIC session.
    pub async fn attempt_p2p_hole_punch(
        &self,
        peer_node_id: [u8; 32],
    ) -> veil_ipc::HolePunchOutcome {
        use veil_ipc::HolePunchOutcome as Outcome;
        // Anonymity gate FIRST: `onion_service_hops` is `Some` iff the node
        // was booted with `[anonymity].onion_service = true` (pinned at
        // boot; reloads cannot flip it), which is exactly the posture whose
        // real external address must never be disclosed by a punch.
        if self.anonymity.onion_service_hops.is_some() {
            self.logger.debug(
                "nat.udp_punch.refused_anonymous",
                format!(
                    "explicit punch refused under onion-service posture peer={}",
                    veil_util::hex_short(&peer_node_id)
                ),
            );
            return Outcome::RefusedAnonymous;
        }
        // Idempotent short-circuit: a live direct session already exists
        // (same registry signal `PnetStatusProvider` derives `admitted`
        // from — sessions appear there only after a completed handshake).
        if self.has_live_session(&peer_node_id) {
            return Outcome::Connected;
        }
        // Single-flight: either claim the peer's slot (initiator) or join
        // the attempt already in flight. The map lock is confined to this
        // block — never held across an await.
        enum Flight {
            Join(tokio::sync::broadcast::Receiver<veil_ipc::HolePunchOutcome>),
            Run(HolePunchInflightGuard),
        }
        let flight = {
            let mut inflight = lock!(self.hole_punch_inflight);
            match inflight.get(&peer_node_id) {
                Some(tx) => Flight::Join(tx.subscribe()),
                None => {
                    let (tx, _rx) = tokio::sync::broadcast::channel(1);
                    inflight.insert(peer_node_id, tx.clone());
                    Flight::Run(HolePunchInflightGuard {
                        map: Arc::clone(&self.hole_punch_inflight),
                        peer_node_id,
                        tx,
                        outcome: None,
                    })
                }
            }
        };
        match flight {
            Flight::Join(mut rx) => match rx.recv().await {
                Ok(outcome) => outcome,
                // Initiator dropped without broadcasting: the drop-guard
                // normally sends PunchTimeout, so this arm is
                // belt-and-braces for a torn-down runtime.
                Err(_) => Outcome::PunchTimeout,
            },
            Flight::Run(mut guard) => {
                let outcome = self.attempt_p2p_hole_punch_run(peer_node_id).await;
                guard.outcome = Some(outcome);
                drop(guard); // releases the slot + broadcasts to joiners
                outcome
            }
        }
    }

    /// Number of exclusive punch attempts started through this
    /// `NodeServices` (single-flight joiners do not count). Test hook for
    /// asserting that a concurrent second call joined instead of starting
    /// a second punch.
    pub fn hole_punch_run_count(&self) -> u64 {
        self.hole_punch_run_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The staged body of one exclusive (slot-holding) punch attempt.
    async fn attempt_p2p_hole_punch_run(
        &self,
        peer_node_id: [u8; 32],
    ) -> veil_ipc::HolePunchOutcome {
        use veil_ipc::HolePunchOutcome as Outcome;
        self.hole_punch_run_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let budget =
            std::time::Duration::from_millis(veil_proto::budget::HOLE_PUNCH_ATTEMPT_BUDGET_MS);
        let deadline = tokio::time::Instant::now() + budget;
        // The target must be a registered peer: endpoint exchange
        // (bootstrap join) both authenticates the pubkey/nonce we hand to
        // the QUIC context below and bounds who can make this node punch.
        let Some(peer) = lock_state(&self.state)
            .peers
            .values()
            .find(|entry| entry.node_id.as_bytes() == &peer_node_id)
            .cloned()
        else {
            return Outcome::UnknownPeer;
        };
        let config = match veil_cfg::load_config(&self.config_path) {
            Ok(config) => config,
            Err(error) => {
                self.logger.warn(
                    "nat.udp_punch.config_unavailable",
                    format!("explicit punch cannot load config: {error}"),
                );
                return Outcome::ConfigUnavailable;
            }
        };
        let peer_ctx = match peer_transport_context(&self.transport_ctx, &peer) {
            Ok(ctx) => Arc::new(ctx),
            Err(error) => {
                self.logger.warn(
                    "nat.udp_punch.peer_ctx_failed",
                    format!("peer={} error={error}", peer.peer_id),
                );
                return Outcome::QuicFailed;
            }
        };
        // Reserve a slice of the shared budget for the OVL1 handshake on
        // the punched connection so a slow punch cannot leave registration
        // with a zero deadline.
        const HANDSHAKE_RESERVE: std::time::Duration = std::time::Duration::from_millis(1_000);
        let dial_budget = budget.saturating_sub(HANDSHAKE_RESERVE);
        let connection = match self
            .udp_hole_punch_dial_stages(peer_node_id, peer_ctx, &config, dial_budget)
            .await
        {
            Ok(connection) => connection,
            Err(failure) => return failure.into(),
        };
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let session_ctx = self.make_session_context();
        if let Some(metrics) = &session_ctx.metrics {
            metrics.inc_outbound_connect_attempts();
        }
        // E20: a punched dial is a one-sided no-glare recovery dial — the
        // primary URI was undialable and the peer is not reciprocally
        // dialing this exact socket — so bypass directional dedup like the
        // other NAT-traversal recovery paths.
        let registered = tokio::time::timeout(
            remaining,
            register_connection_session(
                session_ctx,
                SessionSource::Outbound(peer.peer_id),
                Some(ExpectedPeerIdentity {
                    peer_id: peer.peer_id,
                    public_key: peer.public_key.clone(),
                    node_id: peer.node_id,
                    nonce: peer.nonce.clone(),
                    row_transport_at_dial: peer.transport.clone(),
                }),
                None,
                SessionState::Active,
                connection,
                true,
            ),
        )
        .await;
        match registered {
            Ok(Ok(Some(session))) => {
                self.logger.info(
                    "nat.udp_punch.session_registered",
                    format!("peer={} via=explicit_call_path", peer.peer_id),
                );
                self.spawn_punched_outbound(session, &peer);
                Outcome::Connected
            }
            Ok(Ok(None)) => {
                // Handoff-binding is an inbound-only branch; reaching it on
                // an outbound register would be a runtime bug. Surface as
                // the QUIC/session stage failing rather than lying about
                // success.
                self.logger.warn(
                    "nat.udp_punch.session_register_anomaly",
                    "outbound punched register returned handoff-bound (impossible)",
                );
                Outcome::QuicFailed
            }
            Ok(Err(error)) => {
                self.logger.warn(
                    "nat.udp_punch.session_register_failed",
                    format!("peer={} error={error}", peer.peer_id),
                );
                Outcome::QuicFailed
            }
            Err(_) => {
                self.logger.warn(
                    "nat.udp_punch.session_register_failed",
                    "punched session handshake exceeded the attempt budget",
                );
                Outcome::QuicFailed
            }
        }
    }

    /// Spawn the session runner for an initiator-side punched session —
    /// the outbound analog of [`Self::spawn_punched_inbound`]. Mirrors the
    /// outbound-connector runner wiring minus the connector-loop concerns
    /// (no gateway ATTACH/keepalive, no bootstrap FIND_NODE burst) and
    /// with `primary_uri: None`: the punched mapping is ephemeral, so
    /// rotation/handoff must not try to re-dial it — recovery of a dead
    /// punched session belongs to the standard outbound connector via the
    /// SessionGuard refresh bump (mobility slice).
    fn spawn_punched_outbound(
        &self,
        session: AttachedDebugSession,
        peer: &crate::types::PeerConfigEntry,
    ) {
        let access = self.clone();
        let peer = peer.clone();
        let handle = tokio::spawn(async move {
            let dispatcher = Arc::clone(&access.dispatcher);
            let ban_list = Arc::clone(&dispatcher.abuse.ban_list);
            let violation_tracker = Arc::clone(&dispatcher.abuse.violation_tracker);
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
            let outbox_rx = session.reserved_outbox_rx;
            let rpc_rx = access.session_outbox.register_owned(peer_id, session_id);
            let mut runner = veil_session::runner::SessionRunner {
                stream: session.stream,
                quic_datagrams: session.quic_datagrams,
                peer_id: *peer_id.as_bytes(),
                dispatcher,
                logger: Arc::clone(&access.logger),
                metrics: access.metrics.clone(),
                ban_list,
                violation_tracker,
                crypto: veil_session::runner::CryptoState {
                    tx_cipher,
                    rx_cipher,
                    peer_mlkem_keys: Some(Arc::clone(&access.identity.peer_mlkem_keys)),
                    per_session_mlkem_dk: Some(Arc::clone(&access.identity.per_session_mlkem_dk)),
                },
                outbox: Some(outbox_rx),
                rpc_outbox: Some(rpc_rx),
                keepalive_interval: access.defaults.keepalive_interval,
                idle_timeout: access.defaults.idle_timeout,
                max_pending_responses: access.defaults.max_pending_responses,
                pending_response_ttl: access.defaults.pending_response_ttl,
                max_frame_body: access.defaults.max_frame_body,
                rekey: veil_session::runner::RekeyConfig {
                    bytes_threshold: access.defaults.rekey_bytes_threshold,
                    time_threshold_secs: access.defaults.rekey_time_threshold_secs,
                },
                qos_weights: access.defaults.qos_weights,
                session_id,
                local_node_id: access.local_node_id,
                mobile: veil_session::runner::MobileConfig {
                    base_keepalive_interval: access.defaults.keepalive_interval,
                    battery_keepalive_scale_low: access.mobile.battery_keepalive_scale_low,
                    battery_keepalive_scale_medium: access.mobile.battery_keepalive_scale_medium,
                    battery_threshold_low: access.mobile.battery_threshold_low,
                    battery_threshold_medium: access.mobile.battery_threshold_medium,
                },
                // Client role — the responder issues the ticket; we store it.
                ticket_to_send: None,
                peer_tickets: Some(Arc::clone(&access.resumption.peer_tickets)),
                raw_session_keys: Some((raw_tx_key, raw_rx_key, session_id)),
                peer_public_key: Some(session.public_key.clone()),
                peer_nonce: Some(session.nonce.clone()),
                hot_standby: veil_session::runner::HotStandbyState {
                    swap_registry: None,
                    swap_rx: None,
                    handoff_registry: Some(Arc::clone(&access.handoff.registry)),
                    handoff_ack_waiters: Some(Arc::clone(&access.handoff.ack_waiters)),
                    controller: Some(Arc::clone(&access.handoff.controller)),
                    auto_trigger_after_write_errors: access.handoff.auto_trigger_after_write_errors,
                },
                primary_uri: None,
            };
            // Same post-handshake bookkeeping as the outbound connector: the
            // peer joins the DHT routing table (proved key ownership), the
            // dispatcher learns the session + reflector advertisements, and
            // the mobility-slice connectivity-gain hook fires (an outbound
            // handshake completing is fresh evidence of working egress).
            access
                .dht
                .add_contact_trusted(veil_dht::routing::Contact::from_handshake(
                    *peer.node_id.as_bytes(),
                    &peer.transport,
                    session
                        .remote_caps_stated
                        .then_some((session.remote_discovery_mode, session.remote_dht_service)),
                ));
            let _ = access
                .dht
                .promote_contact_if_pending(peer.node_id.as_bytes());
            access.dispatcher.on_session_opened(
                *peer_id.as_bytes(),
                session.observed_addr,
                session.udp_reflector_port,
                &session.shared_udp_reflectors,
            );
            access.connectivity_gain.on_outbound_session_established();
            crate::runtime::send_local_announcement(
                &access.dht,
                &access.session_outbox,
                *peer_id.as_bytes(),
            );
            access
                .session_tx_registry
                .write()
                .unwrap_or_else(|p| p.into_inner())
                .send_to(
                    peer_id.as_bytes(),
                    veil_proto::priority::INTERACTIVE,
                    crate::outbound_connector::build_startup_route_probe_frame(),
                );
            let _swap_guard = runner.register_swap_channel(&access.handoff.swap_registry);
            runner.run().await;
            drop(_swap_guard);
            // Owner-aware teardown — same contract as the inbound path:
            // never tear down peer-wide state a reconnect now owns. This
            // path also used to notify the dispatcher BEFORE unregistering
            // the tx channel, the ordering the inbound path fixed long ago.
            session_guard::release_session(
                session_guard::SessionRelease {
                    session_tx_registry: &access.session_tx_registry,
                    session_outbox: &access.session_outbox,
                    session_close_generations: &access.session_close_generations,
                    identity: &access.identity,
                    dispatcher: &access.dispatcher,
                    logger: &access.logger,
                },
                peer_id,
                &session_id,
                // Outbound sessions are never capacity-referral.
                false,
            );
            let _ = runner.stream.shutdown().await;
        });
        push_session_handle(&self.tasks, handle);
    }

    pub(crate) async fn nat_fallback_dial(
        &self,
        peer: &crate::types::PeerConfigEntry,
        primary_uri: &TransportUri,
        peer_ctx: Arc<veil_transport::TransportContext>,
    ) -> Option<Box<dyn TransportConnection>> {
        // Cheap-bail #1: primary URI scheme must be promotable. No
        // point running signaling to learn the peer's IP if we can't
        // build a connectable URI from it (`with_host_port` returns
        // None for Unix/Socks/Ws*).
        primary_uri.with_host_port("0.0.0.0".into(), 0)?;

        // Cheap-bail #2: signaling needs at least one connected peer
        // to act as a coordinator. `try_nat_traversal` would also
        // return None in this case, but going through the full path
        // for an inevitable miss wastes log lines.
        let connected_peer_count = rlock!(self.session_tx_registry).peer_ids().len();
        if connected_peer_count == 0 {
            return None;
        }

        if let Some(connection) = self
            .udp_hole_punch_dial(*peer.node_id.as_bytes(), Arc::clone(&peer_ctx))
            .await
        {
            return Some(connection);
        }

        // Build our own host candidates from the dispatcher's known
        // listen transports (same source-of-truth used by the
        // dispatcher's echo-bugfix path so the wire is
        // symmetric).
        let local_candidates = veil_dispatcher::build_own_host_candidates(
            &self
                .dispatcher
                .listen_transports
                .read()
                .unwrap_or_else(|p| p.into_inner()),
        );

        let promoted = self
            .try_nat_traversal_promote_uris(
                *peer.node_id.as_bytes(),
                primary_uri,
                local_candidates,
                std::time::Duration::from_secs(3),
            )
            .await;
        if promoted.is_empty() {
            return None;
        }

        const MAX_FALLBACK_DIAL_ATTEMPTS: usize = 4;
        for candidate_uri in promoted.into_iter().take(MAX_FALLBACK_DIAL_ATTEMPTS) {
            match self
                .registry
                .connect(&candidate_uri, Arc::clone(&peer_ctx))
                .await
            {
                Ok(connection) => return Some(connection),
                Err(_) => continue, // try next candidate
            }
        }
        None
    }

    /// Anti-censorship: wrap a failed-direct dial through an operator-
    /// configured SOCKS proxy (typically local Tor on
    /// `socks5://127.0.0.1:9050`).  Closes #22/#23/#27 partially —
    /// Tor's exit nodes are in diverse ASes by design, so an AS-level
    /// block on the operator's host is bypassed via the proxy hop.
    ///
    /// Returns `None` if:
    /// * `transport.outbound_socks_fallback_proxy` is unset (default —
    ///   feature opt-in)
    /// * the primary URI's scheme cannot be wrapped in SOCKS
    ///   (`Self::Quic`, `Self::Unix`, etc. — SOCKS5 is a TCP-only
    ///   transport)
    /// * the proxy URL is unparseable as a SOCKS URI
    /// * the proxy itself fails to connect (logged, returns None)
    pub(crate) async fn socks_fallback_dial(
        &self,
        primary_uri: &TransportUri,
        peer_ctx: Arc<veil_transport::TransportContext>,
    ) -> Option<Box<dyn TransportConnection>> {
        let proxy_str = peer_ctx.outbound_socks_fallback_proxy.as_ref()?;
        let (proxy_host, proxy_port, target_host, target_port) =
            crate::socks_fallback::compose_socks_fallback(proxy_str, primary_uri)?;

        // Construct a `socks://<proxy>/<target_host>:<target_port>`
        // URI and dial via the existing SOCKS transport.
        let socks_uri_str = format!(
            "socks://{}:{}/{}:{}",
            proxy_host, proxy_port, target_host, target_port,
        );
        let socks_uri = TransportUri::parse(&socks_uri_str).ok()?;

        self.logger.info(
            "peer.connect.socks_fallback_dial",
            format!(
                "primary={} proxy={proxy_host}:{proxy_port}",
                veil_util::redact_addr_for_log(&primary_uri.to_string()),
            ),
        );

        match self.registry.connect(&socks_uri, peer_ctx).await {
            Ok(connection) => Some(connection),
            Err(e) => {
                self.logger.warn(
                    "peer.connect.socks_fallback_failed",
                    format!("proxy={proxy_host}:{proxy_port} error={e}"),
                );
                None
            }
        }
    }
}
