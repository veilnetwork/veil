//! Getting through a NAT: learning the address other people can reach.
//!
//! Three tasks, one question. A node behind a home router does not know its
//! own reachable address, and nothing else it does works until it finds out:
//!
//!  * [`NodeRuntime::spawn_udp_reflector_task`] is the SERVING half — this
//!    node tells other people what address their packets arrived from. Every
//!    Core node offers it automatically, which is what removed the
//!    central, client-configured reflector list.
//!  * [`NodeRuntime::spawn_udp_punch_responder_task`] is the ACTIVE half:
//!    a peer asks for a hole, both sides fire, and the mapping is promoted
//!    into something dialable.
//!  * [`NodeRuntime::spawn_srflx_probe_task`] is the ASKING half — a
//!    periodic sentinel echo at a connected peer with a public address, so
//!    the node knows its own external address BEFORE a dial needs it rather
//!    than after one has already failed.
//!
//! Serving, punching and asking are the same protocol seen from three
//! positions, and they share one failure mode worth keeping in one file: ask
//! a LAN peer and the answer is your PRIVATE address, which the reply path
//! would then freeze into the listen transports. That constraint is written
//! into the probe's peer choice and would be easy to lose if the three
//! drifted into different files.
//!
//! Moved verbatim out of `service_tasks.rs` (report24 RUNTIME-3). Behaviour
//! is unchanged; these are the same inherent methods on the same type, so
//! `services.rs` still reaches them by name.

use std::sync::Arc;

use veil_util::{lock, rlock};

use super::{NodeRuntime, lock_tasks, supervised_spawn};

impl NodeRuntime {
    /// Bind the fixed-size UDP mapping reflector offered by this node.
    ///
    /// Every Core node opts in automatically on the protocol's conventional
    /// port and advertises the live port to authenticated session peers. This
    /// removes the central, client-configured reflector list: a new operator
    /// becomes useful as soon as their normal Veil node is reachable. The old
    /// `nat.udp_reflector_bind` remains an explicit bind override for unusual
    /// deployments and retains fail-fast startup semantics.
    pub async fn spawn_udp_reflector_task(
        &mut self,
        config: &veil_cfg::Config,
    ) -> crate::Result<()> {
        use std::sync::atomic::Ordering;

        self.dispatcher
            .local_udp_reflector_port
            .store(0, Ordering::Release);
        let explicit = config.nat.udp_reflector_bind.as_deref();
        let auto_enabled = explicit.is_none()
            && config
                .identity
                .as_ref()
                .is_some_and(|identity| identity.role == veil_cfg::NodeRole::Core);
        if explicit.is_none() && !auto_enabled {
            return Ok(());
        }
        let automatic_bind = format!("0.0.0.0:{}", veil_nat::DEFAULT_UDP_REFLECTOR_PORT);
        let bind = explicit.unwrap_or(&automatic_bind);
        let addr = bind.parse::<std::net::SocketAddr>().map_err(|error| {
            crate::error::NodeError::InvalidArgument(format!(
                "invalid nat.udp_reflector_bind `{bind}`: {error}"
            ))
        })?;
        let socket = match tokio::net::UdpSocket::bind(addr).await {
            Ok(socket) => socket,
            Err(error) if explicit.is_none() => {
                self.logger.warn(
                    "nat.udp_reflector.auto_bind_failed",
                    format!("endpoint={addr} error={error}"),
                );
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        veil_util::outbound_interface::configure_outbound_socket(
            &socket,
            if addr.is_ipv4() {
                veil_util::outbound_interface::SocketFamilies::V4
            } else {
                veil_util::outbound_interface::SocketFamilies::V6
            },
        )?;
        let local_addr = socket.local_addr()?;
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return Ok(());
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let logger = Arc::clone(&self.logger);
        let advertised_port = Arc::clone(&self.dispatcher.local_udp_reflector_port);
        advertised_port.store(local_addr.port(), Ordering::Release);
        logger.info(
            "nat.udp_reflector.start",
            format!(
                "endpoint={local_addr} mode={}",
                if explicit.is_some() {
                    "explicit"
                } else {
                    "peer-auto"
                },
            ),
        );
        let handle = supervised_spawn(Arc::clone(&self.logger), "udp_reflector", async move {
            let shutdown = async move {
                loop {
                    match shutdown_rx.changed().await {
                        Ok(()) if *shutdown_rx.borrow() => break,
                        Ok(()) => continue,
                        Err(_) => break,
                    }
                }
            };
            if let Err(error) = veil_nat::serve_udp_reflector(socket, shutdown).await {
                logger.warn("nat.udp_reflector.failed", error.to_string());
            }
            advertised_port.store(0, Ordering::Release);
        });
        lock_tasks(&self.tasks).listeners.push(handle);
        Ok(())
    }

    /// Spawn the socket-owning half of token-bearing NAT traversal offers.
    /// The synchronous dispatcher hands authenticated offers into this bounded
    /// queue; each attempt discovers, replies, punches, then promotes the same
    /// socket into an inbound QUIC session.
    pub fn spawn_udp_punch_responder_task(&mut self, config: &veil_cfg::Config) {
        *lock!(self.dispatcher.nat_punch_offer_tx) = None;
        if !config.nat.enabled {
            return;
        }
        let configured_reflectors = config.nat.udp_reflectors.clone();
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        const OFFER_QUEUE_CAP: usize = 32;
        const MAX_CONCURRENT_ATTEMPTS: usize = 16;
        let (offer_tx, mut offer_rx) = tokio::sync::mpsc::channel(OFFER_QUEUE_CAP);
        *lock!(self.dispatcher.nat_punch_offer_tx) = Some(offer_tx);
        let mut shutdown_rx = shutdown_tx.subscribe();
        let timeout = std::time::Duration::from_millis(config.nat.punch_timeout_ms);
        let access = self.access();
        let logger = Arc::clone(&self.logger);
        let handle = supervised_spawn(
            Arc::clone(&self.logger),
            "udp_punch_responder",
            async move {
                let mut attempts = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        Ok(_) = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                attempts.abort_all();
                                break;
                            }
                        }
                        Some(_) = attempts.join_next(), if !attempts.is_empty() => {}
                        offer = offer_rx.recv() => {
                            let Some(offer) = offer else { break };
                            if attempts.len() >= MAX_CONCURRENT_ATTEMPTS {
                                logger.warn(
                                    "nat.udp_punch.offer_dropped",
                                    "concurrent attempt cap reached",
                                );
                                continue;
                            }
                            let access = access.clone();
                            let reflectors = access.available_udp_reflectors(
                                offer.request.initiator_node_id,
                                &configured_reflectors,
                            );
                            let logger = Arc::clone(&logger);
                            attempts.spawn(async move {
                                if timeout.is_zero() {
                                    return;
                                }
                                let deadline = tokio::time::Instant::now() + timeout;
                                let Some(punch_token) = offer.request.punch_token else {
                                    return;
                                };
                                let Some(first_reflector) = reflectors.first().copied() else {
                                    return;
                                };
                                let reflectors = reflectors
                                    .into_iter()
                                    .filter(|value| {
                                        value.is_ipv4() == first_reflector.is_ipv4()
                                    })
                                    .collect::<Vec<_>>();
                                let bind_addr = match first_reflector {
                                    std::net::SocketAddr::V4(_) => "0.0.0.0:0",
                                    std::net::SocketAddr::V6(_) => "[::]:0",
                                };
                                let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
                                    Ok(socket) => socket,
                                    Err(error) => {
                                        logger.warn("nat.udp_punch.bind_failed", error.to_string());
                                        return;
                                    }
                                };
                                if let Err(error) =
                                    veil_util::outbound_interface::configure_outbound_socket(
                                        &socket,
                                        if first_reflector.is_ipv4() {
                                            veil_util::outbound_interface::SocketFamilies::V4
                                        } else {
                                            veil_util::outbound_interface::SocketFamilies::V6
                                        },
                                    )
                                {
                                    logger.warn(
                                        "nat.udp_punch.interface_pin_failed",
                                        error.to_string(),
                                    );
                                    return;
                                }
                                let discovery_token = {
                                    use rand_core::RngCore;
                                    let mut token = [0u8; 16];
                                    rand_core::OsRng.fill_bytes(&mut token);
                                    token
                                };
                                let mapping = match veil_nat::discover_udp_mapping_any_for_punch(
                                    &socket,
                                    &reflectors,
                                    discovery_token,
                                    timeout.min(std::time::Duration::from_millis(500)),
                                )
                                .await
                                {
                                    Ok(Some((mapping, _))) => mapping,
                                    Ok(None) => {
                                        logger.debug(
                                            "nat.udp_punch.discovery_unusable",
                                            "no non-hairpin UDP mapping from peer-announced reflectors",
                                        );
                                        return;
                                    }
                                    Err(error) => {
                                        logger.warn(
                                            "nat.udp_punch.discovery_failed",
                                            error.to_string(),
                                        );
                                        return;
                                    }
                                };
                                let mut candidate = veil_nat::socket_addr_to_candidate(mapping);
                                candidate.candidate_type =
                                    veil_proto::control::candidate_type::SRFLX;
                                candidate.priority = 1_694_498_815;
                                let final_target_node_id =
                                    if offer.reply_via_node_id == offer.request.initiator_node_id {
                                        [0u8; 32]
                                    } else {
                                        offer.request.initiator_node_id
                                    };
                                let reply = veil_proto::control::NatProbeReplyPayload {
                                    responder_node_id: access.local_node_id,
                                    final_target_node_id,
                                    session_token: offer.request.session_token,
                                    punch_token: Some(punch_token),
                                    candidates: vec![candidate],
                                };
                                let body = reply.encode();
                                let mut header = veil_proto::header::FrameHeader::new(
                                    veil_proto::family::FrameFamily::Control as u8,
                                    veil_proto::family::ControlMsg::NatProbeReply as u16,
                                );
                                header.body_len = body.len() as u32;
                                header.set_priority(veil_proto::priority::INTERACTIVE);
                                let mut frame = veil_proto::codec::encode_header(&header).to_vec();
                                frame.extend_from_slice(&body);
                                if !rlock!(access.session_tx_registry).send_to(
                                    &offer.reply_via_node_id,
                                    veil_proto::priority::INTERACTIVE,
                                    frame,
                                ) {
                                    return;
                                }
                                let peer_candidates = offer
                                    .request
                                    .candidates
                                    .iter()
                                    .filter(|candidate| {
                                        candidate.candidate_type
                                            == veil_proto::control::candidate_type::SRFLX
                                    })
                                    .filter_map(veil_nat::candidate_to_socket_addr)
                                    .filter(|candidate| veil_nat::is_public_punch_addr(*candidate))
                                    .collect::<Vec<_>>();
                                let remaining = deadline
                                    .saturating_duration_since(tokio::time::Instant::now());
                                let quic_reserve =
                                    (remaining / 2).min(std::time::Duration::from_millis(750));
                                let punch_timeout = remaining.saturating_sub(quic_reserve);
                                if punch_timeout.is_zero() {
                                    return;
                                }
                                // Bound to our veil: see `veil_nat::network_tag`.
                                let network_tag = veil_nat::network_tag(
                                    access.transport_ctx.obfs4_psk.as_deref(),
                                );
                                let punched = veil_nat::punch_udp(
                                    &socket,
                                    &peer_candidates,
                                    punch_token,
                                    &network_tag,
                                    punch_timeout,
                                )
                                .await
                                .unwrap_or_default();
                                let Some(peer) = punched.peer else {
                                    if punched.foreign_tokens > 0 {
                                        logger.debug(
                                            "nat.udp_punch.foreign_network",
                                            format!(
                                                "{} punch packet(s) carried a token \
                                                 from another veil",
                                                punched.foreign_tokens
                                            ),
                                        );
                                    }
                                    return;
                                };
                                let remaining = deadline
                                    .saturating_duration_since(tokio::time::Instant::now());
                                if remaining.is_zero() {
                                    return;
                                }
                                let promoted = tokio::time::timeout(
                                    remaining,
                                    veil_transport::promote_punched_quic(
                                        socket,
                                        peer,
                                        Arc::clone(&access.transport_ctx),
                                        veil_transport::PunchedQuicRole::Responder,
                                    ),
                                )
                                .await;
                                match promoted {
                                    Ok(Ok(connection)) => {
                                        logger.info(
                                            "nat.udp_punch.connected",
                                            format!(
                                                "peer={} role=responder",
                                                veil_util::hex_short(
                                                    &offer.request.initiator_node_id
                                                )
                                            ),
                                        );
                                        access.spawn_punched_inbound(connection);
                                    }
                                    Ok(Err(error)) => logger.warn(
                                        "nat.udp_punch.quic_failed",
                                        error.to_string(),
                                    ),
                                    Err(_) => logger.warn(
                                        "nat.udp_punch.quic_failed",
                                        "overall NAT traversal deadline elapsed",
                                    ),
                                }
                            });
                        }
                    }
                }
            },
        );
        lock_tasks(&self.tasks).background.push(handle);
    }

    /// Proactive server-reflexive (srflx) address probe — real-P2P epic,
    /// Stage B.
    ///
    /// The dispatcher already implements the FULL receive side of the
    /// pure STUN-echo protocol: a `NatProbeRequest` with the `[0; 32]`
    /// sentinel target is answered with the observed source `ip:port` as
    /// an SRFLX candidate, and the initiator's `NatProbeReply` handler
    /// rewrites wildcard listen transports (`0.0.0.0` → observed external
    /// IP). What was missing is any SENDER: the only production
    /// `NatProbeRequest` site is the relay-mode signaling driver inside
    /// `nat_fallback_dial`, which fires only after an outbound dial has
    /// already failed. This task closes the gap: periodically fire one
    /// sentinel echo at a connected peer with a PUBLIC remote address so
    /// the node knows its own external address BEFORE it is needed
    /// (direct-endpoint exchange mines `listen_transports` for it).
    ///
    /// Peer choice matters: probing a LAN peer would echo our PRIVATE
    /// address, and the reply path would freeze the wildcard rewrite on
    /// it (rewrites only touch wildcard hosts). Sessions without a
    /// parseable public `remote_addr` are skipped.
    ///
    /// Fire-and-forget: no waiter is registered — the dispatcher's reply
    /// handler does the listen-transport update on its own.
    pub fn spawn_srflx_probe_task(&mut self) {
        const SRFLX_PROBE_INITIAL_DELAY: std::time::Duration = std::time::Duration::from_secs(20);
        const SRFLX_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);
        // P2P mobility slice: minimum spacing between wake-driven probes.
        // A network flip produces a burst of outbound session-opens (seeds,
        // gateways, app peers) — the burst coalesces into ONE prompt probe;
        // the 300 s periodic tick stays the steady-state ceiling.
        const SRFLX_PROBE_MIN_GAP: std::time::Duration = std::time::Duration::from_secs(10);

        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let dispatcher = Arc::clone(&self.dispatcher);
        let session_tx_registry = Arc::clone(&self.session_tx_registry);
        let live_sessions = Arc::clone(&self.live_sessions);
        let logger = Arc::clone(&self.logger);
        let connectivity_gain = Arc::clone(&self.connectivity_gain);
        let local_node_id = *self.identity.local_identity.node_id.as_bytes();
        let handle = supervised_spawn(Arc::clone(&self.logger), "srflx_probe", async move {
            fn is_public_ip(ip: &std::net::IpAddr) -> bool {
                match ip {
                    std::net::IpAddr::V4(v4) => {
                        !(v4.is_loopback()
                            || v4.is_private()
                            || v4.is_link_local()
                            || v4.is_unspecified()
                            || v4.is_broadcast()
                            || v4.is_documentation()
                            // CGNAT shared space (100.64.0.0/10) — an echo
                            // from there is another operator-NAT view, not
                            // our internet-facing address.
                            || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])))
                    }
                    std::net::IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified()),
                }
            }

            // Let the startup dials land a session before the first probe —
            // or start immediately when the first outbound session lands
            // (connectivity-gain wake), whichever comes first.
            tokio::select! {
                Ok(_) = shutdown_rx.changed() => return,
                _ = tokio::time::sleep(SRFLX_PROBE_INITIAL_DELAY) => {}
                _ = connectivity_gain.srflx_wake() => {}
            }
            let mut interval = tokio::time::interval(SRFLX_PROBE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // consume the immediate first tick
            // Instant of the last ACTUALLY-SENT probe (wake-driven min-gap).
            let mut last_probe_sent: Option<tokio::time::Instant> = None;
            loop {
                // Refresh every tick: `record_own_external_addr` rotates a
                // CHANGED external IP (DHCP lease, network switch) in as the
                // freshest observation, so periodic re-probing doubles as
                // mobility tracking. One tiny control frame per interval.
                let listen_snapshot = dispatcher.listen_transports_snapshot();
                {
                    let target = {
                        let sessions = lock!(live_sessions);
                        sessions.values().find_map(|s| {
                            let node_id = s.node_id?;
                            if node_id.as_bytes() == &local_node_id {
                                return None;
                            }
                            let addr: std::net::SocketAddr =
                                s.remote_addr.as_deref()?.parse().ok()?;
                            is_public_ip(&addr.ip()).then_some(*node_id.as_bytes())
                        })
                    };
                    if let Some(target_node_id) = target {
                        use veil_proto::codec::encode_header;
                        use veil_proto::control::NatProbeRequestPayload;
                        use veil_proto::family::{ControlMsg, FrameFamily};
                        use veil_proto::header::{FrameHeader, HEADER_SIZE};
                        let session_token: u32 = {
                            use rand_core::RngCore;
                            rand_core::OsRng.next_u32()
                        };
                        let request = NatProbeRequestPayload {
                            initiator_node_id: local_node_id,
                            // `[0; 32]` sentinel = pure STUN echo: "tell me
                            // what srflx address you see for me".
                            target_node_id: [0u8; 32],
                            session_token,
                            punch_token: None,
                            candidates: veil_dispatcher::build_own_host_candidates(
                                &listen_snapshot,
                            ),
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
                        let sent = rlock!(session_tx_registry).send_to(
                            &target_node_id,
                            veil_proto::header::priority::BACKGROUND,
                            frame,
                        );
                        if sent {
                            last_probe_sent = Some(tokio::time::Instant::now());
                            logger.debug(
                                "nat.srflx_probe.sent",
                                format!(
                                    "target={} session_token=0x{session_token:08x}",
                                    veil_util::hex_short(&target_node_id),
                                ),
                            );
                        }
                    }
                }
                tokio::select! {
                    Ok(_) = shutdown_rx.changed() => break,
                    _ = interval.tick() => {}
                    // P2P mobility slice: a fresh outbound session (post
                    // network-flip reconnection) re-observes our external
                    // address NOW instead of waiting out the 300 s tick —
                    // `record_own_external_addr` rotates a CHANGED external
                    // IP in as the freshest observation, so the app's next
                    // direct-endpoint exchange mints the NEW srflx URI.
                    _ = connectivity_gain.srflx_wake() => {
                        // Enforce the min gap: sleep out the remainder so a
                        // burst of session-opens produces one probe.
                        if let Some(t) = last_probe_sent {
                            let since = tokio::time::Instant::now().duration_since(t);
                            if since < SRFLX_PROBE_MIN_GAP {
                                tokio::select! {
                                    Ok(_) = shutdown_rx.changed() => break,
                                    _ = tokio::time::sleep(SRFLX_PROBE_MIN_GAP - since) => {}
                                }
                            }
                        }
                    }
                }
            }
        });
        lock_tasks(&self.tasks).background.push(handle);
    }
}
