use super::*;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use veil_app::registry::AppMessage;
use veil_proto::{AppRtDataPayload, family::AppMsg};
use veil_transport::{
    Transport, TransportContext, TransportListener, TransportUri,
    quic::QuicTransport,
    quic::{PunchedQuicRole, promote_punched_quic},
};

async fn runner_channels_over_real_quic(
    flows: bool,
    parallel: bool,
    rotate: bool,
    shared: bool,
    resumed: bool,
) {
    runner_channels_with_backlog(flows, parallel, rotate, shared, resumed, false).await;
}

async fn runner_channels_with_backlog(
    flows: bool,
    parallel: bool,
    rotate: bool,
    shared: bool,
    resumed: bool,
    blocked_reliable: bool,
) {
    let context = Arc::new(TransportContext::for_debug().unwrap());
    let registry = Arc::new(ParallelRegistry::default());
    let listener: Option<Arc<dyn TransportListener>> = if shared {
        let uri: TransportUri = "quic://127.0.0.1:0".parse().unwrap();
        Some(Arc::from(
            QuicTransport
                .bind(&uri, Arc::clone(&context))
                .await
                .unwrap(),
        ))
    } else {
        None
    };
    let (a, b_task) = if let Some(listener) = &listener {
        let uri: TransportUri = format!("quic://{}", listener.local_addr()).parse().unwrap();
        let listener = Arc::clone(listener);
        let accepted = tokio::spawn(async move { listener.accept().await });
        let a = QuicTransport
            .connect(&uri, Arc::clone(&context))
            .await
            .unwrap();
        (a, accepted)
    } else {
        let a_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a_socket.local_addr().unwrap();
        let b_addr = b_socket.local_addr().unwrap();
        let b_context = Arc::clone(&context);
        let b_task = tokio::spawn(async move {
            promote_punched_quic(b_socket, a_addr, b_context, PunchedQuicRole::Responder).await
        });
        let a = promote_punched_quic(a_socket, b_addr, context, PunchedQuicRole::Initiator)
            .await
            .unwrap();
        (a, b_task)
    };
    let a_datagrams = a.quic_datagrams().unwrap();
    let a_parallel = a.parallel_quic().unwrap();
    let mut a_stream = a.into_stream().unwrap();
    // Advertise the first bidi stream before waiting for accept_bi.
    a_stream.write_all(b"test").await.unwrap();
    let b = b_task.await.unwrap().unwrap();
    let b_datagrams = b.quic_datagrams().unwrap();
    let b_parallel = b.parallel_quic().unwrap();
    let mut b_stream = b.into_stream().unwrap();
    let mut prelude = [0u8; 4];
    b_stream.read_exact(&mut prelude).await.unwrap();

    let mut keys = [([1; 32], [2; 32]), ([2; 32], [1; 32])];
    let mut node_ids = [[1; 32], [2; 32]];
    let mut resumed_caps = None;
    if resumed {
        use base64::Engine as _;
        use veil_node_runtime::local_identity::HandshakeIdentity;
        use veil_session::handshake::perform_ovl1_handshake;
        use veil_session::ticket::{TicketIssuer, TicketKey};
        let identities = [0xAA, 0xBB].map(|seed| {
            let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
            let public_key =
                base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
            HandshakeIdentity {
                algo: veil_cfg::SignatureAlgorithm::Ed25519,
                node_id: veil_cfg::NodeId::from_public_key(
                    veil_cfg::SignatureAlgorithm::Ed25519,
                    &public_key,
                )
                .unwrap(),
                public_key,
                private_key: base64::engine::general_purpose::STANDARD.encode([seed; 32]),
                nonce: format!("resume-test-{seed}"),
            }
        });
        node_ids = identities
            .each_ref()
            .map(|identity| *identity.node_id.as_bytes());
        let issuer = Arc::new(std::sync::Mutex::new(TicketIssuer::new(
            TicketKey::generate(),
        )));
        let blob = issuer.lock().unwrap().issue_for_instance(
            [3; 32],
            node_ids[0],
            [5; 16],
            [2; 32],
            [1; 32],
        );
        let ticket = veil_proto::session::ClientTicketEntry {
            blob,
            tx_key: [1; 32],
            rx_key: [2; 32],
            session_id: [3; 32],
            peer_public_key: identities[1].public_key.clone(),
            peer_nonce: identities[1].nonce.clone(),
            issued_at: std::time::Instant::now(),
        };
        let (a_result, b_result) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                perform_ovl1_handshake(
                    &mut a_stream,
                    &identities[0],
                    NodeRole::Core,
                    veil_cfg::DiscoveryMode::Public,
                    None,
                    None,
                    None,
                    Some(node_ids[1]),
                    Some(ticket),
                    None,
                    None,
                    &[],
                    false,
                    true,
                    None,
                    None,
                    None,
                ),
                perform_ovl1_handshake(
                    &mut b_stream,
                    &identities[1],
                    NodeRole::Core,
                    veil_cfg::DiscoveryMode::Public,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(issuer),
                    None,
                    &[],
                    false,
                    true,
                    None,
                    None,
                    None,
                ),
            )
        })
        .await
        .expect("resumption over real QUIC timed out");
        let results = [a_result.unwrap(), b_result.unwrap()];
        for (index, result) in results.iter().enumerate() {
            assert!(result.remote_caps_stated);
            assert!(result.remote_capabilities.supports_shared_parallel_quic());
            assert!(result.remote_capabilities.supports_duplex_parallel_quic());
            assert_ne!(result.session_keys.tx_key, keys[index].0);
            assert_ne!(result.session_keys.rx_key, keys[index].1);
            keys[index] = (result.session_keys.tx_key, result.session_keys.rx_key);
        }
        resumed_caps = Some(results.map(|result| result.remote_capabilities));
    }

    let mut tasks = Vec::new();
    if let Some(listener) = listener {
        let registry = Arc::clone(&registry);
        tasks.push(tokio::spawn(async move {
            loop {
                let connection = listener.accept().await.unwrap();
                let datagrams = connection.quic_datagrams();
                let stream = connection.into_stream().unwrap();
                match registry.peek_and_dispatch(stream, datagrams).await {
                    ParallelPeekOutcome::Bound => {}
                    ParallelPeekOutcome::Drop(_) => {} // rekey can retire a proof in flight
                    ParallelPeekOutcome::Handshake(_) => {
                        panic!("child created a new canonical peer")
                    }
                }
            }
        }));
    }
    let mut receivers = Vec::new();
    let mut senders = Vec::new();
    let mut endpoints = Vec::new();
    let mut diagnostics = Vec::new();
    let mut writer_attempts = Vec::new();
    let app_id = [0xa0; 32];
    for (direction, device) in [
        (a_stream, a_datagrams, keys[0].0, keys[0].1, a_parallel),
        (b_stream, b_datagrams, keys[1].0, keys[1].1, b_parallel),
    ]
    .into_iter()
    .enumerate()
    {
        let (stream, datagrams, tx_key, rx_key, handle) = device;
        let (_, dummy) = tokio::io::duplex(64);
        let (mut runner, _) = make_swap_runner(dummy);
        let dispatcher = Arc::new(make_test_dispatcher(NodeRole::Core));
        let (endpoint, receiver) = dispatcher.app_registry.register(app_id, 1, 64);
        endpoints.push(endpoint);
        let (out_tx, out_rx) = mpsc::channel::<PriorityFrame>(32);
        let attempted = Arc::new(tokio::sync::Notify::new());
        writer_attempts.push(Arc::clone(&attempted));
        runner.stream = if parallel && !rotate {
            Box::new(StoppedStreamWriter { stream, attempted })
        } else {
            stream
        };
        let offer = if handle.has_exclusive_accept() {
            ParallelQuicOffer::new(handle)
        } else {
            ParallelQuicOffer::new(handle).with_registry(Arc::clone(&registry))
        };
        diagnostics.push(offer.diagnostics());
        let caps = resumed_caps.as_ref().map(|caps| &caps[direction]);
        runner.quic_datagrams = Some(RealtimeLaneOffer {
            handle: datagrams,
            peer_rotates: caps.is_none_or(|caps| caps.supports_realtime_rekey()),
            peer_flows: caps.map_or(flows, |caps| caps.supports_datagram_flows()),
            peer_circuit_datagrams: caps.is_some_and(|caps| caps.supports_circuit_datagrams()),
            parallel: (parallel && caps.is_none_or(|caps| caps.supports_parallel_quic()))
                .then_some(offer),
        });
        runner.session_id = [3; 32];
        runner.raw_session_keys = Some((tx_key, rx_key, [3; 32]));
        if rotate || resumed {
            runner.local_node_id = node_ids[direction];
            runner.peer_id = node_ids[1 - direction];
            runner.crypto.tx_cipher = Some(veil_crypto::session_cipher::SessionCipher::new(
                &tx_key, true,
            ));
            runner.crypto.rx_cipher = Some(veil_crypto::session_cipher::SessionCipher::new(
                &rx_key, true,
            ));
        }
        if rotate {
            // Only A initiates; B exercises the actual responder rekey arm.
            if direction == 0 {
                runner.rekey.time_threshold_secs = 1;
            }
        }
        runner.outbox = Some(out_rx.into());
        runner.ban_list = Arc::clone(&dispatcher.abuse.ban_list);
        runner.violation_tracker = Arc::clone(&dispatcher.abuse.violation_tracker);
        runner.logger = Arc::clone(&dispatcher.logger);
        runner.dispatcher = dispatcher;
        tasks.push(tokio::spawn(async move { runner.run().await }));
        receivers.push(receiver);
        senders.push(out_tx);
    }
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        // Exercise BOTH queue selections and both directions through actual
        // SessionRunners, QUIC DATAGRAM I/O, frame parsing and app dispatch.
        for direction in 0..2 {
            let mut backlog_start: Option<[u64; 3]> = None;
            for seq in 0..if rotate {
                400
            } else if parallel {
                200
            } else {
                16
            } {
                let data = vec![seq as u8; if seq % 2 == 0 { 160 } else { 1500 }];
                let payload = AppRtDataPayload {
                    src_app_id: [0xb0; 32],
                    app_id,
                    endpoint_id: 1,
                    seq,
                    timestamp_us: u64::from(seq) * 20_000,
                    marker: 0,
                    payload_type: 0,
                    payload: data.clone(),
                };
                let body = payload.encode();
                let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppRtData as u16);
                header.body_len = body.len() as u32;
                let mut frame = encode_header(&header).to_vec();
                frame.extend(body);
                let local_priority = if let Some([primary, _, _]) = backlog_start {
                    if diagnostics[direction].sent(0) < primary + 24 {
                        0
                    } else {
                        [0, 2, 3][seq as usize % 3]
                    }
                } else if parallel && seq % 7 == 0 {
                    1
                } else if parallel {
                    [0, 2, 3][seq as usize % 3]
                } else if seq % 2 == 0 {
                    0
                } else {
                    2
                };
                senders[direction]
                    .send((local_priority, veil_bufpool::pooled_shared_from_vec(frame)))
                    .await
                    .unwrap();
                match receivers[1 - direction].recv().await.unwrap() {
                    AppMessage::RtData {
                        src_node_id,
                        payload,
                    } => {
                        assert_eq!(
                            src_node_id,
                            if resumed {
                                node_ids[direction]
                            } else {
                                [if rotate { direction as u8 + 1 } else { 1 }; 32]
                            }
                        );
                        assert_eq!(payload.seq, seq);
                        assert_eq!(payload.payload, data);
                    }
                    other => panic!("unexpected dispatched message {other:?}"),
                }
                if parallel {
                    // Keep a paced producer while TLS binding
                    // warms, then prove frames used BOTH independent senders.
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    if seq >= 16
                        && diagnostics[direction].sent_this_generation(0) >= 8
                        && diagnostics[direction].sent_this_generation(2) >= 8
                        && diagnostics[direction].sent_this_generation(3) >= 8
                        && (!rotate || diagnostics[direction].rekeys() >= 1)
                    {
                        if blocked_reliable {
                            if backlog_start.is_none() {
                                backlog_start =
                                    Some([0, 2, 3].map(|lane| diagnostics[direction].sent(lane)));
                                // Fill the eight-frame writer channel and retain
                                // a reliable FIFO backlog in the actual runner.
                                // Audio must continue for multiple source rounds.
                                for reliable_seq in 0..32 {
                                    let body = veil_proto::AppDataPayload {
                                        app_id,
                                        endpoint_id: 1,
                                        seq: reliable_seq,
                                        data: vec![0x55; 4096],
                                    }
                                    .encode();
                                    let mut header = FrameHeader::new(
                                        FrameFamily::App as u8,
                                        AppMsg::AppData as u16,
                                    );
                                    header.body_len = body.len() as u32;
                                    let mut frame = encode_header(&header).to_vec();
                                    frame.extend(body);
                                    senders[direction]
                                        .send((1, veil_bufpool::pooled_shared_from_vec(frame)))
                                        .await
                                        .unwrap();
                                }
                                writer_attempts[direction].notified().await;
                                continue;
                            }
                            let [primary, secondary, additional] = backlog_start.unwrap();
                            if diagnostics[direction].sent(0) < primary + 24
                                || diagnostics[direction].sent(2) < secondary + 8
                                || diagnostics[direction].sent(3) < additional + 8
                            {
                                continue;
                            }
                        }
                        break;
                    }
                }
            }
        }
    })
    .await;
    // Aborting a runner must also drop its receive task and transport clones.
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    assert!(
        result.is_ok(),
        "local QUIC channels stalled (blocked_reliable={blocked_reliable}); sent={:?}",
        diagnostics
            .iter()
            .map(|observations| [0, 2, 3].map(|lane| observations.sent(lane)))
            .collect::<Vec<_>>()
    );
    if parallel {
        for observations in &diagnostics {
            assert!(
                observations.sent(0) >= 8,
                "primary must leave the shared connection"
            );
            assert!(
                observations.sent(2) >= 8,
                "secondary must use its own connection too"
            );
            assert!(
                observations.sent(3) >= 8,
                "additional source must use its own connection"
            );
            assert_eq!(observations.sent(1), 0, "transit must remain neutral");
            if rotate {
                assert!(
                    observations.rekeys() >= 1,
                    "canonical rekey did not complete"
                );
                assert!(
                    observations.sent_this_generation(0) >= 8,
                    "primary did not rebind"
                );
                assert!(
                    observations.sent_this_generation(2) >= 8,
                    "secondary did not rebind"
                );
                assert!(
                    observations.sent_this_generation(3) >= 8,
                    "additional source did not rebind"
                );
            }
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while diagnostics
                .iter()
                .any(|observations| observations.active_connections() != 0)
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("child tasks/connections survived their session");
    }
}

#[tokio::test]
async fn local_sources_keep_sending_with_a_full_reliable_writer_queue() {
    runner_channels_with_backlog(true, true, false, true, false, true).await;
}

#[tokio::test]
async fn resumed_shared_quic_sessions_keep_both_independent_senders() {
    runner_channels_over_real_quic(true, true, false, true, true).await;
}

#[tokio::test]
async fn opaque_channels_run_bidirectionally_over_real_quic() {
    runner_channels_over_real_quic(true, false, false, false, false).await;
}

#[tokio::test]
async fn legacy_datagram_lane_still_runs_bidirectionally_over_real_quic() {
    runner_channels_over_real_quic(false, false, false, false, false).await;
}

/// Stop the primary writer after QUIC setup, retaining the same connection's
/// real datagram handle. No fake dispatcher or mocked datagram transport.
struct StoppedStreamWriter {
    stream: BoxIoStream,
    attempted: Arc<tokio::sync::Notify>,
}

impl tokio::io::AsyncRead for StoppedStreamWriter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for StoppedStreamWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.attempted.notify_one();
        std::task::Poll::Pending
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.stream).poll_shutdown(cx)
    }
}

async fn runner_circuit_datagrams_over_real_quic(
    negotiated: bool,
    stop_writer: bool,
    offer_lane: bool,
) {
    use veil_anonymity::{
        circuit_data::{CircuitCellBytes, Direction, apply_layer, wrap_payload},
        circuit_origin::{OriginCircuit, OriginCircuitTable},
        circuit_wire::CircuitDataPayload,
    };
    use veil_proto::family::RelayChainMsg;
    let a_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (a_addr, b_addr) = (
        a_socket.local_addr().unwrap(),
        b_socket.local_addr().unwrap(),
    );
    let context = Arc::new(TransportContext::for_debug().unwrap());
    let b_context = Arc::clone(&context);
    let b_task = tokio::spawn(async move {
        promote_punched_quic(b_socket, a_addr, b_context, PunchedQuicRole::Responder).await
    });
    let a = promote_punched_quic(a_socket, b_addr, context, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    let a_datagrams = a.quic_datagrams().unwrap();
    let mut a_stream = a.into_stream().unwrap();
    a_stream.write_all(b"test").await.unwrap();
    let b = b_task.await.unwrap().unwrap();
    let b_datagrams = b.quic_datagrams().unwrap();
    let mut b_stream = b.into_stream().unwrap();
    b_stream.read_exact(&mut [0u8; 4]).await.unwrap();

    let cell_bytes = CircuitCellBytes::legacy(); // 16 KiB: real fragmentation
    let circuit_key = [0x44; 32];
    let circuit_id = 4242;
    let circuit_frame = |circuit_id, seq, msg| {
        let bytes = vec![seq as u8; 250];
        let mut cipher = wrap_payload(&bytes, cell_bytes).unwrap();
        apply_layer(&circuit_key, Direction::Return, seq, &mut cipher);
        let body = CircuitDataPayload {
            circuit_id,
            seq,
            ciphertext: cipher,
        }
        .encode(cell_bytes)
        .unwrap();
        let mut header = FrameHeader::new(FrameFamily::RelayChain as u8, msg as u16);
        header.set_priority(veil_proto::priority::INTERACTIVE);
        header.body_len = body.len() as u32;
        let mut frame = encode_header(&header).to_vec();
        frame.extend(body);
        (
            veil_proto::priority::INTERACTIVE,
            veil_bufpool::pooled_shared_from_vec(frame),
        )
    };
    let mut tasks = Vec::new();
    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    let mut stopped = Vec::new();
    for (stream, datagrams, tx_key, rx_key) in [
        (a_stream, a_datagrams, [1; 32], [2; 32]),
        (b_stream, b_datagrams, [2; 32], [1; 32]),
    ] {
        let (_, dummy) = tokio::io::duplex(64);
        let (mut runner, _) = make_swap_runner(dummy);
        let mut dispatcher = make_test_dispatcher(NodeRole::Core);
        dispatcher.circuit_origin = Some(Arc::new(OriginCircuitTable::new()));
        let mut circuit_receivers = Vec::new();
        for id in [circuit_id, circuit_id + 1] {
            dispatcher
                .circuit_origin
                .as_ref()
                .unwrap()
                .insert(Arc::new(OriginCircuit {
                    cell_bytes,
                    circuit_keys: vec![circuit_key],
                    first_hop: [1; 32],
                    origin_circuit_id: id,
                    created_unix: 0,
                    confirmed: Arc::default(),
                    is_reply: false,
                    last_return_unix: Arc::default(),
                }));
            let (recv_tx, recv_rx) = mpsc::channel(32);
            dispatcher.stream_recv.lock().unwrap().insert(id, recv_tx);
            circuit_receivers.push(recv_rx);
        }
        let attempted = Arc::new(tokio::sync::Notify::new());
        stopped.push(Arc::clone(&attempted));
        runner.stream = if stop_writer {
            Box::new(StoppedStreamWriter { stream, attempted })
        } else {
            stream
        };
        runner.quic_datagrams = offer_lane.then_some(RealtimeLaneOffer {
            handle: datagrams,
            peer_rotates: true,
            peer_flows: true,
            peer_circuit_datagrams: negotiated,
            parallel: None,
        });
        runner.session_id = [3; 32];
        runner.raw_session_keys = Some((tx_key, rx_key, [3; 32]));
        let (out_tx, out_rx) = mpsc::channel(32);
        runner.outbox = Some(out_rx.into());
        let dispatcher = Arc::new(dispatcher);
        runner.ban_list = Arc::clone(&dispatcher.abuse.ban_list);
        runner.violation_tracker = Arc::clone(&dispatcher.abuse.violation_tracker);
        runner.logger = Arc::clone(&dispatcher.logger);
        runner.dispatcher = dispatcher;
        tasks.push(tokio::spawn(async move { runner.run().await }));
        senders.push(out_tx);
        receivers.push(circuit_receivers);
    }
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        for direction in 0..2 {
            if stop_writer {
                // Reliable control/file cells are already held by the writer.
                senders[direction]
                    .send(circuit_frame(circuit_id, 1, RelayChainMsg::CircuitData))
                    .await
                    .unwrap();
                stopped[direction].notified().await;
                assert!(
                    receivers[1 - direction]
                        .iter_mut()
                        .all(|rx| rx.try_recv().is_err())
                );
            }
            for seq in 2..=7 {
                for (index, id) in [circuit_id, circuit_id + 1].into_iter().enumerate() {
                    senders[direction]
                        .send(circuit_frame(id, seq, RelayChainMsg::CircuitDatagram))
                        .await
                        .unwrap();
                    let got = receivers[1 - direction][index].recv().await.unwrap();
                    assert_eq!(got, vec![seq as u8; 250]);
                }
            }
            // Reliable seq=1 never rode the datagram lane.
            assert!(
                receivers[1 - direction]
                    .iter_mut()
                    .all(|rx| rx.try_recv().is_err())
            );
        }
    })
    .await;
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    assert!(
        result.is_ok(),
        "circuit transport must deliver in both directions, negotiated={negotiated}, stopped={stop_writer}"
    );
}

#[tokio::test]
async fn circuit_datagrams_survive_stopped_ordered_writers_over_real_quic() {
    runner_circuit_datagrams_over_real_quic(true, true, true).await;
}

#[tokio::test]
async fn older_opaque_flow_peer_receives_circuit_cells_via_legacy_stream() {
    runner_circuit_datagrams_over_real_quic(false, false, true).await;
}

#[tokio::test]
async fn circuit_cells_preserve_stream_only_transport_fallback() {
    runner_circuit_datagrams_over_real_quic(true, false, false).await;
}

#[tokio::test]
async fn independent_parallel_senders_deliver_through_actual_runners_with_stopped_main_writers() {
    runner_channels_over_real_quic(true, true, false, false, false).await;
}

#[tokio::test]
async fn independent_parallel_senders_rebind_after_actual_canonical_rekey() {
    runner_channels_over_real_quic(true, true, true, false, false).await;
}

#[tokio::test]
async fn shared_listener_parallel_senders_deliver_with_stopped_main_writers() {
    runner_channels_over_real_quic(true, true, false, true, false).await;
}

#[tokio::test]
async fn shared_listener_parallel_senders_rebind_after_actual_canonical_rekey() {
    runner_channels_over_real_quic(true, true, true, true, false).await;
}

/// Two clients share one relay listener. Replies must use the authenticated
/// ingress child through the relay's existing neutral outbox, never source
/// priority slots. Real QUIC sockets and the actual dispatcher/runner are used.
async fn duplex_children_through_neutral_relay(rotate: bool) {
    use veil_anonymity::{
        circuit_data::{CircuitCellBytes, Direction, apply_layer, wrap_payload},
        circuit_origin::{OriginCircuit, OriginCircuitTable},
        circuit_setup::CircuitInstall,
        circuit_table::CircuitTable,
        circuit_wire::CircuitDataPayload,
    };
    use veil_proto::family::RelayChainMsg;
    let context = Arc::new(TransportContext::for_debug().unwrap());
    let uri: TransportUri = "quic://127.0.0.1:0".parse().unwrap();
    let listener: Arc<dyn TransportListener> = Arc::from(
        QuicTransport
            .bind(&uri, Arc::clone(&context))
            .await
            .unwrap(),
    );
    let uri: TransportUri = format!("quic://{}", listener.local_addr()).parse().unwrap();
    let registry = Arc::new(ParallelRegistry::default());
    let cell_bytes = CircuitCellBytes::new(4096).unwrap(); // fragmented real datagrams
    let relay_key = [0x44; 32];
    let receiver_key = [0x55; 32];
    let relay_id = [2; 32];
    let client_ids = [[1; 32], [3; 32]];
    let mut relay = make_test_dispatcher(NodeRole::Core);
    relay.circuit_table = Some(Arc::new(CircuitTable::new()));
    for cid in [42, 142] {
        relay
            .circuit_table
            .as_ref()
            .unwrap()
            .install(
                &CircuitInstall {
                    circuit_id_in: cid,
                    circuit_id_out: cid + 1,
                    circuit_key: relay_key,
                    cell_bytes,
                },
                client_ids[0],
                Some(client_ids[1]),
                0,
            )
            .unwrap();
    }
    let mut tx_registry = SessionTxRegistry::new();
    let relay_outboxes = client_ids.map(|peer| tx_registry.register(peer));
    relay.session_tx_registry = Some(Arc::new(RwLock::new(tx_registry)));
    let relay = Arc::new(relay);
    let mut tasks = Vec::new();
    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    let mut source_observations = Vec::new();
    let mut relay_observations = Vec::new();
    for (direction, relay_outbox) in relay_outboxes.into_iter().enumerate() {
        let acceptor = Arc::clone(&listener);
        let accepted = tokio::spawn(async move { acceptor.accept().await });
        let client = QuicTransport
            .connect(&uri, Arc::clone(&context))
            .await
            .unwrap();
        let client_datagrams = client.quic_datagrams().unwrap();
        let client_parallel = client.parallel_quic().unwrap();
        let mut client_stream = client.into_stream().unwrap();
        client_stream.write_all(b"test").await.unwrap();
        let connection = accepted.await.unwrap().unwrap();
        let relay_datagrams = connection.quic_datagrams().unwrap();
        let relay_parallel = connection.parallel_quic().unwrap();
        let mut relay_stream = connection.into_stream().unwrap();
        relay_stream.read_exact(&mut [0; 4]).await.unwrap();
        let mut endpoint = make_test_dispatcher(NodeRole::Core);
        endpoint.circuit_origin = Some(Arc::new(OriginCircuitTable::new()));
        let mut cell_receivers = Vec::new();
        for cid in [42, 142] {
            let cid = cid + direction as u32;
            endpoint
                .circuit_origin
                .as_ref()
                .unwrap()
                .insert(Arc::new(OriginCircuit {
                    cell_bytes,
                    circuit_keys: vec![if direction == 0 {
                        relay_key
                    } else {
                        receiver_key
                    }],
                    first_hop: relay_id,
                    origin_circuit_id: cid,
                    created_unix: 0,
                    confirmed: Arc::default(),
                    is_reply: false,
                    last_return_unix: Arc::default(),
                }));
            let (tx, rx) = mpsc::channel(32);
            endpoint.stream_recv.lock().unwrap().insert(cid, tx);
            cell_receivers.push(rx);
        }
        receivers.push(cell_receivers);
        let endpoint = Arc::new(endpoint);
        let (out_tx, out_rx) = veil_session::frame_outbox::frame_channel(32);
        senders.push(out_tx);
        let client_key = [direction as u8 + 10; 32];
        let relay_session_key = [direction as u8 + 20; 32];
        let sid = [direction as u8 + 30; 32];
        let client_offer = ParallelQuicOffer::new(client_parallel).with_duplex();
        source_observations.push(client_offer.diagnostics());
        let relay_offer = ParallelQuicOffer::new(relay_parallel)
            .with_registry(Arc::clone(&registry))
            .with_duplex();
        relay_observations.push(relay_offer.diagnostics());
        for (stream, datagrams, offer, dispatcher, outbox, local, peer, tx, rx) in [
            (
                client_stream,
                client_datagrams,
                client_offer,
                endpoint,
                out_rx,
                client_ids[direction],
                relay_id,
                client_key,
                relay_session_key,
            ),
            (
                relay_stream,
                relay_datagrams,
                relay_offer,
                Arc::clone(&relay),
                relay_outbox,
                relay_id,
                client_ids[direction],
                relay_session_key,
                client_key,
            ),
        ] {
            let (_, dummy) = tokio::io::duplex(64);
            let (mut runner, _) = make_swap_runner(dummy);
            // Stop all ordered writers. The bidirectional relay path must
            // retain its datagrams without creating canonical peer sessions.
            runner.stream = if rotate {
                stream
            } else {
                Box::new(StoppedStreamWriter {
                    stream,
                    attempted: Arc::new(tokio::sync::Notify::new()),
                })
            };
            runner.quic_datagrams = Some(RealtimeLaneOffer {
                handle: datagrams,
                peer_rotates: true,
                peer_flows: true,
                peer_circuit_datagrams: true,
                parallel: Some(offer),
            });
            runner.local_node_id = local;
            runner.peer_id = peer;
            runner.session_id = sid;
            runner.raw_session_keys = Some((tx, rx, sid));
            if rotate {
                runner.crypto.tx_cipher =
                    Some(veil_crypto::session_cipher::SessionCipher::new(&tx, true));
                runner.crypto.rx_cipher =
                    Some(veil_crypto::session_cipher::SessionCipher::new(&rx, true));
                if local < peer {
                    runner.rekey.time_threshold_secs = 1;
                }
            }
            runner.outbox = Some(outbox);
            runner.ban_list = Arc::clone(&dispatcher.abuse.ban_list);
            runner.violation_tracker = Arc::clone(&dispatcher.abuse.violation_tracker);
            runner.logger = Arc::clone(&dispatcher.logger);
            runner.dispatcher = dispatcher;
            tasks.push(tokio::spawn(async move { runner.run().await }));
        }
    }
    tasks.push(tokio::spawn(async move {
        loop {
            let connection = listener.accept().await.unwrap();
            let datagrams = connection.quic_datagrams();
            let stream = connection.into_stream().unwrap();
            assert!(matches!(
                registry.peek_and_dispatch(stream, datagrams).await,
                ParallelPeekOutcome::Bound | ParallelPeekOutcome::Drop(_)
            ));
        }
    }));
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        // Prepare both local receive channels with no data frame whatsoever.
        // An idle runner must wake, bind and publish readiness on TLS adoption.
        warm_receive_only_channels(&senders).await;
        for d in &source_observations {
            assert_eq!(d.sent(0), 0);
            assert_eq!(d.sent(2), 0);
            assert_eq!(d.sent(3), 0);
        }
        for d in &relay_observations {
            assert_eq!(d.sent(0), 0);
            assert_eq!(d.sent(2), 0);
            assert_eq!(d.sent(3), 0);
            assert_eq!(d.replies(), 0);
        }
        let mut first_epoch_done = false;
        let mut replies_before = [0; 2];
        for seq in 1..=200u32 {
            for direction in 0..2 {
                for (index, cid) in [42, 142].into_iter().enumerate() {
                    let payload = vec![seq as u8, index as u8, direction as u8];
                    let mut cipher = wrap_payload(&payload, cell_bytes).unwrap();
                    if direction == 0 {
                        apply_layer(&receiver_key, Direction::Return, seq, &mut cipher);
                        apply_layer(&relay_key, Direction::Forward, seq, &mut cipher);
                    }
                    let body = CircuitDataPayload {
                        circuit_id: cid + direction as u32,
                        seq,
                        ciphertext: cipher,
                    }
                    .encode(cell_bytes)
                    .unwrap();
                    let mut header = FrameHeader::new(
                        FrameFamily::RelayChain as u8,
                        RelayChainMsg::CircuitDatagram as u16,
                    );
                    header.set_priority(veil_proto::priority::INTERACTIVE);
                    header.body_len = body.len() as u32;
                    let mut frame = encode_header(&header).to_vec();
                    frame.extend(body);
                    senders[direction]
                        .send((
                            if index == 0 { 0 } else { 2 },
                            veil_bufpool::pooled_shared_from_vec(frame),
                        ))
                        .await
                        .unwrap();
                    assert_eq!(
                        receivers[1 - direction][index].recv().await.unwrap(),
                        payload
                    );
                }
            }
            let ready = source_observations
                .iter()
                .all(|d| d.sent_this_generation(0) >= 8 && d.sent_this_generation(2) >= 8)
                && relay_observations
                    .iter()
                    .enumerate()
                    .all(|(i, d)| d.replies() >= replies_before[i] + 16);
            if ready {
                if !rotate || first_epoch_done {
                    break;
                }
                first_epoch_done = true;
                replies_before = [
                    relay_observations[0].replies(),
                    relay_observations[1].replies(),
                ];
                // Quiesce the producers across credential retirement. In-flight
                // loss-tolerant cells are allowed to expire during rekey.
                while source_observations
                    .iter()
                    .chain(&relay_observations)
                    .any(|d| d.rekeys() == 0)
                {
                    // This fixture disables idle/keepalive timers. Wake the
                    // real canonical loops with ordinary encrypted control
                    // traffic while circuit producers remain quiescent.
                    let ping =
                        FrameHeader::new(FrameFamily::Control as u8, ControlMsg::Ping as u16);
                    for sender in &senders {
                        sender
                            .send((
                                veil_proto::priority::INTERACTIVE,
                                veil_bufpool::pooled_shared_from_vec(encode_header(&ping).to_vec()),
                            ))
                            .await
                            .unwrap();
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                for sender in &senders {
                    assert_eq!(
                        sender.local_datagram_channel_state(0),
                        LocalDatagramChannelState::Warming
                    );
                    assert_eq!(
                        sender.local_datagram_channel_state(2),
                        LocalDatagramChannelState::Warming
                    );
                }
                warm_receive_only_channels(&senders).await;
                for d in &source_observations {
                    assert_eq!(d.sent_this_generation(0), 0);
                    assert_eq!(d.sent_this_generation(2), 0);
                    assert_eq!(d.sent_this_generation(3), 0);
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            receivers
                .iter_mut()
                .flatten()
                .all(|rx| rx.try_recv().is_err()),
            "no duplicates"
        );
    })
    .await;
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    let all_observations = source_observations.iter().chain(&relay_observations);
    tokio::time::timeout(Duration::from_secs(1), async {
        while all_observations
            .clone()
            .any(|d| d.active_connections() != 0)
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("children survived their canonical sessions");
    assert!(result.is_ok(), "duplex relay path did not converge");
    for sender in &senders {
        assert_eq!(
            sender.local_datagram_channel_state(0),
            LocalDatagramChannelState::Unsupported
        );
        assert_eq!(
            sender.local_datagram_channel_state(2),
            LocalDatagramChannelState::Unsupported
        );
    }
    for d in source_observations {
        assert!(d.sent(0) >= 8 && d.sent(2) >= 8);
        if rotate {
            assert!(d.rekeys() >= 1);
            assert!(d.sent_this_generation(0) >= 8 && d.sent_this_generation(2) >= 8);
        }
    }
    for d in relay_observations {
        assert!(
            d.replies() >= 16,
            "relay must reuse admitted generic ingress children"
        );
        assert_eq!(d.sent(0), 0, "relay cannot choose source priority channels");
        assert_eq!(d.sent(2), 0, "relay cannot choose source priority channels");
        assert_eq!(d.sent(3), 0, "relay cannot choose source priority channels");
    }
}

#[tokio::test]
async fn duplex_children_route_both_directions_through_neutral_relay() {
    duplex_children_through_neutral_relay(false).await;
}

#[tokio::test]
async fn duplex_relay_children_rebind_after_canonical_rekey() {
    duplex_children_through_neutral_relay(true).await;
}

async fn warm_receive_only_channels(senders: &[FrameSender]) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut ready = true;
            for sender in senders {
                assert_eq!(
                    sender.request_local_datagram_channel(1),
                    LocalDatagramChannelState::Unsupported
                );
                for lane in [0, 2, 3] {
                    ready &= sender.request_local_datagram_channel(lane)
                        == LocalDatagramChannelState::Ready;
                }
            }
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("receive-only source channels did not bind without data frames");
}

#[path = "neutral_chain_tests.rs"]
mod neutral_chain_tests;
