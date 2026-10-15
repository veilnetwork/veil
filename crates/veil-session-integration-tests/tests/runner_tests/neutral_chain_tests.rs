//! Actual QUIC or obfs4/TCP A <-> R1 <-> R2 <-> C, with neutral relay FIFOs.
use super::*;
use veil_anonymity::{
    circuit_data::{CircuitCellBytes, Direction, apply_layer, wrap_payload},
    circuit_origin::{OriginCircuit, OriginCircuitTable},
    circuit_setup::CircuitInstall,
    circuit_table::CircuitTable,
    circuit_wire::CircuitDataPayload,
};
use veil_proto::family::RelayChainMsg;
use veil_session::dispatcher_sink::DispatchResult;

struct ChainTasks(Vec<tokio::task::JoinHandle<()>>);
impl Drop for ChainTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

#[allow(clippy::await_holding_lock)]
async fn chain(rotate: bool, ordered: bool, forwards: bool) {
    let _rotation = epic488_1_lock();
    let mut context = TransportContext::for_debug().unwrap();
    context.obfs4_psk = Some(Arc::new([0x42; 32]));
    let context = Arc::new(context);
    let transport: Box<dyn Transport> = if ordered {
        Box::new(veil_transport::obfs4_tcp::Obfs4TcpTransport)
    } else {
        Box::new(QuicTransport)
    };
    let mut listeners = Vec::new();
    let registries: Vec<_> = (0..4)
        .map(|_| Arc::new(ParallelRegistry::default()))
        .collect();
    for _ in 0..4 {
        let uri: TransportUri = format!("{}://127.0.0.1:0", transport.scheme())
            .parse()
            .unwrap();
        listeners.push(Arc::<dyn TransportListener>::from(
            transport.bind(&uri, Arc::clone(&context)).await.unwrap(),
        ));
    }
    let ids = [[1; 32], [2; 32], [3; 32], [4; 32]];
    let keys = [[0x44; 32], [0x66; 32]];
    let receiver_key = [0x55; 32];
    let cell_bytes = CircuitCellBytes::new(4096).unwrap();
    // Two installed circuits need distinct live generic connections, without
    // exceeding the fixed per-neighbor quota. The previous bucket allocator
    // needed sixteen IDs to sample its two hashes; ownership no longer hashes
    // distinct installed circuits together. Capacity rejection is covered by
    // the channel-assignment saturation tests.
    let circuits: Vec<u32> = (100..102).collect();
    let mut dispatchers = Vec::new();
    let mut probes = Vec::new();
    let mut outboxes = std::collections::HashMap::new();
    let mut producers = std::collections::HashMap::new();
    let mut receivers = Vec::new();
    let mut forward_receivers = Vec::new();
    let mut forward_endpoints = Vec::new();
    let app = [0xa0; 32];
    for node in 0usize..4 {
        let mut dispatcher = make_test_dispatcher(NodeRole::Core);
        dispatcher.local_node_id = ids[node];
        if forwards {
            // Both identities have the same route across the two neutral hops.
            let destination = if node < 2 { 3 } else { 0 };
            let next = if node < 2 { node + 1 } else { node - 1 };
            dispatcher.route_cache.write().unwrap().insert(
                ids[destination],
                ids[next],
                1,
                node.abs_diff(destination) as u8,
            );
            if node == 0 || node == 3 {
                let (endpoint, receiver) = dispatcher.app_registry.register(app, 1, 64);
                forward_endpoints.push(endpoint);
                forward_receivers.push(receiver);
            }
        }
        let mut tx_registry = SessionTxRegistry::new();
        for neighbor in (0..4).filter(|&other| node.abs_diff(other) == 1) {
            outboxes.insert((node, neighbor), tx_registry.register(ids[neighbor]));
            producers.insert(
                (node, neighbor),
                tx_registry.get_sender(&ids[neighbor]).unwrap().clone(),
            );
        }
        dispatcher.session_tx_registry = Some(Arc::new(RwLock::new(tx_registry)));
        if node == 0 || node == 3 {
            dispatcher.circuit_origin = Some(Arc::new(OriginCircuitTable::new()));
            let mut endpoint_receivers = Vec::new();
            for &cid in &circuits {
                let cid = cid + if node == 0 { 0 } else { 2000 };
                dispatcher
                    .circuit_origin
                    .as_ref()
                    .unwrap()
                    .insert(Arc::new(OriginCircuit {
                        cell_bytes,
                        circuit_keys: if node == 0 {
                            keys.to_vec()
                        } else {
                            vec![receiver_key]
                        },
                        first_hop: ids[if node == 0 { 1 } else { 2 }],
                        origin_circuit_id: cid,
                        created_unix: 0,
                        confirmed: Arc::default(),
                        is_reply: false,
                        last_return_unix: Arc::default(),
                    }));
                let (tx, rx) = mpsc::channel(32);
                dispatcher.stream_recv.lock().unwrap().insert(cid, tx);
                endpoint_receivers.push(rx);
            }
            receivers.push(endpoint_receivers);
        } else {
            let table = Arc::new(CircuitTable::new());
            for &cid in &circuits {
                table
                    .install(
                        &CircuitInstall {
                            circuit_id_in: cid + (node as u32 - 1) * 1000,
                            circuit_id_out: cid + node as u32 * 1000,
                            circuit_key: keys[node - 1],
                            cell_bytes,
                        },
                        ids[node - 1],
                        Some(ids[node + 1]),
                        0,
                    )
                    .unwrap();
            }
            dispatcher.circuit_table = Some(table);
        }
        let dispatcher = Arc::new(dispatcher);
        probes.push(Arc::new(ForwardProbe {
            dispatcher: dispatcher.clone(),
            connections: Mutex::new(Vec::new()),
        }));
        dispatchers.push(dispatcher);
    }
    let mut tasks = ChainTasks(Vec::new());
    let mut observations = Vec::new();
    let mut source_observations = Vec::new();
    let mut bridge_observations = Vec::new();
    for left in 0..3 {
        let right = left + 1;
        let listener = Arc::clone(&listeners[right]);
        let uri: TransportUri = format!("{}://{}", transport.scheme(), listener.local_addr())
            .parse()
            .unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await });
        let connection = transport.connect(&uri, Arc::clone(&context)).await.unwrap();
        let datagrams = connection.quic_datagrams();
        let parallel = connection.parallel_quic();
        let ordered_offer = connection.parallel_stream();
        let mut stream = connection.into_stream().unwrap();
        stream.write_all(b"test").await.unwrap();
        stream.flush().await.unwrap();
        let incoming = accepted.await.unwrap().unwrap();
        let incoming_datagrams = incoming.quic_datagrams();
        let incoming_parallel = incoming.parallel_quic();
        let incoming_ordered = incoming.parallel_stream();
        let mut incoming_stream = incoming.into_stream().unwrap();
        incoming_stream.read_exact(&mut [0; 4]).await.unwrap();
        let left_key = [10 + left as u8; 32];
        let right_key = [20 + left as u8; 32];
        let sid = [30 + left as u8; 32];
        for (node, peer, stream, datagrams, parallel, ordered_offer, tx, rx) in [
            (
                left,
                right,
                stream,
                datagrams,
                parallel,
                ordered_offer,
                left_key,
                right_key,
            ),
            (
                right,
                left,
                incoming_stream,
                incoming_datagrams,
                incoming_parallel,
                incoming_ordered,
                right_key,
                left_key,
            ),
        ] {
            let (realtime_transport, parallel, diagnostic) = if ordered {
                let offer = ParallelOrderedOffer::new(
                    ordered_offer.unwrap(),
                    Arc::clone(&registries[node]),
                );
                let diagnostic = offer.diagnostics();
                (RealtimeTransportOffer::Ordered(offer), None, diagnostic)
            } else {
                let offer = ParallelQuicOffer::new(parallel.unwrap())
                    .with_registry(Arc::clone(&registries[node]))
                    .with_duplex();
                let diagnostic = offer.diagnostics();
                (
                    RealtimeTransportOffer::Quic(datagrams.unwrap()),
                    Some(offer),
                    diagnostic,
                )
            };
            observations.push((node, Arc::clone(&diagnostic)));
            if node == 0 || node == 3 {
                source_observations.push(Arc::clone(&diagnostic));
            }
            if left == 1 {
                bridge_observations.push(diagnostic);
            }
            let (_, dummy) = tokio::io::duplex(64);
            let (mut runner, _) = make_swap_runner(dummy);
            runner.stream = if rotate {
                stream
            } else {
                Box::new(StoppedStreamWriter {
                    stream,
                    attempted: Arc::new(tokio::sync::Notify::new()),
                })
            };
            runner.quic_datagrams = Some(RealtimeLaneOffer {
                peer_datagrams: true,
                transport: realtime_transport,
                peer_rotates: true,
                peer_flows: true,
                peer_circuit_datagrams: true,
                peer_neutral_forwards: true,
                parallel,
            });
            runner.local_node_id = ids[node];
            runner.peer_id = ids[peer];
            runner.session_id = sid;
            runner.raw_session_keys = Some((tx, rx, sid));
            if rotate {
                runner.crypto.tx_cipher =
                    Some(veil_crypto::session_cipher::SessionCipher::new(&tx, true));
                runner.crypto.rx_cipher =
                    Some(veil_crypto::session_cipher::SessionCipher::new(&rx, true));
                if node < peer {
                    runner.rekey.time_threshold_secs = 1;
                }
            }
            runner.outbox = Some(outboxes.remove(&(node, peer)).unwrap());
            let dispatcher = Arc::clone(&dispatchers[node]);
            runner.ban_list = Arc::clone(&dispatcher.abuse.ban_list);
            runner.violation_tracker = Arc::clone(&dispatcher.abuse.violation_tracker);
            runner.logger = Arc::clone(&dispatcher.logger);
            runner.dispatcher = if forwards {
                probes[node].clone()
            } else {
                dispatcher
            };
            tasks
                .0
                .push(tokio::spawn(async move { runner.run().await }));
        }
    }
    for (listener, registry) in listeners.into_iter().zip(registries) {
        tasks.0.push(tokio::spawn(async move {
            loop {
                let connection = listener.accept().await.unwrap();
                let datagrams = connection.quic_datagrams();
                let binding = connection.stream_channel_binding();
                let stream = connection.into_stream().unwrap();
                let outcome = if ordered {
                    registry
                        .peek_and_dispatch_with_binding(stream, datagrams, binding)
                        .await
                } else {
                    registry.peek_and_dispatch(stream, datagrams).await
                };
                assert!(matches!(
                    outcome,
                    ParallelPeekOutcome::Bound | ParallelPeekOutcome::Drop(_)
                ));
            }
        }));
    }
    let source_senders = [producers[&(0, 1)].clone(), producers[&(3, 2)].clone()];
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        warm_receive_only_channels(&source_senders).await;
        if ordered {
            tokio::time::timeout(Duration::from_secs(5), async {
                while observations
                    .iter()
                    .any(|(_, d)| d.active_connections() != 6)
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("relay ordered pools did not bind");
        }
        if forwards {
            forward_frames(
                rotate,
                &source_senders,
                &producers,
                &mut forward_receivers,
                &source_observations,
                &bridge_observations,
                &observations,
                ids,
                app,
                &probes,
            )
            .await;
            return;
        }
        let mut first_epoch_done = false;
        for seq in 1..=300u32 {
            for direction in 0..2 {
                for (index, &cid) in circuits.iter().enumerate() {
                    let payload = vec![seq as u8, index as u8, direction as u8];
                    let mut cipher = wrap_payload(&payload, cell_bytes).unwrap();
                    if direction == 0 {
                        apply_layer(&receiver_key, Direction::Return, seq, &mut cipher);
                        for key in keys.iter().rev() {
                            apply_layer(key, Direction::Forward, seq, &mut cipher);
                        }
                    }
                    let body = CircuitDataPayload {
                        circuit_id: cid + if direction == 0 { 0 } else { 2000 },
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
                    source_senders[direction]
                        .send((
                            if index % 2 == 0 { 0 } else { 2 },
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
                && bridge_observations.iter().any(|d| {
                    d.transit_sent_this_generation() >= 16
                        && (2..veil_transport::QuicParallelHandle::CONNECTIONS_PER_DIRECTION)
                            .contains(&d.transit_shards_used_this_generation())
                })
                && observations
                    .iter()
                    .filter(|(n, _)| *n == 1 || *n == 2)
                    .all(|(_, d)| d.replies() + d.transit_sent() >= 16);
            if ready {
                if !rotate || first_epoch_done {
                    break;
                }
                first_epoch_done = true;
                while observations.iter().any(|(_, d)| d.rekeys() == 0) {
                    let ping =
                        FrameHeader::new(FrameFamily::Control as u8, ControlMsg::Ping as u16);
                    for sender in producers.values() {
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
                assert!(
                    bridge_observations
                        .iter()
                        .all(|d| d.transit_sent_this_generation() == 0)
                );
                warm_receive_only_channels(&source_senders).await;
                if ordered {
                    tokio::time::timeout(Duration::from_secs(5), async {
                        while observations
                            .iter()
                            .any(|(_, d)| d.active_connections() != 6)
                        {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    })
                    .await
                    .expect("relay ordered pools did not rebind");
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            source_observations
                .iter()
                .all(|d| d.sent_this_generation(0) >= 8 && d.sent_this_generation(2) >= 8)
        );
        assert!(
            bridge_observations
                .iter()
                .any(|d| d.transit_sent_this_generation() >= 16
                    && (2..veil_transport::QuicParallelHandle::CONNECTIONS_PER_DIRECTION)
                        .contains(&d.transit_shards_used_this_generation())),
            "bridge did not use multiple connections within its neutral quota"
        );
        for (node, d) in &observations {
            if *node == 1 || *node == 2 {
                assert_eq!(d.sent(0), 0, "relay selected a source priority channel");
                assert_eq!(d.sent(2), 0, "relay selected a source priority channel");
                assert_eq!(d.sent(3), 0, "relay selected a source priority channel");
                assert_eq!(
                    d.sent(veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE),
                    0,
                    "relay selected a source priority channel"
                );
            }
            if rotate {
                assert!(d.rekeys() > 0);
            }
        }
        assert!(
            receivers
                .iter_mut()
                .flatten()
                .all(|rx| rx.try_recv().is_err()),
            "duplicate cells"
        );
    })
    .await;
    for task in tasks.0.drain(..) {
        task.abort();
        let _ = task.await;
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while observations
            .iter()
            .any(|(_, d)| d.active_connections() != 0)
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("children survived canonical teardown");
    for sender in source_senders {
        for lane in [0, 2, 3, veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE] {
            assert_eq!(
                sender.local_datagram_channel_state(lane),
                LocalDatagramChannelState::Unsupported
            );
        }
    }
    assert!(result.is_ok(), "two-relay chain stalled: {result:?}");
}

#[tokio::test]
async fn two_relays_use_bounded_neutral_quic_shards() {
    chain(false, false, false).await;
}

#[tokio::test]
async fn neutral_chain_rebinds_after_real_canonical_rekey() {
    chain(true, false, false).await;
}

#[tokio::test]
async fn two_relays_use_bounded_neutral_ordered_shards() {
    chain(false, true, false).await;
}

#[tokio::test]
async fn neutral_ordered_chain_rebinds_after_real_canonical_rekey() {
    chain(true, true, false).await;
}

// The complete receive -> dispatch -> ordinary outbox -> outgoing selector
// path, rather than constructing or inspecting a local carrier ourselves.
// All Forward bodies use the same sender, recipient and application endpoint.
// Only source-local connection choice distinguishes the four producers.
#[allow(clippy::too_many_arguments)]
async fn forward_frames(
    rotate: bool,
    sources: &[FrameSender; 2],
    producers: &std::collections::HashMap<(usize, usize), FrameSender>,
    receivers: &mut [mpsc::Receiver<veil_app::registry::AppMessage>],
    source_observations: &[Arc<veil_session::runner::ParallelDiagnostics>],
    bridge_observations: &[Arc<veil_session::runner::ParallelDiagnostics>],
    observations: &[(usize, Arc<veil_session::runner::ParallelDiagnostics>)],
    ids: [[u8; 32]; 4],
    app: [u8; 32],
    probes: &[Arc<ForwardProbe>],
) {
    use veil_app::registry::AppMessage;
    use veil_proto::{
        delivery::{DeliveryEnvelope, ForwardPayload},
        family::DeliveryMsg,
    };
    let lanes = [0, 2, 3, veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE];
    warm_forward_channels(sources, &lanes).await;
    let ready = || {
        source_observations
            .iter()
            .all(|d| lanes.iter().all(|&lane| d.sent_this_generation(lane) >= 8))
            && bridge_observations.iter().all(|d| {
                d.transit_sent_this_generation() >= 24
                    && d.transit_shards_used_this_generation() >= lanes.len()
            })
            && probes.iter().enumerate().all(|(node, probe)| {
                (0..4)
                    .filter(|&peer| node.abs_diff(peer) == 1)
                    .all(|peer| probe.live_connections(ids[peer]) >= lanes.len())
            })
    };
    let mut first_epoch_done = false;
    for seq in 1..=300u32 {
        for direction in 0..2 {
            let origin = if direction == 0 { 0 } else { 3 };
            let destination = 3 - origin;
            for (index, &lane) in lanes.iter().enumerate() {
                let data = format!("neutral forward {seq}/{index}/{direction}").into_bytes();
                let body = ForwardPayload {
                    next_hop_node_id: ids[if direction == 0 { 1 } else { 2 }],
                    relay_hops: 0,
                    delivery_attempt: None,
                    traffic_class: Some(veil_proto::priority::INTERACTIVE),
                    envelope: DeliveryEnvelope {
                        recipient: veil_proto::recipient::Recipient::any(ids[destination]),
                        sender_node_id: ids[origin],
                        src_app_id: app,
                        app_id: app,
                        endpoint_id: 1,
                        content_id: *blake3::hash(&data).as_bytes(),
                        created_at: veil_util::unix_secs_now_u64(),
                        ttl_secs: veil_proto::delivery::FORWARD_REALTIME_TTL_SECS,
                        payload: data.clone(),
                        trace_id: 0,
                        require_ack: false,
                    },
                }
                .encode();
                let mut header =
                    FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
                header.set_priority(veil_proto::priority::INTERACTIVE);
                header.body_len = body.len() as u32;
                let mut frame = encode_header(&header).to_vec();
                frame.extend(body);
                sources[direction]
                    .send((lane, veil_bufpool::pooled_shared_from_vec(frame)))
                    .await
                    .unwrap();
                match receivers[1 - direction].recv().await.unwrap() {
                    AppMessage::Deliver { data: got, .. } => assert_eq!(&*got, &data),
                    other => panic!("unexpected neutral Forward dispatch {other:?}"),
                }
            }
        }
        if ready() {
            if !rotate || first_epoch_done {
                break;
            }
            first_epoch_done = true;
            while observations.iter().any(|(_, d)| d.rekeys() == 0) {
                let ping = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::Ping as u16);
                for sender in producers.values() {
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
            assert!(
                bridge_observations
                    .iter()
                    .all(|d| d.transit_sent_this_generation() == 0)
            );
            warm_forward_channels(sources, &lanes).await;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        ready(),
        "same-route Forward connections collapsed on a relay hop"
    );
    assert!(!rotate || first_epoch_done);
    assert!(
        receivers.iter_mut().all(|rx| rx.try_recv().is_err()),
        "duplicate Forwards"
    );
    for (node, diagnostics) in observations {
        if *node == 1 || *node == 2 {
            for lane in [0, 2, 3, veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE] {
                assert_eq!(diagnostics.sent(lane), 0, "relay claimed a source role");
            }
        }
    }
}

#[tokio::test]
async fn same_route_forwards_keep_four_connections_across_two_quic_relays() {
    chain(false, false, true).await;
}

#[tokio::test]
async fn same_route_forwards_keep_four_connections_across_two_ordered_relays() {
    chain(false, true, true).await;
}

#[tokio::test]
async fn same_route_forward_connections_rebind_after_quic_rekey() {
    chain(true, false, true).await;
}

#[tokio::test]
async fn same_route_forward_connections_rebind_after_ordered_rekey() {
    chain(true, true, true).await;
}

async fn warm_forward_channels(sources: &[FrameSender], lanes: &[u8]) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut ready = true;
            for source in sources {
                for &lane in lanes {
                    ready &= source.request_local_datagram_channel(lane)
                        == LocalDatagramChannelState::Ready;
                }
            }
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("all four source channels did not bind");
}

// Observes only authenticated local connection ownership, not source roles.
// Every actual dispatch/admission/accounting method delegates unchanged.
// Counting live witnesses excludes early canonical fallback and retired epochs.
struct ForwardProbe {
    dispatcher: Arc<veil_dispatcher::FrameDispatcher>,
    connections: Mutex<
        Vec<(
            NodeIdBytes,
            veil_anonymity::circuit_carrier::LocalIngressFlow,
            veil_anonymity::circuit_carrier::Carrier,
        )>,
    >,
}

impl ForwardProbe {
    fn live_connections(&self, peer: NodeIdBytes) -> usize {
        let mut connections = self.connections.lock().unwrap();
        connections.retain(|(_, key, witness)| {
            witness
                .upgrade()
                .is_some_and(|carrier| carrier.local_ingress_flow() == Some(*key))
        });
        connections
            .iter()
            .filter(|(source, _, _)| *source == peer)
            .count()
    }
}

impl veil_session::dispatcher_sink::DispatcherSink for ForwardProbe {
    fn dispatch(&self, h: &FrameHeader, body: &[u8], peer: NodeIdBytes) -> DispatchResult {
        veil_session::dispatcher_sink::DispatcherSink::dispatch(&*self.dispatcher, h, body, peer)
    }
    fn dispatch_with_carrier(
        &self,
        h: &FrameHeader,
        body: &[u8],
        peer: NodeIdBytes,
        carrier: Option<veil_anonymity::circuit_carrier::Carrier>,
    ) -> DispatchResult {
        if h.family == FrameFamily::Delivery as u8
            && h.msg_type == veil_proto::family::DeliveryMsg::Forward as u16
        {
            assert_eq!(h.priority(), veil_proto::priority::INTERACTIVE);
            if let Some((key, witness)) = carrier.as_ref().and_then(|witness| {
                witness
                    .upgrade()?
                    .local_ingress_flow()
                    .map(|key| (key, witness.clone()))
            }) {
                let _ = self.live_connections(peer);
                let mut connections = self.connections.lock().unwrap();
                if !connections
                    .iter()
                    .any(|(source, existing, _)| *source == peer && *existing == key)
                {
                    connections.push((peer, key, witness));
                }
            }
        }
        veil_session::dispatcher_sink::DispatcherSink::dispatch_with_carrier(
            &*self.dispatcher,
            h,
            body,
            peer,
            carrier,
        )
    }
    fn abort_app_stream(
        &self,
        peer: NodeIdBytes,
        stream: u32,
        app: [u8; 32],
        endpoint: u32,
        notify: bool,
    ) {
        self.dispatcher
            .abort_app_stream(peer, stream, app, endpoint, notify);
    }
    fn capture_outbound(&self, peer: NodeIdBytes, frame: &[u8]) {
        self.dispatcher.capture_outbound(peer, frame);
    }
    fn allow_outbound_bandwidth(&self, bytes: usize) -> bool {
        self.dispatcher.allow_outbound_bandwidth(bytes)
    }
    fn logger(&self) -> &Arc<veil_observability::NodeLogger> {
        &self.dispatcher.logger
    }
    fn session_tx_registry(&self) -> Option<Arc<RwLock<SessionTxRegistry>>> {
        self.dispatcher.session_tx_registry.clone()
    }
    fn dht(&self) -> &Arc<veil_dht::KademliaService> {
        &self.dispatcher.dht
    }
    fn rendezvous_weak(
        &self,
    ) -> Arc<Mutex<Option<std::sync::Weak<veil_session::rendezvous::RendezvousController>>>> {
        self.dispatcher.rendezvous_weak()
    }
    fn pow_solver_semaphore(&self) -> Arc<tokio::sync::Semaphore> {
        self.dispatcher.pow_solver_semaphore()
    }
    fn pow_active_difficulty(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.dispatcher.pow_active_difficulty()
    }
    fn route_cache(&self) -> Arc<RwLock<veil_routing::RouteCache>> {
        self.dispatcher.route_cache.clone()
    }
    fn register_session_aliases(
        &self,
        local: [u8; 8],
        local_node: NodeIdBytes,
        remote: [u8; 8],
        remote_node: NodeIdBytes,
    ) {
        self.dispatcher
            .register_session_aliases(local, local_node, remote, remote_node);
    }
    fn unregister_session_aliases(&self, local: [u8; 8], remote: [u8; 8]) {
        self.dispatcher.unregister_session_aliases(local, remote);
    }
}
