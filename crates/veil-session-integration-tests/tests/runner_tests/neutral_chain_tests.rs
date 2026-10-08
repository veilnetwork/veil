//! Actual UDP/QUIC A <-> R1 <-> R2 <-> C, with neutral relay FIFOs.
use super::*;
use veil_anonymity::{
    circuit_data::{CircuitCellBytes, Direction, apply_layer, wrap_payload},
    circuit_origin::{OriginCircuit, OriginCircuitTable},
    circuit_setup::CircuitInstall,
    circuit_table::CircuitTable,
    circuit_wire::CircuitDataPayload,
};
use veil_proto::family::RelayChainMsg;

async fn chain(rotate: bool) {
    let context = Arc::new(TransportContext::for_debug().unwrap());
    let mut listeners = Vec::new();
    let registries: Vec<_> = (0..4)
        .map(|_| Arc::new(ParallelRegistry::default()))
        .collect();
    for _ in 0..4 {
        let uri: TransportUri = "quic://127.0.0.1:0".parse().unwrap();
        listeners.push(Arc::<dyn TransportListener>::from(
            QuicTransport
                .bind(&uri, Arc::clone(&context))
                .await
                .unwrap(),
        ));
    }
    let ids = [[1; 32], [2; 32], [3; 32], [4; 32]];
    let keys = [[0x44; 32], [0x66; 32]];
    let receiver_key = [0x55; 32];
    let cell_bytes = CircuitCellBytes::new(4096).unwrap();
    // Independent opaque IDs sample both bounded shards. They carry no roles.
    let circuits: Vec<u32> = (100..116).collect();
    let mut dispatchers = Vec::new();
    let mut outboxes = std::collections::HashMap::new();
    let mut producers = std::collections::HashMap::new();
    let mut receivers = Vec::new();
    for node in 0usize..4 {
        let mut dispatcher = make_test_dispatcher(NodeRole::Core);
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
        dispatchers.push(Arc::new(dispatcher));
    }
    let mut tasks = Vec::new();
    let mut observations = Vec::new();
    let mut source_observations = Vec::new();
    let mut bridge_observations = Vec::new();
    for left in 0..3 {
        let right = left + 1;
        let listener = Arc::clone(&listeners[right]);
        let uri: TransportUri = format!("quic://{}", listener.local_addr()).parse().unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await });
        let connection = QuicTransport
            .connect(&uri, Arc::clone(&context))
            .await
            .unwrap();
        let datagrams = connection.quic_datagrams().unwrap();
        let parallel = connection.parallel_quic().unwrap();
        let mut stream = connection.into_stream().unwrap();
        stream.write_all(b"test").await.unwrap();
        let incoming = accepted.await.unwrap().unwrap();
        let incoming_datagrams = incoming.quic_datagrams().unwrap();
        let incoming_parallel = incoming.parallel_quic().unwrap();
        let mut incoming_stream = incoming.into_stream().unwrap();
        incoming_stream.read_exact(&mut [0; 4]).await.unwrap();
        let left_key = [10 + left as u8; 32];
        let right_key = [20 + left as u8; 32];
        let sid = [30 + left as u8; 32];
        for (node, peer, stream, datagrams, parallel, tx, rx) in [
            (
                left, right, stream, datagrams, parallel, left_key, right_key,
            ),
            (
                right,
                left,
                incoming_stream,
                incoming_datagrams,
                incoming_parallel,
                right_key,
                left_key,
            ),
        ] {
            let offer = ParallelQuicOffer::new(parallel)
                .with_registry(Arc::clone(&registries[node]))
                .with_duplex();
            let diagnostic = offer.diagnostics();
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
                transport: veil_session::runner::RealtimeTransportOffer::Quic(datagrams),
                peer_rotates: true,
                peer_flows: true,
                peer_circuit_datagrams: true,
                peer_neutral_forwards: true,
                parallel: Some(offer),
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
            runner.dispatcher = dispatcher;
            tasks.push(tokio::spawn(async move { runner.run().await }));
        }
    }
    for (listener, registry) in listeners.into_iter().zip(registries) {
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
    }
    let source_senders = [producers[&(0, 1)].clone(), producers[&(3, 2)].clone()];
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        warm_receive_only_channels(&source_senders).await;
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
                        && d.transit_shards_used_this_generation() == 2
                })
                && observations
                    .iter()
                    .filter(|(n, _)| *n == 1 || *n == 2)
                    .all(|(_, d)| d.replies() >= 16);
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
                    && d.transit_shards_used_this_generation() == 2),
            "bridge never used both neutral shards"
        );
        for (node, d) in &observations {
            if *node == 1 || *node == 2 {
                assert_eq!(d.sent(0), 0, "relay selected a source priority channel");
                assert_eq!(d.sent(2), 0, "relay selected a source priority channel");
                assert_eq!(d.sent(3), 0, "relay selected a source priority channel");
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
    for task in tasks {
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
        assert_eq!(
            sender.local_datagram_channel_state(0),
            LocalDatagramChannelState::Unsupported
        );
        assert_eq!(
            sender.local_datagram_channel_state(2),
            LocalDatagramChannelState::Unsupported
        );
    }
    assert!(result.is_ok(), "two-relay chain stalled: {result:?}");
}

#[tokio::test]
async fn two_relays_use_bounded_neutral_quic_shards() {
    chain(false).await;
}

#[tokio::test]
async fn neutral_chain_rebinds_after_real_canonical_rekey() {
    chain(true).await;
}
