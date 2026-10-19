//! Exercise the production candidate/writer/receiver paths on real TLS/QUIC.
use super::super::RealtimeReceiverContext;
use super::*;
use std::{
    collections::HashSet,
    sync::{Mutex, RwLock, Weak},
};
use veil_proto::{
    header::FrameHeader,
    priority::{INTERACTIVE, REALTIME},
};
use veil_transport::context::QuicCongestionControl;
use veil_types::NodeIdBytes;

#[tokio::test]
async fn negotiated_ordered_sources_do_not_enter_parent_and_preserve_ordinary_cipher_order() {
    use super::super::{
        ParallelOrderedOffer, ParallelRegistry, RealtimeLaneOffer, RealtimeTransportOffer,
    };
    use veil_proto::{
        family::{AppMsg, FrameFamily},
        priority::{BACKGROUND, BULK},
    };
    use veil_transport::{
        Transport, TransportListener, TransportUri, obfs4_tcp::Obfs4TcpTransport,
    };
    let mut context = TransportContext::for_debug().unwrap();
    context.obfs4_psk = Some(Arc::new([0x42; 32]));
    let context = Arc::new(context);
    let listener: Arc<dyn TransportListener> = Arc::from(
        Obfs4TcpTransport
            .bind(
                &TransportUri::Obfs4Tcp {
                    host: "127.0.0.1".into(),
                    port: 0,
                },
                context.clone(),
            )
            .await
            .unwrap(),
    );
    let port = listener
        .local_addr()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let uri = TransportUri::Obfs4Tcp {
        host: "127.0.0.1".into(),
        port,
    };
    let (local, remote) = tokio::join!(Obfs4TcpTransport.connect(&uri, context), listener.accept());
    let local = local.unwrap();
    let remote = remote.unwrap();
    let offer = ParallelOrderedOffer::new(
        local.parallel_stream().unwrap(),
        Arc::new(ParallelRegistry::default()),
    );
    let mut remote_stream = remote.into_stream().unwrap();
    let mut registry = crate::SessionTxRegistry::new();
    let outbox = registry.register([0xB1; 32]);
    let sender = registry.get_sender(&[0xB1; 32]).unwrap().clone();
    let mut runner = super::reliable_source_pressure_quic_tests::make_runner(
        local.into_stream().unwrap(),
        outbox,
        Some(RealtimeLaneOffer {
            transport: RealtimeTransportOffer::Ordered(offer),
            peer_datagrams: true,
            peer_flows: true,
            peer_rotates: true,
            peer_circuit_datagrams: true,
            peer_neutral_forwards: true,
            parallel: None,
        }),
    );
    runner.raw_session_keys = Some(([2; 32], [3; 32], [1; 32]));
    let swap_tx = runner.with_swap_inbox();
    let task = tokio::spawn(async move { runner.run().await });
    for lane in [REALTIME, BULK, BACKGROUND] {
        assert_eq!(sender.local_packet_framing(lane), None);
        sender
            .try_send((
                lane,
                veil_bufpool::pooled_shared_from_vec(primary_test_frame(false, 1, 0)),
            ))
            .unwrap();
    }
    // The listener has not accepted any child: do not mistake a missing
    // separate connection for permission to serialize media into the parent.
    assert!(
        timeout(
            Duration::from_millis(200),
            remote_stream.read(&mut [0; 4096])
        )
        .await
        .is_err(),
        "negotiated source escaped onto the ordered parent"
    );
    // A working ordinary frame proves the parent was not just broken. Its
    // successful decryption also detects a nonce burned by discarded media.
    let body = b"ordinary-parent-still-works";
    let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppSend as u16);
    header.body_len = body.len() as u32;
    sender
        .try_send((
            INTERACTIVE,
            veil_bufpool::pooled_shared_from_vec(veil_proto::codec::encode_frame(&header, body)),
        ))
        .unwrap();
    let mut reader = super::super::ordered_reader::Reader::default();
    let wire = timeout(
        Duration::from_secs(1),
        reader.read(&mut remote_stream, 65536),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(wire.header.msg_type, AppMsg::AppSend as u16);
    let mut cipher = veil_crypto::session_cipher::SessionCipher::new(&[0x51; 32], true);
    assert_eq!(
        cipher
            .open(&wire.body, &veil_proto::codec::frame_aad(&wire.header))
            .unwrap(),
        body
    );
    let (replacement, mut replacement_peer) = tokio::io::duplex(1024);
    swap_tx.send(Box::new(replacement)).await.unwrap();
    let closed = timeout(Duration::from_secs(2), remote_stream.read(&mut [0; 1]))
        .await
        .expect("old obfs4 stream must retire");
    assert!(matches!(closed, Ok(0) | Err(_)));
    // This ordered factory is bound to the original TCP owner. It closes
    // with that owner: the session must request fresh authentication, not
    // remain alive forever with unready children or spill media into the parent.
    timeout(Duration::from_secs(2), task)
        .await
        .expect("closed ordered factory must end the swapped session")
        .expect("runner must not panic");
    assert_eq!(
        timeout(Duration::from_secs(1), replacement_peer.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn negotiated_sources_never_spill_to_parent_while_children_warm_or_close() {
    verify_sources_across_canonical_transport(false, false, false).await;
}

#[tokio::test]
async fn independent_sources_survive_canonical_stream_swap_without_reset_or_parent_spill() {
    verify_sources_across_canonical_transport(true, false, false).await;
}

#[tokio::test]
async fn independent_sources_can_warm_after_canonical_swap_and_survive_another_swap() {
    verify_sources_across_canonical_transport(true, true, false).await;
}

#[tokio::test]
async fn independent_sources_reauthenticate_when_retained_quic_factory_closes_after_swap() {
    verify_sources_across_canonical_transport(true, false, true).await;
}

async fn verify_sources_across_canonical_transport(
    swap_canonical: bool,
    swap_before_warm: bool,
    close_factory: bool,
) {
    use super::super::{ParallelQuicOffer, RealtimeLaneOffer, RealtimeTransportOffer};
    use veil_proto::priority::{BACKGROUND, BULK};
    let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let left_addr = left.local_addr().unwrap();
    let right_addr = right.local_addr().unwrap();
    let ctx = Arc::new(TransportContext::for_debug().unwrap());
    let remote = tokio::spawn(promote_punched_quic(
        right,
        left_addr,
        ctx.clone(),
        PunchedQuicRole::Responder,
    ));
    let local = promote_punched_quic(left, right_addr, ctx, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    let parent = local.quic_datagrams().unwrap();
    let offer = ParallelQuicOffer::new(local.parallel_quic().unwrap()).with_duplex();
    let diagnostics = offer.diagnostics();
    let mut stream = local.into_stream().unwrap();
    stream.write_all(b"main").await.unwrap();
    let remote = remote.await.unwrap().unwrap();
    let remote_parent = remote.quic_datagrams().unwrap();
    let remote_offer = ParallelQuicOffer::new(remote.parallel_quic().unwrap()).with_duplex();
    let mut remote_stream = remote.into_stream().unwrap();
    remote_stream.read_exact(&mut [0; 4]).await.unwrap();
    let mut registry = crate::SessionTxRegistry::new();
    let outbox = registry.register([0xB1; 32]);
    let sender = registry.get_sender(&[0xB1; 32]).unwrap().clone();
    let mut runner = super::reliable_source_pressure_quic_tests::make_runner(
        stream,
        outbox,
        Some(RealtimeLaneOffer {
            transport: RealtimeTransportOffer::Quic(parent),
            peer_datagrams: true,
            peer_flows: true,
            peer_rotates: true,
            peer_circuit_datagrams: true,
            peer_neutral_forwards: true,
            parallel: Some(offer),
        }),
    );
    runner.raw_session_keys = Some(([2; 32], [3; 32], [1; 32]));
    let swap_tx = runner.with_swap_inbox();
    let task = tokio::spawn(async move { runner.run().await });
    for lane in [REALTIME, BULK, BACKGROUND] {
        sender
            .try_send((
                lane,
                veil_bufpool::pooled_shared_from_vec(primary_test_frame(false, 1, 0)),
            ))
            .unwrap();
    }
    // No remote child registration yet: negotiation alone must not permit
    // either shared parent DATAGRAMs or the encrypted reliable parent writer.
    async fn no_parent_payload(
        parent: &QuicDatagramHandle,
        stream: &mut veil_transport::BoxIoStream,
    ) {
        let mut bytes = [0; 4096];
        let result = timeout(Duration::from_millis(200), async {
            tokio::select! {
                p = parent.recv() => { assert!(p.is_ok()); },
                n = stream.read(&mut bytes) => { assert!(n.unwrap() > 0); },
            }
        })
        .await;
        assert!(
            result.is_err(),
            "negotiated source escaped onto the shared parent"
        );
    }
    no_parent_payload(&remote_parent, &mut remote_stream).await;
    if swap_before_warm {
        let (replacement, replacement_peer) = tokio::io::duplex(1024);
        swap_tx.send(Box::new(replacement)).await.unwrap();
        let closed = timeout(Duration::from_secs(2), remote_stream.read(&mut [0; 1]))
            .await
            .expect("cold canonical stream must retire");
        assert!(matches!(closed, Ok(0) | Err(_)));
        remote_stream = Box::new(replacement_peer);
        // The remote child acceptor still does not exist. A byte-only swap
        // cannot authorize source traffic to spill onto the replacement.
        no_parent_payload(&remote_parent, &mut remote_stream).await;
    }
    let started = Instant::now();
    let (received, mut packets) = mpsc::unbounded_channel();
    let logger = Arc::new(veil_observability::NodeLogger::new_noop());
    let mut context = super::super::ordered_receiver_tests::pool_fixture_context();
    let ingress = Arc::new(Mutex::new(std::collections::HashMap::new()));
    context.dispatcher = Arc::new(Capture {
        ingress: Some(ingress.clone()),
        started,
        received,
        logger,
    });
    let child_receiver = super::super::parallel_lanes::ParallelSession::new(
        remote_offer.clone(),
        &[3; 32],
        &[2; 32],
        [1; 32],
        context.clone(),
        None,
    );
    let mut seen = HashSet::new();
    timeout(Duration::from_secs(5), async {
        for tick in 0u32.. {
            for (index, lane) in [REALTIME, BULK, BACKGROUND].into_iter().enumerate() {
                sender
                    .try_send((
                        lane,
                        veil_bufpool::pooled_shared_from_vec(primary_test_frame(
                            false,
                            (index as u32 + 1) * 1000 + tick,
                            0,
                        )),
                    ))
                    .unwrap();
            }
            while let Ok((seq, _, _)) = packets.try_recv() {
                seen.insert(seq / 1000);
            }
            if seen.len() == 3 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all three independent sources must actually deliver");
    timeout(Duration::from_secs(1), async {
        while [REALTIME, BULK, BACKGROUND]
            .iter()
            .any(|lane| sender.local_packet_framing(*lane).is_none())
        {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("authenticated child must publish its actual framing");
    for lane in [REALTIME, BULK, BACKGROUND] {
        assert!(diagnostics.sent(lane) > 0);
        assert!(
            matches!(sender.local_packet_framing(lane), Some(crate::LocalPacketFraming::QuicDatagram { ceiling }) if ceiling > 60)
        );
    }
    no_parent_payload(&remote_parent, &mut remote_stream).await;
    if swap_canonical {
        use veil_proto::family::{AppMsg, FrameFamily};
        // A transport-only swap retains the existing ordered cipher too.
        // Decrypt a marker on each side of the swap with ONE receiver cipher;
        // spending a nonce on leaked media or resetting it must fail here.
        let mut cipher = veil_crypto::session_cipher::SessionCipher::new(&[0x51; 32], true);
        async fn ordinary_marker(
            sender: &crate::frame_outbox::FrameSender,
            stream: &mut veil_transport::BoxIoStream,
            cipher: &mut veil_crypto::session_cipher::SessionCipher,
            body: &[u8],
        ) {
            let mut h = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppSend as u16);
            h.body_len = body.len() as u32;
            sender
                .try_send((
                    INTERACTIVE,
                    veil_bufpool::pooled_shared_from_vec(veil_proto::codec::encode_frame(&h, body)),
                ))
                .unwrap();
            let mut reader = super::super::ordered_reader::Reader::default();
            let wire = timeout(Duration::from_secs(2), reader.read(stream, 65536))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(wire.header.family, FrameFamily::App as u8);
            assert_eq!(wire.header.msg_type, AppMsg::AppSend as u16);
            assert_eq!(
                cipher
                    .open(&wire.body, &veil_proto::codec::frame_aad(&wire.header))
                    .unwrap(),
                body
            );
        }
        ordinary_marker(&sender, &mut remote_stream, &mut cipher, b"before-swap").await;
        let active = diagnostics.active_connections();
        assert!(
            active >= 3,
            "each independent source must be authenticated first"
        );
        let before = [REALTIME, BULK, BACKGROUND].map(|lane| diagnostics.sent(lane));
        let old_ingress = ingress.lock().unwrap().clone();
        let (replacement, replacement_peer) = tokio::io::duplex(1024);
        swap_tx.send(Box::new(replacement)).await.unwrap();
        // Completion of the old ordered writer is an actual swap witness,
        // not a sleep that assumes the command has been processed.
        let closed = timeout(Duration::from_secs(2), remote_stream.read(&mut [0; 1]))
            .await
            .expect("old canonical stream must retire");
        assert!(matches!(closed, Ok(0) | Err(_)));
        remote_stream = Box::new(replacement_peer);
        ordinary_marker(&sender, &mut remote_stream, &mut cipher, b"after-swap").await;
        assert_eq!(
            diagnostics.active_connections(),
            active,
            "replacing the canonical stream must not retire independent connections"
        );
        assert_eq!(diagnostics.rekeys(), 0, "transport swap is not a key epoch");
        // Make the NEW canonical writer genuinely block on an ordinary
        // encrypted body. All three independent sources must still deliver.
        let large_body = vec![0x63; 16 * 1024];
        let mut large_header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppSend as u16);
        large_header.body_len = large_body.len() as u32;
        sender
            .try_send((
                INTERACTIVE,
                veil_bufpool::pooled_shared_from_vec(veil_proto::codec::encode_frame(
                    &large_header,
                    &large_body,
                )),
            ))
            .unwrap();
        let mut large_header_wire = [0; veil_proto::header::HEADER_SIZE];
        timeout(
            Duration::from_secs(2),
            remote_stream.read_exact(&mut large_header_wire),
        )
        .await
        .unwrap()
        .unwrap();
        let large_wire_header = veil_proto::codec::decode_header(&large_header_wire).unwrap();
        assert!(large_wire_header.body_len > 1024);
        let mut delivered = HashSet::new();
        timeout(Duration::from_secs(3), async {
            for tick in 0u32.. {
                for (index, lane) in [REALTIME, BULK, BACKGROUND].into_iter().enumerate() {
                    sender
                        .try_send((
                            lane,
                            veil_bufpool::pooled_shared_from_vec(primary_test_frame(
                                false,
                                (index as u32 + 7) * 1000 + tick,
                                0,
                            )),
                        ))
                        .unwrap();
                }
                while let Ok((seq, _, _)) = packets.try_recv() {
                    if (7..=9).contains(&(seq / 1000)) {
                        delivered.insert(seq / 1000);
                    }
                }
                if delivered.len() == 3 {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("all existing remote decryptors must accept post-swap source traffic");
        for (index, lane) in [REALTIME, BULK, BACKGROUND].into_iter().enumerate() {
            assert!(diagnostics.sent(lane) > before[index]);
            assert_eq!(
                ingress.lock().unwrap().get(&(index as u32 + 7)),
                old_ingress.get(&(index as u32 + 1)),
                "source must keep the same authenticated parent and child, not recreate its codec"
            );
        }
        if close_factory {
            // The new canonical body is still blocked. Fresh authentication
            // must not wait for its ordinary five-second graceful drain.
            remote_parent.close();
            timeout(Duration::from_secs(2), task)
                .await
                .expect("lost independent factory must abort the blocked writer promptly")
                .expect("runner must not panic");
            let mut tail = Vec::new();
            timeout(Duration::from_secs(1), remote_stream.read_to_end(&mut tail))
                .await
                .unwrap()
                .unwrap();
            assert!(
                tail.len() < large_wire_header.body_len as usize,
                "fixture must leave an actual incomplete ordered body"
            );
            drop(child_receiver);
            return;
        }
        // Drain exactly that ordinary body with the same ordered cipher.
        // Interleaved media or any reset/consumption of its nonce breaks this.
        let mut large_wire_body = vec![0; large_wire_header.body_len as usize];
        timeout(
            Duration::from_secs(2),
            remote_stream.read_exact(&mut large_wire_body),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            cipher
                .open(
                    &large_wire_body,
                    &veil_proto::codec::frame_aad(&large_wire_header)
                )
                .unwrap(),
            large_body
        );
        no_parent_payload(&remote_parent, &mut remote_stream).await;
    }
    drop(child_receiver);
    sleep(Duration::from_millis(50)).await;
    for lane in [REALTIME, BULK, BACKGROUND] {
        sender
            .try_send((
                lane,
                veil_bufpool::pooled_shared_from_vec(primary_test_frame(false, 9000, 0)),
            ))
            .unwrap();
    }
    no_parent_payload(&remote_parent, &mut remote_stream).await;
    let replacement_receiver = super::super::parallel_lanes::ParallelSession::new(
        remote_offer,
        &[3; 32],
        &[2; 32],
        [1; 32],
        context,
        None,
    );
    let mut recovered = HashSet::new();
    timeout(Duration::from_secs(5), async {
        for tick in 0u32.. {
            for (index, lane) in [REALTIME, BULK, BACKGROUND].into_iter().enumerate() {
                sender
                    .try_send((
                        lane,
                        veil_bufpool::pooled_shared_from_vec(primary_test_frame(
                            false,
                            (index as u32 + 4) * 1000 + tick,
                            0,
                        )),
                    ))
                    .unwrap();
            }
            while let Ok((seq, _, _)) = packets.try_recv() {
                if (4..=6).contains(&(seq / 1000)) {
                    recovered.insert(seq / 1000);
                }
            }
            if recovered.len() == 3 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all three sources must deliver again after child replacement");
    no_parent_payload(&remote_parent, &mut remote_stream).await;
    drop(replacement_receiver);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    for lane in [REALTIME, BULK, BACKGROUND] {
        assert_eq!(sender.local_packet_framing(lane), None);
    }
}

type IngressCapture =
    Arc<Mutex<std::collections::HashMap<u32, veil_anonymity::circuit_carrier::LocalIngressFlow>>>;

struct Capture {
    ingress: Option<IngressCapture>,
    started: Instant,
    received: mpsc::UnboundedSender<(u32, u64, Duration)>,
    logger: Arc<veil_observability::NodeLogger>,
}

impl crate::dispatcher_sink::DispatcherSink for Capture {
    fn dispatch_with_carrier(
        &self,
        header: &FrameHeader,
        body: &[u8],
        peer: NodeIdBytes,
        carrier: Option<veil_anonymity::circuit_carrier::Carrier>,
    ) -> crate::dispatcher_sink::DispatchResult {
        if let Some(ingress) = &self.ingress {
            let flow = carrier
                .and_then(|c| c.upgrade())
                .and_then(|c| c.local_ingress_flow())
                .expect("independent source must retain an authenticated ingress witness");
            let seq = veil_proto::app::AppRtDataPayload::decode(body).unwrap().seq;
            ingress.lock().unwrap().insert(seq / 1000, flow);
        }
        self.dispatch(header, body, peer)
    }
    fn dispatch(
        &self,
        h: &FrameHeader,
        body: &[u8],
        peer: NodeIdBytes,
    ) -> crate::dispatcher_sink::DispatchResult {
        assert_eq!(peer, [9; 32]);
        let (seq, sent) = if h.family == veil_proto::family::FrameFamily::Delivery as u8 {
            assert_eq!(h.priority(), INTERACTIVE);
            let forward = veil_proto::delivery::ForwardPayload::decode(body).unwrap();
            assert_eq!(forward.traffic_class, Some(INTERACTIVE));
            let payload = forward.envelope.payload;
            assert!(payload[12..].iter().all(|b| *b == 0x11));
            (
                u32::from_be_bytes(payload[..4].try_into().unwrap()),
                u64::from_be_bytes(payload[4..12].try_into().unwrap()),
            )
        } else if h.family == veil_proto::family::FrameFamily::App as u8 {
            let p = veil_proto::app::AppRtDataPayload::decode(body).unwrap();
            assert_eq!(p.payload, vec![0x11; 128]);
            (p.seq, p.timestamp_us)
        } else {
            assert_eq!(
                h.priority(),
                INTERACTIVE,
                "opaque circuit must not expose the source hint"
            );
            let p = veil_anonymity::circuit_wire::CircuitDataPayload::decode(body).unwrap();
            assert_eq!(p.circuit_id, 1);
            assert!(p.ciphertext[8..].iter().all(|b| *b == 0x11));
            (
                p.seq,
                u64::from_be_bytes(p.ciphertext[..8].try_into().unwrap()),
            )
        };
        let _ = self.received.send((seq, sent, self.started.elapsed()));
        crate::dispatcher_sink::DispatchResult::NoResponse
    }
    fn capture_outbound(&self, _: NodeIdBytes, _: &[u8]) {}
    fn allow_outbound_bandwidth(&self, _: usize) -> bool {
        true
    }
    fn logger(&self) -> &Arc<veil_observability::NodeLogger> {
        &self.logger
    }
    fn session_tx_registry(&self) -> Option<Arc<RwLock<crate::tx_registry::SessionTxRegistry>>> {
        None
    }
    fn dht(&self) -> &Arc<veil_dht::KademliaService> {
        unreachable!("datagram-only fixture")
    }
    fn rendezvous_weak(&self) -> Arc<Mutex<Option<Weak<crate::rendezvous::RendezvousController>>>> {
        unreachable!("datagram-only fixture")
    }
    fn pow_solver_semaphore(&self) -> Arc<tokio::sync::Semaphore> {
        unreachable!("datagram-only fixture")
    }
    fn pow_active_difficulty(&self) -> Arc<std::sync::atomic::AtomicU64> {
        unreachable!("datagram-only fixture")
    }
    fn route_cache(&self) -> Arc<RwLock<veil_routing::RouteCache>> {
        unreachable!("datagram-only fixture")
    }
    fn register_session_aliases(&self, _: [u8; 8], _: NodeIdBytes, _: [u8; 8], _: NodeIdBytes) {
        unreachable!("datagram-only fixture")
    }
    fn unregister_session_aliases(&self, _: [u8; 8], _: [u8; 8]) {
        unreachable!("datagram-only fixture")
    }
}

#[derive(Debug)]
struct Report {
    first_fresh: Option<Duration>,
    max_post_age: Duration,
    attempts: u64,
    switches: u64,
    duplicates: usize,
    post_received: usize,
    reverse_switches: u64,
    reverse_post_received: usize,
    reverse_first_fresh: Option<Duration>,
    reverse_max_post_age: Duration,
}

async fn measure(
    large: bool,
    recover: bool,
    congestion: QuicCongestionControl,
    full_duplex: bool,
) -> Report {
    measure_channel(large, recover, congestion, full_duplex, REALTIME, false).await
}

fn channel_frame(large: bool, forward: bool, seq: u32, sent_us: u64) -> Vec<u8> {
    if !forward {
        return primary_test_frame(large, seq, sent_us);
    }
    let mut payload = seq.to_be_bytes().to_vec();
    payload.extend_from_slice(&sent_us.to_be_bytes());
    payload.extend_from_slice(&[0x11; 128]);
    let mut content_id = [7; 32];
    content_id[..4].copy_from_slice(&seq.to_be_bytes());
    let body = veil_proto::delivery::ForwardPayload {
        next_hop_node_id: [9; 32],
        envelope: veil_proto::delivery::DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any([8; 32]),
            sender_node_id: [7; 32],
            src_app_id: [6; 32],
            app_id: [5; 32],
            endpoint_id: 1,
            content_id,
            created_at: veil_util::unix_secs_now_u64(),
            ttl_secs: veil_proto::delivery::FORWARD_REALTIME_TTL_SECS,
            payload,
            trace_id: 0,
            require_ack: false,
        },
        relay_hops: 1,
        delivery_attempt: None,
        traffic_class: Some(INTERACTIVE),
    }
    .encode();
    let mut header = FrameHeader::new(
        veil_proto::family::FrameFamily::Delivery as u8,
        veil_proto::family::DeliveryMsg::Forward as u16,
    );
    header.set_priority(INTERACTIVE);
    header.body_len = body.len() as u32;
    veil_proto::codec::encode_frame(&header, &body)
}

fn channel_admits(sender: &super::super::RealtimeSender, packets: &[Vec<u8>], lane: u8) -> bool {
    let available = sender.handle.send_buffer_space();
    if lane == REALTIME {
        super::super::local_primary_datagram_fits(packets.iter().map(Vec::len).sum(), available)
    } else {
        super::super::local_datagram_fits(
            lane,
            packets
                .iter()
                .map(|packet| sender.handle.queue_charge(packet.len()))
                .sum(),
            available,
        )
    }
}

async fn measure_channel(
    large: bool,
    recover: bool,
    congestion: QuicCongestionControl,
    full_duplex: bool,
    lane: u8,
    forward: bool,
) -> Report {
    use super::super::parallel_lanes::{ParallelQuicOffer, ParallelSession};
    let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let link = NeutralLink::new(
        left.local_addr().unwrap(),
        right.local_addr().unwrap(),
        1_000_000,
        Duration::from_millis(20),
    )
    .await;
    link.enabled.store(true, Ordering::Relaxed);
    let mut ctx = TransportContext::for_debug().unwrap();
    ctx.quic.congestion_control = congestion;
    let ctx = Arc::new(ctx);
    let remote = tokio::spawn(promote_punched_quic(
        right,
        link.right_addr,
        Arc::clone(&ctx),
        PunchedQuicRole::Responder,
    ));
    let local = promote_punched_quic(left, link.left_addr, ctx, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    let close = local.quic_connection().unwrap();
    let a_offer = ParallelQuicOffer::new(local.parallel_quic().unwrap()).with_duplex();
    let diagnostics = a_offer.diagnostics();
    let mut a_stream = local.into_stream().unwrap();
    a_stream.write_all(b"main").await.unwrap();
    let remote = remote.await.unwrap().unwrap();
    let b_offer = ParallelQuicOffer::new(remote.parallel_quic().unwrap()).with_duplex();
    let b_diagnostics = b_offer.diagnostics();
    let mut b_stream = remote.into_stream().unwrap();
    let mut prefix = [0; 4];
    b_stream.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"main");
    let started = Instant::now();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let logger = Arc::new(veil_observability::NodeLogger::new_noop());
    let sink: Arc<dyn crate::dispatcher_sink::DispatcherSink> = Arc::new(Capture {
        ingress: None,
        started,
        received: tx,
        logger: Arc::clone(&logger),
    });
    let context = RealtimeReceiverContext {
        peer_id: [9; 32],
        dispatcher: sink,
        logger,
        metrics: None,
        ban_list: Arc::new(Mutex::new(veil_abuse::BanList::new())),
        violation_tracker: Arc::new(Mutex::new(
            veil_abuse::ViolationTracker::with_fixed_duration(
                10,
                Duration::from_secs(10),
                Duration::from_secs(10),
            )
            .unwrap(),
        )),
        activity: Arc::new(crate::datagram_activity::AuthenticatedDatagramActivity::new()),
    };
    let mut a = ParallelSession::new(a_offer, &[2; 32], &[3; 32], [1; 32], context.clone(), None);
    let mut b = ParallelSession::new(b_offer, &[3; 32], &[2; 32], [1; 32], context, None);
    if full_duplex {
        for session in [&mut a, &mut b] {
            for lane in crate::local_datagram_status::LOCAL_DATAGRAM_PRIORITIES {
                timeout(Duration::from_secs(3), async {
                    while !session.prepare(lane) {
                        sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .expect("full-duplex source connection budget");
            }
            let mut transit = HashSet::new();
            timeout(Duration::from_secs(3), async {
                // Opaque circuit ids exercise both neutral shards, with no
                // role-specific treatment at the receiver or neutral link.
                while transit.len() < 2 {
                    for id in 1u32..64 {
                        if let Some(index) = session.prepare_frame(
                            INTERACTIVE,
                            &id.to_be_bytes(),
                            super::super::RealtimeLaneFrameKind::CircuitDatagram,
                        ) {
                            transit.insert(index);
                        }
                    }
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("full-duplex neutral connection budget");
        }
        timeout(Duration::from_secs(3), async {
            while diagnostics.active_connections() != 12 || b_diagnostics.active_connections() != 12
            {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("optional signaling retired without consuming recovery capacity");
    }
    let warm_frame = channel_frame(large, forward, 0, 0);
    let (_, warm_body, warm_kind) = super::super::decode_realtime_lane_frame(&warm_frame).unwrap();
    let index = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(index) = a.prepare_frame(lane, warm_body, warm_kind) {
                break index;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let reverse_index = if full_duplex {
        Some(
            timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(index) = b.prepare_frame(lane, warm_body, warm_kind) {
                        break index;
                    }
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap(),
        )
    } else {
        None
    };
    let original = a.sender(index).handle.quic().unwrap().clone();
    let original_exporter = original.channel_binding().unwrap();
    let blackout_start = started.elapsed() + Duration::from_secs(6);
    let blackout_end = blackout_start + Duration::from_secs(4);
    let end = blackout_end + Duration::from_secs(4);
    let media_started = Instant::now();
    let mut last_attempt = 0;
    let mut last_switch = 0;
    let mut seq = 0u32;
    let mut changed_exporter = false;
    let mut retained_during_pending = true;
    while started.elapsed() < end {
        sleep_until(media_started + Duration::from_millis(u64::from(seq) * 20)).await;
        let now = started.elapsed();
        link.blackout.store(
            (blackout_start..blackout_end).contains(&now),
            Ordering::Relaxed,
        );
        let frame = channel_frame(large, forward, seq, now.as_micros() as u64);
        let (_, body, kind) = super::super::decode_realtime_lane_frame(&frame).unwrap();
        // Baseline polls the same production slot but cannot request repair.
        let ready = if recover {
            a.prepare_frame(lane, body, kind) == Some(index)
        } else {
            a.prepare_without_recovery(index)
        };
        assert!(ready, "pending recovery displaced a usable sender");
        let attempt = diagnostics.recovery_attempts();
        let switches = diagnostics.recovery_switches();
        if attempt != last_attempt || switches != last_switch {
            eprintln!(
                "recovery stage large={large} since_blackout_ms={} attempt={attempt} switches={switches} old={:?}",
                now.saturating_sub(blackout_start).as_millis(),
                original.path_stats()
            );
            last_attempt = attempt;
            last_switch = switches;
        }
        let mut sender = a.sender(index);
        if sender.handle.quic().unwrap().channel_binding().unwrap() != original_exporter {
            changed_exporter = true;
        }
        if now < blackout_end {
            retained_during_pending &=
                sender.handle.quic().unwrap().channel_binding().unwrap() == original_exporter;
        }
        let max_size = sender.max_datagram_size;
        let packets = sender
            .tx
            .encode_frame(
                super::super::local_datagram_flow(lane, body, kind),
                &frame,
                max_size,
            )
            .unwrap();
        if channel_admits(&sender, &packets, lane) {
            let expiry =
                super::super::local_datagram_expiry(&crate::frame_outbox::FrameEnvelope::from((
                    lane,
                    veil_bufpool::pooled_shared_from_vec(frame.clone()),
                )));
            for packet in packets {
                if let Some(expiry) = expiry {
                    sender.handle.send_before(&packet, expiry).unwrap();
                } else {
                    sender.handle.send(&packet).unwrap();
                }
            }
        }
        seq += 1;
        drop(sender);
        if full_duplex {
            let frame = channel_frame(large, forward, seq | (1 << 31), now.as_micros() as u64);
            let (_, body, kind) = super::super::decode_realtime_lane_frame(&frame).unwrap();
            let index = reverse_index.unwrap();
            let ready = if recover {
                b.prepare_frame(lane, body, kind) == Some(index)
            } else {
                b.prepare_without_recovery(index)
            };
            assert!(ready, "pending reverse recovery displaced a usable sender");
            let mut sender = b.sender(index);
            let max_size = sender.max_datagram_size;
            let packets = sender
                .tx
                .encode_frame(
                    super::super::local_datagram_flow(lane, body, kind),
                    &frame,
                    max_size,
                )
                .unwrap();
            if channel_admits(&sender, &packets, lane) {
                let expiry =
                    super::super::local_datagram_expiry(&crate::frame_outbox::FrameEnvelope::from(
                        (lane, veil_bufpool::pooled_shared_from_vec(frame)),
                    ));
                for packet in packets {
                    if let Some(expiry) = expiry {
                        sender.handle.send_before(&packet, expiry).unwrap();
                    } else {
                        sender.handle.send(&packet).unwrap();
                    }
                }
            }
        }
    }
    sleep(Duration::from_millis(100)).await;
    let attempts = diagnostics.recovery_attempts();
    let switches = diagnostics.recovery_switches();
    let reverse_switches = b_diagnostics.recovery_switches();
    // Teardown first, including held old connection handles and candidate tasks.
    drop((a, b));
    close.close(0u32.into(), b"primary recovery stand complete");
    timeout(Duration::from_secs(1), original.closed())
        .await
        .unwrap();
    let mut seen = HashSet::new();
    let mut duplicates = 0;
    let mut post = 0;
    let mut reverse_post_received = 0;
    let mut reverse_first_fresh = None;
    let mut reverse_max_post_age = Duration::ZERO;
    let mut first_fresh = None;
    let mut max_age = Duration::ZERO;
    while let Ok((s, sent, arrived)) = rx.try_recv() {
        if !seen.insert(s) {
            duplicates += 1;
        }
        if arrived >= blackout_end {
            if s & (1 << 31) != 0 {
                reverse_post_received += 1;
                reverse_max_post_age =
                    reverse_max_post_age.max(arrived.saturating_sub(Duration::from_micros(sent)));
                if Duration::from_micros(sent) >= blackout_end && reverse_first_fresh.is_none() {
                    reverse_first_fresh = Some(arrived - blackout_end);
                }
                continue;
            }
            post += 1;
            max_age = max_age.max(arrived.saturating_sub(Duration::from_micros(sent)));
            if Duration::from_micros(sent) >= blackout_end && first_fresh.is_none() {
                first_fresh = Some(arrived - blackout_end);
            }
        }
    }
    assert!(
        retained_during_pending,
        "unauthenticated candidate displaced old connection"
    );
    assert_eq!(changed_exporter, switches > 0);
    let report = Report {
        first_fresh,
        max_post_age: max_age,
        attempts,
        switches,
        duplicates,
        post_received: post,
        reverse_switches,
        reverse_post_received,
        reverse_first_fresh,
        reverse_max_post_age,
    };
    eprintln!("production channel recovery {report:?}");
    report
}

#[tokio::test]
async fn opaque_forward_channels_recover_without_a_source_role_in_both_directions() {
    timeout(Duration::from_secs(45), async {
        let baseline = measure_channel(
            true,
            false,
            QuicCongestionControl::Cubic,
            true,
            INTERACTIVE,
            true,
        )
        .await;
        assert_eq!(baseline.switches, 0);
        assert_eq!(baseline.reverse_switches, 0);
        assert!(
            baseline.first_fresh.unwrap() > Duration::from_millis(600),
            "{baseline:?}"
        );
        assert!(
            baseline.reverse_first_fresh.unwrap() > Duration::from_millis(600),
            "{baseline:?}"
        );
        let report = measure_channel(
            true,
            true,
            QuicCongestionControl::Cubic,
            true,
            INTERACTIVE,
            true,
        )
        .await;
        assert!(
            report.switches > 0 && report.reverse_switches > 0,
            "{report:?}"
        );
        assert!(
            report.first_fresh.unwrap() < Duration::from_millis(600),
            "{report:?}"
        );
        assert!(
            report.reverse_first_fresh.unwrap() < Duration::from_millis(600),
            "{report:?}"
        );
        assert!(
            report.max_post_age < Duration::from_millis(400),
            "{report:?}"
        );
        assert!(
            report.reverse_max_post_age < Duration::from_millis(400),
            "{report:?}"
        );
        assert!(
            report.first_fresh < baseline.first_fresh,
            "baseline={baseline:?} repaired={report:?}"
        );
        assert!(
            report.reverse_first_fresh < baseline.reverse_first_fresh,
            "baseline={baseline:?} repaired={report:?}"
        );
        assert_eq!(report.duplicates, 0);
        assert!(
            report.post_received >= 140 && report.reverse_post_received >= 140,
            "{report:?}"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn full_duplex_sources_and_neutral_shards_leave_room_for_primary_recovery() {
    timeout(Duration::from_secs(25), async {
        let report = measure(false, true, QuicCongestionControl::Cubic, true).await;
        assert!(
            report.switches > 0 && report.reverse_switches > 0,
            "{report:?}"
        );
        assert!(
            report.first_fresh.unwrap() < Duration::from_millis(600),
            "{report:?}"
        );
        assert!(
            report.max_post_age < Duration::from_millis(400),
            "{report:?}"
        );
        assert!(
            report.reverse_first_fresh.unwrap() < Duration::from_millis(600)
                && report.reverse_max_post_age < Duration::from_millis(400),
            "reverse audio recovery must be equally prompt: {report:?}"
        );
        assert_eq!(report.duplicates, 0);
        assert!(
            report.post_received >= 140 && report.reverse_post_received >= 140,
            "{report:?}"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn authenticated_primary_replacement_recovers_after_four_second_neutral_outage() {
    for large in [false, true] {
        // Keep the historical stall reproducible independently of the
        // production congestion controller. All existing recovery gates
        // still apply to the authenticated replacement path.
        let old = measure(large, false, QuicCongestionControl::Cubic, false).await;
        let repaired = measure(large, true, QuicCongestionControl::Cubic, false).await;
        assert!(
            old.first_fresh.unwrap() > Duration::from_millis(600),
            "baseline must reproduce excess recovery delay: {old:?}"
        );
        assert!(
            repaired.first_fresh.unwrap() < Duration::from_millis(600),
            "fresh authenticated channel must resume promptly: {repaired:?}"
        );
        assert!(
            repaired.max_post_age < Duration::from_millis(400),
            "recovery must not replay an aged backlog: {repaired:?}"
        );
        assert_eq!(repaired.duplicates, 0);
        assert!(repaired.attempts > 0 && repaired.switches > 0);
        assert!(
            repaired.post_received >= 140,
            "too many post-outage source opportunities lost: {repaired:?}"
        );
    }
}

#[tokio::test]
async fn bbr_recovers_fresh_datagrams_after_neutral_outage() {
    for large in [false, true] {
        for recover in [false, true] {
            let report = measure(large, recover, QuicCongestionControl::Bbr, false).await;
            assert!(
                report.first_fresh.unwrap() < Duration::from_millis(600),
                "{report:?}"
            );
            assert!(
                report.max_post_age < Duration::from_millis(400),
                "{report:?}"
            );
            assert_eq!(report.duplicates, 0);
            assert!(report.post_received >= 140, "{report:?}");
        }
    }
}

#[tokio::test]
async fn local_signaling_and_data_have_distinct_quic_connections_and_survive_screen_close() {
    verify_distinct_sources(false, false).await;
}

#[tokio::test]
async fn late_camera_and_screen_survive_idle_and_reopen_after_close_without_retiring_audio() {
    verify_distinct_sources(true, false).await;
}

#[tokio::test]
async fn auxiliary_only_control_and_signaling_have_distinct_connections() {
    verify_distinct_sources(false, true).await;
}

async fn verify_distinct_sources(late_idle: bool, auxiliary_only: bool) {
    use veil_proto::{
        ipc::LOCAL_RECOVERABLE_DATA_LANE,
        priority::{BACKGROUND, BULK},
    };
    timeout(Duration::from_secs(if late_idle { 65 } else { 20 }), async {
        use super::super::parallel_lanes::{ParallelQuicOffer, ParallelSession};
        let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let link = NeutralLink::new(
            left.local_addr().unwrap(),
            right.local_addr().unwrap(),
            1_000_000,
            Duration::from_millis(20),
        )
        .await;
        link.enabled.store(true, Ordering::Relaxed);
        let mut ctx = TransportContext::for_debug().unwrap();
        ctx.quic.congestion_control = QuicCongestionControl::Cubic;
        let ctx = Arc::new(ctx);
        let remote = tokio::spawn(promote_punched_quic(
            right,
            link.right_addr,
            Arc::clone(&ctx),
            PunchedQuicRole::Responder,
        ));
        let local = promote_punched_quic(left, link.left_addr, ctx, PunchedQuicRole::Initiator)
            .await
            .unwrap();
        let close = local.quic_connection().unwrap();
        let factory = local.parallel_quic().unwrap();
        let mut a_offer = ParallelQuicOffer::new(factory.clone()).with_duplex();
        if auxiliary_only {
            a_offer = a_offer.with_reliable().with_auxiliary_records()
                .with_auxiliary_app_streams().with_auxiliary_only();
        }
        let diagnostics = a_offer.diagnostics();
        let mut a_stream = local.into_stream().unwrap();
        a_stream.write_all(b"main").await.unwrap();
        let remote = remote.await.unwrap().unwrap();
        let mut b_offer = ParallelQuicOffer::new(remote.parallel_quic().unwrap()).with_duplex();
        if auxiliary_only {
            b_offer = b_offer.with_reliable().with_auxiliary_records()
                .with_auxiliary_app_streams().with_auxiliary_only();
        }
        let mut b_stream = remote.into_stream().unwrap();
        let mut prefix = [0; 4];
        b_stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"main");
        let started = Instant::now();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let logger = Arc::new(veil_observability::NodeLogger::new_noop());
        let sink: Arc<dyn crate::dispatcher_sink::DispatcherSink> = Arc::new(Capture {
            ingress: None,
            started,
            received: tx,
            logger: Arc::clone(&logger),
        });
        let context = RealtimeReceiverContext {
            peer_id: [9; 32],
            dispatcher: sink,
            logger,
            metrics: None,
            ban_list: Arc::new(Mutex::new(veil_abuse::BanList::new())),
            violation_tracker: Arc::new(Mutex::new(
                veil_abuse::ViolationTracker::with_fixed_duration(
                    10,
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                )
                .unwrap(),
            )),
            activity: Arc::new(crate::datagram_activity::AuthenticatedDatagramActivity::new()),
        };
        let mut a =
            ParallelSession::new(a_offer, &[2; 32], &[3; 32], [1; 32], context.clone(), None);
        let b = ParallelSession::new(b_offer, &[3; 32], &[2; 32], [1; 32], context, None);
        assert!(a.reliable().is_none());
        let mut lanes = vec![
            REALTIME,
            BULK,
            BACKGROUND,
            LOCAL_RECOVERABLE_DATA_LANE,
            crate::LOCAL_SIGNALING_LANE,
        ];
        if auxiliary_only { lanes.push(crate::LOCAL_NETWORK_CONTROL_LANE); }
        for &lane in &lanes {
            timeout(Duration::from_secs(5), async {
                while !a.prepare(lane) {
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
        assert_eq!(diagnostics.active_connections(), lanes.len());
        let mut bindings = HashSet::new();
        let mut handles = Vec::new();
        for (seq, lane) in lanes.into_iter().enumerate() {
            // Identical neutral circuit framing for every trusted local source.
            let frame = primary_test_frame(true, seq as u32, 0);
            let (header, body, kind) = super::super::decode_realtime_lane_frame(&frame).unwrap();
            assert_eq!(header.priority(), INTERACTIVE);
            let index = a.prepare_frame(lane, body, kind).unwrap();
            let sender = a.sender(index);
            assert!(bindings.insert(sender.handle.quic().unwrap().channel_binding().unwrap()));
            handles.push(sender.handle.quic().unwrap().clone());
        }
        if auxiliary_only {
            assert_eq!(factory.available_connection_slots(), 2);
            // Fill both remaining generic slots. Closing/replacing signaling
            // at the original eight-child quota must retain every other owner.
            for index in [6, 7] {
                timeout(Duration::from_secs(3), async {
                    while !a.prepare_without_recovery(index) {
                        sleep(Duration::from_millis(5)).await;
                    }
                }).await.unwrap();
            }
            assert_eq!(factory.available_connection_slots(), 0);
            assert_eq!(diagnostics.active_connections(), 8);
        }
        if late_idle {
            // Exceed the real QUIC idle timeout without shortening config or
            // advancing a test clock. Retained generic siblings must survive
            // without application data. Then force an actual transport close
            // and verify the existing replacement/primary-isolation behavior.
            let audio_binding = handles[0].channel_binding().unwrap();
            let idle_started = Instant::now();
            let mut seq = 100u32;
            let mut heartbeat_at = Duration::ZERO;
            let mut late_sent = [false; 2];
            let mut late_received = [false; 2];
            let mut idle_observed = false;
            let mut primary_peak = Duration::ZERO;
            let mut reopened_handles = Vec::new();
            while idle_started.elapsed() < Duration::from_secs(35)
                || !late_received.iter().all(|received| *received)
            {
                let round = Instant::now();
                let elapsed = idle_started.elapsed();
                assert!(elapsed < Duration::from_secs(40), "late sources must reopen within the existing five-second preparation budget");
                if elapsed >= heartbeat_at {
                    a_stream.write_all(b"ping").await.unwrap();
                    let mut ping = [0; 4];
                    b_stream.read_exact(&mut ping).await.unwrap();
                    assert_eq!(&ping, b"ping");
                    heartbeat_at = elapsed + Duration::from_secs(5);
                }
                if elapsed >= Duration::from_secs(35) {
                    if !idle_observed {
                        for index in [1, 2] {
                            assert!(!handles[index].is_closed(),
                                "retained idle child must not force recurring TLS dials");
                            handles[index].close();
                            timeout(Duration::from_millis(100), handles[index].closed()).await
                                .expect("explicitly retired child must close before reopening");
                        }
                        idle_observed = true;
                    }
                    for (index, lane) in [BULK, BACKGROUND].into_iter().enumerate() {
                        if late_sent[index] { continue; }
                        let frame = primary_test_frame(true, 1_000_000 + index as u32, 0);
                        let (_, body, kind) = super::super::decode_realtime_lane_frame(&frame).unwrap();
                        if let Some(slot) = a.prepare_frame(lane, body, kind) {
                            let mut sender = a.sender(slot);
                            let handle = sender.handle.quic().unwrap().clone();
                            let binding = handle.channel_binding().unwrap();
                            assert_ne!(binding, handles[index + 1].channel_binding().unwrap());
                            assert_ne!(binding, audio_binding, "late source cannot share primary congestion state");
                            let max_size = sender.max_datagram_size;
                            for packet in sender.tx.encode_frame(u64::from(lane), &frame, max_size).unwrap() {
                                sender.handle.send(&packet).unwrap();
                            }
                            reopened_handles.push(handle);
                            late_sent[index] = true;
                        }
                    }
                }
                let frame = primary_test_frame(true, seq, 0);
                let (_, body, kind) = super::super::decode_realtime_lane_frame(&frame).unwrap();
                let slot = a.prepare_frame(REALTIME, body, kind).expect("primary stays ready while other sources close/warm");
                let primary_sent = Instant::now();
                {
                    let mut sender = a.sender(slot);
                    assert_eq!(sender.handle.quic().unwrap().channel_binding().unwrap(), audio_binding);
                    let max_size = sender.max_datagram_size;
                    for packet in sender.tx.encode_frame(u64::from(REALTIME), &frame, max_size).unwrap() {
                        sender.handle.send(&packet).unwrap();
                    }
                }
                timeout(Duration::from_millis(200), async {
                    loop {
                        let (observed, _, _) = rx.recv().await.unwrap();
                        if observed == seq { break; }
                        assert!((1_000_000..1_000_002).contains(&observed), "primary loss/duplicate/reordering");
                        let index = (observed - 1_000_000) as usize;
                        assert!(!late_received[index], "late source duplicate");
                        late_received[index] = true;
                    }
                }).await.expect("primary packet held by late source preparation");
                primary_peak = primary_peak.max(primary_sent.elapsed());
                seq += 1;
                sleep_until(round + Duration::from_millis(20)).await;
            }
            assert!(idle_observed && late_sent.iter().all(|sent| *sent));
            assert!(late_received.iter().all(|received| *received));
            eprintln!("late sources: primary_packets={} primary_packet_peak_ms={:.3} real_idle_seconds=35 camera_and_screen_received=true", seq - 100, primary_peak.as_secs_f64() * 1000.0);
            drop((a, b));
            close.close(0u32.into(), b"late local source separation complete");
            handles.extend(reopened_handles);
            for handle in handles {
                timeout(Duration::from_secs(1), handle.closed()).await.unwrap();
            }
            assert_eq!(diagnostics.active_connections(), 0);
            return;
        }
        // Channel maintenance may retire a previously prepared signaling
        // child. Repeated real transport closes must report unavailability,
        // then reopen with new keys, while the audio child keeps working.
        // The physical call-start failure exercises the narrower close /
        // capacity race between the old two readiness polls.
        let frame = primary_test_frame(true, 80, 0);
        let (_, body, kind) = super::super::decode_realtime_lane_frame(&frame).unwrap();
        for seq in 80..83 {
            let retired_binding = handles[4].channel_binding().unwrap();
            handles[4].close();
            timeout(Duration::from_secs(1), handles[4].closed())
                .await
                .unwrap();
            assert!(
                a.prepare_frame(crate::LOCAL_SIGNALING_LANE, body, kind)
                    .is_none()
            );
            let primary = a.prepare_frame(REALTIME, body, kind).unwrap();
            assert_eq!(
                a.sender(primary)
                    .handle
                    .quic()
                    .unwrap()
                    .channel_binding()
                    .unwrap(),
                handles[0].channel_binding().unwrap()
            );
            {
                let primary_frame = primary_test_frame(true, seq + 1000, 0);
                let mut sender = a.sender(primary);
                let max_size = sender.max_datagram_size;
                for packet in sender
                    .tx
                    .encode_frame(100, &primary_frame, max_size)
                    .unwrap()
                {
                    sender.handle.send(&packet).unwrap();
                }
            }
            assert_eq!(
                timeout(Duration::from_secs(2), rx.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
                seq + 1000
            );
            let index = timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(index) = a.prepare_frame(crate::LOCAL_SIGNALING_LANE, body, kind) {
                        break index;
                    }
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            let frame = primary_test_frame(true, seq, 0);
            let new_handle = {
                let mut sender = a.sender(index);
                let new_handle = sender.handle.quic().unwrap().clone();
                assert_ne!(new_handle.channel_binding().unwrap(), retired_binding);
                let max_size = sender.max_datagram_size;
                for packet in sender.tx.encode_frame(99, &frame, max_size).unwrap() {
                    sender.handle.send(&packet).unwrap();
                }
                new_handle
            };
            assert_eq!(
                timeout(Duration::from_secs(2), rx.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
                seq
            );
            handles[4] = new_handle;
        }
        // Retiring only the screen connection cannot retire the file source
        // or silently fall back to a shared canonical congestion controller.
        let screen_binding = handles[2].channel_binding().unwrap();
        handles[2].close();
        timeout(Duration::from_secs(1), handles[2].closed())
            .await
            .unwrap();
        for (seq, lane) in [
            REALTIME,
            BULK,
            LOCAL_RECOVERABLE_DATA_LANE,
            crate::LOCAL_SIGNALING_LANE,
        ]
        .into_iter()
        .enumerate()
        {
            let frame = primary_test_frame(true, seq as u32, 0);
            let (_, body, kind) = super::super::decode_realtime_lane_frame(&frame).unwrap();
            let index = a.prepare_frame(lane, body, kind).unwrap();
            let mut sender = a.sender(index);
            assert_ne!(
                sender.handle.quic().unwrap().channel_binding().unwrap(),
                screen_binding
            );
            let max_size = sender.max_datagram_size;
            for packet in sender
                .tx
                .encode_frame(u64::from(lane), &frame, max_size)
                .unwrap()
            {
                sender.handle.send(&packet).unwrap();
            }
        }
        let mut received = HashSet::new();
        timeout(Duration::from_secs(2), async {
            while received.len() < 4 {
                let (seq, _, _) = rx.recv().await.unwrap();
                assert!(received.insert(seq), "one source delivered a duplicate");
            }
        })
        .await
        .unwrap();
        drop((a, b));
        close.close(0u32.into(), b"local source separation stand complete");
        for handle in handles {
            timeout(Duration::from_secs(1), handle.closed())
                .await
                .unwrap();
        }
        assert_eq!(diagnostics.active_connections(), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn verified_primary_replacement_wins_over_old_ack_progress() {
    timeout(Duration::from_secs(20), async {
        use super::super::parallel_lanes::{ParallelQuicOffer, ParallelSession};
        let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let link = NeutralLink::new(
            left.local_addr().unwrap(),
            right.local_addr().unwrap(),
            1_000_000,
            Duration::from_millis(20),
        )
        .await;
        link.enabled.store(true, Ordering::Relaxed);
        let mut ctx = TransportContext::for_debug().unwrap();
        ctx.quic.congestion_control = QuicCongestionControl::Cubic;
        let ctx = Arc::new(ctx);
        let remote = tokio::spawn(promote_punched_quic(
            right,
            link.right_addr,
            Arc::clone(&ctx),
            PunchedQuicRole::Responder,
        ));
        let local = promote_punched_quic(left, link.left_addr, ctx, PunchedQuicRole::Initiator)
            .await
            .unwrap();
        let close = local.quic_connection().unwrap();
        let a_offer = ParallelQuicOffer::new(local.parallel_quic().unwrap()).with_duplex();
        let diagnostics = a_offer.diagnostics();
        let mut a_stream = local.into_stream().unwrap();
        a_stream.write_all(b"main").await.unwrap();
        let remote = remote.await.unwrap().unwrap();
        let b_offer = ParallelQuicOffer::new(remote.parallel_quic().unwrap()).with_duplex();
        let mut b_stream = remote.into_stream().unwrap();
        let mut prefix = [0; 4];
        b_stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"main");
        let started = Instant::now();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let logger = Arc::new(veil_observability::NodeLogger::new_noop());
        let sink: Arc<dyn crate::dispatcher_sink::DispatcherSink> = Arc::new(Capture {
            ingress: None,
            started,
            received: tx,
            logger: Arc::clone(&logger),
        });
        let context = RealtimeReceiverContext {
            peer_id: [9; 32],
            dispatcher: sink,
            logger,
            metrics: None,
            ban_list: Arc::new(Mutex::new(veil_abuse::BanList::new())),
            violation_tracker: Arc::new(Mutex::new(
                veil_abuse::ViolationTracker::with_fixed_duration(
                    10,
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                )
                .unwrap(),
            )),
            activity: Arc::new(crate::datagram_activity::AuthenticatedDatagramActivity::new()),
        };
        let mut a =
            ParallelSession::new(a_offer, &[2; 32], &[3; 32], [1; 32], context.clone(), None);
        let b = ParallelSession::new(b_offer, &[3; 32], &[2; 32], [1; 32], context, None);
        timeout(Duration::from_secs(5), async {
            while !a.prepare(REALTIME) {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let old = a.sender(0).handle.quic().unwrap().clone();
        let old_binding = old.channel_binding().unwrap();
        // A real authenticated candidate can close while its successful
        // preparation result waits for this session to poll it. It must not
        // replace a still-working primary or increment successful switches.
        let stale = a.stage_verified_primary_replacement().await;
        stale.close();
        timeout(Duration::from_secs(1), stale.closed())
            .await
            .unwrap();
        let probe = primary_test_frame(true, 35, started.elapsed().as_micros() as u64);
        let (_, body, kind) = super::super::decode_realtime_lane_frame(&probe).unwrap();
        let index = a
            .prepare_frame(REALTIME, body, kind)
            .expect("a closed prepared candidate must not displace the live primary");
        assert_eq!(diagnostics.recovery_switches(), 0);
        {
            let mut sender = a.sender(index);
            assert_eq!(
                sender.handle.quic().unwrap().channel_binding().unwrap(),
                old_binding
            );
            let max_size = sender.max_datagram_size;
            for packet in sender
                .tx
                .encode_frame(u64::from(REALTIME), &probe, max_size)
                .unwrap()
            {
                sender.handle.send(&packet).unwrap();
            }
        }
        assert_eq!(
            timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap()
                .0,
            35
        );
        // An in-flight user can retain an old ingress carrier after its
        // child closes. This must not pin a downstream slot on a live parent.
        let retained_old_carrier = a.ingress_carrier_for_test(0);
        let old_flow = retained_old_carrier.local_ingress_flow().unwrap();
        let retained_old_witness = Arc::downgrade(&retained_old_carrier);
        let mut downstream = super::super::channel_assignments::ChannelAssignments::<1>::default();
        assert_eq!(
            downstream
                .transit(Some(&retained_old_witness), 0)
                .unwrap()
                .physical,
            0,
        );
        a.stage_verified_primary_replacement().await;
        // Supply a real datagram and wait for its ACK on the OLD child while
        // the authenticated candidate stays queued for the runner to adopt.
        let old_acks = old.path_stats().acknowledgments_received;
        let old_frame = primary_test_frame(true, 36, started.elapsed().as_micros() as u64);
        {
            let mut sender = a.sender(0);
            let size = sender.max_datagram_size;
            for packet in sender
                .tx
                .encode_frame(u64::from(REALTIME), &old_frame, size)
                .unwrap()
            {
                sender.handle.send(&packet).unwrap();
            }
        }
        assert_eq!(
            timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap()
                .0,
            36
        );
        timeout(Duration::from_secs(2), async {
            while old.path_stats().acknowledgments_received <= old_acks {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("old child datagram ACK");
        assert_eq!(
            old.path_stats().pto_count,
            0,
            "the old path can report ACK progress"
        );
        let frame = primary_test_frame(true, 37, started.elapsed().as_micros() as u64);
        let (_, body, kind) = super::super::decode_realtime_lane_frame(&frame).unwrap();
        let index = a.prepare_frame(REALTIME, body, kind).unwrap();
        assert_eq!(
            diagnostics.recovery_switches(),
            1,
            "a completed replacement must be adopted before old ACK progress cancels it"
        );
        assert!(
            retained_old_carrier.local_ingress_flow().is_none(),
            "a retained retired child must stop claiming a live ingress flow",
        );
        let replacement_carrier = a.ingress_carrier_for_test(index);
        let replacement_flow = replacement_carrier.local_ingress_flow().unwrap();
        let replacement_witness = Arc::downgrade(&replacement_carrier);
        assert_eq!(old_flow.parent, replacement_flow.parent);
        assert_ne!(old_flow.connection, replacement_flow.connection);
        assert_eq!(
            downstream
                .transit(Some(&replacement_witness), 0)
                .unwrap()
                .physical,
            0,
            "retirement must free the downstream slot without a canonical rekey",
        );
        {
            let mut sender = a.sender(index);
            assert_ne!(
                sender.handle.quic().unwrap().channel_binding().unwrap(),
                old_binding
            );
            let size = sender.max_datagram_size;
            for packet in sender
                .tx
                .encode_frame(u64::from(REALTIME), &frame, size)
                .unwrap()
            {
                sender.handle.send(&packet).unwrap();
            }
        }
        let received = timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            received.0, 37,
            "the adopted child must deliver fresh datagrams"
        );
        a_stream.write_all(b"live").await.unwrap();
        b_stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"live", "the canonical parent remains usable");
        drop((a, b));
        close.close(0u32.into(), b"verified replacement race complete");
    })
    .await
    .expect("verified replacement race stand timed out");
}
