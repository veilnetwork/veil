//! Full production ordered scheduler: endpoint pressure on another TLS/QUIC
//! neighbor holds local file bytes, but preserves neutral transit and resumes
//! without new input. Payload/ciphertext order is checked at the actual peer.
use super::super::{CryptoState, HotStandbyState, MobileConfig, RekeyConfig, SessionRunner};
use super::*;
use std::sync::{Mutex, RwLock, Weak};
use veil_crypto::session_cipher::SessionCipher;
use veil_proto::{
    family::{AppMsg, FrameFamily},
    header::FrameHeader,
    priority::{INTERACTIVE, REALTIME},
};
use veil_types::NodeIdBytes;

struct Capture {
    logger: Arc<veil_observability::NodeLogger>,
}
impl crate::dispatcher_sink::DispatcherSink for Capture {
    fn dispatch(
        &self,
        h: &FrameHeader,
        body: &[u8],
        peer: NodeIdBytes,
    ) -> crate::dispatcher_sink::DispatchResult {
        let _ = (h, body, peer);
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
        unreachable!("outgoing-only fixture")
    }
    fn rendezvous_weak(&self) -> Arc<Mutex<Option<Weak<crate::rendezvous::RendezvousController>>>> {
        unreachable!("outgoing-only fixture")
    }
    fn pow_solver_semaphore(&self) -> Arc<tokio::sync::Semaphore> {
        unreachable!("outgoing-only fixture")
    }
    fn pow_active_difficulty(&self) -> Arc<std::sync::atomic::AtomicU64> {
        unreachable!("outgoing-only fixture")
    }
    fn route_cache(&self) -> Arc<RwLock<veil_routing::RouteCache>> {
        unreachable!("outgoing-only fixture")
    }
    fn register_session_aliases(&self, _: [u8; 8], _: NodeIdBytes, _: [u8; 8], _: NodeIdBytes) {
        unreachable!("outgoing-only fixture")
    }
    fn unregister_session_aliases(&self, _: [u8; 8], _: [u8; 8]) {
        unreachable!("outgoing-only fixture")
    }
}

async fn pair_full() -> (
    NeutralLink,
    QuicDatagramHandle,
    QuicDatagramHandle,
    veil_transport::BoxIoStream,
    veil_transport::BoxIoStream,
) {
    let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let link = NeutralLink::new(
        left.local_addr().unwrap(),
        right.local_addr().unwrap(),
        1_000_000,
        Duration::from_millis(1),
    )
    .await;
    let ctx = Arc::new(TransportContext::for_debug().unwrap());
    let remote = tokio::spawn(promote_punched_quic(
        right,
        link.right_addr,
        Arc::clone(&ctx),
        PunchedQuicRole::Responder,
    ));
    let local = promote_punched_quic(left, link.left_addr, ctx, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    let handle = local.quic_datagrams().unwrap();
    let mut tx = local.into_stream().unwrap();
    tx.write_all(b"warm").await.unwrap();
    let remote = remote.await.unwrap().unwrap();
    let remote_handle = remote.quic_datagrams().unwrap();
    let mut rx = remote.into_stream().unwrap();
    let mut warm = [0; 4];
    rx.read_exact(&mut warm).await.unwrap();
    assert_eq!(&warm, b"warm");
    timeout(Duration::from_secs(2), async {
        while handle.path_stats().rtt_us >= 150_000 || handle.path_stats().in_flight_bytes != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    (link, handle, remote_handle, tx, rx)
}

async fn pair() -> (
    NeutralLink,
    QuicDatagramHandle,
    veil_transport::BoxIoStream,
    veil_transport::BoxIoStream,
) {
    let (link, handle, _remote, tx, rx) = pair_full().await;
    (link, handle, tx, rx)
}

fn frame(msg: AppMsg, body: &[u8]) -> veil_bufpool::PooledShared {
    let mut h = FrameHeader::new(FrameFamily::App as u8, msg as u16);
    h.set_priority(INTERACTIVE);
    h.stream_id = 71;
    h.body_len = body.len() as u32;
    let mut wire = veil_proto::codec::encode_header(&h).to_vec();
    wire.extend_from_slice(body);
    veil_bufpool::pooled_shared_from_vec(wire)
}

fn make_runner(
    file_stream: veil_transport::BoxIoStream,
    outbox: crate::FrameOutbox,
    offer: Option<super::super::RealtimeLaneOffer>,
) -> SessionRunner {
    let logger = Arc::new(veil_observability::NodeLogger::new_noop());
    let key = [0x51; 32];
    SessionRunner {
        stream: file_stream,
        quic_datagrams: offer,
        peer_id: [0xB1; 32],
        dispatcher: Arc::new(Capture {
            logger: Arc::clone(&logger),
        }),
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
        crypto: CryptoState {
            tx_cipher: Some(SessionCipher::new(&key, true)),
            rx_cipher: Some(SessionCipher::new(&[0x52; 32], true)),
            peer_mlkem_keys: None,
            per_session_mlkem_dk: None,
        },
        outbox: Some(outbox),
        rpc_outbox: None,
        keepalive_interval: Duration::ZERO,
        idle_timeout: Duration::ZERO,
        session_id: [0; 32],
        local_node_id: [0xA0; 32],
        max_pending_responses: 16,
        pending_response_ttl: Duration::from_secs(30),
        max_frame_body: 65536,
        rekey: RekeyConfig {
            bytes_threshold: u64::MAX,
            time_threshold_secs: u64::MAX,
        },
        qos_weights: [8, 4, 2, 1],
        mobile: MobileConfig {
            base_keepalive_interval: Duration::ZERO,
            battery_keepalive_scale_low: 1.0,
            battery_keepalive_scale_medium: 1.0,
            battery_threshold_low: 20,
            battery_threshold_medium: 50,
        },
        ticket_to_send: None,
        peer_tickets: None,
        raw_session_keys: None,
        peer_public_key: None,
        peer_nonce: None,
        hot_standby: HotStandbyState {
            swap_registry: None,
            swap_rx: None,
            handoff_registry: None,
            handoff_ack_waiters: None,
            controller: None,
            auto_trigger_after_write_errors: 0,
        },
        primary_uri: None,
    }
}

#[tokio::test]
async fn pressured_ordered_file_keeps_bytes_and_wakes_without_input() {
    use super::super::local_reliable_admission::LocalReliableAdmission;
    use veil_proto::app::{AppClosePayload, AppDataPayload, AppOpenPayload};
    let (primary_link, primary, _primary_stream, _primary_peer) = pair().await;
    let (_file_link, file_handle, file_stream, mut peer) = pair().await;
    let mut node = crate::SessionTxRegistry::new();
    let primary_outbox = node.register([0xA1; 32]);
    let file_outbox = node.register([0xB1; 32]);
    let sender = node.get_sender(&[0xB1; 32]).unwrap().clone();
    let mut admission = LocalReliableAdmission::for_source(
        primary.clone(),
        primary_outbox.shared_source_activity(),
    );
    admission.observe(
        REALTIME,
        &circuit_frame(1, 0x11),
        std::time::Instant::now(),
        true,
    );
    primary_link.blackout.store(true, Ordering::Relaxed);
    primary.send(&[0x11; 200]).unwrap();
    timeout(Duration::from_secs(2), async {
        while primary.path_stats().pto_count == 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let pressured = std::time::Instant::now();
    admission.observe_primary_path(&primary, pressured);
    admission.observe(REALTIME, &circuit_frame(1, 0x11), pressured, true);
    assert!(primary.path_stats().rtt_us < 150_000);
    assert_eq!(primary.path_stats().expired_outgoing_datagrams, 0);
    let key = [0x51; 32];
    let mut runner = make_runner(file_stream, file_outbox, None);
    let app_id = [0x42; 32];
    assert!(
        sender
            .send_reliable(frame(
                AppMsg::AppOpen,
                &AppOpenPayload {
                    app_id,
                    endpoint_id: 9,
                    flags: 0
                }
                .encode()
            ))
            .await
    );
    let data: Vec<u8> = (0..48 * 3900).map(|n| (n % 251) as u8).collect();
    for segment in data.chunks(veil_proto::budget::LOCAL_STREAM_SEGMENT_DATA_BYTES) {
        assert!(
            sender
                .send_reliable(frame(
                    AppMsg::AppData,
                    &AppDataPayload {
                        app_id,
                        endpoint_id: 9,
                        seq: 0,
                        data: segment.to_vec()
                    }
                    .encode()
                ))
                .await
        );
    }
    assert!(
        sender
            .send_reliable(frame(
                AppMsg::AppClose,
                &AppClosePayload {
                    app_id,
                    endpoint_id: 9,
                    reason: 0
                }
                .encode()
            ))
            .await
    );
    // Queue neutral work only AFTER the file was held. It must still pass.
    let job = tokio::spawn(async move {
        runner.run().await;
    });
    sleep(Duration::from_millis(30)).await;
    sender
        .send((INTERACTIVE, frame(AppMsg::AppSend, b"neutral-transit")))
        .await
        .unwrap();
    let mut reader = super::super::ordered_reader::Reader::default();
    let mut cipher = SessionCipher::new(&key, true);
    let mut received = Vec::new();
    let mut opened = false;
    let mut neutral = false;
    let mut early_bytes = 0;
    let ended = timeout(Duration::from_secs(6), async {
        loop {
            let wire = reader.read(&mut peer, 65536).await.unwrap();
            let body = cipher
                .open(&wire.body, &veil_proto::codec::frame_aad(&wire.header))
                .unwrap();
            if wire.header.family == FrameFamily::Session as u8 {
                continue;
            }
            assert_eq!(
                wire.header.priority(),
                INTERACTIVE,
                "no endpoint source hint on wire"
            );
            match wire.header.msg_type {
                x if x == AppMsg::AppOpen as u16 => {
                    assert!(!opened);
                    opened = true;
                }
                x if x == AppMsg::AppData as u16 => {
                    assert!(opened);
                    let p = AppDataPayload::decode(&body).unwrap();
                    assert_eq!(p.seq, 0);
                    received.extend_from_slice(&p.data);
                    if pressured.elapsed() < Duration::from_millis(180) {
                        early_bytes += p.data.len();
                    }
                }
                x if x == AppMsg::AppSend as u16 => {
                    assert_eq!(body, b"neutral-transit");
                    assert!(
                        pressured.elapsed() < Duration::from_millis(180),
                        "neutral traffic held behind local producer pressure"
                    );
                    neutral = true;
                }
                x if x == AppMsg::AppClose as u16 => {
                    assert!(opened);
                    break pressured.elapsed();
                }
                x => panic!("unexpected message {x}"),
            }
        }
    })
    .await
    .unwrap();
    assert!(
        early_bytes <= 3900,
        "ordered file bypassed pressure on another neighbor: {early_bytes}"
    );
    assert!(neutral);
    assert!(
        ended >= Duration::from_millis(400),
        "file should wait for source pressure deadlines"
    );
    assert_eq!(
        received, data,
        "no loss, duplication or reordered bytes through holds and cipher batches"
    );
    // No more outbox/incoming/keepalive activity was required to resume.
    file_handle.close();
    primary.close();
    timeout(Duration::from_secs(2), job).await.unwrap().unwrap();
}

#[derive(Clone, Copy)]
enum OrderedPrimary {
    NoDatagrams,
    NeutralForward,
    LegacyCircuit,
}

fn primary_frame(mode: OrderedPrimary) -> veil_bufpool::PooledShared {
    if matches!(mode, OrderedPrimary::LegacyCircuit) {
        return veil_bufpool::pooled_shared_from_vec(circuit_frame(1, 0x71));
    }
    use veil_proto::{
        delivery::{DeliveryEnvelope, ForwardPayload},
        family::DeliveryMsg,
    };
    let body = ForwardPayload {
        next_hop_node_id: [0xD1; 32],
        envelope: DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any([0xC1; 32]),
            sender_node_id: [0xA0; 32],
            src_app_id: [0x42; 32],
            app_id: [0x42; 32],
            endpoint_id: 9,
            content_id: [0x43; 32],
            created_at: veil_util::unix_secs_now_u64(),
            ttl_secs: veil_proto::delivery::FORWARD_REALTIME_TTL_SECS,
            payload: vec![0x71; 256],
            trace_id: 0,
            require_ack: false,
        },
        relay_hops: 0,
        delivery_attempt: None,
        traffic_class: Some(INTERACTIVE),
    }
    .encode();
    let mut h = FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
    h.set_priority(INTERACTIVE);
    h.body_len = body.len() as u32;
    let mut bytes = veil_proto::codec::encode_header(&h).to_vec();
    bytes.extend_from_slice(&body);
    veil_bufpool::pooled_shared_from_vec(bytes)
}

async fn verify_ordered_primary_feedback(mode: OrderedPrimary) {
    use super::super::RealtimeLaneOffer;
    use veil_proto::app::AppDataPayload;
    let (link, handle, remote_handle, stream, mut peer) = pair_full().await;
    let (_file_link, file_handle, file_stream, mut file_peer) = pair().await;
    let mut node = crate::SessionTxRegistry::new();
    let primary_outbox = node.register([0xB1; 32]);
    let source = primary_outbox.shared_source_activity();
    let sender = node.get_sender(&[0xB1; 32]).unwrap().clone();
    let file_outbox = node.register([0xB2; 32]);
    let file_sender = node.get_sender(&[0xB2; 32]).unwrap().clone();
    let offer = RealtimeLaneOffer {
        peer_datagrams: !matches!(mode, OrderedPrimary::NoDatagrams),
        handle: handle.clone(),
        peer_rotates: false,
        peer_flows: false,
        peer_circuit_datagrams: false,
        peer_neutral_forwards: false,
        parallel: None,
    };
    let mut runner = make_runner(stream, primary_outbox, Some(offer));
    runner.raw_session_keys = Some(([0x51; 32], [0x52; 32], [0; 32]));
    let job = tokio::spawn(async move {
        runner.run().await;
    });
    let bytes = primary_frame(mode);
    assert!(super::super::decode_realtime_lane_frame(&bytes).is_some());
    // A transit packet claiming REALTIME on wire cannot publish source policy.
    let mut claimed = bytes.to_vec();
    let mut claimed_header = veil_proto::codec::decode_header(&claimed).unwrap();
    claimed_header.set_priority(REALTIME);
    claimed[..veil_proto::header::HEADER_SIZE]
        .copy_from_slice(&veil_proto::codec::encode_header(&claimed_header));
    sender
        .send((INTERACTIVE, veil_bufpool::pooled_shared_from_vec(claimed)))
        .await
        .unwrap();
    let mut primary_reader = super::super::ordered_reader::Reader::default();
    let mut primary_cipher = SessionCipher::new(&[0x51; 32], true);
    timeout(Duration::from_secs(1), async {
        let wire = primary_reader.read(&mut peer, 65536).await.unwrap();
        primary_cipher
            .open(&wire.body, &veil_proto::codec::frame_aad(&wire.header))
            .unwrap();
    })
    .await
    .unwrap();
    assert!(!source.active(std::time::Instant::now()));
    timeout(Duration::from_secs(1), async {
        while handle.path_stats().in_flight_bytes != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    link.blackout.store(true, Ordering::Relaxed);
    let stop = Arc::new(AtomicBool::new(false));
    let producer_stop = Arc::clone(&stop);
    let producer = tokio::spawn(async move {
        for _ in 0..100 {
            if producer_stop.load(Ordering::Relaxed) {
                break;
            }
            sender.send((REALTIME, bytes.clone())).await.unwrap();
            sleep(Duration::from_millis(20)).await;
        }
    });
    timeout(Duration::from_secs(2), async {
        loop {
            if handle.path_stats().pto_count > 0
                && !source.allow_secondary(std::time::Instant::now())
            {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ordered primary path never published pressure to another neighbor");
    let stats = handle.path_stats();
    assert!(
        stats.rtt_us < 150_000,
        "no delayed RTT is needed to detect the ACK blackout"
    );
    assert_eq!(stats.expired_outgoing_datagrams, 0);
    assert!(
        stats.in_flight_bytes > 2048,
        "ordered primary cannot inherit a 1-KiB reliable window"
    );
    assert!(
        timeout(Duration::from_millis(30), remote_handle.recv())
            .await
            .is_err(),
        "no datagrams may be sent to this compatibility peer"
    );
    stop.store(true, Ordering::Relaxed);
    producer.await.unwrap();
    link.blackout.store(false, Ordering::Relaxed);
    // Read and decrypt the actual fallback framing, including the old circuit
    // discriminant; the peer does not need a datagram decoder or a new role.
    timeout(Duration::from_secs(2), async {
        loop {
            let wire = primary_reader.read(&mut peer, 65536).await.unwrap();
            primary_cipher
                .open(&wire.body, &veil_proto::codec::frame_aad(&wire.header))
                .unwrap();
            if wire.header.family == FrameFamily::Session as u8 {
                continue;
            }
            assert_eq!(wire.header.priority(), INTERACTIVE);
            if matches!(mode, OrderedPrimary::LegacyCircuit) {
                assert_eq!(
                    wire.header.msg_type,
                    veil_proto::family::RelayChainMsg::CircuitData as u16
                );
            } else {
                assert_eq!(
                    wire.header.msg_type,
                    veil_proto::family::DeliveryMsg::Forward as u16
                );
            }
            break;
        }
    })
    .await
    .unwrap();
    // Retiring this publisher must leave the other session's pressure grace.
    handle.close();
    timeout(Duration::from_secs(2), job).await.unwrap().unwrap();
    let expected: Vec<u8> = (0..3 * 3900).map(|n| (n % 251) as u8).collect();
    for data in expected.chunks(3900) {
        assert!(
            file_sender
                .send_reliable(frame(
                    AppMsg::AppData,
                    &AppDataPayload {
                        app_id: [0x42; 32],
                        endpoint_id: 9,
                        seq: 0,
                        data: data.to_vec()
                    }
                    .encode()
                ))
                .await
        );
    }
    file_sender
        .send((INTERACTIVE, frame(AppMsg::AppSend, b"neutral")))
        .await
        .unwrap();
    let mut file_runner = make_runner(file_stream, file_outbox, None);
    let file_job = tokio::spawn(async move {
        file_runner.run().await;
    });
    let began = std::time::Instant::now();
    let mut output = Vec::new();
    let mut neutral = false;
    let mut reader = super::super::ordered_reader::Reader::default();
    let mut cipher = SessionCipher::new(&[0x51; 32], true);
    timeout(Duration::from_secs(2), async {
        while output.len() < expected.len() {
            let wire = reader.read(&mut file_peer, 65536).await.unwrap();
            let body = cipher
                .open(&wire.body, &veil_proto::codec::frame_aad(&wire.header))
                .unwrap();
            if wire.header.family == FrameFamily::Session as u8 {
                continue;
            }
            if wire.header.msg_type == AppMsg::AppSend as u16 {
                assert_eq!(body, b"neutral");
                assert!(output.len() < expected.len());
                neutral = true;
            } else {
                assert_eq!(wire.header.msg_type, AppMsg::AppData as u16);
                let p = AppDataPayload::decode(&body).unwrap();
                assert_eq!(p.seq, 0);
                output.extend(p.data);
            }
        }
    })
    .await
    .unwrap();
    assert!(neutral);
    assert_eq!(output, expected);
    assert!(
        began.elapsed() >= Duration::from_millis(350),
        "other neighbor's ordered file bypassed primary pressure"
    );
    file_handle.close();
    timeout(Duration::from_secs(2), file_job)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn ordered_primary_feedback_survives_peer_without_datagram_decoder() {
    verify_ordered_primary_feedback(OrderedPrimary::NoDatagrams).await;
}
#[tokio::test]
async fn ordered_primary_feedback_survives_peer_without_neutral_forward_datagrams() {
    verify_ordered_primary_feedback(OrderedPrimary::NeutralForward).await;
}
#[tokio::test]
async fn ordered_primary_feedback_survives_legacy_circuit_carrier() {
    verify_ordered_primary_feedback(OrderedPrimary::LegacyCircuit).await;
}
