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
    captured_frames: Option<Arc<std::sync::atomic::AtomicUsize>>,
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
    fn capture_outbound(&self, _: NodeIdBytes, bytes: &[u8]) {
        if let Some(count) = &self.captured_frames
            && veil_proto::codec::decode_header(bytes).is_ok_and(|header| {
                header.family == FrameFamily::Delivery as u8
                    && header.msg_type == veil_proto::family::DeliveryMsg::Forward as u16
            })
        {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }
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

pub(super) fn make_runner(
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
            captured_frames: None,
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
    let data: Vec<u8> = (0..48 * 3900).map(|n| (n % 251) as u8).collect();
    let produced = data.clone();
    let producer_sender = sender.clone();
    // Exercise backpressure with a live consumer. Preloading the entire file
    // before starting the runner assumes all file frames fit in lookahead.
    let producer = tokio::spawn(async move {
        assert!(
            producer_sender
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
        for segment in produced.chunks(veil_proto::budget::LOCAL_STREAM_SEGMENT_DATA_BYTES) {
            assert!(
                producer_sender
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
            producer_sender
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
    });
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
    producer.await.unwrap();
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

// A burst below the envelope fragmentation threshold must share the endpoint
// pressure policy with files. Its neutral wire header must not throttle transit.
// Read the real encrypted stream to check ordering and wakeups, not just a gate.
#[tokio::test]
async fn pressured_small_authored_messages_preserve_transit_and_all_bytes() {
    use super::super::local_reliable_admission::LocalReliableAdmission;
    let (primary_link, primary, _primary_stream, _primary_peer) = pair().await;
    let (_data_link, data_handle, data_stream, mut peer) = pair().await;
    let mut node = crate::SessionTxRegistry::new();
    let primary_outbox = node.register([0xA1; 32]);
    let data_outbox = node.register([0xB1; 32]);
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
    let mut runner = make_runner(data_stream, data_outbox, None);
    let expected: Vec<Vec<u8>> = (0..32u8).map(|n| vec![n; 400]).collect();
    // The local source credit spans ingress and scheduling. Run its consumer
    // concurrently instead of deadlocking setup by filling a bounded source
    // before the scheduler starts. All original pressure/delivery gates remain.
    let source = sender.clone();
    let outgoing = expected.clone();
    let producer = tokio::spawn(async move {
        for body in outgoing {
            source
                .send((
                    veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
                    frame(AppMsg::AppSend, &body),
                ))
                .await
                .unwrap();
        }
    });
    let job = tokio::spawn(async move {
        runner.run().await;
    });
    sleep(Duration::from_millis(30)).await;
    sender
        .send((INTERACTIVE, frame(AppMsg::AppSend, b"neutral-transit")))
        .await
        .unwrap();
    let mut reader = super::super::ordered_reader::Reader::default();
    let mut cipher = SessionCipher::new(&[0x51; 32], true);
    let mut received = Vec::new();
    let mut neutral = false;
    let mut early_bytes = 0;
    let ended = timeout(Duration::from_secs(6), async {
        while received.len() < expected.len() || !neutral {
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
                "wire does not reveal origin"
            );
            assert_eq!(wire.header.msg_type, AppMsg::AppSend as u16);
            if body == b"neutral-transit" {
                assert!(
                    pressured.elapsed() < Duration::from_millis(180),
                    "transit blocked by this endpoint's authored burst"
                );
                assert!(!neutral, "duplicate transit");
                neutral = true;
            } else {
                if pressured.elapsed() < Duration::from_millis(180) {
                    early_bytes += body.len();
                }
                received.push(body);
            }
        }
        pressured.elapsed()
    })
    .await
    .unwrap();
    assert!(
        early_bytes <= 3900,
        "small messages bypassed audio pressure: {early_bytes}"
    );
    assert!(
        ended >= Duration::from_millis(400),
        "source did not wait for pressure windows"
    );
    assert_eq!(
        received, expected,
        "lost, duplicated or reordered authored message"
    );
    timeout(Duration::from_secs(1), producer)
        .await
        .unwrap()
        .unwrap();
    data_handle.close();
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
        transport: super::super::RealtimeTransportOffer::Quic(handle.clone()),
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
                && !source.allow_secondary(
                    crate::local_source_activity::LOSSY_SECONDARY_BYTES,
                    std::time::Instant::now(),
                )
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
    // Run the consumer while the bounded source lookahead applies backpressure.
    let produced = expected.clone();
    let producer_sender = file_sender.clone();
    let file_producer = tokio::spawn(async move {
        for data in produced.chunks(3900) {
            assert!(
                producer_sender
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
    });
    // Neutral traffic is independent of the blocked file producer.
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
    file_producer.await.unwrap();
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

#[tokio::test]
async fn stream_only_primary_backpressure_holds_a_healthy_neighbor_file() {
    verify_stream_only_primary_backpressure(0).await;
}

#[tokio::test]
async fn ordered_primary_keeps_freshness_before_immutable_ciphertext_queue() {
    verify_primary_write_ahead(40, false).await;
}

#[tokio::test]
async fn ordered_primary_burst_keeps_one_frame_per_ciphertext_blob() {
    verify_primary_write_ahead(4, true).await;
}

async fn verify_primary_write_ahead(frame_count: u8, burst: bool) {
    let (stream, mut peer) = tokio::io::duplex(64);
    let mut registry = crate::SessionTxRegistry::new();
    let outbox = registry.register([0xB1; 32]);
    let sender = registry.get_sender(&[0xB1; 32]).unwrap().clone();
    let captures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut runner = make_runner(Box::new(stream), outbox, None);
    runner.dispatcher = Arc::new(Capture {
        logger: Arc::clone(&runner.logger),
        captured_frames: Some(Arc::clone(&captures)),
    });
    let job = tokio::spawn(async move {
        runner.run().await;
    });
    // The real sender's suffix remains present on an ordered compatibility
    // hop. Stop the reader while fresh source packets arrive at 50 per second.
    for seq in 0..frame_count {
        let mut bytes = primary_frame(OrderedPrimary::NeutralForward).to_vec();
        bytes[veil_proto::header::HEADER_SIZE + 32 + veil_proto::delivery::OFFSET_PAYLOAD] = seq;
        sender
            .send((REALTIME, veil_bufpool::pooled_shared_from_vec(bytes)))
            .await
            .unwrap();
        if !burst {
            sleep(Duration::from_millis(20)).await;
        }
    }
    if burst {
        sleep(Duration::from_millis(50)).await;
    }
    let committed = captures.load(Ordering::Relaxed);
    assert!(
        committed <= 2,
        "primary write-ahead escaped its freshness queue: {committed}"
    );
    let mut reader = super::super::ordered_reader::Reader::default();
    let mut cipher = SessionCipher::new(&[0x51; 32], true);
    let mut sequences = Vec::new();
    timeout(Duration::from_secs(2), async {
        loop {
            let wire = reader.read(&mut peer, 65536).await.unwrap();
            let plaintext = cipher
                .open(&wire.body, &veil_proto::codec::frame_aad(&wire.header))
                .unwrap();
            if wire.header.family != FrameFamily::Delivery as u8 {
                continue;
            }
            let decoded = veil_proto::delivery::ForwardPayload::decode(&plaintext).unwrap();
            assert_eq!(decoded.traffic_class, Some(INTERACTIVE));
            let seq = decoded.envelope.payload[0];
            sequences.push(seq);
            if seq == frame_count - 1 {
                break;
            }
        }
    })
    .await
    .expect("fresh queued primary did not resume without new input");
    assert_eq!(
        sequences.len(),
        sequences
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
    assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        sequences
            .iter()
            .skip(committed)
            .all(|&seq| seq >= frame_count.saturating_sub(10)),
        "stale source packets replayed: {sequences:?}"
    );
    drop(peer);
    timeout(Duration::from_secs(2), job).await.unwrap().unwrap();
}

#[tokio::test]
async fn primary_queued_behind_neutral_ciphertext_holds_other_producers() {
    verify_stream_only_primary_backpressure(1).await;
}

#[tokio::test]
async fn primary_queued_behind_a_full_neutral_writer_holds_other_producers() {
    verify_stream_only_primary_backpressure(128).await;
}

async fn verify_stream_only_primary_backpressure(neutral_prefix: usize) {
    use veil_proto::app::AppDataPayload;
    let (primary_stream, mut primary_peer) = tokio::io::duplex(64);
    let (_link, file_handle, file_stream, mut file_peer) = pair().await;
    let mut node = crate::SessionTxRegistry::new();
    let primary_outbox = node.register([0xB1; 32]);
    let source = primary_outbox.shared_source_activity();
    let primary_sender = node.get_sender(&[0xB1; 32]).unwrap().clone();
    let file_outbox = node.register([0xB2; 32]);
    let file_sender = node.get_sender(&[0xB2; 32]).unwrap().clone();
    let secondary_outbox = node.register([0xB3; 32]);
    let secondary_sender = node.get_sender(&[0xB3; 32]).unwrap().clone();
    let bytes = primary_frame(OrderedPrimary::NeutralForward);
    for _ in 0..neutral_prefix {
        primary_sender
            .send((INTERACTIVE, frame(AppMsg::AppSend, &[0xCC; 5000])))
            .await
            .unwrap();
    }
    let mut runner = make_runner(Box::new(primary_stream), primary_outbox, None);
    let primary_job = tokio::spawn(async move {
        runner.run().await;
    });
    if neutral_prefix != 0 {
        sleep(Duration::from_millis(50)).await;
    }
    primary_sender
        .send((REALTIME, bytes.clone()))
        .await
        .unwrap();
    // The encrypted primary blocks on a transport with no QUIC handle.
    timeout(Duration::from_secs(1), async {
        loop {
            let now = std::time::Instant::now();
            // DATA has a budget even before congestion. The independent RPC
            // allowance is pressure-only and proves the writer observation.
            assert!(source.admit_network_control(1024, now).is_ok());
            if source.admit_network_control(1024, now).is_err() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("stream-only primary never published cross-neighbor pressure");
    // Retain producer activity, as a live call would, while the old blob waits.
    primary_sender
        .send((REALTIME, bytes.clone()))
        .await
        .unwrap();
    // Secondary lossy bytes use a different, healthy stream-only neighbor.
    // They still share one endpoint byte budget and neutral work must pass.
    let (secondary_stream, mut secondary_peer) = tokio::io::duplex(262144);
    for _ in 0..50 {
        secondary_sender
            .send((veil_proto::priority::BULK, bytes.clone()))
            .await
            .unwrap();
    }
    secondary_sender
        .send((INTERACTIVE, frame(AppMsg::AppSend, b"neutral-secondary")))
        .await
        .unwrap();
    let mut secondary_runner = make_runner(Box::new(secondary_stream), secondary_outbox, None);
    let secondary_began = std::time::Instant::now();
    let secondary_job = tokio::spawn(async move {
        secondary_runner.run().await;
    });
    let secondary_received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let neutral_received = Arc::new(AtomicBool::new(false));
    let count = Arc::clone(&secondary_received);
    let neutral_count = Arc::clone(&neutral_received);
    let expected_secondary = bytes.clone();
    let secondary_read = tokio::spawn(async move {
        let mut reader = super::super::ordered_reader::Reader::default();
        let mut cipher = SessionCipher::new(&[0x51; 32], true);
        timeout(Duration::from_secs(5), async {
            loop {
                let wire = reader.read(&mut secondary_peer, 65536).await.unwrap();
                let body = cipher
                    .open(&wire.body, &veil_proto::codec::frame_aad(&wire.header))
                    .unwrap();
                if wire.header.family == FrameFamily::Session as u8 {
                    continue;
                }
                assert_eq!(
                    wire.header.priority(),
                    INTERACTIVE,
                    "no source role on wire"
                );
                if wire.header.family == FrameFamily::App as u8 {
                    assert_eq!(body, b"neutral-secondary");
                    neutral_count.store(true, Ordering::Relaxed);
                } else {
                    assert_eq!(body, &expected_secondary[veil_proto::header::HEADER_SIZE..]);
                    count.fetch_add(1, Ordering::Relaxed);
                    if wire.header.stream_id == 72 {
                        break;
                    }
                }
            }
        })
        .await
        .unwrap();
        secondary_peer
    });
    sleep(Duration::from_millis(180)).await;
    let admitted = secondary_received.load(Ordering::Relaxed);
    let cost = super::super::encrypted_wire_len(bytes.len()).unwrap();
    let windows = 1 + secondary_began.elapsed().as_millis() / 200;
    assert!(
        (admitted * cost) as u128
            <= windows * crate::local_source_activity::LOSSY_SECONDARY_BYTES as u128,
        "ordered secondary bypassed endpoint byte pressure: items={admitted} cost={cost} windows={windows}"
    );
    assert!(
        admitted > 1,
        "small packets still consume a whole pressure allowance"
    );
    assert!(
        neutral_received.load(Ordering::Relaxed),
        "secondary hold starved neutral work"
    );
    let expected: Vec<u8> = (0..3 * 3900).map(|n| (n % 251) as u8).collect();
    // Run the consumer while the bounded source lookahead applies backpressure.
    let produced = expected.clone();
    let producer_sender = file_sender.clone();
    let file_producer = tokio::spawn(async move {
        for data in produced.chunks(3900) {
            assert!(
                producer_sender
                    .send_reliable(frame(
                        AppMsg::AppData,
                        &AppDataPayload {
                            app_id: [0x42; 32],
                            endpoint_id: 9,
                            seq: 0,
                            data: data.to_vec(),
                        }
                        .encode()
                    ))
                    .await
            );
        }
    });
    // Neutral traffic is independent of the blocked file producer.
    file_sender
        .send((INTERACTIVE, frame(AppMsg::AppSend, b"neutral")))
        .await
        .unwrap();
    let mut file_runner = make_runner(file_stream, file_outbox, None);
    let file_job = tokio::spawn(async move {
        file_runner.run().await;
    });
    let began = std::time::Instant::now();
    let mut reader = super::super::ordered_reader::Reader::default();
    let mut cipher = SessionCipher::new(&[0x51; 32], true);
    let mut output = Vec::new();
    let mut neutral = false;
    timeout(Duration::from_secs(2), async {
        while output.len() < expected.len() {
            let wire = reader.read(&mut file_peer, 65536).await.unwrap();
            let body = cipher
                .open(&wire.body, &veil_proto::codec::frame_aad(&wire.header))
                .unwrap();
            if wire.header.family == FrameFamily::Session as u8 {
                continue;
            }
            assert_eq!(wire.header.priority(), INTERACTIVE);
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
    file_producer.await.unwrap();
    assert_eq!(output, expected);
    assert!(neutral);
    assert!(
        began.elapsed() >= Duration::from_millis(350),
        "file bypassed stalled primary"
    );
    // Unblock and decrypt both primary frames. Pressure ticks never cancel or
    // restart partial encrypted writes or consume an extra cipher nonce.
    if neutral_prefix != 0 {
        let mut fresh = bytes.to_vec();
        let mut header = veil_proto::codec::decode_header(&fresh).unwrap();
        header.stream_id = 73;
        fresh[..veil_proto::header::HEADER_SIZE]
            .copy_from_slice(&veil_proto::codec::encode_header(&header));
        primary_sender
            .send((REALTIME, veil_bufpool::pooled_shared_from_vec(fresh)))
            .await
            .unwrap();
    }
    let mut reader = super::super::ordered_reader::Reader::default();
    let mut cipher = SessionCipher::new(&[0x51; 32], true);
    timeout(Duration::from_secs(2), async {
        let mut received = 0;
        let mut prefix_received = 0;
        let mut fresh_received = false;
        while (if neutral_prefix == 0 {
            received < 2
        } else {
            !fresh_received
        }) || prefix_received < neutral_prefix
        {
            let wire = reader.read(&mut primary_peer, 65536).await.unwrap();
            let body = cipher
                .open(&wire.body, &veil_proto::codec::frame_aad(&wire.header))
                .unwrap();
            if wire.header.family == FrameFamily::Session as u8 {
                continue;
            }
            assert_eq!(wire.header.priority(), INTERACTIVE);
            if wire.header.family == FrameFamily::App as u8 {
                assert_eq!(body, [0xCC; 5000]);
                prefix_received += 1;
            } else {
                assert_eq!(body, &bytes[veil_proto::header::HEADER_SIZE..]);
                if wire.header.stream_id == 73 {
                    fresh_received = true;
                } else {
                    received += 1;
                }
            }
        }
        if neutral_prefix != 0 {
            assert_eq!(
                received,
                if neutral_prefix >= 128 { 0 } else { 1 },
                "old primary remained in the scheduler and must expire before encryption"
            );
        }
    })
    .await
    .unwrap();
    drop(primary_peer);
    // Old lossy frames should expire before encryption. A fresh secondary
    // frame after pressure grace must pass with the same session cipher.
    sleep(crate::local_source_activity::PRESSURE_GRACE + Duration::from_millis(30)).await;
    let mut fresh = bytes.to_vec();
    let mut header = veil_proto::codec::decode_header(&fresh).unwrap();
    header.stream_id = 72;
    fresh[..veil_proto::header::HEADER_SIZE]
        .copy_from_slice(&veil_proto::codec::encode_header(&header));
    secondary_sender
        .send((
            veil_proto::priority::BULK,
            veil_bufpool::pooled_shared_from_vec(fresh),
        ))
        .await
        .unwrap();
    let secondary_peer = secondary_read.await.unwrap();
    assert!(
        secondary_received.load(Ordering::Relaxed) < 50,
        "stale secondary backlog must not drain after pressure"
    );
    drop(secondary_peer);
    timeout(Duration::from_secs(2), secondary_job)
        .await
        .unwrap()
        .unwrap();
    file_handle.close();
    timeout(Duration::from_secs(2), primary_job)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), file_job)
        .await
        .unwrap()
        .unwrap();
}

fn network_query(id: u32) -> Vec<u8> {
    use veil_proto::{discovery::FindNodeV2Payload, family::DiscoveryMsg};
    let body = FindNodeV2Payload {
        target: [id as u8; 32],
        k: 8,
    }
    .encode();
    let mut h = FrameHeader::new(
        FrameFamily::Discovery as u8,
        DiscoveryMsg::FindNodeV2 as u16,
    );
    h.request_id = id;
    h.set_priority(INTERACTIVE);
    h.body_len = body.len() as u32;
    let mut bytes = veil_proto::codec::encode_header(&h).to_vec();
    bytes.extend_from_slice(&body);
    bytes
}

#[tokio::test]
async fn own_rpc_admission_survives_drain_overflow_and_reconnect_ownership() {
    use crate::pending_response_table::PendingResponseTable;
    use crate::{LOCAL_NETWORK_CONTROL_LANE, PriorityQueue, SessionOutbox};
    let outbox = SessionOutbox::with_capacity(2);
    let peer = [0xB1; 32];
    let mut requests = outbox.register_owned(peer, [1; 32]);
    let first = outbox.send_request(peer, 1, network_query(1)).unwrap();
    assert!(outbox.send_oneway(peer, network_query(2)));
    let mut pq = PriorityQueue::with_capacity([8, 4, 2, 1], 1);
    let mut pending = PendingResponseTable::new(8, Duration::from_secs(30));
    while let Ok(req) = requests.try_recv() {
        SessionRunner::queue_rpc_request(req, &mut pq, &mut pending);
    }
    assert!(
        outbox.send_request(peer, 3, network_query(3)).is_none(),
        "mpsc drain must not renew source credits"
    );
    for id in 100..200 {
        pq.push(
            INTERACTIVE,
            veil_bufpool::pooled_shared_from_vec(network_query(id)),
        );
    }
    assert_eq!(pq.len(), 3);
    assert_eq!(pq.drops_total(), 99);
    assert_eq!(&*pq.pop().unwrap(), &network_query(199));
    let held = pq.pop_envelope_if(|_, _| true).unwrap();
    assert_eq!(held.frame.0, LOCAL_NETWORK_CONTROL_LANE);
    assert_eq!(&*held.frame.1, &network_query(1));
    assert!(outbox.send_request(peer, 3, network_query(3)).is_none());
    drop(held);
    assert!(outbox.send_request(peer, 3, network_query(3)).is_some());
    pending
        .take(1)
        .unwrap()
        .send(Some(b"reply".to_vec()))
        .unwrap();
    assert_eq!(first.await.unwrap(), Some(b"reply".to_vec()));
    let mut replacement = outbox.register_owned(peer, [2; 32]);
    assert!(!outbox.unregister_owned(peer, &[1; 32]));
    assert!(outbox.send_oneway(peer, network_query(4)));
    assert!(outbox.send_oneway(peer, network_query(5)));
    assert!(!outbox.send_oneway(peer, network_query(6)));
    drop(pq);
    drop(requests);
    assert!(
        !outbox.send_oneway(peer, network_query(6)),
        "old credits must not grant new owner capacity"
    );
    drop(replacement.try_recv().unwrap());
    assert!(outbox.send_oneway(peer, network_query(6)));
}

async fn verify_own_network_pressure(rpc: bool) {
    use super::super::local_reliable_admission::LocalReliableAdmission;
    let (primary_link, primary, _primary_stream, _primary_peer) = pair().await;
    let (_query_link, query_handle, query_stream, mut peer) = pair().await;
    let mut node = crate::SessionTxRegistry::new();
    let primary_outbox = node.register([0xA1; 32]);
    let query_outbox = node.register([0xB1; 32]);
    let sender = node.get_sender(&[0xB1; 32]).unwrap().clone();
    let source = primary_outbox.shared_source_activity();
    let mut admission = LocalReliableAdmission::for_source(primary.clone(), Arc::clone(&source));
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
    // A exhausted DATA allowance cannot starve this node's route recovery.
    source
        .admit_reliable_secondary(
            crate::local_source_activity::RELIABLE_SECONDARY_BYTES,
            pressured,
        )
        .unwrap();
    let outbox = crate::SessionOutbox::with_capacity(64);
    let mut runner = make_runner(query_stream, query_outbox, None);
    if rpc {
        runner.rpc_outbox = Some(outbox.register([0xB1; 32]));
    }
    for id in 1..=48 {
        if rpc {
            assert!(outbox.send_oneway([0xB1; 32], network_query(id)));
        } else {
            assert!(node.send_to(
                &[0xB1; 32],
                crate::LOCAL_NETWORK_CONTROL_LANE,
                network_query(id)
            ));
        }
    }
    // Same encoded message family and priority; the neutral origin must pass.
    assert!(node.send_to(&[0xB1; 32], INTERACTIVE, network_query(90)));
    let job = tokio::spawn(async move { runner.run().await });
    let mut reader = super::super::ordered_reader::Reader::default();
    let mut cipher = SessionCipher::new(&[0x51; 32], true);
    let mut ids = Vec::new();
    let mut neutral = false;
    let mut early_wire_bytes = 0;
    let ended = timeout(Duration::from_secs(6), async {
        while ids.len() < 48 || !neutral {
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
                "local origin must not appear on wire"
            );
            let expected = network_query(wire.header.request_id);
            let expected_header = veil_proto::codec::decode_header(&expected).unwrap();
            assert_eq!(wire.header.family, expected_header.family);
            assert_eq!(wire.header.msg_type, expected_header.msg_type);
            assert_eq!(&body, &expected[veil_proto::header::HEADER_SIZE..]);
            if wire.header.request_id == 90 {
                assert!(!neutral);
                assert!(
                    pressured.elapsed() < Duration::from_millis(180),
                    "own source pressure held neutral transit"
                );
                neutral = true;
            } else {
                if pressured.elapsed() < Duration::from_millis(180) {
                    early_wire_bytes += super::super::encrypted_wire_len(expected.len()).unwrap();
                }
                ids.push(wire.header.request_id);
            }
        }
        pressured.elapsed()
    })
    .await
    .unwrap();
    assert!(
        early_wire_bytes > 0,
        "DATA exhausted the independent network allowance"
    );
    assert!(
        early_wire_bytes <= crate::local_source_activity::NETWORK_CONTROL_BYTES,
        "own network source bypassed audio pressure: {early_wire_bytes}"
    );
    assert!(
        ended >= Duration::from_millis(400),
        "query burst did not wait for pressure deadlines"
    );
    assert_eq!(
        ids,
        (1..=48).collect::<Vec<_>>(),
        "queries lost, duplicated or reordered"
    );
    drop(sender);
    query_handle.close();
    primary.close();
    timeout(Duration::from_secs(2), job).await.unwrap().unwrap();
}

#[tokio::test]
async fn pressured_rpc_queries_preserve_transit_and_resume_without_input() {
    verify_own_network_pressure(true).await;
}

#[tokio::test]
async fn pressured_own_fanout_preserves_transit_and_resumes_without_input() {
    verify_own_network_pressure(false).await;
}

// Real encrypted scheduler coverage: a waiting local work item must release
// from its timer without another producer event, while audio and opaque
// transit can pass between its cells. Exercise DATAGRAM and ordered fallback.
async fn verify_paced_work(datagrams: bool) {
    use veil_proto::priority::BULK;
    use veil_types::local_lossy_work::{LocalLossyWork, SOURCE_WORK_MAX_AGE};
    let (_link, handle, remote_handle, stream, mut peer) = pair_full().await;
    let (sender, outbox) = crate::frame_outbox::frame_channel(32);
    let offer = datagrams.then(|| super::super::RealtimeLaneOffer {
        peer_datagrams: true,
        transport: super::super::RealtimeTransportOffer::Quic(handle.clone()),
        peer_rotates: false,
        peer_flows: false,
        peer_circuit_datagrams: false,
        peer_neutral_forwards: true,
        parallel: None,
    });
    let mut runner = make_runner(stream, outbox, offer);
    runner.raw_session_keys = Some(([0x51; 32], [0x52; 32], [0; 32]));
    let template = primary_frame(OrderedPrimary::NeutralForward);
    let make = |marker| {
        let mut payload =
            veil_proto::delivery::ForwardPayload::decode(&template[veil_proto::HEADER_SIZE..])
                .unwrap();
        payload.envelope.payload[0] = marker;
        let mut bytes = template[..veil_proto::HEADER_SIZE].to_vec();
        bytes.extend_from_slice(&payload.encode());
        veil_bufpool::pooled_shared_from_vec(bytes)
    };
    let now = std::time::Instant::now();
    // Opaque sealed payload length, not the envelope sent below.
    let work = LocalLossyWork::new_paced(
        vec![256; 3],
        Duration::from_millis(100),
        now + SOURCE_WORK_MAX_AGE,
    )
    .unwrap();
    for index in 0..3 {
        assert!(sender.try_send_local_work((BULK, make(index as u8)), work.cell(index).unwrap()));
    }
    // Missing the ORIGINAL receipt deadline must not grant a fresh 200 ms.
    let expired = LocalLossyWork::new_paced(
        vec![256; 2],
        Duration::from_millis(100),
        now - Duration::from_millis(1),
    )
    .unwrap();
    assert!(!sender.try_send_local_work((BULK, make(99)), expired.cell(0).unwrap()));
    assert!(expired.cell(1).unwrap().rejected());
    let job = tokio::spawn(async move {
        runner.run().await;
    });
    let mut ordered_reader = super::super::ordered_reader::Reader::default();
    let mut ordered_cipher = SessionCipher::new(&[0x51; 32], true);
    let mut datagram_cipher =
        crate::datagram_flows::SessionDatagramRx::new(&[0x51; 32], &[0; 32], false);
    let mut work_arrivals = Vec::new();
    let mut controls = Vec::new();
    timeout(Duration::from_secs(2), async {
        while work_arrivals.len() < 3 || controls.len() < 2 {
            let decoded = if datagrams {
                loop {
                    let packet = remote_handle.recv().await.unwrap();
                    if let Some(frame) = datagram_cipher
                        .decode_datagram(&packet, std::time::Instant::now())
                        .unwrap()
                    {
                        break frame;
                    }
                }
            } else {
                loop {
                    let wire = ordered_reader.read(&mut peer, 65536).await.unwrap();
                    let body = ordered_cipher
                        .open(&wire.body, &veil_proto::codec::frame_aad(&wire.header))
                        .unwrap();
                    if wire.header.family == FrameFamily::Session as u8 {
                        continue;
                    }
                    let mut header = wire.header;
                    header.body_len = body.len() as u32;
                    let mut frame = veil_proto::codec::encode_header(&header).to_vec();
                    frame.extend_from_slice(&body);
                    break frame;
                }
            };
            let header = veil_proto::codec::decode_header(&decoded).unwrap();
            assert_eq!(
                header.priority(),
                INTERACTIVE,
                "source scheduling is never advertised on wire"
            );
            let payload =
                veil_proto::delivery::ForwardPayload::decode(&decoded[veil_proto::HEADER_SIZE..])
                    .unwrap();
            let marker = payload.envelope.payload[0];
            assert_eq!(
                decoded.as_slice(),
                make(marker).as_ref(),
                "opaque bytes unchanged"
            );
            match marker {
                0 => {
                    assert!(work_arrivals.is_empty());
                    work_arrivals.push(std::time::Instant::now());
                    // No producer input after these two independent sources.
                    // Remaining work must wake from its release timers.
                    sender.send((REALTIME, make(9))).await.unwrap();
                    sender.send((INTERACTIVE, make(10))).await.unwrap();
                }
                1 | 2 => {
                    assert_eq!(
                        controls.len(),
                        2,
                        "audio and transit must pass the held video"
                    );
                    assert_eq!(
                        marker as usize,
                        work_arrivals.len(),
                        "no duplicates/reordering"
                    );
                    work_arrivals.push(std::time::Instant::now());
                }
                9 | 10 => controls.push(marker),
                other => panic!("unexpected payload {other}"),
            }
        }
    })
    .await
    .unwrap();
    controls.sort_unstable();
    assert_eq!(controls, [9, 10]);
    assert!(work_arrivals[1].duration_since(work_arrivals[0]) >= Duration::from_millis(20));
    assert!(work_arrivals[2].duration_since(work_arrivals[0]) >= Duration::from_millis(50));
    assert!(
        !work.cell(2).unwrap().rejected(),
        "a pacing wait must not reject admitted work"
    );
    handle.close();
    remote_handle.close();
    timeout(Duration::from_secs(2), job).await.unwrap().unwrap();
}

#[tokio::test]
async fn paced_local_work_wakes_on_datagrams_and_preserves_other_sources() {
    verify_paced_work(true).await;
}

#[tokio::test]
async fn paced_local_work_wakes_on_ordered_fallback_and_preserves_other_sources() {
    verify_paced_work(false).await;
}
