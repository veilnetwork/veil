//! The normal session codec/dispatcher on parent-bound ordered records.
//! Deterministic duplex fixtures isolate parser/admission/lifetime behavior;
//! fresh encrypted obfs4 bindings and listener quotas have separate real-I/O
//! tests in parallel_registry_ordered_tests.rs.
use super::*;
use crate::parallel_binding::{BoundOrderedChannel, ParallelParent};
use std::sync::{
    RwLock, Weak,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::time::{Duration, timeout};
use veil_anonymity::circuit_carrier::CarrierSend;

fn ordered_pair(
    capacity: usize,
) -> (
    ParallelParent,
    ParallelParent,
    BoundOrderedChannel,
    BoundOrderedChannel,
) {
    let a = ParallelParent::new([1; 32], [2; 32], [3; 32]);
    let b = ParallelParent::new([1; 32], [3; 32], [2; 32]);
    let (hello, pending) = a.begin([4; 32]).unwrap();
    let (ack, b_keys) = b.accept(&hello, [4; 32]).unwrap();
    let a_keys = pending.finish(&ack).unwrap();
    let (left, right) = tokio::io::duplex(capacity);
    let left = a_keys.into_ordered(Box::new(left)).unwrap();
    let right = b_keys.into_ordered(Box::new(right)).unwrap();
    (a, b, left, right)
}

fn app_frame(seq: u32, size: usize) -> Vec<u8> {
    let body = veil_proto::app::AppRtDataPayload {
        src_app_id: [1; 32],
        app_id: [2; 32],
        endpoint_id: 1,
        seq,
        timestamp_us: 0,
        marker: 0,
        payload_type: 111,
        payload: vec![0x55; size],
    }
    .encode();
    let mut h = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppRtData as u16);
    h.set_priority(veil_proto::priority::REALTIME);
    h.body_len = body.len() as u32;
    let mut frame = encode_header(&h).to_vec();
    frame.extend_from_slice(&body);
    frame
}

struct Capture {
    logger: Arc<NodeLogger>,
    accepted: tokio::sync::mpsc::UnboundedSender<(u32, Vec<u8>)>,
    allowed: AtomicBool,
    attempts: AtomicUsize,
}

impl crate::dispatcher_sink::DispatcherSink for Capture {
    fn dispatch(&self, h: &FrameHeader, body: &[u8], peer: NodeIdBytes) -> DispatchResult {
        assert_eq!(peer, [9; 32], "child must use the canonical peer");
        assert_eq!(h.priority(), veil_proto::priority::REALTIME);
        self.attempts.fetch_add(1, Ordering::Relaxed);
        if !self.allowed.load(Ordering::Relaxed) {
            return DispatchResult::RateLimited;
        }
        let p = veil_proto::app::AppRtDataPayload::decode(body).unwrap();
        if p.seq == 77 {
            return DispatchResult::Violation("fixture violation".into());
        }
        self.accepted.send((p.seq, p.payload)).unwrap();
        DispatchResult::NoResponse
    }
    fn capture_outbound(&self, _: NodeIdBytes, _: &[u8]) {}
    fn allow_outbound_bandwidth(&self, _: usize) -> bool {
        true
    }
    fn logger(&self) -> &Arc<NodeLogger> {
        &self.logger
    }
    fn session_tx_registry(&self) -> Option<Arc<RwLock<crate::tx_registry::SessionTxRegistry>>> {
        None
    }
    fn dht(&self) -> &Arc<veil_dht::KademliaService> {
        unreachable!("record receiver fixture")
    }
    fn rendezvous_weak(&self) -> Arc<Mutex<Option<Weak<crate::rendezvous::RendezvousController>>>> {
        unreachable!("record receiver fixture")
    }
    fn pow_solver_semaphore(&self) -> Arc<tokio::sync::Semaphore> {
        unreachable!("record receiver fixture")
    }
    fn pow_active_difficulty(&self) -> Arc<std::sync::atomic::AtomicU64> {
        unreachable!("record receiver fixture")
    }
    fn route_cache(&self) -> Arc<RwLock<veil_routing::RouteCache>> {
        unreachable!("record receiver fixture")
    }
    fn register_session_aliases(&self, _: [u8; 8], _: NodeIdBytes, _: [u8; 8], _: NodeIdBytes) {
        unreachable!("record receiver fixture")
    }
    fn unregister_session_aliases(&self, _: [u8; 8], _: [u8; 8]) {
        unreachable!("record receiver fixture")
    }
}

async fn until(mut ready: impl FnMut() -> bool) {
    timeout(Duration::from_secs(1), async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

pub(super) fn pool_fixture_context() -> RealtimeReceiverContext {
    let logger = Arc::new(NodeLogger::new_noop());
    let (accepted, _) = tokio::sync::mpsc::unbounded_channel();
    RealtimeReceiverContext {
        peer_id: [9; 32],
        dispatcher: Arc::new(Capture {
            logger: logger.clone(),
            accepted,
            allowed: AtomicBool::new(false),
            attempts: AtomicUsize::new(0),
        }),
        logger,
        metrics: None,
        ban_list: Arc::new(Mutex::new(BanList::new())),
        violation_tracker: Arc::new(Mutex::new(
            ViolationTracker::with_fixed_duration(
                10,
                Duration::from_secs(10),
                Duration::from_secs(10),
            )
            .unwrap(),
        )),
        activity: Arc::new(crate::datagram_activity::AuthenticatedDatagramActivity::new()),
    }
}

#[tokio::test]
async fn ordered_records_use_normal_replay_eligibility_dispatch_and_abuse_budgets() {
    let (a_parent, b_parent, a, b) = ordered_pair(64 * 1024);
    let logger = Arc::new(NodeLogger::new_noop());
    let (tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
    let sink = Arc::new(Capture {
        logger: logger.clone(),
        accepted: tx,
        allowed: AtomicBool::new(false),
        attempts: AtomicUsize::new(0),
    });
    let bans = Arc::new(Mutex::new(BanList::new()));
    let context = RealtimeReceiverContext {
        peer_id: [9; 32],
        dispatcher: sink.clone(),
        logger,
        metrics: None,
        ban_list: bans.clone(),
        violation_tracker: Arc::new(Mutex::new(
            ViolationTracker::with_fixed_duration(
                1,
                Duration::from_secs(10),
                Duration::from_secs(10),
            )
            .unwrap(),
        )),
        activity: Arc::new(crate::datagram_activity::AuthenticatedDatagramActivity::new()),
    };
    let mut codec =
        crate::datagram_flows::SessionDatagramTx::new(a.keys.tx_key(), &a.keys.session_id, true);
    let rx =
        crate::datagram_flows::SessionDatagramRx::new(b.keys.rx_key(), &b.keys.session_id, true);
    let (_rekey_owner, rekeys) = tokio::sync::watch::channel(None);
    let mut receiver = spawn_realtime_receiver(b.handle(), rx, rekeys, context, None);
    let packets = codec.encode_frame(0, &app_frame(0, 6000), 1200).unwrap();
    assert!(packets.len() > 1);
    let handle = a.handle();
    let mut damaged = packets[0].clone();
    *damaged.last_mut().unwrap() ^= 1;
    handle.send(&damaged).unwrap();
    for packet in packets.iter().rev() {
        handle.send(packet).unwrap();
    }
    for packet in &packets {
        handle.send(packet).unwrap();
    }
    // Even an authenticated ordinary frame is ineligible for this lossy codec.
    let mut h = FrameHeader::new(FrameFamily::Session as u8, 1);
    h.body_len = 0;
    for packet in codec.encode_frame(0, &encode_header(&h), 1200).unwrap() {
        handle.send(&packet).unwrap();
    }
    until(|| sink.attempts.load(Ordering::Relaxed) == 1).await;
    assert!(
        accepted.try_recv().is_err(),
        "shared dispatch refused its budget"
    );
    sink.allowed.store(true, Ordering::Relaxed);
    for (seq, size) in [(1, 6000), (2, 128)] {
        for packet in codec.encode_frame(0, &app_frame(seq, size), 1200).unwrap() {
            handle.send(&packet).unwrap();
        }
        assert_eq!(
            timeout(Duration::from_secs(1), accepted.recv())
                .await
                .unwrap()
                .unwrap(),
            (seq, vec![0x55; size])
        );
    }
    for packet in codec.encode_frame(0, &app_frame(77, 128), 1200).unwrap() {
        handle.send(&packet).unwrap();
    }
    until(|| bans.lock().unwrap().is_banned(&[9; 32])).await;
    assert_eq!(sink.attempts.load(Ordering::Relaxed), 4);
    assert!(
        accepted.try_recv().is_err(),
        "replay/violation produced an extra message"
    );
    b_parent.retire();
    timeout(Duration::from_secs(1), &mut receiver.0)
        .await
        .unwrap()
        .unwrap();
    drop((a_parent, b_parent, a, b));
}

#[tokio::test]
async fn ordered_duplex_carrier_preserves_neutral_priority_and_admission() {
    let (a_parent, b_parent, a, b) = ordered_pair(64 * 1024);
    let diagnostics = Arc::new(parallel_lanes::ParallelDiagnostics::default());
    let sender = Arc::new(Mutex::new(RealtimeSender::new(
        a.handle(),
        crate::datagram_flows::SessionDatagramTx::new(a.keys.tx_key(), &a.keys.session_id, true),
    )));
    let carrier =
        parallel_lanes::make_carrier(&diagnostics, sender.clone(), a_parent.handle(), [9; 32]);
    let cell = veil_anonymity::circuit_data::CircuitCellBytes::legacy();
    let body = veil_anonymity::circuit_wire::CircuitDataPayload {
        circuit_id: 1,
        seq: 0,
        ciphertext: vec![0x55; cell.get()],
    }
    .encode(cell)
    .unwrap();
    let mut header = FrameHeader::new(
        FrameFamily::RelayChain as u8,
        veil_proto::family::RelayChainMsg::CircuitDatagram as u16,
    );
    header.set_priority(veil_proto::priority::INTERACTIVE);
    header.body_len = body.len() as u32;
    let mut frame = encode_header(&header).to_vec();
    frame.extend_from_slice(&body);
    let mut admits = 0;
    assert!(matches!(
        carrier.try_send(&[8; 32], &frame, &mut |_| {
            admits += 1;
            true
        }),
        CarrierSend::Unavailable
    ));
    assert_eq!(admits, 0);
    assert!(matches!(
        carrier.try_send(&[9; 32], &frame, &mut |_| {
            admits += 1;
            false
        }),
        CarrierSend::Dropped { wire_bytes: 0 }
    ));
    assert_eq!(admits, 1);
    let sent = carrier.try_send(&[9; 32], &frame, &mut |_| {
        admits += 1;
        true
    });
    assert!(matches!(sent, CarrierSend::Sent { wire_bytes } if wire_bytes > 0));
    assert_eq!(admits, 2);
    let mut rx =
        crate::datagram_flows::SessionDatagramRx::new(b.keys.rx_key(), &b.keys.session_id, true);
    let restored = timeout(Duration::from_secs(1), async {
        loop {
            let packet = b.handle().recv().await.unwrap();
            if let Some(frame) = rx
                .decode_datagram(&packet, std::time::Instant::now())
                .unwrap()
            {
                break frame;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(restored, frame);
    assert_eq!(diagnostics.replies(), 1);
    let mut h =
        decode_header_with_limit(&frame[..veil_proto::header::HEADER_SIZE], u32::MAX).unwrap();
    h.set_priority(veil_proto::priority::REALTIME);
    frame[..veil_proto::header::HEADER_SIZE].copy_from_slice(&encode_header(&h));
    assert!(matches!(
        carrier.try_send(&[9; 32], &frame, &mut |_| {
            admits += 1;
            true
        }),
        CarrierSend::Unavailable
    ));
    assert_eq!(
        admits, 2,
        "remote source priority must not acquire neutral return carrier"
    );
    a_parent.retire();
    assert!(matches!(
        carrier.try_send(&[9; 32], &restored, &mut |_| true),
        CarrierSend::Unavailable
    ));
    drop((a_parent, b_parent, a, b));
}

#[tokio::test]
async fn ordered_queue_drop_keeps_channel_usable_and_reports_only_local_progress() {
    let (a_parent, b_parent, a, b) = ordered_pair(1);
    let handle: LossyTransportHandle = a.handle().into();
    assert!(handle.quic().is_none());
    assert_eq!(handle.queue_charge(1), 40);
    assert_eq!(handle.queue_charge(1200), 1202);
    let trace = handle.path_trace();
    assert!(trace.contains("transport=ordered"));
    for name in [
        "rtt_us",
        "acks_received",
        "cwnd_bytes",
        "udp_sent",
        "pto_count",
    ] {
        assert!(!trace.contains(name));
    }
    let mut admitted = 0;
    loop {
        match handle.send(&[0x55; 1200]) {
            Ok(()) => admitted += 1,
            Err(error) => {
                assert!(matches!(error, LossySendError::Full));
                assert!(error.is_temporary());
                break;
            }
        }
    }
    assert_eq!(
        admitted,
        veil_transport::REALTIME_DATAGRAM_BUFFER_BYTES / 1202
    );
    let expired = handle
        .send_before(&[1], std::time::Instant::now())
        .unwrap_err();
    assert!(matches!(expired, LossySendError::Expired));
    assert!(expired.is_temporary());
    assert_eq!(handle.max_size(), Some(1200));
    timeout(Duration::from_secs(1), async {
        for _ in 0..admitted {
            assert_eq!(b.handle().recv().await.unwrap(), vec![0x55; 1200]);
        }
    })
    .await
    .unwrap();
    until(|| handle.send_buffer_space() == veil_transport::REALTIME_DATAGRAM_BUFFER_BYTES).await;
    handle.send(&[7]).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), b.handle().recv())
            .await
            .unwrap()
            .unwrap(),
        vec![7]
    );
    drop(a_parent);
    assert!(handle.max_size().is_none());
    assert!(matches!(
        handle.send(&[8]),
        Err(LossySendError::Unavailable(_))
    ));
    drop((b_parent, a, b));
}
