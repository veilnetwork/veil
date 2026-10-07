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

struct Capture {
    started: Instant,
    received: mpsc::UnboundedSender<(u32, u64, Duration)>,
    logger: Arc<veil_observability::NodeLogger>,
}

impl crate::dispatcher_sink::DispatcherSink for Capture {
    fn dispatch(
        &self,
        h: &FrameHeader,
        body: &[u8],
        peer: NodeIdBytes,
    ) -> crate::dispatcher_sink::DispatchResult {
        assert_eq!(peer, [9; 32]);
        let (seq, sent) = if h.family == veil_proto::family::FrameFamily::App as u8 {
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
}

async fn measure(large: bool, recover: bool, congestion: QuicCongestionControl) -> Report {
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
    let mut b_stream = remote.into_stream().unwrap();
    let mut prefix = [0; 4];
    b_stream.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"main");
    let started = Instant::now();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let logger = Arc::new(veil_observability::NodeLogger::new_noop());
    let sink: Arc<dyn crate::dispatcher_sink::DispatcherSink> = Arc::new(Capture {
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
    let b = ParallelSession::new(b_offer, &[3; 32], &[2; 32], [1; 32], context, None);
    timeout(Duration::from_secs(5), async {
        while !a.prepare(REALTIME) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let index = 0;
    let original = a.sender(index).handle.clone();
    let original_exporter = original.channel_binding().unwrap();
    let blackout_start = started.elapsed() + Duration::from_secs(6);
    let blackout_end = blackout_start + Duration::from_secs(4);
    let end = blackout_end + Duration::from_secs(4);
    let mut last_attempt = 0;
    let mut last_switch = 0;
    let mut seq = 0u32;
    let mut changed_exporter = false;
    let mut retained_during_pending = true;
    while started.elapsed() < end {
        sleep_until(started + Duration::from_millis(u64::from(seq) * 20)).await;
        let now = started.elapsed();
        link.blackout.store(
            (blackout_start..blackout_end).contains(&now),
            Ordering::Relaxed,
        );
        let frame = primary_test_frame(large, seq, now.as_micros() as u64);
        let (_, body, kind) = super::super::decode_realtime_lane_frame(&frame).unwrap();
        // Baseline polls the same production slot but cannot request repair.
        let ready = if recover {
            a.prepare_frame(REALTIME, body, kind).is_some()
        } else {
            a.prepare(REALTIME)
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
        if sender.handle.channel_binding().unwrap() != original_exporter {
            changed_exporter = true;
        }
        if now < blackout_end {
            retained_during_pending &=
                sender.handle.channel_binding().unwrap() == original_exporter;
        }
        let max_size = sender.max_datagram_size;
        let packets = sender
            .tx
            .encode_frame(u64::from(REALTIME), &frame, max_size)
            .unwrap();
        if super::super::local_primary_datagram_fits(
            packets.iter().map(Vec::len).sum(),
            sender.handle.send_buffer_space(),
        ) {
            let expiry = super::super::local_primary_datagram_expiry(
                &crate::frame_outbox::FrameEnvelope::from((
                    REALTIME,
                    veil_bufpool::pooled_shared_from_vec(frame.clone()),
                )),
            )
            .unwrap();
            for packet in packets {
                sender.handle.send_before(&packet, expiry).unwrap();
            }
        }
        seq += 1;
    }
    sleep(Duration::from_millis(100)).await;
    let attempts = diagnostics.recovery_attempts();
    let switches = diagnostics.recovery_switches();
    // Teardown first, including held old connection handles and candidate tasks.
    drop((a, b));
    close.close(0u32.into(), b"primary recovery stand complete");
    timeout(Duration::from_secs(1), original.closed())
        .await
        .unwrap();
    let mut seen = HashSet::new();
    let mut duplicates = 0;
    let mut post = 0;
    let mut first_fresh = None;
    let mut max_age = Duration::ZERO;
    while let Ok((s, sent, arrived)) = rx.try_recv() {
        if !seen.insert(s) {
            duplicates += 1;
        }
        if arrived >= blackout_end {
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
    };
    eprintln!("production primary recovery {report:?}");
    report
}

#[tokio::test]
async fn authenticated_primary_replacement_recovers_after_four_second_neutral_outage() {
    for large in [false, true] {
        // Keep the historical stall reproducible independently of the
        // production congestion controller. All existing recovery gates
        // still apply to the authenticated replacement path.
        let old = measure(large, false, QuicCongestionControl::Cubic).await;
        let repaired = measure(large, true, QuicCongestionControl::Cubic).await;
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
            let report = measure(large, recover, QuicCongestionControl::Bbr).await;
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
