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
        assert_eq!(diagnostics.active_connections(), 12);
        assert_eq!(b_diagnostics.active_connections(), 12);
    }
    timeout(Duration::from_secs(5), async {
        while !a.prepare(REALTIME) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let index = 0;
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
        drop(sender);
        if full_duplex {
            let frame = primary_test_frame(large, seq | (1 << 31), now.as_micros() as u64);
            let (_, body, kind) = super::super::decode_realtime_lane_frame(&frame).unwrap();
            let index = b.prepare_frame(REALTIME, body, kind).unwrap();
            let mut sender = b.sender(index);
            let max_size = sender.max_datagram_size;
            let packets = sender.tx.encode_frame(0, &frame, max_size).unwrap();
            if super::super::local_primary_datagram_fits(
                packets.iter().map(Vec::len).sum(),
                sender.handle.send_buffer_space(),
            ) {
                let expiry = super::super::local_primary_datagram_expiry(
                    &crate::frame_outbox::FrameEnvelope::from((
                        REALTIME,
                        veil_bufpool::pooled_shared_from_vec(frame),
                    )),
                )
                .unwrap();
                for packet in packets {
                    sender.handle.send_before(&packet, expiry).unwrap();
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
    eprintln!("production primary recovery {report:?}");
    report
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
async fn recoverable_source_has_its_own_quic_connection_and_survives_screen_close() {
    use veil_proto::{
        ipc::LOCAL_RECOVERABLE_DATA_LANE,
        priority::{BACKGROUND, BULK},
    };
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
        let lanes = [REALTIME, BULK, BACKGROUND, LOCAL_RECOVERABLE_DATA_LANE];
        for lane in lanes {
            timeout(Duration::from_secs(5), async {
                while !a.prepare(lane) {
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
        assert_eq!(diagnostics.active_connections(), 4);
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
        // Retiring only the screen connection cannot retire the file source
        // or silently fall back to a shared canonical congestion controller.
        let screen_binding = handles[2].channel_binding().unwrap();
        handles[2].close();
        timeout(Duration::from_secs(1), handles[2].closed())
            .await
            .unwrap();
        for (seq, lane) in [REALTIME, BULK, LOCAL_RECOVERABLE_DATA_LANE]
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
            while received.len() < 3 {
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
