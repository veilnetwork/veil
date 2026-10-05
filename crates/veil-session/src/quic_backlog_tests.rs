//! Real encrypted QUIC cells behind a neutral bandwidth-limited UDP FIFO.
//! Compare the previous capacity-only admission with the production endpoint
//! backlog bound. The link never inspects application/flow bytes or priorities.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, sleep, sleep_until, timeout},
};
use veil_transport::{
    PunchedQuicRole, QuicDatagramHandle, REALTIME_DATAGRAM_BUFFER_BYTES, TransportContext,
    promote_punched_quic,
};

struct NeutralLink {
    enabled: Arc<AtomicBool>,
    blackout: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    tasks: Vec<JoinHandle<()>>,
    left_addr: SocketAddr,
    right_addr: SocketAddr,
}

impl Drop for NeutralLink {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl NeutralLink {
    async fn new(left: SocketAddr, right: SocketAddr, bps: u64, delay: Duration) -> Self {
        let left_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let right_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let enabled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicU64::new(0));
        let blackout = Arc::new(AtomicBool::new(false));
        let mut tasks = Vec::new();
        for (input, expected, output, destination) in [
            (
                Arc::clone(&left_socket),
                left,
                Arc::clone(&right_socket),
                right,
            ),
            (
                Arc::clone(&right_socket),
                right,
                Arc::clone(&left_socket),
                left,
            ),
        ] {
            // A fixed FIFO tail drop models a neutral router. No payload,
            // flow, endpoint or application label affects admission/service.
            let (tx, mut rx) = mpsc::channel::<(Vec<u8>, Instant)>(32);
            let drops = Arc::clone(&dropped);
            let unavailable = Arc::clone(&blackout);
            tasks.push(tokio::spawn(async move {
                let mut buffer = vec![0; 65536];
                loop {
                    let Ok((len, source)) = input.recv_from(&mut buffer).await else {
                        return;
                    };
                    if source != expected {
                        continue;
                    }
                    if unavailable.load(Ordering::Relaxed)
                        || tx
                            .try_send((buffer[..len].to_vec(), Instant::now()))
                            .is_err()
                    {
                        drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
            let shape = Arc::clone(&enabled);
            let unavailable = Arc::clone(&blackout);
            let drops = Arc::clone(&dropped);
            tasks.push(tokio::spawn(async move {
                let mut wire_at = Instant::now();
                while let Some((packet, arrived)) = rx.recv().await {
                    if shape.load(Ordering::Relaxed) {
                        // Serialization is cumulative; propagation overlaps
                        // between packets rather than charging RTT per packet.
                        wire_at = wire_at.max(arrived)
                            + Duration::from_secs_f64(packet.len() as f64 * 8.0 / bps as f64);
                        sleep_until(wire_at + delay).await;
                    } else {
                        wire_at = Instant::now();
                    }
                    // A blackout drops packets, including one already in
                    // propagation. It never stores traffic for later replay.
                    if unavailable.load(Ordering::Relaxed) {
                        drops.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if output.send_to(&packet, destination).await.is_err() {
                        return;
                    }
                }
            }));
        }
        Self {
            enabled,
            blackout,
            dropped,
            tasks,
            left_addr: left_socket.local_addr().unwrap(),
            right_addr: right_socket.local_addr().unwrap(),
        }
    }
}

fn circuit_frame(circuit_id: u32, fill: u8) -> Vec<u8> {
    use veil_anonymity::{circuit_data::CircuitCellBytes, circuit_wire::CircuitDataPayload};
    use veil_proto::{codec::encode_header, family::RelayChainMsg, header::FrameHeader};
    let cell_size = CircuitCellBytes::new(2048).unwrap();
    let body = CircuitDataPayload {
        circuit_id,
        seq: 1,
        ciphertext: vec![fill; cell_size.get()],
    }
    .encode(cell_size)
    .unwrap();
    let mut header = FrameHeader::new(
        veil_proto::family::FrameFamily::RelayChain as u8,
        RelayChainMsg::CircuitDatagram as u16,
    );
    header.set_priority(veil_proto::priority::INTERACTIVE);
    header.body_len = body.len() as u32;
    let mut frame = encode_header(&header).to_vec();
    frame.extend_from_slice(&body);
    frame
}

async fn receive_primary(
    rx: &QuicDatagramHandle,
    cipher: &mut crate::datagram_flows::SessionDatagramRx,
    primary: &[u8],
    secondary: &[u8],
) -> (Option<Duration>, usize) {
    let started = Instant::now();
    let mut secondary_received = 0;
    let result = timeout(Duration::from_secs(3), async {
        loop {
            let packet = rx.recv().await.unwrap();
            if let Some(frame) = cipher
                .decode_datagram(&packet, std::time::Instant::now())
                .unwrap()
            {
                if frame == primary {
                    return started.elapsed();
                }
                assert_eq!(frame, secondary);
                secondary_received += 1;
            }
        }
    })
    .await;
    (result.ok(), secondary_received)
}

// Each case has a fresh real connection so a previous load's congestion
// controller state cannot make the production case artificially faster.
async fn measure(capacity_only: Option<bool>) -> (Option<Duration>, usize, usize) {
    measure_burst(capacity_only, veil_proto::priority::BULK).await
}

async fn measure_burst(
    capacity_only: Option<bool>,
    burst_priority: u8,
) -> (Option<Duration>, usize, usize) {
    use crate::datagram_flows::{MAX_FRAME_WIRE_BYTES, SessionDatagramRx, SessionDatagramTx};
    use veil_proto::priority::{BULK, REALTIME};
    let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let link = NeutralLink::new(
        left.local_addr().unwrap(),
        right.local_addr().unwrap(),
        1_000_000,
        Duration::from_millis(20),
    )
    .await;
    let context = Arc::new(TransportContext::for_debug().unwrap());
    let remote_context = Arc::clone(&context);
    let remote_addr = link.right_addr;
    let remote = tokio::spawn(async move {
        promote_punched_quic(
            right,
            remote_addr,
            remote_context,
            PunchedQuicRole::Responder,
        )
        .await
        .unwrap()
    });
    let local = promote_punched_quic(left, link.left_addr, context, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    let tx = local.quic_datagrams().unwrap();
    let mut local_stream = local.into_stream().unwrap();
    local_stream.write_all(b"stand").await.unwrap();
    let remote = remote.await.unwrap();
    let rx = remote.quic_datagrams().unwrap();
    let _remote_stream = remote.into_stream().unwrap();
    sleep(Duration::from_millis(100)).await;
    link.enabled.store(true, Ordering::Relaxed);

    let primary = circuit_frame(1, 0x11);
    let secondary = circuit_frame(2, 0x22);
    let mut cipher_tx = SessionDatagramTx::new(&[7; 32], &[8; 32], true);
    let mut cipher_rx = SessionDatagramRx::new(&[7; 32], &[8; 32], true);
    let ceiling = tx.max_size().unwrap();
    let secondary_wire = cipher_tx
        .encode_frame(u64::from(burst_priority), &secondary, ceiling)
        .unwrap()
        .iter()
        .map(Vec::len)
        .sum::<usize>();
    let mut queued = 0;
    if let Some(capacity_only) = capacity_only {
        // All admission and fragments run before yielding to Quinn's driver.
        // The regression side reproduces the previous production reserve.
        for _ in 0..20 {
            let available = tx.send_buffer_space();
            let fits = if capacity_only {
                let reserve = if burst_priority == BULK {
                    MAX_FRAME_WIRE_BYTES
                } else {
                    0
                };
                secondary_wire + reserve <= available
            } else if burst_priority == REALTIME {
                super::local_primary_datagram_fits(secondary_wire, available)
            } else {
                super::local_datagram_fits(burst_priority, secondary_wire, available)
            };
            if !fits {
                break;
            }
            for packet in cipher_tx
                .encode_frame(u64::from(burst_priority), &secondary, ceiling)
                .unwrap()
            {
                tx.send(&packet).unwrap();
            }
            queued += secondary_wire;
            assert!(queued <= REALTIME_DATAGRAM_BUFFER_BYTES);
        }
    }
    let packets = cipher_tx
        .encode_frame(u64::from(REALTIME), &primary, ceiling)
        .unwrap();
    // The paced producer may shed a full-buffer sample and try a fresh one
    // on its next turn. Include this admission wait in the reported delay.
    let admission_started = Instant::now();
    if burst_priority == REALTIME && capacity_only == Some(false) {
        timeout(Duration::from_secs(1), async {
            while !super::local_primary_datagram_fits(
                packets.iter().map(Vec::len).sum(),
                tx.send_buffer_space(),
            ) {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("primary backlog never drains");
    }
    assert!(super::local_datagram_fits(
        REALTIME,
        packets.iter().map(Vec::len).sum(),
        tx.send_buffer_space(),
    ));
    let admission_wait = admission_started.elapsed();
    for packet in packets {
        tx.send(&packet).unwrap();
    }
    let (elapsed, received) = receive_primary(&rx, &mut cipher_rx, &primary, &secondary).await;
    let elapsed = elapsed.map(|elapsed| elapsed + admission_wait);
    eprintln!(
        "capacity_only={capacity_only:?} burst_priority={burst_priority} queued_bytes={queued} secondary_received={received} primary_ms={:?} neutral_udp_drops={}",
        elapsed.map(|v| v.as_secs_f64() * 1000.0),
        link.dropped.load(Ordering::Relaxed),
    );
    (elapsed, queued, received)
}

#[tokio::test]
async fn endpoint_backlog_bound_keeps_primary_cells_fresh_on_a_neutral_slow_link() {
    let (idle, queued, received) = measure(None).await;
    assert_eq!((queued, received), (0, 0));
    assert!(idle.unwrap() < Duration::from_millis(200));
    let (old, old_queued, old_received) = measure(Some(true)).await;
    assert!(
        old_queued > 32 * 1024,
        "regression must actually fill Quinn"
    );
    assert!(old_received > 4, "the competing cells must really arrive");
    let (current, current_queued, current_received) = measure(Some(false)).await;
    assert!(
        current_queued > 0,
        "load cannot be removed from the fixture"
    );
    assert!(current_queued <= 4096);
    assert!(current_received > 0);
    let current = current.expect("primary cell must survive the competing load");
    assert!(current < Duration::from_millis(200), "{current:?}");
    assert!(
        old.is_none_or(|old| old > current + Duration::from_millis(200)),
        "capacity-only admission must fail the same latency requirement: {old:?} vs {current:?}"
    );
}

#[tokio::test]
async fn primary_burst_cannot_replay_a_large_local_quic_backlog() {
    use veil_proto::priority::REALTIME;
    let (old, old_queued, old_received) = measure_burst(Some(true), REALTIME).await;
    assert!(
        old_queued > 32 * 1024,
        "old primary must really queue a burst"
    );
    assert!(old_received > 4, "old primary samples must actually arrive");
    let (current, current_queued, current_received) = measure_burst(Some(false), REALTIME).await;
    assert!(current_queued > 0, "the source burst must not be omitted");
    assert!(
        current_queued < 8 * 1024,
        "primary backlog={current_queued}"
    );
    assert!(current_received > 0);
    let current = current.expect("fresh primary sample must arrive");
    assert!(current < Duration::from_millis(200), "{current:?}");
    assert!(
        old.is_none_or(|old| old > current + Duration::from_millis(200)),
        "capacity-only primary must demonstrate stale delivery: {old:?} vs {current:?}"
    );
}

#[derive(Debug)]
struct ContinuousReport {
    primary_sent: usize,
    primary_received: usize,
    primary_p95: Option<Duration>,
    secondary_sent: usize,
    secondary_received: usize,
    secondary_dropped: usize,
    file_bytes: u64,
    file_accepted: u64,
}

#[derive(Clone, Copy, Debug)]
enum StreamBudget {
    Default,
    Manual(u64),
    LocalPrimary,
    IndependentPrimary,
    ReturnedToSharedPrimary,
    TransitPrimary,
    ExpiredLocalPrimary,
    DroppedLocalPrimary,
}

fn apply_stream_budget(
    mode: StreamBudget,
    tx: &veil_transport::QuicDatagramHandle,
    admission: &mut super::local_reliable_admission::LocalReliableAdmission,
) {
    use super::local_reliable_admission::LocalReliableAdmission;
    use veil_proto::priority::{INTERACTIVE, REALTIME};
    let frame = circuit_frame(1, 0x11);
    let now = std::time::Instant::now();
    match mode {
        StreamBudget::Default => {}
        StreamBudget::Manual(bytes) => tx.set_reliable_send_window(bytes),
        StreamBudget::LocalPrimary => admission.observe(REALTIME, &frame, now, false),
        StreamBudget::IndependentPrimary => admission.observe(REALTIME, &frame, now, true),
        StreamBudget::ReturnedToSharedPrimary => {
            admission.observe(REALTIME, &frame, now, true);
            admission.observe(REALTIME, &frame, now, false);
        }
        StreamBudget::TransitPrimary => {
            // Neither an invalid local frame nor a forged wire priority may
            // activate a source-only budget on an ordinary forwarding lane.
            admission.observe(REALTIME, &[0; 8], now, false);
            let mut header =
                veil_proto::decode_header(&frame[..veil_proto::header::HEADER_SIZE]).unwrap();
            header.set_priority(REALTIME);
            let mut forged = frame;
            forged[..veil_proto::header::HEADER_SIZE]
                .copy_from_slice(&veil_proto::encode_header(&header));
            admission.observe(INTERACTIVE, &forged, now, false);
        }
        StreamBudget::ExpiredLocalPrimary => {
            admission.observe(REALTIME, &frame, now, false);
            admission.expire(now + Duration::from_secs(3));
        }
        StreamBudget::DroppedLocalPrimary => {
            let mut guard = LocalReliableAdmission::new(tx.clone());
            guard.observe(REALTIME, &frame, now, false);
            drop(guard);
        }
    }
}

async fn measure_continuous(
    file: bool,
    video_tick_period: Option<u32>,
    primary_tick_period: u32,
) -> ContinuousReport {
    measure_continuous_with_stream_budget(
        file,
        video_tick_period,
        primary_tick_period,
        StreamBudget::Default,
        Duration::ZERO,
    )
    .await
}

async fn measure_continuous_with_stream_budget(
    file: bool,
    video_tick_period: Option<u32>,
    primary_tick_period: u32,
    stream_budget: StreamBudget,
    file_lead: Duration,
) -> ContinuousReport {
    measure_continuous_for_ticks(
        file,
        video_tick_period,
        primary_tick_period,
        stream_budget,
        file_lead,
        200,
    )
    .await
}

async fn measure_continuous_for_ticks(
    file: bool,
    video_tick_period: Option<u32>,
    primary_tick_period: u32,
    stream_budget: StreamBudget,
    file_lead: Duration,
    ticks: u32,
) -> ContinuousReport {
    use crate::datagram_flows::{SessionDatagramRx, SessionDatagramTx};
    use veil_anonymity::circuit_wire::CircuitDataPayload;
    use veil_proto::{
        header::HEADER_SIZE,
        priority::{BULK, REALTIME},
    };
    let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let link = NeutralLink::new(
        left.local_addr().unwrap(),
        right.local_addr().unwrap(),
        1_000_000,
        Duration::from_millis(20),
    )
    .await;
    // The initial RTT must include the same link as application traffic.
    // A loopback handshake followed by an artificial RTT jump would bias a
    // minimum-RTT congestion estimator towards an unrelated network path.
    link.enabled.store(true, Ordering::Relaxed);
    let context = Arc::new(TransportContext::for_debug().unwrap());
    let remote_context = Arc::clone(&context);
    let remote_addr = link.right_addr;
    let remote = tokio::spawn(async move {
        promote_punched_quic(
            right,
            remote_addr,
            remote_context,
            PunchedQuicRole::Responder,
        )
        .await
        .unwrap()
    });
    let local = promote_punched_quic(left, link.left_addr, context, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    let tx = local.quic_datagrams().unwrap();
    let mut admission = super::local_reliable_admission::LocalReliableAdmission::new(tx.clone());
    if file_lead.is_zero() {
        apply_stream_budget(stream_budget, &tx, &mut admission);
    }
    let mut local_stream = local.into_stream().unwrap();
    local_stream.write_all(b"stand").await.unwrap();
    let remote = remote.await.unwrap();
    let rx = remote.quic_datagrams().unwrap();
    let mut remote_stream = remote.into_stream().unwrap();
    let mut prefix = [0; 5];
    remote_stream.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"stand");
    sleep(Duration::from_millis(100)).await;
    link.enabled.store(true, Ordering::Relaxed);
    let file_bytes = Arc::new(AtomicU64::new(0));
    let received_file = Arc::clone(&file_bytes);
    let file_reader = tokio::spawn(async move {
        let mut buffer = [0; 16384];
        while let Ok(len) = remote_stream.read(&mut buffer).await {
            if len == 0 {
                break;
            }
            assert!(buffer[..len].iter().all(|byte| *byte == 0xb2));
            received_file.fetch_add(len as u64, Ordering::Relaxed);
        }
    });
    let file_accepted = Arc::new(AtomicU64::new(0));
    let accepted_file = Arc::clone(&file_accepted);
    let file_writer = tokio::spawn(async move {
        if file {
            let body = vec![0xb2; 4 * 1024 * 1024];
            let mut offset = 0;
            while offset < body.len() {
                let len = local_stream.write(&body[offset..]).await.unwrap();
                assert!(len > 0);
                offset += len;
                accepted_file.fetch_add(len as u64, Ordering::Relaxed);
            }
        }
        std::future::pending::<()>().await;
        drop(local_stream);
    });
    if !file_lead.is_zero() {
        sleep(file_lead).await;
        apply_stream_budget(stream_budget, &tx, &mut admission);
    }
    let started = Instant::now();
    let secondary_received = Arc::new(AtomicU64::new(0));
    let received_secondary = Arc::clone(&secondary_received);
    let (received_tx, mut received_rx) = mpsc::unbounded_channel();
    let media_reader = tokio::spawn(async move {
        let mut cipher = SessionDatagramRx::new(&[7; 32], &[8; 32], true);
        while let Ok(packet) = rx.recv().await {
            if let Some(frame) = cipher
                .decode_datagram(&packet, std::time::Instant::now())
                .unwrap()
            {
                let cell = CircuitDataPayload::decode(&frame[HEADER_SIZE..]).unwrap();
                if cell.circuit_id == 1 {
                    let sent_ns = u64::from_be_bytes(cell.ciphertext[..8].try_into().unwrap());
                    received_tx
                        .send((
                            cell.seq,
                            started
                                .elapsed()
                                .saturating_sub(Duration::from_nanos(sent_ns)),
                        ))
                        .unwrap();
                } else {
                    assert_eq!(cell.circuit_id, 2);
                    received_secondary.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });
    let mut cipher = SessionDatagramTx::new(&[7; 32], &[8; 32], true);
    let mut primary_sent = 0;
    let mut secondary_sent = 0;
    let mut secondary_dropped = 0;
    // Tick periods 2/1 produce 50 primary and 100 secondary cells/s,
    // overloading this link. The reliable stream is independent application
    // traffic on the same QUIC.
    for tick in 0..ticks {
        sleep_until(started + Duration::from_millis(u64::from(tick) * 10)).await;
        let ceiling = tx.max_size().unwrap();
        if tick % primary_tick_period == 0 {
            let mut primary = circuit_frame(1, 0x11);
            // Circuit header is id:u32 + seq:u32 + ciphertext_len:u16.
            primary[HEADER_SIZE + 4..HEADER_SIZE + 8]
                .copy_from_slice(&(tick / primary_tick_period).to_be_bytes());
            primary[HEADER_SIZE + 10..HEADER_SIZE + 18]
                .copy_from_slice(&(started.elapsed().as_nanos() as u64).to_be_bytes());
            if matches!(
                stream_budget,
                StreamBudget::LocalPrimary | StreamBudget::TransitPrimary
            ) {
                admission.observe(
                    if matches!(stream_budget, StreamBudget::LocalPrimary) {
                        REALTIME
                    } else {
                        veil_proto::priority::INTERACTIVE
                    },
                    &primary,
                    std::time::Instant::now(),
                    false,
                );
            }
            let packets = cipher
                .encode_frame(u64::from(REALTIME), &primary, ceiling)
                .unwrap();
            if super::local_datagram_fits(
                REALTIME,
                packets.iter().map(Vec::len).sum(),
                tx.send_buffer_space(),
            ) {
                for packet in packets {
                    tx.send(&packet).unwrap();
                }
                primary_sent += 1;
            }
        }
        // Low-cadence capture is an independent producer. Offset its compact
        // frames by one tick instead of forcing every frame to coincide with
        // primary admission (which can intentionally shed the whole frame).
        if video_tick_period.is_none_or(|period| (tick + period - 1) % period != 0) {
            continue;
        }
        let secondary = circuit_frame(2, 0x22);
        let packets = cipher
            .encode_frame(u64::from(BULK), &secondary, ceiling)
            .unwrap();
        if super::local_datagram_fits(
            BULK,
            packets.iter().map(Vec::len).sum(),
            tx.send_buffer_space(),
        ) {
            for packet in packets {
                tx.send(&packet).unwrap();
            }
            secondary_sent += 1;
        } else {
            secondary_dropped += 1;
        }
    }
    sleep(Duration::from_secs(1)).await;
    let mut samples = Vec::new();
    let mut sequences = std::collections::HashSet::new();
    while let Ok((seq, delay)) = received_rx.try_recv() {
        assert!(sequences.insert(seq), "duplicate primary cell");
        samples.push(delay);
    }
    samples.sort_unstable();
    let p95 = samples.get(samples.len() * 95 / 100).copied();
    eprintln!(
        "continuous: ticks={ticks} file={file} video_tick_period={video_tick_period:?} primary_tick_period={primary_tick_period} stream_budget={stream_budget:?} file_lead_ms={} primary_sent={primary_sent} primary_received={} primary_p95_ms={:?} secondary_sent={secondary_sent} secondary_received={} secondary_dropped={secondary_dropped} file_bytes={} file_accepted={} neutral_udp_drops={}",
        file_lead.as_millis(),
        samples.len(),
        p95.map(|v| v.as_secs_f64() * 1000.0),
        secondary_received.load(Ordering::Relaxed),
        file_bytes.load(Ordering::Relaxed),
        file_accepted.load(Ordering::Relaxed),
        link.dropped.load(Ordering::Relaxed)
    );
    for task in [file_writer, file_reader, media_reader] {
        task.abort();
        let _ = task.await;
    }
    ContinuousReport {
        primary_sent,
        primary_received: samples.len(),
        primary_p95: p95,
        secondary_sent,
        secondary_received: secondary_received.load(Ordering::Relaxed) as usize,
        secondary_dropped,
        file_bytes: file_bytes.load(Ordering::Relaxed),
        file_accepted: file_accepted.load(Ordering::Relaxed),
    }
}

fn require_primary_quality(report: &ContinuousReport) {
    require_primary_quality_for(report, 100);
}

fn require_primary_quality_for(report: &ContinuousReport, expected: usize) {
    assert_eq!(report.primary_sent, expected);
    assert!(
        report.primary_received >= expected * 95 / 100,
        "too many primary cells lost: {report:?}"
    );
    assert!(
        report
            .primary_p95
            .is_some_and(|v| v < Duration::from_millis(200)),
        "{report:?}"
    );
}

#[tokio::test]
async fn continuous_primary_delivery_on_a_neutral_link_without_competing_load() {
    let report = measure_continuous(false, None, 2).await;
    assert_eq!(report.file_bytes, 0);
    assert_eq!((report.secondary_sent, report.secondary_dropped), (0, 0));
    require_primary_quality(&report);
}

// A manual matrix characterizes the sustained-load root cause; it is not a
// passing quality gate for the loaded configurations. Every case has fresh
// connections and the same neutral FIFO, padding and authentication.
#[tokio::test]
#[ignore = "Manual shared-connection load matrix; run with --ignored --nocapture"]
async fn characterize_continuous_primary_with_independent_competing_producers() {
    for (file, video_period, period) in [
        (false, None, 2),
        (false, Some(1), 2),
        (true, None, 2),
        (true, Some(1), 2),
        (true, Some(1), 4),
        // Lowest anonymous video cadence: 2 padded frames/s, no file.
        (false, Some(50), 2),
    ] {
        let report = measure_continuous(file, video_period, period).await;
        assert_eq!(report.primary_sent as u32, 200 / period);
        assert!(report.primary_received > 0);
        assert_eq!(report.file_bytes > 0, file);
        assert_eq!(report.secondary_sent > 0, video_period.is_some());
    }
}

#[tokio::test]
#[ignore = "Experimental endpoint stream budget matrix; run with --ignored --nocapture"]
async fn characterize_local_reliable_admission_during_primary_delivery() {
    for (budget, lead) in [
        (StreamBudget::Default, Duration::ZERO),
        (StreamBudget::LocalPrimary, Duration::ZERO),
        (StreamBudget::Manual(2048), Duration::ZERO),
        (StreamBudget::LocalPrimary, Duration::from_millis(250)),
    ] {
        let report = measure_continuous_with_stream_budget(true, None, 2, budget, lead).await;
        assert_eq!(report.primary_sent, 100);
        assert!(report.primary_received > 0);
        assert!(report.file_bytes > 0);
    }
}

#[tokio::test]
async fn local_primary_bounds_new_file_admission_and_preserves_delivery() {
    let report = measure_continuous_with_stream_budget(
        true,
        None,
        2,
        StreamBudget::LocalPrimary,
        Duration::ZERO,
    )
    .await;
    assert!(report.file_bytes > 0, "file must actually progress");
    require_primary_quality(&report);
}

#[tokio::test]
async fn local_primary_stays_fresh_with_low_cadence_video_and_file_for_ten_seconds() {
    // Exercise the current endpoint reliable budget together with compact
    // secondary frames at 2/s. The old overload characterization below keeps
    // its unbounded reliable admission and 100 secondary frames/s. This
    // neutral FIFO sees no roles, priorities or special flow treatment.
    let report = measure_continuous_for_ticks(
        true,
        Some(50),
        2,
        StreamBudget::LocalPrimary,
        Duration::ZERO,
        1000,
    )
    .await;
    assert!(report.secondary_sent > 0 && report.secondary_received > 0);
    assert!(
        report.file_bytes > 0,
        "file payload must actually cross the link"
    );
    require_primary_quality_for(&report, 500);
}

#[tokio::test]
async fn transit_and_retired_local_producers_keep_normal_reliable_admission() {
    for mode in [
        StreamBudget::TransitPrimary,
        StreamBudget::ExpiredLocalPrimary,
        StreamBudget::DroppedLocalPrimary,
    ] {
        let report =
            measure_continuous_with_stream_budget(true, None, 2, mode, Duration::ZERO).await;
        assert_eq!(
            report.file_accepted,
            4 * 1024 * 1024,
            "{mode:?}: admission must be restored or unchanged"
        );
        assert!(report.file_bytes > 0);
    }
}

// Deliberately retained as a failing characterization, not a passing quality
// gate: one physical congestion budget still cannot sustain these producers.
#[tokio::test]
#[ignore = "Known shared-connection latency/loss under sustained load; run with --ignored --nocapture"]
async fn continuous_primary_delivery_under_video_and_reliable_stream_load() {
    let report = measure_continuous(true, Some(1), 2).await;
    assert!(report.secondary_sent > 0 && report.secondary_dropped > 0);
    assert!(report.file_bytes > 0, "file must actually cross the link");
    require_primary_quality(&report);
}

#[tokio::test]
async fn independent_primary_budget_allows_file_progress_and_returns_to_shared_bound() {
    // Actual QUIC admission policy; not a media quality assertion. Production
    // obtains readiness from the selected, prepared independent connection.
    let shared = measure_continuous_with_stream_budget(
        true,
        None,
        2,
        StreamBudget::LocalPrimary,
        Duration::ZERO,
    )
    .await;
    let independent = measure_continuous_with_stream_budget(
        true,
        None,
        2,
        StreamBudget::IndependentPrimary,
        Duration::ZERO,
    )
    .await;
    let returned = measure_continuous_with_stream_budget(
        true,
        None,
        2,
        StreamBudget::ReturnedToSharedPrimary,
        Duration::ZERO,
    )
    .await;
    assert!(
        independent.file_bytes > shared.file_bytes * 2,
        "independent readiness must not retain the one-KiB bottleneck"
    );
    assert!(
        independent.file_accepted < 4 * 1024 * 1024,
        "source write-ahead remains bounded"
    );
    assert!(
        returned.file_bytes < independent.file_bytes / 2,
        "fallback must reapply the shared admission bound"
    );
    assert!(
        returned.file_bytes > 0,
        "shared fallback must still make file progress"
    );
}

struct BlackoutReport {
    max_post_age: Duration,
    first_fresh: Option<Duration>,
}

// Diagnose transport recovery independently of call control, ratchets, video,
// files and route repair. A prepared source's production policy is used when
// expiry is enabled; the neutral link never learns that local selection.
async fn measure_primary_blackout(
    large_cells: bool,
    link_delay: Duration,
    expiry: bool,
) -> BlackoutReport {
    use crate::datagram_flows::{SessionDatagramRx, SessionDatagramTx};
    use std::collections::HashSet;
    use veil_proto::{
        app::AppRtDataPayload,
        family::{AppMsg, FrameFamily},
        header::{FrameHeader, HEADER_SIZE},
        priority::REALTIME,
    };

    // Warm the congestion controller on the actual link before loss.
    let blackout_start = Duration::from_secs(6);
    let blackout_end = blackout_start + Duration::from_secs(2);
    let total_ticks = 900;
    let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let link = NeutralLink::new(
        left.local_addr().unwrap(),
        right.local_addr().unwrap(),
        1_000_000,
        link_delay,
    )
    .await;
    link.enabled.store(true, Ordering::Relaxed);
    let context = Arc::new(TransportContext::for_debug().unwrap());
    let remote_context = Arc::clone(&context);
    let remote_addr = link.right_addr;
    let remote = tokio::spawn(async move {
        promote_punched_quic(
            right,
            remote_addr,
            remote_context,
            PunchedQuicRole::Responder,
        )
        .await
        .unwrap()
    });
    let local = promote_punched_quic(left, link.left_addr, context, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    let tx = local.quic_datagrams().unwrap();
    let mut local_stream = local.into_stream().unwrap();
    local_stream.write_all(b"stand").await.unwrap();
    let remote = remote.await.unwrap();
    let rx = remote.quic_datagrams().unwrap();
    let stats_rx = rx.clone();
    let mut remote_stream = remote.into_stream().unwrap();
    let mut prefix = [0; 5];
    remote_stream.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"stand");
    sleep(Duration::from_millis(100)).await;

    let started = Instant::now();
    let (received_tx, mut received_rx) = mpsc::unbounded_channel();
    let reader = tokio::spawn(async move {
        let mut cipher = SessionDatagramRx::new(&[7; 32], &[8; 32], true);
        while let Ok(packet) = rx.recv().await {
            if let Some(frame) = cipher
                .decode_datagram(&packet, std::time::Instant::now())
                .unwrap()
            {
                let (seq, sent_us) = if large_cells {
                    let cell = veil_anonymity::circuit_wire::CircuitDataPayload::decode(
                        &frame[HEADER_SIZE..],
                    )
                    .unwrap();
                    assert_eq!(cell.circuit_id, 1);
                    assert!(cell.ciphertext[8..].iter().all(|byte| *byte == 0x11));
                    (
                        cell.seq,
                        u64::from_be_bytes(cell.ciphertext[..8].try_into().unwrap()),
                    )
                } else {
                    let payload = AppRtDataPayload::decode(&frame[HEADER_SIZE..]).unwrap();
                    assert_eq!(payload.payload, vec![0x11; 128]);
                    assert_eq!(payload.src_app_id, [1; 32]);
                    (payload.seq, payload.timestamp_us)
                };
                if received_tx.send((seq, sent_us, started.elapsed())).is_err() {
                    return;
                }
            }
        }
    });
    let mut cipher = SessionDatagramTx::new(&[7; 32], &[8; 32], true);
    let mut accepted = 0;
    let mut admission_drops = 0;
    let mut max_queued_bytes = 0;
    for tick in 0u32..total_ticks {
        sleep_until(started + Duration::from_millis(u64::from(tick) * 20)).await;
        // Both directions lose every packet, including ACKs, for exactly
        // two seconds. Handshake and steady-state RTT use the same FIFO.
        link.blackout.store(
            (blackout_start..blackout_end).contains(&started.elapsed()),
            Ordering::Relaxed,
        );
        let sent_us = started.elapsed().as_micros() as u64;
        let frame = if large_cells {
            let mut frame = circuit_frame(1, 0x11);
            frame[HEADER_SIZE + 4..HEADER_SIZE + 8].copy_from_slice(&tick.to_be_bytes());
            frame[HEADER_SIZE + 10..HEADER_SIZE + 18].copy_from_slice(&sent_us.to_be_bytes());
            frame
        } else {
            let body = AppRtDataPayload {
                src_app_id: [1; 32],
                app_id: [2; 32],
                endpoint_id: 1,
                seq: tick,
                timestamp_us: sent_us,
                marker: 0,
                payload_type: 111,
                payload: vec![0x11; 128],
            }
            .encode();
            let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppRtData as u16);
            header.set_priority(REALTIME);
            header.body_len = body.len() as u32;
            let mut frame = veil_proto::encode_header(&header).to_vec();
            frame.extend_from_slice(&body);
            frame
        };
        let packets = cipher
            .encode_frame(u64::from(REALTIME), &frame, tx.max_size().unwrap())
            .unwrap();
        if super::local_primary_datagram_fits(
            packets.iter().map(Vec::len).sum(),
            tx.send_buffer_space(),
        ) {
            let deadline =
                super::local_primary_datagram_expiry(REALTIME, expiry, std::time::Instant::now());
            for packet in packets {
                match deadline {
                    Some(deadline) => tx.send_before(&packet, deadline).unwrap(),
                    None => tx.send(&packet).unwrap(),
                }
            }
            accepted += 1;
        } else {
            admission_drops += 1;
        }
        max_queued_bytes = max_queued_bytes
            .max(REALTIME_DATAGRAM_BUFFER_BYTES.saturating_sub(tx.send_buffer_space()));
    }
    sleep(link_delay + Duration::from_millis(300)).await;
    reader.abort();
    assert!(reader.await.unwrap_err().is_cancelled());
    let mut seen = HashSet::new();
    let mut pre_blackout = 0;
    let mut post_blackout = 0;
    let mut duplicates = 0;
    let mut first_fresh = None;
    let mut max_post_age = Duration::ZERO;
    let mut latest_seq = 0;
    let mut max_post_gap = Duration::ZERO;
    let mut previous_post = None;
    while let Ok((seq, sent_us, arrived)) = received_rx.try_recv() {
        if !seen.insert(seq) {
            duplicates += 1;
        }
        latest_seq = latest_seq.max(seq);
        if arrived < blackout_start {
            pre_blackout += 1;
        }
        if arrived >= blackout_end {
            post_blackout += 1;
            max_post_age = max_post_age.max(arrived.saturating_sub(Duration::from_micros(sent_us)));
            if Duration::from_micros(sent_us) >= blackout_end && first_fresh.is_none() {
                first_fresh = Some(arrived - blackout_end);
            }
            if let Some(previous) = previous_post {
                max_post_gap = max_post_gap.max(arrived - previous);
            }
            previous_post = Some(arrived);
        }
    }
    eprintln!(
        "blackout expiry={expiry} large_cells={large_cells} link_delay_ms={} accepted={accepted} admission_drops={admission_drops} pre={pre_blackout} post={post_blackout} first_fresh_ms={:?} max_post_age_ms={} max_post_gap_ms={} latest_seq={latest_seq} duplicates={duplicates} max_queued_bytes={max_queued_bytes} neutral_drops={} tx={:?} rx={:?}",
        link_delay.as_millis(),
        first_fresh.map(|v| v.as_millis()),
        max_post_age.as_millis(),
        max_post_gap.as_millis(),
        link.dropped.load(Ordering::Relaxed),
        tx.path_stats(),
        stats_rx.path_stats(),
    );
    assert!(
        pre_blackout > 0,
        "must actually establish delivery before the blackout"
    );
    assert!(
        post_blackout > 0 && latest_seq >= total_ticks - 100,
        "must actually recover on the same connection"
    );
    assert_eq!(duplicates, 0);
    // No tight latency assertion: report actual recovery before attributing
    // a many-second phone outage to QUIC's loss-probe backoff.
    drop((local_stream, remote_stream));
    BlackoutReport {
        max_post_age,
        first_fresh,
    }
}

#[tokio::test]
#[ignore = "Manual neutral UDP blackout/expiry characterization; run with --ignored --nocapture"]
async fn characterize_primary_datagram_recovery_after_neutral_udp_blackout() {
    for expiry in [false, true] {
        for (large_cells, link_delay) in [
            (false, Duration::from_millis(20)),
            (true, Duration::from_millis(20)),
            (false, Duration::from_secs(1)),
            (true, Duration::from_secs(1)),
        ] {
            let report = measure_primary_blackout(large_cells, link_delay, expiry).await;
            assert!(report.first_fresh.is_some());
        }
    }
}

#[tokio::test]
async fn prepared_primary_expires_stale_packets_after_neutral_udp_loss() {
    // The unchanged admission/capacity policy alone keeps old packets for
    // seconds. Same link/loss/frame sizes, fresh real connections in both cases.
    let old = measure_primary_blackout(false, Duration::from_millis(20), false).await;
    let fresh = measure_primary_blackout(false, Duration::from_millis(20), true).await;
    assert!(
        old.max_post_age > Duration::from_secs(1),
        "control must reproduce stale delivery"
    );
    assert!(
        fresh.first_fresh.is_some(),
        "fresh logical frames must resume"
    );
    assert!(
        fresh.max_post_age < Duration::from_millis(400),
        "200 ms sender deadline plus link delay must replace stale backlog: {:?}",
        fresh.max_post_age
    );
}

struct BoundTestLane {
    tx: QuicDatagramHandle,
    rx: QuicDatagramHandle,
    tx_cipher: crate::datagram_flows::SessionDatagramTx,
    rx_cipher: crate::datagram_flows::SessionDatagramRx,
    _tx_stream: veil_transport::BoxIoStream,
    _rx_stream: veil_transport::BoxIoStream,
}

async fn bind_test_lane(
    local: &veil_transport::QuicParallelHandle,
    remote: &veil_transport::QuicParallelHandle,
    local_parent: &crate::parallel_binding::ParallelParent,
    remote_parent: &crate::parallel_binding::ParallelParent,
) -> BoundTestLane {
    use crate::parallel_binding::HELLO_BYTES;
    let remote = remote.clone();
    let remote_parent = remote_parent.handle();
    let accept = tokio::spawn(async move {
        let connection = remote.accept().await.unwrap();
        let datagrams = connection.quic_datagrams().unwrap();
        let exporter = datagrams.channel_binding().unwrap();
        let mut stream = connection.into_stream().unwrap();
        let mut hello = [0; HELLO_BYTES];
        stream.read_exact(&mut hello).await.unwrap();
        let (ack, keys) = remote_parent.accept(&hello, exporter).unwrap();
        stream.write_all(&ack).await.unwrap();
        (datagrams, stream, keys)
    });
    let connection = local.connect().await.unwrap();
    let tx = connection.quic_datagrams().unwrap();
    let (hello, pending) = local_parent.begin(tx.channel_binding().unwrap()).unwrap();
    let mut tx_stream = connection.into_stream().unwrap();
    tx_stream.write_all(&hello).await.unwrap();
    let mut ack = [0; 32];
    tx_stream.read_exact(&mut ack).await.unwrap();
    let tx_keys = pending.finish(&ack).unwrap();
    let (rx, rx_stream, rx_keys) = accept.await.unwrap();
    assert_eq!(tx_keys.session_id, rx_keys.session_id);
    assert!(tx_keys.tx_key() == rx_keys.rx_key());
    BoundTestLane {
        tx,
        rx,
        tx_cipher: crate::datagram_flows::SessionDatagramTx::new(
            tx_keys.tx_key(),
            &tx_keys.session_id,
            true,
        ),
        rx_cipher: crate::datagram_flows::SessionDatagramRx::new(
            rx_keys.rx_key(),
            &rx_keys.session_id,
            true,
        ),
        _tx_stream: tx_stream,
        _rx_stream: rx_stream,
    }
}

fn primary_test_frame(large: bool, seq: u32, sent_us: u64) -> Vec<u8> {
    use veil_proto::{
        app::AppRtDataPayload,
        family::{AppMsg, FrameFamily},
        header::{FrameHeader, HEADER_SIZE},
    };
    if large {
        let mut frame = circuit_frame(1, 0x11);
        frame[HEADER_SIZE + 4..HEADER_SIZE + 8].copy_from_slice(&seq.to_be_bytes());
        frame[HEADER_SIZE + 10..HEADER_SIZE + 18].copy_from_slice(&sent_us.to_be_bytes());
        frame
    } else {
        let body = AppRtDataPayload {
            src_app_id: [1; 32],
            app_id: [2; 32],
            endpoint_id: 1,
            seq,
            timestamp_us: sent_us,
            marker: 0,
            payload_type: 111,
            payload: vec![0x11; 128],
        }
        .encode();
        let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppRtData as u16);
        header.set_priority(veil_proto::priority::REALTIME);
        header.body_len = body.len() as u32;
        let mut frame = veil_proto::encode_header(&header).to_vec();
        frame.extend_from_slice(&body);
        frame
    }
}

#[derive(Debug)]
struct IndependentLoadReport {
    large_primary: bool,
    loaded: bool,
    primary_sent: usize,
    primary_received: usize,
    primary_duplicates: usize,
    primary_p95_ms: f64,
    primary_max_age_ms: f64,
    primary_max_gap_ms: f64,
    secondary_sent: usize,
    secondary_received: u64,
    secondary_dropped: usize,
    file_bytes: u64,
    file_accepted: u64,
    neutral_drops: u64,
}

async fn measure_bound_independent_load(
    large_primary: bool,
    loaded: bool,
) -> IndependentLoadReport {
    use crate::parallel_binding::ParallelParent;
    use std::collections::HashSet;
    use veil_proto::{
        app::AppRtDataPayload,
        header::HEADER_SIZE,
        priority::{BULK, REALTIME},
    };
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
    let context = Arc::new(TransportContext::for_debug().unwrap());
    let remote_context = Arc::clone(&context);
    let remote_addr = link.right_addr;
    let remote = tokio::spawn(promote_punched_quic(
        right,
        remote_addr,
        remote_context,
        PunchedQuicRole::Responder,
    ));
    let local = promote_punched_quic(left, link.left_addr, context, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    let close = local.quic_connection().unwrap();
    let local_handle = local.parallel_quic().unwrap();
    let canonical = local.quic_datagrams().unwrap();
    let mut local_stream = local.into_stream().unwrap();
    local_stream.write_all(b"stand").await.unwrap();
    let remote = remote.await.unwrap().unwrap();
    let remote_handle = remote.parallel_quic().unwrap();
    let mut remote_stream = remote.into_stream().unwrap();
    let mut prefix = [0; 5];
    remote_stream.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"stand");
    // Credentials stand in for a previously authenticated canonical session.
    // This test verifies exporter-bound child activation, not identity mining.
    let local_parent = ParallelParent::new([1; 32], [2; 32], [3; 32]);
    let remote_parent = ParallelParent::new([1; 32], [3; 32], [2; 32]);
    let mut primary =
        bind_test_lane(&local_handle, &remote_handle, &local_parent, &remote_parent).await;
    let mut secondary =
        bind_test_lane(&local_handle, &remote_handle, &local_parent, &remote_parent).await;
    assert!(primary.tx.channel_binding().unwrap() != secondary.tx.channel_binding().unwrap());
    assert!(primary.tx.channel_binding().unwrap() != canonical.channel_binding().unwrap());
    let mut admission = super::local_reliable_admission::LocalReliableAdmission::new(canonical);
    let fixture = primary_test_frame(large_primary, 0, 0);
    admission.observe(REALTIME, &fixture, std::time::Instant::now(), true);
    sleep(Duration::from_millis(100)).await;
    let started = Instant::now();
    let file_bytes = Arc::new(AtomicU64::new(0));
    let file_accepted = Arc::new(AtomicU64::new(0));
    let file_rx = Arc::clone(&file_bytes);
    let file_tx = Arc::clone(&file_accepted);
    let file_reader = tokio::spawn(async move {
        let mut bytes = [0; 16384];
        while let Ok(len) = remote_stream.read(&mut bytes).await {
            if len == 0 {
                return;
            }
            assert!(bytes[..len].iter().all(|byte| *byte == 0xb2));
            file_rx.fetch_add(len as u64, Ordering::Relaxed);
        }
    });
    let file_writer = tokio::spawn(async move {
        if loaded {
            sleep_until(started + Duration::from_secs(2)).await;
            let bytes = vec![0xb2; 4 * 1024 * 1024];
            let mut offset = 0;
            while offset < bytes.len() {
                let len = local_stream.write(&bytes[offset..]).await.unwrap();
                offset += len;
                file_tx.fetch_add(len as u64, Ordering::Relaxed);
            }
        }
        std::future::pending::<()>().await;
        drop(local_stream);
    });
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let primary_rx = primary.rx.clone();
    let mut primary_cipher_rx = primary.rx_cipher;
    let primary_reader = tokio::spawn(async move {
        while let Ok(packet) = primary_rx.recv().await {
            if let Some(frame) = primary_cipher_rx
                .decode_datagram(&packet, std::time::Instant::now())
                .unwrap()
            {
                let (seq, timestamp) = if large_primary {
                    let cell = veil_anonymity::circuit_wire::CircuitDataPayload::decode(
                        &frame[HEADER_SIZE..],
                    )
                    .unwrap();
                    assert_eq!(cell.circuit_id, 1);
                    assert!(cell.ciphertext[8..].iter().all(|byte| *byte == 0x11));
                    (
                        cell.seq,
                        u64::from_be_bytes(cell.ciphertext[..8].try_into().unwrap()),
                    )
                } else {
                    let rt = AppRtDataPayload::decode(&frame[HEADER_SIZE..]).unwrap();
                    assert_eq!(rt.payload, vec![0x11; 128]);
                    (rt.seq, rt.timestamp_us)
                };
                if observed_tx
                    .send((seq, timestamp, started.elapsed()))
                    .is_err()
                {
                    return;
                }
            }
        }
    });
    let secondary_received = Arc::new(AtomicU64::new(0));
    let secondary_count = Arc::clone(&secondary_received);
    let secondary_rx = secondary.rx.clone();
    let mut secondary_cipher_rx = secondary.rx_cipher;
    let secondary_reader = tokio::spawn(async move {
        while let Ok(packet) = secondary_rx.recv().await {
            if let Some(frame) = secondary_cipher_rx
                .decode_datagram(&packet, std::time::Instant::now())
                .unwrap()
            {
                let cell =
                    veil_anonymity::circuit_wire::CircuitDataPayload::decode(&frame[HEADER_SIZE..])
                        .unwrap();
                assert_eq!(cell.circuit_id, 2);
                assert!(cell.ciphertext.iter().all(|byte| *byte == 0x22));
                secondary_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    let mut primary_sent = 0;
    let mut secondary_sent = 0;
    let mut secondary_dropped = 0;
    for tick in 0u32..1200 {
        sleep_until(started + Duration::from_millis(u64::from(tick) * 10)).await;
        if tick % 2 == 0 {
            let seq = tick / 2;
            let frame =
                primary_test_frame(large_primary, seq, started.elapsed().as_micros() as u64);
            let now = std::time::Instant::now();
            admission.observe_primary_path(&primary.tx, now);
            admission.observe(REALTIME, &frame, now, true);
            let packets = primary
                .tx_cipher
                .encode_frame(u64::from(REALTIME), &frame, primary.tx.max_size().unwrap())
                .unwrap();
            if super::local_primary_datagram_fits(
                packets.iter().map(Vec::len).sum(),
                primary.tx.send_buffer_space(),
            ) {
                let deadline =
                    super::local_primary_datagram_expiry(REALTIME, true, std::time::Instant::now())
                        .unwrap();
                for packet in packets {
                    primary.tx.send_before(&packet, deadline).unwrap();
                }
                if tick >= 200 {
                    primary_sent += 1;
                }
            }
        }
        // Interleaved neutral traffic cannot select or reset the local gate.
        for priority in [
            veil_proto::priority::INTERACTIVE,
            REALTIME,
            veil_proto::priority::BACKGROUND,
        ] {
            assert!(admission.allow_secondary(priority, std::time::Instant::now()));
        }
        if loaded && tick >= 200 {
            let frame = circuit_frame(2, 0x22);
            let packets = secondary
                .tx_cipher
                .encode_frame(u64::from(BULK), &frame, secondary.tx.max_size().unwrap())
                .unwrap();
            if admission.allow_secondary(BULK, std::time::Instant::now())
                && super::local_datagram_fits(
                    BULK,
                    packets.iter().map(Vec::len).sum(),
                    secondary.tx.send_buffer_space(),
                )
            {
                for packet in packets {
                    secondary.tx.send(&packet).unwrap();
                }
                secondary_sent += 1;
            } else {
                secondary_dropped += 1;
            }
        }
    }
    sleep(Duration::from_millis(400)).await;
    // Close before evaluating quality so a failed assertion cannot strand
    // child transports, blocked writes or stand reader tasks.
    close.close(0u32.into(), b"independent stand complete");
    let tasks = [file_reader, file_writer, primary_reader, secondary_reader];
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        match task.await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => panic!("independent stand worker failed: {error}"),
        }
    }
    let mut ages = Vec::new();
    let mut previous = None;
    let mut max_gap = Duration::ZERO;
    let mut seen = HashSet::new();
    let mut duplicates = 0;
    while let Ok((seq, timestamp, arrived)) = observed_rx.try_recv() {
        if seq < 100 {
            continue;
        }
        if !seen.insert(seq) {
            duplicates += 1;
        }
        ages.push(
            arrived
                .saturating_sub(Duration::from_micros(timestamp))
                .as_secs_f64()
                * 1000.0,
        );
        max_gap = max_gap.max(arrived - previous.unwrap_or(Duration::from_secs(2)));
        previous = Some(arrived);
    }
    max_gap = max_gap
        .max(Duration::from_secs(12).saturating_sub(previous.unwrap_or(Duration::from_secs(2))));
    ages.sort_by(f64::total_cmp);
    let report = IndependentLoadReport {
        large_primary,
        loaded,
        primary_sent,
        primary_received: ages.len(),
        primary_duplicates: duplicates,
        primary_p95_ms: ages
            .get((ages.len() * 95 / 100).min(ages.len().saturating_sub(1)))
            .copied()
            .unwrap_or(f64::INFINITY),
        primary_max_age_ms: ages.last().copied().unwrap_or(f64::INFINITY),
        primary_max_gap_ms: max_gap.as_secs_f64() * 1000.0,
        secondary_sent,
        secondary_received: secondary_received.load(Ordering::Relaxed),
        secondary_dropped,
        file_bytes: file_bytes.load(Ordering::Relaxed),
        file_accepted: file_accepted.load(Ordering::Relaxed),
        neutral_drops: link.dropped.load(Ordering::Relaxed),
    };
    eprintln!(
        "bound_independent large_primary={} loaded={} primary_sent={} primary_received={} duplicates={} primary_p95_ms={} primary_max_age_ms={} primary_max_gap_ms={} secondary_sent={} secondary_received={} secondary_dropped={} file_bytes={} file_accepted={} neutral_drops={}",
        report.large_primary,
        report.loaded,
        report.primary_sent,
        report.primary_received,
        report.primary_duplicates,
        report.primary_p95_ms,
        report.primary_max_age_ms,
        report.primary_max_gap_ms,
        report.secondary_sent,
        report.secondary_received,
        report.secondary_dropped,
        report.file_bytes,
        report.file_accepted,
        report.neutral_drops
    );
    report
}

#[tokio::test]
#[ignore = "Manual exporter-bound independent connection load characterization"]
async fn characterize_bound_independent_primary_under_secondary_and_file_load() {
    for large in [false, true] {
        for loaded in [false, true] {
            let report = measure_bound_independent_load(large, loaded).await;
            assert_eq!(report.primary_duplicates, 0);
            assert!(report.primary_received > 0);
            if loaded {
                assert!(report.secondary_received > 0 && report.file_bytes > 0);
            }
        }
    }
}

#[tokio::test]
async fn bound_independent_primary_survives_competing_endpoint_producers() {
    let report = measure_bound_independent_load(true, true).await;
    // The denominator is all 500 source attempts, including local admission
    // drops; counting only accepted frames would hide primary starvation.
    assert!(
        report.primary_received >= 450,
        "primary starvation: {report:?}"
    );
    assert!(
        report.primary_p95_ms < 350.0,
        "sustained queue delay: {report:?}"
    );
    assert!(
        report.primary_max_gap_ms < 300.0,
        "primary freeze: {report:?}"
    );
    assert_eq!(report.primary_duplicates, 0);
    assert!(
        report.secondary_received > 0 && report.file_bytes >= 16 * 1024,
        "competing producers made no progress: {report:?}"
    );
}

#[tokio::test]
async fn primary_ack_blackout_limits_secondary_before_rtt_or_expiry_changes() {
    use veil_proto::priority::{BULK, INTERACTIVE, REALTIME};
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
    let close = local.quic_connection().unwrap();
    let handle = local.quic_datagrams().unwrap();
    let mut stream = local.into_stream().unwrap();
    stream.write_all(b"warm").await.unwrap();
    let remote = remote.await.unwrap().unwrap();
    let mut remote_stream = remote.into_stream().unwrap();
    let mut prefix = [0; 4];
    remote_stream.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"warm");
    timeout(Duration::from_secs(2), async {
        loop {
            let s = handle.path_stats();
            if s.rtt_us < 150_000 && s.in_flight_bytes == 0 && s.pto_count == 0 {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let mut admission =
        super::local_reliable_admission::LocalReliableAdmission::new(handle.clone());
    let frame = circuit_frame(1, 0x11);
    admission.observe(REALTIME, &frame, std::time::Instant::now(), true);
    link.blackout.store(true, Ordering::Relaxed);
    handle.send(&[0x11; 200]).unwrap();
    timeout(Duration::from_secs(2), async {
        while handle.path_stats().pto_count == 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let stalled = handle.path_stats();
    assert!(
        stalled.rtt_us < 150_000,
        "RTT must still look healthy: {stalled:?}"
    );
    assert_eq!(stalled.expired_outgoing_datagrams, 0);
    assert!(stalled.in_flight_bytes > 0 && link.dropped.load(Ordering::Relaxed) > 0);
    let now = std::time::Instant::now();
    admission.observe_primary_path(&handle, now);
    let probe_allowed = admission.allow_secondary(BULK, now);
    let burst_allowed = admission.allow_secondary(BULK, now + Duration::from_millis(1));
    for priority in [REALTIME, INTERACTIVE, veil_proto::priority::BACKGROUND] {
        assert!(admission.allow_secondary(priority, now));
    }
    link.blackout.store(false, Ordering::Relaxed);
    handle.send(&[0x22; 200]).unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            let s = handle.path_stats();
            if s.in_flight_bytes == 0 && s.pto_count == 0 {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    // ACK progress and the bounded grace permit full production again.
    admission.observe_primary_path(&handle, now + Duration::from_secs(2));
    let recovered = admission.allow_secondary(BULK, now + Duration::from_secs(2));
    close.close(0u32.into(), b"ack blackout gate complete");
    assert!(
        probe_allowed,
        "one sparse recovery probe must remain possible"
    );
    assert!(
        !burst_allowed,
        "stale low RTT allowed a secondary burst during primary PTO"
    );
    assert!(recovered, "secondary failed to resume after pressure grace");
}
