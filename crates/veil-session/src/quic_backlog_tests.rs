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
            tasks.push(tokio::spawn(async move {
                let mut buffer = vec![0; 65536];
                loop {
                    let Ok((len, source)) = input.recv_from(&mut buffer).await else {
                        return;
                    };
                    if source == expected
                        && tx
                            .try_send((buffer[..len].to_vec(), Instant::now()))
                            .is_err()
                    {
                        drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
            let shape = Arc::clone(&enabled);
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
                    if output.send_to(&packet, destination).await.is_err() {
                        return;
                    }
                }
            }));
        }
        Self {
            enabled,
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
