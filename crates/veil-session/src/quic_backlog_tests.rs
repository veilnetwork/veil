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
    io::AsyncWriteExt,
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
        .encode_frame(u64::from(BULK), &secondary, ceiling)
        .unwrap()
        .iter()
        .map(Vec::len)
        .sum::<usize>();
    let mut queued = 0;
    if let Some(capacity_only) = capacity_only {
        // All admission and fragments run before yielding to Quinn's driver.
        // The regression side reproduces the previous production reserve.
        loop {
            let available = tx.send_buffer_space();
            let fits = if capacity_only {
                secondary_wire + MAX_FRAME_WIRE_BYTES <= available
            } else {
                super::local_datagram_fits(BULK, secondary_wire, available)
            };
            if !fits {
                break;
            }
            for packet in cipher_tx
                .encode_frame(u64::from(BULK), &secondary, ceiling)
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
    assert!(super::local_datagram_fits(
        REALTIME,
        packets.iter().map(Vec::len).sum(),
        tx.send_buffer_space(),
    ));
    for packet in packets {
        tx.send(&packet).unwrap();
    }
    let (elapsed, received) = receive_primary(&rx, &mut cipher_rx, &primary, &secondary).await;
    eprintln!(
        "capacity_only={capacity_only:?} queued_bytes={queued} secondary_received={received} primary_ms={:?} neutral_udp_drops={}",
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
