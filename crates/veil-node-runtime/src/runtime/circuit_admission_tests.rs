//! Allocation and local rejection must not manufacture replay-window loss.
use super::*;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use veil_anonymity::{
    circuit_data::{CircuitCellBytes, ReplayWindow},
    circuit_wire::CircuitDataPayload,
};
use veil_proto::{HEADER_SIZE, family::RelayChainMsg};

fn circuit(last: u32) -> DataCircuit {
    DataCircuit {
        _local_path: None,
        first_hop: [0x71; 32],
        relay_path: vec![[0x71; 32]],
        origin_circuit_id: 7,
        keys: vec![[0x25; 32]],
        next_seq: AtomicU32::new(last),
        confirmed: Arc::new(AtomicBool::new(true)),
        cell_bytes: CircuitCellBytes::new(2048).unwrap(),
    }
}

#[test]
fn circuit_sequence_exhaustion_is_permanent() {
    let ordinary = circuit(0);
    assert_eq!(ordinary.alloc_seq(), Some(1));
    assert_eq!(ordinary.alloc_seq(), Some(2));
    let exhausted = circuit(u32::MAX - 1);
    assert_eq!(exhausted.alloc_seq(), Some(u32::MAX));
    for _ in 0..4 {
        assert_eq!(
            exhausted.alloc_seq(),
            None,
            "exhausted circuit reused a keystream nonce"
        );
    }
    assert_eq!(exhausted.next_seq.load(Ordering::Relaxed), u32::MAX);
}

#[test]
fn circuit_sequence_exhaustion_remains_unique_under_concurrent_calls() {
    let shared = Arc::new(circuit(u32::MAX - 16));
    let barrier = Arc::new(Barrier::new(8));
    let jobs = (0..8)
        .map(|_| {
            let shared = shared.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                (0..8)
                    .filter_map(|_| shared.alloc_seq())
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    let mut values = jobs
        .into_iter()
        .flat_map(|j| j.join().unwrap())
        .collect::<Vec<_>>();
    values.sort_unstable();
    assert_eq!(values, (u32::MAX - 15..=u32::MAX).collect::<Vec<_>>());
    assert_eq!(shared.alloc_seq(), None);
}

async fn fixture() -> (
    tempfile::TempDir,
    NodeRuntime,
    DataCircuit,
    veil_session::FrameOutbox,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut config = super::tests::runtime_config_with_metrics();
    config.peers.clear();
    config.global.meeting_points = veil_cfg::MeetingPoints::Only(Vec::new());
    veil_cfg::save_config(&path, &config).unwrap();
    let runtime = NodeRuntime::start(&path, true).await.unwrap();
    let services = runtime.access();
    let outbox = services
        .session_tx_registry
        .write()
        .unwrap()
        .register([0x71; 32]);
    (dir, runtime, circuit(0), outbox)
}
fn receive_seq(rx: &mut veil_session::FrameOutbox) -> u32 {
    let (_, bytes) = rx.try_recv().unwrap();
    let header = veil_proto::codec::decode_header(&bytes[..HEADER_SIZE]).unwrap();
    assert_eq!(header.msg_type, RelayChainMsg::CircuitDatagram as u16);
    CircuitDataPayload::decode(&bytes[HEADER_SIZE..])
        .unwrap()
        .seq
}

#[tokio::test]
async fn rejected_recoverable_cells_do_not_push_fresh_cells_out_of_replay_window() {
    let (_dir, mut runtime, circuit, mut rx) = fixture().await;
    let services = runtime.access();
    let send = || {
        services.send_circuit_datagram_on_local_lane_detailed(
            &circuit,
            b"payload",
            veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
        )
    };
    assert_eq!(send(), Ok(()));
    assert_eq!(send(), Ok(()));
    for _ in 0..ReplayWindow::WINDOW + 2 {
        assert_eq!(send(), Err(DataCircuitSendError::QueueFull));
    }
    let first = receive_seq(&mut rx);
    let second = receive_seq(&mut rx);
    assert_eq!(send(), Ok(()));
    let third = receive_seq(&mut rx);
    runtime.stop().await.unwrap();
    let mut replay = ReplayWindow::new();
    assert!(replay.accept(third));
    assert!(
        replay.accept(first),
        "local rejection gaps made a fresh delayed cell look too old"
    );
    assert!(replay.accept(second));
    assert!(
        !replay.accept(first),
        "an actual duplicate bypassed replay protection"
    );
    assert_eq!([first, second, third], [1, 2, 3]);
}

#[tokio::test]
async fn invalid_circuit_payload_does_not_consume_a_sequence_on_a_full_queue() {
    let (_dir, mut runtime, circuit, _rx) = fixture().await;
    let services = runtime.access();
    for _ in 0..2 {
        services
            .send_circuit_datagram_on_local_lane_detailed(
                &circuit,
                b"payload",
                veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
            )
            .unwrap();
    }
    let before = circuit.next_seq.load(Ordering::Relaxed);
    let error = services.send_circuit_datagram_on_local_lane_detailed(
        &circuit,
        &vec![0; 2048],
        veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
    );
    let after = circuit.next_seq.load(Ordering::Relaxed);
    runtime.stop().await.unwrap();
    assert_eq!(error, Err(DataCircuitSendError::PayloadTooLarge));
    assert_eq!(
        before, after,
        "payload rejected before admission consumed a nonce"
    );
}

#[tokio::test]
async fn exhausted_circuit_requests_rotation_even_when_recoverable_ingress_is_full() {
    let (_dir, mut runtime, circuit, _rx) = fixture().await;
    let services = runtime.access();
    for _ in 0..2 {
        services
            .send_circuit_datagram_on_local_lane_detailed(
                &circuit,
                b"payload",
                veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
            )
            .unwrap();
    }
    circuit.next_seq.store(u32::MAX, Ordering::Relaxed);
    let result = services.send_circuit_datagram_on_local_lane_detailed(
        &circuit,
        b"payload",
        veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
    );
    let unchanged = circuit.next_seq.load(Ordering::Relaxed);
    runtime.stop().await.unwrap();
    assert_eq!(result, Err(DataCircuitSendError::NoRelays));
    assert_eq!(unchanged, u32::MAX);
}
