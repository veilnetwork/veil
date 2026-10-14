//! The production scheduler must prefer separate ready circuit children over
//! a shared legacy return observation. Real obfs4 proofs and record I/O.
use super::super::{
    ParallelOrderedOffer, ParallelRegistry, RealtimeLaneOffer, RealtimeTransportOffer,
};
use super::*;
use std::sync::atomic::AtomicUsize;
use veil_anonymity::{
    circuit_carrier::{CarrierSend, DatagramCarrier},
    circuit_data::CircuitCellBytes,
    circuit_setup::CircuitInstall,
    circuit_table::CircuitTable,
    circuit_wire::CircuitDataPayload,
};
use veil_proto::{
    family::{FrameFamily, RelayChainMsg},
    header::FrameHeader,
    priority::INTERACTIVE,
};
use veil_transport::{Transport, TransportListener, TransportUri, obfs4_tcp::Obfs4TcpTransport};

struct SharedReturn(AtomicUsize);
impl DatagramCarrier for SharedReturn {
    fn try_send(&self, _: &[u8; 32], _: &[u8], _: &mut dyn FnMut(usize) -> bool) -> CarrierSend {
        self.0.fetch_add(1, Ordering::Relaxed);
        CarrierSend::Dropped { wire_bytes: 0 }
    }
}

#[tokio::test]
async fn production_ordered_scheduler_prefers_six_ready_circuits_over_shared_return() {
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
    let (local, remote) = (local.unwrap(), remote.unwrap());
    let remote_handle = remote.parallel_stream().unwrap();
    let remote_main = remote.into_stream().unwrap();
    let remote_parent = crate::parallel_binding::ParallelParent::new([1; 32], [3; 32], [2; 32]);
    let remote_registry = Arc::new(ParallelRegistry::default());
    let (incoming_tx, mut incoming) = tokio::sync::mpsc::channel(8);
    let remote_diagnostics = Arc::default();
    let registration = remote_registry
        .register_ordered(
            [1; 32],
            remote_parent.handle(),
            remote_handle,
            remote_diagnostics,
            incoming_tx,
        )
        .unwrap();
    let (stop_accept, mut accept_stop) = tokio::sync::oneshot::channel();
    let acceptor = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut accept_stop => break,
                result = listener.accept() => {
                    let connection = result.unwrap();
                    let binding = connection.stream_channel_binding();
                    assert!(matches!(remote_registry.peek_and_dispatch_with_binding(
                        connection.into_stream().unwrap(), None, binding).await,
                        super::super::ParallelPeekOutcome::Bound));
                }
            }
        }
    });
    let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
    let (stop_receivers, mut receiver_stop) = tokio::sync::oneshot::channel();
    let receivers = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        let mut index = 0;
        loop {
            tokio::select! {
                _ = &mut receiver_stop => break,
                Some(child) = incoming.recv() => {
                    let events = events.clone();
                    let child_index = index;
                    index += 1;
                    tasks.spawn(async move {
                        let channel = child.finish().await.unwrap();
                        let mut decoder = crate::datagram_flows::SessionDatagramRx::new(
                            channel.keys().rx_key(), &channel.keys().session_id, true);
                        while let Ok(packet) = channel.handle().recv().await {
                            if let Some(frame) = decoder.decode_datagram(&packet, std::time::Instant::now()).unwrap() {
                                events.send((child_index, frame)).unwrap();
                            }
                        }
                    });
                }
            }
        }
        tasks.shutdown().await;
    });
    let offer = ParallelOrderedOffer::new(
        local.parallel_stream().unwrap(),
        Arc::new(ParallelRegistry::default()),
    );
    let diagnostics = offer.diagnostics();
    let mut registry = crate::SessionTxRegistry::new();
    let outbox = registry.register([0xB1; 32]);
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
    let job = tokio::spawn(async move { runner.run().await });
    timeout(Duration::from_secs(5), async {
        while diagnostics.active_connections() != 6 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("six authenticated ready children");
    let table = CircuitTable::new();
    let shared = Arc::new(SharedReturn(AtomicUsize::new(0)));
    let erased: Arc<dyn DatagramCarrier> = shared.clone();
    let salt = blake3::derive_key("veil/transit-shard/v1", &[1; 32]);
    let bucket = |cid: u32| super::super::parallel_lanes::transit_index(&salt, &cid.to_be_bytes());
    let ids: Vec<_> = (1..100u32)
        .filter(|cid| bucket(*cid) == bucket(1))
        .take(6)
        .collect();
    let mut expected = Vec::new();
    for cid in ids {
        let state = table
            .install(
                &CircuitInstall {
                    circuit_id_in: cid,
                    circuit_id_out: cid,
                    circuit_key: [5; 32],
                    cell_bytes: CircuitCellBytes::new(1024).unwrap(),
                },
                [7; 32],
                Some([0xB1; 32]),
                1000,
            )
            .unwrap();
        state.observe_carrier(false, 1, Some(&Arc::downgrade(&erased)));
        let body = CircuitDataPayload {
            circuit_id: cid,
            seq: 1,
            ciphertext: vec![42; 1024],
        }
        .encode(CircuitCellBytes::new(1024).unwrap())
        .unwrap();
        let mut header = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitDatagram as u16,
        );
        header.set_priority(INTERACTIVE);
        header.body_len = body.len() as u32;
        let frame = veil_proto::codec::encode_frame(&header, &body);
        registry
            .send_to_on_carrier_result(&[0xB1; 32], frame.clone(), state.outbound_carrier(true))
            .unwrap();
        expected.push(frame);
    }
    let mut pipes = std::collections::HashSet::new();
    timeout(Duration::from_secs(2), async {
        for _ in 0..6 {
            let (pipe, frame) = received.recv().await.unwrap();
            assert!(
                pipes.insert(pipe),
                "different circuits used the same physical connection"
            );
            let index = expected
                .iter()
                .position(|e| *e == frame)
                .expect("original neutral frame");
            expected.swap_remove(index);
        }
    })
    .await
    .expect("all six circuit frames must reach actual independent children");
    assert_eq!(
        shared.0.load(Ordering::Relaxed),
        0,
        "shared return bypassed ready independent children"
    );
    assert!(expected.is_empty());
    stop_accept.send(()).unwrap();
    acceptor.await.unwrap();
    drop(remote_main);
    timeout(Duration::from_secs(2), job).await.unwrap().unwrap();
    stop_receivers.send(()).unwrap();
    receivers.await.unwrap();
    drop(registration);
}
