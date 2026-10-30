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
        first_hop_close_generation: 0,
        first_hop_registration: 1,
        relay_path: vec![[0x71; 32]],
        origin_circuit_id: 7,
        keys: vec![[0x25; 32]],
        next_seq: AtomicU32::new(last),
        confirmed: Arc::new(AtomicBool::new(true)),
        last_sent_unix: Default::default(),
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
    circuit.last_sent_unix.store(7, Ordering::Relaxed);
    for _ in 0..ReplayWindow::WINDOW + 2 {
        assert_eq!(send(), Err(DataCircuitSendError::QueueFull));
    }
    assert_eq!(circuit.last_sent_unix.load(Ordering::Relaxed), 7);
    let first = receive_seq(&mut rx);
    let second = receive_seq(&mut rx);
    assert_eq!(send(), Ok(()));
    assert!(circuit.last_sent_unix.load(Ordering::Relaxed) > 7);
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
    circuit.last_sent_unix.store(7, Ordering::Relaxed);
    let error = services.send_circuit_datagram_on_local_lane_detailed(
        &circuit,
        &vec![0; 2048],
        veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
    );
    let after = circuit.next_seq.load(Ordering::Relaxed);
    assert_eq!(circuit.last_sent_unix.load(Ordering::Relaxed), 7);
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

#[tokio::test]
async fn expired_or_unroutable_cells_do_not_renew_the_origin_idle_clock() {
    let (_dir, mut runtime, circuit, mut rx) = fixture().await;
    let services = runtime.access();
    circuit.last_sent_unix.store(7, Ordering::Relaxed);
    assert_eq!(
        services.send_circuit_datagram_on_local_lane_before(
            &circuit,
            b"expired",
            veil_proto::priority::INTERACTIVE,
            std::time::Instant::now() - std::time::Duration::from_secs(1),
        ),
        Ok(())
    );
    assert!(
        rx.try_recv().is_err(),
        "expired cell entered the source queue"
    );
    assert_eq!(circuit.last_sent_unix.load(Ordering::Relaxed), 7);
    services
        .session_tx_registry
        .write()
        .unwrap()
        .unregister(&circuit.first_hop);
    assert_eq!(
        services.send_circuit_cell_detailed(&circuit, b"unroutable"),
        Err(DataCircuitSendError::NoRelays)
    );
    assert_eq!(circuit.last_sent_unix.load(Ordering::Relaxed), 7);
    runtime.stop().await.unwrap();
}

async fn originated_fixture() -> (
    tempfile::TempDir,
    NodeRuntime,
    [u8; 32],
    veil_crypto::GeneratedKeyPair,
    veil_session::FrameOutbox,
) {
    use veil_anonymity::directory::{relay_directory_dht_key, sign_entry};
    use veil_types::SignatureAlgorithm;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut config = super::tests::runtime_config_with_metrics();
    config.peers.clear();
    config.global.meeting_points = veil_cfg::MeetingPoints::Only(Vec::new());
    config.anonymity.receive_anonymous = true;
    veil_cfg::save_config(&path, &config).unwrap();
    let runtime = NodeRuntime::start(&path, true).await.unwrap();
    let services = runtime.access();
    let key = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519);
    let public =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &key.public_key)
            .unwrap();
    let hop = *blake3::hash(&public).as_bytes();
    let xpk = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([3; 32]));
    services.dht.store_local(
        relay_directory_dht_key(&hop),
        sign_entry(
            hop,
            xpk.to_bytes(),
            1_000_000,
            1,
            &key.public_key,
            &key.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap(),
    );
    let outbox = services.session_tx_registry.write().unwrap().register(hop);
    (dir, runtime, hop, key, outbox)
}

#[tokio::test]
async fn active_origin_survives_creation_age_after_real_local_handoff() {
    use veil_anonymity::circuit_origin::OriginCircuitTable;
    for recoverable in [false, true] {
        let (_dir, mut runtime, hop, _key, mut outbox) = originated_fixture().await;
        let services = runtime.access();
        let (circuit, _inbound) = services.open_data_circuit(&[hop], b"live path").unwrap();
        outbox
            .try_recv()
            .expect("build reached the first-hop queue");
        let table = services.dispatcher.circuit_origin.as_ref().unwrap();
        let original = table.lookup(&hop, circuit.origin_circuit_id()).unwrap();
        original.mark_confirmed();
        // Change only the build clock. The real handle and origin retain any
        // shared activity witness installed by the production builder.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut aged = (*original).clone();
        aged.created_unix = now - OriginCircuitTable::DEFAULT_TTL_SECS - 1;
        assert!(table.insert(Arc::new(aged)));
        let sent = if recoverable {
            services.send_circuit_datagram_on_local_lane_detailed(
                &circuit,
                b"payload",
                veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
            )
        } else {
            services.send_circuit_cell_detailed(&circuit, b"payload")
        };
        assert_eq!(sent, Ok(()));
        outbox.try_recv().expect("data reached the first-hop queue");
        let removed = table.gc(now);
        let kept = table.lookup(&hop, circuit.origin_circuit_id()).is_some();
        // With no further local send, the state must still be collectable.
        table.gc(now + OriginCircuitTable::DEFAULT_TTL_SECS + 2);
        let expired = table.lookup(&hop, circuit.origin_circuit_id()).is_none();
        let expired_handle_unconfirmed = !circuit.confirmed.load(Ordering::Acquire);
        runtime.stop().await.unwrap();
        assert_eq!(removed, 0, "GC discarded an actively used origin");
        assert!(kept && expired);
        assert!(
            expired_handle_unconfirmed,
            "expired handle must trigger repair"
        );
    }
}

/// Real local admission failures must not accumulate paths that never reached
/// their first hop. Keep a live path throughout, exceed the real origin cap,
/// and require a new build to succeed as soon as the queue becomes usable.
async fn rejected_builds_release_state(kind: &str, failure: &str) {
    use veil_types::AnonOnionSendError;
    let (_dir, mut runtime, hop, key, mut outbox) = originated_fixture().await;
    let services = runtime.access();
    let (live, mut live_inbound) = services.open_data_circuit(&[hop], b"live path").unwrap();
    assert!(outbox.try_recv().is_ok(), "live path was not handed off");
    let table = services.dispatcher.circuit_origin.as_ref().unwrap();
    let before = table.len();
    let sinks_before = services.dispatcher.stream_recv.lock().unwrap().len();
    assert_eq!(before, 1, "fixture must contain exactly the live path");
    assert_eq!(sinks_before, 1);

    match failure {
        "full" => {
            let mut filled = false;
            for _ in 0..8192 {
                match services.send_relay_chain_frame(&hop, RelayChainMsg::CircuitBuild, b"fill") {
                    Ok(()) => {}
                    Err(veil_session::SendToError::Full) => {
                        filled = true;
                        break;
                    }
                    Err(other) => panic!("unexpected queue fill failure: {other:?}"),
                }
            }
            assert!(filled, "fixture never reached actual queue backpressure");
        }
        "closed" => outbox.close(),
        "missing" => {
            services
                .session_tx_registry
                .write()
                .unwrap()
                .unregister(&hop);
        }
        _ => unreachable!("unknown local failure fixture"),
    }
    let expected = match failure {
        "full" => veil_session::SendToError::Full,
        "closed" => veil_session::SendToError::Closed,
        "missing" => veil_session::SendToError::Missing,
        _ => unreachable!(),
    };
    assert_eq!(
        services.send_relay_chain_frame(&hop, RelayChainMsg::CircuitBuild, b"probe"),
        Err(expected)
    );
    let epoch = std::sync::atomic::AtomicU64::new(0);
    let build = || -> std::result::Result<(), AnonOnionSendError> {
        match kind {
            "data" => services.open_data_circuit(&[hop], b"new path").map(|_| ()),
            "service" | "reply" => services
                .build_onion_circuit_once(&[hop], [0x52; 16], &key, &epoch, kind == "reply")
                .map(|_| ()),
            _ => unreachable!("unknown circuit build kind"),
        }
    };
    let attempts = table.cap() + 1;
    for _ in 0..attempts {
        assert!(matches!(build(), Err(AnonOnionSendError::NoRelays)));
    }
    let after_rejection = table.len();
    let sinks_after_rejection = services.dispatcher.stream_recv.lock().unwrap().len();
    let live_kept = table.lookup(&hop, live.origin_circuit_id()).is_some()
        && services
            .dispatcher
            .stream_recv
            .lock()
            .unwrap()
            .contains_key(&live.origin_circuit_id());
    let live_receiver_kept = matches!(
        live_inbound.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    );
    if failure == "full" {
        while outbox.try_recv().is_ok() {}
    } else {
        outbox = services.session_tx_registry.write().unwrap().register(hop);
    }
    let recovered = build().is_ok();
    let mut accepted_builds = 0;
    while let Ok((_, frame)) = outbox.try_recv() {
        let header = veil_proto::codec::decode_header(&frame[..HEADER_SIZE]).unwrap();
        accepted_builds += usize::from(
            header.family == veil_proto::family::FrameFamily::RelayChain as u8
                && header.msg_type == RelayChainMsg::CircuitBuild as u16,
        );
    }
    let after_success = table.len();
    let sinks_after_success = services.dispatcher.stream_recv.lock().unwrap().len();
    runtime.stop().await.unwrap();
    println!(
        "build rollback {kind}/{failure}: attempts={attempts} origins={before}->{after_rejection}->{after_success} sinks={sinks_before}->{sinks_after_rejection}->{sinks_after_success} recovered={recovered} admitted={accepted_builds}"
    );
    assert!(
        recovered && accepted_builds == 1,
        "failed {kind}/{failure} builds prevented immediate recovery"
    );
    assert_eq!(
        after_rejection, before,
        "failed {kind}/{failure} build leaked origin state"
    );
    assert_eq!(
        sinks_after_rejection, sinks_before,
        "failed build leaked return sinks"
    );
    assert!(
        live_kept && live_receiver_kept,
        "rollback discarded the live path"
    );
    assert_eq!(
        after_success,
        before + 1,
        "successful build lost its origin state"
    );
    assert_eq!(
        sinks_after_success,
        sinks_before + usize::from(kind == "data")
    );
}

#[tokio::test]
async fn rejected_data_builds_do_not_exhaust_origin_capacity() {
    for failure in ["full", "closed", "missing"] {
        rejected_builds_release_state("data", failure).await;
    }
}

#[tokio::test]
async fn rejected_service_builds_do_not_exhaust_origin_capacity() {
    for failure in ["full", "closed", "missing"] {
        rejected_builds_release_state("service", failure).await;
    }
}

#[tokio::test]
async fn rejected_reply_builds_do_not_retain_unreachable_paths() {
    for failure in ["full", "closed", "missing"] {
        rejected_builds_release_state("reply", failure).await;
    }
}

/// Reconnecting to the same relay does not restore its old circuit mapping.
/// A live replacement TX queue must not make an obsolete handle look usable.
#[tokio::test]
async fn reconnected_session_rejects_old_circuit_before_local_handoff() {
    for recoverable in [false, true] {
        let (_dir, mut runtime, hop, _key, mut old_outbox) = originated_fixture().await;
        let services = runtime.access();
        let (old, _old_rx) = services
            .open_data_circuit(&[hop], b"old generation")
            .unwrap();
        old_outbox.try_recv().unwrap();
        services
            .session_close_generations
            .lock()
            .unwrap()
            .insert(hop, 1);
        let mut replacement = services.session_tx_registry.write().unwrap().register(hop);
        old.last_sent_unix.store(7, Ordering::Relaxed);
        let send = |c: &DataCircuit| {
            if recoverable {
                services.send_circuit_datagram_on_local_lane_detailed(
                    c,
                    b"payload",
                    veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
                )
            } else {
                services.send_circuit_cell_detailed(c, b"payload")
            }
        };
        // A delayed Built/probe echo cannot make an old session current.
        old.confirmed.store(true, Ordering::Relaxed);
        assert_eq!(old.first_hop_close_generation(), 0);
        assert!(!services.data_circuit_session_current(&old));
        let stale = send(&old);
        let stale_enqueued = replacement.try_recv().is_ok();
        let stale_seq = old.next_seq.load(Ordering::Relaxed);
        let stale_activity = old.last_sent_unix.load(Ordering::Relaxed);
        let (fresh, _fresh_rx) = services.open_data_circuit(&[hop], b"replacement").unwrap();
        replacement.try_recv().unwrap();
        assert_eq!(fresh.first_hop_close_generation(), 1);
        assert!(services.data_circuit_session_current(&fresh));
        let fresh_sent = send(&fresh);
        let fresh_enqueued = replacement.try_recv().is_ok();
        runtime.stop().await.unwrap();
        assert_eq!(stale, Err(DataCircuitSendError::NoRelays));
        assert!(
            !stale_enqueued,
            "obsolete circuit entered replacement session"
        );
        assert_eq!(stale_seq, 0, "obsolete circuit consumed a nonce");
        assert_eq!(stale_activity, 7, "obsolete circuit renewed its idle lease");
        assert_eq!(fresh_sent, Ok(()));
        assert!(
            fresh_enqueued,
            "replacement circuit could not use live session"
        );
    }
}

#[tokio::test]
async fn late_old_runner_exit_preserves_circuit_built_on_replacement_session() {
    for recoverable in [false, true] {
        let (_dir, mut runtime, hop, _key, _initial) = originated_fixture().await;
        let services = runtime.access();
        let mut old_tx = services
            .session_tx_registry
            .write()
            .unwrap()
            .register_owned(hop, [1; 32]);
        let (old, _old_rx) = services.open_data_circuit(&[hop], b"old owner").unwrap();
        old_tx.try_recv().unwrap();
        let mut fresh_tx = services
            .session_tx_registry
            .write()
            .unwrap()
            .register_owned(hop, [2; 32]);
        let (fresh, _fresh_rx) = services.open_data_circuit(&[hop], b"new owner").unwrap();
        fresh_tx.try_recv().unwrap();
        assert!(services.data_circuit_session_current(&fresh));
        assert!(!session_guard::release_session(
            session_guard::SessionRelease {
                session_tx_registry: &services.session_tx_registry,
                session_outbox: &services.session_outbox,
                session_close_generations: &services.session_close_generations,
                identity: &services.identity,
                dispatcher: &services.dispatcher,
                logger: &services.logger,
            },
            hop.into(),
            &[1; 32],
            false,
        ));
        let still_current = services.data_circuit_session_current(&fresh);
        let obsolete_current = services.data_circuit_session_current(&old);
        let result = if recoverable {
            services.send_circuit_datagram_on_local_lane_detailed(
                &fresh,
                b"payload",
                veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
            )
        } else {
            services.send_circuit_cell_detailed(&fresh, b"payload")
        };
        let admitted = fresh_tx.try_recv().is_ok();
        let before_close = fresh.next_seq.load(Ordering::Relaxed);
        drop(fresh_tx); // closed entry is unusable even before runner cleanup
        let closed_current = services.data_circuit_session_current(&fresh);
        let closed_send = services.send_circuit_cell_detailed(&fresh, b"after close");
        let after_close = fresh.next_seq.load(Ordering::Relaxed);
        runtime.stop().await.unwrap();
        assert!(
            still_current,
            "late old runner invalidated a circuit built on the live replacement"
        );
        assert!(
            !obsolete_current,
            "a replacement must still invalidate the old circuit"
        );
        assert_eq!(result, Ok(()));
        assert!(admitted);
        assert!(!closed_current);
        assert_eq!(closed_send, Err(DataCircuitSendError::NoRelays));
        assert_eq!(before_close, after_close, "closed entry consumed a nonce");
    }
}
