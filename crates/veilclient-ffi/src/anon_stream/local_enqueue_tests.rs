//! Real circuit setup and local outbox rejection, without a public network.
use super::*;
use veil_onion_stream::CellSender;

struct Fixture {
    _dir: tempfile::TempDir,
    runtime: veil_node_runtime::NodeRuntime,
    cells: CircuitCells,
    circuit: Arc<veil_node_runtime::DataCircuit>,
    hop: [u8; 32],
    _outbox: veil_session::FrameOutbox,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let mut config = veil_cfg::build_stub_config_with_ephemeral_identity(false).unwrap();
    // The deferred stub uses a shared identity. Independent fixtures need
    // distinct ids so the embedded-services map cannot cross-wire runtimes.
    config.identity = Some(
        tokio::task::spawn_blocking(|| {
            veil_cfg::identity_ops::IdentityUseCases::new(Default::default())
                .provision(veil_types::SignatureAlgorithm::Ed25519, None)
                .unwrap()
        })
        .await
        .unwrap(),
    );
    config.identity.as_mut().unwrap().role = veil_cfg::NodeRole::Leaf;
    config.global.meeting_points = veil_cfg::MeetingPoints::Only(Vec::new());
    config.anonymity.receive_anonymous = true;
    veil_cfg::save_config(&path, &config).unwrap();
    let runtime = veil_node_runtime::NodeRuntime::start(&path, true)
        .await
        .unwrap();
    let services = runtime.access();
    let (circuit, hop, outbox) = add_circuit(&services);
    let (in_tx, _in_rx) = mpsc::channel(4);
    let mut cells = try_open_circuit(
        services.local_node_id(),
        in_tx,
        CircuitMode::PublishedRendezvous,
    )
    .unwrap();
    assert!(Arc::ptr_eq(
        &services.session_tx_registry,
        &cells.services.session_tx_registry
    ));
    cells.data_pacer = Arc::new(StreamDataPacer::new(Duration::ZERO));
    Fixture {
        _dir: dir,
        runtime,
        cells,
        circuit,
        hop,
        _outbox: outbox,
    }
}

fn add_circuit(
    services: &veil_node_runtime::NodeServices,
) -> (
    Arc<veil_node_runtime::DataCircuit>,
    [u8; 32],
    veil_session::FrameOutbox,
) {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use veil_anonymity::directory::{relay_directory_dht_key, sign_entry};
    let key = veil_crypto::generate_keypair(veil_types::SignatureAlgorithm::Ed25519);
    let public = STANDARD.decode(&key.public_key).unwrap();
    let hop = *blake3::hash(&public).as_bytes();
    services.dht.store_local(
        relay_directory_dht_key(&hop),
        sign_entry(
            hop,
            [3; 32],
            1_000_000,
            1,
            &key.public_key,
            &key.private_key,
            veil_types::SignatureAlgorithm::Ed25519,
        )
        .unwrap(),
    );
    let outbox = services.session_tx_registry.write().unwrap().register(hop);
    let (circuit, _rx) = services
        .open_data_circuit(&[hop], b"private fixture")
        .unwrap();
    (Arc::new(circuit), hop, outbox)
}

fn route(circuit: &Arc<veil_node_runtime::DataCircuit>, sender: [u8; 32]) -> CircuitRoute {
    CircuitRoute {
        circuit: Arc::clone(circuit),
        rendezvous_node: Some(circuit.first_hop()),
        first_hop_close_generation: 0,
        peer_cookie: [0x42; COOKIE_LEN],
        envelope: CircuitEnvelope::LegacyClearSender {
            sender_node: sender,
        },
        stats: Some(Arc::new(CircuitRouteStats::new(Instant::now()))),
    }
}

fn entry(route: &CircuitRoute, streams: &[u32]) -> CircuitEntry {
    let now = Instant::now();
    CircuitEntry {
        circuit: Arc::clone(&route.circuit),
        rendezvous_node: route.rendezvous_node.unwrap(),
        first_hop_close_generation: route.first_hop_close_generation,
        peer_tag: [0x32; CIRCUIT_PEER_TAG_LEN],
        peer_cookie: route.peer_cookie,
        receiver_x25519_pk: [3; 32],
        opened_at: now,
        last_used: now,
        last_non_handshake: now,
        handshake_streams: streams.iter().copied().collect(),
        stats: Arc::clone(route.stats.as_ref().unwrap()),
    }
}

fn data_run(stream_id: u32, count: usize) -> std::collections::VecDeque<Vec<u8>> {
    (0..count)
        .map(|index| {
            let mut bytes = Vec::new();
            Frame::Data {
                stream_id,
                seq: 101 + index as u32 * 5,
                win: 8192,
                payload: &[index as u8; 5],
            }
            .encode_into(&mut bytes);
            bytes
        })
        .collect()
}

fn frames(stream_id: u32) -> Vec<Vec<u8>> {
    [
        Frame::Syn {
            stream_id,
            isn: 100,
            win: 8192,
        },
        Frame::SynAck {
            stream_id,
            isn: 500,
            win: 8192,
            ack: 101,
        },
        Frame::Ack {
            stream_id,
            ack: 101,
            win: 8192,
            sacks: Default::default(),
        },
        Frame::Fin {
            stream_id,
            seq: 101,
        },
        Frame::Data {
            stream_id,
            seq: 101,
            win: 8192,
            payload: b"first",
        },
        Frame::Data {
            stream_id,
            seq: 106,
            win: 8192,
            payload: b"second",
        },
    ]
    .into_iter()
    .map(|frame| {
        let mut bytes = Vec::new();
        frame.encode_into(&mut bytes);
        bytes
    })
    .collect()
}

async fn reject_without_handoff(stale_guard: bool) {
    let mut f = fixture().await;
    let destination = Addr {
        node: [0xb9; 32],
        app: [0xbc; 32],
    };
    if !stale_guard {
        // This mode skips the preflight stale guard. The real runtime enqueue
        // reports NoRelays, also covering a session closing after preflight.
        f.cells.mode = CircuitMode::ValidationMinRouting;
        f.cells
            .inbound_circuits
            .lock()
            .await
            .push(Arc::clone(&f.circuit));
    }
    f.cells
        .services
        .session_tx_registry
        .write()
        .unwrap()
        .unregister(&f.hop);
    let mut observed = Vec::new();
    for (index, encoded) in frames(71).into_iter().enumerate() {
        if stale_guard {
            let route = CircuitRoute {
                circuit: Arc::clone(&f.circuit),
                rendezvous_node: Some(f.hop),
                first_hop_close_generation: 0,
                peer_cookie: [0x42; COOKIE_LEN],
                envelope: CircuitEnvelope::LegacyClearSender {
                    sender_node: f.cells.me,
                },
                stats: None,
            };
            let class = if index == 2 {
                RouteClass::Ack
            } else {
                RouteClass::Bulk
            };
            f.cells
                .stream_routes
                .lock()
                .await
                .insert((destination.node, 71, class), route);
        }
        let expected = if index == 4 {
            frames(71).into_iter().skip(4).collect()
        } else {
            vec![encoded]
        };
        let mut pending: std::collections::VecDeque<_> = expected.clone().into();
        let result = f.cells.send_many(destination, &mut pending).await;
        observed.push((result.err().map(|error| error.kind()), pending, expected));
    }
    f.runtime.stop().await.unwrap();
    for (error, pending, expected) in observed {
        assert_eq!(
            error,
            Some(io::ErrorKind::WouldBlock),
            "unaccepted cells reported as delivered"
        );
        assert_eq!(
            pending.into_iter().collect::<Vec<_>>(),
            expected,
            "unaccepted cells discarded"
        );
    }
}

#[tokio::test]
async fn stale_stream_route_retains_controls_and_data_runs() {
    reject_without_handoff(true).await;
}

#[tokio::test]
async fn rejected_stream_enqueue_retains_controls_and_data_runs() {
    reject_without_handoff(false).await;
}

#[tokio::test]
async fn healthy_stream_enqueue_accepts_each_cell_once() {
    let mut f = fixture().await;
    f.cells.mode = CircuitMode::ValidationMinRouting;
    f.cells
        .inbound_circuits
        .lock()
        .await
        .push(Arc::clone(&f.circuit));
    while f._outbox.try_recv().is_ok() {}
    let mut pending: std::collections::VecDeque<_> = frames(71).into();
    let result = f
        .cells
        .send_many(
            Addr {
                node: [0xb9; 32],
                app: [0xbc; 32],
            },
            &mut pending,
        )
        .await;
    let mut count = 0;
    while f._outbox.try_recv().is_ok() {
        count += 1;
    }
    f.runtime.stop().await.unwrap();
    result.unwrap();
    assert!(pending.is_empty());
    assert_eq!(count, 6);
}

#[tokio::test]
async fn queue_full_keeps_unsent_tail_and_accounts_for_accepted_prefix() {
    use veil_node_runtime::DataCircuitSendError;
    let mut f = fixture().await;
    let route = route(&f.circuit, f.cells.me);
    while f._outbox.try_recv().is_ok() {}
    let filler = frames(71).pop().unwrap();
    let mut filled = false;
    for _ in 0..65536 {
        match f
            .cells
            .send_one_cell_on_route(&route.peer_cookie, &route, &filler)
        {
            Ok(()) => (),
            Err(DataCircuitSendError::QueueFull) => {
                filled = true;
                break;
            }
            error => panic!("unexpected local error: {error:?}"),
        }
    }
    assert!(filled, "bounded outbox never filled");
    // The only receiver is held by this fixture. Free exactly two slots.
    f._outbox.try_recv().unwrap();
    f._outbox.try_recv().unwrap();
    let mut pending = data_run(71, 5);
    let expected = pending.iter().skip(2).cloned().collect::<Vec<_>>();
    let result = f
        .cells
        .send_chunk_on_route([0xb9; 32], &route, 5, &mut pending);
    let (accepted, error) = result.unwrap();
    let retry_error = f
        .cells
        .stream_enqueue_error([0xb9; 32], &route, error.unwrap())
        .await;
    let cooled = f.cells.route_cooldowns.lock().unwrap().contains_key(&f.hop);
    f.runtime.stop().await.unwrap();
    assert_eq!(accepted, 2);
    assert_eq!(error, Some(DataCircuitSendError::QueueFull));
    assert_eq!(retry_error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(pending.into_iter().collect::<Vec<_>>(), expected);
    assert!(
        !cooled,
        "queue saturation must not quarantine a working route"
    );
}

#[tokio::test]
async fn striped_route_failure_preserves_nonprefix_pending_cells_and_suffix() {
    let mut f = fixture().await;
    let primary = route(&f.circuit, f.cells.me);
    let (alternate, _, mut outbox) = add_circuit(&f.cells.services);
    let alternate = route(&alternate, f.cells.me);
    while outbox.try_recv().is_ok() {}
    f.cells
        .services
        .session_tx_registry
        .write()
        .unwrap()
        .unregister(&f.hop);
    // The actual source-credit budget intentionally admits just two cells
    // without a session consumer. Keep this case below that real bound.
    let mut pending = data_run(71, 4);
    let suffix = frames(99)[2].clone();
    let expected = pending
        .iter()
        .step_by(2)
        .cloned()
        .chain([suffix.clone()])
        .collect::<Vec<_>>();
    pending.push_back(suffix);
    let error = f
        .cells
        .send_striped_run(
            Addr {
                node: [0xb9; 32],
                app: [0xbc; 32],
            },
            71,
            &primary,
            std::slice::from_ref(&alternate),
            4,
            &mut pending,
        )
        .await
        .unwrap_err();
    let mut accepted = 0;
    while outbox.try_recv().is_ok() {
        accepted += 1;
    }
    let primary_failed = f.cells.route_cooldowns.lock().unwrap().contains_key(&f.hop);
    let alternate_cooled = f
        .cells
        .route_cooldowns
        .lock()
        .unwrap()
        .contains_key(&alternate.circuit.first_hop());
    let snapshot = alternate.stats.as_ref().unwrap().snapshot();
    f.runtime.stop().await.unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(pending.into_iter().collect::<Vec<_>>(), expected);
    assert_eq!(accepted, 2);
    assert_eq!(snapshot.data_cells, 2);
    assert!(primary_failed && !alternate_cooled);
}

#[tokio::test]
async fn striped_missing_route_then_full_queue_keeps_original_pending_order() {
    use veil_node_runtime::DataCircuitSendError;
    let mut f = fixture().await;
    let primary = route(&f.circuit, f.cells.me);
    let (alternate, _, _outbox) = add_circuit(&f.cells.services);
    let alternate = route(&alternate, f.cells.me);
    let filler = frames(71).pop().unwrap();
    let mut filled = false;
    for _ in 0..65536 {
        match f
            .cells
            .send_one_cell_on_route(&alternate.peer_cookie, &alternate, &filler)
        {
            Ok(()) => (),
            Err(DataCircuitSendError::QueueFull) => {
                filled = true;
                break;
            }
            result => panic!("unexpected local result: {result:?}"),
        }
    }
    assert!(filled);
    f.cells
        .services
        .session_tx_registry
        .write()
        .unwrap()
        .unregister(&f.hop);
    let mut pending = data_run(71, 6);
    pending.push_back(frames(99)[2].clone());
    let expected = pending.clone();
    let error = f
        .cells
        .send_striped_run(
            Addr {
                node: [0xb9; 32],
                app: [0xbc; 32],
            },
            71,
            &primary,
            std::slice::from_ref(&alternate),
            6,
            &mut pending,
        )
        .await
        .unwrap_err();
    let alternate_cooled = f
        .cells
        .route_cooldowns
        .lock()
        .unwrap()
        .contains_key(&alternate.circuit.first_hop());
    f.runtime.stop().await.unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(
        pending, expected,
        "earlier rejected cells must precede the unsent tail"
    );
    assert!(!alternate_cooled);
}

#[tokio::test]
async fn oversized_striped_cell_is_fatal_without_cooling_the_route() {
    use veil_node_runtime::DataCircuitSendError;
    let mut f = fixture().await;
    let route = route(&f.circuit, f.cells.me);
    let result = f.cells.send_one_cell_on_route(
        &route.peer_cookie,
        &route,
        &vec![0x3a; circuit_env_max() + 1],
    );
    let error = f
        .cells
        .stream_enqueue_error([0xb9; 32], &route, result.unwrap_err())
        .await;
    let cooled = f.cells.route_cooldowns.lock().unwrap().contains_key(&f.hop);
    f.runtime.stop().await.unwrap();
    assert_eq!(result, Err(DataCircuitSendError::PayloadTooLarge));
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(!cooled);
}

#[tokio::test]
async fn stale_primary_ack_completes_when_an_alternate_actually_accepts_it() {
    let mut f = fixture().await;
    let destination = Addr {
        node: [0xb9; 32],
        app: [0xbc; 32],
    };
    let primary = route(&f.circuit, f.cells.me);
    let (alternate, hop, mut outbox) = add_circuit(&f.cells.services);
    while outbox.try_recv().is_ok() {}
    let now = Instant::now();
    f.cells.outbound_circuits.lock().await.insert(
        destination.node,
        vec![CircuitEntry {
            circuit: alternate,
            rendezvous_node: hop,
            first_hop_close_generation: 0,
            peer_tag: [0x32; CIRCUIT_PEER_TAG_LEN],
            peer_cookie: [0x35; COOKIE_LEN],
            receiver_x25519_pk: [3; 32],
            opened_at: now,
            last_used: now,
            last_non_handshake: now,
            handshake_streams: HashSet::new(),
            stats: Arc::new(CircuitRouteStats::new(now)),
        }],
    );
    f.cells.ack_redundancy = 2;
    f.cells
        .stream_routes
        .lock()
        .await
        .insert((destination.node, 71, RouteClass::Ack), primary);
    f.cells
        .services
        .session_tx_registry
        .write()
        .unwrap()
        .unregister(&f.hop);
    let mut pending = std::collections::VecDeque::from([frames(71)[2].clone()]);
    let result = f.cells.send_many(destination, &mut pending).await;
    let copies = f.cells.ack_dup_sent.load(Ordering::Relaxed);
    let mut count = 0;
    while outbox.try_recv().is_ok() {
        count += 1;
    }
    f.runtime.stop().await.unwrap();
    result.unwrap();
    assert!(pending.is_empty());
    assert_eq!(copies, 1);
    assert_eq!(count, 1);
}

#[tokio::test]
async fn handshake_timeout_remaps_only_the_unconfirmed_stream_without_retiring_pool() {
    let mut f = fixture().await;
    let destination = Addr {
        node: [0xb9; 32],
        app: [0xbc; 32],
    };
    let mut primary = route(&f.circuit, f.cells.me);
    primary.envelope = CircuitEnvelope::ProtectedIntro {
        peer_tag: [0x32; CIRCUIT_PEER_TAG_LEN],
        receiver_x25519_pk: [3; 32],
    };
    let (alternate, _, _outbox) = add_circuit(&f.cells.services);
    let alternate = route(&alternate, f.cells.me);
    primary.stats.as_ref().unwrap().record_stream_open();
    primary.stats.as_ref().unwrap().record_stream_open();
    f.cells.outbound_circuits.lock().await.insert(
        destination.node,
        vec![entry(&primary, &[71, 99]), entry(&alternate, &[])],
    );
    for sid in [71, 99] {
        f.cells
            .stream_routes
            .lock()
            .await
            .insert((destination.node, sid, RouteClass::Bulk), primary.clone());
        f.cells
            .stream_routes
            .lock()
            .await
            .insert((destination.node, sid, RouteClass::Ack), primary.clone());
    }
    f.cells.on_stream_handshake_rto(destination, 71, 1).await;
    let routes = f.cells.stream_routes.lock().await;
    let changed = Arc::ptr_eq(
        &routes[&(destination.node, 71, RouteClass::Bulk)].circuit,
        &alternate.circuit,
    );
    let sibling_preserved = Arc::ptr_eq(
        &routes[&(destination.node, 99, RouteClass::Bulk)].circuit,
        &primary.circuit,
    );
    let ack_changed = Arc::ptr_eq(
        &routes[&(destination.node, 71, RouteClass::Ack)].circuit,
        &alternate.circuit,
    );
    let sibling_ack_preserved = Arc::ptr_eq(
        &routes[&(destination.node, 99, RouteClass::Ack)].circuit,
        &primary.circuit,
    );
    drop(routes);
    let pool = f.cells.outbound_circuits.lock().await;
    let entries = &pool[&destination.node];
    let pool_len = entries.len();
    let old_membership = entries[0].handshake_streams.clone();
    let new_membership = entries[1].handshake_streams.clone();
    drop(pool);
    let old_active = primary.stats.as_ref().unwrap().active_streams();
    let new_active = alternate.stats.as_ref().unwrap().active_streams();
    let cooled = !f.cells.route_cooldowns.lock().unwrap().is_empty()
        || !f.cells.first_hop_cooldowns.lock().unwrap().is_empty();
    f.runtime.stop().await.unwrap();
    assert!(changed, "handshake retry remains pinned to the silent path");
    assert!(sibling_preserved);
    assert!(ack_changed && sibling_ack_preserved);
    assert_eq!(pool_len, 2);
    assert_eq!(old_membership, HashSet::from([99]));
    assert_eq!(new_membership, HashSet::from([71]));
    assert_eq!((old_active, new_active), (1, 1));
    assert!(
        !cooled,
        "one handshake timeout must not quarantine shared circuits"
    );
}

#[tokio::test]
async fn handshake_timeout_keeps_the_only_usable_route() {
    for unavailable in ["absent", "closed", "cooled", "at_limit"] {
        let mut f = fixture().await;
        let destination = Addr {
            node: [0xb9; 32],
            app: [0xbc; 32],
        };
        let primary = route(&f.circuit, f.cells.me);
        let mut entries = vec![entry(&primary, &[71])];
        let mut alternate_outbox = None;
        if unavailable != "absent" {
            let (alternate, hop, outbox) = add_circuit(&f.cells.services);
            alternate_outbox = Some(outbox);
            let alternate = route(&alternate, f.cells.me);
            match unavailable {
                "closed" => f
                    .cells
                    .services
                    .session_tx_registry
                    .write()
                    .unwrap()
                    .unregister(&hop),
                "cooled" => {
                    f.cells
                        .route_cooldowns
                        .lock()
                        .unwrap()
                        .insert(hop, Instant::now() + Duration::from_secs(60));
                }
                "at_limit" => {
                    f.cells.bulk_route_active_limit = 1;
                    alternate.stats.as_ref().unwrap().record_stream_open();
                }
                _ => unreachable!(),
            }
            entries.push(entry(&alternate, &[]));
        }
        f.cells
            .outbound_circuits
            .lock()
            .await
            .insert(destination.node, entries);
        f.cells
            .stream_routes
            .lock()
            .await
            .insert((destination.node, 71, RouteClass::Bulk), primary.clone());
        f.cells.on_stream_handshake_rto(destination, 71, 1).await;
        let routes = f.cells.stream_routes.lock().await;
        let kept = Arc::ptr_eq(
            &routes[&(destination.node, 71, RouteClass::Bulk)].circuit,
            &primary.circuit,
        );
        drop(routes);
        f.runtime.stop().await.unwrap();
        drop(alternate_outbox);
        assert!(
            kept,
            "lost the only usable route when alternative was {unavailable}"
        );
    }
}

#[tokio::test]
async fn data_no_progress_really_changes_the_sticky_route() {
    let mut f = fixture().await;
    let destination = Addr {
        node: [0xb9; 32],
        app: [0xbc; 32],
    };
    let mut primary = route(&f.circuit, f.cells.me);
    primary.envelope = CircuitEnvelope::ProtectedIntro {
        peer_tag: [0x32; CIRCUIT_PEER_TAG_LEN],
        receiver_x25519_pk: [3; 32],
    };
    let (alternate, _, _outbox) = add_circuit(&f.cells.services);
    let alternate = route(&alternate, f.cells.me);
    primary.stats.as_ref().unwrap().record_stream_open();
    f.cells.outbound_circuits.lock().await.insert(
        destination.node,
        vec![entry(&primary, &[71]), entry(&alternate, &[])],
    );
    f.cells
        .stream_routes
        .lock()
        .await
        .insert((destination.node, 71, RouteClass::Bulk), primary.clone());
    f.cells.on_stream_data_rto(destination, 71, 2, 100).await;
    let selected = f
        .cells
        .circuit_for(destination.node, Some(71), RouteClass::Bulk, false)
        .await
        .unwrap()
        .unwrap();
    let changed = Arc::ptr_eq(&selected.circuit, &alternate.circuit);
    let cooled = !f.cells.route_cooldowns.lock().unwrap().is_empty();
    f.runtime.stop().await.unwrap();
    assert!(
        changed,
        "removed cache pin was immediately restored by handshake membership"
    );
    assert!(!cooled);
}

#[tokio::test]
async fn real_mux_handshake_retry_reaches_a_working_pooled_route() {
    use std::sync::atomic::AtomicBool;
    use veil_onion_stream::{Config, End, StreamMux};
    struct Sender {
        me: Addr,
        backend: Option<HubCells>,
        primary: Option<CircuitRoute>,
        first_syn: AtomicBool,
        wire: mpsc::Sender<(Addr, Vec<u8>)>,
        retries: AtomicU64,
        closed: tokio::sync::Notify,
    }
    impl CellSender for Sender {
        async fn send(&self, dst: Addr, cell: Vec<u8>) -> io::Result<()> {
            if let Some(HubCells::Circuit(backend)) = &self.backend {
                if let Some(Frame::Syn { stream_id, .. }) = Frame::decode(&cell) {
                    let primary = self.primary.as_ref().unwrap();
                    if !self.first_syn.swap(true, Ordering::Relaxed) {
                        primary.stats.as_ref().unwrap().record_stream_open();
                        backend
                            .stream_routes
                            .lock()
                            .await
                            .insert((dst.node, stream_id, RouteClass::Bulk), primary.clone());
                        backend
                            .outbound_circuits
                            .lock()
                            .await
                            .get_mut(&dst.node)
                            .unwrap()[0]
                            .note_handshake_stream(stream_id);
                    }
                }
                backend.send(dst, cell.clone()).await?;
                if let Some(Frame::Syn { stream_id, .. }) = Frame::decode(&cell) {
                    let routes = backend.stream_routes.lock().await;
                    if Arc::ptr_eq(
                        &routes[&(dst.node, stream_id, RouteClass::Bulk)].circuit,
                        &self.primary.as_ref().unwrap().circuit,
                    ) {
                        // An actually accepted local SYN is lost on the first
                        // network path. Do not fake a local enqueue rejection.
                        return Ok(());
                    }
                }
            }
            self.wire
                .try_send((self.me, cell))
                .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "controlled wire full"))
        }
        async fn on_stream_handshake_rto(&self, dst: Addr, stream_id: u32, retries: u32) {
            self.retries.fetch_add(1, Ordering::Relaxed);
            if let Some(backend) = &self.backend {
                backend
                    .on_stream_handshake_rto(dst, stream_id, retries)
                    .await;
            }
        }
        async fn on_stream_closed(&self, dst: Addr, stream_id: u32, end: End) {
            if let Some(backend) = &self.backend {
                backend.on_stream_closed(dst, stream_id, end).await;
            }
            self.closed.notify_one();
        }
    }
    let mut f = fixture().await;
    let a = Addr {
        node: f.cells.me,
        app: [0xab; 32],
    };
    let b = Addr {
        node: [0xb9; 32],
        app: [0xbc; 32],
    };
    let primary = route(&f.circuit, f.cells.me);
    let (alternate, _, _alternate_outbox) = add_circuit(&f.cells.services);
    let alternate = route(&alternate, f.cells.me);
    f.cells
        .outbound_circuits
        .lock()
        .await
        .insert(b.node, vec![entry(&primary, &[]), entry(&alternate, &[])]);
    let (a_tx, a_rx) = mpsc::channel(64);
    let (b_tx, b_rx) = mpsc::channel(64);
    let forward = Arc::new(Sender {
        me: a,
        backend: Some(HubCells::Circuit(Box::new(f.cells))),
        primary: Some(primary),
        first_syn: AtomicBool::new(false),
        wire: b_tx,
        retries: AtomicU64::new(0),
        closed: Default::default(),
    });
    let backward = Arc::new(Sender {
        me: b,
        backend: None,
        primary: None,
        first_syn: AtomicBool::new(false),
        wire: a_tx,
        retries: AtomicU64::new(0),
        closed: Default::default(),
    });
    let cfg = Config {
        handshake_rto_ms: 50,
        ..Config::default()
    };
    let mux_a = StreamMux::new(a.node, Arc::clone(&forward), a_rx, cfg);
    let mux_b = StreamMux::new(b.node, Arc::clone(&backward), b_rx, cfg);
    let mut outgoing = mux_a.open(b);
    outgoing.write_all(b"manifest request").await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        let (mut incoming, _) = mux_b.accept().await.unwrap();
        let mut request = [0; 16];
        let mut got = 0;
        while got < request.len() {
            let n = incoming.read(&mut request[got..]).await.unwrap();
            assert!(n > 0);
            got += n;
        }
        assert_eq!(&request, b"manifest request");
        incoming.write_all(b"manifest").await.unwrap();
        let mut reply = [0; 8];
        let mut got = 0;
        while got < reply.len() {
            let n = outgoing.read(&mut reply[got..]).await.unwrap();
            assert!(n > 0);
            got += n;
        }
        assert_eq!(&reply, b"manifest");
        incoming
            .reset(veil_onion_stream::wire::reset_reason::APP)
            .await;
    })
    .await;
    outgoing
        .reset(veil_onion_stream::wire::reset_reason::APP)
        .await;
    let closed = tokio::time::timeout(Duration::from_secs(1), forward.closed.notified()).await;
    f.runtime.stop().await.unwrap();
    assert!(closed.is_ok());
    assert!(
        forward.retries.load(Ordering::Relaxed) > 0,
        "real driver did not report its handshake timeout"
    );
    assert!(
        result.is_ok(),
        "lost SYN stayed pinned despite a working pooled circuit"
    );
}

#[tokio::test]
async fn stream_recovery_never_switches_receiver_cookie_or_key() {
    for data_phase in [false, true] {
        for changed in ["cookie", "key"] {
            let mut f = fixture().await;
            let destination = Addr {
                node: [0xb9; 32],
                app: [0xbc; 32],
            };
            let mut primary = route(&f.circuit, f.cells.me);
            primary.envelope = CircuitEnvelope::ProtectedIntro {
                peer_tag: [0x32; CIRCUIT_PEER_TAG_LEN],
                receiver_x25519_pk: [3; 32],
            };
            primary.stats.as_ref().unwrap().record_stream_open();
            let (alternate, _, _outbox) = add_circuit(&f.cells.services);
            let alternate = route(&alternate, f.cells.me);
            let mut candidate = entry(&alternate, &[]);
            if changed == "cookie" {
                candidate.peer_cookie[0] ^= 1;
            } else {
                candidate.receiver_x25519_pk[0] ^= 1;
            }
            f.cells
                .outbound_circuits
                .lock()
                .await
                .insert(destination.node, vec![entry(&primary, &[71]), candidate]);
            f.cells
                .stream_routes
                .lock()
                .await
                .insert((destination.node, 71, RouteClass::Bulk), primary.clone());
            if data_phase {
                f.cells.on_stream_data_rto(destination, 71, 2, 100).await;
            } else {
                f.cells.on_stream_handshake_rto(destination, 71, 1).await;
            }
            let selected = f
                .cells
                .circuit_for(destination.node, Some(71), RouteClass::Bulk, false)
                .await
                .unwrap()
                .unwrap();
            let kept = Arc::ptr_eq(&selected.circuit, &primary.circuit);
            f.runtime.stop().await.unwrap();
            assert!(
                kept,
                "recovery changed receiver {changed}; data_phase={data_phase}"
            );
        }
    }
}
