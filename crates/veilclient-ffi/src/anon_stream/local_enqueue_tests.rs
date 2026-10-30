//! Real circuit setup and local outbox rejection, without a public network.
use super::*;
use veil_onion_stream::CellSender;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use veil_anonymity::rendezvous::{rendezvous_ad_dht_key_at, sign_rendezvous_ad_v5};
async fn advertised_receiver(f: &Fixture) -> [u8; 32] {
    advertised_receiver_at_relays(f, &[f.hop]).await
}

async fn advertised_receiver_at_relays(f: &Fixture, relays: &[[u8; 32]]) -> [u8; 32] {
    let key = veil_crypto::generate_keypair(veil_types::SignatureAlgorithm::Ed25519);
    let receiver = *blake3::hash(&STANDARD.decode(&key.public_key).unwrap()).as_bytes();
    let now = veil_util::unix_secs_now_u64();
    for (index, relay) in relays.iter().enumerate() {
        let ad = sign_rendezvous_ad_v5(
            receiver,
            *relay,
            [0x52; COOKIE_LEN],
            [0x33; 32],
            now,
            now + 3600,
            &[],
            &[],
            &[],
            0,
            &[],
            &key.public_key,
            &key.private_key,
            veil_types::SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        f.cells
            .services
            .dht
            .store_local(rendezvous_ad_dht_key_at(&receiver, index as u8), ad);
    }
    let ads = f
        .cells
        .services
        .resolve_stream_rendezvous_ads(receiver)
        .await
        .unwrap();
    assert!(ads.iter().any(|ad| ad.auth_cookie == [0x52; COOKIE_LEN]));
    assert!(
        relays
            .iter()
            .all(|relay| ads.iter().any(|ad| ad.rendezvous_node_id == *relay))
    );
    receiver
}

/// A throughput shed needs a DIFFERENT rendezvous. Repeated DATA with only
/// the already represented relay must not construct another same-R path.
#[tokio::test]
async fn slow_route_expansion_only_constructs_missing_rendezvous() {
    const CHILD: &str = "VEIL_TEST_SLOW_EXPANSION_CHILD";
    if let Ok(mode) = std::env::var(CHILD) {
        let mut f = fixture().await;
        let relays = if matches!(mode.as_str(), "new-relay" | "cooled-new-relay") {
            vec![f.hop, [0x91; 32]]
        } else {
            vec![f.hop]
        };
        let receiver = advertised_receiver_at_relays(&f, &relays).await;
        if mode == "cooled-new-relay" {
            mark_rendezvous_cooldown(
                &f.cells.route_cooldowns,
                [0x91; 32],
                Duration::from_secs(60),
            );
        }
        f.circuit.confirmed_flag().store(true, Ordering::Relaxed);
        let mut primary = protected_route(&f.circuit, f.cells.me);
        primary.peer_cookie = [0x52; COOKIE_LEN];
        primary.envelope = CircuitEnvelope::ProtectedIntro {
            peer_tag: [0x32; CIRCUIT_PEER_TAG_LEN],
            receiver_x25519_pk: [0x33; 32],
        };
        let stats = primary.stats.as_ref().unwrap();
        stats.record_stream_open();
        stats
            .slow_windows
            .store(CIRCUIT_ROUTE_SHED_SLOW_WINDOWS, Ordering::Relaxed);
        stats.slow_mark_expiry_ms.store(60_000, Ordering::Relaxed);
        let mut original = entry(&primary, &[71]);
        original.receiver_x25519_pk = [0x33; 32];
        if mode != "pinned-only" {
            f.cells
                .outbound_circuits
                .lock()
                .await
                .insert(receiver, vec![original]);
        }
        f.cells
            .stream_routes
            .lock()
            .await
            .insert((receiver, 71, RouteClass::Bulk), primary.clone());
        let mut alternative_outbox = None;
        let alternative = if mode == "ready-alternative" {
            let (alternative, _, outbox) = add_circuit(&f.cells.services);
            alternative.confirmed_flag().store(true, Ordering::Relaxed);
            alternative_outbox = Some(outbox);
            let mut other = protected_route(&alternative, f.cells.me);
            other.peer_cookie = primary.peer_cookie;
            other.envelope = primary.envelope;
            let mut other_entry = entry(&other, &[]);
            other_entry.receiver_x25519_pk = [0x33; 32];
            f.cells
                .outbound_circuits
                .lock()
                .await
                .get_mut(&receiver)
                .unwrap()
                .push(other_entry);
            Some(other)
        } else {
            None
        };
        async fn finish(cells: &CircuitCells, receiver: [u8; 32]) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while cells.outbound_opening.lock().await.contains_key(&receiver) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("expansion did not finish");
        }
        for index in 0..16 {
            let current = f
                .cells
                .stream_routes
                .lock()
                .await
                .get(&(receiver, 71, RouteClass::Bulk))
                .unwrap()
                .clone();
            f.cells
                .maybe_shed_slow_bulk_route(receiver, 71, &current)
                .await;
            if index == 0 && matches!(mode.as_str(), "overlap-warm" | "overlap-repair") {
                assert!(
                    f.cells
                        .outbound_opening
                        .lock()
                        .await
                        .contains_key(&receiver)
                );
                if mode == "overlap-warm" {
                    f.cells.warm_outbound(receiver).await;
                } else {
                    f.cells
                        .ensure_outbound_opening(receiver, RouteClass::Bulk)
                        .await;
                }
            }
            finish(&f.cells, receiver).await;
        }
        if matches!(mode.as_str(), "later-same" | "cooled-new-relay") {
            tokio::time::sleep(CIRCUIT_OPEN_FAILURE_RETRY + Duration::from_millis(50)).await;
            f.cells
                .maybe_shed_slow_bulk_route(receiver, 71, &primary)
                .await;
            finish(&f.cells, receiver).await;
        }
        if mode == "repair" {
            f.cells
                .ensure_outbound_opening(receiver, RouteClass::Bulk)
                .await;
            finish(&f.cells, receiver).await;
        } else if mode == "warm" {
            f.cells.warm_outbound(receiver).await;
            finish(&f.cells, receiver).await;
        }
        let selected = f
            .cells
            .stream_routes
            .lock()
            .await
            .get(&(receiver, 71, RouteClass::Bulk))
            .unwrap()
            .clone();
        if let Some(other) = alternative {
            assert!(Arc::ptr_eq(&selected.circuit, &other.circuit));
            assert_eq!(stats.active_streams(), 0);
            assert_eq!(other.stats.as_ref().unwrap().active_streams(), 1);
            assert!(
                f.cells
                    .bulk_shed_marks
                    .lock()
                    .unwrap()
                    .contains_key(&receiver)
            );
        } else {
            assert!(Arc::ptr_eq(&selected.circuit, &primary.circuit));
            assert_eq!(stats.active_streams(), 1);
            assert!(
                !f.cells
                    .bulk_shed_marks
                    .lock()
                    .unwrap()
                    .contains_key(&receiver)
            );
        }
        f.runtime.stop().await.unwrap();
        drop(alternative_outbox);
        assert_eq!(crate::veil_debug_flush_console_logs(2000), 0);
        return;
    }
    for (mode, expected_candidates, expected_discovery_passes) in [
        ("same-relay", 0, 1),
        ("later-same", 0, 2),
        ("pinned-only", 0, 1),
        ("ready-alternative", 0, 1),
        ("new-relay", 1, 1),
        ("cooled-new-relay", 0, 2),
        ("repair", 1, 2),
        ("warm", 1, 2),
        ("overlap-warm", 1, 1),
        ("overlap-repair", 1, 1),
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "anon_stream::local_enqueue_tests::slow_route_expansion_only_constructs_missing_rendezvous", "--nocapture"])
            .env(CHILD, mode).output().unwrap();
        assert!(
            output.status.success(),
            "child failed: {mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let candidates = String::from_utf8_lossy(&output.stderr)
            .lines()
            .filter(|line| {
                line.contains("outbound R=")
                    && line.contains("open failed after ")
                    && line.contains("NoRelays")
            })
            .count();
        assert_eq!(
            candidates, expected_candidates,
            "unnecessary construction or missing expansion: {mode}"
        );
        // Count completed ad resolution/ranking passes as well as actual
        // construction. A permanently suppressed probe would hide future ads;
        // an unbounded no-op probe would still run on every DATA cell.
        let discovery_passes = String::from_utf8_lossy(&output.stderr)
            .lines()
            .filter(|line| line.contains("outbound rendezvous rank for "))
            .count();
        assert_eq!(
            discovery_passes, expected_discovery_passes,
            "discovery cadence or re-probe failed: {mode}"
        );
    }
}

/// A warm request must not reconstruct a matching, usable path. The fixture
/// supplies a real signed receiver ad and live first-hop session; attempting a
/// NEW path still fails NoRelays because there is no complete two-hop route.
/// Count those real construction failures in an isolated diagnostic process.
#[tokio::test]
async fn warming_ready_pool_reuses_routes_but_preserves_repair() {
    const CHILD: &str = "VEIL_TEST_READY_POOL_WARM_CHILD";
    if let Ok(mode) = std::env::var(CHILD) {
        let mut f = fixture().await;
        let receiver = advertised_receiver(&f).await;
        f.circuit.confirmed_flag().store(true, Ordering::Relaxed);
        let primary = route(&f.circuit, f.cells.me);
        let mut ready = entry(&primary, &[71]);
        ready.peer_cookie = [0x52; COOKIE_LEN];
        ready.receiver_x25519_pk = [0x33; 32];
        match mode.as_str() {
            "unconfirmed" => f.circuit.confirmed_flag().store(false, Ordering::Relaxed),
            "cookie" => ready.peer_cookie = [0x53; COOKIE_LEN],
            "key" => ready.receiver_x25519_pk = [0x34; 32],
            "generation" => ready.first_hop_close_generation += 1,
            "dead" => {
                f.cells
                    .services
                    .session_tx_registry
                    .write()
                    .unwrap()
                    .unregister(&f.hop);
            }
            "cooled-relay" => {
                mark_rendezvous_cooldown(&f.cells.route_cooldowns, f.hop, Duration::from_secs(60))
            }
            "cooled-hop" => mark_first_hop_cooldown(
                &f.cells.first_hop_cooldowns,
                f.hop,
                Duration::from_secs(60),
            ),
            "slow" => ready
                .stats
                .slow_mark_expiry_ms
                .store(60_000, Ordering::Relaxed),
            "quiet" | "busy" | "recent-data" => {
                ready.opened_at -= CIRCUIT_HANDSHAKE_REOPEN_AFTER + Duration::from_secs(1);
                ready.last_non_handshake = ready.opened_at;
                if mode == "busy" {
                    ready.stats.record_stream_open();
                } else if mode == "recent-data" {
                    ready.last_non_handshake = Instant::now();
                }
            }
            _ => {}
        }
        if !matches!(mode.as_str(), "empty" | "cold-overlap") {
            f.cells
                .outbound_circuits
                .lock()
                .await
                .insert(receiver, vec![ready]);
        }
        // Coalesce a repair with a warm opener that is blocked on the pool.
        // It must still perform a fresh construction, even if the warm pass
        // finds a reusable route after the lock is released.
        let pool_owners = Arc::strong_count(&f.cells.outbound_circuits);
        let overlap = matches!(mode.as_str(), "overlap" | "cold-overlap");
        let held = if overlap {
            Some(f.cells.outbound_circuits.lock().await)
        } else {
            None
        };
        f.cells.warm_outbound(receiver).await;
        if overlap {
            // The scheduled worker owns one clone; its construction pass owns
            // another only AFTER sampling the warm/refresh flag. Keep the pool
            // locked until that pass is live, so this exercises an upgrade
            // after the worker selected reuse, without a timing-only sleep.
            tokio::time::timeout(Duration::from_secs(5), async {
                while Arc::strong_count(&f.cells.outbound_circuits) < pool_owners + 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("warm construction pass did not start");
            f.cells
                .ensure_outbound_opening(receiver, RouteClass::Bulk)
                .await;
        }
        drop(held);
        async fn finish_opening(cells: &CircuitCells, receiver: [u8; 32]) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while cells.outbound_opening.lock().await.contains_key(&receiver) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("background opener did not finish");
        }
        finish_opening(&f.cells, receiver).await;
        if mode == "repair" {
            f.cells
                .ensure_outbound_opening(receiver, RouteClass::Bulk)
                .await;
            finish_opening(&f.cells, receiver).await;
        } else {
            f.cells.warm_outbound(receiver).await;
            finish_opening(&f.cells, receiver).await;
        }
        if matches!(mode.as_str(), "ready" | "busy" | "recent-data") {
            let pool = f.cells.outbound_circuits.lock().await;
            let kept = &pool.get(&receiver).unwrap()[0];
            assert!(Arc::ptr_eq(&kept.circuit, &primary.circuit));
            assert!(Arc::ptr_eq(&kept.stats, primary.stats.as_ref().unwrap()));
            assert!(kept.handshake_streams.contains(&71));
            assert_eq!(kept.stats.active_streams(), u64::from(mode == "busy"));
        }
        f.runtime.stop().await.unwrap();
        assert_eq!(crate::veil_debug_flush_console_logs(2000), 0);
        return;
    }
    for (mode, expected) in [
        ("cold-overlap", 1),
        ("ready", 0),
        ("busy", 0),
        ("recent-data", 0),
        ("empty", 1),
        ("unconfirmed", 1),
        ("quiet", 1),
        ("cooled-relay", 1),
        ("cooled-hop", 1),
        ("slow", 1),
        ("dead", 1),
        ("generation", 1),
        ("cookie", 1),
        ("key", 1),
        ("repair", 1),
        ("overlap", 1),
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "anon_stream::local_enqueue_tests::warming_ready_pool_reuses_routes_but_preserves_repair", "--nocapture"])
            .env(CHILD, mode).output().unwrap();
        assert!(
            output.status.success(),
            "child case failed: {mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let failures = String::from_utf8_lossy(&output.stderr)
            .lines()
            .filter(|line| {
                line.contains("outbound circuit open failed for ") && line.contains("NoRelays")
            })
            .count();
        assert_eq!(
            failures, expected,
            "unnecessary warm construction or suppressed repair: {mode}"
        );
    }
}

/// Console diagnostics are process-global. Run the real offline services in a
/// child so the count cannot include another parallel fixture's failures.
#[tokio::test]
async fn fast_no_relays_failure_does_not_restart_on_every_carrier_retry() {
    const CHILD: &str = "VEIL_TEST_FAST_CIRCUIT_RETRY_CHILD";
    if let Ok(mode) = std::env::var(CHILD) {
        let mut f = fixture().await;
        let receiver = advertised_receiver(&f).await;
        let other_receiver = if mode == "peer" {
            Some(advertised_receiver(&f).await)
        } else {
            None
        };
        let audio = f
            .cells
            .isolated_producer(crate::media::LocalMediaPlane::Primary);
        // A valid receiver ad exists, but the fixture has no complete relay
        // path. Each completed real opener fails with NoRelays immediately.
        for _ in 0..16 {
            f.cells
                .ensure_outbound_opening(receiver, RouteClass::Bulk)
                .await;
            if let Some(other) = other_receiver {
                f.cells
                    .ensure_outbound_opening(other, RouteClass::Bulk)
                    .await;
            }
            if mode == "producer" {
                audio
                    .ensure_outbound_opening(receiver, RouteClass::Bulk)
                    .await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if mode == "retry" {
            // No sleeping background worker retries on its own. A later
            // carrier request can try again once the failure cooldown expires.
            tokio::time::sleep(CIRCUIT_OPEN_FAILURE_RETRY + Duration::from_millis(50)).await;
            f.cells
                .ensure_outbound_opening(receiver, RouteClass::Bulk)
                .await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if mode == "usable" {
            // A healthy route published during the cooldown remains usable;
            // retry admission must never gate the actual carrier send.
            // Use a different relay: the failed one above is legitimately
            // in its existing route-send cooldown.
            let (healthy, _, mut healthy_outbox) = add_circuit(&f.cells.services);
            let primary = route(&healthy, f.cells.me);
            f.cells
                .outbound_circuits
                .lock()
                .await
                .insert(receiver, vec![entry(&primary, &[])]);
            while healthy_outbox.try_recv().is_ok() {}
            f.cells
                .send(
                    Addr {
                        node: receiver,
                        app: [0xbc; 32],
                    },
                    frames(71)[0].clone(),
                )
                .await
                .unwrap();
            assert!(healthy_outbox.try_recv().is_ok());
        }
        f.runtime.stop().await.unwrap();
        assert_eq!(crate::veil_debug_flush_console_logs(2000), 0);
        return;
    }
    for (mode, expected) in [
        ("burst", 1),
        ("retry", 2),
        ("peer", 2),
        ("producer", 2),
        ("usable", 1),
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "anon_stream::local_enqueue_tests::fast_no_relays_failure_does_not_restart_on_every_carrier_retry",
            "--nocapture",
        ])
        .env(CHILD, mode)
        .output()
        .unwrap();
        assert!(output.status.success(), "child case failed: {mode}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let failures = stderr
            .lines()
            .filter(|line| {
                line.contains("outbound circuit open failed for ") && line.contains("NoRelays")
            })
            .count();
        assert_eq!(failures, expected, "retry admission failed: {mode}");
    }
}

#[tokio::test]
async fn file_outbound_candidates_do_not_replace_the_advertised_receive_registration() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use veil_anonymity::{
        circuit_data::CircuitCellBytes,
        circuit_register::{CircuitRegisterPayload, CircuitRendezvousRegistry},
        circuit_setup::CircuitInstall,
        circuit_table::CircuitTable,
    };
    let mut f = fixture().await;
    let key = &f.cells.reg_kp;
    let epoch = &f.cells.epoch;
    let published = outbound_registration(key, epoch, false).unwrap();
    let mut registrations = vec![published];
    for _ in 0..3 {
        registrations.push(
            outbound_registration(key, epoch, f.cells.private_outbound_registration).unwrap(),
        );
    }
    let table = CircuitTable::new();
    let registry = CircuitRendezvousRegistry::with_params(8, 300);
    let link = [0x8d; 32];
    for (index, registration) in registrations.iter().enumerate() {
        let id = index as u32 + 1;
        table
            .install(
                &CircuitInstall {
                    circuit_id_in: id,
                    circuit_id_out: 0,
                    circuit_key: [9; 32],
                    cell_bytes: CircuitCellBytes::legacy(),
                },
                link,
                None,
                0,
            )
            .unwrap();
        let reg_pk = STANDARD
            .decode(&registration.keypair.public_key)
            .unwrap()
            .try_into()
            .unwrap();
        // Use the actual configured epoch owner, as circuit construction does.
        let epoch = registration.epoch.fetch_add(1, Ordering::Relaxed) + 1;
        let bytes = CircuitRegisterPayload::signing_bytes(&registration.cookie, &reg_pk, epoch);
        let payload = CircuitRegisterPayload {
            cookie: registration.cookie,
            reg_pk,
            epoch,
            signature: veil_crypto::sign_message(
                veil_types::SignatureAlgorithm::Ed25519,
                &registration.keypair.public_key,
                &registration.keypair.private_key,
                &bytes,
            )
            .unwrap(),
        };
        registry
            .register(&payload, table.lookup_forward(&link, id).unwrap(), 0)
            .unwrap();
    }
    let received_on = registry
        .lookup(&registrations[0].cookie)
        .unwrap()
        .circuit_id_in;
    f.runtime.stop().await.unwrap();
    assert_eq!(
        received_on, 1,
        "outbound setup displaced the advertised inbound receive circuit"
    );
    assert_eq!(registry.len(), 4);
    assert_eq!(f.cells.epoch.load(Ordering::Relaxed), 1);
    for (index, registration) in registrations.iter().enumerate() {
        assert_eq!(
            registry.lookup(&registration.cookie).unwrap().circuit_id_in,
            index as u32 + 1
        );
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    runtime: veil_node_runtime::NodeRuntime,
    cells: CircuitCells,
    circuit: Arc<veil_node_runtime::DataCircuit>,
    hop: [u8; 32],
    _outbox: veil_session::FrameOutbox,
}

#[tokio::test]
async fn completed_stream_releases_bulk_admission_but_retains_its_ack_binding() {
    let mut f = fixture().await;
    let destination = Addr {
        node: [0xb9; 32],
        app: [0xbc; 32],
    };
    let primary = protected_route(&f.circuit, f.cells.me);
    f.cells.bulk_route_active_limit = 1;
    let hub = HubCells::Circuit(Box::new(f.cells.clone()));
    f.cells
        .outbound_circuits
        .lock()
        .await
        .insert(destination.node, vec![entry(&primary, &[])]);
    f.cells
        .circuit_for(destination.node, Some(71), RouteClass::Bulk, true)
        .await
        .unwrap()
        .unwrap();
    f.cells
        .circuit_for(destination.node, Some(71), RouteClass::Ack, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(primary.stats.as_ref().unwrap().active_streams(), 1);
    hub.on_stream_linger(destination, 71).await;
    let active_during_linger = primary.stats.as_ref().unwrap().active_streams();
    let binding = f.cells.stream_receiver(destination.node, Some(71));
    let ack = f
        .cells
        .circuit_for(destination.node, Some(71), RouteClass::Ack, false)
        .await
        .unwrap();
    let next = f
        .cells
        .circuit_for(destination.node, Some(73), RouteClass::Bulk, true)
        .await
        .unwrap();
    hub.on_stream_linger(destination, 71).await;
    let after_duplicate_linger = primary.stats.as_ref().unwrap().active_streams();
    hub.on_stream_closed(destination, 71, End::Eof).await;
    let after_close = primary.stats.as_ref().unwrap().active_streams();
    let completed_binding_removed = f
        .cells
        .stream_receiver(destination.node, Some(71))
        .is_none();
    f.runtime.stop().await.unwrap();
    assert_eq!(
        active_during_linger, 0,
        "the final-ACK responder consumed the only data admission slot"
    );
    assert!(binding.is_some_and(|b| b.matches_route(&primary)) && ack.is_some());
    assert!(
        next.is_some(),
        "a completed file kept a new handshake waiting for the close lease"
    );
    assert_eq!(
        (after_duplicate_linger, after_close),
        (1, 1),
        "final cleanup decremented the next stream's admission"
    );
    assert!(completed_binding_removed);
}

#[tokio::test]
async fn cold_handshake_fallback_does_not_bypass_route_admission() {
    let mut outcomes = Vec::new();
    for unavailable in ["relay_cooldown", "hop_cooldown", "active_limit"] {
        let mut f = fixture().await;
        let destination = Addr {
            node: [0xb9; 32],
            app: [0xbc; 32],
        };
        let primary = protected_route(&f.circuit, f.cells.me);
        primary.stats.as_ref().unwrap().record_stream_open();
        let mut old = entry(&primary, &[65]);
        let quiet = Instant::now() - CIRCUIT_HANDSHAKE_REOPEN_AFTER - Duration::from_secs(1);
        old.opened_at = quiet;
        old.last_non_handshake = quiet;
        f.cells
            .outbound_circuits
            .lock()
            .await
            .insert(destination.node, vec![old]);
        // A background replacement is already pending. The handshake may
        // neither wait for it nor use a path rejected by the normal selector.
        f.cells.outbound_opening.lock().await.insert(
            destination.node,
            OutboundOpening::new(Instant::now(), PoolOpenIntent::Refresh),
        );
        match unavailable {
            "relay_cooldown" => {
                mark_rendezvous_cooldown(&f.cells.route_cooldowns, f.hop, Duration::from_secs(60))
            }
            "hop_cooldown" => mark_first_hop_cooldown(
                &f.cells.first_hop_cooldowns,
                f.hop,
                Duration::from_secs(60),
            ),
            "active_limit" => f.cells.bulk_route_active_limit = 1,
            _ => unreachable!(),
        }
        while f._outbox.try_recv().is_ok() {}
        let encoded = Frame::SynAck {
            stream_id: 71,
            isn: 100,
            win: 8192,
            ack: 1,
        }
        .encode();
        let mut pending = std::collections::VecDeque::from([encoded.clone()]);
        let result = f.cells.send_many(destination, &mut pending).await;
        let untouched = pending == [encoded];
        let emitted = f._outbox.try_recv().is_ok();
        let pinned = f
            .cells
            .stream_receiver(destination.node, Some(71))
            .is_some();
        let active = primary.stats.as_ref().unwrap().active_streams();
        f.runtime.stop().await.unwrap();
        outcomes.push((
            unavailable,
            result.err().map(|e| e.kind()),
            untouched,
            emitted,
            pinned,
            active,
        ));
    }
    for (unavailable, error, untouched, emitted, pinned, active) in outcomes {
        assert_eq!(error, Some(io::ErrorKind::WouldBlock), "{unavailable}");
        assert!(
            untouched && !emitted && !pinned,
            "inadmissible {unavailable} path accepted a handshake"
        );
        assert_eq!(
            active, 1,
            "handshake inflated an inadmissible path's active count"
        );
    }
}

#[tokio::test]
async fn cold_handshake_rechecks_a_refilled_pool_and_preserves_receiver_binding() {
    let mut f = fixture().await;
    let destination = [0xb9; 32];
    let primary = protected_route(&f.circuit, f.cells.me);
    primary.stats.as_ref().unwrap().record_stream_open();
    f.cells
        .remember_stream_receiver(destination, 71, &primary)
        .unwrap();
    let mut old = entry(&primary, &[65]);
    let quiet = Instant::now() - CIRCUIT_HANDSHAKE_REOPEN_AFTER - Duration::from_secs(1);
    old.opened_at = quiet;
    old.last_non_handshake = quiet;
    mark_rendezvous_cooldown(&f.cells.route_cooldowns, f.hop, Duration::from_secs(60));
    f.cells
        .outbound_circuits
        .lock()
        .await
        .insert(destination, vec![old]);
    let (good, _, _good_outbox) = add_circuit(&f.cells.services);
    let good = protected_route(&good, f.cells.me);
    let (wrong, _, _wrong_outbox) = add_circuit(&f.cells.services);
    let mut wrong = entry(&protected_route(&wrong, f.cells.me), &[]);
    wrong.peer_cookie[0] ^= 1;
    f.cells.outbound_opening.lock().await.insert(
        destination,
        OutboundOpening::new(Instant::now(), PoolOpenIntent::Refresh),
    );
    let opening = f.cells.outbound_opening.lock().await;
    let mut selection =
        Box::pin(
            f.cells
                .circuit_for(destination, Some(71), RouteClass::Bulk, true),
        );
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(selection.as_mut(), &mut context).is_pending());
    // Simulate publication while admission is suspended at the opener lock.
    // The first newly published route belongs to another receiver generation.
    {
        let mut pool = f.cells.outbound_circuits.lock().await;
        let entries = pool.get_mut(&destination).unwrap();
        entries.insert(0, wrong);
        entries.push(entry(&good, &[]));
    }
    drop(opening);
    let selected = selection.await.unwrap();
    let correct = selected
        .as_ref()
        .is_some_and(|r| Arc::ptr_eq(&r.circuit, &good.circuit));
    let binding = f.cells.stream_receiver(destination, Some(71)).unwrap();
    let old_active = primary.stats.as_ref().unwrap().active_streams();
    let good_active = good.stats.as_ref().unwrap().active_streams();
    f.runtime.stop().await.unwrap();
    assert!(
        correct,
        "handshake ignored a compatible healthy route published during admission"
    );
    assert!(binding.matches_route(&primary));
    assert_eq!((old_active, good_active), (1, 1));
}

/// A host retaining the retired C entry point must not make this receiver
/// undiscoverable. Exercise the real publisher and verify its signed DHT ad,
/// rather than only checking that the compatibility call returns.
#[tokio::test]
async fn retired_publish_pause_does_not_suppress_stream_rendezvous() {
    use veil_anonymity::rendezvous::{
        MAX_RENDEZVOUS_AD_SLOTS, decode_rendezvous_ad, verify_rendezvous_ad,
    };

    let mut f = fixture().await;
    let services = f.runtime.access();
    let receiver = services.local_node_id();
    let cookie = [0x59; COOKIE_LEN];
    crate::veil_debug_set_publish_pause(1);
    services.publish_stream_rendezvous_ad(f.hop, cookie);
    crate::veil_debug_set_publish_pause(0);
    let ad = (0..MAX_RENDEZVOUS_AD_SLOTS)
        .filter_map(|slot| {
            services
                .dht
                .get_local(&rendezvous_ad_dht_key_at(&receiver, slot))
        })
        .filter_map(|bytes| decode_rendezvous_ad(&bytes).ok())
        .find(|ad| ad.auth_cookie == cookie);
    f.runtime.stop().await.unwrap();

    let ad = ad.expect("legacy debug calls must not suppress a receiver's new ad");
    verify_rendezvous_ad(&ad).expect("the published ad must remain authentic");
    assert_eq!(ad.receiver_node_id, receiver);
    assert_eq!(ad.rendezvous_node_id, f.hop);
}

#[tokio::test]
async fn exact_call_receiver_uses_a_matching_route_even_when_another_relay_is_first() {
    let mut f = fixture().await;
    let (second, second_hop, mut second_outbox) = add_circuit(&f.cells.services);
    f.circuit.confirmed_flag().store(true, Ordering::Release);
    second.confirmed_flag().store(true, Ordering::Release);
    let destination = [0xb3; 32];
    f.cells.outbound_circuits.lock().await.insert(
        destination,
        vec![
            entry(&protected_route(&f.circuit, f.cells.me), &[]),
            entry(&protected_route(&second, f.cells.me), &[]),
        ],
    );
    while f._outbox.try_recv().is_ok() {}
    while second_outbox.try_recv().is_ok() {}
    let receiver = media_routes::ReceiveAddress {
        plane: 0,
        relay: second_hop,
        cookie: [0x57; 16],
        intro_key: [0x33; 32],
    };
    let cipher = crate::media::cipher_for_test(&destination, &[0x81; 32], &[0x82; 32]).unwrap();
    let mut accepted = 0;
    for _ in 0..4 {
        let sealed = cipher
            .seal_on_plane(LocalMediaPlane::Primary, b"audio")
            .unwrap();
        accepted += usize::from(
            f.cells
                .send_datagram_to_receiver(destination, &sealed, Some(&receiver))
                .await,
        );
    }
    let datagrams = |rx: &mut veil_session::FrameOutbox| {
        let mut count = 0;
        while let Ok((_, bytes)) = rx.try_recv() {
            let header = veil_proto::codec::decode_header_with_limit(
                &bytes[..veil_proto::HEADER_SIZE],
                65536,
            )
            .unwrap();
            count += usize::from(
                header.family == veil_proto::family::FrameFamily::RelayChain as u8
                    && header.msg_type == veil_proto::family::RelayChainMsg::CircuitDatagram as u16,
            );
        }
        count
    };
    let wrong = datagrams(&mut f._outbox);
    let wanted = datagrams(&mut second_outbox);
    f.runtime.stop().await.unwrap();
    assert_eq!(
        accepted, 4,
        "a healthy matching route must not lose round-robin turns"
    );
    assert_eq!(wrong, 0, "no packet may use the unrelated rendezvous");
    assert_eq!(wanted, 4);
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

#[tokio::test]
async fn stream_lookup_does_not_wait_for_a_mailbox_only_cache_to_expire() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use veil_anonymity::rendezvous::{rendezvous_ad_dht_key_at, sign_rendezvous_ad_v5};
    let mut f = fixture().await;
    let services = f.runtime.access();
    let key = veil_crypto::generate_keypair(veil_types::SignatureAlgorithm::Ed25519);
    let receiver = *blake3::hash(&STANDARD.decode(&key.public_key).unwrap()).as_bytes();
    let mailbox_cookie = veil_node_runtime::NodeServices::mailbox_rendezvous_cookie(&receiver);
    let stream_cookie = [0x52; COOKIE_LEN];
    assert_ne!(stream_cookie, mailbox_cookie);
    let now = veil_util::unix_secs_now_u64();
    let ad = |cookie| {
        sign_rendezvous_ad_v5(
            receiver,
            [0x71; 32],
            cookie,
            [0x33; 32],
            now,
            now + 3600,
            &[],
            &[],
            &[],
            0,
            &[],
            &key.public_key,
            &key.private_key,
            veil_types::SignatureAlgorithm::Ed25519,
        )
        .unwrap()
    };
    services
        .dht
        .store_local(rendezvous_ad_dht_key_at(&receiver, 0), ad(mailbox_cookie));
    let first = services
        .resolve_stream_rendezvous_ads(receiver)
        .await
        .unwrap();
    assert!(first.iter().all(|ad| ad.auth_cookie == mailbox_cookie));
    let cached_at = Instant::now();
    // The stream registration appears AFTER an earlier lookup cached only
    // mailbox ads. Its independently signed slot is already available to the
    // resolver; a 15-second general positive-cache hit must not hide it.
    services
        .dht
        .store_local(rendezvous_ad_dht_key_at(&receiver, 1), ad(stream_cookie));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = services
        .resolve_stream_rendezvous_ads(receiver)
        .await
        .unwrap();
    let found = second.iter().any(|ad| ad.auth_cookie == stream_cookie);
    let elapsed = cached_at.elapsed();
    f.runtime.stop().await.unwrap();
    assert!(
        elapsed < Duration::from_secs(10),
        "test did not stay inside the ordinary cache TTL"
    );
    assert!(
        found,
        "mailbox-only positive cache hid an available, signed stream ad"
    );
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
        _lifetime: None,
        rendezvous_node: Some(circuit.first_hop()),
        first_hop_close_generation: 0,
        peer_cookie: [0x42; COOKIE_LEN],
        envelope: CircuitEnvelope::LegacyClearSender {
            sender_node: sender,
        },
        stats: Some(Arc::new(CircuitRouteStats::new(Instant::now()))),
    }
}

fn protected_route(
    circuit: &Arc<veil_node_runtime::DataCircuit>,
    sender: [u8; 32],
) -> CircuitRoute {
    let mut route = route(circuit, sender);
    route.envelope = CircuitEnvelope::ProtectedIntro {
        peer_tag: [0x32; CIRCUIT_PEER_TAG_LEN],
        receiver_x25519_pk: [3; 32],
    };
    route
}

fn entry(route: &CircuitRoute, streams: &[u32]) -> CircuitEntry {
    let now = Instant::now();
    CircuitEntry {
        circuit: Arc::clone(&route.circuit),
        lifetime: route._lifetime.clone(),
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
                _lifetime: None,
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
            lifetime: None,
            rendezvous_node: hop,
            first_hop_close_generation: 0,
            peer_tag: [0x32; CIRCUIT_PEER_TAG_LEN],
            peer_cookie: primary.peer_cookie,
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

fn fill_ordinary_outbox(cells: &CircuitCells, circuit: &veil_node_runtime::DataCircuit) {
    for _ in 0..65536 {
        match cells
            .services
            .send_circuit_cell_detailed(circuit, b"ordinary traffic")
        {
            Ok(()) => (),
            Err(veil_node_runtime::DataCircuitSendError::QueueFull) => return,
            error => panic!("unexpected local enqueue result: {error:?}"),
        }
    }
    panic!("ordinary outbox did not reach its actual bounded capacity");
}

#[tokio::test]
async fn first_ack_keeps_bulk_receiver_and_independent_ack_path() {
    let mut observed = Vec::new();
    for different in ["cookie", "key"] {
        let mut f = fixture().await;
        let destination = [0xb9; 32];
        let primary = protected_route(&f.circuit, f.cells.me);
        f.cells
            .outbound_circuits
            .lock()
            .await
            .insert(destination, vec![entry(&primary, &[])]);
        f.cells
            .circuit_for(destination, Some(71), RouteClass::Bulk, true)
            .await
            .unwrap()
            .unwrap();
        let (wrong, _, _wrong_outbox) = add_circuit(&f.cells.services);
        let (good, _, _good_outbox) = add_circuit(&f.cells.services);
        let good = protected_route(&good, f.cells.me);
        let mut wrong = entry(&protected_route(&wrong, f.cells.me), &[]);
        if different == "cookie" {
            wrong.peer_cookie[0] ^= 1;
        } else {
            wrong.receiver_x25519_pk[0] ^= 1;
        }
        f.cells.outbound_circuits.lock().await.insert(
            destination,
            vec![wrong, entry(&good, &[]), entry(&primary, &[71])],
        );
        f.cells.ack_outbound_pool_target = 1;
        let ack = f
            .cells
            .circuit_for(destination, Some(71), RouteClass::Ack, false)
            .await
            .unwrap()
            .unwrap();
        f.runtime.stop().await.unwrap();
        observed.push((different, Arc::ptr_eq(&ack.circuit, &good.circuit)));
    }
    for (different, correct) in observed {
        assert!(
            correct,
            "first ACK ignored the Bulk receiver {different} or lost its independent path"
        );
    }
}

#[tokio::test]
async fn an_ack_without_a_stream_binding_does_not_guess_a_receiver() {
    let mut f = fixture().await;
    let destination = [0xb9; 32];
    let primary = protected_route(&f.circuit, f.cells.me);
    f.cells
        .outbound_circuits
        .lock()
        .await
        .insert(destination, vec![entry(&primary, &[])]);
    let ack = f
        .cells
        .circuit_for(destination, Some(71), RouteClass::Ack, false)
        .await
        .unwrap();
    let bulk = f
        .cells
        .circuit_for(destination, Some(71), RouteClass::Bulk, true)
        .await
        .unwrap();
    let later_ack = f
        .cells
        .circuit_for(destination, Some(71), RouteClass::Ack, false)
        .await
        .unwrap();
    f.runtime.stop().await.unwrap();
    assert!(ack.is_none());
    assert!(bulk.is_some() && later_ack.is_some());
}

#[tokio::test]
async fn racing_same_class_selections_pin_and_account_for_one_route() {
    let mut f = fixture().await;
    let destination = [0xb9; 32];
    let primary = protected_route(&f.circuit, f.cells.me);
    let (second, _, _outbox) = add_circuit(&f.cells.services);
    let second = protected_route(&second, f.cells.me);
    let mut pool = f.cells.outbound_circuits.lock().await;
    pool.insert(destination, vec![entry(&primary, &[]), entry(&second, &[])]);
    let mut first = Box::pin(
        f.cells
            .circuit_for(destination, Some(71), RouteClass::Bulk, true),
    );
    let mut other = Box::pin(
        f.cells
            .circuit_for(destination, Some(71), RouteClass::Bulk, true),
    );
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    // Both callers see an empty pin cache, then park at the real pool lock.
    assert!(std::future::Future::poll(first.as_mut(), &mut context).is_pending());
    assert!(std::future::Future::poll(other.as_mut(), &mut context).is_pending());
    let pins = f.cells.stream_routes.lock().await;
    drop(pool);
    // Both finish pool selection, then park before committing the cache pin.
    assert!(std::future::Future::poll(first.as_mut(), &mut context).is_pending());
    assert!(std::future::Future::poll(other.as_mut(), &mut context).is_pending());
    drop(pins);
    let (first, other) = tokio::join!(first, other);
    let first = first.unwrap().unwrap();
    let other = other.unwrap().unwrap();
    let active = primary.stats.as_ref().unwrap().active_streams()
        + second.stats.as_ref().unwrap().active_streams();
    f.cells
        .on_stream_closed(
            Addr {
                node: destination,
                app: [0xbc; 32],
            },
            71,
            End::Eof,
        )
        .await;
    let after_close = primary.stats.as_ref().unwrap().active_streams()
        + second.stats.as_ref().unwrap().active_streams();
    f.runtime.stop().await.unwrap();
    assert!(
        Arc::ptr_eq(&first.circuit, &other.circuit),
        "same stream committed two different Bulk pins"
    );
    assert_eq!(active, 1, "one stream consumed two admission slots");
    assert_eq!(after_close, 0, "close leaked an admission slot");
}

#[tokio::test]
async fn stale_session_eviction_preserves_a_ready_same_rendezvous_replacement() {
    let mut f = fixture().await;
    let destination = Addr {
        node: [0xb9; 32],
        app: [0xbc; 32],
    };
    let mut old = protected_route(&f.circuit, f.cells.me);
    // The fixture keeps a real live outbox. Only the retained handle's
    // generation differs, exactly the stale-handle guard used after reconnect.
    old.first_hop_close_generation = f
        .cells
        .services
        .session_close_generation(&f.hop)
        .wrapping_add(1);
    assert!(f.cells.route_session_stale(&old));
    assert!(f.cells.services.has_live_session(&f.hop));
    let (fresh, _rx) = f
        .cells
        .services
        .open_data_circuit(&[f.hop], b"replacement")
        .unwrap();
    let fresh = Arc::new(fresh);
    fresh.confirmed_flag().store(true, Ordering::Release);
    let ready = protected_route(&fresh, f.cells.me);
    f.cells
        .outbound_circuits
        .lock()
        .await
        .insert(destination.node, vec![entry(&ready, &[72])]);
    f.cells
        .remember_stream_receiver(destination.node, 71, &old)
        .unwrap();
    f.cells
        .remember_stream_receiver(destination.node, 72, &ready)
        .unwrap();
    old.stats.as_ref().unwrap().record_stream_open();
    ready.stats.as_ref().unwrap().record_stream_open();
    {
        let mut pins = f.cells.stream_routes.lock().await;
        pins.insert((destination.node, 71, RouteClass::Bulk), old.clone());
        pins.insert((destination.node, 72, RouteClass::Bulk), ready.clone());
        pins.insert((destination.node, 72, RouteClass::Ack), ready.clone());
    }
    while f._outbox.try_recv().is_ok() {}
    f.cells.mark_route_stale(destination.node, &old).await;
    let replacement_kept = f
        .cells
        .outbound_circuits
        .lock()
        .await
        .get(&destination.node)
        .is_some_and(|entries| entries.iter().any(|e| Arc::ptr_eq(&e.circuit, &fresh)));
    let active_pin_kept = f
        .cells
        .stream_routes
        .lock()
        .await
        .get(&(destination.node, 72, RouteClass::Bulk))
        .is_some_and(|r| Arc::ptr_eq(&r.circuit, &fresh));
    let ack_pin_kept = f
        .cells
        .stream_routes
        .lock()
        .await
        .get(&(destination.node, 72, RouteClass::Ack))
        .is_some_and(|r| Arc::ptr_eq(&r.circuit, &fresh));
    let relay_cooled = f.cells.route_cooldowns.lock().unwrap().contains_key(&f.hop);
    let hop_cooled = f
        .cells
        .first_hop_cooldowns
        .lock()
        .unwrap()
        .contains_key(&f.hop);
    let active_before = ready.stats.as_ref().unwrap().active_streams();
    let mut data = data_run(71, 1);
    let sent = f.cells.send_many(destination, &mut data).await;
    let mut accepted = 0;
    while let Ok((lane, _)) = f._outbox.try_recv() {
        assert_eq!(lane, veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE);
        accepted += 1;
    }
    let old_active = old.stats.as_ref().unwrap().active_streams();
    f.runtime.stop().await.unwrap();
    assert!(
        replacement_kept,
        "late stale handle removed the ready replacement at the same R"
    );
    assert!(
        active_pin_kept && ack_pin_kept,
        "stale handle evicted another live stream's pins"
    );
    assert!(
        !relay_cooled && !hop_cooled,
        "reconnected live hop was quarantined by its old handle"
    );
    assert_eq!(
        active_before, 1,
        "live replacement lost its admission accounting"
    );
    assert_eq!(old_active, 0);
    assert!(sent.is_ok() && data.is_empty());
    assert_eq!(
        accepted, 1,
        "the retained stream must hand off on the ready replacement"
    );
}

#[tokio::test]
async fn stale_session_eviction_preserves_real_cooldowns_and_dead_hop_guards() {
    for guard in ["rendezvous", "first_hop", "dead_hop"] {
        let mut f = fixture().await;
        let destination = Addr {
            node: [0xb9; 32],
            app: [0xbc; 32],
        };
        let mut old = protected_route(&f.circuit, f.cells.me);
        old.first_hop_close_generation = f
            .cells
            .services
            .session_close_generation(&f.hop)
            .wrapping_add(1);
        let (fresh, _rx) = f
            .cells
            .services
            .open_data_circuit(&[f.hop], b"replacement")
            .unwrap();
        let ready = protected_route(&Arc::new(fresh), f.cells.me);
        f.cells
            .outbound_circuits
            .lock()
            .await
            .insert(destination.node, vec![entry(&ready, &[])]);
        f.cells
            .remember_stream_receiver(destination.node, 71, &old)
            .unwrap();
        old.stats.as_ref().unwrap().record_stream_open();
        f.cells
            .stream_routes
            .lock()
            .await
            .insert((destination.node, 71, RouteClass::Bulk), old.clone());
        if guard == "rendezvous" {
            mark_rendezvous_cooldown(&f.cells.route_cooldowns, f.hop, Duration::from_secs(120));
        } else if guard == "first_hop" {
            mark_first_hop_cooldown(
                &f.cells.first_hop_cooldowns,
                f.hop,
                Duration::from_secs(120),
            );
        } else {
            f.cells
                .services
                .session_tx_registry
                .write()
                .unwrap()
                .unregister(&f.hop);
        }
        let relay_errors = f.cells.route_cooldowns.lock().unwrap().clone();
        let hop_errors = f.cells.first_hop_cooldowns.lock().unwrap().clone();
        while f._outbox.try_recv().is_ok() {}
        f.cells.mark_route_stale(destination.node, &old).await;
        let relay_after = f.cells.route_cooldowns.lock().unwrap().clone();
        let hop_after = f.cells.first_hop_cooldowns.lock().unwrap().clone();
        let mut data = data_run(71, 1);
        let sent = f.cells.send_many(destination, &mut data).await;
        let data_admitted = std::iter::from_fn(|| f._outbox.try_recv().ok())
            .any(|(lane, _)| lane == veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE);
        f.runtime.stop().await.unwrap();
        assert_eq!(
            relay_after, relay_errors,
            "real relay failures changed: {guard}"
        );
        assert_eq!(hop_after, hop_errors, "real hop failures changed: {guard}");
        assert_eq!(sent.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(data.len(), 1, "an unaccepted cell was discarded: {guard}");
        assert!(
            !data_admitted,
            "unavailable/cooled path accepted data: {guard}"
        );
    }
}

#[tokio::test]
async fn stale_route_eviction_does_not_rebind_a_live_stream_to_another_receiver() {
    let mut observed = Vec::new();
    for different in ["cookie", "key"] {
        for matching in [false, true] {
            let mut f = fixture().await;
            let destination = [0xb9; 32];
            let primary = protected_route(&f.circuit, f.cells.me);
            f.cells
                .outbound_circuits
                .lock()
                .await
                .insert(destination, vec![entry(&primary, &[])]);
            f.cells
                .circuit_for(destination, Some(71), RouteClass::Bulk, true)
                .await
                .unwrap()
                .unwrap();
            let (wrong, _, _wrong_outbox) = add_circuit(&f.cells.services);
            let (good, _, _good_outbox) = add_circuit(&f.cells.services);
            let good = protected_route(&good, f.cells.me);
            let mut wrong = entry(&protected_route(&wrong, f.cells.me), &[]);
            if different == "cookie" {
                wrong.peer_cookie[0] ^= 1;
            } else {
                wrong.receiver_x25519_pk[0] ^= 1;
            }
            let mut entries = vec![entry(&primary, &[71]), wrong];
            if matching {
                entries.push(entry(&good, &[]));
            }
            f.cells
                .outbound_circuits
                .lock()
                .await
                .insert(destination, entries);
            f.cells.mark_route_stale(destination, &primary).await;
            let next = f
                .cells
                .circuit_for(destination, Some(71), RouteClass::Bulk, false)
                .await
                .unwrap();
            let correct = match next {
                Some(route) => matching && Arc::ptr_eq(&route.circuit, &good.circuit),
                None => !matching,
            };
            // A fresh stream can legitimately choose the other device. The
            // old stream can do so only after its own lifetime has ended.
            let fresh = f
                .cells
                .circuit_for(destination, Some(72), RouteClass::Bulk, true)
                .await
                .unwrap();
            let new_allowed = fresh.as_ref().is_some_and(|route| {
                !StreamReceiverBinding::from_route(&primary).matches_route(route)
            });
            f.cells
                .on_stream_closed(
                    Addr {
                        node: destination,
                        app: [0xbc; 32],
                    },
                    71,
                    End::Eof,
                )
                .await;
            f.cells
                .next_outbound_route
                .lock()
                .unwrap()
                .insert((destination, RouteClass::Bulk), 0);
            let reused = f
                .cells
                .circuit_for(destination, Some(71), RouteClass::Bulk, true)
                .await
                .unwrap();
            let released = reused.as_ref().is_some_and(|route| {
                !StreamReceiverBinding::from_route(&primary).matches_route(route)
            });
            let unrelated_kept = f.cells.stream_routes.lock().await.contains_key(&(
                destination,
                72,
                RouteClass::Bulk,
            ));
            f.runtime.stop().await.unwrap();
            observed.push((
                different,
                matching,
                correct && new_allowed && released && unrelated_kept,
            ));
        }
    }
    for (different, matching, correct) in observed {
        assert!(
            correct,
            "live stream rebound after cache eviction: {different}, matching alternative={matching}"
        );
    }
}

#[tokio::test]
async fn cached_wrong_ack_is_reselected_without_changing_bulk_binding() {
    let mut f = fixture().await;
    let destination = [0xb9; 32];
    let primary = protected_route(&f.circuit, f.cells.me);
    let (wrong, _, _wrong_outbox) = add_circuit(&f.cells.services);
    let (good, _, _good_outbox) = add_circuit(&f.cells.services);
    let mut wrong = protected_route(&wrong, f.cells.me);
    wrong.peer_cookie[0] ^= 1;
    let good = protected_route(&good, f.cells.me);
    f.cells.outbound_circuits.lock().await.insert(
        destination,
        vec![
            entry(&good, &[]),
            entry(&wrong, &[]),
            entry(&primary, &[71]),
        ],
    );
    {
        let mut routes = f.cells.stream_routes.lock().await;
        routes.insert((destination, 71, RouteClass::Bulk), primary.clone());
        routes.insert((destination, 71, RouteClass::Ack), wrong);
    }
    let ack = f
        .cells
        .circuit_for(destination, Some(71), RouteClass::Ack, false)
        .await
        .unwrap()
        .unwrap();
    let bulk = f
        .cells
        .circuit_for(destination, Some(71), RouteClass::Bulk, false)
        .await
        .unwrap()
        .unwrap();
    f.runtime.stop().await.unwrap();
    assert!(Arc::ptr_eq(&ack.circuit, &good.circuit));
    assert!(Arc::ptr_eq(&bulk.circuit, &primary.circuit));
}

#[tokio::test]
async fn ack_copy_recovery_keeps_binding_after_bulk_pin_eviction() {
    let mut f = fixture().await;
    let destination = [0xb9; 32];
    let primary = protected_route(&f.circuit, f.cells.me);
    f.cells
        .outbound_circuits
        .lock()
        .await
        .insert(destination, vec![entry(&primary, &[])]);
    f.cells
        .circuit_for(destination, Some(71), RouteClass::Bulk, true)
        .await
        .unwrap()
        .unwrap();
    let (wrong, _, mut wrong_outbox) = add_circuit(&f.cells.services);
    let (good, _, mut good_outbox) = add_circuit(&f.cells.services);
    let mut wrong = entry(&protected_route(&wrong, f.cells.me), &[]);
    wrong.receiver_x25519_pk[0] ^= 1;
    let good = protected_route(&good, f.cells.me);
    while wrong_outbox.try_recv().is_ok() {}
    while good_outbox.try_recv().is_ok() {}
    f.cells.outbound_circuits.lock().await.insert(
        destination,
        vec![entry(&primary, &[71]), wrong, entry(&good, &[])],
    );
    f.cells.mark_route_stale(destination, &primary).await;
    let ack = frames(71)[2].clone();
    let accepted = f.cells.send_ack_copies(destination, None, &ack, 1).await;
    let wrong_sent = wrong_outbox.try_recv().is_ok();
    let good_sent = good_outbox.try_recv().is_ok();
    f.cells
        .on_stream_closed(
            Addr {
                node: destination,
                app: [0xbc; 32],
            },
            71,
            End::Eof,
        )
        .await;
    let after_close = f.cells.send_ack_copies(destination, None, &ack, 1).await;
    f.runtime.stop().await.unwrap();
    assert_eq!(accepted, 1);
    assert!(!wrong_sent && good_sent);
    assert_eq!(
        after_close, 0,
        "closed stream guessed a new receiver for its ACK"
    );
}

#[tokio::test]
async fn route_cache_pressure_keeps_live_bulk_pins_and_receiver_admission_bounded() {
    let mut f = fixture().await;
    let destination = [0xb9; 32];
    let primary = protected_route(&f.circuit, f.cells.me);
    f.cells
        .outbound_circuits
        .lock()
        .await
        .insert(destination, vec![entry(&primary, &[])]);
    f.cells.bulk_route_active_limit = 0;
    for sid in 1..=MAX_STREAM_RECEIVER_BINDINGS as u32 {
        f.cells
            .circuit_for(destination, Some(sid), RouteClass::Bulk, true)
            .await
            .unwrap()
            .unwrap();
    }
    let ack = f
        .cells
        .circuit_for(destination, Some(1), RouteClass::Ack, false)
        .await;
    let bulk_kept = f
        .cells
        .stream_routes
        .lock()
        .await
        .get(&(destination, 2, RouteClass::Bulk))
        .is_some_and(|route| Arc::ptr_eq(&route.circuit, &primary.circuit));
    let new_sid = MAX_STREAM_RECEIVER_BINDINGS as u32 + 1;
    let full = f
        .cells
        .circuit_for(destination, Some(new_sid), RouteClass::Bulk, true)
        .await;
    let full_rejected = full
        .as_ref()
        .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock);
    f.cells
        .on_stream_closed(
            Addr {
                node: destination,
                app: [0xbc; 32],
            },
            1,
            End::Eof,
        )
        .await;
    let resumed = f
        .cells
        .circuit_for(destination, Some(new_sid), RouteClass::Bulk, true)
        .await;
    let bindings = f.cells.stream_receivers.lock().unwrap().len();
    let pinned = f.cells.stream_routes.lock().await.len();
    let active = primary.stats.as_ref().unwrap().active_streams();
    f.runtime.stop().await.unwrap();
    assert!(
        ack.unwrap().is_some(),
        "full pin cache blocked an existing stream ACK"
    );
    assert!(bulk_kept, "cache pressure evicted a live Bulk pin");
    assert!(
        full_rejected,
        "receiver admission erased or exceeded the live binding bound"
    );
    assert!(
        resumed.unwrap().is_some(),
        "closed stream failed to release admission"
    );
    assert!(bindings <= MAX_STREAM_RECEIVER_BINDINGS && pinned <= MAX_STREAM_ROUTE_ENTRIES);
    assert_eq!(active, MAX_STREAM_RECEIVER_BINDINGS as u64);
}

#[tokio::test]
async fn slow_route_shedding_keeps_the_original_receiver() {
    for matching in [false, true] {
        let mut f = fixture().await;
        let destination = [0xb9; 32];
        let primary = protected_route(&f.circuit, f.cells.me);
        f.cells
            .outbound_circuits
            .lock()
            .await
            .insert(destination, vec![entry(&primary, &[])]);
        f.cells
            .circuit_for(destination, Some(71), RouteClass::Bulk, true)
            .await
            .unwrap()
            .unwrap();
        let (wrong, _, _wrong_outbox) = add_circuit(&f.cells.services);
        let (good, _, _good_outbox) = add_circuit(&f.cells.services);
        let good = protected_route(&good, f.cells.me);
        let mut wrong = entry(&protected_route(&wrong, f.cells.me), &[]);
        wrong.peer_cookie[0] ^= 1;
        let mut entries = vec![entry(&primary, &[71]), wrong];
        if matching {
            entries.push(entry(&good, &[]));
        }
        f.cells
            .outbound_circuits
            .lock()
            .await
            .insert(destination, entries);
        let stats = primary.stats.as_ref().unwrap();
        stats
            .slow_windows
            .store(CIRCUIT_ROUTE_SHED_SLOW_WINDOWS, Ordering::Relaxed);
        stats.slow_mark_expiry_ms.store(60_000, Ordering::Relaxed);
        f.cells
            .maybe_shed_slow_bulk_route(destination, 71, &primary)
            .await;
        let selected = f
            .cells
            .circuit_for(destination, Some(71), RouteClass::Bulk, false)
            .await
            .unwrap()
            .unwrap();
        f.runtime.stop().await.unwrap();
        assert!(Arc::ptr_eq(
            &selected.circuit,
            if matching {
                &good.circuit
            } else {
                &primary.circuit
            }
        ));
    }
}

#[tokio::test]
async fn stripe_candidates_preserve_the_streams_exact_receiver_binding() {
    for different in ["cookie", "key"] {
        let mut f = fixture().await;
        let destination = [0xb9; 32];
        let mut primary = route(&f.circuit, f.cells.me);
        primary.envelope = CircuitEnvelope::ProtectedIntro {
            peer_tag: [0x32; CIRCUIT_PEER_TAG_LEN],
            receiver_x25519_pk: [3; 32],
        };
        let (wrong, _, _wrong_outbox) = add_circuit(&f.cells.services);
        let (good, _, _good_outbox) = add_circuit(&f.cells.services);
        let good = route(&good, f.cells.me);
        let mut wrong = entry(&route(&wrong, f.cells.me), &[]);
        if different == "cookie" {
            wrong.peer_cookie[0] ^= 1;
        } else {
            wrong.receiver_x25519_pk[0] ^= 1;
        }
        f.cells.outbound_circuits.lock().await.insert(
            destination,
            vec![entry(&primary, &[71]), wrong, entry(&good, &[])],
        );
        let selected = f.cells.stripe_alternates(destination, &primary, 1).await;
        f.runtime.stop().await.unwrap();
        assert_eq!(selected.len(), 1);
        assert!(
            Arc::ptr_eq(&selected[0].circuit, &good.circuit),
            "selected another receiver's {different}"
        );
    }
}

#[tokio::test]
async fn a_full_primary_outbox_does_not_stop_a_healthy_stripe() {
    let mut f = fixture().await;
    let primary = route(&f.circuit, f.cells.me);
    let (alternate, _, mut outbox) = add_circuit(&f.cells.services);
    let alternate = route(&alternate, f.cells.me);
    while outbox.try_recv().is_ok() {}
    fill_ordinary_outbox(&f.cells, &f.circuit);
    f.cells.stripe_rr.store(0, Ordering::Relaxed);
    let mut pending = data_run(71, 4);
    let suffix = frames(99)[2].clone();
    let expected: std::collections::VecDeque<_> = pending
        .iter()
        .step_by(2)
        .cloned()
        .chain([suffix.clone()])
        .collect();
    pending.push_back(suffix);
    let result = f
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
        .await;
    let mut accepted = 0;
    while outbox.try_recv().is_ok() {
        accepted += 1;
    }
    let cooled = f.cells.route_cooldowns.lock().unwrap().contains_key(&f.hop);
    let sent = alternate.stats.as_ref().unwrap().snapshot().data_cells;
    f.runtime.stop().await.unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert_eq!(pending, expected);
    assert_eq!(
        accepted, 2,
        "full primary prevented a healthy stripe from being tried"
    );
    assert_eq!(sent, 2);
    assert!(
        !cooled,
        "local saturation quarantined a healthy network route"
    );
}

#[tokio::test]
async fn short_data_tail_retries_bound_alternates_after_full_first_hops() {
    for all_full in [false, true] {
        for accepted_prefix in [0, 1] {
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
            let (wrong, _, mut wrong_outbox) = add_circuit(&f.cells.services);
            let (full, _, _full_outbox) = add_circuit(&f.cells.services);
            let (good, _, mut good_outbox) = add_circuit(&f.cells.services);
            let good = route(&good, f.cells.me);
            while wrong_outbox.try_recv().is_ok() {}
            while good_outbox.try_recv().is_ok() {}
            let mut wrong = entry(&route(&wrong, f.cells.me), &[]);
            wrong.receiver_x25519_pk[0] ^= 1;
            f.cells.outbound_circuits.lock().await.insert(
                destination.node,
                vec![
                    entry(&primary, &[71]),
                    wrong,
                    entry(&route(&full, f.cells.me), &[]),
                    entry(&good, &[]),
                ],
            );
            f.cells
                .stream_routes
                .lock()
                .await
                .insert((destination.node, 71, RouteClass::Bulk), primary.clone());
            // This is path recovery, including when ordinary multi-path
            // striping is disabled, not a reason to change that configuration.
            f.cells.stripe_routes = 1;
            fill_ordinary_outbox(&f.cells, &f.circuit);
            fill_ordinary_outbox(&f.cells, &full);
            if all_full {
                fill_ordinary_outbox(&f.cells, &good.circuit);
            }
            if accepted_prefix == 1 {
                f._outbox.try_recv().unwrap();
            }
            let mut pending = data_run(71, 2); // below STRIPE_MIN_RUN_CELLS
            let suffix = frames(99)[2].clone();
            pending.push_back(suffix.clone());
            let expected_blocked = pending
                .iter()
                .skip(accepted_prefix)
                .cloned()
                .collect::<std::collections::VecDeque<_>>();
            let result = f
                .cells
                .send_data_run(destination, 71, 2, &mut pending)
                .await;
            let mut accepted_on_good = 0;
            if !all_full {
                while let Ok((local_lane, bytes)) = good_outbox.try_recv() {
                    assert_eq!(local_lane, veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE);
                    let header =
                        veil_proto::codec::decode_header(&bytes[..veil_proto::HEADER_SIZE])
                            .unwrap();
                    assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                    accepted_on_good += 1;
                }
            }
            let wrong_received = wrong_outbox.try_recv().is_ok();
            let primary_sent = primary.stats.as_ref().unwrap().snapshot().data_cells;
            let good_sent = good.stats.as_ref().unwrap().snapshot().data_cells;
            let cooled = !f.cells.route_cooldowns.lock().unwrap().is_empty();
            f.runtime.stop().await.unwrap();
            assert!(
                !wrong_received,
                "recovery sent DATA to another receiver key"
            );
            assert!(!cooled, "full queues quarantined a network route");
            assert_eq!(primary_sent, accepted_prefix as u64);
            if all_full {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
                assert_eq!(pending, expected_blocked);
                assert_eq!(good_sent, 0);
            } else {
                assert!(
                    result.is_ok(),
                    "healthy bound third path was not tried: {result:?}"
                );
                assert_eq!(pending, std::collections::VecDeque::from([suffix]));
                assert_eq!(accepted_on_good, 2 - accepted_prefix);
                assert_eq!(good_sent, (2 - accepted_prefix) as u64);
            }
        }
    }
}

#[tokio::test]
async fn single_data_request_uses_the_same_bound_queue_recovery_as_a_burst() {
    for all_full in [false, true] {
        for direct in [false, true] {
            let mut f = fixture().await;
            let destination = Addr {
                node: [0xb9; 32],
                app: [0xbc; 32],
            };
            let primary = protected_route(&f.circuit, f.cells.me);
            let (wrong, _, mut wrong_outbox) = add_circuit(&f.cells.services);
            let (full, _, _full_outbox) = add_circuit(&f.cells.services);
            let (good, _, mut good_outbox) = add_circuit(&f.cells.services);
            let good = protected_route(&good, f.cells.me);
            while wrong_outbox.try_recv().is_ok() {}
            while good_outbox.try_recv().is_ok() {}
            let mut wrong = entry(&protected_route(&wrong, f.cells.me), &[]);
            wrong.receiver_x25519_pk[0] ^= 1;
            f.cells.outbound_circuits.lock().await.insert(
                destination.node,
                vec![
                    entry(&primary, &[71]),
                    wrong,
                    entry(&protected_route(&full, f.cells.me), &[]),
                    entry(&good, &[]),
                ],
            );
            f.cells
                .stream_routes
                .lock()
                .await
                .insert((destination.node, 71, RouteClass::Bulk), primary.clone());
            f.cells.stripe_routes = 1;
            fill_ordinary_outbox(&f.cells, &f.circuit);
            fill_ordinary_outbox(&f.cells, &full);
            if all_full {
                fill_ordinary_outbox(&f.cells, &good.circuit);
            }
            let mut encoded = Vec::new();
            Frame::Data {
                stream_id: 71,
                seq: 101,
                win: 8192,
                payload: &[0x39; 48],
            }
            .encode_into(&mut encoded);
            let mut pending = std::collections::VecDeque::from([encoded.clone()]);
            let result = if direct {
                f.cells.send(destination, encoded.clone()).await
            } else {
                f.cells.send_many(destination, &mut pending).await
            };
            let mut accepted = 0;
            if !all_full {
                while let Ok((lane, bytes)) = good_outbox.try_recv() {
                    assert_eq!(lane, veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE);
                    let header =
                        veil_proto::codec::decode_header(&bytes[..veil_proto::HEADER_SIZE])
                            .unwrap();
                    assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                    accepted += 1;
                }
            }
            let wrong_received = wrong_outbox.try_recv().is_ok();
            let primary_sent = primary.stats.as_ref().unwrap().snapshot().data_cells;
            let good_sent = good.stats.as_ref().unwrap().snapshot().data_cells;
            let cooled = !f.cells.route_cooldowns.lock().unwrap().is_empty();
            let pinned = f
                .cells
                .stream_routes
                .lock()
                .await
                .get(&(destination.node, 71, RouteClass::Bulk))
                .cloned()
                .unwrap();
            f.runtime.stop().await.unwrap();
            assert!(!wrong_received, "single DATA changed the receiver key");
            assert!(!cooled, "local queue pressure quarantined a route");
            assert!(Arc::ptr_eq(&pinned.circuit, &primary.circuit));
            assert_eq!(primary_sent, 0);
            if all_full {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
                assert_eq!(pending, std::collections::VecDeque::from([encoded]));
                assert_eq!(good_sent, 0);
            } else {
                assert!(
                    result.is_ok(),
                    "single request ignored a usable path: {result:?}"
                );
                if !direct {
                    assert!(pending.is_empty());
                }
                assert_eq!(accepted, 1, "request was lost or duplicated");
                assert_eq!(good_sent, 1);
            }
        }
    }
}

#[tokio::test]
async fn oversized_single_data_remains_invalid_input_without_path_cooldown() {
    let mut f = fixture().await;
    let destination = Addr {
        node: [0xb9; 32],
        app: [0xbc; 32],
    };
    let primary = protected_route(&f.circuit, f.cells.me);
    f.cells
        .stream_routes
        .lock()
        .await
        .insert((destination.node, 71, RouteClass::Bulk), primary.clone());
    let mut encoded = Vec::new();
    Frame::Data {
        stream_id: 71,
        seq: 101,
        win: 8192,
        payload: &vec![0x39; circuit_env_max()],
    }
    .encode_into(&mut encoded);
    let error = f.cells.send(destination, encoded).await.unwrap_err();
    let sent = primary.stats.as_ref().unwrap().snapshot().data_cells;
    let cooled = !f.cells.route_cooldowns.lock().unwrap().is_empty();
    f.runtime.stop().await.unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(sent, 0);
    assert!(!cooled);
}

#[tokio::test]
async fn ack_redundancy_tries_a_healthy_third_path_after_shared_first_hop_queue_full() {
    let mut observed = Vec::new();
    for all_full in [false, true] {
        let mut f = fixture().await;
        let destination = Addr {
            node: [0xb9; 32],
            app: [0xbc; 32],
        };
        let primary = route(&f.circuit, f.cells.me);
        let (_directory, second_hop, _second_outbox) = add_circuit(&f.cells.services);
        let (shared_first, _rx) = f
            .cells
            .services
            .open_data_circuit(&[f.hop, second_hop], b"shared first hop")
            .unwrap();
        let mut shared_first = route(&Arc::new(shared_first), f.cells.me);
        shared_first.rendezvous_node = Some(second_hop);
        let (healthy, _, mut healthy_outbox) = add_circuit(&f.cells.services);
        let healthy = route(&healthy, f.cells.me);
        while healthy_outbox.try_recv().is_ok() {}
        f.cells.outbound_circuits.lock().await.insert(
            destination.node,
            vec![
                entry(&primary, &[]),
                entry(&shared_first, &[]),
                entry(&healthy, &[]),
            ],
        );
        f.cells
            .stream_routes
            .lock()
            .await
            .insert((destination.node, 71, RouteClass::Ack), primary);
        f.cells.ack_redundancy = 2;
        fill_ordinary_outbox(&f.cells, &f.circuit);
        if all_full {
            fill_ordinary_outbox(&f.cells, &healthy.circuit);
        }
        let encoded = frames(71)[2].clone();
        let mut pending = std::collections::VecDeque::from([encoded.clone()]);
        let result = f.cells.send_many(destination, &mut pending).await;
        let copies = f.cells.ack_dup_sent.load(Ordering::Relaxed);
        let mut sent = 0;
        if !all_full {
            while let Ok((priority, bytes)) = healthy_outbox.try_recv() {
                assert_eq!(priority, veil_proto::priority::INTERACTIVE);
                let header =
                    veil_proto::codec::decode_header(&bytes[..veil_proto::HEADER_SIZE]).unwrap();
                assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                sent += 1;
            }
        }
        f.runtime.stop().await.unwrap();
        observed.push((
            all_full,
            result.err().map(|e| e.kind()),
            pending,
            encoded,
            copies,
            sent,
        ));
    }
    for (all_full, error, pending, encoded, copies, sent) in observed {
        if all_full {
            assert_eq!(error, Some(io::ErrorKind::WouldBlock));
            assert_eq!(pending, std::collections::VecDeque::from([encoded]));
            assert_eq!(copies, 0);
        } else {
            assert_eq!(error, None, "a healthy distinct first hop was never tried");
            assert!(pending.is_empty());
            assert_eq!(
                copies, 1,
                "failed attempts must not consume or inflate the copy budget"
            );
            assert_eq!(sent, 1);
        }
    }
}

#[tokio::test]
async fn ack_fallback_keeps_receiver_binding_and_the_successful_copy_budget() {
    for primary_known in [false, true] {
        for different in ["cookie", "key"] {
            let mut f = fixture().await;
            let destination = [0xb9; 32];
            let mut primary = route(&f.circuit, f.cells.me);
            primary.envelope = CircuitEnvelope::ProtectedIntro {
                peer_tag: [0x32; CIRCUIT_PEER_TAG_LEN],
                receiver_x25519_pk: [3; 32],
            };
            f.cells
                .stream_routes
                .lock()
                .await
                .insert((destination, 71, RouteClass::Bulk), primary.clone());
            let (wrong, _, mut wrong_outbox) = add_circuit(&f.cells.services);
            let (good, _, mut good_outbox) = add_circuit(&f.cells.services);
            let (extra, _, mut extra_outbox) = add_circuit(&f.cells.services);
            for outbox in [&mut wrong_outbox, &mut good_outbox, &mut extra_outbox] {
                while outbox.try_recv().is_ok() {}
            }
            let mut wrong = entry(&route(&wrong, f.cells.me), &[]);
            if different == "cookie" {
                wrong.peer_cookie[0] ^= 1;
            } else {
                wrong.receiver_x25519_pk[0] ^= 1;
            }
            f.cells.outbound_circuits.lock().await.insert(
                destination,
                vec![
                    wrong,
                    entry(&route(&good, f.cells.me), &[]),
                    entry(&route(&extra, f.cells.me), &[]),
                ],
            );
            let ack = frames(71)[2].clone();
            let accepted = f
                .cells
                .send_ack_copies(destination, primary_known.then_some(&primary), &ack, 1)
                .await;
            let mut counts = [0usize; 3];
            for (index, outbox) in [&mut wrong_outbox, &mut good_outbox, &mut extra_outbox]
                .into_iter()
                .enumerate()
            {
                while outbox.try_recv().is_ok() {
                    counts[index] += 1;
                }
            }
            f.cells.stream_routes.lock().await.clear();
            let unbound = f.cells.send_ack_copies(destination, None, &ack, 1).await;
            let no_unbound_frames = [&mut wrong_outbox, &mut good_outbox, &mut extra_outbox]
                .into_iter()
                .all(|outbox| outbox.try_recv().is_err());
            let copies = f.cells.ack_dup_sent.load(Ordering::Relaxed);
            f.runtime.stop().await.unwrap();
            assert_eq!(accepted, 1);
            assert_eq!(
                counts,
                [0, 1, 0],
                "wrong receiver or excess ACK copies; primary_known={primary_known}, differing={different}"
            );
            assert_eq!(unbound, 0);
            assert!(no_unbound_frames);
            assert_eq!(copies, 1);
        }
    }
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

#[tokio::test]
async fn cold_registered_opening_does_not_park_the_handshake_carrier() {
    let mut f = fixture().await;
    let destination = Addr {
        node: [0xb9; 32],
        app: [0xbc; 32],
    };
    // The resolver/opener is live but has not published its first route yet.
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let opener = tokio::spawn(async {
        let _ = release_rx.await;
    });
    f.cells.outbound_opening.lock().await.insert(
        destination.node,
        OutboundOpening::new(Instant::now(), PoolOpenIntent::Refresh),
    );
    assert!(!opener.is_finished());
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        f.cells.send(destination, frames(71)[0].clone()),
    )
    .await;
    release_tx.send(()).unwrap();
    opener.await.unwrap();
    f.runtime.stop().await.unwrap();
    let error = result
        .expect("cold shared opener parked the carrier instead of returning local backpressure")
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
}

#[tokio::test]
async fn isolated_small_rtos_keep_the_route_but_backlog_and_blackhole_recover() {
    use veil_onion_stream::{Config, Event, StreamEngine};
    for rewind in [false, true] {
        for mode in ["isolated", "backlogged", "blackhole", "legacy"] {
            let mut f = fixture().await;
            let destination = Addr {
                node: [0xb9; 32],
                app: [0xbc; 32],
            };
            let primary = protected_route(&f.circuit, f.cells.me);
            let (alternate, _, mut alternate_outbox) = add_circuit(&f.cells.services);
            let alternate = protected_route(&alternate, f.cells.me);
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
            let hub = HubCells::Circuit(Box::new(f.cells.clone()));
            let cfg = Config {
                mss: 8,
                init_cwnd: 8,
                init_rto_ms: 50,
                min_rto_ms: 50,
                max_rto_ms: 50,
                rto_rewind_no_sack: rewind,
                ..Config::default()
            };
            let mut engine = StreamEngine::connect(71, cfg, 0, 100);
            let mut cell = Vec::new();
            assert!(engine.poll_transmit(0, &mut cell));
            Frame::SynAck {
                stream_id: 71,
                isn: 500,
                win: 8192,
                ack: 101,
            }
            .encode_into(&mut cell);
            engine.on_cell(&cell, 1);
            while engine.poll_event().is_some() {}
            let mut replaced = false;
            let mut contexts = Vec::new();
            let mut ack_end = 101;
            let expected_rtos = if mode == "blackhole" { 2 } else { 5 };
            for index in 0..expected_rtos {
                let now = 1000 + index * 1000;
                if index == 0 || mode != "blackhole" {
                    let payload = vec![0x39; if mode == "backlogged" { 64 } else { 8 }];
                    assert_eq!(engine.write(&payload), payload.len());
                }
                for _ in 0..4 {
                    if !engine.poll_transmit(now, &mut cell) {
                        break;
                    }
                    if let Some(Frame::Data { seq, payload, .. }) = Frame::decode(&cell) {
                        ack_end = seq.wrapping_add(payload.len() as u32);
                        hub.send(destination, cell.clone()).await.unwrap();
                        break;
                    }
                }
                while f._outbox.try_recv().is_ok() {}
                while alternate_outbox.try_recv().is_ok() {}
                engine.on_timeout(now + 60);
                let mut got_rto = false;
                while let Some(event) = engine.poll_event() {
                    if let Event::DataRto {
                        consec_rto,
                        snd_una,
                        app_limited,
                    } = event
                    {
                        got_rto = true;
                        contexts.push(app_limited);
                        if mode == "legacy" {
                            hub.on_stream_data_rto(destination, 71, consec_rto, snd_una)
                                .await;
                        } else {
                            hub.on_stream_data_rto_with_demand(
                                destination,
                                71,
                                consec_rto,
                                snd_una,
                                app_limited,
                            )
                            .await;
                        }
                    }
                }
                assert!(
                    got_rto,
                    "test must exercise a real engine RTO: {mode} {index}"
                );
                if mode != "blackhole" {
                    // The repair is locally admitted before its ACK arrives.
                    for _ in 0..4 {
                        if !engine.poll_transmit(now + 61, &mut cell) {
                            break;
                        }
                        if matches!(Frame::decode(&cell), Some(Frame::Data { .. })) {
                            hub.send(destination, cell.clone()).await.unwrap();
                            break;
                        }
                    }
                    while f._outbox.try_recv().is_ok() {}
                    while alternate_outbox.try_recv().is_ok() {}
                    Frame::Ack {
                        stream_id: 71,
                        ack: ack_end,
                        win: 8192,
                        sacks: Default::default(),
                    }
                    .encode_into(&mut cell);
                    engine.on_cell(&cell, now + 62);
                }
                let pin = f
                    .cells
                    .stream_routes
                    .lock()
                    .await
                    .get(&(destination.node, 71, RouteClass::Bulk))
                    .cloned();
                replaced |= pin.is_none_or(|pin| !Arc::ptr_eq(&pin.circuit, &primary.circuit));
            }
            let total_rtos = primary.stats.as_ref().unwrap().snapshot().rto_events
                + alternate.stats.as_ref().unwrap().snapshot().rto_events;
            let cooled = !f.cells.route_cooldowns.lock().unwrap().is_empty();
            f.runtime.stop().await.unwrap();
            assert_eq!(total_rtos, expected_rtos, "RTO diagnostics were hidden");
            if mode == "isolated" || mode == "legacy" {
                assert!(contexts.iter().all(|limited| *limited));
            } else if mode == "backlogged" {
                assert!(contexts.iter().all(|limited| !limited));
            }
            if mode == "isolated" {
                assert!(
                    !replaced,
                    "acknowledged tiny writes replaced their route (rewind={rewind})"
                );
                assert!(!cooled, "a progressing app-limited stream cooled a path");
            } else {
                assert!(
                    replaced,
                    "backlog, blackhole or legacy recovery disabled: {mode} {rewind}"
                );
            }
        }
    }
}

#[tokio::test]
async fn confirmed_last_resort_route_can_recover_its_observed_cooldown() {
    for mode in [
        "recovered",
        "newer_relay_error",
        "newer_hop_error",
        "unconfirmed",
        "stale_generation",
        "dead_hop",
        "error_after_snapshot",
    ] {
        let mut f = fixture().await;
        let destination = Addr {
            node: [0xb9; 32],
            app: [0xbc; 32],
        };
        let mut ready = protected_route(&f.circuit, f.cells.me);
        ready
            .circuit
            .confirmed_flag()
            .store(mode != "unconfirmed", Ordering::Release);
        if mode == "stale_generation" {
            ready.first_hop_close_generation += 1;
        }
        while f._outbox.try_recv().is_ok() {}
        if mode != "error_after_snapshot" {
            mark_rendezvous_cooldown(&f.cells.route_cooldowns, f.hop, Duration::from_secs(60));
        }
        let observed = f.cells.route_cooldowns.lock().unwrap().clone();
        if mode == "newer_relay_error" || mode == "error_after_snapshot" {
            mark_rendezvous_cooldown(&f.cells.route_cooldowns, f.hop, Duration::from_secs(120));
        }
        if mode == "newer_hop_error" {
            mark_first_hop_cooldown(
                &f.cells.first_hop_cooldowns,
                f.hop,
                Duration::from_secs(120),
            );
        }
        if mode == "dead_hop" {
            f.cells
                .services
                .session_tx_registry
                .write()
                .unwrap()
                .unregister(&f.hop);
        }
        let expected_error = f.cells.route_cooldowns.lock().unwrap().get(&f.hop).copied();
        publish_outbound_candidates(
            &f.cells.services,
            destination.node,
            &f.cells.outbound_circuits,
            &[entry(&ready, &[])],
            OutboundCooldownRecovery {
                route_cooldowns: &f.cells.route_cooldowns,
                first_hop_cooldowns: &f.cells.first_hop_cooldowns,
                observed: &observed,
            },
        )
        .await;
        let selected = {
            let mut pool = f.cells.outbound_circuits.lock().await;
            f.cells.select_outbound_route(
                destination.node,
                pool.get_mut(&destination.node).unwrap(),
                Some(71),
                RouteClass::Bulk,
                Instant::now(),
            )
        };
        let current_error = f.cells.route_cooldowns.lock().unwrap().get(&f.hop).copied();
        let mut accepted = 0;
        if selected.is_some() {
            let mut cell = Vec::new();
            Frame::Data {
                stream_id: 71,
                seq: 101,
                win: 8192,
                payload: b"request",
            }
            .encode_into(&mut cell);
            f.cells.send(destination, cell).await.unwrap();
            while let Ok((lane, _)) = f._outbox.try_recv() {
                assert_eq!(lane, veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE);
                accepted += 1;
            }
        }
        f.runtime.stop().await.unwrap();
        if mode == "recovered" {
            assert!(
                selected.is_some(),
                "confirmed recovery stayed excluded by its old cooldown"
            );
            assert_eq!(current_error, None);
            assert_eq!(accepted, 1);
        } else {
            assert!(
                selected.is_none(),
                "ineligible recovery became usable: {mode}"
            );
            assert_eq!(
                current_error, expected_error,
                "newer or unproven failure was erased: {mode}"
            );
            assert_eq!(accepted, 0);
        }
    }
}

#[tokio::test]
async fn published_pool_prefix_is_usable_and_keeps_live_metadata_on_refill() {
    let mut f = fixture().await;
    let destination = Addr {
        node: [0xb9; 32],
        app: [0xbc; 32],
    };
    let primary = route(&f.circuit, f.cells.me);
    while f._outbox.try_recv().is_ok() {}
    let candidates = vec![entry(&primary, &[])];
    publish_outbound_candidates(
        &f.cells.services,
        destination.node,
        &f.cells.outbound_circuits,
        &candidates,
        OutboundCooldownRecovery {
            route_cooldowns: &f.cells.route_cooldowns,
            first_hop_cooldowns: &f.cells.first_hop_cooldowns,
            observed: &HashMap::new(),
        },
    )
    .await;
    // A later candidate is still warming, but the first confirmed route must
    // already carry the opener's SYN without waiting for the whole pool.
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let pending = tokio::spawn(async {
        let _ = release_rx.await;
    });
    f.cells.outbound_opening.lock().await.insert(
        destination.node,
        OutboundOpening::new(Instant::now(), PoolOpenIntent::Refresh),
    );
    let sent = tokio::time::timeout(
        Duration::from_millis(50),
        f.cells.send(destination, frames(71)[0].clone()),
    )
    .await;
    let mut cells_sent = 0;
    while f._outbox.try_recv().is_ok() {
        cells_sent += 1;
    }
    let active = primary.stats.as_ref().unwrap().active_streams();
    {
        let mut pool = f.cells.outbound_circuits.lock().await;
        let first = &mut pool.get_mut(&destination.node).unwrap()[0];
        first.note_handshake_stream(71);
        // Metadata changed by live traffic must survive the opener's old copy.
        first.last_non_handshake = first.opened_at + Duration::from_millis(1);
    }
    let (second, _, _second_outbox) = add_circuit(&f.cells.services);
    let second = route(&second, f.cells.me);
    let mut candidates = candidates;
    candidates.push(entry(&second, &[]));
    publish_outbound_candidates(
        &f.cells.services,
        destination.node,
        &f.cells.outbound_circuits,
        &candidates,
        OutboundCooldownRecovery {
            route_cooldowns: &f.cells.route_cooldowns,
            first_hop_cooldowns: &f.cells.first_hop_cooldowns,
            observed: &HashMap::new(),
        },
    )
    .await;
    let (ordered, preserved, same_activity, bounded) = {
        let pool = f.cells.outbound_circuits.lock().await;
        let entries = pool.get(&destination.node).unwrap();
        (
            Arc::ptr_eq(&entries[0].circuit, &primary.circuit)
                && Arc::ptr_eq(&entries[1].circuit, &second.circuit),
            entries[0].handshake_streams.contains(&71)
                && entries[0].last_non_handshake > entries[0].opened_at,
            entries[0].stats.active_streams() == active,
            entries.len() <= MAX_CIRCUIT_OUTBOUND_POOL,
        )
    };
    release_tx.send(()).unwrap();
    pending.await.unwrap();
    f.runtime.stop().await.unwrap();
    assert!(
        sent.expect("ready prefix waited for a later candidate")
            .is_ok()
    );
    assert_eq!(cells_sent, 1);
    assert!(active > 0);
    assert!(ordered && preserved && same_activity && bounded);
}

#[tokio::test]
async fn inbound_repair_ignores_backpressure_but_detects_a_closed_first_hop() {
    let mut f = fixture().await;
    let (healthy, healthy_hop, _healthy_outbox) = add_circuit(&f.cells.services);
    f.circuit.confirmed_flag().store(true, Ordering::Release);
    healthy.confirmed_flag().store(true, Ordering::Release);
    let snapshot = [Arc::clone(&f.circuit), healthy];
    let select = || {
        inbound_session_repair_relays(
            snapshot.iter().map(|c| {
                (
                    *c.relay_path().last().unwrap(),
                    f.cells.services.data_circuit_session_current(c),
                )
            }),
            true,
        )
    };
    fill_ordinary_outbox(&f.cells, &f.circuit);
    assert!(select().is_empty(), "a full queue is not a lost session");
    f._outbox.close();
    let affected = select();
    f.runtime.stop().await.unwrap();
    assert_eq!(affected, [f.hop].into_iter().collect());
    assert!(
        !affected.contains(&healthy_hop),
        "healthy receive path was rotated"
    );
}

/// A silent first registration must not keep a ready neighbour's receiver off.
/// The confirmation is held by an explicit gate, not a network-time threshold.
#[tokio::test]
async fn slow_confirmation_does_not_delay_other_inbound_feeds() {
    use std::{future::Future, task::Poll};
    let mut f = fixture().await;
    let (second, _hop, _outbox) = add_circuit(&f.cells.services);
    let (first_tx, first_rx) = mpsc::channel(4);
    let (second_tx, second_rx) = mpsc::channel(4);
    let (in_tx, mut in_rx) = mpsc::channel(4);
    let started = Arc::new(AtomicU64::new(0));
    let tasks = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(tokio::sync::Notify::new());
    let candidates = vec![(Arc::clone(&f.circuit), first_rx), (second, second_rx)];
    let mut activation = Box::pin(start_then_confirm_inbound(
        candidates,
        |(c, rx)| {
            started.fetch_add(1, Ordering::Relaxed);
            let task = spawn_circuit_feed(
                f.cells.services.clone(),
                rx,
                in_tx.clone(),
                None,
                None,
                Arc::clone(&f.cells.peer_tags),
                Some(c.confirmed_flag()),
            );
            tasks.lock().unwrap().push(task);
            c
        },
        |c| {
            let gate = Arc::clone(&gate);
            async move {
                gate.notified().await;
                c
            }
        },
    ));
    // Poll exactly to the held first confirmation. The operation cannot
    // advance past it until this test explicitly polls/releases it again.
    std::future::poll_fn(|cx| {
        assert!(activation.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let started_count = started.load(Ordering::Relaxed);
    let cell = Frame::Syn {
        stream_id: 91,
        isn: 500,
        win: 8192,
    }
    .encode();
    let mut envelope = [0x81; 32].to_vec();
    envelope.extend_from_slice(&cell);
    let mut received = false;
    if started_count == 2 {
        second_tx.send(envelope).await.unwrap();
        // Watchdog only; correctness is that the confirmation gate stays shut.
        received = tokio::time::timeout(Duration::from_secs(5), in_rx.recv())
            .await
            .unwrap()
            .is_some_and(|(_, got)| got == cell);
    }
    drop(activation);
    drop(first_tx);
    drop(second_tx);
    for task in tasks.lock().unwrap().drain(..) {
        task.abort();
    }
    f.runtime.stop().await.unwrap();
    assert_eq!(
        started_count, 2,
        "a pending confirmation prevented the other feed from starting"
    );
    assert!(
        received,
        "ready circuit did not deliver while its neighbour was unconfirmed"
    );
}
