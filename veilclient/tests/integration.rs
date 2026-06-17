//! Integration test: echo server + ping client through a local IpcServer.
//!
//! — verifies that `VeilClient::connect` / `bind` / `send` / `recv`
//! work end-to-end against the real IPC server running on the same node.
//!
//! Unix-only: `VeilClient` requires UnixStream.  Windows-native applications
//! talk to the IPC TCP backend via raw frames (see `examples/ovl_proto.py`).

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use veil_ipc::{IpcEndpoint, IpcServer};
use veilcore::node::app::{AppEndpointRegistry, address::app_id};

// ── helpers ───────────────────────────────────────────────────────────────────

fn node_id() -> [u8; 32] {
    [0x42u8; 32]
}

fn temp_socket() -> PathBuf {
    let id = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("veil-client-test-{}-{}.sock", id, ts))
}

async fn start_server(sock: PathBuf) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let registry = Arc::new(AppEndpointRegistry::new());
    let mut server = IpcServer::new(IpcEndpoint::Unix(sock), shutdown_rx, registry, node_id());
    let handle = tokio::spawn(async move {
        let _ = server.run().await;
    });
    // Give the server a moment to start listening.
    tokio::time::sleep(Duration::from_millis(30)).await;
    (shutdown_tx, handle)
}

// ── 35.6: echo server + client, single datagram round-trip ───────────────────

#[tokio::test]
async fn echo_roundtrip_via_veilclient() {
    let sock = temp_socket();
    let (shutdown_tx, server_handle) = start_server(sock.clone()).await;

    // Both app_ids are deterministic from the fixed node_id + namespace + name.
    let echo_app_id = app_id(&node_id(), "test.echo", "echo");
    let ping_app_id = app_id(&node_id(), "test.ping", "ping");

    // ── Echo server: bind endpoint 10, send back every message ───────────────
    let sock_echo = sock.clone();
    let ping_app_id_copy = ping_app_id;
    let echo_handle = tokio::spawn(async move {
        let client = veilclient::VeilClient::connect(&sock_echo).await.unwrap();
        let mut handle = client.bind_named("test.echo", "echo", 10).await.unwrap();
        // Receive one message, echo it back to ping's endpoint 20.
        if let Some(msg) = handle.recv().await.unwrap() {
            handle
                .send(msg.src_node_id, ping_app_id_copy, 20, &msg.data)
                .await
                .unwrap();
        }
    });

    // Give the echo server task a moment to bind.
    tokio::time::sleep(Duration::from_millis(30)).await;

    // ── Ping client: bind endpoint 20, send to echo server, receive reply ────
    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let mut handle = client.bind_named("test.ping", "ping", 20).await.unwrap();

    // Send to echo server's app_id + endpoint 10.
    handle
        .send(node_id(), echo_app_id, 10, b"ping")
        .await
        .unwrap();

    // Expect our echo back on endpoint 20.
    let reply = tokio::time::timeout(Duration::from_millis(500), handle.recv())
        .await
        .expect("timeout waiting for echo reply")
        .unwrap()
        .expect("connection closed before reply");

    assert_eq!(reply.data, b"ping");

    // ── Cleanup ───────────────────────────────────────────────────────────────
    let _ = echo_handle.await;
    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

// ── Bounded-channel regression: slow stream consumer is silently closed ──
//
// Audit batch 2026-05-23, HIGH-finding follow-up: per-stream `StreamEvent`
// queue in the SDK was `mpsc::unbounded_channel`, so an opener that opened
// a stream and then stopped reading let the daemon's STREAM_DATA frames
// accumulate unboundedly in SDK RAM.  On budget Android in hostile networks
// (the project's target platform) a malicious peer could flood STREAM_DATA
// frames faster than the consumer drained, exhausting RAM.
//
// Post-fix: per-stream queue is bounded to `STREAM_EVENT_QUEUE_CAP = 256`.
// A consumer that falls behind has its stream silently closed by the reader
// task (sender dropped from `dispatch.streams`), visible to the SDK as
// `VeilStream::read` returning EOF (0 bytes) after the drained backlog.
//
// This test asserts the budget IS bounded: it opens a stream, sends
// 4 × STREAM_EVENT_QUEUE_CAP = 1024 frames through the daemon back to the
// opener without that opener reading a single byte, then verifies the
// opener eventually sees EOF rather than memory growth.
#[tokio::test]
async fn stream_event_queue_is_bounded_on_slow_consumer() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let sock = temp_socket();
    let (shutdown_tx, server_handle) = start_server(sock.clone()).await;

    // Acceptor (B) binds endpoint 50.
    let sock_b = sock.clone();
    let acceptor_done_tx = std::sync::Arc::new(tokio::sync::Notify::new());
    let acceptor_done_rx = std::sync::Arc::clone(&acceptor_done_tx);
    let b_handle = tokio::spawn(async move {
        let client = veilclient::VeilClient::connect(&sock_b).await.unwrap();
        let mut handle = client
            .bind_named("test.stream.bounded", "acceptor", 50)
            .await
            .unwrap();
        // Wait for A's inbound stream.
        let inbound = tokio::time::timeout(Duration::from_secs(2), handle.accept_stream())
            .await
            .expect("timeout accepting stream")
            .expect("connection closed before stream arrived");
        let mut s = inbound.stream;
        // Flood A with way more than STREAM_EVENT_QUEUE_CAP (256) frames.
        // The daemon enforces flow control on A→B (windowed), but B→A in
        // route_data_from_b is unwindowed — that's exactly the path the
        // SDK bound-queue defends against.  Send 1024 small frames; SDK
        // is supposed to close A's stream after ~256 unread frames.
        for _ in 0..1024 {
            // Ignore write errors: the daemon may close mid-flood
            // when A's stream is reaped, which is the success case.
            if s.write_all(b"x").await.is_err() {
                break;
            }
        }
        // Signal the opener it can stop waiting.
        acceptor_done_rx.notify_one();
    });

    // Opener (A) opens a stream to B and THEN STOPS READING.
    let client_a = veilclient::VeilClient::connect(&sock).await.unwrap();
    let a_handle = client_a
        .bind_named("test.stream.bounded", "opener", 51)
        .await
        .unwrap();
    let acceptor_app_id = app_id(&node_id(), "test.stream.bounded", "acceptor");
    let mut stream = tokio::time::timeout(
        Duration::from_secs(2),
        a_handle.open_stream(node_id(), acceptor_app_id, 50, 65536),
    )
    .await
    .expect("timeout opening stream")
    .expect("open_stream failed");

    // Wait for the acceptor to finish flooding.
    tokio::time::timeout(Duration::from_secs(5), acceptor_done_tx.notified())
        .await
        .expect("flood timeout");

    // Now drain the stream — the post-fix invariant is that the SDK
    // closes the stream once the per-stream queue overflows, surfaced
    // here as `read` eventually returning Ok(0) (EOF) rather than
    // serving up the full 1024 frames OR blocking forever waiting for
    // memory to fill.  Read in a bounded loop with a deadline so a
    // regression (unbounded growth + no EOF) doesn't hang the test.
    let mut buf = [0u8; 64];
    let mut total = 0usize;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .unwrap_or(Duration::from_millis(0));
        if remaining.is_zero() {
            panic!(
                "stream did not EOF after STREAM_EVENT_QUEUE_CAP overflow; \
                 read {total} bytes before deadline.  Regression: bounded \
                 channel cap not enforced, slow consumer can pin unbounded RAM."
            );
        }
        let n = tokio::time::timeout(remaining, stream.read(&mut buf))
            .await
            .ok()
            .and_then(|r| r.ok());
        match n {
            Some(0) => break,      // EOF — bounded behaviour confirmed
            Some(k) => total += k, // drained a frame from the queue
            None => break,         // timeout while reading — also bounded
        }
        // sanity cap so a runaway test doesn't spin forever
        if total > 4 * 1024 * 1024 {
            panic!("stream emitted {total} bytes before EOF — bound looks ignored");
        }
    }

    // Cleanup.
    let _ = b_handle.await;
    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

// ── Flutter foundation IPC tests ─────────────────────

use std::sync::Mutex;
use veil_ipc::{
    BootstrapJoinOutcome, BootstrapJoinSink, MobileEventSink, MobileStatusProvider,
    PeerListProvider,
};
use veil_proto::{
    MobileBackgroundMode, MobileStatusPayload, NetworkChangedPayload, PeersListEntry,
    PeersListPayload, join_status, peer_direction, peer_state,
};

/// Spin up an IpcServer with the supplied sinks/providers + a custom
/// local identity (algo + pubkey).  Returns the socket path + shutdown
/// handle.  Mirrors `start_server` but exercises builder
/// methods so the test surface covers the full Flutter foundation API.
async fn start_server_full(
    sock: PathBuf,
    local_pubkey: Vec<u8>,
    local_algo: u8,
    mobile_sink: Option<Arc<dyn MobileEventSink>>,
    peer_list: Option<Arc<dyn PeerListProvider>>,
    bootstrap_join: Option<Arc<dyn BootstrapJoinSink>>,
    mobile_status: Option<Arc<dyn MobileStatusProvider>>,
) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let registry = Arc::new(AppEndpointRegistry::new());
    let mut server = IpcServer::new(IpcEndpoint::Unix(sock), shutdown_rx, registry, node_id())
        .with_local_identity(local_algo, local_pubkey);
    if let Some(s) = mobile_sink {
        server = server.with_mobile_event_sink(s);
    }
    if let Some(p) = peer_list {
        server = server.with_peer_list_provider(p);
    }
    if let Some(b) = bootstrap_join {
        server = server.with_bootstrap_join_sink(b);
    }
    if let Some(m) = mobile_status {
        server = server.with_mobile_status_provider(m);
    }
    let handle = tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    (shutdown_tx, handle)
}

#[tokio::test]
async fn get_node_identity_returns_daemon_pubkey() {
    let sock = temp_socket();
    let pubkey = vec![0xCDu8; 32]; // Ed25519-sized stub
    let (shutdown_tx, server_handle) =
        start_server_full(sock.clone(), pubkey.clone(), 0, None, None, None, None).await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let identity = client.node_identity().await.unwrap();

    assert_eq!(identity.node_id, node_id(), "node_id round-trips");
    assert_eq!(identity.algo, 0, "ed25519 wire byte");
    assert_eq!(identity.public_key, pubkey, "pubkey round-trips byte-exact");

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn get_peers_returns_provider_snapshot() {
    let sock = temp_socket();
    // Mock provider that always returns 2 fixed peers.
    struct MockPeers;
    impl PeerListProvider for MockPeers {
        fn list_peers(&self) -> PeersListPayload {
            PeersListPayload {
                peers: vec![
                    PeersListEntry {
                        node_id: [0xAA; 32],
                        state: peer_state::ACTIVE,
                        direction: peer_direction::OUTBOUND,
                        transport: b"tcp://1.2.3.4:5555".to_vec(),
                    },
                    PeersListEntry {
                        node_id: [0xBB; 32],
                        state: peer_state::CONNECTING,
                        direction: peer_direction::INBOUND,
                        transport: b"tcp://10.0.0.1:5555".to_vec(),
                    },
                ],
            }
        }
    }
    let provider: Arc<dyn PeerListProvider> = Arc::new(MockPeers);
    let (shutdown_tx, server_handle) = start_server_full(
        sock.clone(),
        vec![0u8; 32],
        0,
        None,
        Some(provider),
        None,
        None,
    )
    .await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let peers = client.peers().await.unwrap();

    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].node_id, [0xAA; 32]);
    assert_eq!(peers[0].state, peer_state::ACTIVE);
    assert_eq!(peers[0].direction, peer_direction::OUTBOUND);
    assert_eq!(peers[0].transport, "tcp://1.2.3.4:5555");
    assert_eq!(peers[1].node_id, [0xBB; 32]);
    assert_eq!(peers[1].direction, peer_direction::INBOUND);

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn get_peers_without_provider_returns_empty() {
    let sock = temp_socket();
    let (shutdown_tx, server_handle) = start_server_full(
        sock.clone(),
        vec![0u8; 32],
        0,
        None,
        None, // no provider — expect empty list, NOT a protocol error
        None,
        None,
    )
    .await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let peers = client.peers().await.unwrap();
    assert!(
        peers.is_empty(),
        "no provider → empty list, not protocol error"
    );

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn set_mobile_background_mode_propagates_to_sink() {
    let sock = temp_socket();
    // Mock sink that records every call.
    #[derive(Default)]
    struct RecordingSink {
        modes: Mutex<Vec<MobileBackgroundMode>>,
        networks: Mutex<Vec<NetworkChangedPayload>>,
    }
    impl MobileEventSink for RecordingSink {
        fn set_mobile_background_mode(&self, mode: MobileBackgroundMode) {
            self.modes.lock().unwrap().push(mode);
        }
        fn network_changed(&self, payload: NetworkChangedPayload) {
            self.networks.lock().unwrap().push(payload);
        }
    }
    let sink = Arc::new(RecordingSink::default());
    let sink_dyn: Arc<dyn MobileEventSink> = Arc::clone(&sink) as Arc<dyn MobileEventSink>;
    let (shutdown_tx, server_handle) = start_server_full(
        sock.clone(),
        vec![0u8; 32],
        0,
        Some(sink_dyn),
        None,
        None,
        None,
    )
    .await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    client
        .set_mobile_background_mode(MobileBackgroundMode::Active)
        .await
        .unwrap();
    client
        .set_mobile_background_mode(MobileBackgroundMode::LowPower)
        .await
        .unwrap();
    client
        .notify_network_changed(veilclient::NetworkKind::Cellular, 1280)
        .await
        .unwrap();

    // Allow the server-side dispatch task to drain the writes.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // chore: snapshot the lock contents into owned values
    // before the `.await` boundary so the `MutexGuard` doesn't cross
    // an await point (clippy::await_holding_lock).
    let modes_snapshot = sink.modes.lock().unwrap().clone();
    assert_eq!(
        modes_snapshot,
        vec![MobileBackgroundMode::Active, MobileBackgroundMode::LowPower],
        "mode transitions reach the sink in order"
    );
    let nets_snapshot = sink.networks.lock().unwrap().clone();
    assert_eq!(nets_snapshot.len(), 1);
    assert_eq!(
        nets_snapshot[0].kind,
        veil_proto::NetworkKind::Cellular,
        "network kind round-trips"
    );
    assert_eq!(nets_snapshot[0].mtu_hint, 1280, "mtu_hint round-trips");

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn join_bootstrap_uri_returns_sink_outcome() {
    let sock = temp_socket();
    // Mock sink that returns OK for one URI and SignatureInvalid for another.
    struct DispatchSink;
    impl BootstrapJoinSink for DispatchSink {
        fn join_uri(
            &self,
            uri: &str,
            _password: Option<&str>,
            _expected_issuer_pk: Option<&str>,
        ) -> BootstrapJoinOutcome {
            if uri.contains("good") {
                BootstrapJoinOutcome::Ok {
                    peer_node_id: [0xDE; 32],
                    detail: "dispatched".into(),
                }
            } else {
                BootstrapJoinOutcome::SignatureInvalid("bad signature".into())
            }
        }
    }
    let sink: Arc<dyn BootstrapJoinSink> = Arc::new(DispatchSink);
    let (shutdown_tx, server_handle) =
        start_server_full(sock.clone(), vec![0u8; 32], 0, None, None, Some(sink), None).await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();

    // Happy path.
    let ok = client
        .join_bootstrap_uri("veil:bootstrap?good", None, None)
        .await
        .unwrap();
    assert_eq!(ok.status, join_status::OK);
    assert_eq!(ok.peer_node_id, [0xDE; 32]);
    assert_eq!(ok.detail, "dispatched");

    // Error path.
    let err = client
        .join_bootstrap_uri("veil:signed-invite?bad", None, Some("issuer-pk"))
        .await
        .unwrap();
    assert_eq!(err.status, join_status::SIGNATURE_INVALID);
    assert_eq!(err.peer_node_id, [0u8; 32], "node_id zero-filled on error");
    assert_eq!(err.detail, "bad signature");

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn join_bootstrap_uri_without_sink_returns_internal_error() {
    let sock = temp_socket();
    let (shutdown_tx, server_handle) = start_server_full(
        sock.clone(),
        vec![0u8; 32],
        0,
        None,
        None,
        None, // no sink wired
        None,
    )
    .await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let result = client
        .join_bootstrap_uri("veil:bootstrap?pk=foo", None, None)
        .await
        .unwrap();
    assert_eq!(result.status, join_status::INTERNAL_ERROR);
    assert!(
        result.detail.contains("not wired"),
        "missing sink should surface 'feature not wired' detail, got: {}",
        result.detail
    );

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn get_mobile_status_returns_provider_snapshot() {
    let sock = temp_socket();
    // Mock provider returning a Active-tier + low-battery scenario.
    struct MockMobile;
    impl MobileStatusProvider for MockMobile {
        fn mobile_status(&self) -> MobileStatusPayload {
            MobileStatusPayload {
                background_tier: 1, // Active
                background_keepalive_multiplier: 60,
                background_keepalive_factor: 2,
                battery_level_pct: 25,
                low_battery_threshold_pct: 30,
                low_battery_multiplier: 4,
                battery_route_probe_factor: 4,
            }
        }
    }
    let provider: Arc<dyn MobileStatusProvider> = Arc::new(MockMobile);
    let (shutdown_tx, server_handle) = start_server_full(
        sock.clone(),
        vec![0u8; 32],
        0,
        None,
        None,
        None,
        Some(provider),
    )
    .await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let status = client.mobile_status().await.unwrap();

    assert_eq!(status.background_tier, 1);
    assert_eq!(status.background_keepalive_multiplier, 60);
    assert_eq!(status.background_keepalive_factor, 2);
    assert_eq!(status.battery_level_pct, 25);
    assert_eq!(status.low_battery_threshold_pct, 30);
    assert_eq!(status.low_battery_multiplier, 4);
    assert_eq!(status.battery_route_probe_factor, 4);

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn get_mobile_status_without_provider_returns_default() {
    let sock = temp_socket();
    let (shutdown_tx, server_handle) = start_server_full(
        sock.clone(),
        vec![0u8; 32],
        0,
        None,
        None,
        None,
        None, // no provider — expect default zero-state, NOT protocol error
    )
    .await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let status = client.mobile_status().await.unwrap();

    // Default = "feature off" — Foreground tier, multiplier=1, AC battery,
    // disabled threshold sentinel.
    assert_eq!(status.background_tier, 0);
    assert_eq!(status.background_keepalive_multiplier, 1);
    assert_eq!(status.background_keepalive_factor, 1);
    assert_eq!(
        status.battery_level_pct,
        veil_proto::MOBILE_BATTERY_AC_OR_UNKNOWN
    );
    assert_eq!(
        status.low_battery_threshold_pct,
        veil_proto::MOBILE_LOW_BATTERY_THRESHOLD_DISABLED,
    );

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn concurrent_node_identity_queries_match_in_order() {
    // Validates the FIFO oneshot dispatch in the SDK reader task —
    // two parallel queries must each get their reply matched in
    // order, not one cross-matched to the other.
    let sock = temp_socket();
    let (shutdown_tx, server_handle) =
        start_server_full(sock.clone(), vec![0u8; 32], 0, None, None, None, None).await;

    let client = Arc::new(veilclient::VeilClient::connect(&sock).await.unwrap());
    let c1 = Arc::clone(&client);
    let c2 = Arc::clone(&client);

    let (id1, id2) = tokio::join!(
        async move { c1.node_identity().await.unwrap() },
        async move { c2.node_identity().await.unwrap() },
    );
    assert_eq!(
        id1, id2,
        "concurrent queries return the same daemon identity"
    );
    assert_eq!(id1.node_id, node_id());

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

// ── push event stream tests ──────────────────────────

use veil_ipc::EventBus;
use veil_proto::{EventPayload, event_kind};

/// Spin up an IpcServer with an EventBus attached.
async fn start_server_with_bus(
    sock: PathBuf,
    bus: Arc<EventBus>,
) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let registry = Arc::new(AppEndpointRegistry::new());
    let mut server = IpcServer::new(IpcEndpoint::Unix(sock), shutdown_rx, registry, node_id())
        .with_event_bus(bus);
    let handle = tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    (shutdown_tx, handle)
}

#[tokio::test]
async fn event_bus_publishes_to_connected_client() {
    let sock = temp_socket();
    let bus = Arc::new(EventBus::new());
    let (shutdown_tx, server_handle) = start_server_with_bus(sock.clone(), Arc::clone(&bus)).await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let mut events = client.events().await;

    // Give the server a moment to register the new subscriber on the bus.
    // The accept-task path is: accept → spawn → handshake → enter loop →
    // bus.subscribe().  We also need our `events()` call (which sets the
    // SDK-side sink) to win the race against any frame already in flight.
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while bus.receiver_count() == 0 {
        if std::time::Instant::now() > deadline {
            panic!("server never subscribed to event bus");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Publish three distinct events.
    bus.publish(EventPayload {
        kind: event_kind::SESSIONS_CHANGED,
        payload: 7u16.to_be_bytes().to_vec(),
    });
    bus.publish(EventPayload {
        kind: event_kind::MOBILE_TIER_CHANGED,
        payload: vec![2u8],
    });
    bus.publish(EventPayload {
        kind: event_kind::IDENTITY_ROTATED,
        payload: vec![0xCDu8; 32],
    });

    // Receive all three with a generous per-event timeout.
    let e1 = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("first event timed out")
        .expect("event channel closed prematurely");
    assert_eq!(e1.kind, event_kind::SESSIONS_CHANGED);
    assert_eq!(e1.payload, 7u16.to_be_bytes().to_vec());

    let e2 = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("second event timed out")
        .expect("event channel closed prematurely");
    assert_eq!(e2.kind, event_kind::MOBILE_TIER_CHANGED);
    assert_eq!(e2.payload, vec![2u8]);

    let e3 = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("third event timed out")
        .expect("event channel closed prematurely");
    assert_eq!(e3.kind, event_kind::IDENTITY_ROTATED);
    assert_eq!(e3.payload, vec![0xCDu8; 32]);

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn event_bus_without_subscriber_publish_is_noop() {
    // Publishing on a bus with zero subscribers must not panic — this is
    // the steady state when the daemon comes up before any app
    // connects.
    let bus = EventBus::new();
    let observed = bus.publish(EventPayload {
        kind: 0,
        payload: vec![],
    });
    assert_eq!(observed, 0);
    assert_eq!(bus.receiver_count(), 0);
}

#[tokio::test]
async fn event_bus_oversized_payload_dropped_at_source() {
    // Defence-in-depth: oversized payloads must not propagate, even
    // if a buggy publisher forgets to clamp.  The IPC frame budget
    // would also reject them on encode, but dropping at the source
    // means slow consumers don't lag on a frame that would just be
    // refused anyway.
    let bus = EventBus::new();
    let _rx = bus.subscribe();
    let observed = bus.publish(EventPayload {
        kind: 0,
        payload: vec![0u8; veil_proto::MAX_EVENT_PAYLOAD_LEN + 1],
    });
    assert_eq!(observed, 0, "oversized payload must drop at the source");
}

#[tokio::test]
async fn event_bus_resubscribe_replaces_previous_sink() {
    // Calling events() twice — the second call replaces the first
    // sink, so events flow only into the most recent receiver.  This
    // matches the documented single-subscriber contract.
    let sock = temp_socket();
    let bus = Arc::new(EventBus::new());
    let (shutdown_tx, server_handle) = start_server_with_bus(sock.clone(), Arc::clone(&bus)).await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let mut events_first = client.events().await;
    let mut events_second = client.events().await;

    // Wait for server-side subscription to wire up.
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while bus.receiver_count() == 0 {
        if std::time::Instant::now() > deadline {
            panic!("server never subscribed to event bus");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    bus.publish(EventPayload {
        kind: event_kind::SESSIONS_CHANGED,
        payload: 1u16.to_be_bytes().to_vec(),
    });

    let received = tokio::time::timeout(Duration::from_secs(2), events_second.recv())
        .await
        .expect("second receiver timed out")
        .expect("event channel closed");
    assert_eq!(received.kind, event_kind::SESSIONS_CHANGED);

    // First receiver must have observed nothing (sink was replaced
    // before the publish).  Either it times out (sender still alive
    // somewhere) or recv returns None (sender dropped on replace) —
    // both mean "no event delivered to this receiver", which is the
    // contract.  We reject only the path where it actually yielded
    // a payload.
    match tokio::time::timeout(Duration::from_millis(150), events_first.recv()).await {
        Err(_) => {}   // timeout — fine
        Ok(None) => {} // channel closed when sink was replaced — fine
        Ok(Some(ev)) => panic!(
            "first receiver must not see events after resubscribe, got {:?}",
            ev
        ),
    }

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

// ── T1.4 P7a: mailbox / outbox / replica-lookup IPC tests ────────

use std::sync::Mutex as StdMutex;
use veil_ipc::{
    MailboxBackend, MailboxBlobOut, MailboxPutOutcome, OutboxBackend, OutboxEntryOut,
    RendezvousReplicaResolver, ResolvedReplica,
};

/// Mailbox blob entry: sender_id + payload + envelope-present flag.
type MockBlobEntry = ([u8; 32], Vec<u8>, bool);
/// Mailbox key: receiver_id + content_id.
type MockBlobKey = ([u8; 32], [u8; 32]);

/// Mock mailbox backend that records every call in Mutex'd vectors.
/// Simple HashMap by `(receiver, content_id)` to support fetch/ack.
struct MockMailbox {
    /// `(receiver, content_id) -> (sender, blob, envelope_present)`
    blobs: StdMutex<std::collections::HashMap<MockBlobKey, MockBlobEntry>>,
    /// Cookie that fetch/ack must match.  Stub: a single cookie per receiver.
    expected_cookie: [u8; 16],
}

impl MailboxBackend for MockMailbox {
    fn put(
        &self,
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        sender_id: [u8; 32],
        blob: Vec<u8>,
        push_envelope: Option<Vec<u8>>,
        _capability_token: Option<Vec<u8>>,
        _wake_hmac_envelope: Option<Vec<u8>>,
    ) -> Option<MailboxPutOutcome> {
        let mut g = self.blobs.lock().unwrap();
        if g.contains_key(&(receiver_id, content_id)) {
            return Some(MailboxPutOutcome::Duplicate);
        }
        g.insert(
            (receiver_id, content_id),
            (sender_id, blob, push_envelope.is_some()),
        );
        Some(MailboxPutOutcome::Stored { evicted: 0 })
    }

    fn fetch(&self, receiver_id: [u8; 32], auth_cookie: [u8; 16]) -> Option<Vec<MailboxBlobOut>> {
        if auth_cookie != self.expected_cookie {
            return Some(Vec::new());
        }
        let g = self.blobs.lock().unwrap();
        let mut out = Vec::new();
        for ((r, cid), (s, b, _env)) in g.iter() {
            if *r == receiver_id {
                out.push(MailboxBlobOut {
                    sender_id: *s,
                    content_id: *cid,
                    deposited_at: 0,
                    blob: b.clone(),
                });
            }
        }
        Some(out)
    }

    fn ack(
        &self,
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        auth_cookie: [u8; 16],
    ) -> Option<bool> {
        if auth_cookie != self.expected_cookie {
            return Some(false);
        }
        let mut g = self.blobs.lock().unwrap();
        Some(g.remove(&(receiver_id, content_id)).is_some())
    }
}

/// Mock outbox backend backed by a HashMap.
struct MockOutbox {
    entries: StdMutex<std::collections::HashMap<MockBlobKey, Vec<u8>>>,
}

impl OutboxBackend for MockOutbox {
    fn put(&self, receiver_id: [u8; 32], content_id: [u8; 32], blob: Vec<u8>) -> bool {
        self.entries
            .lock()
            .unwrap()
            .insert((receiver_id, content_id), blob);
        true
    }

    fn find_missing(
        &self,
        receiver_id: [u8; 32],
        _since: u64,
        _bloom_bytes: Vec<u8>,
    ) -> Option<Vec<OutboxEntryOut>> {
        // Mock ignores the bloom filter and returns everything for the receiver.
        let g = self.entries.lock().unwrap();
        let entries = g
            .iter()
            .filter(|((r, _), _)| *r == receiver_id)
            .map(|((_, cid), blob)| OutboxEntryOut {
                content_id: *cid,
                deposited_at: 0,
                blob: blob.clone(),
            })
            .collect();
        Some(entries)
    }

    fn ack(&self, receiver_id: [u8; 32], content_id: [u8; 32]) -> bool {
        self.entries
            .lock()
            .unwrap()
            .remove(&(receiver_id, content_id))
            .is_some()
    }
}

/// Mock resolver returns a hardcoded replica list for the requested receiver.
struct MockResolver {
    replicas: Vec<ResolvedReplica>,
}

impl RendezvousReplicaResolver for MockResolver {
    fn resolve_replicas<'a>(
        &'a self,
        _receiver_id: [u8; 32],
        max_replicas: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<ResolvedReplica>> + Send + 'a>>
    {
        let out = self.replicas.iter().take(max_replicas).cloned().collect();
        Box::pin(async move { out })
    }
}

async fn start_server_with_mailbox(
    sock: PathBuf,
    mailbox: Option<Arc<dyn MailboxBackend>>,
    outbox: Option<Arc<dyn OutboxBackend>>,
    resolver: Option<Arc<dyn RendezvousReplicaResolver>>,
) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let registry = Arc::new(AppEndpointRegistry::new());
    let mut server = IpcServer::new(IpcEndpoint::Unix(sock), shutdown_rx, registry, node_id());
    if let Some(m) = mailbox {
        server = server.with_mailbox_backend(m);
    }
    if let Some(o) = outbox {
        server = server.with_outbox_backend(o);
    }
    if let Some(r) = resolver {
        server = server.with_rendezvous_resolver(r);
    }
    let handle = tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    (shutdown_tx, handle)
}

#[tokio::test]
async fn t1_4_p7a_mailbox_put_fetch_ack_round_trip() {
    let sock = temp_socket();
    let cookie = [0xAB; 16];
    let mailbox: Arc<dyn MailboxBackend> = Arc::new(MockMailbox {
        blobs: StdMutex::new(std::collections::HashMap::new()),
        expected_cookie: cookie,
    });
    let (shutdown_tx, server_handle) =
        start_server_with_mailbox(sock.clone(), Some(Arc::clone(&mailbox)), None, None).await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let receiver = [11u8; 32];
    let cid = [22u8; 32];
    let sender = [33u8; 32];

    // Put.
    let reply = client
        .mailbox_put(
            receiver,
            cid,
            sender,
            b"opaque-blob".to_vec(),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        reply.status,
        veilclient::MailboxPutStatus::Stored,
        "expected Stored, got {:?}",
        reply.status,
    );

    // Fetch with correct cookie.
    let blobs = client.mailbox_fetch(receiver, cookie).await.unwrap();
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].content_id, cid);
    assert_eq!(blobs[0].blob, b"opaque-blob");

    // Fetch with wrong cookie returns empty.
    let blobs = client.mailbox_fetch(receiver, [0u8; 16]).await.unwrap();
    assert!(blobs.is_empty());

    // Ack.
    let removed = client.mailbox_ack(receiver, cid, cookie).await.unwrap();
    assert!(removed);

    // After ack, fetch returns empty.
    let blobs = client.mailbox_fetch(receiver, cookie).await.unwrap();
    assert!(blobs.is_empty());

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn t1_4_p7a_mailbox_put_no_backend_returns_not_relay() {
    let sock = temp_socket();
    let (shutdown_tx, server_handle) =
        start_server_with_mailbox(sock.clone(), None, None, None).await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let reply = client
        .mailbox_put(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            b"x".to_vec(),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(reply.status, veilclient::MailboxPutStatus::NotMailboxRelay,);

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn t1_4_p7a_mailbox_put_duplicate_status() {
    let sock = temp_socket();
    let mailbox: Arc<dyn MailboxBackend> = Arc::new(MockMailbox {
        blobs: StdMutex::new(std::collections::HashMap::new()),
        expected_cookie: [0u8; 16],
    });
    let (shutdown_tx, server_handle) =
        start_server_with_mailbox(sock.clone(), Some(mailbox), None, None).await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let recv = [1u8; 32];
    let cid = [2u8; 32];
    let _ = client
        .mailbox_put(recv, cid, [9u8; 32], b"a".to_vec(), None, None, None)
        .await
        .unwrap();
    let reply2 = client
        .mailbox_put(recv, cid, [9u8; 32], b"b".to_vec(), None, None, None)
        .await
        .unwrap();
    assert_eq!(reply2.status, veilclient::MailboxPutStatus::Duplicate);

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn t1_4_p7a_outbox_put_find_missing_ack_round_trip() {
    let sock = temp_socket();
    let outbox: Arc<dyn OutboxBackend> = Arc::new(MockOutbox {
        entries: StdMutex::new(std::collections::HashMap::new()),
    });
    let (shutdown_tx, server_handle) =
        start_server_with_mailbox(sock.clone(), None, Some(outbox), None).await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let recv = [11u8; 32];

    // Put two entries.
    assert!(
        client
            .outbox_put(recv, [b'A'; 32], b"a".to_vec())
            .await
            .unwrap()
    );
    assert!(
        client
            .outbox_put(recv, [b'B'; 32], b"b".to_vec())
            .await
            .unwrap()
    );

    // Find missing — mock returns everything.
    let missing = client
        .outbox_find_missing(recv, 0, vec![1, 0, 0, 0, 0])
        .await
        .unwrap();
    assert_eq!(missing.len(), 2);

    // Ack one, find_missing returns one.
    let removed = client.outbox_ack(recv, [b'A'; 32]).await.unwrap();
    assert!(removed);
    let missing = client
        .outbox_find_missing(recv, 0, vec![1, 0, 0, 0, 0])
        .await
        .unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].content_id, [b'B'; 32]);

    // Idempotent ack.
    let removed_again = client.outbox_ack(recv, [b'A'; 32]).await.unwrap();
    assert!(!removed_again);

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn t1_4_p7a_outbox_put_no_backend_returns_false() {
    let sock = temp_socket();
    let (shutdown_tx, server_handle) =
        start_server_with_mailbox(sock.clone(), None, None, None).await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let stored = client
        .outbox_put([1u8; 32], [2u8; 32], b"x".to_vec())
        .await
        .unwrap();
    assert!(!stored);

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn t1_4_p7a_lookup_rendezvous_replicas_returns_resolver_output() {
    let sock = temp_socket();
    let resolver: Arc<dyn RendezvousReplicaResolver> = Arc::new(MockResolver {
        replicas: vec![
            ResolvedReplica {
                relay_node_id: [1u8; 32],
                valid_until_unix: 1_700_000_000,
                push_envelope: vec![0xAA; 32],
                capability_token: vec![],
                // Epic 489.10 slice 2b: a non-empty wake-HMAC envelope must
                // survive the ResolvedReplica → ReplicaWire (3rd trailer) →
                // RendezvousReplicaInfo round-trip through the live IPC pipe.
                wake_hmac_envelope: vec![0xC7; 48],
                rendezvous_kem_algo: 0,
                rendezvous_kem_pk: vec![],
            },
            ResolvedReplica {
                relay_node_id: [2u8; 32],
                valid_until_unix: 1_700_000_500,
                push_envelope: vec![],
                capability_token: vec![],
                wake_hmac_envelope: vec![],
                rendezvous_kem_algo: 0,
                rendezvous_kem_pk: vec![],
            },
        ],
    });
    let (shutdown_tx, server_handle) =
        start_server_with_mailbox(sock.clone(), None, None, Some(resolver)).await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let entries = client
        .lookup_rendezvous_replicas([7u8; 32], 8)
        .await
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].relay_node_id, [1u8; 32]);
    assert_eq!(entries[0].push_envelope, vec![0xAA; 32]);
    // wake_hmac_envelope round-trips end-to-end so the SDK caller can feed
    // entries[0].wake_hmac_envelope into mailbox_put(.., wake_hmac_envelope).
    assert_eq!(entries[0].wake_hmac_envelope, vec![0xC7; 48]);
    assert_eq!(entries[1].push_envelope, Vec::<u8>::new());
    assert_eq!(entries[1].wake_hmac_envelope, Vec::<u8>::new());

    // max_replicas caps the result.
    let entries = client
        .lookup_rendezvous_replicas([7u8; 32], 1)
        .await
        .unwrap();
    assert_eq!(entries.len(), 1);

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

#[tokio::test]
async fn t1_4_p7a_lookup_rendezvous_replicas_no_resolver_returns_empty() {
    let sock = temp_socket();
    let (shutdown_tx, server_handle) =
        start_server_with_mailbox(sock.clone(), None, None, None).await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let entries = client
        .lookup_rendezvous_replicas([7u8; 32], 8)
        .await
        .unwrap();
    assert!(entries.is_empty());

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}

// ── chat_node wedge mitigation: SDK bind timeout ────────────────────────────

/// Stub IPC server that completes the HELLO handshake but never sends
/// `AppBindOk` / `AppBindErr`.  Models the failure mode where the
/// daemon's routing layer is still initializing right after a
/// `systemctl restart veil` cascade — pre-fix this wedged the
/// client forever.
async fn start_unresponsive_bind_server(
    sock: PathBuf,
) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use veil_proto::{
        AppIpcHelloOkPayload, AppIpcHelloPayload, codec,
        family::{FrameFamily, LocalAppMsg},
        header::FrameHeader,
    };

    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let listener = UnixListener::bind(&sock).unwrap();
    let handle = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut hdr_buf = [0u8; veil_proto::HEADER_SIZE];
            let _ = stream.read_exact(&mut hdr_buf).await;
            if let Ok(h) = codec::decode_header(&hdr_buf)
                && h.body_len > 0
                && h.body_len < 4096
            {
                let mut body = vec![0u8; h.body_len as usize];
                let _ = stream.read_exact(&mut body).await;
                if AppIpcHelloPayload::decode(&body).is_ok() {
                    let ok = AppIpcHelloOkPayload {
                        version: veil_proto::IPC_PROTOCOL_VERSION,
                        client_token: [0u8; 16],
                    };
                    let body = ok.encode();
                    let mut hdr = FrameHeader::new(
                        FrameFamily::LocalApp as u8,
                        LocalAppMsg::AppHelloOk as u16,
                    );
                    hdr.body_len = body.len() as u32;
                    let _ = stream.write_all(&codec::encode_header(&hdr)).await;
                    let _ = stream.write_all(&body).await;
                }
            }
            // Drain APP_BIND but never reply — emulate wedged daemon.
            let _ = stream.read_exact(&mut hdr_buf).await;
            if let Ok(h) = codec::decode_header(&hdr_buf)
                && h.body_len > 0
                && h.body_len < 4096
            {
                let mut body = vec![0u8; h.body_len as usize];
                let _ = stream.read_exact(&mut body).await;
            }
            // Hold connection open silently — bind must time out client-side.
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf).await;
        }
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    (shutdown_tx, handle)
}

#[tokio::test]
async fn t1_4_followup_bind_times_out_when_daemon_unresponsive() {
    // Pause the test clock so we don't have to wait 30 real seconds.
    tokio::time::pause();

    let sock = temp_socket();
    let (shutdown_tx, server_handle) = start_unresponsive_bind_server(sock.clone()).await;

    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let bind_handle =
        tokio::spawn(async move { client.bind_named("myapp.example", "test", 1).await });
    // Let the bind future park on the timeout, then advance the
    // virtual clock past 30 s.
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::time::advance(Duration::from_secs(31)).await;
    let res = bind_handle.await.unwrap();

    match res {
        Err(veilclient::ClientError::Protocol(msg)) => {
            assert!(
                msg.contains("bind timeout"),
                "expected 'bind timeout' in error message, got: {msg}",
            );
        }
        Err(e) => panic!("expected Protocol/'bind timeout', got error: {e}"),
        Ok(_) => panic!("expected timeout error, got Ok(AppHandle)"),
    }

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
}
