//! Drive the real connector through its failure-to-backoff boundary. Error
//! formatting is synchronous and happens after the outer dial select chose Err,
//! so the fixture can deliver a broadcast in that exact gap without sleeps.
use super::tests::{runtime_config_with_listen, save_test_config};
use super::*;
use futures::future::BoxFuture;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use veil_transport::{
    Transport, TransportCapabilities, TransportConnection, TransportListener, TransportUri,
};

#[derive(Clone, Copy)]
enum Wake {
    Network,
    Connectivity,
    None,
    NetworkWhileBanned,
}

struct Gate {
    formats: AtomicUsize,
    calls: AtomicUsize,
    on_gap: Box<dyn Fn() + Send + Sync>,
    gap: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    second: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

struct AtFailure(Arc<Gate>);
impl fmt::Debug for AtFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fixture dial failure")
    }
}
impl std::error::Error for AtFailure {}
impl fmt::Display for AtFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // First formatting: NodeServices records the transport error before
        // returning it. Second: the connector selected Err and is about to
        // decide its retry pause. No formatter runs in the fixture transport.
        if self.0.formats.fetch_add(1, Ordering::SeqCst) == 1 {
            (self.0.on_gap)();
            if let Some(tx) = self.0.gap.lock().unwrap().take() {
                let _ = tx.send(());
            }
        }
        f.write_str("fixture refused dial")
    }
}
struct FailureTransport(Arc<Gate>);
impl Transport for FailureTransport {
    fn scheme(&self) -> &'static str {
        "tcp"
    }
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities::stream_connection()
    }
    fn connect<'a>(
        &'a self,
        _: &'a TransportUri,
        _: Arc<TransportContext>,
    ) -> BoxFuture<'a, veil_transport::error::Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            if self.0.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(std::io::Error::other(AtFailure(self.0.clone())).into())
            } else {
                if let Some(tx) = self.0.second.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                std::future::pending().await
            }
        })
    }
    fn bind<'a>(
        &'a self,
        _: &'a TransportUri,
        _: Arc<TransportContext>,
    ) -> BoxFuture<'a, veil_transport::error::Result<Box<dyn TransportListener>>> {
        Box::pin(async { unreachable!("dial-only fixture") })
    }
}

async fn retry_wake_gap_fixture(wake: Wake) {
    let mut config = runtime_config_with_listen();
    config.peers.clear();
    config.bootstrap_peers.clear();
    config.listen.clear();
    config.global.meeting_points = veil_cfg::MeetingPoints::Only(Vec::new());
    config.global.builtin_seed_policy = veil_cfg::BuiltinSeedPolicy::Never;
    config.pex.enabled = false;
    config.identity.as_mut().unwrap().lazy_mining = false;
    config.connection.reconnect_backoff_min_ms = 60_000;
    config.connection.reconnect_backoff_max_ms = 60_000;
    let path = save_test_config("retry-wake-gap", config).unwrap();
    let mut runtime = NodeRuntime::start(&path, true).await.unwrap();
    let mut services = runtime.access();
    let keys = crate::test_support::ed25519_keypair();
    let peer = crate::types::PeerConfigEntry {
        peer_id: PeerId::new(1),
        node_id: NodeId::from_public_key(veil_cfg::SignatureAlgorithm::Ed25519, &keys.public_key)
            .unwrap(),
        public_key: keys.public_key,
        nonce: veil_cfg::default_nonce_base64(),
        transport: "tcp://127.0.0.1:9".into(),
        algo: veil_cfg::SignatureAlgorithm::Ed25519,
        tls_cert: None,
        tls_key: None,
        tls_ca_cert: None,
        bootstrap_only: true,
        source: crate::types::PeerSource::Bootstrap,
    };
    let peer_node = *peer.node_id.as_bytes();
    let forced = services.force_reconnect_notify.clone();
    let gain = services.connectivity_gain.clone();
    let banned = services.dispatcher.abuse.ban_list.clone();
    let (gap_tx, gap_rx) = tokio::sync::oneshot::channel();
    let (second_tx, mut second_rx) = tokio::sync::oneshot::channel();
    let gate = Arc::new(Gate {
        formats: AtomicUsize::new(0),
        calls: AtomicUsize::new(0),
        gap: Mutex::new(Some(gap_tx)),
        second: Mutex::new(Some(second_tx)),
        on_gap: Box::new(move || match wake {
            Wake::Network => forced.notify_waiters(),
            Wake::Connectivity => gain.on_outbound_session_established(),
            Wake::None => {}
            Wake::NetworkWhileBanned => {
                banned
                    .lock()
                    .unwrap()
                    .ban_manual(peer_node, "fixture ban remains authoritative");
                forced.notify_waiters();
            }
        }),
    });
    let mut registry = veil_transport::TransportRegistry::new();
    registry.register(Arc::new(FailureTransport(gate.clone())));
    services.registry = Arc::new(registry);
    services
        .state
        .lock()
        .unwrap()
        .peers
        .insert(peer.peer_id, peer.clone());
    let (shutdown, _) = tokio::sync::watch::channel(false);
    let handles = crate::outbound_connector::spawn_outbound_peers(vec![peer], &services, &shutdown);
    assert_eq!(handles.len(), 1);
    // Only a fixture watchdog: the property below uses no elapsed-time bound.
    let reached = tokio::time::timeout(std::time::Duration::from_secs(10), gap_rx).await;
    // On this current-thread executor the connector continues synchronously
    // from formatting until it parks. A retained broadcast starts dial two
    // before that park; a lost broadcast parks on the unchanged 60-s pause.
    let retried_without_timer = second_rx.try_recv().is_ok();
    let formats = gate.formats.load(Ordering::SeqCst);
    let is_banned = services
        .dispatcher
        .abuse
        .ban_list
        .lock()
        .unwrap()
        .is_banned(&peer_node);
    let _ = shutdown.send(true);
    for handle in handles {
        handle.await.unwrap();
    }
    runtime.stop().await.unwrap();
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
    assert!(
        matches!(reached, Ok(Ok(()))),
        "fixture never reached selected-error formatting"
    );
    assert_eq!(
        formats, 2,
        "the gap must follow the transport and connector formats"
    );
    assert_eq!(is_banned, matches!(wake, Wake::NetworkWhileBanned));
    assert_eq!(
        retried_without_timer,
        matches!(wake, Wake::Network | Wake::Connectivity),
        "a broadcast in the failure-to-backoff gap was lost, or retry bypassed the unchanged pause/ban"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn retry_wake_gap_retains_network_change() {
    retry_wake_gap_fixture(Wake::Network).await;
}
#[tokio::test(flavor = "current_thread")]
async fn retry_wake_gap_retains_connectivity_gain() {
    retry_wake_gap_fixture(Wake::Connectivity).await;
}
#[tokio::test(flavor = "current_thread")]
async fn retry_wake_gap_without_event_preserves_backoff() {
    retry_wake_gap_fixture(Wake::None).await;
}
#[tokio::test(flavor = "current_thread")]
async fn retry_wake_gap_does_not_bypass_ban() {
    retry_wake_gap_fixture(Wake::NetworkWhileBanned).await;
}

/// A retained gain must not let our own successful handshake erase the
/// stillborn-session backoff. Complete a real TCP/OVL1 handshake, then close
/// the peer immediately. The next dial is observed at the Transport boundary,
/// before it can depend on OS readiness or a second handshake.
#[tokio::test(flavor = "current_thread")]
async fn retry_wake_own_success_preserves_refused_session_pause() {
    struct CountDials {
        calls: AtomicUsize,
        second: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    }
    impl Transport for CountDials {
        fn scheme(&self) -> &'static str {
            "tcp"
        }
        fn capabilities(&self) -> TransportCapabilities {
            TransportCapabilities::stream_connection()
        }
        fn connect<'a>(
            &'a self,
            uri: &'a TransportUri,
            ctx: Arc<TransportContext>,
        ) -> BoxFuture<'a, veil_transport::error::Result<Box<dyn TransportConnection>>> {
            Box::pin(async move {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    veil_transport::TransportRegistry::with_defaults()
                        .connect(uri, ctx)
                        .await
                } else {
                    if let Some(tx) = self.second.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                    std::future::pending().await
                }
            })
        }
        fn bind<'a>(
            &'a self,
            _: &'a TransportUri,
            _: Arc<TransportContext>,
        ) -> BoxFuture<'a, veil_transport::error::Result<Box<dyn TransportListener>>> {
            Box::pin(async { unreachable!("dial-only fixture") })
        }
    }

    let mut config = runtime_config_with_listen();
    config.peers.clear();
    config.bootstrap_peers.clear();
    config.listen.clear();
    config.global.meeting_points = veil_cfg::MeetingPoints::Only(Vec::new());
    config.global.builtin_seed_policy = veil_cfg::BuiltinSeedPolicy::Never;
    config.pex.enabled = false;
    config.identity.as_mut().unwrap().lazy_mining = false;
    config.connection.reconnect_backoff_min_ms = 60_000;
    config.connection.reconnect_backoff_max_ms = 60_000;
    let path = save_test_config("retry-wake-own-gain", config).unwrap();
    let mut runtime = NodeRuntime::start(&path, true).await.unwrap();
    let mut services = runtime.access();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let keys = crate::test_support::ed25519_keypair();
    let identity = HandshakeIdentity {
        algo: veil_cfg::SignatureAlgorithm::Ed25519,
        node_id: NodeId::from_public_key(veil_cfg::SignatureAlgorithm::Ed25519, &keys.public_key)
            .unwrap(),
        public_key: keys.public_key.clone(),
        private_key: keys.private_key,
        nonce: veil_cfg::default_nonce_base64(),
    };
    let peer = crate::types::PeerConfigEntry {
        peer_id: PeerId::new(1),
        node_id: identity.node_id,
        public_key: keys.public_key,
        nonce: identity.nonce.clone(),
        transport: format!("tcp://{}", listener.local_addr().unwrap()),
        algo: identity.algo,
        tls_cert: None,
        tls_key: None,
        tls_ca_cert: None,
        bootstrap_only: true,
        source: crate::types::PeerSource::Bootstrap,
    };
    let (second_tx, mut second_rx) = tokio::sync::oneshot::channel();
    let transport = Arc::new(CountDials {
        calls: AtomicUsize::new(0),
        second: Mutex::new(Some(second_tx)),
    });
    let mut registry = veil_transport::TransportRegistry::new();
    registry.register(transport.clone());
    services.registry = Arc::new(registry);
    services
        .state
        .lock()
        .unwrap()
        .peers
        .insert(peer.peer_id, peer.clone());
    let mut own_gain = Box::pin(services.connectivity_gain.retry_wake());
    let (shutdown, _) = tokio::sync::watch::channel(false);
    let handles = crate::outbound_connector::spawn_outbound_peers(vec![peer], &services, &shutdown);
    let exercised = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (mut stream, _) = listener.accept().await.unwrap();
        veil_session::handshake::perform_ovl1_handshake(
            &mut stream,
            &identity,
            veil_cfg::NodeRole::Core,
            veil_cfg::DiscoveryMode::Public,
            None,
            None,
            None,
            Some([0; 32]),
            None,
            None,
            None,
            &[],
            false,
            true,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        // Registration is not sufficient: the connector publishes gain later.
        (&mut own_gain).await;
        assert!(
            !runtime.sessions().is_empty(),
            "fixture never established a session"
        );
        drop(stream);
        // live_sessions is removed by the guard AFTER the refusal pause.
        // Observe the actual TX teardown, which precedes that pause.
        while services
            .session_tx_registry
            .read()
            .unwrap()
            .has_session(identity.node_id.as_bytes())
        {
            tokio::task::yield_now().await;
        }
        // The runner can wake its connector after removing session state.
        // Let that task resume through its synchronous teardown to its next
        // suspension; a mistaken self-wake starts dial two before that park.
        tokio::task::yield_now().await;
    })
    .await;
    let retried_without_timer = second_rx.try_recv().is_ok();
    let _ = shutdown.send(true);
    for handle in handles {
        handle.await.unwrap();
    }
    drop(own_gain);
    runtime.stop().await.unwrap();
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
    assert!(
        exercised.is_ok(),
        "fixture did not close an established session"
    );
    assert!(
        !retried_without_timer,
        "own success bypassed the refusal pause"
    );
}
