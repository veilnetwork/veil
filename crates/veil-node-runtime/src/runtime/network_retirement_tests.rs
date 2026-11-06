//! A real authenticated TCP session must redial after NetworkChanged even
//! when its old writer cannot make progress. No peer EOF or timer can rescue
//! the retirement-to-dial boundary asserted below.
use super::tests::{runtime_config_with_listen, save_test_config};
use super::*;
use futures::{FutureExt, future::BoxFuture};
use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use veil_transport::{
    BoxIoStream, PeerMeta, Transport, TransportCapabilities, TransportConnection,
    TransportListener, TransportUri,
};

#[derive(Default)]
struct Gate {
    blocked: AtomicBool,
    old_dropped: AtomicBool,
    dials: AtomicUsize,
    write_blocked: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    redial: Mutex<Option<tokio::sync::oneshot::Sender<bool>>>,
}

struct GateIo {
    inner: BoxIoStream,
    gate: Arc<Gate>,
}
impl AsyncRead for GateIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for GateIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.gate.blocked.load(Ordering::SeqCst) {
            if let Some(tx) = self.gate.write_blocked.lock().unwrap().take() {
                let _ = tx.send(());
            }
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl Drop for GateIo {
    fn drop(&mut self) {
        self.gate.old_dropped.store(true, Ordering::SeqCst);
    }
}

struct GateConnection {
    inner: Box<dyn TransportConnection>,
    gate: Arc<Gate>,
}
impl TransportConnection for GateConnection {
    fn capabilities(&self) -> &TransportCapabilities {
        self.inner.capabilities()
    }
    fn peer_meta(&self) -> &PeerMeta {
        self.inner.peer_meta()
    }
    fn into_stream(self: Box<Self>) -> veil_transport::Result<BoxIoStream> {
        Ok(Box::new(GateIo {
            inner: self.inner.into_stream()?,
            gate: self.gate,
        }))
    }
    fn close<'a>(&'a mut self) -> BoxFuture<'a, veil_transport::Result<()>> {
        self.inner.close()
    }
}

struct GateTransport(Arc<Gate>);
impl Transport for GateTransport {
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
    ) -> BoxFuture<'a, veil_transport::Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let first = self.0.dials.fetch_add(1, Ordering::SeqCst) == 0;
            if !first && let Some(tx) = self.0.redial.lock().unwrap().take() {
                let _ = tx.send(self.0.old_dropped.load(Ordering::SeqCst));
            }
            let inner = veil_transport::TransportRegistry::with_defaults()
                .connect(uri, ctx)
                .await?;
            if first {
                Ok(Box::new(GateConnection {
                    inner,
                    gate: self.0.clone(),
                }) as Box<dyn TransportConnection>)
            } else {
                Ok(inner)
            }
        })
    }
    fn bind<'a>(
        &'a self,
        _: &'a TransportUri,
        _: Arc<TransportContext>,
    ) -> BoxFuture<'a, veil_transport::Result<Box<dyn TransportListener>>> {
        Box::pin(async { unreachable!("dial-only fixture") })
    }
}

async fn handshake(
    stream: &mut tokio::net::TcpStream,
    identity: &HandshakeIdentity,
) -> veil_session::handshake::OvlHandshakeResult {
    veil_session::handshake::perform_ovl1_handshake(
        stream,
        identity,
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
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn network_retirement_redials_and_sends_on_a_fresh_authenticated_session() {
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
    let path = save_test_config("network-retirement", config).unwrap();
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
    let (blocked_tx, blocked_rx) = tokio::sync::oneshot::channel();
    let (redial_tx, mut redial_rx) = tokio::sync::oneshot::channel();
    let gate = Arc::new(Gate {
        write_blocked: Mutex::new(Some(blocked_tx)),
        redial: Mutex::new(Some(redial_tx)),
        ..Default::default()
    });
    let mut registry = veil_transport::TransportRegistry::new();
    registry.register(Arc::new(GateTransport(gate.clone())));
    services.registry = Arc::new(registry);
    services
        .state
        .lock()
        .unwrap()
        .peers
        .insert(peer.peer_id, peer.clone());
    let mut gained = Box::pin(services.connectivity_gain.retry_wake());
    let (shutdown, _) = tokio::sync::watch::channel(false);
    let handles = crate::outbound_connector::spawn_outbound_peers(vec![peer], &services, &shutdown);
    // Watchdog only. The regression assertion is made with paused virtual time
    // and runnable yields, before any timer/peer EOF can release the old writer.
    let mut clock_paused = false;
    let exercised = tokio::time::timeout(
        std::time::Duration::from_secs(12),
        std::panic::AssertUnwindSafe(async {
            let (mut old_peer, _) = listener.accept().await.unwrap();
            let old = handshake(&mut old_peer, &identity).await;
            (&mut gained).await;
            let old_registration = services
                .session_tx_registry
                .read()
                .unwrap()
                .live_registration(identity.node_id.as_bytes())
                .unwrap();
            gate.blocked.store(true, Ordering::SeqCst);
            let producer = services
                .session_tx_registry
                .read()
                .unwrap()
                .get_sender(identity.node_id.as_bytes())
                .unwrap()
                .clone();
            producer
                .try_send((
                    veil_proto::priority::INTERACTIVE,
                    veil_bufpool::pooled_shared_from_vec(
                        crate::outbound_connector::build_session_keepalive_frame(),
                    ),
                ))
                .unwrap();
            blocked_rx.await.unwrap();
            tokio::time::pause();
            clock_paused = true;
            let decision_at = tokio::time::Instant::now();
            use veil_ipc::MobileEventSink;
            crate::mobile_sink::MobileEventForwarder::new(
                services.logger.clone(),
                services.gateway_failover_notify.clone(),
                services.force_reconnect_notify.clone(),
                services.session_tx_registry.clone(),
            )
            .network_changed(veil_proto::NetworkChangedPayload {
                kind: veil_proto::NetworkKind::Cellular,
                mtu_hint: 0,
            });
            let mut redial = None;
            for _ in 0..64 {
                tokio::task::yield_now().await;
                if let Ok(dropped_before_redial) = redial_rx.try_recv() {
                    redial = Some(dropped_before_redial);
                    break;
                }
            }
            let no_timer_paid = tokio::time::Instant::now() == decision_at;
            tokio::time::resume();
            clock_paused = false;
            if redial != Some(true) || !no_timer_paid {
                return (redial, no_timer_paid, false);
            }
            let (mut new_peer, _) = listener.accept().await.unwrap();
            let new = handshake(&mut new_peer, &identity).await;
            while services
                .session_tx_registry
                .read()
                .unwrap()
                .live_registration(identity.node_id.as_bytes())
                .is_none_or(|r| r == old_registration)
            {
                tokio::task::yield_now().await;
            }
            // Decode and authenticate the first actual ordered frame on the new
            // connection. Registration/admission alone would not prove wire output.
            let mut header = [0; veil_proto::header::HEADER_SIZE];
            new_peer.read_exact(&mut header).await.unwrap();
            let header = veil_proto::codec::decode_header_with_limit(&header, 65536).unwrap();
            let mut body = vec![0; header.body_len as usize];
            new_peer.read_exact(&mut body).await.unwrap();
            let mut rx =
                veil_crypto::session_cipher::SessionCipher::new(&new.session_keys.rx_key, true);
            rx.open(&body, &veil_proto::codec::frame_aad(&header))
                .unwrap();
            assert_ne!(old.session_keys.session_id, new.session_keys.session_id);
            assert_ne!(old.session_keys.tx_key, new.session_keys.tx_key);
            drop(producer);
            (redial, no_timer_paid, true)
        })
        .catch_unwind(),
    )
    .await;
    // Also clean a failing fixture: never leave a runner or its owned writer
    // alive just because a regression assertion failed.
    if clock_paused {
        tokio::time::resume();
    }
    let _ = shutdown.send(true);
    for handle in handles {
        handle.abort();
        let _ = handle.await;
    }
    drop(gained);
    runtime.stop().await.unwrap();
    tokio::task::yield_now().await;
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    assert!(!path.parent().unwrap().exists());
    let (redial, no_timer_paid, wire_verified) = exercised
        .expect("fixture did not finish")
        .expect("fixture panicked before its cleanup");
    assert_eq!(
        redial,
        Some(true),
        "reconnect waited for old writer, or redial leaked its transport"
    );
    assert!(no_timer_paid, "timer substituted for immediate reconnect");
    assert!(
        wire_verified,
        "fresh authenticated session did not transmit"
    );
}
