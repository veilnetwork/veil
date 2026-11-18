//! Real runtimes and auxiliary ordered lanes across NetworkChanged/resume.
//! Block the leaf's canonical reads AND writes before each fresh RT exchange:
//! a Ready snapshot alone cannot substitute for actual child delivery.
use super::resume_data_tests::{APP, ENDPOINT, frame, payload};
use super::tests::{resumption_leaf_identity, runtime_config_with_listen, save_test_config};
use super::*;
use futures::{FutureExt, future::BoxFuture, task::AtomicWaker};
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use veil_app::AppMessage;
use veil_proto::priority;
use veil_transport::{
    PeerMeta, Transport, TransportCapabilities, TransportConnection, TransportListener,
    TransportRegistry, TransportUri,
};

#[derive(Default)]
struct Gate {
    read_blocked: AtomicBool,
    write_blocked: AtomicBool,
    shutdown_blocked: AtomicBool,
    read_seen: AtomicBool,
    shutdown_seen: AtomicBool,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
    shutdown_waker: AtomicWaker,
    changed: tokio::sync::Notify,
    read_bytes: AtomicU64,
    written_bytes: AtomicU64,
}
impl Gate {
    async fn block_reads(&self) {
        self.read_blocked.store(true, Ordering::SeqCst);
        self.read_waker.wake();
        while !self.read_seen.load(Ordering::SeqCst) {
            self.changed.notified().await;
        }
    }
    fn release(&self) {
        self.read_blocked.store(false, Ordering::SeqCst);
        self.write_blocked.store(false, Ordering::SeqCst);
        self.shutdown_blocked.store(false, Ordering::SeqCst);
        self.read_waker.wake();
        self.write_waker.wake();
        self.shutdown_waker.wake();
    }
    fn bytes(&self) -> (u64, u64) {
        (
            self.read_bytes.load(Ordering::SeqCst),
            self.written_bytes.load(Ordering::SeqCst),
        )
    }
}

struct GatedIo {
    inner: BoxIoStream,
    gate: Arc<Gate>,
}
impl AsyncRead for GatedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.gate.read_waker.register(cx.waker());
        if self.gate.read_blocked.load(Ordering::SeqCst) {
            self.gate.read_seen.store(true, Ordering::SeqCst);
            self.gate.changed.notify_one();
            return Poll::Pending;
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        self.gate
            .read_bytes
            .fetch_add((buf.filled().len() - before) as u64, Ordering::SeqCst);
        result
    }
}
impl AsyncWrite for GatedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.gate.write_waker.register(cx.waker());
        if self.gate.write_blocked.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = &result {
            self.gate
                .written_bytes
                .fetch_add(*n as u64, Ordering::SeqCst);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.gate.shutdown_waker.register(cx.waker());
        if self.gate.shutdown_blocked.load(Ordering::SeqCst) {
            self.gate.shutdown_seen.store(true, Ordering::SeqCst);
            self.gate.changed.notify_one();
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct GatedConnection {
    inner: Box<dyn TransportConnection>,
    gate: Arc<Gate>,
}
impl TransportConnection for GatedConnection {
    fn capabilities(&self) -> &TransportCapabilities {
        self.inner.capabilities()
    }
    fn peer_meta(&self) -> &PeerMeta {
        self.inner.peer_meta()
    }
    fn stream_channel_binding(&self) -> Option<[u8; 32]> {
        self.inner.stream_channel_binding()
    }
    fn parallel_stream(&self) -> Option<veil_transport::stream_parallel::StreamParallelHandle> {
        self.inner.parallel_stream()
    }
    fn into_stream(self: Box<Self>) -> veil_transport::Result<BoxIoStream> {
        Ok(Box::new(GatedIo {
            inner: self.inner.into_stream()?,
            gate: self.gate,
        }))
    }
    fn close<'a>(&'a mut self) -> BoxFuture<'a, veil_transport::Result<()>> {
        self.inner.close()
    }
}

struct ClientTransport {
    gates: Arc<Mutex<Vec<Arc<Gate>>>>,
    first_socket: tokio::sync::watch::Sender<Option<SocketAddr>>,
}
impl Transport for ClientTransport {
    fn scheme(&self) -> &'static str {
        "obfs4-tcp"
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
            let inner = TransportRegistry::with_defaults().connect(uri, ctx).await?;
            let local = inner.peer_meta().local_addr.expect("real loopback socket");
            self.first_socket.send_if_modified(|value| {
                if value.is_some() {
                    false
                } else {
                    *value = Some(local);
                    true
                }
            });
            let gate = Arc::new(Gate::default());
            self.gates.lock().unwrap().push(gate.clone());
            Ok(Box::new(GatedConnection { inner, gate }) as Box<dyn TransportConnection>)
        })
    }
    fn bind<'a>(
        &'a self,
        _: &'a TransportUri,
        _: Arc<TransportContext>,
    ) -> BoxFuture<'a, veil_transport::Result<Box<dyn TransportListener>>> {
        Box::pin(async { unreachable!("canonical dial wrapper only") })
    }
}

fn config(role: veil_cfg::NodeRole) -> veil_cfg::Config {
    let mut config = runtime_config_with_listen();
    config.peers.clear();
    config.bootstrap_peers.clear();
    config.listen.clear();
    config.global.meeting_points = veil_cfg::MeetingPoints::Only(Vec::new());
    config.global.builtin_seed_policy = veil_cfg::BuiltinSeedPolicy::Never;
    config.pex.enabled = false;
    let identity = config.identity.as_mut().unwrap();
    identity.role = role;
    identity.lazy_mining = false;
    if role == veil_cfg::NodeRole::Leaf {
        let leaf = resumption_leaf_identity();
        identity.algo = leaf.algo;
        identity.node_id = Some(leaf.node_id);
        identity.public_key = leaf.public_key.clone();
        identity.private_key = leaf.private_key.clone();
        identity.nonce = leaf.nonce.clone();
    }
    config
}

async fn ready(services: &NodeServices, peer: &[u8; 32]) {
    loop {
        let state = services
            .session_tx_registry
            .read()
            .unwrap()
            .request_local_datagram_channel(peer, priority::REALTIME);
        if state == veil_session::LocalDatagramChannelState::Ready {
            return;
        }
        tokio::task::yield_now().await;
    }
}

async fn receive(rx: &mut tokio::sync::mpsc::Receiver<AppMessage>, from: [u8; 32], seq: u32) {
    match rx.recv().await.expect("live real application endpoint") {
        AppMessage::RtData {
            src_node_id,
            payload: actual,
            ..
        } => {
            assert_eq!(src_node_id, from);
            assert_eq!(actual, payload(seq));
        }
        other => panic!("unexpected application message: {other:?}"),
    }
}

async fn exchange(
    leaf: &NodeServices,
    core: &NodeServices,
    leaf_rx: &mut tokio::sync::mpsc::Receiver<AppMessage>,
    core_rx: &mut tokio::sync::mpsc::Receiver<AppMessage>,
    gate: &Gate,
    seq: u32,
) {
    gate.write_blocked.store(true, Ordering::SeqCst);
    gate.block_reads().await;
    let before = gate.bytes();
    assert!(leaf.session_tx_registry.read().unwrap().send_to(
        &core.local_node_id,
        priority::REALTIME,
        frame(&payload(seq)),
    ));
    receive(core_rx, leaf.local_node_id, seq).await;
    assert!(core.session_tx_registry.read().unwrap().send_to(
        &leaf.local_node_id,
        priority::REALTIME,
        frame(&payload(seq + 1)),
    ));
    receive(leaf_rx, core.local_node_id, seq + 1).await;
    assert_eq!(
        gate.bytes(),
        before,
        "canonical bytes substituted for auxiliary delivery"
    );
}

#[tokio::test]
async fn real_ordered_media_survives_resumption_and_late_parent_teardown() {
    // Synchronous PoW must finish before the executor starts its watchdog.
    let core_config = config(veil_cfg::NodeRole::Core);
    let leaf_config = config(veil_cfg::NodeRole::Leaf);
    let core_path = save_test_config("ordered-resume-core", core_config).unwrap();
    let leaf_path = save_test_config("ordered-resume-leaf", leaf_config).unwrap();
    let mut core = NodeRuntime::start(&core_path, true).await.unwrap();
    let mut leaf = NodeRuntime::start(&leaf_path, true).await.unwrap();
    let core_services = core.access();
    let mut leaf_services = leaf.access();
    let mut context = TransportContext::for_debug().unwrap();
    context.obfs4_psk = Some(Arc::new([0x42; 32])); // Synthetic fixture PSK.
    let context = Arc::new(context);
    leaf_services.transport_ctx = context.clone();
    let listener = TransportRegistry::with_defaults()
        .bind(
            &TransportUri::parse("obfs4-tcp://127.0.0.1:0").unwrap(),
            context,
        )
        .await
        .unwrap();
    let peer_identity = &core_services.identity.local_identity;
    let peer = crate::types::PeerConfigEntry {
        peer_id: PeerId::new(1),
        node_id: peer_identity.node_id,
        public_key: peer_identity.public_key.clone(),
        nonce: peer_identity.nonce.clone(),
        algo: peer_identity.algo,
        transport: format!("obfs4-tcp://{}", listener.local_addr()),
        tls_cert: None,
        tls_key: None,
        tls_ca_cert: None,
        bootstrap_only: true,
        source: crate::types::PeerSource::Bootstrap,
    };
    let client_gates = Arc::new(Mutex::new(Vec::new()));
    let (first_socket, _) = tokio::sync::watch::channel(None);
    let mut registry = TransportRegistry::new();
    registry.register(Arc::new(ClientTransport {
        gates: client_gates.clone(),
        first_socket: first_socket.clone(),
    }));
    leaf_services.registry = Arc::new(registry);
    leaf_services
        .state
        .lock()
        .unwrap()
        .peers
        .insert(peer.peer_id, peer.clone());
    let old_core_gate = Arc::new(Gate::default());
    old_core_gate.shutdown_blocked.store(true, Ordering::SeqCst);
    let (old_done_tx, old_done_rx) = tokio::sync::oneshot::channel();
    let old_done = Arc::new(Mutex::new(Some(old_done_tx)));
    let (accept_stop, mut accept_stop_rx) = tokio::sync::oneshot::channel();
    let inbound = InboundSessionContext {
        runtime: core_services.make_session_context(),
        listen_id: ListenId::new(0),
        listener_handle: ListenerHandle::new(0),
    };
    let accepted_gate = old_core_gate.clone();
    let acceptor = tokio::spawn(async move {
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut accept_stop_rx => break,
                Some(done) = sessions.join_next(), if !sessions.is_empty() => { done.unwrap(); },
                raw = listener.accept_split() => {
                    let raw = raw.unwrap();
                    let inbound = inbound.clone();
                    let gate = accepted_gate.clone();
                    let old_done = old_done.clone();
                    let mut selected = first_socket.subscribe();
                    sessions.spawn(async move {
                        let connection = raw.finish.await.unwrap();
                        let first = selected.wait_for(|v| v.is_some()).await.unwrap().unwrap();
                        let old = connection.peer_meta().remote_addr == Some(first);
                        let connection: Box<dyn TransportConnection> = if old {
                            Box::new(GatedConnection { inner: connection, gate })
                        } else { connection };
                        inbound_session(inbound, connection, false).await;
                        if old && let Some(done) = old_done.lock().unwrap().take() { let _ = done.send(()); }
                    });
                }
            }
        }
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
    });
    let (_core_endpoint, mut core_rx) = core.app_registry().register(APP, ENDPOINT, 16);
    let (_leaf_endpoint, mut leaf_rx) = leaf.app_registry().register(APP, ENDPOINT, 16);
    let (connector_stop, _) = tokio::sync::watch::channel(false);
    let connectors = crate::outbound_connector::spawn_outbound_peers(
        vec![peer],
        &leaf_services,
        &connector_stop,
    );
    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        std::panic::AssertUnwindSafe(async {
            let original_ticket = loop {
                if let Some(ticket) = leaf_services
                    .resumption
                    .peer_tickets
                    .lock()
                    .unwrap()
                    .get(&core_services.local_node_id)
                    .cloned()
                {
                    break ticket;
                }
                tokio::task::yield_now().await;
            };
            eprintln!("ordered_resume: initial real session ticket stored");
            ready(&leaf_services, &core_services.local_node_id).await;
            eprintln!("ordered_resume: initial leaf auxiliary channel ready");
            ready(&core_services, &leaf_services.local_node_id).await;
            eprintln!("ordered_resume: initial core auxiliary channel ready");
            let old_gate = client_gates.lock().unwrap()[0].clone();
            exchange(
                &leaf_services,
                &core_services,
                &mut leaf_rx,
                &mut core_rx,
                &old_gate,
                10,
            )
            .await;
            eprintln!("ordered_resume: initial auxiliary data verified with canonical blocked");
            let original_registration = core_services
                .session_tx_registry
                .read()
                .unwrap()
                .live_registration(&leaf_services.local_node_id)
                .unwrap();
            assert!(core_services.state.lock().unwrap().peers.is_empty());
            old_core_gate.block_reads().await; // Hold the old Core side past leaf EOF.
            eprintln!("ordered_resume: old core canonical reader held before network change");
            use veil_ipc::MobileEventSink;
            crate::mobile_sink::MobileEventForwarder::new(
                leaf_services.logger.clone(),
                leaf_services.gateway_failover_notify.clone(),
                leaf_services.force_reconnect_notify.clone(),
                leaf_services.session_tx_registry.clone(),
            )
            .network_changed(veil_proto::NetworkChangedPayload {
                kind: veil_proto::NetworkKind::Cellular,
                mtu_hint: 0,
            });
            while !old_core_gate.shutdown_seen.load(Ordering::SeqCst) {
                old_core_gate.changed.notified().await;
            }
            eprintln!("ordered_resume: predecessor reached held final shutdown");
            let resumed_ticket = loop {
                if let Some(ticket) = leaf_services
                    .resumption
                    .peer_tickets
                    .lock()
                    .unwrap()
                    .get(&core_services.local_node_id)
                    .cloned()
                    && ticket.session_id != original_ticket.session_id
                {
                    break ticket;
                }
                tokio::task::yield_now().await;
            };
            assert_ne!(original_ticket.tx_key, resumed_ticket.tx_key);
            assert_ne!(original_ticket.rx_key, resumed_ticket.rx_key);
            let current_registration = core_services
                .session_tx_registry
                .read()
                .unwrap()
                .live_registration(&leaf_services.local_node_id)
                .unwrap();
            assert_ne!(original_registration, current_registration);
            assert!(
                core_services
                    .session_tx_registry
                    .read()
                    .unwrap()
                    .owns_live_session(&leaf_services.local_node_id, &resumed_ticket.session_id)
            );
            assert!(core_services.state.lock().unwrap().peers.is_empty());
            ready(&leaf_services, &core_services.local_node_id).await;
            ready(&core_services, &leaf_services.local_node_id).await;
            assert_eq!(client_gates.lock().unwrap().len(), 2);
            let new_gate = client_gates.lock().unwrap()[1].clone();
            exchange(
                &leaf_services,
                &core_services,
                &mut leaf_rx,
                &mut core_rx,
                &new_gate,
                12,
            )
            .await;
            eprintln!(
                "ordered_resume: resumed auxiliary data verified with predecessor teardown held"
            );
            old_core_gate.release();
            old_done_rx.await.unwrap();
            assert_eq!(
                core_services
                    .session_tx_registry
                    .read()
                    .unwrap()
                    .live_registration(&leaf_services.local_node_id),
                Some(current_registration)
            );
            exchange(
                &leaf_services,
                &core_services,
                &mut leaf_rx,
                &mut core_rx,
                &new_gate,
                14,
            )
            .await;
            assert_eq!(
                client_gates.lock().unwrap().len(),
                2,
                "an extra canonical reconnect masked the result"
            );
            assert!(
                core_services
                    .session_tx_registry
                    .read()
                    .unwrap()
                    .owns_live_session(&leaf_services.local_node_id, &resumed_ticket.session_id,)
            );
            assert!(
                leaf_services
                    .session_tx_registry
                    .read()
                    .unwrap()
                    .owns_live_session(&core_services.local_node_id, &resumed_ticket.session_id,)
            );
            eprintln!("ordered_resume: auxiliary data verified after predecessor teardown");
        })
        .catch_unwind(),
    )
    .await;
    old_core_gate.release();
    for gate in client_gates.lock().unwrap().iter() {
        gate.release();
    }
    let _ = connector_stop.send(true);
    for task in connectors {
        task.abort();
        let _ = task.await;
    }
    let _ = accept_stop.send(());
    acceptor.await.unwrap();
    leaf.stop().await.unwrap();
    core.stop().await.unwrap();
    for path in [leaf_path, core_path] {
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!("ordered auxiliary resume fixture exceeded watchdog"),
    }
}
