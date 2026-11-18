//! Admission of a resumed leaf is insufficient: exercise the actual inbound
//! runner and its encrypted canonical-stream application traffic before and
//! after late teardown of its predecessor. No auxiliary lanes are installed
//! in the manual leaf. Exercised peer streams are loopback; no configured or
//! built-in seeds.
use super::tests::{resumption_leaf_identity, runtime_config_with_listen, save_test_config};
use super::*;
use futures::{FutureExt, future::BoxFuture, task::AtomicWaker};
use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use veil_app::AppMessage;
use veil_crypto::session_cipher::SessionCipher;
use veil_proto::{
    app::AppRtDataPayload,
    codec,
    family::{AppMsg, FrameFamily, SessionMsg},
    header::{FrameHeader, HEADER_SIZE, priority},
    session::ClientTicketEntry,
};
use veil_session::handshake::{OvlHandshakeResult, perform_ovl1_handshake};
use veil_transport::{
    PeerMeta, TransportCapabilities, TransportConnection, TransportRegistry, TransportUri,
};

pub(super) const APP: [u8; 32] = [0x63; 32];
pub(super) const ENDPOINT: u32 = 7;

#[derive(Default)]
struct ShutdownGate {
    released: AtomicBool,
    waker: AtomicWaker,
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}
impl ShutdownGate {
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.waker.wake();
    }
}

struct GatedIo {
    inner: BoxIoStream,
    gate: Arc<ShutdownGate>,
}
impl AsyncRead for GatedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for GatedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.gate.waker.register(cx.waker());
        if !self.gate.released.load(Ordering::SeqCst) {
            if let Some(tx) = self.gate.entered.lock().unwrap().take() {
                let _ = tx.send(());
            }
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct CanonicalConnection {
    inner: Box<dyn TransportConnection>,
    gate: Option<Arc<ShutdownGate>>,
}
impl TransportConnection for CanonicalConnection {
    fn capabilities(&self) -> &TransportCapabilities {
        self.inner.capabilities()
    }
    fn peer_meta(&self) -> &PeerMeta {
        self.inner.peer_meta()
    }
    fn stream_channel_binding(&self) -> Option<[u8; 32]> {
        self.inner.stream_channel_binding()
    }
    // Deliberately use the trait's None parallel_stream offer: the manual leaf
    // implements the canonical session only. Offering obfs4 auxiliary lanes
    // would route RT data to children this fixture does not accept, testing an
    // incomplete peer instead of resumed canonical transport. Exporter binding
    // above and the real obfs4/session authentication remain intact.
    fn into_stream(self: Box<Self>) -> veil_transport::Result<BoxIoStream> {
        let inner = self.inner.into_stream()?;
        Ok(match self.gate {
            Some(gate) => Box::new(GatedIo { inner, gate }) as BoxIoStream,
            None => inner,
        })
    }
    fn close<'a>(&'a mut self) -> BoxFuture<'a, veil_transport::Result<()>> {
        self.inner.close()
    }
}

struct Leaf {
    stream: BoxIoStream,
    handshake: OvlHandshakeResult,
    tx: SessionCipher,
    rx: SessionCipher,
}
impl Leaf {
    async fn receive(&mut self) -> (FrameHeader, Vec<u8>) {
        let mut header = [0; HEADER_SIZE];
        self.stream.read_exact(&mut header).await.unwrap();
        let header = codec::decode_header_with_limit(&header, 65536).unwrap();
        let mut body = vec![0; header.body_len as usize];
        self.stream.read_exact(&mut body).await.unwrap();
        let body = self.rx.open(&body, &codec::frame_aad(&header)).unwrap();
        (header, body)
    }

    async fn ticket(&mut self) -> ClientTicketEntry {
        // Consume and authenticate intervening control frames, preserving the
        // session nonce counter. The ticket itself must come from the runner,
        // not a test-side call to the issuer.
        loop {
            let (header, body) = self.receive().await;
            if header.family == FrameFamily::Session as u8
                && header.msg_type == SessionMsg::Ticket as u16
            {
                return ClientTicketEntry {
                    blob: body,
                    tx_key: self.handshake.session_keys.tx_key,
                    rx_key: self.handshake.session_keys.rx_key,
                    session_id: self.handshake.session_keys.session_id,
                    peer_public_key: self.handshake.public_key.clone(),
                    peer_nonce: self.handshake.nonce.clone(),
                    issued_at: std::time::Instant::now(),
                };
            }
        }
    }
}

async fn connect(
    runtime: &NodeRuntime,
    scheme: &str,
    ticket: Option<ClientTicketEntry>,
    gate: Option<Arc<ShutdownGate>>,
    runners: &mut Vec<Option<JoinHandle<()>>>,
) -> Leaf {
    let registry = TransportRegistry::with_defaults();
    let mut context = TransportContext::for_debug().unwrap();
    context.obfs4_psk = Some(Arc::new([0x42; 32])); // Synthetic fixture-only PSK.
    let context = Arc::new(context);
    let listener = registry
        .bind(
            &TransportUri::parse(&format!("{scheme}://127.0.0.1:0")).unwrap(),
            context.clone(),
        )
        .await
        .unwrap();
    let uri = TransportUri::parse(&format!("{scheme}://{}", listener.local_addr())).unwrap();
    eprintln!("resume_data {scheme}: listener ready");
    let (client, server) = tokio::join!(registry.connect(&uri, context), listener.accept());
    eprintln!("resume_data {scheme}: transport pair ready");
    let mut stream = client.unwrap().into_stream().unwrap();
    let server = server.unwrap();
    let server = Box::new(CanonicalConnection {
        inner: server,
        gate,
    });
    runners.push(Some(spawn_inbound_session(
        InboundSessionContext {
            runtime: runtime.access().make_session_context(),
            listen_id: ListenId::new(0),
            listener_handle: ListenerHandle::new(0),
        },
        server,
    )));
    eprintln!("resume_data {scheme}: core runner spawned");
    let handshake = perform_ovl1_handshake(
        &mut stream,
        resumption_leaf_identity(),
        veil_cfg::NodeRole::Leaf,
        veil_cfg::DiscoveryMode::IntroductionOnly,
        None,
        None,
        None,
        Some([0; 32]),
        ticket,
        None,
        None,
        &[],
        false,
        false,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    Leaf {
        tx: SessionCipher::new(&handshake.session_keys.tx_key, true),
        rx: SessionCipher::new(&handshake.session_keys.rx_key, true),
        handshake,
        stream,
    }
}

pub(super) fn payload(seq: u32) -> AppRtDataPayload {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(&seq.to_be_bytes());
    let ciphertext = ChaCha20Poly1305::new_from_slice(&[0x37; 32])
        .unwrap()
        .encrypt(
            Nonce::from_slice(&nonce),
            b"synthetic resume data".as_slice(),
        )
        .unwrap();
    AppRtDataPayload {
        src_app_id: APP,
        app_id: APP,
        endpoint_id: ENDPOINT,
        seq,
        timestamp_us: u64::from(seq),
        marker: 0,
        payload_type: 123,
        payload: ciphertext,
    }
}

pub(super) fn frame(payload: &AppRtDataPayload) -> Vec<u8> {
    let body = payload.encode();
    let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppRtData as u16);
    header.body_len = body.len() as u32;
    header.set_priority(priority::REALTIME);
    [codec::encode_header(&header).as_slice(), &body].concat()
}

async fn exchange(
    runtime: &NodeRuntime,
    leaf: &mut Leaf,
    received: &mut tokio::sync::mpsc::Receiver<AppMessage>,
    seq: u32,
) {
    let peer = *resumption_leaf_identity().node_id.as_bytes();
    let to_core = payload(seq);
    let encrypted = veil_session::runner::apply_tx_cipher(&frame(&to_core), &mut leaf.tx).unwrap();
    leaf.stream.write_all(&encrypted).await.unwrap();
    leaf.stream.flush().await.unwrap();
    match received.recv().await.expect("live application endpoint") {
        AppMessage::RtData {
            src_node_id,
            payload,
            ..
        } => {
            assert_eq!(src_node_id, peer);
            assert_eq!(payload, to_core);
        }
        other => panic!("unexpected endpoint message: {other:?}"),
    }
    let to_leaf = payload(seq + 1);
    assert!(
        runtime
            .access()
            .session_tx_registry
            .read()
            .unwrap()
            .send_to(&peer, priority::REALTIME, frame(&to_leaf),)
    );
    loop {
        let (header, body) = leaf.receive().await;
        if header.family == FrameFamily::App as u8 && header.msg_type == AppMsg::AppRtData as u16 {
            assert_eq!(AppRtDataPayload::decode(&body).unwrap(), to_leaf);
            break;
        }
    }
}

async fn resumed_data_fixture(scheme: &str) {
    // Provision before starting the runtime/watchdog: synchronous PoW must
    // not prevent a current-thread executor from polling its timeout.
    let _ = resumption_leaf_identity();
    let mut config = runtime_config_with_listen();
    config.peers.clear();
    config.bootstrap_peers.clear();
    config.listen.clear();
    config.global.meeting_points = veil_cfg::MeetingPoints::Only(Vec::new());
    config.global.builtin_seed_policy = veil_cfg::BuiltinSeedPolicy::Never;
    config.pex.enabled = false;
    config.identity.as_mut().unwrap().lazy_mining = false;
    let path = save_test_config("resumed-application-data", config).unwrap();
    let mut runtime = NodeRuntime::start(&path, true).await.unwrap();
    let gate = Arc::new(ShutdownGate::default());
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    *gate.entered.lock().unwrap() = Some(entered_tx);
    let mut runners = Vec::new();
    let outcome = tokio::time::timeout(
        Duration::from_secs(30),
        std::panic::AssertUnwindSafe(async {
            let services = runtime.access();
            let (_endpoint, mut received) = runtime.app_registry().register(APP, ENDPOINT, 16);
            let mut old = connect(&runtime, scheme, None, Some(gate.clone()), &mut runners).await;
            eprintln!("resume_data {scheme}: initial handshake complete");
            let ticket = old.ticket().await;
            eprintln!("resume_data {scheme}: real ticket received");
            exchange(&runtime, &mut old, &mut received, 0).await;
            eprintln!("resume_data {scheme}: initial bidirectional data complete");
            let peer = *resumption_leaf_identity().node_id.as_bytes();
            assert!(services.state.lock().unwrap().peers.is_empty());
            let before = services
                .session_tx_registry
                .read()
                .unwrap()
                .live_registration(&peer)
                .unwrap();
            // The old peer stays open. Admission forbids an unknown leaf's full
            // handshake from replacing it: a new registration here requires
            // the authenticated resume ticket of that exact predecessor.
            let mut new = connect(&runtime, scheme, Some(ticket), None, &mut runners).await;
            eprintln!("resume_data {scheme}: resume handshake complete");
            entered_rx.await.expect("old runner reached final shutdown");
            assert!(
                !runners[0].as_ref().unwrap().is_finished(),
                "old teardown must remain gated"
            );
            let after = services
                .session_tx_registry
                .read()
                .unwrap()
                .live_registration(&peer)
                .unwrap();
            assert_ne!(before, after);
            assert_ne!(
                old.handshake.session_keys.session_id,
                new.handshake.session_keys.session_id
            );
            assert_ne!(
                old.handshake.session_keys.tx_key,
                new.handshake.session_keys.tx_key
            );
            assert_ne!(
                old.handshake.session_keys.rx_key,
                new.handshake.session_keys.rx_key
            );
            exchange(&runtime, &mut new, &mut received, 2).await;
            eprintln!("resume_data {scheme}: resumed data complete with old teardown held");
            gate.release();
            runners[0].as_mut().unwrap().await.unwrap();
            runners[0].take(); // Do not poll a completed JoinHandle in cleanup.
            assert_eq!(
                services
                    .session_tx_registry
                    .read()
                    .unwrap()
                    .live_registration(&peer),
                Some(after)
            );
            exchange(&runtime, &mut new, &mut received, 4).await;
            eprintln!("resume_data {scheme}: resumed data complete after old teardown");
            drop(old);
            drop(new);
        })
        .catch_unwind(),
    )
    .await;
    // A failing assertion or watchdog must not detach owned session tasks.
    gate.release();
    for runner in runners.into_iter().flatten() {
        runner.abort();
        let _ = runner.await;
    }
    runtime.stop().await.unwrap();
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!("resumed application data fixture exceeded watchdog ({scheme})"),
    }
}

#[tokio::test]
async fn resumed_tcp_carries_canonical_data_across_late_predecessor_teardown() {
    resumed_data_fixture("tcp").await;
}

#[tokio::test]
async fn resumed_obfs4_tcp_carries_canonical_data_across_late_predecessor_teardown() {
    resumed_data_fixture("obfs4-tcp").await;
}
