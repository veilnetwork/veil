use super::*;
use crate::parallel_binding::{ParallelParent, PendingParallelBinding};
use tokio::time::{Duration, timeout};
use veil_transport::{
    Transport, TransportContext, TransportListener, TransportUri, obfs4_tcp::Obfs4TcpTransport,
};

struct Fixture {
    context: Arc<TransportContext>,
    listener: Arc<dyn TransportListener>,
    uri: TransportUri,
    registry: Arc<ParallelRegistry>,
    initiator: ParallelParent,
    responder: ParallelParent,
    transport: veil_transport::stream_parallel::StreamParallelHandle,
    incoming: mpsc::Receiver<BoundOrderedChild>,
    diagnostics: Arc<ParallelDiagnostics>,
    registration: Option<Registration>,
    main: [BoxIoStream; 2],
}

struct Client {
    stream: BoxIoStream,
    pending: PendingParallelBinding,
    hello: [u8; HELLO_BYTES],
}

impl Client {
    async fn finish_reliable(mut self) -> crate::parallel_binding::BoundReliableChannel {
        let mut ack = [0; 32];
        timeout(Duration::from_secs(2), self.stream.read_exact(&mut ack))
            .await
            .unwrap()
            .unwrap();
        self.pending
            .finish(&ack)
            .unwrap()
            .into_reliable(self.stream)
            .unwrap()
    }

    async fn finish(mut self) -> crate::parallel_binding::BoundOrderedChannel {
        let mut ack = [0; 32];
        timeout(Duration::from_secs(2), self.stream.read_exact(&mut ack))
            .await
            .unwrap()
            .unwrap();
        self.pending
            .finish(&ack)
            .unwrap()
            .into_ordered(self.stream)
            .unwrap()
    }

    async fn rejected(mut self) {
        let mut byte = [0];
        let read = timeout(Duration::from_secs(2), self.stream.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "rejected child received an ACK"
        );
    }
}

impl Fixture {
    async fn new(queue: usize) -> Self {
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
        let (a, b) = tokio::join!(
            Obfs4TcpTransport.connect(&uri, context.clone()),
            listener.accept()
        );
        let a = a.unwrap();
        let b = b.unwrap();
        let transport = b.parallel_stream().unwrap();
        let initiator = ParallelParent::new([1; 32], [2; 32], [3; 32]);
        let responder = ParallelParent::new([1; 32], [3; 32], [2; 32]);
        let registry = Arc::new(ParallelRegistry::default());
        let diagnostics = Arc::new(ParallelDiagnostics::default());
        let (tx, incoming) = mpsc::channel(queue);
        let registration = registry
            .register_ordered(
                [1; 32],
                responder.handle(),
                transport.clone(),
                diagnostics.clone(),
                tx,
            )
            .unwrap();
        Self {
            context,
            listener,
            uri,
            registry,
            initiator,
            responder,
            transport,
            incoming,
            diagnostics,
            registration: Some(registration),
            main: [a.into_stream().unwrap(), b.into_stream().unwrap()],
        }
    }

    async fn dispatch(
        &self,
        captured: Option<[u8; HELLO_BYTES]>,
        exporter: bool,
    ) -> (ParallelPeekOutcome, Client) {
        self.dispatch_mode(captured, exporter, false).await
    }

    async fn dispatch_mode(
        &self,
        captured: Option<[u8; HELLO_BYTES]>,
        exporter: bool,
        reliable: bool,
    ) -> (ParallelPeekOutcome, Client) {
        // Fresh independent dials deliberately bypass the sender partition:
        // enforce the authenticated receiver's aggregate budget against them.
        let (a, b) = tokio::join!(
            Obfs4TcpTransport.connect(&self.uri, self.context.clone()),
            self.listener.accept()
        );
        let a = a.unwrap();
        let b = b.unwrap();
        let binding_a = a.stream_channel_binding().unwrap();
        let (hello, pending) = if reliable {
            self.initiator.begin_reliable(binding_a)
        } else {
            self.initiator.begin(binding_a)
        }
        .unwrap();
        let hello = captured.unwrap_or(hello);
        let binding = exporter.then(|| b.stream_channel_binding().unwrap());
        let mut stream = a.into_stream().unwrap();
        stream.write_all(&hello).await.unwrap();
        stream.flush().await.unwrap();
        let outcome = self
            .registry
            .peek_and_dispatch_with_binding(b.into_stream().unwrap(), None, binding)
            .await;
        (
            outcome,
            Client {
                stream,
                pending,
                hello,
            },
        )
    }

    async fn main_survives(&mut self) {
        self.main[0].write_all(b"canonical alive").await.unwrap();
        self.main[0].flush().await.unwrap();
        let mut bytes = [0; 15];
        timeout(Duration::from_secs(1), self.main[1].read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"canonical alive");
    }
}

#[tokio::test]
async fn reliable_ordered_dispatch_requires_opt_in_and_never_enters_the_lossy_inbox() {
    let mut f = Fixture::new(1).await;
    let (outcome, denied) = f.dispatch_mode(None, true, true).await;
    assert!(
        matches!(outcome, ParallelPeekOutcome::Drop(ref e) if e == "parallel reliable support not negotiated")
    );
    denied.rejected().await;
    assert_eq!(f.diagnostics.active_connections(), 0);
    let (tx, mut rx) = mpsc::channel(1);
    let registration = f.registration.as_ref().unwrap();
    assert!(registration.enable_reliable(tx.clone()));
    assert!(!registration.enable_reliable(tx));
    let (outcome, client) = f.dispatch_mode(None, true, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Bound));
    assert!(f.incoming.try_recv().is_err());
    let bound = rx.recv().await.unwrap();
    let (server, client) = tokio::join!(bound.finish(), client.finish_reliable());
    let server = server.unwrap();
    assert_eq!(server.keys().session_id, client.keys.session_id);
    client.handle().send(b"lossless forward").await.unwrap();
    assert_eq!(server.handle().recv().await.unwrap(), b"lossless forward");
    server.handle().send(b"lossless return").await.unwrap();
    assert_eq!(client.handle().recv().await.unwrap(), b"lossless return");
    drop(server);
    timeout(Duration::from_secs(1), client.handle().closed())
        .await
        .unwrap();
    assert_eq!(f.diagnostics.active_connections(), 0);
    f.main_survives().await;
}

#[tokio::test]
async fn reliable_ordered_queue_failure_and_retirement_reclaim_transport_ownership() {
    let mut f = Fixture::new(1).await;
    let (tx, mut rx) = mpsc::channel(1);
    assert!(f.registration.as_ref().unwrap().enable_reliable(tx));
    let (outcome, first) = f.dispatch_mode(None, true, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Bound));
    let hello = first.hello;
    let (outcome, full) = f.dispatch_mode(None, true, true).await;
    assert!(
        matches!(outcome, ParallelPeekOutcome::Drop(ref e) if e == "parallel reliable owner unavailable")
    );
    full.rejected().await;
    assert_eq!(f.diagnostics.active_connections(), 1);
    let (outcome, replay) = f.dispatch_mode(Some(hello), true, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Drop(_)));
    replay.rejected().await;
    let child = rx.recv().await.unwrap();
    f.responder.retire();
    assert!(child.finish().await.is_err());
    first.rejected().await;
    assert_eq!(f.diagnostics.active_connections(), 0);
    assert!(
        !f.registration
            .as_ref()
            .unwrap()
            .enable_reliable(mpsc::channel(1).0)
    );
    drop(f.registration.take());
    let (outcome, unregistered) = f.dispatch_mode(None, true, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Drop(_)));
    unregistered.rejected().await;
    f.main_survives().await;
}

#[tokio::test]
async fn reliable_frame_actor_preserves_actual_app_stream_on_shared_obfs4_listener() {
    use crate::{
        frame_outbox::FrameEnvelope,
        reliable_frames::{FrameAdmissionError, ReliableFrameChannel},
    };
    use veil_proto::{
        AppMsg, FrameFamily,
        app::{AppClosePayload, AppDataPayload, AppOpenPayload},
        header::{FrameHeader, HEADER_SIZE},
    };
    timeout(Duration::from_secs(8), async {
        let mut f = Fixture::new(1).await;
        let (tx, mut incoming) = mpsc::channel(1);
        assert!(f.registration.as_ref().unwrap().enable_reliable(tx));
        let (outcome, client) = f.dispatch_mode(None, true, true).await;
        assert!(matches!(outcome, ParallelPeekOutcome::Bound));
        let (server, client) = tokio::join!(
            incoming.recv().await.unwrap().finish(),
            client.finish_reliable()
        );
        let server = ReliableFrameChannel::from_registered(server.unwrap());
        let client = ReliableFrameChannel::new(client);
        let handle = client.handle();
        let producer = tokio::spawn(async move {
            let mut bodies = vec![(
                AppMsg::AppOpen,
                AppOpenPayload {
                    app_id: [0x55; 32],
                    endpoint_id: 17,
                    flags: 0,
                }
                .encode()
                .to_vec(),
            )];
            for n in 0..64u8 {
                bodies.push((
                    AppMsg::AppData,
                    AppDataPayload {
                        app_id: [0x55; 32],
                        endpoint_id: 17,
                        seq: 0,
                        data: vec![n; 4096],
                    }
                    .encode(),
                ));
            }
            bodies.push((
                AppMsg::AppClose,
                AppClosePayload {
                    app_id: [0x55; 32],
                    endpoint_id: 17,
                    reason: 0,
                }
                .encode()
                .to_vec(),
            ));
            for (msg, body) in bodies {
                let mut h = FrameHeader::new(FrameFamily::App as u8, msg as u16);
                h.stream_id = 19;
                h.body_len = body.len() as u32;
                let mut frame = FrameEnvelope::from((
                    veil_proto::priority::INTERACTIVE,
                    veil_bufpool::pooled_shared_from_vec(veil_proto::codec::encode_frame(
                        &h, &body,
                    )),
                ));
                let receipt = loop {
                    match handle.try_send(frame) {
                        Ok(receipt) => break receipt,
                        Err(FrameAdmissionError::Full(retained)) => {
                            frame = retained;
                            tokio::task::yield_now().await;
                        }
                        Err(_) => panic!("lossless admission failed"),
                    }
                };
                receipt.wait().await.unwrap();
            }
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        let handle = server.handle();
        let plain = handle.recv().await.unwrap();
        let h = veil_proto::codec::decode_header(&plain).unwrap();
        assert_eq!(h.msg_type, AppMsg::AppOpen as u16);
        assert_eq!(
            AppOpenPayload::decode(&plain[HEADER_SIZE..])
                .unwrap()
                .endpoint_id,
            17
        );
        for n in 0..64u8 {
            let plain = handle.recv().await.unwrap();
            let h = veil_proto::codec::decode_header(&plain).unwrap();
            assert_eq!(h.msg_type, AppMsg::AppData as u16);
            assert_eq!(h.stream_id, 19);
            let data = AppDataPayload::decode(&plain[HEADER_SIZE..]).unwrap();
            assert_eq!(data.seq, 0);
            assert_eq!(data.data, vec![n; 4096]);
        }
        let plain = handle.recv().await.unwrap();
        assert_eq!(
            veil_proto::codec::decode_header(&plain).unwrap().msg_type,
            AppMsg::AppClose as u16
        );
        assert_eq!(
            AppClosePayload::decode(&plain[HEADER_SIZE..])
                .unwrap()
                .reason,
            0
        );
        producer.await.unwrap();
        drop(server);
        client.handle().closed().await;
        assert_eq!(f.diagnostics.active_connections(), 0);
        f.main_survives().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn shared_ordered_dispatch_verifies_real_exporter_and_rejects_replay_and_retirement() {
    let mut f = Fixture::new(8).await;
    let (outcome, client) = f.dispatch(None, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Bound));
    let hello = client.hello;
    let bound = f.incoming.recv().await.unwrap();
    let (server, client) = tokio::join!(bound.finish(), client.finish());
    let server = server.unwrap();
    assert_eq!(client.keys.session_id, server.keys().session_id);
    assert_eq!(f.diagnostics.active_connections(), 1);
    client.handle().send(b"opaque forward").unwrap();
    assert_eq!(server.handle().recv().await.unwrap(), b"opaque forward");
    server.handle().send(b"opaque return").unwrap();
    assert_eq!(client.handle().recv().await.unwrap(), b"opaque return");
    let (outcome, replay) = f.dispatch(Some(hello), true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Drop(_)));
    replay.rejected().await;
    assert!(f.incoming.try_recv().is_err());
    assert_eq!(f.diagnostics.active_connections(), 1);
    drop(server);
    timeout(Duration::from_secs(1), client.handle().closed())
        .await
        .unwrap();
    assert_eq!(f.diagnostics.active_connections(), 0);
    let (outcome, queued) = f.dispatch(None, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Bound));
    let queued_child = f.incoming.recv().await.unwrap();
    f.responder.retire();
    assert!(queued_child.finish().await.is_err());
    queued.rejected().await;
    assert_eq!(f.diagnostics.active_connections(), 0);
    let (outcome, retired) = f.dispatch(None, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Drop(_)));
    retired.rejected().await;
    f.main_survives().await;
}

#[tokio::test]
async fn ordered_incoming_budget_is_bounded_reclaimed_and_does_not_consume_outgoing_capacity() {
    let mut f = Fixture::new(8).await;
    let mut clients = Vec::new();
    let mut children = Vec::new();
    for _ in 0..veil_transport::stream_parallel::StreamParallelHandle::CONNECTIONS_PER_DIRECTION {
        let (outcome, client) = f.dispatch(None, true).await;
        assert!(matches!(outcome, ParallelPeekOutcome::Bound));
        clients.push(client);
        children.push(f.incoming.recv().await.unwrap());
    }
    assert_eq!(f.diagnostics.active_connections(), 7);
    assert_eq!(f.transport.available_connection_slots(), 7);
    let (outcome, rejected) = f.dispatch(None, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Drop(_)));
    rejected.rejected().await;
    drop(children.pop());
    clients.pop().unwrap().rejected().await;
    assert_eq!(f.diagnostics.active_connections(), 6);
    let (outcome, replacement) = f.dispatch(None, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Bound));
    let bound = f.incoming.recv().await.unwrap();
    let (server, client) = tokio::join!(bound.finish(), replacement.finish());
    let server = server.unwrap();
    client.handle().send(b"replacement").unwrap();
    assert_eq!(server.handle().recv().await.unwrap(), b"replacement");
    f.main_survives().await;
}

#[tokio::test]
async fn ordered_dispatch_rejects_missing_exporter_missing_registration_and_full_owner_queue() {
    let mut f = Fixture::new(1).await;
    let (outcome, missing) = f.dispatch(None, false).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Drop(_)));
    missing.rejected().await;
    assert_eq!(f.diagnostics.active_connections(), 0);
    let (outcome, first) = f.dispatch(None, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Bound));
    let (outcome, full) = f.dispatch(None, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Drop(_)));
    full.rejected().await;
    assert_eq!(f.diagnostics.active_connections(), 1);
    drop(f.incoming.recv().await.unwrap());
    first.rejected().await;
    assert_eq!(f.diagnostics.active_connections(), 0);
    drop(f.registration.take());
    let (outcome, unknown) = f.dispatch(None, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Drop(_)));
    unknown.rejected().await;
    f.main_survives().await;
}

#[tokio::test]
async fn ordered_listener_preserves_ordinary_ovl_bytes_before_any_new_peer_admission() {
    let mut f = Fixture::new(8).await;
    let (a, b) = tokio::join!(
        Obfs4TcpTransport.connect(&f.uri, f.context.clone()),
        f.listener.accept()
    );
    let mut a = a.unwrap().into_stream().unwrap();
    let b = b.unwrap();
    let binding = b.stream_channel_binding();
    a.write_all(b"ordinary OVL1 input").await.unwrap();
    a.flush().await.unwrap();
    let ParallelPeekOutcome::Handshake(mut ordinary) = f
        .registry
        .peek_and_dispatch_with_binding(b.into_stream().unwrap(), None, binding)
        .await
    else {
        panic!("ordinary input was intercepted")
    };
    let mut bytes = [0; 19];
    ordinary.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"ordinary OVL1 input");
    assert!(f.incoming.try_recv().is_err());
    assert_eq!(f.diagnostics.active_connections(), 0);
    f.main_survives().await;
}

#[tokio::test]
async fn valid_quic_proof_cannot_enter_an_ordered_parent_registration() {
    use veil_transport::quic::QuicTransport;
    let mut f = Fixture::new(8).await;
    let listener = QuicTransport
        .bind(&"quic://127.0.0.1:0".parse().unwrap(), f.context.clone())
        .await
        .unwrap();
    let uri = format!("quic://{}", listener.local_addr()).parse().unwrap();
    let accepted = tokio::spawn(async move { listener.accept().await });
    let a = QuicTransport
        .connect(&uri, f.context.clone())
        .await
        .unwrap();
    let handle = a.quic_datagrams().unwrap();
    let (hello, _) = f
        .initiator
        .begin(handle.channel_binding().unwrap())
        .unwrap();
    let mut stream = a.into_stream().unwrap();
    stream.write_all(&hello).await.unwrap();
    stream.flush().await.unwrap();
    let b = accepted.await.unwrap().unwrap();
    let datagrams = b.quic_datagrams();
    let outcome = f
        .registry
        .peek_and_dispatch_with_binding(b.into_stream().unwrap(), datagrams, None)
        .await;
    assert!(matches!(outcome, ParallelPeekOutcome::Drop(_)));
    timeout(Duration::from_secs(1), handle.closed())
        .await
        .unwrap();
    assert!(f.incoming.try_recv().is_err());
    assert_eq!(f.diagnostics.active_connections(), 0);
    f.main_survives().await;
}

#[tokio::test]
async fn authenticated_records_progress_while_the_canonical_tcp_write_is_blocked() {
    let mut f = Fixture::new(8).await;
    let bulk = vec![0x55; 4 * 1024 * 1024];
    assert!(
        timeout(Duration::from_millis(150), f.main[0].write_all(&bulk))
            .await
            .is_err(),
        "control must fill actual TCP buffers, not just a simulated queue"
    );
    // The primary remains held open and unread. Authenticate three independent
    // children through the SAME central dispatcher and canonical budget.
    let mut channels = Vec::new();
    for _ in 0..3 {
        let (outcome, client) = f.dispatch(None, true).await;
        assert!(matches!(outcome, ParallelPeekOutcome::Bound));
        let child = f.incoming.recv().await.unwrap();
        let (server, client) = tokio::join!(child.finish(), client.finish());
        channels.push((client, server.unwrap()));
    }
    for index in 0..20u8 {
        for (client, server) in &channels {
            let left = client.handle();
            let right = server.handle();
            timeout(Duration::from_millis(200), async {
                left.send(&[index; 500]).unwrap();
                assert_eq!(right.recv().await.unwrap(), vec![index; 500]);
                right.send(&[index; 30]).unwrap();
                assert_eq!(left.recv().await.unwrap(), vec![index; 30]);
            })
            .await
            .expect("independent records waited behind primary TCP backlog");
        }
    }
    assert_eq!(f.diagnostics.active_connections(), 3);
    // Retiring one child does not close its sibling or canonical credentials.
    drop(channels.pop());
    let (client, server) = &channels[0];
    client.handle().send(b"sibling survives").unwrap();
    assert_eq!(server.handle().recv().await.unwrap(), b"sibling survives");
    assert_eq!(f.diagnostics.active_connections(), 2);
}

/// Preserve the real obfs4 connection and its exporter proof while holding its
/// record write after one accepted plaintext byte. Read/close stay real I/O.
struct HoldRecordWrite {
    stream: BoxIoStream,
    progressed: Arc<std::sync::atomic::AtomicBool>,
}

impl tokio::io::AsyncRead for HoldRecordWrite {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for HoldRecordWrite {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::sync::atomic::Ordering;
        if self.progressed.load(Ordering::Acquire) {
            return std::task::Poll::Pending;
        }
        let result = std::pin::Pin::new(&mut self.stream).poll_write(cx, &buf[..buf.len().min(1)]);
        if matches!(&result, std::task::Poll::Ready(Ok(n)) if *n > 0) {
            self.progressed.store(true, Ordering::Release);
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn expired_ordered_child_closes_real_obfs4_io_reclaims_its_lease_and_keeps_parent_alive() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut f = Fixture::new(8).await;
    let (outcome, mut client) = f.dispatch(None, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Bound));
    let child = f.incoming.recv().await.unwrap();
    let server = child.finish().await.unwrap();
    let mut ack = [0; 32];
    client.stream.read_exact(&mut ack).await.unwrap();
    let keys = client.pending.finish(&ack).unwrap();
    let progressed = Arc::new(AtomicBool::new(false));
    let client = keys
        .into_ordered(Box::new(HoldRecordWrite {
            stream: client.stream,
            progressed: progressed.clone(),
        }))
        .unwrap();
    client
        .handle()
        .send_before(
            b"expired partial record",
            std::time::Instant::now() + Duration::from_millis(80),
        )
        .unwrap();
    timeout(Duration::from_millis(200), async {
        while !progressed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let (outcome, sibling) = f.dispatch(None, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Bound));
    let bound = f.incoming.recv().await.unwrap();
    let (sibling_server, sibling) = tokio::join!(bound.finish(), sibling.finish());
    let sibling_server = sibling_server.unwrap();
    sibling.handle().send(b"sibling survives").unwrap();
    assert_eq!(
        sibling_server.handle().recv().await.unwrap(),
        b"sibling survives"
    );
    timeout(Duration::from_millis(300), client.handle().closed())
        .await
        .unwrap();
    timeout(Duration::from_millis(300), server.handle().closed())
        .await
        .unwrap();
    // This is the same ownership cleanup the normal pool performs on finding
    // a closed child. Its canonical credentials remain live throughout.
    drop(server);
    drop(client);
    assert_eq!(f.diagnostics.active_connections(), 1);
    f.main_survives().await;

    let (outcome, replacement) = f.dispatch(None, true).await;
    assert!(matches!(outcome, ParallelPeekOutcome::Bound));
    let bound = f.incoming.recv().await.unwrap();
    let (replacement_server, replacement) = tokio::join!(bound.finish(), replacement.finish());
    let replacement_server = replacement_server.unwrap();
    replacement.handle().send(b"fresh proof and keys").unwrap();
    assert_eq!(
        replacement_server.handle().recv().await.unwrap(),
        b"fresh proof and keys"
    );
    sibling_server
        .handle()
        .send(b"return path still alive")
        .unwrap();
    assert_eq!(
        sibling.handle().recv().await.unwrap(),
        b"return path still alive"
    );
    assert_eq!(f.diagnostics.active_connections(), 2);
    f.main_survives().await;
}
