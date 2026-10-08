//! Real obfs4/TCP children through the production SessionRunner and app
//! dispatcher. Canonical transport ownership, local source selection and
//! ordinary negotiated rekey run normally; no media-aware relay is involved.
use super::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use veil_app::registry::AppMessage;
use veil_proto::{
    app::{AppClosePayload, AppDataPayload, AppOpenPayload, receipt_status},
    family::AppMsg,
};
use veil_session::runner::{ParallelOrderedOffer, RealtimeLaneOffer, RealtimeTransportOffer};
use veil_transport::{
    Transport, TransportContext, TransportListener, TransportUri, obfs4_tcp::Obfs4TcpTransport,
};

struct Tasks(Vec<tokio::task::JoinHandle<()>>);

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

struct BlockedMain {
    stream: BoxIoStream,
    attempted: Arc<tokio::sync::Notify>,
}
impl tokio::io::AsyncRead for BlockedMain {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, b)
    }
}
impl tokio::io::AsyncWrite for BlockedMain {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.attempted.notify_one();
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

#[allow(clippy::await_holding_lock)]
async fn run_reliable(abort: bool) {
    // Rekey changes session keys, not transport lifetime. Do not inherit the
    // concurrent rotation test's process-wide 1–2 second close deadline.
    let _rotation = epic488_1_lock();
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
    let (a, b) = tokio::join!(Obfs4TcpTransport.connect(&uri, context), listener.accept());
    let a = a.unwrap();
    let b = b.unwrap();
    let a_offer = a.parallel_stream().unwrap();
    let b_offer = b.parallel_stream().unwrap();
    assert!(a_offer.can_connect());
    assert!(
        !b_offer.can_connect(),
        "accepted source port is not a listener"
    );
    let mut tasks = Tasks(Vec::new());
    let registries = [
        Arc::new(ParallelRegistry::default()),
        Arc::new(ParallelRegistry::default()),
    ];
    let accepted_registry = registries[1].clone();
    tasks.0.push(tokio::spawn(async move {
        loop {
            let connection = listener.accept().await.unwrap();
            let binding = connection.stream_channel_binding();
            match accepted_registry
                .peek_and_dispatch_with_binding(connection.into_stream().unwrap(), None, binding)
                .await
            {
                ParallelPeekOutcome::Bound | ParallelPeekOutcome::Drop(_) => {}
                ParallelPeekOutcome::Handshake(_) => {
                    panic!("auxiliary child created a canonical identity")
                }
            }
        }
    }));
    let mut receivers = Vec::new();
    let mut senders = Vec::new();
    let mut endpoints = Vec::new();
    let mut diagnostics = Vec::new();
    let mut attempted = Vec::new();
    let mut dispatchers = Vec::new();
    let app_id = [0xa0; 32];
    for (direction, (stream, handle)) in [
        (a.into_stream().unwrap(), a_offer.clone()),
        (b.into_stream().unwrap(), b_offer.clone()),
    ]
    .into_iter()
    .enumerate()
    {
        let (_, dummy) = tokio::io::duplex(64);
        let (mut runner, _) = make_swap_runner(dummy);
        let dispatcher = Arc::new(make_test_dispatcher(NodeRole::Core));
        let (endpoint, receiver) = dispatcher.app_registry.register(app_id, 1, 64);
        endpoints.push(endpoint);
        receivers.push(receiver);
        let (sender, outbox) = veil_session::frame_outbox::frame_channel(64);
        senders.push(sender);
        let writing = Arc::new(tokio::sync::Notify::new());
        attempted.push(writing.clone());
        runner.stream = Box::new(BlockedMain {
            stream,
            attempted: writing,
        });
        let offer =
            ParallelOrderedOffer::new(handle, registries[direction].clone()).with_reliable();
        diagnostics.push(offer.diagnostics());
        runner.quic_datagrams = Some(RealtimeLaneOffer {
            peer_datagrams: true,
            transport: RealtimeTransportOffer::Ordered(offer),
            peer_rotates: true,
            peer_flows: true,
            peer_circuit_datagrams: true,
            peer_neutral_forwards: true,
            parallel: None,
        });
        let (tx, rx) = if direction == 0 {
            ([1; 32], [2; 32])
        } else {
            ([2; 32], [1; 32])
        };
        runner.local_node_id = [direction as u8 + 1; 32];
        runner.peer_id = [2 - direction as u8; 32];
        runner.session_id = [3; 32];
        runner.raw_session_keys = Some((tx, rx, [3; 32]));
        {
            runner.crypto.tx_cipher =
                Some(veil_crypto::session_cipher::SessionCipher::new(&tx, true));
            runner.crypto.rx_cipher =
                Some(veil_crypto::session_cipher::SessionCipher::new(&rx, true));
        }
        runner.outbox = Some(outbox);
        runner.ban_list = dispatcher.abuse.ban_list.clone();
        runner.violation_tracker = dispatcher.abuse.violation_tracker.clone();
        runner.logger = dispatcher.logger.clone();
        dispatchers.push(dispatcher.clone());
        runner.dispatcher = dispatcher;
        tasks.0.push(tokio::spawn(async move {
            runner.run().await;
        }));
    }
    // Fill the canonical writer while all App sources use their real IPC lane.
    // The wrapper witnesses a Pending actual write, not an inferred sleep.
    for direction in 0..2 {
        for _ in 0..400 {
            let mut h = FrameHeader::new(FrameFamily::Session as u8, SessionMsg::Keepalive as u16);
            h.body_len = 16384;
            let mut wire = encode_header(&h).to_vec();
            wire.extend(vec![0; 16384]);
            senders[direction]
                .send((
                    veil_proto::priority::INTERACTIVE,
                    veil_bufpool::pooled_shared_from_vec(wire),
                ))
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), attempted[direction].notified())
            .await
            .unwrap();
    }
    let mut streams = [0u32; 2];
    // A pre-ready Open is permanently canonical. Use a fresh ID for each
    // attempt; receipt delivery proves both directions use the ready child.
    for direction in 0..2 {
        tokio::time::timeout(Duration::from_secs(8), async {
            for attempt in 0..100u32 {
                let id = 1000 + direction as u32 * 1000 + attempt;
                let (tx, rx) = tokio::sync::oneshot::channel();
                dispatchers[direction]
                    .pending_stream_receipts
                    .lock()
                    .unwrap()
                    .insert(([2 - direction as u8; 32], id), tx);
                send_app(
                    &senders[direction],
                    id,
                    AppMsg::AppOpen,
                    &AppOpenPayload {
                        app_id,
                        endpoint_id: 1,
                        flags: 0,
                    }
                    .encode(),
                )
                .await;
                if let Ok(Ok(status)) = tokio::time::timeout(Duration::from_millis(100), rx).await {
                    assert_eq!(status, receipt_status::ACCEPTED);
                    streams[direction] = id;
                    break;
                }
                dispatchers[direction]
                    .pending_stream_receipts
                    .lock()
                    .unwrap()
                    .remove(&([2 - direction as u8; 32], id));
            }
            assert!(
                streams[direction] != 0,
                "AppOpen never bypassed canonical backlog"
            );
        })
        .await
        .unwrap();
        assert!(diagnostics[direction].reliable_frames_sent() > 0);
        assert!(
            diagnostics[direction].reliable_full_writer_bypasses() > 0,
            "child must admit while the actual canonical writer queue has zero capacity"
        );
        match tokio::time::timeout(Duration::from_secs(1), receivers[1 - direction].recv())
            .await
            .unwrap()
            .unwrap()
        {
            AppMessage::StreamOpen {
                stream_id,
                src_node_id,
                ..
            } => {
                assert_eq!(stream_id, streams[direction]);
                assert_eq!(src_node_id, [direction as u8 + 1; 32]);
            }
            other => panic!("unexpected Open {other:?}"),
        }
    }
    for seq in 0..24u64 {
        for direction in 0..2 {
            let data = vec![seq as u8; 2048];
            send_app(
                &senders[direction],
                streams[direction],
                AppMsg::AppData,
                &AppDataPayload {
                    app_id,
                    endpoint_id: 1,
                    seq,
                    data: data.clone(),
                }
                .encode(),
            )
            .await;
            match tokio::time::timeout(Duration::from_secs(2), receivers[1 - direction].recv())
                .await
                .unwrap()
                .unwrap()
            {
                AppMessage::StreamData {
                    stream_id,
                    data: received,
                } => {
                    assert_eq!(stream_id, streams[direction]);
                    assert_eq!(received, data);
                }
                other => panic!("unexpected Data {other:?}"),
            }
        }
    }
    if abort {
        let peer = [2; 32];
        let id = streams[0];
        let (receipt, waiter) = tokio::sync::oneshot::channel();
        dispatchers[0]
            .pending_stream_receipts
            .lock()
            .unwrap()
            .insert((peer, id), receipt);
        let (data, mut reader) = tokio::sync::mpsc::channel(4);
        dispatchers[0]
            .veil_stream_rx
            .lock()
            .unwrap()
            .insert((peer, id), data);
        tasks.0[1].abort();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap(),
            receipt_status::REJECTED
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), reader.recv())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !dispatchers[0]
                .pending_stream_receipts
                .lock()
                .unwrap()
                .contains_key(&(peer, id))
        );
        assert!(
            !dispatchers[0]
                .veil_stream_rx
                .lock()
                .unwrap()
                .contains_key(&(peer, id))
        );
        let mut closed = std::collections::HashSet::new();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !closed.contains(&streams[0]) || !closed.contains(&streams[1]) {
                match receivers[0].recv().await.unwrap() {
                    AppMessage::StreamClose { stream_id } => {
                        assert!(closed.insert(stream_id), "duplicate abort notification");
                    }
                    other => panic!("unexpected abort {other:?}"),
                }
            }
        })
        .await
        .unwrap();
        return;
    }
    for direction in 0..2 {
        send_app(
            &senders[direction],
            streams[direction],
            AppMsg::AppClose,
            &AppClosePayload {
                app_id,
                endpoint_id: 1,
                reason: 0,
            }
            .encode(),
        )
        .await;
        assert!(
            matches!(tokio::time::timeout(Duration::from_secs(2),receivers[1-direction].recv()).await.unwrap().unwrap(),
            AppMessage::StreamClose { stream_id } if stream_id == streams[direction])
        );
        assert!(
            receivers[1 - direction].try_recv().is_err(),
            "duplicate stream event"
        );
    }
}
async fn send_app(
    sender: &veil_session::frame_outbox::FrameSender,
    stream: u32,
    msg: AppMsg,
    body: &[u8],
) {
    let mut h = FrameHeader::new(FrameFamily::App as u8, msg as u16);
    h.stream_id = stream;
    h.set_priority(veil_proto::priority::INTERACTIVE);
    h.body_len = body.len() as u32;
    let mut wire = encode_header(&h).to_vec();
    wire.extend_from_slice(body);
    sender
        .send((
            veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
            veil_bufpool::pooled_shared_from_vec(wire),
        ))
        .await
        .unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reliable_app_streams_and_receipts_bypass_blocked_canonical_writers() {
    run_reliable(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reliable_runner_retirement_wakes_open_receipts_and_stream_readers() {
    run_reliable(true).await;
}
