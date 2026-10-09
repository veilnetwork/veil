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
use veil_proto::{AppRtDataPayload, family::AppMsg};
use veil_session::runner::{ParallelOrderedOffer, RealtimeLaneOffer, RealtimeTransportOffer};
use veil_transport::{
    Transport, TransportContext, TransportListener, TransportUri, obfs4_tcp::Obfs4TcpTransport,
};

struct Tasks(Vec<tokio::task::JoinHandle<()>>);

fn record_media(message: AppMessage, direction: usize, seen: &mut std::collections::HashSet<u32>) {
    match message {
        AppMessage::RtData {
            src_node_id,
            payload,
        } => {
            assert_eq!(src_node_id, [direction as u8 + 1; 32]);
            assert!(payload.seq < 160, "unexpected sequence");
            assert_eq!(
                payload.payload,
                vec![payload.seq as u8; if payload.seq % 2 == 0 { 160 } else { 6000 }]
            );
            assert!(seen.insert(payload.seq), "duplicate media frame");
        }
        other => panic!("unexpected dispatch {other:?}"),
    }
}
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
async fn run(rotate: bool) {
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
        runner.stream = if rotate {
            stream
        } else {
            Box::new(BlockedMain {
                stream,
                attempted: writing,
            })
        };
        let offer = ParallelOrderedOffer::new(handle, registries[direction].clone());
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
        if rotate {
            runner.crypto.tx_cipher =
                Some(veil_crypto::session_cipher::SessionCipher::new(&tx, true));
            runner.crypto.rx_cipher =
                Some(veil_crypto::session_cipher::SessionCipher::new(&rx, true));
            if direction == 0 {
                runner.rekey.time_threshold_secs = 1;
            }
        }
        runner.outbox = Some(outbox);
        runner.ban_list = dispatcher.abuse.ban_list.clone();
        runner.violation_tracker = dispatcher.abuse.violation_tracker.clone();
        runner.logger = dispatcher.logger.clone();
        runner.dispatcher = dispatcher;
        tasks.0.push(tokio::spawn(async move {
            runner.run().await;
        }));
    }
    let sources = [
        veil_proto::priority::REALTIME,
        veil_proto::priority::BULK,
        veil_proto::priority::BACKGROUND,
        veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
    ];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            // Request every producer before observing readiness. Short-circuit
            // `all` would request just one per tick and can miss this fixture's
            // deliberately short one-second credential generation.
            let mut channels_ready = true;
            for sender in &senders {
                for &source in &sources {
                    channels_ready &= sender.request_local_datagram_channel(source)
                        == veil_session::LocalDatagramChannelState::Ready;
                }
            }
            if diagnostics.iter().all(|d| d.active_connections() == 6) && channels_ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("duplex pool did not become ready at both endpoints");
    assert_eq!(diagnostics[0].active_connections(), 6);
    assert_eq!(diagnostics[1].active_connections(), 6);
    assert_eq!(
        a_offer.available_connection_slots(),
        veil_transport::stream_parallel::StreamParallelHandle::CONNECTIONS_PER_DIRECTION - 6
    );
    if !rotate {
        // Reliable writers really enter Pending before media is submitted.
        for direction in 0..2 {
            let mut header =
                FrameHeader::new(FrameFamily::Session as u8, SessionMsg::Keepalive as u16);
            header.body_len = 0;
            senders[direction]
                .try_send((
                    veil_proto::priority::INTERACTIVE,
                    veil_bufpool::pooled_shared_from_vec(encode_header(&header).to_vec()),
                ))
                .unwrap();
            tokio::time::timeout(Duration::from_secs(1), attempted[direction].notified())
                .await
                .unwrap();
        }
    }
    let mut seen: [std::collections::HashSet<u32>; 2] = Default::default();
    let mut last_received = [std::time::Instant::now(); 2];
    tokio::time::timeout(Duration::from_secs(12), async {
        for seq in 0..if rotate { 160 } else { 16 } {
            for direction in 0..2 {
                let data = vec![seq as u8; if seq % 2 == 0 { 160 } else { 6000 }];
                let body = AppRtDataPayload {
                    src_app_id: [0xb0; 32],
                    app_id,
                    endpoint_id: 1,
                    seq,
                    timestamp_us: u64::from(seq) * 20_000,
                    marker: 0,
                    payload_type: 0,
                    payload: data.clone(),
                }
                .encode();
                let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppRtData as u16);
                header.set_priority(veil_proto::priority::REALTIME);
                header.body_len = body.len() as u32;
                let mut frame = encode_header(&header).to_vec();
                frame.extend(body);
                senders[direction]
                    .try_send((
                        sources[seq as usize % 4],
                        veil_bufpool::pooled_shared_from_vec(frame),
                    ))
                    .unwrap();
                if rotate {
                    // Retirement may discard in-flight lossy records. Keep
                    // producing fresh frames instead of waiting forever for
                    // exactly the record whose old parent was retired.
                    while let Ok(message) = receivers[1 - direction].try_recv() {
                        record_media(message, direction, &mut seen[direction]);
                        last_received[direction] = std::time::Instant::now();
                    }
                    assert!(last_received[direction].elapsed() < Duration::from_secs(2),
                        "ordered source did not resume after rekey");
                    continue;
                }
                match tokio::time::timeout(Duration::from_secs(2), receivers[1 - direction].recv())
                    .await
                    .unwrap_or_else(|error| panic!(
                        "receive {error:?}: seq={seq} direction={direction} rekeys={:?} active={:?} sent={:?}",
                        diagnostics.iter().map(|d| d.rekeys()).collect::<Vec<_>>(),
                        diagnostics.iter().map(|d| d.active_connections()).collect::<Vec<_>>(),
                        diagnostics.iter().map(|d| sources.map(|p| d.sent(p))).collect::<Vec<_>>(),
                    ))
                    .unwrap()
                {
                    AppMessage::RtData {
                        src_node_id,
                        payload,
                    } => {
                        assert_eq!(src_node_id, [direction as u8 + 1; 32]);
                        assert_eq!(payload.seq, seq);
                        assert_eq!(payload.payload, data);
                    }
                    other => panic!("unexpected dispatch {other:?}"),
                }
            }
            if rotate {
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        }
    })
    .await
    .unwrap();
    if rotate {
        // Drain records already admitted before checking both pre- and
        // post-rekey delivery on every local source, with no duplicate or
        // corrupted payload accepted during the transition.
        let until = tokio::time::Instant::now() + Duration::from_millis(200);
        while tokio::time::Instant::now() < until {
            for direction in 0..2 {
                while let Ok(message) = receivers[1 - direction].try_recv() {
                    record_media(message, direction, &mut seen[direction]);
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for messages in &seen {
            for source in 0..4 {
                assert!(
                    messages.iter().any(|seq| *seq < 16 && *seq % 4 == source),
                    "source never delivered before rekey"
                );
                assert!(
                    messages.iter().any(|seq| *seq >= 128 && *seq % 4 == source),
                    "source never delivered fresh media after rekey"
                );
            }
        }
    }
    for diagnostic in &diagnostics {
        for priority in sources {
            assert!(
                diagnostic.sent(priority) > 0,
                "local source never used its separate ordered connection"
            );
        }
        if rotate {
            assert!(
                diagnostic.rekeys() > 0,
                "ordinary runner never rekeyed the ordered pool"
            );
        }
    }
    for receiver in &mut receivers {
        assert!(receiver.try_recv().is_err(), "duplicate message");
    }
    for task in tasks.0.iter().skip(1) {
        task.abort();
    }
    for task in tasks.0.drain(1..) {
        let _ = task.await;
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while diagnostics.iter().any(|d| d.active_connections() != 0)
            || a_offer.available_connection_slots() != 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retired runner retained ordered children or canonical TCP writer");
    assert_eq!(
        a_offer.available_connection_slots(),
        0,
        "canonical transport retirement must revoke dials"
    );
    assert!(senders.iter().all(|sender| {
        sources.iter().all(|&p| {
            sender.local_datagram_channel_state(p)
                == veil_session::LocalDatagramChannelState::Unsupported
        })
    }));
    drop(endpoints);
}

#[tokio::test]
async fn ordered_children_dispatch_all_sources_with_blocked_parent_writer() {
    run(false).await;
}

#[tokio::test]
async fn ordered_children_rebind_after_normal_runner_rekey() {
    run(true).await;
}

#[allow(clippy::await_holding_lock)]
async fn run_neutral_forward(negotiated: bool, blocked: bool) {
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
        let mut dispatcher = make_test_dispatcher(NodeRole::Core);
        dispatcher.local_node_id = [direction as u8 + 1; 32];
        let dispatcher = Arc::new(dispatcher);
        let (endpoint, receiver) = dispatcher.app_registry.register(app_id, 1, 64);
        endpoints.push(endpoint);
        receivers.push(receiver);
        let (sender, outbox) = veil_session::frame_outbox::frame_channel(64);
        senders.push(sender);
        let writing = Arc::new(tokio::sync::Notify::new());
        attempted.push(writing.clone());
        runner.stream = if !blocked {
            stream
        } else {
            Box::new(BlockedMain {
                stream,
                attempted: writing,
            })
        };
        let offer = ParallelOrderedOffer::new(handle, registries[direction].clone());
        diagnostics.push(offer.diagnostics());
        runner.quic_datagrams = Some(RealtimeLaneOffer {
            peer_datagrams: true,
            transport: RealtimeTransportOffer::Ordered(offer),
            peer_rotates: true,
            peer_flows: true,
            peer_circuit_datagrams: true,
            peer_neutral_forwards: negotiated,
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
        runner.dispatcher = dispatcher;
        tasks.0.push(tokio::spawn(async move {
            runner.run().await;
        }));
    }

    tokio::time::timeout(Duration::from_secs(2), async {
        while !senders.iter().all(|s| s.has_datagram_transport()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("ordered runner readiness");
    for sender in &senders {
        assert_eq!(sender.has_neutral_forward_datagram_transport(), negotiated);
    }
    // Generic readiness is advertised before child authentication. Wait for
    // the existing bounded pool; this isolates selection from startup fallback.
    tokio::time::timeout(Duration::from_secs(3), async {
        while !diagnostics.iter().all(|d| d.active_connections() == 6) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ordered child pool did not authenticate");
    // Enter the ORDINARY transit queue, with the neutral wire marker used by
    // the production delivery dispatcher. Local primary hints must play no part.
    for direction in 0..2usize {
        let body = veil_proto::delivery::ForwardPayload {
            next_hop_node_id: [2 - direction as u8; 32],
            relay_hops: 1,
            delivery_attempt: None,
            traffic_class: Some(veil_proto::priority::INTERACTIVE),
            envelope: veil_proto::delivery::DeliveryEnvelope {
                recipient: veil_proto::recipient::Recipient::any([2 - direction as u8; 32]),
                sender_node_id: [direction as u8 + 1; 32],
                src_app_id: [0xb0; 32],
                app_id,
                endpoint_id: 1,
                content_id: [direction as u8 + 9; 32],
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                ttl_secs: veil_proto::delivery::FORWARD_REALTIME_TTL_SECS,
                payload: vec![direction as u8 + 42; 64],
                trace_id: 0,
                require_ack: false,
            },
        }
        .encode();
        let mut header = FrameHeader::new(
            FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );
        header.set_priority(veil_proto::priority::INTERACTIVE);
        header.body_len = body.len() as u32;
        let mut frame = encode_header(&header).to_vec();
        frame.extend(body);
        senders[direction]
            .try_send((
                veil_proto::priority::INTERACTIVE,
                veil_bufpool::pooled_shared_from_vec(frame),
            ))
            .unwrap();
    }
    for direction in 0..2usize {
        let received =
            tokio::time::timeout(Duration::from_secs(2), receivers[1 - direction].recv()).await;
        if negotiated || !blocked {
            match received
                .expect("neutral Forward remained on the blocked canonical writer")
                .unwrap()
            {
                AppMessage::Deliver {
                    src_node_id, data, ..
                } => {
                    assert_eq!(src_node_id, [direction as u8 + 1; 32]);
                    assert_eq!(&*data, &[direction as u8 + 42; 64]);
                }
                other => panic!("unexpected neutral delivery {other:?}"),
            }
        } else {
            assert!(
                received.is_err(),
                "unsupported peer received an unnegotiated neutral child record"
            );
        }
    }
    for d in &diagnostics {
        if negotiated {
            assert!(d.transit_sent() > 0, "Forward did not use a neutral child");
            assert!(d.transit_shards_used_this_generation() <= 2);
        } else {
            assert_eq!(d.transit_sent(), 0);
        }
        assert_eq!(
            d.sent(veil_proto::priority::REALTIME),
            0,
            "transit acquired local source priority"
        );
        assert_eq!(d.sent(veil_proto::priority::BULK), 0);
    }
    for task in &tasks.0 {
        task.abort();
    }
    for task in tasks.0.drain(..) {
        let _ = task.await;
    }
    for sender in &senders {
        assert!(!sender.has_datagram_transport());
    }
}

#[tokio::test]
async fn neutral_forward_uses_ordered_children_without_source_priority() {
    run_neutral_forward(true, true).await;
}

#[tokio::test]
async fn neutral_forward_keeps_unnegotiated_ordered_compatibility() {
    run_neutral_forward(false, true).await;
    run_neutral_forward(false, false).await;
}
