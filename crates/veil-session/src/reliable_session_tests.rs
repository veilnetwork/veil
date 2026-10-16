use super::*;
use crate::frame_outbox::FrameEnvelope;
use reliable_session::{ReliableEvent, ReliableReady};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};
use veil_transport::{
    PunchedQuicRole, Transport, TransportContext, TransportListener, TransportUri,
    obfs4_tcp::Obfs4TcpTransport, promote_punched_quic,
};

fn app_frame(byte: u8) -> FrameEnvelope {
    let body = veil_proto::app::AppDataPayload {
        app_id: [0x55; 32],
        endpoint_id: 17,
        seq: 0,
        data: vec![byte; 2048],
    }
    .encode();
    let mut h = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppData as u16);
    h.stream_id = 19;
    h.body_len = body.len() as u32;
    FrameEnvelope::from((
        veil_proto::priority::INTERACTIVE,
        veil_bufpool::pooled_shared_from_vec(veil_proto::codec::encode_frame(&h, &body)),
    ))
}

pub(super) fn forward_record(byte: u8) -> Vec<u8> {
    use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};
    let body = ForwardPayload {
        next_hop_node_id: [2; 32],
        envelope: DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any([2; 32]),
            sender_node_id: [1; 32],
            src_app_id: [0x55; 32],
            app_id: [0x55; 32],
            endpoint_id: 17,
            content_id: [byte; 32],
            created_at: 1,
            ttl_secs: 60,
            payload: vec![byte; 4542],
            trace_id: 0,
            require_ack: true,
        },
        relay_hops: 0,
        delivery_attempt: Some(0),
        traffic_class: None,
    }
    .encode();
    let mut h = FrameHeader::new(
        FrameFamily::Delivery as u8,
        veil_proto::family::DeliveryMsg::Forward as u16,
    );
    h.body_len = body.len() as u32;
    veil_proto::codec::encode_frame(&h, &body)
}

async fn delivery_round_trip(
    from: &reliable_session::ReliableSession,
    to: &reliable_session::ReliableSession,
    byte: u8,
) {
    let ctx = ordered_receiver_tests::pool_fixture_context();
    let mut route = reliable_streams::ReliableStreams::new(true, ctx.dispatcher, ctx.peer_id)
        .with_delivery(true);
    let ready = from.ready().unwrap();
    let frame = forward_record(byte);
    assert_eq!(
        route.route_with_local_class(&frame, Some(ready.id()), 1),
        reliable_streams::Route::Child(ready.id())
    );
    let receipt = ready
        .handle()
        .try_send(FrameEnvelope::from((
            veil_proto::priority::INTERACTIVE,
            veil_bufpool::pooled_shared_from_vec(frame.clone()),
        )))
        .ok()
        .expect("delivery admission");
    loop {
        match to.next().await {
            ReliableEvent::Changed => {}
            ReliableEvent::Frame { child, result } => {
                let received = result.unwrap();
                route
                    .incoming(&received, reliable_streams::Route::Child(child))
                    .unwrap();
                assert_eq!(&received[..], &frame);
                let payload = veil_proto::delivery::ForwardPayload::decode(
                    &received[veil_proto::header::HEADER_SIZE..],
                )
                .unwrap();
                assert_eq!(payload.envelope.content_id, [byte; 32]);
                assert_eq!(payload.envelope.payload, vec![byte; 4542]);
                assert!(payload.envelope.require_ack);
                break;
            }
            ReliableEvent::Stopped => panic!("delivery child stopped"),
        }
    }
    receipt.wait().await.unwrap();
}

#[tokio::test]
async fn reliable_delivery_ordered_child_transfers_complete_records_both_ways_across_rekey() {
    timeout(Duration::from_secs(10), async {
        let mut f = OrderedFixture::new().await;
        assert!(f.a.reliable_delivery() && f.b.reliable_delivery());
        delivery_round_trip(f.a.reliable().unwrap(), f.b.reliable().unwrap(), 10).await;
        delivery_round_trip(f.b.reliable().unwrap(), f.a.reliable().unwrap(), 11).await;
        f.canonical_survives().await;
        let old = f.a.reliable().unwrap().ready().unwrap();
        f.a.rekey(&[4; 32], &[5; 32], [6; 32]);
        f.b.rekey(&[5; 32], &[4; 32], [6; 32]);
        assert!(old.handle().recv().await.is_err());
        until(|| {
            f.a.reliable().unwrap().ready().is_some() && f.b.reliable().unwrap().ready().is_some()
        })
        .await;
        delivery_round_trip(f.a.reliable().unwrap(), f.b.reliable().unwrap(), 12).await;
        f.canonical_survives().await;
    })
    .await
    .unwrap();
}

async fn direct_record_round_trip(
    from: &reliable_session::ReliableSession,
    to: &reliable_session::ReliableSession,
    msg: AppMsg,
    byte: u8,
) {
    let ctx = ordered_receiver_tests::pool_fixture_context();
    let mut routing = reliable_streams::ReliableStreams::new(true, ctx.dispatcher, ctx.peer_id)
        .with_direct_app(true);
    let payload = vec![byte; 4096];
    let body = if msg == AppMsg::AppSendUnopenable {
        Vec::new()
    } else {
        veil_proto::app::AppSendPayload {
            src_app_id: [1; 32],
            app_id: [2; 32],
            endpoint_id: 17,
            data: veil_bufpool::pooled_shared_from_vec(payload.clone()),
        }
        .encode()
    };
    let mut h = FrameHeader::new(FrameFamily::App as u8, msg as u16);
    h.body_len = body.len() as u32;
    let bytes = veil_proto::codec::encode_frame(&h, &body);
    let ready = from.ready().unwrap();
    assert_eq!(
        routing.route_with_local_class(&bytes, Some(ready.id()), 3),
        reliable_streams::Route::Child(ready.id())
    );
    let receipt = ready
        .handle()
        .try_send(FrameEnvelope::from((
            3,
            veil_bufpool::pooled_shared_from_vec(bytes.clone()),
        )))
        .ok()
        .expect("direct record admission");
    loop {
        match to.next().await {
            ReliableEvent::Changed => {}
            ReliableEvent::Frame { child, result } => {
                let received = result.unwrap();
                routing
                    .incoming(&received, reliable_streams::Route::Child(child))
                    .unwrap();
                assert_eq!(&received[..], &bytes);
                if msg != AppMsg::AppSendUnopenable {
                    let decoded = veil_proto::app::AppSendPayload::decode(
                        &received[veil_proto::header::HEADER_SIZE..],
                    )
                    .unwrap();
                    assert_eq!(&decoded.data[..], &payload);
                    assert_eq!(decoded.src_app_id, [1; 32]);
                    assert_eq!(decoded.app_id, [2; 32]);
                }
                break;
            }
            ReliableEvent::Stopped => panic!("direct record child stopped"),
        }
    }
    receipt.wait().await.unwrap();
}

#[tokio::test]
async fn direct_app_ordered_child_preserves_records_both_ways_and_rekey_ownership() {
    timeout(Duration::from_secs(10), async {
        let mut f = OrderedFixture::with_direct_app(true).await;
        assert!(f.a.reliable_direct_app() && f.b.reliable_direct_app());
        for msg in [
            AppMsg::AppSend,
            AppMsg::AppSendSealed,
            AppMsg::AppSendChunk,
            AppMsg::AppSendUnopenable,
        ] {
            direct_record_round_trip(f.a.reliable().unwrap(), f.b.reliable().unwrap(), msg, 31)
                .await;
            direct_record_round_trip(f.b.reliable().unwrap(), f.a.reliable().unwrap(), msg, 32)
                .await;
        }
        f.canonical_survives().await;
        let old = f.a.reliable().unwrap().ready().unwrap();
        f.a.rekey(&[4; 32], &[5; 32], [6; 32]);
        f.b.rekey(&[5; 32], &[4; 32], [6; 32]);
        assert!(old.handle().recv().await.is_err());
        until(|| {
            f.a.reliable().unwrap().ready().is_some() && f.b.reliable().unwrap().ready().is_some()
        })
        .await;
        direct_record_round_trip(
            f.b.reliable().unwrap(),
            f.a.reliable().unwrap(),
            AppMsg::AppSendSealed,
            33,
        )
        .await;
        f.canonical_survives().await;
    })
    .await
    .unwrap();
}

async fn until(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

fn send(ready: &ReliableReady, byte: u8) -> crate::reliable_frames::FrameReceipt {
    match ready.handle().try_send(app_frame(byte)) {
        Ok(receipt) => receipt,
        Err(_) => panic!("reliable admission failed"),
    }
}

async fn receive(pool: &reliable_session::ReliableSession, byte: u8) {
    loop {
        match pool.next().await {
            ReliableEvent::Changed => {}
            ReliableEvent::Stopped => panic!("pool stopped before expected frame"),
            ReliableEvent::Frame { result, .. } => {
                let frame = result.unwrap();
                let data = veil_proto::app::AppDataPayload::decode(
                    &frame[veil_proto::header::HEADER_SIZE..],
                )
                .unwrap();
                assert_eq!(data.seq, 0);
                assert_eq!(data.data, vec![byte; 2048]);
                return;
            }
        }
    }
}

#[tokio::test]
async fn reliable_pool_worker_exit_retires_snapshot_and_returns_a_terminal_event() {
    timeout(Duration::from_secs(10), async {
        let mut f = OrderedFixture::new().await;
        let ready = f.a.reliable().unwrap().ready().unwrap();
        let peer = f.b.reliable().unwrap().ready().unwrap();
        send(&peer, 9).wait().await.unwrap();
        until(|| ready.handle().record_progress().received_records == 1).await;
        // Drop the actual canonical TCP owner while the OVL1 fixture's parent
        // object and retained reliable snapshot remain alive.
        f.main[0] = broken_stream_sentinel();
        until(|| f.a.reliable().unwrap().ready().is_none()).await;
        assert!(ready.handle().recv().await.is_err());
        loop {
            match f.a.reliable().unwrap().next().await {
                ReliableEvent::Changed => {}
                ReliableEvent::Stopped => break,
                _ => panic!("unexpected frame after parent transport stopped"),
            }
        }
    })
    .await
    .unwrap();
}

struct OrderedFixture {
    a: ordered_lanes::OrderedSession,
    b: ordered_lanes::OrderedSession,
    outgoing: veil_transport::stream_parallel::StreamParallelHandle,
    diagnostics: [Arc<ParallelDiagnostics>; 2],
    main: [BoxIoStream; 2],
    accepts: tokio::task::JoinHandle<()>,
}
impl Drop for OrderedFixture {
    fn drop(&mut self) {
        self.accepts.abort();
    }
}

impl OrderedFixture {
    async fn new() -> Self {
        Self::with_direct_app(false).await
    }
    async fn with_direct_app(direct: bool) -> Self {
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
        let outgoing = a.parallel_stream().unwrap();
        let incoming = b.parallel_stream().unwrap();
        assert!(outgoing.can_connect());
        assert!(!incoming.can_connect());
        let registry = Arc::new(ParallelRegistry::default());
        let a_offer =
            ParallelOrderedOffer::new(outgoing.clone(), Arc::new(ParallelRegistry::default()))
                .with_reliable()
                .with_reliable_delivery();
        let b_offer = ParallelOrderedOffer::new(incoming, registry.clone())
            .with_reliable()
            .with_reliable_delivery();
        let a_offer = if direct {
            a_offer.with_reliable_direct_app()
        } else {
            a_offer
        };
        let b_offer = if direct {
            b_offer.with_reliable_direct_app()
        } else {
            b_offer
        };
        let diagnostics = [a_offer.diagnostics(), b_offer.diagnostics()];
        let ctx = ordered_receiver_tests::pool_fixture_context();
        let a_session = ordered_lanes::OrderedSession::new(
            a_offer,
            &[2; 32],
            &[3; 32],
            [1; 32],
            ctx.clone(),
            None,
        );
        let b_session =
            ordered_lanes::OrderedSession::new(b_offer, &[3; 32], &[2; 32], [1; 32], ctx, None);
        let accepts = tokio::spawn(async move {
            loop {
                let child = listener.accept().await.unwrap();
                let binding = child.stream_channel_binding();
                assert!(matches!(
                    registry
                        .peek_and_dispatch_with_binding(child.into_stream().unwrap(), None, binding)
                        .await,
                    ParallelPeekOutcome::Bound
                ));
            }
        });
        let result = Self {
            a: a_session,
            b: b_session,
            outgoing,
            diagnostics,
            main: [a.into_stream().unwrap(), b.into_stream().unwrap()],
            accepts,
        };
        until(|| {
            result.a.reliable().unwrap().ready().is_some()
                && result.b.reliable().unwrap().ready().is_some()
        })
        .await;
        result
    }
    async fn canonical_survives(&mut self) {
        self.main[0].write_all(b"alive").await.unwrap();
        self.main[0].flush().await.unwrap();
        let mut bytes = [0; 5];
        self.main[1].read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"alive");
    }
}

#[tokio::test]
async fn reliable_ordered_session_prewarms_one_duplex_child_and_preserves_replacement_capacity() {
    timeout(Duration::from_secs(10), async {
        let mut f = OrderedFixture::new().await;
        until(|| f.diagnostics.iter().all(|d| d.active_connections() == 7)).await;
        assert_eq!(
            f.outgoing.available_connection_slots(),
            1,
            "six expiring + one reliable leave a replacement"
        );
        let a = f.a.reliable().unwrap().ready().unwrap();
        let b = f.b.reliable().unwrap().ready().unwrap();
        assert_eq!(a.id(), b.id());
        let receipt = send(&a, 1);
        receive(f.b.reliable().unwrap(), 1).await;
        receipt.wait().await.unwrap();
        let receipt = send(&b, 2);
        receive(f.a.reliable().unwrap(), 2).await;
        receipt.wait().await.unwrap();
        f.canonical_survives().await;
        let retained = a.handle();
        f.a.rekey(&[4; 32], &[5; 32], [6; 32]);
        f.b.rekey(&[5; 32], &[4; 32], [6; 32]);
        assert!(retained.recv().await.is_err());
        until(|| {
            f.a.reliable().unwrap().ready().is_some() && f.b.reliable().unwrap().ready().is_some()
        })
        .await;
        let fresh = f.a.reliable().unwrap().ready().unwrap();
        assert_ne!(fresh.id(), a.id());
        let receipt = send(&fresh, 3);
        receive(f.b.reliable().unwrap(), 3).await;
        receipt.wait().await.unwrap();
        f.canonical_survives().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reliable_worker_keeps_completed_receive_tail_until_reader_acknowledges_failure() {
    timeout(Duration::from_secs(10), async {
        let mut f = OrderedFixture::new().await;
        let a = f.a.reliable().unwrap().ready().unwrap();
        let b = f.b.reliable().unwrap().ready().unwrap();
        send(&a, 4).wait().await.unwrap();
        // Let the bounded record reader finish before transport retirement.
        tokio::time::sleep(Duration::from_millis(50)).await;
        a.handle().close();
        b.handle().closed().await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(f.b.reliable().unwrap().ready().unwrap().id(), b.id());
        receive(f.b.reliable().unwrap(), 4).await;
        match f.b.reliable().unwrap().next().await {
            ReliableEvent::Frame { child, result } => {
                assert_eq!(child, b.id());
                assert!(result.is_err());
            }
            _ => panic!("expected terminal error after complete tail"),
        }
        f.a.reliable().unwrap().acknowledge_failure(a.id());
        f.b.reliable().unwrap().acknowledge_failure(b.id());
        until(|| {
            f.a.reliable()
                .unwrap()
                .ready()
                .is_some_and(|r| r.id() != a.id())
                && f.b
                    .reliable()
                    .unwrap()
                    .ready()
                    .is_some_and(|r| r.id() != b.id())
        })
        .await;
        let fresh = f.a.reliable().unwrap().ready().unwrap();
        send(&fresh, 5).wait().await.unwrap();
        receive(f.b.reliable().unwrap(), 5).await;
        assert!(a.handle().recv().await.is_err());
        f.canonical_survives().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reliable_punched_quic_session_uses_exclusive_accept_and_retires_retained_snapshot() {
    timeout(Duration::from_secs(10), async {
        let left = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let right = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = left.local_addr().unwrap();
        let b_addr = right.local_addr().unwrap();
        let ctx = Arc::new(TransportContext::for_debug().unwrap());
        let remote = tokio::spawn(promote_punched_quic(
            right,
            a_addr,
            ctx.clone(),
            PunchedQuicRole::Responder,
        ));
        let local = promote_punched_quic(left, b_addr, ctx, PunchedQuicRole::Initiator)
            .await
            .unwrap();
        let a_handle = local.parallel_quic().unwrap();
        assert!(a_handle.is_original_dialer());
        let mut a_stream = local.into_stream().unwrap();
        a_stream.write_all(b"main").await.unwrap();
        let remote = remote.await.unwrap().unwrap();
        let b_handle = remote.parallel_quic().unwrap();
        assert!(!b_handle.is_original_dialer());
        let mut b_stream = remote.into_stream().unwrap();
        let mut bytes = [0; 4];
        b_stream.read_exact(&mut bytes).await.unwrap();
        let context = ordered_receiver_tests::pool_fixture_context();
        let mut a = parallel_lanes::ParallelSession::new(
            ParallelQuicOffer::new(a_handle.clone())
                .with_duplex()
                .with_reliable()
                .with_reliable_delivery()
                .with_reliable_direct_app(),
            &[2; 32],
            &[3; 32],
            [1; 32],
            context.clone(),
            None,
        );
        let b = parallel_lanes::ParallelSession::new(
            ParallelQuicOffer::new(b_handle)
                .with_duplex()
                .with_reliable()
                .with_reliable_delivery()
                .with_reliable_direct_app(),
            &[3; 32],
            &[2; 32],
            [1; 32],
            context,
            None,
        );
        until(|| {
            a.reliable().unwrap().ready().is_some() && b.reliable().unwrap().ready().is_some()
        })
        .await;
        let ready = a.reliable().unwrap().ready().unwrap();
        assert_eq!(
            a_handle.available_connection_slots(),
            veil_transport::QuicParallelHandle::CONNECTIONS_PER_DIRECTION - 1
        );
        // A prepared-but-unused child can expire without a send setting its
        // broken flag. Preparing again must rebuild it before claiming Ready.
        until(|| a.prepare(veil_proto::priority::REALTIME)).await;
        let index = a
            .prepare_frame(
                veil_proto::priority::REALTIME,
                &[],
                RealtimeLaneFrameKind::DirectApp,
            )
            .unwrap();
        let old = {
            let sender = a.sender_arc(index);
            let sender = sender.lock().unwrap();
            sender.handle.quic().unwrap().clone()
        };
        old.close();
        assert!(old.is_closed());
        assert!(
            !a.prepare(veil_proto::priority::REALTIME),
            "a closed unused child must not remain Ready"
        );
        until(|| a.prepare(veil_proto::priority::REALTIME)).await;
        let sender = a.sender_arc(index);
        assert_ne!(
            sender
                .lock()
                .unwrap()
                .handle
                .quic()
                .unwrap()
                .local_trace_id(),
            old.local_trace_id()
        );
        until(|| a.prepare(crate::LOCAL_SIGNALING_LANE)).await;
        let mut reserved = Vec::new();
        while a_handle.available_connection_slots() > 2 {
            let child = a_handle.connect().await.unwrap();
            let close = child.quic_datagrams().unwrap();
            let mut stream = child.into_stream().unwrap();
            // Let the peer accept this stream; with no preface bytes its
            // two TLS accept tasks would wait for the first stream forever.
            stream.write_all(b"hold").await.unwrap();
            reserved.push((close, stream));
        }
        assert_eq!(a_handle.available_connection_slots(), 2);
        for _ in 0..20 {
            assert!(a.prepare(veil_proto::priority::REALTIME));
            assert!(
                a.prepare(crate::LOCAL_SIGNALING_LANE),
                "using a ready channel must not retire and restart the signaling child"
            );
        }
        for (close, _) in reserved {
            close.close();
        }
        assert!(a.reliable_delivery() && b.reliable_delivery());
        delivery_round_trip(a.reliable().unwrap(), b.reliable().unwrap(), 13).await;
        delivery_round_trip(b.reliable().unwrap(), a.reliable().unwrap(), 14).await;
        assert!(a.reliable_direct_app() && b.reliable_direct_app());
        for msg in [
            AppMsg::AppSend,
            AppMsg::AppSendSealed,
            AppMsg::AppSendChunk,
            AppMsg::AppSendUnopenable,
        ] {
            direct_record_round_trip(a.reliable().unwrap(), b.reliable().unwrap(), msg, 41).await;
            direct_record_round_trip(b.reliable().unwrap(), a.reliable().unwrap(), msg, 42).await;
        }
        send(&ready, 6).wait().await.unwrap();
        receive(b.reliable().unwrap(), 6).await;
        drop(a);
        assert!(ready.handle().recv().await.is_err());
        until(|| {
            a_handle.available_connection_slots()
                == veil_transport::QuicParallelHandle::CONNECTIONS_PER_DIRECTION
        })
        .await;
        a_stream.write_all(b"alive").await.unwrap();
        let mut bytes = [0; 5];
        b_stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"alive");
    })
    .await
    .unwrap();
}
