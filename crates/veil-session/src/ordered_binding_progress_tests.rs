//! A blocked proof-ACK write must not park the entire ordered-child pool.
//! The parent uses a real obfs4 offer/connection budget. Deterministic child
//! pipes carry the actual exporter-bound proofs through ParallelRegistry.
use super::*;
use crate::parallel_binding::{HELLO_BYTES, PendingParallelBinding};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use veil_transport::{Transport, TransportContext, TransportUri, obfs4_tcp::Obfs4TcpTransport};

struct BlockAck {
    inner: tokio::io::DuplexStream,
    entered: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    seen: bool,
}
impl AsyncRead for BlockAck {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for BlockAck {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.seen {
            self.seen = true;
            self.entered.fetch_add(1, Ordering::SeqCst);
        }
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl Drop for BlockAck {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

struct Client {
    stream: tokio::io::DuplexStream,
    pending: PendingParallelBinding,
}
impl Client {
    async fn finish(mut self) -> BoundOrderedChannel {
        let mut ack = [0; 32];
        self.stream.read_exact(&mut ack).await.unwrap();
        self.pending
            .finish(&ack)
            .unwrap()
            .into_ordered(Box::new(self.stream))
            .unwrap()
    }
}

struct Fixture {
    offer: ParallelOrderedOffer,
    source: ParallelParent,
    destination: Option<ParallelParent>,
    incoming: Option<mpsc::Receiver<BoundOrderedChild>>,
    entered: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    _registration: ParallelRegistration,
    _canonical: [veil_transport::BoxIoStream; 2],
}
impl Fixture {
    async fn new() -> Self {
        let mut context = TransportContext::for_debug().unwrap();
        context.obfs4_psk = Some(Arc::new([0x42; 32]));
        let context = Arc::new(context);
        let listener = Obfs4TcpTransport
            .bind(
                &TransportUri::Obfs4Tcp {
                    host: "127.0.0.1".into(),
                    port: 0,
                },
                context.clone(),
            )
            .await
            .unwrap();
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
        let (a, b) = (a.unwrap(), b.unwrap());
        let offer = ParallelOrderedOffer::new(b.parallel_stream().unwrap(), Arc::default());
        assert!(!offer.handle.can_connect());
        let source = ParallelParent::new([1; 32], [2; 32], [3; 32]);
        let destination = ParallelParent::new([1; 32], [3; 32], [2; 32]);
        let (tx, incoming) = mpsc::channel(StreamParallelHandle::CONNECTIONS_PER_DIRECTION);
        let registration = offer
            .registry
            .register_ordered(
                [1; 32],
                destination.handle(),
                offer.handle.clone(),
                offer.diagnostics.clone(),
                tx,
            )
            .unwrap();
        Self {
            offer,
            source,
            destination: Some(destination),
            incoming: Some(incoming),
            entered: Arc::default(),
            dropped: Arc::default(),
            _registration: registration,
            _canonical: [a.into_stream().unwrap(), b.into_stream().unwrap()],
        }
    }
    async fn child(&self, blocked: bool, exporter: u8) -> (ParallelPeekOutcome, Client) {
        let binding = [exporter; 32];
        let (hello, pending) = self.source.begin(binding).unwrap();
        assert_eq!(hello.len(), HELLO_BYTES);
        let (mut client, server) = tokio::io::duplex(65536);
        client.write_all(&hello).await.unwrap();
        let server: veil_transport::BoxIoStream = if blocked {
            Box::new(BlockAck {
                inner: server,
                entered: self.entered.clone(),
                dropped: self.dropped.clone(),
                seen: false,
            })
        } else {
            Box::new(server)
        };
        let outcome = self
            .offer
            .registry
            .peek_and_dispatch_with_binding(server, None, Some(binding))
            .await;
        (
            outcome,
            Client {
                stream: client,
                pending,
            },
        )
    }
    fn start(&mut self, pool: Arc<Mutex<Pool>>) -> RealtimeReceiverTask {
        worker(
            self.offer.clone(),
            self.destination.as_ref().unwrap().handle(),
            super::super::ordered_receiver_tests::pool_fixture_context(),
            pool,
            Weak::new(),
            self.incoming.take().unwrap(),
        )
    }
    async fn stop(&mut self, task: &mut RealtimeReceiverTask) {
        drop(self.destination.take());
        (&mut task.0).await.unwrap();
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cold_prepare_does_not_change_who_gets_the_first_completed_child() {
    use crate::LocalDatagramChannelState::{Ready as ChannelReady, Warming};
    let mut outcomes = Vec::new();
    for mode in 0..4 {
        let eager = mode == 1;
        let fixture = Fixture::new().await;
        let status = Arc::new(LocalDatagramStatus::default());
        let context = super::super::ordered_receiver_tests::pool_fixture_context();
        let offer = ParallelOrderedOffer::new(fixture.offer.handle.clone(), Arc::default());
        let mut session = OrderedSession::new(
            offer,
            &[3; 32],
            &[2; 32],
            [1; 32],
            context.clone(),
            Some(status.clone()),
        );
        // Drive one authenticated completion explicitly. This models an
        // outbound attempt completing at index 1 before index 0; the worker's
        // periodic tick must not decide the result of this regression.
        session._worker.0.abort();
        assert!((&mut session._worker.0).await.unwrap_err().is_cancelled());
        let mut channels = ParallelChannels::Ordered(Box::new(session));
        tokio::time::pause();
        let before = tokio::time::Instant::now();
        if mode != 3 {
            status.request_fresh(veil_proto::priority::REALTIME);
            status.request_fresh(veil_proto::priority::BULK);
        }
        if eager {
            channels.prepare(veil_proto::priority::REALTIME);
        }
        if mode == 2 {
            // The worker publishes from its first/periodic tick even before
            // any child has completed. Exercise that same publisher twice;
            // it must not pin either pending requester to an unopened slot.
            let ParallelChannels::Ordered(session) = &channels else {
                unreachable!()
            };
            for _ in 0..2 {
                mark(
                    &mut lock!(session.pool),
                    &Arc::downgrade(session.readiness.as_ref().unwrap()),
                );
            }
        }
        if mode == 3 {
            // A failed source selection also must not reserve a nonexistent
            // child. Ordered connections are prewarmed independently of roles.
            for priority in [veil_proto::priority::REALTIME, veil_proto::priority::BULK] {
                assert!(
                    channels
                        .sender(priority, &[], RealtimeLaneFrameKind::DirectApp, None)
                        .is_none()
                );
            }
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let mut notification = Box::pin(status.notified());
            assert!(notification.as_mut().poll(&mut cx).is_ready());
            drop(notification);
            for priority in [veil_proto::priority::REALTIME, veil_proto::priority::BULK] {
                assert!(
                    channels
                        .sender(priority, &[], RealtimeLaneFrameKind::DirectApp, None)
                        .is_none()
                );
            }
            let mut notification = Box::pin(status.notified());
            assert!(
                notification.as_mut().poll(&mut cx).is_pending(),
                "repeated unavailable-source probes must not keep the runner runnable"
            );
        }
        let ParallelChannels::Ordered(session) = &channels else {
            unreachable!()
        };
        let binding = [61; 32];
        let (hello, pending) = fixture.source.begin(binding).unwrap();
        let (ack, local_keys) = session.parent.handle().accept(&hello, binding).unwrap();
        let remote_keys = pending.finish(&ack).unwrap();
        let (a, b) = tokio::io::duplex(65536);
        let remote = remote_keys.into_ordered(Box::new(a)).unwrap();
        let local = local_keys.into_ordered(Box::new(b)).unwrap();
        {
            let mut pool = lock!(session.pool);
            pool.slots[1] = Some(Ready::new(
                Owner::Outgoing(local),
                session.parent.handle(),
                context,
                session.offer.diagnostics.clone(),
            ));
            mark(
                &mut pool,
                &Arc::downgrade(session.readiness.as_ref().unwrap()),
            );
        }
        let primary = status.state(veil_proto::priority::REALTIME);
        let secondary = status.state(veil_proto::priority::BULK);
        let no_timer = tokio::time::Instant::now() == before;
        tokio::time::resume();
        if primary == ChannelReady {
            let body = veil_proto::app::AppRtDataPayload {
                src_app_id: [1; 32],
                app_id: [2; 32],
                endpoint_id: 1,
                seq: 19,
                timestamp_us: 0,
                marker: 0,
                payload_type: 111,
                payload: vec![0x57; 32],
            }
            .encode();
            let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppRtData as u16);
            header.set_priority(veil_proto::priority::REALTIME);
            header.body_len = body.len() as u32;
            let mut frame = encode_header(&header).to_vec();
            frame.extend_from_slice(&body);
            let sender = channels
                .sender(
                    veil_proto::priority::REALTIME,
                    &body,
                    RealtimeLaneFrameKind::DirectApp,
                    None,
                )
                .unwrap();
            let datagrams = lock!(sender).tx.encode_frame(1, &frame, 1200).unwrap();
            assert_eq!(datagrams.len(), 1);
            lock!(sender).handle.send(&datagrams[0]).unwrap();
            let received =
                tokio::time::timeout(std::time::Duration::from_secs(2), remote.handle().recv())
                    .await
                    .unwrap()
                    .unwrap();
            let mut decoder = crate::datagram_flows::SessionDatagramRx::new(
                remote.keys.rx_key(),
                &remote.keys.session_id,
                true,
            );
            assert_eq!(
                decoder
                    .decode_datagram(&received, std::time::Instant::now())
                    .unwrap()
                    .unwrap(),
                frame
            );
        }
        outcomes.push((eager, primary, secondary, no_timer));
        drop(channels);
        drop(remote);
        drop(fixture);
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }
    assert_eq!(
        outcomes[0],
        (false, ChannelReady, Warming, true),
        "control without eager publication must use the completed child"
    );
    assert_eq!(
        outcomes[1],
        (true, ChannelReady, Warming, true),
        "eager publication must not reserve unopened children ahead of the first completion"
    );
    assert_eq!(
        outcomes[2],
        (false, ChannelReady, Warming, true),
        "periodic publication must not reserve unopened children ahead of the first completion"
    );
    assert_eq!(
        outcomes[3],
        (false, ChannelReady, Warming, true),
        "failed source selections must not reserve unopened children ahead of the first completion"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn failed_ready_child_rearms_demand_before_a_spare_completion() {
    use crate::LocalDatagramChannelState::{Ready as ChannelReady, Warming};
    for &priority in ORDERED_PRIORITIES {
        let fixture = Fixture::new().await;
        let status = Arc::new(LocalDatagramStatus::default());
        let context = super::super::ordered_receiver_tests::pool_fixture_context();
        let offer = ParallelOrderedOffer::new(fixture.offer.handle.clone(), Arc::default());
        let mut session = OrderedSession::new(
            offer,
            &[3; 32],
            &[2; 32],
            [1; 32],
            context.clone(),
            Some(status.clone()),
        );
        session._worker.0.abort();
        assert!((&mut session._worker.0).await.unwrap_err().is_cancelled());
        let make_child = |binding| {
            let (hello, pending) = fixture.source.begin(binding).unwrap();
            let (ack, local_keys) = session.parent.handle().accept(&hello, binding).unwrap();
            let remote_keys = pending.finish(&ack).unwrap();
            let (a, b) = tokio::io::duplex(65536);
            let remote = remote_keys.into_ordered(Box::new(a)).unwrap();
            let local = local_keys.into_ordered(Box::new(b)).unwrap();
            let ready = Ready::new(
                Owner::Outgoing(local),
                session.parent.handle(),
                context.clone(),
                session.offer.diagnostics.clone(),
            );
            (ready, remote)
        };
        let (initial, _old_remote) = make_child([71; 32]);
        let (spare, remote) = make_child([72; 32]);
        tokio::time::pause();
        let before = tokio::time::Instant::now();
        status.request_fresh(priority);
        lock!(session.pool).slots[0] = Some(initial);
        mark(
            &mut lock!(session.pool),
            &Arc::downgrade(session.readiness.as_ref().unwrap()),
        );
        assert_eq!(status.state(priority), ChannelReady);
        assert_eq!(status.pending(), 0);
        let sender = session
            .sender_with_carrier(priority, &[], RealtimeLaneFrameKind::DirectApp, None)
            .unwrap();
        lock!(sender).broken = true;
        // The receiver/record writer can fail between periodic publications.
        // Do not refresh readiness or send again after this single failure.
        assert!(
            session
                .sender_with_carrier(priority, &[], RealtimeLaneFrameKind::DirectApp, None)
                .is_none()
        );
        assert_eq!(
            status.state(priority),
            Warming,
            "a failed selection must invalidate its stale Ready snapshot"
        );
        assert_ne!(status.pending(), 0, "the replacement demand must survive");
        {
            let mut pool = lock!(session.pool);
            pool.slots[1] = Some(spare);
            mark(
                &mut pool,
                &Arc::downgrade(session.readiness.as_ref().unwrap()),
            );
        }
        assert_eq!(status.state(priority), ChannelReady);
        assert_eq!(status.pending(), 0);
        assert_eq!(tokio::time::Instant::now(), before);
        tokio::time::resume();
        let replacement = session
            .sender_with_carrier(priority, &[], RealtimeLaneFrameKind::DirectApp, None)
            .unwrap();
        assert!(!Arc::ptr_eq(&sender, &replacement));
        let frame = super::super::ordered_receiver_tests::app_frame(23, 32);
        let datagrams = lock!(replacement).tx.encode_frame(1, &frame, 1200).unwrap();
        assert_eq!(datagrams.len(), 1);
        lock!(replacement).handle.send(&datagrams[0]).unwrap();
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(2), remote.handle().recv())
                .await
                .unwrap()
                .unwrap();
        let mut decoder = crate::datagram_flows::SessionDatagramRx::new(
            remote.keys.rx_key(),
            &remote.keys.session_id,
            true,
        );
        assert_eq!(
            decoder
                .decode_datagram(&received, std::time::Instant::now())
                .unwrap()
                .unwrap(),
            frame
        );
        drop(session);
        drop(remote);
        drop(fixture);
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn warmed_ordered_readiness_request_is_published_without_the_periodic_tick() {
    use crate::LocalDatagramChannelState::{Ready as ChannelReady, Warming};
    let fixture = Fixture::new().await;
    let status = Arc::new(LocalDatagramStatus::default());
    let offer = ParallelOrderedOffer::new(fixture.offer.handle.clone(), Arc::default());
    let context = super::super::ordered_receiver_tests::pool_fixture_context();
    let mut channels = ParallelChannels::Ordered(Box::new(OrderedSession::new(
        offer,
        &[3; 32],
        &[2; 32],
        [1; 32],
        context,
        Some(status.clone()),
    )));
    let binding = [51; 32];
    let (hello, pending) = fixture.source.begin(binding).unwrap();
    let (mut client, server) = tokio::io::duplex(65536);
    client.write_all(&hello).await.unwrap();
    let ParallelChannels::Ordered(session) = &channels else {
        unreachable!()
    };
    let outcome = session
        .offer
        .registry
        .peek_and_dispatch_with_binding(Box::new(server), None, Some(binding))
        .await;
    assert!(matches!(outcome, ParallelPeekOutcome::Bound));
    let client = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        Client {
            stream: client,
            pending,
        }
        .finish(),
    )
    .await
    .unwrap();
    for _ in 0..128 {
        if lock!(session.pool).slots.iter().flatten().count() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(lock!(session.pool).slots.iter().flatten().count(), 1);
    // There is one real, authenticated, already-warmed child, but no producer
    // has requested ownership yet. No wall-time performance threshold here.
    assert_eq!(status.state(veil_proto::priority::REALTIME), Warming);
    tokio::time::pause();
    let before = tokio::time::Instant::now();
    status.request_fresh(veil_proto::priority::REALTIME);
    status.request_fresh(veil_proto::priority::BACKGROUND);
    channels.prepare(veil_proto::priority::REALTIME);
    let primary = status.state(veil_proto::priority::REALTIME);
    let secondary = status.state(veil_proto::priority::BACKGROUND);
    let no_timer = tokio::time::Instant::now() == before;
    tokio::time::resume();
    if primary != ChannelReady || !no_timer {
        drop(channels);
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            primary, ChannelReady,
            "ordered readiness request waited for the periodic worker tick"
        );
        assert!(no_timer);
        return;
    }
    assert_eq!(
        secondary, Warming,
        "one child cannot serve two distinct owners"
    );
    let body = veil_proto::app::AppRtDataPayload {
        src_app_id: [1; 32],
        app_id: [2; 32],
        endpoint_id: 1,
        seq: 17,
        timestamp_us: 0,
        marker: 0,
        payload_type: 111,
        payload: vec![0x55; 32],
    }
    .encode();
    let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppRtData as u16);
    header.set_priority(veil_proto::priority::REALTIME);
    header.body_len = body.len() as u32;
    let mut frame = encode_header(&header).to_vec();
    frame.extend_from_slice(&body);
    let sender = channels
        .sender(
            veil_proto::priority::REALTIME,
            &body,
            RealtimeLaneFrameKind::DirectApp,
            None,
        )
        .unwrap();
    let datagrams = lock!(sender).tx.encode_frame(1, &frame, 1200).unwrap();
    assert_eq!(datagrams.len(), 1);
    lock!(sender).handle.send(&datagrams[0]).unwrap();
    let received = tokio::time::timeout(std::time::Duration::from_secs(2), client.handle().recv())
        .await
        .unwrap()
        .unwrap();
    let mut decoder = crate::datagram_flows::SessionDatagramRx::new(
        client.keys.rx_key(),
        &client.keys.session_id,
        true,
    );
    assert_eq!(
        decoder
            .decode_datagram(&received, std::time::Instant::now())
            .unwrap()
            .unwrap(),
        frame
    );
    let ParallelChannels::Ordered(session) = &channels else {
        unreachable!()
    };
    session.parent.retire();
    status.request_fresh(veil_proto::priority::REALTIME);
    channels.prepare(veil_proto::priority::REALTIME);
    assert_ne!(
        status.state(veil_proto::priority::REALTIME),
        ChannelReady,
        "retired parent cannot publish readiness"
    );
    drop(channels);
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_incoming_ack_does_not_delay_a_second_authenticated_child() {
    let mut fixture = Fixture::new().await;
    let (first, _first_client) = fixture.child(true, 4).await;
    assert!(matches!(first, ParallelPeekOutcome::Bound));
    let pool = Arc::new(Mutex::new(Pool::default()));
    let mut task = fixture.start(pool.clone());
    while fixture.entered.load(Ordering::SeqCst) != 1 {
        tokio::task::yield_now().await;
    }
    let (second, client) = fixture.child(false, 5).await;
    assert!(matches!(second, ParallelPeekOutcome::Bound));
    tokio::time::pause();
    let at = tokio::time::Instant::now();
    for _ in 0..128 {
        tokio::task::yield_now().await;
    }
    let ready = lock!(pool).slots.iter().flatten().count();
    let no_timer = tokio::time::Instant::now() == at;
    tokio::time::resume();
    // Always tear down before asserting the regression; a failed check must
    // not leave a live worker or rely on its three-second timeout for cleanup.
    if ready != 1 || !no_timer {
        fixture.stop(&mut task).await;
        assert_eq!(ready, 1, "ready second child waited behind the first ACK");
        assert!(no_timer);
        return;
    }
    let client = tokio::time::timeout(std::time::Duration::from_secs(2), client.finish())
        .await
        .unwrap();
    let handle = lock!(pool)
        .slots
        .iter()
        .flatten()
        .next()
        .unwrap()
        ._owner
        .handle();
    handle.send(b"independent authenticated record").unwrap();
    let record = tokio::time::timeout(std::time::Duration::from_secs(2), client.handle().recv())
        .await
        .unwrap()
        .unwrap();
    // Let only the blocked ACK expire. Its failed binding must release its
    // lease without retiring the independent authenticated sibling.
    tokio::time::pause();
    tokio::time::advance(BIND_TIMEOUT + std::time::Duration::from_secs(1)).await;
    for _ in 0..128 {
        tokio::task::yield_now().await;
    }
    let after_failure = (
        fixture.offer.diagnostics.active_connections(),
        lock!(pool).slots.iter().flatten().count(),
    );
    let sibling_still_active = !handle.is_closed();
    tokio::time::resume();
    // Do not send records after advancing only Tokio's clock: record expiry
    // intentionally uses monotonic std time, so that would test clock skew in
    // the fixture rather than whether the other binding remained registered.
    fixture.stop(&mut task).await;
    lock!(pool).slots.fill_with(|| None);
    assert_eq!(record, b"independent authenticated record");
    assert_eq!(after_failure, (1, 1));
    assert!(sibling_still_active);
    assert_eq!(fixture.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.offer.diagnostics.active_connections(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn incoming_binding_flights_keep_the_transport_budget_and_cancel_on_retirement() {
    let mut fixture = Fixture::new().await;
    let mut clients = Vec::new();
    for i in 0..StreamParallelHandle::CONNECTIONS_PER_DIRECTION {
        let (outcome, client) = fixture.child(true, 10 + i as u8).await;
        assert!(matches!(outcome, ParallelPeekOutcome::Bound));
        clients.push(client);
    }
    let (excess, _client) = fixture.child(true, 50).await;
    assert!(
        matches!(excess, ParallelPeekOutcome::Drop(ref reason) if reason == "parallel connection budget exhausted")
    );
    let budget = StreamParallelHandle::CONNECTIONS_PER_DIRECTION;
    assert_eq!(fixture.offer.diagnostics.active_connections(), budget);
    let pool = Arc::new(Mutex::new(Pool::default()));
    let mut task = fixture.start(pool.clone());
    tokio::time::pause();
    let at = tokio::time::Instant::now();
    for _ in 0..128 {
        tokio::task::yield_now().await;
    }
    let started = fixture.entered.load(Ordering::SeqCst);
    let no_timer = tokio::time::Instant::now() == at;
    tokio::time::resume();
    fixture.stop(&mut task).await;
    assert_eq!(
        started, budget,
        "one blocked ACK parked other admitted proofs"
    );
    assert!(no_timer);
    assert!(lock!(pool).incoming.is_empty());
    assert!(lock!(pool).slots.iter().all(Option::is_none));
    assert_eq!(fixture.offer.diagnostics.active_connections(), 0);
    // Includes the refused ninth stream, which never obtained a lease.
    assert_eq!(fixture.dropped.load(Ordering::SeqCst), budget + 1);
    drop(clients);
}
