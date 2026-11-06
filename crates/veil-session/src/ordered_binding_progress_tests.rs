//! A blocked proof-ACK write must not park the entire ordered-child pool.
//! The parent uses a real obfs4 offer/connection budget. Deterministic child
//! pipes carry the actual exporter-bound proofs through ParallelRegistry.
use super::*;
use crate::parallel_binding::{HELLO_BYTES, PendingParallelBinding};
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
