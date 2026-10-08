use super::*;
use veil_transport::{
    Transport, TransportContext, TransportListener, TransportUri, quic::QuicTransport,
};

struct Fixture {
    listener: Arc<dyn TransportListener>,
    context: Arc<TransportContext>,
    uri: TransportUri,
    registry: Arc<ParallelRegistry>,
    initiator: ParallelParent,
    responder: ParallelParent,
    offer: ParallelQuicOffer,
    incoming: mpsc::Receiver<BoundChild>,
    _registration: Registration,
    main_handles: [QuicDatagramHandle; 2],
    main_streams: [BoxIoStream; 2],
}

impl Fixture {
    async fn new() -> Self {
        let context = Arc::new(TransportContext::for_debug().unwrap());
        let bind: TransportUri = "quic://127.0.0.1:0".parse().unwrap();
        let listener: Arc<dyn TransportListener> = Arc::from(
            QuicTransport
                .bind(&bind, Arc::clone(&context))
                .await
                .unwrap(),
        );
        let uri: TransportUri = format!("quic://{}", listener.local_addr()).parse().unwrap();
        let accepted = {
            let listener = Arc::clone(&listener);
            tokio::spawn(async move { listener.accept().await })
        };
        let a = QuicTransport
            .connect(&uri, Arc::clone(&context))
            .await
            .unwrap();
        let a_handle = a.quic_datagrams().unwrap();
        let mut a_stream = a.into_stream().unwrap();
        a_stream.write_all(b"main").await.unwrap();
        let b = accepted.await.unwrap().unwrap();
        let b_handle = b.quic_datagrams().unwrap();
        let offer = ParallelQuicOffer::new(b.parallel_quic().unwrap());
        assert!(!offer.handle.has_exclusive_accept());
        assert!(
            offer.handle.accept().await.is_err(),
            "parent must not steal listener accepts"
        );
        let mut b_stream = b.into_stream().unwrap();
        let mut prelude = [0; 4];
        b_stream.read_exact(&mut prelude).await.unwrap();
        let initiator = ParallelParent::new([1; 32], [2; 32], [3; 32]);
        let responder = ParallelParent::new([1; 32], [3; 32], [2; 32]);
        let registry = Arc::new(ParallelRegistry::default());
        let (tx, incoming) = mpsc::channel(8);
        let registration = registry
            .register([1; 32], responder.handle(), &offer, tx)
            .unwrap();
        Self {
            listener,
            context,
            uri,
            registry,
            initiator,
            responder,
            offer,
            incoming,
            _registration: registration,
            main_handles: [a_handle, b_handle],
            main_streams: [a_stream, b_stream],
        }
    }

    fn start_accept(
        &self,
    ) -> tokio::task::JoinHandle<veil_transport::Result<Box<dyn veil_transport::TransportConnection>>>
    {
        let listener = Arc::clone(&self.listener);
        tokio::spawn(async move { listener.accept().await })
    }

    async fn dispatch(
        &self,
        captured: Option<[u8; HELLO_BYTES]>,
    ) -> (
        ParallelPeekOutcome,
        QuicDatagramHandle,
        BoxIoStream,
        [u8; HELLO_BYTES],
    ) {
        // Independent client endpoints intentionally avoid the sender's slot
        // cap: the shared receiver must enforce its own aggregate budget.
        let accepted = self.start_accept();
        let connection = QuicTransport
            .connect(&self.uri, Arc::clone(&self.context))
            .await
            .unwrap();
        let handle = connection.quic_datagrams().unwrap();
        let hello = captured.unwrap_or_else(|| {
            self.initiator
                .begin(handle.channel_binding().unwrap())
                .unwrap()
                .0
        });
        let mut stream = connection.into_stream().unwrap();
        stream.write_all(&hello).await.unwrap();
        let inbound = accepted.await.unwrap().unwrap();
        let datagrams = inbound.quic_datagrams();
        let outcome = self
            .registry
            .peek_and_dispatch(inbound.into_stream().unwrap(), datagrams)
            .await;
        (outcome, handle, stream, hello)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for handle in &self.main_handles {
            handle.close();
        }
    }
}

impl Fixture {
    async fn dispatch_reliable(
        &self,
    ) -> (
        ParallelPeekOutcome,
        QuicDatagramHandle,
        BoxIoStream,
        crate::parallel_binding::PendingParallelBinding,
    ) {
        let accepted = self.start_accept();
        let connection = QuicTransport
            .connect(&self.uri, self.context.clone())
            .await
            .unwrap();
        let handle = connection.quic_datagrams().unwrap();
        let (hello, pending) = self
            .initiator
            .begin_reliable(handle.channel_binding().unwrap())
            .unwrap();
        let mut stream = connection.into_stream().unwrap();
        stream.write_all(&hello).await.unwrap();
        let inbound = accepted.await.unwrap().unwrap();
        let raw = inbound.quic_datagrams();
        let outcome = self
            .registry
            .peek_and_dispatch(inbound.into_stream().unwrap(), raw)
            .await;
        (outcome, handle, stream, pending)
    }
}

#[tokio::test]
async fn reliable_quic_dispatch_requires_opt_in_retains_accounting_and_closes_real_child() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut f = Fixture::new().await;
        let (outcome, raw, _stream, _) = f.dispatch_reliable().await;
        assert!(matches!(outcome, ParallelPeekOutcome::Drop(ref e) if e == "parallel reliable support not negotiated"));
        raw.closed().await;
        let (tx, mut rx) = mpsc::channel(1);
        assert!(f._registration.enable_reliable(tx));
        let (outcome, raw, mut stream, pending) = f.dispatch_reliable().await;
        assert!(matches!(outcome, ParallelPeekOutcome::Bound));
        assert!(f.incoming.try_recv().is_err());
        let bound = rx.recv().await.unwrap();
        let (server, ack) = tokio::join!(bound.finish(), async {
            let mut ack = [0; 32];
            stream.read_exact(&mut ack).await.unwrap();
            ack
        });
        let server = server.unwrap();
        let client = pending.finish(&ack).unwrap().into_reliable_quic(stream, raw.clone()).unwrap();
        assert_eq!(f.offer.diagnostics.active_connections(), 1);
        client.handle().send(b"opaque reliable").await.unwrap();
        assert_eq!(server.handle().recv().await.unwrap(), b"opaque reliable");
        server.handle().send(b"return").await.unwrap();
        assert_eq!(client.handle().recv().await.unwrap(), b"return");
        drop(server);
        raw.closed().await;
        assert_eq!(f.offer.diagnostics.active_connections(), 0);
        // This is the real canonical transport, kept separate from the child.
        f.main_streams[0].write_all(b"alive").await.unwrap();
        let mut bytes = [0; 5];
        f.main_streams[1].read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"alive");
    }).await.unwrap();
}

#[tokio::test]
async fn reliable_quic_queue_failure_closes_child_with_retained_raw_clones() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let f = Fixture::new().await;
        let (tx, mut rx) = mpsc::channel(1);
        assert!(f._registration.enable_reliable(tx));
        let (outcome, first, _stream, _) = f.dispatch_reliable().await;
        assert!(matches!(outcome, ParallelPeekOutcome::Bound));
        let (outcome, full, _stream, _) = f.dispatch_reliable().await;
        assert!(matches!(outcome, ParallelPeekOutcome::Drop(ref e) if e == "parallel reliable owner unavailable"));
        full.closed().await;
        assert_eq!(f.offer.diagnostics.active_connections(), 1);
        let child = rx.recv().await.unwrap();
        f.responder.retire();
        assert!(child.finish().await.is_err());
        first.closed().await;
        assert_eq!(f.offer.diagnostics.active_connections(), 0);
        assert!(f.main_handles.iter().all(|h| h.max_size().is_some()));
    }).await.unwrap();
}

#[tokio::test]
async fn shared_registry_authenticates_once_and_rejects_cross_connection_replay_and_retirement() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let mut f = Fixture::new().await;
        let (result, child, mut stream, hello) = f.dispatch(None).await;
        assert!(matches!(result, ParallelPeekOutcome::Bound));
        let mut bound = f.incoming.recv().await.unwrap();
        assert!(bound.parent.is_active());
        bound.channel.stream.write_all(&bound.ack).await.unwrap();
        let mut ack = [0; 32];
        stream.read_exact(&mut ack).await.unwrap();
        // Replaying the exact proof on another TLS connection must not enter
        // the canonical runner's queue or receive any acknowledgement.
        let (result, replay, _stream, _) = f.dispatch(Some(hello)).await;
        assert!(matches!(result, ParallelPeekOutcome::Drop(_)));
        replay.closed().await;
        assert!(f.incoming.try_recv().is_err());
        assert_eq!(f.offer.diagnostics.active_connections(), 1);
        drop(bound);
        child.closed().await;
        assert_eq!(f.offer.diagnostics.active_connections(), 0);
        f.responder.retire();
        let (result, retired, _stream, _) = f.dispatch(None).await;
        assert!(matches!(result, ParallelPeekOutcome::Drop(_)));
        retired.closed().await;
        // Rejections close only children; ordinary canonical bytes still work.
        f.main_streams[0].write_all(b"alive").await.unwrap();
        let mut bytes = [0; 5];
        f.main_streams[1].read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"alive");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn shared_registry_bounds_incoming_preserves_outgoing_capacity_and_ordinary_accepts() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        let mut f = Fixture::new().await;
        let mut children = Vec::new();
        for _ in 0..veil_transport::QuicParallelHandle::CONNECTIONS_PER_DIRECTION {
            let (outcome, handle, stream, _) = f.dispatch(None).await;
            assert!(matches!(outcome, ParallelPeekOutcome::Bound));
            children.push((handle, stream));
        }
        assert_eq!(
            f.offer.diagnostics.active_connections(),
            veil_transport::QuicParallelHandle::CONNECTIONS_PER_DIRECTION
        );
        let (outcome, rejected, _stream, _) = f.dispatch(None).await;
        assert!(matches!(outcome, ParallelPeekOutcome::Drop(_)));
        rejected.closed().await;
        assert_eq!(
            f.offer.handle.available_connection_slots(),
            veil_transport::QuicParallelHandle::CONNECTIONS_PER_DIRECTION,
            "unclassified incoming children consumed local outgoing capacity"
        );
        // Child saturation must not consume or authenticate an unrelated
        // canonical connection, nor take the shared accept loop away from it.
        let accepted = f.start_accept();
        let connection = QuicTransport
            .connect(&f.uri, Arc::clone(&f.context))
            .await
            .unwrap();
        let handle = connection.quic_datagrams().unwrap();
        let mut stream = connection.into_stream().unwrap();
        stream.write_all(b"ordinary OVL1 input").await.unwrap();
        let inbound = accepted.await.unwrap().unwrap();
        let datagrams = inbound.quic_datagrams();
        let ParallelPeekOutcome::Handshake(mut ordinary) = f
            .registry
            .peek_and_dispatch(inbound.into_stream().unwrap(), datagrams)
            .await
        else {
            panic!("ordinary peer was intercepted")
        };
        let mut bytes = [0; 19];
        ordinary.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ordinary OVL1 input");
        handle.close();
        // Cancelling the owning receiver drops all queued children; the map's
        // stale sender cannot acknowledge or resurrect the retired task.
        f.incoming.close();
        while let Some(child) = f.incoming.recv().await {
            drop(child);
        }
        for (handle, _) in &children {
            handle.closed().await;
        }
        assert_eq!(f.offer.diagnostics.active_connections(), 0);
        let (outcome, closed, _stream, _) = f.dispatch(None).await;
        assert!(matches!(outcome, ParallelPeekOutcome::Drop(_)));
        closed.closed().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn shared_registry_cancellation_closes_an_unclassified_child_with_live_handle_clones() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let f = Fixture::new().await;
        for bytes in [
            b"VP".as_slice(),
            crate::parallel_binding::PREFACE.as_slice(),
        ] {
            let accepted = f.start_accept();
            let connection = QuicTransport
                .connect(&f.uri, Arc::clone(&f.context))
                .await
                .unwrap();
            let handle = connection.quic_datagrams().unwrap();
            let mut stream = connection.into_stream().unwrap();
            stream.write_all(bytes).await.unwrap();
            let inbound = accepted.await.unwrap().unwrap();
            let held_clone = inbound.quic_datagrams().unwrap();
            let pending = f
                .registry
                .peek_and_dispatch(inbound.into_stream().unwrap(), Some(held_clone.clone()));
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(20), pending)
                    .await
                    .is_err()
            );
            // The clone deliberately survives cancellation. Dropping just the
            // wrapper/stream is insufficient to close the actual connection.
            handle.closed().await;
            held_clone.closed().await;
        }
        assert_eq!(f.offer.diagnostics.active_connections(), 0);
        assert!(
            f.main_handles
                .iter()
                .all(|handle| handle.max_size().is_some())
        );
    })
    .await
    .unwrap();
}
