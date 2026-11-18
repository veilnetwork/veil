//! Actual outgoing worker, real obfs4/exporter binding and a gated TCP proxy.
//! The proxy holds complete first flights; this models pending handshake reads,
//! not unacknowledged packets on a mobile route.
use super::*;
use std::{net::SocketAddr, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use veil_transport::{Transport, TransportContext, TransportUri, obfs4_tcp::Obfs4TcpTransport};

#[derive(Clone)]
struct Stop(watch::Sender<bool>);
impl Stop {
    fn new() -> Self {
        Self(watch::channel(false).0)
    }
    fn cancel(&self) {
        self.0.send_replace(true);
    }
    async fn cancelled(&self) {
        let mut changes = self.0.subscribe();
        while !*changes.borrow_and_update() {
            if changes.changed().await.is_err() {
                return;
            }
        }
    }
}

struct HeldFlight {
    release: oneshot::Sender<()>,
    closed: oneshot::Receiver<()>,
}

struct Tasks {
    stop: Stop,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Tasks {
    fn new() -> Self {
        Self {
            stop: Stop::new(),
            tasks: Vec::new(),
        }
    }
    async fn finish(mut self) {
        self.stop.cancel();
        for task in self.tasks.drain(..) {
            task.await.unwrap();
        }
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        self.stop.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn gated_proxy(
    listener: TcpListener,
    upstream: SocketAddr,
    held: mpsc::UnboundedSender<HeldFlight>,
    stop: Stop,
) {
    let mut children = tokio::task::JoinSet::new();
    let mut canonical = true;
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            Some(result) = children.join_next(), if !children.is_empty() => { result.unwrap(); },
            accepted = listener.accept() => {
                let (mut client, _) = accepted.unwrap();
                let gate = !canonical;
                canonical = false;
                let held = held.clone();
                children.spawn(async move {
                    let mut first = [0];
                    if client.read_exact(&mut first).await.is_err() { return; }
                    let mut buffered = first.to_vec();
                    if gate {
                        let (release, mut permit) = oneshot::channel();
                        let (closed, eof) = oneshot::channel();
                        if held.send(HeldFlight { release, closed: eof }).is_err() { return; }
                        // Read only enough to observe cancellation while the
                        // flight is held. No bytes reach the upstream socket.
                        let mut bytes = [0; 4096];
                        loop {
                            tokio::select! {
                                result = &mut permit => {
                                    if result.is_err() { return; }
                                    break;
                                }
                                result = client.read(&mut bytes) => {
                                    match result {
                                        Ok(0) => { let _ = closed.send(()); return; }
                                        Ok(n) => {
                                            assert!(buffered.len() + n <= 4096);
                                            buffered.extend_from_slice(&bytes[..n]);
                                        }
                                        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                                            let _ = closed.send(());
                                            return;
                                        }
                                        Err(error) => panic!("held client read: {error}"),
                                    }
                                }
                            }
                        }
                    }
                    let mut server = TcpStream::connect(upstream).await.unwrap();
                    if server.write_all(&buffered).await.is_err() { return; }
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                });
            }
        }
    }
    children.abort_all();
    while children.join_next().await.is_some() {}
}

#[derive(Clone, Copy)]
enum Release {
    Backup,
    Retry,
}

async fn outgoing_scenario(release: Release) {
    let mut tasks = Tasks::new();
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
    let core: SocketAddr = listener.local_addr().parse().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let (held_tx, mut held_rx) = mpsc::unbounded_channel();
    tasks.tasks.push(tokio::spawn(gated_proxy(
        proxy,
        core,
        held_tx,
        tasks.stop.clone(),
    )));
    let uri = TransportUri::Obfs4Tcp {
        host: "127.0.0.1".into(),
        port: proxy_addr.port(),
    };
    let (client, server) =
        tokio::join!(Obfs4TcpTransport.connect(&uri, context), listener.accept());
    let (client, server) = (client.unwrap(), server.unwrap());
    let outgoing = client.parallel_stream().unwrap();
    let incoming = server.parallel_stream().unwrap();
    let canonical = [client.into_stream().unwrap(), server.into_stream().unwrap()];
    let peer_parent = ParallelParent::new([1; 32], [3; 32], [2; 32]);
    let registry = Arc::new(ParallelRegistry::default());
    let (proof_tx, mut proof_rx) = mpsc::channel(StreamParallelHandle::CONNECTIONS_PER_DIRECTION);
    let registration = registry
        .register_ordered(
            [1; 32],
            peer_parent.handle(),
            incoming,
            Arc::default(),
            proof_tx,
        )
        .unwrap();
    let stop = tasks.stop.clone();
    tasks.tasks.push(tokio::spawn(async move {
        let mut handshakes = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = stop.cancelled() => break,
                Some(result) = handshakes.join_next(), if !handshakes.is_empty() => { result.unwrap(); },
                raw = listener.accept_split() => {
                    let raw = raw.unwrap();
                    let registry = registry.clone();
                    handshakes.spawn(async move {
                        if let Ok(connection) = raw.finish.await {
                            let binding = connection.stream_channel_binding();
                            let io = connection.into_stream().unwrap();
                            assert!(matches!(registry.peek_and_dispatch_with_binding(io, None, binding).await,
                                ParallelPeekOutcome::Bound));
                        }
                    });
                }
            }
        }
        handshakes.abort_all();
        while handshakes.join_next().await.is_some() {}
    }));
    let status = Arc::new(LocalDatagramStatus::default());
    let offer = ParallelOrderedOffer::new(outgoing.clone(), Arc::default());
    let mut session = OrderedSession::new(
        offer,
        &[2; 32],
        &[3; 32],
        [1; 32],
        super::super::ordered_receiver_tests::pool_fixture_context(),
        Some(status.clone()),
    );
    assert!(session.registration.is_some());
    assert!(outgoing.can_connect());
    status.request_fresh(veil_proto::priority::REALTIME);
    let mut blocked = Vec::new();
    for _ in 0..TOTAL_SLOTS {
        blocked.push(held_rx.recv().await.unwrap());
    }
    assert_eq!(
        outgoing.available_connection_slots(),
        StreamParallelHandle::CONNECTIONS_PER_DIRECTION - TOTAL_SLOTS
    );
    assert_eq!(
        status.state(veil_proto::priority::REALTIME),
        crate::LocalDatagramChannelState::Warming
    );
    assert!(
        session
            .sender_with_carrier(
                veil_proto::priority::REALTIME,
                &[],
                RealtimeLaneFrameKind::DirectApp,
                None
            )
            .is_none()
    );

    // Without passing any primary flight, the next connection can only
    // be a delayed backup. Let a single authenticated connection through.
    let candidate = match release {
        Release::Backup => held_rx.recv().await.unwrap(),
        Release::Retry => {
            for _ in 0..TOTAL_SLOTS {
                blocked.push(held_rx.recv().await.unwrap());
            }
            // Hold every primary and backup until the actual pool cancels
            // them. Socket EOF is the witness, rather than elapsed time.
            for HeldFlight { release, closed } in blocked.drain(..) {
                closed
                    .await
                    .expect("expired attempt did not close its socket");
                assert!(release.is_closed());
            }
            assert_eq!(
                status.state(veil_proto::priority::REALTIME),
                crate::LocalDatagramChannelState::Warming,
            );
            assert!(matches!(
                proof_rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            held_rx.recv().await.unwrap()
        }
    };
    candidate.release.send(()).unwrap();
    let child = proof_rx
        .recv()
        .await
        .expect("backup proof was not verified");
    assert_eq!(
        status.state(veil_proto::priority::REALTIME),
        crate::LocalDatagramChannelState::Warming,
        "an accepted obfs4 transport is not ready before its proof ACK"
    );
    let remote = child.finish().await.unwrap();
    while status.state(veil_proto::priority::REALTIME) != crate::LocalDatagramChannelState::Ready {
        status.notified().await;
    }
    assert_eq!(lock!(session.pool).slots.iter().flatten().count(), 1);
    let frame = super::super::ordered_receiver_tests::app_frame(913, 32);
    let sender = session
        .sender_with_carrier(
            veil_proto::priority::REALTIME,
            &[],
            RealtimeLaneFrameKind::DirectApp,
            None,
        )
        .unwrap();
    let packets = lock!(sender).tx.encode_frame(1, &frame, 1200).unwrap();
    assert_eq!(packets.len(), 1);
    lock!(sender).handle.send(&packets[0]).unwrap();
    let received = remote.handle().recv().await.unwrap();
    let mut decoder = crate::datagram_flows::SessionDatagramRx::new(
        remote.keys().rx_key(),
        &remote.keys().session_id,
        true,
    );
    assert_eq!(
        decoder
            .decode_datagram(&received, std::time::Instant::now())
            .unwrap()
            .unwrap(),
        frame
    );

    session.parent.retire();
    (&mut session._worker.0).await.unwrap();
    drop(sender);
    drop(session);
    while outgoing.available_connection_slots() != StreamParallelHandle::CONNECTIONS_PER_DIRECTION {
        tokio::task::yield_now().await;
    }
    drop(remote);
    drop(registration);
    drop(peer_parent);
    drop(canonical);
    drop(blocked);
    tasks.finish().await;
    // Both actual listening sockets must have been dropped with their owners.
    for address in [core, proxy_addr] {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.bind(address).unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn actual_outgoing_pool_uses_a_verified_backup_while_other_first_flights_stall() {
    tokio::time::timeout(Duration::from_secs(12), outgoing_scenario(Release::Backup))
        .await
        .expect("outgoing pool fixture watchdog");
}

#[tokio::test(flavor = "current_thread")]
async fn actual_outgoing_pool_recovers_after_every_first_flight_expires() {
    tokio::time::timeout(Duration::from_secs(12), outgoing_scenario(Release::Retry))
        .await
        .expect("outgoing pool retry fixture watchdog");
}
