//! Opt-in TCP observations while obfs4 still owns the raw socket. The normal
//! writer trace starts after upgrade and cannot describe a lost first flight.
//! No socket is cloned: cancellation samples before dropping its one owner.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::{ConnectTraceContext, KernelSnapshot, NEXT_CONNECTION, SocketMetadata, enabled_cell};

#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
pub(crate) struct InitialAckDeadline {
    baseline: u64,
    timer: Pin<Box<tokio::time::Sleep>>,
}

#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
impl InitialAckDeadline {
    pub(crate) fn new(baseline: u64, timeout: std::time::Duration) -> Self {
        Self {
            baseline,
            timer: Box::pin(tokio::time::sleep(timeout)),
        }
    }

    pub(crate) fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        std::future::Future::poll(self.timer.as_mut(), cx).is_ready()
    }

    pub(crate) fn no_ack_progress(&self, acknowledged: Option<u64>) -> bool {
        acknowledged == Some(self.baseline)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum HandshakeSide {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Connected,
    Write,
    Flush,
    Read,
    Shutdown,
}

struct Observation {
    connection: u64,
    side: HandshakeSide,
    started: Instant,
    active: AtomicBool,
    phase: Phase,
    written_bytes: u64,
    read_bytes: u64,
    attempt: Option<u64>,
    candidate: Option<&'static str>,
    connect_context: Option<u64>,
    tcp_connect_started_us: Option<u64>,
}

impl Observation {
    fn log(&self, socket: &TcpStream, outcome: &'static str) {
        // A capture disabled during the handshake must stop emitting too.
        if !enabled_cell().load(Ordering::Relaxed) {
            return;
        }
        log::info!(target: "transport.tcp_trace.handshake",
            "tcp_handshake connection={} monotonic_us={} side={:?} outcome={} phase={:?} elapsed_ms={} written_bytes={} read_bytes={} socket={:?} kernel={:?} attempt={:?} candidate={:?} connect_context={:?} tcp_connect_started_us={:?}",
            self.connection,
            veil_util::diagnostic_clock::monotonic_us().map_or_else(|| "unknown".to_owned(), |us| us.to_string()),
            self.side, outcome, self.phase, self.started.elapsed().as_millis(),
            self.written_bytes, self.read_bytes,
            SocketMetadata::read(socket), KernelSnapshot::read(socket), self.attempt, self.candidate, self.connect_context, self.tcp_connect_started_us);
    }
}

/// Observes handshake I/O and applies the caller's optional initial ACK
/// deadline. After upgrade it delegates without collecting application I/O.
pub(crate) struct HandshakeStream {
    socket: TcpStream,
    observation: Option<Observation>,
    #[cfg(any(target_os = "android", all(test, target_os = "linux")))]
    initial_ack: Option<InitialAckDeadline>,
    #[cfg(all(test, any(target_os = "android", target_os = "linux")))]
    test_ack_bytes: Option<u64>,
}

impl HandshakeStream {
    pub(crate) fn new(socket: TcpStream, side: HandshakeSide) -> Self {
        Self::new_in_context(socket, side, None)
    }

    pub(crate) fn new_in_context(
        socket: TcpStream,
        side: HandshakeSide,
        context: Option<ConnectTraceContext>,
    ) -> Self {
        Self::with_observation(
            socket,
            side,
            enabled_cell().load(Ordering::Relaxed),
            context,
            None,
        )
    }

    /// Sample before polling each physical TCP connect, not at the logical
    /// parent dial: auxiliary and delayed backup sockets begin independently.
    pub(crate) fn connect_start_clock() -> Option<u64> {
        super::is_enabled()
            .then(veil_util::diagnostic_clock::monotonic_us)
            .flatten()
    }

    pub(crate) fn new_client_after_connect(
        socket: TcpStream,
        context: Option<ConnectTraceContext>,
        tcp_connect_started_us: Option<u64>,
    ) -> Self {
        Self::with_observation(
            socket,
            HandshakeSide::Client,
            enabled_cell().load(Ordering::Relaxed),
            context,
            tcp_connect_started_us,
        )
    }

    fn with_observation(
        socket: TcpStream,
        side: HandshakeSide,
        enabled: bool,
        context: Option<ConnectTraceContext>,
        tcp_connect_started_us: Option<u64>,
    ) -> Self {
        let observation = enabled.then(|| Observation {
            connection: NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed),
            side,
            started: Instant::now(),
            active: AtomicBool::new(true),
            phase: Phase::Connected,
            written_bytes: 0,
            read_bytes: 0,
            attempt: None,
            candidate: None,
            connect_context: context.map(ConnectTraceContext::local_id),
            tcp_connect_started_us,
        });
        let stream = Self {
            socket,
            observation,
            #[cfg(any(target_os = "android", all(test, target_os = "linux")))]
            initial_ack: None,
            #[cfg(all(test, any(target_os = "android", target_os = "linux")))]
            test_ack_bytes: None,
        };
        if let Some(o) = &stream.observation {
            o.log(&stream.socket, "start");
        }
        stream
    }

    pub(crate) fn socket(&self) -> &TcpStream {
        &self.socket
    }

    #[cfg(any(target_os = "android", all(test, target_os = "linux")))]
    pub(crate) fn with_initial_ack_deadline(mut self, timeout: std::time::Duration) -> Self {
        self.initial_ack = self
            .initial_ack_bytes()
            .map(|baseline| InitialAckDeadline::new(baseline, timeout));
        self
    }

    #[cfg(any(target_os = "android", all(test, target_os = "linux")))]
    pub(crate) fn initial_ack_bytes(&self) -> Option<u64> {
        #[cfg(test)]
        if let Some(bytes) = self.test_ack_bytes {
            return Some(bytes);
        }
        super::linux_progress::acknowledged_bytes(&self.socket)
    }

    /// Freeze the kernel observation while using real handshake I/O and clocks.
    #[cfg(all(test, any(target_os = "android", target_os = "linux")))]
    pub(crate) fn with_test_ack_bytes(mut self, bytes: u64) -> Self {
        self.test_ack_bytes = Some(bytes);
        self
    }

    pub(crate) fn connection_id(&self) -> Option<u64> {
        self.observation.as_ref().map(|o| o.connection)
    }

    /// Same opt-in scope as the socket observations. A local attempt number
    /// groups its primary/backup sockets; it is never sent to a peer.
    pub(crate) fn for_attempt(mut self, attempt: Option<u64>, candidate: &'static str) -> Self {
        if let Some(o) = &mut self.observation {
            o.attempt = attempt;
            o.candidate = Some(candidate);
            o.log(&self.socket, "linked");
        }
        self
    }

    pub(crate) fn selected(&self) {
        if let Some(o) = &self.observation {
            o.log(&self.socket, "selected");
        }
    }

    pub(crate) fn complete(&self) {
        if let Some(o) = &self.observation
            && o.active.swap(false, Ordering::Relaxed)
        {
            o.log(&self.socket, "complete");
        }
    }

    fn active(&mut self) -> Option<&mut Observation> {
        self.observation
            .as_mut()
            .filter(|o| o.active.load(Ordering::Relaxed))
    }
}

impl Drop for HandshakeStream {
    fn drop(&mut self) {
        if let Some(o) = &self.observation
            && o.active.load(Ordering::Relaxed)
        {
            // Error, timeout and caller cancellation all arrive here while the
            // descriptor is still live. The outer result determines which;
            // elapsed time alone must not be labelled network latency.
            o.log(&self.socket, "incomplete");
        }
    }
}

impl AsyncRead for HandshakeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        if let Some(o) = self.active() {
            o.phase = Phase::Read;
        }
        let result = Pin::new(&mut self.socket).poll_read(cx, buf);
        if let Some(o) = self.active() {
            o.read_bytes = o
                .read_bytes
                .saturating_add((buf.filled().len() - before) as u64);
        }
        // The client only reads after writing its opening flight. Give a
        // socket with any ACK progress (or a reply) the regular handshake
        // budget. TCP_USER_TIMEOUT alone can be observed late, on the next
        // retransmission, even when the initial bytes have never been ACKed.
        #[cfg(any(target_os = "android", all(test, target_os = "linux")))]
        if let Some(deadline) = &mut self.initial_ack
            && (!result.is_pending()
                || std::future::Future::poll(deadline.timer.as_mut(), cx).is_ready())
        {
            let baseline = deadline.baseline;
            self.initial_ack = None;
            if result.is_pending() && self.initial_ack_bytes() == Some(baseline) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no TCP acknowledgement for the obfs4 opening",
                )));
            }
        }
        result
    }
}

impl AsyncWrite for HandshakeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(o) = self.active() {
            o.phase = Phase::Write;
        }
        let result = Pin::new(&mut self.socket).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = result
            && let Some(o) = self.active()
        {
            o.written_bytes = o.written_bytes.saturating_add(n as u64);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(o) = self.active() {
            o.phase = Phase::Flush;
        }
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(o) = self.active() {
            o.phase = Phase::Shutdown;
        }
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair(enabled: bool) -> (HandshakeStream, TcpStream) {
        pair_in_context(enabled, None).await
    }

    async fn pair_in_context(
        enabled: bool,
        context: Option<ConnectTraceContext>,
    ) -> (HandshakeStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, server) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        (
            HandshakeStream::with_observation(
                client.unwrap(),
                HandshakeSide::Client,
                enabled,
                context,
                None,
            ),
            server.unwrap().0,
        )
    }

    #[tokio::test]
    async fn observes_handshake_but_stops_before_application_bytes() {
        let (mut io, mut remote) = pair(true).await;
        io.socket().set_nodelay(true).unwrap();
        io.write_all(b"opaque flight").await.unwrap();
        io.flush().await.unwrap();
        let mut bytes = [0; 13];
        remote.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"opaque flight");
        remote.write_all(b"reply").await.unwrap();
        let mut reply = [0; 5];
        io.read_exact(&mut reply).await.unwrap();
        let o = io.observation.as_ref().unwrap();
        assert_eq!(
            (o.written_bytes, o.read_bytes, o.phase),
            (13, 5, Phase::Read)
        );
        assert!(io.socket().nodelay().unwrap());
        io.complete();
        io.complete();
        io.write_all(b"application").await.unwrap();
        let mut application = [0; 11];
        remote.read_exact(&mut application).await.unwrap();
        assert_eq!(&application, b"application");
        remote.write_all(b"later").await.unwrap();
        io.read_exact(&mut reply).await.unwrap();
        let o = io.observation.as_ref().unwrap();
        assert!(!o.active.load(Ordering::Relaxed));
        assert_eq!((o.written_bytes, o.read_bytes), (13, 5));
    }

    #[tokio::test]
    async fn pending_read_keeps_first_flight_counters_and_cancel_closes_socket() {
        let (mut io, mut remote) = pair(true).await;
        io.write_all(b"first").await.unwrap();
        let mut received = [0; 5];
        remote.read_exact(&mut received).await.unwrap();
        let mut byte = [0; 1];
        std::future::poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut byte);
            assert!(Pin::new(&mut io).poll_read(cx, &mut buf).is_pending());
            Poll::Ready(())
        })
        .await;
        let o = io.observation.as_ref().unwrap();
        assert_eq!(
            (o.written_bytes, o.read_bytes, o.phase),
            (5, 0, Phase::Read)
        );
        drop(io);
        assert_eq!(remote.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn disabled_observer_keeps_no_handshake_state_and_preserves_io() {
        let (io, mut remote) = pair(false).await;
        assert!(io.connection_id().is_none());
        let mut io = io.for_attempt(Some(123), "backup");
        assert!(io.observation.is_none());
        remote.write_all(b"wire").await.unwrap();
        let mut bytes = [0; 4];
        io.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"wire");
        io.write_all(&bytes).await.unwrap();
        remote.read_exact(&mut bytes).await.unwrap();
        io.complete();
        io.selected();
        assert!(io.observation.is_none());
        io.shutdown().await.unwrap();
        assert_eq!(remote.read(&mut bytes).await.unwrap(), 0);
        let context = ConnectTraceContext::allocate_if(true).unwrap();
        let (io, _) = pair_in_context(false, Some(context)).await;
        assert!(
            io.observation.is_none(),
            "a context must not enable the observer"
        );
    }

    struct Recorder {
        rows: std::sync::Mutex<Vec<String>>,
        contexts: std::sync::Mutex<Vec<u64>>,
    }
    impl log::Log for Recorder {
        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
            metadata.target() == "transport.tcp_trace.handshake"
        }
        fn log(&self, record: &log::Record<'_>) {
            if self.enabled(record.metadata()) {
                let row = record.args().to_string();
                if !self
                    .contexts
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|id| row.contains(&format!("connect_context=Some({id})")))
                {
                    return;
                }
                let mut rows = self.rows.lock().unwrap();
                if rows.len() < 256 {
                    rows.push(row);
                }
            }
        }
        fn flush(&self) {}
    }
    static RECORDER: Recorder = Recorder {
        rows: std::sync::Mutex::new(Vec::new()),
        contexts: std::sync::Mutex::new(Vec::new()),
    };
    static LOGGER: std::sync::Once = std::sync::Once::new();

    #[tokio::test]
    async fn cancellation_logs_live_kernel_snapshot_without_payload_or_addresses() {
        LOGGER.call_once(|| log::set_logger(&RECORDER).unwrap());
        struct Restore(bool, log::LevelFilter);
        impl Drop for Restore {
            fn drop(&mut self) {
                enabled_cell().store(self.0, Ordering::Relaxed);
                log::set_max_level(self.1);
            }
        }
        let _restore = Restore(
            enabled_cell().swap(true, Ordering::Relaxed),
            log::max_level(),
        );
        log::set_max_level(log::LevelFilter::Info);
        let context = ConnectTraceContext::new_if_enabled().unwrap();
        RECORDER.contexts.lock().unwrap().push(context.local_id());
        let (io, mut remote) = pair_in_context(true, Some(context)).await;
        let connection = io.observation.as_ref().unwrap().connection;
        let mut io = io.for_attempt(Some(connection), "backup");
        let payload = b"private-handshake-canary";
        io.write_all(payload).await.unwrap();
        io.flush().await.unwrap();
        let mut received = vec![0; payload.len()];
        remote.read_exact(&mut received).await.unwrap();
        let mut byte = [0; 1];
        std::future::poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut byte);
            assert!(Pin::new(&mut io).poll_read(cx, &mut buf).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(io);
        assert_eq!(remote.read(&mut byte).await.unwrap(), 0);
        let key = format!("tcp_handshake connection={connection} ");
        let rows: Vec<_> = RECORDER
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| row.starts_with(&key))
            .cloned()
            .collect();
        assert_eq!(rows.len(), 3, "start, linked and incomplete observation");
        assert!(rows[0].contains("outcome=start"));
        assert!(rows[1].contains("outcome=linked"));
        let end = &rows[2];
        assert!(end.contains(&format!(
            "attempt=Some({connection}) candidate=Some(\"backup\")"
        )));
        assert!(end.contains("outcome=incomplete phase=Read"));
        assert!(
            rows.iter()
                .all(|row| row.contains(&format!("connect_context=Some({})", context.local_id(),)))
        );
        assert!(end.contains(&format!("written_bytes={} read_bytes=0", payload.len())));
        assert!(end.contains("socket=Ok(SocketMetadata { local_port:"));
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios"
        ))]
        assert!(
            end.contains("kernel=Ok(KernelSnapshot"),
            "socket must still be live when sampled"
        );
        for row in rows {
            // Android may discard the log target: the message stays identifiable.
            assert!(row.starts_with("tcp_handshake "));
            assert!(!row.contains("private-handshake-canary"));
            assert!(!row.contains("127.0.0.1"));
        }
        real_obfs_primary_backup_and_child_keep_the_same_context().await;

        let (io, _) = pair_in_context(true, Some(context)).await;
        let before = RECORDER.rows.lock().unwrap().len();
        enabled_cell().store(false, Ordering::Relaxed);
        assert!(ConnectTraceContext::new_if_enabled().is_none());
        assert!(HandshakeStream::connect_start_clock().is_none());
        drop(io);
        assert_eq!(
            RECORDER.rows.lock().unwrap().len(),
            before,
            "disabling capture must silence a retained context"
        );
    }

    async fn real_obfs_primary_backup_and_child_keep_the_same_context() {
        use crate::{Transport, TransportContext, TransportUri, obfs4_tcp::Obfs4TcpTransport};
        use std::{collections::HashSet, sync::Arc, time::Duration};
        let context = ConnectTraceContext::new_if_enabled().unwrap();
        RECORDER.contexts.lock().unwrap().push(context.local_id());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let uri = TransportUri::parse(&format!("obfs4-tcp://{}", listener.local_addr().unwrap()))
            .unwrap();
        let mut settings = TransportContext::for_debug().unwrap();
        settings.obfs4_psk = Some(Arc::new([0x42; 32]));
        settings.tracing.set_tcp_connect_context(Some(context));
        let fixture_not_before = veil_util::diagnostic_clock::monotonic_us().unwrap();
        let child_not_before = tokio::time::timeout(Duration::from_secs(12), async {
            let server = async {
                let (mut stalled, _) = listener.accept().await.unwrap();
                let mut byte = [0];
                stalled.read_exact(&mut byte).await.unwrap();
                let (backup, _) = listener.accept().await.unwrap();
                let server =
                    veil_obfs4::obfs4_server_accept(backup, &veil_obfs4::NodeIdMacKey([0x42; 32]))
                        .await
                        .unwrap();
                (server, stalled)
            };
            let (client, (mut server, _stalled)) =
                tokio::join!(Obfs4TcpTransport.connect(&uri, Arc::new(settings)), server,);
            let client = client.unwrap();
            let auxiliary = client.parallel_stream().unwrap();
            let mut client = client.into_stream().unwrap();
            client.write_all(b"opaque primary control").await.unwrap();
            client.flush().await.unwrap();
            let mut bytes = [0; 22];
            server.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"opaque primary control");
            // Transport primitive only: actual parent proof/admission is covered
            // by runtime integration tests. The child must retain the context
            // through its factory's cloned TransportContext.
            let child_server = async {
                let (tcp, _) = listener.accept().await.unwrap();
                veil_obfs4::obfs4_server_accept(tcp, &veil_obfs4::NodeIdMacKey([0x42; 32]))
                    .await
                    .unwrap()
            };
            let child_not_before = veil_util::diagnostic_clock::monotonic_us().unwrap();
            let (child, mut child_server) = tokio::join!(auxiliary.connect(), child_server);
            let mut child = child.unwrap().into_stream().unwrap();
            child.write_all(b"opaque child control").await.unwrap();
            child.flush().await.unwrap();
            let mut bytes = [0; 20];
            child_server.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"opaque child control");
            child_not_before
        })
        .await
        .expect("transport context fixture watchdog");
        let key = format!("connect_context=Some({})", context.local_id());
        let rows: Vec<_> = RECORDER
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| row.contains(&key))
            .cloned()
            .collect();
        let connections: HashSet<_> = rows
            .iter()
            .map(|row| {
                row.split("connection=")
                    .nth(1)
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .unwrap()
            })
            .collect();
        assert_eq!(
            connections.len(),
            3,
            "silent primary, selected backup and independent child"
        );
        assert!(
            rows.iter().any(|row| row.contains("outcome=selected")
                && row.contains("candidate=Some(\"backup\")"))
        );
        assert!(
            rows.iter().any(|row| row.contains("outcome=selected")
                && row.contains("candidate=Some(\"primary\")"))
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.contains("outcome=start"))
                .count(),
            3
        );
        let mut socket_clocks: Vec<(u64, u64)> = rows
            .iter()
            .filter(|row| row.contains("outcome=start"))
            .map(|row| {
                let observed = row
                    .split("monotonic_us=")
                    .nth(1)
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap();
                let before_connect = row
                    .split("tcp_connect_started_us=Some(")
                    .nth(1)
                    .expect("a physical socket needs its own pre-connect clock")
                    .split(')')
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap();
                (observed, before_connect)
            })
            .collect();
        socket_clocks.sort_unstable();
        assert_eq!(socket_clocks.len(), 3);
        assert!(
            socket_clocks
                .iter()
                .all(|&(observed, before)| fixture_not_before <= before && before <= observed)
        );
        assert!(
            socket_clocks[1].1 > socket_clocks[0].0,
            "backup clock belongs to the delayed physical connect"
        );
        assert!(
            socket_clocks[2].1 >= child_not_before,
            "child must not inherit the parent's physical connect clock"
        );
        assert!(
            rows.iter()
                .all(|row| !row.contains("127.0.0.1") && !row.contains("opaque "))
        );
    }
}
