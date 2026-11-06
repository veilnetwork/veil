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

use super::{KernelSnapshot, NEXT_CONNECTION, SocketMetadata, enabled_cell};

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
}

impl Observation {
    fn log(&self, socket: &TcpStream, outcome: &'static str) {
        // A capture disabled during the handshake must stop emitting too.
        if !enabled_cell().load(Ordering::Relaxed) {
            return;
        }
        log::info!(target: "transport.tcp_trace.handshake",
            "tcp_handshake connection={} monotonic_us={} side={:?} outcome={} phase={:?} elapsed_ms={} written_bytes={} read_bytes={} socket={:?} kernel={:?} attempt={:?} candidate={:?}",
            self.connection,
            veil_util::diagnostic_clock::monotonic_us().map_or_else(|| "unknown".to_owned(), |us| us.to_string()),
            self.side, outcome, self.phase, self.started.elapsed().as_millis(),
            self.written_bytes, self.read_bytes,
            SocketMetadata::read(socket), KernelSnapshot::read(socket), self.attempt, self.candidate);
    }
}

/// The wrapper is only an I/O observer; authentication, framing and deadlines
/// remain owned by obfs4 and its transport caller. After upgrade it delegates
/// without collecting application I/O. Neither socket options nor results change.
pub(crate) struct HandshakeStream {
    socket: TcpStream,
    observation: Option<Observation>,
}

impl HandshakeStream {
    pub(crate) fn new(socket: TcpStream, side: HandshakeSide) -> Self {
        Self::with_observation(socket, side, enabled_cell().load(Ordering::Relaxed))
    }

    fn with_observation(socket: TcpStream, side: HandshakeSide, enabled: bool) -> Self {
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
        });
        let stream = Self {
            socket,
            observation,
        };
        if let Some(o) = &stream.observation {
            o.log(&stream.socket, "start");
        }
        stream
    }

    pub(crate) fn socket(&self) -> &TcpStream {
        &self.socket
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, server) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        (
            HandshakeStream::with_observation(client.unwrap(), HandshakeSide::Client, enabled),
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
    }

    struct Recorder(std::sync::Mutex<Vec<String>>);
    impl log::Log for Recorder {
        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
            metadata.target() == "transport.tcp_trace.handshake"
        }
        fn log(&self, record: &log::Record<'_>) {
            if self.enabled(record.metadata()) {
                let mut rows = self.0.lock().unwrap();
                if rows.len() < 256 {
                    rows.push(record.args().to_string());
                }
            }
        }
        fn flush(&self) {}
    }
    static RECORDER: Recorder = Recorder(std::sync::Mutex::new(Vec::new()));
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
        let (io, mut remote) = pair(true).await;
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
            .0
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
    }
}
