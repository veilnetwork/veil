//! Local, opt-in diagnostics for TCP writer progress and kernel backlog.
//!
//! No peer addresses, application roles, payloads, wire flags or priorities.
//! A process-local connection number correlates events. Kernel snapshots are
//! sampled at the first Pending and on a slow completion/re-poll; elapsed
//! time includes task scheduling and must not be called network latency.
//! Successful flushes also sample cumulative kernel high-water marks; accepting
//! bytes without Pending does not prove that they have reached the peer.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

static ENABLED: OnceLock<AtomicBool> = OnceLock::new();
static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);
const SLOW: Duration = Duration::from_millis(50);
const LOG_INTERVAL: Duration = Duration::from_secs(1);

fn enabled_cell() -> &'static AtomicBool {
    ENABLED.get_or_init(|| {
        AtomicBool::new(std::env::var("VEIL_RT_TRACE").is_ok_and(|v| v.trim() == "1"))
    })
}

/// Embedded-node twin of the VEIL_RT_TRACE environment gate.
pub fn set_enabled(on: bool) {
    enabled_cell().store(on, Ordering::Relaxed);
}

// The snapshots are consumed through field-labelled Debug output.
#[allow(dead_code)]
#[derive(Debug)]
struct KernelSnapshot {
    rtt_us: u64,
    rto_us: u64,
    cwnd_bytes: u64,
    send_mss_bytes: u32,
    send_buffer_bytes: usize,
    queued_bytes: Option<u32>,
    notsent_bytes: Option<u32>,
    unacked_packets: Option<u32>,
    retransmitted_packets: Option<u32>,
    retransmitted_bytes: Option<u64>,
}

// Debug is deliberately field-labelled: Linux retransmissions are packets,
// Darwin reports bytes, and unsupported fields must remain None, not zero.
impl KernelSnapshot {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    fn read(stream: &TcpStream) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let send_buffer_bytes = socket2::SockRef::from(stream).send_buffer_size()?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // Stable Linux UAPI prefix and optional extension through
            // tcpi_notsent_bytes (offset 144). Android libc does not expose
            // tcp_info; decode native-endian u32s from the returned length
            // instead of reading an uninitialised or version-dependent struct.
            let mut raw = [0u8; 256];
            let mut len = raw.len() as libc::socklen_t;
            // SAFETY: live borrowed socket, writable buffer and size; neither
            // descriptor nor pointer escapes this synchronous call.
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_INFO,
                    raw.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if len < 104 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            let u32_at = |offset| u32::from_ne_bytes(raw[offset..offset + 4].try_into().unwrap());
            let mut queued = 0i32;
            // SAFETY: live socket and writable int matching SIOCOUTQ's ABI.
            let rc = unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut queued) };
            Ok(Self {
                rtt_us: u32_at(68) as u64,
                rto_us: u32_at(8) as u64,
                cwnd_bytes: u32_at(80) as u64 * u32_at(16) as u64,
                send_mss_bytes: u32_at(16),
                send_buffer_bytes,
                queued_bytes: (rc == 0 && queued >= 0).then_some(queued as u32),
                notsent_bytes: (len >= 148).then(|| u32_at(144)),
                unacked_packets: Some(u32_at(24)),
                retransmitted_packets: Some(u32_at(100)),
                retransmitted_bytes: None,
            })
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            // Darwin's TCP_CONNECTION_INFO has packed TFO bitfields before
            // the u64 counters. libc 0.2's struct expands those bitfields,
            // shifting the counters, so use the native SDK's stable byte ABI.
            // Read only fields present in the kernel's returned length.
            let mut raw = [0u8; 256];
            let mut len = raw.len() as libc::socklen_t;
            // SAFETY: live borrowed socket, writable buffer and length. No
            // descriptor or pointer escapes this synchronous getsockopt.
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_CONNECTION_INFO,
                    raw.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if len < 48 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            let u32_at = |offset| u32::from_ne_bytes(raw[offset..offset + 4].try_into().unwrap());
            Ok(Self {
                rtt_us: u32_at(44) as u64 * 1000,
                rto_us: u32_at(12) as u64 * 1000,
                cwnd_bytes: u32_at(24) as u64,
                send_mss_bytes: u32_at(16),
                send_buffer_bytes,
                queued_bytes: Some(u32_at(32)),
                notsent_bytes: None,
                unacked_packets: None,
                retransmitted_packets: None,
                retransmitted_bytes: (len >= 80)
                    .then(|| u64::from_ne_bytes(raw[72..80].try_into().unwrap())),
            })
        }
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    fn read(_: &TcpStream) -> std::io::Result<Self> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

struct Wait {
    start: Instant,
    last_poll: Instant,
    max_poll_gap: Duration,
    polls: u64,
    operation: &'static str,
    ciphertext_bytes: usize,
    kernel: std::io::Result<KernelSnapshot>,
}

/// Successful writes can enter a kernel backlog without ever returning
/// Pending. This diagnostic is role-neutral and changes no socket option.
#[derive(Default)]
struct KernelProgress {
    last_sample: Option<Instant>,
    last_log: Option<Instant>,
    samples: u64,
    rtt_max_us: u64,
    queued_max_bytes: Option<u32>,
    notsent_max_bytes: Option<u32>,
    retransmitted_max_bytes: Option<u64>,
}

#[derive(Default)]
pub(crate) struct WriteTrace {
    connection: u64,
    progress: KernelProgress,
    wait: Option<Wait>,
    last_log: Option<Instant>,
}

impl WriteTrace {
    /// Called after polling the real writer, never changes its result.
    pub(crate) fn observe(
        &mut self,
        stream: &TcpStream,
        operation: &'static str,
        pending: bool,
        ciphertext_bytes: usize,
    ) {
        if !enabled_cell().load(Ordering::Relaxed) {
            self.wait = None;
            if self.progress.samples != 0 {
                self.progress = KernelProgress::default();
            }
            return;
        }
        let now = Instant::now();
        if operation == "flush" {
            self.observe_kernel_progress(stream, now);
        }
        self.observe_enabled(stream, operation, pending, ciphertext_bytes, now);
    }

    fn observe_kernel_progress(&mut self, stream: &TcpStream, now: Instant) {
        // Sample even quick successful flushes, but at most 200 times/second
        // per connection. All reads are opt-in; no I/O or option is changed.
        if self
            .progress
            .last_sample
            .is_some_and(|last| now.saturating_duration_since(last) < Duration::from_millis(5))
        {
            return;
        }
        self.progress.last_sample = Some(now);
        if self.connection == 0 {
            self.connection = NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed);
        }
        let snapshot = KernelSnapshot::read(stream);
        if let Ok(kernel) = &snapshot {
            let p = &mut self.progress;
            p.samples = p.samples.saturating_add(1);
            p.rtt_max_us = p.rtt_max_us.max(kernel.rtt_us);
            if let Some(value) = kernel.queued_bytes {
                p.queued_max_bytes = Some(p.queued_max_bytes.map_or(value, |old| old.max(value)));
            }
            if let Some(value) = kernel.notsent_bytes {
                p.notsent_max_bytes = Some(p.notsent_max_bytes.map_or(value, |old| old.max(value)));
            }
            if let Some(value) = kernel.retransmitted_bytes {
                p.retransmitted_max_bytes = Some(
                    p.retransmitted_max_bytes
                        .map_or(value, |old| old.max(value)),
                );
            }
        }
        if self
            .progress
            .last_log
            .is_none_or(|last| now.saturating_duration_since(last) >= LOG_INTERVAL)
        {
            log::info!(target: "transport.tcp_trace.kernel_progress",
                "connection={} monotonic_us={} samples={} rtt_max_us={} queued_max_bytes={:?} notsent_max_bytes={:?} retransmitted_max_bytes={:?} kernel_now={:?}",
                self.connection,
                veil_util::diagnostic_clock::monotonic_us().map_or_else(|| "unknown".to_owned(), |us| us.to_string()),
                self.progress.samples, self.progress.rtt_max_us,
                self.progress.queued_max_bytes, self.progress.notsent_max_bytes,
                self.progress.retransmitted_max_bytes, snapshot);
            self.progress.last_log = Some(now);
        }
    }

    fn observe_enabled(
        &mut self,
        stream: &TcpStream,
        operation: &'static str,
        pending: bool,
        ciphertext_bytes: usize,
        now: Instant,
    ) {
        if let Some(wait) = &mut self.wait {
            wait.max_poll_gap = wait.max_poll_gap.max(now.duration_since(wait.last_poll));
            wait.last_poll = now;
            wait.polls += 1;
            let elapsed = now.duration_since(wait.start);
            if elapsed >= SLOW
                && self
                    .last_log
                    .is_none_or(|t| now.duration_since(t) >= LOG_INTERVAL)
            {
                log::info!(target: "transport.tcp_trace.write_wait",
                    "connection={} operation={} complete={} elapsed_ms={} polls={} max_poll_gap_ms={} ciphertext_start={} ciphertext_now={} kernel_start={:?} kernel_now={:?}",
                    self.connection, wait.operation, !pending, elapsed.as_millis(), wait.polls,
                    wait.max_poll_gap.as_millis(), wait.ciphertext_bytes, ciphertext_bytes,
                    wait.kernel, KernelSnapshot::read(stream));
                self.last_log = Some(now);
            }
            if !pending {
                self.wait = None;
            }
        } else if pending {
            if self.connection == 0 {
                self.connection = NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed);
            }
            self.wait = Some(Wait {
                start: now,
                last_poll: now,
                max_poll_gap: Duration::ZERO,
                polls: 1,
                operation,
                ciphertext_bytes,
                kernel: KernelSnapshot::read(stream),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn connected() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (a, b) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        (a.unwrap(), b.unwrap().0)
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    #[tokio::test]
    async fn snapshot_queries_live_socket_without_changing_io() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut a, mut b) = connected().await;
        let before = KernelSnapshot::read(&a).unwrap();
        assert!(before.send_buffer_bytes > 0);
        a.write_all(b"neutral transport control").await.unwrap();
        let mut bytes = [0u8; 25];
        b.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"neutral transport control");
        let after = KernelSnapshot::read(&a).unwrap();
        assert!(after.send_buffer_bytes > 0);
    }

    #[tokio::test]
    async fn pending_interval_survives_repoll_and_resets_at_completion() {
        let (a, _b) = connected().await;
        let mut trace = WriteTrace::default();
        let start = Instant::now();
        trace.observe_enabled(&a, "flush", true, 1200, start);
        trace.observe_enabled(&a, "flush", true, 600, start + Duration::from_millis(100));
        let wait = trace.wait.as_ref().unwrap();
        assert_eq!(wait.start, start);
        assert_eq!(wait.ciphertext_bytes, 1200);
        assert_eq!(wait.polls, 2);
        assert_eq!(wait.max_poll_gap, Duration::from_millis(100));
        trace.observe_enabled(&a, "flush", false, 0, start + Duration::from_millis(1400));
        assert!(trace.wait.is_none());
        let id = trace.connection;
        trace.observe_enabled(&a, "write", true, 800, start + Duration::from_millis(1401));
        assert_eq!(trace.connection, id);
        assert_eq!(trace.wait.as_ref().unwrap().ciphertext_bytes, 800);
    }
}

#[cfg(all(
    test,
    any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )
))]
mod kernel_progress_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn successful_write_snapshot_preserves_socket_options_and_wire_bytes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(TcpStream::connect(address), listener.accept());
        let mut client = client.unwrap();
        let (mut server, _) = server.unwrap();
        client.set_nodelay(true).unwrap();
        client.write_all(b"opaque record").await.unwrap();
        client.flush().await.unwrap();
        let mut trace = WriteTrace::default();
        trace.observe_kernel_progress(&client, Instant::now());
        assert_eq!(trace.progress.samples, 1);
        assert!(trace.progress.queued_max_bytes.is_some());
        assert!(client.nodelay().unwrap());
        let mut received = [0; 13];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"opaque record");
        assert!(
            trace.wait.is_none(),
            "successful writes are not writer stalls"
        );
    }
}
