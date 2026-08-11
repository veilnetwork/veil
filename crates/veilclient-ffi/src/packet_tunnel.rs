//! Process-safe packet-tunnel lifecycle around `tun2proxy`.
//!
//! The upstream crate also exposes a CLI-oriented C entry point whose shutdown
//! fallback calls `process::exit`. An embedded messenger must never use that
//! entry point. This module invokes `general_run_async` directly with an owned
//! cancellation token and exposes one process-wide VPN instance to Flutter.

use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::os::raw::{c_char, c_int, c_ushort, c_void};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tun2proxy::{ArgDns, ArgProxy, ArgVerbosity, Args, CancellationToken, ProxySelectorConfig};

#[cfg(target_os = "linux")]
mod linux_helper;

pub const VEIL_TUNNEL_STOPPED: c_int = 0;
pub const VEIL_TUNNEL_STARTING: c_int = 1;
pub const VEIL_TUNNEL_RUNNING: c_int = 2;
pub const VEIL_TUNNEL_ERROR: c_int = 3;

const STOP_TIMEOUT: Duration = Duration::from_secs(2);
const PACKET_QUEUE_CAPACITY: usize = 64;

/// Host callback for one raw IP packet emitted by the userspace stack.
///
/// `data` is borrowed only for the duration of the callback. The callback may
/// run on the tunnel's Rust worker thread and must copy/enqueue the packet
/// without blocking. `ctx` must remain valid until
/// [`veil_packet_tunnel_stop`] returns.
pub type PacketWriteFn = extern "C" fn(*mut c_void, *const u8, usize);

struct PacketTunnel {
    cancel: CancellationToken,
    phase: Arc<AtomicU8>,
    error: Arc<Mutex<Option<String>>>,
    packet_tx: Option<mpsc::Sender<Vec<u8>>>,
    mtu: u16,
    thread: Option<std::thread::JoinHandle<()>>,
    /// The host callback, for the callback-driven path. `None` for the
    /// fd-driven one, which hands the host nothing to keep alive.
    sink: Option<Arc<WriteSink>>,
}

/// The host's packet-write callback, and the only thing allowed to call it.
///
/// The opaque `ctx` is a raw pointer whose lifetime belongs to the host, and
/// the host stops guaranteeing it the moment `veil_packet_tunnel_stop`
/// returns. Stop cannot always establish that the worker is gone — it gives up
/// after `STOP_TIMEOUT` and returns `VEIL_ERR` with the thread still running —
/// so "the worker finished" is the wrong thing to build the contract on.
///
/// What stop CAN establish, in bounded time, is that nothing will call the
/// callback again. [`Self::retire`] does exactly that: it closes the door and
/// waits for whoever is already inside to leave. After it returns, `ctx` is
/// unreachable from this process whatever the worker is still doing, and the
/// host is free to deallocate.
///
/// That rendezvous is also why stop cannot run *inside* the callback. The read
/// lock a dispatch holds is exactly what `retire` waits for, so a host callback
/// that calls stop synchronously would be waiting for its own stack frame —
/// `std::sync::RwLock` tracks no reentrancy and would simply never return. The
/// same call would reach `thread.join()` first on the path where the worker has
/// already finished, and `Runtime::drop` there waits for the very tokio worker
/// thread the callback is running on. Neither edge is closed by releasing the
/// lock earlier; both are closed by refusing. [`IN_DISPATCH`] is how stop
/// recognises the case.
struct WriteSink {
    /// Identifies this sink to [`IN_DISPATCH`]. Never zero, so "no dispatch on
    /// this thread" and "dispatching some sink" cannot be confused.
    id: u64,
    /// Checked before the lock is taken. Without it a steady stream of
    /// packets could keep readers arriving while `retire` waits for the
    /// write lock, and the wait would not be bounded.
    retired: AtomicBool,
    slot: RwLock<Option<(PacketWriteFn, usize)>>,
}

thread_local! {
    /// Id of the sink this thread is currently dispatching, 0 for none.
    ///
    /// Read by [`veil_packet_tunnel_stop`] to detect a stop issued from inside
    /// the host's own packet callback, which it must refuse rather than serve:
    /// on this thread the callback is on the stack, so every wait stop would
    /// otherwise perform is a wait for this thread.
    static IN_DISPATCH: Cell<u64> = const { Cell::new(0) };
}

impl WriteSink {
    fn new(write_cb: PacketWriteFn, write_ctx: *mut c_void) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            retired: AtomicBool::new(false),
            // Raw pointers are not Send. Stored as an integer and turned back
            // into a pointer only at callback time, under the read lock.
            slot: RwLock::new(Some((write_cb, write_ctx as usize))),
        }
    }

    fn write(&self, data: &[u8]) {
        if self.retired.load(Ordering::Acquire) {
            return;
        }
        let guard = self
            .slot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((write_cb, write_ctx)) = guard.as_ref() {
            // Save and restore rather than set and clear: the marker describes
            // the innermost dispatch on this stack, and clearing it would tell
            // an outer dispatch's stop that it is safe to block.
            let previous = IN_DISPATCH.replace(self.id);
            write_cb(*write_ctx as *mut c_void, data.as_ptr(), data.len());
            IN_DISPATCH.set(previous);
        }
    }

    /// Forbid further calls, then wait for any already in flight to return.
    ///
    /// Taking the write lock IS the wait: it cannot be granted while a reader
    /// is inside the host callback.
    fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        *self
            .slot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

/// Packet-oriented host bridge presented as a byte stream to `ipstack`.
///
/// Network Extension owns packet boundaries, while `tun2proxy::run` consumes
/// an `AsyncRead + AsyncWrite`. Reads therefore concatenate queued packets and
/// retain any unread suffix when the caller supplies a smaller `ReadBuf`.
/// Writes are emitted immediately as one raw IP packet; `ipstack` issues one
/// write per packet on its TUN-facing side.
struct CallbackDevice {
    packet_rx: mpsc::Receiver<Vec<u8>>,
    pending: Option<Vec<u8>>,
    pending_offset: usize,
    sink: Arc<WriteSink>,
    mtu: usize,
}

impl CallbackDevice {
    fn new(packet_rx: mpsc::Receiver<Vec<u8>>, sink: Arc<WriteSink>, mtu: u16) -> Self {
        Self {
            packet_rx,
            pending: None,
            pending_offset: 0,
            sink,
            mtu: usize::from(mtu),
        }
    }
}

impl AsyncRead for CallbackDevice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if let Some(packet) = self.pending.as_ref() {
                let packet_len = packet.len();
                let copied = {
                    let available = &packet[self.pending_offset..];
                    let copied = available.len().min(buf.remaining());
                    buf.put_slice(&available[..copied]);
                    copied
                };
                self.pending_offset += copied;
                if self.pending_offset == packet_len {
                    self.pending = None;
                    self.pending_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.packet_rx).poll_recv(cx) {
                Poll::Ready(Some(packet)) => {
                    self.pending = Some(packet);
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for CallbackDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if buf.len() > self.mtu {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "userspace stack emitted packet larger than tunnel MTU",
            )));
        }
        self.sink.write(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn tunnel_slot() -> &'static Mutex<Option<PacketTunnel>> {
    static SLOT: OnceLock<Mutex<Option<PacketTunnel>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Serialises the tests that install into, or assert on, the process-wide
/// tunnel slot. Cargo runs a suite's tests on parallel threads and the slot is
/// one object; without this, a test that installs a tunnel makes a test that
/// asserts "no tunnel is running" fail for a reason that has nothing to do
/// with either of them.
#[cfg(test)]
static SLOT_SERIAL: Mutex<()> = Mutex::new(());

fn set_error(error: &Arc<Mutex<Option<String>>>, message: impl Into<String>) {
    *error
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(message.into());
}

fn phase_code(phase: u8) -> c_int {
    match phase {
        1 => VEIL_TUNNEL_STARTING,
        2 => VEIL_TUNNEL_RUNNING,
        3 => VEIL_TUNNEL_ERROR,
        _ => VEIL_TUNNEL_STOPPED,
    }
}

unsafe fn required_str<'a>(value: *const c_char, label: &str) -> Result<&'a str, String> {
    if value.is_null() {
        return Err(format!("{label} is null"));
    }
    // SAFETY: the caller contract requires a live NUL-terminated string for
    // the duration of this synchronous call.
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map_err(|_| format!("{label} is not UTF-8"))
}

fn cleanup_finished(slot: &mut Option<PacketTunnel>) {
    let finished = slot
        .as_ref()
        .and_then(|tunnel| tunnel.thread.as_ref())
        .is_some_and(std::thread::JoinHandle::is_finished);
    if finished
        && let Some(mut tunnel) = slot.take()
        && let Some(thread) = tunnel.thread.take()
    {
        let _ = thread.join();
    }
}

fn tunnel_args(proxy_url: &str, dns_ip: &str, mtu: u16, route_dns: bool) -> Result<Args, c_int> {
    if !(1280..=9000).contains(&mtu) {
        return Err(crate::VEIL_ERR_INVALID_ARG);
    }
    let proxy = match ArgProxy::try_from(proxy_url) {
        Ok(value) if value.addr.ip().is_loopback() => value,
        _ => return Err(crate::VEIL_ERR_INVALID_ARG),
    };
    let dns_addr = dns_ip
        .parse::<IpAddr>()
        .map_err(|_| crate::VEIL_ERR_INVALID_ARG)?;
    Ok(Args {
        proxy,
        // `OverTcp` sends DNS to `dns_addr` through the same authenticated
        // SOCKS5/veil path as application traffic. `Direct` is reserved for
        // the user's explicit DNS-bypass policy. Keeping this choice inside
        // the packet engine prevents platform route configuration from
        // claiming DNS privacy while the userspace stack leaks it directly.
        dns: if route_dns {
            ArgDns::OverTcp
        } else {
            ArgDns::Direct
        },
        dns_addr,
        ipv6_enabled: true,
        setup: false,
        mtu,
        verbosity: ArgVerbosity::Warn,
        ..Args::default()
    })
}

fn launch_tunnel<F>(
    packet_tx: Option<mpsc::Sender<Vec<u8>>>,
    sink: Option<Arc<WriteSink>>,
    mtu: u16,
    run: F,
) -> c_int
where
    F: FnOnce(tokio::runtime::Runtime, CancellationToken) -> std::io::Result<usize>
        + Send
        + 'static,
{
    let mut slot = tunnel_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cleanup_finished(&mut slot);
    if slot.is_some() {
        return crate::VEIL_ERR_REENTRANT;
    }

    let cancel = CancellationToken::new();
    let phase = Arc::new(AtomicU8::new(VEIL_TUNNEL_STARTING as u8));
    let error = Arc::new(Mutex::new(None));
    let worker_cancel = cancel.clone();
    let worker_phase = Arc::clone(&phase);
    let worker_error = Arc::clone(&error);

    let thread = match std::thread::Builder::new()
        .name("veil-packet-tunnel".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    set_error(&worker_error, format!("create tunnel runtime: {error}"));
                    worker_phase.store(VEIL_TUNNEL_ERROR as u8, Ordering::Release);
                    return;
                }
            };
            worker_phase.store(VEIL_TUNNEL_RUNNING as u8, Ordering::Release);
            let result = run(runtime, worker_cancel.clone());
            if worker_cancel.is_cancelled() {
                worker_phase.store(VEIL_TUNNEL_STOPPED as u8, Ordering::Release);
            } else if let Err(error) = result {
                set_error(&worker_error, format!("packet tunnel failed: {error}"));
                worker_phase.store(VEIL_TUNNEL_ERROR as u8, Ordering::Release);
            } else {
                worker_phase.store(VEIL_TUNNEL_STOPPED as u8, Ordering::Release);
            }
        }) {
        Ok(thread) => thread,
        Err(_) => return crate::VEIL_ERR,
    };

    *slot = Some(PacketTunnel {
        cancel,
        phase,
        error,
        packet_tx,
        mtu,
        thread: Some(thread),
        sink,
    });
    crate::VEIL_OK
}

/// Start a packet engine over an OS-owned TUN file descriptor.
///
/// The host remains responsible for creating/configuring the interface. The
/// engine duplicates the descriptor before starting its worker, so Android's
/// `ParcelFileDescriptor` and Rust never race over one descriptor lifetime.
/// `proxy_url` must be a loopback SOCKS5 URL; accepting a remote/plain proxy
/// here would bypass veil and make the VPN indicator misleading.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_packet_tunnel_start_fd(
    tun_fd: c_int,
    proxy_url: *const c_char,
    dns_ip: *const c_char,
    mtu: c_ushort,
    ipv6_enabled: bool,
    packet_information: bool,
    route_dns: bool,
) -> c_int {
    unsafe {
        start_fd_impl(
            tun_fd,
            proxy_url,
            dns_ip,
            mtu,
            ipv6_enabled,
            packet_information,
            route_dns,
            None,
        )
    }
}

/// Start a TUN engine whose SOCKS5 listener is selected per flow by an
/// authenticated loopback service (Android VpnService UID ownership lookup).
/// A selector failure rejects the new flow instead of leaking it through the
/// default exit.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_packet_tunnel_start_fd_routed(
    tun_fd: c_int,
    proxy_url: *const c_char,
    dns_ip: *const c_char,
    mtu: c_ushort,
    ipv6_enabled: bool,
    packet_information: bool,
    route_dns: bool,
    selector_addr: *const c_char,
    selector_token: *const c_char,
) -> c_int {
    let address = match unsafe { required_str(selector_addr, "selector_addr") }.and_then(|value| {
        value
            .parse::<SocketAddr>()
            .map_err(|_| "selector_addr is not a socket address".to_owned())
    }) {
        Ok(value) if value.ip().is_loopback() => value,
        _ => return crate::VEIL_ERR_INVALID_ARG,
    };
    let token = match unsafe { required_str(selector_token, "selector_token") } {
        Ok(value)
            if (32..=128).contains(&value.len())
                && value.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            value.to_owned()
        }
        _ => return crate::VEIL_ERR_INVALID_ARG,
    };
    unsafe {
        start_fd_impl(
            tun_fd,
            proxy_url,
            dns_ip,
            mtu,
            ipv6_enabled,
            packet_information,
            route_dns,
            Some(ProxySelectorConfig {
                addr: address,
                token,
            }),
        )
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn start_fd_impl(
    tun_fd: c_int,
    proxy_url: *const c_char,
    dns_ip: *const c_char,
    mtu: c_ushort,
    ipv6_enabled: bool,
    packet_information: bool,
    route_dns: bool,
    proxy_selector: Option<ProxySelectorConfig>,
) -> c_int {
    if tun_fd < 0 {
        return crate::VEIL_ERR_INVALID_ARG;
    }
    // SAFETY: validated and copied before this call returns.
    let proxy_url = match unsafe { required_str(proxy_url, "proxy_url") } {
        Ok(value) => value,
        Err(_) => return crate::VEIL_ERR_INVALID_ARG,
    };
    // SAFETY: validated and copied before this call returns.
    let dns_ip = match unsafe { required_str(dns_ip, "dns_ip") } {
        Ok(value) => value,
        Err(_) => return crate::VEIL_ERR_INVALID_ARG,
    };
    let mut args = match tunnel_args(proxy_url, dns_ip, mtu, route_dns) {
        Ok(args) => args,
        Err(code) => return code,
    };
    args.ipv6_enabled = ipv6_enabled;
    args.proxy_selector = proxy_selector;

    // Own a separate close-on-exec descriptor. In particular, Android keeps the
    // original in ParcelFileDescriptor; sharing that exact fd with the async
    // Rust worker lets service abort/restart invalidate an in-flight read.
    // Keeping an OwnedFd until the worker consumes it also closes the duplicate
    // if thread creation fails.
    // SAFETY: F_DUPFD_CLOEXEC does not dereference memory and accepts any fd.
    let duplicated_fd = unsafe { libc::fcntl(tun_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated_fd < 0 {
        return crate::VEIL_ERR_INVALID_ARG;
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned by this function.
    let duplicated_fd = unsafe { OwnedFd::from_raw_fd(duplicated_fd) };

    launch_tunnel(None, None, mtu, move |runtime, cancel| {
        args.tun_fd(Some(duplicated_fd.into_raw_fd()))
            .close_fd_on_drop(true);
        runtime.block_on(tun2proxy::general_run_async(
            args,
            mtu,
            packet_information,
            cancel,
        ))
    })
}

/// Start a packet engine over a host-owned packet callback.
///
/// This is the public Network Extension path for iOS/macOS: the provider feeds
/// each raw IP packet with [`veil_packet_tunnel_send_packet`], while `write_cb`
/// receives each raw IP packet that must be returned through
/// `NEPacketTunnelFlow.writePackets`. It deliberately avoids private access to
/// Network Extension's underlying socket/file descriptor.
///
/// The ingress queue is bounded to 64 packets. A full queue returns
/// `VEIL_ERR`; the provider should stop reading briefly and retry instead of
/// accumulating unbounded packet memory.
///
/// The callback context must remain live until [`veil_packet_tunnel_stop`]
/// returns, and that is a contract stop keeps on EVERY return path, including
/// the one where it gives up on the worker and answers `VEIL_ERR`: it retires
/// the callback and waits for any invocation already in flight before it
/// returns, so no call can reach the context afterwards. `write_cb` is
/// required and must not be null (a null C function pointer violates this FFI
/// contract).
///
/// `write_cb` must NOT call [`veil_packet_tunnel_stop`] on the callback's own
/// thread. The one invocation stop would have to wait for is the caller's, so
/// it cannot honour the promise above and refuses instead, answering
/// `VEIL_ERR_REENTRANT` after requesting cancellation. Hand the stop to
/// another thread — the Apple provider posts it to its packet queue — and the
/// full guarantee applies again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_packet_tunnel_start_packets(
    proxy_url: *const c_char,
    dns_ip: *const c_char,
    mtu: c_ushort,
    ipv6_enabled: bool,
    route_dns: bool,
    write_cb: PacketWriteFn,
    write_ctx: *mut c_void,
) -> c_int {
    // SAFETY: validated and copied before this call returns.
    let proxy_url = match unsafe { required_str(proxy_url, "proxy_url") } {
        Ok(value) => value,
        Err(_) => return crate::VEIL_ERR_INVALID_ARG,
    };
    // SAFETY: validated and copied before this call returns.
    let dns_ip = match unsafe { required_str(dns_ip, "dns_ip") } {
        Ok(value) => value,
        Err(_) => return crate::VEIL_ERR_INVALID_ARG,
    };
    let mut args = match tunnel_args(proxy_url, dns_ip, mtu, route_dns) {
        Ok(args) => args,
        Err(code) => return code,
    };
    args.ipv6_enabled = ipv6_enabled;

    let (packet_tx, packet_rx) = mpsc::channel(PACKET_QUEUE_CAPACITY);
    let sink = Arc::new(WriteSink::new(write_cb, write_ctx));
    let device = CallbackDevice::new(packet_rx, Arc::clone(&sink), mtu);
    launch_tunnel(Some(packet_tx), Some(sink), mtu, move |runtime, cancel| {
        let sessions = runtime.block_on(tun2proxy::run(device, mtu, args, cancel))?;
        Ok(sessions)
    })
}

/// Queue one raw IP packet read from the host packet-flow API.
///
/// Returns `VEIL_OK` when accepted, `VEIL_ERR` when the bounded queue is full,
/// `VEIL_ERR_CLOSED` when no callback-backed tunnel is running, or
/// `VEIL_ERR_INVALID_ARG` for null/empty/over-MTU input. The function copies
/// `data` before returning; the host may release its buffer immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_packet_tunnel_send_packet(data: *const u8, len: usize) -> c_int {
    if data.is_null() || len == 0 {
        return crate::VEIL_ERR_INVALID_ARG;
    }
    let mut slot = tunnel_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cleanup_finished(&mut slot);
    let Some(tunnel) = slot.as_ref() else {
        return crate::VEIL_ERR_CLOSED;
    };
    let Some(packet_tx) = tunnel.packet_tx.as_ref() else {
        return crate::VEIL_ERR_CLOSED;
    };
    if len > usize::from(tunnel.mtu) {
        return crate::VEIL_ERR_INVALID_ARG;
    }
    // SAFETY: pointer/length are caller-owned and promised live for this call;
    // the length was bounded by the validated tunnel MTU before allocation.
    let packet = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    match packet_tx.try_send(packet) {
        Ok(()) => crate::VEIL_OK,
        Err(mpsc::error::TrySendError::Full(_)) => crate::VEIL_ERR,
        Err(mpsc::error::TrySendError::Closed(_)) => crate::VEIL_ERR_CLOSED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn veil_packet_tunnel_status() -> c_int {
    let slot = tunnel_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    slot.as_ref()
        .map(|tunnel| phase_code(tunnel.phase.load(Ordering::Acquire)))
        .unwrap_or(VEIL_TUNNEL_STOPPED)
}

/// Stop the running tunnel, or `VEIL_OK` when none is running.
///
/// Returns `VEIL_ERR_REENTRANT` when called from inside the host's packet
/// callback. Cancellation is still requested in that case, so the host's
/// intent is not dropped; only the waiting is skipped, and the caller must not
/// read that code as "nothing happened".
#[unsafe(no_mangle)]
pub extern "C" fn veil_packet_tunnel_stop() -> c_int {
    // Before anything that can block, including `cleanup_finished`: it joins a
    // finished worker thread, and on the reentrant path that thread is inside
    // `Runtime::drop` waiting for the tokio worker this callback is running on.
    // Everything stop does afterwards — the join, and `retire` waiting for the
    // read lock this dispatch holds — is a wait for this very thread.
    {
        let slot = tunnel_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dispatching = IN_DISPATCH.get();
        let reentrant_cancel = match slot.as_ref() {
            Some(tunnel)
                if tunnel
                    .sink
                    .as_ref()
                    .is_some_and(|sink| sink.id == dispatching) =>
            {
                Some(tunnel.cancel.clone())
            }
            _ => None,
        };
        drop(slot);
        if let Some(cancel) = reentrant_cancel {
            // Cheap, non-blocking and idempotent. The host asked for a stop and
            // is about to be told "not from here"; the request itself still
            // stands, and the worker unwinds on its own thread.
            cancel.cancel();
            return crate::VEIL_ERR_REENTRANT;
        }
    }

    let (cancel, sink) = {
        let mut slot = tunnel_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cleanup_finished(&mut slot);
        let Some(tunnel) = slot.as_ref() else {
            return crate::VEIL_OK;
        };
        (tunnel.cancel.clone(), tunnel.sink.clone())
    };
    cancel.cancel();

    let deadline = Instant::now() + STOP_TIMEOUT;
    while Instant::now() < deadline {
        if matches!(
            veil_packet_tunnel_status(),
            VEIL_TUNNEL_STOPPED | VEIL_TUNNEL_ERROR
        ) {
            let mut slot = tunnel_slot()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(mut tunnel) = slot.take()
                && let Some(thread) = tunnel.thread.take()
            {
                let _ = thread.join();
            }
            // Redundant after a join, and kept anyway: the guarantee this
            // function makes must not depend on which way it returned.
            if let Some(sink) = sink {
                sink.retire();
            }
            return crate::VEIL_OK;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Timed out. The worker is still running, and this function cannot wait
    // for it — the host's own stop path has a deadline of its own, and on
    // Apple platforms it tears the provider down when that expires.
    //
    // Retiring the sink is what makes returning here safe. It used to return
    // VEIL_ERR with the worker still holding the host's context pointer, and
    // the host had already been told the context need only live "until stop
    // returns": a packet arriving a moment later called a callback on a freed
    // provider. Now the callback is unreachable before the return, so the
    // leak is a leaked thread and not a corrupted heap.
    if let Some(sink) = sink {
        sink.retire();
    }
    crate::VEIL_ERR
}

/// Latest engine error, allocated with `CString::into_raw`. Free with the
/// existing `veil_free_string` ABI. Returns null when no error is recorded.
#[unsafe(no_mangle)]
pub extern "C" fn veil_packet_tunnel_last_error() -> *mut c_char {
    let slot = tunnel_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(message) = slot
        .as_ref()
        .and_then(|tunnel| tunnel.error.lock().ok()?.clone())
    else {
        return std::ptr::null_mut();
    };
    CString::new(message)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Run xVeil's privileged Linux desktop packet-tunnel helper.
///
/// The normal GUI re-executes the *same xVeil executable* through `pkexec`
/// with a root-owned helper mode; no separately installed VPN binary or daemon
/// is required. `config_path` points to a bounded, owner-checked JSON request.
/// The helper writes one JSON status line to stdout, then remains alive until
/// stdin closes/receives `stop` or SIGINT/SIGTERM arrives. System routes,
/// nftables state, resolver settings, and the GUI's temporary cgroup are
/// restored before the function returns.
///
/// On non-Linux targets this always returns `VEIL_ERR_INVALID_ARG`.
///
/// # Safety
/// `config_path` must be a live NUL-terminated UTF-8 string for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_packet_tunnel_run_linux_helper(config_path: *const c_char) -> c_int {
    let config_path = match unsafe { required_str(config_path, "config_path") } {
        Ok(value) => value,
        Err(_) => return crate::VEIL_ERR_INVALID_ARG,
    };
    #[cfg(target_os = "linux")]
    {
        linux_helper::run(config_path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = config_path;
        crate::VEIL_ERR_INVALID_ARG
    }
}

#[cfg(test)]
mod write_sink_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    // Statics rather than captures: the host callback is an `extern "C" fn`
    // and cannot close over anything. One set per test, because the suite
    // runs its tests on parallel threads.
    static DELIVERED: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn count_calls(_ctx: *mut c_void, _data: *const u8, _len: usize) {
        DELIVERED.fetch_add(1, Ordering::SeqCst);
    }

    /// A retired sink is unreachable, which is the whole guarantee stop makes.
    ///
    /// `veil_packet_tunnel_stop` gives up on the worker after `STOP_TIMEOUT`
    /// and returns `VEIL_ERR` with the thread still running, while the host
    /// has been told the context need only outlive the call. Whether that is
    /// a leak or a use-after-free comes down to this: can a packet arriving
    /// after stop returned still reach the callback.
    #[test]
    fn a_retired_sink_never_calls_the_host() {
        let sink = WriteSink::new(count_calls, std::ptr::null_mut());
        sink.write(b"before");
        assert_eq!(
            DELIVERED.load(Ordering::SeqCst),
            1,
            "the sink delivered nothing even before retirement, so this test \
             would pass against a sink that never worked"
        );

        sink.retire();
        sink.write(b"after");
        assert_eq!(
            DELIVERED.load(Ordering::SeqCst),
            1,
            "a retired sink called the host — by then the provider may be freed"
        );
    }

    static ENTERED: AtomicBool = AtomicBool::new(false);
    static LEFT: AtomicBool = AtomicBool::new(false);

    extern "C" fn slow_callback(_ctx: *mut c_void, _data: *const u8, _len: usize) {
        ENTERED.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(200));
        LEFT.store(true, Ordering::SeqCst);
    }

    /// Retirement must also wait for the call already inside the host.
    ///
    /// Closing the door is not enough on its own: stop returns and the host
    /// deallocates, and a callback that was already running is holding that
    /// exact pointer. Setting the flag without waiting would satisfy the test
    /// above and still corrupt memory here.
    #[test]
    fn retire_waits_for_a_callback_already_in_flight() {
        let sink = Arc::new(WriteSink::new(slow_callback, std::ptr::null_mut()));
        let writer = Arc::clone(&sink);
        let handle = std::thread::spawn(move || writer.write(b"in flight"));

        while !ENTERED.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        sink.retire();
        assert!(
            LEFT.load(Ordering::SeqCst),
            "retire returned while the host callback was still running — the \
             host is free to release the context the moment stop returns"
        );
        handle.join().expect("writer thread panicked");
    }

    static MARKER_DURING_DISPATCH: AtomicU64 = AtomicU64::new(0);

    extern "C" fn record_dispatch_marker(_ctx: *mut c_void, _data: *const u8, _len: usize) {
        // Recorded, not asserted: unwinding out of an `extern "C" fn` aborts
        // the process, which would take the whole suite down with it.
        MARKER_DURING_DISPATCH.store(IN_DISPATCH.get(), Ordering::SeqCst);
    }

    /// A dispatch names itself on this thread, and only for its own duration.
    ///
    /// This is what lets stop tell "called from the host's callback" apart
    /// from "called from anywhere else", and it is structural: no sleeps, no
    /// second thread, nothing that can pass by being slow. The marker must be
    /// absent before the call — otherwise a stop issued from an ordinary
    /// thread would be refused for no reason — and absent again after it, or
    /// the refusal outlives the callback and stop stops working entirely.
    #[test]
    fn a_dispatch_marks_this_thread_only_while_it_runs() {
        let sink = WriteSink::new(record_dispatch_marker, std::ptr::null_mut());
        assert_ne!(sink.id, 0, "0 is the reserved 'no dispatch' marker value");
        assert_eq!(
            IN_DISPATCH.get(),
            0,
            "this thread claims to be dispatching before anything was dispatched"
        );

        sink.write(b"egress packet");

        assert_eq!(
            MARKER_DURING_DISPATCH.load(Ordering::SeqCst),
            sink.id,
            "the host callback ran without this sink's marker set, so a stop \
             called from inside it cannot be recognised as reentrant"
        );
        assert_eq!(
            IN_DISPATCH.get(),
            0,
            "the marker outlived the dispatch — every later stop on this \
             thread would be refused"
        );
    }

    extern "C" fn stop_from_inside_the_callback(ctx: *mut c_void, _data: *const u8, _len: usize) {
        let code = veil_packet_tunnel_stop();
        // SAFETY: the test leaks the sender on purpose, precisely because on
        // the failing path this callback is parked inside stop holding the
        // pointer while the test thread unwinds.
        let sender = unsafe { &*(ctx.cast::<std::sync::mpsc::Sender<c_int>>()) };
        let _ = sender.send(code);
    }

    /// Stop called from inside the host callback must answer, not hang.
    ///
    /// Two separate waits inside stop are waits for this exact thread: `retire`
    /// wants the write lock that this dispatch is holding as a reader, and the
    /// join reaches `Runtime::drop`, which waits for the tokio worker the
    /// callback is running on. `RwLock` has no reentrancy tracking, so the
    /// first is a permanent self-deadlock rather than an error.
    ///
    /// The Apple provider is one deleted `packetQueue.async` away from this:
    /// `failTunnel` already calls stop from the write path's own logic.
    #[test]
    fn stop_from_inside_the_callback_refuses_instead_of_deadlocking() {
        let _serial = SLOT_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let (sender, receiver) = std::sync::mpsc::channel::<c_int>();
        let sender = Box::into_raw(Box::new(sender));
        let sink = Arc::new(WriteSink::new(
            stop_from_inside_the_callback,
            sender.cast::<c_void>(),
        ));
        let cancel = CancellationToken::new();
        *tunnel_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(PacketTunnel {
            cancel: cancel.clone(),
            phase: Arc::new(AtomicU8::new(VEIL_TUNNEL_RUNNING as u8)),
            error: Arc::new(Mutex::new(None)),
            packet_tx: None,
            mtu: 1280,
            thread: None,
            sink: Some(Arc::clone(&sink)),
        });

        let writer = Arc::clone(&sink);
        std::thread::spawn(move || writer.write(b"egress packet"));

        // Bounded, and never joined: joining the writer is exactly the
        // unbounded wait this test exists to prove impossible.
        let outcome = receiver.recv_timeout(Duration::from_secs(10));
        // Put the singleton back before anything can unwind, so a failure here
        // does not cascade into every other test that reads it.
        *tunnel_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;

        let code = outcome.expect(
            "reentrant stop deadlocked: the host callback called \
             veil_packet_tunnel_stop and never got an answer",
        );
        assert_eq!(
            code,
            crate::VEIL_ERR_REENTRANT,
            "stop served a call it cannot honour from inside the callback"
        );
        assert!(
            cancel.is_cancelled(),
            "the refusal dropped the host's request: refusing to wait is not \
             the same as refusing to stop"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    extern "C" fn collect_packet(ctx: *mut c_void, data: *const u8, len: usize) {
        // SAFETY: tests pass a live `StdMutex<Vec<Vec<u8>>>` for the whole
        // callback invocation, and the device guarantees a live packet slice.
        let packets = unsafe { &*(ctx.cast::<StdMutex<Vec<Vec<u8>>>>()) };
        // SAFETY: callback contract guarantees a non-null pointer valid for
        // exactly `len` bytes during this call.
        let packet = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
        packets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(packet);
    }

    #[test]
    fn invalid_inputs_fail_before_creating_global_tunnel() {
        let _serial = SLOT_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let proxy = CString::new("socks5://127.0.0.1:1080").unwrap();
        let dns = CString::new("1.1.1.1").unwrap();
        // SAFETY: pointers remain valid for the duration of the call.
        let result = unsafe {
            veil_packet_tunnel_start_fd(-1, proxy.as_ptr(), dns.as_ptr(), 1280, true, false, true)
        };
        assert_eq!(result, crate::VEIL_ERR_INVALID_ARG);
        assert_eq!(veil_packet_tunnel_status(), VEIL_TUNNEL_STOPPED);
    }

    #[test]
    fn remote_proxy_is_rejected_so_vpn_cannot_bypass_veil() {
        let _serial = SLOT_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let proxy = CString::new("socks5://8.8.8.8:1080").unwrap();
        let dns = CString::new("1.1.1.1").unwrap();
        // fd is rejected too, but proxy validation happens first and both must
        // stay fail-closed without mutating the singleton.
        let result = unsafe {
            veil_packet_tunnel_start_fd(0, proxy.as_ptr(), dns.as_ptr(), 1280, true, false, true)
        };
        assert_eq!(result, crate::VEIL_ERR_INVALID_ARG);
        assert_eq!(veil_packet_tunnel_status(), VEIL_TUNNEL_STOPPED);
    }

    #[test]
    fn phase_codes_are_stable_for_platform_bridges() {
        assert_eq!(phase_code(0), VEIL_TUNNEL_STOPPED);
        assert_eq!(phase_code(1), VEIL_TUNNEL_STARTING);
        assert_eq!(phase_code(2), VEIL_TUNNEL_RUNNING);
        assert_eq!(phase_code(3), VEIL_TUNNEL_ERROR);
        assert_eq!(phase_code(u8::MAX), VEIL_TUNNEL_STOPPED);
    }

    #[test]
    fn dns_policy_selects_overlay_or_explicit_bypass() {
        let through_overlay = tunnel_args("socks5://127.0.0.1:1080", "1.1.1.1", 1280, true)
            .expect("valid routed-DNS tunnel args");
        assert_eq!(through_overlay.dns, ArgDns::OverTcp);

        let direct = tunnel_args("socks5://127.0.0.1:1080", "1.1.1.1", 1280, false)
            .expect("valid bypass-DNS tunnel args");
        assert_eq!(direct.dns, ArgDns::Direct);
    }

    #[test]
    fn callback_device_preserves_ingress_and_egress_packets() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (packet_tx, packet_rx) = mpsc::channel(2);
        let output = StdMutex::new(Vec::<Vec<u8>>::new());
        let output_ctx = (&output as *const StdMutex<Vec<Vec<u8>>>) as *mut c_void;
        let mut device = CallbackDevice::new(
            packet_rx,
            Arc::new(WriteSink::new(collect_packet, output_ctx)),
            1280,
        );

        packet_tx.try_send(vec![0x45, 1, 2, 3, 4]).unwrap();
        runtime.block_on(async {
            let mut prefix = [0_u8; 2];
            device.read_exact(&mut prefix).await.unwrap();
            assert_eq!(prefix, [0x45, 1]);
            let mut suffix = [0_u8; 3];
            device.read_exact(&mut suffix).await.unwrap();
            assert_eq!(suffix, [2, 3, 4]);

            device.write_all(&[0x60, 9, 8, 7]).await.unwrap();
        });
        assert_eq!(
            *output
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            vec![vec![0x60, 9, 8, 7]],
        );
    }

    #[test]
    fn callback_device_rejects_over_mtu_output() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (_packet_tx, packet_rx) = mpsc::channel(1);
        let output = StdMutex::new(Vec::<Vec<u8>>::new());
        let output_ctx = (&output as *const StdMutex<Vec<Vec<u8>>>) as *mut c_void;
        let mut device = CallbackDevice::new(
            packet_rx,
            Arc::new(WriteSink::new(collect_packet, output_ctx)),
            1280,
        );
        let error = runtime
            .block_on(device.write_all(&vec![0_u8; 1281]))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            output
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
        );
    }
}
