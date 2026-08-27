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
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
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

/// How long the worker waits for its own runtime to wind down before
/// abandoning what is left. Shorter than [`STOP_TIMEOUT`] on purpose: a stop
/// polls for the phase, and the phase is published before this wait begins, so
/// the caller is never held for the sum of the two.
const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_millis(500);
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

/// Runtime THREADS that did not come back, since this process started.
///
/// Zero is the expected value: blocking work that observes the cancellation
/// token finishes inside [`RUNTIME_SHUTDOWN_GRACE`]. A number that climbs
/// means something is parked in a syscall nothing here can interrupt, and
/// that is worth being able to read rather than infer from memory use.
///
/// Counted from the threads themselves — a thread that never returns never
/// runs its stop hook — and not from how long the shutdown took. The elapsed
/// time measures a timeout: a machine the scheduler paused for half a second
/// reported an abandonment that did not happen, and it could only ever say
/// "at least one" for a teardown that stranded several (report16 V16-M5).
static ABANDONED_WORKERS: AtomicUsize = AtomicUsize::new(0);

/// How many runtime THREADS did not come back, since this process started.
///
/// One per thread, not one per teardown: a thread that never returns never
/// runs its stop hook, and that is what this counts. See
/// [`ABANDONED_WORKERS`].
#[unsafe(no_mangle)]
pub extern "C" fn veil_packet_tunnel_abandoned_workers() -> u32 {
    u32::try_from(ABANDONED_WORKERS.load(Ordering::Acquire)).unwrap_or(u32::MAX)
}

fn launch_tunnel<F>(
    packet_tx: Option<mpsc::Sender<Vec<u8>>>,
    sink: Option<Arc<WriteSink>>,
    mtu: u16,
    run: F,
) -> c_int
where
    F: FnOnce(&tokio::runtime::Runtime, CancellationToken) -> std::io::Result<usize>
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
            // Every thread this runtime starts, counted in and counted out.
            //
            // What follows the shutdown used to be inferred from ELAPSED TIME:
            // if `shutdown_timeout` took as long as the grace, something was
            // assumed to have been abandoned. That measures a timeout, not a
            // thread — a machine paused by the scheduler for half a second
            // reports an abandonment that did not happen, and a thread
            // abandoned quickly reports none (report16 V16-M5). The threads
            // themselves say so: one that never returns never runs its stop
            // hook.
            let live_threads = Arc::new(AtomicUsize::new(0));
            let started = Arc::clone(&live_threads);
            let stopped = Arc::clone(&live_threads);
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .on_thread_start(move || {
                    started.fetch_add(1, Ordering::AcqRel);
                })
                .on_thread_stop(move || {
                    stopped.fetch_sub(1, Ordering::AcqRel);
                })
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
            let result = run(&runtime, worker_cancel.clone());
            // The phase is published BEFORE the runtime is taken down, and the
            // teardown is BOUNDED. Both halves matter, and both were missing.
            //
            // The runtime used to be moved into `run`, so `Runtime::drop` ran
            // inside it — and drop waits for every blocking task. tun2proxy
            // reads the TUN descriptor from one, and the engine owns a
            // duplicate of that descriptor, so closing the host's copy does
            // not wake it: the worker parked in drop forever, the phase never
            // reached STOPPED, `veil_packet_tunnel_stop` polled for
            // STOP_TIMEOUT and gave up with the slot still occupied, and every
            // later start answered VEIL_ERR_REENTRANT. Measured on a phone:
            // after stopping the VPN from the UI, it could not be started
            // again for the life of the process — only killing the app cured
            // it, three times over.
            if worker_cancel.is_cancelled() {
                worker_phase.store(VEIL_TUNNEL_STOPPED as u8, Ordering::Release);
            } else if let Err(error) = result {
                set_error(&worker_error, format!("packet tunnel failed: {error}"));
                worker_phase.store(VEIL_TUNNEL_ERROR as u8, Ordering::Release);
            } else {
                worker_phase.store(VEIL_TUNNEL_STOPPED as u8, Ordering::Release);
            }
            // Abandons a blocking task that will not finish rather than
            // waiting on it. What leaks is a thread; what it buys is a slot
            // that frees, so the next start is a start and not a refusal.
            //
            // The token is already cancelled by the time this runs, so
            // blocking work that LOOKS at it finishes inside the grace and
            // costs nothing. What cannot be woken is abandoned — and counted,
            // because the alternative is silent: repeated start/stop with a
            // wedged reader parks one more thread every cycle, and nothing
            // said so (report15 V15-M6, measured at four for four).
            //
            // Counted rather than prevented, deliberately. Preventing it means
            // waking the reader, and which task parks is not established: the
            // blocking read lives in a crate this tree does not own. A number
            // that grows is what lets that be diagnosed instead of inferred.
            runtime.shutdown_timeout(RUNTIME_SHUTDOWN_GRACE);
            // Counted from the threads, not from the clock. `shutdown_timeout`
            // returns once every thread it could join has joined, so whatever
            // this still counts is a thread that did not come back — one
            // increment per thread rather than one per teardown, which is what
            // makes a number that grows say how much is parked rather than how
            // many times something was slow.
            let left = live_threads.load(Ordering::Acquire);
            if left > 0 {
                ABANDONED_WORKERS.fetch_add(left, Ordering::Release);
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

    /// A blocking task that will not finish must not hold the tunnel slot.
    ///
    /// tun2proxy reads the TUN descriptor from a blocking task, and the engine
    /// owns a DUPLICATE of that descriptor — so closing the host's copy does
    /// not wake it. `Runtime::drop` waits for such a task forever. With the
    /// runtime dropped inside the worker closure, the worker parked there, the
    /// phase never reached STOPPED, stop gave up after STOP_TIMEOUT with the
    /// slot still occupied, and every later start answered REENTRANT.
    ///
    /// Measured on a phone before the fix: after stopping the VPN from the UI
    /// it could not be started again for the life of the process. Only killing
    /// the app cured it — three separate times.
    #[test]
    fn a_blocking_task_that_never_finishes_does_not_hold_the_slot() {
        let _serial = SLOT_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let parked = launch_tunnel(None, None, 1280, |runtime, cancel| {
            // Exactly the shape that wedged: a blocking task nothing can
            // interrupt, still parked when the cancelled loop returns.
            runtime.spawn_blocking(|| std::thread::sleep(Duration::from_secs(3600)));
            runtime.block_on(async move { cancel.cancelled().await });
            Ok(0)
        });
        assert_eq!(parked, crate::VEIL_OK, "the tunnel did not start");

        assert_eq!(
            veil_packet_tunnel_stop(),
            crate::VEIL_OK,
            "stop gave up on a worker whose only obstacle was a blocking task"
        );

        // The whole point: the NEXT start is a start, not a refusal.
        let again = launch_tunnel(None, None, 1280, |runtime, cancel| {
            runtime.block_on(async move { cancel.cancelled().await });
            Ok(0)
        });
        assert_eq!(
            again,
            crate::VEIL_OK,
            "the slot was still held, so the VPN could not be restarted"
        );
        assert_eq!(veil_packet_tunnel_stop(), crate::VEIL_OK);
    }

    /// report16 V16-M5: what the counter counts is THREADS, not timeouts.
    ///
    /// It used to compare the shutdown's elapsed time against the grace and
    /// add one if it ran over. That measures a timeout: a machine the
    /// scheduler paused for half a second reported an abandonment that did not
    /// happen, and a teardown that stranded three threads could only ever say
    /// one. The threads themselves say so — one that never returns never runs
    /// its stop hook.
    ///
    /// Two parked tasks, so the difference between "one per teardown" and
    /// "one per thread" is visible in the number.
    #[test]
    fn abandoned_workers_counts_threads_not_teardowns() {
        let _serial = SLOT_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let before = veil_packet_tunnel_abandoned_workers();

        let parked = launch_tunnel(None, None, 1280, |runtime, cancel| {
            // Neither can be woken, and both outlive the grace.
            runtime.spawn_blocking(|| std::thread::sleep(Duration::from_secs(3600)));
            runtime.spawn_blocking(|| std::thread::sleep(Duration::from_secs(3600)));
            runtime.block_on(async move { cancel.cancelled().await });
            Ok(0)
        });
        assert_eq!(parked, crate::VEIL_OK, "the tunnel did not start");
        assert_eq!(veil_packet_tunnel_stop(), crate::VEIL_OK);

        // `stop` joins the worker thread, which does the shutdown, so the
        // count is settled by the time stop returns.
        let added = veil_packet_tunnel_abandoned_workers() - before;
        assert!(
            added >= 2,
            "counted {added} for two threads that did not come back — the \
             number says how many teardowns were slow, not how much is parked"
        );
    }

    /// CONTROL: a teardown that strands nothing counts nothing.
    ///
    /// Without this the test above is satisfied by a counter that adds the
    /// thread count on every stop, which is worse than the elapsed-time proxy
    /// it replaced.
    #[test]
    fn a_clean_teardown_counts_nothing() {
        let _serial = SLOT_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let before = veil_packet_tunnel_abandoned_workers();

        let clean = launch_tunnel(None, None, 1280, |runtime, cancel| {
            runtime.block_on(async move { cancel.cancelled().await });
            Ok(0)
        });
        assert_eq!(clean, crate::VEIL_OK, "the tunnel did not start");
        assert_eq!(veil_packet_tunnel_stop(), crate::VEIL_OK);

        assert_eq!(
            veil_packet_tunnel_abandoned_workers(),
            before,
            "a teardown that stranded nothing was counted as an abandonment"
        );
    }

    /// report15 V15-M1: one flow's setup error is not the tunnel's, and a
    /// refused flow gives its session slot back.
    ///
    /// Structural, and in THIS crate rather than in the vendored engine: the
    /// accept loop needs a live tun device and an ip stack to run at all, and
    /// a guard living inside `third_party/tun2proxy` is one an upstream sync
    /// can carry away.
    ///
    /// Two shapes were wrong. `new_proxy_handler(…).await?` sits inside the
    /// accept loop, so a selector timeout or an unreachable proxy for ONE flow
    /// returned from `run` and stopped the tunnel for every application on the
    /// device. And the session count was incremented BEFORE the handler was
    /// built, so an error path that left in between kept the slot — an HTTP
    /// proxy profile refuses UDP by design, so the tunnel reached
    /// `max_sessions` and then dropped ALL new traffic, TCP included.
    ///
    /// The second one is why the slot is an OBJECT now. A first attempt at
    /// this test looked for a `fetch_sub` near each setup site and passed with
    /// the one on the failure side deleted, because it found the one belonging
    /// to the spawned task on the success side. Hand-written bookkeeping is
    /// hard to check for the same reason it was easy to get wrong; a permit
    /// that gives itself back on `Drop` cannot be forgotten on a branch, and
    /// the check becomes "is anybody still counting by hand".
    #[test]
    fn a_failed_flow_setup_neither_stops_the_tunnel_nor_leaks_a_slot() {
        let source = std::fs::read_to_string("../../third_party/tun2proxy/src/lib.rs")
            .expect("the vendored engine moved");
        let loop_start = source
            .find("let max_sessions = args.max_sessions;")
            .expect("the accept loop moved");
        let body = &source[loop_start..];

        assert!(
            !body.contains("new_proxy_handler(info, domain_name, false).await?")
                && !body.contains("new_proxy_handler(info, None, false).await?")
                && !body.contains("new_proxy_handler(tcpinfo, None, false).await?"),
            "a setup error here returns from `run` and stops the whole tunnel"
        );
        assert!(
            !body.contains("task_count.fetch_sub") && !body.contains("task_count.fetch_add"),
            "the session count is being kept by hand again; use SessionPermit, \
             which gives the slot back on every exit including the ones nobody \
             thought about"
        );
        assert!(
            source.contains("impl Drop for SessionPermit"),
            "the permit stopped giving the slot back"
        );

        // And every branch that admits a flow takes one.
        let takes = body.matches("SessionPermit::take(&task_count)").count();
        assert!(
            takes >= 2,
            "only {takes} branches take a permit; TCP and UDP both must"
        );
    }

    /// report15 V15-M6: the slot frees, and what it cost was a thread.
    ///
    /// `shutdown_timeout` abandons a blocking task rather than waiting on it,
    /// so before the token reached that task nothing woke it: four start/stop
    /// cycles left four workers parked, measured. Before the slot fix a wedge
    /// was self-limiting, because the VPN could never be started again.
    ///
    /// The contract now is that blocking work which LOOKS at the cancellation
    /// token finishes inside the grace and costs nothing at all.
    #[test]
    fn cancellable_blocking_work_does_not_pile_up_across_cycles() {
        let _serial = SLOT_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        use std::sync::atomic::AtomicUsize;
        static LIVE: AtomicUsize = AtomicUsize::new(0);
        LIVE.store(0, Ordering::SeqCst);
        let abandoned_before = veil_packet_tunnel_abandoned_workers();

        const CYCLES: usize = 4;
        for _ in 0..CYCLES {
            let started = launch_tunnel(None, None, 1280, |runtime, cancel| {
                let watching = cancel.clone();
                runtime.spawn_blocking(move || {
                    LIVE.fetch_add(1, Ordering::SeqCst);
                    // A blocking read that can be woken looks like this: it
                    // comes up for air and asks whether it is still wanted.
                    //
                    // Longer than a moment on purpose, so the task is still
                    // alive when the teardown starts and this measures a
                    // wake-up rather than a coincidence.
                    while !watching.is_cancelled() {
                        std::thread::sleep(Duration::from_millis(250));
                    }
                    LIVE.fetch_sub(1, Ordering::SeqCst);
                });
                runtime.block_on(async move { cancel.cancelled().await });
                Ok(0)
            });
            assert_eq!(started, crate::VEIL_OK, "a cycle failed to start");
            assert_eq!(veil_packet_tunnel_stop(), crate::VEIL_OK);
        }

        std::thread::sleep(Duration::from_millis(400));
        let live = LIVE.load(Ordering::SeqCst);
        assert_eq!(
            live, 0,
            "{live} workers still parked after {CYCLES} cycles - each is a \
             thread this process cannot get back"
        );
        // And none of them was recorded as abandoned, which is the other half
        // of the contract: work that can be woken costs nothing.
        //
        // Note what this does NOT pin: the value of the grace. Measured,
        // `shutdown_timeout` returns in tens of microseconds here whatever the
        // grace is, because it does not wait on blocking tasks that are gone -
        // so shrinking the grace to 1ms leaves this green. The grace matters
        // for work still running, and that is the test below.
        assert_eq!(
            veil_packet_tunnel_abandoned_workers(),
            abandoned_before,
            "cancellable work was abandoned instead of being waited for"
        );
    }

    /// And work that CANNOT be woken is counted rather than lost quietly.
    ///
    /// This is the honest half. Which task parks in production is not
    /// established (the blocking read lives in a crate this tree does not
    /// own), so the guarantee here is not that it never happens. It is that it
    /// is visible when it does: a number that climbs can be diagnosed, memory
    /// that climbs cannot.
    #[test]
    fn work_that_cannot_be_woken_is_counted() {
        let _serial = SLOT_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let before = veil_packet_tunnel_abandoned_workers();

        let started = launch_tunnel(None, None, 1280, |runtime, cancel| {
            runtime.spawn_blocking(|| std::thread::sleep(Duration::from_secs(3600)));
            runtime.block_on(async move { cancel.cancelled().await });
            Ok(0)
        });
        assert_eq!(started, crate::VEIL_OK);
        assert_eq!(veil_packet_tunnel_stop(), crate::VEIL_OK);
        // The worker finishes its teardown after stop returns; the count is
        // published at the end of it.
        std::thread::sleep(RUNTIME_SHUTDOWN_GRACE + Duration::from_millis(400));

        assert!(
            veil_packet_tunnel_abandoned_workers() > before,
            "a thread was abandoned and nothing recorded it"
        );
    }

    /// Premise for the test above: a worker that ends cleanly frees the slot
    /// too, so the assertions there are not passing on a slot that is never
    /// taken in the first place.
    #[test]
    fn an_ordinary_worker_frees_the_slot() {
        let _serial = SLOT_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let started = launch_tunnel(None, None, 1280, |runtime, cancel| {
            runtime.block_on(async move { cancel.cancelled().await });
            Ok(0)
        });
        assert_eq!(started, crate::VEIL_OK);
        assert_eq!(veil_packet_tunnel_stop(), crate::VEIL_OK);
        assert_eq!(veil_packet_tunnel_status(), VEIL_TUNNEL_STOPPED);
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
