//! Process-safe packet-tunnel lifecycle around `tun2proxy`.
//!
//! The upstream crate also exposes a CLI-oriented C entry point whose shutdown
//! fallback calls `process::exit`. An embedded messenger must never use that
//! entry point. This module invokes `general_run_async` directly with an owned
//! cancellation token and exposes one process-wide VPN instance to Flutter.

use std::ffi::{CStr, CString};
use std::net::IpAddr;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::os::raw::{c_char, c_int, c_ushort, c_void};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tun2proxy::{ArgDns, ArgProxy, ArgVerbosity, Args, CancellationToken};

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
    write_cb: PacketWriteFn,
    write_ctx: usize,
    mtu: usize,
}

impl CallbackDevice {
    fn new(
        packet_rx: mpsc::Receiver<Vec<u8>>,
        write_cb: PacketWriteFn,
        write_ctx: *mut c_void,
        mtu: u16,
    ) -> Self {
        Self {
            packet_rx,
            pending: None,
            pending_offset: 0,
            write_cb,
            // Raw pointers are not Send. The host guarantees that the opaque
            // context remains valid until stop completes, so store its bits as
            // an integer and restore the pointer only at callback time.
            write_ctx: write_ctx as usize,
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
        (self.write_cb)(self.write_ctx as *mut c_void, buf.as_ptr(), buf.len());
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

fn launch_tunnel<F>(packet_tx: Option<mpsc::Sender<Vec<u8>>>, mtu: u16, run: F) -> c_int
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

    launch_tunnel(None, mtu, move |runtime, cancel| {
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
/// accumulating unbounded packet memory. The callback context must remain live
/// until [`veil_packet_tunnel_stop`] returns. `write_cb` is required and must
/// not be null (a null C function pointer violates this FFI contract).
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
    let device = CallbackDevice::new(packet_rx, write_cb, write_ctx, mtu);
    launch_tunnel(Some(packet_tx), mtu, move |runtime, cancel| {
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

#[unsafe(no_mangle)]
pub extern "C" fn veil_packet_tunnel_stop() -> c_int {
    let cancel = {
        let mut slot = tunnel_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cleanup_finished(&mut slot);
        let Some(tunnel) = slot.as_ref() else {
            return crate::VEIL_OK;
        };
        tunnel.cancel.clone()
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
            return crate::VEIL_OK;
        }
        std::thread::sleep(Duration::from_millis(10));
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
        let mut device = CallbackDevice::new(packet_rx, collect_packet, output_ctx, 1280);

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
        let mut device = CallbackDevice::new(packet_rx, collect_packet, output_ctx, 1280);
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
