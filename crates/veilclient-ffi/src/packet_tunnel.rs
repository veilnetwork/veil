//! Process-safe packet-tunnel lifecycle around `tun2proxy`.
//!
//! The upstream crate also exposes a CLI-oriented C entry point whose shutdown
//! fallback calls `process::exit`. An embedded messenger must never use that
//! entry point. This module invokes `general_run_async` directly with an owned
//! cancellation token and exposes one process-wide VPN instance to Flutter.

use std::ffi::{CStr, CString};
use std::net::IpAddr;
use std::os::raw::{c_char, c_int, c_ushort};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tun2proxy::{ArgDns, ArgProxy, ArgVerbosity, Args, CancellationToken};

pub const VEIL_TUNNEL_STOPPED: c_int = 0;
pub const VEIL_TUNNEL_STARTING: c_int = 1;
pub const VEIL_TUNNEL_RUNNING: c_int = 2;
pub const VEIL_TUNNEL_ERROR: c_int = 3;

const STOP_TIMEOUT: Duration = Duration::from_secs(2);

struct PacketTunnel {
    cancel: CancellationToken,
    phase: Arc<AtomicU8>,
    error: Arc<Mutex<Option<String>>>,
    thread: Option<std::thread::JoinHandle<()>>,
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

/// Start a packet engine over an OS-owned TUN file descriptor.
///
/// The host remains responsible for creating/configuring the interface and for
/// keeping the descriptor alive until [`veil_packet_tunnel_stop`] returns.
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
) -> c_int {
    if tun_fd < 0 || !(1280..=9000).contains(&mtu) {
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
    let proxy = match ArgProxy::try_from(proxy_url) {
        Ok(value) if value.addr.ip().is_loopback() => value,
        _ => return crate::VEIL_ERR_INVALID_ARG,
    };
    let dns_addr = match dns_ip.parse::<IpAddr>() {
        Ok(value) => value,
        Err(_) => return crate::VEIL_ERR_INVALID_ARG,
    };

    // Reject stale/closed descriptors before starting the worker. This check is
    // intentionally non-owning: the platform service remains the fd owner.
    // SAFETY: F_GETFD does not dereference memory and accepts any integer fd.
    if unsafe { libc::fcntl(tun_fd, libc::F_GETFD) } < 0 {
        return crate::VEIL_ERR_INVALID_ARG;
    }

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
            let mut args = Args {
                proxy,
                dns: ArgDns::Direct,
                dns_addr,
                ipv6_enabled,
                setup: false,
                mtu,
                verbosity: ArgVerbosity::Warn,
                ..Args::default()
            };
            args.tun_fd(Some(tun_fd)).close_fd_on_drop(false);

            worker_phase.store(VEIL_TUNNEL_RUNNING as u8, Ordering::Release);
            let result = runtime.block_on(tun2proxy::general_run_async(
                args,
                mtu,
                packet_information,
                worker_cancel.clone(),
            ));
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
        thread: Some(thread),
    });
    crate::VEIL_OK
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_inputs_fail_before_creating_global_tunnel() {
        let proxy = CString::new("socks5://127.0.0.1:1080").unwrap();
        let dns = CString::new("1.1.1.1").unwrap();
        // SAFETY: pointers remain valid for the duration of the call.
        let result = unsafe {
            veil_packet_tunnel_start_fd(-1, proxy.as_ptr(), dns.as_ptr(), 1280, true, false)
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
            veil_packet_tunnel_start_fd(0, proxy.as_ptr(), dns.as_ptr(), 1280, true, false)
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
}
