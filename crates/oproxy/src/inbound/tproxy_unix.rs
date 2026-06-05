//! Linux TProxy implementation.
//!
//! `IP_TRANSPARENT` socket option + `SO_ORIGINAL_DST` getsockopt
//! retrieve the original destination of redirected connections.
//!
//! FreeBSD support was removed in the audit batch 2026-05-23 — the
//! previous `ipfw fwd` + `getpeername` path was а stub that compiled
//! но failed at runtime on the first accept.  Re-add к
//! `crates/oproxy/src/inbound/{mod,tproxy}.rs` cfg-gates when а real
//! FreeBSD path (pf + divert OR ipfw fwd + getpeername) is implemented.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::net::{TcpListener, TcpStream};

use veilclient::AppSender;

use crate::config::RoutingConfig;
use crate::connector::bridge_via_routing;

// SO_ORIGINAL_DST constant (Linux netfilter).  Defined in linux/netfilter_ipv4.h.
// libc crate doesn't expose it directly on all targets, so define inline.
#[cfg(target_os = "linux")]
const SO_ORIGINAL_DST: libc::c_int = 80;
// IPv6 equivalent.
#[cfg(target_os = "linux")]
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

pub async fn run(
    listen_addr: String,
    app_handle: Arc<AppSender>,
    server_node_id: [u8; 32],
    server_app_id: [u8; 32],
    routing: Arc<RoutingConfig>,
    semaphore: Arc<tokio::sync::Semaphore>,
) -> Result<()> {
    // Bind с IP_TRANSPARENT set so the kernel accepts non-local destinations.
    let listener = bind_transparent(&listen_addr)
        .with_context(|| format!("bind TProxy listener {listen_addr}"))?;
    log::info!(
        "oproxy.tproxy: listening on {listen_addr} (IP_TRANSPARENT enabled). \
         Operator must wire matching iptables -j TPROXY rule + ip rule + ip route."
    );
    loop {
        // Audit batch 2026-05-24 (M8): semaphore gating, см. socks5.rs.
        let permit = match Arc::clone(&semaphore).acquire_owned().await {
            Ok(p) => p,
            Err(_closed) => return Ok(()),
        };
        let (stream, peer) = listener.accept().await.context("accept TProxy")?;
        let orig_dst = match get_original_dst(&stream) {
            Ok(addr) => addr,
            Err(e) => {
                log::warn!("oproxy.tproxy: SO_ORIGINAL_DST failed для {peer}: {e}");
                continue;
            }
        };
        log::debug!("oproxy.tproxy: accept от {peer} → orig dst {orig_dst}");
        let h = Arc::clone(&app_handle);
        let r = Arc::clone(&routing);
        tokio::spawn(async move {
            let _permit = permit;
            let host = orig_dst.ip().to_string();
            let port = orig_dst.port();
            if let Err(e) =
                bridge_via_routing(h, server_node_id, server_app_id, r, stream, host, port).await
            {
                log::debug!("oproxy.tproxy: peer {peer} → {orig_dst} dropped: {e}");
            }
        });
    }
}

/// Create а TCP listener with `IP_TRANSPARENT = 1`.  Returns а tokio
/// `TcpListener` ready for `accept()`.
fn bind_transparent(listen_addr: &str) -> Result<TcpListener> {
    use std::net::TcpListener as StdListener;

    let std_listener =
        StdListener::bind(listen_addr).with_context(|| format!("std bind {listen_addr}"))?;
    let fd = std_listener.as_raw_fd();
    unsafe {
        let one: libc::c_int = 1;
        let rc = libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TRANSPARENT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if rc != 0 {
            return Err(anyhow!(
                "setsockopt(IP_TRANSPARENT) failed: {} \
                 (requires CAP_NET_ADMIN или root)",
                std::io::Error::last_os_error(),
            ));
        }
    }
    std_listener
        .set_nonblocking(true)
        .context("set nonblocking")?;
    TcpListener::from_std(std_listener).context("tokio from_std")
}

/// Retrieve the original destination of а connection redirected via
/// the netfilter mangle table (Linux / Keenetic) или ipfw fwd (FreeBSD).
fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    // Try IPv4 first (most common); fall back к IPv6.
    if let Ok(addr) = get_original_dst_v4(fd) {
        return Ok(addr);
    }
    get_original_dst_v6(fd)
}

#[cfg(target_os = "linux")]
fn get_original_dst_v4(fd: std::os::unix::io::RawFd) -> Result<SocketAddr> {
    unsafe {
        let mut storage: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut storage as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if rc != 0 {
            return Err(anyhow!(
                "getsockopt(SO_ORIGINAL_DST, v4): {}",
                std::io::Error::last_os_error()
            ));
        }
        let port = u16::from_be(storage.sin_port);
        let ip_be = storage.sin_addr.s_addr;
        let ip = Ipv4Addr::from(u32::from_be(ip_be));
        Ok(SocketAddr::new(IpAddr::V4(ip), port))
    }
}

#[cfg(target_os = "linux")]
fn get_original_dst_v6(fd: std::os::unix::io::RawFd) -> Result<SocketAddr> {
    unsafe {
        let mut storage: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            &mut storage as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if rc != 0 {
            return Err(anyhow!(
                "getsockopt(SO_ORIGINAL_DST, v6): {}",
                std::io::Error::last_os_error()
            ));
        }
        let port = u16::from_be(storage.sin6_port);
        let ip = Ipv6Addr::from(storage.sin6_addr.s6_addr);
        Ok(SocketAddr::new(IpAddr::V6(ip), port))
    }
}
