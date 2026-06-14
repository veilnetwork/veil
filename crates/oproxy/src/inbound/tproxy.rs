//! Transparent proxy inbound (Linux `IP_TRANSPARENT` + `SO_ORIGINAL_DST`
//! pattern, also known as Xray's "dokodemo-door").
//!
//! # How it works
//!
//! 1. Operator sets up iptables / nftables to redirect transit traffic
//!    to the local listener:
//!    ```text
//!    iptables -t mangle -A PREROUTING -p tcp \
//!        --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 \
//!        --on-port 12345
//!    ```
//!    Plus a matching `ip rule` + `ip route local` setup so the kernel
//!    delivers the packets to the listener instead of routing them
//!    outbound.
//! 2. The listener socket is created with `IP_TRANSPARENT = 1` (so the
//!    kernel accepts connections destined to any address) and `MARK`
//!    set to match the iptables rule.
//! 3. For each accepted connection, recover the **original** destination
//!    address via `getsockopt(SOL_IP, SO_ORIGINAL_DST)` (Linux) or the
//!    equivalent FreeBSD ipfw mechanism.
//! 4. Forward to the veil server using `(orig_dst.ip, orig_dst.port)`.
//!
//! # Platform support
//!
//! * **Linux / Keenetic** — full support (Keenetic uses the standard
//!   Linux kernel surface).
//! * **FreeBSD / macOS / Windows** — **not supported**.  FreeBSD's
//!   `ipfw fwd` + `getpeername` path was never finished (stubs in
//!   [`tproxy_unix`] returned a runtime error from the first accept);
//!   macOS would need pfctl + a divert socket with kernel reads;
//!   Windows would need WinDivert + a kernel driver.  All three return
//!   a descriptive error at startup so operators learn the gap
//!   before traffic ever lands.
//!
//! Operators on FreeBSD / macOS / Windows should use the SOCKS5 / HTTP
//! inbounds and configure their applications to point at them.

use std::sync::Arc;

use anyhow::Result;

use veilclient::AppSender;

use crate::config::RoutingConfig;

#[cfg(target_os = "linux")]
pub async fn run(
    listen_addr: String,
    app_handle: Arc<AppSender>,
    server_node_id: [u8; 32],
    server_app_id: [u8; 32],
    routing: Arc<RoutingConfig>,
    semaphore: Arc<tokio::sync::Semaphore>,
) -> Result<()> {
    crate::inbound::tproxy_unix::run(
        listen_addr,
        app_handle,
        server_node_id,
        server_app_id,
        routing,
        semaphore,
    )
    .await
}

/// FreeBSD fail-fast: the previous build path bound a listener and only
/// failed on the first accepted connection, which made operators believe
/// TProxy was working (the listener was visible in `sockstat`) until
/// real traffic landed.  Audit batch 2026-05-23: gate this to a startup
/// error like macOS / Windows.  Re-open trigger: someone actually
/// implements pf+divert OR ipfw fwd + getpeername — restore the
/// `cfg(target_os = "freebsd")` to the linux branch above.
#[cfg(not(target_os = "linux"))]
pub async fn run(
    _listen_addr: String,
    _app_handle: Arc<AppSender>,
    _server_node_id: [u8; 32],
    _server_app_id: [u8; 32],
    _routing: Arc<RoutingConfig>,
    _semaphore: Arc<tokio::sync::Semaphore>,
) -> Result<()> {
    Err(anyhow::anyhow!(
        "TProxy inbound is not supported on this platform. \
         Linux / Keenetic only.  Use SOCKS5 or HTTP inbound on \
         FreeBSD / macOS / Windows."
    ))
}
