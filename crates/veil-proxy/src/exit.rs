//! Exit proxy.
//!
//! The exit node receives veil proxy-connect streams (identified by
//! a `PROXY_CONNECT` destination payload prepended to the stream data) and
//! opens an outgoing TCP connection to the requested host:port on behalf of
//! the client. Data is then bridged in both directions.
//!
//! # Protocol
//!
//! When a proxy-connect stream is opened the initiating node prepends a small
//! header before any application data:
//!
//! ```text
//! [host_len: u16 BE][host: UTF-8 bytes][port: u16 BE]
//! ```
//!
//! The exit node reads this header, connects to `host:port`, sends a one-byte
//! success acknowledgement (`0x00`) and then bridges bidirectionally.

use std::net::IpAddr;
use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    time::timeout,
};

use veil_types::NodeRole;

/// Connection timeout for the outgoing TCP leg.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Check that `role` is eligible to act as an exit proxy.
///
/// Only Core nodes with exit enabled may accept proxy-connect
/// streams (33.4 role check).
pub fn can_act_as_exit(role: NodeRole, exit_enabled: bool) -> bool {
    exit_enabled && matches!(role, NodeRole::Core)
}

/// refuse to proxy to non-routable / sensitive destinations.
///
/// Blocks by default: loopback, private (RFC1918 / IPv6 unique-local and
/// link-local), multicast, unspecified (`0.0.0.0` / `::`), broadcast, and
/// the cloud metadata endpoint `169.254.169.254` (IPv4 link-local).
///
/// The operator can opt out via `config.proxy.exit.allow_private` for
/// isolated testbeds where the exit is trusted to probe internal nets.
pub fn is_forbidden_destination(ip: IpAddr) -> bool {
    // SECURITY: canonicalize before any classification. Both the IPv4-mapped
    // (`::ffff:x.x.x.x`) AND the deprecated IPv4-compatible (`::x.x.x.x`,
    // RFC 4291 §2.5.5.1) IPv6 forms embed a V4 address whose leading V6
    // segment is 0x0000 — so they match neither the fc00::/7 nor fe80::/10
    // V6 prefixes below, and are not caught by `is_loopback()` (they are not
    // `::1`). Left un-canonicalized they slip through as "allowed", letting a
    // remote peer drive the exit toward RFC1918 / cloud-metadata / loopback,
    // defeating `allow_private = false`. `to_canonical()` handles the mapped
    // form; the explicit branch below handles the IPv4-compatible form.
    //
    // MUST stay in sync with `oproxy::routing::is_forbidden_ip` — the audit
    // 2026-05-29 fix here covered only the mapped form; the IPv4-compatible
    // and CGNAT cases were fixed in `oproxy` (cycle-6) but not mirrored here.
    let ip = match ip {
        IpAddr::V6(v6) => {
            let c = v6.to_canonical(); // handles ::ffff:x.x.x.x
            if c.is_ipv4() {
                c
            } else {
                let s = v6.segments();
                // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052): the embedded
                // V4 lives in the low 32 bits, but its leading segment is 0x0064
                // (non-zero) so `to_canonical()` leaves it as V6 and it dodges
                // the fc00::/fe80:: prefix checks below. Translate + re-classify
                // so 64:ff9b::169.254.169.254 / ::10.0.0.1 stay forbidden.
                let is_nat64 = s[0] == 0x0064 && s[1] == 0xff9b && s[2..6].iter().all(|&x| x == 0);
                // IPv4-compatible: first 96 bits zero, low 32 bits the V4
                // addr (exclude `::` unspecified and `::1` loopback, both
                // already caught by the checks below regardless).
                if is_nat64 || (s[0..6].iter().all(|&x| x == 0) && (s[6] != 0 || s[7] > 1)) {
                    IpAddr::V4(std::net::Ipv4Addr::new(
                        (s[6] >> 8) as u8,
                        (s[6] & 0xff) as u8,
                        (s[7] >> 8) as u8,
                        (s[7] & 0xff) as u8,
                    ))
                } else {
                    IpAddr::V6(v6)
                }
            }
        }
        other => other,
    };
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            // is_private: 10/8, 172.16/12, 192.168/16.
            // is_link_local: 169.254/16 (covers 169.254.169.254 metadata).
            // is_broadcast: 255.255.255.255.
            // CGNAT: RFC 6598 Shared Address Space 100.64.0.0/10 — routable
            // carrier-internal infra, must be treated like RFC1918.
            let o = v4.octets();
            let is_cgnat = o[0] == 100 && (o[1] & 0xC0) == 64;
            // 0.0.0.0/8 ("this network", RFC 1122) — only 0.0.0.0 itself is
            // caught by is_unspecified() above; reject the whole /8.
            o[0] == 0 || v4.is_private() || v4.is_link_local() || v4.is_broadcast() || is_cgnat
        }
        IpAddr::V6(v6) => {
            // Unique-local fc00::/7 and link-local fe80::/10 are not
            // exposed as stable methods on IpAddr stable as of 1.80, so
            // match by the first byte/prefix directly.
            let seg = v6.segments()[0];
            // fc00::/7 = 1111 110x prefix (0xFC00 – 0xFDFF).
            let is_unique_local = (seg & 0xFE00) == 0xFC00;
            // fe80::/10 = 1111 1110 10xx prefix.
            let is_link_local = (seg & 0xFFC0) == 0xFE80;
            is_unique_local || is_link_local
        }
    }
}

/// Read the proxy-connect destination header from a stream.
///
/// Returns `(host, port)`.
pub async fn read_proxy_header<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(String, u16)> {
    let mut host_len_buf = [0u8; 2];
    reader.read_exact(&mut host_len_buf).await?;
    let host_len = u16::from_be_bytes(host_len_buf) as usize;
    if host_len > 255 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("host_len {host_len} exceeds maximum 255"),
        ));
    }

    let mut host_bytes = vec![0u8; host_len];
    reader.read_exact(&mut host_bytes).await?;
    let host = String::from_utf8(host_bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid host encoding")
    })?;

    let mut port_buf = [0u8; 2];
    reader.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok((host, port))
}

/// Write the proxy-connect destination header to a stream.
pub fn encode_proxy_header(host: &str, port: u16) -> Vec<u8> {
    let host_bytes = host.as_bytes();
    let mut buf = Vec::with_capacity(2 + host_bytes.len() + 2);
    buf.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(host_bytes);
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

/// Handle an inbound proxy-connect veil stream.
///
/// Reads the destination header, opens a TCP connection to the target, sends
/// a `0x00` acknowledgement, then bridges bytes in both directions.
///
/// # Arguments
///
/// * `role` — local node role (must be Core or Gateway).
/// * `exit_enabled` — `config.proxy.exit.enabled`.
/// * `veil_stream` — the bidirectional veil stream (already fully opened).
pub async fn handle_proxy_connect_stream<S>(
    role: NodeRole,
    exit_enabled: bool,
    allow_private: bool,
    veil_stream: S,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    handle_proxy_connect_stream_with_metrics(role, exit_enabled, allow_private, None, veil_stream)
        .await
}

/// metric-enabled variant — called from the production spawn
/// path so `exit_proxy_dest_denied_total` is tickable. Tests use the
/// simpler 4-arg `handle_proxy_connect_stream` which passes `None`.
pub async fn handle_proxy_connect_stream_with_metrics<S>(
    role: NodeRole,
    exit_enabled: bool,
    allow_private: bool,
    metrics: Option<std::sync::Arc<dyn crate::ProxyMetrics>>,
    veil_stream: S,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if !can_act_as_exit(role, exit_enabled) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "this node is not configured as an exit proxy",
        ));
    }

    let (mut veil_r, mut veil_w) = tokio::io::split(veil_stream);

    // Read the destination header from the veil stream.
    let (host, port) = read_proxy_header(&mut veil_r).await?;

    // resolve host → IPs and pick the first non-forbidden one.
    // Resolving explicitly (rather than deferring to `TcpStream::connect`)
    // gives us a chance to enforce the deny-list; `connect((host, port))`
    // would happily race through every resolved address silently.
    let candidates: Vec<std::net::SocketAddr> =
        timeout(CONNECT_TIMEOUT, lookup_host((host.as_str(), port)))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "resolve timeout"))?
            .map_err(|e| std::io::Error::new(e.kind(), format!("resolve {host}:{port}: {e}")))?
            .collect();
    if candidates.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("no addresses resolved for {host}:{port}"),
        ));
    }
    let picked = candidates
        .into_iter()
        .find(|addr| allow_private || !is_forbidden_destination(addr.ip()));
    let Some(addr) = picked else {
        if let Some(m) = &metrics {
            m.inc_exit_proxy_dest_denied();
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "exit-proxy denied {host}:{port}: all resolved addresses are \
                 private/loopback/link-local (override via proxy.exit.allow_private)"
            ),
        ));
    };

    // Open an outgoing TCP connection to the filtered target.
    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))?
        .map_err(|e| std::io::Error::new(e.kind(), format!("tcp connect to {addr}: {e}")))?;

    // Acknowledge success.
    veil_w.write_all(&[0x00]).await?;

    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    // Bridge bidirectionally, draining BOTH directions (audit cycle-8). The old
    // `select!` cancelled the opposite `copy` the instant either direction
    // finished, so a client that half-closes its request direction (HTTP/1.0,
    // SMTP, line protocols) truncated the server's response mid-flight. Mirror
    // oproxy's bridge: `join!` each direction's copy + a `shutdown` of its write
    // half so a one-way EOF propagates without cancelling the other half.
    let up = async {
        let _ = tokio::io::copy(&mut veil_r, &mut tcp_w).await;
        let _ = tcp_w.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut tcp_r, &mut veil_w).await;
        let _ = veil_w.shutdown().await;
    };
    tokio::join!(up, down);

    Ok(())
}

/// Exit proxy service handle.
pub struct ExitProxy {
    pub role: NodeRole,
    pub enabled: bool,
}

impl ExitProxy {
    pub fn new(role: NodeRole, enabled: bool) -> Self {
        Self { role, enabled }
    }

    pub fn can_accept(&self) -> bool {
        can_act_as_exit(self.role, self.enabled)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── 33.4: role check ──────────────────────────────────────────────────────

    #[test]
    fn only_core_can_exit() {
        assert!(can_act_as_exit(NodeRole::Core, true));
        assert!(!can_act_as_exit(NodeRole::Leaf, true));
        assert!(!can_act_as_exit(NodeRole::Core, false));
    }

    // ── Proxy header encode/decode roundtrip ──────────────────────────────────

    #[tokio::test]
    async fn proxy_header_roundtrip() {
        let encoded = encode_proxy_header("example.com", 8080);
        let mut cursor = std::io::Cursor::new(encoded);
        let (host, port) = read_proxy_header(&mut cursor).await.unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    // ── 33.3: exit node bridges data to target TCP ────────────────────────────
    //
    // Spin up a local echo TCP server, then call `handle_proxy_connect_stream`
    // with a fake veil stream pointing to that echo server. Verify that
    // data sent via the veil emerges from the echo server and comes back.

    #[tokio::test]
    async fn exit_proxy_bridges_to_tcp_target() {
        use tokio::net::TcpListener;

        // Start a simple echo server.
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = echo_listener.accept().await {
                let (mut r, mut w) = s.split();
                tokio::io::copy(&mut r, &mut w).await.ok();
            }
        });

        // Build a duplex pair simulating the veil stream.
        let (client_half, server_half) = tokio::io::duplex(4096);

        // Spawn the exit handler. Echo server binds 127.0.0.1, which is
        // loopback → would be denied by default ACL, so allow_private = true.
        tokio::spawn(handle_proxy_connect_stream(
            NodeRole::Core,
            true,
            true,
            server_half,
        ));

        let (mut client_r, mut client_w) = tokio::io::split(client_half);

        // Write the proxy header pointing to our echo server.
        let header = encode_proxy_header("127.0.0.1", echo_addr.port());
        client_w.write_all(&header).await.unwrap();

        // Read the acknowledgement byte.
        let mut ack = [0u8; 1];
        client_r.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack[0], 0x00, "expected ACK");

        // Write data and read it back (echo).
        client_w.write_all(b"hello proxy").await.unwrap();
        let mut buf = [0u8; 11];
        client_r.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello proxy");
    }

    // ── 33.4: non-exit role is rejected ──────────────────────────────────────

    #[tokio::test]
    async fn leaf_node_rejects_proxy_connect() {
        let (_, server_half) = tokio::io::duplex(64);
        let result = handle_proxy_connect_stream(NodeRole::Leaf, true, false, server_half).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    // ── 461.2: ACL tests for private/loopback/link-local destinations ────────

    #[test]
    fn forbidden_ipv4_loopback() {
        assert!(is_forbidden_destination("127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_destination("127.255.255.254".parse().unwrap()));
    }

    #[test]
    fn forbidden_ipv4_private_ranges() {
        assert!(is_forbidden_destination("10.0.0.1".parse().unwrap()));
        assert!(is_forbidden_destination("172.16.0.1".parse().unwrap()));
        assert!(is_forbidden_destination("172.31.255.254".parse().unwrap()));
        assert!(is_forbidden_destination("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn forbidden_ipv4_cloud_metadata() {
        // 169.254.169.254 = AWS/GCP/Azure instance metadata; classified as
        // link-local so is_link_local catches it.
        assert!(is_forbidden_destination("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn forbidden_ipv4_broadcast_and_multicast() {
        assert!(is_forbidden_destination("255.255.255.255".parse().unwrap()));
        assert!(is_forbidden_destination("224.0.0.1".parse().unwrap()));
    }

    #[test]
    fn forbidden_ipv6_loopback_and_unspecified() {
        assert!(is_forbidden_destination("::1".parse().unwrap()));
        assert!(is_forbidden_destination("::".parse().unwrap()));
    }

    #[test]
    fn forbidden_ipv6_unique_local() {
        // fc00::/7 covers fc00..fdff.
        assert!(is_forbidden_destination("fc00::1".parse().unwrap()));
        assert!(is_forbidden_destination("fd00::1".parse().unwrap()));
    }

    #[test]
    fn forbidden_ipv6_link_local() {
        // fe80::/10 covers fe80..febf.
        assert!(is_forbidden_destination("fe80::1".parse().unwrap()));
    }

    #[test]
    fn allowed_ipv4_public() {
        assert!(!is_forbidden_destination("8.8.8.8".parse().unwrap()));
        assert!(!is_forbidden_destination("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn allowed_ipv6_public() {
        assert!(!is_forbidden_destination("2001:db8::1".parse().unwrap()));
        assert!(!is_forbidden_destination("2606:4700::1".parse().unwrap()));
    }

    /// SECURITY (audit 2026-05-29, CRITICAL SSRF regression): IPv4-mapped
    /// IPv6 destinations MUST be canonicalized and blocked exactly like
    /// their plain-IPv4 form.  Pre-fix, `::ffff:169.254.169.254` had
    /// first segment 0x0000 → bypassed both the fc00::/7 and fe80::/10
    /// prefix checks AND `is_loopback()`, admitting cloud-metadata /
    /// RFC1918 / loopback over IPv4 on dual-stack hosts.
    #[test]
    fn forbidden_ipv4_mapped_ipv6_cloud_metadata() {
        assert!(
            is_forbidden_destination("::ffff:169.254.169.254".parse().unwrap()),
            "IPv4-mapped cloud-metadata must be forbidden"
        );
    }

    #[test]
    fn forbidden_ipv4_mapped_ipv6_loopback_and_private() {
        assert!(
            is_forbidden_destination("::ffff:127.0.0.1".parse().unwrap()),
            "IPv4-mapped loopback must be forbidden"
        );
        assert!(
            is_forbidden_destination("::ffff:10.0.0.1".parse().unwrap()),
            "IPv4-mapped RFC1918 must be forbidden"
        );
        assert!(
            is_forbidden_destination("::ffff:192.168.1.1".parse().unwrap()),
            "IPv4-mapped private must be forbidden"
        );
    }

    /// SECURITY (C-04, 2026-06-02): the deprecated IPv4-COMPATIBLE IPv6 form
    /// `::x.x.x.x` (distinct from the `::ffff:` mapped form) also embeds a V4
    /// address with a 0x0000 leading segment, but `to_canonical()` only
    /// collapses the mapped form — so pre-fix it bypassed the deny-list.
    /// These MUST be blocked exactly like their plain-IPv4 equivalents.
    #[test]
    fn forbidden_ipv4_compatible_ipv6() {
        assert!(
            is_forbidden_destination("::169.254.169.254".parse().unwrap()),
            "IPv4-compatible cloud-metadata must be forbidden"
        );
        assert!(
            is_forbidden_destination("::127.0.0.1".parse().unwrap()),
            "IPv4-compatible loopback must be forbidden"
        );
        assert!(
            is_forbidden_destination("::10.0.0.1".parse().unwrap()),
            "IPv4-compatible RFC1918 must be forbidden"
        );
    }

    /// SECURITY (C-04, 2026-06-02): CGNAT / RFC 6598 shared address space
    /// 100.64.0.0/10 is routable carrier-internal infrastructure and must be
    /// blocked like RFC1918 — in plain and mapped forms — without over-
    /// blocking the public 100.x space outside the /10.
    #[test]
    fn forbidden_cgnat_shared_address_space() {
        assert!(is_forbidden_destination("100.64.0.1".parse().unwrap()));
        assert!(is_forbidden_destination("100.127.255.254".parse().unwrap()));
        assert!(is_forbidden_destination(
            "::ffff:100.64.0.1".parse().unwrap()
        ));
        // 100.63.x and 100.128.x are OUTSIDE the /10 — must stay allowed.
        assert!(!is_forbidden_destination("100.63.255.255".parse().unwrap()));
        assert!(!is_forbidden_destination("100.128.0.1".parse().unwrap()));
    }

    #[test]
    fn allowed_ipv4_mapped_ipv6_public() {
        // A public IPv4 in mapped form stays allowed (canonicalization
        // must not over-block).
        assert!(
            !is_forbidden_destination("::ffff:8.8.8.8".parse().unwrap()),
            "IPv4-mapped public address must remain allowed"
        );
    }

    /// SECURITY: the NAT64 well-known prefix 64:ff9b::/96 (RFC 6052) embeds a
    /// V4 address in its low 32 bits. `to_canonical()` leaves it as V6 and its
    /// 0x0064 leading segment dodges the fc00::/fe80:: prefix checks, so pre-fix
    /// it bypassed the deny-list. The embedded V4 MUST be classified like its
    /// plain-IPv4 equivalent — without over-blocking an embedded public V4.
    #[test]
    fn forbidden_nat64_well_known_prefix() {
        assert!(
            is_forbidden_destination("64:ff9b::169.254.169.254".parse().unwrap()),
            "NAT64-embedded cloud-metadata must be forbidden"
        );
        assert!(
            is_forbidden_destination("64:ff9b::10.0.0.1".parse().unwrap()),
            "NAT64-embedded RFC1918 must be forbidden"
        );
        // Embedded PUBLIC V4 must stay allowed (no over-block).
        assert!(
            !is_forbidden_destination("64:ff9b::8.8.8.8".parse().unwrap()),
            "NAT64-embedded public address must remain allowed"
        );
    }

    /// SECURITY: 0.0.0.0/8 ("this network", RFC 1122). is_unspecified() only
    /// catches 0.0.0.0 itself; the rest of the /8 must also be forbidden.
    #[test]
    fn forbidden_zero_network_slash8() {
        assert!(is_forbidden_destination("0.0.0.1".parse().unwrap()));
        assert!(is_forbidden_destination("0.255.255.255".parse().unwrap()));
        // 1.0.0.0 is OUTSIDE 0.0.0.0/8 — must stay allowed.
        assert!(!is_forbidden_destination("1.0.0.1".parse().unwrap()));
        // Sanity: a public address stays allowed.
        assert!(!is_forbidden_destination("8.8.8.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn exit_denies_loopback_without_override() {
        // Without allow_private, connecting to 127.0.0.1 must fail with
        // PermissionDenied before any TCP connect is attempted.
        let (client_half, server_half) = tokio::io::duplex(4096);
        let join = tokio::spawn(handle_proxy_connect_stream(
            NodeRole::Core,
            true,
            false, // allow_private = false → ACL active
            server_half,
        ));
        let (_, mut client_w) = tokio::io::split(client_half);
        let header = encode_proxy_header("127.0.0.1", 1);
        client_w.write_all(&header).await.unwrap();
        let result = join.await.unwrap();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
}
