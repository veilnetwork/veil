//! SOCKS-fallback URI composition helpers.
//!
//! Anti-censorship strategy: when direct outbound dial fails (AS-level
//! block, ISP route hijack, transient TSPU rule), the runtime retries
//! the connection wrapped through an operator-configured SOCKS proxy
//! (typically local Tor on `socks5://127.0.0.1:9050`).
//!
//! This module ships the **pure URI-composition layer** so the runtime's
//! `socks_fallback_dial` async method stays thin and the parsing logic is
//! unit-testable without a mock SOCKS server.

use veil_transport::TransportUri;

/// Compose the SOCKS-fallback dial parameters from an operator-supplied
/// proxy string and the primary target URI.
///
/// Returns `Some((proxy_host, proxy_port, target_host, target_port))`
/// when the wrapper can be built, or `None` if:
///
/// * `proxy_str` is unparseable (missing `:port` or malformed)
/// * `primary_uri`'s scheme can't be tunneled through SOCKS5 (QUIC, Unix,
///   webtunnel-wss, etc. — SOCKS5 is a TCP-only transport)
///
/// Accepted proxy formats:
/// * `socks5://host:port`
/// * `socks://host:port`
/// * Bare `host:port` (defaults to SOCKS5)
pub fn compose_socks_fallback(
    proxy_str: &str,
    primary_uri: &TransportUri,
) -> Option<(String, u16, String, u16)> {
    let (proxy_host, proxy_port) = parse_proxy_endpoint(proxy_str)?;
    let (target_host, target_port) = extract_tcp_target(primary_uri)?;
    Some((proxy_host, proxy_port, target_host, target_port))
}

/// Parse a proxy endpoint string into (host, port).  Delegates to the canonical
/// parser in `veil-transport` (audit U13) so the peer-dial SOCKS fallback
/// accepts exactly the same forms as the bootstrap / `.onion` dial path —
/// `socks5h://` / `socks5://` / `socks://` / bare `host:port`, a tolerated
/// trailing `/path`, and a non-zero port. The old local copy silently rejected
/// `socks5h://`, so an operator's `socks5h://127.0.0.1:9050` fallback was
/// dropped instead of used.
fn parse_proxy_endpoint(proxy_str: &str) -> Option<(String, u16)> {
    veil_transport::socks::parse_socks_proxy_url(proxy_str).ok()
}

/// Extract a TCP-shaped target from a primary URI.  Returns None for
/// schemes that SOCKS5 cannot tunnel.
fn extract_tcp_target(uri: &TransportUri) -> Option<(String, u16)> {
    match uri {
        TransportUri::Tcp { host, port }
        | TransportUri::Tls { host, port, .. }
        | TransportUri::Obfs4Tcp { host, port } => Some((host.clone(), *port)),
        // QUIC is UDP — can't tunnel via SOCKS5.
        // Unix sockets are local-only.
        // SOCKS / SocksTls / Ws / Wss / WebtunnelWss already have their
        // own proxy paths or aren't routable through a SOCKS hop.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(host: &str, port: u16) -> TransportUri {
        TransportUri::Tcp {
            host: host.to_owned(),
            port,
        }
    }

    fn obfs4(host: &str, port: u16) -> TransportUri {
        TransportUri::Obfs4Tcp {
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn parse_socks5_uri_form() {
        let parsed = parse_proxy_endpoint("socks5://127.0.0.1:9050");
        assert_eq!(parsed, Some(("127.0.0.1".to_owned(), 9050)));
    }

    #[test]
    fn parse_socks_uri_form() {
        let parsed = parse_proxy_endpoint("socks://proxy.example.com:1080");
        assert_eq!(parsed, Some(("proxy.example.com".to_owned(), 1080)));
    }

    #[test]
    fn parse_bare_host_port_form() {
        let parsed = parse_proxy_endpoint("127.0.0.1:9050");
        assert_eq!(parsed, Some(("127.0.0.1".to_owned(), 9050)));
    }

    #[test]
    fn parse_strips_trailing_target() {
        // Operator pasted a full SOCKS URI by accident — handle gracefully.
        let parsed = parse_proxy_endpoint("socks://127.0.0.1:9050/target:5556");
        assert_eq!(parsed, Some(("127.0.0.1".to_owned(), 9050)));
    }

    #[test]
    fn parse_rejects_missing_port() {
        assert_eq!(parse_proxy_endpoint("127.0.0.1"), None);
        assert_eq!(parse_proxy_endpoint("socks5://127.0.0.1"), None);
    }

    #[test]
    fn parse_rejects_zero_port() {
        // Port 0 is "kernel-assigned" — meaningless for a proxy.
        assert_eq!(parse_proxy_endpoint("127.0.0.1:0"), None);
    }

    #[test]
    fn parse_rejects_bad_port() {
        assert_eq!(parse_proxy_endpoint("127.0.0.1:notaport"), None);
        assert_eq!(parse_proxy_endpoint("127.0.0.1:99999"), None);
    }

    #[test]
    fn compose_tcp_target() {
        let proxy = "socks5://127.0.0.1:9050";
        let primary = tcp("peer.example", 5556);
        let composed = compose_socks_fallback(proxy, &primary);
        assert_eq!(
            composed,
            Some((
                "127.0.0.1".to_owned(),
                9050,
                "peer.example".to_owned(),
                5556
            )),
        );
    }

    #[test]
    fn compose_obfs4_tcp_target() {
        // obfs4-tcp is a TCP-shaped transport — SOCKS5 should tunnel
        // it transparently (SOCKS layer doesn't touch payload).
        let proxy = "socks5://127.0.0.1:9050";
        let primary = obfs4("peer.example", 5556);
        let composed = compose_socks_fallback(proxy, &primary);
        assert_eq!(
            composed,
            Some((
                "127.0.0.1".to_owned(),
                9050,
                "peer.example".to_owned(),
                5556
            )),
        );
    }

    #[test]
    fn compose_rejects_quic_target() {
        // QUIC is UDP-based; SOCKS5 can only carry TCP.
        let proxy = "socks5://127.0.0.1:9050";
        let primary = TransportUri::Quic {
            host: "peer.example".to_owned(),
            port: 5556,
            sni: None,
            alpn: vec![],
        };
        assert_eq!(compose_socks_fallback(proxy, &primary), None);
    }

    #[test]
    fn compose_rejects_unix_target() {
        let proxy = "socks5://127.0.0.1:9050";
        let primary = TransportUri::Unix {
            path: std::path::PathBuf::from("/tmp/sock"),
        };
        assert_eq!(compose_socks_fallback(proxy, &primary), None);
    }

    #[test]
    fn compose_rejects_bad_proxy() {
        let proxy = "not-a-proxy";
        let primary = tcp("peer.example", 5556);
        assert_eq!(compose_socks_fallback(proxy, &primary), None);
    }
}
