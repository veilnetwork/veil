use std::{fmt, path::PathBuf, str::FromStr};

use url::Url;

use super::error::{Result, TransportError};

/// Wrapping protocol layered on top of a base transport (TLS, SOCKS, WS).
#[allow(missing_docs)] // Variant names are self-describing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wrapper {
    Tls,
    Socks,
    WebSocket,
    /// obfs4-style anti-DPI handshake + framing (NTOR + AEAD).
    Obfs4,
    /// Webtunnel: HTTP routing + WebSocket upgrade with secret-path
    /// activation, decoy content on miss.
    Webtunnel,
}

/// Stack description for a transport URI — the base layer plus zero or more
/// wrappers. Derived [`TransportUri`] by [`TransportUri::stack`].
#[allow(missing_docs)] // Variant names describe well-known layer stacks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportStack {
    Tcp,
    Unix,
    Quic,
    /// Recursive wrapping: `wrapper` on top of `lower`.
    Wrapped {
        lower: Box<TransportStack>,
        wrapper: Wrapper,
    },
}

/// Strongly-typed transport URI (`tcp://`, `tls://`, `quic://`, `unix://`
/// `socks://`, `sockstls://`, `ws://`, `wss://`). Produced by
/// [`TransportUri::parse`]; every variant carries the fields its scheme
/// actually uses (so that optionals are explicit in the type).
#[allow(missing_docs)] // Fields of wire-format URI variants are self-documenting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportUri {
    Tcp {
        host: String,
        port: u16,
    },
    Tls {
        host: String,
        port: u16,
        sni: Option<String>,
        alpn: Vec<Vec<u8>>,
    },
    Quic {
        host: String,
        port: u16,
        sni: Option<String>,
        alpn: Vec<Vec<u8>>,
    },
    Unix {
        path: PathBuf,
    },
    Socks {
        proxy_host: String,
        proxy_port: u16,
        target_host: String,
        target_port: u16,
    },
    SocksTls {
        proxy_host: String,
        proxy_port: u16,
        target_host: String,
        target_port: u16,
        sni: Option<String>,
        alpn: Vec<Vec<u8>>,
    },
    Ws {
        host: String,
        port: u16,
        path: String,
        query: Option<String>,
    },
    Wss {
        host: String,
        port: u16,
        path: String,
        query: Option<String>,
        sni: Option<String>,
        alpn: Vec<Vec<u8>>,
    },
    /// TCP wrapped with obfs4-style anti-DPI handshake + framing.
    /// PSK is supplied separately (TransportContext field) — embedding
    /// it in the URI would leak it through logs / hint publishes.
    Obfs4Tcp {
        host: String,
        port: u16,
    },
    /// Webtunnel-over-WSS: TLS-encrypted WebSocket tunnel that looks like
    /// a regular HTTPS site to an active prober.  Decoy content served
    /// on bad credentials; tunnel mode activated with secret path + auth
    /// header (sourced from TransportContext.webtunnel_*).
    WebtunnelWss {
        host: String,
        port: u16,
        sni: Option<String>,
    },
}

impl TransportUri {
    /// Parse a URI string into the strongly-typed variant. Returns
    /// [`TransportError::InvalidUri`] on malformed input.
    pub fn parse(value: &str) -> Result<Self> {
        value.parse()
    }

    /// Short scheme string used by [`super::TransportRegistry`] to look up a
    /// concrete transport implementation.
    pub fn scheme(&self) -> &'static str {
        match self {
            Self::Tcp { .. } => "tcp",
            Self::Tls { .. } => "tls",
            Self::Quic { .. } => "quic",
            Self::Unix { .. } => "unix",
            Self::Socks { .. } => "socks",
            Self::SocksTls { .. } => "sockstls",
            Self::Ws { .. } => "ws",
            Self::Wss { .. } => "wss",
            Self::Obfs4Tcp { .. } => "obfs4-tcp",
            Self::WebtunnelWss { .. } => "webtunnel-wss",
        }
    }

    /// Returns the host string for any host-bearing variant, regardless
    /// of encryption status.  Differs from [`plaintext_host`] (which only
    /// returns hosts visible on the wire to DPI for warning purposes).
    /// `None` for `unix`.
    pub fn host(&self) -> Option<&str> {
        match self {
            Self::Tcp { host, .. }
            | Self::Tls { host, .. }
            | Self::Quic { host, .. }
            | Self::Ws { host, .. }
            | Self::Wss { host, .. }
            | Self::Obfs4Tcp { host, .. }
            | Self::WebtunnelWss { host, .. } => Some(host.as_str()),
            Self::Socks { target_host, .. } | Self::SocksTls { target_host, .. } => {
                Some(target_host.as_str())
            }
            Self::Unix { .. } => None,
        }
    }

    /// Returns the plaintext host for `tcp`/`ws`/`socks` schemes, `None` for
    /// TLS-encrypted schemes (where traffic is not DPI-readable) or `unix`
    /// (where socket permissions, not encryption, are the security model).
    ///
    /// Used by to warn operators when they bind or connect to a
    /// plaintext endpoint on a non-localhost address — DPI on the wire can
    /// read OVL1 frames and fingerprint the protocol.
    pub fn plaintext_host(&self) -> Option<&str> {
        match self {
            Self::Tcp { host, .. } | Self::Ws { host, .. } => Some(host.as_str()),
            // Socks tunnels TCP through a proxy — the hop from proxy to target
            // is plaintext regardless of how we reach the proxy.
            Self::Socks { target_host, .. } => Some(target_host.as_str()),
            // Obfs4Tcp wraps plaintext TCP with AEAD framing — wire bytes
            // are statistically random, so DPI cannot read OVL1.
            // `None` matches the encrypted-transport classification.
            Self::Obfs4Tcp { .. } => None,
            // WebtunnelWss is TLS-encrypted — no plaintext on wire.
            Self::WebtunnelWss { .. } => None,
            Self::Tls { .. }
            | Self::Quic { .. }
            | Self::Wss { .. }
            | Self::SocksTls { .. }
            | Self::Unix { .. } => None,
        }
    }

    /// `true` when the host looks like a loopback address (`127.0.0.0/8`, `::1`)
    /// or the literal string `localhost`. Used to suppress the plaintext warning
    /// for local-only listeners/connects. `0.0.0.0` and `[::]` are NOT localhost
    /// — they bind on every interface, exposing plaintext on public ones.
    pub fn host_is_localhost(host: &str) -> bool {
        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
            return v4.is_loopback();
        }
        if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
            return v6.is_loopback();
        }
        false
    }

    /// Return a [`TransportStack`] describing the base transport and any
    /// wrappers layered on top, derived from this URI variant.
    pub fn stack(&self) -> TransportStack {
        match self {
            Self::Tcp { .. } => TransportStack::Tcp,
            Self::Unix { .. } => TransportStack::Unix,
            Self::Quic { .. } => TransportStack::Quic,
            Self::Obfs4Tcp { .. } => TransportStack::Wrapped {
                lower: Box::new(TransportStack::Tcp),
                wrapper: Wrapper::Obfs4,
            },
            Self::WebtunnelWss { .. } => TransportStack::Wrapped {
                lower: Box::new(TransportStack::Wrapped {
                    lower: Box::new(TransportStack::Wrapped {
                        lower: Box::new(TransportStack::Tcp),
                        wrapper: Wrapper::Tls,
                    }),
                    wrapper: Wrapper::WebSocket,
                }),
                wrapper: Wrapper::Webtunnel,
            },
            Self::Tls { .. } => TransportStack::Wrapped {
                lower: Box::new(TransportStack::Tcp),
                wrapper: Wrapper::Tls,
            },
            Self::Socks { .. } => TransportStack::Wrapped {
                lower: Box::new(TransportStack::Tcp),
                wrapper: Wrapper::Socks,
            },
            Self::SocksTls { .. } => TransportStack::Wrapped {
                lower: Box::new(TransportStack::Wrapped {
                    lower: Box::new(TransportStack::Tcp),
                    wrapper: Wrapper::Socks,
                }),
                wrapper: Wrapper::Tls,
            },
            Self::Ws { .. } => TransportStack::Wrapped {
                lower: Box::new(TransportStack::Tcp),
                wrapper: Wrapper::WebSocket,
            },
            Self::Wss { .. } => TransportStack::Wrapped {
                lower: Box::new(TransportStack::Wrapped {
                    lower: Box::new(TransportStack::Tcp),
                    wrapper: Wrapper::Tls,
                }),
                wrapper: Wrapper::WebSocket,
            },
        }
    }

    /// produce a new URI with the same transport stack
    /// (scheme + SNI + ALPN) as `self` but `host`/`port` replaced by the
    /// supplied values. Used by the NAT-traversal fallback path to
    /// promote a `NatCandidate` (raw IP+port pair learned via signaling)
    /// into a connectable URI that uses the SAME crypto envelope the
    /// caller's known-stale template URI was configured with — SNI must
    /// stay pinned to the peer's identity, not get overwritten by the
    /// candidate's IP literal, otherwise TLS fails the cert match on
    /// every fallback attempt.
    ///
    /// Returns `None` for variants where NAT-traversal is not meaningful:
    /// * `Unix` — local IPC, no IP at all.
    /// * `Socks` / `SocksTls` — already proxy-tunnelled, the proxy
    ///   itself does the routing. Substituting the candidate as a new
    ///   proxy is wrong; substituting it as a new target loses the
    ///   proxy guarantee. Either way: caller's intent is unclear, so
    ///   fall back to "not supported".
    /// * `Ws` / `Wss` — the `path` + `query` carry app-level routing
    ///   that the candidate's bare IP doesn't preserve.
    ///
    /// `Tcp`, `Tls`, and `Quic` are the supported cases — these are
    /// also the schemes the production stack actually uses for peer-to-
    /// peer veil sessions.
    pub fn with_host_port(&self, new_host: String, new_port: u16) -> Option<Self> {
        match self {
            Self::Tcp { .. } => Some(Self::Tcp {
                host: new_host,
                port: new_port,
            }),
            Self::Tls { sni, alpn, .. } => Some(Self::Tls {
                host: new_host,
                port: new_port,
                sni: sni.clone(),
                alpn: alpn.clone(),
            }),
            Self::Quic { sni, alpn, .. } => Some(Self::Quic {
                host: new_host,
                port: new_port,
                sni: sni.clone(),
                alpn: alpn.clone(),
            }),
            Self::Obfs4Tcp { .. } => Some(Self::Obfs4Tcp {
                host: new_host,
                port: new_port,
            }),
            Self::WebtunnelWss { sni, .. } => Some(Self::WebtunnelWss {
                host: new_host,
                port: new_port,
                sni: sni.clone(),
            }),
            Self::Unix { .. }
            | Self::Socks { .. }
            | Self::SocksTls { .. }
            | Self::Ws { .. }
            | Self::Wss { .. } => None,
        }
    }
}

impl FromStr for TransportUri {
    type Err = TransportError;

    fn from_str(value: &str) -> Result<Self> {
        let url = Url::parse(value).map_err(|err| TransportError::InvalidUri(err.to_string()))?;
        match url.scheme() {
            "tcp" => Ok(Self::Tcp {
                host: host(&url)?,
                port: port(&url)?,
            }),
            "tls" => Ok(Self::Tls {
                host: host(&url)?,
                port: port(&url)?,
                sni: sni(&url),
                alpn: alpn(&url),
            }),
            "quic" => Ok(Self::Quic {
                host: host(&url)?,
                port: port(&url)?,
                sni: sni(&url),
                alpn: alpn(&url),
            }),
            "unix" => Ok(Self::Unix {
                path: PathBuf::from(url.path()),
            }),
            "socks" => {
                let (target_host, target_port) = parse_target_path(url.path())?;
                Ok(Self::Socks {
                    proxy_host: host(&url)?,
                    proxy_port: port(&url)?,
                    target_host,
                    target_port,
                })
            }
            "sockstls" => {
                let (target_host, target_port) = parse_target_path(url.path())?;
                Ok(Self::SocksTls {
                    proxy_host: host(&url)?,
                    proxy_port: port(&url)?,
                    target_host: target_host.clone(),
                    target_port,
                    sni: sni(&url).or(Some(target_host)),
                    alpn: alpn(&url),
                })
            }
            "ws" => Ok(Self::Ws {
                host: host(&url)?,
                port: port(&url)?,
                path: ws_path(&url),
                query: url.query().map(str::to_owned),
            }),
            "wss" => Ok(Self::Wss {
                host: host(&url)?,
                port: port(&url)?,
                path: ws_path(&url),
                query: url.query().map(str::to_owned),
                sni: sni(&url),
                alpn: alpn(&url),
            }),
            "obfs4-tcp" => Ok(Self::Obfs4Tcp {
                host: host(&url)?,
                port: port(&url)?,
            }),
            "webtunnel-wss" => Ok(Self::WebtunnelWss {
                host: host(&url)?,
                port: port(&url)?,
                sni: sni(&url),
            }),
            scheme => Err(TransportError::Unsupported(format!(
                "scheme `{scheme}` is not registered"
            ))),
        }
    }
}

fn host(url: &Url) -> Result<String> {
    url.host_str()
        .map(|h| {
            // The `url` crate wraps IPv6 addresses in brackets in `host_str`
            // (e.g. `[::1]`). Strip them so our internal representation is
            // always bracket-free; `fmt_host` re-adds them on `Display`.
            if h.starts_with('[') && h.ends_with(']') {
                h[1..h.len() - 1].to_owned()
            } else {
                h.to_owned()
            }
        })
        .ok_or_else(|| TransportError::InvalidUri("missing host".to_owned()))
}

fn port(url: &Url) -> Result<u16> {
    url.port()
        .ok_or_else(|| TransportError::InvalidUri("missing port".to_owned()))
}

fn sni(url: &Url) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == "sni")
        .map(|(_, value)| value.into_owned())
}

fn alpn(url: &Url) -> Vec<Vec<u8>> {
    url.query_pairs()
        .filter(|(key, _)| key == "alpn")
        .map(|(_, value)| value.as_bytes().to_vec())
        .collect()
}

fn parse_target_path(path: &str) -> Result<(String, u16)> {
    let trimmed = path.trim_start_matches('/');
    let (host, port) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| TransportError::InvalidUri("SOCKS target must be /host:port".to_owned()))?;
    let port = port
        .parse::<u16>()
        .map_err(|err| TransportError::InvalidUri(err.to_string()))?;
    Ok((host.to_owned(), port))
}

fn ws_path(url: &Url) -> String {
    let path = url.path();
    if path.is_empty() {
        "/".to_owned()
    } else {
        path.to_owned()
    }
}

impl fmt::Display for TransportUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp { host, port } => write!(f, "tcp://{}:{port}", fmt_host(host)),
            Self::Tls { host, port, .. } => write!(f, "tls://{}:{port}", fmt_host(host)),
            Self::Quic { host, port, .. } => write!(f, "quic://{}:{port}", fmt_host(host)),
            Self::Unix { path } => write!(f, "unix://{}", path.display()),
            Self::Socks {
                proxy_host,
                proxy_port,
                target_host,
                target_port,
            } => write!(
                f,
                "socks://{}:{proxy_port}/{}:{target_port}",
                fmt_host(proxy_host),
                fmt_host(target_host),
            ),
            Self::SocksTls {
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                ..
            } => write!(
                f,
                "sockstls://{}:{proxy_port}/{}:{target_port}",
                fmt_host(proxy_host),
                fmt_host(target_host),
            ),
            Self::Ws {
                host,
                port,
                path,
                query,
            } => write!(
                f,
                "ws://{}:{port}{}{}",
                fmt_host(host),
                path,
                fmt_query(query)
            ),
            Self::Wss {
                host,
                port,
                path,
                query,
                ..
            } => write!(
                f,
                "wss://{}:{port}{}{}",
                fmt_host(host),
                path,
                fmt_query(query)
            ),
            Self::Obfs4Tcp { host, port } => write!(f, "obfs4-tcp://{}:{port}", fmt_host(host)),
            Self::WebtunnelWss { host, port, .. } => {
                write!(f, "webtunnel-wss://{}:{port}", fmt_host(host))
            }
        }
    }
}

// ── rewrite_wildcard_host ──────────────────────────────────────────────────────

/// Replace the host in a listen transport URI if it is a wildcard address.
///
/// Returns `Some(new_uri_string)` when the URI's host was `0.0.0.0` (IPv4
/// unspecified) or `::` (IPv6 unspecified), with the host replaced by `new_ip`.
/// Returns `None` when the host is already specific (non-wildcard) or the URI
/// has no host component (e.g. `unix://`).
///
/// This is used by [`FrameDispatcher`] to rewrite advertised listen transports
/// once the node learns its external IP via a `NatProbeReply` from a core peer.
pub fn rewrite_wildcard_host(uri: &str, new_ip: std::net::IpAddr) -> Option<String> {
    let parsed = TransportUri::parse(uri).ok()?;
    let new_host = new_ip.to_string();
    let rewritten = match parsed {
        TransportUri::Tcp { ref host, port } if is_wildcard_host(host) => TransportUri::Tcp {
            host: new_host,
            port,
        },
        TransportUri::Tls {
            ref host,
            port,
            sni,
            alpn,
        } if is_wildcard_host(host) => TransportUri::Tls {
            host: new_host,
            port,
            sni,
            alpn,
        },
        TransportUri::Quic {
            ref host,
            port,
            sni,
            alpn,
        } if is_wildcard_host(host) => TransportUri::Quic {
            host: new_host,
            port,
            sni,
            alpn,
        },
        TransportUri::Ws {
            ref host,
            port,
            path,
            query,
        } if is_wildcard_host(host) => TransportUri::Ws {
            host: new_host,
            port,
            path,
            query,
        },
        TransportUri::Wss {
            ref host,
            port,
            path,
            query,
            sni,
            alpn,
        } if is_wildcard_host(host) => TransportUri::Wss {
            host: new_host,
            port,
            path,
            query,
            sni,
            alpn,
        },
        TransportUri::Obfs4Tcp { ref host, port } if is_wildcard_host(host) => {
            TransportUri::Obfs4Tcp {
                host: new_host,
                port,
            }
        }
        TransportUri::WebtunnelWss {
            ref host,
            port,
            sni,
        } if is_wildcard_host(host) => TransportUri::WebtunnelWss {
            host: new_host,
            port,
            sni,
        },
        _ => return None,
    };
    Some(rewritten.to_string())
}

/// Format a host string for use in a URI.
///
/// IPv6 addresses (those containing `:`) must be wrapped in brackets per
/// RFC 3986 §3.2.2 — e.g. `::1` becomes `[::1]` so the URI reads `tcp://[::1]:7001`.
/// IPv4 addresses and hostnames are passed through unchanged.
fn fmt_host(host: &str) -> std::borrow::Cow<'_, str> {
    if host.contains(':') {
        std::borrow::Cow::Owned(format!("[{host}]"))
    } else {
        std::borrow::Cow::Borrowed(host)
    }
}

/// Returns `true` when `host` is an unspecified (wildcard) address.
///
/// Matches both the IPv4 wildcard (`0.0.0.0`) and the IPv6 wildcard (`::`)
/// so that callers can rewrite either to a specific external address.
fn is_wildcard_host(host: &str) -> bool {
    host == "0.0.0.0" || host == "::"
}

fn fmt_query(query: &Option<String>) -> String {
    query
        .as_ref()
        .map(|query| format!("?{query}"))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::TransportUri;
    use std::path::PathBuf;

    #[test]
    fn parses_tcp_uri() {
        let uri = TransportUri::parse("tcp://127.0.0.1:9001").expect("tcp uri parses");
        assert!(matches!(
            uri,
            TransportUri::Tcp { host, port } if host == "127.0.0.1" && port == 9001
        ));
    }

    #[test]
    fn parses_socks_tls_uri() {
        let uri = TransportUri::parse("sockstls://2.2.2.2:2345/1.1.1.1:1234")
            .expect("sockstls uri parses");
        assert!(matches!(
            uri,
            TransportUri::SocksTls {
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                ..
            } if proxy_host == "2.2.2.2"
                && proxy_port == 2345
                && target_host == "1.1.1.1"
                && target_port == 1234
        ));
    }

    #[test]
    fn parses_ws_uri() {
        let uri = TransportUri::parse("ws://127.0.0.1:8080/veil?mode=test").expect("ws uri parses");
        assert!(matches!(
            uri,
            TransportUri::Ws { host, port, path, query }
                if host == "127.0.0.1"
                    && port == 8080
                    && path == "/veil"
                    && query.as_deref() == Some("mode=test")
        ));
    }

    #[test]
    fn rewrite_wildcard_host_tcp_ipv4() {
        use super::rewrite_wildcard_host;
        use std::net::IpAddr;
        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        let result = rewrite_wildcard_host("tcp://0.0.0.0:7001", ip);
        assert_eq!(result, Some("tcp://203.0.113.42:7001".to_string()));
    }

    #[test]
    fn rewrite_wildcard_host_ipv6_wildcard_rewrites_correctly() {
        use super::rewrite_wildcard_host;
        use std::net::IpAddr;
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        // IPv6 wildcard `[::]` is now rewritten; Display brackets the address correctly.
        let result = rewrite_wildcard_host("tcp://[::]:7001", ip);
        assert_eq!(result, Some("tcp://[2001:db8::1]:7001".to_string()));
    }

    #[test]
    fn display_ipv6_address_is_bracketed() {
        use super::TransportUri;
        let uri = TransportUri::Tcp {
            host: "::1".to_string(),
            port: 7001,
        };
        assert_eq!(uri.to_string(), "tcp://[::1]:7001");
        let uri6 = TransportUri::Tcp {
            host: "2001:db8::1".to_string(),
            port: 443,
        };
        assert_eq!(uri6.to_string(), "tcp://[2001:db8::1]:443");
    }

    #[test]
    fn rewrite_wildcard_host_no_rewrite_for_specific_ip() {
        use super::rewrite_wildcard_host;
        use std::net::IpAddr;
        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        // Already has a specific host — should return None
        let result = rewrite_wildcard_host("tcp://192.168.1.5:7001", ip);
        assert!(result.is_none());
    }

    #[test]
    fn rewrite_wildcard_host_unix_returns_none() {
        use super::rewrite_wildcard_host;
        use std::net::IpAddr;
        let ip: IpAddr = "203.0.113.42".parse().unwrap();
        let result = rewrite_wildcard_host("unix:///tmp/veil.sock", ip);
        assert!(result.is_none());
    }

    // ── plaintext-scheme audit helpers ─────────────────────────

    #[test]
    fn plaintext_host_flags_tcp_ws_socks() {
        let tcp = TransportUri::parse("tcp://203.0.113.5:9000").unwrap();
        assert_eq!(tcp.plaintext_host(), Some("203.0.113.5"));

        let ws = TransportUri::parse("ws://example.com:8080/veil").unwrap();
        assert_eq!(ws.plaintext_host(), Some("example.com"));

        let socks = TransportUri::parse("socks://proxy:1080/target:9001").unwrap();
        // The target hop is plaintext regardless of how we reach the proxy.
        assert_eq!(socks.plaintext_host(), Some("target"));
    }

    #[test]
    fn plaintext_host_none_for_encrypted_and_unix() {
        let tls = TransportUri::parse("tls://node.example.com:9443").unwrap();
        assert_eq!(tls.plaintext_host(), None);

        let quic = TransportUri::parse("quic://node.example.com:9443").unwrap();
        assert_eq!(quic.plaintext_host(), None);

        let wss = TransportUri::parse("wss://node.example.com:8443/veil").unwrap();
        assert_eq!(wss.plaintext_host(), None);

        let unix = TransportUri::parse("unix:///tmp/veil.sock").unwrap();
        assert_eq!(unix.plaintext_host(), None);
    }

    /// Regression: `host()` returns the host regardless of wire-level
    /// encryption.  Caught at the live PoW-Rendezvous canary deploy on
    /// node1 — the wire-up code was mistakenly using `plaintext_host`
    /// for extracting bind/advertise hosts from obfs4-tcp listeners,
    /// which returns None.
    #[test]
    fn host_returns_for_all_host_bearing_schemes() {
        let obfs4 = TransportUri::parse("obfs4-tcp://203.0.113.5:9000").unwrap();
        assert_eq!(obfs4.host(), Some("203.0.113.5"));
        assert_eq!(obfs4.plaintext_host(), None); // contrast — DPI-visibility

        let tls = TransportUri::parse("tls://node.example.com:9443").unwrap();
        assert_eq!(tls.host(), Some("node.example.com"));
        assert_eq!(tls.plaintext_host(), None);

        let wtss = TransportUri::parse("webtunnel-wss://node.example.com:8443/secret/foo").unwrap();
        assert_eq!(wtss.host(), Some("node.example.com"));

        let socks =
            TransportUri::parse("socks://proxy.example.com:1080/target.example:9001").unwrap();
        assert_eq!(socks.host(), Some("target.example"));

        let unix = TransportUri::parse("unix:///tmp/veil.sock").unwrap();
        assert_eq!(unix.host(), None);
    }

    #[test]
    fn host_is_localhost_matches_loopback() {
        assert!(TransportUri::host_is_localhost("localhost"));
        assert!(TransportUri::host_is_localhost("LOCALHOST"));
        assert!(TransportUri::host_is_localhost("127.0.0.1"));
        assert!(TransportUri::host_is_localhost("127.1.2.3")); // entire /8 is loopback
        assert!(TransportUri::host_is_localhost("::1"));

        // Wildcard / any — NOT localhost; binds on every interface including public.
        assert!(!TransportUri::host_is_localhost("0.0.0.0"));
        assert!(!TransportUri::host_is_localhost("::"));
        assert!(!TransportUri::host_is_localhost("203.0.113.5"));
        assert!(!TransportUri::host_is_localhost("example.com"));
    }

    #[test]
    fn with_host_port_tcp_replaces_endpoint_only() {
        let stale = TransportUri::Tcp {
            host: "stale.example".into(),
            port: 5000,
        };
        let promoted = stale.with_host_port("192.168.1.10".into(), 7000).unwrap();
        assert_eq!(
            promoted,
            TransportUri::Tcp {
                host: "192.168.1.10".into(),
                port: 7000
            }
        );
    }

    #[test]
    fn with_host_port_tls_preserves_sni_and_alpn() {
        // The whole point of preserving SNI: an IP-literal candidate must
        // still present the peer's identity-pinned name to TLS, otherwise
        // cert verification fails on every fallback dial.
        let stale = TransportUri::Tls {
            host: "stale.example".into(),
            port: 5000,
            sni: Some("peer-identity.example".into()),
            alpn: vec![b"ovl1".to_vec()],
        };
        let promoted = stale.with_host_port("192.168.1.10".into(), 7000).unwrap();
        assert_eq!(
            promoted,
            TransportUri::Tls {
                host: "192.168.1.10".into(),
                port: 7000,
                sni: Some("peer-identity.example".into()),
                alpn: vec![b"ovl1".to_vec()],
            }
        );
    }

    #[test]
    fn with_host_port_quic_preserves_sni_and_alpn() {
        let stale = TransportUri::Quic {
            host: "stale.example".into(),
            port: 5000,
            sni: Some("peer-identity.example".into()),
            alpn: vec![b"ovl1".to_vec()],
        };
        let promoted = stale.with_host_port("[2001:db8::1]".into(), 7000).unwrap();
        assert_eq!(
            promoted,
            TransportUri::Quic {
                host: "[2001:db8::1]".into(),
                port: 7000,
                sni: Some("peer-identity.example".into()),
                alpn: vec![b"ovl1".to_vec()],
            }
        );
    }

    #[test]
    fn with_host_port_returns_none_for_unsupported_variants() {
        // Unix has no IP — substituting host:port is meaningless.
        let unix = TransportUri::Unix {
            path: PathBuf::from("/tmp/sock"),
        };
        assert!(unix.with_host_port("1.2.3.4".into(), 5000).is_none());

        // Socks: substituting candidate as proxy is wrong; as target loses
        // the proxy guarantee. Caller intent unclear → not supported.
        let socks = TransportUri::Socks {
            proxy_host: "proxy".into(),
            proxy_port: 1080,
            target_host: "target".into(),
            target_port: 443,
        };
        assert!(socks.with_host_port("1.2.3.4".into(), 5000).is_none());

        // Ws/Wss carry app-level path+query that bare IP doesn't preserve.
        let ws = TransportUri::Ws {
            host: "host".into(),
            port: 80,
            path: "/api".into(),
            query: None,
        };
        assert!(ws.with_host_port("1.2.3.4".into(), 5000).is_none());
    }
}
