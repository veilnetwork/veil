use std::sync::Arc;

use futures::future::BoxFuture;
use tokio_socks::tcp::Socks5Stream;

use super::{
    TransportContext,
    error::{Result, TransportError},
    tcp::{boxed_stream_connection, peer_meta},
    traits::{Transport, TransportCapabilities, TransportConnection, TransportListener},
    uri::TransportUri,
};

// route `sockstls://` through the same TLS backend as `tls://`
// (BoringSSL when `tls-boring` is enabled, rustls otherwise) so the JA3
// fingerprint is consistent across every TLS-bearing transport.
// TLS over an already-established SOCKS tunnel. Both backends expose a 5-arg
// `(stream, host, sni, alpn, ctx)` entry: rustls has no fingerprint to morph,
// and the tls-boring `connect_tls_stream_proxied` applies the fingerprint
// policy's *preferred* profile without rotation (the SOCKS tunnel is already
// up; re-dialing per fingerprint is the proxy layer's concern).
#[cfg(not(feature = "tls-boring"))]
use super::tls::connect_tls_stream as connect_tls_over_socks;
#[cfg(feature = "tls-boring")]
use super::tls_boring::connect_tls_stream_proxied as connect_tls_over_socks;

/// `Transport` that dials the peer through a SOCKS5 proxy (e.g. Tor/ssh).
/// Plaintext after the proxy handshake — pair with `SocksTlsTransport` for
/// confidentiality.
#[derive(Debug, Default)]
pub struct SocksTransport;

/// Same as `SocksTransport` but terminates a TLS session on top of the SOCKS
/// tunnel, so the proxy operator sees only encrypted bytes.
#[derive(Debug, Default)]
pub struct SocksTlsTransport;

enum SocksConnectParts<'a> {
    Plain {
        proxy_host: &'a str,
        proxy_port: u16,
        target_host: &'a str,
        target_port: u16,
    },
    Tls {
        proxy_host: &'a str,
        proxy_port: u16,
        target_host: &'a str,
        target_port: u16,
        sni: Option<&'a str>,
        alpn: &'a [Vec<u8>],
    },
}

fn socks_connect_parts<'a>(uri: &'a TransportUri) -> Result<SocksConnectParts<'a>> {
    match uri {
        TransportUri::Socks {
            proxy_host,
            proxy_port,
            target_host,
            target_port,
        } => Ok(SocksConnectParts::Plain {
            proxy_host: proxy_host.as_str(),
            proxy_port: *proxy_port,
            target_host: target_host.as_str(),
            target_port: *target_port,
        }),
        TransportUri::SocksTls {
            proxy_host,
            proxy_port,
            target_host,
            target_port,
            sni,
            alpn,
        } => Ok(SocksConnectParts::Tls {
            proxy_host: proxy_host.as_str(),
            proxy_port: *proxy_port,
            target_host: target_host.as_str(),
            target_port: *target_port,
            sni: sni.as_deref(),
            alpn: alpn.as_slice(),
        }),
        _ => Err(TransportError::Unsupported(format!(
            "socks transport cannot handle `{}`",
            uri.scheme()
        ))),
    }
}

async fn connect_socks_stream(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
) -> Result<tokio::net::TcpStream> {
    Ok(
        Socks5Stream::connect((proxy_host, proxy_port), (target_host, target_port))
            .await?
            .into_inner(),
    )
}

/// Parse a SOCKS5 proxy endpoint URL into `(host, port)`.
///
/// Accepts `socks5://host:port`, `socks5h://host:port`, `socks://host:port`,
/// or a bare `host:port`.  The `5h` variant is accepted for operator
/// familiarity but is semantically identical here — see
/// [`connect_socks5_stream`] (we always defer name resolution to the proxy).
/// Bracketed IPv6 literals (`[::1]:9050`) are not parsed; a Tor SOCKS endpoint
/// is virtually always `127.0.0.1:9050` / `localhost:9050`.
///
/// Canonical single parser (audit U13): also tolerates a trailing `/path`
/// component (an operator who pasted a full URI) and rejects port 0, so the
/// runtime's peer-dial SOCKS fallback can delegate here instead of keeping a
/// second, divergent copy.
pub fn parse_socks_proxy_url(proxy_url: &str) -> Result<(String, u16)> {
    let rest = proxy_url
        .strip_prefix("socks5h://")
        .or_else(|| proxy_url.strip_prefix("socks5://"))
        .or_else(|| proxy_url.strip_prefix("socks://"))
        .unwrap_or(proxy_url);
    // Drop any trailing `/path` (e.g. a pasted `socks5://host:port/target`).
    let endpoint = rest.split('/').next().unwrap_or(rest);
    let (host, port_str) = endpoint.rsplit_once(':').ok_or_else(|| {
        TransportError::InvalidUri(format!(
            "SOCKS proxy `{proxy_url}` must be `socks5://host:port`"
        ))
    })?;
    if host.is_empty() {
        return Err(TransportError::InvalidUri(format!(
            "SOCKS proxy `{proxy_url}` has an empty host"
        )));
    }
    let port: u16 = port_str.parse().map_err(|_| {
        TransportError::InvalidUri(format!(
            "SOCKS proxy `{proxy_url}` has an invalid port `{port_str}`"
        ))
    })?;
    if port == 0 {
        return Err(TransportError::InvalidUri(format!(
            "SOCKS proxy `{proxy_url}` port must be non-zero"
        )));
    }
    Ok((host.to_owned(), port))
}

/// Open a raw TCP stream to `target_host:target_port` **through** the SOCKS5
/// proxy at `proxy_url` (`socks5://host:port`, e.g. a local Tor daemon at
/// `socks5://127.0.0.1:9050`).
///
/// The target host is sent to the proxy as a SOCKS5 **domain** address
/// (RFC 1928 ATYP 0x03) and is **not** resolved locally — so `.onion`
/// hostnames are resolved by the proxy (Tor), which is exactly what the
/// bootstrap layer needs to fetch `.onion` seed bundles.  The returned stream
/// is the plaintext tunnel; the caller speaks whatever protocol it likes over
/// it (the bootstrap layer speaks hand-rolled HTTP/1.1, relying on the signed
/// bundle for authenticity rather than TLS).
pub async fn connect_socks5_stream(
    proxy_url: &str,
    target_host: &str,
    target_port: u16,
) -> Result<tokio::net::TcpStream> {
    let (proxy_host, proxy_port) = parse_socks_proxy_url(proxy_url)?;
    connect_socks_stream(&proxy_host, proxy_port, target_host, target_port).await
}

fn unsupported_listen_error(uri: &TransportUri) -> TransportError {
    TransportError::Unsupported(format!("listening is not supported for `{}`", uri.scheme()))
}

impl Transport for SocksTransport {
    fn scheme(&self) -> &'static str {
        "socks"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities::stream_connection()
    }

    fn connect<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            match socks_connect_parts(uri)? {
                SocksConnectParts::Plain {
                    proxy_host,
                    proxy_port,
                    target_host,
                    target_port,
                } => {
                    let stream =
                        connect_socks_stream(proxy_host, proxy_port, target_host, target_port)
                            .await?;
                    let local_addr = stream.local_addr().ok();
                    let remote_addr = stream.peer_addr().ok();
                    let peer = peer_meta("socks", uri.clone(), local_addr, remote_addr);
                    Ok(boxed_stream_connection(peer, stream))
                }
                SocksConnectParts::Tls {
                    proxy_host,
                    proxy_port,
                    target_host,
                    target_port,
                    sni,
                    alpn,
                } => {
                    let stream =
                        connect_socks_stream(proxy_host, proxy_port, target_host, target_port)
                            .await?;
                    let tls_stream =
                        connect_tls_over_socks(stream, target_host, sni, alpn, &ctx).await?;
                    let peer = peer_meta("sockstls", uri.clone(), None, None);
                    Ok(boxed_stream_connection(peer, tls_stream))
                }
            }
        })
    }

    fn bind<'a>(
        &'a self,
        uri: &'a TransportUri,
        _ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>> {
        Box::pin(async move { Err(unsupported_listen_error(uri)) })
    }
}

impl Transport for SocksTlsTransport {
    fn scheme(&self) -> &'static str {
        "sockstls"
    }

    fn capabilities(&self) -> TransportCapabilities {
        SocksTransport.capabilities()
    }

    fn connect<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        SocksTransport.connect(uri, ctx)
    }

    fn bind<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>> {
        SocksTransport.bind(uri, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_socks_proxy_url_accepts_schemes_and_bare() {
        // socks5:// scheme (the documented Tor form).
        assert_eq!(
            parse_socks_proxy_url("socks5://127.0.0.1:9050").unwrap(),
            ("127.0.0.1".to_owned(), 9050)
        );
        // socks5h:// (remote-resolve variant) treated identically.
        assert_eq!(
            parse_socks_proxy_url("socks5h://localhost:9150").unwrap(),
            ("localhost".to_owned(), 9150)
        );
        // socks:// and bare host:port also accepted.
        assert_eq!(
            parse_socks_proxy_url("socks://10.0.0.1:1080").unwrap(),
            ("10.0.0.1".to_owned(), 1080)
        );
        assert_eq!(
            parse_socks_proxy_url("127.0.0.1:9050").unwrap(),
            ("127.0.0.1".to_owned(), 9050)
        );
    }

    #[test]
    fn parse_socks_proxy_url_rejects_malformed() {
        // No port.
        assert!(matches!(
            parse_socks_proxy_url("socks5://127.0.0.1"),
            Err(TransportError::InvalidUri(_))
        ));
        // Empty host.
        assert!(matches!(
            parse_socks_proxy_url("socks5://:9050"),
            Err(TransportError::InvalidUri(_))
        ));
        // Non-numeric port.
        assert!(matches!(
            parse_socks_proxy_url("socks5://127.0.0.1:tor"),
            Err(TransportError::InvalidUri(_))
        ));
        // Out-of-range port.
        assert!(matches!(
            parse_socks_proxy_url("socks5://127.0.0.1:70000"),
            Err(TransportError::InvalidUri(_))
        ));
    }
}
