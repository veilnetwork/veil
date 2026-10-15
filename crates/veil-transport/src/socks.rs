use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::time::timeout;
use tokio_socks::tcp::Socks5Stream;

use super::{
    TransportContext,
    error::{Result, TransportError, connect_timeout},
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

/// Fallback dial timeout when no caller-supplied budget is threaded in (the
/// bare `connect_socks5_stream` entrypoint). Generous because a SOCKS hop
/// through Tor is legitimately slower than a direct TCP connect.
const DEFAULT_SOCKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

async fn connect_socks_stream(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    connect_timeout_duration: Duration,
) -> Result<tokio::net::TcpStream> {
    // Bound the dial: `tokio_socks` otherwise blocks forever if the proxy
    // accepts the TCP connection but never answers the SOCKS handshake (a
    // down/misconfigured/DROP-firewalled local Tor), wedging the peer-dial
    // task. Every sibling transport bounds `connect` the same way, and this
    // path must not rely on an outer caller timeout.
    match timeout(
        connect_timeout_duration,
        Socks5Stream::connect((proxy_host, proxy_port), (target_host, target_port)),
    )
    .await
    {
        Ok(result) => {
            let stream = result?.into_inner();
            // The socket belongs to our proxy connection. Apply the same
            // payload-blind backlog bounds as a direct TCP connection; the
            // proxy still resolves the destination and schedules its own link.
            super::tcp::clamp_downlink_mss(&stream);
            super::tcp::clamp_uplink_sndbuf(&stream);
            Ok(stream)
        }
        Err(_) => Err(connect_timeout(connect_timeout_duration)),
    }
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
    connect_socks_stream(
        &proxy_host,
        proxy_port,
        target_host,
        target_port,
        DEFAULT_SOCKS_CONNECT_TIMEOUT,
    )
    .await
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
                    let stream = connect_socks_stream(
                        proxy_host,
                        proxy_port,
                        target_host,
                        target_port,
                        ctx.tcp.connect_timeout,
                    )
                    .await?;
                    stream.set_nodelay(ctx.tcp.nodelay)?;
                    let local_addr = stream.local_addr().ok();
                    let remote_addr = stream.peer_addr().ok();
                    let peer = peer_meta("socks", uri.clone(), local_addr, remote_addr);
                    Ok(boxed_stream_connection(
                        peer,
                        crate::tcp_write_gate::gate(stream, |tcp| tcp),
                    ))
                }
                SocksConnectParts::Tls {
                    proxy_host,
                    proxy_port,
                    target_host,
                    target_port,
                    sni,
                    alpn,
                } => {
                    let stream = connect_socks_stream(
                        proxy_host,
                        proxy_port,
                        target_host,
                        target_port,
                        ctx.tcp.connect_timeout,
                    )
                    .await?;
                    stream.set_nodelay(ctx.tcp.nodelay)?;
                    let tls_stream =
                        connect_tls_over_socks(stream, target_host, sni, alpn, &ctx).await?;
                    let peer = peer_meta("sockstls", uri.clone(), None, None);
                    Ok(boxed_stream_connection(
                        peer,
                        crate::tcp_write_gate::gate(tls_stream, |tls| {
                            #[cfg(feature = "tls-boring")]
                            {
                                tls.get_ref()
                            }
                            #[cfg(not(feature = "tls-boring"))]
                            {
                                tls.get_ref().0
                            }
                        }),
                    ))
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A real loopback proxy endpoint holds application reads after completing
    // SOCKS (and optionally TLS). Exercise the public transport, not a gate
    // constructed by the test: neither proxied path may bypass write admission.
    async fn verify_proxied_backpressure(tls: bool) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        socket2::SockRef::from(&listener)
            .set_recv_buffer_size(4096)
            .unwrap();
        let address = listener.local_addr().unwrap();
        let ctx = Arc::new(TransportContext::for_debug().unwrap());
        let server_tls = ctx.tls.server_config.clone();
        let (release, wait_for_reads) = tokio::sync::oneshot::channel();
        let proxy = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            socket.write_all(&[5, 0]).await.unwrap();
            let mut header = [0; 5];
            socket.read_exact(&mut header).await.unwrap();
            assert_eq!(&header[..4], &[5, 1, 0, 3]);
            let mut destination = vec![0; header[4] as usize];
            socket.read_exact(&mut destination).await.unwrap();
            assert_eq!(destination, b"peer.invalid");
            let mut port = [0; 2];
            socket.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);
            socket
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                .await
                .unwrap();
            let mut stream: crate::BoxIoStream = if tls {
                Box::new(
                    tokio_rustls::TlsAcceptor::from(server_tls)
                        .accept(socket)
                        .await
                        .unwrap(),
                )
            } else {
                Box::new(socket)
            };
            // Backpressure in the sending direction must not wedge reads in
            // the other direction, including TLS's independent read wakeup.
            stream.write_all(b"receive-alive").await.unwrap();
            stream.flush().await.unwrap();
            wait_for_reads.await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            stream.shutdown().await.unwrap();
            received
        });
        let uri = if tls {
            TransportUri::SocksTls {
                proxy_host: address.ip().to_string(),
                proxy_port: address.port(),
                target_host: "peer.invalid".to_owned(),
                target_port: 443,
                sni: Some("localhost".to_owned()),
                alpn: Vec::new(),
            }
        } else {
            TransportUri::Socks {
                proxy_host: address.ip().to_string(),
                proxy_port: address.port(),
                target_host: "peer.invalid".to_owned(),
                target_port: 443,
            }
        };
        let mut stream = timeout(Duration::from_secs(5), SocksTransport.connect(&uri, ctx))
            .await
            .unwrap()
            .unwrap()
            .into_stream()
            .unwrap();
        let payload: Vec<u8> = (0..512 * 1024).map(|n| (n % 251) as u8).collect();
        // Darwin's gate must cap an oversized application write itself. On
        // other hosts there is no such gate: BoringSSL may wait for the whole
        // supplied write, so asking it for 512 KiB before releasing this fake
        // proxy's reader would deadlock the fixture rather than test duplex I/O.
        #[cfg(target_vendor = "apple")]
        let initial = payload.as_slice();
        #[cfg(not(target_vendor = "apple"))]
        let initial = &payload[..4096];
        let first = timeout(Duration::from_secs(2), stream.write(initial))
            .await
            .expect("initial proxied write stalled before reader release")
            .unwrap();
        assert!(
            first > 0 && first <= 4096,
            "invalid initial proxied write size: {first}"
        );
        let (mut reader, mut writer) = tokio::io::split(stream);
        let remainder = payload[first..].to_vec();
        let mut writing = tokio::spawn(async move {
            writer.write_all(&remainder).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let mut ping = [0; 13];
        timeout(Duration::from_secs(2), reader.read_exact(&mut ping))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ping, b"receive-alive");
        let stalled = timeout(Duration::from_millis(100), &mut writing)
            .await
            .is_err();
        release.send(()).unwrap();
        if stalled {
            timeout(Duration::from_secs(10), writing)
                .await
                .unwrap()
                .unwrap();
        }
        let received = timeout(Duration::from_secs(10), proxy)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            received, payload,
            "backpressure must preserve reliable bytes and EOF"
        );
        assert!(stalled, "fixture did not exercise a blocked proxy reader");
    }

    #[tokio::test]
    async fn socks_write_admission_preserves_data_and_duplex_progress() {
        verify_proxied_backpressure(false).await;
    }

    #[tokio::test]
    async fn socks_tls_write_admission_preserves_data_and_duplex_progress() {
        verify_proxied_backpressure(true).await;
    }

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

    #[tokio::test]
    async fn socks_dial_times_out_against_a_silent_proxy() {
        // A proxy that accepts the TCP connection but never speaks the SOCKS5
        // handshake models a down/DROP-firewalled local Tor. Without the dial
        // timeout the connect blocks forever and wedges the peer-dial task.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        // Hold accepted sockets open and silent for the duration of the test.
        let _accept = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });

        let budget = Duration::from_millis(200);
        let started = std::time::Instant::now();
        let result = connect_socks_stream(
            &proxy_addr.ip().to_string(),
            proxy_addr.port(),
            "example.invalid",
            443,
            budget,
        )
        .await;

        assert!(
            matches!(result, Err(TransportError::ConnectTimeout(_))),
            "silent proxy must surface a connect timeout, got {result:?}"
        );
        // It must return promptly on the bounded budget, not hang.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "dial should time out near the budget, took {:?}",
            started.elapsed()
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
