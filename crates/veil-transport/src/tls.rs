use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream,
    server::TlsStream as ServerTlsStream,
};

use super::{
    TransportContext,
    error::{Result, TransportError, handshake_timeout, tls_error},
    tcp::{StreamConnection, connect_tcp_stream, peer_meta},
    traits::{
        BoxIoStream, RawInbound, Transport, TransportCapabilities, TransportConnection,
        TransportHandshakeMode, TransportListener, native_runtime_info,
    },
    uri::TransportUri,
};

/// Boxed alias for the concrete rustls stream over a TCP socket.
pub type BoxTlsStream = tokio_rustls::TlsStream<TcpStream>;

/// SECURITY (audit 2026-05-29, HIGH listener-DoS fix): hard upper bound on
/// the inline TLS server handshake.  Like the obfs4 listener, the TLS
/// `accept()` future runs the full handshake inline before the runtime
/// accept-loop can take the next connection; a peer that connects-and-
/// stalls mid-handshake would otherwise hang the loop indefinitely.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// TLS `Transport` implementation backed by rustls (default) or BoringSSL
/// when the `tls-boring` feature is enabled.
#[derive(Debug, Default)]
pub struct TlsTransport;

/// default ALPN when the user did not specify `?alpn=...` in the
/// URI. `h2` (HTTP/2) is the most common TLS ALPN on the modern Internet, so
/// advertising it lets OVL1 sessions blend into ordinary HTTPS traffic seen
/// by on-path DPI.
pub(crate) const DEFAULT_ALPN: &[u8] = b"h2";

/// Apply the default ALPN when the caller left the list empty. Returns the
/// caller's list unchanged when they specified one or more protocols — operator
/// intent always wins.
pub(crate) fn effective_alpn(alpn: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if alpn.is_empty() {
        vec![DEFAULT_ALPN.to_vec()]
    } else {
        alpn.to_vec()
    }
}

pub(crate) async fn connect_tls_stream<S>(
    stream: S,
    host: &str,
    sni: Option<&str>,
    alpn: &[Vec<u8>],
    ctx: &TransportContext,
) -> Result<tokio_rustls::client::TlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let server_name = ctx.server_name(ctx.effective_sni(sni, host))?;
    let mut config = (*ctx.tls.client_config).clone();
    config.alpn_protocols = effective_alpn(alpn);
    let connector = TlsConnector::from(Arc::new(config));
    timeout(
        ctx.tcp.connect_timeout,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| handshake_timeout(ctx.tcp.connect_timeout))?
    .map_err(|err| tls_error(err.to_string()))
}

// only used when `tls-boring` feature is OFF — with it on, the
// wss transport routes through `tls_boring::connect_tls_client_stream`.
#[cfg_attr(feature = "tls-boring", allow(dead_code))]
pub async fn connect_tls_client_stream(
    _scheme: &'static str,
    host: &str,
    port: u16,
    sni: Option<&str>,
    alpn: &[Vec<u8>],
    ctx: &TransportContext,
) -> Result<BoxIoStream> {
    let stream = connect_tcp_stream(host, port, ctx).await?;
    let tls_stream: ClientTlsStream<TcpStream> =
        connect_tls_stream(stream, host, sni, alpn, ctx).await?;
    Ok(Box::new(tls_stream))
}

/// TLS handshake against
/// **public Web PKI** (Mozilla's webpki-roots), distinct from
/// [`connect_tls_client_stream`] which uses the operator-supplied
/// veil trust store + node-id binding. Used by the HTTPS
/// bootstrap fetch path (`veil-bootstrap::https`) so an on-path
/// MITM cannot tamper with or replay stale signed seed bundles, and
/// by the signed-update fetch path for similar reasons.
///
/// **Why a separate function:** veil peer transport (`tls://`
/// `wss://`) intentionally uses `set_verify(NONE)` and accepts
/// self-signed certs because trust binds to the session-layer
/// `node_id`, not to a certificate chain. Reusing that path for
/// HTTPS to a public CDN would be insecure — a MITM could present
/// any self-signed cert and veil's TLS layer would happily
/// accept it. This function builds a dedicated `ClientConfig` with
/// Mozilla's bundled CA roots + standard hostname verification.
///
/// `alpn` is honoured (typically `h2`/`http/1.1` for a CDN target).
/// `sni` defaults to `host` if `None`; passing `Some(parsed_host)`
/// matches the existing bootstrap convention.
pub async fn connect_pki_verified_https_stream(
    host: &str,
    port: u16,
    sni: Option<&str>,
    alpn: &[Vec<u8>],
    ctx: &TransportContext,
) -> Result<BoxIoStream> {
    let stream = connect_tcp_stream(host, port, ctx).await?;
    let server_name = ctx.server_name(ctx.effective_sni(sni, host))?;

    // Build a fresh PKI-trusting ClientConfig — DO NOT reuse
    // `ctx.tls.client_config` (operator-veil trust, node-id bound).
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // **Stage 10 slice 2b** — opt-in ECH GREASE on the public-PKI HTTPS
    // bootstrap path.  Driven by `GlobalConfig.tls_ech_grease`
    // (plumbed through `TransportContext::tls_ech_grease`).  When `true`,
    // pin TLS 1.3 (rustls `with_ech` requires it) and attach a
    // GREASE extension to ClientHello so middleboxes cannot fingerprint
    // ECH-capable from non-ECH connections.  Slice 2c will flip the
    // GlobalConfig default to `true`.  See `docs/en/OPERATIONS.md` →
    // "TLS ECH (Stage 10 slice 2)" for the rollout plan + cover-traffic
    // argument.
    let mut config = if ctx.tls_ech_grease {
        // `with_ech` lives on `ConfigBuilder<_, WantsVersions>` — that
        // returned by `builder_with_provider`, not the version-pinned
        // `builder`.  Use `aws_lc_rs::default_provider()` directly
        // (matches the install_default sites elsewhere in this crate).
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        // **Stage 10 slice 3** — try real ECH first via DNS HTTPS RR
        // lookup; fall back to slice 2c's GREASE on any DNS-side
        // failure.  See `crate::ech_dns` for the soft-failure model.
        let mode = match resolve_real_ech_mode(host, ctx).await {
            Some(real) => real,
            None => rustls::client::EchMode::Grease(build_ech_grease_config()?),
        };
        rustls::ClientConfig::builder_with_provider(provider)
            .with_ech(mode)
            .map_err(|e| tls_error(format!("ECH config build: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    config.alpn_protocols = effective_alpn(alpn);
    let connector = TlsConnector::from(Arc::new(config));

    let tls_stream: ClientTlsStream<TcpStream> = timeout(
        ctx.tcp.connect_timeout,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| handshake_timeout(ctx.tcp.connect_timeout))?
    .map_err(|err| tls_error(err.to_string()))?;

    Ok(Box::new(tls_stream))
}

/// Resolve real ECH config from DNS HTTPS RR (Stage 10 slice 3).  Returns
/// `Some(EchMode::Enable(...))` if a live HTTPS record exists and
/// rustls can select a supported HPKE suite from the published
/// EchConfigList; returns `None` for the caller to fall back to GREASE.
///
/// Failure paths that land in the `None` branch:
/// * no HTTPS record exists for `host` (most domains today),
/// * the record exists but carries no `ech` SvcParamKey,
/// * the DNS lookup times out (3 s default per `ech_dns::HTTPS_RR_TIMEOUT`),
/// * the published EchConfigList is malformed,
/// * none of the published HPKE suites overlap with aws-lc-rs's
///   [`ALL_SUPPORTED_SUITES`].
///
/// Errors are logged at DEBUG level (operators can grep `tls.ech.dns`)
/// but never propagated as TLS errors — the GREASE fallback is always
/// available.
async fn resolve_real_ech_mode(
    host: &str,
    ctx: &TransportContext,
) -> Option<rustls::client::EchMode> {
    use rustls::client::EchConfig;
    use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
    use rustls::pki_types::EchConfigListBytes;

    let raw = ctx.resolver.resolve_https_ech(host).await?;
    let bytes = EchConfigListBytes::from(raw);
    match EchConfig::new(bytes, ALL_SUPPORTED_SUITES) {
        Ok(cfg) => {
            log::info!(
                target: "tls.ech.dns",
                "real ECH selected host={host} suite=aws-lc-rs"
            );
            Some(rustls::client::EchMode::Enable(cfg))
        }
        Err(e) => {
            log::debug!(
                target: "tls.ech.dns",
                "ECH bytes parsed but no supported HPKE suite available \
                 — falling back to GREASE host={host} err={e}"
            );
            None
        }
    }
}

/// Build an `EchGreaseConfig` for use in
/// `connect_pki_verified_https_stream` when
/// `TransportContext::tls_ech_grease == true` (Stage 10 slice 2b).
///
/// Picks the `DH_KEM_X25519_HKDF_SHA256_AES_128` HPKE suite (widely
/// supported, the canonical default for ECH in the wild) and generates a
/// random 32-byte placeholder X25519 public key.  GREASE makes the
/// ClientHello indistinguishable from a real ECH-enabled connection
/// without requiring an actual EchConfig from DNS.  The real-ECH path
/// (`EchMode::Enable`, with the `EchConfig` resolved from an HTTPS RR — see
/// the resolver above) is implemented as of Stage 10 slice 3; GREASE is the
/// fallback used when no real `EchConfig` is available from DNS.
fn build_ech_grease_config() -> Result<rustls::client::EchGreaseConfig> {
    use rand::RngCore;
    use rustls::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
    use rustls::crypto::hpke::HpkePublicKey;

    let mut placeholder_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut placeholder_bytes);
    let placeholder_key = HpkePublicKey(placeholder_bytes.to_vec());
    Ok(rustls::client::EchGreaseConfig::new(
        DH_KEM_X25519_HKDF_SHA256_AES_128,
        placeholder_key,
    ))
}

struct TlsTransportListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    bind_uri: TransportUri,
}

type TlsConnectParts<'a> = (&'a str, u16, Option<&'a str>, &'a [Vec<u8>]);

fn tls_connect_parts(uri: &TransportUri) -> Result<TlsConnectParts<'_>> {
    match uri {
        TransportUri::Tls {
            host,
            port,
            sni,
            alpn,
        } => Ok((host.as_str(), *port, sni.as_deref(), alpn.as_slice())),
        _ => Err(TransportError::Unsupported(format!(
            "tls transport cannot handle `{}`",
            uri.scheme()
        ))),
    }
}

fn tls_bind_parts(uri: &TransportUri) -> Result<(&str, u16, &[Vec<u8>])> {
    match uri {
        TransportUri::Tls {
            host, port, alpn, ..
        } => Ok((host.as_str(), *port, alpn.as_slice())),
        _ => Err(TransportError::Unsupported(format!(
            "tls transport cannot bind `{}`",
            uri.scheme()
        ))),
    }
}

fn native_tls_peer(
    uri: TransportUri,
    local_addr: Option<std::net::SocketAddr>,
    remote_addr: Option<std::net::SocketAddr>,
) -> crate::PeerMeta {
    let mut peer = peer_meta("tls", uri, local_addr, remote_addr);
    peer.runtime_info = Some(native_runtime_info(TransportHandshakeMode::TlsRustls));
    peer
}

fn boxed_tls_connection(
    peer: crate::PeerMeta,
    stream: impl super::traits::IoStream + 'static,
) -> Box<dyn TransportConnection> {
    Box::new(StreamConnection::new(peer, stream)) as Box<dyn TransportConnection>
}

fn build_tls_acceptor(ctx: &TransportContext, alpn: &[Vec<u8>]) -> TlsAcceptor {
    let mut server_config = (*ctx.tls.server_config).clone();
    server_config.alpn_protocols = effective_alpn(alpn);
    TlsAcceptor::from(Arc::new(server_config))
}

fn boxed_tls_listener(
    listener: TcpListener,
    bind_uri: TransportUri,
    ctx: &TransportContext,
    alpn: &[Vec<u8>],
) -> Box<dyn TransportListener> {
    Box::new(TlsTransportListener {
        listener,
        acceptor: build_tls_acceptor(ctx, alpn),
        bind_uri,
    }) as Box<dyn TransportListener>
}

impl TransportListener for TlsTransportListener {
    fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (stream, remote_addr) = self.listener.accept().await?;
            let local_addr = stream.local_addr().ok();
            // SECURITY (audit 2026-05-29): bound the inline TLS handshake
            // so a stalled client cannot freeze the accept loop.
            let tls_stream: ServerTlsStream<TcpStream> =
                tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, self.acceptor.accept(stream))
                    .await
                    .map_err(|_| tls_error("tls server handshake timed out".to_string()))?
                    .map_err(|err| tls_error(err.to_string()))?;
            Ok(boxed_tls_connection(
                native_tls_peer(self.bind_uri.clone(), local_addr, Some(remote_addr)),
                tls_stream,
            ))
        })
    }

    /// cycle-8 H2: split the kernel accept from the TLS handshake so a stalled
    /// client occupies one spawned, semaphore-bounded handshake slot rather than
    /// serializing the accept loop (the 10 s timeout bounded a single hang, but
    /// the loop still processed handshakes one at a time).
    fn accept_split<'a>(&'a self) -> BoxFuture<'a, Result<RawInbound>> {
        Box::pin(async move {
            let (stream, remote_addr) = self.listener.accept().await?;
            let local_addr = stream.local_addr().ok();
            let acceptor = self.acceptor.clone();
            let bind_uri = self.bind_uri.clone();
            let finish: BoxFuture<'static, Result<Box<dyn TransportConnection>>> =
                Box::pin(async move {
                    let tls_stream: ServerTlsStream<TcpStream> =
                        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                            .await
                            .map_err(|_| {
                                tls_error("tls server handshake timed out".to_string())
                            })?
                            .map_err(|err| tls_error(err.to_string()))?;
                    Ok(boxed_tls_connection(
                        native_tls_peer(bind_uri, local_addr, Some(remote_addr)),
                        tls_stream,
                    ))
                });
            Ok(RawInbound {
                remote_addr: Some(remote_addr),
                finish,
            })
        })
    }

    fn local_addr(&self) -> String {
        self.listener
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| self.bind_uri.to_string())
    }
}

impl Transport for TlsTransport {
    fn scheme(&self) -> &'static str {
        "tls"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities::stream_listener()
    }

    fn connect<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (host, port, sni, alpn) = tls_connect_parts(uri)?;
            let stream = connect_tcp_stream(host, port, &ctx).await?;
            let local_addr = stream.local_addr().ok();
            let remote_addr = stream.peer_addr().ok();
            let tls_stream: ClientTlsStream<TcpStream> =
                connect_tls_stream(stream, host, sni, alpn, &ctx).await?;
            Ok(boxed_tls_connection(
                native_tls_peer(uri.clone(), local_addr, remote_addr),
                tls_stream,
            ))
        })
    }

    fn bind<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>> {
        Box::pin(async move {
            let (host, port, alpn) = tls_bind_parts(uri)?;
            let listener = TcpListener::bind((host, port)).await?;
            Ok(boxed_tls_listener(listener, uri.clone(), &ctx, alpn))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── default ALPN ─────────────────────────────────────────

    #[test]
    fn empty_alpn_defaults_to_h2() {
        let alpn: Vec<Vec<u8>> = vec![];
        let result = effective_alpn(&alpn);
        assert_eq!(result, vec![b"h2".to_vec()]);
    }

    #[test]
    fn explicit_alpn_is_preserved() {
        let alpn = vec![b"http/1.1".to_vec(), b"spdy/3".to_vec()];
        let result = effective_alpn(&alpn);
        assert_eq!(result, vec![b"http/1.1".to_vec(), b"spdy/3".to_vec()]);
    }

    #[test]
    fn explicit_h2_passed_through() {
        // Operator explicitly specified h2 — same as default, still pass through.
        let alpn = vec![b"h2".to_vec()];
        let result = effective_alpn(&alpn);
        assert_eq!(result, vec![b"h2".to_vec()]);
    }
}
