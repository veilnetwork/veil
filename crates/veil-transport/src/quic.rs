use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::time::timeout;

use super::{
    TransportContext,
    error::{Result, TransportError, connect_timeout, handshake_timeout, quic_error},
    tcp::peer_meta,
    traits::{
        BoxIoStream, PeerMeta, Transport, TransportCapabilities, TransportConnection,
        TransportHandshakeMode, TransportListener, native_runtime_info,
    },
    uri::TransportUri,
};

/// QUIC `Transport` implementation. Opens an endpoint per
/// `connect`/`listen` and serves one bidirectional stream per logical
/// connection; TLS is integrated into the QUIC handshake.
#[derive(Debug, Default)]
pub struct QuicTransport;

/// Adapter that exposes a QUIC `(SendStream, RecvStream)` pair as a single
/// duplex stream satisfying `AsyncRead + AsyncWrite`.
pub struct QuicBidiStream {
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl tokio::io::AsyncRead for QuicBidiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::pin::Pin;
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for QuicBidiStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::pin::Pin;
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(|err| std::io::Error::other(err.to_string()))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::pin::Pin;
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(|err| std::io::Error::other(err.to_string()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::pin::Pin;
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(|err| std::io::Error::other(err.to_string()))
    }
}

struct QuicTransportConnection {
    capabilities: TransportCapabilities,
    peer_meta: PeerMeta,
    connection: quinn::Connection,
    stream: Option<BoxIoStream>,
}

impl QuicTransportConnection {
    fn new(peer_meta: PeerMeta, connection: quinn::Connection, stream: BoxIoStream) -> Self {
        Self {
            capabilities: TransportCapabilities::quic_connection(),
            peer_meta,
            connection,
            stream: Some(stream),
        }
    }
}

fn boxed_quic_connection(
    peer_meta: PeerMeta,
    connection: quinn::Connection,
    stream: BoxIoStream,
) -> Box<dyn TransportConnection> {
    Box::new(QuicTransportConnection::new(peer_meta, connection, stream))
        as Box<dyn TransportConnection>
}

fn native_quic_peer(
    uri: TransportUri,
    local_addr: Option<std::net::SocketAddr>,
    remote_addr: Option<std::net::SocketAddr>,
) -> PeerMeta {
    let mut peer = peer_meta("quic", uri, local_addr, remote_addr);
    peer.runtime_info = Some(native_runtime_info(TransportHandshakeMode::QuicNative));
    peer
}

fn boxed_quic_listener(
    endpoint: quinn::Endpoint,
    bind_uri: TransportUri,
) -> Box<dyn TransportListener> {
    Box::new(QuicTransportListener { endpoint, bind_uri }) as Box<dyn TransportListener>
}

type QuicConnectParts<'a> = (&'a str, u16, Option<&'a str>, Vec<Vec<u8>>);

fn quic_connect_parts(uri: &TransportUri) -> Result<QuicConnectParts<'_>> {
    match uri {
        TransportUri::Quic {
            host,
            port,
            sni,
            alpn,
        } => Ok((host.as_str(), *port, sni.as_deref(), alpn.clone())),
        _ => Err(TransportError::Unsupported(format!(
            "quic transport cannot handle `{}`",
            uri.scheme()
        ))),
    }
}

fn quic_bind_parts(uri: &TransportUri) -> Result<(&str, u16, Vec<Vec<u8>>)> {
    match uri {
        TransportUri::Quic {
            host, port, alpn, ..
        } => Ok((host.as_str(), *port, alpn.clone())),
        _ => Err(TransportError::Unsupported(format!(
            "quic transport cannot bind `{}`",
            uri.scheme()
        ))),
    }
}

async fn resolve_remote_addr(
    ctx: &TransportContext,
    host: &str,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>> {
    let addrs = ctx.resolver.resolve(host, port).await?;
    if addrs.is_empty() {
        return Err(TransportError::Dns(format!(
            "no addresses resolved for {host}:{port}"
        )));
    }
    Ok(addrs)
}

/// default QUIC ALPN when the user did not specify `?alpn=...`.
/// `h3` (HTTP/3) is the standard QUIC ALPN, so OVL1 traffic masquerades as
/// ordinary HTTP/3 to on-path DPI.
pub(crate) const DEFAULT_QUIC_ALPN: &[u8] = b"h3";

fn effective_quic_alpn(alpn: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    if alpn.is_empty() {
        vec![DEFAULT_QUIC_ALPN.to_vec()]
    } else {
        alpn
    }
}

// ── Chrome HTTP/3 transport-parameter mimicry (anti-censorship P1 #4) ──
//
// Chrome's QUIC sends а distinctive set of transport-parameter values
// в its TLS-CRYPTO-frame ClientHello — DPI tooling что fingerprints
// QUIC connections (СКАТ DPI 12.0+, Wireshark dissectors,
// independent classifier services) profile these values к
// distinguish "real Chrome HTTP/3" от "library defaults / VPN /
// proxy".  quinn's `TransportConfig::default()` matches none of
// them — initial_max_data is the most obviously distinct (quinn's
// default is `VarInt::MAX`, Chrome's is а modest 15 MiB).
//
// Reproducing Chrome's exact values closes the QUIC-fingerprint
// half of #19 (QUIC_UNKNOWN_MARKED) против stateless classifiers.
// Bit-exact ClientHello mimicry — extensions ordering, point format
// list, etc. — lives in the `tls-boring` feature (`quinn-btls`
// backend); this module covers the transport-parameter layer на top
// of whichever crypto backend is enabled.
//
// Values sourced от Chromium's net/quic/quic_session_pool.cc
// (`InitializeSessionConfig`) и net/third_party/quiche/src/
// quiche/quic/core/quic_session.cc (stable channel mid-2026).
//
// Note: quinn names some parameters differently от the IETF spec:
// - `stream_receive_window`  ↔ `initial_max_stream_data_bidi_local`
// - `receive_window`         ↔ `initial_max_data`
// - `send_window` is а quinn-only knob; left at default (1 MiB) as
//   it doesn't appear в the transport-param list sent on the wire.

/// `initial_max_data` value Chrome 120+ stable advertises (≈ 15 MiB).
/// DPI compares this к pattern-bucket Chrome's 15728640 falls in;
/// quinn's default `VarInt::MAX` (62-bit) is the dead giveaway.
pub(crate) const CHROME_INITIAL_MAX_DATA: u64 = 15 * 1024 * 1024;

/// `initial_max_stream_data_bidi_{local,remote}` value Chrome
/// advertises (6 MiB).
pub(crate) const CHROME_INITIAL_MAX_STREAM_DATA: u64 = 6 * 1024 * 1024;

/// `initial_max_streams_bidi` value Chrome advertises (100).  quinn's
/// default for connect-side is 100, server-side is unbounded — we
/// pin both к Chrome's 100 для symmetry.
pub(crate) const CHROME_INITIAL_MAX_STREAMS_BIDI: u64 = 100;

/// `initial_max_streams_uni` value Chrome advertises (100).
pub(crate) const CHROME_INITIAL_MAX_STREAMS_UNI: u64 = 100;

/// `max_idle_timeout` value Chrome advertises (30 seconds).  quinn's
/// default is 0 = "no idle timeout from this endpoint"; both sides
/// must agree on min, so we set а concrete value matching Chrome.
pub(crate) const CHROME_MAX_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Build а `TransportConfig` що mimics Chrome HTTP/3's transport
/// parameters.  Applied к both client + server config builders.
pub fn chrome_mimic_transport_config() -> quinn::TransportConfig {
    let mut cfg = quinn::TransportConfig::default();
    cfg.max_concurrent_bidi_streams(
        quinn::VarInt::from_u64(CHROME_INITIAL_MAX_STREAMS_BIDI).expect("≤ VarInt::MAX"),
    );
    cfg.max_concurrent_uni_streams(
        quinn::VarInt::from_u64(CHROME_INITIAL_MAX_STREAMS_UNI).expect("≤ VarInt::MAX"),
    );
    cfg.stream_receive_window(
        quinn::VarInt::from_u64(CHROME_INITIAL_MAX_STREAM_DATA).expect("≤ VarInt::MAX"),
    );
    cfg.receive_window(quinn::VarInt::from_u64(CHROME_INITIAL_MAX_DATA).expect("≤ VarInt::MAX"));
    cfg.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_millis(CHROME_MAX_IDLE_TIMEOUT_MS))
            .expect("30s is a valid IdleTimeout"),
    ));
    cfg
}

#[cfg(not(feature = "tls-boring"))]
fn build_quic_client_config(
    ctx: &TransportContext,
    alpn: Vec<Vec<u8>>,
) -> Result<quinn::ClientConfig> {
    let mut client_crypto = (*ctx.tls.client_config).clone();
    client_crypto.alpn_protocols = effective_quic_alpn(alpn);
    let client_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).map_err(quic_error)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    // Anti-censorship P1 #4: Chrome-mimic transport parameters
    // (see chrome_mimic_transport_config docs above).
    client_config.transport_config(Arc::new(chrome_mimic_transport_config()));
    Ok(client_config)
}

#[cfg(not(feature = "tls-boring"))]
fn build_quic_server_config(
    ctx: &TransportContext,
    alpn: Vec<Vec<u8>>,
) -> Result<quinn::ServerConfig> {
    let mut server_crypto = (*ctx.tls.server_config).clone();
    server_crypto.alpn_protocols = effective_quic_alpn(alpn);
    let server_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).map_err(quic_error)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    // Anti-censorship P1 #4: same Chrome-mimic transport params на
    // the accept side.  Servers и clients negotiate the min of each
    // side's advertised value, so symmetry minimizes the chance that
    // а DPI middlebox observes а transport-params mismatch.
    server_config.transport_config(Arc::new(chrome_mimic_transport_config()));
    Ok(server_config)
}

// ── BoringSSL-backed QUIC via `quinn-btls` ──────────────────────
//
// When `tls-boring` is enabled, replace the rustls crypto provider with
// `quinn_btls::{client,server}::Config` so QUIC Initial packets carry a
// Chrome-like TLS ClientHello (JA4 masquerade). Shares the same BoringSSL
// C source already compiled for TLS via `btls` — no double link.

// Note — Chrome curve order on QUIC:
// `quinn-btls` exposes the `SslContext` only through the `QuicSslContext`
// trait, which does NOT include `set_curves_list`. BoringSSL's default
// QUIC group preferences already place X25519 first (matching Chrome), so
// skipping this call is acceptable for the JA4 goal; the key-share extension
// will still advertise X25519 as Chrome does. If bit-exact Chrome JA4
// matching becomes required, upstream `quinn-btls` needs a patch to expose
// the curve list setter (or a local fork).

#[cfg(feature = "tls-boring")]
fn build_quic_client_config(
    _ctx: &TransportContext,
    alpn: Vec<Vec<u8>>,
) -> Result<quinn::ClientConfig> {
    let mut cfg = quinn_btls::ClientConfig::new()
        .map_err(|e| quic_error(format!("quinn-btls ClientConfig::new: {e}")))?;
    // Veil binds trust to node_id at the session layer — disable QUIC TLS
    // verification (parity with the TCP-TLS path in `tls_boring.rs`).
    cfg.verify_peer(false);

    cfg.set_alpn(&effective_quic_alpn(alpn))
        .map_err(|e| quic_error(format!("quinn-btls set_alpn: {e}")))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(cfg));
    // Anti-censorship P1 #4: Chrome-mimic transport parameters.
    client_config.transport_config(Arc::new(chrome_mimic_transport_config()));
    Ok(client_config)
}

#[cfg(feature = "tls-boring")]
fn build_quic_server_config(
    ctx: &TransportContext,
    alpn: Vec<Vec<u8>>,
) -> Result<quinn::ServerConfig> {
    use btls::pkey::PKey;
    use btls::x509::X509;
    use quinn_btls::QuicSslContext;

    let mut cfg = quinn_btls::ServerConfig::new()
        .map_err(|e| quic_error(format!("quinn-btls ServerConfig::new: {e}")))?;
    // Mirror TCP-TLS: no client cert verification (veil node-id binds trust).
    cfg.verify_peer(false);

    // Load cert chain + private key into the SslContext through the
    // `QuicSslContext` trait (quinn-btls exposes ctx only via this trait
    // not the full `SslContextBuilder` API). Methods here take ownership
    // unlike the boring / builder API which takes `&X509Ref` / `&PKeyRef`.
    let chain = ctx.tls.server_cert_chain_der();
    let key_der = ctx.tls.server_private_key_der();

    let mut iter = chain.iter();
    let leaf_der = iter.next().ok_or_else(|| {
        TransportError::Unsupported("tls-boring: server cert chain is empty".to_owned())
    })?;
    let leaf = X509::from_der(leaf_der.as_ref())
        .map_err(|e| quic_error(format!("quinn-btls X509::from_der(leaf): {e}")))?;
    cfg.ctx_mut()
        .set_certificate(leaf)
        .map_err(|e| quic_error(format!("quinn-btls set_certificate: {e}")))?;
    for extra in iter {
        let cert = X509::from_der(extra.as_ref())
            .map_err(|e| quic_error(format!("quinn-btls X509::from_der(chain): {e}")))?;
        cfg.ctx_mut()
            .add_to_cert_chain(cert)
            .map_err(|e| quic_error(format!("quinn-btls add_to_cert_chain: {e}")))?;
    }
    let key = PKey::private_key_from_pkcs8(key_der.secret_der())
        .or_else(|_| PKey::private_key_from_der(key_der.secret_der()))
        .map_err(|e| quic_error(format!("quinn-btls private_key_from_{{pkcs8|der}}: {e}")))?;
    cfg.ctx_mut()
        .set_private_key(key)
        .map_err(|e| quic_error(format!("quinn-btls set_private_key: {e}")))?;
    cfg.ctx_mut().check_private_key().map_err(|e| {
        quic_error(format!(
            "quinn-btls check_private_key (cert/key mismatch?): {e}"
        ))
    })?;

    cfg.set_alpn(&effective_quic_alpn(alpn))
        .map_err(|e| quic_error(format!("quinn-btls set_alpn: {e}")))?;

    let mut server_config = quinn_btls::helpers::server_config(Arc::new(cfg))
        .map_err(|e| quic_error(format!("quinn-btls helpers::server_config: {e}")))?;
    // Anti-censorship P1 #4: Chrome-mimic transport parameters.
    server_config.transport_config(Arc::new(chrome_mimic_transport_config()));
    Ok(server_config)
}

/// when the btls-backed crypto provider is active, the endpoint
/// must use btls's HmacKey/EndpointConfig too — quinn's rustls default uses
/// ring-based HMAC which cannot authenticate tokens minted by btls.
#[cfg(feature = "tls-boring")]
fn build_client_endpoint(bind_addr: std::net::SocketAddr) -> Result<quinn::Endpoint> {
    quinn_btls::helpers::client_endpoint(bind_addr).map_err(Into::into)
}

#[cfg(not(feature = "tls-boring"))]
fn build_client_endpoint(bind_addr: std::net::SocketAddr) -> Result<quinn::Endpoint> {
    quinn::Endpoint::client(bind_addr).map_err(Into::into)
}

#[cfg(feature = "tls-boring")]
fn build_server_endpoint(
    config: quinn::ServerConfig,
    bind_addr: std::net::SocketAddr,
) -> Result<quinn::Endpoint> {
    quinn_btls::helpers::server_endpoint(config, bind_addr).map_err(Into::into)
}

#[cfg(not(feature = "tls-boring"))]
fn build_server_endpoint(
    config: quinn::ServerConfig,
    bind_addr: std::net::SocketAddr,
) -> Result<quinn::Endpoint> {
    quinn::Endpoint::server(config, bind_addr).map_err(Into::into)
}

async fn connect_native_quic(
    ctx: &TransportContext,
    host: &str,
    port: u16,
    sni: Option<&str>,
    alpn: Vec<Vec<u8>>,
) -> Result<(quinn::Endpoint, std::net::SocketAddr, quinn::Connection)> {
    let mut endpoint = build_client_endpoint(ctx.quic.bind_addr)?;
    endpoint.set_default_client_config(build_quic_client_config(ctx, alpn)?);
    let remote_addrs = resolve_remote_addr(ctx, host, port).await?;
    // Try all resolved addresses (IPv4 + IPv6), not just the first.
    let mut last_err = None;
    for &remote_addr in &remote_addrs {
        match endpoint.connect(remote_addr, ctx.effective_sni(sni, host)) {
            Ok(connecting) => match timeout(ctx.quic.connect_timeout, connecting).await {
                Ok(Ok(connection)) => return Ok((endpoint, remote_addr, connection)),
                Ok(Err(e)) => last_err = Some(TransportError::from(e)),
                Err(_) => last_err = Some(connect_timeout(ctx.quic.connect_timeout)),
            },
            Err(e) => last_err = Some(TransportError::from(e)),
        }
    }
    Err(last_err
        .unwrap_or_else(|| TransportError::Dns(format!("no addresses resolved for {host}:{port}"))))
}

async fn bind_native_quic(
    ctx: &TransportContext,
    host: &str,
    port: u16,
    alpn: Vec<Vec<u8>>,
) -> Result<quinn::Endpoint> {
    let bind_addrs = resolve_remote_addr(ctx, host, port).await?;
    build_server_endpoint(build_quic_server_config(ctx, alpn)?, bind_addrs[0])
}

impl TransportConnection for QuicTransportConnection {
    fn capabilities(&self) -> &TransportCapabilities {
        &self.capabilities
    }

    fn peer_meta(&self) -> &PeerMeta {
        &self.peer_meta
    }

    fn into_stream(mut self: Box<Self>) -> Result<BoxIoStream> {
        self.stream
            .take()
            .ok_or_else(|| TransportError::Unsupported("stream already taken".to_owned()))
    }

    fn quic_connection(&self) -> Option<quinn::Connection> {
        Some(self.connection.clone())
    }

    fn send_datagram<'a>(&'a self, payload: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.connection
                .send_datagram(payload.to_vec().into())
                .map_err(quic_error)
        })
    }

    fn recv_datagram<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let payload = self.connection.read_datagram().await?;
            Ok(payload.to_vec())
        })
    }

    fn open_substream<'a>(&'a self) -> BoxFuture<'a, Result<BoxIoStream>> {
        Box::pin(async move {
            let (send, recv) = self.connection.open_bi().await?;
            Ok(Box::new(QuicBidiStream { recv, send }) as BoxIoStream)
        })
    }

    fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.connection.close(0u32.into(), b"closed");
            self.stream.take();
            Ok(())
        })
    }
}

struct QuicTransportListener {
    endpoint: quinn::Endpoint,
    bind_uri: TransportUri,
}

impl TransportListener for QuicTransportListener {
    fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let incoming = self
                .endpoint
                .accept()
                .await
                .ok_or_else(|| quic_error("endpoint closed"))?;
            let local_addr = incoming
                .local_ip()
                .map(|ip| std::net::SocketAddr::new(ip, 0));
            let connection = incoming.await?;
            let remote_addr = connection.remote_address();
            let peer_meta = native_quic_peer(self.bind_uri.clone(), local_addr, Some(remote_addr));

            let stream: BoxIoStream = {
                let (send, recv) = connection.accept_bi().await?;
                Box::new(QuicBidiStream { recv, send })
            };

            Ok(boxed_quic_connection(peer_meta, connection, stream))
        })
    }

    fn local_addr(&self) -> String {
        self.endpoint
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| self.bind_uri.to_string())
    }
}

impl Transport for QuicTransport {
    fn scheme(&self) -> &'static str {
        "quic"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities::quic_listener()
    }

    fn connect<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (host, port, sni, alpn) = quic_connect_parts(uri)?;
            let (endpoint, remote_addr, connection) =
                connect_native_quic(&ctx, host, port, sni, alpn).await?;
            let peer_meta =
                native_quic_peer(uri.clone(), endpoint.local_addr().ok(), Some(remote_addr));

            let stream: BoxIoStream = {
                let (send, recv) = timeout(ctx.quic.handshake_timeout, connection.open_bi())
                    .await
                    .map_err(|_| handshake_timeout(ctx.quic.handshake_timeout))??;
                Box::new(QuicBidiStream { recv, send })
            };

            Ok(boxed_quic_connection(peer_meta, connection, stream))
        })
    }

    fn bind<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>> {
        Box::pin(async move {
            let (host, port, alpn) = quic_bind_parts(uri)?;
            let endpoint = bind_native_quic(&ctx, host, port, alpn).await?;
            Ok(boxed_quic_listener(endpoint, uri.clone()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anti-censorship P1 #4: the Chrome-mimic transport config builder
    /// must produce concrete values matching Chromium's QUIC params, не
    /// the quinn defaults (which are wildly different — initial_max_data
    /// defaults к `VarInt::MAX` for example).  This test pins the
    /// concrete constants so а quinn upgrade что changes its defaults
    /// can't silently regress the DPI-fingerprint surface.
    #[test]
    fn chrome_mimic_constants_match_published_values() {
        assert_eq!(CHROME_INITIAL_MAX_DATA, 15 * 1024 * 1024);
        assert_eq!(CHROME_INITIAL_MAX_STREAM_DATA, 6 * 1024 * 1024);
        assert_eq!(CHROME_INITIAL_MAX_STREAMS_BIDI, 100);
        assert_eq!(CHROME_INITIAL_MAX_STREAMS_UNI, 100);
        assert_eq!(CHROME_MAX_IDLE_TIMEOUT_MS, 30_000);
    }

    /// `chrome_mimic_transport_config()` must construct without panicking;
    /// pre-shadow the VarInt::from_u64 conversions in case quinn ever
    /// shrinks VarInt::MAX (unlikely — currently 2^62 - 1, far above
    /// 15 MiB).
    #[test]
    fn chrome_mimic_transport_config_constructs_ok() {
        let _cfg = chrome_mimic_transport_config();
    }

    /// Default ALPN must be the bare bytes `b"h3"` — matches Chrome
    /// stable от ~v120 (which dropped the `h3-29 / h3-32` draft
    /// variants).  А DPI fingerprint check on the ClientHello ALPN
    /// list would flag any variant.
    #[test]
    fn default_alpn_is_h3_only() {
        assert_eq!(DEFAULT_QUIC_ALPN, b"h3");
        let effective = effective_quic_alpn(vec![]);
        assert_eq!(effective, vec![b"h3".to_vec()]);
    }

    /// Operator-supplied ALPN overrides the default — so test harnesses
    /// can use а distinct ALPN to isolate test traffic without рисуя
    /// production's anti-DPI guarantees.
    #[test]
    fn user_supplied_alpn_overrides_default() {
        let user = vec![b"my-test-proto".to_vec()];
        let effective = effective_quic_alpn(user.clone());
        assert_eq!(effective, user);
    }
}
