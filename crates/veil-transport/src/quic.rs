use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::time::timeout;

use super::{
    TransportContext,
    error::{Result, TransportError, connect_timeout, handshake_timeout, quic_error},
    tcp::peer_meta,
    traits::{
        BoxIoStream, PeerMeta, RawInbound, Transport, TransportCapabilities, TransportConnection,
        TransportHandshakeMode, TransportListener, native_runtime_info,
    },
    uri::TransportUri,
};

/// QUIC `Transport` implementation. Opens an endpoint per
/// `connect`/`listen` and serves one bidirectional stream per logical
/// connection; TLS is integrated into the QUIC handshake.
#[derive(Debug, Default)]
pub struct QuicTransport;

/// Deterministic role used when promoting a simultaneously-punched UDP socket
/// into a QUIC connection. Callers derive this from stable node-id ordering so
/// exactly one peer emits the QUIC Initial while the other accepts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PunchedQuicRole {
    Initiator,
    Responder,
}

/// A bounded, deliberately small QUIC DATAGRAM queue keeps realtime media
/// fresh under congestion. Quinn's 1 MiB send / 1.25 MiB receive defaults are
/// appropriate for throughput-oriented application datagrams, but at a
/// 900-kbit/s video rate they can retain roughly 9--11 seconds of obsolete
/// RTP. 64 KiB is about sixteen 30-fps frames at that rate: enough to absorb a
/// short scheduler hiccup while still preferring a current frame over stale
/// video.
pub const REALTIME_DATAGRAM_BUFFER_BYTES: usize = 64 * 1024;

/// Stable transport-level classification of Quinn DATAGRAM send failures.
/// Session code needs to distinguish a path-MTU change (drop one lossy frame,
/// refresh the ceiling and continue) from a permanently unavailable lane.
#[derive(Clone, Debug, thiserror::Error)]
pub enum QuicDatagramSendError {
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    #[error("datagram support disabled")]
    Disabled,
    #[error("datagram too large")]
    TooLarge,
    #[error("connection lost: {0}")]
    ConnectionLost(String),
}

/// Cloneable access to QUIC's unreliable datagram plane while the primary
/// OVL1 byte stream remains owned by the session runner.
///
/// The handle is intentionally transport-scoped: callers cannot reach Quinn
/// configuration or open arbitrary streams, but can query the negotiated
/// datagram ceiling and send/receive one authenticated-session side channel.
/// Keeping a clone also keeps the underlying connection alive.
#[derive(Clone)]
pub struct QuicDatagramHandle {
    connection: quinn::Connection,
}

impl QuicDatagramHandle {
    /// Largest payload accepted by both QUIC endpoints, or `None` when the
    /// peer disabled DATAGRAM support.
    pub fn max_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    /// Queue one unreliable datagram. Success means Quinn accepted the bytes;
    /// loss after that point is expected and must be handled by the caller.
    pub fn send(&self, payload: &[u8]) -> std::result::Result<(), QuicDatagramSendError> {
        self.connection
            .send_datagram(payload.to_vec().into())
            .map_err(|error| match error {
                quinn::SendDatagramError::UnsupportedByPeer => {
                    QuicDatagramSendError::UnsupportedByPeer
                }
                quinn::SendDatagramError::Disabled => QuicDatagramSendError::Disabled,
                quinn::SendDatagramError::TooLarge => QuicDatagramSendError::TooLarge,
                quinn::SendDatagramError::ConnectionLost(error) => {
                    QuicDatagramSendError::ConnectionLost(error.to_string())
                }
            })
    }

    /// Remaining bytes in Quinn's outgoing DATAGRAM queue. A value smaller
    /// than the next datagram means `send_datagram` will discard older queued
    /// media to preserve recency.
    pub fn send_buffer_space(&self) -> usize {
        self.connection.datagram_send_buffer_space()
    }

    /// Receive the next unreliable datagram for this connection.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        self.connection
            .read_datagram()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(Into::into)
    }
}

/// Adapter that exposes a QUIC `(SendStream, RecvStream)` pair as a single
/// duplex stream satisfying `AsyncRead + AsyncWrite`.
pub struct QuicBidiStream {
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

/// Owns the endpoint/connection handles when a `TransportConnection` is
/// consumed into its primary byte stream. Without this wrapper, consuming the
/// connection dropped the last Endpoint handle and Quinn immediately closed an
/// otherwise healthy stream with application code 0.
struct QuicOwnedStream {
    inner: BoxIoStream,
    _endpoint: quinn::Endpoint,
    _connection: quinn::Connection,
}

impl tokio::io::AsyncRead for QuicOwnedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for QuicOwnedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
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
    // Quinn closes every connection when the last Endpoint handle is dropped.
    // Keep one beside the promoted/accepted connection for its full lifetime.
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    stream: Option<BoxIoStream>,
}

impl QuicTransportConnection {
    fn new(
        peer_meta: PeerMeta,
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        stream: BoxIoStream,
    ) -> Self {
        Self {
            capabilities: TransportCapabilities::quic_connection(),
            peer_meta,
            _endpoint: endpoint,
            connection,
            stream: Some(stream),
        }
    }
}

fn boxed_quic_connection(
    peer_meta: PeerMeta,
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    stream: BoxIoStream,
) -> Box<dyn TransportConnection> {
    Box::new(QuicTransportConnection::new(
        peer_meta, endpoint, connection, stream,
    )) as Box<dyn TransportConnection>
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
// Chrome's QUIC sends a distinctive set of transport-parameter values
// in its TLS-CRYPTO-frame ClientHello — DPI tooling that fingerprints
// QUIC connections (SKAT DPI 12.0+, Wireshark dissectors,
// independent classifier services) profile these values to
// distinguish "real Chrome HTTP/3" from "library defaults / VPN /
// proxy".  quinn's `TransportConfig::default()` matches none of
// them — initial_max_data is the most obviously distinct (quinn's
// default is `VarInt::MAX`, Chrome's is a modest 15 MiB).
//
// Reproducing Chrome's exact values closes the QUIC-fingerprint
// half of #19 (QUIC_UNKNOWN_MARKED) against stateless classifiers.
// The TLS crypto is deliberately kept on Quinn's maintained rustls backend.
// `quinn-btls` 0.1 can panic while deriving application secrets and poison the
// endpoint mutex, turning a malformed/failed handshake into a process abort.
// BoringSSL remains available to the TCP-TLS camouflage transports; peer QUIC
// prioritizes memory safety and keeps the Chrome-like transport parameters.
//
// Values sourced from Chromium's net/quic/quic_session_pool.cc
// (`InitializeSessionConfig`) and net/third_party/quiche/src/
// quiche/quic/core/quic_session.cc (stable channel mid-2026).
//
// Note: quinn names some parameters differently from the IETF spec:
// - `stream_receive_window`  ↔ `initial_max_stream_data_bidi_local`
// - `receive_window`         ↔ `initial_max_data`
// - `send_window` is a quinn-only knob; left at default (1 MiB) as
//   it doesn't appear in the transport-param list sent on the wire.

/// `initial_max_data` value Chrome 120+ stable advertises (≈ 15 MiB).
/// DPI compares this to pattern-bucket Chrome's 15728640 falls in;
/// quinn's default `VarInt::MAX` (62-bit) is the dead giveaway.
pub(crate) const CHROME_INITIAL_MAX_DATA: u64 = 15 * 1024 * 1024;

/// `initial_max_stream_data_bidi_{local,remote}` value Chrome
/// advertises (6 MiB).
pub(crate) const CHROME_INITIAL_MAX_STREAM_DATA: u64 = 6 * 1024 * 1024;

/// `initial_max_streams_bidi` value Chrome advertises (100).  quinn's
/// default for connect-side is 100, server-side is unbounded — we
/// pin both to Chrome's 100 for symmetry.
pub(crate) const CHROME_INITIAL_MAX_STREAMS_BIDI: u64 = 100;

/// `initial_max_streams_uni` value Chrome advertises (100).
pub(crate) const CHROME_INITIAL_MAX_STREAMS_UNI: u64 = 100;

/// `max_idle_timeout` value Chrome advertises (30 seconds).  quinn's
/// default is 0 = "no idle timeout from this endpoint"; both sides
/// must agree on min, so we set a concrete value matching Chrome.
pub(crate) const CHROME_MAX_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Build a `TransportConfig` that mimics Chrome HTTP/3's transport
/// parameters.  Applied to both client + server config builders.
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
    cfg.datagram_send_buffer_size(REALTIME_DATAGRAM_BUFFER_BYTES);
    cfg.datagram_receive_buffer_size(Some(REALTIME_DATAGRAM_BUFFER_BYTES));
    cfg
}

#[derive(Debug)]
struct SessionBoundQuicServerVerifier(Arc<rustls::crypto::CryptoProvider>);

impl SessionBoundQuicServerVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        ))
    }
}

/// Veil peer QUIC authenticates the remote node in the mandatory signed
/// session handshake immediately after TLS. The transport certificate is an
/// ephemeral encryption shell, not a PKI identity, so independently generated
/// self-signed certs must be accepted here. Signature checks are retained to
/// prove possession of the presented certificate key. Public HTTPS uses the
/// separate PKI-verifying path in `tls.rs` and never this verifier.
impl rustls::client::danger::ServerCertVerifier for SessionBoundQuicServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn build_quic_client_config(
    ctx: &TransportContext,
    alpn: Vec<Vec<u8>>,
) -> Result<quinn::ClientConfig> {
    let mut client_crypto = (*ctx.tls.client_config).clone();
    client_crypto.alpn_protocols = effective_quic_alpn(alpn);
    client_crypto
        .dangerous()
        .set_certificate_verifier(SessionBoundQuicServerVerifier::new());
    let client_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).map_err(quic_error)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    // Anti-censorship P1 #4: Chrome-mimic transport parameters
    // (see chrome_mimic_transport_config docs above).
    client_config.transport_config(Arc::new(chrome_mimic_transport_config()));
    Ok(client_config)
}

fn build_quic_server_config(
    ctx: &TransportContext,
    alpn: Vec<Vec<u8>>,
) -> Result<quinn::ServerConfig> {
    let mut server_crypto = (*ctx.tls.server_config).clone();
    server_crypto.alpn_protocols = effective_quic_alpn(alpn);
    let server_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).map_err(quic_error)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    // Anti-censorship P1 #4: same Chrome-mimic transport params on
    // the accept side.  Servers and clients negotiate the min of each
    // side's advertised value, so symmetry minimizes the chance that
    // a DPI middlebox observes a transport-params mismatch.
    server_config.transport_config(Arc::new(chrome_mimic_transport_config()));
    Ok(server_config)
}

fn build_client_endpoint(bind_addr: std::net::SocketAddr) -> Result<quinn::Endpoint> {
    use socket2::{Domain, Protocol, Socket, Type};
    use veil_util::outbound_interface::{SocketFamilies, configure_outbound_socket};

    let socket = Socket::new(
        Domain::for_address(bind_addr),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    let families = if bind_addr.is_ipv6() {
        match socket.set_only_v6(false) {
            Ok(()) => SocketFamilies::Dual,
            Err(error) => {
                log::debug!("failed to enable QUIC dual-stack socket: {error}");
                SocketFamilies::V6
            }
        }
    } else {
        SocketFamilies::V4
    };
    configure_outbound_socket(&socket, families)?;
    socket.bind(&bind_addr.into())?;
    let socket: std::net::UdpSocket = socket.into();
    socket.set_nonblocking(true)?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(Into::into)
}

fn build_punched_endpoint(
    socket: std::net::UdpSocket,
    server_config: quinn::ServerConfig,
) -> Result<quinn::Endpoint> {
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(Into::into)
}

/// Promote the exact UDP socket used for mapping discovery and hole punching
/// into a native QUIC byte-stream connection.
///
/// Consuming the socket is intentional: binding a fresh endpoint would choose
/// a different local port and invalidate the NAT mapping just opened by the
/// punch. Both roles install client and server configuration so role selection
/// remains a signaling policy, not a different transport surface.
pub async fn promote_punched_quic(
    socket: tokio::net::UdpSocket,
    remote_addr: std::net::SocketAddr,
    ctx: Arc<TransportContext>,
    role: PunchedQuicRole,
) -> Result<Box<dyn TransportConnection>> {
    let alpn = Vec::new();
    let server_config = build_quic_server_config(&ctx, alpn.clone())?;
    let std_socket = socket.into_std()?;
    veil_util::outbound_interface::configure_outbound_socket(
        &std_socket,
        if remote_addr.is_ipv4() {
            veil_util::outbound_interface::SocketFamilies::V4
        } else {
            veil_util::outbound_interface::SocketFamilies::V6
        },
    )?;
    let mut endpoint = build_punched_endpoint(std_socket, server_config)?;
    endpoint.set_default_client_config(build_quic_client_config(&ctx, alpn)?);

    let host = remote_addr.ip().to_string();
    let uri = TransportUri::Quic {
        host: host.clone(),
        port: remote_addr.port(),
        sni: None,
        alpn: Vec::new(),
    };
    let local_addr = endpoint.local_addr().ok();

    let connection = match role {
        PunchedQuicRole::Initiator => {
            let connecting = endpoint.connect(remote_addr, ctx.effective_sni(None, &host))?;
            timeout(ctx.quic.connect_timeout, connecting)
                .await
                .map_err(|_| connect_timeout(ctx.quic.connect_timeout))??
        }
        PunchedQuicRole::Responder => {
            let incoming = timeout(ctx.quic.connect_timeout, async {
                loop {
                    let incoming = endpoint
                        .accept()
                        .await
                        .ok_or_else(|| quic_error("punched QUIC endpoint closed"))?;
                    if incoming.remote_address() == remote_addr {
                        return Ok::<_, TransportError>(incoming);
                    }
                    // The punch established one expected peer-reflexive source.
                    // Ignore unrelated QUIC Initials instead of allowing them to
                    // consume this one-shot promotion.
                    incoming.refuse();
                }
            })
            .await
            .map_err(|_| connect_timeout(ctx.quic.connect_timeout))??;
            // Convert the one-shot `Incoming` into `Connecting` before it is
            // wrapped in a cancellable timeout. This is the same ownership
            // rule as the normal listener paths below: cancellation must drop
            // a handshake future, never an unconsumed Quinn incoming whose
            // accept state can be re-entered during unwind.
            let connecting = incoming.accept().map_err(quic_error)?;
            timeout(ctx.quic.handshake_timeout, connecting)
                .await
                .map_err(|_| handshake_timeout(ctx.quic.handshake_timeout))??
        }
    };

    let stream: BoxIoStream = match role {
        PunchedQuicRole::Initiator => {
            let (send, recv) = timeout(ctx.quic.handshake_timeout, connection.open_bi())
                .await
                .map_err(|_| handshake_timeout(ctx.quic.handshake_timeout))??;
            Box::new(QuicBidiStream { recv, send })
        }
        PunchedQuicRole::Responder => {
            let (send, recv) = timeout(ctx.quic.handshake_timeout, connection.accept_bi())
                .await
                .map_err(|_| handshake_timeout(ctx.quic.handshake_timeout))??;
            Box::new(QuicBidiStream { recv, send })
        }
    };
    let peer_meta = native_quic_peer(uri, local_addr, Some(remote_addr));
    Ok(boxed_quic_connection(
        peer_meta, endpoint, connection, stream,
    ))
}

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
        let stream = self
            .stream
            .take()
            .ok_or_else(|| TransportError::Unsupported("stream already taken".to_owned()))?;
        Ok(Box::new(QuicOwnedStream {
            inner: stream,
            _endpoint: self._endpoint.clone(),
            _connection: self.connection.clone(),
        }))
    }

    fn quic_connection(&self) -> Option<quinn::Connection> {
        Some(self.connection.clone())
    }

    fn quic_datagrams(&self) -> Option<QuicDatagramHandle> {
        Some(QuicDatagramHandle {
            connection: self.connection.clone(),
        })
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

/// Bound the QUIC handshake + first-stream accept (audit cycle-8 H2). The QUIC
/// `accept()` and `accept_bi()` were previously UNbounded; a peer that starts a
/// connection then stalls could hold the accept path indefinitely.
const QUIC_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
            // Consume `Incoming` exactly once before wrapping the handshake in
            // a timeout. Passing `Incoming` itself through the generic
            // `IntoFuture` adapter can re-enter its consuming `accept()` while
            // unwinding a cancelled accept; quinn then panics on its empty
            // internal state. `Connecting` is the actual cancellable future.
            let connecting = incoming.accept().map_err(quic_error)?;
            let connection = tokio::time::timeout(QUIC_HANDSHAKE_TIMEOUT, connecting)
                .await
                .map_err(|_| quic_error("quic handshake timed out"))??;
            let remote_addr = connection.remote_address();
            let peer_meta = native_quic_peer(self.bind_uri.clone(), local_addr, Some(remote_addr));

            let stream: BoxIoStream = {
                let (send, recv) =
                    tokio::time::timeout(QUIC_HANDSHAKE_TIMEOUT, connection.accept_bi())
                        .await
                        .map_err(|_| quic_error("quic accept_bi timed out"))??;
                Box::new(QuicBidiStream { recv, send })
            };

            Ok(boxed_quic_connection(
                peer_meta,
                self.endpoint.clone(),
                connection,
                stream,
            ))
        })
    }

    /// cycle-8 H2: split the QUIC connection accept (fast) from the handshake +
    /// first bidi-stream accept (slow, attacker-driven, previously UNbounded).
    /// The peer address is known pre-handshake via `Incoming::remote_address`.
    fn accept_split<'a>(&'a self) -> BoxFuture<'a, Result<RawInbound>> {
        Box::pin(async move {
            let incoming = self
                .endpoint
                .accept()
                .await
                .ok_or_else(|| quic_error("endpoint closed"))?;
            let local_addr = incoming
                .local_ip()
                .map(|ip| std::net::SocketAddr::new(ip, 0));
            let remote_addr = incoming.remote_address();
            let bind_uri = self.bind_uri.clone();
            let endpoint = self.endpoint.clone();
            let finish: BoxFuture<'static, Result<Box<dyn TransportConnection>>> =
                Box::pin(async move {
                    // See `accept()` above: consume Incoming once, then time
                    // out the resulting handshake future.
                    let connecting = incoming.accept().map_err(quic_error)?;
                    let connection = tokio::time::timeout(QUIC_HANDSHAKE_TIMEOUT, connecting)
                        .await
                        .map_err(|_| quic_error("quic handshake timed out"))??;
                    let peer_meta = native_quic_peer(bind_uri, local_addr, Some(remote_addr));
                    let stream: BoxIoStream = {
                        let (send, recv) =
                            tokio::time::timeout(QUIC_HANDSHAKE_TIMEOUT, connection.accept_bi())
                                .await
                                .map_err(|_| quic_error("quic accept_bi timed out"))??;
                        Box::new(QuicBidiStream { recv, send })
                    };
                    Ok(boxed_quic_connection(
                        peer_meta, endpoint, connection, stream,
                    ))
                });
            Ok(RawInbound {
                remote_addr: Some(remote_addr),
                finish,
            })
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

            Ok(boxed_quic_connection(
                peer_meta, endpoint, connection, stream,
            ))
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
    /// must produce concrete values matching Chromium's QUIC params, not
    /// the quinn defaults (which are wildly different — initial_max_data
    /// defaults to `VarInt::MAX` for example).  This test pins the
    /// concrete constants so a quinn upgrade that changes its defaults
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
    /// stable from ~v120 (which dropped the `h3-29 / h3-32` draft
    /// variants).  A DPI fingerprint check on the ClientHello ALPN
    /// list would flag any variant.
    #[test]
    fn default_alpn_is_h3_only() {
        assert_eq!(DEFAULT_QUIC_ALPN, b"h3");
        let effective = effective_quic_alpn(vec![]);
        assert_eq!(effective, vec![b"h3".to_vec()]);
    }

    /// Operator-supplied ALPN overrides the default — so test harnesses
    /// can use a distinct ALPN to isolate test traffic without dragging in
    /// production's anti-DPI guarantees.
    #[test]
    fn user_supplied_alpn_overrides_default() {
        let user = vec![b"my-test-proto".to_vec()];
        let effective = effective_quic_alpn(user.clone());
        assert_eq!(effective, user);
    }

    #[tokio::test]
    async fn punched_socket_is_reused_for_quic_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let initiator_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let responder_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let initiator_addr = initiator_socket.local_addr().unwrap();
        let responder_addr = responder_socket.local_addr().unwrap();
        let ctx = Arc::new(TransportContext::for_debug().unwrap());

        let responder_ctx = Arc::clone(&ctx);
        let responder_task = tokio::spawn(async move {
            promote_punched_quic(
                responder_socket,
                initiator_addr,
                responder_ctx,
                PunchedQuicRole::Responder,
            )
            .await
        });
        let initiator = promote_punched_quic(
            initiator_socket,
            responder_addr,
            Arc::clone(&ctx),
            PunchedQuicRole::Initiator,
        )
        .await
        .unwrap();
        assert_eq!(initiator.peer_meta().local_addr, Some(initiator_addr));
        let initiator_datagrams = initiator.quic_datagrams().unwrap();

        let mut initiator_stream = initiator.into_stream().unwrap();
        // QUIC bidi streams are advertised lazily on first write. Real session
        // startup writes its handshake immediately; do the same before awaiting
        // the responder's `accept_bi`.
        initiator_stream.write_all(b"veil").await.unwrap();
        let responder = responder_task.await.unwrap().unwrap();
        assert_eq!(responder.peer_meta().local_addr, Some(responder_addr));
        let responder_datagrams = responder.quic_datagrams().unwrap();
        assert!(initiator_datagrams.max_size().is_some());
        assert_eq!(
            initiator_datagrams.send_buffer_space(),
            REALTIME_DATAGRAM_BUFFER_BYTES,
        );
        initiator_datagrams.send(b"rt-datagram").unwrap();
        assert_eq!(responder_datagrams.recv().await.unwrap(), b"rt-datagram");
        let mut responder_stream = responder.into_stream().unwrap();
        let (read_done_tx, read_done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut bytes = [0u8; 4];
            responder_stream.read_exact(&mut bytes).await.unwrap();
            responder_stream.write_all(&bytes).await.unwrap();
            responder_stream.flush().await.unwrap();
            let _ = read_done_rx.await;
        });
        let mut echoed = [0u8; 4];
        initiator_stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"veil");
        let _ = read_done_tx.send(());
        server.await.unwrap();
    }
}
