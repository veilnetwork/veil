//! BoringSSL-backed TLS connect/accept with Chrome-like ClientHello fingerprint.
//!
//! # Feature gate
//!
//! This module is compiled only when `--features tls-boring` is set — which is
//! **on by default** for the `veil-cli` binary (it powers browser-like
//! ClientHello fingerprints + rotation, the censorship-resistance baseline).
//! Pure-Rust / cross-compile builds (routers, embedded, no `cmake`/C toolchain)
//! opt out with `--no-default-features --features rocksdb-cold`, which falls
//! back to the `rustls` stack [`super::tls`] (single, non-morphable
//! fingerprint). See [Cargo.toml] `tls-boring` feature docs + `docs/en/
//! OPERATIONS.md` → "TLS ClientHello fingerprint rotation".
//!
//! # Why BoringSSL
//!
//! `rustls` does not expose control over TLS ClientHello construction: the
//! cipher-suite order, extension order, and supported-group list are fixed by
//! the library, producing a distinctive JA3 fingerprint that on-path DPI can
//! block or throttle. BoringSSL (the crypto backend Chrome itself uses) lets
//! us emit a ClientHello that matches Chrome byte-for-byte, so veil traffic
//! blends into ordinary HTTPS.
//!
//! # Binding crate: `btls` (not `boring`)
//!
//! We use [`btls`] rather than Cloudflare's [`boring`] because the `btls`
//! ecosystem ships a working [`quinn-btls`] for QUIC, while the corresponding
//! `quinn-boring` is stuck on a yanked `boring` version. Both crates are
//! near-identical bindings to the same BoringSSL C source, but `btls`'s
//! `tokio-btls` wrapper uses the manual `SslStream::new + pin.connect`
//! pattern rather than `boring`'s `tokio_boring::connect(...)` helper.
//!
//! # Scope
//!
//! * Chrome TLS 1.3 + TLS 1.2 cipher preferences
//! * Supported curves: X25519, secp256r1, secp384r1
//! * ALPN wire format per Chrome (h2, http/1.1 by default)
//! * Custom certificate verifier disabled — veil uses node-id binding, not
//! DNS-based PKI validation
//!
//! # Limitations
//!
//! * BoringSSL does not expose `SSL_set_record_padding_callback`. TLS record
//! padding is done at the OVL1 framing layer instead — see
//! [`crate::node::session::runner::coalesce_with_padding`].

use std::pin::Pin;
use std::sync::Arc;

use btls::ssl::{AlpnError, SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
use futures::future::BoxFuture;
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_btls::SslStream;

use super::{
    TransportContext,
    error::{Result, TransportError, handshake_timeout, tls_error},
    fingerprint::{FingerprintProfile, TlsFingerprint},
    tcp::{StreamConnection, connect_tcp_stream, peer_meta},
    traits::{
        BoxIoStream, Transport, TransportCapabilities, TransportConnection, TransportHandshakeMode,
        TransportListener, native_runtime_info,
    },
    uri::TransportUri,
};

/// Encode ALPN list in wire format: `len1 bytes1 len2 bytes2 …`. BoringSSL
/// (`set_alpn_protos`) consumes this layout, not rustls's `Vec<Vec<u8>>`.
fn alpn_wire(alpn: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(alpn.iter().map(|p| 1 + p.len()).sum());
    for proto in alpn {
        // Audit L-14: SKIP entries that don't fit the u8 length prefix instead
        // of TRUNCATING them. The previous `.min(255)` emitted a corrupted ALPN
        // entry in release builds (the debug_assert is compiled out), silently
        // mis-negotiating the handshake. A >255-byte ALPN protocol id is never
        // legitimate (the wire format caps each entry at 255 bytes), so dropping
        // it is safe and avoids advertising a mangled value.
        if proto.len() > 255 {
            debug_assert!(false, "ALPN entry too long for u8 length prefix; skipped");
            continue;
        }
        out.push(proto.len() as u8);
        out.extend_from_slice(proto);
    }
    out
}

/// Server-side supported-groups list (X25519 first — Chrome-like). The
/// listener is not fingerprint-rotated; only the outbound ClientHello is.
pub(crate) const CHROME_CURVES_LIST: &str = "X25519:P-256:P-384";

/// Build a client SSL connector shaped to a specific [`FingerprintProfile`].
/// Caller supplies ALPN (already normalised by [`super::tls::effective_alpn`]).
/// `set_verify(NONE)` is unconditional — veil trust binds to the node-id,
/// not the TLS cert chain — so every profile works with self-signed certs.
fn build_client_connector(profile: &FingerprintProfile, alpn: &[Vec<u8>]) -> Result<SslConnector> {
    // btls exposes `SslMethod::tls` (unified client+server method) instead
    // of boring's separate `tls_client` / `tls_server`.
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| tls_error(format!("btls SslConnector::builder: {e}")))?;

    // Veil trust is anchored in the session-layer node-id binding, not the
    // TLS cert chain. Disable BoringSSL's built-in verification entirely so
    // self-signed veil peer certs are accepted regardless of fingerprint.
    builder.set_verify(SslVerifyMode::NONE);

    builder
        .set_cipher_list(&profile.tls12_ciphers)
        .map_err(|e| tls_error(format!("btls set_cipher_list ({}): {e}", profile.label)))?;
    builder
        .set_curves_list(&profile.curves)
        .map_err(|e| tls_error(format!("btls set_curves_list ({}): {e}", profile.label)))?;
    builder
        .set_sigalgs_list(&profile.sigalgs)
        .map_err(|e| tls_error(format!("btls set_sigalgs_list ({}): {e}", profile.label)))?;
    // GREASE + extension permutation are infallible setters in btls.
    builder.set_grease_enabled(profile.grease);
    builder.set_permute_extensions(profile.permute_extensions);

    let alpn_bytes = alpn_wire(alpn);
    if !alpn_bytes.is_empty() {
        builder
            .set_alpn_protos(&alpn_bytes)
            .map_err(|e| tls_error(format!("btls set_alpn_protos: {e}")))?;
    }

    Ok(builder.build())
}

/// Perform a TLS client handshake with the given fingerprint `profile` over an
/// already-connected stream.
pub(crate) async fn connect_tls_stream<S>(
    stream: S,
    host: &str,
    sni: Option<&str>,
    alpn: &[Vec<u8>],
    ctx: &TransportContext,
    profile: &FingerprintProfile,
) -> Result<SslStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let connector = build_client_connector(profile, alpn)?;
    // `into_ssl(domain)` takes ownership; pass effective SNI.
    let server_name = ctx.effective_sni(sni, host).to_owned();
    let ssl = connector
        .configure()
        .map_err(|e| tls_error(format!("btls configure: {e}")))?
        // Verify is already NONE via set_verify above; also disable hostname
        // matching so self-signed veil certs without the SNI-advertised
        // hostname in subject are accepted.
        .verify_hostname(false)
        .into_ssl(&server_name)
        .map_err(|e| tls_error(format!("btls into_ssl: {e}")))?;

    let mut stream =
        SslStream::new(ssl, stream).map_err(|e| tls_error(format!("btls SslStream::new: {e}")))?;

    timeout(ctx.tcp.connect_timeout, Pin::new(&mut stream).connect())
        .await
        .map_err(|_| handshake_timeout(ctx.tcp.connect_timeout))?
        .map_err(|err| tls_error(format!("btls handshake: {err}")))?;

    Ok(stream)
}

/// TLS handshake over an already-established stream (e.g. a SOCKS tunnel),
/// using the fingerprint policy's *preferred* profile. Does NOT rotate — the
/// underlying tunnel is already up, so re-dialing per fingerprint is the proxy
/// layer's concern; in `rotate` mode this presents the sticky last-known-good
/// (the head of `attempt_order`). Matches the rustls `connect_tls_stream`
/// arity so [`super::socks`] can call either backend uniformly.
pub(crate) async fn connect_tls_stream_proxied<S>(
    stream: S,
    host: &str,
    sni: Option<&str>,
    alpn: &[Vec<u8>],
    ctx: &TransportContext,
) -> Result<SslStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let fp = ctx
        .tls_fingerprint
        .attempt_order()
        .into_iter()
        .next()
        .map(|(_, fp)| fp)
        .unwrap_or(TlsFingerprint::Chrome);
    connect_tls_stream(
        stream,
        host,
        sni,
        alpn,
        ctx,
        &FingerprintProfile::resolve(fp),
    )
    .await
}

/// Connect to `host:port` with TLS-fingerprint rotation.
///
/// Tries each fingerprint from `ctx.tls_fingerprint.attempt_order()` over a
/// **fresh** TCP connection (a failed TLS handshake consumes the socket, and
/// presenting a different ClientHello requires a new connection) until one
/// completes the handshake. On success the winning rotation index is recorded
/// so sticky policies keep using the profile that worked. If every fingerprint
/// fails the TLS handshake, the last handshake error is returned. A TCP-level
/// dial failure is returned immediately — rotating the ClientHello cannot fix
/// an unreachable host or a dropped SYN.
async fn connect_tls_rotating(
    host: &str,
    port: u16,
    sni: Option<&str>,
    alpn: &[Vec<u8>],
    ctx: &TransportContext,
) -> Result<(
    SslStream<TcpStream>,
    Option<std::net::SocketAddr>,
    Option<std::net::SocketAddr>,
)> {
    let attempts = ctx.tls_fingerprint.attempt_order();
    let mut last_err: Option<TransportError> = None;
    for (rotation_idx, fp) in attempts {
        let profile = FingerprintProfile::resolve(fp);
        let stream = connect_tcp_stream(host, port, ctx).await?;
        let local_addr = stream.local_addr().ok();
        let remote_addr = stream.peer_addr().ok();
        match connect_tls_stream(stream, host, sni, alpn, ctx, &profile).await {
            Ok(tls) => {
                ctx.tls_fingerprint.record_success(rotation_idx);
                return Ok((tls, local_addr, remote_addr));
            }
            Err(e) => {
                log::debug!(
                    target: "tls.fingerprint",
                    "fingerprint '{}' failed TLS handshake to {host}:{port}, rotating: {e}",
                    profile.label
                );
                last_err = Some(e);
            }
        }
    }
    Err(last_err
        .unwrap_or_else(|| tls_error("tls-boring: no fingerprint candidates to try".to_owned())))
}

/// Build a btls-backed TLS acceptor for server listeners. Pulls the same
/// cert/key material as the rustls path (from `ctx.tls.server_config`) but
/// configures Chrome-like curve preferences.
fn build_tls_acceptor(ctx: &TransportContext, alpn: &[Vec<u8>]) -> Result<SslAcceptor> {
    use btls::pkey::PKey;
    use btls::x509::X509;

    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())
        .map_err(|e| tls_error(format!("btls SslAcceptor::mozilla_modern: {e}")))?;

    builder
        .set_curves_list(CHROME_CURVES_LIST)
        .map_err(|e| tls_error(format!("btls set_curves_list: {e}")))?;

    let chain = ctx.tls.server_cert_chain_der();
    let key_der = ctx.tls.server_private_key_der();

    let mut iter = chain.iter();
    let leaf_der = iter.next().ok_or_else(|| {
        TransportError::Unsupported("tls-boring: server cert chain is empty".to_owned())
    })?;
    let leaf = X509::from_der(leaf_der.as_ref())
        .map_err(|e| tls_error(format!("btls X509::from_der(leaf): {e}")))?;
    builder
        .set_certificate(&leaf)
        .map_err(|e| tls_error(format!("btls set_certificate: {e}")))?;
    for extra in iter {
        let cert = X509::from_der(extra.as_ref())
            .map_err(|e| tls_error(format!("btls X509::from_der(chain): {e}")))?;
        builder
            .add_extra_chain_cert(cert)
            .map_err(|e| tls_error(format!("btls add_extra_chain_cert: {e}")))?;
    }

    let key = PKey::private_key_from_pkcs8(key_der.secret_der())
        .or_else(|_| PKey::private_key_from_der(key_der.secret_der()))
        .map_err(|e| tls_error(format!("btls private_key_from_{{pkcs8|der}}: {e}")))?;
    builder
        .set_private_key(&key)
        .map_err(|e| tls_error(format!("btls set_private_key: {e}")))?;

    let alpn_bytes = alpn_wire(alpn);
    if !alpn_bytes.is_empty() {
        // Server-side ALPN: walk `client_protos` (u8-length-prefixed wire
        // format) and return the first entry we also advertise. Return slice
        // must share lifetime with `client_protos` per set_alpn_select_callback.
        let advertised_list: Vec<Vec<u8>> = alpn.to_vec();
        builder.set_alpn_select_callback(move |_ssl, client_protos: &[u8]| {
            let mut idx = 0usize;
            while idx < client_protos.len() {
                let len = client_protos[idx] as usize;
                let start = idx + 1;
                let end = start + len;
                if end > client_protos.len() {
                    break;
                }
                let candidate = &client_protos[start..end];
                if advertised_list.iter().any(|p| p.as_slice() == candidate) {
                    return Ok(candidate);
                }
                idx = end;
            }
            Err(AlpnError::NOACK)
        });
    }

    Ok(builder.build())
}

// ── Transport impl ───────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct TlsBoringTransport;

/// Parallels [`super::tls::connect_tls_client_stream`] — used by the `wss://`
/// transport [`super::websocket`] when the `tls-boring` feature is active.
pub async fn connect_tls_client_stream(
    _scheme: &'static str,
    host: &str,
    port: u16,
    sni: Option<&str>,
    alpn: &[Vec<u8>],
    ctx: &TransportContext,
) -> Result<BoxIoStream> {
    let (tls_stream, _local, _remote) = connect_tls_rotating(host, port, sni, alpn, ctx).await?;
    Ok(Box::new(tls_stream))
}

/// PKI-verified HTTPS handshake
/// for the bootstrap fetch path. Mirrors
/// [`super::tls::connect_pki_verified_https_stream`] — see that
/// function's doc-comment for the full rationale. Distinct from
/// [`connect_tls_client_stream`] which uses `SslVerifyMode::NONE` for
/// veil peer transport (where trust binds to node_id, not the
/// cert chain).
///
/// Builds a fresh PEER-verifying SSL connector with the system trust
/// store loaded via `set_default_verify_paths`. Hostname
/// verification is **enabled** (mandatory for a CDN target).
///
/// Note: this path intentionally does NOT apply the Chrome-fingerprint
/// cipher list / curve list — a CDN is a legitimate HTTPS target and
/// modern boringssl defaults are appropriate. The fingerprint-mimicking
/// path is still available [`connect_tls_client_stream`] for
/// veil peer traffic that needs DPI evasion.
pub async fn connect_pki_verified_https_stream(
    host: &str,
    port: u16,
    sni: Option<&str>,
    alpn: &[Vec<u8>],
    ctx: &TransportContext,
) -> Result<BoxIoStream> {
    let stream = connect_tcp_stream(host, port, ctx).await?;

    // PKI-verifying connector — distinct from
    // `build_chrome_client_connector` which sets verify=NONE.
    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| tls_error(format!("btls SslConnector::builder (pki): {e}")))?;
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_default_verify_paths()
        .map_err(|e| tls_error(format!("btls set_default_verify_paths: {e}")))?;
    let alpn_bytes = alpn_wire(alpn);
    if !alpn_bytes.is_empty() {
        builder
            .set_alpn_protos(&alpn_bytes)
            .map_err(|e| tls_error(format!("btls set_alpn_protos (pki): {e}")))?;
    }
    let connector = builder.build();

    let server_name = ctx.effective_sni(sni, host).to_owned();
    let ssl = connector
        .configure()
        .map_err(|e| tls_error(format!("btls configure (pki): {e}")))?
        // Bootstrap path REQUIRES hostname matching — a CDN serving
        // bootstrap content must present a cert whose SAN/CN matches
        // the URL host. Without this, MITM with a valid-but-unrelated
        // cert (e.g. one issued for a domain the attacker controls)
        // would still pass the trust-store check.
        .verify_hostname(true)
        .into_ssl(&server_name)
        .map_err(|e| tls_error(format!("btls into_ssl (pki): {e}")))?;

    let mut tls_stream = SslStream::new(ssl, stream)
        .map_err(|e| tls_error(format!("btls SslStream::new (pki): {e}")))?;

    timeout(ctx.tcp.connect_timeout, Pin::new(&mut tls_stream).connect())
        .await
        .map_err(|_| handshake_timeout(ctx.tcp.connect_timeout))?
        .map_err(|err| tls_error(format!("btls handshake (pki): {err}")))?;

    Ok(Box::new(tls_stream))
}

struct TlsBoringListener {
    listener: TcpListener,
    acceptor: Arc<SslAcceptor>,
    bind_uri: TransportUri,
}

fn native_tls_peer(
    uri: TransportUri,
    local_addr: Option<std::net::SocketAddr>,
    remote_addr: Option<std::net::SocketAddr>,
) -> crate::PeerMeta {
    let mut peer = peer_meta("tls", uri, local_addr, remote_addr);
    peer.runtime_info = Some(native_runtime_info(TransportHandshakeMode::TlsBoring));
    peer
}

fn boxed_tls_connection(
    peer: crate::PeerMeta,
    stream: impl super::traits::IoStream + 'static,
) -> Box<dyn TransportConnection> {
    Box::new(StreamConnection::new(peer, stream)) as Box<dyn TransportConnection>
}

/// Server-side handshake — wraps `SslStream::new + Pin::new.accept`.
async fn accept_tls_stream<S>(acceptor: &SslAcceptor, stream: S) -> Result<SslStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let ssl = btls::ssl::Ssl::new(acceptor.context())
        .map_err(|e| tls_error(format!("btls Ssl::new(acceptor.context): {e}")))?;
    let mut tls_stream = SslStream::new(ssl, stream)
        .map_err(|e| tls_error(format!("btls SslStream::new(server): {e}")))?;
    Pin::new(&mut tls_stream)
        .accept()
        .await
        .map_err(|e| tls_error(format!("btls accept: {e}")))?;
    Ok(tls_stream)
}

impl TransportListener for TlsBoringListener {
    fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (stream, remote_addr) = self.listener.accept().await?;
            let local_addr = stream.local_addr().ok();
            let tls_stream = accept_tls_stream(&self.acceptor, stream).await?;
            Ok(boxed_tls_connection(
                native_tls_peer(self.bind_uri.clone(), local_addr, Some(remote_addr)),
                tls_stream,
            ))
        })
    }

    fn local_addr(&self) -> String {
        self.listener
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| self.bind_uri.to_string())
    }
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
            "tls-boring transport cannot handle `{}`",
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
            "tls-boring transport cannot bind `{}`",
            uri.scheme()
        ))),
    }
}

impl Transport for TlsBoringTransport {
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
            let (tls_stream, local_addr, remote_addr) =
                connect_tls_rotating(host, port, sni, alpn, &ctx).await?;
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
            let acceptor = Arc::new(build_tls_acceptor(&ctx, alpn)?);
            Ok(Box::new(TlsBoringListener {
                listener,
                acceptor,
                bind_uri: uri.clone(),
            }) as Box<dyn TransportListener>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Chrome ClientHello shape ─────────────────────────────

    #[test]
    fn alpn_wire_format_matches_rfc7301() {
        let alpn = vec![b"h2".to_vec()];
        assert_eq!(alpn_wire(&alpn), vec![0x02, b'h', b'2']);

        let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        assert_eq!(
            alpn_wire(&alpn),
            vec![
                0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'
            ]
        );
    }

    #[test]
    fn alpn_wire_empty_produces_empty() {
        let alpn: Vec<Vec<u8>> = vec![];
        assert!(alpn_wire(&alpn).is_empty());
    }

    #[test]
    fn chrome_curves_starts_with_x25519() {
        assert!(
            CHROME_CURVES_LIST.starts_with("X25519:"),
            "curves list must start with X25519, got {CHROME_CURVES_LIST:?}"
        );
        assert!(CHROME_CURVES_LIST.contains("P-256"));
        assert!(CHROME_CURVES_LIST.contains("P-384"));
    }

    #[test]
    fn chrome_tls12_ciphers_lead_with_ecdhe_ecdsa_aes128_gcm() {
        use crate::fingerprint::{FingerprintProfile, TlsFingerprint};
        let chrome = FingerprintProfile::resolve(TlsFingerprint::Chrome);
        assert!(
            chrome
                .tls12_ciphers
                .starts_with("ECDHE-ECDSA-AES128-GCM-SHA256"),
            "Chrome TLS1.2 ciphers lead changed: {}",
            chrome.tls12_ciphers
        );
    }

    /// Every shipped fingerprint profile (and several randomised draws) must
    /// build a valid btls connector — catches an invalid cipher / curve /
    /// sigalg token in any profile's spec strings.
    #[test]
    fn every_profile_builds_a_valid_connector() {
        use crate::fingerprint::{FingerprintProfile, TlsFingerprint};
        let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        for fp in TlsFingerprint::ALL_CONCRETE {
            let profile = FingerprintProfile::resolve(fp);
            let c = build_client_connector(&profile, &alpn);
            assert!(c.is_ok(), "profile {fp:?} failed to build: {:?}", c.err());
        }
        // Randomised draws must also always be valid.
        for _ in 0..16 {
            let profile = FingerprintProfile::randomized();
            let c = build_client_connector(&profile, &alpn);
            assert!(
                c.is_ok(),
                "randomized profile failed to build: {:?} / {:?}",
                profile,
                c.err()
            );
        }
    }

    #[test]
    fn client_connector_builds_with_default_alpn() {
        use crate::fingerprint::{FingerprintProfile, TlsFingerprint};
        let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector =
            build_client_connector(&FingerprintProfile::resolve(TlsFingerprint::Chrome), &alpn);
        assert!(
            connector.is_ok(),
            "Chrome connector build: {:?}",
            connector.err()
        );
    }

    // ── on-the-wire ClientHello regression harness ───────────
    //
    // Catches the realistic regression that defeats DPI evasion: a btls
    // version bump or a refactor of `build_chrome_client_connector` silently
    // changes the ClientHello bytes so on-path DPI can fingerprint veil
    // traffic again. The unit tests above check the *configuration*; this
    // test captures the actual ClientHello off a live socket and parses out
    // the JA3-relevant fields. The schema we assert against is the Chrome
    // 120+ shape — same fields a JA3 hash is computed from.

    /// Decoded JA3-relevant fields from a captured ClientHello.
    #[derive(Debug)]
    struct ClientHelloShape {
        legacy_version: u16,
        cipher_suites: Vec<u16>,
        extensions: Vec<u16>,
        /// Contents of the supported_groups extension (0x000a), in order.
        supported_groups: Vec<u16>,
        /// Whether ALPN extension (0x0010) is present.
        has_alpn: bool,
        /// Whether supported_versions extension (0x002b) advertises TLS 1.3.
        offers_tls13: bool,
    }

    /// Parse a TLS Handshake record + ClientHello. Returns `None` if the
    /// bytes are not a well-formed ClientHello. Intentionally minimal —
    /// just enough to extract JA3 inputs, not a general TLS parser.
    fn parse_client_hello(buf: &[u8]) -> Option<ClientHelloShape> {
        if buf.len() < 5 + 4 + 34 {
            return None;
        }
        // Record header: type=0x16 handshake, version 0x03 0x0[1..3], len u16
        if buf[0] != 0x16 || buf[1] != 0x03 {
            return None;
        }
        let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let body = buf.get(5..5 + rec_len)?;
        // Handshake header: type=0x01 ClientHello, length u24
        if body.first()? != &0x01 {
            return None;
        }
        let mut p = 4; // skip handshake header
        let legacy_version = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]);
        p += 2;
        p += 32; // random
        let sid_len = *body.get(p)? as usize;
        p += 1 + sid_len;
        let cs_len = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
        p += 2;
        let cs_bytes = body.get(p..p + cs_len)?;
        p += cs_len;
        let mut cipher_suites = Vec::with_capacity(cs_len / 2);
        let mut i = 0;
        while i + 1 < cs_bytes.len() {
            cipher_suites.push(u16::from_be_bytes([cs_bytes[i], cs_bytes[i + 1]]));
            i += 2;
        }
        let comp_len = *body.get(p)? as usize;
        p += 1 + comp_len;
        let ext_total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
        p += 2;
        let ext_end = p + ext_total;
        let mut extensions = Vec::new();
        let mut supported_groups = Vec::new();
        let mut has_alpn = false;
        let mut offers_tls13 = false;
        while p + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([body[p], body[p + 1]]);
            let ext_len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
            p += 4;
            extensions.push(ext_type);
            let ext_data = body.get(p..p + ext_len)?;
            match ext_type {
                0x000a if ext_data.len() >= 2 => {
                    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    let list_bytes = ext_data.get(2..2 + list_len)?;
                    let mut j = 0;
                    while j + 1 < list_bytes.len() {
                        supported_groups
                            .push(u16::from_be_bytes([list_bytes[j], list_bytes[j + 1]]));
                        j += 2;
                    }
                }
                0x0010 => has_alpn = true,
                0x002b => {
                    // supported_versions: length-prefixed list of u16s; look for 0x0304 (TLS1.3)
                    if let Some(&len) = ext_data.first() {
                        let list = ext_data.get(1..1 + len as usize).unwrap_or(&[]);
                        let mut j = 0;
                        while j + 1 < list.len() {
                            if u16::from_be_bytes([list[j], list[j + 1]]) == 0x0304 {
                                offers_tls13 = true;
                                break;
                            }
                            j += 2;
                        }
                    }
                }
                _ => {}
            }
            p += ext_len;
        }
        Some(ClientHelloShape {
            legacy_version,
            cipher_suites,
            extensions,
            supported_groups,
            has_alpn,
            offers_tls13,
        })
    }

    /// Capture the first up-to-2048 bytes a btls client emits for a given
    /// fingerprint `fp` to a passive TCP listener (no TLS server response —
    /// the handshake will fail, but the ClientHello has already been written).
    async fn capture_client_hello(fp: crate::fingerprint::TlsFingerprint) -> Vec<u8> {
        use crate::fingerprint::FingerprintProfile;
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = vec![0u8; 2048];
                let n = s.read(&mut buf).await.unwrap_or(0);
                buf.truncate(n);
                let _ = tx.send(buf);
            }
        });
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let ctx = TransportContext::for_debug().expect("debug ctx");
        let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let profile = FingerprintProfile::resolve(fp);
        // Handshake is expected to fail — the listener never replies. We
        // only care about what bytes hit the wire on the way out.
        let _ = connect_tls_stream(stream, "127.0.0.1", None, &alpn, &ctx, &profile).await;
        tokio::time::timeout(std::time::Duration::from_secs(2), rx)
            .await
            .expect("captured ClientHello timed out")
            .expect("oneshot recv")
    }

    /// GREASE cipher/group values are `0x?a?a` (high byte == low byte, low
    /// nibble `0xa`). Strip them so two captures of the same profile compare
    /// equal despite per-handshake GREASE randomisation.
    fn strip_grease(values: &[u16]) -> Vec<u16> {
        values
            .iter()
            .copied()
            .filter(|v| {
                let hi = v >> 8;
                let lo = v & 0xff;
                !(hi == lo && (lo & 0x0f) == 0x0a)
            })
            .collect()
    }

    #[tokio::test]
    async fn epic480_6_chrome_client_hello_shape_regression() {
        let bytes = capture_client_hello(crate::fingerprint::TlsFingerprint::Chrome).await;
        let shape = parse_client_hello(&bytes).unwrap_or_else(|| {
            panic!(
                "ClientHello parse failed; first 32 bytes = {:02x?}",
                &bytes[..bytes.len().min(32)],
            )
        });

        // Chrome legacy_version field is 0x0303 (TLS 1.2) — TLS 1.3 is
        // negotiated inside supported_versions. rustls also uses 0x0303
        // so this alone doesn't distinguish, but a regression here would
        // mean btls produced something fundamentally non-TLS.
        assert_eq!(
            shape.legacy_version, 0x0303,
            "legacy_version must be 0x0303 (TLS1.2 record), got {:#06x}",
            shape.legacy_version
        );

        // Chrome offers many cipher suites (typically 15+); rustls offers
        // far fewer. A regression to 1-3 suites means btls fell back to
        // a minimal default.
        assert!(
            shape.cipher_suites.len() >= 8,
            "Chrome shape requires >= 8 cipher suites, got {}: {:#06x?}",
            shape.cipher_suites.len(),
            shape.cipher_suites
        );

        // First curve in supported_groups must be X25519 (0x001d) — this
        // is THE most fingerprintable single byte for Chrome vs everything
        // else. rustls in stock config offers X25519 too but in different
        // order; many other stacks offer secp256r1 first.
        assert!(
            !shape.supported_groups.is_empty(),
            "supported_groups extension missing or empty"
        );
        // GREASE is now enabled (matches real Chrome), so the list may lead
        // with a GREASE group — compare the first *real* group.
        let real_groups = strip_grease(&shape.supported_groups);
        assert_eq!(
            real_groups.first().copied(),
            Some(0x001d),
            "first non-GREASE supported_group must be X25519 (0x001d): {:#06x?}",
            shape.supported_groups
        );

        // Chrome always advertises ALPN (h2, http/1.1). Missing ALPN means
        // build_chrome_client_connector silently dropped set_alpn_protos.
        assert!(
            shape.has_alpn,
            "ALPN extension (0x0010) missing — Chrome always sends it"
        );

        // Chrome offers TLS 1.3 in supported_versions. Missing means btls
        // is stuck on TLS 1.2 only — instantly fingerprintable.
        assert!(
            shape.offers_tls13,
            "supported_versions must advertise TLS 1.3 (0x0304); ext list = {:#06x?}",
            shape.extensions
        );

        // Chrome ClientHello has many extensions (typically 12+). A drop
        // to 3-4 means we're emitting a minimal ClientHello that DPI can
        // separate from real Chrome traffic.
        assert!(
            shape.extensions.len() >= 8,
            "Chrome shape requires >= 8 extensions, got {}: {:#06x?}",
            shape.extensions.len(),
            shape.extensions
        );
    }

    /// End-to-end feature check: each non-Chrome profile emits a VALID
    /// ClientHello that is DISTINCT from Chrome's on the wire (GREASE-stripped
    /// cipher list differs). If the profiles all produced the same bytes,
    /// rotation would be pointless — this is what makes the feature real.
    #[tokio::test]
    async fn fingerprint_profiles_are_valid_and_distinct_on_the_wire() {
        use crate::fingerprint::TlsFingerprint;

        let chrome = parse_client_hello(&capture_client_hello(TlsFingerprint::Chrome).await)
            .expect("chrome CH parses");
        let chrome_ciphers = strip_grease(&chrome.cipher_suites);

        for fp in [TlsFingerprint::Firefox, TlsFingerprint::Safari] {
            let bytes = capture_client_hello(fp).await;
            let shape = parse_client_hello(&bytes)
                .unwrap_or_else(|| panic!("{fp:?} ClientHello failed to parse"));
            // Still a valid modern ClientHello.
            assert_eq!(shape.legacy_version, 0x0303, "{fp:?} legacy_version");
            assert!(shape.offers_tls13, "{fp:?} must offer TLS 1.3");
            assert!(shape.has_alpn, "{fp:?} must send ALPN");
            assert_eq!(
                strip_grease(&shape.supported_groups).first().copied(),
                Some(0x001d),
                "{fp:?} must lead supported_groups with X25519"
            );
            // …but materially different from Chrome on the wire (the point).
            assert_ne!(
                strip_grease(&shape.cipher_suites),
                chrome_ciphers,
                "{fp:?} cipher list must differ from Chrome (GREASE-stripped)"
            );
        }

        // Randomized must also be a valid modern ClientHello.
        let rnd = parse_client_hello(&capture_client_hello(TlsFingerprint::Randomized).await)
            .expect("randomized CH parses");
        assert!(
            rnd.offers_tls13 && rnd.has_alpn,
            "randomized must be valid+modern"
        );
        assert_eq!(
            strip_grease(&rnd.supported_groups).first().copied(),
            Some(0x001d),
            "randomized must lead supported_groups with X25519"
        );
    }
}
