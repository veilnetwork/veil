//! Webtunnel-over-WSS transport.
//!
//! Stack: TCP → TLS (rustls) → HTTP/1.1 → WebSocket upgrade → byte stream.
//!
//! Server side: incoming requests са wrong secret path / auth get а decoy
//! HTML response (looks like а regular HTTPS site).  Tunnel-mode requests
//! upgrade к WebSocket binary frames carrying OVL1 plaintext.
//!
//! Client side: dials с realistic Chrome-like browser headers, completes
//! TLS+WS upgrade, exposes а transparent byte stream к session layer.
//!
//! Configuration via [`TransportContext`]:
//! - `webtunnel_secret_path`: e.g. `/_t/32-random-chars`
//! - `webtunnel_auth_token`: optional auth header value
//! - `webtunnel_decoy_dir`: directory с decoy site content
//!
//! In-process TLS uses the existing `ctx.tls.client_config` / `server_config`
//! infrastructure — same node-id-bound certs as other TLS transports.

use std::sync::Arc;

use futures::future::BoxFuture;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};
use veil_webtunnel::{
    DecoyProvider, SecretMatcher, StaticDirectoryDecoy, StaticStringDecoy, WebtunnelClient,
    WebtunnelRouter,
};

use super::{
    TransportContext,
    error::{Result, TransportError, handshake_timeout},
    traits::{
        BoxIoStream, Transport, TransportCapabilities, TransportConnection, TransportHandshakeMode,
        TransportListener, standard_peer_meta,
    },
    uri::TransportUri,
};

// Audit M-E: route the webtunnel CLIENT TLS handshake through the same
// backend-switched entry tls:// and wss:// use — BoringSSL Chrome-like
// ClientHello (with GREASE + extension permutation + rotation) under
// `tls-boring`, rustls otherwise — instead of a hard-coded `tokio_rustls`
// connector that always emitted the fixed rustls fingerprint, defeating
// webtunnel's own anti-DPI purpose in the default `tls-boring` build. This also
// makes the cert-trust semantics consistent with the other peer transports
// (node-id-bound trust at the session layer, not a PKI chain).
#[cfg(not(feature = "tls-boring"))]
use super::tls::connect_tls_client_stream;
#[cfg(feature = "tls-boring")]
use super::tls_boring::connect_tls_client_stream;

/// WSS-over-webtunnel transport.
#[derive(Debug, Default)]
pub struct WebtunnelWssTransport;

fn parts(uri: &TransportUri) -> Result<(&str, u16, Option<&str>)> {
    match uri {
        TransportUri::WebtunnelWss { host, port, sni } => {
            Ok((host.as_str(), *port, sni.as_deref()))
        }
        _ => Err(TransportError::Unsupported(format!(
            "webtunnel-wss transport cannot handle `{}`",
            uri.scheme()
        ))),
    }
}

fn build_matcher(ctx: &TransportContext) -> Result<SecretMatcher> {
    let path = ctx.webtunnel_secret_path.as_ref().ok_or_else(|| {
        TransportError::Unsupported(
            "webtunnel-wss requires `webtunnel_secret_path` в TransportContext".to_owned(),
        )
    })?;
    let m = match &ctx.webtunnel_auth_token {
        Some(tok) => SecretMatcher::with_auth(path.clone(), "X-Veil-Auth", (**tok).clone()),
        None => SecretMatcher::path_only(path.clone()),
    };
    Ok(m)
}

fn build_decoy(ctx: &TransportContext) -> Arc<dyn DecoyProvider> {
    match &ctx.webtunnel_decoy_dir {
        Some(dir) => Arc::new(StaticDirectoryDecoy::new(dir.clone())),
        None => Arc::new(StaticStringDecoy::new(
            "<!DOCTYPE html>\n<html><head><title>Welcome</title></head>\n<body><h1>Welcome</h1>\n<p>It works.</p></body></html>\n",
        )),
    }
}

fn build_client(ctx: &TransportContext, host: &str) -> Result<WebtunnelClient> {
    let path = ctx.webtunnel_secret_path.as_ref().ok_or_else(|| {
        TransportError::Unsupported(
            "webtunnel-wss client requires `webtunnel_secret_path`".to_owned(),
        )
    })?;
    let mut c = WebtunnelClient::new(path.clone()).with_host(host.to_owned());
    if let Some(tok) = &ctx.webtunnel_auth_token {
        c = c.with_auth("X-Veil-Auth", (**tok).clone());
    }
    Ok(c)
}

// ── WebSocketStream → AsyncRead+AsyncWrite bridge ───────────────────────────

/// Convert а WebSocketStream (Stream<Message> + Sink<Message>) к а byte
/// stream compatible с session-layer's BoxIoStream.  Reads pull binary
/// messages → bytes; writes wrap bytes в binary messages.
fn ws_to_byte_stream<S>(ws: WebSocketStream<S>) -> tokio::io::DuplexStream
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    const BRIDGE_BUFFER: usize = 64 * 1024;
    let (app_side, bridge_side) = duplex(BRIDGE_BUFFER);
    let (bridge_reader, bridge_writer) = tokio::io::split(bridge_side);
    let (ws_sink, ws_source) = ws.split();
    let ws_sink = Arc::new(Mutex::new(ws_sink));

    // ws → bridge_writer (inbound)
    tokio::spawn({
        let mut bridge_writer = bridge_writer;
        let mut ws_source = ws_source;
        async move {
            while let Some(msg) = ws_source.next().await {
                match msg {
                    Ok(Message::Binary(payload)) => {
                        if bridge_writer.write_all(&payload).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::Text(payload)) => {
                        if bridge_writer.write_all(payload.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
                    Ok(Message::Close(_)) | Ok(Message::Frame(_)) | Err(_) => break,
                }
            }
            let _ = bridge_writer.shutdown().await;
        }
    });

    // bridge_reader → ws_sink (outbound)
    tokio::spawn({
        let ws_sink = Arc::clone(&ws_sink);
        let mut bridge_reader = bridge_reader;
        async move {
            let mut buf = vec![0u8; 8 * 1024];
            loop {
                match bridge_reader.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        let mut s = ws_sink.lock().await;
                        let _ = s.close().await;
                        break;
                    }
                    Ok(n) => {
                        let mut s = ws_sink.lock().await;
                        if s.send(Message::Binary(buf[..n].to_vec())).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });

    app_side
}

// ── Transport impl ──────────────────────────────────────────────────────────

impl Transport for WebtunnelWssTransport {
    fn scheme(&self) -> &'static str {
        "webtunnel-wss"
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
            let (host, port, sni_override) = parts(uri)?;
            let server_name_str = ctx.effective_sni(sni_override, host).to_owned();

            // Audit M-E: backend-switched TLS handshake (morphs the ClientHello
            // fingerprint under `tls-boring`). Advertise no ALPN — matching the
            // previous behaviour, where `ctx.tls.client_config` had an empty
            // ALPN list — so the server falls back to HTTP/1.1 and the WebSocket
            // upgrade below succeeds. `connect_tls_client_stream` does the TCP
            // connect internally and returns a type-erased `BoxIoStream`, so the
            // peer addresses are reported as `None` (same as the wss:// path).
            let tls_stream =
                connect_tls_client_stream("webtunnel-wss", host, port, sni_override, &[], &ctx)
                    .await?;

            // Webtunnel HTTP+WS upgrade over the fingerprint-morphed TLS stream.
            let client = build_client(&ctx, &server_name_str)?;
            let ws = client
                .connect(tls_stream)
                .await
                .map_err(|e| TransportError::Tls(format!("webtunnel client: {e}")))?;

            let byte_stream = ws_to_byte_stream(ws);
            #[cfg(feature = "tls-boring")]
            let handshake_mode = TransportHandshakeMode::TlsBoring;
            #[cfg(not(feature = "tls-boring"))]
            let handshake_mode = TransportHandshakeMode::TlsRustls;
            let peer = standard_peer_meta("webtunnel-wss", uri.clone(), None, None, handshake_mode);
            Ok(super::tcp::boxed_stream_connection(peer, byte_stream))
        })
    }

    fn bind<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>> {
        Box::pin(async move {
            let (host, port, _sni) = parts(uri)?;
            let listener = TcpListener::bind((host, port)).await?;
            let matcher = build_matcher(&ctx)?;
            let decoy = build_decoy(&ctx);
            let router = WebtunnelRouter::new(matcher, decoy);
            let acceptor = TlsAcceptor::from(Arc::clone(&ctx.tls.server_config));
            Ok(Box::new(WebtunnelListener {
                listener,
                bind_uri: uri.clone(),
                router,
                acceptor,
            }) as Box<dyn TransportListener>)
        })
    }
}

struct WebtunnelListener {
    listener: TcpListener,
    bind_uri: TransportUri,
    router: WebtunnelRouter,
    acceptor: TlsAcceptor,
}

/// SECURITY (audit 2026-05-29): hard upper bound on the inline webtunnel
/// server handshake (TLS + HTTP/WS routing).  See the obfs4/tls/wss
/// listeners for the shared rationale (slowloris / accept-loop HOL DoS).
const WEBTUNNEL_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl TransportListener for WebtunnelListener {
    fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (tcp, remote_addr) = self.listener.accept().await?;
            let local_addr = tcp.local_addr().ok();

            // SECURITY (audit 2026-05-29, HIGH listener-DoS fix): bound the
            // inline TLS handshake AND the webtunnel HTTP/WS routing — both
            // read attacker-controlled bytes inside the accept future, so
            // either could otherwise wedge the accept loop on а silent
            // client.  Mirrors the obfs4/tls/wss listeners.
            let tls_stream =
                tokio::time::timeout(WEBTUNNEL_HANDSHAKE_TIMEOUT, self.acceptor.accept(tcp))
                    .await
                    .map_err(|_| handshake_timeout(WEBTUNNEL_HANDSHAKE_TIMEOUT))?
                    .map_err(|e| TransportError::Tls(format!("webtunnel TLS accept: {e}")))?;

            // Webtunnel routing — Box к break the recursive type.
            let ws = tokio::time::timeout(
                WEBTUNNEL_HANDSHAKE_TIMEOUT,
                self.router.handle(Box::new(tls_stream) as BoxIoStream),
            )
            .await
            .map_err(|_| handshake_timeout(WEBTUNNEL_HANDSHAKE_TIMEOUT))?
            .map_err(|e| TransportError::Tls(format!("webtunnel router: {e}")))?;

            let byte_stream = ws_to_byte_stream(ws);
            let peer = standard_peer_meta(
                "webtunnel-wss",
                self.bind_uri.clone(),
                local_addr,
                Some(remote_addr),
                TransportHandshakeMode::TlsRustls,
            );
            Ok(super::tcp::boxed_stream_connection(peer, byte_stream))
        })
    }

    fn local_addr(&self) -> String {
        self.listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| self.bind_uri.to_string())
    }
}
