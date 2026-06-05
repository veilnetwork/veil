use std::sync::Arc;

use futures::future::BoxFuture;
use futures::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream as ServerTlsStream};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async, client_async,
    tungstenite::{Message, client::IntoClientRequest, http},
};

use super::{
    TransportContext,
    error::{Result, TransportError, handshake_timeout, tls_error, websocket_error},
    tcp::{connect_tcp_stream, peer_meta},
    traits::{
        BoxIoStream, PeerMeta, Transport, TransportCapabilities, TransportConnection,
        TransportListener, TransportMessage, apply_standard_websocket_metadata,
    },
    uri::TransportUri,
};

// route `wss://` through the same TLS backend as `tls://`
// (BoringSSL when `tls-boring` is enabled, rustls otherwise). The WebSocket
// handshake runs on top of the already-established TLS stream, which is
// backend-agnostic from the ws-framing layer's perspective.
#[cfg(not(feature = "tls-boring"))]
use super::tls::connect_tls_client_stream;
#[cfg(feature = "tls-boring")]
use super::tls_boring::connect_tls_client_stream;

/// SECURITY (audit 2026-05-29, HIGH listener-DoS fix): hard upper bound on
/// the inline WS/WSS server handshake (TLS handshake + WebSocket
/// upgrade).  Both run inside the `accept()` future before the runtime
/// accept-loop takes the next connection, so an unbounded read here lets
/// а silent client wedge the listener.  Mirrors the obfs4/tls listeners.
const WS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Plain `ws://` `Transport` — binary WebSocket framing over TCP, used for
/// browser-compatible deployments where raw TCP is unavailable.
#[derive(Debug, Default)]
pub struct WebSocketTransport;

/// `wss://` `Transport` — WebSocket over TLS. Negotiates a standard
/// HTTP/1.1 Upgrade after the TLS handshake so it survives corporate
/// middleboxes that allow HTTPS.
#[derive(Debug, Default)]
pub struct WebSocketSecureTransport;

const WS_BRIDGE_BUFFER_SIZE: usize = 64 * 1024;
const WS_MESSAGE_QUEUE_SIZE: usize = 128;

struct WebSocketConnection {
    capabilities: TransportCapabilities,
    peer_meta: PeerMeta,
    outbound_messages: mpsc::Sender<TransportMessage>,
    inbound_messages: Arc<Mutex<mpsc::Receiver<TransportMessage>>>,
    stream: Option<BoxIoStream>,
}

impl WebSocketConnection {
    fn new<S>(peer_meta: PeerMeta, ws_stream: WebSocketStream<S>) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (outbound_messages, inbound_messages, app_stream) = setup_websocket_bridge(ws_stream);

        Self {
            capabilities: TransportCapabilities::websocket_connection(),
            peer_meta,
            outbound_messages,
            inbound_messages,
            stream: Some(Box::new(app_stream)),
        }
    }
}

fn setup_websocket_bridge<S>(
    ws_stream: WebSocketStream<S>,
) -> (
    mpsc::Sender<TransportMessage>,
    Arc<Mutex<mpsc::Receiver<TransportMessage>>>,
    tokio::io::DuplexStream,
)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (app_stream, bridge_stream) = duplex(WS_BRIDGE_BUFFER_SIZE);
    let (bridge_reader, bridge_writer) = tokio::io::split(bridge_stream);
    let (ws_sink, ws_source) = ws_stream.split();
    let ws_sink = Arc::new(Mutex::new(ws_sink));
    let (outbound_messages, outbound_rx) = mpsc::channel(WS_MESSAGE_QUEUE_SIZE);
    let (inbound_tx, inbound_rx) = mpsc::channel(WS_MESSAGE_QUEUE_SIZE);

    spawn_websocket_inbound_task(ws_source, inbound_tx, bridge_writer);
    spawn_websocket_stream_bridge_task(bridge_reader, Arc::clone(&ws_sink));
    spawn_websocket_message_pump_task(outbound_rx, Arc::clone(&ws_sink));

    (
        outbound_messages,
        Arc::new(Mutex::new(inbound_rx)),
        app_stream,
    )
}

fn spawn_websocket_inbound_task<S>(
    ws_source: futures::stream::SplitStream<WebSocketStream<S>>,
    inbound_tx: mpsc::Sender<TransportMessage>,
    bridge_writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut ws_source = ws_source;
        let mut bridge_writer = bridge_writer;
        while let Some(message) = ws_source.next().await {
            match message {
                Ok(Message::Binary(payload)) => {
                    // Write bridge first (borrows payload), then move into channel.
                    if bridge_writer.write_all(&payload).await.is_err() {
                        break;
                    }
                    let _ = inbound_tx.send(TransportMessage::Binary(payload)).await;
                }
                Ok(Message::Text(payload)) => {
                    // Consistent ordering with Binary: bridge first, then channel.
                    if bridge_writer.write_all(payload.as_bytes()).await.is_err() {
                        break;
                    }
                    let _ = inbound_tx
                        .send(TransportMessage::Text(payload.to_string()))
                        .await;
                }
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {}
                Ok(Message::Close(_)) | Ok(Message::Frame(_)) | Err(_) => break,
            }
        }
        let _ = bridge_writer.shutdown().await;
    });
}

fn spawn_websocket_stream_bridge_task<S>(
    bridge_reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    ws_sink: Arc<Mutex<futures::stream::SplitSink<WebSocketStream<S>, Message>>>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut bridge_reader = bridge_reader;
        let mut buf = vec![0_u8; 8192];
        loop {
            match bridge_reader.read(&mut buf).await {
                Ok(0) => {
                    let mut ws_sink = ws_sink.lock().await;
                    let _ = ws_sink.close().await;
                    break;
                }
                Ok(read) => {
                    let mut ws_sink = ws_sink.lock().await;
                    if ws_sink
                        .send(Message::Binary(buf[..read].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => {
                    let mut ws_sink = ws_sink.lock().await;
                    let _ = ws_sink.close().await;
                    break;
                }
            }
        }
    });
}

fn spawn_websocket_message_pump_task<S>(
    outbound_rx: mpsc::Receiver<TransportMessage>,
    ws_sink: Arc<Mutex<futures::stream::SplitSink<WebSocketStream<S>, Message>>>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut outbound_rx = outbound_rx;
        while let Some(message) = outbound_rx.recv().await {
            let outbound = match message {
                TransportMessage::Binary(payload) => Message::Binary(payload),
                TransportMessage::Text(payload) => Message::Text(payload),
            };
            let mut ws_sink = ws_sink.lock().await;
            if ws_sink.send(outbound).await.is_err() {
                break;
            }
        }
    });
}

impl TransportConnection for WebSocketConnection {
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

    fn send_message<'a>(&'a self, message: TransportMessage) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.outbound_messages
                .send(message)
                .await
                .map_err(|_| websocket_error("websocket writer task is closed"))
        })
    }

    fn recv_message<'a>(&'a self) -> BoxFuture<'a, Result<TransportMessage>> {
        Box::pin(async move {
            self.inbound_messages
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| websocket_error("websocket reader task is closed"))
        })
    }

    fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.stream.take();
            Ok(())
        })
    }
}

struct WsListener {
    listener: TcpListener,
    bind_uri: TransportUri,
}

type WsConnectParts<'a> = (&'a str, u16, &'a str, Option<&'a str>);
type WssConnectParts<'a> = (
    &'a str,
    u16,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    &'a [Vec<u8>],
);
type WssBindParts<'a> = (&'a str, u16, Vec<Vec<u8>>);

struct WebSocketConnectTarget<'a> {
    scheme: &'static str,
    uri: TransportUri,
    host: &'a str,
    port: u16,
    path: &'a str,
    query: Option<&'a str>,
    local_addr: Option<std::net::SocketAddr>,
    remote_addr: Option<std::net::SocketAddr>,
}

fn ws_connect_parts(uri: &TransportUri) -> Result<WsConnectParts<'_>> {
    match uri {
        TransportUri::Ws {
            host,
            port,
            path,
            query,
        } => Ok((host.as_str(), *port, path.as_str(), query.as_deref())),
        _ => Err(TransportError::Unsupported(format!(
            "websocket transport cannot handle `{}`",
            uri.scheme()
        ))),
    }
}

fn ws_bind_parts(uri: &TransportUri) -> Result<(&str, u16)> {
    match uri {
        TransportUri::Ws { host, port, .. } => Ok((host.as_str(), *port)),
        _ => Err(TransportError::Unsupported(format!(
            "websocket transport cannot bind `{}`",
            uri.scheme()
        ))),
    }
}

fn wss_connect_parts(uri: &TransportUri) -> Result<WssConnectParts<'_>> {
    match uri {
        TransportUri::Wss {
            host,
            port,
            path,
            query,
            sni,
            alpn,
        } => Ok((
            host.as_str(),
            *port,
            path.as_str(),
            query.as_deref(),
            sni.as_deref(),
            alpn.as_slice(),
        )),
        _ => Err(TransportError::Unsupported(format!(
            "secure websocket transport cannot handle `{}`",
            uri.scheme()
        ))),
    }
}

fn wss_bind_parts(uri: &TransportUri) -> Result<WssBindParts<'_>> {
    match uri {
        TransportUri::Wss {
            host, port, alpn, ..
        } => Ok((host.as_str(), *port, alpn.clone())),
        _ => Err(TransportError::Unsupported(format!(
            "secure websocket transport cannot bind `{}`",
            uri.scheme()
        ))),
    }
}

fn listener_local_addr(listener: &TcpListener, bind_uri: &TransportUri) -> String {
    listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| bind_uri.to_string())
}

fn boxed_ws_listener(listener: TcpListener, bind_uri: TransportUri) -> Box<dyn TransportListener> {
    Box::new(WsListener { listener, bind_uri }) as Box<dyn TransportListener>
}

fn boxed_wss_listener(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    bind_uri: TransportUri,
) -> Box<dyn TransportListener> {
    Box::new(WssListener {
        listener,
        acceptor,
        bind_uri,
    }) as Box<dyn TransportListener>
}

/// Build a path-checking callback for `accept_hdr_async`.
type PathCallbackResult = std::result::Result<http::Response<()>, http::Response<Option<String>>>;
type PathCallback =
    Box<dyn FnOnce(&http::Request<()>, http::Response<()>) -> PathCallbackResult + Send + Unpin>;

/// When `expected_path` is `"/"` (the default — no explicit path configured)
/// all incoming paths are accepted for backward compatibility.
/// Otherwise the request path must match exactly; mismatches are rejected with
/// HTTP 404.
#[allow(clippy::result_large_err)] // Response<Option<String>> is the tungstenite ErrorResponse type; cannot be changed
fn make_path_callback(expected_path: String) -> PathCallback {
    Box::new(move |req, resp| {
        if expected_path == "/" || req.uri().path() == expected_path {
            Ok(resp)
        } else {
            // SAFETY — Response::builder с known-valid
            // status (constant) и Some-body cannot fail к build;.unwrap
            // here is provably-infallible. Use.expect для self-
            // documenting the invariant.
            Err(http::Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(Some(format!("path not found: {}", req.uri().path())))
                .expect("404 response с literal status + Some body is well-formed"))
        }
    })
}

/// Extract the configured listen path from a bind URI.
fn listen_path(uri: &TransportUri) -> String {
    match uri {
        TransportUri::Ws { path, .. } => path.clone(),
        TransportUri::Wss { path, .. } => path.clone(),
        _ => "/".to_owned(),
    }
}

async fn accept_ws_connection(
    scheme: &'static str,
    bind_uri: TransportUri,
    stream: TcpStream,
    remote_addr: std::net::SocketAddr,
) -> Result<Box<dyn TransportConnection>> {
    let local_addr = stream.local_addr().ok();
    let path = listen_path(&bind_uri);
    // SECURITY (audit 2026-05-29): bound the WS upgrade handshake.
    let ws_stream = tokio::time::timeout(
        WS_HANDSHAKE_TIMEOUT,
        accept_hdr_async(stream, make_path_callback(path)),
    )
    .await
    .map_err(|_| handshake_timeout(WS_HANDSHAKE_TIMEOUT))?
    .map_err(websocket_error)?;
    Ok(boxed_websocket_connection(
        standard_websocket_peer(scheme, bind_uri, local_addr, Some(remote_addr)),
        ws_stream,
    ))
}

async fn accept_wss_connection(
    bind_uri: TransportUri,
    acceptor: TlsAcceptor,
    stream: TcpStream,
    remote_addr: std::net::SocketAddr,
) -> Result<Box<dyn TransportConnection>> {
    let local_addr = stream.local_addr().ok();
    // SECURITY (audit 2026-05-29): bound the TLS handshake AND the WS
    // upgrade — either stage could otherwise hang on а silent client.
    let tls_stream: ServerTlsStream<TcpStream> =
        tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
            .await
            .map_err(|_| handshake_timeout(WS_HANDSHAKE_TIMEOUT))?
            .map_err(|err| tls_error(err.to_string()))?;
    let path = listen_path(&bind_uri);
    let ws_stream = tokio::time::timeout(
        WS_HANDSHAKE_TIMEOUT,
        accept_hdr_async(tls_stream, make_path_callback(path)),
    )
    .await
    .map_err(|_| handshake_timeout(WS_HANDSHAKE_TIMEOUT))?
    .map_err(websocket_error)?;
    Ok(boxed_websocket_connection(
        standard_websocket_peer("wss", bind_uri, local_addr, Some(remote_addr)),
        ws_stream,
    ))
}

async fn connect_ws_stream<S>(
    target: WebSocketConnectTarget<'_>,
    stream: S,
) -> Result<Box<dyn TransportConnection>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ws_stream = connect_websocket_client(
        target.scheme,
        target.host,
        target.port,
        target.path,
        target.query,
        stream,
    )
    .await?;
    Ok(boxed_websocket_connection(
        standard_websocket_peer(
            target.scheme,
            target.uri,
            target.local_addr,
            target.remote_addr,
        ),
        ws_stream,
    ))
}

impl TransportListener for WsListener {
    fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (stream, remote_addr) = self.listener.accept().await?;
            accept_ws_connection("ws", self.bind_uri.clone(), stream, remote_addr).await
        })
    }

    fn local_addr(&self) -> String {
        listener_local_addr(&self.listener, &self.bind_uri)
    }
}

struct WssListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    bind_uri: TransportUri,
}

impl TransportListener for WssListener {
    fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (stream, remote_addr) = self.listener.accept().await?;
            accept_wss_connection(
                self.bind_uri.clone(),
                self.acceptor.clone(),
                stream,
                remote_addr,
            )
            .await
        })
    }

    fn local_addr(&self) -> String {
        listener_local_addr(&self.listener, &self.bind_uri)
    }
}

impl Transport for WebSocketTransport {
    fn scheme(&self) -> &'static str {
        "ws"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities::websocket_listener()
    }

    fn connect<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (host, port, path, query) = ws_connect_parts(uri)?;
            let stream = connect_tcp_stream(host, port, &ctx).await?;
            let local_addr = stream.local_addr().ok();
            let remote_addr = stream.peer_addr().ok();
            connect_ws_stream(
                WebSocketConnectTarget {
                    scheme: "ws",
                    uri: uri.clone(),
                    host,
                    port,
                    path,
                    query,
                    local_addr,
                    remote_addr,
                },
                stream,
            )
            .await
        })
    }

    fn bind<'a>(
        &'a self,
        uri: &'a TransportUri,
        _ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>> {
        Box::pin(async move {
            let (host, port) = ws_bind_parts(uri)?;
            let listener = TcpListener::bind((host, port)).await?;
            Ok(boxed_ws_listener(listener, uri.clone()))
        })
    }
}

impl Transport for WebSocketSecureTransport {
    fn scheme(&self) -> &'static str {
        "wss"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities::websocket_listener()
    }

    fn connect<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (host, port, path, query, sni, alpn) = wss_connect_parts(uri)?;
            let tls_stream = connect_tls_client_stream("wss", host, port, sni, alpn, &ctx).await?;
            connect_ws_stream(
                WebSocketConnectTarget {
                    scheme: "wss",
                    uri: uri.clone(),
                    host,
                    port,
                    path,
                    query,
                    local_addr: None,
                    remote_addr: None,
                },
                tls_stream,
            )
            .await
        })
    }

    fn bind<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>> {
        Box::pin(async move {
            let (host, port, alpn) = wss_bind_parts(uri)?;
            let listener = TcpListener::bind((host, port)).await?;
            let mut server_config = (*ctx.tls.server_config).clone();
            // default to h2 when operator did not specify `?alpn=...`
            // so WSS listeners advertise standard HTTP/2 instead of an empty
            // list that some DPI flags as suspicious.
            server_config.alpn_protocols = crate::tls::effective_alpn(&alpn);
            Ok(boxed_wss_listener(
                listener,
                TlsAcceptor::from(Arc::new(server_config)),
                uri.clone(),
            ))
        })
    }
}

fn standard_websocket_peer(
    scheme: &'static str,
    uri: TransportUri,
    local_addr: Option<std::net::SocketAddr>,
    remote_addr: Option<std::net::SocketAddr>,
) -> PeerMeta {
    let mut peer = peer_meta(scheme, uri, local_addr, remote_addr);
    apply_standard_websocket_metadata(&mut peer);
    peer
}

fn boxed_websocket_connection<S>(
    peer: PeerMeta,
    ws_stream: WebSocketStream<S>,
) -> Box<dyn TransportConnection>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    Box::new(WebSocketConnection::new(peer, ws_stream)) as Box<dyn TransportConnection>
}

async fn connect_websocket_client<S>(
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
    query: Option<&str>,
    stream: S,
) -> Result<WebSocketStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let request = ws_request(scheme, host, port, path, query)?;
    let (ws_stream, _) = client_async(request, stream).await?;
    Ok(ws_stream)
}

fn ws_request(
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
    query: Option<&str>,
) -> Result<tokio_tungstenite::tungstenite::http::Request<()>> {
    let path_and_query = match query {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };
    format!("{scheme}://{}{}", authority(host, port), path_and_query)
        .into_client_request()
        .map_err(websocket_error)
}

fn authority(host: &str, port: u16) -> String {
    match port {
        80 | 443 => host.to_owned(),
        _ => format!("{host}:{port}"),
    }
}

#[cfg(test)]
mod tests {
    use super::make_path_callback;
    use tokio_tungstenite::tungstenite::http;

    fn make_request(path: &str) -> http::Request<()> {
        http::Request::builder()
            .uri(format!("ws://127.0.0.1{path}"))
            .body(())
            .unwrap()
    }

    fn ok_response() -> http::Response<()> {
        http::Response::builder().status(101).body(()).unwrap()
    }

    #[test]
    fn path_slash_accepts_any_request_path() {
        // When the configured path is "/" (no explicit path), all paths are accepted.
        let cb = make_path_callback("/".to_owned());
        let result = cb(&make_request("/veil"), ok_response());
        assert!(result.is_ok(), "path '/' should accept any incoming path");
    }

    #[test]
    fn path_slash_accepts_root_path() {
        let cb = make_path_callback("/".to_owned());
        let result = cb(&make_request("/"), ok_response());
        assert!(result.is_ok());
    }

    #[test]
    fn explicit_path_accepts_matching_request() {
        let cb = make_path_callback("/veil".to_owned());
        let result = cb(&make_request("/veil"), ok_response());
        assert!(result.is_ok());
    }

    #[test]
    fn explicit_path_rejects_wrong_path_with_404() {
        let cb = make_path_callback("/veil".to_owned());
        let result = cb(&make_request("/wrong"), ok_response());
        let err_resp = result.expect_err("wrong path must be rejected");
        assert_eq!(err_resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[test]
    fn explicit_path_rejects_root_when_not_configured() {
        let cb = make_path_callback("/veil".to_owned());
        let result = cb(&make_request("/"), ok_response());
        assert!(
            result.is_err(),
            "root path should be rejected when path is /veil"
        );
    }
}
