use std::{net::SocketAddr, sync::Arc};

use futures::future::{BoxFuture, ready};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{
    TransportContext,
    error::{Result, TransportError},
    uri::TransportUri,
};

/// Marker trait combining `AsyncRead + AsyncWrite + Send + Sync + Unpin`.
/// Every byte-oriented transport stream satisfies this bound.
pub trait IoStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

impl<T> IoStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

/// Boxed alias for `dyn IoStream` — the concrete handle returned by
/// `TransportConnection::into_stream`.
pub type BoxIoStream = Box<dyn IoStream>;

/// Message-style payload for transports that support framed sends/receives
/// (WebSocket). Byte-stream transports (TCP/TLS/QUIC) do not produce this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportMessage {
    /// Binary frame.
    Binary(Vec<u8>),
    /// UTF-8 text frame.
    Text(String),
}

/// Static feature flags describing what a `Transport` / `TransportConnection`
/// can do. Used by the OVL1 runtime to pick the right code path per peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransportCapabilities {
    /// Peer exposes a reliable ordered byte stream.
    pub byte_stream: bool,
    /// Peer supports unreliable datagrams (QUIC).
    pub datagrams: bool,
    /// Peer supports opening additional substreams (QUIC).
    pub substreams: bool,
    /// Peer speaks a message-oriented protocol (WebSocket).
    pub messages: bool,
    /// Connection uses the standard WebSocket HTTP upgrade handshake.
    pub browser_like_websocket_handshake: bool,
    /// Connection mimics a browser's TLS/QUIC fingerprint.
    pub browser_fingerprint_impersonation: bool,
    /// Transport attaches `TransportRuntimeInfo` to peer metadata.
    pub runtime_metadata: bool,
    /// Transport is a listener (not a connection).
    pub listener: bool,
}

impl TransportCapabilities {
    /// Capabilities for a byte-stream listener (TCP, TLS, Unix).
    pub const fn stream_listener() -> Self {
        Self {
            byte_stream: true,
            datagrams: false,
            substreams: false,
            messages: false,
            browser_like_websocket_handshake: false,
            browser_fingerprint_impersonation: false,
            runtime_metadata: true,
            listener: true,
        }
    }

    /// Capabilities for a byte-stream connection.
    pub const fn stream_connection() -> Self {
        Self {
            listener: false,
            ..Self::stream_listener()
        }
    }

    /// Capabilities for a WebSocket listener (message-oriented).
    pub const fn websocket_listener() -> Self {
        Self {
            messages: true,
            ..Self::stream_listener()
        }
    }

    /// Capabilities for a WebSocket connection.
    pub const fn websocket_connection() -> Self {
        Self {
            listener: false,
            ..Self::websocket_listener()
        }
    }

    /// Capabilities for a QUIC listener (stream + datagram + substream).
    pub const fn quic_listener() -> Self {
        Self {
            byte_stream: true,
            datagrams: true,
            substreams: true,
            messages: false,
            browser_like_websocket_handshake: false,
            browser_fingerprint_impersonation: false,
            runtime_metadata: true,
            listener: true,
        }
    }

    /// Capabilities for a QUIC connection.
    pub const fn quic_connection() -> Self {
        Self {
            listener: false,
            ..Self::quic_listener()
        }
    }
}

/// Handshake flavour actually performed on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // Variant names are self-describing.
pub enum TransportHandshakeMode {
    Stream,
    TlsRustls,
    /// BoringSSL-backed TLS with Chrome-like ClientHello
    /// fingerprint. Requires `tls-boring` feature.
    TlsBoring,
    QuicNative,
    WebSocketStandard,
}

/// Runtime metadata reported by a transport on every connection.
/// removed browser-impersonation variants, leaving only the handshake
/// flavour as useful runtime info; the struct is preserved so future
/// fields (cipher suite, ALPN, etc.) have a natural home.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportRuntimeInfo {
    /// Actual handshake flavour used.
    pub handshake_mode: TransportHandshakeMode,
}

/// Per-connection metadata about the remote peer.
#[derive(Clone, Debug)]
pub struct PeerMeta {
    /// URI scheme (`"tcp"`, `"tls"`, `"quic"`, …).
    pub scheme: &'static str,
    /// Full transport URI.
    pub uri: TransportUri,
    /// Local socket address after bind/connect (if applicable).
    pub local_addr: Option<SocketAddr>,
    /// Remote socket address (if applicable).
    pub remote_addr: Option<SocketAddr>,
    /// Human-readable description for logs.
    pub description: String,
    /// Runtime handshake info (None for legacy peers that don't report it).
    pub runtime_info: Option<TransportRuntimeInfo>,
}

pub(crate) fn native_runtime_info(handshake_mode: TransportHandshakeMode) -> TransportRuntimeInfo {
    TransportRuntimeInfo { handshake_mode }
}

pub(crate) fn standard_peer_meta(
    scheme: &'static str,
    uri: TransportUri,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
    handshake_mode: TransportHandshakeMode,
) -> PeerMeta {
    let description = remote_addr
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| uri.to_string());
    PeerMeta {
        scheme,
        uri,
        local_addr,
        remote_addr,
        description,
        runtime_info: Some(native_runtime_info(handshake_mode)),
    }
}

pub(crate) fn apply_standard_websocket_metadata(peer: &mut PeerMeta) {
    peer.runtime_info = Some(native_runtime_info(
        TransportHandshakeMode::WebSocketStandard,
    ));
}

/// A live peer connection produced by `Transport::connect` /
/// `TransportListener::accept`. Provides byte-stream access plus optional
/// message / datagram / substream APIs depending on transport capabilities.
pub trait TransportConnection: Send + Sync {
    /// Capability set advertised by this connection.
    fn capabilities(&self) -> &TransportCapabilities;
    /// Metadata about the remote peer.
    fn peer_meta(&self) -> &PeerMeta;
    /// Convert into a raw byte-stream handle, consuming the connection.
    fn into_stream(self: Box<Self>) -> Result<BoxIoStream>;

    /// return the underlying QUIC connection for pooling (if this is a QUIC transport).
    /// Default: `None` (TCP/TLS/WebSocket transports).
    fn quic_connection(&self) -> Option<quinn::Connection> {
        None
    }

    /// Send a datagram (QUIC only). Default: `Unsupported`.
    fn send_datagram<'a>(&'a self, _payload: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(ready(Err(TransportError::Unsupported(
            "datagrams are not supported".to_owned(),
        ))))
    }

    /// Receive a datagram (QUIC only). Default: `Unsupported`.
    fn recv_datagram<'a>(&'a self) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(ready(Err(TransportError::Unsupported(
            "datagrams are not supported".to_owned(),
        ))))
    }

    /// Open an additional substream on top of the connection (QUIC only).
    /// Default: `Unsupported`.
    fn open_substream<'a>(&'a self) -> BoxFuture<'a, Result<BoxIoStream>> {
        Box::pin(ready(Err(TransportError::Unsupported(
            "substreams are not supported".to_owned(),
        ))))
    }

    /// Send a framed message (WebSocket only). Default: `Unsupported`.
    fn send_message<'a>(&'a self, _message: TransportMessage) -> BoxFuture<'a, Result<()>> {
        Box::pin(ready(Err(TransportError::Unsupported(
            "message frames are not supported".to_owned(),
        ))))
    }

    /// Receive a framed message (WebSocket only). Default: `Unsupported`.
    fn recv_message<'a>(&'a self) -> BoxFuture<'a, Result<TransportMessage>> {
        Box::pin(ready(Err(TransportError::Unsupported(
            "message frames are not supported".to_owned(),
        ))))
    }

    /// Gracefully shut down the connection.
    fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<()>>;
}

/// Factory trait implemented by every transport. One instance is installed
/// per URI scheme [`super::TransportRegistry`].
pub trait Transport: Send + Sync {
    /// URI scheme this transport handles (`"tcp"`, `"tls"`, `"quic"`, …).
    fn scheme(&self) -> &'static str;
    /// Capability set exposed by this transport kind.
    fn capabilities(&self) -> TransportCapabilities;
    /// Open an outbound connection to `uri`.
    fn connect<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>>;
    /// Start listening on `uri`.
    fn bind<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>>;
}

/// Accepts inbound connections of a single transport kind.
pub trait TransportListener: Send + Sync {
    /// Await and return the next inbound connection.
    fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>>;
    /// Resolved local bind address, rendered as a string.
    fn local_addr(&self) -> String;
}
