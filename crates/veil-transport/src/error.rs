use std::{io, net::AddrParseError, time::Duration};

use thiserror::Error;

use super::tls_material::explain_tls_error;

/// Canonical error type for every `Transport` implementation. Higher-level
/// code converts this into `NodeError::Transport` via `#[from]`.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Malformed `transport://host:port?opts` URI.
    #[error("invalid transport URI: {0}")]
    InvalidUri(String),
    /// DNS lookup failed for the host portion of the URI.
    #[error("dns resolution failed: {0}")]
    Dns(String),
    /// TCP/QUIC `connect` did not complete within the configured deadline.
    #[error("connection timed out after {0:?}")]
    ConnectTimeout(Duration),
    /// TLS/OVL1 handshake did not complete within the configured deadline.
    #[error("handshake timed out after {0:?}")]
    HandshakeTimeout(Duration),
    /// Underlying I/O failure (socket closed, write error, …).
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// TLS layer reported a protocol or certificate error.
    #[error("tls error: {0}")]
    Tls(String),
    /// QUIC layer error surfaced from `quinn`.
    #[error("quic error: {0}")]
    Quic(String),
    /// WebSocket upgrade or framing error.
    #[error("websocket error: {0}")]
    WebSocket(String),
    /// The requested operation (scheme, feature) is not available.
    #[error("unsupported transport operation: {0}")]
    Unsupported(String),
}

pub(crate) fn connect_timeout(duration: Duration) -> TransportError {
    TransportError::ConnectTimeout(duration)
}

pub(crate) fn handshake_timeout(duration: Duration) -> TransportError {
    TransportError::HandshakeTimeout(duration)
}

pub(crate) fn tls_error(message: impl Into<String>) -> TransportError {
    TransportError::Tls(explain_tls_error(message))
}

pub(crate) fn quic_error(message: impl ToString) -> TransportError {
    TransportError::Quic(message.to_string())
}

pub(crate) fn websocket_error(message: impl ToString) -> TransportError {
    TransportError::WebSocket(message.to_string())
}

pub(crate) fn io_other_error(message: impl ToString) -> TransportError {
    TransportError::Io(io::Error::other(message.to_string()))
}

impl From<rustls::Error> for TransportError {
    fn from(value: rustls::Error) -> Self {
        tls_error(value.to_string())
    }
}

impl From<tokio_rustls::rustls::pki_types::InvalidDnsNameError> for TransportError {
    fn from(value: tokio_rustls::rustls::pki_types::InvalidDnsNameError) -> Self {
        Self::InvalidUri(value.to_string())
    }
}

impl From<quinn::ConnectError> for TransportError {
    fn from(value: quinn::ConnectError) -> Self {
        quic_error(value)
    }
}

impl From<quinn::ConnectionError> for TransportError {
    fn from(value: quinn::ConnectionError) -> Self {
        quic_error(value)
    }
}

impl From<quinn::ReadError> for TransportError {
    fn from(value: quinn::ReadError) -> Self {
        quic_error(value)
    }
}

impl From<quinn::WriteError> for TransportError {
    fn from(value: quinn::WriteError) -> Self {
        quic_error(value)
    }
}

impl From<quinn::ConfigError> for TransportError {
    fn from(value: quinn::ConfigError) -> Self {
        quic_error(value)
    }
}

impl From<AddrParseError> for TransportError {
    fn from(value: AddrParseError) -> Self {
        Self::InvalidUri(value.to_string())
    }
}

impl From<tokio_socks::Error> for TransportError {
    fn from(value: tokio_socks::Error) -> Self {
        io_other_error(value)
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for TransportError {
    fn from(value: tokio_tungstenite::tungstenite::Error) -> Self {
        websocket_error(value)
    }
}

/// Shorthand alias for `Result<T, TransportError>` used by every transport.
pub type Result<T> = std::result::Result<T, TransportError>;
