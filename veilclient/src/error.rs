//! Error types for the veil client SDK.

use thiserror::Error;

/// Errors that can occur when using the veil client.
#[derive(Debug, Error)]
pub enum ClientError {
    /// I/O error communicating with the veil node.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The veil node rejected the hello handshake.
    #[error("handshake error (code {code}): {detail}")]
    Handshake { code: u16, detail: String },

    /// The veil node rejected an APP_BIND request.
    #[error("bind error (code {code}): {detail}")]
    Bind { code: u16, detail: String },

    /// Failed to open a stream to the remote endpoint.
    #[error("stream open error (code {code})")]
    StreamOpen { code: u16 },

    /// The connection was closed unexpectedly.
    #[error("connection closed")]
    ConnectionClosed,

    /// A protocol frame could not be decoded.
    #[error("protocol error: {0}")]
    Protocol(String),
}
