use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("{0}")]
    Config(#[from] veil_cfg::ConfigError),
    #[error("{0}")]
    Transport(#[from] veil_transport::TransportError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("node handshake error: {0}")]
    Handshake(String),
    #[error("unsupported node operation: {0}")]
    Unsupported(String),
    #[error("admin protocol error: {0}")]
    AdminProtocol(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

pub type Result<T> = std::result::Result<T, NodeError>;

// Phase 2 session 2 prep: session/handshake.rs defines its own narrow
// `HandshakeError` к avoid а dep on veilcore::node::error (which
// references `veil_transport::TransportError` и thus cannot move к
// the upcoming `veil-session` sibling crate без cycle).  This
// From-impl preserves the legacy ergonomic chain — runtime callers
// of `perform_ovl1_handshake` continue к use `?` against а
// `Result<T, NodeError>` signature без surface-level changes.
impl From<veil_session::handshake::HandshakeError> for NodeError {
    fn from(e: veil_session::handshake::HandshakeError) -> Self {
        NodeError::Handshake(e.0)
    }
}
