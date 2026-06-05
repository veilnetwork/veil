//! IPC transport — thin facade over [`veil_local_transport`]
//! (refactored from a stand-alone copy of admin_transport that
//! had drifted by hand for too long).
//!
//! Type aliases preserve the historical names (`IpcListener`, `IpcStream`
//! `IpcToken`, `IpcReadHalf`, `IpcWriteHalf`) so existing call sites in
//! `node/ipc/server.rs` continue to work without churn. Behaviour and wire
//! format are unchanged from the previous hand-rolled implementation.
//!
//! # Backends (unchanged)
//!
//! * **Unix** (default on Unix) — file-mode `0o600`. No on-wire handshake.
//! * **TCP-loopback** (default on non-Unix; opt-in on Unix) — binds to
//!   `127.0.0.1:0`; a 32-byte token is generated at bind time and verified
//!   on every accept, before any IPC bytes are exchanged.

use std::path::Path;

use veil_local_transport as local_transport;

/// Byte length of the IPC-auth token. Re-exported [`local_transport`].
pub const IPC_TOKEN_BYTES: usize = local_transport::TOKEN_BYTES;

/// 32-byte cryptographically-random authentication token for the TCP-loopback
/// IPC backend. Alias [`local_transport::LocalToken`].
pub type IpcToken = local_transport::LocalToken;

/// Platform-agnostic IPC listener. Alias [`local_transport::LocalListener`].
pub type IpcListener = local_transport::LocalListener;

/// Platform-agnostic IPC byte stream. Alias [`local_transport::LocalStream`].
pub type IpcStream = local_transport::LocalStream;

/// Owned read half of an [`IpcStream`].
pub type IpcReadHalf = local_transport::LocalReadHalf;

/// Owned write half of an [`IpcStream`].
pub type IpcWriteHalf = local_transport::LocalWriteHalf;

// ── token / port file helpers ────────────────────────────────────────────────

/// Write the token to `path` with owner-only permissions (`0o600` on Unix).
pub async fn write_token_file(path: &Path, token: &IpcToken) -> std::io::Result<()> {
    local_transport::write_token_file(path, token).await
}

/// Read a token from `path`.
pub async fn read_token_file(path: &Path) -> std::io::Result<IpcToken> {
    local_transport::read_token_file(path).await
}

/// Write a TCP port to `path` with owner-only permissions (`0o600` on Unix).
/// Atomic — uses `OpenOptions::mode(0o600).create(true)` so there's no
/// world-readable window between create and chmod.
pub async fn write_port_file(path: &Path, port: u16) -> std::io::Result<()> {
    local_transport::write_port_file(path, port).await
}

/// Read a TCP port previously written by [`write_port_file`].
pub async fn read_port_file(path: &Path) -> std::io::Result<u16> {
    local_transport::read_port_file(path).await
}

// ── bind / connect helpers ────────────────────────────────────────────────────

/// Bind an IPC listener on a Unix domain socket.
#[cfg(unix)]
pub fn bind_unix(path: &Path) -> std::io::Result<IpcListener> {
    local_transport::bind_unix(path)
}

/// Connect to an IPC listener over a Unix domain socket.
#[cfg(unix)]
pub async fn connect_unix(path: &Path) -> std::io::Result<IpcStream> {
    local_transport::connect_unix(path).await
}

/// Non-Unix stub.
#[cfg(not(unix))]
pub fn bind_unix(path: &Path) -> std::io::Result<IpcListener> {
    local_transport::bind_unix(path)
}

/// Non-Unix stub.
#[cfg(not(unix))]
pub async fn connect_unix(path: &Path) -> std::io::Result<IpcStream> {
    local_transport::connect_unix(path).await
}

/// Bind an IPC listener on a loopback TCP port. Generates a fresh token;
/// the caller must persist it [`write_token_file`] so clients can find it.
pub async fn bind_tcp(
    addr: std::net::SocketAddr,
) -> std::io::Result<(IpcListener, std::net::SocketAddr, IpcToken)> {
    local_transport::bind_tcp(addr).await
}

/// Connect to an IPC listener over TCP and perform the token handshake.
pub async fn connect_tcp(
    addr: std::net::SocketAddr,
    token: &IpcToken,
) -> std::io::Result<IpcStream> {
    local_transport::connect_tcp(addr, token).await
}
