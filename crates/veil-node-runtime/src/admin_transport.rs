//! Admin transport — thin facade over [`veil_local_transport`]
//! (refactored from a stand-alone copy that had drifted by
//! hand for too long).
//!
//! Type aliases preserve the historical names (`AdminListener`
//! `AdminStream`, `AdminToken`, `AdminPeerInfo`) so call sites in
//! `node/admin.rs` keep working without churn. The only API differences
//! vs. the underlying `veil_local_transport` are:
//!
//! * [`AdminToken::from_hex`] returns [`crate::error::Result`] (wrapping
//!   the inner `std::io::Error` into `NodeError::AdminProtocol`) so admin
//!   error handling stays uniform.
//! * [`bind_unix`] / [`connect_unix`] / [`bind_tcp`] / [`connect_tcp`] /
//!   [`AdminListener::accept`] return [`crate::error::Result`] for the same
//!   reason.
//!
//! Behaviour and wire format are unchanged from the previous hand-rolled
//! implementation.
//!
//! switched from the deleted
//! `crate::node::local_transport` re-export shim to direct
//! `veil_local_transport::*` import.

use std::path::Path;

use crate::error::{NodeError, Result};
use veil_local_transport as local_transport;

/// Byte length of the admin-auth token. Re-exported [`local_transport`].
/// Public for cross-module test fixtures that build raw `AdminToken`s; the
/// non-test admin codepath uses `bind_tcp` which generates one internally.
///
/// gated to match the `impl AdminToken` block below — both have
/// only test callers today (`admin::tests::admin_tcp_*`, `admin_transport::tests::*`).
#[cfg(test)]
pub const ADMIN_TOKEN_BYTES: usize = local_transport::TOKEN_BYTES;

// ── AdminToken ────────────────────────────────────────────────────────────────

/// 32-byte cryptographically-random authentication token for the TCP-loopback
/// admin backend. Wraps [`local_transport::LocalToken`] only to provide a
/// `from_hex` returning [`NodeError`] instead of `std::io::Error`.
#[derive(Clone, Debug)]
pub struct AdminToken(local_transport::LocalToken);

/// Production admin code drives token generation through `bind_tcp` (which
/// constructs the inner `LocalToken` directly) and reads tokens via
/// `read_token_file`. These wrapper methods exist for test fixtures only.
///
/// switched from `#[allow(dead_code)]` to `#[cfg(test)]` — the
/// consumer surface hasn't needed any of these outside tests and the
/// previous annotation masked that. Drop the gate when (if) a direct
/// caller materialises.
#[cfg(test)]
impl AdminToken {
    /// Generate a fresh random token using `OsRng`.
    pub fn generate() -> Self {
        Self(local_transport::LocalToken::generate())
    }

    /// Construct from raw bytes.
    pub fn from_bytes(bytes: [u8; ADMIN_TOKEN_BYTES]) -> Self {
        Self(local_transport::LocalToken::from_bytes(bytes))
    }

    /// Borrow the raw byte representation. Symmetric with `from_bytes`;
    /// no tests read it back yet but the pair is kept together for API
    /// clarity.
    #[allow(dead_code)]
    pub fn as_bytes(&self) -> &[u8; ADMIN_TOKEN_BYTES] {
        self.0.as_bytes()
    }

    /// Encode as lowercase hex (64 chars).
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Decode from hex. Wraps the inner `std::io::Error` into
    /// [`NodeError::AdminProtocol`] so admin error handling stays uniform.
    pub fn from_hex(s: &str) -> Result<Self> {
        local_transport::LocalToken::from_hex(s)
            .map(Self)
            .map_err(|e| NodeError::AdminProtocol(format!("admin token: {e}")))
    }

    /// Constant-time comparison with another token.
    pub fn ct_eq(&self, other: &AdminToken) -> bool {
        self.0.ct_eq(&other.0)
    }
}

// ── token / port file helpers ────────────────────────────────────────────────

/// Write the admin token to `path` with owner-only permissions.
pub async fn write_token_file(path: &Path, token: &AdminToken) -> Result<()> {
    Ok(local_transport::write_token_file(path, &token.0).await?)
}

/// Read an admin token from `path`.
pub async fn read_token_file(path: &Path) -> Result<AdminToken> {
    let inner = local_transport::read_token_file(path)
        .await
        .map_err(|e| NodeError::AdminProtocol(format!("admin token file: {e}")))?;
    Ok(AdminToken(inner))
}

/// Write the kernel-assigned TCP port to `path` as decimal ASCII.
pub async fn write_port_file(path: &Path, port: u16) -> Result<()> {
    Ok(local_transport::write_port_file(path, port).await?)
}

/// Read the TCP port previously written by [`write_port_file`].
pub async fn read_port_file(path: &Path) -> Result<u16> {
    local_transport::read_port_file(path)
        .await
        .map_err(|e| NodeError::AdminProtocol(format!("admin port file: {e}")))
}

// ── AdminListener ─────────────────────────────────────────────────────────────

/// Platform-agnostic admin-protocol listener. Newtype around
/// [`local_transport::LocalListener`] so `accept` can return
/// [`crate::error::Result`] with admin-specific error wrapping.
pub struct AdminListener(local_transport::LocalListener);

impl AdminListener {
    /// Accept the next inbound admin connection. Wraps the underlying
    /// `std::io::Error` into [`NodeError::AdminProtocol`] for token-handshake
    /// failures (timeout / mismatch) so the admin server can log a uniform
    /// error class; transport-level I/O errors propagate as `NodeError::Io`.
    ///
    /// production callers use [`Self::accept_raw`] +
    /// task-spawned [`AdminPendingStream::verify`] for slow-loris
    /// resistance; this serial wrapper is retained for tests / docs.
    #[cfg(test)]
    pub async fn accept(&self) -> Result<(AdminStream, AdminPeerInfo)> {
        match self.0.accept().await {
            Ok((stream, peer_info)) => Ok((
                AdminStream(stream),
                AdminPeerInfo {
                    uid_matches_local: peer_info.uid_matches_local,
                },
            )),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::TimedOut,
                ) =>
            {
                Err(NodeError::AdminProtocol(e.to_string()))
            }
            Err(e) => Err(NodeError::from(e)),
        }
    }

    /// slow-loris fix: accept the raw kernel-level
    /// connection without performing the 32-byte token handshake.
    /// Returns immediately after `accept(2)` (μs); caller spawns
    /// a task that calls [`AdminPendingStream::verify`] to complete
    /// the handshake. Pre-fix, the admin accept loop awaited the
    /// 3 s token-read inline, so a single malicious connect-and-stall
    /// blocked admin for 3 s × N attempts.
    pub async fn accept_raw(&self) -> Result<(AdminPendingStream, AdminPeerInfo)> {
        let (pending, peer_info) = self.0.accept_raw().await?;
        Ok((
            AdminPendingStream(pending),
            AdminPeerInfo {
                uid_matches_local: peer_info.uid_matches_local,
            },
        ))
    }

    /// Return the locally-bound TCP address, if this is a TCP listener.
    ///
    /// ANCHOR (audit cycle-3, dead-code policy): currently uncalled — kept as
    /// the symmetric accessor to `AdminListener`'s inner transport for when a
    /// TCP admin endpoint writes its bound port to a discovery file (the Unix
    /// path already exposes its socket path). Remove if that never lands.
    #[allow(dead_code)]
    pub fn local_tcp_addr(&self) -> Option<std::net::SocketAddr> {
        self.0.local_tcp_addr()
    }
}

// ── AdminPendingStream ────────────────────────────────────────────────────────

/// a pre-handshake admin connection. Wraps
/// [`local_transport::PendingStream`] and translates handshake-time errors
/// (timeout / token mismatch) into [`NodeError::AdminProtocol`] for uniform
/// admin-server logging.
pub struct AdminPendingStream(local_transport::PendingStream);

impl AdminPendingStream {
    /// Complete the token handshake. Spawn this in a task so the accept loop
    /// is never blocked by a slow-loris client.
    pub async fn verify(self) -> Result<AdminStream> {
        match self.0.verify().await {
            Ok(stream) => Ok(AdminStream(stream)),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::TimedOut,
                ) =>
            {
                Err(NodeError::AdminProtocol(e.to_string()))
            }
            Err(e) => Err(NodeError::from(e)),
        }
    }
}

// ── AdminStream ───────────────────────────────────────────────────────────────

/// Platform-agnostic admin-protocol byte stream. Implements `AsyncRead` +
/// `AsyncWrite` via deref [`local_transport::LocalStream`].
pub struct AdminStream(local_transport::LocalStream);

impl std::fmt::Debug for AdminStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminStream(..)")
    }
}

impl tokio::io::AsyncRead for AdminStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for AdminStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

// ── AdminPeerInfo ─────────────────────────────────────────────────────────────

/// Peer-authentication summary produced on accept.
#[derive(Debug, Clone, Copy)]
pub struct AdminPeerInfo {
    /// `true` if the peer has been authenticated as the same local user that
    /// runs the node process. See [`local_transport::PeerInfo`] for the
    /// per-backend semantics.
    pub uid_matches_local: bool,
}

// ── bind / connect helpers ────────────────────────────────────────────────────

/// Bind an admin listener on a Unix domain socket.
#[cfg(unix)]
pub fn bind_unix(path: &Path) -> Result<AdminListener> {
    Ok(AdminListener(local_transport::bind_unix(path)?))
}

/// Connect to an admin listener over a Unix domain socket.
#[cfg(unix)]
pub async fn connect_unix(path: &Path) -> Result<AdminStream> {
    Ok(AdminStream(local_transport::connect_unix(path).await?))
}

/// Non-Unix stub. Returns [`NodeError::Unsupported`] for clean failure on
/// platforms without Unix sockets.
#[cfg(not(unix))]
#[allow(dead_code)]
pub fn bind_unix(_path: &Path) -> Result<AdminListener> {
    Err(NodeError::Unsupported(
        "Unix domain sockets are not supported on this platform".to_owned(),
    ))
}

/// Non-Unix stub — see [`bind_unix`].
#[cfg(not(unix))]
pub async fn connect_unix(_path: &Path) -> Result<AdminStream> {
    Err(NodeError::Unsupported(
        "Unix domain sockets are not supported on this platform".to_owned(),
    ))
}

/// Bind an admin listener on a loopback TCP port. Generates a fresh
/// [`AdminToken`]; the caller must persist it [`write_token_file`].
pub async fn bind_tcp(
    addr: std::net::SocketAddr,
) -> Result<(AdminListener, std::net::SocketAddr, AdminToken)> {
    let (listener, addr, token) = local_transport::bind_tcp(addr).await?;
    Ok((AdminListener(listener), addr, AdminToken(token)))
}

/// Connect to an admin listener over TCP and perform the token handshake.
pub async fn connect_tcp(addr: std::net::SocketAddr, token: &AdminToken) -> Result<AdminStream> {
    Ok(AdminStream(
        local_transport::connect_tcp(addr, &token.0).await?,
    ))
}

/// Windows NamedPipe bind facade.
#[cfg(windows)]
pub fn bind_named_pipe(name: &str) -> Result<(AdminListener, String, AdminToken)> {
    let (listener, name, token) = local_transport::bind_named_pipe(name)?;
    Ok((AdminListener(listener), name, AdminToken(token)))
}

/// Windows NamedPipe connect facade. Performs token handshake.
#[cfg(windows)]
pub async fn connect_named_pipe(name: &str, token: &AdminToken) -> Result<AdminStream> {
    Ok(AdminStream(
        local_transport::connect_named_pipe(name, &token.0).await?,
    ))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn token_generate_yields_unique_values() {
        let a = AdminToken::generate();
        let b = AdminToken::generate();
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn token_hex_roundtrip() {
        let t = AdminToken::generate();
        let hex = t.to_hex();
        assert_eq!(hex.len(), ADMIN_TOKEN_BYTES * 2);
        let back = AdminToken::from_hex(&hex).unwrap();
        assert!(t.ct_eq(&back));
    }

    #[test]
    fn token_hex_rejects_wrong_length_with_node_error() {
        let err = AdminToken::from_hex("deadbeef").unwrap_err();
        assert!(
            matches!(err, NodeError::AdminProtocol(_)),
            "must wrap io::Error into NodeError::AdminProtocol, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn token_file_roundtrip() {
        let dir = crate::test_support::scratch_dir("veil-admin-token-test");
        let path = dir.join("admin.token");

        let token = AdminToken::generate();
        write_token_file(&path, &token).await.unwrap();
        let read = read_token_file(&path).await.unwrap();
        assert!(token.ct_eq(&read));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn tcp_accept_with_valid_token_succeeds() {
        let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (listener, local_addr, token) = bind_tcp(bind_addr).await.unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, peer_info) = listener.accept().await.unwrap();
            assert!(peer_info.uid_matches_local);
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await.unwrap();
            stream.write_all(&b).await.unwrap();
            stream.flush().await.unwrap();
        });

        let mut client = connect_tcp(local_addr, &token).await.unwrap();
        client.write_all(&[0xAB]).await.unwrap();
        client.flush().await.unwrap();
        let mut echo = [0u8; 1];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(echo, [0xAB]);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_accept_with_wrong_token_returns_admin_protocol_error() {
        let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (listener, local_addr, _real) = bind_tcp(bind_addr).await.unwrap();

        let server = tokio::spawn(async move {
            let err = listener.accept().await.unwrap_err();
            assert!(
                matches!(err, NodeError::AdminProtocol(_)),
                "wrong-token reject must surface as AdminProtocol, got: {err:?}"
            );
        });

        let wrong = AdminToken::from_bytes([0xFFu8; ADMIN_TOKEN_BYTES]);
        let _ = connect_tcp(local_addr, &wrong).await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_accept_rejects_silent_client() {
        let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (listener, local_addr, _token) = bind_tcp(bind_addr).await.unwrap();

        let server = tokio::spawn(async move {
            let start = std::time::Instant::now();
            let err = listener.accept().await.unwrap_err();
            assert!(
                matches!(err, NodeError::AdminProtocol(_)),
                "silent-client reject must surface as AdminProtocol, got: {err:?}"
            );
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
        });

        let _silent = tokio::net::TcpStream::connect(local_addr).await.unwrap();
        server.await.unwrap();
    }
}
