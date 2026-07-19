//! Shared listener/stream/token plumbing for the **admin** and **IPC** local
//! protocols. Both planes need the same primitive: a
//! Unix-socket-or-TCP-loopback listener with an optional 32-byte token
//! handshake, behind a single `AsyncRead`+`AsyncWrite` enum. Before this
//! module they were two near-duplicate files (`admin_transport.rs` +
//! `ipc/transport.rs`) — kept in sync by hand and prone to drift.
//!
//! The split-half API ([`LocalStream::into_split`]) is needed by IPC for
//! concurrent reader/writer tasks; admin reuses the joined stream. `accept`
//! always returns a [`PeerInfo`]; BOTH planes consult its
//! `uid_matches_local` (computed via `SO_PEERCRED`/`getpeereid` on Unix) as a
//! kernel-level same-user gate, in addition to the on-disk 0o600 socket mode
//! and the 32-byte token handshake on the TCP backend. (On TCP / named-pipe
//! backends `uid_matches_local` is always true, so the check is a no-op
//! there and the token handshake is the gate.)
//!
//! # Errors
//!
//! All fallible APIs here return `std::io::Result` so the module stays
//! protocol-agnostic. Each facade (admin / IPC) wraps the result type
//! into its own error enum at the boundary.

use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Byte length of the auth token shared by admin and IPC TCP backends.
/// 32 bytes ≈ 128 bits of effective brute-force resistance after the OS RNG.
pub const TOKEN_BYTES: usize = 32;

/// Maximum time we wait for the client to send the token after `connect`.
const TOKEN_READ_TIMEOUT: Duration = Duration::from_secs(3);

// ── LocalToken ────────────────────────────────────────────────────────────────

/// 32-byte cryptographically-random authentication token. The token is
/// generated once at bind time (server side) and persisted to a file with
/// owner-only permissions; clients read the file and present the token as
/// the first 32 bytes after `connect`. Verified in constant time.
///
/// `ZeroizeOnDrop` so a panic-dump of the process memory
/// after the runtime tears down doesn't leave token plaintext sitting
/// around for forensics. The Drop impl runs during stack-unwind too
/// so even an unwinding panic clears tokens that pass through the
/// stack between `bind` and `connect`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LocalToken([u8; TOKEN_BYTES]);

impl LocalToken {
    /// Generate a fresh random token using `OsRng`.
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; TOKEN_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Construct from raw bytes.
    pub fn from_bytes(bytes: [u8; TOKEN_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw byte representation.
    pub fn as_bytes(&self) -> &[u8; TOKEN_BYTES] {
        &self.0
    }

    /// Encode as lowercase hex (64 chars). Convenient for storing in a
    /// text file readable by `cat`/scripts without binary handling.
    pub fn to_hex(&self) -> String {
        veil_util::bytes_to_hex(&self.0)
    }

    /// Decode from hex (accepts any-case; rejects invalid/length-wrong input).
    pub fn from_hex(s: &str) -> std::io::Result<Self> {
        let s = s.trim();
        if s.len() != TOKEN_BYTES * 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "token hex must be {} chars, got {}",
                    TOKEN_BYTES * 2,
                    s.len()
                ),
            ));
        }
        let mut bytes = [0u8; TOKEN_BYTES];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let hi = hex_nibble(s.as_bytes()[i * 2])?;
            let lo = hex_nibble(s.as_bytes()[i * 2 + 1])?;
            *byte = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }

    /// Constant-time comparison with another token.
    pub fn ct_eq(&self, other: &LocalToken) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl std::fmt::Debug for LocalToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LocalToken([redacted; {} bytes])", TOKEN_BYTES)
    }
}

fn hex_nibble(c: u8) -> std::io::Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid hex char {c:?} in token"),
        )),
    }
}

// ── token / port file helpers ────────────────────────────────────────────────

/// Write the token to `path` with owner-only permissions (`0o600` on Unix).
/// Any stale file at the path is overwritten.
///
/// Synchronous `std::fs` underneath — the write is 64 bytes of hex; avoiding
/// the tokio blocking-pool hop keeps bind-time latency deterministic when
/// many parallel tests compete for the pool.
pub async fn write_token_file(path: &Path, token: &LocalToken) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // No `remove_file` pre-step: `write_owner_only` (atomic_write) replaces the
    // target via a hardened staged rename, which avoids the symlink/TOCTOU
    // window that an unlink-then-create sequence opens.
    // hex-encoded copy is a heap String — zeroize it
    // before drop so the token bytes don't linger in heap memory
    // after this function returns. The on-disk file is the published
    // surface; in-process traces are not.
    let mut hex = token.to_hex();
    let result = write_owner_only(path, hex.as_bytes());
    hex.zeroize();
    result
}

/// Read a token from `path` previously written by [`write_token_file`].
pub async fn read_token_file(path: &Path) -> std::io::Result<LocalToken> {
    // read into a Vec we control + zeroize before drop
    // so the heap copy of the token plaintext doesn't outlive this
    // function. The returned LocalToken itself is ZeroizeOnDrop.
    let mut bytes = tokio::fs::read(path).await?;
    let parsed = std::str::from_utf8(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
        .and_then(LocalToken::from_hex);
    bytes.zeroize();
    parsed
}

/// Write the kernel-assigned TCP port to `path` as decimal ASCII, owner-only
/// permissions on Unix. Paired with [`read_port_file`].
pub async fn write_port_file(path: &Path, port: u16) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_owner_only(path, port.to_string().as_bytes())
}

/// Read the TCP port previously written by [`write_port_file`].
pub async fn read_port_file(path: &Path) -> std::io::Result<u16> {
    let bytes = tokio::fs::read(path).await?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    text.trim().parse::<u16>().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("port file contains invalid port `{text}`: {e}"),
        )
    })
}

/// create `path` with `0o600` mode *atomically* on Unix, then
/// write `bytes`. Using `OpenOptions::mode(0o600).create(true)` closes the
/// TOCTOU window where a `write` + post-chmod sequence briefly exposed
/// the file world-readable; any local process that won the race could scrape
/// an admin/ipc token off disk.
///
/// On non-Unix the mode bits are ignored (NTFS ACLs would need a separate
/// mechanism —).
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // Hardened against symlink / TOCTOU on the sidecar path: delegate to
    // `veil_util::atomic_write`, which stages to an UNPREDICTABLE
    // `<path>.tmp.<getrandom-hex>` opened `O_EXCL` + `O_NOFOLLOW` at mode
    // `0o600` (Unix), fsyncs, and atomically renames over `path` — replacing a
    // symlink rather than following it. This closes the previous
    // `remove_file` + `create(true)` window where a local attacker with write
    // access to a misconfigured runtime dir could pre-place a symlink and
    // capture/redirect the token/port write (the Unix-socket bind is already
    // hardened separately in `bind_unix`).
    veil_util::atomic_write(path, bytes)
}

// ── PeerInfo ──────────────────────────────────────────────────────────────────

/// Peer-authentication summary produced on accept.
#[derive(Debug, Clone, Copy)]
pub struct PeerInfo {
    /// `true` if the peer has been authenticated as the same local user that
    /// runs the node process. On Unix this is the `SO_PEERCRED`/`getpeereid`
    /// result; on TCP-loopback, where the token gates access, this is always
    /// `true` on successful accept (the token IS the uid-equivalent).
    pub uid_matches_local: bool,
}

// ── LocalListener ─────────────────────────────────────────────────────────────

/// Platform-agnostic local-socket listener used by both admin and IPC planes.
pub enum LocalListener {
    /// Unix domain socket listener. Auth is via file mode + `SO_PEERCRED`/
    /// `getpeereid`; no on-wire token handshake.
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
    /// TCP-loopback listener with token authentication. The expected token
    /// is stored alongside the listener and compared in constant time on
    /// every accept.
    Tcp {
        /// The bound listener.
        listener: tokio::net::TcpListener,
        /// Expected token — clients must send exactly these 32 bytes first.
        expected_token: LocalToken,
    },
    /// Windows NamedPipe listener with token authentication.
    /// Unlike TCP, NamedPipe has no persistent listener — a fresh
    /// `NamedPipeServer` instance is `create`d on every `accept` call
    /// then `connect.await` waits for a client. The pipe `name` (full
    /// `\\.\pipe\xxx` form) is stored so each accept knows what to bind.
    /// Default Windows DACL on the pipe permits any authenticated user to
    /// open it; the 32-byte token (file-protected by NTFS ACL) is the
    /// access-control gate, exactly as for TCP-loopback.
    #[cfg(windows)]
    NamedPipe {
        /// Full Windows pipe name, e.g. `\\.\pipe\veil-admin-1234`.
        name: String,
        /// Expected token — clients must send exactly these 32 bytes first.
        expected_token: LocalToken,
    },
}

/// audit: a raw-accepted local connection that has not yet
/// completed the token-handshake step. Caller obtains a `PendingStream`
/// [`LocalListener::accept_raw`] and must call [`Self::verify`] (in
/// a spawned task) to produce the authenticated [`LocalStream`].
///
/// Splitting the handshake out from the accept loop is the slow-loris fix:
/// pre-split, the accept loop awaited the 32-byte token read inline (with
/// 3 s timeout), so an attacker connecting to loopback TCP and not sending
/// a token blocked the entire accept loop for 3 s × N sequential
/// attempts. Post-split, the accept loop returns immediately after
/// the kernel-level TCP accept (μs); handshake runs in a task per
/// connection and cannot stall concurrent legitimate connects.
pub struct PendingStream {
    inner: PendingStreamInner,
}

enum PendingStreamInner {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    Tcp {
        stream: tokio::net::TcpStream,
        expected_token: LocalToken,
    },
    #[cfg(windows)]
    NamedPipe {
        server: tokio::net::windows::named_pipe::NamedPipeServer,
        expected_token: LocalToken,
    },
}

impl PendingStream {
    /// Complete the per-backend token handshake. TCP / NamedPipe paths
    /// read a 32-byte token [`TOKEN_READ_TIMEOUT`]; Unix returns
    /// immediately (handshake-free, kernel SO_PEERCRED is the gate).
    /// Returns a ready-to-use [`LocalStream`].
    pub async fn verify(self) -> std::io::Result<LocalStream> {
        match self.inner {
            #[cfg(unix)]
            PendingStreamInner::Unix(stream) => Ok(LocalStream::Unix(stream)),
            PendingStreamInner::Tcp {
                mut stream,
                expected_token,
            } => {
                let mut buf = [0u8; TOKEN_BYTES];
                let read_res =
                    tokio::time::timeout(TOKEN_READ_TIMEOUT, stream.read_exact(&mut buf)).await;
                match read_res {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "token read timed out",
                        ));
                    }
                }
                let presented = LocalToken::from_bytes(buf);
                if !expected_token.ct_eq(&presented) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "token mismatch",
                    ));
                }
                Ok(LocalStream::Tcp(stream))
            }
            #[cfg(windows)]
            PendingStreamInner::NamedPipe {
                mut server,
                expected_token,
            } => {
                let mut buf = [0u8; TOKEN_BYTES];
                let read_res =
                    tokio::time::timeout(TOKEN_READ_TIMEOUT, server.read_exact(&mut buf)).await;
                match read_res {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "token read timed out",
                        ));
                    }
                }
                let presented = LocalToken::from_bytes(buf);
                if !expected_token.ct_eq(&presented) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "token mismatch",
                    ));
                }
                Ok(LocalStream::NamedPipe(Box::new(server)))
            }
        }
    }
}

impl LocalListener {
    /// audit: accept the next raw inbound connection
    /// without performing the token-handshake step. Returns
    /// immediately after the kernel TCP-accept (μs); caller spawns
    /// a task that calls [`PendingStream::verify`] to complete the
    /// 32-byte token check. This is the slow-loris fix: pre-split
    /// a malicious client connecting to loopback TCP and not sending
    /// a token would stall the accept loop for 3 s × N attempts.
    /// Post-split, accept loop is not blocked by stragglers.
    ///
    /// `PeerInfo::uid_matches_local` is preset based on the backend
    /// (Unix: kernel SO_PEERCRED; TCP / NamedPipe: presumed-true
    /// confirmed when `verify` succeeds).
    pub async fn accept_raw(&self) -> std::io::Result<(PendingStream, PeerInfo)> {
        match self {
            #[cfg(unix)]
            Self::Unix(listener) => {
                let (stream, _addr) = listener.accept().await?;
                let uid_matches = unix_peer_uid_matches(&stream);
                Ok((
                    PendingStream {
                        inner: PendingStreamInner::Unix(stream),
                    },
                    PeerInfo {
                        uid_matches_local: uid_matches,
                    },
                ))
            }
            Self::Tcp {
                listener,
                expected_token,
            } => {
                let (stream, _addr) = listener.accept().await?;
                Ok((
                    PendingStream {
                        inner: PendingStreamInner::Tcp {
                            stream,
                            expected_token: expected_token.clone(),
                        },
                    },
                    PeerInfo {
                        uid_matches_local: true,
                    },
                ))
            }
            #[cfg(windows)]
            Self::NamedPipe {
                name,
                expected_token,
            } => {
                use tokio::net::windows::named_pipe::ServerOptions;
                let server = ServerOptions::new()
                    .first_pipe_instance(false)
                    .create(name)?;
                server.connect().await?;
                Ok((
                    PendingStream {
                        inner: PendingStreamInner::NamedPipe {
                            server,
                            expected_token: expected_token.clone(),
                        },
                    },
                    PeerInfo {
                        uid_matches_local: true,
                    },
                ))
            }
        }
    }

    /// Accept the next inbound connection and complete authentication
    /// inline (legacy serial path). Backwards-compat wrapper for
    /// callers that don't need slow-loris protection (e.g. tests).
    /// **Production callers should use [`Self::accept_raw`] +
    /// task-spawned [`PendingStream::verify`]** to keep the accept
    /// loop responsive under slow handshake clients.
    pub async fn accept(&self) -> std::io::Result<(LocalStream, PeerInfo)> {
        let (pending, peer) = self.accept_raw().await?;
        let stream = pending.verify().await?;
        Ok((stream, peer))
    }

    /// Return the locally-bound TCP address, if this is a TCP listener.
    /// Used by tests to query the kernel-assigned port without going through
    /// the on-disk `*.port` sidecar.
    pub fn local_tcp_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            #[cfg(unix)]
            Self::Unix(_) => None,
            Self::Tcp { listener, .. } => listener.local_addr().ok(),
            #[cfg(windows)]
            Self::NamedPipe { .. } => None,
        }
    }
}

// ── LocalStream + halves ──────────────────────────────────────────────────────

/// Marker trait for any duplex byte stream (used to type-erase
/// `NamedPipeServer` / `NamedPipeClient` since they don't share a common
/// concrete type in tokio). Requires `Sync` so `Box<dyn DuplexStream>` can
/// flow through the codebase's `Arc<Mutex<...>>` / `tokio::spawn` paths
/// without per-site trait-object-bound tweaks.
///
/// Only constructed by the `NamedPipe` variant of `LocalStream` (Windows
/// only). Gated to that target so non-Windows builds don't carry an
/// unused trait in the public crate surface.
#[cfg(windows)]
pub trait DuplexStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
#[cfg(windows)]
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + ?Sized> DuplexStream for T {}

/// Platform-agnostic local-socket byte stream. Implements `AsyncRead` +
/// `AsyncWrite` so framing code works against it without knowing the backend.
pub enum LocalStream {
    /// Unix domain socket stream.
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    /// TCP-loopback stream (already authenticated via token handshake).
    Tcp(tokio::net::TcpStream),
    /// Windows NamedPipe stream — type-erased so the same variant carries
    /// either a `NamedPipeServer` (from `accept`) or `NamedPipeClient` (from
    /// `connect_named_pipe`). Authenticated via token handshake.
    #[cfg(windows)]
    NamedPipe(Box<dyn DuplexStream>),
}

impl LocalStream {
    /// Split this stream into owned read and write halves so the IPC server
    /// can read from and write to it concurrently from different tasks.
    /// Admin doesn't use this — admin connections are single-threaded JSON
    /// request/response.
    pub fn into_split(self) -> (LocalReadHalf, LocalWriteHalf) {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => {
                let (r, w) = s.into_split();
                (LocalReadHalf::Unix(r), LocalWriteHalf::Unix(w))
            }
            Self::Tcp(s) => {
                let (r, w) = s.into_split();
                (LocalReadHalf::Tcp(r), LocalWriteHalf::Tcp(w))
            }
            #[cfg(windows)]
            Self::NamedPipe(s) => {
                // `tokio::io::split` works on any `AsyncRead + AsyncWrite`
                // including `Box<dyn DuplexStream>`. The resulting halves
                // share an internal lock — fine for our IPC pattern of one
                // reader + one writer task.
                let (r, w) = tokio::io::split(s);
                (LocalReadHalf::NamedPipe(r), LocalWriteHalf::NamedPipe(w))
            }
        }
    }
}

impl AsyncRead for LocalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(windows)]
            Self::NamedPipe(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(windows)]
            Self::NamedPipe(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_flush(cx),
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(windows)]
            Self::NamedPipe(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(windows)]
            Self::NamedPipe(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Owned read half of a [`LocalStream`].
pub enum LocalReadHalf {
    /// Unix domain socket read half.
    #[cfg(unix)]
    Unix(tokio::net::unix::OwnedReadHalf),
    /// TCP-loopback read half.
    Tcp(tokio::net::tcp::OwnedReadHalf),
    /// NamedPipe read half (from `tokio::io::split` on `Box<dyn DuplexStream>`).
    #[cfg(windows)]
    NamedPipe(tokio::io::ReadHalf<Box<dyn DuplexStream>>),
}

impl AsyncRead for LocalReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(windows)]
            Self::NamedPipe(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

/// Owned write half of a [`LocalStream`].
pub enum LocalWriteHalf {
    /// Unix domain socket write half.
    #[cfg(unix)]
    Unix(tokio::net::unix::OwnedWriteHalf),
    /// TCP-loopback write half.
    Tcp(tokio::net::tcp::OwnedWriteHalf),
    /// NamedPipe write half (from `tokio::io::split` on `Box<dyn DuplexStream>`).
    #[cfg(windows)]
    NamedPipe(tokio::io::WriteHalf<Box<dyn DuplexStream>>),
}

impl AsyncWrite for LocalWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(windows)]
            Self::NamedPipe(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_flush(cx),
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(windows)]
            Self::NamedPipe(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(unix)]
            Self::Unix(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(windows)]
            Self::NamedPipe(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// ── bind / connect helpers ────────────────────────────────────────────────────

/// Bind a listener on a Unix domain socket.
///
/// hardens the bind against pre-create / symlink-redirect
/// attacks on the `path`'s parent directory. Before calling
/// `UnixListener::bind` we:
///
/// 1. lstat `path` itself. If it exists and is a SYMLINK we refuse —
///    `UnixListener::bind` would dereference and create the socket at
///    the symlink target, which an attacker controls.
/// 2. lstat the PARENT directory. Refuse if:
///    it doesn't exist (operator misconfiguration; deliberate fail-fast)
///    it isn't owned by the current effective uid (someone else can
///    write into it; pre-create attack viable)
///    its mode allows group OR other write (`0o022` set).
/// 3. If the path exists as a regular socket file, unlink it first.
///    If it exists as anything else (regular file, FIFO, etc.) — refuse;
///    we'd be deleting operator data.
/// 4. Finally call `UnixListener::bind`. TOCTOU between step 3 and 4
///    is closed by step 2 (only this uid can write to the parent dir).
#[cfg(unix)]
pub fn bind_unix(path: &Path) -> std::io::Result<LocalListener> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    // Step 1: refuse symlinks at the path itself.
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(std::io::Error::other(format!(
                "refusing to bind admin socket: {:?} is a symlink — symlink-redirect attack vector",
                path
            )));
        }
        Ok(_) | Err(_) => {} // either non-symlink (handled below) or absent
    }

    // Step 2: parent directory ownership + mode check.
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::other(format!(
            "admin socket path {:?} has no parent directory",
            path
        ))
    })?;
    let parent_meta = std::fs::metadata(parent).map_err(|e| {
        std::io::Error::other(format!("admin socket parent {:?} stat failed: {e}", parent))
    })?;
    if !parent_meta.is_dir() {
        return Err(std::io::Error::other(format!(
            "admin socket parent {:?} is not a directory",
            parent
        )));
    }
    // SAFETY: geteuid is always safe and infallible.
    let our_uid = unsafe { libc::geteuid() };
    let parent_mode = parent_meta.mode() & 0o7777;
    let sticky_bit_set = parent_mode & 0o1000 != 0;
    let world_or_group_writable = parent_mode & 0o022 != 0;

    // The /tmp-style case: world-writable directory WITH sticky bit
    // (0o1777) is acceptable. Pre-create-attack is mitigated because
    // sticky bit prevents non-owners from deleting our socket file
    // once we've created it, AND step 3 below refuses to delete an
    // attacker-pre-created file (unlink on a non-owned file in a
    // sticky dir returns EPERM, which we surface as a clean error
    // rather than blindly overwriting). Operator-controlled dirs
    // (e.g. ~/.veil) should still be 0o700-locked.
    if world_or_group_writable && !sticky_bit_set {
        return Err(std::io::Error::other(format!(
            "admin socket parent {:?} mode {:o} allows group/other write \
             without sticky bit — refusing to bind (pre-create attack vector)",
            parent, parent_mode
        )));
    }

    // Owner check only enforced when the dir is NOT world-writable+sticky;
    // /tmp is owned by root but every user can write into it, so requiring
    // owner-equality there would lock out unprivileged daemons that
    // legitimately use /tmp paths.
    if !sticky_bit_set && parent_meta.uid() != our_uid {
        return Err(std::io::Error::other(format!(
            "admin socket parent {:?} owned by uid {}, not us ({}) — refusing to bind",
            parent,
            parent_meta.uid(),
            our_uid
        )));
    }

    // Step 3: clean up a stale socket file iff it IS a socket (don't
    // delete operator data sitting at the same path).
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_socket()
    {
        std::fs::remove_file(path).map_err(|e| {
            std::io::Error::other(format!(
                "admin socket: failed to remove stale {:?}: {e}",
                path
            ))
        })?;
    } else if std::fs::symlink_metadata(path).is_ok() {
        return Err(std::io::Error::other(format!(
            "admin socket path {:?} exists but is not a socket — refusing to overwrite",
            path
        )));
    }

    // Step 4: actually bind.
    let listener = tokio::net::UnixListener::bind(path)?;
    Ok(LocalListener::Unix(listener))
}

/// Connect to a listener over a Unix domain socket.
#[cfg(unix)]
pub async fn connect_unix(path: &Path) -> std::io::Result<LocalStream> {
    let stream = tokio::net::UnixStream::connect(path).await?;
    Ok(LocalStream::Unix(stream))
}

/// Non-Unix stub. Kept for API symmetry; callers that reach it on Windows
/// get a clean `Unsupported` instead of a missing-symbol link error.
#[cfg(not(unix))]
pub fn bind_unix(_path: &Path) -> std::io::Result<LocalListener> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Unix domain sockets are not supported on this platform",
    ))
}

/// Non-Unix stub — see [`bind_unix`].
#[cfg(not(unix))]
pub async fn connect_unix(_path: &Path) -> std::io::Result<LocalStream> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Unix domain sockets are not supported on this platform",
    ))
}

/// Bind a listener on a loopback TCP port. Generates a fresh [`LocalToken`];
/// the caller must persist it [`write_token_file`] for clients to
/// discover. Returns the bound listener plus its kernel-assigned address
/// plus the expected token.
pub async fn bind_tcp(
    addr: std::net::SocketAddr,
) -> std::io::Result<(LocalListener, std::net::SocketAddr, LocalToken)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let token = LocalToken::generate();
    Ok((
        LocalListener::Tcp {
            listener,
            expected_token: token.clone(),
        },
        local,
        token,
    ))
}

/// Connect to a listener over TCP and perform the token handshake. The
/// `token` must match the value the server wrote to its token file at bind
/// time; on mismatch the server closes the connection without responding.
pub async fn connect_tcp(
    addr: std::net::SocketAddr,
    token: &LocalToken,
) -> std::io::Result<LocalStream> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    stream.write_all(token.as_bytes()).await?;
    stream.flush().await?;
    Ok(LocalStream::Tcp(stream))
}

/// 12: bind a NamedPipe listener on Windows. `name` must be the
/// full pipe form (e.g. `\\.\pipe\veil-admin-123`). A fresh [`LocalToken`]
/// is generated; the caller must persist it [`write_token_file`] so
/// clients can find it. See [`LocalListener::NamedPipe`] for ACL notes.
///
/// Returns the listener plus the pipe name (echoed back for logging) plus
/// the expected token.
#[cfg(windows)]
pub fn bind_named_pipe(name: &str) -> std::io::Result<(LocalListener, String, LocalToken)> {
    // Validate we can create at least one server instance up front — this
    // catches "path already exists + first_pipe_instance enforced" and
    // similar bind errors at config-time rather than at first-accept. The
    // temp instance is dropped immediately; `accept` will create the
    // real instance.
    {
        use tokio::net::windows::named_pipe::ServerOptions;
        let _probe = ServerOptions::new().create(name)?;
    }
    let token = LocalToken::generate();
    Ok((
        LocalListener::NamedPipe {
            name: name.to_owned(),
            expected_token: token.clone(),
        },
        name.to_owned(),
        token,
    ))
}

/// 12: connect to a NamedPipe listener and perform the token
/// handshake. The `token` must match the value the server wrote to its
/// token file at bind time; on mismatch the server closes the connection
/// without responding (same semantics as [`connect_tcp`]).
#[cfg(windows)]
pub async fn connect_named_pipe(name: &str, token: &LocalToken) -> std::io::Result<LocalStream> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let mut client = ClientOptions::new().open(name)?;
    client.write_all(token.as_bytes()).await?;
    client.flush().await?;
    Ok(LocalStream::NamedPipe(Box::new(client)))
}

// ── Unix peer-uid check ───────────────────────────────────────────────────────

/// Return `true` if the connecting peer has the same effective uid as the
/// current process. On unrecognized Unix the check defaults to `true`
/// (file-mode 0o600 still gates access).
#[cfg(unix)]
fn unix_peer_uid_matches(stream: &tokio::net::UnixStream) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `stream` owns the fd for the duration of this call;
        // `getsockopt(SO_PEERCRED)` is read-only and async-signal-safe.
        unsafe {
            let mut cred = libc::ucred {
                pid: 0,
                uid: 0,
                gid: 0,
            };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let fd = stream.as_raw_fd();
            let ret = libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            );
            if ret != 0 {
                return false;
            }
            cred.uid == libc::geteuid()
        }
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: see Linux branch; `getpeereid` is read-only.
        unsafe {
            let fd = stream.as_raw_fd();
            let mut uid: libc::uid_t = 0;
            let mut gid: libc::gid_t = 0;
            let ret = libc::getpeereid(fd, &mut uid, &mut gid);
            if ret != 0 {
                return false;
            }
            uid == libc::geteuid()
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        let _ = stream;
        true
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_generate_yields_unique_values() {
        let a = LocalToken::generate();
        let b = LocalToken::generate();
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn token_hex_roundtrip() {
        let t = LocalToken::generate();
        let hex = t.to_hex();
        assert_eq!(hex.len(), TOKEN_BYTES * 2);
        let back = LocalToken::from_hex(&hex).unwrap();
        assert!(t.ct_eq(&back));
    }

    #[test]
    fn token_hex_rejects_wrong_length() {
        assert!(LocalToken::from_hex("deadbeef").is_err());
        assert!(LocalToken::from_hex("").is_err());
    }

    #[test]
    fn token_hex_rejects_invalid_chars() {
        let mut s = "0".repeat(TOKEN_BYTES * 2);
        s.replace_range(0..1, "z");
        assert!(LocalToken::from_hex(&s).is_err());
    }

    /// confirm Zeroize actually zeros the inner array
    /// when the token is explicitly zeroized. We can't directly
    /// observe a Drop result (the value is gone), so use the explicit
    /// `Zeroize::zeroize` call which the Drop impl runs internally.
    #[test]
    fn token_zeroize_clears_inner_bytes() {
        let mut t = LocalToken::from_bytes([0xAAu8; TOKEN_BYTES]);
        // Sanity: bytes are non-zero before zeroize.
        assert!(t.as_bytes().iter().any(|&b| b != 0));
        t.zeroize();
        assert!(
            t.as_bytes().iter().all(|&b| b == 0),
            "zeroize must reset every byte to 0"
        );
    }

    #[tokio::test]
    async fn token_file_roundtrip() {
        use rand_core::{OsRng, RngCore};
        let nonce: u128 = (OsRng.next_u64() as u128) << 64 | OsRng.next_u64() as u128;
        let dir = std::env::temp_dir().join(format!(
            "veil-local-token-test-{}-{:032x}",
            std::process::id(),
            nonce,
        ));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("token");

        let token = LocalToken::generate();
        write_token_file(&path, &token).await.unwrap();

        let read = read_token_file(&path).await.unwrap();
        assert!(token.ct_eq(&read));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = tokio::fs::metadata(&path).await.unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

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
    async fn tcp_accept_with_wrong_token_rejected() {
        let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (listener, local_addr, _real) = bind_tcp(bind_addr).await.unwrap();

        let server = tokio::spawn(async move {
            let result = listener.accept().await;
            assert!(result.is_err(), "wrong token must be rejected");
        });

        let wrong = LocalToken::from_bytes([0xFFu8; TOKEN_BYTES]);
        let _ = connect_tcp(local_addr, &wrong).await;

        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_accept_rejects_silent_client() {
        let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (listener, local_addr, _token) = bind_tcp(bind_addr).await.unwrap();

        let server = tokio::spawn(async move {
            let start = std::time::Instant::now();
            let result = listener.accept().await;
            assert!(result.is_err(), "silent client must be rejected");
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "reject must happen within timeout window"
            );
        });

        let _silent = tokio::net::TcpStream::connect(local_addr).await.unwrap();
        server.await.unwrap();
    }

    /// regression: `accept_raw` must NOT block on
    /// a silent client. Pre-fix the accept loop awaited the 32-byte
    /// token read inline (with 3 s timeout); attaching N silent clients
    /// would stall the loop for 3 s × N seconds, blocking concurrent
    /// legitimate connects. Post-fix, `accept_raw` returns immediately
    /// after kernel TCP-accept, and `pending.verify` (which the caller
    /// runs in a spawned task) absorbs the stall.
    #[tokio::test]
    async fn tcp_accept_raw_unblocked_by_silent_client() {
        let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (listener, local_addr, token) = bind_tcp(bind_addr).await.unwrap();

        // Stall artist: connect, never send token.
        let _silent = tokio::net::TcpStream::connect(local_addr).await.unwrap();

        // accept_raw must complete promptly — well under TOKEN_READ_TIMEOUT.
        let start = std::time::Instant::now();
        let (silent_pending, _) =
            tokio::time::timeout(Duration::from_millis(500), listener.accept_raw())
                .await
                .expect("accept_raw blocks on silent client")
                .unwrap();
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "accept_raw should be ~instant after kernel accept"
        );

        // Legit client next — accept_raw must still return promptly
        // not waiting on the silent connection's handshake to time out.
        let legit_handle =
            tokio::spawn(async move { connect_tcp(local_addr, &token).await.unwrap() });
        let start2 = std::time::Instant::now();
        let (legit_pending, _) =
            tokio::time::timeout(Duration::from_secs(1), listener.accept_raw())
                .await
                .expect("accept_raw blocked behind silent client")
                .unwrap();
        assert!(
            start2.elapsed() < Duration::from_secs(1),
            "accept_raw must not be serialized behind stalled handshakes"
        );

        let legit_stream = legit_pending
            .verify()
            .await
            .expect("legit handshake should succeed");
        let _ = legit_handle.await.unwrap();
        drop(legit_stream);

        // Silent's verify will time out — that's fine, just ensure it
        // resolves to PermissionDenied / TimedOut and not panics.
        let silent_res = silent_pending.verify().await;
        assert!(silent_res.is_err());
    }

    #[tokio::test]
    async fn tcp_stream_split_reads_and_writes_concurrently() {
        let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (listener, local_addr, token) = bind_tcp(bind_addr).await.unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut rh, mut wh) = stream.into_split();
            let mut buf = [0u8; 4];
            rh.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, [1, 2, 3, 4]);
            wh.write_all(&[5, 6, 7, 8]).await.unwrap();
            wh.flush().await.unwrap();
        });

        let client = connect_tcp(local_addr, &token).await.unwrap();
        let (mut rh, mut wh) = client.into_split();
        wh.write_all(&[1, 2, 3, 4]).await.unwrap();
        wh.flush().await.unwrap();
        let mut reply = [0u8; 4];
        rh.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 6, 7, 8]);

        server.await.unwrap();
    }

    // ── bind_unix TOCTOU hardening ───────────────────────────

    #[cfg(unix)]
    fn unique_tmp_dir(label: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Root the socket-test dir at a SHORT base (`/tmp`), not
        // `std::env::temp_dir()`. On macOS `$TMPDIR` is a long
        // `/var/folders/xx/.../T/` path, and `<that>/<dir>/admin.sock`
        // overruns the AF_UNIX `sun_path` limit (`SUN_LEN`, 104 on macOS) —
        // `bind_unix` then fails with a cryptic "path too long" instead of
        // exercising the TOCTOU/permission logic these tests target. `/tmp`
        // is always present on unix (this fn is `#[cfg(unix)]`); the short
        // `vlt-` prefix leaves ample headroom under SUN_LEN.
        let dir = std::path::PathBuf::from("/tmp")
            .join(format!("vlt-{label}-{}-{n:x}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Lock down to 0700 — the bind_unix check refuses world/group writable.
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&dir).unwrap().permissions();
        p.set_mode(0o700);
        std::fs::set_permissions(&dir, p).unwrap();
        dir
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_unix_succeeds_in_owned_0700_dir() {
        let dir = unique_tmp_dir("happy");
        let path = dir.join("admin.sock");
        let _listener = bind_unix(&path).expect("bind in owned 0700 dir must succeed");
        assert!(path.exists(), "bind must create the socket file");
    }

    /// `LocalListener` doesn't impl Debug (we don't want runtime
    /// listeners to leak metadata via panic dump), so `Result::expect_err`
    /// can't be used. This helper unwraps to the error string for us.
    #[cfg(unix)]
    fn must_fail(r: std::io::Result<LocalListener>, ctx: &str) -> String {
        match r {
            Ok(_) => panic!("{ctx}: expected Err, got Ok"),
            Err(e) => e.to_string(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn bind_unix_refuses_symlink_at_path() {
        let dir = unique_tmp_dir("symlink");
        let target = dir.join("real.sock");
        let link = dir.join("admin.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = must_fail(bind_unix(&link), "symlink at bind path must be refused");
        assert!(
            err.contains("symlink"),
            "error must mention symlink-redirect attack vector: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bind_unix_refuses_world_writable_parent() {
        let dir = unique_tmp_dir("ww-parent");
        // Loosen parent to 0777 — simulates an operator-misconfigured
        // socket dir that could be pre-created into.
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&dir).unwrap().permissions();
        p.set_mode(0o777);
        std::fs::set_permissions(&dir, p).unwrap();
        let path = dir.join("admin.sock");
        let err = must_fail(bind_unix(&path), "0777 parent must be refused");
        assert!(
            err.contains("group/other write"),
            "error must mention parent-mode failure: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bind_unix_refuses_when_path_holds_regular_file() {
        let dir = unique_tmp_dir("regular");
        let path = dir.join("admin.sock");
        std::fs::write(&path, b"operator data").unwrap();
        let err = must_fail(bind_unix(&path), "non-socket existing file must be refused");
        assert!(
            err.contains("not a socket"),
            "error must explain why the existing file is not removed: {err}"
        );
        // Verify operator's data is still there — we did NOT delete it.
        let body = std::fs::read(&path).unwrap();
        assert_eq!(body, b"operator data");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_unix_accepts_sticky_world_writable_dir() {
        // /tmp-style directories (mode 0o1777) are accepted because the
        // sticky bit prevents non-owners from deleting/renaming our
        // socket file once created, and step 3 of bind_unix refuses
        // to overwrite an attacker-pre-created file.
        let dir = unique_tmp_dir("sticky");
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(&dir).unwrap().permissions();
        p.set_mode(0o1777); // sticky + world-writable
        std::fs::set_permissions(&dir, p).unwrap();
        let path = dir.join("admin.sock");
        let _listener = bind_unix(&path).expect("sticky 0o1777 must be accepted");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_unix_replaces_stale_socket_file() {
        let dir = unique_tmp_dir("stale");
        let path = dir.join("admin.sock");
        // First bind creates the socket.
        let listener = bind_unix(&path).expect("first bind");
        drop(listener);
        // Socket file lingers (Unix doesn't auto-clean). Second bind
        // should detect it as a socket and unlink + bind cleanly.
        assert!(path.exists());
        let _listener2 = bind_unix(&path).expect("rebind over stale socket must work");
    }
}
