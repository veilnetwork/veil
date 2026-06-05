//! Veil-network proxy bridge.
//!
//! Two standalone binaries:
//!
//! * `oproxy-server` — binds an veil app (custom name → derives app_id),
//!   accepts incoming proxy-connect streams, opens outbound TCP к the
//!   requested host:port, и bridges duplex.  Optionally enforces an
//!   `allowed_node_ids` allowlist на the source node_id (only-permitted-
//!   peers semantic).
//!
//! * `oproxy-client` — runs one OR more local inbound listeners
//!   (SOCKS5 / HTTP / TProxy via dokodemo-door) и tunnels each inbound
//!   connection через an veil stream к а configured server's
//!   (node_id + app_name) pair.
//!
//! # Wire protocol (over veil byte stream)
//!
//! Same shape as the existing `veil-proxy::exit` header — reused
//! verbatim для interop:
//!
//! ```text
//! [host_len: u16 BE][host: UTF-8 bytes][port: u16 BE]
//! ```
//!
//! After the header, the server replies с а single byte:
//! * `0x00` — connected; proceed с bidirectional byte-pipe.
//! * `0x01` — DENIED (node_id not в allowlist or destination forbidden).
//! * `0x02` — CONNECT_FAILED (TCP-connect к destination failed).
//! * `0x03` — BAD_REQUEST (malformed header).
//!
//! On non-OK status the server then closes the stream.
//!
//! # Cross-platform support
//!
//! | Platform   | SOCKS5 | HTTP CONNECT | TProxy |
//! |------------|--------|--------------|--------|
//! | Linux      | ✓      | ✓            | ✓ (IP_TRANSPARENT + SO_ORIGINAL_DST) |
//! | FreeBSD    | ✓      | ✓            | ✓ (ipfw fwd) |
//! | Keenetic   | ✓      | ✓            | ✓ (Linux kernel) |
//! | macOS      | ✓      | ✓            | ✗ (no public TProxy API) |
//! | Windows    | ✓      | ✓            | ✗ (WinDivert требует kernel driver) |
//!
//! On unsupported platforms the TProxy inbound returns а descriptive
//! error at startup; SOCKS5 / HTTP work everywhere.

pub mod app_cert_gate;
pub mod authz;
pub mod config;
pub mod config_template;
// `connector` + `inbound` use `veilclient::AppSender`, which itself
// is `#[cfg(unix)]`-gated в veilclient because the underlying IPC
// transport (Unix-domain socket) doesn't exist on Windows.  Gate the
// IPC-dependent modules so cross-compile к x86_64-pc-windows-gnu
// doesn't trip on `unresolved import`; the bins (which need these
// modules) ара built only on the Unix family per the workspace's
// existing platform matrix.  Platform-independent modules (wire,
// config, authz, app_cert_gate, routing, timeouts) stay available
// for type-only consumers.
#[cfg(unix)]
pub mod connector;
#[cfg(unix)]
pub mod inbound;
pub mod logging;
pub mod routing;
pub mod timeouts;
pub mod wire;

pub use logging::init_oproxy_logger;

/// Namespace string used when deriving the server-side app_id.
/// Both client и server compute `app_id =
/// veil_app::address::app_id(server_node_id, SERVER_NAMESPACE, app_name)`
/// — same canonical helper, so identical bytes на both sides.
pub const SERVER_NAMESPACE: &str = "oproxy";

/// Namespace used by the client when binding its OWN endpoint (so the
/// daemon's veil-app routing table differentiates client-side bind
/// от server-side bind even если both run на the same host).
pub const CLIENT_NAMESPACE: &str = "oproxy.client";

/// Bind name для the client-side endpoint.  Per-client uniqueness не
/// matters — only outbound `open_stream` calls happen here, so а
/// constant name is fine.
pub const CLIENT_BIND_NAME: &str = "outbound";
