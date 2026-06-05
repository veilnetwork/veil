//! Shared timeout constants для oproxy inbound listeners + veil
//! connector + server-side stream handling.
//!
//! All timeouts are intentionally generous (15 s default) so legitimate
//! clients on slow networks complete the handshake, but bounded so
//! slow-loris-style attacks cannot hold tasks indefinitely.
//!
//! Audit batch 2026-05-24 (audit follow-up): added в response к the
//! finding "SOCKS5 / HTTP / connect-header reads без timeout — slow
//! client или veil peer holds task indefinitely".

use std::time::Duration;

/// Cap on the time а client has к complete the SOCKS5 / HTTP request-
/// reading phase before the listener gives up и closes the connection.
/// Covers method-select, CONNECT-request, HTTP header block.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Cap on the time the veil-side waits для the connect-status reply
/// от the veil-server.  Used by `try_veil_setup_and_bridge` после
/// writing the connect header.
pub const VEIL_STATUS_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on the time `open_stream(...)` may block before we give up и let
/// the inbound caller fall back per routing policy.  Wraps the AppHandle
/// `open_stream().await` call.  Without this, а stalled veil-peer can
/// hold the AppHandle mutex indefinitely и starve все other proxy
/// connects.
pub const OPEN_STREAM_TIMEOUT: Duration = Duration::from_secs(15);

/// Cap on direct TCP connect (`routing.rs::open_direct_and_bridge`).
/// Same value as the server-side outbound connect (`server.rs`); matches
/// typical OS-level connect-retry budget (~10 s on Linux default).
pub const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on the time `oproxy-server` waits for the connect header от an
/// inbound veil stream.  Same envelope as the client-side handshake.
pub const SERVER_CONNECT_HEADER_TIMEOUT: Duration = Duration::from_secs(15);
