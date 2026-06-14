//! Re-export shim for the extracted [`veil-transport`](veil_transport) crate.
//!
//! the crate split moved all transport primitives — TCP, QUIC
//! TLS (rustls + optional BoringSSL), WebSocket, SOCKS proxy, Unix domain
//! sockets — out to a standalone Tier-2 crate. This module preserves the
//! existing `crate::transport::X` import paths so the rest of veilcore
//! does not need a mass find/replace.
//!
//! New code should prefer importing from `veil_transport` directly.

pub use veil_transport::*;
