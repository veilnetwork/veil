//! webtunnel-style endpoint masking for WSS / TLS veil transports.
//!
//! Phase 5a of [`docs/internal/PLAN_TRANSPORT_OBFUSCATION.md`](../../docs/internal/PLAN_TRANSPORT_OBFUSCATION.md).
//!
//! # Concept
//!
//! When operating veil nodes on the public Internet, TLS-bearing
//! transports (`tls://`, `wss://`) hide OVL1 from passive DPI but still
//! leave the endpoint identifiable to **active probers**: censorship
//! scanners that connect to every public IP, speak a protocol, and flag
//! endpoints that respond like veil nodes.
//!
//! webtunnel addresses this by making the endpoint look like a **regular
//! HTTPS site by default**.  Tunnel mode kicks in only when the client
//! connects with the configured secret path + auth header.  An active
//! prober without the secret sees only a neutral website (status dashboard
//! caching of a real site, etc.) — indistinguishable from any other
//! public HTTPS server.
//!
//! # This crate (Phase 5a)
//!
//! Provides the **decoy provider abstraction** and **path/auth matcher**.
//! HTTP routing + WebSocket upgrade integration is Phase 5b.  Operator-
//! facing config + transport-layer wiring is Phase 5c.
//!
//! Pieces shipped here:
//!
//! - [`DecoyProvider`] trait — async fn that takes a bare HTTP request
//!   and returns the response to serve as decoy traffic.
//! - [`StaticStringDecoy`] — simplest: one fixed HTML string for all
//!   requests.  Low realism, zero setup cost.
//! - [`StaticDirectoryDecoy`] — serves a snapshot of a static-content
//!   directory.  Medium realism, low operator cost (point at a dir
//!   of cached pages).
//! - [`SecretMatcher`] — constant-time check of path + optional auth
//!   header against the configured tunnel-mode credentials.

#![forbid(unsafe_code)]

pub mod client;
pub mod decoy;
pub mod matcher;
pub mod router;

pub use client::{ClientError, WebtunnelClient};
pub use decoy::{
    DecoyError, DecoyProvider, DecoyResponse, ReverseProxyDecoy, StaticDirectoryDecoy,
    StaticStringDecoy,
};
pub use matcher::{MatchResult, SecretMatcher};
pub use router::{RouterError, WebtunnelRouter};
