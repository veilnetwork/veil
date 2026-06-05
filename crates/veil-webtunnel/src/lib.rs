//! webtunnel-style endpoint masking для WSS / TLS veil transports.
//!
//! Phase 5a of [`docs/internal/PLAN_TRANSPORT_OBFUSCATION.md`](../../docs/internal/PLAN_TRANSPORT_OBFUSCATION.md).
//!
//! # Concept
//!
//! When operating veil nodes on the public Internet, TLS-bearing
//! transports (`tls://`, `wss://`) hide OVL1 от passive DPI but still
//! leave the endpoint identifiable к **active probers**: censorship
//! scanners що connect к every public IP, speak а protocol, и flag
//! endpoints що respond like veil nodes.
//!
//! webtunnel addresses this by making the endpoint look like а **regular
//! HTTPS site by default**.  Tunnel mode kicks в only when the client
//! connects с the configured secret path + auth header.  An active
//! prober без the secret sees only а neutral website (status dashboard
//! caching of а real site, etc.) — indistinguishable от any other
//! public HTTPS server.
//!
//! # This crate (Phase 5a)
//!
//! Provides the **decoy provider abstraction** и **path/auth matcher**.
//! HTTP routing + WebSocket upgrade integration is Phase 5b.  Operator-
//! facing config + transport-layer wiring is Phase 5c.
//!
//! Pieces shipped here:
//!
//! - [`DecoyProvider`] trait — async fn що takes а bare HTTP request
//!   и returns the response к serve как decoy traffic.
//! - [`StaticStringDecoy`] — simplest: one fixed HTML string for all
//!   requests.  Low realism, zero setup cost.
//! - [`StaticDirectoryDecoy`] — serves а snapshot of а static-content
//!   directory.  Medium realism, low operator cost (point at а dir
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
