//! Re-export shim for the extracted [`veil-abuse`](veil_abuse) crate.
//!
//! the crate split moved abuse-resistance primitives — rate
//! limiter, ban list, violation tracker, replay window, PoW verifier
//! bandwidth gate, identity quota, DHT quota, AIMD backpressure — out
//! to a standalone Tier-3 crate. This module preserves the existing
//! `crate::node::abuse::X` import paths.
//!
//! `NodeLogger` plugs into [`veil_abuse::AbuseLogger`] via the impl
//! block in `node::transport_hints` so the auto-ban path can emit
//! `abuse.auto_ban` events without depending on observability.

pub use veil_abuse::*;
