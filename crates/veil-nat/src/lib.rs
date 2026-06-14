//! NAT helpers — external-address (STUN-like) discovery and `NatCandidate`
//! ⇄ `SocketAddr` conversion.
//!
//! A node asks a core/gateway peer "what address do you see my connection
//! coming from?" ([`ExternalAddrDiscovery`]); the peer echoes the observed
//! external `(IP, port)` back in a `NAT_PROBE_REPLY`. [`candidate_to_socket_addr`]
//! decodes the `NatCandidate`s carried in those replies into usable addresses.
//!
//! ## History
//!
//! This crate originally also carried UDP hole-punching (`NatPuncher`),
//! candidate coordination (`NatCoordinator`), and relay-fallback
//! (`RelayFallback`) plumbing. None of it was ever wired into the dial path —
//! no production caller ever constructed any of those types (the one would-be
//! call site was cargo-cult and had already been removed) — so that ~1k LOC of
//! dead code was deleted. Only the discovery + candidate-conversion layer below
//! remains in use (by `veil-dispatcher` and `veil-node-runtime`).

pub mod discovery;

pub use discovery::{ExternalAddrDiscovery, candidate_to_socket_addr};
