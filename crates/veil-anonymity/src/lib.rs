//! Anonymity layer.
//!
//! Optional Tor-like onion-routing infrastructure: fixed-size cells
//! layered encryption, multi-hop circuits, rendezvous points.
//!
//! This module is being built out incrementally — the foundational
//! primitives ship first as self-contained pieces that can be tested
//! and reasoned about in isolation, then wiring into the dispatcher
//! happens once the primitives are stable.
//!
//! Currently shipped:
//! * [`cell`] — fixed-size cell padding. Pure encoding;
//!   no wire integration yet.
//! * [`onion`] — single-hop AEAD wrap/unwrap (subset).
//!   Pure crypto; no circuit infrastructure yet.
//! * [`circuit`] — multi-hop circuit envelope on top of `onion` with
//!   next-hop-id encoding (subset). Stateless single-
//!   message circuits; no `CircuitId`, no return path.
//! * [`packet`] — user-facing API combining cell + circuit + onion.
//!   Guarantees outbound from every hop is also a 512-byte cell —
//!   THE load-bearing observer-cannot-correlate-by-size property.
//! * [`directory`] — signed relay-directory entries (
//!   primitive). Wire format + sign/verify + DHT key derivation;
//!   periodic publish + sender-side query are separate slices.
//! * [`circuit_builder`] — picks N hops out of a candidate pool
//!   returned by `directory::discover_relay_hops`, ready for
//!   `packet::build_anonymous_cell`. Two strategies:
//!   uniform-random (baseline) and latency-aware (composes with
//!   Vivaldi).
//! * [`sender`] — composition layer that closes the SEND-side
//!   pipeline: discovery → picker → packet → first-hop dispatch
//!   . Pure helper that takes already-fetched
//!   DiscoveredRelay candidates + RTT estimator + target identity
//!   and returns `(first_hop_node_id, cell_bytes)` ready to
//!   transmit.

pub mod cell;
pub mod circuit;
pub mod circuit_builder;
pub mod circuit_data;
pub mod circuit_setup;
pub mod circuit_wire;
pub mod directory;
pub mod onion;
pub mod packet;
pub mod push_envelope;
/// Per-sender-local relay-failure ledger (Epic 482.3/482.4 Phase A).
pub mod relay_reputation;
pub mod rendezvous;
pub mod sender;
