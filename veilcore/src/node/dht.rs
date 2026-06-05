//! Re-export shim for the extracted [`veil-dht`](veil_dht) crate.
//!
//! the crate split moved Kademlia routing/storage out to a
//! standalone Tier-3 crate. This module preserves the existing
//! `crate::node::dht::X` import paths so the rest of veilcore does
//! not need a mass find/replace.
//!
//! Upper-layer hooks (frame dispatch, RTT/Vivaldi hints, metrics) are
//! plugged in via the trait surfaces [`veil_dht::traits`]; the
//! concrete adapters live in `crate::node::dht_glue`.

pub use veil_dht::*;
