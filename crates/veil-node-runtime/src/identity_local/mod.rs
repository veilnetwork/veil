//! Re-export shim for the sovereign-identity runtime.
//!
//! (2/3): every runtime identity module — verify, publish
//! resolver, freshness, mlkem_fanout, pair_runtime, pair_transport
//! sovereign, error — moved [`veil_identity`]. Only
//! [`publisher_dht`] (the production Kademlia adapter) stays here
//! because it depends on `KademliaService` directly.
//!
//! Existing call sites under `crate::node::identity::*` keep compiling
//! unchanged via the re-exports below.

pub use veil_identity::{
    IdentityError, IdentityResult, error, freshness, mlkem_fanout, pair_runtime, pair_transport,
    publish, resolver, sovereign, verify,
};

pub mod anonymity_x25519;
pub mod publisher_dht;
