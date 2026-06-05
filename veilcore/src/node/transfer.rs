//! Re-export shim for the extracted [`veil-transfer`](veil_transfer) crate.
//!
//! the crate split moved the chunk-based transfer primitives
//! (payload fragmentation + reassembly within the proto budget) out to
//! a standalone Tier-3 crate.

pub use veil_transfer::*;
