//! Re-export shim for the extracted [`veil-gateway`](veil_gateway) crate.
//!
//! the crate split moved the multi-gateway scoring and
//! failover module out to a standalone Tier-3 crate.

pub use veil_gateway::*;
