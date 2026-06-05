//! Re-export shim for the extracted [`veil-bootstrap`](veil_bootstrap) crate.
//!
//! the crate split moved bootstrap (DNS-TXT seed records
//! signed/encrypted invites, HTTPS bundle fetch, builtin seeds) out to
//! a standalone Tier-3 crate. This module preserves the existing
//! `crate::node::bootstrap::X` import paths so the rest of veilcore
//! does not need a mass find/replace.

pub use veil_bootstrap::*;
