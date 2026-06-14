//! Re-export shim for the extracted [`veil-anonymity`](veil_anonymity) crate.
//!
//! the crate split moved the anonymity stack — onion routing
//! fixed-size cells, circuits, rendezvous points — out to a standalone
//! Tier-3 crate. This module preserves the existing
//! `crate::node::anonymity::X` import paths so the rest of veilcore does
//! not need a mass find/replace.

pub use veil_anonymity::*;
