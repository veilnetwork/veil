//! Re-export shim for [`veil-proto`](veil_proto) Tier-1 crate.
//!
//! All wire-format types, codecs, and on-wire constants live in
//! `veil_proto`. This module preserves the existing
//! `crate::proto::X` import paths so the rest of veilcore (cfg
//! node, cmd, sim, …) does not need a mass find/replace.
//!
//! New code should prefer importing from `veil_proto` directly.

pub use veil_proto::*;
