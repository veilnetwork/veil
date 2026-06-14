//! Re-export shim for the network-size-aware adaptive parameter formulas.
//!
//! lifted [`veil_adaptive`] (Tier-0 leaf crate, zero
//! internal deps). The module was already self-contained — pure
//! formulas + a single struct + Default impl — so the move is a clean
//! `git mv` with a re-export here. Existing call sites under
//! `crate::adaptive::*` keep compiling unchanged.

pub use veil_adaptive::*;
