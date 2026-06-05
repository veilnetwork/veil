//! Re-export shim — `util.rs` was extracted to the `veil-util`
//! workspace crate. This module re-exports its public API so
//! existing in-crate callers (`crate::util::atomic_write`, etc)
//! keep compiling без touching every import site.
//!
//! New code should `use veil_util::...` directly.
pub use veil_util::*;
