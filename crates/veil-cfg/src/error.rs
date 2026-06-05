//! Re-export shim — `ConfigError` + `Result` were extracted к
//! the `veil-error` workspace crate (Tier 0 leaf, breaks
//! the cfg ↔ crypto cycle so `crypto/` can become its own crate
//! depending only on Tier 0 leaves). This module re-exports the
//! types so existing `crate::ConfigError` / `crate::Result`
//! callers keep compiling без touching every import site.
//!
//! New code should `use veil_error::{ConfigError, Result}` directly.
pub use veil_error::{ConfigError, Result};
