//! Re-export shim for the extracted [`veil-update`](veil_update) crate.
//!
//! the crate split moved the self-update infrastructure
//! — signed manifest fetch, multi-CDN failover, anti-
//! downgrade timestamp, atomic binary swap, periodic check task — out
//! to a standalone Tier-3 crate. This module preserves the existing
//! `crate::node::update::X` import paths.
//!
//! `NodeLogger` plugs into [`veil_update::UpdateLogger`] via the impl
//! block in `node::observability` so the periodic check task can emit
//! `update.check.*` events without depending on the observability layer.

pub use veil_update::*;
