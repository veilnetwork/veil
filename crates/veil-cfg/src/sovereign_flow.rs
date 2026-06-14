//! Re-export shim for the sovereign-identity CRUD flow.
//!
//! (2/3): lifted [`veil_identity::sovereign_flow`] together
//! with `node::identity::*`. Existing call sites under
//! `crate::sovereign_flow::*` keep compiling unchanged via the
//! re-exports below.

pub use veil_identity::sovereign_flow::*;
