//! Re-export shim for the canonical identity-policy struct.
//!
//! lifted [`veil_identity::identity_policy`] so wallet
//! and CLI code paths can compute / validate identity policies without
//! depending on veilcore. Existing call sites
//! (`crate::identity_policy::{IdentityPolicy, PowPolicy}`) keep
//! compiling unchanged via the re-exports below.

pub use veil_identity::identity_policy::{IdentityPolicy, PowPolicy};
