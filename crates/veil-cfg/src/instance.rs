//! Re-export shim for per-device `instance_id` state.
//!
//! lifted [`veil_identity::instance`]. Existing call
//! sites under `crate::instance::*` keep compiling unchanged via
//! the re-exports below.

pub use veil_identity::instance::*;
