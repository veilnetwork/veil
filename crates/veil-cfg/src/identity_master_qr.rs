//! Re-export shim for the offline QR backup share codec.
//!
//! lifted [`veil_identity::master_qr`]. Existing call
//! sites under `crate::identity_master_qr::*` keep compiling
//! unchanged via the re-exports below.

pub use veil_identity::master_qr::*;
