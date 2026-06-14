//! Re-export shim for the Argon2id-encrypted master-seed at-rest format.
//!
//! lifted [`veil_identity::master_file`]. Existing call
//! sites under `crate::identity_master_file::*` keep compiling
//! unchanged via the re-exports below.

pub use veil_identity::master_file::*;
