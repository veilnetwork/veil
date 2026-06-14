//! Re-export shim for the master-seed BIP39 mnemonic codec.
//!
//! lifted [`veil_identity::master_seed`] together with
//! `master_file`, `master_qr` and `instance` so wallet apps and recovery
//! tooling can handle master-seed material without depending on
//! veilcore. Existing call sites under `crate::identity_master::*`
//! keep compiling unchanged via the re-exports below.

pub use veil_identity::master_seed::*;
