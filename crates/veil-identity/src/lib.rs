//! Sovereign identity for the Veil network.
//!
//! extraction: the entire identity stack lifted out of
//! `veilcore::cfg` and `veilcore::node::identity` into a Tier-3
//! crate. Production runtime (`veilcore`) keeps a thin re-export
//! shim per module so existing call sites compile unchanged; everything
//! interesting lives here.
//!
//! ## Module map
//!
//! Identity *persistence* (no veil-crypto / veil-proto needed):
//! [`master_seed`] — BIP39 mnemonic codec, 32-byte master key.
//! [`master_file`] — Argon2id-encrypted at-rest format.
//! [`master_qr`] — offline `veil:master-backup` QR-share URI codec.
//! [`instance`] — per-device 16-byte `instance_id` state.
//!
//! Identity *flow / runtime* (depends on veil-crypto + veil-proto):
//! [`sovereign_flow`] — top-level CRUD: `create_identity`
//! `restore_identity`, `load_identity_sk`, master-key-rotation flows.
//! [`error`] — `IdentityError` / `IdentityResult` typed errors.
//! [`sovereign`] — `SovereignIdentity` runtime view +
//! subkey re-issuance.
//! [`verify`] — `IdentityDocument` signature + freshness check.
//! [`publish`] — abstract `IdentityPublisher` trait + the
//! publish orchestrator (DHT-agnostic; the Kademlia adapter lives in
//! veilcore::node::identity::publisher_dht).
//! [`resolver`] — name → `IdentityDocument` resolver.
//! [`freshness`] — refresh-policy helpers for delegated subkeys.
//! [`mlkem_fanout`] — multi-instance ML-KEM key fanout used during
//! identity rotation (post-quantum encryption upgrade path).
//! [`pair_runtime`] — pair-with-other-device orchestration.
//! [`pair_transport`] — pair-session transport adapter.

pub mod auth_deliver;
pub mod error;
pub mod freshness;
pub mod identity_policy;
pub mod instance;
pub mod mailbox_seal;
pub mod master_file;
pub mod master_qr;
pub mod master_seed;
pub mod migration;
pub mod mlkem_fanout;
pub mod network_access;
pub mod network_ban;
pub mod network_cert;
pub mod pair_runtime;
pub mod pair_transport;
pub mod publish;
pub mod resolver;
pub mod signing_key;
pub mod sovereign;
pub mod sovereign_flow;
pub mod verify;

pub use error::{IdentityError, IdentityResult};

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::PathBuf;
    use std::time::Duration;

    /// Build a collision-free scratch directory under `std::env::temp_dir`.
    /// 128 bits of `OsRng` entropy + `process::id` guarantee uniqueness
    /// across parallel tests, across cargo-test processes (nextest), and
    /// across re-runs. On WSL2 ext4 the first `mkdirat` is retried to paper
    /// over transient `EACCES` under heavy concurrent load.
    pub fn scratch_dir(prefix: &str) -> PathBuf {
        use rand_core::{OsRng, RngCore};
        let nonce: u128 = ((OsRng.next_u64() as u128) << 64) | OsRng.next_u64() as u128;
        let dir =
            std::env::temp_dir().join(format!("{prefix}-{}-{:032x}", std::process::id(), nonce,));
        for attempt in 0..3 {
            match std::fs::create_dir_all(&dir) {
                Ok(()) => return dir,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && attempt < 2 => {
                    std::thread::sleep(Duration::from_millis(25 * (attempt as u64 + 1)));
                }
                Err(e) => panic!("test_support::scratch_dir({prefix}) failed: {e}"),
            }
        }
        unreachable!()
    }
}
