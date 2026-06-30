//! Stable ML-KEM-768 mailbox decapsulation seed for the node.
//!
//! The mailbox keypair's PUBLIC half (the encapsulation key) is published in
//! the node's signed `MlKemKeyCert`, bound to the stable `node_id`; offline
//! senders seal store-and-forward blobs to it. The decapsulation seed therefore
//! MUST stay stable across restarts, or a peer's already-sealed blob fails to
//! open after we restart (AEAD `mailbox_open … Failed`) — silently black-holing
//! reverse delivery.
//!
//! The legacy loader ([`veil_e2e::load_or_generate_mlkem_key_encrypted`])
//! persisted the seed as an encrypted PEM next to the node config. For an
//! xVeil client that config lives in an **ephemeral** per-session runtime dir,
//! so the file never survived and a fresh RANDOM key was minted every launch —
//! exactly the churn above. [`load_or_derive`] fixes it by DERIVING the seed
//! from the stable per-identity Ed25519 SK seed when no persisted key exists,
//! mirroring [`super::anonymity_x25519::load_or_derive`].

use std::path::Path;

use veil_crypto::identity::derive_mlkem_dk_seed;
use veil_e2e::{
    DK_SEED_BYTES, EK_BYTES, keypair_from_dk_seed, load_or_generate_mlkem_key_encrypted,
};

use crate::error::NodeError;

/// Where the node's ML-KEM mailbox seed came from — surfaced at the call site
/// for field diagnosis (`node.mlkem_dk.source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemKeySource {
    /// An existing on-disk `mlkem.key` PEM was loaded verbatim (long-lived
    /// operator/seed nodes — never rotated on upgrade).
    Persisted,
    /// Derived deterministically from the identity Ed25519 SK seed (the fix for
    /// ephemeral-runtime-dir nodes such as the xVeil clients).
    IdentityDerived,
    /// No persisted key and no usable identity seed — a fresh random key was
    /// generated and persisted (legacy / identity-less seed daemons).
    FallbackRandom,
}

impl MlKemKeySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Persisted => "persisted",
            Self::IdentityDerived => "identity_derived",
            Self::FallbackRandom => "fallback_random",
        }
    }
}

/// Resolve the node's ML-KEM-768 mailbox keypair `(ek, dk_seed)`, preferring
/// STABILITY across sessions.
///
/// Order (first match wins):
/// 1. An existing persisted `mlkem.key` — loaded verbatim, so a long-lived
///    operator/seed node NEVER rotates its key (and its already-published cert
///    stays valid).
/// 2. Else, when the identity Ed25519 SK seed (`device_identity_sk.bin`) is on
///    disk, DERIVE the dk_seed from it. This is the fix for ephemeral-runtime-dir
///    nodes (xVeil clients recreate `veil_dir` every session, so step 1 never
///    matches and the old code minted a fresh RANDOM key each launch — churning
///    the published EK and breaking reverse delivery to peers holding an older
///    cert). The seed is itself stable across sessions (it is the identity), so
///    the derived keypair is too. The derived key is intentionally NOT persisted:
///    it is reproducible, and writing it would shadow a future identity rotation.
/// 3. Else, generate + persist a fresh random key (legacy behaviour for
///    identity-less seed daemons).
pub fn load_or_derive(
    mlkem_key_path: &Path,
    veil_dir: &Path,
    passphrase: Option<&str>,
) -> Result<([u8; EK_BYTES], [u8; DK_SEED_BYTES], MlKemKeySource), NodeError> {
    // 1. An existing persisted key wins — never rotate a node that already has one.
    if mlkem_key_path.exists() {
        let (ek, dk) = load_or_generate_mlkem_key_encrypted(mlkem_key_path, passphrase)
            .map_err(|e| NodeError::InvalidArgument(format!("{e}")))?;
        return Ok((ek, dk, MlKemKeySource::Persisted));
    }
    // 2. Ephemeral-dir node with an identity: derive deterministically.
    match veil_identity::sovereign_flow::load_identity_sk(veil_dir) {
        Ok(seed) => {
            let dk_seed = derive_mlkem_dk_seed(seed.as_array());
            let (ek, dk) = keypair_from_dk_seed(&dk_seed)
                .map_err(|e| NodeError::InvalidArgument(format!("{e}")))?;
            return Ok((ek, dk, MlKemKeySource::IdentityDerived));
        }
        // Identity present but no Ed25519 seed file (e.g. a Falcon multi-device
        // node) — fall through to a random+persisted key rather than failing.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    // 3. Fallback: random + persist (legacy behaviour).
    let (ek, dk) = load_or_generate_mlkem_key_encrypted(mlkem_key_path, passphrase)
        .map_err(|e| NodeError::InvalidArgument(format!("{e}")))?;
    Ok((ek, dk, MlKemKeySource::FallbackRandom))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn save_seed(dir: &Path, byte: u8) {
        let seed = veil_util::sensitive_bytes::SensitiveBytesN::<32>::from_bytes([byte; 32]);
        veil_identity::sovereign_flow::save_identity_sk(dir, &seed).unwrap();
    }

    /// An existing persisted key WINS even when an identity seed is present:
    /// long-lived nodes must NOT rotate their mailbox key on upgrade (else their
    /// already-published cert is invalidated). The no-rotation safety guarantee.
    #[test]
    fn persisted_file_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("mlkem.key");
        // Create a persisted (random) key file + capture its EK.
        let (ek_file, _dk) = load_or_generate_mlkem_key_encrypted(&key_path, None).unwrap();
        assert!(key_path.exists());
        // Also drop an identity seed so the derive branch WOULD be eligible.
        save_seed(tmp.path(), 0x11);

        let (ek, _dk, src) = load_or_derive(&key_path, tmp.path(), None).unwrap();
        assert_eq!(src, MlKemKeySource::Persisted);
        assert_eq!(
            ek, ek_file,
            "existing key must be returned unchanged (no rotation)"
        );
    }

    /// An ephemeral-dir node (no persisted key) with an identity DERIVES from the
    /// seed — deterministically, and the SAME across a simulated restart (fresh
    /// dir, same seed). This is the actual delivery fix. It must NOT persist a key.
    #[test]
    fn derives_when_no_keyfile_but_identity_present() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("mlkem.key");
        save_seed(tmp.path(), 0x22);

        let (ek, dk, src) = load_or_derive(&key_path, tmp.path(), None).unwrap();
        assert_eq!(src, MlKemKeySource::IdentityDerived);
        // Matches the standalone derive helpers.
        let want_seed = derive_mlkem_dk_seed(&[0x22u8; 32]);
        let (want_ek, want_dk) = keypair_from_dk_seed(&want_seed).unwrap();
        assert_eq!(ek, want_ek);
        assert_eq!(dk, want_dk);
        // No on-disk artifact — the derived key is reproducible.
        assert!(!key_path.exists(), "derive must not persist a key file");

        // Simulated restart: a FRESH dir with the SAME identity seed yields the
        // SAME keypair (the cross-session stability that fixes the AEAD black-hole).
        let tmp2 = tempfile::tempdir().unwrap();
        save_seed(tmp2.path(), 0x22);
        let (ek2, _dk2, _src2) =
            load_or_derive(&tmp2.path().join("mlkem.key"), tmp2.path(), None).unwrap();
        assert_eq!(
            ek, ek2,
            "same identity seed across sessions must give the same EK"
        );
    }

    /// Two DIFFERENT identities derive DIFFERENT keys (master/decoy isolation).
    #[test]
    fn distinct_identities_derive_distinct_keys() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        save_seed(a.path(), 0x01);
        save_seed(b.path(), 0x02);
        let (ek_a, _, _) = load_or_derive(&a.path().join("mlkem.key"), a.path(), None).unwrap();
        let (ek_b, _, _) = load_or_derive(&b.path().join("mlkem.key"), b.path(), None).unwrap();
        assert_ne!(ek_a, ek_b);
    }

    /// Identity-less node with no key file: fall back to a fresh random key that
    /// is persisted (legacy behaviour for relay-only daemons without a seed).
    #[test]
    fn fallback_random_when_no_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("mlkem.key");
        let (_ek, _dk, src) = load_or_derive(&key_path, tmp.path(), None).unwrap();
        assert_eq!(src, MlKemKeySource::FallbackRandom);
        assert!(key_path.exists(), "fallback must persist the random key");
    }
}
