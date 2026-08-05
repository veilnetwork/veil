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

use veil_crypto::identity::derive_mlkem_dk_seed_epoch;
use veil_e2e::{
    DK_SEED_BYTES, EK_BYTES, MlKemKeyAtRest, keypair_from_dk_seed,
    load_or_generate_mlkem_key_encrypted,
};

use crate::error::NodeError;

/// The rotation epoch in force at `now_unix`.
///
/// `rotation_secs == 0` (rotation off) pins epoch 0, which
/// [`derive_mlkem_dk_seed_epoch`] defines as the pre-rotation key — so a node
/// with the knob off publishes exactly what it always published.
///
/// Deriving the epoch from the wall clock rather than counting rotations is
/// what makes this survive a restart with nothing persisted: a process that
/// comes back inside the same epoch re-derives the same key, and one that comes
/// back later lands on the right epoch instead of restarting the sequence.
pub fn rotation_epoch(now_unix: u64, rotation_secs: u64) -> u64 {
    if rotation_secs == 0 {
        return 0;
    }
    now_unix / rotation_secs
}

/// The ML-KEM keypair for `epoch`, or `None` if this node's key is not one that
/// can be re-derived.
///
/// The `None` case is not a failure: a node running a persisted `mlkem.key`
/// (operator/seed daemons) holds a random key that exists only in that file, so
/// there is no epoch sequence to move along. Rotating it would mean minting a
/// key that vanishes at the next restart, black-holing everything sealed to it.
///
/// This is also the single place that decides "is this node's key derivable" —
/// [`load_or_derive`] takes the same branch through here, so a startup and a
/// rotation can never disagree about it.
pub fn derive_for_epoch(
    mlkem_key_path: &Path,
    veil_dir: &Path,
    epoch: u64,
) -> Option<([u8; EK_BYTES], [u8; DK_SEED_BYTES])> {
    if mlkem_key_path.exists() {
        return None;
    }
    let seed = veil_identity::sovereign_flow::load_identity_sk(veil_dir).ok()?;
    let dk_seed = derive_mlkem_dk_seed_epoch(seed.as_array(), epoch);
    keypair_from_dk_seed(&dk_seed).ok()
}

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
    /// The node is booting under a placeholder identity: a random key held in
    /// memory only, never written and never derived from the placeholder. It is
    /// replaced outright when the real identity is applied.
    EphemeralStub,
}

impl MlKemKeySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Persisted => "persisted",
            Self::IdentityDerived => "identity_derived",
            Self::FallbackRandom => "fallback_random",
            Self::EphemeralStub => "ephemeral_stub",
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
    epoch: u64,
    ephemeral_identity: bool,
) -> Result<ResolvedMlKemKey, NodeError> {
    // 0. Placeholder identity: a random in-memory key, persisted NOWHERE.
    //    Not derived, because the placeholder is a compiled-in constant; and not
    //    written, because a file here would win branch 1 forever — the node
    //    would keep this throwaway key after its real identity arrived, publish
    //    it under that identity, and derive a DIFFERENT key on the next restart.
    if ephemeral_identity {
        let (ek, dk) = veil_e2e::generate_keypair();
        return Ok(ResolvedMlKemKey::in_memory(
            ek,
            dk,
            MlKemKeySource::EphemeralStub,
        ));
    }
    // 1. An existing persisted key wins — never rotate a node that already has one.
    if mlkem_key_path.exists() {
        let loaded = load_or_generate_mlkem_key_encrypted(mlkem_key_path, passphrase)
            .map_err(|e| NodeError::InvalidArgument(format!("{e}")))?;
        return Ok(ResolvedMlKemKey::from_file(
            loaded,
            MlKemKeySource::Persisted,
        ));
    }
    // 2. Ephemeral-dir node with an identity: derive deterministically, at the
    //    epoch currently in force. Starting at `epoch` rather than at 0 matters:
    //    a restart must land on the key the node was already publishing, not
    //    walk back to genesis and rotate forward again on every launch.
    match veil_identity::sovereign_flow::load_identity_sk(veil_dir) {
        Ok(seed) => {
            let dk_seed = derive_mlkem_dk_seed_epoch(seed.as_array(), epoch);
            let (ek, dk) = keypair_from_dk_seed(&dk_seed)
                .map_err(|e| NodeError::InvalidArgument(format!("{e}")))?;
            return Ok(ResolvedMlKemKey::in_memory(
                ek,
                dk,
                MlKemKeySource::IdentityDerived,
            ));
        }
        // Identity present but no Ed25519 seed file (e.g. a Falcon multi-device
        // node) — fall through to a random+persisted key rather than failing.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    // 3. Fallback: random + persist (legacy behaviour).
    let loaded = load_or_generate_mlkem_key_encrypted(mlkem_key_path, passphrase)
        .map_err(|e| NodeError::InvalidArgument(format!("{e}")))?;
    Ok(ResolvedMlKemKey::from_file(
        loaded,
        MlKemKeySource::FallbackRandom,
    ))
}

/// What [`load_or_derive`] resolved: the keypair, where it came from, and — for
/// the branches that read a FILE — whether that file is stored in the form the
/// configuration asks for.
///
/// `at_rest` used to have nowhere to go. The loader below discarded the
/// auto-upgrade write's error entirely, so a node whose operator had just
/// enabled a passphrase could run indefinitely with its decapsulation seed in
/// plaintext and say nothing (audit report7 V-02). It is carried here so the
/// startup path can warn and record it.
#[derive(Debug, Clone)]
pub struct ResolvedMlKemKey {
    /// Encapsulation key (public half).
    pub ek: [u8; EK_BYTES],
    /// Decapsulation seed (private half).
    pub dk_seed: [u8; DK_SEED_BYTES],
    /// Which branch produced the key.
    pub source: MlKemKeySource,
    /// On-disk state. Always [`MlKemKeyAtRest::AsConfigured`] for the branches
    /// that never touch a file — a key that is not stored cannot be stored
    /// wrongly.
    pub at_rest: MlKemKeyAtRest,
}

impl ResolvedMlKemKey {
    fn in_memory(ek: [u8; EK_BYTES], dk_seed: [u8; DK_SEED_BYTES], source: MlKemKeySource) -> Self {
        Self {
            ek,
            dk_seed,
            source,
            at_rest: MlKemKeyAtRest::AsConfigured,
        }
    }

    fn from_file(loaded: veil_e2e::MlKemKeyLoad, source: MlKemKeySource) -> Self {
        Self {
            ek: loaded.ek,
            dk_seed: loaded.dk_seed,
            source,
            at_rest: loaded.at_rest,
        }
    }
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
        let ek_file = load_or_generate_mlkem_key_encrypted(&key_path, None)
            .unwrap()
            .ek;
        assert!(key_path.exists());
        // Also drop an identity seed so the derive branch WOULD be eligible.
        save_seed(tmp.path(), 0x11);

        let r = load_or_derive(&key_path, tmp.path(), None, 0, false).unwrap();
        assert_eq!(r.source, MlKemKeySource::Persisted);
        assert_eq!(
            r.ek, ek_file,
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

        let r = load_or_derive(&key_path, tmp.path(), None, 0, false).unwrap();
        assert_eq!(r.source, MlKemKeySource::IdentityDerived);
        let ek = r.ek;
        // Matches the standalone derive helpers.
        let want_seed = derive_mlkem_dk_seed_epoch(&[0x22u8; 32], 0);
        let (want_ek, want_dk) = keypair_from_dk_seed(&want_seed).unwrap();
        assert_eq!(ek, want_ek);
        assert_eq!(r.dk_seed, want_dk);
        // No on-disk artifact — the derived key is reproducible.
        assert!(!key_path.exists(), "derive must not persist a key file");

        // Simulated restart: a FRESH dir with the SAME identity seed yields the
        // SAME keypair (the cross-session stability that fixes the AEAD black-hole).
        let tmp2 = tempfile::tempdir().unwrap();
        save_seed(tmp2.path(), 0x22);
        let ek2 = load_or_derive(&tmp2.path().join("mlkem.key"), tmp2.path(), None, 0, false)
            .unwrap()
            .ek;
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
        let ek_a = load_or_derive(&a.path().join("mlkem.key"), a.path(), None, 0, false)
            .unwrap()
            .ek;
        let ek_b = load_or_derive(&b.path().join("mlkem.key"), b.path(), None, 0, false)
            .unwrap()
            .ek;
        assert_ne!(ek_a, ek_b);
    }

    /// The overlap constant is arithmetic over values that live in other
    /// crates, so it is asserted HERE — the one place that can see all of them.
    ///
    /// `veil-e2e` sits below `veil-mailbox` and cannot name its retention
    /// constant, so it restates the number. Restated numbers drift. If someone
    /// lengthens how long a relay holds an undelivered blob, this fails instead
    /// of the window quietly becoming too short — which would show up only as
    /// week-old mail that no longer opens.
    #[test]
    fn overlap_window_covers_the_real_mailbox_and_cache_lifetimes() {
        let republish_interval = 6 * 3600;
        let want = veil_mailbox::DEFAULT_TTL_SECS
            + veil_types::IpcConfig::default().e2e_key_ttl_secs
            + republish_interval;
        assert_eq!(
            veil_e2e::MLKEM_SEED_MIN_OVERLAP_SECS,
            want,
            "the overlap must equal mailbox retention + peer EK cache + republish lag"
        );
    }

    /// A placeholder identity yields a key that is neither derived from it nor
    /// written anywhere.
    ///
    /// Both halves matter. DERIVING would make this node's mailbox key a pure
    /// function of a constant compiled into the binary. WRITING would let the
    /// persisted-key branch win at the next resolve, so the node would keep the
    /// throwaway key after its real identity arrived — publishing it under that
    /// identity and deriving a different one on the next restart.
    #[test]
    fn a_placeholder_identity_neither_derives_nor_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("mlkem.key");
        save_seed(tmp.path(), 0x99);

        let r = load_or_derive(&key_path, tmp.path(), None, 0, true).unwrap();
        let ek = r.ek;
        assert_eq!(r.source, MlKemKeySource::EphemeralStub);
        assert!(
            !key_path.exists(),
            "a placeholder must leave nothing on disk"
        );

        // NOT the key the seed on disk would derive — even though that seed is
        // sitting right there and the non-ephemeral path would use it.
        let (derived_ek, _) = derive_for_epoch(&key_path, tmp.path(), 0).unwrap();
        assert_ne!(ek, derived_ek);

        // And random per call, so two deferred nodes never share one.
        let ek2 = load_or_derive(&key_path, tmp.path(), None, 0, true)
            .unwrap()
            .ek;
        assert_ne!(ek, ek2);
    }

    /// Rotation off pins epoch 0, and epoch 0 is the pre-rotation key — so
    /// upgrading a binary without touching the config republishes nothing.
    #[test]
    fn rotation_off_pins_the_genesis_epoch() {
        assert_eq!(rotation_epoch(1_800_000_000, 0), 0);
        // …and with rotation on, the epoch advances once per interval and is a
        // pure function of the clock, so a restart lands where it left off.
        let interval = 8 * 24 * 3600;
        let t = 1_800_000_000u64;
        assert_eq!(rotation_epoch(t, interval), rotation_epoch(t + 5, interval));
        assert_eq!(
            rotation_epoch(t + interval, interval),
            rotation_epoch(t, interval) + 1
        );
    }

    /// A node whose key came from a persisted file has no epoch sequence: the
    /// key is random and lives only in that file, so `derive_for_epoch` must
    /// decline rather than hand back a key that dies at the next restart.
    #[test]
    fn persisted_key_cannot_be_rotated() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("mlkem.key");
        load_or_generate_mlkem_key_encrypted(&key_path, None).unwrap();
        save_seed(tmp.path(), 0x33);
        assert!(
            derive_for_epoch(&key_path, tmp.path(), 5).is_none(),
            "a persisted key must not be rotated out from under its published cert"
        );
        // The same node's startup agrees — both go through one branch.
        let src = load_or_derive(&key_path, tmp.path(), None, 5, false)
            .unwrap()
            .source;
        assert_eq!(src, MlKemKeySource::Persisted);
    }

    /// An identity-derived node rotates, and a restart mid-epoch comes back to
    /// the SAME key rather than to genesis — the property that lets rotation
    /// persist nothing.
    #[test]
    fn derived_key_rotates_and_survives_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("mlkem.key");
        save_seed(tmp.path(), 0x44);

        let (ek0, _) = derive_for_epoch(&key_path, tmp.path(), 0).unwrap();
        let (ek5, dk5) = derive_for_epoch(&key_path, tmp.path(), 5).unwrap();
        assert_ne!(ek0, ek5, "an epoch step must actually change the key");

        // Restart inside epoch 5: startup derives the key already published.
        let restart = load_or_derive(&key_path, tmp.path(), None, 5, false).unwrap();
        assert_eq!(restart.source, MlKemKeySource::IdentityDerived);
        assert_eq!(restart.ek, ek5);
        assert_eq!(restart.dk_seed, dk5);
        // And still no on-disk artifact — the key stays reproducible.
        assert!(!key_path.exists());
    }

    /// Identity-less node with no key file: fall back to a fresh random key that
    /// is persisted (legacy behaviour for relay-only daemons without a seed).
    #[test]
    fn fallback_random_when_no_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("mlkem.key");
        let src = load_or_derive(&key_path, tmp.path(), None, 0, false)
            .unwrap()
            .source;
        assert_eq!(src, MlKemKeySource::FallbackRandom);
        assert!(key_path.exists(), "fallback must persist the random key");
    }
}
