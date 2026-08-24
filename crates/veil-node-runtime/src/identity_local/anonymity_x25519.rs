//! Persistent X25519 secret key for the anonymity / push-relay role.
//!
//!.4 P0: the relay's X25519 keypair is the
//! seal-target apps use to encrypt FCM/APNs push tokens. Before T1.4
//! the key was generated fresh on every startup
//! (`StaticSecret::random_from_rng`), which silently invalidated every
//! sealed envelope already registered with the relay's rendezvous
//! publisher. We now persist the key on disk so it survives restarts.
//!
//! ## File format
//!
//! Path: `<veil_dir>/device_anonymity_x25519_sk.bin`
//! Contents: raw 32-byte X25519 secret scalar (little-endian, as
//! produced by `StaticSecret::to_bytes`).
//! Mode: `0o600` on Unix (owner-readable only) — enforced by
//! [`veil_util::atomic_write`].
//!
//! ## Lifecycle
//!
//! On first relay-capable startup: [`load_or_create`] generates a
//! fresh key and persists it.
//! On subsequent startups: [`load_or_create`] reads the existing key
//! and returns it unchanged.
//! The key has no rotation flow yet; rotation would invalidate every
//! sealed envelope until apps re-fetch the new public key. Punted to
//! a later phase (operator-initiated, with a grace window).

use std::path::{Path, PathBuf};

const FILE_NAME: &str = "device_anonymity_x25519_sk.bin";
const KEY_LEN: usize = 32;

/// Where the key lives, relative to `veil_dir`.
pub fn key_path(veil_dir: &Path) -> PathBuf {
    veil_dir.join(FILE_NAME)
}

/// Persist `sk` to `<veil_dir>/device_anonymity_x25519_sk.bin`.
///
/// Uses [`veil_util::atomic_write`] so a crash mid-write cannot leave
/// a half-written file at the target path (write-to-tmp, fsync, rename
/// fsync_dir). File mode is `0o600` on Unix.
pub fn save(veil_dir: &Path, sk: &x25519_dalek::StaticSecret) -> std::io::Result<()> {
    let bytes = sk.to_bytes();
    veil_util::atomic_write(&key_path(veil_dir), &bytes)
}

/// Try to load the key from disk.
///
/// Returns:
/// `Ok(Some(sk))` — file exists and decoded cleanly.
/// `Ok(None)` — file does not exist (first-time startup).
/// `Err(_)` — file exists but is corrupt (wrong size) or unreadable.
/// Caller decides whether to refuse to start or regenerate.
pub fn load(veil_dir: &Path) -> std::io::Result<Option<x25519_dalek::StaticSecret>> {
    let path = key_path(veil_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if bytes.len() != KEY_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "anonymity X25519 sk file has wrong length: expected {KEY_LEN}, got {}",
                bytes.len()
            ),
        ));
    }
    let mut buf = [0u8; KEY_LEN];
    buf.copy_from_slice(&bytes);
    Ok(Some(x25519_dalek::StaticSecret::from(buf)))
}

/// Load the key from disk; if absent, generate a fresh one and persist it —
/// unless somebody else got there first, in which case theirs is used.
///
/// The two-step (load → maybe-save) is not atomic, and it used to end there:
/// two processes racing on first startup both generated a key, `atomic_write`'s
/// `rename(2)` published one of them, and the loser carried on with an
/// in-memory key that nothing on disk backed. Everything it sealed under that
/// key became un-openable at its next restart, silently, and the only stated
/// defence was that operators are expected to run one daemon per `veil_dir`.
///
/// The publish is now `create_new` (`O_EXCL`), so the race has a winner and a
/// LOSER RATHER THAN TWO WINNERS: `AlreadyExists` means another process
/// published first, and this one adopts what is on disk instead of keeping a
/// key nobody else will ever have. One daemon per directory is still the
/// supported arrangement — this removes the silent divergence when it is not
/// the arrangement in force.
pub fn load_or_create(veil_dir: &Path) -> std::io::Result<x25519_dalek::StaticSecret> {
    if let Some(sk) = load(veil_dir)? {
        return Ok(sk);
    }
    let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    match save_new(veil_dir, &sk) {
        Ok(()) => Ok(sk),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // The other process won. Its key is the one every future start of
            // this directory will read, so it is the one to use now.
            load(veil_dir)?.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "anonymity X25519 sk vanished between create and read",
                )
            })
        },
        Err(e) => Err(e),
    }
}

/// Publish the key only if the file does not exist yet.
///
/// `O_EXCL` rather than [`save`]'s temp-and-rename: the point here is to LOSE
/// when somebody else has already published, and a rename always wins.
fn save_new(veil_dir: &Path, sk: &x25519_dalek::StaticSecret) -> std::io::Result<()> {
    use std::io::Write as _;
    let path = key_path(veil_dir);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path)?;
    f.write_all(&sk.to_bytes())?;
    f.sync_all()
}

/// Derive the anonymity X25519 secret DETERMINISTICALLY from this identity's
/// Ed25519 SK seed (HKDF-SHA256, domain-separated). The public half is what
/// peers seal their rendezvous introduces to, so pinning it to the stable
/// identity seed means the key no longer churns across sessions — even a peer
/// holding a slightly-stale ad still decrypts. See
/// [`veil_crypto::identity::derive_anonymity_x25519_sk`].
pub fn derive_from_identity_seed(
    seed: &veil_util::sensitive_bytes::SensitiveBytesN<32>,
) -> x25519_dalek::StaticSecret {
    let okm = veil_crypto::identity::derive_anonymity_x25519_sk(seed.as_array());
    // `*okm` copies the 32 bytes into StaticSecret::from (which clamps); `okm`
    // itself is Zeroizing and wipes on drop.
    x25519_dalek::StaticSecret::from(*okm)
}

/// Where the anonymity X25519 secret came from — surfaced at the call site for
/// field diagnosis (`node.anonymity_x25519.source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonymityKeySource {
    /// An existing on-disk key file was loaded verbatim (long-lived nodes — no
    /// rotation).
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

impl AnonymityKeySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Persisted => "persisted",
            Self::IdentityDerived => "identity_derived",
            Self::FallbackRandom => "fallback_random",
            Self::EphemeralStub => "ephemeral_stub",
        }
    }
}

/// Resolve the anonymity X25519 secret, preferring STABILITY across sessions.
///
/// Order (first match wins):
/// 1. An existing persisted `device_anonymity_x25519_sk.bin` — loaded verbatim,
///    so a long-lived operator/seed node NEVER rotates its key on upgrade.
/// 2. Else, when this node has a sovereign identity, DERIVE the key from its
///    Ed25519 SK seed. This is the fix for ephemeral-runtime-dir nodes (xVeil
///    clients recreate `veil_dir` every session, so step 1 never matches and the
///    old code minted a fresh RANDOM key each launch — churning the published
///    pubkey and silently black-holing delivery to peers holding an older ad).
///    The seed is itself stable across sessions (it is the identity), so the
///    derived key is too. A sovereign identity with NO Ed25519 seed file
///    (`NotFound`, e.g. a Falcon multi-device node) falls through to step 3.
/// 3. Else, generate + persist a fresh random key (legacy [`load_or_create`]).
///
/// Returns the secret plus where it came from (for logging).
pub fn load_or_derive(
    veil_dir: &Path,
    sovereign_present: bool,
    ephemeral_identity: bool,
) -> std::io::Result<(x25519_dalek::StaticSecret, AnonymityKeySource)> {
    // 0. Placeholder identity: a random in-memory key, persisted NOWHERE — same
    //    reasoning as the ML-KEM seed's ephemeral branch. Deriving it from the
    //    placeholder would make this node's rendezvous receive key a published
    //    constant; writing it would make branch 1 keep the throwaway key after
    //    the real identity arrived.
    if ephemeral_identity {
        return Ok((
            x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng),
            AnonymityKeySource::EphemeralStub,
        ));
    }
    // 1. An existing persisted key wins — never rotate a node that already has one.
    if let Some(sk) = load(veil_dir)? {
        return Ok((sk, AnonymityKeySource::Persisted));
    }
    // 2. Ephemeral-dir node with an identity: derive deterministically.
    if sovereign_present {
        match veil_identity::sovereign_flow::load_identity_sk(veil_dir) {
            Ok(seed) => {
                return Ok((
                    derive_from_identity_seed(&seed),
                    AnonymityKeySource::IdentityDerived,
                ));
            }
            // Identity present but no Ed25519 seed file (Falcon multi-device,
            // etc.) — fall through to a random+persisted key rather than failing
            // to start.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    // 3. Fallback: random + persist (legacy behaviour).
    let sk = load_or_create(veil_dir)?;
    Ok((sk, AnonymityKeySource::FallbackRandom))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two starts racing on an empty directory must end on ONE key.
    ///
    /// Both generate one — there is nothing on disk to load — and the publish
    /// used to be a rename, which always wins. So both processes believed
    /// their own key while only one was on disk, and everything the loser
    /// sealed became un-openable at its next start. Nothing said so; the only
    /// stated defence was that operators run one daemon per directory.
    #[test]
    fn two_racing_starts_agree_on_one_key() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create(&dir).unwrap().to_bytes()
                })
            })
            .collect();

        let keys: Vec<[u8; 32]> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let on_disk = load(&dir).unwrap().expect("a key must be published").to_bytes();
        for (i, k) in keys.iter().enumerate() {
            assert_eq!(
                *k, on_disk,
                "starter {i} kept a key that is not the one on disk — its \
                 sealed data dies at the next start",
            );
        }
    }

    use x25519_dalek::PublicKey;

    /// Placeholder identity: neither derived from it nor written. Same reasoning
    /// as the ML-KEM seed's — and here the stakes include the onion auth-cookie,
    /// which derives from the SAME seed, so a shared placeholder would put every
    /// deferred node on one relay cookie.
    #[test]
    fn a_placeholder_identity_neither_derives_nor_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let seed = veil_util::sensitive_bytes::SensitiveBytesN::<32>::from_bytes([0x98u8; 32]);
        veil_identity::sovereign_flow::save_identity_sk(tmp.path(), &seed).unwrap();

        let (sk, src) = load_or_derive(tmp.path(), true, true).unwrap();
        assert_eq!(src, AnonymityKeySource::EphemeralStub);
        assert!(
            load(tmp.path()).unwrap().is_none(),
            "a placeholder must leave nothing on disk"
        );
        assert_ne!(
            sk.to_bytes(),
            derive_from_identity_seed(&seed).to_bytes(),
            "must not derive from the placeholder even though a seed is right there"
        );

        let (sk2, _) = load_or_derive(tmp.path(), true, true).unwrap();
        assert_ne!(sk.to_bytes(), sk2.to_bytes(), "random per boot");
    }

    #[test]
    fn t1_4_p0_load_returns_none_when_file_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let result = load(tmp.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn t1_4_p0_save_then_load_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        save(tmp.path(), &sk).unwrap();
        let loaded = load(tmp.path()).unwrap().unwrap();
        // StaticSecret has no PartialEq; compare via derived public keys
        // (pk = sk * G is deterministic).
        assert_eq!(
            PublicKey::from(&sk).to_bytes(),
            PublicKey::from(&loaded).to_bytes()
        );
    }

    #[test]
    fn t1_4_p0_load_or_create_persists_first_call() {
        let tmp = tempfile::tempdir().unwrap();
        // First call generates + persists.
        let sk1 = load_or_create(tmp.path()).unwrap();
        assert!(key_path(tmp.path()).exists());
        // Second call must return the SAME key (loaded from disk).
        let sk2 = load_or_create(tmp.path()).unwrap();
        assert_eq!(
            PublicKey::from(&sk1).to_bytes(),
            PublicKey::from(&sk2).to_bytes()
        );
    }

    #[test]
    fn t1_4_p0_load_rejects_wrong_length_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = key_path(tmp.path());
        std::fs::write(&path, b"too-short").unwrap();
        // `StaticSecret` doesn't impl Debug, so `.unwrap_err` won't
        // type-check on the Ok branch — pattern-match instead.
        match load(tmp.path()) {
            Ok(_) => panic!("expected load to fail on truncated file"),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidData),
        }
    }

    #[cfg(unix)]
    #[test]
    fn t1_4_p0_save_writes_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        save(tmp.path(), &sk).unwrap();
        let meta = std::fs::metadata(key_path(tmp.path())).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {:o}", mode);
    }

    // ── load_or_derive ───────────────────────────────────────────────────────

    /// An existing persisted key WINS even when a sovereign identity is present:
    /// long-lived nodes (the seeds) must NOT rotate their anonymity key on
    /// upgrade. This is the no-rotation safety guarantee.
    #[test]
    fn load_or_derive_prefers_existing_persisted_key() {
        let tmp = tempfile::tempdir().unwrap();
        let existing = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        save(tmp.path(), &existing).unwrap();
        // Also drop an identity seed so the derive branch WOULD be eligible.
        let seed = veil_util::sensitive_bytes::SensitiveBytesN::<32>::from_bytes([0x11u8; 32]);
        veil_identity::sovereign_flow::save_identity_sk(tmp.path(), &seed).unwrap();

        let (sk, src) = load_or_derive(tmp.path(), true, false).unwrap();
        assert_eq!(src, AnonymityKeySource::Persisted);
        assert_eq!(
            PublicKey::from(&sk).to_bytes(),
            PublicKey::from(&existing).to_bytes(),
            "existing key must be returned unchanged (no rotation)"
        );
    }

    /// An ephemeral-dir node (no persisted anonymity key) with a sovereign
    /// identity DERIVES from the identity seed — deterministically and matching
    /// the standalone derive helper. This is the actual delivery fix.
    #[test]
    fn load_or_derive_derives_from_identity_seed_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let seed = veil_util::sensitive_bytes::SensitiveBytesN::<32>::from_bytes([0x22u8; 32]);
        veil_identity::sovereign_flow::save_identity_sk(tmp.path(), &seed).unwrap();

        let (sk, src) = load_or_derive(tmp.path(), true, false).unwrap();
        assert_eq!(src, AnonymityKeySource::IdentityDerived);
        assert_eq!(
            PublicKey::from(&sk).to_bytes(),
            PublicKey::from(&derive_from_identity_seed(&seed)).to_bytes(),
        );
        // Deriving in a SECOND fresh dir from the SAME seed yields the SAME key
        // (the cross-session stability that fixes the stale-ad black-hole). A
        // derive run must NOT write a key file (no on-disk artifact).
        assert!(
            !key_path(tmp.path()).exists(),
            "derive must not persist a key file"
        );
        let tmp2 = tempfile::tempdir().unwrap();
        veil_identity::sovereign_flow::save_identity_sk(tmp2.path(), &seed).unwrap();
        let (sk2, _) = load_or_derive(tmp2.path(), true, false).unwrap();
        assert_eq!(
            PublicKey::from(&sk).to_bytes(),
            PublicKey::from(&sk2).to_bytes(),
            "same identity seed across sessions must give the same anonymity key"
        );
    }

    /// Identity-less node with no key file: fall back to a fresh random key that
    /// is persisted (legacy behaviour for relay-only daemons without a seed).
    #[test]
    fn load_or_derive_falls_back_to_random_without_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let (_sk, src) = load_or_derive(tmp.path(), false, false).unwrap();
        assert_eq!(src, AnonymityKeySource::FallbackRandom);
        assert!(
            key_path(tmp.path()).exists(),
            "fallback must persist the random key"
        );
    }
}
