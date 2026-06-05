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

/// Load the key from disk; if absent, generate a fresh one and persist.
///
/// The two-step (load → maybe-save) is intentionally not atomic: if two
/// processes race on first startup, both will generate a key and one
/// will overwrite the other's file [`veil_util::atomic_write`]'s
/// `rename(2)`. The losing process keeps using its in-memory key
/// which becomes orphaned (un-decryptable) once it restarts. Operators
/// are expected to run a single daemon per `veil_dir`; this is the
/// same constraint as [`SovereignIdentity`].
pub fn load_or_create(veil_dir: &Path) -> std::io::Result<x25519_dalek::StaticSecret> {
    if let Some(sk) = load(veil_dir)? {
        return Ok(sk);
    }
    let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    save(veil_dir, &sk)?;
    Ok(sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::PublicKey;

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
}
