//! Encrypted master-seed file.
//!
//! Optional second storage channel for the 32-byte `master_seed`
//! alongside the mandatory BIP-39 paper backup
//! (see [`identity_master`](super::master_seed)). The encrypted
//! file lives at `~/.config/veil/master.enc` by default and is
//! unlocked with a user-chosen password.
//!
//! ## Rationale for BOTH paper + file
//!
//! The paper phrase is the only truly immutable backup — disk
//! corruption cannot touch it, and attackers who compromise a running
//! box cannot grind passwords on it at any speed. The encrypted file
//! complements the paper by giving the user a convenient, machine-
//! readable format for routine operations like `identity rotate` that
//! legitimately need the master inside a process.
//!
//! ## Cryptographic construction
//!
//! ```text
//! kdf_salt ← 16 B random (per-file, regenerated on save)
//! aead_nonce ← 12 B random
//!
//! key (32 B) = Argon2id(
//! password
//! salt = kdf_salt
//! m_cost = 65_536 KiB / 64 MiB
//! t_cost = 3
//! p_cost = 4
//! output_len = 32
//! //!
//! ciphertext || tag (32 + 16 B) =
//! ChaCha20-Poly1305(
//! key
//! nonce = aead_nonce
//! aad = "veil.master.v1"
//! plaintext = master_seed[..32]
//! //! ```
//!
//! The additional authenticated data (AAD) binds the ciphertext to
//! the intended purpose — copying the file into an unrelated context
//! that used a different AAD string would fail authentication even
//! with the correct password.
//!
//! ## Wire layout (binary, big-endian)
//!
//! ```text
//! [0..2] magic = "IM" u16 (Identity-Master)
//! [2] version = 1 u8
//! [3] kdf = 1 u8 (Argon2id)
//! [4..8] m_cost_kib u32
//! [8..12] t_cost u32
//! [12] p_cost u8
//! [13] salt_len u8
//! [..] salt [u8; salt_len]
//! [12] nonce_len = 12 u8
//! [..] nonce [u8; 12]
//! [..] ciphertext_len u16 BE
//! [..] ciphertext_and_tag [u8; ciphertext_len]
//! ```
//!
//! Every KDF parameter ships in-band so a future tightening (e.g.
//! m_cost = 128 MiB) loads older files transparently. The verifier
//! refuses parameters below the minimums declared in
//! [`MIN_M_COST_KIB`] / [`MIN_T_COST`] / [`MIN_P_COST`] to block
//! downgrade attacks from a tampered file.
//!
//! ## File mode
//!
//! On Unix the file is written with `0o600`. The temporary file used
//! for atomic rename is removed on failure so a crash mid-write does
//! not leave a readable scratch copy.

use std::fs;
use std::io;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use super::master_seed::MASTER_SEED_LEN;

// ── Constants ────────────────────────────────────────────────────────────────

/// Magic bytes identifying an encrypted-master file.
pub const MASTER_FILE_MAGIC: [u8; 2] = [b'I', b'M'];
/// Wire-format version.
pub const MASTER_FILE_V1: u8 = 1;

/// KDF byte: Argon2id.
pub const KDF_ARGON2ID: u8 = 1;

/// AEAD additional-authenticated-data string — binds the ciphertext
/// to this module's purpose.
pub const MASTER_FILE_AAD: &[u8] = b"veil.master.v1";

/// Default Argon2id memory cost (64 MiB).
pub const DEFAULT_M_COST_KIB: u32 = 64 * 1024;
/// Default Argon2id iteration count.
pub const DEFAULT_T_COST: u32 = 3;
/// Default Argon2id parallelism.
pub const DEFAULT_P_COST: u32 = 4;

/// Minimum m_cost we accept when opening a file — prevents downgrade
/// attacks from a tampered header that asks Argon2 to barely hash.
pub const MIN_M_COST_KIB: u32 = 16 * 1024;
/// Minimum t_cost accepted on open.
pub const MIN_T_COST: u32 = 1;
/// Minimum p_cost accepted on open.
pub const MIN_P_COST: u8 = 1;

/// Length of the AEAD nonce (ChaCha20-Poly1305 uses 96-bit nonces).
pub const AEAD_NONCE_LEN: usize = 12;
/// Length of the KDF salt (128 bits).
pub const KDF_SALT_LEN: usize = 16;
/// Length of the AEAD authentication tag appended to ciphertext.
pub const AEAD_TAG_LEN: usize = 16;
/// Total ciphertext = seed || tag.
pub const CIPHERTEXT_LEN: usize = MASTER_SEED_LEN + AEAD_TAG_LEN;

/// Upper bound on the full wire size — small by construction (~120 B)
/// but this guards against a malicious file claiming a gigabyte
/// `ciphertext_len`.
pub const MAX_MASTER_FILE_BYTES: usize = 512;

// ── Errors ───────────────────────────────────────────────────────────────────

/// Errors emitted while saving or loading the encrypted master file.
#[derive(Debug, thiserror::Error)]
pub enum MasterFileError {
    #[error("master file io: {0}")]
    Io(#[from] io::Error),
    #[error("master file malformed: {0}")]
    Malformed(String),
    #[error("master file uses unsupported KDF {0}")]
    UnsupportedKdf(u8),
    #[error(
        "master file KDF parameters below minimum (m_cost={m_cost}, \
         t_cost={t_cost}, p_cost={p_cost})"
    )]
    KdfTooWeak {
        m_cost: u32,
        t_cost: u32,
        p_cost: u8,
    },
    #[error(
        "master file KDF parameters above maximum (m_cost={m_cost}, \
         t_cost={t_cost}, p_cost={p_cost}) — refusing to run an unbounded KDF"
    )]
    KdfTooStrong {
        m_cost: u32,
        t_cost: u32,
        p_cost: u8,
    },
    #[error("master file password is wrong or file is corrupt")]
    WrongPasswordOrTampered,
    #[error("argon2 error: {0}")]
    Argon2(String),
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Encrypt `seed` with `password` and write the result to `path`
/// atomically (tmp + fsync + rename).
///
/// Creates the parent directory if missing. On Unix, sets the file
/// mode to `0o600` so group/world cannot read the ciphertext.
///
/// Uses the default Argon2id parameters. Callers may substitute
/// higher values [`save_master_seed_encrypted_with`].
pub fn save_master_seed_encrypted(
    path: &Path,
    seed: &[u8; MASTER_SEED_LEN],
    password: &[u8],
) -> Result<(), MasterFileError> {
    save_master_seed_encrypted_with(
        path,
        seed,
        password,
        DEFAULT_M_COST_KIB,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
    )
}

/// Like [`save_master_seed_encrypted`] but lets the caller pin KDF
/// parameters — test scenarios use very cheap parameters to keep the
/// suite fast; production calls the default wrapper.
pub fn save_master_seed_encrypted_with(
    path: &Path,
    seed: &[u8; MASTER_SEED_LEN],
    password: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(), MasterFileError> {
    let encoded = encode_master_seed_encrypted_with(seed, password, m_cost_kib, t_cost, p_cost)?;
    write_file_atomically_secure(path, &encoded)?;
    Ok(())
}

/// produce the encrypted master-seed bundle as bytes
/// without writing to disk. Used by the QR cold-backup flow
/// which encodes the bundle into an `veil:master-backup?…`
/// URI for offline (photographable) storage. Same wire layout as
/// `save_master_seed_encrypted_with` — every byte that lands on
/// disk in the production path also lands in the QR payload, so
/// `decode_master_seed_encrypted` accepts both.
pub fn encode_master_seed_encrypted_with(
    seed: &[u8; MASTER_SEED_LEN],
    password: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u8>, MasterFileError> {
    let mut salt = [0u8; KDF_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(password, &salt, m_cost_kib, t_cost, p_cost)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_array()));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: seed,
                aad: MASTER_FILE_AAD,
            },
        )
        .map_err(|_| MasterFileError::Argon2("chacha20poly1305 encrypt failed".into()))?;

    Ok(encode_file(m_cost_kib, t_cost, p_cost, &salt, &nonce, &ct))
}

/// decrypt an encrypted master-seed bundle held in
/// memory (the inverse [`encode_master_seed_encrypted_with`]).
/// Used by the QR backup import flow + by
/// [`load_master_seed_encrypted`] internally. Enforces the same
/// `MIN_M_COST_KIB` / `MIN_T_COST` / `MIN_P_COST` downgrade
/// guards as the file-based loader.
pub fn decode_master_seed_encrypted(
    bytes: &[u8],
    password: &[u8],
) -> Result<Zeroizing<[u8; MASTER_SEED_LEN]>, MasterFileError> {
    if bytes.len() > MAX_MASTER_FILE_BYTES {
        return Err(MasterFileError::Malformed(format!(
            "buffer too large ({}B > {MAX_MASTER_FILE_BYTES}B)",
            bytes.len()
        )));
    }
    let parsed = decode_file(bytes)?;
    if parsed.m_cost_kib < MIN_M_COST_KIB
        || parsed.t_cost < MIN_T_COST
        || parsed.p_cost < MIN_P_COST
    {
        return Err(MasterFileError::KdfTooWeak {
            m_cost: parsed.m_cost_kib,
            t_cost: parsed.t_cost,
            p_cost: parsed.p_cost,
        });
    }
    // audit cycle-7 (MED): clamp the UPPER bound + m_cost×t_cost product of the
    // in-band Argon2id cost params BEFORE any KDF work. The bundle is
    // attacker-photographable (QR cold-backup import / pasteable
    // `veil:master-backup` URI), so the cost params are attacker-controlled.
    // Without an upper clamp, m_cost_kib up to u32::MAX makes argon2 attempt a
    // ~4 TiB allocation (and m_cost×t_cost a multi-minute CPU burn) BEFORE the
    // AEAD tag is even checked → OOM / DoS of the importing process. Bounds
    // mirror the sibling `veil-e2e::decode_pem_encrypted` hardening (audit
    // 2026-05-25 phase L): 1 GiB memory / 1000 iters / 64 lanes individual caps
    // + a 256 GiB·iter product cap — generous beyond any legitimate Argon2
    // schedule (OWASP m=64 MiB t=3 = 192 MiB·iter sits far inside this).
    const MAX_M_COST_KIB: u32 = 1_048_576; // 1 GiB
    const MAX_T_COST: u32 = 1000;
    const MAX_P_COST: u8 = 64;
    const MAX_KDF_PRODUCT_KIB: u64 = 256 * 1024 * 1024; // 256 GiB·iter
    if parsed.m_cost_kib > MAX_M_COST_KIB
        || parsed.t_cost > MAX_T_COST
        || parsed.p_cost > MAX_P_COST
        || (parsed.m_cost_kib as u64).saturating_mul(parsed.t_cost as u64) > MAX_KDF_PRODUCT_KIB
    {
        return Err(MasterFileError::KdfTooStrong {
            m_cost: parsed.m_cost_kib,
            t_cost: parsed.t_cost,
            p_cost: parsed.p_cost,
        });
    }
    let key = derive_key(
        password,
        &parsed.salt,
        parsed.m_cost_kib,
        parsed.t_cost,
        parsed.p_cost as u32,
    )?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_array()));
    // wrap the decrypt result в `Zeroizing` IMMEDIATELY so
    // the master-seed bytes are wiped on every exit path (early
    // return, panic, etc.) — not relying on а manual loop after а
    // copy. Closes the timing window where the seed sits in plain
    // heap storage between the AEAD decrypt и the explicit zeroing.
    let pt: Zeroizing<Vec<u8>> = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&parsed.nonce),
                Payload {
                    msg: &parsed.ciphertext,
                    aad: MASTER_FILE_AAD,
                },
            )
            .map_err(|_| MasterFileError::WrongPasswordOrTampered)?,
    );
    if pt.len() != MASTER_SEED_LEN {
        return Err(MasterFileError::Malformed(format!(
            "decrypted plaintext length {} != {MASTER_SEED_LEN}",
            pt.len()
        )));
    }
    let mut out = Zeroizing::new([0u8; MASTER_SEED_LEN]);
    out.copy_from_slice(&pt);
    // pt is dropped here, Zeroizing wipes the heap allocation.
    Ok(out)
}

/// Decrypt the master seed at `path` using `password`.
///
/// Returns the 32-byte seed wrapped [`Zeroizing`]. Any tampering
/// (wrong password, mutated ciphertext, mismatched AAD) surfaces as
/// [`MasterFileError::WrongPasswordOrTampered`] — indistinguishable
/// by design, so error messages do not leak whether the password
/// was close or the file was corrupt.
pub fn load_master_seed_encrypted(
    path: &Path,
    password: &[u8],
) -> Result<Zeroizing<[u8; MASTER_SEED_LEN]>, MasterFileError> {
    // wrap the on-disk ciphertext
    // buffer in `Zeroizing` so it's wiped on every exit path. The
    // ciphertext is not directly catastrophic to leak (still
    // password-encrypted), but the bundled salt + KDF parameters are
    // useful to a future cracker, and zeroizing all key-adjacent
    // material is cheap insurance against a memory-disclosure bug
    // elsewhere in the process.
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(fs::read(path)?);
    decode_master_seed_encrypted(&bytes, password)
}

/// Re-encrypt an existing file with a new password (master-key
/// rotation at the file level without changing the underlying seed).
pub fn change_master_file_password(
    path: &Path,
    old_password: &[u8],
    new_password: &[u8],
) -> Result<(), MasterFileError> {
    let seed = load_master_seed_encrypted(path, old_password)?;
    save_master_seed_encrypted(path, &seed, new_password)
}

// ── Codec ────────────────────────────────────────────────────────────────────

struct Parsed {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u8,
    salt: Vec<u8>,
    nonce: [u8; AEAD_NONCE_LEN],
    ciphertext: Vec<u8>,
}

fn encode_file(
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    salt: &[u8],
    nonce: &[u8; AEAD_NONCE_LEN],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + salt.len() + ciphertext.len());
    out.extend_from_slice(&MASTER_FILE_MAGIC);
    out.push(MASTER_FILE_V1);
    out.push(KDF_ARGON2ID);
    out.extend_from_slice(&m_cost_kib.to_be_bytes());
    out.extend_from_slice(&t_cost.to_be_bytes());
    out.push(p_cost as u8);
    out.push(salt.len() as u8);
    out.extend_from_slice(salt);
    out.push(AEAD_NONCE_LEN as u8);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
}

fn decode_file(buf: &[u8]) -> Result<Parsed, MasterFileError> {
    if buf.len() < 16 {
        return Err(MasterFileError::Malformed(format!(
            "buffer too short ({}B)",
            buf.len()
        )));
    }
    if buf[0..2] != MASTER_FILE_MAGIC {
        return Err(MasterFileError::Malformed("bad magic".into()));
    }
    if buf[2] != MASTER_FILE_V1 {
        return Err(MasterFileError::Malformed(format!(
            "unsupported version {}",
            buf[2]
        )));
    }
    let kdf = buf[3];
    if kdf != KDF_ARGON2ID {
        return Err(MasterFileError::UnsupportedKdf(kdf));
    }

    let mut pos = 4;
    let m_cost_kib = read_u32(buf, &mut pos)?;
    let t_cost = read_u32(buf, &mut pos)?;
    let p_cost = read_u8(buf, &mut pos)?;
    let salt_len = read_u8(buf, &mut pos)? as usize;
    if salt_len == 0 || salt_len > 64 {
        return Err(MasterFileError::Malformed(format!(
            "salt_len {salt_len} out of range"
        )));
    }
    let salt = read_bytes(buf, &mut pos, salt_len)?.to_vec();

    let nonce_len = read_u8(buf, &mut pos)? as usize;
    if nonce_len != AEAD_NONCE_LEN {
        return Err(MasterFileError::Malformed(format!(
            "nonce_len {nonce_len} != {AEAD_NONCE_LEN}"
        )));
    }
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(read_bytes(buf, &mut pos, AEAD_NONCE_LEN)?);

    let ct_len = read_u16(buf, &mut pos)? as usize;
    // The only legitimate ciphertext length is seed (32) + tag (16) =
    // 48 bytes. Reject anything else up front.
    if ct_len != CIPHERTEXT_LEN {
        return Err(MasterFileError::Malformed(format!(
            "ciphertext_len {ct_len} != {CIPHERTEXT_LEN}"
        )));
    }
    let ciphertext = read_bytes(buf, &mut pos, ct_len)?.to_vec();

    if pos != buf.len() {
        return Err(MasterFileError::Malformed(format!(
            "{} trailing bytes",
            buf.len() - pos
        )));
    }

    Ok(Parsed {
        m_cost_kib,
        t_cost,
        p_cost,
        salt,
        nonce,
        ciphertext,
    })
}

fn read_u8(buf: &[u8], pos: &mut usize) -> Result<u8, MasterFileError> {
    let v = *buf
        .get(*pos)
        .ok_or_else(|| MasterFileError::Malformed(format!("truncated at {}", *pos)))?;
    *pos += 1;
    Ok(v)
}

fn read_u16(buf: &[u8], pos: &mut usize) -> Result<u16, MasterFileError> {
    let slice = buf
        .get(*pos..*pos + 2)
        .ok_or_else(|| MasterFileError::Malformed(format!("truncated u16 at {}", *pos)))?;
    let v = u16::from_be_bytes(slice.try_into().unwrap());
    *pos += 2;
    Ok(v)
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32, MasterFileError> {
    let slice = buf
        .get(*pos..*pos + 4)
        .ok_or_else(|| MasterFileError::Malformed(format!("truncated u32 at {}", *pos)))?;
    let v = u32::from_be_bytes(slice.try_into().unwrap());
    *pos += 4;
    Ok(v)
}

fn read_bytes<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], MasterFileError> {
    let slice = buf
        .get(*pos..*pos + n)
        .ok_or_else(|| MasterFileError::Malformed(format!("truncated {}B at {}", n, *pos)))?;
    *pos += n;
    Ok(slice)
}

// ── KDF + atomic write ───────────────────────────────────────────────────────

fn derive_key(
    password: &[u8],
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<veil_util::sensitive_bytes::SensitiveBytesN<32>, MasterFileError> {
    // Этап 6 slice 6d: pilot migration от `Zeroizing<[u8; 32]>` к the
    // mlock-when-possible `SensitiveBytesN<32>` companion type.  The
    // Argon2-derived key пинна in RAM (closes the swap-к-disk vector)
    // when `RLIMIT_MEMLOCK` permits; falls back к zeroize-only otherwise
    // (same protection as the pre-Этап-6 code path).  Caller-side API
    // changes: `.as_ref()` → `.as_array()`.
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
        .map_err(|e| MasterFileError::Argon2(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key: veil_util::sensitive_bytes::SensitiveBytesN<32> =
        veil_util::sensitive_bytes::SensitiveBytesN::new();
    argon
        .hash_password_into(password, salt, key.as_mut_slice())
        .map_err(|e| MasterFileError::Argon2(e.to_string()))?;
    Ok(key)
}

fn write_file_atomically_secure(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // Delegate к the shared helper, which already provides:
    //   - parent `mkdir -p` with EACCES retry
    //   - tmp-file open `0o600` on Unix (owner-only)
    //   - `f.sync_all()` on the tmp file
    //   - atomic `rename(tmp, path)`
    //   - **fsync of the parent dir after rename** — the bit this
    //     local copy was missing. Without parent-dir fsync а power
    //     loss in the narrow window between `rename(2)` returning и
    //     the dirent hitting disk could leave the directory referencing
    //     either the old name (file gone), the new name (good), or а
    //     half-allocated inode. Most FS configs journal dirent updates
    //     по умолчанию, но explicit parent fsync is the portable guarantee.
    veil_util::atomic_write(path, bytes)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Test-only parameters: cheap enough to run 10+ tests in < 2 s.
    // The test suite still exercises the full codec path — only the
    // KDF cost is lowered.
    const TEST_M_COST_KIB: u32 = 16 * 1024; // 16 MiB — above MIN_M_COST_KIB
    const TEST_T_COST: u32 = 1;
    const TEST_P_COST: u32 = 1;

    fn tempdir() -> PathBuf {
        crate::test_support::scratch_dir("veil-master-file-test")
    }

    fn save_test(path: &Path, seed: &[u8; MASTER_SEED_LEN], password: &[u8]) {
        save_master_seed_encrypted_with(
            path,
            seed,
            password,
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
        )
        .unwrap();
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let dir = tempdir();
        let path = dir.join("master.enc");
        let seed = [0x42u8; MASTER_SEED_LEN];
        save_test(&path, &seed, b"correct horse battery staple");

        let decoded = load_master_seed_encrypted(&path, b"correct horse battery staple").unwrap();
        assert_eq!(&*decoded, &seed);
    }

    #[test]
    fn decode_rejects_oversized_argon2_cost() {
        // cycle-7 (MED): a structurally-valid bundle declaring an absurd Argon2
        // cost must be rejected as KdfTooStrong BEFORE any KDF allocation —
        // guards the QR / master-backup import path against unbounded-alloc
        // OOM/DoS (mirror of the veil-e2e phase-L hardening).
        let salt = [0x11u8; 16];
        let nonce = [0x22u8; AEAD_NONCE_LEN];
        let ct = [0x33u8; CIPHERTEXT_LEN];

        // (a) absurd m_cost — argon2 would attempt a ~4 TiB allocation.
        let huge_m = encode_file(u32::MAX, TEST_T_COST, TEST_P_COST, &salt, &nonce, &ct);
        assert!(
            matches!(
                decode_master_seed_encrypted(&huge_m, b"pw").unwrap_err(),
                MasterFileError::KdfTooStrong { .. }
            ),
            "u32::MAX m_cost must be rejected as KdfTooStrong",
        );

        // (b) t_cost over the per-param cap.
        let huge_t = encode_file(TEST_M_COST_KIB, 100_000, TEST_P_COST, &salt, &nonce, &ct);
        assert!(matches!(
            decode_master_seed_encrypted(&huge_t, b"pw").unwrap_err(),
            MasterFileError::KdfTooStrong { .. }
        ));

        // (c) product cap: each param under its individual cap but m×t huge.
        let huge_product = encode_file(1_000_000, 1000, TEST_P_COST, &salt, &nonce, &ct);
        assert!(matches!(
            decode_master_seed_encrypted(&huge_product, b"pw").unwrap_err(),
            MasterFileError::KdfTooStrong { .. }
        ));

        // (d) sane params pass the clamp (reach the AEAD step → wrong-password
        // rejection, NOT KdfTooStrong).
        let sane = encode_file(
            TEST_M_COST_KIB,
            TEST_T_COST,
            TEST_P_COST,
            &salt,
            &nonce,
            &ct,
        );
        assert!(
            !matches!(
                decode_master_seed_encrypted(&sane, b"pw").unwrap_err(),
                MasterFileError::KdfTooStrong { .. }
            ),
            "sane KDF params must pass the cost clamp",
        );
    }

    #[test]
    fn wrong_password_rejected() {
        let dir = tempdir();
        let path = dir.join("master.enc");
        save_test(&path, &[0u8; MASTER_SEED_LEN], b"good password");
        let err = load_master_seed_encrypted(&path, b"wrong password").unwrap_err();
        assert!(
            matches!(err, MasterFileError::WrongPasswordOrTampered),
            "{err:?}"
        );
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let dir = tempdir();
        let path = dir.join("master.enc");
        save_test(&path, &[0x11u8; MASTER_SEED_LEN], b"password");

        // Flip a byte deep in the ciphertext region.
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 4;
        bytes[last] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        let err = load_master_seed_encrypted(&path, b"password").unwrap_err();
        assert!(
            matches!(err, MasterFileError::WrongPasswordOrTampered),
            "{err:?}"
        );
    }

    #[test]
    fn tampered_nonce_rejected() {
        let dir = tempdir();
        let path = dir.join("master.enc");
        save_test(&path, &[0x22u8; MASTER_SEED_LEN], b"password");

        // Flip a byte in the nonce region (offset 4+4+4+1+1+16+1 = 31: nonce
        // starts right after "nonce_len" byte). Walk using our known header.
        let mut bytes = fs::read(&path).unwrap();
        // Header = 2 magic + 1 ver + 1 kdf + 4 m_cost + 4 t_cost + 1 p_cost
        // + 1 salt_len + salt + 1 nonce_len + nonce...
        // With KDF_SALT_LEN = 16, nonce starts at 2+1+1+4+4+1+1+16+1 = 31.
        let nonce_offset = 2 + 1 + 1 + 4 + 4 + 1 + 1 + KDF_SALT_LEN + 1;
        bytes[nonce_offset] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        let err = load_master_seed_encrypted(&path, b"password").unwrap_err();
        assert!(
            matches!(err, MasterFileError::WrongPasswordOrTampered),
            "{err:?}"
        );
    }

    #[test]
    fn tampered_aad_equivalent_rejected_via_magic() {
        // We bind AAD in-process; there's no way for an attacker to
        // "use a different AAD" on load since the module hard-codes
        // it. But we can simulate an older file produced under a
        // different AAD by corrupting magic → that decodes as
        // Malformed, not Wrong­PasswordOrTampered, confirming the
        // magic gate fires first.
        let dir = tempdir();
        let path = dir.join("master.enc");
        save_test(&path, &[0x33u8; MASTER_SEED_LEN], b"p");
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] = b'X';
        fs::write(&path, &bytes).unwrap();
        let err = load_master_seed_encrypted(&path, b"p").unwrap_err();
        assert!(matches!(err, MasterFileError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_unsupported_version() {
        let dir = tempdir();
        let path = dir.join("master.enc");
        save_test(&path, &[0u8; MASTER_SEED_LEN], b"p");
        let mut bytes = fs::read(&path).unwrap();
        bytes[2] = 99;
        fs::write(&path, &bytes).unwrap();
        let err = load_master_seed_encrypted(&path, b"p").unwrap_err();
        assert!(matches!(err, MasterFileError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_unsupported_kdf() {
        let dir = tempdir();
        let path = dir.join("master.enc");
        save_test(&path, &[0u8; MASTER_SEED_LEN], b"p");
        let mut bytes = fs::read(&path).unwrap();
        bytes[3] = 99;
        fs::write(&path, &bytes).unwrap();
        let err = load_master_seed_encrypted(&path, b"p").unwrap_err();
        assert!(
            matches!(err, MasterFileError::UnsupportedKdf(99)),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_params_below_minimum_on_open() {
        // Craft a file header claiming m_cost = 1 KiB — well below
        // MIN_M_COST_KIB. We don't actually need a valid ciphertext
        // since the KDF check fires before decryption.
        let dir = tempdir();
        let path = dir.join("master.enc");
        let mut out = Vec::new();
        out.extend_from_slice(&MASTER_FILE_MAGIC);
        out.push(MASTER_FILE_V1);
        out.push(KDF_ARGON2ID);
        out.extend_from_slice(&1u32.to_be_bytes()); // m_cost = 1 KiB (too weak)
        out.extend_from_slice(&1u32.to_be_bytes()); // t_cost
        out.push(1); // p_cost
        out.push(KDF_SALT_LEN as u8);
        out.extend_from_slice(&[0u8; KDF_SALT_LEN]);
        out.push(AEAD_NONCE_LEN as u8);
        out.extend_from_slice(&[0u8; AEAD_NONCE_LEN]);
        out.extend_from_slice(&(CIPHERTEXT_LEN as u16).to_be_bytes());
        out.extend_from_slice(&[0u8; CIPHERTEXT_LEN]);
        fs::write(&path, &out).unwrap();
        let err = load_master_seed_encrypted(&path, b"p").unwrap_err();
        assert!(matches!(err, MasterFileError::KdfTooWeak { .. }), "{err:?}");
    }

    #[test]
    fn rejects_trailing_bytes() {
        let dir = tempdir();
        let path = dir.join("master.enc");
        save_test(&path, &[0u8; MASTER_SEED_LEN], b"p");
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(0xFF);
        fs::write(&path, &bytes).unwrap();
        let err = load_master_seed_encrypted(&path, b"p").unwrap_err();
        assert!(matches!(err, MasterFileError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_truncated_file() {
        let dir = tempdir();
        let path = dir.join("master.enc");
        save_test(&path, &[0u8; MASTER_SEED_LEN], b"p");
        let mut bytes = fs::read(&path).unwrap();
        bytes.truncate(bytes.len() - 5);
        fs::write(&path, &bytes).unwrap();
        let err = load_master_seed_encrypted(&path, b"p").unwrap_err();
        assert!(matches!(err, MasterFileError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_oversized_file() {
        let dir = tempdir();
        let path = dir.join("master.enc");
        fs::write(&path, vec![0u8; MAX_MASTER_FILE_BYTES + 1]).unwrap();
        let err = load_master_seed_encrypted(&path, b"p").unwrap_err();
        assert!(matches!(err, MasterFileError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn different_passwords_produce_different_files() {
        // Even with the same seed, two save calls should produce
        // different ciphertexts because salt + nonce are random.
        let dir = tempdir();
        let path_a = dir.join("a.enc");
        let path_b = dir.join("b.enc");
        let seed = [0x77u8; MASTER_SEED_LEN];
        save_test(&path_a, &seed, b"alpha");
        save_test(&path_b, &seed, b"alpha");
        let a = fs::read(&path_a).unwrap();
        let b = fs::read(&path_b).unwrap();
        assert_ne!(a, b, "salt/nonce must be random per save");
    }

    #[test]
    fn change_password_keeps_seed_invariant() {
        let dir = tempdir();
        let path = dir.join("master.enc");
        let seed = [0xAAu8; MASTER_SEED_LEN];
        save_test(&path, &seed, b"old");
        // change_master_file_password uses the default params, which
        // cost ~100 ms / call — fine for one call in a test.
        change_master_file_password(&path, b"old", b"new").unwrap();
        let decoded = load_master_seed_encrypted(&path, b"new").unwrap();
        assert_eq!(&*decoded, &seed);
        // Old password must now fail.
        let err = load_master_seed_encrypted(&path, b"old").unwrap_err();
        assert!(matches!(err, MasterFileError::WrongPasswordOrTampered));
    }

    #[test]
    fn creates_parent_directory() {
        let dir = tempdir();
        let path = dir.join("sub").join("dir").join("master.enc");
        save_test(&path, &[0u8; MASTER_SEED_LEN], b"p");
        assert!(path.exists());
    }

    #[test]
    #[cfg(unix)]
    fn file_mode_is_600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let path = dir.join("master.enc");
        save_test(&path, &[0u8; MASTER_SEED_LEN], b"p");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        // u+rw, no other bits set.
        assert_eq!(
            mode & 0o777,
            0o600,
            "expected 0o600, got {:o}",
            mode & 0o777
        );
    }

    #[test]
    fn round_trip_with_empty_password() {
        // Argon2 accepts empty passwords; we should too (no policy
        // decision about password strength at this layer — UX layer
        // will enforce minimum lengths).
        let dir = tempdir();
        let path = dir.join("master.enc");
        let seed = [0x01u8; MASTER_SEED_LEN];
        save_test(&path, &seed, b"");
        let decoded = load_master_seed_encrypted(&path, b"").unwrap();
        assert_eq!(&*decoded, &seed);
    }
}
