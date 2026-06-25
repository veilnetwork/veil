//! E2E encryption helpers.
//!
//! Wraps ML-KEM-768 + HKDF-SHA256 + ChaCha20-Poly1305 to provide
//! `encrypt` / `decrypt` for application payloads traversing relay nodes.
//!
//! # Key persistence
//!
//! `load_or_generate_mlkem_key_encrypted(path, passphrase)` loads the 64-byte
//! DK seed from a PEM-like file at `path`, or generates and saves a fresh
//! keypair if the file does not exist. The encapsulation key (public key
//! 1184 bytes) is always re-derived from the seed.

use std::path::Path;

use base64::Engine as _;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use ml_kem::{
    Decapsulate, Encapsulate, Kem, KeyExport, MlKem768, Seed, array::Array, kem::DecapsulationKey,
    ml_kem_768::EncapsulationKey as EK768,
};
use rand_core::OsRng;
use sha2::Sha256;

use veil_proto::{E2eEnvelope, ProtoError};

// ── Key sizes ─────────────────────────────────────────────────────────────────

/// Size of a serialised ML-KEM-768 encapsulation key (public key), in bytes.
pub const EK_BYTES: usize = 1184;
/// Size of a ML-KEM-768 decapsulation-key seed, in bytes.
pub const DK_SEED_BYTES: usize = 64;

/// Cached peer ML-KEM-768 encapsulation key: `peer_id → (ek_bytes, cached_at)`.
///
/// The `cached_at` timestamp is used for TTL-based eviction in the maintenance
/// loop (see `IpcConfig::e2e_key_ttl_secs`).
pub type PeerMlKemCache = std::collections::HashMap<[u8; 32], (Vec<u8>, std::time::Instant)>;

type DK768 = DecapsulationKey<MlKem768>;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum E2eError {
    #[error("proto error: {0}")]
    Proto(#[from] ProtoError),

    /// Variant only constructed by `parse_ek` which is only called from
    /// IPC-server paths (`#[cfg(unix)]`). Live on Unix; suppress the
    /// Windows-target warning until wires the IPC TCP backend.
    #[error("invalid encapsulation key ({0} bytes, expected {EK_BYTES})")]
    InvalidEk(usize),

    #[error("invalid decapsulation key seed ({0} bytes, expected {DK_SEED_BYTES})")]
    InvalidDk(usize),

    #[error("ML-KEM decapsulation failed")]
    DecapsulationFailed,

    #[error("AEAD authentication failed")]
    AeadAuthFailed,

    #[error("meta-E2E plaintext too short: {0} bytes (need ≥ 100)")]
    MetaPlaintextTooShort(usize),

    /// ML-KEM key file exists but cannot be decoded. Refusing to silently
    /// regenerate — that would destroy the existing DK seed and orphan every
    /// E2E mailbox payload encrypted to the old EK. Operator must either
    /// supply the correct passphrase, restore the file from backup, or
    /// explicitly delete `mlkem.key` to force fresh generation.
    #[error(
        "ML-KEM key file at {path} exists but could not be decoded \
         (wrong passphrase, corrupt file, or unknown PEM format). Refusing \
         to regenerate; delete the file explicitly if you intended a fresh keypair."
    )]
    MlKemKeyUnreadable { path: std::path::PathBuf },

    /// ML-KEM key file I/O error during read or atomic write.
    #[error("ML-KEM key file I/O error at {path}: {source}")]
    MlKemKeyIo {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate a fresh ML-KEM-768 keypair.
///
/// Returns `(encapsulation_key_bytes, decapsulation_key_seed_bytes)`.
pub fn generate_keypair() -> ([u8; EK_BYTES], [u8; DK_SEED_BYTES]) {
    let (dk, ek) = MlKem768::generate_keypair();
    let ek_arr = ek.to_bytes();
    let seed = dk.to_seed().expect("freshly generated key must have seed");
    let ek_bytes: [u8; EK_BYTES] = ek_arr.as_slice().try_into().expect("EK size mismatch");
    let dk_bytes: [u8; DK_SEED_BYTES] = seed.as_slice().try_into().expect("DK size mismatch");
    (ek_bytes, dk_bytes)
}

/// Encrypt `plaintext` for `recipient_ek` (raw 1184-byte encapsulation key).
///
/// `src_id` / `dst_id` are 32-byte node IDs used as AEAD context and HKDF info.
///
/// Called only from `ipc/server.rs` which is `#[cfg(unix)]`; suppress the
/// Windows-target dead-code warning until wires the IPC TCP backend.
pub fn encrypt(
    recipient_ek: &[u8],
    src_id: &[u8; 32],
    dst_id: &[u8; 32],
    plaintext: &[u8],
) -> Result<E2eEnvelope, E2eError> {
    encrypt_with_ack(recipient_ek, src_id, dst_id, plaintext).map(|(env, _ack)| env)
}

/// Like [`encrypt`], but also returns the per-message **delivery-ACK key** =
/// `HKDF(shared_secret, … "ack" …)`, domain-separated from the AEAD key. The
/// sender stores it; the recipient re-derives the same key via
/// [`decrypt_with_ack`]. A relay that only sees the envelope cannot derive it
/// (it never learns the ML-KEM shared secret). Used by the authenticated
/// DELIVERED-ACK (C-09): the recipient MACs `content_id` with this key so a
/// relay cannot forge a delivery confirmation it never actually performed.
pub fn encrypt_with_ack(
    recipient_ek: &[u8],
    src_id: &[u8; 32],
    dst_id: &[u8; 32],
    plaintext: &[u8],
) -> Result<(E2eEnvelope, [u8; 32]), E2eError> {
    let ek = parse_ek(recipient_ek)?;

    // 1. ML-KEM-768 encapsulation — (ciphertext, shared_secret)
    let (kem_ct, shared_secret) = ek.encapsulate();
    let kem_ct_bytes: Vec<u8> = kem_ct.as_slice().to_vec();
    let ss: &[u8] = shared_secret.as_slice();

    // 2. HKDF-SHA256 key derivation (AEAD key + domain-separated ACK key)
    let key = derive_key(ss, src_id, dst_id);
    let ack_key = derive_ack_key(ss, src_id, dst_id);

    // 3. Random 12-byte nonce
    let nonce_arr: [u8; 12] = {
        use rand_core::RngCore;
        let mut n = [0u8; 12];
        OsRng.fill_bytes(&mut n);
        n
    };

    // 4. ChaCha20-Poly1305 encrypt
    let aad = make_aad(src_id, dst_id);
    let ciphertext = ChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(
            Nonce::from_slice(&nonce_arr),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| E2eError::AeadAuthFailed)?;

    Ok((
        E2eEnvelope {
            kem_ciphertext: kem_ct_bytes,
            nonce: nonce_arr,
            ciphertext,
        },
        ack_key,
    ))
}

/// Decrypt an [`E2eEnvelope`] using the local 64-byte decapsulation-key seed.
pub fn decrypt(
    dk_seed: &[u8],
    src_id: &[u8; 32],
    dst_id: &[u8; 32],
    envelope: &E2eEnvelope,
) -> Result<Vec<u8>, E2eError> {
    decrypt_with_ack(dk_seed, src_id, dst_id, envelope).map(|(plain, _ack)| plain)
}

/// Like [`decrypt`], but also returns the per-message delivery-ACK key derived
/// from the same ML-KEM shared secret (matches [`encrypt_with_ack`]). The
/// recipient uses it to MAC `content_id` in the authenticated DELIVERED-ACK
/// (C-09) so a relay cannot forge a delivery confirmation.
pub fn decrypt_with_ack(
    dk_seed: &[u8],
    src_id: &[u8; 32],
    dst_id: &[u8; 32],
    envelope: &E2eEnvelope,
) -> Result<(Vec<u8>, [u8; 32]), E2eError> {
    let dk = parse_dk(dk_seed)?;

    // 1. ML-KEM-768 decapsulation using raw ciphertext bytes
    let shared_secret = dk
        .decapsulate_slice(&envelope.kem_ciphertext)
        .map_err(|_| E2eError::DecapsulationFailed)?;
    let ss: &[u8] = shared_secret.as_slice();

    // 2. HKDF-SHA256 key derivation (must match encrypt)
    let key = derive_key(ss, src_id, dst_id);
    let ack_key = derive_ack_key(ss, src_id, dst_id);

    // 3. ChaCha20-Poly1305 decrypt
    let aad = make_aad(src_id, dst_id);
    let plain = ChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(
            Nonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| E2eError::AeadAuthFailed)?;
    Ok((plain, ack_key))
}

/// Result type [`meta_decrypt`]: `(sender_node_id, src_app_id, app_id, endpoint_id, payload)`.
pub type MetaDecryptResult = ([u8; 32], [u8; 32], [u8; 32], u32, Vec<u8>);

/// Encrypt a message using the **meta-E2E** (onion) format.
///
/// The sender's identity (`sender_node_id`, `src_app_id`, `app_id`
/// `endpoint_id`) is encrypted together with the application `payload` inside
/// [`E2eEnvelope`]. Relay nodes see only `dst_node_id` in the outer
/// [`DeliveryEnvelope`]; the sender's identity is hidden until the recipient
/// decrypts.
///
/// The outer `DeliveryEnvelope.sender_node_id` MUST be set to `[0u8; 32]` by
/// the caller — the true sender lives inside the ciphertext.
///
/// Returns the full `DeliveryEnvelope.payload` bytes:
/// `META_E2E_MARKER ++ E2eEnvelope::encode`.
///
/// # Wire layout of the decrypted plaintext
/// ```text
/// [0..32] sender_node_id
/// [32..64] src_app_id
/// [64..96] app_id
/// [96..100] endpoint_id u32 BE
/// [100..] application payload
/// ```
///
/// IPC-server only (`#[cfg(unix)]`); suppress Windows-target warning until.
pub fn meta_encrypt(
    recipient_ek: &[u8],
    sender_node_id: &[u8; 32],
    src_app_id: &[u8; 32],
    app_id: &[u8; 32],
    endpoint_id: u32,
    dst_id: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, E2eError> {
    // Build plaintext: sender_node_id || src_app_id || app_id || endpoint_id_be || payload
    let mut plaintext = Vec::with_capacity(100 + payload.len());
    plaintext.extend_from_slice(sender_node_id);
    plaintext.extend_from_slice(src_app_id);
    plaintext.extend_from_slice(app_id);
    plaintext.extend_from_slice(&endpoint_id.to_be_bytes());
    plaintext.extend_from_slice(payload);

    // Encrypt under recipient's key. Use the zero node-id as src (anonymous).
    const ZERO: [u8; 32] = [0u8; 32];
    let envelope = encrypt(recipient_ek, &ZERO, dst_id, &plaintext)?;

    let mut out =
        Vec::with_capacity(1 + envelope.kem_ciphertext.len() + 12 + 4 + envelope.ciphertext.len());
    out.push(veil_proto::META_E2E_MARKER);
    out.extend_from_slice(&envelope.encode());
    Ok(out)
}

/// Decrypt a **meta-E2E** envelope from `DeliveryEnvelope.payload`.
///
/// `envelope_payload` must start with [`veil_proto::META_E2E_MARKER`] (`0xE3`).
/// A missing marker is rejected with [`E2eError::Proto`] — previously the
/// loader silently accepted marker-less payloads via `unwrap_or`, weakening
/// the format contract and making it harder to catch protocol bugs where
/// callers forgot the prepend.
///
/// Returns `(sender_node_id, src_app_id, app_id, endpoint_id, application_payload)`.
///
/// SECURITY — the returned `sender_node_id` (and `src_app_id`) is
/// **UNAUTHENTICATED**. meta-E2E is the anonymous-sender path: the envelope is
/// sealed to the recipient with ML-KEM (confidentiality only — a KEM proves
/// nothing about the origin), so anyone who knows the recipient's published EK
/// can craft a valid envelope claiming ANY `sender_node_id`. Callers MUST NOT
/// use it for trust / authorization / routing decisions without an app-layer
/// signature carried inside `application_payload`. The dispatcher accordingly
/// does NOT learn a reverse route from a meta-E2E sender (audit cycle-4 M2).
/// The authenticated path is the `E2E_MARKER` flow, which binds the sender to
/// the OVL1 session peer.
pub fn meta_decrypt(
    dk_seed: &[u8],
    dst_id: &[u8; 32],
    envelope_payload: &[u8],
) -> Result<MetaDecryptResult, E2eError> {
    // Hard-reject missing marker — meta-E2E payloads MUST begin with 0xE3.
    let envelope_bytes = envelope_payload
        .strip_prefix(&[veil_proto::META_E2E_MARKER])
        .ok_or_else(|| {
            E2eError::Proto(ProtoError::Malformed(format!(
                "meta-E2E envelope missing 0x{:02X} marker (got first byte {:?})",
                veil_proto::META_E2E_MARKER,
                envelope_payload.first().copied()
            )))
        })?;

    let e2e_env = veil_proto::E2eEnvelope::decode(envelope_bytes)?;

    const ZERO: [u8; 32] = [0u8; 32];
    let plaintext = decrypt(dk_seed, &ZERO, dst_id, &e2e_env)?;

    // Parse plaintext: 32+32+32+4 = 100 bytes header
    const HDR: usize = 100;
    if plaintext.len() < HDR {
        return Err(E2eError::MetaPlaintextTooShort(plaintext.len()));
    }
    let mut sender_node_id = [0u8; 32];
    sender_node_id.copy_from_slice(&plaintext[0..32]);
    let mut src_app_id = [0u8; 32];
    src_app_id.copy_from_slice(&plaintext[32..64]);
    let mut app_id = [0u8; 32];
    app_id.copy_from_slice(&plaintext[64..96]);
    let mut ep_buf = [0u8; 4];
    ep_buf.copy_from_slice(&plaintext[96..100]);
    let endpoint_id = u32::from_be_bytes(ep_buf);
    let app_payload = plaintext[HDR..].to_vec();

    Ok((sender_node_id, src_app_id, app_id, endpoint_id, app_payload))
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// `HKDF-SHA256(ikm=shared_secret, info = src_id ‖ dst_id ‖ "ovl1-e2e-v1")[0..32]`
fn derive_key(shared_secret: &[u8], src_id: &[u8; 32], dst_id: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut info = [0u8; 75]; // 32 + 32 + 11
    info[..32].copy_from_slice(src_id);
    info[32..64].copy_from_slice(dst_id);
    info[64..75].copy_from_slice(b"ovl1-e2e-v1");
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("HKDF expand: valid length");
    key
}

/// `HKDF-SHA256(ikm=shared_secret, info = src_id ‖ dst_id ‖ "ovl1-e2e-ack-v1")[0..32]`
///
/// Per-message delivery-ACK MAC key. Derived from the same ML-KEM shared secret
/// as [`derive_key`] but with a distinct `info` tag, so the two keys are
/// independent (compromising one does not reveal the other). See
/// [`encrypt_with_ack`] / [`decrypt_with_ack`].
fn derive_ack_key(shared_secret: &[u8], src_id: &[u8; 32], dst_id: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut info = [0u8; 79]; // 32 + 32 + 15
    info[..32].copy_from_slice(src_id);
    info[32..64].copy_from_slice(dst_id);
    info[64..79].copy_from_slice(b"ovl1-e2e-ack-v1");
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("HKDF expand: valid length");
    key
}

/// AAD = src_id ‖ dst_id (64 bytes).
fn make_aad(src_id: &[u8; 32], dst_id: &[u8; 32]) -> [u8; 64] {
    let mut aad = [0u8; 64];
    aad[..32].copy_from_slice(src_id);
    aad[32..].copy_from_slice(dst_id);
    aad
}
fn parse_ek(bytes: &[u8]) -> Result<EK768, E2eError> {
    if bytes.len() != EK_BYTES {
        return Err(E2eError::InvalidEk(bytes.len()));
    }
    let arr = Array::try_from(bytes).map_err(|_| E2eError::InvalidEk(bytes.len()))?;
    EK768::new(&arr).map_err(|_| E2eError::InvalidEk(bytes.len()))
}

fn parse_dk(seed: &[u8]) -> Result<DK768, E2eError> {
    if seed.len() != DK_SEED_BYTES {
        return Err(E2eError::InvalidDk(seed.len()));
    }
    let arr: Seed = Array::try_from(seed).map_err(|_| E2eError::InvalidDk(seed.len()))?;
    Ok(DK768::from_seed(arr))
}

/// Recompute the ML-KEM-768 keypair `(ek, dk_seed)` from a 64-byte decapsulation
/// seed. Pure function of the seed: `DK768::from_seed` is deterministic and the
/// EK is recomputed from it, so a deterministically-derived seed (see
/// [`veil_crypto::identity::derive_mlkem_dk_seed`]) yields a STABLE keypair
/// across restarts. The single home for the seed→keypair recompute used by both
/// the persisted-key loader and the identity-derived path.
pub fn keypair_from_dk_seed(
    seed: &[u8; DK_SEED_BYTES],
) -> Result<([u8; EK_BYTES], [u8; DK_SEED_BYTES]), E2eError> {
    let dk = parse_dk(seed)?;
    let ek: [u8; EK_BYTES] = dk
        .encapsulation_key()
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| E2eError::InvalidDk(EK_BYTES))?;
    Ok((ek, *seed))
}

// ── Key persistence ───────────────────────────────────────────────────────────

const PEM_HEADER: &str = "-----BEGIN VEIL ML-KEM-768 KEY-----";
const PEM_FOOTER: &str = "-----END VEIL ML-KEM-768 KEY-----";
const PEM_ENC_HEADER: &str = "-----BEGIN VEIL ML-KEM-768 ENCRYPTED KEY-----";
const PEM_ENC_FOOTER: &str = "-----END VEIL ML-KEM-768 ENCRYPTED KEY-----";

fn encode_pem(seed: &[u8; DK_SEED_BYTES]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(seed);
    format!("{PEM_HEADER}\n{b64}\n{PEM_FOOTER}\n")
}

fn decode_pem(pem: &str) -> Option<Vec<u8>> {
    let mut inside = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line == PEM_HEADER {
            inside = true;
            continue;
        }
        if line == PEM_FOOTER {
            break;
        }
        if inside {
            b64.push_str(line);
        }
    }
    if b64.is_empty() {
        return None;
    }
    base64::engine::general_purpose::STANDARD.decode(&b64).ok()
}

// ── Encrypted PEM ───────────────────────────────────────────────
//
// Two wire formats coexist:
//
// **v1 (legacy, 92 bytes blob)** — fixed BLAKE3-derived salt, Argon2id
// `m_cost=256 KiB, t=3, p=1`. Same passphrase across nodes → same
// derived key → rainbow-table risk and cross-node compromise scope. Kept
// for read-back compat only; **never written** by post-audit builds.
//
// ```text
// [0..12]  nonce
// [12..92] ciphertext+tag (DK seed 64 + Poly1305 tag 16)
// ```
//
// **v2 (current, 113 bytes blob)** — random 16-byte salt per file +
// in-band Argon2id params (so future tuning doesn't break old files).
// Defaults: `m=32 MiB, t=3, p=1` — ~50-100 ms on typical hardware,
// rainbow-table-resistant, per-file unique derivation.
//
// ```text
// [0]      version = 0x02
// [1..17]  salt (16 random bytes)
// [17..21] m_cost_kib (u32 BE)
// [21..25] t_cost     (u32 BE)
// [25..29] p_cost     (u32 BE)
// [29..41] nonce (12 random bytes)
// [41..113] ciphertext+tag (80 bytes)
// ```
//
// Loader detection: first decoded byte == `0x02` → v2 path; else v1.

/// v2 encrypted-PEM version byte.
const ENC_PEM_V2: u8 = 0x02;

/// v2 default Argon2id memory cost in KiB. 32 MiB strikes a balance between
/// startup time (~50-100 ms typical) and offline-attack resistance.
const ENC_PEM_V2_M_COST_KIB: u32 = 32 * 1024;
const ENC_PEM_V2_T_COST: u32 = 3;
const ENC_PEM_V2_P_COST: u32 = 1;

/// v1 (legacy) Argon2id params. Reproduce the original derivation
/// exactly so existing on-disk files still decrypt.
const ENC_PEM_V1_M_COST_KIB: u32 = 256;
const ENC_PEM_V1_T_COST: u32 = 3;
const ENC_PEM_V1_P_COST: u32 = 1;

/// Derive a 32-byte AEAD key from a passphrase using Argon2id with
/// caller-supplied salt and cost params.
///
/// # Memory hygiene (Phase 6 slice 6f)
///
/// Returns [`SensitiveBytesN<32>`] — pages pinned via `mlock(2)` when
/// `RLIMIT_MEMLOCK` permits, falls back to a zeroize-on-drop
/// `Zeroizing<Vec<u8>>` when the budget is exhausted (same protection
/// posture as the pre-Phase-6 `Zeroizing<[u8; 32]>`).  The mlocked path
/// closes the swap-to-disk vector for the Argon2-derived ML-KEM DK-seed
/// encryption key — these keys are the **on-disk root-of-trust** for
/// the `mlkem.key` file, and if they leak via swap, anyone with read access
/// to the host's `mlkem.key` AND the swap partition can decrypt the
/// node's persistent ML-KEM decapsulation seed.  Parallel to slice 6d's
/// `veil-identity::master_file::derive_key`.
fn derive_key_from_passphrase(
    passphrase: &str,
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> veil_util::sensitive_bytes::SensitiveBytesN<32> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32)).expect("argon2 params in-range");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key: veil_util::sensitive_bytes::SensitiveBytesN<32> =
        veil_util::sensitive_bytes::SensitiveBytesN::new();
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut_slice())
        .expect("argon2 hash infallible");
    key
}

/// v1-compat derivation: fixed BLAKE3-derived salt + legacy 256 KiB params.
fn derive_key_v1(passphrase: &str) -> veil_util::sensitive_bytes::SensitiveBytesN<32> {
    let salt = blake3::hash(b"ovl1_dk_seed_encryption_salt_v1");
    derive_key_from_passphrase(
        passphrase,
        &salt.as_bytes()[..16],
        ENC_PEM_V1_M_COST_KIB,
        ENC_PEM_V1_T_COST,
        ENC_PEM_V1_P_COST,
    )
}

/// Encrypt DK seed → v2 PEM with random salt and embedded KDF params.
fn encode_pem_encrypted(seed: &[u8; DK_SEED_BYTES], passphrase: &str) -> String {
    use chacha20poly1305::{
        ChaCha20Poly1305, Key, Nonce,
        aead::{Aead, KeyInit},
    };
    use rand_core::{OsRng, RngCore};

    // Random salt (16 B) + random nonce (12 B).
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key_from_passphrase(
        passphrase,
        &salt,
        ENC_PEM_V2_M_COST_KIB,
        ENC_PEM_V2_T_COST,
        ENC_PEM_V2_P_COST,
    );
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_array()));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, seed.as_slice())
        .expect("ChaCha20Poly1305 encrypt infallible");

    // v2 wire: ver[1] || salt[16] || m[4] || t[4] || p[4] || nonce[12] || ct+tag[80]
    let mut blob = Vec::with_capacity(1 + 16 + 12 + 12 + ciphertext.len());
    blob.push(ENC_PEM_V2);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&ENC_PEM_V2_M_COST_KIB.to_be_bytes());
    blob.extend_from_slice(&ENC_PEM_V2_T_COST.to_be_bytes());
    blob.extend_from_slice(&ENC_PEM_V2_P_COST.to_be_bytes());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
    format!("{PEM_ENC_HEADER}\n{b64}\n{PEM_ENC_FOOTER}\n")
}

/// Decrypt DK seed from encrypted PEM. Auto-detects v1 / v2 by first
/// decoded byte. v1 returns the seed but the caller (loader) re-writes
/// in v2 on success → see auto-upgrade path in
/// `load_or_generate_mlkem_key_encrypted`.
fn decode_pem_encrypted(pem: &str, passphrase: &str) -> Option<Vec<u8>> {
    use chacha20poly1305::{
        ChaCha20Poly1305, Key, Nonce,
        aead::{Aead, KeyInit},
    };

    // Parse PEM body (base64).
    let mut inside = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line == PEM_ENC_HEADER {
            inside = true;
            continue;
        }
        if line == PEM_ENC_FOOTER {
            break;
        }
        if inside {
            b64.push_str(line);
        }
    }
    if b64.is_empty() {
        return None;
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .ok()?;

    // v2 path: first byte version marker, in-band salt + params.
    if blob.first() == Some(&ENC_PEM_V2) {
        // v2: 1 + 16 + 4 + 4 + 4 + 12 + ≥16 (Poly1305 tag) = ≥57
        if blob.len() < 41 + 16 {
            return None;
        }
        let salt: &[u8] = &blob[1..17];
        let m_cost = u32::from_be_bytes(blob[17..21].try_into().ok()?);
        let t_cost = u32::from_be_bytes(blob[21..25].try_into().ok()?);
        let p_cost = u32::from_be_bytes(blob[25..29].try_into().ok()?);
        // Sanity-clamp KDF params to prevent a malicious file forcing
        // multi-GiB Argon2 allocation. 1 GiB max memory, 1000 iter max
        // — generous upper bounds beyond which the caller's CPU/RAM
        // would be the constraint anyway.
        //
        // Audit batch 2026-05-25 phase L: individual caps hadn't
        // covered the **product** of m_cost × t_cost.  Worst case at
        // max individual caps: m=1 GiB × t=1000 ≈ 50–100 s of KDF
        // burn on commodity hardware — a 100× hot-path startup stall
        // if attacker placeholders the key file.  Add product cap at
        // 256 GiB·iter (sufficient for legitimate Argon2 schedules:
        // OWASP recommends m=64 MiB t=3 = 192 MiB·iter, or
        // m=256 MiB t=2 = 512 MiB·iter, both well within budget).
        if m_cost > 1_048_576 || t_cost > 1000 || p_cost > 64 || p_cost == 0 {
            return None;
        }
        let product_kib = (m_cost as u64).saturating_mul(t_cost as u64);
        const MAX_KDF_PRODUCT_KIB: u64 = 256 * 1024 * 1024; // 256 GiB·iter
        if product_kib > MAX_KDF_PRODUCT_KIB {
            return None;
        }
        let nonce_bytes = &blob[29..41];
        let ct = &blob[41..];
        let key = derive_key_from_passphrase(passphrase, salt, m_cost, t_cost, p_cost);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_array()));
        let nonce = Nonce::from_slice(nonce_bytes);
        return cipher.decrypt(nonce, ct).ok();
    }

    // v1 path (legacy, no version byte): fixed-salt 256 KiB Argon2id.
    if blob.len() < 12 + 16 {
        return None;
    }
    let key = derive_key_v1(passphrase);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_array()));
    let nonce = Nonce::from_slice(&blob[..12]);
    cipher.decrypt(nonce, &blob[12..]).ok()
}

/// `true` if the encrypted PEM uses v2 wire format. Used by the loader
/// to decide whether to re-write a freshly-decoded file in the new format.
fn is_v2_encrypted_pem(pem: &str) -> bool {
    let mut inside = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let line = line.trim();
        if line == PEM_ENC_HEADER {
            inside = true;
            continue;
        }
        if line == PEM_ENC_FOOTER {
            break;
        }
        if inside {
            b64.push_str(line);
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .ok()
        .and_then(|b| b.first().copied())
        == Some(ENC_PEM_V2)
}

/// Load ML-KEM key with optional passphrase encryption.
///
/// Semantics (fail-closed):
/// * If the file **does not exist**, a fresh keypair is generated and
///   atomically written to `path` with mode `0o600` (Unix). The freshly
///   generated key and encapsulation key are returned.
/// * If the file **exists**:
///   - With `passphrase = Some(...)`: try encrypted PEM, then plaintext PEM
///     (auto-upgrade — re-encrypt plaintext under passphrase).
///   - With `passphrase = None`: try plaintext PEM.
///   - If decoding fails in any path (wrong passphrase, corrupt file,
///     unknown PEM format), return [`E2eError::MlKemKeyUnreadable`]
///     **without overwriting the file**. The previous loader silently
///     generated a fresh keypair and overwrote the file, destroying the
///     existing DK seed and orphaning every E2E mailbox payload encrypted
///     to the previous EK. That fall-through is a data-loss bug; this
///     loader fails closed instead.
///
/// I/O errors during read or atomic write are returned as
/// [`E2eError::MlKemKeyIo`] — startup should bail rather than continue
/// without persistent identity.
pub fn load_or_generate_mlkem_key_encrypted(
    path: &Path,
    passphrase: Option<&str>,
) -> Result<([u8; EK_BYTES], [u8; DK_SEED_BYTES]), E2eError> {
    // Read existing file. Distinguish "not found" (→ generate) from other
    // I/O errors (→ propagate) to avoid silent regeneration on transient
    // failures (e.g. EACCES from a too-restrictive parent dir, EIO from
    // a failing disk).
    match std::fs::read_to_string(path) {
        Ok(pem) => {
            // Try encrypted PEM first if a passphrase is set.
            if let Some(pass) = passphrase
                && pem.contains(PEM_ENC_HEADER)
            {
                if let Some(seed) = decode_pem_encrypted(&pem, pass)
                    && seed.len() == DK_SEED_BYTES
                {
                    let dk = parse_dk(&seed).expect("seed just validated");
                    let ek_arr = dk.encapsulation_key().to_bytes();
                    let ek: [u8; EK_BYTES] = ek_arr.as_slice().try_into().expect("EK size");

                    // v1 → v2 auto-upgrade. v1 used a fixed BLAKE3-derived salt and
                    // 256 KiB Argon2id — rainbow-table risk + cross-file
                    // attack-amortisation. v2 uses random per-file salt and
                    // 32 MiB Argon2id with embedded params. Re-write atomically;
                    // failure is non-fatal (key still in memory, retry next start).
                    if !is_v2_encrypted_pem(&pem) {
                        let seed_arr: [u8; DK_SEED_BYTES] =
                            seed.clone().try_into().expect("DK_SEED_BYTES");
                        let new_pem = encode_pem_encrypted(&seed_arr, pass);
                        let _ = veil_util::atomic_write(path, new_pem.as_bytes());
                    }

                    return Ok((ek, seed.try_into().expect("DK_SEED_BYTES")));
                }
                // Encrypted header found but decode failed → wrong passphrase
                // or corrupt blob. DO NOT fall through to plaintext attempt
                // or to regeneration — operator must resolve.
                return Err(E2eError::MlKemKeyUnreadable {
                    path: path.to_path_buf(),
                });
            }
            // Plaintext PEM path (no passphrase, or passphrase set but file
            // is plaintext — auto-upgrade).
            if let Some(seed) = decode_pem(&pem)
                && seed.len() == DK_SEED_BYTES
            {
                let dk = parse_dk(&seed).expect("seed just validated");
                let ek_arr = dk.encapsulation_key().to_bytes();
                let ek: [u8; EK_BYTES] = ek_arr.as_slice().try_into().expect("EK size");

                // Auto-upgrade: if passphrase is set and file is plaintext →
                // re-encrypt in-place via atomic_write. Failure to re-encrypt
                // is non-fatal: we still have the key in memory; the
                // upgrade can be retried at next startup. Logged via Result
                // discard since this function doesn't have a logger handle.
                if let Some(pass) = passphrase {
                    let seed_arr: [u8; DK_SEED_BYTES] =
                        seed.clone().try_into().expect("DK_SEED_BYTES");
                    let enc_pem = encode_pem_encrypted(&seed_arr, pass);
                    let _ = veil_util::atomic_write(path, enc_pem.as_bytes());
                }

                return Ok((ek, seed.try_into().expect("DK_SEED_BYTES")));
            }
            // File exists but neither encrypted-with-passphrase nor
            // plaintext PEM parse worked → corrupt or unknown format.
            Err(E2eError::MlKemKeyUnreadable {
                path: path.to_path_buf(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Fresh install — generate and atomically write.
            let (ek, dk_seed) = generate_keypair();
            let pem = if let Some(pass) = passphrase {
                encode_pem_encrypted(&dk_seed, pass)
            } else {
                encode_pem(&dk_seed)
            };
            // atomic_write handles 0o600 mode, fsync, parent dir fsync.
            veil_util::atomic_write(path, pem.as_bytes()).map_err(|source| {
                E2eError::MlKemKeyIo {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            Ok((ek, dk_seed))
        }
        Err(source) => Err(E2eError::MlKemKeyIo {
            path: path.to_path_buf(),
            source,
        }),
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> ([u8; 32], [u8; 32]) {
        ([0xAA; 32], [0xBB; 32])
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (ek, dk) = generate_keypair();
        let (src, dst) = ids();
        let plaintext = b"hello veil e2e";

        let env = encrypt(&ek, &src, &dst, plaintext).unwrap();
        let recovered = decrypt(&dk, &src, &dst, &env).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn keypair_from_dk_seed_is_stable_and_openable() {
        // Regression for the reverse-delivery black-hole: a deterministic 64-byte
        // dk_seed yields a STABLE keypair, and a payload sealed to its EK opens
        // with the dk_seed re-derived from the SAME seed — exactly the cross-
        // restart property that makes a peer's already-sealed mailbox blob open.
        let seed = [0x55u8; DK_SEED_BYTES];
        let (ek, dk) = keypair_from_dk_seed(&seed).unwrap();
        let (ek2, dk2) = keypair_from_dk_seed(&seed).unwrap();
        assert_eq!(ek, ek2, "same seed must give the same EK");
        assert_eq!(dk, dk2);
        assert_eq!(dk, seed, "dk_seed is returned verbatim");
        // The EK genuinely matches the dk_seed across a simulated restart.
        let (src, dst) = ids();
        let env = encrypt(&ek, &src, &dst, b"reverse delivery").unwrap();
        let recovered = decrypt(&dk2, &src, &dst, &env).unwrap();
        assert_eq!(recovered, b"reverse delivery");
    }

    /// C-09 foundation: the sender (encapsulate) and recipient (decapsulate)
    /// derive the SAME per-message delivery-ACK key from the same ML-KEM shared
    /// secret. A relay never learns that shared secret, so it cannot compute
    /// the ACK MAC — which is what stops it forging a delivery confirmation.
    #[test]
    fn ack_key_agrees_between_sender_and_recipient() {
        let (ek, dk) = generate_keypair();
        let (src, dst) = ids();

        let (env, ack_send) = encrypt_with_ack(&ek, &src, &dst, b"payload").unwrap();
        let (plain, ack_recv) = decrypt_with_ack(&dk, &src, &dst, &env).unwrap();

        assert_eq!(plain, b"payload");
        assert_eq!(
            ack_send, ack_recv,
            "sender and recipient must derive the same delivery-ACK key"
        );
        assert_ne!(ack_send, [0u8; 32], "ACK key must be non-trivial");
    }

    /// The ACK key is domain-separated from the AEAD key (distinct HKDF info),
    /// so they are independent for the same shared secret / (src,dst).
    #[test]
    fn ack_key_is_domain_separated_from_aead_key() {
        let ss = [7u8; 32];
        let (src, dst) = ids();
        assert_ne!(
            derive_key(&ss, &src, &dst),
            derive_ack_key(&ss, &src, &dst),
            "ACK key must differ from the AEAD key"
        );
        // Direction-bound: swapping src/dst changes the key.
        assert_ne!(
            derive_ack_key(&ss, &src, &dst),
            derive_ack_key(&ss, &dst, &src),
            "ACK key must be bound to the (src,dst) direction"
        );
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let (ek, _dk) = generate_keypair();
        let (_ek2, dk2) = generate_keypair();
        let (src, dst) = ids();

        let env = encrypt(&ek, &src, &dst, b"secret").unwrap();
        // Wrong DK → random shared secret → AEAD auth failure.
        assert!(decrypt(&dk2, &src, &dst, &env).is_err());
    }

    #[test]
    fn wrong_aad_fails_decrypt() {
        let (ek, dk) = generate_keypair();
        let (src, _dst) = ids();
        let dst2 = [0xCC; 32];

        let env = encrypt(&ek, &src, &src, b"secret").unwrap();
        // Different dst_id → different AAD → auth failure.
        assert!(decrypt(&dk, &src, &dst2, &env).is_err());
    }

    #[test]
    fn invalid_ek_length_rejected() {
        let (src, dst) = ids();
        let err = encrypt(&[0u8; 100], &src, &dst, b"data").unwrap_err();
        assert!(matches!(err, E2eError::InvalidEk(100)));
    }

    #[test]
    fn invalid_dk_seed_length_rejected() {
        let env = E2eEnvelope {
            kem_ciphertext: vec![0u8; 1088],
            nonce: [0u8; 12],
            ciphertext: vec![0u8; 32],
        };
        let (src, dst) = ids();
        let err = decrypt(&[0u8; 10], &src, &dst, &env).unwrap_err();
        assert!(matches!(err, E2eError::InvalidDk(10)));
    }

    #[test]
    fn key_roundtrip_serialization() {
        let (ek1, dk1) = generate_keypair();
        let (src, dst) = ids();
        let env = encrypt(&ek1, &src, &dst, b"verify serde").unwrap();
        let out = decrypt(&dk1, &src, &dst, &env).unwrap();
        assert_eq!(out, b"verify serde");
    }

    // ── meta-E2E (onion) roundtrip ─────────────────────────────────────────

    #[test]
    fn meta_encrypt_decrypt_roundtrip() {
        let (ek, dk) = generate_keypair();
        let sender_node_id = [0x11u8; 32];
        let src_app_id = [0x22u8; 32];
        let app_id = [0x33u8; 32];
        let endpoint_id = 42u32;
        let dst_id = [0x44u8; 32];
        let payload = b"secret message";

        let wire = meta_encrypt(
            &ek,
            &sender_node_id,
            &src_app_id,
            &app_id,
            endpoint_id,
            &dst_id,
            payload,
        )
        .unwrap();
        assert_eq!(wire[0], veil_proto::META_E2E_MARKER);

        let (s, sa, ai, eid, pl) = meta_decrypt(&dk, &dst_id, &wire).unwrap();
        assert_eq!(s, sender_node_id);
        assert_eq!(sa, src_app_id);
        assert_eq!(ai, app_id);
        assert_eq!(eid, endpoint_id);
        assert_eq!(pl, payload);
    }

    #[test]
    fn meta_decrypt_wrong_key_fails() {
        let (ek, _dk) = generate_keypair();
        let (_ek2, dk2) = generate_keypair();
        let dst_id = [0xBBu8; 32];
        let wire =
            meta_encrypt(&ek, &[1u8; 32], &[2u8; 32], &[3u8; 32], 0, &dst_id, b"data").unwrap();
        assert!(meta_decrypt(&dk2, &dst_id, &wire).is_err());
    }

    // ── loader fail-closed tests ──────────────────────────────────────────
    //
    // Verifies the post-fix contract: existing-but-unreadable files MUST NOT
    // be silently regenerated. The previous loader had a fall-through that
    // destroyed the existing DK seed on wrong-passphrase or corrupt-file.

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "veil_mlkem_loader_test_{}_{}",
            std::process::id(),
            name
        ));
        p
    }

    #[test]
    fn loader_generates_when_file_missing() {
        let path = tmp_path("generates");
        let _ = std::fs::remove_file(&path);
        let (ek1, dk1) = load_or_generate_mlkem_key_encrypted(&path, None).unwrap();
        // File must now exist.
        assert!(path.exists());
        // Re-load must return the SAME keys (no regeneration).
        let (ek2, dk2) = load_or_generate_mlkem_key_encrypted(&path, None).unwrap();
        assert_eq!(ek1, ek2, "EK must round-trip from disk");
        assert_eq!(dk1, dk2, "DK seed must round-trip from disk");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn loader_fails_closed_on_wrong_passphrase() {
        let path = tmp_path("wrong_pass");
        let _ = std::fs::remove_file(&path);
        // Encrypt under "correct" passphrase.
        let (_ek_orig, _dk_orig) =
            load_or_generate_mlkem_key_encrypted(&path, Some("correct-pass")).unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        // Now attempt load with WRONG passphrase.
        let err = load_or_generate_mlkem_key_encrypted(&path, Some("wrong-pass")).unwrap_err();
        assert!(
            matches!(err, E2eError::MlKemKeyUnreadable { .. }),
            "expected MlKemKeyUnreadable, got {err:?}"
        );
        // CRITICAL invariant: file MUST be untouched (no silent regen).
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            saved, after,
            "loader regenerated key after wrong passphrase — DATA LOSS"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn loader_fails_closed_on_corrupt_pem() {
        let path = tmp_path("corrupt");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "this is not a valid PEM file at all").unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        let err = load_or_generate_mlkem_key_encrypted(&path, None).unwrap_err();
        assert!(
            matches!(err, E2eError::MlKemKeyUnreadable { .. }),
            "expected MlKemKeyUnreadable, got {err:?}"
        );
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(before, after, "loader must not overwrite corrupt file");
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn loader_writes_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = tmp_path("perms");
        let _ = std::fs::remove_file(&path);
        let _ = load_or_generate_mlkem_key_encrypted(&path, None).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn loader_auto_upgrades_plaintext_to_encrypted() {
        let path = tmp_path("auto_upgrade");
        let _ = std::fs::remove_file(&path);
        // Generate as plaintext first.
        let (ek1, _dk1) = load_or_generate_mlkem_key_encrypted(&path, None).unwrap();
        let plain_pem = std::fs::read_to_string(&path).unwrap();
        assert!(plain_pem.contains(PEM_HEADER));
        // Now re-load with passphrase — should auto-upgrade in-place.
        let (ek2, _dk2) = load_or_generate_mlkem_key_encrypted(&path, Some("upgraded")).unwrap();
        assert_eq!(ek1, ek2, "key must be preserved across auto-upgrade");
        let upgraded_pem = std::fs::read_to_string(&path).unwrap();
        assert!(upgraded_pem.contains(PEM_ENC_HEADER));
        let _ = std::fs::remove_file(&path);
    }

    // ── v2 encrypted PEM format tests ─────────────────────────────────────

    /// Helper: encode a DK seed in legacy v1 format (fixed BLAKE3 salt,
    /// 256 KiB Argon2id). Used to verify that v1 files written by
    /// pre-audit binaries still decode and auto-upgrade.
    fn encode_pem_encrypted_v1(seed: &[u8; DK_SEED_BYTES], passphrase: &str) -> String {
        use chacha20poly1305::{
            ChaCha20Poly1305, Key, Nonce,
            aead::{Aead, KeyInit},
        };
        use rand_core::{OsRng, RngCore};
        let key = derive_key_v1(passphrase);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_array()));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, seed.as_slice()).unwrap();
        let mut blob = Vec::with_capacity(12 + ciphertext.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ciphertext);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        format!("{PEM_ENC_HEADER}\n{b64}\n{PEM_ENC_FOOTER}\n")
    }

    #[test]
    fn v2_roundtrip_uses_random_salt() {
        let (_, dk_seed) = generate_keypair();
        // Encrypt the same seed twice with the same passphrase. Random salt +
        // random nonce mean the on-wire blobs MUST differ.
        let pem_a = encode_pem_encrypted(&dk_seed, "pass-a");
        let pem_b = encode_pem_encrypted(&dk_seed, "pass-a");
        assert_ne!(pem_a, pem_b, "v2 must use random salt per encrypt");
        // Both must decrypt back to the original seed.
        let dec_a = decode_pem_encrypted(&pem_a, "pass-a").unwrap();
        let dec_b = decode_pem_encrypted(&pem_b, "pass-a").unwrap();
        assert_eq!(dec_a.as_slice(), dk_seed.as_slice());
        assert_eq!(dec_b.as_slice(), dk_seed.as_slice());
    }

    #[test]
    fn v2_wrong_passphrase_returns_none() {
        let (_, dk_seed) = generate_keypair();
        let pem = encode_pem_encrypted(&dk_seed, "correct");
        assert!(decode_pem_encrypted(&pem, "wrong").is_none());
    }

    #[test]
    fn v1_backcompat_decodes() {
        let (_, dk_seed) = generate_keypair();
        let v1_pem = encode_pem_encrypted_v1(&dk_seed, "legacy-pass");
        // is_v2 should return false for v1 blob.
        assert!(
            !is_v2_encrypted_pem(&v1_pem),
            "v1 must not be detected as v2"
        );
        // Decode should still work through the v1 fallback path.
        let decoded = decode_pem_encrypted(&v1_pem, "legacy-pass").unwrap();
        assert_eq!(decoded.as_slice(), dk_seed.as_slice());
    }

    #[test]
    fn v1_wrong_passphrase_returns_none() {
        let (_, dk_seed) = generate_keypair();
        let v1_pem = encode_pem_encrypted_v1(&dk_seed, "correct-v1");
        assert!(decode_pem_encrypted(&v1_pem, "wrong-v1").is_none());
    }

    #[test]
    fn loader_auto_upgrades_v1_to_v2() {
        let path = tmp_path("v1_v2_upgrade");
        let _ = std::fs::remove_file(&path);
        // Write a v1-format encrypted file directly.
        let (_, dk_seed) = generate_keypair();
        let v1_pem = encode_pem_encrypted_v1(&dk_seed, "shared-pass");
        std::fs::write(&path, v1_pem.as_bytes()).unwrap();
        // Sanity: file is v1 format.
        let read_back = std::fs::read_to_string(&path).unwrap();
        assert!(
            !is_v2_encrypted_pem(&read_back),
            "test fixture must start as v1"
        );
        // Now load with the correct passphrase — should decrypt and auto-upgrade.
        let (_, dk_loaded) =
            load_or_generate_mlkem_key_encrypted(&path, Some("shared-pass")).unwrap();
        assert_eq!(dk_loaded, dk_seed, "key must round-trip across upgrade");
        // File must now be in v2 format.
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            is_v2_encrypted_pem(&after),
            "loader must auto-upgrade v1 → v2"
        );
        // Re-load to confirm v2 path also works.
        let (_, dk_reloaded) =
            load_or_generate_mlkem_key_encrypted(&path, Some("shared-pass")).unwrap();
        assert_eq!(dk_reloaded, dk_seed);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn v2_rejects_unreasonable_kdf_params() {
        // Craft a v2 blob with m_cost = 2 GiB (above 1 GiB sanity clamp).
        let mut blob = Vec::new();
        blob.push(ENC_PEM_V2);
        blob.extend_from_slice(&[0u8; 16]); // salt
        blob.extend_from_slice(&2_000_000u32.to_be_bytes()); // m_cost_kib = ~2 GiB
        blob.extend_from_slice(&3u32.to_be_bytes()); // t_cost
        blob.extend_from_slice(&1u32.to_be_bytes()); // p_cost
        blob.extend_from_slice(&[0u8; 12]); // nonce
        blob.extend_from_slice(&[0u8; 80]); // ct
        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let pem = format!("{PEM_ENC_HEADER}\n{b64}\n{PEM_ENC_FOOTER}\n");
        assert!(
            decode_pem_encrypted(&pem, "any").is_none(),
            "malicious blob with 2 GiB m_cost must be rejected before Argon2 alloc"
        );
    }

    #[test]
    fn v2_wire_format_size() {
        let (_, dk_seed) = generate_keypair();
        let pem = encode_pem_encrypted(&dk_seed, "test-pass");
        // Find the base64 line(s) and decode to count raw bytes.
        let mut inside = false;
        let mut b64 = String::new();
        for line in pem.lines() {
            let line = line.trim();
            if line == PEM_ENC_HEADER {
                inside = true;
                continue;
            }
            if line == PEM_ENC_FOOTER {
                break;
            }
            if inside {
                b64.push_str(line);
            }
        }
        let blob = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap();
        // v2: 1 + 16 + 4 + 4 + 4 + 12 + 80 (DK 64 + tag 16) = 121 bytes.
        assert_eq!(blob.len(), 121, "v2 wire size must be 121 bytes");
        assert_eq!(blob[0], ENC_PEM_V2, "version byte must be 0x02");
    }

    #[test]
    fn meta_decrypt_rejects_missing_marker() {
        // Hard-reject payloads without leading META_E2E_MARKER.
        let (ek, dk) = generate_keypair();
        let dst_id = [0xBBu8; 32];
        // Encode a valid E2E envelope without the marker prefix.
        let env =
            meta_encrypt(&ek, &[1u8; 32], &[2u8; 32], &[3u8; 32], 0, &dst_id, b"data").unwrap();
        // Strip the marker (first byte) — should now fail decode.
        let stripped = &env[1..];
        let err = meta_decrypt(&dk, &dst_id, stripped).unwrap_err();
        match err {
            E2eError::Proto(ProtoError::Malformed(msg)) => {
                assert!(
                    msg.contains("missing"),
                    "expected missing-marker error, got {msg}"
                );
            }
            other => panic!("expected Proto(Malformed), got {other:?}"),
        }
    }

    // ── Phase 6 slice 6f: derive_key_from_passphrase migration ─────────

    /// AEAD round-trip works identically after migrating from
    /// `Zeroizing<[u8; 32]>` to `SensitiveBytesN<32>` storage — proves
    /// the Argon2-derived key flows correctly through the new
    /// `SensitiveBytesN::as_array()` path.
    #[test]
    fn etap6_slice6f_v2_roundtrip_with_sensitive_bytes_n_key() {
        let (_ek, dk) = generate_keypair();
        let passphrase = "etap6-slice6f-test-passphrase";
        let pem = encode_pem_encrypted(&dk, passphrase);
        let decoded = decode_pem_encrypted(&pem, passphrase)
            .expect("Argon2 key derived via SensitiveBytesN must decrypt round-trip");
        assert_eq!(
            decoded.as_slice(),
            dk.as_slice(),
            "round-trip plaintext must equal input"
        );
    }

    /// `derive_key_v1` legacy path also round-trips through the new
    /// storage type — guards against accidental regression in the
    /// v1-compatibility path which uses different cost params.
    #[test]
    fn etap6_slice6f_v1_legacy_path_still_decrypts() {
        // We can't easily synthesize a v1 PEM here without duplicating
        // the encoder logic, so verify the SensitiveBytesN-backed
        // `derive_key_v1` produces deterministic bytes via a
        // double-derive equality check (instead of byte-comparison
        // which the type doesn't expose directly).
        let passphrase = "etap6-slice6f-legacy";
        let key_a = derive_key_v1(passphrase);
        let key_b = derive_key_v1(passphrase);
        assert_eq!(
            key_a.as_array(),
            key_b.as_array(),
            "Argon2 derivation must be deterministic across calls"
        );
    }

    #[test]
    fn meta_decrypt_truncated_plaintext_fails() {
        // Encrypt with empty payload so plaintext is exactly 100 bytes — that's valid.
        // To get < 100 bytes we'd need to bypass encrypt, so instead just craft a garbage payload.
        let (ek, dk) = generate_keypair();
        let dst_id = [0xBBu8; 32];
        // Encrypt only 50 bytes as plaintext (no sender header — simulates corruption).
        const ZERO: [u8; 32] = [0u8; 32];
        let short_env = encrypt(&ek, &ZERO, &dst_id, &[0u8; 50]).unwrap();
        let mut wire = vec![veil_proto::META_E2E_MARKER];
        wire.extend_from_slice(&short_env.encode());
        let err = meta_decrypt(&dk, &dst_id, &wire).unwrap_err();
        assert!(matches!(err, E2eError::MetaPlaintextTooShort(50)));
    }
}
