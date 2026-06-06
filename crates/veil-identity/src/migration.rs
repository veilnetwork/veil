//! classical → hybrid → PQ identity migration.
//!
//! Bridges existing Ed25519 / Falcon-512 / hybrid sovereign identities
//! across `master_algo` upgrades. Since `node_id = BLAKE3(master_pubkey)`
//! and migration changes the master pubkey (e.g. Ed25519 → Hybrid adds a
//! Falcon component), the new identity necessarily has a NEW node_id.
//! Without a migration record, peers would treat the new identity as an
//! unrelated entity — breaking message-history continuity, rendezvous
//! advertisements, contact lists, and every cross-peer reference held
//! by a node_id pointer.
//!
//! Solution: a `MigrationCert` signed by the OLD master attesting "the
//! new identity at `new_node_id` is the same entity as me at
//! `old_node_id`". Peers seeing both identities can follow the cert
//! chain to update their references.
//!
//! # Wire format (binary, big-endian)
//!
//! ```text
//! [0..2] magic "MG"
//! [2] version 1
//! [3] old_master_algo u8 (used to verify cert signature)
//! [4..36] old_node_id [u8; 32]
//! [36..68] new_node_id [u8; 32]
//! [68] new_master_algo u8
//! [69..71] new_master_pubkey_len u16 BE
//! [71..] new_master_pubkey bytes
//! [..] issued_at_unix u64 BE
//! [..] valid_until_unix u64 BE
//! [..] sig_len u16 BE
//! [..] signature bytes (signed by OLD master)
//! ```
//!
//! # Security invariants
//!
//! 1. **Single chain**: a master MUST NOT sign two distinct migration
//!    certs (would create a fork). Verifiers reject the second one
//!    encountered for the same `old_node_id`. Operators producing
//!    duplicate certs are flagged as compromised.
//! 2. **No reverse migration**: hybrid → ed25519 downgrade is a hard
//!    reject (loss of PQ security with same node_id implication).
//!    Verifier checks `new_master_algo` provides ≥ security guarantees
//!    of `old_master_algo`.
//! 3. **Validity window cap**: ≤ 30 days. Prevents an old master
//!    captured by an adversary from being used to migrate to attacker-
//!    controlled identity years after the operator already migrated.
//! 4. **Domain separation**: signed canonical message has
//!    `MIGRATION_CONTEXT` prefix — sigs from this domain cannot replay
//!    against IdentityDocument doc_sig, IdentityKey cert_sig, etc.

use base64::Engine as _;
use veil_crypto::{sign_message, verify_message};
use veil_proto::identity_document::{
    ALGO_ED25519, ALGO_ED25519_FALCON512_HYBRID, ALGO_ED25519_FALCON1024_HYBRID, ALGO_FALCON512,
};
use veil_types::SignatureAlgorithm;

/// Wire-magic identifying a `MigrationCert`.
pub const MIGRATION_CERT_MAGIC: [u8; 2] = [b'M', b'G'];
/// Current wire-format version.
pub const MIGRATION_CERT_VERSION: u8 = 1;
/// Hard cap on the migration cert's validity window. Prevents an old
/// master captured years later from being usable to migrate to an
/// attacker-controlled identity. 30 days matches typical key-rotation
/// hygiene; operators that need a longer window publish a fresh cert.
pub const MAX_MIGRATION_VALIDITY_SECS: u64 = 30 * 86_400;
/// Maximum on-wire size — accommodates a hybrid `new_master_pubkey`
/// (929 B) + a hybrid signature (~730 B) + framing overhead. Real
/// certs are ~2 KiB; the 4 KiB cap leaves headroom for future PQ algos.
pub const MAX_MIGRATION_CERT_BYTES: usize = 4 * 1024;
/// Domain-separated signing context.
pub const MIGRATION_CONTEXT: &[u8] = b"veil.migration_cert.v1";

/// Errors emitted by [`sign_migration_cert`] / [`verify_migration_cert`].
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum MigrationCertError {
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("unsupported algo byte: {0}")]
    BadAlgo(u8),
    #[error("validity window inverted: valid_from {valid_from} >= valid_until {valid_until}")]
    InvertedWindow { valid_from: u64, valid_until: u64 },
    #[error("validity window exceeds {MAX_MIGRATION_VALIDITY_SECS}s cap (got {got}s)")]
    WindowTooLong { got: u64 },
    #[error("cert exceeds {MAX_MIGRATION_CERT_BYTES} byte cap (got {got})")]
    TooLarge { got: usize },
    #[error("cert is expired: now={now} >= valid_until={valid_until}")]
    Expired { now: u64, valid_until: u64 },
    #[error("cert is not yet valid: now={now} < issued_at={issued_at}")]
    NotYetValid { now: u64, issued_at: u64 },
    #[error("signature verification failed (wrong key, tampered fields, or wrong algo)")]
    VerifyFailed,
    #[error(
        "downgrade migration rejected: old_algo={old_algo} → new_algo={new_algo} \
         would lose security guarantees"
    )]
    SecurityDowngrade { old_algo: u8, new_algo: u8 },
    #[error("internal: {0}")]
    Internal(String),
}

/// A decoded migration cert. Construct [`sign_migration_cert`];
/// transmit as bytes (typically published to the DHT under
/// `migration_cert_dht_key(old_node_id)`); decode at the receiver via
/// [`decode_migration_cert`]; verify [`verify_migration_cert`].
#[derive(Debug, Clone, PartialEq)]
pub struct MigrationCert {
    pub old_master_algo: u8,
    pub old_node_id: [u8; 32],
    pub new_node_id: [u8; 32],
    pub new_master_algo: u8,
    pub new_master_pubkey: Vec<u8>,
    pub issued_at_unix: u64,
    pub valid_until_unix: u64,
    pub signature: Vec<u8>,
}

/// DHT key under which `old_node_id`'s migration cert is published.
/// Domain-separated from other DHT-key derivations so that a migration
/// query cannot accidentally hit a relay-directory or rendezvous-ad slot.
pub fn migration_cert_dht_key(old_node_id: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"veil:v1:migration-cert\0");
    h.update(old_node_id);
    *h.finalize().as_bytes()
}

/// Build the canonical bytes that the OLD master signs to attest the
/// migration. Domain-prefixed so signatures from this scheme cannot
/// replay against any other signed primitive (IdentityDocument doc_sig
/// IdentityKey cert_sig, RelayDirectoryEntry, RendezvousAd, etc.).
fn canonical_message(
    old_node_id: &[u8; 32],
    new_node_id: &[u8; 32],
    new_master_algo: u8,
    new_master_pubkey: &[u8],
    issued_at_unix: u64,
    valid_until_unix: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        MIGRATION_CONTEXT.len() + 32 + 32 + 1 + 2 + new_master_pubkey.len() + 8 + 8,
    );
    msg.extend_from_slice(MIGRATION_CONTEXT);
    msg.extend_from_slice(old_node_id);
    msg.extend_from_slice(new_node_id);
    msg.push(new_master_algo);
    msg.extend_from_slice(&(new_master_pubkey.len() as u16).to_be_bytes());
    msg.extend_from_slice(new_master_pubkey);
    msg.extend_from_slice(&issued_at_unix.to_be_bytes());
    msg.extend_from_slice(&valid_until_unix.to_be_bytes());
    msg
}

/// Algo-byte to `SignatureAlgorithm` enum bridge. Returns `Err` for
/// unknown bytes — the caller MUST reject (no silent default).
fn algo_from_byte(b: u8) -> Result<SignatureAlgorithm, MigrationCertError> {
    match b {
        ALGO_ED25519 => Ok(SignatureAlgorithm::Ed25519),
        ALGO_FALCON512 => Ok(SignatureAlgorithm::Falcon512),
        ALGO_ED25519_FALCON512_HYBRID => Ok(SignatureAlgorithm::Ed25519Falcon512Hybrid),
        ALGO_ED25519_FALCON1024_HYBRID => Ok(SignatureAlgorithm::Ed25519Falcon1024Hybrid),
        b => Err(MigrationCertError::BadAlgo(b)),
    }
}

/// Returns the security tier of a master_algo for downgrade-prevention
/// checks. Higher = more security. Hybrid > Falcon512 > Ed25519
/// because hybrid retains classical security AND adds PQ.
///
/// `pub(crate)` so the resolver's migration-cert tie-break uses this single
/// source of truth rather than a duplicate that can drift (audit U7: the
/// resolver's copy was missing the Falcon-1024 arm and ranked it tier 0).
pub(crate) fn security_tier(algo: u8) -> u8 {
    match algo {
        ALGO_ED25519 => 1,                   // classical only
        ALGO_FALCON512 => 2,                 // PQ only (no classical fallback)
        ALGO_ED25519_FALCON512_HYBRID => 3,  // classical + Falcon-512 PQ
        ALGO_ED25519_FALCON1024_HYBRID => 4, // classical + Falcon-1024 PQ (stronger)
        _ => 0,                              // unknown — treat as worst-case
    }
}

/// Sign a fresh `MigrationCert` linking `old_node_id` (signed by the
/// OLD master keypair) to `new_node_id` (the new master's public key).
///
/// `old_master_pubkey_b64` / `old_master_sk_b64` are the base64-encoded
/// keypair material of the OLD master — the entity that's relinquishing
/// control of `old_node_id` to the new identity. The signature must
/// verify against the old IdentityDocument's `master_pubkey` at the
/// time the cert is published, which is what gives the cert its weight.
#[allow(clippy::too_many_arguments)]
pub fn sign_migration_cert(
    old_master_algo: u8,
    old_master_pubkey_b64: &str,
    old_master_sk_b64: &str,
    old_node_id: [u8; 32],
    new_node_id: [u8; 32],
    new_master_algo: u8,
    new_master_pubkey: Vec<u8>,
    issued_at_unix: u64,
    valid_until_unix: u64,
) -> Result<Vec<u8>, MigrationCertError> {
    // Validate algo bytes and security non-downgrade BEFORE doing any
    // crypto work.
    let old_algo = algo_from_byte(old_master_algo)?;
    let _new_algo = algo_from_byte(new_master_algo)?;
    if security_tier(new_master_algo) < security_tier(old_master_algo) {
        return Err(MigrationCertError::SecurityDowngrade {
            old_algo: old_master_algo,
            new_algo: new_master_algo,
        });
    }

    // Validate the validity window.
    if issued_at_unix >= valid_until_unix {
        return Err(MigrationCertError::InvertedWindow {
            valid_from: issued_at_unix,
            valid_until: valid_until_unix,
        });
    }
    let window = valid_until_unix - issued_at_unix;
    if window > MAX_MIGRATION_VALIDITY_SECS {
        return Err(MigrationCertError::WindowTooLong { got: window });
    }

    let canonical = canonical_message(
        &old_node_id,
        &new_node_id,
        new_master_algo,
        &new_master_pubkey,
        issued_at_unix,
        valid_until_unix,
    );
    let signature = sign_message(
        old_algo,
        old_master_pubkey_b64,
        old_master_sk_b64,
        &canonical,
    )
    .map_err(|e| MigrationCertError::Internal(format!("sign: {e}")))?;

    encode_body(
        old_master_algo,
        &old_node_id,
        &new_node_id,
        new_master_algo,
        &new_master_pubkey,
        issued_at_unix,
        valid_until_unix,
        &signature,
    )
}

/// Decode `bytes` into a `MigrationCert` without verifying the
/// signature. Caller MUST chain [`verify_migration_cert`] before
/// trusting any field. Decoding-without-verifying is exposed
/// separately so debug tools can pretty-print "what does this cert
/// claim" before deciding to trust it.
pub fn decode_migration_cert(blob: &[u8]) -> Result<MigrationCert, MigrationCertError> {
    if blob.len() > MAX_MIGRATION_CERT_BYTES {
        return Err(MigrationCertError::TooLarge { got: blob.len() });
    }
    let mut p = 0usize;
    let magic = read(blob, &mut p, 2)?;
    if magic != MIGRATION_CERT_MAGIC {
        return Err(MigrationCertError::Malformed(format!(
            "bad magic: {magic:?}"
        )));
    }
    let version = read(blob, &mut p, 1)?[0];
    if version != MIGRATION_CERT_VERSION {
        return Err(MigrationCertError::Malformed(format!(
            "unsupported version {version}"
        )));
    }
    let old_master_algo = read(blob, &mut p, 1)?[0];
    let mut old_node_id = [0u8; 32];
    old_node_id.copy_from_slice(read(blob, &mut p, 32)?);
    let mut new_node_id = [0u8; 32];
    new_node_id.copy_from_slice(read(blob, &mut p, 32)?);
    let new_master_algo = read(blob, &mut p, 1)?[0];
    let pk_len = u16::from_be_bytes(read(blob, &mut p, 2)?.try_into().unwrap()) as usize;
    if pk_len > 2048 {
        return Err(MigrationCertError::Malformed(format!(
            "new_master_pubkey too long: {pk_len}"
        )));
    }
    let new_master_pubkey = read(blob, &mut p, pk_len)?.to_vec();
    let issued_at_unix = u64::from_be_bytes(read(blob, &mut p, 8)?.try_into().unwrap());
    let valid_until_unix = u64::from_be_bytes(read(blob, &mut p, 8)?.try_into().unwrap());
    let sig_len = u16::from_be_bytes(read(blob, &mut p, 2)?.try_into().unwrap()) as usize;
    if sig_len > 2048 {
        return Err(MigrationCertError::Malformed(format!(
            "signature too long: {sig_len}"
        )));
    }
    let signature = read(blob, &mut p, sig_len)?.to_vec();
    if p != blob.len() {
        return Err(MigrationCertError::Malformed(format!(
            "trailing garbage: {} bytes after cert end",
            blob.len() - p
        )));
    }

    Ok(MigrationCert {
        old_master_algo,
        old_node_id,
        new_node_id,
        new_master_algo,
        new_master_pubkey,
        issued_at_unix,
        valid_until_unix,
        signature,
    })
}

/// Verify `cert` against `old_master_pubkey` (typically loaded by the
/// caller from the published IdentityDocument at `cert.old_node_id`).
/// Checks: signature, validity-window absence-of-expired-or-not-yet-valid
/// security non-downgrade, structural binding (`new_node_id ==
/// BLAKE3(new_master_pubkey)`).
///
/// `now_unix` is a monotonic-ish wall-clock timestamp; production caller
/// supplies `SystemTime::now.duration_since(UNIX_EPOCH).as_secs`
/// tests pin to a literal.
pub fn verify_migration_cert(
    cert: &MigrationCert,
    old_master_pubkey_b64: &str,
    now_unix: u64,
) -> Result<(), MigrationCertError> {
    // 1. Validity window.
    if now_unix < cert.issued_at_unix {
        return Err(MigrationCertError::NotYetValid {
            now: now_unix,
            issued_at: cert.issued_at_unix,
        });
    }
    if now_unix >= cert.valid_until_unix {
        return Err(MigrationCertError::Expired {
            now: now_unix,
            valid_until: cert.valid_until_unix,
        });
    }
    let window = cert.valid_until_unix.saturating_sub(cert.issued_at_unix);
    if window > MAX_MIGRATION_VALIDITY_SECS {
        return Err(MigrationCertError::WindowTooLong { got: window });
    }

    // 2. Structural binding: new_node_id MUST equal BLAKE3(new_master_pubkey).
    let expected_new_node_id = *blake3::hash(&cert.new_master_pubkey).as_bytes();
    if expected_new_node_id != cert.new_node_id {
        return Err(MigrationCertError::Malformed(
            "new_node_id != BLAKE3(new_master_pubkey)".into(),
        ));
    }

    // 3. Security non-downgrade.
    if security_tier(cert.new_master_algo) < security_tier(cert.old_master_algo) {
        return Err(MigrationCertError::SecurityDowngrade {
            old_algo: cert.old_master_algo,
            new_algo: cert.new_master_algo,
        });
    }

    // 4. Signature verify against the OLD master pubkey.
    let old_algo = algo_from_byte(cert.old_master_algo)?;
    let _new_algo_ok = algo_from_byte(cert.new_master_algo)?;
    let canonical = canonical_message(
        &cert.old_node_id,
        &cert.new_node_id,
        cert.new_master_algo,
        &cert.new_master_pubkey,
        cert.issued_at_unix,
        cert.valid_until_unix,
    );
    verify_message(old_algo, old_master_pubkey_b64, &canonical, &cert.signature)
        .map_err(|_| MigrationCertError::VerifyFailed)?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_body(
    old_master_algo: u8,
    old_node_id: &[u8; 32],
    new_node_id: &[u8; 32],
    new_master_algo: u8,
    new_master_pubkey: &[u8],
    issued_at_unix: u64,
    valid_until_unix: u64,
    signature: &[u8],
) -> Result<Vec<u8>, MigrationCertError> {
    let mut out = Vec::with_capacity(
        2 + 1 + 1 + 32 + 32 + 1 + 2 + new_master_pubkey.len() + 8 + 8 + 2 + signature.len(),
    );
    out.extend_from_slice(&MIGRATION_CERT_MAGIC);
    out.push(MIGRATION_CERT_VERSION);
    out.push(old_master_algo);
    out.extend_from_slice(old_node_id);
    out.extend_from_slice(new_node_id);
    out.push(new_master_algo);
    out.extend_from_slice(&(new_master_pubkey.len() as u16).to_be_bytes());
    out.extend_from_slice(new_master_pubkey);
    out.extend_from_slice(&issued_at_unix.to_be_bytes());
    out.extend_from_slice(&valid_until_unix.to_be_bytes());
    out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    out.extend_from_slice(signature);
    if out.len() > MAX_MIGRATION_CERT_BYTES {
        return Err(MigrationCertError::TooLarge { got: out.len() });
    }
    Ok(out)
}

fn read<'a>(blob: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8], MigrationCertError> {
    // `checked_add` (no `*p + n` overflow on 32-bit targets) AND an explicit
    // `end <= blob.len()` bound, so this never underflows or OOB-slices even if
    // a future caller seeds `*p` past `blob.len()` (migration certs are
    // network-presentable identity records — a panic here would be remote DoS).
    let end = p
        .checked_add(n)
        .filter(|&e| e <= blob.len())
        .ok_or_else(|| {
            let remaining = blob.len().saturating_sub(*p);
            MigrationCertError::Malformed(format!(
                "truncated: need {n} bytes at offset {p}, have {remaining}",
            ))
        })?;
    let s = &blob[*p..end];
    *p = end;
    Ok(s)
}

/// Convenience: encode a raw pubkey blob to the base64 form `sign_message`
/// / `verify_message` expect. Caller-side helper so glue code doesn't
/// re-import the base64 engine.
pub fn pubkey_bytes_to_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_crypto::generate_keypair;

    fn fresh_b64_kp(algo: SignatureAlgorithm) -> (String, String, Vec<u8>) {
        let kp = generate_keypair(algo);
        let pk_bytes = base64::engine::general_purpose::STANDARD
            .decode(&kp.public_key)
            .unwrap();
        (kp.public_key, kp.private_key, pk_bytes)
    }

    #[test]
    fn epic486_3_roundtrip_ed25519_to_hybrid() {
        // Old master = Ed25519; new master = hybrid (security UPGRADE).
        let (old_pk_b64, old_sk_b64, old_pk_bytes) = fresh_b64_kp(SignatureAlgorithm::Ed25519);
        let (_new_pk_b64, _new_sk_b64, new_pk_bytes) =
            fresh_b64_kp(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        let old_node_id = *blake3::hash(&old_pk_bytes).as_bytes();
        let new_node_id = *blake3::hash(&new_pk_bytes).as_bytes();
        let now = 1_700_000_000u64;
        let valid_until = now + 7 * 86_400; // 7 days

        let cert_bytes = sign_migration_cert(
            ALGO_ED25519,
            &old_pk_b64,
            &old_sk_b64,
            old_node_id,
            new_node_id,
            ALGO_ED25519_FALCON512_HYBRID,
            new_pk_bytes.clone(),
            now,
            valid_until,
        )
        .unwrap();

        let cert = decode_migration_cert(&cert_bytes).unwrap();
        assert_eq!(cert.old_node_id, old_node_id);
        assert_eq!(cert.new_node_id, new_node_id);
        assert_eq!(cert.new_master_algo, ALGO_ED25519_FALCON512_HYBRID);
        assert_eq!(cert.new_master_pubkey, new_pk_bytes);
        verify_migration_cert(&cert, &old_pk_b64, now + 1).unwrap();
    }

    #[test]
    fn etap10_roundtrip_hybrid512_to_hybrid1024() {
        // Falcon-512 hybrid → Falcon-1024 hybrid is a PQ-strength UPGRADE
        // (tier 3 → 4). Must sign + verify; exercises the new
        // ALGO_ED25519_FALCON1024_HYBRID arms in algo_from_byte/security_tier.
        let (old_pk_b64, old_sk_b64, old_pk_bytes) =
            fresh_b64_kp(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        let (_n_pk_b64, _n_sk_b64, new_pk_bytes) =
            fresh_b64_kp(SignatureAlgorithm::Ed25519Falcon1024Hybrid);
        let old_node_id = *blake3::hash(&old_pk_bytes).as_bytes();
        let new_node_id = *blake3::hash(&new_pk_bytes).as_bytes();
        let now = 1_700_000_000u64;
        let valid_until = now + 7 * 86_400;

        let cert_bytes = sign_migration_cert(
            ALGO_ED25519_FALCON512_HYBRID,
            &old_pk_b64,
            &old_sk_b64,
            old_node_id,
            new_node_id,
            ALGO_ED25519_FALCON1024_HYBRID,
            new_pk_bytes.clone(),
            now,
            valid_until,
        )
        .unwrap();

        let cert = decode_migration_cert(&cert_bytes).unwrap();
        assert_eq!(cert.new_master_algo, ALGO_ED25519_FALCON1024_HYBRID);
        assert_eq!(cert.new_master_pubkey, new_pk_bytes);
        verify_migration_cert(&cert, &old_pk_b64, now + 1).unwrap();
    }

    #[test]
    fn etap10_downgrade_hybrid1024_to_hybrid512_rejected() {
        // Falcon-1024 hybrid → Falcon-512 hybrid is a PQ-strength DOWNGRADE
        // (tier 4 → 3). Must reject at sign — proves 1024-hybrid is ranked
        // strictly above 512-hybrid, not merely "also recognized".
        let (old_pk_b64, old_sk_b64, old_pk_bytes) =
            fresh_b64_kp(SignatureAlgorithm::Ed25519Falcon1024Hybrid);
        let (_, _, new_pk_bytes) = fresh_b64_kp(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        let old_node_id = *blake3::hash(&old_pk_bytes).as_bytes();
        let new_node_id = *blake3::hash(&new_pk_bytes).as_bytes();
        let now = 1_700_000_000u64;

        let err = sign_migration_cert(
            ALGO_ED25519_FALCON1024_HYBRID,
            &old_pk_b64,
            &old_sk_b64,
            old_node_id,
            new_node_id,
            ALGO_ED25519_FALCON512_HYBRID,
            new_pk_bytes,
            now,
            now + 1000,
        )
        .unwrap_err();
        assert!(matches!(err, MigrationCertError::SecurityDowngrade { .. }));
    }

    #[test]
    fn epic486_3_security_downgrade_rejected() {
        // Old master = Hybrid; new master = Ed25519 — DOWNGRADE, must reject at sign.
        let (old_pk_b64, old_sk_b64, old_pk_bytes) =
            fresh_b64_kp(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        let (_, _, new_pk_bytes) = fresh_b64_kp(SignatureAlgorithm::Ed25519);
        let old_node_id = *blake3::hash(&old_pk_bytes).as_bytes();
        let new_node_id = *blake3::hash(&new_pk_bytes).as_bytes();
        let now = 1_700_000_000u64;

        let err = sign_migration_cert(
            ALGO_ED25519_FALCON512_HYBRID,
            &old_pk_b64,
            &old_sk_b64,
            old_node_id,
            new_node_id,
            ALGO_ED25519,
            new_pk_bytes,
            now,
            now + 1000,
        )
        .unwrap_err();
        assert!(matches!(err, MigrationCertError::SecurityDowngrade { .. }));
    }

    #[test]
    fn epic486_3_tampered_new_node_id_rejected_at_verify() {
        let (old_pk_b64, old_sk_b64, old_pk_bytes) = fresh_b64_kp(SignatureAlgorithm::Ed25519);
        let (_, _, new_pk_bytes) = fresh_b64_kp(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        let old_node_id = *blake3::hash(&old_pk_bytes).as_bytes();
        let new_node_id = *blake3::hash(&new_pk_bytes).as_bytes();
        let now = 1_700_000_000u64;
        let cert_bytes = sign_migration_cert(
            ALGO_ED25519,
            &old_pk_b64,
            &old_sk_b64,
            old_node_id,
            new_node_id,
            ALGO_ED25519_FALCON512_HYBRID,
            new_pk_bytes,
            now,
            now + 1000,
        )
        .unwrap();
        let mut cert = decode_migration_cert(&cert_bytes).unwrap();
        cert.new_node_id[0] ^= 0xFF;
        // Structural binding fails first (new_node_id!= BLAKE3(new_master_pubkey)).
        let err = verify_migration_cert(&cert, &old_pk_b64, now + 1).unwrap_err();
        assert!(matches!(err, MigrationCertError::Malformed(_)));
    }

    #[test]
    fn epic486_3_validity_window_expired_rejected() {
        let (old_pk_b64, old_sk_b64, old_pk_bytes) = fresh_b64_kp(SignatureAlgorithm::Ed25519);
        let (_, _, new_pk_bytes) = fresh_b64_kp(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        let old_node_id = *blake3::hash(&old_pk_bytes).as_bytes();
        let new_node_id = *blake3::hash(&new_pk_bytes).as_bytes();
        let now = 1_700_000_000u64;
        let valid_until = now + 100;
        let cert_bytes = sign_migration_cert(
            ALGO_ED25519,
            &old_pk_b64,
            &old_sk_b64,
            old_node_id,
            new_node_id,
            ALGO_ED25519_FALCON512_HYBRID,
            new_pk_bytes,
            now,
            valid_until,
        )
        .unwrap();
        let cert = decode_migration_cert(&cert_bytes).unwrap();

        // At now + 200 the cert is expired.
        let err = verify_migration_cert(&cert, &old_pk_b64, now + 200).unwrap_err();
        assert!(matches!(err, MigrationCertError::Expired { .. }));

        // At now - 1 the cert is not yet valid.
        let err = verify_migration_cert(&cert, &old_pk_b64, now - 1).unwrap_err();
        assert!(matches!(err, MigrationCertError::NotYetValid { .. }));

        // At now + 50 (within window) verify succeeds.
        verify_migration_cert(&cert, &old_pk_b64, now + 50).unwrap();
    }

    #[test]
    fn epic486_3_window_cap_30_days_enforced() {
        let (old_pk_b64, old_sk_b64, old_pk_bytes) = fresh_b64_kp(SignatureAlgorithm::Ed25519);
        let (_, _, new_pk_bytes) = fresh_b64_kp(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        let old_node_id = *blake3::hash(&old_pk_bytes).as_bytes();
        let new_node_id = *blake3::hash(&new_pk_bytes).as_bytes();
        let now = 1_700_000_000u64;
        let too_long = now + MAX_MIGRATION_VALIDITY_SECS + 1;
        let err = sign_migration_cert(
            ALGO_ED25519,
            &old_pk_b64,
            &old_sk_b64,
            old_node_id,
            new_node_id,
            ALGO_ED25519_FALCON512_HYBRID,
            new_pk_bytes,
            now,
            too_long,
        )
        .unwrap_err();
        assert!(matches!(err, MigrationCertError::WindowTooLong { .. }));
    }

    #[test]
    fn epic486_3_dht_key_domain_separated() {
        let node_id = [0x11u8; 32];
        let mig_key = migration_cert_dht_key(&node_id);
        // Should NOT match BLAKE3(node_id) alone — that's used elsewhere.
        let bare = *blake3::hash(&node_id).as_bytes();
        assert_ne!(mig_key, bare);
    }

    #[test]
    fn epic486_3_truncated_blob_rejected() {
        let (old_pk_b64, old_sk_b64, old_pk_bytes) = fresh_b64_kp(SignatureAlgorithm::Ed25519);
        let (_, _, new_pk_bytes) = fresh_b64_kp(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        let old_node_id = *blake3::hash(&old_pk_bytes).as_bytes();
        let new_node_id = *blake3::hash(&new_pk_bytes).as_bytes();
        let now = 1_700_000_000u64;
        let cert_bytes = sign_migration_cert(
            ALGO_ED25519,
            &old_pk_b64,
            &old_sk_b64,
            old_node_id,
            new_node_id,
            ALGO_ED25519_FALCON512_HYBRID,
            new_pk_bytes,
            now,
            now + 1000,
        )
        .unwrap();
        // Truncate by 10 bytes.
        let truncated = &cert_bytes[..cert_bytes.len() - 10];
        let err = decode_migration_cert(truncated).unwrap_err();
        assert!(matches!(err, MigrationCertError::Malformed(_)));
    }
}
