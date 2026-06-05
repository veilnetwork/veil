//! QR cold backup of the encrypted master_seed.
//!
//! Wraps the encrypted bundle produced by
//! [`encode_master_seed_encrypted_with`](super::master_file::encode_master_seed_encrypted_with)
//! in a `veil:master-backup?…` URI suitable for QR rendering.
//! Restoration goes through [`decode_master_backup_uri`] back to
//! the raw 32-byte master_seed, which the caller then feeds into
//! `restore_identity` on the recovering device.
//!
//! ## Threat model
//!
//! The QR is a **photo-grade backup** for the case where both
//! the BIP-39 paper phrase AND the encrypted master file are
//! unavailable. The plaintext seed never leaves the device — the
//! QR carries only the password-protected ciphertext. The
//! password MUST be conveyed out-of-band (verbal, sealed envelope
//! in a safe, separate password manager). Filming the QR alone
//! is insufficient to compromise the identity.
//!
//! ## URI shape
//!
//! ```text
//! veil:master-backup?v=1&data=<base64url-no-pad of encrypted bundle>
//! ```
//!
//! `v=1` is the URI envelope version (lets us evolve the QR
//! payload format independently of the inner master-file
//! wire version, which has its own `MASTER_FILE_V1` byte).
//! `data` is base64-url **without padding** so URL-safe
//! characters survive QR error correction without escaping.
//! Field order is canonical on encode but accepted in any
//! order on decode.
//!
//! Total URI length on default Argon2id params (~140 B bundle →
//! ~200 B base64 → ~225 B URI) fits comfortably inside one QR
//! code at error-correction level Q (≈ 750 B max).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

use super::master_file::{
    DEFAULT_M_COST_KIB, DEFAULT_P_COST, DEFAULT_T_COST, MasterFileError,
    decode_master_seed_encrypted, encode_master_seed_encrypted_with,
};
use super::master_seed::MASTER_SEED_LEN;

/// URI scheme prefix. Distinct from `veil:identity` (462.26
/// public contact) and `veil:pair` (462.30 invite) so a
/// scanner can dispatch on the prefix unambiguously.
pub const MASTER_BACKUP_URI_SCHEME: &str = "veil:master-backup";

/// URI envelope version. Bumping this requires updating
/// `decode_master_backup_uri`'s accept-set.
pub const MASTER_BACKUP_URI_V1: u8 = 1;

/// Hard cap on URI byte length. Defends decoders against
/// resource-exhaustion attacks via an adversarial QR. Headroom
/// over a typical default-params payload (~225 B) so future
/// stronger Argon2id params (e.g., 256 MiB m_cost → ~250 B
/// payload) still fit in one QR.
pub const MAX_MASTER_BACKUP_URI_BYTES: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum MasterBackupUriError {
    #[error("master backup uri: oversized ({got}B > {MAX_MASTER_BACKUP_URI_BYTES}B)")]
    Oversized { got: usize },
    #[error("master backup uri: wrong scheme (expected `veil:master-backup`)")]
    BadScheme,
    #[error("master backup uri: missing `?` query separator")]
    MissingQuery,
    #[error("master backup uri: missing required field `{field}`")]
    MissingField { field: &'static str },
    #[error("master backup uri: duplicate field `{field}`")]
    DuplicateField { field: &'static str },
    #[error("master backup uri: unknown field `{field}`")]
    UnknownField { field: String },
    #[error("master backup uri: malformed pair `{pair}` (expected `key=value`)")]
    MalformedPair { pair: String },
    #[error(
        "master backup uri: unsupported envelope version `{got}` (expected {MASTER_BACKUP_URI_V1})"
    )]
    UnsupportedVersion { got: String },
    #[error("master backup uri: invalid base64-url in field `data`")]
    InvalidBase64,
    /// Wrong password / tampered payload — surfaced as one error
    /// kind (no oracle distinguishing the two).
    #[error("master backup uri: decryption failed (wrong password or tampered payload)")]
    Decrypt(MasterFileError),
}

/// Encode an encrypted master_seed bundle as a canonical
/// `veil:master-backup?…` URI. Default Argon2id parameters.
pub fn encode_master_backup_uri(
    seed: &[u8; MASTER_SEED_LEN],
    password: &[u8],
) -> Result<String, MasterFileError> {
    encode_master_backup_uri_with(
        seed,
        password,
        DEFAULT_M_COST_KIB,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
    )
}

/// Like [`encode_master_backup_uri`] but lets the caller pin
/// Argon2id KDF parameters. Tests pass minimum-strength values
/// to keep the suite fast; production calls the default wrapper.
pub fn encode_master_backup_uri_with(
    seed: &[u8; MASTER_SEED_LEN],
    password: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<String, MasterFileError> {
    let bundle = encode_master_seed_encrypted_with(seed, password, m_cost_kib, t_cost, p_cost)?;
    let b64 = URL_SAFE_NO_PAD.encode(&bundle);
    Ok(format!(
        "{MASTER_BACKUP_URI_SCHEME}?v={MASTER_BACKUP_URI_V1}&data={b64}",
    ))
}

/// Decode a `veil:master-backup?…` URI back to the raw
/// 32-byte master_seed. Caller feeds the result into
/// `restore_identity` on the recovering device.
pub fn decode_master_backup_uri(
    uri: &str,
    password: &[u8],
) -> Result<Zeroizing<[u8; MASTER_SEED_LEN]>, MasterBackupUriError> {
    if uri.len() > MAX_MASTER_BACKUP_URI_BYTES {
        return Err(MasterBackupUriError::Oversized { got: uri.len() });
    }

    let q_idx = uri.find('?').ok_or(MasterBackupUriError::MissingQuery)?;
    let head = &uri[..q_idx];
    if !head.eq_ignore_ascii_case(MASTER_BACKUP_URI_SCHEME) {
        return Err(MasterBackupUriError::BadScheme);
    }
    let query = &uri[q_idx + 1..];

    let mut seen_v: Option<&str> = None;
    let mut seen_data: Option<&str> = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let mut split = pair.splitn(2, '=');
        let key = split
            .next()
            .ok_or_else(|| MasterBackupUriError::MalformedPair {
                pair: pair.to_string(),
            })?;
        let value = split
            .next()
            .ok_or_else(|| MasterBackupUriError::MalformedPair {
                pair: pair.to_string(),
            })?;
        match key {
            "v" => {
                if seen_v.is_some() {
                    return Err(MasterBackupUriError::DuplicateField { field: "v" });
                }
                seen_v = Some(value);
            }
            "data" => {
                if seen_data.is_some() {
                    return Err(MasterBackupUriError::DuplicateField { field: "data" });
                }
                seen_data = Some(value);
            }
            other => {
                return Err(MasterBackupUriError::UnknownField {
                    field: other.to_string(),
                });
            }
        }
    }

    let v = seen_v.ok_or(MasterBackupUriError::MissingField { field: "v" })?;
    if v != MASTER_BACKUP_URI_V1.to_string().as_str() {
        return Err(MasterBackupUriError::UnsupportedVersion { got: v.to_string() });
    }
    let data = seen_data.ok_or(MasterBackupUriError::MissingField { field: "data" })?;
    let bundle = URL_SAFE_NO_PAD
        .decode(data.as_bytes())
        .map_err(|_| MasterBackupUriError::InvalidBase64)?;

    decode_master_seed_encrypted(&bundle, password).map_err(MasterBackupUriError::Decrypt)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::master_file::MIN_M_COST_KIB;
    use super::*;

    fn fast_params() -> (u32, u32, u32) {
        // Just-strong-enough to clear `MIN_M_COST_KIB` / `MIN_T_COST`
        // / `MIN_P_COST` — tests never use production-grade KDF.
        (MIN_M_COST_KIB, 1, 1)
    }

    #[test]
    fn round_trip_recovers_original_seed() {
        let (m, t, p) = fast_params();
        let seed = [0xAAu8; MASTER_SEED_LEN];
        let uri =
            encode_master_backup_uri_with(&seed, b"correct-horse-battery-staple", m, t, p).unwrap();
        assert!(uri.starts_with("veil:master-backup?"));
        assert!(uri.contains("v=1"));
        assert!(uri.contains("data="));
        let recovered = decode_master_backup_uri(&uri, b"correct-horse-battery-staple").unwrap();
        assert_eq!(recovered.as_ref(), &seed);
    }

    #[test]
    fn wrong_password_rejected_indistinguishably() {
        let (m, t, p) = fast_params();
        let seed = [0x33u8; MASTER_SEED_LEN];
        let uri = encode_master_backup_uri_with(&seed, b"right", m, t, p).unwrap();
        let err = decode_master_backup_uri(&uri, b"wrong").unwrap_err();
        assert!(
            matches!(
                err,
                MasterBackupUriError::Decrypt(MasterFileError::WrongPasswordOrTampered)
            ),
            "{err:?}",
        );
    }

    #[test]
    fn wrong_scheme_rejected() {
        let err = decode_master_backup_uri("veil:identity?v=1&data=AA", b"x").unwrap_err();
        assert!(matches!(err, MasterBackupUriError::BadScheme), "{err:?}");
    }

    #[test]
    fn missing_query_rejected() {
        let err = decode_master_backup_uri("veil:master-backup", b"x").unwrap_err();
        assert!(matches!(err, MasterBackupUriError::MissingQuery), "{err:?}");
    }

    #[test]
    fn missing_v_field_rejected() {
        let err = decode_master_backup_uri("veil:master-backup?data=AAAA", b"x").unwrap_err();
        assert!(
            matches!(err, MasterBackupUriError::MissingField { field: "v" }),
            "{err:?}",
        );
    }

    #[test]
    fn missing_data_field_rejected() {
        let err = decode_master_backup_uri("veil:master-backup?v=1", b"x").unwrap_err();
        assert!(
            matches!(err, MasterBackupUriError::MissingField { field: "data" }),
            "{err:?}",
        );
    }

    #[test]
    fn unsupported_version_rejected() {
        let err = decode_master_backup_uri("veil:master-backup?v=99&data=AAAA", b"x").unwrap_err();
        assert!(
            matches!(err, MasterBackupUriError::UnsupportedVersion { .. }),
            "{err:?}",
        );
    }

    #[test]
    fn duplicate_field_rejected() {
        let err =
            decode_master_backup_uri("veil:master-backup?v=1&v=1&data=AAAA", b"x").unwrap_err();
        assert!(
            matches!(err, MasterBackupUriError::DuplicateField { field: "v" }),
            "{err:?}",
        );
    }

    #[test]
    fn unknown_field_rejected() {
        let err =
            decode_master_backup_uri("veil:master-backup?v=1&data=AAAA&extra=x", b"x").unwrap_err();
        assert!(
            matches!(err, MasterBackupUriError::UnknownField { ref field } if field == "extra"),
            "{err:?}",
        );
    }

    #[test]
    fn invalid_base64_rejected() {
        let err =
            decode_master_backup_uri("veil:master-backup?v=1&data=!!not-b64!!", b"x").unwrap_err();
        assert!(
            matches!(err, MasterBackupUriError::InvalidBase64),
            "{err:?}"
        );
    }

    #[test]
    fn shuffled_field_order_accepted_on_decode() {
        // Encoder emits canonical `v=…&data=…`; decoder must
        // also accept reverse order so QR scanners that don't
        // preserve query order still work.
        let (m, t, p) = fast_params();
        let seed = [0x77u8; MASTER_SEED_LEN];
        let canonical = encode_master_backup_uri_with(&seed, b"pw", m, t, p).unwrap();
        // Hand-build a reverse-order URI from the same data.
        let q_idx = canonical.find('?').unwrap();
        let v_eq = canonical.find("v=").unwrap();
        let data_eq = canonical.find("data=").unwrap();
        let v_part = &canonical[v_eq..data_eq - 1];
        let data_part = &canonical[data_eq..];
        let shuffled = format!("{}?{}&{}", &canonical[..q_idx], data_part, v_part,);
        let recovered = decode_master_backup_uri(&shuffled, b"pw").unwrap();
        assert_eq!(recovered.as_ref(), &seed);
    }

    #[test]
    fn case_insensitive_scheme() {
        let (m, t, p) = fast_params();
        let seed = [0x55u8; MASTER_SEED_LEN];
        let uri = encode_master_backup_uri_with(&seed, b"pw", m, t, p).unwrap();
        let upper = uri.replacen("veil:master-backup", "Veil:Master-Backup", 1);
        let recovered = decode_master_backup_uri(&upper, b"pw").unwrap();
        assert_eq!(recovered.as_ref(), &seed);
    }

    #[test]
    fn oversized_uri_rejected() {
        let mut huge = String::from("veil:master-backup?v=1&data=");
        huge.push_str(&"A".repeat(MAX_MASTER_BACKUP_URI_BYTES));
        let err = decode_master_backup_uri(&huge, b"x").unwrap_err();
        assert!(
            matches!(err, MasterBackupUriError::Oversized { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn tampered_data_field_rejected() {
        let (m, t, p) = fast_params();
        let seed = [0x42u8; MASTER_SEED_LEN];
        let mut uri = encode_master_backup_uri_with(&seed, b"pw", m, t, p).unwrap();
        // Flip a base64 char near the end of `data` — invalidates
        // either the bundle structure or the AEAD tag.
        let last_idx = uri.len() - 5;
        let original = uri.as_bytes()[last_idx];
        let bumped = if original == b'A' { b'B' } else { b'A' };
        unsafe {
            uri.as_bytes_mut()[last_idx] = bumped;
        }
        let err = decode_master_backup_uri(&uri, b"pw").unwrap_err();
        assert!(matches!(err, MasterBackupUriError::Decrypt(_)), "{err:?}");
    }

    #[test]
    fn bundle_round_trip_through_byte_helpers() {
        // Sanity check on the underlying byte-level helpers
        // (not the URI envelope). Confirms that the new
        // `encode_master_seed_encrypted_with` / `decode_master_seed_encrypted`
        // pair is a tight inverse — guards against accidental
        // padding / framing changes that would break the QR
        // payload silently.
        let (m, t, p) = fast_params();
        let seed = [0x99u8; MASTER_SEED_LEN];
        let bundle = encode_master_seed_encrypted_with(&seed, b"hello", m, t, p).unwrap();
        let recovered = decode_master_seed_encrypted(&bundle, b"hello").unwrap();
        assert_eq!(recovered.as_ref(), &seed);
    }
}
