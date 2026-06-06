//! Signed update-manifest primitive.
//!
//! Operator-signed metadata describing a release: version, binary
//! locations, expected SHA-256, downgrade-protection timestamp.
//! Clients fetch + verify before downloading the binary itself.
//!
//! # Wire format (binary, big-endian)
//!
//! ```text
//! [0..2] magic = "UM" (Update-Manifest)
//! [2] version = 1
//! [3] sig_algo u8 (0 = Ed25519, 1 = Falcon-512)
//! [4..12] release_unix u64 BE
//! [12..14] version_str_len u16 BE
//! [..] version_str ASCII semver "1.2.3" (≤ 64 B)
//! [..] min_version_len u8
//! [..] min_compatible_version ASCII semver (≤ 64 B; oldest version
//! that may upgrade to this. ENFORCED on apply: `apply_update`
//! refuses when the running binary's version is below this
//! (see `min_compatible_satisfied`). An empty value means "no
//! constraint"; a present-but-malformed value is rejected
//! fail-closed.)
//! [..] platform_target_len u8
//! [..] platform_target ASCII (≤ 64 B): "linux-x86_64"
//! "linux-aarch64", "macos-aarch64"
//! "windows-x86_64", "android-aarch64"
//! [..] binary_sha256 32 B (BLAKE3-or-SHA256 of the
//! decompressed binary blob)
//! [..] binary_url_count u8 (1..=8)
//! [..] [u16 BE len + URL bytes] × N
//! [..] issuer_pk_len u16 BE
//! [..] issuer_pk base64-encoded identity pubkey
//! same encoding as `IdentityConfig.public_key`
//! [..] sig_len u16 BE
//! [..] signature raw bytes (Ed25519=64, Falcon-512≈660)
//! ```
//!
//! # Canonical signed message
//!
//! ```text
//! "veil-update-manifest:v1\0"
//! + release_unix.to_be_bytes
//! + version_str.as_bytes
//! + 0x00
//! + min_compatible_version.as_bytes
//! + 0x00
//! + platform_target.as_bytes
//! + 0x00
//! + binary_sha256
//! + (binary_urls joined with 0x00 separator)
//! ```
//!
//! Domain prefix prevents cross-protocol signature reuse (an
//! identity_proof or signed_invite signature elsewhere can't be
//! replayed as an update manifest).
//!
//! # Anti-downgrade
//!
//! Verifier rejects manifest with `release_unix < installed_release_unix`.
//! Stops a censor that captures an OLD signed manifest from convincing
//! clients to roll back to a known-vulnerable version (which the
//! censor может then exploit). Each install records its source
//! manifest's `release_unix`; subsequent updates must monotonically
//! advance.
//!
//! # Anti-tamper
//!
//! Signature covers ALL fields including `binary_sha256` and every
//! `binary_url`. Attacker cannot:
//!
//! * Substitute a malicious binary at one URL (binary_sha256 mismatch
//!   stops install).
//! * Add a malicious URL to the list (signature fails because URLs
//!   are in the canonical message).
//! * Forward-date `release_unix` to skip ahead of legitimate updates
//!   (would only matter if attacker has issuer_sk, in which case
//!   it's full compromise anyway).
//!
//! Negative tests cover all four tamper modes.
//!
//! # What this module does NOT do (deferred to follow-up slices)
//!
//! * **No HTTPS fetch.** Caller resolves URLs and downloads bytes;
//!   this primitive только validates the manifest envelope + provides
//!   `binary_sha256` for caller to check downloaded bytes against.
//! * **No in-place restart.** Apply mechanism is separate.
//! * **No partial / delta updates.** Each manifest names a complete
//!   binary; v2 protocol can add deltas without breaking v1 readers.
//! * **No revocation.** Operators wanting to revoke a release just
//!   publish a newer manifest; old manifests with a lower
//!   `release_unix` get rejected by anti-downgrade automatically.

use veil_crypto::{sign_message, verify_message};
use veil_types::SignatureAlgorithm;

const MAGIC: &[u8; 2] = b"UM";
const VERSION: u8 = 1;
const SIG_DOMAIN: &[u8] = b"veil-update-manifest:v1\0";

/// Hard cap on manifest blob size — bounds memory for an attacker-
/// supplied manifest. Generous enough for Falcon-512 (~660 B sig +
/// ~900 B pubkey) plus 8 URLs × ~256 B each ≈ 4 KiB envelope.
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024;

/// maximum allowed positive clock skew between the verifier's local
/// time and the manifest's `release_unix` (seconds).
///
/// **Staged tier** (86 400 s = 24 h) — central policy in
/// `veil-proto::time_validity::STAGED_SKEW_SECS`.  Cannot import
/// directly (veil-update doesn't depend на veil-proto) so the
/// constant is duplicated.  **Pinned by the `staged_tier_is_24_hours`
/// test в `veil-proto::time_validity`** — that test fails если а
/// future refactor flips the central tier without updating this site.
///
/// Why this tier:
/// * 1 day covers normal client clock drift на budget-Android devices
///   (where NTP may not run while the device is offline / in airplane
///   mode for several days) without admitting indefinitely-future-dated
///   manifests.
/// * Admits pre-staged rollouts: issuer signs at T1, schedules
///   activation at T2, clients pulling в the T1-T2 window must
///   accept.
/// * An attacker who compromises the issuer key can still sign now+1d,
///   но cannot stage a 10-year-future manifest that freezes upgrades
///   after rotation.
pub const MAX_MANIFEST_FUTURE_SKEW_SECS: u64 = 86_400;

/// maximum allowed *age* of a manifest before
/// the verifier rejects it as stale (seconds). 90 days bounds the
/// replay window for an old captured manifest while leaving room for
/// devices that have been offline for multiple weeks (common in
/// authoritarian-state operating environments).
pub const MAX_MANIFEST_AGE_SECS: u64 = 86_400 * 90;

/// Hard caps on field sizes so a malformed manifest can't blow our
/// memory or skew display columns in `veil update --check` output.
pub const MAX_VERSION_STR_LEN: usize = 64;
pub const MAX_PLATFORM_TARGET_LEN: usize = 64;
pub const MAX_BINARY_URL_LEN: usize = 512;
pub const MAX_BINARY_URLS: usize = 8;
pub const BINARY_SHA256_LEN: usize = 32;

/// Per-algorithm cap on the (base64-encoded UTF-8) `issuer_pk` field.
/// Raw key sizes: Ed25519 = 32 B, Falcon-512 = 897 B, Hybrid = 929 B.
/// Base64 expands ~4/3 (≈44, 1196, 1240 chars respectively). Round up
/// for padding + any operator slack but keep tight per algorithm so a
/// malformed manifest cannot inflate the `issuer_pk` field past what
/// the declared algo actually needs (M-22).
fn max_issuer_pk_len(algo: SignatureAlgorithm) -> usize {
    match algo {
        SignatureAlgorithm::Ed25519 => 128,
        SignatureAlgorithm::Falcon512 => 1280,
        SignatureAlgorithm::Ed25519Falcon512Hybrid => 1408,
        // Hybrid-1024: 32 (ed25519) + 1793 (falcon-1024) = 1825 raw bytes.
        // Base64 ≈ 1825 × 4/3 ≈ 2434 chars; round up к 2560 для padding +
        // operator slack while keeping the cap tight enough that
        // malformed manifests can't inflate the issuer_pk field.
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => 2560,
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ManifestError {
    #[error("sign: {0}")]
    Sign(String),
    #[error("signature verification failed (wrong issuer key, tampered fields, or wrong algo)")]
    Verify,
    #[error("issuer pubkey mismatch: expected {expected}, got {got}")]
    IssuerMismatch { expected: String, got: String },
    #[error("downgrade rejected: manifest release_unix={manifest} but installed={installed}")]
    Downgrade { manifest: u64, installed: u64 },
    /// manifest is too far in the future
    /// (clock-skew check). Either a misconfigured issuer signed it
    /// before-time, or an attacker is staging a future manifest to
    /// freeze upgrades — both block via this gate.
    #[error("future-dated manifest rejected: release_unix={release} > now+{skew}={limit}")]
    FutureSkew { release: u64, skew: u64, limit: u64 },
    /// manifest predates `MAX_MANIFEST_AGE_SECS`.
    /// Old manifest replays serve no legitimate use after the next
    /// release lands — refusing them tightens the censor-replay window.
    #[error("stale manifest rejected: release_unix={release} < now-{max_age}={limit}")]
    Stale {
        release: u64,
        max_age: u64,
        limit: u64,
    },
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("unsupported sig algo byte: {0}")]
    BadSigAlgo(u8),
    #[error("manifest exceeds {MAX_MANIFEST_BYTES} byte cap (got {got})")]
    TooLarge { got: usize },
    #[error("field over cap: {field} ({got} > {max})")]
    FieldTooLong {
        field: &'static str,
        got: usize,
        max: usize,
    },
    #[error("binary_url_count {got} not in 1..={MAX_BINARY_URLS}")]
    BadUrlCount { got: u8 },
    #[error("binary_sha256 length {got}; must be {BINARY_SHA256_LEN}")]
    BadHashLen { got: usize },
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateManifest {
    pub release_unix: u64,
    pub version: String,
    pub min_compatible_version: String,
    pub platform_target: String,
    pub binary_sha256: [u8; BINARY_SHA256_LEN],
    pub binary_urls: Vec<String>,
    pub issuer_pk: String,
    pub issuer_algo: SignatureAlgorithm,
    pub signature: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn sign_manifest(
    release_unix: u64,
    version: &str,
    min_compatible_version: &str,
    platform_target: &str,
    binary_sha256: [u8; BINARY_SHA256_LEN],
    binary_urls: Vec<String>,
    issuer_pk: &str,
    issuer_sk: &str,
    issuer_algo: SignatureAlgorithm,
) -> Result<Vec<u8>, ManifestError> {
    if version.len() > MAX_VERSION_STR_LEN {
        return Err(ManifestError::FieldTooLong {
            field: "version",
            got: version.len(),
            max: MAX_VERSION_STR_LEN,
        });
    }
    if min_compatible_version.len() > MAX_VERSION_STR_LEN {
        return Err(ManifestError::FieldTooLong {
            field: "min_compatible_version",
            got: min_compatible_version.len(),
            max: MAX_VERSION_STR_LEN,
        });
    }
    if platform_target.len() > MAX_PLATFORM_TARGET_LEN {
        return Err(ManifestError::FieldTooLong {
            field: "platform_target",
            got: platform_target.len(),
            max: MAX_PLATFORM_TARGET_LEN,
        });
    }
    if binary_urls.is_empty() || binary_urls.len() > MAX_BINARY_URLS {
        return Err(ManifestError::BadUrlCount {
            got: binary_urls.len() as u8,
        });
    }
    for url in &binary_urls {
        if url.len() > MAX_BINARY_URL_LEN {
            return Err(ManifestError::FieldTooLong {
                field: "binary_url",
                got: url.len(),
                max: MAX_BINARY_URL_LEN,
            });
        }
    }
    let issuer_pk_cap = max_issuer_pk_len(issuer_algo);
    if issuer_pk.len() > issuer_pk_cap {
        return Err(ManifestError::FieldTooLong {
            field: "issuer_pk",
            got: issuer_pk.len(),
            max: issuer_pk_cap,
        });
    }

    let canonical = canonical_message(
        release_unix,
        version,
        min_compatible_version,
        platform_target,
        &binary_sha256,
        &binary_urls,
    );
    let signature = sign_message(issuer_algo, issuer_pk, issuer_sk, &canonical)
        .map_err(|e| ManifestError::Sign(format!("{e}")))?;

    let bytes = encode_body(
        release_unix,
        version,
        min_compatible_version,
        platform_target,
        &binary_sha256,
        &binary_urls,
        issuer_pk.as_bytes(),
        issuer_algo,
        &signature,
    )?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge { got: bytes.len() });
    }
    Ok(bytes)
}

/// Decode bytes into [`UpdateManifest`] WITHOUT verifying signature
/// or checking freshness. Caller MUST chain [`verify_manifest`]
/// before trusting any field.
pub fn decode_manifest(blob: &[u8]) -> Result<UpdateManifest, ManifestError> {
    if blob.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge { got: blob.len() });
    }
    let mut p = 0usize;
    let magic = read(blob, &mut p, 2)?;
    if magic != MAGIC {
        return Err(ManifestError::Malformed(format!("bad magic: {magic:?}")));
    }
    let version_byte = read(blob, &mut p, 1)?[0];
    if version_byte != VERSION {
        return Err(ManifestError::Malformed(format!(
            "unsupported version {version_byte}",
        )));
    }
    let sig_algo_byte = read(blob, &mut p, 1)?[0];
    let issuer_algo = match sig_algo_byte {
        0 => SignatureAlgorithm::Ed25519,
        1 => SignatureAlgorithm::Falcon512,
        2 => SignatureAlgorithm::Ed25519Falcon512Hybrid,
        3 => SignatureAlgorithm::Ed25519Falcon1024Hybrid,
        b => return Err(ManifestError::BadSigAlgo(b)),
    };
    let release_unix = u64::from_be_bytes(read(blob, &mut p, 8)?.try_into().unwrap());

    let version = read_string_u16(blob, &mut p, "version", MAX_VERSION_STR_LEN)?;
    let min_compatible_version =
        read_string_u8(blob, &mut p, "min_compatible_version", MAX_VERSION_STR_LEN)?;
    let platform_target = read_string_u8(blob, &mut p, "platform_target", MAX_PLATFORM_TARGET_LEN)?;

    let hash_bytes = read(blob, &mut p, BINARY_SHA256_LEN)?;
    let mut binary_sha256 = [0u8; BINARY_SHA256_LEN];
    binary_sha256.copy_from_slice(hash_bytes);

    let url_count = read(blob, &mut p, 1)?[0];
    if url_count == 0 || url_count > MAX_BINARY_URLS as u8 {
        return Err(ManifestError::BadUrlCount { got: url_count });
    }
    let mut binary_urls = Vec::with_capacity(url_count as usize);
    for _ in 0..url_count {
        binary_urls.push(read_string_u16(
            blob,
            &mut p,
            "binary_url",
            MAX_BINARY_URL_LEN,
        )?);
    }

    let issuer_pk_bytes =
        read_string_u16_raw(blob, &mut p, "issuer_pk", max_issuer_pk_len(issuer_algo))?;
    let issuer_pk = std::str::from_utf8(issuer_pk_bytes)
        .map_err(|e| ManifestError::Malformed(format!("issuer_pk utf8: {e}")))?
        .to_owned();

    let sig_len = u16::from_be_bytes(read(blob, &mut p, 2)?.try_into().unwrap()) as usize;
    let signature = read(blob, &mut p, sig_len)?.to_vec();

    if p != blob.len() {
        return Err(ManifestError::Malformed(format!(
            "{} trailing byte(s)",
            blob.len() - p,
        )));
    }
    Ok(UpdateManifest {
        release_unix,
        version,
        min_compatible_version,
        platform_target,
        binary_sha256,
        binary_urls,
        issuer_pk,
        issuer_algo,
        signature,
    })
}

/// Verify a decoded manifest. Five checks run in order:
///
/// 1. **Anti-downgrade**: when `installed_release_unix` is `Some`
///    manifest's `release_unix` must be strictly greater. Stops
///    a censor that captures an OLD signed manifest from rolling
///    clients back to a known-vulnerable version.
/// 2. **/ — clock-skew (future)**: when `now_unix_secs`
///    is `Some`, `release_unix` must not exceed `now + MAX_MANIFEST_FUTURE_SKEW_SECS`.
///    Bounds future-dated manifest abuse from a temporarily-compromised
///    issuer key.
/// 3. **/ — staleness**: `release_unix` must not
///    predate `now - MAX_MANIFEST_AGE_SECS`. Rejects ancient
///    captured manifests after legitimate releases have superseded them.
/// 4. **Issuer match** (when `expected_issuer_pk` provided): the
///    embedded `issuer_pk` must match. Without this check, an
///    attacker who controls ANY identity could publish a
///    manifest signed by their own key and have it pass the
///    internal-consistency signature check.
/// 5. **Signature**: cryptographic verify of the canonical message.
pub fn verify_manifest(
    manifest: &UpdateManifest,
    expected_issuer_pk: Option<&str>,
    installed_release_unix: Option<u64>,
    now_unix_secs: Option<u64>,
) -> Result<(), ManifestError> {
    if let Some(installed) = installed_release_unix
        && manifest.release_unix <= installed
    {
        return Err(ManifestError::Downgrade {
            manifest: manifest.release_unix,
            installed,
        });
    }
    if let Some(now) = now_unix_secs {
        let future_limit = now.saturating_add(MAX_MANIFEST_FUTURE_SKEW_SECS);
        if manifest.release_unix > future_limit {
            return Err(ManifestError::FutureSkew {
                release: manifest.release_unix,
                skew: MAX_MANIFEST_FUTURE_SKEW_SECS,
                limit: future_limit,
            });
        }
        let stale_limit = now.saturating_sub(MAX_MANIFEST_AGE_SECS);
        if manifest.release_unix < stale_limit {
            return Err(ManifestError::Stale {
                release: manifest.release_unix,
                max_age: MAX_MANIFEST_AGE_SECS,
                limit: stale_limit,
            });
        }
    }
    if let Some(expected) = expected_issuer_pk
        && expected != manifest.issuer_pk
    {
        return Err(ManifestError::IssuerMismatch {
            expected: expected.to_owned(),
            got: manifest.issuer_pk.clone(),
        });
    }
    let canonical = canonical_message(
        manifest.release_unix,
        &manifest.version,
        &manifest.min_compatible_version,
        &manifest.platform_target,
        &manifest.binary_sha256,
        &manifest.binary_urls,
    );
    verify_message(
        manifest.issuer_algo,
        &manifest.issuer_pk,
        &canonical,
        &manifest.signature,
    )
    .map_err(|_| ManifestError::Verify)
}

fn canonical_message(
    release_unix: u64,
    version: &str,
    min_compatible_version: &str,
    platform_target: &str,
    binary_sha256: &[u8; BINARY_SHA256_LEN],
    binary_urls: &[String],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIG_DOMAIN.len() + 256);
    out.extend_from_slice(SIG_DOMAIN);
    out.extend_from_slice(&release_unix.to_be_bytes());
    out.extend_from_slice(version.as_bytes());
    out.push(0x00);
    out.extend_from_slice(min_compatible_version.as_bytes());
    out.push(0x00);
    out.extend_from_slice(platform_target.as_bytes());
    out.push(0x00);
    out.extend_from_slice(binary_sha256);
    for url in binary_urls {
        out.extend_from_slice(url.as_bytes());
        out.push(0x00);
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn encode_body(
    release_unix: u64,
    version: &str,
    min_compatible_version: &str,
    platform_target: &str,
    binary_sha256: &[u8; BINARY_SHA256_LEN],
    binary_urls: &[String],
    issuer_pk: &[u8],
    issuer_algo: SignatureAlgorithm,
    signature: &[u8],
) -> Result<Vec<u8>, ManifestError> {
    if issuer_pk.len() > u16::MAX as usize {
        return Err(ManifestError::Malformed("issuer_pk too long".into()));
    }
    if signature.len() > u16::MAX as usize {
        return Err(ManifestError::Malformed("signature too long".into()));
    }
    let mut out = Vec::with_capacity(2 + 1 + 1 + 8 + 256);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(match issuer_algo {
        SignatureAlgorithm::Ed25519 => 0,
        SignatureAlgorithm::Falcon512 => 1,
        SignatureAlgorithm::Ed25519Falcon512Hybrid => 2,
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => 3,
    });
    out.extend_from_slice(&release_unix.to_be_bytes());
    write_string_u16(&mut out, version);
    write_string_u8(&mut out, min_compatible_version);
    write_string_u8(&mut out, platform_target);
    out.extend_from_slice(binary_sha256);
    out.push(binary_urls.len() as u8);
    for url in binary_urls {
        write_string_u16(&mut out, url);
    }
    out.extend_from_slice(&(issuer_pk.len() as u16).to_be_bytes());
    out.extend_from_slice(issuer_pk);
    out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    out.extend_from_slice(signature);
    Ok(out)
}

fn write_string_u16(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn write_string_u8(out: &mut Vec<u8>, s: &str) {
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
}

fn read<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], ManifestError> {
    // checked_add so an attacker-controlled length field can't wrap `*pos + n`
    // (matches the defensive pattern in signed_bundle.rs). `.get()` already
    // bounds-checks the slice; this closes the overflow edge on the offset.
    let end = pos
        .checked_add(n)
        .ok_or_else(|| ManifestError::Malformed(format!("offset overflow {}+{}", *pos, n)))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| ManifestError::Malformed(format!("truncated {}B at {}", n, *pos)))?;
    *pos = end;
    Ok(slice)
}

fn read_string_u16(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
    max: usize,
) -> Result<String, ManifestError> {
    let len = u16::from_be_bytes(read(buf, pos, 2)?.try_into().unwrap()) as usize;
    if len > max {
        return Err(ManifestError::FieldTooLong {
            field,
            got: len,
            max,
        });
    }
    let bytes = read(buf, pos, len)?;
    std::str::from_utf8(bytes)
        .map_err(|e| ManifestError::Malformed(format!("{field} utf8: {e}")))
        .map(|s| s.to_owned())
}

fn read_string_u16_raw<'a>(
    buf: &'a [u8],
    pos: &mut usize,
    field: &'static str,
    max: usize,
) -> Result<&'a [u8], ManifestError> {
    let len = u16::from_be_bytes(read(buf, pos, 2)?.try_into().unwrap()) as usize;
    if len > max {
        return Err(ManifestError::FieldTooLong {
            field,
            got: len,
            max,
        });
    }
    read(buf, pos, len)
}

fn read_string_u8(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
    max: usize,
) -> Result<String, ManifestError> {
    let len = read(buf, pos, 1)?[0] as usize;
    if len > max {
        return Err(ManifestError::FieldTooLong {
            field,
            got: len,
            max,
        });
    }
    let bytes = read(buf, pos, len)?;
    std::str::from_utf8(bytes)
        .map_err(|e| ManifestError::Malformed(format!("{field} utf8: {e}")))
        .map(|s| s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_crypto::generate_keypair;

    fn fresh_issuer() -> (String, String) {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        (kp.public_key, kp.private_key)
    }

    fn fixture_hash() -> [u8; BINARY_SHA256_LEN] {
        [0xAB; BINARY_SHA256_LEN]
    }

    fn fixture_urls() -> Vec<String> {
        vec![
            "https://cdn1.example/veil-1.2.3-linux-x86_64".to_owned(),
            "https://cdn2.example/veil-1.2.3-linux-x86_64".to_owned(),
            "https://veil.s3.amazonaws.com/1.2.3/linux-x86_64".to_owned(),
        ]
    }

    fn build_fixture(release_unix: u64, version: &str) -> (Vec<u8>, String) {
        let (pk, sk) = fresh_issuer();
        let bytes = sign_manifest(
            release_unix,
            version,
            "1.0.0",
            "linux-x86_64",
            fixture_hash(),
            fixture_urls(),
            &pk,
            &sk,
            SignatureAlgorithm::Ed25519,
        )
        .expect("sign");
        (bytes, pk)
    }

    #[test]
    fn epic484_3_sign_decode_verify_round_trip() {
        let (bytes, issuer_pk) = build_fixture(1_700_000_000, "1.2.3");
        let m = decode_manifest(&bytes).expect("decode");
        verify_manifest(&m, Some(&issuer_pk), None, None).expect("verify");
        assert_eq!(m.release_unix, 1_700_000_000);
        assert_eq!(m.version, "1.2.3");
        assert_eq!(m.min_compatible_version, "1.0.0");
        assert_eq!(m.platform_target, "linux-x86_64");
        assert_eq!(m.binary_sha256, fixture_hash());
        assert_eq!(m.binary_urls.len(), 3);
        assert_eq!(m.issuer_pk, issuer_pk);
    }

    #[test]
    fn epic484_3_anti_downgrade_rejects_older_release() {
        let (bytes, issuer_pk) = build_fixture(1_700_000_000, "1.2.3");
        let m = decode_manifest(&bytes).unwrap();
        // Installed is NEWER (Friday) than manifest (Thursday) → reject.
        let err = verify_manifest(&m, Some(&issuer_pk), Some(1_700_086_400), None).unwrap_err();
        assert!(
            matches!(err, ManifestError::Downgrade { .. }),
            "older manifest must be rejected as downgrade: {err:?}"
        );
    }

    #[test]
    fn epic484_3_anti_downgrade_accepts_newer_release() {
        let (bytes, issuer_pk) = build_fixture(1_700_086_400, "1.2.4");
        let m = decode_manifest(&bytes).unwrap();
        verify_manifest(&m, Some(&issuer_pk), Some(1_700_000_000), None)
            .expect("newer manifest must pass");
    }

    #[test]
    fn epic484_3_anti_downgrade_rejects_equal_release() {
        // Same timestamp = no upgrade signal = reject (forces operators
        // to actually advance release_unix on every push).
        let (bytes, issuer_pk) = build_fixture(1_700_000_000, "1.2.3");
        let m = decode_manifest(&bytes).unwrap();
        let err = verify_manifest(&m, Some(&issuer_pk), Some(1_700_000_000), None).unwrap_err();
        assert!(matches!(err, ManifestError::Downgrade { .. }));
    }

    #[test]
    fn epic484_3_wrong_expected_issuer_rejected() {
        let (bytes, _) = build_fixture(1_700_000_000, "1.2.3");
        let (other_pk, _) = fresh_issuer();
        let m = decode_manifest(&bytes).unwrap();
        let err = verify_manifest(&m, Some(&other_pk), None, None).unwrap_err();
        assert!(
            matches!(err, ManifestError::IssuerMismatch { .. }),
            "wrong expected issuer must be rejected: {err:?}"
        );
    }

    #[test]
    fn epic484_3_tampered_binary_sha256_fails_verify() {
        // The most security-critical tamper: attacker swaps the hash
        // → could redirect to malicious binary при ostalisya legitimate
        // signature. Must fail.
        let (bytes, issuer_pk) = build_fixture(1_700_000_000, "1.2.3");
        let mut m = decode_manifest(&bytes).unwrap();
        m.binary_sha256[0] ^= 0x01;
        let err = verify_manifest(&m, Some(&issuer_pk), None, None).unwrap_err();
        assert_eq!(
            err,
            ManifestError::Verify,
            "tampered binary_sha256 must fail signature: {err:?}"
        );
    }

    #[test]
    fn epic484_3_tampered_binary_url_fails_verify() {
        // Attacker adds malicious URL to the list → would let attacker
        // serve binary that matches sha256 (if attacker has bin) but
        // through their own URL. Signature covers URLs so this fails.
        let (bytes, issuer_pk) = build_fixture(1_700_000_000, "1.2.3");
        let mut m = decode_manifest(&bytes).unwrap();
        m.binary_urls
            .push("https://attacker.example/evil-binary".to_owned());
        let err = verify_manifest(&m, Some(&issuer_pk), None, None).unwrap_err();
        assert_eq!(err, ManifestError::Verify);
    }

    #[test]
    fn epic484_3_tampered_release_unix_fails_verify() {
        // Forward-dating release_unix bypasses anti-downgrade. Must
        // fail signature regardless.
        let (bytes, issuer_pk) = build_fixture(1_700_000_000, "1.2.3");
        let mut m = decode_manifest(&bytes).unwrap();
        m.release_unix = 1_800_000_000;
        let err = verify_manifest(&m, Some(&issuer_pk), None, None).unwrap_err();
        assert_eq!(err, ManifestError::Verify);
    }

    #[test]
    fn epic484_3_tampered_version_fails_verify() {
        let (bytes, issuer_pk) = build_fixture(1_700_000_000, "1.2.3");
        let mut m = decode_manifest(&bytes).unwrap();
        m.version = "9.9.9".to_owned();
        let err = verify_manifest(&m, Some(&issuer_pk), None, None).unwrap_err();
        assert_eq!(err, ManifestError::Verify);
    }

    #[test]
    fn epic484_3_tampered_signature_fails_verify() {
        let (bytes, issuer_pk) = build_fixture(1_700_000_000, "1.2.3");
        let mut m = decode_manifest(&bytes).unwrap();
        m.signature[0] ^= 0x01;
        let err = verify_manifest(&m, Some(&issuer_pk), None, None).unwrap_err();
        assert_eq!(err, ManifestError::Verify);
    }

    #[test]
    fn phase645_h10_future_skew_rejected() {
        // Manifest dated 2 days in the future relative to now.
        let now = 1_700_000_000u64;
        let future = now + 2 * 86_400;
        let (bytes, issuer_pk) = build_fixture(future, "1.2.3");
        let m = decode_manifest(&bytes).unwrap();
        let err = verify_manifest(&m, Some(&issuer_pk), None, Some(now)).unwrap_err();
        assert!(
            matches!(err, ManifestError::FutureSkew { .. }),
            "future-dated manifest must trip clock-skew gate: {err:?}"
        );
    }

    #[test]
    fn phase645_h10_within_skew_accepted() {
        // Manifest dated 12 hours in the future — within the 1-day window.
        let now = 1_700_000_000u64;
        let future = now + 12 * 3600;
        let (bytes, issuer_pk) = build_fixture(future, "1.2.3");
        let m = decode_manifest(&bytes).unwrap();
        verify_manifest(&m, Some(&issuer_pk), None, Some(now))
            .expect("near-future manifest within skew tolerance must pass");
    }

    #[test]
    fn phase645_h10_stale_manifest_rejected() {
        // Manifest dated 100 days in the past — beyond MAX_MANIFEST_AGE_SECS.
        let now = 1_700_000_000u64 + 100 * 86_400;
        let (bytes, issuer_pk) = build_fixture(1_700_000_000, "1.2.3");
        let m = decode_manifest(&bytes).unwrap();
        let err = verify_manifest(&m, Some(&issuer_pk), None, Some(now)).unwrap_err();
        assert!(
            matches!(err, ManifestError::Stale { .. }),
            "stale manifest must trip age gate: {err:?}"
        );
    }

    #[test]
    fn phase645_h10_within_age_accepted() {
        // Manifest dated 30 days in the past — within the 90-day age window.
        let now = 1_700_000_000u64 + 30 * 86_400;
        let (bytes, issuer_pk) = build_fixture(1_700_000_000, "1.2.3");
        let m = decode_manifest(&bytes).unwrap();
        verify_manifest(&m, Some(&issuer_pk), None, Some(now))
            .expect("manifest within MAX_MANIFEST_AGE_SECS must pass");
    }

    #[test]
    fn epic484_3_zero_urls_rejected_at_sign() {
        let (pk, sk) = fresh_issuer();
        let err = sign_manifest(
            1_700_000_000,
            "1.2.3",
            "1.0.0",
            "linux-x86_64",
            fixture_hash(),
            vec![],
            &pk,
            &sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap_err();
        assert!(
            matches!(err, ManifestError::BadUrlCount { got: 0 }),
            "zero URLs must reject — would defeat multi-endpoint anti-takedown: {err:?}"
        );
    }

    #[test]
    fn epic484_3_too_many_urls_rejected_at_sign() {
        let (pk, sk) = fresh_issuer();
        let urls: Vec<String> = (0..MAX_BINARY_URLS + 1)
            .map(|i| format!("https://cdn{i}.example/binary"))
            .collect();
        let err = sign_manifest(
            1_700_000_000,
            "1.2.3",
            "1.0.0",
            "linux-x86_64",
            fixture_hash(),
            urls,
            &pk,
            &sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap_err();
        assert!(matches!(err, ManifestError::BadUrlCount { .. }));
    }

    #[test]
    fn epic484_3_oversized_version_rejected_at_sign() {
        let (pk, sk) = fresh_issuer();
        let huge = "1".repeat(MAX_VERSION_STR_LEN + 1);
        let err = sign_manifest(
            1_700_000_000,
            &huge,
            "1.0.0",
            "linux-x86_64",
            fixture_hash(),
            fixture_urls(),
            &pk,
            &sk,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ManifestError::FieldTooLong {
                    field: "version",
                    ..
                }
            ),
            "oversized version string must reject: {err:?}"
        );
    }

    #[test]
    fn epic484_3_bad_magic_rejected_at_decode() {
        let bytes = vec![b'X', b'X', 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = decode_manifest(&bytes).unwrap_err();
        assert!(matches!(err, ManifestError::Malformed(_)));
    }

    #[test]
    fn epic484_3_unsupported_version_byte_rejected() {
        let (mut bytes, _) = build_fixture(1_700_000_000, "1.2.3");
        bytes[2] = 99;
        let err = decode_manifest(&bytes).unwrap_err();
        assert!(matches!(err, ManifestError::Malformed(_)));
    }

    #[test]
    fn epic484_3_truncated_blob_rejected() {
        let (bytes, _) = build_fixture(1_700_000_000, "1.2.3");
        let truncated = &bytes[..bytes.len() / 2];
        let err = decode_manifest(truncated).unwrap_err();
        assert!(matches!(err, ManifestError::Malformed(_)));
    }

    #[test]
    fn epic484_3_oversized_blob_rejected_pre_decode() {
        let bogus = vec![0u8; MAX_MANIFEST_BYTES + 1];
        let err = decode_manifest(&bogus).unwrap_err();
        assert!(matches!(err, ManifestError::TooLarge { .. }));
    }

    #[test]
    fn epic484_3_typical_manifest_well_under_8kib_cap() {
        let (bytes, _) = build_fixture(1_700_000_000, "1.2.3");
        // Ed25519 manifest with 3 URLs ≈ ~600 B. Well under 8 KiB.
        assert!(
            bytes.len() < 1024,
            "Ed25519 manifest with 3 URLs ballooned to {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn epic484_3_canonical_message_includes_domain_separator() {
        let m = canonical_message(1, "1.0", "0.9", "linux", &[0; 32], &["x".to_owned()]);
        assert!(
            m.starts_with(SIG_DOMAIN),
            "canonical message must start with domain prefix"
        );
    }

    /// End-to-end: install scenario. Sign manifest A (release 1000)
    /// verify accepted on fresh install (no installed_release_unix).
    /// Sign manifest B (release 2000), verify accepted as upgrade
    /// from A. Sign manifest C (release 500), verify rejected as
    /// downgrade from B.
    #[test]
    fn epic484_3_install_upgrade_downgrade_chain() {
        let (pk, sk) = fresh_issuer();
        let make = |t: u64, v: &str| {
            sign_manifest(
                t,
                v,
                "1.0.0",
                "linux-x86_64",
                fixture_hash(),
                fixture_urls(),
                &pk,
                &sk,
                SignatureAlgorithm::Ed25519,
            )
            .unwrap()
        };
        // Fresh install accepts A.
        let a = decode_manifest(&make(1000, "1.0.0")).unwrap();
        verify_manifest(&a, Some(&pk), None, None).expect("fresh install A");
        // Upgrade A → B accepted.
        let b = decode_manifest(&make(2000, "1.1.0")).unwrap();
        verify_manifest(&b, Some(&pk), Some(1000), None).expect("upgrade A → B");
        // Captured-old-manifest C rolling back from B rejected.
        let c = decode_manifest(&make(500, "0.9.0")).unwrap();
        let err = verify_manifest(&c, Some(&pk), Some(2000), None).unwrap_err();
        assert!(
            matches!(err, ManifestError::Downgrade { .. }),
            "captured old manifest must NOT roll back: {err:?}"
        );
    }
}
