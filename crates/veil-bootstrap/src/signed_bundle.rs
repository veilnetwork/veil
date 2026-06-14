//! Operator-signed bootstrap bundle.
//!
//! Wraps a JSON-encoded `Vec<BootstrapPeer>` (the same shape used by
//! [`super::seeds::encode_bootstrap_bundle`]) with an Ed25519 / Falcon-512
//! signature from the operator's identity keypair. The bundle is
//! published to the DHT under the well-known
//! [`super::seeds::bootstrap_bundle_dht_key`] slot. Resolvers fetch
//! the bundle, verify the signature against the operator's pinned
//! pubkey, and merge the inner peers into their `[[bootstrap_peers]]`.
//!
//! # Why this matters for censorship resistance
//!
//! Pre the bundle slot was unsigned: anyone could `DhtPut` a
//! malicious peer list at the well-known key. Combined with the
//! K-closest replication policy this gave any attacker with
//! a node_id close to the bundle's keyspace slot a one-shot inject of
//! peers that legitimate fetchers would dial — bootstrapping new
//! devices straight into an attacker-controlled subnet.
//!
//! closes the gap: the operator signs ONCE, every fetcher
//! who has the operator's pubkey (baked into the binary via
//! `--features production-seeds`, or supplied via OOB channel) can
//! verify that the bundle came from the claimed operator and was not
//! substituted in transit / on a hostile DHT replica.
//!
//! # Threat model
//!
//! Defends against:
//! * Sybil close to the bundle's keyspace slot publishes a malicious
//!   bundle and wins last-write on a replica → fetcher's quorum tally
//!   may even pick it, but signature verification fails → reject.
//! * Plain replay of an old bundle (operator rotated seeds, attacker
//!   caches the previous version): the `issued_at_unix` field is
//!   covered by the signature; resolvers reject bundles older than
//!   `MAX_BUNDLE_AGE_SECS`.
//!
//! Does NOT defend against:
//! * Operator's identity_sk compromise (out-of-band attack). Mitigation:
//!   rotate the operator pubkey, ship a binary update.
//! * No anchor on the resolver side (`expected_issuer_pk = None`):
//!   resolver only checks "envelope is internally consistent", same
//!   degraded mode as `verify_signed_invite` — still better than
//!   no signature at all because the bundle bytes can't be tampered
//!   with mid-flight under quorum + sig consistency, but doesn't
//!   detect a wholly-attacker-issued envelope.
//!
//! # Wire format (binary, big-endian)
//!
//! ```text
//! [0..2] magic = "SB" (Signed-Bundle)
//! [2] version = 1
//! [3] issuer_algo u8 (0 = Ed25519, 1 = Falcon-512)
//! [4..6] pk_len u16 BE
//! [..] issuer_pk (base64-as-bytes, same encoding as IdentityConfig.public_key)
//! [..8] issued_at u64 BE
//! [..2] sig_len u16 BE
//! [..] signature (raw bytes)
//! [..4] bundle_len u32 BE
//! [..] bundle_bytes (the JSON encoding produced by encode_bootstrap_bundle)
//! ```
//!
//! # Canonical signed message
//!
//! ```text
//! "veil-signed-bundle:v1\n"
//! + bundle_bytes
//! + "\n"
//! + issued_at_unix.to_string
//! ```
//!
//! Domain prefix prevents cross-protocol signature reuse (an
//! identity_proof or signed-invite signature can't be repurposed as
//! a bundle signature).

use veil_crypto::{sign_message, verify_message};
use veil_types::{BootstrapPeer, SignatureAlgorithm};

use super::seeds::{decode_bootstrap_bundle, encode_bootstrap_bundle};

pub const SIGNED_BUNDLE_MAGIC: &[u8; 2] = b"SB";
const MAGIC: &[u8; 2] = SIGNED_BUNDLE_MAGIC;
const VERSION: u8 = 1;
const SIG_DOMAIN: &[u8] = b"veil-signed-bundle:v1\n";

/// Maximum age (relative to "now") at which a signed bundle is still
/// honoured. 30 days lets a single freshly-published bundle carry
/// devices through a censorship event of typical duration without
/// forcing the operator to keep republishing on a tight cadence;
/// shorter than the validity ceiling on signed invites because
/// bundles describe ground-truth network membership which rotates
/// faster than personal contact graphs.
pub const MAX_BUNDLE_AGE_SECS: u64 = 30 * 24 * 60 * 60;

/// Maximum encoded length of a signed bundle. Sized for the bundle's own
/// payload (peer list + operator pubkey + signature + framing ≤ 2 KiB,
/// Falcon-512 worst case); 6 KiB leaves headroom while still rejecting
/// bundles too large to be a sane single STORE value (well within the
/// `MAX_DHT_VALUE_BYTES = 16 KiB` DHT value limit).
pub const MAX_SIGNED_BUNDLE_BYTES: usize = 6 * 1024;

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum SignedBundleError {
    #[error("encode inner bundle: {0}")]
    InnerEncode(String),
    #[error("decode inner bundle: {0}")]
    InnerDecode(String),
    #[error("sign: {0}")]
    Sign(String),
    #[error("signature verification failed (wrong issuer key, tampered bundle, or bad signature)")]
    Verify,
    #[error("issuer pubkey mismatch: expected {expected}, got {got}")]
    IssuerMismatch { expected: String, got: String },
    #[error("bundle too old: now={now} > issued_at + max_age = {expiry}")]
    Expired { now: u64, expiry: u64 },
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("encoded bundle exceeds {MAX_SIGNED_BUNDLE_BYTES} byte cap")]
    TooLarge,
    #[error("unsupported signature algorithm byte {0}")]
    UnsupportedAlgo(u8),
}

/// Decoded signed-bundle envelope. The inner peer list is exposed
/// only after the envelope is fully parsed; verification is a
/// separate step [`verify_signed_bundle`].
#[derive(Debug, Clone, PartialEq)]
pub struct SignedBootstrapBundle {
    /// JSON-encoded `Vec<BootstrapPeer>` — the canonical bytes the
    /// operator signed over. Decode via
    /// [`super::seeds::decode_bootstrap_bundle`] after verification.
    pub bundle_bytes: Vec<u8>,
    /// Issuer's public key (base64), as in `IdentityConfig.public_key`.
    pub issuer_pk: String,
    pub issuer_algo: SignatureAlgorithm,
    pub issued_at_unix: u64,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

/// Sign a list of bootstrap peers with the operator's identity keypair
/// and produce the wire envelope ready for `dht_publish_replicated`.
pub fn sign_bundle(
    peers: &[BootstrapPeer],
    issuer_pk: &str,
    issuer_sk: &str,
    issuer_algo: SignatureAlgorithm,
    issued_at_unix: u64,
) -> Result<Vec<u8>, SignedBundleError> {
    let bundle_bytes = encode_bootstrap_bundle(peers).map_err(SignedBundleError::InnerEncode)?;
    let canonical = canonical_message(&bundle_bytes, issued_at_unix);
    let signature = sign_message(issuer_algo, issuer_pk, issuer_sk, &canonical)
        .map_err(|e| SignedBundleError::Sign(format!("{e}")))?;
    let body = encode_body(
        issuer_algo,
        issuer_pk.as_bytes(),
        issued_at_unix,
        &signature,
        &bundle_bytes,
    )?;
    if body.len() > MAX_SIGNED_BUNDLE_BYTES {
        return Err(SignedBundleError::TooLarge);
    }
    Ok(body)
}

/// Decode an envelope WITHOUT verifying — useful for diagnostic
/// commands that surface the issuer pubkey before deciding whether
/// to trust it. Resolvers MUST call [`verify_signed_bundle`] before
/// merging the inner peers into their config.
pub fn decode_signed_bundle(buf: &[u8]) -> Result<SignedBootstrapBundle, SignedBundleError> {
    if buf.len() > MAX_SIGNED_BUNDLE_BYTES {
        return Err(SignedBundleError::TooLarge);
    }
    let (issuer_algo, issuer_pk_bytes, issued_at_unix, signature, bundle_bytes) = decode_body(buf)?;
    let issuer_pk = std::str::from_utf8(issuer_pk_bytes)
        .map_err(|e| SignedBundleError::Malformed(format!("issuer_pk utf8: {e}")))?
        .to_owned();
    Ok(SignedBootstrapBundle {
        bundle_bytes: bundle_bytes.to_vec(),
        issuer_pk,
        issuer_algo,
        issued_at_unix,
        signature: signature.to_vec(),
    })
}

/// Verify the envelope and return the inner peer list.
///
/// `expected_issuer_pk` pins the trust anchor — when `Some(pk)` the
/// envelope's claimed issuer must match `pk` exactly. This is the
/// only mode that catches "attacker forges a bundle under a key the
/// resolver doesn't trust". `None` validates the envelope is
/// internally consistent (bytes haven't been tampered mid-flight)
/// but provides NO trust signal — caller MUST still chain with
/// their own out-of-band check or compare to a baked-in pubkey
/// constant before acting on the result.
pub fn verify_signed_bundle(
    b: &SignedBootstrapBundle,
    expected_issuer_pk: Option<&str>,
    now_unix: u64,
) -> Result<Vec<BootstrapPeer>, SignedBundleError> {
    let expiry = b.issued_at_unix.saturating_add(MAX_BUNDLE_AGE_SECS);
    if now_unix > expiry {
        return Err(SignedBundleError::Expired {
            now: now_unix,
            expiry,
        });
    }
    if let Some(expected) = expected_issuer_pk
        && expected != b.issuer_pk
    {
        return Err(SignedBundleError::IssuerMismatch {
            expected: expected.to_owned(),
            got: b.issuer_pk.clone(),
        });
    }
    let canonical = canonical_message(&b.bundle_bytes, b.issued_at_unix);
    verify_message(b.issuer_algo, &b.issuer_pk, &canonical, &b.signature)
        .map_err(|_| SignedBundleError::Verify)?;
    decode_bootstrap_bundle(&b.bundle_bytes).map_err(SignedBundleError::InnerDecode)
}

fn canonical_message(bundle_bytes: &[u8], issued_at_unix: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIG_DOMAIN.len() + bundle_bytes.len() + 32);
    out.extend_from_slice(SIG_DOMAIN);
    out.extend_from_slice(bundle_bytes);
    out.push(b'\n');
    out.extend_from_slice(issued_at_unix.to_string().as_bytes());
    out
}

fn encode_body(
    issuer_algo: SignatureAlgorithm,
    issuer_pk: &[u8],
    issued_at_unix: u64,
    signature: &[u8],
    bundle_bytes: &[u8],
) -> Result<Vec<u8>, SignedBundleError> {
    if issuer_pk.len() > u16::MAX as usize {
        return Err(SignedBundleError::Malformed("issuer_pk too long".into()));
    }
    if signature.len() > u16::MAX as usize {
        return Err(SignedBundleError::Malformed("signature too long".into()));
    }
    if bundle_bytes.len() > u32::MAX as usize {
        return Err(SignedBundleError::Malformed("bundle too long".into()));
    }
    let mut out = Vec::with_capacity(
        2 + 1 + 1 + 2 + issuer_pk.len() + 8 + 2 + signature.len() + 4 + bundle_bytes.len(),
    );
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(algo_to_u8(issuer_algo));
    out.extend_from_slice(&(issuer_pk.len() as u16).to_be_bytes());
    out.extend_from_slice(issuer_pk);
    out.extend_from_slice(&issued_at_unix.to_be_bytes());
    out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    out.extend_from_slice(signature);
    out.extend_from_slice(&(bundle_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bundle_bytes);
    Ok(out)
}

type DecodedBody<'a> = (SignatureAlgorithm, &'a [u8], u64, &'a [u8], &'a [u8]);

fn decode_body(buf: &[u8]) -> Result<DecodedBody<'_>, SignedBundleError> {
    let mut p = 0usize;
    let magic = read(buf, &mut p, 2)?;
    if magic != MAGIC {
        return Err(SignedBundleError::Malformed(format!(
            "bad magic: {magic:?}"
        )));
    }
    let version = read(buf, &mut p, 1)?[0];
    if version != VERSION {
        return Err(SignedBundleError::Malformed(format!(
            "unsupported version {version}",
        )));
    }
    let algo_byte = read(buf, &mut p, 1)?[0];
    let issuer_algo = algo_from_u8(algo_byte)?;
    // replaced `try_into.unwrap` cluster with
    // `read_u*_be` helpers — same wire format, no `.unwrap`.
    let pk_len = read_u16_be(buf, &mut p)? as usize;
    let issuer_pk = read(buf, &mut p, pk_len)?;
    let issued_at_unix = read_u64_be(buf, &mut p)?;
    let sig_len = read_u16_be(buf, &mut p)? as usize;
    let signature = read(buf, &mut p, sig_len)?;
    let bundle_len = read_u32_be(buf, &mut p)? as usize;
    let bundle_bytes = read(buf, &mut p, bundle_len)?;
    if p != buf.len() {
        return Err(SignedBundleError::Malformed(format!(
            "{} trailing byte(s)",
            buf.len() - p,
        )));
    }
    Ok((
        issuer_algo,
        issuer_pk,
        issued_at_unix,
        signature,
        bundle_bytes,
    ))
}

fn read<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], SignedBundleError> {
    let end = pos
        .checked_add(n)
        .ok_or_else(|| SignedBundleError::Malformed(format!("read overflow at offset {pos}")))?;
    if end > buf.len() {
        return Err(SignedBundleError::Malformed(format!(
            "short read: needed {n} bytes at offset {pos}, buf has {}",
            buf.len(),
        )));
    }
    let slice = &buf[*pos..end];
    *pos = end;
    Ok(slice)
}

// replace `.expect(...)` panic
// primitives in the parser path with explicit error returns. The
// invariants ARE upheld by `read(...)` returning exactly N bytes
// but a future refactor of `read` could break them — and panicking
// during attacker-controlled bundle decode is worse than returning a
// `Malformed(...)` that the caller can log and skip.
fn read_u16_be(buf: &[u8], pos: &mut usize) -> Result<u16, SignedBundleError> {
    let s = read(buf, pos, 2)?;
    let arr: [u8; 2] = s
        .try_into()
        .map_err(|_| SignedBundleError::Malformed("read_u16_be: slice not 2 bytes".to_string()))?;
    Ok(u16::from_be_bytes(arr))
}

fn read_u32_be(buf: &[u8], pos: &mut usize) -> Result<u32, SignedBundleError> {
    let s = read(buf, pos, 4)?;
    let arr: [u8; 4] = s
        .try_into()
        .map_err(|_| SignedBundleError::Malformed("read_u32_be: slice not 4 bytes".to_string()))?;
    Ok(u32::from_be_bytes(arr))
}

fn read_u64_be(buf: &[u8], pos: &mut usize) -> Result<u64, SignedBundleError> {
    let s = read(buf, pos, 8)?;
    let arr: [u8; 8] = s
        .try_into()
        .map_err(|_| SignedBundleError::Malformed("read_u64_be: slice not 8 bytes".to_string()))?;
    Ok(u64::from_be_bytes(arr))
}

fn algo_to_u8(algo: SignatureAlgorithm) -> u8 {
    match algo {
        SignatureAlgorithm::Ed25519 => 0,
        SignatureAlgorithm::Falcon512 => 1,
        SignatureAlgorithm::Ed25519Falcon512Hybrid => 2,
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => 3,
    }
}

fn algo_from_u8(byte: u8) -> Result<SignatureAlgorithm, SignedBundleError> {
    match byte {
        0 => Ok(SignatureAlgorithm::Ed25519),
        1 => Ok(SignatureAlgorithm::Falcon512),
        2 => Ok(SignatureAlgorithm::Ed25519Falcon512Hybrid),
        3 => Ok(SignatureAlgorithm::Ed25519Falcon1024Hybrid),
        b => Err(SignedBundleError::UnsupportedAlgo(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_crypto::generate_keypair;

    fn sample_peers() -> Vec<BootstrapPeer> {
        vec![BootstrapPeer {
            transport: "tls://b1.example:9906".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            nonce: "AAAAAA==".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        }]
    }

    fn fresh_keypair() -> (String, String) {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        (kp.public_key, kp.private_key)
    }

    #[test]
    fn sign_then_verify_roundtrip_with_pinned_issuer() {
        let (pk, sk) = fresh_keypair();
        let peers = sample_peers();
        let now = 1_700_000_000u64;
        let signed = sign_bundle(&peers, &pk, &sk, SignatureAlgorithm::Ed25519, now).unwrap();
        let decoded = decode_signed_bundle(&signed).unwrap();
        assert_eq!(decoded.issuer_pk, pk);
        let verified = verify_signed_bundle(&decoded, Some(&pk), now + 60).unwrap();
        assert_eq!(verified, peers);
    }

    #[test]
    fn verify_without_anchor_still_works_when_envelope_consistent() {
        let (pk, sk) = fresh_keypair();
        let peers = sample_peers();
        let signed = sign_bundle(&peers, &pk, &sk, SignatureAlgorithm::Ed25519, 0).unwrap();
        let decoded = decode_signed_bundle(&signed).unwrap();
        // expected_issuer_pk = None: only checks internal consistency.
        verify_signed_bundle(&decoded, None, 1_000).unwrap();
    }

    #[test]
    fn verify_rejects_pubkey_mismatch_when_pinned() {
        let (pk_a, sk_a) = fresh_keypair();
        let (pk_b, _sk_b) = fresh_keypair();
        let signed = sign_bundle(
            &sample_peers(),
            &pk_a,
            &sk_a,
            SignatureAlgorithm::Ed25519,
            0,
        )
        .unwrap();
        let decoded = decode_signed_bundle(&signed).unwrap();
        let err = verify_signed_bundle(&decoded, Some(&pk_b), 1_000).unwrap_err();
        assert!(matches!(err, SignedBundleError::IssuerMismatch { .. }));
    }

    #[test]
    fn verify_rejects_tampered_bundle_bytes() {
        let (pk, sk) = fresh_keypair();
        let signed =
            sign_bundle(&sample_peers(), &pk, &sk, SignatureAlgorithm::Ed25519, 0).unwrap();
        // Flip one byte in the bundle payload (last byte = inside bundle_bytes).
        let mut tampered = signed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let decoded = decode_signed_bundle(&tampered).unwrap();
        let err = verify_signed_bundle(&decoded, Some(&pk), 1_000).unwrap_err();
        assert!(matches!(err, SignedBundleError::Verify));
    }

    #[test]
    fn verify_rejects_replay_after_max_age() {
        let (pk, sk) = fresh_keypair();
        let signed = sign_bundle(
            &sample_peers(),
            &pk,
            &sk,
            SignatureAlgorithm::Ed25519,
            1_000,
        )
        .unwrap();
        let decoded = decode_signed_bundle(&signed).unwrap();
        let now = 1_000 + MAX_BUNDLE_AGE_SECS + 1;
        let err = verify_signed_bundle(&decoded, Some(&pk), now).unwrap_err();
        assert!(matches!(err, SignedBundleError::Expired { .. }));
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut garbage = vec![b'X', b'X', 1, 0];
        garbage.extend_from_slice(&[0u8; 32]);
        let err = decode_signed_bundle(&garbage).unwrap_err();
        assert!(matches!(err, SignedBundleError::Malformed(_)));
    }
}
