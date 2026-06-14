//! Issuer-signed bootstrap invite.
//!
//! Wraps an existing [`super::invite`] URL with an Ed25519 / Falcon-512
//! signature from the issuer's identity keypair. The recipient verifies
//! the signature against the issuer's known public key (provided
//! out-of-band: business card, profile bio, prior friendship) before
//! adding the inner peer to their config.
//!
//! # Why this matters for censorship resistance
//!
//! (`encrypted_invite`) protects the URL channel with a
//! shared password — strong against passive observers, but every new
//! recipient needs the password through a separate trusted channel.
//! That doesn't scale beyond a few personal contacts.
//!
//! (`signed_invite`) is the complementary defense:
//! the issuer signs ONCE, posts the URL on a public channel, and any
//! recipient who already has the issuer's pubkey can verify the URL
//! came from the claimed person and wasn't substituted by a censor MITM.
//! No shared secret needed; the issuer's pubkey IS the trust anchor.
//!
//! Combined with 481.2 you get both: `sign(encrypt(invite, password)
//! issuer_sk)` — one URL that's both attested AND privately distributed.
//!
//! # Threat model
//!
//! Defends against:
//! * Censor MITMs the URL channel (forum, paste, DNS) and substitutes
//!   a malicious URL pointing at an attacker-controlled bootstrap node.
//! * Random publication of unsigned invites being mistaken for the
//!   real operator's invite.
//!
//! Does NOT defend against:
//! * Recipient lacking the issuer's pubkey out-of-band — the signature
//!   verifies nothing if the verifier has no anchor.
//! * Replay within the validity window — the signed envelope is
//!   self-contained and can be re-redeemed by anyone who saw it. An
//!   issuer who needs strict one-shot semantics must keep the validity
//!   window short and rotate their `[identity]` keypair after redemption.
//! * Compromise of the issuer's private key (out-of-band attack).
//!
//! # Wire format (binary, big-endian, then base64url)
//!
//! ```text
//! [0..2] magic = "SI" (Signed-Invite)
//! [2] version = 1
//! [3] issuer_algo u8 (0 = Ed25519, 1 = Falcon-512 — matches `SignatureAlgorithm`)
//! [4..6] issuer_pk_len u16 BE
//! [..] issuer_pk (base64-as-bytes; same encoding as `IdentityConfig.public_key`)
//! [..] issued_at_unix u64 BE
//! [..] expiry_unix u64 BE
//! [..] sig_len u16 BE
//! [..] signature (raw bytes, length matches algo)
//! [..] inner_uri_len u16 BE
//! [..] inner_uri (the canonical `veil:bootstrap?…` URL bytes)
//! ```
//!
//! Then wrapped as `veil:signed-invite?b=<base64url-no-pad>`.
//!
//! # Canonical signed message
//!
//! The issuer signs over a domain-separated, version-tagged message:
//!
//! ```text
//! "veil-signed-invite:v1\n"
//! + inner_uri + "\n"
//! + issued_at_unix.to_string + "\n"
//! + expiry_unix.to_string
//! ```
//!
//! Domain prefix prevents cross-protocol signature reuse (e.g. an
//! identity_proof signature from elsewhere can't be repurposed as a
//! bootstrap-invite signature). Including both `issued_at` and
//! `expiry` in the signed payload pins the validity window: an
//! attacker who captures a signed invite cannot extend its lifetime.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use veil_crypto::{sign_message, verify_message};
use veil_types::{BootstrapPeer, SignatureAlgorithm};

use super::invite::{self, BootstrapUriError, MAX_BOOTSTRAP_URI_BYTES};

pub const SIGNED_INVITE_SCHEME: &str = "veil:signed-invite?";
const MAGIC: &[u8; 2] = b"SI";
const VERSION: u8 = 1;

/// Maximum URL byte length. Plaintext inner URI ≤
/// [`MAX_BOOTSTRAP_URI_BYTES`] (= 4 KiB), plus issuer pubkey
/// (Falcon-512 ≈ 1 KiB base64), plus signature (Falcon-512 ≈ 900 B
/// raw), plus base64 expansion ≈ 4/3. 8 KiB cap leaves headroom.
pub const MAX_SIGNED_INVITE_BYTES: usize = 8 * 1024;

/// Domain-separation prefix for the canonical signed message. Bumping
/// `:v1` to `:v2` would invalidate every signed invite ever issued —
/// only do this for a security-relevant format change.
const SIG_DOMAIN: &[u8] = b"veil-signed-invite:v1\n";

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SignedInviteError {
    #[error("encode inner invite: {0}")]
    InnerEncode(BootstrapUriError),
    #[error("decode inner invite: {0}")]
    InnerDecode(BootstrapUriError),
    #[error("sign: {0}")]
    Sign(String),
    #[error("signature verification failed (wrong issuer key, tampered URL, or bad signature)")]
    Verify,
    #[error("issuer pubkey mismatch: expected {expected}, got {got}")]
    IssuerMismatch { expected: String, got: String },
    #[error("expired (now={now} > expiry={expiry})")]
    Expired { now: u64, expiry: u64 },
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("scheme: expected `{SIGNED_INVITE_SCHEME}…`")]
    BadScheme,
    #[error("base64: {0}")]
    Base64(String),
    #[error("URL exceeds {MAX_SIGNED_INVITE_BYTES} byte cap")]
    TooLarge,
    #[error("issued_at_unix > expiry_unix (clock skew or tampered envelope)")]
    InvertedWindow,
    #[error("validity window exceeds 1 year — likely operator typo or attack")]
    ValidityTooLong,
}

/// Maximum allowed validity window. An invite signed today and valid
/// for years is almost certainly a typo (operator meant `--expiry-secs
/// 10` and got "10 secs"…) or an attacker trying to stretch a captured
/// invite.
///
/// lowered from 1 year to 7 days. A signed
/// invite is a transferable bearer credential — anyone holding a
/// captured copy can re-bootstrap into the network as the named peer
/// for the entire validity window. A 1-year window meant a single
/// leaked invite was weapons-grade for ~12 months; 7 days bounds the
/// blast radius and matches typical operator-rotation cadences.
/// Operators who genuinely need longer-lived invites should issue a
/// fresh one weekly via their existing CI/CD pipeline.
const MAX_VALIDITY_SECS: u64 = 7 * 24 * 60 * 60;

/// Decoded signed-invite envelope, as returned by [`decode_signed_invite`].
/// The inner [`BootstrapPeer`] is exposed only after the envelope is
/// fully parsed — verification is a separate step via
/// [`verify_signed_invite`].
#[derive(Debug, Clone, PartialEq)]
pub struct SignedInvite {
    /// Inner peer to be added to `[[bootstrap_peers]]` once verified.
    pub peer: BootstrapPeer,
    /// Issuer's public key (base64), as it appears in their
    /// `IdentityConfig.public_key`.
    pub issuer_pk: String,
    /// Issuer's signature algorithm (must match the algo of `issuer_pk`).
    pub issuer_algo: SignatureAlgorithm,
    /// When the issuer signed the envelope (Unix seconds).
    pub issued_at_unix: u64,
    /// When the envelope stops being honoured (Unix seconds).
    pub expiry_unix: u64,
    /// Raw signature bytes (Ed25519 = 64 B, Falcon-512 ≈ 660 B).
    /// Kept on the struct so callers can pass it back through
    /// [`verify_signed_invite`] without re-decoding.
    pub signature: Vec<u8>,
    /// Original inner URI bytes — exposed because the canonical
    /// signed message includes them, and a verifier needs the EXACT
    /// bytes that were signed (not a re-serialised round-trip).
    pub inner_uri: String,
}

/// Sign a [`BootstrapPeer`] with the issuer's identity keypair and
/// produce an `veil:signed-invite?b=<base64>` URL.
///
/// `issuer_pk` and `issuer_sk` are base64-encoded as in
/// [`crate::cfg::IdentityConfig`]. `validity_secs` is capped at 1
/// year ([`MAX_VALIDITY_SECS`]).
pub fn sign_invite(
    peer: &BootstrapPeer,
    issuer_pk: &str,
    issuer_sk: &str,
    issuer_algo: SignatureAlgorithm,
    issued_at_unix: u64,
    validity_secs: u64,
) -> Result<String, SignedInviteError> {
    if validity_secs > MAX_VALIDITY_SECS {
        return Err(SignedInviteError::ValidityTooLong);
    }
    let expiry_unix = issued_at_unix.saturating_add(validity_secs);
    let inner_uri = invite::encode_uri(peer).map_err(SignedInviteError::InnerEncode)?;

    let canonical = canonical_message(&inner_uri, issued_at_unix, expiry_unix);
    let signature = sign_message(issuer_algo, issuer_pk, issuer_sk, &canonical)
        .map_err(|e| SignedInviteError::Sign(format!("{e}")))?;

    let body = encode_body(
        issuer_algo,
        issuer_pk.as_bytes(),
        issued_at_unix,
        expiry_unix,
        &signature,
        inner_uri.as_bytes(),
    )?;
    let b64 = URL_SAFE_NO_PAD.encode(body);
    let url = format!("{SIGNED_INVITE_SCHEME}b={b64}");
    if url.len() > MAX_SIGNED_INVITE_BYTES {
        return Err(SignedInviteError::TooLarge);
    }
    Ok(url)
}

/// Decode the envelope WITHOUT verifying the signature — useful for
/// `bootstrap decode --uri …` preflight where the operator wants to
/// see the issuer pubkey before deciding whether to trust it. Verifier
/// MUST call [`verify_signed_invite`] before adding the inner peer to
/// config.
pub fn decode_signed_invite(url: &str) -> Result<SignedInvite, SignedInviteError> {
    if url.len() > MAX_SIGNED_INVITE_BYTES {
        return Err(SignedInviteError::TooLarge);
    }
    let body_b64 = url
        .strip_prefix(SIGNED_INVITE_SCHEME)
        .and_then(|s| s.strip_prefix("b="))
        .ok_or(SignedInviteError::BadScheme)?;
    let body = URL_SAFE_NO_PAD
        .decode(body_b64.as_bytes())
        .map_err(|e| SignedInviteError::Base64(e.to_string()))?;

    let (issuer_algo, issuer_pk_bytes, issued_at_unix, expiry_unix, signature, inner_uri_bytes) =
        decode_body(&body)?;
    if issued_at_unix > expiry_unix {
        return Err(SignedInviteError::InvertedWindow);
    }
    if expiry_unix.saturating_sub(issued_at_unix) > MAX_VALIDITY_SECS {
        return Err(SignedInviteError::ValidityTooLong);
    }
    let inner_uri = std::str::from_utf8(inner_uri_bytes)
        .map_err(|e| SignedInviteError::Malformed(format!("inner_uri utf8: {e}")))?
        .to_owned();
    if inner_uri.len() > MAX_BOOTSTRAP_URI_BYTES {
        return Err(SignedInviteError::Malformed(format!(
            "inner_uri exceeds {MAX_BOOTSTRAP_URI_BYTES} byte cap",
        )));
    }
    let peer = invite::decode_uri(&inner_uri).map_err(SignedInviteError::InnerDecode)?;
    let issuer_pk = std::str::from_utf8(issuer_pk_bytes)
        .map_err(|e| SignedInviteError::Malformed(format!("issuer_pk utf8: {e}")))?
        .to_owned();

    Ok(SignedInvite {
        peer,
        issuer_pk,
        issuer_algo,
        issued_at_unix,
        expiry_unix,
        signature: signature.to_vec(),
        inner_uri,
    })
}

/// Verify the envelope. When `expected_issuer_pk` is `Some`, the
/// envelope's claimed issuer must match — this is the only mode that
/// catches "attacker forges an invite under a key the recipient
/// doesn't trust". `None` validates the signature is internally
/// consistent (envelope's `issuer_pk` did sign over the envelope
/// content) but provides NO trust signal — operator MUST chain this
/// with their own out-of-band check.
pub fn verify_signed_invite(
    invite: &SignedInvite,
    expected_issuer_pk: Option<&str>,
    now_unix: u64,
) -> Result<BootstrapPeer, SignedInviteError> {
    // Expiry is INCLUSIVE: an invite is dead at exactly `expiry_unix`, not one
    // second later. Matches `veil-invite`'s `now_unix >= self.exp` so both
    // invite paths agree on the boundary (audit cycle-8: this used `>`, which
    // accepted an invite during its final expiry second).
    if now_unix >= invite.expiry_unix {
        return Err(SignedInviteError::Expired {
            now: now_unix,
            expiry: invite.expiry_unix,
        });
    }
    if let Some(expected) = expected_issuer_pk
        && expected != invite.issuer_pk
    {
        return Err(SignedInviteError::IssuerMismatch {
            expected: expected.to_owned(),
            got: invite.issuer_pk.clone(),
        });
    }
    let canonical = canonical_message(&invite.inner_uri, invite.issued_at_unix, invite.expiry_unix);
    verify_message(
        invite.issuer_algo,
        &invite.issuer_pk,
        &canonical,
        &invite.signature,
    )
    .map_err(|_| SignedInviteError::Verify)?;
    Ok(invite.peer.clone())
}

fn canonical_message(inner_uri: &str, issued_at_unix: u64, expiry_unix: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIG_DOMAIN.len() + inner_uri.len() + 64);
    out.extend_from_slice(SIG_DOMAIN);
    out.extend_from_slice(inner_uri.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(issued_at_unix.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(expiry_unix.to_string().as_bytes());
    out
}

fn encode_body(
    issuer_algo: SignatureAlgorithm,
    issuer_pk: &[u8],
    issued_at_unix: u64,
    expiry_unix: u64,
    signature: &[u8],
    inner_uri: &[u8],
) -> Result<Vec<u8>, SignedInviteError> {
    if issuer_pk.len() > u16::MAX as usize {
        return Err(SignedInviteError::Malformed("issuer_pk too long".into()));
    }
    if signature.len() > u16::MAX as usize {
        return Err(SignedInviteError::Malformed("signature too long".into()));
    }
    if inner_uri.len() > u16::MAX as usize {
        return Err(SignedInviteError::Malformed("inner_uri too long".into()));
    }
    let mut out = Vec::with_capacity(
        2 + 1 + 1 + 2 + issuer_pk.len() + 8 + 8 + 2 + signature.len() + 2 + inner_uri.len(),
    );
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(algo_to_u8(issuer_algo));
    out.extend_from_slice(&(issuer_pk.len() as u16).to_be_bytes());
    out.extend_from_slice(issuer_pk);
    out.extend_from_slice(&issued_at_unix.to_be_bytes());
    out.extend_from_slice(&expiry_unix.to_be_bytes());
    out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    out.extend_from_slice(signature);
    out.extend_from_slice(&(inner_uri.len() as u16).to_be_bytes());
    out.extend_from_slice(inner_uri);
    Ok(out)
}

/// Decoded signed-invite envelope fields (zero-copy slice references).
/// `(sig_algo, body, issued_at_unix, expires_at_unix, issuer_pk, signature)`.
type DecodedSignedInvite<'a> = (SignatureAlgorithm, &'a [u8], u64, u64, &'a [u8], &'a [u8]);

fn decode_body(buf: &[u8]) -> Result<DecodedSignedInvite<'_>, SignedInviteError> {
    let mut p = 0usize;
    let magic = read(buf, &mut p, 2)?;
    if magic != MAGIC {
        return Err(SignedInviteError::Malformed(format!(
            "bad magic: {magic:?}"
        )));
    }
    let version = read(buf, &mut p, 1)?[0];
    if version != VERSION {
        return Err(SignedInviteError::Malformed(format!(
            "unsupported version {version}",
        )));
    }
    let algo_byte = read(buf, &mut p, 1)?[0];
    let issuer_algo = algo_from_u8(algo_byte)?;
    // previous code used `try_into.unwrap` which is
    // provably infallible (read enforces N bytes), but ugly-looking
    // hygiene + survives less well across refactors. Switched to
    // explicit `read_u16_be` / `read_u64_be` helpers that handle
    // the byte-array conversion internally — same wire format
    // panic-free in the literal sense.
    let pk_len = read_u16_be(buf, &mut p)? as usize;
    let issuer_pk = read(buf, &mut p, pk_len)?;
    let issued_at_unix = read_u64_be(buf, &mut p)?;
    let expiry_unix = read_u64_be(buf, &mut p)?;
    let sig_len = read_u16_be(buf, &mut p)? as usize;
    let signature = read(buf, &mut p, sig_len)?;
    let uri_len = read_u16_be(buf, &mut p)? as usize;
    let inner_uri = read(buf, &mut p, uri_len)?;
    if p != buf.len() {
        return Err(SignedInviteError::Malformed(format!(
            "{} trailing byte(s)",
            buf.len() - p,
        )));
    }
    Ok((
        issuer_algo,
        issuer_pk,
        issued_at_unix,
        expiry_unix,
        signature,
        inner_uri,
    ))
}

fn read<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], SignedInviteError> {
    // defensive overflow check on `*pos + n`. In
    // practice `pos` stays well below `usize::MAX` because `buf`
    // is a decode buffer bounded to the network frame size, but
    // `checked_add` removes the implicit wraparound risk on
    // 32-bit Android targets.
    let end = pos
        .checked_add(n)
        .ok_or_else(|| SignedInviteError::Malformed(format!("read overflow: pos={pos} + n={n}")))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| SignedInviteError::Malformed(format!("truncated {}B at {}", n, *pos)))?;
    *pos = end;
    Ok(slice)
}

fn read_u16_be(buf: &[u8], pos: &mut usize) -> Result<u16, SignedInviteError> {
    let s = read(buf, pos, 2)?;
    // 2-byte slice → [u8; 2] is infallible by construction; we
    // express it via TryInto so the conversion is explicit, and the
    // `.expect` message documents the invariant that survives
    // across refactors.
    Ok(u16::from_be_bytes(
        s.try_into().expect("read returned exactly 2 bytes"),
    ))
}

fn read_u64_be(buf: &[u8], pos: &mut usize) -> Result<u64, SignedInviteError> {
    let s = read(buf, pos, 8)?;
    Ok(u64::from_be_bytes(
        s.try_into().expect("read returned exactly 8 bytes"),
    ))
}

fn algo_to_u8(algo: SignatureAlgorithm) -> u8 {
    match algo {
        SignatureAlgorithm::Ed25519 => 0,
        SignatureAlgorithm::Falcon512 => 1,
        SignatureAlgorithm::Ed25519Falcon512Hybrid => 2,
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => 3,
    }
}

fn algo_from_u8(b: u8) -> Result<SignatureAlgorithm, SignedInviteError> {
    match b {
        0 => Ok(SignatureAlgorithm::Ed25519),
        1 => Ok(SignatureAlgorithm::Falcon512),
        2 => Ok(SignatureAlgorithm::Ed25519Falcon512Hybrid),
        3 => Ok(SignatureAlgorithm::Ed25519Falcon1024Hybrid),
        _ => Err(SignedInviteError::Malformed(format!(
            "unknown algo byte {b}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_crypto::generate_keypair;

    fn sample_peer() -> BootstrapPeer {
        BootstrapPeer {
            transport: "tcp://10.1.2.3:9000".to_owned(),
            public_key: "PEERKEY".to_owned(),
            nonce: "PEERNONCE".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        }
    }

    fn fresh_issuer() -> (String, String) {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        (kp.public_key, kp.private_key)
    }

    const T0: u64 = 1_700_000_000;
    const VALID_FOR_1H: u64 = 3600;

    #[test]
    fn epic481_3_sign_verify_round_trip_returns_inner_peer() {
        let (issuer_pk, issuer_sk) = fresh_issuer();
        let peer = sample_peer();
        let url = sign_invite(
            &peer,
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
            T0,
            VALID_FOR_1H,
        )
        .expect("sign");
        assert!(
            url.starts_with(SIGNED_INVITE_SCHEME),
            "URL must start with `{SIGNED_INVITE_SCHEME}`: {url}"
        );
        let envelope = decode_signed_invite(&url).expect("decode");
        let recovered = verify_signed_invite(&envelope, Some(&issuer_pk), T0 + 1).expect("verify");
        assert_eq!(recovered, peer);
    }

    #[test]
    fn epic481_3_verify_with_no_expected_issuer_still_validates_signature() {
        // None expected_issuer means "envelope is internally consistent
        // but trust is the caller's responsibility". Useful for the
        // `bootstrap decode` preflight.
        let (issuer_pk, issuer_sk) = fresh_issuer();
        let url = sign_invite(
            &sample_peer(),
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
            T0,
            VALID_FOR_1H,
        )
        .unwrap();
        let env = decode_signed_invite(&url).unwrap();
        verify_signed_invite(&env, None, T0 + 1).expect("internal consistency check");
    }

    #[test]
    fn epic481_3_expired_envelope_rejected() {
        let (issuer_pk, issuer_sk) = fresh_issuer();
        let url = sign_invite(
            &sample_peer(),
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
            T0,
            60,
        )
        .unwrap();
        let env = decode_signed_invite(&url).unwrap();
        let err = verify_signed_invite(&env, Some(&issuer_pk), T0 + 61).unwrap_err();
        assert!(
            matches!(err, SignedInviteError::Expired { .. }),
            "expired envelope must be rejected: {err:?}"
        );
        // Audit cycle-8: expiry is INCLUSIVE — at exactly T0+60 (= expiry_unix)
        // the invite is already dead, not valid for one more second.
        let err_exact = verify_signed_invite(&env, Some(&issuer_pk), T0 + 60).unwrap_err();
        assert!(
            matches!(err_exact, SignedInviteError::Expired { .. }),
            "invite at exactly expiry_unix must be rejected: {err_exact:?}"
        );
        // One second before expiry it is still valid.
        assert!(
            verify_signed_invite(&env, Some(&issuer_pk), T0 + 59).is_ok(),
            "invite one second before expiry must still verify"
        );
    }

    #[test]
    fn epic481_3_wrong_expected_issuer_rejected() {
        let (issuer_pk, issuer_sk) = fresh_issuer();
        let (other_pk, _) = fresh_issuer();
        let url = sign_invite(
            &sample_peer(),
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
            T0,
            VALID_FOR_1H,
        )
        .unwrap();
        let env = decode_signed_invite(&url).unwrap();
        let err = verify_signed_invite(&env, Some(&other_pk), T0 + 1).unwrap_err();
        assert!(
            matches!(err, SignedInviteError::IssuerMismatch { .. }),
            "wrong expected issuer must be rejected: {err:?}"
        );
    }

    #[test]
    fn epic481_3_tampered_signature_rejected() {
        let (issuer_pk, issuer_sk) = fresh_issuer();
        let url = sign_invite(
            &sample_peer(),
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
            T0,
            VALID_FOR_1H,
        )
        .unwrap();
        let mut env = decode_signed_invite(&url).unwrap();
        // Flip a bit in the signature.
        env.signature[0] ^= 0x01;
        let err = verify_signed_invite(&env, Some(&issuer_pk), T0 + 1).unwrap_err();
        assert_eq!(
            err,
            SignedInviteError::Verify,
            "tampered signature must be rejected: {err:?}"
        );
    }

    #[test]
    fn epic481_3_tampered_inner_uri_rejected() {
        let (issuer_pk, issuer_sk) = fresh_issuer();
        let url = sign_invite(
            &sample_peer(),
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
            T0,
            VALID_FOR_1H,
        )
        .unwrap();
        let mut env = decode_signed_invite(&url).unwrap();
        // Substitute a different inner URI — verification must fail
        // because the canonical message no longer matches the signature.
        let mut other = sample_peer();
        other.transport = "tcp://attacker.example:9000".to_owned();
        env.inner_uri = invite::encode_uri(&other).unwrap();
        env.peer = other;
        let err = verify_signed_invite(&env, Some(&issuer_pk), T0 + 1).unwrap_err();
        assert_eq!(
            err,
            SignedInviteError::Verify,
            "swapped inner peer must fail signature check: {err:?}"
        );
    }

    #[test]
    fn epic481_3_tampered_validity_window_rejected() {
        // An attacker who captures a signed invite with 60-second
        // expiry tries to extend it by rewriting the expiry field.
        // Because expiry is included in the canonical signed message
        // the signature check fails.
        let (issuer_pk, issuer_sk) = fresh_issuer();
        let url = sign_invite(
            &sample_peer(),
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
            T0,
            60,
        )
        .unwrap();
        let mut env = decode_signed_invite(&url).unwrap();
        env.expiry_unix = T0 + 86400; // attempt to extend by 1 day
        let err = verify_signed_invite(&env, Some(&issuer_pk), T0 + 100).unwrap_err();
        assert_eq!(
            err,
            SignedInviteError::Verify,
            "tampered expiry must fail signature check: {err:?}"
        );
    }

    #[test]
    fn epic481_3_validity_too_long_rejected_at_sign() {
        let (issuer_pk, issuer_sk) = fresh_issuer();
        let err = sign_invite(
            &sample_peer(),
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
            T0,
            MAX_VALIDITY_SECS + 1,
        )
        .unwrap_err();
        assert_eq!(err, SignedInviteError::ValidityTooLong);
    }

    #[test]
    fn epic481_3_inverted_window_rejected_at_decode() {
        // Construct a body with issued_at > expiry directly (sign_invite
        // can't produce this because of saturating_add).
        let (issuer_pk, issuer_sk) = fresh_issuer();
        let inner = invite::encode_uri(&sample_peer()).unwrap();
        let issued = T0 + 1000;
        let expiry = T0; // inverted
        let canonical = canonical_message(&inner, issued, expiry);
        let sig = sign_message(
            SignatureAlgorithm::Ed25519,
            &issuer_pk,
            &issuer_sk,
            &canonical,
        )
        .unwrap();
        let body = encode_body(
            SignatureAlgorithm::Ed25519,
            issuer_pk.as_bytes(),
            issued,
            expiry,
            &sig,
            inner.as_bytes(),
        )
        .unwrap();
        let url = format!("{SIGNED_INVITE_SCHEME}b={}", URL_SAFE_NO_PAD.encode(body));
        let err = decode_signed_invite(&url).unwrap_err();
        assert_eq!(
            err,
            SignedInviteError::InvertedWindow,
            "issued_at > expiry must be rejected at decode: {err:?}"
        );
    }

    #[test]
    fn epic481_3_bad_scheme_rejected() {
        let (issuer_pk, issuer_sk) = fresh_issuer();
        let url = sign_invite(
            &sample_peer(),
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
            T0,
            VALID_FOR_1H,
        )
        .unwrap();
        let evil = url.replace(SIGNED_INVITE_SCHEME, "https://attacker.example?b=");
        let err = decode_signed_invite(&evil).unwrap_err();
        assert_eq!(err, SignedInviteError::BadScheme);
    }

    #[test]
    fn epic481_3_oversized_url_rejected_pre_decode() {
        let bogus = format!(
            "{SIGNED_INVITE_SCHEME}b={}",
            "A".repeat(MAX_SIGNED_INVITE_BYTES)
        );
        let err = decode_signed_invite(&bogus).unwrap_err();
        assert_eq!(err, SignedInviteError::TooLarge);
    }

    #[test]
    fn epic481_3_typical_url_under_8kib_cap() {
        let (issuer_pk, issuer_sk) = fresh_issuer();
        let url = sign_invite(
            &sample_peer(),
            &issuer_pk,
            &issuer_sk,
            SignatureAlgorithm::Ed25519,
            T0,
            VALID_FOR_1H,
        )
        .unwrap();
        assert!(
            url.len() < MAX_SIGNED_INVITE_BYTES,
            "typical Ed25519 signed URL = {} B (cap = {} B)",
            url.len(),
            MAX_SIGNED_INVITE_BYTES
        );
        // Sanity: an Ed25519 signed URL shouldn't be >1 KiB.
        assert!(
            url.len() < 1024,
            "regression: typical signed URL ballooned to {} B",
            url.len()
        );
    }

    #[test]
    fn epic481_3_canonical_message_includes_domain_separator() {
        let m = canonical_message("veil:bootstrap?pk=X", 1_000, 2_000);
        assert!(
            m.starts_with(SIG_DOMAIN),
            "canonical message must start with domain prefix: {:?}",
            std::str::from_utf8(&m).unwrap_or("<non-utf8>")
        );
    }
}
