//! Password-protected pairing URL.
//!
//! Wraps the existing [`super::invite`] URL in an Argon2id-derived
//! ChaCha20-Poly1305 envelope so the operator can post the URL on a
//! large public channel (forum, paste, social media — easy to censor)
//! while shipping the password through a small private channel
//! (Telegram, in-person, Signal — hard to censor at scale).
//!
//! # Threat model
//!
//! Defends against an adversary who can:
//! * Read the URL (it's posted publicly).
//! * MITM the URL channel and substitute a malicious URL.
//! * Brute-force passwords offline at rates limited by Argon2id cost.
//!
//! Does NOT defend against:
//! * The recipient's password being weak (Argon2id raises the cost
//!   floor but cannot make `1234` strong).
//! * Compromise of the password channel itself (if the censor reads
//!   both the URL and the password, the wrap adds nothing).
//! * Replay — the wrap doesn't add freshness; the inner URL itself
//!   is static and can be re-redeemed. An issuer who needs one-shot
//!   semantics must rotate their `[identity]` keypair after redemption.
//!
//! # Cryptographic construction
//!
//! ```text
//! kdf_salt ← 16 B random
//! aead_nonce ← 12 B random
//!
//! key (32 B) = Argon2id(
//! password
//! salt = kdf_salt
//! m_cost = 32_768 KiB / 32 MiB
//! t_cost = 2
//! p_cost = 1
//! output_len = 32
//! //!
//! ciphertext || tag = ChaCha20-Poly1305(
//! key
//! nonce = aead_nonce
//! aad = "veil.pair.v1"
//! plaintext = bootstrap_uri_bytes
//! //! ```
//!
//! Argon2id parameters are intentionally lighter than the master-seed
//! file (which uses 64 MiB / 3 passes) — pairing happens interactively
//! on whatever device the recipient has, including budget phones, and
//! a 2 s KDF on a Pi 4 would make the UX terrible. 32 MiB / 2 passes
//! costs ≈ 200-400 ms on modern hardware while still raising offline
//! brute-force to ≈ 10⁹ attempts/$ for a moderately complex password.
//!
//! # Wire layout (binary, big-endian, then base64url)
//!
//! ```text
//! [0..2] magic = "EI" (Encrypted-Invite)
//! [2] version = 1
//! [3] kdf = 1 (Argon2id)
//! [4..8] m_cost_kib u32 BE
//! [8..12] t_cost u32 BE
//! [12] p_cost u8
//! [13] salt_len u8
//! [..] salt
//! [..] nonce_len = 12 u8
//! [..] nonce 12 B
//! [..] ciphertext_len u16 BE
//! [..] ciphertext_and_tag
//! ```
//!
//! Then wrapped as `veil:pair?b=<base64url-no-pad>`.
//!
//! KDF parameters ship in-band so future tightening (e.g. m_cost =
//! 64 MiB) loads older URLs transparently. The verifier rejects
//! parameters below [`MIN_M_COST_KIB`] / [`MIN_T_COST`] / [`MIN_P_COST`]
//! to block downgrade attacks from a tampered URL.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use veil_types::BootstrapPeer;

use super::invite::{self, BootstrapUriError, MAX_BOOTSTRAP_URI_BYTES};

pub const ENCRYPTED_INVITE_SCHEME: &str = "veil:pair?";
const MAGIC: &[u8; 2] = b"EI";
const VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const AEAD_AAD: &[u8] = b"veil.pair.v1";

/// KDF cost defaults — interactive-friendly while still raising
/// offline brute-force well above the unprotected baseline.
pub const DEFAULT_M_COST_KIB: u32 = 32 * 1024;
pub const DEFAULT_T_COST: u32 = 2;
pub const DEFAULT_P_COST: u8 = 1;

/// Minimum KDF parameters accepted on decode. Anything weaker is
/// treated as a downgrade attempt and refused so an attacker can't
/// re-publish a URL with `m_cost = 1` and brute-force it on a laptop.
pub const MIN_M_COST_KIB: u32 = 8 * 1024;
pub const MIN_T_COST: u32 = 1;
pub const MIN_P_COST: u8 = 1;

/// Maximum KDF parameters accepted on decode.
/// Without an upper bound, an attacker-published invite with `m_cost_kib =
/// u32::MAX` would ask `Argon2::new` to allocate 4 TiB on the victim
/// machine when user pastes the URL — guaranteed OOM kill.
///
/// Caps:
/// * `MAX_M_COST_KIB = 1 GiB` — well above legit `DEFAULT_M_COST_KIB`
///   (32 MiB) with slack for high-security operator preset; below the
///   typical mobile RAM budget so worst-case Argon2 alloc is bounded.
/// * `MAX_T_COST = 64` — legit caps are typically 2-8; 64 leaves room for
///   a 32× security upgrade without enabling 30-second per-decode CPU.
/// * `MAX_P_COST = 16` — single device cores rarely benefit past 4-8;
///   16 covers high-end mobile / desktop.
pub const MAX_M_COST_KIB: u32 = 1024 * 1024;
pub const MAX_T_COST: u32 = 64;
pub const MAX_P_COST: u8 = 16;

/// Cap on the post-base64 URL length. The plaintext is bounded by
/// [`MAX_BOOTSTRAP_URI_BYTES`]; ciphertext adds 16 B (tag) + ~50 B
/// header / salt / nonce. Times 4/3 for base64 = ≈ 5.5 KiB ceiling.
pub const MAX_ENCRYPTED_INVITE_BYTES: usize = 6 * 1024;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum EncryptedInviteError {
    #[error("encode inner invite: {0}")]
    InnerEncode(BootstrapUriError),
    #[error("decode inner invite: {0}")]
    InnerDecode(BootstrapUriError),
    #[error("argon2: {0}")]
    Kdf(String),
    #[error("aead: ciphertext failed authentication (wrong password or tampered URL)")]
    Aead,
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("scheme: expected `{ENCRYPTED_INVITE_SCHEME}…`")]
    BadScheme,
    #[error("base64: {0}")]
    Base64(String),
    #[error("URL exceeds {MAX_ENCRYPTED_INVITE_BYTES} byte cap")]
    TooLarge,
    #[error("KDF parameters below minimum (m_cost_kib={m}, t_cost={t}, p_cost={p})")]
    KdfDowngrade { m: u32, t: u32, p: u8 },
}

/// Encrypt a [`BootstrapPeer`] under `password` and return an
/// `veil:pair?b=<base64>` URL safe to post on a public channel.
///
/// `password` is consumed by Argon2id immediately; callers that want
/// stronger zeroize semantics on the input should wrap their own
/// buffer [`zeroize::Zeroizing`] before calling.
pub fn encrypt_invite(
    peer: &BootstrapPeer,
    password: &str,
) -> Result<String, EncryptedInviteError> {
    encrypt_invite_with(
        peer,
        password,
        DEFAULT_M_COST_KIB,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
    )
}

/// Same as [`encrypt_invite`] but with explicit KDF parameters —
/// kept `pub` for tests that need to use cheap params and for future
/// callers that want to tune cost per-deployment.
pub fn encrypt_invite_with(
    peer: &BootstrapPeer,
    password: &str,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u8,
) -> Result<String, EncryptedInviteError> {
    let inner = invite::encode_uri(peer).map_err(EncryptedInviteError::InnerEncode)?;
    let plaintext = inner.as_bytes();

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(
        password.as_bytes(),
        &salt,
        m_cost_kib,
        t_cost,
        p_cost as u32,
    )?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: AEAD_AAD,
            },
        )
        .map_err(|_| EncryptedInviteError::Aead)?;

    let body = encode_body(m_cost_kib, t_cost, p_cost, &salt, &nonce, &ciphertext)?;
    let b64 = URL_SAFE_NO_PAD.encode(body);
    let url = format!("{ENCRYPTED_INVITE_SCHEME}b={b64}");
    if url.len() > MAX_ENCRYPTED_INVITE_BYTES {
        return Err(EncryptedInviteError::TooLarge);
    }
    Ok(url)
}

/// Decrypt an `veil:pair?b=<base64>` URL with `password` and return
/// the inner [`BootstrapPeer`]. Errors:
///
/// * [`EncryptedInviteError::Aead`] — wrong password OR a censor
///   tampered with the URL bytes. These are intentionally not
///   distinguishable to avoid a password-confirmation oracle.
/// * [`EncryptedInviteError::KdfDowngrade`] — URL ships KDF params
///   below the minimum; almost certainly a tamper attempt.
pub fn decrypt_invite(url: &str, password: &str) -> Result<BootstrapPeer, EncryptedInviteError> {
    if url.len() > MAX_ENCRYPTED_INVITE_BYTES {
        return Err(EncryptedInviteError::TooLarge);
    }
    let body_b64 = url
        .strip_prefix(ENCRYPTED_INVITE_SCHEME)
        .and_then(|s| s.strip_prefix("b="))
        .ok_or(EncryptedInviteError::BadScheme)?;
    let body = URL_SAFE_NO_PAD
        .decode(body_b64.as_bytes())
        .map_err(|e| EncryptedInviteError::Base64(e.to_string()))?;

    let (m_cost_kib, t_cost, p_cost, salt, nonce, ciphertext) = decode_body(&body)?;
    // lower-and-upper bound on attacker-supplied KDF params.
    // Without upper bound an invite with `m_cost = u32::MAX` triggers 4 TiB OOM on paste.
    if m_cost_kib < MIN_M_COST_KIB
        || t_cost < MIN_T_COST
        || p_cost < MIN_P_COST
        || m_cost_kib > MAX_M_COST_KIB
        || t_cost > MAX_T_COST
        || p_cost > MAX_P_COST
    {
        return Err(EncryptedInviteError::KdfDowngrade {
            m: m_cost_kib,
            t: t_cost,
            p: p_cost,
        });
    }

    let key = derive_key(password.as_bytes(), salt, m_cost_kib, t_cost, p_cost as u32)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: AEAD_AAD,
            },
        )
        .map_err(|_| EncryptedInviteError::Aead)?;

    let inner = std::str::from_utf8(&plaintext)
        .map_err(|e| EncryptedInviteError::Malformed(format!("plaintext utf8: {e}")))?;
    if inner.len() > MAX_BOOTSTRAP_URI_BYTES {
        return Err(EncryptedInviteError::Malformed(format!(
            "inner URI exceeds {MAX_BOOTSTRAP_URI_BYTES} byte cap",
        )));
    }
    invite::decode_uri(inner).map_err(EncryptedInviteError::InnerDecode)
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, EncryptedInviteError> {
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
        .map_err(|e| EncryptedInviteError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| EncryptedInviteError::Kdf(e.to_string()))?;
    Ok(key)
}

fn encode_body(
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u8,
    salt: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncryptedInviteError> {
    if salt.len() > u8::MAX as usize {
        return Err(EncryptedInviteError::Malformed("salt too long".into()));
    }
    if ciphertext.len() > u16::MAX as usize {
        return Err(EncryptedInviteError::Malformed(
            "ciphertext too long".into(),
        ));
    }
    let mut out = Vec::with_capacity(
        2 + 1 + 1 + 4 + 4 + 1 + 1 + salt.len() + 1 + nonce.len() + 2 + ciphertext.len(),
    );
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(KDF_ARGON2ID);
    out.extend_from_slice(&m_cost_kib.to_be_bytes());
    out.extend_from_slice(&t_cost.to_be_bytes());
    out.push(p_cost);
    out.push(salt.len() as u8);
    out.extend_from_slice(salt);
    out.push(nonce.len() as u8);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// Decoded encrypted-invite envelope fields (zero-copy slice references).
/// `(time_cost, mem_cost_kib, parallelism, salt, nonce, ciphertext)`.
type DecodedInviteBody<'a> = (u32, u32, u8, &'a [u8], &'a [u8], &'a [u8]);

fn decode_body(buf: &[u8]) -> Result<DecodedInviteBody<'_>, EncryptedInviteError> {
    let mut p = 0usize;
    let magic = read(buf, &mut p, 2)?;
    if magic != MAGIC {
        return Err(EncryptedInviteError::Malformed(format!(
            "bad magic: {:?}",
            magic,
        )));
    }
    let version = read(buf, &mut p, 1)?[0];
    if version != VERSION {
        return Err(EncryptedInviteError::Malformed(format!(
            "unsupported version {version}",
        )));
    }
    let kdf = read(buf, &mut p, 1)?[0];
    if kdf != KDF_ARGON2ID {
        return Err(EncryptedInviteError::Malformed(format!(
            "unsupported kdf id {kdf}",
        )));
    }
    let m_cost_kib = u32::from_be_bytes(read(buf, &mut p, 4)?.try_into().unwrap());
    let t_cost = u32::from_be_bytes(read(buf, &mut p, 4)?.try_into().unwrap());
    let p_cost = read(buf, &mut p, 1)?[0];

    let salt_len = read(buf, &mut p, 1)?[0] as usize;
    let salt = read(buf, &mut p, salt_len)?;
    let nonce_len = read(buf, &mut p, 1)?[0] as usize;
    if nonce_len != NONCE_LEN {
        return Err(EncryptedInviteError::Malformed(format!(
            "nonce_len = {nonce_len}, expected {NONCE_LEN}",
        )));
    }
    let nonce = read(buf, &mut p, nonce_len)?;
    let ct_len = u16::from_be_bytes(read(buf, &mut p, 2)?.try_into().unwrap()) as usize;
    let ciphertext = read(buf, &mut p, ct_len)?;
    if p != buf.len() {
        return Err(EncryptedInviteError::Malformed(format!(
            "{} trailing byte(s) after ciphertext",
            buf.len() - p,
        )));
    }
    Ok((m_cost_kib, t_cost, p_cost, salt, nonce, ciphertext))
}

fn read<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], EncryptedInviteError> {
    // checked_add — mirror signed_invite.rs:389 + cursor.rs.
    let end = pos
        .checked_add(n)
        .ok_or_else(|| EncryptedInviteError::Malformed(format!("truncated {}B at {}", n, *pos)))?;
    let slice = buf
        .get(*pos..end)
        .ok_or_else(|| EncryptedInviteError::Malformed(format!("truncated {}B at {}", n, *pos)))?;
    *pos = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_types::SignatureAlgorithm;

    // Cheap KDF cost so the test suite still finishes quickly while
    // exercising the real codec path.
    const TEST_M_COST_KIB: u32 = MIN_M_COST_KIB;
    const TEST_T_COST: u32 = 1;
    const TEST_P_COST: u8 = 1;

    fn sample_peer() -> BootstrapPeer {
        BootstrapPeer {
            transport: "tcp://10.1.2.3:9000".to_owned(),
            public_key: "AAAAAAAA".to_owned(),
            nonce: "BBBBBBBB".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        }
    }

    fn sample_peer_with_tls() -> BootstrapPeer {
        BootstrapPeer {
            transport: "wss://example.org:443/ovl".to_owned(),
            public_key: "PPPPPPPP".to_owned(),
            nonce: "NNNNNNNN".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: Some("CCCCCCCC".to_owned()),
            tls_ca_cert: Some("DDDDDDDD".to_owned()),
        }
    }

    fn enc(peer: &BootstrapPeer, pw: &str) -> String {
        encrypt_invite_with(peer, pw, TEST_M_COST_KIB, TEST_T_COST, TEST_P_COST).expect("encrypt")
    }

    #[test]
    fn epic481_2_encrypt_decrypt_round_trip_recovers_peer() {
        let peer = sample_peer();
        let url = enc(&peer, "correct horse battery staple");
        assert!(
            url.starts_with(ENCRYPTED_INVITE_SCHEME),
            "URL must start with `{ENCRYPTED_INVITE_SCHEME}`: {url}"
        );
        let back = decrypt_invite(&url, "correct horse battery staple").expect("decrypt");
        assert_eq!(peer, back);
    }

    #[test]
    fn epic481_2_round_trip_preserves_optional_tls_fields() {
        let peer = sample_peer_with_tls();
        let url = enc(&peer, "hunter2");
        let back = decrypt_invite(&url, "hunter2").expect("decrypt");
        assert_eq!(peer, back);
    }

    #[test]
    fn epic481_2_wrong_password_fails_with_aead_error() {
        let url = enc(&sample_peer(), "alpha");
        let err = decrypt_invite(&url, "beta").unwrap_err();
        assert_eq!(
            err,
            EncryptedInviteError::Aead,
            "wrong password must be indistinguishable from tamper: {err}"
        );
    }

    #[test]
    fn epic481_2_tampered_ciphertext_fails_with_aead_error() {
        let mut url = enc(&sample_peer(), "pw");
        // Flip a single byte deep inside the ciphertext segment by
        // mutating the last char of the base64 body — guaranteed to
        // change the decoded payload, guaranteed to fail Poly1305.
        let last = url.pop().expect("non-empty");
        let mutated = if last == 'a' { 'b' } else { 'a' };
        url.push(mutated);
        let err = decrypt_invite(&url, "pw").unwrap_err();
        assert!(
            matches!(
                err,
                EncryptedInviteError::Aead
                    | EncryptedInviteError::Base64(_)
                    | EncryptedInviteError::Malformed(_)
            ),
            "tamper must fail loudly: {err:?}",
        );
    }

    #[test]
    fn epic481_2_bad_scheme_rejected() {
        let body = enc(&sample_peer(), "pw");
        let evil = body.replace(ENCRYPTED_INVITE_SCHEME, "https://attacker.example?b=");
        let err = decrypt_invite(&evil, "pw").unwrap_err();
        assert_eq!(err, EncryptedInviteError::BadScheme);
    }

    #[test]
    fn epic481_2_malformed_base64_rejected() {
        let url = format!("{ENCRYPTED_INVITE_SCHEME}b=!!not-base64!!");
        let err = decrypt_invite(&url, "pw").unwrap_err();
        assert!(
            matches!(err, EncryptedInviteError::Base64(_)),
            "non-base64 body must be rejected: {err:?}"
        );
    }

    #[test]
    fn epic481_2_kdf_downgrade_attempt_rejected() {
        // Encrypt with cost = 1/1/1 (below minimum); decoder must refuse.
        let peer = sample_peer();
        let inner = invite::encode_uri(&peer).unwrap();
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        // Use intentionally weak params (m_cost_kib = 8 KiB — below MIN).
        // We still need a high enough Argon2 floor to actually run, so use
        // the libargon2 absolute minimum (8 KiB, 1 pass, 1 par).
        let weak_m: u32 = argon2::Params::MIN_M_COST;
        assert!(
            weak_m < MIN_M_COST_KIB,
            "test premise: argon2 min ({weak_m} KiB) must be < MIN_M_COST_KIB ({MIN_M_COST_KIB} KiB)"
        );
        let key = derive_key(b"pw", &salt, weak_m, 1, 1).unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: inner.as_bytes(),
                    aad: AEAD_AAD,
                },
            )
            .unwrap();
        let body = encode_body(weak_m, 1, 1, &salt, &nonce, &ciphertext).unwrap();
        let url = format!(
            "{ENCRYPTED_INVITE_SCHEME}b={}",
            URL_SAFE_NO_PAD.encode(body)
        );
        let err = decrypt_invite(&url, "pw").unwrap_err();
        assert!(
            matches!(err, EncryptedInviteError::KdfDowngrade { .. }),
            "below-minimum KDF params must be refused: {err:?}"
        );
    }

    #[test]
    fn epic481_2_truncated_body_rejected_not_panics() {
        let mut url = enc(&sample_peer(), "pw");
        // Hack off the second half of the base64 body — guarantees a
        // truncated binary body underneath.
        let body_start = url.find("b=").unwrap() + 2;
        let cutoff = body_start + (url.len() - body_start) / 4;
        url.truncate(cutoff);
        let err = decrypt_invite(&url, "pw").unwrap_err();
        // Either base64 parsing or binary header parsing flags it; both
        // are acceptable — the contract is "no panic, no Aead-success".
        assert!(
            matches!(
                err,
                EncryptedInviteError::Malformed(_)
                    | EncryptedInviteError::Base64(_)
                    | EncryptedInviteError::Aead
            ),
            "truncated URL must surface a typed error: {err:?}"
        );
    }

    #[test]
    fn epic481_2_oversized_url_rejected_pre_decode() {
        // A 7-KiB URL is past MAX_ENCRYPTED_INVITE_BYTES = 6 KiB.
        let bogus = format!("{ENCRYPTED_INVITE_SCHEME}b={}", "A".repeat(7 * 1024));
        let err = decrypt_invite(&bogus, "pw").unwrap_err();
        assert_eq!(err, EncryptedInviteError::TooLarge);
    }

    #[test]
    fn epic481_2_url_size_for_typical_peer_under_cap() {
        let url = enc(&sample_peer_with_tls(), "pw");
        assert!(
            url.len() < MAX_ENCRYPTED_INVITE_BYTES,
            "typical peer encrypted URL = {} B (cap = {} B)",
            url.len(),
            MAX_ENCRYPTED_INVITE_BYTES
        );
        // Sanity check the rough size envelope.
        assert!(
            url.len() < 1024,
            "regression: typical encrypted URL ballooned to {} B",
            url.len()
        );
    }

    #[test]
    fn epic481_2_distinct_encryptions_produce_distinct_ciphertexts() {
        // Same peer + same password → different URLs (random salt + nonce).
        // Without this property, an observer correlating two postings could
        // confirm "this is the same invite reissued" without decrypting.
        let peer = sample_peer();
        let url_a = enc(&peer, "pw");
        let url_b = enc(&peer, "pw");
        assert_ne!(
            url_a, url_b,
            "fresh salt/nonce per encryption must yield distinct URLs"
        );
        // But both decrypt back to the same peer.
        assert_eq!(decrypt_invite(&url_a, "pw").unwrap(), peer);
        assert_eq!(decrypt_invite(&url_b, "pw").unwrap(), peer);
    }
}
