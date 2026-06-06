//! Push-token sealing primitive.
//!
//! The receiver's `RendezvousAd` (see [`super::rendezvous`]) carries a
//! `push_envelope: Vec<u8>` field — opaque-to-veil sealed bytes that
//! only a trusted push-relay operator can decrypt. This module provides
//! the actual seal / unseal primitive.
//!
//! # Threat model
//!
//! * **Sender** (anyone fetching the rendezvous-ad from DHT) sees only
//!   the sealed envelope. Cannot recover the underlying FCM/APNs token
//!   nor link receiver_node_id ↔ token without the relay's X25519 sk.
//! * **Censor** observing DHT traffic sees published envelopes but can't
//!   decrypt — so cannot pressure Google/Apple to disclose "give me the
//!   device IDs that received these FCM tokens" to deanonymize users.
//! * **Push-relay operator** holds the X25519 sk and can decrypt. Sees
//!   only "user X (by node_id) wants a wake-up at time T". Cannot read
//!   message content (veil E2E protects). Trust placed:
//!   "this operator forwards wake-ups but does not log token-to-user
//!   correlations indefinitely". Future slice can add forward-secrecy
//!   via per-message ephemeral relay keys; currently the relay's
//!   long-term sk decrypts every envelope addressed to it.
//!
//! # Wire format
//!
//! ```text
//! [0..32] eph_pk — sender's ephemeral X25519 public key
//! [32..44] nonce — fresh 96-bit random nonce
//! [44..] ciphertext+tag — ChaCha20-Poly1305 encrypted token + 16-byte tag
//! ```
//!
//! Total: `64 + token.len` bytes. Cap [`MAX_PUSH_TOKEN_LEN`] = 384 so
//! a sealed envelope fits in [`super::rendezvous::MAX_PUSH_ENVELOPE_LEN`]
//! = 512 B cap on the wire field.
//!
//! # Domain separation
//!
//! AEAD AAD = `b"veil-push-envelope-v1\0"` — distinct from onion-layer
//! ([`super::onion`] uses `b"veil-onion-v1\0"`) so an envelope sealed
//! for push delivery cannot be re-dispatched as a circuit layer (or vice
//! versa). Bumping `:v1` would invalidate every published envelope —
//! only do this on a security-relevant format change.
//!
//! # Forward secrecy
//!
//! Sender's per-call ephemeral keypair gives forward secrecy IF the
//! relay keeps its long-term sk safe. If the relay's disk is seized
//! ALL past sealed envelopes addressed to it can be retroactively
//! decrypted (same property as Tor's pre-NTor onion routing).
//! documents the analogous gap for anonymity-layer
//! relay keys; same defence direction applies — short-rotation cadence
//! published as overlapping `valid_from / valid_until` intervals.
//! Out-of-scope for this primitive; the rotation scheme lives in the
//! push-relay reference implementation.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{
    EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret,
};

// ── Wire constants ────────────────────────────────────────────────────────────

/// Length of the X25519 ephemeral public key prefix. Same as in
/// [`super::onion::EPHEMERAL_PK_LEN`] but redeclared here so this
/// module is self-contained.
pub const EPH_PK_LEN: usize = 32;

/// ChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 12;

/// ChaCha20-Poly1305 AEAD tag length.
pub const TAG_LEN: usize = 16;

/// Per-envelope wire overhead: eph_pk + nonce + AEAD tag. Add to
/// `token.len` to compute the full sealed envelope length.
pub const PUSH_ENVELOPE_OVERHEAD: usize = EPH_PK_LEN + NONCE_LEN + TAG_LEN;

/// Hard cap on the inner token length. FCM HTTP v1 tokens are typically
/// ~163 chars (base64-ish); APNs binary tokens are 32 bytes; iOS
/// PassKit tokens up to ~190 bytes; this 384 ceiling leaves slack for
/// future formats and still fits sealed envelope under the
/// [`super::rendezvous::MAX_PUSH_ENVELOPE_LEN`] = 512 B wire cap
/// (384 + 60 = 444 ≤ 512 with 68 B slack).
pub const MAX_PUSH_TOKEN_LEN: usize = 384;

/// Hard cap on the wire envelope size. Mirrors
/// [`super::rendezvous::MAX_PUSH_ENVELOPE_LEN`] for consistency but
/// kept as a separate constant so this module is loadable in
/// isolation (e.g. push-relay reference impl that doesn't import
/// rendezvous primitives).
pub const MAX_PUSH_ENVELOPE_LEN: usize = 512;

const PUSH_AEAD_DOMAIN: &[u8] = b"veil-push-envelope-v1\0";

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PushEnvelopeError {
    #[error("token is {got} B; max is {MAX_PUSH_TOKEN_LEN} B")]
    TokenTooLarge { got: usize },
    #[error("envelope is {got} B; min sealed size is {min} B (eph_pk + nonce + tag)")]
    EnvelopeTooSmall { got: usize, min: usize },
    #[error("envelope is {got} B; max wire size is {MAX_PUSH_ENVELOPE_LEN} B")]
    EnvelopeTooLarge { got: usize },
    #[error("AEAD verification failed (wrong relay key, tampered envelope, or domain mismatch)")]
    Aead,
}

// ── Seal ────────────────────────────────────────────────────────────────────

/// Encrypt `token` to the push-relay identified by `relay_pk` (X25519
/// public key). Output layout: `eph_pk (32B) || nonce (12B) || ct+tag`.
///
/// Fresh ephemeral keypair generated per call → forward secrecy against
/// future ephemeral compromise (assumes relay's long-term sk stays safe;
/// see module docstring).
pub fn seal_push_envelope(
    token: &[u8],
    relay_pk: &[u8; EPH_PK_LEN],
) -> Result<Vec<u8>, PushEnvelopeError> {
    if token.len() > MAX_PUSH_TOKEN_LEN {
        return Err(PushEnvelopeError::TokenTooLarge { got: token.len() });
    }
    let ephemeral_sk = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk).to_bytes();
    let relay = X25519PublicKey::from(*relay_pk);
    let shared = ephemeral_sk.diffie_hellman(&relay);
    // Defense-in-depth: refuse to seal against a non-contributory relay key.
    if !shared.was_contributory() {
        return Err(PushEnvelopeError::Aead);
    }

    let aead_key = derive_aead_key(shared.as_bytes());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let aad = build_aad(&ephemeral_pk, &nonce_bytes);
    // ChaCha20-Poly1305 cannot fail at the encrypt path for valid
    // key/nonce/payload sizes (which we control here); panic here would
    // be a chacha20poly1305 bug.
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: token,
                aad: &aad,
            },
        )
        .expect("chacha20poly1305 encrypt must not fail on valid inputs");

    let mut out = Vec::with_capacity(PUSH_ENVELOPE_OVERHEAD + token.len());
    out.extend_from_slice(&ephemeral_pk);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    debug_assert!(out.len() <= MAX_PUSH_ENVELOPE_LEN);
    Ok(out)
}

// ── Unseal ──────────────────────────────────────────────────────────────────

/// Decrypt a sealed envelope using the push-relay's static X25519 secret.
/// Returns the original `token` bytes on success; AEAD failure on wrong
/// key / tampered envelope / wrong domain.
///
/// Used by the push-relay reference impl.
pub fn unseal_push_envelope(
    envelope: &[u8],
    relay_sk: &X25519StaticSecret,
) -> Result<Vec<u8>, PushEnvelopeError> {
    if envelope.len() < PUSH_ENVELOPE_OVERHEAD {
        return Err(PushEnvelopeError::EnvelopeTooSmall {
            got: envelope.len(),
            min: PUSH_ENVELOPE_OVERHEAD,
        });
    }
    if envelope.len() > MAX_PUSH_ENVELOPE_LEN {
        return Err(PushEnvelopeError::EnvelopeTooLarge {
            got: envelope.len(),
        });
    }
    let mut ephemeral_pk = [0u8; EPH_PK_LEN];
    ephemeral_pk.copy_from_slice(&envelope[..EPH_PK_LEN]);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&envelope[EPH_PK_LEN..EPH_PK_LEN + NONCE_LEN]);
    let ciphertext = &envelope[EPH_PK_LEN + NONCE_LEN..];

    let shared = relay_sk.diffie_hellman(&X25519PublicKey::from(ephemeral_pk));
    // Reject a non-contributory (low-order) ephemeral_pk (attacker-controlled,
    // read off the wire above): a small-order point forces a known shared
    // secret. Fail closed rather than derive an AEAD key off it.
    if !shared.was_contributory() {
        return Err(PushEnvelopeError::Aead);
    }
    let aead_key = derive_aead_key(shared.as_bytes());

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let aad = build_aad(&ephemeral_pk, &nonce_bytes);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| PushEnvelopeError::Aead)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// BLAKE3-based KDF: derives a 32-byte ChaCha20-Poly1305 key from the
/// X25519 shared-secret bytes. Domain separator binds the derivation
/// to "push-envelope" purpose, distinct from onion-layer keys.
fn derive_aead_key(shared: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("veil.push_envelope.aead.v1");
    h.update(shared);
    let full = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full.as_bytes()[..32]);
    out
}

/// AAD bound into the AEAD: `domain || eph_pk || nonce`. Tampering with
/// any of these triggers AEAD failure on decrypt. Including eph_pk +
/// nonce in AAD makes header-bit fuzzing produce AEAD failures rather
/// than silent successes.
fn build_aad(eph_pk: &[u8; EPH_PK_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PUSH_AEAD_DOMAIN.len() + EPH_PK_LEN + NONCE_LEN);
    aad.extend_from_slice(PUSH_AEAD_DOMAIN);
    aad.extend_from_slice(eph_pk);
    aad.extend_from_slice(nonce);
    aad
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_relay_keypair() -> (X25519StaticSecret, [u8; 32]) {
        let sk = X25519StaticSecret::random_from_rng(OsRng);
        let pk = X25519PublicKey::from(&sk).to_bytes();
        (sk, pk)
    }

    #[test]
    fn t1_1_seal_unseal_round_trip_fcm_token() {
        let (relay_sk, relay_pk) = fixture_relay_keypair();
        let token = b"fcm-test-token-aaaa-bbbb-cccc-dddd-eeee-ffff:APA91b...";
        let envelope = seal_push_envelope(token, &relay_pk).unwrap();
        let recovered = unseal_push_envelope(&envelope, &relay_sk).unwrap();
        assert_eq!(recovered, token);
    }

    #[test]
    fn t1_1_seal_unseal_round_trip_apns_binary() {
        // APNs tokens are 32 bytes raw binary.
        let (relay_sk, relay_pk) = fixture_relay_keypair();
        let token: [u8; 32] = [0xAB; 32];
        let envelope = seal_push_envelope(&token, &relay_pk).unwrap();
        let recovered = unseal_push_envelope(&envelope, &relay_sk).unwrap();
        assert_eq!(recovered, token);
    }

    #[test]
    fn t1_1_envelope_size_bounded() {
        let (_relay_sk, relay_pk) = fixture_relay_keypair();
        let token = b"short";
        let envelope = seal_push_envelope(token, &relay_pk).unwrap();
        assert_eq!(envelope.len(), PUSH_ENVELOPE_OVERHEAD + token.len());
        assert!(envelope.len() <= MAX_PUSH_ENVELOPE_LEN);
    }

    #[test]
    fn t1_1_max_size_token_accepted() {
        let (relay_sk, relay_pk) = fixture_relay_keypair();
        let token = vec![0xCC; MAX_PUSH_TOKEN_LEN];
        let envelope = seal_push_envelope(&token, &relay_pk).unwrap();
        assert!(envelope.len() <= MAX_PUSH_ENVELOPE_LEN);
        let recovered = unseal_push_envelope(&envelope, &relay_sk).unwrap();
        assert_eq!(recovered, token);
    }

    #[test]
    fn t1_1_oversized_token_rejected() {
        let (_relay_sk, relay_pk) = fixture_relay_keypair();
        let token = vec![0u8; MAX_PUSH_TOKEN_LEN + 1];
        let err = seal_push_envelope(&token, &relay_pk).unwrap_err();
        assert!(matches!(err, PushEnvelopeError::TokenTooLarge { .. }));
    }

    #[test]
    fn t1_1_empty_token_round_trips() {
        // App that wants to unregister push: send empty envelope.
        // Still must encrypt-then-decrypt cleanly so the relay sees
        // "this user has no push" rather than a malformed envelope.
        let (relay_sk, relay_pk) = fixture_relay_keypair();
        let envelope = seal_push_envelope(b"", &relay_pk).unwrap();
        let recovered = unseal_push_envelope(&envelope, &relay_sk).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn t1_1_wrong_relay_sk_aead_failure() {
        let (_relay_sk, relay_pk) = fixture_relay_keypair();
        let attacker_sk = X25519StaticSecret::random_from_rng(OsRng);
        let envelope = seal_push_envelope(b"secret-fcm-token", &relay_pk).unwrap();
        let err = unseal_push_envelope(&envelope, &attacker_sk).unwrap_err();
        assert_eq!(err, PushEnvelopeError::Aead);
    }

    #[test]
    fn t1_1_tampered_ciphertext_aead_failure() {
        let (relay_sk, relay_pk) = fixture_relay_keypair();
        let mut envelope = seal_push_envelope(b"original-token", &relay_pk).unwrap();
        // Flip a bit in the ciphertext.
        let last = envelope.len() - 1;
        envelope[last] ^= 0x01;
        let err = unseal_push_envelope(&envelope, &relay_sk).unwrap_err();
        assert_eq!(err, PushEnvelopeError::Aead);
    }

    #[test]
    fn t1_1_tampered_eph_pk_aead_failure() {
        // CRITICAL: AAD includes eph_pk so swapping it produces AEAD
        // failure rather than a silent success with garbled ciphertext.
        let (relay_sk, relay_pk) = fixture_relay_keypair();
        let mut envelope = seal_push_envelope(b"token", &relay_pk).unwrap();
        envelope[0] ^= 0x01;
        let err = unseal_push_envelope(&envelope, &relay_sk).unwrap_err();
        assert_eq!(err, PushEnvelopeError::Aead);
    }

    #[test]
    fn t1_1_tampered_nonce_aead_failure() {
        let (relay_sk, relay_pk) = fixture_relay_keypair();
        let mut envelope = seal_push_envelope(b"token", &relay_pk).unwrap();
        envelope[EPH_PK_LEN] ^= 0x01;
        let err = unseal_push_envelope(&envelope, &relay_sk).unwrap_err();
        assert_eq!(err, PushEnvelopeError::Aead);
    }

    #[test]
    fn t1_1_truncated_envelope_rejected() {
        let buf = vec![0u8; PUSH_ENVELOPE_OVERHEAD - 1];
        let (relay_sk, _) = fixture_relay_keypair();
        let err = unseal_push_envelope(&buf, &relay_sk).unwrap_err();
        assert!(matches!(err, PushEnvelopeError::EnvelopeTooSmall { .. }));
    }

    #[test]
    fn t1_1_oversized_envelope_rejected() {
        let buf = vec![0u8; MAX_PUSH_ENVELOPE_LEN + 1];
        let (relay_sk, _) = fixture_relay_keypair();
        let err = unseal_push_envelope(&buf, &relay_sk).unwrap_err();
        assert!(matches!(err, PushEnvelopeError::EnvelopeTooLarge { .. }));
    }

    #[test]
    fn t1_1_two_seals_produce_distinct_ciphertexts() {
        // Fresh ephemeral keypair per seal → two seals of the same token
        // to the same relay produce different envelopes. Without this
        // a passive observer correlating envelopes could fingerprint a
        // user as "same token across multiple receivers".
        let (_relay_sk, relay_pk) = fixture_relay_keypair();
        let e1 = seal_push_envelope(b"same-token", &relay_pk).unwrap();
        let e2 = seal_push_envelope(b"same-token", &relay_pk).unwrap();
        assert_ne!(e1, e2);
    }

    #[test]
    fn t1_1_envelope_does_not_reveal_token() {
        // Smoke test: passive observer of the envelope cannot read
        // the underlying token (without the relay's sk). We don't claim
        // CCA security beyond AEAD's standard guarantees; this just
        // checks the wire format does NOT contain plaintext token.
        let (_relay_sk, relay_pk) = fixture_relay_keypair();
        let token = b"secret-token-do-not-leak";
        let envelope = seal_push_envelope(token, &relay_pk).unwrap();
        // The token bytes should not appear contiguously in the envelope.
        assert!(!envelope.windows(token.len()).any(|w| w == token));
    }
}
