//! X25519 Diffie-Hellman key exchange primitives.
//!
//! Used in the OVL1 session handshake (`KeyAgreementPayload`) to establish a
//! per-session shared secret. The caller is responsible for serialising the
//! 32-byte public key into the wire payload and passing the 32-byte remote
//! public key received from the peer.

use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::Zeroizing;

// ── types ────────────────────────────────────────────────────────────────────

/// An ephemeral X25519 keypair. The private key is consumed when
/// `compute_shared_secret` is called, enforcing that it is used exactly once.
pub struct EphemeralKeypair {
    secret: EphemeralSecret,
    pub public_key: [u8; 32],
}

/// Errors returned by [`compute_shared_secret`][].
#[derive(Debug, thiserror::Error)]
pub enum KexError {
    /// The remote public key was a low-order point, so the resulting
    /// shared secret is all-zero (or another fixed value known to the
    /// attacker who chose the point).  Aborting the handshake is the
    /// only safe response — proceeding would derive session keys from a
    /// secret known to the adversary.
    #[error(
        "non-contributory X25519: remote pubkey is a low-order point (shared secret would be known to attacker)"
    )]
    NonContributory,
}

// ── public API ───────────────────────────────────────────────────────────────

/// Generate a fresh X25519 ephemeral keypair using the OS random source.
pub fn generate_ephemeral() -> EphemeralKeypair {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&secret).to_bytes();
    EphemeralKeypair { secret, public_key }
}

/// Consume the ephemeral secret and compute the X25519 shared secret with
/// the given remote public key bytes. Returns the raw 32-byte secret
/// wrapped [`Zeroizing`] so the bytes are wiped from memory when the
/// caller drops or moves the result.
///
/// Callers that need the bytes for HKDF or AEAD-key derivation should
/// pass `&*secret` (deref to `&[u8; 32]`); the wrapper Zeroizes when
/// the binding goes out of scope.
///
/// Returns [`KexError::NonContributory`] when the remote pubkey is a
/// low-order point — `x25519-dalek` silently produces an all-zero
/// shared secret in that case, which would let an attacker who chose
/// the point derive identical session keys.  Even though OVL1 binds
/// peer-supplied pubkeys through an ephemeral signature (see
/// `runner.rs::on_session_init`), the cheap zero-check provides
/// defense-in-depth against a compromised long-term key actively
/// publishing low-order points.
pub fn compute_shared_secret(
    keypair: EphemeralKeypair,
    remote_pubkey: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, KexError> {
    let remote = PublicKey::from(*remote_pubkey);
    let shared: SharedSecret = keypair.secret.diffie_hellman(&remote);
    // Reject non-contributory DH (low-order remote pubkey → attacker-known
    // output). `was_contributory()` is the canonical x25519-dalek check,
    // matching the anonymity/rendezvous/push DH paths.
    if !shared.was_contributory() {
        return Err(KexError::NonContributory);
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_shared_secret_is_symmetric() {
        let alice = generate_ephemeral();
        let bob = generate_ephemeral();

        let alice_pub = alice.public_key;
        let bob_pub = bob.public_key;

        let secret_a = compute_shared_secret(alice, &bob_pub).expect("contributory");
        let secret_b = compute_shared_secret(bob, &alice_pub).expect("contributory");

        assert_eq!(*secret_a, *secret_b, "X25519 shared secrets must be equal");
        assert_ne!(*secret_a, [0u8; 32], "shared secret must not be all zeros");
    }

    #[test]
    fn distinct_keypairs_produce_distinct_secrets() {
        let kp1a = generate_ephemeral();
        let kp1b = generate_ephemeral();
        let kp2a = generate_ephemeral();
        let kp2b = generate_ephemeral();

        let pub1b = kp1b.public_key;
        let pub2b = kp2b.public_key;

        let s1 = compute_shared_secret(kp1a, &pub1b).expect("contributory");
        let s2 = compute_shared_secret(kp2a, &pub2b).expect("contributory");

        assert_ne!(
            *s1, *s2,
            "independent sessions must not share the same secret"
        );
    }

    #[test]
    fn low_order_remote_pubkey_is_rejected() {
        let kp = generate_ephemeral();
        // All-zero pubkey is the canonical low-order point (X25519
        // identity).  diffie_hellman returns all-zero shared secret →
        // compute_shared_secret must refuse.
        let low_order = [0u8; 32];
        match compute_shared_secret(kp, &low_order) {
            Err(KexError::NonContributory) => {}
            other => panic!("expected NonContributory, got {other:?}"),
        }
    }
}
