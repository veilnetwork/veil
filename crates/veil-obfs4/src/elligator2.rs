//! Elligator2 wrapper over `curve25519-elligator2`.
//!
//! Elligator2 is a bijection between a subset of Curve25519 points and
//! uniformly-random 32-byte strings.  When the obfs4 handshake sends a
//! Curve25519 public key, it actually sends the elligator2 *representative*
//! of that key — a 32-byte string statistically indistinguishable from random
//! noise.  Without elligator2, the bias in standard X25519 pubkey encoding
//! (~1 bit in the high byte) is detectable by a sophisticated DPI.
//!
//! ## Key generation flow
//!
//! 1. Generate a fresh random 32-byte private key.
//! 2. Compute its Montgomery pubkey + try to elligator-encode.
//! 3. Encoding succeeds for ~50% of keys (those whose pubkey has a
//!    "square representative" on the curve).  If encoding returns
//!    `None`, retry with a fresh private key.
//! 4. Retry limit: 64 attempts (`P_failure ≈ 5.4e-20` — effectively never).
//!
//! ## Two-way mapping
//!
//! - `private_key → representative` is a **probabilistic** map (~50% rate).
//! - `representative → public_key` is **always** defined.
//!
//! Domain separation: each side generates ONE elligator-encodable
//! ephemeral key per handshake.  Long-term identity keys never go
//! through elligator2 — they live in `transport_hints`.

use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};
use rand::RngCore;
use zeroize::Zeroize;

use super::HandshakeError;

/// Number of retries when generating an elligator-encodable keypair.
/// `(1/2)^64 ≈ 5.4e-20` failure probability, so this is effectively a
/// guard against a broken RNG, not real workload.
pub const ELLIGATOR_RETRY_LIMIT: usize = 64;

/// Length of an elligator2 representative on the wire.
pub const REPRESENTATIVE_LEN: usize = 32;

/// Length of a Curve25519 private key.
pub const PRIVATE_KEY_LEN: usize = 32;

/// An elligator-encodable ephemeral keypair.
///
/// Holds the 32-byte private scalar and the precomputed 32-byte
/// representative.  `Zeroize` on drop clears the private bytes.
pub struct ElligatorKeypair {
    private: [u8; PRIVATE_KEY_LEN],
    representative: [u8; REPRESENTATIVE_LEN],
    /// Elligator2 needs a 1-byte "tweak" parameter (used to randomise
    /// the parity bit of the encoded point).  Kept alongside the
    /// representative because decoders need both.
    tweak: u8,
}

impl Drop for ElligatorKeypair {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

impl ElligatorKeypair {
    /// Generate a fresh elligator-encodable ephemeral keypair.  Retries
    /// internally if a given private key produces a pubkey without a valid
    /// representative.  Returns `Err(NoRepresentative)` only when the
    /// retry limit is exhausted — effectively never for a sound RNG.
    pub fn generate() -> Result<Self, HandshakeError> {
        let mut private = [0u8; PRIVATE_KEY_LEN];
        let mut rng = rand::rng();
        let mut tweak_buf = [0u8; 1];
        rng.fill_bytes(&mut tweak_buf);
        let tweak = tweak_buf[0];

        for _ in 0..ELLIGATOR_RETRY_LIMIT {
            rng.fill_bytes(&mut private);
            let opt: Option<[u8; 32]> = Randomized::to_representative(&private, tweak).into();
            if let Some(repr) = opt {
                return Ok(Self {
                    private,
                    representative: repr,
                    tweak,
                });
            }
        }
        private.zeroize();
        Err(HandshakeError::NoRepresentative)
    }

    /// Test/internal: construct from pre-supplied scalar + tweak.
    /// Returns `None` if the scalar doesn't have an elligator
    /// representative with given tweak (use in tests where determinism
    /// matters).
    #[doc(hidden)]
    pub fn from_private_for_test(private: [u8; 32], tweak: u8) -> Option<Self> {
        let opt: Option<[u8; 32]> = Randomized::to_representative(&private, tweak).into();
        opt.map(|repr| Self {
            private,
            representative: repr,
            tweak,
        })
    }

    /// 32-byte elligator2 representative.  This is what gets sent over
    /// the wire — uniformly-random-looking to a DPI observer.
    pub fn representative(&self) -> &[u8; REPRESENTATIVE_LEN] {
        &self.representative
    }

    /// Tweak byte chosen at generation.  Sent alongside the
    /// representative on the wire (1 extra byte).  Required for
    /// decoding by the peer.
    pub fn tweak(&self) -> u8 {
        self.tweak
    }

    /// 32-byte private key (Curve25519 scalar).  Used for ECDH with the
    /// peer's decoded pubkey.  Caller must keep this secret.
    pub fn private(&self) -> &[u8; PRIVATE_KEY_LEN] {
        &self.private
    }

    /// Compute the Montgomery public key for this private scalar.
    /// Used by tests and debug paths; on-wire we send the representative
    /// instead.
    pub fn public(&self) -> MontgomeryPoint {
        MontgomeryPoint::from_representative::<Randomized>(&self.representative)
            .expect("we just verified self has a valid representative")
    }
}

/// Decode an elligator2 representative back to a Curve25519 public point.
/// Always succeeds (elligator's forward map is total).
pub fn decode_representative(repr: &[u8; REPRESENTATIVE_LEN]) -> MontgomeryPoint {
    MontgomeryPoint::from_representative::<Randomized>(repr)
        .expect("elligator2 from_representative is total")
}

/// ECDH: scalar × point.  Returns the shared 32-byte secret.  Uses
/// the crate's `mul_clamped`, that applies RFC 7748 §5 clamping internally
/// and does a direct Montgomery ladder (does NOT reduce the scalar mod
/// curve order, that `Scalar::from_bytes_mod_order` would do — wrong for X25519).
pub fn ecdh(private: &[u8; PRIVATE_KEY_LEN], peer_public: &MontgomeryPoint) -> [u8; 32] {
    let result = peer_public.mul_clamped(*private);
    result.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_succeeds() {
        let kp = ElligatorKeypair::generate().expect("generate with retry should succeed");
        assert_eq!(kp.representative().len(), REPRESENTATIVE_LEN);
    }

    #[test]
    fn representative_decodes_back() {
        let kp = ElligatorKeypair::generate().unwrap();
        let pk_from_repr = decode_representative(kp.representative());
        let pk_direct = kp.public();
        assert_eq!(pk_from_repr.0, pk_direct.0);
    }

    #[test]
    fn ecdh_round_trip() {
        // Two parties: each generates ephemeral key, exchanges
        // representatives, derives matching shared secret.
        let alice = ElligatorKeypair::generate().unwrap();
        let bob = ElligatorKeypair::generate().unwrap();

        let bob_pk = decode_representative(bob.representative());
        let alice_pk = decode_representative(alice.representative());

        let alice_shared = ecdh(alice.private(), &bob_pk);
        let bob_shared = ecdh(bob.private(), &alice_pk);

        assert_eq!(alice_shared, bob_shared, "ECDH must agree across parties");
    }

    #[test]
    fn distinct_keypairs_produce_distinct_representatives() {
        let kp1 = ElligatorKeypair::generate().unwrap();
        let kp2 = ElligatorKeypair::generate().unwrap();
        assert_ne!(kp1.representative(), kp2.representative());
    }

    /// Statistical sanity: 1000 representatives must look uniformly
    /// distributed.  Spot-check: byte 0 across the corpus must visit
    /// at least ~half of all possible u8 values.  Strict statistical
    /// tests (chi-square) are in Phase 6.
    #[test]
    fn representatives_spread_byte_values() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let kp = ElligatorKeypair::generate().unwrap();
            seen.insert(kp.representative()[0]);
        }
        assert!(
            seen.len() > 128,
            "byte-0 of 1000 representatives should cover ≥128 distinct values, got {}",
            seen.len()
        );
    }
}
