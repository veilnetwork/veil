//! Ed25519 key blinding for blinded service descriptors (onion-registration #3,
//! Tor-v3 rend-spec style). See `PLAN_ANON_SERVICE_ONION_REGISTRATION.md` §7.4.
//!
//! A location-anonymous service publishes its descriptor under a per-time-period
//! **blinded** public key `A' = h·A` (where `A` is the service identity key and
//! `h` is a period-derived scalar), and signs the descriptor with the matching
//! blinded private scalar `a' = h·a` (so `a'·B = h·a·B = h·A = A'`). A client who
//! KNOWS the service identity `A` can derive `A'` (to find the descriptor) and
//! verify its signature; a DHT enumerator who does NOT know `A` sees only a
//! rotating, identity-unlinkable key + (separately) an encrypted descriptor body.
//!
//! This is for veil-internal use (veil client ↔ veil service), NOT Tor interop,
//! so the derivation just has to be SELF-CONSISTENT — the round-trip tests
//! (`sign_blinded` → `verify_blinded` under an independently-derived `A'`) fully
//! validate it.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

const BLIND_DOMAIN: &[u8] = b"veil.descriptor.blind.v1\0";
const PREFIX_DOMAIN: &[u8] = b"veil.descriptor.blind.prefix.v1\0";

/// Period-derived blinding scalar `h = H(domain ‖ A ‖ period)`.
fn blinding_factor(identity_vk: &[u8; 32], period: u64) -> Scalar {
    let mut h = Sha512::new();
    h.update(BLIND_DOMAIN);
    h.update(identity_vk);
    h.update(period.to_le_bytes());
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Ed25519 verifying key for a 32-byte seed. Use this to obtain the `identity_vk`
/// that pairs with an `identity_sk` rather than trusting a separately-supplied
/// value: the blinded-signing safety invariant (see [`sign_blinded`]) requires
/// the public key to be DERIVED from the seed, not caller-asserted.
pub fn ed25519_public_from_seed(identity_sk: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(identity_sk)
        .verifying_key()
        .to_bytes()
}

/// Blinded PUBLIC key `A' = h·A` for `(identity, period)`. `None` if `identity_vk`
/// is not a valid Edwards point, is a SMALL-ORDER point, or the blinded result is
/// the identity element. A client derives this from a service's known identity
/// key to locate + authenticate its descriptor.
pub fn blinded_public(identity_vk: &[u8; 32], period: u64) -> Option<[u8; 32]> {
    let a = CompressedEdwardsY(*identity_vk).decompress()?;
    // Reject the 8 small-order points: `A' = h·A` would then be low-order /
    // identity, collapsing the per-period unlinkability AND yielding a blinded
    // key under which a forged signature could verify. A legitimate Ed25519
    // identity key is never small-order, so this only rejects malformed input.
    if a.is_small_order() {
        return None;
    }
    let h = blinding_factor(identity_vk, period);
    let a_prime = h * a;
    if a_prime.is_identity() {
        return None;
    }
    Some(a_prime.compress().to_bytes())
}

/// Sign `msg` with the blinded private key for `(identity, period)`. The result
/// verifies under [`blinded_public`]`(identity_vk, period)`. `identity_sk` is the
/// 32-byte Ed25519 seed; `None` if the derived blinded key is degenerate.
///
/// SAFETY INVARIANT (load-bearing): `vk_bytes` MUST be the verifying key DERIVED
/// from `identity_sk` (as done below) — never a caller-supplied value. We sign
/// via `ed25519-dalek`'s `hazmat::raw_sign`, which performs none of the
/// strict-API checks; signing under a public key that does not match the secret
/// scalar would leak the blinded private scalar across two signatures. Deriving
/// `vk_bytes` here makes the invariant unbreakable from outside this function.
pub fn sign_blinded(identity_sk: &[u8; 32], period: u64, msg: &[u8]) -> Option<[u8; 64]> {
    let sk = SigningKey::from_bytes(identity_sk);
    let vk_bytes = sk.verifying_key().to_bytes();
    let esk = ExpandedSecretKey::from(sk.as_bytes());

    // Blinded scalar a' = h·a; blinded point A' = h·A == a'·B.
    let h = blinding_factor(&vk_bytes, period);
    let a_prime = h * esk.scalar;
    let a_prime_vk = VerifyingKey::from_bytes(&blinded_public(&vk_bytes, period)?).ok()?;

    // Deterministic blinded nonce prefix (Ed25519's r = H(prefix ‖ M)).
    let mut ph = Sha512::new();
    ph.update(PREFIX_DOMAIN);
    ph.update(esk.hash_prefix);
    ph.update(period.to_le_bytes());
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&ph.finalize()[..32]);

    let blinded = ExpandedSecretKey {
        scalar: a_prime,
        hash_prefix: prefix,
    };
    Some(raw_sign::<Sha512>(&blinded, msg, &a_prime_vk).to_bytes())
}

/// Verify a blinded signature against the BLINDED key derived from the service's
/// identity key — i.e. the verifier authenticates the descriptor knowing only
/// the service identity, not the (private) blinded key.
pub fn verify_blinded(identity_vk: &[u8; 32], period: u64, msg: &[u8], sig: &[u8; 64]) -> bool {
    let Some(a_prime) = blinded_public(identity_vk, period) else {
        return false;
    };
    verify_under_blinded_pub(&a_prime, msg, sig)
}

/// Verify a signature DIRECTLY under a given blinded public key, without
/// deriving it from a service identity. Used by the self-authenticating
/// descriptor STORE gate: a relay accepting a blinded descriptor into the DHT
/// has the blinded_pub from the wire (and binds the DHT key to it) but does NOT
/// know the service identity, so it can only check that the descriptor is
/// self-consistent (signed by the key it claims). `verify_strict` rejects
/// small-order keys / non-canonical `R`.
pub fn verify_under_blinded_pub(blinded_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(blinded_pub) else {
        return false;
    };
    vk.verify_strict(msg, &Signature::from_bytes(sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn blinded_sign_verify_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let identity_sk = sk.to_bytes();
        let identity_vk = sk.verifying_key().to_bytes();
        let period = 42u64;
        let msg = b"descriptor bytes";

        let sig = sign_blinded(&identity_sk, period, msg).unwrap();
        assert!(
            verify_blinded(&identity_vk, period, msg, &sig),
            "blinded signature verifies under the independently-derived blinded key"
        );
        // Wrong period → different blinded key → fails.
        assert!(!verify_blinded(&identity_vk, period + 1, msg, &sig));
        // Tampered message → fails.
        assert!(!verify_blinded(&identity_vk, period, b"other", &sig));
        // A different identity → fails.
        let other_vk = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        assert!(!verify_blinded(&other_vk, period, msg, &sig));
    }

    #[test]
    fn blinded_public_rotates_per_period_and_hides_identity() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key().to_bytes();
        let b1 = blinded_public(&vk, 1).unwrap();
        assert_eq!(
            b1,
            blinded_public(&vk, 1).unwrap(),
            "deterministic per period"
        );
        assert_ne!(b1, blinded_public(&vk, 2).unwrap(), "rotates per period");
        assert_ne!(b1, vk, "blinded key is not the identity key");
    }

    #[test]
    fn blinded_public_rejects_small_order_points() {
        // diff-audit S5: a small-order `identity_vk` would blind to a low-order /
        // identity point under which a forged signature could verify and which
        // carries no per-period unlinkability. Reject it.
        let mut identity = [0u8; 32];
        identity[0] = 1; // canonical encoding of the order-1 identity point
        assert_eq!(
            blinded_public(&identity, 1),
            None,
            "identity point must be rejected"
        );
        // y = 0 is an order-4 (small-order) point.
        assert_eq!(
            blinded_public(&[0u8; 32], 1),
            None,
            "y=0 small-order point must be rejected"
        );
        // A legitimate key still blinds fine.
        let vk = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        assert!(blinded_public(&vk, 1).is_some());
    }

    #[test]
    fn ed25519_public_from_seed_matches_dalek() {
        let sk = SigningKey::generate(&mut OsRng);
        assert_eq!(
            ed25519_public_from_seed(&sk.to_bytes()),
            sk.verifying_key().to_bytes(),
        );
    }
}
