//! Proof-of-Work verification for session admission.
//!
//! During the `Identity` phase of the OVL1 handshake, the peer presents its
//! `public_key` and `nonce` in `IdentityPayload`. `PowVerifier` computes a
//! BLAKE3-based work score over `public_key || nonce` and rejects peers whose
//! score is below the required minimum difficulty.
//!
//! # Algorithm
//!
//! ```text
//! hash = BLAKE3(public_key || nonce)
//! score = leading_zero_bits(hash)
//! accept if score >= min_difficulty
//! ```
//!
//! A `min_difficulty = 0` effectively disables PoW (all nonces accepted).
//!
//! # Replay scope (audit batch 2026-05-24, L2)
//!
//! **By design**, а single `(public_key, nonce)` pair что meets the
//! difficulty threshold is accepted в multiple sessions.  PoW here
//! enforces а **per-peer admission cost** — the work is paid once per
//! identity к join the network, not per-session.  Re-using the nonce
//! across handshakes does NOT bypass any security gate:
//!   * Each session still negotiates fresh keys (X25519 ephemeral DH).
//!   * Replay attacks on session bytes are prevented by AEAD nonce
//!     counters, не by PoW freshness.
//!   * The `nonce` field is part of the IdentityDocument signature,
//!     so an attacker cannot use someone else's nonce.
//!
//! If а future design wants per-session work, add а replay cache keyed
//! on `(public_key, nonce, session_id)` here.  Current default is
//! intentional.

// ── PowVerifier ───────────────────────────────────────────────────────────────

/// Verifies that a peer's `public_key + nonce` meets the configured PoW requirement.
#[derive(Debug, Clone, Copy)]
pub struct PowVerifier {
    /// Minimum number of leading zero bits required in the BLAKE3 hash.
    pub min_difficulty: u32,
}

impl PowVerifier {
    /// Create a verifier. `min_difficulty = 0` disables PoW checks.
    pub fn new(min_difficulty: u32) -> Self {
        Self { min_difficulty }
    }

    /// Verify that `BLAKE3(public_key || nonce)` has at least `min_difficulty`
    /// leading zero bits. Returns `true` if the check passes.
    pub fn verify(&self, public_key: &[u8], nonce: &[u8]) -> bool {
        if self.min_difficulty == 0 {
            return true;
        }
        let mut input = Vec::with_capacity(public_key.len() + nonce.len());
        input.extend_from_slice(public_key);
        input.extend_from_slice(nonce);
        let hash = blake3::hash(&input);
        let score = veil_util::leading_zero_bits(hash.as_bytes());
        score >= self.min_difficulty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_difficulty_always_passes() {
        let v = PowVerifier::new(0);
        assert!(v.verify(b"any_key", b"any_nonce"));
        assert!(v.verify(b"", b""));
    }

    #[test]
    fn empty_nonce_fails_high_difficulty() {
        // BLAKE3(key||nonce) is unlikely to have 100 leading zeros
        let v = PowVerifier::new(100);
        assert!(!v.verify(b"some_key", b"bad_nonce_0000"));
    }

    #[test]
    fn score_computed_correctly() {
        // A nonce that produces a hash with at least 1 leading zero bit should exist.
        // We try incrementing nonces until we find one with score >= 1.
        let v = PowVerifier::new(1);
        let key = b"test_public_key";
        let mut found = false;
        for nonce in 0u32..10_000 {
            if v.verify(key, &nonce.to_be_bytes()) {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "should find a nonce with >= 1 zero bit within 10k tries"
        );
    }

    #[test]
    fn deterministic_for_same_input() {
        let v = PowVerifier::new(4);
        let key = b"pubkey";
        let nonce = b"nonce";
        let r1 = v.verify(key, nonce);
        let r2 = v.verify(key, nonce);
        assert_eq!(r1, r2);
    }
}
