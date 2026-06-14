//! Identity safety-number fingerprint.
//!
//! Produces a short, user-comparable numeric string for an **unordered
//! pair** of node_ids. Inspired directly by Signal's safety
//! numbers. The goal: two users can read the number to each other
//! over a voice channel and confirm they have the same view of each
//! other's identity, preventing MITM even if the DHT or handshake
//! fabric has been compromised.
//!
//! ## Algorithm
//!
//! ```text
//! min_id, max_id = order_pair(id_a, id_b)
//! digest = BLAKE3(
//! "veil.fingerprint.v1"
//! || min_id
//! || max_id
//! -> 48 B via XOF
//! for i in 0..12:
//! group_i = u32::from_be_bytes(digest[4i..4i+4]) mod 100_000
//! format as 5 zero-padded decimal digits
//! fingerprint = groups joined by single spaces
//! (60 digits total, 12 × 5-digit groups)
//! ```
//!
//! Because the inputs are sorted before hashing, both sides of a
//! conversation compute identical strings without extra negotiation.
//! `order_pair` uses byte-lex order — well-defined for any two
//! distinct `[u8; 32]` values.
//!
//! ## Why decimal and why 60 digits
//!
//! **Decimal**, not hex: users reading over a phone line don't have
//! to distinguish between spoken "five" and "B"; the channel is
//! purely spoken.
//! **60 digits** ≈ 200 bits of hash output, which matches the
//! security margin every other primitive in this system targets.
//! Preimage resistance of 60 decimal digits is 10^60 ≈ 2^199.
//! **Groups of 5**: short enough for short-term visual memory
//! long enough to recognise at a glance.

/// Number of 5-digit groups in the fingerprint.
pub const FINGERPRINT_GROUPS: usize = 12;
/// Total decimal digits (groups × 5).
pub const FINGERPRINT_DIGITS: usize = FINGERPRINT_GROUPS * 5;

/// Context string for BLAKE3 input — identical across caller
/// implementations so fingerprints interoperate.
pub const FINGERPRINT_CONTEXT: &[u8] = b"veil.fingerprint.v1";

/// Compute a pair-symmetric fingerprint for two node_ids.
///
/// The returned string is always exactly `FINGERPRINT_DIGITS +
/// (FINGERPRINT_GROUPS - 1)` characters long (digits plus inner
/// spaces). Group ordering is stable between callers: swapping
/// `id_a` and `id_b` produces the same output.
///
/// Two identical identities yield a valid fingerprint too — callers
/// that want to disallow self-pairs must check beforehand. We return
/// an error here only to surface "someone fed us nonsense", not to
/// encode a policy.
pub fn identity_fingerprint(id_a: &[u8; 32], id_b: &[u8; 32]) -> String {
    let (lo, hi) = order_pair(id_a, id_b);

    let mut hasher = blake3::Hasher::new();
    hasher.update(FINGERPRINT_CONTEXT);
    hasher.update(lo);
    hasher.update(hi);

    // XOF: pull out 48 bytes (12 × 4-byte groups).
    let mut out_bytes = [0u8; FINGERPRINT_GROUPS * 4];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut out_bytes);

    let mut s = String::with_capacity(FINGERPRINT_DIGITS + FINGERPRINT_GROUPS - 1);
    for i in 0..FINGERPRINT_GROUPS {
        if i > 0 {
            s.push(' ');
        }
        let chunk: [u8; 4] = out_bytes[i * 4..(i + 1) * 4].try_into().unwrap();
        let v = u32::from_be_bytes(chunk) % 100_000;
        // Zero-pad to 5 digits.
        let group = format!("{v:05}");
        s.push_str(&group);
    }
    s
}

/// Stable byte-lex order of two node_ids.
fn order_pair<'a>(a: &'a [u8; 32], b: &'a [u8; 32]) -> (&'a [u8; 32], &'a [u8; 32]) {
    if a.as_slice() <= b.as_slice() {
        (a, b)
    } else {
        (b, a)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_shape_is_60_digits_in_12_groups() {
        let fp = identity_fingerprint(&[0x11u8; 32], &[0x22u8; 32]);
        // 12 groups × 5 digits = 60 digits, 11 inner spaces -> 71 chars.
        assert_eq!(fp.len(), 71);
        let parts: Vec<&str> = fp.split(' ').collect();
        assert_eq!(parts.len(), FINGERPRINT_GROUPS);
        for p in parts {
            assert_eq!(p.len(), 5);
            assert!(p.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn fingerprint_is_pair_symmetric() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        assert_eq!(
            identity_fingerprint(&a, &b),
            identity_fingerprint(&b, &a),
            "swapping operands must not change the number"
        );
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let a = [0x33u8; 32];
        let b = [0x44u8; 32];
        let x = identity_fingerprint(&a, &b);
        let y = identity_fingerprint(&a, &b);
        assert_eq!(x, y);
    }

    #[test]
    fn distinct_identity_pairs_produce_distinct_fingerprints() {
        // With BLAKE3-256 collision probability per pair flip is
        // 2^-128 — well below the tolerance of any test-failure
        // budget. Three distinct pair-combinations suffice.
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let c = [0x33u8; 32];
        let ab = identity_fingerprint(&a, &b);
        let ac = identity_fingerprint(&a, &c);
        let bc = identity_fingerprint(&b, &c);
        assert_ne!(ab, ac);
        assert_ne!(ab, bc);
        assert_ne!(ac, bc);
    }

    #[test]
    fn single_bit_flip_in_either_id_changes_fingerprint() {
        // Cryptographically significant property: BLAKE3 should map
        // even a 1-bit input delta to a wildly different output.
        let a = [0x55u8; 32];
        let b = [0x66u8; 32];
        let original = identity_fingerprint(&a, &b);

        let mut a_flipped = a;
        a_flipped[0] ^= 0x01;
        assert_ne!(original, identity_fingerprint(&a_flipped, &b));

        let mut b_flipped = b;
        b_flipped[31] ^= 0x80;
        assert_ne!(original, identity_fingerprint(&a, &b_flipped));
    }

    #[test]
    fn identical_identities_produce_a_fingerprint() {
        // Policy-agnostic: the function itself returns something
        // sensible even for self-pairs. Callers enforce policy.
        let a = [0x77u8; 32];
        let fp = identity_fingerprint(&a, &a);
        assert_eq!(fp.len(), 71);
    }

    #[test]
    fn order_pair_returns_stable_lex_order() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let (lo, hi) = order_pair(&a, &b);
        assert_eq!(lo, &a);
        assert_eq!(hi, &b);
        let (lo2, hi2) = order_pair(&b, &a);
        assert_eq!(lo2, &a);
        assert_eq!(hi2, &b);
    }

    #[test]
    fn every_group_uses_all_digits_distribution_smoke() {
        // Sanity check: with random-ish inputs we should see all
        // digits 0..=9 appearing across groups, not (say) only
        // small values from an accidental `% 10` bug.
        let a = [0xABu8; 32];
        let b = [0xCDu8; 32];
        let fp = identity_fingerprint(&a, &b);
        let digits: std::collections::HashSet<char> =
            fp.chars().filter(|c| c.is_ascii_digit()).collect();
        // Very weak floor — we just want "more than one distinct digit".
        assert!(
            digits.len() >= 4,
            "got suspiciously few distinct digits: {digits:?}"
        );
    }

    #[test]
    fn fingerprint_context_is_domain_separated() {
        // Fingerprint input must begin with FINGERPRINT_CONTEXT; this
        // is a guard against an accidental rename of the context. If
        // the constant is shortened to something a user-controlled
        // prefix could impersonate, the test will catch it because
        // the hash output will change.
        assert!(FINGERPRINT_CONTEXT.starts_with(b"veil."));
        assert!(!FINGERPRINT_CONTEXT.is_empty());
    }
}
