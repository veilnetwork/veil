//! Out-of-band (OOB) confirmation code for the pairing ceremony
//!
//!
//! After the source + target devices complete the pair handshake
//! they share a symmetric secret (the session key, established via
//! X25519 + the `pair_secret`). Both sides run that secret through
//! [`derive_pair_oob_code`] to get the **same** 6-digit number
//! which the user compares visually between the two screens before
//! confirming the device link.
//!
//! ## Algorithm
//!
//! ```text
//! h = BLAKE3(OOB_CONTEXT || session_key)
//! n = u32::from_be_bytes(h[0..4]) % 1_000_000
//! code = format!("{:03}-{:03}", n / 1000, n % 1000)
//! ```
//!
//! Domain-separated so a session_key used elsewhere (session
//! cipher, KDF chain) cannot alias back into the OOB digits.
//! `1_000_000` range → 20 bits of entropy → 1-in-a-million
//! chance an attacker-chosen secret matches any given code.
//! 3-3 split matches the UX convention in Signal / WhatsApp
//! confirmations.
//!
//! ## Why not hex?
//!
//! Digits read aloud without ambiguity ("one-two-three dash
//! four-five-six") whereas hex has multiple read-aloud conventions
//! (`b` = "bee" / "bravo") that produce typos under pressure.
//! Users of the ceremony are meant to compare visually, but a voice
//! fallback must be reliable too.
//!
//! ## Why not more digits?
//!
//! Six digits is the established UX sweet-spot — short enough for
//! visual comparison on mobile at a glance, long enough that a
//! single-digit typo has a 1-in-99 999 chance of collision per
//! ceremony. Longer codes hurt the UX without meaningfully raising
//! the security floor (active MITM must already have subverted the
//! session KDF to produce ANY matching code).

use blake3::Hasher;

/// Domain-separated prefix for OOB-code derivation — keeps the
/// digits distinct from any other value derived off the same
/// session key.
pub const PAIR_OOB_CONTEXT: &[u8] = b"veil.pair.oob.v1";

/// Derive the 6-digit confirmation code from the post-handshake
/// shared secret.
///
/// Both devices call this with the identical `session_key` they
/// each established; the user then visually compares the two
/// screens. Output shape: `"123-456"` — 7 chars, ASCII only.
pub fn derive_pair_oob_code(session_key: &[u8]) -> String {
    let mut h = Hasher::new();
    h.update(PAIR_OOB_CONTEXT);
    h.update(session_key);
    let hash = h.finalize();
    let bytes = hash.as_bytes();
    let n = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 1_000_000;
    format!("{:03}-{:03}", n / 1000, n % 1000)
}

/// Structure of the emitted code string — useful to the UI layer
/// for consistent display and test assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairOobCode {
    /// Left 3-digit group (`"012"` through `"999"`).
    pub left: u16,
    /// Right 3-digit group (`"000"` through `"999"`).
    pub right: u16,
}

impl PairOobCode {
    /// Parse a previously-emitted code (`"012-345"`) back into its
    /// numeric groups. Rejects anything that doesn't match the
    /// canonical shape.
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() != 7 || s.as_bytes()[3] != b'-' {
            return None;
        }
        let l: u16 = s.get(0..3)?.parse().ok()?;
        let r: u16 = s.get(4..7)?.parse().ok()?;
        if l > 999 || r > 999 {
            return None;
        }
        Some(Self { left: l, right: r })
    }

    /// Canonical rendering: `"012-345"`.
    pub fn to_string_canonical(&self) -> String {
        format!("{:03}-{:03}", self.left, self.right)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_session_key() {
        let key = [0x11u8; 32];
        assert_eq!(derive_pair_oob_code(&key), derive_pair_oob_code(&key));
    }

    #[test]
    fn distinct_session_keys_produce_distinct_codes() {
        let a = derive_pair_oob_code(&[0x11u8; 32]);
        let b = derive_pair_oob_code(&[0x22u8; 32]);
        // Astronomical chance of collision — use `assert_ne!`.
        assert_ne!(a, b);
    }

    #[test]
    fn output_shape_is_canonical() {
        let code = derive_pair_oob_code(&[0u8; 32]);
        assert_eq!(code.len(), 7, "7 chars total (XXX-XXX)");
        assert_eq!(code.as_bytes()[3], b'-', "dash at index 3");
        assert!(
            code.bytes()
                .enumerate()
                .all(|(i, b)| i == 3 || b.is_ascii_digit()),
            "non-separator positions are digits: {code}"
        );
    }

    #[test]
    fn padded_zeros_for_small_values() {
        // Pick a session key whose first 4 BE bytes mod 1_000_000 is
        // small enough to exercise the left-padding path. Brute-force
        // a short loop to find one — guaranteed to exist quickly.
        for i in 0u32..1_000 {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            let code = derive_pair_oob_code(&k);
            assert_eq!(code.len(), 7, "still 7 chars for tiny mod result: {code}");
        }
    }

    #[test]
    fn is_domain_separated_from_raw_blake3() {
        let key = [0x42u8; 32];
        let naive = blake3::hash(&key);
        let naive_n = u32::from_be_bytes([
            naive.as_bytes()[0],
            naive.as_bytes()[1],
            naive.as_bytes()[2],
            naive.as_bytes()[3],
        ]) % 1_000_000;
        let naive_code = format!("{:03}-{:03}", naive_n / 1000, naive_n % 1000);
        let domain_code = derive_pair_oob_code(&key);
        assert_ne!(
            naive_code, domain_code,
            "domain separation must produce a different digest than raw BLAKE3(key)"
        );
    }

    #[test]
    fn both_devices_derive_the_same_code() {
        // Two "devices" each hold the same post-handshake session key;
        // the ceremony requires them to derive identical codes.
        let session_key = [0xABu8; 32];
        let source_side = derive_pair_oob_code(&session_key);
        let target_side = derive_pair_oob_code(&session_key);
        assert_eq!(source_side, target_side);
    }

    #[test]
    fn parse_canonical_shape_roundtrip() {
        let code_str = derive_pair_oob_code(&[0u8; 32]);
        let parsed = PairOobCode::parse(&code_str).expect("canonical parse");
        assert_eq!(parsed.to_string_canonical(), code_str);
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(PairOobCode::parse("").is_none());
        assert!(PairOobCode::parse("123456").is_none()); // no dash
        assert!(PairOobCode::parse("1234-56").is_none()); // wrong layout
        assert!(PairOobCode::parse("abc-def").is_none()); // not digits
        assert!(PairOobCode::parse("999-9999").is_none()); // wrong length
    }
}
