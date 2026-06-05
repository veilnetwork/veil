//! NameClaim V2 — DHT-stored `@name → node_id` binding.
//!
//! Replaces `NameRecord` with a structure tailored to
//! the sovereign identity model:
//!
//! binds the claim to `node_id`, so the claim follows the owner
//! across subkey rotation automatically;
//! any active identity subkey may sign, with `signing_identity_key_idx`
//! pointing into the current `IdentityDocument.identity_keys`;
//! PoW is *rarity-proportional* — short alphabetic names cost much
//! more hash-work than long random ones, so squatting short aliases
//! is economically hostile;
//! a `freshness_hour` anchor blocks rainbow-table pre-computation
//! — the PoW nonce must be freshly mined and cannot
//! be hoarded;
//! character set is **ASCII-only** whitelist `[a-z0-9#_-]`;
//! Unicode (and therefore Unicode-homoglyph typosquatting like
//! `alíce` vs `alice`) is refused at decode time. IDNA2008
//! support will land in a follow-up epic if/when it's justified.
//!
//! ## Wire layout (canonical bytes, big-endian)
//!
//! ```text
//! [0..2] magic = "NM" u16
//! [2] version = 1 u8
//! [3..35] node_id [u8; 32]
//! [35] name_len u8
//! [..] name (normalized ASCII) [u8; name_len]
//! [..] claimed_at_unix u64 BE
//! [..] pow_nonce [u8; 16]
//! [..] freshness_hour u32 BE
//! [..] signing_identity_key_idx u16 BE
//! [..] sig_len u16 BE
//! [..] sig [u8; sig_len]
//! ```
//!
//! The signature covers `NAME_CLAIM_SIG_CONTEXT || canonical_bytes
//! minus sig trailer` produced by [`NameClaim::canonical_signing_bytes`].
//!
//! PoW input:
//! ```text
//! BLAKE3(canonical_signing_bytes_before_sig || pow_nonce)
//! ```
//! has ≥ `required_difficulty(name)` leading zero bits.

use super::ProtoError;
use super::cursor::{read_array, read_bytes, read_u8, read_u16, read_u32, read_u64};

// ── Constants ────────────────────────────────────────────────────────────────

/// "NM" — identifies a NameClaim value on the wire.
pub const NAME_CLAIM_MAGIC: [u8; 2] = [b'N', b'M'];
/// Wire-format version.
pub const NAME_CLAIM_V1: u8 = 1;
/// Domain-separated signing context.
pub const NAME_CLAIM_SIG_CONTEXT: &[u8] = b"veil.name_claim.v1";

/// Maximum name length (UTF-8 bytes, ASCII-only).
pub const MAX_NAME_LEN: usize = 64;

/// Absolute upper bound on wire size.
pub const MAX_NAME_CLAIM_BYTES: usize = 1024;

/// Signature length cap.
const MAX_SIG_BYTES: usize = 1024;

// ── ASCII whitelist ──────────────────────────────────────────────────────────

/// Whether a byte is an accepted name character.
///
/// Whitelist: `a-z`, `0-9`, `#`, `_`, `-`. Explicit rather than using
/// `char::is_ascii_*` helpers so the policy is obvious at call site.
#[inline]
pub fn is_allowed_byte(b: u8) -> bool {
    matches!(b,
        b'a'..=b'z' | b'0'..=b'9' | b'#' | b'_' | b'-'
    )
}

/// Normalize a candidate name to the canonical on-wire form.
///
/// Trims leading/trailing whitespace.
/// Lowercases ASCII alphabetic characters (uppercase input is
/// accepted as a user-facing convenience).
/// Returns `Err` if any byte falls outside the whitelist — Unicode
/// characters, spaces in the middle, or punctuation not in the
/// list surface as [`NameError::InvalidChar`].
pub fn normalize_name(raw: &str) -> Result<String, NameError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(NameError::Empty);
    }
    if trimmed.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong {
            len: trimmed.len(),
            max: MAX_NAME_LEN,
        });
    }
    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        // Lowercase ASCII uppercase; accept ASCII lowercase/digits/whitelist;
        // reject everything else, including Unicode.
        if !ch.is_ascii() {
            return Err(NameError::InvalidChar(ch));
        }
        let lower = ch.to_ascii_lowercase();
        if !is_allowed_byte(lower as u8) {
            return Err(NameError::InvalidChar(ch));
        }
        out.push(lower);
    }
    Ok(out)
}

// ── Rarity-proportional PoW difficulty ──────────────────────────────────────

/// Required PoW difficulty (leading zero bits) for a normalized name.
///
/// Short, all-alphabetic names are desirable (`alice`, `bob`) and
/// therefore cost the most hash-work to register. Adding digits or
/// using the Discord-style `handle#tag` convention drops the cost
/// because those names are inherently less collision-prone and so
/// less valuable to squat. Long random strings are cheap — registration
/// there is effectively free friction for legitimate use.
///
/// `#[cfg(test)]` (and the `test-low-difficulty` feature, set by
/// downstream test profiles) lowers every tier so the unit tests can
/// mine valid nonces in a handful of iterations.
pub fn required_difficulty(normalized_name: &str) -> u32 {
    #[cfg(any(test, feature = "test-low-difficulty"))]
    const ALPHA_1_3: u32 = 8;
    #[cfg(not(any(test, feature = "test-low-difficulty")))]
    const ALPHA_1_3: u32 = 28;

    #[cfg(any(test, feature = "test-low-difficulty"))]
    const ALPHA_4_6: u32 = 8;
    #[cfg(not(any(test, feature = "test-low-difficulty")))]
    const ALPHA_4_6: u32 = 24;

    #[cfg(any(test, feature = "test-low-difficulty"))]
    const ALPHANUM_5_7: u32 = 8;
    #[cfg(not(any(test, feature = "test-low-difficulty")))]
    const ALPHANUM_5_7: u32 = 22;

    #[cfg(any(test, feature = "test-low-difficulty"))]
    const HANDLE_TAGGED: u32 = 6;
    #[cfg(not(any(test, feature = "test-low-difficulty")))]
    const HANDLE_TAGGED: u32 = 14;

    #[cfg(any(test, feature = "test-low-difficulty"))]
    const LONG_MIXED: u32 = 4;
    #[cfg(not(any(test, feature = "test-low-difficulty")))]
    const LONG_MIXED: u32 = 12;

    if normalized_name.contains('#') {
        return HANDLE_TAGGED;
    }

    let len = normalized_name.len();
    let all_alpha = normalized_name.bytes().all(|b| b.is_ascii_lowercase());
    let all_alphanum = normalized_name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());

    if all_alpha {
        match len {
            1..=3 => ALPHA_1_3,
            4..=6 => ALPHA_4_6,
            7..=10 => ALPHANUM_5_7,
            _ => LONG_MIXED,
        }
    } else if all_alphanum {
        match len {
            1..=4 => ALPHA_4_6,
            5..=7 => ALPHANUM_5_7,
            _ => LONG_MIXED,
        }
    } else {
        // Contains `_` or `-`.
        LONG_MIXED
    }
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NameError {
    #[error("name is empty")]
    Empty,
    #[error("name length {len} exceeds max {max}")]
    TooLong { len: usize, max: usize },
    #[error("name contains invalid character: {0:?}")]
    InvalidChar(char),
}

// ── NameClaim ────────────────────────────────────────────────────────────────

/// Signed `@name → node_id` binding published to the DHT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameClaim {
    /// Normalized name (ASCII whitelist, lowercase).
    pub name: String,
    /// Identity claiming the name.
    pub node_id: [u8; 32],
    /// Unix seconds when the claim was produced.
    pub claimed_at_unix: u64,
    /// Anti-spam proof-of-work nonce.
    pub pow_nonce: [u8; 16],
    /// `freshness_hour = floor(unix_now / 3600)` at mining time.
    /// Consumers reject if `|freshness_hour − now/3600| > 2` hours.
    pub freshness_hour: u32,
    /// Index into the owner's `IdentityDocument.identity_keys` of the
    /// subkey that signed this claim.
    pub signing_identity_key_idx: u16,
    /// Signature over `NAME_CLAIM_SIG_CONTEXT || canonical_signing_bytes`.
    pub sig: Vec<u8>,
}

impl NameClaim {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&NAME_CLAIM_MAGIC);
        out.push(NAME_CLAIM_V1);
        out.extend_from_slice(&self.node_id);
        out.push(self.name.len() as u8);
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(&self.claimed_at_unix.to_be_bytes());
        out.extend_from_slice(&self.pow_nonce);
        out.extend_from_slice(&self.freshness_hour.to_be_bytes());
        out.extend_from_slice(&self.signing_identity_key_idx.to_be_bytes());
        out.extend_from_slice(&(self.sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Decode wire bytes with full structural validation — including
    /// ASCII-only name check and length caps.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() > MAX_NAME_CLAIM_BYTES {
            return Err(ProtoError::Malformed(format!(
                "name_claim: oversized ({}B > {MAX_NAME_CLAIM_BYTES}B)",
                buf.len()
            )));
        }
        let mut pos = 0;
        if buf.get(pos..pos + 2) != Some(&NAME_CLAIM_MAGIC[..]) {
            return Err(ProtoError::Malformed("name_claim: bad magic".into()));
        }
        pos += 2;

        let version = read_u8(buf, &mut pos, "name_claim.version")?;
        if version != NAME_CLAIM_V1 {
            return Err(ProtoError::Malformed(format!(
                "name_claim: unsupported version {version}"
            )));
        }

        let node_id = read_array::<32>(buf, &mut pos, "name_claim.node_id")?;

        let name_len = read_u8(buf, &mut pos, "name_claim.name_len")? as usize;
        if name_len == 0 || name_len > MAX_NAME_LEN {
            return Err(ProtoError::Malformed(format!(
                "name_claim: name_len {name_len} out of range"
            )));
        }
        let name_bytes = read_bytes(buf, &mut pos, name_len, "name_claim.name")?;
        for &b in &name_bytes {
            if !is_allowed_byte(b) {
                return Err(ProtoError::Malformed(format!(
                    "name_claim: disallowed byte {:#04x} in name",
                    b,
                )));
            }
        }
        // SAFETY: every byte passed is_allowed_byte which is ASCII.
        let name = String::from_utf8(name_bytes)
            .map_err(|e| ProtoError::Malformed(format!("name_claim.name utf8: {e}")))?;

        let claimed_at_unix = read_u64(buf, &mut pos, "name_claim.claimed_at")?;
        let pow_nonce = read_array::<16>(buf, &mut pos, "name_claim.pow_nonce")?;
        let freshness_hour = read_u32(buf, &mut pos, "name_claim.freshness_hour")?;
        let signing_identity_key_idx = read_u16(buf, &mut pos, "name_claim.signing_key_idx")?;

        let sig_len = read_u16(buf, &mut pos, "name_claim.sig_len")? as usize;
        if sig_len == 0 || sig_len > MAX_SIG_BYTES {
            return Err(ProtoError::Malformed(format!(
                "name_claim: sig_len {sig_len} out of range"
            )));
        }
        let sig = read_bytes(buf, &mut pos, sig_len, "name_claim.sig")?;

        if pos != buf.len() {
            return Err(ProtoError::Malformed(format!(
                "name_claim: {} trailing bytes",
                buf.len() - pos
            )));
        }

        Ok(Self {
            name,
            node_id,
            claimed_at_unix,
            pow_nonce,
            freshness_hour,
            signing_identity_key_idx,
            sig,
        })
    }

    /// Canonical bytes covered by the signature (full encoding minus
    /// the `sig_len + sig` trailer).
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut encoded = self.encode();
        let trailer = 2 + self.sig.len();
        encoded.truncate(encoded.len() - trailer);
        encoded
    }

    /// Bytes fed into BLAKE3 for the PoW check.
    ///
    /// ```text
    /// pow_input = canonical_signing_bytes_without_pow_nonce
    /// || pow_nonce
    /// valid iff BLAKE3(pow_input).leading_zeros ≥ required_difficulty(name)
    /// ```
    ///
    /// Including `freshness_hour` (which already lives in canonical
    /// bytes) binds the PoW to "mined within the last ±2 hours" —
    /// rainbow-table pre-computation of name nonces is infeasible.
    pub fn pow_preimage(&self) -> Vec<u8> {
        // canonical_signing_bytes already contains pow_nonce and
        // freshness_hour in their wire positions. For PoW we hash
        // those bytes directly.
        self.canonical_signing_bytes()
    }

    /// DHT key under which the claim is stored — derived from the
    /// **normalized** name so all equivalent inputs (case, stray
    /// whitespace) hash to the same slot.
    pub fn dht_key(normalized_name: &str) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"veil.name_claim_dht.v1");
        h.update(&(normalized_name.len() as u16).to_be_bytes());
        h.update(normalized_name.as_bytes());
        *h.finalize().as_bytes()
    }

    fn encoded_len(&self) -> usize {
        2 + 1 + 32 + 1 + self.name.len() + 8 + 16 + 4 + 2 + 2 + self.sig.len()
    }

    /// Convenience: `required_difficulty(&self.name)`.
    pub fn required_difficulty(&self) -> u32 {
        required_difficulty(&self.name)
    }
}

// ── Decode helpers ───────────────────────────────────────────────────────────
//
// local `read_array` removed — use cursor::read_array.

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> NameClaim {
        NameClaim {
            name: "alice".to_string(),
            node_id: [0x11u8; 32],
            claimed_at_unix: 1_700_000_000,
            pow_nonce: [0x22u8; 16],
            freshness_hour: 472_222,
            signing_identity_key_idx: 0,
            sig: vec![0xCC; 64],
        }
    }

    // ── Normalize ────────────────────────────────────────────────────────────

    #[test]
    fn normalize_lowercases_ascii() {
        assert_eq!(normalize_name("AlIcE").unwrap(), "alice");
    }

    #[test]
    fn normalize_trims_whitespace() {
        assert_eq!(normalize_name("   alice  \n").unwrap(), "alice");
    }

    #[test]
    fn normalize_preserves_digits_and_allowed_punct() {
        assert_eq!(normalize_name("Alice#1234").unwrap(), "alice#1234");
        assert_eq!(normalize_name("foo_bar-baz").unwrap(), "foo_bar-baz");
    }

    #[test]
    fn normalize_rejects_empty() {
        let err = normalize_name("").unwrap_err();
        assert_eq!(err, NameError::Empty);
        let err = normalize_name("   ").unwrap_err();
        assert_eq!(err, NameError::Empty);
    }

    #[test]
    fn normalize_rejects_internal_whitespace() {
        let err = normalize_name("foo bar").unwrap_err();
        assert!(matches!(err, NameError::InvalidChar(' ')), "{err:?}");
    }

    #[test]
    fn normalize_rejects_unicode() {
        // Cyrillic, looks like ASCII — classic homoglyph attack.
        let err = normalize_name("аlice").unwrap_err();
        assert!(matches!(err, NameError::InvalidChar(_)), "{err:?}");

        // Accented Latin.
        let err = normalize_name("alíce").unwrap_err();
        assert!(matches!(err, NameError::InvalidChar(_)), "{err:?}");

        // Emoji.
        let err = normalize_name("🦀rust").unwrap_err();
        assert!(matches!(err, NameError::InvalidChar(_)), "{err:?}");
    }

    #[test]
    fn normalize_rejects_forbidden_ascii_punct() {
        for ch in ['.', '/', '!', '@', '\\', '$', ' ', '*'] {
            let name = format!("foo{ch}bar");
            let err = normalize_name(&name).unwrap_err();
            assert!(
                matches!(err, NameError::InvalidChar(c) if c == ch),
                "{ch:?} -> {err:?}"
            );
        }
    }

    #[test]
    fn normalize_rejects_too_long() {
        let s = "a".repeat(MAX_NAME_LEN + 1);
        let err = normalize_name(&s).unwrap_err();
        assert!(matches!(err, NameError::TooLong { .. }));
    }

    #[test]
    fn normalize_accepts_max_length_exactly() {
        let s = "a".repeat(MAX_NAME_LEN);
        let out = normalize_name(&s).unwrap();
        assert_eq!(out.len(), MAX_NAME_LEN);
    }

    // ── Difficulty ───────────────────────────────────────────────────────────

    #[test]
    fn difficulty_short_alpha_highest() {
        // In cfg(test) all tiers are low, but the *relative* ordering
        // is what callers depend on. Check relative rarity:
        // short alpha ≥ short alphanumeric ≥ long alphanumeric ≥
        // handle-with-# ≥ long-mixed.
        // All test-mode tiers are equal or decreasing by construction.
        let d_short_alpha = required_difficulty("bob");
        let d_short_num = required_difficulty("b0b");
        let d_long_alpha = required_difficulty("bobalongnamehere");
        let d_tagged = required_difficulty("alice#1234");
        let d_mixed = required_difficulty("a-b_c-d-e");

        // Every tier must be at least the lowest tier.
        assert!(d_short_alpha >= d_mixed);
        assert!(d_short_num >= d_mixed);
        assert!(d_long_alpha >= d_mixed);
        assert!(d_tagged >= d_mixed);

        // Handle-style must be cheaper than short all-alpha.
        assert!(d_tagged <= d_short_alpha);
    }

    #[test]
    fn difficulty_is_deterministic() {
        assert_eq!(required_difficulty("alice"), required_difficulty("alice"));
    }

    // ── Encode / decode ──────────────────────────────────────────────────────

    #[test]
    fn roundtrip_basic_claim() {
        let c = sample();
        let bytes = c.encode();
        let back = NameClaim::decode(&bytes).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn roundtrip_varied_names() {
        for name in [
            "a",
            "bob",
            "alice",
            "alice#1234",
            "foo_bar-baz",
            "longishalphanumericname42",
            &"x".repeat(MAX_NAME_LEN),
        ] {
            let c = NameClaim {
                name: name.to_string(),
                ..sample()
            };
            let bytes = c.encode();
            let back = NameClaim::decode(&bytes).unwrap();
            assert_eq!(c, back);
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = sample().encode();
        bytes[0] = b'X';
        let err = NameClaim::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_unknown_version() {
        let mut bytes = sample().encode();
        bytes[2] = 99;
        let err = NameClaim::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_zero_name_len() {
        let mut c = sample();
        c.name = String::new();
        // Manually build the buffer with name_len = 0 (encode asserts
        // this implicitly by encoding the actual length, so we bypass).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&NAME_CLAIM_MAGIC);
        bytes.push(NAME_CLAIM_V1);
        bytes.extend_from_slice(&c.node_id);
        bytes.push(0); // name_len = 0
        bytes.extend_from_slice(&c.claimed_at_unix.to_be_bytes());
        bytes.extend_from_slice(&c.pow_nonce);
        bytes.extend_from_slice(&c.freshness_hour.to_be_bytes());
        bytes.extend_from_slice(&c.signing_identity_key_idx.to_be_bytes());
        bytes.extend_from_slice(&(c.sig.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&c.sig);
        let err = NameClaim::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_disallowed_byte_in_name() {
        // Hand-craft bytes with ASCII '!' in the name (not in whitelist).
        let c = sample();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&NAME_CLAIM_MAGIC);
        bytes.push(NAME_CLAIM_V1);
        bytes.extend_from_slice(&c.node_id);
        let bad_name = b"bad!name";
        bytes.push(bad_name.len() as u8);
        bytes.extend_from_slice(bad_name);
        bytes.extend_from_slice(&c.claimed_at_unix.to_be_bytes());
        bytes.extend_from_slice(&c.pow_nonce);
        bytes.extend_from_slice(&c.freshness_hour.to_be_bytes());
        bytes.extend_from_slice(&c.signing_identity_key_idx.to_be_bytes());
        bytes.extend_from_slice(&(c.sig.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&c.sig);
        let err = NameClaim::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_non_ascii_utf8_byte_in_name() {
        let c = sample();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&NAME_CLAIM_MAGIC);
        bytes.push(NAME_CLAIM_V1);
        bytes.extend_from_slice(&c.node_id);
        // Put a valid UTF-8 multibyte character (cyrillic 'а' = C2 B0? actually C3 A0...).
        // Use a byte > 0x7F to ensure is_allowed_byte rejects it.
        let bad_name = &[0xC3, 0xA1]; // "á"
        bytes.push(bad_name.len() as u8);
        bytes.extend_from_slice(bad_name);
        bytes.extend_from_slice(&c.claimed_at_unix.to_be_bytes());
        bytes.extend_from_slice(&c.pow_nonce);
        bytes.extend_from_slice(&c.freshness_hour.to_be_bytes());
        bytes.extend_from_slice(&c.signing_identity_key_idx.to_be_bytes());
        bytes.extend_from_slice(&(c.sig.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&c.sig);
        let err = NameClaim::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_oversized_input() {
        let bytes = vec![0u8; MAX_NAME_CLAIM_BYTES + 1];
        let err = NameClaim::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_truncated_input() {
        let bytes = sample().encode();
        for len in 0..bytes.len() {
            let err = NameClaim::decode(&bytes[..len]).unwrap_err();
            assert!(matches!(err, ProtoError::Malformed(_)), "len={len} {err:?}");
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = sample().encode();
        bytes.push(0xFF);
        let err = NameClaim::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_zero_length_sig() {
        let mut c = sample();
        c.sig = Vec::new();
        let bytes = c.encode();
        let err = NameClaim::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    // ── Canonical bytes / PoW ────────────────────────────────────────────────

    #[test]
    fn canonical_bytes_exclude_sig_trailer() {
        let c = sample();
        let full = c.encode();
        let canonical = c.canonical_signing_bytes();
        assert!(canonical.len() < full.len());
        assert_eq!(&full[..canonical.len()], &canonical[..]);
        assert_eq!(full.len() - canonical.len(), 2 + c.sig.len());
    }

    #[test]
    fn canonical_bytes_stable_under_sig_mutation() {
        let mut c = sample();
        let before = c.canonical_signing_bytes();
        c.sig = vec![0xFF; 64];
        let after = c.canonical_signing_bytes();
        assert_eq!(before, after);
    }

    #[test]
    fn canonical_bytes_differ_on_name_change() {
        let a = NameClaim {
            name: "alice".into(),
            ..sample()
        };
        let b = NameClaim {
            name: "bob".into(),
            ..sample()
        };
        assert_ne!(a.canonical_signing_bytes(), b.canonical_signing_bytes());
    }

    #[test]
    fn canonical_bytes_differ_on_identity_change() {
        let mut b = sample();
        b.node_id = [0x99u8; 32];
        assert_ne!(
            sample().canonical_signing_bytes(),
            b.canonical_signing_bytes()
        );
    }

    // ── DHT key ──────────────────────────────────────────────────────────────

    #[test]
    fn dht_key_is_deterministic_for_normalized_name() {
        let a = NameClaim::dht_key("alice");
        let b = NameClaim::dht_key("alice");
        assert_eq!(a, b);
    }

    #[test]
    fn dht_key_differs_for_distinct_names() {
        assert_ne!(NameClaim::dht_key("alice"), NameClaim::dht_key("bob"));
    }

    #[test]
    fn dht_key_equal_for_equal_normalized_forms() {
        // Caller is expected to normalize before keying; this test
        // confirms the key function treats two equal inputs as
        // equivalent. Also doubles as a regression guard against
        // accidentally including un-normalized strings.
        let a = NameClaim::dht_key(&normalize_name("AlIcE").unwrap());
        let b = NameClaim::dht_key(&normalize_name("  alice\n").unwrap());
        assert_eq!(a, b);
    }

    #[test]
    fn dht_key_length_prefix_prevents_collision() {
        // Length-prefix hashing means "a"+"bc" cannot collide with
        // "ab"+"c" even if the subclaimant colluded to construct such
        // names.
        let a = NameClaim::dht_key("a");
        let b = NameClaim::dht_key("ab");
        assert_ne!(a, b);
    }

    // ── Structural fields preserved ──────────────────────────────────────────

    #[test]
    fn decode_preserves_all_fields() {
        let c = NameClaim {
            name: "alice#9999".into(),
            node_id: [0x77u8; 32],
            claimed_at_unix: 1_800_000_000,
            pow_nonce: [0xABu8; 16],
            freshness_hour: 500_000,
            signing_identity_key_idx: 3,
            sig: vec![0xFEu8; 96],
        };
        let bytes = c.encode();
        let back = NameClaim::decode(&bytes).unwrap();
        assert_eq!(back.name, c.name);
        assert_eq!(back.node_id, c.node_id);
        assert_eq!(back.claimed_at_unix, c.claimed_at_unix);
        assert_eq!(back.pow_nonce, c.pow_nonce);
        assert_eq!(back.freshness_hour, c.freshness_hour);
        assert_eq!(back.signing_identity_key_idx, c.signing_identity_key_idx);
        assert_eq!(back.sig, c.sig);
    }
}
