//! Master-seed BIP-39 paper backup.
//!
//! The 32-byte `master_seed` is the single root-of-trust for an
//! veil sovereign identity. Losing it means permanent loss of
//! control over the identity. Exposing it to an attacker means full
//! account takeover. The design brief (`docs/identity-model.md`)
//! therefore mandates **two** storage channels:
//!
//! a mandatory 24-word paper backup (this module), encoded via the
//! standard BIP-39 English wordlist with SHA-256 checksum;
//! an optional encrypted file backup (see
//! [`identity_master_file`](super::master_file), b).
//!
//! 24 words of the standard BIP-39 English wordlist encode exactly 256
//! bits of entropy plus an 8-bit checksum — matching our `master_seed`
//! length. Keeping to the canonical word list means the phrase can
//! also be stored in any BIP-39-compatible hardware wallet as a
//! redundant cold backup.
//!
//! # Security notes
//!
//! Seed material is always wrapped [`Zeroizing`] so dropped
//! copies are wiped. Callers should avoid `clone` on the plain
//! byte arrays where possible — `Mnemonic` values returned by
//! [`encode_master_seed_to_phrase`] are themselves `Zeroize`-safe.
//! The checksum is verified on decode; a phrase with even one word
//! in the wrong position fails loudly rather than silently
//! producing a different seed.
//! Whitespace is normalised: leading/trailing spaces are stripped
//! and runs of internal whitespace collapse to a single space, so
//! hand-typed phrases don't fail over formatting.
//! Case is normalised to lowercase before lookup (the BIP-39
//! wordlist is all-lowercase).
//!
//! # Out of scope (user OpSec responsibility)
//!
//! Shoulder-surfing during display.
//! Phishing ("veil support asking for your phrase").
//! Phrases written on disk-cached clipboard, screenshot, or
//! camera-roll — we only guarantee the in-memory path is zeroed.
//!
//! See `docs/opsec-user-guide.md` for user-facing guidance.

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

/// Length of the master seed (32 bytes = 256 bits).
///
/// Matches [`crypto::identity::MASTER_SEED_LEN`] — redeclared here to
/// avoid a `crypto::*` import from a `cfg::*` module.
///
/// [`crypto::identity::MASTER_SEED_LEN`]: crate::crypto::identity::MASTER_SEED_LEN
pub const MASTER_SEED_LEN: usize = 32;

/// Number of words in our BIP-39 phrase (256-bit entropy + 8-bit
/// checksum → 264 bits = 24 × 11).
pub const MASTER_PHRASE_WORDS: usize = 24;

/// Errors raised while parsing or validating a user-entered phrase.
#[derive(Debug, thiserror::Error)]
pub enum MasterSeedError {
    #[error("master phrase must be {expected} words, got {actual}")]
    WrongWordCount { expected: usize, actual: usize },
    #[error("master phrase contains unknown word: {0}")]
    UnknownWord(String),
    #[error("master phrase checksum invalid")]
    ChecksumInvalid,
    #[error("master phrase bip39 error: {0}")]
    Bip39(String),
    #[error(
        "master seed must be {MASTER_SEED_LEN} bytes, got {0} — \
         BIP-39 v2 API surfaced an unexpected length"
    )]
    UnexpectedEntropyLength(usize),
    #[error(
        "extra-entropy buffer too short ({len} < {min}) — \
         supply at least {min} bytes from a high-entropy source"
    )]
    ExtraEntropyTooShort { len: usize, min: usize },
}

// ── Encoder / decoder ────────────────────────────────────────────────────────

/// Encode a 32-byte `master_seed` into a 24-word BIP-39 English mnemonic.
///
/// Callers typically display [`Mnemonic::to_string`] to the user and
/// immediately clear any intermediate buffers. The returned
/// `Mnemonic` owns zeroizing internal state; it wipes itself on drop.
pub fn encode_master_seed_to_phrase(
    seed: &[u8; MASTER_SEED_LEN],
) -> Result<Mnemonic, MasterSeedError> {
    Mnemonic::from_entropy_in(Language::English, seed)
        .map_err(|e| MasterSeedError::Bip39(e.to_string()))
}

/// Decode a BIP-39 English phrase back into the 32-byte `master_seed`.
///
/// The input is trimmed, case-normalised, and its whitespace collapsed
/// before parsing so that formatting differences (single vs double
/// spaces, trailing newline) do not cause spurious failures. The
/// checksum is verified against the last 8 bits of the entropy.
///
/// The result is wrapped [`Zeroizing`]; when it goes out of scope
/// the bytes are overwritten.
pub fn decode_master_seed_from_phrase(
    phrase: &str,
) -> Result<Zeroizing<[u8; MASTER_SEED_LEN]>, MasterSeedError> {
    let normalized = normalize_phrase(phrase);
    let word_count = normalized.split(' ').filter(|w| !w.is_empty()).count();
    if word_count != MASTER_PHRASE_WORDS {
        return Err(MasterSeedError::WrongWordCount {
            expected: MASTER_PHRASE_WORDS,
            actual: word_count,
        });
    }

    let mnemonic =
        Mnemonic::parse_in_normalized(Language::English, &normalized).map_err(|e| match e {
            bip39::Error::UnknownWord(idx) => {
                let word = normalized
                    .split(' ')
                    .filter(|w| !w.is_empty())
                    .nth(idx)
                    .unwrap_or("?")
                    .to_string();
                MasterSeedError::UnknownWord(word)
            }
            bip39::Error::InvalidChecksum => MasterSeedError::ChecksumInvalid,
            other => MasterSeedError::Bip39(other.to_string()),
        })?;

    let (entropy, len) = mnemonic.to_entropy_array();
    if len != MASTER_SEED_LEN {
        return Err(MasterSeedError::UnexpectedEntropyLength(len));
    }
    let mut seed = Zeroizing::new([0u8; MASTER_SEED_LEN]);
    seed.copy_from_slice(&entropy[..MASTER_SEED_LEN]);
    Ok(seed)
}

/// Canonical form of a user-typed phrase:
/// lowercase;
/// trimmed of leading/trailing whitespace;
/// internal whitespace collapsed to single spaces.
fn normalize_phrase(phrase: &str) -> String {
    phrase
        .split_whitespace()
        .map(|w| w.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

// ── Random generation ────────────────────────────────────────────────────────

/// Minimum size (in bytes) for a user-supplied extra-entropy file.
///
/// 32 B = the seed length itself. Less than that risks accidentally
/// downgrading entropy: if the file was supposed to add a quartet of
/// dice rolls (≈ 25 bits) but the user committed only those 4 bytes
/// to disk, the operator might believe they have "extra" entropy
/// while in fact they have *less* than the OS RNG provides. Refusing
/// short files surfaces the issue at create-time.
pub const MIN_EXTRA_ENTROPY_BYTES: usize = MASTER_SEED_LEN;

/// Generate a fresh 32-byte seed from the OS RNG.
///
/// Returns `Zeroizing<[u8; 32]>` so the bytes are wiped on drop even
/// if an intermediate callframe panics.
pub fn generate_master_seed() -> Zeroizing<[u8; MASTER_SEED_LEN]> {
    use rand_core::{OsRng, RngCore};
    let mut seed = Zeroizing::new([0u8; MASTER_SEED_LEN]);
    OsRng.fill_bytes(&mut *seed);
    seed
}

/// Generate a master seed using OS RNG **mixed with caller-supplied
/// extra entropy**.
///
/// For paranoid users who do not (fully) trust [`OsRng`]. Operators
/// generate `extra` from out-of-band sources — dice rolls, coin
/// flips, ambient audio — and feed it in. The function:
///
/// 1. Refuses any `extra` shorter than [`MIN_EXTRA_ENTROPY_BYTES`]
///    so an accidentally-short file cannot weaken security.
/// 2. Distils `extra` to 32 bytes via BLAKE3 (`veil.master.extra.v1`
///    domain key).
/// 3. Draws a fresh 32-byte block from `OsRng`.
/// 4. Returns `os ⊕ blake3(extra)` — XOR ensures the result is at
///    least as unpredictable as either input alone. An attacker
///    knowing one of `os` or `extra` learns nothing about the other.
///
/// Even if `OsRng` were silently broken (RNG backdoor scare), the
/// XOR-with-distilled-extra leaves the attacker facing the full
/// 256-bit search space of the user's chosen entropy. The reverse
/// also holds: a non-uniform user file (e.g. text from a book) is
/// still combined with truly-random OS bytes.
///
/// Output is wrapped [`Zeroizing`].
pub fn generate_master_seed_with_extra_entropy(
    extra: &[u8],
) -> Result<Zeroizing<[u8; MASTER_SEED_LEN]>, MasterSeedError> {
    if extra.len() < MIN_EXTRA_ENTROPY_BYTES {
        return Err(MasterSeedError::ExtraEntropyTooShort {
            len: extra.len(),
            min: MIN_EXTRA_ENTROPY_BYTES,
        });
    }
    // Distil to 32 bytes with a domain-keyed BLAKE3.
    let extra_distilled: [u8; 32] = *blake3::Hasher::new_keyed(&MASTER_EXTRA_DOMAIN_KEY)
        .update(extra)
        .finalize()
        .as_bytes();

    let os_seed = generate_master_seed();
    let mut combined = Zeroizing::new([0u8; MASTER_SEED_LEN]);
    for i in 0..MASTER_SEED_LEN {
        combined[i] = os_seed[i] ^ extra_distilled[i];
    }
    Ok(combined)
}

/// 32-byte BLAKE3 keyed-hash key for distilling extra entropy. A
/// fixed domain string reduces to a 32-byte key via BLAKE3
/// `derive_key`-style usage and is hard-coded so two devices that
/// both run [`generate_master_seed_with_extra_entropy`] using the
/// same source `extra` agree on the distilled value (useful for
/// recoverable-by-design backups, though the typical use is
/// per-device).
const MASTER_EXTRA_DOMAIN_KEY: [u8; 32] = {
    // BLAKE3 derive_key("veil.master.extra.v1", &[]) computed
    // offline and pinned here. The companion test
    // `master_extra_domain_key_matches_blake3_derive_key` re-runs
    // the derivation at test time and asserts equality, so any
    // BLAKE3 ABI shift is caught immediately.
    [
        80, 8, 18, 92, 74, 254, 103, 126, 5, 67, 190, 166, 136, 75, 48, 77, 143, 111, 133, 193, 79,
        28, 233, 124, 141, 208, 195, 71, 245, 240, 130, 103,
    ]
};

// ── Interactive-confirmation helper ──────────────────────────────────────────

/// Pick `n` random word positions the user must retype to prove the
/// phrase has been written down.
///
/// Returns a sorted list of 1-based positions. CLI flow
/// displays the phrase, then shows e.g.
/// `"Retype words at positions 4, 11, and 19:"`. The user typing
/// back the actual BIP-39 words at those positions proves they made
/// a durable copy.
pub fn pick_confirmation_positions(n: usize) -> Vec<usize> {
    use rand_core::{OsRng, RngCore};
    let n = n.min(MASTER_PHRASE_WORDS);
    let mut picked = Vec::with_capacity(n);
    while picked.len() < n {
        // Rejection sampling: draw u32 then mod 24, discard duplicates.
        let mut buf = [0u8; 4];
        OsRng.fill_bytes(&mut buf);
        let idx = (u32::from_le_bytes(buf) as usize % MASTER_PHRASE_WORDS) + 1;
        if !picked.contains(&idx) {
            picked.push(idx);
        }
    }
    picked.sort_unstable();
    picked
}

/// Verify the user's answers to a confirmation challenge.
///
/// `answers` is the user-supplied list of `(position, word)` tuples.
/// Returns `true` iff for every `(pos, word)` the word at 1-based
/// `pos` of `expected_phrase` matches `word` (case-insensitive
/// whitespace-trimmed). A non-matching pair — or any missing/extra
/// pair relative to `expected_positions` — returns `false`.
pub fn verify_confirmation_answers(
    expected_phrase: &Mnemonic,
    expected_positions: &[usize],
    answers: &[(usize, String)],
) -> bool {
    if expected_positions.len() != answers.len() {
        return false;
    }
    let words: Vec<&str> = expected_phrase.words().collect();
    let mut supplied = std::collections::HashMap::with_capacity(answers.len());
    for (pos, word) in answers {
        if supplied
            .insert(*pos, word.trim().to_ascii_lowercase())
            .is_some()
        {
            return false;
        }
    }
    for pos in expected_positions {
        let Some(user_word) = supplied.get(pos) else {
            return false;
        };
        let Some(expected_word) = words.get(pos.saturating_sub(1)) else {
            return false;
        };
        if user_word != expected_word {
            return false;
        }
    }
    true
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_zero_seed() {
        let seed = [0u8; MASTER_SEED_LEN];
        let phrase = encode_master_seed_to_phrase(&seed).unwrap();
        assert_eq!(phrase.word_count(), MASTER_PHRASE_WORDS);
        let decoded = decode_master_seed_from_phrase(&phrase.to_string()).unwrap();
        assert_eq!(&*decoded, &seed);
    }

    #[test]
    fn roundtrip_all_ones_seed() {
        let seed = [0xFFu8; MASTER_SEED_LEN];
        let phrase = encode_master_seed_to_phrase(&seed).unwrap();
        let decoded = decode_master_seed_from_phrase(&phrase.to_string()).unwrap();
        assert_eq!(&*decoded, &seed);
    }

    #[test]
    fn roundtrip_arbitrary_seed() {
        let mut seed = [0u8; MASTER_SEED_LEN];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i * 7 + 11) as u8;
        }
        let phrase = encode_master_seed_to_phrase(&seed).unwrap();
        let decoded = decode_master_seed_from_phrase(&phrase.to_string()).unwrap();
        assert_eq!(&*decoded, &seed);
    }

    #[test]
    fn encoding_is_deterministic() {
        let seed = [0x42u8; MASTER_SEED_LEN];
        let a = encode_master_seed_to_phrase(&seed).unwrap().to_string();
        let b = encode_master_seed_to_phrase(&seed).unwrap().to_string();
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_produce_different_phrases() {
        let a = encode_master_seed_to_phrase(&[0u8; MASTER_SEED_LEN])
            .unwrap()
            .to_string();
        let b = encode_master_seed_to_phrase(&[1u8; MASTER_SEED_LEN])
            .unwrap()
            .to_string();
        assert_ne!(a, b);
    }

    #[test]
    fn phrase_has_exactly_24_words() {
        let seed = [0x99u8; MASTER_SEED_LEN];
        let phrase = encode_master_seed_to_phrase(&seed).unwrap();
        assert_eq!(phrase.word_count(), 24);
        assert_eq!(phrase.to_string().split_whitespace().count(), 24);
    }

    #[test]
    fn accepts_mixed_case_input() {
        let seed = [0x33u8; MASTER_SEED_LEN];
        let phrase = encode_master_seed_to_phrase(&seed).unwrap().to_string();
        let upper = phrase.to_uppercase();
        let decoded = decode_master_seed_from_phrase(&upper).unwrap();
        assert_eq!(&*decoded, &seed);
    }

    #[test]
    fn accepts_extra_whitespace_and_newlines() {
        let seed = [0x77u8; MASTER_SEED_LEN];
        let phrase = encode_master_seed_to_phrase(&seed).unwrap().to_string();
        // Split on spaces and rejoin with varied whitespace.
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let messy = format!("  {}\n", words.join("   \t  "));
        let decoded = decode_master_seed_from_phrase(&messy).unwrap();
        assert_eq!(&*decoded, &seed);
    }

    #[test]
    fn rejects_wrong_word_count_too_few() {
        // 23 words of a valid 24-word phrase.
        let phrase = encode_master_seed_to_phrase(&[0u8; MASTER_SEED_LEN])
            .unwrap()
            .to_string();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let truncated = words[..23].join(" ");
        let err = decode_master_seed_from_phrase(&truncated).unwrap_err();
        assert!(matches!(
            err,
            MasterSeedError::WrongWordCount {
                expected: 24,
                actual: 23
            }
        ));
    }

    #[test]
    fn rejects_wrong_word_count_too_many() {
        let phrase = encode_master_seed_to_phrase(&[0u8; MASTER_SEED_LEN])
            .unwrap()
            .to_string();
        let extended = format!("{phrase} abandon");
        let err = decode_master_seed_from_phrase(&extended).unwrap_err();
        assert!(matches!(err, MasterSeedError::WrongWordCount { .. }));
    }

    #[test]
    fn rejects_unknown_word() {
        // Replace first word with a non-wordlist token.
        let phrase = encode_master_seed_to_phrase(&[0u8; MASTER_SEED_LEN])
            .unwrap()
            .to_string();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let mut bogus = vec!["xyzzy".to_string()];
        bogus.extend(words.iter().skip(1).map(|s| s.to_string()));
        let bogus_phrase = bogus.join(" ");
        let err = decode_master_seed_from_phrase(&bogus_phrase).unwrap_err();
        assert!(
            matches!(err, MasterSeedError::UnknownWord(ref w) if w == "xyzzy"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_phrase_with_wrong_checksum() {
        // Swap two adjacent words — high probability of invalidating
        // the SHA-256 checksum while leaving every word valid.
        let seed = [0x12u8; MASTER_SEED_LEN];
        let phrase = encode_master_seed_to_phrase(&seed).unwrap().to_string();
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        words.swap(0, 23);
        let tampered = words.join(" ");
        let err = decode_master_seed_from_phrase(&tampered).unwrap_err();
        assert!(matches!(err, MasterSeedError::ChecksumInvalid), "{err:?}");
    }

    #[test]
    fn seed_is_zeroized_on_drop() {
        // Smoke test: the returned Zeroizing<[u8;32]> compiles and
        // drops cleanly. We can't assert the post-drop memory state
        // directly in safe Rust, but the type guarantees the wipe —
        // this test exists to lock in the Zeroizing return type so a
        // refactor that accidentally strips it fails the build.
        let seed: Zeroizing<[u8; MASTER_SEED_LEN]> = generate_master_seed();
        drop(seed);
    }

    #[test]
    fn generate_master_seed_is_non_trivial() {
        // Two consecutive RNG draws must differ. Probability of
        // collision is 2^-256 — well below any practical concern.
        let a = generate_master_seed();
        let b = generate_master_seed();
        assert_ne!(&*a, &*b);
    }

    #[test]
    fn pick_confirmation_positions_returns_distinct_sorted() {
        for _ in 0..32 {
            let pos = pick_confirmation_positions(5);
            assert_eq!(pos.len(), 5);
            assert!(pos.iter().all(|&p| (1..=MASTER_PHRASE_WORDS).contains(&p)));
            assert_eq!(
                pos.len(),
                pos.iter().collect::<std::collections::HashSet<_>>().len(),
                "positions must be distinct",
            );
            let mut sorted = pos.clone();
            sorted.sort_unstable();
            assert_eq!(pos, sorted, "positions must be returned sorted");
        }
    }

    #[test]
    fn pick_confirmation_positions_clamps_n_to_phrase_length() {
        let pos = pick_confirmation_positions(100);
        assert_eq!(pos.len(), MASTER_PHRASE_WORDS);
    }

    #[test]
    fn verify_confirmation_answers_accepts_exact_match() {
        let seed = [0x55u8; MASTER_SEED_LEN];
        let phrase = encode_master_seed_to_phrase(&seed).unwrap();
        let words: Vec<&str> = phrase.words().collect();
        let positions = vec![1, 5, 17];
        let answers: Vec<(usize, String)> = positions
            .iter()
            .map(|&p| (p, words[p - 1].to_string()))
            .collect();
        assert!(verify_confirmation_answers(&phrase, &positions, &answers));
    }

    #[test]
    fn verify_confirmation_answers_rejects_wrong_word() {
        let seed = [0x55u8; MASTER_SEED_LEN];
        let phrase = encode_master_seed_to_phrase(&seed).unwrap();
        let positions = vec![1, 5];
        let answers = vec![(1, "wrongword".to_string()), (5, "alsowrong".to_string())];
        assert!(!verify_confirmation_answers(&phrase, &positions, &answers));
    }

    #[test]
    fn verify_confirmation_answers_rejects_missing_position() {
        let seed = [0x55u8; MASTER_SEED_LEN];
        let phrase = encode_master_seed_to_phrase(&seed).unwrap();
        let words: Vec<&str> = phrase.words().collect();
        let positions = vec![1, 5, 17];
        let answers = vec![(1, words[0].to_string()), (5, words[4].to_string())];
        assert!(!verify_confirmation_answers(&phrase, &positions, &answers));
    }

    #[test]
    fn verify_confirmation_answers_rejects_duplicate_positions() {
        let seed = [0x55u8; MASTER_SEED_LEN];
        let phrase = encode_master_seed_to_phrase(&seed).unwrap();
        let words: Vec<&str> = phrase.words().collect();
        let positions = vec![1, 5];
        let answers = vec![(1, words[0].to_string()), (1, words[0].to_string())];
        assert!(!verify_confirmation_answers(&phrase, &positions, &answers));
    }

    #[test]
    fn verify_confirmation_answers_case_insensitive() {
        let seed = [0x66u8; MASTER_SEED_LEN];
        let phrase = encode_master_seed_to_phrase(&seed).unwrap();
        let words: Vec<&str> = phrase.words().collect();
        let positions = vec![3];
        let answers = vec![(3, words[2].to_uppercase())];
        assert!(verify_confirmation_answers(&phrase, &positions, &answers));
    }

    #[test]
    fn generated_seed_roundtrips_through_phrase() {
        let seed = generate_master_seed();
        let phrase = encode_master_seed_to_phrase(&seed).unwrap();
        let decoded = decode_master_seed_from_phrase(&phrase.to_string()).unwrap();
        assert_eq!(*seed, *decoded);
    }

    // ── Extra entropy ──────────────────────────────────────────

    #[test]
    fn extra_entropy_rejects_short_input() {
        let err = generate_master_seed_with_extra_entropy(&[0u8; 31]).unwrap_err();
        assert!(
            matches!(
                err,
                MasterSeedError::ExtraEntropyTooShort { len: 31, min: 32 }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn extra_entropy_accepts_exactly_minimum_length() {
        let seed = generate_master_seed_with_extra_entropy(&[0xABu8; 32]).unwrap();
        assert_eq!(seed.len(), MASTER_SEED_LEN);
    }

    #[test]
    fn extra_entropy_accepts_long_input() {
        // 1 KiB of repeated pattern — distillation collapses to 32 B.
        let seed = generate_master_seed_with_extra_entropy(&[0x42u8; 1024]).unwrap();
        assert_eq!(seed.len(), MASTER_SEED_LEN);
    }

    #[test]
    fn extra_entropy_two_calls_differ() {
        // OsRng adds fresh randomness on each call, so even with the
        // same `extra` we expect distinct seeds.
        let a = generate_master_seed_with_extra_entropy(&[0u8; 32]).unwrap();
        let b = generate_master_seed_with_extra_entropy(&[0u8; 32]).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn extra_entropy_xor_inverts_to_distilled_extra_for_known_os() {
        // Property check: if we run the function and grab the OS-side
        // bytes by XOR-ing back the distilled extra, those reconstructed
        // OS bytes should themselves look random (specifically they
        // shouldn't equal `[0u8; 32]` — which would mean OsRng silently
        // returned all zeros, an extreme failure mode). This is a
        // smoke test against an obvious malfunction.
        let extra = [0xAAu8; 64];
        let distilled = blake3::Hasher::new_keyed(&MASTER_EXTRA_DOMAIN_KEY)
            .update(&extra)
            .finalize();
        let combined = generate_master_seed_with_extra_entropy(&extra).unwrap();
        let mut reconstructed_os = [0u8; MASTER_SEED_LEN];
        for i in 0..MASTER_SEED_LEN {
            reconstructed_os[i] = combined[i] ^ distilled.as_bytes()[i];
        }
        assert_ne!(reconstructed_os, [0u8; MASTER_SEED_LEN]);
    }

    #[test]
    fn extra_entropy_distillation_is_deterministic_given_input() {
        // Distil twice — must produce identical 32-byte output.
        let extra = b"the quick brown fox jumps over the lazy dog twice";
        let a = blake3::Hasher::new_keyed(&MASTER_EXTRA_DOMAIN_KEY)
            .update(extra)
            .finalize();
        let b = blake3::Hasher::new_keyed(&MASTER_EXTRA_DOMAIN_KEY)
            .update(extra)
            .finalize();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn master_extra_domain_key_matches_blake3_derive_key() {
        // Pin the hard-coded MASTER_EXTRA_DOMAIN_KEY against the live
        // BLAKE3 derive_key result. If a future BLAKE3 ABI change
        // alters the derived bytes, this test catches it before the
        // mismatch causes silent operator-visible rerolls.
        let derived = blake3::derive_key("veil.master.extra.v1", &[]);
        assert_eq!(derived, MASTER_EXTRA_DOMAIN_KEY);
    }

    #[test]
    fn extra_entropy_seed_roundtrips_through_phrase() {
        let seed = generate_master_seed_with_extra_entropy(&[0xCDu8; 64]).unwrap();
        let phrase = encode_master_seed_to_phrase(&seed).unwrap();
        let decoded = decode_master_seed_from_phrase(&phrase.to_string()).unwrap();
        assert_eq!(*seed, *decoded);
    }
}
