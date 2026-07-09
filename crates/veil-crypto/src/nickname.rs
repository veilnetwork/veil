//! Human-readable nicknames over veil — record format, cumulative
//! displaceable proof-of-work, and verification.
//!
//! Design: `doc/NICKNAMES-DESIGN.md` in the host app (xVeil). A nickname is
//! a `NM || blake3(normalize(name))`-keyed DHT record owned by a SOVEREIGN
//! identity (so a name survives device changes). Ownership is contestable by
//! WEIGHT: a heavier cumulative proof-of-work displaces the incumbent, and
//! short names carry a higher per-length weight FLOOR (anti-squatting without
//! a central authority).
//!
//! This module is deliberately self-contained and network-free: it defines
//! the record, its canonical bytes, ed25519 signing, and the PoW weight math,
//! all unit-tested in isolation. Wiring it into the DHT (a new record kind,
//! resolve/publish, the conflict-replace rule) is a later brick.

use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use veil_util::leading_zero_bits;

/// Max seeds kept in a record. The weight of one seed is `2^bits`, so the 64
/// heaviest seeds dominate any realistic contest while bounding record size.
pub const MAX_NICKNAME_SEEDS: usize = 64;

/// Name length bounds (normalized).
pub const MIN_NICKNAME_LEN: usize = 3;
pub const MAX_NICKNAME_LEN: usize = 32;

/// Record format version (weight math + canonical bytes). Bumped on any
/// change that alters verification.
pub const NICKNAME_RECORD_VERSION: u8 = 1;

/// Source of a record's ownership weight. Forward-compatible with a future
/// cryptocurrency stake — a stake simply becomes a heavier weight class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightKind {
    /// blake3 leading-zero-bit proof-of-work, weight = Σ 2^bits per seed.
    PowV1,
}

impl WeightKind {
    pub fn tag(self) -> u8 {
        match self {
            WeightKind::PowV1 => 0,
        }
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(WeightKind::PowV1),
            _ => None,
        }
    }
}

/// Why a record failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NicknameError {
    /// Name is not valid normalized form (length or charset).
    BadName,
    /// `owner_node_id != blake3(owner_sign_pk)`.
    OwnerMismatch,
    /// ed25519 signature does not verify.
    BadSignature,
    /// Recomputed cumulative weight is less than the claimed `weight`, or
    /// duplicate/oversized seed list.
    BadPow,
    /// Claimed weight is below this name-length's floor.
    UnderLengthFloor,
    /// Unknown version / weight kind.
    Unsupported,
}

/// A signed nickname ownership record. `sig` covers [`Self::canonical_bytes`]
/// (everything except the signature itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicknameRecord {
    pub version: u8,
    /// Normalized name (see [`normalize_name`]).
    pub name: String,
    /// Sovereign node id: MUST equal `blake3(owner_sign_pk)`.
    pub owner_node_id: [u8; 32],
    /// ed25519 verifying key of the owner.
    pub owner_sign_pk: [u8; 32],
    pub weight_kind: WeightKind,
    /// CUMULATIVE claimed weight (Σ 2^bits over `pow_seeds`).
    pub weight: u64,
    /// Nonce seeds proving `weight`. At most [`MAX_NICKNAME_SEEDS`].
    pub pow_seeds: Vec<[u8; 32]>,
    /// Unix seconds — freshness for a same-owner refresh (no re-mine).
    pub issued_at_unix: u64,
    /// ed25519 signature over the canonical bytes.
    pub sig: [u8; 64],
}

/// Normalize a candidate name to canonical form, or `None` if it cannot be:
/// ASCII lowercased, only `[a-z0-9_]`, length in
/// `[MIN_NICKNAME_LEN, MAX_NICKNAME_LEN]`.
///
/// v1 is deliberately ASCII-only (no Unicode confusables to reason about);
/// widening the charset is a versioned change.
pub fn normalize_name(input: &str) -> Option<String> {
    let lowered: String = input.trim().to_ascii_lowercase();
    let len = lowered.chars().count();
    if len < MIN_NICKNAME_LEN || len > MAX_NICKNAME_LEN {
        return None;
    }
    if !lowered
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    Some(lowered)
}

/// The DHT key body for a name: `blake3(normalize(name))`. Callers prefix the
/// record-kind tag (`NM`). Returns `None` for an un-normalizable name.
pub fn nickname_key(name: &str) -> Option<[u8; 32]> {
    let norm = normalize_name(name)?;
    Some(*blake3::hash(norm.as_bytes()).as_bytes())
}

/// Minimum cumulative weight a name of `char_len` must carry. Short names cost
/// exponentially more (3 chars ≫ 32 chars) — the anti-squatting floor. Tuned
/// modestly for v1; every verifier enforces the same curve.
pub fn length_weight_floor(char_len: usize) -> u64 {
    // Floor bits: 3→28, 4→24, 5→20, 6→18, 7→16, then -1/char down to a base
    // of 8 for long names. weight = 2^bits.
    let bits: u32 = match char_len {
        0..=3 => 28,
        4 => 24,
        5 => 20,
        6 => 18,
        7 => 16,
        n => 16u32.saturating_sub((n as u32).saturating_sub(7)).max(8),
    };
    1u64 << bits
}

/// Weight contributed by one PoW seed: `2^leading_zero_bits(h)` where
/// `h = blake3(name_norm || owner_node_id || seed)`.
pub fn seed_weight(name_norm: &str, owner_node_id: &[u8; 32], seed: &[u8; 32]) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(name_norm.as_bytes());
    hasher.update(owner_node_id);
    hasher.update(seed);
    let bits = leading_zero_bits(hasher.finalize().as_bytes());
    // Cap the exponent so a freak hash can't overflow the running sum.
    1u64 << bits.min(63)
}

/// Sum of seed weights, or `None` on a duplicate/oversized seed list (which a
/// verifier must reject rather than silently under-count).
fn cumulative_weight(
    name_norm: &str,
    owner_node_id: &[u8; 32],
    seeds: &[[u8; 32]],
) -> Option<u64> {
    if seeds.len() > MAX_NICKNAME_SEEDS {
        return None;
    }
    // Reject duplicate seeds (double-counting the same work).
    let mut seen = seeds.to_vec();
    seen.sort_unstable();
    seen.dedup();
    if seen.len() != seeds.len() {
        return None;
    }
    let mut total: u64 = 0;
    for s in seeds {
        total = total.saturating_add(seed_weight(name_norm, owner_node_id, s));
    }
    Some(total)
}

impl NicknameRecord {
    /// Deterministic bytes covered by [`Self::sig`]. Every field except the
    /// signature, length-prefixed so no two distinct records share bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160 + self.pow_seeds.len() * 32);
        out.push(self.version);
        let name = self.name.as_bytes();
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&self.owner_node_id);
        out.extend_from_slice(&self.owner_sign_pk);
        out.push(self.weight_kind.tag());
        out.extend_from_slice(&self.weight.to_le_bytes());
        out.extend_from_slice(&(self.pow_seeds.len() as u32).to_le_bytes());
        for s in &self.pow_seeds {
            out.extend_from_slice(s);
        }
        out.extend_from_slice(&self.issued_at_unix.to_le_bytes());
        out
    }

    /// Build and sign a record for an already-mined seed set. `signing_key` is
    /// the owner's sovereign ed25519 key; `owner_node_id` MUST be
    /// `blake3(verifying_key)` (asserted at verify time).
    pub fn sign(
        name: &str,
        signing_key: &SigningKey,
        owner_node_id: [u8; 32],
        pow_seeds: Vec<[u8; 32]>,
        issued_at_unix: u64,
    ) -> Option<Self> {
        let norm = normalize_name(name)?;
        let weight = cumulative_weight(&norm, &owner_node_id, &pow_seeds)?;
        let mut rec = NicknameRecord {
            version: NICKNAME_RECORD_VERSION,
            name: norm,
            owner_node_id,
            owner_sign_pk: signing_key.verifying_key().to_bytes(),
            weight_kind: WeightKind::PowV1,
            weight,
            pow_seeds,
            issued_at_unix,
            sig: [0u8; 64],
        };
        let sig: Signature = signing_key.sign(&rec.canonical_bytes());
        rec.sig = sig.to_bytes();
        Some(rec)
    }

    /// Full validity check: version, name form, owner binding, signature,
    /// recomputed weight ≥ claimed, and the length floor.
    pub fn verify(&self) -> Result<(), NicknameError> {
        if self.version != NICKNAME_RECORD_VERSION {
            return Err(NicknameError::Unsupported);
        }
        if self.weight_kind != WeightKind::PowV1 {
            return Err(NicknameError::Unsupported);
        }
        let norm = normalize_name(&self.name).ok_or(NicknameError::BadName)?;
        if norm != self.name {
            return Err(NicknameError::BadName);
        }
        // Owner binding: node id is blake3 of the signing pubkey.
        if *blake3::hash(&self.owner_sign_pk).as_bytes() != self.owner_node_id {
            return Err(NicknameError::OwnerMismatch);
        }
        // Signature over the canonical bytes.
        let vk = VerifyingKey::from_bytes(&self.owner_sign_pk)
            .map_err(|_| NicknameError::BadSignature)?;
        let sig = Signature::from_bytes(&self.sig);
        vk.verify(&self.canonical_bytes(), &sig)
            .map_err(|_| NicknameError::BadSignature)?;
        // Cumulative PoW must actually back the claimed weight.
        let recomputed = cumulative_weight(&norm, &self.owner_node_id, &self.pow_seeds)
            .ok_or(NicknameError::BadPow)?;
        if recomputed < self.weight {
            return Err(NicknameError::BadPow);
        }
        // Per-length anti-squatting floor.
        if self.weight < length_weight_floor(norm.chars().count()) {
            return Err(NicknameError::UnderLengthFloor);
        }
        Ok(())
    }

    /// Conflict rule: does `self` REPLACE `incumbent` for the same name?
    /// A heavier valid record wins; a same-owner record with a newer
    /// `issued_at_unix` refreshes without re-mining. Ties keep the incumbent.
    /// Caller has already verified both and confirmed equal names.
    pub fn displaces(&self, incumbent: &NicknameRecord) -> bool {
        if self.weight > incumbent.weight {
            return true;
        }
        self.owner_node_id == incumbent.owner_node_id
            && self.weight == incumbent.weight
            && self.issued_at_unix > incumbent.issued_at_unix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let node_id = *blake3::hash(&sk.verifying_key().to_bytes()).as_bytes();
        (sk, node_id)
    }

    /// Mine seeds until the top-[`MAX_NICKNAME_SEEDS`] cumulative weight clears
    /// `target` (test-only; real mining lives in the FFI worker). Keeps only
    /// the heaviest seeds — mirroring the real record cap — so a higher target
    /// yields a genuinely heavier record. Bounded so a test can't spin forever.
    fn mine(name: &str, owner: &[u8; 32], target: u64) -> Vec<[u8; 32]> {
        let norm = normalize_name(name).unwrap();
        let mut kept: Vec<(u64, [u8; 32])> = Vec::new();
        let mut n = 0u64;
        while n < 5_000_000 {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&n.to_le_bytes());
            n += 1;
            let w = seed_weight(&norm, owner, &seed);
            if w < 2 {
                continue; // a bits=0 seed adds ~nothing; skip to converge fast
            }
            kept.push((w, seed));
            kept.sort_by(|a, b| b.0.cmp(&a.0));
            kept.truncate(MAX_NICKNAME_SEEDS);
            if kept.iter().map(|(w, _)| *w).sum::<u64>() >= target {
                break;
            }
        }
        kept.into_iter().map(|(_, s)| s).collect()
    }

    #[test]
    fn normalize_rules() {
        assert_eq!(normalize_name("  VART  ").as_deref(), Some("vart"));
        assert_eq!(normalize_name("a_b_9").as_deref(), Some("a_b_9"));
        assert_eq!(normalize_name("ab"), None); // too short
        assert_eq!(normalize_name("has space"), None);
        assert_eq!(normalize_name("emoji😀x"), None);
        assert_eq!(normalize_name(&"x".repeat(33)), None); // too long
    }

    #[test]
    fn key_is_stable_and_normalized() {
        assert_eq!(nickname_key("VART"), nickname_key("  vart "));
        assert!(nickname_key("no").is_none());
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (sk, node_id) = test_key();
        let name = "longenoughname"; // long → low floor, easy to satisfy
        let seeds = mine(name, &node_id, length_weight_floor(name.len()));
        let rec = NicknameRecord::sign(name, &sk, node_id, seeds, 1000).unwrap();
        assert_eq!(rec.verify(), Ok(()));
    }

    #[test]
    fn tampered_name_fails_owner_or_sig() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let seeds = mine(name, &node_id, length_weight_floor(name.len()));
        let mut rec = NicknameRecord::sign(name, &sk, node_id, seeds, 1000).unwrap();
        rec.name = "differentname".into();
        assert_eq!(rec.verify(), Err(NicknameError::BadSignature));
    }

    #[test]
    fn wrong_owner_node_id_rejected() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let seeds = mine(name, &node_id, length_weight_floor(name.len()));
        let mut rec = NicknameRecord::sign(name, &sk, node_id, seeds, 1000).unwrap();
        rec.owner_node_id = [9u8; 32]; // no longer blake3(pubkey)
        assert_eq!(rec.verify(), Err(NicknameError::OwnerMismatch));
    }

    #[test]
    fn inflated_weight_rejected() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let seeds = mine(name, &node_id, length_weight_floor(name.len()));
        let mut rec = NicknameRecord::sign(name, &sk, node_id, seeds, 1000).unwrap();
        // Claim more than the seeds prove, then re-sign so only the PoW check
        // (not the signature) is what rejects it.
        rec.weight = rec.weight.saturating_mul(4);
        let sig = sk.sign(&rec.canonical_bytes());
        rec.sig = sig.to_bytes();
        assert_eq!(rec.verify(), Err(NicknameError::BadPow));
    }

    #[test]
    fn duplicate_seeds_rejected() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let mut seeds = mine(name, &node_id, length_weight_floor(name.len()));
        if let Some(first) = seeds.first().copied() {
            seeds.push(first); // duplicate → double-count attempt
        }
        // sign() itself refuses to build a record from a duplicate seed list.
        assert!(NicknameRecord::sign(name, &sk, node_id, seeds, 1000).is_none());
    }

    #[test]
    fn short_name_under_floor_rejected() {
        let (sk, node_id) = test_key();
        // A 4-char name needs a high floor; a single weak seed won't clear it.
        let name = "vart";
        let weak = vec![[0u8; 32]];
        // May be None (weight 0) or a record under floor — either way not valid.
        match NicknameRecord::sign(name, &sk, node_id, weak, 1000) {
            None => {}
            Some(rec) => assert_eq!(rec.verify(), Err(NicknameError::UnderLengthFloor)),
        }
    }

    #[test]
    fn displacement_rules() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let floor = length_weight_floor(name.len());
        let light = mine(name, &node_id, floor);
        let base = NicknameRecord::sign(name, &sk, node_id, light.clone(), 1000).unwrap();

        // Same owner, newer timestamp, same weight → refresh displaces.
        let refreshed =
            NicknameRecord::sign(name, &sk, node_id, light, 2000).unwrap();
        assert!(refreshed.displaces(&base));
        assert!(!base.displaces(&refreshed));

        // Heavier record displaces regardless of owner.
        let heavy_seeds = mine(name, &node_id, floor.saturating_mul(4));
        let heavy = NicknameRecord::sign(name, &sk, node_id, heavy_seeds, 500).unwrap();
        if heavy.weight > base.weight {
            assert!(heavy.displaces(&base));
        }
    }
}
