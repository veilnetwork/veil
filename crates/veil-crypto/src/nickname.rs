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

use std::sync::atomic::{AtomicBool, Ordering};

use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use veil_util::leading_zero_bits;

/// Max seeds kept in a record. The weight of one seed is `2^bits`, so the 64
/// heaviest seeds dominate any realistic contest while bounding record size.
pub const MAX_NICKNAME_SEEDS: usize = 64;

/// Wire magic identifying a [`NicknameRecord`] value in the DHT (first two
/// bytes of [`NicknameRecord::to_bytes`]). The dispatcher STORE gate routes
/// record kinds by this prefix. `b"NM"` — the design doc's kind tag — is
/// already taken on the value plane by the legacy `NameClaim` v2
/// (`veil_proto::name_claim_v2::NAME_CLAIM_MAGIC`), so nickname records use
/// `b"NK"`; the `NM` tag lives on in the key-derivation domain (see
/// [`nickname_dht_key`]).
pub const NICKNAME_DHT_MAGIC: [u8; 2] = *b"NK";

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
    if !(MIN_NICKNAME_LEN..=MAX_NICKNAME_LEN).contains(&len) {
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

/// The full 32-byte DHT key a nickname record is stored under:
/// `blake3("veil.nickname_dht.v1:NM" || nickname_key(name))` — the design's
/// `NM ‖ blake3(normalize(name))` with the kind tag folded into the hash
/// domain, matching every other record kind (`relay_directory_dht_key`,
/// `rendezvous_ad_dht_key`, `NameClaim::dht_key`, …). A literal `NM` byte
/// prefix would cluster ALL nickname keys in one corner of the Kademlia XOR
/// keyspace, concentrating every nickname on the same K-closest nodes; the
/// domain-hash keeps them uniformly spread. Returns `None` for an
/// un-normalizable name.
pub fn nickname_dht_key(name: &str) -> Option<[u8; 32]> {
    let body = nickname_key(name)?;
    let mut h = Hasher::new();
    h.update(b"veil.nickname_dht.v1:NM");
    h.update(&body);
    Some(*h.finalize().as_bytes())
}

/// Minimum cumulative weight a name of `char_len` must carry. Short names cost
/// exponentially more (3 chars ≫ 32 chars) — the anti-squatting floor. Every
/// verifier enforces the same curve, so retuning it is a consensus change —
/// only safe while no records are deployed.
pub fn length_weight_floor(char_len: usize) -> u64 {
    // Floor bits: 3→35, 4→31, 5→26, 6→22, 7→19, then -1/char from 16 down
    // to a base of 8 for long names. weight = 2^bits.
    //
    // Calibrated 2026-07-10 on a mid-range phone (release blake3 in the
    // app's mining chunks, ~2.8M hashes/s; observed cumulative weight ≈
    // 2.8 × hashes): 3 chars ≈ 1.2 h, 4 ≈ 5 min, 5 ≈ 9 s, 6 ≈ 0.5 s,
    // 7+ effectively instant — "short names cost hours, long names cost
    // seconds".
    let bits: u32 = match char_len {
        0..=3 => 35,
        4 => 31,
        5 => 26,
        6 => 22,
        7 => 19,
        n => 16u32.saturating_sub((n as u32).saturating_sub(8)).max(8),
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
fn cumulative_weight(name_norm: &str, owner_node_id: &[u8; 32], seeds: &[[u8; 32]]) -> Option<u64> {
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

/// Outcome of a [`mine_seeds`] run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MineOutcome {
    /// The heaviest seeds found (≤ [`MAX_NICKNAME_SEEDS`]).
    pub seeds: Vec<[u8; 32]>,
    /// Cumulative weight of [`Self::seeds`].
    pub weight: u64,
    /// Hashes actually computed (for progress / effort reporting).
    pub hashes_done: u64,
    /// Whether `target_weight` was reached (false = budget/cancel stopped it).
    pub hit_target: bool,
}

/// Mine PoW seeds for `name` under `owner_node_id`, keeping the heaviest
/// [`MAX_NICKNAME_SEEDS`] and stopping when their cumulative weight reaches
/// `target_weight`, `max_hashes` is spent, or `cancel` flips true.
///
/// `salt` seeds the search region so concurrent miners explore different
/// nonces (the FFI layer passes a random value; tests pass a fixed one). The
/// heavy loop is CPU-bound and MUST run off the UI isolate.
pub fn mine_seeds(
    name: &str,
    owner_node_id: &[u8; 32],
    target_weight: u64,
    max_hashes: u64,
    salt: u64,
    cancel: &AtomicBool,
) -> Option<MineOutcome> {
    mine_seeds_continue(
        name,
        owner_node_id,
        &[],
        target_weight,
        max_hashes,
        salt,
        cancel,
    )
}

/// Like [`mine_seeds`], but continues from a `prior` seed set — so a host can
/// mine in bounded chunks (each with a fresh random `salt`), threading the
/// running best set back in, and cancel simply by not calling again. Duplicate
/// or invalid prior seeds are dropped; the result is always a clean top-N set.
pub fn mine_seeds_continue(
    name: &str,
    owner_node_id: &[u8; 32],
    prior: &[[u8; 32]],
    target_weight: u64,
    max_hashes: u64,
    salt: u64,
    cancel: &AtomicBool,
) -> Option<MineOutcome> {
    let norm = normalize_name(name)?;
    let mut kept: Vec<(u64, [u8; 32])> = Vec::with_capacity(MAX_NICKNAME_SEEDS + 1);
    // Seed the working set from prior seeds (dedup by keeping the map keyed on
    // the seed bytes; recompute each weight so a caller can't inflate).
    for s in prior {
        if kept.iter().any(|(_, k)| k == s) {
            continue;
        }
        let w = seed_weight(&norm, owner_node_id, s);
        if w >= 2 {
            kept.push((w, *s));
        }
    }
    kept.sort_by_key(|item| std::cmp::Reverse(item.0));
    kept.truncate(MAX_NICKNAME_SEEDS);
    if !kept.is_empty() && kept.iter().map(|(w, _)| *w).sum::<u64>() >= target_weight {
        let weight = kept.iter().map(|(w, _)| *w).sum();
        return Some(MineOutcome {
            seeds: kept.into_iter().map(|(_, s)| s).collect(),
            weight,
            hashes_done: 0,
            hit_target: true,
        });
    }
    let mut hashes_done = 0u64;
    let mut counter = 0u64;
    let mut hit_target = false;
    while hashes_done < max_hashes {
        // Check cancellation every 4096 hashes — cheap, responsive.
        if counter & 0xFFF == 0 && cancel.load(Ordering::Relaxed) {
            break;
        }
        let mut seed = [0u8; 32];
        seed[0..8].copy_from_slice(&counter.to_le_bytes());
        seed[8..16].copy_from_slice(&salt.to_le_bytes());
        counter += 1;
        hashes_done += 1;
        let w = seed_weight(&norm, owner_node_id, &seed);
        if w < 2 {
            continue; // a bits=0 seed adds ~nothing to the cumulative weight
        }
        if kept.iter().any(|(_, k)| *k == seed) {
            continue; // never double-count a seed already kept (e.g. from prior)
        }
        kept.push((w, seed));
        kept.sort_by_key(|item| std::cmp::Reverse(item.0));
        kept.truncate(MAX_NICKNAME_SEEDS);
        if kept.iter().map(|(w, _)| *w).sum::<u64>() >= target_weight {
            hit_target = true;
            break;
        }
    }
    let weight = kept.iter().map(|(w, _)| *w).sum();
    Some(MineOutcome {
        seeds: kept.into_iter().map(|(_, s)| s).collect(),
        weight,
        hashes_done,
        hit_target,
    })
}

/// Bounds-checked little-endian byte reader for [`NicknameRecord::from_bytes`].
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.b.get(self.at..end)?;
        self.at = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }
    fn arr64(&mut self) -> Option<[u8; 64]> {
        self.take(64)?.try_into().ok()
    }
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

    /// Full wire encoding: the [`NICKNAME_DHT_MAGIC`] prefix, the canonical
    /// bytes, then the 64-byte signature. This is what crosses the FFI
    /// boundary and lands in the DHT (the dispatcher STORE gate dispatches on
    /// the magic). The magic is framing, not content — the signature covers
    /// [`Self::canonical_bytes`] only. Round-trips with [`Self::from_bytes`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 160 + self.pow_seeds.len() * 32);
        out.extend_from_slice(&NICKNAME_DHT_MAGIC);
        out.extend_from_slice(&self.canonical_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Parse a record from [`Self::to_bytes`]. Structural only — call
    /// [`Self::verify`] afterwards for cryptographic validity. Returns `None`
    /// on a missing/wrong magic prefix or any truncation / bad length prefix.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader { b: bytes, at: 0 };
        if r.take(2)? != NICKNAME_DHT_MAGIC {
            return None;
        }
        let version = r.u8()?;
        let name_len = r.u32()? as usize;
        let name = String::from_utf8(r.take(name_len)?.to_vec()).ok()?;
        let owner_node_id = r.arr32()?;
        let owner_sign_pk = r.arr32()?;
        let weight_kind = WeightKind::from_tag(r.u8()?)?;
        let weight = r.u64()?;
        let seed_count = r.u32()? as usize;
        if seed_count > MAX_NICKNAME_SEEDS {
            return None;
        }
        let mut pow_seeds = Vec::with_capacity(seed_count);
        for _ in 0..seed_count {
            pow_seeds.push(r.arr32()?);
        }
        let issued_at_unix = r.u64()?;
        let sig = r.arr64()?;
        if r.at != bytes.len() {
            return None; // trailing garbage
        }
        Some(NicknameRecord {
            version,
            name,
            owner_node_id,
            owner_sign_pk,
            weight_kind,
            weight,
            pow_seeds,
            issued_at_unix,
            sig,
        })
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

/// Outcome of the DHT STORE gate for a nickname key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreDecision {
    /// Store the incoming record (no valid incumbent, or it displaces one).
    Accept,
    /// Keep the incumbent — the incoming record does not displace it.
    RejectKeepExisting,
    /// The incoming record is itself invalid; do not store it.
    RejectInvalid,
}

/// The replace-on-heavier gate a DHT node applies when a STORE arrives for a
/// nickname key `NM || blake3(name)`. `incoming` is the serialized candidate;
/// `existing` is the currently-stored bytes for that key (None if empty).
///
/// - Invalid incoming (bad parse / signature / PoW / floor) → `RejectInvalid`.
/// - Incoming for a DIFFERENT name than the key implies is the caller's job to
///   check via [`nickname_key`]; this gate assumes the key matches the name.
/// - No valid incumbent (empty, junk, or a record for a different name) →
///   `Accept` (a valid record replaces nothing/garbage).
/// - Valid incumbent → `Accept` iff `incoming.displaces(existing)`.
pub fn nickname_store_decision(existing: Option<&[u8]>, incoming: &[u8]) -> StoreDecision {
    let Some(incoming_rec) = NicknameRecord::from_bytes(incoming) else {
        return StoreDecision::RejectInvalid;
    };
    if incoming_rec.verify().is_err() {
        return StoreDecision::RejectInvalid;
    }
    // Parse the incumbent; treat an unparseable/invalid/mismatched-name one as
    // "no valid incumbent" so a real record can always overwrite garbage.
    let valid_incumbent = existing
        .and_then(NicknameRecord::from_bytes)
        .filter(|r| r.verify().is_ok() && r.name == incoming_rec.name);
    match valid_incumbent {
        None => StoreDecision::Accept,
        Some(inc) => {
            if incoming_rec.displaces(&inc) {
                StoreDecision::Accept
            } else {
                StoreDecision::RejectKeepExisting
            }
        }
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
            kept.sort_by_key(|item| std::cmp::Reverse(item.0));
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
    fn dht_key_is_stable_normalized_and_distinct() {
        assert_eq!(nickname_dht_key("VART"), nickname_dht_key("  vart "));
        assert_ne!(nickname_dht_key("vart"), nickname_dht_key("varta"));
        // The full key is domain-separated from the bare name hash.
        assert_ne!(nickname_dht_key("vart"), nickname_key("vart"));
        assert!(nickname_dht_key("no").is_none());
    }

    #[test]
    fn wire_bytes_carry_magic_and_require_it() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let seeds = mine(name, &node_id, length_weight_floor(name.len()));
        let rec = NicknameRecord::sign(name, &sk, node_id, seeds, 1000).unwrap();
        let bytes = rec.to_bytes();
        assert_eq!(&bytes[..2], &NICKNAME_DHT_MAGIC[..]);
        // Stripping or corrupting the magic must fail the parse.
        assert!(NicknameRecord::from_bytes(&bytes[2..]).is_none());
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert!(NicknameRecord::from_bytes(&bad).is_none());
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
    fn miner_reaches_target_and_signs() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let target = length_weight_floor(name.len());
        let cancel = AtomicBool::new(false);
        let out = mine_seeds(name, &node_id, target, 5_000_000, 42, &cancel).unwrap();
        assert!(out.hit_target);
        assert!(out.weight >= target);
        assert!(out.seeds.len() <= MAX_NICKNAME_SEEDS);
        let rec = NicknameRecord::sign(name, &sk, node_id, out.seeds, 1000).unwrap();
        assert_eq!(rec.verify(), Ok(()));
    }

    #[test]
    fn miner_honors_cancel() {
        let (_sk, node_id) = test_key();
        let cancel = AtomicBool::new(true); // pre-cancelled
        let out = mine_seeds("longenoughname", &node_id, u64::MAX, 5_000_000, 1, &cancel).unwrap();
        assert!(!out.hit_target);
        // Cancel is checked at counter&0xFFF==0, so at most a few thousand hashes.
        assert!(out.hashes_done <= 4096);
    }

    #[test]
    fn miner_honors_hash_budget() {
        let (_sk, node_id) = test_key();
        let cancel = AtomicBool::new(false);
        // Impossible target, tiny budget → stops at the budget, not the target.
        let out = mine_seeds("longenoughname", &node_id, u64::MAX, 1000, 1, &cancel).unwrap();
        assert!(!out.hit_target);
        assert_eq!(out.hashes_done, 1000);
    }

    #[test]
    fn record_bytes_roundtrip() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let seeds = mine(name, &node_id, length_weight_floor(name.len()));
        let rec = NicknameRecord::sign(name, &sk, node_id, seeds, 1000).unwrap();
        let bytes = rec.to_bytes();
        let parsed = NicknameRecord::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, rec);
        assert_eq!(parsed.verify(), Ok(()));
    }

    #[test]
    fn from_bytes_rejects_truncated_and_trailing() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let seeds = mine(name, &node_id, length_weight_floor(name.len()));
        let rec = NicknameRecord::sign(name, &sk, node_id, seeds, 1000).unwrap();
        let bytes = rec.to_bytes();
        assert!(NicknameRecord::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(NicknameRecord::from_bytes(&extra).is_none());
    }

    #[test]
    fn store_gate_accepts_first_and_heavier() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let floor = length_weight_floor(name.len());
        let light =
            NicknameRecord::sign(name, &sk, node_id, mine(name, &node_id, floor), 1000).unwrap();
        let light_bytes = light.to_bytes();

        // First claim → accept (no incumbent).
        assert_eq!(
            nickname_store_decision(None, &light_bytes),
            StoreDecision::Accept,
        );

        // Same record again → keep existing (not strictly heavier/newer).
        assert_eq!(
            nickname_store_decision(Some(&light_bytes), &light_bytes),
            StoreDecision::RejectKeepExisting,
        );

        // Heavier record → accept (displaces).
        let heavy = NicknameRecord::sign(
            name,
            &sk,
            node_id,
            mine(name, &node_id, floor.saturating_mul(4)),
            500,
        )
        .unwrap();
        if heavy.weight > light.weight {
            assert_eq!(
                nickname_store_decision(Some(&light_bytes), &heavy.to_bytes()),
                StoreDecision::Accept,
            );
            // ...and the reverse (lighter over heavier) is rejected.
            assert_eq!(
                nickname_store_decision(Some(&heavy.to_bytes()), &light_bytes),
                StoreDecision::RejectKeepExisting,
            );
        }
    }

    #[test]
    fn store_gate_rejects_invalid_incoming() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let mut rec = NicknameRecord::sign(
            name,
            &sk,
            node_id,
            mine(name, &node_id, length_weight_floor(name.len())),
            1000,
        )
        .unwrap();
        rec.owner_node_id = [0u8; 32]; // breaks owner binding
        assert_eq!(
            nickname_store_decision(None, &rec.to_bytes()),
            StoreDecision::RejectInvalid,
        );
        assert_eq!(
            nickname_store_decision(None, b"not a record"),
            StoreDecision::RejectInvalid,
        );
    }

    #[test]
    fn store_gate_overwrites_garbage_incumbent() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let rec = NicknameRecord::sign(
            name,
            &sk,
            node_id,
            mine(name, &node_id, length_weight_floor(name.len())),
            1000,
        )
        .unwrap();
        // A valid record replaces junk / an unparseable incumbent.
        assert_eq!(
            nickname_store_decision(Some(b"garbage"), &rec.to_bytes()),
            StoreDecision::Accept,
        );
    }

    #[test]
    fn displacement_rules() {
        let (sk, node_id) = test_key();
        let name = "longenoughname";
        let floor = length_weight_floor(name.len());
        let light = mine(name, &node_id, floor);
        let base = NicknameRecord::sign(name, &sk, node_id, light.clone(), 1000).unwrap();

        // Same owner, newer timestamp, same weight → refresh displaces.
        let refreshed = NicknameRecord::sign(name, &sk, node_id, light, 2000).unwrap();
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
