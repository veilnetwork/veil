//! Per-instance prekey bundle for X3DH-style forward secrecy
//!
//!
//! Each device publishes a small pool of one-time ML-KEM-768
//! encapsulation keys plus a single fallback key. A sender wishing
//! to deliver an asynchronous (recipient-offline) message:
//!
//! 1. Fetches the current `PrekeyBundle` for the recipient identity
//! from the DHT.
//! 2. Picks an unused one-time prekey (or the fallback if the pool
//! is exhausted).
//! 3. ML-KEM-encapsulates against that prekey, derives the session
//! key from the resulting shared secret, encrypts the ciphertext.
//! 4. Marks the chosen `prekey_id` as consumed.
//!
//! The recipient, on first read of that ciphertext:
//!
//! 1. Looks up the local decapsulation seed for the consumed
//! `prekey_id` (kept in a per-device secret store).
//! 2. Decapsulates, derives the session key, decrypts.
//! 3. **Permanently deletes the local seed** — past messages cannot
//! be re-decrypted by anyone, including a later compromise of the
//! identity_sk or master_sk. This is the forward-secrecy
//! property X3DH gives us.
//!
//! When `< MIN_PREKEY_POOL_REMAINING` one-time prekeys remain unused
//! the device generates a fresh batch and republishes its bundle
//! with a higher `bundle_version`. Older one-time entries with
//! `expires_at_unix < now` are GC'd.
//!
//! ## Wire layout (canonical bytes, big-endian)
//!
//! ```text
//! [0..2] magic = "PB" u16
//! [2] version = 1 u8
//! [3..35] node_id [u8; 32]
//! [35..51] instance_id [u8; 16]
//! [..] bundle_version u64 BE
//! [..] issued_at_unix u64 BE
//! [..] signing_identity_key_idx u16 BE
//! [..] algo u8 (1 = ML-KEM-768)
//! [..] one_time_count u8 (≤ MAX_ONE_TIME_PREKEYS)
//! repeated one_time_count times:
//! [..] prekey_id u32 BE
//! [..] ek_len u16 BE
//! [..] encapsulation_key [u8; ek_len]
//! [..] expires_at_unix u64 BE
//! [..] fallback.prekey_id u32 BE
//! [..] fallback.ek_len u16 BE
//! [..] fallback.encapsulation_key [u8; ek_len]
//! [..] fallback.expires_at_unix u64 BE
//! [..] sig_len u16 BE
//! [..] sig [u8; sig_len]
//! ```
//!
//! The signature covers `PREKEY_BUNDLE_SIG_CONTEXT ||
//! canonical_signing_bytes` produced by the active identity_sk
//! identified by `signing_identity_key_idx`.
//!
//! ## Capacity caps
//!
//! `MAX_ONE_TIME_PREKEYS = 8`: 8 × 1184 B + fallback ≈ 11 KB —
//! well below typical DHT value caps while still letting a busy
//! inbox buffer ~8 messages of true forward secrecy before falling
//! back.
//! `MAX_PREKEY_BUNDLE_BYTES = 16 KB`.
//! Decoder rejects any `prekey_id` duplicates and any encapsulation
//! key whose length disagrees with the algorithm's expected size.

use super::ProtoError;
use super::cursor::{read_array, read_bytes, read_u8, read_u16, read_u32, read_u64};

// ── Constants ────────────────────────────────────────────────────────────────

/// "PB" — identifies a PrekeyBundle on the wire.
pub const PREKEY_BUNDLE_MAGIC: [u8; 2] = [b'P', b'B'];
/// Wire-format version.
pub const PREKEY_BUNDLE_V1: u8 = 1;

/// Domain-separated signing context for the bundle.
pub const PREKEY_BUNDLE_SIG_CONTEXT: &[u8] = b"veil.prekey_bundle.v1";

// b: Algorithm byte and EK length moved to `veil-types` so the
// crypto layer can reference them without depending on `proto`. Re-exported
// here to preserve existing call sites.
pub use veil_types::{ALGO_ML_KEM_768, ML_KEM_768_EK_LEN};

/// Maximum one-time prekeys per bundle.
pub const MAX_ONE_TIME_PREKEYS: usize = 8;

/// Pool refill threshold — when fewer than this many unused
/// one-time prekeys remain, the publisher rotates the bundle.
pub const MIN_PREKEY_POOL_REMAINING: usize = 3;

/// Absolute upper bound on bundle wire size (DHT value cap headroom).
pub const MAX_PREKEY_BUNDLE_BYTES: usize = 16 * 1024;

/// Maximum signature length.
const MAX_SIG_BYTES: usize = 1024;

// ── Types ────────────────────────────────────────────────────────────────────

/// One-time prekey — consumed exactly once. Recipient deletes the
/// matching decapsulation seed on first use; sender marks the id as
/// "spent" so it isn't reused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimePrekey {
    pub prekey_id: u32,
    pub encapsulation_key: Vec<u8>,
    pub expires_at_unix: u64,
}

/// Fallback prekey — used when the one-time pool is exhausted.
/// Reduced forward-secrecy guarantees (the same key may be reused
/// by multiple senders in a window between rotations) but the device
/// stays reachable. Rotated weekly by the publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackPrekey {
    pub prekey_id: u32,
    pub encapsulation_key: Vec<u8>,
    pub expires_at_unix: u64,
}

/// Complete published prekey bundle for a single (identity, instance) pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrekeyBundle {
    pub node_id: [u8; 32],
    pub instance_id: [u8; 16],
    pub bundle_version: u64,
    pub issued_at_unix: u64,
    pub signing_identity_key_idx: u16,
    pub algo: u8,
    pub one_time_prekeys: Vec<OneTimePrekey>,
    pub fallback: FallbackPrekey,
    pub sig: Vec<u8>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Expected encapsulation-key length for the named algorithm.
pub fn ek_len_for_algo(algo: u8) -> Result<usize, ProtoError> {
    match algo {
        ALGO_ML_KEM_768 => Ok(ML_KEM_768_EK_LEN),
        other => Err(ProtoError::Malformed(format!(
            "prekey_bundle: unsupported algo byte {other}"
        ))),
    }
}

// ── Codec ────────────────────────────────────────────────────────────────────

impl PrekeyBundle {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&PREKEY_BUNDLE_MAGIC);
        out.push(PREKEY_BUNDLE_V1);
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.instance_id);
        out.extend_from_slice(&self.bundle_version.to_be_bytes());
        out.extend_from_slice(&self.issued_at_unix.to_be_bytes());
        out.extend_from_slice(&self.signing_identity_key_idx.to_be_bytes());
        out.push(self.algo);
        out.push(self.one_time_prekeys.len() as u8);
        for pk in &self.one_time_prekeys {
            encode_prekey_fields(
                &mut out,
                pk.prekey_id,
                &pk.encapsulation_key,
                pk.expires_at_unix,
            );
        }
        encode_prekey_fields(
            &mut out,
            self.fallback.prekey_id,
            &self.fallback.encapsulation_key,
            self.fallback.expires_at_unix,
        );
        out.extend_from_slice(&(self.sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() > MAX_PREKEY_BUNDLE_BYTES {
            return Err(ProtoError::Malformed(format!(
                "prekey_bundle: oversized ({}B > {MAX_PREKEY_BUNDLE_BYTES}B)",
                buf.len()
            )));
        }
        let mut pos = 0;
        if buf.get(pos..pos + 2) != Some(&PREKEY_BUNDLE_MAGIC[..]) {
            return Err(ProtoError::Malformed("prekey_bundle: bad magic".into()));
        }
        pos += 2;

        let version = read_u8(buf, &mut pos, "prekey_bundle.version")?;
        if version != PREKEY_BUNDLE_V1 {
            return Err(ProtoError::Malformed(format!(
                "prekey_bundle: unsupported version {version}"
            )));
        }

        let node_id = read_array::<32>(buf, &mut pos, "prekey_bundle.node_id")?;
        let instance_id = read_array::<16>(buf, &mut pos, "prekey_bundle.instance_id")?;
        let bundle_version = read_u64(buf, &mut pos, "prekey_bundle.bundle_version")?;
        let issued_at_unix = read_u64(buf, &mut pos, "prekey_bundle.issued_at")?;
        let signing_identity_key_idx = read_u16(buf, &mut pos, "prekey_bundle.signing_key_idx")?;
        let algo = read_u8(buf, &mut pos, "prekey_bundle.algo")?;
        let expected_ek_len = ek_len_for_algo(algo)?;

        let one_time_count = read_u8(buf, &mut pos, "prekey_bundle.one_time_count")? as usize;
        if one_time_count > MAX_ONE_TIME_PREKEYS {
            return Err(ProtoError::Malformed(format!(
                "prekey_bundle: one_time_count {one_time_count} exceeds cap {MAX_ONE_TIME_PREKEYS}"
            )));
        }
        let mut one_time_prekeys = Vec::with_capacity(one_time_count);
        for _ in 0..one_time_count {
            let (prekey_id, encapsulation_key, expires_at_unix) =
                decode_prekey_fields(buf, &mut pos, expected_ek_len, "prekey_bundle.one_time")?;
            one_time_prekeys.push(OneTimePrekey {
                prekey_id,
                encapsulation_key,
                expires_at_unix,
            });
        }

        let (fb_id, fb_ek, fb_exp) =
            decode_prekey_fields(buf, &mut pos, expected_ek_len, "prekey_bundle.fallback")?;
        let fallback = FallbackPrekey {
            prekey_id: fb_id,
            encapsulation_key: fb_ek,
            expires_at_unix: fb_exp,
        };

        let sig_len = read_u16(buf, &mut pos, "prekey_bundle.sig_len")? as usize;
        if sig_len == 0 || sig_len > MAX_SIG_BYTES {
            return Err(ProtoError::Malformed(format!(
                "prekey_bundle: sig_len {sig_len} out of range"
            )));
        }
        let sig = read_bytes(buf, &mut pos, sig_len, "prekey_bundle.sig")?;

        if pos != buf.len() {
            return Err(ProtoError::Malformed(format!(
                "prekey_bundle: {} trailing bytes",
                buf.len() - pos
            )));
        }

        // Uniqueness defense: prekey_ids must be globally unique
        // within the bundle so the consumer can dedupe consumption
        // tracking by id alone.
        for i in 0..one_time_prekeys.len() {
            if one_time_prekeys[i].prekey_id == fallback.prekey_id {
                return Err(ProtoError::Malformed(format!(
                    "prekey_bundle: one_time prekey_id {} collides with fallback",
                    fallback.prekey_id
                )));
            }
            for j in (i + 1)..one_time_prekeys.len() {
                if one_time_prekeys[i].prekey_id == one_time_prekeys[j].prekey_id {
                    return Err(ProtoError::Malformed(format!(
                        "prekey_bundle: duplicate one_time prekey_id at {i}+{j}"
                    )));
                }
            }
        }

        Ok(Self {
            node_id,
            instance_id,
            bundle_version,
            issued_at_unix,
            signing_identity_key_idx,
            algo,
            one_time_prekeys,
            fallback,
            sig,
        })
    }

    /// Canonical bytes covered by the bundle signature.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut encoded = self.encode();
        let trailer = 2 + self.sig.len();
        encoded.truncate(encoded.len() - trailer);
        encoded
    }

    /// DHT key under which this bundle is stored.
    pub fn dht_key(node_id: &[u8; 32], instance_id: &[u8; 16]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"veil.prekey_bundle_dht.v1");
        h.update(node_id);
        h.update(instance_id);
        *h.finalize().as_bytes()
    }

    fn encoded_len(&self) -> usize {
        2 + 1
            + 32
            + 16
            + 8
            + 8
            + 2
            + 1
            + 1
            + self
                .one_time_prekeys
                .iter()
                .map(|pk| 4 + 2 + pk.encapsulation_key.len() + 8)
                .sum::<usize>()
            + 4
            + 2
            + self.fallback.encapsulation_key.len()
            + 8
            + 2
            + self.sig.len()
    }

    /// Pick an unused, non-expired one-time prekey, or fall back.
    /// Returns the chosen `prekey_id` along with its encapsulation
    /// key so the caller can immediately encapsulate against it.
    ///
    /// `consumed` lets callers exclude prekey_ids they have already
    /// used (typically tracked locally by the sender so the same
    /// recipient bundle isn't replayed against the same prekey).
    pub fn pick_for_send<'a>(
        &'a self,
        consumed: &std::collections::HashSet<u32>,
        now_unix_secs: u64,
    ) -> PickedPrekey<'a> {
        for pk in &self.one_time_prekeys {
            if consumed.contains(&pk.prekey_id) {
                continue;
            }
            if pk.expires_at_unix < now_unix_secs {
                continue;
            }
            return PickedPrekey::OneTime(pk);
        }
        if self.fallback.expires_at_unix >= now_unix_secs {
            PickedPrekey::Fallback(&self.fallback)
        } else {
            PickedPrekey::None
        }
    }
}

/// Outcome [`PrekeyBundle::pick_for_send`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickedPrekey<'a> {
    OneTime(&'a OneTimePrekey),
    Fallback(&'a FallbackPrekey),
    /// Both pool exhausted/expired AND fallback expired.
    None,
}

// ── Codec helpers ────────────────────────────────────────────────────────────

fn encode_prekey_fields(out: &mut Vec<u8>, prekey_id: u32, ek: &[u8], expires_at: u64) {
    out.extend_from_slice(&prekey_id.to_be_bytes());
    out.extend_from_slice(&(ek.len() as u16).to_be_bytes());
    out.extend_from_slice(ek);
    out.extend_from_slice(&expires_at.to_be_bytes());
}

fn decode_prekey_fields(
    buf: &[u8],
    pos: &mut usize,
    expected_ek_len: usize,
    field: &'static str,
) -> Result<(u32, Vec<u8>, u64), ProtoError> {
    let prekey_id = read_u32(buf, pos, field)?;
    let ek_len = read_u16(buf, pos, field)? as usize;
    if ek_len != expected_ek_len {
        return Err(ProtoError::Malformed(format!(
            "{field}: ek_len {ek_len} != expected {expected_ek_len}"
        )));
    }
    let ek = read_bytes(buf, pos, ek_len, field)?;
    let expires_at = read_u64(buf, pos, field)?;
    Ok((prekey_id, ek, expires_at))
}

// local `read_array` removed — use cursor::read_array.

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn one_time(prekey_id: u32, expires_at: u64) -> OneTimePrekey {
        OneTimePrekey {
            prekey_id,
            encapsulation_key: vec![prekey_id as u8; ML_KEM_768_EK_LEN],
            expires_at_unix: expires_at,
        }
    }

    fn fallback(prekey_id: u32, expires_at: u64) -> FallbackPrekey {
        FallbackPrekey {
            prekey_id,
            encapsulation_key: vec![0xFD; ML_KEM_768_EK_LEN],
            expires_at_unix: expires_at,
        }
    }

    fn sample_bundle() -> PrekeyBundle {
        PrekeyBundle {
            node_id: [0x11u8; 32],
            instance_id: [0x22u8; 16],
            bundle_version: 5,
            issued_at_unix: 1_700_000_000,
            signing_identity_key_idx: 0,
            algo: ALGO_ML_KEM_768,
            one_time_prekeys: vec![
                one_time(1, 1_800_000_000),
                one_time(2, 1_800_000_000),
                one_time(3, 1_800_000_000),
            ],
            fallback: fallback(99, 1_800_000_000),
            sig: vec![0xCC; 64],
        }
    }

    #[test]
    fn roundtrip_basic() {
        let b = sample_bundle();
        let bytes = b.encode();
        assert_eq!(bytes.len(), b.encoded_len());
        let back = PrekeyBundle::decode(&bytes).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn roundtrip_with_max_prekeys() {
        let mut b = sample_bundle();
        b.one_time_prekeys = (0..MAX_ONE_TIME_PREKEYS as u32)
            .map(|i| one_time(i, 1_800_000_000))
            .collect();
        let bytes = b.encode();
        let back = PrekeyBundle::decode(&bytes).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn roundtrip_with_zero_one_time_prekeys() {
        // Pool fully consumed — only fallback present.
        let mut b = sample_bundle();
        b.one_time_prekeys = Vec::new();
        let bytes = b.encode();
        let back = PrekeyBundle::decode(&bytes).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = sample_bundle().encode();
        bytes[0] = b'X';
        let err = PrekeyBundle::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = sample_bundle().encode();
        bytes[2] = 99;
        let err = PrekeyBundle::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_unsupported_algo() {
        let mut b = sample_bundle();
        b.algo = 99;
        let bytes = b.encode();
        let err = PrekeyBundle::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_oversized_input() {
        let bytes = vec![0u8; MAX_PREKEY_BUNDLE_BYTES + 1];
        let err = PrekeyBundle::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_truncated() {
        let bytes = sample_bundle().encode();
        // Sample only a few representative truncation lengths to keep
        // CPU bounded — bundles are 11 KB+ so iterating every offset
        // is wasteful.
        for cut in [1, 2, 3, 35, 100, 500, 5000].iter().copied() {
            if cut < bytes.len() {
                let err = PrekeyBundle::decode(&bytes[..cut]).unwrap_err();
                assert!(matches!(err, ProtoError::Malformed(_)), "cut={cut} {err:?}");
            }
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = sample_bundle().encode();
        bytes.push(0xFF);
        let err = PrekeyBundle::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_one_time_count_above_cap() {
        // Build a bundle in-memory with MAX+1 one-time prekeys, then
        // encode and decode; the count byte will exceed the cap.
        let mut b = sample_bundle();
        b.one_time_prekeys = (0..(MAX_ONE_TIME_PREKEYS as u32 + 1))
            .map(|i| one_time(i + 100, 1_800_000_000))
            .collect();
        let bytes = b.encode();
        let err = PrekeyBundle::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_wrong_ek_length() {
        let mut b = sample_bundle();
        // Tamper with the first one-time prekey's EK length only —
        // the encoded ek_len won't match the algorithm's expected
        // length.
        b.one_time_prekeys[0].encapsulation_key = vec![0u8; ML_KEM_768_EK_LEN - 10];
        let bytes = b.encode();
        let err = PrekeyBundle::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_duplicate_one_time_prekey_ids() {
        let mut b = sample_bundle();
        b.one_time_prekeys[1].prekey_id = b.one_time_prekeys[0].prekey_id;
        let bytes = b.encode();
        let err = PrekeyBundle::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_collision_with_fallback_id() {
        let mut b = sample_bundle();
        b.fallback.prekey_id = b.one_time_prekeys[0].prekey_id;
        let bytes = b.encode();
        let err = PrekeyBundle::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_zero_sig() {
        let mut b = sample_bundle();
        b.sig = Vec::new();
        let bytes = b.encode();
        let err = PrekeyBundle::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn canonical_bytes_excludes_sig() {
        let b = sample_bundle();
        let full = b.encode();
        let canonical = b.canonical_signing_bytes();
        assert_eq!(&full[..canonical.len()], &canonical[..]);
        assert_eq!(full.len() - canonical.len(), 2 + b.sig.len());
    }

    #[test]
    fn canonical_bytes_stable_under_sig_change() {
        let mut b = sample_bundle();
        let before = b.canonical_signing_bytes();
        b.sig = vec![0x00; 64];
        let after = b.canonical_signing_bytes();
        assert_eq!(before, after);
    }

    #[test]
    fn dht_key_is_per_instance_not_per_identity() {
        let id = [0x11u8; 32];
        let inst_a = [0x22u8; 16];
        let inst_b = [0x33u8; 16];
        let a = PrekeyBundle::dht_key(&id, &inst_a);
        let b = PrekeyBundle::dht_key(&id, &inst_b);
        assert_ne!(a, b);
        // Same (id, instance) → same key (deterministic).
        assert_eq!(a, PrekeyBundle::dht_key(&id, &inst_a));
    }

    // ── pick_for_send ────────────────────────────────────────────────────────

    #[test]
    fn pick_returns_first_unused_one_time() {
        let b = sample_bundle();
        let consumed = std::collections::HashSet::new();
        let now = 1_700_000_001;
        match b.pick_for_send(&consumed, now) {
            PickedPrekey::OneTime(pk) => assert_eq!(pk.prekey_id, 1),
            other => panic!("expected OneTime(1), got {other:?}"),
        }
    }

    #[test]
    fn pick_skips_consumed_one_time() {
        let b = sample_bundle();
        let mut consumed = std::collections::HashSet::new();
        consumed.insert(1u32);
        consumed.insert(2u32);
        let now = 1_700_000_001;
        match b.pick_for_send(&consumed, now) {
            PickedPrekey::OneTime(pk) => assert_eq!(pk.prekey_id, 3),
            other => panic!("expected OneTime(3), got {other:?}"),
        }
    }

    #[test]
    fn pick_skips_expired_one_time() {
        let mut b = sample_bundle();
        for pk in &mut b.one_time_prekeys {
            pk.expires_at_unix = 1_500_000_000; // expired
        }
        let consumed = std::collections::HashSet::new();
        let now = 1_700_000_000;
        match b.pick_for_send(&consumed, now) {
            PickedPrekey::Fallback(_) => {}
            other => panic!("expected Fallback, got {other:?}"),
        }
    }

    #[test]
    fn pick_falls_back_when_pool_exhausted() {
        let b = sample_bundle();
        let consumed: std::collections::HashSet<u32> =
            b.one_time_prekeys.iter().map(|p| p.prekey_id).collect();
        let now = 1_700_000_001;
        match b.pick_for_send(&consumed, now) {
            PickedPrekey::Fallback(pk) => assert_eq!(pk.prekey_id, 99),
            other => panic!("expected Fallback, got {other:?}"),
        }
    }

    #[test]
    fn pick_returns_none_when_everything_expired() {
        let mut b = sample_bundle();
        for pk in &mut b.one_time_prekeys {
            pk.expires_at_unix = 1_500_000_000;
        }
        b.fallback.expires_at_unix = 1_500_000_000;
        let consumed = std::collections::HashSet::new();
        let now = 1_700_000_000;
        assert_eq!(b.pick_for_send(&consumed, now), PickedPrekey::None);
    }

    #[test]
    fn ek_len_helper_works_for_known_algo() {
        assert_eq!(ek_len_for_algo(ALGO_ML_KEM_768).unwrap(), ML_KEM_768_EK_LEN);
        assert!(ek_len_for_algo(99).is_err());
    }
}
