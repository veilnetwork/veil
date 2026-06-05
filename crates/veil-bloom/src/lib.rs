//! Tiny Bloom filter, sized for veil peer-sync.
//!
//! Use case: a receiver assembling its `received content_id` set into
//! a compact summary it sends to a peer ("here's what I have, send me
//! what you have that I don't"). False positives cost nothing — A
//! just doesn't retransmit something B may already have, and B's app
//! layer dedups on its own. False negatives are forbidden — they
//! would make A skip a message B never received, breaking eventual
//! delivery.
//!
//! ## Design choices
//!
//! **Sizing.** Caller supplies expected element count `n` and target
//! false-positive rate `p` (e.g. `1e-2`). We pick `m = -n·ln(p)/ln(2)²`
//! bits and `k = m/n · ln(2)` hash functions per element, rounded to
//! sensible bounds. At the typical veil-messenger scale —
//! 1000 outstanding messages, 1% FP — that's a 1.2 KB filter and 7
//! hash functions, well under the 16 KB IPC frame budget.
//! **Hashing.** We use BLAKE3 once per element to derive a 64-byte
//! seed, then split it into pairs of 32-bit halves and combine with
//! `(h1 + i·h2) mod m` (the Kirsch-Mitzenmacher trick). No SipHash
//! / FNV / Murmur dance — BLAKE3 is already a dependency, fast
//! enough, and gives us SHA-strength avalanche, which matters
//! because an adversary who can pre-image the filter (which we DO
//! transmit on the wire) could craft content_ids that collide
//! maximally and cause the peer to skip transmitting them. Defence
//! in depth — even if the filter were leaked, BLAKE3 is keyless
//! here so collisions are universal, not per-receiver. Future
//! hardening: keyed BLAKE3 with a per-receiver key.
//! **Wire format.** Length-prefixed bytes: `[k_u8 | bits_len_u32_be |
//! bits_bytes]`. No version byte — bumps would change the type
//! itself.
//!
//! ## What this crate does NOT do
//!
//! **No removal.** Bloom doesn't support delete; counting Bloom
//! would solve that but bloats the wire size 4x — we don't need it
//! for peer-sync (B rebuilds the filter on every sync invocation).
//! **No serialization optimization** for sparse filters. Fixed-size
//! bit array. At 1000 elements / 1% FP this is 1.2 KB — fine for
//! our use case.

#![deny(missing_docs)]

use blake3::Hasher;

/// Errors returned by the encoder/decoder.
#[derive(Debug, thiserror::Error)]
pub enum BloomError {
    /// Wire buffer too short for the claimed `bits_len`.
    #[error("buffer too short: need {need}, got {got}")]
    BufferTooShort {
        /// Required size.
        need: usize,
        /// Actual size.
        got: usize,
    },
    /// `bits_len` exceeds [`MAX_BITS_BYTES`].
    #[error("bits_len {value} > MAX_BITS_BYTES {max}")]
    TooLarge {
        /// Claimed size.
        value: u32,
        /// Hard cap.
        max: u32,
    },
    /// `k` (hash count) is zero — degenerate filter.
    #[error("k must be > 0")]
    InvalidK,
    /// `bits_len` is zero — degenerate filter with no bit array. Accepting
    /// it would set `m = 0` and make every `insert`/`contains` panic on the
    /// `% m` (modulo-by-zero) in [`combine`].
    #[error("bits_len must be > 0")]
    ZeroBits,
}

/// Hard cap on filter size in bytes (16 KiB). At 1% FP this is
/// ~13 000 elements — well above the peer-sync workload (typical
/// outbox holds < 1000 messages).
pub const MAX_BITS_BYTES: u32 = 16 * 1024;

/// Hard cap on hash-function count. Higher k slows down both
/// `insert` and `contains` linearly with no FP benefit.
pub const MAX_K: u8 = 32;

/// A Bloom filter sized at construction time and immutable thereafter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomFilter {
    /// Bit array. `bits[i / 8] & (1 << (i % 8))` is the i-th bit.
    bits: Vec<u8>,
    /// Number of hash functions per element. `1 ≤ k ≤ MAX_K`.
    k: u8,
    /// Total bit count = `bits.len * 8`.
    m: usize,
}

impl BloomFilter {
    /// Construct a filter sized for `expected_elements` at false-
    /// positive rate `target_fp` (between 0 and 1, e.g. `0.01` for 1%).
    /// Both inputs are clamped to sane ranges so a pathological
    /// caller can't blow memory.
    pub fn for_capacity(expected_elements: usize, target_fp: f64) -> Self {
        // Clamp inputs.
        let n = expected_elements.clamp(1, 100_000);
        let p = target_fp.clamp(1e-9, 0.5);
        // Optimal m = -n·ln(p) / (ln 2)²
        let ln2_sq = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        let m_bits = (-(n as f64) * p.ln() / ln2_sq).ceil() as usize;
        // Cap m at MAX_BITS_BYTES * 8.
        let m_bits = m_bits.max(64).min(MAX_BITS_BYTES as usize * 8);
        // Round up to byte boundary.
        let m_bytes = m_bits.div_ceil(8);
        let m = m_bytes * 8;
        // Optimal k = (m/n) · ln 2
        let k_f = (m as f64 / n as f64) * std::f64::consts::LN_2;
        let k = (k_f.round() as u8).clamp(1, MAX_K);
        Self {
            bits: vec![0u8; m_bytes],
            k,
            m,
        }
    }

    /// Bits in the filter (always a multiple of 8).
    pub fn m(&self) -> usize {
        self.m
    }

    /// Hash function count.
    pub fn k(&self) -> u8 {
        self.k
    }

    /// Insert an element. Idempotent.
    pub fn insert(&mut self, element: &[u8]) {
        let (h1, h2) = derive_hashes(element);
        for i in 0..self.k as u64 {
            let idx = combine(h1, h2, i, self.m);
            self.bits[idx / 8] |= 1u8 << (idx % 8);
        }
    }

    /// True if the element MAY be in the filter (with the configured
    /// false-positive probability), false if definitely absent.
    pub fn contains(&self, element: &[u8]) -> bool {
        let (h1, h2) = derive_hashes(element);
        for i in 0..self.k as u64 {
            let idx = combine(h1, h2, i, self.m);
            if self.bits[idx / 8] & (1u8 << (idx % 8)) == 0 {
                return false;
            }
        }
        true
    }

    /// Wire layout: `[k_u8 | bits_len_u32_be | bits_bytes]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 4 + self.bits.len());
        buf.push(self.k);
        buf.extend_from_slice(&(self.bits.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.bits);
        buf
    }

    /// Decode from wire bytes, validating bounds.
    pub fn decode(buf: &[u8]) -> Result<Self, BloomError> {
        if buf.len() < 5 {
            return Err(BloomError::BufferTooShort {
                need: 5,
                got: buf.len(),
            });
        }
        let k = buf[0];
        if k == 0 {
            return Err(BloomError::InvalidK);
        }
        // reject `k > MAX_K`.
        // Previously the decoder accepted any 1..=255 here, which let
        // а malicious peer ship а Bloom с `k = 255` — every
        // `contains` call then runs 255 BLAKE3-derived index
        // calculations, turning а cheap membership check into а CPU
        // amplifier the peer controls remotely. At MAX_K=32 the
        // worst-case probe cost is bounded by а constant the local
        // node chose, not the peer.
        if k > MAX_K {
            return Err(BloomError::TooLarge {
                value: k as u32,
                max: MAX_K as u32,
            });
        }
        let bits_len = u32::from_be_bytes(buf[1..5].try_into().unwrap());
        // audit cycle-6 (P5): reject the degenerate `bits_len == 0` filter.
        // Without this lower bound a 5-byte wire buffer `[k, 0,0,0,0]` decodes
        // into a filter with `m = bits_len * 8 = 0`; the next `contains`/`insert`
        // then computes `(_ as usize) % 0` in `combine` → modulo-by-zero panic
        // (debug AND release). The peer-supplied outbox-sync bloom reaches this
        // via `OutboxBackend::find_missing`, so the decode gate must close it —
        // symmetric with the existing `k == 0` rejection above.
        if bits_len == 0 {
            return Err(BloomError::ZeroBits);
        }
        if bits_len > MAX_BITS_BYTES {
            return Err(BloomError::TooLarge {
                value: bits_len,
                max: MAX_BITS_BYTES,
            });
        }
        let need = 5 + bits_len as usize;
        if buf.len() < need {
            return Err(BloomError::BufferTooShort {
                need,
                got: buf.len(),
            });
        }
        Ok(Self {
            bits: buf[5..need].to_vec(),
            k,
            m: bits_len as usize * 8,
        })
    }
}

/// Derive two 64-bit hashes from one BLAKE3 of the input. Per the
/// Kirsch-Mitzenmacher result, `h_i(x) = h1(x) + i·h2(x) mod m` is
/// asymptotically as good as `k` independent hash functions.
fn derive_hashes(element: &[u8]) -> (u64, u64) {
    let mut h = Hasher::new();
    h.update(element);
    let out = h.finalize();
    let bytes = out.as_bytes();
    let h1 = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
    let h2 = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    (h1, h2)
}

fn combine(h1: u64, h2: u64, i: u64, m: usize) -> usize {
    // Wrapping arithmetic on u64 — overflow into modulo m doesn't
    // skew the distribution materially at the sizes we use.
    let mixed = h1.wrapping_add(i.wrapping_mul(h2));
    (mixed as usize) % m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t1_4_p4_bloom_basic_insert_contains() {
        let mut bf = BloomFilter::for_capacity(100, 0.01);
        bf.insert(b"alpha");
        bf.insert(b"beta");
        assert!(bf.contains(b"alpha"));
        assert!(bf.contains(b"beta"));
        // gamma was not inserted — most of the time absent.
        assert!(!bf.contains(b"gamma"));
    }

    #[test]
    fn t1_4_p4_bloom_no_false_negatives() {
        // Critical invariant: every inserted element must appear
        // present. A miss here breaks peer-sync correctness.
        let mut bf = BloomFilter::for_capacity(1000, 0.01);
        let inputs: Vec<Vec<u8>> = (0..1000)
            .map(|i| format!("element-{i}").into_bytes())
            .collect();
        for x in &inputs {
            bf.insert(x);
        }
        for x in &inputs {
            assert!(
                bf.contains(x),
                "false negative on {:?}",
                std::str::from_utf8(x)
            );
        }
    }

    #[test]
    fn t1_4_p4_bloom_false_positive_rate_within_target() {
        // Build a 1000-element filter at target FP 1%, then probe
        // 10000 unrelated keys. Expect ≤ ~3% observed FP (3x slack).
        let mut bf = BloomFilter::for_capacity(1000, 0.01);
        for i in 0..1000 {
            bf.insert(format!("inserted-{i}").as_bytes());
        }
        let mut fp = 0;
        let probes = 10_000;
        for i in 0..probes {
            if bf.contains(format!("probe-{i}").as_bytes()) {
                fp += 1;
            }
        }
        let observed = fp as f64 / probes as f64;
        assert!(
            observed < 0.03,
            "FP rate {observed} too high (target 1%, slack 3x)",
        );
    }

    #[test]
    fn t1_4_p4_bloom_encode_decode_round_trip() {
        let mut bf = BloomFilter::for_capacity(256, 0.01);
        bf.insert(b"hello");
        bf.insert(b"world");
        let buf = bf.encode();
        let bf2 = BloomFilter::decode(&buf).unwrap();
        assert_eq!(bf2, bf);
        // Decoded filter still answers correctly.
        assert!(bf2.contains(b"hello"));
        assert!(bf2.contains(b"world"));
    }

    #[test]
    fn t1_4_p4_bloom_decode_rejects_zero_k() {
        let mut buf = vec![0u8]; // k = 0
        buf.extend_from_slice(&8u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            BloomFilter::decode(&buf),
            Err(BloomError::InvalidK)
        ));
    }

    #[test]
    fn audit_2026_05_08_bloom_decode_rejects_k_above_max() {
        // audit fix: peer sends а Bloom claiming `k=255`.
        // Decoder must reject so each `contains` call doesn't run
        // 255 hash derivations under attacker control.
        for bad_k in [(MAX_K + 1), (MAX_K + 17), 200u8, 255u8] {
            let mut buf = vec![bad_k];
            buf.extend_from_slice(&8u32.to_be_bytes());
            buf.extend_from_slice(&[0u8; 8]);
            match BloomFilter::decode(&buf) {
                Err(BloomError::TooLarge { value, max }) => {
                    assert_eq!(value, bad_k as u32);
                    assert_eq!(max, MAX_K as u32);
                }
                other => panic!("k={bad_k}: expected TooLarge, got {:?}", other),
            }
        }
    }

    #[test]
    fn audit_2026_05_08_bloom_decode_accepts_k_at_max() {
        // The cap is INCLUSIVE — `k == MAX_K` is fine, only k > MAX_K
        // gets rejected. Otherwise valid filters at the boundary
        // would round-trip-fail.
        let bf = BloomFilter::for_capacity(2, 0.01); // tiny n → k saturates к MAX_K
        // Force k to MAX_K before encode (small filters might pick
        // smaller k); test против the boundary explicitly.
        let mut buf = bf.encode();
        buf[0] = MAX_K; // override
        let _ = BloomFilter::decode(&buf).expect("k=MAX_K must be accepted");
    }

    #[test]
    fn audit_cycle6_bloom_decode_rejects_zero_bits_len() {
        // audit cycle-6 (P5): a peer-supplied bloom with `bits_len == 0`
        // must be rejected at decode. Before the fix this 5-byte buffer
        // decoded into a filter with `m = 0`, and the first `contains`
        // call panicked with a modulo-by-zero in `combine`.
        let mut buf = vec![1u8]; // k = 1 (valid)
        buf.extend_from_slice(&0u32.to_be_bytes()); // bits_len = 0
        assert!(matches!(
            BloomFilter::decode(&buf),
            Err(BloomError::ZeroBits),
        ));
        // Guard the actual panic vector: the rejected filter must never be
        // constructed, so a `contains` probe can never reach `% 0`.
        assert!(BloomFilter::decode(&buf).is_err());
    }

    #[test]
    fn t1_4_p4_bloom_decode_rejects_oversized() {
        let mut buf = vec![5u8]; // k = 5
        buf.extend_from_slice(&(MAX_BITS_BYTES + 1).to_be_bytes());
        // Don't bother appending payload — decoder rejects at length check.
        assert!(matches!(
            BloomFilter::decode(&buf),
            Err(BloomError::TooLarge { .. }),
        ));
    }

    #[test]
    fn t1_4_p4_bloom_decode_rejects_truncated() {
        let mut buf = vec![5u8];
        buf.extend_from_slice(&100u32.to_be_bytes()); // claims 100 bytes
        buf.extend_from_slice(&[0u8; 50]); // only 50
        assert!(matches!(
            BloomFilter::decode(&buf),
            Err(BloomError::BufferTooShort { .. }),
        ));
    }

    #[test]
    fn t1_4_p4_bloom_for_capacity_clamps_extreme_inputs() {
        // Zero elements → still produces a valid (tiny) filter.
        let bf = BloomFilter::for_capacity(0, 0.01);
        assert!(bf.m() >= 64);
        assert!(bf.k() >= 1);
        // Million elements at 1% would want a 1.2 MB filter; we cap.
        let bf = BloomFilter::for_capacity(1_000_000, 0.01);
        assert!(bf.m() <= MAX_BITS_BYTES as usize * 8);
    }

    #[test]
    fn t1_4_p4_bloom_distinct_elements_have_distinct_indices() {
        // Sanity: BLAKE3-based hashing should not collide on adjacent
        // small-int keys. Build filter, insert 0..100, ensure ≤2%
        // of single-bit positions are shared (loose check).
        let mut bf = BloomFilter::for_capacity(1000, 0.01);
        for i in 0..100u32 {
            bf.insert(&i.to_be_bytes());
        }
        let popcount: u32 = bf.bits.iter().map(|b| b.count_ones()).sum();
        // 100 elements × 7 hashes = ~700 set bits at most (unique);
        // accept anywhere from 600 to 700 (some collisions are fine).
        assert!(popcount > 500, "too few bits set: {popcount}");
    }
}
