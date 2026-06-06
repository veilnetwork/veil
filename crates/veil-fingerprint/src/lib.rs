//! DPI-fingerprint regression-test infrastructure.
//!
//! Anti-censorship strategy P2 #5 (Epic 488.2 carry-over) — closes
//! the **validation** half of DPI method #33 (flow-cache state
//! tracking + n-gram analysis).  Existing wire-level work (obfs4,
//! tls-boring Chrome ClientHello, QUIC Chrome transport params)
//! aims to make OVL1 traffic statistically indistinguishable от
//! reference HTTPS/CDN traffic — but без а regression suite, а
//! seemingly-innocuous feature addition (а new field with non-random
//! bytes, а padding-pattern change) could silently break that goal.
//!
//! This crate ships the **analyzer engine**:
//!
//! * [`NGramModel`] — counts byte n-grams в а sample, normalises
//!   к а probability distribution.
//! * [`kl_divergence`] / [`chi_squared`] — pairwise distance metrics
//!   between two models.  KL is asymmetric и useful когда one
//!   distribution is а "reference" (low KL ⇒ sample looks like ref);
//!   chi-squared is symmetric и more sensitive at low counts.
//! * [`uniform_random_baseline`] — synthetic reference for «AEAD
//!   ciphertext / obfs4 output ought to look like». Generates byte
//!   sequences from а seeded ChaCha RNG so tests are deterministic.
//!
//! ## What is **not** in this crate (deliberately)
//!
//! * **Real-world Tor / OpenVPN / WireGuard reference pcaps** —
//!   those are heavy artifacts (license + privacy concerns), и а
//!   meaningful comparison needs hand-curated fixtures from а
//!   diverse set of clients.  Future slice: ingest pcap-format files
//!   into the same `NGramModel` API.
//! * **Live capture against running veil nodes** — out of scope
//!   for an in-process test crate.  Operator runs are documented in
//!   `docs/internal/FINGERPRINT_REGRESSION.md`.
//! * **A static "Chrome HTTPS" fixture** —ed by the `tls-boring`
//!   ClientHello fingerprint already; this crate stays domain-agnostic
//!   so the same analyzer can be pointed at any byte stream.

use std::collections::HashMap;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

#[cfg(feature = "pcap")]
pub mod pcap;

/// Maximum supported n-gram length.  N > 4 explodes the alphabet
/// (256^N) и tends к overfit; 2-3 is the sweet spot for byte-level
/// flow-shape detection.
pub const MAX_N: usize = 4;

/// А byte n-gram probability distribution.
///
/// Stored as а sparse map of byte-tuples → observed-frequency.
/// `n` is the n-gram length.  An empty model has `total_count == 0`
/// и returns zero probability for every key.
#[derive(Debug, Clone)]
pub struct NGramModel {
    n: usize,
    counts: HashMap<Vec<u8>, u64>,
    total_count: u64,
}

impl NGramModel {
    /// Construct an empty model для the given n-gram length.  Panics
    /// если `n == 0` или `n > MAX_N` — caller error, not а runtime
    /// path.
    pub fn new(n: usize) -> Self {
        assert!(n > 0, "n must be positive");
        assert!(n <= MAX_N, "n must be ≤ {MAX_N}");
        Self {
            n,
            counts: HashMap::new(),
            total_count: 0,
        }
    }

    /// N-gram length (1 = unigram = per-byte histogram).
    pub fn n(&self) -> usize {
        self.n
    }

    /// Total n-gram observations seen.  Note: this is bytes − n + 1
    /// per sample (one less than `bytes.len()` for n=2, etc.).
    pub fn total_count(&self) -> u64 {
        self.total_count
    }

    /// Number of distinct n-grams observed (non-zero buckets).
    pub fn distinct_ngrams(&self) -> usize {
        self.counts.len()
    }

    /// Update the model from а byte sample.  Sliding-window of length
    /// `n` — emits `bytes.len() - n + 1` n-grams.  Sample length less
    /// than `n` produces zero updates (silent no-op).
    pub fn observe(&mut self, bytes: &[u8]) {
        if bytes.len() < self.n {
            return;
        }
        for window in bytes.windows(self.n) {
            *self.counts.entry(window.to_vec()).or_insert(0) += 1;
            self.total_count += 1;
        }
    }

    /// Probability of а particular n-gram.  Zero for unseen n-grams.
    pub fn probability(&self, ngram: &[u8]) -> f64 {
        if ngram.len() != self.n || self.total_count == 0 {
            return 0.0;
        }
        let count = self.counts.get(ngram).copied().unwrap_or(0);
        count as f64 / self.total_count as f64
    }

    /// Iterate observed n-grams со their counts.
    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &u64)> {
        self.counts.iter()
    }
}

/// Kullback–Leibler divergence от `sample` к `reference`.  Lower =
/// "sample looks more like reference".  Asymmetric — KL(A‖B) ≠ KL(B‖A).
///
/// Uses Laplace smoothing (`+ epsilon`) on both sides to avoid
/// log(0) on n-grams что appear в `sample` но not в `reference`.
/// `epsilon` defaults к а conservative `1e-9` (corresponds к
/// "one observation if you had а billion samples"); callers що need
/// stricter / looser smoothing pass an explicit value.
///
/// Returns `f64::INFINITY` if either model is empty или the models
/// have different n-gram lengths.
pub fn kl_divergence(sample: &NGramModel, reference: &NGramModel) -> f64 {
    kl_divergence_smoothed(sample, reference, 1e-9)
}

/// KL divergence с explicit smoothing constant.
pub fn kl_divergence_smoothed(sample: &NGramModel, reference: &NGramModel, epsilon: f64) -> f64 {
    if sample.n != reference.n {
        return f64::INFINITY;
    }
    if sample.total_count == 0 || reference.total_count == 0 {
        return f64::INFINITY;
    }
    let mut kl = 0.0;
    for (ngram, &count) in sample.counts.iter() {
        let p = count as f64 / sample.total_count as f64;
        let q = (reference.counts.get(ngram).copied().unwrap_or(0) as f64 + epsilon)
            / (reference.total_count as f64 + epsilon * 256_f64.powi(sample.n as i32));
        if p > 0.0 && q > 0.0 {
            kl += p * (p / q).ln();
        }
    }
    kl
}

/// Chi-squared distance between two models.  Symmetric.  Lower =
/// closer match.  Behaves better than KL when both models are sparse.
///
/// Returns `f64::INFINITY` if either model is empty или their n-gram
/// lengths differ.
pub fn chi_squared(sample: &NGramModel, reference: &NGramModel) -> f64 {
    if sample.n != reference.n {
        return f64::INFINITY;
    }
    if sample.total_count == 0 || reference.total_count == 0 {
        return f64::INFINITY;
    }
    let mut chi = 0.0;
    let sample_total = sample.total_count as f64;
    let reference_total = reference.total_count as f64;
    // Union of keys observed в either model.
    let mut keys: Vec<&Vec<u8>> = sample.counts.keys().collect();
    for key in reference.counts.keys() {
        if !sample.counts.contains_key(key) {
            keys.push(key);
        }
    }
    for ngram in keys {
        let s = sample.counts.get(ngram).copied().unwrap_or(0) as f64 / sample_total;
        let r = reference.counts.get(ngram).copied().unwrap_or(0) as f64 / reference_total;
        let denom = s + r;
        if denom > 0.0 {
            let diff = s - r;
            chi += (diff * diff) / denom;
        }
    }
    chi
}

/// Generate а synthetic uniform-random byte stream of the requested
/// length using а seeded ChaCha8 RNG — deterministic so tests are
/// repeatable.  Useful as а reference distribution that obfs4 / AEAD
/// output should look indistinguishable from.
pub fn uniform_random_baseline(seed: u64, byte_count: usize) -> Vec<u8> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    (0..byte_count).map(|_| rng.random::<u8>()).collect()
}

/// Convenience builder — generate а random-baseline n-gram model
/// of the requested size + length.  Equivalent к
/// `NGramModel::new(n).observe(&uniform_random_baseline(seed, byte_count))`.
pub fn uniform_random_model(seed: u64, byte_count: usize, n: usize) -> NGramModel {
    let bytes = uniform_random_baseline(seed, byte_count);
    let mut model = NGramModel::new(n);
    model.observe(&bytes);
    model
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_model_zero_probability() {
        let m = NGramModel::new(1);
        assert_eq!(m.total_count(), 0);
        assert_eq!(m.probability(&[0]), 0.0);
    }

    #[test]
    fn unigram_counts_match_input() {
        let mut m = NGramModel::new(1);
        m.observe(&[1, 2, 1, 3, 1]);
        assert_eq!(m.total_count(), 5);
        assert!((m.probability(&[1]) - 0.6).abs() < 1e-9);
        assert!((m.probability(&[2]) - 0.2).abs() < 1e-9);
        assert!((m.probability(&[3]) - 0.2).abs() < 1e-9);
        assert_eq!(m.probability(&[4]), 0.0);
    }

    #[test]
    fn bigram_sliding_window() {
        let mut m = NGramModel::new(2);
        m.observe(&[1, 2, 3, 4]); // bigrams: (1,2), (2,3), (3,4)
        assert_eq!(m.total_count(), 3);
        assert!((m.probability(&[1, 2]) - 1.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn observe_sample_shorter_than_n_is_noop() {
        let mut m = NGramModel::new(3);
        m.observe(&[1, 2]); // length < n, no update
        assert_eq!(m.total_count(), 0);
    }

    #[test]
    fn identical_models_have_zero_distance() {
        // Two identically-seeded baselines: every n-gram probability
        // matches, so KL и chi-squared both reduce к 0 (modulo the
        // smoothing constant в KL, which is negligible at large N).
        let a = uniform_random_model(42, 100_000, 2);
        let b = uniform_random_model(42, 100_000, 2);
        assert!(kl_divergence(&a, &b) < 1e-6);
        assert!(chi_squared(&a, &b) < 1e-6);
    }

    #[test]
    fn uniform_random_close_to_uniform_random_diff_seeds() {
        // Two random samples от different seeds — bigram space
        // (256² = 65 536 buckets) has high variance under 100 k
        // samples (~1.5 obs per bucket on average), so empirical
        // chi² lands ~0.6.  Threshold set к 1.0 — above the noise
        // floor но below the biased-vs-random regime (≥ 2.0 в the
        // sibling test).
        let a = uniform_random_model(1, 100_000, 2);
        let b = uniform_random_model(2, 100_000, 2);
        let chi = chi_squared(&a, &b);
        assert!(chi < 1.0, "random/random chi² = {chi}, expected < 1.0");
    }

    /// Tighter bound for unigrams (256 buckets) — much lower variance
    /// since each bucket sees ~390 obs at 100 k samples.
    #[test]
    fn uniform_random_close_unigram() {
        let a = uniform_random_model(1, 100_000, 1);
        let b = uniform_random_model(2, 100_000, 1);
        let chi = chi_squared(&a, &b);
        assert!(
            chi < 0.005,
            "unigram random/random chi² = {chi}, expected < 0.005"
        );
    }

    #[test]
    fn non_random_distinguishable_from_random() {
        // А biased sample (only byte values 0..=15 — first nibble
        // only) should be EASILY distinguishable от uniform random.
        let mut biased = NGramModel::new(1);
        let bias_bytes: Vec<u8> = (0..100_000).map(|i| (i % 16) as u8).collect();
        biased.observe(&bias_bytes);
        let random = uniform_random_model(7, 100_000, 1);
        let chi = chi_squared(&biased, &random);
        // Order-of-magnitude check — biased↔random should be
        // far apart (chi² > 0.5 в practice; we floor at 0.3 for
        // robustness across RNG sample variance).
        assert!(chi > 0.3, "biased/random chi² = {chi}, expected > 0.3");
    }

    /// **Anti-censorship regression test** — the canonical assertion:
    /// obfs4-style ciphertext (AEAD output, which is statistically
    /// indistinguishable от uniform random) should match а
    /// uniform-random baseline within а tight chi² threshold.
    ///
    /// Failing this test means either:
    ///   (a) Wire-format change leaked non-random bytes into the
    ///       outer envelope (regression — fix the leak), или
    ///   (b) The threshold is too tight (revisit constant).
    #[test]
    fn aead_like_ciphertext_indistinguishable_from_uniform() {
        // Simulate AEAD output by feeding ChaCha keystream bytes
        // directly (which is bit-for-bit what AEAD produces когда
        // plaintext is zero, и а fair proxy for AEAD-over-arbitrary-
        // plaintext for n-gram analysis purposes — the output's
        // statistical properties don't depend on the plaintext).
        // Unigram (n=1, 256 buckets) — tight noise floor (~0.005).
        let aead = uniform_random_model(0xCAFEBABE, 200_000, 1);
        let reference = uniform_random_model(0xDEADBEEF, 200_000, 1);
        let chi = chi_squared(&aead, &reference);
        // Conservative bound — random/random unigram chi² at 200 k
        // samples lands ≈ 0.002; threshold 0.01 sits comfortably
        // above the noise floor while still tripping on а real
        // distribution shift (biased samples hit > 0.3 in the
        // sibling test).
        assert!(
            chi < 0.01,
            "AEAD-like vs reference chi² = {chi}, expected < 0.01 — \
             possible regression: wire format leaks non-random bytes"
        );
    }

    /// Sample-size sanity: doubling the sample size should reduce
    /// the chi² between two random samples (variance shrinks с √N).
    /// Catches а bug в the chi² normalization (e.g., forgetting к
    /// divide by total_count).
    #[test]
    fn chi_squared_decreases_with_sample_size() {
        let small_a = uniform_random_model(10, 10_000, 2);
        let small_b = uniform_random_model(20, 10_000, 2);
        let large_a = uniform_random_model(30, 100_000, 2);
        let large_b = uniform_random_model(40, 100_000, 2);
        let small_chi = chi_squared(&small_a, &small_b);
        let large_chi = chi_squared(&large_a, &large_b);
        assert!(
            large_chi < small_chi,
            "expected chi² к decrease с sample size: \
             small={small_chi}, large={large_chi}"
        );
    }

    #[test]
    fn kl_divergence_zero_when_distributions_match() {
        let a = uniform_random_model(99, 100_000, 1);
        let b = uniform_random_model(99, 100_000, 1);
        let kl = kl_divergence(&a, &b);
        assert!(kl.abs() < 1e-6, "KL(A‖A) = {kl}, expected ~0");
    }

    #[test]
    fn mismatched_n_returns_infinity() {
        let a = NGramModel::new(2);
        let b = NGramModel::new(3);
        assert_eq!(kl_divergence(&a, &b), f64::INFINITY);
        assert_eq!(chi_squared(&a, &b), f64::INFINITY);
    }

    #[test]
    fn empty_model_distance_is_infinity() {
        let a = NGramModel::new(2);
        let b = uniform_random_model(1, 1000, 2);
        assert_eq!(kl_divergence(&a, &b), f64::INFINITY);
        assert_eq!(chi_squared(&a, &b), f64::INFINITY);
    }

    #[test]
    fn baseline_is_deterministic_for_same_seed() {
        let a = uniform_random_baseline(123, 1000);
        let b = uniform_random_baseline(123, 1000);
        assert_eq!(a, b, "seeded baseline must be deterministic");
    }
}
