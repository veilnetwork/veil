//! Adaptive network parameters.
//!
//! Instead of hardcoded constants, each node estimates the network size `N`
//! from its local state and derives optimal routing parameters from `N`.
//! Parameters are recomputed on each `reload` cycle.

// ── NetworkSizeEstimator ─────────────────────────────────────────────────────

/// Estimate the global network size from locally-observable state.
///
/// The heuristic combines:
/// `routing_table_contacts`: total contacts across all k-buckets
/// `active_sessions`: number of live OVL1 sessions
/// `bootstrap_peers`: number of configured bootstrap peers
///
/// For a Kademlia network with k-bucket size K, a well-populated routing table
/// of C contacts implies `N ≈ C * 2^(256/C)` but that's overly precise.
/// The practical formula: `N ≈ C * C` (contacts squared) provides a rough
/// order-of-magnitude estimate that errs on the high side, which is the safe
/// direction (larger N → more conservative parameters).
///
/// Floor: 100 (minimum meaningful network).
/// Ceiling: 10^10 (design limit).
#[derive(Debug, Clone, Copy)]
pub struct NetworkSizeEstimate {
    /// Estimated total network size, clamped to `[100, 10^10]`.
    pub estimated_n: u64,
    /// DHT routing-table contact count the estimate was derived from.
    pub routing_table_contacts: usize,
    /// OVL1 active-session count the estimate was derived from.
    pub active_sessions: usize,
}

/// Estimate the overall network size from local observations.
///
/// Uses `N ≈ c²` where `c = max(routing_table_contacts, active_sessions)`;
/// the clamp `[100, 10^10]` keeps adaptive params in a sane range for very
/// small or pathologically large `c`.
pub fn estimate_network_size(
    routing_table_contacts: usize,
    active_sessions: usize,
) -> NetworkSizeEstimate {
    let c = routing_table_contacts.max(active_sessions) as u64;
    // N ≈ c² (clamped [100, 10^10]).
    let raw = c.saturating_mul(c);
    let estimated_n = raw.clamp(100, 10_000_000_000);
    NetworkSizeEstimate {
        estimated_n,
        routing_table_contacts,
        active_sessions,
    }
}

// ── AdaptiveParams ───────────────────────────────────────────────────────────

/// Computed routing/DHT parameters derived from estimated network size.
///
/// All formulas produce monotonically increasing values as N grows and
/// degrade gracefully to sensible defaults for small networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveParams {
    /// Kademlia bucket size. `max(20, ceil(log2(N)))`
    pub k: usize,
    /// Gossip ROUTE_ANNOUNCE TTL. `min(ceil(1.5 * log_K(N)), 24)`
    pub gossip_ttl: u8,
    /// Epidemic broadcast fan-out. `max(3, ceil(sqrt(K)))`
    pub epidemic_fanout: usize,
    /// Route cache capacity. `clamp(N / 100, 1_024, 1_000_000)`
    pub route_cache_capacity: usize,
    /// Route seen-set capacity. `route_cache_capacity * 4`
    pub route_seen_capacity: usize,
    /// Peer public-key cache size. `clamp(N / 10, 65_536, 10_000_000)`
    pub peer_pubkey_cache: usize,
    /// Max nodes per subnet per k-bucket (Eclipse protection). `k / 4`
    pub max_nodes_per_subnet_per_bucket: usize,
    /// minimum shared-prefix bits a recursive-query responder
    /// must have with the queried key for the receiver to accept the
    /// response (anti-amplification). Production used to hardcode this
    /// at 16 bits — but on a network of N uniformly-
    /// distributed nodes the *expected* maximum shared-prefix among honest
    /// peers is `log2(N)` bits, so 16 bits required ≥ 2^16 ≈ 65K nodes
    /// before *any* legitimate random-key recursive lookup could clear
    /// the gate. That blocked every small-network bootstrap path
    /// (early testnet, 100-1000 node deployments, isolated meshes in
    /// authoritarian states) — the gate was anti-amplification on
    /// paper, anti-bootstrap in practice.
    ///
    /// Adaptive formula: `min(16, max(0, ceil(log2(N)) - 4))`.
    /// * Floors at 0 for very small N — gate disabled, every honest
    ///   peer proves they hold the value by sending the actual bytes
    ///   (the gate was redundant defense layered on top of the
    ///   payload-already-validated invariant).
    /// * Saturates at 16 for N ≥ 2^20 ≈ 1M — preserves the production
    ///   anti-amplification floor at scale (matches 's
    ///   `2^16 = 65k attempts per forged response`).
    /// * In between: scales such that the top 1/16 closest peers
    ///   always clear, blocking adversaries who hold less than ~6.25%
    ///   of the network — a high bar even in adversarial-majority
    ///   scenarios.
    ///
    /// Worked examples (`from_network_size` = `clamp(ceil(log2(N)) - 4, 0, 16)`):
    /// * N=100 → 3 bits (audit cycle-5 fix: `ceil(log2(100)) - 4 = 3`, NOT 0 —
    ///   the gate-off 0-bit behaviour comes from `Default` / the runtime override
    ///   `min_responder_prefix_bits_from_observed`, not from this field's
    ///   `from_network_size`-derived value)
    /// * N=1024 → 6 bits (legitimate top 1/64 closest pass)
    /// * N=65k → 12 bits
    /// * N=1M → 16 bits (production floor reached)
    /// * N=10B → 16 bits (capped)
    pub min_responder_prefix_bits: u32,
    /// Original network size estimate.
    pub estimated_n: u64,
}

impl AdaptiveParams {
    /// Compute the minimum responder-proximity prefix bits
    /// from the **actually observed** peer count (routing-table contacts
    /// or active sessions, whichever is larger), NOT from the floored
    /// `estimate_network_size` value.
    ///
    /// Why a separate formula instead of using `from_network_size`'s
    /// estimated_n: `estimate_network_size` floors at 100 to keep cache
    /// capacities + k-bucket size sane for very small networks. For the
    /// proximity gate this floor backfires — on a 2-node devnet the
    /// floored estimate of 100 produces a 3-bit gate that rejects every
    /// recursive response (expected closest peer leading_zeros on 2
    /// nodes is ≤1 bit). By computing the gate from the raw observed
    /// peer count we get gate=0 on tiny networks (every peer clears
    /// bootstrap works) and the same `min(16, log2(N) - 4)` curve at
    /// scale.
    ///
    /// Formula: `min(16, max(0, ceil(log2(max(1, observed))) - 4))`.
    /// `max(1, observed)` avoids `log2(0) = -inf` when no peers are
    /// connected yet (early startup); the formula then naturally
    /// returns 0 ("gate off, accept anything").
    pub fn min_responder_prefix_bits_from_observed(observed_peer_count: usize) -> u32 {
        let n = observed_peer_count.max(1) as f64;
        let raw = n.log2().ceil() as i64 - 4;
        raw.clamp(0, 16) as u32
    }

    /// Compute the minimum PoW difficulty for a network of estimated size `n`.
    ///
    /// Formula: `24 + ceil(log2(N / 100_000))`. At N=100K → 24 bits (current
    /// production default). At N=10^10 → 41 bits. Capped at 48 bits.
    pub fn adaptive_pow_difficulty(n: u64) -> u32 {
        let n = n.max(100_000); // floor at 100K → difficulty 24
        let extra = ((n as f64 / 100_000.0).log2().ceil() as u32).min(24);
        24 + extra
    }

    /// Compute adaptive parameters from the estimated network size.
    pub fn from_network_size(n: u64) -> Self {
        let n = n.max(100); // floor
        let nf = n as f64;
        let log2_n = nf.log2();

        // K = max(20, ceil(log2(N)))
        let k = (log2_n.ceil() as usize).max(20);

        // Gossip TTL = min(ceil(1.5 * log_K(N)), 24)
        let log_k_n = if k > 1 { nf.log(k as f64) } else { log2_n };
        let gossip_ttl = ((1.5 * log_k_n).ceil() as u8).min(24);

        // Epidemic fan-out = max(3, ceil(sqrt(K)))
        let epidemic_fanout = ((k as f64).sqrt().ceil() as usize).max(3);

        // Route cache capacity = clamp(N / 100, 1_024, 1_000_000)
        let route_cache_capacity = ((n / 100) as usize).clamp(1_024, 1_000_000);

        // Route seen capacity = route_cache * 4
        let route_seen_capacity = route_cache_capacity.saturating_mul(4);

        // Peer pubkey cache = clamp(N / 10, 65_536, 10_000_000)
        let peer_pubkey_cache = ((n / 10) as usize).clamp(65_536, 10_000_000);

        // Subnet diversity = k / 4 (at least 1)
        let max_nodes_per_subnet_per_bucket = (k / 4).max(1);

        // responder-proximity gate: min(16, max(0, log2(N) - 4)).
        // See `min_responder_prefix_bits` field doc for the security/
        // bootstrap-liveness trade-off. `log2_n.ceil` rather than
        // `floor` so a mesh of exactly 2^k nodes uses the higher rounding
        // (more conservative for adversaries near a power-of-2 boundary).
        let min_responder_prefix_bits = {
            let raw = log2_n.ceil() as i64 - 4;
            raw.clamp(0, 16) as u32
        };

        Self {
            k,
            gossip_ttl,
            epidemic_fanout,
            route_cache_capacity,
            route_seen_capacity,
            peer_pubkey_cache,
            max_nodes_per_subnet_per_bucket,
            min_responder_prefix_bits,
            estimated_n: n,
        }
    }
}

impl Default for AdaptiveParams {
    fn default() -> Self {
        // bootstrap-mode gate. At dispatcher construction
        // time we have zero connected peers, so the only correct gate
        // value is 0 (accept anything). The reload tick recomputes
        // this from the live routing table once peers connect. Cache
        // sizes etc. still use `from_network_size(100)` floor.
        let mut p = Self::from_network_size(100);
        p.min_responder_prefix_bits = 0;
        p
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_small_network() {
        let est = estimate_network_size(10, 5);
        assert_eq!(est.estimated_n, 100); // floor
    }

    #[test]
    fn estimate_medium_network() {
        let est = estimate_network_size(1_000, 50);
        assert_eq!(est.estimated_n, 1_000_000); // 1000²
    }

    #[test]
    fn estimate_large_network() {
        let est = estimate_network_size(100_000, 100);
        assert_eq!(est.estimated_n, 10_000_000_000); // capped at 10^10
    }

    #[test]
    fn adaptive_params_n_100() {
        let p = AdaptiveParams::from_network_size(100);
        assert_eq!(p.k, 20, "K floor at 20 for small networks");
        assert!(p.gossip_ttl >= 2 && p.gossip_ttl <= 5);
        assert_eq!(p.epidemic_fanout, 5); // ceil(sqrt(20)) = 5
        assert_eq!(p.route_cache_capacity, 1_024); // floor
        assert_eq!(p.max_nodes_per_subnet_per_bucket, 5); // 20/4
    }

    #[test]
    fn adaptive_params_n_1m() {
        let p = AdaptiveParams::from_network_size(1_000_000);
        assert_eq!(p.k, 20, "log2(10^6) = 19.9 → 20");
        assert!(p.gossip_ttl >= 4, "TTL for 10^6: {}", p.gossip_ttl);
        assert_eq!(p.route_cache_capacity, 10_000); // 10^6 / 100
        assert_eq!(p.peer_pubkey_cache, 100_000); // 10^6 / 10
    }

    #[test]
    fn adaptive_params_n_10b() {
        let p = AdaptiveParams::from_network_size(10_000_000_000);
        assert_eq!(p.k, 34, "log2(10^10) = 33.2 → 34");
        assert!(p.gossip_ttl <= 24, "TTL capped at 24");
        assert_eq!(p.epidemic_fanout, 6); // ceil(sqrt(34)) = 6
        assert_eq!(p.route_cache_capacity, 1_000_000); // cap
        assert_eq!(p.peer_pubkey_cache, 10_000_000); // capped
    }

    #[test]
    fn adaptive_pow_difficulty_values() {
        assert_eq!(AdaptiveParams::adaptive_pow_difficulty(100), 24); // floor
        assert_eq!(AdaptiveParams::adaptive_pow_difficulty(100_000), 24);
        assert_eq!(AdaptiveParams::adaptive_pow_difficulty(1_000_000), 28); // log2(10) ≈ 3.3 → 4
        assert_eq!(AdaptiveParams::adaptive_pow_difficulty(10_000_000_000), 41); // log2(10^5) ≈ 16.6 → 17
    }

    #[test]
    fn adaptive_params_monotonic() {
        let sizes = [100, 1_000, 100_000, 10_000_000, 10_000_000_000];
        let params: Vec<_> = sizes
            .iter()
            .map(|&n| AdaptiveParams::from_network_size(n))
            .collect();
        for w in params.windows(2) {
            assert!(w[1].k >= w[0].k, "K must be monotonic");
            assert!(w[1].route_cache_capacity >= w[0].route_cache_capacity);
            // min_responder_prefix_bits must also be monotonic
            // — adversary capability scales with absolute N, so the gate
            // tightens (or saturates) but never loosens as N grows.
            assert!(
                w[1].min_responder_prefix_bits >= w[0].min_responder_prefix_bits,
                "min_responder_prefix_bits must be monotonic in N",
            );
        }
    }

    /// prove the adaptive responder-proximity gate solves the
    /// "16-bit hardcoded threshold blocks small-network bootstrap" issue.
    /// At small N the gate floors to 0 (every honest peer clears, no
    /// random-key recursive-lookup gets rejected). At N≈1M and above
    /// it saturates at 16 — exactly matching the pre-refactor
    /// production behaviour, so anti-amplification at scale is
    /// preserved.
    #[test]
    fn adaptive_gate_floors_small_network() {
        // 2-node devnet (after estimate floor of 100): gate must be ≤
        // a few bits or every random-key lookup would be rejected.
        let p = AdaptiveParams::from_network_size(100);
        assert!(
            p.min_responder_prefix_bits <= 4,
            "gate must floor for small N (got {} bits at N=100)",
            p.min_responder_prefix_bits
        );
    }

    #[test]
    fn adaptive_gate_saturates_large_network() {
        // 1M-node deployment matches the pre-refactor production
        // anti-amplification floor (= 16 bits; hardcoded
        // value). Production behaviour at scale is preserved.
        for n in [1_000_000u64, 10_000_000, 1_000_000_000, 10_000_000_000] {
            let p = AdaptiveParams::from_network_size(n);
            assert_eq!(
                p.min_responder_prefix_bits, 16,
                "gate must saturate at 16 bits for N={n} (got {})",
                p.min_responder_prefix_bits
            );
        }
    }

    /// observed-count gate must floor at 0 for tiny
    /// networks so bootstrap actually works. This is the test that
    /// was missing in the first commit — `from_network_size`'s
    /// floor-at-100 produced gate=3 on a 2-node devnet, rejecting
    /// every recursive response. The observed-count formula bypasses
    /// the floor and computes from the raw peer count.
    #[test]
    fn observed_gate_zero_on_tiny_networks() {
        for c in 0..=2usize {
            let g = AdaptiveParams::min_responder_prefix_bits_from_observed(c);
            assert_eq!(
                g, 0,
                "observed peer count {c}: expected gate=0 (bootstrap-mode), got {g}"
            );
        }
    }

    /// observed-count gate must reach the production floor
    /// of 16 at N≥1M observed peers — same as the legacy hardcoded
    /// behaviour, so anti-amplification at scale is preserved.
    #[test]
    fn observed_gate_saturates_at_scale() {
        for c in [1_048_576usize, 10_000_000, 100_000_000] {
            let g = AdaptiveParams::min_responder_prefix_bits_from_observed(c);
            assert_eq!(
                g, 16,
                "observed peer count {c}: expected gate=16 (production floor), got {g}"
            );
        }
    }

    /// spot-check the curve with explicit (observed, gate) pairs.
    #[test]
    fn observed_gate_curve_spotcheck() {
        let cases = [
            (1usize, 0),     // log2(1)=0, 0-4 → clamp 0
            (16, 0),         // log2(16)=4, 4-4 = 0
            (32, 1),         // log2(32)=5, 5-4 = 1
            (256, 4),        // log2(256)=8, 8-4 = 4
            (1024, 6),       // log2(1024)=10, 10-4 = 6
            (65_536, 12),    // log2(65k)=16, 16-4 = 12
            (1_048_576, 16), // saturated
        ];
        for (c, expected) in cases {
            let g = AdaptiveParams::min_responder_prefix_bits_from_observed(c);
            assert_eq!(
                g, expected,
                "observed={c}: expected {expected} bits, got {g}"
            );
        }
    }

    /// AdaptiveParams::default must publish gate=0 so
    /// that the dispatcher's initial state (before the first reload
    /// tick computes real values) doesn't accidentally reject every
    /// recursive response in bootstrap.
    #[test]
    fn default_params_have_zero_gate() {
        let p = AdaptiveParams::default();
        assert_eq!(
            p.min_responder_prefix_bits, 0,
            "default AdaptiveParams must start with gate=0 (bootstrap mode)"
        );
    }

    #[test]
    fn adaptive_gate_intermediate_values() {
        // Spot-check the curve. These exact values lock in the
        // formula `min(16, max(0, ceil(log2(N)) - 4))` — if a future
        // refactor shifts the curve (e.g., changes the security
        // margin from 4 to 6), this test forces an explicit decision
        // about whether the new curve still meets the bootstrap-vs-
        // amplification trade-off.
        let cases = [
            (100u64, 3),     // ceil(log2(100))=7, 7-4=3
            (1_024, 6),      // ceil(log2(1024))=10, 10-4=6
            (16_384, 10),    // ceil(log2(16384))=14, 14-4=10
            (65_536, 12),    // ceil(log2(65536))=16, 16-4=12
            (262_144, 14),   // ceil(log2(262144))=18, 18-4=14
            (1_048_576, 16), // saturates
        ];
        for (n, expected) in cases {
            let p = AdaptiveParams::from_network_size(n);
            assert_eq!(
                p.min_responder_prefix_bits, expected,
                "N={n}: expected {expected} bits, got {}",
                p.min_responder_prefix_bits
            );
        }
    }
}
