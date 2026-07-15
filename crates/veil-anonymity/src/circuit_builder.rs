//! Circuit builder.
//!
//! Picks `N` hops out of a candidate pool returned by
//! [`super::directory::discover_relay_hops`], producing a hop list
//! ready [`super::packet::build_anonymous_cell`] to wrap.
//!
//! Two strategies ship in this slice:
//!
//! * [`pick_circuit_hops_random`] — uniform-random selection from
//!   the candidate pool. Baseline; no information leak about
//!   sender's network position. Use this when latency data is
//!   unavailable or untrusted.
//!
//! * [`pick_circuit_hops_latency_aware`] — sort candidates by an
//!   externally-provided RTT estimate (typically Vivaldi-derived
//!   pick the `N` lowest. Composes anonymity with
//!   the latency-aware routing infrastructure. **This is the
//!   novelty-vs-Tor piece**: Tor selects circuit hops by relay
//!   bandwidth + uniform random; we select by user-experienced
//!   latency, which gives interactive-traffic UX significantly
//!   better than Tor's typical 200–800 ms per round trip.
//!
//! # Anonymity-validity constraints
//!
//! Both strategies enforce **distinct hops** — same hop appearing
//! twice in a circuit reduces anonymity to that of an N-1-hop
//! circuit while still paying the latency cost of N. v1 of this
//! module deduplicates by `node_id`; geographic / AS-diversity
//! constraints (e.g., "don't pick three hops from the same
//! `/24` netblock or same operator") belong in a follow-up that
//! has the necessary IP / AS metadata.
//!
//! # What this module does NOT do (deferred to follow-ups)
//!
//! * **Path-product latency optimisation**: with only single-sided
//!   RTT estimates (sender → each candidate), we can't optimize
//!   for inter-hop legs (B → C latency given path A → B → C).
//!   `pick_circuit_hops_latency_aware` minimises the sum of
//!   sender-to-each-hop RTTs, which is a useful proxy but not
//!   optimal. Pairwise RTT discovery is its own slice.
//! * **Bandwidth-weighted selection**: candidates carry
//!   `advertised_bps`; this module ignores it. A future weighted
//!   strategy could bias toward higher-bandwidth relays for bulk
//!   transfers and lower-latency for interactive — out of scope
//!   here.
//! * **Sticky / persistent circuits**: this module returns hop
//!   selections, not CircuitId-tagged sessions. Stateful circuits
//!   belong in the dispatcher integration.

use std::collections::HashSet;

use super::circuit::Hop;
use super::directory::DiscoveredRelay;

/// `Some(hops)` when ≥ `n` distinct candidates were available;
/// `None` when the candidate pool can't fill the requested hop
/// count. Returning `None` instead of "best effort" avoids
/// silently building an under-sized circuit that the caller may
/// not realise is weaker than expected.
pub type CircuitPickResult = Option<Vec<Hop>>;

/// Uniform-random selection of `n` distinct hops from the candidate
/// pool. Caller supplies a `prng_byte` closure that returns a
/// fresh random byte per call (typically `OsRng.next_u32 as u8`);
/// injected so this function stays pure for unit tests.
///
/// Returns `None` if the pool has fewer than `n` distinct candidates.
///
/// cleanup: pre-replaced by `pick_circuit_hops_latency_aware`
/// — current production sender uses the latency-aware variant exclusively.
/// Kept under `#[cfg(test)]` as a baseline for diversity-test scenarios
/// where uniform selection is the null-hypothesis.
#[cfg(test)]
pub fn pick_circuit_hops_random<R>(
    candidates: &[DiscoveredRelay],
    n: usize,
    mut prng_byte: R,
) -> CircuitPickResult
where
    R: FnMut() -> u8,
{
    let distinct: Vec<&DiscoveredRelay> = dedup_by_node_id(candidates);
    if distinct.len() < n {
        return None;
    }
    // Fisher-Yates partial shuffle: pick n in O(n) without
    // allocating a full permutation. We index into `distinct` via
    // a working Vec and swap in the picked element.
    let mut pool: Vec<&DiscoveredRelay> = distinct;
    let len = pool.len();
    let mut picked = Vec::with_capacity(n);
    for i in 0..n {
        // Bound the random byte into [i, len). PRNG-byte modulo
        // bias is acceptable for circuit selection — the bias is
        // bounded by 256/(len-i) which for typical len ≤ 256 means
        // < 1 % skew per slot.
        let remaining = len - i;
        let pick_offset = (prng_byte() as usize) % remaining;
        let chosen = i + pick_offset;
        pool.swap(i, chosen);
        picked.push(pool[i].hop);
    }
    Some(picked)
}

/// Latency-aware selection: sort candidates by `rtt_estimator(node_id)`
/// ascending, pick the `n` lowest. Distinct-by-node-id; ties broken
/// by candidate-pool order (stable sort).
///
/// `rtt_estimator` returns `Some(rtt_ms)` when the sender has a usable
/// RTT estimate for the candidate (typically from
/// [`veilcore::node::routing::VivaldiCoord`] —) or `None` when
/// no estimate is known. Candidates without an estimate sort to the
/// END of the candidate list (lower priority), so the sender never
/// blindly picks an unknown-latency hop over a known-low-latency one.
///
/// Returns `None` if the pool has fewer than `n` distinct candidates.
pub fn pick_circuit_hops_latency_aware<F>(
    candidates: &[DiscoveredRelay],
    n: usize,
    rtt_estimator: F,
) -> CircuitPickResult
where
    F: Fn(&[u8; 32]) -> Option<u32>,
{
    let distinct: Vec<&DiscoveredRelay> = dedup_by_node_id(candidates);
    if distinct.len() < n {
        return None;
    }
    // Score: (rtt_or_inf, original_index) — Some(rtt) ranks below
    // None (we use u64::MAX as sentinel for missing RTT so sort
    // pushes them last). Stable sort preserves input order on ties.
    let mut scored: Vec<(u64, &DiscoveredRelay)> = distinct
        .iter()
        .map(|c| {
            let rtt = rtt_estimator(&c.hop.node_id)
                .map(|x| x as u64)
                .unwrap_or(u64::MAX);
            (rtt, *c)
        })
        .collect();
    scored.sort_by_key(|(rtt, _)| *rtt);
    Some(scored.into_iter().take(n).map(|(_, c)| c.hop).collect())
}

/// Latency-aware selection with **AS / geographic diversity**.
///
/// Like [`pick_circuit_hops_latency_aware`] but additionally enforces
/// a "no two hops share the same diversity-key" rule. The
/// `diversity_key_of` closure maps each candidate's `node_id` to an
/// opaque key (typically `Some("v4:1.2")` for the /16 IPv4 prefix
/// `Some("v6:fc00:0000")` for the /32 IPv6 prefix, or `Some("AS13335")`
/// when the caller has an ASN dataset). Returns `None` for candidates
/// where the key cannot be derived; those candidates are still
/// eligible (no diversity constraint applies, but they don't BLOCK
/// other candidates either).
///
/// **Why diversity matters for anonymity:** an attacker who controls
/// a single AS or /16 netblock can deanonymize circuit traffic via
/// the well-known "first-and-last hop in same AS = traffic correlation
/// attack" pattern. Enforcing distinct AS across all picked hops
/// turns the attack from "control one AS" to "control multiple
/// independent ASes" — substantially raising the bar.
///
/// Selection algorithm:
/// 1. Sort candidates by RTT (same as `latency_aware`).
/// 2. Walk in sorted order, keep a candidate iff its
///    diversity-key has not been seen yet (or is `None`).
/// 3. Stop after `n` distinct-key picks.
///
/// Returns `None` if fewer than `n` distinct-key candidates exist.
/// Greedy by latency: closer-by-RTT candidates win each diversity
/// slot; further-out candidates with conflicting keys are skipped.
pub fn pick_circuit_hops_latency_aware_with_diversity<F, K>(
    candidates: &[DiscoveredRelay],
    n: usize,
    rtt_estimator: F,
    diversity_key_of: K,
) -> CircuitPickResult
where
    F: Fn(&[u8; 32]) -> Option<u32>,
    K: Fn(&[u8; 32]) -> Option<String>,
{
    let distinct: Vec<&DiscoveredRelay> = dedup_by_node_id(candidates);
    if distinct.len() < n {
        return None;
    }
    let mut scored: Vec<(u64, &DiscoveredRelay)> = distinct
        .iter()
        .map(|c| {
            let rtt = rtt_estimator(&c.hop.node_id)
                .map(|x| x as u64)
                .unwrap_or(u64::MAX);
            (rtt, *c)
        })
        .collect();
    scored.sort_by_key(|(rtt, _)| *rtt);

    let mut seen_keys: HashSet<String> = HashSet::new();
    let mut picked: Vec<Hop> = Vec::with_capacity(n);
    for (_, c) in scored {
        if let Some(key) = diversity_key_of(&c.hop.node_id)
            && !seen_keys.insert(key)
        {
            continue; // duplicate AS — skip this candidate
        }
        // No diversity-key (e.g. transport is non-IP, or BLE) — accept.
        // This is the conservative choice: rejecting unkeyed candidates
        // would silently exclude legit relays whose transport doesn't
        // have an extractable AS prefix (e.g. mesh-only or
        // future Tor-bridge transport).
        picked.push(c.hop);
        if picked.len() == n {
            return Some(picked);
        }
    }
    None // fewer than `n` AS-distinct candidates available
}

/// Latency-aware + AS-diversity + **reputation-downweighting** selection
/// (Epic 482.3/482.4 Phase A).
///
/// Identical to [`pick_circuit_hops_latency_aware_with_diversity`] except
/// the latency score is bumped by a reputation-derived penalty: every
/// observed failure for the relay (from
/// [`crate::relay_reputation::RelayReputation::record_failure`]) adds
/// [`crate::relay_reputation::FAILURE_PENALTY_MS`] ms to its effective RTT.
/// Relays that admit circuit builds but then drop / stall cells suffer
/// progressively worse ranking with each observed failure.
///
/// `reputation_penalty_ms` is a closure (rather than a direct
/// `&RelayReputation` ref) so callers can:
/// - Plug in a no-op (always-0) penalty in tests.
/// - Combine multiple penalty sources (e.g. reputation + per-deployment
///   operator-supplied deny-list weight).
///
/// Selection algorithm:
/// 1. Score each candidate: `score = rtt_or_inf + reputation_penalty_ms`.
///    Missing RTT still maps to `u64::MAX` — reputation cannot promote
///    unknown-RTT relays past known ones.
/// 2. Sort ascending by score.
/// 3. Walk in sorted order; keep a candidate iff its diversity-key has
///    not been seen yet (or is `None`).
/// 4. Stop after `n` distinct-key picks.
///
/// Returns `None` if fewer than `n` distinct-key candidates exist.
pub fn pick_circuit_hops_latency_aware_with_diversity_and_reputation<F, K, P>(
    candidates: &[DiscoveredRelay],
    n: usize,
    rtt_estimator: F,
    diversity_key_of: K,
    reputation_penalty_ms: P,
) -> CircuitPickResult
where
    F: Fn(&[u8; 32]) -> Option<u32>,
    K: Fn(&[u8; 32]) -> Option<String>,
    P: Fn(&[u8; 32]) -> u32,
{
    pick_circuit_hops_latency_aware_with_diversity_and_reputation_guarded(
        candidates,
        n,
        rtt_estimator,
        diversity_key_of,
        reputation_penalty_ms,
        |_| true, // no liveness gate — every candidate is guard-eligible
    )
}

/// Like [`pick_circuit_hops_latency_aware_with_diversity_and_reputation`] but
/// the FIRST hop (guard slot) prefers candidates for which `first_hop_live`
/// returns `true` — in production, "we hold a live direct session to this
/// relay" ([`SessionTxRegistry::has_session`]-shaped).
///
/// Why the first hop is special: the built cell is handed to `hops[0]` over a
/// DIRECT session — there is no dial-on-demand on the send path, so picking a
/// sessionless first hop silently drops the entire cell (the send layer
/// returns `false` and the message dies until an app-layer retry). Middle and
/// terminus hops are reached THROUGH the circuit and need no local session,
/// so the liveness gate deliberately applies to the guard slot only — the
/// anonymity set of later hops is untouched.
///
/// Anonymity: Tor-guard semantics. The first hop already learns our IP by
/// virtue of the direct session, so preferring already-connected relays
/// reveals nothing new; it pins the guard slot to the live-session set
/// (typically small), which is the same trade Tor makes deliberately with
/// persistent guards.
///
/// Selection:
/// 1. Score + sort all candidates (same as the ungated variant).
/// 2. Guard slot = best-scored candidate with `first_hop_live == true`;
///    if NO live candidate exists, fall back to the best-scored overall
///    (exactly the previous behavior — a cold node still builds circuits).
/// 3. Remaining `n-1` picks: diversity walk over the rest in score order,
///    seeded with the guard's diversity key.
pub fn pick_circuit_hops_latency_aware_with_diversity_and_reputation_guarded<F, K, P, G>(
    candidates: &[DiscoveredRelay],
    n: usize,
    rtt_estimator: F,
    diversity_key_of: K,
    reputation_penalty_ms: P,
    first_hop_live: G,
) -> CircuitPickResult
where
    F: Fn(&[u8; 32]) -> Option<u32>,
    K: Fn(&[u8; 32]) -> Option<String>,
    P: Fn(&[u8; 32]) -> u32,
    G: Fn(&[u8; 32]) -> bool,
{
    if n == 0 {
        return Some(Vec::new());
    }
    let distinct: Vec<&DiscoveredRelay> = dedup_by_node_id(candidates);
    if distinct.len() < n {
        return None;
    }
    // Score = rtt + reputation_penalty. Missing-RTT stays at u64::MAX
    // — penalty cannot promote that kind of candidate over a known one.
    let mut scored: Vec<(u64, &DiscoveredRelay)> = distinct
        .iter()
        .map(|c| {
            let rtt = rtt_estimator(&c.hop.node_id)
                .map(|x| x as u64)
                .unwrap_or(u64::MAX);
            let penalty = reputation_penalty_ms(&c.hop.node_id) as u64;
            let score = rtt.saturating_add(penalty);
            (score, *c)
        })
        .collect();
    scored.sort_by_key(|(score, _)| *score);

    // Guard slot: best-scored live candidate, else best-scored overall
    // (index 0 — identical to the ungated walk's first pick).
    let guard_idx = scored
        .iter()
        .position(|(_, c)| first_hop_live(&c.hop.node_id))
        .unwrap_or(0);
    let (_, guard) = scored.remove(guard_idx);

    let mut seen_keys: HashSet<String> = HashSet::new();
    if let Some(key) = diversity_key_of(&guard.hop.node_id) {
        seen_keys.insert(key);
    }
    let mut picked: Vec<Hop> = Vec::with_capacity(n);
    picked.push(guard.hop);
    if picked.len() == n {
        return Some(picked);
    }
    for (_, c) in scored {
        if let Some(key) = diversity_key_of(&c.hop.node_id)
            && !seen_keys.insert(key)
        {
            continue;
        }
        picked.push(c.hop);
        if picked.len() == n {
            return Some(picked);
        }
    }
    None
}

/// Guard-slot sibling of [`pick_circuit_hops_latency_aware`] for the
/// degraded latency-only fallback path (no AS-diverse set exists): sort by
/// RTT, first hop prefers `first_hop_live` candidates, rest are the best of
/// the remainder. Falls back to the plain best-scored pick when no live
/// candidate exists — see the guarded diversity variant for the rationale.
pub fn pick_circuit_hops_latency_aware_guarded<F, G>(
    candidates: &[DiscoveredRelay],
    n: usize,
    rtt_estimator: F,
    first_hop_live: G,
) -> CircuitPickResult
where
    F: Fn(&[u8; 32]) -> Option<u32>,
    G: Fn(&[u8; 32]) -> bool,
{
    if n == 0 {
        return Some(Vec::new());
    }
    let distinct: Vec<&DiscoveredRelay> = dedup_by_node_id(candidates);
    if distinct.len() < n {
        return None;
    }
    let mut scored: Vec<(u64, &DiscoveredRelay)> = distinct
        .iter()
        .map(|c| {
            let rtt = rtt_estimator(&c.hop.node_id)
                .map(|x| x as u64)
                .unwrap_or(u64::MAX);
            (rtt, *c)
        })
        .collect();
    scored.sort_by_key(|(rtt, _)| *rtt);

    let guard_idx = scored
        .iter()
        .position(|(_, c)| first_hop_live(&c.hop.node_id))
        .unwrap_or(0);
    let (_, guard) = scored.remove(guard_idx);

    let mut picked: Vec<Hop> = Vec::with_capacity(n);
    picked.push(guard.hop);
    picked.extend(scored.into_iter().take(n - 1).map(|(_, c)| c.hop));
    Some(picked)
}

/// Dedup candidate list by `node_id`, preserving first-occurrence
/// order. Keeps this private — both strategies need the same
/// deduplication rule, and exposing it would invite callers to
/// re-implement it slightly differently.
fn dedup_by_node_id(candidates: &[DiscoveredRelay]) -> Vec<&DiscoveredRelay> {
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    candidates
        .iter()
        .filter(|c| seen.insert(c.hop.node_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_hop(id_byte: u8, x25519_byte: u8) -> DiscoveredRelay {
        let mut node_id = [0u8; 32];
        node_id[0] = id_byte;
        let mut pubkey = [0u8; 32];
        pubkey[0] = x25519_byte;
        DiscoveredRelay {
            hop: Hop { node_id, pubkey },
            advertised_bps: 1_000_000,
            last_published_unix: 1_700_000_000,
        }
    }

    /// Deterministic PRNG closure for tests — cycles through a
    /// pre-set sequence so test outcomes are reproducible.
    fn fixed_prng(bytes: Vec<u8>) -> impl FnMut() -> u8 {
        let mut idx = 0;
        move || {
            let b = bytes[idx % bytes.len()];
            idx += 1;
            b
        }
    }

    // ── pick_circuit_hops_random ──────────────────────────────────────

    #[test]
    fn epic482_6_random_returns_none_when_pool_smaller_than_n() {
        let pool = vec![fixture_hop(1, 0xAA), fixture_hop(2, 0xBB)];
        let result = pick_circuit_hops_random(&pool, 3, fixed_prng(vec![0]));
        assert_eq!(
            result, None,
            "must return None when distinct pool has fewer than n candidates"
        );
    }

    #[test]
    fn epic482_6_random_returns_n_distinct_hops() {
        let pool = (1..=10).map(|i| fixture_hop(i, i)).collect::<Vec<_>>();
        let result =
            pick_circuit_hops_random(&pool, 3, fixed_prng(vec![1, 3, 5])).expect("3 hops from 10");
        assert_eq!(result.len(), 3);
        let unique_ids: HashSet<_> = result.iter().map(|h| h.node_id).collect();
        assert_eq!(unique_ids.len(), 3, "all picked hops must be distinct");
    }

    #[test]
    fn epic482_6_random_dedups_input_pool_by_node_id() {
        // Input has 3 candidates but only 2 distinct node_ids. With
        // n = 3, the result must be None (insufficient distinct).
        let pool = vec![
            fixture_hop(1, 0xAA),
            fixture_hop(2, 0xBB),
            fixture_hop(1, 0xCC), // duplicate node_id 1, different x25519_pk
        ];
        let result = pick_circuit_hops_random(&pool, 3, fixed_prng(vec![0]));
        assert_eq!(
            result, None,
            "duplicate node_ids must collapse — 3 candidates with 2 distinct ids \
             cannot fill a 3-hop circuit"
        );
    }

    #[test]
    fn epic482_6_random_n_equals_pool_returns_all_distinct() {
        let pool = vec![
            fixture_hop(1, 0xAA),
            fixture_hop(2, 0xBB),
            fixture_hop(3, 0xCC),
        ];
        let result = pick_circuit_hops_random(&pool, 3, fixed_prng(vec![0, 0, 0]))
            .expect("n == distinct pool size must succeed");
        assert_eq!(result.len(), 3);
        let unique_ids: HashSet<_> = result.iter().map(|h| h.node_id).collect();
        assert_eq!(unique_ids.len(), 3);
    }

    #[test]
    fn epic482_6_random_n_zero_returns_empty_vec() {
        // Edge case: caller asks for 0 hops. Returns Some(vec![])
        // (not None) — the request is satisfiable; it's just trivial.
        let pool = vec![fixture_hop(1, 0xAA)];
        let result =
            pick_circuit_hops_random(&pool, 0, fixed_prng(vec![0])).expect("0 hops is satisfiable");
        assert!(result.is_empty());
    }

    // ── pick_circuit_hops_latency_aware ───────────────────────────────

    #[test]
    fn epic482_6_latency_returns_none_when_pool_smaller_than_n() {
        let pool = vec![fixture_hop(1, 0xAA), fixture_hop(2, 0xBB)];
        let result = pick_circuit_hops_latency_aware(&pool, 3, |_| Some(50));
        assert_eq!(result, None);
    }

    #[test]
    fn epic482_6_latency_picks_lowest_rtt_first() {
        // 4 candidates; pick top 2 by RTT.
        let pool = vec![
            fixture_hop(1, 0xAA), // rtt 100
            fixture_hop(2, 0xBB), // rtt 20 ← second-fastest
            fixture_hop(3, 0xCC), // rtt 200
            fixture_hop(4, 0xDD), // rtt 5 ← fastest
        ];
        let rtts: std::collections::HashMap<u8, u32> = [(1, 100), (2, 20), (3, 200), (4, 5)]
            .iter()
            .copied()
            .collect();
        let result = pick_circuit_hops_latency_aware(&pool, 2, |id| rtts.get(&id[0]).copied())
            .expect("2 picks from 4");
        assert_eq!(result[0].node_id[0], 4, "fastest must come first");
        assert_eq!(result[1].node_id[0], 2, "second-fastest must come second");
    }

    #[test]
    fn epic482_6_latency_unknown_rtt_sorts_last() {
        // Candidate with no RTT data must be picked LAST, never
        // ahead of a candidate with known low RTT. Without this
        // property, a freshly-discovered relay with no probe data
        // would be picked before a known-good fast one.
        let pool = vec![
            fixture_hop(1, 0xAA), // unknown
            fixture_hop(2, 0xBB), // rtt 10
        ];
        let result =
            pick_circuit_hops_latency_aware(
                &pool,
                2,
                |id| {
                    if id[0] == 2 { Some(10) } else { None }
                },
            )
            .expect("2 picks");
        assert_eq!(
            result[0].node_id[0], 2,
            "known-RTT must come before unknown"
        );
        assert_eq!(result[1].node_id[0], 1, "unknown-RTT must come last");
    }

    #[test]
    fn epic482_6_latency_dedups_input_pool() {
        let pool = vec![
            fixture_hop(1, 0xAA),
            fixture_hop(2, 0xBB),
            fixture_hop(1, 0xCC), // dup node_id 1
        ];
        let result = pick_circuit_hops_latency_aware(&pool, 3, |_| Some(0));
        assert_eq!(
            result, None,
            "duplicate node_ids collapse — n=3 needs 3 distinct, only 2 available"
        );
    }

    #[test]
    fn epic482_6_latency_stable_order_on_rtt_ties() {
        // When multiple candidates have the same RTT, stable sort
        // preserves input order. Without this, two consecutive picks
        // with the same RTT input could yield different orderings
        // across runs — bad for reproducibility.
        let pool = vec![
            fixture_hop(1, 0xAA),
            fixture_hop(2, 0xBB),
            fixture_hop(3, 0xCC),
        ];
        let result = pick_circuit_hops_latency_aware(&pool, 3, |_| Some(50)).expect("3 from 3");
        assert_eq!(result[0].node_id[0], 1);
        assert_eq!(result[1].node_id[0], 2);
        assert_eq!(result[2].node_id[0], 3);
    }

    #[test]
    fn epic482_6_latency_all_unknown_rtt_returns_in_pool_order() {
        // No RTT data at all → every candidate scores u64::MAX →
        // stable sort returns them in pool order. Equivalent to
        // pick_circuit_hops_random with a "first-N" selector, useful
        // as a fallback when Vivaldi hasn't converged yet.
        let pool = vec![
            fixture_hop(7, 0xAA),
            fixture_hop(3, 0xBB),
            fixture_hop(5, 0xCC),
        ];
        let result = pick_circuit_hops_latency_aware(&pool, 3, |_| None)
            .expect("3 from 3 even when no RTT data");
        assert_eq!(result[0].node_id[0], 7);
        assert_eq!(result[1].node_id[0], 3);
        assert_eq!(result[2].node_id[0], 5);
    }

    /// End-to-end composition: discovery output → latency-aware
    /// selection → packet build. Verifies the wire-types compose;
    /// if any of the three modules' types drift this trips before
    /// touching the dispatcher.
    #[test]
    fn epic482_6_compose_with_packet_build() {
        use super::super::packet::{CellPeelResult, build_anonymous_cell, peel_anonymous_cell};
        use rand_core::OsRng;

        // Generate 4 fresh "relays" with real keys.
        let mut sks = Vec::new();
        let mut candidates = Vec::new();
        for i in 0..4u8 {
            let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let pk = x25519_dalek::PublicKey::from(&sk).to_bytes();
            let mut node_id = [0u8; 32];
            node_id[0] = i + 1;
            sks.push((node_id, sk));
            candidates.push(DiscoveredRelay {
                hop: Hop {
                    node_id,
                    pubkey: pk,
                },
                advertised_bps: 0,
                last_published_unix: 0,
            });
        }

        // Pick 2 hops by latency (use index as RTT — first is fastest).
        let hops = pick_circuit_hops_latency_aware(&candidates, 2, |id| Some(id[0] as u32))
            .expect("2 picks");
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].node_id[0], 1, "id-1 has lowest RTT");
        assert_eq!(hops[1].node_id[0], 2);

        // Build → peel through both hops → recover payload.
        let payload = b"composed end-to-end";
        let cell = build_anonymous_cell(payload, &hops).expect("build");

        // Hop 1 forwards.
        let sk1 = &sks.iter().find(|(id, _)| id[0] == 1).unwrap().1;
        let to_hop2 = match peel_anonymous_cell(&cell, sk1).unwrap() {
            CellPeelResult::Forward { outbound_cell, .. } => outbound_cell,
            other => panic!("hop1 must Forward, got {other:?}"),
        };

        // Hop 2 is final.
        let sk2 = &sks.iter().find(|(id, _)| id[0] == 2).unwrap().1;
        match peel_anonymous_cell(&to_hop2, sk2).unwrap() {
            CellPeelResult::Final { payload: p } => assert_eq!(p.as_slice(), payload),
            other => panic!("hop2 must Final, got {other:?}"),
        }
    }

    // ── AS/geographic diversity ───────────────────────

    /// 5 candidates with 3 distinct AS-keys; n=3 should pick one per AS
    /// preferring lowest-RTT within each.
    #[test]
    fn diversity_picks_lowest_rtt_per_as() {
        let candidates = vec![
            fixture_hop(1, 0x01), // AS-A, RTT 100
            fixture_hop(2, 0x02), // AS-A, RTT 50 (better in A)
            fixture_hop(3, 0x03), // AS-B, RTT 80
            fixture_hop(4, 0x04), // AS-B, RTT 30 (better in B)
            fixture_hop(5, 0x05), // AS-C, RTT 10
        ];
        let rtt = |node_id: &[u8; 32]| -> Option<u32> {
            match node_id[0] {
                1 => Some(100),
                2 => Some(50),
                3 => Some(80),
                4 => Some(30),
                5 => Some(10),
                _ => None,
            }
        };
        let as_key = |node_id: &[u8; 32]| -> Option<String> {
            match node_id[0] {
                1 | 2 => Some("AS-A".to_string()),
                3 | 4 => Some("AS-B".to_string()),
                5 => Some("AS-C".to_string()),
                _ => None,
            }
        };
        let picked = pick_circuit_hops_latency_aware_with_diversity(&candidates, 3, rtt, as_key)
            .expect("3 distinct AS available, must succeed");
        // Expected: AS-C (RTT 10), AS-B (best is node4, RTT 30), AS-A (best is node2, RTT 50).
        assert_eq!(picked.len(), 3);
        assert_eq!(picked[0].node_id[0], 5, "AS-C lowest-RTT picked first");
        assert_eq!(
            picked[1].node_id[0], 4,
            "AS-B best (node4 RTT 30) picked second"
        );
        assert_eq!(
            picked[2].node_id[0], 2,
            "AS-A best (node2 RTT 50) picked third"
        );
    }

    /// Fewer distinct ASes than `n` requested → None. Verifies that
    /// the picker doesn't silently downgrade to a less-diverse circuit.
    #[test]
    fn diversity_returns_none_when_too_few_distinct_as() {
        let candidates = vec![
            fixture_hop(1, 0x01),
            fixture_hop(2, 0x02),
            fixture_hop(3, 0x03),
        ];
        let rtt = |_: &[u8; 32]| -> Option<u32> { Some(50) };
        // All 3 candidates in same AS — 0 distinct.
        let as_key = |_: &[u8; 32]| -> Option<String> { Some("AS-X".to_string()) };
        assert!(
            pick_circuit_hops_latency_aware_with_diversity(&candidates, 3, rtt, as_key).is_none(),
            "3 candidates in 1 AS cannot satisfy n=3 diversity",
        );
    }

    /// Candidates with `None` AS-key (unkeyed transport) accepted
    /// without diversity constraint applied.
    #[test]
    fn diversity_accepts_unkeyed_candidates() {
        let candidates = vec![
            fixture_hop(1, 0x01),
            fixture_hop(2, 0x02),
            fixture_hop(3, 0x03),
        ];
        let rtt = |_: &[u8; 32]| -> Option<u32> { Some(50) };
        let as_key = |_: &[u8; 32]| -> Option<String> { None };
        let picked = pick_circuit_hops_latency_aware_with_diversity(&candidates, 3, rtt, as_key)
            .expect("unkeyed candidates accepted as anonymity baseline");
        assert_eq!(picked.len(), 3);
    }

    /// Mixed keyed + unkeyed: keyed-but-conflicting are skipped
    /// unkeyed and keyed-distinct are kept. Demonstrates that
    /// an evil AS doesn't get to fill a circuit slot just because
    /// it has the lowest RTT.
    #[test]
    fn diversity_skips_redundant_keyed_keeps_unkeyed() {
        let candidates = vec![
            fixture_hop(1, 0x01), // AS-A, RTT 10
            fixture_hop(2, 0x02), // AS-A, RTT 20 → must skip (AS-A taken)
            fixture_hop(3, 0x03), // unkeyed, RTT 30
            fixture_hop(4, 0x04), // AS-B, RTT 40
        ];
        let rtt = |node_id: &[u8; 32]| -> Option<u32> {
            match node_id[0] {
                1 => Some(10),
                2 => Some(20),
                3 => Some(30),
                4 => Some(40),
                _ => None,
            }
        };
        let as_key = |node_id: &[u8; 32]| -> Option<String> {
            match node_id[0] {
                1 | 2 => Some("AS-A".to_string()),
                4 => Some("AS-B".to_string()),
                _ => None,
            }
        };
        let picked = pick_circuit_hops_latency_aware_with_diversity(&candidates, 3, rtt, as_key)
            .expect("3 distinct slots: AS-A, unkeyed, AS-B");
        assert_eq!(picked.len(), 3);
        assert_eq!(picked[0].node_id[0], 1, "AS-A best (node1) picked first");
        assert_eq!(
            picked[1].node_id[0], 3,
            "unkeyed (node3) picked second; node2 skipped (AS-A dup)"
        );
        assert_eq!(picked[2].node_id[0], 4, "AS-B (node4) picked third");
    }

    // ── pick_circuit_hops_latency_aware_with_diversity_and_reputation ─────
    //
    // Epic 482.3/482.4 Phase A: reputation-driven downweighting layered on
    // top of latency + diversity selection.

    #[test]
    fn epic482_reputation_penalty_demotes_fast_misbehaver() {
        // Sender has 3 candidates: fast misbehaver (RTT=10ms) and two
        // slower-but-honest (RTT=200, 300ms). Without penalty the fast one
        // wins. After 1 recorded failure (+500ms penalty → effective 510ms)
        // the misbehaver sorts behind both honest relays.
        let candidates = vec![
            fixture_hop(1, 0xAA), // fast misbehaver
            fixture_hop(2, 0xBB), // honest mid
            fixture_hop(3, 0xCC), // honest slow
        ];
        let rtt = |id: &[u8; 32]| -> Option<u32> {
            match id[0] {
                1 => Some(10),
                2 => Some(200),
                3 => Some(300),
                _ => None,
            }
        };
        let no_diversity = |_id: &[u8; 32]| None;

        // Without penalty: fast misbehaver wins.
        let no_penalty = |_id: &[u8; 32]| 0u32;
        let picked = pick_circuit_hops_latency_aware_with_diversity_and_reputation(
            &candidates,
            2,
            rtt,
            no_diversity,
            no_penalty,
        )
        .unwrap();
        assert_eq!(
            picked[0].node_id[0], 1,
            "fast misbehaver wins without penalty"
        );

        // After 1 failure (+500ms): effective scores
        // misbehaver = 10 + 500 = 510, honest_mid = 200, honest_slow = 300
        // → honest_mid wins, honest_slow second.
        let penalty_after_one_failure = |id: &[u8; 32]| if id[0] == 1 { 500u32 } else { 0 };
        let picked = pick_circuit_hops_latency_aware_with_diversity_and_reputation(
            &candidates,
            2,
            rtt,
            no_diversity,
            penalty_after_one_failure,
        )
        .unwrap();
        assert_eq!(
            picked[0].node_id[0], 2,
            "honest_mid promoted past penalized misbehaver"
        );
        assert_eq!(picked[1].node_id[0], 3);
    }

    #[test]
    fn epic482_reputation_penalty_does_not_promote_unknown_rtt() {
        // Sender has: known-RTT misbehaver (10ms + heavy penalty)
        // and unknown-RTT relay (no penalty). The unknown-RTT relay should
        // sort to the end of the list regardless — a penalty can't promote
        // candidates whose RTT is unknown.
        let candidates = vec![
            fixture_hop(1, 0xAA), // known misbehaver
            fixture_hop(2, 0xBB), // unknown-RTT honest
            fixture_hop(3, 0xCC), // known honest
        ];
        let rtt = |id: &[u8; 32]| -> Option<u32> {
            match id[0] {
                1 => Some(10),
                3 => Some(200),
                _ => None,
            }
        };
        let no_diversity = |_id: &[u8; 32]| None;
        let heavy_penalty_on_1 = |id: &[u8; 32]| if id[0] == 1 { 10_000u32 } else { 0 };

        let picked = pick_circuit_hops_latency_aware_with_diversity_and_reputation(
            &candidates,
            2,
            rtt,
            no_diversity,
            heavy_penalty_on_1,
        )
        .unwrap();
        // node3 wins (RTT=200, no penalty), node1 is second
        // (RTT=10 + 10000 = 10010 < u64::MAX), node2 (unknown-RTT) NOT picked.
        assert_eq!(picked[0].node_id[0], 3);
        assert_eq!(
            picked[1].node_id[0], 1,
            "penalized misbehaver still beats unknown-RTT"
        );
    }

    #[test]
    fn epic482_reputation_composes_with_diversity() {
        // Diversity + reputation: misbehaver is in AS-A; non-misbehaver is also
        // in AS-A. After penalty, non-misbehaver from AS-A wins that slot
        // and another AS gets the second slot.
        let candidates = vec![
            fixture_hop(1, 0xAA), // AS-A, misbehaver (RTT=10)
            fixture_hop(2, 0xBB), // AS-A, honest (RTT=100)
            fixture_hop(3, 0xCC), // AS-B, honest (RTT=200)
        ];
        let rtt = |id: &[u8; 32]| -> Option<u32> {
            match id[0] {
                1 => Some(10),
                2 => Some(100),
                3 => Some(200),
                _ => None,
            }
        };
        let as_key = |id: &[u8; 32]| -> Option<String> {
            Some(match id[0] {
                1 | 2 => "AS-A".to_string(),
                3 => "AS-B".to_string(),
                _ => return None,
            })
        };
        let penalty_on_1 = |id: &[u8; 32]| if id[0] == 1 { 500u32 } else { 0 };

        let picked = pick_circuit_hops_latency_aware_with_diversity_and_reputation(
            &candidates,
            2,
            rtt,
            as_key,
            penalty_on_1,
        )
        .unwrap();
        // Sort: node1=510, node2=100, node3=200. node2 wins; node1 same-AS skipped;
        // node3 second slot (AS-B).
        assert_eq!(picked[0].node_id[0], 2, "honest AS-A peer wins AS-A slot");
        assert_eq!(picked[1].node_id[0], 3, "AS-B fills second slot");
    }

    #[test]
    fn epic482_reputation_returns_none_when_pool_too_small() {
        let candidates = vec![fixture_hop(1, 0xAA), fixture_hop(2, 0xBB)];
        let rtt = |_id: &[u8; 32]| Some(50u32);
        let no_diversity = |_id: &[u8; 32]| None;
        let no_penalty = |_id: &[u8; 32]| 0u32;
        let picked = pick_circuit_hops_latency_aware_with_diversity_and_reputation(
            &candidates,
            3,
            rtt,
            no_diversity,
            no_penalty,
        );
        assert_eq!(picked, None);
    }

    #[test]
    fn epic482_reputation_wired_through_relay_reputation_struct() {
        // End-to-end: build a real RelayReputation, record failures,
        // confirm the selector picks up the penalty via the
        // `rtt_penalty_ms` adapter closure.
        use crate::relay_reputation::RelayReputation;
        use std::sync::Arc;

        let rep = Arc::new(RelayReputation::new());
        let candidates = vec![
            fixture_hop(1, 0xAA), // fast misbehaver
            fixture_hop(2, 0xBB), // honest mid
        ];
        let rtt = |id: &[u8; 32]| -> Option<u32> {
            match id[0] {
                1 => Some(10),
                2 => Some(200),
                _ => None,
            }
        };
        let no_diversity = |_id: &[u8; 32]| None;
        let rep_for_closure = Arc::clone(&rep);
        let penalty = move |id: &[u8; 32]| rep_for_closure.rtt_penalty_ms(*id);

        // Initial: node1 wins (10ms < 200ms).
        let picked = pick_circuit_hops_latency_aware_with_diversity_and_reputation(
            &candidates,
            1,
            rtt,
            no_diversity,
            &penalty,
        )
        .unwrap();
        assert_eq!(picked[0].node_id[0], 1, "initial: misbehaver wins by RTT");

        // Record 1 failure → +500ms penalty → effective 510 > 200 → node2.
        let mut id1 = [0u8; 32];
        id1[0] = 1;
        rep.record_failure(id1);

        let picked = pick_circuit_hops_latency_aware_with_diversity_and_reputation(
            &candidates,
            1,
            rtt,
            no_diversity,
            &penalty,
        )
        .unwrap();
        assert_eq!(picked[0].node_id[0], 2, "after 1 failure: honest mid wins");
    }

    // ── first-hop liveness guard (2a first-attempt-loss fix) ─────────

    /// RTT map: node_id[0] → rtt. Missing → None (unknown).
    fn rtt_by_first_byte(map: Vec<(u8, u32)>) -> impl Fn(&[u8; 32]) -> Option<u32> {
        move |id: &[u8; 32]| map.iter().find(|(b, _)| *b == id[0]).map(|(_, r)| *r)
    }

    fn live_set(bytes: Vec<u8>) -> impl Fn(&[u8; 32]) -> bool {
        move |id: &[u8; 32]| bytes.contains(&id[0])
    }

    #[test]
    fn guard_prefers_live_first_hop_over_faster_dead_one() {
        // node1 fastest but dead; node3 live. Guard slot must be node3,
        // and the faster dead node1 is still eligible for the middle slot.
        let pool = vec![
            fixture_hop(1, 0xAA),
            fixture_hop(2, 0xBB),
            fixture_hop(3, 0xCC),
        ];
        let rtt = rtt_by_first_byte(vec![(1, 10), (2, 20), (3, 300)]);
        let picked = pick_circuit_hops_latency_aware_with_diversity_and_reputation_guarded(
            &pool,
            2,
            &rtt,
            |_| None,
            |_| 0,
            live_set(vec![3]),
        )
        .expect("2 hops from 3");
        assert_eq!(picked[0].node_id[0], 3, "guard slot must be the live node");
        assert_eq!(
            picked[1].node_id[0], 1,
            "middle slot stays best-RTT, liveness-blind"
        );
    }

    #[test]
    fn guard_picks_best_scored_among_live() {
        let pool = (1..=4).map(|i| fixture_hop(i, i)).collect::<Vec<_>>();
        let rtt = rtt_by_first_byte(vec![(1, 5), (2, 50), (3, 30), (4, 40)]);
        let picked = pick_circuit_hops_latency_aware_with_diversity_and_reputation_guarded(
            &pool,
            1,
            &rtt,
            |_| None,
            |_| 0,
            live_set(vec![2, 3]),
        )
        .expect("1 hop");
        assert_eq!(
            picked[0].node_id[0], 3,
            "among live {{2,3}} the lower-RTT node3 must win the guard slot"
        );
    }

    #[test]
    fn guard_falls_back_to_ungated_pick_when_no_live_candidate() {
        let pool = vec![fixture_hop(1, 0xAA), fixture_hop(2, 0xBB)];
        let rtt = rtt_by_first_byte(vec![(1, 10), (2, 20)]);
        let picked = pick_circuit_hops_latency_aware_with_diversity_and_reputation_guarded(
            &pool,
            2,
            &rtt,
            |_| None,
            |_| 0,
            |_| false, // nothing live
        )
        .expect("fallback must still build");
        assert_eq!(
            picked[0].node_id[0], 1,
            "no live candidate → previous behavior (best RTT first)"
        );
        assert_eq!(picked[1].node_id[0], 2);
    }

    #[test]
    fn guard_seeds_diversity_with_guard_key() {
        // Guard node3 shares a /16 with node1 — the middle slot must skip
        // node1 (same diversity key as the already-picked guard) and take
        // node2 despite node1's better RTT.
        let pool = vec![
            fixture_hop(1, 0xAA),
            fixture_hop(2, 0xBB),
            fixture_hop(3, 0xCC),
        ];
        let rtt = rtt_by_first_byte(vec![(1, 10), (2, 20), (3, 30)]);
        let diversity = |id: &[u8; 32]| -> Option<String> {
            match id[0] {
                1 | 3 => Some("v4:10.0".to_string()),
                2 => Some("v4:20.0".to_string()),
                _ => None,
            }
        };
        let picked = pick_circuit_hops_latency_aware_with_diversity_and_reputation_guarded(
            &pool,
            2,
            &rtt,
            &diversity,
            |_| 0,
            live_set(vec![3]),
        )
        .expect("2 hops");
        assert_eq!(picked[0].node_id[0], 3, "guard = live node3");
        assert_eq!(
            picked[1].node_id[0], 2,
            "node1 shares the guard's /16 and must be skipped"
        );
    }

    #[test]
    fn guard_gated_variant_matches_legacy_when_all_live() {
        let pool = (1..=5).map(|i| fixture_hop(i, i)).collect::<Vec<_>>();
        let rtt = rtt_by_first_byte(vec![(1, 10), (2, 20), (3, 30), (4, 40), (5, 50)]);
        let legacy = pick_circuit_hops_latency_aware_with_diversity_and_reputation(
            &pool,
            3,
            &rtt,
            |_| None,
            |_| 0,
        )
        .unwrap();
        let guarded = pick_circuit_hops_latency_aware_with_diversity_and_reputation_guarded(
            &pool,
            3,
            &rtt,
            |_| None,
            |_| 0,
            |_| true,
        )
        .unwrap();
        assert_eq!(
            legacy.iter().map(|h| h.node_id).collect::<Vec<_>>(),
            guarded.iter().map(|h| h.node_id).collect::<Vec<_>>(),
            "|_| true guard must reproduce the ungated pick exactly"
        );
    }

    #[test]
    fn guard_latency_only_variant_prefers_live_first_hop() {
        let pool = vec![
            fixture_hop(1, 0xAA),
            fixture_hop(2, 0xBB),
            fixture_hop(3, 0xCC),
        ];
        let rtt = rtt_by_first_byte(vec![(1, 10), (2, 20), (3, 300)]);
        let picked = pick_circuit_hops_latency_aware_guarded(&pool, 2, &rtt, live_set(vec![3]))
            .expect("2 hops");
        assert_eq!(picked[0].node_id[0], 3, "guard slot = live node");
        assert_eq!(picked[1].node_id[0], 1, "rest = best remaining RTT");
    }

    #[test]
    fn guard_latency_only_falls_back_when_no_live() {
        let pool = vec![fixture_hop(1, 0xAA), fixture_hop(2, 0xBB)];
        let rtt = rtt_by_first_byte(vec![(1, 10), (2, 20)]);
        let picked = pick_circuit_hops_latency_aware_guarded(&pool, 2, &rtt, |_| false)
            .expect("fallback builds");
        assert_eq!(picked[0].node_id[0], 1);
        assert_eq!(picked[1].node_id[0], 2);
    }
}
