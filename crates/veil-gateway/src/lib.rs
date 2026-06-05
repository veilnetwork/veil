//! Gateway crate — multi-gateway scoring/failover + per-leaf attach lifecycle.
//!
//! Two distinct service surfaces live here:
//!
//! * [`GatewayList`] — node-side aggregator що picks the best upstream
//!   gateway peer (this file).
//! * [`service::GatewayService`] — Core-node-side service що handles
//!   incoming `ATTACH` / `DETACH` / `KEEPALIVE` от leaves (Phase 3 prep,
//!   moved от `veilcore::node::gateway`).
//!
//! Modules:

pub mod attachment;
pub mod endpoint;
pub mod lease;
pub mod service;

pub use service::{GatewayError, GatewayService};

// ── GatewayList — multi-gateway scoring and failover ────────────────────────
//
// [`GatewayList`] aggregates Gateway peers from two sources:
// * Static configured peers (`config.peers`)
// * Dynamically discovered gateways via mesh beacons
//
// It scores each gateway and provides:
// * [`GatewayList::preferred`] — best gateway considering active sessions and
//   the `prefer_internet` flag (141.2)
// * [`GatewayList::select_relay_peer`] — integrates with NAT relay (141.4)
// * Hysteresis logic — avoids oscillation when a primary gateway recovers
//   (141.7)

use std::time::{Duration, Instant};

// ── constants ────────────────────────────────────────────────────────────────

/// Hysteresis: a recovered gateway must be stable for this long before the
/// node switches back to it.
pub const HYSTERESIS_STABLE_SECS: u64 = 30;

/// Hysteresis: a candidate gateway's effective score must exceed the current
/// gateway's by this fraction before triggering a switch-back.
pub const HYSTERESIS_SCORE_MARGIN: f64 = 0.20;

/// Base score for a configured (static) gateway peer (141.1).
pub const BASE_SCORE_CONFIGURED: f64 = 100.0;

/// Base score for an autodiscovered gateway peer (141.1).
pub const BASE_SCORE_AUTODISCOVERED: f64 = 50.0;

// ── GatewayEntry ─────────────────────────────────────────────────────────────

/// One entry in the gateway list.
#[derive(Debug, Clone)]
pub struct GatewayEntry {
    /// Veil node_id of this gateway.
    pub node_id: [u8; 32],
    /// Dial address (e.g. `"tcp://10.0.0.1:9000"`).
    pub veil_addr: String,
    /// Base score (higher = better). Updated when fresh RTT data arrives.
    pub score: f64,
    /// Whether this gateway advertises internet connectivity (`HAS_INTERNET`).
    pub has_internet: bool,
    /// Timestamp of last beacon or successful session activity.
    pub last_seen: Instant,
    /// When the gateway's session became (re-)established.
    /// `None` means the gateway currently has no active session.
    pub stable_since: Option<Instant>,
}

impl GatewayEntry {
    /// Effective score used for sorting and preference decisions.
    ///
    /// When `prefer_internet` is `true`, gateways with `HAS_INTERNET` get a
    /// 2× multiplier so they rank above same-score non-internet gateways
    ///`).
    pub fn effective_score(&self, prefer_internet: bool) -> f64 {
        self.score
            * (1.0
                + if prefer_internet && self.has_internet {
                    1.0
                } else {
                    0.0
                })
    }
}

/// Serialisable snapshot of one gateway entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GatewaySnapshot {
    #[serde(with = "veil_proto::serde_base64::hex_array")]
    pub node_id: [u8; 32],
    pub veil_addr: String,
    pub score: f64,
    pub has_internet: bool,
}

// ── GatewayList ───────────────────────────────────────────────────────────────

/// Sorted list of known gateways with scoring and failover logic.
#[derive(Debug, Default)]
pub struct GatewayList {
    entries: Vec<GatewayEntry>,
    prefer_internet: bool,
}

impl GatewayList {
    pub fn new(prefer_internet: bool) -> Self {
        Self {
            entries: Vec::new(),
            prefer_internet,
        }
    }

    // ── population ────────────────────────────────────────────────────────

    /// Insert or update a gateway entry.
    ///
    /// If the node_id is already present, the score, `has_internet`, and
    /// `last_seen` are refreshed without resetting `stable_since`.
    pub fn upsert(&mut self, node_id: [u8; 32], veil_addr: String, score: f64, has_internet: bool) {
        let now = Instant::now();
        if let Some(e) = self.entries.iter_mut().find(|e| e.node_id == node_id) {
            e.veil_addr = veil_addr;
            e.score = score;
            e.has_internet = has_internet;
            e.last_seen = now;
        } else {
            self.entries.push(GatewayEntry {
                node_id,
                veil_addr,
                score,
                has_internet,
                last_seen: now,
                stable_since: None,
            });
        }
        self.sort();
    }

    /// Mark `node_id`'s session as active (sets `stable_since` if not already
    /// set). Called when a session to this gateway is successfully established.
    pub fn mark_connected(&mut self, node_id: &[u8; 32]) {
        let now = Instant::now();
        if let Some(e) = self.entries.iter_mut().find(|e| &e.node_id == node_id)
            && e.stable_since.is_none()
        {
            e.stable_since = Some(now);
        }
    }

    /// Mark `node_id`'s session as inactive. Called on session close.
    pub fn mark_disconnected(&mut self, node_id: &[u8; 32]) {
        if let Some(e) = self.entries.iter_mut().find(|e| &e.node_id == node_id) {
            e.stable_since = None;
        }
    }

    /// Update score for a gateway (e.g. from fresh RTT data) and re-sort.
    pub fn update_score(&mut self, node_id: &[u8; 32], score: f64) {
        if let Some(e) = self.entries.iter_mut().find(|e| &e.node_id == node_id) {
            e.score = score;
        }
        self.sort();
    }

    // ── lookup ────────────────────────────────────────────────────────────

    /// Return all entries sorted by effective score descending.
    pub fn entries(&self) -> &[GatewayEntry] {
        &self.entries
    }

    /// Return the best active gateway.
    ///
    /// `active_sessions` is the set of `node_id`s with a currently-open session.
    /// Only gateways present in `active_sessions` are considered.
    ///
    /// When `prefer_internet` is set, the formula `score × (1 + has_internet)`
    /// is used so HAS_INTERNET gateways rank ahead of non-internet ones at the
    /// same raw score.
    pub fn preferred<'a>(
        &'a self,
        active_sessions: &std::collections::HashSet<[u8; 32]>,
    ) -> Option<&'a GatewayEntry> {
        self.entries
            .iter()
            .filter(|e| active_sessions.contains(&e.node_id))
            .max_by(|a, b| {
                a.effective_score(self.prefer_internet)
                    .partial_cmp(&b.effective_score(self.prefer_internet))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// pick a gateway from the top-`k` candidates with probability
    /// proportional to its effective score. Use this instead [`preferred`]
    /// when you want to **diversify** outbound paths — a single fat connection
    /// to one gateway IP is statistically distinctive (one of the patterns
    /// VPN-blocking systems target), whereas spreading across N similarly-good
    /// gateways looks like ordinary traffic.
    ///
    /// `rand_u64` is any caller-provided source of randomness (e.g. derived
    /// from `local_node_id` xor a frame counter); accepting it as a parameter
    /// keeps `GatewayList` itself stateless and easy to test. Returns `None`
    /// when no active gateway is available.
    pub fn pick_weighted<'a>(
        &'a self,
        active_sessions: &std::collections::HashSet<[u8; 32]>,
        top_k: usize,
        rand_u64: u64,
    ) -> Option<&'a GatewayEntry> {
        let candidates: Vec<&GatewayEntry> = self
            .entries
            .iter()
            .filter(|e| active_sessions.contains(&e.node_id))
            .take(top_k.max(1))
            .collect();
        if candidates.is_empty() {
            return None;
        }
        if candidates.len() == 1 {
            return Some(candidates[0]);
        }
        // Weighted sample: positive scores only (treat ≤0 as floor 1.0 so a
        // gateway with no score data isn't completely starved).
        let weights: Vec<f64> = candidates
            .iter()
            .map(|e| {
                let s = e.effective_score(self.prefer_internet);
                if s > 0.0 { s } else { 1.0 }
            })
            .collect();
        let total: f64 = weights.iter().sum();
        if !total.is_finite() || total <= 0.0 {
            return Some(candidates[0]);
        }
        // Map rand_u64 → [0, total) by scaling the high 32 bits to avoid
        // floating-point bias from full-width modulus.
        let r = ((rand_u64 >> 32) as f64) / (u32::MAX as f64 + 1.0) * total;
        let mut acc = 0.0f64;
        for (entry, w) in candidates.iter().zip(weights.iter()) {
            acc += w;
            if r < acc {
                return Some(*entry);
            }
        }
        // Fall-through (should be unreachable due to floating-point summation
        // tolerance — return the last candidate as the safe default).
        candidates.last().copied()
    }

    /// Like [`preferred`] but only considers gateways with `has_internet = true`.
    ///
    /// Used in delivery.rs to route frames destined for global-veil nodes
    /// through a gateway that has internet access.
    pub fn preferred_internet_gateway<'a>(
        &'a self,
        active_sessions: &std::collections::HashSet<[u8; 32]>,
    ) -> Option<&'a GatewayEntry> {
        self.entries
            .iter()
            .filter(|e| e.has_internet && active_sessions.contains(&e.node_id))
            .max_by(|a, b| {
                a.score
                    .partial_cmp(&b.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Return the 0-based rank of `node_id` in the list sorted by effective
    /// score descending. Used for staggered-reconnect delay.
    ///
    /// Returns `self.entries.len` when the node_id is not in the list.
    pub fn rank_of(&self, node_id: &[u8; 32]) -> usize {
        self.entries
            .iter()
            .position(|e| &e.node_id == node_id)
            .unwrap_or(self.entries.len())
    }

    // ── hysteresis ────────────────────────────────────────────────────────

    /// Return `true` when switching from `current` to `candidate` is warranted.
    ///
    /// Conditions:
    /// 1. `candidate` has been stably connected for ≥ `HYSTERESIS_STABLE_SECS`.
    /// 2. `candidate`'s effective score exceeds `current`'s by ≥
    ///    `HYSTERESIS_SCORE_MARGIN` (20 %).
    pub fn should_switch(&self, current: &[u8; 32], candidate: &[u8; 32]) -> bool {
        if current == candidate {
            return false;
        }
        let Some(cand) = self.entries.iter().find(|e| &e.node_id == candidate) else {
            return false;
        };
        let Some(curr) = self.entries.iter().find(|e| &e.node_id == current) else {
            return true; // current gateway unknown — always switch
        };
        // Stability check.
        let stable = cand
            .stable_since
            .is_some_and(|t| t.elapsed() >= Duration::from_secs(HYSTERESIS_STABLE_SECS));
        if !stable {
            return false;
        }
        // Score margin check.
        let cand_eff = cand.effective_score(self.prefer_internet);
        let curr_eff = curr.effective_score(self.prefer_internet);
        cand_eff > curr_eff * (1.0 + HYSTERESIS_SCORE_MARGIN)
    }

    // ── persistence ────────────────────────────────────────────

    /// Return all entries as a snapshot for persistence.
    pub fn snapshot(&self) -> Vec<GatewaySnapshot> {
        self.entries
            .iter()
            .map(|e| GatewaySnapshot {
                node_id: e.node_id,
                veil_addr: e.veil_addr.clone(),
                score: e.score,
                has_internet: e.has_internet,
            })
            .collect()
    }

    /// Restore entries from a persisted snapshot.
    ///
    /// Restored entries are inserted with a reduced initial score
    /// (`score × 0.5`) so freshly-observed gateways quickly overtake them.
    /// `stable_since` is left as `None` — restored entries are not yet
    /// considered active sessions.
    pub fn restore(&mut self, entries: Vec<GatewaySnapshot>) {
        for e in entries {
            // Only insert if not already known (config-based entries take precedence).
            if self.entries.iter().any(|x| x.node_id == e.node_id) {
                continue;
            }
            self.entries.push(GatewayEntry {
                node_id: e.node_id,
                veil_addr: e.veil_addr,
                score: e.score * 0.5, // restored entries start at half score
                has_internet: e.has_internet,
                last_seen: Instant::now(),
                stable_since: None,
            });
        }
        self.sort();
    }

    // ── internals ─────────────────────────────────────────────────────────

    fn sort(&mut self) {
        let prefer = self.prefer_internet;
        self.entries.sort_by(|a, b| {
            let sa = b.effective_score(prefer);
            let sb = a.effective_score(prefer);
            sa.partial_cmp(&sb).unwrap_or_else(|| {
                // NaN scores: treat NaN as worst (sort to END). Audit cycle-5:
                // `sa`/`sb` are the SWAPPED scores (sa=b, sb=a) for descending
                // order, so a's NaN-ness is `sb.is_nan()` and b's is
                // `sa.is_nan()`. Comparing in the original a/b orientation
                // (`sb.is_nan().cmp(&sa.is_nan())`) makes a NaN-scored entry sort
                // AFTER a finite one; the previous `sa.is_nan().cmp(&sb.is_nan())`
                // reused the swapped operands and floated NaN to the FRONT.
                sb.is_nan().cmp(&sa.is_nan())
            })
        });
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Audit cycle-5 (#2): a NaN-scored gateway must sort to the END (worst),
    /// not the front. Guards the descending-sort NaN fallback comparator.
    #[test]
    fn nan_scored_gateway_sorts_to_end_cycle5() {
        let mut gl = GatewayList::new(false);
        let (b, ba, bs, bi) = make_gw(0x0b, 20.0, true);
        let (c, ca, cs, ci) = make_gw(0x0c, 30.0, true);
        let (a, aa, _, ai) = make_gw(0x0a, 0.0, true);
        gl.upsert(b, ba, bs, bi);
        gl.upsert(c, ca, cs, ci);
        gl.upsert(a, aa, 0.0, ai);
        gl.update_score(&a, f64::NAN);
        let entries = gl.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries.last().unwrap().node_id,
            a,
            "NaN-scored gateway must sort to the END (worst)"
        );
        assert_ne!(
            entries.first().unwrap().node_id,
            a,
            "NaN-scored gateway must not be ranked first"
        );
    }

    fn make_gw(node_id_byte: u8, score: f64, has_internet: bool) -> ([u8; 32], String, f64, bool) {
        let mut id = [0u8; 32];
        id[0] = node_id_byte;
        (
            id,
            format!("tcp://10.0.0.{}:9000", node_id_byte),
            score,
            has_internet,
        )
    }

    #[test]
    fn upsert_and_preferred() {
        let mut list = GatewayList::new(true);
        let (id_a, addr_a, score_a, internet_a) = make_gw(1, 100.0, true);
        let (id_b, addr_b, score_b, internet_b) = make_gw(2, 80.0, false);
        list.upsert(id_a, addr_a, score_a, internet_a);
        list.upsert(id_b, addr_b, score_b, internet_b);
        let mut active: HashSet<[u8; 32]> = HashSet::new();
        active.insert(id_a);
        active.insert(id_b);
        // A has score=100 × (1+1)=200; B has score=80 × (1+0)=80. A wins.
        let pref = list.preferred(&active).unwrap();
        assert_eq!(pref.node_id, id_a);
    }

    #[test]
    fn prefer_internet_gateway_filters_non_internet() {
        let mut list = GatewayList::new(true);
        let (id_a, addr_a, score_a, _) = make_gw(1, 50.0, false); // no internet
        let (id_b, addr_b, score_b, _) = make_gw(2, 40.0, true); // has internet
        list.upsert(id_a, addr_a, score_a, false);
        list.upsert(id_b, addr_b, score_b, true);
        let mut active: HashSet<[u8; 32]> = HashSet::new();
        active.insert(id_a);
        active.insert(id_b);
        let pref = list.preferred_internet_gateway(&active).unwrap();
        assert_eq!(pref.node_id, id_b, "only has_internet gateways returned");
    }

    #[test]
    fn preferred_returns_none_when_no_active_sessions() {
        let mut list = GatewayList::new(true);
        let (id, addr, score, has_int) = make_gw(1, 100.0, true);
        list.upsert(id, addr, score, has_int);
        assert!(list.preferred(&HashSet::new()).is_none());
    }

    #[test]
    fn rank_of_returns_position() {
        let mut list = GatewayList::new(false);
        let (id_a, addr_a, score_a, _) = make_gw(1, 100.0, false);
        let (id_b, addr_b, score_b, _) = make_gw(2, 50.0, false);
        list.upsert(id_a, addr_a, score_a, false); // rank 0
        list.upsert(id_b, addr_b, score_b, false); // rank 1
        assert_eq!(list.rank_of(&id_a), 0);
        assert_eq!(list.rank_of(&id_b), 1);
    }

    #[test]
    fn should_switch_requires_stability_and_margin() {
        let mut list = GatewayList::new(false);
        let (id_a, addr_a, score_a, _) = make_gw(1, 100.0, false); // current
        let (id_b, addr_b, score_b, _) = make_gw(2, 130.0, false); // candidate (30 % better)
        list.upsert(id_a, addr_a, score_a, false);
        list.upsert(id_b, addr_b, score_b, false);
        // B not yet stable — should not switch.
        assert!(
            !list.should_switch(&id_a, &id_b),
            "must not switch before stability window"
        );
        // Manually mark B as stable for >30s.
        let past = Instant::now() - Duration::from_secs(HYSTERESIS_STABLE_SECS + 1);
        list.entries
            .iter_mut()
            .find(|e| e.node_id == id_b)
            .unwrap()
            .stable_since = Some(past);
        assert!(
            list.should_switch(&id_a, &id_b),
            "should switch when stable + score margin met"
        );
    }

    #[test]
    fn should_switch_no_margin_no_switch() {
        let mut list = GatewayList::new(false);
        let (id_a, addr_a, score_a, _) = make_gw(1, 100.0, false);
        let (id_b, addr_b, score_b, _) = make_gw(2, 110.0, false); // only 10% better — below 20% margin
        list.upsert(id_a, addr_a, score_a, false);
        list.upsert(id_b, addr_b, score_b, false);
        let past = Instant::now() - Duration::from_secs(HYSTERESIS_STABLE_SECS + 1);
        list.entries
            .iter_mut()
            .find(|e| e.node_id == id_b)
            .unwrap()
            .stable_since = Some(past);
        assert!(
            !list.should_switch(&id_a, &id_b),
            "margin < 20 % — must not switch"
        );
    }

    #[test]
    fn mark_connected_sets_stable_since() {
        let mut list = GatewayList::new(false);
        let (id, addr, score, _) = make_gw(1, 100.0, false);
        list.upsert(id, addr, score, false);
        assert!(list.entries[0].stable_since.is_none());
        list.mark_connected(&id);
        assert!(list.entries[0].stable_since.is_some());
        // Second call does not reset it.
        let first = list.entries[0].stable_since.unwrap();
        list.mark_connected(&id);
        assert_eq!(list.entries[0].stable_since.unwrap(), first);
    }

    #[test]
    fn mark_disconnected_clears_stable_since() {
        let mut list = GatewayList::new(false);
        let (id, addr, score, _) = make_gw(1, 100.0, false);
        list.upsert(id, addr, score, false);
        list.mark_connected(&id);
        list.mark_disconnected(&id);
        assert!(list.entries[0].stable_since.is_none());
    }

    // ── GatewayList snapshot / restore ──────────────────────────────

    /// snapshot returns all current entries with their scores.
    #[test]
    fn snapshot_returns_all_entries() {
        let mut list = GatewayList::new(false);
        let (id_a, addr_a, _, _) = make_gw(1, 100.0, true);
        let (id_b, addr_b, _, _) = make_gw(2, 60.0, false);
        list.upsert(id_a, addr_a, 100.0, true);
        list.upsert(id_b, addr_b, 60.0, false);
        let snap = list.snapshot();
        assert_eq!(snap.len(), 2);
        let a = snap.iter().find(|s| s.node_id == id_a).unwrap();
        assert!((a.score - 100.0).abs() < 1e-9);
        assert!(a.has_internet);
        let b = snap.iter().find(|s| s.node_id == id_b).unwrap();
        assert!(!b.has_internet);
    }

    /// restore inserts entries not already in the list, halving their score.
    #[test]
    fn restore_inserts_missing_with_half_score() {
        let mut list = GatewayList::new(false);
        let (id, addr, _, _) = make_gw(5, 80.0, false);
        let snap = vec![GatewaySnapshot {
            node_id: id,
            veil_addr: addr,
            score: 80.0,
            has_internet: false,
        }];
        list.restore(snap);
        assert_eq!(list.entries().len(), 1);
        // Restored score must be halved.
        assert!((list.entries()[0].score - 40.0).abs() < 1e-9);
    }

    /// restore skips entries already present (config entries take precedence).
    #[test]
    fn restore_does_not_overwrite_existing() {
        let mut list = GatewayList::new(false);
        let (id, addr, _, _) = make_gw(7, 100.0, true);
        list.upsert(id, addr.clone(), 100.0, true);
        let snap = vec![GatewaySnapshot {
            node_id: id,
            veil_addr: addr,
            score: 999.0,
            has_internet: false,
        }];
        list.restore(snap);
        assert_eq!(list.entries().len(), 1);
        // Original score unchanged.
        assert!((list.entries()[0].score - 100.0).abs() < 1e-9);
        assert!(list.entries()[0].has_internet);
    }

    // ── weighted egress diversification ────────────────────────

    #[test]
    fn pick_weighted_returns_none_with_no_active_gateways() {
        let mut list = GatewayList::new(false);
        let (id, addr, _, _) = make_gw(1, 50.0, true);
        list.upsert(id, addr, 50.0, true);
        let active = std::collections::HashSet::new();
        assert!(list.pick_weighted(&active, 4, 0).is_none());
    }

    #[test]
    fn pick_weighted_returns_only_candidate_when_one_active() {
        let mut list = GatewayList::new(false);
        let (id1, addr1, _, _) = make_gw(1, 100.0, false);
        let (id2, addr2, _, _) = make_gw(2, 200.0, false);
        list.upsert(id1, addr1, 100.0, false);
        list.upsert(id2, addr2, 200.0, false);
        // Only id1 has an open session.
        let mut active = std::collections::HashSet::new();
        active.insert(id1);
        let picked = list
            .pick_weighted(&active, 4, 0xDEAD_BEEF_0000_0000)
            .unwrap();
        assert_eq!(picked.node_id, id1);
    }

    #[test]
    fn pick_weighted_distributes_across_top_k_proportional_to_score() {
        let mut list = GatewayList::new(false);
        let (id1, addr1, _, _) = make_gw(1, 100.0, false);
        let (id2, addr2, _, _) = make_gw(2, 100.0, false);
        let (id3, addr3, _, _) = make_gw(3, 100.0, false);
        list.upsert(id1, addr1, 100.0, false);
        list.upsert(id2, addr2, 100.0, false);
        list.upsert(id3, addr3, 100.0, false);
        let mut active = std::collections::HashSet::new();
        active.insert(id1);
        active.insert(id2);
        active.insert(id3);

        // Run 1000 picks with a deterministic xorshift sequence; each gateway
        // should get ~333 picks (with ±10% slack). Equal scores → uniform.
        let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut counts = [0u32; 3];
        for _ in 0..1000 {
            // Trivial xorshift step for the rolling RNG.
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let picked = list.pick_weighted(&active, 4, rng).unwrap();
            if picked.node_id == id1 {
                counts[0] += 1;
            } else if picked.node_id == id2 {
                counts[1] += 1;
            } else {
                counts[2] += 1;
            }
        }
        for c in counts {
            assert!(
                (250..=420).contains(&c),
                "uniform-weight pick distribution out of expected range: {counts:?}",
            );
        }
    }

    #[test]
    fn pick_weighted_respects_top_k_window() {
        let mut list = GatewayList::new(false);
        // 5 gateways with descending scores.
        let mut active = std::collections::HashSet::new();
        for i in 1..=5u8 {
            let (id, addr, _, _) = make_gw(i, (10 - i as i32) as f64 * 100.0, false);
            list.upsert(id, addr, (10 - i as i32) as f64 * 100.0, false);
            active.insert(id);
        }
        // top_k=2 → only the two highest-scored entries are eligible.
        let mut seen = std::collections::HashSet::new();
        for r in 0..200u64 {
            let picked = list
                .pick_weighted(&active, 2, r.wrapping_mul(0xA0761D6478BD642F))
                .unwrap();
            seen.insert(picked.node_id);
        }
        assert_eq!(
            seen.len(),
            2,
            "top_k=2 must restrict pick to 2 candidates, got {}",
            seen.len()
        );
    }

    /// GatewaySnapshot JSON roundtrip preserves all fields.
    #[test]
    fn snapshot_json_roundtrip() {
        let mut list = GatewayList::new(true);
        let (id, addr, _, _) = make_gw(9, 77.5, true);
        list.upsert(id, addr, 77.5, true);
        let snap = list.snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        let decoded: Vec<GatewaySnapshot> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].node_id, id);
        assert!((decoded[0].score - 77.5).abs() < 1e-9);
        assert!(decoded[0].has_internet);
    }
}
