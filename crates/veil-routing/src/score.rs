//! Neighbour scoring for preferred-gateway selection.
//!
//! `NeighborScore` combines RTT and recent reachability into a single scalar
//! that can be used to rank a set of candidate nodes (e.g. gateways for a
//! leaf, replicas for a mailbox lookup).
//!
//! Lower scores are better (closer / more reachable).

use std::collections::HashMap;

use super::probe::RttTable;

// ── NeighborScore ─────────────────────────────────────────────────────────────

/// Combined routing score for a single neighbour.
#[derive(Debug, Clone, PartialEq)]
pub struct NeighborScore {
    pub node_id: [u8; 32],
    /// Last known RTT in ms, or `u32::MAX` if unknown.
    pub rtt_ms: u32,
    /// Fraction of recent probes that succeeded [0.0, 1.0].
    pub reachability: f32,
}

impl NeighborScore {
    /// Combined score: lower is better.
    ///
    /// `score = rtt_ms / reachability` — unreachable nodes get f32::INFINITY.
    pub fn combined(&self) -> f32 {
        if self.reachability <= 0.0 {
            return f32::INFINITY;
        }
        self.rtt_ms as f32 / self.reachability
    }
}

// ── NeighborScorer ────────────────────────────────────────────────────────────

/// Builds `NeighborScore`s from `RttTable` and reachability history.
#[derive(Debug, Default, Clone)]
pub struct NeighborScorer {
    /// Moving-average reachability per node (0.0 – 1.0).
    reachability: HashMap<[u8; 32], f32>,
    /// EMA weight applied when a probe *fails* (sample = 0.0).
    ///
    /// Higher value → faster response to outages. Default 0.5: reachability
    /// halves with each consecutive failure, so two failures drop it to 0.25.
    alpha_down: f32,
    /// EMA weight applied when a probe *succeeds* (sample = 1.0).
    ///
    /// Lower value → slower trust rebuild after an outage. Default 0.1: it
    /// takes ~22 successes to recover from a fully-unreachable state, preventing
    /// flapping caused by brief outages followed by a single lucky probe.
    alpha_up: f32,
}

impl NeighborScorer {
    /// Create a scorer with a single symmetric alpha.
    ///
    /// For asymmetric behaviour use [`NeighborScorer::with_alphas`].
    pub fn new(alpha: f32) -> Self {
        debug_assert!(alpha > 0.0 && alpha <= 1.0, "alpha must be in (0, 1]");
        Self {
            reachability: HashMap::new(),
            alpha_down: alpha,
            alpha_up: alpha,
        }
    }

    /// Create a scorer with separate down/up alphas.
    ///
    /// `alpha_down` (failure weight) should be ≥ `alpha_up` (recovery weight)
    /// so that the node reacts quickly to outages but rebuilds trust slowly.
    pub fn with_alphas(alpha_down: f32, alpha_up: f32) -> Self {
        debug_assert!(alpha_down > 0.0 && alpha_down <= 1.0);
        debug_assert!(alpha_up > 0.0 && alpha_up <= 1.0);
        Self {
            reachability: HashMap::new(),
            alpha_down,
            alpha_up,
        }
    }

    /// Record a probe outcome for `node_id` (`success = true/false`).
    ///
    /// Uses asymmetric EMA: failures apply `alpha_down` (fast), successes
    /// apply `alpha_up` (slow), so the scorer reacts quickly to outages
    /// but rebuilds trust gradually.
    pub fn record_probe(&mut self, node_id: [u8; 32], success: bool) {
        let (sample, alpha) = if success {
            (1.0f32, self.alpha_up)
        } else {
            (0.0f32, self.alpha_down)
        };
        let entry = self.reachability.entry(node_id).or_insert(1.0);
        *entry = (1.0 - alpha) * *entry + alpha * sample;
    }

    /// Get the current score for `node_id` using `rtt_table` for RTT.
    pub fn score(&self, node_id: &[u8; 32], rtt_table: &RttTable) -> NeighborScore {
        // Use EWMA-smoothed RTT for scoring — less sensitive to transient spikes.
        let rtt_ms = rtt_table
            .get(node_id)
            .map(|p| p.rtt_smoothed)
            .unwrap_or(u32::MAX);
        let reachability = self.reachability.get(node_id).copied().unwrap_or(1.0);
        NeighborScore {
            node_id: *node_id,
            rtt_ms,
            reachability,
        }
    }

    /// Return the reachability fraction for `node_id` (0.0–1.0).
    /// Defaults to 1.0 (fully reachable) for unknown peers.
    pub fn reachability(&self, node_id: &[u8; 32]) -> f32 {
        self.reachability.get(node_id).copied().unwrap_or(1.0)
    }

    /// Drop a peer's reachability entry (audit L-7).
    ///
    /// Called on session close so the map shrinks with peer churn instead of
    /// gaining a permanent entry per distinct ROUTE_REPLY sender. An absent
    /// peer scores the default 1.0, so removing a closed peer is safe.
    pub fn remove(&mut self, node_id: &[u8; 32]) {
        self.reachability.remove(node_id);
    }

    /// Number of tracked reachability entries (for tests / observability).
    pub fn len(&self) -> usize {
        self.reachability.len()
    }

    /// Whether the reachability map is empty.
    pub fn is_empty(&self) -> bool {
        self.reachability.is_empty()
    }

    /// Return the preferred node_id from `candidates` (lowest combined score).
    pub fn preferred_gateway<'a>(
        &self,
        candidates: &'a [[u8; 32]],
        rtt_table: &RttTable,
    ) -> Option<&'a [u8; 32]> {
        candidates.iter().min_by(|a, b| {
            let sa = self.score(a, rtt_table).combined();
            let sb = self.score(b, rtt_table).combined();
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::RttTable;
    use std::time::Duration;

    #[test]
    fn lower_rtt_wins() {
        let scorer = NeighborScorer::new(0.5);
        let mut rtt = RttTable::new(Duration::from_secs(60));
        rtt.record([1u8; 32], crate::probe::PeerReportedRtt::from_raw_ms(10), 0);
        rtt.record(
            [2u8; 32],
            crate::probe::PeerReportedRtt::from_raw_ms(200),
            0,
        );
        let candidates = vec![[1u8; 32], [2u8; 32]];
        let best = scorer.preferred_gateway(&candidates, &rtt).unwrap();
        assert_eq!(*best, [1u8; 32]);
    }

    #[test]
    fn unreachable_node_loses() {
        let mut scorer = NeighborScorer::new(0.5);
        let mut rtt = RttTable::new(Duration::from_secs(60));
        rtt.record([1u8; 32], crate::probe::PeerReportedRtt::from_raw_ms(50), 0);
        rtt.record([2u8; 32], crate::probe::PeerReportedRtt::from_raw_ms(5), 0);
        // Mark node [2] as unreachable (many failures to drive reachability very low)
        for _ in 0..20 {
            scorer.record_probe([2u8; 32], false);
        }
        let candidates = vec![[1u8; 32], [2u8; 32]];
        let best = scorer.preferred_gateway(&candidates, &rtt).unwrap();
        assert_eq!(*best, [1u8; 32]);
    }

    #[test]
    fn empty_candidates_returns_none() {
        let scorer = NeighborScorer::new(0.3);
        let rtt = RttTable::new(Duration::from_secs(60));
        assert!(scorer.preferred_gateway(&[], &rtt).is_none());
    }

    #[test]
    fn reachability_ema_converges() {
        let mut scorer = NeighborScorer::new(0.5);
        let node = [3u8; 32];
        // All failures
        for _ in 0..10 {
            scorer.record_probe(node, false);
        }
        let r = scorer.reachability[&node];
        assert!(r < 0.01, "reachability should converge toward 0: {r}");
    }

    #[test]
    fn combined_score_with_no_rtt() {
        let scorer = NeighborScorer::new(0.5);
        let rtt = RttTable::new(Duration::from_secs(60));
        let s = scorer.score(&[5u8; 32], &rtt);
        // rtt_ms = u32::MAX, reachability = 1.0 → combined = large finite
        assert!(s.combined().is_finite());
        assert!(s.combined() > 1_000_000.0);
    }
}
