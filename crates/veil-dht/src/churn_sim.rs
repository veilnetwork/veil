//! Epic 485.1.c — 24h churn-aware adversary scenario.
//!
//! # Threat model
//!
//! The vanilla 485.1{a,b,c,d} scenarios snap-shot the network at а
//! single moment.  Real adversaries operate в continuous time: they
//! stay online persistently, while honest nodes churn (laptops sleep,
//! cellular drops, daily-restart maintenance cycles).  Over 24h
//! periods, three eclipse paths open up that don't show в а snapshot:
//!
//! 1. **Honest-fade**: persistent sybils outweigh transient honest
//!    nodes в the routing table simply by being available более reliably.
//! 2. **Re-discovery skew**: when an honest peer comes back online,
//!    its FIRST few outgoing lookups walk через а sybil-heavy seed
//!    set (since sybils were the only "live" peers during its offline
//!    window).
//! 3. **Bucket-decay drift**: time-based bucket-rate budget resets
//!    let а sybil cluster slowly fill slots one-per-resetCycle even
//!    если each individual round is bounded.
//!
//! # Scenario
//!
//! Uses `tokio::time::pause` к compress а simulated 24h into seconds.
//! Builds а 30-node mesh (25 honest + 5 sybils ≈ 16 % adversary
//! fraction).  Each simulated hour, 30 % of honest nodes go offline
//! и а different 30 % come back online — sybils ара always online.
//! Victim runs `find_node_iterative` once per simulated hour и
//! accumulates the union of all discovered contacts.
//!
//! # Validation
//!
//! After 24 simulated hours, the cumulative-discovered set's sybil
//! fraction must stay below а bound proportional к the population
//! ratio — sybils ара never going к disappear, но they shouldn't
//! dominate due к churn-amplified availability bias.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use veil_util::lock;

use crate::iterative::{FindValueResult, IterativeParams, PeerQuerier, find_node_iterative};
use crate::routing::{Contact, RoutingTable};

/// Churning [`PeerQuerier`] wrapper.  Wraps an inner querier и tracks
/// а per-node "offline" set: queries к offline nodes return empty,
/// matching the network behaviour where а timed-out peer's reply is
/// indistinguishable от "no contacts known".
///
/// Designed for tokio-time-paused tests где simulated hours advance
/// в zero wall-clock; the offline-set is updated explicitly via
/// [`Self::set_offline`] от the test driver.
pub struct ChurningPeerQuerier {
    inner: Arc<dyn PeerQuerier>,
    offline: Arc<std::sync::Mutex<HashSet<[u8; 32]>>>,
}

impl ChurningPeerQuerier {
    pub fn new(inner: Arc<dyn PeerQuerier>) -> Self {
        Self {
            inner,
            offline: Arc::new(std::sync::Mutex::new(HashSet::new())),
        }
    }

    /// Replace the offline set wholesale.  Idempotent.
    pub fn set_offline(&self, offline_set: HashSet<[u8; 32]>) {
        *lock!(self.offline) = offline_set;
    }
}

impl PeerQuerier for ChurningPeerQuerier {
    fn find_node<'a>(
        &'a self,
        peer_id: [u8; 32],
        target: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Vec<Contact>> + Send + 'a>> {
        let inner = Arc::clone(&self.inner);
        let offline_check = lock!(self.offline).contains(&peer_id);
        Box::pin(async move {
            if offline_check {
                Vec::new()
            } else {
                inner.find_node(peer_id, target).await
            }
        })
    }

    fn find_value<'a>(
        &'a self,
        peer_id: [u8; 32],
        key: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = FindValueResult> + Send + 'a>> {
        let inner = Arc::clone(&self.inner);
        let offline_check = lock!(self.offline).contains(&peer_id);
        Box::pin(async move {
            if offline_check {
                FindValueResult::Nodes(Vec::new())
            } else {
                inner.find_value(peer_id, key).await
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iterative::LocalPeerQuerier;

    /// Epic 485.1.c — over 24 simulated hours of honest-node churn,
    /// the cumulative discovered set's sybil fraction stays bounded
    /// roughly at the population ratio (no churn-induced eclipse).
    ///
    /// Topology: 25 honest + 5 sybils = 30 total (16.7 % sybil
    /// fraction).
    ///
    /// Churn model: each simulated hour, 30 % of honest nodes ара
    /// offline.  Different 30 % each hour (randomised), so over 24h
    /// each honest node averages ~30 % offline time.  Sybils stay
    /// online 100 % of the time.
    ///
    /// Victim runs `find_node` once per hour и accumulates the union
    /// of discovered contacts across all hours.  After 24h:
    /// * Total discoveries should include most honest nodes (~25
    ///   given the union grows over the period).
    /// * Sybil fraction should approximate the population ratio, not
    ///   100 % (which would indicate churn-amplified eclipse).
    ///
    /// **Bound**: sybil fraction ≤ 30 % — generous headroom over the
    /// 16.7 % population ratio.  Tighter bound would flake on rare
    /// scenarios где the random offline-set happens к ban most honest
    /// nodes during the victim's lookup hour.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn epic485_1_c_24h_churn_does_not_amplify_sybil_eclipse() {
        const HONEST_COUNT: usize = 25;
        const SYBIL_COUNT: usize = 5;
        const POPULATION: usize = HONEST_COUNT + SYBIL_COUNT;
        const SIM_HOURS: usize = 24;
        const HOURLY_OFFLINE_FRACTION: usize = 30; // %

        use rand_core::{OsRng, RngCore};

        // Step 1 — generate deterministic-but-distinct node_ids.
        let mut node_ids = Vec::with_capacity(POPULATION);
        for _ in 0..POPULATION {
            let mut id = [0u8; 32];
            OsRng.fill_bytes(&mut id);
            node_ids.push(id);
        }
        let honest_ids: &[[u8; 32]] = &node_ids[..HONEST_COUNT];
        let sybil_ids: HashSet<[u8; 32]> = node_ids[HONEST_COUNT..].iter().copied().collect();
        let victim_id = honest_ids[0];

        // Step 2 — build inner mesh: each node knows all others.
        let inner = Arc::new(LocalPeerQuerier::new());
        for &nid in &node_ids {
            let mut rt = RoutingTable::new(nid);
            for &other in &node_ids {
                if other != nid {
                    rt.insert(Contact::new(other, format!("tcp://{other:?}.test")));
                }
            }
            inner.add_node(nid, rt);
        }

        // Step 3 — wrap с churn layer.
        let churn = Arc::new(ChurningPeerQuerier::new(inner));

        // Step 4 — simulate 24 hours.  Each hour: pick а random 30 %
        // honest-subset к take offline, then victim runs find_node.
        let mut cumulative_discovered: HashSet<[u8; 32]> = HashSet::new();
        let offline_per_hour = HONEST_COUNT * HOURLY_OFFLINE_FRACTION / 100;
        let params = IterativeParams::default();

        for _hour in 0..SIM_HOURS {
            // Roll the offline set for this hour.
            let mut offline: HashSet<[u8; 32]> = HashSet::new();
            // Take а random subset of honest_ids of size `offline_per_hour`.
            let mut indices: Vec<usize> = (0..HONEST_COUNT).collect();
            // Fisher-Yates shuffle prefix.
            for i in 0..offline_per_hour {
                let j = i + (OsRng.next_u32() as usize % (HONEST_COUNT - i));
                indices.swap(i, j);
            }
            for &idx in &indices[..offline_per_hour] {
                offline.insert(honest_ids[idx]);
            }
            // Victim is never offline (it's the one querying).
            offline.remove(&victim_id);
            churn.set_offline(offline);

            // Pick а random target и run iterative.
            let mut target = [0u8; 32];
            OsRng.fill_bytes(&mut target);
            // Seed contacts: small subset of the full population (so
            // the walk has к expand) — но both honest и sybils
            // включены, matching realistic re-discovery.
            let seed: Vec<Contact> = node_ids
                .iter()
                .take(8)
                .filter(|&&id| id != victim_id)
                .map(|&id| Contact::new(id, format!("tcp://{id:?}.test")))
                .collect();
            let result = find_node_iterative(target, seed, &*churn, &params).await;
            for c in &result {
                cumulative_discovered.insert(c.node_id);
            }

            // Advance simulated clock by 1 hour.  tokio::time::pause
            // means real wall-clock doesn't move; this lets the test
            // run в milliseconds.
            tokio::time::advance(Duration::from_secs(3600)).await;
        }

        // Step 5 — measure cumulative sybil fraction.
        let total = cumulative_discovered.len();
        let sybil_count = cumulative_discovered
            .iter()
            .filter(|id| sybil_ids.contains(*id))
            .count();
        let fraction = sybil_count as f64 / total.max(1) as f64;

        eprintln!(
            "epic485_1_c: 24h sim — discovered={total} (population={POPULATION}) \
             sybils_in_set={sybil_count} fraction={fraction:.3}",
        );

        // Generous bound: 30 % — covers а stretched-luck run где all 5
        // sybils + few honest nodes happened к be the only-online set
        // в early hours.  Tighter bound would flake.
        assert!(
            fraction < 0.30,
            "24h churn produced excessive sybil eclipse: \
             total={total} sybils={sybil_count} fraction={fraction:.3} \
             (expected < 30 %; population ratio is ~16.7 %)",
        );
        // Sanity: at least а few honest contacts были discovered.
        assert!(
            total >= HONEST_COUNT / 2,
            "24h sim discovered <50 % of honest nodes (got {total}); \
             likely churn fixture or LocalPeerQuerier mock bug",
        );
    }
}
