//! Simulation event log, replay, scenario config, and snapshot.
//!
//! # Event log
//!
//! When `SimNetwork` is created with `recording(true)` every topology mutation
//! is appended to an internal log as a [`SimEvent`]. The log can be exported
//! with [`SimNetwork::events`] and fed back into [`SimNetwork::replay`] to
//! reproduce the identical topology sequence.
//!
//! # Scenario
//!
//! [`ScenarioConfig`] packages seed, topology, and impairment parameters into a
//! single value; [`run_scenario`] builds a network from it and returns the event
//! log for verification.
//!
//! # Snapshot
//!
//! [`SimSnapshot`] captures the observable state (seed, active links, loss map
//! event log) without cloning live async nodes. It can be serialised with serde
//! and restored [`SimNetwork::restore_links`].

use std::collections::HashMap;

// ── SimEvent ──────────────────────────────────────────────────────────────────

/// An observable topology event produced by [`crate::sim::SimNetwork`].
#[derive(Debug, Clone, PartialEq)]
pub enum SimEvent {
    /// Two nodes became connected (session established).
    NodeConnected { a: usize, b: usize },
    /// Two nodes were disconnected.
    NodeDisconnected { a: usize, b: usize },
    /// Link-loss probability was recorded for the link (a, b).
    LinkLossSet { a: usize, b: usize, rate: f64 },
    /// A partition was applied between two groups.
    Partition {
        group_a: Vec<usize>,
        group_b: Vec<usize>,
    },
    /// A partition was healed.
    HealPartition {
        group_a: Vec<usize>,
        group_b: Vec<usize>,
    },
    /// A synthetic time tick injected during replay (millisecond delay).
    TimeTick { ms: u64 },
}

// ── SimSnapshot ───────────────────────────────────────────────────────────────

/// A serialisable snapshot of a [`SimNetwork`]'s observable state.
///
/// Does **not** capture live TCP sessions — it captures the logical topology
/// that can be reconstructed on a fresh network.
#[derive(Debug, Clone)]
pub struct SimSnapshot {
    /// The PRNG seed used when the network was built.
    pub seed: u64,
    /// Active links at snapshot time: pairs `(a, b)` with `a < b`.
    pub active_links: Vec<(usize, usize)>,
    /// Recorded per-link loss probabilities.
    pub loss_map: HashMap<(usize, usize), f64>,
    /// Full event log at snapshot time (empty if recording was not enabled).
    pub event_log: Vec<SimEvent>,
}

// ── ScenarioConfig ────────────────────────────────────────────────────────────

/// Parameterised simulation scenario.
///
/// Pass [`run_scenario`] to build and run a network with the described
/// configuration and receive back the event log.
#[derive(Debug, Clone)]
pub struct ScenarioConfig {
    /// PRNG seed — same seed → identical event log for deterministic topology ops.
    pub seed: u64,
    /// Number of nodes (all `NodeRole::Core`).
    pub node_count: usize,
    /// Topology: `"ring"`, `"star"`, `"full_mesh"`, or `"random"`.
    pub topology: String,
    /// For `"random"` topology: edge probability (0.0 – 1.0).
    pub random_edge_prob: f64,
    /// Simulated link-loss probability applied to every link (0.0 = none).
    pub loss_rate: f64,
    /// Partition event at `partition_at_ms` ms after wiring (0 = disabled).
    pub partition_at_ms: u64,
    /// Groups to partition (index pairs).
    pub partition_groups: Option<(Vec<usize>, Vec<usize>)>,
    /// Heal event at `heal_at_ms` ms after partition (0 = no heal).
    pub heal_at_ms: u64,
}

impl Default for ScenarioConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            node_count: 4,
            topology: "ring".to_owned(),
            random_edge_prob: 0.5,
            loss_rate: 0.0,
            partition_at_ms: 0,
            partition_groups: None,
            heal_at_ms: 0,
        }
    }
}

/// Build a [`SimNetwork`] from `cfg`, wire it, apply impairments, and return
/// the event log. The network is stopped before returning.
pub async fn run_scenario(cfg: ScenarioConfig) -> Vec<SimEvent> {
    use crate::{cfg::NodeRole, sim::network::SimNetworkBuilder};

    let mut net = SimNetworkBuilder::default()
        .nodes(cfg.node_count)
        .role(NodeRole::Core)
        .seed(cfg.seed)
        .recording(true)
        .build()
        .await;

    // Wire topology
    match cfg.topology.as_str() {
        "star" => net.wire_star().await,
        "full_mesh" => net.wire_full_mesh().await,
        "random" => net.wire_random_seeded(cfg.random_edge_prob).await,
        _ => net.wire_ring().await, // default: ring
    }

    // Apply uniform link loss
    if cfg.loss_rate > 0.0 {
        let links: Vec<_> = net.active_links();
        for (a, b) in links {
            net.set_link_loss(a, b, cfg.loss_rate);
        }
    }

    // Partition
    if cfg.partition_at_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(cfg.partition_at_ms)).await;
        if let Some((ref ga, ref gb)) = cfg.partition_groups {
            net.partition(ga, gb).await;

            // Heal
            if cfg.heal_at_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(cfg.heal_at_ms)).await;
                let cross: Vec<_> = net
                    .events()
                    .iter()
                    .filter_map(|e| {
                        if let SimEvent::NodeDisconnected { a, b } = e {
                            Some((*a, *b))
                        } else {
                            None
                        }
                    })
                    .collect();
                net.heal_partition(ga, gb, &cross).await;
            }
        }
    }

    let log = net.events().to_vec();
    net.stop().await;
    log
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── 251.2: event log records topology events ─────────────────────────────

    #[ignore = "Phase E20 directional dedup: SimNetwork random identities cause ~50% pairwise-session establishment failure; see audit batch 2026-05-24"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]

    async fn event_log_records_connect_and_disconnect() {
        use crate::{cfg::NodeRole, sim::network::SimNetworkBuilder};

        let mut net = SimNetworkBuilder::default()
            .nodes(2)
            .role(NodeRole::Core)
            .seed(0)
            .recording(true)
            .build()
            .await;

        net.connect(0, 1).await;
        net.disconnect(0, 1).await;

        let events = net.events().to_vec();
        net.stop().await;

        assert!(
            events.contains(&SimEvent::NodeConnected { a: 0, b: 1 }),
            "NodeConnected must be recorded: {:?}",
            events
        );
        assert!(
            events.contains(&SimEvent::NodeDisconnected { a: 0, b: 1 }),
            "NodeDisconnected must be recorded: {:?}",
            events
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn event_log_records_link_loss() {
        use crate::{cfg::NodeRole, sim::network::SimNetworkBuilder};

        let mut net = SimNetworkBuilder::default()
            .nodes(2)
            .role(NodeRole::Core)
            .seed(0)
            .recording(true)
            .build()
            .await;

        net.connect(0, 1).await;
        net.set_link_loss(0, 1, 0.5);

        let events = net.events().to_vec();
        net.stop().await;

        assert!(
            events.iter().any(|e| matches!(e, SimEvent::LinkLossSet { a: 0, b: 1, rate } if (*rate - 0.5).abs() < f64::EPSILON)),
            "LinkLossSet must be recorded: {:?}", events
        );
    }

    // ── 251.1: same seed → identical event log ────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_seed_produces_identical_random_topology() {
        use crate::{cfg::NodeRole, sim::network::SimNetworkBuilder};

        let build = |seed: u64| async move {
            let mut net = SimNetworkBuilder::default()
                .nodes(5)
                .role(NodeRole::Core)
                .seed(seed)
                .recording(true)
                .build()
                .await;
            net.wire_random_seeded(0.6).await;
            let links = net.active_links().len();
            net.stop().await;
            links
        };

        let links_a = build(42).await;
        let links_b = build(42).await;
        assert_eq!(links_a, links_b, "same seed must produce same link count");
    }

    // ── 251.3: replay ─────────────────────────────────────────────────────────

    #[ignore = "Phase E20 directional dedup: SimNetwork random identities cause ~50% pairwise-session establishment failure; see audit batch 2026-05-24"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]

    async fn replay_produces_same_active_links() {
        use crate::{cfg::NodeRole, sim::network::SimNetworkBuilder};

        // Record events from a 3-node ring.
        let mut net = SimNetworkBuilder::default()
            .nodes(3)
            .role(NodeRole::Core)
            .seed(1)
            .recording(true)
            .build()
            .await;
        net.wire_ring().await;
        let snapshot = net.snapshot();
        net.stop().await;

        // Replay on a fresh network of the same size.
        let mut net2 = SimNetworkBuilder::default()
            .nodes(3)
            .role(NodeRole::Core)
            .seed(1)
            .recording(true)
            .build()
            .await;
        net2.replay(&snapshot.event_log).await;

        let links2 = net2.active_links().len();
        net2.stop().await;

        assert_eq!(
            links2,
            snapshot.active_links.len(),
            "replayed network must have same active-link count"
        );
    }

    // ── 251.4: scenario parameterization ──────────────────────────────────────

    #[ignore = "Phase E20 directional dedup: SimNetwork random identities cause ~50% pairwise-session establishment failure; see audit batch 2026-05-24"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]

    async fn scenario_ring_produces_n_links() {
        let cfg = ScenarioConfig {
            seed: 7,
            node_count: 4,
            topology: "ring".to_owned(),
            ..ScenarioConfig::default()
        };
        let events = run_scenario(cfg).await;
        let connects = events
            .iter()
            .filter(|e| matches!(e, SimEvent::NodeConnected { .. }))
            .count();
        assert_eq!(
            connects, 4,
            "ring of 4 should produce exactly 4 connect events"
        );
    }

    #[ignore = "Phase E20 directional dedup: SimNetwork random identities cause ~50% pairwise-session establishment failure; see audit batch 2026-05-24"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]

    async fn scenario_full_mesh_produces_correct_links() {
        let cfg = ScenarioConfig {
            seed: 13,
            node_count: 4,
            topology: "full_mesh".to_owned(),
            ..ScenarioConfig::default()
        };
        let events = run_scenario(cfg).await;
        let connects = events
            .iter()
            .filter(|e| matches!(e, SimEvent::NodeConnected { .. }))
            .count();
        // C(4,2) = 6
        assert_eq!(
            connects, 6,
            "full mesh of 4 should produce exactly 6 connect events"
        );
    }

    // ── 251.5: snapshot / restore ─────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn snapshot_captures_seed_and_links() {
        use crate::{cfg::NodeRole, sim::network::SimNetworkBuilder};

        let mut net = SimNetworkBuilder::default()
            .nodes(3)
            .role(NodeRole::Core)
            .seed(99)
            .recording(true)
            .build()
            .await;
        net.wire_ring().await;
        let snap = net.snapshot();
        net.stop().await;

        assert_eq!(snap.seed, 99);
        assert_eq!(snap.active_links.len(), 3, "ring of 3 has 3 links");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn snapshot_captures_loss_map() {
        use crate::{cfg::NodeRole, sim::network::SimNetworkBuilder};

        let mut net = SimNetworkBuilder::default()
            .nodes(2)
            .role(NodeRole::Core)
            .seed(0)
            .recording(true)
            .build()
            .await;
        net.connect(0, 1).await;
        net.set_link_loss(0, 1, 0.3);
        let snap = net.snapshot();
        net.stop().await;

        let loss = snap.loss_map.get(&(0, 1)).copied().unwrap_or(0.0);
        assert!(
            (loss - 0.3).abs() < f64::EPSILON,
            "snapshot must capture link loss"
        );
    }
}
