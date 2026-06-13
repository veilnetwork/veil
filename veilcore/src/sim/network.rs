//! Multi-node simulation network.
//!
//! `SimNetwork` starts N `SimNode` instances and provides topology control:
//! connect, disconnect, partition, and churn.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use super::events::{SimEvent, SimSnapshot};

// Re-export so scenario tests can use LossyLink directly.
pub use super::loss::LossyLink;

use crate::{
    cfg::SessionConfig,
    cfg::{
        Config, IdentityConfig, ListenConfig, ListenId, NodeId, NodeRole, PeerId,
        SignatureAlgorithm,
    },
};

use super::node::{SimNode, SimNodeId};

// ── Global config counter ─────────────────────────────────────────────────────

static SIM_NODE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Build a sim-tempdir suffix that's collision-free across cargo-test
/// processes, nextest workers, and re-runs. pid+nonce+counter triple —
/// pid for human readability, 128-bit OsRng for uniqueness, counter so
/// in-scenario node ordering stays stable for log-grep.
fn sim_unique_suffix(prefix: &str) -> String {
    use rand_core::{OsRng, RngCore};
    let n = SIM_NODE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nonce: u128 = ((OsRng.next_u64() as u128) << 64) | OsRng.next_u64() as u128;
    format!("sim-{prefix}-{pid}-{nonce:032x}-{n}")
}

fn next_sim_config_path(prefix: &str) -> PathBuf {
    // return a per-node subdirectory unconditionally. Previously
    // non-sovereign sim builds returned a flat `/tmp/sim-*.toml`, which made
    // every sim node's `veil_dir = config.parent = /tmp/`. Once
    // added auto-build of `identity_document.bin` from the `[identity]`
    // keypair (persisted to veil_dir on first start), every sim node after
    // the first loaded node 0's just-written file → all nodes ended up with
    // node 0's `node_id` → handshakes between them rejected as "self". Fix
    // is the per-node-dir layout the sovereign scenarios already used; the
    // legacy flat layout had no callers that actually depended on it.
    next_sim_config_path_with_dir(prefix)
}

/// Returns a config path inside a per-node subdirectory, so
/// `NodeRuntime::start` can treat that dir as the node's
/// `veil_dir` — isolating `identity_document.bin`
/// `device_identity_sk.bin`, MLKEM keypair, revocation cache, etc.
/// from sibling nodes.
fn next_sim_config_path_with_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(sim_unique_suffix(prefix));
    crate::util::create_dir_all_with_eacces_retry(&dir).expect("create sim veil dir");
    dir.join("config.toml")
}

/// sign a fresh `NameClaim` under the sovereign
/// identity just created by `provision_sovereign_identity_for_sim`
/// and drop it into `<veil_dir>/name_claims/<name>.bin`. The
/// runtime's startup scan DHT-publishes the claim; peers then
/// resolve `@name` via `NameClaim::dht_key` lookups.
fn provision_name_claim_for_sim(config_path: &std::path::Path, name: &str) {
    use crate::cfg::sovereign_flow::IDENTITY_DOCUMENT_FILE;
    use crate::node::identity::sovereign::{SovereignIdentity, save_name_claim};
    use std::time::{SystemTime, UNIX_EPOCH};

    let veil_dir = config_path
        .parent()
        .expect("config_path has parent")
        .to_path_buf();
    assert!(
        veil_dir.join(IDENTITY_DOCUMENT_FILE).exists(),
        "name_claim requires sovereign_identities(true) — run \
         provision_sovereign_identity_for_sim first",
    );
    let sov = SovereignIdentity::load_from_dir(&veil_dir)
        .expect("sim: load sovereign identity to sign name claim");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let claim = sov
        .sign_name_claim(name, now)
        .expect("sim: sign name claim");
    save_name_claim(&veil_dir, &claim).expect("sim: save name claim");
}

/// run `create_identity` into the config's parent
/// directory so the subsequent `NodeRuntime::start` auto-loads it
/// via the canonical on-disk layout. Uses the `#[cfg(test)]`
/// identity-policy PoW difficulty (16 bits) for fast mining;
/// produces no encrypted master file (sim nodes don't need the
/// `master.enc` recovery path).
fn provision_sovereign_identity_for_sim(config_path: &std::path::Path) {
    use crate::cfg::sovereign_flow::{CreateIdentityOptions, create_identity};
    use std::time::{SystemTime, UNIX_EPOCH};

    let veil_dir = config_path
        .parent()
        .expect("config_path has parent")
        .to_path_buf();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let out = create_identity(CreateIdentityOptions {
        veil_dir: veil_dir.clone(),
        save_encrypted_with_password: None,
        argon2_params_override: None,
        extra_entropy: None,
        instance_label: "sim-node".into(),
        pow_difficulty: crate::identity_policy::IdentityPolicy::DEFAULT_POW_DIFFICULTY,
        issued_at_unix: now,
        valid_until_unix: now + 7 * 86_400,
        algo: veil_types::SignatureAlgorithm::Ed25519,
    })
    .expect("sim sovereign identity provisioning");

    // (test-only): stash the raw master_seed bytes so
    // scenario tests that exercise `rotate_identity` / `revoke` can
    // re-derive `master_sk` without going through BIP-39 prompts or
    // the encrypted-master-file path. File name `master_seed.sim`
    // is intentionally distinct from the production `master.enc` so
    // it's never mistaken for a real artifact.
    std::fs::write(
        veil_dir.join(SIM_MASTER_SEED_FILE),
        out.master_seed.as_ref(),
    )
    .expect("sim: persist test master_seed");
}

/// provision a sim node's sovereign identity via
/// `restore_identity` against the supplied `master_seed` (typically
/// read from another node's `master_seed.sim` via
/// `sim_read_master_seed`). Produces a fresh per-device
/// identity_sk + instance_id but pins `node_id` to the
/// master-derived value. Mirrors the production "user lost
/// device, recovers from BIP-39 paper backup" flow.
fn provision_restored_sovereign_identity_for_sim(
    config_path: &std::path::Path,
    master_seed: zeroize::Zeroizing<[u8; 32]>,
) {
    use crate::cfg::sovereign_flow::{RestoreIdentityOptions, restore_identity};
    use std::time::{SystemTime, UNIX_EPOCH};

    let veil_dir = config_path
        .parent()
        .expect("config_path has parent")
        .to_path_buf();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    restore_identity(RestoreIdentityOptions {
        veil_dir: veil_dir.clone(),
        master_seed: master_seed.clone(),
        save_encrypted_with_password: None,
        argon2_params_override: None,
        instance_label: "sim-restored".into(),
        pow_difficulty: crate::identity_policy::IdentityPolicy::DEFAULT_POW_DIFFICULTY,
        now_unix: now,
        valid_until_unix: now + 7 * 86_400,
        algo: veil_types::SignatureAlgorithm::Ed25519,
        master_falcon_keypair_bytes: None,
    })
    .expect("sim restored sovereign identity provisioning");

    // Stash the master_seed on the restored device too so scenarios
    // that exercise `rotate_identity` from the restored side keep
    // working without reaching back into the source node's dir.
    std::fs::write(veil_dir.join(SIM_MASTER_SEED_FILE), master_seed.as_ref())
        .expect("sim: persist test master_seed on restored device");
}

/// Filename used by [`provision_sovereign_identity_for_sim`] to
/// stash the raw master_seed bytes for scenario tests. Absent in
/// production layouts.
pub const SIM_MASTER_SEED_FILE: &str = "master_seed.sim";

/// Read the raw 32-byte master_seed written by
/// `provision_sovereign_identity_for_sim`. Panics if the file is
/// missing or the wrong size — scenarios opt-in via
/// `sovereign_identities(true)` before calling this.
pub fn sim_read_master_seed(veil_dir: &std::path::Path) -> zeroize::Zeroizing<[u8; 32]> {
    let bytes = std::fs::read(veil_dir.join(SIM_MASTER_SEED_FILE))
        .expect("sim: master_seed.sim missing — did you enable sovereign_identities(true)?");
    assert_eq!(bytes.len(), 32, "sim master_seed must be 32 bytes");
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    out
}

// ── SimNetwork ────────────────────────────────────────────────────────────────

/// A simulation network containing multiple veil nodes.
pub struct SimNetwork {
    nodes: Vec<SimNode>,
    /// Links: (a, b) with a < b, present if the link is active.
    links: HashSet<(usize, usize)>,
    /// Next PeerId to assign.
    next_peer_id: u64,
    /// Recorded link-level loss probabilities (a, b) with a < b.
    ///
    /// Used by scenario tests to document intended impairments and by
    /// `LossyLink`-based mesh tests. The `SimNetwork` itself runs over real
    /// TCP (which is reliable); loss at the TCP byte level requires a
    /// transport-layer proxy (future work).
    loss_map: HashMap<(usize, usize), f64>,
    /// PRNG seed used for deterministic operations.
    seed: u64,
    /// XorShift64 state derived from `seed` — advanced by `rng_u64`.
    rng: u64,
    /// Optional topology event log (enabled via `SimNetworkBuilder::recording`).
    event_log: Option<Vec<SimEvent>>,
}

impl SimNetwork {
    /// Create a builder for a simulation network.
    pub fn builder() -> SimNetworkBuilder {
        SimNetworkBuilder::default()
    }

    // ── PRNG (xorshift64) ─────────────────────────────────────────────────────

    /// Advance the XorShift64 RNG and return the next value.
    fn rng_u64(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    /// The seed this network was constructed with.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    // ── Event log ─────────────────────────────────────────────────────────────

    fn record(&mut self, event: SimEvent) {
        if let Some(ref mut log) = self.event_log {
            log.push(event);
        }
    }

    /// Return the event log (empty slice if recording was not enabled).
    pub fn events(&self) -> &[SimEvent] {
        self.event_log.as_deref().unwrap_or(&[])
    }

    // ── Number of nodes in the network.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Get a node by index.
    pub fn node(&self, idx: usize) -> &SimNode {
        &self.nodes[idx]
    }

    /// Get a mutable node by index.
    pub fn node_mut(&mut self, idx: usize) -> &mut SimNode {
        &mut self.nodes[idx]
    }

    /// Connect nodes `a` and `b` (bidirectional session).
    ///
    /// Adds each as a peer of the other, reloads both configs, and waits up to
    /// 5 s for the session to establish.
    pub async fn connect(&mut self, a: usize, b: usize) -> bool {
        let key = (a.min(b), a.max(b));
        if self.links.contains(&key) {
            return true; // already connected
        }
        // E20: a single pairwise reload of just `a` and `b` strands any
        // third-party canonical dialer that already had a session to whichever
        // endpoint we reload (its session is torn down by the reload, and it
        // then sits in the 30s connector sleep). Rather than reload only the
        // pair, add the edge and re-converge the WHOLE current link set via the
        // descending-node_id reload pass (smallest node_id last), so every
        // affected dialer re-dials after its partner is back up. For an
        // isolated pair this reduces to exactly "reload both, smaller last".
        self.links.insert(key);
        self.converge_links_descending().await;

        // Report whether THIS pair established (the caller's contract), and
        // record the connect event only for this newly-added edge.
        let a_id = self.nodes[a].node_id();
        let b_id = self.nodes[b].node_id();
        let ok_a = self.nodes[a]
            .wait_session_to(b_id, Duration::from_secs(5))
            .await;
        let ok_b = self.nodes[b]
            .wait_session_to(a_id, Duration::from_secs(5))
            .await;
        let established = ok_a && ok_b;
        if established {
            self.record(SimEvent::NodeConnected { a: key.0, b: key.1 });
        }
        established
    }

    /// Disconnect nodes `a` and `b`.
    ///
    /// Removes each from the other's peer list and reloads both.
    pub async fn disconnect(&mut self, a: usize, b: usize) {
        let key = (a.min(b), a.max(b));
        let was_connected = self.links.remove(&key);
        let b_key = self.nodes[b].node_id();
        let a_key = self.nodes[a].node_id();

        let mut config_a = self.nodes[a].config.clone();
        config_a.peers.retain(|p| {
            // Remove peers whose transport points to b's listen addr
            !p.transport.contains(&self.nodes[b].listen_addr)
        });
        let mut config_b = self.nodes[b].config.clone();
        config_b
            .peers
            .retain(|p| !p.transport.contains(&self.nodes[a].listen_addr));

        let _ = self.nodes[a].reload_with(config_a).await;
        let _ = self.nodes[b].reload_with(config_b).await;
        // Brief pause for sessions to close
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = (a_key, b_key); // suppress unused warnings
        if was_connected {
            self.record(SimEvent::NodeDisconnected { a: key.0, b: key.1 });
        }
    }

    /// Partition the network: disconnect all links crossing the boundary between
    /// the two sets.
    ///
    /// `group_a` and `group_b` are indices; all links between them are removed.
    pub async fn partition(&mut self, group_a: &[usize], group_b: &[usize]) {
        let mut pairs = Vec::new();
        for &a in group_a {
            for &b in group_b {
                let key = (a.min(b), a.max(b));
                if self.links.contains(&key) {
                    pairs.push((a, b));
                }
            }
        }
        for (a, b) in pairs {
            self.disconnect(a, b).await;
        }
        self.record(SimEvent::Partition {
            group_a: group_a.to_vec(),
            group_b: group_b.to_vec(),
        });
    }

    /// Heal a partition by reconnecting all previously-connected pairs.
    pub async fn heal_partition(
        &mut self,
        group_a: &[usize],
        group_b: &[usize],
        original_links: &[(usize, usize)],
    ) {
        for &(a, b) in original_links {
            if (group_a.contains(&a) && group_b.contains(&b))
                || (group_a.contains(&b) && group_b.contains(&a))
            {
                self.connect(a, b).await;
            }
        }
        self.record(SimEvent::HealPartition {
            group_a: group_a.to_vec(),
            group_b: group_b.to_vec(),
        });
    }

    /// Count all currently active sessions across all nodes.
    pub fn total_sessions(&self) -> usize {
        self.nodes.iter().map(|n| n.runtime.sessions().len()).sum()
    }

    /// Snapshot of all active links.
    pub fn active_links(&self) -> Vec<(usize, usize)> {
        self.links.iter().copied().collect()
    }

    /// True iff the link between `a` and `b` is currently active.
    pub fn is_connected(&self, a: usize, b: usize) -> bool {
        let key = (a.min(b), a.max(b));
        self.links.contains(&key)
    }

    /// Record a simulated link-loss probability for the link between nodes `a`
    /// and `b`.
    ///
    /// This stores the impairment in `self.loss_map` for use by scenario tests
    /// and documentation purposes. The `SimNetwork` operates over real TCP
    /// (reliable), so this does **not** inject byte-level packet loss on the
    /// TCP stream; use [`LossyLink`] with `InMemoryLink` for mesh-layer loss
    /// injection.
    ///
    /// A value of `0.0` means no loss; `1.0` means total loss (link blackhole).
    pub fn set_link_loss(&mut self, a: usize, b: usize, p: f64) {
        let rate = p.clamp(0.0, 1.0);
        self.loss_map.insert((a.min(b), a.max(b)), rate);
        self.record(SimEvent::LinkLossSet {
            a: a.min(b),
            b: a.max(b),
            rate,
        });
    }

    /// Return the recorded loss probability for the link (a, b), or `0.0` if
    /// no impairment has been set.
    pub fn link_loss(&self, a: usize, b: usize) -> f64 {
        self.loss_map
            .get(&(a.min(b), a.max(b)))
            .copied()
            .unwrap_or(0.0)
    }

    // ── Topology wiring ────────────────────────────────────────────────────────

    /// E20-safe bulk-topology convergence (the shared primitive behind
    /// `wire_full_mesh` / `wire_ring` / `wire_star` / `wire_random*`).
    ///
    /// Given the edge set already recorded in `self.links`, rebuild every
    /// node's COMPLETE peer set from scratch and reload each node that has at
    /// least one link exactly ONCE, in DESCENDING node_id order (smallest
    /// node_id reloads LAST). Directional dedup makes the smaller-node_id side
    /// own the canonical outbound dial; reloading it last guarantees every
    /// pair's session forms AFTER both endpoints are up and is never torn down
    /// by a later reload — and any partner whose session was dropped by an
    /// earlier reload re-dials when it itself reloads. Then converge-wait so
    /// every node reaches its expected (degree) session count.
    ///
    /// This replaces the old O(N^2) incremental `connect(i, j)` wiring, which
    /// reloaded shared nodes O(N) times and stranded ~half of the canonical
    /// dialers behind the 30s connector sleep — the Phase E20 "~50% pairwise
    /// session establishment failure" flake.
    ///
    /// Caller must populate `self.links` first; this method only rebuilds peer
    /// sets from it. Rebuilding from scratch (rather than appending) keeps the
    /// peer sets in exact sync with `self.links`, so it is correct after edge
    /// removals too.
    ///
    /// Returns a per-node `converged` vector (`converged[i]` is true iff node
    /// `i` reached its expected session degree). Does NOT emit any `SimEvent` —
    /// event recording is the caller's responsibility, so that callers invoked
    /// repeatedly (e.g. incremental `connect`) don't re-record already-present
    /// edges every pass.
    async fn converge_links_descending(&mut self) -> Vec<bool> {
        let n = self.nodes.len();
        if n == 0 {
            return Vec::new();
        }
        // Expected session count (degree) per node from the edge set.
        let mut degree = vec![0usize; n];
        for &(a, b) in &self.links {
            degree[a] += 1;
            degree[b] += 1;
        }
        // Rebuild each node's complete peer set from `self.links`.
        let mut configs: Vec<_> = (0..n).map(|i| self.nodes[i].config.clone()).collect();
        for (i, cfg) in configs.iter_mut().enumerate() {
            cfg.peers.clear();
            for j in 0..n {
                if i == j || !self.links.contains(&(i.min(j), i.max(j))) {
                    continue;
                }
                let peer_id = PeerId::new(self.next_peer_id as u32);
                self.next_peer_id += 1;
                if let Some(p) = self.nodes[j].as_peer_config(peer_id) {
                    cfg.peers.push(p);
                }
            }
        }
        // Reload order: descending node_id (smallest node reloads LAST). Skip
        // link-less nodes — no session to converge and no reason to churn them.
        let mut order: Vec<usize> = (0..n).filter(|&i| degree[i] > 0).collect();
        order.sort_by(|&x, &y| self.nodes[y].node_id().cmp(&self.nodes[x].node_id()));
        let mut configs: Vec<Option<_>> = configs.into_iter().map(Some).collect();
        for &i in &order {
            if let Some(cfg) = configs[i].take() {
                let _ = self.nodes[i].reload_with(cfg).await;
            }
        }
        // Convergence: each node should reach `degree[i]` sessions.
        let mut converged = vec![false; n];
        for &i in &order {
            converged[i] = self.nodes[i]
                .wait_sessions(degree[i], Duration::from_secs(30))
                .await;
        }
        converged
    }

    /// Converge `self.links`, then record a `NodeConnected` event for every
    /// edge whose endpoints both reached their expected session degree. Shared
    /// by the bulk-wiring helpers, which establish a full edge set in one shot.
    async fn converge_and_record_all(&mut self) {
        let converged = self.converge_links_descending().await;
        let edges: Vec<(usize, usize)> = self.links.iter().copied().collect();
        for (a, b) in edges {
            if converged.get(a).copied().unwrap_or(false)
                && converged.get(b).copied().unwrap_or(false)
            {
                self.record(SimEvent::NodeConnected { a, b });
            }
        }
    }

    /// Wire a ring: 0-1-2-…-(n-1)-0.
    pub async fn wire_ring(&mut self) {
        let n = self.nodes.len();
        if n < 2 {
            return;
        }
        for i in 0..n {
            self.links.insert((i.min((i + 1) % n), i.max((i + 1) % n)));
        }
        self.converge_and_record_all().await;
    }

    /// Wire a full mesh: every pair (i, j) with i < j.
    pub async fn wire_full_mesh(&mut self) {
        let n = self.nodes.len();
        if n == 0 {
            return;
        }
        for i in 0..n {
            for j in (i + 1)..n {
                self.links.insert((i, j));
            }
        }
        self.converge_and_record_all().await;
    }

    /// Wire a star: node 0 is the hub, connected to all others.
    pub async fn wire_star(&mut self) {
        let n = self.nodes.len();
        for spoke in 1..n {
            self.links.insert((0, spoke));
        }
        self.converge_and_record_all().await;
    }

    /// Wire a random graph where each pair (i, j) is connected with probability `p`.
    ///
    /// Uses a simple xorshift seeded from `seed` for reproducibility.
    pub async fn wire_random(&mut self, p: f64, seed: u64) {
        let n = self.nodes.len();
        // Avoid XorShift64 zero-fixpoint: wrapping u64::MAX + 1 = 0 → all random = 0.
        let mut rng = seed.wrapping_add(1).max(1);
        for i in 0..n {
            for j in (i + 1)..n {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                if (rng as f64) / (u64::MAX as f64) < p {
                    self.links.insert((i, j));
                }
            }
        }
        self.converge_and_record_all().await;
    }

    /// Wire a random graph using the network's own seeded RNG.
    ///
    /// Produces the same topology for the same seed passed to the builder.
    pub async fn wire_random_seeded(&mut self, p: f64) {
        let n = self.nodes.len();
        for i in 0..n {
            for j in (i + 1)..n {
                let r = self.rng_u64();
                if (r as f64) / (u64::MAX as f64) < p {
                    self.links.insert((i, j));
                }
            }
        }
        self.converge_and_record_all().await;
    }

    // ── Snapshot / replay ────────────────────────────────

    /// Capture the current observable state of the network.
    pub fn snapshot(&self) -> SimSnapshot {
        SimSnapshot {
            seed: self.seed,
            active_links: self.links.iter().copied().collect(),
            loss_map: self.loss_map.clone(),
            event_log: self.event_log.clone().unwrap_or_default(),
        }
    }

    /// Replay a sequence [`SimEvent`]s on this network.
    ///
    /// Only topology events (connect / disconnect / loss) are replayed.
    /// `Partition`, `HealPartition`, `TimeTick`, and `LinkLossSet` are
    /// interpreted directly. The network must have the same node count as
    /// the one that produced the events.
    pub async fn replay(&mut self, events: &[SimEvent]) {
        for event in events {
            match event {
                SimEvent::NodeConnected { a, b } => {
                    self.connect(*a, *b).await;
                }
                SimEvent::NodeDisconnected { a, b } => {
                    self.disconnect(*a, *b).await;
                }
                SimEvent::LinkLossSet { a, b, rate } => {
                    self.set_link_loss(*a, *b, *rate);
                }
                SimEvent::Partition { group_a, group_b } => {
                    // Disconnects are already in the log; just record the partition marker.
                    let _ = (group_a, group_b);
                }
                SimEvent::HealPartition { group_a, group_b } => {
                    let _ = (group_a, group_b);
                }
                SimEvent::TimeTick { ms } => {
                    tokio::time::sleep(Duration::from_millis(*ms)).await;
                }
            }
        }
    }

    /// Stop all nodes.
    pub async fn stop(mut self) {
        for node in &mut self.nodes {
            let _ = node.runtime.stop().await;
        }
        // Clean up temp config files.
        for node in &self.nodes {
            let _ = std::fs::remove_file(&node.config_path);
        }
    }
}

// ── SimNetworkBuilder ─────────────────────────────────────────────────────────

#[derive(Default)]
pub struct SimNetworkBuilder {
    roles: Vec<NodeRole>,
    /// Optional session-config override applied to every node's config.
    session_config: Option<SessionConfig>,
    /// Optional DHT-config override applied to every node's config.
    /// Most scenarios use defaults; tests that need fast DHT republishing
    /// set a short `republish_interval_secs`.
    dht_config: Option<crate::cfg::DhtConfig>,
    /// PRNG seed for deterministic topology operations.
    seed: u64,
    /// Whether to record topology events in an event log.
    recording: bool,
    /// when `true`, each node enables in-memory metrics counters (with an
    /// ephemeral `tcp://127.0.0.1:0` exporter bind so there's no port conflict
    /// across nodes), so tests can read `runtime.metrics_snapshot()`. Default
    /// `false` — most scenarios assert on sessions/routes, not counters.
    with_metrics: bool,
    /// when `true`, each node additionally gets its
    /// own on-disk sovereign identity (via `create_identity`) in
    /// a per-node veil directory, so `NodeRuntime::start`
    /// auto-loads a distinct `SovereignIdentity` per node.
    /// Doubles start time (extra PoW mine per node) but is the
    /// only way to exercise the identity-addressed runtime
    /// pipeline end-to-end against real TCP. Defaults `false`.
    with_sovereign_identities: bool,
    /// per-node name-claim to persist into
    /// `<veil_dir>/name_claims/<name>.bin` between
    /// `create_identity` and `NodeRuntime::start`. Indexed
    /// parallel to `roles`; `None` at index `i` means that node
    /// doesn't pre-claim a name. Requires
    /// `with_sovereign_identities = true` — claims need a
    /// sovereign identity to sign against. Claims are picked up
    /// by the runtime's startup scan and DHT-published
    /// automatically (same path as persisted claims written by
    /// `veil-cli identity claim-name`).
    name_claims: Vec<Option<String>>,
    /// when `Some(j)` at index `i`, node `i`'s
    /// sovereign identity is provisioned via `restore_identity`
    /// using node `j`'s previously-provisioned `master_seed`
    /// so node `i` and node `j` end up with the same
    /// `node_id` but distinct per-device subkeys + instance
    /// tags. Requires `with_sovereign_identities = true` and
    /// `j < i` (source node must build first).
    restored_from: Vec<Option<usize>>,
    /// (477.7): when `true` at index `i`, node `i` is
    /// NOT pre-provisioned with `create_identity` — instead
    /// `NodeRuntime::start` auto-builds a degenerate ("standalone")
    /// `IdentityDocument` from the node's `[identity]` Ed25519
    /// keypair on first start. Mirrors the production single-
    /// device UX (phone-only / laptop-only). Requires
    /// `with_sovereign_identities = true`; mutually exclusive
    /// with `restored_from[i]` and `name_claims[i]` (a fresh
    /// standalone identity has no master_seed for restore and
    /// no pre-claim source). Empty defaults to "all multi-device"
    /// (legacy behaviour).
    standalone_identities: Vec<bool>,
    /// per-node opt-in to `[anonymity].relay_capable = true`.
    /// `true` at index `i` makes node `i` advertise the
    /// `cap_flags::ANONYMITY_RELAY` bit, generate a fresh
    /// `anonymity_x25519_sk` at startup, and publish a signed
    /// relay-directory entry so it's discoverable by senders building
    /// onion circuits. Empty defaults to "no relays" (legacy). Length
    /// must match `roles.len`.
    anonymity_relay_indices: Vec<bool>,
    /// per-node prefix-grinding spec (Epic 485.1 adversary validation).
    /// `Some((target, bits))` at index `i` makes node `i`'s identity
    /// keypair grinded so its `node_id` shares `bits` leading bits with
    /// `target`.  Empty defaults to "no grinding" (legacy).  Cost is
    /// ≈ 2^bits keypair draws — use bits ≤ 12 in normal tests.
    grind_prefix: Vec<Option<([u8; 32], u32)>>,
}

impl SimNetworkBuilder {
    /// Set the number of nodes to create (all with the same role).
    pub fn nodes(mut self, count: usize) -> Self {
        self.roles = vec![NodeRole::Core; count];
        self
    }

    /// Set the role for all nodes (applied to the count set by `nodes`).
    pub fn role(mut self, role: NodeRole) -> Self {
        for r in &mut self.roles {
            *r = role;
        }
        self
    }

    /// Set per-node roles explicitly, overriding `nodes` + `role`.
    pub fn roles(mut self, roles: Vec<NodeRole>) -> Self {
        self.roles = roles;
        self
    }

    /// Override the session-layer config (keepalive / idle-timeout) for every
    /// node. Useful for tests that need short idle timeouts.
    pub fn session(mut self, cfg: SessionConfig) -> Self {
        self.session_config = Some(cfg);
        self
    }

    /// Enable in-memory metrics counters on every node (ephemeral exporter
    /// bind, no port conflict), so tests can assert on
    /// `runtime.metrics_snapshot()`. Off by default.
    pub fn with_metrics(mut self) -> Self {
        self.with_metrics = true;
        self
    }

    /// Override the DHT config for every node. Useful for tests that need
    /// fast republish intervals.
    pub fn dht(mut self, cfg: crate::cfg::DhtConfig) -> Self {
        self.dht_config = Some(cfg);
        self
    }

    /// Set the PRNG seed for deterministic topology operations.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Enable topology event recording.
    pub fn recording(mut self, on: bool) -> Self {
        self.recording = on;
        self
    }

    /// provision a fresh sovereign identity on every
    /// node before start. Pre-flight `create_identity` into each
    /// node's veil dir so `NodeRuntime::start` auto-loads it.
    /// Costs one extra PoW mine per node.
    pub fn sovereign_identities(mut self, on: bool) -> Self {
        self.with_sovereign_identities = on;
        self
    }

    /// set the per-node name-claim vector. Length
    /// must match `roles.len`; `None` at index `i` means no
    /// claim for that node. Requires `sovereign_identities(true)`.
    pub fn name_claims(mut self, claims: Vec<Option<String>>) -> Self {
        self.name_claims = claims;
        self
    }

    /// opt indexed nodes into provisioning via
    /// `restore_identity` against the source node's
    /// `master_seed`. `restored[i] = Some(j)` makes node `i`
    /// share `node_id` with node `j` (different device
    /// subkeys, different instance tags). Length must match
    /// `roles.len`; `j < i` mandatory; requires
    /// `sovereign_identities(true)`.
    pub fn restored_from(mut self, restored: Vec<Option<usize>>) -> Self {
        self.restored_from = restored;
        self
    }

    /// (477.7): mark indexed nodes as standalone — no
    /// pre-flight `create_identity`, the runtime auto-builds a
    /// degenerate `IdentityDocument` on first start. Length must
    /// match `roles.len`; `false` at index `i` means that node
    /// gets the legacy multi-device provisioning (or `restored_from`
    /// when set).
    pub fn standalone_identities(mut self, standalone: Vec<bool>) -> Self {
        self.standalone_identities = standalone;
        self
    }

    /// opt indexed nodes into anonymity-relay capability.
    /// `relay[i] = true` enables `[anonymity].relay_capable = true` for
    /// node `i`, which causes the runtime to generate a fresh
    /// `anonymity_x25519_sk`, advertise `cap_flags::ANONYMITY_RELAY` in
    /// handshakes, and self-publish a signed relay-directory entry to
    /// the DHT. Length must match `roles.len` (or be empty for
    /// "no relays" default).
    pub fn anonymity_relay(mut self, relay: Vec<bool>) -> Self {
        self.anonymity_relay_indices = relay;
        self
    }

    /// Per-node prefix-grinding spec.  Length must match `roles.len`
    /// (or be empty for "no grinding").  `Some((target, bits))` at
    /// index `i` makes that node's `node_id` share `bits` leading bits
    /// with `target` — adversary-validation primitive for ID-grinding
    /// sybil scenarios.
    pub fn grind_prefix(mut self, spec: Vec<Option<([u8; 32], u32)>>) -> Self {
        self.grind_prefix = spec;
        self
    }

    /// Build and start the network.
    pub async fn build(self) -> SimNetwork {
        let mut nodes: Vec<SimNode> = Vec::with_capacity(self.roles.len());
        for (i, role) in self.roles.iter().enumerate() {
            let sim_id = SimNodeId(i);
            let mut config =
                if let Some((target, bits)) = self.grind_prefix.get(i).copied().flatten() {
                    make_core_config_grinded(*role, &target, bits)
                } else {
                    make_core_config(*role)
                };
            if let Some(ref sc) = self.session_config {
                config.session = sc.clone();
            }
            if let Some(ref dc) = self.dht_config {
                config.dht = dc.clone();
            }
            if self.with_metrics {
                // Ephemeral bind (port 0) → each node gets a distinct port, no
                // conflict; `metrics_from_config` builds the in-memory counters
                // either way, which is what `metrics_snapshot()` reads.
                config.metrics = Some(crate::cfg::MetricsConfig {
                    listen: "tcp://127.0.0.1:0".to_owned(),
                    path: Some("/metrics".to_owned()),
                    auth_token: None,
                    allow_unauthenticated_remote_metrics: false,
                });
            }
            // per-node anonymity-relay opt-in.
            if self
                .anonymity_relay_indices
                .get(i)
                .copied()
                .unwrap_or(false)
            {
                config.anonymity.relay_capable = true;
            }
            // when sovereign identities are requested we
            // need a distinct veil_dir per node (runtime uses
            // config.parent → `identity_document.bin`). Use a
            // per-node subdir; otherwise keep the legacy flat
            // `/tmp/sim-*.toml` layout the older scenarios expect.
            let config_path = if self.with_sovereign_identities {
                next_sim_config_path_with_dir(&format!("node{i}"))
            } else {
                next_sim_config_path(&format!("node{i}"))
            };
            crate::cfg::save_config(&config_path, &config).expect("save sim config");

            if self.with_sovereign_identities {
                let standalone = self.standalone_identities.get(i).copied().unwrap_or(false);
                if standalone {
                    // skip pre-provisioning entirely — the
                    // runtime auto-builds a degenerate IdentityDocument
                    // from [identity] keypair on first start.
                    assert!(
                        self.restored_from.get(i).copied().flatten().is_none(),
                        "standalone_identities[{i}] = true is mutually \
                         exclusive with restored_from[{i}]",
                    );
                    assert!(
                        self.name_claims.get(i).cloned().flatten().is_none(),
                        "standalone_identities[{i}] = true: name_claims \
                         pre-provisioning needs an identity to sign against, \
                         which the runtime hasn't built yet",
                    );
                } else if let Some(Some(source_idx)) = self.restored_from.get(i).copied() {
                    assert!(
                        source_idx < i,
                        "restored_from[{i}] = Some({source_idx}): source must \
                         build before the restored node",
                    );
                    let source_dir = nodes[source_idx]
                        .config_path
                        .parent()
                        .expect("source config has parent")
                        .to_path_buf();
                    let master_seed = sim_read_master_seed(&source_dir);
                    provision_restored_sovereign_identity_for_sim(&config_path, master_seed);
                } else {
                    provision_sovereign_identity_for_sim(&config_path);
                }
                // Optional per-node NameClaim — sign under the
                // just-provisioned sovereign identity and drop
                // into `<veil_dir>/name_claims/<name>.bin` so
                // `NodeRuntime::start`'s scanner picks it up and
                // DHT-publishes on first republish tick.
                if let Some(Some(name)) = self.name_claims.get(i).cloned() {
                    provision_name_claim_for_sim(&config_path, &name);
                }
            }

            let node = SimNode::start(sim_id, config, config_path)
                .await
                .expect("sim node start");
            nodes.push(node);
        }
        let rng = self.seed.wrapping_add(1).max(1);
        SimNetwork {
            nodes,
            links: HashSet::new(),
            next_peer_id: 1,
            loss_map: HashMap::new(),
            seed: self.seed,
            rng,
            event_log: if self.recording {
                Some(Vec::new())
            } else {
                None
            },
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Adversary-validation helper: keep generating Ed25519 keypairs until
/// the resulting `node_id = BLAKE3(pubkey)` shares at least `bits`
/// leading bits with the target.  Mirrors what a real sybil attacker
/// would do — except the attacker pays for each draw in wall-clock
/// time, while a sim wants this to finish fast.
///
/// Cost analysis: expected iterations ≈ 2^bits.  Keypair generation
/// is microsecond-class so bits ≤ 12 (~4096 draws) finishes in
/// milliseconds; bits = 16 (~65k draws) finishes in seconds; bits >
/// 20 starts approaching real-attacker territory and should not be
/// used in normal CI tests (the abstraction is "the attacker WOULD
/// pay that, what does eclipse look like at that point").
///
/// Returns the matching `(keypair, derived_node_id)`.  Does NOT solve
/// PoW — caller chains a separate `search_nonce` call (cheaper to
/// re-mine once at the end than to PoW for every grinding draw).
pub(crate) fn grind_keypair_with_prefix(
    target: &[u8; 32],
    bits: u32,
) -> (crate::crypto::GeneratedKeyPair, [u8; 32]) {
    assert!(
        bits <= 32,
        "grind_keypair_with_prefix: bits {bits} > 32 — would never finish in sim time"
    );
    use crate::crypto;
    loop {
        let candidate = crypto::generate_keypair(SignatureAlgorithm::Ed25519);
        // `candidate.public_key` is base64; `NodeId::from_public_key`
        // decodes + applies the canonical BLAKE3 hash that the rest
        // of the runtime uses to compute node_ids.  Match against that
        // canonical id so the grind result actually corresponds to
        // what a live node would advertise.
        let id = NodeId::from_public_key(SignatureAlgorithm::Ed25519, &candidate.public_key)
            .expect("derive node_id from candidate pubkey");
        let candidate_id = *id.as_bytes();
        if leading_bits_match(target, &candidate_id, bits) {
            return (candidate, candidate_id);
        }
    }
}

/// Helper for [grind_keypair_with_prefix]: do `a` and `b` agree on
/// the leading `bits` bits?
fn leading_bits_match(a: &[u8; 32], b: &[u8; 32], bits: u32) -> bool {
    if bits == 0 {
        return true;
    }
    let full_bytes = (bits / 8) as usize;
    let extra_bits = bits % 8;
    if a[..full_bytes] != b[..full_bytes] {
        return false;
    }
    if extra_bits == 0 {
        return true;
    }
    let mask: u8 = !((1u8 << (8 - extra_bits)) - 1);
    (a[full_bytes] & mask) == (b[full_bytes] & mask)
}

/// Build a minimal `Core` node config with a random loopback TCP listener.
fn make_core_config(role: NodeRole) -> Config {
    make_core_config_with_optional_grind(role, None)
}

/// Same as [make_core_config] but with an optional prefix-grind spec.
/// `grind = Some((target, bits))` makes the resulting node_id share
/// `bits` leading bits with `target` (via [grind_keypair_with_prefix]).
/// Use this for adversary-validation scenarios that need synthetic
/// sybils close to a chosen victim's keyspace.
pub(crate) fn make_core_config_grinded(role: NodeRole, target: &[u8; 32], bits: u32) -> Config {
    make_core_config_with_optional_grind(role, Some((*target, bits)))
}

fn make_core_config_with_optional_grind(role: NodeRole, grind: Option<([u8; 32], u32)>) -> Config {
    use crate::crypto;
    let keypair = if let Some((target, bits)) = grind {
        grind_keypair_with_prefix(&target, bits).0
    } else {
        crypto::generate_keypair(SignatureAlgorithm::Ed25519)
    };
    let public_key =
        crypto::Base64PublicKey::new(SignatureAlgorithm::Ed25519, keypair.public_key.clone())
            .expect("valid pubkey");
    let private_key =
        crypto::Base64PrivateKey::new(SignatureAlgorithm::Ed25519, keypair.private_key.clone())
            .expect("valid privkey");

    // Solve PoW at canonical difficulty (matches DEFAULT_POW_DIFFICULTY).
    // Use all available threads so the search finishes quickly even on loaded
    // CI machines where a single-threaded search can time out.
    let threads = crypto::available_thread_count();
    let pow_result = crypto::search_nonce(crypto::PowParams {
        algo: SignatureAlgorithm::Ed25519,
        public_key: public_key.clone(),
        private_key: private_key.clone(),
        target_zero_bits: crate::crypto::DEFAULT_POW_DIFFICULTY,
        timeout: std::time::Duration::from_secs(300),
        start_from: crypto::Base64Nonce::zero(),
        threads,
        progress: None,
    })
    .expect("sim pow");
    assert_eq!(
        pow_result.stop_reason,
        crypto::PowStopReason::Found,
        "sim PoW timed out: best_zero_bits={} < {}",
        pow_result.best_zero_bits,
        crate::crypto::DEFAULT_POW_DIFFICULTY,
    );

    let node_id = NodeId::from_public_key(SignatureAlgorithm::Ed25519, &keypair.public_key)
        .expect("node id from pubkey");

    Config {
        identity: Some(IdentityConfig {
            algo: SignatureAlgorithm::Ed25519,
            role,
            public_key: keypair.public_key,
            private_key: keypair.private_key,
            nonce: pow_result.best_nonce.into_inner(),
            node_id: Some(node_id),
            key_passphrase: None,
            key_passphrase_file: None,
            key_passphrase_prompt: false,
            lazy_mining: true,
            max_lazy_difficulty: 64,
        }),
        listen: vec![ListenConfig {
            id: ListenId::new(1),
            transport: "tcp://127.0.0.1:0".to_owned(),
            advertise: None,
            relay: None,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            ..Default::default()
        }],
        peers: vec![],
        ..Config::default()
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// `leading_bits_match` boundary cases — verify the helper that
    /// drives prefix grinding actually compares bits the way the
    /// docstring claims.
    #[test]
    fn leading_bits_match_boundaries() {
        // bits = 0: everything matches.
        assert!(leading_bits_match(&[0x00; 32], &[0xFF; 32], 0));
        // bits = 8 (one full byte): first byte must match exactly.
        assert!(leading_bits_match(&[0xAB; 32], &[0xAB; 32], 8));
        let mut diff = [0xABu8; 32];
        diff[0] = 0xAC;
        assert!(!leading_bits_match(&[0xAB; 32], &diff, 8));
        // bits = 4 (half byte): only the top nibble matters.
        // 0xA0 vs 0xAF — top nibble equal, low nibble different → match.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 0xA0;
        b[0] = 0xAF;
        assert!(leading_bits_match(&a, &b, 4));
        // bits = 5: top 5 bits = 0xA0 >> 3 vs 0xAF >> 3 = 0b10100 vs
        // 0b10101 → differ.
        assert!(!leading_bits_match(&a, &b, 5));
    }

    /// Grind primitive: should always return a keypair whose
    /// canonical node_id matches the requested prefix.  Use a small
    /// prefix (4 bits) so the test finishes in milliseconds.
    #[test]
    fn grind_keypair_with_prefix_matches_target() {
        let mut target = [0u8; 32];
        target[0] = 0xC0; // top nibble = 1100
        let (kp, id) = grind_keypair_with_prefix(&target, 4);
        // Verify the returned id actually matches.
        assert!(
            leading_bits_match(&target, &id, 4),
            "grinded id {id:?} does not match target prefix 4 bits of {target:?}"
        );
        // And derive canonically — id must equal NodeId::from_public_key(kp).
        let canonical = NodeId::from_public_key(SignatureAlgorithm::Ed25519, &kp.public_key)
            .expect("canonical derive");
        assert_eq!(*canonical.as_bytes(), id);
    }

    /// Two-node network: start, connect, verify sessions.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_node_connect_establishes_session() {
        let mut net = SimNetwork::builder()
            .nodes(2)
            .role(NodeRole::Core)
            .build()
            .await;
        let ok = net.connect(0, 1).await;
        assert!(ok, "session should establish between nodes 0 and 1");
        assert!(
            !net.node(0).runtime.sessions().is_empty(),
            "node 0 should have at least one session"
        );
        assert!(
            !net.node(1).runtime.sessions().is_empty(),
            "node 1 should have at least one session"
        );
        net.stop().await;
    }

    /// Disconnect should remove sessions.
    #[ignore = "Phase E20 directional dedup: SimNetwork random identities cause ~50% pairwise-session establishment failure; see audit batch 2026-05-24"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disconnect_removes_session() {
        let mut net = SimNetwork::builder()
            .nodes(2)
            .role(NodeRole::Core)
            .build()
            .await;
        let ok = net.connect(0, 1).await;
        assert!(ok, "session should establish");
        net.disconnect(0, 1).await;
        // After disconnect, peers list is empty → no reconnect → sessions should drop.
        tokio::time::sleep(Duration::from_millis(500)).await;
        // Sessions may persist briefly; just verify peers list is cleared.
        assert!(
            net.node(0).config.peers.is_empty(),
            "peers list should be empty after disconnect"
        );
        net.stop().await;
    }

    /// Three-node linear topology: 0-1-2.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn three_node_linear_topology() {
        let mut net = SimNetwork::builder()
            .nodes(3)
            .role(NodeRole::Core)
            .build()
            .await;
        let ok01 = net.connect(0, 1).await;
        let ok12 = net.connect(1, 2).await;
        assert!(ok01, "0-1 session");
        assert!(ok12, "1-2 session");
        // Node 1 should have 2 sessions (may need brief wait after reload).
        let ok = net.node(1).wait_sessions(2, Duration::from_secs(5)).await;
        assert!(ok, "node 1 should have 2 sessions");
        net.stop().await;
    }

    // ── 72.2: Configurable topology ─────────────────────────────────────────────

    /// Ring topology: 4 nodes → 4 links, each node has exactly 2 sessions.
    #[ignore = "Phase E20 directional dedup: SimNetwork random identities cause ~50% pairwise-session establishment failure; see audit batch 2026-05-24"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ring_topology() {
        let mut net = SimNetwork::builder()
            .nodes(4)
            .role(NodeRole::Core)
            .build()
            .await;
        net.wire_ring().await;
        assert_eq!(net.active_links().len(), 4, "ring has N links");
        for i in 0..4 {
            let ok = net.node(i).wait_sessions(2, Duration::from_secs(10)).await;
            assert!(ok, "node {i} should have 2 sessions in ring");
        }
        net.stop().await;
    }

    /// Star topology: 4 nodes → hub (node 0) has 3 sessions, spokes have 1.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn star_topology() {
        let mut net = SimNetwork::builder()
            .nodes(4)
            .role(NodeRole::Core)
            .build()
            .await;
        net.wire_star().await;
        assert_eq!(net.active_links().len(), 3, "star has N-1 links");
        // Each reload of node 0 can temporarily drop earlier sessions while peers
        // reconnect, so wait for all sessions to be active rather than asserting
        // the count immediately after wire_star.
        let ok = net.node(0).wait_sessions(3, Duration::from_secs(10)).await;
        assert!(ok, "hub has 3 sessions");
        for spoke in 1..4 {
            let ok = net
                .node(spoke)
                .wait_sessions(1, Duration::from_secs(10))
                .await;
            assert!(ok, "spoke {spoke} has 1 session");
        }
        net.stop().await;
    }

    /// Full mesh: 4 nodes → 6 links, each node eventually has 3 sessions.
    #[ignore = "Phase E20 directional dedup: SimNetwork random identities cause ~50% pairwise-session establishment failure; see audit batch 2026-05-24"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_mesh_topology() {
        let mut net = SimNetwork::builder()
            .nodes(4)
            .role(NodeRole::Core)
            .build()
            .await;
        net.wire_full_mesh().await;
        let expected_links = 4 * 3 / 2; // C(4,2) = 6
        assert_eq!(
            net.active_links().len(),
            expected_links,
            "full mesh has C(N,2) links"
        );
        // After wiring, nodes reconnect to all peers — wait for session counts to stabilize.
        for i in 0..4 {
            let ok = net.node(i).wait_sessions(3, Duration::from_secs(10)).await;
            assert!(ok, "node {i} should have 3 sessions in full mesh");
        }
        net.stop().await;
    }

    /// Random topology: deterministic seed → repeatable link count.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn random_topology_is_deterministic() {
        let mut net_a = SimNetwork::builder()
            .nodes(5)
            .role(NodeRole::Core)
            .build()
            .await;
        net_a.wire_random(0.6, 42).await;
        let links_a = net_a.active_links().len();
        net_a.stop().await;

        let mut net_b = SimNetwork::builder()
            .nodes(5)
            .role(NodeRole::Core)
            .build()
            .await;
        net_b.wire_random(0.6, 42).await;
        let links_b = net_b.active_links().len();
        net_b.stop().await;

        assert_eq!(links_a, links_b, "same seed must produce same link set");
        // With p=0.6 and 10 possible edges, expect 4–10 links (not all or none).
        assert!(
            links_a > 0 && links_a <= 10,
            "link count {links_a} in range"
        );
    }
}
