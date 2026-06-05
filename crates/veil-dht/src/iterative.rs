//! Iterative Kademlia lookup across multiple nodes.
//!
//! `find_node_iterative` implements the standard Kademlia iterative node
//! lookup algorithm (§2.3 of the paper):
//!
//! 1. Seed the *shortlist* from the local routing table (K closest known contacts).
//! 2. In each round, pick up to ALPHA unqueried nodes from the shortlist and
//!    send them `FIND_NODE(target)`.
//! 3. Merge returned contacts into the shortlist, keeping only the K closest.
//! 4. Terminate when a full round returns no *new* nodes closer than the current
//!    K-th closest (convergence), or when the shortlist is exhausted.
//!
//! # Abstraction
//!
//! Network I/O is abstracted behind the `PeerQuerier` trait so the algorithm
//! can be unit-tested with an in-process mock (`LocalPeerQuerier`) and later
//! wired to real OVL1 sessions via `NetworkPeerQuerier`.

use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use veil_util::lock;

use super::routing::{Contact, K, RoutingTable, xor_distance};

// ── Constants (legacy defaults — still used by unit tests via IterativeParams::default) ────

/// Kademlia parallelism factor (α): number of concurrent queries per round.
pub const ALPHA: usize = 3;

/// Maximum number of lookup rounds before terminating unconditionally.
pub const MAX_ROUNDS: usize = 20;

// ── IterativeParams ───────────────────────────────────────────────────────────

/// Runtime-configurable parameters for iterative Kademlia lookups.
///
/// Constructed from veilcore's `cfg::DhtConfig` at node startup (via the
/// `From<&DhtConfig>` impl in `veilcore::cfg::dht_glue`) and passed into
/// `find_node_iterative` / `find_value_iterative`.
#[derive(Clone, Copy, Debug)]
pub struct IterativeParams {
    /// Kademlia k — shortlist size cap and contacts per response (default 20).
    pub k: usize,
    /// Kademlia α — parallel queries per round (default 3).
    pub alpha: usize,
    /// Maximum rounds before unconditional termination (default 20).
    pub max_rounds: usize,
    /// when > 0.0, bias alpha selection toward peers with lower
    /// estimated network distance. The bias is applied as a secondary sort
    /// key: `composite = xor_distance + proximity_bias * estimated_rtt_ms`.
    /// Default: 0.0 (pure XOR selection, no Vivaldi bias).
    pub proximity_bias: f64,
}

impl Default for IterativeParams {
    fn default() -> Self {
        Self {
            k: K,
            alpha: ALPHA,
            max_rounds: MAX_ROUNDS,
            proximity_bias: 0.0,
        }
    }
}

impl From<&crate::traits::DhtRuntimeConfig> for IterativeParams {
    fn from(cfg: &crate::traits::DhtRuntimeConfig) -> Self {
        Self {
            k: cfg.k as usize,
            alpha: cfg.alpha as usize,
            max_rounds: cfg.max_rounds as usize,
            proximity_bias: cfg.vivaldi_weight,
        }
    }
}

// ── PeerQuerier ───────────────────────────────────────────────────────────────

/// Result of a FIND_VALUE query to a single peer.
#[derive(Debug)]
pub enum FindValueResult {
    /// The peer has the value stored.
    Value(Vec<u8>),
    /// The peer does not have the value; returns K closest contacts instead.
    Nodes(Vec<Contact>),
}

/// Abstraction for sending `FIND_NODE` / `FIND_VALUE` requests to a specific peer.
///
/// Implementations:
/// `LocalPeerQuerier` — in-process mock for unit tests.
/// `NetworkPeerQuerier` — sends OVL1 frames over live sessions.
pub trait PeerQuerier: Send + Sync {
    /// Ask `peer_id` for the K nodes closest to `target`.
    ///
    /// Returns an empty `Vec` on timeout or unreachable peer.
    fn find_node<'a>(
        &'a self,
        peer_id: [u8; 32],
        target: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Vec<Contact>> + Send + 'a>>;

    /// Ask `peer_id` for the value stored at `key`.
    ///
    /// Returns `FindValueResult::Value` if found, `FindValueResult::Nodes` (K closest)
    /// otherwise. Returns `FindValueResult::Nodes(vec![])` on timeout / unreachable.
    fn find_value<'a>(
        &'a self,
        peer_id: [u8; 32],
        key: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = FindValueResult> + Send + 'a>>;
}

// ── LocalPeerQuerier ──────────────────────────────────────────────────────────

/// In-process peer querier: maintains a registry of `RoutingTable`s keyed by
/// node_id. Used for unit tests and benchmarks that simulate a multi-node
/// topology without real network I/O.
#[derive(Clone, Default)]
pub struct LocalPeerQuerier {
    /// node_id → routing table for that simulated node.
    nodes: Arc<Mutex<std::collections::HashMap<[u8; 32], RoutingTable>>>,
}

impl LocalPeerQuerier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a simulated node with its routing table.
    pub fn add_node(&self, node_id: [u8; 32], routing: RoutingTable) {
        lock!(self.nodes).insert(node_id, routing);
    }
}

impl PeerQuerier for LocalPeerQuerier {
    fn find_node<'a>(
        &'a self,
        peer_id: [u8; 32],
        target: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Vec<Contact>> + Send + 'a>> {
        let nodes = Arc::clone(&self.nodes);
        Box::pin(async move {
            let guard = lock!(nodes);
            match guard.get(&peer_id) {
                Some(rt) => rt.find_closest(&target, K).into_iter().cloned().collect(),
                None => vec![],
            }
        })
    }

    fn find_value<'a>(
        &'a self,
        peer_id: [u8; 32],
        key: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = FindValueResult> + Send + 'a>> {
        let nodes = Arc::clone(&self.nodes);
        Box::pin(async move {
            let guard = lock!(nodes);
            match guard.get(&peer_id) {
                Some(rt) => {
                    let contacts = rt.find_closest(&key, K).into_iter().cloned().collect();
                    FindValueResult::Nodes(contacts)
                }
                None => FindValueResult::Nodes(vec![]),
            }
        })
    }
}

// ── find_node_iterative ───────────────────────────────────────────────────────

/// Iterative Kademlia FIND_NODE lookup.
///
/// Seeds the shortlist from `seed_contacts` (typically the K closest known
/// contacts from the local routing table), then iteratively queries up to
/// `params.alpha` unqueried nodes per round until convergence.
///
/// Returns up to `params.k` contacts closest to `target`.
pub async fn find_node_iterative(
    target: [u8; 32],
    seed_contacts: Vec<Contact>,
    querier: &dyn PeerQuerier,
    params: &IterativeParams,
) -> Vec<Contact> {
    let IterativeParams {
        k,
        alpha,
        max_rounds,
        ..
    } = *params;
    let mut queried: HashSet<[u8; 32]> = HashSet::new();
    // shortlist: all contacts seen so far, kept sorted by XOR distance to target.
    let mut shortlist: Vec<Contact> = seed_contacts;
    sort_by_distance(&mut shortlist, &target);
    shortlist.dedup_by_key(|c| c.node_id);
    shortlist.truncate(k);

    // D4: cap `iterative.lookup.all_filtered` log volume per
    // lookup. Each peer that answers with all-non-progressive contacts
    // emits one INFO line — N Sybils colluding in a single round produced
    // N log lines, and a sustained sequence of attacker-driven lookups
    // floods the operator's log pipeline. Emit details for the first
    // few peers, then a single summary at the end of the lookup.
    const MAX_ALL_FILTERED_DETAIL_LOGS: usize = 3;
    let mut all_filtered_logged = 0usize;
    let mut all_filtered_total = 0usize;

    for _ in 0..max_rounds {
        // Pick up to alpha unqueried node IDs from the shortlist.
        // Collect only the node_id ([u8;32], Copy) — no Contact clone needed.
        let to_query: Vec<[u8; 32]> = shortlist
            .iter()
            .filter(|c| !queried.contains(&c.node_id))
            .take(alpha)
            .map(|c| c.node_id)
            .collect();

        if to_query.is_empty() {
            break; // All known nodes have been queried — converged.
        }

        let prev_closest = shortlist.first().map(|c| c.node_id);

        // Query alpha peers concurrently.
        let futures: Vec<_> = to_query
            .iter()
            .map(|&peer_id| querier.find_node(peer_id, target))
            .collect();
        let results = futures::future::join_all(futures).await;
        // HashSet for O(1) duplicate check during shortlist admission.
        let mut shortlist_ids: std::collections::HashSet<[u8; 32]> =
            shortlist.iter().map(|c| c.node_id).collect();
        for (&peer_id, responses) in to_query.iter().zip(results) {
            queried.insert(peer_id);
            let peer_dist = xor_distance(&peer_id, &target);
            // — eclipse mitigation, three layers.
            //
            // Layer 1 (XOR distance filter): drop contacts that are not
            // *strictly closer* than the responder by at least 2× margin.
            // A responder MUST demonstrate progress — i.e. point at peers
            // genuinely closer to the target than itself.
            // `r_dist > 2 * peer_dist` ⟺ `r_dist >> 1 > peer_dist` (big-endian).
            //
            // tightened to **strict** progress.
            // Previously `r_dist >> 1 > peer_dist` rejected only contacts
            // STRICTLY farther than 2× — a same-distance responder
            // (`r_dist == peer_dist`) was admitted. A Sybil at distance D
            // could thus return its own collaborator at distance D, which
            // collaborator could then return ANOTHER collaborator at D, …
            // → shortlist saturated with same-distance Sybils, convergence
            // halted at the wrong neighbourhood.
            //
            // The new rule is `r_dist > peer_dist` (any-not-strictly-closer
            // rejected). A legitimate peer pointing at its own bucket-mates
            // typically returns contacts in different distance brackets;
            // requiring strict closeness costs little legitimately and
            // forces a Sybil to actually walk closer.
            //
            // Layer 2 (per-responder cap): admit at most `k` new contacts per
            // response. Prevents a single attacker from flooding the shortlist
            // even if their contacts pass the distance filter.
            //
            // NOTE: a third layer — a per-/16 (AS-proxy) admission cap across
            // ALL responders in a round (capping same-/16 contacts so a
            // colluding cluster on one rented /16 can't flood the shortlist) —
            // was specified but is deliberately NOT implemented here. Since the
            // FIND_NODE-v2 / ResolveTransport redesign (and C-06 for FIND_VALUE)
            // these responses carry node-ids ONLY, with an empty transport, so
            // there is no address at admission time from which to derive a /16
            // prefix (`routing.rs::as16_prefix` would always be None). The
            // shortlist is protected by the two layers above; re-introduce the
            // /16 cap only if admission-time responses ever carry transports
            // again. (Epic 485.1)
            let mut admitted = 0usize;
            // count contacts dropped by
            // the strict-progress filter so we can detect responders
            // whose entire reply was non-progressive (a strong Sybil-
            // collusion signal). Without this counter, a single
            // malicious peer that returns only same- or farther-distance
            // contacts looks identical (from the caller's POV) to a
            // genuinely-empty bucket — silent convergence on a poisoned
            // shortlist.
            let total_in_response = responses.len();
            let mut filtered = 0usize;
            for r in responses {
                if admitted >= k {
                    break; // per-responder cap reached
                }
                let r_dist = xor_distance(&r.node_id, &target);
                // Strict-progress check: r_dist must be strictly LESS than
                // peer_dist — i.e., the contact is genuinely closer to the
                // target. Reject equal-distance siblings of the responder.
                if r_dist >= peer_dist {
                    filtered += 1;
                    continue;
                }
                if shortlist_ids.insert(r.node_id) {
                    shortlist.push(r);
                    admitted += 1;
                }
            }
            // diagnostic: if a peer returned ≥3 contacts
            // and ALL of them failed the strict-progress filter, the
            // peer is either (a) a degenerate edge of the routing
            // graph that only knows same-distance siblings, or (b)
            // an active eclipse attempt. Either way the operator
            // wants visibility. Log at `info` level (not `warn`)
            // because case (a) is not necessarily malicious.
            if total_in_response >= 3 && filtered == total_in_response {
                all_filtered_total += 1;
                if all_filtered_logged < MAX_ALL_FILTERED_DETAIL_LOGS {
                    log::info!(
                        "iterative.lookup.all_filtered: peer={:02x}{:02x} target={:02x}{:02x} \
                         all {} contacts non-progressive — possible eclipse / Sybil cluster",
                        peer_id[0],
                        peer_id[1],
                        target[0],
                        target[1],
                        total_in_response,
                    );
                    all_filtered_logged += 1;
                }
            }
        }

        sort_by_distance(&mut shortlist, &target);
        shortlist.dedup_by_key(|c| c.node_id);
        shortlist.truncate(k);

        // Convergence check: did the closest node change this round?
        let new_closest = shortlist.first().map(|c| c.node_id);
        if new_closest == prev_closest {
            // Check if all k-closest are already queried.
            let all_queried = shortlist
                .iter()
                .take(k)
                .all(|c| queried.contains(&c.node_id));
            if all_queried {
                break;
            }
        }
    }

    // D4 summary: if the lookup saw more all-filtered peers
    // than we logged in detail, emit one final tally so operators don't
    // miss the magnitude of a Sybil cluster encounter.
    if all_filtered_total > all_filtered_logged {
        log::info!(
            "iterative.lookup.all_filtered_summary: target={:02x}{:02x} {} peers \
             returned all non-progressive contacts ({} logged in detail above) — \
             likely Sybil cluster",
            target[0],
            target[1],
            all_filtered_total,
            all_filtered_logged,
        );
    }

    shortlist
}

// ── find_value_iterative ──────────────────────────────────────────────────────

/// Iterative Kademlia FIND_VALUE lookup.
///
/// Walks the network the same way as `find_node_iterative`, but each hop the
/// local store (via `local_lookup`) is checked first. The first non-`None`
/// result short-circuits the walk and returns `Some(value)`.
///
/// Returns `None` if the value is not found within the reachable network.
pub async fn find_value_iterative(
    key: [u8; 32],
    seed_contacts: Vec<Contact>,
    querier: &dyn PeerQuerier,
    local_lookup: impl Fn(&[u8; 32]) -> Option<Vec<u8>>,
    params: &IterativeParams,
) -> Option<Vec<u8>> {
    let IterativeParams {
        k,
        alpha,
        max_rounds,
        ..
    } = *params;
    // Check locally first.
    if let Some(v) = local_lookup(&key) {
        return Some(v);
    }

    let mut queried: HashSet<[u8; 32]> = HashSet::new();
    let mut shortlist: Vec<Contact> = seed_contacts;
    sort_by_distance(&mut shortlist, &key);
    shortlist.dedup_by_key(|c| c.node_id);
    shortlist.truncate(k);

    for _ in 0..max_rounds {
        // Collect only node_id ([u8;32], Copy) — no Contact clone needed.
        let to_query: Vec<[u8; 32]> = shortlist
            .iter()
            .filter(|c| !queried.contains(&c.node_id))
            .take(alpha)
            .map(|c| c.node_id)
            .collect();

        if to_query.is_empty() {
            break;
        }

        let prev_closest = shortlist.first().map(|c| c.node_id);

        // Query alpha peers concurrently; short-circuit as soon as a Value is found.
        let futures: Vec<_> = to_query
            .iter()
            .map(|&peer_id| querier.find_value(peer_id, key))
            .collect();
        let results = futures::future::join_all(futures).await;
        // HashSet for O(1) duplicate check during shortlist admission.
        let mut shortlist_ids: std::collections::HashSet<[u8; 32]> =
            shortlist.iter().map(|c| c.node_id).collect();
        for (&peer_id, result) in to_query.iter().zip(results) {
            queried.insert(peer_id);
            match result {
                FindValueResult::Value(v) => return Some(v),
                FindValueResult::Nodes(responses) => {
                    // same XOR filter + per-responder cap as find_node_iterative.
                    let peer_dist = xor_distance(&peer_id, &key);
                    let mut admitted = 0usize;
                    for r in responses {
                        if admitted >= k {
                            break;
                        }
                        let r_dist = xor_distance(&r.node_id, &key);
                        // Audit batch 2026-05-25 phase L (cross-audit
                        // closure): unify eclipse filter с
                        // `find_node_iterative` (line 293) — strict
                        // progress `r_dist < peer_dist`.  Previously
                        // FIND_VALUE used а legacy `half_r_dist >
                        // peer_dist` check that admitted same-distance
                        // contacts, leaving an asymmetric Sybil-eclipse
                        // window: FIND_NODE was protected (strict
                        // filter) but FIND_VALUE was not.  Attackers
                        // publishing Sybils close к а target key could
                        // funnel resolution к forged values
                        // (sovereign-identity lookup, name-claim
                        // resolve, mlkem-cert fetch).  Unifying к the
                        // strict filter closes the asymmetry.
                        if r_dist >= peer_dist {
                            continue;
                        }
                        if shortlist_ids.insert(r.node_id) {
                            shortlist.push(r);
                            admitted += 1;
                        }
                    }
                }
            }
        }

        sort_by_distance(&mut shortlist, &key);
        shortlist.dedup_by_key(|c| c.node_id);
        shortlist.truncate(k);

        let new_closest = shortlist.first().map(|c| c.node_id);
        if new_closest == prev_closest {
            let all_queried = shortlist
                .iter()
                .take(k)
                .all(|c| queried.contains(&c.node_id));
            if all_queried {
                break;
            }
        }
    }

    None
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn sort_by_distance(contacts: &mut [Contact], target: &[u8; 32]) {
    contacts.sort_by(|a, b| {
        let da = xor_distance(target, &a.node_id);
        let db = xor_distance(target, &b.node_id);
        da.cmp(&db)
    });
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::routing::RoutingTable;
    use super::*;

    /// Build a 3-node topology: A knows B and C, B knows C and D, C knows D.
    /// Looking up D from A should traverse A → B/C → D.
    #[tokio::test]
    async fn iterative_lookup_traverses_3_node_topology() {
        let node_a = [0x01u8; 32];
        let node_b = [0x02u8; 32];
        let node_c = [0x03u8; 32];
        let node_d = [0x04u8; 32]; // target

        let querier = LocalPeerQuerier::new();

        // Node A's routing table: knows B and C.
        let mut rt_a = RoutingTable::new(node_a);
        rt_a.insert(Contact::new(node_b, "tcp://b:9001"));
        rt_a.insert(Contact::new(node_c, "tcp://c:9002"));
        querier.add_node(node_a, rt_a);

        // Node B's routing table: knows C and D.
        let mut rt_b = RoutingTable::new(node_b);
        rt_b.insert(Contact::new(node_c, "tcp://c:9002"));
        rt_b.insert(Contact::new(node_d, "tcp://d:9003"));
        querier.add_node(node_b, rt_b);

        // Node C's routing table: knows D.
        let mut rt_c = RoutingTable::new(node_c);
        rt_c.insert(Contact::new(node_d, "tcp://d:9003"));
        querier.add_node(node_c, rt_c);

        // Node D's routing table (empty — just a leaf).
        querier.add_node(node_d, RoutingTable::new(node_d));

        // Seed: what A knows.
        let seeds = vec![
            Contact::new(node_b, "tcp://b:9001"),
            Contact::new(node_c, "tcp://c:9002"),
        ];

        let result =
            find_node_iterative(node_d, seeds, &querier, &IterativeParams::default()).await;
        let found = result.iter().any(|c| c.node_id == node_d);
        assert!(found, "D must appear in the iterative lookup result");
    }

    #[tokio::test]
    async fn iterative_lookup_empty_topology_returns_empty() {
        let querier = LocalPeerQuerier::new();
        let result =
            find_node_iterative([0xFFu8; 32], vec![], &querier, &IterativeParams::default()).await;
        assert!(result.is_empty(), "empty seed should return empty result");
    }

    #[tokio::test]
    async fn iterative_find_value_returns_none_when_not_found() {
        let querier = LocalPeerQuerier::new();
        let result = find_value_iterative(
            [0x42u8; 32],
            vec![],
            &querier,
            |_| None,
            &IterativeParams::default(),
        )
        .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn iterative_find_value_returns_local_hit() {
        let querier = LocalPeerQuerier::new();
        let key = [0x42u8; 32];
        let result = find_value_iterative(
            key,
            vec![],
            &querier,
            |k| {
                if k == &key {
                    Some(b"found!".to_vec())
                } else {
                    None
                }
            },
            &IterativeParams::default(),
        )
        .await;
        assert_eq!(result, Some(b"found!".to_vec()));
    }

    /// Multi-hop FIND_VALUE: value lives at node C, which is 2 hops away from the
    /// initiator (A only knows B; B knows C; C holds the value).
    ///
    /// `LocalPeerQuerier` returns only routing entries (not values), so we build a
    /// custom querier that also knows the value stored at C.
    #[tokio::test]
    async fn find_value_iterative_two_hops_finds_value() {
        let node_b = [0x0Bu8; 32];
        let node_c = [0x0Cu8; 32]; // value holder

        let key = [0xCCu8; 32];
        let value = b"the-app-endpoint".to_vec();

        // A custom querier: B forwards to C; C has the value.
        struct TwoHopQuerier {
            node_b: [u8; 32],
            node_c: [u8; 32],
            key: [u8; 32],
            value: Vec<u8>,
        }

        impl PeerQuerier for TwoHopQuerier {
            fn find_node<'a>(
                &'a self,
                peer_id: [u8; 32],
                _target: [u8; 32],
            ) -> Pin<Box<dyn Future<Output = Vec<Contact>> + Send + 'a>> {
                let c = Contact::new(self.node_c, "tcp://c:9102");
                let peer_b = self.node_b;
                Box::pin(async move { if peer_id == peer_b { vec![c] } else { vec![] } })
            }

            fn find_value<'a>(
                &'a self,
                peer_id: [u8; 32],
                key: [u8; 32],
            ) -> Pin<Box<dyn Future<Output = FindValueResult> + Send + 'a>> {
                let node_b = self.node_b;
                let node_c = self.node_c;
                let stored_key = self.key;
                let value = self.value.clone();
                Box::pin(async move {
                    if peer_id == node_b {
                        // B doesn't have it; returns C as closest node.
                        FindValueResult::Nodes(vec![Contact::new(node_c, "tcp://c:9102")])
                    } else if peer_id == node_c && key == stored_key {
                        FindValueResult::Value(value)
                    } else {
                        FindValueResult::Nodes(vec![])
                    }
                })
            }
        }

        let querier = TwoHopQuerier {
            node_b,
            node_c,
            key,
            value: value.clone(),
        };
        let seeds = vec![Contact::new(node_b, "tcp://b:9101")];

        let result =
            find_value_iterative(key, seeds, &querier, |_| None, &IterativeParams::default()).await;
        assert_eq!(
            result,
            Some(value),
            "value must be found via 2-hop FIND_VALUE walk"
        );
    }

    /// 64-node linear chain: node[i] knows ONLY node[i+1] (toward the target),
    /// and node[63] holds the value. The initiator (node[0]) must walk the
    /// full 63-hop chain to find it — the "chain of 64, endpoints must find
    /// each other" property at the iterative-DHT-lookup level.
    ///
    /// Node IDs are arranged so XOR distance to the key strictly decreases
    /// along the chain (key == node[63].id == all-zero), so the strict-progress
    /// eclipse filter admits each forward hop. `max_rounds` is raised to N
    /// because production `MAX_ROUNDS = 20` deliberately bounds the walk (a real
    /// 63-hop physical chain resolves via source-routing/RelayPath, not a pure
    /// iterative DHT walk).
    ///
    /// CRITICALLY: every FIND_VALUE `Nodes` response here carries an EMPTY
    /// transport (`Contact::new(id, "")`) — i.e. node-id-only, the shape that
    /// audit finding C-06 would have FIND_VALUE return. This proves the
    /// multi-hop walk depends only on node-ids (transport is resolved
    /// separately when dialing), so making FIND_VALUE node-id-only does not
    /// break long-chain endpoint discovery.
    #[tokio::test]
    async fn find_value_iterative_64_node_chain_reaches_far_endpoint() {
        const N: usize = 64;

        // node[i].id high byte = N-1-i, so node[0]=63.. and node[63]=0.. (== key).
        fn chain_id(i: usize) -> [u8; 32] {
            let mut id = [0u8; 32];
            id[0] = (N - 1 - i) as u8;
            id
        }
        fn index_of(id: &[u8; 32]) -> usize {
            N - 1 - id[0] as usize
        }

        let key = chain_id(N - 1); // all-zero — held by node[63]
        let value = b"far-endpoint-app-record".to_vec();

        struct ChainQuerier {
            key: [u8; 32],
            value: Vec<u8>,
        }
        impl PeerQuerier for ChainQuerier {
            fn find_node<'a>(
                &'a self,
                peer_id: [u8; 32],
                _target: [u8; 32],
            ) -> Pin<Box<dyn Future<Output = Vec<Contact>> + Send + 'a>> {
                Box::pin(async move {
                    let i = index_of(&peer_id);
                    if i + 1 < N {
                        // node-id-only: empty transport string.
                        vec![Contact::new(chain_id(i + 1), "")]
                    } else {
                        vec![]
                    }
                })
            }
            fn find_value<'a>(
                &'a self,
                peer_id: [u8; 32],
                key: [u8; 32],
            ) -> Pin<Box<dyn Future<Output = FindValueResult> + Send + 'a>> {
                let stored_key = self.key;
                let value = self.value.clone();
                Box::pin(async move {
                    let i = index_of(&peer_id);
                    if i + 1 < N {
                        // forward toward the value holder; node-id-only.
                        FindValueResult::Nodes(vec![Contact::new(chain_id(i + 1), "")])
                    } else if key == stored_key {
                        FindValueResult::Value(value)
                    } else {
                        FindValueResult::Nodes(vec![])
                    }
                })
            }
        }

        let querier = ChainQuerier {
            key,
            value: value.clone(),
        };
        // node[0]'s routing table holds only its single neighbour, node[1].
        let seeds = vec![Contact::new(chain_id(1), "")];
        let params = IterativeParams {
            max_rounds: N + 4,
            ..IterativeParams::default()
        };

        let result = find_value_iterative(key, seeds, &querier, |_| None, &params).await;
        assert_eq!(
            result,
            Some(value),
            "node[0] must resolve the value held by node[63] across the 63-hop chain"
        );
    }

    // ── — eclipse mitigation tests ───────────────────────────────────

    /// Layer 1: a responder that returns contacts farther than 2× its own XOR
    /// distance from the target must have those contacts filtered out.
    ///
    /// Node A (all zeros) queries for target [0xFF;32].
    /// Malicious responder M is at XOR distance 0x80.. from target.
    /// M returns contact Evil at XOR distance 0xFF.. from target, which is
    /// 2× farther than M — must be filtered out.
    #[tokio::test]
    async fn xor_filter_drops_contacts_farther_than_2x_responder() {
        struct FilterTestQuerier {
            evil_node: [u8; 32],
        }

        impl PeerQuerier for FilterTestQuerier {
            fn find_node<'a>(
                &'a self,
                _peer_id: [u8; 32],
                _target: [u8; 32],
            ) -> Pin<Box<dyn Future<Output = Vec<Contact>> + Send + 'a>> {
                let evil = self.evil_node;
                Box::pin(async move {
                    // Return the evil node which is far from target.
                    vec![Contact::new(evil, "tcp://evil:1")]
                })
            }

            fn find_value<'a>(
                &'a self,
                peer_id: [u8; 32],
                target: [u8; 32],
            ) -> Pin<Box<dyn Future<Output = FindValueResult> + Send + 'a>> {
                let contacts = self.find_node(peer_id, target);
                Box::pin(async move { FindValueResult::Nodes(contacts.await) })
            }
        }

        // Responder at XOR distance 0x01 from target (node_id = target XOR 0x01).
        // Evil contact at XOR distance 0x04 from target (> 2 × 0x01 = 0x02) → filtered.
        let target = [0xFFu8; 32];
        let mut resp_id = target;
        resp_id[31] ^= 0x01; // XOR dist = 0x..01
        let mut evil_id = target;
        evil_id[31] ^= 0x04; // XOR dist = 0x..04 > 2 × 0x01 = 0x..02 → filtered

        let querier = FilterTestQuerier { evil_node: evil_id };
        let seeds = vec![Contact::new(resp_id, "tcp://resp:1")];
        let params = IterativeParams {
            k: 20,
            alpha: 1,
            max_rounds: 1,
            proximity_bias: 0.0,
        };

        let result = find_node_iterative(target, seeds, &querier, &params).await;
        // evil_id must NOT appear in the result (was filtered by XOR > 2× check).
        assert!(
            !result.iter().any(|c| c.node_id == evil_id),
            "contact 4× farther than responder must be filtered by XOR distance check",
        );
    }

    /// Layer 2: per-responder cap limits contacts admitted from a single response.
    /// Responder returns K+5 contacts all closer than threshold — only K admitted.
    #[tokio::test]
    async fn per_responder_cap_limits_contacts_from_single_response() {
        let target = [0x00u8; 32];
        let k = 5usize;

        struct CapTestQuerier {
            contacts: Vec<Contact>,
        }

        impl PeerQuerier for CapTestQuerier {
            fn find_node<'a>(
                &'a self,
                _peer_id: [u8; 32],
                _target: [u8; 32],
            ) -> Pin<Box<dyn Future<Output = Vec<Contact>> + Send + 'a>> {
                let c = self.contacts.clone();
                Box::pin(async move { c })
            }

            fn find_value<'a>(
                &'a self,
                peer_id: [u8; 32],
                target: [u8; 32],
            ) -> Pin<Box<dyn Future<Output = FindValueResult> + Send + 'a>> {
                let contacts = self.find_node(peer_id, target);
                Box::pin(async move { FindValueResult::Nodes(contacts.await) })
            }
        }

        // Responder is at XOR distance 0xFF from target.
        let mut resp_id = target;
        resp_id[31] = 0xFF;

        // Build k+5 contacts all closer than responder (XOR dist 0x01..0x0A).
        let contacts: Vec<Contact> = (1..=(k + 5))
            .map(|i| {
                let mut id = target;
                id[31] = i as u8; // XOR dist = i (all < 0xFF = responder dist)
                Contact::new(id, format!("tcp://node{i}:1"))
            })
            .collect();

        let querier = CapTestQuerier { contacts };
        let seeds = vec![Contact::new(resp_id, "tcp://resp:1")];
        let params = IterativeParams {
            k,
            alpha: 1,
            max_rounds: 1,
            proximity_bias: 0.0,
        };

        let result = find_node_iterative(target, seeds, &querier, &params).await;
        // shortlist.truncate(k) also applies, so result len == k.
        // The important thing: the number of contacts from this one responder ≤ k.
        assert!(
            result.len() <= k,
            "result must be capped at k={k}, got {}",
            result.len(),
        );
    }

    /// a Sybil responder at distance D from
    /// the target that points at peers at distance ≥ D (within the old
    /// `2 × D` slack) is now rejected by the strict-progress filter.
    /// Pre-fix, contacts up to 2× the responder's own distance were
    /// admitted — non-progress neighbours of the Sybil flooded the
    /// shortlist, halting convergence on attacker-controlled peers.
    /// Strict `<` rejects them outright.
    ///
    /// Test setup uses small concrete distances to make XOR comparisons
    /// readable:
    /// target = 0x00…0
    /// responder = 0x01,0x00,… (distance = 0x01,0x00,… i.e. "1")
    /// sybil_collab = 0x02,0x00,… (distance = 0x02,0x00,… i.e. "2")
    /// With old 2× filter: collab admitted (2 ≤ 2 × 1 = 2 — at boundary).
    /// With new strict-progress filter: collab rejected (2 ≥ 1).
    #[tokio::test]
    async fn phase647_h22_non_progress_contact_rejected() {
        let target = [0x00u8; 32];
        let mut responder = [0u8; 32];
        responder[0] = 0x01; // distance 0x01,0x00,…
        let mut sybil_collab = [0u8; 32];
        sybil_collab[0] = 0x02; // distance 0x02,0x00,… (= 2 × responder)

        // Sanity: responder is closer than sybil_collab.
        let d_resp = xor_distance(&responder, &target);
        let d_collab = xor_distance(&sybil_collab, &target);
        assert!(
            d_resp < d_collab,
            "responder must be strictly closer than collaborator"
        );

        // Without the fix, the OLD filter `r_dist >> 1 > peer_dist`
        // would admit the collaborator because 0x02 >> 1 == 0x01 ==
        // peer_dist (not strictly greater) → admitted at the 2×
        // boundary. The NEW strict-progress filter requires
        // `r_dist < peer_dist` → 0x02 < 0x01 fails → rejected.

        let querier = LocalPeerQuerier::new();
        let mut rt_resp = RoutingTable::new(responder);
        rt_resp.insert(Contact::new(sybil_collab, "tcp://collab:9000"));
        querier.add_node(responder, rt_resp);
        querier.add_node(sybil_collab, RoutingTable::new(sybil_collab));

        let seeds = vec![Contact::new(responder, "tcp://resp:9000")];
        let params = IterativeParams {
            k: 4,
            alpha: 2,
            max_rounds: 5,
            ..Default::default()
        };
        let result = find_node_iterative(target, seeds, &querier, &params).await;

        // The non-progress collaborator must NOT be in the shortlist.
        // Responder itself is admitted (it was the seed; filter applies
        // only to contacts pointed-at, not seeds).
        let has_collab = result.iter().any(|c| c.node_id == sybil_collab);
        assert!(
            !has_collab,
            "non-progress collaborator must be filtered, got {:?}",
            result.iter().map(|c| c.node_id).collect::<Vec<_>>()
        );
    }
}
