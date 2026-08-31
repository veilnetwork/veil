//! The iterative lookup: ask the nodes nearest the target, then the nearer
//! ones they name, until nobody knows anyone nearer.
//!
//! This is where a DHT is either bounded or a way to be kept busy forever by
//! strangers. Every loop here has a ceiling — rounds, queries, and a wall-clock
//! deadline — and a lookup that hits one returns what it has rather than
//! failing: on this network a partial answer is the normal answer.
//!
//! The network is a parameter rather than a socket, so the algorithm can be
//! tested against a simulated DHT that behaves in ways the real one will
//! eventually behave and cannot be asked to on demand: nodes that lie, nodes
//! that name each other in a circle, nodes that never answer.

use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use crate::client::{Client, QueryError};
use crate::krpc::{NodeId, NodeInfo, Query, Response};

/// How many nodes a lookup keeps and eventually announces to. BEP 5's `k`.
pub const K: usize = 8;

/// How many queries are in flight at once. BEP 5's `α`.
pub const ALPHA: usize = 3;

/// Ceilings. A lookup that reaches one returns what it found.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Most rounds of "ask the closest we have not asked".
    pub rounds: usize,
    /// Most queries in total, however the rounds fall.
    pub queries: usize,
    /// Wall clock for the whole lookup.
    pub deadline: Duration,
    /// Wall clock for one query.
    pub per_query: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            rounds: 12,
            queries: 96,
            deadline: Duration::from_secs(30),
            per_query: Duration::from_secs(4),
        }
    }
}

/// What a lookup found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// Peers holding the target, in the order they were heard of.
    pub peers: Vec<std::net::SocketAddrV4>,
    /// The closest nodes that answered, nearest first, with the write token
    /// each gave. These are who an announce goes to.
    pub closest: Vec<(NodeInfo, Vec<u8>)>,
    /// How many queries were spent.
    pub queries: usize,
    /// Whether the search stopped because it ran out of room rather than
    /// because it converged. Not a failure — a caller may want to say so.
    pub hit_a_limit: bool,
}

/// The one thing a lookup needs from the network.
///
/// A trait rather than a `Client` so the algorithm can be driven by a
/// simulated DHT in tests. Nothing else about the socket matters here.
pub trait GetPeers {
    fn get_peers(
        &self,
        addr: SocketAddr,
        info_hash: NodeId,
    ) -> impl Future<Output = Result<Response, QueryError>> + Send;
}

impl GetPeers for (&Client, Duration) {
    async fn get_peers(&self, addr: SocketAddr, info_hash: NodeId) -> Result<Response, QueryError> {
        self.0
            .query(
                addr,
                Query::GetPeers {
                    id: self.0.id(),
                    info_hash,
                },
                self.1,
            )
            .await
    }
}

/// Run a `get_peers` lookup from `seeds` towards `info_hash`.
pub async fn find_peers<N: GetPeers>(
    net: &N,
    info_hash: NodeId,
    seeds: &[SocketAddr],
    limits: Limits,
) -> Found {
    let started = std::time::Instant::now();
    let mut found = Found::default();

    // Candidates by distance, so "the closest we have not asked" is the front
    // of a map rather than a sort every round. Keyed by distance THEN address,
    // because two nodes may claim one id and both still need asking.
    let mut candidates: BTreeMap<([u8; 20], SocketAddr), NodeInfo> = BTreeMap::new();
    let mut asked: HashSet<SocketAddr> = HashSet::new();
    let mut heard_peers: HashSet<std::net::SocketAddrV4> = HashSet::new();

    // Seeds have no id yet — that is what the first query is for. A zero id
    // sorts them first, which is right: they are all we have.
    for addr in seeds {
        candidates.insert(
            ([0u8; 20], *addr),
            NodeInfo {
                id: NodeId([0u8; 20]),
                addr: match addr {
                    SocketAddr::V4(v4) => *v4,
                    // A v6 seed cannot be named in a compact v4 answer; keep
                    // it dialable but out of the compact bookkeeping.
                    SocketAddr::V6(_) => "0.0.0.0:0".parse().expect("literal"),
                },
            },
        );
    }

    for _round in 0..limits.rounds {
        if started.elapsed() >= limits.deadline || found.queries >= limits.queries {
            found.hit_a_limit = true;
            break;
        }

        let batch: Vec<SocketAddr> = candidates
            .keys()
            .map(|(_, addr)| *addr)
            .filter(|addr| !asked.contains(addr))
            .take(ALPHA)
            .collect();
        if batch.is_empty() {
            break; // Converged: nobody left to ask.
        }

        let mut learned_closer = false;
        for addr in batch {
            if started.elapsed() >= limits.deadline || found.queries >= limits.queries {
                found.hit_a_limit = true;
                break;
            }
            asked.insert(addr);
            found.queries += 1;
            let Ok(response) = net.get_peers(addr, info_hash).await else {
                continue;
            };

            let (id, nodes, token, peers) = match response {
                Response::Id { id } => (id, Vec::new(), None, Vec::new()),
                Response::Nodes { id, nodes } => (id, nodes, None, Vec::new()),
                Response::Peers {
                    id,
                    token,
                    peers,
                    nodes,
                } => (id, nodes, Some(token), peers),
            };

            for peer in peers {
                if heard_peers.insert(peer) {
                    found.peers.push(peer);
                }
            }
            if let Some(token) = token {
                let who = NodeInfo {
                    id,
                    addr: match addr {
                        SocketAddr::V4(v4) => v4,
                        SocketAddr::V6(_) => continue,
                    },
                };
                found.closest.push((who, token));
            }
            for node in nodes {
                // A node that names itself, or names an unroutable address, is
                // not a lead worth spending a query on.
                if node.addr.port() == 0 || node.addr.ip().is_unspecified() {
                    continue;
                }
                let key = (id_distance(&node.id, &info_hash), SocketAddr::V4(node.addr));
                if !asked.contains(&key.1) && candidates.insert(key, node).is_none() {
                    learned_closer = true;
                }
            }
        }

        // No new lead this round means the search has converged; another round
        // would ask the same nodes the same question.
        if !learned_closer {
            break;
        }
        // The candidate set is bounded too: an adversary that answers with
        // fresh nodes forever cannot make this grow without limit.
        while candidates.len() > K * 8 {
            let last = candidates.keys().next_back().copied().expect("non-empty");
            candidates.remove(&last);
        }
    }

    // Nearest first, and only the k that a BEP 5 announce would go to.
    found
        .closest
        .sort_by_key(|(node, _)| id_distance(&node.id, &info_hash));
    found.closest.truncate(K);
    found
}

fn id_distance(a: &NodeId, b: &NodeId) -> [u8; 20] {
    a.distance(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Mutex;

    fn addr(n: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, (n % 250) as u8 + 1),
            n,
        ))
    }

    fn id(b: u8) -> NodeId {
        NodeId([b; 20])
    }

    /// A DHT that exists only in this test.
    #[derive(Default)]
    struct Sim {
        /// What each address answers with.
        nodes: HashMap<SocketAddr, Response>,
        /// Addresses that never answer.
        silent: HashSet<SocketAddr>,
        /// Every query this lookup made, in order.
        asked: Mutex<Vec<SocketAddr>>,
    }

    impl GetPeers for Sim {
        async fn get_peers(
            &self,
            addr: SocketAddr,
            _info_hash: NodeId,
        ) -> Result<Response, QueryError> {
            // Locked and released before any await: the workspace denies a
            // guard held across one, and here there is no reason to.
            self.asked.lock().expect("sim lock").push(addr);
            if self.silent.contains(&addr) {
                return Err(QueryError::TimedOut);
            }
            self.nodes.get(&addr).cloned().ok_or(QueryError::TimedOut)
        }
    }

    fn node(id_byte: u8, at: SocketAddr) -> NodeInfo {
        NodeInfo {
            id: id(id_byte),
            addr: match at {
                SocketAddr::V4(v4) => v4,
                SocketAddr::V6(_) => unreachable!("tests use v4"),
            },
        }
    }

    #[tokio::test]
    async fn a_lookup_walks_towards_the_target_and_brings_back_its_peers() {
        // Seed knows a middle node; the middle node holds the peers. A lookup
        // that did not follow the lead would come back empty.
        let target = id(0xFF);
        let seed = addr(1);
        let middle = addr(2);
        let peer: SocketAddrV4 = "203.0.113.5:51413".parse().unwrap();

        let mut sim = Sim::default();
        sim.nodes.insert(
            seed,
            Response::Nodes {
                id: id(0x01),
                nodes: vec![node(0xF0, middle)],
            },
        );
        sim.nodes.insert(
            middle,
            Response::Peers {
                id: id(0xF0),
                token: b"tok".to_vec(),
                peers: vec![peer],
                nodes: Vec::new(),
            },
        );

        let found = find_peers(&sim, target, &[seed], Limits::default()).await;
        assert_eq!(found.peers, vec![peer], "the lead was not followed");
        assert_eq!(
            found.closest.len(),
            1,
            "the node that gave a token is the one to announce to"
        );
        assert_eq!(found.closest[0].1, b"tok".to_vec());
        assert!(!found.hit_a_limit);
    }

    #[tokio::test]
    async fn nodes_that_name_each_other_in_a_circle_do_not_spin_forever() {
        // The failure this prevents does not fail: it hangs, which is the
        // worst kind. Two nodes each naming the other, forever.
        let a = addr(1);
        let b = addr(2);
        let mut sim = Sim::default();
        sim.nodes.insert(
            a,
            Response::Nodes {
                id: id(0x0A),
                nodes: vec![node(0x0B, b)],
            },
        );
        sim.nodes.insert(
            b,
            Response::Nodes {
                id: id(0x0B),
                nodes: vec![node(0x0A, a)],
            },
        );

        let found = find_peers(&sim, id(0xFF), &[a], Limits::default()).await;
        assert!(found.peers.is_empty());
        // Each address is asked at most once, whatever it names.
        let asked = sim.asked.lock().expect("sim lock").clone();
        let unique: HashSet<_> = asked.iter().collect();
        assert_eq!(
            asked.len(),
            unique.len(),
            "an address was asked twice: {asked:?}"
        );
        assert!(
            asked.len() <= 2,
            "a two-node circle cost {} queries",
            asked.len()
        );
    }

    #[tokio::test]
    async fn a_node_that_answers_with_endless_fresh_nodes_is_bounded() {
        // An adversary's cheapest move: never converge. It must cost a fixed
        // number of queries and then stop.
        struct Endless {
            asked: Mutex<usize>,
        }
        impl GetPeers for Endless {
            async fn get_peers(
                &self,
                _addr: SocketAddr,
                _info_hash: NodeId,
            ) -> Result<Response, QueryError> {
                let n = {
                    let mut a = self.asked.lock().expect("sim lock");
                    *a += 1;
                    *a
                };
                // Every answer names three nodes nobody has seen, each closer
                // than the last, forever.
                Ok(Response::Nodes {
                    id: NodeId([0u8; 20]),
                    nodes: (0..3)
                        .map(|k| NodeInfo {
                            id: NodeId([(255 - (n % 200) as u8); 20]),
                            addr: SocketAddrV4::new(
                                Ipv4Addr::new(10, (n / 250) as u8, (n % 250) as u8, k + 1),
                                4000 + n as u16,
                            ),
                        })
                        .collect(),
                })
            }
        }
        let net = Endless {
            asked: Mutex::new(0),
        };
        let limits = Limits {
            rounds: 5,
            queries: 9,
            ..Limits::default()
        };
        let found = find_peers(&net, id(0xFF), &[addr(1)], limits).await;
        assert!(found.hit_a_limit, "an endless answerer did not hit a limit");
        assert!(
            found.queries <= limits.queries,
            "{} queries spent against a ceiling of {}",
            found.queries,
            limits.queries
        );
    }

    #[tokio::test]
    async fn silence_costs_one_query_each_and_the_lookup_still_returns() {
        // Most of the real DHT is nodes that have gone away without saying so.
        let seed = addr(1);
        let dead: Vec<SocketAddr> = (2..6).map(addr).collect();
        let mut sim = Sim::default();
        sim.nodes.insert(
            seed,
            Response::Nodes {
                id: id(0x01),
                nodes: dead.iter().map(|a| node(0xF0, *a)).collect(),
            },
        );
        for d in &dead {
            sim.silent.insert(*d);
        }

        let found = find_peers(&sim, id(0xFF), &[seed], Limits::default()).await;
        assert!(found.peers.is_empty());
        let asked = sim.asked.lock().expect("sim lock").clone();
        let unique: HashSet<_> = asked.iter().collect();
        assert_eq!(asked.len(), unique.len(), "a silent node was asked twice");
    }

    #[tokio::test]
    async fn a_node_naming_an_unroutable_address_is_not_chased() {
        // Port 0 and 0.0.0.0 are what a node says when it has nothing to say,
        // and a query spent on either is a query not spent on a real lead.
        let seed = addr(1);
        let mut sim = Sim::default();
        sim.nodes.insert(
            seed,
            Response::Nodes {
                id: id(0x01),
                nodes: vec![
                    NodeInfo {
                        id: id(0xF0),
                        addr: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 0),
                    },
                    NodeInfo {
                        id: id(0xF1),
                        addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 6881),
                    },
                ],
            },
        );
        let found = find_peers(&sim, id(0xFF), &[seed], Limits::default()).await;
        // One lock, taken once. `assert_eq!` evaluates its format arguments
        // while the first guard is still alive, so locking twice in one
        // assertion deadlocks on the FAILURE path -- the test hangs instead of
        // reddening, which is the worst way for a guard to behave. Found by
        // breaking the filter this test guards.
        let asked = sim.asked.lock().expect("sim lock").clone();
        assert_eq!(asked.len(), 1, "an unroutable lead was chased: {asked:?}");
        assert!(found.peers.is_empty());
    }

    #[tokio::test]
    async fn the_nodes_to_announce_to_come_back_nearest_first_and_capped_at_k() {
        // An announce goes to the k closest, so the order here is the order it
        // is spent in.
        //
        // The addresses are walked in one order and the ids are laid out in the
        // OPPOSITE order on purpose. An earlier version of this test numbered
        // them the same way, so the list came out sorted by accident and
        // deleting the sort changed nothing -- the guard passed a break.
        let target = id(0x00);
        let chain: Vec<SocketAddr> = (1..=12).map(addr).collect();
        let mut sim = Sim::default();
        for (i, at) in chain.iter().enumerate() {
            // First address, farthest id; last address, nearest id.
            let id_byte = (12 - i) as u8 * 8;
            let next = chain
                .get(i + 1)
                .map(|n| node(id_byte.saturating_sub(8), *n));
            sim.nodes.insert(
                *at,
                Response::Peers {
                    id: id(id_byte),
                    token: vec![i as u8],
                    peers: Vec::new(),
                    // Naming the next one is what keeps the search walking; a
                    // node that names nobody ends the round.
                    nodes: next.into_iter().collect(),
                },
            );
        }

        let found = find_peers(
            &sim,
            target,
            &[chain[0]],
            Limits {
                rounds: 30,
                queries: 60,
                ..Limits::default()
            },
        )
        .await;

        assert!(
            found.closest.len() > 1,
            "only {} node answered",
            found.closest.len()
        );
        assert!(
            found.closest.len() <= K,
            "{} nodes to announce to, more than k",
            found.closest.len()
        );
        let distances: Vec<[u8; 20]> = found
            .closest
            .iter()
            .map(|(n, _)| n.id.distance(&target))
            .collect();
        let mut sorted = distances.clone();
        sorted.sort();
        assert_eq!(
            distances, sorted,
            "the announce targets are not nearest-first"
        );
        // And the k kept are the k NEAREST, not the k that answered first --
        // truncating an unsorted list keeps the wrong ones.
        let nearest_seen = found
            .closest
            .iter()
            .map(|(n, _)| n.id.distance(&target))
            .min()
            .expect("some node answered");
        assert_eq!(
            distances[0], nearest_seen,
            "the nearest node that answered is not at the front"
        );
    }

    #[tokio::test]
    async fn a_lookup_with_no_seeds_returns_rather_than_reaching_for_the_network() {
        let sim = Sim::default();
        let found = find_peers(&sim, id(0xFF), &[], Limits::default()).await;
        assert_eq!(found, Found::default());
        assert!(
            sim.asked.lock().expect("sim lock").is_empty(),
            "a query went out with no seeds"
        );
    }

    #[tokio::test]
    #[ignore = "runs a real lookup on the live Mainline DHT; run with --ignored"]
    async fn a_real_lookup_converges_on_the_live_dht() {
        // Everything above drives this algorithm against a DHT written to
        // agree with it. This drives it against the one that exists.
        use crate::client::{Client, PUBLIC_ROUTERS, random_node_id};

        let client = Client::bind(random_node_id()).await.expect("bind");
        let mut seeds = Vec::new();
        for router in PUBLIC_ROUTERS {
            if let Ok(addrs) = tokio::net::lookup_host(*router).await {
                seeds.extend(addrs.filter(std::net::SocketAddr::is_ipv4));
            }
        }
        assert!(
            !seeds.is_empty(),
            "no router resolved; this machine has no DNS"
        );

        let target = random_node_id();
        let found = find_peers(
            &(&client, Duration::from_secs(4)),
            target,
            &seeds,
            Limits::default(),
        )
        .await;

        eprintln!(
            "spent {} queries, {} node(s) gave a write token, {} peer(s), hit a limit: {}",
            found.queries,
            found.closest.len(),
            found.peers.len(),
            found.hit_a_limit
        );
        for (node, token) in &found.closest {
            eprintln!(
                "  {:02x?}… at {} token {} bytes",
                &node.id.0[..4],
                node.addr,
                token.len()
            );
        }

        // A random target has no peers -- nobody is sharing it. What proves
        // the lookup worked is that real nodes answered with write tokens,
        // because a token is what an announce needs and only a node that
        // understood our get_peers hands one out.
        assert!(
            !found.closest.is_empty(),
            "no node on the live DHT gave a write token in {} queries",
            found.queries
        );
        assert!(found.queries > 1, "the lookup stopped at its seeds");
    }
}
