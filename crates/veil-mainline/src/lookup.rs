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
    /// Most peer addresses to keep, across the whole lookup.
    ///
    /// Every address here came from a stranger: one `get_peers` response may
    /// carry a full 64-KiB page of them, and a lookup makes up to `queries` of
    /// those. Collecting them all and letting the caller take four means the
    /// hostile case is bounded only by the deadline. Keeping a fixed number
    /// costs nothing in the honest case -- a rendezvous with more than a few
    /// dozen live nodes is one where the first few are as good as any.
    pub max_peers: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            rounds: 12,
            queries: 96,
            deadline: Duration::from_secs(30),
            per_query: Duration::from_secs(4),
            max_peers: 64,
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
                if found.peers.len() >= limits.max_peers {
                    break;
                }
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

/// The other half: telling the nodes we found that we are here.
pub trait AnnouncePeer {
    fn announce_peer(
        &self,
        addr: SocketAddr,
        info_hash: NodeId,
        port: u16,
        token: Vec<u8>,
    ) -> impl Future<Output = Result<Response, QueryError>> + Send;
}

impl AnnouncePeer for (&Client, Duration) {
    async fn announce_peer(
        &self,
        addr: SocketAddr,
        info_hash: NodeId,
        port: u16,
        token: Vec<u8>,
    ) -> Result<Response, QueryError> {
        self.0
            .query(
                addr,
                Query::AnnouncePeer {
                    id: self.0.id(),
                    info_hash,
                    port,
                    // FALSE, and this is the one place where the obvious answer
                    // is the wrong one. `implied_port` tells the storing node to
                    // record the port the datagram CAME FROM, which is the NAT
                    // mapping of this DHT socket -- not the port anything veil
                    // listens on. Measured on the live DHT 2026-08-31: with it
                    // set, three nodes stored the DHT socket's mapped port and
                    // one stored the port we claimed, so a peer dialling what
                    // the DHT gave back would reach a UDP socket that speaks
                    // KRPC and nothing else.
                    //
                    // With it clear, the address is still the one the datagram
                    // came from -- which is right, it is the only address a
                    // node behind NAT can be reached at -- and the PORT is the
                    // one we name.
                    implied_port: false,
                    token,
                },
                self.1,
            )
            .await
    }
}

/// Tell the nodes a lookup found that this node is at `port`.
///
/// Returns how many accepted. Partial success is the normal outcome and not an
/// error: a rendezvous held by six of eight nodes is a rendezvous.
pub async fn announce<N: AnnouncePeer>(
    net: &N,
    info_hash: NodeId,
    port: u16,
    targets: &[(NodeInfo, Vec<u8>)],
) -> usize {
    let mut accepted = 0;
    for (node, token) in targets {
        // A token is what makes an announce legitimate to the node storing it;
        // one we never received cannot be invented.
        if token.is_empty() {
            continue;
        }
        if net
            .announce_peer(SocketAddr::V4(node.addr), info_hash, port, token.clone())
            .await
            .is_ok()
        {
            accepted += 1;
        }
    }
    accepted
}

fn id_distance(a: &NodeId, b: &NodeId) -> [u8; 20] {
    a.distance(b)
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn one_lookup_keeps_a_bounded_number_of_addresses() {
        // Every address in a `get_peers` reply came from a stranger, one reply
        // may carry a 64-KiB page of them, and a lookup makes up to 96
        // queries. Collecting all of them and letting the caller take four
        // bounds the hostile case by the deadline alone.
        struct Flood(u16);
        impl GetPeers for Flood {
            async fn get_peers(
                &self,
                _addr: SocketAddr,
                _info_hash: NodeId,
            ) -> Result<Response, QueryError> {
                Ok(Response::Peers {
                    id: NodeId([0u8; 20]),
                    token: vec![1],
                    peers: (0..self.0)
                        .map(|i| {
                            SocketAddrV4::new(std::net::Ipv4Addr::new(203, 0, 113, 9), 1024 + i)
                        })
                        .collect(),
                    nodes: Vec::new(),
                })
            }
        }

        let limits = Limits {
            max_peers: 8,
            ..Default::default()
        };
        let seeds = vec![SocketAddr::V4(SocketAddrV4::new(
            std::net::Ipv4Addr::new(203, 0, 113, 1),
            6881,
        ))];
        let found = find_peers(&Flood(500), NodeId([7u8; 20]), &seeds, limits).await;
        assert!(
            found.peers.len() <= 8,
            "a lookup kept {} addresses against a cap of 8",
            found.peers.len()
        );
    }
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

    /// Records what it was told to announce, and can be made to refuse.
    #[derive(Default)]
    struct Announces {
        seen: Mutex<Vec<(SocketAddr, u16, Vec<u8>)>>,
        refuse: HashSet<SocketAddr>,
    }

    impl AnnouncePeer for Announces {
        async fn announce_peer(
            &self,
            addr: SocketAddr,
            _info_hash: NodeId,
            port: u16,
            token: Vec<u8>,
        ) -> Result<Response, QueryError> {
            if self.refuse.contains(&addr) {
                return Err(QueryError::TimedOut);
            }
            self.seen
                .lock()
                .expect("sim lock")
                .push((addr, port, token));
            Ok(Response::Id {
                id: NodeId([0u8; 20]),
            })
        }
    }

    #[tokio::test]
    async fn an_announce_goes_to_each_node_with_the_token_that_node_gave() {
        // A token belongs to the node that issued it. Sending one node's token
        // to another is an announce that is refused, and worse, an announce
        // this node would count as having landed.
        let targets: Vec<(NodeInfo, Vec<u8>)> = (1..=3)
            .map(|n| (node(n as u8, addr(n)), vec![n as u8; 4]))
            .collect();
        let net = Announces::default();
        let accepted = announce(&net, id(0xFF), 5556, &targets).await;
        assert_eq!(accepted, 3);
        let seen = net.seen.lock().expect("sim lock").clone();
        assert_eq!(seen.len(), 3);
        for (i, (at, port, token)) in seen.iter().enumerate() {
            let n = i as u16 + 1;
            assert_eq!(*at, addr(n), "announce {n} went to the wrong node");
            assert_eq!(*port, 5556);
            assert_eq!(
                *token,
                vec![n as u8; 4],
                "announce {n} carried another node's token"
            );
        }
    }

    #[tokio::test]
    async fn a_node_that_refuses_does_not_stop_the_others() {
        // Partial success is the normal outcome here: a rendezvous held by
        // some of the nodes is a rendezvous.
        let targets: Vec<(NodeInfo, Vec<u8>)> = (1..=4)
            .map(|n| (node(n as u8, addr(n)), vec![n as u8; 4]))
            .collect();
        let mut net = Announces::default();
        net.refuse.insert(addr(2));
        let accepted = announce(&net, id(0xFF), 5556, &targets).await;
        assert_eq!(accepted, 3, "a refusal ended the round");
        let seen = net.seen.lock().expect("sim lock").clone();
        assert!(
            seen.iter().any(|(at, _, _)| *at == addr(4)),
            "the node after the refusal was never asked"
        );
    }

    #[tokio::test]
    async fn a_node_that_gave_no_token_is_not_announced_to() {
        // A token cannot be invented, and an announce without one is refused
        // by the node storing it -- so spending the query is pure waste.
        let targets = vec![(node(1, addr(1)), Vec::new())];
        let net = Announces::default();
        let accepted = announce(&net, id(0xFF), 5556, &targets).await;
        assert_eq!(accepted, 0);
        assert!(
            net.seen.lock().expect("sim lock").is_empty(),
            "an announce went out with an empty token"
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

    #[tokio::test]
    #[ignore = "announces on the live Mainline DHT; run with --ignored"]
    async fn the_live_dht_stores_what_this_node_announces() {
        // The write half, end to end, against the network that exists.
        //
        // The infohash is RANDOM and deliberately not veil's rendezvous. The
        // mechanism under test is identical either way, and announcing on the
        // veil point would put this machine's address on a public index
        // labelled as a veil node -- which is a decision for whoever owns the
        // machine (`global.bootstrap`), not for a test. Against a random
        // infohash the announcement says nothing except that some address is a
        // peer for twenty bytes of noise, which is what every BitTorrent
        // client on the internet is saying constantly.
        use crate::client::{Client, PUBLIC_ROUTERS, random_node_id};

        let client = Client::bind(random_node_id()).await.expect("bind");
        let mut seeds = Vec::new();
        for router in PUBLIC_ROUTERS {
            if let Ok(addrs) = tokio::net::lookup_host(*router).await {
                seeds.extend(addrs.filter(std::net::SocketAddr::is_ipv4));
            }
        }
        assert!(!seeds.is_empty(), "no router resolved");

        let target = random_node_id();
        let net = (&client, Duration::from_secs(4));
        let first = find_peers(&net, target, &seeds, Limits::default()).await;
        eprintln!(
            "lookup: {} queries, {} token(s), {} peer(s)",
            first.queries,
            first.closest.len(),
            first.peers.len()
        );
        assert!(
            !first.closest.is_empty(),
            "no node gave a write token, so there is nobody to announce to"
        );
        // NOT asserted empty. A random infohash should have no peers, and
        // usually does -- but the live DHT contains nodes that answer any
        // get_peers with values, and one run of this test met one. An
        // assertion about what strangers say is an assertion about the
        // network, not about this code; what is measured below instead is
        // what appeared AFTER the announce that was not there before.
        let before: HashSet<std::net::SocketAddrV4> = first.peers.iter().copied().collect();
        if !before.is_empty() {
            eprintln!("note: {} peer(s) present before announcing", before.len());
        }

        let accepted = announce(&net, target, 5556, &first.closest).await;
        eprintln!("announced to {}/{} node(s)", accepted, first.closest.len());
        assert!(accepted > 0, "not one node accepted the announcement");

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Ask the very nodes that took it, one at a time. A fresh iterative
        // lookup asks whoever it converges on, which need not be the same
        // eight -- so a lookup that comes back empty cannot tell "nobody
        // stored it" from "we asked somebody else". This can.
        let mut direct_hits = 0;
        for (node, _) in &first.closest {
            match net
                .get_peers(std::net::SocketAddr::V4(node.addr), target)
                .await
            {
                Ok(Response::Peers { peers, .. }) if peers.iter().any(|p| !before.contains(p)) => {
                    eprintln!("  {} gave back {:?}", node.addr, peers);
                    direct_hits += 1;
                }
                Ok(_) => eprintln!("  {} stored nothing", node.addr),
                Err(e) => eprintln!("  {}: {e}", node.addr),
            }
        }
        eprintln!(
            "{direct_hits}/{} node(s) gave the announcement back",
            first.closest.len()
        );

        // And the iterative path, for comparison.
        let second = find_peers(&net, target, &seeds, Limits::default()).await;
        eprintln!(
            "a fresh lookup found {} peer(s) {:?}",
            second.peers.len(),
            second.peers
        );

        assert!(
            direct_hits > 0,
            "all {accepted} node(s) accepted the announcement and not one of \
             them gave it back when asked directly"
        );
    }
}
