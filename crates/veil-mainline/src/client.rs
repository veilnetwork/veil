//! A UDP client for the Mainline DHT: send a query, wait for its answer.
//!
//! Deliberately one query at a time. The iterative lookup that Kademlia needs
//! is built on top of this, and building it into the socket would make the
//! socket untestable without one.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::bencode::MAX_BYTES_LEN;
use crate::krpc::{KrpcError, Message, NodeId, Query, Response, decode_message, encode_message};

/// How long to wait for one answer. The DHT is full of nodes that have gone
/// away without saying so, and most of a lookup's time is spent not hearing
/// from them.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(4);

/// What went wrong with one query.
#[derive(Debug)]
pub enum QueryError {
    Io(io::Error),
    /// No answer inside the timeout — the ordinary case on this network, not
    /// an exception.
    TimedOut,
    /// An answer arrived and was not one.
    Malformed(KrpcError),
    /// The node answered with a KRPC error.
    Refused {
        code: i64,
        message: String,
    },
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::TimedOut => f.write_str("no answer"),
            Self::Malformed(e) => write!(f, "answer was not KRPC: {e}"),
            Self::Refused { code, message } => write!(f, "refused ({code}): {message}"),
        }
    }
}

impl std::error::Error for QueryError {}

/// Bound sockets that speak KRPC.
///
/// TWO, because Mainline is two overlays over one key space: BEP 5 carries
/// IPv4 and BEP 32 carries IPv6, and a datagram has to leave by a socket of
/// the family it is addressed to. One socket meant every IPv6 contact the DHT
/// offered was unreachable, and a host with no IPv4 at all could not use the
/// layer for anything.
pub struct Client {
    socket: UdpSocket,
    /// `None` where the host has no IPv6 at all, which is an ordinary state
    /// and not a failure: the v4 half works on its own, as it always did.
    socket6: Option<UdpSocket>,
    id: NodeId,
    /// One query at a time per socket.
    ///
    /// A query owns its socket for the length of its own window: it sends,
    /// then reads until a datagram carrying ITS transaction id arrives.
    /// Anything else is dropped on the floor — including, with two queries in
    /// flight on one socket, the other one's answer, which then times out
    /// having actually been replied to. The runtime asks sequentially today,
    /// so this changes nothing it does; it is what stops a second caller from
    /// being a bug rather than a slowdown (report21 V21-L1).
    turn: tokio::sync::Mutex<()>,
}

impl Client {
    /// Bind an ephemeral port on every interface, in both families.
    ///
    /// IPv4 is required -- without it there is no DHT to speak of on most of
    /// the internet. IPv6 is attempted and its absence recorded rather than
    /// raised: plenty of hosts have none, and refusing to start there would
    /// trade a working layer for a principle.
    pub async fn bind(id: NodeId) -> io::Result<Self> {
        let socket6 = UdpSocket::bind("[::]:0").await.ok();
        Ok(Self {
            socket: UdpSocket::bind("0.0.0.0:0").await?,
            socket6,
            id,
            turn: tokio::sync::Mutex::new(()),
        })
    }

    /// Whether this client can reach IPv6 peers at all.
    pub fn has_ipv6(&self) -> bool {
        self.socket6.is_some()
    }

    /// The socket that can reach `addr`, or `None` when this host has no
    /// address of that family.
    fn socket_for(&self, addr: SocketAddr) -> Option<&UdpSocket> {
        match addr {
            SocketAddr::V4(_) => Some(&self.socket),
            SocketAddr::V6(_) => self.socket6.as_ref(),
        }
    }

    /// This client's own node id, as it puts in every query.
    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Send one query and wait for its answer.
    ///
    /// Datagrams that are not the answer to this query are dropped and the
    /// wait continues: on a shared UDP socket a stray or late reply is
    /// ordinary, and treating one as this query's answer would pair a response
    /// to the wrong question.
    pub async fn query(
        &self,
        to: SocketAddr,
        query: Query,
        timeout: Duration,
    ) -> Result<Response, QueryError> {
        let transaction = self.fresh_transaction();
        let wire = encode_message(&Message::Query {
            transaction: transaction.clone(),
            query,
        });
        // The socket of the destination's own family. A datagram cannot leave
        // an IPv4 socket for an IPv6 address, and a host with no IPv6 simply
        // cannot reach one -- said plainly here rather than surfacing as an
        // I/O error nobody can read.
        let socket = self.socket_for(to).ok_or_else(|| {
            QueryError::Io(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no socket of that address family on this host",
            ))
        })?;
        // Held across the send AND the read: the window in which a datagram
        // for somebody else's transaction would be thrown away is exactly the
        // window in which this one is reading.
        let _turn = self.turn.lock().await;
        socket.send_to(&wire, to).await.map_err(QueryError::Io)?;

        let deadline = tokio::time::Instant::now() + timeout;
        let mut buf = vec![0u8; MAX_BYTES_LEN];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(QueryError::TimedOut);
            }
            let received = match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
                Err(_) => return Err(QueryError::TimedOut),
                Ok(Err(e)) => return Err(QueryError::Io(e)),
                Ok(Ok((n, from))) => (n, from),
            };
            let (n, from) = received;
            if from != to {
                continue;
            }
            match decode_message(&buf[..n]) {
                Ok(Message::Response {
                    transaction: t,
                    response,
                }) if t == transaction => return Ok(response),
                Ok(Message::Error {
                    transaction: t,
                    code,
                    message,
                }) if t == transaction => {
                    return Err(QueryError::Refused {
                        code,
                        message: String::from_utf8_lossy(&message).into_owned(),
                    });
                }
                // Somebody else's transaction, or a query aimed at us. Neither
                // answers this question.
                Ok(_) => continue,
                Err(e) => {
                    // One malformed datagram from the address we asked is not
                    // proof the next one will be, and on this network it is not
                    // even unusual.
                    log::debug!("mainline: {from} sent something unreadable: {e}");
                    continue;
                }
            }
        }
    }

    /// Two random bytes, which is what every other client uses.
    fn fresh_transaction(&self) -> Vec<u8> {
        use rand_core::RngCore as _;
        let mut t = [0u8; 2];
        rand_core::OsRng.fill_bytes(&mut t);
        t.to_vec()
    }
}

/// A node id drawn at random.
///
/// NOT yet BEP 42, which asks that an id be derived from the node's external
/// address so that one host cannot cheaply occupy a chosen region of the
/// keyspace. Nodes that enforce it will treat this id as untrusted and keep it
/// out of their routing tables, which costs us reachability, not correctness:
/// queries are still answered. Deriving it needs the external address, which
/// needs a first query to learn — so it belongs after this, not in it.
pub fn random_node_id() -> NodeId {
    use rand_core::RngCore as _;
    let mut id = [0u8; 20];
    rand_core::OsRng.fill_bytes(&mut id);
    NodeId(id)
}

/// The addresses that answer for the DHT itself.
///
/// These are somebody's infrastructure, and it is worth being plain that
/// swapping this project's seeds for them is a trade rather than a cure: they
/// are a handful of hosts run by BitTorrent Inc, Transmission and others. What
/// makes the trade worth taking is that they are not OURS — nobody can be
/// served notice about a veil developer to have them taken down — and that
/// they are needed only until this node has met anybody at all. A cached node
/// from a previous run makes them unnecessary, which is the same shape as the
/// discovered-peer cache does for layer 5.
pub const PUBLIC_ROUTERS: &[&str] = &[
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "router.utorrent.com:6881",
    "dht.libtorrent.org:25401",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::krpc::{Message, NodeInfo};

    /// A socket that answers whatever it is told to, so the client can be
    /// tested without the real DHT.
    async fn responder(reply: impl Fn(Message) -> Option<Message> + Send + 'static) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind responder");
        let addr = socket.local_addr().expect("responder addr");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let Ok(message) = decode_message(&buf[..n]) else {
                    continue;
                };
                if let Some(answer) = reply(message) {
                    let _ = socket.send_to(&encode_message(&answer), from).await;
                }
            }
        });
        addr
    }

    fn echo_id(id: NodeId) -> impl Fn(Message) -> Option<Message> + Send + 'static {
        move |m| match m {
            Message::Query { transaction, .. } => Some(Message::Response {
                transaction,
                response: Response::Id { id },
            }),
            _ => None,
        }
    }

    #[tokio::test]
    async fn a_query_gets_its_own_answer_back() {
        let them = NodeId([0xBB; 20]);
        let addr = responder(echo_id(them)).await;
        let client = Client::bind(NodeId([0xAA; 20])).await.expect("bind client");
        let response = client
            .query(addr, Query::Ping { id: client.id() }, DEFAULT_QUERY_TIMEOUT)
            .await
            .expect("ping should be answered");
        assert_eq!(response.id(), them);
    }

    #[tokio::test]
    async fn an_answer_to_somebody_elses_question_is_not_taken_as_ours() {
        // The failure this prevents pairs a response to the wrong query, which
        // on an iterative lookup means walking off towards a node nobody asked
        // about.
        let them = NodeId([0xBB; 20]);
        let addr = responder(move |m| match m {
            Message::Query { .. } => Some(Message::Response {
                // A transaction we did not send.
                transaction: b"zz".to_vec(),
                response: Response::Id { id: them },
            }),
            _ => None,
        })
        .await;
        let client = Client::bind(NodeId([0xAA; 20])).await.expect("bind client");
        let result = client
            .query(
                addr,
                Query::Ping { id: client.id() },
                Duration::from_millis(600),
            )
            .await;
        assert!(
            matches!(result, Err(QueryError::TimedOut)),
            "a foreign transaction was accepted: {result:?}"
        );
    }

    #[tokio::test]
    async fn a_krpc_error_is_reported_as_a_refusal_not_as_silence() {
        let addr = responder(|m| match m {
            Message::Query { transaction, .. } => Some(Message::Error {
                transaction,
                code: 203,
                message: b"Protocol Error".to_vec(),
            }),
            _ => None,
        })
        .await;
        let client = Client::bind(NodeId([0xAA; 20])).await.expect("bind client");
        let result = client
            .query(addr, Query::Ping { id: client.id() }, DEFAULT_QUERY_TIMEOUT)
            .await;
        match result {
            Err(QueryError::Refused { code, ref message }) => {
                assert_eq!(code, 203);
                assert_eq!(message, "Protocol Error");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn silence_ends_in_a_timeout_rather_than_a_wait_forever() {
        // Most of a real lookup is spent here: the DHT is full of nodes that
        // have gone away without saying so.
        let addr = responder(|_| None).await;
        let client = Client::bind(NodeId([0xAA; 20])).await.expect("bind client");
        let started = std::time::Instant::now();
        let result = client
            .query(
                addr,
                Query::Ping { id: client.id() },
                Duration::from_millis(300),
            )
            .await;
        assert!(matches!(result, Err(QueryError::TimedOut)), "{result:?}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the timeout did not bound the wait: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn rubbish_from_the_right_address_does_not_end_the_wait() {
        // A node that sends a malformed datagram and then a good one is
        // ordinary on this network. Giving up on the first would lose the
        // answer that was coming.
        let them = NodeId([0xBB; 20]);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            if let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(b"not bencode at all", from).await;
                if let Ok(Message::Query { transaction, .. }) = decode_message(&buf[..n]) {
                    let _ = socket
                        .send_to(
                            &encode_message(&Message::Response {
                                transaction,
                                response: Response::Id { id: them },
                            }),
                            from,
                        )
                        .await;
                }
            }
        });
        let client = Client::bind(NodeId([0xAA; 20])).await.unwrap();
        let response = client
            .query(addr, Query::Ping { id: client.id() }, DEFAULT_QUERY_TIMEOUT)
            .await
            .expect("the good answer after the bad one should be taken");
        assert_eq!(response.id(), them);
    }

    #[tokio::test]
    async fn find_node_brings_back_nodes_in_the_compact_form() {
        let them = NodeId([0xBB; 20]);
        let given = NodeInfo {
            id: NodeId([0xCC; 20]),
            addr: "203.0.113.9:6881".parse().unwrap(),
        };
        let addr = responder(move |m| match m {
            Message::Query { transaction, .. } => Some(Message::Response {
                transaction,
                response: Response::Nodes {
                    id: them,
                    nodes: vec![given],
                },
            }),
            _ => None,
        })
        .await;
        let client = Client::bind(NodeId([0xAA; 20])).await.unwrap();
        let response = client
            .query(
                addr,
                Query::FindNode {
                    want_both: true,
                    id: client.id(),
                    target: NodeId([0xCC; 20]),
                },
                DEFAULT_QUERY_TIMEOUT,
            )
            .await
            .expect("find_node should be answered");
        match response {
            Response::Nodes { nodes, .. } => assert_eq!(nodes, vec![given]),
            other => panic!("expected nodes, got {other:?}"),
        }
    }

    #[test]
    fn a_random_id_is_twenty_bytes_and_not_the_same_one_twice() {
        let a = random_node_id();
        let b = random_node_id();
        assert_ne!(a, b, "the same id twice is not random");
        assert_ne!(a.0, [0u8; 20], "an all-zero id is not random either");
    }

    #[tokio::test]
    #[ignore = "talks to the real Mainline DHT; run with --ignored"]
    async fn the_real_dht_answers_what_this_client_sends() {
        // The only test here that proves the encoder against somebody ELSE'S
        // decoder. Everything above pairs our writer with our reader, which
        // agree by construction; a real router does not.
        let client = Client::bind(random_node_id()).await.expect("bind");
        let mut answered = Vec::new();
        for router in PUBLIC_ROUTERS {
            let Ok(mut addrs) = tokio::net::lookup_host(*router).await else {
                eprintln!("{router}: does not resolve");
                continue;
            };
            // One address per router: if the first v4 answer does not
            // work, the next router is a better bet than the same host again.
            if let Some(addr) = addrs.find(|a| a.is_ipv4()) {
                match client
                    .query(
                        addr,
                        Query::FindNode {
                            want_both: true,
                            id: client.id(),
                            target: client.id(),
                        },
                        Duration::from_secs(6),
                    )
                    .await
                {
                    Ok(Response::Nodes { id, nodes }) => {
                        eprintln!(
                            "{router} ({addr}) answered as {:02x?}… with {} node(s)",
                            &id.0[..4],
                            nodes.len()
                        );
                        assert!(!nodes.is_empty(), "{router} answered with no nodes");
                        for n in &nodes {
                            assert_ne!(n.addr.port(), 0, "a node with port 0 from {router}");
                        }
                        answered.push(*router);
                    }
                    Ok(other) => eprintln!("{router}: unexpected {other:?}"),
                    Err(e) => eprintln!("{router} ({addr}): {e}"),
                }
            }
        }
        assert!(
            !answered.is_empty(),
            "no public router answered a find_node — either this machine has no \
             UDP out, or what we send is not what they read"
        );
        eprintln!("routers that answered: {answered:?}");
    }
}
