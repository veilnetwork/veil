//! KRPC — the four queries BEP 5 defines, over [`crate::bencode`].
//!
//! # Looking like everyone else
//!
//! This layer's whole value is that veil traffic on the Mainline DHT is
//! indistinguishable from the millions of BitTorrent clients already there. So
//! the messages here are BEP 5 as written and nothing more: the same four
//! method names, the same argument keys, the same compact encodings.
//!
//! In particular there is no `v` (client version) key. It is optional, plenty
//! of clients omit it, and a veil-specific value in it would be a beacon
//! saying exactly which nodes to look at.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::bencode::{DecodeError, Value, bytes, dict};

/// A Mainline node id: 160 bits, unlike veil's own 256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub [u8; 20]);

impl NodeId {
    /// Kademlia distance — XOR, read as a big-endian number.
    pub fn distance(&self, other: &NodeId) -> [u8; 20] {
        let mut out = [0u8; 20];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self.0[i] ^ other.0[i];
        }
        out
    }
}

/// An entry of a `nodes` string: 20 bytes of id, 4 of address, 2 of port.
pub const COMPACT_NODE_LEN: usize = 26;
/// An entry of a `values` list: 4 bytes of address, 2 of port.
pub const COMPACT_PEER_LEN: usize = 6;
/// An entry of a `nodes6` string (BEP 32): 20 bytes of id, 16 of address, 2 of
/// port.
pub const COMPACT_NODE6_LEN: usize = 38;
/// An IPv6 entry of a `values` list (BEP 32): 16 bytes of address, 2 of port.
pub const COMPACT_PEER6_LEN: usize = 18;

/// A node as the wire carries it.
///
/// The address is family-agnostic because Mainline is two overlays sharing one
/// key space: BEP 5 carries IPv4 in `nodes`, BEP 32 carries IPv6 in `nodes6`,
/// and a response may hold both. Pinning this to `SocketAddrV4` is what made
/// the whole client IPv4-only, and the reason had never been written down --
/// it was simply the half that got implemented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub id: NodeId,
    pub addr: SocketAddr,
}

/// The four queries. Nothing else is sent, and anything else received is
/// answered with "method unknown" rather than parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query {
    Ping {
        id: NodeId,
    },
    FindNode {
        id: NodeId,
        target: NodeId,
        /// Ask for contacts of both families (BEP 32 `want: ["n4","n6"]`).
        ///
        /// PART OF THE MESSAGE, not something the encoder adds. A query
        /// decoded from a datagram that carried no `want` must re-encode
        /// without one, or this client's bytes differ from the BEP's own
        /// examples -- and a client whose bytes differ from the spec differs
        /// from every other client on the wire.
        want_both: bool,
    },
    GetPeers {
        id: NodeId,
        info_hash: NodeId,
        /// See [`Query::FindNode::want_both`].
        want_both: bool,
    },
    AnnouncePeer {
        id: NodeId,
        info_hash: NodeId,
        port: u16,
        /// When set, the receiver uses the source port of the datagram and
        /// ignores `port`. That is the right answer behind NAT, where the
        /// port we bound is not the port anyone can reach.
        implied_port: bool,
        token: Vec<u8>,
    },
}

/// What comes back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// `ping`, and `announce_peer`, answer with an id and nothing else.
    Id { id: NodeId },
    /// `find_node`, and a `get_peers` that knows no peers.
    Nodes { id: NodeId, nodes: Vec<NodeInfo> },
    /// `get_peers` with peers to give.
    Peers {
        id: NodeId,
        token: Vec<u8>,
        peers: Vec<SocketAddr>,
        /// A response may carry both; nodes are how the search continues.
        nodes: Vec<NodeInfo>,
    },
}

impl Response {
    /// The responder's own id, whichever shape the answer took.
    pub fn id(&self) -> NodeId {
        match self {
            Self::Id { id } | Self::Nodes { id, .. } | Self::Peers { id, .. } => *id,
        }
    }
}

/// A whole message, with the transaction id that pairs a response to a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Query {
        transaction: Vec<u8>,
        query: Query,
    },
    Response {
        transaction: Vec<u8>,
        response: Response,
    },
    Error {
        transaction: Vec<u8>,
        code: i64,
        message: Vec<u8>,
    },
}

/// Why a datagram was not a KRPC message we could act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KrpcError {
    /// Not bencode at all.
    Bencode(DecodeError),
    /// Bencode, but not shaped like a KRPC message.
    NotKrpc,
    /// A field that has to be exactly 20 bytes, or a compact string whose
    /// length is not a multiple of its entry size.
    BadLength,
    /// A query naming a method this client does not implement. Distinct from
    /// [`Self::NotKrpc`] because it has an answer: error code 204.
    UnknownMethod,
}

impl std::fmt::Display for KrpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bencode(e) => write!(f, "not bencode: {e}"),
            Self::NotKrpc => f.write_str("not a KRPC message"),
            Self::BadLength => f.write_str("a fixed-width field had the wrong width"),
            Self::UnknownMethod => f.write_str("unknown method"),
        }
    }
}

impl std::error::Error for KrpcError {}

fn node_id(value: Option<&Value>) -> Result<NodeId, KrpcError> {
    let raw = value.and_then(Value::as_bytes).ok_or(KrpcError::NotKrpc)?;
    raw.try_into().map(NodeId).map_err(|_| KrpcError::BadLength)
}

/// Parse a `nodes` string. Length must divide exactly: a trailing partial
/// entry means the sender and we disagree about the format, and guessing
/// which entries are real is how a routing table gets poisoned with rubbish.
pub fn parse_compact_nodes(raw: &[u8]) -> Result<Vec<NodeInfo>, KrpcError> {
    if !raw.len().is_multiple_of(COMPACT_NODE_LEN) {
        return Err(KrpcError::BadLength);
    }
    Ok(raw
        .chunks_exact(COMPACT_NODE_LEN)
        .map(|c| NodeInfo {
            id: NodeId(c[..20].try_into().expect("chunk is 26 bytes")),
            addr: socket_from(&c[20..26]),
        })
        .collect())
}

/// Parse a `values` entry (or a whole compact peer string).
pub fn parse_compact_peers(raw: &[u8]) -> Result<Vec<SocketAddr>, KrpcError> {
    if !raw.len().is_multiple_of(COMPACT_PEER_LEN) {
        return Err(KrpcError::BadLength);
    }
    Ok(raw
        .chunks_exact(COMPACT_PEER_LEN)
        .map(socket_from)
        .collect())
}

fn socket_from(six: &[u8]) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(six[0], six[1], six[2], six[3]),
        u16::from_be_bytes([six[4], six[5]]),
    ))
}

/// 16 bytes of address and 2 of port, as BEP 32 writes them.
fn socket6_from(eighteen: &[u8]) -> SocketAddr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&eighteen[..16]);
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(octets),
        u16::from_be_bytes([eighteen[16], eighteen[17]]),
        0,
        0,
    ))
}

/// Parse a `nodes6` string. Same shape as [`parse_compact_nodes`], sixteen
/// bytes of address instead of four.
pub fn parse_compact_nodes6(raw: &[u8]) -> Result<Vec<NodeInfo>, KrpcError> {
    if !raw.len().is_multiple_of(COMPACT_NODE6_LEN) {
        return Err(KrpcError::BadLength);
    }
    Ok(raw
        .chunks_exact(COMPACT_NODE6_LEN)
        .map(|c| NodeInfo {
            id: NodeId(c[..20].try_into().expect("chunk is 38 bytes")),
            addr: socket6_from(&c[20..38]),
        })
        .collect())
}

/// One `values` entry, whichever family it is.
///
/// A responder may mix them in one list, so length decides: six bytes is IPv4,
/// eighteen is IPv6, anything else is a disagreement about the format and is
/// refused rather than guessed at.
pub fn parse_compact_peer_entry(raw: &[u8]) -> Result<SocketAddr, KrpcError> {
    match raw.len() {
        COMPACT_PEER_LEN => Ok(socket_from(raw)),
        COMPACT_PEER6_LEN => Ok(socket6_from(raw)),
        _ => Err(KrpcError::BadLength),
    }
}

/// A node in its own family's compact form, or `None` for a family the caller
/// asked to encode into the wrong list.
fn compact_node(node: &NodeInfo) -> Option<[u8; COMPACT_NODE_LEN]> {
    let SocketAddr::V4(v4) = node.addr else {
        return None;
    };
    let mut out = [0u8; COMPACT_NODE_LEN];
    out[..20].copy_from_slice(&node.id.0);
    out[20..24].copy_from_slice(&v4.ip().octets());
    out[24..26].copy_from_slice(&v4.port().to_be_bytes());
    Some(out)
}

fn compact_node6(node: &NodeInfo) -> Option<[u8; COMPACT_NODE6_LEN]> {
    let SocketAddr::V6(v6) = node.addr else {
        return None;
    };
    let mut out = [0u8; COMPACT_NODE6_LEN];
    out[..20].copy_from_slice(&node.id.0);
    out[20..36].copy_from_slice(&v6.ip().octets());
    out[36..38].copy_from_slice(&v6.port().to_be_bytes());
    Some(out)
}

/// Both compact node strings for a set of nodes: `nodes` (IPv4) and `nodes6`
/// (IPv6). Either may be empty, and an empty one is simply not written.
fn compact_node_strings(nodes: &[NodeInfo]) -> (Vec<u8>, Vec<u8>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for n in nodes {
        if let Some(c) = compact_node(n) {
            v4.extend_from_slice(&c);
        } else if let Some(c) = compact_node6(n) {
            v6.extend_from_slice(&c);
        }
    }
    (v4, v6)
}

/// One `values` entry, in whichever family the address is.
fn compact_peer_entry(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut six = [0u8; COMPACT_PEER_LEN];
            six[..4].copy_from_slice(&v4.ip().octets());
            six[4..].copy_from_slice(&v4.port().to_be_bytes());
            six.to_vec()
        }
        SocketAddr::V6(v6) => {
            let mut eighteen = [0u8; COMPACT_PEER6_LEN];
            eighteen[..16].copy_from_slice(&v6.ip().octets());
            eighteen[16..].copy_from_slice(&v6.port().to_be_bytes());
            eighteen.to_vec()
        }
    }
}

/// Decode one datagram.
pub fn decode_message(datagram: &[u8]) -> Result<Message, KrpcError> {
    let value = crate::bencode::decode(datagram).map_err(KrpcError::Bencode)?;
    let transaction = value
        .get(b"t")
        .and_then(Value::as_bytes)
        .ok_or(KrpcError::NotKrpc)?
        .to_vec();

    match value.get(b"y").and_then(Value::as_bytes) {
        Some(b"q") => {
            let args = value.get(b"a").ok_or(KrpcError::NotKrpc)?;
            let id = node_id(args.get(b"id"))?;
            let query = match value.get(b"q").and_then(Value::as_bytes) {
                Some(b"ping") => Query::Ping { id },
                Some(b"find_node") => Query::FindNode {
                    want_both: wants_both(args),
                    id,
                    target: node_id(args.get(b"target"))?,
                },
                Some(b"get_peers") => Query::GetPeers {
                    want_both: wants_both(args),
                    id,
                    info_hash: node_id(args.get(b"info_hash"))?,
                },
                Some(b"announce_peer") => Query::AnnouncePeer {
                    id,
                    info_hash: node_id(args.get(b"info_hash"))?,
                    port: u16::try_from(
                        args.get(b"port")
                            .and_then(Value::as_int)
                            .unwrap_or(0)
                            .max(0),
                    )
                    .map_err(|_| KrpcError::BadLength)?,
                    implied_port: args.get(b"implied_port").and_then(Value::as_int) == Some(1),
                    token: args
                        .get(b"token")
                        .and_then(Value::as_bytes)
                        .ok_or(KrpcError::NotKrpc)?
                        .to_vec(),
                },
                Some(_) => return Err(KrpcError::UnknownMethod),
                None => return Err(KrpcError::NotKrpc),
            };
            Ok(Message::Query { transaction, query })
        }
        Some(b"r") => {
            let r = value.get(b"r").ok_or(KrpcError::NotKrpc)?;
            let id = node_id(r.get(b"id"))?;
            // BOTH families. BEP 32 puts IPv6 contacts in `nodes6` beside the
            // IPv4 ones in `nodes`, and a responder asked for both answers with
            // both. Reading only `nodes` is what made this client IPv4-only.
            let mut nodes = match r.get(b"nodes").and_then(Value::as_bytes) {
                Some(raw) => parse_compact_nodes(raw)?,
                None => Vec::new(),
            };
            if let Some(raw) = r.get(b"nodes6").and_then(Value::as_bytes) {
                nodes.extend(parse_compact_nodes6(raw)?);
            }
            // The TOKEN decides, not `values`. BEP 5 answers a get_peers with
            // a token and `values` when it knows peers, and with a token and
            // `nodes` when it does not -- and the token is the half that
            // matters, because it is what an announce has to carry. Requiring
            // `values` before believing a token dropped every token the live
            // DHT sent: twenty-one real nodes answered and this read none of
            // them as having offered one.
            //
            // `values` is a LIST of per-peer strings, not one long string. A
            // reader that accepts either is a reader two implementations can
            // disagree with. Each entry is six bytes for IPv4 or eighteen for
            // IPv6, and one list may hold both.
            let peers = match r.get(b"values") {
                Some(values) => {
                    let list = values.as_list().ok_or(KrpcError::NotKrpc)?;
                    let mut peers = Vec::with_capacity(list.len());
                    for entry in list {
                        let raw = entry.as_bytes().ok_or(KrpcError::NotKrpc)?;
                        peers.push(parse_compact_peer_entry(raw)?);
                    }
                    peers
                }
                None => Vec::new(),
            };
            match r.get(b"token").and_then(Value::as_bytes) {
                Some(token) => Ok(Message::Response {
                    transaction,
                    response: Response::Peers {
                        id,
                        token: token.to_vec(),
                        peers,
                        nodes,
                    },
                }),
                None if !nodes.is_empty() => Ok(Message::Response {
                    transaction,
                    response: Response::Nodes { id, nodes },
                }),
                None => Ok(Message::Response {
                    transaction,
                    response: Response::Id { id },
                }),
            }
        }
        Some(b"e") => {
            let list = value
                .get(b"e")
                .and_then(Value::as_list)
                .ok_or(KrpcError::NotKrpc)?;
            let code = list
                .first()
                .and_then(Value::as_int)
                .ok_or(KrpcError::NotKrpc)?;
            let message = list
                .get(1)
                .and_then(Value::as_bytes)
                .unwrap_or(b"")
                .to_vec();
            Ok(Message::Error {
                transaction,
                code,
                message,
            })
        }
        _ => Err(KrpcError::NotKrpc),
    }
}

/// Encode one message.
/// Whether a decoded query asked for both families.
fn wants_both(args: &Value) -> bool {
    args.get(b"want").and_then(Value::as_list).is_some_and(|l| {
        let has = |w: &[u8]| l.iter().any(|v| v.as_bytes() == Some(w));
        has(b"n4") && has(b"n6")
    })
}

/// `want` asking for contacts of both families, as BEP 32 spells it.
fn want_list() -> Value {
    Value::List(vec![
        Value::Bytes(b"n4".to_vec()),
        Value::Bytes(b"n6".to_vec()),
    ])
}

pub fn encode_message(message: &Message) -> Vec<u8> {
    let value = match message {
        Message::Query { transaction, query } => {
            let (method, args): (&[u8], Value) = match query {
                Query::Ping { id } => (b"ping", dict([(b"id", bytes(id.0))])),
                // `want` is how BEP 32 asks for the other family. Without it a
                // responder answers with contacts of the family the query
                // arrived over and nothing else, so a v4-only socket would
                // never hear of a v6 node however many of them there are.
                // Asking for both from both sockets is what makes the two
                // overlays one search.
                Query::FindNode {
                    id,
                    target,
                    want_both,
                } => (
                    b"find_node",
                    if *want_both {
                        dict([
                            (b"id", bytes(id.0)),
                            (b"target", bytes(target.0)),
                            (b"want", want_list()),
                        ])
                    } else {
                        dict([(b"id", bytes(id.0)), (b"target", bytes(target.0))])
                    },
                ),
                Query::GetPeers {
                    id,
                    info_hash,
                    want_both,
                } => (
                    b"get_peers",
                    if *want_both {
                        dict([
                            (b"id", bytes(id.0)),
                            (b"info_hash", bytes(info_hash.0)),
                            (b"want", want_list()),
                        ])
                    } else {
                        dict([(b"id", bytes(id.0)), (b"info_hash", bytes(info_hash.0))])
                    },
                ),
                Query::AnnouncePeer {
                    id,
                    info_hash,
                    port,
                    implied_port,
                    token,
                } => (
                    b"announce_peer",
                    dict([
                        (b"id", bytes(id.0)),
                        (b"implied_port", Value::Int(i64::from(*implied_port))),
                        (b"info_hash", bytes(info_hash.0)),
                        (b"port", Value::Int(i64::from(*port))),
                        (b"token", bytes(token)),
                    ]),
                ),
            };
            dict([
                (b"a", args),
                (b"q", bytes(method)),
                (b"t", bytes(transaction)),
                (b"y", bytes("q")),
            ])
        }
        Message::Response {
            transaction,
            response,
        } => {
            let r = match response {
                Response::Id { id } => dict([(b"id", bytes(id.0))]),
                Response::Nodes { id, nodes } => {
                    let (flat, flat6) = compact_node_strings(nodes);
                    if flat6.is_empty() {
                        dict([(b"id", bytes(id.0)), (b"nodes", Value::Bytes(flat))])
                    } else if flat.is_empty() {
                        dict([(b"id", bytes(id.0)), (b"nodes6", Value::Bytes(flat6))])
                    } else {
                        dict([
                            (b"id", bytes(id.0)),
                            (b"nodes", Value::Bytes(flat)),
                            (b"nodes6", Value::Bytes(flat6)),
                        ])
                    }
                }
                Response::Peers {
                    id,
                    token,
                    peers,
                    nodes,
                } => {
                    let values = Value::List(
                        peers
                            .iter()
                            .map(|p| Value::Bytes(compact_peer_entry(p)))
                            .collect(),
                    );
                    let (flat, _flat6) = compact_node_strings(nodes);
                    // `values` is written only when there are peers, and
                    // `nodes` only when there are nodes -- an empty list of
                    // either is a key a real client does not send.
                    match (nodes.is_empty(), peers.is_empty()) {
                        (true, true) => dict([(b"id", bytes(id.0)), (b"token", bytes(token))]),
                        (true, false) => dict([
                            (b"id", bytes(id.0)),
                            (b"token", bytes(token)),
                            (b"values", values),
                        ]),
                        (false, true) => dict([
                            (b"id", bytes(id.0)),
                            (b"nodes", Value::Bytes(flat)),
                            (b"token", bytes(token)),
                        ]),
                        (false, false) => dict([
                            (b"id", bytes(id.0)),
                            (b"nodes", Value::Bytes(flat)),
                            (b"token", bytes(token)),
                            (b"values", values),
                        ]),
                    }
                }
            };
            dict([(b"r", r), (b"t", bytes(transaction)), (b"y", bytes("r"))])
        }
        Message::Error {
            transaction,
            code,
            message,
        } => dict([
            (
                b"e",
                Value::List(vec![Value::Int(*code), Value::Bytes(message.clone())]),
            ),
            (b"t", bytes(transaction)),
            (b"y", bytes("e")),
        ]),
    };
    crate::bencode::encode(&value)
}

#[cfg(test)]
mod tests {

    #[test]
    fn ipv6_contacts_survive_the_wire_in_both_directions() {
        use std::net::Ipv6Addr;
        // BEP 32 is the other half of Mainline: the same key space reached
        // over IPv6, with `nodes6` beside `nodes` and eighteen-byte `values`
        // entries beside the six-byte ones. Reading only the v4 halves is what
        // made this client v4-only, and nothing had ever said so.
        let v6 = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            6881,
            0,
            0,
        ));
        let v4: SocketAddr = "203.0.113.9:6881".parse().unwrap();

        // A node string of each family, round-tripped through the codec.
        let nodes = vec![
            NodeInfo {
                id: NodeId([1u8; 20]),
                addr: v4,
            },
            NodeInfo {
                id: NodeId([2u8; 20]),
                addr: v6,
            },
        ];
        let wire = encode_message(&Message::Response {
            transaction: b"aa".to_vec(),
            response: Response::Nodes {
                id: NodeId([9u8; 20]),
                nodes: nodes.clone(),
            },
        });
        let Message::Response {
            response: Response::Nodes { nodes: back, .. },
            ..
        } = decode_message(&wire).expect("decodes")
        else {
            panic!("not a nodes response");
        };
        assert_eq!(back.len(), 2, "a family was dropped on the way through");
        assert!(
            back.iter().any(|n| n.addr == v6),
            "the IPv6 contact was lost"
        );
        assert!(
            back.iter().any(|n| n.addr == v4),
            "the IPv4 contact was lost"
        );

        // `values` may mix families in one list, and length is what says which.
        let wire = encode_message(&Message::Response {
            transaction: b"bb".to_vec(),
            response: Response::Peers {
                id: NodeId([9u8; 20]),
                token: b"t".to_vec(),
                peers: vec![v4, v6],
                nodes: Vec::new(),
            },
        });
        let Message::Response {
            response: Response::Peers { peers, .. },
            ..
        } = decode_message(&wire).expect("decodes")
        else {
            panic!("not a peers response");
        };
        assert_eq!(peers, vec![v4, v6], "a mixed values list did not survive");

        // Sizes are the BEP's, not ours.
        assert_eq!(COMPACT_NODE6_LEN, 38);
        assert_eq!(COMPACT_PEER6_LEN, 18);
        // An entry of neither length is a disagreement about the format and is
        // refused rather than guessed at.
        assert!(parse_compact_peer_entry(&[0u8; 7]).is_err());
    }

    #[test]
    fn a_query_carries_want_only_when_it_was_asked_for() {
        // `want` is part of the message. Adding it at encode time made this
        // client's bytes differ from the BEP's own examples -- and a client
        // whose bytes differ from the spec differs from every other client on
        // the wire, which is the one thing a blending-in protocol must not do.
        let plain = encode_message(&Message::Query {
            transaction: b"aa".to_vec(),
            query: Query::FindNode {
                id: NodeId([1u8; 20]),
                target: NodeId([2u8; 20]),
                want_both: false,
            },
        });
        assert!(
            !plain.windows(4).any(|w| w == b"want"),
            "a query that did not ask for both families carried `want` anyway"
        );

        let asking = encode_message(&Message::Query {
            transaction: b"aa".to_vec(),
            query: Query::GetPeers {
                id: NodeId([1u8; 20]),
                info_hash: NodeId([2u8; 20]),
                want_both: true,
            },
        });
        assert!(
            asking.windows(4).any(|w| w == b"want"),
            "asking for both families produced no `want`, so no responder \
             will ever answer with IPv6 contacts"
        );
        // ...and it survives a round trip rather than being re-invented.
        let Message::Query {
            query: Query::GetPeers { want_both, .. },
            ..
        } = decode_message(&asking).expect("decodes")
        else {
            panic!("not a get_peers");
        };
        assert!(want_both, "the decoder did not see the `want` we wrote");
    }
    use super::*;

    fn id(b: u8) -> NodeId {
        NodeId([b; 20])
    }

    fn round_trip(message: Message) {
        let wire = encode_message(&message);
        let back =
            decode_message(&wire).unwrap_or_else(|e| panic!("{message:?} did not survive: {e}"));
        assert_eq!(back, message);
        assert_eq!(
            encode_message(&back),
            wire,
            "encoding is not stable across a round trip"
        );
    }

    #[test]
    fn every_query_survives_the_wire() {
        round_trip(Message::Query {
            transaction: b"aa".to_vec(),
            query: Query::Ping { id: id(1) },
        });
        round_trip(Message::Query {
            transaction: b"bb".to_vec(),
            query: Query::FindNode {
                want_both: false,
                id: id(1),
                target: id(2),
            },
        });
        round_trip(Message::Query {
            transaction: b"cc".to_vec(),
            query: Query::GetPeers {
                want_both: false,
                id: id(1),
                info_hash: id(3),
            },
        });
        round_trip(Message::Query {
            transaction: b"dd".to_vec(),
            query: Query::AnnouncePeer {
                id: id(1),
                info_hash: id(3),
                port: 6881,
                implied_port: true,
                token: b"aoeusnth".to_vec(),
            },
        });
    }

    #[test]
    fn every_response_survives_the_wire() {
        let node = NodeInfo {
            id: id(9),
            addr: "192.0.2.7:6881".parse().unwrap(),
        };
        round_trip(Message::Response {
            transaction: b"aa".to_vec(),
            response: Response::Id { id: id(1) },
        });
        round_trip(Message::Response {
            transaction: b"bb".to_vec(),
            response: Response::Nodes {
                id: id(1),
                nodes: vec![node, node],
            },
        });
        round_trip(Message::Response {
            transaction: b"cc".to_vec(),
            response: Response::Peers {
                id: id(1),
                token: b"tok".to_vec(),
                peers: vec!["198.51.100.3:51413".parse().unwrap()],
                nodes: Vec::new(),
            },
        });
        round_trip(Message::Response {
            transaction: b"dd".to_vec(),
            response: Response::Peers {
                id: id(1),
                token: b"tok".to_vec(),
                peers: vec!["198.51.100.3:51413".parse().unwrap()],
                nodes: vec![node],
            },
        });
        round_trip(Message::Error {
            transaction: b"ee".to_vec(),
            code: 201,
            message: b"A Generic Error Ocurred".to_vec(),
        });
    }

    #[test]
    fn a_get_peers_answer_with_a_token_and_no_peers_still_carries_the_token() {
        // What the live DHT actually sends when it knows no peers for a
        // target: a token AND nodes, no `values`. Requiring `values` before
        // believing the token read twenty-one real answers as having offered
        // none, and an announce needs a token.
        let node = NodeInfo {
            id: id(9),
            addr: "192.0.2.7:6881".parse().unwrap(),
        };
        round_trip(Message::Response {
            transaction: b"aa".to_vec(),
            response: Response::Peers {
                id: id(1),
                token: b"tok".to_vec(),
                peers: Vec::new(),
                nodes: vec![node],
            },
        });
        // And with neither peers nor nodes, which a saturated node may send.
        round_trip(Message::Response {
            transaction: b"aa".to_vec(),
            response: Response::Peers {
                id: id(1),
                token: b"tok".to_vec(),
                peers: Vec::new(),
                nodes: Vec::new(),
            },
        });
        // A response with nodes and NO token stays what it is: a find_node
        // answer, which cannot be announced to.
        let wire = crate::bencode::encode(&dict([
            (
                b"r",
                dict([
                    (b"id", bytes([1u8; 20])),
                    (b"nodes", Value::Bytes(vec![0u8; COMPACT_NODE_LEN])),
                ]),
            ),
            (b"t", bytes("aa")),
            (b"y", bytes("r")),
        ]));
        assert!(matches!(
            decode_message(&wire),
            Ok(Message::Response {
                response: Response::Nodes { .. },
                ..
            })
        ));
    }

    #[test]
    fn the_beps_own_examples_parse_and_re_encode_byte_for_byte() {
        // If our bytes differ from the BEP's, they differ from every other
        // client's, and this layer's whole value is not being tellable apart.
        let cases: &[&[u8]] = &[
            b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe",
            b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re",
            b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe",
            b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe",
            b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee",
        ];
        for wire in cases {
            let msg = decode_message(wire)
                .unwrap_or_else(|e| panic!("{:?}: {e}", String::from_utf8_lossy(wire)));
            assert_eq!(
                encode_message(&msg),
                *wire,
                "re-encoding changed {:?}",
                String::from_utf8_lossy(wire)
            );
        }
    }

    #[test]
    fn a_compact_string_with_a_partial_entry_is_refused_whole() {
        // Guessing which of the entries are real is how a routing table fills
        // with rubbish somebody chose.
        assert!(parse_compact_nodes(&[0u8; COMPACT_NODE_LEN]).is_ok());
        assert!(parse_compact_nodes(&[0u8; COMPACT_NODE_LEN * 3]).is_ok());
        assert!(parse_compact_nodes(&[]).is_ok(), "empty is a real answer");
        for bad in [1, 25, 27, COMPACT_NODE_LEN * 2 + 1] {
            assert_eq!(
                parse_compact_nodes(&vec![0u8; bad]).err(),
                Some(KrpcError::BadLength),
                "{bad} bytes was accepted as nodes"
            );
        }
        assert!(parse_compact_peers(&[0u8; COMPACT_PEER_LEN * 2]).is_ok());
        for bad in [1, 5, 7] {
            assert_eq!(
                parse_compact_peers(&vec![0u8; bad]).err(),
                Some(KrpcError::BadLength),
                "{bad} bytes was accepted as peers"
            );
        }
    }

    #[test]
    fn a_compact_node_reads_the_address_the_way_the_wire_wrote_it() {
        let mut raw = [0u8; COMPACT_NODE_LEN];
        raw[..20].copy_from_slice(&[0xAB; 20]);
        raw[20..24].copy_from_slice(&[203, 0, 113, 42]);
        raw[24..26].copy_from_slice(&6881u16.to_be_bytes());
        let parsed = parse_compact_nodes(&raw).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, NodeId([0xAB; 20]));
        assert_eq!(parsed[0].addr, "203.0.113.42:6881".parse().unwrap());
        // Big-endian, not little: 6881 must not come back as 57371.
        assert_eq!(parsed[0].addr.port(), 6881);
    }

    #[test]
    fn an_id_that_is_not_twenty_bytes_is_refused() {
        // A shorter id would silently become a different node; a longer one
        // would be truncated into somebody else's.
        for len in [0usize, 19, 21, 32] {
            let wire = crate::bencode::encode(&dict([
                (b"a", dict([(b"id", Value::Bytes(vec![7u8; len]))])),
                (b"q", bytes("ping")),
                (b"t", bytes("aa")),
                (b"y", bytes("q")),
            ]));
            assert_eq!(
                decode_message(&wire).err(),
                Some(KrpcError::BadLength),
                "a {len}-byte id was accepted"
            );
        }
    }

    #[test]
    fn a_method_we_do_not_implement_is_named_as_such_and_not_guessed_at() {
        // It has an answer -- error 204 -- which is why it is not lumped in
        // with "this is not KRPC".
        let wire = crate::bencode::encode(&dict([
            (b"a", dict([(b"id", bytes([1u8; 20]))])),
            (b"q", bytes("put")),
            (b"t", bytes("aa")),
            (b"y", bytes("q")),
        ]));
        assert_eq!(decode_message(&wire).err(), Some(KrpcError::UnknownMethod));
    }

    #[test]
    fn rubbish_is_refused_and_none_of_it_panics() {
        let real = encode_message(&Message::Query {
            transaction: b"aa".to_vec(),
            query: Query::GetPeers {
                want_both: false,
                id: id(1),
                info_hash: id(2),
            },
        });
        assert!(decode_message(&real).is_ok());
        // Every prefix of a real message.
        for cut in 0..real.len() {
            assert!(
                decode_message(&real[..cut]).is_err(),
                "a message cut at {cut} was accepted"
            );
        }
        // And things that are bencode but not KRPC.
        for not_krpc in [
            &b"i1e"[..],
            b"le",
            b"de",
            b"d1:t2:aae",                 // no `y`
            b"d1:y1:qe",                  // no `t`
            b"d1:t2:aa1:y1:xe",           // unknown `y`
            b"d1:q4:ping1:t2:aa1:y1:qe",  // query with no `a`
            b"d1:t2:aa1:y1:re",           // response with no `r`
            b"d1:eli201ee1:t2:aa1:y1:ee", // error list missing its text
        ] {
            let _ = decode_message(not_krpc);
        }
        assert!(
            decode_message(b"d1:t2:aae").is_err(),
            "a message with no `y`"
        );
        assert!(
            decode_message(b"d1:y1:qe").is_err(),
            "a message with no `t`"
        );
        assert!(
            decode_message(b"d1:q4:ping1:t2:aa1:y1:qe").is_err(),
            "a query with no arguments"
        );
        // An error whose text is missing is still an error, not a crash.
        assert!(matches!(
            decode_message(b"d1:eli201ee1:t2:aa1:y1:ee"),
            Ok(Message::Error { code: 201, .. })
        ));
    }

    #[test]
    fn distance_is_xor_and_a_node_is_nearest_to_itself() {
        assert_eq!(id(0xFF).distance(&id(0xFF)), [0u8; 20]);
        assert_eq!(id(0x00).distance(&id(0xFF)), [0xFFu8; 20]);
        // Symmetric, which Kademlia requires and a subtraction would not be.
        assert_eq!(id(0x0F).distance(&id(0xF0)), id(0xF0).distance(&id(0x0F)));
    }

    #[test]
    fn nothing_we_send_carries_a_client_version() {
        // A `v` key with a veil-specific value would be a beacon saying which
        // nodes on the DHT to look at. Omitting it is ordinary; plenty of
        // clients do.
        for message in [
            Message::Query {
                transaction: b"aa".to_vec(),
                query: Query::Ping { id: id(1) },
            },
            Message::Response {
                transaction: b"aa".to_vec(),
                response: Response::Id { id: id(1) },
            },
        ] {
            let wire = encode_message(&message);
            let value = crate::bencode::decode(&wire).unwrap();
            assert!(
                value.get(b"v").is_none(),
                "a client-version key reached the wire: {:?}",
                String::from_utf8_lossy(&wire)
            );
        }
    }
}
