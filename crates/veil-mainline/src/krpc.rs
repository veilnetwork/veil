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

use std::net::{Ipv4Addr, SocketAddrV4};

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

/// A node as the wire carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub id: NodeId,
    pub addr: SocketAddrV4,
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
    },
    GetPeers {
        id: NodeId,
        info_hash: NodeId,
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
        peers: Vec<SocketAddrV4>,
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
pub fn parse_compact_peers(raw: &[u8]) -> Result<Vec<SocketAddrV4>, KrpcError> {
    if !raw.len().is_multiple_of(COMPACT_PEER_LEN) {
        return Err(KrpcError::BadLength);
    }
    Ok(raw
        .chunks_exact(COMPACT_PEER_LEN)
        .map(socket_from)
        .collect())
}

fn socket_from(six: &[u8]) -> SocketAddrV4 {
    SocketAddrV4::new(
        Ipv4Addr::new(six[0], six[1], six[2], six[3]),
        u16::from_be_bytes([six[4], six[5]]),
    )
}

fn compact_node(node: &NodeInfo) -> [u8; COMPACT_NODE_LEN] {
    let mut out = [0u8; COMPACT_NODE_LEN];
    out[..20].copy_from_slice(&node.id.0);
    out[20..24].copy_from_slice(&node.addr.ip().octets());
    out[24..26].copy_from_slice(&node.addr.port().to_be_bytes());
    out
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
                    id,
                    target: node_id(args.get(b"target"))?,
                },
                Some(b"get_peers") => Query::GetPeers {
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
            let nodes = match r.get(b"nodes").and_then(Value::as_bytes) {
                Some(raw) => parse_compact_nodes(raw)?,
                None => Vec::new(),
            };
            // `values` is a LIST of 6-byte strings, not one long string. A
            // reader that accepts either is a reader two implementations can
            // disagree with.
            match (r.get(b"values"), r.get(b"token").and_then(Value::as_bytes)) {
                (Some(values), Some(token)) => {
                    let list = values.as_list().ok_or(KrpcError::NotKrpc)?;
                    let mut peers = Vec::with_capacity(list.len());
                    for entry in list {
                        let raw = entry.as_bytes().ok_or(KrpcError::NotKrpc)?;
                        peers.extend(parse_compact_peers(raw)?);
                    }
                    Ok(Message::Response {
                        transaction,
                        response: Response::Peers {
                            id,
                            token: token.to_vec(),
                            peers,
                            nodes,
                        },
                    })
                }
                _ if !nodes.is_empty() => Ok(Message::Response {
                    transaction,
                    response: Response::Nodes { id, nodes },
                }),
                _ => Ok(Message::Response {
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
pub fn encode_message(message: &Message) -> Vec<u8> {
    let value = match message {
        Message::Query { transaction, query } => {
            let (method, args): (&[u8], Value) = match query {
                Query::Ping { id } => (b"ping", dict([(b"id", bytes(id.0))])),
                Query::FindNode { id, target } => (
                    b"find_node",
                    dict([(b"id", bytes(id.0)), (b"target", bytes(target.0))]),
                ),
                Query::GetPeers { id, info_hash } => (
                    b"get_peers",
                    dict([(b"id", bytes(id.0)), (b"info_hash", bytes(info_hash.0))]),
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
                    let mut flat = Vec::with_capacity(nodes.len() * COMPACT_NODE_LEN);
                    for n in nodes {
                        flat.extend_from_slice(&compact_node(n));
                    }
                    dict([(b"id", bytes(id.0)), (b"nodes", Value::Bytes(flat))])
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
                            .map(|p| {
                                let mut six = [0u8; COMPACT_PEER_LEN];
                                six[..4].copy_from_slice(&p.ip().octets());
                                six[4..].copy_from_slice(&p.port().to_be_bytes());
                                Value::Bytes(six.to_vec())
                            })
                            .collect(),
                    );
                    let mut flat = Vec::with_capacity(nodes.len() * COMPACT_NODE_LEN);
                    for n in nodes {
                        flat.extend_from_slice(&compact_node(n));
                    }
                    if nodes.is_empty() {
                        dict([
                            (b"id", bytes(id.0)),
                            (b"token", bytes(token)),
                            (b"values", values),
                        ])
                    } else {
                        dict([
                            (b"id", bytes(id.0)),
                            (b"nodes", Value::Bytes(flat)),
                            (b"token", bytes(token)),
                            (b"values", values),
                        ])
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
                id: id(1),
                target: id(2),
            },
        });
        round_trip(Message::Query {
            transaction: b"cc".to_vec(),
            query: Query::GetPeers {
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
