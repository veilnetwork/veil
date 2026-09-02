//! A client for BitTorrent's Mainline DHT.
//!
//! Bootstrap layers 1 to 4 all end at somebody's infrastructure — a seed list
//! compiled in, an HTTPS URL someone hosts, a DNS domain someone owns. Layer 6
//! ends at the wire in the building and cannot leave it. This is the layer for
//! the space between: a rendezvous on a network of millions of nodes that no
//! one operates, no one can be served notice about, and no one can take down
//! without taking down BitTorrent.
//!
//! Nothing here is veil-specific. It speaks BEP 5 as written, because a client
//! that speaks it differently is a client that can be told apart from the
//! millions.

pub mod bencode;
pub mod client;
pub mod endpoint;
pub mod krpc;
pub mod lookup;
pub mod rendezvous;
