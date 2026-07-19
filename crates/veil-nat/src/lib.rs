//! NAT helpers — external-address (STUN-like) discovery and `NatCandidate`
//! ⇄ `SocketAddr` conversion.
//!
//! A node asks a core/gateway peer "what address do you see my connection
//! coming from?" ([`ExternalAddrDiscovery`]); the peer echoes the observed
//! external `(IP, port)` back in a `NAT_PROBE_REPLY`. [`candidate_to_socket_addr`]
//! decodes the `NatCandidate`s carried in those replies into usable addresses.
//!
//! ## History
//!
//! The original, unwired `NatPuncher` was removed. The replacement in
//! [`udp_punch`] is deliberately smaller: one fixed-size anti-amplification
//! reflection packet and a token-authenticated simultaneous-open primitive.
//! It owns no routing policy and is usable with the existing E2E candidate
//! signaling before the punched socket is promoted into QUIC.

pub mod discovery;
pub mod udp_punch;

pub use discovery::{ExternalAddrDiscovery, candidate_to_socket_addr, socket_addr_to_candidate};
pub use udp_punch::{
    DEFAULT_UDP_REFLECTOR_PORT, UDP_PUNCH_PACKET_LEN, UdpReflectorAdvertisement,
    discover_udp_mapping, discover_udp_mapping_any, discover_udp_mapping_any_for_punch,
    is_public_punch_addr, parse_udp_reflector_advertisement, punch_udp, serve_udp_reflector,
    udp_reflector_advertisement, udp_reflector_endpoint_advertisement,
};
