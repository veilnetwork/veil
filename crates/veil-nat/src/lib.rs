//! NAT traversal — UDP hole punching + relay fallback.
//!
//! ## Architecture
//!
//! 1. **External address discovery** ([`ExternalAddrDiscovery`]): A node
//!    contacts a core node and learns its external `(IP, port)` from the core's
//!    perspective (STUN-like).
//!
//! 2. **Candidate exchange** ([`NatPuncher`]): Alice sends
//!    `NAT_PROBE_REQUEST` with her candidates through the veil (via core).
//!    Bob receives it, replies with `NAT_PROBE_REPLY` carrying his own candidates.
//!
//! 3. **Hole punching** ([`NatPuncher::punch`]): Both sides simultaneously send
//!    UDP QUIC handshake packets to all candidates. The first successful QUIC
//!    connection becomes the direct path.
//!
//! 4. **Relay fallback** ([`RelayFallback`]): If punching fails within a
//!    deadline, `NAT_RELAY_REQUEST` is sent to a core node which opens a
//!    `FORWARD` tunnel between the two leaf nodes.

pub mod coordinator;
pub mod discovery;
pub mod puncher;
pub mod relay;

pub use coordinator::{NatCoordinator, NatResult, NatState};
pub use discovery::{ExternalAddrDiscovery, candidate_to_socket_addr};
pub use puncher::{CandidateList, NatPuncher, PunchResult};
pub use relay::RelayFallback;
