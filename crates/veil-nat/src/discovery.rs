//! STUN-like external address discovery.
//!
//! A node asks a core peer "what address do you see my connection coming from?"
//! The core echoes back the observed remote `SocketAddr`. This is the node's
//! best guess at its external NAT-mapped address.
//!
//! Wire encoding: the core responds with a `NAT_PROBE_REPLY` that has a single
//! candidate carrying the observed external address.

use std::net::SocketAddr;

use veil_proto::{NatCandidate, NatProbeReplyPayload, NatProbeRequestPayload};

// ── ExternalAddrDiscovery ─────────────────────────────────────────────────────

/// Encapsulates the result of an external address discovery round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAddrInfo {
    /// The externally-observed `(IP, port)` of the requesting node.
    pub external_addr: SocketAddr,
    /// Session token echoed from the request so callers can match replies.
    pub session_token: u32,
}

/// Builds a `NAT_PROBE_REQUEST` payload for external-addr discovery.
///
/// The payload contains a single "local" candidate (the node's best guess at
/// its local address) plus the session token. The responder (Core, Gateway, or
/// Relay-role node) will reply with a single-candidate `NAT_PROBE_REPLY`
/// carrying the observed external address.
///
/// # Local-mesh support
///
/// A Gateway with the `IS_RELAY` flag can act as a STUN echo server
/// for leaf nodes in an internet-isolated mesh: it observes the sender's
/// remote address from the veil session and echoes it back. No changes to
/// the request format are required — the same `build_request` / `parse_reply`
/// round-trip works regardless of whether the responder is a global Core or a
/// local-mesh Gateway.
pub struct ExternalAddrDiscovery;

impl ExternalAddrDiscovery {
    /// Build the probe request to send toward a core node.
    pub fn build_request(
        local_node_id: [u8; 32],
        local_addr: SocketAddr,
        session_token: u32,
    ) -> NatProbeRequestPayload {
        // STUN-echo legacy mode → target_node_id is the
        // sentinel `[0; 32]`. The receiver will respond to the SENDER
        // with whatever srflx address it observed.
        NatProbeRequestPayload {
            initiator_node_id: local_node_id,
            target_node_id: [0u8; 32],
            session_token,
            candidates: vec![socket_addr_to_candidate(local_addr)],
        }
    }

    /// Parse the core's reply and extract the observed external address.
    ///
    /// Returns `None` if the reply carries no candidates.
    pub fn parse_reply(reply: &NatProbeReplyPayload) -> Option<ExternalAddrInfo> {
        let candidate = reply.candidates.first()?;
        let addr = candidate_to_socket_addr(candidate)?;
        Some(ExternalAddrInfo {
            external_addr: addr,
            session_token: reply.session_token,
        })
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Convert a `SocketAddr` to a `NatCandidate`.
///
/// `candidate_type` is set to `candidate_type::HOST`; callers that produce
/// server-reflexive or relay addresses must override the type and priority
/// after construction.
pub fn socket_addr_to_candidate(addr: SocketAddr) -> NatCandidate {
    use veil_proto::control::candidate_type;
    // RFC 8445 §5.1.2 host-candidate priority: type_pref=126, local_pref=65535, component=1
    // priority = (2^24 × 126) + (2^8 × 65535) + (256 − 1) = 2_130_706_431
    const HOST_PRIORITY: u32 = 2_130_706_431;
    match addr {
        SocketAddr::V4(v4) => NatCandidate {
            atyp: 4,
            candidate_type: candidate_type::HOST,
            priority: HOST_PRIORITY,
            addr: v4.ip().octets().to_vec(),
            port: v4.port(),
        },
        SocketAddr::V6(v6) => NatCandidate {
            atyp: 6,
            candidate_type: candidate_type::HOST,
            priority: HOST_PRIORITY,
            addr: v6.ip().octets().to_vec(),
            port: v6.port(),
        },
    }
}

/// Convert a `NatCandidate` to a `SocketAddr`, returning `None` on malformed data.
pub fn candidate_to_socket_addr(c: &NatCandidate) -> Option<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match c.atyp {
        4 => {
            if c.addr.len() != 4 {
                return None;
            }
            let ip = Ipv4Addr::from(<[u8; 4]>::try_from(c.addr.as_slice()).ok()?);
            Some(SocketAddr::new(IpAddr::V4(ip), c.port))
        }
        6 => {
            if c.addr.len() != 16 {
                return None;
            }
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(c.addr.as_slice()).ok()?);
            Some(SocketAddr::new(IpAddr::V6(ip), c.port))
        }
        _ => None,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_roundtrip_ipv4() {
        let node_id = [0x42u8; 32];
        let local: SocketAddr = "192.168.1.5:4000".parse().unwrap();
        let token = 0xABCD_1234u32;

        let req = ExternalAddrDiscovery::build_request(node_id, local, token);
        assert_eq!(req.session_token, token);
        assert_eq!(req.candidates.len(), 1);
        assert_eq!(candidate_to_socket_addr(&req.candidates[0]).unwrap(), local);

        // Simulate core building a reply with the observed external addr.
        let external: SocketAddr = "203.0.113.7:51000".parse().unwrap();
        let reply = NatProbeReplyPayload {
            responder_node_id: [0x00u8; 32],
            final_target_node_id: [0u8; 32], // direct response
            session_token: token,
            candidates: vec![socket_addr_to_candidate(external)],
        };

        let info = ExternalAddrDiscovery::parse_reply(&reply).unwrap();
        assert_eq!(info.external_addr, external);
        assert_eq!(info.session_token, token);
    }

    #[test]
    fn candidate_conversion_ipv6() {
        let addr: SocketAddr = "[::1]:8080".parse().unwrap();
        let c = socket_addr_to_candidate(addr);
        assert_eq!(c.atyp, 6);
        assert_eq!(c.addr.len(), 16);
        let back = candidate_to_socket_addr(&c).unwrap();
        assert_eq!(back, addr);
    }

    #[test]
    fn parse_reply_empty_candidates_returns_none() {
        let reply = NatProbeReplyPayload {
            responder_node_id: [0u8; 32],
            final_target_node_id: [0u8; 32],
            session_token: 1,
            candidates: vec![],
        };
        assert!(ExternalAddrDiscovery::parse_reply(&reply).is_none());
    }
}
