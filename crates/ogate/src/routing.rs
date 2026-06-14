//! Virtual-IP ↔ peer routing table.
//!
//! Two views over the same configured peer set:
//!
//! * `virtual_ip → peer_node_id` — used on TUN read (egress) to pick the
//!   veil destination for an outbound IP packet.
//! * `peer_node_id → expected virtual_ips` — used on veil receive
//!   (ingress) to verify that `src_node_id` is allowed to inject a packet
//!   from `src_ip` (anti-spoofing in authorized mode).
//!
//! Authorized mode additionally maintains an allowlist of `node_id`s
//! (= the keys of the peer table). Open mode skips the membership check
//! but still uses the table to resolve egress destinations; an unknown
//! destination IP is dropped (no flooding).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::{AccessMode, OgateConfig};

pub type NodeId = [u8; 32];

/// Outcome of `lookup_egress` / `lookup_ingress` for the bridge loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Forward to / accept from this peer.
    Forward(NodeId),
    /// No matching peer — drop the packet (TUN egress).
    NoRoute,
    /// Peer is known but not in the allowlist (`authorized` mode only).
    Unauthorized,
    /// Source IP does not match the peer's expected virtual IP
    /// (`authorized` mode anti-spoofing).
    SpoofedSourceIp,
}

#[derive(Debug, Clone)]
pub struct RoutingTable {
    mode: AccessMode,
    v4: HashMap<Ipv4Addr, NodeId>,
    v6: HashMap<Ipv6Addr, NodeId>,
    /// node_id → set of expected virtual IPs (for ingress spoofing check).
    by_peer: HashMap<NodeId, PeerAddrs>,
}

#[derive(Debug, Clone, Default)]
struct PeerAddrs {
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
}

impl RoutingTable {
    /// Build the table from the resolved config.
    pub fn from_config(cfg: &OgateConfig) -> Result<Self, &'static str> {
        let mut v4 = HashMap::new();
        let mut v6 = HashMap::new();
        let mut by_peer = HashMap::new();
        for peer in &cfg.peers {
            let nid = decode_node_id(&peer.node_id).ok_or("peer node_id is not 32-byte hex")?;
            let addrs = PeerAddrs {
                v4: peer.addr_v4,
                v6: peer.addr_v6,
            };
            if let Some(ip) = peer.addr_v4
                && v4.insert(ip, nid).is_some()
            {
                return Err("duplicate IPv4 in peer table");
            }
            if let Some(ip) = peer.addr_v6
                && v6.insert(ip, nid).is_some()
            {
                return Err("duplicate IPv6 in peer table");
            }
            if by_peer.insert(nid, addrs).is_some() {
                return Err("duplicate node_id in peer table");
            }
        }
        Ok(Self {
            mode: cfg.mode,
            v4,
            v6,
            by_peer,
        })
    }

    pub fn mode(&self) -> AccessMode {
        self.mode
    }

    pub fn peer_count(&self) -> usize {
        self.by_peer.len()
    }

    pub fn peer_node_ids(&self) -> impl Iterator<Item = &NodeId> {
        self.by_peer.keys()
    }

    /// Resolve an outbound packet's destination IP to a peer `node_id`.
    pub fn lookup_egress(&self, dst: IpAddr) -> Decision {
        let nid = match dst {
            IpAddr::V4(v4) => self.v4.get(&v4).copied(),
            IpAddr::V6(v6) => self.v6.get(&v6).copied(),
        };
        match nid {
            Some(n) => Decision::Forward(n),
            None => Decision::NoRoute,
        }
    }

    /// Decide what to do with an inbound packet given the veil sender's
    /// `node_id` and the packet's claimed source IP.
    ///
    /// * `open` mode: accept any peer in the network namespace, **but**
    ///   packet must still parse as a valid IP header (post-audit: was
    ///   accepting malformed packets unconditionally, which let a
    ///   namespace-peer inject garbage into the TUN interface).
    /// * `authorized` mode: accept only if `src_node_id` is in the peer
    ///   table AND `src_ip` matches the peer's recorded virtual IP.
    pub fn lookup_ingress(&self, src_node_id: &NodeId, src_ip: Option<IpAddr>) -> Decision {
        // Malformed packet (no parsable IP header) — drop in both modes.
        // post-fix: open mode previously forwarded
        // anything, allowing TUN-injection of arbitrary bytes by a peer
        // in the network namespace.
        if src_ip.is_none() {
            return Decision::SpoofedSourceIp;
        }
        if self.mode == AccessMode::Open {
            return Decision::Forward(*src_node_id);
        }
        let Some(peer) = self.by_peer.get(src_node_id) else {
            return Decision::Unauthorized;
        };
        let Some(ip) = src_ip else {
            // Already short-circuited above; defensive — should be unreachable.
            return Decision::SpoofedSourceIp;
        };
        let matches = match ip {
            IpAddr::V4(v4) => peer.v4 == Some(v4),
            IpAddr::V6(v6) => peer.v6 == Some(v6),
        };
        if matches {
            Decision::Forward(*src_node_id)
        } else {
            Decision::SpoofedSourceIp
        }
    }
}

/// Parse a 64-char hex string into a 32-byte node_id.
pub fn decode_node_id(s: &str) -> Option<NodeId> {
    if s.len() != 64 {
        return None;
    }
    let raw = hex::decode(s).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Some(out)
}

/// Hex-encode a node_id (lowercase, no separators).
pub fn encode_node_id(nid: &NodeId) -> String {
    hex::encode(nid)
}

/// Extract the IP version + source + destination from a raw IP packet.
///
/// Returns `None` for packets too short to parse a header or with
/// invalid header-length / total-length fields.  Supports IPv4
/// (version=4) and IPv6 (version=6); other versions return `None`.
///
/// Audit batch 2026-05-24 (L9): also validates `IHL` (v4 internet
/// header length) and `total_length` / `payload_length` consistency
/// so a malformed packet doesn't reach TUN write with garbage headers.
pub fn parse_ip_endpoints(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;
    match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            // IHL field = packet[0] & 0x0F = #32-bit words in header.
            // Minimum 5 (= 20 bytes); maximum 15 (= 60 bytes).  Header
            // must fit in the buffer.
            let ihl = (packet[0] & 0x0F) as usize;
            if ihl < 5 || packet.len() < ihl * 4 {
                return None;
            }
            // Total length (offset 2-3, BE) — must match packet len and
            // be at least IHL*4.
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if total_len < ihl * 4 || total_len > packet.len() {
                return None;
            }
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            Some((IpAddr::V4(src), IpAddr::V4(dst)))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            // Payload length (offset 4-5, BE) — must fit in buffer
            // beyond the 40-byte fixed header.
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            if 40usize
                .checked_add(payload_len)
                .is_none_or(|n| n > packet.len())
            {
                return None;
            }
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&packet[8..24]);
            dst.copy_from_slice(&packet[24..40]);
            Some((
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerEntry;

    fn cfg_with_peer(mode: AccessMode, node_hex: &str, v4: Option<Ipv4Addr>) -> OgateConfig {
        OgateConfig {
            network: "test".to_owned(),
            app: "ogate".to_owned(),
            mode,
            socket_path: "/run/veil/app.sock".into(),
            iface_name: "ogate0".to_owned(),
            mtu: 1280,
            local_addr_v4: Some(Ipv4Addr::new(10, 99, 0, 1)),
            prefix_v4: 24,
            local_addr_v6: None,
            prefix_v6: 64,
            peers: vec![PeerEntry {
                node_id: node_hex.to_owned(),
                addr_v4: v4,
                addr_v6: None,
                name: None,
            }],
            endpoint_id: 1,
            runtime: Default::default(),
            logging: Default::default(),
            batch: Default::default(),
            pnet_required: false,
            app_cert_trusted_owner_pubkey: None,
            app_cert_owner_algo: None,
            app_cert_network_id: None,
            app_cert_path: None,
        }
    }

    const PEER_HEX: &str = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

    #[test]
    fn egress_lookup_hits_known_dst() {
        let cfg = cfg_with_peer(
            AccessMode::Open,
            PEER_HEX,
            Some(Ipv4Addr::new(10, 99, 0, 2)),
        );
        let t = RoutingTable::from_config(&cfg).unwrap();
        let r = t.lookup_egress(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2)));
        assert!(matches!(r, Decision::Forward(_)));
    }

    #[test]
    fn egress_lookup_unknown_dst_drops() {
        let cfg = cfg_with_peer(
            AccessMode::Open,
            PEER_HEX,
            Some(Ipv4Addr::new(10, 99, 0, 2)),
        );
        let t = RoutingTable::from_config(&cfg).unwrap();
        let r = t.lookup_egress(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 9)));
        assert_eq!(r, Decision::NoRoute);
    }

    #[test]
    fn ingress_open_mode_accepts_unknown_peer() {
        let cfg = cfg_with_peer(
            AccessMode::Open,
            PEER_HEX,
            Some(Ipv4Addr::new(10, 99, 0, 2)),
        );
        let t = RoutingTable::from_config(&cfg).unwrap();
        let r = t.lookup_ingress(&[0xff; 32], Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(matches!(r, Decision::Forward(_)));
    }

    #[test]
    fn ingress_authorized_rejects_unknown_peer() {
        let cfg = cfg_with_peer(
            AccessMode::Authorized,
            PEER_HEX,
            Some(Ipv4Addr::new(10, 99, 0, 2)),
        );
        let t = RoutingTable::from_config(&cfg).unwrap();
        let r = t.lookup_ingress(&[0xff; 32], Some(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2))));
        assert_eq!(r, Decision::Unauthorized);
    }

    #[test]
    fn ingress_authorized_rejects_spoofed_source_ip() {
        let cfg = cfg_with_peer(
            AccessMode::Authorized,
            PEER_HEX,
            Some(Ipv4Addr::new(10, 99, 0, 2)),
        );
        let t = RoutingTable::from_config(&cfg).unwrap();
        let nid = decode_node_id(PEER_HEX).unwrap();
        let r = t.lookup_ingress(&nid, Some(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 7))));
        assert_eq!(r, Decision::SpoofedSourceIp);
    }

    #[test]
    fn ingress_authorized_accepts_matching_src() {
        let cfg = cfg_with_peer(
            AccessMode::Authorized,
            PEER_HEX,
            Some(Ipv4Addr::new(10, 99, 0, 2)),
        );
        let t = RoutingTable::from_config(&cfg).unwrap();
        let nid = decode_node_id(PEER_HEX).unwrap();
        let r = t.lookup_ingress(&nid, Some(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2))));
        assert!(matches!(r, Decision::Forward(_)));
    }

    #[test]
    fn parse_ipv4_endpoints() {
        // Audit batch 2026-05-24 (L9): parse_ip_endpoints now validates
        // IHL and total_length consistency.  Test fixture must set both
        // — a raw zero-header packet (legitimate use case: synthetic
        // test data) would otherwise be rejected.
        let mut pkt = [0u8; 40];
        pkt[0] = 0x45; // version=4, IHL=5 (20-byte header)
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes()); // total_len = 40
        pkt[12..16].copy_from_slice(&[10, 99, 0, 5]);
        pkt[16..20].copy_from_slice(&[10, 99, 0, 6]);
        let (src, dst) = parse_ip_endpoints(&pkt).unwrap();
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(10, 99, 0, 5)));
        assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(10, 99, 0, 6)));
    }

    #[test]
    fn parse_ipv4_rejects_bad_ihl() {
        // IHL = 4 (= 16 bytes header) — < min 20.
        let mut pkt = [0u8; 40];
        pkt[0] = 0x44;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        assert!(parse_ip_endpoints(&pkt).is_none());
    }

    #[test]
    fn parse_ipv4_rejects_truncated_total_length() {
        // total_len = 100, buffer = 40 — packet truncated.
        let mut pkt = [0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert!(parse_ip_endpoints(&pkt).is_none());
    }

    #[test]
    fn parse_ipv6_rejects_oversize_payload_length() {
        // payload_len = 10000, buffer = 40 — payload outside buffer.
        let mut pkt = [0u8; 40];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&10000u16.to_be_bytes());
        assert!(parse_ip_endpoints(&pkt).is_none());
    }

    #[test]
    fn parse_ipv6_endpoints() {
        let mut pkt = [0u8; 40];
        pkt[0] = 0x60;
        let s = [
            0x20u8, 0x01, 0xdb, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let d = [
            0x20u8, 0x01, 0xdb, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ];
        pkt[8..24].copy_from_slice(&s);
        pkt[24..40].copy_from_slice(&d);
        let (src, dst) = parse_ip_endpoints(&pkt).unwrap();
        assert!(matches!(src, IpAddr::V6(_)));
        assert!(matches!(dst, IpAddr::V6(_)));
    }

    #[test]
    fn parse_unknown_version_returns_none() {
        let pkt = [0x30u8; 40];
        assert!(parse_ip_endpoints(&pkt).is_none());
    }
}
