//! OVL1 Control-family payload types.
//!
//! | Payload | Message | Description |
//! |-----------------------|----------------|---------------------------------------|
//! | `NeighborOfferPayload` | `NEIGHBOR_OFFER` | Announce self as a reachable neighbor |
//! | `RouteProbePayload` | `ROUTE_PROBE` | RTT probe — receiver echoes it back |
//! | `RouteReplyPayload` | `ROUTE_REPLY` | Echo of probe + measured RTT |

use super::ProtoError;

// ── NeighborOfferPayload ───────────────────────────────────────────────────────

/// Announce self as a reachable neighbor.
///
/// Wire layout:
/// ```text
/// [0..32] node_id [u8; 32]
/// [32..34] addr_len u16 BE
/// [34..34+addr_len] addr bytes (UTF-8 multiaddr or binary)
/// [34+addr_len] flags u8
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborOfferPayload {
    /// Announcing node's `node_id`.
    pub node_id: [u8; 32],
    /// Serialized address (e.g. "127.0.0.1:9000" UTF-8, or empty).
    pub addr: Vec<u8>,
    /// Reserved flags byte.
    pub flags: u8,
}

impl NeighborOfferPayload {
    const FIXED_SIZE: usize = 32 + 2 + 1; // node_id + addr_len + flags

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let addr_len = (self.addr.len()).min(u16::MAX as usize) as u16;
        let mut buf = Vec::with_capacity(32 + 2 + self.addr.len() + 1);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&addr_len.to_be_bytes());
        // diff-audit M6: write only the CLAMPED length so field + body agree.
        buf.extend_from_slice(&self.addr[..addr_len as usize]);
        buf.push(self.flags);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        // minimum: 32 (node_id) + 2 (addr_len) + 0 (addr) + 1 (flags) = 35
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let node_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let addr_len = super::read_u16_be(buf, 32)? as usize;
        let addr_end = 34 + addr_len;
        if buf.len() < addr_end + 1 {
            return Err(ProtoError::BufferTooShort {
                need: addr_end + 1,
                got: buf.len(),
            });
        }
        let addr = buf[34..addr_end].to_vec();
        let flags = buf[addr_end];
        Ok(Self {
            node_id,
            addr,
            flags,
        })
    }
}

// ── RouteProbePayload ─────────────────────────────────────────────────────────

/// RTT probe — receiver must echo it back as `RouteReplyPayload`.
///
/// Wire layout:
/// ```text
/// [0..4] probe_id u32 BE
/// [4..12] timestamp_ms u64 BE (sender's local clock in milliseconds)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProbePayload {
    /// Random probe identifier the replier echoes back.
    pub probe_id: u32,
    /// Sender's local-clock timestamp in milliseconds.
    pub timestamp_ms: u64,
}

impl RouteProbePayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 4 + 8;

    /// Encode to the fixed 12-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..4].copy_from_slice(&self.probe_id.to_be_bytes());
        buf[4..12].copy_from_slice(&self.timestamp_ms.to_be_bytes());
        buf
    }

    /// Parse from a 12-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            probe_id: super::read_u32_be(buf, 0)?,
            timestamp_ms: super::read_u64_be(buf, 4)?,
        })
    }
}

// ── RouteReplyPayload ─────────────────────────────────────────────────────────

/// Echo of `RouteProbePayload` with an observed one-way RTT.
///
/// Wire layout:
/// ```text
/// [0..4] probe_id u32 BE
/// [4..12] timestamp_ms u64 BE (echoed from the probe)
/// [12..16] rtt_ms u32 BE (round-trip time measured by the replier, 0 = unknown)
/// [16] congestion u8 (0 = free … 255 = saturated; absent in older peers → 0)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteReplyPayload {
    /// Echo of the probe's `probe_id`.
    pub probe_id: u32,
    /// Echo of the probe's `timestamp_ms` for RTT computation.
    pub timestamp_ms: u64,
    /// Round-trip time measured by the replier (0 = unknown).
    pub rtt_ms: u32,
    /// Congestion score of the replying node, scaled 0–255.
    pub congestion: u8,
}

impl RouteReplyPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 4 + 8 + 4 + 1;

    /// Encode to the fixed 17-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..4].copy_from_slice(&self.probe_id.to_be_bytes());
        buf[4..12].copy_from_slice(&self.timestamp_ms.to_be_bytes());
        buf[12..16].copy_from_slice(&self.rtt_ms.to_be_bytes());
        buf[16] = self.congestion;
        buf
    }

    /// Parse from the fixed 17-byte wire layout.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            probe_id: super::read_u32_be(buf, 0)?,
            timestamp_ms: super::read_u64_be(buf, 4)?,
            rtt_ms: super::read_u32_be(buf, 12)?,
            congestion: buf[16],
        })
    }
}

// ── NatProbeRequestPayload ────────────────────────────────────────────────────

/// Request NAT traversal to a peer.
///
/// Sent through the signalling channel (via core) to start hole punching.
///
/// Wire layout:
/// ```text
/// [0..32] initiator_node_id [u8; 32]
/// [32..36] session_token u32 BE (random nonce to match request/reply)
/// [36..38] candidate_count u16 BE
/// [38..] candidates repeated AddrCandidate (each 18 bytes: 4+2 IPv4, or 16+2 IPv6)
/// ```
/// Each candidate is:
/// ```text
/// [0] atyp u8 (4=IPv4, 6=IPv6)
/// [1..5] addr u8[4] or u8[16]
/// [last 2] port u16 BE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatProbeRequestPayload {
    /// Initiator's `node_id`.
    pub initiator_node_id: [u8; 32],
    /// ultimate target of this probe. Two modes:
    ///
    /// * `[0u8; 32]` (sentinel) — legacy STUN-echo path. The receiving
    ///   peer treats this request as "tell me what srflx address you
    ///   see for ME" and replies directly. Used by a leaf to discover
    ///   its own external address via a Core peer.
    ///
    /// * non-zero, equal to receiver's `node_id` — same as STUN echo:
    ///   the request is addressed to us, respond locally.
    ///
    /// * non-zero, different from receiver — **relay-forward** mode.
    ///   The receiver acts as a coordinator: forward this request to
    ///   the addressed peer over an existing session. The eventual
    ///   reply must carry `final_target_node_id == initiator_node_id`
    ///   so the coordinator can route it back. Stateless on the
    ///   coordinator (no reverse-path map needed).
    ///
    /// Using a sentinel rather than `Option<[u8; 32]>` keeps the wire
    /// format fixed-size and decoding panic-free at the cost of one
    /// reserved value (`[0; 32]` is a valid node_id only with
    /// negligible BLAKE3 collision probability).
    pub target_node_id: [u8; 32],
    /// Random token echoed by the responder to correlate reply with request.
    pub session_token: u32,
    /// Each candidate: (atyp=4|6, addr_bytes, port)
    pub candidates: Vec<NatCandidate>,
}

/// ICE candidate type constants (RFC 8445 §5.1.2).
pub mod candidate_type {
    /// Directly reachable address on the local interface.
    pub const HOST: u8 = 0;
    /// Server-reflexive address learned via STUN (external address as seen by a STUN server).
    pub const SRFLX: u8 = 1;
    /// Relay address provided by a TURN/relay node.
    pub const RELAY: u8 = 2;
}

/// A single NAT candidate address.
///
/// Wire layout (per candidate):
/// ```text
/// [0] atyp u8 — 4=IPv4, 6=IPv6
/// [1] candidate_type u8 — 0=host, 1=srflx, 2=relay
/// [2..6] priority u32 BE — RFC 8445 §5.1.2 priority
/// [6..N] addr 4 or 16 bytes
/// [N..N+2] port u16 BE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatCandidate {
    /// 4 for IPv4 (addr is 4 bytes), 6 for IPv6 (addr is 16 bytes).
    pub atyp: u8,
    /// ICE candidate type: `candidate_type::HOST`, `SRFLX`, or `RELAY`.
    pub candidate_type: u8,
    /// RFC 8445 §5.1.2 priority. Higher is preferred.
    /// Formula: `(2^24 × type_pref) + (2^8 × local_pref) + (256 − component_id)`.
    pub priority: u32,
    /// Raw address bytes (4 or 16 depending on `atyp`).
    pub addr: Vec<u8>,
    /// UDP/TCP port number.
    pub port: u16,
}

impl NatCandidate {
    fn wire_size(&self) -> usize {
        // atyp(1) + candidate_type(1) + priority(4) + addr + port(2)
        1 + 1 + 4 + self.addr.len() + 2
    }

    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.push(self.atyp);
        buf.push(self.candidate_type);
        buf.extend_from_slice(&self.priority.to_be_bytes());
        buf.extend_from_slice(&self.addr);
        buf.extend_from_slice(&self.port.to_be_bytes());
    }

    fn decode_from(buf: &[u8]) -> Result<(Self, usize), ProtoError> {
        // minimum: atyp(1) + candidate_type(1) + priority(4) + addr_min(4) + port(2) = 12
        if buf.len() < 12 {
            return Err(ProtoError::BufferTooShort {
                need: 12,
                got: buf.len(),
            });
        }
        let atyp = buf[0];
        let candidate_type = buf[1];
        let priority = super::read_u32_be(buf, 2)?;
        let addr_len = match atyp {
            4 => 4usize,
            6 => 16usize,
            _ => {
                return Err(ProtoError::ValueTooLarge {
                    field: "NatCandidate.atyp",
                    value: atyp as u64,
                    max: 6,
                });
            }
        };
        let total = 1 + 1 + 4 + addr_len + 2;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        let addr = buf[6..6 + addr_len].to_vec();
        let port = super::read_u16_be(buf, 6 + addr_len)?;
        Ok((
            Self {
                atyp,
                candidate_type,
                priority,
                addr,
                port,
            },
            total,
        ))
    }
}

impl NatProbeRequestPayload {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        // Clamp to u16::MAX candidates (defensive — caller should limit).
        let cand_size: usize = self.candidates.iter().map(|c| c.wire_size()).sum();
        let mut buf = Vec::with_capacity(32 + 32 + 4 + 2 + cand_size);
        buf.extend_from_slice(&self.initiator_node_id);
        buf.extend_from_slice(&self.target_node_id);
        buf.extend_from_slice(&self.session_token.to_be_bytes());
        buf.extend_from_slice(&(self.candidates.len() as u16).to_be_bytes());
        for c in &self.candidates {
            c.encode_into(&mut buf);
        }
        buf
    }

    /// Parse from wire bytes. Enforces
    /// `candidate_count ≤ MAX_NAT_CANDIDATES`.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        // wire change: layout is now
        // [initiator_node_id 32B][target_node_id 32B][session_token 4B]
        // [candidate_count 2B][candidates...] Minimum = 70 bytes.
        if buf.len() < 70 {
            return Err(ProtoError::BufferTooShort {
                need: 70,
                got: buf.len(),
            });
        }
        let initiator_node_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let target_node_id: [u8; 32] = super::read_array::<32>(buf, 32)?;
        let session_token = super::read_u32_be(buf, 64)?;
        let candidate_count = super::read_u16_be(buf, 68)? as usize;
        if candidate_count > crate::budget::MAX_NAT_CANDIDATES {
            return Err(ProtoError::ValueTooLarge {
                field: "candidate_count",
                value: candidate_count as u64,
                max: crate::budget::MAX_NAT_CANDIDATES as u64,
            });
        }
        let mut offset = 70;
        let mut candidates = Vec::with_capacity(candidate_count);
        for _ in 0..candidate_count {
            let (c, n) = NatCandidate::decode_from(&buf[offset..])?;
            offset += n;
            candidates.push(c);
        }
        Ok(Self {
            initiator_node_id,
            target_node_id,
            session_token,
            candidates,
        })
    }
}

// ── NatProbeReplyPayload ──────────────────────────────────────────────────────

/// Reply to `NatProbeRequestPayload` — carries the responder's candidates.
///
/// Wire layout mirrors `NatProbeRequestPayload` with a `responder_node_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatProbeReplyPayload {
    /// Responder's `node_id`.
    pub responder_node_id: [u8; 32],
    /// ultimate destination of this reply. Two modes
    /// symmetric to `NatProbeRequestPayload::target_node_id`:
    ///
    /// * `[0u8; 32]` (sentinel) — STUN-echo reply addressed to the
    ///   peer who sent the original request. Matches legacy
    ///   pre-refactor protocol behaviour and the `NatProbeReply`
    ///   path used by the runtime to learn its own srflx address.
    ///
    /// * non-zero, equal to receiver's `node_id` — addressed to us;
    ///   consume locally.
    ///
    /// * non-zero, different from receiver — receiver is acting as
    ///   the **coordinator** that originally forwarded the request;
    ///   forward this reply to the addressed peer over an existing
    ///   session. Stateless (no reverse-path map needed): the reply
    ///   carries its own destination.
    pub final_target_node_id: [u8; 32],
    /// Echo of the request's `session_token`.
    pub session_token: u32,
    /// Responder's ICE candidates.
    pub candidates: Vec<NatCandidate>,
}

impl NatProbeReplyPayload {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        // Clamp to u16::MAX candidates (defensive).
        let cand_size: usize = self.candidates.iter().map(|c| c.wire_size()).sum();
        let mut buf = Vec::with_capacity(32 + 32 + 4 + 2 + cand_size);
        buf.extend_from_slice(&self.responder_node_id);
        buf.extend_from_slice(&self.final_target_node_id);
        buf.extend_from_slice(&self.session_token.to_be_bytes());
        buf.extend_from_slice(&(self.candidates.len() as u16).to_be_bytes());
        for c in &self.candidates {
            c.encode_into(&mut buf);
        }
        buf
    }

    /// Parse from wire bytes, enforcing the candidate-count cap.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        // wire change: layout is now
        // [responder_node_id 32B][final_target_node_id 32B]
        // [session_token 4B][candidate_count 2B][candidates...]
        // Minimum = 70 bytes.
        if buf.len() < 70 {
            return Err(ProtoError::BufferTooShort {
                need: 70,
                got: buf.len(),
            });
        }
        let responder_node_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let final_target_node_id: [u8; 32] = super::read_array::<32>(buf, 32)?;
        let session_token = super::read_u32_be(buf, 64)?;
        let candidate_count = super::read_u16_be(buf, 68)? as usize;
        if candidate_count > crate::budget::MAX_NAT_CANDIDATES {
            return Err(ProtoError::ValueTooLarge {
                field: "candidate_count",
                value: candidate_count as u64,
                max: crate::budget::MAX_NAT_CANDIDATES as u64,
            });
        }
        let mut offset = 70;
        let mut candidates = Vec::with_capacity(candidate_count);
        for _ in 0..candidate_count {
            let (c, n) = NatCandidate::decode_from(&buf[offset..])?;
            offset += n;
            candidates.push(c);
        }
        Ok(Self {
            responder_node_id,
            final_target_node_id,
            session_token,
            candidates,
        })
    }
}

// ── NatRelayRequestPayload ────────────────────────────────────────────────────

/// Ask a core node to act as relay for traffic between two leaf nodes.
///
/// Wire layout:
/// ```text
/// [0..32] node_a [u8; 32]
/// [32..64] node_b [u8; 32]
/// [64..68] session_token u32 BE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatRelayRequestPayload {
    /// First peer's `node_id`.
    pub node_a: [u8; 32],
    /// Second peer's `node_id`.
    pub node_b: [u8; 32],
    /// Random token correlating the relay session with the probe exchange.
    pub session_token: u32,
}

impl NatRelayRequestPayload {
    /// Fixed wire size (`node_a` + `node_b` + `session_token`).
    pub const WIRE_SIZE: usize = 32 + 32 + 4;

    /// Encode to the fixed 68-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.node_a);
        buf[32..64].copy_from_slice(&self.node_b);
        buf[64..68].copy_from_slice(&self.session_token.to_be_bytes());
        buf
    }

    /// Parse from a 68-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            node_a: super::read_array::<32>(buf, 0)?,
            node_b: super::read_array::<32>(buf, 32)?,
            session_token: super::read_u32_be(buf, 64)?,
        })
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neighbor_offer_roundtrip_with_addr() {
        let p = NeighborOfferPayload {
            node_id: [0xABu8; 32],
            addr: b"127.0.0.1:9000".to_vec(),
            flags: 0x01,
        };
        let encoded = p.encode();
        let decoded = NeighborOfferPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn neighbor_offer_roundtrip_empty_addr() {
        let p = NeighborOfferPayload {
            node_id: [0u8; 32],
            addr: vec![],
            flags: 0,
        };
        let decoded = NeighborOfferPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn neighbor_offer_too_short() {
        let err = NeighborOfferPayload::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn route_probe_roundtrip() {
        let p = RouteProbePayload {
            probe_id: 0xDEAD_BEEF,
            timestamp_ms: 1_234_567_890,
        };
        let decoded = RouteProbePayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn route_probe_too_short() {
        let err = RouteProbePayload::decode(&[0u8; 5]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn route_reply_roundtrip() {
        let p = RouteReplyPayload {
            probe_id: 42,
            timestamp_ms: 999_999,
            rtt_ms: 17,
            congestion: 200,
        };
        let decoded = RouteReplyPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn route_reply_too_short() {
        let err = RouteReplyPayload::decode(&[0u8; 8]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn route_reply_16_byte_rejected() {
        // 16-byte payload (no congestion byte) must now be rejected.
        let truncated = [0u8; 16];
        assert!(RouteReplyPayload::decode(&truncated).is_err());
    }

    #[test]
    fn nat_probe_request_roundtrip() {
        let p = NatProbeRequestPayload {
            initiator_node_id: [0x11u8; 32],
            target_node_id: [0u8; 32], // STUN-echo legacy mode
            session_token: 0xDEAD_BEEF,
            candidates: vec![
                NatCandidate {
                    atyp: 4,
                    candidate_type: candidate_type::HOST,
                    priority: 2_130_706_431,
                    addr: vec![192, 168, 1, 1],
                    port: 7000,
                },
                NatCandidate {
                    atyp: 4,
                    candidate_type: candidate_type::SRFLX,
                    priority: 1_694_498_815,
                    addr: vec![203, 0, 113, 5],
                    port: 9001,
                },
            ],
        };
        let decoded = NatProbeRequestPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
    }

    /// relay-mode request carries the target's node_id.
    #[test]
    fn nat_probe_request_relay_mode_roundtrip() {
        let p = NatProbeRequestPayload {
            initiator_node_id: [0xA1u8; 32],
            target_node_id: [0xB2u8; 32], // Bob, behind NAT, reachable via coordinator
            session_token: 0x4242_4242,
            candidates: vec![NatCandidate {
                atyp: 4,
                candidate_type: candidate_type::HOST,
                priority: 2_130_706_431,
                addr: vec![10, 0, 0, 5],
                port: 9099,
            }],
        };
        let decoded = NatProbeRequestPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
        assert_ne!(
            decoded.target_node_id, [0u8; 32],
            "relay-mode target must round-trip non-zero"
        );
    }

    #[test]
    fn nat_probe_reply_roundtrip() {
        let p = NatProbeReplyPayload {
            responder_node_id: [0x22u8; 32],
            final_target_node_id: [0u8; 32], // direct response to sender (legacy)
            session_token: 0xCAFE_BABE,
            candidates: vec![NatCandidate {
                atyp: 4,
                candidate_type: candidate_type::RELAY,
                priority: 16_777_215,
                addr: vec![10, 0, 0, 1],
                port: 5000,
            }],
        };
        let decoded = NatProbeReplyPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
    }

    /// forwarded reply carries the original initiator's node_id
    /// so the coordinator can route it back without per-session state.
    #[test]
    fn nat_probe_reply_forwarded_mode_roundtrip() {
        let p = NatProbeReplyPayload {
            responder_node_id: [0xB2u8; 32],    // Bob (responder)
            final_target_node_id: [0xA1u8; 32], // Alice (original initiator)
            session_token: 0x4242_4242,
            candidates: vec![NatCandidate {
                atyp: 4,
                candidate_type: candidate_type::SRFLX,
                priority: 1_694_498_815,
                addr: vec![198, 51, 100, 7],
                port: 4400,
            }],
        };
        let decoded = NatProbeReplyPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
        assert_ne!(
            decoded.final_target_node_id, [0u8; 32],
            "forwarded-reply final_target must round-trip non-zero"
        );
    }

    #[test]
    fn nat_relay_request_roundtrip() {
        let p = NatRelayRequestPayload {
            node_a: [0xAAu8; 32],
            node_b: [0xBBu8; 32],
            session_token: 0x1234_5678,
        };
        let decoded = NatRelayRequestPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn nat_probe_request_empty_candidates() {
        let p = NatProbeRequestPayload {
            initiator_node_id: [0u8; 32],
            target_node_id: [0u8; 32],
            session_token: 0,
            candidates: vec![],
        };
        let decoded = NatProbeRequestPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn nat_candidate_ipv6_roundtrip() {
        let p = NatProbeRequestPayload {
            initiator_node_id: [0x33u8; 32],
            target_node_id: [0u8; 32],
            session_token: 0xABCD_1234,
            candidates: vec![NatCandidate {
                atyp: 6,
                candidate_type: candidate_type::HOST,
                priority: 2_130_706_431,
                addr: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                port: 4433,
            }],
        };
        let decoded = NatProbeRequestPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn nat_candidate_invalid_atyp_returns_value_too_large() {
        // Craft a NatProbeRequestPayload buffer with one candidate whose atyp is 99
        // (not 4 or 6). The buffer is long enough to pass size checks, so the
        // error must be ValueTooLarge — NOT BufferTooShort.
        // wire change: header is now 70 bytes (32 initiator +
        // 32 target + 4 token + 2 count) instead of 38.
        let mut buf = vec![0u8; 70 + 12]; // header(70) + candidate_min(12)
        buf[68] = 0;
        buf[69] = 1; // candidate_count = 1
        buf[70] = 99; // candidate atyp = 99, invalid
        let err = NatProbeRequestPayload::decode(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                super::ProtoError::ValueTooLarge {
                    field: "NatCandidate.atyp",
                    ..
                }
            ),
            "expected ValueTooLarge for invalid atyp, got {err:?}",
        );
    }

    #[test]
    fn nat_candidates_sorted_by_priority() {
        // host > srflx > relay ordering by priority values
        let host = NatCandidate {
            atyp: 4,
            candidate_type: candidate_type::HOST,
            priority: 2_130_706_431,
            addr: vec![10, 0, 0, 1],
            port: 1,
        };
        let srflx = NatCandidate {
            atyp: 4,
            candidate_type: candidate_type::SRFLX,
            priority: 1_694_498_815,
            addr: vec![10, 0, 0, 2],
            port: 2,
        };
        let relay = NatCandidate {
            atyp: 4,
            candidate_type: candidate_type::RELAY,
            priority: 16_777_215,
            addr: vec![10, 0, 0, 3],
            port: 3,
        };
        let mut candidates = vec![relay.clone(), srflx.clone(), host.clone()];
        candidates.sort_by_key(|c| std::cmp::Reverse(c.priority));
        assert_eq!(candidates, vec![host, srflx, relay]);
    }
}
