//! Diagnostic protocol wire types (FrameFamily::Diag = 9).
//!
//! Four message types:
//! Ping(1) — sender → target: measure RTT
//! Pong(2) — target → sender: RTT reply
//! TraceProbe(3) — sender → target: traceroute probe with TTL
//! TraceHop(4) — relay → sender: TTL-expired hop report

use super::ProtoError;

/// Default forwarding hop budget for relayed diagnostic frames
/// (Ping / Pong / TraceHop). Each relay decrements it and drops the frame
/// once it reaches zero, bounding route-cache loops and amplification:
/// without it a single frame can bounce forever between two relays whose
/// route caches disagree about the next hop (Ping/Pong/TraceHop carry no
/// other loop guard, unlike TraceProbe which already has a TTL).
///
/// Sized to `crate::delivery::MAX_RELAY_PATH_HOPS` (= 64), the network's
/// relay-path anti-amplification ceiling, so any legitimate diagnostic path
/// still completes. Also used as the back-compat default when decoding a
/// legacy frame that predates the `hop_limit` field.
pub const DIAG_DEFAULT_HOP_LIMIT: u8 = 64;

// ── DiagPingPayload ───────────────────────────────────────────────────────────
//
// Wire layout:
// [0..4] seq u32 BE
// [4..36] sender [u8; 32]
// [36..44] ts_us u64 BE — sender wall-clock µs (for display only)
// [44..76] target [u8; 32] — final destination; relays forward toward it
// [76] hop_limit u8 — forwarding budget; relays decrement, drop at 0 (loop
//      guard). Trailing/optional: legacy 76-byte frames decode with the
//      default budget, so adding it is back-compatible across versions.

/// Ping probe sent by the initiating node.
/// Relays forward the probe toward `target`; only the target replies with Pong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagPingPayload {
    /// Monotonic probe sequence number.
    pub seq: u32,
    /// Originator `node_id`.
    pub sender: [u8; 32],
    /// Sender wall-clock timestamp, microseconds — for display only.
    pub ts_us: u64,
    /// Final destination for relay routing.
    pub target: [u8; 32],
    /// Forwarding hop budget. Each relay decrements it and drops the frame
    /// at zero, bounding route-cache loops. See [`DIAG_DEFAULT_HOP_LIMIT`].
    pub hop_limit: u8,
}

impl DiagPingPayload {
    /// Wire size including the trailing `hop_limit` byte.
    pub const SIZE: usize = 4 + 32 + 8 + 32 + 1;
    /// Legacy wire size before the `hop_limit` byte was appended. Frames of
    /// exactly this length are accepted for back-compat (hop_limit defaults).
    pub const LEGACY_SIZE: usize = 4 + 32 + 8 + 32;

    /// Encode to the 77-byte layout (76 legacy bytes + `hop_limit`).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.sender);
        buf.extend_from_slice(&self.ts_us.to_be_bytes());
        buf.extend_from_slice(&self.target);
        buf.push(self.hop_limit);
        buf
    }

    /// Parse a ping payload. Accepts both the current 77-byte layout and the
    /// legacy 76-byte layout (hop_limit ⇒ [`DIAG_DEFAULT_HOP_LIMIT`]).
    pub fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        if b.len() < Self::LEGACY_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::LEGACY_SIZE,
                got: b.len(),
            });
        }
        let seq = super::read_u32_be(b, 0)?;
        let sender: [u8; 32] = super::read_array::<32>(b, 4)?;
        let ts_us = super::read_u64_be(b, 36)?;
        let target: [u8; 32] = super::read_array::<32>(b, 44)?;
        let hop_limit = if b.len() > Self::LEGACY_SIZE {
            b[Self::LEGACY_SIZE]
        } else {
            DIAG_DEFAULT_HOP_LIMIT
        };
        Ok(Self {
            seq,
            sender,
            ts_us,
            target,
            hop_limit,
        })
    }
}

// ── DiagPongPayload ───────────────────────────────────────────────────────────
//
// Wire layout:
// [0..4] seq u32 BE
// [4..36] responder [u8; 32]
// [36..44] echo_ts_us u64 BE — copy of DiagPingPayload.ts_us
// [44..76] dest [u8; 32] — original sender; used for relay forwarding
// [76] hop_limit u8 — forwarding budget; relays decrement, drop at 0 (loop
//      guard). Trailing/optional: legacy 76-byte frames decode with the
//      default budget, so adding it is back-compatible across versions.

/// Pong reply sent by the target back to the initiating node.
/// Relays forward the pong toward `dest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagPongPayload {
    /// Sequence number copied from the matching `DiagPingPayload`.
    pub seq: u32,
    /// `node_id` of the responder.
    pub responder: [u8; 32],
    /// Echo of `DiagPingPayload.ts_us` for RTT computation.
    pub echo_ts_us: u64,
    /// Final destination — the node that should receive this pong (= ping sender).
    pub dest: [u8; 32],
    /// Forwarding hop budget. Each relay decrements it and drops the frame
    /// at zero, bounding route-cache loops. See [`DIAG_DEFAULT_HOP_LIMIT`].
    pub hop_limit: u8,
}

impl DiagPongPayload {
    /// Wire size including the trailing `hop_limit` byte.
    pub const SIZE: usize = 4 + 32 + 8 + 32 + 1;
    /// Legacy wire size before the `hop_limit` byte was appended. Frames of
    /// exactly this length are accepted for back-compat (hop_limit defaults).
    pub const LEGACY_SIZE: usize = 4 + 32 + 8 + 32;

    /// Encode to the 77-byte layout (76 legacy bytes + `hop_limit`).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.responder);
        buf.extend_from_slice(&self.echo_ts_us.to_be_bytes());
        buf.extend_from_slice(&self.dest);
        buf.push(self.hop_limit);
        buf
    }

    /// Parse a pong payload. Accepts both the current 77-byte layout and the
    /// legacy 76-byte layout (hop_limit ⇒ [`DIAG_DEFAULT_HOP_LIMIT`]).
    pub fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        if b.len() < Self::LEGACY_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::LEGACY_SIZE,
                got: b.len(),
            });
        }
        let seq = super::read_u32_be(b, 0)?;
        let responder: [u8; 32] = super::read_array::<32>(b, 4)?;
        let echo_ts_us = super::read_u64_be(b, 36)?;
        let dest: [u8; 32] = super::read_array::<32>(b, 44)?;
        let hop_limit = if b.len() > Self::LEGACY_SIZE {
            b[Self::LEGACY_SIZE]
        } else {
            DIAG_DEFAULT_HOP_LIMIT
        };
        Ok(Self {
            seq,
            responder,
            echo_ts_us,
            dest,
            hop_limit,
        })
    }
}

// ── DiagTraceProbePayload ─────────────────────────────────────────────────────
//
// Wire layout:
// [0..4] seq u32 BE
// [4..36] sender [u8; 32]
// [36..44] ts_us u64 BE
// [44] ttl u8 — relay decrements; at 0 → send TraceHop back
// [45] max_hops u8 — informational upper bound
// [46] orig_ttl u8 — TTL at creation (hop index, never modified)
// [47..79] target [u8; 32] — final destination for relay routing

/// Traceroute probe. Each relay decrements `ttl`; when it hits zero the relay
/// sends a `DiagTraceHop` back to `sender`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagTraceProbePayload {
    /// Probe sequence number.
    pub seq: u32,
    /// Originator `node_id`.
    pub sender: [u8; 32],
    /// Sender wall-clock timestamp, microseconds.
    pub ts_us: u64,
    /// TTL decremented by each relay; report generated when it hits 0.
    pub ttl: u8,
    /// Informational upper bound on probe depth.
    pub max_hops: u8,
    /// TTL at creation — equals the hop index this probe is probing.
    pub orig_ttl: u8,
    /// Final destination; relays use this to route the probe correctly.
    pub target: [u8; 32],
}

impl DiagTraceProbePayload {
    /// Fixed wire size.
    pub const SIZE: usize = 4 + 32 + 8 + 1 + 1 + 1 + 32;

    /// Encode to the fixed 79-byte layout.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.sender);
        buf.extend_from_slice(&self.ts_us.to_be_bytes());
        buf.push(self.ttl);
        buf.push(self.max_hops);
        buf.push(self.orig_ttl);
        buf.extend_from_slice(&self.target);
        buf
    }

    /// Parse a trace-probe payload from a 79-byte buffer.
    pub fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        if b.len() < Self::SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::SIZE,
                got: b.len(),
            });
        }
        let seq = super::read_u32_be(b, 0)?;
        let sender: [u8; 32] = super::read_array::<32>(b, 4)?;
        let ts_us = super::read_u64_be(b, 36)?;
        let ttl = b[44];
        let max_hops = b[45];
        let orig_ttl = b[46];
        let target: [u8; 32] = super::read_array::<32>(b, 47)?;
        Ok(Self {
            seq,
            sender,
            ts_us,
            ttl,
            max_hops,
            orig_ttl,
            target,
        })
    }
}

// ── DiagTraceHopPayload ───────────────────────────────────────────────────────
//
// Wire layout:
// [0..4] seq u32 BE
// [4..36] hop_node_id [u8; 32] — node that consumed TTL
// [36] hop_idx u8 — which hop index (= original TTL value)
// [37..45] echo_ts_us u64 BE — copy of probe ts_us
// [45..77] dest [u8; 32] — final destination (= original sender); used for relay forwarding
// [77] hop_limit u8 — forwarding budget; relays decrement, drop at 0 (loop
//      guard). Trailing/optional: legacy 77-byte frames decode with the
//      default budget, so adding it is back-compatible across versions.

/// Sent back to the original `sender` by the relay whose TTL hit zero.
///
/// The `dest` field carries the original probe sender's node_id so that
/// intermediate relays can forward the hop report toward its destination
/// without consuming it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagTraceHopPayload {
    /// Probe sequence number (copy of the originating probe's `seq`).
    pub seq: u32,
    /// `node_id` of the relay whose TTL reached 0.
    pub hop_node_id: [u8; 32],
    /// Hop index (equals the probe's `orig_ttl`).
    pub hop_idx: u8,
    /// Echo of the probe's `ts_us` for RTT computation.
    pub echo_ts_us: u64,
    /// Final destination — the node that should receive this hop report.
    pub dest: [u8; 32],
    /// Forwarding hop budget. Each relay decrements it and drops the frame
    /// at zero, bounding route-cache loops. See [`DIAG_DEFAULT_HOP_LIMIT`].
    pub hop_limit: u8,
}

impl DiagTraceHopPayload {
    /// Wire size including the trailing `hop_limit` byte.
    pub const SIZE: usize = 4 + 32 + 1 + 8 + 32 + 1;
    /// Legacy wire size before the `hop_limit` byte was appended. Frames of
    /// exactly this length are accepted for back-compat (hop_limit defaults).
    pub const LEGACY_SIZE: usize = 4 + 32 + 1 + 8 + 32;

    /// Encode to the 78-byte layout (77 legacy bytes + `hop_limit`).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.hop_node_id);
        buf.push(self.hop_idx);
        buf.extend_from_slice(&self.echo_ts_us.to_be_bytes());
        buf.extend_from_slice(&self.dest);
        buf.push(self.hop_limit);
        buf
    }

    /// Parse a trace-hop payload. Accepts both the current 78-byte layout and
    /// the legacy 77-byte layout (hop_limit ⇒ [`DIAG_DEFAULT_HOP_LIMIT`]).
    pub fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        if b.len() < Self::LEGACY_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::LEGACY_SIZE,
                got: b.len(),
            });
        }
        let seq = super::read_u32_be(b, 0)?;
        let hop_node_id: [u8; 32] = super::read_array::<32>(b, 4)?;
        let hop_idx = b[36];
        let echo_ts_us = super::read_u64_be(b, 37)?;
        let dest: [u8; 32] = super::read_array::<32>(b, 45)?;
        let hop_limit = if b.len() > Self::LEGACY_SIZE {
            b[Self::LEGACY_SIZE]
        } else {
            DIAG_DEFAULT_HOP_LIMIT
        };
        Ok(Self {
            seq,
            hop_node_id,
            hop_idx,
            echo_ts_us,
            dest,
            hop_limit,
        })
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_roundtrip() {
        let p = DiagPingPayload {
            seq: 42,
            sender: [0xAA; 32],
            ts_us: 123_456_789,
            target: [0x11; 32],
            hop_limit: 17,
        };
        let enc = p.encode();
        assert_eq!(enc.len(), DiagPingPayload::SIZE);
        assert_eq!(DiagPingPayload::decode(&enc).unwrap(), p);
    }

    #[test]
    fn ping_legacy_decode_defaults_hop_limit() {
        // A peer that predates the hop_limit byte sends a 76-byte frame.
        // Decoding must succeed and apply the default budget (no version break).
        let p = DiagPingPayload {
            seq: 42,
            sender: [0xAA; 32],
            ts_us: 123_456_789,
            target: [0x11; 32],
            hop_limit: 17,
        };
        let legacy = &p.encode()[..DiagPingPayload::LEGACY_SIZE];
        let decoded = DiagPingPayload::decode(legacy).unwrap();
        assert_eq!(decoded.hop_limit, DIAG_DEFAULT_HOP_LIMIT);
        assert_eq!(decoded.seq, p.seq);
        assert_eq!(decoded.sender, p.sender);
        assert_eq!(decoded.target, p.target);
    }

    #[test]
    fn pong_roundtrip() {
        let p = DiagPongPayload {
            seq: 7,
            responder: [0xBB; 32],
            echo_ts_us: 987,
            dest: [0x22; 32],
            hop_limit: 5,
        };
        let enc = p.encode();
        assert_eq!(enc.len(), DiagPongPayload::SIZE);
        assert_eq!(DiagPongPayload::decode(&enc).unwrap(), p);
    }

    #[test]
    fn pong_legacy_decode_defaults_hop_limit() {
        let p = DiagPongPayload {
            seq: 7,
            responder: [0xBB; 32],
            echo_ts_us: 987,
            dest: [0x22; 32],
            hop_limit: 5,
        };
        let legacy = &p.encode()[..DiagPongPayload::LEGACY_SIZE];
        let decoded = DiagPongPayload::decode(legacy).unwrap();
        assert_eq!(decoded.hop_limit, DIAG_DEFAULT_HOP_LIMIT);
        assert_eq!(decoded.dest, p.dest);
    }

    #[test]
    fn trace_probe_roundtrip() {
        let p = DiagTraceProbePayload {
            seq: 1,
            sender: [0x11; 32],
            ts_us: 5000,
            ttl: 3,
            max_hops: 8,
            orig_ttl: 3,
            target: [0x22; 32],
        };
        assert_eq!(DiagTraceProbePayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn trace_hop_roundtrip() {
        let p = DiagTraceHopPayload {
            seq: 2,
            hop_node_id: [0xCC; 32],
            hop_idx: 3,
            echo_ts_us: 4444,
            dest: [0xDD; 32],
            hop_limit: 9,
        };
        let enc = p.encode();
        assert_eq!(enc.len(), DiagTraceHopPayload::SIZE);
        assert_eq!(DiagTraceHopPayload::decode(&enc).unwrap(), p);
    }

    #[test]
    fn trace_hop_legacy_decode_defaults_hop_limit() {
        let p = DiagTraceHopPayload {
            seq: 2,
            hop_node_id: [0xCC; 32],
            hop_idx: 3,
            echo_ts_us: 4444,
            dest: [0xDD; 32],
            hop_limit: 9,
        };
        let legacy = &p.encode()[..DiagTraceHopPayload::LEGACY_SIZE];
        let decoded = DiagTraceHopPayload::decode(legacy).unwrap();
        assert_eq!(decoded.hop_limit, DIAG_DEFAULT_HOP_LIMIT);
        assert_eq!(decoded.dest, p.dest);
        assert_eq!(decoded.hop_idx, p.hop_idx);
    }

    #[test]
    fn ping_truncated() {
        let p = DiagPingPayload {
            seq: 1,
            sender: [0u8; 32],
            ts_us: 0,
            target: [0u8; 32],
            hop_limit: DIAG_DEFAULT_HOP_LIMIT,
        };
        let enc = p.encode();
        let err = DiagPingPayload::decode(&enc[..10]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn pong_truncated() {
        let err = DiagPongPayload::decode(&[0u8; 5]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn trace_probe_truncated() {
        let err = DiagTraceProbePayload::decode(&[0u8; 20]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn trace_hop_truncated() {
        let err = DiagTraceHopPayload::decode(&[0u8; 44]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn ping_extra_bytes_ignored() {
        let p = DiagPingPayload {
            seq: 99,
            sender: [0x55; 32],
            ts_us: 1,
            target: [0x77; 32],
            hop_limit: 3,
        };
        let mut enc = p.encode();
        enc.extend_from_slice(&[0xFF; 10]);
        assert_eq!(DiagPingPayload::decode(&enc).unwrap(), p);
    }
}
