/// Four-byte fixed header preamble: ASCII `"OVL1"`.
pub const MAGIC: [u8; 4] = *b"OVL1";
/// Wire-protocol major version.
pub const VERSION: u8 = 1;
/// Size of the fixed portion of the frame header, in bytes.
pub const HEADER_SIZE: usize = 24;

/// Priority constants extracted from `FrameHeader.flags` bits [1:0].
pub mod priority {
    /// Real-time traffic (voice/video RTP) — highest priority.
    pub const REALTIME: u8 = 0;
    /// Interactive traffic: RPC, control, user messaging.
    pub const INTERACTIVE: u8 = 1;
    /// Bulk transfer: file transfer, backup.
    pub const BULK: u8 = 2;
    /// Background traffic: DHT scans, analytics.
    pub const BACKGROUND: u8 = 3;
}

/// Mask for the priority bits in `FrameHeader.flags`.
pub const FLAGS_PRIORITY_MASK: u16 = 0x0003;

/// Type-safe traffic-class enum for QoS frame classification.
///
/// Discriminant values match the 2-bit priority field in `FrameHeader.flags`
/// so `class as u8` yields a wire-compatible priority value.
/// Converting an unknown raw value (should never occur after masking with
/// `FLAGS_PRIORITY_MASK`) defaults to `Interactive` for backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrafficClass {
    /// Real-time traffic: voice/video RTP. Highest priority; weight 8 in WRR.
    RealTime = 0,
    /// Interactive traffic: RPC, control frames, user messaging. Weight 4.
    Interactive = 1,
    /// Bulk transfer: file transfer, sync, backup. Weight 2.
    Bulk = 2,
    /// Background traffic: DHT scans, analytics, low-priority gossip. Weight 1.
    Background = 3,
}

impl From<TrafficClass> for u8 {
    fn from(tc: TrafficClass) -> u8 {
        tc as u8
    }
}

/// Fixed 24-byte OVL1 frame header.
///
/// Layout (big-endian):
/// ```text
/// [0..4] magic "OVL1"
/// [4] version 1
/// [5] family FrameFamily discriminant
/// [6..8] msg_type per-family message type
/// [8..10] flags frame flags (bits[1:0] = priority class)
/// [10..12] header_len total header size incl. TLV extensions
/// [12..16] body_len payload size in bytes
/// [16..20] stream_id logical stream identifier
/// [20..24] request_id request/response correlation id
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    /// Wire-protocol major version; equal [`VERSION`] on encode.
    pub version: u8,
    /// `FrameFamily` discriminant (see [`crate::family`]).
    pub family: u8,
    /// Per-family message type.
    pub msg_type: u16,
    /// Frame flags; low 2 bits carry the priority class.
    pub flags: u16,
    /// Total header size (fixed 24 + optional TLV block).
    pub header_len: u16,
    /// Payload size in bytes, excluding the header.
    pub body_len: u32,
    /// Logical stream identifier used for multiplexing.
    pub stream_id: u32,
    /// Request/response correlation id.
    pub request_id: u32,
}

impl FrameHeader {
    /// Construct a fresh header with `family`/`msg_type` set and every other
    /// field at its zero default (`flags = 0`, `header_len = HEADER_SIZE`).
    pub fn new(family: u8, msg_type: u16) -> Self {
        Self {
            version: VERSION,
            family,
            msg_type,
            flags: 0,
            header_len: HEADER_SIZE as u16,
            body_len: 0,
            stream_id: 0,
            request_id: 0,
        }
    }

    /// Return the 2-bit priority class from `flags[1:0]`.
    pub fn priority(&self) -> u8 {
        (self.flags & FLAGS_PRIORITY_MASK) as u8
    }

    /// Set the 2-bit priority class in `flags[1:0]`.
    pub fn set_priority(&mut self, p: u8) {
        self.flags = (self.flags & !FLAGS_PRIORITY_MASK) | (p as u16 & FLAGS_PRIORITY_MASK);
    }
}
