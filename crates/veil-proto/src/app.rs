//! Application-plane payload structs for the OVL1 binary protocol.
//!
//! Each struct corresponds to one `AppMsg` variant and is encoded as the frame
//! body (bytes following the fixed `FrameHeader`). Encoding is manual
//! big-endian byte packing — no external serde dependency.
//!
//! # Message semantics
//!
//! | Struct | `AppMsg` variant | Semantics |
//! |---------------------|------------------|----------------------------------|
//! | `AppOpenPayload` | `AppOpen` | Open a stream to an app endpoint |
//! | `AppDataPayload` | `AppData` | Ordered stream data segment |
//! | `AppClosePayload` | `AppClose` | Close a stream |
//! | `AppSendPayload` | `AppSend` | Datagram (fire-and-forget) |
//! | `AppReceiptPayload` | `AppReceipt` | Delivery receipt for AppSend |

use super::ProtoError;

// ── AppOpenPayload ────────────────────────────────────────────────────────────

/// Open a stream to a remote application endpoint.
///
/// Wire layout:
/// ```text
/// [0..32] app_id [u8; 32]
/// [32..36] endpoint_id u32 BE
/// [36..38] flags u16 BE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppOpenPayload {
    /// Target app's `app_id`.
    pub app_id: [u8; 32],
    /// Bound endpoint on the target app.
    pub endpoint_id: u32,
    /// Reserved flags bitmask.
    pub flags: u16,
}

impl AppOpenPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 4 + 2;

    /// Encode to the fixed 38-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.app_id);
        buf[32..36].copy_from_slice(&self.endpoint_id.to_be_bytes());
        buf[36..38].copy_from_slice(&self.flags.to_be_bytes());
        buf
    }

    /// Parse from a 38-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            app_id: super::read_array::<32>(buf, 0)?,
            endpoint_id: super::read_u32_be(buf, 32)?,
            flags: super::read_u16_be(buf, 36)?,
        })
    }
}

// ── AppDataPayload ────────────────────────────────────────────────────────────

/// Ordered stream data segment.
///
/// Wire layout:
/// ```text
/// [0..32] app_id [u8; 32]
/// [32..36] endpoint_id u32 BE
/// [36..44] seq u64 BE (per-stream sequence number)
/// [44..48] data_len u32 BE
/// [48..48+data_len] data bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDataPayload {
    /// Target app's `app_id`.
    pub app_id: [u8; 32],
    /// Target endpoint on the receiving app.
    pub endpoint_id: u32,
    /// Per-stream sequence number.
    pub seq: u64,
    /// Payload bytes.
    pub data: Vec<u8>,
}

impl AppDataPayload {
    const FIXED_SIZE: usize = 32 + 4 + 8 + 4; // 48

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.data.len());
        buf.extend_from_slice(&self.app_id);
        buf.extend_from_slice(&self.endpoint_id.to_be_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        debug_assert!(
            self.data.len() <= crate::codec::MAX_FRAME_BODY as usize,
            "AppDataPayload data {} exceeds MAX_FRAME_BODY",
            self.data.len(),
        );
        let data = if self.data.len() > crate::codec::MAX_FRAME_BODY as usize {
            &self.data[..crate::codec::MAX_FRAME_BODY as usize]
        } else {
            &self.data
        };
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
        buf
    }

    /// Parse an `AppDataPayload` from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let app_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let endpoint_id = super::read_u32_be(buf, 32)?;
        let seq = super::read_u64_be(buf, 36)?;
        let data_len = super::read_u32_be(buf, 44)? as usize;
        // checked_add — 32-bit overflow defence.
        let end = 48usize
            .checked_add(data_len)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
        if buf.len() < end {
            return Err(ProtoError::BufferTooShort {
                need: end,
                got: buf.len(),
            });
        }
        Ok(Self {
            app_id,
            endpoint_id,
            seq,
            data: buf[48..end].to_vec(),
        })
    }
}

// ── AppClosePayload ───────────────────────────────────────────────────────────

/// Close reason codes for `AppClosePayload`.
pub mod close_reason {
    /// Normal (graceful) close initiated by the sender.
    pub const NORMAL: u8 = 0;
    /// Application-level error forced the close.
    pub const ERROR: u8 = 1;
    /// Stream timed out.
    pub const TIMEOUT: u8 = 2;
    /// Remote side refused the open request.
    pub const REFUSED: u8 = 3;
}

/// Close a stream.
///
/// Wire layout:
/// ```text
/// [0..32] app_id [u8; 32]
/// [32..36] endpoint_id u32 BE
/// [36] reason u8
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppClosePayload {
    /// Target app's `app_id`.
    pub app_id: [u8; 32],
    /// Endpoint being closed.
    pub endpoint_id: u32,
    /// Close reason (see [`close_reason`]).
    pub reason: u8,
}

impl AppClosePayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 4 + 1;

    /// Encode to the fixed 37-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.app_id);
        buf[32..36].copy_from_slice(&self.endpoint_id.to_be_bytes());
        buf[36] = self.reason;
        buf
    }

    /// Parse from a 37-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            app_id: super::read_array::<32>(buf, 0)?,
            endpoint_id: super::read_u32_be(buf, 32)?,
            reason: buf[36],
        })
    }
}

// ── AppSendPayload ────────────────────────────────────────────────────────────

/// Datagram (fire-and-forget) application message.
///
/// Wire layout:
/// ```text
/// [0..32] src_app_id [u8; 32]
/// [32..64] app_id [u8; 32] (destination)
/// [64..68] endpoint_id u32 BE (destination)
/// [68..72] data_len u32 BE
/// [72..72+data_len] data bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSendPayload {
    /// Sender's app_id on the originating node.
    pub src_app_id: [u8; 32],
    /// Destination app's `app_id`.
    pub app_id: [u8; 32],
    /// Destination endpoint.
    pub endpoint_id: u32,
    /// Datagram payload. d: pool-backed for chat_node 60 KB-frame
    /// load — eliminates the `.to_vec` 60 KB malloc per inbound msg
    /// previously fueling jemalloc dirty-page retention.
    pub data: veil_bufpool::PooledShared,
}

impl AppSendPayload {
    const FIXED_SIZE: usize = 32 + 32 + 4 + 4; // 72

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let data_full: &[u8] = &self.data;
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + data_full.len());
        buf.extend_from_slice(&self.src_app_id);
        buf.extend_from_slice(&self.app_id);
        buf.extend_from_slice(&self.endpoint_id.to_be_bytes());
        debug_assert!(
            data_full.len() <= crate::codec::MAX_FRAME_BODY as usize,
            "AppIpcSendPayload data {} exceeds MAX_FRAME_BODY",
            data_full.len(),
        );
        let data = if data_full.len() > crate::codec::MAX_FRAME_BODY as usize {
            &data_full[..crate::codec::MAX_FRAME_BODY as usize]
        } else {
            data_full
        };
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
        buf
    }

    /// Parse an `AppSendPayload` from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let src_app_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let app_id: [u8; 32] = super::read_array::<32>(buf, 32)?;
        let endpoint_id = super::read_u32_be(buf, 64)?;
        let data_len = super::read_u32_be(buf, 68)? as usize;
        // checked_add — 32-bit overflow defence.
        let end = 72usize
            .checked_add(data_len)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
        if buf.len() < end {
            return Err(ProtoError::BufferTooShort {
                need: end,
                got: buf.len(),
            });
        }
        // d: pool the data field (eliminates 60 KB malloc per OVL1
        // AppSend frame on receiver side — symmetric with the IPC inbound
        // path's AppIpcSendPayload decode).
        let mut pooled = veil_bufpool::global().acquire(data_len);
        pooled.as_vec_mut().extend_from_slice(&buf[72..end]);
        Ok(Self {
            src_app_id,
            app_id,
            endpoint_id,
            data: pooled.into_shared(),
        })
    }
}

// ── AppReceiptPayload ─────────────────────────────────────────────────────────

/// Receipt status codes for `AppReceiptPayload`.
pub mod receipt_status {
    /// Receiver accepted the datagram and queued it locally.
    pub const ACCEPTED: u8 = 0;
    /// Receiver delivered the datagram to its application.
    pub const DELIVERED: u8 = 1;
    /// Receiver has no matching endpoint for the datagram.
    pub const NOT_FOUND: u8 = 2;
    /// Receiver refused the datagram (quota, rate limit, etc.).
    pub const REJECTED: u8 = 3;
}

/// Delivery receipt for an `AppSend` datagram.
///
/// Wire layout:
/// ```text
/// [0..32] app_id [u8; 32]
/// [32..36] endpoint_id u32 BE
/// [36..44] seq u64 BE (matches the AppSend this receipts, if tracked)
/// [44] status u8
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppReceiptPayload {
    /// Receipt-carrying app's `app_id`.
    pub app_id: [u8; 32],
    /// Endpoint that produced the receipt.
    pub endpoint_id: u32,
    /// Sequence number of the `AppSend` being acknowledged.
    pub seq: u64,
    /// One [`receipt_status`] codes.
    pub status: u8,
}

impl AppReceiptPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 4 + 8 + 1;

    /// Encode to the fixed 45-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.app_id);
        buf[32..36].copy_from_slice(&self.endpoint_id.to_be_bytes());
        buf[36..44].copy_from_slice(&self.seq.to_be_bytes());
        buf[44] = self.status;
        buf
    }

    /// Parse from a 45-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            app_id: super::read_array::<32>(buf, 0)?,
            endpoint_id: super::read_u32_be(buf, 32)?,
            seq: super::read_u64_be(buf, 36)?,
            status: buf[44],
        })
    }
}

// ── AppWindowUpdatePayload ────────────────────────────────────────────────────

/// Increase the receive window for an veil application stream.
///
/// Sent by the receiver to grant additional send credits to the sender.
///
/// Wire layout:
/// ```text
/// [0..4] stream_id u32 BE
/// [4..8] increment u32 BE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppWindowUpdatePayload {
    /// Stream the credit applies to.
    pub stream_id: u32,
    /// Number of additional bytes the sender may send.
    pub increment: u32,
}

impl AppWindowUpdatePayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 4 + 4;

    /// Encode to the fixed 8-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..4].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[4..8].copy_from_slice(&self.increment.to_be_bytes());
        buf
    }

    /// Parse from an 8-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            stream_id: super::read_u32_be(buf, 0)?,
            increment: super::read_u32_be(buf, 4)?,
        })
    }
}

// ── AppRtDataPayload ──────────────────────────────────────────────────────────

/// Real-time media frame for low-latency audio/video transport.
///
/// Unlike `AppDataPayload`, this frame is **loss-tolerant**: the receiver does
/// not enforce ordered delivery or flow-control windows. Sequence gaps are
/// expected and reported via metrics (`veil_rt_loss_rate`).
///
/// Wire layout:
/// ```text
/// [0..32] app_id [u8; 32]
/// [32..36] endpoint_id u32 BE
/// [36..40] seq u32 BE (monotonic, wraparound ok)
/// [40..48] timestamp_us u64 BE (media clock, microseconds)
/// [48] marker u8 (e.g. RTP marker — last frame of talk-spurt)
/// [49..53] payload_type u32 BE (codec ID, app-defined)
/// [53..57] payload_len u32 BE
/// [57..] payload bytes
/// [57+payload_len..] src_app_id [u8; 32] (optional compatibility tail)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRtDataPayload {
    /// Originating app's `app_id`. Appended after the payload on the wire so
    /// older receivers safely ignore it. A missing legacy tail decodes to
    /// zero and must be treated as unauthenticated by applications.
    pub src_app_id: [u8; 32],
    /// Target app's `app_id`.
    pub app_id: [u8; 32],
    /// Endpoint delivering the RT frame.
    pub endpoint_id: u32,
    /// Monotonic sequence (wraparound-safe).
    pub seq: u32,
    /// Media clock in microseconds.
    pub timestamp_us: u64,
    /// RTP-style marker bit (e.g. end-of-talk-spurt).
    pub marker: u8,
    /// App-defined codec identifier.
    pub payload_type: u32,
    /// Codec-level payload bytes.
    pub payload: Vec<u8>,
}

impl AppRtDataPayload {
    /// Fixed-size header portion (without variable-length payload).
    pub const HEADER_SIZE: usize = 32 + 4 + 4 + 8 + 1 + 4 + 4;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.app_id);
        buf.extend_from_slice(&self.endpoint_id.to_be_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_us.to_be_bytes());
        buf.push(self.marker);
        buf.extend_from_slice(&self.payload_type.to_be_bytes());
        debug_assert!(
            self.payload.len() <= crate::codec::MAX_FRAME_BODY as usize,
            "AppRtDataPayload payload {} exceeds MAX_FRAME_BODY",
            self.payload.len(),
        );
        let payload = if self.payload.len() > crate::codec::MAX_FRAME_BODY as usize {
            &self.payload[..crate::codec::MAX_FRAME_BODY as usize]
        } else {
            &self.payload
        };
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&self.src_app_id);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let app_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let endpoint_id = super::read_u32_be(buf, 32)?;
        let seq = super::read_u32_be(buf, 36)?;
        let timestamp_us = super::read_u64_be(buf, 40)?;
        let marker = buf[48];
        let payload_type = super::read_u32_be(buf, 49)?;
        let payload_len = super::read_u32_be(buf, 53)? as usize;
        // checked_add — 32-bit overflow defence.
        let end = Self::HEADER_SIZE
            .checked_add(payload_len)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
        if buf.len() < end {
            return Err(ProtoError::BufferTooShort {
                need: end,
                got: buf.len(),
            });
        }
        let payload_start = 57usize;
        let payload_end =
            payload_start
                .checked_add(payload_len)
                .ok_or(ProtoError::BufferTooShort {
                    need: usize::MAX,
                    got: buf.len(),
                })?;
        let src_app_id = if payload_end
            .checked_add(32)
            .is_some_and(|end| buf.len() >= end)
        {
            super::read_array::<32>(buf, payload_end)?
        } else {
            [0u8; 32]
        };
        Ok(Self {
            src_app_id,
            app_id,
            endpoint_id,
            seq,
            timestamp_us,
            marker,
            payload_type,
            payload: buf[payload_start..payload_end].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_app_id() -> [u8; 32] {
        [0xABu8; 32]
    }

    #[test]
    fn app_open_roundtrip() {
        let p = AppOpenPayload {
            app_id: sample_app_id(),
            endpoint_id: 7,
            flags: 0xF0_0D,
        };
        let encoded = p.encode();
        let decoded = AppOpenPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn app_open_too_short() {
        let err = AppOpenPayload::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn app_data_roundtrip() {
        let p = AppDataPayload {
            app_id: sample_app_id(),
            endpoint_id: 3,
            seq: 12345678,
            data: b"application payload".to_vec(),
        };
        let encoded = p.encode();
        let decoded = AppDataPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn app_data_empty() {
        let p = AppDataPayload {
            app_id: sample_app_id(),
            endpoint_id: 0,
            seq: 0,
            data: vec![],
        };
        assert_eq!(AppDataPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn app_data_too_short() {
        let err = AppDataPayload::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn app_close_roundtrip() {
        let p = AppClosePayload {
            app_id: sample_app_id(),
            endpoint_id: 99,
            reason: close_reason::ERROR,
        };
        let encoded = p.encode();
        let decoded = AppClosePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn app_close_too_short() {
        let err = AppClosePayload::decode(&[0u8; 5]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn app_send_roundtrip() {
        let p = AppSendPayload {
            src_app_id: [0u8; 32],
            app_id: sample_app_id(),
            endpoint_id: 42,
            data: veil_bufpool::pooled_shared_from_vec(b"datagram!".to_vec()),
        };
        assert_eq!(AppSendPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn app_send_empty_data() {
        let p = AppSendPayload {
            src_app_id: [0u8; 32],
            app_id: sample_app_id(),
            endpoint_id: 0,
            data: veil_bufpool::pooled_shared_from_vec(vec![]),
        };
        assert_eq!(AppSendPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn app_send_too_short() {
        let err = AppSendPayload::decode(&[0u8; 5]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn app_receipt_roundtrip() {
        let p = AppReceiptPayload {
            app_id: sample_app_id(),
            endpoint_id: 1,
            seq: 999,
            status: receipt_status::DELIVERED,
        };
        let encoded = p.encode();
        let decoded = AppReceiptPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn app_receipt_too_short() {
        let err = AppReceiptPayload::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn app_rt_data_roundtrip() {
        let p = AppRtDataPayload {
            src_app_id: [0x5Au8; 32],
            app_id: sample_app_id(),
            endpoint_id: 42,
            seq: 1234,
            timestamp_us: 987_654_321_000,
            marker: 1,
            payload_type: 111,
            payload: b"opus_frame_data".to_vec(),
        };
        let encoded = p.encode();
        let decoded = AppRtDataPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn app_rt_data_empty_payload() {
        let p = AppRtDataPayload {
            src_app_id: [0x5Bu8; 32],
            app_id: sample_app_id(),
            endpoint_id: 1,
            seq: 0,
            timestamp_us: 0,
            marker: 0,
            payload_type: 0,
            payload: vec![],
        };
        let encoded = p.encode();
        let decoded = AppRtDataPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn app_rt_data_too_short() {
        let err = AppRtDataPayload::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn app_rt_data_legacy_without_source_fails_closed() {
        let p = AppRtDataPayload {
            src_app_id: [0x5Cu8; 32],
            app_id: sample_app_id(),
            endpoint_id: 7,
            seq: 9,
            timestamp_us: 11,
            marker: 0,
            payload_type: 111,
            payload: b"legacy-compatible".to_vec(),
        };
        let mut encoded = p.encode();
        encoded.truncate(encoded.len() - 32);
        let decoded = AppRtDataPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.src_app_id, [0u8; 32]);
        assert_eq!(decoded.payload, p.payload);
    }
}
