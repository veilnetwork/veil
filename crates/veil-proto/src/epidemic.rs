//! Epidemic broadcast payload.
//!
//! `EpidemicPayload` is carried in a `ControlMsg::EpidemicBroadcast` frame.
//! Each node that receives a new (unseen) message delivers it locally and
//! forwards it to up to K random neighbours with `ttl` decremented by one.
//! Deduplication uses `msg_id` via an `EpidemicSeenSet`.

use super::ProtoError;

// ── EpidemicPayload ───────────────────────────────────────────────────────────

/// Payload for an epidemic flood broadcast.
///
/// Wire layout:
/// ```text
/// [0..16] msg_id [u8; 16] — random 128-bit message identifier
/// [16] ttl u8 — remaining hop count
/// [17..49] origin [u8; 32] — original sender node_id
/// [49..51] payload_len u16 BE
/// [51..51+payload_len] payload bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpidemicPayload {
    /// Random 128-bit identifier; used for deduplication.
    pub msg_id: [u8; 16],
    /// Remaining hop count. Nodes MUST NOT forward when this reaches 0.
    pub ttl: u8,
    /// Original sender's node_id.
    pub origin: [u8; 32],
    /// Application-level payload bytes.
    pub payload: Vec<u8>,
}

impl EpidemicPayload {
    const FIXED_SIZE: usize = 16 + 1 + 32 + 2; // msg_id + ttl + origin + payload_len

    /// Serialise to the wire layout:
    /// `msg_id(16) ‖ ttl(1) ‖ origin(32) ‖ payload_len(2 BE) ‖ payload`.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.payload.len() <= crate::budget::MAX_EPIDEMIC_PAYLOAD,
            "EpidemicBroadcast: payload exceeds MAX_EPIDEMIC_PAYLOAD"
        );
        // Clamp the length field and the appended bytes to the SAME value so
        // the frame is always self-consistent — a > u16::MAX payload can
        // never produce a length prefix that disagrees with the body (which
        // a bare `as u16` cast would, by wrapping to 0). Producers are bounded
        // well under this; the clamp is purely a corruption backstop.
        let len = self.payload.len().min(u16::MAX as usize);
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + len);
        buf.extend_from_slice(&self.msg_id);
        buf.push(self.ttl);
        buf.extend_from_slice(&self.origin);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload[..len]);
        buf
    }

    /// Parse an `EpidemicPayload` from `buf`, enforcing
    /// `payload_len ≤ MAX_EPIDEMIC_PAYLOAD`.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let msg_id: [u8; 16] = super::read_array::<16>(buf, 0)?;
        let ttl = buf[16];
        let origin: [u8; 32] = super::read_array::<32>(buf, 17)?;
        let payload_len = super::read_u16_be(buf, 49)? as usize;
        let payload = super::read_slice(
            buf,
            51,
            payload_len,
            crate::budget::MAX_EPIDEMIC_PAYLOAD,
            "payload_len",
        )?
        .to_vec();
        Ok(Self {
            msg_id,
            ttl,
            origin,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epidemic_roundtrip() {
        let ep = EpidemicPayload {
            msg_id: [0xab; 16],
            ttl: 7,
            origin: [0x11; 32],
            payload: b"hello epidemic".to_vec(),
        };
        let enc = ep.encode();
        let dec = EpidemicPayload::decode(&enc).unwrap();
        assert_eq!(ep, dec);
    }

    #[test]
    fn epidemic_empty_payload() {
        let ep = EpidemicPayload {
            msg_id: [0u8; 16],
            ttl: 0,
            origin: [0u8; 32],
            payload: vec![],
        };
        let enc = ep.encode();
        let dec = EpidemicPayload::decode(&enc).unwrap();
        assert_eq!(ep, dec);
    }

    #[test]
    fn epidemic_decode_too_short() {
        assert!(EpidemicPayload::decode(&[0u8; 10]).is_err());
    }
}
