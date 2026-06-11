//! Wire payloads for stateful return circuits (onion-registration epic, the
//! Epic 482.7 return path). See `docs/internal/PLAN_ANON_SERVICE_ONION_REGISTRATION.md`.
//!
//! **Slice b1 — wire + types only.** This module defines the crypto-INDEPENDENT
//! outer framing for the `RelayChainMsg::Circuit*` variants: the data-cell
//! header (`[circuit_id][seq][ciphertext]`, design §4.1 option D1) and the
//! teardown payload. The per-hop key-install payload (`CircuitBuild`) and the
//! layer crypto are deliberately NOT here — they are the anonymity-critical core
//! and land in b2/b3 under the threat-model gate. Nothing in this module
//! installs or peels circuit state; it is pure encode/decode framing.

use crate::circuit::CircuitError;

/// Per-link circuit identifier. Scoped to a single (link, direction) — each hop
/// re-tags `circuit_id_in → circuit_id_out`, so the same circuit shows a
/// DIFFERENT id on each link (that re-tagging is what stops a passive observer
/// from following one id end-to-end). 32 bits: ample space, cheap header.
pub type CircuitId = u32;

/// Hard cap on a single circuit data cell's ciphertext, so a decoder never
/// trusts an unbounded length field. Matches the fixed onion cell budget
/// (`CELL_SIZE`); the exact figure is revisited in b3 when the data plane is
/// wired to the cell layer.
pub const MAX_CIRCUIT_DATA_CIPHERTEXT: usize = 512;

/// A data cell travelling along an established circuit, in EITHER direction
/// (originator→terminus or the return path). Outer header is cleartext so each
/// hop can route + re-tag without unwrapping the layered ciphertext.
///
/// Wire: `[circuit_id u32 BE][seq u32 BE][ciphertext_len u16 BE][ciphertext]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitDataPayload {
    /// Circuit id on the link this cell arrived/leaves on (re-tagged per hop).
    pub circuit_id: CircuitId,
    /// Per-circuit monotonic sequence (anti-replay window lands in b3).
    pub seq: u32,
    /// Layered ciphertext (peeled/added one layer per hop; opaque here).
    pub ciphertext: Vec<u8>,
}

impl CircuitDataPayload {
    /// `circuit_id + seq + ciphertext_len` prefix.
    pub const HEADER_LEN: usize = 4 + 4 + 2;

    pub fn encode(&self) -> Result<Vec<u8>, CircuitError> {
        if self.ciphertext.len() > MAX_CIRCUIT_DATA_CIPHERTEXT {
            return Err(CircuitError::Malformed(format!(
                "circuit data ciphertext {} > MAX {MAX_CIRCUIT_DATA_CIPHERTEXT}",
                self.ciphertext.len()
            )));
        }
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.circuit_id.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    pub fn decode(blob: &[u8]) -> Result<Self, CircuitError> {
        if blob.len() < Self::HEADER_LEN {
            return Err(CircuitError::Malformed(format!(
                "circuit data too short: {} < {}",
                blob.len(),
                Self::HEADER_LEN
            )));
        }
        let circuit_id = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]);
        let seq = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]);
        let len = u16::from_be_bytes([blob[8], blob[9]]) as usize;
        if len > MAX_CIRCUIT_DATA_CIPHERTEXT {
            return Err(CircuitError::Malformed(format!(
                "circuit data ciphertext_len {len} > MAX {MAX_CIRCUIT_DATA_CIPHERTEXT}"
            )));
        }
        if blob.len() < Self::HEADER_LEN + len {
            return Err(CircuitError::Malformed(format!(
                "circuit data truncated: have {}, need {}",
                blob.len(),
                Self::HEADER_LEN + len
            )));
        }
        Ok(Self {
            circuit_id,
            seq,
            ciphertext: blob[Self::HEADER_LEN..Self::HEADER_LEN + len].to_vec(),
        })
    }
}

/// Tear down a circuit on a link + free its per-hop state. Sent in either
/// direction; a relay drops the `(link, circuit_id)` state and propagates
/// teardown to the matched neighbour (propagation logic lands in b6).
///
/// Wire: `[circuit_id u32 BE]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitTeardownPayload {
    /// Circuit id on the link this teardown arrived on.
    pub circuit_id: CircuitId,
}

impl CircuitTeardownPayload {
    pub const WIRE_LEN: usize = 4;

    pub fn encode(&self) -> [u8; Self::WIRE_LEN] {
        self.circuit_id.to_be_bytes()
    }

    pub fn decode(blob: &[u8]) -> Result<Self, CircuitError> {
        if blob.len() < Self::WIRE_LEN {
            return Err(CircuitError::Malformed(format!(
                "circuit teardown too short: {} < {}",
                blob.len(),
                Self::WIRE_LEN
            )));
        }
        Ok(Self {
            circuit_id: u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_data_roundtrip() {
        let p = CircuitDataPayload {
            circuit_id: 0xDEAD_BEEF,
            seq: 42,
            ciphertext: vec![1, 2, 3, 4, 5],
        };
        let enc = p.encode().unwrap();
        assert_eq!(CircuitDataPayload::decode(&enc).unwrap(), p);
    }

    #[test]
    fn circuit_data_empty_ciphertext_roundtrip() {
        let p = CircuitDataPayload {
            circuit_id: 1,
            seq: 0,
            ciphertext: vec![],
        };
        let enc = p.encode().unwrap();
        assert_eq!(enc.len(), CircuitDataPayload::HEADER_LEN);
        assert_eq!(CircuitDataPayload::decode(&enc).unwrap(), p);
    }

    #[test]
    fn circuit_data_rejects_oversize() {
        let p = CircuitDataPayload {
            circuit_id: 1,
            seq: 1,
            ciphertext: vec![0u8; MAX_CIRCUIT_DATA_CIPHERTEXT + 1],
        };
        assert!(p.encode().is_err());
    }

    #[test]
    fn circuit_data_rejects_truncated() {
        assert!(CircuitDataPayload::decode(&[0u8; 3]).is_err());
        // Header claims 10 bytes of ciphertext but body is empty.
        let mut blob = Vec::new();
        blob.extend_from_slice(&7u32.to_be_bytes());
        blob.extend_from_slice(&0u32.to_be_bytes());
        blob.extend_from_slice(&10u16.to_be_bytes());
        assert!(CircuitDataPayload::decode(&blob).is_err());
    }

    #[test]
    fn circuit_teardown_roundtrip() {
        let p = CircuitTeardownPayload {
            circuit_id: 0x0102_0304,
        };
        assert_eq!(CircuitTeardownPayload::decode(&p.encode()).unwrap(), p);
        assert!(CircuitTeardownPayload::decode(&[0u8; 3]).is_err());
    }
}
