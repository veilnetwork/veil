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
use crate::circuit_data::CIRCUIT_PAYLOAD_BYTES;

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
    /// Per-circuit sequence, anti-replay + keystream nonce.
    ///
    /// Δ2-f note: unlike `circuit_id`, `seq` is NOT re-tagged per hop — it is
    /// the SAME value end-to-end (the relay re-emits it verbatim). This is
    /// load-bearing, not an oversight: it is the nonce in the length-preserving
    /// XOR keystream (`circuit_data::keystream`), where the originator
    /// pre-applies every hop's layer under one `seq` and each hop peels under
    /// that same `seq`; and it is the drop-tolerant anti-replay token
    /// (`ReplayWindow`), so it can't be an implicit per-hop counter (onion legs
    /// drop cells). Hiding it on the wire would need a per-link header cipher —
    /// but relay-chain frames already ride the transport-encrypted session, so a
    /// non-hop observer never sees `seq`, and a hop already correlates its own
    /// two links via its `(link, circuit_id)` state. A per-link header cipher
    /// would therefore be redundant with the transport layer.
    pub seq: u32,
    /// Layered ciphertext (peeled/added one layer per hop; opaque here).
    pub ciphertext: Vec<u8>,
}

impl CircuitDataPayload {
    /// `circuit_id + seq + ciphertext_len` prefix.
    pub const HEADER_LEN: usize = 4 + 4 + 2;

    pub fn encode(&self) -> Result<Vec<u8>, CircuitError> {
        // diff-audit Δ2-f: every circuit data cell carries EXACTLY the fixed
        // payload size — `wrap_payload` pads to it and the XOR layers are
        // length-preserving, so legitimate cells are always this size. Enforce it
        // (rather than the old `<= MAX` cap) so a variable-length cell can never
        // reach the wire as a size-correlation fingerprint for a passive observer.
        if self.ciphertext.len() != CIRCUIT_PAYLOAD_BYTES {
            return Err(CircuitError::Malformed(format!(
                "circuit data ciphertext {} != fixed {CIRCUIT_PAYLOAD_BYTES}",
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
        // Δ2-f: reject any cell that is not the fixed payload size (see `encode`).
        if len != CIRCUIT_PAYLOAD_BYTES {
            return Err(CircuitError::Malformed(format!(
                "circuit data ciphertext_len {len} != fixed {CIRCUIT_PAYLOAD_BYTES}"
            )));
        }
        // Exact length: reject BOTH truncation and trailing garbage. The cell
        // is delivered as an exact RelayChainMsg frame body (body_len), so a
        // legitimate cell is precisely HEADER_LEN + the fixed payload; anything
        // longer is wire malleability (bad for fuzz/versioning), not a real cell.
        if blob.len() != Self::HEADER_LEN + len {
            return Err(CircuitError::Malformed(format!(
                "circuit data wrong length: have {}, need exactly {}",
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
        if blob.len() != Self::WIRE_LEN {
            return Err(CircuitError::Malformed(format!(
                "circuit teardown wrong length: {} != {}",
                blob.len(),
                Self::WIRE_LEN
            )));
        }
        Ok(Self {
            circuit_id: u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]),
        })
    }
}

/// Domain separator for [`circuit_built_token`]. Distinct context string ⇒ the
/// token cannot collide with any other use of the same circuit key (notably the
/// data-cell keystream in `circuit_data`).
const CIRCUIT_BUILT_CONTEXT: &str = "veil.anonymity.circuit_built.v1 terminus ack token";

/// Proof that the sender of a `CircuitBuilt` ACK holds the **terminus** hop key
/// of this circuit.
///
/// ## What it is for
///
/// The ACK's only other field is a circuit id, and every hop knows the id of
/// the link it sits on — including the first hop, which knows the very id the
/// originator matches on. So any hop could synthesise the ACK and have the
/// originator mark a circuit CONFIRMED (and freeze that path) without a single
/// byte having reached the terminus: a black hole that looks healthy.
///
/// The originator picks a fresh random `circuit_key` per hop and delivers each
/// one sealed to that hop's X25519 public key inside the setup envelope. The
/// terminus key is therefore known to exactly two parties — the originator and
/// the node the originator chose as terminus — and to nobody in between. A
/// token derived from it proves both that the ACK came from the terminus and
/// that it belongs to *this* circuit, because the key is fresh per circuit.
/// There is nothing variable left to bind, so the token is the derivation
/// itself rather than a MAC over a message.
///
/// Replaying a captured token only re-confirms the circuit it was minted for,
/// which is already confirmed; it carries no authority anywhere else.
#[must_use]
pub fn circuit_built_token(circuit_key: &[u8; crate::circuit_setup::CIRCUIT_KEY_LEN]) -> [u8; 32] {
    blake3::derive_key(CIRCUIT_BUILT_CONTEXT, circuit_key)
}

/// Constant-time compare of two ACK tokens.
///
/// Variable-time comparison here would leak a prefix oracle to whichever hop
/// forwards the ACK: it could bisect a valid token one byte at a time by
/// watching how long the originator takes to reject.
#[must_use]
pub fn circuit_built_token_matches(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Terminus → originator circuit-establishment ACK (diff-audit Δ2-d). Routed
/// back down the return path; each hop re-tags `circuit_id` (like a return data
/// cell) so the originator matches it against its origin circuit and marks the
/// circuit CONFIRMED.
///
/// Wire: `[circuit_id u32 BE][token 32]`.
///
/// **Breaking wire change.** The ACK used to be the bare circuit id, which any
/// hop could forge — see [`circuit_built_token`]. There is no version
/// negotiation on relay-chain messages, so a node of the old shape drops these
/// frames (exact-length decode) and confirms nothing: circuits stay
/// unconfirmed, which is the pre-existing safe state, and path maintenance
/// re-selects as it already does for an unconfirmed circuit. Roll relays before
/// clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitBuiltPayload {
    /// Circuit id on the link this ACK arrived on.
    pub circuit_id: CircuitId,
    /// Terminus proof-of-key token; see [`circuit_built_token`]. Forwarded
    /// unchanged by intermediate hops, which re-tag only `circuit_id`.
    pub token: [u8; 32],
}

impl CircuitBuiltPayload {
    pub const WIRE_LEN: usize = 4 + 32;

    pub fn encode(&self) -> [u8; Self::WIRE_LEN] {
        let mut out = [0u8; Self::WIRE_LEN];
        out[..4].copy_from_slice(&self.circuit_id.to_be_bytes());
        out[4..].copy_from_slice(&self.token);
        out
    }

    pub fn decode(blob: &[u8]) -> Result<Self, CircuitError> {
        if blob.len() != Self::WIRE_LEN {
            return Err(CircuitError::Malformed(format!(
                "circuit built wrong length: {} != {}",
                blob.len(),
                Self::WIRE_LEN
            )));
        }
        let mut token = [0u8; 32];
        token.copy_from_slice(&blob[4..]);
        Ok(Self {
            circuit_id: u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]),
            token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_built_roundtrip() {
        let p = CircuitBuiltPayload {
            circuit_id: 0x1234_5678,
            token: [0xA5; 32],
        };
        assert_eq!(CircuitBuiltPayload::decode(&p.encode()).unwrap(), p);
        assert!(CircuitBuiltPayload::decode(&[0u8; 3]).is_err());
    }

    /// The old bare-circuit-id ACK is exactly the forgeable shape this
    /// change removes; it must not decode into an ACK whose token would
    /// then be compared against something.
    #[test]
    fn the_legacy_bare_circuit_id_ack_no_longer_decodes() {
        let legacy = 0x1234_5678u32.to_be_bytes();
        assert!(CircuitBuiltPayload::decode(&legacy).is_err());
    }

    /// The token is a function of the terminus key alone, so two circuits
    /// never share one and a hop that lacks the key cannot produce it.
    #[test]
    fn the_token_is_bound_to_its_circuit_key() {
        let key_a = [7u8; crate::circuit_setup::CIRCUIT_KEY_LEN];
        let mut key_b = key_a;
        key_b[0] ^= 1;

        let tok_a = circuit_built_token(&key_a);
        assert_eq!(tok_a, circuit_built_token(&key_a), "must be deterministic");
        assert_ne!(
            tok_a,
            circuit_built_token(&key_b),
            "a one-bit different circuit key must give a different token"
        );
        assert_ne!(
            tok_a.as_slice(),
            key_a.as_slice(),
            "the token must not be the raw key — it travels the wire in clear"
        );
    }

    #[test]
    fn token_compare_accepts_equal_and_rejects_near_miss() {
        let a = circuit_built_token(&[3u8; crate::circuit_setup::CIRCUIT_KEY_LEN]);
        assert!(circuit_built_token_matches(&a, &a));
        for flip in [0usize, 15, 31] {
            let mut b = a;
            b[flip] ^= 1;
            assert!(
                !circuit_built_token_matches(&a, &b),
                "a single flipped bit at byte {flip} must not match"
            );
        }
    }

    #[test]
    fn circuit_data_roundtrip() {
        let mut ciphertext = vec![0u8; CIRCUIT_PAYLOAD_BYTES];
        ciphertext[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        let p = CircuitDataPayload {
            circuit_id: 0xDEAD_BEEF,
            seq: 42,
            ciphertext,
        };
        let enc = p.encode().unwrap();
        assert_eq!(
            enc.len(),
            CircuitDataPayload::HEADER_LEN + CIRCUIT_PAYLOAD_BYTES
        );
        assert_eq!(CircuitDataPayload::decode(&enc).unwrap(), p);
    }

    #[test]
    fn circuit_data_rejects_non_fixed_size_delta2f() {
        // Δ2-f: only the fixed cell size is valid on the wire — an empty or
        // otherwise-sized ciphertext is rejected at encode AND decode.
        let empty = CircuitDataPayload {
            circuit_id: 1,
            seq: 0,
            ciphertext: vec![],
        };
        assert!(empty.encode().is_err(), "empty ciphertext must be rejected");
        // A hand-built blob declaring a non-fixed length is rejected at decode.
        let mut blob = Vec::new();
        blob.extend_from_slice(&1u32.to_be_bytes());
        blob.extend_from_slice(&0u32.to_be_bytes());
        blob.extend_from_slice(&(100u16).to_be_bytes());
        blob.extend_from_slice(&[0u8; 100]);
        assert!(CircuitDataPayload::decode(&blob).is_err());
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
        // Header declares the fixed size but the body is truncated.
        let mut blob = Vec::new();
        blob.extend_from_slice(&7u32.to_be_bytes());
        blob.extend_from_slice(&0u32.to_be_bytes());
        blob.extend_from_slice(&(CIRCUIT_PAYLOAD_BYTES as u16).to_be_bytes());
        blob.extend_from_slice(&[0u8; 8]); // far short of CIRCUIT_PAYLOAD_BYTES
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

    // Exact-length decode: every wire decoder rejects trailing garbage after a
    // valid payload (protocol malleability / fuzz-seed hardening). The decoders
    // are fed exact frame bodies (RelayChainMsg body_len), so a legitimate
    // producer never appends trailing bytes.
    #[test]
    fn circuit_wire_decoders_reject_trailing_bytes() {
        // CircuitDataPayload: valid fixed cell + one trailing byte.
        let data = CircuitDataPayload {
            circuit_id: 0xAABB_CCDD,
            seq: 9,
            ciphertext: vec![7u8; CIRCUIT_PAYLOAD_BYTES],
        };
        let mut enc = data.encode().unwrap();
        assert!(CircuitDataPayload::decode(&enc).is_ok());
        enc.push(0x00); // trailing garbage
        assert!(
            CircuitDataPayload::decode(&enc).is_err(),
            "CircuitDataPayload must reject trailing bytes"
        );

        // CircuitBuiltPayload: exact-length payload + trailing.
        let built = CircuitBuiltPayload {
            circuit_id: 1,
            token: [0u8; 32],
        };
        let mut b = built.encode().to_vec();
        b.push(0xFF);
        assert!(
            CircuitBuiltPayload::decode(&b).is_err(),
            "CircuitBuiltPayload must reject trailing bytes"
        );

        // CircuitTeardownPayload: 4-byte payload + trailing.
        let td = CircuitTeardownPayload { circuit_id: 2 };
        let mut t = td.encode().to_vec();
        t.extend_from_slice(&[0xDE, 0xAD]);
        assert!(
            CircuitTeardownPayload::decode(&t).is_err(),
            "CircuitTeardownPayload must reject trailing bytes"
        );
    }
}
