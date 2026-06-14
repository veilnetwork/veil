//! Stateful-circuit DATA plane — FIXED-SIZE, length-preserving onion layers
//! (onion-registration epic b3 + 2a). See
//! `docs/internal/PLAN_ANON_SERVICE_ONION_REGISTRATION.md` §3.C.
//!
//! Each per-hop layer is a **BLAKE3-XOF keystream XOR** under the b2-installed
//! `circuit_key` — length-preserving and self-inverse. So a data cell is the
//! SAME size on every link, regardless of hop position. (The first cut used a
//! per-layer ChaCha20-Poly1305 AEAD whose 16-byte tag grew/shrank the cell per
//! hop, leaking hop position to a passive observer — 2a fixes that.)
//!
//! **Integrity** is end-to-end, NOT per layer: the payload that flows is a
//! sealed introduce (its own ChaCha20-Poly1305 to the recipient's x25519 key),
//! so a hop that flips bits in the XOR stream just makes the recipient's inner
//! AEAD fail closed; a hop can never forge a valid introduce (no x25519 key).
//! General (plaintext) circuit data would need an end-to-end MAC at this layer —
//! out of scope, only sealed introduces flow today.
//!
//! XOR is commutative + self-inverse, so layering is trivial: the originator
//! applies EVERY hop's keystream; each hop applies its own (removing it); the
//! terminus/originator end up with the payload. Forward and Return derive
//! SEPARATE sub-keystreams, and the per-cell `seq` keeps each cell's keystream
//! unique (the key is reused — the counter is what guarantees that, exactly as
//! `onion.rs::derive_nonce` warns for a stateful circuit).

use rand_core::{OsRng, RngCore};

use crate::circuit::CircuitError;
use crate::circuit_setup::CIRCUIT_KEY_LEN;

/// Fixed on-the-wire size of a circuit data cell's payload field — constant for
/// EVERY cell so size never reveals hop position. Sized to hold the largest
/// sealed introduce (`MAX_INTRODUCE_CIPHERTEXT` = 320) + the length prefix +
/// slack.
pub const CIRCUIT_PAYLOAD_BYTES: usize = 384;
/// Length-prefix width inside the fixed payload (`[len u16 BE][bytes][pad]`).
const LEN_PREFIX: usize = 2;
/// Largest real payload that fits one fixed cell.
pub const MAX_CIRCUIT_INNER: usize = CIRCUIT_PAYLOAD_BYTES - LEN_PREFIX;

/// Travel direction along a circuit. Mixed into the keystream so the two
/// directions are cryptographically independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Originator → terminus.
    Forward,
    /// Terminus → originator (the return path that hides the originator).
    Return,
}

impl Direction {
    fn tag(self) -> u8 {
        match self {
            Direction::Forward => 0x01,
            Direction::Return => 0x02,
        }
    }
}

/// Fill `out` with this hop's per-(direction, seq) keystream.
fn keystream(circuit_key: &[u8; CIRCUIT_KEY_LEN], dir: Direction, seq: u32, out: &mut [u8]) {
    let mut h = blake3::Hasher::new();
    h.update(b"veil.circuit.data.xof.v1\0");
    h.update(&[dir.tag()]);
    h.update(&seq.to_be_bytes());
    h.update(circuit_key);
    let mut reader = h.finalize_xof();
    reader.fill(out);
}

/// XOR one circuit layer in place under `circuit_key` for `(dir, seq)`.
/// Length-preserving and self-inverse — sealing and peeling are the same call.
pub fn apply_layer(circuit_key: &[u8; CIRCUIT_KEY_LEN], dir: Direction, seq: u32, buf: &mut [u8]) {
    let mut ks = vec![0u8; buf.len()];
    keystream(circuit_key, dir, seq, &mut ks);
    for (b, k) in buf.iter_mut().zip(ks.iter()) {
        *b ^= k;
    }
}

/// Apply every key's layer (originator side). XOR is commutative, so order is
/// irrelevant; pass the full circuit key set first-hop → terminus.
pub fn apply_layers(
    keys: &[[u8; CIRCUIT_KEY_LEN]],
    dir: Direction,
    seq: u32,
    buf: &mut [u8],
) -> Result<(), CircuitError> {
    if keys.is_empty() {
        return Err(CircuitError::NoHops);
    }
    for k in keys {
        apply_layer(k, dir, seq, buf);
    }
    Ok(())
}

/// Frame a payload into a FIXED-SIZE cell buffer: `[len u16 BE][payload][random
/// pad]`. The pad is random so a fixed cell reveals nothing about the payload
/// length to a hop (the recipient reads `len` back out after peeling).
pub fn wrap_payload(payload: &[u8]) -> Result<Vec<u8>, CircuitError> {
    if payload.len() > MAX_CIRCUIT_INNER {
        return Err(CircuitError::Malformed(format!(
            "circuit payload {} > MAX {MAX_CIRCUIT_INNER}",
            payload.len()
        )));
    }
    let mut buf = vec![0u8; CIRCUIT_PAYLOAD_BYTES];
    buf[..LEN_PREFIX].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    buf[LEN_PREFIX..LEN_PREFIX + payload.len()].copy_from_slice(payload);
    OsRng.fill_bytes(&mut buf[LEN_PREFIX + payload.len()..]);
    Ok(buf)
}

/// Read the payload back out of a peeled fixed-size cell buffer.
pub fn read_payload(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < LEN_PREFIX {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if LEN_PREFIX + len > buf.len() {
        return None;
    }
    Some(buf[LEN_PREFIX..LEN_PREFIX + len].to_vec())
}

/// Sliding-window anti-replay over a circuit's per-direction `seq` (Epic 482.7's
/// named requirement, §4.3). Accepts strictly-fresh seqs within a window of the
/// highest seen; rejects duplicates and too-old seqs. Relay-side state (wired in
/// b6); pure + testable here.
#[derive(Debug)]
pub struct ReplayWindow {
    /// Highest accepted seq so far (0 = nothing seen; seq numbering starts at 1).
    highest: u32,
    /// Bitmask of the `WINDOW` seqs at or below `highest` (bit 0 = `highest`).
    seen: u64,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// Window width in cells.
    pub const WINDOW: u32 = 64;

    pub fn new() -> Self {
        Self {
            highest: 0,
            seen: 0,
        }
    }

    /// Check + record `seq`. Returns `true` if fresh (accept), `false` if a
    /// duplicate or older than the window (reject). `seq` must be ≥ 1 (0 is
    /// reserved as "nothing seen").
    pub fn accept(&mut self, seq: u32) -> bool {
        if seq == 0 {
            return false;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            self.seen = if shift >= Self::WINDOW {
                0
            } else {
                self.seen << shift
            };
            self.seen |= 1;
            self.highest = seq;
            return true;
        }
        let behind = self.highest - seq;
        if behind >= Self::WINDOW {
            return false;
        }
        let bit = 1u64 << behind;
        if self.seen & bit != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(b: u8) -> [u8; CIRCUIT_KEY_LEN] {
        [b; CIRCUIT_KEY_LEN]
    }

    #[test]
    fn wrap_read_roundtrip_is_fixed_size() {
        let buf = wrap_payload(b"introduce-bytes").unwrap();
        assert_eq!(
            buf.len(),
            CIRCUIT_PAYLOAD_BYTES,
            "cell is always fixed-size"
        );
        assert_eq!(read_payload(&buf).unwrap(), b"introduce-bytes");
        // Empty payload still a full fixed cell.
        let e = wrap_payload(b"").unwrap();
        assert_eq!(e.len(), CIRCUIT_PAYLOAD_BYTES);
        assert!(read_payload(&e).unwrap().is_empty());
        // Oversize rejected.
        assert!(wrap_payload(&vec![0u8; MAX_CIRCUIT_INNER + 1]).is_err());
    }

    #[test]
    fn layer_is_self_inverse_and_size_preserving() {
        let key = k(0xA1);
        let mut buf = wrap_payload(b"hello").unwrap();
        let orig = buf.clone();
        apply_layer(&key, Direction::Return, 7, &mut buf);
        assert_eq!(buf.len(), orig.len(), "size preserved");
        assert_ne!(buf, orig, "layer changed the bytes");
        apply_layer(&key, Direction::Return, 7, &mut buf); // self-inverse
        assert_eq!(buf, orig);
    }

    #[test]
    fn return_path_three_hops_fixed_size() {
        // orig — h0 — h1 — h2(terminus). Keys orig assigned at build.
        let (k0, k1, k2) = (k(10), k(20), k(30));
        let seq = 99u32;
        // Terminus wraps + applies its layer; each hop toward orig applies its.
        let mut cell = wrap_payload(b"reply payload").unwrap();
        apply_layer(&k2, Direction::Return, seq, &mut cell);
        assert_eq!(cell.len(), CIRCUIT_PAYLOAD_BYTES);
        apply_layer(&k1, Direction::Return, seq, &mut cell);
        apply_layer(&k0, Direction::Return, seq, &mut cell);
        assert_eq!(cell.len(), CIRCUIT_PAYLOAD_BYTES, "same size at every hop");
        // Originator applies ALL keys → recovers the wrapped buffer.
        apply_layers(&[k0, k1, k2], Direction::Return, seq, &mut cell).unwrap();
        assert_eq!(read_payload(&cell).unwrap(), b"reply payload");
    }

    #[test]
    fn forward_and_return_are_independent() {
        let key = k(5);
        let mut a = wrap_payload(b"x").unwrap();
        let mut b = a.clone();
        apply_layer(&key, Direction::Forward, 1, &mut a);
        apply_layer(&key, Direction::Return, 1, &mut b);
        assert_ne!(a, b, "forward and return keystreams differ");
    }

    #[test]
    fn replay_window_basic_and_too_old() {
        let mut w = ReplayWindow::new();
        assert!(!w.accept(0));
        assert!(w.accept(1));
        assert!(!w.accept(1));
        assert!(w.accept(5));
        assert!(w.accept(3));
        assert!(!w.accept(3));
        let mut w2 = ReplayWindow::new();
        assert!(w2.accept(1000));
        assert!(!w2.accept(1000 - ReplayWindow::WINDOW));
        assert!(w2.accept(1000 - ReplayWindow::WINDOW + 1));
        assert!(!w2.accept(1));
    }
}
