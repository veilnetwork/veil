//! Stateful-circuit DATA plane — per-hop symmetric AEAD layers over an
//! established circuit (onion-registration epic b3; Epic 482.7 sub-problem B).
//! See `docs/internal/PLAN_ANON_SERVICE_ONION_REGISTRATION.md` §3.C +
//! `PLAN_STATEFUL_CIRCUITS_482_7.md` §4.
//!
//! Once b2 installs a per-hop `circuit_key`, data cells skip per-message ECDH:
//! each hop's layer is a ChaCha20-Poly1305 seal under that key. **Nonce safety:**
//! the circuit key is REUSED across cells, so — exactly as `onion.rs::derive_nonce`
//! warns for "a stateful circuit" — the nonce here mixes a per-cell **counter**
//! (the circuit sequence number) so `(key, nonce)` never repeats. Forward and
//! return directions derive SEPARATE sub-keys, so a forward cell and a return
//! cell with the same seq can never collide.
//!
//! Layering (3-hop circuit `orig — h0 — h1 — h2`):
//! * **Return** (`h2 → orig`): h2 seals once; h1 seals again; h0 seals again;
//!   `orig` opens all three in order `[k0, k1, k2]`. So R (the terminus) sends a
//!   single-sealed cell that accretes a layer at each hop back to the originator
//!   — R never learns who/where `orig` is.
//! * **Forward** (`orig → h2`): `orig` seals `[k2, k1, k0]` (k0 outermost); each
//!   hop opens one; h2 reads the plaintext.
//!
//! This module is the crypto primitive only — the relay re-tag/forward state
//! machine + cell framing is wired in b4/b6 using these calls. Replay is bounded
//! by [`ReplayWindow`] (per circuit + direction), enforced relay-side in b6.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::circuit::CircuitError;
use crate::circuit_setup::CIRCUIT_KEY_LEN;

/// AEAD tag length (ChaCha20-Poly1305).
pub const DATA_TAG_LEN: usize = 16;
/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;

/// Travel direction along a circuit. Mixed into BOTH the sub-key and the AAD so
/// the two directions are cryptographically independent.
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

/// Per-(direction) AEAD sub-key derived from the installed circuit key, so the
/// raw `circuit_key` is never used directly as an AEAD key and the two
/// directions are independent.
fn derive_data_key(circuit_key: &[u8; CIRCUIT_KEY_LEN], dir: Direction) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"veil.circuit.data.key.v1\0");
    h.update(&[dir.tag()]);
    h.update(circuit_key);
    *h.finalize().as_bytes()
}

/// Counter-based nonce: unique per `seq` within a (key, direction). The circuit
/// key is reused, so the seq counter is what keeps `(key, nonce)` unique — see
/// the module note + `onion.rs::derive_nonce`.
fn derive_data_nonce(dir: Direction, seq: u32) -> [u8; NONCE_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(b"veil.circuit.data.nonce.v1\0");
    h.update(&[dir.tag()]);
    h.update(&seq.to_be_bytes());
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&h.finalize().as_bytes()[..NONCE_LEN]);
    n
}

fn aad(dir: Direction, seq: u32) -> [u8; 5] {
    let s = seq.to_be_bytes();
    [dir.tag(), s[0], s[1], s[2], s[3]]
}

/// Seal one circuit-data layer under `circuit_key` for `(dir, seq)`. Output is
/// `plaintext.len() + DATA_TAG_LEN` bytes.
pub fn seal_layer(
    circuit_key: &[u8; CIRCUIT_KEY_LEN],
    dir: Direction,
    seq: u32,
    plaintext: &[u8],
) -> Vec<u8> {
    let key = derive_data_key(circuit_key, dir);
    let nonce = derive_data_nonce(dir, seq);
    let aad = aad(dir, seq);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("chacha20poly1305 encrypt must not fail on valid inputs")
}

/// Open one circuit-data layer. Fails with [`CircuitError::Onion`]-style AEAD
/// rejection on a wrong key / tampered ciphertext / wrong (dir, seq).
pub fn open_layer(
    circuit_key: &[u8; CIRCUIT_KEY_LEN],
    dir: Direction,
    seq: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CircuitError> {
    let key = derive_data_key(circuit_key, dir);
    let nonce = derive_data_nonce(dir, seq);
    let aad = aad(dir, seq);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CircuitError::Malformed("circuit data AEAD verify failed".into()))
}

/// Originator-side: open ALL layers of a cell in `keys` order. For a return
/// cell, pass the circuit keys first-hop → terminus (`[k0, k1, …, k_term]`); the
/// outermost layer (first hop) is removed first.
pub fn open_layers(
    keys: &[[u8; CIRCUIT_KEY_LEN]],
    dir: Direction,
    seq: u32,
    cell: &[u8],
) -> Result<Vec<u8>, CircuitError> {
    if keys.is_empty() {
        return Err(CircuitError::NoHops);
    }
    let mut buf = cell.to_vec();
    for k in keys {
        buf = open_layer(k, dir, seq, &buf)?;
    }
    Ok(buf)
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
            // Advance the window; shift the seen-mask by the gap.
            let shift = seq - self.highest;
            self.seen = if shift >= Self::WINDOW {
                0
            } else {
                self.seen << shift
            };
            self.seen |= 1; // mark the new highest
            self.highest = seq;
            return true;
        }
        let behind = self.highest - seq;
        if behind >= Self::WINDOW {
            return false; // too old
        }
        let bit = 1u64 << behind;
        if self.seen & bit != 0 {
            return false; // duplicate
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
    fn layer_roundtrip() {
        let key = k(0xA1);
        let ct = seal_layer(&key, Direction::Return, 7, b"hello circuit");
        assert_eq!(ct.len(), b"hello circuit".len() + DATA_TAG_LEN);
        assert_eq!(
            open_layer(&key, Direction::Return, 7, &ct).unwrap(),
            b"hello circuit"
        );
    }

    #[test]
    fn wrong_key_or_seq_or_dir_fails() {
        let key = k(1);
        let ct = seal_layer(&key, Direction::Return, 5, b"x");
        assert!(open_layer(&k(2), Direction::Return, 5, &ct).is_err()); // wrong key
        assert!(open_layer(&key, Direction::Return, 6, &ct).is_err()); // wrong seq
        assert!(open_layer(&key, Direction::Forward, 5, &ct).is_err()); // wrong dir
    }

    #[test]
    fn return_path_three_hops() {
        // orig — h0 — h1 — h2(terminus). Keys orig assigned at build (b2).
        let (k0, k1, k2) = (k(10), k(20), k(30));
        let seq = 99u32;
        // Terminus seals, then each hop toward orig adds a layer.
        let c2 = seal_layer(&k2, Direction::Return, seq, b"reply payload");
        let c1 = seal_layer(&k1, Direction::Return, seq, &c2);
        let c0 = seal_layer(&k0, Direction::Return, seq, &c1);
        // Originator opens all three in first-hop→terminus order.
        let pt = open_layers(&[k0, k1, k2], Direction::Return, seq, &c0).unwrap();
        assert_eq!(&pt, b"reply payload");
    }

    #[test]
    fn forward_path_three_hops() {
        let (k0, k1, k2) = (k(10), k(20), k(30));
        let seq = 1u32;
        // orig seals innermost=terminus first, outermost=first hop last.
        let c2 = seal_layer(&k2, Direction::Forward, seq, b"to terminus");
        let c1 = seal_layer(&k1, Direction::Forward, seq, &c2);
        let c0 = seal_layer(&k0, Direction::Forward, seq, &c1);
        // h0 opens, h1 opens, h2 reads.
        let i1 = open_layer(&k0, Direction::Forward, seq, &c0).unwrap();
        let i2 = open_layer(&k1, Direction::Forward, seq, &i1).unwrap();
        let pt = open_layer(&k2, Direction::Forward, seq, &i2).unwrap();
        assert_eq!(&pt, b"to terminus");
    }

    #[test]
    fn replay_window_basic() {
        let mut w = ReplayWindow::new();
        assert!(!w.accept(0)); // 0 reserved
        assert!(w.accept(1));
        assert!(!w.accept(1)); // duplicate
        assert!(w.accept(2));
        assert!(w.accept(5)); // gap ok
        assert!(w.accept(3)); // in-window late arrival
        assert!(!w.accept(3)); // duplicate
        assert!(w.accept(4));
    }

    #[test]
    fn replay_window_rejects_too_old() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(1000));
        // 1000 - WINDOW = 936 is the oldest acceptable boundary.
        assert!(!w.accept(1000 - ReplayWindow::WINDOW)); // exactly window-edge → too old
        assert!(w.accept(1000 - ReplayWindow::WINDOW + 1)); // just inside
        assert!(!w.accept(1)); // far older than the window → rejected
    }
}
