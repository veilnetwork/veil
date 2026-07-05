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
/// EVERY cell so size never reveals hop position (still holds: every cell is
/// the same, larger, quantum). Must comfortably hold the largest sealed
/// introduce (`MAX_INTRODUCE_CIPHERTEXT` = 320) + the length prefix.
///
/// 2026-07-02 flag-day bump 384 -> 4096: the reliable onion stream's live
/// ceiling was per-CELL processing cost on phones (syscalls/wakes/locks per
/// 318-byte MSS), not bandwidth. A ~10.7x larger cell cuts the per-byte
/// overhead by the same factor. BREAKING: every relay and client on a network
/// must agree on this constant (each hop validates the fixed size).
///
/// 2026-07-02 second bump 4096 -> 16384: the next ceiling was still per-cell
/// work, now on the RELAY (~90% of one vCPU at ~12 MB/s splice = ~3k cells/s
/// each way) and in the local stack benchmark (19.3 MiB/s loopback). 4x fewer
/// cells per byte cuts both. Cost: small control/chat sends still pad to one
/// uniform cell, now 16 KiB on the wire — accepted for the same uniformity
/// reason as the first bump.
pub const CIRCUIT_PAYLOAD_BYTES: usize = 16384;
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

/// The per-(direction, seq) ChaCha20 nonce for this circuit layer.
///
/// Layout (12 B, the IETF ChaCha20 nonce width): `[dir_tag(1)][seq BE(4)][0;7]`.
/// Uniqueness under the fixed `circuit_key`: `seq` is strictly monotonic per
/// circuit direction (`alloc_seq`/`alloc_return_seq` never wrap — see
/// `CircuitState`), and `dir_tag` splits the Forward and Return streams, so no
/// (dir, seq) pair — hence no nonce — ever repeats under one key. That is the
/// one safety obligation of a stream cipher used as a keystream. The 32-bit
/// ChaCha20 block counter covers 256 GiB per nonce, far beyond one cell.
#[inline]
fn layer_nonce(dir: Direction, seq: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = dir.tag();
    nonce[1..5].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// XOR one circuit layer in place under `circuit_key` for `(dir, seq)`.
/// Length-preserving and self-inverse — sealing and peeling are the same call.
///
/// The keystream is ChaCha20 (2026-07-02, replacing a BLAKE3-XOF keystream):
/// on the relay — the network's CPU ceiling — ChaCha20's AVX2 backend runs the
/// circuit XOR ~2.3x cheaper than BLAKE3-XOF, whose single-stream `compress_xof`
/// has no AVX2 path and fell back to SSE4.1 on the AVX2-without-AVX512 seed CPUs
/// (measured 0.94 vs 2.17 cyc/byte). ChaCha20 is constant-time on every target
/// (no data-dependent branches/tables), so the win carries no timing-side-channel
/// cost. BREAKING: the keystream is not blake3-compatible — every relay and
/// client on a network must run this build (flag-day, like the cell-size bumps).
pub fn apply_layer(circuit_key: &[u8; CIRCUIT_KEY_LEN], dir: Direction, seq: u32, buf: &mut [u8]) {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    let nonce = layer_nonce(dir, seq);
    // XOR the keystream straight into `buf` — no scratch allocation (the old
    // BLAKE3 path allocated a full cell-sized keystream buffer per cell).
    chacha20::ChaCha20::new(circuit_key.into(), (&nonce).into()).apply_keystream(buf);
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

/// Payload of a FORWARD keepalive "heartbeat" cell. The receiver periodically
/// sends this UP its own inbound rendezvous circuit so the first-hop TCP
/// session — and every hop's socket along the path — stays warm. An idle
/// receiver's socket otherwise dies (mobile power-save / NAT rebind / VPN) and
/// the rendezvous relay's downstream introduce pushes queue behind a dead TCP
/// until the receiver next transmits, which on-device turned prompt delivery
/// into 10–60 s stalls that flushed in a batch on the next outbound cell.
///
/// The terminus recognises this exact payload and silently drops it (it carries
/// no data). Deliberately shorter than [`crate::circuit_register::COOKIE_LEN`]
/// (16) so it can never be mistaken for a stream-splice cookie prefix.
pub const CIRCUIT_HEARTBEAT_MAGIC: &[u8] = b"veil/hb1";

/// True if a peeled forward-terminus payload is a keepalive heartbeat (see
/// [`CIRCUIT_HEARTBEAT_MAGIC`]).
pub fn is_heartbeat(payload: &[u8]) -> bool {
    payload == CIRCUIT_HEARTBEAT_MAGIC
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
    fn distinct_seq_gives_distinct_keystream() {
        // Nonce uniqueness in action: consecutive seqs must never reuse the
        // keystream (a reuse would XOR two payloads under one pad — catastrophic
        // for a stream cipher). Applied to a zeroed buffer, the output IS the
        // keystream.
        let key = k(0x33);
        let mut s1 = vec![0u8; 64];
        let mut s2 = vec![0u8; 64];
        apply_layer(&key, Direction::Forward, 1, &mut s1);
        apply_layer(&key, Direction::Forward, 2, &mut s2);
        assert_ne!(s1, s2, "seq 1 and 2 must produce different keystreams");
    }

    #[test]
    fn chacha20_keystream_known_answer_vector() {
        // Pins the ON-THE-WIRE circuit keystream (primitive + nonce layout) for
        // a fixed (key, dir, seq). A future change to the cipher or nonce scheme
        // — which would silently make every relay/client on the network mutually
        // unintelligible — fails loudly here instead. Changing it is a
        // deliberate, coordinated flag-day (as ChaCha20 replacing BLAKE3-XOF was).
        // Output = keystream (apply_layer over a zeroed buffer).
        let key = k(0x42);
        let mut ks = vec![0u8; 32];
        apply_layer(&key, Direction::Forward, 1, &mut ks);
        let hex: String = ks.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "342756a953c82f875ae70511ffbed52bf60cc4f99a892cac1a458aebc98d4e11",
            "circuit keystream changed — coordinated flag-day only"
        );
    }

    #[test]
    fn heartbeat_forward_roundtrip_and_recognition() {
        // A heartbeat travels FORWARD: the originator applies every hop's layer,
        // each relay peels one, the terminus reads the plaintext back out and
        // recognises the magic. Mirrors `return_path_three_hops_fixed_size` but
        // in the forward direction (the keepalive path added for dead-idle-TCP).
        let (k0, k1, k2) = (k(10), k(20), k(30));
        let seq = 42u32;
        let mut cell = wrap_payload(CIRCUIT_HEARTBEAT_MAGIC).unwrap();
        apply_layers(&[k0, k1, k2], Direction::Forward, seq, &mut cell).unwrap();
        assert_eq!(cell.len(), CIRCUIT_PAYLOAD_BYTES, "fixed size on the wire");
        // Each hop peels its own layer; the terminus peels the last and reads it.
        apply_layer(&k0, Direction::Forward, seq, &mut cell);
        apply_layer(&k1, Direction::Forward, seq, &mut cell);
        apply_layer(&k2, Direction::Forward, seq, &mut cell);
        let payload = read_payload(&cell).unwrap();
        assert!(is_heartbeat(&payload), "terminus recognises the heartbeat");
        // Ordinary payloads are not heartbeats.
        assert!(!is_heartbeat(b"introduce-bytes"));
        assert!(!is_heartbeat(b""));
    }

    #[test]
    fn heartbeat_magic_cannot_be_a_splice_cookie() {
        // The terminus only attempts a stream splice when the payload is at
        // least COOKIE_LEN (16) bytes; keeping the heartbeat shorter guarantees
        // it can never be mistaken for a cookie prefix even before the explicit
        // is_heartbeat() check.
        use crate::circuit_register::COOKIE_LEN;
        assert!(CIRCUIT_HEARTBEAT_MAGIC.len() < COOKIE_LEN);
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
