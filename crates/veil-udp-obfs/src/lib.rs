//! Stateless AEAD-per-datagram obfuscation for UDP plaintext transports.
//!
//! Phase 1a of [`docs/internal/PLAN_TRANSPORT_OBFUSCATION.md`](../../docs/internal/PLAN_TRANSPORT_OBFUSCATION.md).
//!
//! # What this crate does
//!
//! Wraps each outbound UDP datagram in an AEAD envelope so that the wire
//! bytes are statistically indistinguishable from random.  Passive DPI
//! that looks for the OVL1 magic (`4f 56 4c 31`) sees only ciphertext.
//!
//! ## Design
//!
//! No handshake.  No per-session state.  No setup latency.  Each
//! datagram is self-contained:
//!
//! ```text
//! [ 16 byte random nonce-prefix (plaintext)         ]
//! [ 8 byte counter u64 BE       (plaintext)         ]
//! [ ChaCha20-Poly1305(payload || padding, key, nonce) ]
//! [ 16 byte AEAD tag                                ]
//! ```
//!
//! Total overhead per datagram: **40 bytes**.
//!
//! - **Key** = `HKDF-SHA256(PSK, "veil-udp-obfs:v1:" || peer_node_id, 32)`.
//! - **AEAD nonce** = first 12 bytes of `nonce-prefix || counter` (24 bytes
//!   total; the AEAD primitive consumes 12).  Random prefix gives 2^96
//!   nonce-uniqueness even if counter is reused across distinct senders.
//! - **Replay window** (opt-in) = sliding bitmap by counter, default 1024
//!   slots (= 128 bytes of state per peer). Applied ONLY by the *stateful*
//!   [`ReceiverState::open_and_check`] (after AEAD verify); the stateless
//!   [`open_datagram`] helper does NOT consult it — see Threat model below.
//!
//! ## Properties
//!
//! - **Wire entropy:** uniformly random for an observer without the key.
//!   Counter in plaintext but cannot be advanced or replayed without the key.
//! - **Loss-tolerant:** datagram drop doesn't break anything; next
//!   datagram decrypts independently.
//! - **Reorder-tolerant:** sliding replay window accepts out-of-order
//!   counter values up to window-width back from the highest-seen counter.
//! - **Duplicate-resistant:** replay window's bitmap reject already-seen
//!   counters.
//!
//! ## Threat model
//!
//! In-scope (always — stateless `seal_datagram` / `open_datagram`):
//! - Passive DPI looking for plaintext OVL1 magic.
//! - Statistical fingerprinting of packet bodies (header bytes leak protocol).
//!
//! In-scope ONLY via the *stateful* [`ReceiverState`] / [`SenderState`] API:
//! - Replay attacks (capture + retransmit). Replay rejection needs per-peer
//!   [`ReplayWindow`] state, so it is NOT provided by the stateless helpers.
//!   The realm-wide mesh receive path (`veil-mesh`'s `UdpRealm::recv_frame`)
//!   shares one realm key across every sender — it cannot demux per-sender
//!   counters and so does not replay-check at this layer; it instead relies on
//!   the dispatcher's frame dedup (`ForwardSeenSet` / `RouteSeenSet`) to drop
//!   replayed DATA frames. Point-to-point callers that hold per-peer state
//!   should use [`ReceiverState::open_and_check`] to get replay rejection.
//!
//! Out-of-scope:
//! - Active probers que know the PSK (== anyone in the bootstrap pool).
//! - Traffic analysis (packet timing, size patterns).
//! - PSK leakage: compromise of PSK reveals all past and future traffic
//!   encrypted under it.  This is the central trade-off vs handshake-
//!   based (WireGuard-style) UDP obfuscation — accepted because UDP
//!   in veil carries discovery / NAT-probe / diagnostic traffic
//!   a not long-lived data streams.
//!
//! See plan doc for re-open triggers.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Constants ────────────────────────────────────────────────────────────────

/// Length of the random nonce-prefix that prefixes every datagram.
pub const NONCE_PREFIX_LEN: usize = 16;

/// Length of the in-wire counter field.
pub const COUNTER_LEN: usize = 8;

/// ChaCha20-Poly1305 AEAD tag length.
pub const AEAD_TAG_LEN: usize = 16;

/// Total wire overhead added to every payload.
pub const WIRE_OVERHEAD: usize = NONCE_PREFIX_LEN + COUNTER_LEN + AEAD_TAG_LEN;

/// Default sliding-replay-window width (bits) per peer.  1024 = 128 bytes
/// of state per peer; accepts out-of-order datagrams up to 1024
/// positions behind the highest-seen counter.
pub const DEFAULT_REPLAY_WINDOW_BITS: u64 = 1024;

/// Maximum padding bytes appended to payload before AEAD encrypt.  Random
/// padding length defeats fixed-size fingerprinting where DPI matches
/// distinctive payload-size buckets.
pub const MAX_PADDING_BYTES: usize = 256;

/// HKDF context label.  Domain-separated so the same PSK reused for another
/// purpose doesn't produce key collisions.
pub const HKDF_INFO_PREFIX: &[u8] = b"veil-udp-obfs:v1:";

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ObfsError {
    #[error("datagram too short: need ≥{WIRE_OVERHEAD} bytes, got {0}")]
    TooShort(usize),

    #[error("AEAD verification failed (wrong key or tampered datagram)")]
    AeadFailure,

    #[error("counter {0} rejected by replay window (already seen or too old)")]
    ReplayRejected(u64),

    #[error("padding length byte {0} exceeds remaining payload {1}")]
    BadPadding(usize, usize),

    #[error("sender counter overflowed u64 — the key must be rotated before reuse")]
    CounterOverflow,
}

// ── Key derivation ───────────────────────────────────────────────────────────

/// Per-peer obfuscation key.  Derived once at construction; stored as
/// raw 32 bytes wrapped in `ChaCha20Poly1305` cipher for reuse across
/// many datagrams without re-running HKDF.
///
/// `ZeroizeOnDrop` clears the key material at drop.  `Zeroize` skip on
/// the cipher field is necessary because upstream's `ChaCha20Poly1305`
/// does NOT implement `Zeroize` — same workaround pattern as
/// [`veil_crypto::session_cipher`].
#[derive(ZeroizeOnDrop)]
pub struct ObfsKey {
    #[zeroize(skip)]
    cipher: ChaCha20Poly1305,
}

impl ObfsKey {
    /// Derive an obfuscation key for traffic to/from `peer_node_id` from
    /// the deployment's pre-shared key `psk`.  Both sides must derive
    /// the SAME key for a given (psk, peer_node_id) pair.
    ///
    /// HKDF context: `"veil-udp-obfs:v1:" || peer_node_id` (32 bytes).
    pub fn derive(psk: &[u8], peer_node_id: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, psk);
        let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + peer_node_id.len());
        info.extend_from_slice(HKDF_INFO_PREFIX);
        info.extend_from_slice(peer_node_id);

        let mut key_bytes = [0u8; 32];
        hk.expand(&info, &mut key_bytes)
            .expect("HKDF-SHA256 32-byte expand cannot fail (length < 8160)");
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        key_bytes.zeroize();
        Self { cipher }
    }
}

// ── Wire format helpers ──────────────────────────────────────────────────────

/// Build the 12-byte AEAD nonce from prefix + counter.  ChaCha20-Poly1305
/// consumes 12 bytes; we have 16 + 8 = 24 bytes of nonce material
/// available, fold them deterministically:
///
/// `nonce = prefix[0..4] XOR counter_bytes[0..4] || prefix[4..12]`.
///
/// This gives uniform distribution on the nonce space even when senders
/// happen to pick the same random prefix; counter ensures uniqueness
/// per-sender, prefix ensures cross-sender separation.
fn build_nonce(prefix: &[u8; NONCE_PREFIX_LEN], counter: u64) -> [u8; 12] {
    let counter_bytes = counter.to_be_bytes();
    let mut nonce = [0u8; 12];
    // Bytes 0..4: XOR of prefix[0..4] and high half of counter.
    nonce[0] = prefix[0] ^ counter_bytes[0];
    nonce[1] = prefix[1] ^ counter_bytes[1];
    nonce[2] = prefix[2] ^ counter_bytes[2];
    nonce[3] = prefix[3] ^ counter_bytes[3];
    // Bytes 4..12: prefix[4..12] verbatim.
    nonce[4..12].copy_from_slice(&prefix[4..12]);
    // Mix low half of counter into bytes 8..12 for full per-counter
    // uniqueness when prefix is reused across many datagrams from
    // one sender (unlikely with 16-byte random but belt-and-braces).
    nonce[8] ^= counter_bytes[4];
    nonce[9] ^= counter_bytes[5];
    nonce[10] ^= counter_bytes[6];
    nonce[11] ^= counter_bytes[7];
    nonce
}

/// Generate a fresh 16-byte random nonce-prefix.
fn fresh_prefix() -> [u8; NONCE_PREFIX_LEN] {
    let mut buf = [0u8; NONCE_PREFIX_LEN];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// Generate a random padding length in `0..=255` bytes.
fn fresh_padding_len() -> u8 {
    let mut b = [0u8; 1];
    rand::rng().fill_bytes(&mut b);
    // `b[0]` is already 0..=255, so `% (MAX_PADDING_BYTES + 1)` (= % 257) is a
    // no-op on a single byte: this draws uniformly from 0..=255 with NO modulo
    // bias. The top value 256 is intentionally unreachable — the pad length is
    // transmitted in a single `u8` length byte, which caps at 255.
    (b[0] as usize % (MAX_PADDING_BYTES + 1)) as u8
}

// ── Encrypt / decrypt ────────────────────────────────────────────────────────

/// Encrypt a datagram with the given counter.  Caller picks the counter
/// (typically a monotonically-increasing per-peer u64); each (key
/// counter) pair must be unique by AEAD security.
///
/// Returns the wire-bytes ready to hand to `UdpSocket::send_to`.
pub fn seal_datagram(key: &ObfsKey, counter: u64, payload: &[u8]) -> Result<Vec<u8>, ObfsError> {
    let prefix = fresh_prefix();
    let nonce_bytes = build_nonce(&prefix, counter);
    let pad_len = fresh_padding_len();

    // Prefix body with 1-byte pad-length, then payload, then random padding.
    let mut body = Vec::with_capacity(1 + payload.len() + pad_len as usize);
    body.push(pad_len);
    body.extend_from_slice(payload);
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len as usize];
        rand::rng().fill_bytes(&mut pad);
        body.extend_from_slice(&pad);
    }

    let ciphertext = key
        .cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &body,
                aad: &[],
            },
        )
        .map_err(|_| ObfsError::AeadFailure)?;

    let mut out = Vec::with_capacity(WIRE_OVERHEAD + ciphertext.len());
    out.extend_from_slice(&prefix);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a datagram, returning the original payload (with padding stripped).
///
/// Performs:
/// 1. Length check (≥ `WIRE_OVERHEAD`).
/// 2. Counter extraction (plaintext from wire).
/// 3. AEAD verify + decrypt with the derived nonce.
/// 4. Pad-length validation and trimming.
///
/// Does NOT consult a replay window — callers that need replay protection
/// must invoke [`ReplayWindow::check_and_record`] separately.  Splitting
/// the AEAD-verify step from replay-check lets callers that don't care
/// about replay (e.g., one-shot probes) opt out cheaply.
pub fn open_datagram(key: &ObfsKey, wire: &[u8]) -> Result<(u64, Vec<u8>), ObfsError> {
    if wire.len() < WIRE_OVERHEAD {
        return Err(ObfsError::TooShort(wire.len()));
    }
    let mut prefix = [0u8; NONCE_PREFIX_LEN];
    prefix.copy_from_slice(&wire[..NONCE_PREFIX_LEN]);
    let counter = u64::from_be_bytes(
        wire[NONCE_PREFIX_LEN..NONCE_PREFIX_LEN + COUNTER_LEN]
            .try_into()
            .expect("checked length above"),
    );
    let nonce_bytes = build_nonce(&prefix, counter);
    let ciphertext = &wire[NONCE_PREFIX_LEN + COUNTER_LEN..];

    let body = key
        .cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|_| ObfsError::AeadFailure)?;

    if body.is_empty() {
        return Err(ObfsError::BadPadding(0, 0));
    }
    let pad_len = body[0] as usize;
    if 1 + pad_len > body.len() {
        return Err(ObfsError::BadPadding(pad_len, body.len() - 1));
    }
    let payload = body[1..body.len() - pad_len].to_vec();
    Ok((counter, payload))
}

// ── Replay window ────────────────────────────────────────────────────────────

/// Sliding-bitmap replay window.
///
/// Tracks the highest counter seen so far and a bitmap of recent counters.
/// Counters more than `bits` behind the highest are rejected as "too old."
/// Counters within the window are checked against the bitmap; already-seen
/// → reject; not-seen → record + accept.  Counters AHEAD of `highest` slide
/// the window forward.
///
/// Memory: `bits / 8` bytes (default 1024 bits = 128 bytes) per peer.
pub struct ReplayWindow {
    /// Highest counter accepted so far.
    highest: u64,
    /// Bitmap of last `bits` counter slots, bit-0 = highest, bit-1 =
    /// highest-1, ... .  Stored as `Vec<u64>` for cheap word-shift slide.
    bitmap: Vec<u64>,
    /// Total bits in the window.
    bits: u64,
}

impl ReplayWindow {
    pub fn new(bits: u64) -> Self {
        let words = bits.div_ceil(64) as usize;
        Self {
            highest: 0,
            bitmap: vec![0u64; words],
            bits,
        }
    }

    /// Check whether `counter` is acceptable and, if so, record it.
    /// Returns `Ok(())` on accept, `Err(ReplayRejected)` if already seen
    /// or too old.
    ///
    /// Side-effects: on accept, advances `highest` and/or sets the
    /// corresponding bit in the bitmap.
    pub fn check_and_record(&mut self, counter: u64) -> Result<(), ObfsError> {
        if counter > self.highest {
            // Slide window forward by (counter - highest) bits.
            let shift = counter - self.highest;
            self.slide(shift);
            self.highest = counter;
            self.set_bit(0);
            Ok(())
        } else {
            let behind = self.highest - counter;
            if behind >= self.bits {
                return Err(ObfsError::ReplayRejected(counter));
            }
            if self.get_bit(behind) {
                return Err(ObfsError::ReplayRejected(counter));
            }
            self.set_bit(behind);
            Ok(())
        }
    }

    fn slide(&mut self, shift: u64) {
        if shift >= self.bits {
            // Window fully cleared.
            for w in &mut self.bitmap {
                *w = 0;
            }
            return;
        }
        // Word-by-word shift right (bit-0 is highest, so newer counters
        // push older bits "down" in word indices).
        let word_shift = (shift / 64) as usize;
        let bit_shift = (shift % 64) as u32;
        let words = self.bitmap.len();
        if word_shift > 0 {
            // Move bitmap[i] → bitmap[i + word_shift], clear new low.
            for i in (word_shift..words).rev() {
                self.bitmap[i] = self.bitmap[i - word_shift];
            }
            for w in &mut self.bitmap[..word_shift] {
                *w = 0;
            }
        }
        if bit_shift > 0 {
            // Shift each word left by bit_shift, carrying in bits from
            // the previous word.
            let mut carry: u64 = 0;
            for w in &mut self.bitmap {
                let new_carry = *w >> (64 - bit_shift);
                *w = (*w << bit_shift) | carry;
                carry = new_carry;
            }
        }
    }

    fn set_bit(&mut self, pos: u64) {
        let word = (pos / 64) as usize;
        let bit = pos % 64;
        if word < self.bitmap.len() {
            self.bitmap[word] |= 1u64 << bit;
        }
    }

    fn get_bit(&self, pos: u64) -> bool {
        let word = (pos / 64) as usize;
        let bit = pos % 64;
        if word < self.bitmap.len() {
            self.bitmap[word] & (1u64 << bit) != 0
        } else {
            false
        }
    }

    /// Test/diag: current highest accepted counter.
    pub fn highest(&self) -> u64 {
        self.highest
    }
}

// ── Per-peer state (key + counter + replay window) ───────────────────────────

/// Sender-side per-peer state: tracks the outbound counter that monotonically
/// increases across each `seal_next` call.  Holds the derived [`ObfsKey`].
pub struct SenderState {
    key: ObfsKey,
    counter: u64,
}

impl SenderState {
    pub fn new(key: ObfsKey) -> Self {
        Self { key, counter: 0 }
    }

    /// Seal a datagram, advancing the counter.  Returns wire-bytes.
    ///
    /// Uses `checked_add` (matching `OutboundStream::wrap_next` /
    /// `session_cipher`): on the astronomically-unreachable 2^64th datagram the
    /// counter would wrap to a value already used with this key, reusing an AEAD
    /// (key, nonce) pair. Erroring forces a rekey instead of silently breaking
    /// confidentiality.
    pub fn seal_next(&mut self, payload: &[u8]) -> Result<Vec<u8>, ObfsError> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(ObfsError::CounterOverflow)?;
        seal_datagram(&self.key, self.counter, payload)
    }
}

/// Receiver-side per-peer state: [`ObfsKey`] + [`ReplayWindow`].
pub struct ReceiverState {
    key: ObfsKey,
    replay: ReplayWindow,
}

impl ReceiverState {
    pub fn new(key: ObfsKey) -> Self {
        Self {
            key,
            replay: ReplayWindow::new(DEFAULT_REPLAY_WINDOW_BITS),
        }
    }

    pub fn with_window(key: ObfsKey, window_bits: u64) -> Self {
        Self {
            key,
            replay: ReplayWindow::new(window_bits),
        }
    }

    /// Open and replay-check a datagram.  AEAD-verify runs BEFORE the
    /// replay check (cheaper to reject malformed traffic from random
    /// noise that happens to hit a stale counter slot).
    pub fn open_and_check(&mut self, wire: &[u8]) -> Result<Vec<u8>, ObfsError> {
        let (counter, payload) = open_datagram(&self.key, wire)?;
        self.replay.check_and_record(counter)?;
        Ok(payload)
    }
}

// ── Multi-peer state map ─────────────────────────────────────────────────────

/// Convenience wrapper holding per-peer [`SenderState`] + [`ReceiverState`].
/// Use when a single transport handles datagrams to/from many peers.
///
/// Memory: ~200 bytes per peer (key + counter + replay bitmap).  No
/// LRU eviction — caller is responsible for removing entries on peer
/// teardown.
#[derive(Default)]
pub struct PeerStateMap {
    senders: HashMap<[u8; 32], SenderState>,
    receivers: HashMap<[u8; 32], ReceiverState>,
}

impl PeerStateMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sender_mut(&mut self, peer_node_id: &[u8; 32], psk: &[u8]) -> &mut SenderState {
        self.senders
            .entry(*peer_node_id)
            .or_insert_with(|| SenderState::new(ObfsKey::derive(psk, peer_node_id)))
    }

    pub fn receiver_mut(&mut self, peer_node_id: &[u8; 32], psk: &[u8]) -> &mut ReceiverState {
        self.receivers
            .entry(*peer_node_id)
            .or_insert_with(|| ReceiverState::new(ObfsKey::derive(psk, peer_node_id)))
    }

    pub fn forget(&mut self, peer_node_id: &[u8; 32]) {
        self.senders.remove(peer_node_id);
        self.receivers.remove(peer_node_id);
    }

    pub fn peer_count(&self) -> usize {
        self.senders.len().max(self.receivers.len())
    }
}

// ── Constant-time tag-equality helper (for future use in TCP framing) ──────

/// Constant-time equality for two byte slices.  Re-export of [`subtle`]
/// for convenience.  AEAD primitives already use constant-time compare
/// internally; this is exposed for downstream callers that need it directly.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PSK: &[u8] = b"test-psk-do-not-use-in-production";

    fn peer_a() -> [u8; 32] {
        [0xAA; 32]
    }

    fn peer_b() -> [u8; 32] {
        [0xBB; 32]
    }

    #[test]
    fn seal_open_round_trip() {
        let key = ObfsKey::derive(TEST_PSK, &peer_a());
        let payload = b"hello veil";
        let wire = seal_datagram(&key, 1, payload).unwrap();
        let (counter, opened) = open_datagram(&key, &wire).unwrap();
        assert_eq!(counter, 1);
        assert_eq!(opened, payload);
    }

    #[test]
    fn wire_overhead_constant() {
        let key = ObfsKey::derive(TEST_PSK, &peer_a());
        let payload = b"";
        let wire = seal_datagram(&key, 1, payload).unwrap();
        // Wire length = WIRE_OVERHEAD + 1-byte pad-length-header + random padding.
        // Minimum case: WIRE_OVERHEAD + 1 (pad-len byte) + 0 (zero padding).
        assert!(wire.len() > WIRE_OVERHEAD);
        // Maximum case: WIRE_OVERHEAD + 1 + MAX_PADDING_BYTES.
        assert!(wire.len() <= WIRE_OVERHEAD + 1 + MAX_PADDING_BYTES);
    }

    #[test]
    fn different_peer_id_derives_different_key() {
        let key_a = ObfsKey::derive(TEST_PSK, &peer_a());
        let key_b = ObfsKey::derive(TEST_PSK, &peer_b());
        let payload = b"secret";
        let wire = seal_datagram(&key_a, 1, payload).unwrap();
        // Wrong peer key must fail to decrypt.
        assert_eq!(
            open_datagram(&key_b, &wire).unwrap_err(),
            ObfsError::AeadFailure
        );
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = ObfsKey::derive(TEST_PSK, &peer_a());
        let mut wire = seal_datagram(&key, 1, b"hello").unwrap();
        // Flip a byte in the ciphertext region (past prefix + counter).
        let flip_at = NONCE_PREFIX_LEN + COUNTER_LEN + 1;
        wire[flip_at] ^= 0x01;
        assert_eq!(
            open_datagram(&key, &wire).unwrap_err(),
            ObfsError::AeadFailure
        );
    }

    #[test]
    fn tampered_nonce_prefix_rejected() {
        let key = ObfsKey::derive(TEST_PSK, &peer_a());
        let mut wire = seal_datagram(&key, 1, b"hello").unwrap();
        wire[0] ^= 0x01;
        assert_eq!(
            open_datagram(&key, &wire).unwrap_err(),
            ObfsError::AeadFailure
        );
    }

    #[test]
    fn tampered_counter_rejected() {
        let key = ObfsKey::derive(TEST_PSK, &peer_a());
        let mut wire = seal_datagram(&key, 1, b"hello").unwrap();
        wire[NONCE_PREFIX_LEN] ^= 0x80;
        assert_eq!(
            open_datagram(&key, &wire).unwrap_err(),
            ObfsError::AeadFailure
        );
    }

    #[test]
    fn too_short_rejected() {
        let key = ObfsKey::derive(TEST_PSK, &peer_a());
        let short = vec![0u8; WIRE_OVERHEAD - 1];
        match open_datagram(&key, &short).unwrap_err() {
            ObfsError::TooShort(_) => {}
            e => panic!("expected TooShort, got {e:?}"),
        }
    }

    #[test]
    fn empty_payload_roundtrips() {
        let key = ObfsKey::derive(TEST_PSK, &peer_a());
        let wire = seal_datagram(&key, 42, b"").unwrap();
        let (counter, opened) = open_datagram(&key, &wire).unwrap();
        assert_eq!(counter, 42);
        assert!(opened.is_empty());
    }

    #[test]
    fn multiple_counters_all_decrypt() {
        let key = ObfsKey::derive(TEST_PSK, &peer_a());
        for c in 1..=100u64 {
            let payload = format!("msg-{c}");
            let wire = seal_datagram(&key, c, payload.as_bytes()).unwrap();
            let (got_c, got) = open_datagram(&key, &wire).unwrap();
            assert_eq!(got_c, c);
            assert_eq!(got, payload.as_bytes());
        }
    }

    // ── Replay window ────────────────────────────────────────────────────

    #[test]
    fn replay_window_accepts_in_order() {
        let mut w = ReplayWindow::new(1024);
        for c in 1..=100u64 {
            w.check_and_record(c).unwrap();
        }
        assert_eq!(w.highest(), 100);
    }

    #[test]
    fn replay_window_rejects_duplicate() {
        let mut w = ReplayWindow::new(1024);
        w.check_and_record(5).unwrap();
        assert_eq!(
            w.check_and_record(5).unwrap_err(),
            ObfsError::ReplayRejected(5)
        );
    }

    #[test]
    fn replay_window_accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::new(1024);
        w.check_and_record(100).unwrap();
        // 99 is 1 behind the highest, within window.
        w.check_and_record(99).unwrap();
        // 50 is 50 behind, still within 1024-bit window.
        w.check_and_record(50).unwrap();
        // 99 again — already seen, reject.
        assert_eq!(
            w.check_and_record(99).unwrap_err(),
            ObfsError::ReplayRejected(99)
        );
    }

    #[test]
    fn replay_window_rejects_too_old() {
        let mut w = ReplayWindow::new(64); // small window for test
        w.check_and_record(1000).unwrap();
        // 935 is 65 behind — beyond 64-bit window.
        assert_eq!(
            w.check_and_record(935).unwrap_err(),
            ObfsError::ReplayRejected(935)
        );
        // 936 is exactly 64 behind — also out of window (window is
        // [highest - bits + 1, highest], so bits=64 means 64
        // valid slots ending at highest, oldest valid = highest - 63).
        assert_eq!(
            w.check_and_record(936).unwrap_err(),
            ObfsError::ReplayRejected(936)
        );
        // 937 is 63 behind — within window.
        w.check_and_record(937).unwrap();
    }

    #[test]
    fn replay_window_slides_correctly() {
        let mut w = ReplayWindow::new(64);
        w.check_and_record(10).unwrap();
        w.check_and_record(20).unwrap();
        // Jump to 100 — slides window by 80; entries at 10 and 20 fall
        // out of the new window (highest=100, oldest=37).
        w.check_and_record(100).unwrap();
        // 10 and 20 are now "too old"
        assert!(matches!(
            w.check_and_record(10).unwrap_err(),
            ObfsError::ReplayRejected(_)
        ));
        // 50 within new window.
        w.check_and_record(50).unwrap();
        // 50 again — rejected.
        assert!(matches!(
            w.check_and_record(50).unwrap_err(),
            ObfsError::ReplayRejected(_)
        ));
    }

    #[test]
    fn replay_window_huge_jump_clears_bitmap() {
        let mut w = ReplayWindow::new(64);
        w.check_and_record(5).unwrap();
        w.check_and_record(10).unwrap();
        // Jump to 10000 — window fully cleared.
        w.check_and_record(10_000).unwrap();
        // Old entries gone.
        assert!(matches!(
            w.check_and_record(5).unwrap_err(),
            ObfsError::ReplayRejected(_)
        ));
        // 9999 within window now.
        w.check_and_record(9_999).unwrap();
    }

    // ── SenderState / ReceiverState ──────────────────────────────────────

    #[test]
    fn sender_receiver_round_trip() {
        let mut sender = SenderState::new(ObfsKey::derive(TEST_PSK, &peer_a()));
        let mut receiver = ReceiverState::new(ObfsKey::derive(TEST_PSK, &peer_a()));

        for i in 0..50 {
            let payload = format!("msg-{i}");
            let wire = sender.seal_next(payload.as_bytes()).unwrap();
            let got = receiver.open_and_check(&wire).unwrap();
            assert_eq!(got, payload.as_bytes());
        }
    }

    #[test]
    fn sender_receiver_replay_rejected() {
        let mut sender = SenderState::new(ObfsKey::derive(TEST_PSK, &peer_a()));
        let mut receiver = ReceiverState::new(ObfsKey::derive(TEST_PSK, &peer_a()));

        let wire = sender.seal_next(b"hello").unwrap();
        receiver.open_and_check(&wire).unwrap();
        // Replay same wire — replay window rejects.
        assert!(matches!(
            receiver.open_and_check(&wire).unwrap_err(),
            ObfsError::ReplayRejected(_)
        ));
    }

    #[test]
    fn sender_receiver_tolerates_reorder() {
        let mut sender = SenderState::new(ObfsKey::derive(TEST_PSK, &peer_a()));
        let mut receiver = ReceiverState::new(ObfsKey::derive(TEST_PSK, &peer_a()));

        let w1 = sender.seal_next(b"first").unwrap();
        let w2 = sender.seal_next(b"second").unwrap();
        let w3 = sender.seal_next(b"third").unwrap();

        // Receive in reversed order — all should decrypt.
        assert_eq!(receiver.open_and_check(&w3).unwrap(), b"third");
        assert_eq!(receiver.open_and_check(&w1).unwrap(), b"first");
        assert_eq!(receiver.open_and_check(&w2).unwrap(), b"second");
    }

    // ── PeerStateMap ─────────────────────────────────────────────────────

    #[test]
    fn peer_state_map_isolates_peers() {
        let mut map = PeerStateMap::new();
        let pa = peer_a();
        let pb = peer_b();

        let wire_a = map.sender_mut(&pa, TEST_PSK).seal_next(b"to-a").unwrap();
        let wire_b = map.sender_mut(&pb, TEST_PSK).seal_next(b"to-b").unwrap();

        // Receive from peer A through peer A's receiver.
        let got_a = map
            .receiver_mut(&pa, TEST_PSK)
            .open_and_check(&wire_a)
            .unwrap();
        assert_eq!(got_a, b"to-a");

        // Wire intended for B fails on A's key.
        assert_eq!(
            map.receiver_mut(&pa, TEST_PSK)
                .open_and_check(&wire_b)
                .unwrap_err(),
            ObfsError::AeadFailure
        );

        // B's receiver accepts B's wire.
        let got_b = map
            .receiver_mut(&pb, TEST_PSK)
            .open_and_check(&wire_b)
            .unwrap();
        assert_eq!(got_b, b"to-b");
    }

    #[test]
    fn peer_state_map_forget_resets() {
        let mut map = PeerStateMap::new();
        let pa = peer_a();
        let _ = map.sender_mut(&pa, TEST_PSK).seal_next(b"x").unwrap();
        assert_eq!(map.peer_count(), 1);
        map.forget(&pa);
        assert_eq!(map.peer_count(), 0);
    }

    // ── Wire format spot-check ───────────────────────────────────────────

    /// Wire bytes must NOT contain any plaintext OVL1-magic-resembling
    /// sequence at any fixed offset.  Spot-check across many random
    /// payloads + counters.
    #[test]
    fn wire_bytes_uniformly_random_looking() {
        let key = ObfsKey::derive(TEST_PSK, &peer_a());
        let payload = b"OVL1\x01\x00\x00\x00\x00\x00\x00\x18 .. \"OVL1\" inside payload";
        for c in 1..=200u64 {
            let wire = seal_datagram(&key, c, payload).unwrap();
            // The plaintext `OVL1` magic must NOT appear consecutively
            // anywhere in the wire bytes (probabilistic — would happen ≤
            // 1 in 4 billion per random chance, vanishingly unlikely for
            // 200 trials of ~330-byte buffers).
            let magic = b"OVL1";
            for window in wire.windows(4) {
                assert_ne!(
                    window, magic,
                    "OVL1 magic appeared in wire bytes at counter={c}"
                );
            }
        }
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }
}
