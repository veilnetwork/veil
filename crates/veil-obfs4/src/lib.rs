//! obfs4-style TCP stream obfuscation.
//!
//! Phase 1b of [`docs/internal/PLAN_TRANSPORT_OBFUSCATION.md`](../../docs/internal/PLAN_TRANSPORT_OBFUSCATION.md).
//!
//! # Scope of this crate
//!
//! **Phase 1b (this commit):** AEAD frame wrap/unwrap core.  Pure
//! functions; no I/O, no handshake, no key exchange.  This is the
//! framing layer that sits AFTER an obfs4 handshake derives session
//! keys — wraps every OVL1 frame in random-looking AEAD ciphertext with
//! encrypted length so DPI cannot see frame boundaries either.
//!
//! **Phase 1c (next session):** NTOR handshake + elligator2 encoding
//! that produces the session keys consumed by this crate's framing layer.
//! Wire bytes from Phase 1c handshake are uniformly random; Phase 1b
//! framing keeps them random for the rest of the connection.
//!
//! # Wire format (post-handshake stream)
//!
//! Each frame on the wire:
//! ```text
//! [ 2 byte length     (ChaCha20-keystream encrypted) ]
//! [ ChaCha20-Poly1305(payload || random padding 0..MAX_PADDING) ]
//! [ 16 byte AEAD tag ]
//! ```
//!
//! Length-field encryption: the 2-byte big-endian length is XOR'd with
//! the first 2 bytes of a ChaCha20 keystream block keyed by the same
//! session key, nonce = `b"obfs4-len:v1\0\0\0\0" || counter[..4]`.
//! Without the key, frame boundaries are invisible — an observer sees
//! one continuous random byte stream.
//!
//! The AEAD body is encrypted with a **separate** nonce derivation
//! (`b"obfs4-body:v1" || counter[..8]`) so length-keystream and body-key
//! domain-separate properly.
//!
//! # Counter management
//!
//! Each direction maintains a monotonic u64 counter.  Sender increments
//! on every wrap; receiver expects strict monotonicity (no
//! out-of-order, since TCP delivers in order).  Counter overflow → close
//! the stream (signals that rekey is overdue; handshake should have
//! re-negotiated long before 2^64 frames).
//!
//! # Threat model
//!
//! In-scope:
//! - Passive DPI looking for OVL1 magic, frame-length patterns, or
//!   distinctive header bytes.  Wire entropy is uniform per AEAD.
//! - Tampered ciphertext / length field → AEAD rejects, peer disconnect.
//!
//! Out-of-scope for Phase 1b:
//! - Active probing (handled by Phase 1c silent-drop on bad MAC).
//! - First-handshake-byte uniformity (handled by Phase 1c elligator2).
//! - Statistical timing analysis.

#![forbid(unsafe_code)]

pub mod elligator2;
pub mod ntor;
pub mod stream;
pub mod wire_variant;

pub use wire_variant::WireFormatVariant;

pub use ntor::{
    ClientHandshake, ClientHandshakeOutput, HANDSHAKE_MAX_BYTES, HANDSHAKE_MIN_BYTES, NodeIdMacKey,
    ServerHandshake, ServerHandshakeOutput,
};
pub use stream::{
    Obfs4Stream, UpgradeError, obfs4_client_connect, obfs4_client_connect_variant,
    obfs4_server_accept, obfs4_server_accept_multi,
};

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Handshake errors ────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HandshakeError {
    #[error("failed to generate elligator-encodable keypair (broken RNG?)")]
    NoRepresentative,

    #[error("handshake message too short: got {0}")]
    TooShort(usize),

    #[error("handshake bad padding: declared={declared}, available={available}")]
    BadPadding { declared: usize, available: usize },

    #[error("handshake trailing bytes: {0}")]
    TrailingBytes(usize),

    #[error("client MAC does not match (wrong PSK or tampering)")]
    ClientMacMismatch,

    #[error("server AUTH does not match (tampered response or wrong server)")]
    AuthMismatch,
}

// ── Constants ────────────────────────────────────────────────────────────────

/// AEAD tag length (ChaCha20-Poly1305).
pub const AEAD_TAG_LEN: usize = 16;

/// Length-prefix size on the wire (encrypted u16 BE).
pub const LEN_PREFIX_BYTES: usize = 2;

/// Max length-prefix value (= max ciphertext length).  16 KiB is large
/// enough for any OVL1 session frame (capped by `MAX_FRAME_BODY = 16 MiB`
/// in veil-proto, but fragmented to 16 KiB chunks in practice for NIC
/// MTU efficiency).
pub const MAX_FRAME_CIPHERTEXT_BYTES: usize = 16 * 1024;

/// Max padding appended to each frame body before AEAD.  Larger values
/// disrupt frame-size fingerprinting but cost bandwidth.  1024 bytes is
/// the same magnitude as TLS record padding upper bound.
pub const MAX_PADDING_BYTES: usize = 1024;

/// Max plaintext bytes that fit into a single obfs4 frame with the
/// worst-case padding budget.  `MAX_FRAME_CIPHERTEXT_BYTES - AEAD_TAG_LEN
/// - MAX_PADDING_BYTES` — callers fragmenting large writes (e.g.
/// `Obfs4Stream::poll_write`) bound each chunk at this value so
/// `wrap_next` never trips the oversized-frame guard.
pub const MAX_PLAINTEXT_PER_FRAME: usize =
    MAX_FRAME_CIPHERTEXT_BYTES - AEAD_TAG_LEN - MAX_PADDING_BYTES;

// Audit batch 2026-05-25 phase M: lock in the chunking-math invariants.
// `MAX_PLAINTEXT_PER_FRAME` derives MAX_FRAME_CIPHERTEXT_BYTES minus
// the AEAD overhead and a conservative `MAX_PADDING_BYTES` budget
// (`wrap_frame` actually caps the wire pad-len byte at u8::MAX=255 via
// `.min(255)` regardless of MAX_PADDING_BYTES, so the formula is
// over-conservative — a strict improvement).  Compile-time invariants
// guard the underlying arithmetic against silently going negative or
// past the wire-frame cap.
const _: () = {
    assert!(
        AEAD_TAG_LEN < MAX_FRAME_CIPHERTEXT_BYTES,
        "MAX_FRAME_CIPHERTEXT_BYTES must leave room for the AEAD tag",
    );
    assert!(
        AEAD_TAG_LEN + MAX_PADDING_BYTES < MAX_FRAME_CIPHERTEXT_BYTES,
        "AEAD_TAG_LEN + MAX_PADDING_BYTES must fit under MAX_FRAME_CIPHERTEXT_BYTES \
         otherwise MAX_PLAINTEXT_PER_FRAME underflows",
    );
    assert!(
        MAX_PLAINTEXT_PER_FRAME > 0,
        "MAX_PLAINTEXT_PER_FRAME would be zero or negative",
    );
};

/// HKDF context — domain separates key-deriv from any other obfs use of
/// the same shared secret.
pub const HKDF_CONTEXT: &[u8] = b"veil-obfs4-stream:v1";

/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("AEAD verification failed (wrong key, tampered, or counter mismatch)")]
    AeadFailure,

    #[error("frame ciphertext length {0} exceeds cap {MAX_FRAME_CIPHERTEXT_BYTES}")]
    OversizedFrame(usize),

    #[error("frame ciphertext too short: need ≥{AEAD_TAG_LEN}, got {0}")]
    TooShort(usize),

    #[error("padding byte {0} exceeds remaining frame body {1}")]
    BadPadding(usize, usize),

    #[error("counter overflow — re-handshake required")]
    CounterOverflow,
}

// ── Direction keys ───────────────────────────────────────────────────────────

/// Per-direction session keys.  An obfs4 stream has TWO of these:
/// one for client-to-server and one for server-to-client.  Each direction
/// has its own AEAD key + length-encryption key + monotonic counter.
///
/// Derived from the handshake's shared secret via HKDF with per-direction
/// context label.
#[derive(ZeroizeOnDrop)]
pub struct DirectionKey {
    /// AEAD cipher for frame body.
    #[zeroize(skip)]
    body_cipher: ChaCha20Poly1305,
    /// AEAD cipher for length-prefix encryption.  Different key
    /// derived from same shared secret through separate HKDF info.
    #[zeroize(skip)]
    len_cipher: ChaCha20Poly1305,
}

impl std::fmt::Debug for DirectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirectionKey(<redacted>)")
    }
}

impl DirectionKey {
    /// Derive a direction key from the post-handshake shared secret.
    ///
    /// `shared_secret` — 32-byte X25519 output (typically).
    /// `direction_label` — e.g. b"c2s" or b"s2c", domain-separating
    ///   the two directions so that keys are independent.
    pub fn derive(shared_secret: &[u8], direction_label: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut body_key = [0u8; 32];
        let mut len_key = [0u8; 32];

        let mut info_body = Vec::with_capacity(HKDF_CONTEXT.len() + direction_label.len() + 5);
        info_body.extend_from_slice(HKDF_CONTEXT);
        info_body.extend_from_slice(b":body:");
        info_body.extend_from_slice(direction_label);
        hk.expand(&info_body, &mut body_key)
            .expect("HKDF-SHA256 32-byte expand cannot fail");

        let mut info_len = Vec::with_capacity(HKDF_CONTEXT.len() + direction_label.len() + 4);
        info_len.extend_from_slice(HKDF_CONTEXT);
        info_len.extend_from_slice(b":len:");
        info_len.extend_from_slice(direction_label);
        hk.expand(&info_len, &mut len_key)
            .expect("HKDF-SHA256 32-byte expand cannot fail");

        let body_cipher = ChaCha20Poly1305::new(Key::from_slice(&body_key));
        let len_cipher = ChaCha20Poly1305::new(Key::from_slice(&len_key));
        body_key.zeroize();
        len_key.zeroize();
        Self {
            body_cipher,
            len_cipher,
        }
    }

    /// Test-only: from raw 32-byte secret bytes (skips HKDF). Production
    /// callers must use [`derive`](Self::derive). Gated `#[cfg(test)]` +
    /// `pub(crate)` so this non-HKDF constructor (with its weak XOR len-key
    /// derivation) is unreachable from any production build or other crate.
    #[cfg(test)]
    pub(crate) fn from_raw_for_test(secret: &[u8; 32]) -> Self {
        let body_cipher = ChaCha20Poly1305::new(Key::from_slice(secret));
        // For test, derive a distinct len_key by XOR — still
        // domain-separated for testing purposes.
        let mut len_key = *secret;
        for (i, b) in len_key.iter_mut().enumerate() {
            *b ^= (i as u8).wrapping_mul(13).wrapping_add(7);
        }
        let len_cipher = ChaCha20Poly1305::new(Key::from_slice(&len_key));
        len_key.zeroize();
        Self {
            body_cipher,
            len_cipher,
        }
    }
}

// ── Nonce derivation ─────────────────────────────────────────────────────────

/// Build the 12-byte body-AEAD nonce from counter.  Domain-separated from
/// the length-encryption nonce so the two ciphers never share nonce-key
/// state.
fn body_nonce(counter: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..4].copy_from_slice(b"BODY");
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

/// Build the 12-byte length-AEAD nonce from counter.  Used to encrypt
/// (well, AEAD-encrypt without using the tag) the 2-byte length prefix.
fn len_nonce(counter: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..4].copy_from_slice(b"LEN_");
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

// ── Frame wrap / unwrap ──────────────────────────────────────────────────────

/// Wrap an outbound payload into a wire frame.
///
/// Steps:
/// 1. Pick a random pad-length in `[0, MAX_PADDING_BYTES]`.
/// 2. Build body = `[1 byte pad-len || payload || pad-len bytes random]`.
/// 3. AEAD-encrypt body with `body_cipher` keyed on counter-derived nonce.
/// 4. Encrypt the 2-byte length prefix with `len_cipher` AEAD (taking only
///    the first 2 bytes of the resulting ciphertext — we discard the
///    AEAD tag for the length prefix since the body's AEAD tag already
///    authenticates the entire frame including its length).
///
/// Step (4) deserves a note: we treat the length-cipher as a keystream-
/// only operation by XOR'ing the plaintext length with 2 bytes derived
/// from encrypting `[0u8; 2]` under the length-cipher's keyed AEAD.  This
/// gives us a PRF on the (key, counter) pair without committing to ChaCha20
/// streamcipher API directly (chacha20poly1305 crate doesn't expose the
/// streamcipher).  The trade-off: 2-byte AEAD wraps internally produce
/// 18 bytes but we extract only the first 2 ciphertext bytes — that's
/// equivalent to ChaCha20 keystream prefix encryption.
pub fn wrap_frame(key: &DirectionKey, counter: u64, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    // Pad-length: random 0..=MAX_PADDING_BYTES.
    let mut pad_byte = [0u8; 2];
    rand::rng().fill_bytes(&mut pad_byte);
    let pad_len = (u16::from_be_bytes(pad_byte) as usize) % (MAX_PADDING_BYTES + 1);

    // Body = pad-len-byte || payload || random padding.
    //
    // Audit batch 2026-05-25 phase M: clarified comment.  Wire format
    // packs pad_len in a single u8, so we cap to 255 first then build
    // the body — receiver reads exactly `pad_len` bytes off the tail.
    // NOTE (audit cycle-6): the runtime `.min(u8::MAX)` below is the ONLY
    // guard — `MAX_PADDING_BYTES` is intentionally larger than `u8::MAX`
    // (1024), and there is NO compile-time assert that it is ≤ u8::MAX (an
    // earlier comment here wrongly claimed one — such an assert would in
    // fact fail to compile). The runtime cap makes the on-wire pad_len fit
    // the single byte regardless of `MAX_PADDING_BYTES`.
    let pad_len = pad_len.min(u8::MAX as usize);
    let body_len = 1 + payload.len() + pad_len;
    let mut body = Vec::with_capacity(body_len);
    body.push(pad_len as u8);
    body.extend_from_slice(payload);
    if pad_len > 0 {
        let mut pad_buf = vec![0u8; pad_len];
        rand::rng().fill_bytes(&mut pad_buf);
        body.extend_from_slice(&pad_buf);
    }

    // AEAD-encrypt body.
    let body_ct = key
        .body_cipher
        .encrypt(
            Nonce::from_slice(&body_nonce(counter)),
            Payload {
                msg: &body,
                aad: &counter.to_be_bytes(),
            },
        )
        .map_err(|_| FrameError::AeadFailure)?;

    if body_ct.len() > MAX_FRAME_CIPHERTEXT_BYTES {
        return Err(FrameError::OversizedFrame(body_ct.len()));
    }

    // Encrypted length prefix.
    let len_be = (body_ct.len() as u16).to_be_bytes();
    let len_ct = encrypt_len_prefix(key, counter, &len_be)?;

    let mut out = Vec::with_capacity(LEN_PREFIX_BYTES + body_ct.len());
    out.extend_from_slice(&len_ct);
    out.extend_from_slice(&body_ct);
    Ok(out)
}

/// Decrypt + verify a frame from wire bytes.  Caller is responsible
/// for buffering enough bytes on the underlying transport so that the
/// length-prefix can be decrypted, then the body fetched in a second
/// read.  This crate exposes the framing as pure functions; the
/// caller's tokio read-loop applies them in the correct order.
///
/// Returns `(consumed, payload)` so the caller can advance its buffer.
/// `consumed` includes the length prefix.
pub fn unwrap_frame(
    key: &DirectionKey,
    counter: u64,
    wire: &[u8],
) -> Result<(usize, Vec<u8>), FrameError> {
    if wire.len() < LEN_PREFIX_BYTES {
        return Err(FrameError::TooShort(wire.len()));
    }
    let mut len_ct = [0u8; LEN_PREFIX_BYTES];
    len_ct.copy_from_slice(&wire[..LEN_PREFIX_BYTES]);
    let len_pt = decrypt_len_prefix(key, counter, &len_ct)?;
    let body_len = u16::from_be_bytes(len_pt) as usize;

    if body_len > MAX_FRAME_CIPHERTEXT_BYTES {
        return Err(FrameError::OversizedFrame(body_len));
    }
    if body_len < AEAD_TAG_LEN {
        return Err(FrameError::TooShort(body_len));
    }
    if wire.len() < LEN_PREFIX_BYTES + body_len {
        return Err(FrameError::TooShort(wire.len()));
    }

    let body_ct = &wire[LEN_PREFIX_BYTES..LEN_PREFIX_BYTES + body_len];
    let body = key
        .body_cipher
        .decrypt(
            Nonce::from_slice(&body_nonce(counter)),
            Payload {
                msg: body_ct,
                aad: &counter.to_be_bytes(),
            },
        )
        .map_err(|_| FrameError::AeadFailure)?;

    if body.is_empty() {
        return Err(FrameError::BadPadding(0, 0));
    }
    let pad_len = body[0] as usize;
    if 1 + pad_len > body.len() {
        return Err(FrameError::BadPadding(pad_len, body.len() - 1));
    }
    let payload = body[1..body.len() - pad_len].to_vec();
    Ok((LEN_PREFIX_BYTES + body_len, payload))
}

/// Encrypt the 2-byte length prefix.  Uses a keystream-only construction
/// over the length-cipher: encrypt 2 zero bytes under (len_key, len_nonce)
/// and XOR with the plaintext length.  AEAD tag is discarded — body AEAD
/// authenticates the entire frame anyway.
fn encrypt_len_prefix(
    key: &DirectionKey,
    counter: u64,
    len_be: &[u8; LEN_PREFIX_BYTES],
) -> Result<[u8; LEN_PREFIX_BYTES], FrameError> {
    let zero = [0u8; LEN_PREFIX_BYTES];
    let ks_ct = key
        .len_cipher
        .encrypt(Nonce::from_slice(&len_nonce(counter)), zero.as_slice())
        .map_err(|_| FrameError::AeadFailure)?;
    // Take first 2 bytes of the AEAD ciphertext as keystream.  The
    // AEAD tag (16 trailing bytes) is discarded.
    let mut out = [0u8; LEN_PREFIX_BYTES];
    for i in 0..LEN_PREFIX_BYTES {
        out[i] = ks_ct[i] ^ len_be[i];
    }
    Ok(out)
}

/// Decrypt the 2-byte length prefix (inverse of `encrypt_len_prefix`).
/// XOR is symmetric so the function is identical to encrypt.
fn decrypt_len_prefix(
    key: &DirectionKey,
    counter: u64,
    len_ct: &[u8; LEN_PREFIX_BYTES],
) -> Result<[u8; LEN_PREFIX_BYTES], FrameError> {
    encrypt_len_prefix(key, counter, len_ct)
}

// ── Stream state machine (monotonic counter) ─────────────────────────────────

/// Outbound stream state: holds the direction key and monotonic counter.
/// One per direction (sender uses its own, peer's sender uses its own
/// in the opposite direction).
pub struct OutboundStream {
    key: DirectionKey,
    counter: u64,
}

impl OutboundStream {
    pub fn new(key: DirectionKey) -> Self {
        Self { key, counter: 0 }
    }

    /// Wrap a frame, advancing the counter.  Returns wire bytes ready
    /// for `AsyncWrite::write_all`.
    pub fn wrap_next(&mut self, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(FrameError::CounterOverflow)?;
        wrap_frame(&self.key, self.counter, payload)
    }
}

/// Inbound stream state: direction key + expected next counter.  Counter
/// must be strictly monotonic (TCP delivers in order; out-of-order or
/// gaps signal tampering or session loss).
pub struct InboundStream {
    key: DirectionKey,
    expected_counter: u64,
}

impl InboundStream {
    pub fn new(key: DirectionKey) -> Self {
        Self {
            key,
            expected_counter: 0,
        }
    }

    /// Peek the next frame's length from wire bytes (decrypts the
    /// 2-byte length prefix).  Caller uses this to know how many more
    /// bytes to buffer before calling `unwrap_next`.
    ///
    /// Does NOT advance the counter — call `unwrap_next` once enough
    /// bytes are buffered.
    pub fn peek_frame_len(&self, wire: &[u8]) -> Result<usize, FrameError> {
        if wire.len() < LEN_PREFIX_BYTES {
            return Err(FrameError::TooShort(wire.len()));
        }
        let next_counter = self
            .expected_counter
            .checked_add(1)
            .ok_or(FrameError::CounterOverflow)?;
        let mut len_ct = [0u8; LEN_PREFIX_BYTES];
        len_ct.copy_from_slice(&wire[..LEN_PREFIX_BYTES]);
        let len_pt = decrypt_len_prefix(&self.key, next_counter, &len_ct)?;
        Ok(u16::from_be_bytes(len_pt) as usize)
    }

    /// Unwrap a complete frame.  Advances the counter on success.
    pub fn unwrap_next(&mut self, wire: &[u8]) -> Result<(usize, Vec<u8>), FrameError> {
        let next_counter = self
            .expected_counter
            .checked_add(1)
            .ok_or(FrameError::CounterOverflow)?;
        let result = unwrap_frame(&self.key, next_counter, wire)?;
        self.expected_counter = next_counter;
        Ok(result)
    }
}

// ── Constant-time helpers (re-exported for callers) ──────────────────────────

use subtle::ConstantTimeEq;

/// Constant-time equality compare.  Re-exported for Phase 1c handshake
/// MAC verification.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: [u8; 32] = [0x42; 32];

    fn make_pair() -> (DirectionKey, DirectionKey) {
        // Same secret + same label → identical key (for tests; real
        // usage uses different labels per direction).
        (
            DirectionKey::from_raw_for_test(&TEST_SECRET),
            DirectionKey::from_raw_for_test(&TEST_SECRET),
        )
    }

    #[test]
    fn round_trip_single_frame() {
        let (sk, rk) = make_pair();
        let mut out = OutboundStream::new(sk);
        let mut inb = InboundStream::new(rk);

        let payload = b"hello obfs4";
        let wire = out.wrap_next(payload).unwrap();
        let (consumed, got) = inb.unwrap_next(&wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(got, payload);
    }

    #[test]
    fn round_trip_many_frames() {
        let (sk, rk) = make_pair();
        let mut out = OutboundStream::new(sk);
        let mut inb = InboundStream::new(rk);

        for i in 1..=200u64 {
            let msg = format!("frame-{i}");
            let wire = out.wrap_next(msg.as_bytes()).unwrap();
            let (consumed, got) = inb.unwrap_next(&wire).unwrap();
            assert_eq!(consumed, wire.len());
            assert_eq!(got, msg.as_bytes());
        }
    }

    #[test]
    fn empty_payload_roundtrips() {
        let (sk, rk) = make_pair();
        let mut out = OutboundStream::new(sk);
        let mut inb = InboundStream::new(rk);

        let wire = out.wrap_next(b"").unwrap();
        let (_, got) = inb.unwrap_next(&wire).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn large_payload_roundtrips() {
        let (sk, rk) = make_pair();
        let mut out = OutboundStream::new(sk);
        let mut inb = InboundStream::new(rk);

        // ~14 KiB payload + padding must fit under MAX_FRAME_CIPHERTEXT_BYTES.
        let payload = vec![0xABu8; 14_000];
        let wire = out.wrap_next(&payload).unwrap();
        let (_, got) = inb.unwrap_next(&wire).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn tampered_body_rejected() {
        let (sk, rk) = make_pair();
        let mut out = OutboundStream::new(sk);
        let mut inb = InboundStream::new(rk);

        let mut wire = out.wrap_next(b"hello").unwrap();
        // Flip byte in the body region.
        wire[LEN_PREFIX_BYTES + 2] ^= 0x01;
        assert_eq!(inb.unwrap_next(&wire).unwrap_err(), FrameError::AeadFailure);
    }

    #[test]
    fn tampered_length_prefix_yields_aead_failure_or_short() {
        let (sk, rk) = make_pair();
        let mut out = OutboundStream::new(sk);
        let mut inb = InboundStream::new(rk);

        let mut wire = out.wrap_next(b"hello").unwrap();
        wire[0] ^= 0x01; // flip a length-prefix bit
        let err = inb.unwrap_next(&wire).unwrap_err();
        // Could surface as `TooShort` (decrypted len > available) or
        // `OversizedFrame` (decrypted len > cap) or `AeadFailure` (length
        // happens to be valid but body decrypt fails).
        assert!(matches!(
            err,
            FrameError::TooShort(_) | FrameError::OversizedFrame(_) | FrameError::AeadFailure
        ));
    }

    #[test]
    fn out_of_order_counter_rejected() {
        let (sk, rk) = make_pair();
        let mut out = OutboundStream::new(sk);
        let mut inb = InboundStream::new(rk);

        let w1 = out.wrap_next(b"first").unwrap();
        let w2 = out.wrap_next(b"second").unwrap();

        // Consume w2 first — counter mismatch.  Decrypts under wrong
        // counter → length prefix decrypts to garbage → either too-short
        // or oversized-frame or (rarely) AEAD fails after a valid-looking
        // length.  Any of the three means rejection.
        let err = inb.unwrap_next(&w2).unwrap_err();
        assert!(matches!(
            err,
            FrameError::AeadFailure | FrameError::TooShort(_) | FrameError::OversizedFrame(_)
        ));
        // After failure, expected_counter still 0.  w1 was wrapped at
        // counter 1; inb's next-expected is 1 → w1 decrypts.
        let (_, got) = inb.unwrap_next(&w1).unwrap();
        assert_eq!(got, b"first");
    }

    #[test]
    fn frames_have_distinct_lengths_due_to_padding() {
        let (sk, _) = make_pair();
        let mut out = OutboundStream::new(sk);
        let mut lengths = std::collections::HashSet::new();
        // 200 frames with the same payload should produce variable
        // wire lengths thanks to random padding.
        for _ in 0..200 {
            let wire = out.wrap_next(b"same payload").unwrap();
            lengths.insert(wire.len());
        }
        assert!(
            lengths.len() > 5,
            "padding randomisation should produce ≥5 distinct frame lengths, got {}",
            lengths.len()
        );
    }

    #[test]
    fn wire_bytes_have_no_ovl1_magic() {
        let (sk, _) = make_pair();
        let mut out = OutboundStream::new(sk);
        // Payload contains plaintext OVL1 magic; after framing it must
        // not appear consecutively in wire bytes.
        let payload = b"OVL1\x01\x00\x00\x00\x00OVL1OVL1\x18 trailing";
        for _ in 0..200 {
            let wire = out.wrap_next(payload).unwrap();
            let magic = b"OVL1";
            for window in wire.windows(4) {
                assert_ne!(window, magic, "OVL1 magic leaked in obfs4 frame wire bytes");
            }
        }
    }

    #[test]
    fn different_direction_labels_yield_different_keys() {
        let secret = [0xCC; 32];
        let dk_c2s = DirectionKey::derive(&secret, b"c2s");
        let dk_s2c = DirectionKey::derive(&secret, b"s2c");

        let mut out = OutboundStream::new(dk_c2s);
        let mut inb_wrong = InboundStream::new(dk_s2c);

        let wire = out.wrap_next(b"hello").unwrap();
        // Wrong-direction key → length prefix decrypts to garbage, then
        // either the apparent body length exceeds available bytes
        // (TooShort), exceeds the cap (OversizedFrame), or matches but
        // body AEAD fails.  Any rejection mode is acceptable.
        let err = inb_wrong.unwrap_next(&wire).unwrap_err();
        assert!(matches!(
            err,
            FrameError::AeadFailure | FrameError::TooShort(_) | FrameError::OversizedFrame(_)
        ));
    }

    #[test]
    fn matched_derived_keys_round_trip() {
        let secret = [0xCC; 32];
        let dk_c2s_sender = DirectionKey::derive(&secret, b"c2s");
        let dk_c2s_receiver = DirectionKey::derive(&secret, b"c2s");

        let mut out = OutboundStream::new(dk_c2s_sender);
        let mut inb = InboundStream::new(dk_c2s_receiver);

        let wire = out.wrap_next(b"hello").unwrap();
        let (_, got) = inb.unwrap_next(&wire).unwrap();
        assert_eq!(got, b"hello");
    }

    #[test]
    fn peek_frame_len_matches_actual() {
        let (sk, rk) = make_pair();
        let mut out = OutboundStream::new(sk);
        let inb = InboundStream::new(rk);

        let wire = out.wrap_next(b"some payload").unwrap();
        let peeked = inb.peek_frame_len(&wire).unwrap();
        // peek_frame_len returns body ciphertext length; total wire =
        // peeked + LEN_PREFIX_BYTES.
        assert_eq!(peeked + LEN_PREFIX_BYTES, wire.len());
    }

    #[test]
    fn counter_overflow_handled() {
        let (sk, rk) = make_pair();
        let mut out = OutboundStream::new(sk);
        let mut inb = InboundStream::new(rk);

        // Force counters near saturation.
        out.counter = u64::MAX - 1;
        inb.expected_counter = u64::MAX - 1;

        // One more wrap → counter advances to u64::MAX → OK.
        let wire = out.wrap_next(b"last").unwrap();
        let (_, got) = inb.unwrap_next(&wire).unwrap();
        assert_eq!(got, b"last");

        // Next wrap → overflow.
        assert_eq!(
            out.wrap_next(b"too many").unwrap_err(),
            FrameError::CounterOverflow
        );
        // Receiver also rejects (its expected_counter is now u64::MAX).
        let dummy = vec![0u8; LEN_PREFIX_BYTES + AEAD_TAG_LEN + 4];
        assert_eq!(
            inb.unwrap_next(&dummy).unwrap_err(),
            FrameError::CounterOverflow
        );
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(b"hello", b"hello!"));
    }
}
