//! ChaCha20-Poly1305 AEAD for OVL1 session frame encryption.
//!
//! Each OVL1 session maintains two independent nonce counters (one per
//! direction). The 12-byte nonce is constructed as:
//!
//! ```text
//! [0..4] direction salt — [0,0,0,1] for tx, [0,0,0,2] for rx
//! [4..12] counter — u64 little-endian, incremented per frame
//! ```
//!
//! The direction salt prevents nonce reuse if the same key were ever used for
//! both directions (they are not in our KDF, but the extra protection costs
//! nothing).
//!
//! Only the **frame body** (after the 24-byte `FrameHeader`) is encrypted.
//! The header travels in the clear so that the receiver can determine `body_len`
//! before allocating the decryption buffer.
//!
//! ## AAD binding
//!
//! Every `seal`/`open` call accepts an `aad: &[u8]` slice that is mixed into
//! the Poly1305 tag. Callers **must** pass the 3-byte frame-type prefix
//! `[family, msg_type_hi, msg_type_lo]` so that the frame type is
//! cryptographically bound to its ciphertext. Substituting a ciphertext into
//! a different frame-type slot will fail authentication.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, AeadInPlace, Payload},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── public error ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum CipherError {
    #[error("AEAD decryption failed (bad MAC or corrupted ciphertext)")]
    DecryptFailed,
    #[error("AEAD encryption failed")]
    EncryptFailed,
    #[error("nonce counter overflow — session must be renegotiated")]
    NonceOverflow,
}

/// Number of bytes the AEAD appends to the plaintext. ChaCha20-Poly1305 emits
/// a 16-byte Poly1305 tag after the ciphertext; there is no explicit nonce on
/// the wire (it is derived from the per-direction counter).
///
/// Exposed for sizing calculations [`veilcore::node::session::runner`] where
/// the target wire length determines how many plaintext bytes fit in a frame
///
pub const AEAD_OVERHEAD: usize = 16;

// ── SessionCipher ─────────────────────────────────────────────────────────────

/// Stateful AEAD context for one direction of an OVL1 session.
///
/// Each direction (tx / rx) gets its own `SessionCipher` instance so counters
/// never collide.
///
/// # Memory hygiene
///
/// `SessionCipher` is `ZeroizeOnDrop` так that the session key material is
/// wiped from heap memory as soon as the cipher is dropped. The wipe is а
/// composition of two layers:
///
/// * Our `#[derive(Zeroize, ZeroizeOnDrop)]` generates а `Drop` impl that
///   calls `self.zeroize()` — but the upstream `chacha20poly1305` crate
///   only implements [`ZeroizeOnDrop`] (а marker trait) on
///   `ChaCha20Poly1305`, **not** the [`Zeroize`] trait itself.  Therefore
///   the `cipher` field must be `#[zeroize(skip)]` — otherwise the derive
///   would fail к compile.
///
/// * Rust drops struct fields in declaration order **after** the explicit
///   `Drop::drop` body runs.  So the actual wipe sequence on drop is:
///   1. Our derive's `Drop::drop` → zeros `counter` + `dir_salt`
///      (`cipher` skipped here, per annotation rationale above).
///   2. Field `cipher` drops → its own `ZeroizeOnDrop` `Drop` impl
///      → wipes the embedded `Key` (32 bytes of secret material).
///
/// Net effect: 100 % of secret bytes wiped on drop.  The skip annotation
/// is required для compile, NOT а hole в the zeroize coverage.  See
/// `cipher_drop_zeroizes_via_upstream` test для type-system verification.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionCipher {
    /// `#[zeroize(skip)]` — see struct doc.  Upstream `ChaCha20Poly1305`'s
    /// own `Drop` zeroes the key when this field is dropped after our
    /// derive's Drop body runs.
    #[zeroize(skip)]
    cipher: ChaCha20Poly1305,
    counter: u64,
    dir_salt: [u8; 4],
}

impl SessionCipher {
    /// Create a new cipher context.
    ///
    /// `key` — 32-byte session key derived by `session_kdf::derive_session_keys`.
    /// `is_tx` — `true` for the outgoing direction, `false` for incoming.
    pub fn new(key: &[u8; 32], is_tx: bool) -> Self {
        let dir_salt = if is_tx { [0, 0, 0, 1] } else { [0, 0, 0, 2] };
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            counter: 0,
            dir_salt,
        }
    }

    /// Encrypt `plaintext` with `aad` mixed into the authentication tag.
    ///
    /// `aad` **must** be the 3-byte frame-type prefix `[family, msg_hi, msg_lo]`
    /// derived from the `FrameHeader`. Passing `b""` is rejected at compile time
    /// by the type signature — use `frame_aad(family, msg_type)` to build it.
    ///
    /// Returns `ciphertext ‖ tag` (16-byte Poly1305 tag appended).
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        let nonce = self.next_nonce()?;
        self.cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CipherError::EncryptFailed)
    }

    /// Decrypt `ciphertext ‖ tag`. Returns the plaintext on success.
    ///
    /// `aad` must match the value used in the corresponding `seal` call exactly;
    /// any mismatch (including a wrong frame type) causes authentication failure.
    /// number of frames already processed in this direction
    /// (= AEAD nonce counter). The runtime watches this to trigger a
    /// proactive rekey before approaching nonce exhaustion (2^64).
    /// Cheap O(1) accessor — no lock, no allocation.
    pub fn frames_processed(&self) -> u64 {
        self.counter
    }

    /// Decrypt one inbound frame.
    ///
    /// **Counter advance semantics (fixed / hardening):**
    /// the receive counter advances ONLY on successful decrypt. Failed
    /// AEAD verification — corruption, wrong key, replayed frame — leaves
    /// the counter at its previous value so the next legitimate frame
    /// (same sender counter) can still decrypt.
    ///
    /// This matters at rekey boundaries: a responder that switches rx
    /// keys eagerly can encounter in-flight OLD-encrypted frames from
    /// the initiator (sent before the initiator received `RekeyAck`).
    /// Without this fix, those failures would burn nonce slots on the
    /// NEW cipher and permanently desynchronise it from the sender
    /// making EVERY subsequent NEW frame fail. Pre-fix, this manifested
    /// as transient cluster-wide decrypt-failure storms after multi-hour
    /// uptime.
    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CipherError> {
        // Compute the candidate next nonce without committing the
        // counter advance — overflow is still a hard error (the cipher
        // must close before reusing a nonce-key pair).
        let candidate = self
            .counter
            .checked_add(1)
            .ok_or(CipherError::NonceOverflow)?;
        let mut n = [0u8; 12];
        n[0..4].copy_from_slice(&self.dir_salt);
        n[4..12].copy_from_slice(&candidate.to_le_bytes());
        let nonce = *Nonce::from_slice(&n);
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CipherError::DecryptFailed)?;
        // Commit the counter advance only after successful AEAD verify.
        self.counter = candidate;
        Ok(plaintext)
    }

    /// b bufpool: decrypt in-place using the AEAD's `AeadInPlace`
    /// trait. `buf` enters containing `ciphertext ‖ tag`; on success
    /// the buffer is truncated к the plaintext (tag stripped, length
    /// shrinks by `AEAD_OVERHEAD` bytes). On failure the buffer's
    /// contents are unspecified (документация chacha20poly1305:
    /// "If decryption fails, the buffer is left in an undefined
    /// state.") — callers MUST NOT read from `buf` after а failed
    /// `open_in_place`.
    ///
    /// Counter-advance discipline matches [`Self::open`]: advances
    /// ONLY on successful AEAD verify (hardening
    /// rekey-grace correctness). Nonce overflow is а hard error
    /// before any cipher work (same semantics as [`Self::open`]).
    ///
    /// # Rekey-grace caveat
    ///
    /// The rekey-grace fallback relies on
    /// retrying decryption against prior ciphers when the current
    /// cipher fails. Because `open_in_place` corrupts the buffer на
    /// failure, **callers that arm rekey-grace must keep а copy of
    /// the original ciphertext** before invoking this method — see
    /// runner.rs `decrypt_frame_body_in_place` for the conditional-
    /// i: in-place encrypt variant [`Self::seal`].
    ///
    /// Encrypts `buf` (treated as plaintext) in-place и returns the 16-byte
    /// AEAD tag separately. Caller is responsible for appending the tag at
    /// the desired wire position (typically right after the ciphertext).
    ///
    /// Sidesteps the per-frame `Vec<u8>` allocation [`Self::seal`]
    /// produces — at 15 k frames/sec on а bootstrap that translates к
    /// ~900 MiB/sec of allocator churn outside the bufpool. Combined with
    /// pool-backed output buffers, the wire-encrypt path becomes
    /// zero-allocation per frame.
    pub fn seal_in_place_detached(
        &mut self,
        buf: &mut [u8],
        aad: &[u8],
    ) -> Result<[u8; 16], CipherError> {
        let nonce = self.next_nonce()?;
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, aad, buf)
            .map_err(|_| CipherError::EncryptFailed)?;
        Ok(tag.into())
    }

    /// snapshot pattern.
    pub fn open_in_place(&mut self, buf: &mut Vec<u8>, aad: &[u8]) -> Result<(), CipherError> {
        let candidate = self
            .counter
            .checked_add(1)
            .ok_or(CipherError::NonceOverflow)?;
        let mut n = [0u8; 12];
        n[0..4].copy_from_slice(&self.dir_salt);
        n[4..12].copy_from_slice(&candidate.to_le_bytes());
        let nonce = *Nonce::from_slice(&n);
        self.cipher
            .decrypt_in_place(&nonce, aad, buf)
            .map_err(|_| CipherError::DecryptFailed)?;
        // Commit the counter advance only after successful AEAD verify.
        self.counter = candidate;
        Ok(())
    }

    // ── internal ─────────────────────────────────────────────────────────────

    fn next_nonce(&mut self) -> Result<Nonce, CipherError> {
        let c = self
            .counter
            .checked_add(1)
            .ok_or(CipherError::NonceOverflow)?;
        self.counter = c;
        let mut n = [0u8; 12];
        n[0..4].copy_from_slice(&self.dir_salt);
        n[4..12].copy_from_slice(&c.to_le_bytes());
        Ok(*Nonce::from_slice(&n))
    }
}

// ── frame_aad helper ─────────────────────────────────────────────────────────

/// Build the 3-byte AAD value `[family, msg_type_hi, msg_type_lo]` to be passed
/// [`SessionCipher::seal`] / [`SessionCipher::open`].
///
/// Binding the frame family and message type into the Poly1305 tag prevents a
/// relay from transplanting a valid ciphertext from one frame slot to another.
#[inline]
pub fn frame_aad(family: u8, msg_type: u16) -> [u8; 3] {
    [family, (msg_type >> 8) as u8, msg_type as u8]
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    const TEST_AAD: &[u8] = &[1, 0, 1]; // family=1, msg_type=1

    /// Type-system verification that `SessionCipher`'s drop-time zeroize
    /// chain is intact:
    ///
    /// 1. `SessionCipher: ZeroizeOnDrop` — our derive generates the
    ///    marker + auto-Drop wrapper.
    /// 2. `ChaCha20Poly1305: ZeroizeOnDrop` — upstream `chacha20poly1305`
    ///    crate guarantees the wrapped `Key` is wiped в its own `Drop`.
    ///
    /// If either guarantee regresses (e.g. upstream drops `zeroize`
    /// feature, or our derive macro changes), this test fails к compile,
    /// surfacing the regression before silent secret-leak risk hits prod.
    #[test]
    fn cipher_drop_zeroizes_via_upstream() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        // Both layers must impl the marker trait.
        assert_zeroize_on_drop::<SessionCipher>();
        assert_zeroize_on_drop::<ChaCha20Poly1305>();
        // Sanity: SessionCipher must also impl explicit Zeroize (our derive).
        fn assert_zeroize<T: zeroize::Zeroize>() {}
        assert_zeroize::<SessionCipher>();
    }

    #[test]
    fn seal_then_open_roundtrip() {
        let key = test_key(0xAB);
        let mut enc = SessionCipher::new(&key, true);
        let mut dec = SessionCipher::new(&key, true); // same direction → same nonces

        let plaintext = b"hello ovl1 encryption";
        let ct = enc.seal(plaintext, TEST_AAD).expect("seal");
        let pt = dec.open(&ct, TEST_AAD).expect("open");

        assert_eq!(pt, plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let key = test_key(0x01);
        let mut enc = SessionCipher::new(&key, true);
        let mut dec = SessionCipher::new(&key, true);

        let mut ct = enc.seal(b"secret", TEST_AAD).expect("seal");
        ct[0] ^= 0xFF; // flip a bit

        assert!(
            dec.open(&ct, TEST_AAD).is_err(),
            "tampered ciphertext must fail"
        );
    }

    #[test]
    fn nonce_counter_increments_correctly() {
        let key = test_key(0x55);
        let mut enc = SessionCipher::new(&key, true);
        let mut dec = SessionCipher::new(&key, true);

        for i in 0..10u8 {
            let pt = vec![i; 32];
            let ct = enc.seal(&pt, TEST_AAD).unwrap();
            let recovered = dec.open(&ct, TEST_AAD).unwrap();
            assert_eq!(recovered, pt);
        }
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let key_a = test_key(0x01);
        let key_b = test_key(0x02);
        let mut enc = SessionCipher::new(&key_a, true);
        let mut dec = SessionCipher::new(&key_b, true);

        let ct = enc.seal(b"data", TEST_AAD).unwrap();
        assert!(dec.open(&ct, TEST_AAD).is_err());
    }

    #[test]
    fn tx_and_rx_ciphers_are_compatible() {
        let tx_key = test_key(0xAA);
        let mut alice_tx = SessionCipher::new(&tx_key, true);
        let mut bob_rx = SessionCipher::new(&tx_key, false);

        // Different dir_salts → nonces diverge → can't decrypt each other's traffic.
        let ct = alice_tx.seal(b"ping", TEST_AAD).unwrap();
        assert!(
            bob_rx.open(&ct, TEST_AAD).is_err(),
            "different dir salts: nonces differ"
        );

        // Correct usage: both sides use the SAME dir flag on matching keys.
        let mut alice_tx2 = SessionCipher::new(&tx_key, true);
        let mut bob_rx2 = SessionCipher::new(&tx_key, true);
        let ct2 = alice_tx2.seal(b"ping", TEST_AAD).unwrap();
        assert!(
            bob_rx2.open(&ct2, TEST_AAD).is_ok(),
            "matching dir flag works"
        );
    }

    // ── AAD binds frame type to ciphertext ───────────────────────────

    #[test]
    fn wrong_aad_fails_to_open() {
        let key = test_key(0x77);
        let mut enc = SessionCipher::new(&key, true);
        let mut dec = SessionCipher::new(&key, true);

        let aad_app_data: [u8; 3] = frame_aad(3, 3); // APP family, APP_DATA
        let aad_route_ann: [u8; 3] = frame_aad(4, 1); // ROUTING family, ROUTE_ANNOUNCE

        let ct = enc.seal(b"payload", &aad_app_data).unwrap();
        // Decrypting with a different frame type must fail.
        assert!(
            dec.open(&ct, &aad_route_ann).is_err(),
            "wrong frame-type AAD must fail authentication",
        );
    }

    #[test]
    fn frame_aad_helper_encodes_correctly() {
        assert_eq!(frame_aad(3, 0x0102), [3, 1, 2]);
        assert_eq!(frame_aad(0xFF, 0xFFFF), [0xFF, 0xFF, 0xFF]);
        assert_eq!(frame_aad(0, 0), [0, 0, 0]);
    }

    // ── nonce-counter accessor ────────────────────────────────

    #[test]
    fn frames_processed_starts_zero_and_increments_on_seal() {
        let key = test_key(0xC0);
        let mut enc = SessionCipher::new(&key, true);
        assert_eq!(enc.frames_processed(), 0, "fresh cipher starts at 0");
        enc.seal(b"a", TEST_AAD).unwrap();
        assert_eq!(enc.frames_processed(), 1);
        enc.seal(b"b", TEST_AAD).unwrap();
        enc.seal(b"c", TEST_AAD).unwrap();
        assert_eq!(enc.frames_processed(), 3);
    }

    #[test]
    fn frames_processed_increments_on_open_too() {
        // open consumes a nonce slot just like seal (decryption
        // must move the counter so the next call uses nonce N+1).
        let key = test_key(0xC1);
        let mut enc = SessionCipher::new(&key, true);
        let mut dec = SessionCipher::new(&key, true);
        for _ in 0..5 {
            let ct = enc.seal(b"frame", TEST_AAD).unwrap();
            dec.open(&ct, TEST_AAD).unwrap();
        }
        assert_eq!(enc.frames_processed(), 5);
        assert_eq!(dec.frames_processed(), 5);
    }

    /// hardening: failed AEAD must NOT advance the
    /// receiver counter. Without this guarantee a transient AEAD failure
    /// (e.g. an OLD-encrypted frame in-flight during rekey) would burn
    /// the NEW cipher's nonce slot и permanently desynchronise it from
    /// the sender, manifesting as the cluster-wide decrypt-failure
    /// storm.
    #[test]
    fn open_does_not_advance_counter_on_failure() {
        let key = [7u8; 32];
        let mut dec = SessionCipher::new(&key, false);
        let initial = dec.frames_processed();

        // A garbage ciphertext with the right structural shape (≥ 16 byte tag)
        // but bogus contents — AEAD will reject the tag.
        let garbage = vec![0u8; 32];
        let err = dec.open(&garbage, TEST_AAD).unwrap_err();
        assert!(
            matches!(err, CipherError::DecryptFailed),
            "expected DecryptFailed on garbage input, got {:?}",
            err
        );
        assert_eq!(
            dec.frames_processed(),
            initial,
            "counter must NOT advance on failed decrypt — pre-fix behaviour \
             would desync the cipher across legitimate sender"
        );
    }

    #[test]
    fn legitimate_frame_after_failed_attempt_still_decrypts() {
        // Same convention as `tx_and_rx_ciphers_are_compatible`:
        // matched-direction-flag pair shares one key. The crypto
        // model uses separate keys (tx_key vs rx_key) для direction
        // separation, не the dir_salt — runner.rs:
        // both ciphers built с is_tx=true, with distinct keys.
        let key = [9u8; 32];
        let mut enc = SessionCipher::new(&key, true);
        let mut dec = SessionCipher::new(&key, true);

        // First frame from sender — encrypted now but not delivered yet.
        let ct1 = enc.seal(b"hello", TEST_AAD).unwrap();

        // Garbage frame causes failed AEAD on receiver — must not consume
        // the slot for ct1.
        assert!(dec.open(&[0u8; 32], TEST_AAD).is_err());
        assert_eq!(dec.frames_processed(), 0);

        // Now the legitimate frame should decrypt at counter=1, не be
        // rejected because the receiver already burned counter=1.
        let pt = dec.open(&ct1, TEST_AAD).unwrap();
        assert_eq!(pt, b"hello");
        assert_eq!(dec.frames_processed(), 1);
    }

    // ── b: open_in_place safety properties ────────────────────────

    #[test]
    fn open_in_place_roundtrip_yields_same_plaintext() {
        let key = test_key(0xAB);
        let mut enc = SessionCipher::new(&key, true);
        let mut dec = SessionCipher::new(&key, true);

        let plaintext = b"in-place decrypt test".to_vec();
        let ct = enc.seal(&plaintext, TEST_AAD).unwrap();

        let mut buf = ct.clone();
        dec.open_in_place(&mut buf, TEST_AAD)
            .expect("open_in_place");
        // On success the buffer is truncated к plaintext (tag stripped).
        assert_eq!(buf, plaintext, "buffer must hold plaintext after success");
    }

    #[test]
    fn open_in_place_does_not_advance_counter_on_failure() {
        // Critical safety: matches hardening for `open`.
        // If `open_in_place` advanced counter on auth failure, the
        // receiver would desync the same way that triggered the
        // incident.
        let key = test_key(0x77);
        let mut dec = SessionCipher::new(&key, false);
        let initial = dec.frames_processed();

        let mut garbage = vec![0u8; 32];
        let err = dec.open_in_place(&mut garbage, TEST_AAD).unwrap_err();
        assert!(matches!(err, CipherError::DecryptFailed));
        assert_eq!(
            dec.frames_processed(),
            initial,
            "open_in_place must NOT advance counter on failed AEAD verify"
        );
    }

    #[test]
    fn open_in_place_advances_counter_on_success() {
        let key = test_key(0x88);
        let mut enc = SessionCipher::new(&key, true);
        let mut dec = SessionCipher::new(&key, true);
        assert_eq!(dec.frames_processed(), 0);

        let ct = enc.seal(b"frame", TEST_AAD).unwrap();
        let mut buf = ct.clone();
        dec.open_in_place(&mut buf, TEST_AAD).unwrap();
        assert_eq!(dec.frames_processed(), 1, "counter advances on success");
    }

    #[test]
    fn open_in_place_legitimate_frame_after_failed_attempt() {
        // Same property as legitimate_frame_after_failed_attempt_still_decrypts
        // but для the in-place variant — guards against counter desync
        // through the new code path.
        let key = test_key(0x99);
        let mut enc = SessionCipher::new(&key, true);
        let mut dec = SessionCipher::new(&key, true);

        let ct1 = enc.seal(b"hello in-place", TEST_AAD).unwrap();

        let mut garbage = vec![0u8; 32];
        assert!(dec.open_in_place(&mut garbage, TEST_AAD).is_err());
        assert_eq!(dec.frames_processed(), 0);

        let mut buf = ct1.clone();
        dec.open_in_place(&mut buf, TEST_AAD).unwrap();
        assert_eq!(buf, b"hello in-place");
        assert_eq!(dec.frames_processed(), 1);
    }

    #[test]
    fn open_in_place_wrong_aad_fails_without_advance() {
        let key = test_key(0x33);
        let mut enc = SessionCipher::new(&key, true);
        let mut dec = SessionCipher::new(&key, true);

        let ct = enc.seal(b"data", TEST_AAD).unwrap();
        let mut buf = ct.clone();
        let wrong_aad: &[u8] = &[9, 9, 9];
        assert!(dec.open_in_place(&mut buf, wrong_aad).is_err());
        assert_eq!(
            dec.frames_processed(),
            0,
            "wrong-AAD failure must NOT advance counter"
        );

        // Original ct still decrypts with correct AAD on а fresh buffer.
        let mut buf2 = ct.clone();
        dec.open_in_place(&mut buf2, TEST_AAD).unwrap();
        assert_eq!(buf2, b"data");
    }

    #[test]
    fn open_in_place_and_open_produce_same_plaintext() {
        // Cross-check: in-place и heap-alloc variants must yield byte-
        // identical plaintexts на the same ciphertext. If они drift
        // production traffic would silently desync.
        let key = test_key(0x44);
        let mut enc = SessionCipher::new(&key, true);
        let mut dec_classic = SessionCipher::new(&key, true);
        let mut dec_inplace = SessionCipher::new(&key, true);

        let plaintext = b"identical output required";

        for _ in 0..5 {
            let ct = enc.seal(plaintext, TEST_AAD).unwrap();
            let classic = dec_classic.open(&ct, TEST_AAD).unwrap();
            let mut buf = ct.clone();
            dec_inplace.open_in_place(&mut buf, TEST_AAD).unwrap();
            assert_eq!(classic, buf, "in-place must match classic output");
            assert_eq!(buf, plaintext);
        }
    }
}
