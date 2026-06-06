//! E2E-encryption envelope for relay-path messages.
//!
//! When an app message traverses relay nodes, the payload is wrapped in an
//! [`E2eEnvelope`] so that relay nodes cannot read the content.
//!
//! # Marker
//!
//! The first byte of `DeliveryEnvelope.payload` is set [`E2E_MARKER`] (`0xE2`)
//! when the payload is E2E-encrypted. The [`E2eEnvelope`] wire bytes follow
//! immediately at offset 1.
//!
//! # Wire layout (after the 0xE2 marker byte)
//!
//! ```text
//! [0] version u8 = 1
//! [1..3] kem_ct_len u16 BE — always 1088 for ML-KEM-768
//! [3..1091] kem_ciphertext [u8; N] — ML-KEM encapsulated key
//! [1091..1103] nonce [u8; 12] — ChaCha20-Poly1305 nonce
//! [1103..1107] ct_len u32 BE
//! [1107..] ciphertext bytes — ChaCha20-Poly1305 ciphertext + tag
//! ```
//!
//! # Encryption
//!
//! 1. `(kem_ct, shared_secret) = ML-KEM-768.Encaps(recipient_ek)`
//! 2. `key = HKDF-SHA256(shared_secret, info = src_id || dst_id || "ovl1-e2e-v1")[0..32]`
//! 3. `nonce[12] = random`
//! 4. `ciphertext = ChaCha20-Poly1305.Seal(key, nonce, plaintext, aad = src_id || dst_id)`

use super::ProtoError;

/// First byte of `DeliveryEnvelope.payload` when the message is E2E-encrypted.
pub const E2E_MARKER: u8 = 0xE2;

/// First byte of `DeliveryEnvelope.payload` when the message uses the
/// **meta-E2E** (onion) format.
///
/// In meta-E2E mode the sender's `sender_node_id`, `src_app_id`, `app_id`
/// `endpoint_id`, and the actual payload are all encrypted together under the
/// recipient's ML-KEM key. Intermediate relays see only `dst_node_id` and the
/// routing metadata; the sender's identity is hidden until the recipient
/// decrypts.
///
/// The outer `DeliveryEnvelope.sender_node_id` MUST be zero (`[0u8; 32]`) for
/// meta-E2E envelopes — the true sender identity lives inside the ciphertext.
pub const META_E2E_MARKER: u8 = 0xE3;

/// E2E encryption envelope placed inside `DeliveryEnvelope.payload`.
///
/// The full payload stored on wire is `[E2E_MARKER] ++ E2eEnvelope::encode`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2eEnvelope {
    /// ML-KEM ciphertext (encapsulated shared key). 1088 bytes for ML-KEM-768.
    pub kem_ciphertext: Vec<u8>,
    /// ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: [u8; 12],
    /// ChaCha20-Poly1305 ciphertext + 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
}

impl E2eEnvelope {
    /// Minimum encoded size when kem_ciphertext and ciphertext are both empty.
    /// Practical minimum with 1088-byte ML-KEM ciphertext: 1107 bytes.
    pub const HEADER_SIZE: usize = 1   // version
                                 + 2   // kem_ct_len
                                 + 12  // nonce (placed after kem_ct)
                                 + 4; // ct_len

    /// Serialise this envelope to the wire layout:
    /// `version(1) ‖ kem_ct_len(2) ‖ kem_ct ‖ nonce(12) ‖ ct_len(4) ‖ ct`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            Self::HEADER_SIZE + self.kem_ciphertext.len() + self.ciphertext.len(),
        );
        buf.push(1u8); // version
        debug_assert!(
            self.kem_ciphertext.len() <= u16::MAX as usize,
            "E2ePayload: kem_ciphertext exceeds u16::MAX bytes"
        );
        buf.extend_from_slice(&(self.kem_ciphertext.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.kem_ciphertext);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Parse an `E2eEnvelope` from `buf`. Rejects truncated or over-length
    /// inputs with [`ProtoError::BufferTooShort`] / [`ProtoError::BodyTooLarge`];
    /// the version byte is ignored for forward-compat.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        // Minimum: version(1) + kem_ct_len(2) + nonce(12) + ct_len(4) = 19
        const MIN: usize = 19;
        if buf.len() < MIN {
            return Err(ProtoError::BufferTooShort {
                need: MIN,
                got: buf.len(),
            });
        }
        // [0] version — ignored for forward-compat
        let kem_ct_len = super::read_u16_be(buf, 1)? as usize;
        let offset = 3;
        if offset + kem_ct_len > buf.len() {
            return Err(ProtoError::BufferTooShort {
                need: offset + kem_ct_len,
                got: buf.len(),
            });
        }
        let kem_ciphertext = buf[offset..offset + kem_ct_len].to_vec();
        let offset = offset + kem_ct_len;

        if offset + 12 > buf.len() {
            return Err(ProtoError::BufferTooShort {
                need: offset + 12,
                got: buf.len(),
            });
        }
        let nonce: [u8; 12] = super::read_array::<12>(buf, offset)?;
        let offset = offset + 12;

        // checked_add chain defends 32-bit hosts (Android armv7)
        // against ct_len wraparound — bare `+` here would let a u32::MAX-class
        // value pass the bounds check but panic on slicing. Mirrors the
        // relay_chain.rs fix.
        let need_len_field = offset.checked_add(4).ok_or(ProtoError::BufferTooShort {
            need: usize::MAX,
            got: buf.len(),
        })?;
        if need_len_field > buf.len() {
            return Err(ProtoError::BufferTooShort {
                need: need_len_field,
                got: buf.len(),
            });
        }
        let ct_len = super::read_u32_be(buf, offset)? as usize;
        let offset = need_len_field;

        let ct_end = offset
            .checked_add(ct_len)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
        if ct_end > buf.len() {
            return Err(ProtoError::BufferTooShort {
                need: ct_end,
                got: buf.len(),
            });
        }
        let ciphertext = buf[offset..ct_end].to_vec();

        Ok(Self {
            kem_ciphertext,
            nonce,
            ciphertext,
        })
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_envelope(kem_len: usize, ct_len: usize) -> E2eEnvelope {
        E2eEnvelope {
            kem_ciphertext: vec![0xABu8; kem_len],
            nonce: [0x12u8; 12],
            ciphertext: vec![0xCDu8; ct_len],
        }
    }

    #[test]
    fn roundtrip_typical() {
        let env = make_envelope(1088, 64);
        let encoded = env.encode();
        let decoded = E2eEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn roundtrip_zero_lengths() {
        let env = make_envelope(0, 0);
        let decoded = E2eEnvelope::decode(&env.encode()).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn decode_too_short_returns_error() {
        let err = E2eEnvelope::decode(&[0u8; 5]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn decode_truncated_kem_ct_returns_error() {
        let env = make_envelope(100, 32);
        let encoded = env.encode();
        // Truncate inside the kem_ciphertext region
        let err = E2eEnvelope::decode(&encoded[..20]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    #[test]
    fn marker_byte_is_0xe2() {
        assert_eq!(E2E_MARKER, 0xE2);
    }
}
