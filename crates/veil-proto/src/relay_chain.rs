//! Relay chain protocol payloads.
//!
//! A relay chain is a sequence of `N` intermediate relay nodes plus a final
//! destination. The sender builds an **onion-encrypted** payload using
//! `RelayChainBuilder::build`: each relay only sees its own decryption key
//! and the identity of the next hop. Only the final recipient sees the
//! plaintext payload.
//!
//! # Wire format: `RelayChainHop`
//!
//! ```text
//! [0..32] next_hop_node_id [u8; 32] (all-zeros = final destination)
//! [32..36] inner_len u32 BE
//! [36..] inner [u8; inner_len]
//! ```
//!
//! The `inner` bytes are:
//! For **intermediate hops**: XChaCha20-Poly1305-encrypted `RelayChainHop`
//! (next layer), keyed by the ECDH shared secret with that relay.
//! For the **final hop**: XChaCha20-Poly1305-encrypted application payload.
//!
//! # Simplification
//!
//! This implementation uses **symmetric-key** wrapping with pre-shared keys
//! for testability. A production implementation would derive per-hop keys
//! via X25519 ECDH using the relay's long-term public key (analogous to
//! Tor's CREATE/CREATED handshake), but that requires the relay's pubkey at
//! build time and is beyond this epic's scope.

use super::ProtoError;

// ── Wire constants ────────────────────────────────────────────────────────────

/// Sentinel used in `next_hop_node_id` to signal "deliver to the final
/// destination" (i.e., this is the last hop).
pub const FINAL_HOP_SENTINEL: [u8; 32] = [0u8; 32];

// ── RelayChainHop ─────────────────────────────────────────────────────────────

/// A single hop in the relay chain.
///
/// Each relay decrypts its layer to obtain the next `RelayChainHop`, then
/// forwards it toward `next_hop_node_id`. If `next_hop_node_id ==
/// FINAL_HOP_SENTINEL`, the relay delivers `inner` to the local application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayChainHop {
    /// The node_id of the next relay in the chain.
    ///
    /// `FINAL_HOP_SENTINEL` (`[0u8; 32]`) means this is the last hop and
    /// `inner` is the plaintext application payload.
    pub next_hop_node_id: [u8; 32],
    /// The encrypted (or plaintext, for the final hop) inner payload.
    pub inner: Vec<u8>,
}

impl RelayChainHop {
    const FIXED_HEADER: usize = 32 + 4; // next_hop_node_id + inner_len

    /// Is this the final (delivery) hop?
    pub fn is_final(&self) -> bool {
        self.next_hop_node_id == FINAL_HOP_SENTINEL
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED_HEADER + self.inner.len());
        buf.extend_from_slice(&self.next_hop_node_id);
        buf.extend_from_slice(&(self.inner.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.inner);
        buf
    }

    /// Decode from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_HEADER {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_HEADER,
                got: buf.len(),
            });
        }
        let next_hop_node_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let inner_len = super::read_u32_be(buf, 32)? as usize;
        // Per-field cap: the inner payload can't exceed the hard frame body
        // ceiling (the only implicit bound today); make it explicit so the
        // decoder is self-bounding regardless of caller.
        if inner_len > crate::MAX_FRAME_BODY as usize {
            return Err(ProtoError::ValueTooLarge {
                field: "inner_len",
                value: inner_len as u64,
                max: crate::MAX_FRAME_BODY as u64,
            });
        }
        let end = Self::FIXED_HEADER
            .checked_add(inner_len)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
        if buf.len() < end {
            return Err(ProtoError::BufferTooShort {
                need: end,
                got: buf.len(),
            });
        }
        Ok(Self {
            next_hop_node_id,
            inner: buf[Self::FIXED_HEADER..end].to_vec(),
        })
    }
}

// ── ChaCha20-Poly1305 per-hop encryption ─────────────────────────
//
// Each relay layer is AEAD-encrypted with ChaCha20-Poly1305.
// Wire format: [nonce: 12 bytes][ciphertext + 16-byte tag].
// The per-hop key is derived to a 32-byte ChaCha20 key via BLAKE3 keyed
// derivation so that callers can pass arbitrary-length shared secrets.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use rand_core::{OsRng, RngCore};

/// AEAD overhead: 12-byte nonce + 16-byte tag.
pub const LAYER_OVERHEAD: usize = 12 + 16;

/// Derive a 32-byte ChaCha20-Poly1305 key from an arbitrary-length shared
/// secret. Uses BLAKE3 in keyed-derivation mode so that even short keys
/// produce a full-strength 256-bit symmetric key.
fn derive_layer_key(raw_key: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("veil_relay_chain_layer_key");
    h.update(raw_key);
    *h.finalize().as_bytes()
}

/// Encrypt `plaintext` with `key` → `nonce(12) || ciphertext+tag`.
pub fn encrypt_layer(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let dk = derive_layer_key(key);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dk));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .expect("ChaCha20Poly1305 encrypt is infallible for valid inputs");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt `data` (`nonce(12) || ciphertext+tag`) with `key` → plaintext.
///
/// Returns `None` on authentication failure or truncation.
pub fn decrypt_layer(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    if data.len() < LAYER_OVERHEAD {
        return None;
    }
    let dk = derive_layer_key(key);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dk));
    let nonce = Nonce::from_slice(&data[..12]);
    cipher.decrypt(nonce, &data[12..]).ok()
}

// ── RelayChainBuilder ─────────────────────────────────────────────────────────

/// Builds an onion-wrapped relay chain from a list of hops.
///
/// # Usage
///
/// ```ignore
/// // Define hops: each entry is (relay_node_id, per-hop key).
/// // The last entry is the final destination.
/// let chain_frame = RelayChainBuilder::new
///.hop([relay1_id; 32], b"key1")
///.hop([relay2_id; 32], b"key2")
///.destination([dest_id; 32], b"key3", payload_bytes)
///.build;
/// ```
pub struct RelayChainBuilder {
    /// Hops from outermost to innermost: `(next_hop_node_id, per_hop_key)`.
    /// The last entry is the final destination + its key.
    hops: Vec<([u8; 32], Vec<u8>)>,
    /// Plaintext payload delivered to the final destination.
    payload: Vec<u8>,
    /// `next_hop_node_id` of the final destination (the *logical* target).
    dest_node_id: [u8; 32],
}

impl RelayChainBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            hops: Vec::new(),
            payload: Vec::new(),
            dest_node_id: FINAL_HOP_SENTINEL,
        }
    }

    /// Add an intermediate relay hop.
    ///
    /// * `relay_id`: the node_id of this relay.
    /// * `key`: the symmetric key shared with this relay (used to encrypt the
    ///   inner payload at this layer).
    pub fn hop(mut self, relay_id: [u8; 32], key: &[u8]) -> Self {
        self.hops.push((relay_id, key.to_vec()));
        self
    }

    /// Set the final destination.
    ///
    /// * `dest_id`: the node_id of the final recipient.
    /// * `key`: the key shared with the destination (encrypts the plaintext payload).
    /// * `payload`: the application-level plaintext.
    pub fn destination(mut self, dest_id: [u8; 32], key: &[u8], payload: Vec<u8>) -> Self {
        self.dest_node_id = dest_id;
        self.hops.push((dest_id, key.to_vec()));
        self.payload = payload;
        self
    }

    /// Build the outermost `RelayChainHop` frame.
    ///
    /// Onion wrapping semantics — for a 2-relay chain `RELAY1 → RELAY2 → DEST`:
    ///
    /// ```text
    /// dest_layer = {sentinel, payload} ← dest sees this
    /// relay2_layer = {DEST, encrypt(dest_layer_bytes, key_dest)} ← relay2 sees this
    /// relay1_layer = {RELAY2, encrypt(relay2_layer_bytes, key2)} ← relay1 sees this
    /// outermost = {RELAY1, encrypt(relay1_layer_bytes, key1)} ← sender sends this
    /// ```
    ///
    /// Each `process_hop(current_layer, current_key)` decrypts `current_layer.inner`
    /// and decodes the result as the next inner `RelayChainHop`.
    pub fn build(self) -> Option<RelayChainHop> {
        if self.hops.is_empty() {
            return None;
        }
        let n = self.hops.len();

        // Step 1: The innermost layer is {sentinel, payload} — what the destination
        // will decode after decrypting with its key.
        let mut current_bytes = RelayChainHop {
            next_hop_node_id: FINAL_HOP_SENTINEL,
            inner: self.payload.clone(),
        }
        .encode();

        // Step 2: Wrap from inside-out. For each hop going from the destination
        // (i = n-1) back toward the first relay (i = 0):
        // Encrypt `current_bytes` with hops[i].key (this hop's shared key).
        // Wrap in a new RelayChainHop whose `next_hop_node_id` = hops[i].node_id
        // (tells the *previous* relay where to route this layer).
        //
        // hops[n-1] = (dest_id, key_dest)
        // hops[n-2] = (relay_closest_to_dest, key_relay_n_2)
        //...
        // hops[0] = (first_relay, key1)
        //
        // The final outermost hop's `next_hop_node_id` = hops[0].node_id.
        for i in (0..n).rev() {
            let (node_id, key) = &self.hops[i];
            let encrypted = encrypt_layer(&current_bytes, key);
            let layer = RelayChainHop {
                next_hop_node_id: *node_id,
                inner: encrypted,
            };
            current_bytes = layer.encode();
        }

        RelayChainHop::decode(&current_bytes).ok()
    }
}

impl Default for RelayChainBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Hop processor ─────────────────────────────────────────────────────────────

/// Process a received `RelayChainHop` at a relay node.
///
/// Given the relay's `key`, decrypt the inner layer and decode the next hop.
///
/// Returns:
/// * `Ok((next_hop, inner_hop))` — forward `inner_hop` to `next_hop`.
/// * `Err(_)` — decoding failed; drop the frame.
pub fn process_hop(hop: &RelayChainHop, key: &[u8]) -> Result<RelayChainHop, ProtoError> {
    let decrypted = decrypt_layer(&hop.inner, key).ok_or(ProtoError::DecryptionFailed)?;
    RelayChainHop::decode(&decrypted)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY1: [u8; 32] = [0x01u8; 32];
    const RELAY2: [u8; 32] = [0x02u8; 32];
    const DEST: [u8; 32] = [0x03u8; 32];

    #[test]
    fn relay_chain_hop_roundtrip() {
        let hop = RelayChainHop {
            next_hop_node_id: RELAY1,
            inner: b"hello world".to_vec(),
        };
        let decoded = RelayChainHop::decode(&hop.encode()).unwrap();
        assert_eq!(decoded, hop);
    }

    #[test]
    fn final_hop_sentinel_detected() {
        let hop = RelayChainHop {
            next_hop_node_id: FINAL_HOP_SENTINEL,
            inner: b"payload".to_vec(),
        };
        assert!(hop.is_final());
    }

    #[test]
    fn non_final_hop_not_sentinel() {
        let hop = RelayChainHop {
            next_hop_node_id: RELAY1,
            inner: vec![],
        };
        assert!(!hop.is_final());
    }

    #[test]
    fn hop_too_short_returns_error() {
        assert!(RelayChainHop::decode(&[0u8; 10]).is_err());
    }

    // ── 2-hop relay chain ────────────────────────────────────────

    /// Sender builds a 2-hop chain: Relay1 → Relay2 → Dest.
    /// Each relay processes its hop with its key. The final recipient
    /// receives the plaintext payload.
    #[test]
    fn relay_chain_2hop_end_to_end() {
        let payload = b"secret message".to_vec();
        let key1 = b"relay1-key";
        let key2 = b"relay2-key";
        let key_dest = b"dest-key";

        // Sender builds the chain.
        let outermost = RelayChainBuilder::new()
            .hop(RELAY1, key1)
            .hop(RELAY2, key2)
            .destination(DEST, key_dest, payload.clone())
            .build()
            .expect("build must succeed");

        // Relay1 processes its hop.
        let relay1_inner = process_hop(&outermost, key1).expect("relay1 must decrypt");
        assert_eq!(
            relay1_inner.next_hop_node_id, RELAY2,
            "relay1 must forward to relay2"
        );
        assert!(!relay1_inner.is_final());

        // Relay2 processes its hop.
        let relay2_inner = process_hop(&relay1_inner, key2).expect("relay2 must decrypt");
        assert_eq!(
            relay2_inner.next_hop_node_id, DEST,
            "relay2 must forward to dest"
        );
        assert!(!relay2_inner.is_final());

        // Destination processes its hop (final layer).
        let final_hop = process_hop(&relay2_inner, key_dest).expect("dest must decrypt");
        assert!(final_hop.is_final(), "dest must see final sentinel");

        // The decrypted inner is the plaintext payload.
        assert_eq!(
            final_hop.inner, payload,
            "dest must recover plaintext payload"
        );
    }

    #[test]
    fn direct_destination_no_relays() {
        let payload = b"direct".to_vec();
        let key_dest = b"dkey";

        // When there are no intermediate relays, the sender creates one layer:
        // outermost = {DEST, encrypt({sentinel, payload}.bytes, key_dest)}
        // The destination calls process_hop and recovers {sentinel, payload}.
        let outermost = RelayChainBuilder::new()
            .destination(DEST, key_dest, payload.clone())
            .build()
            .expect("build must succeed");

        assert_eq!(
            outermost.next_hop_node_id, DEST,
            "direct hop must route to DEST"
        );

        // Dest decrypts its layer.
        let final_hop = process_hop(&outermost, key_dest).expect("dest must decrypt");
        assert!(final_hop.is_final(), "decoded layer must be final hop");
        assert_eq!(
            final_hop.inner, payload,
            "dest must recover plaintext payload"
        );
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plain = b"test payload 12345";
        let key = b"secret";
        let ct = encrypt_layer(plain, key);
        assert_ne!(&ct[12..], plain, "ciphertext must differ from plaintext");
        let pt = decrypt_layer(&ct, key).expect("decrypt must succeed");
        assert_eq!(pt, plain);
    }

    #[test]
    fn wrong_key_returns_none() {
        let ct = encrypt_layer(b"secret data", b"key1");
        assert!(
            decrypt_layer(&ct, b"key2").is_none(),
            "wrong key must fail auth"
        );
    }

    #[test]
    fn tampered_ciphertext_returns_none() {
        let mut ct = encrypt_layer(b"secret data", b"key1");
        *ct.last_mut().unwrap() ^= 0xFF;
        assert!(
            decrypt_layer(&ct, b"key1").is_none(),
            "tampered data must fail auth"
        );
    }

    /// Intermediate relay cannot read the payload — it only sees AEAD ciphertext
    /// that fails authentication with the wrong key.
    #[test]
    fn relay_cannot_read_inner_payload() {
        let payload = b"top secret message".to_vec();
        let key1 = b"relay1-key";
        let key_dest = b"dest-key";
        let wrong_key = b"attacker-key";

        let outermost = RelayChainBuilder::new()
            .hop(RELAY1, key1)
            .destination(DEST, key_dest, payload.clone())
            .build()
            .expect("build must succeed");

        // Relay1 decrypts its layer correctly.
        let relay1_inner = process_hop(&outermost, key1).expect("relay1 must decrypt");
        // But relay1 cannot decrypt the next layer (dest's layer) — wrong key.
        assert!(
            process_hop(&relay1_inner, wrong_key).is_err(),
            "relay must not be able to decrypt dest's layer with a wrong key"
        );
        // The raw inner bytes of relay1_inner do not contain the plaintext.
        assert!(
            !relay1_inner
                .inner
                .windows(payload.len())
                .any(|w| w == payload.as_slice()),
            "plaintext must not be visible in the encrypted inner"
        );
    }
}
