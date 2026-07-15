//! Pairing-ceremony session wire frames.
//!
//! After the source has published a [`PairingInvite`] and displayed
//! its QR + endpoint, the target dials the endpoint and runs a
//! three-frame ceremony over the direct session:
//!
//! ```text
//! target ── Hello ──▶ source (target_ek_pk, target_id_pk, target_instance_id, MAC(pair_secret))
//! target ◀── Cert ── source (source_ek_pk, updated IdentityDocument with master-cert for target_id_pk)
//! target ── Confirm ──▶ source (session-key proof + user's OOB-compare bit)
//! ```
//!
//! The MAC on Hello proves target holds the raw `pair_secret` (which
//! is never sent in clear — it was the `secret` URL param of the QR
//! and the source has only the hash). The Confirm's proof binds
//! the channel to the X25519-derived session key, foiling a MITM
//! who couldn't compute it.
//!
//! These frames do **no** crypto by themselves — they're pure
//! encode/decode containers with magic + version + length guards.
//! The state machines [`veilcore::node::identity::pair_runtime`]
//! drive the ceremony and populate / validate the crypto fields.
//!
//! # Size budget
//!
//! [`PairingHello`] is fixed 147 B.
//! [`PairingCert`] is variable (header + encoded document); we
//! hard-cap at [`MAX_PAIR_CERT_SIZE`] (8 KiB) to match the
//! document's own 4 KiB ceiling plus encoder overhead.
//! [`PairingConfirm`] is fixed 37 B.

use crate::ProtoError;

// ── Magic + versions ─────────────────────────────────────────────────────────

/// Hello: target → source.
pub const PAIR_HELLO_MAGIC: [u8; 2] = *b"PH";
/// Cert: source → target.
pub const PAIR_CERT_MAGIC: [u8; 2] = *b"PC";
/// Confirm: target → source (final).
pub const PAIR_CONFIRM_MAGIC: [u8; 2] = *b"PF";

pub const PAIR_HELLO_V1: u8 = 1;
pub const PAIR_CERT_V1: u8 = 1;
pub const PAIR_CONFIRM_V1: u8 = 1;

/// Domain tag mixed into the Hello MAC. Keeps the `pair_secret`
/// from accidentally signing any other veil payload shape.
pub const PAIR_HELLO_MAC_CONTEXT: &[u8] = b"veil.pair.hello.mac.v1";

/// Domain tag mixed into the Confirm proof. Binds the proof to the
/// pairing ceremony specifically.
pub const PAIR_CONFIRM_PROOF_CONTEXT: &[u8] = b"veil.pair.confirm.proof.v1";

/// Size of the signed document blob the Cert carries must not
/// exceed this ceiling — 8 KiB is ample headroom over the
/// `IdentityDocument`'s own 4 KiB cap and guards decoder memory
/// without imposing a hard post-8-subkey ceiling.
pub const MAX_PAIR_CERT_DOC_SIZE: usize = 8 * 1024;

/// Full-frame cap for Hello (includes all fixed fields).
pub const PAIR_HELLO_SIZE: usize = 2 + 1 + 32 + 32 + 32 + 16 + 32;

/// Full-frame cap for Confirm (includes all fixed fields).
pub const PAIR_CONFIRM_SIZE: usize = 2 + 1 + 1 + 32;

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PairSessionError {
    #[error("pair frame: wrong magic (got 0x{0:02x}{1:02x})")]
    BadMagic(u8, u8),
    #[error("pair frame: unsupported version {0}")]
    BadVersion(u8),
    #[error("pair frame: truncated (expected ≥{expected} B, got {got})")]
    Truncated { expected: usize, got: usize },
    #[error("pair frame: trailing data (consumed {consumed} B, got {got})")]
    TrailingData { consumed: usize, got: usize },
    #[error("pair cert: document blob oversized ({got} B > {MAX_PAIR_CERT_DOC_SIZE} B)")]
    DocOversized { got: usize },
    #[error("pair confirm: confirmed byte must be 0 or 1, got {0}")]
    BadConfirmedByte(u8),
}

impl From<PairSessionError> for ProtoError {
    fn from(e: PairSessionError) -> ProtoError {
        ProtoError::Malformed(e.to_string())
    }
}

// ── Hello ────────────────────────────────────────────────────────────────────

/// Target → Source opener. Proves target holds the raw
/// `pair_secret` (via the MAC) and hands over the ephemeral +
/// identity public keys the source needs to compute the session
/// key and build the master certification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingHello {
    /// `BLAKE3(PAIR_SECRET_HASH_CONTEXT || pair_secret)` — lets
    /// source correlate which pending invite this Hello belongs to
    /// without scanning the cleartext `pair_secret` off the wire.
    pub pair_secret_hash: [u8; 32],
    /// Target's ephemeral X25519 pub. Fresh per ceremony.
    pub target_ephemeral_x25519_pk: [u8; 32],
    /// Target's fresh Ed25519 pub that will become its
    /// `identity_sk` subkey under the source's identity (set as
    /// `IdentityKey.pubkey` once master-certified).
    pub target_identity_pk: [u8; 32],
    /// Target's fresh 16-byte per-device tag.
    pub target_instance_id: [u8; 16],
    /// `BLAKE3_keyed(pair_secret, MAC_CONTEXT || prior_bytes)`.
    /// The key is the raw `pair_secret` held by the target — an
    /// attacker without `pair_secret` cannot forge this.
    pub mac: [u8; 32],
}

impl PairingHello {
    /// Bytes the MAC is computed over — everything in the frame
    /// *before* the MAC field. Exposed so the state machine can
    /// both produce and verify without duplicating layout.
    pub fn mac_input(
        pair_secret_hash: &[u8; 32],
        target_ephemeral_x25519_pk: &[u8; 32],
        target_identity_pk: &[u8; 32],
        target_instance_id: &[u8; 16],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAIR_HELLO_MAC_CONTEXT.len() + 32 + 32 + 32 + 16);
        out.extend_from_slice(PAIR_HELLO_MAC_CONTEXT);
        out.extend_from_slice(pair_secret_hash);
        out.extend_from_slice(target_ephemeral_x25519_pk);
        out.extend_from_slice(target_identity_pk);
        out.extend_from_slice(target_instance_id);
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAIR_HELLO_SIZE);
        out.extend_from_slice(&PAIR_HELLO_MAGIC);
        out.push(PAIR_HELLO_V1);
        out.extend_from_slice(&self.pair_secret_hash);
        out.extend_from_slice(&self.target_ephemeral_x25519_pk);
        out.extend_from_slice(&self.target_identity_pk);
        out.extend_from_slice(&self.target_instance_id);
        out.extend_from_slice(&self.mac);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PairSessionError> {
        if bytes.len() < PAIR_HELLO_SIZE {
            return Err(PairSessionError::Truncated {
                expected: PAIR_HELLO_SIZE,
                got: bytes.len(),
            });
        }
        if bytes.len() > PAIR_HELLO_SIZE {
            return Err(PairSessionError::TrailingData {
                consumed: PAIR_HELLO_SIZE,
                got: bytes.len(),
            });
        }
        if bytes[0..2] != PAIR_HELLO_MAGIC {
            return Err(PairSessionError::BadMagic(bytes[0], bytes[1]));
        }
        if bytes[2] != PAIR_HELLO_V1 {
            return Err(PairSessionError::BadVersion(bytes[2]));
        }
        let mut pair_secret_hash = [0u8; 32];
        let mut tek = [0u8; 32];
        let mut tid = [0u8; 32];
        let mut instance = [0u8; 16];
        let mut mac = [0u8; 32];
        pair_secret_hash.copy_from_slice(&bytes[3..35]);
        tek.copy_from_slice(&bytes[35..67]);
        tid.copy_from_slice(&bytes[67..99]);
        instance.copy_from_slice(&bytes[99..115]);
        mac.copy_from_slice(&bytes[115..147]);
        Ok(PairingHello {
            pair_secret_hash,
            target_ephemeral_x25519_pk: tek,
            target_identity_pk: tid,
            target_instance_id: instance,
            mac,
        })
    }
}

// ── Cert ─────────────────────────────────────────────────────────────────────

/// Source → Target reply. Delivers the updated identity document
/// with `target_identity_pk` already appended as a new
/// master-certified `IdentityKey`, plus the source's ephemeral
/// X25519 pub so target can finish the session-key DH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCert {
    pub source_ephemeral_x25519_pk: [u8; 32],
    /// Encoded [`IdentityDocument`] carrying the freshly-appended
    /// target `IdentityKey` + bumped `document_version`. The
    /// full document is shipped (not a delta) so target can verify
    /// the cert chain from scratch.
    pub signed_document: Vec<u8>,
}

impl PairingCert {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + 32 + 4 + self.signed_document.len());
        out.extend_from_slice(&PAIR_CERT_MAGIC);
        out.push(PAIR_CERT_V1);
        out.extend_from_slice(&self.source_ephemeral_x25519_pk);
        out.extend_from_slice(&(self.signed_document.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.signed_document);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PairSessionError> {
        const HEADER: usize = 2 + 1 + 32 + 4;
        if bytes.len() < HEADER {
            return Err(PairSessionError::Truncated {
                expected: HEADER,
                got: bytes.len(),
            });
        }
        if bytes[0..2] != PAIR_CERT_MAGIC {
            return Err(PairSessionError::BadMagic(bytes[0], bytes[1]));
        }
        if bytes[2] != PAIR_CERT_V1 {
            return Err(PairSessionError::BadVersion(bytes[2]));
        }
        let mut sek = [0u8; 32];
        sek.copy_from_slice(&bytes[3..35]);
        let doc_len = u32::from_be_bytes([bytes[35], bytes[36], bytes[37], bytes[38]]) as usize;
        if doc_len > MAX_PAIR_CERT_DOC_SIZE {
            return Err(PairSessionError::DocOversized { got: doc_len });
        }
        let expected = HEADER + doc_len;
        if bytes.len() < expected {
            return Err(PairSessionError::Truncated {
                expected,
                got: bytes.len(),
            });
        }
        if bytes.len() > expected {
            return Err(PairSessionError::TrailingData {
                consumed: expected,
                got: bytes.len(),
            });
        }
        Ok(PairingCert {
            source_ephemeral_x25519_pk: sek,
            signed_document: bytes[HEADER..expected].to_vec(),
        })
    }
}

// ── Confirm ──────────────────────────────────────────────────────────────────

/// Target → Source final frame. Delivers the user's OOB-compare
/// decision (bit) plus a session-key-keyed proof that binds this
/// confirmation to the post-DH shared secret (so a MITM who spoofed
/// the channel can't forge a "user pressed OK" ack).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingConfirm {
    /// User's verdict from the OOB compare: `true` = codes matched
    /// and user pressed confirm, `false` = user aborted.
    pub confirmed: bool,
    /// `BLAKE3_keyed(session_key, PROOF_CONTEXT || confirmed_byte)`.
    pub proof: [u8; 32],
}

impl PairingConfirm {
    /// Bytes the proof is computed over. Exposed so both sides
    /// can recompute without duplicating layout.
    pub fn proof_input(confirmed: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAIR_CONFIRM_PROOF_CONTEXT.len() + 1);
        out.extend_from_slice(PAIR_CONFIRM_PROOF_CONTEXT);
        out.push(u8::from(confirmed));
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAIR_CONFIRM_SIZE);
        out.extend_from_slice(&PAIR_CONFIRM_MAGIC);
        out.push(PAIR_CONFIRM_V1);
        out.push(u8::from(self.confirmed));
        out.extend_from_slice(&self.proof);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PairSessionError> {
        if bytes.len() < PAIR_CONFIRM_SIZE {
            return Err(PairSessionError::Truncated {
                expected: PAIR_CONFIRM_SIZE,
                got: bytes.len(),
            });
        }
        if bytes.len() > PAIR_CONFIRM_SIZE {
            return Err(PairSessionError::TrailingData {
                consumed: PAIR_CONFIRM_SIZE,
                got: bytes.len(),
            });
        }
        if bytes[0..2] != PAIR_CONFIRM_MAGIC {
            return Err(PairSessionError::BadMagic(bytes[0], bytes[1]));
        }
        if bytes[2] != PAIR_CONFIRM_V1 {
            return Err(PairSessionError::BadVersion(bytes[2]));
        }
        let confirmed = match bytes[3] {
            0 => false,
            1 => true,
            other => return Err(PairSessionError::BadConfirmedByte(other)),
        };
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&bytes[4..36]);
        Ok(PairingConfirm { confirmed, proof })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hello() -> PairingHello {
        PairingHello {
            pair_secret_hash: [0x11; 32],
            target_ephemeral_x25519_pk: [0x22; 32],
            target_identity_pk: [0x33; 32],
            target_instance_id: [0x44; 16],
            mac: [0x55; 32],
        }
    }

    fn sample_cert(doc_len: usize) -> PairingCert {
        PairingCert {
            source_ephemeral_x25519_pk: [0x66; 32],
            signed_document: vec![0xAA; doc_len],
        }
    }

    fn sample_confirm(confirmed: bool) -> PairingConfirm {
        PairingConfirm {
            confirmed,
            proof: [0x77; 32],
        }
    }

    // Hello ------------------------------------------------------------------

    #[test]
    fn hello_round_trip() {
        let h = sample_hello();
        let bytes = h.encode();
        assert_eq!(bytes.len(), PAIR_HELLO_SIZE);
        assert_eq!(&bytes[0..2], &PAIR_HELLO_MAGIC);
        assert_eq!(bytes[2], PAIR_HELLO_V1);
        assert_eq!(PairingHello::decode(&bytes).unwrap(), h);
    }

    #[test]
    fn hello_mac_input_includes_context_and_all_fields() {
        let h = sample_hello();
        let input = PairingHello::mac_input(
            &h.pair_secret_hash,
            &h.target_ephemeral_x25519_pk,
            &h.target_identity_pk,
            &h.target_instance_id,
        );
        assert!(input.starts_with(PAIR_HELLO_MAC_CONTEXT));
        // Context + 32 + 32 + 32 + 16
        assert_eq!(
            input.len(),
            PAIR_HELLO_MAC_CONTEXT.len() + 32 + 32 + 32 + 16
        );
    }

    #[test]
    fn hello_rejects_bad_magic() {
        let mut bytes = sample_hello().encode();
        bytes[0] = b'X';
        assert!(matches!(
            PairingHello::decode(&bytes),
            Err(PairSessionError::BadMagic(b'X', b'H'))
        ));
    }

    #[test]
    fn hello_rejects_bad_version() {
        let mut bytes = sample_hello().encode();
        bytes[2] = 99;
        assert!(matches!(
            PairingHello::decode(&bytes),
            Err(PairSessionError::BadVersion(99))
        ));
    }

    #[test]
    fn hello_rejects_truncation() {
        let bytes = sample_hello().encode();
        let got = bytes.len() - 1;
        assert!(matches!(
            PairingHello::decode(&bytes[..got]),
            Err(PairSessionError::Truncated {
                expected: PAIR_HELLO_SIZE,
                ..
            })
        ));
    }

    #[test]
    fn hello_rejects_trailing() {
        let mut bytes = sample_hello().encode();
        bytes.push(0);
        assert!(matches!(
            PairingHello::decode(&bytes),
            Err(PairSessionError::TrailingData { .. })
        ));
    }

    // Cert -------------------------------------------------------------------

    #[test]
    fn cert_round_trip() {
        let c = sample_cert(512);
        let bytes = c.encode();
        assert_eq!(&bytes[0..2], &PAIR_CERT_MAGIC);
        assert_eq!(PairingCert::decode(&bytes).unwrap(), c);
    }

    #[test]
    fn cert_round_trip_empty_doc() {
        let c = sample_cert(0);
        let bytes = c.encode();
        assert_eq!(PairingCert::decode(&bytes).unwrap(), c);
    }

    #[test]
    fn cert_rejects_bad_magic() {
        let mut bytes = sample_cert(16).encode();
        bytes[1] = b'X';
        assert!(matches!(
            PairingCert::decode(&bytes),
            Err(PairSessionError::BadMagic(b'P', b'X'))
        ));
    }

    #[test]
    fn cert_rejects_bad_version() {
        let mut bytes = sample_cert(16).encode();
        bytes[2] = 99;
        assert!(matches!(
            PairingCert::decode(&bytes),
            Err(PairSessionError::BadVersion(99))
        ));
    }

    #[test]
    fn cert_rejects_truncation_in_header() {
        let bytes = sample_cert(16).encode();
        assert!(matches!(
            PairingCert::decode(&bytes[..10]),
            Err(PairSessionError::Truncated { .. })
        ));
    }

    #[test]
    fn cert_rejects_truncation_in_doc() {
        let bytes = sample_cert(64).encode();
        assert!(matches!(
            PairingCert::decode(&bytes[..bytes.len() - 1]),
            Err(PairSessionError::Truncated { .. })
        ));
    }

    #[test]
    fn cert_rejects_trailing_data() {
        let mut bytes = sample_cert(16).encode();
        bytes.push(0);
        assert!(matches!(
            PairingCert::decode(&bytes),
            Err(PairSessionError::TrailingData { .. })
        ));
    }

    #[test]
    fn cert_rejects_oversized_doc_len_header() {
        // Fabricate a header with doc_len > MAX cap, then truncate
        // so we hit the length guard before the bytes-missing check.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PAIR_CERT_MAGIC);
        bytes.push(PAIR_CERT_V1);
        bytes.extend_from_slice(&[0x66u8; 32]);
        let bogus_len = (MAX_PAIR_CERT_DOC_SIZE + 1) as u32;
        bytes.extend_from_slice(&bogus_len.to_be_bytes());
        assert!(matches!(
            PairingCert::decode(&bytes),
            Err(PairSessionError::DocOversized { .. })
        ));
    }

    // Confirm ----------------------------------------------------------------

    #[test]
    fn confirm_round_trip_true() {
        let c = sample_confirm(true);
        let bytes = c.encode();
        assert_eq!(bytes.len(), PAIR_CONFIRM_SIZE);
        assert_eq!(PairingConfirm::decode(&bytes).unwrap(), c);
    }

    #[test]
    fn confirm_round_trip_false() {
        let c = sample_confirm(false);
        let bytes = c.encode();
        assert_eq!(PairingConfirm::decode(&bytes).unwrap(), c);
    }

    #[test]
    fn confirm_rejects_bad_magic() {
        let mut bytes = sample_confirm(true).encode();
        bytes[0] = b'X';
        assert!(matches!(
            PairingConfirm::decode(&bytes),
            Err(PairSessionError::BadMagic(b'X', b'F'))
        ));
    }

    #[test]
    fn confirm_rejects_bad_version() {
        let mut bytes = sample_confirm(true).encode();
        bytes[2] = 9;
        assert!(matches!(
            PairingConfirm::decode(&bytes),
            Err(PairSessionError::BadVersion(9))
        ));
    }

    #[test]
    fn confirm_rejects_bad_confirmed_byte() {
        let mut bytes = sample_confirm(true).encode();
        bytes[3] = 42;
        assert!(matches!(
            PairingConfirm::decode(&bytes),
            Err(PairSessionError::BadConfirmedByte(42))
        ));
    }

    #[test]
    fn confirm_rejects_truncation() {
        let bytes = sample_confirm(true).encode();
        assert!(matches!(
            PairingConfirm::decode(&bytes[..bytes.len() - 1]),
            Err(PairSessionError::Truncated { .. })
        ));
    }

    #[test]
    fn confirm_rejects_trailing() {
        let mut bytes = sample_confirm(true).encode();
        bytes.push(0);
        assert!(matches!(
            PairingConfirm::decode(&bytes),
            Err(PairSessionError::TrailingData { .. })
        ));
    }

    #[test]
    fn confirm_proof_input_includes_context_and_byte() {
        let input = PairingConfirm::proof_input(true);
        assert!(input.starts_with(PAIR_CONFIRM_PROOF_CONTEXT));
        assert_eq!(*input.last().unwrap(), 1);
        let input_false = PairingConfirm::proof_input(false);
        assert_eq!(*input_false.last().unwrap(), 0);
    }

    #[test]
    fn proof_inputs_differ_between_true_and_false() {
        // Same `session_key` must produce different proofs for
        // `confirmed=true` vs `false`; the proof-input bytes MUST
        // differ for that to be true.
        assert_ne!(
            PairingConfirm::proof_input(true),
            PairingConfirm::proof_input(false),
        );
    }
}
