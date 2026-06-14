//! In-handshake sovereign-identity proof payload.
//!
//! A peer presents an `IdentityProof` during the OVL1 handshake so its
//! counterpart can verify — **without** any DHT round-trip — that:
//!
//! 1. The peer owns the `identity_sk` matching the `identity_pubkey`
//! (the peer signs the session's X25519 ephemeral pk with it →
//! anti-MITM binding).
//! 2. `identity_pubkey` is master-certified under `node_id` (the
//! inline `master_sig` covers the same message shape that
//! [`IdentityKey::certify_message`] produces in the full document).
//! 3. `node_id == BLAKE3(master_pubkey_bytes)` — so the binding
//! chain is `node_id → master_pk → identity_pk → ephemeral_pk`.
//!
//! Revocation is replaced by short cert validity:
//! `key_valid_until_unix` defaults to `DELEGATION_VALIDITY_SECS`
//! (7 days) and the master re-issues at half-validity. A stale cert
//! is rejected by the verifier; a leaked subkey ages out within
//! ≤ 7 days even with no in-band revocation channel.
//!
//! Wire layout:
//!
//! ```text
//! [0..2] magic b"IP"
//! [2] version u8 (=1)
//! [3..35] node_id [u8; 32]
//!
//! # Master section — enough for the receiver to verify the inline cert.
//! [35] master_algo u8
//! [36..38] master_pk_len u16 BE
//! [..] master_pubkey bytes
//!
//! # Inline identity subkey (single active one — enough for handshake
//! # auth; the full document is fetched lazily if needed).
//! [..] identity_algo u8
//! [..] identity_pk_len u16 BE
//! [..] identity_pubkey bytes
//! [..] device_id [u8; 32]
//! [..] key_valid_from_unix u64 BE
//! [..] key_valid_until_unix u64 BE
//! [..] master_sig_len u16 BE
//! [..] master_sig bytes (master_sk.sign(certify_message))
//!
//! # Proof validity window + replay guard.
//! [..] proof_valid_until_unix u64 BE
//! [..] freshness_hour u32 BE (within FRESHNESS_HOUR_SKEW
//! of now/3600)
//!
//! # Anti-MITM: identity_sk binds the session's X25519 ephemeral pk.
//! [..] ephemeral_x25519_pk [u8; 32]
//! [..] ephemeral_sig_len u16 BE
//! [..] ephemeral_sig bytes
//! ```
//!
//! The inner `master_sig` covers the exact same bytes that
//! [`IdentityKey::certify_message`] produces in a full
//! [`IdentityDocument`], so a peer that already has the document can
//! cross-check consistency.
//!
//! The inner `ephemeral_sig` covers:
//!
//! ```text
//! EPHEMERAL_SIG_CONTEXT
//! || node_id
//! || proof_valid_until_unix (u64 BE)
//! || ephemeral_x25519_pk (32 B)
//! ```
//!
//! which binds the ephemeral key to this specific identity *and* to a
//! bounded time window — a harvested proof cannot be replayed onto a
//! different session or after expiry.
//!
//! [`IdentityKey::certify_message`]: super::identity_document::IdentityKey::certify_message
//! [`IdentityDocument`]: super::identity_document::IdentityDocument

use super::ProtoError;
use super::cursor::{read_array, read_bytes, read_u8, read_u16, read_u32, read_u64};

// ── Constants ────────────────────────────────────────────────────────────────

pub const IDENTITY_PROOF_MAGIC: [u8; 2] = [b'I', b'P'];
pub const IDENTITY_PROOF_V1: u8 = 1;

/// Context prefix the identity_sk signs along with the ephemeral pk.
pub const EPHEMERAL_SIG_CONTEXT: &[u8] = b"veil.identity_proof.ephemeral.v1";

/// Hard upper bound on a single `IdentityProof` wire payload. Covers
/// Falcon-sized sigs on both master and identity + the usual per-field
/// headers with ample headroom for future algorithm upgrades.
/// A 1024-hybrid proof carries master_pubkey 1825 B + master_sig ~1528 B +
/// the active subkey + ephemeral sig ⇒ ~3.6 KiB. 8 KiB keeps the "ample
/// headroom" promise for the largest algorithm; the proof is a handshake
/// frame (not DHT-stored), bounded well under `ipc::MAX_PAIR_CEREMONY_BYTES`.
pub const MAX_IDENTITY_PROOF_BYTES: usize = 8 * 1024;

/// Maximum single-pubkey length accepted at the structural layer.
/// Falcon-512 hybrid pubkeys are 929 B; Ed25519+Falcon-1024 hybrid is
/// 1825 B. 2048 covers the largest with headroom.
const MAX_PUBKEY_BYTES: usize = 2048;

/// Maximum single-signature length. Falcon-512 hybrid sigs are ~754 B;
/// Ed25519+Falcon-1024 hybrid is ~1528 B. 2048 fits the largest + headroom
/// without creating a DoS vector.
const MAX_SIG_BYTES: usize = 2048;

// ── Struct ───────────────────────────────────────────────────────────────────

/// Self-contained OVL1 handshake identity proof.
///
/// Build via `sign_identity_proof` in the publish-side library;
/// verify via `verify_identity_proof` in the identity verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProof {
    /// Stable 32-byte identity address (must equal
    /// `BLAKE3(master_pubkey)` — verifier checks).
    pub node_id: [u8; 32],

    /// Master public key algorithm byte (mirrors `ALGO_ED25519` /
    /// `ALGO_FALCON512`).
    pub master_algo: u8,
    /// Master public key bytes. The binding
    /// `node_id == BLAKE3(master_pubkey)` is enforced by the
    /// verifier.
    pub master_pubkey: Vec<u8>,

    /// Subkey algorithm byte.
    pub identity_algo: u8,
    /// Active identity subkey used to sign the ephemeral pk.
    pub identity_pubkey: Vec<u8>,
    /// Deterministic device address `BLAKE3(identity_pubkey)`.
    /// Verifier rejects the proof if this binding does not hold.
    pub device_id: [u8; 32],
    /// When the subkey first became valid (mirrors the `IdentityKey`
    /// field in the full document).
    pub key_valid_from_unix: u64,
    /// Upper bound of the master delegation's validity window. After
    /// this timestamp the verifier rejects the cert chain regardless
    /// of `proof_valid_until_unix`. Mirrors `IdentityKey.valid_until_unix`.
    pub key_valid_until_unix: u64,
    /// Master signature over the standard `IdentityKey` certify
    /// message — lets the peer verify the cert chain inline.
    pub master_sig: Vec<u8>,

    /// Upper bound of this proof's own validity window (set by signer
    /// — typically `now + a few minutes`). After this timestamp, the
    /// proof is rejected regardless of cert-chain validity.
    pub proof_valid_until_unix: u64,
    /// Replay-guard: hour bucket asserted by the signer (verifier
    /// requires it to lie within `±FRESHNESS_HOUR_SKEW` of `now/3600`).
    pub freshness_hour: u32,

    /// Session X25519 ephemeral pk that the `identity_sk` signs. The
    /// peer uses this to confirm the ephemeral pk observed in the
    /// handshake transcript belongs to the claimed identity.
    pub ephemeral_x25519_pk: [u8; 32],
    /// Identity signature over `EPHEMERAL_SIG_CONTEXT || node_id
    /// || proof_valid_until_unix || ephemeral_x25519_pk`.
    pub ephemeral_sig: Vec<u8>,
}

impl IdentityProof {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&IDENTITY_PROOF_MAGIC);
        out.push(IDENTITY_PROOF_V1);
        out.extend_from_slice(&self.node_id);

        // Master section.
        out.push(self.master_algo);
        out.extend_from_slice(&(self.master_pubkey.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.master_pubkey);

        // Inline identity subkey + its master cert.
        out.push(self.identity_algo);
        out.extend_from_slice(&(self.identity_pubkey.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.identity_pubkey);
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.key_valid_from_unix.to_be_bytes());
        out.extend_from_slice(&self.key_valid_until_unix.to_be_bytes());
        out.extend_from_slice(&(self.master_sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.master_sig);

        // Validity window + freshness guard.
        out.extend_from_slice(&self.proof_valid_until_unix.to_be_bytes());
        out.extend_from_slice(&self.freshness_hour.to_be_bytes());

        // Anti-MITM ephemeral binding.
        out.extend_from_slice(&self.ephemeral_x25519_pk);
        out.extend_from_slice(&(self.ephemeral_sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ephemeral_sig);

        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() > MAX_IDENTITY_PROOF_BYTES {
            return Err(ProtoError::Malformed(format!(
                "identity_proof: oversized ({}B > {MAX_IDENTITY_PROOF_BYTES}B)",
                buf.len()
            )));
        }
        let mut pos = 0;
        if buf.get(pos..pos + 2) != Some(&IDENTITY_PROOF_MAGIC[..]) {
            return Err(ProtoError::Malformed("identity_proof: bad magic".into()));
        }
        pos += 2;

        let version = read_u8(buf, &mut pos, "identity_proof.version")?;
        if version != IDENTITY_PROOF_V1 {
            return Err(ProtoError::Malformed(format!(
                "identity_proof: unsupported version {version}"
            )));
        }

        let node_id = read_array::<32>(buf, &mut pos, "identity_proof.node_id")?;

        let master_algo = read_u8(buf, &mut pos, "identity_proof.master_algo")?;
        let master_pk_len = read_u16(buf, &mut pos, "identity_proof.master_pk_len")? as usize;
        if master_pk_len == 0 || master_pk_len > MAX_PUBKEY_BYTES {
            return Err(ProtoError::Malformed(format!(
                "identity_proof: master_pk_len {master_pk_len} out of range"
            )));
        }
        let master_pubkey = read_bytes(buf, &mut pos, master_pk_len, "identity_proof.master_pk")?;

        let identity_algo = read_u8(buf, &mut pos, "identity_proof.identity_algo")?;
        let identity_pk_len = read_u16(buf, &mut pos, "identity_proof.identity_pk_len")? as usize;
        if identity_pk_len == 0 || identity_pk_len > MAX_PUBKEY_BYTES {
            return Err(ProtoError::Malformed(format!(
                "identity_proof: identity_pk_len {identity_pk_len} out of range"
            )));
        }
        let identity_pubkey =
            read_bytes(buf, &mut pos, identity_pk_len, "identity_proof.identity_pk")?;

        let device_id = read_array::<32>(buf, &mut pos, "identity_proof.device_id")?;
        let key_valid_from_unix = read_u64(buf, &mut pos, "identity_proof.key_valid_from")?;
        let key_valid_until_unix = read_u64(buf, &mut pos, "identity_proof.key_valid_until")?;
        if key_valid_until_unix < key_valid_from_unix {
            return Err(ProtoError::Malformed(
                "identity_proof: key_valid_until < key_valid_from".into(),
            ));
        }

        let master_sig_len = read_u16(buf, &mut pos, "identity_proof.master_sig_len")? as usize;
        if master_sig_len == 0 || master_sig_len > MAX_SIG_BYTES {
            return Err(ProtoError::Malformed(format!(
                "identity_proof: master_sig_len {master_sig_len} out of range"
            )));
        }
        let master_sig = read_bytes(buf, &mut pos, master_sig_len, "identity_proof.master_sig")?;

        let proof_valid_until_unix = read_u64(buf, &mut pos, "identity_proof.valid_until")?;
        let freshness_hour = read_u32(buf, &mut pos, "identity_proof.freshness_hour")?;

        let ephemeral_x25519_pk = read_array::<32>(buf, &mut pos, "identity_proof.ephemeral_pk")?;
        let ephemeral_sig_len =
            read_u16(buf, &mut pos, "identity_proof.ephemeral_sig_len")? as usize;
        if ephemeral_sig_len == 0 || ephemeral_sig_len > MAX_SIG_BYTES {
            return Err(ProtoError::Malformed(format!(
                "identity_proof: ephemeral_sig_len {ephemeral_sig_len} out of range"
            )));
        }
        let ephemeral_sig = read_bytes(
            buf,
            &mut pos,
            ephemeral_sig_len,
            "identity_proof.ephemeral_sig",
        )?;

        // Trailing bytes are explicitly tolerated: when this
        // payload travels inside an OVL1 handshake frame the
        // transport layer appends random padding, and
        // the message is already self-delimiting via explicit
        // length-prefix fields. The `ephemeral_sig` covers only
        // the canonical field subset, so trailing bytes cannot
        // extend the signed surface.

        Ok(Self {
            node_id,
            master_algo,
            master_pubkey,
            identity_algo,
            identity_pubkey,
            device_id,
            key_valid_from_unix,
            key_valid_until_unix,
            master_sig,
            proof_valid_until_unix,
            freshness_hour,
            ephemeral_x25519_pk,
            ephemeral_sig,
        })
    }

    /// Bytes the `identity_sk` signs to produce `ephemeral_sig`:
    /// `EPHEMERAL_SIG_CONTEXT || node_id ||
    /// proof_valid_until_unix || ephemeral_x25519_pk`.
    ///
    /// Shared by the producer (for signing) and verifier (for
    /// checking).
    pub fn ephemeral_signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(EPHEMERAL_SIG_CONTEXT.len() + 32 + 8 + 32);
        msg.extend_from_slice(EPHEMERAL_SIG_CONTEXT);
        msg.extend_from_slice(&self.node_id);
        msg.extend_from_slice(&self.proof_valid_until_unix.to_be_bytes());
        msg.extend_from_slice(&self.ephemeral_x25519_pk);
        msg
    }

    fn encoded_len(&self) -> usize {
        2 + 1
            + 32
            + 1
            + 2
            + self.master_pubkey.len()
            + 1
            + 2
            + self.identity_pubkey.len()
            + 32
            + 8
            + 8
            + 2
            + self.master_sig.len()
            + 8
            + 4
            + 32
            + 2
            + self.ephemeral_sig.len()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────
//
// local `read_array` removed — use cursor::read_array.

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_proof() -> IdentityProof {
        IdentityProof {
            node_id: [0x11; 32],
            master_algo: 0,
            master_pubkey: vec![0x22; 32],
            identity_algo: 0,
            identity_pubkey: vec![0x33; 32],
            device_id: [0x44; 32],
            key_valid_from_unix: 1_700_000_000,
            key_valid_until_unix: 1_700_000_000 + 7 * 86_400,
            master_sig: vec![0x55; 64],
            proof_valid_until_unix: 1_700_000_000 + 300,
            freshness_hour: (1_700_000_000 / 3600) as u32,
            ephemeral_x25519_pk: [0x66; 32],
            ephemeral_sig: vec![0x77; 64],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let p = sample_proof();
        let bytes = p.encode();
        let decoded = IdentityProof::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn encoded_len_matches_actual() {
        let p = sample_proof();
        let bytes = p.encode();
        assert_eq!(bytes.len(), p.encoded_len());
    }

    #[test]
    fn magic_mismatch_is_rejected() {
        let p = sample_proof();
        let mut bytes = p.encode();
        bytes[0] ^= 0xFF;
        let err = IdentityProof::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("bad magic")));
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let p = sample_proof();
        let mut bytes = p.encode();
        bytes[2] = 99;
        let err = IdentityProof::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("unsupported version")));
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let bytes = vec![0u8; MAX_IDENTITY_PROOF_BYTES + 1];
        let err = IdentityProof::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("oversized")));
    }

    #[test]
    fn trailing_bytes_are_tolerated() {
        // OVL1 handshake frames append random padding
        // so this wire type must decode the canonical portion and
        // ignore anything after the last length-prefixed field.
        let p = sample_proof();
        let mut bytes = p.encode();
        let original_len = bytes.len();
        bytes.extend_from_slice(&[0xAA; 32]); // simulated padding
        let decoded = IdentityProof::decode(&bytes).expect("trailing bytes must be tolerated");
        assert_eq!(decoded, p);
        // Sanity: the canonical re-encode length is unchanged.
        assert_eq!(decoded.encode().len(), original_len);
    }

    #[test]
    fn truncated_mid_field_is_rejected() {
        let p = sample_proof();
        let bytes = p.encode();
        let err = IdentityProof::decode(&bytes[..bytes.len() - 5]).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("truncated")));
    }

    #[test]
    fn zero_length_master_sig_is_rejected() {
        let mut p = sample_proof();
        p.master_sig.clear();
        let err = IdentityProof::decode(&p.encode()).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("master_sig_len")));
    }

    #[test]
    fn zero_length_ephemeral_sig_is_rejected() {
        let mut p = sample_proof();
        p.ephemeral_sig.clear();
        let err = IdentityProof::decode(&p.encode()).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(m) if m.contains("ephemeral_sig_len")));
    }

    #[test]
    fn ephemeral_signing_message_is_stable_and_binds_all_fields() {
        let p = sample_proof();
        let m1 = p.ephemeral_signing_message();

        // Tweaking node_id or valid_until or ephemeral_pk MUST change the bytes.
        let mut p2 = p.clone();
        p2.node_id[0] ^= 0xFF;
        assert_ne!(p2.ephemeral_signing_message(), m1);

        let mut p3 = p.clone();
        p3.proof_valid_until_unix += 1;
        assert_ne!(p3.ephemeral_signing_message(), m1);

        let mut p4 = p.clone();
        p4.ephemeral_x25519_pk[0] ^= 0xFF;
        assert_ne!(p4.ephemeral_signing_message(), m1);

        // Prefix is the stable context so re-encoded bytes of the
        // same struct reproduce the same signing message.
        assert!(m1.starts_with(EPHEMERAL_SIG_CONTEXT));
        assert_eq!(m1, p.ephemeral_signing_message());
    }
}
