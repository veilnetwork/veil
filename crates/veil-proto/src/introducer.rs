//! In-band introducer wire-frame — Epic 481.3.
//!
//! Out-of-band bootstrap (Epic 481) shipped 5 channels: builtin seeds, DHT
//! bootstrap-bundle, transport hints, gossip, and operator-injected URIs.
//! Those cover the common "fresh node finds *some* peer to talk to" case
//! but don't transmit a **transitive-trust signal** between peers. An
//! introducer record lets node A vouch for node B: "I, A, attest that B's
//! node_id is sensible to talk to in the context I personally know."
//!
//! The vouch is paper-thin — `IntroduceRequest` carries no claim of
//! "I verified B is honest" — but it does carry a cryptographic anchor
//! that the introducer pubkey actually said this, and a bounded expiry.
//! Higher layers (pairing invites, sponsored mailbox access, mass-onboard
//! flashmob bootstraps) can attach app-level meaning to a valid signature.
//!
//! ## Wire format
//!
//! ```text
//! [0..2]   MAGIC = "IN"
//! [2]      VERSION = 1
//! [3..35]  introducer_node_id [u8; 32]
//! [35..67] sponsoree_node_id  [u8; 32]
//! [67..75] expiry_unix u64 BE — Unix seconds, hard expiry
//! [75..77] introducer_pubkey_len u16 BE
//! [77..K]  introducer_pubkey bytes (Ed25519 = 32 bytes)
//! [K..K+2] sig_len u16 BE
//! [K+2..]  sig bytes — Ed25519 over canonical signing bytes
//! ```
//!
//! Canonical signing bytes = wire encoding minus the trailing `sig_len + sig`
//! pair. The signature thus covers every field that contributes to meaning
//! including the version and both node_ids and the expiry.
//!
//! ## Validity policy
//!
//! `expiry_unix` is interpreted as a hard cutoff: receivers reject if
//! `now_unix > expiry_unix + WIRE_SKEW_SECS` (5-minute skew tolerance from
//! [`crate::time_validity::WIRE_SKEW_SECS`]). Introducer SHOULD pick a
//! reasonable expiry — recommended max is `SHORT_STATE_TTL_SECS` for one-
//! shot pairing flows, up to 1 hour for mass-onboarding events. Long expiries
//! (> 1 day) are accepted by the wire layer but should be flagged at policy.
//!
//! ## What this module does NOT do
//!
//! - **No identity binding check.** Verifying that `introducer_pubkey` actually
//!   belongs to `introducer_node_id` requires a separate IdentityDocument
//!   lookup; this module only validates that the signature is integrity-
//!   correct for the embedded pubkey. Callers must do the identity binding
//!   step before trusting the introducer field.
//! - **No replay prevention.** Same record can be replayed any number of
//!   times before expiry. Callers needing replay protection must layer
//!   their own nonce/seen-set on top.
//! - **No bandwidth control.** Wire-level allows up to 64 KiB of pubkey
//!   + sig (both u16-length-prefixed); soft cap on Ed25519-only deployments
//!   is implicit in [`MAX_INTRODUCE_REQUEST_BYTES`].

use super::ProtoError;
use super::cursor::{read_array, read_bytes, read_u8, read_u16, read_u64};
use super::time_validity::WIRE_SKEW_SECS;

/// "IN" — identifies an IntroduceRequest value on the wire.
pub const INTRODUCE_MAGIC: [u8; 2] = [b'I', b'N'];

/// Current wire format version.
pub const INTRODUCE_V1: u8 = 1;

/// Domain-separated signing context. Concatenated with canonical bytes
/// before Ed25519 signing/verification so that a sig produced for one
/// protocol artefact cannot be re-used as a valid sig for another.
pub const INTRODUCE_SIG_CONTEXT: &[u8] = b"veil.introduce.v1";

/// Absolute upper bound on wire size. Generous: 1 KiB covers Ed25519
/// pubkey/sig (32 + 64) plus headers with room for future curve upgrades.
pub const MAX_INTRODUCE_REQUEST_BYTES: usize = 1024;

/// Hard cap on pubkey-length field on the wire. Ed25519 = 32; ML-DSA
/// (post-quantum) ≤ 5 KiB — staying in u16-prefix is fine.
pub const MAX_INTRODUCER_PUBKEY_LEN: usize = 256;

/// Hard cap on sig-length field. Ed25519 = 64. Same forward-room reasoning.
pub const MAX_INTRODUCER_SIG_LEN: usize = 512;

// ── IntroduceRequest ─────────────────────────────────────────────────────────

/// In-band introducer record — vouching that `introducer_node_id` (signing
/// owner of `introducer_pubkey`) attests to the validity of `sponsoree_node_id`.
///
/// See module-level docs for wire format and validity policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroduceRequest {
    /// Node attesting to the sponsoree's identity.
    pub introducer_node_id: [u8; 32],
    /// Node being introduced.
    pub sponsoree_node_id: [u8; 32],
    /// Hard expiry in Unix seconds — receiver rejects if
    /// `now > expiry + WIRE_SKEW_SECS`.
    pub expiry_unix: u64,
    /// Introducer's Ed25519 verifying key (32 bytes for current curve).
    pub introducer_pubkey: Vec<u8>,
    /// Ed25519 signature over `INTRODUCE_SIG_CONTEXT || canonical_signing_bytes`.
    pub sig: Vec<u8>,
}

/// Error variants surfaced during introducer-request validity checks.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IntroduceError {
    #[error("introducer-pubkey length {0} is not a valid Ed25519 verifying key")]
    BadPubkeyLen(usize),

    #[error("signature length {0} is not a valid Ed25519 signature")]
    BadSigLen(usize),

    #[error("Ed25519 pubkey parse failed: {0}")]
    PubkeyParse(String),

    #[error("Ed25519 signature verification failed")]
    BadSignature,

    #[error("record expired: expiry={expiry}, now={now}")]
    Expired { expiry: u64, now: u64 },

    #[error("introducer and sponsoree node_ids are identical (self-vouching)")]
    SelfVouching,
}

impl IntroduceRequest {
    /// Build + sign a new record.
    ///
    /// The provided `signing_key` must correspond to the
    /// `introducer_node_id`'s active identity — callers should source it
    /// from the local sovereign-identity master, not invent a fresh key.
    /// This function does not check that binding; it just signs.
    ///
    /// Returns `Err(SelfVouching)` if `introducer_node_id == sponsoree_node_id`
    /// — a node cannot meaningfully vouch for itself through this channel.
    pub fn sign(
        introducer_node_id: [u8; 32],
        sponsoree_node_id: [u8; 32],
        expiry_unix: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, IntroduceError> {
        if introducer_node_id == sponsoree_node_id {
            return Err(IntroduceError::SelfVouching);
        }
        let introducer_pubkey = signing_key.verifying_key().to_bytes().to_vec();
        // Build a draft with empty sig so canonical_signing_bytes produces
        // the right preimage; then attach the actual signature.
        let mut draft = Self {
            introducer_node_id,
            sponsoree_node_id,
            expiry_unix,
            introducer_pubkey,
            sig: Vec::new(),
        };
        let preimage = draft.canonical_signing_input();
        use ed25519_dalek::Signer;
        draft.sig = signing_key.sign(&preimage).to_bytes().to_vec();
        Ok(draft)
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let pk_len = self.introducer_pubkey.len();
        let sig_len = self.sig.len();
        let total = 2 + 1 + 32 + 32 + 8 + 2 + pk_len + 2 + sig_len;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&INTRODUCE_MAGIC);
        out.push(INTRODUCE_V1);
        out.extend_from_slice(&self.introducer_node_id);
        out.extend_from_slice(&self.sponsoree_node_id);
        out.extend_from_slice(&self.expiry_unix.to_be_bytes());
        out.extend_from_slice(&(pk_len as u16).to_be_bytes());
        out.extend_from_slice(&self.introducer_pubkey);
        out.extend_from_slice(&(sig_len as u16).to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Decode wire bytes with full structural validation.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() > MAX_INTRODUCE_REQUEST_BYTES {
            return Err(ProtoError::Malformed(format!(
                "introduce: oversized ({}B > {MAX_INTRODUCE_REQUEST_BYTES}B)",
                buf.len()
            )));
        }
        let mut pos = 0;
        if buf.get(pos..pos + 2) != Some(&INTRODUCE_MAGIC[..]) {
            return Err(ProtoError::Malformed("introduce: bad magic".into()));
        }
        pos += 2;

        let version = read_u8(buf, &mut pos, "introduce.version")?;
        if version != INTRODUCE_V1 {
            return Err(ProtoError::Malformed(format!(
                "introduce: unsupported version {version}"
            )));
        }

        let introducer_node_id = read_array::<32>(buf, &mut pos, "introduce.introducer_node_id")?;
        let sponsoree_node_id = read_array::<32>(buf, &mut pos, "introduce.sponsoree_node_id")?;
        let expiry_unix = read_u64(buf, &mut pos, "introduce.expiry_unix")?;

        let pk_len = read_u16(buf, &mut pos, "introduce.pubkey_len")? as usize;
        if pk_len == 0 || pk_len > MAX_INTRODUCER_PUBKEY_LEN {
            return Err(ProtoError::Malformed(format!(
                "introduce: pubkey_len {pk_len} out of range"
            )));
        }
        let introducer_pubkey = read_bytes(buf, &mut pos, pk_len, "introduce.pubkey")?;

        let sig_len = read_u16(buf, &mut pos, "introduce.sig_len")? as usize;
        if sig_len == 0 || sig_len > MAX_INTRODUCER_SIG_LEN {
            return Err(ProtoError::Malformed(format!(
                "introduce: sig_len {sig_len} out of range"
            )));
        }
        let sig = read_bytes(buf, &mut pos, sig_len, "introduce.sig")?;

        if pos != buf.len() {
            return Err(ProtoError::Malformed(format!(
                "introduce: {} trailing bytes",
                buf.len() - pos
            )));
        }

        Ok(Self {
            introducer_node_id,
            sponsoree_node_id,
            expiry_unix,
            introducer_pubkey,
            sig,
        })
    }

    /// Wire bytes covered by the signature: full encoding minus the
    /// trailing `sig_len + sig` pair.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut encoded = self.encode();
        let trailer = 2 + self.sig.len();
        encoded.truncate(encoded.len() - trailer);
        encoded
    }

    /// Bytes actually fed to Ed25519: `INTRODUCE_SIG_CONTEXT || canonical_signing_bytes`.
    fn canonical_signing_input(&self) -> Vec<u8> {
        let canonical = self.canonical_signing_bytes();
        let mut out = Vec::with_capacity(INTRODUCE_SIG_CONTEXT.len() + canonical.len());
        out.extend_from_slice(INTRODUCE_SIG_CONTEXT);
        out.extend_from_slice(&canonical);
        out
    }

    /// Full validity check: signature integrity, expiry, self-vouching gate.
    ///
    /// `now_unix` is provided by the caller — typically `SystemTime::now()`
    /// converted to Unix seconds. The check applies a fixed
    /// [`WIRE_SKEW_SECS`] skew tolerance on the expiry comparison.
    ///
    /// Does NOT verify identity binding (that `introducer_pubkey` belongs
    /// to `introducer_node_id`) — call IdentityDocument lookup separately
    /// and compare the resolved pubkey against `self.introducer_pubkey`.
    pub fn verify(&self, now_unix: u64) -> Result<(), IntroduceError> {
        // Self-vouching guard — same as on sign(), kept on decode-path too
        // so that a malicious encoder can't fabricate a self-introducing
        // record that bypasses the higher-layer "no self" gate.
        if self.introducer_node_id == self.sponsoree_node_id {
            return Err(IntroduceError::SelfVouching);
        }

        // Expiry: skew-tolerant comparison.
        let cutoff = self.expiry_unix.saturating_add(WIRE_SKEW_SECS);
        if now_unix > cutoff {
            return Err(IntroduceError::Expired {
                expiry: self.expiry_unix,
                now: now_unix,
            });
        }

        // Sig + pubkey size sanity (Ed25519-specific; widen if the curve changes).
        if self.introducer_pubkey.len() != 32 {
            return Err(IntroduceError::BadPubkeyLen(self.introducer_pubkey.len()));
        }
        if self.sig.len() != 64 {
            return Err(IntroduceError::BadSigLen(self.sig.len()));
        }

        let pk_arr: [u8; 32] = self
            .introducer_pubkey
            .as_slice()
            .try_into()
            .expect("checked above what introducer_pubkey.len() == 32");
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| IntroduceError::PubkeyParse(e.to_string()))?;
        let sig_arr: [u8; 64] = self
            .sig
            .as_slice()
            .try_into()
            .expect("checked above that sig.len() == 64");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

        let msg = self.canonical_signing_input();
        use ed25519_dalek::Verifier;
        pk.verify(&msg, &sig)
            .map_err(|_| IntroduceError::BadSignature)?;
        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn introducer_id(sk: &SigningKey) -> [u8; 32] {
        // For tests we tie introducer_node_id directly to sk's pubkey hash —
        // matches the "node_id = BLAKE3(pubkey)" production rule closely
        // enough to exercise the wire format.
        let pk = sk.verifying_key().to_bytes();
        *blake3::hash(&pk).as_bytes()
    }

    #[test]
    fn roundtrip_encode_decode() {
        let sk = key(0x42);
        let i_id = introducer_id(&sk);
        let s_id = [0xBB; 32];
        let req = IntroduceRequest::sign(i_id, s_id, 1_700_000_000, &sk).unwrap();

        let bytes = req.encode();
        let decoded = IntroduceRequest::decode(&bytes).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn signed_record_verifies() {
        let sk = key(0x42);
        let i_id = introducer_id(&sk);
        let s_id = [0xBB; 32];
        let req = IntroduceRequest::sign(i_id, s_id, 1_700_000_000, &sk).unwrap();

        // Verify within window — expiry is far future relative to now=0.
        assert_eq!(req.verify(1_699_999_000), Ok(()));
    }

    #[test]
    fn tampered_sponsoree_breaks_signature() {
        let sk = key(0x42);
        let i_id = introducer_id(&sk);
        let req = IntroduceRequest::sign(i_id, [0xBB; 32], 1_700_000_000, &sk).unwrap();

        // Flip sponsoree_node_id post-sign.
        let mut bytes = req.encode();
        // Offset of sponsoree_node_id: 2 (magic) + 1 (ver) + 32 = 35.
        bytes[35] ^= 0x01;
        let tampered = IntroduceRequest::decode(&bytes).unwrap();
        assert_eq!(
            tampered.verify(1_699_999_000),
            Err(IntroduceError::BadSignature)
        );
    }

    #[test]
    fn tampered_expiry_breaks_signature() {
        let sk = key(0x42);
        let i_id = introducer_id(&sk);
        let req = IntroduceRequest::sign(i_id, [0xBB; 32], 1_700_000_000, &sk).unwrap();

        let mut bytes = req.encode();
        // Offset of expiry_unix: 2 + 1 + 32 + 32 = 67.
        bytes[67] ^= 0x80; // flip top byte of expiry
        let tampered = IntroduceRequest::decode(&bytes).unwrap();
        assert_eq!(tampered.verify(0), Err(IntroduceError::BadSignature));
    }

    #[test]
    fn expired_record_rejected() {
        let sk = key(0x42);
        let i_id = introducer_id(&sk);
        let req = IntroduceRequest::sign(i_id, [0xBB; 32], 1000, &sk).unwrap();

        // now = expiry + WIRE_SKEW_SECS + 1 → just past tolerance.
        let now = 1000 + WIRE_SKEW_SECS + 1;
        assert!(matches!(
            req.verify(now),
            Err(IntroduceError::Expired { .. })
        ));
    }

    #[test]
    fn within_skew_tolerance_passes() {
        let sk = key(0x42);
        let i_id = introducer_id(&sk);
        let req = IntroduceRequest::sign(i_id, [0xBB; 32], 1000, &sk).unwrap();

        // now = expiry + WIRE_SKEW_SECS → at the boundary, should pass
        // (cutoff is inclusive: `now > expiry + skew` rejects).
        let now = 1000 + WIRE_SKEW_SECS;
        assert_eq!(req.verify(now), Ok(()));
    }

    #[test]
    fn self_vouching_rejected_on_sign() {
        let sk = key(0x42);
        let id = [0xAA; 32];
        let err = IntroduceRequest::sign(id, id, 1_700_000_000, &sk).unwrap_err();
        assert_eq!(err, IntroduceError::SelfVouching);
    }

    #[test]
    fn self_vouching_rejected_on_verify() {
        let sk = key(0x42);
        // Manually fabricate a self-introducing record bypassing sign()'s gate.
        let id = [0xAA; 32];
        let mut req = IntroduceRequest {
            introducer_node_id: id,
            sponsoree_node_id: id,
            expiry_unix: 1_700_000_000,
            introducer_pubkey: sk.verifying_key().to_bytes().to_vec(),
            sig: Vec::new(),
        };
        let preimage = req.canonical_signing_input();
        use ed25519_dalek::Signer;
        req.sig = sk.sign(&preimage).to_bytes().to_vec();

        // Sig now verifies cryptographically, but verify() still rejects.
        assert_eq!(req.verify(1_699_999_000), Err(IntroduceError::SelfVouching));
    }

    #[test]
    fn wrong_pubkey_rejected() {
        let sk_a = key(0xAA);
        let sk_b = key(0xBB);
        let i_id = introducer_id(&sk_a);

        // Sign with key_a but overwrite pubkey to key_b's after the fact.
        let mut req = IntroduceRequest::sign(i_id, [0xCC; 32], 1_700_000_000, &sk_a).unwrap();
        req.introducer_pubkey = sk_b.verifying_key().to_bytes().to_vec();
        // Sig was produced by key_a but record claims key_b's pubkey → mismatch.
        assert_eq!(req.verify(1_699_999_000), Err(IntroduceError::BadSignature));
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = vec![b'X', b'X', 1u8];
        bytes.resize(80, 0);
        assert!(matches!(
            IntroduceRequest::decode(&bytes),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn bad_version_rejected() {
        let sk = key(0x42);
        let i_id = introducer_id(&sk);
        let req = IntroduceRequest::sign(i_id, [0xBB; 32], 1_700_000_000, &sk).unwrap();
        let mut bytes = req.encode();
        // version byte is at offset 2.
        bytes[2] = 99;
        assert!(matches!(
            IntroduceRequest::decode(&bytes),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn oversized_payload_rejected() {
        // Payload > MAX_INTRODUCE_REQUEST_BYTES — synthetic.
        let bytes = vec![0u8; MAX_INTRODUCE_REQUEST_BYTES + 1];
        assert!(matches!(
            IntroduceRequest::decode(&bytes),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let sk = key(0x42);
        let i_id = introducer_id(&sk);
        let req = IntroduceRequest::sign(i_id, [0xBB; 32], 1_700_000_000, &sk).unwrap();
        let mut bytes = req.encode();
        bytes.push(0x00);
        assert!(matches!(
            IntroduceRequest::decode(&bytes),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn zero_pubkey_len_rejected() {
        // Manually craft a record with declared pubkey_len = 0.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&INTRODUCE_MAGIC);
        bytes.push(INTRODUCE_V1);
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.extend_from_slice(&[0xBB; 32]);
        bytes.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes()); // pubkey_len = 0
        bytes.extend_from_slice(&64u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        assert!(matches!(
            IntroduceRequest::decode(&bytes),
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn canonical_signing_bytes_excludes_sig() {
        let sk = key(0x42);
        let i_id = introducer_id(&sk);
        let req = IntroduceRequest::sign(i_id, [0xBB; 32], 1_700_000_000, &sk).unwrap();

        let full = req.encode();
        let canonical = req.canonical_signing_bytes();
        // Canonical = full minus (2-byte sig_len + sig).
        assert_eq!(canonical.len(), full.len() - 2 - req.sig.len());
        assert_eq!(&canonical[..], &full[..canonical.len()]);
    }
}
