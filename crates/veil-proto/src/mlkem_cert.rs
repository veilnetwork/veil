//! Per-instance ML-KEM key certificate.
//!
//! Each device (instance) owns an ML-KEM-768 keypair it uses for
//! asynchronous E2E encapsulation. The public half (`ek` = 1184 B)
//! is pinned to the identity's cert chain through this certificate
//! signed by one of the identity's active subkeys
//! (`signing_identity_key_idx` points into
//! `IdentityDocument.identity_keys`):
//!
//! ```text
//! master_pk
//! ↳ identity_key.master_sig (in IdentityDocument —)
//! ↳ MlKemKeyCert.sig (this module)
//! ↳ mlkem_pubkey (used by the sender to encapsulate)
//! ```
//!
//! A sender who wants to E2E-encrypt a message to `@alice` with
//! `InstanceTag::All` fetches one [`MlKemKeyCert`] per instance
//! verifies the full chain [`IdentityDocument`], encapsulates
//! once per cert, and sends the resulting ciphertexts fanned out —
//! each instance decapsulates only its own copy. [`InstanceTag::Specific`]
//! does the same for a single instance.
//!
//! ## Wire layout (canonical bytes, big-endian)
//!
//! ```text
//! [0..2] magic = "MC" u16
//! [2] version = 1 u8
//! [3..35] node_id [u8; 32]
//! [35..51] instance_id [u8; 16]
//! [51] mlkem_algo (= ALGO_ML_KEM_768 = 1) u8
//! [..] mlkem_pubkey_len u16 BE
//! [..] mlkem_pubkey [u8; len]
//! [..] valid_from_unix u64 BE
//! [..] valid_until_unix u64 BE
//! [..] cert_version u64 BE
//! [..] signing_identity_key_idx u16 BE
//! [..] sig_len u16 BE
//! [..] sig [u8; sig_len]
//! ```
//!
//! The signature covers `MLKEM_CERT_SIG_CONTEXT || canonical_signing_bytes`.
//!
//! [`IdentityDocument`]: super::identity_document::IdentityDocument
//! [`InstanceTag::All`]: super::recipient::InstanceTag::All
//! [`InstanceTag::Specific`]: super::recipient::InstanceTag::Specific

use super::ProtoError;
use super::cursor::BoundedDecoder;
use super::prekey_bundle::ek_len_for_algo;
#[cfg(test)]
use super::prekey_bundle::{ALGO_ML_KEM_768, ML_KEM_768_EK_LEN};

// ── Constants ────────────────────────────────────────────────────────────────

pub const MLKEM_CERT_MAGIC: [u8; 2] = *b"MC";
pub const MLKEM_CERT_V1: u8 = 1;
pub const MLKEM_CERT_SIG_CONTEXT: &[u8] = b"veil.mlkem_cert.v1";

/// Upper bound on the wire payload — accommodates Falcon-sized
/// signatures plus the 1184-byte ML-KEM-768 pubkey with headroom.
pub const MAX_MLKEM_CERT_BYTES: usize = 2 * 1024;

/// Maximum ML-KEM pubkey length accepted at the structural layer
/// (algo-specific length is enforced [`ek_len_for_algo`]).
pub const MAX_MLKEM_PUBKEY_BYTES: usize = 1500;

const MAX_SIG_BYTES: usize = 1024;

// ── Struct ───────────────────────────────────────────────────────────────────

/// Instance-scoped ML-KEM public-key certificate, signed by a
/// subkey of the instance's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKemKeyCert {
    pub node_id: [u8; 32],
    pub instance_id: [u8; 16],
    pub mlkem_algo: u8,
    /// ML-KEM encapsulation key (public). Length must match the
    /// algorithm — validated at decode time.
    pub mlkem_pubkey: Vec<u8>,
    pub valid_from_unix: u64,
    pub valid_until_unix: u64,
    /// Monotonic counter bumped on each cert rotation so a later
    /// cert supersedes an earlier one unambiguously.
    pub cert_version: u64,
    /// Index into the current `IdentityDocument.identity_keys` of
    /// the subkey that signed this cert.
    pub signing_identity_key_idx: u16,
    pub sig: Vec<u8>,
}

impl MlKemKeyCert {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&MLKEM_CERT_MAGIC);
        out.push(MLKEM_CERT_V1);
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.instance_id);
        out.push(self.mlkem_algo);
        out.extend_from_slice(&(self.mlkem_pubkey.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.mlkem_pubkey);
        out.extend_from_slice(&self.valid_from_unix.to_be_bytes());
        out.extend_from_slice(&self.valid_until_unix.to_be_bytes());
        out.extend_from_slice(&self.cert_version.to_be_bytes());
        out.extend_from_slice(&self.signing_identity_key_idx.to_be_bytes());
        out.extend_from_slice(&(self.sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Decode wire bytes to a fully-populated certificate.
    ///
    /// demo migration: replaced ~10 hand-rolled cursor
    /// calls with [`BoundedDecoder`] which encapsulates buf+pos so a new
    /// reader can't accidentally drift the cursor. Trailing-bytes
    /// rejection moved to `assert_eof`. Net: ~25 lines deleted, the
    /// remaining flow is a straight-line read sequence without cursor
    /// arithmetic visible at the call site.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() > MAX_MLKEM_CERT_BYTES {
            return Err(ProtoError::Malformed(format!(
                "mlkem_cert: oversized ({}B > {MAX_MLKEM_CERT_BYTES}B)",
                buf.len()
            )));
        }
        let mut d = BoundedDecoder::new(buf);
        // Magic: read 2 bytes manually so the error message stays
        // "bad magic" (BoundedDecoder would just say "truncated: magic").
        let magic = d.read_array::<2>("mlkem_cert.magic")?;
        if magic != MLKEM_CERT_MAGIC {
            return Err(ProtoError::Malformed("mlkem_cert: bad magic".into()));
        }
        let version = d.read_u8("mlkem_cert.version")?;
        if version != MLKEM_CERT_V1 {
            return Err(ProtoError::Malformed(format!(
                "mlkem_cert: unsupported version {version}"
            )));
        }
        let node_id = d.read_array::<32>("mlkem_cert.node_id")?;
        let instance_id = d.read_array::<16>("mlkem_cert.instance_id")?;
        let mlkem_algo = d.read_u8("mlkem_cert.algo")?;
        let expected_ek_len = ek_len_for_algo(mlkem_algo)?;

        // Read u16 pubkey_len with algo-specific equality check; cannot use
        // `read_u16_prefixed_bytes` directly since we need exact-length
        // (not <= max) and a custom error message. Read length explicitly
        // and then the body via `read_bytes`.
        let pk_len = d.read_u16("mlkem_cert.pubkey_len")? as usize;
        if pk_len != expected_ek_len {
            return Err(ProtoError::Malformed(format!(
                "mlkem_cert: pubkey_len {pk_len} != expected {expected_ek_len}"
            )));
        }
        let mlkem_pubkey = d.read_bytes(pk_len, "mlkem_cert.pubkey")?;

        let valid_from_unix = d.read_u64("mlkem_cert.valid_from")?;
        let valid_until_unix = d.read_u64("mlkem_cert.valid_until")?;
        if valid_until_unix < valid_from_unix {
            return Err(ProtoError::Malformed(
                "mlkem_cert: valid_until < valid_from".into(),
            ));
        }
        let cert_version = d.read_u64("mlkem_cert.cert_version")?;
        let signing_identity_key_idx = d.read_u16("mlkem_cert.signing_key_idx")?;

        // sig_len with custom "must be > 0 AND <= MAX_SIG_BYTES" rule —
        // again can't use `read_u16_prefixed_bytes` (allows 0-len).
        let sig_len = d.read_u16("mlkem_cert.sig_len")? as usize;
        if sig_len == 0 || sig_len > MAX_SIG_BYTES {
            return Err(ProtoError::Malformed(format!(
                "mlkem_cert: sig_len {sig_len} out of range"
            )));
        }
        let sig = d.read_bytes(sig_len, "mlkem_cert.sig")?;

        d.assert_eof()
            .map_err(|e| ProtoError::Malformed(format!("mlkem_cert: {e}")))?;

        Ok(Self {
            node_id,
            instance_id,
            mlkem_algo,
            mlkem_pubkey,
            valid_from_unix,
            valid_until_unix,
            cert_version,
            signing_identity_key_idx,
            sig,
        })
    }

    /// Canonical bytes the signature covers.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut encoded = self.encode();
        let trailer = 2 + self.sig.len();
        encoded.truncate(encoded.len() - trailer);
        encoded
    }

    /// Bytes the signer signs: `SIG_CONTEXT || canonical_signing_bytes`.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(MLKEM_CERT_SIG_CONTEXT.len() + self.encoded_len());
        msg.extend_from_slice(MLKEM_CERT_SIG_CONTEXT);
        msg.extend_from_slice(&self.canonical_signing_bytes());
        msg
    }

    fn encoded_len(&self) -> usize {
        2 + 1 + 32 + 16 + 1 + 2 + self.mlkem_pubkey.len() + 8 + 8 + 8 + 2 + 2 + self.sig.len()
    }

    /// Convenience: is the cert valid at `now_unix_secs`?
    pub fn is_valid_at(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.valid_from_unix && now_unix_secs <= self.valid_until_unix
    }

    /// DHT key under which this certificate is published. Keyed
    /// by `(node_id, instance_id)` — cert_version is NOT in
    /// the key so that a rotation replaces the previous cert at
    /// the same slot (consumers rely on the signature + validity
    /// window to reject stale certs).
    pub fn dht_key(node_id: &[u8; 32], instance_id: &[u8; 16]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"veil.mlkem_cert_dht.v1");
        h.update(node_id);
        h.update(instance_id);
        *h.finalize().as_bytes()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────
// ad-hoc `read_array` removed; use `BoundedDecoder::read_array`
// which has identical semantics but lives with the cursor primitive.

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert() -> MlKemKeyCert {
        MlKemKeyCert {
            node_id: [0x11; 32],
            instance_id: [0x22; 16],
            mlkem_algo: ALGO_ML_KEM_768,
            mlkem_pubkey: vec![0xAA; ML_KEM_768_EK_LEN],
            valid_from_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 30 * 86_400,
            cert_version: 3,
            signing_identity_key_idx: 0,
            sig: vec![0xCC; 64],
        }
    }

    #[test]
    fn codec_roundtrip() {
        let c = sample_cert();
        let bytes = c.encode();
        assert_eq!(bytes.len(), c.encoded_len());
        let back = MlKemKeyCert::decode(&bytes).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn rejects_bad_magic() {
        let c = sample_cert();
        let mut bytes = c.encode();
        bytes[0] = b'X';
        let err = MlKemKeyCert::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_unsupported_version() {
        let c = sample_cert();
        let mut bytes = c.encode();
        bytes[2] = 99;
        let err = MlKemKeyCert::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_unsupported_algo() {
        let mut c = sample_cert();
        c.mlkem_algo = 99;
        let bytes = c.encode();
        let err = MlKemKeyCert::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_wrong_ek_length() {
        let mut c = sample_cert();
        c.mlkem_pubkey = vec![0; ML_KEM_768_EK_LEN - 1];
        let bytes = c.encode();
        let err = MlKemKeyCert::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_valid_until_before_valid_from() {
        let mut c = sample_cert();
        c.valid_from_unix = 2_000_000_000;
        c.valid_until_unix = 1_900_000_000;
        let bytes = c.encode();
        let err = MlKemKeyCert::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_zero_sig() {
        let mut c = sample_cert();
        c.sig = Vec::new();
        let bytes = c.encode();
        let err = MlKemKeyCert::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_oversized_input() {
        let bytes = vec![0u8; MAX_MLKEM_CERT_BYTES + 1];
        let err = MlKemKeyCert::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_trailing_bytes() {
        let c = sample_cert();
        let mut bytes = c.encode();
        bytes.push(0xFF);
        let err = MlKemKeyCert::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_truncated() {
        let c = sample_cert();
        let bytes = c.encode();
        for cut in [1, 5, 35, 50, 100].iter().copied() {
            if cut < bytes.len() {
                let err = MlKemKeyCert::decode(&bytes[..cut]).unwrap_err();
                assert!(matches!(err, ProtoError::Malformed(_)), "cut={cut} {err:?}");
            }
        }
    }

    #[test]
    fn canonical_bytes_exclude_sig() {
        let c = sample_cert();
        let full = c.encode();
        let canonical = c.canonical_signing_bytes();
        assert_eq!(&full[..canonical.len()], &canonical[..]);
        assert_eq!(full.len() - canonical.len(), 2 + c.sig.len());
    }

    #[test]
    fn signing_message_has_context_prefix() {
        let c = sample_cert();
        let msg = c.signing_message();
        assert!(msg.starts_with(MLKEM_CERT_SIG_CONTEXT));
    }

    #[test]
    fn is_valid_at_within_window() {
        let c = sample_cert();
        assert!(c.is_valid_at(c.valid_from_unix));
        assert!(c.is_valid_at(c.valid_until_unix));
        assert!(c.is_valid_at((c.valid_from_unix + c.valid_until_unix) / 2));
    }

    #[test]
    fn is_valid_at_rejects_outside_window() {
        let c = sample_cert();
        assert!(!c.is_valid_at(c.valid_from_unix - 1));
        assert!(!c.is_valid_at(c.valid_until_unix + 1));
    }
}
