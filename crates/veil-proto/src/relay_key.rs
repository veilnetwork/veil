//! Relay X25519 KEM key record — DHT-stored advertisement of a node's
//! relay/anonymity X25519 public key, resolvable by `node_id`.
//!
//! A node that hosts the built-in mailbox (or otherwise acts as an
//! anonymity relay) owns a stable, persisted X25519 keypair (the
//! `device_anonymity_x25519_sk`). To let an OFFLINE receiver advertise some
//! always-on relay R as its mailbox host — and to let a sender seal an
//! anonymous deposit to R — peers must be able to learn R's X25519 KEM
//! public key by R's `node_id` alone. `get_relay_x25519_pubkey` only
//! returns the LOCAL node's own key (it is an IPC call into that node), so a
//! third party cannot use it. This record fills the gap: R publishes a
//! signed `RelayKeyRecord` to the DHT and any peer resolves it by `node_id`.
//!
//! Authenticated like [`MlKemKeyCert`]: signed by one of the node's active
//! identity subkeys (`signing_identity_key_idx` points into
//! `IdentityDocument.identity_keys`), so the resolver verifies the chain
//! `master_pk → identity_key.master_sig → RelayKeyRecord.sig → relay_kem_pk`.
//! Crucially this is a SEPARATE DHT record — it does NOT touch the
//! [`IdentityDocument`] / [`MlKemKeyCert`] wire formats, so a node that
//! publishes one stays fully decodable on the universal ML-KEM resolve path.
//!
//! The KEM is algorithm-tagged (`relay_kem_algo`, `0` = X25519) so a future
//! post-quantum relay KEM can migrate without a wire break — mirroring the
//! `RendezvousAd` relay-KEM tag.
//!
//! ## Wire layout (canonical bytes, big-endian)
//!
//! ```text
//! [0..2] magic = "RK" u16
//! [2] version = 1 u8
//! [3..35] node_id [u8; 32]
//! [35] relay_kem_algo u8            (0 = X25519)
//! [..] relay_kem_pk_len u16 BE
//! [..] relay_kem_pk [u8; len]
//! [..] valid_from_unix u64 BE
//! [..] valid_until_unix u64 BE
//! [..] record_version u64 BE        (monotonic; later supersedes earlier)
//! [..] signing_identity_key_idx u16 BE
//! [..] sig_len u16 BE
//! [..] sig [u8; sig_len]
//! ```
//!
//! The signature covers `RELAY_KEY_SIG_CONTEXT || canonical_signing_bytes`.
//!
//! [`IdentityDocument`]: super::identity_document::IdentityDocument
//! [`MlKemKeyCert`]: super::mlkem_cert::MlKemKeyCert

use super::ProtoError;
use super::cursor::BoundedDecoder;

// ── Constants ────────────────────────────────────────────────────────────────

pub const RELAY_KEY_MAGIC: [u8; 2] = [b'R', b'K'];
pub const RELAY_KEY_V1: u8 = 1;
pub const RELAY_KEY_SIG_CONTEXT: &[u8] = b"veil.relay_key.v1";

/// X25519 relay-KEM algorithm tag (the only one today).
pub const RELAY_KEM_ALGO_X25519: u8 = 0;
/// Exact length of an X25519 public key.
pub const X25519_PK_LEN: usize = 32;

/// Upper bound on the wire payload. A 32-byte X25519 key with a Falcon-sized
/// signature is well under 1 KiB; 2 KiB leaves headroom for a future
/// post-quantum relay KEM pubkey.
pub const MAX_RELAY_KEY_BYTES: usize = 2 * 1024;
/// Structural cap on the relay-KEM pubkey length (algo-specific length is
/// enforced separately — X25519 must be exactly [`X25519_PK_LEN`]).
pub const MAX_RELAY_KEM_PK_BYTES: usize = 1500;
const MAX_SIG_BYTES: usize = 1024;

// ── Struct ───────────────────────────────────────────────────────────────────

/// A node's signed relay X25519 KEM public key, resolvable by `node_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayKeyRecord {
    pub node_id: [u8; 32],
    /// KEM algorithm tag (`0` = X25519). PQ-migration reserve.
    pub relay_kem_algo: u8,
    /// Relay/anonymity KEM public key. For `relay_kem_algo == 0` this is a
    /// 32-byte X25519 public key — validated at decode time.
    pub relay_kem_pk: Vec<u8>,
    pub valid_from_unix: u64,
    pub valid_until_unix: u64,
    /// Monotonic counter bumped on each republish so a later record
    /// supersedes an earlier one unambiguously.
    pub record_version: u64,
    /// Index into the current `IdentityDocument.identity_keys` of the subkey
    /// that signed this record.
    pub signing_identity_key_idx: u16,
    pub sig: Vec<u8>,
}

impl RelayKeyRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&RELAY_KEY_MAGIC);
        out.push(RELAY_KEY_V1);
        out.extend_from_slice(&self.node_id);
        out.push(self.relay_kem_algo);
        out.extend_from_slice(&(self.relay_kem_pk.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.relay_kem_pk);
        out.extend_from_slice(&self.valid_from_unix.to_be_bytes());
        out.extend_from_slice(&self.valid_until_unix.to_be_bytes());
        out.extend_from_slice(&self.record_version.to_be_bytes());
        out.extend_from_slice(&self.signing_identity_key_idx.to_be_bytes());
        out.extend_from_slice(&(self.sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Decode wire bytes into a fully-populated record. Structural invariants
    /// only — signature verification against the [`IdentityDocument`] is a
    /// separate step.
    ///
    /// [`IdentityDocument`]: super::identity_document::IdentityDocument
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() > MAX_RELAY_KEY_BYTES {
            return Err(ProtoError::Malformed(format!(
                "relay_key: oversized ({}B > {MAX_RELAY_KEY_BYTES}B)",
                buf.len()
            )));
        }
        let mut d = BoundedDecoder::new(buf);
        let magic = d.read_array::<2>("relay_key.magic")?;
        if magic != RELAY_KEY_MAGIC {
            return Err(ProtoError::Malformed("relay_key: bad magic".into()));
        }
        let version = d.read_u8("relay_key.version")?;
        if version != RELAY_KEY_V1 {
            return Err(ProtoError::Malformed(format!(
                "relay_key: unsupported version {version}"
            )));
        }
        let node_id = d.read_array::<32>("relay_key.node_id")?;
        let relay_kem_algo = d.read_u8("relay_key.kem_algo")?;
        let pk_len = d.read_u16("relay_key.kem_pk_len")? as usize;
        if pk_len == 0 || pk_len > MAX_RELAY_KEM_PK_BYTES {
            return Err(ProtoError::Malformed(format!(
                "relay_key: kem_pk_len {pk_len} out of range"
            )));
        }
        // Algo-specific length: X25519 keys are exactly 32 bytes. Unknown
        // (future) algos are accepted structurally so an old decoder doesn't
        // hard-reject a PQ record it simply won't use.
        if relay_kem_algo == RELAY_KEM_ALGO_X25519 && pk_len != X25519_PK_LEN {
            return Err(ProtoError::Malformed(format!(
                "relay_key: X25519 kem_pk_len {pk_len} != {X25519_PK_LEN}"
            )));
        }
        let relay_kem_pk = d.read_bytes(pk_len, "relay_key.kem_pk")?;
        let valid_from_unix = d.read_u64("relay_key.valid_from")?;
        let valid_until_unix = d.read_u64("relay_key.valid_until")?;
        if valid_until_unix < valid_from_unix {
            return Err(ProtoError::Malformed(
                "relay_key: valid_until < valid_from".into(),
            ));
        }
        let record_version = d.read_u64("relay_key.record_version")?;
        let signing_identity_key_idx = d.read_u16("relay_key.signing_key_idx")?;
        let sig_len = d.read_u16("relay_key.sig_len")? as usize;
        if sig_len == 0 || sig_len > MAX_SIG_BYTES {
            return Err(ProtoError::Malformed(format!(
                "relay_key: sig_len {sig_len} out of range"
            )));
        }
        let sig = d.read_bytes(sig_len, "relay_key.sig")?;

        d.assert_eof()
            .map_err(|e| ProtoError::Malformed(format!("relay_key: {e}")))?;

        Ok(Self {
            node_id,
            relay_kem_algo,
            relay_kem_pk,
            valid_from_unix,
            valid_until_unix,
            record_version,
            signing_identity_key_idx,
            sig,
        })
    }

    /// Canonical bytes the signature covers (everything minus the
    /// `sig_len + sig` trailer).
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut encoded = self.encode();
        let trailer = 2 + self.sig.len();
        encoded.truncate(encoded.len() - trailer);
        encoded
    }

    /// Bytes the signer signs: `RELAY_KEY_SIG_CONTEXT || canonical_signing_bytes`.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(RELAY_KEY_SIG_CONTEXT.len() + self.encoded_len());
        msg.extend_from_slice(RELAY_KEY_SIG_CONTEXT);
        msg.extend_from_slice(&self.canonical_signing_bytes());
        msg
    }

    fn encoded_len(&self) -> usize {
        2 + 1 + 32 + 1 + 2 + self.relay_kem_pk.len() + 8 + 8 + 8 + 2 + 2 + self.sig.len()
    }

    /// Is the record valid at `now_unix_secs`?
    pub fn is_valid_at(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.valid_from_unix && now_unix_secs <= self.valid_until_unix
    }

    /// DHT key under which this record is published. Keyed by `node_id` only —
    /// `record_version` is NOT in the key, so a republish replaces the previous
    /// record at the same slot (consumers rely on the signature + validity
    /// window + `record_version` to reject stale records).
    pub fn dht_key(node_id: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"veil.relay_key_dht.v1");
        h.update(node_id);
        *h.finalize().as_bytes()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> RelayKeyRecord {
        RelayKeyRecord {
            node_id: [0x11; 32],
            relay_kem_algo: RELAY_KEM_ALGO_X25519,
            relay_kem_pk: vec![0xAA; X25519_PK_LEN],
            valid_from_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 30 * 86_400,
            record_version: 3,
            signing_identity_key_idx: 0,
            sig: vec![0xCC; 64],
        }
    }

    #[test]
    fn codec_roundtrip() {
        let r = sample_record();
        let bytes = r.encode();
        assert_eq!(bytes.len(), r.encoded_len());
        let back = RelayKeyRecord::decode(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = sample_record().encode();
        bytes[0] = b'X';
        let err = RelayKeyRecord::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("bad magic"), "{err}");
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = sample_record().encode();
        bytes[2] = 99;
        let err = RelayKeyRecord::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("unsupported version"), "{err}");
    }

    #[test]
    fn rejects_wrong_x25519_length() {
        let mut r = sample_record();
        r.relay_kem_pk = vec![0; X25519_PK_LEN - 1];
        let bytes = r.encode();
        let err = RelayKeyRecord::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("X25519 kem_pk_len"), "{err}");
    }

    #[test]
    fn accepts_unknown_algo_for_pq_forward_compat() {
        let mut r = sample_record();
        r.relay_kem_algo = 1; // a hypothetical future PQ KEM
        r.relay_kem_pk = vec![0x55; 64]; // some other length
        let bytes = r.encode();
        let back = RelayKeyRecord::decode(&bytes).expect("unknown algo must decode structurally");
        assert_eq!(back.relay_kem_algo, 1);
        assert_eq!(back.relay_kem_pk.len(), 64);
    }

    #[test]
    fn rejects_valid_until_before_valid_from() {
        let mut r = sample_record();
        r.valid_from_unix = 2_000_000_000;
        r.valid_until_unix = 1_900_000_000;
        let bytes = r.encode();
        let err = RelayKeyRecord::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("valid_until < valid_from"), "{err}");
    }

    #[test]
    fn rejects_zero_sig() {
        let mut r = sample_record();
        r.sig = Vec::new();
        let bytes = r.encode();
        let err = RelayKeyRecord::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("sig_len"), "{err}");
    }

    #[test]
    fn rejects_oversized_input() {
        let bytes = vec![0u8; MAX_RELAY_KEY_BYTES + 1];
        let err = RelayKeyRecord::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("oversized"), "{err}");
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = sample_record().encode();
        bytes.push(0xFF);
        let err = RelayKeyRecord::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_truncated() {
        let bytes = sample_record().encode();
        for cut in [1, 5, 35, 50].iter().copied() {
            if cut < bytes.len() {
                let err = RelayKeyRecord::decode(&bytes[..cut]).unwrap_err();
                assert!(matches!(err, ProtoError::Malformed(_)), "cut={cut} {err:?}");
            }
        }
    }

    #[test]
    fn canonical_bytes_exclude_sig() {
        let r = sample_record();
        let full = r.encode();
        let canonical = r.canonical_signing_bytes();
        assert_eq!(&full[..canonical.len()], &canonical[..]);
        assert_eq!(full.len() - canonical.len(), 2 + r.sig.len());
    }

    #[test]
    fn signing_message_has_context_prefix() {
        let r = sample_record();
        assert!(r.signing_message().starts_with(RELAY_KEY_SIG_CONTEXT));
    }

    #[test]
    fn is_valid_at_window() {
        let r = sample_record();
        assert!(r.is_valid_at(r.valid_from_unix));
        assert!(r.is_valid_at(r.valid_until_unix));
        assert!(!r.is_valid_at(r.valid_from_unix - 1));
        assert!(!r.is_valid_at(r.valid_until_unix + 1));
    }

    #[test]
    fn dht_key_deterministic_and_distinct() {
        let a = RelayKeyRecord::dht_key(&[0x01; 32]);
        let b = RelayKeyRecord::dht_key(&[0x01; 32]);
        let c = RelayKeyRecord::dht_key(&[0x02; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
