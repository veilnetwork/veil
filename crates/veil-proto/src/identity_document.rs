//! IdentityDocument — DHT-stored sovereign identity record.
//!
//! An `IdentityDocument` binds a stable `node_id` to:
//! a master public key (root of trust, rarely used);
//! a list of per-instance identity subkeys, each certified by the master;
//! a document signature by any currently active subkey.
//!
//! Freshness is provided by a short `valid_until_unix` window — verifiers
//! reject documents whose window has expired. There is no separate
//! freshness signature, no document-level PoW, and no revocation list:
//! dropped those mechanisms in favour of a "republish often
//! revoke never" model. then made each per-device subkey carry
//! a deterministic `device_id = BLAKE3(device_pubkey)` plus its own
//! short `valid_until_unix` (default 7 days, re-issued at half-validity).
//!
//! See [`docs/identity-model.md`](../../../../docs/identity-model.md) for
//! the full specification and threat model.
//!
//! # Wire layout (canonical bytes, all integers big-endian)
//!
//! ```text
//! [0..2] magic = "ID" u16 BE
//! [2] version = 1 u8
//! [3..35] node_id [u8; 32]
//! [35] master_algo u8
//! [36..38] master_pubkey_len u16 BE
//! [38..38+L] master_pubkey [u8; L]
//! [...] issued_at_unix u64 BE
//! [...] valid_until_unix u64 BE
//! [...] sig_key_idx u16 BE
//! [...] identity_keys_count u8
//! [...] IdentityKey × count
//! [...] document_sig_len u16 BE
//! [last] document_sig [u8; S]
//! ```

use super::ProtoError;
use super::cursor::{read_array, read_bytes, read_u8, read_u16, read_u64};

// ── Magic, version, algorithms ────────────────────────────────────────────────

/// "ID" — identifies an IdentityDocument value in DHT.
pub const IDENTITY_DOCUMENT_MAGIC: [u8; 2] = [b'I', b'D'];

/// Wire-format version.
pub const IDENTITY_DOCUMENT_V1: u8 = 1;

/// Ed25519 algorithm byte.
pub const ALGO_ED25519: u8 = 0;
/// Falcon-512 algorithm byte.
pub const ALGO_FALCON512: u8 = 2;
/// Ed25519 + Falcon-512 hybrid algorithm byte. IdentityDocument
/// with `master_algo = ALGO_ED25519_FALCON512_HYBRID` carries a 929-byte
/// `master_pubkey` (32 ed + 897 falcon) and a `document_sig` produced by
/// the hybrid sign function (64 ed + 2 length prefix + ~666 falcon).
pub const ALGO_ED25519_FALCON512_HYBRID: u8 = 3;
/// Ed25519 + Falcon-1024 hybrid algorithm byte (Этап 10).  Higher-PQ
/// hybrid: IdentityDocument with `master_algo = ALGO_ED25519_FALCON1024_HYBRID`
/// carries а 1825-byte `master_pubkey` (32 ed + 1793 falcon) and а
/// `document_sig` produced by the hybrid-1024 sign function (64 ed +
/// 2 length prefix + ≤ 1462 falcon-1024).  Sovereign-identity creation
/// flow is а future slice — for now, the wire byte и crypto primitive
/// are present so config-signing / general signature operations can
/// adopt Falcon-1024 hybrid keys today.
pub const ALGO_ED25519_FALCON1024_HYBRID: u8 = 4;

// ── Domain-separated signing contexts ─────────────────────────────────────────

// b: CERTIFY_CONTEXT moved to `veil-types` so crypto can reference
// it without depending on `proto`. Re-exported here to preserve call sites.
pub use veil_types::CERTIFY_CONTEXT;
/// Context for document signature by the active identity subkey.
pub const DOC_SIG_CONTEXT: &[u8] = b"veil.identity_doc.v1";

// ── Policy caps ───────────────────────────────────────────────────────────────

/// Maximum concurrent identity subkeys.
pub const MAX_IDENTITY_KEYS: usize = 8;
/// Absolute upper bound on the IdentityDocument wire size accepted by
/// `decode`. Sized to hold a fully-rotated (MAX_IDENTITY_KEYS) Ed25519 +
/// Falcon-1024 hybrid document: master_pubkey 1825 B + up to 8 subkey certs
/// of ~1.6 KiB each (a hybrid master_sig is ~1.5 KiB) ⇒ ~15 KiB. 16 KiB is
/// the value the rest of the codebase already documents (see
/// `ipc::MAX_PAIR_CEREMONY_BYTES`). Matches the network-wide DHT value cap
/// (`budget::MAX_DHT_VALUE_BYTES`, also 16 KiB) so a fully-rotated multi-key
/// 1024-hybrid document both decodes locally AND is DHT-publishable.
pub const MAX_IDENTITY_DOCUMENT_BYTES: usize = 16 * 1024;
/// Maximum pubkey length accepted. Ed25519 = 32 B, Falcon-512 = 897 B,
/// Ed25519+Falcon-512 hybrid = 929 B, Ed25519+Falcon-1024 hybrid = 1825 B.
/// 2048 covers the largest (1825) with headroom.
const MAX_PUBKEY_BYTES: usize = 2048;
/// Maximum signature length accepted. Ed25519 = 64 B, Falcon-512 ≈ 690 B,
/// Ed25519+Falcon-512 hybrid ≈ 754 B, Ed25519+Falcon-1024 hybrid ≈ 1528 B
/// (ed 64 + len 2 + falcon ≤ 1462). 2048 covers the largest with headroom.
const MAX_SIG_BYTES: usize = 2048;
/// Maximum `valid_until - issued_at` window (30 days) — documents older than
/// this are stale and rejected.
pub const MAX_FRESHNESS_WINDOW_SECS: u64 = 30 * 24 * 3600;

/// Default lifetime of a single per-device delegation cert.
///
/// The master signs `(device_pubkey, valid_until_unix)` with this default
/// validity window. The maintenance loop re-issues at half-validity (~3.5
/// days remaining) so a long-running honest device never lapses, and a
/// compromised device's cert ages out within ≤ 7 days even without an
/// explicit revocation.
pub const DELEGATION_VALIDITY_SECS: u64 = 7 * 24 * 60 * 60;

// ── IdentityKey ───────────────────────────────────────────────────────────────

/// A per-device identity subkey, certified by the master via a `Delegation`
/// cert.
///
/// `device_id` is the deterministic per-device address `BLAKE3(pubkey)`;
/// the verifier checks that binding holds. The cert binds the subkey to
/// a specific device pubkey + a `valid_until_unix` window — a compromised
/// subkey naturally expires within ≤ `DELEGATION_VALIDITY_SECS` if the
/// master stops re-issuing, so there is no separate revocation channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKey {
    /// Signature algorithm ([`ALGO_ED25519`] / [`ALGO_FALCON512`]).
    pub algo: u8,
    /// Raw public key bytes.
    pub pubkey: Vec<u8>,
    /// Deterministic device address: `BLAKE3(pubkey)`. Verifier
    /// rejects any cert where this binding does not hold.
    pub device_id: [u8; 32],
    /// Unix timestamp when this subkey became valid.
    pub valid_from_unix: u64,
    /// Unix timestamp past which the master no longer endorses this
    /// subkey. Verifiers reject the cert once `now > valid_until_unix`.
    /// Default validity is `DELEGATION_VALIDITY_SECS` (7 days); the
    /// maintenance loop re-issues at half-validity.
    pub valid_until_unix: u64,
    /// Master signature over the certification message.
    ///
    /// Covers:
    /// ```text
    /// CERTIFY_CONTEXT
    /// || node_id
    /// || algo
    /// || len(pubkey) as u16 BE
    /// || pubkey
    /// || device_id
    /// || valid_from_unix
    /// || valid_until_unix
    /// ```
    pub master_sig: Vec<u8>,
}

impl IdentityKey {
    fn encoded_len(&self) -> usize {
        1       // algo
            + 2 // pubkey_len
            + self.pubkey.len()
            + 32 // device_id
            + 8  // valid_from_unix
            + 8  // valid_until_unix
            + 2  // master_sig_len
            + self.master_sig.len()
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.algo);
        out.extend_from_slice(&(self.pubkey.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.valid_from_unix.to_be_bytes());
        out.extend_from_slice(&self.valid_until_unix.to_be_bytes());
        out.extend_from_slice(&(self.master_sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.master_sig);
    }

    fn decode(buf: &[u8], pos: &mut usize) -> Result<Self, ProtoError> {
        let algo = read_u8(buf, pos, "identity_key.algo")?;
        let pubkey_len = read_u16(buf, pos, "identity_key.pubkey_len")? as usize;
        if pubkey_len == 0 || pubkey_len > MAX_PUBKEY_BYTES {
            return Err(ProtoError::Malformed(format!(
                "identity_key: pubkey_len out of range ({pubkey_len})"
            )));
        }
        let pubkey = read_bytes(buf, pos, pubkey_len, "identity_key.pubkey")?;
        let device_id = read_array::<32>(buf, pos, "identity_key.device_id")?;
        let valid_from_unix = read_u64(buf, pos, "identity_key.valid_from")?;
        let valid_until_unix = read_u64(buf, pos, "identity_key.valid_until")?;
        if valid_until_unix < valid_from_unix {
            return Err(ProtoError::Malformed(
                "identity_key: valid_until < valid_from".into(),
            ));
        }
        let sig_len = read_u16(buf, pos, "identity_key.master_sig_len")? as usize;
        if sig_len == 0 || sig_len > MAX_SIG_BYTES {
            return Err(ProtoError::Malformed(format!(
                "identity_key: master_sig_len out of range ({sig_len})"
            )));
        }
        let master_sig = read_bytes(buf, pos, sig_len, "identity_key.master_sig")?;
        Ok(Self {
            algo,
            pubkey,
            device_id,
            valid_from_unix,
            valid_until_unix,
            master_sig,
        })
    }

    /// The bytes that master_sk signs to produce `master_sig`.
    ///
    /// Callers (crypto/identity.rs helpers) use this to build + verify the
    /// certification signature.
    pub fn certify_message(&self, node_id: &[u8; 32]) -> Vec<u8> {
        let mut msg =
            Vec::with_capacity(CERTIFY_CONTEXT.len() + 32 + 1 + 2 + self.pubkey.len() + 32 + 8 + 8);
        msg.extend_from_slice(CERTIFY_CONTEXT);
        msg.extend_from_slice(node_id);
        msg.push(self.algo);
        msg.extend_from_slice(&(self.pubkey.len() as u16).to_be_bytes());
        msg.extend_from_slice(&self.pubkey);
        msg.extend_from_slice(&self.device_id);
        msg.extend_from_slice(&self.valid_from_unix.to_be_bytes());
        msg.extend_from_slice(&self.valid_until_unix.to_be_bytes());
        msg
    }
}

// ── IdentityDocument ──────────────────────────────────────────────────────────

/// Sovereign identity record stored in the DHT under key
/// `BLAKE3("veil.identity_dht.v1" || node_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityDocument {
    /// Stable identity address = `BLAKE3(master_pubkey)`. In standalone
    /// mode (single-device, no separate master) `device_pubkey ==
    /// master_pubkey` and so `device_id == node_id`.
    pub node_id: [u8; 32],
    /// Master signature algorithm.
    pub master_algo: u8,
    /// Master public key. Verifies node_id binding and certifies
    /// subkeys.
    pub master_pubkey: Vec<u8>,

    /// Unix timestamp when the current document was issued.
    pub issued_at_unix: u64,
    /// Unix timestamp past which verifiers reject the document. The
    /// owner must republish before this expires.
    pub valid_until_unix: u64,
    /// Index into [`Self::identity_keys`] identifying the subkey that
    /// produced [`Self::document_sig`].
    pub sig_key_idx: u16,
    /// Active identity subkeys (≤ `MAX_IDENTITY_KEYS`).
    pub identity_keys: Vec<IdentityKey>,
    /// Document signature by the active identity subkey.
    ///
    /// Covers the canonical bytes of every preceding field (everything in
    /// [`Self::canonical_signing_bytes`]).
    pub document_sig: Vec<u8>,
}

impl IdentityDocument {
    /// Encode the document into its wire representation.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&IDENTITY_DOCUMENT_MAGIC);
        out.push(IDENTITY_DOCUMENT_V1);
        out.extend_from_slice(&self.node_id);
        out.push(self.master_algo);
        out.extend_from_slice(&(self.master_pubkey.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.master_pubkey);
        out.extend_from_slice(&self.issued_at_unix.to_be_bytes());
        out.extend_from_slice(&self.valid_until_unix.to_be_bytes());
        out.extend_from_slice(&self.sig_key_idx.to_be_bytes());
        out.push(self.identity_keys.len() as u8);
        for k in &self.identity_keys {
            k.encode_into(&mut out);
        }
        out.extend_from_slice(&(self.document_sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.document_sig);
        out
    }

    /// Decode a wire buffer into an `IdentityDocument`. Enforces structural
    /// invariants only — signature verification is a separate step (see
    /// `node/identity/verify.rs`).
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() > MAX_IDENTITY_DOCUMENT_BYTES {
            return Err(ProtoError::Malformed(format!(
                "identity_document: oversized ({} > {MAX_IDENTITY_DOCUMENT_BYTES})",
                buf.len()
            )));
        }

        let mut pos = 0;

        if buf.get(pos..pos + 2) != Some(&IDENTITY_DOCUMENT_MAGIC[..]) {
            return Err(ProtoError::Malformed("identity_document: bad magic".into()));
        }
        pos += 2;

        let version = read_u8(buf, &mut pos, "identity_document.version")?;
        if version != IDENTITY_DOCUMENT_V1 {
            return Err(ProtoError::Malformed(format!(
                "identity_document: unsupported version {version}"
            )));
        }

        let node_id = read_array::<32>(buf, &mut pos, "identity_document.id")?;

        let master_algo = read_u8(buf, &mut pos, "identity_document.master_algo")?;
        let master_pubkey_len =
            read_u16(buf, &mut pos, "identity_document.master_pubkey_len")? as usize;
        if master_pubkey_len == 0 || master_pubkey_len > MAX_PUBKEY_BYTES {
            return Err(ProtoError::Malformed(format!(
                "identity_document: master_pubkey_len out of range ({master_pubkey_len})"
            )));
        }
        let master_pubkey = read_bytes(
            buf,
            &mut pos,
            master_pubkey_len,
            "identity_document.master_pubkey",
        )?;

        let issued_at_unix = read_u64(buf, &mut pos, "identity_document.issued_at")?;
        let valid_until_unix = read_u64(buf, &mut pos, "identity_document.valid_until")?;
        if valid_until_unix < issued_at_unix {
            return Err(ProtoError::Malformed(
                "identity_document: valid_until < issued_at".into(),
            ));
        }
        if valid_until_unix.saturating_sub(issued_at_unix) > MAX_FRESHNESS_WINDOW_SECS {
            return Err(ProtoError::Malformed(format!(
                "identity_document: freshness window > {MAX_FRESHNESS_WINDOW_SECS}s"
            )));
        }

        let sig_key_idx = read_u16(buf, &mut pos, "identity_document.sig_key_idx")?;

        let identity_keys_count = read_u8(buf, &mut pos, "identity_document.keys_count")?;
        if identity_keys_count as usize > MAX_IDENTITY_KEYS {
            return Err(ProtoError::Malformed(format!(
                "identity_document: identity_keys_count > {MAX_IDENTITY_KEYS}"
            )));
        }
        let mut identity_keys = Vec::with_capacity(identity_keys_count as usize);
        for _ in 0..identity_keys_count {
            identity_keys.push(IdentityKey::decode(buf, &mut pos)?);
        }

        if (sig_key_idx as usize) >= identity_keys.len() {
            return Err(ProtoError::Malformed(format!(
                "identity_document: sig_key_idx {sig_key_idx} out of bounds \
                 ({} keys)",
                identity_keys.len()
            )));
        }

        let doc_sig_len = read_u16(buf, &mut pos, "identity_document.doc_sig_len")? as usize;
        if doc_sig_len == 0 || doc_sig_len > MAX_SIG_BYTES {
            return Err(ProtoError::Malformed(format!(
                "identity_document: document_sig_len out of range ({doc_sig_len})"
            )));
        }
        let document_sig =
            read_bytes(buf, &mut pos, doc_sig_len, "identity_document.document_sig")?;

        // No trailing bytes allowed — prevents canonical-encoding drift.
        if pos != buf.len() {
            return Err(ProtoError::Malformed(format!(
                "identity_document: trailing {} bytes after decode",
                buf.len() - pos
            )));
        }

        Ok(Self {
            node_id,
            master_algo,
            master_pubkey,
            issued_at_unix,
            valid_until_unix,
            sig_key_idx,
            identity_keys,
            document_sig,
        })
    }

    /// Return the canonical bytes over [`Self::document_sig`] is
    /// computed: everything from magic through the last `IdentityKey` —
    /// i.e., the full encoding *minus* the `document_sig_len` and
    /// `document_sig` trailer.
    ///
    /// The signer builds `DOC_SIG_CONTEXT || canonical_signing_bytes` and
    /// signs that with the active identity_sk. Verifiers do the same.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut encoded = self.encode();
        // Strip the trailing `document_sig_len (2 B) + document_sig (N B)`.
        let trailer = 2 + self.document_sig.len();
        encoded.truncate(encoded.len() - trailer);
        encoded
    }

    /// DHT key under which this document is stored.
    pub fn dht_key(node_id: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"veil.identity_dht.v1");
        h.update(node_id);
        *h.finalize().as_bytes()
    }

    /// Estimate the encoded size of this document (cheap, no allocation
    /// beyond summing field lengths).
    pub fn encoded_len(&self) -> usize {
        2 + 1
            + 32
            + 1
            + 2
            + self.master_pubkey.len()
            + 8
            + 8
            + 2
            + 1
            + self
                .identity_keys
                .iter()
                .map(|k| k.encoded_len())
                .sum::<usize>()
            + 2
            + self.document_sig.len()
    }
}

// ── Decode helpers (buf, &mut pos) ────────────────────────────────────────────
//
// local `read_array` removed — use cursor::read_array
// (canonical primitive, identical semantics).

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity_key(device_tag: u8) -> IdentityKey {
        IdentityKey {
            algo: ALGO_ED25519,
            pubkey: vec![0xAA; 32],
            device_id: [device_tag; 32],
            valid_from_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + DELEGATION_VALIDITY_SECS,
            master_sig: vec![0xCC; 64],
        }
    }

    fn sample_document() -> IdentityDocument {
        IdentityDocument {
            node_id: [0x12; 32],
            master_algo: ALGO_ED25519,
            master_pubkey: vec![0xAB; 32],
            issued_at_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + MAX_FRESHNESS_WINDOW_SECS,
            sig_key_idx: 0,
            identity_keys: vec![sample_identity_key(0xAA)],
            document_sig: vec![0xDE; 64],
        }
    }

    #[test]
    fn encode_decode_roundtrip_minimal() {
        let doc = sample_document();
        let wire = doc.encode();
        assert_eq!(&wire[..2], &IDENTITY_DOCUMENT_MAGIC);
        assert_eq!(wire[2], IDENTITY_DOCUMENT_V1);
        let decoded = IdentityDocument::decode(&wire).expect("roundtrip");
        assert_eq!(decoded, doc);
    }

    #[test]
    fn encoded_len_matches_encode() {
        let doc = sample_document();
        assert_eq!(doc.encode().len(), doc.encoded_len());
    }

    #[test]
    fn bad_magic_rejected() {
        let mut wire = sample_document().encode();
        wire[0] = 0xFF;
        let err = IdentityDocument::decode(&wire).unwrap_err();
        assert!(err.to_string().contains("bad magic"), "got: {err}");
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut wire = sample_document().encode();
        wire[2] = 99;
        let err = IdentityDocument::decode(&wire).unwrap_err();
        assert!(
            err.to_string().contains("unsupported version"),
            "got: {err}"
        );
    }

    #[test]
    fn truncated_rejected() {
        let wire = sample_document().encode();
        let err = IdentityDocument::decode(&wire[..50]).unwrap_err();
        assert!(err.to_string().contains("truncated"), "got: {err}");
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut wire = sample_document().encode();
        wire.push(0xFF);
        let err = IdentityDocument::decode(&wire).unwrap_err();
        assert!(err.to_string().contains("trailing"), "got: {err}");
    }

    #[test]
    fn oversized_rejected() {
        let mut wire = vec![0u8; MAX_IDENTITY_DOCUMENT_BYTES + 1];
        wire[0] = b'I';
        wire[1] = b'D';
        let err = IdentityDocument::decode(&wire).unwrap_err();
        assert!(err.to_string().contains("oversized"), "got: {err}");
    }

    #[test]
    fn excessive_keys_rejected() {
        let mut doc = sample_document();
        doc.identity_keys = (0..10).map(|i| sample_identity_key(i as u8)).collect();
        // The struct itself allows this, but encoded bytes claim count=10
        // and decode enforces the cap.
        let wire = doc.encode();
        let err = IdentityDocument::decode(&wire).unwrap_err();
        assert!(
            err.to_string().contains("identity_keys_count"),
            "got: {err}"
        );
    }

    #[test]
    fn valid_until_before_issued_rejected() {
        let mut doc = sample_document();
        doc.valid_until_unix = doc.issued_at_unix - 1;
        let wire = doc.encode();
        let err = IdentityDocument::decode(&wire).unwrap_err();
        assert!(
            err.to_string().contains("valid_until < issued_at"),
            "got: {err}"
        );
    }

    #[test]
    fn excessive_freshness_window_rejected() {
        let mut doc = sample_document();
        doc.valid_until_unix = doc.issued_at_unix + MAX_FRESHNESS_WINDOW_SECS + 1;
        let wire = doc.encode();
        let err = IdentityDocument::decode(&wire).unwrap_err();
        assert!(err.to_string().contains("freshness window"), "got: {err}");
    }

    #[test]
    fn sig_key_idx_out_of_bounds_rejected() {
        let mut doc = sample_document();
        doc.sig_key_idx = 5; // only 1 key present
        let wire = doc.encode();
        let err = IdentityDocument::decode(&wire).unwrap_err();
        assert!(err.to_string().contains("sig_key_idx"), "got: {err}");
    }

    #[test]
    fn canonical_signing_bytes_excludes_doc_sig() {
        let doc = sample_document();
        let canonical = doc.canonical_signing_bytes();
        let full = doc.encode();
        // Canonical bytes are a prefix of the encoded document.
        assert!(full.starts_with(&canonical));
        // The missing trailer is exactly doc_sig_len_prefix + doc_sig.
        assert_eq!(full.len() - canonical.len(), 2 + doc.document_sig.len());
    }

    #[test]
    fn identity_key_certify_message_format() {
        let key = sample_identity_key(0x77);
        let node_id: [u8; 32] = [0x11; 32];
        let msg = key.certify_message(&node_id);
        assert!(msg.starts_with(CERTIFY_CONTEXT));
        let after_ctx = &msg[CERTIFY_CONTEXT.len()..];
        assert_eq!(&after_ctx[..32], &node_id);
        assert_eq!(after_ctx[32], key.algo);
        assert_eq!(&after_ctx[33..35], &(key.pubkey.len() as u16).to_be_bytes());
    }

    #[test]
    fn dht_key_deterministic_and_distinct() {
        let a = IdentityDocument::dht_key(&[0x01; 32]);
        let b = IdentityDocument::dht_key(&[0x01; 32]);
        let c = IdentityDocument::dht_key(&[0x02; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
