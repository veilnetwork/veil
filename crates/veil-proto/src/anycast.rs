//! Anycast service-address protocol.
//!
//! An `AnycastRecord` is stored in the DHT under a key derived from the
//! service tag so that any node can advertise itself as a provider of a
//! given service and any other node can find the closest provider.
//!
//! # DHT key derivation
//! ```text
//! key = BLAKE3("anycast:v1:" ‖ service_tag[4])
//! ```
//!
//! # Wire format of `AnycastRecord`
//! ```text
//! 0-1 magic [0x41, 0x43] "AC"
//! 2-5 service_tag [u8; 4]
//! 6-37 node_id [u8; 32]
//! 38-39 score u16 BE (routing score; 0 = best)
//! 40-43 ttl u32 BE (seconds until expiry)
//! ```
//! Total: 44 bytes per record.
//!
//! # DHT value format
//! Multiple records can be stored under the same DHT key (one per advertising node).
//! The DHT value is a concatenation of `AnycastRecord` entries, each 44 bytes.
//! Up to `MAX_ANYCAST_CANDIDATES` records are stored; older entries are evicted
//! when the list is full.

use crate::ProtoError;

/// Magic bytes identifying a **v1 (unsigned)** AnycastRecord value in DHT.
/// V1 records carry no owner signature — `score` is peer-controlled.
/// Kept readable for backward compatibility with existing deployments.
pub const ANYCAST_MAGIC: [u8; 2] = [0x41, 0x43]; // "AC"

/// Magic bytes identifying a **v2 (owner-signed)** AnycastRecord.
/// V2 appends an Ed25519 signature over the canonical bytes, allowing the
/// resolver to reject records published under a different `node_id` than
/// the signing key proves ownership of. See module security doc.
pub const ANYCAST_MAGIC_V2: [u8; 2] = [0x41, 0x44]; // "AD"

/// Magic bytes identifying a **v3 (algo-tagged, owner-signed)** AnycastRecord.
/// V3 generalizes v2 to ANY signature algorithm (Ed25519 / Falcon-512 / hybrid)
/// so a PQ-only sovereign identity can own-sign its anycast records. The owner
/// pubkey and signature are length-prefixed (algo-dependent sizes), and a
/// 1-byte `sig_algo` selects the algorithm. INVARIANT: v3 carries a NON-Ed25519
/// algo — plain Ed25519 stays on the fixed-size v2 wire for backward-compat with
/// resolvers that predate v3 (they skip the unknown v3 magic).
pub const ANYCAST_MAGIC_V3: [u8; 2] = [0x41, 0x45]; // "AE"

/// Wire size of a **v1 (unsigned)** record.
pub const ANYCAST_RECORD_SIZE: usize = 44;

/// Wire size of a **v2 (signed)** record.
/// Layout: 44 (v1 fields) + 32 (owner_pubkey) + 1 (sig_key_idx) + 64 (sig) = 141.
pub const ANYCAST_RECORD_V2_SIZE: usize = 141;

/// Upper bound on a v3 owner-pubkey length (Falcon-512 = 897 B; hybrid encodings
/// are larger). Bounds the pre-alloc / scan against a malformed length field.
pub const MAX_ANYCAST_PUBKEY_LEN: usize = 4096;

/// Upper bound on a v3 signature length (Falcon-512 detached ≈ 690 B; hybrid is
/// Ed25519(64) + len-prefixed Falcon). Same anti-amplification rationale.
pub const MAX_ANYCAST_SIG_LEN: usize = 4096;

/// Fixed prefix length of a v3 record up to (not including) `owner_pubkey`:
/// 2 magic + 4 service_tag + 32 node_id + 2 score + 4 ttl + 1 sig_algo + 2
/// pubkey_len = 47.
const ANYCAST_V3_PREFIX_LEN: usize = 47;

/// Maximum number of candidate records stored per service tag in the DHT.
pub const MAX_ANYCAST_CANDIDATES: usize = 32;

// ── AnycastRecord ─────────────────────────────────────────────────────────────

/// Owner-binding signature payload for a v2/v3 `AnycastRecord`.
///
/// `owner_pubkey` is the verifying key that signed the canonical bytes
/// (everything in the record except the signature itself). Caller is
/// responsible for making sure this key is bound to `node_id` — typically
/// `node_id == BLAKE3(owner_pubkey)`, but advanced sovereign-identity flows may
/// use a subkey indicated by `sig_key_idx`.
///
/// `sig_algo` is a [`veil_types::SignatureAlgorithm::wire_byte`]: Ed25519
/// records ride the fixed-size v2 wire (32-byte pubkey, 64-byte sig); any other
/// algorithm (Falcon-512, hybrid) rides the length-prefixed v3 wire. The struct
/// holds `Vec`s so a single shape covers both — for v2 they are always exactly
/// 32 / 64 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnycastRecordSig {
    /// Signature algorithm wire-byte ([`veil_types::SignatureAlgorithm::wire_byte`]).
    pub sig_algo: u8,
    /// Verifying key bytes that produced `signature` (algo-dependent length).
    pub owner_pubkey: Vec<u8>,
    /// Which subkey index in the owner's identity document signed this
    /// record. `0` for nodes without sovereign-identity multi-key setup.
    pub sig_key_idx: u8,
    /// Signature over the canonical bytes (fields up to and including
    /// `sig_key_idx`), algo-dependent length.
    pub signature: Vec<u8>,
}

/// A single anycast service advertisement stored in the DHT.
///
/// When `signature` is `Some(...)`, this is a v2 record (wire size
/// [`ANYCAST_RECORD_V2_SIZE`] = 141 B) and verifiers MUST check the
/// embedded Ed25519 signature before trusting any field. When `None`,
/// this is a legacy v1 record ([`ANYCAST_RECORD_SIZE`] = 44 B) with no
/// owner binding — see the [crate-level security docs] for handling.
///
/// [crate-level security docs]: crate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnycastRecord {
    /// 4-byte application-defined service tag (e.g. b"mbox", b"gate", b"brg\0").
    pub service_tag: [u8; 4],
    /// Advertising node's `node_id`.
    pub node_id: [u8; 32],
    /// Routing score hint (lower = better); 0 means "no score available".
    pub score: u16,
    /// TTL in seconds from the time of advertisement.
    pub ttl: u32,
    /// Owner-binding signature (v2 only). `None` ⇒ legacy v1 record.
    pub signature: Option<AnycastRecordSig>,
}

/// Whether a `sig_algo` wire-byte denotes Ed25519 (the v2 algorithm). `1` is the
/// canonical Ed25519 wire-byte; `0` is accepted as a legacy alias (see
/// [`veil_types::SignatureAlgorithm::from_wire_byte`]). Ed25519 records use the
/// fixed-size v2 wire; everything else uses v3.
fn is_ed25519_wire_algo(sig_algo: u8) -> bool {
    sig_algo == 0 || sig_algo == 1
}

impl AnycastRecord {
    /// Compute the DHT key for the given service tag.
    ///
    /// All nodes advertising the same `service_tag` store records under
    /// this key so that DHT lookups converge on the same bucket.
    pub fn dht_key(service_tag: [u8; 4]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"anycast:v1:");
        h.update(&service_tag);
        *h.finalize().as_bytes()
    }

    /// Encode the record. Unsigned → v1 (44 B). Signed with Ed25519 → v2
    /// (141 B, backward-compatible). Signed with any other algorithm
    /// (Falcon-512, hybrid) → v3 (length-prefixed, variable). Returns a
    /// `Vec<u8>` because the length depends on version.
    pub fn encode(&self) -> Vec<u8> {
        match &self.signature {
            Some(sig) if is_ed25519_wire_algo(sig.sig_algo) => {
                let mut buf = Vec::with_capacity(ANYCAST_RECORD_V2_SIZE);
                self.encode_canonical_v2(&mut buf, sig);
                buf.extend_from_slice(&sig.signature);
                buf
            }
            Some(sig) => {
                let mut buf = Vec::with_capacity(
                    ANYCAST_V3_PREFIX_LEN + sig.owner_pubkey.len() + 1 + 2 + sig.signature.len(),
                );
                self.encode_canonical_v3(&mut buf, sig);
                buf.extend_from_slice(&(sig.signature.len() as u16).to_be_bytes());
                buf.extend_from_slice(&sig.signature);
                buf
            }
            None => {
                let mut buf = Vec::with_capacity(ANYCAST_RECORD_SIZE);
                buf.extend_from_slice(&ANYCAST_MAGIC);
                buf.extend_from_slice(&self.service_tag);
                buf.extend_from_slice(&self.node_id);
                buf.extend_from_slice(&self.score.to_be_bytes());
                buf.extend_from_slice(&self.ttl.to_be_bytes());
                buf
            }
        }
    }

    /// Canonical bytes the embedded signature covers (everything EXCEPT the
    /// signature itself), in the v2 or v3 layout matching how [`Self::encode`]
    /// serializes this record. Empty for an unsigned (v1) record. Exposed so the
    /// algo-generic verifier (in `veil-anycast`, which has the PQ crypto deps)
    /// can reconstruct exactly what was signed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let Some(sig) = &self.signature else {
            return Vec::new();
        };
        let mut buf = Vec::new();
        if is_ed25519_wire_algo(sig.sig_algo) {
            self.encode_canonical_v2(&mut buf, sig);
        } else {
            self.encode_canonical_v3(&mut buf, sig);
        }
        buf
    }

    /// Write the canonical-bytes prefix of a v3 record (magic … sig_key_idx).
    fn encode_canonical_v3(&self, buf: &mut Vec<u8>, sig: &AnycastRecordSig) {
        buf.extend_from_slice(&ANYCAST_MAGIC_V3);
        buf.extend_from_slice(&self.service_tag);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&self.score.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        buf.push(sig.sig_algo);
        buf.extend_from_slice(&(sig.owner_pubkey.len() as u16).to_be_bytes());
        buf.extend_from_slice(&sig.owner_pubkey);
        buf.push(sig.sig_key_idx);
    }

    /// Write the canonical-bytes prefix of a v2 record (77 bytes — everything
    /// except the signature itself). This is exactly the byte sequence
    /// that the Ed25519 signature covers.
    fn encode_canonical_v2(&self, buf: &mut Vec<u8>, sig: &AnycastRecordSig) {
        buf.extend_from_slice(&ANYCAST_MAGIC_V2);
        buf.extend_from_slice(&self.service_tag);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&self.score.to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());
        buf.extend_from_slice(&sig.owner_pubkey);
        buf.push(sig.sig_key_idx);
    }

    /// Decode a record. Auto-detects v1 vs v2 by magic bytes. v2 records
    /// have their embedded signature integrity-checked (the signature is
    /// stored intact for caller-side `verify_signature`).
    ///
    /// **This function does NOT verify the signature** — call
    /// [`Self::verify_signature`] separately if you want trust enforcement.
    /// Decode-only allows downstream code to receive both signed and unsigned
    /// records and make policy decisions about which to trust.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 2 {
            return Err(ProtoError::BufferTooShort {
                need: 2,
                got: buf.len(),
            });
        }
        match (buf[0], buf[1]) {
            (a, b) if [a, b] == ANYCAST_MAGIC => Self::decode_v1(buf),
            (a, b) if [a, b] == ANYCAST_MAGIC_V2 => Self::decode_v2(buf),
            (a, b) if [a, b] == ANYCAST_MAGIC_V3 => Self::decode_v3(buf),
            _ => Err(ProtoError::InvalidMagic([buf[0], buf[1], 0, 0])),
        }
    }

    /// Total wire length of the record that starts at `buf[0]`, without fully
    /// decoding it. Used by the list decoder to step over variable-length v3
    /// records. Returns `None` on unknown magic or a truncated header.
    pub fn wire_len(buf: &[u8]) -> Option<usize> {
        if buf.len() < 2 {
            return None;
        }
        match (buf[0], buf[1]) {
            (a, b) if [a, b] == ANYCAST_MAGIC => Some(ANYCAST_RECORD_SIZE),
            (a, b) if [a, b] == ANYCAST_MAGIC_V2 => Some(ANYCAST_RECORD_V2_SIZE),
            (a, b) if [a, b] == ANYCAST_MAGIC_V3 => {
                // [..45 fixed..][pubkey_len u16 @45][pubkey][sig_key_idx u8]
                // [sig_len u16][sig]
                let pubkey_len = super::read_u16_be(buf, 45).ok()? as usize;
                if pubkey_len > MAX_ANYCAST_PUBKEY_LEN {
                    return None;
                }
                let sig_len_off = ANYCAST_V3_PREFIX_LEN
                    .checked_add(pubkey_len)?
                    .checked_add(1)?;
                let sig_len = super::read_u16_be(buf, sig_len_off).ok()? as usize;
                if sig_len > MAX_ANYCAST_SIG_LEN {
                    return None;
                }
                sig_len_off.checked_add(2)?.checked_add(sig_len)
            }
            _ => None,
        }
    }

    fn decode_v1(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < ANYCAST_RECORD_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: ANYCAST_RECORD_SIZE,
                got: buf.len(),
            });
        }
        let service_tag = super::read_array::<4>(buf, 2)?;
        let node_id = super::read_array::<32>(buf, 6)?;
        let score = super::read_u16_be(buf, 38)?;
        let ttl = super::read_u32_be(buf, 40)?;
        Ok(AnycastRecord {
            service_tag,
            node_id,
            score,
            ttl,
            signature: None,
        })
    }

    fn decode_v2(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < ANYCAST_RECORD_V2_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: ANYCAST_RECORD_V2_SIZE,
                got: buf.len(),
            });
        }
        let service_tag = super::read_array::<4>(buf, 2)?;
        let node_id = super::read_array::<32>(buf, 6)?;
        let score = super::read_u16_be(buf, 38)?;
        let ttl = super::read_u32_be(buf, 40)?;
        let owner_pubkey = super::read_array::<32>(buf, 44)?;
        let sig_key_idx = buf[76];
        let signature = super::read_array::<64>(buf, 77)?;
        Ok(AnycastRecord {
            service_tag,
            node_id,
            score,
            ttl,
            signature: Some(AnycastRecordSig {
                // v2 wire carries no algo byte — it is Ed25519 by definition.
                sig_algo: 1,
                owner_pubkey: owner_pubkey.to_vec(),
                sig_key_idx,
                signature: signature.to_vec(),
            }),
        })
    }

    fn decode_v3(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < ANYCAST_V3_PREFIX_LEN {
            return Err(ProtoError::BufferTooShort {
                need: ANYCAST_V3_PREFIX_LEN,
                got: buf.len(),
            });
        }
        let service_tag = super::read_array::<4>(buf, 2)?;
        let node_id = super::read_array::<32>(buf, 6)?;
        let score = super::read_u16_be(buf, 38)?;
        let ttl = super::read_u32_be(buf, 40)?;
        let sig_algo = buf[44];
        // INVARIANT: v3 carries a NON-Ed25519 algo (Ed25519 belongs on the v2
        // wire). This keeps the v2/v3 split unambiguous so the canonical bytes
        // a verifier reconstructs always match what was signed.
        if is_ed25519_wire_algo(sig_algo) {
            return Err(ProtoError::Malformed(
                "anycast v3 record must not carry an Ed25519 algo (use v2)".to_string(),
            ));
        }
        let pubkey_len = super::read_u16_be(buf, 45)? as usize;
        if pubkey_len > MAX_ANYCAST_PUBKEY_LEN {
            return Err(ProtoError::Malformed(format!(
                "anycast v3 owner_pubkey too long: {pubkey_len} > {MAX_ANYCAST_PUBKEY_LEN}"
            )));
        }
        let pubkey_end = ANYCAST_V3_PREFIX_LEN + pubkey_len;
        // need pubkey + sig_key_idx(1) + sig_len(2)
        if buf.len() < pubkey_end + 3 {
            return Err(ProtoError::BufferTooShort {
                need: pubkey_end + 3,
                got: buf.len(),
            });
        }
        let owner_pubkey = buf[ANYCAST_V3_PREFIX_LEN..pubkey_end].to_vec();
        let sig_key_idx = buf[pubkey_end];
        let sig_len = super::read_u16_be(buf, pubkey_end + 1)? as usize;
        if sig_len > MAX_ANYCAST_SIG_LEN {
            return Err(ProtoError::Malformed(format!(
                "anycast v3 signature too long: {sig_len} > {MAX_ANYCAST_SIG_LEN}"
            )));
        }
        let sig_start = pubkey_end + 3;
        let sig_end = sig_start + sig_len;
        // Exact length: the caller (list decoder) slices to `wire_len`, so the
        // record must be precisely its declared size — reject trailing bytes.
        if buf.len() != sig_end {
            return Err(ProtoError::Malformed(format!(
                "anycast v3 wrong length: have {}, expected exactly {sig_end}",
                buf.len()
            )));
        }
        Ok(AnycastRecord {
            service_tag,
            node_id,
            score,
            ttl,
            signature: Some(AnycastRecordSig {
                sig_algo,
                owner_pubkey,
                sig_key_idx,
                signature: buf[sig_start..sig_end].to_vec(),
            }),
        })
    }

    /// Verify the embedded **Ed25519** owner-signature (v2 records, or a v3
    /// record whose `sig_algo` is Ed25519). Returns `Ok(())` if the signature
    /// is valid under `signature.owner_pubkey`; `Err` otherwise. Unsigned (v1)
    /// records, or records signed with a NON-Ed25519 algorithm, return `Err` —
    /// the latter must be verified through the algo-generic path in
    /// `veil-anycast` (which has the PQ crypto deps). `veil-proto` deliberately
    /// stays crypto-light (Ed25519 only).
    ///
    /// Caller is responsible separately for checking that
    /// `signature.owner_pubkey` actually corresponds to the claimed
    /// `node_id` (typically via a sovereign-identity-document lookup).
    /// Without that binding check, an attacker can publish a valid
    /// signature under an unrelated key claiming a target node_id — the
    /// signature itself is valid but the binding is forged.
    pub fn verify_signature(&self) -> Result<(), ProtoError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Some(sig) = &self.signature else {
            return Err(ProtoError::Malformed(
                "anycast record is unsigned (v1); cannot verify".to_string(),
            ));
        };
        if !is_ed25519_wire_algo(sig.sig_algo) {
            return Err(ProtoError::Malformed(format!(
                "anycast record: non-Ed25519 algo {} — verify via the algo-generic path",
                sig.sig_algo,
            )));
        }
        let pk: [u8; 32] = sig.owner_pubkey.as_slice().try_into().map_err(|_| {
            ProtoError::Malformed(
                "anycast record: Ed25519 owner_pubkey must be 32 bytes".to_string(),
            )
        })?;
        let sig_bytes: [u8; 64] = sig.signature.as_slice().try_into().map_err(|_| {
            ProtoError::Malformed("anycast record: Ed25519 signature must be 64 bytes".to_string())
        })?;
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| {
            ProtoError::Malformed("anycast record: invalid Ed25519 owner_pubkey".to_string())
        })?;
        let canonical = self.canonical_bytes();
        let sig_obj = Signature::from_bytes(&sig_bytes);
        vk.verify(&canonical, &sig_obj).map_err(|_| {
            ProtoError::Malformed(
                "anycast record: Ed25519 signature verification failed".to_string(),
            )
        })
    }

    /// Verify the **owner-binding** in addition to the embedded signature —
    /// confirms that the signer (whose pubkey is embedded in `signature.owner_pubkey`)
    /// is actually the same identity as the claimed `node_id`.
    ///
    /// Without this check, [`Self::verify_signature`] alone only proves
    /// integrity: an attacker can mint a valid signature under their OWN
    /// key while putting a victim's `node_id` in the record body.  The
    /// signature passes, the binding is a forgery.  See the crate-level
    /// security docs in `veil-anycast` for the full attack model.
    ///
    /// ## Binding contract
    ///
    /// This method accepts ONLY the "self-signed" binding case:
    /// 1. The record carries a v2 signature (calls [`Self::verify_signature`] first).
    /// 2. `signature.sig_key_idx == 0` — i.e. the signer is using its
    ///    PRIMARY (root) Ed25519 key, NOT a sovereign-identity subkey.
    /// 3. `node_id == BLAKE3(signature.owner_pubkey)` — i.e. the claimed
    ///    `node_id` is provably derived from the embedded pubkey via the
    ///    standard 32-byte BLAKE3 hash used everywhere in veil's
    ///    identity layer.
    ///
    /// `sig_key_idx > 0` (multi-device sovereign identity flow with subkeys)
    /// is rejected here because verifying it requires an async DHT lookup
    /// of the identity document to check `identity_keys[sig_key_idx] ==
    /// owner_pubkey`, which doesn't fit a synchronous record-validator API.
    /// Callers that need to support subkey-signed records must either:
    /// * Use [`Self::verify_signature`] alone + perform the identity-doc
    ///   lookup themselves, OR
    /// * Use the daemon's verified-identity-resolve path (which already
    ///   does this composition asynchronously).
    ///
    /// Audit batch 2026-05-23: added to close the "anycast SignedOnly
    /// proves signature but not binding" finding — the cross-audit pointed
    /// out that the cfg-level SignedOnly knob would NOT prevent a sybil
    /// from minting a valid signature under their own key while claiming
    /// another node's `node_id`.
    pub fn verify_owner_binding(&self) -> Result<(), ProtoError> {
        self.verify_signature()?;
        // `verify_signature` already errored when signature is None, but
        // the borrow-checker doesn't know that — so unwrap is safe here.
        let sig = self.signature.as_ref().ok_or_else(|| {
            ProtoError::Malformed(
                "anycast record: owner-binding requires a v2 signature".to_string(),
            )
        })?;
        if sig.sig_key_idx != 0 {
            return Err(ProtoError::Malformed(format!(
                "anycast record: owner-binding only supports sig_key_idx == 0 \
                 (got {}); subkey-signed records require async identity-document \
                 lookup, use verify_signature + caller-side binding check instead",
                sig.sig_key_idx,
            )));
        }
        let derived_node_id = blake3::hash(sig.owner_pubkey.as_slice());
        if derived_node_id.as_bytes() != &self.node_id {
            return Err(ProtoError::Malformed(
                "anycast record: BLAKE3(owner_pubkey) != node_id — \
                 signature valid but owner-binding is forged"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Construct a v2 (signed) record. Caller supplies the Ed25519
    /// signing key; pubkey is derived and embedded automatically.
    pub fn sign(
        service_tag: [u8; 4],
        node_id: [u8; 32],
        score: u16,
        ttl: u32,
        sig_key_idx: u8,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;
        let owner_pubkey = signing_key.verifying_key().to_bytes().to_vec();
        // Build placeholder sig to get canonical bytes via encode_canonical_v2.
        let mut placeholder = Self {
            service_tag,
            node_id,
            score,
            ttl,
            signature: Some(AnycastRecordSig {
                sig_algo: 1, // Ed25519
                owner_pubkey,
                sig_key_idx,
                signature: vec![0u8; 64],
            }),
        };
        // unwrap: we just set signature to Some above.
        let canonical = placeholder.canonical_bytes();
        let sig_bytes = signing_key.sign(&canonical).to_bytes().to_vec();
        // Replace placeholder signature with actual signature.
        if let Some(s) = placeholder.signature.as_mut() {
            s.signature = sig_bytes;
        }
        placeholder
    }
}

// ── AnycastList — DHT value containing multiple records ───────────────────────

/// A list of `AnycastRecord` entries stored as a single DHT value.
///
/// Encoding: concatenation of records, each `ANYCAST_RECORD_SIZE` bytes.
/// Empty list = empty byte slice.
#[derive(Debug, Clone, Default)]
pub struct AnycastList(pub Vec<AnycastRecord>);

impl AnycastList {
    /// Decode all records from a DHT value blob.
    ///
    /// Auto-detects v1 (44 B), v2 (141 B) and v3 (variable, length-prefixed)
    /// records by magic prefix. Silently skips records that fail to decode
    /// (wrong magic, stale format, truncated tail). DOES NOT verify signatures
    /// here — caller decides trust policy.
    pub fn decode(blob: &[u8]) -> Self {
        let mut records = Vec::new();
        let mut pos = 0;
        while pos + 2 <= blob.len() {
            // `wire_len` reads only the header/length fields to size the record
            // (constant for v1/v2, length-prefixed for v3).
            let Some(rec_size) = AnycastRecord::wire_len(&blob[pos..]) else {
                // Unknown magic / truncated header — abort to avoid sliding
                // into garbage.
                break;
            };
            if pos + rec_size > blob.len() {
                // Truncated tail; stop parsing.
                break;
            }
            if let Ok(r) = AnycastRecord::decode(&blob[pos..pos + rec_size]) {
                records.push(r);
            }
            pos += rec_size;
        }
        AnycastList(records)
    }

    /// Encode all records into a DHT value blob. Length per record varies
    /// by version (v1 = 44 B, v2 = 141 B); total is the sum.
    pub fn encode(&self) -> Vec<u8> {
        // Conservative upper bound: assume all v2.
        let mut buf = Vec::with_capacity(self.0.len() * ANYCAST_RECORD_V2_SIZE);
        for r in &self.0 {
            buf.extend_from_slice(&r.encode());
        }
        buf
    }

    /// Add or update a record for `node_id`.
    ///
    /// If a record with the same `node_id` already exists, it is replaced.
    /// If the list is at `MAX_ANYCAST_CANDIDATES`, the oldest entry (last in
    /// the slice) is evicted to make room.
    pub fn upsert(&mut self, record: AnycastRecord) {
        if let Some(pos) = self.0.iter().position(|r| r.node_id == record.node_id) {
            self.0[pos] = record;
        } else {
            if self.0.len() >= MAX_ANYCAST_CANDIDATES {
                self.0.pop(); // evict last (oldest) entry
            }
            self.0.insert(0, record); // newest first
        }
    }
}

// ── IPC payloads ──────────────────────────────────────────────────────────────

/// IPC request: resolve a service tag to the nearest N candidate nodes.
///
/// Wire layout:
/// ```text
/// [0..4] service_tag [u8; 4]
/// [4] max_results u8 (1..=32; clamped to MAX_ANYCAST_CANDIDATES)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnycastResolvePayload {
    /// 4-byte application-defined service tag to resolve.
    pub service_tag: [u8; 4],
    /// Upper bound on candidate count; clamped to `MAX_ANYCAST_CANDIDATES`.
    pub max_results: u8,
}

impl AnycastResolvePayload {
    /// Fixed wire size (`service_tag` + `max_results`).
    pub const WIRE_SIZE: usize = 5;

    /// Encode to the 5-byte wire layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..4].copy_from_slice(&self.service_tag);
        buf[4] = self.max_results;
        buf
    }

    /// Decode a 5-byte payload; clamps `max_results` to
    /// `[1, MAX_ANYCAST_CANDIDATES]`.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let service_tag = super::read_array::<4>(buf, 0)?;
        let max_results = buf[4].max(1).min(MAX_ANYCAST_CANDIDATES as u8);
        Ok(AnycastResolvePayload {
            service_tag,
            max_results,
        })
    }
}

/// IPC response: resolved anycast candidates for a service tag.
///
/// Wire layout:
/// ```text
/// [0..4] service_tag [u8; 4]
/// [4] count u8
/// [5..] node_ids count × [u8; 32] (sorted best-first by routing score)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnycastResultPayload {
    /// The service tag these candidates advertise.
    pub service_tag: [u8; 4],
    /// Candidate `node_id`s sorted by routing score (best first).
    pub node_ids: Vec<[u8; 32]>,
}

impl AnycastResultPayload {
    /// Encode to the wire; caller-supplied lists longer than
    /// `MAX_ANYCAST_CANDIDATES` are truncated silently.
    pub fn encode(&self) -> Vec<u8> {
        let count = self.node_ids.len().min(MAX_ANYCAST_CANDIDATES);
        let mut buf = Vec::with_capacity(5 + count * 32);
        buf.extend_from_slice(&self.service_tag);
        buf.push(count as u8);
        for id in self.node_ids.iter().take(count) {
            buf.extend_from_slice(id);
        }
        buf
    }

    /// Decode a wire payload. Rejects with
    /// [`ProtoError::BufferTooShort`] when `count × 32` exceeds the
    /// remaining buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 5 {
            return Err(ProtoError::BufferTooShort {
                need: 5,
                got: buf.len(),
            });
        }
        let service_tag = super::read_array::<4>(buf, 0)?;
        let count = buf[4] as usize;
        let need = 5 + count * 32;
        if buf.len() < need {
            return Err(ProtoError::BufferTooShort {
                need,
                got: buf.len(),
            });
        }
        let mut node_ids = Vec::with_capacity(count);
        for i in 0..count {
            node_ids.push(super::read_array::<32>(buf, 5 + i * 32)?);
        }
        Ok(AnycastResultPayload {
            service_tag,
            node_ids,
        })
    }
}

/// IPC request: advertise this node as a provider for a service tag.
///
/// Wire layout:
/// ```text
/// [0..4] service_tag [u8; 4]
/// [4..6] score u16 BE (lower = better; 0 = no info)
/// [6..10] ttl_secs u32 BE (seconds until the entry should be re-published)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnycastAdvertisePayload {
    pub service_tag: [u8; 4],
    pub score: u16,
    pub ttl_secs: u32,
}

impl AnycastAdvertisePayload {
    pub const WIRE_SIZE: usize = 10;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..4].copy_from_slice(&self.service_tag);
        buf[4..6].copy_from_slice(&self.score.to_be_bytes());
        buf[6..10].copy_from_slice(&self.ttl_secs.to_be_bytes());
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let service_tag = super::read_array::<4>(buf, 0)?;
        let score = super::read_u16_be(buf, 4)?;
        let ttl_secs = super::read_u32_be(buf, 6)?;
        Ok(AnycastAdvertisePayload {
            service_tag,
            score,
            ttl_secs,
        })
    }
}

/// IPC request: withdraw this node's anycast advertisement for a service tag.
///
/// Wire layout: 4-byte `service_tag`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnycastWithdrawPayload {
    pub service_tag: [u8; 4],
}

impl AnycastWithdrawPayload {
    pub const WIRE_SIZE: usize = 4;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.service_tag
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(AnycastWithdrawPayload {
            service_tag: super::read_array::<4>(buf, 0)?,
        })
    }
}

/// IPC request: report a CONCRETE failure (timeout / conn-refused / validation
/// reject) of a candidate `node_id` returned by an earlier `AnycastResolve`
/// under `service_tag`. Fire-and-forget; the daemon feeds it into the local
/// [`veil_anycast::AnycastReputation`] ledger (audit cycle-7 M6).
///
/// Wire layout: 4-byte `service_tag` ‖ 32-byte `node_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnycastReportFailurePayload {
    pub service_tag: [u8; 4],
    pub node_id: [u8; 32],
}

impl AnycastReportFailurePayload {
    pub const WIRE_SIZE: usize = 36;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[..4].copy_from_slice(&self.service_tag);
        buf[4..].copy_from_slice(&self.node_id);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(AnycastReportFailurePayload {
            service_tag: super::read_array::<4>(buf, 0)?,
            node_id: super::read_array::<32>(buf, 4)?,
        })
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(tag: u8) -> AnycastRecord {
        AnycastRecord {
            service_tag: [tag; 4],
            node_id: [tag; 32],
            score: 100,
            ttl: 3600,
            signature: None,
        }
    }

    #[test]
    fn record_encode_decode_roundtrip() {
        let r = sample_record(0xAA);
        let enc = r.encode();
        assert_eq!(enc.len(), ANYCAST_RECORD_SIZE);
        assert_eq!(&enc[0..2], &ANYCAST_MAGIC);
        let dec = AnycastRecord::decode(&enc).unwrap();
        assert_eq!(dec, r);
    }

    #[test]
    fn record_bad_magic() {
        let mut enc = sample_record(1).encode();
        enc[0] = 0xFF;
        assert!(AnycastRecord::decode(&enc).is_err());
    }

    // Build a v3 record carrying a non-Ed25519 (e.g. Falcon-512-shaped) sig.
    fn sample_v3(tag: u8, pubkey_len: usize, sig_len: usize) -> AnycastRecord {
        AnycastRecord {
            service_tag: [tag; 4],
            node_id: [tag; 32],
            score: 7,
            ttl: 1234,
            signature: Some(AnycastRecordSig {
                sig_algo: 2, // Falcon512 wire-byte
                owner_pubkey: vec![0xAB; pubkey_len],
                sig_key_idx: 0,
                signature: vec![0xCD; sig_len],
            }),
        }
    }

    #[test]
    fn v3_encode_decode_roundtrip_falcon_shaped() {
        // Falcon-512: 897-byte pubkey, ~690-byte detached sig.
        let r = sample_v3(0x5E, 897, 690);
        let enc = r.encode();
        assert_eq!(&enc[0..2], &ANYCAST_MAGIC_V3, "v3 magic");
        assert_ne!(enc.len(), ANYCAST_RECORD_V2_SIZE, "v3 is variable, not 141");
        assert_eq!(
            AnycastRecord::wire_len(&enc),
            Some(enc.len()),
            "wire_len must match the encoded size",
        );
        let dec = AnycastRecord::decode(&enc).unwrap();
        assert_eq!(dec, r, "v3 round-trips exactly");
    }

    #[test]
    fn v3_rejects_trailing_bytes_and_ed25519_algo() {
        // Trailing garbage after a valid v3 record is rejected (exact-length).
        let mut enc = sample_v3(0x11, 64, 64).encode();
        enc.push(0x00);
        assert!(
            AnycastRecord::decode(&enc).is_err(),
            "trailing bytes must be rejected",
        );
        // A v3 record claiming the Ed25519 algo is rejected (Ed25519 ⇒ v2).
        let mut ed = sample_v3(0x22, 32, 64);
        if let Some(s) = ed.signature.as_mut() {
            s.sig_algo = 1; // Ed25519
        }
        // Hand-roll the v3 wire (encode() would route Ed25519 to v2, so force v3).
        let mut buf = Vec::new();
        if let Some(sig) = ed.signature.as_ref() {
            ed.encode_canonical_v3(&mut buf, sig);
            buf.extend_from_slice(&(sig.signature.len() as u16).to_be_bytes());
            buf.extend_from_slice(&sig.signature);
        }
        assert!(
            AnycastRecord::decode(&buf).is_err(),
            "v3 wire with Ed25519 algo must be rejected",
        );
    }

    #[test]
    fn ed25519_signed_record_stays_on_v2_wire() {
        // Backward-compat invariant: an Ed25519-signed record serializes as the
        // fixed 141-byte v2 format, NOT v3, so pre-v3 resolvers still parse it.
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let r = AnycastRecord::sign(
            [0x6D; 4],
            blake3::hash(key.verifying_key().as_bytes()).into(),
            5,
            60,
            0,
            &key,
        );
        let enc = r.encode();
        assert_eq!(enc.len(), ANYCAST_RECORD_V2_SIZE);
        assert_eq!(&enc[0..2], &ANYCAST_MAGIC_V2);
        assert!(r.verify_signature().is_ok());
        assert!(r.verify_owner_binding().is_ok());
    }

    #[test]
    fn list_decode_handles_mixed_v1_v2_v3() {
        let v1 = sample_record(0x01);
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x07; 32]);
        let v2 = AnycastRecord::sign([0x02; 4], [0x02; 32], 1, 60, 0, &key);
        let v3 = sample_v3(0x03, 897, 690);
        let mut blob = Vec::new();
        blob.extend_from_slice(&v1.encode());
        blob.extend_from_slice(&v2.encode());
        blob.extend_from_slice(&v3.encode());
        let list = AnycastList::decode(&blob);
        assert_eq!(list.0.len(), 3, "all three versions decode");
        assert_eq!(list.0[0].signature, None);
        assert_eq!(list.0[2], v3);
    }

    #[test]
    fn list_encode_decode_roundtrip() {
        let mut list = AnycastList::default();
        list.upsert(sample_record(1));
        list.upsert(sample_record(2));
        let blob = list.encode();
        assert_eq!(blob.len(), 2 * ANYCAST_RECORD_SIZE);
        let decoded = AnycastList::decode(&blob);
        assert_eq!(decoded.0.len(), 2);
        assert_eq!(decoded.0[0].node_id, [2u8; 32]); // newest first
        assert_eq!(decoded.0[1].node_id, [1u8; 32]);
    }

    #[test]
    fn list_upsert_updates_existing() {
        let mut list = AnycastList::default();
        list.upsert(sample_record(5));
        let mut updated = sample_record(5);
        updated.score = 50;
        list.upsert(updated.clone());
        assert_eq!(list.0.len(), 1);
        assert_eq!(list.0[0].score, 50);
    }

    #[test]
    fn list_evicts_oldest_at_capacity() {
        let mut list = AnycastList::default();
        for i in 0..MAX_ANYCAST_CANDIDATES as u8 {
            list.upsert(sample_record(i));
        }
        assert_eq!(list.0.len(), MAX_ANYCAST_CANDIDATES);
        // Adding one more should evict the last (oldest) entry
        let mut new_rec = sample_record(0xFF);
        new_rec.node_id = [0xFF; 32];
        list.upsert(new_rec);
        assert_eq!(list.0.len(), MAX_ANYCAST_CANDIDATES);
        assert_eq!(list.0[0].node_id, [0xFF; 32]); // newest at front
    }

    #[test]
    fn dht_key_is_deterministic() {
        let tag = *b"mbox";
        assert_eq!(AnycastRecord::dht_key(tag), AnycastRecord::dht_key(tag));
        assert_ne!(
            AnycastRecord::dht_key(*b"mbox"),
            AnycastRecord::dht_key(*b"gate")
        );
    }

    #[test]
    fn resolve_payload_roundtrip() {
        let p = AnycastResolvePayload {
            service_tag: *b"mbox",
            max_results: 5,
        };
        let enc = p.encode();
        let dec = AnycastResolvePayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn advertise_payload_roundtrip() {
        let p = AnycastAdvertisePayload {
            service_tag: *b"mbox",
            score: 42,
            ttl_secs: 3600,
        };
        let enc = p.encode();
        assert_eq!(enc.len(), AnycastAdvertisePayload::WIRE_SIZE);
        let dec = AnycastAdvertisePayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn withdraw_payload_roundtrip() {
        let p = AnycastWithdrawPayload {
            service_tag: *b"gate",
        };
        let enc = p.encode();
        let dec = AnycastWithdrawPayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn advertise_payload_short_buffer_rejected() {
        assert!(AnycastAdvertisePayload::decode(&[0u8; 5]).is_err());
    }

    #[test]
    fn withdraw_payload_short_buffer_rejected() {
        assert!(AnycastWithdrawPayload::decode(&[0u8; 2]).is_err());
    }

    #[test]
    fn report_failure_payload_roundtrip() {
        let p = AnycastReportFailurePayload {
            service_tag: *b"mbox",
            node_id: [0x7Au8; 32],
        };
        let enc = p.encode();
        assert_eq!(enc.len(), AnycastReportFailurePayload::WIRE_SIZE);
        let dec = AnycastReportFailurePayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn report_failure_payload_short_buffer_rejected() {
        assert!(AnycastReportFailurePayload::decode(&[0u8; 35]).is_err());
    }

    #[test]
    fn result_payload_roundtrip() {
        let p = AnycastResultPayload {
            service_tag: *b"gate",
            node_ids: vec![[1u8; 32], [2u8; 32]],
        };
        let enc = p.encode();
        let dec = AnycastResultPayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }

    // ── verify_owner_binding (audit batch 2026-05-23) ────────────────

    fn signed_record_for(node_id: [u8; 32], sig_key_idx: u8) -> AnycastRecord {
        // Synthesize a signing key whose BLAKE3 pubkey-hash gives the
        // desired `node_id` is hard (would require grinding); instead
        // build a record where we KNOW the relationship between key and
        // node_id, then test both "bound" and "forged-binding" cases
        // separately.
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        AnycastRecord::sign(*b"mbox", node_id, 5, 3600, sig_key_idx, &signing_key)
    }

    #[test]
    fn verify_owner_binding_accepts_blake3_match() {
        // Build a record where node_id is the BLAKE3 hash of the
        // signer's pubkey — the standard sovereign-identity binding.
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();
        let derived_node_id: [u8; 32] = *blake3::hash(&pubkey).as_bytes();
        let r = AnycastRecord::sign(*b"mbox", derived_node_id, 5, 3600, 0, &signing_key);
        // Sig integrity holds (always true for freshly-signed record).
        assert!(r.verify_signature().is_ok());
        // Binding holds because node_id == BLAKE3(pubkey) by construction.
        assert!(
            r.verify_owner_binding().is_ok(),
            "BLAKE3(owner_pubkey) == node_id must satisfy binding"
        );
    }

    #[test]
    fn verify_owner_binding_rejects_forged_node_id() {
        // Sign a record where node_id is NOT derived from the signer's
        // pubkey — this is the sybil attack `SignedOnly` cannot catch.
        let forged_node_id = [0xAB; 32];
        let r = signed_record_for(forged_node_id, 0);
        // Sig integrity passes — attacker IS holding a valid key.
        assert!(
            r.verify_signature().is_ok(),
            "signature integrity holds (signer has the key)"
        );
        // But binding fails because BLAKE3(pubkey) != [0xAB; 32].
        let err = r
            .verify_owner_binding()
            .expect_err("forged node_id must fail binding");
        match err {
            ProtoError::Malformed(msg) => assert!(
                msg.contains("owner-binding is forged") || msg.contains("BLAKE3"),
                "diagnostic must mention binding failure, got: {msg}"
            ),
            _ => panic!("expected ProtoError::Malformed, got {err:?}"),
        }
    }

    #[test]
    fn verify_owner_binding_rejects_sig_key_idx_nonzero() {
        // Compute the correct node_id for the primary key so the
        // BLAKE3 check would pass — but set sig_key_idx = 7 (subkey
        // flow).  Binding must reject because async identity-doc
        // lookup is required and out-of-scope for this sync API.
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();
        let derived_node_id: [u8; 32] = *blake3::hash(&pubkey).as_bytes();
        let r = AnycastRecord::sign(*b"mbox", derived_node_id, 5, 3600, 7, &signing_key);
        // Sig integrity passes (the body was signed correctly).
        assert!(r.verify_signature().is_ok());
        // But binding rejects because sig_key_idx > 0.
        let err = r
            .verify_owner_binding()
            .expect_err("sig_key_idx > 0 must fail binding");
        match err {
            ProtoError::Malformed(msg) => assert!(
                msg.contains("sig_key_idx"),
                "diagnostic must mention sig_key_idx, got: {msg}"
            ),
            _ => panic!("expected ProtoError::Malformed, got {err:?}"),
        }
    }

    #[test]
    fn verify_owner_binding_rejects_unsigned_v1() {
        let r = sample_record(0xAA);
        assert!(r.signature.is_none());
        // v1 records have no signature, so binding can't be verified.
        assert!(r.verify_owner_binding().is_err());
    }
}
