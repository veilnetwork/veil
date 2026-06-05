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

/// Magic bytes identifying а **v1 (unsigned)** AnycastRecord value in DHT.
/// V1 records carry no owner signature — `score` is peer-controlled.
/// Kept readable для backward compatibility с existing deployments.
pub const ANYCAST_MAGIC: [u8; 2] = [0x41, 0x43]; // "AC"

/// Magic bytes identifying а **v2 (owner-signed)** AnycastRecord.
/// V2 appends an Ed25519 signature over the canonical bytes, allowing the
/// resolver к reject records published under а different `node_id` than
/// the signing key proves ownership of. See module security doc.
pub const ANYCAST_MAGIC_V2: [u8; 2] = [0x41, 0x44]; // "AD"

/// Wire size of а **v1 (unsigned)** record.
pub const ANYCAST_RECORD_SIZE: usize = 44;

/// Wire size of а **v2 (signed)** record.
/// Layout: 44 (v1 fields) + 32 (owner_pubkey) + 1 (sig_key_idx) + 64 (sig) = 141.
pub const ANYCAST_RECORD_V2_SIZE: usize = 141;

/// Maximum number of candidate records stored per service tag in the DHT.
pub const MAX_ANYCAST_CANDIDATES: usize = 32;

// ── AnycastRecord ─────────────────────────────────────────────────────────────

/// Owner-binding signature payload for а v2 `AnycastRecord`.
///
/// `owner_pubkey` is the Ed25519 verifying key that signed the canonical
/// bytes (everything in the record except the signature itself). Caller
/// is responsible для making sure this key is bound к `node_id` —
/// typically `node_id == BLAKE3(owner_pubkey)`, but advanced sovereign-
/// identity flows may use а subkey indicated by `sig_key_idx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnycastRecordSig {
    /// Ed25519 verifying key that produced `signature`.
    pub owner_pubkey: [u8; 32],
    /// Which subkey index в the owner's identity document signed this
    /// record. `0` for nodes без sovereign-identity multi-key setup.
    pub sig_key_idx: u8,
    /// Ed25519 signature over canonical bytes (the first 77 bytes of the
    /// v2 wire format — i.e. fields up к и including `sig_key_idx`).
    pub signature: [u8; 64],
}

/// A single anycast service advertisement stored in the DHT.
///
/// When `signature` is `Some(...)`, this is а v2 record (wire size
/// [`ANYCAST_RECORD_V2_SIZE`] = 141 B) and verifiers MUST check the
/// embedded Ed25519 signature before trusting any field. When `None`,
/// this is а legacy v1 record ([`ANYCAST_RECORD_SIZE`] = 44 B) with no
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

    /// Encode the record. Selects v2 wire format (141 B) если `signature`
    /// is `Some`, otherwise v1 (44 B). Returns а `Vec<u8>` because the
    /// length depends on version.
    pub fn encode(&self) -> Vec<u8> {
        match &self.signature {
            Some(sig) => {
                let mut buf = Vec::with_capacity(ANYCAST_RECORD_V2_SIZE);
                self.encode_canonical_v2(&mut buf, sig);
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

    /// Write the canonical-bytes prefix of а v2 record (77 bytes — everything
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

    /// Decode а record. Auto-detects v1 vs v2 by magic bytes. v2 records
    /// have their embedded signature integrity-checked (the signature is
    /// stored intact for caller-side `verify_signature`).
    ///
    /// **This function does NOT verify the signature** — call
    /// [`Self::verify_signature`] separately if you want trust enforcement.
    /// Decode-only allows downstream code к receive both signed и unsigned
    /// records и make policy decisions about which к trust.
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
            _ => Err(ProtoError::InvalidMagic([buf[0], buf[1], 0, 0])),
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
                owner_pubkey,
                sig_key_idx,
                signature,
            }),
        })
    }

    /// Verify the embedded v2 owner-signature. Returns `Ok(())` if signed
    /// и signature is valid под `signature.owner_pubkey`; `Err` otherwise.
    /// Unsigned (v1) records return `Err(ProtoError::Malformed(...))`.
    ///
    /// Caller is responsible separately для checking that
    /// `signature.owner_pubkey` actually corresponds к the claimed
    /// `node_id` (typically via а sovereign-identity-document lookup).
    /// Without that binding check, an attacker can publish а valid
    /// signature под an unrelated key claiming а target node_id — the
    /// signature itself is valid but the binding is forged.
    pub fn verify_signature(&self) -> Result<(), ProtoError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Some(sig) = &self.signature else {
            return Err(ProtoError::Malformed(
                "anycast record is unsigned (v1); cannot verify".to_string(),
            ));
        };
        let vk = VerifyingKey::from_bytes(&sig.owner_pubkey).map_err(|_| {
            ProtoError::Malformed("anycast record: invalid Ed25519 owner_pubkey".to_string())
        })?;
        let mut canonical = Vec::with_capacity(77);
        self.encode_canonical_v2(&mut canonical, sig);
        let sig_obj = Signature::from_bytes(&sig.signature);
        vk.verify(&canonical, &sig_obj).map_err(|_| {
            ProtoError::Malformed(
                "anycast record: Ed25519 signature verification failed".to_string(),
            )
        })
    }

    /// Verify the **owner-binding** in addition к the embedded signature —
    /// confirms that the signer (whose pubkey is embedded in `signature.owner_pubkey`)
    /// is actually the same identity as the claimed `node_id`.
    ///
    /// Without this check, [`Self::verify_signature`] alone only proves
    /// integrity: an attacker can mint а valid signature под their OWN
    /// key while putting а victim's `node_id` in the record body.  The
    /// signature passes, the binding is а forgery.  See the crate-level
    /// security docs in `veil-anycast` для the full attack model.
    ///
    /// ## Binding contract
    ///
    /// This method accepts ONLY the "self-signed" binding case:
    /// 1. The record carries а v2 signature (calls [`Self::verify_signature`] first).
    /// 2. `signature.sig_key_idx == 0` — i.e. the signer is using its
    ///    PRIMARY (root) Ed25519 key, NOT а sovereign-identity subkey.
    /// 3. `node_id == BLAKE3(signature.owner_pubkey)` — i.e. the claimed
    ///    `node_id` is provably derived from the embedded pubkey via the
    ///    standard 32-byte BLAKE3 hash used everywhere в veil's
    ///    identity layer.
    ///
    /// `sig_key_idx > 0` (multi-device sovereign identity flow с subkeys)
    /// is rejected here because verifying it requires an async DHT lookup
    /// of the identity document к check `identity_keys[sig_key_idx] ==
    /// owner_pubkey`, which doesn't fit а synchronous record-validator API.
    /// Callers что need to support subkey-signed records должны either:
    /// * Use [`Self::verify_signature`] alone + perform the identity-doc
    ///   lookup themselves, OR
    /// * Use the daemon's verified-identity-resolve path (which already
    ///   does this composition asynchronously).
    ///
    /// Audit batch 2026-05-23: added к close the "anycast SignedOnly
    /// proves signature but не binding" finding — the cross-audit pointed
    /// out що the cfg-level SignedOnly knob would NOT prevent а sybil
    /// from minting а valid signature under their own key while claiming
    /// another node's `node_id`.
    pub fn verify_owner_binding(&self) -> Result<(), ProtoError> {
        self.verify_signature()?;
        // `verify_signature` already errored when signature is None, but
        // the borrow-checker doesn't know that — so unwrap is safe here.
        let sig = self.signature.as_ref().ok_or_else(|| {
            ProtoError::Malformed(
                "anycast record: owner-binding requires а v2 signature".to_string(),
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
        let derived_node_id = blake3::hash(&sig.owner_pubkey);
        if derived_node_id.as_bytes() != &self.node_id {
            return Err(ProtoError::Malformed(
                "anycast record: BLAKE3(owner_pubkey) != node_id — \
                 signature valid but owner-binding is forged"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Construct а v2 (signed) record. Caller supplies the Ed25519
    /// signing key; pubkey is derived и embedded automatically.
    pub fn sign(
        service_tag: [u8; 4],
        node_id: [u8; 32],
        score: u16,
        ttl: u32,
        sig_key_idx: u8,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;
        let owner_pubkey = signing_key.verifying_key().to_bytes();
        // Build placeholder sig к get canonical bytes via encode_canonical_v2.
        let mut placeholder = Self {
            service_tag,
            node_id,
            score,
            ttl,
            signature: Some(AnycastRecordSig {
                owner_pubkey,
                sig_key_idx,
                signature: [0u8; 64],
            }),
        };
        let mut canonical = Vec::with_capacity(77);
        // unwrap: we just set signature к Some above.
        placeholder.encode_canonical_v2(&mut canonical, placeholder.signature.as_ref().unwrap());
        let sig_bytes = signing_key.sign(&canonical).to_bytes();
        // Replace placeholder signature с actual signature.
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
    /// Decode all records от а DHT value blob.
    ///
    /// Auto-detects v1 (44 B) и v2 (141 B) records by magic prefix.
    /// Silently skips records that fail к decode (wrong magic, stale format,
    /// truncated tail). DOES NOT verify v2 signatures here — caller decides
    /// trust policy via [`AnycastRecord::verify_signature`].
    pub fn decode(blob: &[u8]) -> Self {
        let mut records = Vec::new();
        let mut pos = 0;
        while pos + 2 <= blob.len() {
            let magic = &blob[pos..pos + 2];
            let rec_size = if magic == ANYCAST_MAGIC {
                ANYCAST_RECORD_SIZE
            } else if magic == ANYCAST_MAGIC_V2 {
                ANYCAST_RECORD_V2_SIZE
            } else {
                // Unknown magic — abort to avoid sliding into garbage.
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

    /// Encode all records into а DHT value blob. Length per record varies
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
        // Synthesize а signing key whose BLAKE3 pubkey-hash gives the
        // desired `node_id` is hard (would require grinding); instead
        // build а record where we KNOW the relationship between key и
        // node_id, then test both "bound" и "forged-binding" cases
        // separately.
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        AnycastRecord::sign(*b"mbox", node_id, 5, 3600, sig_key_idx, &signing_key)
    }

    #[test]
    fn verify_owner_binding_accepts_blake3_match() {
        // Build а record where node_id is the BLAKE3 hash of the
        // signer's pubkey — the standard sovereign-identity binding.
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();
        let derived_node_id: [u8; 32] = *blake3::hash(&pubkey).as_bytes();
        let r = AnycastRecord::sign(*b"mbox", derived_node_id, 5, 3600, 0, &signing_key);
        // Sig integrity holds (always true для freshly-signed record).
        assert!(r.verify_signature().is_ok());
        // Binding holds because node_id == BLAKE3(pubkey) by construction.
        assert!(
            r.verify_owner_binding().is_ok(),
            "BLAKE3(owner_pubkey) == node_id must satisfy binding"
        );
    }

    #[test]
    fn verify_owner_binding_rejects_forged_node_id() {
        // Sign а record where node_id is NOT derived от the signer's
        // pubkey — this is the sybil attack `SignedOnly` cannot catch.
        let forged_node_id = [0xAB; 32];
        let r = signed_record_for(forged_node_id, 0);
        // Sig integrity passes — attacker IS holding а valid key.
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
        // Compute the correct node_id для the primary key so the
        // BLAKE3 check would pass — но set sig_key_idx = 7 (subkey
        // flow).  Binding must reject because async identity-doc
        // lookup is required и out-of-scope для this sync API.
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
