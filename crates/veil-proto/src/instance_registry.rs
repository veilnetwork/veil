//! InstanceRegistry — per-identity list of active devices.
//!
//! Each sovereign identity may operate from multiple devices at once
//! (phone + desktop + server; three nodes load-balancing). The
//! registry advertises this fan-out so that peers sending to a
//! `Recipient { node_id, instance_tag }` can select the right
//! `InstanceEntry` — whether that means "any" (balanced), "all"
//! (multi-device fan-out), or "specific" (targeted delivery).
//!
//! ## Per-instance identity_key binding
//!
//! `InstanceEntry.bound_identity_key_idx` points at
//! [`IdentityDocument::identity_keys`] — the subkey that device uses
//! to sign its own session frames. Each subkey carries a deterministic
//! `device_id = BLAKE3(pubkey)` so a sender can
//! encrypt/authenticate to a particular device without ambiguity.
//! Compromise of one device naturally ages out within
//! `DELEGATION_VALIDITY_SECS` (7 days) once the master stops
//! re-issuing that subkey's delegation.
//!
//! ## Wire layout (canonical bytes, all integers big-endian)
//!
//! ```text
//! [0..2] magic = "IR" u16
//! [2] version = 1 u8
//! [3..35] node_id [u8; 32]
//! [35..43] reg_version u64 BE
//! [43..45] signing_identity_key_idx u16 BE
//! [45] instances_count u8
//! repeated instances_count times:
//! [..16] instance_id [u8; 16]
//! [..2] bound_identity_key_idx u16 BE
//! [..1] label_len u8
//! [..n] label (UTF-8) [u8; n]
//! [..8] last_seen_unix_ms u64 BE
//! [..2] sig_len u16 BE
//! [..s] sig [u8; s]
//! ```
//!
//! The signature covers `INSTANCE_REGISTRY_SIG_CONTEXT || canonical
//! bytes minus sig trailer`. Any active identity subkey may sign; the
//! verifier checks `signing_identity_key_idx`
//! against the current [`IdentityDocument`] and requires that subkey
//! be both certified and not revoked.
//!
//! ## Capacity caps
//!
//! A malicious publisher cannot DoS consumers into heap-blowing
//! allocations because every length-bearing field is range-checked
//! against a hard cap on decode. See [`MAX_INSTANCES`]
//! [`MAX_LABEL_BYTES`] and the
//! overall [`MAX_INSTANCE_REGISTRY_BYTES`].
//!
//! [`IdentityDocument`]: super::identity_document::IdentityDocument
//! [`IdentityDocument::identity_keys`]: super::identity_document::IdentityDocument::identity_keys

use super::ProtoError;
use super::cursor::{read_array, read_bytes, read_u8, read_u16, read_u64};

// ── Magic, version, domain context ───────────────────────────────────────────

/// "IR" — identifies an InstanceRegistry value on the wire.
pub const INSTANCE_REGISTRY_MAGIC: [u8; 2] = [b'I', b'R'];
/// Wire-format version.
pub const INSTANCE_REGISTRY_V1: u8 = 1;
/// Domain-separated signing context.
pub const INSTANCE_REGISTRY_SIG_CONTEXT: &[u8] = b"veil.instance_registry.v1";

// ── Policy caps ──────────────────────────────────────────────────────────────

/// Maximum instances per identity (16 devices is already generous
/// for personal use; fleet-style load balancers pre-shard).
pub const MAX_INSTANCES: usize = 16;

/// Maximum label length (UTF-8 bytes). Device names like
/// "MacBook Pro 2025" or "home-server-01" fit comfortably.
pub const MAX_LABEL_BYTES: usize = 64;

// dropped `MAX_ENCRYPTED_CONTACT_BYTES` along with the
// `encrypted_contact` field + Tier-B encryption layer.

/// Absolute upper bound on registry wire size (DHT value cap).
///
/// Per-instance overhead ~620 B × 16 + header ≈ 10 KB. We cap at
/// 12 KB so even pathological label sizes fit before the decoder
/// rejects individual caps.
pub const MAX_INSTANCE_REGISTRY_BYTES: usize = 12 * 1024;

/// Maximum signature length (matches Falcon-512 headroom).
const MAX_SIG_BYTES: usize = 1024;

// ── Types ────────────────────────────────────────────────────────────────────

/// A single device advertised by an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceEntry {
    /// 16-byte per-device random identifier. Stable for the
    /// device's lifetime; generated once by
    /// [`cfg::instance`](cfg::instance) on first start.
    pub instance_id: [u8; 16],
    /// Index into the current `IdentityDocument.identity_keys` of the
    /// subkey this device uses to sign session frames
    /// (per-instance-key model).
    pub bound_identity_key_idx: u16,
    /// Human-readable tag (empty string permitted). UTF-8.
    pub label: String,
    /// Last time this device published or refreshed the registry
    /// milliseconds since Unix epoch.
    pub last_seen_unix_ms: u64,
    // dropped `mailbox_anchor: [u8; 32]` (orphan after
    // removed the mailbox subsystem) and `encrypted_contact:
    // Vec<u8>` (Tier-B storage that only existed to hide
    // mailbox_anchor + transport hints from passive DHT observers —
    // mailbox is gone, transports moved to `SignedTransportAnnouncement`
    // gossip.4c). Wire format simplified accordingly.
}

/// A signed list of instances for a single identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceRegistry {
    /// Identity this registry belongs to.
    pub node_id: [u8; 32],
    /// Monotonic registry version (bumped on each publish). Consumers
    /// reject decreasing values to defend against stale replay.
    pub reg_version: u64,
    /// Index into the current `IdentityDocument.identity_keys` of the
    /// subkey that signed this registry.
    pub signing_identity_key_idx: u16,
    /// The instances themselves.
    pub instances: Vec<InstanceEntry>,
    /// Signature over `SIG_CONTEXT || canonical_bytes_without_sig`.
    pub sig: Vec<u8>,
}

// ── Impls ────────────────────────────────────────────────────────────────────

impl InstanceEntry {
    fn encoded_len(&self) -> usize {
        16 + 2 + 1 + self.label.len() + 8
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.instance_id);
        out.extend_from_slice(&self.bound_identity_key_idx.to_be_bytes());
        out.push(self.label.len() as u8);
        out.extend_from_slice(self.label.as_bytes());
        out.extend_from_slice(&self.last_seen_unix_ms.to_be_bytes());
    }

    fn decode(buf: &[u8], pos: &mut usize) -> Result<Self, ProtoError> {
        let instance_id = read_array::<16>(buf, pos, "instance_entry.instance_id")?;
        let bound_identity_key_idx = read_u16(buf, pos, "instance_entry.key_idx")?;

        let label_len = read_u8(buf, pos, "instance_entry.label_len")? as usize;
        if label_len > MAX_LABEL_BYTES {
            return Err(ProtoError::Malformed(format!(
                "instance_entry: label_len {label_len} exceeds cap {MAX_LABEL_BYTES}"
            )));
        }
        let label_bytes = read_bytes(buf, pos, label_len, "instance_entry.label")?;
        let label = String::from_utf8(label_bytes).map_err(|e| {
            ProtoError::Malformed(format!("instance_entry.label: invalid utf8: {e}"))
        })?;

        let last_seen_unix_ms = read_u64(buf, pos, "instance_entry.last_seen_ms")?;

        Ok(Self {
            instance_id,
            bound_identity_key_idx,
            label,
            last_seen_unix_ms,
        })
    }
}

impl InstanceRegistry {
    /// Encode the registry into its wire representation.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&INSTANCE_REGISTRY_MAGIC);
        out.push(INSTANCE_REGISTRY_V1);
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.reg_version.to_be_bytes());
        out.extend_from_slice(&self.signing_identity_key_idx.to_be_bytes());
        out.push(self.instances.len() as u8);
        for inst in &self.instances {
            inst.encode_into(&mut out);
        }
        out.extend_from_slice(&(self.sig.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    /// Decode a wire buffer. Enforces structural caps only — the
    /// consuming runtime verifies the signature against
    /// the current [`IdentityDocument`] afterwards.
    ///
    /// [`IdentityDocument`]: super::identity_document::IdentityDocument
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() > MAX_INSTANCE_REGISTRY_BYTES {
            return Err(ProtoError::Malformed(format!(
                "instance_registry: oversized ({}B > {MAX_INSTANCE_REGISTRY_BYTES}B)",
                buf.len()
            )));
        }

        let mut pos = 0;
        if buf.get(pos..pos + 2) != Some(&INSTANCE_REGISTRY_MAGIC[..]) {
            return Err(ProtoError::Malformed("instance_registry: bad magic".into()));
        }
        pos += 2;

        let version = read_u8(buf, &mut pos, "instance_registry.version")?;
        if version != INSTANCE_REGISTRY_V1 {
            return Err(ProtoError::Malformed(format!(
                "instance_registry: unsupported version {version}"
            )));
        }

        let node_id = read_array::<32>(buf, &mut pos, "instance_registry.node_id")?;
        let reg_version = read_u64(buf, &mut pos, "instance_registry.reg_version")?;
        let signing_identity_key_idx =
            read_u16(buf, &mut pos, "instance_registry.signing_key_idx")?;

        let instances_count = read_u8(buf, &mut pos, "instance_registry.instances_count")? as usize;
        if instances_count > MAX_INSTANCES {
            return Err(ProtoError::Malformed(format!(
                "instance_registry: instances_count {instances_count} exceeds cap {MAX_INSTANCES}"
            )));
        }
        let mut instances = Vec::with_capacity(instances_count);
        for _ in 0..instances_count {
            instances.push(InstanceEntry::decode(buf, &mut pos)?);
        }

        // Enforce instance_id uniqueness within a single registry.
        // Duplicate ids would let the publisher shadow routing
        // decisions — reject at decode time.
        for i in 0..instances.len() {
            for j in (i + 1)..instances.len() {
                if instances[i].instance_id == instances[j].instance_id {
                    return Err(ProtoError::Malformed(format!(
                        "instance_registry: duplicate instance_id at positions {i}+{j}"
                    )));
                }
            }
        }

        let sig_len = read_u16(buf, &mut pos, "instance_registry.sig_len")? as usize;
        if sig_len == 0 || sig_len > MAX_SIG_BYTES {
            return Err(ProtoError::Malformed(format!(
                "instance_registry: sig_len {sig_len} out of range"
            )));
        }
        let sig = read_bytes(buf, &mut pos, sig_len, "instance_registry.sig")?;

        if pos != buf.len() {
            return Err(ProtoError::Malformed(format!(
                "instance_registry: {} trailing bytes",
                buf.len() - pos
            )));
        }

        Ok(Self {
            node_id,
            reg_version,
            signing_identity_key_idx,
            instances,
            sig,
        })
    }

    /// Canonical bytes the signature covers: the full encoding minus
    /// the `sig_len + sig` trailer. Signer and verifier both run
    /// this; the signature message itself is
    /// `INSTANCE_REGISTRY_SIG_CONTEXT || canonical_signing_bytes`.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut encoded = self.encode();
        let trailer = 2 + self.sig.len();
        encoded.truncate(encoded.len() - trailer);
        encoded
    }

    /// DHT key under which the registry is stored.
    pub fn dht_key(node_id: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"veil.instance_registry_dht.v1");
        h.update(node_id);
        *h.finalize().as_bytes()
    }

    /// Estimate the encoded size of this registry.
    pub fn encoded_len(&self) -> usize {
        2 + 1
            + 32
            + 8
            + 2
            + 1
            + self
                .instances
                .iter()
                .map(|i| i.encoded_len())
                .sum::<usize>()
            + 2
            + self.sig.len()
    }

    /// Lookup an instance by id.
    pub fn find(&self, instance_id: &[u8; 16]) -> Option<&InstanceEntry> {
        self.instances
            .iter()
            .find(|e| &e.instance_id == instance_id)
    }
}

// ── Decode helpers ───────────────────────────────────────────────────────────
//
// local `read_array` removed — use cursor::read_array.

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(tag: u8, key_idx: u16) -> InstanceEntry {
        InstanceEntry {
            instance_id: [tag; 16],
            bound_identity_key_idx: key_idx,
            label: format!("device-{tag}"),
            last_seen_unix_ms: 1_700_000_000_000 + tag as u64,
        }
    }

    fn sample_registry() -> InstanceRegistry {
        InstanceRegistry {
            node_id: [0xAAu8; 32],
            reg_version: 7,
            signing_identity_key_idx: 0,
            instances: vec![sample_entry(1, 0), sample_entry(2, 1), sample_entry(3, 0)],
            sig: vec![0xCC; 64],
        }
    }

    #[test]
    fn roundtrip_basic_registry() {
        let r = sample_registry();
        let bytes = r.encode();
        assert_eq!(bytes.len(), r.encoded_len());
        let r2 = InstanceRegistry::decode(&bytes).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn empty_instances_roundtrip() {
        let r = InstanceRegistry {
            node_id: [0x01; 32],
            reg_version: 1,
            signing_identity_key_idx: 0,
            instances: Vec::new(),
            sig: vec![0xEE; 64],
        };
        let bytes = r.encode();
        let r2 = InstanceRegistry::decode(&bytes).unwrap();
        assert_eq!(r, r2);
    }

    // dropped `roundtrip_with_tier_b_encrypted_contact` —
    // `encrypted_contact` field gone with `mailbox_anchor`.

    #[test]
    fn roundtrip_with_labels() {
        let mut r = sample_registry();
        r.instances[0].label = "MacBook Pro 2025".to_string();
        r.instances[1].label = "home-server-01".to_string();
        r.instances[2].label = "".to_string();
        let bytes = r.encode();
        let r2 = InstanceRegistry::decode(&bytes).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = sample_registry().encode();
        bytes[0] = b'X';
        let err = InstanceRegistry::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = sample_registry().encode();
        bytes[2] = 99;
        let err = InstanceRegistry::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_truncated_buffer() {
        let bytes = sample_registry().encode();
        for len in 0..bytes.len() {
            let err = InstanceRegistry::decode(&bytes[..len]).unwrap_err();
            assert!(
                matches!(err, ProtoError::Malformed(_)),
                "len={len} err={err:?}"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = sample_registry().encode();
        bytes.push(0xFF);
        let err = InstanceRegistry::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_oversized_input() {
        let bytes = vec![0u8; MAX_INSTANCE_REGISTRY_BYTES + 1];
        let err = InstanceRegistry::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_too_many_instances() {
        // Build a registry-level encoding with instances_count = 17.
        // We cannot go through `encode` because InstanceRegistry
        // allows arbitrary Vec lengths in-memory — the cap is
        // enforced at decode to protect consumers. Instead build the
        // wire buffer directly with 17 bogus entries.
        let mut out = Vec::new();
        out.extend_from_slice(&INSTANCE_REGISTRY_MAGIC);
        out.push(INSTANCE_REGISTRY_V1);
        out.extend_from_slice(&[0u8; 32]);
        out.extend_from_slice(&1u64.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.push(17);
        // 17 × minimal entry = 17 * (16+2+1+8+32+2) = 17 * 61 = 1037 bytes.
        for i in 0..17u8 {
            out.extend_from_slice(&[i; 16]); // instance_id
            out.extend_from_slice(&0u16.to_be_bytes()); // key_idx
            out.push(0); // label_len
            out.extend_from_slice(&0u64.to_be_bytes()); // last_seen
            out.extend_from_slice(&[0u8; 32]); // anchor
            out.extend_from_slice(&0u16.to_be_bytes()); // enc_contact_len
        }
        out.extend_from_slice(&1u16.to_be_bytes());
        out.push(0);

        let err = InstanceRegistry::decode(&out).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_label_above_cap() {
        // Build wire with label_len = MAX_LABEL_BYTES + 1.
        let mut out = Vec::new();
        out.extend_from_slice(&INSTANCE_REGISTRY_MAGIC);
        out.push(INSTANCE_REGISTRY_V1);
        out.extend_from_slice(&[0u8; 32]);
        out.extend_from_slice(&1u64.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.push(1);
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.push((MAX_LABEL_BYTES + 1) as u8);
        out.extend_from_slice(&[b'a'; MAX_LABEL_BYTES + 1]);
        out.extend_from_slice(&0u64.to_be_bytes());
        out.extend_from_slice(&[0u8; 32]);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.push(0);
        let err = InstanceRegistry::decode(&out).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    // dropped `rejects_encrypted_contact_above_cap` — the
    // `encrypted_contact` field + `MAX_ENCRYPTED_CONTACT_BYTES` cap are gone.

    #[test]
    fn rejects_invalid_utf8_label() {
        // Hand-craft a label that isn't valid UTF-8.
        let mut out = Vec::new();
        out.extend_from_slice(&INSTANCE_REGISTRY_MAGIC);
        out.push(INSTANCE_REGISTRY_V1);
        out.extend_from_slice(&[0u8; 32]);
        out.extend_from_slice(&1u64.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.push(1);
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.push(2);
        out.extend_from_slice(&[0xFF, 0xFE]); // invalid utf8
        out.extend_from_slice(&0u64.to_be_bytes());
        out.extend_from_slice(&[0u8; 32]);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.push(0);
        let err = InstanceRegistry::decode(&out).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_duplicate_instance_ids() {
        let mut r = sample_registry();
        r.instances[1].instance_id = r.instances[0].instance_id;
        let bytes = r.encode();
        let err = InstanceRegistry::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_zero_length_sig() {
        // Direct wire construction: set sig_len = 0 and no bytes.
        let mut r = sample_registry();
        r.sig = Vec::new();
        let bytes = r.encode();
        let err = InstanceRegistry::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_sig_above_cap() {
        let mut r = sample_registry();
        r.sig = vec![0x99; MAX_SIG_BYTES + 1];
        let bytes = r.encode();
        let err = InstanceRegistry::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn canonical_signing_bytes_excludes_sig_trailer() {
        let r = sample_registry();
        let full = r.encode();
        let canonical = r.canonical_signing_bytes();
        assert!(canonical.len() < full.len());
        // The canonical bytes must be a proper prefix of the full
        // encoding — i.e., the trailer is just the sig section.
        assert_eq!(&full[..canonical.len()], &canonical[..]);
        assert_eq!(full.len() - canonical.len(), 2 + r.sig.len());
    }

    #[test]
    fn canonical_signing_bytes_stable_under_sig_change() {
        // Changing the signature bytes must NOT change the canonical
        // signing bytes — otherwise verify/sign would chase their
        // own tail.
        let mut r = sample_registry();
        let canonical_before = r.canonical_signing_bytes();
        r.sig = vec![0x00; 64];
        let canonical_after = r.canonical_signing_bytes();
        assert_eq!(canonical_before, canonical_after);
    }

    #[test]
    fn dht_key_is_deterministic() {
        let id = [0xABu8; 32];
        let a = InstanceRegistry::dht_key(&id);
        let b = InstanceRegistry::dht_key(&id);
        assert_eq!(a, b);
        let c = InstanceRegistry::dht_key(&[0xCDu8; 32]);
        assert_ne!(a, c);
    }

    #[test]
    fn find_instance_by_id() {
        let r = sample_registry();
        let found = r.find(&[2u8; 16]).unwrap();
        assert_eq!(found.instance_id, [2u8; 16]);
        assert!(r.find(&[0xFFu8; 16]).is_none());
    }

    #[test]
    fn signing_key_idx_is_preserved() {
        let r = InstanceRegistry {
            signing_identity_key_idx: 5,
            ..sample_registry()
        };
        let bytes = r.encode();
        let r2 = InstanceRegistry::decode(&bytes).unwrap();
        assert_eq!(r2.signing_identity_key_idx, 5);
    }
}
