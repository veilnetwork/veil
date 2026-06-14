//! `Recipient` + `InstanceTag` addressing types (
//! foundation).
//!
//! These types replace the legacy `recipient_node_id: [u8; 32]` on
//! every wire struct (`DeliveryEnvelope`, `DELIVERY_FORWARD`
//! `TransitFramePayload`, `RouteCache`, …) once the breaking
//! wire-format migration in 462.15 lands. Introducing them as a
//! self-contained proto module first — without removing the
//! legacy fields — keeps the risk surface small: downstream
//! modules can flip to `Recipient` one at a time, fuzz-tested
//! against the codec here before being wired in.
//!
//! ## Addressing model
//!
//! A `Recipient` names an identity and an instance-dispatch
//! intent:
//!
//! `InstanceTag::Any` — "any active instance" (load
//! balancing).
//! `InstanceTag::All` — "fan out to every active instance"
//! (multi-device receive).
//! `InstanceTag::Specific` — "this exact instance" (targeted
//! delivery, e.g. for a session
//! continuation).
//!
//! The encoding is tight — 33 B for `Any`/`All`, 49 B for
//! `Specific` — so replacing a bare 32-byte `node_id` costs at
//! most 17 B of on-the-wire overhead.
//!
//! ## Wire layout (canonical bytes, big-endian)
//!
//! ```text
//! [0..32] node_id [u8; 32]
//! [32] tag = ANY | ALL | SPECIFIC u8
//! [33..49] instance_id (ONLY when tag=SPECIFIC) [u8; 16]
//! ```
//!
//! An `Any` or `All` recipient is exactly 33 bytes; a `Specific`
//! recipient is exactly 49 bytes.

use super::ProtoError;
use super::cursor::{read_array, read_u8};

// ── Constants ────────────────────────────────────────────────────────────────

/// Tag byte: "any active instance" — load-balance target.
pub const INSTANCE_TAG_ANY: u8 = 0;
/// Tag byte: "all active instances" — multi-device fan-out.
pub const INSTANCE_TAG_ALL: u8 = 1;
/// Tag byte: "this specific instance" — followed by 16 bytes.
pub const INSTANCE_TAG_SPECIFIC: u8 = 2;

/// Fixed encoded size of `Recipient::Any` / `::All` variants.
pub const RECIPIENT_BYTES_UNBOUND: usize = 32 + 1;
/// Fixed encoded size of `Recipient::Specific`.
pub const RECIPIENT_BYTES_SPECIFIC: usize = 32 + 1 + 16;
/// Upper bound on any recipient encoding — convenient for buffers.
pub const MAX_RECIPIENT_BYTES: usize = RECIPIENT_BYTES_SPECIFIC;

// ── Types ────────────────────────────────────────────────────────────────────

/// How the dispatcher should resolve the recipient's set of active
/// instances into a delivery target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstanceTag {
    /// Any one active instance (balanced).
    Any,
    /// Every active instance.
    All,
    /// The exact instance whose `instance_id` this byte-string
    /// carries.
    Specific([u8; 16]),
}

impl InstanceTag {
    /// Tag byte shipped on the wire for this variant.
    pub const fn byte(&self) -> u8 {
        match self {
            InstanceTag::Any => INSTANCE_TAG_ANY,
            InstanceTag::All => INSTANCE_TAG_ALL,
            InstanceTag::Specific(_) => INSTANCE_TAG_SPECIFIC,
        }
    }

    /// Does this tag select exactly one instance?
    pub const fn is_unicast(&self) -> bool {
        matches!(self, InstanceTag::Any | InstanceTag::Specific(_))
    }

    /// Does this tag fan out to multiple instances?
    pub const fn is_broadcast(&self) -> bool {
        matches!(self, InstanceTag::All)
    }
}

/// Destination addressing: identity + instance-tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Recipient {
    pub node_id: [u8; 32],
    pub instance_tag: InstanceTag,
}

// ── Constructors ─────────────────────────────────────────────────────────────

impl Recipient {
    /// `Recipient` with `InstanceTag::Any`.
    pub const fn any(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            instance_tag: InstanceTag::Any,
        }
    }

    /// `Recipient` with `InstanceTag::All`.
    pub const fn all(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            instance_tag: InstanceTag::All,
        }
    }

    /// `Recipient` with `InstanceTag::Specific(instance_id)`.
    pub const fn specific(node_id: [u8; 32], instance_id: [u8; 16]) -> Self {
        Self {
            node_id,
            instance_tag: InstanceTag::Specific(instance_id),
        }
    }

    /// Encoded size for this recipient.
    pub const fn encoded_len(&self) -> usize {
        match self.instance_tag {
            InstanceTag::Any | InstanceTag::All => RECIPIENT_BYTES_UNBOUND,
            InstanceTag::Specific(_) => RECIPIENT_BYTES_SPECIFIC,
        }
    }

    /// Serialize to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out);
        out
    }

    /// Append the encoded form to `out`. Useful when packing a
    /// recipient as part of a larger frame.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.node_id);
        match self.instance_tag {
            InstanceTag::Any => out.push(INSTANCE_TAG_ANY),
            InstanceTag::All => out.push(INSTANCE_TAG_ALL),
            InstanceTag::Specific(instance_id) => {
                out.push(INSTANCE_TAG_SPECIFIC);
                out.extend_from_slice(&instance_id);
            }
        }
    }

    /// Decode a recipient starting at `*pos` in `buf`. Advances
    /// `*pos` past the bytes consumed.
    ///
    /// This is the embedded form used inside larger frames; the
    /// standalone [`Recipient::decode`] adds a trailing-bytes
    /// check useful when the recipient is the entire wire payload.
    pub fn decode_from(buf: &[u8], pos: &mut usize) -> Result<Self, ProtoError> {
        let node_id = read_array::<32>(buf, pos, "recipient.node_id")?;
        let tag = read_u8(buf, pos, "recipient.tag")?;
        let instance_tag = match tag {
            INSTANCE_TAG_ANY => InstanceTag::Any,
            INSTANCE_TAG_ALL => InstanceTag::All,
            INSTANCE_TAG_SPECIFIC => {
                let instance_id = read_array::<16>(buf, pos, "recipient.instance_id")?;
                InstanceTag::Specific(instance_id)
            }
            other => {
                return Err(ProtoError::Malformed(format!(
                    "recipient: unknown instance tag {other}"
                )));
            }
        };
        Ok(Self {
            node_id,
            instance_tag,
        })
    }

    /// Decode a recipient that is the full wire payload — rejects
    /// trailing bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut pos = 0;
        let r = Self::decode_from(buf, &mut pos)?;
        if pos != buf.len() {
            return Err(ProtoError::Malformed(format!(
                "recipient: {} trailing bytes after decode",
                buf.len() - pos
            )));
        }
        Ok(r)
    }

    /// append the FIXED-49-byte
    /// encoding of this recipient — `node_id (32) || tag (1)
    /// || instance_id (16, zeroed for `Any`/`All`)`. Used by
    /// callers (notably `DeliveryEnvelope`) whose wire layout
    /// requires constant offsets for downstream fields and for
    /// fast-path pre-decoders that read fixed-position bytes
    /// without parsing the whole frame.
    ///
    /// The variable-length [`encode_into`] form is preferred for
    /// small frames where the 16 B padding cost matters; the
    /// fixed form trades ≤16 B per envelope for stable offsets.
    ///
    /// [`encode_into`]: Self::encode_into
    pub fn encode_fixed_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.node_id);
        match self.instance_tag {
            InstanceTag::Any => {
                out.push(INSTANCE_TAG_ANY);
                out.extend_from_slice(&[0u8; 16]);
            }
            InstanceTag::All => {
                out.push(INSTANCE_TAG_ALL);
                out.extend_from_slice(&[0u8; 16]);
            }
            InstanceTag::Specific(instance_id) => {
                out.push(INSTANCE_TAG_SPECIFIC);
                out.extend_from_slice(&instance_id);
            }
        }
    }

    /// decode a fixed-49-byte
    /// recipient encoding produced by [`encode_fixed_into`].
    /// Reads from `buf[*pos..*pos + RECIPIENT_FIXED_SIZE]` and
    /// advances `*pos`. For `Any` / `All` the trailing 16 bytes
    /// are required to be all-zero — non-zero padding is a
    /// protocol violation (signals encoder bug or wire tamper).
    ///
    /// [`encode_fixed_into`]: Self::encode_fixed_into
    pub fn decode_fixed_from(buf: &[u8], pos: &mut usize) -> Result<Self, ProtoError> {
        let node_id = read_array::<32>(buf, pos, "recipient.node_id")?;
        let tag = read_u8(buf, pos, "recipient.tag")?;
        let instance_id = read_array::<16>(buf, pos, "recipient.instance_id_padded")?;
        let instance_tag = match tag {
            INSTANCE_TAG_ANY => {
                if instance_id != [0u8; 16] {
                    return Err(ProtoError::Malformed(
                        "recipient: Any tag with non-zero instance_id padding".into(),
                    ));
                }
                InstanceTag::Any
            }
            INSTANCE_TAG_ALL => {
                if instance_id != [0u8; 16] {
                    return Err(ProtoError::Malformed(
                        "recipient: All tag with non-zero instance_id padding".into(),
                    ));
                }
                InstanceTag::All
            }
            INSTANCE_TAG_SPECIFIC => InstanceTag::Specific(instance_id),
            other => {
                return Err(ProtoError::Malformed(format!(
                    "recipient: unknown instance tag {other}"
                )));
            }
        };
        Ok(Self {
            node_id,
            instance_tag,
        })
    }
}

/// byte length of the fixed-size
/// recipient encoding emitted by [`Recipient::encode_fixed_into`].
/// Constant regardless of `InstanceTag` variant — `Any` / `All`
/// pad the trailing 16 bytes with zeros.
pub const RECIPIENT_FIXED_SIZE: usize = 32 + 1 + 16;

// ── Helpers ──────────────────────────────────────────────────────────────────
//
// local `read_array` removed — use cursor::read_array.

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Encoding ─────────────────────────────────────────────────────────────

    #[test]
    fn any_encoded_size_is_33_bytes() {
        let r = Recipient::any([0x11; 32]);
        assert_eq!(r.encoded_len(), RECIPIENT_BYTES_UNBOUND);
        assert_eq!(r.encode().len(), RECIPIENT_BYTES_UNBOUND);
    }

    #[test]
    fn all_encoded_size_is_33_bytes() {
        let r = Recipient::all([0x22; 32]);
        assert_eq!(r.encoded_len(), RECIPIENT_BYTES_UNBOUND);
    }

    #[test]
    fn specific_encoded_size_is_49_bytes() {
        let r = Recipient::specific([0x33; 32], [0x44; 16]);
        assert_eq!(r.encoded_len(), RECIPIENT_BYTES_SPECIFIC);
        assert_eq!(r.encode().len(), RECIPIENT_BYTES_SPECIFIC);
    }

    #[test]
    fn encoding_places_tag_at_offset_32() {
        let r_any = Recipient::any([0x11; 32]);
        let r_all = Recipient::all([0x11; 32]);
        let r_specific = Recipient::specific([0x11; 32], [0; 16]);
        assert_eq!(r_any.encode()[32], INSTANCE_TAG_ANY);
        assert_eq!(r_all.encode()[32], INSTANCE_TAG_ALL);
        assert_eq!(r_specific.encode()[32], INSTANCE_TAG_SPECIFIC);
    }

    // ── Roundtrip ────────────────────────────────────────────────────────────

    #[test]
    fn roundtrip_any() {
        let r = Recipient::any([0xAB; 32]);
        let bytes = r.encode();
        let back = Recipient::decode(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn roundtrip_all() {
        let r = Recipient::all([0xCD; 32]);
        let bytes = r.encode();
        let back = Recipient::decode(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn roundtrip_specific() {
        let r = Recipient::specific([0xEF; 32], [0x77; 16]);
        let bytes = r.encode();
        let back = Recipient::decode(&bytes).unwrap();
        assert_eq!(r, back);
    }

    // ── Embedded decode ──────────────────────────────────────────────────────

    #[test]
    fn decode_from_advances_position() {
        // Embed a Specific recipient in the middle of a bigger buf
        // and check decode_from leaves pos on the next byte.
        let r = Recipient::specific([0x01; 32], [0x02; 16]);
        let embedded = r.encode();
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xFF; 4]); // 4 bytes of prefix
        buf.extend_from_slice(&embedded);
        buf.extend_from_slice(&[0xEE; 8]); // 8 bytes of suffix

        let mut pos = 4;
        let back = Recipient::decode_from(&buf, &mut pos).unwrap();
        assert_eq!(back, r);
        assert_eq!(pos, 4 + embedded.len());
    }

    #[test]
    fn decode_rejects_trailing_bytes_in_standalone_mode() {
        let r = Recipient::any([0x11; 32]);
        let mut bytes = r.encode();
        bytes.push(0xFF);
        let err = Recipient::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    // ── Negative cases ───────────────────────────────────────────────────────

    #[test]
    fn rejects_truncated_node_id() {
        let bytes = [0u8; 20];
        let err = Recipient::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_missing_tag_byte() {
        let bytes = [0u8; 32];
        let err = Recipient::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_unknown_tag() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.push(99);
        let err = Recipient::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn rejects_specific_missing_instance_id() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.push(INSTANCE_TAG_SPECIFIC);
        bytes.extend_from_slice(&[0u8; 8]); // only 8 bytes of instance id — short
        let err = Recipient::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn any_and_all_never_carry_trailing_instance_id() {
        // Regression guard: encoding `Any` with a stray
        // instance_id would be a bug; confirm that neither
        // constructor nor encoding path introduces one.
        let any = Recipient::any([0; 32]);
        let all = Recipient::all([0; 32]);
        assert_eq!(any.encode().len(), RECIPIENT_BYTES_UNBOUND);
        assert_eq!(all.encode().len(), RECIPIENT_BYTES_UNBOUND);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    #[test]
    fn is_unicast_matches_semantics() {
        assert!(InstanceTag::Any.is_unicast());
        assert!(!InstanceTag::All.is_unicast());
        assert!(InstanceTag::Specific([0; 16]).is_unicast());
    }

    #[test]
    fn is_broadcast_matches_semantics() {
        assert!(!InstanceTag::Any.is_broadcast());
        assert!(InstanceTag::All.is_broadcast());
        assert!(!InstanceTag::Specific([0; 16]).is_broadcast());
    }

    #[test]
    fn tag_byte_stable_across_variants() {
        assert_eq!(InstanceTag::Any.byte(), INSTANCE_TAG_ANY);
        assert_eq!(InstanceTag::All.byte(), INSTANCE_TAG_ALL);
        assert_eq!(InstanceTag::Specific([0; 16]).byte(), INSTANCE_TAG_SPECIFIC);
    }

    #[test]
    fn recipient_constructors_set_expected_tag() {
        assert!(matches!(
            Recipient::any([0; 32]).instance_tag,
            InstanceTag::Any
        ));
        assert!(matches!(
            Recipient::all([0; 32]).instance_tag,
            InstanceTag::All
        ));
        assert!(matches!(
            Recipient::specific([0; 32], [1; 16]).instance_tag,
            InstanceTag::Specific(id) if id == [1u8; 16]
        ));
    }

    #[test]
    fn hashable_for_use_as_map_key() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Recipient::any([0; 32]));
        set.insert(Recipient::all([0; 32]));
        set.insert(Recipient::specific([0; 32], [1; 16]));
        set.insert(Recipient::specific([0; 32], [1; 16])); // dup
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn different_variants_with_same_identity_are_distinct() {
        let a = Recipient::any([0; 32]);
        let b = Recipient::all([0; 32]);
        let c = Recipient::specific([0; 32], [0; 16]);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn max_recipient_bytes_matches_specific_variant() {
        assert_eq!(MAX_RECIPIENT_BYTES, RECIPIENT_BYTES_SPECIFIC);
    }
}
