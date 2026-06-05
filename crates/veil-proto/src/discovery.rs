//! Discovery-plane payload structs for the OVL1 binary protocol.
//!
//! Each struct corresponds to one `DiscoveryMsg` variant and is encoded as the
//! frame body (bytes following the fixed `FrameHeader`).
//!
//! # DHT key derivation (per specification §6.5)
//!
//! | Record type | Key formula |
//! |---------------|------------------------------------------------|
//! | Attachment | `BLAKE3("attach" || node_id)` |
//! | App endpoint | `BLAKE3("app" || node_id || app_id || ep_id)` |
//!
//! Helper functions `attachment_key` and `app_endpoint_key`
//! implement these formulas.
//!
//! # Messages
//!
//! | Struct | `DiscoveryMsg` variant |
//! |-----------------------------|---------------------------|
//! | `AnnounceAttachmentPayload` | `AnnounceAttachment` |
//! | `GetAttachmentPayload` | `GetAttachment` (request) |
//! | `AttachmentResponse` | `GetAttachment` (reply) |
//! | `GetAppEndpointPayload` | `GetAppEndpoint` (req) |
//! | `AppEndpointResponse` | `GetAppEndpoint` (reply) |

use super::ProtoError;

// ── Key derivation ────────────────────────────────────────────────────────────

/// Compute the DHT key for an attachment record.
///
/// `key = BLAKE3("attach" || node_id)`
pub fn attachment_key(node_id: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"attach");
    h.update(node_id);
    *h.finalize().as_bytes()
}

/// Compute the DHT key for the network-wide epoch PoW difficulty record.
///
/// `key = BLAKE3("epoch_difficulty" || epoch_be_bytes)`
///
/// Each 24-hour epoch has a single well-known DHT key. Bootstrap nodes
/// publish the difficulty; other nodes query it to validate new identities.
pub fn epoch_difficulty_key(epoch: u32) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"epoch_difficulty");
    h.update(&epoch.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Epoch difficulty record stored in the DHT.
///
/// Wire layout: `[0..4] epoch u32 BE | [4..8] difficulty u32 BE | [8..40] publisher_node_id [u8;32] | [40..104] signature [u8;64]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochDifficultyRecord {
    /// Epoch number (unix_days = unix_secs / 86400).
    pub epoch: u32,
    /// Required PoW difficulty for this epoch (in leading zero bits).
    pub difficulty: u32,
    /// Node ID of the bootstrap node that published this record.
    pub publisher_node_id: [u8; 32],
    /// Ed25519 signature over `[epoch_be || difficulty_be]` by the publisher.
    pub signature: [u8; 64],
}

impl EpochDifficultyRecord {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 4 + 4 + 32 + 64; // 104

    /// Encode to the fixed 104-byte layout.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf.extend_from_slice(&self.difficulty.to_be_bytes());
        buf.extend_from_slice(&self.publisher_node_id);
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Parse from a 104-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, super::ProtoError> {
        // Use the bounds-checked cursor helpers (each call validates its own
        // range) instead of `buf[a..b].try_into().unwrap()` — the prior form
        // would panic with a useless message if WIRE_SIZE/offsets ever drifted
        // out of sync (audit cycle-8: align with the rest of this module).
        let epoch = super::read_u32_be(buf, 0)?;
        let difficulty = super::read_u32_be(buf, 4)?;
        let publisher_node_id: [u8; 32] = super::read_array::<32>(buf, 8)?;
        let signature: [u8; 64] = super::read_array::<64>(buf, 40)?;
        Ok(Self {
            epoch,
            difficulty,
            publisher_node_id,
            signature,
        })
    }

    /// Bytes that are signed: `epoch_be || difficulty_be || publisher_node_id`.
    ///
    /// `publisher_node_id` is included so an attacker cannot substitute a
    /// different publisher while reusing a genuine signature over the same
    /// `(epoch, difficulty)` pair.
    pub fn signable_bytes(&self) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..4].copy_from_slice(&self.epoch.to_be_bytes());
        buf[4..8].copy_from_slice(&self.difficulty.to_be_bytes());
        buf[8..40].copy_from_slice(&self.publisher_node_id);
        buf
    }

    /// Current epoch number (unix days).
    pub fn current_epoch() -> u32 {
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 86400) as u32
    }
}

/// Compute the DHT key for an application endpoint record.
///
/// `key = BLAKE3("app" || node_id || app_id || endpoint_id_be_bytes)`
pub fn app_endpoint_key(node_id: &[u8; 32], app_id: &[u8; 32], endpoint_id: u32) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"app");
    h.update(node_id);
    h.update(app_id);
    h.update(&endpoint_id.to_be_bytes());
    *h.finalize().as_bytes()
}

// ── GatewayRef (wire) ─────────────────────────────────────────────────────────

/// Compact reference to a gateway node embedded inside announcement payloads.
///
/// Wire layout:
/// ```text
/// [0..32] gateway_node_id [u8; 32]
/// [32..34] priority u16 BE
/// [34..36] weight u16 BE
/// [36..38] flags u16 BE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayRef {
    /// Gateway node's `node_id`.
    pub gateway_node_id: [u8; 32],
    /// Priority (lower = preferred).
    pub priority: u16,
    /// Weight used for weighted-random selection among same-priority entries.
    pub weight: u16,
    /// Reserved flags bitmask.
    pub flags: u16,
}

impl GatewayRef {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 2 + 2 + 2;

    /// Encode to the fixed 38-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.gateway_node_id);
        buf[32..34].copy_from_slice(&self.priority.to_be_bytes());
        buf[34..36].copy_from_slice(&self.weight.to_be_bytes());
        buf[36..38].copy_from_slice(&self.flags.to_be_bytes());
        buf
    }

    /// Parse from a 38-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            gateway_node_id: super::read_array::<32>(buf, 0)?,
            priority: super::read_u16_be(buf, 32)?,
            weight: super::read_u16_be(buf, 34)?,
            flags: super::read_u16_be(buf, 36)?,
        })
    }
}

// ── AnnounceAttachmentPayload ─────────────────────────────────────────────────

// ── EphemeralEndpoint TLV ─────────────────────────────────────────

/// TLV tag for the `EphemeralEndpoint` extension in `AnnounceAttachmentPayload`.
///
/// Appended after the signature trailer; unknown tags are skipped by older
/// decoders that have not been updated to support.
pub const EPHEMERAL_ENDPOINT_TLV_TAG: u16 = 0x0010;

/// An ephemeral (rotating) endpoint identifier announced alongside a node's
/// attachment record.
///
/// Gateways and peers use `endpoint_id` as a short-lived indirection token
/// so that the node's stable `node_id` is not exposed in every packet.
/// The identifier is replaced every `rotation_interval` seconds; the previous
/// identifier remains valid until `valid_until` (grace period).
///
/// Wire layout inside TLV value (24 bytes):
/// ```text
/// [0..16] endpoint_id [u8; 16] (CSPRNG random)
/// [16..24] valid_until u64 BE (Unix secs)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralEndpoint {
    /// Random 16-byte identifier rotated every `rotation_interval` seconds.
    pub endpoint_id: [u8; 16],
    /// Unix timestamp (seconds) after which this id must not be used.
    pub valid_until: u64,
}

impl EphemeralEndpoint {
    /// Wire size of the TLV value.
    pub const VALUE_SIZE: usize = 16 + 8; // 24 bytes

    /// Serialise to a complete TLV entry (tag+len+value).
    pub fn encode_tlv(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 2 + Self::VALUE_SIZE);
        out.extend_from_slice(&EPHEMERAL_ENDPOINT_TLV_TAG.to_be_bytes());
        out.extend_from_slice(&(Self::VALUE_SIZE as u16).to_be_bytes());
        out.extend_from_slice(&self.endpoint_id);
        out.extend_from_slice(&self.valid_until.to_be_bytes());
        out
    }

    /// Try to read an `EphemeralEndpoint` TLV from `buf` at `offset`.
    /// Scans all TLV entries and returns the first matching tag, or `None`.
    pub fn decode_from_tlv(buf: &[u8]) -> Option<Self> {
        let mut pos = 0;
        while pos + 4 <= buf.len() {
            let tag = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;
            if pos + len > buf.len() {
                break;
            }
            if tag == EPHEMERAL_ENDPOINT_TLV_TAG && len == Self::VALUE_SIZE {
                let endpoint_id: [u8; 16] = buf[pos..pos + 16].try_into().ok()?;
                let valid_until = u64::from_be_bytes(buf[pos + 16..pos + 24].try_into().ok()?);
                return Some(Self {
                    endpoint_id,
                    valid_until,
                });
            }
            pos += len;
        }
        None
    }
}

/// Announce that `node_id` is currently reachable via the listed gateways and
/// mailboxes.
///
/// Wire layout:
/// ```text
/// [0..32] node_id [u8; 32]
/// [32] role u8
/// [33..37] realm_id u32 BE
/// [37..41] epoch u32 BE
/// [41..49] expires_at u64 BE (Unix secs)
/// [49] gateway_count u8
/// per gateway: GatewayRef::WIRE_SIZE bytes
/// [after gateways] seq_no u64 BE (monotonic counter)
/// [after seq_no] sig_len u16 BE (signature length; 0 = unsigned)
/// [after sig_len] signature [u8; sig_len]
/// [optional TLV] EPHEMERAL_ENDPOINT_TLV_TAG (tag=0x0010, len=24, value=endpoint_id||valid_until)
/// ```
///
/// The signature covers all bytes up (but not including) `sig_len` itself
/// i.e. it signs `node_id … seq_no` — the canonical "signable body".
/// The optional TLV block is appended after the signature and is not covered by
/// the existing signature (it is self-authenticating via the endpoint registry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceAttachmentPayload {
    /// Node this record announces.
    pub node_id: [u8; 32],
    /// Node role (`NodeRole` discriminant).
    pub role: u8,
    /// Realm identifier.
    pub realm_id: u32,
    /// Attachment epoch (monotonic across reconnects).
    pub epoch: u32,
    /// Unix timestamp (seconds) after which the record must be dropped.
    pub expires_at: u64,
    /// Gateways through which the node is reachable.
    pub gateways: Vec<GatewayRef>,
    /// Monotonic sequence number — larger wins on conflict. 0 when unsigned.
    pub seq_no: u64,
    /// Raw signature bytes (Ed25519 = 64 bytes, Falcon512 = variable).
    /// Empty slice = no signature (unsigned record).
    pub signature: Vec<u8>,
    /// Optional ephemeral endpoint identifier.
    /// `None` when the announcing node does not rotate endpoints.
    pub ephemeral_endpoint: Option<EphemeralEndpoint>,
}

impl AnnounceAttachmentPayload {
    const FIXED_SIZE: usize = 32 + 1 + 4 + 4 + 8 + 1; // 50

    /// Encode the "signable body" (everything before the signature trailer).
    ///
    /// Used both in `encode` and when producing/verifying signatures.
    pub fn signable_body(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.node_id);
        buf.push(self.role);
        buf.extend_from_slice(&self.realm_id.to_be_bytes());
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        // Silently truncate to budget limits — the.take below ensures only
        // MAX items are encoded. No panic on oversized input.
        buf.push(self.gateways.len().min(crate::budget::MAX_GATEWAYS) as u8);
        for gw in self.gateways.iter().take(crate::budget::MAX_GATEWAYS) {
            buf.extend_from_slice(&gw.encode());
        }
        buf.extend_from_slice(&self.seq_no.to_be_bytes());
        buf
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.signature.len() <= u16::MAX as usize,
            "AnnounceAttachmentPayload: signature exceeds u16::MAX bytes"
        );
        let mut buf = self.signable_body();
        let sig_len = self.signature.len() as u16;
        buf.extend_from_slice(&sig_len.to_be_bytes());
        buf.extend_from_slice(&self.signature);
        // optional ephemeral endpoint TLV appended after signature.
        if let Some(ep) = &self.ephemeral_endpoint {
            buf.extend_from_slice(&ep.encode_tlv());
        }
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let node_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let role = buf[32];
        let realm_id = super::read_u32_be(buf, 33)?;
        let epoch = super::read_u32_be(buf, 37)?;
        let expires_at = super::read_u64_be(buf, 41)?;
        let gateway_count = buf[49] as usize;
        if gateway_count > crate::budget::MAX_GATEWAYS {
            return Err(ProtoError::ValueTooLarge {
                field: "gateway_count",
                value: gateway_count as u64,
                max: crate::budget::MAX_GATEWAYS as u64,
            });
        }

        let mut offset = 50;
        let mut gateways = Vec::with_capacity(gateway_count);
        for _ in 0..gateway_count {
            let end = offset + GatewayRef::WIRE_SIZE;
            if buf.len() < end {
                return Err(ProtoError::BufferTooShort {
                    need: end,
                    got: buf.len(),
                });
            }
            gateways.push(GatewayRef::decode(&buf[offset..end])?);
            offset = end;
        }

        // seq_no + signature trailer — optional for backwards compat (old format).
        let (seq_no, signature, sig_end_offset) = if buf.len() >= offset + 8 {
            let seq_no = super::read_u64_be(buf, offset)?;
            offset += 8;
            let (signature, sig_end) = if buf.len() >= offset + 2 {
                let sig_len = super::read_u16_be(buf, offset)? as usize;
                offset += 2;
                // Cap before allocating: Falcon-512 max sig is ~666 B; 1024 gives headroom.
                const MAX_ATTACHMENT_SIG_LEN: usize = 1024;
                let sig =
                    super::read_slice(buf, offset, sig_len, MAX_ATTACHMENT_SIG_LEN, "sig_len")?;
                let end = offset + sig_len;
                (sig.to_vec(), end)
            } else {
                (vec![], offset)
            };
            (seq_no, signature, sig_end)
        } else {
            (0, vec![], offset)
        };

        // optional TLV block after the signature.
        let ephemeral_endpoint = EphemeralEndpoint::decode_from_tlv(&buf[sig_end_offset..]);

        Ok(Self {
            node_id,
            role,
            realm_id,
            epoch,
            expires_at,
            gateways,
            seq_no,
            signature,
            ephemeral_endpoint,
        })
    }
}

// ── GetAttachmentPayload / AttachmentResponse ─────────────────────────────────

/// Request the current attachment record for a node.
///
/// Wire layout: `[0..32] node_id [u8; 32]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAttachmentPayload {
    /// Node id field.
    pub node_id: [u8; 32],
}

impl GetAttachmentPayload {
    /// `WIRE_SIZE` constant.
    pub const WIRE_SIZE: usize = 32;

    /// Encode to wire bytes.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.node_id
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            node_id: super::read_array::<32>(buf, 0)?,
        })
    }
}

/// Response to `GetAttachment`. `found = false` if the node is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentResponse {
    /// Found field.
    pub found: bool,
    /// Record field.
    pub record: Option<AnnounceAttachmentPayload>,
}

impl AttachmentResponse {
    /// Construct a negative response.
    pub fn not_found() -> Self {
        Self {
            found: false,
            record: None,
        }
    }

    /// Construct a positive response.
    pub fn found(record: AnnounceAttachmentPayload) -> Self {
        Self {
            found: true,
            record: Some(record),
        }
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(if self.found { 1u8 } else { 0u8 });
        if let Some(rec) = &self.record {
            buf.extend_from_slice(&rec.encode());
        }
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.is_empty() {
            return Err(ProtoError::BufferTooShort { need: 1, got: 0 });
        }
        let found = buf[0] != 0;
        if found {
            let record = AnnounceAttachmentPayload::decode(&buf[1..])?;
            Ok(Self {
                found: true,
                record: Some(record),
            })
        } else {
            Ok(Self {
                found: false,
                record: None,
            })
        }
    }
}

// ── GetAppEndpointPayload / AppEndpointResponse ───────────────────────────────

/// Request an app endpoint record.
///
/// Wire layout: `[0..32] node_id, [32..64] app_id, [64..68] endpoint_id u32 BE`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAppEndpointPayload {
    /// Node id field.
    pub node_id: [u8; 32],
    /// App id field.
    pub app_id: [u8; 32],
    /// Endpoint id field.
    pub endpoint_id: u32,
}

impl GetAppEndpointPayload {
    /// `WIRE_SIZE` constant.
    pub const WIRE_SIZE: usize = 32 + 32 + 4;

    /// Encode to wire bytes.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.node_id);
        buf[32..64].copy_from_slice(&self.app_id);
        buf[64..68].copy_from_slice(&self.endpoint_id.to_be_bytes());
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            node_id: super::read_array::<32>(buf, 0)?,
            app_id: super::read_array::<32>(buf, 32)?,
            endpoint_id: super::read_u32_be(buf, 64)?,
        })
    }
}

/// Response carrying an app endpoint record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEndpointResponse {
    /// Found field.
    pub found: bool,
    /// Gateway through which the endpoint is reachable (when `found`).
    pub gateway_node_id: Option<[u8; 32]>,
    /// Epoch field.
    pub epoch: u32,
    /// Expires at field.
    pub expires_at: u64,
    /// Max simultaneous streams the endpoint accepts (0 = not declared).
    pub max_concurrent_streams: u16,
    /// Application-level protocol version (0 = not declared).
    pub protocol_version: u16,
    /// Indicative inbound bandwidth in kbps (0 = not declared).
    pub bandwidth_hint_kbps: u32,
}

impl AppEndpointResponse {
    /// Construct a negative response.
    pub fn not_found() -> Self {
        Self {
            found: false,
            gateway_node_id: None,
            epoch: 0,
            expires_at: 0,
            max_concurrent_streams: 0,
            protocol_version: 0,
            bandwidth_hint_kbps: 0,
        }
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(if self.found { 1u8 } else { 0u8 });
        if let Some(gw) = &self.gateway_node_id {
            buf.push(1u8);
            buf.extend_from_slice(gw);
        } else {
            buf.push(0u8);
        }
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        // Capability fields (backwards-compat: old decoders ignore trailing bytes).
        buf.extend_from_slice(&self.max_concurrent_streams.to_be_bytes());
        buf.extend_from_slice(&self.protocol_version.to_be_bytes());
        buf.extend_from_slice(&self.bandwidth_hint_kbps.to_be_bytes());
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 2 {
            return Err(ProtoError::BufferTooShort {
                need: 2,
                got: buf.len(),
            });
        }
        let found = buf[0] != 0;
        let has_gw = buf[1] != 0;
        let mut offset = 2;
        let gateway_node_id = if has_gw {
            let end = offset + 32;
            if buf.len() < end {
                return Err(ProtoError::BufferTooShort {
                    need: end,
                    got: buf.len(),
                });
            }
            let gw: [u8; 32] = super::read_array::<32>(buf, offset)?;
            offset = end;
            Some(gw)
        } else {
            None
        };
        if buf.len() < offset + 12 {
            return Err(ProtoError::BufferTooShort {
                need: offset + 12,
                got: buf.len(),
            });
        }
        let epoch = super::read_u32_be(buf, offset)?;
        let expires_at = super::read_u64_be(buf, offset + 4)?;
        offset += 12;
        // Capability fields — optional for backwards compatibility.
        let max_concurrent_streams = if buf.len() >= offset + 2 {
            let v = super::read_u16_be(buf, offset)?;
            offset += 2;
            v
        } else {
            0
        };
        let protocol_version = if buf.len() >= offset + 2 {
            let v = super::read_u16_be(buf, offset)?;
            offset += 2;
            v
        } else {
            0
        };
        let bandwidth_hint_kbps = if buf.len() >= offset + 4 {
            super::read_u32_be(buf, offset)?
        } else {
            0
        };
        Ok(Self {
            found,
            gateway_node_id,
            epoch,
            expires_at,
            max_concurrent_streams,
            protocol_version,
            bandwidth_hint_kbps,
        })
    }
}

// ── Kademlia protocol payloads ────────────────────────────────────────────────

/// A node contact entry returned in `FIND_NODE` responses.
///
/// Wire layout:
/// ```text
/// [0..32] node_id [u8; 32]
/// [32..36] ip_len u32 BE (length of the transport address string)
/// [36..] transport UTF-8 bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeContact {
    /// Node id field.
    pub node_id: [u8; 32],
    /// Transport address (e.g. `"tcp://1.2.3.4:9000"`)
    pub transport: String,
}

impl NodeContact {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let tb = self.transport.as_bytes();
        let mut buf = Vec::with_capacity(32 + 4 + tb.len());
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&(tb.len() as u32).to_be_bytes());
        buf.extend_from_slice(tb);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ProtoError> {
        if buf.len() < 36 {
            return Err(ProtoError::BufferTooShort {
                need: 36,
                got: buf.len(),
            });
        }
        let node_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let tlen = super::read_u32_be(buf, 32)? as usize;
        if tlen > crate::budget::MAX_TRANSPORT_STR_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "transport_len",
                value: tlen as u64,
                max: crate::budget::MAX_TRANSPORT_STR_LEN as u64,
            });
        }
        let end = 36 + tlen;
        if buf.len() < end {
            return Err(ProtoError::BufferTooShort {
                need: end,
                got: buf.len(),
            });
        }
        let transport =
            String::from_utf8(buf[36..end].to_vec()).map_err(|_| ProtoError::InvalidUtf8)?;
        Ok((Self { node_id, transport }, end))
    }
}

// V1 `FindNodePayload` was removed (475.6) —
// the V1 wire flow leaked transports en masse and is no longer
// supported. See `FindNodeV2Payload` + `ResolveTransportPayload`
// for the current discovery flow.

/// Closest-nodes response body.
///
/// Originally the body of `DiscoveryMsg::FindNodeResponse` (V1 — slot
/// 8, removed by). Retained because
/// [`FindValueResponse::Nodes`] reuses this exact wire layout for the
/// "key not found, here are the closest contacts" branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindNodeResponse {
    /// Nodes field.
    pub nodes: Vec<NodeContact>,
}

impl FindNodeResponse {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        debug_assert!(self.nodes.len() <= crate::budget::MAX_NODES_PER_RESPONSE);
        buf.push(self.nodes.len().min(crate::budget::MAX_NODES_PER_RESPONSE) as u8);
        for node in self
            .nodes
            .iter()
            .take(crate::budget::MAX_NODES_PER_RESPONSE)
        {
            buf.extend_from_slice(&node.encode());
        }
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.is_empty() {
            return Err(ProtoError::BufferTooShort { need: 1, got: 0 });
        }
        let count = buf[0] as usize;
        if count > crate::budget::MAX_NODES_PER_RESPONSE {
            return Err(ProtoError::ValueTooLarge {
                field: "node_count",
                value: count as u64,
                max: crate::budget::MAX_NODES_PER_RESPONSE as u64,
            });
        }
        let mut offset = 1;
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            let (contact, consumed) = NodeContact::decode(&buf[offset..])?;
            offset += consumed;
            nodes.push(contact);
        }
        Ok(Self { nodes })
    }
}

// ── FindNodeV2 + ResolveTransport ──────────────────────────

/// FIND_NODE request — `target` + max-K hint. V1 (with a
/// `transport`-bearing response) was removed
/// (475.6); the "V2" name is retained in the type to keep the wire
/// archaeology obvious in proto comments and protocol-spec.md.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindNodeV2Payload {
    /// Target field.
    pub target: [u8; 32],
    /// K field — number of node_ids requested.
    pub k: u8,
}

impl FindNodeV2Payload {
    /// Fixed wire size: 32-byte target + 1-byte k.
    pub const WIRE_SIZE: usize = 32 + 1;

    /// Encode to wire bytes.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.target);
        buf[32] = self.k;
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            target: super::read_array::<32>(buf, 0)?,
            k: buf[32],
        })
    }
}

/// response to `FIND_NODE_V2` — node_ids only, no transports.
///
/// Wire layout:
/// ```text
/// [0] count u8 (≤ MAX_NODES_PER_RESPONSE)
/// [1..1+count*32] node_ids [u8; 32] × count
/// ```
///
/// Caller follows up with [`ResolveTransportPayload`] for any node_id
/// whose transport URL is needed. Transport disclosure is gated by the
/// resolver's own copy of the target's `discovery_mode` (Public-only
/// returned; non-Public answers as `not_found`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindNodeV2Response {
    /// Bare node_ids, no transports.
    pub node_ids: Vec<[u8; 32]>,
}

impl FindNodeV2Response {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let count = self
            .node_ids
            .len()
            .min(crate::budget::MAX_NODES_PER_RESPONSE);
        debug_assert!(self.node_ids.len() <= crate::budget::MAX_NODES_PER_RESPONSE);
        let mut buf = Vec::with_capacity(1 + count * 32);
        buf.push(count as u8);
        for nid in self.node_ids.iter().take(count) {
            buf.extend_from_slice(nid);
        }
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.is_empty() {
            return Err(ProtoError::BufferTooShort { need: 1, got: 0 });
        }
        let count = buf[0] as usize;
        if count > crate::budget::MAX_NODES_PER_RESPONSE {
            return Err(ProtoError::ValueTooLarge {
                field: "node_count",
                value: count as u64,
                max: crate::budget::MAX_NODES_PER_RESPONSE as u64,
            });
        }
        let need = 1 + count * 32;
        if buf.len() < need {
            return Err(ProtoError::BufferTooShort {
                need,
                got: buf.len(),
            });
        }
        let mut node_ids = Vec::with_capacity(count);
        for i in 0..count {
            let off = 1 + i * 32;
            node_ids.push(super::read_array::<32>(buf, off)?);
        }
        Ok(Self { node_ids })
    }
}

/// per-node-id transport lookup.
///
/// Wire layout:
/// ```text
/// [0..32] node_id [u8; 32] — what to resolve
/// [32..36] time_bucket u32 BE — `unix_seconds / RESOLVE_POW_BUCKET_SECONDS`
/// [36..52] pow_nonce [u8; 16] — solution nonce
/// ```
///
/// The PoW input is constructed by [`compute_resolve_pow`] from
/// `(requester_node_id, target_node_id, time_bucket, pow_nonce)` —
/// the requester id is bound by the OVL1 session context (taken from
/// `peer_id` on the responder side, not carried on the wire). The
/// responder accepts the request iff
/// `leading_zero_bits(BLAKE3(input)) >= RESOLVE_POW_DIFFICULTY` AND
/// `|time_bucket - now_bucket| <= RESOLVE_POW_TIME_WINDOW_BUCKETS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveTransportPayload {
    /// Node id whose transport URL we want.
    pub node_id: [u8; 32],
    /// `unix_seconds / RESOLVE_POW_BUCKET_SECONDS` at the time the PoW
    /// was mined. The responder enforces a bounded window around its
    /// own clock to limit replay opportunity.
    pub time_bucket: u32,
    /// Solution nonce found by the requester such that the BLAKE3 hash
    /// of `(requester_node_id || target_node_id || time_bucket || nonce)`
    /// has at least `RESOLVE_POW_DIFFICULTY` leading zero bits.
    pub pow_nonce: [u8; 16],
}

impl ResolveTransportPayload {
    /// Fixed wire size: 32 (node_id) + 4 (time_bucket BE) + 16 (pow_nonce).
    pub const WIRE_SIZE: usize = 32 + 4 + 16;

    /// Encode to wire bytes.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut out = [0u8; Self::WIRE_SIZE];
        out[0..32].copy_from_slice(&self.node_id);
        out[32..36].copy_from_slice(&self.time_bucket.to_be_bytes());
        out[36..52].copy_from_slice(&self.pow_nonce);
        out
    }

    /// Parse from wire bytes. wire-bump: a pre-refactor sender
    /// (32-byte payload) fails decode here and is rejected by the
    /// dispatcher as a `Violation`.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let node_id = super::read_array::<32>(buf, 0)?;
        let time_bucket = u32::from_be_bytes(super::read_array::<4>(buf, 32)?);
        let pow_nonce = super::read_array::<16>(buf, 36)?;
        Ok(Self {
            node_id,
            time_bucket,
            pow_nonce,
        })
    }
}

/// b: leading-zero-bits required on the `ResolveTransport`
/// PoW solution. Tunable cost knob — keep in sync with the spec
/// document (§5.5). Median mining time on a single-core ~3 GHz x86
/// laptop is ~7 ms at 16 bits; ~14 ms on a low-end ARM phone. Server
/// verification cost is one BLAKE3 hash (~1 µs).
pub const RESOLVE_POW_DIFFICULTY: u32 = 16;

/// b: width (in seconds) of one PoW time bucket. The
/// requester puts `unix_seconds / RESOLVE_POW_BUCKET_SECONDS` into
/// the request; the responder accepts buckets within
/// `RESOLVE_POW_TIME_WINDOW_BUCKETS` of its own. 60 seconds keeps
/// solutions short-lived (limits replay window) while leaving room
/// for client/server clock drift.
pub const RESOLVE_POW_BUCKET_SECONDS: u64 = 60;

/// b: max absolute distance (in buckets) between the
/// requester's `time_bucket` and the responder's current bucket. `1`
/// means a 60-second solution is valid for at most ~120 seconds total
/// (one bucket on each side of "now").
pub const RESOLVE_POW_TIME_WINDOW_BUCKETS: i64 = 1;

/// b: domain-separation tag for the `ResolveTransport` PoW
/// hash. Distinct from any other PoW tag in the system so a solution
/// for one purpose can never satisfy another (e.g. the identity-mining
/// PoW or the routing PoW).
pub const RESOLVE_POW_DOMAIN_TAG: &[u8] = b"epic475.4b/resolve_pow/v1";

/// b: compute the PoW input hash for a `ResolveTransport`
/// request. Inputs are concatenated under a domain-separation tag:
///
/// `BLAKE3( DOMAIN_TAG || requester_node_id || target_node_id ||
/// time_bucket_be || pow_nonce)`.
///
/// Both the requester (mining) and the responder (verifying) call this
/// helper so the format stays in lock-step.
pub fn compute_resolve_pow(
    requester_node_id: &[u8; 32],
    target_node_id: &[u8; 32],
    time_bucket: u32,
    pow_nonce: &[u8; 16],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(RESOLVE_POW_DOMAIN_TAG);
    h.update(requester_node_id);
    h.update(target_node_id);
    h.update(&time_bucket.to_be_bytes());
    h.update(pow_nonce);
    *h.finalize().as_bytes()
}

/// b: verify a `ResolveTransport` PoW solution.
///
/// Returns `true` iff the BLAKE3 hash of the canonical input has at
/// least `RESOLVE_POW_DIFFICULTY` leading zero bits. Time-bucket
/// freshness is checked separately by the caller (it requires a
/// "now" clock value, while this helper is pure).
pub fn verify_resolve_pow(
    requester_node_id: &[u8; 32],
    target_node_id: &[u8; 32],
    time_bucket: u32,
    pow_nonce: &[u8; 16],
) -> bool {
    let hash = compute_resolve_pow(requester_node_id, target_node_id, time_bucket, pow_nonce);
    veil_util::leading_zero_bits(&hash) >= RESOLVE_POW_DIFFICULTY
}

/// b: client-side PoW solver.
///
/// Increments a counter into a `[u8; 16]` nonce until
/// [`verify_resolve_pow`] passes. Returns the nonce; the caller
/// supplies `time_bucket` (typically `unix_seconds /
/// RESOLVE_POW_BUCKET_SECONDS`) so the same time-bucket is reused
/// across retries within a single mining run.
///
/// Median cost at the default difficulty (16 bits) is ~65 k hashes
/// (~7 ms on a fast x86 core). Worst-case (high-tail) is bounded by
/// `max_attempts` — a `None` return means the caller should bump the
/// time bucket and try again.
pub fn mine_resolve_pow(
    requester_node_id: &[u8; 32],
    target_node_id: &[u8; 32],
    time_bucket: u32,
    max_attempts: u64,
) -> Option<[u8; 16]> {
    let mut nonce = [0u8; 16];
    for attempt in 0..max_attempts {
        nonce[..8].copy_from_slice(&attempt.to_be_bytes());
        if verify_resolve_pow(requester_node_id, target_node_id, time_bucket, &nonce) {
            return Some(nonce);
        }
    }
    None
}

/// b: convenience wrapper that picks the current time
/// bucket from the system clock and calls [`mine_resolve_pow`].
/// Returns `(time_bucket, pow_nonce)` ready to plug into a
/// [`ResolveTransportPayload`]. `None` only on (vanishingly
/// unlikely) event that 1 M attempts in a single bucket all fail —
/// the caller should retry.
pub fn mine_resolve_pow_now(
    requester_node_id: &[u8; 32],
    target_node_id: &[u8; 32],
) -> Option<(u32, [u8; 16])> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let time_bucket = (now / RESOLVE_POW_BUCKET_SECONDS) as u32;
    let nonce = mine_resolve_pow(requester_node_id, target_node_id, time_bucket, 1_000_000)?;
    Some((time_bucket, nonce))
}

///self-attested transport advertisement
/// signed by the **target node's identity key**.
///
/// Threat: a malicious resolver (peer Bob) returning a forged
/// transport for peer Alice when walker Charlie does
/// `ResolveTransport(Alice)` — Bob can blackhole or MITM Charlie's
/// future connections to Alice for the entire `TransportCache` TTL.
/// Without signatures, the only sanity check is that Alice's OVL1
/// handshake will fail at the wrong endpoint — by which time Charlie
/// has already poisoned the cache.
///
/// Defense: every node signs its own transport URL with its identity
/// key, gossips the bundle to each session peer (one fire-and-forget
/// `AnnounceTransport` per handshake-complete), and the resolver
/// returns that bundle verbatim instead of an unsigned URI. The
/// walker verifies before caching:
///
/// 1. `BLAKE3(identity_pubkey) == announcement.node_id` — binds the
///    pubkey to the routing identity (matches `NodeId::from_public_key`).
/// 2. Ed25519 signature is valid over the canonical signing input
///    (see [`compute_announcement_message`]).
/// 3. `expiry_unix > now` — bounds replay of compromised
///    advertisements after key rotation / churn.
///
/// Wire layout:
/// ```text
/// [0..32] node_id [u8; 32]
/// [32..64] identity_pubkey [u8; 32] Ed25519 raw pubkey
/// [64..96] signature [u8; 64] Ed25519 signature (64 bytes total — see ANN_SIG_LEN)
///... wait, [64..128] is signature; expiry comes after.
/// [64..128] signature [u8; 64] Ed25519 signature
/// [128..136] expiry_unix u64 BE
/// [136..138] transport_len u16 BE
/// [138..N] transport UTF-8 bytes
/// ```
///
/// Total fixed header = 138 bytes; transport adds ≤ `MAX_TRANSPORT_URI_LEN`.
///
///also `Serialize`/`Deserialize` so the
/// runtime can flush a JSON snapshot of the in-memory announcement
/// store to disk for warm-restart.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedTransportAnnouncement {
    /// Routing-identity node id — must equal `BLAKE3(identity_pubkey)`.
    #[serde(with = "crate::serde_base64::hex_array")]
    pub node_id: [u8; 32],
    /// Raw 32-byte Ed25519 public key — verifier uses this to check
    /// `signature` and to confirm the `node_id` binding.
    #[serde(with = "crate::serde_base64::hex_array")]
    pub identity_pubkey: [u8; 32],
    /// Ed25519 signature over [`compute_transport_announcement_message`].
    #[serde(with = "serde_signature_64")]
    pub signature: [u8; 64],
    /// Unix-seconds at which this announcement is no longer accepted
    /// — caller must call [`verify_transport_announcement`] which
    /// checks against `now`.
    pub expiry_unix: u64,
    /// Transport URI (e.g. `tcp://node.example.com:7000`). Capped at
    /// [`MAX_TRANSPORT_URI_LEN`] on encode to bound the wire frame.
    pub transport: String,
}

/// Serde helper: encode `[u8; 64]` (Ed25519 signature) as a base64
/// string so JSON snapshots stay greppable. The
/// `kademlia::hex_array` helper only handles `[u8; 32]` so we have a
/// 64-byte twin here.
mod serde_signature_64 {
    use base64::Engine as _;
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = <&str as serde::Deserialize>::deserialize(d)?;
        let v = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(D::Error::custom)?;
        v.try_into()
            .map_err(|_| D::Error::custom("expected 64 bytes"))
    }
}

/// c: longest transport URI we'll encode in an announcement.
/// Wire frame is bounded at `~256 + 138 = 394` bytes which is well
/// under the discovery-quota frame budget.
pub const MAX_TRANSPORT_URI_LEN: usize = 256;

/// c: domain-separation tag for the announcement signing
/// hash — distinct from the resolve-PoW tag and any other PoW input
/// in the system.
pub const ANNOUNCEMENT_DOMAIN_TAG: &[u8] = b"epic475.4c/transport_announce/v1";

/// c: default validity window for self-signed transport
/// announcements (30 days). A node re-signs and re-gossips before
/// expiry; verifiers reject anything past `expiry_unix`. 30 days is a
/// trade-off — short enough to bound a compromised key's blast radius
/// long enough that a node offline for two weeks still has a valid
/// announcement when it comes back up.
pub const ANNOUNCEMENT_VALIDITY_SECS: u64 = 30 * 24 * 60 * 60;

impl SignedTransportAnnouncement {
    /// Fixed-prefix wire size — `transport_len` (u16) + `transport`
    /// bytes follow.
    pub const FIXED_PREFIX_SIZE: usize = 32 + 32 + 64 + 8 + 2;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let bytes = self.transport.as_bytes();
        let len = bytes.len().min(MAX_TRANSPORT_URI_LEN);
        let mut buf = Vec::with_capacity(Self::FIXED_PREFIX_SIZE + len);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&self.identity_pubkey);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&self.expiry_unix.to_be_bytes());
        buf.extend_from_slice(&(len as u16).to_be_bytes());
        buf.extend_from_slice(&bytes[..len]);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_PREFIX_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_PREFIX_SIZE,
                got: buf.len(),
            });
        }
        let node_id = super::read_array::<32>(buf, 0)?;
        let identity_pubkey = super::read_array::<32>(buf, 32)?;
        let signature = super::read_array::<64>(buf, 64)?;
        let expiry_unix = super::read_u64_be(buf, 128)?;
        let transport_len = super::read_u16_be(buf, 136)? as usize;
        if transport_len > MAX_TRANSPORT_URI_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "SignedTransportAnnouncement.transport_len",
                value: transport_len as u64,
                max: MAX_TRANSPORT_URI_LEN as u64,
            });
        }
        let need = Self::FIXED_PREFIX_SIZE + transport_len;
        if buf.len() < need {
            return Err(ProtoError::BufferTooShort {
                need,
                got: buf.len(),
            });
        }
        let transport = std::str::from_utf8(&buf[Self::FIXED_PREFIX_SIZE..need])
            .map_err(|_| ProtoError::ValueTooLarge {
                field: "SignedTransportAnnouncement.transport (non-UTF-8)",
                value: transport_len as u64,
                max: MAX_TRANSPORT_URI_LEN as u64,
            })?
            .to_owned();
        Ok(Self {
            node_id,
            identity_pubkey,
            signature,
            expiry_unix,
            transport,
        })
    }
}

/// c: canonical signing input [`SignedTransportAnnouncement`].
///
/// `BLAKE3( DOMAIN_TAG || node_id || expiry_unix_be || transport_len_be
/// || transport_utf8)`.
///
/// The `identity_pubkey` is **not** included in the signing input —
/// the verifier rederives the binding via `BLAKE3(pubkey) == node_id`
/// which is what makes the bundle self-authenticating. Transport
/// length is included so a forger can't truncate / extend the URI
/// without invalidating the signature.
pub fn compute_transport_announcement_message(
    node_id: &[u8; 32],
    expiry_unix: u64,
    transport: &str,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ANNOUNCEMENT_DOMAIN_TAG);
    h.update(node_id);
    h.update(&expiry_unix.to_be_bytes());
    let bytes = transport.as_bytes();
    let len = bytes.len().min(MAX_TRANSPORT_URI_LEN);
    h.update(&(len as u16).to_be_bytes());
    h.update(&bytes[..len]);
    *h.finalize().as_bytes()
}

/// c: produce a fresh self-signed transport announcement.
pub fn sign_transport_announcement(
    signing_key: &ed25519_dalek::SigningKey,
    transport: String,
    expiry_unix: u64,
) -> SignedTransportAnnouncement {
    use ed25519_dalek::Signer;
    let identity_pubkey: [u8; 32] = signing_key.verifying_key().to_bytes();
    let node_id: [u8; 32] = *blake3::hash(&identity_pubkey).as_bytes();
    let msg = compute_transport_announcement_message(&node_id, expiry_unix, &transport);
    let signature: [u8; 64] = signing_key.sign(&msg).to_bytes();
    SignedTransportAnnouncement {
        node_id,
        identity_pubkey,
        signature,
        expiry_unix,
        transport,
    }
}

/// c: verify a signed transport announcement.
pub fn verify_transport_announcement(
    announcement: &SignedTransportAnnouncement,
    now_unix: u64,
) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if announcement.expiry_unix <= now_unix {
        return false;
    }
    if *blake3::hash(&announcement.identity_pubkey).as_bytes() != announcement.node_id {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(&announcement.identity_pubkey) else {
        return false;
    };
    let msg = compute_transport_announcement_message(
        &announcement.node_id,
        announcement.expiry_unix,
        &announcement.transport,
    );
    let sig = Signature::from_bytes(&announcement.signature);
    vk.verify(&msg, &sig).is_ok()
}

/// response to `ResolveTransport`.
///
/// Wire layout:
/// ```text
/// [0..32] node_id [u8; 32] — echoed for caller correlation
/// [32] found u8 (0 = not found, 1 = found)
/// if found == 1:
/// [33..35] announcement_len u16 BE
/// [35..35+N] announcement bytes (encoded `SignedTransportAnnouncement`)
/// ```
///
/// `not_found` is returned when:
/// * The resolver has no signed announcement for `node_id`.
/// * The corresponding Contact's `discovery_mode!= Public`.
/// * The PoW gate on the request failed.
///
/// All rejection reasons collapse to `not_found` — the responder must
/// not reveal *which* check failed.
///
/// 2 carried just an unsigned URI string;
/// promotes it to a `SignedTransportAnnouncement` so a malicious
/// resolver cannot fabricate a transport for a peer it doesn't have
/// a self-signed advertisement (they could still lie about a
/// peer's *existence* — return `not_found` — but cannot redirect
/// traffic to an attacker-controlled endpoint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveTransportResponse {
    /// Echoed `node_id` from the request — caller correlation key.
    pub node_id: [u8; 32],
    /// `Some(announcement)` when the resolver has a self-signed
    /// advertisement for a Public peer with this `node_id`; `None`
    /// for unknown / private / failed-PoW.
    pub announcement: Option<SignedTransportAnnouncement>,
}

impl ResolveTransportResponse {
    /// Wire size of the fixed prefix (`node_id` + `found` flag).
    pub const PREFIX_SIZE: usize = 32 + 1;

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        match &self.announcement {
            None => {
                let mut buf = Vec::with_capacity(Self::PREFIX_SIZE);
                buf.extend_from_slice(&self.node_id);
                buf.push(0u8);
                buf
            }
            Some(ann) => {
                let body = ann.encode();
                let len = body.len().min(u16::MAX as usize);
                let mut buf = Vec::with_capacity(Self::PREFIX_SIZE + 2 + len);
                buf.extend_from_slice(&self.node_id);
                buf.push(1u8);
                buf.extend_from_slice(&(len as u16).to_be_bytes());
                buf.extend_from_slice(&body[..len]);
                buf
            }
        }
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::PREFIX_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::PREFIX_SIZE,
                got: buf.len(),
            });
        }
        let node_id = super::read_array::<32>(buf, 0)?;
        let found = buf[32];
        if found == 0 {
            return Ok(Self {
                node_id,
                announcement: None,
            });
        }
        if buf.len() < Self::PREFIX_SIZE + 2 {
            return Err(ProtoError::BufferTooShort {
                need: Self::PREFIX_SIZE + 2,
                got: buf.len(),
            });
        }
        let ann_len = super::read_u16_be(buf, Self::PREFIX_SIZE)? as usize;
        let ann_end = Self::PREFIX_SIZE + 2 + ann_len;
        if buf.len() < ann_end {
            return Err(ProtoError::BufferTooShort {
                need: ann_end,
                got: buf.len(),
            });
        }
        let announcement =
            SignedTransportAnnouncement::decode(&buf[Self::PREFIX_SIZE + 2..ann_end])?;
        Ok(Self {
            node_id,
            announcement: Some(announcement),
        })
    }
}

// ── FindValuePayload / FindValueResponse ──────────────────────────────────────

/// Request the value stored at a given key, or the closest nodes if not found.
///
/// Wire layout: `[0..32] key [u8; 32]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindValuePayload {
    /// Key field.
    pub key: [u8; 32],
}

impl FindValuePayload {
    /// `WIRE_SIZE` constant.
    pub const WIRE_SIZE: usize = 32;

    /// Encode to wire bytes.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.key
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            key: super::read_array::<32>(buf, 0)?,
        })
    }
}

/// Response to `FIND_VALUE`.
///
/// Wire layout:
/// ```text
/// [0] found u8 (0 = not found, 1 = found)
/// if found:
/// [1..5] value_len u32 BE
/// [5..] value bytes
/// else:
/// closest nodes (FindNodeResponse format, without leading byte)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindValueResponse {
    /// Value bytes found at the target key.
    Value(Vec<u8>),
    /// Target key not found; closest known contacts instead.
    Nodes(Vec<NodeContact>),
}

impl FindValueResponse {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Value(v) => {
                let mut buf = vec![1u8];
                buf.extend_from_slice(&(v.len() as u32).to_be_bytes());
                buf.extend_from_slice(v);
                buf
            }
            Self::Nodes(nodes) => {
                let mut buf = vec![0u8];
                debug_assert!(nodes.len() <= crate::budget::MAX_NODES_PER_RESPONSE);
                buf.push(nodes.len().min(crate::budget::MAX_NODES_PER_RESPONSE) as u8);
                for n in nodes.iter().take(crate::budget::MAX_NODES_PER_RESPONSE) {
                    buf.extend_from_slice(&n.encode());
                }
                buf
            }
        }
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.is_empty() {
            return Err(ProtoError::BufferTooShort { need: 1, got: 0 });
        }
        if buf[0] != 0 {
            // found
            if buf.len() < 5 {
                return Err(ProtoError::BufferTooShort {
                    need: 5,
                    got: buf.len(),
                });
            }
            let vlen = super::read_u32_be(buf, 1)? as usize;
            // checked_add — 32-bit overflow defence.
            let end = 5usize.checked_add(vlen).ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
            if buf.len() < end {
                return Err(ProtoError::BufferTooShort {
                    need: end,
                    got: buf.len(),
                });
            }
            Ok(Self::Value(buf[5..end].to_vec()))
        } else {
            // not found — closest nodes
            if buf.len() < 2 {
                return Err(ProtoError::BufferTooShort {
                    need: 2,
                    got: buf.len(),
                });
            }
            let count = buf[1] as usize;
            if count > crate::budget::MAX_NODES_PER_RESPONSE {
                return Err(ProtoError::ValueTooLarge {
                    field: "node_count",
                    value: count as u64,
                    max: crate::budget::MAX_NODES_PER_RESPONSE as u64,
                });
            }
            let resp = FindNodeResponse::decode(&buf[1..])?;
            Ok(Self::Nodes(resp.nodes))
        }
    }
}

// ── StorePayload ──────────────────────────────────────────────────────────────

/// Store a value at a DHT key.
///
/// Wire layout:
/// ```text
/// [0..32] key [u8; 32]
/// [32..36] value_len u32 BE
/// [36..] value bytes [value_len]
/// ```
///
/// **Optional authenticator extension:**
/// Appended after `value` when `ed25519_pubkey` is `Some`. Enables the
/// receiver to verify that the sender owns the DHT key (when
/// `key == BLAKE3(pubkey)`). Nodes MUST verify and reject STORE frames whose
/// key matches this relationship but whose signature is missing or invalid.
///
/// ```text
/// [36+value_len] sig_flag u8 — 0x00 = unsigned, 0x01 = signed
/// [37+value_len..+32] ed25519_pubkey [u8; 32] — only if sig_flag == 0x01
/// [69+value_len..+64] ed25519_sig [u8; 64] — only if sig_flag == 0x01
/// ```
///
/// The signature covers `key(32) || value(value_len)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePayload {
    /// Key field.
    pub key: [u8; 32],
    /// Value field.
    pub value: Vec<u8>,
    /// Ed25519 public key of the value owner.
    /// `Some` only when the sender wishes to prove ownership of the key.
    pub ed25519_pubkey: Option<[u8; 32]>,
    /// Ed25519 signature over `key || value`.
    /// `Some` iff `ed25519_pubkey` is `Some`.
    pub ed25519_sig: Option<[u8; 64]>,
}

impl StorePayload {
    const FIXED_SIZE: usize = 32 + 4;
    /// Wire size of the optional authenticator extension.
    /// 1 (flag) + 32 (pubkey) + 64 (sig) = 97.
    const AUTH_EXT_SIZE: usize = 1 + 32 + 64;

    /// Build an unsigned StorePayload (no signature).
    pub fn unsigned(key: [u8; 32], value: Vec<u8>) -> Self {
        Self {
            key,
            value,
            ed25519_pubkey: None,
            ed25519_sig: None,
        }
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.value.len() + Self::AUTH_EXT_SIZE);
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(&(self.value.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.value);
        match (&self.ed25519_pubkey, &self.ed25519_sig) {
            (Some(pk), Some(sig)) => {
                buf.push(0x01); // sig_flag: signed
                buf.extend_from_slice(pk);
                buf.extend_from_slice(sig);
            }
            _ => {
                buf.push(0x00); // sig_flag: unsigned
            }
        }
        buf
    }

    /// Parse from wire bytes. `sig_flag` byte is mandatory.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        let key: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let vlen = super::read_u32_be(buf, 32)? as usize;
        let value =
            super::read_slice(buf, 36, vlen, crate::budget::MAX_DHT_VALUE_BYTES, "vlen")?.to_vec();
        // defensive checked_add chain — even though `vlen` is
        // capped via read_slice (≤ MAX_DHT_VALUE_BYTES), defence-in-depth.
        let value_end = 36usize
            .checked_add(vlen)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;

        if buf.len() <= value_end {
            return Err(ProtoError::BufferTooShort {
                need: value_end.saturating_add(1),
                got: buf.len(),
            });
        }
        let sig_flag = buf[value_end];
        let (ed25519_pubkey, ed25519_sig) = if sig_flag == 0x01 {
            // Build offsets с checked_add chain.
            let pk_start = value_end.checked_add(1).ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
            let sig_start = pk_start.checked_add(32).ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
            let ext_end = sig_start
                .checked_add(64)
                .ok_or(ProtoError::BufferTooShort {
                    need: usize::MAX,
                    got: buf.len(),
                })?;
            if buf.len() < ext_end {
                return Err(ProtoError::BufferTooShort {
                    need: ext_end,
                    got: buf.len(),
                });
            }
            let pk: [u8; 32] = super::read_array::<32>(buf, pk_start)?;
            let sig: [u8; 64] = super::read_array::<64>(buf, sig_start)?;
            (Some(pk), Some(sig))
        } else {
            (None, None)
        };

        Ok(Self {
            key,
            value,
            ed25519_pubkey,
            ed25519_sig,
        })
    }

    /// Return the bytes that a signature covers: `key || value`.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + self.value.len());
        v.extend_from_slice(&self.key);
        v.extend_from_slice(&self.value);
        v
    }
}

// ── DeletePayload ─────────────────────────────────────────────────────────────

// ── DhtValue ──────────────────────────────────────────────────────────────────

/// DHT value envelope with signature (specification §5.5).
///
/// All values stored in the Kademlia DHT are wrapped in this envelope.
/// The `signature` covers the "signable prefix" (everything up to and including
/// `seq_no`). An empty `signature` field means the record is unsigned (e.g. for
/// locally-trusted data or data not yet requiring authentication).
///
/// Wire layout:
/// ```text
/// [0..32] key [u8; 32]
/// [32] kind u8 (record type: 1=attachment, 2=mailbox, 3=app_endpoint)
/// [33..37] epoch u32 BE
/// [37..41] ttl_secs u32 BE
/// [41..49] seq_no u64 BE
/// [49..53] body_len u32 BE
/// [53..] body bytes [body_len]
/// [53+body_len.. +2] sig_len u16 BE
/// [55+body_len.. +sig_len] signature
/// ```
///
/// The signable prefix is bytes `[0.. 53+body_len]` (key through body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtValue {
    /// Key field.
    pub key: [u8; 32],
    /// Record type discriminant:
    /// `1` = attachment, `2` = mailbox set, `3` = app endpoint, `0` = raw.
    pub kind: u8,
    /// Epoch field.
    pub epoch: u32,
    /// Ttl secs field.
    pub ttl_secs: u32,
    /// Seq no field.
    pub seq_no: u64,
    /// Body field.
    pub body: Vec<u8>,
    /// Raw signature bytes. Empty = unsigned.
    pub signature: Vec<u8>,
}

/// `DhtValue::kind` discriminants.
pub mod dht_value_kind {
    /// `RAW` constant.
    pub const RAW: u8 = 0;
    /// `ATTACHMENT` constant.
    pub const ATTACHMENT: u8 = 1;
    /// `MAILBOX` constant.
    pub const MAILBOX: u8 = 2;
    /// `APP_ENDPOINT` constant.
    pub const APP_ENDPOINT: u8 = 3;
}

impl DhtValue {
    const FIXED_HEADER: usize = 32 + 1 + 4 + 4 + 8 + 4; // 53

    /// Return the "signable prefix" — bytes that the signature covers.
    pub fn signable_prefix(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED_HEADER + self.body.len());
        buf.extend_from_slice(&self.key);
        buf.push(self.kind);
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf.extend_from_slice(&self.ttl_secs.to_be_bytes());
        buf.extend_from_slice(&self.seq_no.to_be_bytes());
        buf.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.signature.len() <= u16::MAX as usize,
            "DhtValue: signature exceeds u16::MAX bytes"
        );
        let mut buf = self.signable_prefix();
        let sig_len = self.signature.len() as u16;
        buf.extend_from_slice(&sig_len.to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::FIXED_HEADER {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_HEADER,
                got: buf.len(),
            });
        }
        let key: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let kind = buf[32];
        let epoch = super::read_u32_be(buf, 33)?;
        let ttl_secs = super::read_u32_be(buf, 37)?;
        let seq_no = super::read_u64_be(buf, 41)?;
        // checked_add chain — defends 32-bit (Android armv7)
        // against u32::MAX-class body_len/sig_len wraparound that would
        // bypass the bounds check and OOB-panic on slicing.
        let body_len = super::read_u32_be(buf, 49)? as usize;
        let body_end = 53usize
            .checked_add(body_len)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
        if buf.len() < body_end {
            return Err(ProtoError::BufferTooShort {
                need: body_end,
                got: buf.len(),
            });
        }
        let body = buf[53..body_end].to_vec();

        let signature = if buf.len() >= body_end.saturating_add(2) {
            let sig_len = super::read_u16_be(buf, body_end)? as usize;
            let sig_start = body_end.checked_add(2).ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
            let sig_end = sig_start
                .checked_add(sig_len)
                .ok_or(ProtoError::BufferTooShort {
                    need: usize::MAX,
                    got: buf.len(),
                })?;
            if buf.len() < sig_end {
                return Err(ProtoError::BufferTooShort {
                    need: sig_end,
                    got: buf.len(),
                });
            }
            buf[sig_start..sig_end].to_vec()
        } else {
            vec![]
        };

        Ok(Self {
            key,
            kind,
            epoch,
            ttl_secs,
            seq_no,
            body,
            signature,
        })
    }

    /// Return `true` if the record has a non-empty signature.
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }
}

// ── Announcement signing helpers ─────────────────────────────────────────────
// MOVED to `node::discovery::announcement_sig`.
// Proto stays pure-data; orchestration of sign/verify lives at
// caller layer. See docs/CRATE_ARCHITECTURE.md status.

// ── DeletePayload ─────────────────────────────────────────────────────────────

/// Delete a DHT record by key.
///
/// Wire layout:
/// ```text
/// [0..32] key [u8; 32]
/// [32] algo u8 (0 = Ed25519, 2 = Falcon512)
/// [33..35] pk_len u16 BE
/// [35.. 35+pk_len] public_key bytes
/// [.. +2] sig_len u16 BE
/// [.. +sig_len] signature bytes
/// ```
///
/// Signature covers the `key` bytes; pubkey must hash to `key` (BLAKE3).
/// Supports both Ed25519 (32-byte pubkey, 64-byte sig) and Falcon512
/// (897-byte pubkey, ~666-byte sig).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletePayload {
    /// DHT key to delete.
    pub key: [u8; 32],
    /// Signature algorithm: 0 = Ed25519, 2 = Falcon512 (matches `IdentityPayload`).
    pub algo: u8,
    /// Public key of the deleter (length depends on `algo`).
    pub public_key: Vec<u8>,
    /// Signature over `key` — proves ownership (length depends on `algo`).
    pub signature: Vec<u8>,
}

impl DeletePayload {
    /// Minimum wire size: key(32) + algo(1) + pk_len(2) + sig_len(2).
    pub const MIN_WIRE_SIZE: usize = 32 + 1 + 2 + 2;

    /// Bytes covered by the signature (the key itself).
    pub fn signable_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(Self::MIN_WIRE_SIZE + self.public_key.len() + self.signature.len());
        buf.extend_from_slice(&self.key);
        buf.push(self.algo);
        buf.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::MIN_WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::MIN_WIRE_SIZE,
                got: buf.len(),
            });
        }
        let key: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let algo = buf[32];
        let pk_len = super::read_u16_be(buf, 33)? as usize;
        let pk_end = 35 + pk_len;
        let public_key = super::read_slice(
            buf,
            35,
            pk_len,
            crate::budget::MAX_SIGNATURE_PUBKEY_BYTES,
            "pk_len",
        )?
        .to_vec();
        if buf.len() < pk_end + 2 {
            return Err(ProtoError::BufferTooShort {
                need: pk_end + 2,
                got: buf.len(),
            });
        }
        let sig_len = super::read_u16_be(buf, pk_end)? as usize;
        let signature = super::read_slice(
            buf,
            pk_end + 2,
            sig_len,
            crate::budget::MAX_DHT_SIG_BYTES,
            "sig_len",
        )?
        .to_vec();
        Ok(Self {
            key,
            algo,
            public_key,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_gw() -> GatewayRef {
        GatewayRef {
            gateway_node_id: [0xABu8; 32],
            priority: 1,
            weight: 10,
            flags: 0,
        }
    }

    fn sample_announce() -> AnnounceAttachmentPayload {
        AnnounceAttachmentPayload {
            node_id: [1u8; 32],
            role: 1,
            realm_id: 42,
            epoch: 7,
            expires_at: 1_700_000_000,
            gateways: vec![sample_gw()],
            seq_no: 0,
            signature: vec![],
            ephemeral_endpoint: None,
        }
    }

    fn sample_announce_signed() -> AnnounceAttachmentPayload {
        AnnounceAttachmentPayload {
            node_id: [2u8; 32],
            role: 2,
            realm_id: 10,
            epoch: 3,
            expires_at: 1_800_000_000,
            gateways: vec![],
            seq_no: 42,
            signature: vec![0xAAu8; 64], // mock 64-byte Ed25519 signature
            ephemeral_endpoint: None,
        }
    }

    // ── key derivation ────────────────────────────────────────────────────

    #[test]
    fn attachment_key_deterministic() {
        let k1 = attachment_key(&[1u8; 32]);
        let k2 = attachment_key(&[1u8; 32]);
        assert_eq!(k1, k2);
    }

    #[test]
    fn attachment_key_differs_per_node() {
        assert_ne!(attachment_key(&[1u8; 32]), attachment_key(&[2u8; 32]));
    }

    #[test]
    fn app_endpoint_key_differs_by_endpoint() {
        let k1 = app_endpoint_key(&[1u8; 32], &[2u8; 32], 1);
        let k2 = app_endpoint_key(&[1u8; 32], &[2u8; 32], 2);
        assert_ne!(k1, k2);
    }

    // ── GatewayRef ────────────────────────────────────────────────────────

    #[test]
    fn gateway_ref_roundtrip() {
        let gw = sample_gw();
        assert_eq!(GatewayRef::decode(&gw.encode()).unwrap(), gw);
    }

    // ── AnnounceAttachment ────────────────────────────────────────────────

    #[test]
    fn announce_attachment_roundtrip() {
        let p = sample_announce();
        let encoded = p.encode();
        let decoded = AnnounceAttachmentPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn announce_attachment_empty_lists() {
        let mut p = sample_announce();
        p.gateways = vec![];
        assert_eq!(AnnounceAttachmentPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn announce_attachment_too_short() {
        assert!(AnnounceAttachmentPayload::decode(&[0u8; 10]).is_err());
    }

    // ── signed attachment roundtrip ──────────────────────────────────────

    #[test]
    fn announce_attachment_with_signature_roundtrip() {
        let p = sample_announce_signed();
        let decoded = AnnounceAttachmentPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
        assert_eq!(decoded.seq_no, 42);
        assert_eq!(decoded.signature.len(), 64);
    }

    #[test]
    fn signable_body_excludes_signature() {
        let p = sample_announce_signed();
        let body = p.signable_body();
        // Signable body must NOT include the sig_len or signature bytes themselves.
        let full = p.encode();
        // Full encoded = signable_body + 2 (sig_len) + 64 (sig) = body.len + 66
        assert_eq!(full.len(), body.len() + 2 + 64);
    }

    #[test]
    fn announce_attachment_backwards_compat_no_seq_sig() {
        // An old-format record without seq_no/signature should decode with seq_no=0, sig=empty.
        let old_format_body = {
            let p = sample_announce();
            // Encode without the seq_no/signature trailer.
            let mut buf = Vec::new();
            buf.extend_from_slice(&p.node_id);
            buf.push(p.role);
            buf.extend_from_slice(&p.realm_id.to_be_bytes());
            buf.extend_from_slice(&p.epoch.to_be_bytes());
            buf.extend_from_slice(&p.expires_at.to_be_bytes());
            buf.push(p.gateways.len() as u8);
            for gw in &p.gateways {
                buf.extend_from_slice(&gw.encode());
            }
            buf
        };
        let decoded = AnnounceAttachmentPayload::decode(&old_format_body).unwrap();
        assert_eq!(decoded.seq_no, 0);
        assert!(decoded.signature.is_empty());
    }

    // ── EphemeralEndpoint in AnnounceAttachmentPayload ─────────

    #[test]
    fn announce_with_ephemeral_endpoint_roundtrip() {
        let mut p = sample_announce();
        p.ephemeral_endpoint = Some(EphemeralEndpoint {
            endpoint_id: [0xABu8; 16],
            valid_until: 1_700_099_999,
        });
        let decoded = AnnounceAttachmentPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
        let ep = decoded.ephemeral_endpoint.unwrap();
        assert_eq!(ep.endpoint_id, [0xABu8; 16]);
        assert_eq!(ep.valid_until, 1_700_099_999);
    }

    #[test]
    fn announce_without_ephemeral_endpoint_roundtrip() {
        let p = sample_announce(); // ephemeral_endpoint: None
        let decoded = AnnounceAttachmentPayload::decode(&p.encode()).unwrap();
        assert!(decoded.ephemeral_endpoint.is_none());
    }

    // ── GetAttachment / AttachmentResponse ────────────────────────────────

    #[test]
    fn get_attachment_roundtrip() {
        let p = GetAttachmentPayload { node_id: [7u8; 32] };
        assert_eq!(GetAttachmentPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn attachment_response_found_roundtrip() {
        let resp = AttachmentResponse::found(sample_announce());
        assert_eq!(AttachmentResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn attachment_response_not_found_roundtrip() {
        let resp = AttachmentResponse::not_found();
        assert_eq!(AttachmentResponse::decode(&resp.encode()).unwrap(), resp);
    }

    // ── GetAppEndpoint / AppEndpointResponse ──────────────────────────────

    #[test]
    fn get_app_endpoint_roundtrip() {
        let p = GetAppEndpointPayload {
            node_id: [1u8; 32],
            app_id: [2u8; 32],
            endpoint_id: 8080,
        };
        assert_eq!(GetAppEndpointPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn app_endpoint_response_found_roundtrip() {
        let resp = AppEndpointResponse {
            found: true,
            gateway_node_id: Some([0x55u8; 32]),
            epoch: 3,
            expires_at: 1_800_000_000,
            max_concurrent_streams: 50,
            protocol_version: 3,
            bandwidth_hint_kbps: 2048,
        };
        assert_eq!(AppEndpointResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn app_endpoint_response_not_found_roundtrip() {
        let resp = AppEndpointResponse::not_found();
        assert_eq!(AppEndpointResponse::decode(&resp.encode()).unwrap(), resp);
    }

    // ── Kademlia payloads ─────────────────────────────────────────────────

    #[test]
    fn node_contact_roundtrip() {
        let c = NodeContact {
            node_id: [0xAAu8; 32],
            transport: "tcp://1.2.3.4:9000".to_owned(),
        };
        let encoded = c.encode();
        let (decoded, consumed) = NodeContact::decode(&encoded).unwrap();
        assert_eq!(decoded, c);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn find_node_response_roundtrip() {
        let resp = FindNodeResponse {
            nodes: vec![
                NodeContact {
                    node_id: [1u8; 32],
                    transport: "tcp://a:1".to_owned(),
                },
                NodeContact {
                    node_id: [2u8; 32],
                    transport: "tcp://b:2".to_owned(),
                },
            ],
        };
        assert_eq!(FindNodeResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn find_value_response_value_roundtrip() {
        let resp = FindValueResponse::Value(b"attachment-record".to_vec());
        assert_eq!(FindValueResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn find_value_response_nodes_roundtrip() {
        let resp = FindValueResponse::Nodes(vec![NodeContact {
            node_id: [3u8; 32],
            transport: "tcp://c:3".to_owned(),
        }]);
        assert_eq!(FindValueResponse::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn store_payload_roundtrip() {
        // Unsigned (legacy) roundtrip.
        let p = StorePayload::unsigned([7u8; 32], b"stored-value".to_vec());
        assert_eq!(StorePayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn store_payload_signed_roundtrip() {
        // Build a signed StorePayload and verify encode/decode round-trips.
        let p = StorePayload {
            key: [0xAAu8; 32],
            value: b"my-value".to_vec(),
            ed25519_pubkey: Some([0xBBu8; 32]),
            ed25519_sig: Some([0xCCu8; 64]),
        };
        let decoded = StorePayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn store_payload_missing_sig_flag_rejected() {
        // A frame that ends after the value bytes (no sig_flag) must be rejected.
        let key = [0x11u8; 32];
        let value = b"old-format".to_vec();
        let mut buf = Vec::new();
        buf.extend_from_slice(&key);
        buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
        buf.extend_from_slice(&value);
        assert!(StorePayload::decode(&buf).is_err());
    }

    #[test]
    fn delete_payload_roundtrip_ed25519() {
        let p = DeletePayload {
            key: [0xFFu8; 32],
            algo: 0,
            public_key: vec![0u8; 32],
            signature: vec![0u8; 64],
        };
        assert_eq!(DeletePayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn delete_payload_roundtrip_falcon512() {
        let p = DeletePayload {
            key: [0xAAu8; 32],
            algo: 2,
            public_key: vec![0x11u8; 897],
            signature: vec![0x22u8; 666],
        };
        assert_eq!(DeletePayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn delete_payload_roundtrip_hybrid512() {
        // hybrid Ed25519+Falcon-512 pubkey = 32 + 897 = 929 bytes.
        let p = DeletePayload {
            key: [0xBBu8; 32],
            algo: 3,
            public_key: vec![0x33u8; 929],
            signature: vec![0x44u8; 1024],
        };
        assert_eq!(DeletePayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn delete_payload_roundtrip_hybrid1024_pubkey_exceeds_old_cap() {
        // hybrid Ed25519+Falcon-1024 pubkey = 32 + 1793 = 1825 bytes,
        // which exceeds the former MAX_MLKEM_PK_LEN (1600) DELETE decode
        // cap and would have been rejected. With MAX_SIGNATURE_PUBKEY_BYTES
        // (2048) it round-trips, so hybrid-1024 identities can delete.
        let p = DeletePayload {
            key: [0xCCu8; 32],
            algo: 4,
            public_key: vec![0x55u8; 1825],
            signature: vec![0x66u8; 1344],
        };
        // Compile-time invariant: 1825 B (hybrid-1024 pk) exceeds the former
        // MLKEM cap, so this test payload would have been rejected pre-U1.
        const { assert!(1825 > crate::budget::MAX_MLKEM_PK_LEN) };
        assert_eq!(DeletePayload::decode(&p.encode()).unwrap(), p);
    }

    // ── DhtValue ─────────────────────────────────────────────────────────

    #[test]
    fn dht_value_roundtrip_unsigned() {
        let v = DhtValue {
            key: [0x11u8; 32],
            kind: dht_value_kind::ATTACHMENT,
            epoch: 5,
            ttl_secs: 3600,
            seq_no: 99,
            body: b"attachment-body".to_vec(),
            signature: vec![],
        };
        let decoded = DhtValue::decode(&v.encode()).unwrap();
        assert_eq!(decoded, v);
        assert!(!decoded.is_signed());
    }

    #[test]
    fn dht_value_roundtrip_signed() {
        let v = DhtValue {
            key: [0x22u8; 32],
            kind: dht_value_kind::APP_ENDPOINT,
            epoch: 10,
            ttl_secs: 7200,
            seq_no: 1,
            body: b"app-endpoint-body".to_vec(),
            signature: vec![0xBBu8; 64], // mock Ed25519 sig
        };
        let decoded = DhtValue::decode(&v.encode()).unwrap();
        assert_eq!(decoded, v);
        assert!(decoded.is_signed());
    }

    #[test]
    fn dht_value_signable_prefix_excludes_sig() {
        let v = DhtValue {
            key: [0x33u8; 32],
            kind: dht_value_kind::MAILBOX,
            epoch: 1,
            ttl_secs: 600,
            seq_no: 7,
            body: b"mailbox".to_vec(),
            signature: vec![0xCCu8; 64],
        };
        let prefix = v.signable_prefix();
        let full = v.encode();
        // full = prefix + 2 (sig_len) + 64 (sig)
        assert_eq!(full.len(), prefix.len() + 2 + 64);
        assert_eq!(&full[..prefix.len()], prefix.as_slice());
    }

    #[test]
    fn dht_value_too_short() {
        assert!(DhtValue::decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn dht_value_wraps_attachment_body() {
        // Verify that an AnnounceAttachmentPayload can be stored as a DhtValue body.
        let announce = sample_announce();
        let body = announce.encode();
        let key = attachment_key(&announce.node_id);
        let dht_val = DhtValue {
            key,
            kind: dht_value_kind::ATTACHMENT,
            epoch: announce.epoch,
            ttl_secs: 3600,
            seq_no: announce.seq_no,
            body: body.clone(),
            signature: vec![],
        };
        let decoded_val = DhtValue::decode(&dht_val.encode()).unwrap();
        let decoded_ann = AnnounceAttachmentPayload::decode(&decoded_val.body).unwrap();
        assert_eq!(decoded_ann, announce);
    }

    // ── V2 + ResolveTransport wire roundtrips ───────────

    #[test]
    fn epic475_find_node_v2_payload_roundtrip() {
        let p = FindNodeV2Payload {
            target: [0xABu8; 32],
            k: 17,
        };
        let enc = p.encode();
        let dec = FindNodeV2Payload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn epic475_find_node_v2_response_roundtrip_empty() {
        let r = FindNodeV2Response { node_ids: vec![] };
        let dec = FindNodeV2Response::decode(&r.encode()).unwrap();
        assert_eq!(dec.node_ids.len(), 0);
    }

    #[test]
    fn epic475_find_node_v2_response_roundtrip_multi() {
        let r = FindNodeV2Response {
            node_ids: vec![[0x10u8; 32], [0x20u8; 32], [0x30u8; 32]],
        };
        let dec = FindNodeV2Response::decode(&r.encode()).unwrap();
        assert_eq!(dec, r);
    }

    #[test]
    fn epic475_find_node_v2_response_rejects_oversize_count() {
        let buf = vec![crate::budget::MAX_NODES_PER_RESPONSE as u8 + 1];
        let err = FindNodeV2Response::decode(&buf).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::ValueTooLarge {
                field: "node_count",
                ..
            }
        ));
    }

    #[test]
    fn epic475_resolve_transport_payload_roundtrip() {
        let p = ResolveTransportPayload {
            node_id: [0xCDu8; 32],
            time_bucket: 0xDEAD_BEEF,
            pow_nonce: [0x12u8; 16],
        };
        let dec = ResolveTransportPayload::decode(&p.encode()).unwrap();
        assert_eq!(dec, p);
    }

    /// b: a 32-byte (pre-refactor) payload must fail decode —
    /// wire bump is hard, no trailing-tolerance fallback.
    #[test]
    fn epic475_4b_resolve_payload_pre_phase3_rejected() {
        let buf = [0u8; 32];
        let err = ResolveTransportPayload::decode(&buf).unwrap_err();
        assert!(
            matches!(err, ProtoError::BufferTooShort { .. }),
            "32-byte legacy payload must fail; got {err:?}"
        );
    }

    /// b: `compute_resolve_pow` is deterministic — verifier
    /// and solver must produce identical hashes for identical inputs.
    #[test]
    fn epic475_4b_compute_resolve_pow_deterministic() {
        let req = [0xAAu8; 32];
        let tgt = [0xBBu8; 32];
        let nonce = [0x77u8; 16];
        let h1 = compute_resolve_pow(&req, &tgt, 100, &nonce);
        let h2 = compute_resolve_pow(&req, &tgt, 100, &nonce);
        assert_eq!(h1, h2);
    }

    /// b: domain separation — same nonce/bucket but different
    /// inputs (requester, target) must produce distinct hashes, so a
    /// solution mined for one (req, tgt) cannot satisfy another pair.
    #[test]
    fn epic475_4b_compute_resolve_pow_input_binding() {
        let req_a = [0xAAu8; 32];
        let req_b = [0xCCu8; 32];
        let tgt_a = [0xBBu8; 32];
        let tgt_b = [0xDDu8; 32];
        let nonce = [0u8; 16];
        let bucket = 100;
        let h_aa = compute_resolve_pow(&req_a, &tgt_a, bucket, &nonce);
        let h_ba = compute_resolve_pow(&req_b, &tgt_a, bucket, &nonce);
        let h_ab = compute_resolve_pow(&req_a, &tgt_b, bucket, &nonce);
        assert_ne!(
            h_aa, h_ba,
            "different requester must produce different hash"
        );
        assert_ne!(h_aa, h_ab, "different target must produce different hash");
    }

    /// b: `mine_resolve_pow` finds a nonce whose hash satisfies
    /// `verify_resolve_pow`. Round-trip: mine → verify → ok.
    #[test]
    fn epic475_4b_mine_then_verify() {
        let req = [0xAAu8; 32];
        let tgt = [0xBBu8; 32];
        let bucket = 12345u32;
        let nonce = mine_resolve_pow(&req, &tgt, bucket, 1_000_000)
            .expect("mining must succeed at default difficulty within 1M attempts");
        assert!(
            verify_resolve_pow(&req, &tgt, bucket, &nonce),
            "mined nonce must verify"
        );
    }

    /// b: `mine_resolve_pow_now` returns the current minute's
    /// time bucket — verify the bucket is within ±1 of `now/60`.
    #[test]
    fn epic475_4b_mine_now_uses_current_bucket() {
        let req = [0xAAu8; 32];
        let tgt = [0xBBu8; 32];
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let now_bucket = (now_secs / RESOLVE_POW_BUCKET_SECONDS) as u32;
        let (got_bucket, nonce) = mine_resolve_pow_now(&req, &tgt).expect("mining must succeed");
        // Allow ±1 in case the second rolled during the test.
        let delta = (got_bucket as i64 - now_bucket as i64).abs();
        assert!(
            delta <= 1,
            "bucket {got_bucket} must be within ±1 of {now_bucket}"
        );
        assert!(verify_resolve_pow(&req, &tgt, got_bucket, &nonce));
    }

    #[test]
    fn epic475_resolve_transport_response_found_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let ann = sign_transport_announcement(&sk, "tcp://10.0.0.5:9001".to_owned(), 1_900_000_000);
        let r = ResolveTransportResponse {
            node_id: ann.node_id,
            announcement: Some(ann),
        };
        let dec = ResolveTransportResponse::decode(&r.encode()).unwrap();
        assert_eq!(dec, r);
    }

    #[test]
    fn epic475_resolve_transport_response_not_found_roundtrip() {
        let r = ResolveTransportResponse {
            node_id: [0x77u8; 32],
            announcement: None,
        };
        let dec = ResolveTransportResponse::decode(&r.encode()).unwrap();
        assert_eq!(dec, r);
    }

    // ── SignedTransportAnnouncement tests ──────

    /// Sign-verify roundtrip: a freshly-signed announcement passes
    /// verification at the same instant.
    #[test]
    fn epic475_4c_sign_verify_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let ann =
            sign_transport_announcement(&sk, "tcp://node.example:7000".to_owned(), 1_900_000_000);
        assert!(
            verify_transport_announcement(&ann, 1_700_000_000),
            "fresh announcement must verify before expiry"
        );
    }

    /// Wire-roundtrip for `SignedTransportAnnouncement` itself —
    /// encode → decode → equality, verify signature still passes.
    #[test]
    fn epic475_4c_signed_announcement_wire_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let ann = sign_transport_announcement(&sk, "tcp://10.1.2.3:9000".to_owned(), 1_800_000_000);
        let encoded = ann.encode();
        let decoded = SignedTransportAnnouncement::decode(&encoded).unwrap();
        assert_eq!(decoded, ann);
        assert!(verify_transport_announcement(&decoded, 1_700_000_000));
    }

    /// Tampered transport URI invalidates the signature.
    #[test]
    fn epic475_4c_tampered_transport_fails_verify() {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let mut ann = sign_transport_announcement(&sk, "tcp://real:7000".to_owned(), 1_900_000_000);
        ann.transport = "tcp://attacker:7000".to_owned();
        assert!(
            !verify_transport_announcement(&ann, 1_700_000_000),
            "swapped transport must invalidate the signature"
        );
    }

    /// Tampered `expiry_unix` invalidates the signature (so an attacker
    /// can't resurrect an expired announcement by bumping the expiry).
    #[test]
    fn epic475_4c_tampered_expiry_fails_verify() {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let mut ann = sign_transport_announcement(&sk, "tcp://node:7000".to_owned(), 1_700_000_001);
        ann.expiry_unix = 9_999_999_999; // far future, but signature was over original
        assert!(
            !verify_transport_announcement(&ann, 1_700_000_000),
            "swapped expiry must invalidate the signature"
        );
    }

    /// Pubkey ↔ node_id binding: a forger that supplies a real
    /// signature with a `node_id` that doesn't match BLAKE3(pubkey)
    /// is rejected. This is what blocks "I'll claim to be Alice" attacks.
    #[test]
    fn epic475_4c_pubkey_node_id_mismatch_fails_verify() {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let mut ann = sign_transport_announcement(&sk, "tcp://node:7000".to_owned(), 1_900_000_000);
        ann.node_id = [0xFFu8; 32]; // detach from pubkey
        assert!(
            !verify_transport_announcement(&ann, 1_700_000_000),
            "node_id ≠ BLAKE3(pubkey) must be rejected"
        );
    }

    /// Expired announcement is rejected (bounds replay window).
    #[test]
    fn epic475_4c_expired_announcement_rejected() {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let ann = sign_transport_announcement(&sk, "tcp://node:7000".to_owned(), 1_500_000_000);
        assert!(
            !verify_transport_announcement(&ann, 1_700_000_000),
            "expired announcement must be rejected"
        );
        // Boundary: exactly equal to expiry → still rejected (strict `>`).
        assert!(!verify_transport_announcement(&ann, 1_500_000_000));
    }

    /// Cross-key forgery: announcement signed with key A but pubkey
    /// field swapped to key B's pubkey is rejected by signature
    /// verification.
    #[test]
    fn epic475_4c_cross_key_forgery_rejected() {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let sk_a = SigningKey::generate(&mut OsRng);
        let sk_b = SigningKey::generate(&mut OsRng);
        let mut ann =
            sign_transport_announcement(&sk_a, "tcp://node:7000".to_owned(), 1_900_000_000);
        ann.identity_pubkey = sk_b.verifying_key().to_bytes();
        // node_id was bound to A's pubkey — verifier first checks
        // BLAKE3(B_pubkey)!= A_node_id; rejection.
        assert!(!verify_transport_announcement(&ann, 1_700_000_000));
    }

    #[test]
    fn epic475_resolve_transport_response_truncated_buffer_errors_cleanly() {
        // Found-flag byte present but transport_len missing.
        let mut buf = vec![0u8; 32];
        buf.push(1); // found = 1
        // No transport_len bytes — decode must err with BufferTooShort.
        let err = ResolveTransportResponse::decode(&buf).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }
}
