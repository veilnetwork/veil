//! Local mesh plane wire types.
//!
//! # Frame layout
//!
//! ```text
//! MeshFrame (variable length):
//! realm_id [u8; 16] — realm scope
//! src_node_id [u8; 32] — originator
//! dst_node_id [u8; 32] — final destination (broadcast = [0xFF; 32])
//! ttl u8 — hops remaining; 0 → drop
//! payload_len u16 LE — byte length of payload
//! payload [u8; payload_len]
//! Total header: 16 + 32 + 32 + 1 + 2 = 83 bytes
//! ```

use std::sync::Arc;

use super::ProtoError;

// ── RealmId ───────────────────────────────────────────────────────────────────

/// 128-bit opaque realm identifier.
///
/// A realm scopes a local mesh segment. Nodes within the same realm can
/// forward frames directly; frames that escape the realm must go through a
/// `GatewayBridge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RealmId(pub [u8; 16]);

impl RealmId {
    /// Special realm id that addresses every realm (wildcard fan-out).
    pub const BROADCAST: RealmId = RealmId([0xFF; 16]);

    /// Borrow the 16-byte raw representation.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for RealmId {
    fn from(b: [u8; 16]) -> Self {
        Self(b)
    }
}

// ── MeshFrame ─────────────────────────────────────────────────────────────────

/// The fixed-size header prefix of a `MeshFrame` (without payload).
pub const MESH_HEADER_SIZE: usize = 16 + 32 + 32 + 1 + 8 + 2; // 91 (+8 = end-to-end replay nonce)

/// Broadcast destination: deliver to all neighbours in realm.
pub const BROADCAST_NODE_ID: [u8; 32] = [0xFF; 32];

/// A local mesh frame.
///
/// `payload` is stored as `Arc<[u8]>` so `MeshFrame::clone` (called on every
/// forward hop) only bumps a refcount instead of copying the body — critical
/// for broadcast fan-out where a single frame goes to many neighbours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshFrame {
    /// Realm this frame is scoped to.
    pub realm_id: RealmId,
    /// Originator `node_id`.
    pub src_node_id: [u8; 32],
    /// Final destination `node_id`; `BROADCAST_NODE_ID` for fan-out.
    pub dst_node_id: [u8; 32],
    /// Hops remaining. Decremented by each forwarder. Frame dropped when 0.
    pub ttl: u8,
    /// End-to-end replay nonce, set ONCE by the originator and preserved across
    /// every forward hop (unlike the hop-by-hop udp-obfs counter). Receivers
    /// keep a per-`src_node_id` replay window keyed on this value to drop
    /// replayed/duplicated frames. `0` = unset (no replay protection — legacy /
    /// plaintext-origin), so it is NOT replay-checked. Originators set a fresh
    /// random value via [`MeshFrame::with_nonce`]. (audit cycle-2 HIGH: mesh
    /// unicast replay.)
    pub nonce: u64,
    /// Opaque application payload. Immutable post-construction; shared across
    /// clones via `Arc` so fan-out forwarding doesn't reallocate per neighbour.
    pub payload: Arc<[u8]>,
}

impl MeshFrame {
    /// Construct a new mesh frame with the given header fields and payload.
    ///
    /// Accepts any type convertible into `Arc<[u8]>` — e.g. `Vec<u8>`
    /// (zero-copy move of the heap allocation) or `&[u8]` (one copy).
    pub fn new(
        realm_id: RealmId,
        src_node_id: [u8; 32],
        dst_node_id: [u8; 32],
        ttl: u8,
        payload: impl Into<Arc<[u8]>>,
    ) -> Self {
        Self {
            realm_id,
            src_node_id,
            dst_node_id,
            ttl,
            nonce: 0,
            payload: payload.into(),
        }
    }

    /// Stamp a fresh end-to-end replay nonce on a newly-originated frame.
    ///
    /// Called ONLY by the node that originates a frame (not by forwarders,
    /// which preserve the originator's nonce across hops). Pass a value drawn
    /// from a CSPRNG (`OsRng`); `0` is reserved to mean "unset" and is never
    /// replay-checked, so avoid stamping it deliberately. See [`MeshFrame::nonce`].
    #[must_use]
    pub fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    /// True iff this frame targets `BROADCAST_NODE_ID`.
    pub fn is_broadcast(&self) -> bool {
        self.dst_node_id == BROADCAST_NODE_ID
    }

    /// Encode to bytes.
    /// Encode to wire bytes.
    ///
    /// # Panics
    ///
    /// Panics if `payload.len` exceeds `u16::MAX`. This is a programming
    /// error — the decode path (UDP MTU < 65 KiB) guarantees inbound frames
    /// stay within bounds; outbound frames must be constructed within limits
    /// by the caller.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.payload.len() <= u16::MAX as usize,
            "MeshFrame payload {} exceeds u16::MAX",
            self.payload.len(),
        );
        let payload_len = self.payload.len().min(u16::MAX as usize) as u16;
        let mut buf = Vec::with_capacity(MESH_HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.realm_id.0);
        buf.extend_from_slice(&self.src_node_id);
        buf.extend_from_slice(&self.dst_node_id);
        buf.push(self.ttl);
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < MESH_HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: MESH_HEADER_SIZE,
                got: buf.len(),
            });
        }
        let realm_id = RealmId(super::read_array::<16>(buf, 0)?);
        let src_node_id: [u8; 32] = super::read_array::<32>(buf, 16)?;
        let dst_node_id: [u8; 32] = super::read_array::<32>(buf, 48)?;
        let ttl = buf[80];
        let nonce = u64::from_le_bytes(super::read_array::<8>(buf, 81)?);
        let payload_len = u16::from_le_bytes([buf[89], buf[90]]) as usize;
        let total = MESH_HEADER_SIZE + payload_len;
        if buf.len() < total {
            return Err(ProtoError::BufferTooShort {
                need: total,
                got: buf.len(),
            });
        }
        let payload: Arc<[u8]> = Arc::from(&buf[MESH_HEADER_SIZE..total]);
        Ok(Self {
            realm_id,
            src_node_id,
            dst_node_id,
            ttl,
            nonce,
            payload,
        })
    }
}

// ── MeshBeaconPayload ─────────────────────────────────────────────────────────

/// Role flags carried in `MeshBeaconPayload.role_flags`.
///
/// These are additive bit-flags; unknown bits should be ignored for forward
/// compatibility.
/// Bit flags carried in `MeshBeaconPayload.role_flags`.
pub mod beacon_role_flags {
    /// This node acts as a local-mesh ↔ global-veil Gateway.
    pub const IS_GATEWAY: u8 = 0x01;
    /// This node has working internet access and can relay to remote nodes.
    pub const HAS_INTERNET: u8 = 0x02;
    /// This node is a relay-only mesh hop (no global veil address).
    pub const IS_RELAY: u8 = 0x04;
}

/// Neighbour advertisement broadcast within a realm.
///
/// Wire layout (backward-compatible extension):
///
/// ```text
/// node_id [u8; 32] — sender's veil node_id
/// realm_id [u8; 16] — realm scope (must match receiver's realm)
/// role_flags u8 optional — beacon_role_flags bitmask (old nodes omit)
/// addr_len u8 optional — byte length of veil_addr UTF-8 string
/// veil_addr [u8; addr_len] — TCP/TLS veil dial address
/// battery_level u8 optional — 0=unknown/AC, 1..100=percent charge
/// ```
///
/// Byte offset of the role/addr/battery extension — decoders require at least
/// `MESH_BEACON_SIZE + 3` bytes (role_flags + addr_len + battery_level).
pub const MESH_BEACON_SIZE: usize = 32 + 16; // 48 — offset of the v2 extension

/// Periodic neighbour-discovery beacon broadcast within a realm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshBeaconPayload {
    /// Sender's veil `node_id`.
    pub node_id: [u8; 32],
    /// Realm the sender participates in.
    pub realm_id: RealmId,
    /// Role flags. Zero for old nodes that do not set this field.
    pub role_flags: u8,
    /// Veil dial address, e.g. `"tcp://10.0.0.1:9000"`.
    /// `None` when not advertised.
    pub veil_addr: Option<String>,
    /// Battery charge level: 0 = unknown or on AC power (no penalty), 1–100 = percent.
    pub battery_level: u8,
    /// signature algorithm (0 = Ed25519, 2 = Falcon512).
    pub algo: u8,
    /// sender's long-term public key (raw bytes).
    /// Receiver verifies `BLAKE3(public_key) == node_id`.
    pub public_key: Vec<u8>,
    /// signature over the unsigned portion of the beacon
    /// (everything before algo/pubkey/sig fields).
    pub signature: Vec<u8>,
}

impl MeshBeaconPayload {
    /// Create a minimal beacon (unsigned).
    pub fn new_basic(node_id: [u8; 32], realm_id: RealmId) -> Self {
        Self {
            node_id,
            realm_id,
            role_flags: 0,
            veil_addr: None,
            battery_level: 0,
            algo: 0,
            public_key: vec![],
            signature: vec![],
        }
    }

    /// Encode the beacon. The unsigned body is encoded first, then
    /// `algo(1) + pk_len(2) + public_key + sig_len(2) + signature` appended.
    pub fn encode(&self) -> Vec<u8> {
        let addr_bytes = self.veil_addr.as_deref().unwrap_or("").as_bytes();
        let addr_len = addr_bytes.len().min(255);
        let auth_size = if self.public_key.is_empty() {
            0
        } else {
            1 + 2 + self.public_key.len() + 2 + self.signature.len()
        };
        let total = MESH_BEACON_SIZE + 2 + addr_len + 1 + auth_size;
        let mut buf = Vec::with_capacity(total);
        // Unsigned body.
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&self.realm_id.0);
        buf.push(self.role_flags);
        buf.push(addr_len as u8);
        buf.extend_from_slice(&addr_bytes[..addr_len]);
        buf.push(self.battery_level);
        // authentication extension.
        if !self.public_key.is_empty() {
            buf.push(self.algo);
            buf.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
            buf.extend_from_slice(&self.public_key);
            buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
            buf.extend_from_slice(&self.signature);
        }
        buf
    }

    /// Returns the unsigned body bytes (everything before the auth extension).
    /// Used for signing and verification.
    pub fn signable_body(&self) -> Vec<u8> {
        let addr_bytes = self.veil_addr.as_deref().unwrap_or("").as_bytes();
        let addr_len = addr_bytes.len().min(255);
        let mut buf = Vec::with_capacity(MESH_BEACON_SIZE + 2 + addr_len + 1);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&self.realm_id.0);
        buf.push(self.role_flags);
        buf.push(addr_len as u8);
        buf.extend_from_slice(&addr_bytes[..addr_len]);
        buf.push(self.battery_level);
        buf
    }

    /// Parse a beacon payload. Requires the v2 layout
    /// (role_flags + addr_len + addr_bytes + battery_level).
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let min = MESH_BEACON_SIZE + 3;
        if buf.len() < min {
            return Err(ProtoError::BufferTooShort {
                need: min,
                got: buf.len(),
            });
        }
        let node_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let realm_id = RealmId(super::read_array::<16>(buf, 32)?);

        let role_flags = buf[MESH_BEACON_SIZE];
        let addr_len = buf[MESH_BEACON_SIZE + 1] as usize;
        let addr_start = MESH_BEACON_SIZE + 2;
        let addr_end = addr_start + addr_len;
        if buf.len() < addr_end + 1 {
            return Err(ProtoError::BufferTooShort {
                need: addr_end + 1,
                got: buf.len(),
            });
        }
        let veil_addr = if addr_len > 0 {
            String::from_utf8(buf[addr_start..addr_end].to_vec()).ok()
        } else {
            None
        };
        let battery_level = buf[addr_end];
        let body_end = addr_end + 1;
        // authentication extension (optional).
        let auth_start = body_end;
        let (algo, public_key, signature) = if auth_start + 3 <= buf.len() {
            let algo = buf[auth_start];
            let pk_len = u16::from_be_bytes([buf[auth_start + 1], buf[auth_start + 2]]) as usize;
            let pk_end = auth_start + 3 + pk_len;
            if pk_end + 2 <= buf.len() {
                let public_key = buf[auth_start + 3..pk_end].to_vec();
                let sig_len = u16::from_be_bytes([buf[pk_end], buf[pk_end + 1]]) as usize;
                let sig_end = pk_end + 2 + sig_len;
                let signature = if sig_end <= buf.len() {
                    buf[pk_end + 2..sig_end].to_vec()
                } else {
                    vec![]
                };
                (algo, public_key, signature)
            } else {
                (0, vec![], vec![])
            }
        } else {
            (0, vec![], vec![])
        };
        Ok(Self {
            node_id,
            realm_id,
            role_flags,
            veil_addr,
            battery_level,
            algo,
            public_key,
            signature,
        })
    }

    /// Whether this beacon carries a signature.
    pub fn is_signed(&self) -> bool {
        !self.public_key.is_empty()
    }

    // verify_auth was moved to `node::mesh::auth::verify_mesh_beacon_auth`
    // to break the proto → crypto dependency direction.
}

// ── MeshAckPayload ────────────────────────────────────────────────────────────

/// Mesh-level delivery acknowledgement.
///
/// ```text
/// frame_id [u8; 16] — identifies the MeshFrame being acked (first 16 bytes of its hash)
/// status u8 — 0=ok, 1=no_route, 2=ttl_expired
/// ```
pub const MESH_ACK_SIZE: usize = 17;

/// Status codes carried [`MeshAckPayload::status`].
pub mod mesh_ack_status {
    /// Frame was delivered successfully.
    pub const OK: u8 = 0;
    /// No neighbour could forward the frame.
    pub const NO_ROUTE: u8 = 1;
    /// TTL reached 0 before reaching the destination.
    pub const TTL_EXPIRED: u8 = 2;
}

/// Mesh-layer delivery ACK/NACK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAckPayload {
    /// First 16 bytes of the acknowledged frame's hash.
    pub frame_id: [u8; 16],
    /// One [`mesh_ack_status`] codes.
    pub status: u8,
}

impl MeshAckPayload {
    /// Encode to the fixed 17-byte wire layout.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MESH_ACK_SIZE);
        buf.extend_from_slice(&self.frame_id);
        buf.push(self.status);
        buf
    }

    /// Parse a mesh ack from a 17-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < MESH_ACK_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: MESH_ACK_SIZE,
                got: buf.len(),
            });
        }
        let frame_id: [u8; 16] = super::read_array::<16>(buf, 0)?;
        let status = buf[16];
        Ok(Self { frame_id, status })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_frame() -> MeshFrame {
        MeshFrame::new(
            RealmId([0xAA; 16]),
            [1u8; 32],
            [2u8; 32],
            8,
            b"hello mesh".to_vec(),
        )
    }

    #[test]
    fn mesh_frame_roundtrip() {
        let f = sample_frame();
        let enc = f.encode();
        let dec = MeshFrame::decode(&enc).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn mesh_frame_roundtrip_empty_payload() {
        let f = MeshFrame::new(RealmId([0u8; 16]), [3u8; 32], [4u8; 32], 1, vec![]);
        let enc = f.encode();
        let dec = MeshFrame::decode(&enc).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn mesh_frame_too_short_header() {
        let err = MeshFrame::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { need: 91, .. }));
    }

    #[test]
    fn mesh_frame_nonce_roundtrips() {
        let f = sample_frame().with_nonce(0xDEAD_BEEF_0BAD_F00D);
        let dec = MeshFrame::decode(&f.encode()).unwrap();
        assert_eq!(dec.nonce, 0xDEAD_BEEF_0BAD_F00D);
        assert_eq!(dec, f);
        // Default (unset) nonce is 0 and also roundtrips.
        assert_eq!(sample_frame().nonce, 0);
    }

    #[test]
    fn mesh_frame_too_short_payload() {
        let f = sample_frame();
        let mut enc = f.encode();
        // Truncate payload
        enc.truncate(enc.len() - 2);
        assert!(MeshFrame::decode(&enc).is_err());
    }

    #[test]
    fn is_broadcast() {
        let f = MeshFrame::new(RealmId([0u8; 16]), [1u8; 32], BROADCAST_NODE_ID, 4, vec![]);
        assert!(f.is_broadcast());
        let f2 = sample_frame();
        assert!(!f2.is_broadcast());
    }

    #[test]
    fn beacon_roundtrip_basic() {
        let b = MeshBeaconPayload::new_basic([5u8; 32], RealmId([0xBB; 16]));
        let dec = MeshBeaconPayload::decode(&b.encode()).unwrap();
        assert_eq!(dec, b);
        assert_eq!(dec.role_flags, 0);
        assert_eq!(dec.veil_addr, None);
    }

    #[test]
    fn beacon_roundtrip_v2_with_role_and_addr() {
        use super::beacon_role_flags;
        let b = MeshBeaconPayload {
            node_id: [7u8; 32],
            realm_id: RealmId([0xAA; 16]),
            role_flags: beacon_role_flags::IS_GATEWAY | beacon_role_flags::HAS_INTERNET,
            veil_addr: Some("tcp://10.0.0.1:9000".to_owned()),
            battery_level: 0,
            algo: 0,
            public_key: vec![],
            signature: vec![],
        };
        let dec = MeshBeaconPayload::decode(&b.encode()).unwrap();
        assert_eq!(dec, b);
    }

    #[test]
    fn beacon_48_byte_rejected() {
        // Old 48-byte beacon (no v2 extension) must now be rejected.
        let mut v1 = vec![0u8; 48];
        v1[..32].copy_from_slice(&[3u8; 32]);
        v1[32..48].copy_from_slice(&[0xCC; 16]);
        assert!(MeshBeaconPayload::decode(&v1).is_err());
    }

    #[test]
    fn beacon_too_short() {
        let err = MeshBeaconPayload::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { need: 51, .. }));
    }

    #[test]
    fn ack_roundtrip() {
        let a = MeshAckPayload {
            frame_id: [0xCC; 16],
            status: mesh_ack_status::TTL_EXPIRED,
        };
        let dec = MeshAckPayload::decode(&a.encode()).unwrap();
        assert_eq!(dec, a);
    }

    #[test]
    fn ack_too_short() {
        let err = MeshAckPayload::decode(&[0u8; 5]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { need: 17, .. }));
    }

    #[test]
    fn realm_id_default_is_zero() {
        assert_eq!(RealmId::default(), RealmId([0u8; 16]));
    }
}
