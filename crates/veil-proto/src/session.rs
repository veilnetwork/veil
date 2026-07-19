//! Session-plane payload structs for the OVL1 binary protocol.
//!
//! See also `CapabilitiesPayload::from_node_role` for building the capabilities
//! advertisement from a configured `NodeRole`.
//!
//! Each struct corresponds to one `SessionMsg` variant and is encoded as the
//! frame body (the bytes that follow the fixed `FrameHeader`). Encoding is
//! manual big-endian byte packing — no external serde dependency.

use super::ProtoError;
use super::cursor::{read_bytes, read_u8, read_u16};

// ── SessionAlias ─────────────────────────────────────────────────────────────

/// A compact 8-byte identifier for a node within a single OVL1 session.
///
/// Both sides of a session compute each other's alias independently after the
/// handshake using `session_kdf::derive_session_alias(session_id, node_id)`.
/// Aliases appear in aliased gossip frames (`RouteAnnounceAliased`
/// `RouteWithdrawAliased`) to reduce per-frame wire overhead by 48 bytes.
pub type SessionAlias = [u8; 8];

// ── HelloPayload ─────────────────────────────────────────────────────────────

/// First message in a session handshake: announces the OVL1 version and
/// identifies the initiating node.
///
/// Wire layout:
/// ```text
/// [0..2] ovl1_major u16 BE (major protocol version; always 1 for OVL1)
/// [2..34] node_id [u8; 32]
/// [34..] TLV entries (optional; ignored by legacy peers that stop at byte 34)
/// ```
///
/// TLV entry format: `type(1) + length(2 BE) + value(length)`.
/// Defined TLV types: `HELLO_TLV_RESUME_TICKET = 0x01`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloPayload {
    /// OVL1 major version — always 1. Connections fail if major versions differ.
    pub ovl1_major: u16,
    /// Sender's `node_id`.
    pub node_id: [u8; 32],
    /// Encrypted session-resumption ticket.
    ///
    /// Set by the initiator when reconnecting to a known peer and a valid
    /// `EncryptedTicket` is stored for that peer. `None` for initial handshakes
    /// and when the peer does not support session resumption.
    pub resume_ticket: Option<EncryptedTicket>,
    /// Private-network membership cert blob (bincode-encoded
    /// `veil_types::MembershipCert`). Set when the sender's local
    /// config has `[network].mode = "private"`. Receivers in private
    /// mode reject HELLO without it; public-mode receivers ignore the
    /// TLV for forward compat.
    pub membership_cert_blob: Option<Vec<u8>>,
    /// Per-resumption nonce (32 bytes), set by the initiator ONLY when it also
    /// sets `resume_ticket`. The responder mixes this with its own fresh nonce
    /// (returned in the ATTACH trailer) to derive fresh resumed-session keys, so
    /// resumption never reuses the original session's `(key, nonce)`. A
    /// `resume_ticket` present without this nonce is not resumed — the responder
    /// falls back to the full handshake. `None` for non-resuming HELLOs.
    pub resume_nonce: Option<[u8; 32]>,
}

impl HelloPayload {
    /// Fixed-size wire region: major(2) + node_id(32).
    pub const WIRE_SIZE: usize = 2 + 32;

    /// Encode to wire bytes.
    ///
    /// If `resume_ticket` is set, appends a TLV entry after the fixed region.
    /// Same for `membership_cert_blob`.
    pub fn encode(&self) -> Vec<u8> {
        let resume_tlv_len = self.resume_ticket.as_ref().map_or(0, |t| 1 + 2 + t.len());
        let cert_tlv_len = self
            .membership_cert_blob
            .as_ref()
            .map_or(0, |c| 1 + 2 + c.len());
        let nonce_tlv_len = self.resume_nonce.as_ref().map_or(0, |n| 1 + 2 + n.len());
        let mut buf =
            Vec::with_capacity(Self::WIRE_SIZE + resume_tlv_len + cert_tlv_len + nonce_tlv_len);
        buf.extend_from_slice(&self.ovl1_major.to_be_bytes());
        buf.extend_from_slice(&self.node_id);
        if let Some(ticket) = &self.resume_ticket {
            buf.push(super::budget::HELLO_TLV_RESUME_TICKET);
            buf.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
            buf.extend_from_slice(ticket);
        }
        if let Some(cert) = &self.membership_cert_blob {
            buf.push(super::budget::HELLO_TLV_MEMBERSHIP_CERT);
            buf.extend_from_slice(&(cert.len() as u16).to_be_bytes());
            buf.extend_from_slice(cert);
        }
        if let Some(nonce) = &self.resume_nonce {
            buf.push(super::budget::HELLO_TLV_RESUME_NONCE);
            buf.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
            buf.extend_from_slice(nonce);
        }
        buf
    }

    /// Encode without the TLV extensions (fixed 34-byte form).
    ///
    /// Used when the peer is known not to support TLV extensions (e.g. during
    /// tests that verify the exact fixed wire size).
    pub fn encode_fixed(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..2].copy_from_slice(&self.ovl1_major.to_be_bytes());
        buf[2..34].copy_from_slice(&self.node_id);
        buf
    }

    /// Parse a `HelloPayload`, tolerating optional TLV extensions beyond
    /// the fixed 34-byte region.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let ovl1_major = u16::from_be_bytes([buf[0], buf[1]]);
        let node_id = super::read_array::<32>(buf, 2)?;

        // Parse optional TLV extensions after the fixed region.
        let mut resume_ticket: Option<EncryptedTicket> = None;
        let mut membership_cert_blob: Option<Vec<u8>> = None;
        let mut resume_nonce: Option<[u8; 32]> = None;
        let mut pos = Self::WIRE_SIZE;
        while pos + 3 <= buf.len() {
            let tlv_type = buf[pos];
            let tlv_len = u16::from_be_bytes([buf[pos + 1], buf[pos + 2]]) as usize;
            pos += 3;
            if pos + tlv_len > buf.len() {
                break; // truncated TLV — stop parsing, ignore rest
            }
            let value = &buf[pos..pos + tlv_len];
            pos += tlv_len;
            match tlv_type {
                super::budget::HELLO_TLV_RESUME_TICKET => {
                    resume_ticket = Some(value.to_vec());
                }
                super::budget::HELLO_TLV_MEMBERSHIP_CERT => {
                    // Defense-in-depth: reject obviously-oversized blobs
                    // before the consumer attempts bincode deserialization.
                    if tlv_len > super::budget::MAX_MEMBERSHIP_CERT_SIZE {
                        continue;
                    }
                    membership_cert_blob = Some(value.to_vec());
                }
                super::budget::HELLO_TLV_RESUME_NONCE => {
                    // Exactly 32 bytes or ignore (a malformed length must not
                    // half-enable resumption — the responder then sees no nonce
                    // and falls back to the full handshake).
                    if let Ok(arr) = <[u8; 32]>::try_from(value) {
                        resume_nonce = Some(arr);
                    }
                }
                // Unknown TLV types are silently ignored (forward-compat).
                _ => {}
            }
        }

        Ok(Self {
            ovl1_major,
            node_id,
            resume_ticket,
            membership_cert_blob,
            resume_nonce,
        })
    }
}

// ── IdentityPayload ───────────────────────────────────────────────────────────

/// Carries the node's long-term public key and nonce.
///
/// Wire layout:
/// ```text
/// [0] algo u8
/// [1..3] public_key_len u16 BE
/// [3..3+pk] public_key bytes
/// [3+pk] nonce_len u8
/// [4+pk..] nonce bytes
/// [4+pk+n..] node_id [u8; 32]
/// [4+pk+n+32] mlkem_pk_len u16 BE (0 = not present; 1184 when ML-KEM-768)
/// [..] mlkem_pk bytes (omitted when mlkem_pk_len == 0)
/// ```
///
/// The `mlkem_pk_len` field is always present; `mlkem_pk_len = 0` indicates
/// the sender does not publish an ML-KEM key (e.g. E2E disabled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityPayload {
    /// Signature algorithm identifier (mirrors `SignatureAlgorithm` u8 repr).
    pub algo: u8,
    /// Long-term public key bytes.
    pub public_key: Vec<u8>,
    /// PoW nonce paired with `public_key`.
    pub nonce: Vec<u8>,
    /// Sender's `node_id = BLAKE3(public_key)`.
    pub node_id: [u8; 32],
    /// ML-KEM-768 encapsulation key (1184 bytes), if the peer supports E2E
    /// encryption. `None` when `mlkem_pk_len == 0` on the wire.
    pub mlkem_pubkey: Option<Vec<u8>>,
}

impl IdentityPayload {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(
            self.public_key.len() <= u16::MAX as usize,
            "public_key too long"
        );
        debug_assert!(self.nonce.len() <= u8::MAX as usize, "nonce too long");
        let pk_len = self.public_key.len().min(u16::MAX as usize) as u16;
        let nonce_len = self.nonce.len().min(u8::MAX as usize) as u8;
        let mlkem_len = self.mlkem_pubkey.as_deref().map_or(0, |k| k.len());
        debug_assert!(mlkem_len <= u16::MAX as usize, "mlkem_pubkey too long");
        let total = 1 + 2 + self.public_key.len() + 1 + self.nonce.len() + 32 + 2 + mlkem_len;
        let mut buf = Vec::with_capacity(total);
        buf.push(self.algo);
        buf.extend_from_slice(&pk_len.to_be_bytes());
        buf.extend_from_slice(&self.public_key);
        buf.push(nonce_len);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&(mlkem_len as u16).to_be_bytes());
        if let Some(ek) = &self.mlkem_pubkey {
            buf.extend_from_slice(ek);
        }
        buf
    }

    /// Parse an `IdentityPayload`. `mlkem_pk_len` is always present
    /// (0 means no ML-KEM key).
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut pos = 0;

        let algo = read_u8(buf, &mut pos, "identity.algo")?;
        let pk_len = read_u16(buf, &mut pos, "identity.pk_len")? as usize;
        // Per-field cap before allocation — mirrors IdentityProof::decode. The
        // frame body is already ≤ MAX_FRAME_BODY, so this only adds a tight,
        // algorithm-aware ceiling so a pre-auth peer can't make us copy + hash +
        // verify a wildly-oversized "pubkey". (audit cycle-3.)
        if pk_len > super::budget::MAX_SIGNATURE_PUBKEY_BYTES {
            return Err(ProtoError::Malformed(format!(
                "identity.public_key {pk_len} > {}",
                super::budget::MAX_SIGNATURE_PUBKEY_BYTES
            )));
        }
        let public_key = read_bytes(buf, &mut pos, pk_len, "identity.public_key")?;
        let nonce_len = read_u8(buf, &mut pos, "identity.nonce_len")? as usize;
        let nonce = read_bytes(buf, &mut pos, nonce_len, "identity.nonce")?;
        let node_id: [u8; 32] = super::read_array::<32>(buf, pos)?;
        pos += 32;

        let ek_len = read_u16(buf, &mut pos, "identity.ek_len")? as usize;
        if ek_len > super::budget::MAX_MLKEM_PK_LEN {
            return Err(ProtoError::Malformed(format!(
                "identity.mlkem_pubkey {ek_len} > {}",
                super::budget::MAX_MLKEM_PK_LEN
            )));
        }
        let mlkem_pubkey = if ek_len > 0 {
            Some(read_bytes(buf, &mut pos, ek_len, "identity.mlkem_pubkey")?)
        } else {
            None
        };

        Ok(Self {
            algo,
            public_key,
            nonce,
            node_id,
            mlkem_pubkey,
        })
    }
}

// ── CapabilitiesPayload ───────────────────────────────────────────────────────

/// Node capability advertisement.
///
/// Wire layout:
/// ```text
/// [0] roles_supported u8 (bitset: bit0=leaf, bit3=core)
/// [1] flags u8 (CAN_RELAY, SUPPORTS_SOVEREIGN_IDENTITY)
/// [2] discovery_mode u8 (0=Public, 1=ContactsOnly
/// 2=IntroductionOnly)
/// ```
///
/// The pre-audit layout carried six extra fields (`transports_supported`
/// `max_frame_size`, `max_streams`, `ovl1_minor`) plus five cap flags
/// (`CAN_MAILBOX`, `CAN_GATEWAY_LOCAL_MESH`, `CAN_PARTICIPATE_DHT`
/// `CAN_ACCEPT_APP_STREAMS`, `CAN_STORE`, `SUPPORTS_TRANSIT`) that were
/// always advertised but never read — pure wire zombie. Wire format
/// compressed from 12 bytes to 2 bytes in the post-audit cleanup.
///
/// added `discovery_mode` as a trailing byte (3 bytes total);
/// pre-474.4 peers send 2 bytes and decoders default the missing byte to
/// `Public` (the safest interpretation: legacy peers had no opt-in
/// privacy concept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitiesPayload {
    /// Role bitset advertised by the sender (see [`role_bits`]).
    pub roles_supported: u8,
    /// Packed boolean flags — use [`cap_flags`] constants.
    pub flags: u8,
    /// peer's preferred DHT-discoverability — controls
    /// whether `handle_find_node_v2` includes the peer in responses.
    /// Values: 0 = Public (default), 1 = ContactsOnly, 2 = IntroductionOnly.
    /// Unknown values decode as `IntroductionOnly` (most-restrictive
    /// forward-compat default).
    pub discovery_mode: u8,
}

/// Flag bits for `CapabilitiesPayload::flags`.
pub mod cap_flags {
    /// Peer is willing to relay traffic for others. Checked by
    /// `resolve_sovereign_delivery_targets` when picking next-hop
    /// candidates for indirect delivery.
    pub const CAN_RELAY: u8 = 1 << 0;
    /// peer holds a signed sovereign [`IdentityDocument`] and
    /// will emit/consume a [`SessionMsg::IdentityProof`](super::family::SessionMsg::IdentityProof)
    /// frame between `KeyAgreement` and `SessionConfirm`. Legacy peers
    /// advertise `0` for this bit and skip the frame entirely.
    ///
    /// Negotiation: the proof-frame exchange happens only when BOTH
    /// sides have this bit set — otherwise the handshake falls back
    /// to the legacy `ephemeral_sig`-only anti-MITM binding.
    ///
    /// [`IdentityDocument`]: crate::identity_document::IdentityDocument
    pub const SUPPORTS_SOVEREIGN_IDENTITY: u8 = 1 << 1;
    /// peer has opted in to relaying onion-routed
    /// anonymity-layer cells. Distinct from
    /// `CAN_RELAY` which authorises arbitrary frame forwarding for
    /// indirect-delivery — anonymity relay carries different cost
    /// (constant-rate cells, larger bandwidth budget, anti-correlation
    /// timing requirements) and so requires explicit operator opt-in
    /// via `[anonymity].relay_capable = true`. Without this flag
    /// set, the relay-directory layer will not pick the
    /// peer as a circuit candidate even if `CAN_RELAY` is set.
    pub const ANONYMITY_RELAY: u8 = 1 << 2;
    /// peer supports the post-quantum hybrid
    /// session-key derivation path. When BOTH peers set this bit and
    /// have ML-KEM material to exchange (initiator: knows responder's
    /// EK; responder: holds its own ML-KEM DK seed), the handshake
    /// inserts a `SessionMsg::HybridKexCt` frame between `IdentityProof`
    /// and `SessionConfirm`, and replaces the classical SessionKeys
    /// from `derive_session_keys` with
    /// `derive_hybrid_session_keys(x25519_secret, mlkem_secret...)`.
    /// Legacy peers that don't set this bit fall through to the
    /// classical X25519-only path unchanged.
    pub const SUPPORTS_HYBRID_KEX: u8 = 1 << 3;
    /// Peer understands the authenticated realtime side-channel carried in
    /// QUIC DATAGRAMs.  The lane is enabled only when BOTH peers advertise
    /// this bit and the selected transport negotiated DATAGRAM support.
    /// Legacy peers leave the bit clear and continue to carry `AppRtData` on
    /// the reliable ordered session stream.
    pub const SUPPORTS_REALTIME_DATAGRAMS: u8 = 1 << 4;
}

// c: role_bits moved to veil-types alongside NodeRole.
pub use veil_types::role_bits;

impl CapabilitiesPayload {
    /// Fixed wire size: 1 byte roles + 1 byte flags + 1 byte discovery_mode.
    /// Pre-peers send `LEGACY_WIRE_SIZE` (2 bytes); decoder
    /// defaults the missing `discovery_mode` byte to `Public`.
    pub const WIRE_SIZE: usize = 3;
    /// backward-compat: pre-474.4 peers send 2 bytes (no
    /// `discovery_mode`). Decoder accepts both lengths.
    pub const LEGACY_WIRE_SIZE: usize = 2;

    /// Build a capabilities advertisement from a configured `NodeRole`.
    ///
    /// **leaf** — no relay
    /// **core** — `CAN_RELAY`
    ///
    /// `SUPPORTS_SOVEREIGN_IDENTITY` is added later in the handshake when
    /// the local node actually holds an `IdentityDocument`.
    /// `discovery_mode` defaults to `Public`; callers who want a
    /// non-default mode use [`Self::with_discovery_mode`].
    pub fn from_node_role(role: veil_types::NodeRole) -> Self {
        use veil_types::NodeRole;
        let flags = match role {
            NodeRole::Leaf => 0,
            NodeRole::Core => cap_flags::CAN_RELAY,
        };
        Self {
            roles_supported: role.to_role_bits(),
            flags,
            discovery_mode: 0, // Public
        }
    }

    /// Builder helper: stamp `discovery_mode` after `from_node_role`.
    pub fn with_discovery_mode(mut self, mode: veil_types::DiscoveryMode) -> Self {
        self.discovery_mode = match mode {
            veil_types::DiscoveryMode::Public => 0,
            veil_types::DiscoveryMode::ContactsOnly => 1,
            veil_types::DiscoveryMode::IntroductionOnly => 2,
        };
        self
    }

    /// Decode `discovery_mode` byte into the typed `cfg::DiscoveryMode`.
    /// (Variant C): unknown values map to `IntroductionOnly`
    /// — the most-restrictive forward-compat default, so a future mode
    /// byte from a newer peer cannot accidentally widen our disclosure.
    pub fn parse_discovery_mode(&self) -> veil_types::DiscoveryMode {
        match self.discovery_mode {
            0 => veil_types::DiscoveryMode::Public,
            1 => veil_types::DiscoveryMode::ContactsOnly,
            _ => veil_types::DiscoveryMode::IntroductionOnly,
        }
    }

    /// Encode to the fixed 3-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        [self.roles_supported, self.flags, self.discovery_mode]
    }

    /// Parse from a 2- or 3-byte buffer. Pre-peers send 2
    /// bytes; the missing `discovery_mode` byte defaults to `0` (Public).
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::LEGACY_WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::LEGACY_WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            roles_supported: buf[0],
            flags: buf[1],
            discovery_mode: if buf.len() >= Self::WIRE_SIZE {
                buf[2]
            } else {
                0
            },
        })
    }

    // ── Capability helpers ───────────────────────────────────────────────

    /// Does this peer advertise the `SUPPORTS_SOVEREIGN_IDENTITY` bit?
    /// When BOTH sides return `true` the handshake
    /// negotiates the `SessionMsg::IdentityProof` frame exchange.
    pub fn supports_sovereign_identity(&self) -> bool {
        self.flags & cap_flags::SUPPORTS_SOVEREIGN_IDENTITY != 0
    }

    /// Compute the negotiation outcome for the sovereign-identity
    /// proof-frame exchange: `true` iff BOTH sides advertised support.
    pub fn sovereign_identity_negotiated(&self, peer: &CapabilitiesPayload) -> bool {
        self.supports_sovereign_identity() && peer.supports_sovereign_identity()
    }

    /// does this peer advertise
    /// `SUPPORTS_HYBRID_KEX`?
    pub fn supports_hybrid_kex(&self) -> bool {
        self.flags & cap_flags::SUPPORTS_HYBRID_KEX != 0
    }

    /// hybrid-kex negotiation outcome — `true`
    /// iff BOTH sides advertised support. Negotiation MUST also be
    /// gated on availability of ML-KEM material at both ends; this
    /// helper just covers the bit-flag side of the AND.
    pub fn hybrid_kex_negotiated(&self, peer: &CapabilitiesPayload) -> bool {
        self.supports_hybrid_kex() && peer.supports_hybrid_kex()
    }

    /// Does this peer understand the authenticated QUIC DATAGRAM realtime
    /// lane?
    pub fn supports_realtime_datagrams(&self) -> bool {
        self.flags & cap_flags::SUPPORTS_REALTIME_DATAGRAMS != 0
    }

    /// Realtime DATAGRAM negotiation succeeds only when both peers advertise
    /// support. Transport availability is checked separately by the runtime.
    pub fn realtime_datagrams_negotiated(&self, peer: &CapabilitiesPayload) -> bool {
        self.supports_realtime_datagrams() && peer.supports_realtime_datagrams()
    }
}

// ── KeyAgreementPayload ───────────────────────────────────────────────────────

/// Carries an ephemeral public key for key agreement (e.g. X25519) plus
/// a signature over the ephemeral key by the sender's long-term identity key.
///
/// the signature prevents MITM from substituting ephemeral keys.
/// Algorithm-agnostic: works with Ed25519, Falcon512, or any future signer.
///
/// Wire layout:
/// ```text
/// [0] algo u8
/// [1..3] key_len u16 BE
/// [3..3+k] ephemeral_pubkey bytes
/// [3+k..5+k] sig_len u16 BE
/// [5+k..] ephemeral_sig bytes (Ed25519=64, Falcon512=variable)
/// ```
///
/// The decoder is deliberately lenient about bytes following
/// `ephemeral_sig` — existing / OVL1 framing sometimes
/// appends session-layer padding after the structured payload, and
/// historical peers rely on that tolerance. A future sovereign-
/// identity proof will be carried on a *separate* frame
/// type rather than as a trailer on this payload for exactly that
/// reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAgreementPayload {
    /// Signature algorithm for `ephemeral_sig` (mirrors `SignatureAlgorithm`).
    pub algo: u8,
    /// Ephemeral X25519 public key bytes.
    pub ephemeral_pubkey: Vec<u8>,
    /// Signature over `ephemeral_pubkey` by the sender's long-term signing key.
    /// Required (anti-MITM); empty signals an attempted downgrade
    /// and must be rejected by the verifier.
    pub ephemeral_sig: Vec<u8>,
}

impl KeyAgreementPayload {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let key_len = self.ephemeral_pubkey.len().min(u16::MAX as usize) as u16;
        let sig_len = self.ephemeral_sig.len().min(u16::MAX as usize) as u16;
        let mut buf =
            Vec::with_capacity(3 + self.ephemeral_pubkey.len() + 2 + self.ephemeral_sig.len());
        buf.push(self.algo);
        buf.extend_from_slice(&key_len.to_be_bytes());
        buf.extend_from_slice(&self.ephemeral_pubkey);
        buf.extend_from_slice(&sig_len.to_be_bytes());
        buf.extend_from_slice(&self.ephemeral_sig);
        buf
    }

    /// Parse from wire bytes. `sig_len` field is always present; a zero
    /// length means the sender refused to sign (caller must reject).
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut pos = 0;
        let algo = read_u8(buf, &mut pos, "key_agreement.algo")?;
        let key_len = read_u16(buf, &mut pos, "key_agreement.key_len")? as usize;
        // Per-field caps before allocation (audit cycle-3) — same rationale as
        // IdentityPayload/IdentityProof: bound the pre-auth copy + verify work.
        if key_len > super::budget::MAX_SIGNATURE_PUBKEY_BYTES {
            return Err(ProtoError::Malformed(format!(
                "key_agreement.ephemeral_pubkey {key_len} > {}",
                super::budget::MAX_SIGNATURE_PUBKEY_BYTES
            )));
        }
        let ephemeral_pubkey =
            read_bytes(buf, &mut pos, key_len, "key_agreement.ephemeral_pubkey")?;
        let sig_len = read_u16(buf, &mut pos, "key_agreement.sig_len")? as usize;
        if sig_len > super::budget::MAX_SIGNATURE_PUBKEY_BYTES {
            return Err(ProtoError::Malformed(format!(
                "key_agreement.ephemeral_sig {sig_len} > {}",
                super::budget::MAX_SIGNATURE_PUBKEY_BYTES
            )));
        }
        let ephemeral_sig = read_bytes(buf, &mut pos, sig_len, "key_agreement.ephemeral_sig")?;
        Ok(Self {
            algo,
            ephemeral_pubkey,
            ephemeral_sig,
        })
    }
}

// ── SessionConfirmPayload ─────────────────────────────────────────────────────

/// Confirms the session: both sides commit to the negotiated session_id and
/// prove they hold the shared secret via a MAC/signature.
///
/// Wire layout:
/// ```text
/// [0..32] session_id [u8; 32]
/// [32..64] mac [u8; 32]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfirmPayload {
    /// Canonical session identifier both parties committed to.
    pub session_id: [u8; 32],
    /// MAC/signature proving the sender holds the shared secret.
    pub mac: [u8; 32],
}

impl SessionConfirmPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 64;

    /// Encode to the fixed 64-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.session_id);
        buf[32..64].copy_from_slice(&self.mac);
        buf
    }

    /// Parse from a 64-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let session_id = super::read_array::<32>(buf, 0)?;
        let mac = super::read_array::<32>(buf, 32)?;
        Ok(Self { session_id, mac })
    }
}

// ── AttachPayload ─────────────────────────────────────────────────────────────

/// Declares the node's role and realm membership after session establishment.
///
/// Wire layout:
/// ```text
/// [0] role u8
/// [1..5] realm_id u32 BE
/// [5..9] attach_epoch u32 BE
/// [9] mailbox_preference_count u8
/// [10] gateway_preference_count u8
/// [11..13] flags u16 BE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachPayload {
    /// Role byte (mirrors `NodeRole` discriminant).
    pub role: u8,
    /// Realm identifier.
    pub realm_id: u32,
    /// Attachment epoch (monotonic, increments on reconnect).
    pub attach_epoch: u32,
    /// Count of mailbox-preference entries sent in a follow-up TLV.
    pub mailbox_preference_count: u8,
    /// Count of gateway-preference entries sent in a follow-up TLV.
    pub gateway_preference_count: u8,
    /// Reserved flags bitmask.
    pub flags: u16,
}

impl AttachPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 1 + 4 + 4 + 1 + 1 + 2;

    /// Encode to the fixed 13-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0] = self.role;
        [buf[1], buf[2], buf[3], buf[4]] = self.realm_id.to_be_bytes();
        [buf[5], buf[6], buf[7], buf[8]] = self.attach_epoch.to_be_bytes();
        buf[9] = self.mailbox_preference_count;
        buf[10] = self.gateway_preference_count;
        [buf[11], buf[12]] = self.flags.to_be_bytes();
        buf
    }

    /// Parse from a 13-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            role: buf[0],
            realm_id: u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
            attach_epoch: u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]),
            mailbox_preference_count: buf[9],
            gateway_preference_count: buf[10],
            flags: u16::from_be_bytes([buf[11], buf[12]]),
        })
    }
}

// ── Vivaldi TLV extension for AttachPayload ───────────────────────────────────

/// TLV tag for Vivaldi network coordinates appended after `AttachPayload`.
///
/// Wire layout of the value (24 bytes):
/// ```text
/// [0..8] x f64 BE
/// [8..16] y f64 BE
/// [16..24] height f64 BE
/// ```
pub const VIVALDI_TLV_TAG: u16 = 0x0010;

/// Encode an `AttachPayload` followed by a Vivaldi TLV extension.
///
/// Returns a `Vec<u8>` containing the fixed `AttachPayload` bytes and, if
/// `vivaldi` is `Some`, an appended TLV entry (tag=`VIVALDI_TLV_TAG`).
pub fn encode_attach_with_vivaldi(
    payload: &AttachPayload,
    vivaldi: Option<(f64, f64, f64)>,
) -> Vec<u8> {
    let mut out = payload.encode().to_vec();
    if let Some((x, y, height)) = vivaldi {
        // TLV header: tag (2 bytes BE) + len (2 bytes BE) = 4 bytes
        out.extend_from_slice(&VIVALDI_TLV_TAG.to_be_bytes());
        out.extend_from_slice(&(24u16).to_be_bytes()); // value length = 24 bytes
        out.extend_from_slice(&x.to_be_bytes());
        out.extend_from_slice(&y.to_be_bytes());
        out.extend_from_slice(&height.to_be_bytes());
    }
    out
}

/// Extract a Vivaldi coordinate from ATTACH payload bytes (after the fixed header).
///
/// Returns `Some((x, y, height))` if a `VIVALDI_TLV_TAG` entry is present and
/// well-formed, `None` otherwise.
pub fn decode_vivaldi_from_attach(buf: &[u8]) -> Option<(f64, f64, f64)> {
    // TLV region starts after the fixed AttachPayload bytes.
    if buf.len() <= AttachPayload::WIRE_SIZE {
        return None;
    }
    let tlv_region = &buf[AttachPayload::WIRE_SIZE..];
    let mut pos = 0;
    while pos + 4 <= tlv_region.len() {
        let tag = u16::from_be_bytes([tlv_region[pos], tlv_region[pos + 1]]);
        let len = u16::from_be_bytes([tlv_region[pos + 2], tlv_region[pos + 3]]) as usize;
        pos += 4;
        if pos + len > tlv_region.len() {
            break; // truncated
        }
        if tag == VIVALDI_TLV_TAG && len == 24 {
            let v = &tlv_region[pos..pos + 24];
            let x = f64::from_be_bytes(v[0..8].try_into().ok()?);
            let y = f64::from_be_bytes(v[8..16].try_into().ok()?);
            let height = f64::from_be_bytes(v[16..24].try_into().ok()?);
            // Reject NaN / ±Inf — they would corrupt coordinate updates propagated
            // through the network.
            if !x.is_finite() || !y.is_finite() || !height.is_finite() {
                return None;
            }
            return Some((x, y, height));
        }
        pos += len;
    }
    None
}

// ── Battery TLV extension for AttachPayload ───────────────────────

/// TLV tag for battery level appended after `AttachPayload`.
///
/// Wire layout of the value (1 byte):
/// ```text
/// [0] level u8 (0–100 percent; 255 = unknown/not applicable)
/// ```
pub const BATTERY_TLV_TAG: u16 = 0x0011;

/// Encode an `AttachPayload` followed by optional Vivaldi and battery TLV extensions.
///
/// This extends `encode_attach_with_vivaldi` to also append a battery TLV
/// when `battery_level` is `Some`.
pub fn encode_attach_with_vivaldi_and_battery(
    payload: &AttachPayload,
    vivaldi: Option<(f64, f64, f64)>,
    battery_level: Option<u8>,
) -> Vec<u8> {
    let mut out = encode_attach_with_vivaldi(payload, vivaldi);
    if let Some(level) = battery_level {
        // TLV header: tag (2 BE) + len (2 BE) = 4 bytes + 1 byte value
        out.extend_from_slice(&BATTERY_TLV_TAG.to_be_bytes());
        out.extend_from_slice(&(1u16).to_be_bytes());
        out.push(level);
    }
    out
}

/// Extract battery level from ATTACH payload bytes (after the fixed header).
///
/// Returns `Some(level)` if a `BATTERY_TLV_TAG` entry is present and well-formed
/// `None` otherwise.
pub fn decode_battery_from_attach(buf: &[u8]) -> Option<u8> {
    if buf.len() <= AttachPayload::WIRE_SIZE {
        return None;
    }
    let tlv_region = &buf[AttachPayload::WIRE_SIZE..];
    let mut pos = 0;
    while pos + 4 <= tlv_region.len() {
        let tag = u16::from_be_bytes([tlv_region[pos], tlv_region[pos + 1]]);
        let len = u16::from_be_bytes([tlv_region[pos + 2], tlv_region[pos + 3]]) as usize;
        pos += 4;
        if pos + len > tlv_region.len() {
            break; // truncated
        }
        if tag == BATTERY_TLV_TAG && len == 1 {
            return Some(tlv_region[pos]);
        }
        pos += len;
    }
    None
}

// ── AdvertisedTransports TLV ───────

/// TLV tag for the advertised-transports list appended to `ATTACH`.
/// When present, the sender is telling us which transport URIs their
/// own listeners expose (the `advertise` fields from `[[listen]]`);
/// the receiver can use this to pick an alt_uri for hot-standby without
/// operator-supplied static config.
pub const ADVERTISED_TRANSPORTS_TLV_TAG: u16 = 0x0012;

/// Hard cap on serialised TLV body size (excluding the 4-byte header).
/// Keeps the ATTACH frame bounded even if a peer advertises many
/// long URIs. Picked conservatively: 4 URIs × 128 bytes each = 512.
pub const ADVERTISED_TRANSPORTS_MAX_BYTES: usize = 512;
/// Hard cap on how many URIs we serialise — extras are silently dropped.
pub const ADVERTISED_TRANSPORTS_MAX_COUNT: usize = 8;

/// Encode an `AttachPayload` followed by Vivaldi + battery + advertised-
/// transports TLV extensions. Any of the three may be `None`/empty;
/// the output frame tolerates all combinations.
///
/// Wire layout of the TRANSPORTS TLV body:
/// ```text
/// count: u8 -- number of URI entries
/// count × { len: u16 BE, bytes: [u8; len] } -- each entry
/// ```
pub fn encode_attach_with_tlvs(
    payload: &AttachPayload,
    vivaldi: Option<(f64, f64, f64)>,
    battery_level: Option<u8>,
    advertised_transports: &[String],
) -> Vec<u8> {
    let mut out = encode_attach_with_vivaldi_and_battery(payload, vivaldi, battery_level);
    if advertised_transports.is_empty() {
        return out;
    }
    // Build the TLV body first so we can set len up-front. Respect both
    // the count cap and the body-byte cap — whichever is hit first trims.
    let mut body = Vec::with_capacity(256);
    let mut count: u8 = 0;
    for uri in advertised_transports
        .iter()
        .take(ADVERTISED_TRANSPORTS_MAX_COUNT)
    {
        let uri_bytes = uri.as_bytes();
        if uri_bytes.len() > u16::MAX as usize {
            continue;
        }
        let needed = 2 + uri_bytes.len(); // u16 len + bytes
        if body.len() + 1 /* count prefix */ + needed > ADVERTISED_TRANSPORTS_MAX_BYTES {
            break;
        }
        body.extend_from_slice(&(uri_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(uri_bytes);
        count += 1;
    }
    if count == 0 {
        return out;
    }
    // Prepend count byte.
    let mut full_body = Vec::with_capacity(1 + body.len());
    full_body.push(count);
    full_body.extend_from_slice(&body);
    // TLV header: tag (2 BE) + len (2 BE) = 4 bytes, then body.
    out.extend_from_slice(&ADVERTISED_TRANSPORTS_TLV_TAG.to_be_bytes());
    out.extend_from_slice(&(full_body.len() as u16).to_be_bytes());
    out.extend_from_slice(&full_body);
    out
}

/// Extract the advertised-transports list from ATTACH payload bytes
/// (after the fixed header + TLV region scan). Returns an empty `Vec`
/// if no TLV is present or parsing fails partway through — the caller
/// treats absence identically to "peer does not advertise anything".
pub fn decode_advertised_transports_from_attach(buf: &[u8]) -> Vec<String> {
    if buf.len() <= AttachPayload::WIRE_SIZE {
        return Vec::new();
    }
    let tlv_region = &buf[AttachPayload::WIRE_SIZE..];
    let mut pos = 0;
    while pos + 4 <= tlv_region.len() {
        let tag = u16::from_be_bytes([tlv_region[pos], tlv_region[pos + 1]]);
        let len = u16::from_be_bytes([tlv_region[pos + 2], tlv_region[pos + 3]]) as usize;
        pos += 4;
        if pos + len > tlv_region.len() {
            break;
        }
        if tag == ADVERTISED_TRANSPORTS_TLV_TAG {
            return parse_transports_body(&tlv_region[pos..pos + len]);
        }
        pos += len;
    }
    Vec::new()
}

/// Scan an ATTACH frame body for the `OBSERVED_ADDR_TLV_TAG` extension
/// and decode the embedded `SocketAddr` if present.  Returns `None` if
/// the TLV is absent (legacy peer / not yet emitted) or the value is
/// malformed.
pub fn decode_observed_addr_from_attach(buf: &[u8]) -> Option<std::net::SocketAddr> {
    if buf.len() <= AttachPayload::WIRE_SIZE {
        return None;
    }
    let tlv_region = &buf[AttachPayload::WIRE_SIZE..];
    let mut pos = 0;
    while pos + 4 <= tlv_region.len() {
        let tag = u16::from_be_bytes([tlv_region[pos], tlv_region[pos + 1]]);
        let len = u16::from_be_bytes([tlv_region[pos + 2], tlv_region[pos + 3]]) as usize;
        pos += 4;
        if pos + len > tlv_region.len() {
            break;
        }
        if tag == OBSERVED_ADDR_TLV_TAG && len == OBSERVED_ADDR_TLV_LEN {
            return decode_observed_addr(&tlv_region[pos..pos + len]);
        }
        pos += len;
    }
    None
}

fn parse_transports_body(body: &[u8]) -> Vec<String> {
    if body.is_empty() {
        return Vec::new();
    }
    let count = body[0] as usize;
    let mut pos = 1;
    let mut out = Vec::with_capacity(count.min(ADVERTISED_TRANSPORTS_MAX_COUNT));
    for _ in 0..count.min(ADVERTISED_TRANSPORTS_MAX_COUNT) {
        if pos + 2 > body.len() {
            break;
        }
        let len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        if pos + len > body.len() {
            break;
        }
        // Silently drop non-UTF-8 entries.
        if let Ok(s) = std::str::from_utf8(&body[pos..pos + len]) {
            out.push(s.to_owned());
        }
        pos += len;
    }
    out
}

// ── VisibilityScope TLV ───────────────────────────────────────────

/// Visibility scope that limits who can discover this node via the gateway
/// attachment table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum VisibilityScope {
    /// Discoverable by any node (default).
    #[default]
    Public = 0,
    /// Discoverable only by nodes on the local friend list.
    FriendsOnly = 1,
    /// Discoverable only by nodes that hold an invitation token.
    InviteOnly = 2,
    /// Not discoverable — attachment is invisible to all lookup requests.
    Private = 3,
}

impl VisibilityScope {
    /// Decode from a raw byte (unknown values → `Public`).
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::FriendsOnly,
            2 => Self::InviteOnly,
            3 => Self::Private,
            _ => Self::Public,
        }
    }
}

/// TLV tag for visibility scope appended after `AttachPayload`.
///
/// Wire layout of the value (1 byte):
/// ```text
/// [0] scope u8 (0=Public, 1=FriendsOnly, 2=InviteOnly, 3=Private)
/// ```
///
/// NB: was `0x0012` historically — collided with
/// [`ADVERTISED_TRANSPORTS_TLV_TAG`] in the same ATTACH-trailer namespace.
/// The collision was latent (the two encoders are mutually exclusive and the
/// visibility decoder guards on `len == 1`), but a future encoder emitting both
/// on one frame would have the transports decoder mis-parse a visibility TLV.
/// Moved to the next free tag (`0x0016`; `0x0010`-`0x0015` are taken).
pub const VISIBILITY_SCOPE_TLV_TAG: u16 = 0x0016;

/// TLV tag for custom attachment lease TTL appended after `AttachPayload`.
///
/// Wire layout of the value (4 bytes):
/// ```text
/// [0..4] ttl_secs u32 BE (0 = use gateway default)
/// ```
pub const CUSTOM_TTL_TLV_TAG: u16 = 0x0013;

/// TLV tag for the peer's **observed source address** — STUN-style
/// auto-discovery of one's own public IP/port via the daemon counterpart.
///
/// Server side (the side accepting an incoming OVL1 connection) captures
/// the remote `SocketAddr` from the TCP/TLS/QUIC layer and echoes it back
/// in ATTACH. Client side (initiator) parses the TLV and learns "this is
/// the address you appeared as to my counterpart" — useful for NAT-mapped
/// hosts that don't know their public IP, and for operators wanting to
/// auto-fill an `advertise = "..."` URI without external STUN-like tools.
///
/// Wire layout (19 bytes fixed):
/// ```text
/// [0]    family       u8 (4 = IPv4, 6 = IPv6)
/// [1..17] addr        [u8; 16] (IPv4 addr placed in first 4 bytes when family=4)
/// [17..19] port       u16 BE
/// ```
///
/// Always sent in IPv6-mapped form on the wire to keep the field width
/// fixed; the family byte tells the parser how to interpret the bytes.
pub const OBSERVED_ADDR_TLV_TAG: u16 = 0x0014;
pub const OBSERVED_ADDR_TLV_LEN: usize = 19;

/// Encode the observed-address TLV value (without the 4-byte tag+len header).
pub fn encode_observed_addr(addr: std::net::SocketAddr) -> [u8; OBSERVED_ADDR_TLV_LEN] {
    let mut buf = [0u8; OBSERVED_ADDR_TLV_LEN];
    match addr {
        std::net::SocketAddr::V4(v4) => {
            buf[0] = 4;
            buf[1..5].copy_from_slice(&v4.ip().octets());
            // bytes 5..17 remain zero
        }
        std::net::SocketAddr::V6(v6) => {
            buf[0] = 6;
            buf[1..17].copy_from_slice(&v6.ip().octets());
        }
    }
    let port = addr.port();
    buf[17..19].copy_from_slice(&port.to_be_bytes());
    buf
}

/// Decode the observed-address TLV value back to a `SocketAddr`.
/// Returns `None` on invalid family byte or short buffer.
pub fn decode_observed_addr(buf: &[u8]) -> Option<std::net::SocketAddr> {
    if buf.len() < OBSERVED_ADDR_TLV_LEN {
        return None;
    }
    let port = u16::from_be_bytes([buf[17], buf[18]]);
    match buf[0] {
        4 => {
            let octets = [buf[1], buf[2], buf[3], buf[4]];
            Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(octets),
                port,
            )))
        }
        6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(octets),
                port,
                0,
                0,
            )))
        }
        _ => None,
    }
}

// ── Resume-nonce ATTACH TLV (session-resumption fresh-key derivation) ──────────

/// ATTACH-trailer TLV tag carrying the responder's per-resumption nonce.
pub const RESUME_NONCE_TLV_TAG: u16 = 0x0015;
/// Length of the resume-nonce TLV value (32-byte nonce).
pub const RESUME_NONCE_TLV_LEN: usize = 32;

/// Append the responder's per-resumption nonce to an ATTACH byte buffer as a
/// TLV (resume fast-path only). The initiator reads it via
/// [`decode_resume_nonce_from_attach`] and folds it — with its own HELLO nonce
/// — into [`veil_crypto::session_kdf::derive_resume_keys`], so the resumed
/// session gets fresh keys instead of reusing the original session's.
pub fn append_resume_nonce_to_attach(out: &mut Vec<u8>, nonce: &[u8; RESUME_NONCE_TLV_LEN]) {
    out.extend_from_slice(&RESUME_NONCE_TLV_TAG.to_be_bytes());
    out.extend_from_slice(&(RESUME_NONCE_TLV_LEN as u16).to_be_bytes());
    out.extend_from_slice(nonce);
}

/// Scan an ATTACH frame body for the responder's per-resumption nonce TLV.
/// Returns the 32-byte nonce if a well-formed `RESUME_NONCE_TLV_TAG` entry is
/// present, else `None` (initiator then refuses the unsafe resume).
pub fn decode_resume_nonce_from_attach(buf: &[u8]) -> Option<[u8; RESUME_NONCE_TLV_LEN]> {
    if buf.len() <= AttachPayload::WIRE_SIZE {
        return None;
    }
    let tlv_region = &buf[AttachPayload::WIRE_SIZE..];
    let mut pos = 0;
    while pos + 4 <= tlv_region.len() {
        let tag = u16::from_be_bytes([tlv_region[pos], tlv_region[pos + 1]]);
        let len = u16::from_be_bytes([tlv_region[pos + 2], tlv_region[pos + 3]]) as usize;
        pos += 4;
        if pos + len > tlv_region.len() {
            break;
        }
        if tag == RESUME_NONCE_TLV_TAG && len == RESUME_NONCE_TLV_LEN {
            return <[u8; RESUME_NONCE_TLV_LEN]>::try_from(&tlv_region[pos..pos + len]).ok();
        }
        pos += len;
    }
    None
}

/// Encode an `AttachPayload` with optional Vivaldi, battery, visibility scope
/// and custom TTL TLV extensions.
///
/// **Deferred wire-half — DO NOT delete as "dead code".** This and the
/// matching [`decode_visibility_scope_from_attach`] /
/// [`decode_custom_ttl_from_attach`] are the OVL1 wire encode/decode side of
/// the gateway attachment-visibility / custom-lease-TTL feature whose
/// server-side policy is already built and shipped in `veil-gateway`
/// (`attachment.rs::attach_with_scope`, `lease.rs` — which documents
/// `custom_ttl_secs` as riding [`CUSTOM_TTL_TLV_TAG`]). The handshake does not
/// yet emit these TLVs (only `encode_attach_with_tlvs`, the transports-only
/// encoder, is wired), so they read as unused — but removing them would orphan
/// the gateway's documented wire contract. Earlier audit flagged the tag
/// collision (`VISIBILITY_SCOPE_TLV_TAG` was `0x0012`, now `0x0016`); that is
/// resolved. (audit cycle-8 Этап-5.)
pub fn encode_attach_full(
    payload: &AttachPayload,
    vivaldi: Option<(f64, f64, f64)>,
    battery_level: Option<u8>,
    visibility_scope: Option<VisibilityScope>,
    custom_ttl_secs: Option<u32>,
) -> Vec<u8> {
    let mut out = encode_attach_with_vivaldi_and_battery(payload, vivaldi, battery_level);
    if let Some(scope) = visibility_scope
        && scope != VisibilityScope::Public
    {
        out.extend_from_slice(&VISIBILITY_SCOPE_TLV_TAG.to_be_bytes());
        out.extend_from_slice(&(1u16).to_be_bytes());
        out.push(scope as u8);
    }
    if let Some(ttl) = custom_ttl_secs
        && ttl > 0
    {
        out.extend_from_slice(&CUSTOM_TTL_TLV_TAG.to_be_bytes());
        out.extend_from_slice(&(4u16).to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
    }
    out
}

/// Extract visibility scope from ATTACH payload bytes (after the fixed header).
///
/// Returns `VisibilityScope::Public` (default) if the TLV is absent.
pub fn decode_visibility_scope_from_attach(buf: &[u8]) -> VisibilityScope {
    if buf.len() <= AttachPayload::WIRE_SIZE {
        return VisibilityScope::Public;
    }
    let tlv_region = &buf[AttachPayload::WIRE_SIZE..];
    let mut pos = 0;
    while pos + 4 <= tlv_region.len() {
        let tag = u16::from_be_bytes([tlv_region[pos], tlv_region[pos + 1]]);
        let len = u16::from_be_bytes([tlv_region[pos + 2], tlv_region[pos + 3]]) as usize;
        pos += 4;
        if pos + len > tlv_region.len() {
            break;
        }
        if tag == VISIBILITY_SCOPE_TLV_TAG && len == 1 {
            return VisibilityScope::from_u8(tlv_region[pos]);
        }
        pos += len;
    }
    VisibilityScope::Public
}

/// Extract custom TTL from ATTACH payload bytes (after the fixed header).
///
/// Returns `None` if the TLV is absent or the value is 0.
pub fn decode_custom_ttl_from_attach(buf: &[u8]) -> Option<u32> {
    if buf.len() <= AttachPayload::WIRE_SIZE {
        return None;
    }
    let tlv_region = &buf[AttachPayload::WIRE_SIZE..];
    let mut pos = 0;
    while pos + 4 <= tlv_region.len() {
        let tag = u16::from_be_bytes([tlv_region[pos], tlv_region[pos + 1]]);
        let len = u16::from_be_bytes([tlv_region[pos + 2], tlv_region[pos + 3]]) as usize;
        pos += 4;
        if pos + len > tlv_region.len() {
            break;
        }
        if tag == CUSTOM_TTL_TLV_TAG && len == 4 {
            let v = u32::from_be_bytes([
                tlv_region[pos],
                tlv_region[pos + 1],
                tlv_region[pos + 2],
                tlv_region[pos + 3],
            ]);
            return if v > 0 { Some(v) } else { None };
        }
        pos += len;
    }
    None
}

// ── DetachPayload ─────────────────────────────────────────────────────────────

/// Detach reason codes for `DetachPayload`.
pub mod detach_reason {
    /// Graceful user-initiated detach.
    pub const NORMAL: u8 = 0;
    /// Node is going down.
    pub const SHUTDOWN: u8 = 1;
    /// Error caused the detach.
    pub const ERROR: u8 = 2;
    /// Session is moving to another peer.
    pub const MIGRATING: u8 = 3;
}

/// Graceful session detach notification.
///
/// Wire layout:
/// ```text
/// [0] reason u8
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachPayload {
    /// One [`detach_reason`] codes.
    pub reason: u8,
}

impl DetachPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 1;

    /// Encode to a single byte.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        [self.reason]
    }

    /// Parse from a 1-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.is_empty() {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: 0,
            });
        }
        Ok(Self { reason: buf[0] })
    }
}

// ── SleepAdvertisementPayload ────────────────────────────────────────────────

/// Pre-disconnect announcement: a node tells its peers it is going to sleep
/// and expects to be back at `expected_wake_ts`.
///
/// Mailbox hosts that receive this frame extend the TTL of any queued
/// messages for `node_id` so they survive the sleep window. The signature
/// authenticates the announcement under the node's identity key and prevents
/// a third party from announcing arbitrary sleep windows on behalf of
/// other nodes.
///
/// Wire layout:
/// ```text
/// [0..32] node_id [u8; 32]
/// [32..40] expected_wake_ts u64 BE (Unix seconds)
/// [40..48] issued_at_ts u64 BE (Unix seconds; replay window anchor)
/// [48..112] signature [u8; 64] — ed25519 over signable_bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SleepAdvertisementPayload {
    /// Announcing node's `node_id`.
    pub node_id: [u8; 32],
    /// Expected wake-up Unix timestamp (seconds).
    pub expected_wake_ts: u64,
    /// Unix timestamp when the advert was issued (replay-window anchor).
    pub issued_at_ts: u64,
    /// Ed25519 signature over [`Self::signable_bytes`].
    pub signature: [u8; 64],
}

impl SleepAdvertisementPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 8 + 8 + 64; // 112

    /// Bytes covered by the signature (all fields except the signature itself).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(48);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&self.expected_wake_ts.to_be_bytes());
        buf.extend_from_slice(&self.issued_at_ts.to_be_bytes());
        buf
    }

    /// Encode to the fixed 112-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.node_id);
        buf[32..40].copy_from_slice(&self.expected_wake_ts.to_be_bytes());
        buf[40..48].copy_from_slice(&self.issued_at_ts.to_be_bytes());
        buf[48..112].copy_from_slice(&self.signature);
        buf
    }

    /// Parse from a 112-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            node_id: super::read_array::<32>(buf, 0)?,
            expected_wake_ts: super::read_u64_be(buf, 32)?,
            issued_at_ts: super::read_u64_be(buf, 40)?,
            signature: super::read_array::<64>(buf, 48)?,
        })
    }
}

// ── TransportMigrationNotifyPayload ───────────────────────────────────────────

/// Inform peer that the sender is moving to a new transport URI.  Used
/// by ephemeral-port rotation (Phase 5b of per-listener visibility plan):
/// before the sender's old listener closes, it broadcasts this message
/// to each active session so peers learn the new URI without waiting on DHT
/// re-resolution.
///
/// Wire layout:
/// ```text
/// [0..32]    node_id            [u8; 32]
/// [32..40]   new_expiry_unix    u64 BE   (NEW URI valid until that unix-time)
/// [40..48]   issued_at_unix     u64 BE   (replay-window anchor)
/// [48..50]   new_transport_len  u16 BE   (≤ MAX_TRANSPORT_URI_LEN)
/// [50..L]    new_transport      utf8     (e.g. "obfs4-tcp://1.2.3.4:7821")
/// [L..L+64]  signature          [u8; 64] (Ed25519 over signable_bytes)
/// ```
///
/// `signable_bytes` covers `node_id || new_expiry_unix || issued_at_unix ||
/// new_transport_len_be || new_transport_utf8` (everything except the
/// trailing sig).  Receiver verifies sig against node_id's `identity_pubkey`
/// from the existing session's handshake context.
///
/// **Replay tolerance**: receiver accepts iff `|issued_at - now| ≤
/// MIGRATION_REPLAY_WINDOW_SECS` (5 minutes).  Old captures replayed
/// outside window are silently dropped (no error; just skip update).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportMigrationNotifyPayload {
    /// Announcing node's `node_id`.
    pub node_id: [u8; 32],
    /// Unix timestamp with which the NEW URI's announcement should expire.
    /// Beyond this, peers SHOULD revert to DHT lookup.
    pub new_expiry_unix: u64,
    /// Unix timestamp when the notify was issued (replay anchor).
    pub issued_at_unix: u64,
    /// New transport URI (e.g. `"obfs4-tcp://1.2.3.4:7821"`).
    /// Length capped at [`MAX_TRANSPORT_URI_LEN`] (240 bytes).
    pub new_transport: String,
    /// Ed25519 signature over [`Self::signable_bytes`].
    pub signature: [u8; 64],
}

/// Maximum length of `new_transport` field (UTF-8 bytes).  Matches
/// [`crate::discovery::MAX_TRANSPORT_URI_LEN`] for consistency.
pub const MAX_TRANSPORT_URI_LEN: usize = 240;

/// Replay-tolerance window (seconds).  Notifies with `|issued_at - now|`
/// outside this window are silently dropped without error.
pub const MIGRATION_REPLAY_WINDOW_SECS: u64 = 300;

impl TransportMigrationNotifyPayload {
    /// Bytes covered by the signature.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let transport_bytes = self.new_transport.as_bytes();
        let mut buf = Vec::with_capacity(32 + 8 + 8 + 2 + transport_bytes.len());
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&self.new_expiry_unix.to_be_bytes());
        buf.extend_from_slice(&self.issued_at_unix.to_be_bytes());
        buf.extend_from_slice(&(transport_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(transport_bytes);
        buf
    }

    /// Encode to wire bytes.  Variable length (depends on URI length).
    pub fn encode(&self) -> Vec<u8> {
        let transport_bytes = self.new_transport.as_bytes();
        let total = 32 + 8 + 8 + 2 + transport_bytes.len() + 64;
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&self.node_id);
        buf.extend_from_slice(&self.new_expiry_unix.to_be_bytes());
        buf.extend_from_slice(&self.issued_at_unix.to_be_bytes());
        buf.extend_from_slice(&(transport_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(transport_bytes);
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Decode wire bytes with structural validation.  Caller still needs to
    /// verify the Ed25519 signature against the issuer's identity_pubkey
    /// using [`verify_transport_migration_notify`].
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        const HEADER_BEFORE_URI: usize = 32 + 8 + 8 + 2;
        if buf.len() < HEADER_BEFORE_URI + 64 {
            return Err(ProtoError::BufferTooShort {
                need: HEADER_BEFORE_URI + 64,
                got: buf.len(),
            });
        }
        let node_id = super::read_array::<32>(buf, 0)?;
        let new_expiry_unix = super::read_u64_be(buf, 32)?;
        let issued_at_unix = super::read_u64_be(buf, 40)?;
        let transport_len = super::read_u16_be(buf, 48)? as usize;
        if transport_len > MAX_TRANSPORT_URI_LEN {
            return Err(ProtoError::ValueTooLarge {
                field: "TransportMigrationNotify.transport_len",
                value: transport_len as u64,
                max: MAX_TRANSPORT_URI_LEN as u64,
            });
        }
        let total_needed = HEADER_BEFORE_URI + transport_len + 64;
        if buf.len() < total_needed {
            return Err(ProtoError::BufferTooShort {
                need: total_needed,
                got: buf.len(),
            });
        }
        let transport_bytes = &buf[50..50 + transport_len];
        let new_transport = std::str::from_utf8(transport_bytes)
            .map_err(|_| ProtoError::InvalidUtf8)?
            .to_owned();
        let sig_start = 50 + transport_len;
        let signature = super::read_array::<64>(buf, sig_start)?;
        Ok(Self {
            node_id,
            new_expiry_unix,
            issued_at_unix,
            new_transport,
            signature,
        })
    }
}

/// Domain-separation tag for the Ed25519 signature input.  Prepended
/// before `signable_bytes` so sig from one purpose can't be replayed
/// as sig for another.
pub const MIGRATION_SIG_DOMAIN: &[u8] = b"veil-transport-migration:v1\0";

/// Sign a migration notify body with the sender's Ed25519 signing key.
/// Builds the payload with the computed signature filled in.
pub fn sign_transport_migration_notify(
    node_id: [u8; 32],
    new_expiry_unix: u64,
    issued_at_unix: u64,
    new_transport: String,
    signing_key: &ed25519_dalek::SigningKey,
) -> TransportMigrationNotifyPayload {
    let mut draft = TransportMigrationNotifyPayload {
        node_id,
        new_expiry_unix,
        issued_at_unix,
        new_transport,
        signature: [0u8; 64],
    };
    let mut to_sign = Vec::with_capacity(MIGRATION_SIG_DOMAIN.len() + 64);
    to_sign.extend_from_slice(MIGRATION_SIG_DOMAIN);
    to_sign.extend_from_slice(&draft.signable_bytes());
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(&to_sign);
    draft.signature = sig.to_bytes();
    draft
}

/// Verify a migration notify.  Returns `Ok(())` iff:
/// 1. Sig is a valid Ed25519 signature over `MIGRATION_SIG_DOMAIN ||
///    signable_bytes` under `pubkey`.
/// 2. `node_id` equals `BLAKE3(pubkey)` (identity binding).
/// 3. `|issued_at_unix - now_unix| ≤ MIGRATION_REPLAY_WINDOW_SECS`.
///
/// Caller separately checks `new_transport` length cap (already done
/// by `decode`).  Replay outside the window returns
/// `ProtoError::Malformed` so the caller can silent-drop.
pub fn verify_transport_migration_notify(
    payload: &TransportMigrationNotifyPayload,
    pubkey: &[u8; 32],
    now_unix: u64,
) -> Result<(), ProtoError> {
    // Identity binding: node_id MUST equal BLAKE3(pubkey).
    let expected_node_id = *blake3::hash(pubkey).as_bytes();
    if expected_node_id != payload.node_id {
        return Err(ProtoError::Malformed(
            "TransportMigrationNotify: node_id != BLAKE3(pubkey)".to_owned(),
        ));
    }
    // Replay-window check.
    let skew = now_unix.abs_diff(payload.issued_at_unix);
    if skew > MIGRATION_REPLAY_WINDOW_SECS {
        return Err(ProtoError::Malformed(format!(
            "TransportMigrationNotify replay: issued_at skew {}s > {}s window",
            skew, MIGRATION_REPLAY_WINDOW_SECS
        )));
    }
    // Sig verify.
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(pubkey)
        .map_err(|e| ProtoError::Malformed(format!("bad pubkey: {e}")))?;
    let mut to_verify = Vec::with_capacity(MIGRATION_SIG_DOMAIN.len() + 64);
    to_verify.extend_from_slice(MIGRATION_SIG_DOMAIN);
    to_verify.extend_from_slice(&payload.signable_bytes());
    let sig = ed25519_dalek::Signature::from_bytes(&payload.signature);
    use ed25519_dalek::Verifier;
    verifying.verify(&to_verify, &sig).map_err(|_| {
        ProtoError::Malformed("TransportMigrationNotify sig verify failed".to_owned())
    })?;
    Ok(())
}

// ── KeepalivePayload ──────────────────────────────────────────────────────────

/// Session keepalive / heartbeat.
///
/// Wire layout:
/// ```text
/// [0..8] timestamp_secs u64 BE (sender's local Unix time; used for RTT estimation)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeepalivePayload {
    /// Sender's Unix timestamp in seconds (for RTT computation).
    pub timestamp_secs: u64,
}

impl KeepalivePayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 8;

    /// Encode to an 8-byte big-endian buffer.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.timestamp_secs.to_be_bytes()
    }

    /// Parse from an 8-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let timestamp_secs = super::read_u64_be(buf, 0)?;
        Ok(Self { timestamp_secs })
    }
}

// ── RekeyPayload ──────────────────────────────────────────────────────────────

/// Carries a new ephemeral X25519 public key for session rekeying.
///
/// Sent as `RekeyInit` (initiator → responder) and `RekeyAck` (responder → initiator).
///
/// Wire layout:
/// ```text
/// [0..32] ephemeral_pubkey [u8; 32]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyPayload {
    /// New ephemeral X25519 public key (32 bytes).
    pub ephemeral_pubkey: [u8; 32],
}

impl RekeyPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32;

    /// Encode to the 32-byte public key.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.ephemeral_pubkey
    }

    /// Parse from a 32-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let ephemeral_pubkey = super::read_array::<32>(buf, 0)?;
        Ok(Self { ephemeral_pubkey })
    }
}

// ── MlKemRekeyEkPayload ───────────────────────────────────────────────────────

/// Carries a new ML-KEM-768 encapsulation key during intra-session key rotation.
///
/// Sent as `MlKemRekeyEk` by the node that wants to rotate its E2E key.
/// The receiver updates its peer-EK cache to `encapsulation_key` and replies
/// with an empty `MlKemRekeyAck`. Future E2E messages to the sender will use
/// the new key; messages encrypted with the old key can no longer be decrypted
/// once the rotation is committed.
///
/// Wire layout:
/// ```text
/// [0..1184] encapsulation_key [u8; 1184] — ML-KEM-768 encapsulation key
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlKemRekeyEkPayload {
    /// New ML-KEM-768 encapsulation key (1184 bytes).
    pub encapsulation_key: [u8; 1184],
}

impl MlKemRekeyEkPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 1184;

    /// Encode to the 1184-byte encapsulation key.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.encapsulation_key
    }

    /// Parse from a 1184-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let encapsulation_key = super::read_array::<1184>(buf, 0)?;
        Ok(Self { encapsulation_key })
    }
}

// ── SessionTicket ─────────────────────────────────────────────────────────────

/// Opaque byte blob carrying an AEAD-encrypted `SessionTicket`.
///
/// Wire size is always `SESSION_TICKET_ENCRYPTED_SIZE` bytes:
/// `nonce(12) + ciphertext(160) + tag(16) = 188`.
pub type EncryptedTicket = Vec<u8>;

/// Entry stored by the client after the server issues a resumption ticket.
///
/// Contains both the opaque `blob` to present to the server in the next HELLO TLV
/// and the client's own session keys so the cipher can be restored on fast-path
/// acceptance without decrypting the blob.
/// M6: derive `Zeroize + ZeroizeOnDrop` so `tx_key` / `rx_key` /
/// `session_id` are wiped on every drop path (LRU eviction at `MAX_PEER_TICKETS`
/// process shutdown, panic-unwind). Without this the raw 32-byte session
/// keys linger in heap until allocator reuse — meaningful linkability
/// surface on memory-disclosure or core-dump. `blob` is encrypted ciphertext
/// (no value to zero) and skipped; non-`Zeroize` fields (`String`, `Instant`)
/// also skipped.
#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct ClientTicketEntry {
    /// Opaque encrypted ticket blob — sent verbatim in the HELLO `resume_ticket` TLV.
    #[zeroize(skip)]
    pub blob: EncryptedTicket,
    /// Client's TX key from the original session.
    pub tx_key: [u8; 32],
    /// Client's RX key from the original session.
    pub rx_key: [u8; 32],
    /// Session identifier from the original handshake.
    pub session_id: [u8; 32],
    /// Base64-encoded remote peer public key from the original handshake.
    /// Used to reconstruct `OvlHandshakeResult.public_key` on fast-path resumption.
    #[zeroize(skip)]
    pub peer_public_key: String,
    /// Remote peer nonce string from the original handshake.
    #[zeroize(skip)]
    pub peer_nonce: String,
    /// Wall-clock instant when this entry was stored.
    /// Used by `peer_tickets` cap eviction: oldest entry is evicted
    /// when the map reaches `MAX_PEER_TICKETS`.
    #[zeroize(skip)]
    pub issued_at: std::time::Instant,
}

/// Plaintext session ticket issued after a successful OVL1 handshake.
///
/// The server AEAD-encrypts this struct with its host ticket key before sending
/// it to the client as a `SESSION_TICKET` frame. The client stores the opaque
/// `EncryptedTicket` and presents it in the next `HelloPayload` TLV when
/// reconnecting to the same peer.
///
/// Wire layout (plaintext, before encryption):
/// ```text
/// [0..32] session_id [u8; 32] — session identifier from SessionConfirm
/// [32..64] peer_id [u8; 32] — remote peer's node_id
/// [64..96] tx_key [u8; 32] — restored TX AEAD key
/// [96..128] rx_key [u8; 32] — restored RX AEAD key
/// [128..136] issued_at u64 BE — Unix seconds when ticket was issued
/// [136..144] valid_until u64 BE — Unix seconds when ticket expires
/// [144..160] peer_instance_id [u8; 16] — (optional trailer)
/// ```
///
/// # — optional `peer_instance_id` trailer
///
/// Binds the ticket to a specific `(peer_id, peer_instance_id)` pair
/// so that if two instances of the same sovereign identity (laptop
/// phone) both hold a resumption ticket, the server can tell them
/// apart and avoid AEAD nonce reuse when they both reconnect.
/// Legacy (pre-462.17) tickets carry a 144-byte plaintext; new
/// tickets carry 160. The decoder accepts both and defaults
/// `peer_instance_id` to `[0; 16]` on the legacy shape — same
/// "unspecified" sentinel as the 462.19 mailbox path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTicket {
    /// Session identifier derived during the handshake.
    pub session_id: [u8; 32],
    /// The remote peer's node_id (used to bind the ticket to this peer).
    pub peer_id: [u8; 32],
    /// The session TX key (from the original `SessionKeys`).
    pub tx_key: [u8; 32],
    /// The session RX key (from the original `SessionKeys`).
    pub rx_key: [u8; 32],
    /// Unix timestamp (seconds) when this ticket was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) after which the ticket must not be accepted.
    pub valid_until: u64,
    /// which instance of `peer_id` this ticket was issued
    /// to. `[0; 16]` = legacy / unspecified (single-device peer).
    /// Non-zero binds the ticket to that specific instance so two
    /// devices under the same identity cannot collide on AEAD nonces
    /// at resumption time.
    pub peer_instance_id: [u8; 16],
}

impl SessionTicket {
    /// Plaintext wire size: 32+32+32+32+8+8+16 = 160 bytes.
    pub const PLAINTEXT_SIZE: usize = 160;

    /// Encode the plaintext ticket to the fixed 160-byte layout.
    pub fn encode(&self) -> [u8; Self::PLAINTEXT_SIZE] {
        let mut buf = [0u8; Self::PLAINTEXT_SIZE];
        buf[0..32].copy_from_slice(&self.session_id);
        buf[32..64].copy_from_slice(&self.peer_id);
        buf[64..96].copy_from_slice(&self.tx_key);
        buf[96..128].copy_from_slice(&self.rx_key);
        buf[128..136].copy_from_slice(&self.issued_at.to_be_bytes());
        buf[136..144].copy_from_slice(&self.valid_until.to_be_bytes());
        buf[144..160].copy_from_slice(&self.peer_instance_id);
        buf
    }

    /// Parse the plaintext ticket. Requires the full 160-byte layout.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::PLAINTEXT_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::PLAINTEXT_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            session_id: super::read_array::<32>(buf, 0)?,
            peer_id: super::read_array::<32>(buf, 32)?,
            tx_key: super::read_array::<32>(buf, 64)?,
            rx_key: super::read_array::<32>(buf, 96)?,
            issued_at: super::read_u64_be(buf, 128)?,
            valid_until: super::read_u64_be(buf, 136)?,
            peer_instance_id: super::read_array::<16>(buf, 144)?,
        })
    }
}

// ── hybrid-kex ML-KEM ciphertext payload ───────────────

/// Payload of `SessionMsg::HybridKexCt`. Carries the 1088-byte
/// ML-KEM-768 ciphertext from the initiator to the responder.
///
/// Wire layout:
/// ```text
/// [0..2] ct_len u16 BE
/// [2..2+L] ct_bytes [u8; L] (typically L = 1088 for ML-KEM-768)
/// ```
///
/// The length-prefix is included even though ML-KEM-768 has a fixed
/// CT length, so a future PQ algo upgrade (ML-KEM-1024 has a
/// 1568-byte CT) can drop in without a wire-format bump. Decoders
/// reject malformed frames AND any trailing bytes after the declared
/// CT length to catch buggy peers early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridKexCtPayload {
    /// ML-KEM-768 ciphertext (caller validates length).
    pub mlkem_ct: Vec<u8>,
}

impl HybridKexCtPayload {
    /// Reasonable wire-cap. ML-KEM-1024's CT is 1568 B; allow some
    /// slack for future algos. An attacker-supplied frame that
    /// declares a longer length is rejected at decode time before
    /// any allocation.
    pub const MAX_CT_BYTES: usize = 4096;

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.mlkem_ct.len());
        let len = self.mlkem_ct.len().min(u16::MAX as usize) as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.mlkem_ct);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut pos = 0;
        let len = read_u16(buf, &mut pos, "hybrid_kex_ct.len")? as usize;
        if len > Self::MAX_CT_BYTES {
            return Err(ProtoError::ValueTooLarge {
                field: "hybrid_kex_ct.len",
                value: len as u64,
                max: Self::MAX_CT_BYTES as u64,
            });
        }
        let mlkem_ct = read_bytes(buf, &mut pos, len, "hybrid_kex_ct.bytes")?;
        if pos != buf.len() {
            return Err(ProtoError::TrailingBytes {
                trailing: buf.len() - pos,
            });
        }
        Ok(Self { mlkem_ct })
    }
}

// ── hot-standby transport handover ─────────────────────────────────
//
// The handoff migrates a live session onto a new transport via a
// challenge-response on the fresh socket (NOT the old nonce-echo scheme):
//
// 1. `HandoffInit` (over primary, AEAD) — sender announces intent to
// migrate the session onto a new underlying transport.
// 2. `HandoffAck` (over primary, AEAD) — receiver agrees and records a
// pending handoff keyed by `session_id`.
// 3. `HandoffAttach` (first frame on the **new** socket) — initiator
// identifies which session this socket belongs to.
// 4. `HandoffChallenge` (new socket) — the accepting side replies with a
// FRESH 32-byte `OsRng` challenge generated for THIS socket.
// 5. `HandoffResponse` (new socket) — initiator proves ownership with
// `hmac = BLAKE3::keyed(tx_key)(session_id || challenge)`; the accepting
// side recomputes it with its `rx_key` (which equals the sender's
// `tx_key` under the OVL1 DH) and constant-time compares. Mismatch →
// close the socket as a protocol violation.
//
// Anti-replay comes from the per-socket FRESH challenge: a captured
// `HandoffResponse` cannot answer a different socket's challenge (see
// `veil-session/src/handoff.rs` + its replay regression test). Each
// payload is fixed-size, so the decoder rejects any trailing bytes:
// `TrailingBytes { trailing: buf.len - WIRE_SIZE }`.

/// Payload of `SessionMsg::HandoffInit` (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffInitPayload {
    /// Fresh random nonce. The receiver will stash this in its
    /// `HandoffRegistry`; the sender will feed it into the HMAC on the
    /// warm socket's `HandoffAttach`.
    pub nonce: [u8; 32],
}

impl HandoffInitPayload {
    pub const WIRE_SIZE: usize = 32;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.nonce
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() != Self::WIRE_SIZE {
            return Err(ProtoError::Malformed(format!(
                "HandoffInit: expected {} bytes, got {}",
                Self::WIRE_SIZE,
                buf.len(),
            )));
        }
        Ok(Self {
            nonce: buf.try_into().expect("length checked"),
        })
    }
}

/// Payload of `SessionMsg::HandoffAck` (32 bytes).
///
/// The ack echoes the nonce verbatim so the initiator can match this
/// response to its outstanding `HandoffInit`. Any other shape
/// (length mismatch, nonce of all zeros) is a protocol violation and
/// MUST NOT be accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffAckPayload {
    pub nonce: [u8; 32],
}

impl HandoffAckPayload {
    pub const WIRE_SIZE: usize = 32;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.nonce
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() != Self::WIRE_SIZE {
            return Err(ProtoError::Malformed(format!(
                "HandoffAck: expected {} bytes, got {}",
                Self::WIRE_SIZE,
                buf.len(),
            )));
        }
        Ok(Self {
            nonce: buf.try_into().expect("length checked"),
        })
    }
}

/// Payload of `SessionMsg::HandoffAttach` (32 bytes) — audit cycle-6 (T1).
///
/// Wire layout:
/// ```text
/// [0..32] session_id [u8; 32] — the session this warm socket wants to rejoin
/// ```
///
/// This is now a bare ANNOUNCE: the initiator opens the warm socket and sends
/// only the `session_id` it wants to bind to. The receiver replies with a
/// fresh per-socket [`HandoffChallengePayload`], and the initiator proves
/// session-key ownership with a [`HandoffResponsePayload`]. Splitting the proof
/// out of the attach closes the replay race the old single-frame design had: a
/// passive on-path observer that copied the attach bytes onto its own socket
/// now receives a DIFFERENT challenge it cannot answer without the session's
/// `tx_key`. (Previously the HMAC was bound to a nonce fixed before the socket
/// existed, so a replayed attach was a static, valid token.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffAttachPayload {
    pub session_id: [u8; 32],
}

impl HandoffAttachPayload {
    pub const WIRE_SIZE: usize = 32;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.session_id
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() != Self::WIRE_SIZE {
            return Err(ProtoError::Malformed(format!(
                "HandoffAttach: expected {} bytes, got {}",
                Self::WIRE_SIZE,
                buf.len(),
            )));
        }
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&buf[0..32]);
        Ok(Self { session_id })
    }

    /// Compute the HMAC that proves session-key ownership over the receiver's
    /// per-socket challenge. Both sides use the SAME key material: the initiator
    /// keys it with its `tx_key`; the receiver recomputes with its `rx_key`.
    /// Under OVL1 DH these are identical symmetric key bytes, so the HMAC
    /// matches when and only when the response came from the legitimate session
    /// owner. (Kept on this type so existing call sites and tests that reference
    /// `HandoffAttachPayload::compute_hmac` keep working; the `nonce` argument
    /// is now the receiver's fresh per-socket challenge — see
    /// [`HandoffChallengePayload`] / [`HandoffResponsePayload`].)
    pub fn compute_hmac(key: &[u8; 32], session_id: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(session_id);
        hasher.update(nonce);
        *hasher.finalize().as_bytes()
    }
}

/// Payload of `SessionMsg::HandoffChallenge` (32 bytes) — audit cycle-6 (T1).
///
/// Receiver → initiator on the warm socket, in reply to a bare `HandoffAttach`.
/// Carries a fresh 32-byte `OsRng` `challenge` bound to THIS socket; the
/// initiator must echo back `compute_hmac(tx_key, session_id, challenge)` in a
/// [`HandoffResponsePayload`]. Freshness per-socket is what defeats replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffChallengePayload {
    pub challenge: [u8; 32],
}

impl HandoffChallengePayload {
    pub const WIRE_SIZE: usize = 32;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.challenge
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() != Self::WIRE_SIZE {
            return Err(ProtoError::Malformed(format!(
                "HandoffChallenge: expected {} bytes, got {}",
                Self::WIRE_SIZE,
                buf.len(),
            )));
        }
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&buf[0..32]);
        Ok(Self { challenge })
    }
}

/// Payload of `SessionMsg::HandoffResponse` (32 bytes) — audit cycle-6 (T1).
///
/// Initiator → receiver on the warm socket: `hmac =
/// BLAKE3::keyed(tx_key)(session_id || challenge)` over the receiver's
/// per-socket challenge. The receiver recomputes with `rx_key`; only on a
/// constant-time match does it consume the one-shot pending entry and bind the
/// socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffResponsePayload {
    pub hmac: [u8; 32],
}

impl HandoffResponsePayload {
    pub const WIRE_SIZE: usize = 32;

    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        self.hmac
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() != Self::WIRE_SIZE {
            return Err(ProtoError::Malformed(format!(
                "HandoffResponse: expected {} bytes, got {}",
                Self::WIRE_SIZE,
                buf.len(),
            )));
        }
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&buf[0..32]);
        Ok(Self { hmac })
    }
}

// ── decode helpers ────────────────────────────────────────────────────────────

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn node_id(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn observed_addr_v4_roundtrip() {
        let original: std::net::SocketAddr = "203.0.113.42:9000".parse().unwrap();
        let encoded = encode_observed_addr(original);
        assert_eq!(encoded.len(), OBSERVED_ADDR_TLV_LEN);
        assert_eq!(encoded[0], 4);
        let decoded = decode_observed_addr(&encoded).expect("roundtrip");
        assert_eq!(decoded, original);
    }

    #[test]
    fn observed_addr_v6_roundtrip() {
        let original: std::net::SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let encoded = encode_observed_addr(original);
        assert_eq!(encoded[0], 6);
        let decoded = decode_observed_addr(&encoded).expect("roundtrip");
        // Note: SocketAddrV6 carries flowinfo/scope_id; encode normalises them
        // to 0 so we compare only ip + port.
        assert_eq!(decoded.ip().to_string(), original.ip().to_string());
        assert_eq!(decoded.port(), original.port());
    }

    #[test]
    fn observed_addr_rejects_unknown_family() {
        let mut buf = [0u8; OBSERVED_ADDR_TLV_LEN];
        buf[0] = 9; // not 4 or 6
        assert!(decode_observed_addr(&buf).is_none());
    }

    #[test]
    fn observed_addr_rejects_short_buffer() {
        let buf = [0u8; OBSERVED_ADDR_TLV_LEN - 1];
        assert!(decode_observed_addr(&buf).is_none());
    }

    #[test]
    fn hello_roundtrip() {
        let p = HelloPayload {
            ovl1_major: 1,
            node_id: node_id(0xAB),
            resume_ticket: None,
            membership_cert_blob: None,
            resume_nonce: None,
        };
        assert_eq!(HelloPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn hello_roundtrip_with_membership_cert() {
        let cert_blob: Vec<u8> = (0..120).collect();
        let p = HelloPayload {
            ovl1_major: 1,
            node_id: node_id(0xCD),
            resume_ticket: None,
            membership_cert_blob: Some(cert_blob.clone()),
            resume_nonce: None,
        };
        let decoded = HelloPayload::decode(&p.encode()).unwrap();
        assert_eq!(
            decoded.membership_cert_blob.as_deref(),
            Some(&cert_blob[..])
        );
        assert_eq!(decoded, p);
    }

    #[test]
    fn hello_roundtrip_with_both_tlvs() {
        let resume: Vec<u8> = (0..188).collect();
        let cert_blob: Vec<u8> = (0..100).collect();
        let resume_nonce = [0x5Au8; 32];
        let p = HelloPayload {
            ovl1_major: 1,
            node_id: node_id(0xEF),
            resume_ticket: Some(resume.clone()),
            membership_cert_blob: Some(cert_blob.clone()),
            resume_nonce: Some(resume_nonce),
        };
        let decoded = HelloPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded.resume_ticket.as_deref(), Some(&resume[..]));
        assert_eq!(
            decoded.membership_cert_blob.as_deref(),
            Some(&cert_blob[..])
        );
        assert_eq!(decoded.resume_nonce, Some(resume_nonce));
        assert_eq!(decoded, p);
    }

    #[test]
    fn hello_rejects_oversized_membership_cert_tlv() {
        // Manually construct a HELLO wire with a TLV body 2049 bytes
        // (one more than MAX_MEMBERSHIP_CERT_SIZE). Decoder must skip
        // the cert silently, not propagate it.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes()); // ovl1_major
        buf.extend_from_slice(&node_id(0xAA)); // node_id
        buf.push(crate::budget::HELLO_TLV_MEMBERSHIP_CERT);
        let len = (crate::budget::MAX_MEMBERSHIP_CERT_SIZE + 1) as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&vec![0xFFu8; len as usize]);
        let decoded = HelloPayload::decode(&buf).unwrap();
        assert!(decoded.membership_cert_blob.is_none());
    }

    #[test]
    fn identity_roundtrip() {
        let p = IdentityPayload {
            algo: 1,
            public_key: b"ed25519-pubkey-32bytes-placeholder".to_vec(),
            nonce: b"nonce123".to_vec(),
            node_id: node_id(0x42),
            mlkem_pubkey: None,
        };
        assert_eq!(IdentityPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn identity_roundtrip_with_mlkem() {
        let p = IdentityPayload {
            algo: 1,
            public_key: b"ed25519-pubkey-32bytes-placeholder".to_vec(),
            nonce: b"nonce123".to_vec(),
            node_id: node_id(0x42),
            mlkem_pubkey: Some(vec![0xABu8; 1184]),
        };
        assert_eq!(IdentityPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn identity_no_mlkem_zero_len() {
        let p = IdentityPayload {
            algo: 1,
            public_key: b"key".to_vec(),
            nonce: b"n".to_vec(),
            node_id: node_id(0x01),
            mlkem_pubkey: None,
        };
        assert_eq!(IdentityPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn capabilities_roundtrip() {
        let p = CapabilitiesPayload {
            roles_supported: role_bits::LEAF | role_bits::CORE,
            flags: cap_flags::CAN_RELAY | cap_flags::SUPPORTS_SOVEREIGN_IDENTITY,
            discovery_mode: 1, // ContactsOnly
        };
        assert_eq!(CapabilitiesPayload::decode(&p.encode()).unwrap(), p);
    }

    /// pre-474.4 peers send 2 bytes; decoder defaults
    /// the missing `discovery_mode` byte to `0` (Public).
    #[test]
    fn capabilities_legacy_2byte_decodes_as_public() {
        let legacy = [role_bits::CORE, cap_flags::CAN_RELAY];
        let decoded = CapabilitiesPayload::decode(&legacy).unwrap();
        assert_eq!(decoded.roles_supported, role_bits::CORE);
        assert_eq!(decoded.flags, cap_flags::CAN_RELAY);
        assert_eq!(
            decoded.discovery_mode, 0,
            "missing byte must default to Public"
        );
    }

    /// (Variant C): unknown `discovery_mode` byte must
    /// decode as `IntroductionOnly` — most-restrictive forward-compat
    /// default. A future peer sending a not-yet-defined mode value
    /// is treated conservatively (we don't disclose them in FIND_NODE).
    #[test]
    fn capabilities_unknown_discovery_mode_maps_to_introduction_only() {
        let p = CapabilitiesPayload {
            roles_supported: role_bits::CORE,
            flags: 0,
            discovery_mode: 99, // unknown future value
        };
        let decoded = CapabilitiesPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded.discovery_mode, 99, "raw byte preserved on the wire");
        assert_eq!(
            decoded.parse_discovery_mode(),
            veil_types::DiscoveryMode::IntroductionOnly,
            "unknown values must parse as IntroductionOnly (Variant C)",
        );
    }

    #[test]
    fn key_agreement_roundtrip() {
        let p = KeyAgreementPayload {
            algo: 2,
            ephemeral_pubkey: vec![0xDE; 32],
            ephemeral_sig: vec![0xAB; 64],
        };
        assert_eq!(KeyAgreementPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn session_confirm_roundtrip() {
        let p = SessionConfirmPayload {
            session_id: [0xCC; 32],
            mac: [0xDD; 32],
        };
        assert_eq!(SessionConfirmPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn attach_roundtrip() {
        let p = AttachPayload {
            role: 1,
            realm_id: 42,
            attach_epoch: 7,
            mailbox_preference_count: 2,
            gateway_preference_count: 3,
            flags: 0xFF_FF,
        };
        assert_eq!(AttachPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn resume_nonce_attach_tlv_roundtrips_and_coexists() {
        let base = AttachPayload {
            role: 1,
            realm_id: 0,
            attach_epoch: 0,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        };
        // Build an ATTACH that already carries other trailer TLVs (battery +
        // transports + observed_addr), then append the resume nonce — it must be
        // found regardless of the TLVs before it.
        let mut bytes =
            encode_attach_with_tlvs(&base, Some((1.0, 2.0, 3.0)), Some(55), &["tcp".to_owned()]);
        let addr: std::net::SocketAddr = "203.0.113.7:9000".parse().unwrap();
        bytes.extend_from_slice(&OBSERVED_ADDR_TLV_TAG.to_be_bytes());
        bytes.extend_from_slice(&(OBSERVED_ADDR_TLV_LEN as u16).to_be_bytes());
        bytes.extend_from_slice(&encode_observed_addr(addr));
        let nonce = [0x7Bu8; RESUME_NONCE_TLV_LEN];
        append_resume_nonce_to_attach(&mut bytes, &nonce);

        assert_eq!(decode_resume_nonce_from_attach(&bytes), Some(nonce));
        // The pre-existing TLVs still decode (resume nonce didn't shadow them).
        assert_eq!(decode_battery_from_attach(&bytes), Some(55));
        assert_eq!(decode_observed_addr_from_attach(&bytes), Some(addr));
        // No false positive when the TLV is absent.
        let mut without = encode_attach_with_tlvs(&base, None, None, &[]);
        assert_eq!(decode_resume_nonce_from_attach(&without), None);
        // A wrong-length entry under the tag is rejected (not half-accepted).
        without.extend_from_slice(&RESUME_NONCE_TLV_TAG.to_be_bytes());
        without.extend_from_slice(&(16u16).to_be_bytes());
        without.extend_from_slice(&[0u8; 16]);
        assert_eq!(decode_resume_nonce_from_attach(&without), None);
    }

    #[test]
    fn hello_too_short() {
        assert!(HelloPayload::decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn identity_decode_rejects_oversized_fields() {
        // Oversized public_key is rejected before allocation/verify.
        let big_pk = IdentityPayload {
            algo: 0,
            public_key: vec![7u8; crate::budget::MAX_SIGNATURE_PUBKEY_BYTES + 1],
            nonce: vec![],
            node_id: [0u8; 32],
            mlkem_pubkey: None,
        };
        assert!(IdentityPayload::decode(&big_pk.encode()).is_err());
        // Oversized ML-KEM key likewise.
        let big_ek = IdentityPayload {
            algo: 0,
            public_key: vec![1u8; 32],
            nonce: vec![],
            node_id: [0u8; 32],
            mlkem_pubkey: Some(vec![9u8; crate::budget::MAX_MLKEM_PK_LEN + 1]),
        };
        assert!(IdentityPayload::decode(&big_ek.encode()).is_err());
        // A normal-sized identity still decodes.
        let ok = IdentityPayload {
            algo: 0,
            public_key: vec![1u8; 32],
            nonce: vec![2u8; 16],
            node_id: [3u8; 32],
            mlkem_pubkey: None,
        };
        assert!(IdentityPayload::decode(&ok.encode()).is_ok());
    }

    #[test]
    fn key_agreement_decode_rejects_oversized_sig() {
        let big_sig = KeyAgreementPayload {
            algo: 0,
            ephemeral_pubkey: vec![1u8; 32],
            ephemeral_sig: vec![2u8; crate::budget::MAX_SIGNATURE_PUBKEY_BYTES + 1],
        };
        assert!(KeyAgreementPayload::decode(&big_sig.encode()).is_err());
        let ok = KeyAgreementPayload {
            algo: 0,
            ephemeral_pubkey: vec![1u8; 32],
            ephemeral_sig: vec![2u8; 64],
        };
        assert!(KeyAgreementPayload::decode(&ok.encode()).is_ok());
    }

    #[test]
    fn capabilities_too_short() {
        assert!(CapabilitiesPayload::decode(&[0u8; 1]).is_err());
    }

    // ── SUPPORTS_SOVEREIGN_IDENTITY capability flag ──────────

    #[test]
    fn supports_sovereign_identity_flag_value_is_stable() {
        assert_eq!(cap_flags::SUPPORTS_SOVEREIGN_IDENTITY, 1 << 1);
        // And it must not overlap any other cap flag.
        assert_eq!(
            cap_flags::SUPPORTS_SOVEREIGN_IDENTITY & cap_flags::CAN_RELAY,
            0
        );
    }

    #[test]
    fn supports_sovereign_identity_helper_reads_bit() {
        let mut caps = CapabilitiesPayload::from_node_role(veil_types::NodeRole::Core);
        // Baseline Core caps don't set the sovereign bit — legacy default.
        assert!(!caps.supports_sovereign_identity());
        caps.flags |= cap_flags::SUPPORTS_SOVEREIGN_IDENTITY;
        assert!(caps.supports_sovereign_identity());
    }

    #[test]
    fn sovereign_identity_negotiated_requires_both_sides() {
        let mut alice = CapabilitiesPayload::from_node_role(veil_types::NodeRole::Core);
        let mut bob = alice.clone();

        // Neither set → no negotiation.
        assert!(!alice.sovereign_identity_negotiated(&bob));

        // Only one side → still no negotiation.
        alice.flags |= cap_flags::SUPPORTS_SOVEREIGN_IDENTITY;
        assert!(!alice.sovereign_identity_negotiated(&bob));
        assert!(!bob.sovereign_identity_negotiated(&alice));

        // Both set → proof-frame exchange enabled.
        bob.flags |= cap_flags::SUPPORTS_SOVEREIGN_IDENTITY;
        assert!(alice.sovereign_identity_negotiated(&bob));
        assert!(bob.sovereign_identity_negotiated(&alice));
    }

    #[test]
    fn sovereign_identity_flag_survives_encode_decode() {
        // Capabilities wire format preserves the new bit through a
        // full encode/decode round-trip.
        let mut caps = CapabilitiesPayload::from_node_role(veil_types::NodeRole::Core);
        caps.flags |= cap_flags::SUPPORTS_SOVEREIGN_IDENTITY;
        let bytes = caps.encode();
        let decoded = CapabilitiesPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, caps);
        assert!(decoded.supports_sovereign_identity());
    }

    #[test]
    fn sovereign_identity_flag_backwards_compat_with_legacy_peers() {
        // A peer that doesn't know about the new bit still produces
        // a wire payload whose decoder says `supports_sovereign_identity == false`.
        let legacy_caps = CapabilitiesPayload::from_node_role(veil_types::NodeRole::Core);
        assert!(!legacy_caps.supports_sovereign_identity());
        // And negotiating with a new peer correctly falls back to
        // the legacy flow.
        let mut new_caps = legacy_caps.clone();
        new_caps.flags |= cap_flags::SUPPORTS_SOVEREIGN_IDENTITY;
        assert!(!legacy_caps.sovereign_identity_negotiated(&new_caps));
        assert!(!new_caps.sovereign_identity_negotiated(&legacy_caps));
    }

    #[test]
    fn session_confirm_too_short() {
        assert!(SessionConfirmPayload::decode(&[0u8; 32]).is_err());
    }

    #[test]
    fn attach_too_short() {
        assert!(AttachPayload::decode(&[0u8; 5]).is_err());
    }

    #[test]
    fn mlkem_rekey_ek_roundtrip() {
        let p = MlKemRekeyEkPayload {
            encapsulation_key: [0xABu8; 1184],
        };
        let encoded = p.encode();
        assert_eq!(encoded.len(), MlKemRekeyEkPayload::WIRE_SIZE);
        let decoded = MlKemRekeyEkPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn mlkem_rekey_ek_too_short() {
        assert!(MlKemRekeyEkPayload::decode(&[0u8; 100]).is_err());
    }

    #[test]
    fn detach_roundtrip() {
        let p = DetachPayload {
            reason: detach_reason::MIGRATING,
        };
        assert_eq!(DetachPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn detach_empty_buffer_fails() {
        assert!(DetachPayload::decode(&[]).is_err());
    }

    #[test]
    fn keepalive_roundtrip() {
        let p = KeepalivePayload {
            timestamp_secs: 1_700_000_000,
        };
        assert_eq!(KeepalivePayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn sleep_advertisement_roundtrip() {
        let p = SleepAdvertisementPayload {
            node_id: [0xABu8; 32],
            expected_wake_ts: 9_999_999_999,
            issued_at_ts: 1_700_000_000,
            signature: [0x42u8; 64],
        };
        let encoded = p.encode();
        assert_eq!(encoded.len(), SleepAdvertisementPayload::WIRE_SIZE);
        assert_eq!(SleepAdvertisementPayload::decode(&encoded).unwrap(), p);
    }

    #[test]
    fn sleep_advertisement_short_buffer_fails() {
        assert!(SleepAdvertisementPayload::decode(&[0u8; 100]).is_err());
    }

    #[test]
    fn sleep_advertisement_signable_bytes_excludes_signature() {
        let p = SleepAdvertisementPayload {
            node_id: [0x01u8; 32],
            expected_wake_ts: 12345,
            issued_at_ts: 67890,
            signature: [0xFFu8; 64],
        };
        let signable = p.signable_bytes();
        assert_eq!(signable.len(), 48);
        assert_eq!(&signable[0..32], &[0x01u8; 32]);
        // Signature bytes must NOT appear in the signable prefix.
        assert!(!signable.windows(64).any(|w| w == [0xFFu8; 64]));
    }

    #[test]
    fn keepalive_too_short() {
        assert!(KeepalivePayload::decode(&[0u8; 4]).is_err());
    }

    // ── Vivaldi TLV ───────────────────────────────────────────────────────────

    #[test]
    fn vivaldi_tlv_encode_decode_roundtrip() {
        let attach = AttachPayload {
            role: 1,
            realm_id: 42,
            attach_epoch: 7,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        };
        let coord = (1.5_f64, -2.3_f64, 0.1_f64);
        let bytes = encode_attach_with_vivaldi(&attach, Some(coord));

        // Fixed header should still decode correctly.
        let decoded_attach = AttachPayload::decode(&bytes).unwrap();
        assert_eq!(decoded_attach, attach);

        // Vivaldi coord should round-trip.
        let decoded_vivaldi = decode_vivaldi_from_attach(&bytes).unwrap();
        let (x, y, height) = coord;
        assert!((decoded_vivaldi.0 - x).abs() < 1e-12);
        assert!((decoded_vivaldi.1 - y).abs() < 1e-12);
        assert!((decoded_vivaldi.2 - height).abs() < 1e-12);
    }

    #[test]
    fn vivaldi_tlv_absent_when_none() {
        let attach = AttachPayload {
            role: 0,
            realm_id: 0,
            attach_epoch: 0,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        };
        let bytes = encode_attach_with_vivaldi(&attach, None);
        assert_eq!(bytes.len(), AttachPayload::WIRE_SIZE);
        assert!(decode_vivaldi_from_attach(&bytes).is_none());
    }

    // ── Battery TLV ────────────────────────────────────────────────

    /// Battery level = 15% is encoded then immediately decoded back from the
    /// ATTACH TLV region — simulating "attach with battery=15% → peer knows immediately".
    #[test]
    fn battery_tlv_roundtrip_15_percent() {
        let attach = AttachPayload {
            role: 1,
            realm_id: 0,
            attach_epoch: 0,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        };
        let bytes = encode_attach_with_vivaldi_and_battery(&attach, None, Some(15));
        // Fixed header still decodes correctly.
        let decoded = AttachPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, attach);
        // Battery level is preserved.
        let level = decode_battery_from_attach(&bytes);
        assert_eq!(level, Some(15), "peer should see battery level 15%");
    }

    /// When `battery_level` is `None`, no battery TLV is written.
    #[test]
    fn battery_tlv_absent_when_none() {
        let attach = AttachPayload {
            role: 0,
            realm_id: 0,
            attach_epoch: 0,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        };
        let bytes = encode_attach_with_vivaldi_and_battery(&attach, None, None);
        assert_eq!(bytes.len(), AttachPayload::WIRE_SIZE, "no TLV appended");
        assert!(decode_battery_from_attach(&bytes).is_none());
    }

    /// Battery TLV co-exists with Vivaldi TLV; both decode independently.
    #[test]
    fn battery_and_vivaldi_tlv_coexist() {
        let attach = AttachPayload {
            role: 1,
            realm_id: 42,
            attach_epoch: 1,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        };
        let coord = (1.0_f64, 2.0_f64, 0.5_f64);
        let bytes = encode_attach_with_vivaldi_and_battery(&attach, Some(coord), Some(75));
        // Both TLVs present.
        assert!(
            decode_vivaldi_from_attach(&bytes).is_some(),
            "Vivaldi TLV missing"
        );
        let bat = decode_battery_from_attach(&bytes);
        assert_eq!(bat, Some(75), "battery TLV should report 75%");
    }

    // ── Advertised transports TLV ──────────────────

    fn sample_attach() -> AttachPayload {
        AttachPayload {
            role: 1,
            realm_id: 0,
            attach_epoch: 0,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        }
    }

    #[test]
    fn advertised_transports_tlv_roundtrip() {
        let a = sample_attach();
        let uris = vec![
            "tls://peer.example:9906".to_owned(),
            "wss://peer.example:8443/veil".to_owned(),
        ];
        let bytes = encode_attach_with_tlvs(&a, None, None, &uris);
        let decoded = decode_advertised_transports_from_attach(&bytes);
        assert_eq!(decoded, uris);
    }

    #[test]
    fn advertised_transports_tlv_empty_list_emits_no_tlv() {
        let a = sample_attach();
        let with = encode_attach_with_tlvs(&a, None, None, &[]);
        let plain = encode_attach_with_vivaldi_and_battery(&a, None, None);
        assert_eq!(
            with, plain,
            "empty transport list must produce the exact same bytes as no TLV at all"
        );
    }

    #[test]
    fn advertised_transports_tlv_coexists_with_vivaldi_and_battery() {
        let a = sample_attach();
        let coord = (1.0, 2.0, 3.0);
        let uris = vec!["tcp://127.0.0.1:9000".to_owned()];
        let bytes = encode_attach_with_tlvs(&a, Some(coord), Some(42), &uris);
        assert_eq!(decode_battery_from_attach(&bytes), Some(42));
        assert!(decode_vivaldi_from_attach(&bytes).is_some());
        assert_eq!(decode_advertised_transports_from_attach(&bytes), uris);
    }

    #[test]
    fn advertised_transports_tlv_caps_count() {
        // Over-long list must be truncated to ADVERTISED_TRANSPORTS_MAX_COUNT.
        let a = sample_attach();
        let many: Vec<String> = (0..ADVERTISED_TRANSPORTS_MAX_COUNT + 5)
            .map(|i| format!("tcp://p{i}.example:9000"))
            .collect();
        let bytes = encode_attach_with_tlvs(&a, None, None, &many);
        let decoded = decode_advertised_transports_from_attach(&bytes);
        assert_eq!(decoded.len(), ADVERTISED_TRANSPORTS_MAX_COUNT);
        assert_eq!(decoded[0], many[0]);
        assert_eq!(
            decoded[ADVERTISED_TRANSPORTS_MAX_COUNT - 1],
            many[ADVERTISED_TRANSPORTS_MAX_COUNT - 1]
        );
    }

    #[test]
    fn advertised_transports_decoder_tolerates_garbage_trailing_bytes() {
        let a = sample_attach();
        let uris = vec!["tcp://x:1".to_owned()];
        let mut bytes = encode_attach_with_tlvs(&a, None, None, &uris);
        // Append malformed TLV (length > remaining).
        bytes.extend_from_slice(&[0xFFu8, 0xFF, 0x7F, 0xFF]); // tag=0xFFFF len=32767
        // Decoder hits the malformed TLV AFTER the good one — should
        // return the good one. It scans linearly and aborts on truncated
        // but our good TLV was emitted first so it's already returned.
        let decoded = decode_advertised_transports_from_attach(&bytes);
        assert_eq!(decoded, uris);
    }

    #[test]
    fn advertised_transports_absent_returns_empty() {
        let a = sample_attach();
        let bytes = encode_attach_with_vivaldi_and_battery(&a, None, None);
        assert!(decode_advertised_transports_from_attach(&bytes).is_empty());
    }

    // ── payloads ────────────────────────────────────────────────

    #[test]
    fn handoff_init_roundtrip() {
        let p = HandoffInitPayload {
            nonce: [0xABu8; 32],
        };
        let enc = p.encode();
        assert_eq!(enc.len(), HandoffInitPayload::WIRE_SIZE);
        let dec = HandoffInitPayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn handoff_init_rejects_wrong_size() {
        // Short.
        assert!(HandoffInitPayload::decode(&[0u8; 31]).is_err());
        // Long (trailing bytes are not tolerated — fixed-size payload).
        assert!(HandoffInitPayload::decode(&[0u8; 33]).is_err());
        // Empty.
        assert!(HandoffInitPayload::decode(&[]).is_err());
    }

    #[test]
    fn handoff_ack_roundtrip_and_rejects_wrong_size() {
        let p = HandoffAckPayload {
            nonce: [0x5Au8; 32],
        };
        let enc = p.encode();
        let dec = HandoffAckPayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
        assert!(HandoffAckPayload::decode(&[0u8; 16]).is_err());
    }

    #[test]
    fn handoff_attach_roundtrip() {
        // audit cycle-6 (T1): HandoffAttach is now a 32-byte bare announce.
        let p = HandoffAttachPayload {
            session_id: [0x11u8; 32],
        };
        let enc = p.encode();
        assert_eq!(enc.len(), HandoffAttachPayload::WIRE_SIZE);
        assert_eq!(HandoffAttachPayload::WIRE_SIZE, 32);
        let dec = HandoffAttachPayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn handoff_attach_rejects_wrong_size() {
        assert!(HandoffAttachPayload::decode(&[0u8; 31]).is_err());
        assert!(HandoffAttachPayload::decode(&[0u8; 33]).is_err());
    }

    #[test]
    fn handoff_challenge_response_roundtrip() {
        // audit cycle-6 (T1): the two new warm-socket frames.
        let c = HandoffChallengePayload {
            challenge: [0x55u8; 32],
        };
        let enc = c.encode();
        assert_eq!(enc.len(), HandoffChallengePayload::WIRE_SIZE);
        assert_eq!(HandoffChallengePayload::decode(&enc).unwrap(), c);
        assert!(HandoffChallengePayload::decode(&[0u8; 31]).is_err());

        let r = HandoffResponsePayload { hmac: [0x66u8; 32] };
        let renc = r.encode();
        assert_eq!(renc.len(), HandoffResponsePayload::WIRE_SIZE);
        assert_eq!(HandoffResponsePayload::decode(&renc).unwrap(), r);
        assert!(HandoffResponsePayload::decode(&[0u8; 33]).is_err());
    }

    #[test]
    fn handoff_attach_hmac_is_key_sensitive() {
        // Same session_id + nonce but different keys → different HMACs.
        // This is the load-bearing security property: forging HandoffAttach
        // without the session's AEAD key must produce a detectably wrong HMAC.
        let session_id = [0x99u8; 32];
        let nonce = [0x77u8; 32];
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let hmac_a = HandoffAttachPayload::compute_hmac(&key_a, &session_id, &nonce);
        let hmac_b = HandoffAttachPayload::compute_hmac(&key_b, &session_id, &nonce);
        assert_ne!(hmac_a, hmac_b, "different keys must yield different HMACs");
    }

    #[test]
    fn handoff_attach_hmac_is_nonce_sensitive() {
        // Same key + session_id but different nonces → different HMACs.
        // Prevents replay of a captured HandoffAttach against a new
        // handoff round (which uses a fresh nonce).
        let key = [0x11u8; 32];
        let session_id = [0x99u8; 32];
        let nonce_a = [0x01u8; 32];
        let nonce_b = [0x02u8; 32];
        let hmac_a = HandoffAttachPayload::compute_hmac(&key, &session_id, &nonce_a);
        let hmac_b = HandoffAttachPayload::compute_hmac(&key, &session_id, &nonce_b);
        assert_ne!(
            hmac_a, hmac_b,
            "different nonces must yield different HMACs"
        );
    }

    #[test]
    fn handoff_attach_hmac_is_deterministic() {
        // Same inputs → same HMAC (required for receiver to match).
        let key = [0xA5u8; 32];
        let sid = [0x5Au8; 32];
        let n = [0x3Cu8; 32];
        assert_eq!(
            HandoffAttachPayload::compute_hmac(&key, &sid, &n),
            HandoffAttachPayload::compute_hmac(&key, &sid, &n),
        );
    }

    // ── hybrid-kex pieces ────────────────────────────

    #[test]
    fn hybrid_kex_cap_flag_disjoint_from_others() {
        // SUPPORTS_HYBRID_KEX must not collide with CAN_RELAY
        // SUPPORTS_SOVEREIGN_IDENTITY, or ANONYMITY_RELAY — otherwise
        // a peer setting one bit accidentally engages another.
        assert_eq!(cap_flags::SUPPORTS_HYBRID_KEX, 1 << 3);
        assert_eq!(cap_flags::SUPPORTS_HYBRID_KEX & cap_flags::CAN_RELAY, 0);
        assert_eq!(
            cap_flags::SUPPORTS_HYBRID_KEX & cap_flags::SUPPORTS_SOVEREIGN_IDENTITY,
            0
        );
        assert_eq!(
            cap_flags::SUPPORTS_HYBRID_KEX & cap_flags::ANONYMITY_RELAY,
            0
        );
    }

    #[test]
    fn hybrid_kex_negotiated_requires_both_sides() {
        let mut alice = CapabilitiesPayload::from_node_role(veil_types::NodeRole::Core);
        let mut bob = CapabilitiesPayload::from_node_role(veil_types::NodeRole::Core);
        assert!(!alice.hybrid_kex_negotiated(&bob));
        alice.flags |= cap_flags::SUPPORTS_HYBRID_KEX;
        assert!(!alice.hybrid_kex_negotiated(&bob));
        bob.flags |= cap_flags::SUPPORTS_HYBRID_KEX;
        assert!(alice.hybrid_kex_negotiated(&bob));
        assert!(bob.hybrid_kex_negotiated(&alice));
    }

    #[test]
    fn realtime_datagram_negotiation_requires_both_sides() {
        let mut alice = CapabilitiesPayload::from_node_role(veil_types::NodeRole::Leaf);
        let mut bob = CapabilitiesPayload::from_node_role(veil_types::NodeRole::Leaf);
        assert!(!alice.realtime_datagrams_negotiated(&bob));
        alice.flags |= cap_flags::SUPPORTS_REALTIME_DATAGRAMS;
        assert!(alice.supports_realtime_datagrams());
        assert!(!alice.realtime_datagrams_negotiated(&bob));
        bob.flags |= cap_flags::SUPPORTS_REALTIME_DATAGRAMS;
        assert!(alice.realtime_datagrams_negotiated(&bob));
        assert!(bob.realtime_datagrams_negotiated(&alice));
    }

    #[test]
    fn hybrid_kex_ct_payload_roundtrip() {
        // Typical ML-KEM-768 ciphertext is 1088 B; encode/decode
        // round-trips exactly.
        let ct = vec![0xDEu8; 1088];
        let p = HybridKexCtPayload {
            mlkem_ct: ct.clone(),
        };
        let bytes = p.encode();
        // 2-byte len + 1088-byte CT.
        assert_eq!(bytes.len(), 2 + 1088);
        let decoded = HybridKexCtPayload::decode(&bytes).unwrap();
        assert_eq!(decoded.mlkem_ct, ct);
    }

    #[test]
    fn hybrid_kex_ct_rejects_oversized_len() {
        // Declared length exceeds MAX_CT_BYTES — decode must reject
        // BEFORE allocating the underlying buffer.
        let mut bytes = Vec::with_capacity(2);
        let len = (HybridKexCtPayload::MAX_CT_BYTES + 1) as u16;
        bytes.extend_from_slice(&len.to_be_bytes());
        // No actual payload bytes — buffer is short, but the length
        // check should fire first.
        let err = HybridKexCtPayload::decode(&bytes).unwrap_err();
        assert!(
            matches!(err, ProtoError::ValueTooLarge { .. }),
            "expected ValueTooLarge, got {err:?}"
        );
    }

    #[test]
    fn hybrid_kex_ct_rejects_trailing_bytes() {
        // Buggy / malicious peer pads the frame with extra bytes
        // after the declared CT — decoder catches it.
        let ct = vec![0x42u8; 32];
        let mut bytes = HybridKexCtPayload { mlkem_ct: ct }.encode();
        bytes.extend_from_slice(&[0xFF, 0xFF]);
        let err = HybridKexCtPayload::decode(&bytes).unwrap_err();
        assert!(
            matches!(err, ProtoError::TrailingBytes { trailing: 2 }),
            "expected TrailingBytes(2), got {err:?}"
        );
    }

    // ── TransportMigrationNotify ─────────────────────────────────────

    fn test_signing_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn migration_notify_round_trip() {
        let sk = test_signing_key(0x42);
        let pubkey = sk.verifying_key().to_bytes();
        let node_id = *blake3::hash(&pubkey).as_bytes();
        let payload = sign_transport_migration_notify(
            node_id,
            1_700_000_000,
            1_699_999_900,
            "obfs4-tcp://1.2.3.4:7821".to_owned(),
            &sk,
        );
        let bytes = payload.encode();
        let decoded = TransportMigrationNotifyPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(decoded.new_transport, "obfs4-tcp://1.2.3.4:7821");
    }

    #[test]
    fn migration_notify_signed_verifies() {
        let sk = test_signing_key(0x42);
        let pubkey = sk.verifying_key().to_bytes();
        let node_id = *blake3::hash(&pubkey).as_bytes();
        let payload = sign_transport_migration_notify(
            node_id,
            1_700_000_000,
            1_699_999_900,
            "obfs4-tcp://1.2.3.4:9000".to_owned(),
            &sk,
        );
        // Verify in the replay window.
        assert!(verify_transport_migration_notify(&payload, &pubkey, 1_699_999_910).is_ok());
    }

    #[test]
    fn migration_notify_tampered_transport_rejected() {
        let sk = test_signing_key(0x42);
        let pubkey = sk.verifying_key().to_bytes();
        let node_id = *blake3::hash(&pubkey).as_bytes();
        let mut payload = sign_transport_migration_notify(
            node_id,
            1_700_000_000,
            1_699_999_900,
            "obfs4-tcp://1.2.3.4:9000".to_owned(),
            &sk,
        );
        // Attacker rewrites transport, sig is now stale.
        payload.new_transport = "obfs4-tcp://5.6.7.8:9000".to_owned();
        assert!(verify_transport_migration_notify(&payload, &pubkey, 1_699_999_910).is_err());
    }

    #[test]
    fn migration_notify_wrong_pubkey_rejected() {
        let sk_a = test_signing_key(0xAA);
        let sk_b = test_signing_key(0xBB);
        let pubkey_a = sk_a.verifying_key().to_bytes();
        let pubkey_b = sk_b.verifying_key().to_bytes();
        let node_id = *blake3::hash(&pubkey_a).as_bytes();
        let payload = sign_transport_migration_notify(
            node_id,
            1_700_000_000,
            1_699_999_900,
            "obfs4-tcp://1.2.3.4:9000".to_owned(),
            &sk_a,
        );
        // Verify against wrong pubkey fails (identity binding check).
        assert!(verify_transport_migration_notify(&payload, &pubkey_b, 1_699_999_910).is_err());
    }

    #[test]
    fn migration_notify_replay_outside_window_rejected() {
        let sk = test_signing_key(0x42);
        let pubkey = sk.verifying_key().to_bytes();
        let node_id = *blake3::hash(&pubkey).as_bytes();
        let payload = sign_transport_migration_notify(
            node_id,
            1_700_000_000,
            1_699_999_000, // issued 1000s ago — > 300s window
            "obfs4-tcp://1.2.3.4:9000".to_owned(),
            &sk,
        );
        let err = verify_transport_migration_notify(&payload, &pubkey, 1_700_000_000).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("replay"), "got: {msg}");
    }

    #[test]
    fn migration_notify_oversized_uri_rejected() {
        // Encode a payload with URI exactly MAX_TRANSPORT_URI_LEN + 1.
        let huge = "x".repeat(MAX_TRANSPORT_URI_LEN + 1);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]); // node_id
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&((huge.len() as u16).to_be_bytes()));
        bytes.extend_from_slice(huge.as_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        let err = TransportMigrationNotifyPayload::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::ValueTooLarge { .. }));
    }
}
