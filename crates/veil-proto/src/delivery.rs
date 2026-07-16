//! Delivery-plane payload structs for the OVL1 binary protocol.
//!
//! Each struct corresponds to one `DeliveryMsg` variant and is encoded as the
//! frame body (bytes following the fixed `FrameHeader`). Encoding is manual
//! big-endian byte packing — no external serde dependency.
//!
//! # Messages
//!
//! | Struct | `DeliveryMsg` variant |
//! |-------------------------|-------------------------|
//! | `ForwardPayload` | `Forward` |
//! | `DeliveryStatusPayload` | `DeliveryStatus` |

use super::ProtoError;

// ── Limits ────────────────────────────────────────────────────────────────────

/// Maximum allowed payload size inside a `DeliveryEnvelope` (1 MiB).
///
/// Prevents a malicious peer from causing OOM by embedding a giant payload.
/// Payloads larger than this are rejected at decode time.
pub const MAX_ENVELOPE_PAYLOAD: usize = 1024 * 1024;

/// Sender-side threshold above which an envelope is split into relay-
/// preserving chunk envelopes even though it would still FIT in a single
/// [`MAX_ENVELOPE_PAYLOAD`] frame. A session stream serializes each frame
/// contiguously, so one near-1-MiB Forward occupies the wire for ~a second
/// on a 5-10 Mbps relay/mobile uplink and everything queued behind it —
/// including live call media — eats that as head-of-line delay. 64 KiB
/// chunks match `MAX_CHUNK_PAYLOAD` and keep the worst-case occupancy in
/// the tens of milliseconds. Receive-side validation is unchanged: the
/// chunked path has been the production wire form for large payloads all
/// along, this only lowers when the sender reaches for it.
pub const ENVELOPE_CHUNKING_THRESHOLD: usize = 64 * 1024;

/// Maximum TTL a peer may claim for a `DeliveryEnvelope` (7 days in seconds).
///
/// Clamped on decode so that a peer cannot keep messages in relays/mailboxes
/// indefinitely.
pub const MAX_TTL_SECS: u32 = 7 * 24 * 3600; // 604 800

/// Wire flag embedded in the high bit of the `ttl_secs` u32 field.
///
/// When set the originating node requests an end-to-end delivery acknowledgement
/// (`DeliveryStatus(DELIVERED)`) from the final recipient. Old nodes that do
/// not understand this flag will decode `ttl_secs` as a large value and clamp it
/// to `MAX_TTL_SECS` (backward-compatible — the message is still routed).
///
/// New nodes strip this bit before applying the TTL:
/// ```text
/// require_ack = wire_ttl & DELIVERY_FLAG_REQUIRE_ACK!= 0
/// ttl_secs = (wire_ttl &!DELIVERY_FLAG_REQUIRE_ACK).min(MAX_TTL_SECS)
/// ```
pub const DELIVERY_FLAG_REQUIRE_ACK: u32 = 0x8000_0000;

// ── DeliveryEnvelope wire-offset constants ────────────────────────────────────
//
// the recipient field is now the
// fixed-49-byte `Recipient::encode_fixed_into` form (node_id +
// tag byte + 16-byte instance_id, padded with zeros for `Any`/`All`).
// Every offset below shifted by +17 from the pre-3b-wire layout.

/// Byte offset of `endpoint_id` inside `DeliveryEnvelope` wire encoding.
pub const OFFSET_ENDPOINT_ID: usize = 145;
/// Byte offset of `content_id` inside `DeliveryEnvelope` wire encoding.
pub const OFFSET_CONTENT_ID: usize = 149;
/// Byte offset of `created_at` inside `DeliveryEnvelope` wire encoding.
pub const OFFSET_CREATED_AT: usize = 181;
/// Byte offset of `ttl_secs` inside `DeliveryEnvelope` wire encoding.
pub const OFFSET_TTL_SECS: usize = 189;
/// Byte offset of `payload_len` inside `DeliveryEnvelope` wire encoding.
pub const OFFSET_PAYLOAD_LEN: usize = 193;
/// Byte offset where the variable `payload` begins.
pub const OFFSET_PAYLOAD: usize = 197;

// ── DeliveryEnvelope ──────────────────────────────────────────────────────────

/// An encrypted delivery envelope that travels from sender to recipient.
///
/// `sender_node_id` is set once by the originating node and preserved
/// unchanged through every relay hop so that the final recipient always
/// knows who the real sender is, regardless of the relay chain length.
///
/// Wire layout (fixed header = 197 bytes):
/// ```text
/// [0..49] recipient Recipient (32 node_id + 1 tag + 16 instance_id, zero-padded for Any/All)
/// [49..81] sender_node_id [u8; 32]
/// [81..113] src_app_id [u8; 32]
/// [113..145] app_id [u8; 32] (destination)
/// [145..149] endpoint_id u32 BE (destination)
/// [149..181] content_id [u8; 32]
/// [181..189] created_at u64 BE (Unix timestamp, secs)
/// [189..193] ttl_secs u32 BE (high bit = DELIVERY_FLAG_REQUIRE_ACK)
/// [193..197] payload_len u32 BE
/// [197..197+plen] payload bytes
/// ```
///
/// `trace_id` and `require_ack` are decoded from the wire but do not change
/// the fixed header size. `trace_id` travels in the `ForwardPayload` wrapper
///`require_ack` is encoded in the high bit of `ttl_secs`.
/// Old nodes that do not know about `require_ack` clamp the oversized TTL to
/// `MAX_TTL_SECS` and route the message normally (backward-compatible).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryEnvelope {
    /// Final recipient as a [`Recipient`] addressing value.
    ///
    /// Carries `node_id` + `InstanceTag`. The current wire format
    /// transmits only the 32-byte node_id portion — decoders set
    /// `instance_tag` [`InstanceTag::Any`] on the receive side.
    /// Callers wishing to fan out or target a specific instance use
    /// the dispatcher-layer API; the on-wire evolution
    /// that natively carries `InstanceTag` is of 462.15.
    ///
    /// [`Recipient`]: crate::recipient::Recipient
    /// [`InstanceTag::Any`]: crate::recipient::InstanceTag::Any
    pub recipient: crate::recipient::Recipient,
    /// Node-id of the original sender. Set by the source node and never
    /// modified by relay hops. Used by the recipient to reply correctly.
    pub sender_node_id: [u8; 32],
    /// App-id of the original sender. Allows the recipient to reply to the
    /// correct endpoint even when the sender uses an ephemeral app_id.
    pub src_app_id: [u8; 32],
    /// Destination app's `app_id`.
    pub app_id: [u8; 32],
    /// Destination endpoint on the target app.
    pub endpoint_id: u32,
    /// Content-addressed identifier used for dedup and ack correlation.
    pub content_id: [u8; 32],
    /// Creation Unix timestamp (seconds).
    pub created_at: u64,
    /// Time-to-live in seconds after `created_at` (clamped to `MAX_TTL_SECS`).
    pub ttl_secs: u32,
    /// Encrypted payload bytes.
    pub payload: Vec<u8>,
    /// Optional distributed trace identifier.
    ///
    /// Non-zero means this frame is sampled; relay hops log their participation
    /// and forward the `trace_id` unchanged so the full path can be assembled.
    /// 0 = not traced (default; also what old nodes without this field produce).
    pub trace_id: u64,
    /// Request an end-to-end delivery acknowledgement (at-least-).
    ///
    /// When `true` the final recipient sends back a `DeliveryStatus(DELIVERED)`
    /// frame addressed to `sender_node_id`. The sender retransmits the envelope
    /// with the same terminal `content_id` and an incremented Forward
    /// `delivery_attempt` until it receives the ACK or exhausts attempts.
    ///
    /// Encoded as `DELIVERY_FLAG_REQUIRE_ACK` in the high bit of the wire
    /// `ttl_secs` field — backward-compatible with older nodes that don't know
    /// this flag.
    pub require_ack: bool,
}

impl DeliveryEnvelope {
    /// Size of the fixed-width wire header (before the variable payload).
    pub const FIXED_SIZE: usize =
        crate::recipient::RECIPIENT_FIXED_SIZE + 32 + 32 + 32 + 4 + 32 + 8 + 4 + 4; // 49 + 148 = 197

    /// — convenience accessor for the recipient's
    /// `node_id` bytes. Equivalent to `self.recipient.node_id`.
    pub fn recipient_node_id(&self) -> [u8; 32] {
        self.recipient.node_id
    }

    /// — the sender as an node_id-shaped value.
    ///
    /// Once (handshake refactor) lands, `sender_node_id`
    /// will be formally typed as `node_id: [u8; 32]`. This
    /// accessor documents that intent today without changing the
    /// struct layout.
    pub fn sender_node_id(&self) -> [u8; 32] {
        self.sender_node_id
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::FIXED_SIZE + self.payload.len());
        // emit the fixed-49-byte recipient
        // form (node_id + tag byte + 16-byte instance_id
        // zero-padded for Any/All) so peers can natively request
        // `InstanceTag::All` fan-out or `::Specific` targeting
        // over the wire.
        self.recipient.encode_fixed_into(&mut buf);
        buf.extend_from_slice(&self.sender_node_id);
        buf.extend_from_slice(&self.src_app_id);
        buf.extend_from_slice(&self.app_id);
        buf.extend_from_slice(&self.endpoint_id.to_be_bytes());
        buf.extend_from_slice(&self.content_id);
        buf.extend_from_slice(&self.created_at.to_be_bytes());
        // Encode DELIVERY_FLAG_REQUIRE_ACK in the high bit of ttl_secs.
        let ttl_wire = self.ttl_secs
            | if self.require_ack {
                DELIVERY_FLAG_REQUIRE_ACK
            } else {
                0
            };
        buf.extend_from_slice(&ttl_wire.to_be_bytes());
        debug_assert!(
            self.payload.len() <= crate::codec::MAX_FRAME_BODY as usize,
            "payload exceeds MAX_FRAME_BODY"
        );
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse from wire bytes. Returns the decoded envelope and the number of
    /// bytes consumed (so callers can chain multiple envelopes).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ProtoError> {
        if buf.len() < Self::FIXED_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::FIXED_SIZE,
                got: buf.len(),
            });
        }
        // consume the fixed-49-byte
        // recipient encoding; non-zero padding on Any/All is a
        // protocol violation.
        let mut pos = 0usize;
        let recipient = crate::recipient::Recipient::decode_fixed_from(buf, &mut pos)?;
        let sender_node_id: [u8; 32] = super::read_array::<32>(buf, pos)?;
        let src_app_id: [u8; 32] = super::read_array::<32>(buf, pos + 32)?;
        let app_id: [u8; 32] = super::read_array::<32>(buf, pos + 64)?;
        let endpoint_id = super::read_u32_be(buf, OFFSET_ENDPOINT_ID)?;
        let content_id: [u8; 32] = super::read_array::<32>(buf, OFFSET_CONTENT_ID)?;
        let created_at = super::read_u64_be(buf, OFFSET_CREATED_AT)?;
        // Decode flags from high bits then clamp TTL.
        let ttl_wire = super::read_u32_be(buf, OFFSET_TTL_SECS)?;
        let require_ack = ttl_wire & DELIVERY_FLAG_REQUIRE_ACK != 0;
        let ttl_secs = (ttl_wire & !DELIVERY_FLAG_REQUIRE_ACK).min(MAX_TTL_SECS);
        let payload_len = super::read_u32_be(buf, OFFSET_PAYLOAD_LEN)? as usize;
        // Guard: reject oversized payloads before any allocation.
        if payload_len > MAX_ENVELOPE_PAYLOAD {
            return Err(ProtoError::ValueTooLarge {
                field: "payload_len",
                value: payload_len as u64,
                max: MAX_ENVELOPE_PAYLOAD as u64,
            });
        }
        // checked_add: payload_len is bounded to MAX_ENVELOPE_PAYLOAD above so
        // overflow is currently impossible, but use the same defensive pattern
        // as app.rs / e2e.rs so a future cap bump (or 32-bit target) can't wrap.
        let end = OFFSET_PAYLOAD
            .checked_add(payload_len)
            .ok_or(ProtoError::BufferTooShort {
                need: usize::MAX,
                got: buf.len(),
            })?;
        if buf.len() < end {
            return Err(ProtoError::BufferTooShort {
                need: end,
                got: buf.len(),
            });
        }
        let payload = buf[OFFSET_PAYLOAD..end].to_vec();
        // trace_id is transport-level (carried in ForwardPayload, not in the envelope wire format).
        Ok((
            Self {
                recipient,
                sender_node_id,
                src_app_id,
                app_id,
                endpoint_id,
                content_id,
                created_at,
                ttl_secs,
                payload,
                trace_id: 0,
                require_ack,
            },
            end,
        ))
    }
}

// ── ForwardPayload ────────────────────────────────────────────────────────────

/// Optional extension marker preceding a delivery-attempt ordinal in a
/// [`ForwardPayload`]. Legacy decoders ignore bytes after `relay_hops`; new
/// relays preserve this two-byte suffix and use `(content_id, attempt)` for
/// relay-loop dedup while terminal delivery still keys on `content_id` alone.
pub const FORWARD_DELIVERY_ATTEMPT_MARKER: u8 = 0xA7;

/// Optional extension marker preceding the originator's traffic class in a
/// [`ForwardPayload`]. Same backward-compatible tail contract as the
/// delivery-attempt marker: legacy decoders ignore bytes after `relay_hops`.
/// Without it a relay has no way to tell a real-time media datagram from
/// bulk delivery chatter — the frame header's 2-bit priority field is unset
/// (0 = REALTIME) by every legacy sender, so it cannot be trusted — and
/// relays used to re-queue everything at one class, adding seconds of queue
/// delay to live call media on a busy hop.
pub const FORWARD_TRAFFIC_CLASS_MARKER: u8 = 0xA8;

/// A REALTIME class hint is honored by relays only for payloads at or below
/// this size. Real-time media datagrams are small (one RTP/RTCP packet plus
/// E2E envelope overhead); anything larger claiming REALTIME is demoted to
/// INTERACTIVE so bulk transfers cannot jump the media lane.
pub const FORWARD_REALTIME_MAX_PAYLOAD: usize = 8192;

/// Request to forward an envelope to the next hop.
///
/// Wire layout:
/// ```text
/// [0..32] next_hop_node_id [u8; 32]
/// [32..] DeliveryEnvelope (self-framed)
/// [end..+8] trace_id u64 BE
/// [end+8..+1] relay_hops u8
/// [end+9] optional 0xA7 extension marker
/// [end+10] optional delivery_attempt u8 (1..=MAX_DELIVERY_ATTEMPTS)
/// [then] optional 0xA8 extension marker
/// [then+1] optional traffic_class u8 (header::priority constant)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardPayload {
    /// The immediate next hop this frame should be delivered to.
    pub next_hop_node_id: [u8; 32],
    /// Wrapped envelope — relay hops forward this intact.
    pub envelope: DeliveryEnvelope,
    /// Number of relay hops this frame has already traversed.
    ///
    /// Set to `0` by the originating node; incremented by each relay. A relay
    /// node drops the frame (returns `Violation`) when this reaches
    /// [`crate::budget::MAX_RELAY_HOPS`].
    pub relay_hops: u8,
    /// End-to-end acknowledged-delivery attempt ordinal. `None` is the legacy
    /// wire form. Relays validate the bounded range and deduplicate each
    /// attempt separately; the final recipient deliberately ignores it.
    pub delivery_attempt: Option<u8>,
    /// Originator's queueing-class hint ([`crate::header::priority`]).
    /// `None` is the legacy wire form and queues as INTERACTIVE. Relays
    /// preserve the marker when re-encoding and apply
    /// [`Self::relay_traffic_class`], never the raw value.
    pub traffic_class: Option<u8>,
}

impl ForwardPayload {
    /// Encode to wire bytes. Always appends `trace_id` (8 bytes) and
    /// `relay_hops` (1 byte) after the envelope.
    pub fn encode(&self) -> Vec<u8> {
        let env_bytes = self.envelope.encode();
        let mut buf = Vec::with_capacity(
            32 + env_bytes.len()
                + 8
                + 1
                + usize::from(self.delivery_attempt.is_some()) * 2
                + usize::from(self.traffic_class.is_some()) * 2,
        );
        buf.extend_from_slice(&self.next_hop_node_id);
        buf.extend_from_slice(&env_bytes);
        buf.extend_from_slice(&self.envelope.trace_id.to_be_bytes());
        buf.push(self.relay_hops);
        if let Some(attempt) = self.delivery_attempt {
            buf.push(FORWARD_DELIVERY_ATTEMPT_MARKER);
            buf.push(attempt);
        }
        if let Some(tc) = self.traffic_class {
            buf.push(FORWARD_TRAFFIC_CLASS_MARKER);
            buf.push(tc);
        }
        buf
    }

    /// Parse from wire bytes. Requires the fixed `trace_id || relay_hops`
    /// suffix after the envelope; the optional marker pairs may follow in any
    /// order (each at most once — an unknown or repeated marker ends parsing,
    /// mirroring the legacy ignore-the-tail contract).
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < 32 {
            return Err(ProtoError::BufferTooShort {
                need: 32,
                got: buf.len(),
            });
        }
        let next_hop_node_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let (mut envelope, env_consumed) = DeliveryEnvelope::decode(&buf[32..])?;
        let after_env = 32 + env_consumed;
        let need = after_env + 8 + 1;
        if buf.len() < need {
            return Err(ProtoError::BufferTooShort {
                need,
                got: buf.len(),
            });
        }
        envelope.trace_id = super::read_u64_be(buf, after_env)?;
        let relay_hops = buf[after_env + 8];
        let mut cursor = need;
        let mut delivery_attempt = None;
        let mut traffic_class = None;
        while let Some(&marker) = buf.get(cursor) {
            match marker {
                FORWARD_DELIVERY_ATTEMPT_MARKER if delivery_attempt.is_none() => {
                    delivery_attempt = buf.get(cursor + 1).copied();
                    cursor += 2;
                }
                FORWARD_TRAFFIC_CLASS_MARKER if traffic_class.is_none() => {
                    traffic_class = buf.get(cursor + 1).copied();
                    cursor += 2;
                }
                _ => break,
            }
        }
        Ok(Self {
            next_hop_node_id,
            envelope,
            relay_hops,
            delivery_attempt,
            traffic_class,
        })
    }

    /// Queueing class a relay should apply to this forward. A REALTIME hint
    /// is honored only for small payloads ([`FORWARD_REALTIME_MAX_PAYLOAD`])
    /// so bulk transfers cannot jump the media lane; an explicit BULK hint is
    /// respected; everything else — including legacy frames without the
    /// marker and out-of-range values — rides INTERACTIVE.
    pub fn relay_traffic_class(&self) -> u8 {
        use crate::header::priority;
        match self.traffic_class {
            Some(p)
                if p == priority::REALTIME
                    && self.envelope.payload.len() <= FORWARD_REALTIME_MAX_PAYLOAD =>
            {
                p
            }
            Some(p) if p == priority::BULK => p,
            _ => priority::INTERACTIVE,
        }
    }
}

// ── DeliveryStatusPayload ─────────────────────────────────────────────────────

/// Status codes for `DeliveryStatusPayload`.
///
/// These codes are used both in the veil-level `DeliveryStatus` frames
/// (peer → peer) and in the IPC-level `DeliveryStage` notifications
/// (node → local app). They map directly to the 5-stage E2E receipt FSM
///Accepted → Stored → Fetched → Delivered → AppAcked.
pub mod delivery_status {
    /// Gateway accepted the envelope into the delivery pipeline.
    pub const ACCEPTED: u8 = 0;
    /// Final recipient delivered the payload to the local application layer.
    pub const DELIVERED: u8 = 1;
    /// Mailbox stored the envelope durably (replica quorum acknowledged).
    pub const QUEUED: u8 = 2;
    /// No mailbox entry found for this content_id.
    pub const NOT_FOUND: u8 = 3;
    /// Delivery explicitly rejected (quota, policy, auth).
    pub const REJECTED: u8 = 4;
    /// Envelope expired before it could be delivered.
    pub const EXPIRED: u8 = 5;
    /// Mailbox sent the envelope to the recipient (fetched from storage).
    pub const FETCHED: u8 = 6;
    /// Recipient application explicitly acknowledged the delivery via IPC.
    pub const APP_ACKED: u8 = 7;
}

/// Delivery status report (transport or logical acknowledgment).
///
/// Wire layout:
/// ```text
/// [0..32]  content_id [u8; 32]
/// [32]     status u8
/// [33..65] mac [u8; 32]   (C-09)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryStatusPayload {
    /// Content id the status applies to.
    pub content_id: [u8; 32],
    /// One of [`delivery_status`] codes.
    pub status: u8,
    /// **C-09** — BLAKE3 keyed-MAC of `content_id` under the per-message
    /// delivery-ACK key (derived from the E2E ML-KEM shared secret, see
    /// `veil_e2e::derive_ack_key`). Proves the DELIVERED ACK came from the
    /// actual recipient, not an on-path relay (a relay never learns the shared
    /// secret). All-zero when no ACK key was established (non-E2E / legacy):
    /// the originator then clears the pending entry but credits NO reputation.
    pub mac: [u8; 32],
}

impl DeliveryStatusPayload {
    /// Fixed wire size.
    pub const WIRE_SIZE: usize = 32 + 1 + 32;

    /// Encode to the fixed 65-byte layout.
    pub fn encode(&self) -> [u8; Self::WIRE_SIZE] {
        let mut buf = [0u8; Self::WIRE_SIZE];
        buf[0..32].copy_from_slice(&self.content_id);
        buf[32] = self.status;
        buf[33..65].copy_from_slice(&self.mac);
        buf
    }

    /// Parse from a 65-byte buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::WIRE_SIZE,
                got: buf.len(),
            });
        }
        let content_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let status = buf[32];
        let mac: [u8; 32] = super::read_array::<32>(buf, 33)?;
        Ok(Self {
            content_id,
            status,
            mac,
        })
    }
}

// ── Large payload chunking ─────────────────────────────────────────

/// Identifies an in-progress chunked transfer (random 16-byte nonce).
///
/// Assigned by the sender when fragmenting a large payload; all chunks and the
/// manifest of the same transfer share this ID.
pub type TransferId = [u8; 16];

// (Obsolete `IS_CHUNK_FLAG` / `ChunkManifestPayload` / `ChunkPayload` — the old
// direct-chunk frame types — were removed with the orphaned `veil-transfer`
// crate after H-B replaced them with `ChunkedEnvelopePayload` below.)

// ── ChunkedEnvelopePayload (relay-preserving large-payload chunking) ──
//
// Unlike the obsolete direct-chunk frames (removed with `veil-transfer`), which
// rode `DeliveryMsg::ChunkManifest`/`Chunk` straight to a peer we have a session
// with, a `ChunkedEnvelopePayload` is the *body of an ordinary
// `DeliveryEnvelope`*: the sender splits an oversized envelope payload into N
// pieces, wraps each piece in this header, and ships each as a normal
// `DeliveryMsg::Forward` envelope. Every chunk therefore relays hop-by-hop over
// the proven Forward path (TTL, dedup, route-cache failover all reused), and
// the destination reassembles the pieces back into the original envelope
// payload before running the standard E2E-decrypt + addressed-delivery + ACK
// terminal path — preserving `app_id`/`endpoint_id`/E2E/ACK semantics that the
// old `broadcast_epidemic` reassembly discarded.

/// Leading marker byte of a chunk-carrying `DeliveryEnvelope` payload. Distinct
/// from `E2E_MARKER` (0xE2) and `META_E2E_MARKER` (0xE3) so the terminal
/// delivery path can tell a chunk wrapper apart from a (meta-)E2E payload.
pub const CHUNKED_ENVELOPE_MARKER: u8 = 0xE4;

/// `flags` bit: the *original* (reassembled) message requested a delivery ACK.
/// Carried per-chunk so the destination can ACK once after reassembly. The
/// per-chunk envelopes themselves never set `DeliveryEnvelope::require_ack`
/// (they are not individually acked).
pub const CHUNKED_ENVELOPE_FLAG_REQUIRE_ACK: u8 = 0x01;

/// One chunk of an oversized `DeliveryEnvelope`, carried inside the payload of a
/// normal relayable envelope.
///
/// Wire layout (header = 62 bytes, then chunk data):
/// ```text
/// [0]      marker = CHUNKED_ENVELOPE_MARKER (0xE4)
/// [1..17]  transfer_id [u8; 16]
/// [17..21] chunk_index u32 BE (0-based)
/// [21..25] chunk_count u32 BE (1..=MAX_TRANSFER_CHUNKS)
/// [25..29] total_size u32 BE (reassembled payload bytes, ≤ MAX_REASSEMBLY_BYTES)
/// [29..61] orig_content_id [u8; 32] (content_id of the WHOLE message, for ACK + terminal dedup)
/// [61]     flags u8 (bit0 = original require_ack)
/// [62..]   data (this chunk's slice of the original payload, ≤ MAX_CHUNK_PAYLOAD)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkedEnvelopePayload {
    /// Transfer id shared by every chunk of one logical message.
    pub transfer_id: TransferId,
    /// Zero-based index of this chunk.
    pub chunk_index: u32,
    /// Total number of chunks in the transfer.
    pub chunk_count: u32,
    /// Total reassembled payload size in bytes.
    pub total_size: u32,
    /// content_id of the whole (reassembled) message — used for the ACK and the
    /// terminal replay-dedup, distinct from each chunk envelope's own content_id.
    pub orig_content_id: [u8; 32],
    /// `true` iff the original message set `require_ack`.
    pub require_ack: bool,
    /// This chunk's payload slice.
    pub data: Vec<u8>,
}

impl ChunkedEnvelopePayload {
    /// Size of the fixed-width header (before `data`).
    pub const HEADER_SIZE: usize = 1 + 16 + 4 + 4 + 4 + 32 + 1; // 62

    /// Encode to wire bytes (marker-prefixed).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.data.len());
        buf.push(CHUNKED_ENVELOPE_MARKER);
        buf.extend_from_slice(&self.transfer_id);
        buf.extend_from_slice(&self.chunk_index.to_be_bytes());
        buf.extend_from_slice(&self.chunk_count.to_be_bytes());
        buf.extend_from_slice(&self.total_size.to_be_bytes());
        buf.extend_from_slice(&self.orig_content_id);
        buf.push(if self.require_ack {
            CHUNKED_ENVELOPE_FLAG_REQUIRE_ACK
        } else {
            0
        });
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Parse from wire bytes. Validates the marker and the structural bounds
    /// (`chunk_count` in `1..=MAX_TRANSFER_CHUNKS`, `chunk_index < chunk_count`,
    /// `total_size ≤ MAX_REASSEMBLY_BYTES`, `data ≤ MAX_CHUNK_PAYLOAD`) so a
    /// malformed or non-chunk payload is rejected before reassembly.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        if buf[0] != CHUNKED_ENVELOPE_MARKER {
            return Err(ProtoError::Malformed(
                "not a chunked-envelope payload".into(),
            ));
        }
        let chunk_index = u32::from_be_bytes([buf[17], buf[18], buf[19], buf[20]]);
        let chunk_count = u32::from_be_bytes([buf[21], buf[22], buf[23], buf[24]]);
        let total_size = u32::from_be_bytes([buf[25], buf[26], buf[27], buf[28]]);
        if chunk_count == 0 || chunk_count > super::budget::MAX_TRANSFER_CHUNKS {
            return Err(ProtoError::Malformed("chunk_count out of range".into()));
        }
        if chunk_index >= chunk_count {
            return Err(ProtoError::Malformed("chunk_index >= chunk_count".into()));
        }
        if total_size as usize > super::budget::MAX_REASSEMBLY_BYTES {
            return Err(ProtoError::Malformed(
                "total_size exceeds reassembly cap".into(),
            ));
        }
        let data = buf[Self::HEADER_SIZE..].to_vec();
        if data.len() > super::budget::MAX_CHUNK_PAYLOAD {
            return Err(ProtoError::Malformed(
                "chunk data exceeds MAX_CHUNK_PAYLOAD".into(),
            ));
        }
        Ok(Self {
            transfer_id: super::read_array::<16>(buf, 1)?,
            chunk_index,
            chunk_count,
            total_size,
            orig_content_id: super::read_array::<32>(buf, 29)?,
            require_ack: buf[61] & CHUNKED_ENVELOPE_FLAG_REQUIRE_ACK != 0,
            data,
        })
    }
}

// ── TransitFramePayload ───────────────────────────────────────────

/// Stateless transit relay frame — lightweight header for relay forwarding
/// without per-flow session state. E2E encryption protects the payload.
///
/// Wire layout:
/// ```text
/// [0..32] dst_node_id [u8; 32] destination
/// [32..64] src_node_id [u8; 32] source (split-horizon)
/// [64] ttl u8 hop limit
/// [65..73] content_hash [u8; 8] dedup (truncated BLAKE3 of payload)
/// [73..] payload [u8] E2E-encrypted DeliveryEnvelope
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitFramePayload {
    /// Final destination `node_id`.
    pub dst_node_id: [u8; 32],
    /// Source `node_id` (used by relays for split-horizon).
    pub src_node_id: [u8; 32],
    /// Remaining hop budget.
    pub ttl: u8,
    /// 8-byte content hash used for dedup.
    pub content_hash: [u8; 8],
    /// E2E-encrypted wrapped `DeliveryEnvelope`.
    pub payload: Vec<u8>,
}

impl TransitFramePayload {
    /// Size of the fixed-width header (before `payload`).
    pub const HEADER_SIZE: usize = 32 + 32 + 1 + 8; // 73

    /// Compute the content_hash from payload bytes.
    pub fn compute_content_hash(payload: &[u8]) -> [u8; 8] {
        let hash = blake3::hash(payload);
        let mut h = [0u8; 8];
        h.copy_from_slice(&hash.as_bytes()[..8]);
        h
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.dst_node_id);
        buf.extend_from_slice(&self.src_node_id);
        buf.push(self.ttl);
        buf.extend_from_slice(&self.content_hash);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, super::ProtoError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(super::ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        Ok(Self {
            dst_node_id: super::read_array::<32>(buf, 0)?,
            src_node_id: super::read_array::<32>(buf, 32)?,
            ttl: buf[64],
            content_hash: super::read_array::<8>(buf, 65)?,
            payload: buf[Self::HEADER_SIZE..].to_vec(),
        })
    }
}

// ── RecursiveRelayPayload ─────────────────────────────────────────

/// DHT-routed relay frame — forwarded hop-by-hop through Kademlia closest
/// nodes until a node with a live session to the destination is found.
///
/// `originator_pseudonym` replaces raw `originator_id` to prevent
/// transit nodes from learning who initiated the relay. The pseudonym is
/// `BLAKE3("rr_pseudo" || real_originator_id || query_id)` — only the
/// initiator can correlate it back to their identity.
///
/// Wire layout:
/// ```text
/// [0..32] dst_node_id [u8; 32] final destination
/// [32..64] originator_pseudonym [u8; 32] privacy-preserving pseudonym
/// [64..68] query_id u32 dedup token
/// [68] hop_count u8 remaining hops (decremented each hop)
/// [69..] payload [u8] wrapped DELIVERY_FORWARD body
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveRelayPayload {
    /// Final destination `node_id`.
    pub dst_node_id: [u8; 32],
    /// Privacy-preserving pseudonym: `BLAKE3("rr_pseudo" || originator_id || query_id)`.
    /// Transit nodes use this for reverse-path caching without learning the real originator.
    pub originator_pseudonym: [u8; 32],
    /// Unique token used to dedup re-forwards.
    pub query_id: u32,
    /// Remaining hop budget — decremented by each relay.
    pub hop_count: u8,
    /// Wrapped `DELIVERY_FORWARD` body.
    pub payload: Vec<u8>,
}

impl RecursiveRelayPayload {
    /// Size of the fixed-width header (before `payload`).
    pub const HEADER_SIZE: usize = 32 + 32 + 4 + 1; // 69

    /// Compute a privacy-preserving pseudonym from the real originator_id.
    ///
    /// `pseudonym = BLAKE3("rr_pseudo" || originator_id || query_id_be)`
    pub fn make_pseudonym(originator_id: &[u8; 32], query_id: u32) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"rr_pseudo");
        h.update(originator_id);
        h.update(&query_id.to_be_bytes());
        *h.finalize().as_bytes()
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.dst_node_id);
        buf.extend_from_slice(&self.originator_pseudonym);
        buf.extend_from_slice(&self.query_id.to_be_bytes());
        buf.push(self.hop_count);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, super::ProtoError> {
        if buf.len() < Self::HEADER_SIZE {
            return Err(super::ProtoError::BufferTooShort {
                need: Self::HEADER_SIZE,
                got: buf.len(),
            });
        }
        let dst_node_id: [u8; 32] = super::read_array::<32>(buf, 0)?;
        let originator_pseudonym: [u8; 32] = super::read_array::<32>(buf, 32)?;
        let query_id = super::read_u32_be(buf, 64)?;
        let hop_count = buf[68];
        let payload = buf[69..].to_vec();
        Ok(Self {
            dst_node_id,
            originator_pseudonym,
            query_id,
            hop_count,
            payload,
        })
    }
}

// ── RelayPathPayload ──────────────────────────────────────────────────────────
//
// **Source-routed relay** (Epic 482.7-adjacent / Epic 137.5 deferred, lifted
// for audit batch 2026-05-23 as antidote to the Audit-H22 `iterative.lookup`
// strict-progress filter that blocks DHT walks in pathological linear /
// chain-of-pearls topologies).
//
// The sender picks the relay chain explicitly — every hop just looks at the
// next entry in `path` and forwards via its existing session to that node.
//
// Compared to the existing routing-plane options:
//
// * `Forward` / `DeliveryEnvelope`        — relies on receiver-side
//   `route_cache` lookup + gossip propagation; falls over when the
//   cache is empty / partition isolates the sender.
// * `RecursiveRelay`                       — walks DHT closest-nodes to
//   `dst_node_id`; fails when `iterative.lookup` filter rejects all
//   contacts on a chain where each step has the same XOR-distance.
// * `RelayPath` (this one)                 — sender names the entire
//   path up-front; no routing dependency anywhere in the network.
//   Works in **any** connected topology so long as the sender knows
//   a path (which he can obtain out-of-band, through PEX walks, or
//   construct manually for a private testbed).
//
// ## Wire layout
//
// ```text
// [0..1] hop_count u8 — total #entries in path (≤ MAX_RELAY_PATH_HOPS)
// [1..2] next_hop u8 — index of the NEXT recipient (0..hop_count); each
//                     forwarder increments this before re-sending.
// [2..2 + 32 × hop_count] path: [[u8; 32]; hop_count]
// [2 + 32 × hop_count..] inner: Vec<u8>  — body destined for
//                                          `path[hop_count - 1]`; opaque
//                                          to relays.
// ```
//
// ## Invariants
//
// * `next_hop < hop_count` while frame is in-flight (relays drop when
//   next_hop ≥ hop_count, defensive).
// * `hop_count ≤ MAX_RELAY_PATH_HOPS` (anti-amplification budget).
// * `path[next_hop]` is the recipient node-id; recipient checks
//   `path[next_hop] == local_node_id`, else drops (mis-routed).
// * `next_hop == hop_count - 1` means "I am the final destination" →
//   deliver inner locally instead of forwarding.

/// Hard ceiling on source-routed relay path length.  Sized to cover the
/// 64-node testnet diameter end-to-end in a single frame (worst case
/// node-0 → node-63 in linear topology = 63 hops); chosen as a power of
/// two for clean encoding.  The dispatcher's `MAX_RELAY_HOPS` (16) cap
/// on RecursiveRelay does NOT apply here — source routing carries the
/// full path inside the frame, so loops are impossible by construction
/// and the only resource bound is frame size (64 * 32 = 2 KiB path
/// overhead, comfortable within any link MTU).
pub const MAX_RELAY_PATH_HOPS: usize = 64;

/// Source-routed relay frame.  See module docstring for design notes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPathPayload {
    /// Ordered list of node_ids on the path.  Sender NOT included; first
    /// entry = first hop after sender; last entry = ultimate destination.
    pub path: Vec<[u8; 32]>,
    /// Index of the next hop in `path`.  Each forwarder increments before
    /// re-sending.  Receiver checks `path[next_hop] == local_node_id` to
    /// guard against mis-routing.
    pub next_hop: u8,
    /// Opaque inner payload — typically an `AppDeliverPayload`-encoded
    /// frame body destined for the path's last entry.
    pub inner: Vec<u8>,
}

impl RelayPathPayload {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let hop_count = self.path.len().min(MAX_RELAY_PATH_HOPS);
        let mut buf = Vec::with_capacity(2 + 32 * hop_count + self.inner.len());
        buf.push(hop_count as u8);
        buf.push(self.next_hop);
        for n in self.path.iter().take(MAX_RELAY_PATH_HOPS) {
            buf.extend_from_slice(n);
        }
        buf.extend_from_slice(&self.inner);
        buf
    }

    /// Parse wire bytes.  Enforces wire-cap; rejects out-of-bounds
    /// `next_hop`; rejects empty paths (no-op frames).
    pub fn decode(buf: &[u8]) -> Result<Self, super::ProtoError> {
        if buf.len() < 2 {
            return Err(super::ProtoError::BufferTooShort {
                need: 2,
                got: buf.len(),
            });
        }
        let hop_count = buf[0] as usize;
        if hop_count == 0 {
            return Err(super::ProtoError::Malformed(
                "RelayPath: hop_count == 0 (empty path)".to_string(),
            ));
        }
        if hop_count > MAX_RELAY_PATH_HOPS {
            return Err(super::ProtoError::ValueTooLarge {
                field: "RelayPath.hop_count",
                value: hop_count as u64,
                max: MAX_RELAY_PATH_HOPS as u64,
            });
        }
        let next_hop = buf[1];
        if (next_hop as usize) >= hop_count {
            return Err(super::ProtoError::Malformed(format!(
                "RelayPath: next_hop {next_hop} >= hop_count {hop_count}",
            )));
        }
        let path_end = 2 + 32 * hop_count;
        if buf.len() < path_end {
            return Err(super::ProtoError::BufferTooShort {
                need: path_end,
                got: buf.len(),
            });
        }
        let mut path = Vec::with_capacity(hop_count);
        for i in 0..hop_count {
            let off = 2 + 32 * i;
            let mut id = [0u8; 32];
            id.copy_from_slice(&buf[off..off + 32]);
            path.push(id);
        }
        let inner = buf[path_end..].to_vec();
        Ok(Self {
            path,
            next_hop,
            inner,
        })
    }

    /// `true` iff this hop is the ultimate destination (next_hop indexes
    /// the LAST entry).  Caller delivers `inner` locally instead of
    /// forwarding.
    pub fn is_terminal(&self) -> bool {
        usize::from(self.next_hop) + 1 == self.path.len()
    }

    /// The node-id the current forwarder should hand the frame off to.
    /// Returns `None` if `next_hop` is somehow out-of-range (defensive —
    /// `decode` already rejects this).
    pub fn current_recipient(&self) -> Option<&[u8; 32]> {
        self.path.get(self.next_hop as usize)
    }

    /// The node-id the NEXT forwarder will hand the frame off to.
    /// Returns `None` if caller is the terminal hop.
    pub fn next_recipient(&self) -> Option<&[u8; 32]> {
        self.path.get(usize::from(self.next_hop) + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_envelope_round_trip() {
        let p = ChunkedEnvelopePayload {
            transfer_id: [7u8; 16],
            chunk_index: 3,
            chunk_count: 10,
            total_size: 600_000,
            orig_content_id: [0xCDu8; 32],
            require_ack: true,
            data: vec![0xABu8; 1234],
        };
        let wire = p.encode();
        assert_eq!(wire[0], CHUNKED_ENVELOPE_MARKER);
        assert_eq!(wire.len(), ChunkedEnvelopePayload::HEADER_SIZE + 1234);
        let back = ChunkedEnvelopePayload::decode(&wire).expect("decode");
        assert_eq!(back, p);
    }

    #[test]
    fn chunked_envelope_rejects_bad_marker() {
        let mut wire = ChunkedEnvelopePayload {
            transfer_id: [0u8; 16],
            chunk_index: 0,
            chunk_count: 1,
            total_size: 4,
            orig_content_id: [0u8; 32],
            require_ack: false,
            data: vec![1, 2, 3, 4],
        }
        .encode();
        wire[0] = 0xE3; // META_E2E_MARKER — must NOT be mistaken for a chunk
        assert!(ChunkedEnvelopePayload::decode(&wire).is_err());
    }

    #[test]
    fn chunked_envelope_rejects_index_ge_count_and_oversize() {
        // index >= count
        let mut bad = ChunkedEnvelopePayload {
            transfer_id: [0u8; 16],
            chunk_index: 0,
            chunk_count: 2,
            total_size: 4,
            orig_content_id: [0u8; 32],
            require_ack: false,
            data: vec![1, 2, 3, 4],
        }
        .encode();
        // overwrite chunk_index (offset 17..21) to 5 (>= count 2)
        bad[17..21].copy_from_slice(&5u32.to_be_bytes());
        assert!(ChunkedEnvelopePayload::decode(&bad).is_err());

        // chunk_count over MAX_TRANSFER_CHUNKS
        let mut over = ChunkedEnvelopePayload {
            transfer_id: [0u8; 16],
            chunk_index: 0,
            chunk_count: 1,
            total_size: 4,
            orig_content_id: [0u8; 32],
            require_ack: false,
            data: vec![1, 2, 3, 4],
        }
        .encode();
        over[21..25]
            .copy_from_slice(&(super::super::budget::MAX_TRANSFER_CHUNKS + 1).to_be_bytes());
        assert!(ChunkedEnvelopePayload::decode(&over).is_err());
    }

    #[test]
    fn chunked_envelope_truncated_rejected() {
        assert!(ChunkedEnvelopePayload::decode(&[CHUNKED_ENVELOPE_MARKER; 10]).is_err());
    }

    fn sample_envelope() -> DeliveryEnvelope {
        DeliveryEnvelope {
            recipient: crate::recipient::Recipient::any([1u8; 32]),
            sender_node_id: [9u8; 32],
            src_app_id: [0u8; 32],
            app_id: [2u8; 32],
            endpoint_id: 42,
            content_id: [3u8; 32],
            created_at: 1_700_000_000,
            ttl_secs: 3600,
            payload: b"hello world".to_vec(),
            trace_id: 0,
            require_ack: false,
        }
    }

    #[test]
    fn delivery_envelope_roundtrip() {
        let env = sample_envelope();
        let encoded = env.encode();
        let (decoded, consumed) = DeliveryEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, env);
        assert_eq!(consumed, encoded.len());
    }

    /// the recipient's `InstanceTag`
    /// must survive the wire round-trip. Pre-3b-wire, the
    /// encode path discarded everything except `node_id` so
    /// `InstanceTag::All` and `::Specific(...)` decoded back as
    /// `::Any` — making fan-out / instance-targeted delivery
    /// impossible to express over the wire.
    #[test]
    fn delivery_envelope_roundtrip_preserves_instance_tag_all() {
        use crate::recipient::{InstanceTag, Recipient};
        let env = DeliveryEnvelope {
            recipient: Recipient {
                node_id: [0xAA; 32],
                instance_tag: InstanceTag::All,
            },
            ..sample_envelope()
        };
        let (decoded, _) = DeliveryEnvelope::decode(&env.encode()).unwrap();
        assert_eq!(decoded.recipient.instance_tag, InstanceTag::All);
        assert_eq!(decoded.recipient.node_id, [0xAA; 32]);
    }

    #[test]
    fn delivery_envelope_roundtrip_preserves_instance_tag_specific() {
        use crate::recipient::{InstanceTag, Recipient};
        let target_instance = [0xBB; 16];
        let env = DeliveryEnvelope {
            recipient: Recipient {
                node_id: [0xCC; 32],
                instance_tag: InstanceTag::Specific(target_instance),
            },
            ..sample_envelope()
        };
        let (decoded, _) = DeliveryEnvelope::decode(&env.encode()).unwrap();
        assert_eq!(
            decoded.recipient.instance_tag,
            InstanceTag::Specific(target_instance),
        );
        assert_eq!(decoded.recipient.node_id, [0xCC; 32]);
    }

    #[test]
    fn delivery_envelope_decode_rejects_nonzero_padding_on_any() {
        // Hand-build the wire bytes with `Any` tag but non-zero
        // bytes in the 16-byte instance_id padding region. The
        // decoder must reject — non-zero padding on Any/All
        // signals encoder bug or wire tamper, not a valid
        // `Specific` (which would carry tag = SPECIFIC).
        let env = sample_envelope();
        let mut bytes = env.encode();
        // node_id at 0..32, tag at 32, instance_id at 33..49.
        // Tag of `Any` was emitted at byte 32; flip a padding byte.
        assert_eq!(bytes[32], crate::recipient::INSTANCE_TAG_ANY);
        bytes[33] = 0xFF;
        let err = DeliveryEnvelope::decode(&bytes).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)), "{err:?}");
    }

    // ── identity accessors ──────────────────────────────────────

    #[test]
    fn delivery_envelope_recipient_field_is_any_variant() {
        use crate::recipient::InstanceTag;
        let env = sample_envelope();
        // The wire format transports only the node_id portion
        // so a freshly-decoded envelope always has InstanceTag::Any.
        assert!(
            matches!(env.recipient.instance_tag, InstanceTag::Any),
            "legacy wire format maps to InstanceTag::Any"
        );
        assert_eq!(
            env.recipient_node_id(),
            env.recipient.node_id,
            "convenience accessor returns the field"
        );
    }

    #[test]
    fn delivery_envelope_sender_node_id_matches_legacy_field() {
        let env = sample_envelope();
        assert_eq!(env.sender_node_id(), env.sender_node_id);
    }

    #[test]
    fn delivery_envelope_empty_payload() {
        let mut env = sample_envelope();
        env.payload = vec![];
        let encoded = env.encode();
        let (decoded, _) = DeliveryEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn delivery_envelope_too_short() {
        let err = DeliveryEnvelope::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    /// over-cap seqs rejected as ValueTooLarge instead of
    /// panicking in release.

    // ── instance_id trailer wire tests ───────────────────────

    #[test]
    fn forward_roundtrip() {
        let payload = ForwardPayload {
            next_hop_node_id: [9u8; 32],
            envelope: sample_envelope(),
            relay_hops: 0,
            delivery_attempt: None,
            traffic_class: None,
        };
        let encoded = payload.encode();
        let decoded = ForwardPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn forward_too_short() {
        let err = ForwardPayload::decode(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    // ── relay_hops encode/decode ────────────────────────────────────

    /// relay_hops roundtrip with a non-zero value.
    #[test]
    fn forward_relay_hops_roundtrip() {
        let payload = ForwardPayload {
            next_hop_node_id: [7u8; 32],
            envelope: sample_envelope(),
            relay_hops: 5,
            delivery_attempt: None,
            traffic_class: None,
        };
        let encoded = payload.encode();
        let decoded = ForwardPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.relay_hops, 5);
        assert_eq!(decoded, payload);
    }

    /// A truncated frame missing the trace_id/relay_hops suffix is rejected.
    #[test]
    fn forward_missing_suffix_rejected() {
        let env = sample_envelope();
        let env_bytes = env.encode();
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xAAu8; 32]);
        buf.extend_from_slice(&env_bytes);
        assert!(ForwardPayload::decode(&buf).is_err());
    }

    /// relay_hops roundtrip when trace_id is also present.
    #[test]
    fn forward_relay_hops_with_trace_id_roundtrip() {
        let mut env = sample_envelope();
        env.trace_id = 0xDEAD_BEEF_1234_5678;
        let payload = ForwardPayload {
            next_hop_node_id: [3u8; 32],
            envelope: env,
            relay_hops: 12,
            delivery_attempt: Some(2),
            traffic_class: None,
        };
        let encoded = payload.encode();
        let decoded = ForwardPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.envelope.trace_id, 0xDEAD_BEEF_1234_5678);
        assert_eq!(decoded.relay_hops, 12);
        assert_eq!(decoded.delivery_attempt, Some(2));
        assert_eq!(decoded, payload);
    }

    #[test]
    fn forward_unknown_or_truncated_extension_stays_legacy_compatible() {
        let payload = ForwardPayload {
            next_hop_node_id: [4u8; 32],
            envelope: sample_envelope(),
            relay_hops: 1,
            delivery_attempt: None,
            traffic_class: None,
        };
        let mut unknown = payload.encode();
        unknown.extend_from_slice(&[0xEE, 7, 8]);
        assert_eq!(ForwardPayload::decode(&unknown).unwrap(), payload);

        let mut truncated = payload.encode();
        truncated.push(FORWARD_DELIVERY_ATTEMPT_MARKER);
        assert_eq!(ForwardPayload::decode(&truncated).unwrap(), payload);
    }

    #[test]
    fn forward_traffic_class_roundtrip_alone_and_with_attempt() {
        let mut payload = ForwardPayload {
            next_hop_node_id: [5u8; 32],
            envelope: sample_envelope(),
            relay_hops: 1,
            delivery_attempt: None,
            traffic_class: Some(crate::header::priority::REALTIME),
        };
        let decoded = ForwardPayload::decode(&payload.encode()).unwrap();
        assert_eq!(decoded, payload);

        payload.delivery_attempt = Some(2);
        let decoded = ForwardPayload::decode(&payload.encode()).unwrap();
        assert_eq!(decoded.delivery_attempt, Some(2));
        assert_eq!(
            decoded.traffic_class,
            Some(crate::header::priority::REALTIME)
        );
        assert_eq!(decoded, payload);
    }

    #[test]
    fn forward_traffic_class_markers_decode_in_either_order() {
        let payload = ForwardPayload {
            next_hop_node_id: [6u8; 32],
            envelope: sample_envelope(),
            relay_hops: 0,
            delivery_attempt: Some(1),
            traffic_class: Some(crate::header::priority::REALTIME),
        };
        // Re-order the two marker pairs by hand: class first, attempt second.
        let canonical = payload.encode();
        let n = canonical.len();
        let mut swapped = canonical[..n - 4].to_vec();
        swapped.extend_from_slice(&canonical[n - 2..]); // class pair
        swapped.extend_from_slice(&canonical[n - 4..n - 2]); // attempt pair
        assert_eq!(ForwardPayload::decode(&swapped).unwrap(), payload);
    }

    #[test]
    fn relay_traffic_class_honors_small_realtime_and_demotes_abuse() {
        use crate::header::priority;
        let mut payload = ForwardPayload {
            next_hop_node_id: [7u8; 32],
            envelope: sample_envelope(),
            relay_hops: 0,
            delivery_attempt: None,
            traffic_class: Some(priority::REALTIME),
        };
        // Small payload + REALTIME hint → honored.
        assert!(payload.envelope.payload.len() <= FORWARD_REALTIME_MAX_PAYLOAD);
        assert_eq!(payload.relay_traffic_class(), priority::REALTIME);

        // Oversized payload claiming REALTIME → demoted to INTERACTIVE.
        payload.envelope.payload = vec![0u8; FORWARD_REALTIME_MAX_PAYLOAD + 1];
        assert_eq!(payload.relay_traffic_class(), priority::INTERACTIVE);

        // Explicit BULK is respected; junk and legacy ride INTERACTIVE.
        payload.traffic_class = Some(priority::BULK);
        assert_eq!(payload.relay_traffic_class(), priority::BULK);
        payload.traffic_class = Some(0xFF);
        assert_eq!(payload.relay_traffic_class(), priority::INTERACTIVE);
        payload.traffic_class = None;
        assert_eq!(payload.relay_traffic_class(), priority::INTERACTIVE);
    }

    #[test]
    fn delivery_status_roundtrip() {
        let payload = DeliveryStatusPayload {
            content_id: [0xABu8; 32],
            status: delivery_status::DELIVERED,
            mac: [0xCDu8; 32],
        };
        let encoded = payload.encode();
        let decoded = DeliveryStatusPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn delivery_status_too_short() {
        let err = DeliveryStatusPayload::decode(&[0u8; 5]).unwrap_err();
        assert!(matches!(err, ProtoError::BufferTooShort { .. }));
    }

    // ── 90: security and correctness guards ───────────────────────

    /// 89.4: DeliveryEnvelope with payload_len > MAX_ENVELOPE_PAYLOAD is rejected.
    #[test]
    fn envelope_oversized_payload_rejected() {
        // Construct a header with payload_len = MAX_ENVELOPE_PAYLOAD + 1.
        let oversized: u32 = (MAX_ENVELOPE_PAYLOAD + 1) as u32;
        let mut buf = vec![0u8; DeliveryEnvelope::FIXED_SIZE];
        buf[OFFSET_PAYLOAD_LEN..OFFSET_PAYLOAD].copy_from_slice(&oversized.to_be_bytes());
        let err = DeliveryEnvelope::decode(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                ProtoError::ValueTooLarge {
                    field: "payload_len",
                    ..
                }
            ),
            "expected ValueTooLarge, got {err:?}",
        );
    }

    /// 89.5: ttl_secs > MAX_TTL_SECS is clamped on decode, not rejected.
    #[test]
    fn envelope_excessive_ttl_clamped() {
        let mut env = sample_envelope();
        env.ttl_secs = u32::MAX;
        let encoded = env.encode();
        let (decoded, _) = DeliveryEnvelope::decode(&encoded).unwrap();
        assert_eq!(
            decoded.ttl_secs, MAX_TTL_SECS,
            "ttl_secs must be clamped to MAX_TTL_SECS"
        );
    }

    // ── TransitFrame roundtrip ─────────────────────────────────

    #[test]
    fn transit_frame_roundtrip() {
        let tf = TransitFramePayload {
            dst_node_id: [0xAAu8; 32],
            src_node_id: [0xBBu8; 32],
            ttl: 15,
            content_hash: [0xCCu8; 8],
            payload: b"encrypted envelope data".to_vec(),
        };
        let encoded = tf.encode();
        assert!(encoded.len() >= TransitFramePayload::HEADER_SIZE);
        let decoded = TransitFramePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, tf);
    }

    #[test]
    fn transit_frame_content_hash() {
        let payload = b"hello world";
        let h = TransitFramePayload::compute_content_hash(payload);
        assert_eq!(h.len(), 8);
        // Same payload → same hash.
        assert_eq!(h, TransitFramePayload::compute_content_hash(payload));
        // Different payload → different hash.
        assert_ne!(h, TransitFramePayload::compute_content_hash(b"different"));
    }

    #[test]
    fn transit_frame_too_short() {
        assert!(TransitFramePayload::decode(&[0u8; 10]).is_err());
    }

    // ── RelayPathPayload (audit batch 2026-05-23) ─────────────────────

    fn sample_relay_path(hop_count: usize) -> RelayPathPayload {
        let mut path = Vec::with_capacity(hop_count);
        for i in 0..hop_count {
            path.push([(i + 1) as u8; 32]);
        }
        RelayPathPayload {
            path,
            next_hop: 0,
            inner: b"opaque payload".to_vec(),
        }
    }

    #[test]
    fn relay_path_roundtrip_minimal() {
        let p = sample_relay_path(1);
        let bytes = p.encode();
        assert!(bytes.len() >= 2 + 32);
        let decoded = RelayPathPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn relay_path_roundtrip_max() {
        let p = sample_relay_path(MAX_RELAY_PATH_HOPS);
        let bytes = p.encode();
        let decoded = RelayPathPayload::decode(&bytes).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn relay_path_rejects_empty() {
        let buf = [0u8, 0u8]; // hop_count = 0
        assert!(matches!(
            RelayPathPayload::decode(&buf),
            Err(crate::ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn relay_path_rejects_oversized_path() {
        let mut buf = vec![(MAX_RELAY_PATH_HOPS as u8) + 1, 0]; // hop_count > MAX
        buf.extend_from_slice(&[0u8; 32 * (MAX_RELAY_PATH_HOPS + 1)]);
        assert!(matches!(
            RelayPathPayload::decode(&buf),
            Err(crate::ProtoError::ValueTooLarge { .. })
        ));
    }

    #[test]
    fn relay_path_rejects_oob_next_hop() {
        // hop_count = 3 (valid) but next_hop = 99 (OOB).
        let mut buf = vec![3u8, 99u8];
        buf.extend_from_slice(&[0u8; 32 * 3]);
        assert!(matches!(
            RelayPathPayload::decode(&buf),
            Err(crate::ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn relay_path_rejects_truncated_path_bytes() {
        // hop_count = 4, next_hop = 0, but only 2×32 bytes of path data.
        let mut buf = vec![4u8, 0u8];
        buf.extend_from_slice(&[0u8; 32 * 2]);
        assert!(matches!(
            RelayPathPayload::decode(&buf),
            Err(crate::ProtoError::BufferTooShort { .. })
        ));
    }

    #[test]
    fn relay_path_is_terminal_and_current_recipient() {
        let mut p = sample_relay_path(3);
        // next_hop = 0 → not terminal, recipient = path[0]
        assert!(!p.is_terminal());
        assert_eq!(p.current_recipient(), Some(&p.path[0]));
        // Advance to last
        p.next_hop = 2;
        assert!(p.is_terminal());
        assert_eq!(p.current_recipient(), Some(&p.path[2]));
    }
}
