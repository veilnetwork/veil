//! OVL1 wire-protocol types, codecs, and on-wire constants.
//!
//! Every submodule defines one slice of the protocol: the fixed
//! [`header`], per-family message payloads, and [`codec`] that
//! serialises headers. The [`family::FrameFamily`] discriminant selects
//! which submodule's message types apply to a given frame.

/// Anycast service-address records stored in the DHT.
pub(crate) mod cursor;

pub mod anycast;
/// Application-layer message payloads (APP_HELLO, APP_DATA, etc.).
pub mod app;
/// Hard-coded protocol limits used by every decoder.
pub mod budget;
/// Frame-header encode/decode with body-size bounds.
pub mod codec;
/// Control-plane payloads (NAT probes, route probes, neighbour offers).
pub mod control;
/// Delivery-family payloads (FORWARD envelopes, mailbox fetch/put).
pub mod delivery;
/// Diagnostic (ping / trace) message payloads.
pub mod diag;
/// DHT-family payloads (STORE, FIND_NODE, FIND_VALUE, etc.).
pub mod discovery;
/// End-to-end encrypted envelope wrapping application payloads.
pub mod e2e;
/// Public-contact URI payload for QR identity sharing.
pub mod identity_contact;
/// Sovereign identity document: master + per-instance subkeys
/// revocation + freshness, stored in DHT under node_id.
pub mod identity_document;
/// In-handshake sovereign-identity proof payload.
pub mod identity_proof;
/// Per-identity instance registry.
pub mod instance_registry;
/// In-band introducer wire-frame (Epic 481.3): owner-signed vouching record
/// that lets node A attest to the validity of node B for higher-layer trust
/// signals (mass-onboarding, sponsored mailbox access, etc.).
pub mod introducer;
/// Per-instance ML-KEM key certificate.
pub mod mlkem_cert;
/// Name-to-identity claim V2.
pub mod name_claim_v2;
/// Pairing-ceremony session wire frames.
pub mod pair_session;
/// Pairing-ceremony invite + QR URI.
pub mod pairing_invite;
/// Per-instance prekey bundle for X3DH-style forward secrecy.
pub mod prekey_bundle;
/// `Recipient` + `InstanceTag` addressing types.
pub mod recipient;
// a removed `revocation_gossip` (RevocationPush + summary
// frames) — the in-band revocation flow it supported is gone; short
// `valid_until_unix` is the replacement.
/// Epidemic-broadcast payload.
pub mod epidemic;
/// `FrameFamily` plus per-family message-type enums.
pub mod family;
#[cfg(test)]
mod golden_tests;
/// The 24-byte fixed `FrameHeader`, priority constants, and `TrafficClass`.
pub mod header;
/// Local-IPC (application-side) message payloads.
pub mod ipc;
/// Inter-node mesh payloads (beacon, ack, realm-scoped broadcast).
pub mod mesh;
/// Peer Exchange (PEX) wire format — random-walk transport discovery.
pub mod pex;
/// Onion-routed relay-chain builder and per-hop processor.
pub mod relay_chain;
/// PoW-gated rendezvous wire frames + primitives (Slice 1 of the
/// PoW-Gated Rendezvous epic; see `docs/internal/PLAN_POW_GATED_RENDEZVOUS.md`).
pub mod rendezvous;
/// Routing-family payloads (route announce/withdraw, PoW, route request).
pub mod routing;
/// Base64-string serde helpers for byte-array fields shared by proto + DHT snapshots.
pub mod serde_base64;
/// Session-family handshake messages (HELLO, ATTACH, rekey, etc.).
pub mod session;
/// Centralised time-validity skew policy (5 named tiers + rationale).
pub mod time_validity;
/// Transport-hint response payload.
pub mod transport_hints;
pub use app::{
    AppClosePayload, AppDataPayload, AppOpenPayload, AppReceiptPayload, AppRtDataPayload,
    AppSendPayload, AppWindowUpdatePayload, close_reason, receipt_status,
};
pub use codec::{MAX_FRAME_BODY, decode_header, encode_header};
pub use control::{
    NatCandidate, NatProbeReplyPayload, NatProbeRequestPayload, NatRelayRequestPayload,
    NeighborOfferPayload, RouteProbePayload, RouteReplyPayload,
};
pub use delivery::{DeliveryEnvelope, DeliveryStatusPayload, ForwardPayload, delivery_status};
pub use diag::{DiagPingPayload, DiagPongPayload, DiagTraceHopPayload, DiagTraceProbePayload};
pub use discovery::{
    AnnounceAttachmentPayload, AppEndpointResponse, AttachmentResponse, DeletePayload, DhtValue,
    FindNodeResponse, FindNodeV2Payload, FindNodeV2Response, FindValuePayload, FindValueResponse,
    GatewayRef, GetAppEndpointPayload, GetAttachmentPayload, NodeContact, ResolveTransportPayload,
    ResolveTransportResponse, SignedTransportAnnouncement, StorePayload, app_endpoint_key,
    attachment_key, dht_value_kind,
};
pub use e2e::{E2E_MARKER, E2eEnvelope, META_E2E_MARKER};
pub use epidemic::EpidemicPayload;
pub use family::{
    AppMsg, ControlMsg, DeliveryMsg, DiagMsg, DiscoveryMsg, FrameFamily, LocalAppMsg, MeshMsg,
    RelayChainMsg, RoutingMsg, SessionMsg, TunnelMsg,
};
pub use header::{FLAGS_PRIORITY_MASK, FrameHeader, HEADER_SIZE, MAGIC, VERSION, priority};
pub use ipc::{
    AUTH_APP_DELIVER_DOMAIN, AppBindErrPayload, AppBindOkPayload, AppBindPayload,
    AppDeliverPayload, AppIpcHelloErrPayload, AppIpcHelloOkPayload, AppIpcHelloPayload,
    AppIpcRtSendPayload, AppIpcSendPayload, AppUnbindPayload, AuthAppDeliver, AuthDeliverFragment,
    CLIENT_MAX_VERSION, CLIENT_MIN_VERSION, CreateBootstrapInvitePayload,
    CreateBootstrapInviteResultPayload, EventPayload, IPC_PROTOCOL_VERSION, JoinBootstrapPayload,
    JoinBootstrapResultPayload, LookupRendezvousReplicasPayload,
    LookupRendezvousReplicasRespPayload, MAILBOX_AUTH_COOKIE_LEN, MAX_AUTH_DELIVER_FRAGMENTS,
    MAX_AUTH_DELIVER_MSG_BYTES, MAX_CREATE_INVITE_DETAIL_LEN, MAX_CREATE_INVITE_PASSWORD_LEN,
    MAX_CREATE_INVITE_URI_LEN, MAX_EVENT_PAYLOAD_LEN, MAX_JOIN_DETAIL_LEN, MAX_JOIN_ISSUER_PK_LEN,
    MAX_JOIN_PASSWORD_LEN, MAX_JOIN_URI_LEN, MAX_MAILBOX_BLOB_BYTES,
    MAX_MAILBOX_CAPABILITY_TOKEN_BYTES, MAX_MAILBOX_FETCH_ENTRIES, MAX_NODE_IDENTITY_PUBKEY_LEN,
    MAX_OUTBOX_BLOOM_BYTES, MAX_OUTBOX_FIND_MISSING_ENTRIES, MAX_PAIR_CEREMONY_BYTES,
    MAX_PAIR_DETAIL_LEN, MAX_PAIR_URI_LEN, MAX_PEER_TRANSPORT_LEN, MAX_PEERS_LIST_ENTRIES,
    MAX_PUSH_ENVELOPE_BYTES, MAX_RENDEZVOUS_REPLICAS, MAX_WAKE_HMAC_ENVELOPE_BYTES,
    MOBILE_BATTERY_AC_OR_UNKNOWN, MOBILE_LOW_BATTERY_THRESHOLD_DISABLED, MailboxAckPayload,
    MailboxBlobWire, MailboxFetchPayload, MailboxFetchRespPayload, MailboxPutOkPayload,
    MailboxPutPayload, MailboxPutStatus, MobileBackgroundMode, MobileStatusPayload,
    NetworkChangedPayload, NetworkKind, NodeIdentityPayload, OutboxAckPayload, OutboxEntryWire,
    OutboxFindMissingPayload, OutboxFindMissingRespPayload, OutboxPutPayload, PAIR_OOB_CODE_LEN,
    PairCeremonyFramePayload, PairCeremonyFrameResultPayload, PairCeremonyOobResultPayload,
    PairSourceCreateInvitePayload, PairSourceCreateInviteResultPayload, PairStatusResultPayload,
    PairTargetBuildConfirmPayload, PairTargetConsumeUriPayload, PeersListEntry, PeersListPayload,
    PnetStatusResultPayload, ReplicaWire, ReplyBlock, STREAM_INITIAL_WINDOW,
    SetMobileBackgroundModePayload, SetPushEnvelopePayload, SetPushEnvelopeStatus,
    SetWakeHmacEnvelopePayload, SetWakeHmacEnvelopeStatus, StreamClosePayload, StreamDataPayload,
    StreamOpenErrPayload, StreamOpenInboundPayload, StreamOpenOkPayload, StreamOpenPayload,
    StreamWindowPayload, create_invite_status, event_kind, ipc_bind_err, ipc_bind_flags,
    ipc_hello_err, ipc_send_err, join_status, pair_source_status, pair_target_status,
    peer_direction, peer_state, stream_open_err,
};
pub use mesh::{
    BROADCAST_NODE_ID, MESH_HEADER_SIZE, MeshAckPayload, MeshBeaconPayload, MeshFrame, RealmId,
    mesh_ack_status,
};
pub use routing::{
    PowAcceptPayload, PowChallengePayload, PowResponsePayload, RouteAnnounceAliasedPayload,
    RouteAnnouncePayload, RouteDiscoverOfferPayload, RouteDiscoveryPacket, RouteRequestPayload,
    RouteResponsePayload, RouteWithdrawAliasedPayload, RouteWithdrawPayload,
};
pub use session::{RekeyPayload, SessionAlias, SleepAdvertisementPayload};
use thiserror::Error;

/// Errors raised by every OVL1 decoder.
///
/// `#[non_exhaustive]`: this wire-protocol error set gains variants as the
/// protocol evolves; downstream `match`es must include a wildcard arm so
/// adding a variant is not a breaking change.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtoError {
    /// First four bytes were not the ASCII `"OVL1"` preamble.
    #[error("invalid magic: expected OVL1, got {0:?}")]
    InvalidMagic([u8; 4]),

    /// Frame's version byte does not match the compile-time `VERSION`.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),

    /// Family byte does not decode to a known `FrameFamily`.
    #[error("unknown family: {0}")]
    UnknownFamily(u8),

    /// Message-type code is not defined for its family.
    #[error("unknown msg_type {msg_type} for family {family}")]
    UnknownMsgType {
        /// Family byte taken from the frame header.
        family: u8,
        /// Message-type code that failed to decode.
        msg_type: u16,
    },

    /// Declared `body_len` exceeds the session's configured ceiling.
    #[error("frame body too large: {body_len} > {max}")]
    BodyTooLarge {
        /// The declared body length (in bytes) as read from the header.
        body_len: u32,
        /// The enforced upper bound (per-session or hard 16 MiB).
        max: u32,
    },

    /// Buffer exhausted before the decoder finished.
    #[error("buffer too short: need {need}, got {got}")]
    BufferTooShort {
        /// Minimum number of bytes the decoder needed.
        need: usize,
        /// Actual number of bytes available.
        got: usize,
    },

    /// TLV block ended in the middle of a tag/len header or value.
    #[error("TLV block truncated")]
    TlvTruncated,

    /// A TLV entry's value exceeds `u16::MAX` bytes (wire-encodable limit).
    #[error("TLV entry for tag {tag} is oversized: {len} bytes exceeds u16::MAX")]
    TlvOversize {
        /// Tag of the oversized entry.
        tag: u16,
        /// Length in bytes.
        len: usize,
    },

    /// A length/count field exceeded its protocol-defined cap.
    #[error("value too large: {value} > {max} (field: {field})")]
    ValueTooLarge {
        /// Name of the decoded field.
        field: &'static str,
        /// Raw value read from the wire.
        value: u64,
        /// Upper bound enforced for this field.
        max: u64,
    },

    /// Decoder finished successfully but unexpected bytes remained.
    #[error("trailing bytes after message: {trailing} unexpected bytes")]
    TrailingBytes {
        /// Number of bytes left over.
        trailing: usize,
    },

    /// A UTF-8 string field contained invalid bytes.
    #[error("invalid UTF-8 in string field")]
    InvalidUtf8,

    /// AEAD verification failed — wrong key or tampered ciphertext.
    #[error("AEAD decryption failed (wrong key or tampered ciphertext)")]
    DecryptionFailed,

    /// Catch-all for structural violations where a specific variant above
    /// does not cleanly fit. Added for IdentityDocument's rich
    /// set of out-of-range / unknown-tag / context-dependent errors.
    /// Message should be human-readable and include field context.
    #[error("malformed payload: {0}")]
    Malformed(String),
}

/// Read exactly `N` bytes from `buf` starting at `offset` and return them as
/// a fixed-size array. Returns `ProtoError::BufferTooShort` if not enough
/// bytes are available.
#[inline(always)]
pub(crate) fn read_array<const N: usize>(buf: &[u8], offset: usize) -> Result<[u8; N], ProtoError> {
    // Use checked_add so a malicious caller passing offset close to
    // usize::MAX (or an honest caller on a 32-bit target with a large
    // offset) cannot wrap silently and pass the get bound check
    // against a wrapped, smaller end index.
    let end = offset.checked_add(N).ok_or(ProtoError::BufferTooShort {
        need: usize::MAX,
        got: buf.len(),
    })?;
    buf.get(offset..end)
        .and_then(|s| s.try_into().ok())
        .ok_or(ProtoError::BufferTooShort {
            need: end,
            got: buf.len(),
        })
}

/// Borrow a variable-length byte slice `buf[offset..offset+len]`.
///
/// Returns `ProtoError::BufferTooShort` if the buffer is too short, or
/// `ProtoError::ValueTooLarge` if `len` exceeds `max_len` (pass `usize::MAX`
/// to skip the cap check). Use this to replace ad-hoc bounds-checks in
/// protocol decoders.
#[inline(always)]
pub(crate) fn read_slice<'a>(
    buf: &'a [u8],
    offset: usize,
    len: usize,
    max_len: usize,
    field: &'static str,
) -> Result<&'a [u8], ProtoError> {
    if len > max_len {
        return Err(ProtoError::ValueTooLarge {
            field,
            value: len as u64,
            max: max_len as u64,
        });
    }
    let end = offset.saturating_add(len);
    buf.get(offset..end).ok_or(ProtoError::BufferTooShort {
        need: end,
        got: buf.len(),
    })
}

/// Read a `u16` big-endian from `buf[offset..offset+2]`.
#[inline(always)]
pub(crate) fn read_u16_be(buf: &[u8], offset: usize) -> Result<u16, ProtoError> {
    read_array::<2>(buf, offset).map(u16::from_be_bytes)
}

/// Read a `u32` big-endian from `buf[offset..offset+4]`.
#[inline(always)]
pub(crate) fn read_u32_be(buf: &[u8], offset: usize) -> Result<u32, ProtoError> {
    read_array::<4>(buf, offset).map(u32::from_be_bytes)
}

/// Read a `u64` big-endian from `buf[offset..offset+8]`.
#[inline(always)]
pub(crate) fn read_u64_be(buf: &[u8], offset: usize) -> Result<u64, ProtoError> {
    read_array::<8>(buf, offset).map(u64::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{MAX_FRAME_BODY, decode_header, encode_header};
    use family::{FrameFamily, SessionMsg};
    use header::{FrameHeader, HEADER_SIZE};
    // ── header roundtrip ──────────────────────────────────────────────────

    #[test]
    fn header_roundtrip_minimal() {
        let hdr = FrameHeader::new(FrameFamily::Session as u8, SessionMsg::Hello as u16);
        let buf = encode_header(&hdr);
        assert_eq!(buf.len(), HEADER_SIZE);
        let decoded = decode_header(&buf).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn header_roundtrip_all_fields() {
        let hdr = FrameHeader {
            version: 1,
            family: FrameFamily::Control as u8,
            msg_type: 3,
            flags: 0xAB_CD,
            header_len: HEADER_SIZE as u16,
            body_len: 512,
            stream_id: 0x0102_0304,
            request_id: 0xDEAD_BEEF,
        };
        let decoded = decode_header(&encode_header(&hdr)).unwrap();
        assert_eq!(decoded, hdr);
    }

    // ── magic / version checks ────────────────────────────────────────────

    #[test]
    fn bad_magic_rejected() {
        let mut buf = encode_header(&FrameHeader::new(0, 0));
        buf[0] = b'X';
        let err = decode_header(&buf).unwrap_err();
        assert!(matches!(err, ProtoError::InvalidMagic(_)));
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut buf = encode_header(&FrameHeader::new(0, 0));
        buf[4] = 99;
        let err = decode_header(&buf).unwrap_err();
        assert_eq!(err, ProtoError::UnsupportedVersion(99));
    }

    // ── bounds ────────────────────────────────────────────────────────────

    #[test]
    fn body_too_large_rejected() {
        let hdr = FrameHeader {
            version: 1,
            family: 0,
            msg_type: 0,
            flags: 0,
            header_len: HEADER_SIZE as u16,
            body_len: MAX_FRAME_BODY + 1,
            stream_id: 0,
            request_id: 0,
        };
        let buf = encode_header(&hdr);
        let err = decode_header(&buf).unwrap_err();
        assert!(matches!(err, ProtoError::BodyTooLarge { .. }));
    }

    #[test]
    fn body_at_max_allowed() {
        let hdr = FrameHeader {
            version: 1,
            family: 0,
            msg_type: 0,
            flags: 0,
            header_len: HEADER_SIZE as u16,
            body_len: MAX_FRAME_BODY,
            stream_id: 0,
            request_id: 0,
        };
        assert!(decode_header(&encode_header(&hdr)).is_ok());
    }

    #[test]
    fn buffer_too_short_rejected() {
        let buf = [0u8; 10];
        let err = decode_header(&buf).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::BufferTooShort { need: 24, got: 10 }
        ));
    }

    // ── TLV roundtrip ─────────────────────────────────────────────────────

    // ── family TryFrom ────────────────────────────────────────────────────

    #[test]
    fn family_try_from_valid() {
        assert_eq!(FrameFamily::try_from(0).unwrap(), FrameFamily::Session);
        assert_eq!(FrameFamily::try_from(4).unwrap(), FrameFamily::App);
    }

    #[test]
    fn family_try_from_unknown() {
        assert!(matches!(
            FrameFamily::try_from(99),
            Err(ProtoError::UnknownFamily(99))
        ));
    }

    #[test]
    fn session_msg_try_from_valid() {
        assert_eq!(SessionMsg::try_from(0).unwrap(), SessionMsg::Hello);
        assert_eq!(SessionMsg::try_from(5).unwrap(), SessionMsg::Attach);
    }

    #[test]
    fn session_msg_try_from_unknown() {
        assert!(matches!(
            SessionMsg::try_from(99),
            Err(ProtoError::UnknownMsgType {
                family: 0,
                msg_type: 99
            })
        ));
    }
}
