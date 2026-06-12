use super::ProtoError;

/// Top-level frame classification. The discriminant is the `family` byte
/// of the OVL1 frame header and selects which per-family `*Msg` enum
/// applies to the `msg_type` field. Each variant maps one-to-one to a
/// submodule [`crate`].
#[repr(u8)]
#[allow(missing_docs)] // Wire-protocol taxonomy: variant names mirror the submodules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameFamily {
    Session = 0,
    Control = 1,
    Discovery = 2,
    Delivery = 3,
    App = 4,
    Mesh = 5,
    LocalApp = 6,
    /// TUN/TAP virtual network interface tunnel.
    Tunnel = 7,
    /// Route discovery & announcement gossip protocol.
    Routing = 8,
    /// Diagnostic frames: ping/pong/trace.
    Diag = 9,
    /// Onion-encrypted relay chain.
    RelayChain = 10,
    /// Peer Exchange — random-walk transport discovery.
    PeerExchange = 11,
}

impl TryFrom<u8> for FrameFamily {
    type Error = ProtoError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(FrameFamily::Session),
            1 => Ok(FrameFamily::Control),
            2 => Ok(FrameFamily::Discovery),
            3 => Ok(FrameFamily::Delivery),
            4 => Ok(FrameFamily::App),
            5 => Ok(FrameFamily::Mesh),
            6 => Ok(FrameFamily::LocalApp),
            7 => Ok(FrameFamily::Tunnel),
            8 => Ok(FrameFamily::Routing),
            9 => Ok(FrameFamily::Diag),
            10 => Ok(FrameFamily::RelayChain),
            11 => Ok(FrameFamily::PeerExchange),
            _ => Err(ProtoError::UnknownFamily(v)),
        }
    }
}

/// Session family message types — handshake, keepalive, rekey, tickets
/// sleep advertisement, padding. Each variant is a wire-protocol
/// identifier; see the per-variant doc comments where the semantics are
/// non-obvious.
#[repr(u16)]
#[allow(missing_docs)] // Simple handshake step names (Hello/Identity/...) are self-documenting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMsg {
    Hello = 0,
    Identity = 1,
    Capabilities = 2,
    KeyAgreement = 3,
    SessionConfirm = 4,
    Attach = 5,
    Detach = 6,
    Keepalive = 7,
    /// Initiator begins a session rekey: carries a new ephemeral X25519 public key.
    RekeyInit = 8,
    /// Responder completes a session rekey: carries their new ephemeral X25519 public key.
    RekeyAck = 9,
    /// Sender rotates its E2E ML-KEM-768 encapsulation key: carries the new 1184-byte EK.
    /// The receiver updates its peer-EK cache and replies with `MlKemRekeyAck`.
    MlKemRekeyEk = 10,
    /// Acknowledges receipt of a `MlKemRekeyEk`; empty body.
    MlKemRekeyAck = 11,
    /// Encrypted session-resumption ticket issued by the server post-handshake.
    Ticket = 12,
    /// Pre-disconnect sleep announcement with expected wake time.
    /// Mailbox hosts extend retention for the sender until `expected_wake_ts + grace`.
    SleepAdvertisement = 13,
    /// discardable padding frame. The body is random bytes; the
    /// receiver MUST decode the header, skip `body_len` bytes, and treat the
    /// frame as a no-op. Senders emit these to coalesce real frames with
    /// padding into a single TLS record of a target MTU-aligned size, so
    /// on-path DPI cannot infer veil frame sizes from TLS record lengths.
    Padding = 14,
    /// sovereign-identity proof frame — sent between
    /// `KeyAgreement` and `SessionConfirm` by peers that hold a signed
    /// `IdentityDocument`. Body is an encoded
    /// [`IdentityProof`](super::identity_proof::IdentityProof) whose
    /// `ephemeral_x25519_pk` matches the `KeyAgreement` ephemeral_pubkey.
    /// The receiver verifies the proof with
    /// [`verify_identity_proof`](veilcore::node::identity::verify::verify_identity_proof)
    /// and caches the resulting `ValidatedIdentity` against the session.
    /// Legacy (non-sovereign) peers simply don't send this frame;
    /// receivers that don't see one fall back to the existing
    /// `KeyAgreement.ephemeral_sig` anti-MITM binding.
    IdentityProof = 15,

    // ── hot-standby transport handover ─────────────────────────────
    //
    // Three-frame handshake carried out of-band from the OVL1 handshake itself.
    // The session and all AEAD state survive the underlying transport change;
    // the peer proves ownership of the existing session's AEAD key via HMAC
    // on `HandoffAttach`, so a new bare socket can be bound to an existing
    // `SessionRunner` without re-establishing identity / PoW / kex.
    /// Sender announces intent to migrate this session onto a new transport.
    /// Payload: fresh 32-byte random `nonce`. Sent AEAD-encrypted over the
    /// primary session before the new socket is opened.
    HandoffInit = 16,

    /// Receiver confirms the handoff and echoes the `nonce` it will expect
    /// to see in the HMAC of the sender's `HandoffAttach` on the new socket.
    /// Sent AEAD-encrypted over the primary session.
    HandoffAck = 17,

    /// First OVL1 frame on a freshly-opened warm socket: carries
    /// `session_id` + `hmac = BLAKE3::keyed(tx_key)(session_id || nonce)`.
    /// Receiver validates `session_id` against its session registry
    /// recomputes the HMAC with the matching `rx_key`, and on match binds
    /// this socket into the existing `SessionRunner`'s `swap_rx`. A
    /// mismatch is a session-layer violation — the socket is closed.
    HandoffAttach = 18,

    /// hybrid-kex ML-KEM-768 ciphertext sent by
    /// the initiator after `IdentityProof` when both peers advertised
    /// `SUPPORTS_HYBRID_KEX`. Payload = encoded
    /// [`HybridKexCtPayload`](super::session::HybridKexCtPayload)
    /// containing the 1088-byte ML-KEM-768 ciphertext encapsulated
    /// under the responder's static ML-KEM EK (from its mlkem_cert).
    /// The responder decapsulates with its stored DK seed; both sides
    /// then mix the resulting ML-KEM shared secret with the existing
    /// X25519 shared secret via `derive_hybrid_session_keys` to replace
    /// the classical `SessionKeys` before `SessionConfirm`.
    HybridKexCt = 19,

    /// Sent by the winning side of a mutual-rekey-init collision (the
    /// peer with `local_node_id < peer_id`, which kept its own init and
    /// dropped the other's) to signal to the loser: "I will not ACK your
    /// init; drop yours and await ACK for mine." Empty body — receipt
    /// alone carries the back-off semantics. Suppresses the loser's
    /// time/byte-threshold rekey re-trigger for one grace window so
    /// both sides don't immediately re-collide. AEAD-encrypted with
    /// current tx_cipher (pre-rekey keys) like RekeyAck.
    RekeyKeptInit = 20,

    /// Sender informs its peer of a **new transport URI** for future
    /// connections (e.g. when the sender's listener is rotating its
    /// ephemeral port on a snowflake schedule).  Body carries a
    /// signed [`TransportMigrationNotifyPayload`] so that the
    /// receiver can verify the announcement is genuine.
    ///
    /// Receiver updates its local route cache (peers_discovered.json)
    /// for the sender's node_id: marks the prior URI as expiring soon
    /// and adds the new URI.  Subsequent reconnects use the new URI.
    ///
    /// Sent over the existing session BEFORE the old port closes so
    /// active peers don't lose connectivity.  Disconnected peers fall
    /// back to DHT `ResolveTransport` (if sender published the new
    /// URI as `SignedTransportAnnouncement`) or to invite-bundle.
    TransportMigrationNotify = 21,

    /// PoW-gated rendezvous request — initiator asks a target node
    /// (relayed through a mediator's existing session) to provision an
    /// ephemeral listener for one-shot dial.  Body carries a signed
    /// [`crate::rendezvous::RequestEphemeralEndpointPayload`] with a PoW
    /// proof that the requester burned CPU equivalent to a tunable
    /// difficulty.  Anti-DoS gate: scanning attacker cannot flood
    /// rendezvous requests without paying the PoW cost per attempt.
    ///
    /// Target verifies (a) PoW, (b) requester sig, (c) replay-window,
    /// (d) per-requester rate limit; then binds a random-port listener
    /// for a short TTL (or 1 accepted session) and signs an
    /// [`EphemeralEndpointResponse`] (see below).
    RequestEphemeralEndpoint = 22,

    /// PoW-gated rendezvous response — target node sends back a signed
    /// short-lived URI (with per-request PSK) to the requester after
    /// successful PoW verification.  Body carries a signed
    /// [`crate::rendezvous::EphemeralEndpointResponsePayload`].  The
    /// initiator validates the sig against the target's identity_pk,
    /// confirms its own `requester_pubkey` matches the response's echo
    /// field (anti-replay-for-someone-else), and dials the listener.
    EphemeralEndpointResponse = 23,

    // ── handoff anti-replay (audit cycle-6 T1) ─────────────────────
    //
    // The original 3-frame handoff carried a static, plaintext, replayable
    // `HandoffAttach` HMAC on the warm socket (nonce fixed before the socket
    // existed → an on-path observer could copy the bytes and race the legit
    // socket to the one-shot accept). T1 replaces the warm-socket proof with a
    // per-socket challenge-response so a replayed attach gets a fresh challenge
    // it cannot answer without the session's `tx_key`.
    /// Receiver → initiator, on the warm socket, after a bare `HandoffAttach`
    /// announce: a fresh 32-byte `OsRng` challenge bound to THIS socket. Plain
    /// (pre-OVL1) like the rest of the warm-socket handoff frames.
    HandoffChallenge = 24,

    /// Initiator → receiver, on the warm socket: `hmac =
    /// BLAKE3::keyed(tx_key)(session_id || challenge)` proving session-key
    /// ownership over the receiver's per-socket challenge. The receiver
    /// recomputes with `rx_key` and only on match consumes the pending entry
    /// (one-shot) and binds the socket — closing the replay race.
    HandoffResponse = 25,
}

impl TryFrom<u16> for SessionMsg {
    type Error = ProtoError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(SessionMsg::Hello),
            1 => Ok(SessionMsg::Identity),
            2 => Ok(SessionMsg::Capabilities),
            3 => Ok(SessionMsg::KeyAgreement),
            4 => Ok(SessionMsg::SessionConfirm),
            5 => Ok(SessionMsg::Attach),
            6 => Ok(SessionMsg::Detach),
            7 => Ok(SessionMsg::Keepalive),
            8 => Ok(SessionMsg::RekeyInit),
            9 => Ok(SessionMsg::RekeyAck),
            10 => Ok(SessionMsg::MlKemRekeyEk),
            11 => Ok(SessionMsg::MlKemRekeyAck),
            12 => Ok(SessionMsg::Ticket),
            13 => Ok(SessionMsg::SleepAdvertisement),
            14 => Ok(SessionMsg::Padding),
            15 => Ok(SessionMsg::IdentityProof),
            16 => Ok(SessionMsg::HandoffInit),
            17 => Ok(SessionMsg::HandoffAck),
            18 => Ok(SessionMsg::HandoffAttach),
            19 => Ok(SessionMsg::HybridKexCt),
            20 => Ok(SessionMsg::RekeyKeptInit),
            21 => Ok(SessionMsg::TransportMigrationNotify),
            22 => Ok(SessionMsg::RequestEphemeralEndpoint),
            23 => Ok(SessionMsg::EphemeralEndpointResponse),
            24 => Ok(SessionMsg::HandoffChallenge),
            25 => Ok(SessionMsg::HandoffResponse),
            _ => Err(ProtoError::UnknownMsgType {
                family: FrameFamily::Session as u8,
                msg_type: v,
            }),
        }
    }
}

/// Veil control plane message types — NAT traversal, route probes
/// neighbour offers, keepalive, backpressure, and epidemic broadcasts.
#[repr(u16)]
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlMsg {
    Ping = 0,
    Pong = 1,
    NeighborOffer = 2,
    RouteProbe = 3,
    RouteReply = 4,
    Error = 5,
    NatProbeRequest = 6,
    NatProbeReply = 7,
    NatRelayRequest = 8,
    /// OVL1-level keepalive probe.
    Keepalive = 0x10,
    /// Reply to a Keepalive frame.
    KeepaliveAck = 0x11,
    /// Epidemic flood broadcast.
    EpidemicBroadcast = 0x20,
    /// Congestion backpressure signal.
    /// Tells the peer to reduce its sending rate — the local node is overloaded.
    Backpressure = 0x30,
}

impl TryFrom<u16> for ControlMsg {
    type Error = ProtoError;
    fn try_from(v: u16) -> Result<Self, <ControlMsg as TryFrom<u16>>::Error> {
        match v {
            0 => Ok(ControlMsg::Ping),
            1 => Ok(ControlMsg::Pong),
            2 => Ok(ControlMsg::NeighborOffer),
            3 => Ok(ControlMsg::RouteProbe),
            4 => Ok(ControlMsg::RouteReply),
            5 => Ok(ControlMsg::Error),
            6 => Ok(ControlMsg::NatProbeRequest),
            7 => Ok(ControlMsg::NatProbeReply),
            8 => Ok(ControlMsg::NatRelayRequest),
            0x10 => Ok(ControlMsg::Keepalive),
            0x11 => Ok(ControlMsg::KeepaliveAck),
            0x20 => Ok(ControlMsg::EpidemicBroadcast),
            0x30 => Ok(ControlMsg::Backpressure),
            _ => Err(ProtoError::UnknownMsgType {
                family: FrameFamily::Control as u8,
                msg_type: v,
            }),
        }
    }
}

/// Discovery plane message types — Kademlia-like DHT operations plus
/// attachment / app-endpoint lookups.
///
/// Removed slots:
/// * 0 (`FindNode`) and 8 (`FindNodeResponse`) —
///   (475.6): V1 FIND_NODE dropped outright now that V2 + PoW-gated
///   `ResolveTransport` is the only supported flow. Senders that
///   still emit slot 0 / 8 hit `UnknownMsgType` → `Violation` in
///   the dispatcher, which is the desired behavior since legacy
///   V1 walkers leak transports en masse.
/// * 6 (`GetMailboxSet`) — mailbox removal.
///
/// All removed slots are intentionally left unallocated so any
/// future re-introduction is traceable.
///
/// Slots 10-13 added by the decoupled-transport
/// resolution flow:
/// * `FindNodeV2` / `FindNodeV2Response` — V1 minus the `transport`
///   field (response carries node_ids only).
/// * `ResolveTransport` / `ResolveTransportResponse` — separate RPC
///   to look up a single peer's transport, with `discovery_mode`
///   filter + PoW gate applied per-call.
#[repr(u16)]
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMsg {
    FindValue = 1,
    Store = 2,
    Delete = 3,
    AnnounceAttachment = 4,
    GetAttachment = 5,
    GetAppEndpoint = 7,
    FindValueResponse = 9,
    /// V2 of FIND_NODE — response carries node_ids only
    /// no transport URLs. Caller follows up with `ResolveTransport`
    /// for any node_id whose transport is needed.
    FindNodeV2 = 10,
    FindNodeV2Response = 11,
    /// per-node-id transport lookup, gated by `discovery_mode`
    /// + PoW.
    ResolveTransport = 12,
    ResolveTransportResponse = 13,
    ///post-handshake fire-and-forget gossip
    /// of a `SignedTransportAnnouncement` so each peer can return our
    /// signed advertisement when other walkers ask `ResolveTransport`
    /// for our `node_id`. No response — sender treats it as best-effort.
    AnnounceTransport = 14,
}

impl TryFrom<u16> for DiscoveryMsg {
    type Error = ProtoError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(DiscoveryMsg::FindValue),
            2 => Ok(DiscoveryMsg::Store),
            3 => Ok(DiscoveryMsg::Delete),
            4 => Ok(DiscoveryMsg::AnnounceAttachment),
            5 => Ok(DiscoveryMsg::GetAttachment),
            7 => Ok(DiscoveryMsg::GetAppEndpoint),
            9 => Ok(DiscoveryMsg::FindValueResponse),
            10 => Ok(DiscoveryMsg::FindNodeV2),
            11 => Ok(DiscoveryMsg::FindNodeV2Response),
            12 => Ok(DiscoveryMsg::ResolveTransport),
            13 => Ok(DiscoveryMsg::ResolveTransportResponse),
            14 => Ok(DiscoveryMsg::AnnounceTransport),
            _ => Err(ProtoError::UnknownMsgType {
                family: FrameFamily::Discovery as u8,
                msg_type: v,
            }),
        }
    }
}

/// Delivery plane message types — forward, chunked transfers
/// and transit/recursive relay.
///
/// Numeric slots 0,1,2,5,6 were occupied by mailbox messages
/// (MailboxPut/Fetch/Ack/Replicate/FetchReplica)
/// removed the mailbox subsystem. Slots intentionally left
/// unallocated so any future re-introduction is traceable.
#[repr(u16)]
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMsg {
    Forward = 3,
    DeliveryStatus = 4,
    /// OBSOLETE direct-chunk manifest (pre-H-B). No longer emitted; the
    /// dispatcher drops these frames. Large payloads now ride relay-preserving
    /// `ChunkedEnvelopePayload` over `Forward`. Variant kept for wire-compat.
    ChunkManifest = 7,
    /// OBSOLETE direct-chunk fragment (pre-H-B). Dropped on receipt; see
    /// `ChunkManifest`.
    Chunk = 8,
    /// stateless transit relay — lightweight header, no per-flow session state.
    /// Body is `TransitFramePayload`.
    Transit = 0x10,
    /// DHT-routed recursive relay — forward hop-by-hop through
    /// Kademlia closest nodes until a node with a live session delivers.
    /// Body is `RecursiveRelayPayload`.
    RecursiveRelay = 0x11,
    /// **Source-routed relay** — sender names the entire relay chain
    /// up-front, each hop just forwards to the next entry in `path`.
    /// Bypasses both `route_cache` gossip (which has hop-depth limits)
    /// and Audit-H22 `iterative.lookup.all_filtered` (which rejects
    /// non-progressive contacts).  Body is `RelayPathPayload`.
    /// Audit batch 2026-05-23.
    RelayPath = 0x12,
}

impl TryFrom<u16> for DeliveryMsg {
    type Error = ProtoError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            3 => Ok(DeliveryMsg::Forward),
            4 => Ok(DeliveryMsg::DeliveryStatus),
            7 => Ok(DeliveryMsg::ChunkManifest),
            8 => Ok(DeliveryMsg::Chunk),
            0x10 => Ok(DeliveryMsg::Transit),
            0x11 => Ok(DeliveryMsg::RecursiveRelay),
            0x12 => Ok(DeliveryMsg::RelayPath),
            _ => Err(ProtoError::UnknownMsgType {
                family: FrameFamily::Delivery as u8,
                msg_type: v,
            }),
        }
    }
}

/// Local mesh plane message types.
#[repr(u16)]
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshMsg {
    Forward = 0,
    Beacon = 1,
    Ack = 2,
}

impl TryFrom<u16> for MeshMsg {
    type Error = ProtoError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(MeshMsg::Forward),
            1 => Ok(MeshMsg::Beacon),
            2 => Ok(MeshMsg::Ack),
            _ => Err(ProtoError::UnknownMsgType {
                family: FrameFamily::Mesh as u8,
                msg_type: v,
            }),
        }
    }
}

/// Application plane message types — veil-side counterparts to
/// `LocalAppMsg` used for app-to-app traffic across nodes.
#[repr(u16)]
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMsg {
    AppOpen = 0,
    AppData = 1,
    AppClose = 2,
    AppSend = 3,
    AppReceipt = 4,
    AppWindowUpdate = 5,
    AppRtData = 6,
}

impl TryFrom<u16> for AppMsg {
    type Error = ProtoError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(AppMsg::AppOpen),
            1 => Ok(AppMsg::AppData),
            2 => Ok(AppMsg::AppClose),
            3 => Ok(AppMsg::AppSend),
            4 => Ok(AppMsg::AppReceipt),
            5 => Ok(AppMsg::AppWindowUpdate),
            6 => Ok(AppMsg::AppRtData),
            _ => Err(ProtoError::UnknownMsgType {
                family: FrameFamily::App as u8,
                msg_type: v,
            }),
        }
    }
}

/// Local App IPC message types (family=6) — the client-side half of the
/// app messaging protocol, spoken over the Unix-domain IPC socket.
#[repr(u16)]
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAppMsg {
    AppHello = 0,
    AppHelloOk = 1,
    AppHelloErr = 2,
    AppBind = 3,
    AppBindOk = 4,
    AppBindErr = 5,
    AppUnbind = 6,
    AppDeliver = 7,
    AppIpcSend = 8,
    AppSendOk = 9,
    StreamOpen = 10,
    StreamOpenOk = 11,
    StreamOpenErr = 12,
    StreamData = 13,
    StreamClose = 14,
    StreamWindow = 15,
    StreamRtData = 16,
    /// Permanent delivery failure: the node could not deliver the message within
    /// `MAX_DELIVERY_ATTEMPTS`. Payload: `content_id[32]`.
    AppSendFailed = 17,
    /// Outbound real-time frame: client → node. Payload: `AppIpcRtSendPayload`.
    /// The node looks up the active session to `dst_node_id` and sends an
    /// `AppMsg::AppRtData` frame at `REALTIME` priority.
    AppRtSend = 18,
    /// E2E delivery stage notification: node → app.
    /// Payload: `content_id[32] || stage[1]`.
    /// Fired for each stage of the 5-stage receipt FSM (Accepted, Stored
    /// Fetched, Delivered, AppAcked) as the veil receives confirmations.
    DeliveryStage = 19,
    /// Anycast service resolution request: app → node.
    /// Payload: `AnycastResolvePayload`.
    AnycastResolve = 20,
    /// Anycast service resolution result: node → app.
    /// Payload: `AnycastResultPayload`.
    AnycastResult = 21,
    /// Anycast service advertisement: app → node.
    /// Payload: `AnycastAdvertisePayload`. Node merges the local entry into
    /// the DHT list under `BLAKE3("anycast:v1:" || service_tag)`.
    AnycastAdvertise = 22,
    /// Anycast service withdrawal: app → node.
    /// Payload: `AnycastWithdrawPayload`. Removes this node's entry from the
    /// DHT list (the list itself ages out naturally if empty).
    AnycastWithdraw = 23,
    /// Transport-hint query: app → node. Empty body. Node
    /// responds with `TransportHintResult` carrying ranked schemes from
    /// the local `TransportHintRegistry`.
    TransportHintQuery = 24,
    /// Transport-hint result: node → app.
    /// Payload: `TransportHintResultPayload`.
    TransportHintResult = 25,
    /// Mobile background-mode toggle: app → node.
    /// Payload: `[mode_byte: 0=Foreground, 1=Active, 2=LowPower]`.
    /// Daemon adjusts keepalive cadence accordingly so sessions survive
    /// OS-level Doze / iOS background-task suspension.
    SetMobileBackgroundMode = 26,
    /// Network-state change: app → node.
    /// Payload: `NetworkChangedPayload`. Daemon eagerly tears down
    /// stale sessions and reconnects via bootstrap; on mobile this
    /// avoids the keepalive-timeout wait when Wi-Fi → cellular flips.
    NetworkChanged = 27,
    /// Node-identity query: app → node.
    /// Empty body. Node responds with `NodeIdentity` carrying its own
    /// `node_id`, signature algorithm, and public key. Unblocks
    /// Flutter / Swift / Kotlin UIs from displaying "you are: 0xABC…"
    /// without scraping the VEIL_LOCAL_NODE_ID env var.
    GetNodeIdentity = 28,
    /// Node-identity reply: node → app.
    /// Payload: `NodeIdentityPayload`.
    NodeIdentity = 29,
    /// Peer-list query: app → node. Empty body. Node responds
    /// with `PeersList` snapshot of currently-active sessions. Useful for
    /// Flutter UI displaying "connected to N peers" indicator.
    GetPeers = 30,
    /// Peer-list reply: node → app.
    /// Payload: `PeersListPayload`.
    PeersList = 31,
    /// Bootstrap-URI join request: app → node (— Flutter
    /// onboarding). Carries the raw `veil:` invite URL plus
    /// optional password + expected-issuer-pubkey for encrypted /
    /// signed variants. Daemon decodes, verifies, and registers the
    /// resulting peer for outbound dial. Closes the deep-link
    /// onboarding gap that previously required shelling out to
    /// `veil-cli bootstrap join` (impossible from sandboxed
    /// Android / iOS).
    JoinBootstrapUri = 32,
    /// Bootstrap-URI join reply: node → app.
    /// Payload: `JoinBootstrapResultPayload`.
    JoinBootstrapResult = 33,
    /// Mobile-status query: app → node (— Flutter battery /
    /// tier diagnostics). Empty body. Node responds c `MobileStatus`
    /// carrying current tier + battery + effective keepalive/probe
    /// factors so apps can display "Power-saving mode active" badges
    /// or diagnose unexpected keepalive cadence without admin-token.
    GetMobileStatus = 34,
    /// Mobile-status reply: node → app.
    /// Payload: `MobileStatusPayload`.
    MobileStatus = 35,
    /// Push event: node → app.
    /// Payload: `EventPayload` carrying a `kind` byte + opaque per-kind
    /// payload bytes. Daemon emits events on state changes (session
    /// count, mobile tier, identity rotation, etc.) so apps can react
    /// without polling. Critical for budget-Android battery: pre-push
    /// flow polled `mobile_status` / `peers_list` every few seconds
    /// burning ~30-50 mAh/day per polled metric. Push events drop this
    /// to "wake only on actual change", preserving battery for the
    /// censorship-resistant mobile use case.
    Event = 36,
    /// Set push envelope: app → node.
    /// Payload: `SetPushEnvelopePayload` carrying matching rendezvous
    /// `(rendezvous_node_id, auth_cookie)` tuple + already-sealed envelope
    /// bytes. Daemon routes to
    /// `NodeRuntime::set_rendezvous_push_envelope` so the next maintenance
    /// tick re-signs every active rendezvous-ad with the new envelope.
    /// Empty envelope (`bytes.len == 0`) clears push registration without
    /// disrupting the rendezvous publication itself (use case: user
    /// disabled push in settings). Sealing happens client-side ([crate::push_envelope_seal_helper] OR Dart wrapper) so the daemon
    /// never sees the raw FCM/APNs token — only opaque ciphertext.
    SetPushEnvelope = 37,
    /// Set push envelope reply: node → app.
    /// Payload: 1-byte status (0 = OK, 1 = no matching rendezvous
    /// 2 = envelope too large). Wire format kept tiny so it doesn't
    /// burn battery on the response leg.
    SetPushEnvelopeOk = 38,
    /// Mailbox put: app → node.
    /// Payload: `MailboxPutPayload`. Sender's app deposits an
    /// encrypted blob for an offline receiver via one of the
    /// receiver's K rendezvous-publisher relays. No auth_cookie
    /// required — anyone can put (the cap is per-receiver quota +
    /// rate limit). Daemon routes to its local
    /// [`veil_mailbox::Mailbox::put`].
    MailboxPut = 39,
    /// Mailbox put reply: node → app.
    /// Payload: `MailboxPutOkPayload` (1 byte status + 4 bytes
    /// `evicted` count).
    MailboxPutOk = 40,
    /// Mailbox fetch: app → node.
    /// Payload: `MailboxFetchPayload` (32-byte receiver_id +
    /// 16-byte auth_cookie). Recipient's app pulls all pending
    /// blobs after wake-up. `auth_cookie` must match one
    /// previously registered via `RegisterRendezvousPublisher`;
    /// otherwise relay returns an empty list.
    MailboxFetch = 41,
    /// Mailbox fetch reply: node → app.
    /// Payload: `MailboxFetchRespPayload` (length-prefixed list of
    /// `MailboxBlobWire` records, oldest first).
    MailboxFetchResp = 42,
    /// Mailbox ack: app → node. Payload:
    /// `MailboxAckPayload` (32-byte receiver_id + 32-byte content_id +
    /// 16-byte auth_cookie). Recipient confirms end-to-end receipt;
    /// relay deletes the blob and frees its quota slice.
    MailboxAck = 43,
    /// Mailbox ack reply: node → app. Payload: 1
    /// byte (1 = removed, 0 = no-op / unauthorised / not present).
    MailboxAckOk = 44,
    /// Outbox put: app → node.
    /// Payload: `OutboxPutPayload` (32-byte receiver_id + 32-byte
    /// content_id + opaque blob). Sender's app records a freshly-
    /// sent message for later peer-sync retransmission. Empty body
    /// reply: `OutboxPutOk`.
    OutboxPut = 45,
    /// Outbox put reply: node → app. Empty payload.
    OutboxPutOk = 46,
    /// Outbox find-missing: app → node. Payload:
    /// `OutboxFindMissingPayload` (32-byte receiver + u64 since +
    /// length-prefixed Bloom filter). Used when a peer's
    /// peer-sync request arrives over the veil; app translates
    /// the peer's filter into outbox queries.
    OutboxFindMissing = 47,
    /// Outbox find-missing reply: node → app.
    /// Payload: `OutboxFindMissingRespPayload` (length-prefixed list
    /// of `OutboxEntryWire` records, oldest first).
    OutboxFindMissingResp = 48,
    /// Outbox ack: app → node. Payload:
    /// `OutboxAckPayload` (32-byte receiver + 32-byte content_id).
    /// Removes the entry after end-to-end direct ack.
    OutboxAck = 49,
    /// Outbox ack reply: node → app. Payload: 1 byte
    /// (1 = removed, 0 = was not present).
    OutboxAckOk = 50,
    /// Lookup rendezvous replicas: app → node (—
    /// T1.4 P5c). Payload: `LookupRendezvousReplicasPayload`
    /// (32-byte receiver_id + 1-byte max_replicas). Daemon resolves
    /// receiver's RendezvousAd from DHT, verifies signature +
    /// freshness, returns up to `max_replicas` candidate relays
    /// senders can fan-out mailbox puts to. Currently returns at
    /// most 1 (single-key publication); K=3 storage is future work
    /// — Vec wire format keeps API forward-compatible.
    LookupRendezvousReplicas = 51,
    /// Lookup rendezvous replicas reply: node → app.
    /// Payload: `LookupRendezvousReplicasRespPayload`
    /// (length-prefixed list of `ReplicaWire` entries — each
    /// {relay_node_id, push_envelope, valid_until_unix}).
    LookupRendezvousReplicasResp = 52,
    /// Create bootstrap invite request: app → node (Epic 489.7
    /// generator side).  Payload: `CreateBootstrapInvitePayload`
    /// carrying optional password (encrypts the invite) and validity
    /// seconds (for signed variants — currently ignored on plain).
    /// Daemon assembles a `BootstrapPeer` from its own [identity] +
    /// [[listen]] config and encodes the canonical URI (plus encrypt
    /// envelope if password supplied).  Reply: `CreateBootstrapInviteResult`.
    CreateBootstrapInvite = 53,
    /// Create bootstrap invite reply: node → app.
    /// Payload: `CreateBootstrapInviteResultPayload` (1-byte status +
    /// length-prefixed URI bytes on success / detail bytes on error).
    CreateBootstrapInviteResult = 54,

    // ── Multi-device pairing ceremony (Epic 489.8) ──────────────────
    //
    // Six-message ceremony between two devices of the SAME sovereign
    // identity.  Source = existing device holding the master_sk.
    // Target = fresh device to be added to the identity-keys list.
    // State lives ephemerally in the daemon (one-at-a-time semantics,
    // restart-tolerant — daemon crash midway means user restarts
    // ceremony).  See pair_runtime crate for the state machines.
    //
    // Source side (3 messages → 3 replies):
    //   55/56 — PairSourceCreateInvite: generate pair_secret + URI,
    //           stash state, return URI for user to share.
    //   57/58 — PairSourceHandleHello: receive Hello bytes from target,
    //           return Cert bytes + 6-digit OOB code to display.
    //   59/60 — PairSourceHandleConfirm: receive Confirm bytes, finalize
    //           (master-certified subkey persists across daemon restart).
    //
    // Target side (3 messages → 3 replies):
    //   61/62 — PairTargetConsumeUri: parse scanned URI, generate Hello.
    //   63/64 — PairTargetHandleCert: process Cert, return OOB code.
    //   65/66 — PairTargetBuildConfirm: take user "codes match" decision,
    //           emit Confirm; on user_confirmed=true persist new identity.
    PairSourceCreateInvite = 55,
    PairSourceCreateInviteResult = 56,
    PairSourceHandleHello = 57,
    PairSourceHandleHelloResult = 58,
    PairSourceHandleConfirm = 59,
    PairSourceHandleConfirmResult = 60,
    PairTargetConsumeUri = 61,
    PairTargetConsumeUriResult = 62,
    PairTargetHandleCert = 63,
    PairTargetHandleCertResult = 64,
    PairTargetBuildConfirm = 65,
    PairTargetBuildConfirmResult = 66,
    /// **Inbound stream notification: daemon → app.**  Sent when a
    /// remote node opens a stream to a bound endpoint owned by this
    /// IPC client.  Distinct from [`Self::StreamOpenOk`] which is the
    /// reply to the app's OWN outbound `StreamOpen` request — the
    /// two were previously aliased causing inbound streams to be
    /// silently dropped by the SDK.  Payload:
    /// [`crate::ipc::StreamOpenInboundPayload`].
    StreamOpenInbound = 67,
    /// **P-Net status query: app → daemon.**  Asks whether the
    /// session to the given `peer_node_id` was admitted under a valid
    /// `MembershipCert`.  Used by ogate / oproxy / other apps that
    /// want to gate their app-layer admission on the daemon's
    /// already-performed handshake-time cert verification (instead
    /// of maintaining their own static `allowed_node_ids` list).
    /// Payload: 32-byte peer_node_id.  Daemon replies with
    /// [`Self::PnetStatusResult`].
    PnetStatusQuery = 68,
    /// **P-Net status result: daemon → app.**  Reply to
    /// [`Self::PnetStatusQuery`].  Payload:
    /// [`crate::ipc::PnetStatusResultPayload`] —
    /// `admitted` flag + (when admitted) the cert's network_id /
    /// admin flag / valid_until_unix.
    PnetStatusResult = 69,
    /// **Set wake-HMAC envelope: app → node.**  Receiver uploads the
    /// sealed [`veil_crypto::wake_hmac::WakeHmacKey`] envelope so
    /// the daemon embeds it in every subsequent signed RendezvousAd
    /// refresh (Epic 489.10 slice 4.3.4).  Payload:
    /// [`crate::ipc::SetWakeHmacEnvelopePayload`] — matching rendezvous
    /// publication selector + opaque sealed bytes.  Empty envelope
    /// clears the registration (HMAC opt-out fallback).
    SetWakeHmacEnvelope = 70,
    /// **Set wake-HMAC envelope reply: node → app.**  Payload: 1-byte
    /// status (0 = OK, 1 = no matching rendezvous, 2 = envelope too
    /// large).  Mirrors [`Self::SetPushEnvelopeOk`].
    SetWakeHmacEnvelopeOk = 71,
    /// Anycast candidate-failure report: app → node. Fire-and-forget (no
    /// reply, like `AnycastAdvertise` / `AnycastWithdraw`).
    /// Payload: `AnycastReportFailurePayload` (`service_tag[4] || node_id[32]`).
    /// The app calls this after a CONCRETE failure (timeout, conn-refused,
    /// validation reject) against a candidate it got from `AnycastResolve`;
    /// the daemon feeds it into the local `AnycastReputation` ledger so future
    /// resolves de-prioritise the offending candidate. Without this message the
    /// reputation slice has no feedback source and `score_offset` stays 0
    /// (audit cycle-7 M6). Successes are deliberately NOT reported (they are
    /// peer-fakeable; see the reputation module doc).
    AnycastReportFailure = 72,
    /// App → daemon: register this node as a location-anonymous (onion) service.
    /// Body is `RegisterOnionServicePayload`.
    RegisterOnionService = 73,
    /// daemon → app: result of `RegisterOnionService` (2-byte status code,
    /// `0` = ok, else an `ipc_send_err`).
    RegisterOnionServiceResult = 74,
    /// App → daemon: send to a location-anonymous service addressed by its
    /// Ed25519 IDENTITY key (resolves the blinded descriptor). Body is
    /// `SendToOnionServicePayload`.
    SendToOnionService = 75,
    /// daemon → app: result of `SendToOnionService` (2-byte status code,
    /// `0` = ok, else an `ipc_send_err`).
    SendToOnionServiceResult = 76,
}

impl TryFrom<u16> for LocalAppMsg {
    type Error = ProtoError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(LocalAppMsg::AppHello),
            1 => Ok(LocalAppMsg::AppHelloOk),
            2 => Ok(LocalAppMsg::AppHelloErr),
            3 => Ok(LocalAppMsg::AppBind),
            4 => Ok(LocalAppMsg::AppBindOk),
            5 => Ok(LocalAppMsg::AppBindErr),
            6 => Ok(LocalAppMsg::AppUnbind),
            7 => Ok(LocalAppMsg::AppDeliver),
            8 => Ok(LocalAppMsg::AppIpcSend),
            9 => Ok(LocalAppMsg::AppSendOk),
            10 => Ok(LocalAppMsg::StreamOpen),
            11 => Ok(LocalAppMsg::StreamOpenOk),
            12 => Ok(LocalAppMsg::StreamOpenErr),
            13 => Ok(LocalAppMsg::StreamData),
            14 => Ok(LocalAppMsg::StreamClose),
            15 => Ok(LocalAppMsg::StreamWindow),
            16 => Ok(LocalAppMsg::StreamRtData),
            17 => Ok(LocalAppMsg::AppSendFailed),
            18 => Ok(LocalAppMsg::AppRtSend),
            19 => Ok(LocalAppMsg::DeliveryStage),
            20 => Ok(LocalAppMsg::AnycastResolve),
            21 => Ok(LocalAppMsg::AnycastResult),
            22 => Ok(LocalAppMsg::AnycastAdvertise),
            23 => Ok(LocalAppMsg::AnycastWithdraw),
            24 => Ok(LocalAppMsg::TransportHintQuery),
            25 => Ok(LocalAppMsg::TransportHintResult),
            26 => Ok(LocalAppMsg::SetMobileBackgroundMode),
            27 => Ok(LocalAppMsg::NetworkChanged),
            28 => Ok(LocalAppMsg::GetNodeIdentity),
            29 => Ok(LocalAppMsg::NodeIdentity),
            30 => Ok(LocalAppMsg::GetPeers),
            31 => Ok(LocalAppMsg::PeersList),
            32 => Ok(LocalAppMsg::JoinBootstrapUri),
            33 => Ok(LocalAppMsg::JoinBootstrapResult),
            34 => Ok(LocalAppMsg::GetMobileStatus),
            35 => Ok(LocalAppMsg::MobileStatus),
            36 => Ok(LocalAppMsg::Event),
            37 => Ok(LocalAppMsg::SetPushEnvelope),
            38 => Ok(LocalAppMsg::SetPushEnvelopeOk),
            39 => Ok(LocalAppMsg::MailboxPut),
            40 => Ok(LocalAppMsg::MailboxPutOk),
            41 => Ok(LocalAppMsg::MailboxFetch),
            42 => Ok(LocalAppMsg::MailboxFetchResp),
            43 => Ok(LocalAppMsg::MailboxAck),
            44 => Ok(LocalAppMsg::MailboxAckOk),
            45 => Ok(LocalAppMsg::OutboxPut),
            46 => Ok(LocalAppMsg::OutboxPutOk),
            47 => Ok(LocalAppMsg::OutboxFindMissing),
            48 => Ok(LocalAppMsg::OutboxFindMissingResp),
            49 => Ok(LocalAppMsg::OutboxAck),
            50 => Ok(LocalAppMsg::OutboxAckOk),
            51 => Ok(LocalAppMsg::LookupRendezvousReplicas),
            52 => Ok(LocalAppMsg::LookupRendezvousReplicasResp),
            53 => Ok(LocalAppMsg::CreateBootstrapInvite),
            54 => Ok(LocalAppMsg::CreateBootstrapInviteResult),
            55 => Ok(LocalAppMsg::PairSourceCreateInvite),
            56 => Ok(LocalAppMsg::PairSourceCreateInviteResult),
            57 => Ok(LocalAppMsg::PairSourceHandleHello),
            58 => Ok(LocalAppMsg::PairSourceHandleHelloResult),
            59 => Ok(LocalAppMsg::PairSourceHandleConfirm),
            60 => Ok(LocalAppMsg::PairSourceHandleConfirmResult),
            61 => Ok(LocalAppMsg::PairTargetConsumeUri),
            62 => Ok(LocalAppMsg::PairTargetConsumeUriResult),
            63 => Ok(LocalAppMsg::PairTargetHandleCert),
            64 => Ok(LocalAppMsg::PairTargetHandleCertResult),
            65 => Ok(LocalAppMsg::PairTargetBuildConfirm),
            66 => Ok(LocalAppMsg::PairTargetBuildConfirmResult),
            67 => Ok(LocalAppMsg::StreamOpenInbound),
            68 => Ok(LocalAppMsg::PnetStatusQuery),
            69 => Ok(LocalAppMsg::PnetStatusResult),
            70 => Ok(LocalAppMsg::SetWakeHmacEnvelope),
            71 => Ok(LocalAppMsg::SetWakeHmacEnvelopeOk),
            72 => Ok(LocalAppMsg::AnycastReportFailure),
            73 => Ok(LocalAppMsg::RegisterOnionService),
            74 => Ok(LocalAppMsg::RegisterOnionServiceResult),
            75 => Ok(LocalAppMsg::SendToOnionService),
            76 => Ok(LocalAppMsg::SendToOnionServiceResult),
            _ => Err(ProtoError::UnknownMsgType {
                family: FrameFamily::LocalApp as u8,
                msg_type: v,
            }),
        }
    }
}

/// Routing gossip & discovery message types (family=8, Epics 60/61).
#[repr(u16)]
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingMsg {
    /// Gossip: "I can reach `origin_node_id` via me".
    RouteAnnounce = 0,
    /// Gossip: "I can no longer reach `origin_node_id` via me".
    RouteWithdraw = 1,
    /// On-demand: "Who knows how to reach `target_node_id`?".
    RouteRequest = 2,
    /// On-demand: "Here are transports / relays for `target_node_id`".
    RouteResponse = 3,
    /// Direct bootstrap: PoW challenge for session establishment.
    PowChallenge = 4,
    /// Direct bootstrap: PoW solution.
    PowResponse = 5,
    /// Direct bootstrap: PoW accepted, here is my transport.
    PowAccept = 6,
    /// Aliased gossip announce: 8-byte session aliases instead of 32-byte node_ids.
    RouteAnnounceAliased = 7,
    /// Aliased gossip withdraw: 8-byte session aliases instead of 32-byte node_ids.
    RouteWithdrawAliased = 8,
    /// Random-walk route discovery packet.
    RouteDiscover = 9,
    /// Route discovery offer: responder's transport addresses.
    RouteDiscoverOffer = 10,
    /// Recursive DHT query: greedy forwarded toward target.
    RecursiveQuery = 0x10,
    /// Recursive DHT response: direct reply to initiator.
    RecursiveResponse = 0x11,
    /// Event-driven route update: push on connect/disconnect.
    RouteUpdate = 0x12,
    /// Version vector exchange for periodic route reconciliation.
    VersionVectorSync = 0x13,
}

impl TryFrom<u16> for RoutingMsg {
    type Error = ProtoError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(RoutingMsg::RouteAnnounce),
            1 => Ok(RoutingMsg::RouteWithdraw),
            2 => Ok(RoutingMsg::RouteRequest),
            3 => Ok(RoutingMsg::RouteResponse),
            4 => Ok(RoutingMsg::PowChallenge),
            5 => Ok(RoutingMsg::PowResponse),
            6 => Ok(RoutingMsg::PowAccept),
            7 => Ok(RoutingMsg::RouteAnnounceAliased),
            8 => Ok(RoutingMsg::RouteWithdrawAliased),
            9 => Ok(RoutingMsg::RouteDiscover),
            10 => Ok(RoutingMsg::RouteDiscoverOffer),
            0x10 => Ok(RoutingMsg::RecursiveQuery),
            0x11 => Ok(RoutingMsg::RecursiveResponse),
            0x12 => Ok(RoutingMsg::RouteUpdate),
            0x13 => Ok(RoutingMsg::VersionVectorSync),
            _ => Err(ProtoError::UnknownMsgType {
                family: FrameFamily::Routing as u8,
                msg_type: v,
            }),
        }
    }
}

/// Diagnostic message types (family=9).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagMsg {
    /// RTT probe sent from initiator to target.
    Ping = 1,
    /// RTT reply sent from target back to initiator.
    Pong = 2,
    /// Traceroute probe with TTL.
    TraceProbe = 3,
    /// Hop report sent back when TTL expires at a relay.
    TraceHop = 4,
}

impl TryFrom<u16> for DiagMsg {
    type Error = ProtoError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(DiagMsg::Ping),
            2 => Ok(DiagMsg::Pong),
            3 => Ok(DiagMsg::TraceProbe),
            4 => Ok(DiagMsg::TraceHop),
            _ => Err(ProtoError::UnknownMsgType {
                family: FrameFamily::Diag as u8,
                msg_type: v,
            }),
        }
    }
}

/// TUN/TAP tunnel family message types (family=7).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelMsg {
    /// Encapsulated raw IP packet from TUN device.
    IpPacket = 0,
}

impl TryFrom<u16> for TunnelMsg {
    type Error = ProtoError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(TunnelMsg::IpPacket),
            _ => Err(ProtoError::UnknownMsgType {
                family: FrameFamily::Tunnel as u8,
                msg_type: v,
            }),
        }
    }
}

/// Relay chain message types.
///
/// `Hop` is the original onion-cell forwarding primitive;
/// `RegisterRendezvous` / `UnregisterRendezvous` / `ForwardIntroduce` were
/// added to wire the rendezvous-relay state machine
/// over the same family. The dispatcher branches on msg_type — Hop bytes
/// are 512 B onion cells, the rendezvous variants carry plain control
/// payloads over an established OVL1 session (NOT onion-encrypted).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayChainMsg {
    /// An onion-encrypted relay chain hop frame.
    Hop = 0,
    /// Receiver → rendezvous: register interest in a specific
    /// `auth_cookie`. Body is `RegisterRendezvousPayload`.
    RegisterRendezvous = 1,
    /// Receiver → rendezvous: stop forwarding for a previously
    /// registered cookie. Body is `UnregisterRendezvousPayload`.
    UnregisterRendezvous = 2,
    /// Rendezvous → receiver: forward an Introduce ciphertext that
    /// arrived through the onion path. Body is `ForwardIntroducePayload`.
    ForwardIntroduce = 3,
    /// Originator → relays: build a stateful return circuit, installing per-hop
    /// `CircuitState` once. Body is `CircuitBuildPayload`. Stateful-circuit /
    /// onion-registration epic (Epic 482.7 return path) — see
    /// `PLAN_ANON_SERVICE_ONION_REGISTRATION.md`. b1 reserves the wire tag; the
    /// per-hop key-install semantics land in b2.
    CircuitBuild = 4,
    /// A data cell travelling along an established circuit (either direction).
    /// Body is `CircuitDataPayload` (`[circuit_id][seq][layered ciphertext]`).
    /// Re-tagged per hop. Semantics land in b3.
    CircuitData = 5,
    /// Tear down a circuit + free its per-hop state. Body is
    /// `CircuitTeardownPayload`.
    CircuitTeardown = 6,
}

impl TryFrom<u16> for RelayChainMsg {
    type Error = ProtoError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(RelayChainMsg::Hop),
            1 => Ok(RelayChainMsg::RegisterRendezvous),
            2 => Ok(RelayChainMsg::UnregisterRendezvous),
            3 => Ok(RelayChainMsg::ForwardIntroduce),
            4 => Ok(RelayChainMsg::CircuitBuild),
            5 => Ok(RelayChainMsg::CircuitData),
            6 => Ok(RelayChainMsg::CircuitTeardown),
            _ => Err(ProtoError::UnknownMsgType {
                family: FrameFamily::RelayChain as u8,
                msg_type: v,
            }),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_chain_msg_discriminants_and_roundtrip() {
        // Wire-format gate: existing discriminants are frozen; the circuit
        // variants (4–6) are the onion-registration / 482.7 return-path epic.
        let all = [
            (RelayChainMsg::Hop, 0u16),
            (RelayChainMsg::RegisterRendezvous, 1),
            (RelayChainMsg::UnregisterRendezvous, 2),
            (RelayChainMsg::ForwardIntroduce, 3),
            (RelayChainMsg::CircuitBuild, 4),
            (RelayChainMsg::CircuitData, 5),
            (RelayChainMsg::CircuitTeardown, 6),
        ];
        for (variant, disc) in all {
            assert_eq!(variant as u16, disc);
            assert_eq!(RelayChainMsg::try_from(disc).unwrap(), variant);
        }
        assert!(RelayChainMsg::try_from(7).is_err());
    }

    #[test]
    fn session_msg_discriminants_are_stable() {
        // Wire-format guarantee: these discriminants MUST NOT shift
        // without a breaking-protocol bump. Keep this as a hard
        // gate on accidental renumbering.
        assert_eq!(SessionMsg::Hello as u16, 0);
        assert_eq!(SessionMsg::Identity as u16, 1);
        assert_eq!(SessionMsg::Capabilities as u16, 2);
        assert_eq!(SessionMsg::KeyAgreement as u16, 3);
        assert_eq!(SessionMsg::SessionConfirm as u16, 4);
        assert_eq!(SessionMsg::Attach as u16, 5);
        assert_eq!(SessionMsg::Detach as u16, 6);
        assert_eq!(SessionMsg::Keepalive as u16, 7);
        assert_eq!(SessionMsg::RekeyInit as u16, 8);
        assert_eq!(SessionMsg::RekeyAck as u16, 9);
        assert_eq!(SessionMsg::MlKemRekeyEk as u16, 10);
        assert_eq!(SessionMsg::MlKemRekeyAck as u16, 11);
        assert_eq!(SessionMsg::Ticket as u16, 12);
        assert_eq!(SessionMsg::SleepAdvertisement as u16, 13);
        assert_eq!(SessionMsg::Padding as u16, 14);
        assert_eq!(SessionMsg::IdentityProof as u16, 15);
        assert_eq!(SessionMsg::HandoffInit as u16, 16);
        assert_eq!(SessionMsg::HandoffAck as u16, 17);
        assert_eq!(SessionMsg::HandoffAttach as u16, 18);
    }

    #[test]
    fn session_msg_identity_proof_roundtrips() {
        let v = SessionMsg::IdentityProof;
        let n = v as u16;
        assert_eq!(SessionMsg::try_from(n).unwrap(), v);
    }

    #[test]
    fn session_msg_handoff_frames_roundtrip() {
        for v in [
            SessionMsg::HandoffInit,
            SessionMsg::HandoffAck,
            SessionMsg::HandoffAttach,
        ] {
            let n = v as u16;
            assert_eq!(SessionMsg::try_from(n).unwrap(), v);
        }
    }

    #[test]
    fn session_msg_rejects_unknown_discriminant() {
        // One past the last defined variant (HandoffResponse=25, audit cycle-6
        // T1) — must be an error, not silent aliasing. Wire-format extensions
        // that add a new variant must bump this test to the next unused
        // discriminant.
        let err = SessionMsg::try_from(26).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::UnknownMsgType { msg_type: 26, .. },
        ));
    }

    #[test]
    fn all_session_msg_variants_roundtrip() {
        // Enumerate every defined discriminant. If someone adds
        // a new variant without updating `TryFrom`, this test
        // catches it immediately. Range bumped to 25 for the cycle-6 T1
        // HandoffChallenge=24 / HandoffResponse=25 additions.
        for n in 0u16..=25 {
            let v = SessionMsg::try_from(n).expect("defined discriminant decodes");
            assert_eq!(v as u16, n);
        }
    }
}

/// Peer Exchange message types (family=11).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PexMsg {
    /// Random-walk request for peer discovery.
    Walk = 0,
    /// PoW challenge from the walk terminator.
    Challenge = 1,
    /// PoW solution from the walk originator.
    Response = 2,
    /// Peer list after successful verification.
    Result = 3,
}

impl TryFrom<u16> for PexMsg {
    type Error = ProtoError;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(PexMsg::Walk),
            1 => Ok(PexMsg::Challenge),
            2 => Ok(PexMsg::Response),
            3 => Ok(PexMsg::Result),
            _ => Err(ProtoError::UnknownMsgType {
                family: FrameFamily::PeerExchange as u8,
                msg_type: v,
            }),
        }
    }
}
