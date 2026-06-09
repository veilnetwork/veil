//! Wire-size budget for OVL1 protocol frames.
//!
//! This module documents the on-wire size of every payload type. These
//! constants are cross-referenced by tests to catch accidental size regressions.
//!
//! # Size taxonomy
//!
//! * `*_FIXED` — bytes occupied by fixed-width fields (no variable payload).
//! * `*_MAX` — absolute upper bound including the largest allowed variable field.
//! * `FRAME_HEADER_SIZE` — size of the common `FrameHeader` prefix.
//! * `MAX_FRAME_BODY` — maximum body bytes (from `proto/codec.rs`).
//!
//! All sizes are in bytes.
//!
//! # Stability
//!
//! Constants are grouped into two categories:
//!
//! * **Network contract constants (stable)** — exposed to external applications via
//! `veilclient`. Changes to these values constitute a breaking protocol change
//! and require a version bump in `IPC_PROTOCOL_VERSION`.
//!
//! * **Implementation limits (may change)** — internal tuning parameters; not part of
//! the public API. Applications must not hard-code these values.

use crate::codec::MAX_FRAME_BODY;
use crate::header::HEADER_SIZE;

// ═══════════════════════════════════════════════════════════════════════════════
// === Network contract constants (stable) =====================================
// ═══════════════════════════════════════════════════════════════════════════════
//
// These constants define observable protocol behaviour that external applications
// may depend on. They are re-exported through `veilclient`. Changing them
// constitutes a breaking protocol change and requires a version bump.

// ── Common ─────────────────────────────────────────────────────────────────────

/// `FrameHeader` wire size. : kept despite no direct callers —
/// `docs/WIRE_PROTOCOL.md` + `docs/ARCHITECTURE_FULL.md` reference this
/// name as the protocol-contract token, and the `frame_header_size_matches`
/// test pins it to `HEADER_SIZE`.
pub const FRAME_HEADER_SIZE: usize = HEADER_SIZE;

/// Maximum body that can follow a `FrameHeader`. : same
/// documentation role as `FRAME_HEADER_SIZE`.
pub const FRAME_BODY_MAX: u32 = MAX_FRAME_BODY;

// ── Session plane ──────────────────────────────────────────────────────────────

/// `HelloPayload`: ovl1_major(2) + node_id(32) = 34 bytes.
pub const SESSION_HELLO_SIZE: usize = 34;

/// `IdentityPayload`: variable (algo + var pubkey + var nonce + node_id).
pub const SESSION_IDENTITY_MIN: usize = 1;

/// `CapabilitiesPayload`: role(1) + flags(1) = 2 bytes. Pre-audit layout
/// carried six extra fields (transports, max_frame_size, max_streams
/// ovl1_minor) that were always advertised but never read — removed in the
/// single-version cleanup.
pub const SESSION_CAPABILITIES_SIZE: usize = 3;

/// `KeyAgreementPayload`: variable (algo(1) + key_len(2) + key bytes).
pub const SESSION_KEY_AGREEMENT_MIN: usize = 3;

/// `SessionConfirmPayload`: session_id(32) + mac(32) = 64.
pub const SESSION_CONFIRM_SIZE: usize = 64;

/// `DetachPayload`: reason(1).
pub const SESSION_DETACH_SIZE: usize = 1;

/// `KeepalivePayload`: timestamp_secs(8).
pub const SESSION_KEEPALIVE_SIZE: usize = 8;

/// Session ticket lifetime in seconds.
///
/// Tickets issued after a successful OVL1 handshake expire after 1 hour.
/// The resuming client must present the ticket before it expires.
pub const SESSION_TICKET_TTL_SECS: u64 = 3_600; // 1 hour

/// Maximum age of a session ticket that will be accepted by the server.
///
/// Even if a client holds a ticket older than `SESSION_TICKET_TTL_SECS`, the
/// server rejects it. `SESSION_TICKET_MAX_AGE_SECS` gives a small grace window
/// above `SESSION_TICKET_TTL_SECS` for clock skew.
pub const SESSION_TICKET_MAX_AGE_SECS: u64 = 7_200; // 2 hours

/// TLV type byte for a resume_ticket extension in `HelloPayload`.
pub const HELLO_TLV_RESUME_TICKET: u8 = 0x01;

/// TLV type byte for a private-veil-network membership cert
/// extension in `HelloPayload`. Carries the bincode-encoded
/// `veil_types::MembershipCert` blob signed by the network owner.
/// Receivers in `mode = private` reject HELLO frames without a valid
/// cert; receivers in `mode = public` ignore the TLV for forward
/// compatibility with private-mode peers connecting to public bootstrap.
pub const HELLO_TLV_MEMBERSHIP_CERT: u8 = 0x02;

/// TLV type byte for a per-resumption nonce in `HelloPayload`. Set by the
/// initiator alongside `resume_ticket`; the responder folds it (with its own
/// nonce returned in the ATTACH trailer) into a fresh resumption key
/// derivation, so a resumed session never reuses the original session's
/// `(key, nonce)`. A `resume_ticket` without this nonce is NOT resumed
/// (responder falls back to the full handshake). 32 bytes.
pub const HELLO_TLV_RESUME_NONCE: u8 = 0x03;

/// Upper bound on encoded `MembershipCert` blob size (defense-in-depth
/// against a malicious HELLO inflating the TLV). Real certs serialise
/// to ~150-200 bytes (Ed25519 sig = 64 bytes; Falcon = 666 bytes; plus
/// fixed fields). Cap matches the highest expected algo + headroom.
pub const MAX_MEMBERSHIP_CERT_SIZE: usize = 2048;

/// Maximum number of per-peer resumption tickets stored in memory.
///
/// `peer_tickets` is keyed by `peer_id ([u8;32])`, so one entry per distinct
/// peer. On a long-running node that touches thousands of peers this grows
/// without bound. When the map reaches this cap, the entry with the oldest
/// `issued_at` is evicted before inserting the new one. 4 096 × ~250 B ≈ 1 MB.
pub const MAX_PEER_TICKETS: usize = 4_096;

/// Wire size of an encrypted session ticket body.
///
/// `SessionTicket` plaintext layout:
/// `session_id(32) || peer_id(32) || tx_key(32) || rx_key(32) || issued_at(8)
/// || valid_until(8) || peer_instance_id(16)` = 160 bytes.
///
/// Encrypted = nonce(12) || plaintext(160) || AEAD tag(16) = 188 bytes.
pub const SESSION_TICKET_ENCRYPTED_SIZE: usize = 188;

// ── Delivery plane ─────────────────────────────────────────────────────────────

/// `DeliveryEnvelope` fixed header (without variable `payload`).
///
/// the recipient field grew from a
/// 32-byte node_id to the fixed-49-byte
/// `Recipient::encode_fixed_into` form (node_id + tag byte +
/// 16-byte instance_id, zero-padded for `Any`/`All`), so the
/// header expanded by +17 bytes.
///
/// recipient(49) + sender_node_id(32) + src_app_id(32) + app_id(32)
/// + endpoint_id(4) + content_id(32) + created_at(8) + ttl_secs(4)
/// + payload_len(4) = 197 bytes.
pub const DELIVERY_ENVELOPE_HEADER: usize = 197;

/// `DeliveryStatusPayload`: content_id(32) + status(1) + mac(32) = 65 (C-09).
pub const DELIVERY_STATUS_SIZE: usize = 65;

// ── Discovery plane ───────────────────────────────────────────────────────────

/// `GatewayRef`: node_id(32) + transport_len(2) + transport(4 min) = 38 min.
pub const GATEWAY_REF_MIN: usize = 38;

/// `FindValuePayload`: key(32) = 32.
pub const FIND_VALUE_SIZE: usize = 32;

/// `NodeContact`: node_id(32) + transport variable.
pub const NODE_CONTACT_ID_SIZE: usize = 32;

// ── Mesh plane ────────────────────────────────────────────────────────────────

/// `MeshFrame` fixed header (without variable `payload`).
///
/// realm_id(16) + src(32) + dst(32) + ttl(1) + nonce(8) + payload_len(2) = 91 bytes.
pub const MESH_FRAME_HEADER: usize = 91;

/// `MeshBeaconPayload` v1 minimum: node_id(32) + realm_id(16) = 48.
/// v2 adds role_flags(1) + addr_len(1) + veil_addr(0..=255).
pub const MESH_BEACON_SIZE: usize = 48;

/// `MeshAckPayload`: frame_id(16) + status(1) = 17.
pub const MESH_ACK_SIZE: usize = 17;

// ═══════════════════════════════════════════════════════════════════════════════
// === Implementation limits (may change) ======================================
// ═══════════════════════════════════════════════════════════════════════════════
//
// Internal tuning parameters: cache sizes, timeouts, rate limits, etc.
// Applications must not hard-code these values; they may change between releases.

// ── Resource limits ───────────────────────────────────────────────────────────

/// Maximum number of entries in a `NeighborTable`.
pub const MAX_NEIGHBOR_TABLE_SIZE: usize = 256;

/// How long a UDP neighbor may be silent (no successful send) before it is
/// considered dead. `UdpLink::is_alive` returns `false` after this
/// duration, so the next `prune_dead` call removes the stale entry.
///
/// UDP is connectionless — a peer can go offline without triggering a send
/// error on the local side. This timeout bounds how long we forward frames
/// into a silent void.
pub const UDP_NEIGHBOR_IDLE_TIMEOUT_SECS: u64 = 60;

/// Maximum number of entries in a `RouteCache`.
pub const MAX_ROUTE_CACHE_SIZE: usize = 1024;

/// Maximum number of next-hop candidates per destination in `RouteCache`.
/// When the bucket is full, the worst-scoring entry is evicted on insert.
pub const MAX_ROUTES_PER_DST: usize = 4;

/// Maximum number of distinct destinations that a single `via_node_id` (next-hop)
/// may appear in within `RouteCache`.
///
/// Without this limit a single misbehaving or compromised relay could flood the
/// cache by announcing itself as the next-hop to thousands of fake destinations
/// starving legitimate routes via LRU eviction. 256 covers all realistic
/// destinations reachable through one peer in a 1 024-node network with
/// redundant paths.
pub const MAX_ROUTES_PER_VIA: usize = 256;

/// Maximum entries accepted in a `VersionVectorSyncPayload` (per-frame). At
/// ~40 B/entry this caps a single sync frame near 400 KiB. Named so the cap and
/// its memory implication live next to the other routing budgets instead of as
/// a bare literal in the decoder. (audit cycle-3.)
pub const MAX_VERSION_VECTOR_ENTRIES: usize = 10_000;

/// Maximum number of bytes in a single TLV entry value.
///
/// Must not exceed `u16::MAX` (65 535): the wire format stores the TLV length
/// as a 2-byte big-endian field. A value of 65 536 would wrap to 0 on cast
/// silently corrupting the encoded frame.
pub const TLV_MAX_ENTRY_VALUE: usize = u16::MAX as usize; // 65_535

/// Maximum number of concurrently open OVL1 sessions.
/// New inbound connections are rejected with a transport error once this
/// limit is reached. Outbound connections are not capped here (the peer
/// list is already bounded by configuration).
/// raised from 1024. Transit sessions use shallow tx queues
/// (256 depth), making 64K sessions practical on commodity hardware.
pub const MAX_CONCURRENT_SESSIONS: usize = 65_536;

/// Maximum number of entries in `BanList`.
/// When full, the entry with the earliest expiry is evicted to make room.
pub const MAX_BAN_LIST_SIZE: usize = 8_192;

/// Maximum number of entries in `ViolationTracker`.
/// When full, the entry with the oldest `last_violation` timestamp is evicted.
pub const MAX_VIOLATION_TRACKER_SIZE: usize = 8_192;

/// Maximum number of entries in `PerPeerLimiter`.
/// Oldest-idle entry is evicted when the cap is reached.
pub const MAX_PER_PEER_LIMITER_SIZE: usize = 8_192;

/// Maximum number of identities tracked by `IdentityWriteQuota` (audit cycle-5
/// #6). The `node_id` key is attacker-controlled and unverified at the DHT store
/// gate (recursive STORE of nc/id/ir/mc), and the per-process GC sweep is not
/// scheduled, so the map is bounded here: when full, the least-recently-touched
/// identity is evicted on each new insertion. Slightly larger than the per-peer
/// limiter because identities can outnumber direct peers.
pub const MAX_IDENTITY_WRITE_QUOTA_SIZE: usize = 16_384;

/// Maximum number of concurrent inbound sessions allowed from a single source IP.
/// This prevents a single host from exhausting the global `MAX_CONCURRENT_SESSIONS`
/// quota and starving all other peers.
pub const MAX_SESSIONS_PER_IP: usize = 32;

/// Maximum number of entries in the `peer_pubkeys` cache.
///
/// o: lowered 65_536 → 1024. Previous cap was sized for
/// large-deployment servers; under chaos-ban-driven peer churn the
/// HashMap's internal storage grew to full capacity (~5 MB per table)
/// and `reserve_rehash` doubling temporarily held twice that. jeprof
/// showed: 200 MiB live in `cache_peer_handshake_state` → reserve_rehash
/// path under chaos-only load. On a 128-MB device target with realistic
/// peer count (50-200 active), 1024 entries ≈ 80 KiB is plenty.
pub const MAX_PEER_PUBKEYS_CACHE: usize = 1_024;

/// cap for `peer_sovereign_identities` LRU cache.
///
/// o: lowered 4_096 → 256. Each ValidatedIdentity is
/// ~1-2 KiB; 256 × 1.5 KiB = 384 KiB worst-case. Sized for a typical
/// device's address book — sovereign identity churn beyond this hits
/// LRU rather than holding a full 8 MiB cache.
pub const MAX_PEER_SOVEREIGN_IDENTITIES: usize = 256;

/// cap for `per_session_mlkem_dk` LRU cache.
///
/// o: lowered 4_096 → 256. Tied to session count, not
/// historical peer count. Live session ceiling in `SessionConfig` is
/// typically <100; 256 gives comfortable headroom without paying RSS.
pub const MAX_PER_SESSION_MLKEM_DK: usize = 256;

/// maximum application-payload size accepted by
/// `handle_ipc_send` *before* E2E encryption. Set well below
/// `MAX_FRAME_BODY` (16 MiB) to leave room for E2E envelope/header
/// overhead and to bound the worst-case ciphertext allocation per IPC
/// request. Mirrors the FFI's `VEIL_MAX_DATA_LEN` so a misbehaving
/// local app cannot bypass the FFI cap by speaking IPC directly.
pub const MAX_APP_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Maximum number of peer ML-KEM-768 encapsulation keys cached in `PeerMlKemCache`
///
///
/// Each entry is `peer_id ([u8;32])` → `(ek_bytes (~1184 B), Instant)`.
/// o: lowered 4096 → 512 (612 KiB worst-case). Even under
/// peer churn, 512 entries comfortably covers any device's active address
/// book; new peers re-fetch ek through a cheap handshake-time exchange.
pub const MAX_PEER_MLKEM_CACHE: usize = 512;

/// Maximum number of Vivaldi coordinates cached for known peers.
///
/// o: lowered 32_768 → 1024 (~56 KiB worst-case). Coordinates
/// only benefit RTT-aware routing; 1024 entries cover a meshy network with
/// dense connectivity, beyond which routes can fall back to hop-count
/// without measurable user-visible degradation.
pub const MAX_PEER_VIVALDI_CACHE: usize = 1_024;

/// Cap for the `verified_peer_certs` map (private-network membership certs
/// stashed at handshake for `PnetStatusProvider` IPC lookups).
///
/// Each `MembershipCert` carries an owner signature (Falcon ≈ 1.3 KiB), so
/// 4_096 entries ≈ 5 MiB worst-case. Without a cap the map grew once per
/// distinct authorized peer ever seen and was never reclaimed (not even on
/// session close), a slow leak on long-lived private-network relays. The
/// map is best-effort IPC status only — an evicted-but-still-live peer's
/// status lookup simply misses until its next handshake re-populates it.
pub const MAX_VERIFIED_PEER_CERTS: usize = 4_096;

/// Maximum total entries (across all tables) in the `StaticDirectory`.
/// Chosen to comfortably fit a network of ~1 000 nodes each announcing
/// one attachment + several app endpoints.
pub const MAX_DISCOVERY_ENTRIES: usize = 8_192;

/// Maximum number of transport address strings in a single `RouteResponsePayload`.
/// Enforced on both encode (assert!) and decode (hard error).
pub const MAX_TRANSPORT_ADDRS: usize = 32;

/// Maximum byte length of an ML-KEM public key field in routing messages.
///
/// ML-KEM-768 encapsulation key is exactly 1184 bytes; ML-KEM-1024 is 1568 bytes.
/// 1600 gives one round-number of headroom for future ML-KEM parameter sets.
pub const MAX_MLKEM_PK_LEN: usize = 1600;

/// Maximum byte length of an ML-KEM ciphertext field (E2E envelope).
///
/// ML-KEM-768 ciphertext is exactly 1088 bytes; ML-KEM-1024 is 1568 bytes.
/// 1600 matches `MAX_MLKEM_PK_LEN` for one round-number of headroom. Used as
/// the per-field decode cap so `E2eEnvelope::decode` is self-bounding even if
/// ever invoked on a buffer not already gated by the 16 MiB frame body cap.
pub const MAX_KEM_CIPHERTEXT: usize = 1600;

/// Maximum number of NAT candidates in a single `NatProbeRequest`/`NatProbeReply`.
///
/// A node realistically has at most a handful of addresses; 64 is generous.
pub const MAX_NAT_CANDIDATES: usize = 64;

/// Maximum payload length of a single `EpidemicPayload` frame (64 KiB).
///
/// Epidemic frames carry small control blobs (announcements, short signed records).
/// Capped well below `MAX_FRAME_BODY` to limit per-frame allocation.
// NOTE: must fit the u16 length prefix on the wire — 65_535, NOT 65_536.
// A 65_536-byte payload truncates to 0 when cast to u16 on encode (release
// builds), emitting a corrupt frame whose declared length is 0; the decode
// cap must therefore not admit a size the encode side cannot represent.
pub const MAX_EPIDEMIC_PAYLOAD: usize = 65_535;

/// Maximum signature length accepted in DHT control payloads (e.g. DELETE).
///
/// 64 KiB covers the largest NIST PQC standard signature:
/// SLH-DSA-256f (SPHINCS+) produces ~49 856 bytes, leaving ≈30 % headroom
/// for future algorithms. For reference: Ed25519 = 64 B
/// Falcon-1024 = 1 280 B, ML-DSA-87 = 4 595 B.
pub const MAX_DHT_SIG_BYTES: usize = 65_536;

/// Maximum byte length of a *signature* public key in DHT control payloads
/// (e.g. `DeletePayload`). Must cover the largest hybrid identity pubkey —
/// Ed25519(32) + Falcon-1024(1793) = 1825 bytes — so that hybrid-identity
/// owners can delete their own records. `MAX_MLKEM_PK_LEN` (1600) is the
/// wrong cap here: it sizes ML-KEM *encapsulation* keys, not signature
/// pubkeys, and rejects the 1825-byte hybrid-1024 pubkey. 2048 matches
/// `identity_document::MAX_PUBKEY_BYTES` and leaves headroom.
pub const MAX_SIGNATURE_PUBKEY_BYTES: usize = 2048;

/// Maximum number of relay node-IDs in a single `RouteResponsePayload`.
pub const MAX_RELAY_IDS: usize = 32;

/// maximum number of capability/region labels a target may
/// advertise in a single `RouteResponsePayload`. Labels are 4-byte tags
/// (e.g. `b"exit"`, `b"low\0"`, `b"qiwi"`) signed by the target so that
/// requesters can filter routes by attribute without trusting intermediate
/// relays. Cap kept tight to bound on-wire overhead (8 × 5 bytes = 40 B
/// added to RouteResponse) and to discourage label-pollution attacks where
/// a node tries to match every conceivable filter.
pub const MAX_TARGET_LABELS: usize = 8;

/// byte width of one label. Chosen to match the existing
/// anycast service-tag width (`[u8; 4]`) so operators can reuse a single
/// taxonomy across both subsystems (e.g. `b"mbox"` works as anycast tag
/// AND as route label).
pub const LABEL_WIDTH: usize = 4;

/// Maximum number of gateway references in a single `AnnounceAttachmentPayload`.
pub const MAX_GATEWAYS: usize = 32;

/// Maximum number of leaves simultaneously attached to a single Gateway or Core node.
///
/// Enforced by `AttachmentTable::attach`. Re-attach (renewal of an existing
/// lease) is always allowed regardless of this limit.
pub const MAX_GATEWAY_ATTACHMENTS: usize = 4096;

/// Maximum age of a `RouteAnnounce` timestamp (seconds).
///
/// Announcements older than this relative to the local clock are silently
/// dropped. A generous window is needed because gossip propagation adds
/// latency (up to `max_gossip_hops` × per-hop delay).
pub const MAX_ROUTE_ANNOUNCE_AGE_SECS: u32 = 300; // 5 minutes

/// Maximum allowed future skew in a `RouteAnnounce` timestamp (seconds).
///
/// **Gossip tier** — see [`crate::time_validity::GOSSIP_SKEW_SECS`].
/// Announcements with `timestamp > now + skew` are dropped to prevent
/// injection of long-lived "future" routes.  Tighter than the
/// Interactive tier (60 s) because a 30-second-old announce is already
/// obsolete on a busy mesh.
///
/// `u32` (not `u64`) for wire-format compactness.
pub const MAX_ROUTE_ANNOUNCE_SKEW_SECS: u32 = crate::time_validity::GOSSIP_SKEW_SECS as u32; // 30 seconds

/// Maximum byte length of a single transport address string (limited by u8 length prefix).
pub const MAX_TRANSPORT_STR_LEN: usize = 255;

/// Maximum number of node contacts in a `FindNodeResponse` or `FindValueResponse::Nodes`.
pub const MAX_NODES_PER_RESPONSE: usize = 32;

/// Maximum allowed clock skew for `DeliveryEnvelope::created_at`.
///
/// **Wire tier** — see [`crate::time_validity::WIRE_SKEW_SECS`].
/// **Wire-stable v1** — changing this requires a wire-format version
/// bump (cross-version verifier compat).
///
/// Envelopes with `created_at > now + MAX_CLOCK_SKEW_SECS` are rejected by
/// the relay-forward path to prevent TTL-saturation attacks: an attacker who
/// sets `created_at` far in the future can otherwise make envelopes that never
/// expire (because `created_at + ttl_secs > u64::MAX` saturates to `u64::MAX`).
pub const MAX_CLOCK_SKEW_SECS: u64 = crate::time_validity::WIRE_SKEW_SECS; // 300 s = 5 minutes // STABLE v1

/// Maximum number of relay hops a `ForwardPayload` may traverse.
///
/// A relay node drops any `DELIVERY_FORWARD` frame whose `relay_hops` field is
/// already at this limit, preventing multi-node routing loops from circulating
/// indefinitely. The counter is incremented by each relay hop and encoded as a
/// trailing byte in the `ForwardPayload` wire format (backward-compatible: old
/// nodes that do not encode this field are treated as having `relay_hops = 0`).
///
/// 16 hops is well above any realistic veil diameter while still terminating
/// a cycle within one full revolution.
pub const MAX_RELAY_HOPS: u8 = 16; // STABLE v1

/// Maximum hops for DHT-routed recursive relay.
///
/// Each RecursiveRelay frame has its hop_count decremented at every transit node.
/// O(log N) hops cover up to 2^20 ≈ 1M nodes with 20 hops.
pub const MAX_RECURSIVE_RELAY_HOPS: u8 = 20;

/// Trigger a session rekey after this many bytes have been sent/received on the session.
/// 128 GiB keeps nonce space well below ChaCha20-Poly1305's 2^64 counter limit
/// (≈ 2^31 frames at 64 KiB max body, vs 2^96 nonce bits — many orders of magnitude
/// of headroom). Each rekey runs a fresh `kex::generate_ephemeral` DH + HKDF, so
/// forward secrecy holds either way; this default favours minimal rekey churn for
/// long-lived peer sessions. Operators chasing tighter forward-secrecy windows
/// (e.g. matching `MLKEM_REKEY_BYTES_THRESHOLD` = 100 MiB) lower this via
/// `[session] rekey_bytes_threshold` in `config.toml`.
pub const REKEY_BYTES_THRESHOLD: u64 = 128 * 1024 * 1024 * 1024;

/// Trigger a session rekey after this many seconds since the last rekey (or session start).
/// 32 days = 2_764_800 s. Long-lived sessions still get periodic forward secrecy without
/// thrashing rekey state for short transient connections. Operators chasing tighter
/// FS windows lower this via `[session] rekey_time_threshold_secs` in `config.toml`
/// (e.g. 3600 to match `MLKEM_REKEY_TIME_THRESHOLD_SECS`).
pub const REKEY_TIME_THRESHOLD_SECS: u64 = 32 * 24 * 3600;

/// Trigger an ML-KEM intra-session E2E key rotation after this many bytes of E2E traffic
/// have been exchanged on the session. Each rotation generates a fresh ephemeral
/// encapsulation key so that captured ciphertext from before the rotation cannot
/// be decrypted with the new decapsulation key.
///
/// Raised 100 MiB → 128 GiB to match `REKEY_BYTES_THRESHOLD`. At high-throughput
/// workloads (ogate tunnel @ 540 Mbps = 67 MB/s) the 100-MiB threshold fired a
/// rekey every ~1.5 s, burning Ed25519 signing CPU on every cycle without any
/// real forward-secrecy benefit at such short scales (the `MLKEM_REKEY_TIME_THRESHOLD_SECS = 1h`
/// cap already provides time-based rotation). 128 GiB now matches the session-rekey
/// cadence — operators chasing tighter FS lower both thresholds together in
/// `node.toml`.
pub const MLKEM_REKEY_BYTES_THRESHOLD: u64 = 128 * 1024 * 1024 * 1024;

/// Trigger an ML-KEM intra-session E2E key rotation after this many seconds since the last
/// rotation (or session start). 1 hour limits the exposure window of any single
/// ephemeral encapsulation key regardless of traffic volume.
pub const MLKEM_REKEY_TIME_THRESHOLD_SECS: u64 = 3600;

/// Recommended PoW difficulty for production deployments (session bootstrap).
/// ~65 000 hashes on average; solved in < 1 ms on modern hardware.
/// Raise to 20 on high-traffic relay nodes.
pub const RECOMMENDED_PRODUCTION_POW_DIFFICULTY: u8 = 16;

/// Hard cap on the `difficulty` field accepted in an inbound `PowChallenge`.
///
/// A malicious acceptor could set `difficulty = 255`, requiring the requester to
/// Session PoW uses BLAKE3 (fast): difficulty=24 → ~16M hashes → ~17 ms.
/// Rejects challenges above this threshold to prevent solver abuse.
pub const MAX_POW_DIFFICULTY: u8 = 24;

/// Maximum DHT STORE + FIND_NODE requests a single peer may send per window.
/// Default window is 60 seconds.
///
/// bumped from 200 → 2000 after stand-load observations where a
/// Core node with ~100 application records × K=20 closest neighbours running
/// `DhtRepublish` in burst (all keys' jitter-windows overlap during convergence)
/// produces ≥ 5 STOREs/s incoming from a single peer. 200 is sustainable on
/// sparse nets but flapped `abuse.auto_ban` loops under even light production
/// load. The new ceiling 2000/60s ≈ 33/s tolerates K×stored_records_per_neighbour
/// bursts with headroom, and still caps abuse (ethically-sized attack would
/// saturate this in ~30s and trip violation tracker).
pub const MAX_DHT_OPS_PER_PEER_PER_WINDOW: u32 = 2000;

/// Default time window for `DhtQuota`.
pub const DHT_QUOTA_WINDOW_SECS: u64 = 60;

/// token-bucket capacity per Kademlia bucket.
///
/// Replaces the old hard-coded `1 insert / sec / bucket` rate-limit with
/// a proper token bucket: bursts of up to `DHT_BUCKET_TOKENS_MAX` are
/// allowed (matches startup-mesh-race needs of `insert_trusted`)
/// then long-term rate is capped at `DHT_BUCKET_TOKEN_REFILL_PER_SEC`.
/// Without this an eclipse attacker who can just wait still saturates a
/// targeted bucket — the per-bucket cap is `K = 20`, so 20 bursts × 5s
/// apart = 100s to fully poison a bucket in the legacy design. Token
/// bucket allows the same long-term rate but rejects sustained pressure
/// in well under one second.
pub const DHT_BUCKET_TOKENS_MAX: u32 = 5;

/// token refill rate (tokens per second) for the
/// per-bucket token bucket. At `1.0` matches the legacy long-term rate
/// of `1 insert / sec / bucket`.
pub const DHT_BUCKET_TOKEN_REFILL_PER_SEC: f64 = 1.0;

/// base of the exponential backoff applied to
/// a bucket whose tokens are exhausted (in seconds). When the bucket
/// rate-limits an insert, the next insert from that bucket must wait at
/// least `DHT_BUCKET_BACKOFF_BASE_SECS * 2^consecutive_hits` seconds
/// capped at `DHT_BUCKET_BACKOFF_MAX_SECS`. Forces an attacker who
/// sustains pressure on one bucket to back off exponentially even though
/// the bucket would otherwise refill at `1.0/s`.
pub const DHT_BUCKET_BACKOFF_BASE_SECS: u64 = 1;

/// cap on the per-bucket exponential-backoff
/// window. At `60s` an attacker pushing a bucket through the backoff
/// states transitions through 1s, 2s, 4s, 8s, 16s, 32s, 60s — total
/// ≈ 2 minutes of denial after roughly seven sustained-pressure events.
pub const DHT_BUCKET_BACKOFF_MAX_SECS: u64 = 60;

/// maximum cumulative `APP_BIND` decode failures
/// per IPC client connection. A buggy or hostile local app spamming
/// malformed `APP_BIND` frames previously consumed unbounded IPC-write
/// cycles. When this cap is exceeded the IPC session is terminated.
/// 16 leaves abundant slack for honest retry / corruption recovery
/// while bounding the worst case.
pub const MAX_BIND_DECODE_FAILURES: u32 = 16;

/// maximum candidates the QUIC hole-puncher
/// will fan out to in a single attempt. Each candidate triggers an
/// outbound `connect_with` task; legitimate hole-punch needs are
/// bounded by the number of legitimate routes a peer can have (one
/// `host`, one `srflx` from each STUN, optional `prflx`/`relay`).
/// Beyond ~5 candidates the marginal probability of success collapses
/// while the resource cost (concurrent tasks + UDP sockets) grows
/// linearly. Cap at 10 to leave headroom while preventing an attacker
/// from forcing O(N²) sort-and-fan-out on every punch attempt.
pub const MAX_HOLE_PUNCH_CANDIDATES: usize = 10;

/// maximum contacts from the same /16 IPv4
/// (or /32 IPv6) "AS-proxy" prefix allowed in a single k-bucket.
///
/// Complements the existing `MAX_NODES_PER_SUBNET_PER_BUCKET` (24).
/// Cloud-hosted state-actor infrastructure usually rents at-most a
/// few /16 ranges per provider; capping a single /16 to half a bucket
/// (`K/2 = 10`) leaves room for the legitimate edge case of a cluster
/// inside one AS while preventing one BGP-announced range from
/// fully eclipsing a bucket.
pub const MAX_NODES_PER_AS16_PER_BUCKET: usize = 10;

/// Per-peer ceiling on `NatProbeRequest` / `NatProbeReply` frames forwarded
/// (relay-mode) on behalf of that peer over the standard `DHT_QUOTA_WINDOW_SECS`.
///
///round 7: without this gate, a peer that forwards
/// NAT probes through us as coordinator can amplify their own bandwidth
/// ~2× per relay hop (1 inbound request → 1 outbound forward; 1 inbound
/// reply → 1 outbound forward). Coupled with the existing
/// `MAX_DHT_OPS_PER_PEER_PER_WINDOW` rate on recursive forwards, an
/// uncapped NAT-probe forward path lets an attacker burn a victim's
/// outbound capacity on a budget Android phone for free. The ceiling
/// is intentionally tight: legitimate NAT traversal traffic is a small
/// number of probes per minute per pair (bounded by `MAX_NAT_PROBE_WAITERS
/// = 256` initiator slots × ~few coordinator round-trips). 120/min ≈ 2/s
/// per peer leaves order-of-magnitude headroom for real usage and catches
/// any frame-rate flooder.
pub const MAX_NAT_PROBE_FORWARDS_PER_PEER_PER_WINDOW: u32 = 120;

// ── Reliable delivery ─────────────────────────────────────────────

/// Maximum number of delivery attempts before the sender gives up and emits
/// `DeliveryStatus(FAILED)` to the originating application.
pub const MAX_DELIVERY_ATTEMPTS: u32 = 3;

/// Per-attempt timeout before a retransmit is triggered (milliseconds).
pub const DELIVERY_ACK_TIMEOUT_MS: u64 = 5_000;

/// Interval at which the `PendingAckTracker` background task checks for
/// timed-out in-flight envelopes (milliseconds).
pub const DELIVERY_ACK_CHECK_INTERVAL_MS: u64 = 1_000;

/// Maximum number of concurrent in-flight `require_ack` envelopes tracked by
/// `PendingAckTracker`. Prevents unbounded memory growth when a local
/// application sends many acknowledged messages without waiting for replies.
/// Registrations that would exceed this limit are silently dropped (the
/// envelope is still sent, just without at-most-once retransmit semantics).
pub const MAX_PENDING_ACK_ENTRIES: usize = 1_024;

/// per-peer cap on in-flight pending-ack entries.
/// Without this, a single misbehaving (or unreachable) peer destination
/// could occupy every slot in the global `MAX_PENDING_ACK_ENTRIES` budget
/// and starve retransmit tracking for all other peers. 16 leaves plenty
/// of headroom for normal bursty senders while bounding worst-case abuse.
pub const MAX_PENDING_ACK_PER_PEER: usize = 16;

// ── Application-layer stream limits ──────────────────────────────────────────

/// Maximum total concurrently open application streams across all peers.
/// Each stream holds ~80 bytes; 65 536 streams ≈ 5 MB worst case.
pub const MAX_TOTAL_STREAMS: usize = 65_536;

/// Maximum concurrently open application streams **per remote peer**.
/// Prevents a single misbehaving peer from exhausting the global quota.
pub const MAX_STREAMS_PER_PEER: usize = 256;

/// Maximum send-window size for an application stream (16 MiB).
/// `APP_WINDOW_UPDATE` increments are clamped so that `send_window`
/// never grows beyond this value, keeping flow-control meaningful.
pub const MAX_STREAM_SEND_WINDOW: u32 = 16 * 1024 * 1024; // STABLE v1

/// Maximum receive-side window for a single app stream.
/// Currently equal to `MAX_STREAM_SEND_WINDOW`; a separate constant is
/// kept so the two can be tuned independently in the future.
pub const MAX_STREAM_RECV_WINDOW: u32 = MAX_STREAM_SEND_WINDOW;

// ── Channel capacity limits ───────────────────────────────────────

/// Capacity of the bounded MPSC channel that carries reassembled OVL1 frames
/// from `drain_uni_stream` tasks to the `QuicSessionTransport` consumer.
///
/// 1 024 in-flight frames at ~64 B header + ~1 500 B average body ≈ 1.6 MB per
/// connection. Frames are dropped (with a tracing warning) when the channel is
/// full, providing backpressure without blocking the QUIC network I/O task.
pub const QUIC_INCOMING_CHANNEL_CAP: usize = 1_024;

/// Capacity of the bounded MPSC channels used for TUN outbound and inbound
/// packet queues in `TunDevice`.
///
/// 512 MTU-sized packets (≤ 65 535 B each, but typically ~1 500 B) ≈ 768 KB
/// worst-case. Excess packets are dropped, which is the correct behaviour for
/// an IP TUN device (kernel drop-tail mirrors this under pressure).
pub const TUN_CHANNEL_CAP: usize = 512;

/// Capacity of the bounded MPSC channel used for route-miss signals in the
/// runtime maintenance loop.
///
/// Route-miss signals are best-effort: if the consumer is slow the oldest
/// signals are simply dropped. 256 covers typical burst sizes even on
/// heavily-loaded relay nodes.
pub const ROUTE_MISS_CHANNEL_CAP: usize = 256;

// ── PoW challenge table ───────────────────────────────────────────────────────

/// Maximum number of unanswered PoW challenges stored in `pow_pending`.
/// Entries are evicted oldest-first when the cap is reached.
pub const MAX_POW_PENDING: usize = 256;

// ── PoW solver resource limits ─────────────────────────────────────

/// Maximum number of `spawn_blocking` PoW solver tasks that may run concurrently
/// across all sessions.
///
/// Each PoW task saturates one OS thread for up to ~17 ms (difficulty=24 on 1 GHz).
/// At 4 concurrent tasks the solver pool can use at most 4 cores for PoW work
/// leaving headroom for tokio's I/O threads even on a 4-core node. An acceptor
/// that sends more challenges than this limit allows will have the excess silently
/// dropped — the requester logs a warning and does not reply.
pub const MAX_CONCURRENT_POW_SOLVERS: usize = 4;

/// Maximum sum of `difficulty` bits across all currently active PoW solver tasks.
///
/// Independently caps the total CPU commitment even when individual tasks have low
/// difficulty (preventing a flood of trivial tasks from saturating the thread pool).
/// Set to `MAX_CONCURRENT_POW_SOLVERS × MAX_POW_DIFFICULTY = 4 × 24 = 96`.
pub const MAX_POW_ACTIVE_DIFFICULTY_SUM: u64 = 96;

/// Maximum number of distinct `challenge_nonce` values retained in the PoW
/// challenge deduplication set.
///
/// Sized to `4 × MAX_POW_PENDING` so that even with burst relaying across many
/// sessions there is enough room to remember recently-seen nonces without false
/// positives.
pub const MAX_POW_CHALLENGE_SEEN_SIZE: usize = 1_024;

/// Maximum age of an unanswered PoW challenge before it is treated as stale
/// and eligible for eviction.
pub const POW_CHALLENGE_TTL_SECS: u64 = 60;

/// Reputation entries older than this are evicted by the periodic cleanup
/// task. Active sessions are never evicted — this only frees
/// slots occupied by long-gone peers so new ones get tracked. 7 days = a
/// conservative threshold that preserves history across normal uptime gaps.
pub const REPUTATION_STALE_SECS: u64 = 7 * 24 * 3600;

/// Per-peer minimum interval between VersionVectorSync-triggered RouteUpdate
/// replies. A peer that sends VVSync more frequently than this
/// is silently ignored — it already has a recent update pending. Prevents
/// amplification loops where a compromised peer repeatedly triggers O(N)
/// RouteUpdate fan-out.
pub const VVSYNC_MIN_INTERVAL_SECS: u64 = 60;

/// Maximum number of peer_ids tracked in the VVSync rate-limit cache.
/// Scales with expected concurrent peer count; entries expire after
/// `VVSYNC_MIN_INTERVAL_SECS`.
pub const MAX_VVSYNC_SEEN_SIZE: usize = 4_096;

/// Maximum number of concurrently pending diagnostic probes (ping/traceroute).
/// If the cap is reached, stale (closed-receiver) entries are evicted first;
/// if the map is still full, new registrations are silently dropped.
pub const MAX_PENDING_DIAG: usize = 256;

/// Maximum number of concurrently pending recursive DHT queries.
/// The initiator allocates a oneshot sender per in-flight query; the remote
/// `RecursiveResponse` fulfils it. Without a cap, a stuck receiver side would
/// let the map grow unbounded. IPC initiators enforce this cap when
/// registering a new pending entry in `FrameDispatcher::pending_recursive`
/// (closed-receiver entries evicted first, then the insert is silently dropped
/// if the map is still full).
pub const MAX_PENDING_RECURSIVE: usize = 1_024;

/// hygiene: maximum concurrent NAT-probe waiters per
/// dispatcher. Each entry is a `(session_token, oneshot::Sender)`
/// pair registered when the runtime initiates a relay-mode
/// `NatProbeRequest` via `attempt_nat_traversal_via`; the dispatcher's
/// `NatProbeReply` handler removes the entry when the matching reply
/// arrives. Without a cap, a buggy or malicious caller could fire
/// thousands of probes (say, scanning the network for reachability)
/// and grow the map until OOM. At 256 entries the hashmap stays
/// well under 64 KiB even with the senders' inline state, fits the
/// realistic usage pattern (a phone discovering a handful of contacts'
/// candidates, not a probe storm), and matches the order of magnitude
/// of `MAX_PENDING_RECURSIVE` / 4 (NAT probes are coarser-grained than
/// DHT recursive lookups, so the bound can be tighter).
pub const MAX_NAT_PROBE_WAITERS: usize = 256;

/// Maximum wall-clock seconds allowed for a full OVL1 handshake (HELLO →
/// IDENTITY → CAPABILITIES → CONFIRM). If the remote peer stalls at any
/// step, the connection is closed. Prevents "Slow Loris" style attacks where
/// an adversary occupies a session slot indefinitely.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Maximum byte length of a single DHT value accepted via a STORE request from
/// a remote peer. Values larger than this are rejected as a protocol violation.
/// 16 KiB holds the largest legitimate record: a fully-rotated (up to
/// `MAX_IDENTITY_KEYS`) Ed25519+Falcon-1024 hybrid `IdentityDocument`
/// (≈15 KiB; see `identity_document::MAX_IDENTITY_DOCUMENT_BYTES`). Name
/// claims and app-endpoint descriptors are far smaller.
///
/// Memory note: worst-case DHT store memory is `max_store_entries ×
/// MAX_DHT_VALUE_BYTES`. Raising this from 4 KiB to 16 KiB was paired with
/// lowering the default `DhtConfig::max_store_entries` from 100_000 to
/// 25_000 so the product — and thus the worst-case memory ceiling — stays at
/// ≈400 MB (100_000×4 KiB == 25_000×16 KiB). Operators with more RAM raise
/// `max_store_entries` (and optionally set `max_store_bytes`) explicitly.
pub const MAX_DHT_VALUE_BYTES: usize = 16 * 1024;

/// Number of DHT replicas to fan a PUT out to. After
/// publishing locally, the runtime sends `RecursiveQuery(STORE, key, value)`
/// to the K closest peers in keyspace so the value remains reachable
/// when the publisher itself goes offline. K=8 mirrors Kademlia's
/// classic bucket size: large enough that any 1-2 of the K dropping
/// out leaves quorum, small enough that the per-PUT bandwidth cost
/// (≈ K × value_size) stays cheap on mobile/cellular links.
pub const DHT_REPLICATION_K: usize = 8;

// ── Route discovery ────────────────────────────────────────────────

/// Wire size of a `RouteDiscoveryPacket` (fixed).
pub const ROUTE_DISCOVERY_PACKET_SIZE: usize = 73;

/// Minimum wire size of a `RouteDiscoverOfferPayload` (header only, no transports).
pub const ROUTE_DISCOVER_OFFER_MIN_SIZE: usize = 33;

/// Default initial TTL for route discovery packets.
pub const ROUTE_DISCOVERY_INITIAL_TTL: u8 = 16;

/// Default PoW difficulty for route discovery packets.
pub const ROUTE_DISCOVERY_POW_DIFFICULTY: u8 = 16;

/// Per-source rate limit burst for discovery packet forwarding.
pub const DISCOVERY_RATE_BURST: u32 = 3;

/// Per-source rate limit refill interval (seconds) for discovery forwarding.
pub const DISCOVERY_RATE_REFILL_SECS: u64 = 600;

/// Global rate limit burst for all discovery packets (packets/sec).
pub const DISCOVERY_GLOBAL_RATE_BURST: u32 = 50;

/// Number of routes in `RouteCache` at which the discovery interval reaches maximum.
pub const DISCOVERY_MAX_ROUTES_TARGET: usize = 8;

/// Minimum interval between automatic discovery requests (seconds).
pub const DISCOVERY_MIN_INTERVAL_SECS: u64 = 3_600; // 1 hour

/// Maximum interval between automatic discovery requests (seconds).
pub const DISCOVERY_MAX_INTERVAL_SECS: u64 = 172_800; // 48 hours

/// Maximum number of pending `DiscoveryInitiator` per-src rate-limit entries.
/// Entries are evicted when the map reaches this size (oldest-idle first).
pub const MAX_DISCOVERY_RATE_ENTRIES: usize = 4_096;

/// Conservative hash rate (H/s) used to compute discovery PoW timestamp window.
/// Calibrated for weak embedded hardware / old mobile devices.
pub const DISCOVERY_POW_CONSERVATIVE_HASH_RATE: u64 = 50_000;

/// Minimum timestamp validity window for discovery PoW packets (seconds).
pub const DISCOVERY_POW_MIN_WINDOW_SECS: u64 = 600; // 10 minutes

/// Maximum number of simultaneous NAT relay tunnels a node will maintain.
/// Each tunnel is keyed by a 32-bit session_token; entries are removed when
/// the corresponding peer session closes. The cap prevents an authenticated
/// peer from flooding NatRelayRequest frames to exhaust the map.
pub const MAX_RELAY_TUNNELS: usize = 512;

/// Maximum number of entries in the beacon deduplication map (`BeaconReceiver::dedup_seen`).
///
/// Each entry is 32 bytes (node_id key) + 16 bytes (Instant) ≈ 48 bytes.
/// At 4 096 entries the map consumes ≈ 192 KiB — affordable even on embedded nodes.
/// When the cap is reached the map is cleared entirely (cheap reset, brief window of
/// possible re-acceptance is harmless — at most one extra beacon per source).
pub const MAX_BEACON_DEDUP_ENTRIES: usize = 4_096;

/// Max accepted clock-skew (seconds, past or future) on a SIGNED mesh beacon's
/// timestamp. Beyond this a signed beacon is rejected as stale/replayed — so a
/// captured beacon can only redirect the originator's `node_id` for this window
/// instead of forever. Generous enough to tolerate clock skew + several missed
/// beacon intervals; tight enough to bound the replay-redirect window to
/// minutes. (audit cycle-4 M3.)
pub const MAX_BEACON_SKEW_SECS: u64 = 120;

/// Maximum number of peer-observed addresses the dispatcher retains.
/// One entry per active peer (cleaned up on session close), so this is
/// normally well below the active-session limit. The explicit cap is a
/// defence-in-depth guard against edge cases.
pub const MAX_PEER_OBSERVED_ADDRS: usize = 1_024;

// ── Forward-seen / replay dedup ────────────────────────────────

/// Maximum number of `content_id`s retained in the relay deduplication set.
///
/// At 1 000 frames/sec each held for 60 seconds the working set is 60 000
/// entries. 100 000 provides comfortable headroom for burst traffic without
/// allowing an attacker to exhaust the cache by flooding unique content_ids
/// (which would reopen a replay window for older envelopes).
pub const MAX_FORWARD_SEEN_SET_SIZE: usize = 100_000;

/// TTL for entries in the relay deduplication set (seconds).
///
/// 60 seconds covers worst-case round-trip times in a WAN veil. Entries
/// younger than this cannot be replayed; entries older than this are already
/// expired and out-of-window by the TTL of the delivery envelope itself
/// (minimum TTL_SECS is much larger than 60 s in practice).
pub const FORWARD_SEEN_SET_TTL_SECS: u64 = 60;

// ── IPC server limits ──────────────────────────────────────────

/// Maximum number of app endpoints a single IPC client may register.
///
/// Each endpoint spawns a forwarder Tokio task and holds an RAII handle.
/// Without a cap, a malicious local process can exhaust tokio's task budget
/// and node memory by calling APP_BIND in a tight loop.
pub const MAX_IPC_ENDPOINTS_PER_CLIENT: usize = 64;

/// Maximum concurrent locally-originated streams per IPC client connection.
/// The global cap is `MAX_TOTAL_STREAMS = 65_536`; without a per-client cap a
/// single misbehaving local app can open all of them and starve other clients.
/// Counter is decremented when the client receives `STREAM_CLOSE` for one of
/// its opens; resets to zero on reconnect.
pub const MAX_IPC_STREAMS_PER_CLIENT: usize = 256;

// ── Route cache / origin-seq sybil mitigation ─────────────────────

/// Maximum number of distinct origin node_ids tracked in the per-origin
/// announce-sequence cache.
///
/// Must be large enough to resist Sybil-based eviction: an attacker with >N
/// identities can evict legitimate entries, reopening replay windows.
/// 4096 entries × 36 bytes ≈ 144 KiB — negligible memory for strong protection.
pub const MAX_ROUTE_ORIGIN_SEQ_CACHE: usize = 4096;

/// Maximum number of new route (destination) insertions into `RouteCache` that
/// a single peer may contribute via RouteResponse per 60-second window.
///
/// Each RouteResponse inserts one new destination into the cache. 20 per minute
/// covers all legitimate Kademlia iterative lookups (O(log N) ≈ 10 steps for N=1024)
/// while preventing a sybil attacker from flooding the cache with fake destinations
/// in a single burst.
pub const MAX_NEW_ROUTES_PER_PEER_PER_WINDOW: u32 = 20;

// ── Large payload chunking ─────────────────────────────────────────

/// Maximum bytes per chunk body inside a `ChunkPayload` frame (64 KiB).
///
/// Chosen to fit a chunk + frame header comfortably within the 1 MiB default
/// frame body limit while amortising per-frame overhead over many bytes.
pub const MAX_CHUNK_PAYLOAD: usize = 65_536;

/// Maximum number of chunks in a single chunked transfer (16 384 chunks).
///
/// At `MAX_CHUNK_PAYLOAD = 64 KiB` this allows transfers up to 1 GiB.
pub const MAX_TRANSFER_CHUNKS: u32 = 16_384;

/// Total reassembly budget across all in-progress transfers (64 MiB).
///
/// Prevents memory exhaustion when many partial transfers are being accumulated
/// simultaneously. New chunks are rejected if adding them would exceed this cap.
pub const MAX_REASSEMBLY_BYTES: usize = 64 * 1024 * 1024;

/// TTL for a partial chunk transfer in the reassembler (seconds).
///
/// A transfer that has not completed within this window is evicted and all its
/// in-memory chunks freed. The sender can retransmit from scratch.
pub const CHUNK_REASSEMBLY_TTL_SECS: u64 = 300;

// (Obsolete `MAX_TRANSFERS_CONCURRENT` removed with the `veil-transfer`
// `ChunkReassembler`; the relay-chunking reassembler in veil-dispatcher uses its
// own `MAX_CONCURRENT_TRANSFERS` cap.)

// ── Implementation limits — channel capacities ────────────────────────────────

/// Bounded capacity of the per-IPC-client delivery channel (frames queued
/// for an application that has not yet read its socket).
///
/// Phase E27 (2026-05-22): raised 64 → 1024.  Under iperf3-through-ogate
/// testnet with E27 batching, the 64-cap was hit ~5.6 K times in 8 s and dropped
/// 34 % of forwarded packets (`veil_ipc_delivery_drops_total` confirmed),
/// collapsing iperf3 TCP to 30 Kbps.  Each batch envelope is ≤ 60 KiB; 1024
/// slots = ~60 MiB worst-case per client, well within the budget that
/// previously caused the 4096 → 64 cut (which targeted a 60-KiB chat frame
/// rate of 200 msg/s = ~12 MiB/s steady backlog, NOT a burst of much-larger
/// envelopes).  1024 buys ~1 s of buffering — comfortable head-of-line
/// margin for backpressure-to-app to still kick in correctly.
///
/// Historical note:  f: lowered from 4096 (~256 MiB worst-case) to 64
/// under chat-load (200 msg/sec × 60 KiB chat_node frames).  See git log
/// for full rationale.
pub const DELIVERY_CHANNEL_CAP: usize = 1024;

/// Byte budget for the per-IPC-client delivery queue, enforced ALONGSIDE the
/// frame-count cap above.
///
/// The count cap alone bounds frame *count*, not bytes — and a single delivered
/// message can now be large (a relay-chunked transfer reassembles to up to
/// `MAX_REASSEMBLY_BYTES` before the app reads it), so `DELIVERY_CHANNEL_CAP`
/// frames could pin gigabytes against a slow / non-reading client. This caps
/// total in-flight delivery bytes per client: once exceeded, further frames are
/// dropped (counted as `ipc_delivery_drops`) exactly like a count-full queue.
/// 96 MiB leaves headroom above the ~60 MiB steady-state backlog the count cap
/// was tuned for (Phase E27) while bounding the pathological large-frame case.
pub const MAX_DELIVERY_INFLIGHT_BYTES: usize = 96 * 1024 * 1024;

/// Bounded capacity of the per-proxy-stream data channel (APP_DATA chunks
/// queued for an outbound TCP connection that is applying backpressure).
/// At 65536 bytes per chunk this caps memory per proxy stream at ~16 MiB.
/// When the channel is full the stream is closed with APP_CLOSE.
pub const PROXY_STREAM_CHANNEL_CAP: usize = 256;

/// maximum number of concurrent proxy bridges
/// (open SOCKS5 connections through the veil). Each bridge owns a
/// duplex pipe sized at `PROXY_DUPLEX_BUF_SIZE` plus a per-stream
/// channel `PROXY_STREAM_CHANNEL_CAP` × ~64 KiB chunks worst-case.
///
/// At 256 bridges × (`PROXY_DUPLEX_BUF_SIZE` + a few buffered chunks)
/// the proxy's worst-case memory ceiling is ~50 MiB, well-bounded for
/// budget Android devices. New `connect` calls beyond the cap fail
/// with `Socks5Error::ConnectFailed("proxy bridge budget exhausted")`
/// — the SOCKS5 client gets a clean refusal instead of silent OOM.
pub const MAX_PROXY_BRIDGES: usize = 256;

/// per-bridge duplex pipe buffer size (bytes).
///
/// Reduced from the legacy 256 KiB to 64 KiB:
/// * 256 KiB × 512 bridges = 128 MiB baseline — too high for budget
///   Android devices (typical 2-4 GiB total RAM, app limit ~512 MiB).
/// * 64 KiB matches the wire-level `MAX_FRAME_BODY` for typical
///   APP_DATA chunks; one frame fits in the buffer with headroom for
///   pipelined writes.
/// * Lower than 64 KiB starts hurting throughput on lossy networks
///   where the kernel TCP stack can't drain fast enough between writes.
pub const PROXY_DUPLEX_BUF_SIZE: usize = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        delivery::{DeliveryEnvelope, DeliveryStatusPayload},
        mesh::{
            MESH_HEADER_SIZE, MeshAckPayload, MeshBeaconPayload, MeshFrame, RealmId,
            mesh_ack_status,
        },
        session::{
            CapabilitiesPayload, DetachPayload, HelloPayload, KeepalivePayload,
            SessionConfirmPayload, detach_reason,
        },
    };

    // ── Frame header ─────────────────────────────────────────────────────────

    #[test]
    fn frame_header_size_matches() {
        use crate::header::HEADER_SIZE;
        assert_eq!(FRAME_HEADER_SIZE, HEADER_SIZE);
    }

    // ── Session plane wire sizes ─────────────────────────────────────────────

    #[test]
    fn hello_wire_size() {
        let p = HelloPayload {
            ovl1_major: 1,
            node_id: [0u8; 32],
            resume_ticket: None,
            membership_cert_blob: None,
            resume_nonce: None,
        };
        assert_eq!(p.encode().len(), SESSION_HELLO_SIZE);
        assert_eq!(SESSION_HELLO_SIZE, HelloPayload::WIRE_SIZE);
    }

    #[test]
    fn capabilities_wire_size() {
        let p = CapabilitiesPayload::from_node_role(veil_types::NodeRole::Core);
        assert_eq!(p.encode().len(), SESSION_CAPABILITIES_SIZE);
        assert_eq!(SESSION_CAPABILITIES_SIZE, CapabilitiesPayload::WIRE_SIZE);
    }

    #[test]
    fn session_confirm_wire_size() {
        let p = SessionConfirmPayload {
            session_id: [0u8; 32],
            mac: [0u8; 32],
        };
        assert_eq!(p.encode().len(), SESSION_CONFIRM_SIZE);
        assert_eq!(SESSION_CONFIRM_SIZE, SessionConfirmPayload::WIRE_SIZE);
    }

    #[test]
    fn detach_wire_size() {
        let p = DetachPayload {
            reason: detach_reason::NORMAL,
        };
        assert_eq!(p.encode().len(), SESSION_DETACH_SIZE);
        assert_eq!(SESSION_DETACH_SIZE, DetachPayload::WIRE_SIZE);
    }

    #[test]
    fn keepalive_wire_size() {
        let p = KeepalivePayload {
            timestamp_secs: 12345,
        };
        assert_eq!(p.encode().len(), SESSION_KEEPALIVE_SIZE);
        assert_eq!(SESSION_KEEPALIVE_SIZE, KeepalivePayload::WIRE_SIZE);
    }

    // ── Delivery plane wire sizes ─────────────────────────────────────────────

    #[test]
    fn delivery_envelope_header_matches() {
        let e = DeliveryEnvelope {
            recipient: crate::recipient::Recipient::any([0u8; 32]),
            sender_node_id: [0u8; 32],
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0u8; 32],
            created_at: 0,
            ttl_secs: 0,
            payload: vec![],
            trace_id: 0,
            require_ack: false,
        };
        assert_eq!(e.encode().len(), DELIVERY_ENVELOPE_HEADER);
    }

    #[test]
    fn delivery_status_wire_size() {
        let p = DeliveryStatusPayload {
            content_id: [0u8; 32],
            status: 0,
            mac: [0u8; 32],
        };
        assert_eq!(p.encode().len(), DELIVERY_STATUS_SIZE);
    }

    // ── Mesh plane wire sizes ─────────────────────────────────────────────────

    #[test]
    fn mesh_frame_header_matches() {
        assert_eq!(MESH_FRAME_HEADER, MESH_HEADER_SIZE);
        let f = MeshFrame::new(RealmId([0u8; 16]), [0u8; 32], [0u8; 32], 1, vec![]);
        assert_eq!(f.encode().len(), MESH_FRAME_HEADER);
    }

    #[test]
    fn mesh_beacon_wire_size() {
        // v2 encodes role_flags(1) + addr_len(1) + battery_level(1) + timestamp(8),
        // so min size is MESH_BEACON_SIZE + 11 = 59.
        let b = MeshBeaconPayload::new_basic([0u8; 32], RealmId([0u8; 16]));
        assert!(
            b.encode().len() >= MESH_BEACON_SIZE,
            "must include at least the v1 fields"
        );
        assert_eq!(b.encode().len(), MESH_BEACON_SIZE + 3 + 8); // +role_flags +addr_len +battery_level +timestamp
    }

    #[test]
    fn mesh_ack_wire_size() {
        let a = MeshAckPayload {
            frame_id: [0u8; 16],
            status: mesh_ack_status::OK,
        };
        assert_eq!(a.encode().len(), MESH_ACK_SIZE);
    }
}
