//! Shared primitive types for the Veil network.
//!
//! Tier 0 leaf crate. Hosts small types that ALL upper layers
//! (`cfg`, `proto`, `crypto`, `node`) need to reference, without
//! inducing cyclic dependencies between those layers.
//!
//! # Why this crate exists
//!
//! Before extraction, `SignatureAlgorithm` lived in
//! `veilcore::cfg::model`. But `proto` needs it (encoding
//! algo bytes on the wire) and so does `crypto` (selecting the
//! signing primitive). Both `proto` and `crypto` belong below
//! `cfg` in the dependency hierarchy, so having them depend on
//! `cfg` for one enum created a cycle that blocked extraction of
//! either crate. Moving the type here breaks that cycle.
//!
//! Future shared primitives (`NodeId`, `PeerId`, `LinkId`
//! `ListenId`) will migrate here in subsequent phases as their
//! call sites are untangled from cfg-specific helpers.
//!
//! # No external dependencies beyond serde
//!
//! Crate-level discipline: this crate must NEVER depend on other
//! workspace crates. It's the floor. External deps limited to
//! `serde` (for derive on shared enums); even `std` is the only
//! Rust runtime used.

use serde::{Deserialize, Serialize};

// ── Cross-crate session broadcast surface ────────────────────────────────────
//
// Multiple Tier-3 crates (veil-routing's miss_handler, future
// veil-pex / veil-proxy / veil-ipc) need to push outbound frames
// through the session-runtime's `SessionTxRegistry`. Inverting the dep
// via this trait lets each consumer crate stay free of veilcore.
//
// The methods take `&self` because the production impl (held as
// `Arc<Mutex<SessionTxRegistry>>` everywhere) handles its own interior
// mutability. `Vec<u8>` for `send_to` matches the existing callers that
// build a fresh frame per peer; `Arc<[u8]>` for `send_to_all` matches the
// shared-fan-out hot path in `SessionTxRegistry::send_to_all`.

use std::sync::Arc;

/// Session-tx fan-out surface. Implemented by veilcore's
/// `Arc<Mutex<node::session::tx_registry::SessionTxRegistry>>` via a small
/// adapter newtype in `node::session_glue`.
pub trait FrameBroadcaster: Send + Sync {
    /// Send `bytes` to a single registered peer at `priority`. Returns
    /// `false` if the peer is not registered or its channel is closed/full.
    fn send_to(&self, peer_id: &[u8; 32], priority: u8, bytes: Vec<u8>) -> bool;

    /// Fan `bytes` out to every registered session at `priority`. Closed
    /// channels are evicted; full channels drop the frame.
    fn send_to_all_with_priority(&self, priority: u8, bytes: Arc<[u8]>);

    /// Convenience: `send_to_all_with_priority(INTERACTIVE, bytes)` —
    /// matches the historical default behaviour of `SessionTxRegistry::send_to_all`.
    fn send_to_all(&self, bytes: Arc<[u8]>) {
        // Constant kept here so consumers don't have to import veil-proto
        // just to call this method. Mirrors `proto::header::priority::INTERACTIVE`.
        const INTERACTIVE: u8 = 1;
        self.send_to_all_with_priority(INTERACTIVE, bytes);
    }

    /// Snapshot of the node_ids of every currently-registered (live) session.
    /// Used by veil-pex (random-walk seed selection, response routing) and
    /// available for any future module that needs to enumerate connected
    /// peers without importing veilcore's `SessionTxRegistry` concretely.
    fn active_node_ids(&self) -> Vec<[u8; 32]>;
}

// ── MlKemEkResolver — reactive cold-start ML-KEM-768 EK fetch ─────────────────
//
// Epic 486.1 slice 3 (audit batch 2026-05-23): closes the "no ML-KEM key →
// silent drop" gap when an IPC client sends a datagram to a peer that the
// daemon has not yet handshaked with.  Pre-fix the daemon-side
// `peer_mlkem_keys` cache populated **only** at handshake completion (see
// `peer_handshake.rs`); cold-start relay-routed sends would hit the
// "no recipient_ek" branch in `handle_ipc_send` and return `NO_E2E_KEY`.
//
// This trait lets the IPC layer trigger a reactive **DHT lookup** of the
// peer's `MlKemKeyCert` (already published at startup by every sovereign
// identity per Epic 462.12) without taking a direct dependency on
// veil-node-runtime from veil-ipc.  The IPC layer holds an `Option<
// Arc<dyn MlKemEkResolver>>`; production wireup hands it the runtime-side
// `DhtMlKemEkResolver` from service_tasks.rs.
//
// ## API contract
//
// `resolve_ek` walks the DHT to fetch + verify the recipient's current
// ML-KEM-768 EK.  Steps the implementor performs:
//
// 1. Recursive-get the peer's `IdentityDocument` (verified chain).
// 2. Recursive-get the peer's `InstanceRegistry`; pick a recent-active
//    instance by `last_seen_unix_ms`.
// 3. Recursive-get the matching `MlKemKeyCert` at
//    `MlKemKeyCert::dht_key(node_id, instance_id)`.
// 4. Verify the cert chain via `verify_mlkem_cert(cert, doc, now)`.
// 5. Return `cert.mlkem_pubkey` (1184 bytes) or `None`.
//
// `None` masks every failure mode (missing record, sig invalid, decode
// error, network timeout) — callers fall back to "no E2E key" semantics
// identically.  Diagnostic detail belongs in the implementor's logging
// path, not in the trait surface.
//
// ## Why `Pin<Box<dyn Future>>` rather than `async fn`
//
// veil-types is a Tier-0 leaf crate with zero async deps.  Adding the
// `async-trait` macro crate would invert the layering.  This shape
// matches the existing `BroadcastFn` trait in `veil-transport::rotation`
// (also for the same reason) and keeps the trait object-safe.
pub trait MlKemEkResolver: Send + Sync {
    /// Reactively fetch + verify the recipient's ML-KEM-768 encapsulation
    /// key from the DHT.  Returns `None` on any failure (no document, no
    /// instance, no cert, signature invalid, timeout).  Callers should
    /// treat `None` the same as "key not cached" — i.e. drop the
    /// outbound frame with the usual `NO_E2E_KEY` error.
    fn resolve_ek(
        &self,
        target_node_id: [u8; 32],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Vec<u8>>> + Send + '_>>;
}

/// Reactively resolve a node's relay X25519 KEM public key by `node_id` over
/// the DHT (fetch + verify its signed `RelayKeyRecord` against its
/// `IdentityDocument`). Returns `None` on any failure (no record, no document,
/// signature invalid, expired, timeout). Lets an OFFLINE receiver advertise an
/// always-on third-party relay as its mailbox host — and a sender seal an
/// anonymous deposit to it — knowing only that relay's `node_id`.
pub trait RelayKeyResolver: Send + Sync {
    fn resolve_relay_x25519(
        &self,
        target_node_id: [u8; 32],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<[u8; 32]>> + Send + '_>>;
}

// ── AnonOnionSender — authenticated anonymous send over rendezvous ────────────
//
// Lets the IPC layer originate an authenticated anonymous onion send
// (`anonymous_authenticated` flag) without depending on veil-node-runtime: the
// runtime implements this trait and is injected as `Option<&dyn AnonOnionSender>`
// on the send context, exactly like `MlKemEkResolver`. The implementation
// resolves the recipient's RendezvousAd, signs + fragments an `AuthAppDeliver`,
// and onion-routes it to the rendezvous relay.

/// Local (pre-transmit) failure reasons for an authenticated anonymous send.
/// All map to an IPC `AppSendFailed` error code; once the cell is on the wire
/// the result is always `Ok` (fire-and-forget, no end-to-end ACK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonOnionSendError {
    /// No sovereign identity loaded — cannot sign.
    NoIdentity,
    /// No valid RendezvousAd for the recipient (it hasn't opted in to receiving,
    /// or its ad is unresolvable / stale).
    NoRendezvous,
    /// Could not build a circuit (insufficient relay candidates).
    NoRelays,
    /// Message exceeds the authenticated-send size ceiling.
    PayloadTooLarge,
}

/// Originates an authenticated anonymous onion send to a recipient over the
/// rendezvous transport. Implemented by the node runtime; consumed by the IPC
/// send handler.
pub trait AnonOnionSender: Send + Sync {
    /// Send `data` to `(receiver_node_id, app_id, endpoint_id)` as an
    /// authenticated anonymous message. The recipient cryptographically verifies
    /// the sender; no relay learns the sender's location. The circuit length is
    /// the implementation's configured default. Errors are local/pre-transmit.
    fn send_authenticated<'a>(
        &'a self,
        receiver_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &'a [u8],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), AnonOnionSendError>> + Send + 'a>,
    >;

    /// Like [`Self::send_authenticated`], but additionally attach a one-time
    /// reply block addressed to `(reply_app_id, reply_endpoint_id)` on this node
    /// — letting the recipient reply WITHOUT either side publishing a public
    /// rendezvous ad (no presence leak). The reply path is registered
    /// R-locally under a fresh cookie inside the implementation.
    fn send_authenticated_with_reply<'a>(
        &'a self,
        receiver_node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &'a [u8],
        reply_app_id: [u8; 32],
        reply_endpoint_id: u32,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), AnonOnionSendError>> + Send + 'a>,
    >;

    /// Reply to an earlier authenticated message via the opaque `reply_id` the
    /// recipient app received with it. The implementation sends back over the
    /// original sender's rendezvous path. `src_app_id` is the replying app; it
    /// must own the reply block (diff-audit D3) or the reply is rejected.
    /// `NoRendezvous` means the id is unknown, not owned by `src_app_id`, or
    /// expired.
    fn send_reply<'a>(
        &'a self,
        reply_id: u64,
        data: &'a [u8],
        src_app_id: [u8; 32],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), AnonOnionSendError>> + Send + 'a>,
    >;

    /// Register this node as a LOCATION-anonymous service over an onion circuit
    /// (the IPC/FFI entry point, complementing the `[anonymity].onion_service`
    /// config flag): pick relays, build the circuit, publish the ad. `hop_count`
    /// is clamped to ≥ 2. Errors are local/pre-transmit (e.g. `NoRelays`).
    fn register_onion_service<'a>(
        &'a self,
        hop_count: usize,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), AnonOnionSendError>> + Send + 'a>,
    >;

    /// Register a PLAIN rendezvous-publisher entry (the app-IPC entry point for
    /// mailbox-by-discovery): the maintenance tick signs + publishes a v5
    /// `RendezvousAd` under THIS node's real id at the receiver's rendezvous
    /// slot, advertising the relay's KEM key (`relay_kem_algo` / `relay_kem_pk`,
    /// `algo = 0` X25519) so a sender resolving the ad can anonymously deposit a
    /// mailbox PUT at `rendezvous_node_id`. Replaces any existing entry with the
    /// same `(rendezvous_node_id, auth_cookie)`. Empty `relay_kem_pk` advertises
    /// no key. Local + infallible — just records the entry.
    fn register_rendezvous_publisher(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        validity_window_secs: u64,
        relay_kem_algo: u8,
        relay_kem_pk: Vec<u8>,
    );

    /// Send `data` to a LOCATION-anonymous service addressed by its Ed25519
    /// IDENTITY key (the unlinkable analogue of [`Self::send_authenticated`],
    /// which addresses by node_id). Resolves the service's per-period BLINDED
    /// descriptor — a DHT enumerator who doesn't know the identity cannot find
    /// or read it — decrypts it, and routes over the onion. `NoRendezvous` means
    /// no resolvable/decryptable descriptor for that identity.
    fn send_to_onion_service<'a>(
        &'a self,
        service_identity_vk: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        data: &'a [u8],
        hop_count: usize,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), AnonOnionSendError>> + Send + 'a>,
    >;

    /// Like [`Self::send_to_onion_service`] but UNAUTHENTICATED: the service
    /// receives the message with `src_node_id = [0; 32]` and never learns the
    /// sender. `src_app_id` rides inside the sealed payload for the service's
    /// app-level routing only. No sovereign identity is required.
    fn send_to_onion_service_anonymous<'a>(
        &'a self,
        service_identity_vk: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &'a [u8],
        hop_count: usize,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), AnonOnionSendError>> + Send + 'a>,
    >;

    /// DIRECT (non-rendezvous) sender-anonymous send to a KNOWN peer addressed by
    /// its `(target_node_id, target_x25519_pk)`. The source-routed onion hides the
    /// sender's location from every relay; the receiver sees `src_node_id =
    /// [0;32]` (never learns who sent it). For reaching a peer whose transport
    /// address + anonymity x25519 the caller already knows — NOT a
    /// location-anonymous service (use the onion-service paths for those). No
    /// sovereign identity required. Errors are local/pre-transmit.
    #[allow(clippy::too_many_arguments)]
    fn send_anonymous_direct<'a>(
        &'a self,
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &'a [u8],
        hop_count: usize,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), AnonOnionSendError>> + Send + 'a>,
    >;
}

// ── Wire-format constants shared by proto + crypto ────────────────────────────
//
// These three constants are consumed by *both* `proto::*` (encode/decode) and
// `crypto::*` (signing / KEM input validation). Hosting them here lets the
// crypto layer reach them without depending on `proto`, breaking the
// crypto → proto direction.

/// 32-byte cryptographic node identifier — `BLAKE3(pubkey)` of the
/// peer's identity key. Used as the wire-format addressing primitive
/// throughout the veil (DHT keying, routing, ban records, etc.).
///
/// Transparent alias for `[u8; 32]`. Strong-typed wrappers (`NodeId`
/// newtype in `veilcore::cfg::model`) build on top for compile-time
/// distinction between peer-id vs link-id vs raw hash. Use this alias
/// when the slot specifically means a node-identity wire byte sequence
/// — not for content_id / session_id / nonce / other 32-byte tokens
/// that share the wire shape but carry different semantics.
pub type NodeIdBytes = [u8; 32];

/// Wire-byte tag for ML-KEM-768 prekeys (`PrekeyBundle::algo` and
/// `MlkemCert::mlkem_algo`). Currently the only KEM the runtime supports.
pub const ALGO_ML_KEM_768: u8 = 1;

/// Encapsulation-key length in bytes for [`ALGO_ML_KEM_768`]. Used by
/// proto length checks and by `crypto::x3dh` input validation.
pub const ML_KEM_768_EK_LEN: usize = 1184;

/// Domain-separation prefix for delegation/sub-key certificate
/// signatures (the `certify_subkey` flow). Both the wire-format
/// encoder (`proto::identity_document`) and the signing helper
/// (`crypto::identity::sign_certify`) prepend this byte string before
/// the structured payload. Must NEVER change without wire-break bump.
pub const CERTIFY_CONTEXT: &[u8] = b"veil.certify.v1";

/// Role bits for `CapabilitiesPayload::roles_supported` (c moved here
/// so [`NodeRole::to_role_bits`] is self-contained, freeing proto from
/// reverse-importing cfg::NodeRole).
pub mod role_bits {
    /// Leaf node — no relay, no DHT.
    pub const LEAF: u8 = 1 << 0;
    /// Core node — full DHT participant, relay, forwarding.
    pub const CORE: u8 = 1 << 3;
}

/// Role this node plays in the veil network.
///
/// Exactly one role per running instance. The binary supports all roles.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Weak/mobile node; does not participate in DHT, works via core nodes.
    Leaf,
    /// Full participant: DHT (K=40), relay/forwarding, PoW≥24.
    /// Gateway and mesh-bridge features controlled by config flags.
    #[default]
    Core,
}

impl NodeRole {
    /// Convert to the bitset representation used in `CapabilitiesPayload`.
    pub fn to_role_bits(self) -> u8 {
        match self {
            NodeRole::Leaf => role_bits::LEAF,
            NodeRole::Core => role_bits::CORE,
        }
    }
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeRole::Leaf => f.write_str("leaf"),
            NodeRole::Core => f.write_str("core"),
        }
    }
}

impl std::str::FromStr for NodeRole {
    type Err = ParseEnumError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "leaf" => Ok(NodeRole::Leaf),
            "core" => Ok(NodeRole::Core),
            _ => Err(ParseEnumError::new("node role", value)),
        }
    }
}

/// (Layer 2): who is allowed to learn this node's listen
/// transports via `RouteRequest`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    /// Default: anyone may probe. PoW-gated when `abuse.pow_min_difficulty > 0`.
    #[default]
    Public,
    /// Only respond to peers already present in `peer_pubkeys` (i.e.
    /// previously handshaked / pre-paired).
    ContactsOnly,
    /// Never disclose `transports` — `RouteResponse.relay_ids` only.
    IntroductionOnly,
}

impl DiscoveryMode {
    pub fn is_default(&self) -> bool {
        matches!(self, DiscoveryMode::Public)
    }
}

/// Default base64-encoded 4-byte zero nonce — used as the serde default for
/// `nonce` fields on `BootstrapPeer` and `IdentityConfig`. : lifted
/// from `cfg::model` to the Tier 0 layer so veil-bootstrap can reference
/// the same default without depending on cfg.
pub fn default_nonce_base64() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([0_u8; 4])
}

/// Update-mechanism configuration.
///
/// extraction: lifted from `cfg::model` to veil-types so
/// veil-update can consume it without depending on the cfg layer.
/// `cfg::model` re-exports for existing call sites.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UpdateConfig {
    /// HTTPS URLs serving the operator's signed manifest. Multiple URLs
    /// across diverse providers defend against single-endpoint takedown
    ///
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manifest_urls: Vec<String>,

    /// Hex-encoded public key the manifest must be signed by. MUST be set
    /// for the update mechanism to engage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_issuer_pk: Option<String>,

    /// File path where `InstalledVersionStore` records the `release_unix`
    /// of the currently-installed binary. Required for the apply path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_version_path: Option<std::path::PathBuf>,

    /// File path where the binary itself lives. Required for the apply
    /// path (atomic stage + rename target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_path: Option<std::path::PathBuf>,

    /// When `Some(n)`, runtime spawns a periodic background task polling
    /// `manifest_urls` every `n` seconds. Hard-floor: 60 seconds.
    /// `None` disables auto-poll.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_interval_secs: Option<u64>,
}

impl UpdateConfig {
    pub fn is_default(c: &Self) -> bool {
        c.manifest_urls.is_empty()
            && c.expected_issuer_pk.is_none()
            && c.installed_version_path.is_none()
            && c.install_path.is_none()
            && c.check_interval_secs.is_none()
    }

    /// `true` when both `install_path` AND `installed_version_path` are set
    /// i.e. the apply path is fully configured.
    pub fn is_apply_enabled(&self) -> bool {
        self.is_check_enabled()
            && self.install_path.is_some()
            && self.installed_version_path.is_some()
    }

    /// `true` when both `expected_issuer_pk` and `manifest_urls` are set —
    /// minimum viable configuration for the check-only path.
    pub fn is_check_enabled(&self) -> bool {
        self.expected_issuer_pk.is_some() && !self.manifest_urls.is_empty()
    }
}

/// Output format for log lines. extraction: lifted from
/// `cfg::model` to veil-types so veil-observability can consume it
/// without depending on cfg.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// Human-readable plain text: `[timestamp] LEVEL event message`.
    #[default]
    Text,
    /// Newline-delimited JSON objects.
    Json,
}

/// Log sink — stderr (default) or a file specified by `log_file` config.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogsConfig {
    #[default]
    Stderr,
    File,
}

impl std::fmt::Display for LogsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stderr => f.write_str("stderr"),
            Self::File => f.write_str("file"),
        }
    }
}

impl std::str::FromStr for LogsConfig {
    type Err = ParseEnumError;
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "stderr" => Ok(Self::Stderr),
            "file" => Ok(Self::File),
            _ => Err(ParseEnumError::new("logs config", value)),
        }
    }
}

/// Minimum severity level for log output.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug = 0,
    #[default]
    Info = 1,
    Warn = 2,
    Error = 3,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LogLevel {
    type Err = ParseEnumError;
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(ParseEnumError::new("log_level", value)),
        }
    }
}

/// Metrics-server config (Prometheus scrape endpoint).
#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// `Debug` is implemented manually (not derived) to redact `auth_token`
/// so an accidental `{:?}` on a config can't leak the metrics bearer token.
pub struct MetricsConfig {
    /// TCP bind URI (e.g. `tcp://127.0.0.1:9000`). **
    /// audit:** prefer a loopback bind for production. When binding to
    /// a non-loopback address (e.g. `0.0.0.0:9000`), `auth_token`
    /// SHOULD be set or the operator-provided firewall must restrict
    /// scrape sources — otherwise `/admin/state/dump` exposes role
    /// session counts, mailbox/dht state, ban counters to anyone who
    /// can reach the port.
    pub listen: String,
    /// Custom Prometheus path (default: `/metrics`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Optional bearer-auth token. When set, every request MUST carry
    /// `Authorization: Bearer <token>` (constant-time compared); other
    /// requests get a `401 Unauthorized`. When unset (default), all
    /// endpoints are unauthenticated — appropriate only for loopback
    /// binds or firewalled networks. audit closure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    /// Explicit opt-in to publish unauthenticated metrics on a non-
    /// loopback bind. Without this flag, a non-loopback `listen` with
    /// `auth_token = None` would be a security misconfiguration —
    /// `/admin/state/dump` exposes role / session / DHT / mailbox state
    /// to anyone who can reach the port. Default `false`: such a config
    /// causes node startup to fail with a `ValidationFailed` error so
    /// the operator notices.
    ///
    /// Set to `true` when the metrics port is firewalled / Tailscale-
    /// scoped / VPN-gated and the operator deliberately wants unauthenticated
    /// scrape (typical testnet / homelab pattern). Setting the flag
    /// without a meaningful network boundary is a documented self-foot-
    /// shoot path; the warn-log on startup tells the operator what just
    /// happened.
    #[serde(default, skip_serializing_if = "is_default_false")]
    pub allow_unauthenticated_remote_metrics: bool,
}

impl std::fmt::Debug for MetricsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsConfig")
            .field("listen", &self.listen)
            .field("path", &self.path)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "<redacted>"),
            )
            // ".." — omit/cover any remaining (and future) fields.
            .finish_non_exhaustive()
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_default_false(b: &bool) -> bool {
    !b
}

/// Private-veil-network configuration.
///
/// Two modes:
///
/// * **Public (default)** — current veil behaviour. Any node that can
///   reach a listening peer can attempt a handshake; per-peer
///   authentication (Ed25519 / Falcon-512) verifies identity but
///   does not gate membership. Ban decisions stay local (node operator
///   owns the policy for their own node).
///
/// * **Private** — handshake-time membership gate. Every member carries
///   a signed certificate from the network owner; peers reject handshake
///   from a node that doesn't present a valid cert for the same
///   `network_id`. Admin-signed ban records propagate via the DHT so
///   bans applied on any admin node take effect across the whole
///   network (mirrors VPN / private-veil semantics).
///
/// The asymmetry is deliberate: in public networks anyone can connect, so
/// remote-initiated bans would be a DoS vector (anyone signs a ban
/// against the local node → cascading exclusion). In private networks
/// the membership set is constrained by the owner's cert issuance, so
/// bans cannot originate from outside the network.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct NetworkConfig {
    /// Membership mode. `"public"` (default) preserves the current
    /// open-network behaviour; `"private"` enables cert-gated handshake
    /// + DHT-propagated bans.
    #[serde(default)]
    pub mode: NetworkMode,

    /// Stable 32-byte network identifier. BLAKE3 of a human-readable
    /// network name OR a fresh random ID. Mandatory when `mode = private`.
    /// Carried in the membership cert and checked at handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,

    /// Base64-encoded public key of the network owner. Used to verify
    /// membership-cert signatures. Mandatory when `mode = private`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_pubkey: Option<String>,

    /// Signature algorithm used by the owner key. Mandatory when
    /// `mode = private`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_algo: Option<SignatureAlgorithm>,

    /// Path on disk to this node's own membership certificate (signed
    /// by `owner_pubkey`). Loaded at startup and exchanged through the
    /// handshake TLV. Mandatory when `mode = private`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_cert: Option<String>,

    /// Allow-list of admin-cert subject `node_id` values (hex strings).
    /// Only certs with a matching `node_id` AND `admin = true` may
    /// publish ban records to the DHT-propagated ban list. Defense-in-
    /// depth: even if admin private key leaks, only listed node_ids
    /// can act as admins. Empty list (default) accepts any cert with
    /// `admin = true` flag set by the owner.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admin_node_ids: Vec<String>,
}

/// Network membership mode. See [`NetworkConfig`] for behaviour.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// Public network (default). Any peer can attempt handshake; bans
    /// stay local.
    #[default]
    Public,
    /// Private network. Handshake requires a valid membership cert;
    /// admin bans propagate via DHT.
    Private,
}

/// Membership certificate issued by the network owner.
///
/// Format wire-versioned via [`MEMBERSHIP_CERT_VERSION`]. Body fields
/// are serialised in a fixed order for signature-stable canonical
/// encoding (matches the existing identity-cert pattern).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MembershipCert {
    /// Wire-format version. Must match [`MEMBERSHIP_CERT_VERSION`] on
    /// load — older or newer versions are rejected.
    pub version: u8,
    /// Network identifier this cert belongs to. Must match the local
    /// `[network].network_id` at handshake time.
    pub network_id: [u8; 32],
    /// Node identity (BLAKE3(pubkey)) that this cert authorises.
    /// The peer must prove ownership of the matching private key via
    /// the existing handshake signature exchange.
    pub member_node_id: [u8; 32],
    /// Unix seconds when the cert was signed by the owner.
    pub issued_at_unix: u64,
    /// Unix seconds after which the cert is invalid. Certs presenting
    /// `valid_until_unix <= now` are rejected during handshake.
    ///
    /// **Sentinel value `0` ⇒ no expiry** (cert is valid forever as long
    /// as the owner-signature still verifies). Operators wanting a
    /// long-lived service-key for a fleet member set this through
    /// `veil-cli network sign-member --no-expiry`. With `0`, the
    /// only revocation paths are (a) DHT-replicated ban-records and
    /// (b) rotating the network's `owner_pubkey` (re-issues all certs).
    pub valid_until_unix: u64,
    /// Admin flag — when true, this member may publish DHT-replicated
    /// ban records. False members can ONLY ban locally (matches the
    /// public-mode semantics).
    pub admin: bool,
    /// Owner signature algorithm.
    pub algo: SignatureAlgorithm,
    /// Owner signature over the canonical encoding of fields above.
    /// Verified against the local `[network].owner_pubkey` at handshake.
    #[serde(with = "base64_bytes")]
    pub owner_signature: Vec<u8>,
}

/// Wire-format version for [`MembershipCert`]. Bump on every breaking
/// schema change. Older versions in a live deployment must continue
/// to verify until everyone has rotated; do not reuse version numbers.
pub const MEMBERSHIP_CERT_VERSION: u8 = 1;

/// Admin-issued ban record for a private veil network. Replicated
/// via DHT under key `BLAKE3(network_id || ":bans:" || banned_node_id)`
/// so any private-network member can apply bans issued by an admin.
///
/// Verification chain:
/// 1. `admin_cert` is signed by the network owner (verified using the
///    local `[network].owner_pubkey`) and has `admin: true`.
/// 2. `BLAKE3(admin_pubkey) == admin_cert.member_node_id` — pubkey
///    matches the cert's identity binding.
/// 3. `admin_signature` (over the canonical body) verifies against
///    `admin_pubkey` using `admin_cert.algo`.
/// 4. Optional defense-in-depth: `admin_cert.member_node_id` is in the
///    operator-configured `[network].admin_node_ids` allowlist.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BanEntry {
    /// Wire-format version. Must match [`BAN_ENTRY_VERSION`].
    pub version: u8,
    /// Network this ban applies to. Must match local `[network].network_id`.
    pub network_id: [u8; 32],
    /// Node-id being banned (BLAKE3 of its pubkey).
    pub banned_node_id: [u8; 32],
    /// Free-form operator-supplied reason (truncated to 256 bytes
    /// before encoding). Carried inside the signed body so it can be
    /// audited but not altered.
    pub reason: String,
    /// Unix seconds when the admin issued the ban.
    pub issued_at_unix: u64,
    /// Admin node-id (derived from admin_pubkey). Convenience field —
    /// re-derived and checked at verification time.
    pub admin_node_id: [u8; 32],
    /// Bincode-blob of the admin's own membership cert (issued by
    /// network owner, `admin: true`). Embedded so anyone can verify
    /// the ban without prior knowledge of the admin set.
    #[serde(with = "base64_bytes")]
    pub admin_cert_blob: Vec<u8>,
    /// Admin's public key (raw bytes). Must hash to `admin_cert`'s
    /// `member_node_id`.
    #[serde(with = "base64_bytes")]
    pub admin_pubkey: Vec<u8>,
    /// Signature over the canonical ban body, produced by `admin_pubkey`
    /// using `admin_cert.algo`.
    #[serde(with = "base64_bytes")]
    pub admin_signature: Vec<u8>,
}

/// Wire-format version for [`BanEntry`]. Bump on every breaking
/// schema change. Older versions must continue to verify until rotated.
pub const BAN_ENTRY_VERSION: u8 = 1;

/// Cap on `BanEntry.reason` length before encoding. Truncated values
/// signed by the admin remain valid, so writers must clamp themselves
/// before signing.
pub const MAX_BAN_REASON_LEN: usize = 256;

/// Helper for serde base64 round-trip on `Vec<u8>` fields.
mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        STANDARD.decode(&encoded).map_err(serde::de::Error::custom)
    }
}

/// NAT-traversal configuration.
///
/// extraction: lifted from `cfg::model` to veil-types so
/// veil-nat can consume it without depending on the cfg layer.
/// `cfg::model` re-exports for existing call sites.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct NatConfig {
    /// Enable NAT traversal. Default: `true`.
    #[serde(default = "NatConfig::default_enabled")]
    pub enabled: bool,
    /// Maximum time (ms) to wait for a hole-punch attempt before falling
    /// back to relay. Default: 3000 ms.
    #[serde(default = "NatConfig::default_punch_timeout_ms")]
    pub punch_timeout_ms: u64,
    /// External STUN servers for reflexive address discovery (RFC 5389).
    /// Empty (default) — discovery via the veil itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stun_servers: Vec<String>,
    /// Enable relay fallback when hole-punching fails. Default: `true`.
    #[serde(default = "NatConfig::default_relay_enabled")]
    pub relay_enabled: bool,
}

impl NatConfig {
    fn default_enabled() -> bool {
        true
    }
    fn default_punch_timeout_ms() -> u64 {
        3_000
    }
    fn default_relay_enabled() -> bool {
        true
    }

    pub fn is_default(&self) -> bool {
        self.enabled == Self::default_enabled()
            && self.punch_timeout_ms == Self::default_punch_timeout_ms()
            && self.stun_servers.is_empty()
            && self.relay_enabled == Self::default_relay_enabled()
    }
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            punch_timeout_ms: Self::default_punch_timeout_ms(),
            stun_servers: Vec::new(),
            relay_enabled: Self::default_relay_enabled(),
        }
    }
}

/// Peer Exchange (PEX) configuration.
///
/// extraction: lifted from `cfg::model` to veil-types so
/// veil-pex can consume it without depending on the cfg layer.
/// `cfg::model` re-exports for existing call sites.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PexConfig {
    /// Enable PEX random-walk discovery. Default: `true`.
    #[serde(default = "PexConfig::default_enabled")]
    pub enabled: bool,
    /// Maximum peers to keep from PEX discovery. Default: 32.
    #[serde(default = "PexConfig::default_max_peers")]
    pub max_peers: usize,
    /// Number of parallel walk requests per round. Default: 3.
    #[serde(default = "PexConfig::default_walk_parallelism")]
    pub walk_parallelism: u8,
    /// Maximum peers returned per PEX response. Default: 16.
    #[serde(default = "PexConfig::default_max_response_peers")]
    pub max_response_peers: u8,

    // ── Search-walk cadence (tiered by ACTIVE-SESSION count) ─────────────────
    // The discovery walk interval steps down as the node accumulates SESSIONS
    // (not merely discovered peers — see `veil_pex` `compute_interval`):
    //   active sessions < low_peer_threshold            → search_interval_active
    //   low_peer_threshold..high_peer_threshold         → search_interval_mid
    //   >= high_peer_threshold                          → search_interval_idle
    // Keying on sessions keeps it scale-safe: a node stops aggressive searching
    // once it is connected, regardless of how many peers exist to discover.
    /// Below this many ACTIVE SESSIONS, search aggressively
    /// (`search_interval_active_secs`). Default: 3.
    #[serde(default = "PexConfig::default_low_peer_threshold")]
    pub low_peer_threshold: usize,
    /// At/above this many ACTIVE SESSIONS, drop to once-per-day maintenance
    /// search (`search_interval_idle_secs`). Default: 20.
    #[serde(default = "PexConfig::default_high_peer_threshold")]
    pub high_peer_threshold: usize,
    /// Search interval while under-connected (< `low_peer_threshold` sessions).
    /// Default: 900 (15 min).
    #[serde(default = "PexConfig::default_search_interval_active_secs")]
    pub search_interval_active_secs: u64,
    /// Search interval while minimally connected
    /// (`low_peer_threshold`..`high_peer_threshold` sessions).
    /// Default: 3600 (1 h).
    #[serde(default = "PexConfig::default_search_interval_mid_secs")]
    pub search_interval_mid_secs: u64,
    /// Search interval while well-connected (>= `high_peer_threshold` sessions).
    /// Default: 86400 (1 day).
    #[serde(default = "PexConfig::default_search_interval_idle_secs")]
    pub search_interval_idle_secs: u64,
}

impl PexConfig {
    fn default_enabled() -> bool {
        true
    }
    fn default_max_peers() -> usize {
        32
    }
    fn default_walk_parallelism() -> u8 {
        3
    }
    fn default_max_response_peers() -> u8 {
        16
    }
    fn default_low_peer_threshold() -> usize {
        3
    }
    fn default_high_peer_threshold() -> usize {
        20
    }
    fn default_search_interval_active_secs() -> u64 {
        15 * 60
    }
    fn default_search_interval_mid_secs() -> u64 {
        60 * 60
    }
    fn default_search_interval_idle_secs() -> u64 {
        24 * 60 * 60
    }

    pub fn is_default(&self) -> bool {
        self.enabled == Self::default_enabled()
            && self.max_peers == Self::default_max_peers()
            && self.walk_parallelism == Self::default_walk_parallelism()
            && self.max_response_peers == Self::default_max_response_peers()
            && self.low_peer_threshold == Self::default_low_peer_threshold()
            && self.high_peer_threshold == Self::default_high_peer_threshold()
            && self.search_interval_active_secs == Self::default_search_interval_active_secs()
            && self.search_interval_mid_secs == Self::default_search_interval_mid_secs()
            && self.search_interval_idle_secs == Self::default_search_interval_idle_secs()
    }
}

impl Default for PexConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            max_peers: Self::default_max_peers(),
            walk_parallelism: Self::default_walk_parallelism(),
            max_response_peers: Self::default_max_response_peers(),
            low_peer_threshold: Self::default_low_peer_threshold(),
            high_peer_threshold: Self::default_high_peer_threshold(),
            search_interval_active_secs: Self::default_search_interval_active_secs(),
            search_interval_mid_secs: Self::default_search_interval_mid_secs(),
            search_interval_idle_secs: Self::default_search_interval_idle_secs(),
        }
    }
}

/// Local IPC server configuration.
///
/// extraction: lifted from `cfg::model` to veil-types so the
/// freshly-extracted `veil-ipc` crate can consume it without depending
/// on veilcore's full cfg surface. `cfg::model` re-exports for
/// existing call sites.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct IpcConfig {
    /// Whether the IPC server is enabled. Default: `false`.
    #[serde(default)]
    pub enabled: bool,
    /// IPC server backend URI. Accepts `unix:///abs/path` (Linux/macOS) or
    /// `tcp://127.0.0.1:0?runtime_dir=/abs/path` (Windows / multi-node).
    /// TCP host must be loopback — validated at parse time, mirroring
    /// `global.admin_socket`. When unset on Unix, defaults to
    /// `~/.veil/app.sock`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_uri: Option<String>,
    /// Lifetime of cached peer ML-KEM-768 encapsulation keys (seconds).
    ///
    /// After this TTL elapses the key is evicted and a fresh `RouteRequest` /
    /// `RouteResponse` exchange is triggered on the next message send, which
    /// installs a new key. Shorter values increase forward-secrecy at the cost
    /// of one extra round-trip per TTL window.
    ///
    /// Default: 3600 (1 hour).
    #[serde(default = "IpcConfig::default_e2e_key_ttl_secs")]
    pub e2e_key_ttl_secs: u64,
    /// Optional directory for per-app_id sockets.
    ///
    /// When set, registering a non-ephemeral `app_id` via `APP_BIND` causes the
    /// node to create an additional Unix socket at `{app_socket_dir}/{hex(app_id)}.sock`
    /// with permissions `0600`. Only the process that can access this path-specific
    /// socket can connect and claim that `app_id`, preventing other local processes
    /// from stealing the binding.
    ///
    /// Ephemeral app_ids (EPHEMERAL flag) are derived from a per-connection token
    /// and are not eligible for per-app sockets (they are connection-scoped by design).
    ///
    /// Default: `None` (feature disabled; shared socket only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_socket_dir: Option<std::path::PathBuf>,
}

impl Default for IpcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket_uri: None,
            e2e_key_ttl_secs: Self::default_e2e_key_ttl_secs(),
            app_socket_dir: None,
        }
    }
}

impl IpcConfig {
    fn default_e2e_key_ttl_secs() -> u64 {
        3600
    }

    /// `is_default` — see impl.
    pub fn is_default(&self) -> bool {
        !self.enabled
            && self.socket_uri.is_none()
            && self.e2e_key_ttl_secs == Self::default_e2e_key_ttl_secs()
            && self.app_socket_dir.is_none()
    }
}

/// Configuration entry for a bootstrap peer (config schema + runtime input).
///
/// extraction: lifted from `cfg::model` to veil-types so
/// veil-bootstrap can consume the type without depending on the cfg
/// layer. cfg/model.rs re-exports this so existing call sites
/// (`cfg::BootstrapPeer`) keep working.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BootstrapPeer {
    /// Transport URI (e.g. `"tcp://bootstrap.example.com:9000"`).
    pub transport: String,
    /// Node's ed25519 public key (base64).
    pub public_key: String,
    /// Nonce (base64) for node_id derivation.
    #[serde(default = "default_nonce_base64")]
    pub nonce: String,
    /// Signature algorithm used by this bootstrap peer (default: `"ed25519"`).
    #[serde(default)]
    pub algo: SignatureAlgorithm,
    /// TLS certificate (PEM) if the transport is TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    /// TLS CA certificate (PEM) if pinning a custom CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_cert: Option<String>,
}

/// Error returned by `FromStr` impls on veil enums when the
/// input string doesn't match a known variant. Carries `kind`
/// (the enum name, e.g. "signature algorithm") + `value` (what
/// the operator typed) so the diagnostic can guide them to a
/// valid choice.
///
/// Used by [`SignatureAlgorithm::from_str`] and will be reused by
/// future veil-enums that need string parsing with consistent
/// error format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseEnumError {
    pub(crate) kind: &'static str,
    pub(crate) value: String,
}

impl ParseEnumError {
    /// Construct. `kind` is the enum's friendly name (e.g.
    /// "signature algorithm"), `value` is the operator's input.
    pub fn new(kind: &'static str, value: &str) -> Self {
        Self {
            kind,
            value: value.to_owned(),
        }
    }

    /// Friendly enum name passed at construction.
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// Operator input that failed parsing.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for ParseEnumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported {} `{}`", self.kind, self.value)
    }
}

impl std::error::Error for ParseEnumError {}

/// Cryptographic signature algorithm advertised on the wire and
/// referenced throughout config, identity, and crypto layers.
///
/// Variants:
/// `Ed25519` (default) — fast, small (32 B pk, 64 B sig), classical.
/// `Falcon512` — post-quantum lattice-based; slower + larger
/// (~900 B pk, ~660 B sig) but quantum-resistant.
/// `Ed25519Falcon512Hybrid` — hybrid mode that signs
/// with BOTH algorithms; verifier requires BOTH signatures valid.
/// pubkey = ed25519_pk(32) || falcon_pk(897); signature carries
/// both ed25519 and falcon detached sigs with explicit framing.
/// Provides classical security via Ed25519 (fast verify) AND
/// post-quantum security via Falcon-512 (quantum-resistant).
/// `Ed25519Falcon1024Hybrid` (Stage 10) — higher-security PQ
/// hybrid; same construction but swaps Falcon-512 for Falcon-1024
/// (NIST PQC Level 5 vs Level 1).  Use for long-lived sovereign
/// identities that must outlive the cryptographic-relevant-quantum-
/// computer (CRQC) horizon AND need a margin beyond Falcon-512's
/// 103-bit classical security level (matches Falcon-1024's
/// ~270-bit classical-equivalent margin).
///
/// Wire-byte encoding (used in `IdentityPayload.algo` and similar
/// frame fields) is centralized [`Self::wire_byte`] and
/// [`Self::from_wire_byte`] — never duplicate the mapping inline
/// always go through these helpers so a single byte change here
/// updates every wire path consistently.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    #[default]
    /// Ed25519 — RFC 8032 Edwards-curve DSA over Curve25519.
    Ed25519,
    /// Falcon-512 — NIST PQC standard, lattice-based.
    Falcon512,
    /// hybrid Ed25519 + Falcon-512 — both signatures
    /// required for verify. Long-term identities should use this.
    Ed25519Falcon512Hybrid,
    /// hybrid Ed25519 + Falcon-1024 (Stage 10) — both signatures
    /// required for verify.  Higher-security PQ alternative to
    /// `Ed25519Falcon512Hybrid` for identities expected to outlive
    /// the CRQC horizon by a wider margin (~270-bit classical-
    /// equivalent vs ~103-bit for Falcon-512).
    Ed25519Falcon1024Hybrid,
}

impl SignatureAlgorithm {
    /// All variants the runtime supports. Used by config
    /// validation, CLI `key list-algos`, and tests that iterate
    /// over all algos.
    pub fn supported() -> &'static [Self] {
        &[
            Self::Ed25519,
            Self::Falcon512,
            Self::Ed25519Falcon512Hybrid,
            Self::Ed25519Falcon1024Hybrid,
        ]
    }

    /// Wire-byte encoding used in `IdentityPayload.algo` and
    /// equivalent frame fields. Inverted from the ad-hoc
    /// `if algo == 2 { Falcon } else { Ed }` pattern previously
    /// scattered through handshake.rs — centralized here so
    /// malformed bytes produce a clean error instead of silently
    /// defaulting to Ed25519.
    pub fn wire_byte(self) -> u8 {
        match self {
            Self::Ed25519 => 1,
            Self::Falcon512 => 2,
            Self::Ed25519Falcon512Hybrid => 3,
            Self::Ed25519Falcon1024Hybrid => 4,
        }
    }

    /// Decode an `IdentityPayload.algo` byte into the corresponding
    /// enum variant. Returns `None` for any byte that does not
    /// map to a known variant — the caller MUST treat the unknown
    /// byte as a handshake failure, not fall back to a default.
    ///
    /// Ed25519's byte is historically `1`; some legacy payloads
    /// shipped `0` before the wire was tightened, so we accept
    /// `0` as Ed25519 for back-compat with pre-471.17 peers.
    pub fn from_wire_byte(b: u8) -> Option<Self> {
        match b {
            0 | 1 => Some(Self::Ed25519),
            2 => Some(Self::Falcon512),
            3 => Some(Self::Ed25519Falcon512Hybrid),
            4 => Some(Self::Ed25519Falcon1024Hybrid),
            _ => None,
        }
    }

    /// returns `true` when this algorithm provides
    /// post-quantum security guarantees. Used by deployment
    /// validation to enforce "no classical-only identity in
    /// PQ-required mode" and by CLI flags like `--require-pq`.
    pub fn is_post_quantum(self) -> bool {
        matches!(
            self,
            Self::Falcon512 | Self::Ed25519Falcon512Hybrid | Self::Ed25519Falcon1024Hybrid
        )
    }

    /// returns `true` when this algorithm includes a
    /// classical (pre-quantum) signature component. Used to
    /// detect identities that can be verified by legacy peers
    /// even when running in hybrid mode.
    pub fn has_classical_component(self) -> bool {
        matches!(
            self,
            Self::Ed25519 | Self::Ed25519Falcon512Hybrid | Self::Ed25519Falcon1024Hybrid
        )
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 => f.write_str("ed25519"),
            Self::Falcon512 => f.write_str("falcon512"),
            Self::Ed25519Falcon512Hybrid => f.write_str("ed25519+falcon512"),
            Self::Ed25519Falcon1024Hybrid => f.write_str("ed25519+falcon1024"),
        }
    }
}

impl std::str::FromStr for SignatureAlgorithm {
    type Err = ParseEnumError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "ed25519" => Ok(Self::Ed25519),
            "falcon512" => Ok(Self::Falcon512),
            "ed25519+falcon512" | "hybrid" => Ok(Self::Ed25519Falcon512Hybrid),
            "ed25519+falcon1024" | "hybrid1024" => Ok(Self::Ed25519Falcon1024Hybrid),
            _ => Err(ParseEnumError::new("signature algorithm", value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn wire_byte_roundtrip() {
        for &a in SignatureAlgorithm::supported() {
            let b = a.wire_byte();
            assert_eq!(SignatureAlgorithm::from_wire_byte(b), Some(a));
        }
    }

    #[test]
    fn unknown_byte_rejected() {
        // Stage 10 added Ed25519Falcon1024Hybrid at wire byte 4 — bump
        // the unknown-range start to 5.  Sequence pinned centrally in
        // `wire_byte` / `from_wire_byte`; rejection range is the
        // complement of the supported byte set.
        for b in 5u8..=255 {
            assert!(
                SignatureAlgorithm::from_wire_byte(b).is_none(),
                "byte 0x{b:02x} should be rejected"
            );
        }
    }

    #[test]
    fn legacy_zero_accepted_as_ed25519() {
        // Pre-471.17 payloads occasionally shipped algo=0 instead of
        // algo=1 for Ed25519. Preserve backwards compat.
        assert_eq!(
            SignatureAlgorithm::from_wire_byte(0),
            Some(SignatureAlgorithm::Ed25519)
        );
    }

    #[test]
    fn display_round_trip() {
        for &a in SignatureAlgorithm::supported() {
            let s = a.to_string();
            assert_eq!(SignatureAlgorithm::from_str(&s).unwrap(), a);
        }
    }

    #[test]
    fn unknown_str_yields_parse_error() {
        let err = SignatureAlgorithm::from_str("rsa-2048").unwrap_err();
        assert_eq!(err.kind(), "signature algorithm");
        assert_eq!(err.value(), "rsa-2048");
        assert!(err.to_string().contains("rsa-2048"));
    }

    #[test]
    fn default_is_ed25519() {
        assert_eq!(SignatureAlgorithm::default(), SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn parse_enum_error_display_format() {
        let e = ParseEnumError::new("test enum", "garbage");
        assert_eq!(e.to_string(), "unsupported test enum `garbage`");
    }
}

// ── PeerLruCache ──────────────────────────────────────────────────────────────
//
// LRU-evicting bounded HashMap keyed on `NodeIdBytes`.
// Used for `peer_pubkeys` and `peer_roles` caches in `NodeRuntime`,
// `NodeServices`, `SessionRuntimeContext`, and `CryptoContext`.  Keeps
// insertion-order in a `VecDeque` so the oldest entry is evicted first
// (FIFO-LRU), preventing unbounded memory growth while preserving recently
// active peers.
//
// Phase 3 prep (veilcore extraction): moved here from veilcore::node::mod.rs
// so dispatcher and other consumers can move to sibling crates.

/// LRU-evicting bounded HashMap keyed on [`NodeIdBytes`].
///
/// On insert when `capacity` is reached the **least recently used**
/// entry (front of the VecDeque) is evicted.
#[derive(Default)]
pub struct PeerLruCache<V> {
    map: std::collections::HashMap<NodeIdBytes, V>,
    order: std::collections::VecDeque<NodeIdBytes>,
}

impl<V> PeerLruCache<V> {
    /// Pre-allocate the inner HashMap + VecDeque so
    /// that subsequent inserts up to `cap` entries do not trigger
    /// `hashbrown::RawTable::reserve_rehash` transients.  Under chaos-ban
    /// peer churn the rehash spikes were pinning ~49 MiB of dirty pages
    /// in jemalloc small-bin arena.
    /// Trade-off: ~64 bytes/slot upfront × cap (e.g. 64 KiB for 1024 cap)
    /// in exchange for a flat allocator footprint over time.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            map: std::collections::HashMap::with_capacity(cap),
            order: std::collections::VecDeque::with_capacity(cap),
        }
    }

    pub fn map_len(&self) -> usize {
        self.map.len()
    }

    /// Insert `(key, value)`, evicting the LRU entry if `map.len >= capacity`.
    ///
    /// If `key` is already present the value is updated and the key is
    /// promoted to most-recently-used (back of the order).
    pub fn insert_lru(&mut self, key: NodeIdBytes, value: V, capacity: usize) {
        if self.map.contains_key(&key) {
            if let Some(pos) = self.order.iter().position(|k| *k == key) {
                self.order.remove(pos);
            }
        } else if self.map.len() >= capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.map.remove(&oldest);
        }
        self.order.push_back(key);
        self.map.insert(key, value);
    }

    /// Evict the `n` oldest entries (front of the insertion order).
    pub fn evict_oldest(&mut self, n: usize) {
        for _ in 0..n {
            if let Some(key) = self.order.pop_front() {
                self.map.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Read-only lookup (does NOT promote — use [`Self::insert_lru`] for LRU
    /// promotion).
    pub fn get(&self, key: &NodeIdBytes) -> Option<&V> {
        self.map.get(key)
    }

    pub fn contains_key(&self, key: &NodeIdBytes) -> bool {
        self.map.contains_key(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&NodeIdBytes, &V)> {
        self.map.iter()
    }
}

/// Shared, bounded pubkey cache: `peer_id → (algo, public_key_bytes)`.
pub type PeerPubkeysCache = std::sync::Arc<std::sync::Mutex<PeerLruCache<(u8, Vec<u8>)>>>;
