use std::{fmt, path::PathBuf, time::Instant};

pub use veil_cfg::{ListenId, NodeId, NodeRole, PeerId};

/// 32-byte cryptographic node identifier (`BLAKE3(pubkey)` for Ed25519
/// nodes, `BLAKE3(falcon_pubkey)` for PQ nodes).
///
/// Transparent alias for `[u8; 32]` — chosen over the [`NodeId`] newtype
/// for hot-path use because:
///
/// * Zero runtime cost: type-level signal, not wrapper.
/// * Compatible with every existing `[u8; 32]` API (FFI, serde, BLAKE3).
/// * Readable signatures: `fn foo(peer_id: NodeIdBytes)` clearly says
///   "peer's network identity" rather than ambiguous "some 32-byte hash".
///
/// Use this alias when the slot specifically means a node-identity —
/// not for `content_id`, `session_id`, `nonce`, or other 32-byte tokens
/// that share the wire shape but carry different semantics.
///
/// **Do not confuse with [`PeerId`]** (newtype `u32`, the local config-file
/// slot index).  The type system enforces non-interchangeability; this
/// alias is a cognitive aid for human readers, not extra safety.
pub type NodeIdBytes = [u8; 32];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LinkId(u64);

impl LinkId {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListenerHandle(u64);

impl ListenerHandle {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ListenerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionSource {
    Inbound(ListenId),
    Outbound(PeerId),
}

impl fmt::Display for SessionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inbound(id) => write!(f, "inbound({id})"),
            Self::Outbound(id) => write!(f, "outbound({id})"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Active,
    DebugAttached,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::DebugAttached => f.write_str("debug_attached"),
        }
    }
}

/// How this peer was discovered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerSource {
    /// Statically configured in `[[peers]]`.
    #[default]
    Configured,
    /// From `[[bootstrap_peers]]` — used for initial FIND_NODE only.
    Bootstrap,
    /// Discovered via Peer Exchange (PEX).
    Exchanged,
    /// Discovered via mesh beacon autodiscovery.
    Autodiscovered,
}

impl std::fmt::Display for PeerSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configured => f.write_str("configured"),
            Self::Bootstrap => f.write_str("bootstrap"),
            Self::Exchanged => f.write_str("exchanged"),
            Self::Autodiscovered => f.write_str("autodiscovered"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerConfigEntry {
    pub peer_id: PeerId,
    pub node_id: NodeId,
    pub public_key: String,
    pub nonce: String,
    pub transport: String,
    /// Signature algorithm used by this peer to derive its node_id.
    pub algo: veil_cfg::SignatureAlgorithm,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub tls_ca_cert: Option<String>,
    /// True for bootstrap-only peers that are not in `config.peers`.
    /// After the initial FIND_NODE exchange the session is closed and not
    /// reconnected.
    pub bootstrap_only: bool,
    /// How this peer was discovered.
    pub source: PeerSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenConfigEntry {
    pub listen_id: ListenId,
    pub listener_handle: Option<ListenerHandle>,
    pub transport: String,
    /// Overridden advertised address (from `ListenConfig.advertise`).
    pub advertise: Option<String>,
    /// Relay node-id (base64) advertised alongside this listener.
    pub relay: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub tls_ca_cert: Option<String>,
    /// Per-listener PSK file (32 raw bytes base64-encoded).  When set
    /// and the listener's transport is `obfs4-tcp://`, this PSK overrides
    /// the global `transport.obfs4_psk_file`.  Allows different listen
    /// entries on one node to use different PSKs (e.g. public listener
    /// uses deployment-wide PSK; trusted/family listener uses a secret
    /// shared only with invitees).  `None` falls back to global PSK.
    pub psk_file: Option<std::path::PathBuf>,
    /// Visibility level (public/trusted/hidden).  Controls whether
    /// this listener's URI gets gossiped through PEX/DHT.
    pub visibility: veil_cfg::Visibility,
    /// Allowlist of node_ids permitted to authenticate against this
    /// listener.  Required for `hidden`; optional reinforcement for
    /// `trusted`.  Hex-encoded 32-byte node_id strings.
    pub allowlist_node_ids: Vec<String>,
    /// Optional human-readable group tag.
    pub group_label: Option<String>,
    /// Ephemeral random-port rotation config (Phase 5f Step 3).  None =
    /// listener binds at config-specified port and stays there.  Some =
    /// daemon rebinds on a fresh random port from `range` every
    /// `rotation` interval; peers learn the new URI through a signed
    /// `TransportMigrationNotify` broadcast.
    pub ephemeral: Option<veil_cfg::EphemeralConfig>,
    /// PoW-Gated Rendezvous binding config (Slice 5 of the
    /// PoW-Gated Rendezvous epic).  When set + `visibility = "stealth"`
    /// the daemon skips startup-time bind; ports come alive on-demand
    /// after a valid PoW-gated rendezvous request lands.
    pub on_demand: Option<veil_cfg::OnDemandListenConfig>,
    pub local_addr: Option<String>,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub link_id: LinkId,
    pub node_id: Option<NodeId>,
    pub nonce: Option<String>,
    pub matched_peer_id: Option<PeerId>,
    pub source: SessionSource,
    pub listener_handle: Option<ListenerHandle>,
    pub state: SessionState,
    pub transport: String,
    pub remote_addr: Option<String>,
    pub description: String,
}

#[derive(Clone, Debug)]
pub struct NodeSummary {
    pub node_id: NodeId,
    pub role: NodeRole,
    pub config_path: PathBuf,
    pub foreground_mode: bool,
    pub started_at: Instant,
    pub metrics_active: bool,
    pub metrics_endpoint: Option<String>,
    pub peers_configured: usize,
    pub listens_configured: usize,
    pub listens_active: usize,
    pub sessions_active: usize,
}
