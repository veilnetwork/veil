use std::fmt;
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use veil_crypto::Base64PublicKey;

use super::{ConfigError, Result};

// Crate-split : ParseEnumError + SignatureAlgorithm extracted to
// the `veil-types` workspace crate (Tier 0 leaf, breaks cfg ↔ proto
// and cfg ↔ crypto cycles). Re-exports preserve existing
// `crate::ParseEnumError` / `crate::SignatureAlgorithm`
// callers without touching every import site in the codebase.
pub use veil_types::{ParseEnumError, SignatureAlgorithm};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
/// Config (see field docs for details).
pub struct Config {
    #[serde(default)]
    /// `global` — global.
    pub global: GlobalConfig,
    /// `transport` — transport.  Always emitted (no
    /// `skip_serializing_if`) because the `[transport.rotation]`
    /// anti-DPI knob is meant to be discoverable by reading the file.
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// `peers` — peers.
    pub peers: Vec<PeerConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// `listen` — listen.
    pub listen: Vec<ListenConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `metrics` — metrics.
    pub metrics: Option<MetricsConfig>,
    /// Private-veil-network configuration. `None` (default) or
    /// `mode = "public"` keeps the open-veil behaviour; `mode =
    /// "private"` enables cert-gated handshake + DHT-propagated bans.
    /// See [`NetworkConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkConfig>,
    #[serde(
        default,
        rename = "Identity",
        alias = "identity",
        skip_serializing_if = "Option::is_none"
    )]
    /// `identity` — identity.
    pub identity: Option<IdentityConfig>,
    /// Optional local mesh (UDP realm) configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<MeshConfig>,
    /// Mobile / battery-aware tuning. Default off; opt-in
    /// for nodes running on battery-powered devices.
    #[serde(default, skip_serializing_if = "MobileConfig::is_default")]
    pub mobile: MobileConfig,
    /// Anonymity-layer config. Default off; opt-in for
    /// nodes willing to relay onion-routed anonymity cells.
    #[serde(default, skip_serializing_if = "AnonymityConfig::is_default")]
    pub anonymity: AnonymityConfig,
    /// Mailbox role config. Default
    /// off; opt-in by setting `mailbox.enabled = true` for nodes
    /// willing to host store-and-forward blobs for offline receivers.
    #[serde(default, skip_serializing_if = "MailboxConfig::is_default")]
    pub mailbox: MailboxConfig,
    /// Signed update mechanism config. Default
    /// off; opt-in by setting `expected_issuer_pk` + `manifest_urls`.
    #[serde(default, skip_serializing_if = "UpdateConfig::is_default")]
    pub update: UpdateConfig,
    /// Abuse-resistance tuning. All fields default to conservative values.
    #[serde(default, skip_serializing_if = "AbuseConfig::is_default")]
    pub abuse: AbuseConfig,
    /// Local App IPC configuration.
    #[serde(default, skip_serializing_if = "IpcConfig::is_default")]
    pub ipc: IpcConfig,
    /// Priority queue weights for outgoing frames (WRR).
    /// Index 0 = REALTIME, 1 = INTERACTIVE, 2 = BULK, 3 = BACKGROUND.
    #[serde(default, skip_serializing_if = "PriorityWeights::is_default")]
    pub priority_weights: PriorityWeights,
    /// SOCKS5 proxy configuration.
    #[serde(default, skip_serializing_if = "ProxyConfig::is_default")]
    pub proxy: ProxyConfig,
    /// Routing-plane tuning (re-announce interval, etc.).
    #[serde(default, skip_serializing_if = "RoutingConfig::is_default")]
    pub routing: RoutingConfig,
    /// DHT background task tuning.
    #[serde(default, skip_serializing_if = "DhtConfig::is_default")]
    pub dht: DhtConfig,
    /// Anycast resolution policy (signed-only vs best-effort).  Defaults
    /// to best-effort for backward compat; production deployments that
    /// route trust-sensitive traffic through anycast should set
    /// `resolve_policy = "signed_only"`.
    #[serde(default, skip_serializing_if = "AnycastConfig::is_default")]
    pub anycast: AnycastConfig,
    /// Session-layer keepalive and idle-timeout tuning.
    #[serde(default, skip_serializing_if = "SessionConfig::is_default")]
    pub session: SessionConfig,
    /// Hot-standby transport handover tuning).
    /// Controls whether per-session warm-probe tasks are spawned.
    #[serde(default, skip_serializing_if = "HotStandbyConfig::is_default")]
    pub hot_standby: HotStandbyConfig,
    /// Gateway attachment lifecycle tuning.
    #[serde(default, skip_serializing_if = "GatewayConfig::is_default")]
    pub gateway: GatewayConfig,
    /// Bootstrap peers for initial DHT routing table population.
    /// These are contacted at startup to perform FIND_NODE(self).
    /// Unlike `peers`, bootstrap connections are not maintained — the session
    /// is closed after the initial FIND_NODE exchange unless the peer also
    /// appears in `peers`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bootstrap_peers: Vec<BootstrapPeer>,
    /// Pinned relay nodes. Connections to these nodes are
    /// maintained unconditionally — the runtime will reconnect with
    /// exponential back-off whenever the connection drops.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned_relays: Vec<PinnedRelay>,
    /// Friend list for `FriendsOnly` visibility scope.
    /// Node IDs (hex-encoded) that may discover this node when visibility is
    /// set to `FriendsOnly`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub friend_list: Option<FriendList>,
    /// NAT traversal configuration.
    #[serde(default, skip_serializing_if = "NatConfig::is_default")]
    pub nat: NatConfig,
    /// PoW challenge rate-limiter tuning.
    #[serde(default, skip_serializing_if = "PowConfig::is_default")]
    pub pow: PowConfig,
    /// Outbound reconnect back-off tuning.
    #[serde(default, skip_serializing_if = "ConnectionConfig::is_default")]
    pub connection: ConnectionConfig,
    /// Node capacity and load-shedding tuning.
    #[serde(default, skip_serializing_if = "NodeCapacityConfig::is_default")]
    pub capacity: NodeCapacityConfig,
    /// Peer Exchange (PEX) configuration.
    #[serde(default, skip_serializing_if = "PexConfig::is_default")]
    pub pex: PexConfig,

    /// Master switch for all on-disk persistence.
    ///
    /// When `false`, no snapshot files are written and no restore is attempted
    /// on startup — all `*_persist_path` settings are silently ignored.
    /// Useful for ephemeral nodes, CI environments, or troubleshooting.
    ///
    /// Default: `true` (persistence active when paths are configured).
    #[serde(
        default = "Config::default_persist_enabled",
        skip_serializing_if = "Config::is_default_persist_enabled"
    )]
    pub persist_enabled: bool,
}

impl Config {
    fn default_persist_enabled() -> bool {
        true
    }
    fn is_default_persist_enabled(v: &bool) -> bool {
        *v
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            global: GlobalConfig::default(),
            transport: TransportConfig::default(),
            peers: Vec::new(),
            listen: Vec::new(),
            metrics: None,
            network: None,
            identity: None,
            mesh: None,
            mobile: MobileConfig::default(),
            anonymity: AnonymityConfig::default(),
            mailbox: MailboxConfig::default(),
            update: UpdateConfig::default(),
            abuse: AbuseConfig::default(),
            ipc: IpcConfig::default(),
            priority_weights: PriorityWeights::default(),
            proxy: ProxyConfig::default(),
            routing: RoutingConfig::default(),
            dht: DhtConfig::default(),
            anycast: AnycastConfig::default(),
            session: SessionConfig::default(),
            hot_standby: HotStandbyConfig::default(),
            gateway: GatewayConfig::default(),
            bootstrap_peers: Vec::new(),
            pinned_relays: Vec::new(),
            friend_list: None,
            nat: NatConfig::default(),
            pow: PowConfig::default(),
            connection: ConnectionConfig::default(),
            capacity: NodeCapacityConfig::default(),
            pex: PexConfig::default(),
            persist_enabled: true,
        }
    }
}

// `IpcConfig` lifted to `veil_types::IpcConfig` so the
// freshly-extracted `veil-ipc` crate can consume it without
// re-importing this file. Re-exported below so existing
// `cfg::IpcConfig` call sites compile unchanged.
pub use veil_types::IpcConfig;

/// Weighted-round-robin weights for the 4 priority levels.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PriorityWeights {
    /// `realtime` — realtime.
    pub realtime: u32,
    /// `interactive` — interactive.
    pub interactive: u32,
    /// `bulk` — bulk.
    pub bulk: u32,
    /// `background` — background.
    pub background: u32,
}

impl Default for PriorityWeights {
    fn default() -> Self {
        Self {
            realtime: 8,
            interactive: 4,
            bulk: 2,
            background: 1,
        }
    }
}

impl PriorityWeights {
    /// `is_default` — see impl.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Convert to the `[u32; 4]` array used by `PriorityQueue`.
    pub fn to_array(&self) -> [u32; 4] {
        [self.realtime, self.interactive, self.bulk, self.background]
    }
}

/// SOCKS5 proxy configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProxyConfig {
    /// SOCKS5 ingress proxy. When `enabled`, the node accepts SOCKS5 CONNECT
    /// requests on `listen` and tunnels the resulting TCP streams through the
    /// veil to an exit node.
    #[serde(default)]
    pub socks5: Socks5Config,
    /// Exit proxy. When `enabled`, the node accepts veil proxy-connect
    /// streams and establishes outgoing TCP connections on the client's behalf.
    #[serde(default)]
    pub exit: ExitProxyConfig,
}

impl ProxyConfig {
    /// `is_default` — see impl.
    pub fn is_default(&self) -> bool {
        !self.socks5.enabled && !self.exit.enabled
    }
}

/// SOCKS5 ingress listener configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Socks5Config {
    /// Enable the SOCKS5 listener. Default: `false`.
    #[serde(default)]
    pub enabled: bool,
    /// TCP address to listen on. Default: `"127.0.0.1:1080"`.
    #[serde(default = "Socks5Config::default_listen")]
    pub listen: String,
    /// Node ID of the exit proxy to route SOCKS5 streams through.
    ///
    /// Format: 64-character hex string (32 bytes). Required when `enabled = true`.
    #[serde(default)]
    pub exit_node_id: Option<String>,
}

impl Socks5Config {
    fn default_listen() -> String {
        "127.0.0.1:1080".to_string()
    }

    /// Parse `exit_node_id` hex string into 32 bytes. Returns `None` if
    /// `exit_node_id` is absent or malformed.
    pub fn exit_node_id_bytes(&self) -> Option<[u8; 32]> {
        veil_util::hex_to_array::<32>(self.exit_node_id.as_deref()?).ok()
    }
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: Self::default_listen(),
            exit_node_id: None,
        }
    }
}

/// Exit proxy configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExitProxyConfig {
    /// Enable exit proxy. When `true`, this node will forward proxy-connect
    /// streams to external TCP destinations. Default: `false`.
    #[serde(default)]
    pub enabled: bool,
    /// bypass the default deny-list for private/loopback/link-local
    /// IP ranges. Default `false` — connections to RFC1918 (10/8, 172.16/12
    /// 192.168/16), loopback (127/8, ::1), link-local (169.254/16 — cloud
    /// metadata endpoints), unique-local (fc00::/7, fe80::/10), multicast and
    /// broadcast addresses are refused with `PermissionDenied`. Only enable
    /// in isolated testbeds where the exit is trusted to probe internal nets.
    #[serde(default)]
    pub allow_private: bool,
}

/// Configuration for the local mesh UDP realm.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MeshConfig {
    /// UDP address to bind the realm listener on (e.g. "0.0.0.0:9100").
    pub bind_addr: String,
    /// Realm identifier as 32 hex characters (16 bytes).
    pub realm_id: String,
    /// **Opt-in UDP obfuscation** — base64 pre-shared key (>=16 bytes
    /// decoded). When set, mesh DATA datagrams are AEAD-wrapped via
    /// `veil-udp-obfs` so passive DPI sees only ciphertext (the OVL1 magic
    /// is hidden). All realm members must share the same PSK (operator
    /// distributes it OOB). Beacons stay plaintext (discovery). Unset (default)
    /// -> plaintext mesh, unchanged behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_psk: Option<String>,
    /// UDP broadcast/multicast address for beacon discovery.
    #[serde(default = "default_beacon_addr")]
    pub beacon_addr: String,
    /// Automatically connect to Gateway nodes discovered via mesh beacons.
    ///
    /// When `true` (default), the runtime reads `IS_GATEWAY` beacons and
    /// initiates outbound sessions to up to `autodiscover_max_concurrent`
    /// gateways at a time.
    #[serde(default = "MeshConfig::default_autodiscover_gateway")]
    pub autodiscover_gateway: bool,
    /// Maximum simultaneous outbound sessions to auto-discovered gateways.
    ///
    /// Additional candidates are queued; once a session closes the next
    /// candidate is tried (default 3).
    #[serde(default = "MeshConfig::default_autodiscover_max_concurrent")]
    pub autodiscover_max_concurrent: usize,

    /// Minimum interval between processing two beacons from the same source
    ///. Duplicate beacons arriving within this window are silently
    /// dropped, preventing wasted CPU from high-frequency or network-duplicated
    /// beacon packets. Default: 3 seconds. 0 = deduplication disabled.
    #[serde(
        default = "MeshConfig::default_beacon_dedup_window_secs",
        skip_serializing_if = "MeshConfig::is_default_beacon_dedup_window_secs"
    )]
    pub beacon_dedup_window_secs: u64,

    /// Path for persisting the `AutoDiscoveredPeers` table.
    /// Restored on startup so the node knows nearby gateways before the first
    /// beacon round. `None` disables persistence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autodiscover_persist_path: Option<String>,

    /// **SECURITY (audit 2026-05-29, A5)** — when `true`, the beacon
    /// receiver DROPS unsigned beacons instead of accepting them as
    /// "legacy".  An unsigned beacon lets an on-link attacker register
    /// or redirect neighbor links and inject `IS_GATEWAY` entries without any
    /// key.  Recommended `true` for any non-loopback / hostile-LAN realm.
    ///
    /// **Default `true` (C-03):** unsigned beacons are rejected, closing the
    /// on-link injection vector by default. Set `false` only for legacy interop
    /// with deployments still emitting unsigned beacons (flipping signed-on
    /// across a live unsigned network partitions those nodes — roll signed
    /// beacons out fleet-wide first).
    #[serde(
        default = "MeshConfig::default_require_signed_beacons",
        skip_serializing_if = "MeshConfig::is_default_require_signed_beacons"
    )]
    pub require_signed_beacons: bool,

    /// **SECURITY (C-03)** — when `true`, the node advertises its role
    /// (`IS_GATEWAY` / `IS_RELAY` / `HAS_INTERNET`) in its mesh beacon so
    /// neighbours can auto-discover it. **Default `false`:** the beacon carries
    /// `role_flags = 0`, so a passive on-link observer cannot single the node
    /// out as a gateway/relay (a targeting / censorship signal). Operators who
    /// want beacon-based gateway auto-discovery opt in explicitly. NB: the
    /// stable `node_id` is still broadcast — eliminating that requires the
    /// rotating-ephemeral-ID redesign (see the `veil-mesh` beacon docs).
    #[serde(
        default = "MeshConfig::default_advertise_role_in_beacon",
        skip_serializing_if = "MeshConfig::is_default_advertise_role_in_beacon"
    )]
    pub advertise_role_in_beacon: bool,
}

impl MeshConfig {
    fn default_autodiscover_gateway() -> bool {
        true
    }
    fn default_require_signed_beacons() -> bool {
        true
    }
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_default_require_signed_beacons(v: &bool) -> bool {
        *v
    }
    fn default_advertise_role_in_beacon() -> bool {
        false
    }
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_default_advertise_role_in_beacon(v: &bool) -> bool {
        !*v
    }
    fn default_autodiscover_max_concurrent() -> usize {
        3
    }
    pub fn default_beacon_dedup_window_secs() -> u64 {
        3
    }
    fn is_default_beacon_dedup_window_secs(v: &u64) -> bool {
        *v == 3
    }
}

/// mobile / battery-aware tuning. All fields default to
/// the off-position so that desktop / server / Pi-on-AC deployments
/// see no behaviour change unless the operator explicitly opts in.
///
/// When `low_battery_threshold_pct` is `Some(t)` and the local
/// battery reading falls at-or-below `t`, the runtime multiplies
/// non-deadline-driven probe intervals by `low_battery_multiplier`.
/// Eviction ticks, deadline-driven re-mints (announcement
/// half-validity, sovereign re-issue) are deliberately NOT
/// throttled — missing those would break correctness, whereas
/// stretching probe cadence only delays liveness signal.
///
/// On Linux the battery is read from `/sys/class/power_supply/BAT*`.
/// On other platforms the runtime reports `100` (assumes AC) so
/// throttling never engages.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MobileConfig {
    /// Battery percentage at-or-below which probe rates throttle.
    /// `None` (default) disables battery awareness entirely.
    /// Typical mobile setting: `30` (kicks in at 30 % remaining).
    /// Out-of-range values (>100) are clamped at validate time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_battery_threshold_pct: Option<u8>,
    /// Multiplier applied to probe intervals when battery is below
    /// the threshold. e.g. `4` means probes happen 4× less often.
    /// Capped at [`MobileConfig::MAX_LOW_BATTERY_MULTIPLIER`] so a
    /// misconfig doesn't completely starve probe traffic.
    /// Default `4`.
    #[serde(default = "MobileConfig::default_low_battery_multiplier")]
    pub low_battery_multiplier: u32,
    /// multiplier applied to per-session keepalive
    /// intervals when the runtime's `background_mode` flag is set
    /// (toggled via `AdminCommand::SetMobileBackgroundMode` from
    /// the GUI wrapper / mobile app's onPause/onResume hooks).
    ///
    /// Composes multiplicatively with battery scaling — backgrounded
    /// + low-battery → both factors apply.
    ///
    /// Default `1` (feature off — keepalive cadence unchanged).
    /// Mobile profile sets this to `60` (30s → 30 min) so a
    /// suspended-by-OS app preserves its sessions through suspension
    /// rather than re-handshaking every foreground.
    ///
    /// Capped at [`MobileConfig::MAX_BACKGROUND_KEEPALIVE_MULTIPLIER`]
    /// so a misconfig doesn't push keepalive past the operator's
    /// idle_timeout (which would close the session anyway).
    #[serde(default = "MobileConfig::default_background_keepalive_multiplier")]
    pub background_keepalive_multiplier: u32,
    /// deferred : when `true` AND battery is at-or-below
    /// `low_battery_threshold_pct`, the maintenance tick skips eviction +
    /// diagnostic phases (eviction sweeps, route-cache resize, runtime-summary
    /// refresh, transport-cache evict, discovered-peers persist) on
    /// `(multiplier-1)/multiplier` of ticks. Deadline-driven phases (
    /// announcement re-mint, sovereign re-issue
    /// relay-directory publish, rendezvous re-sign), memory-
    /// budget pressure eviction, congestion accounting, and the heartbeat
    /// ALWAYS run — throttling them would break correctness.
    ///
    /// Default `false` (off). Recommended for cellular/mobile deployments
    /// once on-device measurements show that maintenance-tick CPU is a
    /// real drain. Composes c `low_battery_threshold_pct` + the existing
    /// `low_battery_multiplier` — same threshold AND same scale factor.
    #[serde(default, skip_serializing_if = "is_false")]
    pub low_battery_throttle_maintenance: bool,
    /// deferred : when `Some(window_ms)` AND battery is
    /// at-or-below `low_battery_threshold_pct`, the session runner defers
    /// the priority-queue drain pass when the queue's head priority is
    /// **strictly below** `veil_proto::header::priority::INTERACTIVE`
    /// up to `window_ms` since the previous flush. Goal: cellular radio
    /// wakes once per burst instead of once per BACKGROUND frame.
    ///
    /// Interactive frames bypass the delay (they always sit at queue head
    /// thanks to the WRR weights, so they trigger an immediate drain).
    /// Coalescing only kicks in when EVERY queued frame is non-interactive
    /// AND the runtime opted in.
    ///
    /// Default `None` (off). Reasonable values when enabled: 200-500 ms.
    /// Capped at [`MobileConfig::MAX_OUTBOUND_BATCH_WINDOW_MS`] so that
    /// misconfig "10 s coalesce" doesn't starve liveness probes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_batch_window_ms: Option<u32>,
}

impl MobileConfig {
    /// Hard cap on multiplier — avoids "1 probe per hour" footguns.
    pub const MAX_LOW_BATTERY_MULTIPLIER: u32 = 16;

    /// Hard cap on background keepalive multiplier. A 30s base
    /// × 120 = 60 min — safely under any reasonable
    /// `session.idle_timeout_secs` (default 86400 = 24h). Anything
    /// higher would risk the session timing out during background
    /// → defeats the purpose.
    pub const MAX_BACKGROUND_KEEPALIVE_MULTIPLIER: u32 = 120;

    /// Hard cap on outbound batch window. ROUTE_PROBE adaptive scheduler
    /// ticks at 1 s minimum, and keepalives at 30 s — coalescing past 1 s
    /// would risk stalling those. 1000 ms ceiling keeps the slice
    /// strictly a radio-wake-coalescer, not a liveness-killer.
    pub const MAX_OUTBOUND_BATCH_WINDOW_MS: u32 = 1000;

    fn default_low_battery_multiplier() -> u32 {
        4
    }
    fn default_background_keepalive_multiplier() -> u32 {
        1
    }

    pub fn is_default(c: &Self) -> bool {
        c.low_battery_threshold_pct.is_none()
            && c.low_battery_multiplier == Self::default_low_battery_multiplier()
            && c.background_keepalive_multiplier == Self::default_background_keepalive_multiplier()
            && !c.low_battery_throttle_maintenance
            && c.outbound_batch_window_ms.is_none()
    }

    /// Resolved, clamped outbound-batch window for the current battery
    /// reading. Returns `None` (no coalescing) when:
    /// * `outbound_batch_window_ms` is unset, OR
    /// * battery awareness is disabled / battery above threshold (same
    ///   gating as `battery_multiplier` — only throttle when we have
    ///   actually-low battery, not when feature is just configured).
    ///
    /// Otherwise returns `Some(ms.clamp(1, MAX_OUTBOUND_BATCH_WINDOW_MS))`.
    pub fn outbound_batch_window(&self, battery_pct: u8) -> Option<std::time::Duration> {
        let ms = self.outbound_batch_window_ms?;
        if self.battery_multiplier(battery_pct) == 1 {
            return None;
        }
        let clamped = ms.clamp(1, Self::MAX_OUTBOUND_BATCH_WINDOW_MS);
        Some(std::time::Duration::from_millis(clamped as u64))
    }

    /// Resolved decision: should the maintenance tick skip throttle-able
    /// phases on this iteration? `tick_index` is the running 0-based
    /// counter of how many ticks have fired since the runtime started.
    /// Returns `true` only when the operator opted in AND battery is
    /// actually low AND the multiplier > 1 AND this tick falls outside
    /// the every-Nth slot.
    pub fn skip_throttleable_maintenance(&self, battery_pct: u8, tick_index: u64) -> bool {
        if !self.low_battery_throttle_maintenance {
            return false;
        }
        let mult = self.battery_multiplier(battery_pct);
        if mult <= 1 {
            return false;
        }
        !tick_index.is_multiple_of(mult as u64)
    }

    /// Resolved, clamped multiplier for the current background-mode
    /// state. Returns `1` (no scaling) when `background_mode` is
    /// false; otherwise returns `background_keepalive_multiplier`
    /// clamped to `[1, MAX_BACKGROUND_KEEPALIVE_MULTIPLIER]`.
    pub fn background_keepalive_factor(&self, background_mode: bool) -> u32 {
        if !background_mode {
            return 1;
        }
        self.background_keepalive_multiplier
            .clamp(1, Self::MAX_BACKGROUND_KEEPALIVE_MULTIPLIER)
    }

    /// Resolved, validated multiplier for the current battery reading.
    /// Returns `1` (no throttle) when:
    /// * threshold is unset (battery awareness disabled), OR
    /// * battery is above threshold (device has enough juice), OR
    /// * battery is `0` (sentinel for "AC / unknown" — never throttle
    ///   a node we can't prove is on battery; safer for mis-detection
    ///   on non-Linux platforms or odd hardware that reports `0`).
    ///
    /// Otherwise returns `low_battery_multiplier.clamp(1, MAX)`.
    pub fn battery_multiplier(&self, battery_pct: u8) -> u32 {
        let Some(threshold) = self.low_battery_threshold_pct else {
            return 1;
        };
        if battery_pct == 0 || battery_pct > threshold {
            return 1;
        }
        self.low_battery_multiplier
            .clamp(1, Self::MAX_LOW_BATTERY_MULTIPLIER)
    }
}

/// signed-update mechanism config.
///
/// All fields default to "feature disabled". Setting
/// `expected_issuer_pk` + `manifest_urls` together turns on the
/// `veil-cli update --check` path; `installed_version_path` is
/// required only on nodes that perform actual updates (the
/// check-only path can run without persistence).
///
/// # Why all-Option (not derive(Default) with empty Vec)
///
/// A misconfigured node that has `manifest_urls` set but
/// `expected_issuer_pk` empty would accept a manifest signed by
/// ANY key — that's catastrophic. Both fields must be set for
/// the update mechanism to engage; either being None disables
/// the path entirely. Validation surfaces "half-configured"
/// state as an explicit issue.
// UpdateConfig moved to veil-types so veil-update can
// consume it without depending on cfg. Re-exported below.
pub use veil_types::UpdateConfig;

// `impl UpdateConfig { is_default, is_check_enabled, is_apply_enabled }`
// moved to veil-types alongside the struct.

/// anonymity-layer config. All fields default to off so
/// nodes opt in explicitly — the costs of being an anonymity relay
/// (constant-rate cells, anti-correlation timing, bandwidth quota)
/// are non-trivial and shouldn't be incurred by default.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AnonymityConfig {
    /// When `true`, the local node advertises [`cap_flags::ANONYMITY_RELAY`]
    /// during OVL1 handshakes and is eligible to be selected as a hop
    /// in remote peers' onion-routing circuits. When
    /// `false` (default), the bit is never set and the node is
    /// invisible to relay-directory lookups — the node
    /// still uses anonymity for its OWN sends, just doesn't carry
    /// other peers' circuits.
    ///
    /// [`cap_flags::ANONYMITY_RELAY`]: veil_proto::session::cap_flags::ANONYMITY_RELAY
    #[serde(default, skip_serializing_if = "is_false")]
    pub relay_capable: bool,
    /// bandwidth (bytes per second) the node advertises
    /// for anonymity-relay traffic in its DHT relay-directory entry.
    /// Self-reported and UNVERIFIED — relays can lie. Senders use it
    /// for load-balancing across candidate hops; a future reputation
    /// slice can downweight relays that consistently fail to deliver
    /// their claimed capacity. `0` (default) = "I don't know /
    /// don't shape" — senders treat it as "lowest-priority candidate".
    /// Only meaningful when `relay_capable = true`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub advertised_bps: u32,
}

impl AnonymityConfig {
    pub fn is_default(c: &Self) -> bool {
        !c.relay_capable && c.advertised_bps == 0
    }
}

/// Anycast service-tag resolution policy.
///
/// IPC anycast handler routes through `AnycastService::resolve`, which
/// honours [`AnycastConfig::resolve_policy`].  Default is `signed_bound`
/// (audit cycle-6 T2 — secure-by-default: only candidates with a valid
/// owner-signature AND a provable `BLAKE3(owner_pubkey) == node_id`
/// binding are returned). Opt into `best_effort` explicitly for
/// discovery-only deployments that must accept legacy unsigned (v1) records.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AnycastConfig {
    /// String form (TOML-friendly): `"signed_bound"` (default),
    /// `"signed_only"`, or `"best_effort"`.  See [`AnycastResolvePolicyKind`].
    #[serde(default, skip_serializing_if = "AnycastResolvePolicyKind::is_default")]
    pub resolve_policy: AnycastResolvePolicyKind,
}

impl AnycastConfig {
    pub fn is_default(c: &Self) -> bool {
        AnycastResolvePolicyKind::is_default(&c.resolve_policy)
    }
}

/// Anycast resolve-policy variants.  Mirrors `veil_anycast::AnycastResolvePolicy`;
/// kept in cfg layer i.e. veil-cfg doesn't depend on veil-anycast.
/// Node-runtime translates this to the runtime enum at construction
/// of `AnycastService`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnycastResolvePolicyKind {
    /// Accept any record (signed or unsigned).  audit cycle-6 (T2): NO LONGER
    /// the default — opt into this explicitly for discovery-only deployments.
    BestEffort,
    /// Only return candidates with a valid Ed25519 owner-signature.
    /// Note: signature integrity only — a sybil signing under their own
    /// key while claiming another node's `node_id` will pass.  Use
    /// `signed_bound` to close that gap.
    SignedOnly,
    /// Only return candidates with a valid signature AND a provable owner-
    /// binding (`BLAKE3(owner_pubkey) == node_id`, `sig_key_idx == 0`).
    /// Strongest trust posture available in the synchronous resolve path.
    /// Use for production trust-sensitive routing (mailbox routing of
    /// PII, sovereign-identity service discovery, payment endpoints).
    ///
    /// audit cycle-6 (T2): now the DEFAULT (secure-by-default — the network has
    /// no legacy unsigned-anycast deployments to preserve).
    #[default]
    SignedBound,
}

impl AnycastResolvePolicyKind {
    fn is_default(v: &Self) -> bool {
        matches!(v, Self::SignedBound)
    }
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Mailbox role configuration.
///
/// When `enabled = true`, the daemon hosts a store-and-forward
/// mailbox at `<veil_dir>/mailbox/blobs.db` (redb) for offline
/// receivers. The mailbox is independent of the anonymity-relay
/// role — operators can run one without the other.
///
/// Quota and TTL fields fall through to `veil-mailbox`'s built-in
/// defaults (100 MiB per receiver, 10 GiB global, 7-day TTL, 60
/// puts/min/receiver) when set to zero.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct MailboxConfig {
    /// Master switch. Default off — operators must opt in.
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,
    /// Override per-receiver quota (bytes). `0` = use crate default.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub quota_per_receiver_bytes: u64,
    /// Override global per-relay quota (bytes). `0` = use crate default.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub quota_global_bytes: u64,
    /// Override blob TTL (seconds). `0` = use crate default (7 days).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub ttl_secs: u64,
    /// Override per-receiver rate limit (puts per minute). `0` =
    /// use crate default.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub rate_limit_per_minute: u32,
    /// require capability tokens on PUT.
    /// Default `false` for backward compat with pre-slice senders. When
    /// `true`, tokenless puts are rejected with `CapabilityRequired`.
    /// Operators flip to `true` after the receiver-side mint API ships
    /// and senders are propagating tokens via RendezvousAd v3.
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_capability_token: bool,
    /// per-sender byte quota.  `0` (the serde default) ⇒ the runtime
    /// uses the crate-default safe quota
    /// (`veil_mailbox::DEFAULT_QUOTA_PER_SENDER_BYTES`, 10 MiB).
    /// An explicit non-zero value overrides; to fully disable per-sender
    /// accounting in an operator config (NOT recommended), set a very
    /// large value (e.g. 18446744073709551615 / `u64::MAX`).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub quota_per_sender_bytes: u64,
    /// Push-provider credentials. When this
    /// section is empty / absent, the daemon falls back to the
    /// default `LogOnlyDispatcher` (puts get logged but no FCM/APNs
    /// API call is made). Configure either FCM, APNs, or both —
    /// missing-provider tokens fail with `ProviderNotConfigured`.
    #[serde(default, skip_serializing_if = "MailboxPushConfig::is_default")]
    pub push: MailboxPushConfig,
}

impl MailboxConfig {
    pub fn is_default(c: &Self) -> bool {
        *c == Self::default()
    }
}

/// Per-provider credentials for the mailbox push pipeline (
/// T1.4 P6 —).
///
/// All fields are optional. Combinations:
/// all empty → daemon uses `LogOnlyDispatcher` (no real push)
/// only `fcm_credentials_path` set → only FCM tokens dispatched
/// only `apns_*` set (all 4 required: p8 + key_id + team_id + bundle_id)
/// → only APNs tokens dispatched
/// both → multi-provider routing by `PushToken.provider`
///
/// Paths are read at daemon startup; reload required for credential
/// rotation (no hot-reload yet).
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct MailboxPushConfig {
    /// Path to a Google service-account JSON file for FCM v1 OAuth.
    /// Empty / missing → FCM disabled.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fcm_credentials_path: String,
    /// Path to an APNs Auth Key (.p8 PEM, ECDSA P-256).
    /// All four `apns_*` fields must be set together to enable APNs.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub apns_p8_path: String,
    /// APNs Auth Key id (10-char Apple-assigned).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub apns_key_id: String,
    /// Apple Developer team id (10-char).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub apns_team_id: String,
    /// App bundle id sent as APNs `apns-topic`
    /// (e.g. `com.example.VeilClient`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub apns_bundle_id: String,
    /// APNs environment selector — "production" (default) or "sandbox".
    /// Empty → production.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub apns_environment: String,
}

impl MailboxPushConfig {
    pub fn is_default(c: &Self) -> bool {
        *c == Self::default()
    }

    /// True if any FCM credential is configured.
    pub fn fcm_enabled(&self) -> bool {
        !self.fcm_credentials_path.is_empty()
    }

    /// True if all four required APNs fields are populated.
    pub fn apns_enabled(&self) -> bool {
        !self.apns_p8_path.is_empty()
            && !self.apns_key_id.is_empty()
            && !self.apns_team_id.is_empty()
            && !self.apns_bundle_id.is_empty()
    }
}

#[cfg(test)]
mod mobile_tests {
    use super::*;

    #[test]
    fn epic483_5_default_disabled_returns_multiplier_one() {
        let c = MobileConfig::default();
        assert_eq!(
            c.battery_multiplier(5),
            1,
            "default config must NOT throttle"
        );
        assert_eq!(c.battery_multiplier(50), 1);
        assert_eq!(c.battery_multiplier(100), 1);
    }

    #[test]
    fn epic483_5_below_threshold_throttles_with_multiplier() {
        let c = MobileConfig {
            low_battery_threshold_pct: Some(30),
            low_battery_multiplier: 4,
            background_keepalive_multiplier: 1,
            ..MobileConfig::default()
        };
        assert_eq!(c.battery_multiplier(20), 4, "below threshold must throttle");
        assert_eq!(
            c.battery_multiplier(30),
            4,
            "AT threshold must throttle (boundary)"
        );
    }

    #[test]
    fn epic483_5_above_threshold_no_throttle() {
        let c = MobileConfig {
            low_battery_threshold_pct: Some(30),
            low_battery_multiplier: 4,
            background_keepalive_multiplier: 1,
            ..MobileConfig::default()
        };
        assert_eq!(c.battery_multiplier(31), 1, "1pp above threshold");
        assert_eq!(c.battery_multiplier(100), 1);
    }

    #[test]
    fn epic483_5_zero_battery_treated_as_ac_no_throttle() {
        // 0 = "AC / unknown" sentinel — never throttle on this signal
        // it's the safer default for mis-detection.
        let c = MobileConfig {
            low_battery_threshold_pct: Some(50),
            low_battery_multiplier: 4,
            background_keepalive_multiplier: 1,
            ..MobileConfig::default()
        };
        assert_eq!(
            c.battery_multiplier(0),
            1,
            "battery=0 is the AC sentinel and must NOT trigger throttle"
        );
    }

    #[test]
    fn epic483_5_multiplier_clamped_at_max() {
        let c = MobileConfig {
            low_battery_threshold_pct: Some(50),
            low_battery_multiplier: 1_000_000,
            background_keepalive_multiplier: 1,
            ..MobileConfig::default()
        };
        assert_eq!(
            c.battery_multiplier(10),
            MobileConfig::MAX_LOW_BATTERY_MULTIPLIER,
            "absurd multiplier must be clamped at MAX_LOW_BATTERY_MULTIPLIER"
        );
    }

    #[test]
    fn epic483_5_multiplier_floors_at_one() {
        let c = MobileConfig {
            low_battery_threshold_pct: Some(50),
            low_battery_multiplier: 0, // operator typo
            background_keepalive_multiplier: 1,
            ..MobileConfig::default()
        };
        assert_eq!(
            c.battery_multiplier(10),
            1,
            "multiplier=0 must floor at 1 (no throttle), never starve probes"
        );
    }

    // ── background_keepalive_factor ───────────────────

    #[test]
    fn epic483_1_factor_returns_1_when_mode_off() {
        let c = MobileConfig {
            low_battery_threshold_pct: None,
            low_battery_multiplier: 4,
            background_keepalive_multiplier: 60,
            ..MobileConfig::default()
        };
        assert_eq!(
            c.background_keepalive_factor(false),
            1,
            "background_mode=false → factor 1 even with large multiplier"
        );
    }

    #[test]
    fn epic483_1_factor_returns_multiplier_when_mode_on() {
        let c = MobileConfig {
            low_battery_threshold_pct: None,
            low_battery_multiplier: 4,
            background_keepalive_multiplier: 60,
            ..MobileConfig::default()
        };
        assert_eq!(c.background_keepalive_factor(true), 60);
    }

    #[test]
    fn epic483_1_factor_clamps_at_max() {
        let c = MobileConfig {
            low_battery_threshold_pct: None,
            low_battery_multiplier: 4,
            background_keepalive_multiplier: 10_000,
            ..MobileConfig::default()
        };
        assert_eq!(
            c.background_keepalive_factor(true),
            MobileConfig::MAX_BACKGROUND_KEEPALIVE_MULTIPLIER,
            "absurd config multiplier must be clamped at MAX_BACKGROUND_KEEPALIVE_MULTIPLIER \
             so keepalive can't stretch past idle_timeout"
        );
    }

    #[test]
    fn epic483_1_factor_floors_multiplier_at_one() {
        let c = MobileConfig {
            low_battery_threshold_pct: None,
            low_battery_multiplier: 4,
            background_keepalive_multiplier: 0, // operator typo
            ..MobileConfig::default()
        };
        assert_eq!(
            c.background_keepalive_factor(true),
            1,
            "multiplier=0 must floor at 1 (no scaling) — never starve probes"
        );
    }

    // ── deferred : skip_throttleable_maintenance ────

    #[test]
    fn epic483_5d_throttle_maint_off_by_default() {
        let c = MobileConfig::default();
        assert!(
            !c.skip_throttleable_maintenance(10, 1),
            "default config must NOT skip — feature is opt-in"
        );
        assert!(!c.skip_throttleable_maintenance(10, 7));
    }

    #[test]
    fn epic483_5d_throttle_maint_skips_n_minus_1_of_n() {
        let c = MobileConfig {
            low_battery_threshold_pct: Some(30),
            low_battery_multiplier: 4,
            low_battery_throttle_maintenance: true,
            ..MobileConfig::default()
        };
        // Battery 10 % ⇒ multiplier 4 ⇒ skip when tick % 4!= 0
        assert!(!c.skip_throttleable_maintenance(10, 0), "tick 0 runs");
        assert!(c.skip_throttleable_maintenance(10, 1), "tick 1 skips");
        assert!(c.skip_throttleable_maintenance(10, 2), "tick 2 skips");
        assert!(c.skip_throttleable_maintenance(10, 3), "tick 3 skips");
        assert!(!c.skip_throttleable_maintenance(10, 4), "tick 4 runs");
        assert!(!c.skip_throttleable_maintenance(10, 8), "tick 8 runs");
    }

    #[test]
    fn epic483_5d_throttle_maint_battery_above_threshold_no_skip() {
        let c = MobileConfig {
            low_battery_threshold_pct: Some(30),
            low_battery_multiplier: 4,
            low_battery_throttle_maintenance: true,
            ..MobileConfig::default()
        };
        for i in 0..10u64 {
            assert!(
                !c.skip_throttleable_maintenance(50, i),
                "battery=50 above threshold=30 ⇒ never skip"
            );
        }
    }

    #[test]
    fn epic483_5d_throttle_maint_zero_battery_treated_as_ac() {
        let c = MobileConfig {
            low_battery_threshold_pct: Some(50),
            low_battery_multiplier: 4,
            low_battery_throttle_maintenance: true,
            ..MobileConfig::default()
        };
        for i in 0..10u64 {
            assert!(
                !c.skip_throttleable_maintenance(0, i),
                "battery=0 = AC sentinel ⇒ never skip"
            );
        }
    }

    #[test]
    fn epic483_5d_throttle_maint_flag_off_overrides_low_battery() {
        // Threshold + low battery + multiplier=4, but flag explicitly off
        // ⇒ never skip. Defends against the "battery scaling kicked in
        // automatically" worry — the maintenance throttle is independent.
        let c = MobileConfig {
            low_battery_threshold_pct: Some(30),
            low_battery_multiplier: 4,
            low_battery_throttle_maintenance: false,
            ..MobileConfig::default()
        };
        for i in 0..10u64 {
            assert!(
                !c.skip_throttleable_maintenance(10, i),
                "flag=false must always run (the multiplier is for ROUTE_PROBE, not maintenance)"
            );
        }
    }

    // ── deferred : outbound_batch_window ──────────

    #[test]
    fn epic483_5o_outbound_batch_off_by_default() {
        let c = MobileConfig::default();
        assert_eq!(
            c.outbound_batch_window(50),
            None,
            "default config must NOT coalesce — feature is opt-in"
        );
        assert_eq!(c.outbound_batch_window(10), None);
    }

    #[test]
    fn epic483_5o_outbound_batch_returns_window_when_configured() {
        let c = MobileConfig {
            low_battery_threshold_pct: Some(30),
            low_battery_multiplier: 4,
            outbound_batch_window_ms: Some(300),
            ..MobileConfig::default()
        };
        assert_eq!(
            c.outbound_batch_window(10),
            Some(std::time::Duration::from_millis(300)),
            "below threshold + window configured ⇒ Some(window)"
        );
        assert_eq!(
            c.outbound_batch_window(30),
            Some(std::time::Duration::from_millis(300)),
            "AT threshold (boundary) ⇒ Some(window)"
        );
    }

    #[test]
    fn epic483_5o_outbound_batch_above_threshold_returns_none() {
        let c = MobileConfig {
            low_battery_threshold_pct: Some(30),
            low_battery_multiplier: 4,
            outbound_batch_window_ms: Some(300),
            ..MobileConfig::default()
        };
        assert_eq!(
            c.outbound_batch_window(50),
            None,
            "battery above threshold ⇒ no coalescing"
        );
    }

    #[test]
    fn epic483_5o_outbound_batch_zero_battery_returns_none() {
        // 0 = AC sentinel — same semantics as battery_multiplier.
        let c = MobileConfig {
            low_battery_threshold_pct: Some(50),
            low_battery_multiplier: 4,
            outbound_batch_window_ms: Some(300),
            ..MobileConfig::default()
        };
        assert_eq!(
            c.outbound_batch_window(0),
            None,
            "battery=0 = AC sentinel ⇒ never coalesce"
        );
    }

    #[test]
    fn epic483_5o_outbound_batch_clamped_at_max() {
        let c = MobileConfig {
            low_battery_threshold_pct: Some(30),
            low_battery_multiplier: 4,
            outbound_batch_window_ms: Some(60_000), // 60 s — absurd
            ..MobileConfig::default()
        };
        assert_eq!(
            c.outbound_batch_window(10),
            Some(std::time::Duration::from_millis(
                MobileConfig::MAX_OUTBOUND_BATCH_WINDOW_MS as u64
            )),
            "absurd window clamped at MAX so it can't stall liveness probes"
        );
    }

    #[test]
    fn epic483_5o_outbound_batch_threshold_unset_returns_none() {
        // Window configured but threshold not — feature gated on having
        // BOTH so operator who only set window (typo) doesn't see
        // unexpected coalescing.
        let c = MobileConfig {
            low_battery_threshold_pct: None,
            outbound_batch_window_ms: Some(300),
            ..MobileConfig::default()
        };
        assert_eq!(
            c.outbound_batch_window(10),
            None,
            "threshold unset ⇒ feature off (consistent c battery_multiplier)"
        );
    }

    // ── is_default coverage with new fields ─────────────────────────────

    #[test]
    fn epic483_5_is_default_recognises_serde_defaults() {
        // `is_default` compares against the SERDE defaults (multiplier=4
        // keepalive=1), not the Rust `Default` derive (which zero-init's
        // every field). Operator who omits the section entirely from
        // TOML lands in this state — `is_default` must return true so
        // serialisation skips emitting an all-default `[mobile]` block.
        let c = MobileConfig {
            low_battery_threshold_pct: None,
            low_battery_multiplier: MobileConfig::default_low_battery_multiplier(),
            background_keepalive_multiplier: MobileConfig::default_background_keepalive_multiplier(
            ),
            low_battery_throttle_maintenance: false,
            outbound_batch_window_ms: None,
        };
        assert!(
            MobileConfig::is_default(&c),
            "section omitted from TOML must register as default"
        );

        let c2 = MobileConfig {
            low_battery_throttle_maintenance: true,
            ..c.clone()
        };
        assert!(
            !MobileConfig::is_default(&c2),
            "throttle_maintenance=true is non-default"
        );

        let c3 = MobileConfig {
            outbound_batch_window_ms: Some(200),
            ..c
        };
        assert!(
            !MobileConfig::is_default(&c3),
            "outbound_batch_window_ms=Some is non-default"
        );
    }
}

/// Per-peer frame rate cap (frames/s).  Default sized for **2 Gbps per peer**
/// throughput baseline on full-MTU 1500-byte frames:
///
/// ```text
/// 2 Gbps / (1500 B × 8 b/B) ≈ 167 000 frames/s
/// ```
///
/// Bumped from prior 500 fps (which capped throughput at ~6 Mbps with MTU 1500)
/// after audit batch 2026-05-22 testnet iperf revealed silent rate-limit drops
/// were the dominant ogate-tunnel bottleneck (not session-flapping, not CPU).
/// Operators on bandwidth-constrained links can lower this through
/// `[abuse] rate_limit_fps = N` in node.toml.
fn default_rate_limit_fps() -> f64 {
    200_000.0
}
/// Per-peer burst headroom (frames).  2× the rate cap so a brief 200 ms
/// stall doesn't immediately drop a sustained flow.
fn default_rate_limit_burst() -> f64 {
    400_000.0
}
fn default_pow_min_difficulty() -> u32 {
    16
}
fn default_ban_threshold() -> u32 {
    5
}
fn default_ban_initial_secs() -> u64 {
    5
}
fn default_ban_step_secs() -> u64 {
    5
}
fn default_ban_max_secs() -> u64 {
    3600
}

/// Routing-plane configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct RoutingConfig {
    /// ROUTE_PROBE send interval in seconds (default 30).
    #[serde(default = "RoutingConfig::default_route_probe_interval_secs")]
    pub route_probe_interval_secs: u64,

    /// Route re-announce interval in seconds (default 30).
    #[serde(default = "RoutingConfig::default_reannounce_interval_secs")]
    pub reannounce_interval_secs: u64,

    /// Route cache TTL in seconds (default 120).
    #[serde(default = "RoutingConfig::default_route_cache_ttl_secs")]
    pub route_cache_ttl_secs: u64,

    /// Route request retry backoff in milliseconds [attempt0, attempt1, attempt2] (default [500, 1000, 2000]).
    #[serde(default = "RoutingConfig::default_route_request_backoff_ms")]
    pub route_request_backoff_ms: [u64; 3],

    /// iterative-DHT fallback baseline timeout (ms). After
    /// the legacy `RouteRequest` flood (TTL=7) exhausts its retries, the
    /// miss-handler fires a `RecursiveQuery(FIND_NODE)` and awaits the
    /// signed `RecursiveResponse` up to this budget. Tunable for slow
    /// links (cellular, satellite, congested 4G — bump to 20000-30000) or
    /// tight LAN clusters (drop to 3000-5000 for fast-fail).
    /// adaptive logic adjusts on top of this baseline by ±50% based on
    /// recent miss-rate, clamped to [1000, 60000] ms. Default 10000.
    #[serde(default = "RoutingConfig::default_dht_fallback_timeout_ms")]
    pub dht_fallback_timeout_ms: u64,

    /// fraction (0-100) of `MAX_PENDING_RECURSIVE`
    /// at which the DHT fallback starts skipping new attempts to avoid
    /// piling onto a starved dispatcher. Default 75 — once 75% of the
    /// pending-recursive map is occupied, route-miss events that would
    /// trigger a fresh fallback are silently dropped (incremented as
    /// `dht_fallback_skipped_backpressure_total`). Set to 100 to disable
    /// the safety valve and always attempt.
    #[serde(default = "RoutingConfig::default_dht_fallback_backpressure_threshold_pct")]
    pub dht_fallback_backpressure_threshold_pct: u8,

    /// enable adaptive timeout scaling. When `true`
    /// the fallback tracks the last 20 outcomes (resolved/miss) per node and
    /// scales the effective timeout up to 1.5× if miss-rate exceeds 50%
    /// down to 0.67× if miss-rate < 10%. Clamped to [1000, 60000] ms.
    /// Default `false` — opt-in to avoid surprises on well-tuned clusters
    /// where the baseline is correct.
    #[serde(default)]
    pub dht_fallback_adaptive: bool,

    /// priority-aware timeout multipliers. Routes
    /// for INTERACTIVE-priority traffic time out at
    /// `dht_fallback_timeout_ms × interactive_mult / 100`, BACKGROUND at
    /// `× background_mult / 100`. Defaults [50, 200] — INTERACTIVE
    /// (chat / RPC) gets half budget (fast-fail to surface stuck user
    /// flows), BACKGROUND (cover-traffic / DHT housekeeping) gets double
    /// (no user is waiting). Set both to 100 to disable priority-aware
    /// behaviour and use the baseline for everything.
    #[serde(default = "RoutingConfig::default_dht_fallback_priority_mult")]
    pub dht_fallback_priority_mult: [u16; 2],

    /// Master switch for the iterative-DHT route-discovery fallback
    /// (`try_seed_route_via_find_node`). Default `true`. When `false` the
    /// miss-handler records the partition event and drops the frame after the
    /// `RouteRequest` flood exhausts — exactly the pre-fallback behaviour. The
    /// always-on `try_recursive_relay_via_dht` greedy relay is unaffected (it
    /// carries the actual cross-topology delivery). Exposed for operators and
    /// for fallback-on/off A/B measurement: in practice the FIND_NODE fallback
    /// resolves ~0% of route-misses while recursive-relay handles ~100%.
    #[serde(default = "RoutingConfig::default_dht_fallback_enabled")]
    pub dht_fallback_enabled: bool,

    /// Minimum `network_reachability_score` (0.0–1.0) before logging a
    /// partition warning. Default: 0.2 (warn when ≥ 80 % of recent route
    /// attempts fail without recovery). Set to 0.0 to disable.
    #[serde(default = "RoutingConfig::default_partition_score_threshold")]
    pub partition_score_threshold: f64,

    /// Capacity of the route-dedup cache (number of entries, default 4096).
    #[serde(default = "RoutingConfig::default_route_seen_capacity")]
    pub route_seen_capacity: usize,

    /// Time window for route dedup entries in seconds (default 120).
    #[serde(default = "RoutingConfig::default_route_seen_window_secs")]
    pub route_seen_window_secs: u64,

    /// Maximum gossip hop TTL — frames with a higher hop count are dropped (default 2).
    #[serde(default = "RoutingConfig::default_max_gossip_hops")]
    pub max_gossip_hops: u8,

    /// Maximum relative score difference for two routes to be considered
    /// equal-cost (ECMP) and eligible for load balancing.
    ///
    /// `0.20` means routes within 20 % of the best route's score are
    /// placed in the ECMP group. Set to `0.0` to disable ECMP.
    #[serde(default = "RoutingConfig::default_ecmp_score_band")]
    pub ecmp_score_band: f64,

    /// Enable redundant send for critical frames.
    ///
    /// When `true`, frames are transmitted simultaneously on the two best
    /// available paths. The receiver deduplicates via `content_id`.
    /// Reduces p99 latency at the cost of doubled bandwidth on those paths.
    ///
    /// **Adaptive-failover bundle**: pair with
    /// `multi_path_enabled = true` for the recommended setup; see that
    /// field's doc for the full picture. Verify with
    /// `veil-cli node routes` — the header line shows `redundant-send: ON`.
    #[serde(default)]
    pub redundant_send: bool,

    /// Minimum ROUTE_PROBE send interval in seconds when the path is unstable
    /// (default 5). Used by the adaptive-probe scheduler.
    #[serde(default = "RoutingConfig::default_probe_min_interval_secs")]
    pub probe_min_interval_secs: u64,

    /// Maximum ROUTE_PROBE send interval in seconds when the path is stable
    /// (default 120). Used by the adaptive-probe scheduler.
    #[serde(default = "RoutingConfig::default_probe_max_interval_secs")]
    pub probe_max_interval_secs: u64,

    /// RTT stability threshold for adaptive probing (default 0.05).
    ///
    /// Stability is defined as `std_dev / mean` of the last N RTT samples.
    /// When `stability < probe_stability_threshold` the path is considered
    /// stable and probes are sent at `probe_max_interval_secs`; above the
    /// threshold probes are sent at `probe_min_interval_secs`.
    #[serde(default = "RoutingConfig::default_probe_stability_threshold")]
    pub probe_stability_threshold: f64,

    /// Filesystem path for route-cache persistence.
    ///
    /// When set, a snapshot of the route cache is written to this file
    /// periodically and on clean shutdown. At startup the snapshot is restored
    /// (tagged as stale) so the node can forward packets immediately while the
    /// routing protocol converges. `None` disables persistence entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_persist_path: Option<String>,

    /// How often (in seconds) to flush the route-cache snapshot to disk
    /// (default 30). Ignored when `cache_persist_path` is `None`.
    #[serde(default = "RoutingConfig::default_cache_persist_interval_secs")]
    pub cache_persist_interval_secs: u64,

    /// Maximum age (in seconds) of a persisted snapshot before it is
    /// considered too stale to restore (default 3600 = 1 h).
    ///
    /// If the snapshot file's modification time is older than this value
    /// the file is skipped (and deleted) at startup rather than loading
    /// obsolete topology data.
    #[serde(default = "RoutingConfig::default_cache_persist_max_age_secs")]
    pub cache_persist_max_age_secs: u64,

    /// Fanout for epidemic broadcast: number of random neighbours each node
    /// forwards a new `EpidemicBroadcast` to.
    #[serde(default = "RoutingConfig::default_epidemic_fanout")]
    pub epidemic_fanout: usize,

    /// Maximum payload size (bytes) accepted for an `EpidemicBroadcast`
    ///. Frames exceeding this limit are treated as
    /// protocol violations.
    #[serde(default = "RoutingConfig::default_epidemic_max_payload")]
    pub epidemic_max_payload: usize,

    // ── battery-aware routing ──────────────────────────────────────
    /// Battery penalty multiplier for peers with a critically-low charge
    /// (below `battery_threshold_low`). Default: 3.0 (4× normal score).
    #[serde(default = "RoutingConfig::default_battery_penalty_low")]
    pub battery_penalty_low: f64,

    /// Battery penalty multiplier for peers with a medium-low charge
    /// (below `battery_threshold_medium`). Default: 0.5 (1.5× normal score).
    #[serde(default = "RoutingConfig::default_battery_penalty_medium")]
    pub battery_penalty_medium: f64,

    /// Battery charge percentage (0–100) below which `battery_penalty_low`
    /// applies. Default: 20.
    #[serde(default = "RoutingConfig::default_battery_threshold_low")]
    pub battery_threshold_low: u8,

    /// Battery charge percentage (0–100) below which `battery_penalty_medium`
    /// applies (but ≥ `battery_threshold_low`). Default: 40.
    #[serde(default = "RoutingConfig::default_battery_threshold_medium")]
    pub battery_threshold_medium: u8,

    // ── multi-path delivery ────────────────────────────────────────
    /// Enable sending on multiple parallel paths for latency-sensitive frames
    ///. When `true` and `prio <= multi_path_min_priority`, the top
    /// `max_parallel_paths` candidates receive a copy of the frame. The
    /// receiver deduplicates via `content_id` (`ForwardSeenSet`).
    /// Default: `false` (off — uses more bandwidth).
    ///
    /// **Adaptive-failover bundle**: turn this on together with
    /// `redundant_send = true` to make the node spread critical traffic
    /// across the top-2 alternative paths. Combined with the automatic
    /// per-session-close `RouteCache::demote_via` (always on) this gives
    /// fast failover when an intermediate peer goes down — operators
    /// observing `node routes <dst>` will see the alt `next_hop` win
    /// within ~1 RTT instead of waiting for the next probe cycle.
    #[serde(default)]
    pub multi_path_enabled: bool,

    /// Maximum number of parallel paths to send on when multi-path is active
    ///. Default: 2.
    #[serde(
        default = "RoutingConfig::default_max_parallel_paths",
        skip_serializing_if = "RoutingConfig::is_default_max_parallel_paths"
    )]
    pub max_parallel_paths: u8,

    /// Frames with priority ≤ this value are eligible for multi-path delivery
    ///. Default: `INTERACTIVE` (1) — REALTIME and INTERACTIVE.
    /// Bulk and Background frames are not worth the bandwidth overhead.
    #[serde(
        default = "RoutingConfig::default_multi_path_min_priority",
        skip_serializing_if = "RoutingConfig::is_default_multi_path_min_priority"
    )]
    pub multi_path_min_priority: u8,

    // ── relay reputation penalties ─────────────────────────────────
    /// Minimum relay attempts before the reputation penalty is applied.
    ///
    /// Below this threshold `relay_success_ema` is treated as 1.0 (no penalty).
    /// Default: 10 — requires a statistically meaningful sample before penalising.
    #[serde(
        default = "RoutingConfig::default_relay_reputation_min_attempts",
        skip_serializing_if = "RoutingConfig::is_default_relay_reputation_min_attempts"
    )]
    pub relay_reputation_min_attempts: u32,

    /// `relay_success_ema` below this value triggers the reputation penalty.
    ///
    /// Default: 0.5 — penalise relays that succeed less than half the time.
    #[serde(
        default = "RoutingConfig::default_relay_reputation_threshold",
        skip_serializing_if = "RoutingConfig::is_default_relay_reputation_threshold"
    )]
    pub relay_reputation_threshold: f32,

    /// Score multiplier applied to relays with a low success rate.
    ///
    /// `effective_score × relay_reputation_penalty` — default 2.0 makes
    /// unreliable relays appear 2× more expensive in route selection.
    #[serde(
        default = "RoutingConfig::default_relay_reputation_penalty",
        skip_serializing_if = "RoutingConfig::is_default_relay_reputation_penalty"
    )]
    pub relay_reputation_penalty: f64,

    // ── jitter + bandwidth penalties ────────────────────────────────
    /// Additive jitter penalty weight for route scoring.
    ///
    /// Applied as `jitter_penalty_weight × max(0, jitter_ms − jitter_threshold_ms)`.
    /// For REALTIME traffic the weight is doubled (more sensitive to jitter).
    /// Default: 0.5 — each ms of excess jitter adds half a virtual RTT ms.
    #[serde(
        default = "RoutingConfig::default_jitter_penalty_weight",
        skip_serializing_if = "RoutingConfig::is_default_jitter_penalty_weight"
    )]
    pub jitter_penalty_weight: f64,

    /// Jitter below this threshold (ms) is not penalised.
    ///
    /// Prevents noise-floor jitter (< 20 ms) from unfairly penalising nearby
    /// paths. Default: 20 ms.
    #[serde(
        default = "RoutingConfig::default_jitter_threshold_ms",
        skip_serializing_if = "RoutingConfig::is_default_jitter_threshold_ms"
    )]
    pub jitter_threshold_ms: u32,

    /// Score multiplier applied to narrow-bandwidth (< 256 kbps) candidates
    /// for BULK and BACKGROUND priority frames.
    ///
    /// `effective_score × (1 + narrow_bandwidth_bulk_penalty)` — so a value of
    /// `2.0` makes narrow paths appear 3× more expensive for bulk traffic.
    /// Default: 2.0.
    #[serde(
        default = "RoutingConfig::default_narrow_bandwidth_bulk_penalty",
        skip_serializing_if = "RoutingConfig::is_default_narrow_bandwidth_bulk_penalty"
    )]
    pub narrow_bandwidth_bulk_penalty: f64,

    // ── distributed tracing ────────────────────────────────────────
    /// Fraction of outgoing `DELIVERY_FORWARD` frames that get a random
    /// `trace_id` injected (0.0 = off, 1.0 = all). Default: 0.01 (1 %).
    #[serde(default = "RoutingConfig::default_trace_sample_rate")]
    pub trace_sample_rate: f64,

    /// Number of trace-hop records kept in the in-memory ring buffer per node
    ///. Oldest records are evicted when the buffer is full.
    /// Default: 10_000.
    #[serde(default = "RoutingConfig::default_trace_buffer_size")]
    pub trace_buffer_size: usize,

    /// Filesystem path for RTT table persistence.
    ///
    /// When set, `RttTable` snapshots are periodically written to this file
    /// and loaded on startup so routing decisions have warm latency data
    /// immediately after a restart. `None` (default) disables persistence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_persist_path: Option<String>,

    /// How often to flush the RTT snapshot to disk in seconds.
    ///
    /// Default: 60 s. Ignored when `rtt_persist_path` is `None`.
    #[serde(
        default = "RoutingConfig::default_rtt_persist_interval_secs",
        skip_serializing_if = "RoutingConfig::is_default_rtt_persist_interval_secs"
    )]
    pub rtt_persist_interval_secs: u64,

    /// Path for persisting the local Vivaldi coordinate.
    /// Restored on startup so topology-aware routing decisions are warm immediately.
    /// `None` (default) disables persistence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vivaldi_persist_path: Option<String>,

    /// Path for persisting the ranked GatewayList.
    /// Restored on startup so leaf nodes can connect to the best gateway
    /// without waiting for a scoring round. `None` disables persistence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_persist_path: Option<String>,

    /// Path for persisting the peer pubkeys cache.
    /// Restored on startup to avoid re-verifying known peer identities.
    /// `None` disables persistence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_pubkeys_persist_path: Option<String>,

    /// capability/region labels this node claims about itself.
    /// Each label is a 4-byte tag (shorter strings zero-padded, longer
    /// strings truncated to 4 bytes). Attached to outgoing
    /// `RouteResponsePayload` and signed so requesters can filter routes
    /// by attribute (e.g. "only routes through peers labelled `exit`").
    /// Bounded by `MAX_TARGET_LABELS = 8`. Default: empty (no claims).
    ///
    /// Example: `routing.target_labels = ["exit", "low", "qiwi"]`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_labels: Vec<String>,

    /// (Level 2): controls who can learn this node's listen
    /// transports via `RouteRequest`/`RouteResponse`. Default: `Public`
    /// (any peer may probe — gated by PoW if `abuse.pow_min_difficulty > 0`).
    ///
    /// * `Public` — current behaviour; transports disclosed to anyone who
    ///   solves the optional PoW challenge.
    /// * `ContactsOnly` — `RouteRequest`s from peers absent from
    ///   `peer_pubkeys` (no prior handshake) are silently dropped — no
    ///   `PowChallenge`, no `RouteResponse`. Suitable for private-deploy
    ///   nodes that only ever talk to a known contact graph.
    /// * `IntroductionOnly` — `RouteResponse` carries `relay_ids` only;
    ///   `transports` is always empty. Requesters must reach this node
    ///   via one of the advertised relays. Suitable for nodes that
    ///   intentionally stay behind dedicated relay infrastructure
    ///   (Tor-style hidden-service approximation without rendezvous).
    #[serde(default, skip_serializing_if = "DiscoveryMode::is_default")]
    pub discovery_mode: DiscoveryMode,
}

// c: DiscoveryMode moved to veil-types so proto::session can
// reference it without reverse-importing cfg. Re-exported below.
pub use veil_types::DiscoveryMode;

impl RoutingConfig {
    fn default_route_probe_interval_secs() -> u64 {
        30
    }
    fn default_reannounce_interval_secs() -> u64 {
        30
    }
    fn default_route_cache_ttl_secs() -> u64 {
        120
    }
    fn default_route_request_backoff_ms() -> [u64; 3] {
        [500, 1000, 2000]
    }
    fn default_dht_fallback_timeout_ms() -> u64 {
        10_000
    }
    fn default_dht_fallback_backpressure_threshold_pct() -> u8 {
        75
    }
    fn default_dht_fallback_priority_mult() -> [u16; 2] {
        [50, 200]
    }
    fn default_dht_fallback_enabled() -> bool {
        true
    }
    fn default_partition_score_threshold() -> f64 {
        0.2
    }
    fn default_route_seen_capacity() -> usize {
        4096
    }
    fn default_route_seen_window_secs() -> u64 {
        120
    }
    /// lowered from 8 to 2 — with DHT-routed recursive relay
    /// gossip only needs to cover immediate neighbours (1-2 hops).
    fn default_max_gossip_hops() -> u8 {
        2
    }
    fn default_cache_persist_interval_secs() -> u64 {
        30
    }
    fn default_cache_persist_max_age_secs() -> u64 {
        3600
    }
    fn default_ecmp_score_band() -> f64 {
        0.20
    }
    fn default_probe_min_interval_secs() -> u64 {
        5
    }
    fn default_probe_max_interval_secs() -> u64 {
        120
    }
    fn default_probe_stability_threshold() -> f64 {
        0.05
    }
    fn default_epidemic_fanout() -> usize {
        3
    }
    fn default_epidemic_max_payload() -> usize {
        4096
    }
    fn default_battery_penalty_low() -> f64 {
        3.0
    }
    fn default_battery_penalty_medium() -> f64 {
        0.5
    }
    fn default_battery_threshold_low() -> u8 {
        20
    }
    fn default_battery_threshold_medium() -> u8 {
        40
    }
    fn default_trace_sample_rate() -> f64 {
        0.01
    }
    fn default_trace_buffer_size() -> usize {
        10_000
    }
    fn default_rtt_persist_interval_secs() -> u64 {
        60
    }
    fn is_default_rtt_persist_interval_secs(v: &u64) -> bool {
        *v == 60
    }
    fn default_max_parallel_paths() -> u8 {
        2
    }
    fn is_default_max_parallel_paths(v: &u8) -> bool {
        *v == 2
    }
    fn default_multi_path_min_priority() -> u8 {
        veil_proto::header::priority::INTERACTIVE
    }
    fn is_default_multi_path_min_priority(v: &u8) -> bool {
        *v == veil_proto::header::priority::INTERACTIVE
    }
    fn default_relay_reputation_min_attempts() -> u32 {
        10
    }
    fn is_default_relay_reputation_min_attempts(v: &u32) -> bool {
        *v == 10
    }
    fn default_relay_reputation_threshold() -> f32 {
        0.5
    }
    fn is_default_relay_reputation_threshold(v: &f32) -> bool {
        (*v - 0.5).abs() < f32::EPSILON
    }
    fn default_relay_reputation_penalty() -> f64 {
        2.0
    }
    fn is_default_relay_reputation_penalty(v: &f64) -> bool {
        (*v - 2.0).abs() < f64::EPSILON
    }
    fn default_jitter_penalty_weight() -> f64 {
        0.5
    }
    fn is_default_jitter_penalty_weight(v: &f64) -> bool {
        (*v - 0.5).abs() < f64::EPSILON
    }
    fn default_jitter_threshold_ms() -> u32 {
        20
    }
    fn is_default_jitter_threshold_ms(v: &u32) -> bool {
        *v == 20
    }
    fn default_narrow_bandwidth_bulk_penalty() -> f64 {
        2.0
    }
    fn is_default_narrow_bandwidth_bulk_penalty(v: &f64) -> bool {
        (*v - 2.0).abs() < f64::EPSILON
    }

    /// `is_default` — see impl.
    pub fn is_default(&self) -> bool {
        self.route_probe_interval_secs == Self::default_route_probe_interval_secs()
            && self.reannounce_interval_secs == Self::default_reannounce_interval_secs()
            && self.route_cache_ttl_secs == Self::default_route_cache_ttl_secs()
            && self.route_request_backoff_ms == Self::default_route_request_backoff_ms()
            && self.dht_fallback_timeout_ms == Self::default_dht_fallback_timeout_ms()
            && self.dht_fallback_backpressure_threshold_pct
                == Self::default_dht_fallback_backpressure_threshold_pct()
            && !self.dht_fallback_adaptive
            && self.dht_fallback_priority_mult == Self::default_dht_fallback_priority_mult()
            && self.dht_fallback_enabled
            && (self.partition_score_threshold - Self::default_partition_score_threshold()).abs()
                < f64::EPSILON
            && self.route_seen_capacity == Self::default_route_seen_capacity()
            && self.route_seen_window_secs == Self::default_route_seen_window_secs()
            && self.max_gossip_hops == Self::default_max_gossip_hops()
            && (self.ecmp_score_band - Self::default_ecmp_score_band()).abs() < f64::EPSILON
            && !self.redundant_send
            && self.probe_min_interval_secs == Self::default_probe_min_interval_secs()
            && self.probe_max_interval_secs == Self::default_probe_max_interval_secs()
            && (self.probe_stability_threshold - Self::default_probe_stability_threshold()).abs()
                < f64::EPSILON
            && self.cache_persist_path.is_none()
            && self.cache_persist_interval_secs == Self::default_cache_persist_interval_secs()
            && self.cache_persist_max_age_secs == Self::default_cache_persist_max_age_secs()
            && self.epidemic_fanout == Self::default_epidemic_fanout()
            && self.epidemic_max_payload == Self::default_epidemic_max_payload()
            && (self.battery_penalty_low - Self::default_battery_penalty_low()).abs() < f64::EPSILON
            && (self.battery_penalty_medium - Self::default_battery_penalty_medium()).abs()
                < f64::EPSILON
            && self.battery_threshold_low == Self::default_battery_threshold_low()
            && self.battery_threshold_medium == Self::default_battery_threshold_medium()
            && (self.trace_sample_rate - Self::default_trace_sample_rate()).abs() < f64::EPSILON
            && self.trace_buffer_size == Self::default_trace_buffer_size()
            && self.rtt_persist_path.is_none()
            && Self::is_default_rtt_persist_interval_secs(&self.rtt_persist_interval_secs)
            && self.vivaldi_persist_path.is_none()
            && self.gateway_persist_path.is_none()
            && self.peer_pubkeys_persist_path.is_none()
            && !self.multi_path_enabled
            && Self::is_default_max_parallel_paths(&self.max_parallel_paths)
            && Self::is_default_multi_path_min_priority(&self.multi_path_min_priority)
            && Self::is_default_relay_reputation_min_attempts(&self.relay_reputation_min_attempts)
            && Self::is_default_relay_reputation_threshold(&self.relay_reputation_threshold)
            && Self::is_default_relay_reputation_penalty(&self.relay_reputation_penalty)
            && Self::is_default_jitter_penalty_weight(&self.jitter_penalty_weight)
            && Self::is_default_jitter_threshold_ms(&self.jitter_threshold_ms)
            && Self::is_default_narrow_bandwidth_bulk_penalty(&self.narrow_bandwidth_bulk_penalty)
            && self.target_labels.is_empty()
            && self.discovery_mode.is_default()
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            route_probe_interval_secs: Self::default_route_probe_interval_secs(),
            reannounce_interval_secs: Self::default_reannounce_interval_secs(),
            route_cache_ttl_secs: Self::default_route_cache_ttl_secs(),
            route_request_backoff_ms: Self::default_route_request_backoff_ms(),
            dht_fallback_timeout_ms: Self::default_dht_fallback_timeout_ms(),
            dht_fallback_backpressure_threshold_pct:
                Self::default_dht_fallback_backpressure_threshold_pct(),
            dht_fallback_adaptive: false,
            dht_fallback_priority_mult: Self::default_dht_fallback_priority_mult(),
            dht_fallback_enabled: Self::default_dht_fallback_enabled(),
            partition_score_threshold: Self::default_partition_score_threshold(),
            route_seen_capacity: Self::default_route_seen_capacity(),
            route_seen_window_secs: Self::default_route_seen_window_secs(),
            max_gossip_hops: Self::default_max_gossip_hops(),
            ecmp_score_band: Self::default_ecmp_score_band(),
            redundant_send: false,
            probe_min_interval_secs: Self::default_probe_min_interval_secs(),
            probe_max_interval_secs: Self::default_probe_max_interval_secs(),
            probe_stability_threshold: Self::default_probe_stability_threshold(),
            cache_persist_path: None,
            cache_persist_interval_secs: Self::default_cache_persist_interval_secs(),
            cache_persist_max_age_secs: Self::default_cache_persist_max_age_secs(),
            epidemic_fanout: Self::default_epidemic_fanout(),
            epidemic_max_payload: Self::default_epidemic_max_payload(),
            battery_penalty_low: Self::default_battery_penalty_low(),
            battery_penalty_medium: Self::default_battery_penalty_medium(),
            battery_threshold_low: Self::default_battery_threshold_low(),
            battery_threshold_medium: Self::default_battery_threshold_medium(),
            trace_sample_rate: Self::default_trace_sample_rate(),
            trace_buffer_size: Self::default_trace_buffer_size(),
            rtt_persist_path: None,
            rtt_persist_interval_secs: Self::default_rtt_persist_interval_secs(),
            vivaldi_persist_path: None,
            gateway_persist_path: None,
            peer_pubkeys_persist_path: None,
            multi_path_enabled: false,
            max_parallel_paths: Self::default_max_parallel_paths(),
            multi_path_min_priority: Self::default_multi_path_min_priority(),
            relay_reputation_min_attempts: Self::default_relay_reputation_min_attempts(),
            relay_reputation_threshold: Self::default_relay_reputation_threshold(),
            relay_reputation_penalty: Self::default_relay_reputation_penalty(),
            jitter_penalty_weight: Self::default_jitter_penalty_weight(),
            jitter_threshold_ms: Self::default_jitter_threshold_ms(),
            narrow_bandwidth_bulk_penalty: Self::default_narrow_bandwidth_bulk_penalty(),
            target_labels: Vec::new(),
            discovery_mode: DiscoveryMode::default(),
        }
    }
}

/// DHT background task configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DhtConfig {
    /// How often to republish DHT entries in seconds (default 1800 = 30 min).
    #[serde(default = "DhtConfig::default_republish_interval_secs")]
    pub republish_interval_secs: u64,

    /// How often to run DHT cleanup (expired entry eviction) in seconds (default 60).
    #[serde(default = "DhtConfig::default_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,

    /// Whether this node participates in DHT storage (accepts STORE / DELETE).
    ///
    /// Default: `true`. Set to `false` to make this node a pure DHT router
    /// (responds to FIND_NODE / FIND_VALUE but refuses to store values).
    #[serde(
        default = "DhtConfig::default_participate",
        skip_serializing_if = "DhtConfig::is_default_participate"
    )]
    pub participate: bool,

    /// Kademlia k-bucket size — contacts returned per FIND_NODE response (default 20).
    #[serde(default = "DhtConfig::default_k")]
    pub k: u8,

    /// Kademlia α (alpha) — parallel queries per iterative lookup round (default 3).
    #[serde(default = "DhtConfig::default_alpha")]
    pub alpha: u8,

    /// Maximum iterative lookup rounds before giving up (default 20).
    #[serde(default = "DhtConfig::default_max_rounds")]
    pub max_rounds: u8,

    /// Timeout for a single FIND_NODE / FIND_VALUE RPC in milliseconds (default 2000).
    #[serde(default = "DhtConfig::default_find_node_timeout_ms")]
    pub find_node_timeout_ms: u64,

    /// Weight applied to the Vivaldi topology factor in DHT node ranking.
    ///
    /// `composite_score = xor_distance × (1 + vivaldi_weight × vivaldi_factor)`
    ///
    /// where `vivaldi_factor = vivaldi_distance(local, node) / 100.0`.
    ///
    /// `0.0` disables topology-aware placement (pure XOR order).
    /// Default `0.3` gives a mild topology preference without overriding XOR.
    #[serde(
        default = "DhtConfig::default_vivaldi_weight",
        skip_serializing_if = "DhtConfig::is_default_vivaldi_weight"
    )]
    pub vivaldi_weight: f64,

    /// Path for persisting the DHT k-bucket routing table.
    /// Contacts are restored on startup so the node has warm routing state
    /// without waiting for a full bootstrap round. `None` disables persistence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_persist_path: Option<String>,

    /// Path for persisting DHT stored values.
    /// Restored values survive restarts so this node can continue serving as
    /// a DHT storage replica without waiting for republish. `None` disables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values_persist_path: Option<String>,

    /// Directory for a disk-backed **RocksDB cold tier** for DHT values.
    ///
    /// When set (and the binary is built with the `rocksdb-cold` feature —
    /// on by default for `veil-cli`), DHT values demoted out of the
    /// in-memory hot tier are written to this on-disk RocksDB store instead
    /// of the bounded in-memory cold map. This lifts the entry-count ceiling
    /// from RAM to disk, so a dedicated DHT node can serve > 1M entries, and
    /// cold entries survive restarts. `None` (default) keeps the
    /// all-in-memory tiered store.
    ///
    /// Distinct from [`values_persist_path`](Self::values_persist_path),
    /// which is a periodic JSON snapshot of the whole store: the cold tier is
    /// a live, continuously-updated key-value database (the hot tier remains
    /// RAM-only, so pair this with `values_persist_path` if you also want
    /// hot-tier entries restored on restart).
    ///
    /// Ignored — with a startup log line — when the binary lacks the
    /// `rocksdb-cold` feature or the RocksDB open fails; the store then falls
    /// back to the in-memory cold tier so the node keeps serving.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cold_store_path: Option<String>,

    ///path for persisting peer transport
    /// announcements (`SignedTransportAnnouncement` map). Restored
    /// entries survive a restart so the node can immediately answer
    /// `ResolveTransport` for previously-handshaked peers without
    /// waiting for them to re-`AnnounceTransport`. Each entry's
    /// signature + expiry is re-verified on load. `None` disables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_announcements_persist_path: Option<String>,

    ///interval (seconds) between
    /// transport-announcement snapshot flushes. Default 120 s.
    /// Ignored when `transport_announcements_persist_path` is `None`.
    #[serde(
        default = "DhtConfig::default_transport_announcements_persist_interval_secs",
        skip_serializing_if = "DhtConfig::is_default_transport_announcements_persist_interval_secs"
    )]
    pub transport_announcements_persist_interval_secs: u64,

    /// Maximum number of key-value entries in the DHT store.
    ///
    /// When full, the oldest entry is evicted (LRU). Default: 25_000.
    ///
    /// Worst-case memory: `max_store_entries × MAX_DHT_VALUE_BYTES` (16 KiB),
    /// so the default budget is ≈ 400 MB.  Operators running dedicated
    /// DHT-infra with large RAM (≥8 GB) and production fill levels can opt
    /// up to 250_000 (≈ 4 GB worst-case) via explicit config.  See
    /// `docs/OPERATIONS.md` "Default Tuning Guidance" for role-specific
    /// profiles (Leaf = 0, Core = 25k, dedicated DHT = 250k).
    #[serde(default = "DhtConfig::default_max_store_entries")]
    pub max_store_entries: usize,

    /// Optional **global byte budget** for the DHT value store.  When
    /// set, a STORE that would push the cumulative byte total past this
    /// value triggers eviction of the oldest entries (cold tier first,
    /// then hot demoted-and-evicted) until the new value fits.  If
    /// the new value alone exceeds the cap, it is refused outright.
    /// **Default `Some(400 MB)`** — a Core-node baseline that hard-bounds DHT
    /// store memory (matches the 25k × 16 KiB entry-cap worst case, keeping
    /// total node memory comfortably under ~512 MB). To RAISE the ceiling, set
    /// a larger value in `[dht]` (e.g. `4_000_000_000` for a dedicated seed).
    /// Because the field defaults to `Some(..)` and TOML has no null, omitting
    /// the key yields this default rather than "no cap" — the byte ceiling is
    /// always present via config (raise it, don't remove it).
    /// Audit batch 2026-05-23: closes the "count-cap doesn't bound memory if
    /// values approach `MAX_DHT_VALUE_BYTES`" gap.
    ///
    /// Recommended profiles (all overridable in `[dht]`):
    /// * **Leaf clients**: `Some(128_000_000)` (≈ 128 MB — set by the `mobile`
    ///   config profile; budget phones).
    /// * **Core nodes**: `Some(400_000_000)` (≈ 400 MB — this default).
    /// * **Dedicated DHT seeds**: `Some(4_000_000_000)` (≈ 4 GB — leaves
    ///   plenty of room for 250k entries close to `MAX_DHT_VALUE_BYTES`).
    ///
    /// RocksDB backend: the byte total is tracked best-effort because
    /// RocksDB evicts via background compaction; operators relying on
    /// hard byte limits should size `max_store_entries` conservatively.
    #[serde(
        default = "DhtConfig::default_max_store_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_store_bytes: Option<u64>,

    /// Per-origin byte budget (Phase 11e).  When set, a STORE whose signer
    /// pubkey is already holding `>= N` bytes in the local TieredStore is
    /// refused outright (caller sees the same `Ok(())` result the wire
    /// protocol returns for any silent drop).  Honest signers normally hold
    /// a handful of records (NameClaim + IdentityDocument + a small fan-out
    /// of AppEndpointEntry), so 64 KiB is a conservative ceiling that still
    /// leaves headroom for legitimate growth.  Misbehaving / Sybil signers
    /// can no longer fill the store unilaterally — they can only fill their
    /// own per-origin slice.  Unsigned legacy STOREs (when
    /// `allow_unsigned_store = true`) share a single synthetic origin
    /// bucket, so they collectively cap out at the same per-origin
    /// budget — the legacy inner-sig deployment pattern just needs
    /// operators to size this generously (≥ 4 MiB) until they migrate.
    /// `None` (default) disables the per-origin cap entirely — only the
    /// global [`max_store_bytes`] limit (if set) applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_origin_max_bytes: Option<u64>,

    /// enable shard-aware filtering — reject STORE requests for keys
    /// outside the node's local shard set (`key[0]` XOR-distance > 15).
    /// Default: `false` (accept all keys, legacy behaviour).
    #[serde(default)]
    pub shard_filtering: bool,

    /// when `true`, accept `StorePayload` values
    /// that lack the `(ed25519_pubkey, ed25519_sig)` authenticator
    /// tuple at the wire layer AND that ALSO fail the dispatcher's
    /// self-authenticating-magic validation. The legacy deployment pattern
    /// uses inner-record signatures (NameClaim, IdentityDocument,
    /// AnnounceAttachment, AppEndpointEntry all carry their own signed
    /// envelopes inside the `value` blob).
    ///
    /// audit cycle-6 (P1): default flipped to `false` (secure-by-default; the
    /// network has no legacy deployment to preserve). This no longer breaks the
    /// inner-sig records: the dispatcher's `DiscoveryMsg::Store` arm validates
    /// self-authenticating records (`validate_store_value_by_magic`) and writes
    /// them via the per-origin-capped `store_with_origin` path, which bypasses
    /// THIS gate (mirroring the recursive STORE plane). The gate now only
    /// rejects truly-unsigned junk that carries no recognised authenticator and
    /// no self-authenticating magic — i.e. arbitrary `(key, value)` poisoning.
    /// Set `true` only to re-admit raw unsigned STOREs (e.g. an experimental
    /// network that intentionally stores opaque unsigned blobs).
    #[serde(
        default = "DhtConfig::default_allow_unsigned_store",
        skip_serializing_if = "DhtConfig::is_default_allow_unsigned_store"
    )]
    pub allow_unsigned_store: bool,
}

impl DhtConfig {
    fn default_republish_interval_secs() -> u64 {
        1800
    }
    fn default_cleanup_interval_secs() -> u64 {
        60
    }
    fn default_participate() -> bool {
        true
    }
    fn is_default_participate(v: &bool) -> bool {
        *v
    }
    fn default_k() -> u8 {
        20
    }
    fn default_alpha() -> u8 {
        3
    }
    fn default_max_rounds() -> u8 {
        20
    }
    fn default_find_node_timeout_ms() -> u64 {
        2000
    }
    fn default_vivaldi_weight() -> f64 {
        0.3
    }
    fn is_default_vivaldi_weight(v: &f64) -> bool {
        (*v - 0.3).abs() < f64::EPSILON
    }
    /// **RAM-sensitive default.** 25 K entries × up to
    /// `MAX_DHT_VALUE_BYTES` (16 KiB) ≈ **400 MB worst-case** — fits
    /// in 2 GB constrained seeds.  Operators running dedicated DHT-infra
    /// with large RAM (≥8 GB) and production fill levels should opt up to
    /// 250_000 (≈ 4 GiB worst-case) via explicit config.  See
    /// `docs/OPERATIONS.md` → "Default Tuning Guidance" for profile-
    /// specific overrides (0 for leaf clients, 25k for general Core,
    /// 250k for dedicated DHT seeds).  Lowered from 100k to 25k when
    /// `MAX_DHT_VALUE_BYTES` rose 4 KiB→16 KiB (Phase 10 hybrid-1024
    /// identity docs) so the worst-case memory product (entries × value
    /// cap) held constant at ≈400 MB.  Originally lowered 1M→100k in audit
    /// batch 2026-05-21 (Phase C10) — previous default would OOM the
    /// default-tier seed.
    fn default_max_store_entries() -> usize {
        25_000
    }

    /// Core-node baseline: ~400 MB hard byte cap on the DHT store, so total
    /// node memory stays comfortably under ~512 MB. Matches the 25k-entry ×
    /// 16 KiB worst case. The `mobile` profile lowers this to ~128 MB; all
    /// values are overridable via `[dht] max_store_bytes`.
    fn default_max_store_bytes() -> Option<u64> {
        Some(400_000_000)
    }

    fn default_transport_announcements_persist_interval_secs() -> u64 {
        120
    }
    fn is_default_transport_announcements_persist_interval_secs(v: &u64) -> bool {
        *v == 120
    }

    fn default_allow_unsigned_store() -> bool {
        // audit cycle-6 (P1): secure-by-default. Self-authenticating records
        // (AP/AT/NM/ID/IR/MC/SB + PBAN) are accepted via the dispatcher's
        // validated `store_with_origin` / `handle_store` paths regardless of
        // this flag; it now gates ONLY raw unsigned junk.
        false
    }
    fn is_default_allow_unsigned_store(v: &bool) -> bool {
        // audit cycle-6 (P1): default is now `false`, so "is default" means the
        // value IS false. (Was `*v` when the default was `true`; the flip
        // inverted this, which would mis-mark a default config as non-default and
        // invert the `skip_serializing_if` semantics.)
        !*v
    }

    /// `is_default` — see impl.
    pub fn is_default(&self) -> bool {
        self.republish_interval_secs == Self::default_republish_interval_secs()
            && self.cleanup_interval_secs == Self::default_cleanup_interval_secs()
            && self.participate == Self::default_participate()
            && self.k == Self::default_k()
            && self.alpha == Self::default_alpha()
            && self.max_rounds == Self::default_max_rounds()
            && self.find_node_timeout_ms == Self::default_find_node_timeout_ms()
            && Self::is_default_vivaldi_weight(&self.vivaldi_weight)
            && self.routing_persist_path.is_none()
            && self.values_persist_path.is_none()
            && self.cold_store_path.is_none()
            && self.transport_announcements_persist_path.is_none()
            && Self::is_default_transport_announcements_persist_interval_secs(
                &self.transport_announcements_persist_interval_secs,
            )
            && self.max_store_entries == Self::default_max_store_entries()
            && self.max_store_bytes.is_none()
            && self.per_origin_max_bytes.is_none()
            && !self.shard_filtering
            && Self::is_default_allow_unsigned_store(&self.allow_unsigned_store)
    }
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            republish_interval_secs: Self::default_republish_interval_secs(),
            cleanup_interval_secs: Self::default_cleanup_interval_secs(),
            participate: Self::default_participate(),
            k: Self::default_k(),
            alpha: Self::default_alpha(),
            max_rounds: Self::default_max_rounds(),
            find_node_timeout_ms: Self::default_find_node_timeout_ms(),
            vivaldi_weight: Self::default_vivaldi_weight(),
            routing_persist_path: None,
            values_persist_path: None,
            cold_store_path: None,
            transport_announcements_persist_path: None,
            transport_announcements_persist_interval_secs:
                Self::default_transport_announcements_persist_interval_secs(),
            max_store_entries: Self::default_max_store_entries(),
            max_store_bytes: Self::default_max_store_bytes(),
            per_origin_max_bytes: None,
            shard_filtering: false,
            allow_unsigned_store: Self::default_allow_unsigned_store(),
        }
    }
}

// f64 fields (vivaldi_weight) prevent auto-derive of Eq; provide the impl manually.
// vivaldi_weight is never NaN so reflexivity holds in practice.
impl Eq for DhtConfig {}

// ── Traffic shape normalization ─────────────────────────────────────

/// Padding mode selector for outbound frame shaping.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaddingMode {
    /// No padding or jitter (lowest overhead).
    None,
    /// Pad frames to nearest size bucket; no cover traffic (default).
    #[default]
    Adaptive,
    /// Always pad to a fixed bucket size and send cover traffic.
    Full,
}

/// Outbound frame shaping policy.
///
/// Controls three orthogonal mechanisms:
/// * **Size buckets** — frames are padded up to the nearest bucket in
///   `[64, 256, 512, 1200, 1450, 2048, 4096]` bytes, hiding payload length.
/// * **Timing jitter** — a random delay `[0, jitter_ms]` ms is added before
///   each outbound frame, breaking timing analysis.
/// * **Cover traffic** — when the session is idle, dummy frames are sent every
///   `cover_interval_ms` ms to prevent traffic-silence fingerprinting.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct PaddingPolicy {
    /// Operating mode (default: `Adaptive` — size-bucket padding enabled).
    #[serde(default)]
    pub mode: PaddingMode,
    /// Maximum random delay in milliseconds added to each outbound frame.
    /// 0 = no jitter.
    #[serde(default)]
    pub jitter_ms: u32,
    /// Interval between cover (dummy) frames sent during idle sessions, in ms.
    /// 0 = no cover traffic.
    #[serde(default)]
    pub cover_interval_ms: u32,
}

impl PaddingPolicy {
    /// Returns `true` when all settings are at their zero/None defaults.
    /// Used by the serde `skip_serializing_if` gate.
    pub fn is_disabled(&self) -> bool {
        self.mode == PaddingMode::Adaptive && self.jitter_ms == 0 && self.cover_interval_ms == 0
    }
}

/// Session-layer keepalive and idle-timeout configuration.
// f32 fields (battery_keepalive_scale_*) prevent auto-derive of Eq; provide the impl manually.
// These are never NaN so reflexivity holds in practice.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct SessionConfig {
    /// Keepalive send interval in seconds (default 30). 0 = disabled.
    #[serde(default = "SessionConfig::default_keepalive_interval_secs")]
    pub keepalive_interval_secs: u64,

    /// Session idle timeout in seconds (default 90). Session is closed if no
    /// frame is received within this duration. Must be > keepalive_interval_secs.
    /// Ignored when keepalive_interval_secs = 0.
    #[serde(default = "SessionConfig::default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    /// **DEPRECATED** — superseded by [`transport.rotation`] which
    /// supports a min/max range (the new default 1800-3600 s).  This
    /// single-value knob is preserved for back-compat and used **only**
    /// when `transport.rotation` is set to `-1`/`-1` (explicit disable
    /// of the new section).  Operators upgrading from older configs
    /// don't need to touch this field — leave `None` and use the
    /// `[transport.rotation]` section instead.
    ///
    /// Legacy semantics: maximum session age in seconds before forced
    /// graceful close (connection-rotation interval). `None` (default)
    /// disables rotation — sessions live indefinitely subject only
    /// to idle_timeout.
    ///
    /// **Why this exists:** see [`crate::TransportRotationConfig`] —
    /// the rationale (censor-evasion via periodic TCP rotation) is
    /// now centralised there.
    ///
    /// **Validation:** must be ≥ 60 (rotating faster than once-a-
    /// minute is itself anomalous + would dominate connection cost).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,

    /// Maximum number of concurrent OVL1 sessions (per-node hard ceiling).
    /// Default 1000; override in node.toml as `[session] max_concurrent = N`
    /// (or `config set session.max_concurrent N`). A node at the ceiling
    /// refers new clients elsewhere rather than stranding them.
    #[serde(default = "SessionConfig::default_max_concurrent")]
    pub max_concurrent: usize,

    /// Maximum number of inbound sessions accepted from a single IP (default 32).
    /// Set to `0` to disable the check — useful in sim/devnet where many nodes
    /// share `127.0.0.1`.
    #[serde(default = "SessionConfig::default_max_per_ip")]
    pub max_per_ip: usize,

    /// Maximum inbound sessions from a single /24 subnet (default 64).
    /// Prevents eclipse attacks where an attacker fills session slots from
    /// many IPs within the same subnet. Set to `0` to disable the check.
    #[serde(default = "SessionConfig::default_max_per_subnet")]
    pub max_per_subnet: usize,

    /// Maximum pending RPC responses per session (default 256).
    /// Entries over this limit are dropped to prevent memory exhaustion.
    #[serde(default = "SessionConfig::default_max_pending_responses")]
    pub max_pending_responses: usize,

    /// Time-to-live for pending RPC response slots in milliseconds (default 30000).
    /// Older entries are evicted before new ones are inserted.
    #[serde(default = "SessionConfig::default_pending_response_ttl_ms")]
    pub pending_response_ttl_ms: u64,

    /// Capacity of the per-session outbound frame channel (`SessionTxRegistry`).
    /// Frames sent to a full channel are silently dropped.
    /// Default: 4096 frames.
    #[serde(default = "SessionConfig::default_tx_queue_depth")]
    pub tx_queue_depth: usize,

    /// Capacity of the per-session RPC outbox channel (`SessionOutbox`).
    /// `send_request` returns `None` when the channel is full.
    /// Default: 256 requests.
    #[serde(default = "SessionConfig::default_outbox_depth")]
    pub outbox_depth: usize,

    /// Per-session maximum frame body size in bytes (default: 1 MiB).
    /// Frames claiming a larger body are rejected immediately to prevent memory
    /// exhaustion. Values above the hard ceiling (16 MiB) are silently clamped.
    #[serde(default = "SessionConfig::default_max_frame_body_bytes")]
    pub max_frame_body_bytes: u32,

    /// WRR weights for the 4 traffic classes `[RealTime, Interactive, Bulk, Background]`
    /// (default `[8, 4, 2, 1]`). Each class may emit up to its weight-many frames
    /// per scheduler round before yielding to the next class.
    #[serde(default = "SessionConfig::default_qos_weights")]
    pub qos_weights: [u8; 4],

    /// Per-session outbound queue length for `REALTIME` traffic (default 64).
    /// REALTIME frames that arrive when the queue is full are dropped.
    #[serde(default = "SessionConfig::default_rt_queue_len")]
    pub rt_queue_len: usize,

    /// Per-session outbound queue length for `BACKGROUND` traffic (default 256).
    /// BACKGROUND frames that arrive when the queue is full are dropped.
    #[serde(default = "SessionConfig::default_bg_queue_len")]
    pub bg_queue_len: usize,

    // ── Battery-aware polling ──────────────────────────────────────
    /// Keepalive interval multiplier when battery is below `battery_threshold_low`
    /// (default 4.0 — keepalive every 4× base interval to conserve energy).
    #[serde(default = "SessionConfig::default_battery_keepalive_scale_low")]
    pub battery_keepalive_scale_low: f32,

    /// Keepalive interval multiplier when battery is below `battery_threshold_medium`
    /// but ≥ `battery_threshold_low` (default 2.0).
    #[serde(default = "SessionConfig::default_battery_keepalive_scale_medium")]
    pub battery_keepalive_scale_medium: f32,

    /// Battery percentage below which `battery_keepalive_scale_low` applies (default 20).
    #[serde(default = "SessionConfig::default_battery_threshold_low")]
    pub battery_threshold_low: u8,

    /// Battery percentage below which `battery_keepalive_scale_medium` applies (default 50).
    #[serde(default = "SessionConfig::default_battery_threshold_medium")]
    pub battery_threshold_medium: u8,

    // ── Background sync window ────────────────────────────────────
    /// Battery percentage below which BACKGROUND-priority outbound frames are
    /// deferred until the battery recovers above this level (default 15).
    /// Set to 0 to disable background sync gating entirely.
    #[serde(default = "SessionConfig::default_battery_sync_threshold")]
    pub battery_sync_threshold: u8,

    // ── Traffic shape normalization ────────────────────────────────
    /// Outbound frame padding and cover-traffic settings.
    /// Default: `PaddingPolicy::disabled` (no padding, no jitter, no cover traffic).
    #[serde(default, skip_serializing_if = "PaddingPolicy::is_disabled")]
    pub padding: PaddingPolicy,

    /// Trigger a session rekey after this many bytes are sent/received on the session.
    /// Default: `REKEY_BYTES_THRESHOLD` (128 GiB). Lower (e.g. 104857600 for 100 MiB)
    /// to narrow the forward-secrecy compromise window at the cost of more frequent rekey.
    #[serde(default = "SessionConfig::default_rekey_bytes_threshold")]
    pub rekey_bytes_threshold: u64,

    /// Trigger a session rekey after this many seconds since the last rekey (or session start).
    /// Default: `REKEY_TIME_THRESHOLD_SECS` (32 days). Lower (e.g. 3600 for 1 hour) to
    /// narrow the forward-secrecy compromise window at the cost of more frequent rekey.
    #[serde(default = "SessionConfig::default_rekey_time_threshold_secs")]
    pub rekey_time_threshold_secs: u64,

    /// peer-algo allow-list used at handshake time.
    /// Empty = accept any algo in `SignatureAlgorithm::supported`
    /// (backwards compat). Operator sets e.g.
    /// `allowed_peer_algos = ["falcon512"]` to harden a core-only
    /// network against weaker keys. Any algo byte received from a
    /// peer that does not decode to a known `SignatureAlgorithm`
    /// variant is rejected unconditionally (previous behaviour
    /// silently fell back to Ed25519, which masks malformed or
    /// malicious identity frames).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_peer_algos: Vec<SignatureAlgorithm>,
}

// f32 fields are never NaN so reflexivity holds in practice.
impl Eq for SessionConfig {}

impl SessionConfig {
    fn default_keepalive_interval_secs() -> u64 {
        30
    }
    fn default_idle_timeout_secs() -> u64 {
        90
    }
    /// raised from 1024 to 65_536. With RecursiveRelay
    /// handling DHT-routed forwarding, transit sessions use smaller buffers
    /// (tx_queue_depth lowered to 256), making 64K sessions practical (~1 GB).
    fn default_max_concurrent() -> usize {
        // 1000 active sessions per node — the per-node hard ceiling. At ~300
        // B/s idle gossip per session this caps idle egress at ~300 KB/s
        // (≈30% of a 1 MB/s budget), independent of network size — bounded
        // degree is what keeps idle traffic flat as N grows (full-mesh is only
        // an artifact of N < cap on small clusters). A node AT the cap refers
        // new clients to other peers (NeighborOffer on capacity-reject) so the
        // ceiling never strands a joiner. Each session ≈ 50-100 KB state, so
        // 1000 ≈ 50-100 MB worst case. Mobile / budget phones
        // must OVERRIDE through `--profile mobile` (sets 64 → ~5 MB
        // ceiling). Operators running dedicated relay/gateway
        // hardware can raise to thousands explicitly via config.
        // Breaking change vs prior default: nodes that legitimately
        // had > 512 active sessions will start rejecting handshakes
        // until operator raises the cap. Acceptable per "no working
        // network yet" framing — operators reading deployment docs
        // tune for their hardware class.
        1000
    }
    fn default_max_per_ip() -> usize {
        32
    }
    fn default_max_per_subnet() -> usize {
        64
    }
    fn default_max_pending_responses() -> usize {
        256
    }
    fn default_pending_response_ttl_ms() -> u64 {
        30000
    }
    /// Per-session outbox depth (frames).  Sized for **2 Gbps per peer**
    /// baseline (matches the rate-limit + bandwidth-gate defaults):
    ///
    /// ```text
    /// 2 Gbps × 250 ms slack / (1500 B × 8) ≈ 41 000 frames buffered worst-case
    /// ```
    ///
    /// Bumped from prior 64 (which capped sustained throughput at ~100 Mbps
    /// because the session-runner's `PQ_DRAIN_FRAMES_PER_PASS = 16` couldn't
    /// keep up under iperf-burst pressure → `priority_queue_drops_total`
    /// climbed to 64K drops/12s and `session_tx_drops_total` to 500).
    /// 4096 frames × 1500 B avg = ~6 MiB per peer worst-case; on 8 active
    /// peers = ~48 MiB total — well-bounded but lets a brief drain hiccup
    /// absorb instead of dropping.
    ///
    /// Operators on mobile / low-RAM devices can lower through
    /// `[session] tx_queue_depth = 256` in node.toml.
    fn default_tx_queue_depth() -> usize {
        4096
    }
    fn default_outbox_depth() -> usize {
        256
    }
    fn default_max_frame_body_bytes() -> u32 {
        veil_proto::codec::DEFAULT_MAX_FRAME_BODY
    }
    fn default_qos_weights() -> [u8; 4] {
        [8, 4, 2, 1]
    }
    fn default_rt_queue_len() -> usize {
        64
    }
    fn default_bg_queue_len() -> usize {
        256
    }
    fn default_battery_keepalive_scale_low() -> f32 {
        4.0
    }
    fn default_battery_keepalive_scale_medium() -> f32 {
        2.0
    }
    fn default_battery_threshold_low() -> u8 {
        20
    }
    fn default_battery_threshold_medium() -> u8 {
        50
    }
    fn default_battery_sync_threshold() -> u8 {
        15
    }
    fn default_rekey_bytes_threshold() -> u64 {
        veil_proto::budget::REKEY_BYTES_THRESHOLD
    }
    fn default_rekey_time_threshold_secs() -> u64 {
        veil_proto::budget::REKEY_TIME_THRESHOLD_SECS
    }

    /// `is_default` — see impl.
    pub fn is_default(&self) -> bool {
        self.keepalive_interval_secs == Self::default_keepalive_interval_secs()
            && self.idle_timeout_secs == Self::default_idle_timeout_secs()
            && self.max_concurrent == Self::default_max_concurrent()
            && self.max_per_ip == Self::default_max_per_ip()
            && self.max_pending_responses == Self::default_max_pending_responses()
            && self.pending_response_ttl_ms == Self::default_pending_response_ttl_ms()
            && self.tx_queue_depth == Self::default_tx_queue_depth()
            && self.outbox_depth == Self::default_outbox_depth()
            && self.max_frame_body_bytes == Self::default_max_frame_body_bytes()
            && self.qos_weights == Self::default_qos_weights()
            && self.rt_queue_len == Self::default_rt_queue_len()
            && self.bg_queue_len == Self::default_bg_queue_len()
            && self.battery_keepalive_scale_low == Self::default_battery_keepalive_scale_low()
            && self.battery_keepalive_scale_medium == Self::default_battery_keepalive_scale_medium()
            && self.battery_threshold_low == Self::default_battery_threshold_low()
            && self.battery_threshold_medium == Self::default_battery_threshold_medium()
            && self.battery_sync_threshold == Self::default_battery_sync_threshold()
            && self.padding.is_disabled()
            && self.rekey_bytes_threshold == Self::default_rekey_bytes_threshold()
            && self.rekey_time_threshold_secs == Self::default_rekey_time_threshold_secs()
            && self.allowed_peer_algos.is_empty()
            // NB: `max_per_subnet` and `max_age_secs` were previously omitted
            // here. Because `Config.session` is skipped on serialize when
            // `is_default()` is true, a config whose only non-default value
            // was one of these (e.g. a tightened eclipse cap `max_per_subnet`
            // or a `max_age_secs` rotation window) had the entire `[session]`
            // block dropped on save and silently reverted to the default on
            // reload. Both MUST be part of the equality check.
            && self.max_per_subnet == Self::default_max_per_subnet()
            && self.max_age_secs.is_none()
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            keepalive_interval_secs: Self::default_keepalive_interval_secs(),
            idle_timeout_secs: Self::default_idle_timeout_secs(),
            max_age_secs: None,
            max_concurrent: Self::default_max_concurrent(),
            max_per_ip: Self::default_max_per_ip(),
            max_per_subnet: Self::default_max_per_subnet(),
            max_pending_responses: Self::default_max_pending_responses(),
            pending_response_ttl_ms: Self::default_pending_response_ttl_ms(),
            tx_queue_depth: Self::default_tx_queue_depth(),
            outbox_depth: Self::default_outbox_depth(),
            max_frame_body_bytes: Self::default_max_frame_body_bytes(),
            qos_weights: Self::default_qos_weights(),
            rt_queue_len: Self::default_rt_queue_len(),
            bg_queue_len: Self::default_bg_queue_len(),
            battery_keepalive_scale_low: Self::default_battery_keepalive_scale_low(),
            battery_keepalive_scale_medium: Self::default_battery_keepalive_scale_medium(),
            battery_threshold_low: Self::default_battery_threshold_low(),
            battery_threshold_medium: Self::default_battery_threshold_medium(),
            battery_sync_threshold: Self::default_battery_sync_threshold(),
            padding: PaddingPolicy::default(),
            rekey_bytes_threshold: Self::default_rekey_bytes_threshold(),
            rekey_time_threshold_secs: Self::default_rekey_time_threshold_secs(),
            allowed_peer_algos: Vec::new(),
        }
    }
}

/// Hot-standby transport handover configuration).
///
/// When `enabled`, the runtime spawns a per-session **warm-probe** task
/// that pre-opens a second transport to the peer using a scheme from
/// `alt_scheme_order` (different from the primary session's scheme).
/// The probe keeps its socket alive via TCP keepalive and, when asked
/// by a degradation trigger or an operator admin command, runs the
/// three-frame handoff protocol ( stage (d)) so the session
/// migrates to the warm transport without re-establishing identity or
/// rekeying AEAD.
///
/// Default: disabled. Opting in is explicit: the feature doubles the
/// socket count per peer and its security properties are only as good
/// as the weakest alt transport (a misconfigured TLS cert chain on the
/// alt would silently be used during failover).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HotStandbyConfig {
    /// Master switch. `false` (default) = no warm probes spawned, the
    /// handoff wire-protocol is still honored if peers drive it via
    /// admin, but nothing happens automatically.
    #[serde(default = "HotStandbyConfig::default_enabled")]
    pub enabled: bool,

    // cleanup: `alt_scheme_order` and `probe_keepalive_secs`
    // removed. Both were stage-(b) B1+B2 plumbing superseded by
    // stage-(c.3) `auto_set_alt_uri_from_transports` (peer-cap discovery)
    // and stage-(c.2.2) keepalive-probe-timeout machinery respectively.
    // Stale comments referencing them in runtime/mod.rs and warm_probe.rs
    // updated in the same commit.
    /// How long the initiator side waits for `HandoffAck` after sending
    /// `HandoffInit` before aborting the handoff attempt, in seconds.
    /// Default: 5. Must be > the primary transport's round-trip time.
    #[serde(default = "HotStandbyConfig::default_handoff_timeout_secs")]
    pub handoff_timeout_secs: u64,

    /// Per-session flap-damping ceiling: at most this many successful
    /// transport swaps per rolling 60-second window. Beyond the cap
    /// the probe defers further swaps until the window rolls forward.
    /// Protects against rapid flap between primary and alt when both
    /// transports are intermittently unhealthy. Default: 4.
    #[serde(default = "HotStandbyConfig::default_max_swaps_per_minute")]
    pub max_swaps_per_minute: u32,

    /// stage (c): number of consecutive primary-transport
    /// write errors before the session runner auto-triggers a
    /// hot-standby handoff. `0` disables the auto-trigger (only the
    /// manual admin command `node swap-transport` can initiate).
    ///
    /// The trigger fires AFTER the primary has already refused a
    /// write — success depends on the transport being in a half-dead
    /// state (a common Windows Firewall outbound-block scenario).
    /// A proactive RTT-based trigger that fires before the primary
    /// fully dies is follow-up work; see `docs/hot-standby.md`.
    /// Default: 3.
    #[serde(default = "HotStandbyConfig::default_auto_trigger_after_write_errors")]
    pub auto_trigger_after_write_errors: u32,
}

impl HotStandbyConfig {
    fn default_enabled() -> bool {
        false
    }
    fn default_handoff_timeout_secs() -> u64 {
        5
    }
    fn default_max_swaps_per_minute() -> u32 {
        4
    }
    fn default_auto_trigger_after_write_errors() -> u32 {
        3
    }

    /// Used by `#[serde(skip_serializing_if = "...")]` to omit the block
    /// from emitted TOML when it matches defaults exactly — keeps the
    /// default config file terse.
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

impl Default for HotStandbyConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            handoff_timeout_secs: Self::default_handoff_timeout_secs(),
            max_swaps_per_minute: Self::default_max_swaps_per_minute(),
            auto_trigger_after_write_errors: Self::default_auto_trigger_after_write_errors(),
        }
    }
}

/// Gateway attachment lifecycle configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayConfig {
    /// Enable gateway functionality (attachment records for leaf nodes).
    /// Default: `true` for Core nodes. Set to `false` to disable.
    #[serde(default = "GatewayConfig::default_enabled")]
    pub enabled: bool,
    /// How long an attachment lease lives without a keepalive renewal, in seconds (default 300).
    #[serde(default = "GatewayConfig::default_attachment_lease_ttl_secs")]
    pub attachment_lease_ttl_secs: u64,
    /// How often the leaf sends keepalive frames to its gateway, in seconds (default 60).
    /// Set to 0 to disable (not recommended in production).
    #[serde(default = "GatewayConfig::default_keepalive_interval_secs")]
    pub keepalive_interval_secs: u64,
}

impl GatewayConfig {
    fn default_enabled() -> bool {
        true
    }
    fn default_attachment_lease_ttl_secs() -> u64 {
        300
    }
    fn default_keepalive_interval_secs() -> u64 {
        60
    }

    pub fn is_default(&self) -> bool {
        self.enabled == Self::default_enabled()
            && self.attachment_lease_ttl_secs == Self::default_attachment_lease_ttl_secs()
            && self.keepalive_interval_secs == Self::default_keepalive_interval_secs()
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            attachment_lease_ttl_secs: Self::default_attachment_lease_ttl_secs(),
            keepalive_interval_secs: Self::default_keepalive_interval_secs(),
        }
    }
}

// ── PexConfig ─────────────────────────────────────────────────────────────────
// PexConfig moved to veil-types so veil-pex can consume it
// without depending on cfg. Re-exported below.
pub use veil_types::PexConfig;

// ── NatConfig ─────────────────────────────────────────────────────────────────

/// NAT traversal configuration.
///
/// Controls whether hole-punching and relay fallback are attempted when a
/// direct TCP/QUIC connection to a peer fails because the peer is behind NAT.
///
/// # Flow
/// 1. Direct connect fails.
/// 2. If `enabled`: `NatCoordinator` starts.
/// 3. External address is discovered via the veil (STUN-like) or optionally
///    via the public `stun_servers` list.
/// 4. ICE candidates are exchanged with the peer through the veil signalling
///    channel.
/// 5. UDP hole-punch (QUIC) is attempted against all peer candidates, sorted by
///    ICE priority. Deadline = `punch_timeout_ms`.
/// 6. On timeout: if `relay_enabled`, a `NAT_RELAY_REQUEST` is sent to the
///    nearest Core node which opens a forwarding tunnel.
// NatConfig moved to veil-types so veil-nat can consume it
// without depending on cfg. Re-exported below.
pub use veil_types::NatConfig;

/// PoW challenge rate-limiter tuning.
///
/// Controls how aggressively the node issues `PowChallenge` frames to peers
/// that send `RouteRequest` when `abuse.pow_min_difficulty > 0`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct PowConfig {
    /// Steady-state PoW challenges accepted per peer per second (default 1.0).
    #[serde(default = "PowConfig::default_challenge_rate")]
    pub challenge_rate: f64,

    /// Per-peer burst allowance for PoW challenge rate limiter (default 1.0).
    ///
    /// A burst of 1 is sufficient for legitimate RouteRequest flows (one challenge
    /// per request). Higher bursts allow an acceptor to dispatch multiple CPU-heavy
    /// PoW tasks instantly to the requester, effectively multiplying its CPU load.
    /// Operators on high-traffic relay nodes may raise this, but the asymmetric cost
    /// (acceptor sends bytes; requester burns CPU) means the default should be minimal.
    #[serde(default = "PowConfig::default_challenge_burst")]
    pub challenge_burst: f64,

    /// Sliding window in seconds for PoW challenge rate limiter state (default 300).
    #[serde(default = "PowConfig::default_challenge_window_secs")]
    pub challenge_window_secs: u64,
}

impl PowConfig {
    fn default_challenge_rate() -> f64 {
        1.0
    }
    fn default_challenge_burst() -> f64 {
        1.0
    }
    fn default_challenge_window_secs() -> u64 {
        300
    }

    /// `is_default` — see impl.
    pub fn is_default(&self) -> bool {
        (self.challenge_rate - Self::default_challenge_rate()).abs() < f64::EPSILON
            && (self.challenge_burst - Self::default_challenge_burst()).abs() < f64::EPSILON
            && self.challenge_window_secs == Self::default_challenge_window_secs()
    }
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            challenge_rate: Self::default_challenge_rate(),
            challenge_burst: Self::default_challenge_burst(),
            challenge_window_secs: Self::default_challenge_window_secs(),
        }
    }
}

/// Outbound connection back-off tuning.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConnectionConfig {
    /// Minimum reconnect back-off in milliseconds (default 1 000).
    #[serde(default = "ConnectionConfig::default_reconnect_backoff_min_ms")]
    pub reconnect_backoff_min_ms: u64,

    /// Maximum reconnect back-off in milliseconds (default 300 000 = 5 min).
    #[serde(default = "ConnectionConfig::default_reconnect_backoff_max_ms")]
    pub reconnect_backoff_max_ms: u64,

    /// When `true` (default), prefer Gateway nodes with `HAS_INTERNET` flag for
    /// routing frames destined for global-veil nodes.
    ///
    /// Set to `false` to use the nearest available Gateway regardless of whether
    /// it has internet connectivity (useful in fully-isolated mesh deployments).
    #[serde(default = "ConnectionConfig::default_prefer_internet_gateway")]
    pub prefer_internet_gateway: bool,

    /// Minimum duration (in seconds) a Gateway must be unreachable before a
    /// failover to the next Gateway is initiated (default 5).
    ///
    /// Brief disconnects shorter than this window are ignored to avoid
    /// unnecessary failover churn.
    #[serde(default = "ConnectionConfig::default_gateway_failover_delay_secs")]
    pub gateway_failover_delay_secs: u64,

    /// when `true`, exit-gateway selection samples weighted-random
    /// from the top-K candidates instead of always using the single best.
    /// Reduces statistical fingerprinting (one fat connection to one IP looks
    /// distinctive — multiple thin connections to multiple IPs blend).
    /// Default: `false` (preserves the deterministic best-pick behaviour).
    #[serde(default)]
    pub exit_diversification: bool,

    /// window size for `exit_diversification`. Pick is sampled
    /// from the top-`exit_diversification_top_k` gateways by score. Smaller
    /// values keep latency closer to the optimum; larger values spread load
    /// across more peers. Default: 4.
    #[serde(default = "ConnectionConfig::default_exit_diversification_top_k")]
    pub exit_diversification_top_k: u8,

    /// Number of consecutive reconnect failures after which per-attempt
    /// `peer.reconnect.scheduled` log lines are downgraded from `WARN` to
    /// `DEBUG`. The node keeps retrying (a temporarily-down peer should
    /// recover transparently), but the log noise stops drowning everything
    /// else once it's clear the peer is just gone for now. A successful
    /// reconnect after a streak emits a single `INFO peer.recovered` line
    /// and resets the counter, so operators see when a peer comes back
    /// without watching the log tail forever.
    ///
    /// Default: 5 (≈30 s of audible warnings before quieting down).
    /// Set to 0 to disable the quiet mode (keep WARN forever).
    #[serde(default = "ConnectionConfig::default_reconnect_quiet_after_failures")]
    pub reconnect_quiet_after_failures: u32,
}

impl ConnectionConfig {
    fn default_reconnect_backoff_min_ms() -> u64 {
        1_000
    }
    fn default_reconnect_backoff_max_ms() -> u64 {
        300_000
    }
    fn default_prefer_internet_gateway() -> bool {
        true
    }
    fn default_gateway_failover_delay_secs() -> u64 {
        5
    }
    fn default_exit_diversification_top_k() -> u8 {
        4
    }
    fn default_reconnect_quiet_after_failures() -> u32 {
        5
    }

    /// `is_default` — see impl.
    pub fn is_default(&self) -> bool {
        self.reconnect_backoff_min_ms == Self::default_reconnect_backoff_min_ms()
            && self.reconnect_backoff_max_ms == Self::default_reconnect_backoff_max_ms()
            && self.prefer_internet_gateway == Self::default_prefer_internet_gateway()
            && self.gateway_failover_delay_secs == Self::default_gateway_failover_delay_secs()
            && !self.exit_diversification
            && self.exit_diversification_top_k == Self::default_exit_diversification_top_k()
            && self.reconnect_quiet_after_failures == Self::default_reconnect_quiet_after_failures()
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            reconnect_backoff_min_ms: Self::default_reconnect_backoff_min_ms(),
            reconnect_backoff_max_ms: Self::default_reconnect_backoff_max_ms(),
            prefer_internet_gateway: Self::default_prefer_internet_gateway(),
            gateway_failover_delay_secs: Self::default_gateway_failover_delay_secs(),
            exit_diversification: false,
            exit_diversification_top_k: Self::default_exit_diversification_top_k(),
            reconnect_quiet_after_failures: Self::default_reconnect_quiet_after_failures(),
        }
    }
}

/// Node capacity and load-shedding configuration.
///
/// Limits how many sessions this node relays. When the hard cap is reached
/// the node stops accepting new relay sessions and withdraws its routes until
/// load drops back below the soft threshold.
///
/// Set any `max_*` field to `0` to disable that limit.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct NodeCapacityConfig {
    /// Maximum number of relay sessions this node will accept simultaneously.
    /// `0` = unlimited (default).
    #[serde(default)]
    pub max_relay_sessions: usize,

    /// Maximum total active sessions (relay + direct).
    /// `0` = unlimited (default).
    #[serde(default)]
    pub max_total_sessions: usize,

    /// Maximum inbound bandwidth in kilobits per second.
    /// `-1` = unlimited. Default: `10_000_000` (10 Gbit/s).
    #[serde(default = "NodeCapacityConfig::default_bandwidth_kbps")]
    pub max_inbound_bandwidth_kbps: i64,

    /// Maximum outbound bandwidth in kilobits per second.
    /// `-1` = unlimited. Default: `10_000_000` (10 Gbit/s).
    #[serde(default = "NodeCapacityConfig::default_bandwidth_kbps")]
    pub max_outbound_bandwidth_kbps: i64,

    /// Fraction of the TX queue depth at which this node is considered congested
    /// for the purposes of the soft congestion signal.
    /// Must be in `0.0..=1.0`. Default: `0.8`.
    #[serde(default = "NodeCapacityConfig::default_tx_queue_high_watermark")]
    pub tx_queue_high_watermark: f64,

    /// Congestion score above which the node starts shedding new relay sessions
    /// (soft threshold for the ROUTE_REPLY signal). Default: `0.8`.
    #[serde(default = "NodeCapacityConfig::default_congestion_high")]
    pub congestion_high: f64,

    /// Congestion score below which the node resumes accepting relay sessions
    /// after shedding (hysteresis low threshold). Default: `0.6`.
    #[serde(default = "NodeCapacityConfig::default_congestion_low")]
    pub congestion_low: f64,
}

impl NodeCapacityConfig {
    /// Per-node aggregate bandwidth cap (kbps).  Default sized for
    /// **2 Gbps per peer** baseline × ~8 active peers worst-case = 16 Gbps
    /// aggregate, rounded down to 10 Gbps headroom.  Bumped from prior
    /// 100 Mbps (which capped a single-peer iperf flow long before any
    /// other limit kicked in).  Set to `-1` for truly unlimited (datacentre
    /// deployments); set lower (e.g. 1 Gbps) when ISP rate-limited.
    fn default_bandwidth_kbps() -> i64 {
        10_000_000
    } // 10 Gbit/s
    fn default_tx_queue_high_watermark() -> f64 {
        0.8
    }
    fn default_congestion_high() -> f64 {
        0.8
    }
    fn default_congestion_low() -> f64 {
        0.6
    }

    /// Convert a bandwidth config value to a `BandwidthGate`-compatible u32.
    /// `-1` (or any negative) → 0 (unlimited). Positive → kbps as u32.
    pub fn bandwidth_kbps_to_gate(val: i64) -> u32 {
        if val < 0 { 0 } else { val as u32 }
    }

    /// `is_default` — see impl.
    pub fn is_default(&self) -> bool {
        self.max_relay_sessions == 0
            && self.max_total_sessions == 0
            && self.max_inbound_bandwidth_kbps == Self::default_bandwidth_kbps()
            && self.max_outbound_bandwidth_kbps == Self::default_bandwidth_kbps()
            && (self.tx_queue_high_watermark - Self::default_tx_queue_high_watermark()).abs()
                < f64::EPSILON
            && (self.congestion_high - Self::default_congestion_high()).abs() < f64::EPSILON
            && (self.congestion_low - Self::default_congestion_low()).abs() < f64::EPSILON
    }
}

impl Default for NodeCapacityConfig {
    /// **Defaults assume a private / trusted deployment.** `max_relay_sessions
    /// = 0` (unlimited) and `max_total_sessions = 0` (unlimited) make
    /// public-internet seeds DoS-vulnerable: a flood of handshaken but
    /// idle sessions can saturate memory before the abuse detector
    /// reacts. Public seeds **must** set explicit caps —
    /// see `docs/OPERATIONS.md` → "Default Tuning Guidance".
    fn default() -> Self {
        Self {
            max_relay_sessions: 0,
            max_total_sessions: 0,
            max_inbound_bandwidth_kbps: Self::default_bandwidth_kbps(),
            max_outbound_bandwidth_kbps: Self::default_bandwidth_kbps(),
            tx_queue_high_watermark: Self::default_tx_queue_high_watermark(),
            congestion_high: Self::default_congestion_high(),
            congestion_low: Self::default_congestion_low(),
        }
    }
}

// Manual Eq: f64 fields are always finite configuration values, never NaN.
impl Eq for NodeCapacityConfig {}

/// Abuse-resistance configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct AbuseConfig {
    /// Per-peer steady-state frame allowance (frames per second).
    #[serde(default = "default_rate_limit_fps")]
    pub rate_limit_fps: f64,
    /// Per-peer burst capacity (maximum frames before throttling starts).
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: f64,
    /// Minimum leading-zero bits required in the PoW puzzle that guards
    /// direct-session bootstrap via `RouteRequest` / `PowChallenge`.
    ///
    /// Default: `16` (~65K BLAKE3 hashes, solved in <1 ms on modern hardware).
    /// Set to `0` to disable (development only).
    /// Session PoW uses BLAKE3 (fast) — not Argon2id — because handshake
    /// must complete within the 10-second timeout.
    #[serde(default = "default_pow_min_difficulty")]
    pub pow_min_difficulty: u32,
    /// Number of protocol violations before a peer is temporarily banned.
    #[serde(default = "default_ban_threshold")]
    pub ban_threshold: u32,
    /// Initial ban duration in seconds (first ban).
    #[serde(default = "default_ban_initial_secs")]
    pub ban_initial_secs: u64,
    /// Additive step for each subsequent ban in seconds (progressive escalation).
    /// Nth ban = ban_initial_secs + N × ban_step_secs, capped at ban_max_secs.
    #[serde(default = "default_ban_step_secs")]
    pub ban_step_secs: u64,
    /// Maximum ban duration in seconds (ceiling for progressive escalation).
    #[serde(default = "default_ban_max_secs")]
    pub ban_max_secs: u64,

    /// b: per-peer **byte-rate** throttle (bytes/sec
    /// allowed from a single peer). Composes orthogonally with
    /// node-aggregate `capacity.max_inbound_bandwidth_kbps`
    /// — node-aggregate prevents total runaway
    /// per-peer prevents single-peer-flood from saturating
    /// the user's cellular quota. `None` (default) disables
    /// per-peer enforcement; mobile profile sets to 65536
    /// (64 KB/s = 512 kbps per peer — enough for real chat /
    /// signaling, blocks runaway DHT walks / misbehaving relay).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_peer_bytes_per_sec: Option<u64>,

    /// Per-peer byte burst capacity (bytes — Token bucket
    /// initial fill). None defaults to 4× `per_peer_bytes_per_sec`
    /// (4-second burst window) so legitimate-but-bursty peers
    /// don't get throttled on the first frame. Ignored when
    /// `per_peer_bytes_per_sec` is None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_peer_byte_burst: Option<u64>,
}

impl Default for AbuseConfig {
    fn default() -> Self {
        Self {
            rate_limit_fps: default_rate_limit_fps(),
            rate_limit_burst: default_rate_limit_burst(),
            pow_min_difficulty: default_pow_min_difficulty(),
            ban_threshold: default_ban_threshold(),
            ban_initial_secs: default_ban_initial_secs(),
            ban_step_secs: default_ban_step_secs(),
            ban_max_secs: default_ban_max_secs(),
            per_peer_bytes_per_sec: None,
            per_peer_byte_burst: None,
        }
    }
}

// f64 fields are never NaN in practice; implement Eq explicitly so Config can derive Eq.
impl Eq for RoutingConfig {}
impl Eq for AbuseConfig {}
impl Eq for PowConfig {}

impl AbuseConfig {
    pub fn is_default(&self) -> bool {
        self.pow_min_difficulty == default_pow_min_difficulty()
            && self.ban_threshold == default_ban_threshold()
            && self.ban_initial_secs == default_ban_initial_secs()
            && self.ban_step_secs == default_ban_step_secs()
            && self.ban_max_secs == default_ban_max_secs()
            && (self.rate_limit_fps - default_rate_limit_fps()).abs() < f64::EPSILON
            && (self.rate_limit_burst - default_rate_limit_burst()).abs() < f64::EPSILON
            && self.per_peer_bytes_per_sec.is_none()
            && self.per_peer_byte_burst.is_none()
    }

    /// Resolved per-peer byte burst capacity for PerPeerLimiter
    /// construction. Returns `None` when `per_peer_bytes_per_sec`
    /// is None (per-peer enforcement disabled). Otherwise returns
    /// the explicit `per_peer_byte_burst` if set, OR a 4-second
    /// burst (4× rate) as the sensible default.
    pub fn resolved_per_peer_byte_burst(&self) -> Option<u64> {
        let rate = self.per_peer_bytes_per_sec?;
        Some(self.per_peer_byte_burst.unwrap_or(rate.saturating_mul(4)))
    }
}

/// Transport-level connection-rotation policy (`[transport.rotation]`).
///
/// Forces the underlying TCP/TLS connection of every session to be rotated
/// periodically so that DPI fingerprinting based on flow lifetime (e.g.
/// "this HTTPS session has lived 6 hours straight, classify as VPN") loses
/// its signal.  Each session draws a random lifetime uniformly from the
/// `[min_lifetime_secs, max_lifetime_secs]` range at handshake time; when
/// that deadline expires the runner attempts a **make-before-break** swap
/// onto a freshly-handshaked transport (see [`crate::HotStandbyConfig`]
/// for the underlying mechanism).  If make-before-break can't proceed (no
/// alt_uri available and same-URI rotation unsupported by the peer), the
/// runner falls back to a graceful close, letting the outbound connector
/// re-dial.
///
/// **Why a range, not a point value:** a fixed 1-hour cadence is itself
/// a DPI signature (every flow rotates at exactly 3600 ± 10 % seconds —
/// statistical correlation across the fleet identifies veil sessions).
/// Wider uniform spread (1800-3600 s by default = 30 min to 1 hour) hides
/// the rotation event in the noise of normal browser-tab churn.
///
/// **Disabling:** set either `min_lifetime_secs` or `max_lifetime_secs`
/// to `-1` (the sentinel for "disabled"); the runner then runs sessions
/// indefinitely subject only to idle-timeout / failure-detection.  Default
/// is enabled with the 30-60 min range.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TransportRotationConfig {
    /// Minimum session lifetime in seconds.  Default: 1800 (30 min).
    /// Sentinel: `-1` disables the entire rotation mechanism (paired-
    /// or-not with `max_lifetime_secs` — either being `-1` means disabled).
    /// Positive values < 60 are rejected by validation (rotating faster
    /// than once-per-minute is itself anomalous + dominates handshake
    /// cost).
    #[serde(default = "TransportRotationConfig::default_min_lifetime_secs")]
    pub min_lifetime_secs: i64,

    /// Maximum session lifetime in seconds.  Default: 3600 (1 hour).
    /// Sentinel: `-1` disables the entire rotation mechanism.  Must be
    /// `>= min_lifetime_secs` when both are positive (validation rule).
    #[serde(default = "TransportRotationConfig::default_max_lifetime_secs")]
    pub max_lifetime_secs: i64,
}

impl TransportRotationConfig {
    /// Default minimum lifetime: 30 min.  Picked to match the lower end
    /// of typical foreground browsing-tab lifetimes (Chrome's "long-lived"
    /// HTTPS sessions to e.g. Gmail or Slack often last 30-60 min).
    pub fn default_min_lifetime_secs() -> i64 {
        1_800
    }

    /// Default maximum lifetime: 1 hour.  Upper end of normal browser-tab
    /// HTTPS lifetimes; sessions longer than this start to look anomalous
    /// to DPI classifiers that profile flow durations.
    pub fn default_max_lifetime_secs() -> i64 {
        3_600
    }

    /// True if rotation is disabled (either bound is `-1`).
    ///
    /// Consumers that need to know whether to arm the rotation timer
    /// should ask this rather than re-implementing the sentinel check;
    /// keeps the policy in one place.
    pub fn is_disabled(&self) -> bool {
        self.min_lifetime_secs < 0 || self.max_lifetime_secs < 0
    }

    /// Resolve to a pair of positive `(min, max)` seconds, or `None`
    /// when rotation is disabled.  Single helper for downstream callers
    /// (session runner global setter, hot-standby trigger) — they don't
    /// need to know about the `-1` sentinel.
    pub fn resolved_range(&self) -> Option<(u64, u64)> {
        if self.is_disabled() {
            return None;
        }
        let min = self.min_lifetime_secs as u64;
        let max = self.max_lifetime_secs as u64;
        // Validation guarantees min ≤ max when both positive — but we
        // defensively clamp here so a validation-bypassed config can't
        // crash the runner with a max < min uniform sample.
        Some((min, min.max(max)))
    }
}

impl Default for TransportRotationConfig {
    fn default() -> Self {
        Self {
            min_lifetime_secs: Self::default_min_lifetime_secs(),
            max_lifetime_secs: Self::default_max_lifetime_secs(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
/// Transport config (see field docs for details).
pub struct TransportConfig {
    /// Connection-rotation policy ([`TransportRotationConfig`]).
    /// Documented in detail on the struct itself; default (30-60 min)
    /// matches typical browser-tab HTTPS lifetimes for DPI-evasion.
    /// TOML section: `[transport.rotation]`.
    ///
    /// **Always serialised** (no `skip_serializing_if`) — this is a
    /// censor-evasion feature and operators expect to discover it by
    /// reading their config file.  Hiding the section when at default
    /// would hide both its existence AND its current effective values
    /// (the new lifetime range), which is poor security UX even when
    /// the rest of the config follows the "skip-default" convention.
    #[serde(default)]
    pub rotation: TransportRotationConfig,

    #[serde(default, skip_serializing_if = "TlsClientConfig::is_default")]
    /// `tls_client` — tls client.
    pub tls_client: TlsClientConfig,
    /// default SNI hostname advertised in the TLS ClientHello
    /// when the outbound URI does not specify `?sni=...` and the target is
    /// non-loopback. Set to e.g. `"www.google.com"` so on-path DPI sees a
    /// popular domain instead of the node's actual hostname. `None` keeps
    /// the legacy behaviour (use the target host as SNI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_sni: Option<String>,
    /// Path to a file containing the obfs4 pre-shared key (32 bytes,
    /// base64-encoded on one line).  When set, enables the `obfs4-tcp://`
    /// transport: server-side verifies incoming MACs, client-side
    /// includes the MAC in outgoing handshakes.  Single network-wide PSK;
    /// per-peer PSK lookup via signed transport_hints is a follow-up.
    /// `None` disables the obfs4-tcp transport (default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs4_psk_file: Option<std::path::PathBuf>,
    /// Webtunnel secret path (e.g. `/_t/random-32-chars`).  Activates
    /// tunnel mode on the `webtunnel-wss://` transport's server side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webtunnel_secret_path: Option<String>,
    /// Webtunnel auth token file (made of 32-byte random + base64).
    /// Sent in `X-Veil-Auth` header alongside the secret path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webtunnel_auth_token_file: Option<std::path::PathBuf>,
    /// Webtunnel decoy content directory.  Static files served to probes
    /// that don't match the secret path/auth.  Recommended: snapshot of a
    /// neutral website (status dashboard, dev blog).  None falls back
    /// to a minimal hardcoded HTML.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webtunnel_decoy_dir: Option<std::path::PathBuf>,

    /// Anti-censorship strategy: SOCKS proxy URL used as a **fallback**
    /// when direct outbound dialing fails repeatedly (e.g., AS-level
    /// block, ISP route hijack, or a transient TSPU rule).  Format:
    /// `socks5://127.0.0.1:9050` (local Tor) or `socks5://proxy.example:1080`
    /// (operator-controlled bridge).
    ///
    /// **Default: `None`** — no fallback, direct-only.  When set, the
    /// connector retries the peer URI wrapped through this proxy after
    /// the direct + NAT-fallback paths fail.  Closes #22, #23, #27
    /// (AS-level wholesale blocks) partially — Tor's exit nodes are
    /// in diverse ASes by design, so a blocked AS on the operator's host
    /// is bypassed via the proxy hop.
    ///
    /// **Not a replacement for multi-AS hosting**: see
    /// [`docs/internal/DEPLOYMENT_HARDENING.md`](../../docs/internal/DEPLOYMENT_HARDENING.md)
    /// for the recommended infrastructure setup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_socks_fallback_proxy: Option<String>,

    /// Anti-censorship strategy P2 #7 — opt-in bandwidth-profile
    /// mimicry.  When enabled, shapes outbound traffic to match a
    /// reference flow pattern (Chrome browsing / CDN download / etc.)
    /// to defeat throughput-shaping DPI classifiers (#29-31).
    ///
    /// **Default `false`** — feature opt-in.  Currently a **design
    /// landing-pad**: the config field is recognised but the wire-up
    /// (output gating layer) is deferred to the activation epic.  See
    /// [`docs/internal/PLAN_BANDWIDTH_MIMICRY.md`](../../docs/internal/PLAN_BANDWIDTH_MIMICRY.md)
    /// for the activation triggers + scope.
    ///
    /// Operators wanting throughput-shape resistance NOW should use
    /// the operator-side tc/qdisc option in
    /// [`docs/internal/DEPLOYMENT_HARDENING.md`](../../docs/internal/DEPLOYMENT_HARDENING.md)
    /// (Option B in the #29-31 section).
    ///
    /// **Fail-closed (audit batch 2026-05-23):** setting this to `true`
    /// without also setting [`experimental_allow_noop_mimicry`] now causes
    /// `cargo run` to exit with a validation error.  Pre-fix, the daemon
    /// only WARN-logged and continued running — operators could believe
    /// mimicry was active when in fact traffic was unchanged (a
    /// dangerous false sense of anti-DPI protection).  Operators that
    /// genuinely want the no-op landing-pad must also flip the
    /// `experimental_allow_noop_mimicry` flag to confirm understanding.
    #[serde(default)]
    pub bandwidth_mimicry_enabled: bool,

    /// Profile name for [`bandwidth_mimicry_enabled`].  Recognised
    /// values (per `PLAN_BANDWIDTH_MIMICRY.md`): `"chrome-browsing"`,
    /// `"cdn-download"`, `"interactive-chat"`.  Currently a pure
    /// landing-pad field — see the parent doc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_mimicry_profile: Option<String>,

    /// Acknowledge that [`bandwidth_mimicry_enabled`] is currently a
    /// no-op design landing-pad and accept the daemon starting without
    /// actual mimicry.  Required gate paired with
    /// `bandwidth_mimicry_enabled = true` until the activation epic
    /// wires the output gating layer.  Audit batch 2026-05-23.
    #[serde(default, skip_serializing_if = "is_false")]
    pub experimental_allow_noop_mimicry: bool,

    /// **Phase 2 kill-switch — server-side**: list of obfs4 wire-format
    /// variants the listener accepts, in priority order.  Default empty
    /// (resolved to `["v1"]` in transport_glue) preserves pre-Phase-2
    /// behavior bit-for-bit.
    ///
    /// Operator activation sequence for a V1→V2 migration:
    /// 1. Deploy binary with Phase 2 support, set `obfs4_accept_variants
    ///    = ["v2", "v1"]` on **all servers** first — accepts both during
    ///    the grace period.
    /// 2. Wait until all client hosts have been deployed with the same
    ///    binary (clients still use V1 outbound — controlled by
    ///    `obfs4_client_variant`).
    /// 3. Flip `obfs4_client_variant = "v2"` on client hosts so
    ///    outbound dials use V2.  Server-side dual-accept ensures
    ///    mixed-version cluster works.
    /// 4. Once all clients are on V2, flip `obfs4_accept_variants =
    ///    ["v2"]` on servers — cuts off V1.
    ///
    /// See [`docs/internal/PLAN_WIRE_FORMAT_KILL_SWITCH.md`](../../docs/internal/PLAN_WIRE_FORMAT_KILL_SWITCH.md)
    /// for the design + activation playbook.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obfs4_accept_variants: Vec<String>,

    /// **Phase 2 kill-switch — client-side**: obfs4 wire-format variant
    /// used for outbound obfs4-tcp connects.  Default `None` (resolves
    /// to V1 in transport_glue).  Accepted values: `"v1"`, `"v2"`.
    ///
    /// Set to `"v2"` only after **all** target servers' `accept_variants`
    /// includes V2 — otherwise outbound connects silent-drop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs4_client_variant: Option<String>,

    /// Runtime TLS ClientHello fingerprint policy for outbound `tls://` /
    /// `wss://` connects ([`TlsFingerprintConfig`]). TOML section:
    /// `[transport.tls_fingerprint]`. Only effective on `tls-boring` builds
    /// (the rustls backend cannot morph its ClientHello and ignores this).
    ///
    /// **Always serialised** (no `skip_serializing_if`) — like `[transport
    /// .rotation]`, this is a censor-evasion control operators should be able
    /// to discover by reading their config file.
    #[serde(default)]
    pub tls_fingerprint: TlsFingerprintConfig,
}

/// TLS ClientHello fingerprint policy (`[transport.tls_fingerprint]`).
///
/// Effective only on `tls-boring` builds. Maps to
/// `veil_transport::fingerprint::TlsFingerprintPolicy` in `transport_glue`.
///
/// * `mode = "rotate"` (default) — try each `rotation` profile over a fresh
///   connection until one completes the TLS handshake; with `sticky = true`
///   keep using the last one that worked. This is the censorship-robust
///   default: when one browser JA3 is blocked the node falls back to another.
/// * `mode = "pinned"` — always present `profile`.
/// * `mode = "random"` — fresh randomised ClientHello per connection.
///
/// Profile tokens: `chrome`, `firefox`, `safari`, `ios`, `android`, `random`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct TlsFingerprintConfig {
    /// `pinned` | `rotate` | `random`. Default `rotate`.
    pub mode: String,
    /// Profile for `pinned` mode. Default `chrome`.
    pub profile: String,
    /// Ordered profiles to cycle in `rotate` mode. Default
    /// `["chrome", "firefox", "safari"]`.
    pub rotation: Vec<String>,
    /// In `rotate` mode, keep using the last profile that completed a
    /// handshake instead of re-probing from the head each time. Default `true`.
    pub sticky: bool,
}

impl Default for TlsFingerprintConfig {
    fn default() -> Self {
        Self {
            mode: "rotate".to_owned(),
            profile: "chrome".to_owned(),
            rotation: vec![
                "chrome".to_owned(),
                "firefox".to_owned(),
                "safari".to_owned(),
            ],
            sticky: true,
        }
    }
}

/// Tls client config (see field docs for details).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TlsClientConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `connect_timeout_ms` — connect timeout ms.
    pub connect_timeout_ms: Option<u64>,

    /// when `true`, include Mozilla's webpki-roots CA
    /// bundle in the rustls client trust store. Default `false`:
    /// veil trusts only operator-pinned CAs via `trusted_ca_file`.
    /// Flip to `true` for mesh nodes connecting to publicly-certified
    /// seeds (Let's Encrypt, etc.). : this used
    /// to require the `tls-webpki-roots` build feature; that gate is
    /// gone (webpki-roots is now an unconditional dep), so this knob
    /// works in every build.
    #[serde(default, skip_serializing_if = "is_false")]
    pub use_system_roots: bool,

    /// path to a PEM file with operator-trusted CAs.
    /// Added to the rustls trust store on top of any system roots
    /// (when `use_system_roots = true`). `None` keeps the legacy
    /// behaviour where only certs added programmatically via
    /// `TlsContext::with_trusted_certificates` are trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_ca_file: Option<std::path::PathBuf>,
}

fn is_false(v: &bool) -> bool {
    !v
}

impl TlsClientConfig {
    /// `is_default` — see impl.
    pub fn is_default(&self) -> bool {
        self.connect_timeout_ms.is_none()
            && !self.use_system_roots
            && self.trusted_ca_file.is_none()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
/// Global config (see field docs for details).
pub struct GlobalConfig {
    #[serde(default)]
    /// `runtime_flavor` — runtime flavor.
    pub runtime_flavor: RuntimeFlavor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `worker_threads` — worker threads.
    pub worker_threads: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `max_blocking_threads` — max blocking threads.
    pub max_blocking_threads: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `thread_keep_alive_ms` — thread keep alive ms.
    pub thread_keep_alive_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `thread_name` — thread name.
    pub thread_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `thread_stack_size` — thread stack size.
    pub thread_stack_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `admin_socket` — admin socket.
    pub admin_socket: Option<String>,
    /// `admin_max_connections` — soft cap on concurrent admin
    /// connections.
    /// Defaults to 32; operators can raise for high-frequency tooling
    /// workloads OR lower to narrow the resource-budget envelope.
    ///
    /// Implementation: a semaphore with this many permits gates per-
    /// connection task spawns. Excess connections are refused
    /// (logged at info level + `admin.accept_refused_total` metric).
    /// Token auth already gates "who can connect"; this knob caps
    /// "how many connections a single authorised UID can hold at
    /// once" — protects against a bug or mis-tooling that spawns
    /// hundreds of admin clients simultaneously.
    #[serde(default = "GlobalConfig::default_admin_max_connections")]
    pub admin_max_connections: usize,
    #[serde(default)]
    /// `logs` — logs.
    pub logs: LogsConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `log_file` — log file.
    pub log_file: Option<String>,
    /// Minimum log level emitted. Messages below this level are discarded.
    #[serde(default)]
    pub log_level: LogLevel,
    /// Output format for log lines.
    #[serde(default)]
    pub log_format: LogFormat,
    /// DNS domain for bootstrap seed discovery.
    /// Default: `veil.example`. Set to a real domain with `_veil._bootstrap.<domain>` TXT records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_dns_domain: Option<String>,
    /// file path for the discovered-peer cache. After
    /// every successful OVL1 handshake, the runtime upserts the
    /// peer's `(transport, public_key, nonce, algo)` here. At cold
    /// start, the bootstrap cascade tries these cached peers in
    /// addition to `[[bootstrap_peers]]`, builtin seeds and DNS
    /// discovery — gives censorship-resistance even when the
    /// censor takes down all originally-published seeds.
    /// `None` disables persistence (in-memory only; lost on restart).
    /// Default `None` so dev / CI runs don't drop a file in `$TMP`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovered_peers_cache_path: Option<String>,
    /// list of HTTPS URLs that serve a JSON
    /// `Vec<BootstrapPeer>` bundle (same shape as the DHT bootstrap
    /// bundle). Fetched concurrently at startup and
    /// merged into the bootstrap candidate pool. Operator can rotate
    /// the seed list by updating the file on the web server — no
    /// binary rebuild required, no DNS TTL to wait out.
    /// HTTPS-only (plain `http://` is refused — the cert chain is
    /// the operator's authentication that the response is theirs and
    /// not a censor-injected forgery). Empty default keeps the layer
    /// off for dev / CI runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bootstrap_https_urls: Vec<String>,
    /// SOCKS5 proxy used to fetch any **`.onion`** URL listed in
    /// [`bootstrap_https_urls`](Self::bootstrap_https_urls) — e.g. a local Tor
    /// daemon at `socks5://127.0.0.1:9050`.  Deferred backlog item 481.4: the
    /// operator's last-resort bootstrap path when every clearnet CDN / DNS
    /// layer is blocked.
    ///
    /// `.onion` URLs in the list are dialed through this proxy (the host is
    /// resolved by Tor, never locally) and **always require a signed bundle**
    /// regardless of [`legacy_allow_unsigned_bootstrap`](Self::legacy_allow_unsigned_bootstrap):
    /// `.onion` is self-authenticating + Tor-encrypted, so the URL is plain
    /// `http://` and the bundle signature provides authenticity (issuer pinned
    /// via [`trusted_bundle_issuer_pubkey`](Self::trusted_bundle_issuer_pubkey)
    /// when set).
    ///
    /// When unset (default `None`), `.onion` URLs are skipped (with a logged
    /// per-URL error); clearnet `https://` URLs are unaffected either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_tor_socks_proxy: Option<String>,
    /// follow-up: pinned issuer pubkey (base64) for signed
    /// bootstrap bundles. When set, `bootstrap fetch` REJECTS bundles
    /// whose embedded `issuer_pk` does NOT match this value. When
    /// unset, the fetcher accepts any internally-consistent signature
    /// (envelope-tamper-proof but doesn't authenticate WHO signed it).
    ///
    /// In an authoritarian threat-model, downstream users (cellular
    /// phones running the app) typically aren't operators themselves —
    /// they receive the operator's pubkey out-of-band (paper, friend
    /// website on a different jurisdiction) and pin it here. Without
    /// pinning, a sybil close to the bundle's DHT slot could publish
    /// their own validly-signed bundle (their own keypair, real
    /// signature) and the fetcher would accept it: signature
    /// internally consistent → merge attacker's peers into config.
    /// Pinning closes that gap.
    ///
    /// Same base64 encoding as `IdentityConfig.public_key` /
    /// `BootstrapPeer.public_key`. Algo is implied by the bundle's
    /// envelope `issuer_algo` byte; the pin only matches against the
    /// pubkey bytes themselves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_bundle_issuer_pubkey: Option<String>,
    /// LEGACY escape hatch — when `true`, the HTTPS bootstrap fetcher
    /// accepts raw JSON bundles (no signature envelope) instead of
    /// rejecting them.  Default `false`.
    ///
    /// TLS gives channel auth ("bytes came from the CDN endpoint without
    /// on-path tampering") but NOT endpoint auth.  If CDN, CA,
    /// hosting account or mirror endpoint is compromised, attacker
    /// swaps the JSON for own peer list and raw-JSON mode merges those
    /// directly into the seed set.  Signed bundles (operator-signed,
    /// pinned issuer pubkey) close this class of compromise.
    ///
    /// Production deployments should leave this `false` and provision a
    /// signed bundle (see `sign_bundle` CLI).  Set `true` ONLY for
    /// dev/testnet builds that haven't yet generated and published a
    /// signed bundle.  Flag will be removed after a migration window
    /// once production operators have migrated.
    #[serde(default, skip_serializing_if = "is_default_legacy_allow")]
    pub legacy_allow_unsigned_bootstrap: bool,
    /// **Phase-2 Phase 11 slice 11d** enforcement flag.  When `true`,
    /// `load_config` REFUSES to load configs that:
    ///   * Carry no `# VEIL_CONFIG_SIGNATURE_V1: …` header, OR
    ///   * Carry a header but verification fails (tamper, wrong issuer
    ///     under a pinned `VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY`).
    ///
    /// Default `false` (phase-1 warn-only — matches the pre-11d
    /// behaviour where signed-but-tampered configs still load with a
    /// WARN log).  Operators flip to `true` after every machine in the
    /// fleet has been signed AND verified.
    ///
    /// Chicken-and-egg disclaimer: setting `require_signed_config =
    /// false` doesn't help an attacker — they would still need to
    /// tamper other fields, and the signed envelope ALREADY catches
    /// that tamper.  The flag's main purpose is **operator-side
    /// enforcement posture**, not attacker-side defence.
    #[serde(default, skip_serializing_if = "is_default_legacy_allow")]
    pub require_signed_config: bool,

    /// **Phase 10 slice 2c** — TLS ECH GREASE on outbound public-PKI
    /// HTTPS connections (currently the bootstrap fetch path).  When
    /// `true`, the client adds an Encrypted Client Hello GREASE
    /// extension to ClientHello messages, defeating middlebox
    /// fingerprinting that distinguishes ECH-capable from non-ECH
    /// connections.  Censors that block ECH-capable traffic must then
    /// choose between (a) blocking everything (visible failure mode)
    /// and (b) allowing all TLS through.
    ///
    /// **Slice history**:
    /// * Slice 2a (`f44bb512`) — foundation flag (no-op).
    /// * Slice 2b — workspace migration from `rustls-ring` to
    ///   `rustls-aws-lc-rs` crypto provider + actual `EchMode::Grease(...)`
    ///   wiring at `connect_pki_verified_https_stream`.
    /// * Slice 2c (this commit) — default flipped to `true`.  Bundled
    ///   with the 2b implementation because the workspace gates passed
    ///   under aws_lc_rs with no observed regressions.
    /// * Slice 3 (future) — real ECH with `EchMode::Enable(EchConfig::new(...))`
    ///   driven from DNS HTTPS records.  Requires operator-side DNS
    ///   publishing infra.
    ///
    /// Pins TLS 1.3 for the public-HTTPS path when `true` (ECH requires
    /// 1.3; modern CDNs all support it).  Operators stuck on TLS 1.2-
    /// only CDNs can flip this to `false` to restore the pre-Phase-10
    /// posture.
    #[serde(default = "GlobalConfig::default_tls_ech_grease")]
    pub tls_ech_grease: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_default_legacy_allow(v: &bool) -> bool {
    !*v
}

impl GlobalConfig {
    pub(crate) fn default_admin_max_connections() -> usize {
        32
    }

    /// Etap 10 slice 2c — default flipped to `true`.  Operators on
    /// TLS 1.2-only public CDNs can override to `false`.
    pub(crate) fn default_tls_ech_grease() -> bool {
        true
    }

    /// Project the tokio-runtime knobs from `[global]` in a standalone
    /// `RuntimeConfig` that other binaries (ogate, oproxy) can reuse
    /// through `veil_cfg::build_tokio_runtime`.
    pub fn runtime_config(&self) -> crate::RuntimeConfig {
        crate::RuntimeConfig {
            flavor: self.runtime_flavor.clone(),
            worker_threads: self.worker_threads,
            max_blocking_threads: self.max_blocking_threads,
            thread_keep_alive_ms: self.thread_keep_alive_ms,
            thread_name: self.thread_name.clone(),
            thread_stack_size: self.thread_stack_size,
        }
    }
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            runtime_flavor: RuntimeFlavor::MultiThread,
            worker_threads: None,
            max_blocking_threads: None,
            thread_keep_alive_ms: None,
            thread_name: None,
            thread_stack_size: None,
            admin_socket: None,
            admin_max_connections: Self::default_admin_max_connections(),
            logs: LogsConfig::Stderr,
            log_file: None,
            log_level: LogLevel::default(),
            log_format: LogFormat::default(),
            bootstrap_dns_domain: None,
            discovered_peers_cache_path: None,
            bootstrap_https_urls: Vec::new(),
            bootstrap_tor_socks_proxy: None,
            trusted_bundle_issuer_pubkey: None,
            require_signed_config: false,
            legacy_allow_unsigned_bootstrap: false,
            tls_ech_grease: Self::default_tls_ech_grease(),
        }
    }
}

// LogFormat / LogsConfig / LogLevel moved to veil-types
// so veil-observability can consume them without depending on cfg.
pub use veil_types::{LogFormat, LogLevel, LogsConfig};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Runtime flavor (see field docs for details).
pub enum RuntimeFlavor {
    /// `CurrentThread` variant.
    CurrentThread,
    #[default]
    /// `MultiThread` variant.
    MultiThread,
}

impl std::fmt::Display for RuntimeFlavor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentThread => f.write_str("current_thread"),
            Self::MultiThread => f.write_str("multi_thread"),
        }
    }
}

impl std::str::FromStr for RuntimeFlavor {
    type Err = ParseEnumError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "current_thread" => Ok(Self::CurrentThread),
            "multi_thread" => Ok(Self::MultiThread),
            _ => Err(ParseEnumError::new("runtime flavor", value)),
        }
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
/// Identity config (see field docs for details).
///
/// `Debug` is implemented manually (not derived) to redact `private_key`
/// and `key_passphrase` — otherwise an accidental `{:?}` on a `Config`
/// anywhere (e.g. a stray `tracing::debug!`) would spill identity-key /
/// passphrase material into logs.
pub struct IdentityConfig {
    #[serde(default)]
    /// `algo` — algo.
    pub algo: SignatureAlgorithm,
    /// Role this node plays in the veil. Defaults to `leaf`.
    #[serde(default, skip_serializing_if = "is_default_role")]
    pub role: NodeRole,
    /// `public_key` — public key.
    pub public_key: String,
    /// `private_key` — private key.
    pub private_key: String,
    #[serde(default = "default_nonce_base64")]
    /// `nonce` — nonce.
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `node_id` — node id.
    pub node_id: Option<NodeId>,
    /// Inline passphrase for the ML-KEM decapsulation-key seed file.
    /// **Least-secure source**: stored alongside the encrypted file →
    /// offers protection only against config-leak-without-key-file
    /// scenarios. Suitable for dev / smoke tests. Production deployments
    /// should prefer [`Self::key_passphrase_file`] or
    /// [`Self::key_passphrase_prompt`]. A WARN is logged on startup if
    /// this is the resolved source. `None` = no inline passphrase.
    ///
    /// Resolution priority (highest → lowest):
    ///   1. `key_passphrase_prompt = true` → interactive stdin prompt
    ///   2. `VEIL_KEY_PASSPHRASE` env var (wiped after read)
    ///   3. `key_passphrase_file`
    ///   4. `key_passphrase` (this field)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_passphrase: Option<String>,
    /// Path to a file containing the ML-KEM key passphrase. File MUST be
    /// `0o600` owner-readable; daemon reads first line, trims whitespace.
    /// Compatible with systemd `LoadCredential=` (`/run/credentials/...`),
    /// k8s Secret mounts, and vault-fetched files. Wins over inline
    /// [`Self::key_passphrase`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_passphrase_file: Option<std::path::PathBuf>,
    /// When `true`, daemon prompts on stdin for the passphrase at startup.
    /// Highest-security source — passphrase never touches disk / config.
    /// Incompatible with systemd auto-start (no controlling tty); intended
    /// for operator-supervised launches. If `true` AND prompt fails →
    /// daemon refuses to start (does NOT fall back to other sources).
    #[serde(default, skip_serializing_if = "is_false")]
    pub key_passphrase_prompt: bool,
    /// Background mining of a better identity nonce during idle periods.
    /// Higher difficulty = more trust in PEX, DHT priority, etc.
    /// Default: `true` for Core, `false` for Leaf.
    #[serde(
        default = "default_lazy_mining",
        skip_serializing_if = "is_default_lazy_mining"
    )]
    pub lazy_mining: bool,
    /// Upper limit for lazy background nonce mining. Default: 64.
    #[serde(
        default = "default_max_lazy_difficulty",
        skip_serializing_if = "is_default_max_lazy_difficulty"
    )]
    pub max_lazy_difficulty: u8,
}

impl std::fmt::Debug for IdentityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityConfig")
            .field("algo", &self.algo)
            .field("role", &self.role)
            .field("public_key", &self.public_key)
            .field("node_id", &self.node_id)
            .field("private_key", &"<redacted>")
            .field(
                "key_passphrase",
                &self.key_passphrase.as_ref().map(|_| "<redacted>"),
            )
            // ".." — any field not listed (incl. future additions) is
            // omitted, so a newly-added secret can't silently leak.
            .finish_non_exhaustive()
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            algo: SignatureAlgorithm::default(),
            role: NodeRole::default(),
            public_key: String::new(),
            private_key: String::new(),
            nonce: default_nonce_base64(),
            node_id: None,
            key_passphrase: None,
            key_passphrase_file: None,
            key_passphrase_prompt: false,
            lazy_mining: default_lazy_mining(),
            max_lazy_difficulty: default_max_lazy_difficulty(),
        }
    }
}

fn default_lazy_mining() -> bool {
    // Opt-in: lazy_miner runs Ed25519 sign on every PoW nonce attempt to
    // upgrade identity difficulty toward `max_lazy_difficulty`. On small
    // VPS (1-2 vCPU) this burned ~40% CPU continuously, throttling the
    // session loop's throughput. Flipped to opt-in so operators chasing
    // higher identity difficulty turn it on explicitly via
    // `[identity] lazy_mining = true` in node.toml.
    false
}
fn is_default_lazy_mining(v: &bool) -> bool {
    *v == default_lazy_mining()
}
fn default_max_lazy_difficulty() -> u8 {
    64
}
fn is_default_max_lazy_difficulty(v: &u8) -> bool {
    *v == default_max_lazy_difficulty()
}

fn is_default_role(role: &NodeRole) -> bool {
    *role == NodeRole::default()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Node id (see field docs for details).
pub struct NodeId([u8; 32]);

impl NodeId {
    /// `from_public_key` — see impl.
    pub fn from_public_key(algo: SignatureAlgorithm, public_key: &str) -> Result<Self> {
        let public_key = Base64PublicKey::new(algo, public_key.to_owned())?;
        let bytes = STANDARD.decode(public_key.as_str())?;
        Ok(Self(*blake3::hash(&bytes).as_bytes()))
    }

    /// `as_bytes` — see impl.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `to_hex` — see impl.
    pub fn to_hex(self) -> String {
        veil_util::bytes_to_hex(&self.0)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for NodeId {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self> {
        let trimmed = value.trim();
        if trimmed.len() != 64 {
            return Err(ConfigError::InvalidValue {
                key: "identity.node_id".to_owned(),
                value: value.to_owned(),
                reason: "expected 64 lowercase hexadecimal characters".to_owned(),
            });
        }

        let mut bytes = [0_u8; 32];
        for (index, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
            let chunk = std::str::from_utf8(chunk).map_err(|err| ConfigError::InvalidValue {
                key: "identity.node_id".to_owned(),
                value: value.to_owned(),
                reason: err.to_string(),
            })?;
            bytes[index] =
                u8::from_str_radix(chunk, 16).map_err(|err| ConfigError::InvalidValue {
                    key: "identity.node_id".to_owned(),
                    value: value.to_owned(),
                    reason: err.to_string(),
                })?;
        }

        Ok(Self(bytes))
    }
}

impl From<[u8; 32]> for NodeId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Serialize for NodeId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Peer id (see field docs for details).
pub struct PeerId(u32);

impl PeerId {
    /// `new` — see impl.
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// `get` — see impl.
    pub fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

impl FromStr for PeerId {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self> {
        parse_u32_identifier("peers.peer_id", value).map(Self)
    }
}

impl Serialize for PeerId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Listen id (see field docs for details).
pub struct ListenId(u32);

impl ListenId {
    /// `new` — see impl.
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// `get` — see impl.
    pub fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ListenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

impl FromStr for ListenId {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self> {
        parse_u32_identifier("listen.id", value).map(Self)
    }
}

impl Serialize for ListenId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ListenId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// Friend list for `FriendsOnly` visibility scope.
///
/// Contains the set of node IDs (hex-encoded 32 bytes) that are allowed to
/// discover this node when the attachment visibility is set to `FriendsOnly`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct FriendList {
    /// List of node IDs (lowercase 64-char hex strings) of allowed peers.
    #[serde(default)]
    pub allowed: Vec<String>,
}

/// A pinned relay node.
///
/// Pinned relays are always-on relay connections maintained by the node
/// regardless of DHT routing state. The connection is kept alive with
/// exponential-backoff reconnect; losing a pinned relay triggers an
/// immediate reconnect attempt.
///
/// Contains the same identity fields as `PeerConfig` so the OVL1 handshake
/// can verify the remote node's identity.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PinnedRelay {
    /// Transport URI (e.g. `"tcp://relay.example.com:9000"`)
    pub transport: String,
    /// Relay node's ed25519 public key (base64)
    pub public_key: String,
    /// Nonce (base64) for node_id derivation
    #[serde(default = "default_nonce_base64")]
    pub nonce: String,
    /// Signature algorithm used by this relay node (default: `"ed25519"`).
    #[serde(default)]
    pub algo: SignatureAlgorithm,
    /// Connection priority: lower value = preferred (default 128).
    /// Used for tie-breaking when multiple pinned relays are available.
    #[serde(default = "PinnedRelay::default_priority")]
    pub priority: u8,
    /// TLS certificate (PEM) if the transport is TLS
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `tls_ca_cert` — tls ca cert.
    pub tls_ca_cert: Option<String>,
}

impl PinnedRelay {
    fn default_priority() -> u8 {
        128
    }
}

// BootstrapPeer moved to veil-types so veil-bootstrap can
// consume it without depending on cfg. Re-exported below.
pub use veil_types::BootstrapPeer;

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
/// Peer config (see field docs for details).
pub struct PeerConfig {
    /// `peer_id` — peer id.
    pub peer_id: PeerId,
    /// `public_key` — public key.
    pub public_key: String,
    /// `nonce` — nonce.
    pub nonce: String,
    /// `transport` — transport.
    pub transport: String,
    /// Signature algorithm used by this peer (default: `"ed25519"`).
    #[serde(default)]
    pub algo: SignatureAlgorithm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `tls_cert` — tls cert.
    pub tls_cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `tls_key` — tls key.
    pub tls_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `tls_ca_cert` — tls ca cert.
    pub tls_ca_cert: Option<String>,
    /// stage (c): alternate transport URI to dial for hot-standby
    /// handoff when the primary transport starts failing. Operator sets
    /// this once per peer (the peer's own secondary listener address, e.g.
    /// `wss://peer.example:8443/veil` when primary is tls). When
    /// `None`, the hot-standby auto-trigger does nothing for this peer —
    /// the session still closes on repeated write errors (legacy behavior)
    /// and outbound_connector reconnects via a fresh OVL1 handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt_uri: Option<String>,
}

// `Debug` is implemented manually (not derived) to redact the TLS
// credential *paths* (`tls_cert`/`tls_key`/`tls_ca_cert`) — a stray
// `{:?}` on a `Config` would otherwise disclose the on-disk location of
// the private-key file. `finish_non_exhaustive` omits any field not
// listed, so a future secret field can't silently leak.
impl std::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConfig")
            .field("peer_id", &self.peer_id)
            .field("public_key", &self.public_key)
            .field("nonce", &self.nonce)
            .field("transport", &self.transport)
            .field("algo", &self.algo)
            .field("tls_cert", &self.tls_cert.as_ref().map(|_| "<redacted>"))
            .field("tls_key", &self.tls_key.as_ref().map(|_| "<redacted>"))
            .field(
                "tls_ca_cert",
                &self.tls_ca_cert.as_ref().map(|_| "<redacted>"),
            )
            .field("alt_uri", &self.alt_uri)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
/// Listen config (see field docs for details).
#[serde(default)]
pub struct ListenConfig {
    /// `id` — id.
    pub id: ListenId,
    /// Actual bind address (e.g. `ws://127.0.0.1:7001/veil`).
    pub transport: String,
    /// Address advertised to peers in RouteResponse.
    /// When set, overrides `transport` in peer advertisements so that the
    /// node can bind on localhost while telling peers to connect via a
    /// reverse proxy (e.g. `wss://nginx.example.com:443/veil`).
    /// When absent, `transport` is advertised as-is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise: Option<String>,
    /// Relay node-id (base64, 32 bytes) reachable by peers to access this
    /// listener indirectly. Included in `RouteResponsePayload.relay_ids`.
    /// Use when the node is behind a relay/NAT and peers should attempt the
    /// relay path in addition (or instead) direct transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `tls_cert` — tls cert.
    pub tls_cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `tls_key` — tls key.
    pub tls_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// `tls_ca_cert` — tls ca cert.
    pub tls_ca_cert: Option<String>,

    // ── Per-listener visibility / trust controls ─────────────────────
    /// Visibility level — controls whether this listener gets advertised
    /// through PEX + DHT routing announcements.
    /// `Public` (default) — full gossip.
    /// `Trusted` — never advertised; clients learn via invite-bundle.
    /// `Hidden` — never advertised + allowlist enforced on accept.
    /// Backwards compat: legacy configs without `visibility` field treated
    /// as `Public`.
    #[serde(default, skip_serializing_if = "Visibility::is_default")]
    pub visibility: Visibility,

    /// Optional human-readable group tag, mostly diagnostic ("family",
    /// "snowflake-rotation", "internal-mesh").  Not used by daemon
    /// logic; surfaced in logs + metrics labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_label: Option<String>,

    /// Optional path to a listener-specific PSK file (32-byte base64
    /// encoded).  Used by obfs4-tcp listeners to decouple cluster-wide
    /// shared PSK from per-group secret.  None → fall back to
    /// `transport.obfs4_psk_file` (the deployment-wide PSK).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk_file: Option<std::path::PathBuf>,

    /// Per-listener allowlist of node_ids (hex, 32 bytes).  Only peers
    /// whose handshake identity_pubkey hashes to a listed node_id can
    /// establish a session through this listener.  Required for
    /// `visibility = "hidden"`; optional reinforcement for `trusted`
    /// (where PSK protects too).  Empty/missing = no allowlist (allow
    /// any peer that passes the PSK check).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowlist_node_ids: Vec<String>,

    /// Ephemeral binding mode — when set, daemon picks a random port
    /// from `range`, retries `bind_retries` times on EADDRINUSE, and
    /// rotates after `rotation` interval.  `transport` field's port
    /// is ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<EphemeralConfig>,

    /// PoW-Gated Rendezvous binding mode — when set, daemon does
    /// NOT bind a port at startup.  A port is bound on-demand after
    /// a requester completes a PoW-gated rendezvous handshake against
    /// the existing OVL1 session plane.  Requires
    /// `visibility = "stealth"`.  See [`OnDemandListenConfig`] and the
    /// epic design doc `docs/internal/PLAN_POW_GATED_RENDEZVOUS.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_demand: Option<OnDemandListenConfig>,
}

// `Debug` is implemented manually (not derived) to redact the TLS
// credential *paths* (`tls_cert`/`tls_key`/`tls_ca_cert`) — a stray
// `{:?}` on a `Config` would otherwise disclose the on-disk location of
// the private-key file. `finish_non_exhaustive` omits any field not
// listed, so a future secret field can't silently leak.
impl std::fmt::Debug for ListenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenConfig")
            .field("id", &self.id)
            .field("transport", &self.transport)
            .field("advertise", &self.advertise)
            .field("relay", &self.relay)
            .field("tls_cert", &self.tls_cert.as_ref().map(|_| "<redacted>"))
            .field("tls_key", &self.tls_key.as_ref().map(|_| "<redacted>"))
            .field(
                "tls_ca_cert",
                &self.tls_ca_cert.as_ref().map(|_| "<redacted>"),
            )
            .field("visibility", &self.visibility)
            .field("group_label", &self.group_label)
            .field("psk_file", &self.psk_file)
            .field("allowlist_node_ids", &self.allowlist_node_ids)
            .field("ephemeral", &self.ephemeral)
            .field("on_demand", &self.on_demand)
            .finish_non_exhaustive()
    }
}

/// Visibility level for a listen entry.  Controls gossip behaviour;
/// see [`ListenConfig`].
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    /// Default — listener advertised via PEX + DHT.  Any peer on the
    /// network can resolve this listener's URI and connect (subject to
    /// PSK / transport-level auth).
    #[default]
    Public,
    /// Listener bound locally but NOT advertised anywhere.  Discovery is
    /// out-of-band — operator hands clients an invite-bundle with the
    /// URI + PSK.  Inbound connections still verified by transport-
    /// level credential (PSK, TLS).
    Trusted,
    /// As `Trusted`, AND inbound connection identity must match a
    /// node_id in `allowlist_node_ids`.  Strictest mode: even if PSK
    /// leaks, connection rejected unless peer's signed identity matches.
    Hidden,
    /// PoW-Gated Rendezvous (designed in `docs/internal/PLAN_POW_GATED_RENDEZVOUS.md`).
    /// Listener is **not bound** at startup.  Daemon binds an ephemeral
    /// port on-demand only after a requester completes a PoW-gated
    /// rendezvous handshake (see `[listen.on_demand]` config block).
    /// The bound listener accepts a bounded number of sessions within
    /// a short TTL and then auto-closes.  IP becomes invisible to Shodan/
    /// nmap-style scanners since no port is open by default.
    Stealth,
}

impl Visibility {
    /// `is_default` — used by serde to omit the field when value =
    /// `Public` (backwards compat).
    pub fn is_default(&self) -> bool {
        matches!(self, Visibility::Public)
    }

    /// Whether this listener's transport URI must be published in DHT
    /// (`SignedTransportAnnouncement`) and returned through PEX walks.
    pub fn is_advertisable(&self) -> bool {
        matches!(self, Visibility::Public)
    }

    /// Whether incoming connections require their handshake-attested
    /// identity to match the listener's `allowlist_node_ids`.
    pub fn requires_allowlist_match(&self) -> bool {
        matches!(self, Visibility::Hidden)
    }

    /// Whether this listener uses the PoW-Gated Rendezvous flow
    /// (listener bound on-demand only after a valid request lands).
    /// Stealth listeners skip the startup-time physical bind in
    /// `spawn_listeners`; the actual port comes alive only when
    /// the rendezvous controller invokes its BindClosure.
    pub fn is_stealth(&self) -> bool {
        matches!(self, Visibility::Stealth)
    }
}

/// Ephemeral random-port configuration for a listener.  See
/// [`ListenConfig::ephemeral`].
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct EphemeralConfig {
    /// Inclusive port range from which a random bind port is chosen.
    /// `[10000, 60000]` covers a wide non-privileged range without typical
    /// well-known service ports.  Use narrower range if blending with
    /// specific protocol ports (e.g. `[3306, 3306]` for MySQL-SSL
    /// mimicry).
    pub range: (u16, u16),

    /// Rotation interval (ISO-8601 duration or seconds-numeric).
    /// Listener rebinds on a fresh random port after this elapses.
    /// Existing sessions on the old port get a grace period before
    /// it's closed.
    pub rotation: String, // "3d", "12h", "300s" — parsed at runtime

    /// Number of bind retries when the random port is already in use.
    /// `0` disables retry (fail if first pick collides).  Default 64
    /// gives ~99.999% success rate in a 50k-port range under typical
    /// load.
    #[serde(default = "default_bind_retries")]
    pub bind_retries: u32,

    /// Grace period after rotation during which old listener is kept
    /// alive for in-flight sessions.  Default "30m".
    #[serde(default = "default_grace_period")]
    pub grace_period: String,
}

fn default_bind_retries() -> u32 {
    64
}

fn default_grace_period() -> String {
    "30m".to_owned()
}

/// PoW-Gated Rendezvous configuration for a listener entry.  See
/// [`ListenConfig::on_demand`].  Listener bound on-demand only after
/// a valid PoW-gated request lands; no port is open by default.
///
/// Threat model + full design documented in
/// `docs/internal/PLAN_POW_GATED_RENDEZVOUS.md`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OnDemandListenConfig {
    /// Inclusive random-port range from which the on-demand bind picks.
    /// Matches the [`EphemeralConfig::range`] semantics; wide ranges
    /// (50000-60000) reduce collision probability under concurrent
    /// requests.
    pub range: (u16, u16),

    /// Required PoW difficulty in leading-zero-bits.  Production
    /// recommendation: 24 bits (~16M attempts ≈ 0.5 s on a 2-vCPU
    /// VPS).  Higher value = stronger anti-spam, slower legit
    /// requesters.  Verifier accepts requests claiming ≥ this value;
    /// requests below are rejected.
    pub pow_difficulty: u32,

    /// Listener TTL specification (e.g. `"5m"`, `"300s"`).  After
    /// this elapses from bind moment the slot's accept-loop exits and
    /// the listener drops, regardless of whether any session was
    /// accepted.
    pub ttl: String,

    /// Maximum concurrent in-flight on-demand listener slots.  Caps
    /// FD-table consumption against a PoW-funded burst.  Production
    /// recommendation: 16-32.
    #[serde(default = "default_max_concurrent_slots")]
    pub max_concurrent: usize,

    /// Per-requester rate-limit spec, format `"N/period"` where
    /// period is `s` / `m` / `h` / `d`.  Examples: `"3/h"` (3 grants
    /// per hour per requester pubkey), `"1/m"` (one grant per minute).
    /// Independent from the global concurrent cap.
    #[serde(default = "default_rate_limit")]
    pub rate_limit: String,

    /// Maximum accepted sessions per slot before retiring it.  Default
    /// 1 (one-shot rendezvous).  Higher values support multi-device
    /// pairing flows where several connections arrive in quick succession.
    #[serde(default = "default_max_accepts")]
    pub max_accepts: usize,

    /// Number of bind retries when the random port is already in use.
    /// Mirrors [`EphemeralConfig::bind_retries`].
    #[serde(default = "default_bind_retries")]
    pub bind_retries: u32,
}

fn default_max_concurrent_slots() -> usize {
    16
}

fn default_rate_limit() -> String {
    "3/h".to_owned()
}

fn default_max_accepts() -> usize {
    1
}

#[cfg(test)]
mod listen_visibility_tests {
    use super::*;

    #[test]
    fn visibility_default_is_public() {
        assert_eq!(Visibility::default(), Visibility::Public);
        assert!(Visibility::default().is_advertisable());
        assert!(!Visibility::default().requires_allowlist_match());
    }

    #[test]
    fn trusted_does_not_advertise_but_does_not_force_allowlist() {
        let v = Visibility::Trusted;
        assert!(!v.is_advertisable());
        assert!(!v.requires_allowlist_match());
    }

    #[test]
    fn hidden_requires_allowlist() {
        let v = Visibility::Hidden;
        assert!(!v.is_advertisable());
        assert!(v.requires_allowlist_match());
    }

    #[test]
    fn stealth_not_advertised_not_allowlist_marked_stealth() {
        let v = Visibility::Stealth;
        assert!(!v.is_advertisable());
        // Stealth uses PoW gating instead of allowlist enforcement.
        assert!(!v.requires_allowlist_match());
        assert!(v.is_stealth());
    }

    #[test]
    fn non_stealth_visibilities_not_stealth() {
        assert!(!Visibility::Public.is_stealth());
        assert!(!Visibility::Trusted.is_stealth());
        assert!(!Visibility::Hidden.is_stealth());
    }

    #[test]
    fn on_demand_config_serde_round_trip() {
        let cfg = OnDemandListenConfig {
            range: (50000, 60000),
            pow_difficulty: 24,
            ttl: "5m".to_owned(),
            max_concurrent: 32,
            rate_limit: "3/h".to_owned(),
            max_accepts: 1,
            bind_retries: 64,
        };
        let toml_str = toml::to_string(&cfg).unwrap();
        let parsed: OnDemandListenConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn on_demand_config_serde_uses_defaults() {
        // Only the required fields supplied; defaults filled in.
        let toml_src = r#"
            range = [50000, 60000]
            pow_difficulty = 24
            ttl = "5m"
        "#;
        let cfg: OnDemandListenConfig = toml::from_str(toml_src).unwrap();
        assert_eq!(cfg.range, (50000, 60000));
        assert_eq!(cfg.pow_difficulty, 24);
        assert_eq!(cfg.ttl, "5m");
        assert_eq!(cfg.max_concurrent, 16); // default
        assert_eq!(cfg.rate_limit, "3/h"); // default
        assert_eq!(cfg.max_accepts, 1); // default
        assert_eq!(cfg.bind_retries, 64); // default
    }

    #[test]
    fn listen_config_serde_carries_stealth_and_on_demand() {
        let toml_src = r#"
            id = "0x00000004"
            transport = "obfs4-tcp://0.0.0.0:0"
            visibility = "stealth"

            [on_demand]
            range = [50000, 60000]
            pow_difficulty = 24
            ttl = "5m"
        "#;
        let parsed: ListenConfig = toml::from_str(toml_src).unwrap();
        assert_eq!(parsed.visibility, Visibility::Stealth);
        let on_demand = parsed.on_demand.expect("on_demand should parse");
        assert_eq!(on_demand.range, (50000, 60000));
        assert_eq!(on_demand.pow_difficulty, 24);
    }

    /// Backwards-compat: configs without the new fields parse correctly.
    #[test]
    fn legacy_config_parses() {
        let toml_src = r#"
            id = "0x00000001"
            transport = "tcp://0.0.0.0:5555"
        "#;
        let lc: ListenConfig = toml::from_str(toml_src).expect("legacy parses");
        assert_eq!(lc.visibility, Visibility::Public);
        assert!(lc.psk_file.is_none());
        assert!(lc.allowlist_node_ids.is_empty());
        assert!(lc.ephemeral.is_none());
        assert!(lc.group_label.is_none());
    }

    /// Full-featured: new config with all fields parses + serializes round-trip.
    #[test]
    fn full_listen_config_round_trip() {
        let toml_src = r#"
            id = "0x00000002"
            transport = "obfs4-tcp://0.0.0.0:7777"
            advertise = "obfs4-tcp://1.2.3.4:7777"
            visibility = "trusted"
            group_label = "family"
            psk_file = "/var/lib/veil/psk-family.b64"
            allowlist_node_ids = ["abc", "def"]
        "#;
        let lc: ListenConfig = toml::from_str(toml_src).expect("parse ok");
        assert_eq!(lc.visibility, Visibility::Trusted);
        assert_eq!(lc.group_label.as_deref(), Some("family"));
        assert_eq!(
            lc.allowlist_node_ids,
            vec!["abc".to_owned(), "def".to_owned()]
        );
        assert!(!lc.visibility.is_advertisable());

        // Round-trip preserve.
        let re_encoded = toml::to_string(&lc).expect("serialize ok");
        let re_parsed: ListenConfig = toml::from_str(&re_encoded).expect("re-parse ok");
        assert_eq!(re_parsed.visibility, Visibility::Trusted);
        assert_eq!(re_parsed.allowlist_node_ids.len(), 2);
    }

    #[test]
    fn ephemeral_config_parses() {
        let toml_src = r#"
            id = "0x00000003"
            transport = "obfs4-tcp://0.0.0.0:0"
            visibility = "trusted"
            [ephemeral]
            range = [10000, 60000]
            rotation = "3d"
        "#;
        let lc: ListenConfig = toml::from_str(toml_src).expect("parse ok");
        let eph = lc.ephemeral.expect("ephemeral set");
        assert_eq!(eph.range, (10000, 60000));
        assert_eq!(eph.rotation, "3d");
        assert_eq!(eph.bind_retries, 64); // default
        assert_eq!(eph.grace_period, "30m"); // default
    }

    /// Public visibility omits serialization (backwards compat — old
    /// tools that don't recognize the field still parse the file).
    #[test]
    fn public_visibility_omitted_in_serialized_output() {
        let lc = ListenConfig {
            id: ListenId(1),
            transport: "tcp://0.0.0.0:5555".to_owned(),
            visibility: Visibility::Public,
            ..Default::default()
        };
        let s = toml::to_string(&lc).expect("serialize");
        assert!(
            !s.contains("visibility"),
            "Public visibility should be omitted from output, got: {s}"
        );
    }

    #[test]
    fn trusted_visibility_appears_in_serialized_output() {
        let lc = ListenConfig {
            id: ListenId(1),
            transport: "tcp://0.0.0.0:5555".to_owned(),
            visibility: Visibility::Trusted,
            ..Default::default()
        };
        let s = toml::to_string(&lc).expect("serialize");
        assert!(s.contains("visibility = \"trusted\""), "got: {s}");
    }
}

// MetricsConfig moved to veil-types so veil-observability
// can consume it without depending on cfg.
pub use veil_types::MetricsConfig;

// P-Net Phase 1: NetworkConfig + membership-cert types live in
// veil-types so other crates (handshake, DHT ban-list) can reference
// them without depending on `cfg`.
pub use veil_types::{MEMBERSHIP_CERT_VERSION, MembershipCert, NetworkConfig, NetworkMode};

// c: NodeRole moved to veil-types (with role_bits) so proto can
// reference it without reverse-importing cfg. Re-exported below.
pub use veil_types::NodeRole;

#[cfg(test)]
mod node_role_tests {
    use super::*;
    use veil_proto::session::{CapabilitiesPayload, cap_flags, role_bits};

    #[test]
    fn node_role_display_roundtrip() {
        for (role, expected) in [(NodeRole::Leaf, "leaf"), (NodeRole::Core, "core")] {
            assert_eq!(role.to_string(), expected);
            let parsed: NodeRole = expected.parse().unwrap();
            assert_eq!(parsed, role);
        }
    }

    #[test]
    fn legacy_role_names_rejected() {
        for legacy in ["core_router", "relay", "gateway"] {
            assert!(
                legacy.parse::<NodeRole>().is_err(),
                "{legacy} must be rejected"
            );
        }
    }

    #[test]
    fn node_role_default_is_core() {
        assert_eq!(NodeRole::default(), NodeRole::Core);
    }

    #[test]
    fn node_role_serde_roundtrip() {
        for role in [NodeRole::Leaf, NodeRole::Core] {
            let json = serde_json::to_string(&role).unwrap();
            let back: NodeRole = serde_json::from_str(&json).unwrap();
            assert_eq!(back, role);
        }
    }

    #[test]
    fn to_role_bits_correct() {
        assert_eq!(NodeRole::Leaf.to_role_bits(), role_bits::LEAF);
        assert_eq!(NodeRole::Core.to_role_bits(), role_bits::CORE);
    }

    #[test]
    fn capabilities_from_role_leaf() {
        let caps = CapabilitiesPayload::from_node_role(NodeRole::Leaf);
        assert_eq!(caps.roles_supported, role_bits::LEAF);
        assert_eq!(caps.flags & cap_flags::CAN_RELAY, 0, "leaf must not relay");
    }

    #[test]
    fn capabilities_from_role_core() {
        let caps = CapabilitiesPayload::from_node_role(NodeRole::Core);
        assert_eq!(caps.roles_supported, role_bits::CORE);
        assert_ne!(caps.flags & cap_flags::CAN_RELAY, 0);
    }

    #[test]
    fn capabilities_roundtrip_from_role() {
        for role in [NodeRole::Leaf, NodeRole::Core] {
            let caps = CapabilitiesPayload::from_node_role(role);
            let decoded = CapabilitiesPayload::decode(&caps.encode()).unwrap();
            assert_eq!(decoded, caps, "roundtrip failed for {role}");
        }
    }
}

// SignatureAlgorithm moved to veil-types crate (re-exported
// at top of this file). See comment above.

fn default_beacon_addr() -> String {
    "255.255.255.255:9100".to_owned()
}

// `default_nonce_base64` moved to veil-types so the
// `BootstrapPeer` schema (which lives there now) can use it without
// reverse-importing cfg. Re-exported below.
pub use veil_types::default_nonce_base64;

fn parse_u32_identifier(key: &str, value: &str) -> Result<u32> {
    let trimmed = value.trim();
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u32>()
    };

    parsed.map_err(|reason| ConfigError::InvalidValue {
        key: key.to_owned(),
        value: value.to_owned(),
        reason: reason.to_string(),
    })
}

#[cfg(test)]
mod bootstrap_peer_tests {
    use super::*;

    #[test]
    fn bootstrap_peer_config_roundtrip() {
        let bp = BootstrapPeer {
            transport: "tcp://bootstrap.example.com:9000".to_owned(),
            public_key: "AAAA".to_owned(),
            nonce: default_nonce_base64(),
            algo: Default::default(),
            tls_cert: None,
            tls_ca_cert: None,
        };
        let json = serde_json::to_string(&bp).unwrap();
        let bp2: BootstrapPeer = serde_json::from_str(&json).unwrap();
        assert_eq!(bp, bp2);
    }

    #[test]
    fn bootstrap_peer_nonce_default_applied_on_deserialize() {
        // When nonce is absent from JSON, default_nonce_base64 is applied.
        let json = r#"{"transport":"tcp://x:9000","public_key":"AAAA"}"#;
        let bp: BootstrapPeer = serde_json::from_str(json).unwrap();
        assert_eq!(bp.nonce, default_nonce_base64());
    }

    #[test]
    fn bootstrap_peer_optional_fields_omitted_when_none() {
        let bp = BootstrapPeer {
            transport: "tcp://x:9000".to_owned(),
            public_key: "AAAA".to_owned(),
            nonce: default_nonce_base64(),
            algo: Default::default(),
            tls_cert: None,
            tls_ca_cert: None,
        };
        let json = serde_json::to_string(&bp).unwrap();
        assert!(
            !json.contains("tls_cert"),
            "tls_cert must be omitted when None"
        );
        assert!(
            !json.contains("tls_ca_cert"),
            "tls_ca_cert must be omitted when None"
        );
    }
}

#[cfg(test)]
mod abuse_per_peer_byte_burst_tests {
    use super::*;

    #[test]
    fn epic483_6b_resolved_burst_is_4x_rate_when_unset() {
        // Default 4-second burst window — legitimate-but-bursty
        // peers don't get throttled on the first frame.
        let cfg = AbuseConfig {
            per_peer_bytes_per_sec: Some(65_536),
            per_peer_byte_burst: None,
            ..AbuseConfig::default()
        };
        assert_eq!(
            cfg.resolved_per_peer_byte_burst(),
            Some(4 * 65_536),
            "default burst = 4× rate"
        );
    }

    #[test]
    fn epic483_6b_resolved_burst_uses_explicit_value_when_set() {
        // Operator may want a tighter burst (less tolerant of
        // bursts) OR a much wider one (large file transfer use
        // case). Explicit value takes precedence over default.
        let cfg = AbuseConfig {
            per_peer_bytes_per_sec: Some(65_536),
            per_peer_byte_burst: Some(1_048_576), // 1 MB burst
            ..AbuseConfig::default()
        };
        assert_eq!(
            cfg.resolved_per_peer_byte_burst(),
            Some(1_048_576),
            "explicit burst takes precedence over default 4× rate"
        );
    }

    #[test]
    fn epic483_6b_resolved_burst_is_none_when_rate_not_set() {
        // Per-peer enforcement disabled (rate=None) — burst is
        // moot; resolved helper returns None so callers don't
        // accidentally enable enforcement through only-burst-set
        // misconfig.
        let cfg = AbuseConfig {
            per_peer_bytes_per_sec: None,
            per_peer_byte_burst: Some(1_048_576),
            ..AbuseConfig::default()
        };
        assert_eq!(
            cfg.resolved_per_peer_byte_burst(),
            None,
            "rate=None must override any explicit burst — enforcement is rate-driven"
        );
    }

    #[test]
    fn epic483_6b_default_config_disables_per_peer_byte_rate() {
        let cfg = AbuseConfig::default();
        assert!(
            cfg.per_peer_bytes_per_sec.is_none(),
            "default config = per-peer byte enforcement off"
        );
        assert!(cfg.per_peer_byte_burst.is_none());
        assert_eq!(cfg.resolved_per_peer_byte_burst(), None);
    }
}

#[cfg(test)]
mod config_knobs_tests {
    use super::*;

    /// Non-default RoutingConfig values survive a JSON round-trip and differ from defaults.
    #[test]
    fn routing_config_non_default_roundtrip() {
        let custom = RoutingConfig {
            route_probe_interval_secs: 5,
            reannounce_interval_secs: 15,
            route_cache_ttl_secs: 60,
            route_request_backoff_ms: [100, 200, 400],
            partition_score_threshold: 0.5,
            dht_fallback_timeout_ms: 5_000,
            dht_fallback_backpressure_threshold_pct: 50,
            dht_fallback_adaptive: true,
            dht_fallback_priority_mult: [40, 250],
            dht_fallback_enabled: false,
            route_seen_capacity: RoutingConfig::default().route_seen_capacity,
            route_seen_window_secs: RoutingConfig::default().route_seen_window_secs,
            max_gossip_hops: RoutingConfig::default().max_gossip_hops,
            ecmp_score_band: RoutingConfig::default().ecmp_score_band,
            redundant_send: false,
            probe_min_interval_secs: RoutingConfig::default().probe_min_interval_secs,
            probe_max_interval_secs: RoutingConfig::default().probe_max_interval_secs,
            probe_stability_threshold: RoutingConfig::default().probe_stability_threshold,
            cache_persist_path: None,
            cache_persist_interval_secs: RoutingConfig::default().cache_persist_interval_secs,
            cache_persist_max_age_secs: RoutingConfig::default().cache_persist_max_age_secs,
            epidemic_fanout: RoutingConfig::default().epidemic_fanout,
            epidemic_max_payload: RoutingConfig::default().epidemic_max_payload,
            battery_penalty_low: RoutingConfig::default().battery_penalty_low,
            battery_penalty_medium: RoutingConfig::default().battery_penalty_medium,
            battery_threshold_low: RoutingConfig::default().battery_threshold_low,
            battery_threshold_medium: RoutingConfig::default().battery_threshold_medium,
            trace_sample_rate: RoutingConfig::default().trace_sample_rate,
            trace_buffer_size: RoutingConfig::default().trace_buffer_size,
            rtt_persist_path: None,
            rtt_persist_interval_secs: RoutingConfig::default().rtt_persist_interval_secs,
            vivaldi_persist_path: None,
            gateway_persist_path: None,
            peer_pubkeys_persist_path: None,
            multi_path_enabled: false,
            max_parallel_paths: RoutingConfig::default().max_parallel_paths,
            multi_path_min_priority: RoutingConfig::default().multi_path_min_priority,
            relay_reputation_min_attempts: RoutingConfig::default().relay_reputation_min_attempts,
            relay_reputation_threshold: RoutingConfig::default().relay_reputation_threshold,
            relay_reputation_penalty: RoutingConfig::default().relay_reputation_penalty,
            jitter_penalty_weight: RoutingConfig::default().jitter_penalty_weight,
            jitter_threshold_ms: RoutingConfig::default().jitter_threshold_ms,
            narrow_bandwidth_bulk_penalty: RoutingConfig::default().narrow_bandwidth_bulk_penalty,
            target_labels: vec!["exit".to_owned(), "low".to_owned()],
            discovery_mode: DiscoveryMode::ContactsOnly,
        };

        assert!(
            !custom.is_default(),
            "custom config must not equal defaults"
        );

        let json = serde_json::to_string(&custom).unwrap();
        let back: RoutingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, custom, "round-trip must preserve all fields");
        assert_eq!(back.route_request_backoff_ms, [100, 200, 400]);
        assert_eq!(back.route_probe_interval_secs, 5);
        assert!((back.partition_score_threshold - 0.5).abs() < f64::EPSILON);
    }

    /// Non-default SessionConfig survives a JSON round-trip.
    #[test]
    fn session_config_non_default_roundtrip() {
        let custom = SessionConfig {
            keepalive_interval_secs: 10,
            idle_timeout_secs: 45,
            max_age_secs: None,
            max_concurrent: SessionConfig::default().max_concurrent,
            max_per_ip: SessionConfig::default().max_per_ip,
            max_per_subnet: SessionConfig::default().max_per_subnet,
            max_pending_responses: SessionConfig::default().max_pending_responses,
            pending_response_ttl_ms: SessionConfig::default().pending_response_ttl_ms,
            outbox_depth: Default::default(),
            tx_queue_depth: Default::default(),
            max_frame_body_bytes: SessionConfig::default().max_frame_body_bytes,
            qos_weights: SessionConfig::default().qos_weights,
            rt_queue_len: SessionConfig::default().rt_queue_len,
            bg_queue_len: SessionConfig::default().bg_queue_len,
            battery_keepalive_scale_low: SessionConfig::default().battery_keepalive_scale_low,
            battery_keepalive_scale_medium: SessionConfig::default().battery_keepalive_scale_medium,
            battery_threshold_low: SessionConfig::default().battery_threshold_low,
            battery_threshold_medium: SessionConfig::default().battery_threshold_medium,
            battery_sync_threshold: SessionConfig::default().battery_sync_threshold,
            padding: PaddingPolicy::default(),
            rekey_bytes_threshold: SessionConfig::default().rekey_bytes_threshold,
            rekey_time_threshold_secs: SessionConfig::default().rekey_time_threshold_secs,
            allowed_peer_algos: vec![SignatureAlgorithm::Falcon512],
        };

        assert!(!custom.is_default());

        let json = serde_json::to_string(&custom).unwrap();
        let back: SessionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, custom);
    }

    /// Regression for the `is_default()` round-trip bug: it must account
    /// for `max_per_subnet` and `max_age_secs`. Previously omitting them
    /// meant a config whose only non-default value was one of these was
    /// judged "default", so the whole `[session]` block (including the
    /// eclipse-protection cap) was dropped on serialize and silently
    /// reverted to the baked-in default on reload.
    #[test]
    fn session_config_is_default_accounts_for_subnet_and_age() {
        assert!(SessionConfig::default().is_default());

        let only_subnet = SessionConfig {
            max_per_subnet: 8,
            ..SessionConfig::default()
        };
        assert!(
            !only_subnet.is_default(),
            "tightened max_per_subnet must survive serialization, not be dropped as default"
        );

        let only_age = SessionConfig {
            max_age_secs: Some(3600),
            ..SessionConfig::default()
        };
        assert!(
            !only_age.is_default(),
            "a set max_age_secs must survive serialization, not be dropped as default"
        );
    }

    /// `IdentityConfig`'s manual `Debug` must never print the private key or
    /// inline passphrase (defence against an accidental `{:?}` on a `Config`).
    #[test]
    fn identity_config_debug_redacts_secrets() {
        let c = IdentityConfig {
            public_key: "PUB".to_owned(),
            private_key: "SUPER_SECRET_PRIVATE_KEY".to_owned(),
            key_passphrase: Some("SUPER_SECRET_PASSPHRASE".to_owned()),
            ..IdentityConfig::default()
        };
        let dbg = format!("{c:?}");
        assert!(
            !dbg.contains("SUPER_SECRET_PRIVATE_KEY"),
            "private_key leaked in Debug: {dbg}"
        );
        assert!(
            !dbg.contains("SUPER_SECRET_PASSPHRASE"),
            "key_passphrase leaked in Debug: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker: {dbg}"
        );
        // non-secret fields still visible
        assert!(dbg.contains("PUB"), "public_key should be visible: {dbg}");
    }

    /// `PeerConfig` / `ListenConfig` manual `Debug` must never print the
    /// TLS credential *paths* — a stray `{:?}` would otherwise disclose
    /// the on-disk location of the private-key file.
    #[test]
    fn peer_and_listen_config_debug_redacts_tls_paths() {
        let peer = PeerConfig {
            tls_cert: Some("/etc/veil/SECRET_CERT_PATH.pem".to_owned()),
            tls_key: Some("/etc/veil/SECRET_KEY_PATH.pem".to_owned()),
            tls_ca_cert: Some("/etc/veil/SECRET_CA_PATH.pem".to_owned()),
            transport: "tls://example:443/veil".to_owned(),
            ..PeerConfig::default()
        };
        let dbg = format!("{peer:?}");
        assert!(
            !dbg.contains("SECRET_CERT_PATH")
                && !dbg.contains("SECRET_KEY_PATH")
                && !dbg.contains("SECRET_CA_PATH"),
            "PeerConfig leaked a TLS path in Debug: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker: {dbg}"
        );
        // non-secret field still visible
        assert!(
            dbg.contains("tls://example:443/veil"),
            "transport should be visible: {dbg}"
        );

        let listen = ListenConfig {
            tls_cert: Some("/etc/veil/SECRET_CERT_PATH.pem".to_owned()),
            tls_key: Some("/etc/veil/SECRET_KEY_PATH.pem".to_owned()),
            tls_ca_cert: Some("/etc/veil/SECRET_CA_PATH.pem".to_owned()),
            transport: "tls://0.0.0.0:443/veil".to_owned(),
            ..ListenConfig::default()
        };
        let dbg = format!("{listen:?}");
        assert!(
            !dbg.contains("SECRET_CERT_PATH")
                && !dbg.contains("SECRET_KEY_PATH")
                && !dbg.contains("SECRET_CA_PATH"),
            "ListenConfig leaked a TLS path in Debug: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker: {dbg}"
        );
        assert!(
            dbg.contains("tls://0.0.0.0:443/veil"),
            "transport should be visible: {dbg}"
        );
    }

    /// C-03: mesh beacon is secure-by-default — unsigned beacons are rejected,
    /// and the node's role is NOT advertised (no cleartext gateway/relay
    /// targeting signal broadcast to a passive on-link observer by default).
    #[test]
    fn mesh_config_c03_secure_defaults() {
        assert!(
            MeshConfig::default_require_signed_beacons(),
            "C-03: unsigned beacons must be rejected by default"
        );
        assert!(
            !MeshConfig::default_advertise_role_in_beacon(),
            "C-03: node role must not be advertised in the beacon by default"
        );
    }

    /// Non-default DhtConfig survives a JSON round-trip.
    #[test]
    fn dht_config_non_default_roundtrip() {
        let custom = DhtConfig {
            republish_interval_secs: 300,
            cleanup_interval_secs: 30,
            participate: true,
            k: DhtConfig::default().k,
            alpha: DhtConfig::default().alpha,
            max_rounds: DhtConfig::default().max_rounds,
            find_node_timeout_ms: DhtConfig::default().find_node_timeout_ms,
            vivaldi_weight: DhtConfig::default().vivaldi_weight,
            routing_persist_path: None,
            values_persist_path: None,
            cold_store_path: Some("/var/lib/veil/dht-cold".to_owned()),
            transport_announcements_persist_path: None,
            transport_announcements_persist_interval_secs: DhtConfig::default()
                .transport_announcements_persist_interval_secs,
            max_store_entries: DhtConfig::default().max_store_entries,
            // Explicit non-default values: `max_store_bytes` now defaults to
            // Some(400 MB) and is `skip_serializing_if = is_none`, so an
            // explicit `None` would serialize to absent and deserialize back to
            // the default — not round-trippable. Use concrete values so the
            // roundtrip genuinely exercises both byte caps.
            max_store_bytes: Some(256_000_000),
            per_origin_max_bytes: Some(65_536),
            shard_filtering: false,
            allow_unsigned_store: false,
        };

        assert!(!custom.is_default());

        let json = serde_json::to_string(&custom).unwrap();
        let back: DhtConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, custom);
    }

    #[test]
    fn dht_default_byte_cap_is_core_baseline() {
        // Core baseline: ~400 MB byte cap by default, keeping node memory
        // under ~512 MB. The named serde default must also apply when the key
        // is absent from a present `[dht]` table (not fall back to None).
        assert_eq!(DhtConfig::default().max_store_bytes, Some(400_000_000));
        let partial: DhtConfig = toml::from_str("participate = true\n").unwrap();
        assert_eq!(
            partial.max_store_bytes,
            Some(400_000_000),
            "omitting max_store_bytes must yield the Core default, not None"
        );
        // And a whole config with no [dht] section at all gets the default.
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.dht.max_store_bytes, Some(400_000_000));
        // Operator override still wins.
        let over: DhtConfig = toml::from_str("max_store_bytes = 4000000000\n").unwrap();
        assert_eq!(over.max_store_bytes, Some(4_000_000_000));
    }

    /// Config with all-custom routing/session/dht sections serialises and
    /// deserialises correctly end-to-end through the Config struct.
    #[test]
    fn full_config_non_default_sections_roundtrip() {
        let mut config = Config::default();
        config.routing.route_request_backoff_ms = [50, 150, 500];
        config.routing.partition_score_threshold = 0.3;
        config.session.keepalive_interval_secs = 15;
        config.session.idle_timeout_secs = 60;
        config.dht.republish_interval_secs = 600;

        let json = serde_json::to_string_pretty(&config).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();

        assert_eq!(back.routing.route_request_backoff_ms, [50, 150, 500]);
        assert!((back.routing.partition_score_threshold - 0.3).abs() < f64::EPSILON);
        assert_eq!(back.session.keepalive_interval_secs, 15);
        assert_eq!(back.session.idle_timeout_secs, 60);
        assert_eq!(back.dht.republish_interval_secs, 600);
    }
}

// ── verify defaults match old hardcoded constants ─────────────────
#[cfg(test)]
mod epic_117_defaults {
    use super::*;

    /// RoutingConfig defaults must match the constants that were removed from
    /// dispatcher/mod.rs (ROUTE_SEEN_CAPACITY, ROUTE_SEEN_WINDOW) and
    /// dispatcher/routing.rs (MAX_GOSSIP_HOPS).
    #[test]
    fn routing_defaults_match_old_hardcodes() {
        let r = RoutingConfig::default();
        assert_eq!(r.route_seen_capacity, 4096, "ROUTE_SEEN_CAPACITY was 4096");
        assert_eq!(r.route_seen_window_secs, 120, "ROUTE_SEEN_WINDOW was 120 s");
        assert_eq!(r.max_gossip_hops, 2, "MAX_GOSSIP_HOPS lowered to 2");
    }

    /// PowConfig defaults must match POW_CHALLENGE_RATE, POW_CHALLENGE_BURST
    /// POW_CHALLENGE_WINDOW removed from node/runtime.rs.
    #[test]
    fn pow_defaults_match_old_hardcodes() {
        let p = PowConfig::default();
        assert!(
            (p.challenge_rate - 1.0).abs() < f64::EPSILON,
            "POW_CHALLENGE_RATE was 1.0"
        );
        // burst lowered from 2.0 → 1.0 to prevent instant double CPU-task dispatch.
        assert!(
            (p.challenge_burst - 1.0).abs() < f64::EPSILON,
            "POW_CHALLENGE_BURST is 1.0"
        );
        assert_eq!(
            p.challenge_window_secs, 300,
            "POW_CHALLENGE_WINDOW was 300 s"
        );
    }

    /// ConnectionConfig defaults must match BACKOFF_MIN and BACKOFF_MAX
    /// removed from node/outbound_connector.rs.
    #[test]
    fn connection_defaults_match_old_hardcodes() {
        let c = ConnectionConfig::default();
        assert_eq!(
            c.reconnect_backoff_min_ms, 1_000,
            "BACKOFF_MIN was 1 s = 1000 ms"
        );
        assert_eq!(
            c.reconnect_backoff_max_ms, 300_000,
            "BACKOFF_MAX was 300 s = 300000 ms"
        );
    }

    /// DhtConfig defaults must match the constants wired into KademliaService /
    /// NetworkQuerier (k=20, alpha=3, max_rounds=20, find_node_timeout_ms=2000).
    #[test]
    fn dht_defaults_match_old_hardcodes() {
        let d = DhtConfig::default();
        assert_eq!(d.k, 20, "Kademlia k was 20");
        assert_eq!(d.alpha, 3, "Kademlia alpha was 3");
        assert_eq!(d.max_rounds, 20, "max iterative rounds was 20");
        assert_eq!(
            d.find_node_timeout_ms, 2000,
            "FIND_NODE timeout was 2000 ms"
        );
    }

    /// SessionConfig defaults must match MAX_PENDING_RESPONSES and
    /// PENDING_RESPONSE_TTL that were wired from old inline constants.
    #[test]
    fn session_defaults_match_old_hardcodes() {
        let s = SessionConfig::default();
        assert_eq!(
            s.max_pending_responses, 256,
            "MAX_PENDING_RESPONSES was 256"
        );
        assert_eq!(
            s.pending_response_ttl_ms, 30000,
            "PENDING_RESPONSE_TTL was 30 s = 30000 ms"
        );
    }

    // ── Phase 10 slice 2c: tls_ech_grease default = true ──

    /// Default is `true` after slice 2c.  Operators on TLS-1.2-only
    /// CDNs override to `false`.  Guards against accidental
    /// default-reversion in future refactors.
    #[test]
    fn etap10_slice2c_tls_ech_grease_defaults_to_true() {
        let g = GlobalConfig::default();
        assert!(
            g.tls_ech_grease,
            "slice 2c flipped the default to true; operators on TLS-1.2-only \
             CDNs override to false explicitly"
        );
    }

    /// Round-trip preserves a `false` override across serialize / deserialize.
    /// Guards against a future serde-attr regression that would silently
    /// drop the override and default back to `true`.
    #[test]
    fn etap10_slice2c_tls_ech_grease_roundtrips_when_overridden_false() {
        let g = GlobalConfig {
            tls_ech_grease: false,
            ..GlobalConfig::default()
        };
        let json = serde_json::to_string(&g).unwrap();
        let back: GlobalConfig = serde_json::from_str(&json).unwrap();
        assert!(!back.tls_ech_grease);
    }

    /// 481.4: a set `bootstrap_tor_socks_proxy` survives a round-trip
    /// (serde `skip_serializing_if = Option::is_none` must serialize a `Some`
    /// value, not silently drop it), and the default is `None`.
    #[test]
    fn epic481_4_bootstrap_tor_socks_proxy_roundtrips() {
        assert!(
            GlobalConfig::default().bootstrap_tor_socks_proxy.is_none(),
            "default must be None (opt-in)"
        );
        let g = GlobalConfig {
            bootstrap_tor_socks_proxy: Some("socks5://127.0.0.1:9050".to_owned()),
            ..GlobalConfig::default()
        };
        let json = serde_json::to_string(&g).unwrap();
        let back: GlobalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.bootstrap_tor_socks_proxy.as_deref(),
            Some("socks5://127.0.0.1:9050")
        );
    }
}
