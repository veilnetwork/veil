//! Mesh neighbour discovery via periodic beacons.
//!
//! `BeaconSender` periodically broadcasts a `MeshBeaconPayload` to the realm
//! multicast/broadcast address so that other nodes can discover this node.
//!
//! `BeaconReceiver` parses incoming beacons and adds new neighbours to the
//! `NeighborTable`.
//!
//! In the UDP backend, "broadcast" is done by sending to the configured realm
//! broadcast address (e.g. `255.255.255.255:PORT` or a multicast group).
//!
//! ## SECURITY — LAN exposure (C-03)
//!
//! A beacon carries the node's **stable `node_id`** (= `BLAKE3(long-term
//! pubkey)`, never rotates), its veil address, and — *only when the operator
//! opts in via `mesh.advertise_role_in_beacon`* — its role flags. Broadcast in
//! the clear, this lets a passive on-link observer **track the node across
//! reboots** and (if role flags are advertised) **single out gateways/relays**.
//!
//! Mitigations: mesh is opt-in (a default node never beacons), role
//! advertisement is opt-in and **off by default** (C-03), and the receiver
//! rejects unsigned beacons by default (`require_signed_beacons`, C-03).
//!
//! **Closing the node_id exposure (C-03, option A):** when a realm shares a
//! secret via `[mesh] realm_psk`, [`BeaconSender::send_once`] AEAD-seals each
//! broadcast beacon with the realm-wide key (the same key used for DATA
//! datagrams). The stable `node_id`, role flags and dial address move inside
//! the ciphertext, and a fresh random nonce per beacon makes the on-wire bytes
//! rotate (unlinkable, no static magic for DPI). The receiver opens it
//! transparently in [`crate::udp::UdpRealm::recv_frame`] before
//! [`BeaconReceiver::handle_beacon`] verifies the (still-present) signature.
//! Discovery then requires the PSK — expected for a PSK-protected realm — and
//! the format is gated on `realm_psk` (unset => plaintext beacon, unchanged).
//!
//! **Traffic-shape hardening** (also gated on `realm_psk`): a sealed beacon's
//! plaintext is zero-padded to a fixed block, so the datagram size no longer
//! leaks field presence (role/address) or the signature algorithm (see
//! [`pad_to_block`]; the seal's own random 0–256 B padding blends adjacent
//! buckets further), and its interval is jittered ±25 % so the broadcast is not
//! a clean fixed-cadence signal (see [`jittered`]). The remaining shape signal
//! is the broadcast **port**: it is operator-configurable via `[mesh]
//! beacon_addr`, but broadcast cannot rotate it per-packet (every realm member
//! must listen on the same port), so hostile-LAN deployments should set a
//! non-default port there.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use veil_util::lock;

use tokio::net::UdpSocket;

use veil_proto::mesh::{
    BROADCAST_NODE_ID, MeshBeaconPayload, MeshFrame, RealmId, beacon_role_flags,
};

/// Sink for per-peer battery-level updates surfaced from incoming beacons
///. Implemented by `veilcore::node::routing::probe::RttTable`
/// — extraction trait so this crate stays free of the routing layer.
pub trait BatterySink: Send + Sync {
    /// Record `battery_level` (0-100, or `255` for "unknown") for `peer`.
    fn update_battery(&self, peer: [u8; 32], battery_level: u8);
}

use super::{neighbor::NeighborTable, udp::UdpLink};

// ── BeaconRateLimiter ─────────────────────────────────────────────────────────

/// Maximum beacon frames accepted from a single source IP within `BEACON_WINDOW`.
pub const MAX_BEACONS_PER_IP_PER_WINDOW: u32 = 10;

/// Sliding window for beacon rate limiting.
pub const BEACON_WINDOW: Duration = Duration::from_secs(60);

/// /24 (IPv4) or /48 (IPv6) prefix used к bound а single subnet's
/// share of the rate-limiter slots. Without this, а distributed
/// /24-flood evicts legitimate gateway entries while staying under
/// the per-IP threshold.
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
enum SubnetKey {
    V4([u8; 3]),
    V6([u16; 3]),
}

impl SubnetKey {
    fn from_ip(ip: std::net::IpAddr) -> Self {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                Self::V4([o[0], o[1], o[2]])
            }
            std::net::IpAddr::V6(v6) => {
                let s = v6.segments();
                Self::V6([s[0], s[1], s[2]])
            }
        }
    }
}

/// Maximum slots per /24 (IPv4) or /48 (IPv6) — а single subnet cannot
/// occupy more than 64 of the 8192 global slots. Bounds the subnet's
/// share к ~0.8 % of the table, preventing slow-rate distributed-flood
/// eviction attacks.
const MAX_PER_SUBNET: usize = 64;

/// Global slot cap for the rate-limiter table.
const MAX_GLOBAL_SLOTS: usize = 8192;

/// Simple per-source-IP beacon flood limiter (not thread-safe; call from a
/// single owner, e.g. the UDP receive loop).
pub struct BeaconRateLimiter {
    counts: HashMap<std::net::IpAddr, (u32, Instant)>,
    per_subnet: HashMap<SubnetKey, usize>,
    max_count: u32,
    window: Duration,
}

impl BeaconRateLimiter {
    pub fn new(max_count: u32, window: Duration) -> Self {
        Self {
            counts: HashMap::new(),
            per_subnet: HashMap::new(),
            max_count,
            window,
        }
    }

    /// Returns `true` if the beacon from `addr` should be accepted.
    ///
    /// Resets the counter for `addr` once the window expires.
    pub fn allow(&mut self, addr: std::net::IpAddr) -> bool {
        let now = Instant::now();
        let subnet = SubnetKey::from_ip(addr);
        let is_new_ip = !self.counts.contains_key(&addr);
        // Per-subnet cap: prevents а /24-flood
        // от evicting legitimate gateway entries via time-based stale-eviction
        // while staying под the per-IP rate threshold. Only checked для new IPs;
        // already-tracked IPs continue working irrespective of subnet count.
        if is_new_ip {
            let subnet_count = self.per_subnet.get(&subnet).copied().unwrap_or(0);
            if subnet_count >= MAX_PER_SUBNET {
                return false;
            }
        }
        // Global cap к prevent unbounded growth from spoofed source IPs.
        if is_new_ip && self.counts.len() >= MAX_GLOBAL_SLOTS {
            self.evict_stale();
            // If still at cap after eviction, reject the newcomer.
            if self.counts.len() >= MAX_GLOBAL_SLOTS {
                return false;
            }
        }
        let entry = self.counts.entry(addr).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            *entry = (0, now); // reset window
        }
        if entry.0 >= self.max_count {
            return false;
        }
        if entry.0 == 0 && is_new_ip {
            // Fresh entry — bump subnet counter.
            *self.per_subnet.entry(subnet).or_insert(0) += 1;
        }
        entry.0 += 1;
        true
    }

    /// Evict entries whose window has fully expired (optional housekeeping).
    /// Also rebuilds the per-subnet count к stay в sync с `counts`.
    pub fn evict_stale(&mut self) {
        let now = Instant::now();
        let window = self.window;
        let mut evicted: Vec<std::net::IpAddr> = Vec::new();
        self.counts.retain(|ip, (_, t)| {
            let keep = now.duration_since(*t) < window;
            if !keep {
                evicted.push(*ip);
            }
            keep
        });
        for ip in evicted {
            let subnet = SubnetKey::from_ip(ip);
            if let Some(c) = self.per_subnet.get_mut(&subnet) {
                if *c <= 1 {
                    self.per_subnet.remove(&subnet);
                } else {
                    *c -= 1;
                }
            }
        }
    }
}

/// Default beacon interval.
pub const DEFAULT_BEACON_INTERVAL: Duration = Duration::from_secs(10);

/// C-03 traffic-shape: a **sealed** beacon's plaintext is zero-padded up to the
/// next multiple of this block before sealing, so the datagram size cannot leak
/// field presence (role/addr) or the signature algorithm. The seal's own random
/// padding (0–256 B) blends adjacent buckets further. Plaintext beacons are not
/// padded (their content is already exposed).
const BEACON_PAD_BLOCK: usize = 256;

/// C-03 traffic-shape: a **sealed** beacon's interval is jittered by up to ±this
/// fraction per tick so the broadcast is not a clean fixed-period signal.
const BEACON_INTERVAL_JITTER: f64 = 0.25;

/// Zero-pad `buf` up to the next multiple of `block` (no-op if already aligned
/// or `block == 0`). The padding rides inside the AEAD seal, so it is opaque on
/// the wire and zero bytes suffice; [`MeshBeaconPayload::decode`] ignores the
/// trailing bytes.
fn pad_to_block(buf: &mut Vec<u8>, block: usize) {
    if block == 0 {
        return;
    }
    let rem = buf.len() % block;
    if rem != 0 {
        buf.resize(buf.len() + (block - rem), 0);
    }
}

/// Return `base` scaled by a random factor in `[1 - jitter, 1 + jitter]`
/// (clamped non-negative).
fn jittered(base: Duration, jitter: f64) -> Duration {
    let factor = 1.0 + (rand::random::<f64>() * 2.0 - 1.0) * jitter;
    base.mul_f64(factor.max(0.0))
}

// ── AutoDiscoveredPeers ───────────────────────────────────────────────────────

/// Maximum number of gateways tracked simultaneously in `AutoDiscoveredPeers`.
///
/// When the table is full and a new gateway is discovered, the oldest-seen
/// entry (largest `last_seen` gap) is evicted.
pub const MAX_AUTODISCOVERED_GATEWAYS: usize = 8;

/// TTL for auto-discovered gateway entries. Re-announced beacons refresh the
/// entry; silent gateways are dropped after this duration.
pub const AUTODISCOVER_TTL: Duration = Duration::from_secs(60);

/// One entry in `AutoDiscoveredPeers`.
#[derive(Debug, Clone)]
pub struct AutoDiscoveredGateway {
    pub node_id: [u8; 32],
    /// Veil dial address advertised in the beacon (e.g. `"tcp://…"`).
    pub veil_addr: String,
    /// Raw `role_flags` from the beacon (see `beacon_role_flags`).
    pub role_flags: u8,
    /// When the beacon was last seen (used for LRU eviction).
    pub last_seen: Instant,
    /// When this entry expires.
    pub expires_at: Instant,
}

/// Thread-safe table of Gateway nodes discovered via mesh beacons.
///
/// Capped at `MAX_AUTODISCOVERED_GATEWAYS` entries. Evicts the
/// least-recently-seen entry when at capacity.
#[derive(Debug, Default)]
pub struct AutoDiscoveredPeers {
    inner: Mutex<AutoDiscoveredPeersInner>,
}

#[derive(Debug, Default)]
struct AutoDiscoveredPeersInner {
    entries: HashMap<[u8; 32], AutoDiscoveredGateway>,
}

/// Serialisable snapshot of one autodiscovered gateway entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AutoDiscoveredSnapshot {
    #[serde(with = "veil_proto::serde_base64::hex_array")]
    pub node_id: [u8; 32],
    pub veil_addr: String,
    pub role_flags: u8,
}

impl AutoDiscoveredPeers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return all live entries as a snapshot for persistence.
    pub fn snapshot(&self) -> Vec<AutoDiscoveredSnapshot> {
        let now = Instant::now();
        lock!(self.inner)
            .entries
            .values()
            .filter(|e| e.expires_at > now)
            .map(|e| AutoDiscoveredSnapshot {
                node_id: e.node_id,
                veil_addr: e.veil_addr.clone(),
                role_flags: e.role_flags,
            })
            .collect()
    }

    /// Restore entries from a persisted snapshot.
    ///
    /// Restored entries have halved TTL (`AUTODISCOVER_TTL / 2`) so they will
    /// be refreshed or evicted sooner than freshly-discovered entries.
    pub fn restore(&self, entries: Vec<AutoDiscoveredSnapshot>) {
        let ttl = AUTODISCOVER_TTL / 2;
        let now = Instant::now();
        let mut g = lock!(self.inner);
        for e in entries {
            g.entries
                .entry(e.node_id)
                .or_insert_with(|| AutoDiscoveredGateway {
                    node_id: e.node_id,
                    veil_addr: e.veil_addr,
                    role_flags: e.role_flags,
                    last_seen: now,
                    expires_at: now + ttl,
                });
        }
    }

    /// Record or refresh a gateway discovery from a beacon.
    ///
    /// * If the node_id is already known, its TTL and `last_seen` are refreshed.
    /// * If the table is at capacity, the least-recently-seen entry is evicted.
    pub fn upsert(&self, node_id: [u8; 32], veil_addr: String, role_flags: u8) {
        let now = Instant::now();
        let mut g = lock!(self.inner);
        if let Some(e) = g.entries.get_mut(&node_id) {
            // Refresh existing.
            e.veil_addr = veil_addr;
            e.role_flags = role_flags;
            e.last_seen = now;
            e.expires_at = now + AUTODISCOVER_TTL;
            return;
        }
        // Evict LRS entry if at capacity.
        if g.entries.len() >= MAX_AUTODISCOVERED_GATEWAYS {
            let lrs_key = g
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(k, _)| *k);
            if let Some(k) = lrs_key {
                g.entries.remove(&k);
            }
        }
        g.entries.insert(
            node_id,
            AutoDiscoveredGateway {
                node_id,
                veil_addr,
                role_flags,
                last_seen: now,
                expires_at: now + AUTODISCOVER_TTL,
            },
        );
    }

    /// Remove all expired entries.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        lock!(self.inner).entries.retain(|_, e| e.expires_at > now);
    }

    /// Return a snapshot of all non-expired gateway entries.
    pub fn live_gateways(&self) -> Vec<AutoDiscoveredGateway> {
        let now = Instant::now();
        lock!(self.inner)
            .entries
            .values()
            .filter(|e| e.expires_at > now)
            .cloned()
            .collect()
    }

    /// True if `node_id` is currently tracked (and not expired).
    pub fn contains(&self, node_id: &[u8; 32]) -> bool {
        let now = Instant::now();
        lock!(self.inner)
            .entries
            .get(node_id)
            .map(|e| e.expires_at > now)
            .unwrap_or(false)
    }
}

// ── Battery level ────────────────────────────────────────────────────────────

/// Read the current battery charge level.
///
/// Returns 0 (unknown / AC power) on platforms where reading is not supported
/// or when the device is on AC power. Returns 1–100 on battery-powered devices.
///
/// Linux: reads `/sys/class/power_supply/*/capacity` after confirming the supply
/// is not online (plugged in to AC). Takes the minimum capacity across all
/// battery supplies so we report the weakest cell.
fn read_battery_level() -> u8 {
    #[cfg(target_os = "linux")]
    {
        read_battery_level_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(target_os = "linux")]
fn read_battery_level_linux() -> u8 {
    use std::fs;
    use std::path::Path;

    let power_supply = Path::new("/sys/class/power_supply");
    let entries = match fs::read_dir(power_supply) {
        Ok(e) => e,
        Err(_) => return 0,
    };

    let mut min_level: Option<u8> = None;

    for entry in entries.flatten() {
        let path = entry.path();
        // Only consider entries that look like batteries (type == "Battery").
        let type_path = path.join("type");
        let supply_type = fs::read_to_string(&type_path).unwrap_or_default();
        if supply_type.trim() != "Battery" {
            continue;
        }
        // If the battery is online (charging via AC), treat as AC power.
        let status_path = path.join("status");
        let status = fs::read_to_string(&status_path).unwrap_or_default();
        let status = status.trim();
        // "Full" or "Charging" → AC attached; skip this supply.
        if status == "Full" || status == "Charging" {
            // This battery is on AC — skip it, check the remaining ones.
            // A system may have multiple batteries; only treat as AC if ALL are charging.
            continue;
        }
        // Read capacity (0–100).
        let cap_path = path.join("capacity");
        if let Ok(s) = fs::read_to_string(&cap_path)
            && let Ok(v) = s.trim().parse::<u8>()
        {
            min_level = Some(match min_level {
                Some(prev) => prev.min(v),
                None => v,
            });
        }
    }

    // Clamp to 1–100 range (0 is reserved for "unknown/AC").
    min_level.map(|v| v.max(1)).unwrap_or(0)
}

// ── BeaconSender ─────────────────────────────────────────────────────────────

/// Sends periodic beacons to `broadcast_addr`.
///
/// The beacon payload is a `MeshFrame` with `dst_node_id = BROADCAST_NODE_ID`
/// and payload = `MeshBeaconPayload::encode`.
pub struct BeaconSender {
    realm_id: RealmId,
    local_node_id: [u8; 32],
    broadcast_addr: SocketAddr,
    socket: UdpSocket,
    interval: Duration,
    /// Role flags to advertise in the beacon.
    role_flags: u8,
    /// Veil dial address to advertise (e.g. `"tcp://1.2.3.4:9000"`).
    veil_addr: Option<String>,
    /// signing parameters for authenticated beacons.
    algo: u8,
    public_key: Vec<u8>,
    private_key_b64: String,
    public_key_b64: String,
    /// Realm-wide obfuscation key (opt-in via `realm_psk`). When `Some`, every
    /// broadcast beacon is AEAD-sealed (C-03): the stable `node_id`, role flags
    /// and dial address are moved inside the ciphertext, and the on-wire bytes
    /// rotate per beacon (fresh random nonce → unlinkable, no static magic).
    /// `None` => plaintext beacon, unchanged legacy behaviour.
    obfs: Option<Arc<veil_udp_obfs::ObfsKey>>,
    /// Per-sender AEAD counter for `seal_datagram`. The 16-byte random nonce
    /// prefix already guarantees nonce uniqueness; this is the documented
    /// secondary input. Unused when `obfs` is `None`.
    obfs_counter: AtomicU64,
}

impl BeaconSender {
    pub async fn new(
        realm_id: RealmId,
        local_node_id: [u8; 32],
        broadcast_addr: SocketAddr,
        bind_addr: SocketAddr,
        interval: Duration,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        Ok(Self {
            realm_id,
            local_node_id,
            broadcast_addr,
            socket,
            interval,
            role_flags: 0,
            veil_addr: None,
            algo: 0,
            public_key: vec![],
            private_key_b64: String::new(),
            public_key_b64: String::new(),
            obfs: None,
            obfs_counter: AtomicU64::new(0),
        })
    }

    /// Attach the realm-wide obfuscation key so broadcast beacons are
    /// AEAD-sealed (C-03). `None` keeps plaintext beacons (legacy).
    #[must_use]
    pub fn with_obfs(mut self, obfs: Option<Arc<veil_udp_obfs::ObfsKey>>) -> Self {
        self.obfs = obfs;
        self
    }

    /// set signing key for authenticated beacons.
    pub fn set_signing_key(
        mut self,
        algo: veil_types::SignatureAlgorithm,
        public_key_b64: String,
        private_key_b64: String,
    ) -> Self {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        self.algo = match algo {
            veil_types::SignatureAlgorithm::Falcon512 => 2,
            _ => 0,
        };
        self.public_key = STANDARD.decode(&public_key_b64).unwrap_or_default();
        self.public_key_b64 = public_key_b64;
        self.private_key_b64 = private_key_b64;
        self
    }

    /// Set the role flags and veil address advertised in beacons.
    pub fn set_role(mut self, role_flags: u8, veil_addr: Option<String>) -> Self {
        self.role_flags = role_flags;
        self.veil_addr = veil_addr;
        self
    }

    fn make_beacon_frame(&self) -> MeshFrame {
        let mut beacon = MeshBeaconPayload {
            node_id: self.local_node_id,
            realm_id: self.realm_id,
            role_flags: self.role_flags,
            veil_addr: self.veil_addr.clone(),
            battery_level: read_battery_level(),
            algo: self.algo,
            public_key: self.public_key.clone(),
            signature: vec![],
        };
        // sign the beacon body.
        if !self.public_key.is_empty() {
            let algo = if self.algo == 2 {
                veil_types::SignatureAlgorithm::Falcon512
            } else {
                veil_types::SignatureAlgorithm::Ed25519
            };
            let body = beacon.signable_body();
            beacon.signature =
                veil_crypto::sign_message(algo, &self.public_key_b64, &self.private_key_b64, &body)
                    .unwrap_or_default();
        }
        let mut payload_bytes = beacon.encode();
        // C-03 traffic-shape: pad sealed beacons to a fixed block so the
        // datagram size does not leak field presence (role/addr) or the
        // signature algorithm. Plaintext beacons are left unpadded.
        if self.obfs.is_some() {
            pad_to_block(&mut payload_bytes, BEACON_PAD_BLOCK);
        }
        MeshFrame::new(
            self.realm_id,
            self.local_node_id,
            BROADCAST_NODE_ID,
            1, // beacons do not get forwarded
            payload_bytes,
        )
    }

    /// Send one beacon immediately.
    ///
    /// With a realm `obfs` key (opt-in `realm_psk`, C-03) the encoded beacon is
    /// AEAD-sealed before broadcast so a passive LAN observer sees only rotating
    /// ciphertext instead of the stable `node_id` + role + dial address. The
    /// receiver opens it transparently via `UdpRealm::recv_frame`. Without a key
    /// the beacon goes out in cleartext (unchanged legacy behaviour).
    pub async fn send_once(&self) -> std::io::Result<()> {
        let frame = self.make_beacon_frame();
        let encoded = frame.encode();
        let out = match &self.obfs {
            Some(key) => {
                let counter = self.obfs_counter.fetch_add(1, Ordering::Relaxed);
                match veil_udp_obfs::seal_datagram(key, counter, &encoded) {
                    Ok(sealed) => sealed,
                    Err(e) => {
                        // A beacon too large to wrap is dropped rather than sent
                        // in the clear (sending plaintext would defeat C-03).
                        log::warn!("veil-mesh: beacon obfs seal failed, dropping: {e}");
                        return Ok(());
                    }
                }
            }
            None => encoded,
        };
        self.socket.send_to(&out, self.broadcast_addr).await?;
        Ok(())
    }

    /// Run beacon loop until cancelled via `shutdown_rx`.
    pub async fn run(self, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
        loop {
            // C-03 traffic-shape: jitter the period for SEALED beacons so a
            // passive observer cannot fingerprint a clean fixed-cadence signal.
            // Plaintext realms keep the exact configured interval (unchanged).
            let delay = if self.obfs.is_some() {
                jittered(self.interval, BEACON_INTERVAL_JITTER)
            } else {
                self.interval
            };
            tokio::select! {
                _ = tokio::time::sleep(delay) => {
                    let _ = self.send_once().await;
                }
                Ok(_) = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
            }
        }
    }
}

// ── BeaconReceiver ────────────────────────────────────────────────────────────

/// Parses incoming beacons and registers new neighbours.
///
/// Includes an internal `BeaconRateLimiter` to reject beacon floods from a
/// single source IP (default: `MAX_BEACONS_PER_IP_PER_WINDOW` per minute).
///
/// When an `AutoDiscoveredPeers` table is provided via
/// [`BeaconReceiver::with_autodiscovery`], beacons from nodes that advertise
/// `IS_GATEWAY` are additionally recorded there so the runtime can initiate
/// outbound sessions to them.
pub struct BeaconReceiver {
    realm_id: RealmId,
    neighbors: NeighborTable,
    std_socket: Arc<std::net::UdpSocket>,
    /// Realm-wide obfuscation key (opt-in via `realm_psk`), threaded from
    /// [`crate::udp::UdpRealm`] so neighbor links created from incoming beacons
    /// AEAD-seal their DATA frames. `None` => plaintext links (unchanged).
    obfs: Option<Arc<veil_udp_obfs::ObfsKey>>,
    rate_limiter: BeaconRateLimiter,
    /// Optional autodiscovery table for IS_GATEWAY beacons.
    autodiscovered: Option<Arc<AutoDiscoveredPeers>>,
    /// When `true`, ignore IS_GATEWAY beacons (autodiscovery disabled).
    autodiscover_disabled: bool,
    /// Optional RTT table for recording battery levels from beacons.
    rtt_table: Option<Arc<dyn BatterySink>>,
    /// SECURITY (audit 2026-05-29, A5): when `true`, drop beacons that
    /// carry no signature instead of accepting them as "legacy".  An
    /// unsigned beacon lets an on-link attacker register/redirect
    /// neighbor links and inject IS_GATEWAY entries.  Default `false`
    /// preserves the legacy unsigned-beacon interop for existing
    /// deployments; operators on hostile LANs flip
    /// `[mesh] require_signed_beacons = true` to harden.
    require_signed: bool,
    /// Per-source deduplication window.
    ///
    /// Maps `source node_id → last_accepted Instant`. A beacon from a source
    /// seen within `dedup_window` of its previous accepted beacon is dropped.
    /// `Duration::ZERO` disables deduplication.
    dedup_seen: std::collections::HashMap<[u8; 32], std::time::Instant>,
    dedup_window: std::time::Duration,
    /// Beacon counter for amortised rate-limiter housekeeping.
    ///
    /// `BeaconRateLimiter::evict_stale` is called every 256 beacons so the
    /// `counts` HashMap cannot grow unboundedly under a flood of unique source IPs.
    beacon_count: u8,
}

impl BeaconReceiver {
    pub fn new(
        realm_id: RealmId,
        neighbors: NeighborTable,
        std_socket: Arc<std::net::UdpSocket>,
        obfs: Option<Arc<veil_udp_obfs::ObfsKey>>,
    ) -> Self {
        Self {
            realm_id,
            neighbors,
            std_socket,
            obfs,
            rate_limiter: BeaconRateLimiter::new(MAX_BEACONS_PER_IP_PER_WINDOW, BEACON_WINDOW),
            autodiscovered: None,
            autodiscover_disabled: false,
            rtt_table: None,
            dedup_seen: std::collections::HashMap::new(),
            dedup_window: std::time::Duration::from_secs(3), // default 3 s
            beacon_count: 0,
            require_signed: false,
        }
    }

    /// SECURITY (audit 2026-05-29, A5): require every accepted beacon к
    /// carry а valid signature.  When enabled, unsigned beacons are
    /// dropped (logged at `warn`) rather than accepted as "legacy".
    /// Recommended on for non-loopback realms; off by default for
    /// back-compat с existing unsigned-beacon deployments.
    #[must_use]
    pub fn with_require_signed(mut self, require: bool) -> Self {
        self.require_signed = require;
        self
    }

    /// Attach an `AutoDiscoveredPeers` table; IS_GATEWAY beacons will be
    /// recorded there.
    pub fn with_autodiscovery(mut self, peers: Arc<AutoDiscoveredPeers>) -> Self {
        self.autodiscovered = Some(peers);
        self
    }

    /// Disable gateway autodiscovery even if an `AutoDiscoveredPeers` table is set.
    pub fn disable_autodiscovery(mut self) -> Self {
        self.autodiscover_disabled = true;
        self
    }

    /// Attach an RTT table so battery levels from beacons are recorded.
    pub fn with_rtt_table(mut self, rtt_table: Arc<dyn BatterySink>) -> Self {
        self.rtt_table = Some(rtt_table);
        self
    }

    /// Set the per-source deduplication window.
    ///
    /// Beacons from the same `node_id` arriving within `window` of the
    /// previously accepted beacon are silently dropped. Pass
    /// `Duration::ZERO` to disable deduplication entirely.
    pub fn with_dedup_window(mut self, window: std::time::Duration) -> Self {
        self.dedup_window = window;
        self
    }

    /// Process one incoming beacon frame.
    ///
    /// Returns `false` if the beacon was silently dropped (wrong realm, rate
    /// limit exceeded, or neighbor table full). Returns `true` on acceptance.
    pub fn handle_beacon(&mut self, frame: &MeshFrame, sender_addr: SocketAddr) -> bool {
        if frame.realm_id != self.realm_id {
            return false;
        }
        // Amortised housekeeping: evict stale rate-limiter entries every 256 beacons
        // so the IP→counter map cannot grow unboundedly under unique-source floods.
        self.beacon_count = self.beacon_count.wrapping_add(1);
        if self.beacon_count == 0 {
            self.rate_limiter.evict_stale();
        }
        // Rate-limit per source IP.
        if !self.rate_limiter.allow(sender_addr.ip()) {
            return false;
        }
        let beacon = match MeshBeaconPayload::decode(&frame.payload) {
            Ok(b) => b,
            Err(e) => {
                log::debug!("mesh.beacon: decode error from {sender_addr}: {e}");
                return false;
            }
        };

        // verify beacon signature.
        if beacon.is_signed() {
            if !crate::auth::verify_mesh_beacon_auth(&beacon) {
                log::warn!("mesh.beacon: invalid signature from {sender_addr} — possible spoofing");
                return false;
            }
        } else if self.require_signed {
            // SECURITY (audit 2026-05-29, A5): in require-signed mode an
            // unsigned beacon is dropped, not accepted as legacy — an
            // on-link attacker must not be able к register/redirect
            // neighbor links или inject IS_GATEWAY entries без а key.
            log::warn!(
                "mesh.beacon: unsigned beacon from {sender_addr} dropped \
                 (require_signed_beacons=true)"
            );
            return false;
        } else {
            log::debug!("mesh.beacon: unsigned beacon from {sender_addr} — accepted (legacy)");
        }

        // per-source deduplication window.
        if !self.dedup_window.is_zero() {
            let now = std::time::Instant::now();
            if let Some(&last) = self.dedup_seen.get(&beacon.node_id)
                && now.duration_since(last) < self.dedup_window
            {
                return false; // duplicate within window — drop
            }
            // Accept: record timestamp and GC stale entries.
            //
            // Eviction strategy (two-phase, no full clear):
            // 1. Always remove entries older than 2× dedup_window (expired).
            // 2. If still at cap after TTL eviction, evict the single oldest
            // entry by min Instant — O(n) scan but only runs when full
            // which is rare under normal beacon rates. Avoids the previous
            // `.clear` that discarded all dedup state and caused a brief
            // flood of previously-seen beacons to be re-accepted.
            self.dedup_seen
                .retain(|_, &mut t| now.duration_since(t) < self.dedup_window * 2);
            if self.dedup_seen.len() >= veil_proto::budget::MAX_BEACON_DEDUP_ENTRIES {
                // Evict oldest entry instead of clearing all state.
                if let Some(oldest_id) = self
                    .dedup_seen
                    .iter()
                    .min_by_key(|&(_, t)| *t)
                    .map(|(&id, _)| id)
                {
                    self.dedup_seen.remove(&oldest_id);
                }
            }
            self.dedup_seen.insert(beacon.node_id, now);
        }

        // update battery level in the RTT table.
        if let Some(ref rtt) = self.rtt_table {
            rtt.update_battery(beacon.node_id, beacon.battery_level);
        }

        // record IS_GATEWAY beacons in the autodiscovery table.
        if !self.autodiscover_disabled
            && beacon.role_flags & beacon_role_flags::IS_GATEWAY != 0
            && let (Some(peers), Some(addr)) =
                (self.autodiscovered.as_ref(), beacon.veil_addr.as_ref())
        {
            peers.upsert(beacon.node_id, addr.clone(), beacon.role_flags);
        }

        // Always (re-)register the link — if the neighbor already exists this
        // updates the source address (handles NAT rebind). If new, it adds them.
        self.neighbors.remove(&beacon.node_id);
        let link = UdpLink::new(
            beacon.node_id,
            sender_addr,
            Arc::clone(&self.std_socket),
            self.obfs.clone(),
        );
        self.neighbors.add(beacon.node_id, Arc::new(link))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighbor::MeshNeighborProvider;
    use veil_proto::mesh::{MeshBeaconPayload, RealmId};

    #[test]
    fn beacon_frame_encode_decode() {
        let realm_id = RealmId([0x77; 16]);
        let node_id = [5u8; 32];
        let beacon = MeshBeaconPayload::new_basic(node_id, realm_id);
        let encoded = beacon.encode();
        let decoded = MeshBeaconPayload::decode(&encoded).unwrap();
        assert_eq!(decoded.node_id, node_id);
        assert_eq!(decoded.realm_id, realm_id);
    }

    #[test]
    fn beacon_receiver_ignores_wrong_realm() {
        use crate::neighbor::NeighborTable;
        let table = NeighborTable::new();
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut receiver =
            BeaconReceiver::new(RealmId([1u8; 16]), table.clone(), Arc::new(std_sock), None);
        let frame = MeshFrame::new(
            RealmId([2u8; 16]), // wrong realm
            [1u8; 32],
            BROADCAST_NODE_ID,
            1,
            MeshBeaconPayload::new_basic([1u8; 32], RealmId([2u8; 16])).encode(),
        );
        receiver.handle_beacon(&frame, "127.0.0.1:9999".parse().unwrap());
        assert_eq!(table.len(), 0); // not added
    }

    #[test]
    fn beacon_receiver_adds_new_neighbor() {
        use crate::neighbor::NeighborTable;
        let table = NeighborTable::new();
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut receiver =
            BeaconReceiver::new(RealmId([1u8; 16]), table.clone(), Arc::new(std_sock), None);
        let frame = MeshFrame::new(
            RealmId([1u8; 16]),
            [9u8; 32],
            BROADCAST_NODE_ID,
            1,
            MeshBeaconPayload::new_basic([9u8; 32], RealmId([1u8; 16])).encode(),
        );
        receiver.handle_beacon(&frame, "127.0.0.1:5555".parse().unwrap());
        assert_eq!(table.len(), 1);
        assert!(table.link_to(&[9u8; 32]).is_some());
    }

    /// SECURITY (audit 2026-05-29, A5 regression): in require-signed
    /// mode an unsigned beacon MUST be dropped (no neighbor added),
    /// whereas the default (legacy) mode still accepts it.
    #[test]
    fn beacon_receiver_require_signed_drops_unsigned() {
        use crate::neighbor::NeighborTable;
        let table = NeighborTable::new();
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut receiver =
            BeaconReceiver::new(RealmId([1u8; 16]), table.clone(), Arc::new(std_sock), None)
                .with_require_signed(true);
        // new_basic produces an UNSIGNED beacon.
        let frame = MeshFrame::new(
            RealmId([1u8; 16]),
            [9u8; 32],
            BROADCAST_NODE_ID,
            1,
            MeshBeaconPayload::new_basic([9u8; 32], RealmId([1u8; 16])).encode(),
        );
        let accepted = receiver.handle_beacon(&frame, "127.0.0.1:5555".parse().unwrap());
        assert!(
            !accepted,
            "unsigned beacon must be dropped in require_signed mode"
        );
        assert_eq!(
            table.len(),
            0,
            "no neighbor registered from an unsigned beacon"
        );
    }

    /// Default (legacy) mode still accepts unsigned beacons — guards
    /// against accidentally flipping the default-off back-compat.
    #[test]
    fn beacon_receiver_default_accepts_unsigned_legacy() {
        use crate::neighbor::NeighborTable;
        let table = NeighborTable::new();
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut receiver =
            BeaconReceiver::new(RealmId([1u8; 16]), table.clone(), Arc::new(std_sock), None);
        let frame = MeshFrame::new(
            RealmId([1u8; 16]),
            [9u8; 32],
            BROADCAST_NODE_ID,
            1,
            MeshBeaconPayload::new_basic([9u8; 32], RealmId([1u8; 16])).encode(),
        );
        assert!(receiver.handle_beacon(&frame, "127.0.0.1:5555".parse().unwrap()));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn beacon_receiver_does_not_duplicate() {
        use crate::neighbor::NeighborTable;
        let table = NeighborTable::new();
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut receiver =
            BeaconReceiver::new(RealmId([1u8; 16]), table.clone(), Arc::new(std_sock), None);
        let frame = MeshFrame::new(
            RealmId([1u8; 16]),
            [7u8; 32],
            BROADCAST_NODE_ID,
            1,
            MeshBeaconPayload::new_basic([7u8; 32], RealmId([1u8; 16])).encode(),
        );
        receiver.handle_beacon(&frame, "127.0.0.1:6666".parse().unwrap());
        receiver.handle_beacon(&frame, "127.0.0.1:6666".parse().unwrap());
        assert_eq!(table.len(), 1); // not doubled
    }

    // ── BeaconRateLimiter tests ───────────────────────────────────────────────

    #[test]
    fn rate_limiter_allows_up_to_limit() {
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let mut limiter = BeaconRateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip), "4th should be denied");
    }

    #[test]
    fn rate_limiter_independent_ips() {
        let ip1: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: std::net::IpAddr = "10.0.0.2".parse().unwrap();
        let mut limiter = BeaconRateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.allow(ip1));
        assert!(!limiter.allow(ip1), "ip1 over limit");
        assert!(limiter.allow(ip2), "ip2 has its own quota");
    }

    #[test]
    fn beacon_receiver_drops_flood() {
        use crate::neighbor::NeighborTable;
        let table = NeighborTable::new();
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut receiver =
            BeaconReceiver::new(RealmId([1u8; 16]), table.clone(), Arc::new(std_sock), None);
        // Rate limit is MAX_BEACONS_PER_IP_PER_WINDOW = 10 per minute.
        // Send 10+1 beacons from different node_ids (same sender IP).
        let sender: SocketAddr = "127.0.0.1:7777".parse().unwrap();
        let mut accepted = 0u32;
        for i in 0..=MAX_BEACONS_PER_IP_PER_WINDOW {
            let mut node_id = [0u8; 32];
            node_id[0] = i as u8;
            let frame = MeshFrame::new(
                RealmId([1u8; 16]),
                node_id,
                BROADCAST_NODE_ID,
                1,
                MeshBeaconPayload::new_basic(node_id, RealmId([1u8; 16])).encode(),
            );
            if receiver.handle_beacon(&frame, sender) {
                accepted += 1;
            }
        }
        assert_eq!(
            accepted, MAX_BEACONS_PER_IP_PER_WINDOW,
            "exactly the rate limit should be accepted"
        );
    }

    // ── beacon deduplication window ─────────────────────────────

    /// Second beacon from the same source within the dedup window is dropped.
    #[test]
    fn dedup_drops_beacon_within_window() {
        use crate::neighbor::NeighborTable;
        let realm = RealmId([1u8; 16]);
        let node_id = [0xDDu8; 32];
        let table = NeighborTable::new();
        let std_sock = Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());

        let mut receiver = BeaconReceiver::new(realm, table.clone(), std_sock, None)
            .with_dedup_window(std::time::Duration::from_secs(60)); // long window

        let frame = MeshFrame::new(
            realm,
            node_id,
            BROADCAST_NODE_ID,
            1,
            MeshBeaconPayload::new_basic(node_id, realm).encode(),
        );
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();

        // First beacon: accepted.
        assert!(
            receiver.handle_beacon(&frame, addr),
            "first beacon must be accepted"
        );
        // Second beacon within window: dropped.
        assert!(
            !receiver.handle_beacon(&frame, addr),
            "duplicate within window must be dropped"
        );
    }

    // ── AutoDiscoveredPeers snapshot / restore ─────────────────────

    /// snapshot returns all live (non-expired) entries.
    #[test]
    fn snapshot_returns_live_entries() {
        let peers = AutoDiscoveredPeers::new();
        let id_a = [0x01u8; 32];
        let id_b = [0x02u8; 32];
        peers.upsert(id_a, "tcp://1.2.3.4:9000".into(), 0x01);
        peers.upsert(id_b, "tcp://5.6.7.8:9000".into(), 0x02);
        let snap = peers.snapshot();
        assert_eq!(snap.len(), 2);
        let has_a = snap
            .iter()
            .any(|s| s.node_id == id_a && s.veil_addr == "tcp://1.2.3.4:9000");
        let has_b = snap.iter().any(|s| s.node_id == id_b);
        assert!(has_a);
        assert!(has_b);
    }

    /// restore inserts entries that are not already present.
    #[test]
    fn restore_inserts_missing_entries() {
        let peers = AutoDiscoveredPeers::new();
        let id = [0xAAu8; 32];
        let snap = vec![AutoDiscoveredSnapshot {
            node_id: id,
            veil_addr: "tcp://10.0.0.1:9000".into(),
            role_flags: 0x03,
        }];
        peers.restore(snap);
        assert!(peers.contains(&id));
        let live = peers.live_gateways();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].veil_addr, "tcp://10.0.0.1:9000");
        assert_eq!(live[0].role_flags, 0x03);
    }

    /// restore does not overwrite existing entries.
    #[test]
    fn restore_does_not_overwrite_existing() {
        let peers = AutoDiscoveredPeers::new();
        let id = [0xBBu8; 32];
        peers.upsert(id, "tcp://original:9000".into(), 0x01);
        let snap = vec![AutoDiscoveredSnapshot {
            node_id: id,
            veil_addr: "tcp://restored:9000".into(),
            role_flags: 0xFF,
        }];
        peers.restore(snap);
        let live = peers.live_gateways();
        assert_eq!(live.len(), 1);
        assert_eq!(
            live[0].veil_addr, "tcp://original:9000",
            "existing entry must not be overwritten by restore"
        );
    }

    /// AutoDiscoveredSnapshot JSON roundtrip preserves all fields.
    #[test]
    fn snapshot_json_roundtrip() {
        let peers = AutoDiscoveredPeers::new();
        let id = [0xCCu8; 32];
        peers.upsert(id, "tcp://127.0.0.1:9001".into(), 0x05);
        let snap = peers.snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        let decoded: Vec<AutoDiscoveredSnapshot> =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].node_id, id);
        assert_eq!(decoded[0].veil_addr, "tcp://127.0.0.1:9001");
        assert_eq!(decoded[0].role_flags, 0x05);
    }

    /// With dedup disabled (window = 0), all beacons from the same source pass.
    #[test]
    fn dedup_disabled_passes_all_beacons() {
        use crate::neighbor::NeighborTable;
        let realm = RealmId([1u8; 16]);
        let node_id = [0xEEu8; 32];
        let table = NeighborTable::new();
        let std_sock = Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());

        let mut receiver = BeaconReceiver::new(realm, table.clone(), std_sock, None)
            .with_dedup_window(std::time::Duration::ZERO); // disabled

        let frame = MeshFrame::new(
            realm,
            node_id,
            BROADCAST_NODE_ID,
            1,
            MeshBeaconPayload::new_basic(node_id, realm).encode(),
        );
        let addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();

        // Both beacons processed (neighbor table only adds once, but handle_beacon returns true).
        assert!(receiver.handle_beacon(&frame, addr));
        // Second call returns false because neighbor already in table — but not because of dedup.
        // (The neighbor table add returns false for a duplicate, so handle_beacon returns false here.)
        // We just check that the dedup map is empty.
        assert!(
            receiver.dedup_seen.is_empty(),
            "dedup map must remain empty when dedup is disabled"
        );
    }

    // ── C-03 traffic-shape helpers ───────────────────────────────────────────

    #[test]
    fn pad_to_block_quantises_size() {
        // Already aligned → unchanged.
        let mut a = vec![0u8; BEACON_PAD_BLOCK];
        pad_to_block(&mut a, BEACON_PAD_BLOCK);
        assert_eq!(a.len(), BEACON_PAD_BLOCK);

        // Various sub-block lengths all round up to exactly one block.
        for len in [1usize, 7, 100, BEACON_PAD_BLOCK - 1] {
            let mut b = vec![0xAB; len];
            pad_to_block(&mut b, BEACON_PAD_BLOCK);
            assert_eq!(
                b.len(),
                BEACON_PAD_BLOCK,
                "len {len} should pad to one block"
            );
            assert_eq!(b.len() % BEACON_PAD_BLOCK, 0);
            // The original bytes are preserved (only zero padding appended).
            assert!(b[..len].iter().all(|&x| x == 0xAB));
            assert!(b[len..].iter().all(|&x| x == 0));
        }

        // Just over a block → two blocks.
        let mut c = vec![0u8; BEACON_PAD_BLOCK + 1];
        pad_to_block(&mut c, BEACON_PAD_BLOCK);
        assert_eq!(c.len(), 2 * BEACON_PAD_BLOCK);

        // block == 0 is a no-op (no panic).
        let mut d = vec![0u8; 5];
        pad_to_block(&mut d, 0);
        assert_eq!(d.len(), 5);
    }

    /// Two beacons with **different** content (one advertises a role + address,
    /// the other does not) produce the **same** padded plaintext size — the
    /// field-presence signal the size would otherwise leak is hidden.
    #[test]
    fn padding_hides_field_presence() {
        let bare = MeshBeaconPayload::new_basic([1u8; 32], RealmId([2u8; 16]));
        let mut rich = MeshBeaconPayload::new_basic([1u8; 32], RealmId([2u8; 16]));
        rich.role_flags = beacon_role_flags::IS_GATEWAY;
        rich.veil_addr = Some("tcp://203.0.113.7:9000".to_owned());

        let mut a = bare.encode();
        let mut b = rich.encode();
        assert_ne!(a.len(), b.len(), "unpadded sizes differ (the leak)");
        pad_to_block(&mut a, BEACON_PAD_BLOCK);
        pad_to_block(&mut b, BEACON_PAD_BLOCK);
        assert_eq!(
            a.len(),
            b.len(),
            "padded sizes must match (no field-presence leak)"
        );
    }

    #[test]
    fn jittered_stays_in_bounds_and_varies() {
        let base = Duration::from_secs(10);
        let lo = base.mul_f64(1.0 - BEACON_INTERVAL_JITTER);
        let hi = base.mul_f64(1.0 + BEACON_INTERVAL_JITTER);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let d = jittered(base, BEACON_INTERVAL_JITTER);
            assert!(d >= lo && d <= hi, "{d:?} outside [{lo:?}, {hi:?}]");
            seen.insert(d.as_nanos());
        }
        assert!(seen.len() > 1, "jitter should not be constant");
    }
}
