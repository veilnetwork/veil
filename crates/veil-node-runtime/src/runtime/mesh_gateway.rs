//! Mesh + gateway background tasks:
//! `spawn_gateway_failover_task`: monitors AutoDiscoveredPeers, upserts
//! into GatewayList, triggers staggered reconnect on session loss.
//! `spawn_mesh_tasks`: binds the mesh beacon sender/receiver when a
//! local mesh interface is configured.
//! `spawn_mesh_beacon_sender` / `spawn_mesh_beacon_receiver`: one-shot
//! bind + background loop bodies for the mesh plane.
//! `spawn_gateway_autodiscover_loop`: consumes the gateway-autodiscover
//! channel and spawns outbound connectors for freshly-discovered GWs.
//!
//! Extracted from `runtime/mod.rs` during refactor.

use std::sync::{Arc, Mutex};
use veil_util::{lock, rlock};

use veil_cfg;
use veil_cfg::PeerId;
use veil_mesh::{NeighborTable, UdpRealm};

use super::{NodeRuntime, PeerConfigEntry, lock_state, lock_tasks};
use crate::types;
#[allow(unused_imports)]
use crate::types::PeerSource;

impl NodeRuntime {
    /// Spawn the gateway failover monitor.
    ///
    /// Monitors `AutoDiscoveredPeers` for new gateways, upserts them into the
    /// `GatewayList` with appropriate scores, and on session loss triggers
    /// staggered reconnect with hysteresis.
    pub fn spawn_gateway_failover_task(&mut self, failover_delay: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let gateway_list = Arc::clone(&self.gateway_list);
        let autodiscovered = Arc::clone(&self.autodiscovered_peers);
        let access = self.access();
        let state = Arc::clone(&self.state);
        // check liveness against the session_tx_registry (real
        // active sessions) instead of `state.peers` which is an append-only
        // set of configured/autodiscovered peer entries and never sheds
        // entries for dead sessions.
        let session_tx_registry = Arc::clone(&self.session_tx_registry);
        let logger = Arc::clone(&self.logger);
        let shutdown_tx_clone = shutdown_tx.clone();
        // cycle-7 M3: gateway-failover window, disjoint from pinned-relays / PEX
        // (all used to share 0xD000_0000). See `types::synthetic_peer_id`.
        let mut peer_id_ctr: u32 = crate::types::synthetic_peer_id::GATEWAY_FAILOVER_BASE;

        let handle = tokio::spawn(async move {
            use veil_gateway::BASE_SCORE_AUTODISCOVERED;
            use veil_proto::mesh::beacon_role_flags;

            const POLL: std::time::Duration = std::time::Duration::from_secs(10);
            loop {
                tokio::select! {
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                    _ = tokio::time::sleep(POLL) => {}
                }

                // Sync autodiscovered gateways into GatewayList.
                {
                    let gateways = autodiscovered.live_gateways();
                    let mut gl = lock!(gateway_list);
                    for gw in &gateways {
                        let has_internet = gw.role_flags & beacon_role_flags::HAS_INTERNET != 0;
                        gl.upsert(
                            gw.node_id,
                            gw.veil_addr.clone(),
                            BASE_SCORE_AUTODISCOVERED,
                            has_internet,
                        );
                    }
                    // cycle-7 MH4d: evict gateways we have not seen in a while and
                    // are not actively connected to, so a node rotating beacon
                    // node_ids cannot grow GatewayList without bound.
                    const GATEWAY_STALE_TTL: std::time::Duration =
                        std::time::Duration::from_secs(600);
                    let pruned = gl.prune_stale(GATEWAY_STALE_TTL);
                    if pruned > 0 {
                        logger.info(
                            "gateway.prune",
                            format!("evicted {pruned} stale GatewayList entries"),
                        );
                    }
                }

                // Check for gateways that have lost their session and trigger
                // reconnect with staggered delay.
                let entries_snapshot: Vec<_> = {
                    let gl = lock!(gateway_list);
                    gl.entries()
                        .iter()
                        .map(|e| (e.node_id, e.veil_addr.clone()))
                        .collect()
                };
                for (node_id, veil_addr) in entries_snapshot {
                    // liveness = session exists in the tx_registry.
                    // Using `state.peers` here was wrong — peers are inserted
                    // on bootstrap/autodiscover and never removed, so stale
                    // entries from dead gateways prevented reconnect.
                    let already_connected =
                        rlock!(session_tx_registry).get_sender(&node_id).is_some();
                    if already_connected {
                        continue;
                    }
                    if veil_addr.is_empty() {
                        continue;
                    }

                    // Rank-based staggered delay: rank × 500 ms + jitter(±200 ms).
                    let rank = lock!(gateway_list).rank_of(&node_id);
                    let base_ms = (rank as u64).saturating_mul(500);
                    // Simple deterministic jitter from node_id bytes (±200 ms).
                    let jitter_raw = (node_id[0] as i64 % 400) - 200;
                    let delay_ms = if jitter_raw >= 0 {
                        base_ms.saturating_add(jitter_raw as u64)
                    } else {
                        base_ms.saturating_sub(jitter_raw.unsigned_abs())
                    };
                    if delay_ms > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    }

                    // Still disconnected after the stagger delay — initiate reconnect.
                    let still_disconnected =
                        rlock!(session_tx_registry).get_sender(&node_id).is_none();
                    if !still_disconnected {
                        continue;
                    }

                    let peer_id = PeerId::new(peer_id_ctr);
                    peer_id_ctr = peer_id_ctr.wrapping_add(1);
                    let entry = PeerConfigEntry {
                        peer_id,
                        node_id: veil_cfg::NodeId::from(node_id),
                        public_key: String::new(),
                        nonce: String::new(),
                        transport: veil_addr.clone(),
                        algo: veil_cfg::SignatureAlgorithm::Ed25519,
                        tls_cert: None,
                        tls_key: None,
                        tls_ca_cert: None,
                        bootstrap_only: true,
                        source: types::PeerSource::Autodiscovered,
                    };
                    lock_state(&state).peers.insert(peer_id, entry.clone());
                    logger.info(
                        "gateway.failover",
                        format!(
                            "reconnecting node_id={} addr={}",
                            veil_util::hex_short(&node_id),
                            veil_util::redact_addr_for_log(&veil_addr),
                        ),
                    );
                    let _ = failover_delay; // used by caller to decide when to trigger
                    let handles = crate::outbound_connector::spawn_outbound_peers(
                        vec![entry],
                        &access,
                        &shutdown_tx_clone,
                    );
                    let _ = handles;
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// Start mesh realm tasks: beacon sender (with role flags) and gateway
    /// autodiscovery connect loop.
    ///
    /// No-op when `config.mesh` is absent or the realm could not be bound.
    pub fn spawn_mesh_tasks(&mut self, config: &veil_cfg::Config) {
        // three independent mesh tasks — beacon sender, beacon
        // receive loop, gateway autodiscover — live in three named helpers.
        let Some(mesh_cfg) = config.mesh.as_ref() else {
            return;
        };
        let Some(realm) = self.mesh_realm.as_ref().map(Arc::clone) else {
            return;
        };

        self.spawn_mesh_beacon_sender(config, mesh_cfg, &realm);
        self.spawn_mesh_beacon_receiver(mesh_cfg, &realm);
        if mesh_cfg.autodiscover_gateway {
            self.spawn_gateway_autodiscover_loop(mesh_cfg);
        }
    }

    /// Periodic UDP beacon announcing our node_id, role flags, and veil
    /// address.
    pub fn spawn_mesh_beacon_sender(
        &mut self,
        config: &veil_cfg::Config,
        mesh_cfg: &veil_cfg::MeshConfig,
        realm: &Arc<UdpRealm>,
    ) {
        use veil_proto::mesh::beacon_role_flags;
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };

        let local_node_id = self.dispatcher.local_node_id;
        let role = self.dispatcher.role;
        // C-03: only reveal the node's role (IS_GATEWAY / IS_RELAY /
        // HAS_INTERNET) in the cleartext LAN beacon when the operator opts in
        // (`mesh.advertise_role_in_beacon`). By default role_flags = 0 so a
        // passive on-link observer cannot single this node out as a gateway/
        // relay — a targeting / censorship signal. (The stable node_id is still
        // broadcast; eliminating that needs the rotating-ephemeral-ID redesign.)
        let role_flags = if mesh_cfg.advertise_role_in_beacon {
            match role {
                veil_cfg::NodeRole::Core => {
                    let mut f = beacon_role_flags::IS_GATEWAY | beacon_role_flags::IS_RELAY;
                    let has_internet = config.listen.iter().any(|l| l.advertise.is_some());
                    if has_internet {
                        f |= beacon_role_flags::HAS_INTERNET;
                    }
                    f
                }
                veil_cfg::NodeRole::Leaf => 0u8,
            }
        } else {
            0u8
        };
        // Veil address = first listener that advertises a public address.
        let veil_addr = config.listen.iter().find_map(|l| l.advertise.clone());
        let beacon_addr: std::net::SocketAddr = match mesh_cfg.beacon_addr.parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        let beacon_interval = veil_mesh::DEFAULT_BEACON_INTERVAL;
        let realm_clone = Arc::clone(realm);
        let shutdown_beacon = shutdown_tx.subscribe();
        let beacon_algo = self.identity.local_identity.algo;
        let beacon_pubkey = self.identity.local_identity.public_key.clone();
        let beacon_privkey = self.identity.local_identity.private_key.clone();
        let handle = tokio::spawn(async move {
            // pass signing key for authenticated beacons.
            if let Ok(h) = realm_clone
                .spawn_beacon_sender_with_role_and_key(
                    local_node_id,
                    beacon_addr,
                    beacon_interval,
                    shutdown_beacon,
                    role_flags,
                    veil_addr,
                    Some((beacon_algo, beacon_pubkey, beacon_privkey)),
                )
                .await
            {
                let _ = h.await;
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// Process incoming broadcast beacon frames: register mesh neighbours and
    /// (when enabled) feed IS_GATEWAY beacons into `AutoDiscoveredPeers`.
    pub fn spawn_mesh_beacon_receiver(
        &mut self,
        mesh_cfg: &veil_cfg::MeshConfig,
        realm: &Arc<UdpRealm>,
    ) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };

        let realm_recv = Arc::clone(realm);
        let neighbors = Arc::new(NeighborTable::new());
        let autodiscovered_recv = Arc::clone(&self.autodiscovered_peers);
        let autodiscover_enabled = mesh_cfg.autodiscover_gateway;
        let realm_id = realm.realm_id();
        // Thread the realm-wide obfuscation key (opt-in via `realm_psk`) into
        // the directly-constructed BeaconReceiver so beacon-discovered neighbor
        // links seal their DATA frames just like `link_to` links do.
        let beacon_obfs = realm.obfs_key();

        // Build a std socket from the realm's address so BeaconReceiver can
        // create UdpLinks pointing back at discovered neighbors.
        let fallback_addr: std::net::SocketAddr = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
        let addr = realm.local_addr().unwrap_or(fallback_addr);
        let std_socket = match std::net::UdpSocket::bind(addr)
            .or_else(|_| std::net::UdpSocket::bind("0.0.0.0:0"))
        {
            Ok(s) => Arc::new(s),
            Err(_) => {
                self.logger.warn(
                    "mesh.beacon.bind_failed",
                    "failed to bind UDP socket for beacon receiver — skipping beacon setup for this realm",
                );
                return;
            }
        };

        let beacon_rtt_table: Arc<dyn veil_mesh::beacon::BatterySink> = Arc::new(
            crate::mesh_glue::RttBatterySink::new(Arc::clone(&self.routing.rtt_table)),
        );
        let beacon_dedup_window = std::time::Duration::from_secs(mesh_cfg.beacon_dedup_window_secs);
        // SECURITY (audit 2026-05-29, A5): propagate the require-signed-beacons
        // policy into the receiver (default false = legacy interop).
        let require_signed_beacons = mesh_cfg.require_signed_beacons;
        let mut recv_shutdown = shutdown_tx.subscribe();
        let handle = tokio::spawn(async move {
            let mut receiver = {
                let r = veil_mesh::BeaconReceiver::new(
                    realm_id,
                    (*neighbors).clone(),
                    std_socket,
                    beacon_obfs,
                )
                .with_rtt_table(beacon_rtt_table)
                .with_dedup_window(beacon_dedup_window)
                .with_require_signed(require_signed_beacons);
                if autodiscover_enabled {
                    r.with_autodiscovery(autodiscovered_recv)
                } else {
                    r.disable_autodiscovery()
                }
            };
            loop {
                tokio::select! {
                    Ok(_) = recv_shutdown.changed() => {
                        if *recv_shutdown.borrow() { break; }
                    }
                    result = realm_recv.recv_frame() => {
                        match result {
                            Ok((frame, addr)) if frame.is_broadcast() => {
                                receiver.handle_beacon(&frame, addr);
                            }
                            Ok(_) => {} // unicast — handled elsewhere
                            Err(_) => break,
                        }
                    }
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// Periodically top up the set of active sessions to autodiscovered
    /// gateways, up to `mesh_cfg.autodiscover_max_concurrent`. Each
    /// autodiscovered gateway lives in the `0xC000_0000+` peer-id range so
    /// other code paths can recognise it as a synthetic/transient entry.
    pub fn spawn_gateway_autodiscover_loop(&mut self, mesh_cfg: &veil_cfg::MeshConfig) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };

        let autodiscovered = Arc::clone(&self.autodiscovered_peers);
        let max_concurrent = mesh_cfg.autodiscover_max_concurrent;
        let access = self.access();
        let state = Arc::clone(&self.state);
        // count active sessions via session_tx_registry rather
        // than the append-only `state.peers` set. Stale peer entries used
        // to inflate the active count past `max_concurrent` after gateways
        // died, silently blocking further autodiscover reconnects.
        let session_tx_registry = Arc::clone(&self.session_tx_registry);
        let logger = Arc::clone(&self.logger);
        // rank gateway candidates by composite latency+battery
        // score before picking which to dial. Pull the shared `RttTable`
        // so we can look up smoothed-RTT + cached battery_level for each
        // candidate. Both fields are updated by the beacon-receive path
        // (rtt by every probe, battery by every beacon), so this loop
        // sees fresh-ish data without doing its own probing.
        let rtt_table_for_rank = Arc::clone(&self.routing.rtt_table);
        // wakeup channel for sub-second failover. The
        // outbound-connector trips this when a synthetic-range gateway
        // session closes; we treat it as "re-evaluate slots NOW", which
        // collapses the back-fill latency from `POLL_INTERVAL` to ~RTT.
        let failover_notify = Arc::clone(&self.gateway_failover_notify);
        let shutdown_tx_clone = shutdown_tx.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        let handle = tokio::spawn(async move {
            // shortened from 5 s → 1 s as a safety net in
            // case a notify is missed (e.g. the loop body is mid-pass
            // when one fires — `Notify::notify_waiters` doesn't queue).
            // 1 s × 8 entries × 1 sort ≈ negligible CPU.
            const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
            let mut peer_id_counter: u32 = crate::types::synthetic_peer_id::MESH_AUTODISCOVER_BASE;

            loop {
                tokio::select! {
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                    _ = failover_notify.notified() => {}
                    _ = tokio::time::sleep(POLL_INTERVAL) => {}
                }
                autodiscovered.evict_expired();
                let mut gateways = autodiscovered.live_gateways();
                rank_gateways_by_score(&mut gateways, &rtt_table_for_rank);

                // Intersect `state.peers` (for the synthetic-range + bootstrap_only
                // filter) with the tx_registry's live set to count active links.
                let active: usize = {
                    let live = rlock!(session_tx_registry).active_node_ids();
                    let s = lock_state(&state);
                    s.peers
                        .values()
                        .filter(|p| p.bootstrap_only && p.peer_id.get() >= 0xC000_0000)
                        .filter(|p| live.contains(p.node_id.as_bytes()))
                        .count()
                };
                if active >= max_concurrent {
                    continue;
                }

                let slots = max_concurrent - active;
                for gw in gateways.iter().take(slots) {
                    // Skip if we already have a live session to this node_id.
                    let already = rlock!(session_tx_registry)
                        .get_sender(&gw.node_id)
                        .is_some();
                    if already {
                        continue;
                    }

                    let peer_id = PeerId::new(peer_id_counter);
                    peer_id_counter = peer_id_counter.wrapping_add(1);
                    let entry = PeerConfigEntry {
                        peer_id,
                        node_id: veil_cfg::NodeId::from(gw.node_id),
                        public_key: String::new(), // TOFU — verified by node_id only
                        nonce: String::new(),
                        transport: gw.veil_addr.clone(),
                        algo: veil_cfg::SignatureAlgorithm::Ed25519,
                        tls_cert: None,
                        tls_key: None,
                        tls_ca_cert: None,
                        bootstrap_only: true,
                        source: types::PeerSource::Autodiscovered,
                    };
                    lock_state(&state).peers.insert(peer_id, entry.clone());
                    logger.info(
                        "mesh.autodiscover.connect",
                        format!(
                            "node_id={} addr={}",
                            veil_util::hex_short(&gw.node_id),
                            veil_util::redact_addr_for_log(&gw.veil_addr),
                        ),
                    );
                    // `access` drives the connector internally — the returned
                    // handles are already tracked through shutdown_tx_clone.
                    let _ = crate::outbound_connector::spawn_outbound_peers(
                        vec![entry],
                        &access,
                        &shutdown_tx_clone,
                    );
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }
}

/// composite weight for a single ms of smoothed RTT.
///
/// `1.0` means "1 ms of latency = 1 score unit" so the score is
/// directly comparable to a millisecond budget.
pub const GATEWAY_RANK_LATENCY_WEIGHT: f64 = 1.0;

/// weight for one percentage-point of battery drain
/// (relative to a "full battery" baseline of 100 %).
///
/// `5.0` means "1 % battery loss = 5 score units" — equivalently, a
/// gateway running on 0 % battery is penalised by 500 score units
/// the same as a 500 ms RTT increase. The trade-off threshold:
/// prefer a fresh-battery far gateway over a low-battery near one
/// only when the battery gap exceeds 200 % per 1 second of RTT diff
/// (which never happens in practice — the battery penalty mostly
/// matters as a tie-breaker between gateways with similar RTT).
pub const GATEWAY_RANK_BATTERY_WEIGHT: f64 = 5.0;

/// RTT assumed for a gateway with no probe history.
///
/// 500 ms sits between "great" (~50 ms LAN/Wi-Fi) and "bad" (~1 s
/// loaded mobile) so freshly-discovered gateways get a fair chance
/// to be sampled rather than always landing at the bottom.
pub const GATEWAY_RANK_UNKNOWN_RTT_MS: u32 = 500;

/// rank a list of auto-discovered gateways in-place by
/// composite latency + battery score (lower = better). Pulls fresh
/// `rtt_smoothed` and `battery_level` for each candidate from the
/// shared `RttTable` (populated by the beacon-receive path and the
/// regular probe loop).
///
/// Public to `super` so the auto-connect loop can use it; pulled out
/// of the loop body so it can be unit-tested in isolation.
pub fn rank_gateways_by_score(
    gateways: &mut [veil_mesh::AutoDiscoveredGateway],
    rtt_table: &Arc<Mutex<veil_routing::probe::RttTable>>,
) {
    let rtt = lock!(rtt_table);
    gateways.sort_by(|a, b| {
        gateway_score(a, &rtt)
            .partial_cmp(&gateway_score(b, &rtt))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

/// Compute the composite ranking score for one gateway candidate.
/// Lower is better. Pure function over `(gateway, RttTable)`.
pub fn gateway_score(
    gw: &veil_mesh::AutoDiscoveredGateway,
    rtt: &veil_routing::probe::RttTable,
) -> f64 {
    let probe = rtt.get(&gw.node_id);
    let rtt_ms = probe
        .map(|p| p.rtt_smoothed)
        .unwrap_or(GATEWAY_RANK_UNKNOWN_RTT_MS);
    // battery == 0 is RttTable's "AC power / unknown" sentinel — no penalty.
    let battery = probe.map(|p| p.battery_level).unwrap_or(0);
    let battery_penalty = if battery == 0 {
        0.0
    } else {
        (100u8.saturating_sub(battery)) as f64
    };
    GATEWAY_RANK_LATENCY_WEIGHT * (rtt_ms as f64) + GATEWAY_RANK_BATTERY_WEIGHT * battery_penalty
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use veil_mesh::AutoDiscoveredGateway;
    use veil_routing::probe::RttTable;

    fn gw(tag: u8) -> AutoDiscoveredGateway {
        AutoDiscoveredGateway {
            node_id: [tag; 32],
            veil_addr: format!("tcp://10.0.0.{tag}:9000"),
            role_flags: 0x01,
            last_seen: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(60),
        }
    }

    /// Lower RTT must rank first (no battery influence when battery_level == 0
    /// for both candidates).
    #[test]
    fn epic478_2_lower_rtt_ranks_first() {
        let table = RttTable::new(Duration::from_secs(60));
        let table = Arc::new(Mutex::new(table));
        let fast = gw(0xAA);
        let slow = gw(0xBB);
        lock!(table).record(
            fast.node_id,
            veil_routing::probe::PeerReportedRtt::from_raw_ms(30),
            0,
        );
        lock!(table).record(
            slow.node_id,
            veil_routing::probe::PeerReportedRtt::from_raw_ms(200),
            0,
        );
        let mut gws = vec![slow.clone(), fast.clone()];
        rank_gateways_by_score(&mut gws, &table);
        assert_eq!(gws[0].node_id, fast.node_id);
        assert_eq!(gws[1].node_id, slow.node_id);
    }

    /// Among gateways with similar RTT, the higher-battery one ranks first.
    #[test]
    fn epic478_2_higher_battery_breaks_rtt_tie() {
        let table = Arc::new(Mutex::new(RttTable::new(Duration::from_secs(60))));
        let fresh = gw(0xCC);
        let drained = gw(0xDD);
        // Same RTT 100 ms.
        lock!(table).record(
            fresh.node_id,
            veil_routing::probe::PeerReportedRtt::from_raw_ms(100),
            0,
        );
        lock!(table).record(
            drained.node_id,
            veil_routing::probe::PeerReportedRtt::from_raw_ms(100),
            0,
        );
        // Different battery levels.
        lock!(table).update_battery(fresh.node_id, 90);
        lock!(table).update_battery(drained.node_id, 10);
        let mut gws = vec![drained.clone(), fresh.clone()];
        rank_gateways_by_score(&mut gws, &table);
        assert_eq!(
            gws[0].node_id, fresh.node_id,
            "90% battery beats 10% battery at equal RTT"
        );
    }

    /// Unknown-history gateway uses `GATEWAY_RANK_UNKNOWN_RTT_MS = 500` so
    /// it ranks worse than known-fast peers but better than known-slow ones.
    #[test]
    fn epic478_2_unknown_rtt_uses_default_500ms() {
        let table = Arc::new(Mutex::new(RttTable::new(Duration::from_secs(60))));
        let known_fast = gw(0xEE);
        let unknown = gw(0xEF);
        let known_slow = gw(0xF0);
        lock!(table).record(
            known_fast.node_id,
            veil_routing::probe::PeerReportedRtt::from_raw_ms(50),
            0,
        );
        // unknown intentionally has no probe.
        lock!(table).record(
            known_slow.node_id,
            veil_routing::probe::PeerReportedRtt::from_raw_ms(1000),
            0,
        );
        let mut gws = vec![known_slow.clone(), unknown.clone(), known_fast.clone()];
        rank_gateways_by_score(&mut gws, &table);
        assert_eq!(gws[0].node_id, known_fast.node_id);
        assert_eq!(gws[1].node_id, unknown.node_id);
        assert_eq!(gws[2].node_id, known_slow.node_id);
    }

    /// Battery == 0 ("AC / unknown") must NOT be treated as a 100 % penalty —
    /// otherwise plugged-in gateways would always rank below battery-powered ones.
    #[test]
    fn epic478_2_battery_zero_treated_as_no_penalty() {
        let table = Arc::new(Mutex::new(RttTable::new(Duration::from_secs(60))));
        let on_ac = gw(0x10);
        let on_battery = gw(0x11);
        // Same RTT.
        lock!(table).record(
            on_ac.node_id,
            veil_routing::probe::PeerReportedRtt::from_raw_ms(100),
            0,
        );
        lock!(table).record(
            on_battery.node_id,
            veil_routing::probe::PeerReportedRtt::from_raw_ms(100),
            0,
        );
        // on_ac left at battery=0 (AC/unknown sentinel); on_battery at 50%.
        lock!(table).update_battery(on_battery.node_id, 50);
        let mut gws = vec![on_battery.clone(), on_ac.clone()];
        rank_gateways_by_score(&mut gws, &table);
        assert_eq!(
            gws[0].node_id, on_ac.node_id,
            "AC-powered (battery=0) must rank before 50% battery at equal RTT"
        );
    }

    /// a `Notify` waiter wakes within milliseconds of a
    /// `notify_waiters` call. Smoke test for the failover signalling
    /// path — the actual end-to-end "session closes → loop wakes →
    /// reconnects" is covered by sim-scenario 478.6.
    #[tokio::test(flavor = "current_thread")]
    async fn epic478_3_notify_waiters_wakes_listener_promptly() {
        use std::time::Instant;
        use tokio::sync::Notify;
        let n = Arc::new(Notify::new());
        let n_clone = Arc::clone(&n);
        // Listener task starts waiting; we measure how fast it returns
        // after a `notify_waiters` from the producer.
        let started = Instant::now();
        let listener = tokio::spawn(async move {
            n_clone.notified().await;
            started.elapsed()
        });
        // Give the listener a tick to actually `await` (Notify only wakes
        // existing waiters, not future ones — exactly the same constraint
        // the auto-discover loop relies on).
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        n.notify_waiters();
        let elapsed = listener.await.unwrap();
        // 500 ms is generous (was 100 ms; audit batch 2026-05-24 bumped
        // it after observed 131 ms wake on shared GitHub Actions
        // runners under load — local fast metal still hits < 1 ms).
        // The acceptance bar for 478.3 is < 1 s end-to-end (session-close
        // → reconnect dial); the notify hop is < 1 ms typically.
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "notify wake took {elapsed:?}, expected < 500 ms"
        );
    }
}
