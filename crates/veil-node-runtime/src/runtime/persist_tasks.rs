//! Periodic persistence tasks spawned by [`super::NodeRuntime`].
//!
//! Each task flushes a `HashMap` / `Vec` / `Arc`-shared state snapshot to
//! disk on an interval (and once more on shutdown) so a restarting node
//! does not lose its learned routes, RTTs, Vivaldi coord, DHT table
//! autodiscovered peers, gateway list, or peer-pubkey cache. The
//! corresponding `restore_*_snapshot` helpers run at startup.
//!
//! Extracted from `runtime/mod.rs` during the 463 refactor — the file was
//! ~8700 LOC and the ~680-LOC persistence cluster is a self-contained
//! subsystem that reads `config.*_persist_path` knobs and writes to disk.

use std::sync::{Arc, Mutex};
use veil_util::{lock, rlock, wlock};

use crate::types::NodeIdBytes;
use veil_cfg;

use super::{NodeLogger, NodeRuntime, PeerPubkeySnapshot, RttTable, RuntimeTasks, lock_tasks};

/// Atomically serialise `snapshot` to JSON and write it to `path`.
///
/// Logs success at `debug` under `{event}.flush` (with `{detail}` appended)
/// and failures at `warn` under `{event}.flush_err`. Never panics.
///
/// extracted from 8 byte-for-byte copies in this file. In
/// addition to the dedup, this routes through `veil_util::atomic_write`
/// (tmp + fsync + rename + EACCES retry) — the previous `fs::write` +
/// `rename` skipped the fsync, so a power-loss between the kernel page
/// cache flush and the rename could surface a zero-byte file on restart.
pub fn flush_json_snapshot_sync<T: serde::Serialize + ?Sized>(
    path: &str,
    snapshot: &T,
    logger: &NodeLogger,
    event: &str,
    detail: &str,
) {
    let result = (|| -> Result<(), String> {
        let bytes = serde_json::to_vec(snapshot).map_err(|e| format!("serialize: {e}"))?;
        veil_util::atomic_write(std::path::Path::new(path), &bytes)
            .map_err(|e| format!("write: {e}"))
    })();
    match result {
        Ok(()) => logger.debug(
            format!("{event}.flush").as_str(),
            format!("wrote {detail} to {path}"),
        ),
        Err(e) => logger.warn(
            format!("{event}.flush_err").as_str(),
            format!("snapshot write failed: {e}"),
        ),
    }
}

/// Spawn a `tokio` task that runs `flush(build_snapshot)` once per
/// `interval`, plus one final flush on clean shutdown, then exits.
///
/// extracted from 8 spawn-methods that all hand-rolled the
/// same `select! { shutdown_rx.changed | ticker.tick } + spawn_blocking`
/// loop with subtly different snapshot-building call sites. Each remaining
/// caller now passes two closures: one that produces the snapshot from
/// shared state, one that flushes it to disk.
///
/// `flush` is `Fn` (not `FnOnce`) because we call it on every tick AND on
/// shutdown — wrapped in `Arc` so we can hand a shared reference into
/// successive `spawn_blocking` calls.
pub fn spawn_persist_loop<S, B, F>(
    tasks: &Arc<Mutex<RuntimeTasks>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    interval: std::time::Duration,
    mut build_snapshot: B,
    flush: F,
) where
    S: Send + 'static,
    B: FnMut() -> S + Send + 'static,
    F: Fn(S) + Send + Sync + 'static,
{
    let flush = Arc::new(flush);
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick — match prior hand-rolled behaviour.
        ticker.tick().await;

        loop {
            tokio::select! {
                Ok(_) = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        let snap = build_snapshot();
                        let f = Arc::clone(&flush);
                        tokio::task::spawn_blocking(move || f(snap)).await
                            .unwrap_or_else(|e| log::error!("persist flush panicked: {e}"));
                        break;
                    }
                }
                _ = ticker.tick() => {
                    let snap = build_snapshot();
                    let f = Arc::clone(&flush);
                    tokio::task::spawn_blocking(move || f(snap)).await
                        .unwrap_or_else(|e| log::error!("persist flush panicked: {e}"));
                }
            }
        }
    });
    lock_tasks(tasks).background.push(handle);
}

impl NodeRuntime {
    // ── route-cache persistence ─────────────────────────────────────

    /// Try to restore route-cache entries from a persisted snapshot at startup.
    ///
    /// Silently skips if the file does not exist. Logs a warning (does not
    /// panic) on parse errors or if the file is older than `max_age`.
    pub fn restore_route_cache_snapshot(&self, config: &veil_cfg::Config) {
        use std::time::SystemTime;
        let Some(ref path) = config.routing.cache_persist_path else {
            return;
        };
        let max_age = std::time::Duration::from_secs(config.routing.cache_persist_max_age_secs);

        // Check modification time (139.6).
        match std::fs::metadata(path) {
            Ok(meta) => {
                if let Ok(modified) = meta.modified() {
                    let age = SystemTime::now()
                        .duration_since(modified)
                        .unwrap_or(max_age + std::time::Duration::from_secs(1));
                    if age > max_age {
                        self.logger.warn(
                            "cache.persist.stale",
                            format!("snapshot older than {max_age:?} — skipping restore"),
                        );
                        let _ = std::fs::remove_file(path);
                        return;
                    }
                }
            }
            Err(_) => return, // file absent — nothing to restore
        }

        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                self.logger.warn(
                    "cache.persist.read_err",
                    format!("cannot read snapshot: {e}"),
                );
                return;
            }
        };
        let entries: Vec<veil_routing::cache::CacheEntrySnapshot> =
            match serde_json::from_str(&data) {
                Ok(v) => v,
                Err(e) => {
                    self.logger.warn(
                        "cache.persist.parse_err",
                        format!("snapshot parse failed ({e}) — starting without cache"),
                    );
                    return;
                }
            };
        let count = entries.len();
        // Restore contact counts into the RTT table BEFORE restoring cache entries
        // so that top_by_contact_count is available immediately.
        {
            let mut rtt = lock!(self.routing.rtt_table);
            for snap in &entries {
                rtt.restore_contact_count(snap.next_hop, snap.contact_count);
            }
        }
        wlock!(self.routing.route_cache).restore(entries);
        self.logger.info(
            "cache.persist.restored",
            format!("restored {count} stale routes from snapshot"),
        );
    }

    /// Atomically write a route-cache snapshot to `path`.
    ///
    /// Logs a warning on failure; never panics.
    pub fn flush_cache_snapshot_sync(
        path: String,
        snapshot: Vec<veil_routing::cache::CacheEntrySnapshot>,
        logger: Arc<NodeLogger>,
    ) {
        let detail = format!("{} route entries", snapshot.len());
        flush_json_snapshot_sync(&path, &snapshot, &logger, "cache.persist", &detail);
    }

    /// Spawn a background task that periodically flushes the route-cache
    /// snapshot and performs a final flush on clean shutdown.
    pub fn spawn_cache_persist_task(&mut self, path: String, interval: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let shutdown_rx = shutdown_tx.subscribe();
        let route_cache = Arc::clone(&self.routing.route_cache);
        let rtt_table = Arc::clone(&self.routing.rtt_table);
        let logger = Arc::clone(&self.logger);

        spawn_persist_loop(
            &self.tasks,
            shutdown_rx,
            interval,
            move || {
                let counts = Self::collect_contact_counts(&rtt_table);
                rlock!(route_cache).snapshot(&counts)
            },
            move |snap| Self::flush_cache_snapshot_sync(path.clone(), snap, Arc::clone(&logger)),
        );
    }

    /// Build a `next_hop → contact_count` map from the RTT table.
    pub fn collect_contact_counts(
        rtt_table: &Arc<Mutex<RttTable>>,
    ) -> std::collections::HashMap<NodeIdBytes, u32> {
        lock!(rtt_table).all_contact_counts()
    }

    // ── RTT table persistence ───────────────────────────────────────

    /// Restore RTT probes from a persisted snapshot.
    ///
    /// Reads the JSON file at `rtt_persist_path`, deserialises into
    /// `Vec<RttSnapshot>`, and calls `RttTable::restore` so routing decisions
    /// have warm latency data immediately after restart.
    ///
    /// Silently skips (with a warning log) on any I/O or parse error.
    pub fn restore_rtt_snapshot(&self, config: &veil_cfg::Config) {
        let Some(ref path) = config.routing.rtt_persist_path else {
            return;
        };

        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return, // file absent — nothing to restore
        };
        let entries: Vec<veil_routing::probe::RttSnapshot> = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                self.logger.warn(
                    "rtt.persist.parse_err",
                    format!("RTT snapshot parse failed ({e}) — starting without cached RTTs"),
                );
                return;
            }
        };
        let count = entries.len();
        lock!(self.routing.rtt_table).restore(entries);
        self.logger.info(
            "rtt.persist.restored",
            format!("restored {count} RTT probes from snapshot"),
        );
    }

    /// Atomically write an RTT snapshot to `path`.
    pub fn flush_rtt_snapshot_sync(
        path: String,
        snapshot: Vec<veil_routing::probe::RttSnapshot>,
        logger: Arc<NodeLogger>,
    ) {
        let detail = format!("{} RTT entries", snapshot.len());
        flush_json_snapshot_sync(&path, &snapshot, &logger, "rtt.persist", &detail);
    }

    /// Spawn a background task that periodically flushes the RTT snapshot.
    pub fn spawn_rtt_persist_task(&mut self, path: String, interval: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let shutdown_rx = shutdown_tx.subscribe();
        let rtt_table = Arc::clone(&self.routing.rtt_table);
        let logger = Arc::clone(&self.logger);

        spawn_persist_loop(
            &self.tasks,
            shutdown_rx,
            interval,
            move || lock!(rtt_table).snapshot(),
            move |snap| Self::flush_rtt_snapshot_sync(path.clone(), snap, Arc::clone(&logger)),
        );
    }

    // ── Vivaldi coordinate persistence ──────────────────────────────

    pub fn restore_vivaldi_snapshot(&self, config: &veil_cfg::Config) {
        let Some(ref path) = config.routing.vivaldi_persist_path else {
            return;
        };
        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return,
        };
        let coord: veil_routing::VivaldiCoord = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                self.logger.warn(
                    "vivaldi.persist.parse_err",
                    format!("Vivaldi snapshot parse failed ({e}) — starting at origin"),
                );
                return;
            }
        };
        let Some(lv) = self.dispatcher.local_vivaldi.as_ref() else {
            return;
        };
        *lock!(lv) = coord;
        if let Some(m) = &self.metrics {
            {
                let c = lock!(lv);
                m.record_vivaldi_coord(c.x, c.y, c.height, c.error);
            };
        }
        self.logger.info(
            "vivaldi.persist.restored",
            "restored Vivaldi coordinate from snapshot",
        );
    }

    pub fn flush_vivaldi_snapshot_sync(
        path: String,
        coord: veil_routing::VivaldiCoord,
        logger: Arc<NodeLogger>,
    ) {
        flush_json_snapshot_sync(&path, &coord, &logger, "vivaldi.persist", "Vivaldi coord");
    }

    pub fn spawn_vivaldi_persist_task(&mut self, path: String, interval: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let Some(ref local_vivaldi) = self.dispatcher.local_vivaldi else {
            return;
        };
        let shutdown_rx = shutdown_tx.subscribe();
        let local_vivaldi = Arc::clone(local_vivaldi);
        let logger = Arc::clone(&self.logger);

        spawn_persist_loop(
            &self.tasks,
            shutdown_rx,
            interval,
            move || lock!(local_vivaldi).clone(),
            move |snap| Self::flush_vivaldi_snapshot_sync(path.clone(), snap, Arc::clone(&logger)),
        );
    }

    // ── DHT routing table persistence ───────────────────────────────

    pub fn restore_dht_routing_snapshot(&self, config: &veil_cfg::Config) {
        let Some(ref path) = config.dht.routing_persist_path else {
            return;
        };
        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return,
        };
        let contacts: Vec<veil_dht::routing::Contact> = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                self.logger.warn(
                    "dht.routing.persist.parse_err",
                    format!("DHT routing snapshot parse failed ({e})"),
                );
                return;
            }
        };
        let count = contacts.len();
        self.dht.restore_routing_contacts(contacts);
        self.logger.info(
            "dht.routing.persist.restored",
            format!("restored {count} DHT routing contacts from snapshot"),
        );
    }

    pub fn flush_dht_routing_snapshot_sync(
        path: String,
        contacts: Vec<veil_dht::routing::Contact>,
        logger: Arc<NodeLogger>,
    ) {
        let detail = format!("{} DHT contacts", contacts.len());
        flush_json_snapshot_sync(&path, &contacts, &logger, "dht.routing.persist", &detail);
    }

    pub fn spawn_dht_routing_persist_task(&mut self, path: String, interval: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let shutdown_rx = shutdown_tx.subscribe();
        let dht = Arc::clone(&self.dht);
        let logger = Arc::clone(&self.logger);

        spawn_persist_loop(
            &self.tasks,
            shutdown_rx,
            interval,
            move || dht.routing_table_contacts(),
            move |snap| {
                Self::flush_dht_routing_snapshot_sync(path.clone(), snap, Arc::clone(&logger))
            },
        );
    }

    // ── DHT values persistence ─────────────────────────────────────

    pub fn restore_dht_values_snapshot(&self, config: &veil_cfg::Config) {
        // Auto-derive path from config directory when not explicitly set.
        let auto_path;
        let path = match config.dht.values_persist_path.as_ref() {
            Some(p) => p,
            None => {
                let dir = self
                    .config_path
                    .parent()
                    .unwrap_or(std::path::Path::new("."));
                auto_path = dir.join("dht_values.json").to_string_lossy().into_owned();
                &auto_path
            }
        };
        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return,
        };
        let entries: Vec<veil_dht::kademlia::DhtValueSnapshot> = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                self.logger.warn(
                    "dht.values.persist.parse_err",
                    format!("DHT values snapshot parse failed ({e})"),
                );
                return;
            }
        };
        let total = entries.len();
        self.dht.restore_values(entries);
        self.logger.info(
            "dht.values.persist.restored",
            format!("restored {total}/{total} DHT values from snapshot"),
        );
    }

    pub fn flush_dht_values_snapshot_sync(
        path: String,
        entries: Vec<veil_dht::kademlia::DhtValueSnapshot>,
        logger: Arc<NodeLogger>,
    ) {
        let detail = format!("{} DHT values", entries.len());
        flush_json_snapshot_sync(&path, &entries, &logger, "dht.values.persist", &detail);
    }

    pub fn spawn_dht_values_persist_task(&mut self, path: String, interval: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let shutdown_rx = shutdown_tx.subscribe();
        let dht = Arc::clone(&self.dht);
        let logger = Arc::clone(&self.logger);

        spawn_persist_loop(
            &self.tasks,
            shutdown_rx,
            interval,
            move || dht.snapshot_values(),
            move |snap| {
                Self::flush_dht_values_snapshot_sync(path.clone(), snap, Arc::clone(&logger))
            },
        );
    }

    // ── AutoDiscoveredPeers persistence ─────────────────────────────

    pub fn restore_autodiscover_snapshot(&self, config: &veil_cfg::Config) {
        let Some(ref mesh) = config.mesh else { return };
        let Some(ref path) = mesh.autodiscover_persist_path else {
            return;
        };
        let peers = &self.autodiscovered_peers;
        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return,
        };
        let entries: Vec<veil_mesh::AutoDiscoveredSnapshot> = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                self.logger.warn(
                    "autodiscover.persist.parse_err",
                    format!("AutoDiscoveredPeers snapshot parse failed ({e})"),
                );
                return;
            }
        };
        let count = entries.len();
        peers.restore(entries);
        self.logger.info(
            "autodiscover.persist.restored",
            format!("restored {count} autodiscovered peers from snapshot"),
        );
    }

    pub fn flush_autodiscover_snapshot_sync(
        path: String,
        entries: Vec<veil_mesh::AutoDiscoveredSnapshot>,
        logger: Arc<NodeLogger>,
    ) {
        let detail = format!("{} autodiscovered peers", entries.len());
        flush_json_snapshot_sync(&path, &entries, &logger, "autodiscover.persist", &detail);
    }

    pub fn spawn_autodiscover_persist_task(&mut self, path: String, interval: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let shutdown_rx = shutdown_tx.subscribe();
        let peers = Arc::clone(&self.autodiscovered_peers);
        let logger = Arc::clone(&self.logger);

        spawn_persist_loop(
            &self.tasks,
            shutdown_rx,
            interval,
            move || peers.snapshot(),
            move |snap| {
                Self::flush_autodiscover_snapshot_sync(path.clone(), snap, Arc::clone(&logger))
            },
        );
    }

    // ── GatewayList persistence ────────────────────────────────────

    pub fn restore_gateway_list_snapshot(&self, config: &veil_cfg::Config) {
        let Some(ref path) = config.routing.gateway_persist_path else {
            return;
        };
        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return,
        };
        let entries: Vec<veil_gateway::GatewaySnapshot> = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                self.logger.warn(
                    "gateway.persist.parse_err",
                    format!("GatewayList snapshot parse failed ({e})"),
                );
                return;
            }
        };
        let count = entries.len();
        lock!(self.gateway_list).restore(entries);
        self.logger.info(
            "gateway.persist.restored",
            format!("restored {count} gateway entries from snapshot"),
        );
    }

    pub fn flush_gateway_list_snapshot_sync(
        path: String,
        entries: Vec<veil_gateway::GatewaySnapshot>,
        logger: Arc<NodeLogger>,
    ) {
        let detail = format!("{} gateways", entries.len());
        flush_json_snapshot_sync(&path, &entries, &logger, "gateway.persist", &detail);
    }

    pub fn spawn_gateway_list_persist_task(&mut self, path: String, interval: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let shutdown_rx = shutdown_tx.subscribe();
        let gateway_list = Arc::clone(&self.gateway_list);
        let logger = Arc::clone(&self.logger);

        spawn_persist_loop(
            &self.tasks,
            shutdown_rx,
            interval,
            move || lock!(gateway_list).snapshot(),
            move |snap| {
                Self::flush_gateway_list_snapshot_sync(path.clone(), snap, Arc::clone(&logger))
            },
        );
    }

    // ── Peer pubkeys cache persistence ──────────────────────────────

    pub fn restore_peer_pubkeys_snapshot(&self, config: &veil_cfg::Config) {
        let Some(ref path) = config.routing.peer_pubkeys_persist_path else {
            return;
        };
        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return,
        };
        let entries: Vec<PeerPubkeySnapshot> = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(e) => {
                self.logger.warn(
                    "peer_pubkeys.persist.parse_err",
                    format!("peer pubkeys snapshot parse failed ({e})"),
                );
                return;
            }
        };
        let count = entries.len();
        let mut cache = lock!(self.identity.peer_pubkeys);
        for e in entries {
            if !cache.contains_key(&e.node_id) {
                cache.insert_lru(
                    e.node_id,
                    (e.algo, e.pubkey),
                    veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
                );
            }
        }
        self.logger.info(
            "peer_pubkeys.persist.restored",
            format!("restored {count} peer pubkeys from snapshot"),
        );
    }

    pub fn flush_peer_pubkeys_snapshot_sync(
        path: String,
        entries: Vec<PeerPubkeySnapshot>,
        logger: Arc<NodeLogger>,
    ) {
        let detail = format!("{} peer pubkeys", entries.len());
        flush_json_snapshot_sync(&path, &entries, &logger, "peer_pubkeys.persist", &detail);
    }

    pub fn spawn_peer_pubkeys_persist_task(&mut self, path: String, interval: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let shutdown_rx = shutdown_tx.subscribe();
        let peer_pubkeys = Arc::clone(&self.identity.peer_pubkeys);
        let logger = Arc::clone(&self.logger);

        spawn_persist_loop(
            &self.tasks,
            shutdown_rx,
            interval,
            move || -> Vec<PeerPubkeySnapshot> {
                lock!(peer_pubkeys)
                    .iter()
                    .map(|(id, (algo, pk))| PeerPubkeySnapshot {
                        node_id: *id,
                        algo: *algo,
                        pubkey: pk.clone(),
                    })
                    .collect()
            },
            move |snap| {
                Self::flush_peer_pubkeys_snapshot_sync(path.clone(), snap, Arc::clone(&logger))
            },
        );
    }

    // ── transport announcements persistence ───

    /// Restore peer transport announcements from an on-disk snapshot.
    ///
    /// Each entry's signature, pubkey↔node_id binding, and non-expiry
    /// is re-verified before insert via
    /// `KademliaService::restore_transport_announcements`; failures are
    /// silently dropped. This means a tampered file can downgrade
    /// availability (drop entries) but cannot inject forged ones —
    /// the on-disk file is *not* a trust boundary, the signatures are.
    pub fn restore_transport_announcements_snapshot(&self, config: &veil_cfg::Config) {
        let Some(ref path) = config.dht.transport_announcements_persist_path else {
            return;
        };
        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return, // file absent — first run
        };
        let entries: Vec<veil_proto::discovery::SignedTransportAnnouncement> =
            match serde_json::from_str(&data) {
                Ok(v) => v,
                Err(e) => {
                    self.logger.warn(
                        "transport_announcements.persist.parse_err",
                        format!("snapshot parse failed ({e}) — starting cold"),
                    );
                    return;
                }
            };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let total = entries.len();
        let (inserted, rejected) = self
            .dispatcher
            .dht
            .restore_transport_announcements(entries, now_unix);
        self.logger.info(
            "transport_announcements.persist.restored",
            format!("restored {inserted}/{total} announcements ({rejected} rejected: expired or invalid sig)"),
        );
    }

    pub fn flush_transport_announcements_snapshot_sync(
        path: String,
        snapshot: Vec<veil_proto::discovery::SignedTransportAnnouncement>,
        logger: Arc<NodeLogger>,
    ) {
        let detail = format!("{} announcements", snapshot.len());
        flush_json_snapshot_sync(
            &path,
            &snapshot,
            &logger,
            "transport_announcements.persist",
            &detail,
        );
    }

    pub fn spawn_transport_announcements_persist_task(
        &mut self,
        path: String,
        interval: std::time::Duration,
    ) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let shutdown_rx = shutdown_tx.subscribe();
        let dht = Arc::clone(&self.dispatcher.dht);
        let logger = Arc::clone(&self.logger);

        spawn_persist_loop(
            &self.tasks,
            shutdown_rx,
            interval,
            move || dht.snapshot_transport_announcements(),
            move |snap| {
                Self::flush_transport_announcements_snapshot_sync(
                    path.clone(),
                    snap,
                    Arc::clone(&logger),
                )
            },
        );
    }
}
