//! Service-spawn methods extracted from `runtime/mod.rs` (continuation
//! of split).
//!
//! Holds:
//! `spawn_service` — single-dispatch wrapper over the per-feature
//! spawn helpers (one source of truth for startup AND reload).
//! `spawn_all_services` — startup-time iteration over
//! `RuntimeService::ALL`.
//! `spawn_listeners` — bind & accept-loop per `[[listen]]` entry.
//! `spawn_metrics_exporter` — Prometheus HTTP listener.
//! `init_mesh_realm` — UDP-realm bind for local-mesh peers.
//!
//! Pure code-movement; no behavioural change vs the inline definitions
//! from before the split.

#[allow(unused_imports)]
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, RwLock,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Instant,
};
use veil_util::lock;

#[allow(unused_imports)]
use tokio::{
    io::AsyncWriteExt,
    sync::{oneshot, watch},
    task::JoinHandle,
};

#[allow(unused_imports)]
use veil_cfg::{self, Config};
use veil_transport::{TransportContext, TransportUri};

#[allow(unused_imports)]
use crate::error::{NodeError, Result};
use crate::listener_supervisor::pop_accept_waiter;
use crate::state::NodeState;
use crate::types::{ListenConfigEntry, ListenId, ListenerHandle};
use veil_mesh::UdpRealm;

use super::persistence::persist_discovered_peers;
use super::{
    InboundSessionContext, NodeRuntime, NodeServices, SessionRuntimeContext,
    listen_transport_context, lock_state, lock_tasks, push_session_handle, spawn_inbound_session,
};

impl NodeRuntime {
    // ── Stop / reload helpers ─────────────────────────────────────

    /// single dispatch from a [`RuntimeService`] variant to the
    /// underlying spawn-method. Startup and reload both iterate
    /// `RuntimeService::ALL` and call this function, so forgetting to wire a
    /// service in one of the two paths becomes impossible — the exhaustive
    /// `match` here is the single source of truth.
    pub async fn spawn_service(
        &mut self,
        service: crate::task_registry::RuntimeService,
        config: &veil_cfg::Config,
    ) -> Result<()> {
        use crate::task_registry::RuntimeService as S;
        match service {
            // ── Core transport / session plane ────────────────────────────
            S::Listeners => {
                self.spawn_listeners().await?;
            }
            S::OutboundPeers => self.spawn_outbound_peers(),
            S::PinnedRelays => self.spawn_pinned_relays(config),

            // ── Observability / health ────────────────────────────────────
            S::MetricsExporter => {
                self.spawn_metrics_exporter(config).await?;
            }
            S::HealthWatchdog => self.spawn_health_watchdog(),

            // ── Maintenance / GC ──────────────────────────────────────────
            S::MaintenanceTick => self.spawn_maintenance_tick(
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(config.ipc.e2e_key_ttl_secs),
                config.mobile.clone(),
            ),
            S::PowPendingCleanup => self.spawn_pow_pending_cleanup(),
            S::GatewayEviction => self.spawn_gateway_eviction_task(),
            S::HandoffPrune => self.spawn_handoff_prune_task(std::time::Duration::from_secs(10)),
            S::TxRegistryPrune => {
                self.spawn_tx_registry_prune_task(std::time::Duration::from_secs(60))
            }

            // ── Routing / DHT ─────────────────────────────────────────────
            S::RouteProbe => self.spawn_route_probe_task_with(
                std::time::Duration::from_secs(config.routing.probe_min_interval_secs),
                std::time::Duration::from_secs(config.routing.probe_max_interval_secs),
                config.routing.probe_stability_threshold,
                config.mobile.clone(),
            ),
            S::RouteRefresh => self.spawn_route_refresh_task(std::time::Duration::from_secs(
                config.routing.reannounce_interval_secs,
            )),
            S::CongestionWithdraw => self.spawn_congestion_withdraw_task(),
            S::Mesh => self.spawn_mesh_tasks(config),
            S::DhtRepublish => self.spawn_dht_republish_task(std::time::Duration::from_secs(
                config.dht.republish_interval_secs,
            )),
            S::RouteMissHandler => self.spawn_route_miss_handler(
                config.routing.route_request_backoff_ms,
                config.routing.partition_score_threshold,
                config.routing.dht_fallback_timeout_ms,
                config.routing.dht_fallback_backpressure_threshold_pct,
                config.routing.dht_fallback_adaptive,
                config.routing.dht_fallback_priority_mult,
            ),
            S::Bootstrap => self.spawn_bootstrap_task(config),
            S::BootstrapWatchdog => self.spawn_bootstrap_watchdog_task(config),
            S::SovereignIdentityRepublish => self.spawn_sovereign_identity_republish_task(),
            S::PNetBanSync => self.spawn_p_net_ban_sync_task(),
            S::UpdateCheck => self.spawn_update_check_task(config),

            // ── Proxy / IPC / discovery ──────────────────────────────────
            S::DiscoveryInitiator => self.spawn_discovery_initiator_task(),
            S::Socks5 => self.spawn_socks5_task(config),
            S::ExitProxy => self.spawn_exit_proxy_task(config),
            S::IpcServer => self.spawn_ipc_server(config),
            S::PendingAckTick => self.spawn_pending_ack_tick(),
            S::GatewayFailover => self.spawn_gateway_failover_task(std::time::Duration::from_secs(
                config.connection.gateway_failover_delay_secs,
            )),
            S::PexInitiator => {
                if config.pex.enabled
                    && let Some(identity) = config.identity.as_ref()
                    && let Some(shutdown_tx) = &self.shutdown_tx
                {
                    let local_nonce = {
                        use base64::Engine as _;
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(&identity.nonce)
                            .unwrap_or_default();
                        if bytes.len() >= 8 {
                            u64::from_le_bytes([
                                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                                bytes[6], bytes[7],
                            ])
                        } else if bytes.len() >= 4 {
                            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
                        } else {
                            0
                        }
                    };
                    let pk_bytes = {
                        use base64::Engine as _;
                        base64::engine::general_purpose::STANDARD
                            .decode(&identity.public_key)
                            .unwrap_or_default()
                    };
                    let signing_key = if identity.algo == veil_cfg::SignatureAlgorithm::Ed25519
                        && let Ok(sk_bytes) = {
                            use base64::Engine as _;
                            base64::engine::general_purpose::STANDARD.decode(&identity.private_key)
                        }
                        && sk_bytes.len() == 32
                    {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&sk_bytes);
                        Some(ed25519_dalek::SigningKey::from_bytes(&arr))
                    } else {
                        None
                    };
                    // Take the PEX event receiver from the runtime (created once in start).
                    // On subsequent reloads `pex_event_rx` is `None` — the initiator task
                    // is already running and will pick up config changes via its own
                    // shutdown_rx. Only spawn once.
                    if let Some(pex_event_rx) = self.pex.event_rx.take()
                        && let Some(pex_connect_tx) = self.pex.connect_tx.clone()
                    {
                        // PEX moved to veil-pex; bridge concretes
                        // through trait-typed deps (FrameBroadcaster + PexLogger).
                        let broadcaster: Arc<dyn veil_types::FrameBroadcaster> =
                            Arc::new(veil_session::glue::SessionTxBroadcaster::new(Arc::clone(
                                &self.session_tx_registry,
                            )));
                        let pex_logger: Arc<dyn veil_pex::PexLogger> = self.logger.clone();
                        let handle = tokio::spawn(veil_pex::spawn_pex_initiator(
                            *self.identity.local_identity.node_id.as_bytes(),
                            pk_bytes,
                            local_nonce,
                            signing_key,
                            config.pex.clone(),
                            broadcaster,
                            Arc::clone(&self.pex.state),
                            pex_event_rx,
                            pex_connect_tx,
                            shutdown_tx.subscribe(),
                            pex_logger,
                        ));
                        lock_tasks(&self.tasks).background.push(handle);
                    }

                    // Spawn PEX connector task that reads discovered
                    // peers from the channel and initiates outbound connections.
                    if let Some(mut pex_connect_rx) = self.pex.connect_rx.take() {
                        let access = self.access();
                        let shutdown_tx_clone = shutdown_tx.clone();
                        let logger = Arc::clone(&self.logger);
                        let state = Arc::clone(&self.state);
                        let config_path = self.config_path.clone();
                        let handle = tokio::spawn(async move {
                            let mut shutdown_rx = shutdown_tx_clone.subscribe();
                            let mut peer_id_counter: u32 = 0xD000_0000;
                            loop {
                                tokio::select! {
                                    peers = pex_connect_rx.recv() => {
                                        let Some(peers) = peers else { break };
                                        for p in peers {
                                            // Skip if we already have an active session to this node.
                                            let already = {
                                                let reg = access.session_tx_registry
                                                    .read().unwrap_or_else(|e| e.into_inner());
                                                reg.active_node_ids().contains(&p.node_id)
                                            };
                                            if already {
                                                continue;
                                            }
                                            // Skip banned peers.
                                            if lock!(access.dispatcher.abuse.ban_list).is_banned(&p.node_id) {
                                                continue;
                                            }
                                            // dedup: claim happens inside
                                            // `spawn_outbound_peers` — if another caller
                                            // (configured peer, bootstrap, gateway-failover
                                            // earlier PEX walk) already owns a connector
                                            // task for this node_id, the spawn is a no-op
                                            // and the existing task's exponential backoff
                                            // continues unmolested. See the per-task slot
                                            // claim in `outbound_connector::spawn_outbound_peers`.
                                            use base64::Engine as _;
                                            let b64 = base64::engine::general_purpose::STANDARD;
                                            let peer_id = veil_cfg::PeerId::new(peer_id_counter);
                                            peer_id_counter = peer_id_counter.wrapping_add(1);
                                            let entry = crate::types::PeerConfigEntry {
                                                peer_id,
                                                node_id: veil_cfg::NodeId::from(p.node_id),
                                                public_key: b64.encode(&p.public_key),
                                                nonce: b64.encode(p.nonce.to_le_bytes()),
                                                transport: p.transport.clone(),
                                                algo: veil_cfg::SignatureAlgorithm::Ed25519,
                                                tls_cert: None,
                                                tls_key: None,
                                                tls_ca_cert: None,
                                                bootstrap_only: false,
                                                source: crate::types::PeerSource::Exchanged,
                                            };
                                            lock_state(&state).peers.insert(peer_id, entry.clone());
                                            logger.info(
                                                "pex.connect",
                                                format!(
                                                    "node_id={} addr={}",
                                                    veil_util::hex_short(&p.node_id),
                                                    veil_util::redact_addr_for_log(&p.transport),
                                                ),
                                            );
                                            let _ = crate::outbound_connector::spawn_outbound_peers(
                                                vec![entry], &access, &shutdown_tx_clone,
                                            );
                                        }
                                        // Persist all exchanged peers to disk.
                                        persist_discovered_peers(&state, &config_path);
                                    }
                                    _ = shutdown_rx.changed() => break,
                                }
                            }
                        });
                        lock_tasks(&self.tasks).background.push(handle);
                    }
                }
            }
            S::LazyMiner => {
                if let Some(identity) = config.identity.as_ref()
                    && let Some(shutdown_tx) = &self.shutdown_tx
                {
                    let handle = tokio::spawn(crate::lazy_miner::spawn_lazy_miner(
                        self.config_path.clone(),
                        identity.clone(),
                        self.metrics.clone(),
                        self.defaults.max_concurrent,
                        shutdown_tx.subscribe(),
                        Arc::clone(&self.logger),
                    ));
                    lock_tasks(&self.tasks).background.push(handle);
                }
            }

            // ── Persist snapshots ─────────────────────────────────────────
            // RouteCache/Rtt are not gated by `persist_enabled`; they only need
            // their path to be set. All other persist tasks require the
            // master switch.
            S::PersistRouteCache => {
                self.cache_persist_path = config.routing.cache_persist_path.clone();
                if let Some(ref path) = config.routing.cache_persist_path {
                    self.spawn_cache_persist_task(
                        path.clone(),
                        std::time::Duration::from_secs(config.routing.cache_persist_interval_secs),
                    );
                }
            }
            S::PersistRtt => {
                self.rtt_persist_path = config.routing.rtt_persist_path.clone();
                if let Some(ref path) = config.routing.rtt_persist_path {
                    self.spawn_rtt_persist_task(
                        path.clone(),
                        std::time::Duration::from_secs(config.routing.rtt_persist_interval_secs),
                    );
                }
            }
            S::PersistVivaldi => {
                if config.persist_enabled
                    && let Some(ref path) = config.routing.vivaldi_persist_path
                {
                    self.spawn_vivaldi_persist_task(
                        path.clone(),
                        std::time::Duration::from_secs(60),
                    );
                }
            }
            S::PersistDhtRouting => {
                if config.persist_enabled
                    && let Some(ref path) = config.dht.routing_persist_path
                {
                    self.spawn_dht_routing_persist_task(
                        path.clone(),
                        std::time::Duration::from_secs(120),
                    );
                }
            }
            S::PersistDhtValues => {
                if config.persist_enabled {
                    let path = config.dht.values_persist_path.clone().unwrap_or_else(|| {
                        let dir = self
                            .config_path
                            .parent()
                            .unwrap_or(std::path::Path::new("."));
                        dir.join("dht_values.json").to_string_lossy().into_owned()
                    });
                    self.spawn_dht_values_persist_task(path, std::time::Duration::from_secs(120));
                }
            }
            S::PersistAutodiscover => {
                if config.persist_enabled
                    && let Some(ref path) = config
                        .mesh
                        .as_ref()
                        .and_then(|m| m.autodiscover_persist_path.clone())
                {
                    self.spawn_autodiscover_persist_task(
                        path.clone(),
                        std::time::Duration::from_secs(60),
                    );
                }
            }
            S::PersistGatewayList => {
                if config.persist_enabled
                    && let Some(ref path) = config.routing.gateway_persist_path
                {
                    self.spawn_gateway_list_persist_task(
                        path.clone(),
                        std::time::Duration::from_secs(120),
                    );
                }
            }
            S::PersistPeerPubkeys => {
                if config.persist_enabled
                    && let Some(ref path) = config.routing.peer_pubkeys_persist_path
                {
                    self.spawn_peer_pubkeys_persist_task(
                        path.clone(),
                        std::time::Duration::from_secs(300),
                    );
                }
            }
            S::PersistTransportAnnouncements => {
                if config.persist_enabled
                    && let Some(ref path) = config.dht.transport_announcements_persist_path
                {
                    self.spawn_transport_announcements_persist_task(
                        path.clone(),
                        std::time::Duration::from_secs(
                            config.dht.transport_announcements_persist_interval_secs,
                        ),
                    );
                }
            }
        }
        Ok(())
    }

    /// spawn every service listed in `RuntimeService::ALL` using
    /// the exhaustive-match dispatcher [`Self::spawn_service`]. The two
    /// lifecycle paths that use this — cold start and hot reload — share the
    /// same ordering, so they can no longer drift out of sync.
    ///
    /// The gateway list reset + rebuild is not itself a background service —
    /// it is state mutation that must happen between `GatewayEviction` and
    /// `GatewayFailover`. Rather than invent a fake service for it, the
    /// reload path still performs that mutation inline. Start-up sets up the
    /// gateway list before calling this function for the same reason.
    pub async fn spawn_all_services(&mut self, config: &veil_cfg::Config) -> Result<()> {
        for &service in crate::task_registry::RuntimeService::ALL {
            self.spawn_service(service, config).await?;
        }
        Ok(())
    }

    /// Reload config without holding the outer `Arc<Mutex<NodeRuntime>>` during
    /// the 200 ms graceful-shutdown sleep inside `do_stop_tasks`.
    ///
    /// Prefer this over `reload` when the runtime is behind an `Arc<Mutex<…>>`
    /// so that concurrent admin commands are not starved.
    pub async fn reload_via_arc(rt: Arc<tokio::sync::Mutex<NodeRuntime>>) -> Result<()> {
        // (brief lock): load config and extract stop-tasks context.
        let (config, stop_ctx) = {
            let mut s = rt.lock().await;
            let config = veil_cfg::load_config(&s.config_path)?;
            let stop_ctx = s.take_stop_tasks_context();
            (config, stop_ctx)
        };
        // (no lock): task teardown — avoids holding the outer lock
        // during the 200 ms graceful-shutdown sleep + task abort.
        Self::do_stop_tasks(stop_ctx).await;
        // (lock held): apply new config and restart all tasks.
        // Remaining async work (init_mesh_realm, spawn_listeners
        // spawn_metrics_exporter) consists of network bind calls — typically < 50 ms.
        rt.lock().await.apply_reload_after_stop(config).await
    }

    /// **Push а config к the running daemon без going через the
    /// filesystem.**  Parses + validates `toml_content` first; on
    /// success, optionally persists к `self.config_path`, then
    /// performs the full stop → swap → restart cycle used by
    /// [`Self::reload_via_arc`].
    ///
    /// `persist = false` keeps the change in-memory only — useful для
    /// the messenger / embedded use case where the app owns config
    /// storage в а secure backend (Keychain, EncryptedSharedPreferences,
    /// future TPM-sealed store) и passing the bytes через POSIX file
    /// I/O would leak the plaintext к а readable inode.
    ///
    /// `persist = true` атомарно writes к `self.config_path` (через
    /// `veil_util::atomic_write` so а mid-write crash never produces
    /// truncated garbage) before applying.  Used by server-admin
    /// orchestration (Terraform / ansible / scripts) that wants new
    /// configs к survive daemon restarts.
    ///
    /// **Failure mode:** validation rejects the config (TOML parse
    /// error, missing required field, etc.) BEFORE any state change.
    /// The running daemon is left untouched; the returned `Err` carries
    /// the structured `ConfigError` for the caller к surface к the user.
    ///
    /// **Note on identity rotation:** an apply that changes the
    /// `[identity]` block rotates the daemon's keypair — peers will
    /// observe а node_id change и rebuild sessions от scratch.  Use
    /// sparingly; usually `[identity]` is fixed for the daemon's
    /// lifetime.
    pub async fn apply_config_bytes_via_arc(
        rt: Arc<tokio::sync::Mutex<NodeRuntime>>,
        toml_content: &str,
        persist: bool,
    ) -> Result<()> {
        // Phase 1 — validation (no daemon-state mutation).  Parse the
        // TOML и run the same validate-rules the on-disk reload path
        // runs.  Format currently hard-coded к TOML — JSON / future
        // formats can be added later если the messenger build needs
        // them.  `parse_toml_str` is exposed publicly through cfg::*
        // expressly для this use case (the `format` module is
        // pub, so we go through the helper).
        // audit U11: enforce signed-config on this runtime-injection path too.
        // The on-disk loader (`load_config`) refuses a non-Verified config when
        // `require_signed_config = true`; `apply-config` previously used a bare
        // parse with no signature check, so the policy was bypassable at runtime
        // and persisting an unsigned config would brick the next start.
        // `load_config_str` applies the identical gate (keyed on the supplied
        // config's flag, matching `load_config`).
        let config_path = rt.lock().await.config_path.clone();
        let config = veil_cfg::load_config_str(toml_content, &config_path)?;
        let validation = veil_cfg::validate(&config);
        if !validation.is_valid() {
            return Err(crate::error::NodeError::Config(
                veil_cfg::ConfigError::ValidationFailed(validation.format_issues()),
            ));
        }

        // Phase 2 — optional persistence.  Done BEFORE the
        // stop-swap-restart cycle so а crash mid-cycle leaves either
        // the OLD running config OR the persisted-but-not-yet-applied
        // new config on disk (next daemon start picks up the new one).
        if persist {
            persist_applied_config(&config_path, toml_content, &config)?;
        }

        // Phase 3 — stop the running services и apply the new config
        // via the existing reload pipeline.  Reuses `apply_reload_after_stop`
        // verbatim so behavior matches `Reload` exactly от this point on.
        let stop_ctx = {
            let mut s = rt.lock().await;
            s.take_stop_tasks_context()
        };
        Self::do_stop_tasks(stop_ctx).await;
        rt.lock().await.apply_reload_after_stop(config).await
    }

    pub fn access(&self) -> NodeServices {
        NodeServices {
            registry: Arc::clone(&self.registry),
            transport_ctx: Arc::clone(&self.transport_ctx),
            identity: Arc::clone(&self.identity),
            state: Arc::clone(&self.state),
            live_sessions: Arc::clone(&self.live_sessions),
            next_link_id: Arc::clone(&self.next_link_id),
            pending_accepts: Arc::clone(&self.pending_accepts),
            logger: Arc::clone(&self.logger),
            metrics: self.metrics.clone(),
            dispatcher: Arc::clone(&self.dispatcher),
            session_registry: Arc::clone(&self.session_registry),
            session_tx_registry: Arc::clone(&self.session_tx_registry),
            session_outbox: Arc::clone(&self.session_outbox),
            gateway_failover_notify: Arc::clone(&self.gateway_failover_notify),
            force_reconnect_notify: Arc::clone(&self.force_reconnect_notify),
            event_bus: Arc::clone(&self.event_bus),
            outbound_connector_node_ids: Arc::clone(&self.outbound_connector_node_ids),
            discovered_peers_cache: Arc::clone(&self.discovered_peers_cache),
            anonymity: Arc::clone(&self.anonymity),
            sessions_per_ip: Arc::clone(&self.sessions_per_ip),
            scanner_shield: Arc::clone(&self.scanner_shield),
            config_path: self.config_path.clone(),
            defaults: Arc::clone(&self.defaults),
            dht: Arc::clone(&self.dht),
            local_node_id: *self.identity.local_identity.node_id.as_bytes(),
            mobile: Arc::clone(&self.mobile),
            rtt_table: Arc::clone(&self.routing.rtt_table),
            resumption: Arc::clone(&self.resumption),
            handoff: Arc::clone(&self.handoff),
            allowed_peer_algos: self.allowed_peer_algos.clone(),
            network_gate: self.network_gate.as_ref().map(Arc::clone),
            verified_peer_certs: Arc::clone(&self.verified_peer_certs),
        }
    }

    pub fn state(&self) -> Arc<Mutex<NodeState>> {
        Arc::clone(&self.state)
    }

    pub async fn spawn_listeners(&mut self) -> Result<()> {
        let (shutdown_tx, _) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx.clone());

        let listens = self.listens();
        // Follow-up #2: collect ALL stealth listeners first, then wire
        // а single controller с the combined destination pool.  This
        // replaces the prior «refuse second stealth listener» error
        // path с even round-robin distribution across N destinations
        // (shared PoW/rate/max_concurrent policy fields enforced via
        // first-listener-canonical с per-extra match check).
        let mut stealth_listeners: Vec<ListenConfigEntry> = Vec::new();
        for listen in listens {
            // PoW-Gated Rendezvous Slice 5b: visibility=stealth listeners
            // skip the startup-time physical bind.  Their port comes alive
            // on-demand only после а valid PoW-gated request lands; the
            // controller (built here, stored on `NodeRuntime`) drives the
            // bind asynchronously through its BindClosure.  Operators que
            // configure `visibility = "stealth"` without an `[on_demand]`
            // block get а refusal (config-time validation should catch
            // this too once Slice 5c lands operator-docs).
            if listen.visibility.is_stealth() {
                stealth_listeners.push(listen);
                continue;
            }

            let uri = TransportUri::parse(&listen.transport)?;
            let listen_ctx = Arc::new(listen_transport_context(&self.transport_ctx, &listen)?);
            let listener = self.registry.bind(&uri, Arc::clone(&listen_ctx)).await?;
            let listener_handle =
                ListenerHandle::new(self.next_listener_handle.fetch_add(1, Ordering::Relaxed));
            let local_addr = listener.local_addr();
            {
                let mut state = self.lock_state();
                if let Some(entry) = state.listens.get_mut(&listen.listen_id) {
                    entry.listener_handle = Some(listener_handle);
                    entry.local_addr = Some(local_addr.clone());
                    entry.active = true;
                }
            }
            self.logger.info(
                "listen.start",
                format!(
                    "listen_id={} listener_handle={} local_addr={} transport={}",
                    listen.listen_id,
                    listener_handle,
                    veil_util::redact_addr_for_log(&local_addr),
                    veil_util::redact_addr_for_log(&listen.transport),
                ),
            );

            let state = Arc::clone(&self.state);
            let live_sessions = Arc::clone(&self.live_sessions);
            let event_bus = Arc::clone(&self.event_bus);
            let tasks = Arc::clone(&self.tasks);
            // cleanup: bundle replaces 7 individual Arc clones.
            let identity = Arc::clone(&self.identity);
            let next_link_id = Arc::clone(&self.next_link_id);
            let pending_accepts = Arc::clone(&self.pending_accepts);
            let logger = Arc::clone(&self.logger);
            let metrics = self.metrics.clone();
            let dispatcher = Arc::clone(&self.dispatcher);
            let session_registry = Arc::clone(&self.session_registry);
            let session_tx_registry = Arc::clone(&self.session_tx_registry);
            let session_outbox = Arc::clone(&self.session_outbox);
            let anonymity = Arc::clone(&self.anonymity);
            let sessions_per_ip = Arc::clone(&self.sessions_per_ip);
            let scanner_shield = Arc::clone(&self.scanner_shield);
            let rtt_table_for_probe = Arc::clone(&self.routing.rtt_table);
            let config_path_for_listener = self.config_path.clone();
            let defaults_for_listener = Arc::clone(&self.defaults);
            let mobile = Arc::clone(&self.mobile);
            let resumption_for_listener = Arc::clone(&self.resumption);
            let handoff_for_listener = Arc::clone(&self.handoff);
            let allowed_peer_algos_for_listener = self.allowed_peer_algos.clone();
            let network_gate_for_listener = self.network_gate.as_ref().map(Arc::clone);
            let verified_peer_certs_for_listener = Arc::clone(&self.verified_peer_certs);
            // pre-spawn semaphore: limits concurrent IN-FLIGHT
            // handshake tasks (pre-`live_sessions`-cap window). Without this
            // an inbound TCP flood spawns unbounded tokio tasks before the
            // post-handshake `max_concurrent` check kicks in, pinning ~5 KB
            // per pending handshake. Capacity derived от `max_concurrent`
            // at NodeRuntime construction (see `inbound_handshake_sem` field).
            let inbound_sem = Arc::clone(&self.inbound_handshake_sem);
            let mut shutdown_rx = shutdown_tx.subscribe();
            let listen_id = listen.listen_id;

            // ── Phase 5f Step 3 — ephemeral-port rotation ────────────────
            // Per-listener swap channel allows the rotator's consumer task
            // к replace the listener mid-flight without restarting the
            // accept loop.  Capacity 2 gives slack для а rotation event
            // arriving while the loop is still busy с the previous one.
            let (listener_swap_tx, mut listener_swap_rx) =
                tokio::sync::mpsc::channel::<Box<dyn veil_transport::TransportListener>>(2);
            if let Some(eph) = listen.ephemeral.as_ref() {
                self.wire_ephemeral_rotator_for_listen(
                    listen.listen_id,
                    &uri,
                    listen.advertise.as_deref(),
                    eph,
                    Arc::clone(&listen_ctx),
                    listener_swap_tx.clone(),
                )?;
            }
            // Keep `listener_swap_tx` alive в the captured task — dropping
            // it would close the channel и prevent late rotations from
            // landing (even though rotator is task-spawned, the tx half
            // here is the canonical owner since the rotator-consumer
            // gets а cloned tx).
            let _swap_tx_keepalive = listener_swap_tx;

            let handle = tokio::spawn(async move {
                let mut current_listener = listener;
                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => break,
                        // ── Listener swap (Phase 5f Step 3) ────────────
                        // Rotator-consumer pushes а freshly bound listener
                        // here.  Replace the current one и loop back; the
                        // old listener drops here, closing its socket.
                        // Existing accepted connections (already handed
                        // off к session-spawn tasks) are unaffected.
                        Some(new_listener) = listener_swap_rx.recv() => {
                            let new_addr = new_listener.local_addr();
                            logger.info(
                                "listen.swap",
                                format!(
                                    "listen_id={listen_id} listener_handle={listener_handle} \
                                     swapping to new_local_addr={new_addr}",
                                ),
                            );
                            current_listener = new_listener;
                            // Update the published local_addr на the state
                            // entry so admin surfaces reflect the new port.
                            {
                                let mut state_lock = lock!(state);
                                if let Some(entry) = state_lock.listens.get_mut(&listen_id) {
                                    entry.local_addr = Some(new_addr);
                                }
                            }
                            continue;
                        }
                        accepted = current_listener.accept() => match accepted {
                            Ok(connection) => {
                                // drop connections from IPs the scanner-shield
                                // has soft-banned (port scanners, HTTP probes that previously
                                // sent invalid-magic frames). Skips spawning the inbound
                                // task entirely so we don't pay parse/log/metric cost per
                                // garbage handshake.
                                let banned_ip = connection
                                    .peer_meta()
                                    .remote_addr
                                    .map(|sa| sa.ip())
                                    .filter(|ip| scanner_shield.is_banned(*ip));
                                if let Some(ip) = banned_ip {
                                    logger.info(
                                        "session.accept.scanner_dropped",
                                        format!(
                                            "listen_id={} listener_handle={} remote_ip={}",
                                            listen_id, listener_handle, ip
                                        ),
                                    );
                                    drop(connection);
                                    continue;
                                }
                                // j: demoted к DEBUG. Under sustained
                                // peer-retry-after-ban patterns this fires ~30/sec на bootstrap;
                                // operational visibility preserved via
                                // `veil_inbound_sessions_total` counter.
                                logger.debug(
                                    "session.accept",
                                    format!(
                                        "listen_id={} listener_handle={}",
                                        listen_id, listener_handle
                                    ),
                                );
                                let connection = if let Some(waiter) = pop_accept_waiter(&pending_accepts, listen_id) {
                                    match waiter.send((listener_handle, connection)) {
                                        Ok(()) => continue,
                                        Err((_, connection)) => connection,
                                    }
                                } else {
                                    connection
                                };
                                // pre-spawn inbound-handshake cap.
                                // Sem permit MUST be acquired before tokio::spawn so an
                                // inbound flood cannot exhaust task-allocator/memory
                                // before the post-handshake `max_concurrent` gate triggers.
                                let permit = match Arc::clone(&inbound_sem).try_acquire_owned() {
                                    Ok(p) => p,
                                    Err(_) => {
                                        logger.info(
                                            "session.accept.capacity_dropped",
                                            format!(
                                                "listen_id={} listener_handle={} — \
                                                 in-flight handshake cap reached, dropping inbound",
                                                listen_id, listener_handle
                                            ),
                                        );
                                        drop(connection);
                                        continue;
                                    }
                                };
                                let handle = spawn_inbound_session(
                                    InboundSessionContext {
                                        runtime: SessionRuntimeContext {
                                            identity:            Arc::clone(&identity),
                                            state:               Arc::clone(&state),
                                            live_sessions:       Arc::clone(&live_sessions),
                                            event_bus:           Arc::clone(&event_bus),
                                            next_link_id:        Arc::clone(&next_link_id),
                                            logger:              Arc::clone(&logger),
                                            metrics:             metrics.clone(),
                                            dispatcher:          Arc::clone(&dispatcher),
                                            session_registry:    Arc::clone(&session_registry),
                                            session_tx_registry: Arc::clone(&session_tx_registry),
                                            session_outbox:      Arc::clone(&session_outbox),
                                            anonymity: Arc::clone(&anonymity),
                                            sessions_per_ip:     Arc::clone(&sessions_per_ip),
                                            scanner_shield:      Arc::clone(&scanner_shield),
                                            defaults:       Arc::clone(&defaults_for_listener),
                                            rtt_table: Arc::clone(&rtt_table_for_probe),
                                            config_path: config_path_for_listener.clone(),
                                            mobile: Arc::clone(&mobile),
                                            resumption:    Arc::clone(&resumption_for_listener),
                                            handoff:            Arc::clone(&handoff_for_listener),
                                            allowed_peer_algos:             allowed_peer_algos_for_listener.clone(),
                                            network_gate:           network_gate_for_listener.as_ref().map(Arc::clone),
                                            verified_peer_certs:    Arc::clone(&verified_peer_certs_for_listener),
                                        },
                                        listen_id,
                                        listener_handle,
                                    },
                                    connection,
                                );
                                // wrap handle к keep `permit` alive
                                // for the duration of the spawned task. Permit auto-drops on
                                // task exit (success or handshake-timeout), freeing one slot
                                // back to `inbound_handshake_sem`.
                                let wrapped = tokio::spawn(async move {
                                    let _permit = permit;
                                    let _ = handle.await;
                                });
                                push_session_handle(&tasks, wrapped);
                            }
                            Err(err) => {
                                logger.warn(
                                    "listen.accept_error",
                                    format!(
                                        "listen_id={} listener_handle={} error={}",
                                        listen_id, listener_handle, err
                                    ),
                                );
                            }
                        }
                    }
                }
                // Mark listener inactive when the task exits (shutdown or fatal error)
                let mut state = lock_state(&state);
                if let Some(entry) = state.listens.get_mut(&listen_id) {
                    entry.active = false;
                    entry.listener_handle = None;
                    entry.local_addr = None;
                }
            });
            lock_tasks(&self.tasks).listeners.push(handle);
        }

        // Follow-up #2: wire all stealth listeners as а SINGLE
        // controller with а multi-destination policy.  No-op когда
        // zero stealth listeners были configured.
        if !stealth_listeners.is_empty() {
            self.wire_rendezvous_controller_for_stealth(&stealth_listeners)?;
        } else {
            // Audit L-12: on a reload that REMOVED all stealth listeners, the
            // controller would otherwise survive — the strong Arc and the
            // dispatcher's Weak (Arc-cloned across reload in build_reload_
            // dispatcher) are set only in wire_rendezvous_controller_for_stealth
            // and cleared only in Drop. A subsequent PoW-gated rendezvous
            // request would then upgrade the stale Weak and bind an on-demand
            // port for a listener the operator just removed. Clear both so the
            // controller is dropped with its now-removed listeners.
            *veil_util::lock!(self.rendezvous_controller) = None;
            *veil_util::lock!(self.dispatcher.rendezvous_weak) = None;
        }

        Ok(())
    }

    /// Phase 5f Step 3 — bridge between а listen entry's
    /// `EphemeralConfig` и the rotator + consumer pipeline в
    /// [`super::ephemeral_rotator::wire_ephemeral_rotator`].  Resolves
    /// the identity signing key + node_id from runtime state и stores
    /// the rotator+consumer JoinHandles в `self.tasks` for clean
    /// shutdown.
    ///
    /// Refuses when the local identity is не Ed25519 — veil-proto's
    /// `sign_transport_migration_notify` signs с ed25519-dalek и does
    /// not support hybrid keys yet.  Operator must either drop the
    /// `ephemeral` config block on the listen или migrate the node к
    /// а pure-Ed25519 identity.
    #[allow(clippy::too_many_arguments)]
    fn wire_ephemeral_rotator_for_listen(
        &mut self,
        listen_id: ListenId,
        listen_uri: &TransportUri,
        advertise: Option<&str>,
        eph: &veil_cfg::EphemeralConfig,
        listen_ctx: Arc<TransportContext>,
        listener_swap_tx: tokio::sync::mpsc::Sender<Box<dyn veil_transport::TransportListener>>,
    ) -> Result<()> {
        // Identity must be Ed25519 — wire frame's sig path uses
        // ed25519-dalek directly.  Fail fast at startup rather than
        // log-and-skip so the operator's config-error surfaces.
        let algo = self.identity.local_identity.algo;
        if !matches!(algo, veil_cfg::SignatureAlgorithm::Ed25519) {
            return Err(NodeError::Unsupported(format!(
                "listen_id={listen_id} ephemeral rotation requires Ed25519 identity, got {algo:?} \
                 — drop the [listen.ephemeral] block or migrate identity",
            )));
        }
        // Decode the base64 private key to а raw 32-byte seed.
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let raw = STANDARD
            .decode(self.identity.local_identity.private_key.trim())
            .map_err(|e| {
                NodeError::InvalidArgument(format!(
                    "listen_id={listen_id} identity sk base64 decode failed: {e}",
                ))
            })?;
        if raw.len() != 32 {
            return Err(NodeError::InvalidArgument(format!(
                "listen_id={listen_id} identity sk has {} bytes, expected 32",
                raw.len(),
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);

        // Parse the advertise URI if set (operator's external host).
        let advertise_uri = advertise.and_then(|s| TransportUri::parse(s).ok());

        let local_node_id: [u8; 32] = *self.identity.local_identity.node_id.as_bytes();

        let handles = super::ephemeral_rotator::wire_ephemeral_rotator(
            eph,
            listen_uri,
            advertise_uri.as_ref(),
            local_node_id,
            signing_key,
            Arc::clone(&self.session_tx_registry),
            Arc::clone(&self.registry),
            listen_ctx,
            listener_swap_tx,
            Arc::clone(&self.logger),
            listen_id.to_string(),
        )
        .map_err(|e| {
            NodeError::InvalidArgument(format!(
                "listen_id={listen_id} ephemeral rotator wiring failed: {e}",
            ))
        })?;

        // Store JoinHandles so shutdown cleanly aborts both tasks.
        // The `shutdown` watch sender is dropped с the tasks block —
        // its drop signals the rotator's internal channels к close.
        let mut tasks = lock_tasks(&self.tasks);
        tasks.listeners.push(handles.rotator);
        tasks.listeners.push(handles.consumer);
        drop(tasks);
        // Stash the shutdown sender so the rotator loop's
        // `shutdown_rx.changed()` arm does NOT fire immediately on
        // sender-drop (which would exit the loop before any rotation
        // ever happens).  Runtime shutdown sends `true` on each сидер
        // в this list during graceful exit; until then the senders
        // sit idle и the rotator just sleeps on its rotation interval.
        veil_util::lock!(self.ephemeral_rotator_shutdowns).push(handles.shutdown);

        self.logger.info(
            "listen.rotation.spawned",
            format!(
                "listen_id={listen_id} rotation={} grace={} range={}..={}",
                eph.rotation, eph.grace_period, eph.range.0, eph.range.1,
            ),
        );
        Ok(())
    }

    /// PoW-Gated Rendezvous Slice 5c: build the rendezvous controller
    /// для **all** `visibility = "stealth"` listeners и attach the
    /// resulting controller к the dispatcher via а weak ref.  Follow-up #2
    /// (multi-stealth) — replaces the prior one-listener-only path с а
    /// single controller pooling N destination triples (port range +
    /// advertise host + scheme) with unified policy fields shared from
    /// the first listener's `[on_demand]` block.
    ///
    /// Constraints enforced:
    /// * Every listener must include а `[listen.on_demand]` section.
    /// * Identity must be Ed25519 (wire sig path).
    /// * Every listener's `pow_difficulty`, `rate_limit`, and
    ///   `max_concurrent` MUST match the first listener's — these are
    ///   *node-wide* policy fields, not per-destination.
    ///
    /// **Scope (Slice 5c + follow-up #2):** ships the **production**
    /// `RendezvousBinder` що (а) clones the base `TransportContext` +
    /// sets per-request `obfs4_psk`, (b) calls `TransportRegistry::bind(uri, ctx).await`,
    /// (c) spawns а bounded accept task (TTL + accept-budget).  Multi-
    /// destination grants round-robin across all configured stealth
    /// listeners (см. [`RendezvousController::pick_destination`]).
    /// The binder is wired against the FIRST stealth listener's
    /// `AcceptBundle` для observability — `session.accept` events
    /// carry that listener_handle even когда the grant came от an
    /// extra destination's port range.
    fn wire_rendezvous_controller_for_stealth(&self, listens: &[ListenConfigEntry]) -> Result<()> {
        use super::rendezvous_binder::{AcceptBundle, RendezvousBinder};
        use ed25519_dalek::SigningKey;
        use std::sync::Arc;
        use veil_session::rendezvous::{
            AdvertiseDestination, RendezvousController, RendezvousPolicy,
        };

        if listens.is_empty() {
            return Ok(());
        }

        // Identity must be Ed25519 — wire frame's sig path uses
        // ed25519-dalek.  Same constraint as Phase 5e migration notify
        // и Phase 5f ephemeral rotator.
        let algo = self.identity.local_identity.algo;
        if !matches!(algo, veil_cfg::SignatureAlgorithm::Ed25519) {
            return Err(NodeError::Unsupported(format!(
                "stealth rendezvous requires Ed25519 identity, got {algo:?}",
            )));
        }
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let raw = STANDARD
            .decode(self.identity.local_identity.private_key.trim())
            .map_err(|e| NodeError::InvalidArgument(format!("stealth identity sk base64: {e}")))?;
        if raw.len() != 32 {
            return Err(NodeError::InvalidArgument(format!(
                "stealth identity sk has {} bytes (expected 32)",
                raw.len(),
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        let signing_key = SigningKey::from_bytes(&seed);

        let local_node_id: [u8; 32] = *self.identity.local_identity.node_id.as_bytes();

        // Validate every listener has an on_demand block + matches
        // the first listener's shared policy fields.
        let first = &listens[0];
        let first_listen_id = first.listen_id;
        let Some(first_on_demand) = first.on_demand.as_ref() else {
            return Err(NodeError::Unsupported(format!(
                "listen_id={first_listen_id} visibility=stealth requires а [listen.on_demand] block",
            )));
        };
        for extra in listens.iter().skip(1) {
            let id = extra.listen_id;
            let Some(od) = extra.on_demand.as_ref() else {
                return Err(NodeError::Unsupported(format!(
                    "listen_id={id} visibility=stealth requires а [listen.on_demand] block",
                )));
            };
            if od.pow_difficulty != first_on_demand.pow_difficulty {
                return Err(NodeError::InvalidArgument(format!(
                    "listen_id={id} pow_difficulty={} differs от first stealth listener's {} (must match — node-wide policy)",
                    od.pow_difficulty, first_on_demand.pow_difficulty,
                )));
            }
            if od.rate_limit != first_on_demand.rate_limit {
                return Err(NodeError::InvalidArgument(format!(
                    "listen_id={id} rate_limit={} differs от first stealth listener's {} (must match — node-wide policy)",
                    od.rate_limit, first_on_demand.rate_limit,
                )));
            }
            if od.max_concurrent != first_on_demand.max_concurrent {
                return Err(NodeError::InvalidArgument(format!(
                    "listen_id={id} max_concurrent={} differs от first stealth listener's {} (must match — node-wide policy)",
                    od.max_concurrent, first_on_demand.max_concurrent,
                )));
            }
        }

        // Parse the FIRST listener's advertise/transport URI into а
        // (host, scheme) pair — those drive the primary destination.
        let primary_uri_str = first
            .advertise
            .clone()
            .unwrap_or_else(|| first.transport.clone());
        let primary_parsed = TransportUri::parse(&primary_uri_str).map_err(|e| {
            NodeError::InvalidArgument(format!("listen_id={first_listen_id} advertise: {e}",))
        })?;
        // Use TransportUri::host() (not plaintext_host) — plaintext_host
        // returns None for AEAD/TLS schemes by design (DPI-visibility
        // classification).  Стealth listeners primarily use obfs4-tcp
        // where plaintext_host=None, но we still need the host string
        // для composing the response URI.
        let primary_advertise_host = primary_parsed
            .host()
            .ok_or_else(|| {
                NodeError::InvalidArgument(format!(
                    "listen_id={first_listen_id} advertise URI has no host (unix scheme не supported для stealth)",
                ))
            })?
            .to_owned();
        let primary_scheme = primary_parsed.scheme().to_owned();
        let primary_bind_host = primary_parsed.host().unwrap_or("0.0.0.0").to_owned();
        let mut policy = RendezvousPolicy::from_on_demand_config(
            first_on_demand,
            &primary_bind_host,
            &primary_advertise_host,
            &primary_scheme,
        )
        .map_err(|e| {
            NodeError::InvalidArgument(
                format!("listen_id={first_listen_id} on_demand policy: {e}",),
            )
        })?;

        // Build AdvertiseDestination для each extra listener.
        for extra in listens.iter().skip(1) {
            let id = extra.listen_id;
            let od = extra.on_demand.as_ref().expect("on_demand checked above");
            let uri_str = extra
                .advertise
                .clone()
                .unwrap_or_else(|| extra.transport.clone());
            let parsed = TransportUri::parse(&uri_str).map_err(|e| {
                NodeError::InvalidArgument(format!("listen_id={id} advertise: {e}"))
            })?;
            let adv_host = parsed
                .host()
                .ok_or_else(|| {
                    NodeError::InvalidArgument(format!(
                        "listen_id={id} advertise URI has no host (unix scheme не supported)",
                    ))
                })?
                .to_owned();
            let scheme = parsed.scheme().to_owned();
            let bind_host = parsed.host().unwrap_or("0.0.0.0").to_owned();
            let (port_lo, port_hi) = od.range;
            if port_lo > port_hi {
                return Err(NodeError::InvalidArgument(format!(
                    "listen_id={id} [on_demand].range start > end",
                )));
            }
            let ttl = veil_transport::rotation::parse_duration_spec(&od.ttl)
                .map_err(|e| NodeError::InvalidArgument(format!("listen_id={id} ttl: {e}")))?;
            policy.extra_destinations.push(AdvertiseDestination {
                slot_config: veil_transport::on_demand::OnDemandConfig {
                    host: bind_host,
                    port_range: port_lo..=port_hi,
                    bind_retries: od.bind_retries,
                    ttl,
                    max_accepts: od.max_accepts,
                },
                advertise_host: adv_host,
                scheme,
            });
        }

        // Slice 5c production binder: clones base TransportContext +
        // per-request PSK, calls registry.bind, spawns а bounded
        // accept task що calls spawn_inbound_session per accepted
        // connection.  Listener allocated а fresh ListenerHandle so
        // observability (`session.accept` events) carries а unique
        // identifier per stealth slot.  Multi-stealth: uses FIRST
        // listener's listen_id for accept-event accounting.
        let listener_handle =
            ListenerHandle::new(self.next_listener_handle.fetch_add(1, Ordering::Relaxed));
        // Build the SessionRuntimeContext template once; cheap к
        // clone per-accept (all Arc fields inside).
        let session_ctx_template = SessionRuntimeContext {
            identity: Arc::clone(&self.identity),
            state: Arc::clone(&self.state),
            live_sessions: Arc::clone(&self.live_sessions),
            event_bus: Arc::clone(&self.event_bus),
            next_link_id: Arc::clone(&self.next_link_id),
            logger: Arc::clone(&self.logger),
            metrics: self.metrics.clone(),
            dispatcher: Arc::clone(&self.dispatcher),
            session_registry: Arc::clone(&self.session_registry),
            session_tx_registry: Arc::clone(&self.session_tx_registry),
            session_outbox: Arc::clone(&self.session_outbox),
            anonymity: Arc::clone(&self.anonymity),
            sessions_per_ip: Arc::clone(&self.sessions_per_ip),
            scanner_shield: Arc::clone(&self.scanner_shield),
            defaults: Arc::clone(&self.defaults),
            rtt_table: Arc::clone(&self.routing.rtt_table),
            config_path: self.config_path.clone(),
            mobile: Arc::clone(&self.mobile),
            resumption: Arc::clone(&self.resumption),
            handoff: Arc::clone(&self.handoff),
            allowed_peer_algos: self.allowed_peer_algos.clone(),
            network_gate: self.network_gate.as_ref().map(Arc::clone),
            verified_peer_certs: Arc::clone(&self.verified_peer_certs),
        };
        let accept_bundle = AcceptBundle {
            ctx: session_ctx_template,
            listen_id: first_listen_id,
            listener_handle,
            inbound_sem: Arc::clone(&self.inbound_handshake_sem),
            pending_accepts: Arc::clone(&self.pending_accepts),
            tasks: Arc::clone(&self.tasks),
        };
        let binder = RendezvousBinder {
            registry: Arc::clone(&self.registry),
            base_ctx: Arc::clone(&self.transport_ctx),
            accept: accept_bundle,
        };

        let controller = Arc::new(
            RendezvousController::new_with_metrics(
                policy,
                local_node_id,
                signing_key,
                Arc::new(binder),
                self.metrics.clone(),
            )
            .map_err(|e| {
                NodeError::InvalidArgument(format!("stealth-pool controller construct: {e}",))
            })?,
        );

        // Store the strong Arc on NodeRuntime, the Weak on the dispatcher.
        {
            let mut slot = veil_util::lock!(self.rendezvous_controller);
            *slot = Some(Arc::clone(&controller));
        }
        {
            let mut weak_slot = veil_util::lock!(self.dispatcher.rendezvous_weak);
            *weak_slot = Some(Arc::downgrade(&controller));
        }

        let destination_count = controller.destination_count();
        let listen_ids: Vec<String> = listens.iter().map(|l| l.listen_id.to_string()).collect();
        self.logger.info(
            "rendezvous.controller.wired",
            format!(
                "listen_ids=[{}] destinations={destination_count} pow_difficulty={} \
                 ttl={} rate_limit={} max_concurrent={} stealth_listener=true binder=production",
                listen_ids.join(","),
                first_on_demand.pow_difficulty,
                first_on_demand.ttl,
                first_on_demand.rate_limit,
                first_on_demand.max_concurrent,
            ),
        );
        Ok(())
    }

    pub async fn spawn_metrics_exporter(&mut self, config: &veil_cfg::Config) -> Result<()> {
        let Some(metrics) = self.metrics.clone() else {
            return Ok(());
        };
        let Some(metrics_cfg) = config.metrics.as_ref() else {
            return Ok(());
        };
        let path = self
            .metrics_path
            .clone()
            .unwrap_or_else(|| "/metrics".to_owned());
        let Some(shutdown_tx) = self.shutdown_tx.as_ref() else {
            self.logger.warn(
                "metrics.spawn",
                "metrics exporter skipped: shutdown channel not initialised",
            );
            return Ok(());
        };
        let shutdown_rx = shutdown_tx.subscribe();
        let state_probe = crate::metrics_http::RuntimeStateProbe {
            live_sessions: Arc::clone(&self.live_sessions),
            session_tx_registry: Arc::clone(&self.session_tx_registry),
            session_outbox: Arc::clone(&self.session_outbox),
            ban_list: Arc::clone(&self.ban_list),
            dispatcher: Arc::clone(&self.dispatcher),
            discovered_peers_cache: Arc::clone(&self.discovered_peers_cache),
        };
        let (local_addr, handle) = crate::metrics_http::spawn_metrics_http(
            &self.registry,
            Arc::clone(&self.transport_ctx),
            metrics,
            Arc::clone(&self.runtime_summary),
            &metrics_cfg.listen,
            &path,
            metrics_cfg.auth_token.clone(),
            metrics_cfg.allow_unauthenticated_remote_metrics,
            Arc::clone(&self.logger),
            shutdown_rx,
            state_probe,
        )
        .await?;
        self.metrics_endpoint = Some(local_addr.clone());
        {
            let mut state = self.lock_state();
            state.metrics_endpoint = Some(local_addr.clone());
        }
        self.logger.info(
            "metrics.start",
            format!("endpoint={} path={}", local_addr, path),
        );
        lock_tasks(&self.tasks).listeners.push(handle);
        Ok(())
    }

    /// Initialize the optional UDP mesh realm from config.
    pub async fn init_mesh_realm(config: &veil_cfg::Config) -> Option<Arc<UdpRealm>> {
        let mesh_cfg = config.mesh.as_ref()?;
        let addr: std::net::SocketAddr = mesh_cfg.bind_addr.parse().ok()?;
        let s = mesh_cfg.realm_id.trim();
        let realm_id = veil_util::hex_to_array::<16>(s).ok()?;
        use veil_proto::mesh::RealmId;
        // Opt-in UDP obfuscation (audit follow-up D): decode the base64
        // `realm_psk`. A configured-but-invalid PSK is a HARD error — disable
        // the mesh rather than silently fall back to plaintext, which would
        // defeat the operator's intent to obfuscate. Unset/empty => plaintext.
        let realm_psk = match mesh_cfg.realm_psk.as_deref().map(str::trim) {
            Some(b64) if !b64.is_empty() => {
                use base64::{Engine as _, engine::general_purpose::STANDARD};
                match STANDARD.decode(b64) {
                    Ok(bytes) if bytes.len() >= 16 => Some(bytes),
                    Ok(bytes) => {
                        log::error!(
                            "veil-mesh: [mesh] realm_psk decodes to {} bytes (need >=16); mesh disabled",
                            bytes.len()
                        );
                        return None;
                    }
                    Err(e) => {
                        log::error!(
                            "veil-mesh: [mesh] realm_psk is not valid base64 ({e}); mesh disabled"
                        );
                        return None;
                    }
                }
            }
            _ => None,
        };
        match UdpRealm::bind(addr, RealmId(realm_id), realm_psk.as_deref()).await {
            Ok(realm) => Some(Arc::new(realm)),
            // Audit M-D: log the bind failure instead of silently disabling mesh.
            // A reload that races the old socket's release (or a genuinely
            // occupied port) is otherwise invisible to the operator.
            Err(e) => {
                log::warn!("veil-mesh: UdpRealm bind to {addr} failed, mesh disabled: {e}");
                None
            }
        }
    }
}

/// Persist an applied config to disk, preserving a signed bundle's signature.
///
/// Audit M5 (completing U11): a SIGNED config bundle must be persisted
/// byte-for-byte. `save_config` round-trips through the TOML `patch_existing`
/// strategy, which normalises the file and drops the
/// `# VEIL_CONFIG_SIGNATURE_V1:` header comment — so the persisted file
/// would no longer verify, and the NEXT daemon start with
/// `require_signed_config = true` would refuse to boot (a self-brick on the
/// very path the U11 gate was meant to protect). When the supplied
/// `toml_content` carries a signature header (already signature-verified by
/// `load_config_str` at the call site), write the exact bytes so the signature
/// survives.
///
/// Unsigned configs keep the `save_config` path (atomic_write +
/// comment-preserving TOML patch of the existing file).
pub(crate) fn persist_applied_config(
    config_path: &std::path::Path,
    toml_content: &str,
    config: &veil_cfg::Config,
) -> Result<()> {
    if veil_cfg::signed_config::has_signature_header(toml_content) {
        veil_util::atomic_write(config_path, toml_content.as_bytes())?;
    } else {
        veil_cfg::save_config(config_path, config)?;
    }
    Ok(())
}

#[cfg(test)]
mod m5_persist_tests {
    use super::*;

    /// Audit M5: persisting a signed config must keep it verifiable. The old
    /// unconditional `save_config` stripped the signature header (TOML
    /// patch/render), self-bricking a `require_signed_config` daemon on its
    /// next boot. The verbatim write must preserve the exact signed bytes.
    #[test]
    fn signed_config_persisted_verbatim_keeps_signature_m5() {
        use veil_cfg::SignatureAlgorithm;
        use veil_cfg::signed_config::{has_signature_header, sign_config};

        let kp = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519);
        let body = "node_role = \"core\"\n";
        let signed = sign_config(
            body,
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .expect("sign");
        assert!(
            has_signature_header(&signed),
            "precondition: signed has header"
        );

        let path = std::env::temp_dir().join("m5-signed-persist-test.toml");
        let _ = std::fs::remove_file(&path);

        // `config` is unused on the signed path; `Default` is fine here.
        persist_applied_config(&path, &signed, &veil_cfg::Config::default()).expect("persist");

        let read_back = std::fs::read_to_string(&path).expect("read back");
        assert!(
            has_signature_header(&read_back),
            "signed config must be persisted verbatim — signature header preserved"
        );
        assert_eq!(
            read_back, signed,
            "persisted bytes must be byte-for-byte the signed bundle"
        );
        let _ = std::fs::remove_file(&path);
    }
}
