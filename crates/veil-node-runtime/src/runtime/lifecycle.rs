//! Lifecycle methods extracted from `runtime/mod.rs` (
//! refactor follow-up).
//!
//! Holds the start-time `stop` / `reload` / `apply_reload_after_stop`
//! flow plus the helpers that run after the runtime mutex is released
//! (`do_stop_flushes`, `do_stop_tasks`). These live in their own file
//! purely to bound `mod.rs` size — no behavioural change vs the
//! pre-refactor inline definitions.

// NOTE: imports kept identical to `runtime/mod.rs` so any helper or type
// referenced inside the lifted methods continues to resolve unchanged.
// Some imports may be unused here (the linter can prune later); we
// favour zero-behaviour-change over a tight import set during the
// initial split.
use std::sync::{Arc, Mutex, atomic::AtomicU32};
#[allow(unused_imports)]
use veil_util::{lock, rlock, wlock};

#[allow(unused_imports)]
use tokio::{
    io::AsyncWriteExt,
    sync::{oneshot, watch},
    task::JoinHandle,
};

#[allow(unused_imports)]
use veil_cfg::{self, Config};

#[allow(unused_imports)]
use crate::error::{NodeError, Result};
use crate::listener_supervisor::lock_waiters;
use crate::local_identity::HandshakeIdentity;
use crate::metrics_http::RuntimeSummary;
use veil_abuse::{BanList, PerPeerLimiter, ViolationTracker};
use veil_app::AppEndpointRegistry;
use veil_dht::KademliaService;
use veil_discovery::DiscoveryService;
use veil_dispatcher::FrameDispatcher;
use veil_gateway::GatewayService;
use veil_mesh::{GatewayBridge, MeshForwarder, NeighborTable};
use veil_routing::{NeighborScorer, RouteCache, RttTable, VivaldiCoord};
use veil_session::SessionRegistry;

use super::identity_loaders::{load_falcon_signer, load_signing_key};
use super::{
    NodeRuntime, PeerPubkeySnapshot, RuntimeTasks, StopFlushContext, StopTasksContext,
    build_advertised_transports, build_relay_node_ids, build_state, build_target_labels,
    lock_tasks, resolve_metrics_path,
};

impl NodeRuntime {
    pub fn collect_stop_flush_context(&self) -> StopFlushContext {
        StopFlushContext {
            cache_persist_path: self.cache_persist_path.clone(),
            rtt_persist_path: self.rtt_persist_path.clone(),
            persist_enabled: self.persist_enabled,
            config_path: self.config_path.clone(),
            rtt_table: Arc::clone(&self.routing.rtt_table),
            route_cache: Arc::clone(&self.routing.route_cache),
            logger: Arc::clone(&self.logger),
            dht: Arc::clone(&self.dht),
            autodiscovered_peers: Arc::clone(&self.autodiscovered_peers),
            gateway_list: Arc::clone(&self.gateway_list),
            peer_pubkeys: Arc::clone(&self.identity.peer_pubkeys),
            local_vivaldi: self.dispatcher.local_vivaldi.clone(),
            discovered_peers_cache: Arc::clone(&self.discovered_peers_cache),
        }
    }

    /// Extract data needed to run stop_tasks (sync, takes `shutdown_tx` from self).
    pub fn take_stop_tasks_context(&mut self) -> StopTasksContext {
        StopTasksContext {
            session_tx_registry: Arc::clone(&self.session_tx_registry),
            shutdown_tx: self.shutdown_tx.take(),
            pending_accepts: Arc::clone(&self.pending_accepts),
            tasks: Arc::clone(&self.tasks),
            logger: Arc::clone(&self.logger),
            // Audit M7: DRAIN the rotator shutdown senders so `do_stop_tasks`
            // can signal them and the list does not grow across reloads.
            ephemeral_rotator_shutdowns: std::mem::take(&mut *lock!(
                self.ephemeral_rotator_shutdowns
            )),
        }
    }

    /// Execute persist flushes using pre-extracted context (no outer lock needed).
    pub async fn do_stop_flushes(ctx: StopFlushContext) {
        // final route-cache flush.
        if let Some(path) = ctx.cache_persist_path {
            let counts = Self::collect_contact_counts(&ctx.rtt_table);
            let snapshot = rlock!(ctx.route_cache).snapshot(&counts);
            let l = Arc::clone(&ctx.logger);
            tokio::task::spawn_blocking(move || Self::flush_cache_snapshot_sync(path, snapshot, l))
                .await
                .unwrap_or_else(|e| log::error!("persist flush panicked: {e}"));
        }
        // final RTT table flush.
        if let Some(path) = ctx.rtt_persist_path {
            let snapshot = lock!(ctx.rtt_table).snapshot();
            let l = Arc::clone(&ctx.logger);
            tokio::task::spawn_blocking(move || Self::flush_rtt_snapshot_sync(path, snapshot, l))
                .await
                .unwrap_or_else(|e| log::error!("persist flush panicked: {e}"));
        }
        // Epics 159–164: final persist flushes.
        if ctx.persist_enabled
            && let Ok(cfg) = veil_cfg::load_config(&ctx.config_path)
        {
            if let (Some(path), Some(lv)) =
                (cfg.routing.vivaldi_persist_path.clone(), &ctx.local_vivaldi)
            {
                let coord = lock!(lv).clone();
                let l = Arc::clone(&ctx.logger);
                tokio::task::spawn_blocking(move || {
                    Self::flush_vivaldi_snapshot_sync(path, coord, l)
                })
                .await
                .unwrap_or_else(|e| log::error!("persist flush panicked: {e}"));
            }
            if let Some(path) = cfg.dht.routing_persist_path.clone() {
                let contacts = ctx.dht.routing_table_contacts();
                let l = Arc::clone(&ctx.logger);
                tokio::task::spawn_blocking(move || {
                    Self::flush_dht_routing_snapshot_sync(path, contacts, l)
                })
                .await
                .unwrap_or_else(|e| log::error!("persist flush panicked: {e}"));
            }
            if let Some(path) = cfg.dht.values_persist_path.clone() {
                let entries = ctx.dht.snapshot_values();
                let l = Arc::clone(&ctx.logger);
                tokio::task::spawn_blocking(move || {
                    Self::flush_dht_values_snapshot_sync(path, entries, l)
                })
                .await
                .unwrap_or_else(|e| log::error!("persist flush panicked: {e}"));
            }
            if let Some(path) = cfg
                .mesh
                .as_ref()
                .and_then(|m| m.autodiscover_persist_path.clone())
            {
                let snap = ctx.autodiscovered_peers.snapshot();
                let l = Arc::clone(&ctx.logger);
                tokio::task::spawn_blocking(move || {
                    Self::flush_autodiscover_snapshot_sync(path, snap, l)
                })
                .await
                .unwrap_or_else(|e| log::error!("persist flush panicked: {e}"));
            }
            if let Some(path) = cfg.routing.gateway_persist_path.clone() {
                let snap = lock!(ctx.gateway_list).snapshot();
                let l = Arc::clone(&ctx.logger);
                tokio::task::spawn_blocking(move || {
                    Self::flush_gateway_list_snapshot_sync(path, snap, l)
                })
                .await
                .unwrap_or_else(|e| log::error!("persist flush panicked: {e}"));
            }
            if let Some(path) = cfg.routing.peer_pubkeys_persist_path.clone() {
                let snap: Vec<PeerPubkeySnapshot> = lock!(ctx.peer_pubkeys)
                    .iter()
                    .map(|(id, (algo, pk))| PeerPubkeySnapshot {
                        node_id: *id,
                        algo: *algo,
                        pubkey: pk.clone(),
                    })
                    .collect();
                let l = Arc::clone(&ctx.logger);
                tokio::task::spawn_blocking(move || {
                    Self::flush_peer_pubkeys_snapshot_sync(path, snap, l)
                })
                .await
                .unwrap_or_else(|e| log::error!("persist flush panicked: {e}"));
            }
            //final transport-announcements flush.
            if let Some(path) = cfg.dht.transport_announcements_persist_path.clone() {
                let snap = ctx.dht.snapshot_transport_announcements();
                let l = Arc::clone(&ctx.logger);
                tokio::task::spawn_blocking(move || {
                    Self::flush_transport_announcements_snapshot_sync(path, snap, l)
                })
                .await
                .unwrap_or_else(|e| log::error!("persist flush panicked: {e}"));
            }
        }
        // final discovered-peer cache flush.
        Self::tick_save_discovered_peers_cache(&ctx.discovered_peers_cache);
    }

    /// Execute task teardown using pre-extracted context (no outer lock needed).
    ///
    /// Sends `Detach(SHUTDOWN)` to active sessions, sleeps 200 ms for graceful
    /// drain, then signals and aborts all background tasks.
    pub async fn do_stop_tasks(ctx: StopTasksContext) {
        // Step 1: broadcast Detach(SHUTDOWN) to every active session.
        {
            use veil_proto::{
                codec::encode_header,
                family::{FrameFamily, SessionMsg},
                header::HEADER_SIZE,
                session::{DetachPayload, detach_reason},
            };
            let body = DetachPayload {
                reason: detach_reason::SHUTDOWN,
            }
            .encode();
            let mut hdr = veil_proto::header::FrameHeader::new(
                FrameFamily::Session as u8,
                SessionMsg::Detach as u16,
            );
            hdr.body_len = body.len() as u32;
            let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
            frame.extend_from_slice(&encode_header(&hdr));
            frame.extend_from_slice(&body);
            rlock!(ctx.session_tx_registry)
                .send_to_all(veil_bufpool::pooled_shared_from_vec(frame));
        }
        // Give session runners up to 200 ms to drain their outbox.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Step 2: signal all background tasks to stop.
        if let Some(shutdown_tx) = ctx.shutdown_tx {
            let _ = shutdown_tx.send(true);
        }
        // Audit M7: signal each ephemeral-rotator loop to exit gracefully via
        // its `shutdown_rx.changed()` arm before the JoinHandle abort below.
        // The senders were drained from `NodeRuntime`, so they drop at the end
        // of this scope and the source list is left empty for the next reload.
        for rotator_shutdown in &ctx.ephemeral_rotator_shutdowns {
            let _ = rotator_shutdown.send(true);
        }
        lock_waiters(&ctx.pending_accepts).clear();

        let RuntimeTasks {
            listeners,
            peers,
            sessions,
            background,
        } = {
            let mut tasks = lock_tasks(&ctx.tasks);
            std::mem::take(&mut *tasks)
        };
        for handle in listeners
            .into_iter()
            .chain(peers)
            .chain(sessions)
            .chain(background)
        {
            handle.abort();
            let _ = handle.await;
        }
        ctx.logger.info("listen.stop", "all listeners stopped");
    }

    /// Apply final state cleanup after tasks have been torn down (sync).
    pub fn finalize_stop_state(&mut self) {
        {
            let mut state = self.lock_state();
            for listen in state.listens.values_mut() {
                listen.listener_handle = None;
                listen.active = false;
                listen.local_addr = None;
            }
            state.metrics_endpoint = self.metrics_endpoint.clone();
        }
        lock!(self.live_sessions).clear();
        self.logger.info("node.stop", "runtime stopped");
    }

    pub async fn stop(&mut self) -> Result<()> {
        let flush_ctx = self.collect_stop_flush_context();
        let stop_ctx = self.take_stop_tasks_context();
        Self::do_stop_flushes(flush_ctx).await;
        Self::do_stop_tasks(stop_ctx).await;
        self.finalize_stop_state();
        Ok(())
    }

    /// Stop the runtime without holding the outer `Arc<Mutex<NodeRuntime>>` during
    /// the long-running async phases (persist flushes + 200 ms graceful drain).
    ///
    /// Prefer this over `stop` when the runtime is behind an `Arc<Mutex<…>>`
    /// so that concurrent admin commands are not starved.
    pub async fn stop_via_arc(rt: Arc<tokio::sync::Mutex<NodeRuntime>>) -> Result<()> {
        let (flush_ctx, stop_ctx) = {
            let mut s = rt.lock().await;
            (s.collect_stop_flush_context(), s.take_stop_tasks_context())
        };
        Self::do_stop_flushes(flush_ctx).await;
        Self::do_stop_tasks(stop_ctx).await;
        rt.lock().await.finalize_stop_state();
        Ok(())
    }

    /// Dry-run the fallible reconstruction that `apply_reload_after_stop`
    /// performs, so a bad config is rejected BEFORE any running task is torn
    /// down (audit cycle-9 reload-zombie). apply_reload_after_stop runs
    /// `context_from_config` (e.g. unreadable TLS cert) and
    /// `HandshakeIdentity::from_config` (e.g. corrupt identity keypair) AFTER
    /// `do_stop_tasks` has aborted every task and taken `shutdown_tx`. A failure
    /// there leaves the node online-but-dead — zero tasks, `shutdown_tx == None`,
    /// so every `spawn_*` early-returns and a retried reload can't recover
    /// either — until a full process restart. Validating here keeps the running
    /// node intact on a bad reload.
    pub fn validate_reloadable_config(config: &veil_cfg::Config) -> Result<()> {
        veil_cfg::require_identity(config)?; // identity section present
        let _ = veil_cfg::transport_glue::context_from_config(config)?;
        let _ = HandshakeIdentity::from_config(config)?;
        // Dry-run the FULL state build so EVERY fallible step in `build_state`
        // is exercised here, BEFORE do_stop_tasks tears the node down — most
        // importantly the per-peer `NodeId::from_public_key` on each
        // `[[peers]].public_key`. HandshakeIdentity::from_config validates only
        // the LOCAL identity, so a malformed PEER pubkey otherwise sailed
        // through validation and then failed inside `build_state` in
        // apply_reload_after_stop, AFTER the tasks were aborted and shutdown_tx
        // taken → an online-but-dead zombie until process restart. The built
        // NodeState is discarded; build_state is a pure constructor (no spawns),
        // so this is cheap and future-proofs the gate against new fallible build
        // steps. (audit cycle-10 — completes the cycle-9 reload-zombie fix.)
        let _ = build_state(
            config,
            std::path::PathBuf::new(),
            false,
            std::time::Instant::now(),
            false,
            None,
        )?;
        Ok(())
    }

    pub async fn reload(&mut self) -> Result<()> {
        // validate config BEFORE stopping tasks. If the config is invalid or
        // can't be fully reconstructed, return Err without disrupting the node.
        let config = veil_cfg::load_config(&self.config_path)?;
        Self::validate_reloadable_config(&config)?;
        let stop_ctx = self.take_stop_tasks_context();
        Self::do_stop_tasks(stop_ctx).await;
        self.apply_reload_after_stop(config).await
    }

    /// Apply new config and restart all tasks after `do_stop_tasks` has torn down
    /// the old ones. Called by both `reload` and `reload_via_arc`.
    pub async fn apply_reload_after_stop(&mut self, config: veil_cfg::Config) -> Result<()> {
        self.transport_ctx = Arc::new(veil_cfg::transport_glue::context_from_config(&config)?);
        // Δ2-a: the `[anonymity]` section is NOT re-applied on reload — the live
        // AnonymityState (relay_capable, advertised_bps, onion_service, x25519
        // key) is frozen at boot so reload can't orphan already-published
        // directory entries / rotate the anonymity key mid-flight. That freezing
        // is deliberate, but silently ignoring a CHANGED `[anonymity]` is an ops
        // trap, so warn the operator that a restart is required to apply it.
        {
            let new_onion_hops = config.anonymity.onion_service.then(|| {
                config.anonymity.onion_service_hops.map_or(3, |h| h as usize)
            });
            if config.anonymity.relay_capable != self.anonymity.relay_capable
                || config.anonymity.advertised_bps != self.anonymity.advertised_bps
                || new_onion_hops != self.anonymity.onion_service_hops
            {
                self.logger.warn(
                    "config.anonymity.reload_ignored",
                    "[anonymity] changed but is applied at startup only — the live \
                     relay_capable / advertised_bps / onion_service settings are unchanged \
                     until a full restart (the anonymity key + published directory entries \
                     are pinned across reload by design)",
                );
            }
        }
        // identity bundle is `Arc<IdentityState>` — can't
        // mutate fields via deref. Build a fresh IdentityState reusing
        // existing Arc-clones for the peer caches (those are interior-mutable
        // already; their Arc<Mutex<...>> contents persist) and a freshly-made
        // local_identity, then swap the bundle Arc. Downstream NodeServices
        // / SessionRuntimeContext clones held the previous bundle's local_id;
        // after this swap they continue to see the OLD local_identity until
        // their own contexts are rebuilt — matches pre-PR5 semantics where
        // NodeServices.local_identity was the same stale Arc clone.
        let new_local_identity = Arc::new(HandshakeIdentity::from_config(&config)?);
        self.identity = Arc::new(super::identity_state::IdentityState::new(
            new_local_identity,
            self.identity.sovereign_identity.clone(),
            Arc::clone(&self.identity.peer_pubkeys),
            Arc::clone(&self.identity.peer_sovereign_identities),
            Arc::clone(&self.identity.peer_roles),
            Arc::clone(&self.identity.mlkem_ek),
            Arc::clone(&self.identity.peer_mlkem_keys),
            Arc::clone(&self.identity.per_session_mlkem_dk),
        ));
        // re-prime global mobile background-mode
        // multiplier from reloaded config — operator may have
        // bumped it to react to observed cellular usage.
        veil_session::runner::set_mobile_background_keepalive_multiplier(
            config.mobile.background_keepalive_multiplier,
        );
        // deferred : re-prime global outbound-batch
        // signals. Threshold + window are independent atomics so
        // operator who only flips outbound batching (not maintenance
        // throttling) still sees the window apply correctly — the
        // gating predicate in `current_outbound_batch_window` requires
        // BOTH threshold AND window to be set.
        veil_session::runner::set_mobile_low_battery_threshold_pct(
            config.mobile.low_battery_threshold_pct,
        );
        veil_session::runner::set_mobile_outbound_batch_window_ms(
            config.mobile.outbound_batch_window_ms.unwrap_or(0),
        );
        // re-prime global session-rotation interval
        // from reloaded config. Active sessions keep their
        // existing rotation deadline (computed at session start);
        // new sessions opened after this reload pick up the new
        // value. Operator who bumped max_age sees the change
        // applied gradually as old sessions rotate naturally —
        // not a sync-storm from admin reload.
        //
        // Precedence (Q.7 audit batch — censor-evasion):
        //   1. `[transport.rotation]` range knob (new) — preferred.
        //   2. `session.max_age_secs` (deprecated single-value) —
        //      back-compat fallback only when rotation is disabled
        //      at the new section AND set at the legacy field.
        if let Some((min, max)) = config.transport.rotation.resolved_range() {
            veil_session::runner::set_session_rotation_range(min, max);
            // Quiet the deprecation noise if the operator is using the
            // modern knob — but if they ALSO set the legacy field, warn
            // that we're ignoring it (so they don't think it's active).
            if config.session.max_age_secs.is_some() {
                self.logger.warn(
                    "config.session.max_age_secs.shadowed",
                    "session.max_age_secs is set but [transport.rotation] takes precedence — \
                     remove session.max_age_secs from the config to silence this warning",
                );
            }
        } else if let Some(secs) = config.session.max_age_secs {
            self.logger.warn(
                "config.session.max_age_secs.deprecated",
                format!(
                    "session.max_age_secs={secs} is DEPRECATED — migrate to the \
                     [transport.rotation] section (min_lifetime_secs + max_lifetime_secs, \
                     -1 on both to disable) for range-based jitter that defeats \
                     fleet-correlation DPI fingerprinting"
                ),
            );
            veil_session::runner::set_session_max_age_secs(secs);
        } else {
            veil_session::runner::set_session_rotation_range(0, 0);
        }
        self.metrics = veil_cfg::observability_glue::metrics_from_config(&config)
            .map(|(metrics, _)| Arc::new(metrics));
        if let Some(metrics) = &self.metrics {
            metrics.set_configured_peers(config.peers.len());
        }
        self.metrics_path = resolve_metrics_path(&config);
        self.metrics_endpoint = None;
        // Clear the OVL1 session registry — all sessions were torn down by stop_tasks.
        *lock!(self.session_registry) = SessionRegistry::new();
        // Reset the per-IP session counter — all sessions have been torn down.
        self.sessions_per_ip.clear();
        // Clear the live-session inspect cache too. Session-runner tasks that
        // would normally remove their entry on Drop were *aborted* by
        // `do_stop_tasks`, so they never executed their cleanup path —
        // entries linger here unless we reset them. Without this, post-reload
        // `runtime.sessions` returns stale sessions from the previous boot
        // and the `gateway_failure_spokes_lose_hub` /
        // `event_driven_churn_reconverges` sim tests fail because the spoke
        // appears to "still have" a session to a hub that's gone.
        lock!(self.live_sessions).clear();
        // mailbox subsystem removed — nothing to reinitialise here.
        let role = config
            .identity
            .as_ref()
            .map(|id| id.role)
            .unwrap_or_default();
        // Clear the app endpoint registry — all local app registrations are re-established on startup.
        self.app_registry = Arc::new({
            let r = AppEndpointRegistry::new().with_auto_publish(
                self.dispatcher.local_node_id,
                Arc::clone(&self.discovery),
                300,
            );
            if let Some(m) = &self.metrics {
                r.with_metrics(Arc::clone(m) as Arc<dyn veil_app::AppMetrics>)
            } else {
                r
            }
        });
        // Reinitialize gateway service with potentially updated role and lease TTL.
        self.gateway = Arc::new(GatewayService::new_with_lease_ttl(
            role,
            std::time::Duration::from_secs(config.gateway.attachment_lease_ttl_secs),
        ));
        *lock!(self.routing.rtt_table) = RttTable::new(std::time::Duration::from_secs(300));
        self.dht = {
            let mut svc = KademliaService::with_config(
                *self.identity.local_identity.node_id.as_bytes(),
                crate::dht_glue::runtime_config_from(&config.dht),
            );
            svc.set_rtt_table(Arc::new(crate::dht_glue::RttHintAdapter::new(Arc::clone(
                &self.routing.rtt_table,
            ))));
            // wire Vivaldi coords into the DHT for topology-aware ranking.
            if let Some(local_v) = &self.dispatcher.local_vivaldi {
                svc.set_coord_oracle(Arc::new(crate::dht_glue::VivaldiOracle::new(
                    Arc::clone(local_v),
                    Arc::clone(&self.dispatcher.peer_vivaldi),
                )));
            }
            Arc::new(svc)
        };
        // DiscoveryService must wrap (possibly-new) DHT so
        // announce_app_endpoint publishes signed records for cross-DHT
        // replication. Created after the DHT is built.
        self.discovery = {
            let mut svc = DiscoveryService::new(role).with_dht(Arc::clone(&self.dht));
            if let Some(ref sk) = self.dispatcher.crypto.local_signing_key {
                svc = svc.with_signing_key(Arc::clone(sk));
            }
            if let Some(fs) = load_falcon_signer(&config) {
                svc = svc.with_falcon_signer(fs);
            }
            Arc::new(svc)
        };
        let reload_node_id = *self.identity.local_identity.node_id.as_bytes();
        self.mesh_forwarder = Arc::new(MeshForwarder::new(
            reload_node_id,
            role,
            Arc::new(NeighborTable::new()),
        ));
        self.mesh_bridge = Arc::new(
            GatewayBridge::new(reload_node_id, role).with_metrics(
                self.metrics
                    .as_ref()
                    .map(|m| Arc::clone(m) as Arc<dyn veil_mesh::MeshMetrics>),
            ),
        );
        // Audit M-D: release the OLD mesh socket BEFORE rebinding. The previous
        // `self.mesh_realm = init_mesh_realm(..)` evaluated the new bind while
        // the old `UdpRealm` still held its socket on the same address; since
        // `UdpRealm::bind` uses a plain `UdpSocket::bind` (no SO_REUSEADDR), the
        // rebind failed with EADDRINUSE, `init_mesh_realm` silently mapped it to
        // `None`, and the entire mesh subsystem was disabled after any reload
        // until a full restart. The beacon tasks' own realm clones were already
        // dropped by `do_stop_tasks`, so taking+dropping this last clone
        // releases the socket before the rebind.
        drop(self.mesh_realm.take());
        self.mesh_realm = Self::init_mesh_realm(&config).await;
        *wlock!(self.routing.route_cache) = RouteCache::new(std::time::Duration::from_secs(
            config.routing.route_cache_ttl_secs,
        ));
        *lock!(self.routing.neighbor_scorer) = NeighborScorer::with_alphas(0.5, 0.1);
        *lock!(self.routing.vivaldi) = VivaldiCoord::new();
        if let Some(m) = &self.metrics {
            {
                let c = lock!(self.routing.vivaldi);
                m.record_vivaldi_coord(c.x, c.y, c.height, c.error);
            };
        }
        *lock!(self.rate_limiter) = {
            let mut limiter = PerPeerLimiter::new(
                config.abuse.rate_limit_fps,
                config.abuse.rate_limit_burst,
                std::time::Duration::from_secs(300),
            );
            if let Some(rate) = config.abuse.per_peer_bytes_per_sec
                && let Some(burst) = config.abuse.resolved_per_peer_byte_burst()
            {
                limiter = limiter.with_byte_rate(rate as f64, burst as f64);
            }
            limiter
        };
        // Reset then RE-LOAD the persisted bans from disk (audit cycle-9
        // CRIT-4). A bare `BanList::new()` wiped every ban (manual + auto) on
        // any reload (SIGHUP / admin reload / apply-config) while bans.json
        // stayed on disk but inactive until a full process restart — banned
        // peers reconnected immediately after a reload. This mirrors the
        // deliberate cross-reload preservation of `recursive_query_limiter`
        // (so a flood-throttled peer can't reset its budget via reload); the
        // ban list must likewise survive a reload. `persist_bans` only writes
        // manual bans, so this restores those; auto-bans re-accumulate via the
        // freshly-rebuilt violation tracker below.
        *lock!(self.ban_list) = BanList::new();
        super::persistence::load_bans(&self.ban_list, &self.config_path);
        // `.max(1)` clamp makes the `.expect` unreachable here (same
        // invariant as in `runtime/mod.rs` — see commentary there).
        *lock!(self.violation_tracker) = ViolationTracker::new(
            config.abuse.ban_threshold.max(1),
            std::time::Duration::from_secs(config.abuse.ban_initial_secs),
            std::time::Duration::from_secs(config.abuse.ban_step_secs),
            std::time::Duration::from_secs(config.abuse.ban_max_secs),
            std::time::Duration::from_secs(600),
        )
        .expect("ban_threshold clamped to >= 1 — invariant in this call site");
        *lock!(self.runtime_summary) = RuntimeSummary {
            role: role.to_string(),
            ..Default::default()
        };
        // Audit M2: recreate the PEX channel pair so the initiator/connector
        // tasks — torn down by `do_stop_tasks` (aborted out of `tasks.background`
        // and signalled via the main `shutdown_tx`) — respawn fresh in
        // `spawn_all_services` below. The take-once `Option`s on `self.pex` are
        // `None` after the first start, so without re-priming them the spawn
        // arms are skipped and PEX peer-exchange stays dead until a full
        // restart. The new `event_tx` is threaded into the rebuilt dispatcher
        // so inbound PEX frames reach the new initiator.
        let pex_event_tx = if config.pex.enabled {
            let (event_tx, event_rx) = tokio::sync::mpsc::channel::<veil_pex::PexEvent>(64);
            let (connect_tx, connect_rx) =
                tokio::sync::mpsc::channel::<Vec<veil_proto::pex::PexPeer>>(16);
            self.pex.event_rx = Some(event_rx);
            self.pex.connect_tx = Some(connect_tx);
            self.pex.connect_rx = Some(connect_rx);
            Some(event_tx)
        } else {
            self.pex.event_rx = None;
            self.pex.connect_tx = None;
            self.pex.connect_rx = None;
            None
        };
        // Rebuild the dispatcher to pick up the new service Arcs.
        let reload_node_id = *self.identity.local_identity.node_id.as_bytes();
        self.dispatcher =
            Arc::new(self.build_reload_dispatcher(&config, role, reload_node_id, pex_event_tx));
        {
            let mut state = self.lock_state();
            let started_at = state.started_at;
            *state = build_state(
                &config,
                self.config_path.clone(),
                self.foreground_mode,
                started_at,
                config.metrics.is_some(),
                None,
            )?;
        }
        // recompute adaptive params from current network size and resize caches.
        {
            let rt_size = self.dht.routing_table_size();
            let sessions = rlock!(self.session_tx_registry).len();
            let est = veil_cfg::adaptive::estimate_network_size(rt_size, sessions);
            let mut params = veil_cfg::adaptive::AdaptiveParams::from_network_size(est.estimated_n);
            // override min_responder_prefix_bits with the
            // observed-peer-count formula instead of the floored
            // estimated_n. `from_network_size` floors N at 100 to keep
            // cache/k-bucket parameters sane on tiny networks; that floor
            // backfires on the proximity gate (2-node devnet → floored
            // N=100 → gate=3 bits → every recursive response rejected
            // because expected closest leading_zeros on 2 nodes is ≤1).
            // Computing the gate from the raw observed peer count gives
            // gate=0 on bootstrap and the same `min(16, log2(N)-4)` curve
            // at scale.
            //
            // use **verified-handshake sessions
            // only** as the trust source. The DHT routing-table size is
            // Sybil-influenceable (anyone can be inserted via FIND_NODE
            // responses), so feeding it into a security-critical gate
            // would let an attacker inflate the proximity threshold and
            // reject legitimate close-key responders.
            params.min_responder_prefix_bits =
                veil_cfg::adaptive::AdaptiveParams::min_responder_prefix_bits_from_observed(
                    sessions,
                );
            wlock!(self.routing.route_cache).resize(params.route_cache_capacity);
            // Publish the freshly-computed params into the dispatcher so
            // the recursive-response handler reads the scale-aware
            // `min_responder_prefix_bits`. Mutates under writer lock;
            // dispatch handlers read under reader lock + copy out the u32.
            *wlock!(self.dispatcher.adaptive_params) = params;
            // NOTE: route_seen_set and peer_pubkey_cache don't support online resize.
            // They use fixed capacity set at construction time. Adaptive sizing for
            // these components requires restart (acceptable for current scale).
            if matches!(self.dispatcher.role, veil_cfg::NodeRole::Core) {
                let epoch = veil_proto::discovery::EpochDifficultyRecord::current_epoch();
                let difficulty =
                    veil_cfg::adaptive::AdaptiveParams::adaptive_pow_difficulty(est.estimated_n);
                let key = veil_proto::discovery::epoch_difficulty_key(epoch);
                let mut record = veil_proto::discovery::EpochDifficultyRecord {
                    epoch,
                    difficulty,
                    publisher_node_id: *self.identity.local_identity.node_id.as_bytes(),
                    signature: [0u8; 64],
                };
                // Sign the record with the node's local key. Skipped when no
                // signing key is available (identity loaded without private
                // material); downstream readers will observe a zero signature
                // and can choose to trust-first-publisher.
                if let Some(ref sk) = self.dispatcher.crypto.local_signing_key {
                    use ed25519_dalek::Signer;
                    record.signature = sk.sign(&record.signable_bytes()).to_bytes();
                }
                self.dht.store_local(key, record.encode());
            }
            // consume — read epoch difficulty from local DHT store.
            {
                let epoch = veil_proto::discovery::EpochDifficultyRecord::current_epoch();
                let key = veil_proto::discovery::epoch_difficulty_key(epoch);
                if let Some(value) = self.dht.get_local(&key)
                    && let Ok(record) = veil_proto::discovery::EpochDifficultyRecord::decode(&value)
                {
                    self.logger.info(
                        "epoch_difficulty",
                        format!(
                            "epoch={} difficulty={} publisher={}",
                            record.epoch,
                            record.difficulty,
                            veil_util::hex_short(&record.publisher_node_id)
                        ),
                    );
                }
            }
        }
        self.logger
            .info("node.reload", "reloading runtime configuration");
        self.refresh_runtime_tuning(&config);
        // reset gateway list preference for the new config, then
        // rebuild from the current peer set before the failover task spawns.
        // The Arc is reused so the dispatcher shares the refreshed list.
        {
            use veil_gateway::GatewayList;
            *lock!(self.gateway_list) = GatewayList::new(config.connection.prefer_internet_gateway);
        }
        self.rebuild_gateway_list_from_state();
        // Audit L-10: reset the builtin-app host before re-spawning services.
        // Its tasks live in the host (NOT `self.tasks`), so `do_stop_tasks`
        // never aborted them, and its endpoints were bound to the
        // `app_registry` that this reload replaced with a fresh empty one — so
        // each reload would otherwise park another mailbox-app task against an
        // orphaned registry and grow `host.tasks` / `endpoint_handles`
        // unbounded. Tear the old host down (signals shutdown + joins its
        // tasks) and recreate it empty; `spawn_all_services` below re-spawns its
        // services against the fresh `app_registry`.
        if let Some(old_host) = self
            .builtin_app_host
            .replace(crate::builtin::BuiltinAppHost::new())
        {
            old_host.shutdown().await;
        }
        // single lifecycle list shared with cold start — see
        // `NodeRuntime::spawn_service`.
        self.spawn_all_services(&config).await?;
        Ok(())
    }

    /// construct a fresh `FrameDispatcher` wired to the reloaded
    /// config and the current (possibly rebuilt) service Arcs.
    ///
    /// Extracted from `apply_reload_after_stop`. The rule of thumb for every
    /// field: state that must survive a reload is carried forward via
    /// `Arc::clone(&self.dispatcher.*)`; state derived from the config
    /// (routing limits, thresholds, etc.) is read out of `config`; per-reload
    /// singletons (route-seen set, announce seq, discovery forwarder, PoW
    /// challenge limiter) are built fresh here.
    pub fn build_reload_dispatcher(
        &self,
        config: &veil_cfg::Config,
        role: veil_cfg::NodeRole,
        reload_node_id: [u8; 32],
        // Audit M2: the freshly-created PEX event sender (Some iff PEX is
        // enabled). The dispatcher must point at the new channel so the
        // respawned initiator (which holds the new receiver) actually receives
        // inbound PEX events after a reload.
        pex_event_tx: Option<tokio::sync::mpsc::Sender<veil_pex::PexEvent>>,
    ) -> FrameDispatcher {
        let reload_signing_key = load_signing_key(config);
        let reload_listen_transports =
            Arc::new(std::sync::RwLock::new(build_advertised_transports(config)));
        // reuse the same gateway_list Arc across reload so in-flight
        // consumers see the updated entries immediately.
        let reload_gateway_list = Arc::clone(&self.gateway_list);
        FrameDispatcher {
            role,
            gateway: Arc::clone(&self.gateway),
            discovery: Arc::clone(&self.discovery),
            dht: Arc::clone(&self.dht),
            app_registry: Arc::clone(&self.app_registry),
            stream_table: Arc::new(veil_app::AppStreamTable::new()),
            mesh_forwarder: Arc::clone(&self.mesh_forwarder),
            chunk_reassembler: Arc::clone(&self.dispatcher.chunk_reassembler),
            discovery_forwarder: Arc::new(Mutex::new(
                veil_routing::discovery_forwarder::DiscoveryForwarder::with_default_difficulty(
                    reload_node_id,
                    role,
                ),
            )),
            control_plane: Arc::clone(&self.control_plane),
            route_cache: Arc::clone(&self.routing.route_cache),
            metrics: self.metrics.clone(),
            logger: Arc::clone(&self.logger),
            crypto: Arc::new(veil_dispatcher::CryptoContext {
                local_signing_key: reload_signing_key,
                mlkem_ek: Arc::clone(&self.identity.mlkem_ek),
                mlkem_dk_seed: Arc::clone(&self.mlkem_dk_seed),
                peer_mlkem_keys: Arc::clone(&self.identity.peer_mlkem_keys),
                peer_pubkeys: Arc::clone(&self.identity.peer_pubkeys),
                peer_roles: Arc::clone(&self.identity.peer_roles),
                peer_cap_flags: Arc::clone(&self.dispatcher.crypto.peer_cap_flags),
                per_session_mlkem_dk: Arc::clone(&self.identity.per_session_mlkem_dk),
            }),
            abuse: Arc::new(veil_dispatcher::AbuseContext {
                rate_limiter: Arc::clone(&self.rate_limiter),
                ban_list: Arc::clone(&self.ban_list),
                violation_tracker: Arc::clone(&self.violation_tracker),
                dht_quota: Arc::clone(&self.dispatcher.abuse.dht_quota),
                // per-identity DHT write quota.
                identity_write_quota: Arc::clone(&self.dispatcher.abuse.identity_write_quota),
                pow_challenge_limiter: Arc::new(Mutex::new(veil_abuse::PerPeerLimiter::new(
                    config.pow.challenge_rate,
                    config.pow.challenge_burst,
                    std::time::Duration::from_secs(config.pow.challenge_window_secs),
                ))),
                // reuse across reloads for the same reason.
                dht_contact_quota: Arc::clone(&self.dispatcher.abuse.dht_contact_quota),
                // reuse across reloads to preserve in-flight rate state.
                announce_attachment_limiter: Arc::clone(
                    &self.dispatcher.abuse.announce_attachment_limiter,
                ),
                //round 7 / : reuse so the per-peer NAT
                // probe forward quota persists across reloads.
                nat_probe_forward_quota: Arc::clone(&self.dispatcher.abuse.nat_probe_forward_quota),
                // Reuse the recursive-query limiter across reloads so
                // a flood-throttled peer cannot regain its budget by
                // forcing a config reload.
                recursive_query_limiter: Arc::clone(&self.dispatcher.abuse.recursive_query_limiter),
                // 443: recreate bandwidth gates from updated config.
                inbound_bandwidth: Arc::new(Mutex::new(veil_abuse::BandwidthGate::new(
                    veil_cfg::NodeCapacityConfig::bandwidth_kbps_to_gate(
                        config.capacity.max_inbound_bandwidth_kbps,
                    ),
                ))),
                outbound_bandwidth: Arc::new(Mutex::new(veil_abuse::BandwidthGate::new(
                    veil_cfg::NodeCapacityConfig::bandwidth_kbps_to_gate(
                        config.capacity.max_outbound_bandwidth_kbps,
                    ),
                ))),
            }),
            local_node_id: reload_node_id,
            session_tx_registry: Some(Arc::clone(&self.session_tx_registry)),
            // Preserve the existing rendezvous weak ref across reload so
            // in-flight handle_request tasks keep upgrading to the same
            // strong controller.
            rendezvous_weak: Arc::clone(&self.dispatcher.rendezvous_weak),
            session_registry: Some(Arc::clone(&self.session_registry)),
            route_seen_set: Arc::new(Mutex::new(veil_dispatcher::RouteSeenSet::new(
                std::time::Duration::from_secs(config.routing.route_seen_window_secs),
                config.routing.route_seen_capacity,
            ))),
            announce_seq: Arc::new(AtomicU32::new(0)),
            listen_transports: reload_listen_transports,
            relay_node_ids: build_relay_node_ids(config),
            target_labels: build_target_labels(&config.routing),
            route_updated: Arc::new(tokio::sync::Notify::new()),
            pow_difficulty: config.abuse.pow_min_difficulty as u8,
            pow_pending: Arc::new(Mutex::new(veil_dispatcher::PowPendingTable::new())),
            discovery_mode: config.routing.discovery_mode,
            pending_diag: Arc::clone(&self.pending_diag),
            capture_tx: Arc::clone(&self.dispatcher.capture_tx),
            capture_active: Arc::clone(&self.dispatcher.capture_active),
            capture_rate_limit: Arc::clone(&self.dispatcher.capture_rate_limit),
            route_miss_tx: Arc::clone(&self.dispatcher.route_miss_tx),
            auth_deliver_tx: Arc::clone(&self.dispatcher.auth_deliver_tx),
            neighbor_scorer: Arc::clone(&self.routing.neighbor_scorer),
            local_vivaldi: self.dispatcher.local_vivaldi.clone(),
            peer_vivaldi: Arc::clone(&self.dispatcher.peer_vivaldi),
            // reuse the existing dedup set across reloads so in-flight
            // replays that straddle a config reload are still caught.
            forward_seen_set: Arc::clone(&self.dispatcher.forward_seen_set),
            forward_seen_content: Arc::clone(&self.dispatcher.forward_seen_content),
            terminal_ack_replay: Arc::clone(&self.dispatcher.terminal_ack_replay),
            recursive_query_seen: Arc::clone(&self.dispatcher.recursive_query_seen),
            vvsync_seen: Arc::clone(&self.dispatcher.vvsync_seen),
            pending_recursive: Arc::clone(&self.dispatcher.pending_recursive),
            recursive_reverse_path: Arc::clone(&self.dispatcher.recursive_reverse_path),
            alias_registry: Arc::clone(&self.dispatcher.alias_registry),
            peer_observed_addrs: Arc::clone(&self.dispatcher.peer_observed_addrs),
            relay_tunnels: Arc::clone(&self.dispatcher.relay_tunnels),
            nat_probe_waiters: Arc::clone(&self.dispatcher.nat_probe_waiters),
            // reuse the same Arc across reloads so the
            // dispatcher swap-in keeps reading the latest computed
            // params (the reload tick subsequently overwrites the
            // contents under the writer lock).
            adaptive_params: Arc::clone(&self.dispatcher.adaptive_params),
            max_gossip_hops: config.routing.max_gossip_hops,
            congestion_monitor: Some(Arc::clone(&self.congestion_monitor)),
            reputation: self.dispatcher.reputation.clone(),
            gateway_list: Some(Arc::clone(&reload_gateway_list)),
            prefer_internet_gateway: config.connection.prefer_internet_gateway,
            exit_diversification: config.connection.exit_diversification,
            exit_diversification_top_k: config.connection.exit_diversification_top_k,
            ecmp_score_band: config.routing.ecmp_score_band,
            redundant_send: config.routing.redundant_send,
            epidemic_seen: Arc::clone(&self.dispatcher.epidemic_seen),
            epidemic_fanout: config.routing.epidemic_fanout,
            epidemic_max_payload: config.routing.epidemic_max_payload,
            battery_threshold_low: config.routing.battery_threshold_low,
            battery_threshold_medium: config.routing.battery_threshold_medium,
            battery_penalty_low: config.routing.battery_penalty_low,
            battery_penalty_medium: config.routing.battery_penalty_medium,
            // Reload path: preserve the last advertisement timestamp so
            // the rate limiter is not accidentally reset on `reload`.
            last_sleep_advertisement_ts: Arc::clone(&self.dispatcher.last_sleep_advertisement_ts),
            multi_path_enabled: config.routing.multi_path_enabled,
            max_parallel_paths: config.routing.max_parallel_paths,
            multi_path_min_priority: config.routing.multi_path_min_priority,
            relay_reputation_min_attempts: config.routing.relay_reputation_min_attempts,
            relay_reputation_threshold: config.routing.relay_reputation_threshold,
            relay_reputation_penalty: config.routing.relay_reputation_penalty,
            jitter_penalty_weight: config.routing.jitter_penalty_weight,
            jitter_threshold_ms: config.routing.jitter_threshold_ms,
            narrow_bandwidth_bulk_penalty: config.routing.narrow_bandwidth_bulk_penalty,
            trace_buffer: Arc::clone(&self.dispatcher.trace_buffer),
            pending_ack: Arc::clone(&self.dispatcher.pending_ack),
            // reuse the same loss tracker across config reloads so
            // in-flight per-peer counters (and warm windows) are preserved.
            loss_tracker: Arc::clone(&self.dispatcher.loss_tracker),
            route_origin_seq: Arc::clone(&self.dispatcher.route_origin_seq),
            pow_solver_semaphore: Arc::clone(&self.dispatcher.pow_solver_semaphore),
            pow_active_difficulty: Arc::clone(&self.dispatcher.pow_active_difficulty),
            pow_challenge_seen: Arc::clone(&self.dispatcher.pow_challenge_seen),
            pending_stream_receipts: Arc::clone(&self.dispatcher.pending_stream_receipts),
            veil_stream_rx: Arc::clone(&self.dispatcher.veil_stream_rx),
            // Audit M2: rebuild a FRESH dispatcher pointing at the new event
            // channel (do NOT Arc-clone the old one — its sender feeds a
            // channel whose receiver was consumed by the now-aborted initiator).
            pex_dispatcher: pex_event_tx.and_then(|tx| {
                super::pex_runtime::build_pex_dispatcher(
                    config,
                    reload_node_id,
                    self.logger.clone(),
                    tx,
                )
            }),
            pex_state: self.dispatcher.pex_state.as_ref().map(Arc::clone),
            // reload preserves the same anonymity SK so
            // already-published directory entries (which advertise this
            // pubkey) keep working through the reload. An operator who
            // wants a fresh SK should do a full restart, not a reload.
            anonymity_x25519_sk: self.dispatcher.anonymity_x25519_sk.clone(),
            anonymity_relay_capable: self.dispatcher.anonymity_relay_capable,
            // reload preserves the Introduce
            // replay cache so reload doesn't open a window in which
            // captured ciphertexts could be re-submitted between the
            // dispatcher swap and the next legitimate Introduce.
            introduce_replay_cache: Arc::clone(&self.dispatcher.introduce_replay_cache),
            // Δ2-g1: preserve the relay-side introduce dedup across reload (parity
            // with the introduce replay cache), so reload doesn't briefly reopen
            // the replay window.
            circuit_introduce_seen: Arc::clone(&self.dispatcher.circuit_introduce_seen),
            // reload preserves the rendezvous
            // registry so currently-registered cookies survive without
            // forcing a re-registration round-trip from every receiver.
            rendezvous_registry: self.dispatcher.rendezvous_registry.clone(),
            // reload preserves live circuit state so in-flight circuits survive
            // a config reload without a rebuild round-trip.
            circuit_table: self.dispatcher.circuit_table.clone(),
            circuit_rendezvous: self.dispatcher.circuit_rendezvous.clone(),
            circuit_origin: self.dispatcher.circuit_origin.clone(),
        }
    }

    /// refresh scalar runtime knobs from a reloaded config.
    ///
    /// Extracted from `apply_reload_after_stop` — pure field assignment with no
    /// task-spawning or I/O. Groups keepalive/idle/session/gateway/NAT/battery
    /// tunables that are picked up from the new config without any restart.
    pub fn refresh_runtime_tuning(&mut self, config: &veil_cfg::Config) {
        // H10 stage-B (4/N): rebuild the SessionDefaults
        // bundle on reload. Same shape as the constructor: 16 args in
        // declaration order. Returning a fresh `Arc<SessionDefaults>` rather than mutating via interior mutability matches the
        // existing reload pattern (`self.mobile = Arc::new(...)` below).
        self.defaults = super::session_defaults::SessionDefaults::new(
            std::time::Duration::from_secs(config.session.keepalive_interval_secs),
            std::time::Duration::from_secs(config.session.idle_timeout_secs),
            config.session.max_pending_responses,
            std::time::Duration::from_millis(config.session.pending_response_ttl_ms),
            config.session.max_frame_body_bytes,
            config.session.rekey_bytes_threshold,
            config.session.rekey_time_threshold_secs,
            config.session.qos_weights.map(|w| w as u32),
            config.session.max_concurrent,
            config.session.referral_headroom,
            config.session.max_per_ip,
            // previously frozen — operator could edit the limit
            // in config but `reload` would silently ignore it (admission
            // control kept using the original value).
            config.session.max_per_subnet,
            std::time::Duration::from_secs(config.gateway.keepalive_interval_secs),
            std::time::Duration::from_millis(config.connection.reconnect_backoff_min_ms),
            std::time::Duration::from_millis(config.connection.reconnect_backoff_max_ms),
            config.connection.reconnect_quiet_after_failures,
        );
        // rebuild mobile state on reload. Preserve
        // the existing `mobile_background_mode` AtomicBool (its current
        // foreground/background state must survive a config reload —
        // resetting to false would break mobile clients mid-suspension).
        // Battery snapshots refresh from the new config.
        self.mobile = std::sync::Arc::new(super::mobile_state::MobileState::new(
            std::sync::Arc::clone(&self.mobile.mobile_background_mode),
            config.session.battery_keepalive_scale_low,
            config.session.battery_keepalive_scale_medium,
            config.session.battery_threshold_low,
            config.session.battery_threshold_medium,
        ));
        // persist master switch used by readers across the
        // runtime (previously only refreshed inside restart_persist_tasks).
        self.persist_enabled = config.persist_enabled;
    }
}
