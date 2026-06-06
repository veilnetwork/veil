//! Periodic runtime-maintenance task + its `tick_*` phase helpers.
//!
//! Originally lived in `mailbox_cleanup.rs`; the
//! mailbox-specific pieces were stripped and the file was
//! renamed. Despite the rename the cleanup task is still load-bearing —
//! it drives the runtime-summary refresh that admin endpoints read, the
//! memory-budget eviction loop, and the secondary-cache GC.
//!
//! The tick runs every `cleanup_interval` and performs a fixed sequence:
//!
//! 1. Update congestion depth from the session-outbox.
//! 2. Account memory pressure + evict when we're over budget.
//! 3. Evict expired primary stores (gateway, discovery, DHT, chunk reassembler).
//! 4. Record eviction metrics.
//! 5. Evict secondary caches (route cache, RTT, rate limiter, ban list
//!    violations, ML-KEM key cache).
//! 6. Refresh the runtime summary.
//! 7. Prune completed JoinHandles.
//!
//! Each phase lives in a `tick_*` associated function so the main loop
//! stays readable and each step is unit-testable in isolation.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use veil_util::{lock, rlock, wlock};

use veil_types::PeerPubkeysCache;

use super::{
    NodeLogger, NodeMetrics, NodeRuntime, NodeState, RuntimeSummary, RuntimeTasks, lock_state,
    lock_tasks,
};

/// Per-tick counts from `tick_evict_expired_primary_stores`.  Consumed by
/// `tick_record_eviction_metrics` to charge the storage-eviction counter
/// against the appropriate sub-metric.
#[derive(Default, Clone, Copy)]
pub struct PrimaryEvictionCounts {
    pub discovery_evicted: usize,
    pub dht_evicted: usize,
}

impl NodeRuntime {
    pub fn spawn_maintenance_tick(
        &mut self,
        cleanup_interval: std::time::Duration,
        e2e_key_ttl: std::time::Duration,
        // deferred : mobile config governs whether
        // the tick's eviction / diagnostic phases throttle on low
        // battery. When `low_battery_throttle_maintenance = false`
        // (default — opt-) the tick behaves identically to pre-
        // slice baseline. Deadline-driven phases (477.4/
        // 482.4/482.5) and memory-safety phases ALWAYS run.
        mobile_cfg: veil_cfg::MobileConfig,
    ) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let gateway = Arc::clone(&self.gateway);
        let discovery = Arc::clone(&self.discovery);
        let dht = Arc::clone(&self.dht);
        let route_cache = Arc::clone(&self.routing.route_cache);
        let rtt_table = Arc::clone(&self.routing.rtt_table);
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let ban_list = Arc::clone(&self.ban_list);
        let violation_tracker = Arc::clone(&self.violation_tracker);
        let runtime_summary = Arc::clone(&self.runtime_summary);
        let mesh_forwarder = Arc::clone(&self.mesh_forwarder);
        let state = Arc::clone(&self.state);
        let live_sessions = Arc::clone(&self.live_sessions);
        // Audit M8: mailbox handle for the runtime-summary refresh, so
        // `mailbox_entries` reports the real blob count instead of a hardcoded 0.
        let mailbox_for_summary = self.mailbox_state.mailbox.clone();
        // Audit (this pass): outbox handle for the TTL-prune stage below. The
        // mailbox/outbox `prune_expired` were implemented + tested but had NO
        // periodic caller after the old `MailboxCleanup` loop was renamed, so
        // the 7-day mailbox / 30-day outbox TTLs were never actually enforced —
        // a never-ack'd blob lived forever and held its quota slot.
        let outbox_for_prune = self.mailbox_state.outbox.clone();
        let health_tick = Arc::clone(&self.health_tick);
        let metrics = self.metrics.clone();
        let peer_mlkem_keys = Arc::clone(&self.identity.peer_mlkem_keys);
        let session_tx_registry_for_congestion = Arc::clone(&self.session_tx_registry);
        let congestion_monitor = Arc::clone(&self.congestion_monitor);
        let memory_budget = Arc::clone(&self.memory_budget);
        let peer_pubkeys_for_mem = Arc::clone(&self.identity.peer_pubkeys);
        let peer_vivaldi_for_mem = Arc::clone(&self.dispatcher.peer_vivaldi);
        let chunk_reassembler = Arc::clone(&self.dispatcher.chunk_reassembler);
        let reputation = self.dispatcher.reputation.clone();
        let cleanup_logger = Arc::clone(&self.logger);
        // Audit L-6: the maintenance tick enforces the documented 6h
        // rendezvous-cookie linkability TTL (evict_expired was implemented but
        // never wired to a periodic caller). None on non-relay nodes.
        let rendezvous_registry = self.dispatcher.rendezvous_registry.clone();
        // shared client-side TransportCache. Lives on
        // KademliaService; the maintenance tick periodically calls
        // `evict_stale` to keep cold entries from accumulating.
        let transport_cache = self.dht.transport_cache();
        // backlog: re-mint our own announcement at half-validity
        // so long-running peers don't go silent ~30 days after startup.
        // The session_outbox is used to re-gossip the fresh bundle to
        // every live peer when we re-mint.
        let session_outbox_for_remint = Arc::clone(&self.session_outbox);
        // discovered-peer cache snapshot. Periodic flush to
        // disk keeps the cache durable across crashes (the
        // `outbound_connector` upserts on every handshake, but only the
        // tick + shutdown writes to disk).
        let discovered_peers_cache = Arc::clone(&self.discovered_peers_cache);
        // snapshots of the anonymity-relay knobs + identity
        // material needed by `tick_publish_relay_directory_entry`.
        // Captured here (sync) so the spawned tick task doesn't need
        // to take the runtime lock to read them.
        let anonymity_relay_capable = self.anonymity.relay_capable;
        let anonymity_advertised_bps = self.anonymity.advertised_bps;
        let anonymity_x25519_sk = Arc::clone(&self.anonymity.x25519_sk);
        let local_identity_for_publish = Arc::clone(&self.identity.local_identity);
        let dht_for_publish = Arc::clone(&self.dht);
        let publish_logger = Arc::clone(&self.logger);
        // receiver-controlled rendezvous-publisher state.
        let rendezvous_publisher_entries = Arc::clone(&self.anonymity.rendezvous_publisher_entries);
        // follow-up: periodic refresh of adaptive params so the
        // proximity-gate threshold tightens automatically as the network
        // grows, without waiting for an explicit `node reload` from the
        // operator. Maintenance tick is the right home for this — same
        // cadence as the rest of the route-cache resize / metrics
        // refresh logic. Without periodic refresh the gate stays at its
        // bootstrap-mode default (gate=0) forever, weakening anti-
        // amplification on networks that grow past the bootstrap
        // threshold.
        let dispatcher_adaptive_params_for_tick = Arc::clone(&self.dispatcher.adaptive_params);
        let dht_for_tick = Arc::clone(&self.dht);
        let session_tx_registry_for_tick = Arc::clone(&self.session_tx_registry);
        // re-issue local sovereign delegation at half-validity.
        // Standalone-mode only — multi-device delegations need master-sk
        // intervention from a separate device, the tick will skip + log.
        // The veil_dir is the config file's parent; the on-change
        // reload poll in `runtime/sovereign_republish.rs` picks up the
        // mtime change within 60 s and DHT-republishes.
        let sovereign_identity_for_reissue = self.identity.sovereign_identity.clone();
        let veil_dir_for_reissue = self
            .config_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();
        let reissue_logger = Arc::clone(&self.logger);
        let tasks = Arc::clone(&self.tasks);
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            // deferred : tick counter for throttle decision.
            // Wraps at u64::MAX (~580 billion years at 1 Hz, not a concern).
            let mut tick_index: u64 = 0;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let now = std::time::Instant::now();
                        // ── Always-run phase: memory + congestion + heartbeat ──
                        // slice-1 explicitly excludes these from
                        // throttling: memory eviction protects the budget
                        // (correctness), congestion depth feeds adaptive
                        // backpressure (real-time signal), heartbeat is
                        // watchdog liveness — stretching it would trigger
                        // false-positive watchdog kicks.
                        Self::tick_update_congestion_depth(
                            &session_tx_registry_for_congestion,
                            &congestion_monitor,
                        );
                        Self::tick_account_memory_and_evict_over_budget(
                            &memory_budget,
                            &session_tx_registry_for_congestion,
                            &route_cache,
                            &dht,
                            &peer_pubkeys_for_mem,
                            &peer_vivaldi_for_mem,
                        );
                        // ── Throttle-able phase: TTL eviction + diagnostics ──
                        // When `low_battery_throttle_maintenance=true` AND
                        // battery is at-or-below threshold AND multiplier > 1
                        // skip on `(multiplier-1)/multiplier` of ticks.
                        // Default config: skip is always false → same as pre-
                        // slice behaviour for server / desktop / non-opted-in
                        // mobile deployments.
                        let battery = crate::runtime::local_battery_level();
                        let skip_throttleable =
                            mobile_cfg.skip_throttleable_maintenance(battery, tick_index);
                        if !skip_throttleable {
                            let evicted = Self::tick_evict_expired_primary_stores(
                                &gateway, &discovery, &dht,
                                &chunk_reassembler, &cleanup_logger, now,
                            );
                            Self::tick_record_eviction_metrics(evicted, metrics.as_ref());
                            // Enforce mailbox/outbox TTLs (pruned BEFORE the
                            // summary refresh so `mailbox_entries` reflects the
                            // post-prune count).
                            Self::tick_prune_expired_mailbox(
                                mailbox_for_summary.as_ref(),
                                outbox_for_prune.as_ref(),
                                &cleanup_logger,
                            );
                            let (route_cache_size, banned_peers) = Self::tick_evict_secondary_caches(
                                &route_cache, &rtt_table, &rate_limiter,
                                reputation.as_ref(), &ban_list, &violation_tracker,
                                &peer_mlkem_keys, e2e_key_ttl,
                            );
                            Self::tick_refresh_runtime_summary(
                                &runtime_summary, &state, &live_sessions, &discovery,
                                &dht, &mesh_forwarder, route_cache_size, banned_peers,
                                mailbox_for_summary.as_ref(),
                            );
                            Self::tick_evict_transport_cache(&transport_cache);
                            // Audit L-6: enforce the documented 6h
                            // rendezvous-cookie anti-linkability cap. Cookies
                            // from a session that never closes cleanly would
                            // otherwise persist past 6h (only unregister /
                            // clean-close drop_subscriber removed them before).
                            if let Some(reg) = &rendezvous_registry {
                                let dropped = reg.evict_expired(
                                    veil_util::unix_secs_now_u64(),
                                    veil_anonymity::rendezvous::DEFAULT_RENDEZVOUS_REGISTRY_TTL_SECS,
                                );
                                if dropped > 0 {
                                    cleanup_logger.info(
                                        "rendezvous.ttl_evicted",
                                        format!("cookies_removed={dropped}"),
                                    );
                                }
                            }
                            // follow-up: refresh adaptive params so
                            // the proximity gate scales with network size on
                            // its own, between explicit reloads.
                            Self::tick_refresh_adaptive_params(
                                &dispatcher_adaptive_params_for_tick,
                                &dht_for_tick,
                                &session_tx_registry_for_tick,
                            );
                            //sweep announcements
                            // for peers no longer in the routing table.
                            let _orphan_count = dht.prune_orphan_announcements();
                        }
                        // backlog: re-mint our local announcement
                        // at half-validity + re-gossip to all live peers.
                        Self::tick_remint_local_announcement(&dht, &session_outbox_for_remint);
                        // re-issue our sovereign delegation at
                        // half-validity (standalone mode only). No-op when
                        // the doc still has > half its window remaining or
                        // when this node runs in multi-device mode.
                        Self::tick_reissue_local_delegation(
                            sovereign_identity_for_reissue.as_ref(),
                            &veil_dir_for_reissue,
                            &reissue_logger,
                        );
                        // persist the discovered-peer cache to
                        // disk if it has any entries. Cheap (single JSON
                        // write of ≤ 32 entries × ~250 B ≈ 8 KB) and
                        // bounded — won't grow with uptime. No-op when
                        // `discovered_peers_cache_path` is unset.
                        Self::tick_save_discovered_peers_cache(&discovered_peers_cache);
                        // republish our relay-directory entry
                        // every tick (typ. 60s) so DHT consumers see the
                        // entry's last_published_unix advance well within
                        // the 24h freshness window. No-op when
                        // `[anonymity].relay_capable = false`.
                        Self::tick_publish_relay_directory_entry(
                            anonymity_relay_capable,
                            anonymity_advertised_bps,
                            &anonymity_x25519_sk,
                            &local_identity_for_publish,
                            &dht_for_publish,
                            &publish_logger,
                        );
                        // re-sign + DHT-store any
                        // active rendezvous-publisher entries near
                        // half-life. No-op when receiver has not
                        // called `register_rendezvous_publisher`.
                        Self::tick_publish_rendezvous_ads(
                            &rendezvous_publisher_entries,
                            &anonymity_x25519_sk,
                            &local_identity_for_publish,
                            &dht_for_publish,
                            &publish_logger,
                        );
                        Self::tick_prune_completed_task_handles(&tasks);
                        // Advance heartbeat so the watchdog knows we're alive.
                        health_tick.fetch_add(1, Ordering::Relaxed);
                        // Advance the throttle counter for next iteration.
                        tick_index = tick_index.wrapping_add(1);
                    }
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// update the TX queue depth reading in the congestion monitor.
    pub fn tick_update_congestion_depth(
        session_tx_registry: &Arc<RwLock<veil_session::SessionTxRegistry>>,
        congestion_monitor: &Arc<veil_congestion::CongestionMonitor>,
    ) {
        let depth = rlock!(session_tx_registry).total_queued();
        congestion_monitor.set_tx_queue_depth(depth);
    }

    /// 400.5: report every component's memory usage to the budget
    /// then evict 10 % of the lowest-priority component when over budget.
    #[allow(clippy::too_many_arguments)]
    pub fn tick_account_memory_and_evict_over_budget(
        memory_budget: &Arc<crate::memory::MemoryBudget>,
        session_tx_registry: &Arc<RwLock<veil_session::SessionTxRegistry>>,
        route_cache: &Arc<std::sync::RwLock<veil_routing::RouteCache>>,
        dht: &Arc<veil_dht::KademliaService>,
        peer_pubkeys: &PeerPubkeysCache,
        peer_vivaldi: &veil_dispatcher::PeerVivaldiCache,
    ) {
        use crate::memory::MemoryComponent;
        let session_mem = rlock!(session_tx_registry).estimated_memory();
        memory_budget.report(MemoryComponent::Sessions, session_mem);
        let rc_size = rlock!(route_cache).len();
        memory_budget.report(MemoryComponent::RouteCache, rc_size * 200);
        let dht_entries = dht.stored_keys();
        memory_budget.report(MemoryComponent::DhtStore, dht_entries * 4096);
        let pk_count = lock!(peer_pubkeys).map_len();
        memory_budget.report(MemoryComponent::PubkeyCache, pk_count * 80);
        let viv_count = rlock!(peer_vivaldi).len();
        memory_budget.report(MemoryComponent::Vivaldi, viv_count * 48);

        if !memory_budget.over_budget() {
            return;
        }
        let Some((comp, _usage)) = memory_budget.eviction_candidate() else {
            return;
        };
        match comp {
            MemoryComponent::Sessions => {
                wlock!(session_tx_registry).evict_lru(10);
            }
            MemoryComponent::RouteCache => {
                let new_cap = rc_size.saturating_sub(rc_size / 10).max(128);
                wlock!(route_cache).resize(new_cap);
            }
            MemoryComponent::Vivaldi => {
                let mut viv = wlock!(peer_vivaldi);
                let to_remove = viv.len() / 10;
                let mut oldest: Vec<([u8; 32], std::time::Instant)> =
                    viv.iter().map(|(k, (_, ts))| (*k, *ts)).collect();
                oldest.sort_by_key(|(_, ts)| *ts);
                for (k, _) in oldest.into_iter().take(to_remove) {
                    viv.remove(&k);
                }
            }
            MemoryComponent::PubkeyCache => {
                let mut cache = lock!(peer_pubkeys);
                let to_remove = cache.map_len() / 10;
                cache.evict_oldest(to_remove);
            }
            MemoryComponent::DhtStore => {
                dht.cleanup_expired(std::time::Instant::now());
            }
        }
    }

    /// Enforce the mailbox/outbox TTLs. Both stores bound total bytes on the
    /// `put` path, but a blob that is never ack'd (recipient never fetches) is
    /// otherwise reclaimed only under global-quota LRU pressure — never by time
    /// — so the documented 7-day mailbox / 30-day outbox TTLs need an explicit
    /// periodic prune. This stage was silently dropped when the old
    /// `MailboxCleanup` loop was renamed to the generic runtime-maintenance
    /// loop; without it the TTLs were inert and a never-ack'd blob held its
    /// quota slot forever. Best-effort: a prune error is logged, not fatal.
    fn tick_prune_expired_mailbox(
        mailbox: Option<&Arc<veil_mailbox::Mailbox>>,
        outbox: Option<&Arc<veil_mailbox::Outbox>>,
        logger: &Arc<NodeLogger>,
    ) {
        if let Some(mb) = mailbox {
            match mb.prune_expired() {
                Ok(n) if n > 0 => {
                    logger.info("mailbox.ttl_evicted", format!("blobs_removed={n}"));
                }
                Ok(_) => {}
                Err(e) => {
                    logger.warn("mailbox.ttl_prune_failed", format!("error={e}"));
                }
            }
        }
        if let Some(ob) = outbox {
            match ob.prune_expired() {
                Ok(n) if n > 0 => {
                    logger.info("outbox.ttl_evicted", format!("entries_removed={n}"));
                }
                Ok(_) => {}
                Err(e) => {
                    logger.warn("outbox.ttl_prune_failed", format!("error={e}"));
                }
            }
        }
    }

    /// Evict expired entries from the primary stores (gateway, discovery, DHT,
    /// chunk reassembler). Mailbox/outbox TTLs are handled separately by
    /// [`Self::tick_prune_expired_mailbox`].
    #[allow(clippy::too_many_arguments)]
    pub fn tick_evict_expired_primary_stores(
        gateway: &Arc<veil_gateway::GatewayService>,
        discovery: &Arc<veil_discovery::DiscoveryService>,
        dht: &Arc<veil_dht::KademliaService>,
        chunk_reassembler: &Arc<Mutex<veil_dispatcher::envelope_chunks::EnvelopeChunkReassembler>>,
        logger: &Arc<NodeLogger>,
        now: std::time::Instant,
    ) -> PrimaryEvictionCounts {
        gateway.cleanup_expired(now);

        let discovery_before = discovery.entry_count();
        discovery.cleanup_expired(now);
        let discovery_evicted = discovery_before.saturating_sub(discovery.entry_count());

        let dht_before = dht.stored_keys();
        dht.cleanup_expired(now);
        let dht_evicted = dht_before.saturating_sub(dht.stored_keys());

        // evict stale chunked transfers.
        let chunk_evicted = lock!(chunk_reassembler).evict_stale();
        if chunk_evicted > 0 {
            logger.info(
                "chunk.evict_stale",
                format!("evicted {chunk_evicted} stale transfer(s)"),
            );
        }

        PrimaryEvictionCounts {
            discovery_evicted,
            dht_evicted,
        }
    }

    /// Increment the `storage_evictions` counter once per evicted entry
    /// across discovery / DHT. No-op when the metric is unconfigured.
    pub fn tick_record_eviction_metrics(
        evicted: PrimaryEvictionCounts,
        metrics: Option<&Arc<NodeMetrics>>,
    ) {
        let total = evicted.discovery_evicted + evicted.dht_evicted;
        if total == 0 {
            return;
        }
        let Some(m) = metrics else { return };
        for _ in 0..total {
            m.inc_storage_evictions();
        }
    }

    /// Evict stale entries from the secondary caches (route cache, RTT
    /// rate limiter, reputation, ban list, violations, ML-KEM key cache).
    /// removed the replica quorum / fetch replica eviction.
    /// Returns `(route_cache_size, banned_peers)` for the summary refresh step.
    #[allow(clippy::too_many_arguments)]
    pub fn tick_evict_secondary_caches(
        route_cache: &Arc<std::sync::RwLock<veil_routing::RouteCache>>,
        rtt_table: &Arc<Mutex<veil_routing::RttTable>>,
        rate_limiter: &Arc<Mutex<veil_abuse::PerPeerLimiter>>,
        reputation: Option<&Arc<Mutex<veil_reputation::ReputationTracker>>>,
        ban_list: &Arc<Mutex<veil_abuse::BanList>>,
        violation_tracker: &Arc<Mutex<veil_abuse::ViolationTracker>>,
        peer_mlkem_keys: &Arc<std::sync::RwLock<veil_e2e::PeerMlKemCache>>,
        e2e_key_ttl: std::time::Duration,
    ) -> (usize, usize) {
        let route_cache_size = {
            let mut rc = wlock!(route_cache);
            rc.evict_expired();
            rc.len()
        };
        lock!(rtt_table).evict_stale();
        lock!(rate_limiter).evict_stale();
        if let Some(rep) = reputation {
            lock!(rep).evict_stale(std::time::Duration::from_secs(
                veil_proto::budget::REPUTATION_STALE_SECS,
            ));
        }
        let banned_peers = {
            let mut bl = lock!(ban_list);
            bl.evict_expired();
            bl.len()
        };
        lock!(violation_tracker).evict_stale();
        wlock!(peer_mlkem_keys).retain(|_, (_, cached_at): &mut (Vec<u8>, std::time::Instant)| {
            cached_at.elapsed() < e2e_key_ttl
        });
        (route_cache_size, banned_peers)
    }

    /// sweep stale entries out of the client-side
    /// transport cache shared by every `NetworkPeerQuerier` on this
    /// node. Cheap O(n) — `n` is bounded at `MAX_TRANSPORT_CACHE_ENTRIES`
    /// (~4 KiB worth of node_id keys).
    pub fn tick_evict_transport_cache(
        cache: &Arc<Mutex<veil_dht::transport_cache::TransportCache>>,
    ) {
        lock!(cache).evict_stale();
    }

    /// follow-up: refresh the dispatcher's adaptive params
    /// from the live routing table + active session count so the
    /// responder-proximity gate tightens as the network grows, without
    /// requiring an operator-driven `node reload`. Mirrors the
    /// computation in `reload_cycle` (`from_network_size` for cache/
    /// k-bucket fields, `min_responder_prefix_bits_from_observed`
    /// for the gate) so behavior is identical between explicit reload
    /// and periodic tick.
    pub fn tick_refresh_adaptive_params(
        dispatcher_params: &Arc<std::sync::RwLock<veil_cfg::adaptive::AdaptiveParams>>,
        dht: &Arc<veil_dht::KademliaService>,
        session_tx_registry: &Arc<RwLock<veil_session::SessionTxRegistry>>,
    ) {
        let rt_size = dht.routing_table_size();
        let sessions = rlock!(session_tx_registry).len();
        let est = veil_cfg::adaptive::estimate_network_size(rt_size, sessions);
        let mut params = veil_cfg::adaptive::AdaptiveParams::from_network_size(est.estimated_n);
        // feed the responder-proximity gate from
        // the **verified-handshake** session count only. The DHT routing
        // table is Sybil-influenceable (anyone can be inserted via
        // FIND_NODE responses), so combining it into the observed-peer
        // signal would let an attacker inflate the gate and reject
        // legitimate close-key responders. Cache sizes (`from_network_size`
        // above) keep the larger `est` because oversizing caches has no
        // security impact, only memory cost.
        params.min_responder_prefix_bits =
            veil_cfg::adaptive::AdaptiveParams::min_responder_prefix_bits_from_observed(sessions);
        // Single writer-lock acquisition; readers (recursive-response
        // handler in dispatcher/routing.rs) take the reader lock — no
        // contention in practice (gate read is one u32 copy).
        *wlock!(dispatcher_params) = params;
    }

    /// backlog: re-mint the local node's transport
    /// announcement at half-validity and re-gossip the fresh bundle
    /// to every live session peer via `AnnounceTransport`.
    ///
    /// Cheap no-op when the existing announcement is fresh
    /// (one HashMap lookup + one comparison). When re-minting is
    /// needed (~50 µs Ed25519 sign), a single `send_oneway` per live
    /// peer follows — bounded by the session count, typically O(K).
    ///
    /// Without this tick, a long-running peer's announcement expires
    /// `ANNOUNCEMENT_VALIDITY_SECS` (~30 days) after startup, after
    /// which `ResolveTransport(local)` returns `not_found` everywhere
    /// — censor-as-network-observer can simply wait it out.
    /// persist the discovered-peer cache to disk if any
    /// entries are present. Cheap (≤ 32 entries × ~250 B JSON ≈ 8 KB
    /// atomic write) and bounded — won't grow with uptime. No-op when
    /// the cache is in-memory only (`discovered_peers_cache_path = None`).
    pub fn tick_save_discovered_peers_cache(
        cache: &Arc<Mutex<veil_bootstrap::DiscoveredPeerCache>>,
    ) {
        let guard = lock!(cache);
        if guard.is_empty() {
            return;
        }
        // We swallow (don't propagate) save errors — a transient EIO
        // shouldn't bring the maintenance tick down. Cache will retry
        // next interval.
        let _ = guard.save();
    }

    /// publish (or re-publish) the local relay-directory
    /// entry to the DHT. Fires only when the operator opted in via
    /// `[anonymity].relay_capable = true`; otherwise no-op. When
    /// enabled, builds a fresh signed entry every tick (low cost: one
    /// Ed25519 sign + one DHT-store-local), so the entry's
    /// `last_published_unix` advances and downstream senders see the
    /// node as "freshly alive" inside the 24h freshness window.
    ///
    /// Returns `true` when an entry was published this tick (for
    /// metrics + tests); `false` when the no-op branch fired.
    pub fn tick_publish_relay_directory_entry(
        anonymity_relay_capable: bool,
        anonymity_advertised_bps: u32,
        anonymity_x25519_sk: &x25519_dalek::StaticSecret,
        local_identity: &crate::local_identity::HandshakeIdentity,
        dht: &Arc<veil_dht::kademlia::KademliaService>,
        logger: &Arc<veil_observability::NodeLogger>,
    ) -> bool {
        if !anonymity_relay_capable {
            return false;
        }
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let x25519_pk = x25519_dalek::PublicKey::from(anonymity_x25519_sk).to_bytes();
        let node_id = *local_identity.node_id.as_bytes();
        let bytes = match veil_anonymity::directory::sign_entry(
            node_id,
            x25519_pk,
            anonymity_advertised_bps,
            now_unix,
            &local_identity.public_key,
            &local_identity.private_key,
            local_identity.algo,
        ) {
            Ok(b) => b,
            Err(e) => {
                logger.warn("anonymity.relay_directory.sign_failed", format!("err={e}"));
                return false;
            }
        };
        let key = veil_anonymity::directory::relay_directory_dht_key(&node_id);
        dht.store_local(key, bytes);
        true
    }

    /// periodically re-sign + DHT-store every
    /// active `RendezvousAd` for receivers using rendezvous-routed
    /// inbound delivery.
    ///
    /// Per-entry flow:
    /// 1. Read existing ad from local DHT cache (key derived from
    ///    `local_node_id`, NOT from rendezvous_node_id — receivers
    ///    publish under their own identity so senders looking up
    ///    `@receiver` find them).
    /// 2. Decode + check freshness. If still has > half-window
    ///    remaining, skip (no DHT churn for entries already fresh).
    /// 3. Otherwise sign a fresh ad with `valid_from = now`
    ///    `valid_until = now + entry.validity_window_secs` and
    ///    `dht.store_local(...)`.
    ///
    /// Returns the count of ads refreshed this tick (for metrics +
    /// tests). Empty `entries` → 0 with no DHT mutation.
    pub fn tick_publish_rendezvous_ads(
        entries: &Arc<Mutex<Vec<veil_anonymity::rendezvous::RendezvousPublisherEntry>>>,
        anonymity_x25519_sk: &x25519_dalek::StaticSecret,
        local_identity: &crate::local_identity::HandshakeIdentity,
        dht: &Arc<veil_dht::kademlia::KademliaService>,
        logger: &Arc<veil_observability::NodeLogger>,
    ) -> usize {
        //.4 follow-up: publish each `RendezvousPublisherEntry`
        // under its own DHT slot (`rendezvous_ad_dht_key_at(receiver, idx)`)
        // so senders can fan-out mailbox puts to K=3+ replicas. Slot 0
        // is bit-exact with the legacy single-key derivation, so pre-T1.4
        // resolvers see whatever entry is in slot 0 and ignore the rest.
        //
        // Per-slot freshness check: if an existing ad in that slot
        // hasn't crossed half its validity window, skip re-signing it.
        // Operators with churning entry sets (entry added between
        // ticks) get their new entries published next tick — acceptable
        // since the maintenance period is short.
        use veil_anonymity::rendezvous::{
            MAX_RENDEZVOUS_AD_SLOTS, decode_rendezvous_ad, rendezvous_ad_dht_key_at,
            rendezvous_ad_needs_refresh, sign_rendezvous_ad,
        };
        let snapshot = lock!(entries).clone();
        if snapshot.is_empty() {
            return 0;
        }
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let receiver_node_id = *local_identity.node_id.as_bytes();
        let receiver_x25519_pk = x25519_dalek::PublicKey::from(anonymity_x25519_sk).to_bytes();
        // Cap per-receiver slots at MAX_RENDEZVOUS_AD_SLOTS to bound
        // DHT footprint when the entries vec grows pathologically.
        let n_slots = snapshot.len().min(MAX_RENDEZVOUS_AD_SLOTS as usize);
        let mut published = 0usize;
        for (idx, entry) in snapshot.iter().take(n_slots).enumerate() {
            let dht_key = rendezvous_ad_dht_key_at(&receiver_node_id, idx as u8);
            // Slot-level freshness check.
            if let Some(existing_bytes) = dht.get_local(&dht_key)
                && let Ok(ad) = decode_rendezvous_ad(&existing_bytes)
                && !rendezvous_ad_needs_refresh(
                    ad.valid_until_unix,
                    now_unix,
                    entry.validity_window_secs,
                )
            {
                continue;
            }
            let valid_from = now_unix;
            let valid_until = now_unix.saturating_add(entry.validity_window_secs);
            // mint a capability token and stash
            // it in the ad alongside the existing push_envelope. Senders
            // that read the ad via DHT include the token in their PUTs;
            // relays running with `require_capability_token = true` use this
            // to gate inbound mailbox deposits.
            //
            // For Ed25519 / Falcon-512 only. Hybrid (Ed25519+Falcon-512)
            // identities skip the token mint and publish a tokenless ad —
            // verify primitive doesn't support hybrid signatures.
            // Relays running require=true will reject puts from such senders;
            // operators with hybrid identities should keep require=false until
            // grows hybrid support.
            // v2 (relay-bound): per-replica token signed by entry.rendezvous_node_id.
            // Each ad carries a token that only its own replica accepts;
            // a malicious relay observing one cannot replay to another.
            let cap_token = mint_capability_token_for_ad(
                local_identity,
                entry.rendezvous_node_id,
                valid_from,
                valid_until,
                logger,
            );
            let bytes = match sign_rendezvous_ad(
                receiver_node_id,
                entry.rendezvous_node_id,
                entry.auth_cookie,
                receiver_x25519_pk,
                valid_from,
                valid_until,
                &entry.push_envelope, // .10: empty when no push registered
                &cap_token,
                &entry.wake_hmac_envelope, // .10 slice 4.3.2: empty until receiver opts in via IPC (slice 4.3.3)
                &local_identity.public_key,
                &local_identity.private_key,
                local_identity.algo,
            ) {
                Ok(b) => b,
                Err(e) => {
                    logger.warn(
                        "anonymity.rendezvous_ad.sign_failed",
                        format!("slot={idx} err={e}"),
                    );
                    continue;
                }
            };
            dht.store_local(dht_key, bytes);
            logger.info(
                "anonymity.rendezvous_ad.published",
                format!(
                    "slot={idx} rendezvous={} valid_until={valid_until}",
                    veil_util::hex_short(&entry.rendezvous_node_id),
                ),
            );
            published += 1;
        }
        published
    }

    pub fn tick_remint_local_announcement(
        dht: &Arc<veil_dht::kademlia::KademliaService>,
        session_outbox: &Arc<veil_session::SessionOutbox>,
    ) {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if dht.maybe_remint_local_announcement(now_unix).is_none() {
            return; // still fresh OR no source configured
        }
        // Re-gossip to every live peer — they each replace their
        // cached entry for our node_id with the new signature/expiry.
        for peer_id in session_outbox.peer_ids() {
            crate::runtime::send_local_announcement(dht, session_outbox, peer_id);
        }
    }

    /// re-issue the local sovereign delegation at
    /// half-validity so a long-running standalone node never lapses.
    ///
    /// Mirrors the `tick_remint_local_announcement` shape
    /// backlog: reads the active subkey's `valid_until_unix`, re-signs
    /// when `now + DELEGATION_VALIDITY_SECS / 2 ≥ valid_until`, then
    /// atomically writes the new document to
    /// `<veil_dir>/identity_document.bin`. The on-change mtime poll
    /// in `runtime/sovereign_republish.rs` (60 s cadence) picks up the
    /// new document and DHT-republishes — so the auto-reissue path is
    /// fully composed: tick re-signs → mtime-poll re-publishes → peers
    /// see the fresh `valid_until_unix` within ~1 minute.
    ///
    /// Standalone-mode only (master_pk == device_pk). Multi-device
    /// delegations require master-sk intervention from a different
    /// device; for those the tick logs at debug + is a no-op. The
    /// operator must run `veil-cli identity delegate-device` from
    /// the master before the existing 7-day delegation expires.
    pub fn tick_reissue_local_delegation(
        sovereign_identity: Option<&Arc<veil_identity::sovereign::SovereignIdentity>>,
        veil_dir: &std::path::Path,
        logger: &Arc<NodeLogger>,
    ) {
        use veil_proto::identity_document::DELEGATION_VALIDITY_SECS;

        let Some(sov) = sovereign_identity else {
            return;
        };
        if !sov.is_standalone() {
            // Multi-device: master_sk lives elsewhere — the on-change
            // reload poll picks up an externally-re-signed doc within
            // 60 s when the operator drops the new bytes in.
            return;
        }

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let active_idx = sov.sig_key_idx as usize;
        let Some(active_key) = sov.document.identity_keys.get(active_idx) else {
            return; // already validated at construction; defensive guard
        };
        let valid_until = active_key.valid_until_unix;
        let half_validity = DELEGATION_VALIDITY_SECS / 2;
        if now_unix + half_validity < valid_until {
            return; // > half the validity window still remains; cheap no-op
        }

        let new_valid_until = now_unix.saturating_add(DELEGATION_VALIDITY_SECS);
        let new_doc = match sov.reissue_self_delegation(now_unix, new_valid_until) {
            Ok(d) => d,
            Err(e) => {
                logger.warn(
                    "node.sovereign_identity.reissue_failed",
                    format!(
                        "node_id={} — reissue at half-validity failed: {e}",
                        veil_util::bytes_to_hex(sov.node_id()),
                    ),
                );
                return;
            }
        };

        let path = veil_dir.join(veil_identity::sovereign::IDENTITY_DOCUMENT_FILE);
        if let Err(e) = veil_util::atomic_write(&path, &new_doc.encode()) {
            logger.warn(
                "node.sovereign_identity.reissue_persist_failed",
                format!(
                    "node_id={} — wrote re-signed doc but atomic_write failed: {e}",
                    veil_util::bytes_to_hex(sov.node_id()),
                ),
            );
            return;
        }
        logger.info(
            "node.sovereign_identity.reissued",
            format!(
                "node_id={} prev_valid_until={} new_valid_until={} \
                 (standalone half-validity tick)",
                veil_util::bytes_to_hex(sov.node_id()),
                valid_until,
                new_valid_until,
            ),
        );
    }

    /// Refresh the PII-safe runtime summary exposed to admin endpoints.
    ///
    /// Audit M8: `mailbox_entries` now reports the real blob count from
    /// `Mailbox::stats()` (a cheap redb table-length read) instead of a
    /// hardcoded `0` that misled monitoring into reading "0 entries" when the
    /// figure was simply not measured. `None` (mailbox disabled) → genuinely 0;
    /// a transient stats read error keeps the previous value rather than
    /// reporting a false 0.
    #[allow(clippy::too_many_arguments)]
    pub fn tick_refresh_runtime_summary(
        runtime_summary: &Arc<Mutex<RuntimeSummary>>,
        state: &Arc<Mutex<NodeState>>,
        live_sessions: &Arc<
            Mutex<std::collections::BTreeMap<crate::types::LinkId, crate::types::SessionInfo>>,
        >,
        discovery: &Arc<veil_discovery::DiscoveryService>,
        dht: &Arc<veil_dht::KademliaService>,
        mesh_forwarder: &Arc<veil_mesh::MeshForwarder>,
        route_cache_size: usize,
        banned_peers: usize,
        mailbox: Option<&Arc<veil_mailbox::Mailbox>>,
    ) {
        let uptime_secs = lock_state(state).started_at.elapsed().as_secs();
        let active_sessions = lock!(live_sessions).len() as u64;
        mesh_forwarder.prune_neighbors();
        let mut summary = lock!(runtime_summary);
        summary.active_sessions = active_sessions;
        match mailbox {
            // mailbox disabled → genuinely zero stored entries.
            None => summary.mailbox_entries = 0,
            Some(mb) => {
                // A transient redb read error keeps the last good value rather
                // than reporting a misleading 0.
                if let Ok(stats) = mb.stats() {
                    summary.mailbox_entries = stats.blob_count as usize;
                }
            }
        }
        summary.discovery_entries = discovery.entry_count();
        summary.dht_keys = dht.stored_keys();
        summary.neighbor_count = mesh_forwarder.neighbor_count();
        summary.route_cache_size = route_cache_size;
        summary.banned_peers = banned_peers;
        summary.uptime_secs = uptime_secs;
    }

    /// Prune completed JoinHandles from `tasks.sessions` / `tasks.peers` to
    /// prevent unbounded growth on high-churn gateway nodes.
    pub fn tick_prune_completed_task_handles(tasks: &Arc<Mutex<RuntimeTasks>>) {
        let mut t = lock_tasks(tasks);
        t.sessions.retain(|h| !h.is_finished());
        t.peers.retain(|h| !h.is_finished());
    }
}

/// mint a mailbox capability token signed by
/// the receiver's identity sk, for stashing in `RendezvousAd.capability_token`.
///
/// Returns `vec![]` (empty / "no token") when:
/// * The local identity uses a hybrid (Ed25519+Falcon-512) signature —
///   verify primitive doesn't accept hybrid sigs yet.
/// * The base64 → raw conversion of the public key fails (config error).
/// * The signing routine fails.
///
/// Operators running mailbox with `require_capability_token = true` MUST
/// use a pure Ed25519 or Falcon-512 identity until grows
/// hybrid support. The empty fallback prevents pubishing a malformed
/// ad — receivers using hybrid simply won't have a token until then.
pub fn mint_capability_token_for_ad(
    local_identity: &crate::local_identity::HandshakeIdentity,
    relay_node_id: [u8; 32],
    valid_from_unix: u64,
    valid_until_unix: u64,
    logger: &NodeLogger,
) -> Vec<u8> {
    use base64::Engine as _;
    use veil_cfg::SignatureAlgorithm;
    let algo_byte = match local_identity.algo {
        SignatureAlgorithm::Ed25519 => veil_mailbox::ALGO_ED25519,
        SignatureAlgorithm::Falcon512 => veil_mailbox::ALGO_FALCON512,
        // Hybrid = no slice-1 support; receivers w/ hybrid keys publish
        // tokenless ads.
        _ => return Vec::new(),
    };
    // Public key on the wire is base64; decode to raw bytes.
    let pk_raw = match base64::engine::general_purpose::STANDARD.decode(&local_identity.public_key)
    {
        Ok(b) => b,
        Err(e) => {
            logger.warn(
                "mailbox.capability.mint",
                format!("base64 decode of pk failed: {e}"),
            );
            return Vec::new();
        }
    };
    let pk_b64 = local_identity.public_key.clone();
    let sk_b64 = local_identity.private_key.clone();
    let algo = local_identity.algo;
    let sign_fn = |msg: &[u8]| -> Vec<u8> {
        // Sign-failure is a config / fatal error. Empty sig produces
        // an invalid token that fails verify on the relay side; we
        // surface the empty bytes back to the caller which then stashes
        // empty `cap_token` in the ad. Logged at warn — operators
        // know what to do.
        veil_crypto::sign_message(algo, &pk_b64, &sk_b64, msg).unwrap_or_default()
    };
    // v2 bound token: relay_node_id is signed into the token, and the
    // relay's verify path checks expected_relay_id == its own node_id.
    // Closes cross-replica replay attack (malicious relay R observing
    // legitimate PUT cannot replay the token to a sibling replica R').
    match veil_mailbox::capability::sign_token_v2(
        algo_byte,
        &pk_raw,
        relay_node_id,
        valid_from_unix,
        valid_until_unix,
        sign_fn,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            logger.warn(
                "mailbox.capability.mint",
                format!("sign_token_v2 failed: {e}"),
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_identity::HandshakeIdentity;
    use veil_cfg::SignatureAlgorithm;
    use veil_dht::kademlia::KademliaService;
    use veil_observability::NodeLogger;

    fn fresh_identity() -> HandshakeIdentity {
        let kp = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519);
        let node_id =
            veil_cfg::NodeId::from_public_key(SignatureAlgorithm::Ed25519, &kp.public_key).unwrap();
        HandshakeIdentity {
            algo: SignatureAlgorithm::Ed25519,
            public_key: kp.public_key,
            private_key: kp.private_key,
            nonce: "AAAA".to_owned(),
            node_id,
        }
    }

    /// when `relay_capable = false` the helper is a
    /// strict no-op — no DHT mutation, returns `false`. This is the
    /// most common case (operator did NOT opt in to being a relay).
    #[test]
    fn epic482_4_publish_helper_is_noop_when_capability_disabled() {
        let identity = fresh_identity();
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let dht = Arc::new(KademliaService::new(*identity.node_id.as_bytes()));
        let logger = Arc::new(NodeLogger::new_noop());
        let dht_keys_before = dht.stored_keys();

        let did_publish = NodeRuntime::tick_publish_relay_directory_entry(
            false, 0, &sk, &identity, &dht, &logger,
        );

        assert!(
            !did_publish,
            "helper must report no-publish when capability off"
        );
        assert_eq!(
            dht.stored_keys(),
            dht_keys_before,
            "DHT must not be mutated when relay_capable = false"
        );
    }

    /// when `relay_capable = true` the helper signs +
    /// publishes a fresh entry under the deterministic DHT key.
    /// Verifies (a) DHT mutation happened (b) the entry is fetchable
    /// by `relay_directory_dht_key(node_id)` (c) the fetched entry
    /// passes `verify_entry` (d) the X25519 pubkey + bandwidth match
    /// what we passed in.
    #[test]
    fn epic482_4_publish_helper_writes_signed_entry_when_capability_enabled() {
        use veil_anonymity::directory::{decode_entry, relay_directory_dht_key, verify_entry};

        let identity = fresh_identity();
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let expected_pk = x25519_dalek::PublicKey::from(&sk).to_bytes();
        let dht = Arc::new(KademliaService::new(*identity.node_id.as_bytes()));
        let logger = Arc::new(NodeLogger::new_noop());

        let did_publish = NodeRuntime::tick_publish_relay_directory_entry(
            true, 1_000_000, &sk, &identity, &dht, &logger,
        );

        assert!(
            did_publish,
            "helper must report published when capability on"
        );

        // Fetch via the deterministic DHT key + decode + verify.
        let key = relay_directory_dht_key(identity.node_id.as_bytes());
        let bytes = dht
            .get_local(&key)
            .expect("entry must be reachable via relay_directory_dht_key");
        let entry = decode_entry(&bytes).expect("decode");
        verify_entry(&entry).expect("freshly-signed entry must verify");

        assert_eq!(
            entry.x25519_pk, expected_pk,
            "published x25519_pk must match the one derived from our sk"
        );
        assert_eq!(
            entry.advertised_bps, 1_000_000,
            "published advertised_bps must match what we passed in"
        );
        assert_eq!(
            entry.node_id,
            *identity.node_id.as_bytes(),
            "published node_id must match local identity"
        );
    }

    /// empty publisher entries → tick is a strict
    /// no-op (no DHT mutation, returns 0). Most-common-case for
    /// nodes that aren't using rendezvous-routed inbound delivery.
    #[test]
    fn epic482_5_publish_rendezvous_noop_when_empty() {
        let identity = fresh_identity();
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let dht = Arc::new(KademliaService::new(*identity.node_id.as_bytes()));
        let logger = Arc::new(NodeLogger::new_noop());
        let entries = Arc::new(Mutex::new(Vec::new()));
        let dht_keys_before = dht.stored_keys();

        let count =
            NodeRuntime::tick_publish_rendezvous_ads(&entries, &sk, &identity, &dht, &logger);

        assert_eq!(count, 0, "no publisher entries → tick must report 0");
        assert_eq!(
            dht.stored_keys(),
            dht_keys_before,
            "DHT must not be mutated"
        );
    }

    /// with one publisher entry, the tick signs
    /// and DHT-stores the ad. Verifies (a) DHT key is the per-receiver
    /// `rendezvous_ad_dht_key(receiver_node_id)`; (b) decoded ad has
    /// the expected rendezvous_node_id, auth_cookie, receiver_x25519_pk;
    /// (c) signature verifies.
    #[test]
    fn epic482_5_publish_rendezvous_signs_and_stores() {
        use veil_anonymity::rendezvous::{
            RendezvousPublisherEntry, decode_rendezvous_ad, rendezvous_ad_dht_key,
            verify_rendezvous_ad,
        };

        let identity = fresh_identity();
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let expected_pk = x25519_dalek::PublicKey::from(&sk).to_bytes();
        let dht = Arc::new(KademliaService::new(*identity.node_id.as_bytes()));
        let logger = Arc::new(NodeLogger::new_noop());

        let rendezvous_node_id = [0xCC; 32];
        let auth_cookie = [0xDD; 16];
        let entries = Arc::new(Mutex::new(vec![RendezvousPublisherEntry {
            rendezvous_node_id,
            auth_cookie,
            validity_window_secs: 24 * 3600,
            push_envelope: Vec::new(),
            wake_hmac_envelope: Vec::new(),
        }]));

        let count =
            NodeRuntime::tick_publish_rendezvous_ads(&entries, &sk, &identity, &dht, &logger);
        assert_eq!(count, 1);

        // Fetch by deterministic DHT key derived from RECEIVER's node_id.
        let key = rendezvous_ad_dht_key(identity.node_id.as_bytes());
        let bytes = dht.get_local(&key).expect("ad in DHT");
        let ad = decode_rendezvous_ad(&bytes).expect("decode");
        verify_rendezvous_ad(&ad).expect("verify");

        assert_eq!(ad.receiver_node_id, *identity.node_id.as_bytes());
        assert_eq!(ad.rendezvous_node_id, rendezvous_node_id);
        assert_eq!(ad.auth_cookie, auth_cookie);
        assert_eq!(ad.receiver_x25519_pk, expected_pk);
    }

    /// Maintenance tick mints **v2 (relay-bound)** capability tokens —
    /// the token in the published ad is bound to its `rendezvous_node_id`,
    /// not unbound v1. Verifies the token (a) decodes; (b) carries the
    /// matching `relay_node_id`; (c) verifies under that relay_id;
    /// (d) **fails** verify against a different relay_id (cross-replica
    /// replay rejection).
    #[test]
    fn mailbox_cap_v2_publish_rendezvous_mints_relay_bound_token() {
        use veil_anonymity::rendezvous::{
            RendezvousPublisherEntry, decode_rendezvous_ad, rendezvous_ad_dht_key,
        };
        use veil_mailbox::capability::MailboxCapabilityToken;

        let identity = fresh_identity();
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let dht = Arc::new(KademliaService::new(*identity.node_id.as_bytes()));
        let logger = Arc::new(NodeLogger::new_noop());

        let rendezvous_node_id = [0x7Au8; 32];
        let entries = Arc::new(Mutex::new(vec![RendezvousPublisherEntry {
            rendezvous_node_id,
            auth_cookie: [0xEE; 16],
            validity_window_secs: 3600,
            push_envelope: Vec::new(),
            wake_hmac_envelope: Vec::new(),
        }]));

        let n = NodeRuntime::tick_publish_rendezvous_ads(&entries, &sk, &identity, &dht, &logger);
        assert_eq!(n, 1, "tick must publish exactly one ad");

        let key = rendezvous_ad_dht_key(identity.node_id.as_bytes());
        let bytes = dht.get_local(&key).expect("ad in DHT");
        let ad = decode_rendezvous_ad(&bytes).expect("decode ad");

        assert!(
            !ad.capability_token.is_empty(),
            "Ed25519 receiver must publish a non-empty cap_token"
        );

        let token =
            MailboxCapabilityToken::decode(&ad.capability_token).expect("cap_token must decode");
        assert_eq!(
            token.relay_node_id,
            Some(rendezvous_node_id),
            "v2 token must carry the rendezvous_node_id as relay binding"
        );

        // receiver_id = BLAKE3(issuer_pk) — token's verify binds this.
        let receiver_id = *blake3::hash(&token.issuer_pk).as_bytes();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Verifies against its own relay_id.
        token
            .verify(&receiver_id, Some(&rendezvous_node_id), now_unix)
            .expect("v2 token must verify against its bound relay_id");

        // Cross-replica replay rejection.
        let other_relay = [0x42u8; 32];
        let res = token.verify(&receiver_id, Some(&other_relay), now_unix);
        assert!(
            res.is_err(),
            "v2 token must NOT verify against a different relay_id (cross-replica replay)"
        );
    }

    /// re-running the tick when the existing ad
    /// is still fresh (>50% window remaining) is a no-op. The
    /// existing DHT bytes stay byte-equal — no wasted DHT churn.
    #[test]
    fn epic482_5_publish_rendezvous_skips_when_still_fresh() {
        use veil_anonymity::rendezvous::{RendezvousPublisherEntry, rendezvous_ad_dht_key};

        let identity = fresh_identity();
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let dht = Arc::new(KademliaService::new(*identity.node_id.as_bytes()));
        let logger = Arc::new(NodeLogger::new_noop());

        let entries = Arc::new(Mutex::new(vec![RendezvousPublisherEntry {
            rendezvous_node_id: [0xAA; 32],
            auth_cookie: [0xBB; 16],
            validity_window_secs: 24 * 3600,
            push_envelope: Vec::new(),
            wake_hmac_envelope: Vec::new(),
        }]));

        // First tick — publishes.
        let n1 = NodeRuntime::tick_publish_rendezvous_ads(&entries, &sk, &identity, &dht, &logger);
        assert_eq!(n1, 1);
        let key = rendezvous_ad_dht_key(identity.node_id.as_bytes());
        let bytes_after_first = dht.get_local(&key).expect("ad in DHT").to_vec();

        // Second tick without passage of time — ad is still very fresh
        // tick must skip and leave bytes byte-equal.
        let n2 = NodeRuntime::tick_publish_rendezvous_ads(&entries, &sk, &identity, &dht, &logger);
        assert_eq!(n2, 0, "still-fresh ad must NOT trigger republish");
        let bytes_after_second = dht.get_local(&key).expect("ad still in DHT").to_vec();
        assert_eq!(
            bytes_after_first, bytes_after_second,
            "DHT bytes must be unchanged when republish was skipped"
        );
    }

    /// every tick republishes — even when nothing changed
    /// `last_published_unix` should advance so DHT consumers see the
    /// node as "freshly alive" inside the freshness window. Two
    /// consecutive ticks separated by a 1-second wall-clock boundary
    /// must produce entries with strictly increasing timestamps.
    #[test]
    fn epic482_4_publish_helper_advances_last_published_on_repeated_calls() {
        use veil_anonymity::directory::{decode_entry, relay_directory_dht_key};

        let identity = fresh_identity();
        let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let dht = Arc::new(KademliaService::new(*identity.node_id.as_bytes()));
        let logger = Arc::new(NodeLogger::new_noop());

        NodeRuntime::tick_publish_relay_directory_entry(true, 0, &sk, &identity, &dht, &logger);
        let key = relay_directory_dht_key(identity.node_id.as_bytes());
        let t1 = decode_entry(&dht.get_local(&key).unwrap())
            .unwrap()
            .last_published_unix;

        // Sleep ≥ 1 s so the second tick crosses a wall-clock boundary.
        std::thread::sleep(std::time::Duration::from_secs(1));

        NodeRuntime::tick_publish_relay_directory_entry(true, 0, &sk, &identity, &dht, &logger);
        let t2 = decode_entry(&dht.get_local(&key).unwrap())
            .unwrap()
            .last_published_unix;

        assert!(
            t2 > t1,
            "second tick must advance last_published_unix; t1={t1} t2={t2}"
        );
    }

    /// follow-up: the periodic refresh helper must overwrite
    /// any stale params currently held by the dispatcher with values
    /// computed from live network state. On an empty network the gate
    /// must collapse to 0 (bootstrap-friendly), even when the starting
    /// params claimed a tight gate from a previous big-network state —
    /// otherwise a node that loses peers would keep rejecting its own
    /// recovery handshake responses.
    #[test]
    fn phase6_27_followup_tick_refresh_overwrites_with_observed_state() {
        let identity = fresh_identity();
        let dht = Arc::new(KademliaService::new(*identity.node_id.as_bytes()));
        let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));

        // Pre-populate dispatcher params with a "stale big-network" view
        // (gate=10, as if from N=2^14 reload). After refresh on an
        // empty live network it must drop to 0.
        let mut stale = veil_cfg::adaptive::AdaptiveParams::from_network_size(16_384);
        stale.min_responder_prefix_bits = 10;
        let dispatcher_params = Arc::new(std::sync::RwLock::new(stale));

        NodeRuntime::tick_refresh_adaptive_params(&dispatcher_params, &dht, &registry);

        let refreshed = *dispatcher_params.read().unwrap();
        assert_eq!(
            refreshed.min_responder_prefix_bits, 0,
            "empty network → gate=0 (bootstrap-mode), regardless of pre-tick value"
        );
    }

    /// follow-up: as live observed peers grow, the gate
    /// returned by the tick must follow `min_responder_prefix_bits_from_observed`
    /// — i.e. with 64 active sessions the gate moves to `log2(64)-4 = 2`.
    /// This is the whole point of the periodic refresh: without it the
    /// gate would stay at the bootstrap default forever.
    #[test]
    fn phase6_27_followup_tick_refresh_tightens_gate_as_sessions_grow() {
        let identity = fresh_identity();
        let dht = Arc::new(KademliaService::new(*identity.node_id.as_bytes()));
        let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));

        // Hold the receivers — dropping them detaches senders, which is
        // fine for `.len` but keeps the test honest about lifetimes.
        let mut _rx_keepalive = Vec::with_capacity(64);
        {
            let mut reg = registry.write().unwrap();
            for i in 0..64u8 {
                let mut peer = [0u8; 32];
                peer[0] = i;
                _rx_keepalive.push(reg.register(peer));
            }
            assert_eq!(reg.len(), 64, "all 64 peers must be registered");
        }

        let dispatcher_params = Arc::new(std::sync::RwLock::new(
            veil_cfg::adaptive::AdaptiveParams::default(),
        ));

        NodeRuntime::tick_refresh_adaptive_params(&dispatcher_params, &dht, &registry);

        let refreshed = *dispatcher_params.read().unwrap();
        let expected =
            veil_cfg::adaptive::AdaptiveParams::min_responder_prefix_bits_from_observed(64);
        assert_eq!(
            refreshed.min_responder_prefix_bits, expected,
            "gate must match the formula for observed=64 (sessions); got {} expected {}",
            refreshed.min_responder_prefix_bits, expected
        );
        assert_eq!(expected, 2, "sanity: log2(64)-4 = 2");
    }
}
