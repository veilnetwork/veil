//! Periodic routing-plane + health maintenance tasks:
//! `spawn_pow_pending_cleanup`: evicts expired PoW challenges.
//! `spawn_gateway_eviction_task`: drops stale gateway-list entries.
//! `spawn_health_watchdog`: watches the health-tick counter; emits
//! a warn-log when the tick hasn't advanced in 5 s.
//! `spawn_route_probe_task_with`: sends periodic ROUTE_PROBE pings.
//! `spawn_route_refresh_task`: re-announces this node on the routing
//! gossip bus.
//! `spawn_congestion_withdraw_task`: monitors load, withdraws the
//! node from the route-cache when overloaded.
//!
//! Extracted from `runtime/mod.rs` during refactor.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use veil_util::{lock, rlock};

use rand_core::{OsRng, RngCore};

use crate::types::{NodeId, NodeIdBytes};
use veil_routing::RttTable;

use super::{NodeRuntime, lock_tasks, supervised_spawn};

impl NodeRuntime {
    /// Spawn a background task that evicts expired PoW challenge entries.
    ///
    /// Runs every [`POW_CHALLENGE_TTL_SECS`] seconds. Without this task
    /// `pow_pending` is only cleaned lazily on each new `PowChallenge` receipt
    /// so entries accumulate until the next challenge arrives. On idle nodes
    /// the map could retain stale entries for an unbounded period.
    pub fn spawn_pow_pending_cleanup(&mut self) {
        use veil_proto::budget::POW_CHALLENGE_TTL_SECS;
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let pow_pending = Arc::clone(&self.dispatcher.pow_pending);
        let ttl = std::time::Duration::from_secs(POW_CHALLENGE_TTL_SECS);
        let handle = supervised_spawn(
            Arc::clone(&self.logger),
            "pow_pending_cleanup",
            async move {
                let mut interval = tokio::time::interval(ttl);
                loop {
                    tokio::select! {
                        Ok(_) = shutdown_rx.changed() => break,
                        _ = interval.tick() => {
                            let now = std::time::Instant::now();
                            lock!(pow_pending).evict_stale(now, ttl);
                        }
                    }
                }
            },
        );
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// Spawn a background task that prunes expired entries from the
    /// `HandoffRegistry`. The registry auto-prunes opportunistically on
    /// `insert`/`consume` operations, но а quiet session can accumulate
    /// stale entries для bounded time before the cap-eviction kicks in.
    /// This periodic tick guarantees prompt expiry.
    pub fn spawn_handoff_prune_task(&mut self, interval_dur: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let registry = Arc::clone(&self.handoff.registry);
        let handle = supervised_spawn(Arc::clone(&self.logger), "handoff_prune", async move {
            let mut interval = tokio::time::interval(interval_dur);
            loop {
                tokio::select! {
                    Ok(_) = shutdown_rx.changed() => break,
                    _ = interval.tick() => {
                        registry.prune_expired();
                    }
                }
            }
        });
        lock_tasks(&self.tasks).background.push(handle);
    }

    /// Spawn а periodic prune task для closed channels в the
    /// `SessionTxRegistry`.
    ///
    /// Audit batch 2026-05-24 (M4): the registry's internal `prune_closed`
    /// fires only on `register` / `unregister` paths.  Hosts running
    /// pure-broadcast traffic (mesh hubs) с no new session churn could
    /// otherwise accumulate closed-channel entries indefinitely → RAM
    /// drift.  This tick guarantees bounded growth.
    pub fn spawn_tx_registry_prune_task(&mut self, interval_dur: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let registry = Arc::clone(&self.session_tx_registry);
        let logger = Arc::clone(&self.logger);
        let handle = supervised_spawn(
            Arc::clone(&self.logger),
            "session_tx_registry_prune",
            async move {
                let mut interval = tokio::time::interval(interval_dur);
                interval.tick().await; // skip immediate first tick
                loop {
                    tokio::select! {
                        Ok(_) = shutdown_rx.changed() => break,
                        _ = interval.tick() => {
                            // Audit-lint: `wlock!` resolves к а std::sync write guard.
                            // No `.await` inside the critical section (workspace
                            // `clippy::await_holding_lock = "deny"` enforces this).
                            let pruned = veil_util::wlock!(registry).prune_closed_external();
                            if pruned > 0 {
                                logger.debug(
                                    "session_tx_registry.prune",
                                    format!("removed {pruned} closed entries"),
                                );
                            }
                        }
                    }
                }
            },
        );
        lock_tasks(&self.tasks).background.push(handle);
    }

    /// Spawn a background task that evicts expired gateway attachment leases.
    ///
    /// Runs every 10 seconds. The lease TTL is taken from
    /// `config.gateway.attachment_lease_ttl_secs`. Only relevant on
    /// Gateway/Core nodes but safe to run on any role (the table is empty on
    /// Leaf/Relay nodes).
    pub fn spawn_gateway_eviction_task(&mut self) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let gateway = Arc::clone(&self.gateway);
        let handle = supervised_spawn(Arc::clone(&self.logger), "gateway_eviction", async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        gateway.cleanup_expired(std::time::Instant::now());
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

    /// Spawn a health watchdog that logs a WARN if the cleanup loop stalls.
    ///
    /// The watchdog samples `health_tick` every 30 seconds. If it hasn't
    /// advanced by at least 10 ticks (≈ 10 s of work), the event loop is
    /// considered stalled and a WARN is emitted.
    pub fn spawn_health_watchdog(&mut self) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let health_tick = Arc::clone(&self.health_tick);
        let logger = Arc::clone(&self.logger);
        let handle = supervised_spawn(Arc::clone(&self.logger), "health_watchdog", async move {
            const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
            // Conservative threshold: only warn if fewer than 2 ticks in 30s.
            // This avoids false alarms when cleanup_interval is configured > 3s.
            const MIN_TICKS: u64 = 2;
            let mut last = health_tick.load(Ordering::Relaxed);
            let mut interval = tokio::time::interval(CHECK_INTERVAL);
            interval.tick().await; // skip immediate first tick
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let now = health_tick.load(Ordering::Relaxed);
                        if now.wrapping_sub(last) < MIN_TICKS {
                            logger.warn(
                                "node.health_stall",
                                format!(
                                    "cleanup loop advanced only {} ticks in last {}s — \
                                     event loop may be stalled",
                                    now.wrapping_sub(last),
                                    CHECK_INTERVAL.as_secs(),
                                ),
                            );
                        }
                        last = now;
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

    /// Compute the adaptive probe interval for a peer based on RTT stability
    ///
    ///
    /// * Stable path (`stability < threshold`) → use `max_interval` (rare probing).
    /// * Unstable / unknown path → linearly interpolate between `min_interval`
    ///   and `max_interval` proportional to `stability / threshold`, clamped so
    ///   the result stays within `[min_interval, max_interval]`.
    fn adaptive_probe_interval(
        stability: f64,
        threshold: f64,
        min_interval: std::time::Duration,
        max_interval: std::time::Duration,
    ) -> std::time::Duration {
        if stability >= f64::MAX || threshold <= 0.0 {
            // No stability data yet or misconfigured threshold — probe often.
            return min_interval;
        }
        if stability < threshold {
            // Path is stable — back off to the maximum interval.
            return max_interval;
        }
        // Linearly interpolate: at threshold → max_interval; at 2×threshold → min_interval.
        // t = (stability - threshold) / threshold, clamped [0, 1].
        let t = ((stability - threshold) / threshold).clamp(0.0, 1.0);
        let min_ms = min_interval.as_millis() as f64;
        let max_ms = max_interval.as_millis() as f64;
        let ms = (max_ms + t * (min_ms - max_ms)).round() as u64;
        std::time::Duration::from_millis(ms.max(1000))
    }

    /// Build a serialised `ROUTE_PROBE` frame ready for `send_to`.
    ///
    /// Used for the immediate startup probe and by the
    /// periodic probe scheduler. `probe_id = 0` is used for one-shot probes
    /// where we don't need to correlate the reply.
    fn build_route_probe_frame() -> Vec<u8> {
        use veil_proto::{
            codec::encode_header,
            control::RouteProbePayload,
            family::{ControlMsg, FrameFamily},
            header::FrameHeader,
        };
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        let payload = RouteProbePayload {
            probe_id: 0,
            timestamp_ms,
        };
        let body = payload.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::RouteProbe as u16);
        hdr.body_len = body.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&body);
        frame
    }

    /// Send an immediate `ROUTE_PROBE` to `peer_id` if the peer is known
    /// (has a non-zero contact count in the RTT table 145.3).
    ///
    /// Configured outbound peers are always probed; inbound peers are only
    /// probed if we have prior contact history so random clients can't trigger
    /// unsolicited probe traffic.
    pub fn send_startup_probe_if_known(
        rtt_table: &Arc<Mutex<RttTable>>,
        tx_registry: &Arc<RwLock<veil_session::SessionTxRegistry>>,
        peer_id: NodeId,
        always_probe: bool,
    ) {
        let known = always_probe || lock!(rtt_table).contact_count(peer_id.as_bytes()) > 0;
        if !known {
            return;
        }
        rlock!(tx_registry).send_to(
            peer_id.as_bytes(),
            veil_proto::priority::INTERACTIVE,
            Self::build_route_probe_frame(),
        );
    }

    /// Spawn a background task that sends `ROUTE_PROBE` to each active session
    /// at an adaptive rate based on RTT stability.
    ///
    /// Stable paths (low jitter) are probed infrequently (`max_interval`);
    /// unstable or newly-seen paths are probed at `min_interval`. A ±10 %
    /// random jitter is applied to prevent synchronised probe bursts when many
    /// peers are added at the same time.
    ///
    /// when `mobile.low_battery_threshold_pct` is configured
    /// and the local battery is at-or-below the threshold, every per-peer
    /// interval is multiplied by `mobile.low_battery_multiplier` so the
    /// node stops draining the device while still keeping enough
    /// liveness signal for the network to notice we exist. The battery
    /// is sampled once per outer-loop tick (1 s) so the throttle reacts
    /// to a charger plug-in within ~1 s.
    pub fn spawn_route_probe_task_with(
        &mut self,
        min_interval: std::time::Duration,
        max_interval: std::time::Duration,
        stability_threshold: f64,
        mobile: veil_cfg::MobileConfig,
    ) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let session_tx_registry = Arc::clone(&self.session_tx_registry);
        let rtt_table = self.control_plane.rtt_table();
        let handle = supervised_spawn(Arc::clone(&self.logger), "route_probe", async move {
            use std::collections::HashMap;
            use std::time::Instant;
            use veil_proto::{
                codec::encode_header,
                control::RouteProbePayload,
                family::{ControlMsg, FrameFamily},
                header::FrameHeader,
            };

            // Per-peer next-probe deadline.
            let mut next_probe: HashMap<NodeIdBytes, Instant> = HashMap::new();
            let mut probe_id: u32 = 0;

            // Tick every second to check per-peer deadlines.
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                    _ = interval.tick() => {}
                }

                let now = Instant::now();

                // follow-up: skip route-probe loop entirely
                // on LowPower tier (Doze / iOS BackgroundTask). Probe
                // traffic costs ~50-200 B per peer per ~30 s — modest on
                // its own, but on a phone in Doze EVERY background
                // wake-up shortens battery life, and route freshness is
                // not load-bearing while the user can't observe it.
                // Foreground / Active tiers continue probing normally.
                if veil_session::runner::should_suppress_background_maintenance() {
                    continue;
                }

                let peer_ids = rlock!(session_tx_registry).peer_ids();

                // sample battery once per outer tick (cheap;
                // single file read on Linux, no-op elsewhere). When
                // mobile config is at defaults this is a no-op multiplier
                // path, so the cost of the sample is paid only when the
                // operator opted in to mobile mode.
                let battery_mult = if mobile.low_battery_threshold_pct.is_some() {
                    mobile.battery_multiplier(crate::runtime::local_battery_level())
                } else {
                    1
                };

                for peer_id in peer_ids {
                    // Check deadline.
                    let due = next_probe.get(&peer_id).copied().unwrap_or(now);
                    if now < due {
                        continue;
                    }

                    // Determine adaptive interval for this peer.
                    let stability = lock!(rtt_table)
                        .get(&peer_id)
                        .map(|p| p.stability())
                        .unwrap_or(f64::MAX);
                    let base = Self::adaptive_probe_interval(
                        stability,
                        stability_threshold,
                        min_interval,
                        max_interval,
                    );
                    // stretch the interval by the
                    // battery-aware multiplier (1 = no throttle when
                    // disabled / above-threshold / on AC).
                    let throttled = base.saturating_mul(battery_mult);
                    // Apply ±10 % jitter to avoid synchronised probe bursts.
                    let jitter_range_ms = (throttled.as_millis() as u64) / 5; // 20% total range
                    let rnd = OsRng.next_u64();
                    let jitter_ms =
                        (rnd % (jitter_range_ms + 1)) as i64 - (jitter_range_ms / 2) as i64;
                    let interval_ms = (throttled.as_millis() as i64 + jitter_ms).max(1000) as u64;
                    next_probe.insert(peer_id, now + std::time::Duration::from_millis(interval_ms));

                    // Build and send the probe.
                    probe_id = probe_id.wrapping_add(1);
                    let timestamp_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                        .unwrap_or(0);
                    let payload = RouteProbePayload {
                        probe_id,
                        timestamp_ms,
                    };
                    let body = payload.encode();
                    let mut hdr =
                        FrameHeader::new(FrameFamily::Control as u8, ControlMsg::RouteProbe as u16);
                    hdr.body_len = body.len() as u32;
                    hdr.set_priority(veil_proto::priority::INTERACTIVE);
                    let mut frame = encode_header(&hdr).to_vec();
                    frame.extend_from_slice(&body);

                    rlock!(session_tx_registry).send_to(
                        &peer_id,
                        veil_proto::priority::INTERACTIVE,
                        frame,
                    );
                }

                // Clean up departed peers from the deadline map.
                next_probe.retain(|_, deadline| now < *deadline + max_interval * 2);
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// Periodically re-announce every direct peer to all others so that remote
    /// `RouteCache` entries (TTL = 120 s) are refreshed before they expire.
    ///
    /// `interval` is configurable via `config.routing.reannounce_interval_secs`
    /// (default 30 s).
    pub fn spawn_route_refresh_task(&mut self, interval: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let dispatcher = Arc::clone(&self.dispatcher);
        let route_cache = Arc::clone(&self.routing.route_cache);
        let session_tx_registry = Arc::clone(&self.session_tx_registry);
        let dht_for_refresh = Arc::clone(&self.dht);
        let handle = tokio::spawn(async move {
            let mut cycle = 0u32;
            loop {
                // adaptive announce rate — scale interval by
                // log2(routing_table_size) so larger networks gossip less
                // frequently. Minimum: base interval; maximum: base × 10.
                let rt_size = dht_for_refresh.routing_table_size().max(1);
                let scale = (rt_size as f64).log2().clamp(1.0, 10.0);
                let adaptive_interval = interval.mul_f64(scale);
                tokio::select! {
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                    _ = tokio::time::sleep(adaptive_interval) => {}
                }
                cycle += 1;

                // Legacy refresh every 5th cycle (= ~2.5 min instead of every 30s).
                // Event-driven RouteUpdate handles the fast path; this is backward
                // compat for peers that don't support RouteUpdate yet.
                if cycle.is_multiple_of(5) {
                    dispatcher.refresh_all_routes();
                }

                // version-vector exchange every 10th cycle (~5 min).
                if cycle.is_multiple_of(10) {
                    let summary = rlock!(route_cache).version_summary();
                    if !summary.is_empty() {
                        let vv = veil_proto::routing::VersionVectorSyncPayload { entries: summary };
                        let body = vv.encode();
                        let mut hdr = veil_proto::header::FrameHeader::new(
                            veil_proto::family::FrameFamily::Routing as u8,
                            veil_proto::family::RoutingMsg::VersionVectorSync as u16,
                        );
                        hdr.body_len = body.len() as u32;
                        let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
                        frame.extend_from_slice(&body);
                        rlock!(session_tx_registry)
                            .send_to_all(veil_bufpool::pooled_shared_from_vec(frame));
                    }
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    /// React to `CongestionMonitor` admitting-state transitions.
    ///
    /// * `admitting → false`: wait `WITHDRAW_FLAP_DELAY` before sending
    ///   `ROUTE_WITHDRAW`. If the node recovers (admitting → true) within that
    ///   window the withdrawal is cancelled — avoiding spurious churn from short
    ///   load spikes (flap dampening).
    /// * `admitting → true`: send `ROUTE_ANNOUNCE(origin = local_node_id, hop = 0)`
    ///   immediately so peers can route through this node again.
    pub fn spawn_congestion_withdraw_task(&mut self) {
        /// How long to wait before actually broadcasting ROUTE_WITHDRAW after
        /// the congestion monitor crosses the high-watermark. Brief spikes that
        /// recover within this window produce no gossip churn.
        const WITHDRAW_FLAP_DELAY: std::time::Duration = std::time::Duration::from_secs(3);

        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let dispatcher = Arc::clone(&self.dispatcher);
        let mut admitting_rx = self.congestion_monitor.admitting_rx.clone();
        let local_node_id = self.dispatcher.local_node_id;
        let logger = Arc::clone(&self.logger);
        let handle = tokio::spawn(async move {
            // `pending_withdraw`: Some(deadline) when we are waiting to send a
            // ROUTE_WITHDRAW, None when the node is currently admitting (or we
            // already withdrew).
            let mut pending_withdraw: Option<tokio::time::Instant> = None;

            loop {
                // Build the withdraw deadline future only when a withdrawal is pending.
                let withdraw_sleep = async {
                    if let Some(deadline) = pending_withdraw {
                        tokio::time::sleep_until(deadline).await
                    } else {
                        // Never fires while no withdrawal is pending.
                        std::future::pending::<()>().await
                    }
                };

                tokio::select! {
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                    Ok(_) = admitting_rx.changed() => {
                        let now_admitting = *admitting_rx.borrow();
                        if now_admitting {
                            // Cancel any pending withdrawal — the spike was transient.
                            if pending_withdraw.take().is_some() {
                                logger.info("congestion.flap_cancelled",
                                    "load recovered within flap window — withdraw suppressed");
                            } else {
                                logger.info("congestion.recover",
                                    "load dropped — re-announcing self");
                            }
                            dispatcher.reannounce_self(local_node_id.into());
                        } else {
                            // Schedule a withdrawal after the flap delay.
                            logger.warn("congestion.overload",
                                "load high — scheduling route-withdraw in 3 s");
                            pending_withdraw =
                                Some(tokio::time::Instant::now() + WITHDRAW_FLAP_DELAY);
                        }
                    }
                    _ = withdraw_sleep => {
                        // Flap delay elapsed and load is still high — broadcast withdraw.
                        pending_withdraw = None;
                        logger.warn("congestion.withdraw",
                            "flap delay elapsed — withdrawing self from routing");
                        dispatcher.withdraw_self(local_node_id.into());
                    }
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }
}
