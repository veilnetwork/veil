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

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::{sync::watch, time::Instant};
use veil_util::{lock, rlock};

use rand_core::{OsRng, RngCore};

use crate::types::NodeId;
use veil_routing::RttTable;
use veil_session::tx_registry::SessionTxRegistry;

use super::{NodeRuntime, lock_tasks, supervised_spawn};

async fn run_route_probes(
    registry: Arc<RwLock<SessionTxRegistry>>,
    rtt_table: Arc<Mutex<RttTable>>,
    mut shutdown: watch::Receiver<bool>,
    mut background_tier: watch::Receiver<u8>,
    mobile: veil_cfg::MobileConfig,
    probe_interval: impl Fn(f64) -> Duration,
) {
    let mut session_changes = rlock!(registry).subscribe_session_changes();
    let mut next_probe = HashMap::new();
    let mut probe_id = 0_u32;
    let clock_start = Instant::now();

    while !*shutdown.borrow() {
        let paused = *background_tier.borrow_and_update() == 2;
        let mut deadline = None;
        if !paused {
            // Mark before taking the snapshot so a concurrent registration
            // either appears in the snapshot or wakes the next iteration.
            session_changes.mark_unchanged();
            let peers = {
                let registry = rlock!(registry);
                next_probe.retain(|peer, _| registry.has_session(peer));
                registry.live_registrations().collect::<Vec<_>>()
            };
            let now = Instant::now();
            let mut battery_multiplier = None;

            for (peer, registration) in peers {
                if next_probe.get(&peer).is_some_and(|due| now < *due) {
                    continue;
                }
                let multiplier = *battery_multiplier.get_or_insert_with(|| {
                    if mobile.low_battery_threshold_pct.is_some() {
                        mobile.battery_multiplier(crate::runtime::local_battery_level())
                    } else {
                        1
                    }
                });
                let stability = lock!(rtt_table)
                    .get(&peer)
                    .map_or(f64::MAX, |rtt| rtt.stability());
                let interval = probe_interval(stability).saturating_mul(multiplier);

                // Keep the previous one-second resolution so many staggered
                // peers can share one wakeup without sending a probe early.
                let jitter_range_ms = (interval.as_millis() as u64) / 5;
                let jitter_ms = (OsRng.next_u64() % (jitter_range_ms + 1)) as i64
                    - (jitter_range_ms / 2) as i64;
                let interval_ms = (interval.as_millis() as i64 + jitter_ms).max(1000) as u64;
                let elapsed = now.duration_since(clock_start) + Duration::from_millis(interval_ms);
                let seconds = elapsed.as_secs() + u64::from(elapsed.subsec_nanos() != 0);
                let registry = rlock!(registry);
                if registry.live_registration(&peer) == Some(registration) {
                    next_probe.insert(peer, clock_start + Duration::from_secs(seconds));
                    probe_id = probe_id.wrapping_add(1);
                    registry.send_to(
                        &peer,
                        veil_proto::priority::INTERACTIVE,
                        NodeRuntime::build_route_probe_frame(probe_id),
                    );
                }
            }
            deadline = next_probe.values().copied().min();
        }

        tokio::select! {
            result = shutdown.changed() => {
                if result.is_err() { break; }
            }
            result = background_tier.changed() => {
                if result.is_err() { break; }
            }
            _ = session_changes.changed(), if !paused => {}
            _ = async {
                if let Some(deadline) = deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
    }
}

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
    /// `insert`/`consume` operations, but a quiet session can accumulate
    /// stale entries for bounded time before the cap-eviction kicks in.
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

    /// Spawn a periodic prune task for closed channels in the
    /// `SessionTxRegistry`.
    ///
    /// Audit batch 2026-05-24 (M4): the registry's internal `prune_closed`
    /// fires only on `register` / `unregister` paths.  Hosts running
    /// pure-broadcast traffic (mesh hubs) with no new session churn could
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
                            // Audit-lint: `wlock!` resolves to a std::sync write guard.
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
    fn build_route_probe_frame(probe_id: u32) -> Vec<u8> {
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
            probe_id,
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
            Self::build_route_probe_frame(0),
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
    /// Probe cadence is adjusted for the configured low-battery threshold.
    /// In LowPower, only a tier change or shutdown wakes the task.
    pub fn spawn_route_probe_task_with(
        &mut self,
        min_interval: Duration,
        max_interval: Duration,
        stability_threshold: f64,
        mobile: veil_cfg::MobileConfig,
    ) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let handle = supervised_spawn(
            Arc::clone(&self.logger),
            "route_probe",
            run_route_probes(
                Arc::clone(&self.session_tx_registry),
                self.control_plane.rtt_table(),
                shutdown_tx.subscribe(),
                veil_session::runner::subscribe_mobile_background_tier(),
                mobile,
                move |stability| {
                    Self::adaptive_probe_interval(
                        stability,
                        stability_threshold,
                        min_interval,
                        max_interval,
                    )
                },
            ),
        );
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
        let dht_for_refresh = Arc::clone(&self.dht);
        let handle = tokio::spawn(async move {
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
                // Gossip refresh on EVERY cycle.
                //
                // This used to run once every five cycles (~2.5 min instead of
                // ~30 s) because the event-driven RouteUpdate plane was meant
                // to carry the fast path, leaving this as backward compat. That
                // plane is gone (report6 V-H2) — it duplicated RouteAnnounce /
                // RouteWithdraw without their protections — so throttling this
                // to 1-in-5 would now be a straight 5x slowdown in route
                // propagation with nothing covering the gap. The interval is
                // already adaptive in `adaptive_interval` above, which is the
                // right place to trade rate against network size.
                dispatcher.refresh_all_routes();
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

#[cfg(test)]
mod route_probe_tests {
    use super::*;
    use std::future::Future;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Wake, Waker};
    use veil_util::wlock;

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn route_probes_wait_for_a_peer_deadline_or_foreground() {
        let registry = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let rtt = Arc::new(Mutex::new(RttTable::new(Duration::from_secs(60))));
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (tier, tier_rx) = watch::channel(0);
        let mut task = std::pin::pin!(run_route_probes(
            Arc::clone(&registry),
            rtt,
            shutdown_rx,
            tier_rx,
            veil_cfg::MobileConfig::default(),
            |_| Duration::from_millis(100),
        ));
        let wakes = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);

        assert!(task.as_mut().poll(&mut cx).is_pending());
        tokio::time::advance(Duration::from_secs(120)).await;
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0, "idle without peers");

        let mut first = wlock!(registry).register([1; 32]);
        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        assert!(task.as_mut().poll(&mut cx).is_pending());
        assert!(
            first.try_recv().is_ok(),
            "new peer is probed on registration"
        );

        tier.send_replace(2);
        assert!(task.as_mut().poll(&mut cx).is_pending());
        wakes.0.store(0, Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(120)).await;
        let mut second = wlock!(registry).register([2; 32]);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0, "idle in LowPower");
        assert!(first.try_recv().is_err());
        assert!(second.try_recv().is_err());

        tier.send_replace(0);
        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        assert!(task.as_mut().poll(&mut cx).is_pending());
        assert!(first.try_recv().is_ok(), "overdue probe after resuming");
        assert!(second.try_recv().is_ok(), "peer added while paused");

        wakes.0.store(0, Ordering::Relaxed);
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0, "before the deadline");
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        assert!(task.as_mut().poll(&mut cx).is_pending());
        assert!(first.try_recv().is_ok());
        assert!(second.try_recv().is_ok());

        shutdown.send_replace(true);
        assert!(task.as_mut().poll(&mut cx).is_ready());
    }
}
