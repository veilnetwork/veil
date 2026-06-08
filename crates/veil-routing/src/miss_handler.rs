//! Route-miss handler —.
//!
//! When the dispatcher forwards a delivery for a destination with no cached
//! route, it signals this task through a bounded mpsc channel. The handler:
//!
//! 1. Dedups the event (don't re-flood if another request is already in-flight);
//! 2. Floods a signed `ROUTE_REQUEST` to all known peers;
//! 3. Waits on the `route_updated` Notify with configurable back-off (default
//!    500 ms → 1 s → 2 s);
//! 4. On persistent failure — records a partition-suspect reachability event
//!    and warns if the rolling reachability score falls below the threshold.
//!
//! removed the mailbox-flush step that previously ran on success;
//! application-layer retransmit now drives delivery once the route appears.
//!
//! Cross-crate observability arrives through [`RoutingLogger`] +
//! [`RoutingMetrics`] traits, and outbound frames go through
//! [`FrameBroadcaster`], so this module has zero knowledge of veilcore's
//! `NodeLogger` / `NodeMetrics` / `SessionTxRegistry` concretes.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tokio::sync::{Notify, mpsc, watch};
use veil_proto::{
    codec::encode_header,
    family::{FrameFamily, RoutingMsg},
    header::FrameHeader,
    routing::RouteRequestPayload,
};
use veil_types::FrameBroadcaster;
use veil_util::rlock;

use crate::cache::RouteCache;
use crate::{RoutingLogger, RoutingMetrics};

/// iterative-DHT fallback.
///
/// When the legacy `RouteRequest` flood (TTL=7) exhausts its retries without
/// finding a route, the miss-handler can optionally invoke this trait to fire
/// a Kademlia-style `RecursiveQuery(FIND_NODE)` for the target. The dispatcher
/// seeds the returned contacts into `route_cache` as candidate next-hops; the
/// miss-handler's second `wait_for_route` round picks any of them up.
///
/// NOTE — this does **not** resolve a transport or dial the target directly
/// (despite this fallback's history). `FIND_NODE` responses carry node_ids
/// only, no transports, and the seeded node_ids are *target-proximate* (the
/// responder's k-closest-to-target), usable by us only when we already hold a
/// session to one. In the sparse/relay topologies this fallback exists for,
/// the actual cross-topology delivery is done by the dispatcher's always-on
/// `try_recursive_relay_via_dht` (greedy Kademlia relay), which fires on every
/// route-miss independent of this trait. Treat the seeding here as a best-
/// effort opportunistic boost, not the primary recovery path.
///
/// `veil-routing` defines only the trait to keep the crate-graph clean
/// (the concrete impl lives in veilcore where veil-dht is reachable).
/// `None` disables the fallback and preserves pre-refactor behaviour exactly.
pub trait IterativeDhtFallback: Send + Sync {
    /// Fire a `RecursiveQuery(FIND_NODE)` for `target` to seed `route_cache`
    /// with candidate next-hops. Returns `true` if the signed
    /// `RecursiveResponse` oneshot fired within the timeout, `false` otherwise
    /// (timeout, backpressure skip, or no session peers to query). The bool is
    /// only a hint: the dispatcher also seeds the cache from PARTIAL responses
    /// along the path, so the caller re-checks `route_cache` regardless (see
    /// the impl's module docs and the call site in `spawn`).
    ///
    /// `priority` is the original message's traffic-class byte
    /// (INTERACTIVE / BACKGROUND / etc.). The impl scales the timeout by
    /// `dht_fallback_priority_mult` so interactive flows fast-fail and
    /// background flows tolerate longer DHT walks.
    fn try_seed_route_via_find_node<'a>(
        &'a self,
        target: [u8; 32],
        priority: u8,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// Dependencies the route-miss handler needs from its host runtime.
/// Collected here so the spawn entry point has a single-argument signature.
pub struct MissHandlerCtx {
    pub shutdown_rx: watch::Receiver<bool>,
    /// channel item now carries `(target, priority)`.
    /// Priority is the original frame's traffic-class byte so the fallback
    /// can choose between fast-fail (INTERACTIVE) and tolerant (BACKGROUND)
    /// timeout budgets.
    pub rx: mpsc::Receiver<([u8; 32], u8)>,
    pub broadcaster: Arc<dyn FrameBroadcaster>,
    pub route_cache: Arc<std::sync::RwLock<RouteCache>>,
    pub route_updated: Arc<Notify>,
    pub local_node_id: [u8; 32],
    pub signing_key: Option<Arc<SigningKey>>,
    pub metrics: Option<Arc<dyn RoutingMetrics>>,
    pub logger: Arc<dyn RoutingLogger>,
    /// Three retry back-offs in milliseconds (default 500, 1000, 2000).
    pub route_request_backoff_ms: [u64; 3],
    /// When the rolling reachability score falls below this value, log a
    /// `network.partition_suspected` warning.
    pub partition_threshold: f64,
    /// optional iterative-DHT fallback invoked after the
    /// `RouteRequest` retry budget exhausts. `None` preserves legacy
    /// behaviour (record partition event, drop message). Wired in
    /// veilcore via `DhtRouteFallback`.
    pub iterative_dht_fallback: Option<Arc<dyn IterativeDhtFallback>>,
}

/// Re-dedup window: skip re-flooding for the same destination within this
/// interval. Mirrors the pre-refactor inline constant.
const DEDUP_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// Compact 8-hex-char prefix for log formatting (avoids dragging
/// veilcore's `hex_short` helper through a crate boundary).
fn hex_short_8(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for b in &id[..4] {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn spawn(ctx: MissHandlerCtx) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(ctx))
}

async fn run(ctx: MissHandlerCtx) {
    let MissHandlerCtx {
        mut shutdown_rx,
        mut rx,
        broadcaster,
        route_cache,
        route_updated,
        local_node_id,
        signing_key,
        metrics,
        logger,
        route_request_backoff_ms,
        partition_threshold,
        iterative_dht_fallback,
    } = ctx;

    let mut dedup: std::collections::HashMap<[u8; 32], std::time::Instant> =
        std::collections::HashMap::new();
    // priority-aware deduplication ignored — same
    // destination dedups regardless of priority (we only need ONE
    // resolution for a target; the priority just informs the timeout).
    // Periodic cleanup keeps the dedup map bounded even when no miss events
    // arrive for a long time.
    let mut cleanup_ticker = tokio::time::interval(DEDUP_TTL * 10);
    cleanup_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // biased: shutdown must win over in-flight miss events or tick
            // work so `node stop` doesn't wait for the next channel message.
            biased;
            Ok(_) = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
            _ = cleanup_ticker.tick() => {
                let now = std::time::Instant::now();
                dedup.retain(|_, t| now.duration_since(*t) < DEDUP_TTL * 10);
            }
            msg = rx.recv() => {
                let Some((dst, priority)) = msg else { break };
                let now = std::time::Instant::now();

                // Already-in-flight: skip re-flood. removed the
                // mailbox-flush sidecar that used to run here.
                if dedup.get(&dst).is_some_and(|t| now.duration_since(*t) < DEDUP_TTL) {
                    continue;
                }
                dedup.insert(dst, now);

                if let Some(m) = &metrics { m.inc_discovery_triggered(); }

                flood_route_request(
                    &dst, local_node_id, signing_key.as_deref(), broadcaster.as_ref(),
                );

                let mut found = wait_for_route(
                    &dst, &route_cache, &route_updated, route_request_backoff_ms,
                ).await;

                // iterative-DHT fallback. Triggered ONLY if
                // legacy `RouteRequest` flood exhausted its retries without a route.
                // Behaviour-preserving: `None` skips this block entirely and we
                // record the partition event below.
                if !found && let Some(fallback) = iterative_dht_fallback.as_ref() {
                    logger.info(
                        "route.dht_fallback.start",
                        &format!("target={}", hex_short_8(&dst)),
                    );
                    if let Some(m) = &metrics {
                        m.inc_dht_fallback_triggered();
                    }
                    let oneshot_ok = fallback.try_seed_route_via_find_node(dst, priority).await;
                    // Re-check the route cache REGARDLESS of the oneshot result.
                    // `oneshot_ok` only reflects whether our RecursiveResponse
                    // oneshot fired; but the dispatcher ALSO seeds candidate
                    // next-hops into route_cache from PARTIAL recursive responses
                    // that arrive along the path (see DhtRouteFallback docs). So
                    // a route can recover even when the oneshot timed out.
                    // Counting `resolved`/`miss` off the oneshot (as before)
                    // under-counted real recoveries and mislabeled them as
                    // partitions. Tie the outcome to whether a route actually
                    // appeared instead. On oneshot success, give the seeded
                    // route a brief window to settle; on oneshot miss, any seed
                    // already arrived during the timeout, so an immediate check
                    // adds no latency to the (already-slow) miss path.
                    found = if oneshot_ok {
                        wait_for_route(
                            &dst, &route_cache, &route_updated, route_request_backoff_ms,
                        ).await
                    } else {
                        rlock!(route_cache).lookup(&dst).is_some()
                    };
                    if found {
                        if let Some(m) = &metrics {
                            m.inc_dht_fallback_resolved();
                        }
                        logger.info(
                            "route.dht_fallback.resolved",
                            &format!(
                                "target={} oneshot={} cache_seeded={}",
                                hex_short_8(&dst), oneshot_ok, !oneshot_ok
                            ),
                        );
                    } else {
                        if let Some(m) = &metrics {
                            m.inc_dht_fallback_miss();
                        }
                        logger.info(
                            "route.dht_fallback.miss",
                            &format!("target={} oneshot={}", hex_short_8(&dst), oneshot_ok),
                        );
                    }
                }

                if !found {
                    // Persistent miss — record failure event and possibly warn.
                    if let Some(m) = &metrics {
                        let score = m.record_reachability_event(false);
                        if score < partition_threshold {
                            logger.warn(
                                "network.partition_suspected",
                                &format!(
                                    "reachability_score={score:.2} threshold={partition_threshold:.2}"
                                ),
                            );
                        }
                    }
                    continue;
                }

                if let Some(m) = &metrics {
                    m.inc_route_recovery();
                    m.record_reachability_event(true);
                }
                // mailbox flush removed. Application layer retries
                // delivery via the freshly-learned route on its own cadence.
            }
        }
    }
}

/// Build and flood a signed `ROUTE_REQUEST` to every currently-connected peer.
fn flood_route_request(
    dst: &[u8; 32],
    local_node_id: [u8; 32],
    signing_key: Option<&SigningKey>,
    broadcaster: &dyn FrameBroadcaster,
) {
    static NEXT_REQUEST_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    let request_id = NEXT_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut req = RouteRequestPayload {
        target_node_id: *dst,
        requester_node_id: local_node_id,
        request_id,
        ttl: 7,
        signature: [0u8; 64],
    };
    if let Some(key) = signing_key {
        use ed25519_dalek::Signer as _;
        req.signature = key.sign(&req.signable_bytes()).to_bytes();
    }
    let req_bytes = req.encode();
    let mut hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteRequest as u16);
    hdr.body_len = req_bytes.len() as u32;
    let mut rr_frame = encode_header(&hdr).to_vec();
    rr_frame.extend_from_slice(&req_bytes);
    broadcaster.send_to_all(Arc::from(rr_frame.as_slice()));
}

/// Wait for either a `route_updated` notification OR the full back-off window
/// to elapse. Returns `true` as soon as the route_cache shows a hop for `dst`.
async fn wait_for_route(
    dst: &[u8; 32],
    route_cache: &Arc<std::sync::RwLock<RouteCache>>,
    route_updated: &Arc<Notify>,
    backoff_ms: [u64; 3],
) -> bool {
    for &ms in &backoff_ms {
        let notified = route_updated.notified();
        let _ = tokio::time::timeout(std::time::Duration::from_millis(ms), notified).await;
        if rlock!(route_cache).lookup(dst).is_some() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    #[derive(Default)]
    struct MockMetrics {
        triggered: AtomicU64,
        resolved: AtomicU64,
        miss: AtomicU64,
        reach_success: AtomicU64,
        reach_fail: AtomicU64,
    }
    impl RoutingMetrics for MockMetrics {
        fn inc_discovery_triggered(&self) {}
        fn inc_route_recovery(&self) {}
        fn inc_dht_fallback_triggered(&self) {
            self.triggered.fetch_add(1, Ordering::Relaxed);
        }
        fn inc_dht_fallback_resolved(&self) {
            self.resolved.fetch_add(1, Ordering::Relaxed);
        }
        fn inc_dht_fallback_miss(&self) {
            self.miss.fetch_add(1, Ordering::Relaxed);
        }
        fn record_reachability_event(&self, success: bool) -> f64 {
            if success {
                self.reach_success.fetch_add(1, Ordering::Relaxed);
            } else {
                self.reach_fail.fetch_add(1, Ordering::Relaxed);
            }
            1.0
        }
    }

    struct NoopLogger;
    impl RoutingLogger for NoopLogger {
        fn warn(&self, _: &str, _: &str) {}
    }

    struct NoopBroadcaster;
    impl FrameBroadcaster for NoopBroadcaster {
        fn send_to(&self, _: &[u8; 32], _: u8, _: Vec<u8>) -> bool {
            true
        }
        fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {}
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            Vec::new()
        }
    }

    /// Fallback whose oneshot ALWAYS "misses" (returns false, simulating a
    /// RecursiveResponse timeout) but, when `seed` is set, populates the
    /// route_cache during the call — simulating the dispatcher seeding a
    /// candidate next-hop from PARTIAL recursive responses along the path.
    struct SeedingFallback {
        route_cache: Arc<RwLock<RouteCache>>,
        seed: bool,
    }
    impl IterativeDhtFallback for SeedingFallback {
        fn try_seed_route_via_find_node<'a>(
            &'a self,
            target: [u8; 32],
            _priority: u8,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            let cache = Arc::clone(&self.route_cache);
            let seed = self.seed;
            Box::pin(async move {
                if seed {
                    cache.write().unwrap().insert(target, [0xAA; 32], 50_000, 2);
                }
                false // oneshot timed out regardless
            })
        }
    }

    async fn run_one_miss(seed: bool) -> Arc<MockMetrics> {
        let route_cache = Arc::new(RwLock::new(RouteCache::new(Duration::from_secs(60))));
        let metrics = Arc::new(MockMetrics::default());
        let (tx, rx) = mpsc::channel(8);
        let (sh_tx, sh_rx) = watch::channel(false);
        let ctx = MissHandlerCtx {
            shutdown_rx: sh_rx,
            rx,
            broadcaster: Arc::new(NoopBroadcaster),
            route_cache: Arc::clone(&route_cache),
            route_updated: Arc::new(Notify::new()),
            local_node_id: [0u8; 32],
            signing_key: None,
            metrics: Some(metrics.clone() as Arc<dyn RoutingMetrics>),
            logger: Arc::new(NoopLogger),
            // tiny backoffs so the initial RouteRequest wait exhausts fast
            route_request_backoff_ms: [1, 1, 1],
            partition_threshold: 0.5,
            iterative_dht_fallback: Some(Arc::new(SeedingFallback {
                route_cache: Arc::clone(&route_cache),
                seed,
            })),
        };
        let handle = spawn(ctx);
        tx.send(([0x11u8; 32], 1)).await.unwrap();
        // Poll until the fallback outcome lands.
        for _ in 0..500 {
            if metrics.triggered.load(Ordering::Relaxed) > 0
                && metrics.resolved.load(Ordering::Relaxed) + metrics.miss.load(Ordering::Relaxed)
                    > 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let _ = sh_tx.send(true);
        let _ = handle.await;
        metrics
    }

    #[tokio::test]
    async fn cache_seeded_recovery_counts_as_resolved_not_miss() {
        // Oneshot misses, but the cache gets seeded → the route IS recovered.
        // The fix: count this as `resolved` (not `miss`), and DON'T record a
        // partition event.
        let m = run_one_miss(true).await;
        assert_eq!(
            m.triggered.load(Ordering::Relaxed),
            1,
            "fallback must trigger"
        );
        assert_eq!(
            m.resolved.load(Ordering::Relaxed),
            1,
            "cache-seeded recovery must count as resolved"
        );
        assert_eq!(m.miss.load(Ordering::Relaxed), 0, "must NOT count as miss");
        assert_eq!(
            m.reach_fail.load(Ordering::Relaxed),
            0,
            "a recovered route must NOT record a partition event"
        );
    }

    #[tokio::test]
    async fn hard_miss_counts_as_miss_and_partition() {
        // Oneshot misses AND no cache seed → route still absent → genuine miss
        // + partition event.
        let m = run_one_miss(false).await;
        assert_eq!(m.triggered.load(Ordering::Relaxed), 1);
        assert_eq!(m.resolved.load(Ordering::Relaxed), 0);
        assert_eq!(
            m.miss.load(Ordering::Relaxed),
            1,
            "hard miss must count as miss"
        );
        assert!(
            m.reach_fail.load(Ordering::Relaxed) >= 1,
            "hard miss must record a partition/reachability-failure event"
        );
    }
}
