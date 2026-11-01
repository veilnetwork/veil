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
    pub discovery_paths: Arc<std::sync::Mutex<crate::discovery_paths::DiscoveryPaths>>,
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

// Limit simultaneous network walks, not merely the number of tasks waiting
// for a semaphore. The existing bounded input channel remains the backlog.
const MAX_CONCURRENT_ROUTE_LOOKUPS: usize = 4;

struct LookupCtx {
    broadcaster: Arc<dyn FrameBroadcaster>,
    route_cache: Arc<std::sync::RwLock<RouteCache>>,
    route_updated: Arc<Notify>,
    local_node_id: [u8; 32],
    signing_key: Option<Arc<SigningKey>>,
    discovery_paths: Arc<std::sync::Mutex<crate::discovery_paths::DiscoveryPaths>>,
    metrics: Option<Arc<dyn RoutingMetrics>>,
    logger: Arc<dyn RoutingLogger>,
    route_request_backoff_ms: [u64; 3],
    partition_threshold: f64,
    iterative_dht_fallback: Option<Arc<dyn IterativeDhtFallback>>,
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
        discovery_paths,
        metrics,
        logger,
        route_request_backoff_ms,
        partition_threshold,
        iterative_dht_fallback,
    } = ctx;

    let lookup = Arc::new(LookupCtx {
        broadcaster,
        route_cache,
        route_updated,
        local_node_id,
        signing_key,
        discovery_paths,
        metrics,
        logger,
        route_request_backoff_ms,
        partition_threshold,
        iterative_dht_fallback,
    });
    let mut dedup = std::collections::HashMap::<[u8; 32], tokio::time::Instant>::new();
    let mut active = std::collections::HashSet::new();
    let mut targets = std::collections::HashMap::new();
    let mut jobs = tokio::task::JoinSet::new();
    let mut cleanup_ticker = tokio::time::interval(DEDUP_TTL * 10);
    cleanup_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    if *shutdown_rx.borrow() {
        return;
    }
    loop {
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() { break; }
            }
            completed = jobs.join_next_with_id(), if !jobs.is_empty() => {
                let id = match completed.expect("nonempty lookup set") {
                    Ok((id, ())) => id,
                    Err(error) => {
                        lookup.logger.warn("route.lookup.failed", "route lookup task did not complete");
                        error.id()
                    }
                };
                if let Some(target) = targets.remove(&id) {
                    active.remove(&target);
                }
            }
            _ = cleanup_ticker.tick() => {
                let now = tokio::time::Instant::now();
                dedup.retain(|_, at| now.duration_since(*at) < DEDUP_TTL * 10);
            }
            msg = rx.recv(), if jobs.len() < MAX_CONCURRENT_ROUTE_LOOKUPS => {
                let Some((dst, priority)) = msg else { break };
                let now = tokio::time::Instant::now();
                // The short re-flood cooldown can expire while a slow fallback
                // is still alive. Never run two walks for the same address.
                if active.contains(&dst)
                    || dedup.get(&dst).is_some_and(|at| now.duration_since(*at) < DEDUP_TTL) {
                    continue;
                }
                dedup.insert(dst, now);
                active.insert(dst);
                let shared = Arc::clone(&lookup);
                let job = jobs.spawn(async move { lookup_one(&shared, dst, priority).await; });
                targets.insert(job.id(), dst);
            }
        }
    }
    // Aborts and joins every child, so no walk outlives shutdown/receiver close.
    // Aborting this parent also drops JoinSet and aborts its owned children.
    jobs.shutdown().await;
}

async fn lookup_one(ctx: &LookupCtx, dst: [u8; 32], priority: u8) {
    let LookupCtx {
        broadcaster,
        route_cache,
        route_updated,
        local_node_id,
        signing_key,
        discovery_paths,
        metrics,
        logger,
        route_request_backoff_ms,
        partition_threshold,
        iterative_dht_fallback,
    } = ctx;
    if let Some(m) = metrics {
        m.inc_discovery_triggered();
    }

    let flooded = flood_route_request(
        &dst,
        *local_node_id,
        signing_key.as_deref(),
        broadcaster.as_ref(),
        discovery_paths,
    );

    let mut found = if flooded {
        wait_for_route(&dst, route_cache, route_updated, *route_request_backoff_ms).await
    } else {
        false
    };

    // iterative-DHT fallback. Triggered ONLY if
    // legacy `RouteRequest` flood exhausted its retries without a route.
    // Behaviour-preserving: `None` skips this block entirely and we
    // record the partition event below.
    if !found && let Some(fallback) = iterative_dht_fallback.as_ref() {
        logger.info(
            "route.dht_fallback.start",
            &format!("target={}", hex_short_8(&dst)),
        );
        if let Some(m) = metrics {
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
            wait_for_route(&dst, route_cache, route_updated, *route_request_backoff_ms).await
        } else {
            rlock!(route_cache).lookup(&dst).is_some()
        };
        if found {
            if let Some(m) = metrics {
                m.inc_dht_fallback_resolved();
            }
            logger.info(
                "route.dht_fallback.resolved",
                &format!(
                    "target={} oneshot={} cache_seeded={}",
                    hex_short_8(&dst),
                    oneshot_ok,
                    !oneshot_ok
                ),
            );
        } else {
            if let Some(m) = metrics {
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
        if let Some(m) = metrics {
            let score = m.record_reachability_event(false);
            if score < *partition_threshold {
                logger.warn(
                    "network.partition_suspected",
                    &format!("reachability_score={score:.2} threshold={partition_threshold:.2}"),
                );
            }
        }
        return;
    }

    if let Some(m) = metrics {
        m.inc_route_recovery();
        m.record_reachability_event(true);
    }
    // mailbox flush removed. Application layer retries
    // delivery via the freshly-learned route on its own cadence.
}

/// Draw a fresh `RouteRequest` correlation id from the OS CSPRNG.
///
/// This used to be a process-local `AtomicU32` starting at 1, contradicting the
/// wire documentation (`RouteRequestPayload::request_id` is specified as a
/// *random* token) and — far worse — making every node's ids **predictable**.
///
/// The receiving side dedups a `RouteRequest` and the dedup entry lives for the
/// whole seen-set TTL. So an attacker who can guess the ids a fresh node will
/// use only has to occupy them first for a popular `target`: every subsequent
/// legitimate lookup for that target collapses into the attacker's entry and is
/// dropped before it is ever forwarded. With a counter from 1, "guessing" is
/// just counting — the first few ids of every restarted node are 1, 2, 3, …
///
/// An unpredictable 32-bit draw makes the occupy-first game cost the attacker
/// the entire id space instead of the first N values. It is the *correlation*
/// token only — nothing authenticates on it — so 32 bits from `OsRng` is the
/// right primitive rather than a counter with a random seed (which leaks the
/// same "next value is +1" structure once one id is observed).
fn fresh_request_id() -> u32 {
    use rand_core::{OsRng, RngCore};
    OsRng.next_u32()
}

/// Build and flood a signed `ROUTE_REQUEST` to every currently-connected peer.
fn flood_route_request(
    dst: &[u8; 32],
    local_node_id: [u8; 32],
    signing_key: Option<&SigningKey>,
    broadcaster: &dyn FrameBroadcaster,
    discovery_paths: &Arc<std::sync::Mutex<crate::discovery_paths::DiscoveryPaths>>,
) -> bool {
    let request_id = fresh_request_id();
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
    let key = crate::discovery_paths::RequestKey {
        requester: local_node_id,
        target: *dst,
        id: request_id,
    };
    // Publish before the broadcast: a fast reply must find its request witness.
    if !veil_util::lock!(discovery_paths).remember_request(
        key,
        crate::discovery_paths::ReplyTo::Local,
        std::time::Instant::now(),
    ) {
        return false;
    }
    broadcaster.send_to_all(Arc::from(rr_frame.as_slice()));
    true
}

/// Wait for either a `route_updated` notification OR the full back-off window
/// to elapse. Returns `true` as soon as the route_cache shows a hop for `dst`.
async fn wait_for_route(
    dst: &[u8; 32],
    route_cache: &Arc<std::sync::RwLock<RouteCache>>,
    route_updated: &Arc<Notify>,
    backoff_ms: [u64; 3],
) -> bool {
    let mut deadline = tokio::time::Instant::now();
    for &ms in &backoff_ms {
        deadline += std::time::Duration::from_millis(ms);
        loop {
            let notified = route_updated.notified();
            tokio::pin!(notified);
            // Register before reading the cache: notify_waiters does not keep
            // a permit for a future that has not been polled/enabled yet.
            notified.as_mut().enable();
            if rlock!(route_cache).lookup(dst).is_some() {
                return true;
            }
            // A shared notification may concern any other destination. It
            // must neither consume an attempt nor renew this one's deadline.
            if tokio::time::Instant::now() >= deadline
                || tokio::time::timeout_at(deadline, notified).await.is_err()
            {
                break;
            }
        }
    }
    rlock!(route_cache).lookup(dst).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, RwLock};
    use std::time::Duration;

    #[tokio::test]
    async fn wait_for_route_observes_a_reply_that_arrived_before_its_first_poll() {
        use std::task::{Context, Poll, Waker};
        let cache = Arc::new(RwLock::new(RouteCache::new(Duration::from_secs(60))));
        let updated = Arc::new(Notify::new());
        let target = [0x71; 32];
        cache.write().unwrap().insert(target, [0x72; 32], 20_000, 2);
        updated.notify_waiters(); // No registered waiter yet: not a stored permit.
        let mut waiting = Box::pin(wait_for_route(&target, &cache, &updated, [1000; 3]));
        assert_eq!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(true)
        );
    }

    #[tokio::test]
    async fn unrelated_route_notices_do_not_exhaust_another_targets_wait() {
        use std::task::{Context, Poll, Waker};
        let cache = Arc::new(RwLock::new(RouteCache::new(Duration::from_secs(60))));
        let updated = Arc::new(Notify::new());
        let target = [0x71; 32];
        let mut waiting = Box::pin(wait_for_route(&target, &cache, &updated, [1000; 3]));
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(waiting.as_mut().poll(&mut cx), Poll::Pending);
        // No clock advances. These are notifications for OTHER destinations.
        for _ in 0..4 {
            updated.notify_waiters();
            assert_eq!(waiting.as_mut().poll(&mut cx), Poll::Pending);
        }
        cache.write().unwrap().insert(target, [0x72; 32], 20_000, 2);
        updated.notify_waiters();
        assert_eq!(waiting.as_mut().poll(&mut cx), Poll::Ready(true));
    }

    #[tokio::test(start_paused = true)]
    async fn notices_and_late_polls_do_not_extend_the_original_wait_deadline() {
        use std::task::{Context, Poll, Waker};
        let cache = Arc::new(RwLock::new(RouteCache::new(Duration::from_secs(60))));
        let updated = Arc::new(Notify::new());
        let target = [0x71; 32];
        let mut waiting = Box::pin(wait_for_route(&target, &cache, &updated, [1000; 3]));
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(waiting.as_mut().poll(&mut cx), Poll::Pending);
        tokio::time::advance(Duration::from_secs(3)).await;
        updated.notify_waiters();
        assert_eq!(waiting.as_mut().poll(&mut cx), Poll::Ready(false));
    }

    struct HeldFallback {
        entered: mpsc::UnboundedSender<[u8; 32]>,
        release: Arc<tokio::sync::Semaphore>,
        active: Arc<AtomicU64>,
        peak: Arc<AtomicU64>,
    }
    impl IterativeDhtFallback for HeldFallback {
        fn try_seed_route_via_find_node<'a>(
            &'a self,
            target: [u8; 32],
            _: u8,
        ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            Box::pin(async move {
                struct Active(Arc<AtomicU64>);
                impl Drop for Active {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                let count = self.active.fetch_add(1, Ordering::Relaxed) + 1;
                let _active = Active(self.active.clone());
                self.peak.fetch_max(count, Ordering::Relaxed);
                self.entered.send(target).unwrap();
                self.release.acquire().await.unwrap().forget();
                false
            })
        }
    }

    struct HeldHandler {
        input: mpsc::Sender<([u8; 32], u8)>,
        shutdown: watch::Sender<bool>,
        task: tokio::task::JoinHandle<()>,
        starts: mpsc::UnboundedReceiver<[u8; 32]>,
        held: Arc<HeldFallback>,
        broadcaster: Arc<CapturingBroadcaster>,
    }

    fn held_handler() -> HeldHandler {
        let (tx, rx) = mpsc::channel(32);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (entered, starts) = mpsc::unbounded_channel();
        let held = Arc::new(HeldFallback {
            entered,
            release: Arc::new(tokio::sync::Semaphore::new(0)),
            active: Arc::new(AtomicU64::new(0)),
            peak: Arc::new(AtomicU64::new(0)),
        });
        let broadcaster = Arc::new(CapturingBroadcaster::default());
        let handle = spawn(MissHandlerCtx {
            shutdown_rx,
            rx,
            broadcaster: broadcaster.clone(),
            route_cache: Arc::new(RwLock::new(RouteCache::new(Duration::from_secs(60)))),
            route_updated: Arc::new(Notify::new()),
            local_node_id: [0; 32],
            signing_key: None,
            discovery_paths: Arc::new(Mutex::new(Default::default())),
            metrics: None,
            logger: Arc::new(NoopLogger),
            route_request_backoff_ms: [0; 3],
            partition_threshold: 0.5,
            iterative_dht_fallback: Some(held.clone()),
        });
        HeldHandler {
            input: tx,
            shutdown,
            task: handle,
            starts,
            held,
            broadcaster,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_unanswered_target_does_not_block_the_next_targets_discovery() {
        let HeldHandler {
            input: tx,
            shutdown,
            task: handle,
            mut starts,
            held,
            ..
        } = held_handler();
        tx.send(([0x41; 32], 1)).await.unwrap();
        assert_eq!(starts.recv().await, Some([0x41; 32]));
        tx.send(([0x42; 32], 1)).await.unwrap();
        // Virtual tick flushes ready tasks, not a wall-clock latency bound.
        // The first lookup is still held by a gate, not by a network timeout.
        let second = tokio::time::timeout(Duration::from_millis(1), starts.recv()).await;
        shutdown.send(true).unwrap();
        held.release.add_permits(32);
        handle.await.unwrap();
        assert_eq!(second.unwrap_or(None), Some([0x42; 32]));
    }

    #[tokio::test(start_paused = true)]
    async fn lookup_concurrency_is_bounded_and_shutdown_cancels_held_walks() {
        let HeldHandler {
            input: tx,
            shutdown,
            task: handle,
            mut starts,
            held,
            ..
        } = held_handler();
        for target in 1..=8 {
            tx.send(([target; 32], 1)).await.unwrap();
        }
        for _ in 0..MAX_CONCURRENT_ROUTE_LOOKUPS {
            starts.recv().await.unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(1), starts.recv())
                .await
                .is_err()
        );
        assert_eq!(
            held.active.load(Ordering::Relaxed),
            MAX_CONCURRENT_ROUTE_LOOKUPS as u64
        );
        held.release.add_permits(1);
        let next = starts.recv().await.unwrap();
        assert_eq!(next, [5; 32]);
        assert!(held.peak.load(Ordering::Relaxed) <= MAX_CONCURRENT_ROUTE_LOOKUPS as u64);
        shutdown.send(true).unwrap();
        handle.await.unwrap();
        assert_eq!(
            held.active.load(Ordering::Relaxed),
            0,
            "shutdown joins cancellation"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_inflight_target_stays_deduplicated_after_the_short_cooldown_expires() {
        let HeldHandler {
            input: tx,
            shutdown,
            task: handle,
            mut starts,
            held,
            broadcaster: frames,
        } = held_handler();
        tx.send(([0x41; 32], 1)).await.unwrap();
        assert_eq!(starts.recv().await, Some([0x41; 32]));
        tokio::time::advance(DEDUP_TTL + Duration::from_secs(1)).await;
        for _ in 0..8 {
            tx.send(([0x41; 32], 1)).await.unwrap();
        }
        tx.send(([0x42; 32], 1)).await.unwrap();
        assert_eq!(starts.recv().await, Some([0x42; 32]));
        let requests: Vec<_> = frames
            .frames
            .lock()
            .unwrap()
            .iter()
            .map(|f| {
                RouteRequestPayload::decode(&f[veil_proto::HEADER_SIZE..])
                    .unwrap()
                    .target_node_id
            })
            .collect();
        assert_eq!(requests, vec![[0x41; 32], [0x42; 32]]);
        shutdown.send(true).unwrap();
        handle.await.unwrap();
        assert_eq!(held.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn closing_the_miss_input_cancels_its_held_lookups() {
        let HeldHandler {
            input: tx,
            shutdown: _shutdown,
            task: handle,
            mut starts,
            held,
            ..
        } = held_handler();
        tx.send(([0x41; 32], 1)).await.unwrap();
        starts.recv().await.unwrap();
        drop(tx);
        handle.await.unwrap();
        assert_eq!(held.active.load(Ordering::Relaxed), 0);
    }

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

    /// Broadcaster that keeps every frame handed to `send_to_all`, so a test
    /// can decode the `RouteRequestPayload` the flooder actually put on the
    /// wire (rather than re-deriving it from a helper next to the real one).
    #[derive(Default)]
    struct CapturingBroadcaster {
        frames: Mutex<Vec<Vec<u8>>>,
    }
    impl FrameBroadcaster for CapturingBroadcaster {
        fn send_to(&self, _: &[u8; 32], _: u8, _: Vec<u8>) -> bool {
            true
        }
        fn send_to_all_with_priority(&self, _: u8, bytes: Arc<[u8]>) {
            self.frames.lock().unwrap().push(bytes.to_vec());
        }
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            Vec::new()
        }
    }

    #[test]
    fn request_witness_is_published_before_broadcast_and_capacity_refusal_sends_nothing() {
        struct AtBroadcast {
            capture: CapturingBroadcaster,
            paths: Arc<std::sync::Mutex<crate::discovery_paths::DiscoveryPaths>>,
        }
        impl FrameBroadcaster for AtBroadcast {
            fn send_to(&self, _: &[u8; 32], _: u8, _: Vec<u8>) -> bool {
                false
            }
            fn send_to_all_with_priority(&self, priority: u8, bytes: Arc<[u8]>) {
                let req = RouteRequestPayload::decode(&bytes[veil_proto::HEADER_SIZE..]).unwrap();
                assert_eq!(
                    veil_util::lock!(self.paths).request_path(
                        crate::discovery_paths::RequestKey {
                            requester: req.requester_node_id,
                            target: req.target_node_id,
                            id: req.request_id
                        },
                        std::time::Instant::now()
                    ),
                    Some(crate::discovery_paths::ReplyTo::Local),
                    "witness must exist at the actual emit boundary"
                );
                self.capture.send_to_all_with_priority(priority, bytes);
            }
            fn active_node_ids(&self) -> Vec<[u8; 32]> {
                vec![]
            }
        }
        let paths = Arc::new(std::sync::Mutex::new(Default::default()));
        let broadcaster = AtBroadcast {
            capture: CapturingBroadcaster::default(),
            paths: Arc::clone(&paths),
        };
        let me = [1; 32];
        let target = [2; 32];
        assert!(flood_route_request(&target, me, None, &broadcaster, &paths));
        let frames = broadcaster.capture.frames.lock().unwrap();
        let request = RouteRequestPayload::decode(&frames[0][veil_proto::HEADER_SIZE..]).unwrap();
        assert_eq!(
            veil_util::lock!(paths).request_path(
                crate::discovery_paths::RequestKey {
                    requester: me,
                    target,
                    id: request.request_id
                },
                std::time::Instant::now()
            ),
            Some(crate::discovery_paths::ReplyTo::Local)
        );
        drop(frames);
        for _ in 0..1024 {
            let _ = flood_route_request(&target, me, None, &broadcaster, &paths);
        }
        let before = broadcaster.capture.frames.lock().unwrap().len();
        assert!(!flood_route_request(
            &target,
            me,
            None,
            &broadcaster,
            &paths
        ));
        assert_eq!(broadcaster.capture.frames.lock().unwrap().len(), before);
    }

    /// The `request_id`s the flood path actually emits, in order.
    fn flooded_request_ids(n: usize) -> Vec<u32> {
        let bc = CapturingBroadcaster::default();
        for i in 0..n {
            let mut dst = [0u8; 32];
            dst[0] = i as u8;
            flood_route_request(
                &dst,
                [0u8; 32],
                None,
                &bc,
                &Arc::new(std::sync::Mutex::new(Default::default())),
            );
        }
        let frames = bc.frames.lock().unwrap();
        assert_eq!(frames.len(), n, "one frame per flood call");
        frames
            .iter()
            .map(|f| {
                let body = &f[veil_proto::header::HEADER_SIZE..];
                RouteRequestPayload::decode(body)
                    .expect("flooded body must be a RouteRequestPayload")
                    .request_id
            })
            .collect()
    }

    /// `request_id` is documented on the wire as a RANDOM correlation token,
    /// and the receiving dedup keeps `(target, requester, request_id)` alive
    /// for the whole seen-set TTL. A process-local counter starting at 1 made
    /// those ids PREDICTABLE: an attacker only had to occupy the first N ids
    /// for a popular target to swallow every restarted node's route lookups —
    /// and with `ttl = 0` those occupying frames never reach the DHT quota
    /// gate, so the suppression is free and silent.
    ///
    /// Two independent properties, because either one alone is passable by a
    /// weakened implementation: a plain counter fails the magnitude check, and
    /// a counter merely SEEDED from randomness fails the spacing check.
    #[test]
    fn flooded_request_ids_are_unpredictable_not_a_counter() {
        const N: usize = 32;
        let ids = flooded_request_ids(N);

        // (1) Magnitude — with uniform 32-bit draws, P(all 32 land in the
        // bottom sixteenth) = 16^-32 ≈ 2^-128. A counter from 1 emits
        // 1..=32 and fails here outright.
        assert!(
            ids.iter().any(|&id| id > u32::MAX / 16),
            "request_ids look like small counter values: {ids:?}",
        );

        // (2) Spacing — a counter (however it is seeded) advances by a fixed
        // step. Uniform draws do not.
        let steps: Vec<i64> = ids
            .windows(2)
            .map(|w| i64::from(w[1]) - i64::from(w[0]))
            .collect();
        assert!(
            steps.windows(2).any(|s| s[0] != s[1]),
            "consecutive request_ids advance by a constant step: {ids:?}",
        );

        // (3) No repeats within a short burst — a broken source that returns a
        // constant would pass (1) and (2)'s magnitude but not this.
        let unique: std::collections::HashSet<u32> = ids.iter().copied().collect();
        assert_eq!(unique.len(), N, "request_ids repeated within one burst");
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
            discovery_paths: Arc::new(std::sync::Mutex::new(Default::default())),
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
