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
/// finding a route, the miss-handler can optionally invoke this trait to
/// run a Kademlia-style iterative `find_node_iterative` against the DHT
/// resolve the target's transport URI, and trigger a direct outbound dial.
/// This bypasses both `RouteRequest TTL=7` and `MAX_RELAY_HOPS=16` limits —
/// useful when the topology requires reaching peers > 16 hops away in a
/// relay chain (adversarial partition / sparse mesh / pathological cases).
///
/// `veil-routing` defines only the trait k keep crate-graph clean
/// (the concrete impl lives in veilcore where veil-dht is reachable).
/// `None` disables the fallback and preserves pre-refactor behaviour exactly.
pub trait IterativeDhtFallback: Send + Sync {
    /// Attempt to resolve `target` via iterative DHT walk + dial. Returns
    /// `true` once the route_cache shows a hop (either direct session
    /// established or relay-able next-hop learned), `false` on hard miss
    /// (target absent from DHT, all dials failed, walker timeout, etc.).
    ///
    /// `priority` is the original message's traffic-class byte (
    /// — INTERACTIVE / BACKGROUND / etc.). Impl scales the timeout by
    /// `dht_fallback_priority_mult` so interactive flows fast-fail and
    /// background flows tolerate longer DHT walks.
    fn try_resolve_and_dial<'a>(
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
                    let resolved = fallback.try_resolve_and_dial(dst, priority).await;
                    if resolved {
                        // Iterative walk + dial succeeded; route_cache may
                        // already have a hop OR the dial-handshake will
                        // populate it shortly. Wait one more backoff round.
                        found = wait_for_route(
                            &dst, &route_cache, &route_updated, route_request_backoff_ms,
                        ).await;
                        if let Some(m) = &metrics {
                            m.inc_dht_fallback_resolved();
                        }
                        logger.info(
                            "route.dht_fallback.resolved",
                            &format!(
                                "target={} cache_hit={}",
                                hex_short_8(&dst), found
                            ),
                        );
                    } else {
                        if let Some(m) = &metrics {
                            m.inc_dht_fallback_miss();
                        }
                        logger.info(
                            "route.dht_fallback.miss",
                            &format!("target={}", hex_short_8(&dst)),
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
