//! iterative-DHT route-discovery fallback.
//!
//! When `miss_handler`'s legacy `RouteRequest` flood (TTL=7) exhausts its
//! retry budget without finding a route to `target`, this module fires a
//! `RecursiveQuery(FIND_NODE, target_key=target)` for target and waits for
//! the signed `RecursiveResponse` to come back. Dispatcher's
//! `handle_recursive_response` populates `route_cache` from the returned
//! contacts (routing.rs:2409-2424, score 50_000 / hops 2) and fires
//! `route_updated`; `miss_handler`'s second `wait_for_route` round picks any
//! seeded hop up.
//!
//! ## What this is NOT
//!
//! Despite the historical naming, this does **not** resolve a transport URI
//! or dial the target directly. `FIND_NODE` responses carry node_ids only
//! (no transports), and the seeded node_ids are *target-proximate* (the
//! responder's k-closest-to-target) — usable by us only when we already hold
//! a session to one (`send_to` requires a live session; otherwise the hop is
//! invalidated on first send, see `delivery.rs`). So in the sparse/relay
//! topologies this fallback exists for, the seeding rarely yields a directly-
//! usable route. The actual cross-topology delivery is carried by the
//! dispatcher's always-on `try_recursive_relay_via_dht` (greedy Kademlia
//! relay via `find_closest_nodes`), which fires on every route-miss
//! independent of this module. Treat this fallback as a best-effort
//! opportunistic seed, not the primary recovery path — and consult the
//! testnet `dht_fallback_*` metrics before assuming it earns its keep.
//!
//! ## — load/timeout tuning (all four sub-slices in one delivery)
//!
//! * **5a (config-driven baseline)** — `[routing] dht_fallback_timeout_ms`
//!   (default 10000) replaces the hardcoded const. Bounds 1000-60000.
//!
//! * **5b (backpressure-aware skipping)** — when the dispatcher's
//!   `pending_recursive` map is occupied past
//!   `dht_fallback_backpressure_threshold_pct` of
//!   `MAX_PENDING_RECURSIVE`, new fallback attempts return `false`
//!   without enqueueing. Prevents pile-on under load. Bumped as
//!   `dht_fallback_skipped_backpressure_total` metric.
//!
//! * **5c (adaptive timeout)** — opt-in via `dht_fallback_adaptive`.
//!   Tracks the last 20 outcomes; if recent miss-rate > 50% the
//!   effective timeout climbs 1.5× (up to 60s clamp), if < 10% it
//!   drops 0.67× (down to 1s clamp). Logged at info level whenever
//!   the effective timeout shifts.
//!
//! * **5d (per-priority multiplier)** — the trait method now takes
//!   a `priority` byte (carried from `route_miss_tx`'s
//!   `(target, traffic_class)` channel item). Effective timeout is
//!   `baseline × interactive_mult / 100` for INTERACTIVE
//!   `× background_mult / 100` for BACKGROUND. Other priority bytes
//!   use the baseline as-is.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use veil_util::{lock, rlock};

use rand_core::{OsRng, RngCore};
use tokio::sync::oneshot;

use veil_routing::miss_handler::IterativeDhtFallback;

use crate::runtime::NodeServices;
use veil_proto::budget::MAX_PENDING_RECURSIVE;
use veil_proto::codec::encode_header;
use veil_proto::family::{FrameFamily, RoutingMsg};
use veil_proto::header::{FrameHeader, priority};
use veil_proto::routing::{RecursiveQueryPayload, recursive_query_type};

/// Sliding-window size for adaptive-timeout outcome tracking.
/// 20 is a balance between fast reaction to topology change and stability
/// against jitter.
const ADAPTIVE_WINDOW: usize = 20;

/// Hard floor / ceiling clamps applied after all multipliers — guard
/// rails so misconfigured priority multipliers cannot starve the
/// fallback completely OR stall the miss-handler for minutes.
const TIMEOUT_FLOOR_MS: u64 = 1_000;
const TIMEOUT_CEIL_MS: u64 = 60_000;

/// Wires a `RecursiveQuery(FIND_NODE)` initiator into the `miss_handler`
/// pipeline. Captures config knobs at construction time; updates would
/// require a node reload (same pattern as other routing config).
pub struct DhtRouteFallback {
    services: NodeServices,
    /// Baseline timeout in milliseconds.
    baseline_timeout_ms: u64,
    /// b: `pending_recursive` occupancy fraction beyond which new
    /// attempts are dropped without enqueueing. Stored as a raw count
    /// (already-multiplied) for cheap comparison on every attempt.
    backpressure_cap: usize,
    /// c: whether adaptive timeout scaling is enabled.
    adaptive: bool,
    /// c: ring of last `ADAPTIVE_WINDOW` outcomes (true=resolved).
    /// Read/written behind a Mutex; lock is held only for a ring push +
    /// miss-rate calc (~few µs), no I/O across the lock.
    outcomes: Mutex<std::collections::VecDeque<bool>>,
    /// c: current effective timeout ms (adaptive scales this).
    /// AtomicU64 so reads avoid the Mutex. Surfaced as a Prometheus
    /// gauge `veil_dht_fallback_effective_timeout_ms`.
    effective_timeout_ms: AtomicU64,
    /// d: [interactive_mult, background_mult] in percent (100 =
    /// 1.0× baseline). Other priority bytes use 100.
    priority_mult: [u16; 2],
}

impl DhtRouteFallback {
    pub(crate) fn new(
        services: NodeServices,
        timeout_ms: u64,
        backpressure_threshold_pct: u8,
        adaptive: bool,
        priority_mult: [u16; 2],
    ) -> Self {
        let bp_cap =
            (MAX_PENDING_RECURSIVE as u64 * u64::from(backpressure_threshold_pct) / 100) as usize;
        // Seed the gauge with the baseline so dashboards have a value
        // immediately after node start, not only after the first
        // adaptive adjustment.
        if let Some(metrics) = services.metrics.as_ref() {
            metrics.set_dht_fallback_effective_timeout_ms(timeout_ms);
        }
        Self {
            services,
            baseline_timeout_ms: timeout_ms,
            backpressure_cap: bp_cap,
            adaptive,
            outcomes: Mutex::new(std::collections::VecDeque::with_capacity(ADAPTIVE_WINDOW)),
            effective_timeout_ms: AtomicU64::new(timeout_ms),
            priority_mult,
        }
    }

    /// d: compute effective timeout for the given priority. Clamped
    /// to [TIMEOUT_FLOOR_MS, TIMEOUT_CEIL_MS] after multiplier application
    /// so misconfigured knobs can't break the safety invariant.
    fn priority_scaled_ms(&self, priority: u8) -> u64 {
        let baseline = self.effective_timeout_ms.load(Ordering::Relaxed);
        let mult = match priority {
            p if p == priority::INTERACTIVE => self.priority_mult[0],
            p if p == priority::BACKGROUND => self.priority_mult[1],
            _ => 100,
        };
        let scaled = baseline.saturating_mul(u64::from(mult)) / 100;
        scaled.clamp(TIMEOUT_FLOOR_MS, TIMEOUT_CEIL_MS)
    }

    /// c: record an outcome and (if adaptive) adjust the effective
    /// timeout based on the rolling miss-rate.
    fn record_outcome(&self, resolved: bool) {
        if !self.adaptive {
            return;
        }
        let mut ring = self.outcomes.lock().unwrap_or_else(|p| p.into_inner());
        if ring.len() == ADAPTIVE_WINDOW {
            ring.pop_front();
        }
        ring.push_back(resolved);
        if ring.len() < ADAPTIVE_WINDOW / 2 {
            // Not enough samples yet — don't oscillate.
            return;
        }
        let resolved_count = ring.iter().filter(|&&b| b).count();
        let miss_rate = 1.0 - (resolved_count as f64 / ring.len() as f64);
        let current = self.effective_timeout_ms.load(Ordering::Relaxed);
        let new_timeout = if miss_rate > 0.5 {
            // High miss rate — give the network more time.
            ((current as f64 * 1.5) as u64).min(TIMEOUT_CEIL_MS)
        } else if miss_rate < 0.1 {
            // Low miss rate — tighten budget back toward baseline.
            ((current as f64 / 1.5) as u64).max(self.baseline_timeout_ms)
        } else {
            current
        };
        if new_timeout != current {
            self.effective_timeout_ms
                .store(new_timeout, Ordering::Relaxed);
            if let Some(metrics) = self.services.metrics.as_ref() {
                metrics.set_dht_fallback_effective_timeout_ms(new_timeout);
            }
            self.services.logger.info(
                "route.dht_fallback.adaptive",
                format!(
                    "miss_rate={:.2} effective_timeout {}→{} ms",
                    miss_rate, current, new_timeout
                ),
            );
        }
    }
}

impl IterativeDhtFallback for DhtRouteFallback {
    fn try_seed_route_via_find_node<'a>(
        &'a self,
        target: [u8; 32],
        priority: u8,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let services = &self.services;

            // ── backpressure-aware skip ────────────────────────
            // If `pending_recursive` is already near cap, piling another
            // attempt only worsens the situation. Drop early and signal
            // up. The metric makes this visible to operators.
            {
                let m = lock!(services.dispatcher.pending_recursive);
                if m.len() >= self.backpressure_cap {
                    if let Some(metrics) = services.metrics.as_ref() {
                        metrics.inc_dht_fallback_skipped_backpressure();
                    }
                    return false;
                }
            }

            // ── priority-aware effective timeout ───────────────
            let timeout = Duration::from_millis(self.priority_scaled_ms(priority));

            // Build the RecursiveQuery(FIND_NODE) frame with a fresh 16-byte
            // query_id. TTL=40 matches the production recursive-DHT
            // path-length budget.
            let mut query_id = [0u8; 16];
            OsRng.fill_bytes(&mut query_id);
            let q = RecursiveQueryPayload {
                query_id,
                target_key: target,
                reply_to: services.local_node_id,
                ttl: 40,
                query_type: recursive_query_type::FIND_NODE,
                reply_port: 0,
                payload: vec![],
            };
            let q_bytes = q.encode();
            let mut hdr = FrameHeader::new(
                FrameFamily::Routing as u8,
                RoutingMsg::RecursiveQuery as u16,
            );
            hdr.body_len = q_bytes.len() as u32;
            let mut frame = encode_header(&hdr).to_vec();
            frame.extend_from_slice(&q_bytes);

            // Register the oneshot so dispatcher's response handler can
            // wake us when the signed RecursiveResponse arrives. See
            // dispatcher/routing.rs:2409-2424 — for FIND_NODE the
            // dispatcher inserts each returned 32-byte node_id as a
            // candidate next-hop for `target_key` at score=50_000
            // hops=2. So even if our oneshot times out, the cache
            // may still have been seeded by partial responses from
            // intermediate forwarders along the path.
            let (tx, rx) = oneshot::channel::<Vec<u8>>();
            {
                let mut m = lock!(services.dispatcher.pending_recursive);
                m.retain(|_, p| !p.tx.is_closed());
                if m.len() >= MAX_PENDING_RECURSIVE {
                    self.record_outcome(false);
                    return false;
                }
                m.insert(
                    query_id,
                    veil_dispatcher::PendingRecursive {
                        target_key: target,
                        query_type: recursive_query_type::FIND_NODE,
                        tx,
                    },
                );
            }

            // Pick top-2 closest active session peers (sorted by XOR
            // distance to target_key) — mirrors `runtime::dht_recursive_get`
            // fan-out. Sends fire-and-forget.
            let mut peers: Vec<[u8; 32]> = rlock!(services.session_tx_registry).peer_ids();
            if peers.is_empty() {
                self.record_outcome(false);
                return false;
            }
            peers.sort_by_key(|pid| {
                let mut xor = [0u8; 32];
                for i in 0..32 {
                    xor[i] = pid[i] ^ target[i];
                }
                xor
            });
            {
                let guard = rlock!(services.session_tx_registry);
                for pid in peers.iter().take(2) {
                    guard.send_to(pid, priority::INTERACTIVE, frame.clone());
                }
            }

            // Wait for the response OR timeout, and feed the outcome to
            // adaptive accumulator.
            let resolved = matches!(tokio::time::timeout(timeout, rx).await, Ok(Ok(_)));
            self.record_outcome(resolved);
            resolved
        })
    }
}
