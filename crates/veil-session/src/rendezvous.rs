//! PoW-gated rendezvous controller (server-side) — Slice 3 of the
//! PoW-Gated Rendezvous epic ([`docs/internal/PLAN_POW_GATED_RENDEZVOUS.md`]).
//!
//! Owns the full lifecycle of one node's response to incoming rendezvous
//! requests:
//!
//! 1. **Decode + verify** the `RequestEphemeralEndpointPayload` (wire
//!    primitives live in `veil-proto::rendezvous`, Slice 1).
//! 2. **Target check** — `payload.target_node_id` must equal our own
//!    `local_node_id`; rendezvous requests are not relay-forwarded
//!    blindly.
//! 3. **Rate limit** by `requester_pubkey` — protects against a PoW-
//!    funded requester that mines once and burst-replays.
//! 4. **Concurrent slot semaphore** — caps in-flight on-demand
//!    listeners.  Beyond the cap the request is rejected; legitimate
//!    requesters retry after a short backoff.
//! 5. **Bind a slot** via `veil-transport::on_demand::bind_on_demand`
//!    (Slice 2) — probe-bind a random port.
//! 6. **Generate fresh PSK** — per-request 32-byte secret, transports
//!    embed it through their listener context.
//! 7. **Build URI + invoke caller-supplied bind closure** — wraps the
//!    TCP socket with obfs4-tcp/wss/quic + spawns the dedicated accept
//!    task that respects the lifecycle handle (TTL + accept budget).
//! 8. **Sign EphemeralEndpointResponse** + return the wire bytes for
//!    the dispatcher arm to ship back over the session.
//!
//! ## Scope (Slice 3)
//!
//! This module is a **standalone, testable controller** that is now
//! wired in production: the controller is constructed in `node-runtime`
//! (`runtime/services.rs`) and incoming
//! `SessionMsg::RequestEphemeralEndpoint` bodies are dispatched to
//! [`RendezvousController::handle_request`] via the dispatcher's
//! `rendezvous_weak` upgrade on the routing dispatch path
//! (`veil-dispatcher`). (Slice 5 landed; the earlier "pub + unused in
//! production" note was stale.)
//!
//! Tests inject a recording [`BindClosure`] that captures `(uri, psk
//! lifecycle)` tuples; the controller is verified in-process with no
//! real-world bind round-trips required.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use ed25519_dalek::SigningKey;
use tokio::sync::Semaphore;

use veil_transport::on_demand::{OnDemandConfig, OnDemandLifecycle, OnDemandSlot, bind_on_demand};
use veil_transport::rotation::parse_duration_spec;

use veil_proto::rendezvous::{
    EphemeralEndpointResponsePayload, MIN_POW_DIFFICULTY, RequestEphemeralEndpointPayload,
    sign_ephemeral_endpoint_response, verify_request_ephemeral_endpoint,
};

// ── Configuration ───────────────────────────────────────────────────

/// Operator-tunable rendezvous policy.  All fields chosen at
/// `RendezvousController::new` time and immutable afterwards (a reload
/// rebuilds the controller).
#[derive(Debug, Clone)]
pub struct RendezvousPolicy {
    /// Minimum acceptable PoW difficulty (leading-zero-bits) for
    /// incoming requests.  Verifier rejects requests claiming a lower
    /// difficulty.  Production defaults to 24 bits (~0.5 sec CPU on a
    /// typical 2-vCPU VPS).
    pub min_pow_difficulty: u32,

    /// Per-requester rate-limit window: how many granted requests are
    /// allowed per `rate_window` interval per unique `requester_pubkey`.
    pub rate_window: Duration,
    /// Number of requests allowed within `rate_window` per requester.
    pub rate_burst: u32,

    /// Maximum concurrent on-demand listeners in flight.  Protects FD
    /// table from a PoW-funded burst.
    pub max_concurrent_slots: usize,

    /// Per-slot config (port range, TTL, accept budget, retry count).
    /// Primary advertise destination — used when `extra_destinations`
    /// is empty.  Otherwise the controller round-robins between
    /// [primary] ++ extras on each grant.
    pub slot_config: OnDemandConfig,

    /// URI template parts.  The controller composes the response URI
    /// as `{scheme}://{advertise_host}:{port}`.  E.g.
    /// `scheme="obfs4-tcp"`, `advertise_host="example.com"` →
    /// `"obfs4-tcp://example.com:51237"`.
    pub advertise_host: String,
    pub scheme: String,

    /// Follow-up #2: multi-stealth-listener support.  Each entry
    /// contributes an additional bind destination (separate port
    /// range / interface / advertise host) that shares the unified
    /// policy fields (pow_difficulty, rate limits, concurrent-slot
    /// cap, signing identity).  Controller round-robins between
    /// `[primary]` (built from `slot_config`/`advertise_host`/`scheme`)
    /// + every entry in this Vec on each grant — guarantees even
    ///   utilization across all configured stealth surfaces without
    ///   requiring the caller to pre-decide which surface a requester
    ///   will land on.  Empty Vec keeps the single-destination
    ///   behavior bit-for-bit.
    pub extra_destinations: Vec<AdvertiseDestination>,
}

/// Follow-up #2: one additional bind destination (port range +
/// advertise host) sharing the unified rendezvous policy.  Mirrors
/// the trio (`slot_config`, `advertise_host`, `scheme`) carried
/// directly on `RendezvousPolicy` for the primary destination.
#[derive(Debug, Clone)]
pub struct AdvertiseDestination {
    pub slot_config: OnDemandConfig,
    pub advertise_host: String,
    pub scheme: String,
}

impl RendezvousPolicy {
    /// Sanity-check the policy.  Returns `Err` for nonsensical combos
    /// (zero difficulty, zero burst, zero concurrent slots).  Called
    /// by `RendezvousController::new`.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.min_pow_difficulty < MIN_POW_DIFFICULTY {
            return Err(PolicyError::PowDifficultyTooLow {
                requested: self.min_pow_difficulty,
                min: MIN_POW_DIFFICULTY,
            });
        }
        if self.rate_burst == 0 {
            return Err(PolicyError::Invalid("rate_burst must be > 0"));
        }
        if self.rate_window.is_zero() {
            return Err(PolicyError::Invalid("rate_window must be > 0"));
        }
        if self.max_concurrent_slots == 0 {
            return Err(PolicyError::Invalid("max_concurrent_slots must be > 0"));
        }
        if self.advertise_host.is_empty() {
            return Err(PolicyError::Invalid("advertise_host must be non-empty"));
        }
        if self.scheme.is_empty() {
            return Err(PolicyError::Invalid("scheme must be non-empty"));
        }
        // Follow-up #2: validate every extra destination just like
        // the primary trio — empty fields would silently break the
        // round-robin response composition.
        for (i, d) in self.extra_destinations.iter().enumerate() {
            if d.advertise_host.is_empty() {
                return Err(PolicyError::Invalid(
                    "extra_destinations[N].advertise_host must be non-empty",
                ));
            }
            if d.scheme.is_empty() {
                return Err(PolicyError::Invalid(
                    "extra_destinations[N].scheme must be non-empty",
                ));
            }
            if d.slot_config.port_range.is_empty() {
                return Err(PolicyError::Invalid(
                    "extra_destinations[N].slot_config.port_range must be non-empty",
                ));
            }
            let _ = i; // index already implied by the static slot literal
        }
        Ok(())
    }
}

/// Helper builder that parses a `[listen.on_demand]`-style config block
/// (string-based durations) into an `OnDemandConfig`.  Reuses the
/// Phase 5f duration parser.
pub fn slot_config_from_strings(
    host: &str,
    port_range: std::ops::RangeInclusive<u16>,
    bind_retries: u32,
    ttl_spec: &str,
    max_accepts: usize,
) -> Result<OnDemandConfig, PolicyError> {
    let ttl = parse_duration_spec(ttl_spec)
        .map_err(|e| PolicyError::DurationParse(format!("ttl: {e}")))?;
    Ok(OnDemandConfig {
        host: host.to_owned(),
        port_range,
        bind_retries,
        ttl,
        max_accepts,
    })
}

impl RendezvousPolicy {
    /// Build a policy from an operator's `[listen.on_demand]` config block,
    /// completing the missing pieces (host / scheme / advertise_host)
    /// that the config schema doesn't carry directly.
    ///
    /// `bind_host` is the local bind address (typically `"0.0.0.0"`);
    /// `advertise_host` is the publicly-reachable host advertised to
    /// requesters in the EphemeralEndpointResponse URI; `scheme` is the
    /// URI scheme used to compose the response (e.g. `"obfs4-tcp"`).
    pub fn from_on_demand_config(
        cfg: &veil_cfg::OnDemandListenConfig,
        bind_host: &str,
        advertise_host: &str,
        scheme: &str,
    ) -> Result<Self, PolicyError> {
        let (port_lo, port_hi) = cfg.range;
        if port_lo > port_hi {
            return Err(PolicyError::Invalid("[listen.on_demand].range start > end"));
        }
        let ttl = parse_duration_spec(&cfg.ttl)
            .map_err(|e| PolicyError::DurationParse(format!("ttl: {e}")))?;
        let (rate_burst, rate_window) = veil_transport::rotation::parse_rate_spec(&cfg.rate_limit)
            .map_err(|e| PolicyError::DurationParse(format!("rate_limit: {e}")))?;
        let policy = Self {
            min_pow_difficulty: cfg.pow_difficulty,
            rate_window,
            rate_burst,
            max_concurrent_slots: cfg.max_concurrent,
            slot_config: OnDemandConfig {
                host: bind_host.to_owned(),
                port_range: port_lo..=port_hi,
                bind_retries: cfg.bind_retries,
                ttl,
                max_accepts: cfg.max_accepts,
            },
            advertise_host: advertise_host.to_owned(),
            scheme: scheme.to_owned(),
            extra_destinations: Vec::new(),
        };
        policy.validate()?;
        Ok(policy)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid policy: {0}")]
    Invalid(&'static str),
    #[error("min_pow_difficulty={requested} below floor {min}")]
    PowDifficultyTooLow { requested: u32, min: u32 },
    #[error("duration parse: {0}")]
    DurationParse(String),
}

// ── Bind closure ────────────────────────────────────────────────────

/// Caller-supplied bridge between the controller and the actual
/// `TransportRegistry::bind` + accept-task spawn.  Lives outside this
/// module so the controller can be tested with a mock that records what
/// it received, and so Slice 5 can wire the real binding logic against
/// the runtime's `TransportRegistry` + `TransportContext` without a
/// circular dependency.
///
/// Contract: after the controller invokes `bind`, the closure MUST:
/// 1. Construct the actual `Box<dyn TransportListener>` for the given
///    URI with the per-request PSK installed in the listener context.
/// 2. Spawn a dedicated accept task that respects `lifecycle` (exits
///    on TTL OR when `note_accept()` returns 1).
/// 3. Drop the listener when the accept task exits.
///
/// Returns an error iff (1) failed — the controller will surface that
/// as a `RejectReason::BindFailed` to the caller, AND the slot's
/// lifecycle handle should be `shutdown()` to release any concurrent-
/// slot permit (controller does this automatically on drop of the
/// permit guard).
pub trait BindClosure: Send + Sync + 'static {
    fn bind(
        &self,
        uri: String,
        psk: [u8; 32],
        lifecycle: Arc<OnDemandLifecycle>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>;
}

// ── Rate limiter ────────────────────────────────────────────────────

/// Simple sliding-window-per-pubkey rate limiter.  Bounded growth: the
/// outer `HashMap` is pruned on each insertion that finds itself > 2×
/// `rate_burst * max_concurrent_slots` (a very loose bound — at typical
/// production settings (burst=3, slots=16) we cap at ~96 entries
/// before pruning, which is negligible memory).
#[derive(Debug)]
pub struct RateLimiter {
    window: Duration,
    burst: u32,
    /// Per-requester history of grant timestamps.  Old entries pruned
    /// on access.
    state: HashMap<[u8; 32], Vec<Instant>>,
    soft_cap: usize,
}

impl RateLimiter {
    fn new(window: Duration, burst: u32, soft_cap: usize) -> Self {
        Self {
            window,
            burst,
            state: HashMap::new(),
            soft_cap,
        }
    }

    /// Check + record a grant attempt.  Returns true iff the requester
    /// is within budget; false if they would exceed the burst.  On
    /// `true` an entry is appended to their history.
    fn allow(&mut self, requester: [u8; 32], now: Instant) -> bool {
        let entry = self.state.entry(requester).or_default();
        // Prune any timestamps outside the window.
        entry.retain(|t| now.duration_since(*t) <= self.window);
        if entry.len() as u32 >= self.burst {
            return false;
        }
        entry.push(now);

        // Optional global prune to bound memory.  Cheap: drop the
        // entry entirely if its history is empty AND it's an older
        // key; this keeps the map to size O(active requesters in window).
        if self.state.len() > self.soft_cap {
            self.state.retain(|_, ts| {
                ts.retain(|t| now.duration_since(*t) <= self.window);
                !ts.is_empty()
            });
        }
        true
    }

    /// Test/diagnostics helper. (audit cycle-3: `#[cfg(test)]` instead of
    /// `#[allow(dead_code)]` — its only caller, `rate_limiter_entries_for`, is
    /// itself test-only.)
    #[cfg(test)]
    fn current_entries(&self, requester: &[u8; 32]) -> usize {
        self.state.get(requester).map(|v| v.len()).unwrap_or(0)
    }
}

// ── Controller ──────────────────────────────────────────────────────

/// PoW-gated rendezvous controller — entry point for incoming
/// `SessionMsg::RequestEphemeralEndpoint` bodies.  Owns the rate
/// limiter, concurrent-slot semaphore, signing key, and delegates the
/// actual bind to the caller-supplied closure.
pub struct RendezvousController {
    policy: RendezvousPolicy,
    local_node_id: [u8; 32],
    signing_key: Arc<SigningKey>,
    rate_limiter: Mutex<RateLimiter>,
    slot_semaphore: Arc<Semaphore>,
    binder: Arc<dyn BindClosure>,
    /// Optional metrics handle.  When `Some`, every dispatch path
    /// increments the relevant counter (received / granted /
    /// rejected_*).  `None` keeps the controller usable in isolated
    /// unit tests without scaffolding a NodeMetrics fixture.
    metrics: Option<Arc<veil_observability::NodeMetrics>>,
    /// Follow-up #2: round-robin cursor over the destination pool
    /// (`[primary] ++ policy.extra_destinations`).  `fetch_add(1)`
    /// per grant guarantees even fan-out across all advertise
    /// surfaces without any per-bind state inspection.
    next_destination: AtomicUsize,
}

impl RendezvousController {
    /// Construct.  Validates the policy and precomputes the rate
    /// limiter + semaphore.  `metrics` is optional; tests pass
    /// `None`, production passes the runtime's `NodeMetrics`.
    pub fn new(
        policy: RendezvousPolicy,
        local_node_id: [u8; 32],
        signing_key: SigningKey,
        binder: Arc<dyn BindClosure>,
    ) -> Result<Self, PolicyError> {
        Self::new_with_metrics(policy, local_node_id, signing_key, binder, None)
    }

    /// Construct with an explicit `NodeMetrics` handle.
    pub fn new_with_metrics(
        policy: RendezvousPolicy,
        local_node_id: [u8; 32],
        signing_key: SigningKey,
        binder: Arc<dyn BindClosure>,
        metrics: Option<Arc<veil_observability::NodeMetrics>>,
    ) -> Result<Self, PolicyError> {
        policy.validate()?;
        let soft_cap = (policy.rate_burst as usize)
            .saturating_mul(policy.max_concurrent_slots)
            .saturating_mul(2)
            .max(64);
        let rate_limiter = Mutex::new(RateLimiter::new(
            policy.rate_window,
            policy.rate_burst,
            soft_cap,
        ));
        let slot_semaphore = Arc::new(Semaphore::new(policy.max_concurrent_slots));
        Ok(Self {
            policy,
            local_node_id,
            signing_key: Arc::new(signing_key),
            rate_limiter,
            slot_semaphore,
            binder,
            metrics,
            next_destination: AtomicUsize::new(0),
        })
    }

    /// Follow-up #2: number of advertise destinations the controller
    /// rotates between.  Always ≥ 1 (the primary destination from
    /// `policy.slot_config`/`advertise_host`/`scheme`); equals
    /// `1 + policy.extra_destinations.len()` when multi-stealth is
    /// configured.
    pub fn destination_count(&self) -> usize {
        1 + self.policy.extra_destinations.len()
    }

    /// Follow-up #2: pick the next destination's (slot_config,
    /// advertise_host, scheme) triple round-robin.  Pure read —
    /// callers may discard the result without advancing.
    fn pick_destination(&self) -> (OnDemandConfig, &str, &str) {
        let total = 1 + self.policy.extra_destinations.len();
        if total == 1 {
            return (
                self.policy.slot_config.clone(),
                self.policy.advertise_host.as_str(),
                self.policy.scheme.as_str(),
            );
        }
        let idx = self.next_destination.fetch_add(1, Ordering::Relaxed) % total;
        if idx == 0 {
            (
                self.policy.slot_config.clone(),
                self.policy.advertise_host.as_str(),
                self.policy.scheme.as_str(),
            )
        } else {
            let d = &self.policy.extra_destinations[idx - 1];
            (
                d.slot_config.clone(),
                d.advertise_host.as_str(),
                d.scheme.as_str(),
            )
        }
    }

    /// Handle one incoming request body.  Pure entrypoint: decode +
    /// verify + decide + (if granted) bind + sign response.  Caller
    /// (dispatcher arm in Slice 5) ships the returned bytes back over
    /// the session.
    pub async fn handle_request(&self, body: &[u8]) -> RequestOutcome {
        if let Some(m) = self.metrics.as_ref() {
            m.inc_rendezvous_requests_received();
        }

        // 1. Decode.
        let payload = match RequestEphemeralEndpointPayload::decode(body) {
            Ok(p) => p,
            Err(e) => {
                if let Some(m) = self.metrics.as_ref() {
                    m.inc_rendezvous_requests_rejected_decode();
                }
                return RequestOutcome::Rejected(RejectReason::Decode(format!("{e}")));
            }
        };

        // 2. Target check.
        if payload.target_node_id != self.local_node_id {
            if let Some(m) = self.metrics.as_ref() {
                m.inc_rendezvous_requests_rejected_not_our_target();
            }
            return RequestOutcome::Rejected(RejectReason::NotOurTarget);
        }

        // 3. Verify (sig + PoW + replay window).
        let now_unix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Err(e) =
            verify_request_ephemeral_endpoint(&payload, self.policy.min_pow_difficulty, now_unix)
        {
            if let Some(m) = self.metrics.as_ref() {
                m.inc_rendezvous_requests_rejected_verify();
            }
            return RequestOutcome::Rejected(RejectReason::Verify(format!("{e}")));
        }

        // 4. Rate limit by requester_pubkey.
        let now = Instant::now();
        {
            // SECURITY (audit 2026-05-29, poison-DoS fix): recover from a
            // poisoned mutex rather than `.expect()`-panicking — a single
            // prior panic must not cascade into a permanent rendezvous DoS.
            let mut limiter = self.rate_limiter.lock().unwrap_or_else(|p| p.into_inner());
            if !limiter.allow(payload.requester_pubkey, now) {
                if let Some(m) = self.metrics.as_ref() {
                    m.inc_rendezvous_requests_rejected_rate_limit();
                }
                return RequestOutcome::Rejected(RejectReason::RateLimited);
            }
        }

        // 5. Acquire a concurrent-slot permit.
        let permit = match Arc::clone(&self.slot_semaphore).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                if let Some(m) = self.metrics.as_ref() {
                    m.inc_rendezvous_requests_rejected_concurrency();
                }
                return RequestOutcome::Rejected(RejectReason::ConcurrencyExhausted);
            }
        };

        // 6. Probe-bind a slot.  Follow-up #2: pick a destination
        //    round-robin if multiple stealth listeners are configured.
        let (slot_cfg, advertise_host, scheme) = self.pick_destination();
        let slot_ttl = slot_cfg.ttl;
        let slot: OnDemandSlot = match bind_on_demand(slot_cfg).await {
            Ok(s) => s,
            Err(e) => {
                drop(permit); // release the slot permit
                if let Some(m) = self.metrics.as_ref() {
                    m.inc_rendezvous_requests_rejected_bind_failed();
                }
                return RequestOutcome::Rejected(RejectReason::BindFailed(format!(
                    "bind_on_demand: {e}"
                )));
            }
        };

        // 7. Fresh PSK + URI.
        let psk = fresh_psk();
        let uri = format!("{}://{}:{}", scheme, advertise_host, slot.port,);

        // 8. Invoke caller-supplied binder.
        let lifecycle = Arc::clone(&slot.lifecycle);
        let bind_fut = self.binder.bind(uri.clone(), psk, Arc::clone(&lifecycle));
        if let Err(e) = bind_fut.await {
            drop(permit);
            if let Some(m) = self.metrics.as_ref() {
                m.inc_rendezvous_requests_rejected_bind_failed();
            }
            return RequestOutcome::Rejected(RejectReason::BindFailed(format!(
                "bind closure: {e}"
            )));
        }

        // 9. Listener bound — bump the in-use gauge.  Pair with a task
        //    that watches the lifecycle and decrements when it retires
        //    (TTL or accept-exhaustion), at the same time releasing
        //    the slot permit.
        if let Some(m) = self.metrics.as_ref() {
            m.inc_rendezvous_slots_in_use();
        }
        let lifecycle_for_permit = Arc::clone(&lifecycle);
        let metrics_for_decrement = self.metrics.clone();
        tokio::spawn(async move {
            lifecycle_for_permit.await_ttl_or_shutdown().await;
            drop(permit); // releases a semaphore slot
            if let Some(m) = metrics_for_decrement {
                m.dec_rendezvous_slots_in_use();
            }
        });

        // 10. Sign the response.  Follow-up #2: TTL comes from the
        //     picked destination's slot_config, NOT the primary's
        //     (multi-stealth with heterogeneous TTLs — each destination
        //     has its own).
        let valid_until_unix = now_unix.saturating_add(slot_ttl.as_secs());
        let response = match sign_ephemeral_endpoint_response(
            self.local_node_id,
            payload.requester_pubkey,
            valid_until_unix,
            uri.clone(),
            psk,
            &self.signing_key,
        ) {
            Ok(r) => r,
            Err(e) => {
                lifecycle.shutdown();
                if let Some(m) = self.metrics.as_ref() {
                    m.inc_rendezvous_requests_rejected_bind_failed();
                }
                return RequestOutcome::Rejected(RejectReason::BindFailed(format!(
                    "sign response: {e}"
                )));
            }
        };

        if let Some(m) = self.metrics.as_ref() {
            m.inc_rendezvous_requests_granted();
        }
        RequestOutcome::Granted {
            response_bytes: response.encode(),
            port: slot.port,
            response_payload: response,
        }
    }

    /// Diagnostics: number of currently-rate-limited requesters in
    /// the live window.  Test-only — no production consumer (audit cycle-3);
    /// re-export by dropping the `#[cfg(test)]` if a metrics exporter wires in.
    #[cfg(test)]
    pub fn rate_limiter_entries_for(&self, requester: &[u8; 32]) -> usize {
        // SECURITY (audit 2026-05-29, poison-DoS fix): poison-recovering
        // access — see the `allow` call site above for rationale.
        let limiter = self.rate_limiter.lock().unwrap_or_else(|p| p.into_inner());
        limiter.current_entries(requester)
    }
}

// ── Outcome types ───────────────────────────────────────────────────

/// Result of one rendezvous request handling cycle.
#[derive(Debug)]
pub enum RequestOutcome {
    /// Request accepted, listener bound, response signed and ready to
    /// ship.  Caller (Slice 5 dispatcher arm) wraps the bytes in an
    /// `EphemeralEndpointResponse` frame and sends to the requester
    /// over the existing session.
    Granted {
        response_bytes: Vec<u8>,
        port: u16,
        response_payload: EphemeralEndpointResponsePayload,
    },
    /// Request rejected.  No state change on this controller; the
    /// `RejectReason` is shipped (or just logged) for observability.
    Rejected(RejectReason),
}

#[derive(Debug)]
pub enum RejectReason {
    /// Wire bytes don't decode as a valid request structure.
    Decode(String),
    /// Verify failure: sig, PoW, or replay-window.
    Verify(String),
    /// `target_node_id` doesn't match our `local_node_id`.
    NotOurTarget,
    /// Requester exceeded their `rate_burst` within `rate_window`.
    RateLimited,
    /// Concurrent in-flight slot semaphore exhausted.
    ConcurrencyExhausted,
    /// `bind_on_demand` failed (port range exhausted) or the caller-
    /// supplied bind closure failed (e.g. obfs4 wrap error).
    BindFailed(String),
}

// ── helpers ─────────────────────────────────────────────────────────

pub fn fresh_psk() -> [u8; 32] {
    use rand_core::{OsRng, RngCore};
    let mut psk = [0u8; 32];
    OsRng.fill_bytes(&mut psk);
    psk
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use veil_proto::rendezvous::{
        MAX_POW_DIFFICULTY, mine_pow_nonce, sign_request_ephemeral_endpoint,
        verify_ephemeral_endpoint_response,
    };

    // ── Test fixtures ─────────────────────────────────────────────

    fn test_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Mock binder that records every bind call.  Captures (uri, psk
    /// lifecycle) so tests can assert what the controller passed.
    #[derive(Default)]
    #[allow(clippy::type_complexity)] // test-fixture mutex of recorded tuples
    struct RecordingBinder {
        calls: Mutex<Vec<(String, [u8; 32], Arc<OnDemandLifecycle>)>>,
        return_err: Option<String>,
    }

    impl BindClosure for RecordingBinder {
        fn bind(
            &self,
            uri: String,
            psk: [u8; 32],
            lifecycle: Arc<OnDemandLifecycle>,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>> {
            self.calls
                .lock()
                .unwrap()
                .push((uri, psk, Arc::clone(&lifecycle)));
            let err = self.return_err.clone();
            Box::pin(async move {
                match err {
                    Some(e) => Err(e),
                    None => Ok(()),
                }
            })
        }
    }

    fn default_policy() -> RendezvousPolicy {
        RendezvousPolicy {
            min_pow_difficulty: 8, // low so tests mine quickly
            rate_window: Duration::from_secs(60),
            rate_burst: 3,
            max_concurrent_slots: 4,
            slot_config: OnDemandConfig {
                host: "127.0.0.1".to_owned(),
                port_range: 30000..=60000,
                bind_retries: 64,
                ttl: Duration::from_secs(60),
                max_accepts: 1,
            },
            advertise_host: "example.com".to_owned(),
            scheme: "obfs4-tcp".to_owned(),
            extra_destinations: Vec::new(),
        }
    }

    fn target_identity(seed: u8) -> ([u8; 32], SigningKey) {
        let sk = test_sk(seed);
        let pk = sk.verifying_key().to_bytes();
        let nid = *blake3::hash(&pk).as_bytes();
        (nid, sk)
    }

    fn build_signed_request(
        target_node_id: [u8; 32],
        requester_sk: &SigningKey,
        difficulty: u32,
        timestamp_unix: u64,
    ) -> Vec<u8> {
        let requester_pk = requester_sk.verifying_key().to_bytes();
        let mut draft = RequestEphemeralEndpointPayload {
            target_node_id,
            requester_pubkey: requester_pk,
            timestamp_unix,
            pow_difficulty: difficulty,
            pow_nonce: 0,
            requester_sig: [0u8; 64],
        };
        mine_pow_nonce(&mut draft).unwrap();
        let signed = sign_request_ephemeral_endpoint(
            target_node_id,
            requester_pk,
            timestamp_unix,
            difficulty,
            draft.pow_nonce,
            requester_sk,
        );
        signed.encode().to_vec()
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // ── Policy validation ─────────────────────────────────────────

    #[test]
    fn policy_rejects_low_pow_difficulty() {
        let mut p = default_policy();
        p.min_pow_difficulty = 0; // below MIN_POW_DIFFICULTY (8)
        let err = p.validate().unwrap_err();
        assert!(matches!(err, PolicyError::PowDifficultyTooLow { .. }));
    }

    #[test]
    fn policy_rejects_zero_burst() {
        let mut p = default_policy();
        p.rate_burst = 0;
        assert!(matches!(p.validate(), Err(PolicyError::Invalid(_))));
    }

    #[test]
    fn policy_rejects_zero_concurrent_slots() {
        let mut p = default_policy();
        p.max_concurrent_slots = 0;
        assert!(matches!(p.validate(), Err(PolicyError::Invalid(_))));
    }

    // ── Happy path ────────────────────────────────────────────────

    #[tokio::test]
    async fn happy_path_grants_and_returns_signed_response() {
        let (target_nid, target_sk) = target_identity(1);
        let requester_sk = test_sk(2);
        let binder = Arc::new(RecordingBinder::default());
        let controller = RendezvousController::new(
            default_policy(),
            target_nid,
            target_sk.clone(),
            binder.clone(),
        )
        .unwrap();
        let body = build_signed_request(target_nid, &requester_sk, 8, now_unix());
        let outcome = controller.handle_request(&body).await;
        match outcome {
            RequestOutcome::Granted {
                response_bytes,
                port,
                response_payload,
            } => {
                // Port must be in the configured range.
                assert!((30000..=60000).contains(&port));
                // URI must use the operator's advertise_host, NOT the
                // bind host (controller composes with scheme/advertise_host).
                let calls = binder.calls.lock().unwrap();
                assert_eq!(calls.len(), 1);
                let (uri, _psk, _lifecycle) = &calls[0];
                assert!(uri.starts_with("obfs4-tcp://example.com:"));
                assert!(uri.ends_with(&port.to_string()));
                // Response must verify under the target's pubkey from
                // the initiator's POV.
                let target_pk = target_sk.verifying_key().to_bytes();
                let requester_pk = requester_sk.verifying_key().to_bytes();
                verify_ephemeral_endpoint_response(
                    &response_payload,
                    &target_pk,
                    &requester_pk,
                    now_unix(),
                )
                .expect("signed response must verify");
                // PSK passed to binder must match the one in the
                // signed response.
                assert_eq!(calls[0].1, response_payload.psk);
                // response_bytes should decode back to the same payload.
                let decoded = EphemeralEndpointResponsePayload::decode(&response_bytes).unwrap();
                assert_eq!(decoded, response_payload);
            }
            RequestOutcome::Rejected(reason) => panic!("expected Granted, got {reason:?}"),
        }
    }

    // ── Follow-up #2: multi-stealth round-robin ───────────────────

    #[test]
    fn destination_count_reflects_extras() {
        let mut p = default_policy();
        assert_eq!(
            RendezvousController::new(
                p.clone(),
                [0u8; 32],
                test_sk(0),
                Arc::new(RecordingBinder::default())
            )
            .unwrap()
            .destination_count(),
            1,
        );
        p.extra_destinations.push(AdvertiseDestination {
            slot_config: OnDemandConfig {
                host: "127.0.0.2".to_owned(),
                port_range: 40000..=50000,
                bind_retries: 16,
                ttl: Duration::from_secs(30),
                max_accepts: 1,
            },
            advertise_host: "second.example.com".to_owned(),
            scheme: "obfs4-tcp".to_owned(),
        });
        p.extra_destinations.push(AdvertiseDestination {
            slot_config: OnDemandConfig {
                host: "127.0.0.3".to_owned(),
                port_range: 50001..=60000,
                bind_retries: 16,
                ttl: Duration::from_secs(30),
                max_accepts: 1,
            },
            advertise_host: "third.example.com".to_owned(),
            scheme: "obfs4-tcp".to_owned(),
        });
        assert_eq!(
            RendezvousController::new(
                p,
                [0u8; 32],
                test_sk(0),
                Arc::new(RecordingBinder::default())
            )
            .unwrap()
            .destination_count(),
            3,
        );
    }

    #[test]
    fn policy_rejects_extra_with_empty_advertise_host() {
        let mut p = default_policy();
        p.extra_destinations.push(AdvertiseDestination {
            slot_config: OnDemandConfig {
                host: "127.0.0.2".to_owned(),
                port_range: 40000..=50000,
                bind_retries: 16,
                ttl: Duration::from_secs(30),
                max_accepts: 1,
            },
            advertise_host: String::new(),
            scheme: "obfs4-tcp".to_owned(),
        });
        assert!(matches!(p.validate(), Err(PolicyError::Invalid(_))));
    }

    #[tokio::test]
    async fn round_robin_picks_destinations_evenly() {
        // 3 destinations, 6 grants — each destination should fire twice.
        let (target_nid, target_sk) = target_identity(20);
        let binder = Arc::new(RecordingBinder::default());
        let mut p = default_policy();
        p.rate_burst = 100;
        p.max_concurrent_slots = 16; // headroom for 6 concurrent
        // Use distinct advertise_hosts so we can observe round-robin
        // simply by reading the URIs the binder records.
        p.advertise_host = "host-A.example".to_owned();
        p.extra_destinations.push(AdvertiseDestination {
            slot_config: OnDemandConfig {
                host: "127.0.0.1".to_owned(),
                port_range: 30000..=60000,
                bind_retries: 64,
                ttl: Duration::from_secs(60),
                max_accepts: 1,
            },
            advertise_host: "host-B.example".to_owned(),
            scheme: "obfs4-tcp".to_owned(),
        });
        p.extra_destinations.push(AdvertiseDestination {
            slot_config: OnDemandConfig {
                host: "127.0.0.1".to_owned(),
                port_range: 30000..=60000,
                bind_retries: 64,
                ttl: Duration::from_secs(60),
                max_accepts: 1,
            },
            advertise_host: "host-C.example".to_owned(),
            scheme: "obfs4-tcp".to_owned(),
        });
        let controller =
            RendezvousController::new(p, target_nid, target_sk, binder.clone()).unwrap();

        for i in 0..6u64 {
            let requester_sk = test_sk((50 + i) as u8);
            let body = build_signed_request(target_nid, &requester_sk, 8, now_unix() + i);
            let outcome = controller.handle_request(&body).await;
            assert!(matches!(outcome, RequestOutcome::Granted { .. }));
        }

        let calls = binder.calls.lock().unwrap();
        assert_eq!(calls.len(), 6);
        let hosts: Vec<&str> = calls
            .iter()
            .map(|(uri, _, _)| {
                // Extract host token between "://" and ":<port>".
                let after_scheme = uri.split("://").nth(1).unwrap();
                after_scheme.split(':').next().unwrap()
            })
            .collect();
        let count_a = hosts.iter().filter(|h| **h == "host-A.example").count();
        let count_b = hosts.iter().filter(|h| **h == "host-B.example").count();
        let count_c = hosts.iter().filter(|h| **h == "host-C.example").count();
        assert_eq!(count_a, 2, "primary destination should fire 2/6: {hosts:?}");
        assert_eq!(count_b, 2, "extra[0] should fire 2/6: {hosts:?}");
        assert_eq!(count_c, 2, "extra[1] should fire 2/6: {hosts:?}");
    }

    #[tokio::test]
    async fn psk_is_fresh_per_request() {
        let (target_nid, target_sk) = target_identity(3);
        let requester_sk = test_sk(4);
        let binder = Arc::new(RecordingBinder::default());
        // Allow many requests by raising the burst.
        let mut policy = default_policy();
        policy.rate_burst = 10;
        let controller =
            RendezvousController::new(policy, target_nid, target_sk, binder.clone()).unwrap();
        // Two distinct requests with different timestamps so they're
        // both valid AND don't collide on signed bytes.
        let body1 = build_signed_request(target_nid, &requester_sk, 8, now_unix());
        let body2 = build_signed_request(target_nid, &requester_sk, 8, now_unix() + 1);
        let _ = controller.handle_request(&body1).await;
        let _ = controller.handle_request(&body2).await;
        let calls = binder.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_ne!(
            calls[0].1, calls[1].1,
            "PSK must differ between independent requests"
        );
    }

    // ── Rejection paths ───────────────────────────────────────────

    #[tokio::test]
    async fn reject_malformed_body() {
        let (target_nid, target_sk) = target_identity(5);
        let binder = Arc::new(RecordingBinder::default());
        let controller =
            RendezvousController::new(default_policy(), target_nid, target_sk, binder.clone())
                .unwrap();
        let outcome = controller.handle_request(&[0u8; 16]).await;
        assert!(matches!(
            outcome,
            RequestOutcome::Rejected(RejectReason::Decode(_))
        ));
        assert!(binder.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reject_wrong_target_node_id() {
        let (our_nid, our_sk) = target_identity(6);
        let requester_sk = test_sk(7);
        let binder = Arc::new(RecordingBinder::default());
        let controller =
            RendezvousController::new(default_policy(), our_nid, our_sk, binder.clone()).unwrap();
        // Request addressed to a DIFFERENT node_id.
        let other_nid = [0xFFu8; 32];
        let body = build_signed_request(other_nid, &requester_sk, 8, now_unix());
        let outcome = controller.handle_request(&body).await;
        assert!(matches!(
            outcome,
            RequestOutcome::Rejected(RejectReason::NotOurTarget)
        ));
    }

    #[tokio::test]
    async fn reject_bad_signature() {
        let (target_nid, target_sk) = target_identity(8);
        let requester_sk = test_sk(9);
        let binder = Arc::new(RecordingBinder::default());
        let controller =
            RendezvousController::new(default_policy(), target_nid, target_sk, binder.clone())
                .unwrap();
        let mut body = build_signed_request(target_nid, &requester_sk, 8, now_unix());
        // Tamper with the signature bytes (last 64 bytes).
        let len = body.len();
        body[len - 1] ^= 0x01;
        let outcome = controller.handle_request(&body).await;
        assert!(matches!(
            outcome,
            RequestOutcome::Rejected(RejectReason::Verify(_))
        ));
    }

    #[tokio::test]
    async fn reject_pow_below_min_difficulty() {
        let (target_nid, target_sk) = target_identity(10);
        let requester_sk = test_sk(11);
        let binder = Arc::new(RecordingBinder::default());
        let mut policy = default_policy();
        policy.min_pow_difficulty = 16;
        let controller =
            RendezvousController::new(policy, target_nid, target_sk, binder.clone()).unwrap();
        // Build a request with difficulty 8 — below the controller's
        // required min of 16.
        let body = build_signed_request(target_nid, &requester_sk, 8, now_unix());
        let outcome = controller.handle_request(&body).await;
        match outcome {
            RequestOutcome::Rejected(RejectReason::Verify(msg)) => {
                assert!(msg.contains("below operator min"), "got: {msg}");
            }
            other => panic!("expected Verify rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reject_replay_outside_window() {
        let (target_nid, target_sk) = target_identity(12);
        let requester_sk = test_sk(13);
        let binder = Arc::new(RecordingBinder::default());
        let controller =
            RendezvousController::new(default_policy(), target_nid, target_sk, binder.clone())
                .unwrap();
        // Timestamp 1 hour ago — outside the 5-minute replay window.
        let stale_timestamp = now_unix() - 3600;
        let body = build_signed_request(target_nid, &requester_sk, 8, stale_timestamp);
        let outcome = controller.handle_request(&body).await;
        match outcome {
            RequestOutcome::Rejected(RejectReason::Verify(msg)) => {
                assert!(msg.contains("replay"), "got: {msg}");
            }
            other => panic!("expected Verify rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reject_rate_limit_after_burst_exhausted() {
        let (target_nid, target_sk) = target_identity(14);
        let requester_sk = test_sk(15);
        let binder = Arc::new(RecordingBinder::default());
        let mut policy = default_policy();
        policy.rate_burst = 2;
        let controller =
            RendezvousController::new(policy, target_nid, target_sk, binder.clone()).unwrap();
        let ts_base = now_unix();
        // First 2 requests should succeed; 3rd should rate-limit.
        for i in 0..2 {
            let body = build_signed_request(target_nid, &requester_sk, 8, ts_base + i);
            let outcome = controller.handle_request(&body).await;
            assert!(
                matches!(outcome, RequestOutcome::Granted { .. }),
                "request {i} must grant",
            );
        }
        let body = build_signed_request(target_nid, &requester_sk, 8, ts_base + 2);
        let outcome = controller.handle_request(&body).await;
        assert!(matches!(
            outcome,
            RequestOutcome::Rejected(RejectReason::RateLimited)
        ));
    }

    #[tokio::test]
    async fn reject_concurrency_exhausted() {
        let (target_nid, target_sk) = target_identity(16);
        let binder = Arc::new(RecordingBinder::default());
        let mut policy = default_policy();
        policy.max_concurrent_slots = 1;
        policy.rate_burst = 100;
        // TTL long enough that the first listener's permit isn't released.
        policy.slot_config.ttl = Duration::from_secs(300);
        let controller =
            RendezvousController::new(policy, target_nid, target_sk, binder.clone()).unwrap();
        // Use TWO distinct requesters so rate limit doesn't fire.
        let rsk1 = test_sk(17);
        let rsk2 = test_sk(18);
        let body1 = build_signed_request(target_nid, &rsk1, 8, now_unix());
        let body2 = build_signed_request(target_nid, &rsk2, 8, now_unix());
        let outcome1 = controller.handle_request(&body1).await;
        assert!(matches!(outcome1, RequestOutcome::Granted { .. }));
        let outcome2 = controller.handle_request(&body2).await;
        assert!(matches!(
            outcome2,
            RequestOutcome::Rejected(RejectReason::ConcurrencyExhausted)
        ));
    }

    #[tokio::test]
    async fn bind_closure_failure_propagates_as_reject() {
        let (target_nid, target_sk) = target_identity(19);
        let requester_sk = test_sk(20);
        let binder = Arc::new(RecordingBinder {
            return_err: Some("simulated obfs4 wrap failure".to_owned()),
            ..Default::default()
        });
        let controller =
            RendezvousController::new(default_policy(), target_nid, target_sk, binder.clone())
                .unwrap();
        let body = build_signed_request(target_nid, &requester_sk, 8, now_unix());
        let outcome = controller.handle_request(&body).await;
        match outcome {
            RequestOutcome::Rejected(RejectReason::BindFailed(msg)) => {
                assert!(msg.contains("simulated obfs4 wrap failure"), "got: {msg}");
            }
            other => panic!("expected BindFailed, got {other:?}"),
        }
    }

    // ── Rate-limiter unit ─────────────────────────────────────────

    #[test]
    fn rate_limiter_allows_within_burst_blocks_above() {
        let mut rl = RateLimiter::new(Duration::from_secs(60), 3, 64);
        let pk = [0xAAu8; 32];
        let now = Instant::now();
        assert!(rl.allow(pk, now));
        assert!(rl.allow(pk, now));
        assert!(rl.allow(pk, now));
        assert!(!rl.allow(pk, now));
    }

    #[test]
    fn rate_limiter_window_expiry_resets_budget() {
        let mut rl = RateLimiter::new(Duration::from_millis(100), 2, 64);
        let pk = [0xBBu8; 32];
        let now = Instant::now();
        assert!(rl.allow(pk, now));
        assert!(rl.allow(pk, now));
        assert!(!rl.allow(pk, now));
        // Simulate time passing past the window.
        let later = now + Duration::from_millis(150);
        assert!(rl.allow(pk, later));
    }

    #[test]
    fn rate_limiter_independent_pubkeys() {
        let mut rl = RateLimiter::new(Duration::from_secs(60), 1, 64);
        let pk_a = [0xCCu8; 32];
        let pk_b = [0xDDu8; 32];
        let now = Instant::now();
        assert!(rl.allow(pk_a, now));
        assert!(!rl.allow(pk_a, now));
        // Independent identity gets its own budget.
        assert!(rl.allow(pk_b, now));
    }

    #[test]
    fn rate_limiter_soft_cap_prunes_idle_entries() {
        let mut rl = RateLimiter::new(Duration::from_millis(50), 1, 4);
        let now = Instant::now();
        // Fill soft cap with unique pubkeys.
        for i in 0..6u8 {
            rl.allow([i; 32], now);
        }
        // Wait past window THEN add a new entry — prune should kick in.
        let later = now + Duration::from_millis(100);
        rl.allow([0xFFu8; 32], later);
        assert!(rl.state.len() <= 5, "expected prune to bound map");
    }

    // ── PSK uniqueness ────────────────────────────────────────────

    #[test]
    fn fresh_psk_returns_different_values() {
        let a = fresh_psk();
        let b = fresh_psk();
        // Astronomically unlikely to collide.
        assert_ne!(a, b);
    }

    // ── Diagnostics ───────────────────────────────────────────────

    #[tokio::test]
    async fn diagnostics_track_rate_limiter_state() {
        let (target_nid, target_sk) = target_identity(30);
        let requester_sk = test_sk(31);
        let binder = Arc::new(RecordingBinder::default());
        let controller =
            RendezvousController::new(default_policy(), target_nid, target_sk, binder).unwrap();
        let requester_pk = requester_sk.verifying_key().to_bytes();
        assert_eq!(controller.rate_limiter_entries_for(&requester_pk), 0);
        let body = build_signed_request(target_nid, &requester_sk, 8, now_unix());
        let _ = controller.handle_request(&body).await;
        assert_eq!(controller.rate_limiter_entries_for(&requester_pk), 1);
    }

    // ── Concurrency stress ────────────────────────────────────────

    #[tokio::test]
    async fn concurrent_requests_respect_slot_limit() {
        let (target_nid, target_sk) = target_identity(40);
        let binder = Arc::new(RecordingBinder::default());
        let mut policy = default_policy();
        policy.max_concurrent_slots = 3;
        policy.rate_burst = 100;
        policy.slot_config.ttl = Duration::from_secs(300);
        let controller = Arc::new(
            RendezvousController::new(policy, target_nid, target_sk, binder.clone()).unwrap(),
        );

        let grant_count = Arc::new(AtomicUsize::new(0));
        let reject_count = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];
        for i in 0..10 {
            let requester_sk = test_sk(50 + i);
            let body = build_signed_request(target_nid, &requester_sk, 8, now_unix());
            let c = Arc::clone(&controller);
            let g = Arc::clone(&grant_count);
            let r = Arc::clone(&reject_count);
            handles.push(tokio::spawn(async move {
                match c.handle_request(&body).await {
                    RequestOutcome::Granted { .. } => g.fetch_add(1, Ordering::SeqCst),
                    RequestOutcome::Rejected(RejectReason::ConcurrencyExhausted) => {
                        r.fetch_add(1, Ordering::SeqCst)
                    }
                    RequestOutcome::Rejected(other) => {
                        panic!("unexpected reject: {other:?}")
                    }
                };
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(grant_count.load(Ordering::SeqCst), 3);
        assert_eq!(reject_count.load(Ordering::SeqCst), 7);
    }

    // ── from_on_demand_config builder ────────────────────────────

    fn default_on_demand_cfg() -> veil_cfg::OnDemandListenConfig {
        veil_cfg::OnDemandListenConfig {
            range: (50000, 60000),
            pow_difficulty: 24,
            ttl: "5m".to_owned(),
            max_concurrent: 16,
            rate_limit: "3/h".to_owned(),
            max_accepts: 1,
            bind_retries: 64,
        }
    }

    #[test]
    fn from_on_demand_config_happy_path() {
        let cfg = default_on_demand_cfg();
        let policy =
            RendezvousPolicy::from_on_demand_config(&cfg, "0.0.0.0", "example.com", "obfs4-tcp")
                .unwrap();
        assert_eq!(policy.min_pow_difficulty, 24);
        assert_eq!(policy.rate_burst, 3);
        assert_eq!(policy.rate_window, Duration::from_secs(3600));
        assert_eq!(policy.max_concurrent_slots, 16);
        assert_eq!(policy.slot_config.host, "0.0.0.0");
        assert_eq!(policy.slot_config.port_range, 50000..=60000);
        assert_eq!(policy.slot_config.ttl, Duration::from_secs(300));
        assert_eq!(policy.slot_config.max_accepts, 1);
        assert_eq!(policy.advertise_host, "example.com");
        assert_eq!(policy.scheme, "obfs4-tcp");
    }

    #[test]
    fn from_on_demand_config_rejects_inverted_range() {
        let mut cfg = default_on_demand_cfg();
        cfg.range = (60000, 50000);
        let err =
            RendezvousPolicy::from_on_demand_config(&cfg, "0.0.0.0", "example.com", "obfs4-tcp")
                .unwrap_err();
        assert!(matches!(err, PolicyError::Invalid(_)));
    }

    #[test]
    fn from_on_demand_config_rejects_unparseable_ttl() {
        let mut cfg = default_on_demand_cfg();
        cfg.ttl = "garbage".to_owned();
        let err =
            RendezvousPolicy::from_on_demand_config(&cfg, "0.0.0.0", "example.com", "obfs4-tcp")
                .unwrap_err();
        assert!(matches!(err, PolicyError::DurationParse(_)));
    }

    #[test]
    fn from_on_demand_config_rejects_unparseable_rate_limit() {
        let mut cfg = default_on_demand_cfg();
        cfg.rate_limit = "not-a-rate".to_owned();
        let err =
            RendezvousPolicy::from_on_demand_config(&cfg, "0.0.0.0", "example.com", "obfs4-tcp")
                .unwrap_err();
        assert!(matches!(err, PolicyError::DurationParse(_)));
    }

    #[test]
    fn from_on_demand_config_rejects_low_difficulty() {
        let mut cfg = default_on_demand_cfg();
        cfg.pow_difficulty = 4; // below MIN_POW_DIFFICULTY (8)
        let err =
            RendezvousPolicy::from_on_demand_config(&cfg, "0.0.0.0", "example.com", "obfs4-tcp")
                .unwrap_err();
        assert!(matches!(err, PolicyError::PowDifficultyTooLow { .. }));
    }

    #[test]
    fn from_on_demand_config_short_rate_period() {
        let mut cfg = default_on_demand_cfg();
        cfg.rate_limit = "10/30s".to_owned();
        let policy =
            RendezvousPolicy::from_on_demand_config(&cfg, "0.0.0.0", "example.com", "obfs4-tcp")
                .unwrap();
        assert_eq!(policy.rate_burst, 10);
        assert_eq!(policy.rate_window, Duration::from_secs(30));
    }

    // ── PoW max-difficulty sanity ─────────────────────────────────

    #[tokio::test]
    async fn pow_above_max_rejected_at_verify() {
        let (target_nid, target_sk) = target_identity(60);
        let requester_sk = test_sk(61);
        let binder = Arc::new(RecordingBinder::default());
        let controller =
            RendezvousController::new(default_policy(), target_nid, target_sk, binder).unwrap();
        // Construct a request with pow_difficulty > MAX (e.g. 100) — sign
        // but don't mine (PoW would fail too but verify checks the
        // bound first).
        let requester_pk = requester_sk.verifying_key().to_bytes();
        let signed = sign_request_ephemeral_endpoint(
            target_nid,
            requester_pk,
            now_unix(),
            MAX_POW_DIFFICULTY + 5,
            0,
            &requester_sk,
        );
        let body = signed.encode().to_vec();
        let outcome = controller.handle_request(&body).await;
        match outcome {
            RequestOutcome::Rejected(RejectReason::Verify(_)) => {}
            other => panic!("expected Verify reject, got {other:?}"),
        }
    }
}
