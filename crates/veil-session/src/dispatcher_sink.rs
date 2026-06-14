//! `DispatcherSink` trait — abstraction barrier between session and
//! dispatcher concrete type.
//!
//! Phase 2 of `veilcore` extraction
//! (see [`docs/en/PLAN_VEILCORE_EXTRACTION.md`](../../../docs/en/PLAN_VEILCORE_EXTRACTION.md)):
//! before this slice, `SessionRunner` held `Arc<FrameDispatcher>` and
//! directly accessed dispatcher fields in 11 call sites.  That direct
//! field access prevented session code from moving to a sibling crate
//! (`veil-session`) — a sibling crate cannot reach `pub`
//! struct fields in `veilcore`, and making everything `pub` would
//! leak implementation details through the API surface.
//!
//! The `DispatcherSink` trait abstracts the 11 access points into
//! 9 typed methods.  `SessionRunner.dispatcher` field type swaps from
//! `Arc<FrameDispatcher>` to `Arc<dyn DispatcherSink>` — all session-
//! side code talks to the trait, never the concrete type.
//!
//! `FrameDispatcher` retains its concrete struct; the trait impl lives
//! in the same file (one block of `impl DispatcherSink for FrameDispatcher`).
//! Production behavior bit-identical to pre-slice code — every trait
//! method delegates to the previous field access.
//!
//! ## Dynamic-dispatch cost
//!
//! `Arc<dyn DispatcherSink>` imposes a ~5-10 ns vtable lookup per
//! trait method call.  Session loop does ~10 dispatcher calls per
//! frame at ~1000 frames/sec sustained — total overhead ~100 μs/sec,
//! negligible against the per-frame AEAD + I/O cost (~50-200 μs).
//! Profiled on Phase 1 baseline; trait abstraction does NOT measurably
//! affect session throughput.
//!
//! ## Future work (Phase 2 session 2)
//!
//! Once session is extracted to a sibling crate, two trait return
//! types still reference veilcore-local types:
//! * `rendezvous_weak()` returns `Weak<RendezvousController>` —
//!   `RendezvousController` is session-domain (PoW-rendezvous
//!   on-demand listener controller), should move to session crate.
//! * `dht()` returns `&Arc<KademliaService>` — DHT is a separate
//!   concern and stays in its own crate; trait method's return type
//!   gates session→dht direction (correct, not a cycle).

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock, Weak};

use tokio::sync::Semaphore;
use veil_observability::NodeLogger;

use crate::tx_registry::SessionTxRegistry;
use veil_proto::header::FrameHeader;
use veil_proto::routing::PowChallengePayload;
use veil_types::NodeIdBytes;

// ── DispatchResult ────────────────────────────────────────────────────────────

/// Result of dispatching one OVL1 frame.
///
/// Phase 2 session 2 prep: type moved here from
/// `crate::node::dispatcher::mod.rs` — it is the return type of the
/// `DispatcherSink::dispatch` trait method, and belongs alongside the
/// trait that uses it.  `dispatcher::mod.rs` re-exports for backwards
/// compat (`pub use crate::dispatcher_sink::DispatchResult`).
#[derive(Debug)]
pub enum DispatchResult {
    /// Caller should send these bytes back to the peer as a response frame.
    Response(Vec<u8>),
    /// Frame was handled; no response is required.
    NoResponse,
    /// Frame was rejected due to abuse (ban, bad payload, etc.).
    /// Caller should record a violation for the peer.
    Violation(String),
    /// Frame was dropped because the peer exceeded its rate limit.
    /// NOT a violation — the caller should send a backpressure signal
    /// and only escalate to a violation after repeated warnings are ignored.
    RateLimited,
    /// Frame family/type not handled by the dispatcher (e.g. session handshake).
    NotHandled,
    /// A PoW challenge was received for this node.  The runner must solve it
    /// asynchronously (CPU-bound) and send `PowResponse` back to the acceptor.
    SolvePow(PowChallengePayload),
    // cleanup: `AsyncResponse` variant removed. Originally
    // scaffolded for (quorum-replicated DHT writes wait for
    // replica ACKs before responding) — but deleted the mailbox
    // subsystem entirely, removing every potential constructor.  No future
    // home for this variant exists.  Re-introduce from git history (commit
    // 3cb2db6f) if a new "wait for multiple replicas" path materializes.
}

/// Abstraction barrier between session and dispatcher concrete type.
/// See module-doc.
pub trait DispatcherSink: Send + Sync {
    // ── Hot path (called every frame) ─────────────────────────────

    /// Dispatch an incoming frame body to the dispatcher's routing
    /// logic.  Returns the per-frame outcome (response bytes / no
    /// response / violation / etc.).
    fn dispatch(&self, header: &FrameHeader, body: &[u8], peer_id: NodeIdBytes) -> DispatchResult;

    /// Capture a plaintext outbound frame for debug-listener taps.
    /// No-op in production when no taps are attached.
    fn capture_outbound(&self, peer_id: NodeIdBytes, frame: &[u8]);

    /// Enforce outbound-bandwidth cap.  Returns `true` if `bytes`
    /// fits within the configured cap (and consumes the budget);
    /// `false` if the cap is exhausted (caller drops the frame).
    /// Wraps the `lock!(abuse.outbound_bandwidth).allow_bytes(...)`
    /// pattern previously inlined in session/runner.rs.
    fn allow_outbound_bandwidth(&self, bytes: usize) -> bool;

    /// Logger handle for diagnostic events.  Returned as `&Arc<...>`
    /// rather than cloned per-call to avoid a refcount bump on
    /// every event.
    fn logger(&self) -> &Arc<NodeLogger>;

    // ── Setup / rare-event accessors ──────────────────────────────

    /// Session-TX registry handle.  `None` for test fixtures that
    /// stand up a dispatcher without cross-session routing infrastructure.
    fn session_tx_registry(&self) -> Option<Arc<RwLock<SessionTxRegistry>>>;

    /// DHT service handle.  Used by session for transport-cache
    /// lookups during handoff.
    fn dht(&self) -> &Arc<veil_dht::KademliaService>;

    /// Rendezvous controller weak handle.  Session-domain wrapper
    /// around the on-demand-listener controller (PoW-Rendezvous epic).
    /// `Weak` prevents a refcount cycle between dispatcher and controller.
    fn rendezvous_weak(&self) -> Arc<Mutex<Option<Weak<crate::rendezvous::RendezvousController>>>>;

    /// PoW-solver concurrency semaphore.  Limits cluster-wide CPU
    /// budget for PoW challenge solving (anti-DoS).
    fn pow_solver_semaphore(&self) -> Arc<Semaphore>;

    /// Per-cluster active PoW difficulty (bits).  Atomic read so
    /// session can probe-then-acquire without a full mutex.
    fn pow_active_difficulty(&self) -> Arc<AtomicU64>;

    /// Routing cache handle.  Used by session for PoW-response fallback
    /// routing when the direct destination peer has no live session.
    fn route_cache(&self) -> Arc<RwLock<veil_routing::RouteCache>>;

    /// Register `session_alias → node_id` mappings.  Called by the
    /// session-alias RAII guard on session start.
    fn register_session_aliases(
        &self,
        local_alias: [u8; 8],
        local_node_id: NodeIdBytes,
        remote_alias: [u8; 8],
        remote_node_id: NodeIdBytes,
    );

    /// Unregister both aliases.  Called by the RAII guard's `Drop`.
    fn unregister_session_aliases(&self, local_alias: [u8; 8], remote_alias: [u8; 8]);
}

/// Helper: clone an `Arc<T>` where `T: DispatcherSink` and coerce it
/// to `Arc<dyn DispatcherSink>`.  The coercion happens at the function
/// return (a coercion site); call sites get a concise upcast without
/// inline type annotations.
pub fn arc_sink<T: DispatcherSink + 'static>(arc: &Arc<T>) -> Arc<dyn DispatcherSink> {
    let cloned: Arc<T> = Arc::clone(arc);
    cloned
}

// `impl DispatcherSink for FrameDispatcher` lives in veilcore — see
// `veilcore/src/node/dispatcher/sink_impl.rs`.  Orphan rule:
// FrameDispatcher is veilcore-local, DispatcherSink is veil-session-
// local; the impl can be in either crate where one of the types is local,
// and keeping it next to FrameDispatcher's definition is the natural fit
// (veilcore→veil-session dep is one-direction).
