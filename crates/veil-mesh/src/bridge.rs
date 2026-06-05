//! `GatewayBridge` — connects a local mesh realm to the global veil.
//!
//! A gateway node sits at the edge of a local realm. When a mesh frame arrives
//! from the realm that is addressed to a node *outside* the realm (or to a
//! special well-known gateway service), the `GatewayBridge` lifts the payload
//! into the veil as a `DeliveryEnvelope` and queues it in `lifted` for the
//! caller to drain and forward through the veil's `Forward` plane.
//!
//! Conversely, frames arriving on the veil plane that are destined for a
//! realm-local node are injected back into the realm via `MeshForwarder`.
//!
//! In this epic the bridge is purely in-process; real network I/O will be wired
//! in. removed the post-lift mailbox sink; the bridge
//! now produces `LiftedEnvelope`s without writing them to a service.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use veil_util::lock;

use crate::{BandwidthGuard, MeshMetrics};
use veil_proto::{
    delivery::DeliveryEnvelope,
    mesh::{MeshFrame, RealmId},
};
use veil_types::NodeRole;

/// How long a lifted content_id stays in the dedup set before it can be
/// lifted again. 30 seconds matches the ForwardSeenSet TTL.
const LIFT_DEDUP_TTL_SECS: u64 = 30;

/// hard cap on concurrent entries in `lift_seen`. Under flood
/// TTL-only eviction (30s) lets an attacker push arbitrarily many unique
/// content_ids through the gateway and bloat the HashMap. When the cap is
/// reached, evict the oldest entry by `Instant` — LRU by insertion time.
const LIFT_SEEN_MAX_ENTRIES: usize = 4096;

// ── BridgeError ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// Node role does not permit gateway bridging.
    NotGateway,
    /// Encoded envelope is too large for a MeshFrame payload (>= 65536 bytes).
    PayloadTooLarge,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::NotGateway => write!(f, "node role is not gateway"),
            BridgeError::PayloadTooLarge => write!(f, "envelope too large for mesh frame"),
        }
    }
}

// ── GatewayBridge ─────────────────────────────────────────────────────────────

/// Queued delivery record produced when the bridge lifts a mesh frame.
#[derive(Debug, Clone)]
pub struct LiftedEnvelope {
    pub realm_id: RealmId,
    pub src_node_id: [u8; 32],
    pub envelope: DeliveryEnvelope,
}

/// Bridges a local mesh realm to the veil's `Forward` plane.
///
/// Clone-cheap: inner state is `Arc<Mutex<_>>`.
#[derive(Clone)]
pub struct GatewayBridge {
    gateway_id: [u8; 32],
    role: NodeRole,
    /// Frames lifted out of the realm are queued here for the veil layer.
    lifted: Arc<Mutex<Vec<LiftedEnvelope>>>,
    /// Dedup set for content_ids recently lifted from mesh → veil.
    /// Prevents mesh↔veil routing loops.
    lift_seen: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    /// optional metrics handle so `lift_seen` cap-eviction
    /// events are countable (`gateway_lift_seen_evicted_total`). `None`
    /// in tests and when metrics are disabled.
    metrics: Option<Arc<dyn MeshMetrics>>,
    /// per-leaf bandwidth quota. Each leaf (`src_node_id` of
    /// the lifted frame) gets its own token bucket with capacity
    /// `default_burst_bytes` and refill `default_kbps × 1024`. Frames
    /// from leaves that have exhausted their bucket are silently dropped
    /// (return `Ok` without queuing) so a single greedy leaf cannot
    /// hog the gateway's outbound link. `None` disables enforcement
    /// (legacy / test paths).
    leaf_bandwidth: Option<Arc<dyn BandwidthGuard>>,
}

impl GatewayBridge {
    pub fn new(gateway_id: [u8; 32], role: NodeRole) -> Self {
        Self {
            gateway_id,
            role,
            lifted: Arc::new(Mutex::new(Vec::new())),
            lift_seen: Arc::new(Mutex::new(HashMap::new())),
            metrics: None,
            leaf_bandwidth: None,
        }
    }

    /// enable per-leaf bandwidth enforcement at the gateway.
    ///
    /// Each leaf (identified by `frame.src_node_id`) gets its own
    /// token bucket sized at `burst_bytes` and refilling at
    /// `kbps × 1024` bytes / second. Frames from leaves that exceed
    /// their quota are silently dropped at `lift` time.
    ///
    /// Default sizing (recommended for budget gateways):
    /// * `kbps` = 100 KiB/s ≈ 800 kbit/s — comfortable for
    ///   interactive messaging + small attachments, well below
    ///   residential uplink.
    /// * `burst_bytes` = 256 KiB — absorbs short burst (~2.5 s of
    ///   full-rate traffic) before throttling kicks in.
    ///
    /// `None` (= the default `new` behaviour) keeps backward-compatible
    /// "no enforcement" semantics for tests and legacy paths.
    ///
    /// extraction surface — accept any `BandwidthGuard` so
    /// veilcore can inject its concrete `PerPeerLimiter` without
    /// this crate reverse-importing `node::abuse`.
    pub fn with_leaf_bandwidth_quota(mut self, guard: Arc<dyn BandwidthGuard>) -> Self {
        self.leaf_bandwidth = Some(guard);
        self
    }

    /// chainable builder so production paths attach metrics
    /// without changing the bare `new` signature used by every existing
    /// test. Returns `self` for chaining after construction.
    ///
    /// takes `Arc<dyn MeshMetrics>` so veilcore's concrete
    /// `NodeMetrics` plugs in without reverse-coupling veil-mesh
    /// to the observability layer.
    pub fn with_metrics(mut self, metrics: Option<Arc<dyn MeshMetrics>>) -> Self {
        self.metrics = metrics;
        self
    }

    fn is_gateway(&self) -> bool {
        matches!(self.role, NodeRole::Core)
    }

    /// Lift a `MeshFrame` whose payload is a serialised `DeliveryEnvelope` into
    /// the veil plane.
    ///
    /// The envelope is queued in `lifted` for the caller to drain and forward
    /// through the veil's `Forward` plane.
    pub fn lift(&self, realm_id: RealmId, frame: &MeshFrame) -> Result<(), BridgeError> {
        if !self.is_gateway() {
            return Err(BridgeError::NotGateway);
        }
        // per-leaf bandwidth quota. Charge the source
        // leaf's bucket the encoded payload size BEFORE we do any
        // expensive decode / dedup / queueing work. Frames from a
        // leaf that has exhausted its quota are silently dropped — we
        // still return `Ok` so the caller's accounting matches
        // the loop-prevention dedup path (no error propagates from a
        // policy decision).
        if let Some(ref limiter) = self.leaf_bandwidth
            && !limiter.allow_bytes(frame.src_node_id, frame.payload.len())
        {
            return Ok(());
        }
        // Deserialise envelope from frame payload.
        match DeliveryEnvelope::decode(&frame.payload) {
            Ok((envelope, _)) => {
                // content_id dedup prevents mesh↔veil routing loops.
                // If this content_id was recently lifted, skip to break the cycle.
                {
                    let now = Instant::now();
                    let mut seen = lock!(self.lift_seen);
                    // Evict expired entries first (TTL-based).
                    seen.retain(|_, ts| now.duration_since(*ts).as_secs() < LIFT_DEDUP_TTL_SECS);
                    if seen.contains_key(&envelope.content_id) {
                        return Ok(());
                    }
                    // enforce hard cap — evict oldest-by-Instant
                    // if still at limit after TTL sweep. Bounded O(n) scan
                    // on the cap path (n ≤ LIFT_SEEN_MAX_ENTRIES), so cost
                    // only shows up once the dedup set is saturated.
                    if seen.len() >= LIFT_SEEN_MAX_ENTRIES
                        && let Some(oldest) = seen.iter().min_by_key(|(_, ts)| *ts).map(|(k, _)| *k)
                    {
                        seen.remove(&oldest);
                        // signal cap-saturation to ops.
                        if let Some(m) = &self.metrics {
                            m.inc_gateway_lift_seen_evicted();
                        }
                    }
                    seen.insert(envelope.content_id, now);
                }
                lock!(self.lifted).push(LiftedEnvelope {
                    realm_id,
                    src_node_id: frame.src_node_id,
                    envelope,
                });
            }
            Err(e) => {
                log::warn!(
                    "gateway_bridge.lift: envelope decode failed from src={}: {e}",
                    veil_util::bytes_to_hex(&frame.src_node_id),
                );
            }
        }
        Ok(())
    }

    /// Inject an veil `DeliveryEnvelope` into the realm by forwarding it as
    /// a `MeshFrame` toward the destination.
    ///
    /// Returns the `MeshFrame` that was produced (caller sends it via forwarder).
    pub fn inject(
        &self,
        realm_id: RealmId,
        envelope: &DeliveryEnvelope,
        ttl: u8,
    ) -> Result<MeshFrame, BridgeError> {
        if !self.is_gateway() {
            return Err(BridgeError::NotGateway);
        }
        let payload = envelope.encode();
        if payload.len() > u16::MAX as usize {
            return Err(BridgeError::PayloadTooLarge);
        }
        let frame = MeshFrame::new(
            realm_id,
            self.gateway_id,
            envelope.recipient_node_id(),
            ttl,
            payload,
        );
        Ok(frame)
    }

    /// Drain all lifted envelopes accumulated since last drain.
    pub fn drain_lifted(&self) -> Vec<LiftedEnvelope> {
        std::mem::take(&mut *lock!(self.lifted))
    }

    pub fn lifted_count(&self) -> usize {
        lock!(self.lifted).len()
    }

    pub fn gateway_id(&self) -> [u8; 32] {
        self.gateway_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::{
        delivery::DeliveryEnvelope,
        mesh::{MeshFrame, RealmId},
    };

    fn sample_envelope() -> DeliveryEnvelope {
        DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any([2u8; 32]),
            sender_node_id: [0u8; 32],
            src_app_id: [0u8; 32],
            app_id: [3u8; 32],
            endpoint_id: 1,
            content_id: [4u8; 32],
            created_at: 1_000_000,
            ttl_secs: 60,
            payload: b"hello".to_vec(),
            trace_id: 0,
            require_ack: false,
        }
    }

    fn mesh_frame_with_envelope(env: &DeliveryEnvelope) -> MeshFrame {
        MeshFrame::new(RealmId([0u8; 16]), [1u8; 32], [0u8; 32], 4, env.encode())
    }

    #[test]
    fn lift_queues_envelope() {
        let bridge = GatewayBridge::new([10u8; 32], NodeRole::Core);
        let env = sample_envelope();
        let frame = mesh_frame_with_envelope(&env);
        bridge.lift(RealmId([0u8; 16]), &frame).unwrap();
        let drained = bridge.drain_lifted();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].envelope.recipient_node_id(), [2u8; 32]);
    }

    #[test]
    fn leaf_cannot_lift() {
        let bridge = GatewayBridge::new([0u8; 32], NodeRole::Leaf);
        let env = sample_envelope();
        let frame = mesh_frame_with_envelope(&env);
        let err = bridge.lift(RealmId([0u8; 16]), &frame).unwrap_err();
        assert_eq!(err, BridgeError::NotGateway);
    }

    #[test]
    fn inject_produces_mesh_frame() {
        let bridge = GatewayBridge::new([10u8; 32], NodeRole::Core);
        let env = sample_envelope();
        let frame = bridge.inject(RealmId([1u8; 16]), &env, 5).unwrap();
        assert_eq!(frame.ttl, 5);
        assert_eq!(frame.dst_node_id, [2u8; 32]);
        assert_eq!(frame.src_node_id, [10u8; 32]);
        // Payload should round-trip back to the envelope
        let (decoded, _) = DeliveryEnvelope::decode(&frame.payload).unwrap();
        assert_eq!(decoded.recipient_node_id(), env.recipient_node_id());
    }

    #[test]
    fn leaf_cannot_inject() {
        let bridge = GatewayBridge::new([0u8; 32], NodeRole::Leaf);
        let err = bridge
            .inject(RealmId([0u8; 16]), &sample_envelope(), 4)
            .unwrap_err();
        assert_eq!(err, BridgeError::NotGateway);
    }

    #[test]
    fn drain_clears_queue() {
        let bridge = GatewayBridge::new([10u8; 32], NodeRole::Core);
        let env = sample_envelope();
        let frame = mesh_frame_with_envelope(&env);
        bridge.lift(RealmId([0u8; 16]), &frame).unwrap();
        let _ = bridge.drain_lifted();
        assert_eq!(bridge.lifted_count(), 0);
    }

    /// pushing more than `LIFT_SEEN_MAX_ENTRIES` unique
    /// content_ids within the TTL window must not grow the dedup set past
    /// the cap. Older entries are evicted by insertion-time order.
    #[test]
    fn lift_seen_respects_hard_cap() {
        let bridge = GatewayBridge::new([10u8; 32], NodeRole::Core);
        // Fire one extra past the cap; the set should stay at cap.
        for i in 0..(LIFT_SEEN_MAX_ENTRIES + 50) {
            let mut env = sample_envelope();
            // Unique content_id per iteration — use index as big-endian u64
            // prefix so dedup never hits within this test.
            let bytes = (i as u64).to_be_bytes();
            env.content_id[..8].copy_from_slice(&bytes);
            let frame = mesh_frame_with_envelope(&env);
            bridge.lift(RealmId([0u8; 16]), &frame).unwrap();
        }
        let seen_len = lock!(bridge.lift_seen).len();
        assert!(
            seen_len <= LIFT_SEEN_MAX_ENTRIES,
            "lift_seen grew past cap: {seen_len} > {LIFT_SEEN_MAX_ENTRIES}"
        );
    }

    // `lift_seen_cap_eviction_counter_increments` and
    // `epic478_5_per_leaf_bandwidth_quota_throttles_one_leaf_only` moved to
    // `veilcore/tests/mesh_bridge_integration.rs` because they wire the
    // concrete `NodeMetrics` / `PerPeerLimiter` instances that live in
    // veilcore.

    #[test]
    fn epic478_5_no_quota_configured_lifts_all_frames() {
        let bridge = GatewayBridge::new([10u8; 32], NodeRole::Core);
        for i in 0..5 {
            let mut env = sample_envelope();
            env.content_id[0] = i as u8;
            env.payload = vec![0u8; 100_000]; // 100 KiB each
            let frame = mesh_frame_with_envelope(&env);
            bridge.lift(RealmId([0u8; 16]), &frame).unwrap();
        }
        let lifted = bridge.drain_lifted();
        assert_eq!(lifted.len(), 5, "all 5 frames must lift when no quota");
    }
}
