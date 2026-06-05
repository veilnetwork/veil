//! Integration tests moved from `veil_mesh::bridge` (
//! crate-extraction). Both wire concrete veilcore services
//! (`PerPeerLimiter`, `NodeMetrics`) into `GatewayBridge` via the
//! `BandwidthGuard` / `MeshMetrics` trait surfaces in veil-mesh.

use std::sync::Arc;

use veil_proto::{
    delivery::DeliveryEnvelope,
    mesh::{MeshFrame, RealmId},
    recipient::Recipient,
};
use veil_types::NodeRole;

use veil_mesh::{GatewayBridge, MeshMetrics};
use veil_node_runtime::mesh_glue::LeafBandwidthGuard;
use veil_observability::NodeMetrics;

const LIFT_SEEN_MAX_ENTRIES: usize = 4096;

fn sample_envelope() -> DeliveryEnvelope {
    DeliveryEnvelope {
        recipient: Recipient::any([2u8; 32]),
        sender_node_id: [0u8; 32],
        src_app_id: [0u8; 32],
        app_id: [3u8; 32],
        endpoint_id: 1,
        content_id: [4u8; 32],
        created_at: 1_000_000,
        ttl_secs: 60,
        payload: vec![0u8; 0],
        trace_id: 0,
        require_ack: false,
    }
}

fn mesh_frame_with_envelope(env: &DeliveryEnvelope) -> MeshFrame {
    MeshFrame::new(RealmId([0u8; 16]), [1u8; 32], [0u8; 32], 1, env.encode())
}

#[test]
fn lift_seen_cap_eviction_counter_increments() {
    let metrics = Arc::new(NodeMetrics::new());
    let metrics_dyn: Arc<dyn MeshMetrics> = Arc::clone(&metrics) as _;
    let bridge = GatewayBridge::new([10u8; 32], NodeRole::Core).with_metrics(Some(metrics_dyn));
    for i in 0..(LIFT_SEEN_MAX_ENTRIES + 10) {
        let mut env = sample_envelope();
        env.content_id[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let frame = mesh_frame_with_envelope(&env);
        bridge.lift(RealmId([0u8; 16]), &frame).unwrap();
    }
    let evictions = metrics.snapshot().gateway_lift_seen_evicted_total;
    assert!(
        evictions >= 10,
        "expected at least 10 evictions, got {evictions}"
    );
}

#[test]
fn epic478_5_per_leaf_bandwidth_quota_throttles_one_leaf_only() {
    // Re-run with a payload that fits in one bucket-fill but not two.
    let guard = Arc::new(LeafBandwidthGuard::from_kbps_burst(0.1, 1024.0));
    let bridge = GatewayBridge::new([10u8; 32], NodeRole::Core).with_leaf_bandwidth_quota(guard);

    let leaf_a = [0xAAu8; 32];
    let leaf_b = [0xBBu8; 32];
    let mut env = sample_envelope();
    env.payload = vec![0u8; 600];
    env.content_id[0] = 0x10;
    let mut a1 = mesh_frame_with_envelope(&env);
    a1.src_node_id = leaf_a;
    env.content_id[0] = 0x11;
    let mut a2 = mesh_frame_with_envelope(&env);
    a2.src_node_id = leaf_a;
    env.content_id[0] = 0x12;
    let mut b1 = mesh_frame_with_envelope(&env);
    b1.src_node_id = leaf_b;

    bridge.lift(RealmId([0u8; 16]), &a1).unwrap();
    bridge.lift(RealmId([0u8; 16]), &a2).unwrap();
    bridge.lift(RealmId([0u8; 16]), &b1).unwrap();
    let lifted = bridge.drain_lifted();

    assert_eq!(
        lifted.len(),
        2,
        "expected 2 lifts (a1 + b1); a2 must be quota-throttled. Got: {}",
        lifted.len()
    );
    let leaves: Vec<_> = lifted.iter().map(|l| l.src_node_id).collect();
    assert!(
        leaves.contains(&leaf_b),
        "leaf_b must NOT be affected by leaf_a's quota"
    );
    assert_eq!(
        leaves.iter().filter(|&&id| id == leaf_a).count(),
        1,
        "leaf_a's second frame must have been throttled"
    );
}
