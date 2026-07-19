//! Benchmark: RecursiveRelay dispatch through a chain of 20 dispatchers.
//!
//! Measures end-to-end latency of RecursiveRelayPayload decode + dispatch.
//! Target: < 1ms for 20 hop dispatches.

use criterion::{Criterion, criterion_group, criterion_main};
use veilcore::proto::{
    delivery::{DeliveryEnvelope, ForwardPayload, RecursiveRelayPayload},
    recipient::Recipient,
};

fn make_relay_frame(dst: [u8; 32], hop_count: u8) -> Vec<u8> {
    let envelope = DeliveryEnvelope {
        recipient: Recipient::any(dst),
        sender_node_id: [0xBBu8; 32],
        src_app_id: [0u8; 32],
        app_id: [0u8; 32],
        endpoint_id: 0,
        content_id: [0x42u8; 32],
        created_at: 0,
        ttl_secs: 3600,
        payload: vec![0u8; 64], // typical payload
        trace_id: 0,
        require_ack: false,
    };
    let fwd = ForwardPayload {
        next_hop_node_id: dst,
        envelope,
        relay_hops: 0,
        delivery_attempt: None,
        traffic_class: None,
    };
    let rr = RecursiveRelayPayload {
        dst_node_id: dst,
        originator_pseudonym: RecursiveRelayPayload::make_pseudonym(&[0xAAu8; 32], 1),
        query_id: 1,
        hop_count,
        payload: fwd.encode(),
    };
    rr.encode()
}

fn bench_relay_decode(c: &mut Criterion) {
    let body = make_relay_frame([0xDDu8; 32], 20);

    c.bench_function("recursive_relay_decode", |b| {
        b.iter(|| {
            let _ = RecursiveRelayPayload::decode(&body).unwrap();
        });
    });
}

fn bench_relay_decode_20x(c: &mut Criterion) {
    let body = make_relay_frame([0xDDu8; 32], 20);

    c.bench_function("recursive_relay_decode_20_hops", |b| {
        b.iter(|| {
            // Simulate 20 decode + re-encode cycles (what happens at each hop).
            let mut current = body.clone();
            for _ in 0..20 {
                let mut rr = RecursiveRelayPayload::decode(&current).unwrap();
                rr.hop_count = rr.hop_count.saturating_sub(1);
                current = rr.encode();
            }
        });
    });
}

criterion_group!(benches, bench_relay_decode, bench_relay_decode_20x);
criterion_main!(benches);
