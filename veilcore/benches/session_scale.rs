//! Benchmark: SessionTxRegistry at 65K sessions.
//!
//! Measures `send_to` latency and memory overhead with a large number of
//! registered sessions. Target: p99 < 100μs for send_to at 65K sessions.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use veil_session::tx_registry::SessionTxRegistry;

fn bench_send_to_at_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_send_to");

    for &count in &[1_000, 10_000, 65_000] {
        let mut registry = SessionTxRegistry::with_capacity(256);
        let mut receivers = Vec::with_capacity(count);
        for i in 0..count {
            let mut peer_id = [0u8; 32];
            peer_id[..4].copy_from_slice(&(i as u32).to_be_bytes());
            receivers.push((peer_id, registry.register(peer_id)));
        }

        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            let mut idx = 0u32;
            b.iter(|| {
                let mut peer_id = [0u8; 32];
                peer_id[..4].copy_from_slice(&(idx % count as u32).to_be_bytes());
                let frame = vec![0u8; 128]; // typical small frame
                registry.send_to(&peer_id, 1, frame);
                idx = idx.wrapping_add(1);
            });
        });

        // Drain receivers to prevent channel backpressure.
        for (_, mut rx) in receivers {
            while rx.try_recv().is_ok() {}
        }
    }
    group.finish();
}

fn bench_register_unregister(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_register");

    group.bench_function("register_65k", |b| {
        b.iter(|| {
            let mut registry = SessionTxRegistry::with_capacity(64);
            for i in 0..65_000u32 {
                let mut peer_id = [0u8; 32];
                peer_id[..4].copy_from_slice(&i.to_be_bytes());
                let _ = registry.register(peer_id);
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_send_to_at_scale, bench_register_unregister);
criterion_main!(benches);
