//! Bench: pool acquire/release vs raw Vec::with_capacity/drop.
//!
//! Validates exit criterion: pool must be FASTER than malloc
//! under jemalloc. If this bench shows pool slower or equal, the
//! refactor has no per-op CPU benefit and we should reconsider.
//! Memory benefits would still apply, but the case becomes weaker.
//!
//! Run: `cargo bench -p veil-bufpool`

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use veil_bufpool::BufferPool;

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn bench_acquire_release(c: &mut Criterion) {
    let mut group = c.benchmark_group("60kb_roundtrip");

    // Baseline: raw malloc + free
    group.bench_function("malloc", |b| {
        b.iter(|| {
            let v: Vec<u8> = Vec::with_capacity(black_box(61440));
            black_box(&v);
            drop(v);
        });
    });

    // Pool with hot cache (warm-up first)
    let pool = BufferPool::default();
    // Prime cache: 10 acquire/release cycles.
    for _ in 0..10 {
        let _ = pool.acquire(61440);
    }
    group.bench_function("pool_hot", |b| {
        b.iter(|| {
            let buf = pool.acquire(black_box(61440));
            black_box(&buf);
            drop(buf);
        });
    });

    // Pool с cold cache (each iter drops to overflow, next acquires fallback)
    let cold_pool = BufferPool::with_capacity(1);
    group.bench_function("pool_cold_overflow", |b| {
        b.iter(|| {
            // 2 acquires fill+overflow cap=1, simulating burst > cache.
            let a = cold_pool.acquire(black_box(61440));
            let b2 = cold_pool.acquire(black_box(61440));
            black_box((&a, &b2));
            drop(b2);
            drop(a);
        });
    });

    group.finish();

    // Small-frame bench: 256 B (control plane size).
    let mut sg = c.benchmark_group("256b_roundtrip");
    sg.bench_function("malloc", |b| {
        b.iter(|| {
            let v: Vec<u8> = Vec::with_capacity(black_box(256));
            black_box(&v);
            drop(v);
        });
    });
    let pool_small = BufferPool::default();
    for _ in 0..10 {
        let _ = pool_small.acquire(256);
    }
    sg.bench_function("pool_hot", |b| {
        b.iter(|| {
            let buf = pool_small.acquire(black_box(256));
            black_box(&buf);
            drop(buf);
        });
    });
    sg.finish();

    // PooledShared fanout bench: 1 acquire → N clones → drop all.
    let mut fg = c.benchmark_group("shared_fanout_5way");
    let pool_share = BufferPool::default();
    for _ in 0..10 {
        let _ = pool_share.acquire(61440);
    }
    fg.bench_function("pool_hot", |b| {
        b.iter(|| {
            let shared = pool_share.acquire(black_box(61440)).into_shared();
            let clones: Vec<_> = (0..5).map(|_| shared.clone()).collect();
            drop(shared);
            black_box(&clones);
            drop(clones);
        });
    });
    // Equivalent с Arc<[u8]>
    fg.bench_function("arc_box", |b| {
        b.iter(|| {
            let v: Vec<u8> = Vec::with_capacity(black_box(61440));
            let arc: std::sync::Arc<[u8]> = v.into_boxed_slice().into();
            let clones: Vec<_> = (0..5).map(|_| arc.clone()).collect();
            drop(arc);
            black_box(&clones);
            drop(clones);
        });
    });
    fg.finish();
}

criterion_group!(benches, bench_acquire_release);
criterion_main!(benches);
