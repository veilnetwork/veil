//! Benchmark: / hybrid key derivation.
//!
//! Measures the per-handshake cost premium of the hybrid
//! Ed25519+Falcon-style session-key derivation versus the classical
//! X25519-only path, plus the contribution of each composite step
//! (ML-KEM-768 encapsulate, ML-KEM-768 decapsulate, hybrid HKDF).
//!
//! Four groups:
//!
//! 1. `kex_kdf` — classical `derive_session_keys` vs hybrid
//!    `derive_hybrid_session_keys`. Both inputs are pre-computed
//!    shared secrets; this isolates the HKDF-Extract+Expand cost
//!    from the underlying KEM/DH operations. Difference is the
//!    pure-key-schedule overhead a session pays at handshake time.
//!
//! 2. `mlkem_kem` — `mlkem_encapsulate_raw` (sender side) и
//!    `mlkem_decapsulate_raw` (receiver side) на ML-KEM-768. These
//!    are the dominant CPU cost of the hybrid path и land на ONE
//!    side of the handshake each.
//!
//! 3. `mlkem_kem_prepared` — same operations BUT через the
//!    `PreparedEncapsulator` / `PreparedDecapsulator` cache types
//!    что parse the EK / DK seed once и reuse it across calls.
//!    Quantifies how much of group 2's cost is pure parse overhead
//!    vs actual cryptographic work. Relevant для re-keying flows
//!    (mid-session forward-secrecy rotation) where the same peer
//!    gets encap'd / decap'd repeatedly.
//!
//! 4. `kex_full` — end-to-end "what one party computes at handshake
//!    time" for both the classical X25519-only path и the hybrid
//!    path. Hybrid sender-side = encapsulate + HKDF;
//!    hybrid receiver-side = decapsulate + HKDF. The classical
//!    path is the X25519 shared-secret + HKDF. Numbers feed
//!    deployment planning ("how much time does enabling
//!    hybrid kex cost on the dispatcher hot path").
//!
//! All benchmarks are pure-CPU, no async, no network.

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use veil_crypto::session_kdf::{derive_hybrid_session_keys, derive_session_keys};
use veil_crypto::x3dh::{
    PreparedDecapsulator, PreparedEncapsulator, generate_prekey, mlkem_decapsulate_raw,
    mlkem_encapsulate_raw,
};

const LOCAL_NODE_ID: [u8; 32] = [0x11u8; 32];
const REMOTE_NODE_ID: [u8; 32] = [0x22u8; 32];

fn bench_kex_kdf(c: &mut Criterion) {
    let mut g = c.benchmark_group("kex_kdf");
    g.measurement_time(Duration::from_secs(5));

    let x25519_secret = [0xAAu8; 32];
    let mlkem_secret = vec![0xBBu8; 32];

    g.bench_function(BenchmarkId::new("classical", "x25519-only"), |b| {
        b.iter(|| derive_session_keys(&x25519_secret, &LOCAL_NODE_ID, &REMOTE_NODE_ID));
    });
    g.bench_function(BenchmarkId::new("hybrid", "x25519+mlkem"), |b| {
        b.iter(|| {
            derive_hybrid_session_keys(
                &x25519_secret,
                &mlkem_secret,
                &LOCAL_NODE_ID,
                &REMOTE_NODE_ID,
            )
        });
    });
    g.finish();
}

fn bench_mlkem_kem(c: &mut Criterion) {
    let mut g = c.benchmark_group("mlkem_kem");
    g.measurement_time(Duration::from_secs(5));

    let (ek, dk_seed) = generate_prekey();
    g.bench_function(BenchmarkId::new("mlkem768", "encapsulate"), |b| {
        b.iter(|| mlkem_encapsulate_raw(&ek).expect("encap"));
    });
    let (ct, _ss) = mlkem_encapsulate_raw(&ek).expect("seed CT");
    g.bench_function(BenchmarkId::new("mlkem768", "decapsulate"), |b| {
        b.iter(|| mlkem_decapsulate_raw(&dk_seed, &ct).expect("decap"));
    });
    g.finish();
}

/// perf: prepared / cached path. Builds the
/// `PreparedEncapsulator` / `PreparedDecapsulator` ONCE outside the
/// benchmarked closure, then runs encap / decap repeatedly against
/// the cache. Speedup over `mlkem_kem` group quantifies how much of
/// the per-call cost was pure parse overhead (EK validation для
/// encap; full DK seed-expansion для decap, matching the cost of
/// keygen-from-seed).
fn bench_mlkem_kem_prepared(c: &mut Criterion) {
    let mut g = c.benchmark_group("mlkem_kem_prepared");
    g.measurement_time(Duration::from_secs(5));

    let (ek, dk_seed) = generate_prekey();
    let prepared_ek = PreparedEncapsulator::from_bytes(&ek).expect("prepare ek");
    g.bench_function(BenchmarkId::new("mlkem768", "encapsulate"), |b| {
        b.iter(|| prepared_ek.encapsulate());
    });

    let prepared_dk = PreparedDecapsulator::from_seed(&dk_seed).expect("prepare dk");
    let (ct, _ss) = mlkem_encapsulate_raw(&ek).expect("seed CT");
    g.bench_function(BenchmarkId::new("mlkem768", "decapsulate"), |b| {
        b.iter(|| prepared_dk.decapsulate(&ct).expect("decap"));
    });

    // Cost of the parse step alone — `from_bytes` / `from_seed` are
    // what the prepared path amortises. Useful для operators
    // estimating "should I pay the per-session prepare cost OR per-call
    // raw cost".
    g.bench_function(BenchmarkId::new("mlkem768", "prepare_ek"), |b| {
        b.iter(|| PreparedEncapsulator::from_bytes(&ek).expect("prepare"));
    });
    g.bench_function(BenchmarkId::new("mlkem768", "prepare_dk_seed"), |b| {
        b.iter(|| PreparedDecapsulator::from_seed(&dk_seed).expect("prepare"));
    });

    g.finish();
}

fn bench_kex_full(c: &mut Criterion) {
    let mut g = c.benchmark_group("kex_full");
    g.measurement_time(Duration::from_secs(5));

    let x25519_secret = [0xAAu8; 32];
    let (ek, dk_seed) = generate_prekey();

    g.bench_function(BenchmarkId::new("classical", "x25519+hkdf"), |b| {
        b.iter(|| derive_session_keys(&x25519_secret, &LOCAL_NODE_ID, &REMOTE_NODE_ID));
    });

    g.bench_function(BenchmarkId::new("hybrid_sender", "encap+hkdf"), |b| {
        b.iter(|| {
            let (_ct, ss) = mlkem_encapsulate_raw(&ek).expect("encap");
            derive_hybrid_session_keys(&x25519_secret, &ss, &LOCAL_NODE_ID, &REMOTE_NODE_ID)
        });
    });

    let (ct, _ss) = mlkem_encapsulate_raw(&ek).expect("seed CT");
    g.bench_function(BenchmarkId::new("hybrid_receiver", "decap+hkdf"), |b| {
        b.iter(|| {
            let ss = mlkem_decapsulate_raw(&dk_seed, &ct).expect("decap");
            derive_hybrid_session_keys(&x25519_secret, &ss, &LOCAL_NODE_ID, &REMOTE_NODE_ID)
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_kex_kdf,
    bench_mlkem_kem,
    bench_mlkem_kem_prepared,
    bench_kex_full,
);
criterion_main!(benches);
