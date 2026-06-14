//! Benchmark: adversary-validation primitives.
//!
//! Three groups, all pure-CPU, no async, no network:
//!
//! 1. `pow` — `search_nonce` cost as a function of target difficulty.
//!    Feeds (enumeration cost amplification): an attacker
//!    enumerating the network has to pay this cost per handshake
//!    attempt, while a legitimate user pays it once at boot and
//!    caches the result.
//!
//! 2. `sig` — Ed25519 vs Falcon-512 sign+verify throughput.
//!    sovereign-record verify happens on every received signed
//!    record (relay-directory entry, name-claim, identity-document)
//!    so this is on the dispatcher hot path. Falcon-512 is the PQ
//!    baseline; cost difference informs migration planning.
//!
//! 3. `relay_directory` — full `verify_entry` over a real signed
//!    blob (decode + canonical-message rebuild + sig verify). Real
//!    composite cost an anonymity-layer sender pays per discovered
//!    relay candidate.
//!
//! Each group's measurement_time and sample_size is sized so total
//! runtime stays under ~30s while still producing enough samples for
//! tight CI ± 5% confidence intervals. Higher PoW difficulties skip
//! benchmarking when single-iteration cost would balloon total runtime
//! past the budget — they're calculated analytically from the lower
//! difficulties.

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use veil_crypto::{
    Base64Nonce, PowParams, generate_keypair, search_nonce, sign_message, verify_message,
};
use veil_types::SignatureAlgorithm;

// ── Group 1: PoW search ───────────────────────────────────────────────────────

fn bench_pow_search(c: &mut Criterion) {
    let kp = generate_keypair(SignatureAlgorithm::Ed25519);
    let pk = veil_crypto::Base64PublicKey::new(SignatureAlgorithm::Ed25519, kp.public_key.clone())
        .expect("valid pubkey");
    let sk =
        veil_crypto::Base64PrivateKey::new(SignatureAlgorithm::Ed25519, kp.private_key.clone())
            .expect("valid privkey");

    let mut g = c.benchmark_group("pow");
    g.measurement_time(Duration::from_secs(5));
    // Difficulty 12 / 14 / 16 — roughly 4 K / 16 K / 65 K average attempts.
    // 18 / 20 omitted: single-iteration cost (~250 ms / ~1 s) burns the
    // budget; the per-attempt cost scales as 2^bits so 18-bit cost ≈
    // 4 × 16-bit measured cost, 20-bit ≈ 16 ×. Operator can extrapolate.
    for difficulty in [12u32, 14, 16] {
        let id = BenchmarkId::new("search_nonce", format!("{difficulty}bit"));
        // Higher difficulty = lower sample rate so total bench time stays
        // bounded. 16-bit needs ~65 ms × 30 samples = ~2 s; 14-bit ~16 ms
        // × 30 = ~500 ms; 12-bit ~4 ms × 30 = ~120 ms.
        g.sample_size(30);
        g.throughput(Throughput::Elements(1));
        g.bench_with_input(id, &difficulty, |b, &d| {
            b.iter(|| {
                search_nonce(PowParams {
                    algo: SignatureAlgorithm::Ed25519,
                    public_key: pk.clone(),
                    private_key: sk.clone(),
                    target_zero_bits: d,
                    timeout: Duration::from_secs(120),
                    start_from: Base64Nonce::zero(),
                    threads: 1, // single-threaded — fair amplification factor for a per-attempt scanner
                    progress: None,
                })
            });
        });
    }
    g.finish();
}

// ── Group 2: Signature throughput ─────────────────────────────────────────────

fn bench_signatures(c: &mut Criterion) {
    let mut g = c.benchmark_group("sig");
    g.measurement_time(Duration::from_secs(3));
    g.throughput(Throughput::Elements(1));

    let message = b"veil-relay-directory:v1\0".repeat(4); // ~108 B, realistic signed-record size

    for algo in [SignatureAlgorithm::Ed25519, SignatureAlgorithm::Falcon512] {
        let kp = generate_keypair(algo);
        // Cache one signature for the verify benchmark — verify is the
        // hot path on dispatcher receive, sign happens once per publish.
        let sig = sign_message(algo, &kp.public_key, &kp.private_key, &message).expect("sign");

        let label = match algo {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::Falcon512 => "falcon512",
            SignatureAlgorithm::Ed25519Falcon512Hybrid => "ed25519+falcon512",
            SignatureAlgorithm::Ed25519Falcon1024Hybrid => "ed25519+falcon1024",
        };

        g.bench_function(BenchmarkId::new("sign", label), |b| {
            b.iter(|| sign_message(algo, &kp.public_key, &kp.private_key, &message).unwrap());
        });
        g.bench_function(BenchmarkId::new("verify", label), |b| {
            b.iter(|| verify_message(algo, &kp.public_key, &message, &sig).unwrap());
        });
    }
    g.finish();
}

// ── Group 3: Real relay-directory verify (composite) ──────────────────────────

fn bench_relay_directory_verify(c: &mut Criterion) {
    use veil_anonymity::directory::{decode_entry, sign_entry, verify_entry};

    let kp = generate_keypair(SignatureAlgorithm::Ed25519);
    // Realistic node_id: BLAKE3 of pubkey bytes (matches NodeId derivation).
    let pk_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &kp.public_key).unwrap();
    let node_id: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();
    let x25519_pk: [u8; 32] = [42u8; 32];

    let blob = sign_entry(
        node_id,
        x25519_pk,
        1_000_000, // 1 Mbit/s advertised
        1_000_000_000,
        &kp.public_key,
        &kp.private_key,
        SignatureAlgorithm::Ed25519,
    )
    .expect("sign relay directory entry");
    let entry = decode_entry(&blob).expect("decode just-signed entry");

    let mut g = c.benchmark_group("relay_directory");
    g.measurement_time(Duration::from_secs(3));
    g.throughput(Throughput::Elements(1));

    // decode-only: the cheap fast-path before verify_entry confirms.
    g.bench_function("decode_entry", |b| {
        b.iter(|| decode_entry(&blob).unwrap());
    });
    // verify_entry: dispatcher hot path on every discovered candidate.
    g.bench_function("verify_entry", |b| {
        b.iter(|| verify_entry(&entry).unwrap());
    });
    g.finish();
}

// ── Group 4: DHT walk cold/warm + LookupCache hit/miss ──

fn bench_dht_walk_and_cache(c: &mut Criterion) {
    use std::time::Duration;
    use veil_dht::lookup_cache::LookupCache;
    use veil_dht::routing::Contact;

    let mut g = c.benchmark_group("dht_walk_cache");
    g.measurement_time(Duration::from_secs(3));
    g.throughput(Throughput::Elements(1));

    // Pre-populate a cache with N entries; bench `get` (warm hit) vs
    // `get` on absent key (warm miss). Cold walk (full iterative
    // `find_node_iterative`) is already benchmarked by the existing
    // `dht_lookup` bench at the 10-node sim scale; here we measure the
    // cache delta — what an operator's capacity planning needs to know:
    // a cache hit is essentially a HashMap lookup vs a multi-RTT walk.
    let mut cache = LookupCache::with_defaults();
    let hot_key = [0xAAu8; 32];
    let contacts: Vec<Contact> = (0..20)
        .map(|i| {
            let mut nid = [0u8; 32];
            nid[0] = i as u8;
            Contact::new(nid, format!("tcp://127.0.0.1:{}", 9000 + i))
        })
        .collect();
    // Populate ~half the cache so eviction isn't constantly triggered.
    for i in 0..512 {
        let mut k = [0u8; 32];
        k[0..2].copy_from_slice(&(i as u16).to_be_bytes());
        cache.insert(k, contacts.clone());
    }
    cache.insert(hot_key, contacts.clone());

    g.bench_function("lookup_cache_get_hit", |b| {
        b.iter(|| {
            let _ = std::hint::black_box(cache.get(&std::hint::black_box(hot_key)));
        });
    });

    let cold_key = [0xFFu8; 32];
    g.bench_function("lookup_cache_get_miss", |b| {
        b.iter(|| {
            let _ = std::hint::black_box(cache.get(&std::hint::black_box(cold_key)));
        });
    });

    g.bench_function("lookup_cache_insert", |b| {
        // Insert into a fresh cache to avoid amortisation across
        // pre-populated state — measures the steady-state insert cost
        // with eviction when at capacity.
        let mut local_cache = LookupCache::with_defaults();
        for i in 0..512 {
            let mut k = [0u8; 32];
            k[0..2].copy_from_slice(&(i as u16).to_be_bytes());
            local_cache.insert(k, contacts.clone());
        }
        let mut counter: u32 = 1024;
        b.iter(|| {
            let mut k = [0u8; 32];
            k[0..4].copy_from_slice(&counter.to_be_bytes());
            counter = counter.wrapping_add(1);
            local_cache.insert(std::hint::black_box(k), contacts.clone());
        });
    });

    g.finish();
}

criterion_group!(
    benches,
    bench_pow_search,
    bench_signatures,
    bench_relay_directory_verify,
    bench_dht_walk_and_cache,
);
criterion_main!(benches);
