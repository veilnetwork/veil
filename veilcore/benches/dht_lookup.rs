//! Benchmark: DHT iterative FIND_NODE lookup.
//!
//! Simulates a 10-node network entirely in-process via `LocalPeerQuerier`
//! and measures how many `find_node_iterative` calls complete per second.
//! Target: ≥ 100 concurrent lookups without performance regressions.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use veil_dht::{Contact, LocalPeerQuerier, RoutingTable, find_node_iterative};

const NUM_NODES: usize = 10;

fn build_querier() -> (LocalPeerQuerier, Vec<Contact>) {
    let querier = LocalPeerQuerier::new();
    let mut seeds = Vec::new();

    for i in 0..NUM_NODES {
        let mut node_id = [0u8; 32];
        node_id[0] = i as u8;

        // Each node's routing table knows all other nodes.
        let mut rt = RoutingTable::new(node_id);
        for j in 0..NUM_NODES {
            if j == i {
                continue;
            }
            let mut nid = [0u8; 32];
            nid[0] = j as u8;
            rt.insert(Contact::new(nid, format!("tcp://127.0.0.1:{}", 9000 + j)));
        }
        querier.add_node(node_id, rt);
        seeds.push(Contact::new(
            node_id,
            format!("tcp://127.0.0.1:{}", 9000 + i),
        ));
    }

    (querier, seeds)
}

fn bench_dht_lookup(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (querier, seeds) = build_querier();

    let mut g = c.benchmark_group("dht");
    g.throughput(Throughput::Elements(1));

    g.bench_function("find_node_iterative_10nodes", |b| {
        let target = [0xAAu8; 32];
        b.to_async(&rt).iter(|| async {
            find_node_iterative(
                target,
                seeds.clone(),
                &querier,
                &veil_dht::IterativeParams::default(),
            )
            .await
        });
    });

    g.finish();
}

criterion_group!(benches, bench_dht_lookup);
criterion_main!(benches);
