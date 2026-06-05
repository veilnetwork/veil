# Capacity Planning

## Per-Node Resource Estimates

Given total network size **N**:

| Resource | Formula | N=10K | N=1M | N=10M | N=1B | N=10B |
|----------|---------|-------|------|-------|------|-------|
| **K** (bucket size) | `max(20, ceil(log2(N)))` | 20 | 20 | 24 | 30 | 34 |
| **Route cache** | `clamp(N/100, 1K, 1M)` entries | 1K | 10K | 100K | 1M | 1M |
| **DHT store** | up to `max_store_entries` (default 25K in RAM; dedicated DHT seeds opt up to 250K, ~4GB worst-case; lift further to disk via the RocksDB cold tier) | 1K | 25K | 200K¹ | 1M¹ | 1M¹ |
| **Sessions** | up to 65K per node | ~20 | ~200 | ~1K | ~5K | ~10K |
| **RAM** | base 50MB + caches | 60MB | 100MB | 200MB | 400MB | 512MB |
| **Bandwidth** | K × announce_rate + forwarding | 1 Kbps | 10 Kbps | 50 Kbps | 200 Kbps | 500 Kbps |

¹ The in-memory entry ceiling is `max_store_entries` (default 25K, max documented in-RAM 250K). Per-node DHT capacities above ~250K (200K¹/1M¹ shown above) are only achievable via the disk-backed RocksDB cold tier (`[dht] cold_store_path`, cargo feature `rocksdb-cold`, on by default for veil-cli); cold entries spill to disk instead of RAM.

## Core Node Requirements

All Core nodes use K=20 by default (classical Kademlia constant). Adaptive scaling raises it for very large networks as per the `K` formula above.

| Network Size | Min Core Nodes | RAM per Node | Bandwidth per Node |
|-------------|---------------|-------------|-------------------|
| 10K | 3-5 | 256MB | 10 Mbps |
| 100K | 10-20 | 512MB | 50 Mbps |
| 1M | 50-100 | 1GB | 100 Mbps |
| 10M | 500-1,000 | 2GB | 200 Mbps |
| 100M | 5,000-10,000 | 4GB | 500 Mbps |

## Lookup Latency

| Network Size | Hops (O(log_K(N))) | Estimated RTT (50ms/hop) |
|-------------|-------------------|--------------------------|
| 10K | 3 | 150ms |
| 1M | 5 | 250ms |
| 10M | 6 | 300ms |
| 1B | 7 | 350ms |
| 10B | 8 | 400ms |

## Gossip Bandwidth (TTL=2)

With `max_gossip_hops = 2`, each node only receives announcements from direct neighbours:
- **Per-node gossip**: `sessions × announce_size × announce_rate`
- **Typical**: 100 sessions × 200B × 1/30s = **667 B/s** (negligible)

## PoW Difficulty

| Network Size | Difficulty | Mining Time (CPU) | Mining Time (GPU) |
|-------------|-----------|-------------------|-------------------|
| 100K | 24 bits | ~0.3s | ~0.01s |
| 1M | 28 bits | ~5s | ~0.1s |
| 10M | 31 bits | ~40s | ~1s |
| 1B | 38 bits | ~5 hours | ~10 min |
| 10B | 41 bits | ~40 hours | ~80 min |

## Memory Budget Breakdown (256MB default)

| Component | Weight | Typical Usage | Max Usage |
|-----------|--------|--------------|-----------|
| Sessions | highest priority | 65K × 256 × 256B = 4GB (capped by eviction) | Budget-managed |
| Route Cache | high | 100K × 200B = 20MB | 200MB |
| DHT Store | medium | 250K × 16KiB ≈ 4GB worst-case (hot tier = 25% in RAM, cold tier = 75% on disk via RocksDB `cold_store_path`) | Budget-managed |
| Pubkey Cache | low | 65K × 80B = 5MB | 10MB |
| Vivaldi | lowest priority (evicted first) | 65K × 48B = 3MB | 5MB |
