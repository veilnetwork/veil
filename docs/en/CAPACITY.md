# Capacity Planning

This page helps you size a node and plan for growth. The tables below scale
everything off one number: **N**, the total number of nodes in the network. Pick
the column closest to the network you expect, and read down.

A few terms show up throughout. **DHT** is the network's shared address book — a
distributed directory that maps a node's address to where it can be reached right
now; no single node holds all of it, so each one stores a slice. **K** is the
Kademlia bucket size: how many peers a node keeps on hand for each "distance" from
itself. A bigger **K** means more contacts to remember, but faster, more reliable
lookups.

## Per-Node Resource Estimates

These are the resources a single node needs, given a total network size of **N**:

| Resource | Formula | N=10K | N=1M | N=10M | N=1B | N=10B |
|----------|---------|-------|------|-------|------|-------|
| **K** (bucket size) | `max(20, ceil(log2(N)))` | 20 | 20 | 24 | 30 | 34 |
| **Route cache** | `clamp(N/100, 1K, 1M)` entries | 1K | 10K | 100K | 1M | 1M |
| **DHT store** | up to `max_store_entries` (default 25K, held in RAM; dedicated DHT seed nodes can raise this to 250K, ~4GB worst-case; to go higher, spill to disk via the RocksDB cold tier) | 1K | 25K | 200K¹ | 1M¹ | 1M¹ |
| **Sessions** | up to 65K per node | ~20 | ~200 | ~1K | ~5K | ~10K |
| **RAM** | base 50MB + caches | 60MB | 100MB | 200MB | 400MB | 512MB |
| **Bandwidth** | K × announce_rate + forwarding | 1 Kbps | 10 Kbps | 50 Kbps | 200 Kbps | 500 Kbps |

¹ The in-memory ceiling is `max_store_entries` (default 25K, documented max in RAM 250K). To go past ~250K per node (the 200K¹/1M¹ figures above), you need the disk-backed RocksDB cold tier: set `[dht] cold_store_path` and build with the `rocksdb-cold` cargo feature, which is on by default for veil-cli. Cold entries live on disk rather than in RAM, so they don't count against memory.

## Core Node Requirements

Core nodes are the always-on, publicly reachable nodes that hold the network
together. By default they run with K=20, the classic Kademlia constant. On very
large networks, adaptive scaling raises K automatically, following the `K` formula
above.

| Network Size | Min Core Nodes | RAM per Node | Bandwidth per Node |
|-------------|---------------|-------------|-------------------|
| 10K | 3-5 | 256MB | 10 Mbps |
| 100K | 10-20 | 512MB | 50 Mbps |
| 1M | 50-100 | 1GB | 100 Mbps |
| 10M | 500-1,000 | 2GB | 200 Mbps |
| 100M | 5,000-10,000 | 4GB | 500 Mbps |

## Lookup Latency

Latency is the delay before a lookup returns an answer. A *hop* is one
node-to-node step, and *RTT* is the round-trip time for a single hop. Because the
DHT is structured like Kademlia, the number of hops grows only with the logarithm
of N — so even a billion-node network is just a handful of hops away. The estimates
below assume 50ms per hop.

| Network Size | Hops (O(log_K(N))) | Estimated RTT (50ms/hop) |
|-------------|-------------------|--------------------------|
| 10K | 3 | 150ms |
| 1M | 5 | 250ms |
| 10M | 6 | 300ms |
| 1B | 7 | 350ms |
| 10B | 8 | 400ms |

## Gossip Bandwidth (TTL=2)

Nodes gossip — they periodically announce themselves to neighbours, who pass the
news a little further. *TTL* (time-to-live) caps how far an announcement travels.
With `max_gossip_hops = 2`, an announcement reaches only direct neighbours, so the
bandwidth cost stays tiny:

- **Per-node gossip**: `sessions × announce_size × announce_rate`
- **Typical**: 100 sessions × 200B × 1/30s = **667 B/s** (negligible)

## PoW Difficulty

*Proof of Work* (PoW) is the small math puzzle a node solves to mint an identity.
It costs a bit of compute, which keeps honest sign-ups cheap while making it
expensive to churn out fake identities in bulk. The difficulty rises with network
size; the times below show how long that puzzle takes on a CPU versus a GPU.

| Network Size | Difficulty | Mining Time (CPU) | Mining Time (GPU) |
|-------------|-----------|-------------------|-------------------|
| 100K | 24 bits | ~0.3s | ~0.01s |
| 1M | 28 bits | ~5s | ~0.1s |
| 10M | 31 bits | ~40s | ~1s |
| 1B | 38 bits | ~5 hours | ~10 min |
| 10B | 41 bits | ~40 hours | ~80 min |

## Memory Budget Breakdown (256MB default)

A node works within a fixed memory budget — 256MB by default. Each component gets
a priority. When memory runs short, the node *evicts* (drops) data from the
lowest-priority components first, so the most important state survives. "Typical
Usage" is what you'd expect day to day; the larger figures are worst-case totals
that the budget caps in practice, shown here as "Budget-managed".

| Component | Priority | Typical Usage | Max Usage |
|-----------|--------|--------------|-----------|
| Sessions | highest | 65K × 256 × 256B = 4GB (capped by eviction) | Budget-managed |
| Route Cache | high | 100K × 200B = 20MB | 200MB |
| DHT Store | medium | 250K × 16KiB ≈ 4GB worst-case (hot tier = 25% in RAM, cold tier = 75% on disk via RocksDB `cold_store_path`) | Budget-managed |
| Pubkey Cache | low | 65K × 80B = 5MB | 10MB |
| Vivaldi | lowest (evicted first) | 65K × 48B = 3MB | 5MB |
