# Veil Network Architecture

> For an exhaustive, source-level walkthrough see [ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md).

## Layers

```
Application Layer     App ←→ IPC ←→ AppEndpointRegistry
                         ↓
Dispatch Layer        FrameDispatcher (family switch)
                      ├── Session    (Hello..SessionConfirm, Keepalive, Rekey, Ticket)
                      ├── Control    (Ping/Pong, NatProbe*, Backpressure, Epidemic)
                      ├── Discovery  (FindNode, FindValue, Store, Delete, Attachment)
                      ├── Delivery   (Forward, Mailbox, Transit, RecursiveRelay, Chunks)
                      ├── Routing    (RouteAnnounce/Withdraw, RouteRequest, PoW bootstrap)
                      ├── App        (AppOpen, AppData, AppRtData, AppReceipt)
                      ├── Mesh       (MeshBeacon, MeshForward, MeshAck)
                      ├── PeerExchange (Walk, Challenge, Response, Result)
                      ├── Tunnel     (IpPacket — TUN/TAP)
                      ├── RelayChain (onion hop)
                      └── Diag       (DiagPing/Pong, TraceProbe/Hop)
                         ↓
Session Layer         SessionRunner (AEAD encrypt/decrypt, WRR scheduling, rekey)
                         ↓
Transport Layer       TCP / TLS / QUIC / WebSocket (ws,wss) / Unix / SOCKS5
```

## Node Roles

| Role | DHT | Relay | Mailbox | Gateway | Use case |
|------|-----|-------|---------|---------|----------|
| Leaf | - | - | - | - | Mobile, IoT, lightweight clients |
| Core | yes (K=20) | yes | yes | yes (configurable) | Full network participant |

All Core nodes are equal: DHT, relay/forwarding, mailbox, PoW ≥ 24 bits.
Gateway functionality (attachment records for leaf nodes) is on when `CAN_GATEWAY_LOCAL_MESH`
flag is set in capabilities; configurable via `[gateway] enabled = false`.
Legacy roles `Relay / Gateway / CoreRouter` are not part of the protocol — the network has
exactly two roles.

## Data Flow: Message Delivery

```
Sender App
  → DELIVERY_FORWARD
    → Route cache hit?  ──yes──→ Forward to next_hop via SessionTxRegistry
    │                            → ... → Recipient App
    │
    └──no (cache miss)──→ RecursiveRelay via DHT
                           → find_closest_nodes(dst, 3)
                           → Forward to XOR-closest peer
                           → Each hop: live session to dst? → deliver
                           → Hop exhausted? → Mailbox fallback
```

## Routing

- **Gossip**: ROUTE_ANNOUNCE with TTL=2 (local neighbours only)
- **DHT forwarding**: RecursiveRelay O(log N) hops through Kademlia closest nodes
- **Route cache**: TTL-based, adaptive capacity, reverse path caching
- **Scoring**: RTT + Vivaldi + jitter + congestion + battery

## Security Layers

1. **Identity**: Ed25519 **or** Falcon-512 signing key + PoW mining (24+ bits, adaptive)
2. **Handshake**: X25519 + ML-KEM-768 hybrid key exchange
3. **Session**: ChaCha20-Poly1305 AEAD per-frame encryption (rekey at 128 GiB, 32 days, or nonce-counter wrap — configurable)
4. **E2E**: ML-KEM-768 encapsulation for relay-opaque payload (markers `0xE2`/`0xE3`)
5. **Abuse**: Per-IP session limit (32) → PoW challenge → rate limiter → violation tracker → ban list
6. **Reputation**: Uptime + relay success + peer vouches; transit gate 200 points
7. **DHT ownership**: Signed STORE; signed DELETE with BLAKE3(pk)==key

## Threading Model

- **Tokio runtime**: all async I/O, session management, periodic tasks
- **Shared state**: `Arc<Mutex<_>>` for caches, `Arc<AtomicU64>` for counters
- **No nested locks**: single-lock-at-a-time convention prevents deadlocks
- **Dispatcher**: sync dispatch on `FrameHeader` → `DispatchResult` (no async in hot path)

## Key Subsystems

| Subsystem | Module | Purpose |
|-----------|--------|---------|
| Kademlia DHT | `node/dht/` | Distributed hash table, iterative lookup, store/find |
| Mailbox | `node/mailbox/` | Offline message storage, WAL persistence, sharded replicas |
| Route Cache | `node/routing/` | Next-hop lookup, multi-path scoring, adaptive capacity |
| Session | `node/session/` | AEAD sessions, TX registry, WRR scheduling, hibernate |
| Discovery | `node/discovery/` | Attachment records, app endpoints, name service |
| Mesh | `node/mesh/` | UDP beacon, local discovery, gateway bridge |
| NAT | `node/nat/` | Hole punching, relay tunnels, observed address |
| Transport | `transport/` | TCP, TLS, QUIC, WebSocket, SOCKS5, fingerprint |
| Congestion | `node/congestion.rs` | Real-time load monitor, backpressure (>78% → drop transit) |
| Reputation | `node/reputation.rs` | Per-peer trust score, transit gate |
| Memory | `node/memory.rs` | Global RAM budget, priority-based eviction |
| Adaptive | `cfg/adaptive.rs` | Network size estimation, parameter scaling |
