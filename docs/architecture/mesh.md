# Mesh subsystem (Epic 478 audit)

> **Audit date:** 2026-04-26 · **Code state:** master @ 956ca8c (post Epic 477)

## TL;DR

The mesh subsystem already covers the **M leaf-nodes ↔ N gateway-nodes** use case
that Epic 478 plans for: Local-realm peers discover each other via signed UDP beacons,
forward `MeshFrame`s through `MeshForwarder` (Core relays only, TTL-bounded, dedup'd),
and a `GatewayBridge` lifts realm-local frames into the global veil (and injects
veil frames back into the realm).  Auto-discovery + auto-connect to up to N
gateways already runs.

**Gaps to close in Epic 478:**

1. Sub-second failover when active gateway dies (currently ~5 s poll).
2. Gateway selection by latency + battery (currently FIFO of `live_gateways()`).
3. Per-leaf bandwidth quota at gateway (only session-level FPS limiter today).
4. BLE / Wi-Fi Direct transport adapters (only UDP + in-memory loopback today).
5. User-facing diagnostics ("you're connected via gateway X, battery 90 %, latency 12 ms").

The 2-hop forward chain (M → relay-Core → gateway → target) is **already supported**
by `MeshForwarder::forward_with_cache` — multi-hop path through Core nodes works
inside the realm; the gateway is then the egress.  No code change needed for that
sub-task; sim test will assert it.

---

## Components

### Wire types ([`proto/mesh.rs`](../../crates/veil-proto/src/mesh.rs))

- **`RealmId([u8; 16])`** — 128-bit opaque realm scope.  Special wildcard
  `BROADCAST = [0xFF; 16]`.  `MeshForwarder::with_realm_id(...)` enforces realm
  isolation (cross-realm frames silently dropped — Epic 243).
- **`MeshFrame { realm_id, src_node_id, dst_node_id, ttl, payload }`** — 83-byte
  header + variable payload.  `dst = [0xFF; 32]` = realm broadcast.  Payload is
  `Arc<[u8]>` so `clone()` (per-hop) is refcount, not copy — broadcast fan-out
  doesn't reallocate per neighbour.
- **`MeshBeaconPayload { node_id, realm_id, role_flags, veil_addr,
  battery_level, algo, public_key, signature }`** — periodic neighbour discovery.
  Receiver verifies `BLAKE3(public_key) == node_id` AND signature over the
  unsigned body (Epic 406.5).  Bit flags: `IS_GATEWAY = 0x01`,
  `HAS_INTERNET = 0x02`, `IS_RELAY = 0x04`.
- **`MeshAckPayload { status }`** — OK / NoRoute / TtlExpired.

### Forwarder ([`node/mesh/forwarder.rs`](../../crates/veil-mesh/src/forwarder.rs))

`MeshForwarder { local_id, role, neighbors: Arc<dyn MeshNeighborProvider>,
local_realm_id, broadcast_seen }`

- Only `Core` nodes forward transit (`Leaf` returns `NotRelay`).
- TTL = 0 → drop.
- src spoofing detection: drop frame whose `src_node_id == self.local_id`.
- Realm isolation: drop if `frame.realm_id != local_realm_id`.
- Unicast: lookup `link_to(dst)` → send.
- Broadcast: dedup via `BroadcastSeenSet` (4096-cap, 10 s TTL), then fan-out
  to every neighbour (skip self, skip dup).
- `forward_with_cache(frame, route_cache)`: prefer-local ordering —
  (1) direct local-mesh link → (2) `RouteCache` next-hop hint (veil relay)
  → (3) plain `forward()` fallback.  Implements Epic 68.4 prefer-local rule.

### Gateway bridge ([`node/mesh/bridge.rs`](../../crates/veil-mesh/src/bridge.rs))

`GatewayBridge { gateway_id, role, lifted: Arc<Mutex<Vec<LiftedEnvelope>>>,
lift_seen, metrics }`

- **Lift** (mesh → veil): caller hands a `MeshFrame` whose payload decodes as
  `DeliveryEnvelope`, bridge dedupes by `content_id`, queues `LiftedEnvelope` for
  the veil layer to drain.  Loop-prevention: `lift_seen` HashMap with 30 s TTL
  + 4096-cap LRU eviction (Epic 461.4).
- **Inject** (veil → mesh): wrap a `DeliveryEnvelope` into a `MeshFrame`
  destined for a realm-local recipient; caller sends via `MeshForwarder`.

### Neighbour table ([`node/mesh/neighbor.rs`](../../crates/veil-mesh/src/neighbor.rs))

`NeighborTable { inner: Arc<Mutex<HashMap<[u8; 32], Arc<dyn LocalLink>>>> }`

- `add(node_id, link)` — register (or replace) a link.  Capped at
  `MAX_NEIGHBOR_TABLE_SIZE`; new entries beyond cap rejected (existing replaced
  unconditionally).
- `link_to(&node_id)` — read interface for `MeshForwarder`.
- `prune_dead()` — drop links where `is_alive() == false`.

### Discovery / beacon ([`node/mesh/beacon.rs`](../../crates/veil-mesh/src/beacon.rs))

`BeaconSender` / `BeaconReceiver` over UDP broadcast/multicast.  Sender
periodically (default 10 s) emits a signed `MeshBeaconPayload`.  Receiver:

- **Per-IP rate limit** — `BeaconRateLimiter` 10 beacons/min/IP, 8192 IPs cap.
- **Dedup window** — `mesh.beacon_dedup_window_secs` (default 3 s) drops
  duplicate beacons from the same source.
- On valid beacon with `IS_GATEWAY`, calls `AutoDiscoveredPeers::upsert(...)`.

`AutoDiscoveredPeers` — capped at **`MAX_AUTODISCOVERED_GATEWAYS = 8`** entries,
TTL **60 s**, LRU-evicts least-recently-seen on cap hit.  Persisted to disk
when `mesh.autodiscover_persist_path` is set; on restore TTL halved (30 s) so
stale entries refresh quickly.

### Auto-connect loop ([`runtime/mesh_gateway.rs`](../../crates/veil-node-runtime/src/runtime/mesh_gateway.rs))

`spawn_gateway_autodiscover_loop` — every **5 s**:

1. `autodiscovered.evict_expired()` (drop > 60 s old).
2. Count active sessions in synthetic peer-id range `0xC000_0000+`.
3. If `active < mesh.autodiscover_max_concurrent` (default 3), pick the
   shortfall from `live_gateways()` (FIFO order) and spawn outbound sessions.

Each auto-connected gateway gets a synthetic `PeerId` ≥ `0xC000_0000` so other
code paths can recognise it as transient (vs operator-configured peers).

### Config ([`veil_cfg::MeshConfig`](../../crates/veil-cfg/src/model.rs))

```toml
[mesh]
bind_addr = "0.0.0.0:9100"          # UDP realm listener
realm_id = "<32 hex chars>"         # 16-byte realm
beacon_addr = "<broadcast:port>"    # UDP target for beacons
autodiscover_gateway = true         # default: enable auto-connect to gateways
autodiscover_max_concurrent = 3     # default: ≤ 3 simultaneous gateway sessions
beacon_dedup_window_secs = 3        # default: drop dup beacons within 3 s
autodiscover_persist_path = "..."   # optional: cache discovered gateways across restarts
```

---

## Coverage matrix vs Epic 478 user requirements

| Requirement | Coverage | Notes |
|---|---|---|
| Leaf in WiFi-only LAN connects to global veil | ✅ | Beacon → AutoDiscoveredPeers → auto-connect to ≤ 3 gateways. |
| Multi-hop M → relay-Core → gateway → target | ✅ | `MeshForwarder` relays Core→Core inside realm; egress via gateway. Sim test should assert end-to-end. |
| Realm isolation (cross-realm frames blocked) | ✅ | `MeshForwarder::with_realm_id`. |
| Beacon authentication (anti-spoofing) | ✅ | Ed25519 sig + `BLAKE3(pk) == node_id`. |
| Beacon flood protection | ✅ | `BeaconRateLimiter` 10/min/IP, 8192 IPs cap. |
| Broadcast amplification protection | ✅ | `BroadcastSeenSet` 4096 entries × 10 s TTL. |
| TTL-bounded forwarding | ✅ | Per-hop decrement; default initial TTL caller-set. |
| Mesh ↔ veil loop prevention | ✅ | `lift_seen` dedup 30 s + 4096 cap. |
| Persisted gateway memory across restarts | ✅ | `mesh.autodiscover_persist_path` JSONL snapshot. |
| Sub-second failover when active gateway dies | ❌ | Auto-discover loop polls every 5 s; tx-failure on session → ~5 s detection lag. |
| Gateway selection by latency / battery | ❌ | Currently FIFO of `live_gateways()`. `MeshBeaconPayload.battery_level` is parsed but not used in selection. |
| Per-leaf bandwidth quota at gateway | ❌ | Only session-level `per_peer_limiter` (FPS + burst), no byte/sec accounting per leaf. |
| BLE / Wi-Fi Direct transports (true offline LAN) | ❌ | Only UDP + in-memory loopback. |
| User-facing diagnostics | ❌ | No `node show` mesh-aware output ("you're via gateway X, battery 90 %"). |

---

## Out of scope for Epic 478

- **Wire-format change** — none planned.  All gaps are operational / runtime / new
  transport adapters; the mesh wire format is stable.
- **Onion / circuit support** — separate Epic 482.  Mesh layer is plaintext
  realm-local; encryption is upstream (E2E inside `DeliveryEnvelope` payload).
- **Cross-realm bridging** — gateways already lift to the global veil; multi-realm
  gateway (one node bridging realm A ↔ realm B) is plausible but not required
  by current threat model.
