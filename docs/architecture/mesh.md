# Mesh subsystem (Epic 478 audit)

> **Audit date:** 2026-04-26 · **Code state:** master @ 956ca8c (post Epic 477)
>
> **Historical snapshot.** This is the 2026-04-26 audit as written. Since then
> Epic 478 closed: gaps **1 (sub-second failover)** and **2 (latency + battery
> gateway selection)** shipped — see `rank_gateways_by_score` / `gateway_score`
> and `gateway_failover_notify` in `runtime/mesh_gateway.rs`. Gaps **3–5**
> (per-leaf quota, BLE / Wi-Fi Direct, diagnostics) remain open. The list and
> matrix below are flipped to ✅ where shipped.

## TL;DR

The mesh subsystem already covers the **M leaf-nodes ↔ N gateway-nodes** case
that Epic 478 plans for. A realm here is a local-network scope — a group of
nodes that can see each other on the same LAN. Within a realm, peers find each
other through signed UDP beacons. They forward `MeshFrame`s through the
`MeshForwarder` (Core relays only, bounded by a time-to-live hop count, and
de-duplicated). A `GatewayBridge` then lifts realm-local frames out into the
global veil, and injects veil frames back into the realm. Auto-discovery and
auto-connect to up to N gateways already runs.

**Gaps to close in Epic 478:**

1. ✅ Sub-second failover when active gateway dies — shipped in Epic 478 (`gateway_failover_notify`; was ~5 s poll).
2. ✅ Gateway selection by latency + battery — shipped in Epic 478 (`rank_gateways_by_score` / `gateway_score`; was FIFO of `live_gateways()`).
3. Per-leaf bandwidth quota at gateway (only session-level FPS limiter today).
4. BLE / Wi-Fi Direct transport adapters (only UDP + in-memory loopback today).
5. User-facing diagnostics ("you're connected via gateway X, battery 90 %, latency 12 ms").

The 2-hop forward chain (M → relay-Core → gateway → target) is **already
supported** by `MeshForwarder::forward_with_cache`. A multi-hop path through
Core nodes works inside the realm, and the gateway is the exit point. No code
change is needed for that sub-task; a simulation test will assert it.

---

## Components

### Wire types ([`proto/mesh.rs`](../../crates/veil-proto/src/mesh.rs))

- **`RealmId([u8; 16])`** — a 128-bit opaque realm scope (the identifier for one
  local-network group). The wildcard `BROADCAST = [0xFF; 16]` means "every
  realm." `MeshForwarder::with_realm_id(...)` enforces realm isolation: frames
  from another realm are silently dropped (Epic 243).
- **`MeshFrame { realm_id, src_node_id, dst_node_id, ttl, payload }`** — an
  83-byte header plus a variable payload. `dst = [0xFF; 32]` means a realm
  broadcast. The payload is an `Arc<[u8]>`, so the per-hop `clone()` only bumps a
  reference count instead of copying the bytes — a broadcast fan-out doesn't
  reallocate the payload for each neighbour.
- **`MeshBeaconPayload { node_id, realm_id, role_flags, veil_addr,
  battery_level, algo, public_key, signature }`** — the periodic announcement a
  node sends so neighbours can discover it. The receiver checks two things:
  that `BLAKE3(public_key) == node_id`, and that the signature over the unsigned
  body is valid (Epic 406.5). Bit flags: `IS_GATEWAY = 0x01`,
  `HAS_INTERNET = 0x02`, `IS_RELAY = 0x04`.
- **`MeshAckPayload { status }`** — OK / NoRoute / TtlExpired.

### Forwarder ([`node/mesh/forwarder.rs`](../../crates/veil-mesh/src/forwarder.rs))

`MeshForwarder { local_id, role, neighbors: Arc<dyn MeshNeighborProvider>,
local_realm_id, broadcast_seen }`

- Only `Core` nodes forward transit traffic (a `Leaf` returns `NotRelay`).
- TTL = 0 → drop the frame.
- Source-spoofing check: drop any frame whose `src_node_id == self.local_id`.
- Realm isolation: drop the frame if `frame.realm_id != local_realm_id`.
- Unicast: look up `link_to(dst)`, then send.
- Broadcast: de-duplicate via `BroadcastSeenSet` (4096-entry cap, 10 s TTL),
  then fan out to every neighbour (skipping self and any duplicate).
- `forward_with_cache(frame, route_cache)` tries paths in prefer-local order:
  (1) a direct local-mesh link, then (2) a `RouteCache` next-hop hint (a veil
  relay), then (3) a plain `forward()` fallback. This implements the Epic 68.4
  prefer-local rule.

### Gateway bridge ([`node/mesh/bridge.rs`](../../crates/veil-mesh/src/bridge.rs))

`GatewayBridge { gateway_id, role, lifted: Arc<Mutex<Vec<LiftedEnvelope>>>,
lift_seen, metrics }`

- **Lift** (mesh → veil): the caller hands over a `MeshFrame` whose payload
  decodes as a `DeliveryEnvelope`. The bridge de-duplicates by `content_id`,
  then queues a `LiftedEnvelope` for the veil layer to drain. To prevent loops,
  it tracks a `lift_seen` HashMap with a 30 s TTL and 4096-entry LRU eviction
  (Epic 461.4).
- **Inject** (veil → mesh): wrap a `DeliveryEnvelope` in a `MeshFrame` addressed
  to a realm-local recipient. The caller then sends it via `MeshForwarder`.

### Neighbour table ([`node/mesh/neighbor.rs`](../../crates/veil-mesh/src/neighbor.rs))

`NeighborTable { inner: Arc<Mutex<HashMap<[u8; 32], Arc<dyn LocalLink>>>> }`

- `add(node_id, link)` — register a link, or replace one for a node already in
  the table. The table is capped at `MAX_NEIGHBOR_TABLE_SIZE`: a replacement
  always goes through, but a brand-new entry past the cap is rejected.
- `link_to(&node_id)` — the read interface `MeshForwarder` uses to find a link.
- `prune_dead()` — drop any link where `is_alive() == false`.

### Discovery / beacon ([`node/mesh/beacon.rs`](../../crates/veil-mesh/src/beacon.rs))

`BeaconSender` and `BeaconReceiver` run over UDP broadcast/multicast. The sender
emits a signed `MeshBeaconPayload` on a timer (default 10 s). The receiver
applies three checks:

- **Per-IP rate limit** — `BeaconRateLimiter` allows 10 beacons/min/IP, with an
  8192-IP cap.
- **Dedup window** — `mesh.beacon_dedup_window_secs` (default 3 s) drops repeat
  beacons from the same source.
- On a valid beacon flagged `IS_GATEWAY`, it calls
  `AutoDiscoveredPeers::upsert(...)`.

`AutoDiscoveredPeers` is capped at **`MAX_AUTODISCOVERED_GATEWAYS = 8`** entries
with a **60 s** TTL; on a cap hit it evicts the least-recently-seen entry. It is
persisted to disk when `mesh.autodiscover_persist_path` is set. On restore the
TTL is halved (to 30 s) so stale entries refresh quickly.

### Auto-connect loop ([`runtime/mesh_gateway.rs`](../../crates/veil-node-runtime/src/runtime/mesh_gateway.rs))

`spawn_gateway_autodiscover_loop` — every **5 s**:

1. `autodiscovered.evict_expired()` (drop > 60 s old).
2. Count active sessions in synthetic peer-id range `0xC000_0000+`.
3. If `active < mesh.autodiscover_max_concurrent` (default 3), pick the
   shortfall from `live_gateways()` (FIFO order) and spawn outbound sessions.

Each auto-connected gateway gets a synthetic `PeerId` ≥ `0xC000_0000`, so other
code paths can recognise it as transient rather than operator-configured.

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
| Sub-second failover when active gateway dies | ✅ | Shipped in Epic 478: `gateway_failover_notify` wakes the auto-discover loop <1 ms after a synthetic-gateway session closes (poll cut to 1 s as a safety net). |
| Gateway selection by latency / battery | ✅ | Shipped in Epic 478: `rank_gateways_by_score` / `gateway_score` rank by smoothed RTT + `battery_level` (no longer FIFO of `live_gateways()`). |
| Per-leaf bandwidth quota at gateway | ❌ | Only session-level `per_peer_limiter` (FPS + burst), no byte/sec accounting per leaf. |
| BLE / Wi-Fi Direct transports (true offline LAN) | ❌ | Only UDP + in-memory loopback. |
| User-facing diagnostics | ❌ | No `node show` mesh-aware output ("you're via gateway X, battery 90 %"). |

---

## Out of scope for Epic 478

- **Wire-format change** — none planned. Every gap above is operational, a
  runtime concern, or a new transport adapter; the mesh wire format is stable.
- **Onion / circuit support** — handled by a separate Epic 482. The mesh layer
  carries plaintext within a realm; encryption happens upstream, end-to-end
  inside the `DeliveryEnvelope` payload.
- **Cross-realm bridging** — gateways already lift frames into the global veil.
  A multi-realm gateway (one node bridging realm A ↔ realm B directly) is
  plausible, but the current threat model doesn't require it.
