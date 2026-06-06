# Developer Guide

## Project Structure

The project is a Cargo workspace built from many `crates/veil-*` crates. The
real implementations live there. `veilcore/` is now just a thin facade that
re-exports them, and the `veil-cli` binary lives in its own crate,
`crates/veil-cli`.

```
veil/
├── crates/                     # Workspace crates with implementations
│   ├── veil-cli/            # veil-cli binary + CLI commands (clap)
│   │   ├── src/bin/cli.rs      # Entry point of the veil-cli binary
│   │   ├── src/cmd/            # CLI commands
│   │   └── Cargo.toml
│   ├── veil-proto/          # Wire formats (encode/decode), family.rs, budget.rs
│   ├── veil-transport/      # Transport adapters (TCP/TLS/QUIC/WS/SOCKS, Unix)
│   ├── veil-session/        # OVL1 handshake, FSM, runner, handoff
│   ├── veil-dispatcher/     # Frame routing (FrameDispatcher)
│   ├── veil-dht/            # Kademlia DHT (K=20), TieredStore
│   ├── veil-discovery/      # Directory service (attachment, endpoint)
│   ├── veil-gateway/        # Leaf connection management
│   ├── veil-ipc/            # IPC server (Unix socket) for applications
│   ├── veil-mailbox/        # Message store (redb)
│   ├── veil-mesh/           # Local UDP network, beacons
│   ├── veil-nat/            # NAT traversal
│   ├── veil-pex/            # Peer Exchange
│   ├── veil-proxy/          # SOCKS5 proxy over veil
│   ├── veil-routing/        # RouteCache, RTT table, Vivaldi
│   ├── veil-crypto/         # Cryptographic primitives, PoW
│   ├── veil-cfg/            # Configuration (model, parsing, validation)
│   ├── veil-identity/       # Identity, name_access, network_access
│   ├── veil-node-runtime/   # NodeRuntime, admin API, metrics_http
│   ├── veil-observability/  # Metrics and logging
│   ├── ogate/                  # Gateway binary; TUN/TAP in src/tun/
│   └── …                       # ~40 more veil-* crates
├── veilcore/                # Facade aggregator crate (re-export shims)
│   ├── src/
│   │   ├── lib.rs              # Exports, lock! macro
│   │   ├── node/*.rs          # Flat re-export files (dht.rs, control.rs, …)
│   │   │                      #   — facades over the veil-* crates
│   │   ├── proto.rs           # Re-export of veil-proto (a single file, not a directory)
│   │   └── transport.rs       # Re-export shim over veil-transport
│   └── Cargo.toml
├── veilclient/              # Client SDK for applications
├── fuzz/                       # Fuzzing harnesses
├── docs/                       # Documentation (this directory)
└── specification.md            # Original specification (RU)
```

> Note: the binary now lives at `crates/veil-cli` (`src/bin/cli.rs`).
> `veilcore/src/node/*.rs` and `crates/veil-proto/src/lib.rs` are re-export
> facades over the `crates/veil-*` crates (veil-dht, veil-session,
> veil-proto, veil-transport, and so on). The old `crates/veil-cli/src/bin/`
> directory no longer exists.

---

## Architecture

### System Layers

```
┌──────────────────────────────────────────────────────┐
│                  Application Layer                   │
│  Local apps via IPC (Unix socket) / veilclient SDK   │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│               Node Runtime (runtime.rs)              │
│  Event loop, session lifecycle, background tasks     │
└────┬──────────────────┬──────────────────────────────┘
     │                  │
┌────▼────┐    ┌────────▼─────────────────────────────────┐
│Session  │    │         FrameDispatcher                  │
│Manager  │    │  Control │ Discovery │ Delivery │ Routing│
│handshake│    └──────────┬───────────────────────────────┘
│FSM      │               │
└─────────┘   ┌───────────▼───────────────────────────────┐
              │           Services                        │
              │ DHT │ Mailbox │ Gateway │ AppRegistry │.. │
              └───────────────────────────────────────────┘
```

### Core Components

---

## NodeRuntime (`node/runtime.rs`, ~7600 lines)

This is the central event loop. It handles four jobs:

- **Lifecycle**: starting and stopping listeners, connecting to peers, and handling signals (SIGHUP)
- **Session management**: accepting an inbound connection, running the handshake, then registering the session; and reconnecting outbound links with exponential backoff
- **Background tasks**: DHT republish, gateway cleanup, mailbox cleanup, and periodic state persistence (routes, RTT, Vivaldi, gateways, peer pubkeys)
- **Frame dispatch**: once the handshake is done, it passes decoded frames to the `FrameDispatcher`

**Key structures:**

```rust
struct NodeServices {
    local_identity: Arc<LocalIdentity>,
    dispatcher: Arc<FrameDispatcher>,
    session_registry: Arc<Mutex<SessionRegistry>>,
    app_registry: Arc<AppEndpointRegistry>,
    dht: Arc<KademliaService>,
    mailbox: Arc<MailboxService>,
    gateway: Arc<GatewayService>,
    discovery: Arc<DiscoveryService>,
    routing: Arc<RoutingService>,
    metrics: Option<Arc<NodeMetrics>>,
    // ... ~15 more Arc fields
}

struct SessionRuntimeContext {
    peer_node_id: [u8; 32],
    session_keys: SessionKeys,
    outbox: Arc<SessionOutbox>,
    role: NodeRole,
    // Shared services (Arc clone, not a copy of the data)
}
```

**When adding a new service:**
1. Add an `Arc<YourService>` field to `NodeServices`
2. Initialize it in `NodeRuntime::new()`
3. If needed, pass it into `SessionRuntimeContext` via `spawn_session_runner()`
4. Add a background task in `NodeRuntime::run_inner()` if needed

---

## FrameDispatcher (`node/dispatcher/mod.rs`)

Takes a decoded frame from the session runner and routes it by its `family`
(the message category — control, discovery, delivery, and so on):

```rust
pub async fn dispatch(
    &self,
    frame: ParsedFrame,
    ctx: &SessionRuntimeContext,
) -> Option<EncodedFrame> // Some = send a response back
```

**Dispatcher structure:**

```
dispatcher/
├── mod.rs                    # Main dispatch + pending_diag
├── app.rs                    # App plane (streams)
├── control.rs                # Control plane (ping, neighbor, probe)
├── delivery.rs               # Delivery plane (mailbox, forward, trace)
├── discovery.rs              # DHT (FindNode, Store, Delete, Announce)
├── routing.rs                # RouteAnnounce, RouteRequest, PoW
├── session.rs                # Keepalive, Rekey, Detach
├── diag.rs                   # DiagPing, DiagTrace
├── pending_ack.rs            # Tracking of require_ack messages
├── pending_fetch_replica.rs  # Tracking of reseed MAILBOX_FETCH to replica nodes
└── pending_replica.rs        # Tracking of MAILBOX_REPLICATE between Core nodes
```

**When adding a new frame type:**

1. Add a new `msg_type` in `proto/family.rs` (enum + TryFrom)
2. Add a decode method in the appropriate `proto/` file
3. In `dispatcher/mod.rs`, add a branch to `match frame.family`
4. In the appropriate `dispatcher/*.rs`, implement the handler
5. Write a test in `#[cfg(test)] mod tests`

---

## Session Layer (`node/session/`)

```
session/
├── mod.rs          # Re-exports, SessionRegistry
├── handshake.rs    # OVL1 handshake (perform_ovl1_handshake)
├── fsm.rs          # Finite State Machine of the handshake phases
├── runner.rs       # Long-lived session task (reading/writing frames)
└── outbox.rs       # Thread-safe queue for sending frames
```

### Handshake

```rust
pub async fn perform_ovl1_handshake(
    stream: &mut BoxIoStream,
    identity: &HandshakeIdentity,
    role: NodeRole,
    local_mlkem_ek: Option<&[u8]>,
    // ...
) -> Result<OvlHandshakeResult>
```

It returns an `OvlHandshakeResult` carrying `session_keys`, `node_id`, `remote_role`, `remote_identity_payload`, `remote_capabilities`, and `remote_attach`.

### Session Runner

Once the handshake succeeds, a `SessionRunner` takes over. On each loop it:

1. Reads a frame from the transport
2. Decodes the header and body
3. Verifies the ChaCha20-Poly1305 MAC (when `flags.encrypted` is set)
4. Calls `FrameDispatcher::dispatch()`
5. Sends any response back via `SessionOutbox`
6. Checks the keepalive and idle timeouts

**Frame prioritization** uses a Weighted Round-Robin scheme keyed on `flags.priority`. Higher-priority traffic gets a bigger share of each round:
- RT (0): weight 8
- Interactive (1): weight 4
- Bulk (2): weight 2
- Background (3): weight 1

---

## Proto Layer (`proto/`)

This layer defines the wire formats — the exact byte layout of every message on
the network. They are hand-rolled, with no external serialization library: each
type gets an `encode() → Vec<u8>` and a `decode(&[u8]) → Result<Self, ProtoError>`.

```
proto/
├── mod.rs           # Common utilities: read_u16_be, read_array, etc.
├── budget.rs        # All limit constants
├── codec.rs         # MAX_FRAME_BODY, frame codec
├── header.rs        # FrameHeader (24 bytes)
├── family.rs        # ControlMsg, LocalAppMsg, RoutingMsg enums
├── session.rs       # Hello, Identity, Capabilities, KeyAgreement, ATTACH
├── control.rs       # NeighborOffer, RouteProbe/Reply, NAT payloads
├── delivery.rs      # DeliveryEnvelope, MailboxFetch, MailboxAck
├── discovery.rs     # FindNode, Store, AnnounceAttachment, DhtValue
├── routing.rs       # RouteAnnounce, RouteRequest, RouteResponse
├── epidemic.rs      # EpidemicPayload
├── e2e.rs           # E2eEnvelope (ML-KEM + ChaCha20-Poly1305 wrapper)
├── mesh.rs          # MeshFrame, MeshBeaconPayload, MeshAckPayload
├── name.rs          # NameRecord (human-readable names)
├── app.rs           # App-plane payloads
├── diag.rs          # DiagPingPayload, DiagTracePayload
├── anycast.rs       # AnycastRequest / AnycastResponse
├── ipc.rs           # LocalApp IPC messages (app ↔ node)
├── pex.rs           # PEX peer exchange
├── relay_chain.rs   # RecursiveRelay header/onion
└── golden_tests.rs  # Golden vectors of the wire formats
```

### Rules when adding a new payload:

```rust
// 1. Struct with pub fields
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyPayload {
    pub field1: [u8; 32],
    pub field2: u16,
    pub variable: Vec<u8>,
}

// 2. impl with encode/decode
impl MyPayload {
    // ALWAYS add an assert before as u16 / as u8 casts!
    pub fn encode(&self) -> Vec<u8> {
        assert!(
            self.variable.len() <= u16::MAX as usize,
            "MyPayload: variable exceeds u16::MAX bytes"
        );
        let mut buf = Vec::with_capacity(32 + 2 + 2 + self.variable.len());
        buf.extend_from_slice(&self.field1);
        buf.extend_from_slice(&self.field2.to_be_bytes());
        buf.extend_from_slice(&(self.variable.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.variable);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        const MIN: usize = 32 + 2 + 2;
        if buf.len() < MIN {
            return Err(ProtoError::BufferTooShort { need: MIN, got: buf.len() });
        }
        let field1 = super::read_array::<32>(buf, 0)?;
        let field2 = super::read_u16_be(buf, 32)?;
        let var_len = super::read_u16_be(buf, 34)? as usize;
        if buf.len() < 36 + var_len {
            return Err(ProtoError::BufferTooShort { need: 36 + var_len, got: buf.len() });
        }
        Ok(Self { field1, field2, variable: buf[36..36 + var_len].to_vec() })
    }
}

// 3. Tests (mandatory!)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let p = MyPayload { field1: [1u8; 32], field2: 42, variable: b"test".to_vec() };
        assert_eq!(MyPayload::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn decode_too_short() {
        assert!(MyPayload::decode(&[0u8; 5]).is_err());
    }
}
```

---

## Key Services

### MailboxService (`node/mailbox/`)

Stores messages for recipients who are offline. The backend is pluggable behind
this trait:
```rust
pub trait MailboxBackend: Send + Sync {
    fn put(&self, envelope: DeliveryEnvelope) -> Option<u64>;        // → seq
    fn fetch(&self, recipient: &[u8; 32], after_seq: u64) -> Vec<MailboxEntry>;
    fn ack(&self, recipient: &[u8; 32], up_to_seq: u64);
    fn ack_batch(&self, recipient: &[u8; 32], seqs: &[u64]);
    fn senders_for_seqs(&self, recipient: &[u8; 32], seqs: &[u64]) -> Vec<[u8; 32]>;
    fn cleanup_expired(&self, now: Instant);
    fn total_entries(&self) -> usize;
    fn recipient_count(&self) -> usize;
}
```

Adding a new backend:
1. Implement `MailboxBackend` in `node/mailbox/`
2. Add a variant to the `MailboxBackendKind` enum
3. Add a `"yourbackend"` string to the parser in `MailboxService::new()`

### AppEndpointRegistry (`node/app/registry.rs`)

Routes incoming IPC messages to the right registered application:

```rust
pub struct AppEndpointRegistry { ... }

impl AppEndpointRegistry {
    pub fn register(&self, app_id: [u8; 32], endpoint_id: u32)
        -> (EndpointHandle, mpsc::Receiver<AppMessage>);

    pub fn route(&self, msg: AppMessage) -> bool; // true = delivered

    pub fn route_delivery_failed(&self, src_app_id: [u8; 32], content_id: [u8; 32]);
}
```

### KademliaService (`node/dht/`)

```rust
impl KademliaService {
    pub async fn find_node(&self, target: [u8; 32], local_id: [u8; 32])
        -> Vec<Contact>;

    pub fn find_value_local(&self, key: &[u8; 32]) -> Option<Vec<u8>>;
    pub fn store_local(&self, key: [u8; 32], value: Vec<u8>, ttl_secs: u32);
    pub fn add_contact(&self, contact: Contact);
}
```

**Caution:** an iterative lookup that crosses nodes (`find_value` over the
network) has to send frames through live sessions. Drive those through
`dispatcher/discovery.rs`, not directly through `KademliaService`.

### RouteCache (`node/routing/cache.rs`)

```rust
impl RouteCache {
    pub fn insert(&mut self, dst: [u8; 32], via: [u8; 32], score: f64, hops: u8);
    pub fn lookup(&self, dst: &[u8; 32]) -> Option<&RouteCacheEntry>;
    pub fn lookup_all_with_scores(&self, dst: &[u8; 32]) -> Vec<([u8;32], f64)>;
    pub fn evict_expired(&mut self, now: Instant);
}
```

ECMP (equal-cost multi-path): when several paths have a `score` within
`ecmp_score_band` of each other (±20%), the cache picks one at random to spread
the load.

### ControlPlaneService (`node/control.rs`)

Handles round-trip-time (RTT) measurement via the RouteProbe/Reply exchange:

```rust
impl ControlPlaneService {
    pub fn handle_probe(&self, payload: &RouteProbePayload) -> RouteReplyPayload;
    pub fn handle_reply(&self, peer_id: [u8; 32], payload: &RouteReplyPayload);
    pub fn rtt_table(&self) -> Arc<Mutex<RttTable>>;
}
```

---

## Project Patterns

### The `lock!` Macro

Always take a Mutex lock through `lock!`, never with a raw `.lock().unwrap()`:

```rust
// Correct:
let mut table = lock!(self.route_cache);
table.insert(...);

// Incorrect (panics on a poisoned mutex):
self.route_cache.lock().unwrap()
```

If the mutex is poisoned (a thread panicked while holding it), the macro recovers
the guard and logs a warning instead of panicking. It is defined in `lib.rs`.

### `Arc<Mutex<_>>` vs `Arc<RwLock<_>>`

- `Arc<Mutex<_>>` — the default for shared mutable state; reach for this first
- `Arc<RwLock<_>>` — only when reads provably dominate and writes are rare
- Every `Arc<Mutex<_>>` is locked through `lock!`, never `.lock().unwrap()`

### Hex Formatting

Format byte IDs with the helpers in the `veil-util` crate — don't hand-roll it:

```rust
// 32-byte ID (full hex, 64 characters)
veil_util::hex_str(&node_id)

// First 4 bytes (for logs)
veil_util::hex_short(&node_id)

// DON'T do this (code duplication):
node_id.iter().map(|b| format!("{b:02x}")).collect::<String>()
```

### Narrowing Casts

**Always** assert the length fits before an `as u16` or `as u8` cast — a silent
truncation here corrupts the wire format:

```rust
// Correct:
assert!(data.len() <= u16::MAX as usize, "MyMsg: data exceeds u16::MAX");
let len = data.len() as u16;

// Incorrect (silent truncation when data.len() > 65535):
let len = data.len() as u16;
```

### Logging

The project logs through the `log` crate, not `tracing`:

```rust
log::debug!("route.cache.insert dst={} via={} score={}", hex_short(&dst), hex_short(&via), score);
log::info!("session.established peer={}", hex_short(&peer_id));
log::warn!("mailbox.put.failed reason={}", e);
log::error!("config.save.failed: {e}");
```

### Async and Blocking

- All I/O is async, on top of tokio
- Move heavy CPU work (PoW, Falcon512 keygen) onto `tokio::task::spawn_blocking` so it doesn't stall the runtime
- Use a plain `Mutex` (not `tokio::sync::Mutex`) for short critical sections

---

## Adding New Functionality

### Checklist for adding a new protocol message

- [ ] `proto/family.rs`: add a variant to the enum + `TryFrom<u16>`
- [ ] `proto/`: create/extend a file with `encode()`/`decode()` + a unit test
- [ ] `proto/budget.rs`: add limit constants if needed
- [ ] `dispatcher/mod.rs`: add a dispatch branch
- [ ] `dispatcher/NEW.rs`: implement the handler
- [ ] `node/runtime.rs`: wire it into SessionRuntimeContext if needed
- [ ] Write an integration test

### Checklist for adding a new config field

- [ ] `cfg/model.rs`: add the field to the appropriate Config struct
- [ ] A default value via `#[serde(default = "...")]`
- [ ] `cfg/validate/`: add validation if needed
- [ ] `cfg/access.rs`: add a `ConfigKey` variant for get/set via the CLI
- [ ] Documentation in [admin-guide.md](admin-guide.md)

### Checklist for adding a new service

- [ ] Create `node/myservice/mod.rs` with `pub(crate) struct MyService`
- [ ] Make it `Clone-cheap` via `Arc<Mutex<Inner>>`
- [ ] Add it to `NodeServices` as `Arc<MyService>`
- [ ] Initialize it in `NodeRuntime::new()`
- [ ] Add `Arc::clone` in the necessary places (do not pass by value)
- [ ] Add a background task in `run_inner()` via `tokio::spawn`
- [ ] Unit test in `#[cfg(test)]`

---

## Testing

### Test Structure

```
veilcore/src/
├── proto/*/tests      # Unit tests of the wire formats (roundtrip, too-short, etc.)
├── node/*/tests       # Unit tests of the services
└── integration/       # Integration tests (full handshake, multi-hop)
```

### Useful Test Utilities

**Creating a test dispatcher:**

```rust
// In #[cfg(test)]:
use crate::node::dispatcher::make_test_dispatcher;
let dispatcher = make_test_dispatcher(NodeRole::Core);
```

**Duplex stream for handshake tests:**

```rust
let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
let client = tokio::spawn(async move {
    perform_ovl1_handshake(&mut client_stream, &identity_a, NodeRole::Leaf, ...).await
});
let server = tokio::spawn(async move {
    perform_ovl1_handshake(&mut server_stream, &identity_b, NodeRole::Core, ...).await
});
```

**Running tests:**

```bash
cargo test --workspace                    # All tests
cargo test --package veilcore          # Only veilcore
cargo test proto::delivery               # A specific module
cargo test -- --nocapture                # With stdout output
```

**Fuzzing:**

```bash
# The list of all harnesses is in fuzz/Cargo.toml
cargo fuzz run fuzz_session_decode
cargo fuzz run fuzz_delivery_decode
cargo fuzz run fuzz_routing_decode
cargo fuzz run fuzz_app_decode
cargo fuzz run fuzz_ipc_decode
cargo fuzz run fuzz_cipher_open
cargo fuzz run fuzz_proto_decode
```

---

## Known Limitations and Stubs

These components are **stubs** or only partly implemented — don't assume they
are production-ready:

| Component | File | Status |
|-----------|------|--------|
| Mesh WiFi Direct / BLE | absent | Real integration is not implemented; mesh works over UDP links ([`node/mesh/udp.rs`](../../crates/veil-mesh/src/udp.rs)) |
| QUIC sessions | [`transport/quic.rs`](../../crates/veil-transport/src/quic.rs) | The `quic://` transport is always compiled (unconditional `quinn` dependency); there is no longer a separate feature flag |
| PoW signature verify | [`node/dispatcher/routing.rs`](../../crates/veil-dispatcher/src/routing.rs) | The PowChallenge signature is not verified in some paths |
| TUN/TAP | [`crates/ogate/src/tun/`](../../crates/ogate/src/tun/) | Basic implementation in the `ogate` crate (moved out of `veilcore`); production readiness has not been verified |

---

## Component Interaction

### Lifecycle of an inbound message (DeliveryEnvelope)

```
Network → TransportLayer
  → SessionRunner.read_frame()
    → FrameDispatcher.dispatch(family=Delivery, msg_type=MailboxPut)
      → dispatcher/delivery.rs::handle_mailbox_put()
        → MailboxService.put(envelope)
          → MailboxBackend.put()  [memory/wal/rocksdb]
        → DeliveryStatusPayload(OK)
      → encode_response()
  → SessionOutbox.send(response)
→ Network
```

### Lifecycle of an IPC message from an application

```
App (Unix socket)
  → IpcServer.accept()
    → IpcHandler.handle_app_bind()
      → AppEndpointRegistry.register(app_id, endpoint_id)
    → IpcHandler.handle_app_send(target_node_id, payload)
      → E2eService.encrypt(payload, recipient_ek)  [if enabled]
      → DeliveryEnvelope { recipient, sender, payload, ... }
      → SessionRegistry.find_session(target_node_id)
        → SessionOutbox.send(frame)  [if a session exists]
        → MailboxService.put(envelope)  [if no session - via gateway]
```

### Lifecycle of a DHT lookup

```
DiscoveryService.handle_find_value_request(key)
  → KademliaService.find_value_local(key)
    → Some(value) → FindValueResponse::Value
    → None → KademliaRoutingTable.closest(key, k=20)
      → FindValueResponse::Nodes [k closest contacts]

  [The client recursively repeats FindValue until it reaches the right node]
```

### Route Discovery

```
RoutingService.discover_route(target_node_id)
  → PowChallenge.solve()  [if required]
  → RouteDiscoveryPacket { target, requester, ttl=16, pow_solution }
  → broadcast to N random neighbors

[Each intermediate node:]
  → PoW verify
  → If target == self: send RouteDiscoverOffer back
  → Else: forward to closest neighbor, decrement TTL

[The requester receives RouteDiscoverOffer:]
  → RouteCache.insert(target, via=offer_sender, score)
  → Notify waiting sender
```

---

## Adding a New Transport

A transport is the layer that decides how bytes physically travel. To add one
(say, BLUETOOTH_TCP):

1. Implement the `TransportConnection` trait in `transport/`:

```rust
pub trait TransportConnection: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    fn peer_addr(&self) -> Option<SocketAddr>;
    fn local_addr(&self) -> Option<SocketAddr>;
}
```

2. Implement the `TransportListener` trait:

```rust
pub trait TransportListener: Send + 'static {
    async fn accept(&mut self) -> Result<(Box<dyn TransportConnection>, SocketAddr)>;
}
```

3. Register it in `TransportRegistry` with a URI scheme:

```rust
registry.register("bt", Box::new(BluetoothTransportFactory));
```

4. Add parsing in `cfg/model.rs::ListenConfig::transport`

5. Add it to the transports documentation

---

## Build Feature Flags

Optional dependencies are gated behind Cargo feature flags. One thing to keep
straight: the **library crate** `veilcore` and the **user-facing binary**
`veil-cli` (`crates/veil-cli`) ship different defaults.

- `veilcore` (library): `default = ["rocksdb-cold"]`.
- `veil-cli` (the binary users build and run):
  `default = ["rocksdb-cold", "tls-boring"]`. So in shipped builds, BoringSSL and
  its browser-like JA3/JA4-fingerprint ClientHello (with rotation) are on **by
  default**. `rustls` stays available as a fallback via `--no-default-features`.

  (JA3/JA4 fingerprints are how a network observer tags a TLS client by the shape
  of its handshake; mimicking a browser's makes Veil traffic blend in.)

| Flag | Crate | Effect |
|------|-------|--------|
| `rocksdb-cold` (default) | `veilcore`, `veil-cli` | Enables the RocksDB backend for cold stores (mailbox, DHT cold tier). Requires `librocksdb`. |
| `tls-boring` (default for `veil-cli`) | `veilcore`, `veil-cli` | Replaces `rustls` with BoringSSL (`btls`/`tokio-btls`/`quinn-btls`); provides a Chrome-like JA3/JA4 ClientHello fingerprint + rotation (the basic DPI-evasion path). Off by default for `veilcore`, on for `veil-cli`. |
| `tls-webpki-roots` | `veilcore`, `veil-cli` | A semver-stable no-op for existing build configs (webpki-roots is always present in the binary for HTTPS bootstrap). |
| `production-seeds` | `veilcore`, `veil-cli` | Embeds production seed nodes into the binary. |
| `allow-empty-seeds` | `veilcore`, `veil-cli` | Allows starting without seeds (for dev/test only). |
| `test-low-difficulty` | `veilcore`, `veil-cli` | Lowers the identity PoW difficulty to 16 bits for devnet/tests (in production it is 24 bits). |
| `slow-sim-tests` | `veilcore`, `veil-cli` | Enables heavy sim tests (≥55 s), otherwise `#[ignore]`d. |

> QUIC and TUN/TAP are **not** controlled by feature flags: the `quic://`
> transport is always compiled (unconditional `quinn` dependency), and TUN/TAP
> has been moved into the `crates/ogate` crate (`src/tun/`).

### Building with Flags

```bash
# Standard build of the binary (rocksdb-cold + tls-boring by default)
cargo build -p veil-cli

# Without default features: returns the rustls stack (a single non-mutating fingerprint)
cargo build -p veil-cli --no-default-features --features rocksdb-cold

# Building only the veilcore library (default = rocksdb-cold)
cargo build -p veilcore

# A production-suitable build of the binary
cargo build -p veil-cli --features production-seeds

# Check without building
cargo check -p veil-cli --no-default-features
```

### Building on Windows (native)

CI builds the full workspace on Linux. The `windows-test` job deliberately runs
`-p veilcore --no-default-features` to skip the C/C++ crypto deps. You *can*
build the **default** feature set natively on Windows (BoringSSL via `btls-sys`,
RocksDB, `ring`, `aws-lc-sys`, `pqcrypto-internals`), but it takes a specific
toolchain. The reason: the workspace `.cargo/config.toml` `[env]` block forces
GNU-driver flags (`CC=clang`, `CXX=clang++`, `CXXFLAGS=-include cstdint …`) that
are tuned for the Linux runners, and those have to be overridden.

Prerequisites:

- **Visual Studio 2022** with the C++ workload (ships `cmake` + `ninja` under
  `…\Common7\IDE\CommonExtensions\Microsoft\CMake\`).
- **LLVM** (`clang-cl`) — e.g. `winget install LLVM.LLVM`, installs to
  `C:\Program Files\LLVM\bin`.
- **NASM** (BoringSSL / `ring` x86-64 assembly) — `winget install NASM.NASM`,
  installs to `%LOCALAPPDATA%\bin\NASM`.

Then run cargo from a shell with this environment set up. Paste it once per
PowerShell session, or wrap it in a `$PROFILE` function:

```powershell
# 1. MSVC env (INCLUDE/LIB) + bundled ninja/cmake on PATH
$vs = "C:\Program Files\Microsoft Visual Studio\2022\Community"
Import-Module "$vs\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments "-arch=x64 -host_arch=x64" | Out-Null

# 2. clang-cl + NASM on PATH
$env:PATH = "C:\Program Files\LLVM\bin;$env:LOCALAPPDATA\bin\NASM;" + $env:PATH

# 3. Override the Linux-tuned toolchain knobs for clang-cl
$env:CC = "clang-cl"; $env:CXX = "clang-cl"   # plain clang chokes on MSVC `/arch:AVX2`
$env:CMAKE_GENERATOR = "Ninja"                # the VS generator uses cl.exe / MSBuild
$env:CXXFLAGS = "/FIcstdint /FIcstring"       # clang-cl forced-include form of the config's `-include`

cargo build --workspace
cargo clippy --workspace --all-targets
```

What each knob is for:

- `CC/CXX=clang-cl` — `pqcrypto-internals` passes the MSVC flag `/arch:AVX2`,
  which only the `clang-cl` driver understands (plain `clang` errors out).
- `CMAKE_GENERATOR=Ninja` — the Visual Studio generator drives `cl.exe` via
  MSBuild and ignores `CC`; it also can't accept clang-style flags. Ninja invokes
  `clang-cl` directly.
- `CXXFLAGS=/FIcstdint /FIcstring` — `clang-cl` rejects the config's GNU-style
  `-include cstdint` (it treats `cstdint` as a missing input file and BoringSSL's
  cmake configure fails). `/FI` is the equivalent forced-include form; overriding
  the env var replaces the config value for this session.

> Some example and bin targets are `#[cfg(unix)]`-only, so they won't compile
> under `--all-targets` on Windows. If you only need the library lint, scope to
> `--lib --tests` (or exclude the affected crate).

---

## Useful Commands for Development

```bash
# Build with warning inspection
cargo build --workspace 2>&1 | grep -E "warning|error"

# Run the tests
cargo test --workspace

# Only unit tests (no integration tests)
cargo test --lib --workspace

# Check formatting
cargo fmt --check

# Clippy
cargo clippy --workspace -- -D warnings

# Documentation
cargo doc --workspace --open

# Fuzzing (requires nightly)
cargo +nightly fuzz run fuzz_proto_decode -- -max_total_time=60
```
