# Crate Architecture (target state)

The goal is to split the monolithic `veilcore` (148 K lines of code) into
focused crates — a crate being a single Rust library. Each one should be
auditable, testable, and ready to move into its own repository later. For now
the whole thing stays in one workspace (Cargo's term for a set of crates built
together); separate repos come later.

## Target structure

```
veil/                              (workspace root)
├── crates/
│   ├── veil-util                  # Tier 0: macros, atomic_write, hex
│   ├── veil-types                 # Tier 0: SignatureAlgorithm, NodeId,
│   │                                 #         PeerId, error enums
│   ├── veil-proto                 # Tier 1: wire formats, codecs
│   ├── veil-crypto                # Tier 1: Ed25519/Falcon/X25519/AEAD
│   ├── veil-cfg                   # Tier 2: config schema + validation
│   ├── veil-identity              # Tier 2: sovereign identity, delegation
│   ├── veil-transport             # Tier 2: TLS, TCP, QUIC, WS, MeshUDP
│   ├── veil-dht                   # Tier 3: Kademlia routing
│   ├── veil-mesh                  # Tier 3: local-LAN UDP realm
│   ├── veil-anonymity             # Tier 3: onion + circuits + rendezvous
│   ├── veil-node-runtime          # Tier 4: session runtime, dispatcher
│   └── veil-cli                   # Tier 5: CLI binary
├── veilclient                     # existing client SDK
└── ...
```

Tiers are dependency layers. A crate in one tier may depend only on crates in
the same tier or a lower one — never upward.

## Current state (pre-split)

```
veilcore (monolithic; 148 K LOC)
├── util.rs                # truly leaf, 0 internal deps
├── transport/             # leaf, but has 2 callbacks to node/cfg
├── cfg/                   # kitchen sink: deps on crypto, proto, util,
│                          #               + test-only deps on node
├── crypto/                # cycles with cfg + proto
├── proto/                 # cycles with cfg + crypto
├── identity_ops.rs        # depends on cfg, crypto
├── identity_policy.rs     # depends on cfg
├── node/                  # depends on everything above
├── cmd/                   # depends on everything (CLI)
└── sim/                   # test-only, depends on cfg + node
```

Three dependency cycles stand in the way. (A cycle is when two modules each
reach into the other, so neither can be pulled out alone.)

1. **cfg ↔ proto** — cfg::BootstrapPeer is used in proto::bootstrap_bundle, and
   proto::identity_document types are used when parsing cfg.
2. **cfg ↔ crypto** — cfg::SignatureAlgorithm is used by crypto, and
   crypto::session_kdf types are used in cfg.
3. **cfg → node** (test-only) — the cfg/sovereign_flow.rs tests reference
   node::identity::verify::verify_identity_document.

## Migration order (multi-session)

The steps are listed in dependency order. Each one needs only the steps before
it, nothing after.

### Step: pure leaves

- **veil-util** — extract `util.rs`. It has no internal dependencies. 37
  callers need updating with `s/crate::util/veil_util/`.

### Step: foundational types

- **veil-types** — a new crate. It takes:
  - `cfg::SignatureAlgorithm` (the key to breaking the crypto/proto cycle)
  - `cfg::NodeId`, `cfg::PeerId`, `cfg::ListenId`, `cfg::LinkId`
  - common error enums (`cfg::ConfigError` if that works out)

  This breaks cycles (1) and (2) at the type level. The refactor is mechanical:
  every module that says `use crate::cfg::SignatureAlgorithm` switches to
  `use veil_types::SignatureAlgorithm`.

### Step: middle tier

- **veil-proto** — extract `proto/` once it depends only on
  veil-types + veil-util.
- **veil-crypto** — extract `crypto/` once it depends only on
  veil-types + veil-proto + veil-util.

### Step: identity + cfg

- **veil-cfg** — extract what's left of `cfg/` (minus the types that moved to
  veil-types).
- **veil-identity** — extract:
  - `crypto/identity.rs`
  - `cfg/sovereign_flow.rs`
  - `node/identity/`
  - `proto/identity_document.rs`, `proto/instance_registry.rs`,
    `proto/name_claim_v2.rs`, `proto/mlkem_cert.rs`

  This is a big one: identity logic is currently scattered across cfg, crypto,
  proto, and node.

### Step: transport + network primitives

- **veil-transport** — extract `transport/` once its 2 callbacks
  (TransportHintRegistry, Config::from_config) are injected through traits
  instead of named directly.
- **veil-dht** — extract `node/dht/`.
- **veil-mesh** — extract `node/mesh/` + UDP realm.
- **veil-anonymity** — extract `node/anonymity/`.

### Step: top-level

- **veil-node-runtime** — receives the residual `node/`.
- **veil-cli** — extract `cmd/`.

## Execution log

### Util crate

`veil-util` extracted. Added as a workspace member. All 37 call sites keep
working through a re-export shim — a thin module that re-exposes the moved items
under their old path. Build clean, tests green.

### Types crate

- The `veil-types` crate is created. It holds `SignatureAlgorithm` and
  `ParseEnumError`.
- 7 unit tests moved over from cfg/model.rs.
- A re-export shim in cfg/model.rs —
  `pub use veil_types::{ParseEnumError, SignatureAlgorithm};` — keeps all 62
  existing call sites working.
- The cfg ↔ crypto and cfg ↔ proto cycles are now broken at the type level, but
  only for SignatureAlgorithm. Other cfg types (NodeId, ConfigError) still pull
  crypto backward; later steps deal with those.

### Error crate

A tiny `veil-error` crate now holds `ConfigError` and `Result` (the canonical
type alias). The external dependencies `thiserror`, `base64`, `toml`, and
`serde_json` moved from veilcore to veil-error. Their versions are pinned to
match veilcore's, so the `?` operator doesn't trip over mismatched From-trait
implementations.

`cfg/error.rs` becomes a 7-line re-export shim:

```rust
pub use veil_error::{ConfigError, Result};
```

All callers keep working. Crypto's 6 files were updated to
`use veil_error::{ConfigError, Result}` directly.

### proto → crypto direction cut

We took **Option A**: lift the signing helpers out. The orchestration code moved
from `proto/` up to its caller layer, `node/`:

  - `proto::discovery::{sign_announcement, verify_announcement_signature}`
    →  `node::discovery::announcement_sig::*`
  - `proto::mesh::MeshBeaconPayload::verify_auth` (method)
    →  `node::mesh::auth::verify_mesh_beacon_auth` (free function)

The production callers (`node::dispatcher::routing`,
`node::dispatcher::discovery`, `node::discovery::directory`,
`node::mesh::beacon`) now point at the new paths. Build and clippy are clean.
Tests in the touched areas are green (node::mesh 61/61, node::discovery 33/33,
proto:: 516/516).

### crypto → proto direction cut

Three wire-format constants moved to `veil-types`:

  - `ALGO_ML_KEM_768`         (u8)
  - `ML_KEM_768_EK_LEN`       (usize)
  - `CERTIFY_CONTEXT`         (&[u8])

`proto/{prekey_bundle, identity_document}.rs` now re-export them from
veil-types so existing call sites keep working. `crypto/{x3dh, identity}.rs`
import them straight from veil-types.

With both directions cut, here's the count:

  - 0 production refs `crypto → proto`
  - 0 production refs `proto → crypto`
  - 1 cfg(test) ref `proto::identity_contact` → `crypto::compute_node_id`
    (test-only — handled when proto becomes its own crate, either by inlining
    the test or moving it)

The proto ↔ crypto structural cycle is now broken in production. Both crates can
be extracted.

### Final cycle cleanup

Four targeted moves cleared every remaining production cross-reference between
proto/crypto and the rest of veilcore:

  1. Base64 serde helpers (`hex_array`, `serde_bytes_base64`) lifted from
     `node::dht::kademlia` to `proto::serde_base64`. Kademlia now re-exports
     them, which matches the natural layering.
  2. Legacy domain-identity validation helpers
     (`identity_signature_is_valid`, `identity_nonce_meets_difficulty`) moved
     from `crypto::identity` to `cfg::identity`. They take a `DomainIdentity` (a
     cfg type) and orchestrate crypto primitives, so they belong at the caller
     layer. The unused `identity_nonce_has_leading_zero` thin wrapper was
     deleted.
  3. PoW policy defaults (`DEFAULT_POW_DIFFICULTY`, which is cfg(test)-aware, and
     `DEFAULT_POW_TIMEOUT_SECS`) moved from `identity_policy::IdentityPolicy` to
     `crypto::pow::score`. identity_policy now re-exports them from crypto,
     reversing the old crypto → identity_policy direction.
  4. The `NodeRole` and `DiscoveryMode` enums (with their `role_bits` byte
     constants) moved from `cfg::model` to veil-types. Both are pure data, and
     both cfg and proto::session (the CapabilitiesPayload constructor) consume
     them. cfg/model.rs and proto/session.rs re-export them to keep all call
     sites working.

With all three directions cut, the only crate-internal path references left
inside proto/crypto are in `#[cfg(test)]` test functions (cross-derivation
asserts) and doc-comment links. Production code has zero dependencies either
way.

### veil-proto extracted

`crates/veil-proto/` is now a standalone Tier-1 workspace member.

  - Dependencies: veil-types, veil-util, veil-error; external: serde,
    blake3, base64, thiserror, chacha20poly1305, ed25519-dalek, rand_core.
  - 30 source files moved (git recorded each as a rename, ≥ 90% similarity).
  - `crates/veil-proto/src/lib.rs` is a 1-line re-export shim
    (`pub use veil_proto::*;`). It keeps every existing `crate::proto::X` import
    working across cfg/, crypto/, node/, cmd/, sim/.
  - The cross-validation test `uri_roundtrips_against_a_real_identity_document`
    moved to `veilcore/tests/identity_contact_roundtrip.rs`. It's a cross-layer
    integration test and doesn't belong inside proto.
  - `veil-proto`: 515/515 lib tests green on its own.

### veil-crypto extracted

`crates/veil-crypto/` is now a standalone Tier-1 workspace member, a sibling of
veil-proto.

  - Dependencies: veil-types, veil-util, veil-error; external:
    ed25519-dalek, pqcrypto-falcon, ml-kem, x25519-dalek, blake3, hkdf,
    chacha20poly1305, sha2, zeroize, rand_core, base64, ctrlc, thiserror.
  - 11 files plus the `pow/` submodule moved (≥ 88 % rename similarity).
  - The re-export shim in `crates/veil-crypto/src/lib.rs` keeps every existing
    `crate::crypto::X` call site working.
  - The `node_id_matches_cfg_node_id` cross-validation test moved to
    `veilcore/tests/node_id_consistency.rs`.
  - `veil-crypto`: 64/64 lib tests green on its own.

### `cfg(test)` cross-crate gotcha — addressed

Both `veil-crypto::pow::score::DEFAULT_POW_DIFFICULTY` and
`veil-proto::name_claim_v2::required_difficulty` used to rely on a plain
`cfg(test)` to drop the production difficulty (24-28 bits) down to a test
difficulty (4-16 bits), so each test runs in milliseconds. The catch: after
extraction, `cfg(test)` only fires inside the crate that defines it, not in the
test profiles of crates downstream. So veilcore's tests would have burned
through 20 M PoW attempts per case — across 18 tests, that's minutes of
timeouts.

The fix is a `test-low-difficulty` cargo feature on each crate, gated as
`cfg(any(test, feature = "test-low-difficulty"))`. `veilcore`'s
`[dev-dependencies]` list both crates again with that feature on. Cargo unifies
features across the build, so veilcore's test profile compiles with the low
difficulty while production builds keep 24/22.

### Where we stand

```
crates/
├── veil-error      ✅ Tier 0 (ConfigError + Result)
├── veil-types      ✅ Tier 0 (SignatureAlgorithm, NodeRole, DiscoveryMode,
│                                role_bits, ALGO_ML_KEM_768, ML_KEM_768_EK_LEN,
│                                CERTIFY_CONTEXT, ParseEnumError)
├── veil-util       ✅ Tier 0 (atomic_write, hex, retry, leading_zero_bits)
├── veil-adaptive   ✅ Tier 0 (network-size-aware param formulas:
│                                AdaptiveParams + estimate_network_size; 15 tests)
├── veil-proto      ✅ Tier 1 (wire formats, codecs; 515 unit tests)
└── veil-crypto     ✅ Tier 1 (sigs, KEM, AEAD, PoW; 64 unit tests)
veilcore/           (cfg minus adaptive, identity_*, node/*, cmd/*, sim/*, transport/*)
```

The util, types, error, and proto/crypto extraction steps are done.

### Tier-2 / Tier-3 extractions

Each extraction below lists its "trait inversions." That means a cross-layer
dependency on a concrete veilcore type was replaced with a trait the crate
defines, which veilcore then implements — so the crate no longer reaches up into
veilcore.

  - **veil-transport** ✅ (`crates/veil-transport`) — TCP, QUIC,
    TLS (rustls plus optional BoringSSL via `tls-boring`), WebSocket,
    SOCKS5 proxy, Unix sockets. Two cross-layer dependencies were inverted:
    `Context::from_config` lifted to `cfg::transport_glue`, and
    `TransportHintRegistry` reduced to a `TransportHintSink` trait.
    34/34 lib tests green on its own.

  - **veil-anonymity** ✅ (`crates/veil-anonymity`) — onion
    routing, fixed-size cells, circuits, relay directory, rendezvous
    points, packet wrappers. The cleanest target of all — its only
    dependencies are `cfg::SignatureAlgorithm` (already in veil-types) and
    `crypto::*`. 117/117 lib tests green on its own.

  - **veil-mesh** ✅ (`crates/veil-mesh`) — beacon discovery,
    realm-scoped UDP broadcast, neighbor table, gateway-bridge. Four
    trait inversions cover its cross-layer dependencies:
    `BandwidthGuard` (PerPeerLimiter), `MeshMetrics` (NodeMetrics),
    `BatterySink` (RttTable), `NextHopCache` (RouteCache).
    `veilcore::node::mesh_glue` collects the concrete adapters.
    59/59 lib tests green on its own.

### Remaining

  - **veil-cfg / veil-identity:** what's left of `cfg/`, plus the
    sovereign-identity bundle (the `crypto::identity` callers in cfg, and
    `node::identity/`). The two are still tangled up with each other and with
    `node::dht`. Breaking the coupling to the DHT publisher will need a
    `DhtPublishSink` trait in veil-identity.

### veil-dht extracted

`crates/veil-dht/` is now a standalone Tier-3 workspace member. It holds the
Kademlia routing and k-bucket, iterative lookups, a tiered key-value store, the
transport-resolution cache, the lookup LRU, and the network-querier.

Four cross-layer couplings to concrete types were inverted through traits in
`veil_dht::traits`:

  - `FrameRouter` — dispatch of pre-encoded frames (was `SessionOutbox`).
    Implemented directly on `SessionOutbox` in `node::dht_glue`.
  - `RttHint` — RTT-aware contact ordering (was `RttTable::get(peer).rtt_ms`).
    `RttHintAdapter` wraps `Arc<Mutex<RttTable>>`.
  - `CoordinateOracle` — the Vivaldi distance estimate (was
    `VivaldiCoord::distance_estimate(peer)` plus a per-peer cache). The
    `VivaldiOracle` adapter combines the local coordinate and the per-peer
    cache.
  - `DhtMetrics` — the `inc_dht_store` / `inc_dht_lookup` counters
    (implemented directly on `NodeMetrics`).

`cfg::DhtConfig` is mirrored as a smaller `DhtRuntimeConfig` in veil-dht — it
drops the persistence-path fields the DHT internals never touch — and
`runtime_config_from(&cfg)` converts between them at the runtime boundary.

`veil-dht`: 109/109 lib tests green on its own.

### veil-bootstrap + veil-update extracted

Two more Tier-3 crates extracted. Each can be brought up on its own:

  - **veil-bootstrap** — DNS-TXT seed records, signed/encrypted
    invites, HTTPS bundle fetch, builtin seeds. No dependencies outside the
    base set; only `cfg::BootstrapPeer` was lifted to veil-types alongside it.
    82/82 lib tests green on its own.
  - **veil-update** — self-update (signed manifest,
    multi-CDN failover, anti-downgrade timestamp, atomic swap, a periodic
    check task). `cfg::UpdateConfig` was lifted to veil-types, and
    `NodeLogger` was inverted through an `UpdateLogger` trait.
    73/73 lib tests green on its own.

### Done (veil-node-runtime + veil-cli)

The session runtime that was left (`node/session`, `node/runtime`,
`node/dispatcher`, `node/observability`, `node/abuse`, `node/routing`,
`node/identity`, `node/transfer`, `node/anycast`, `node/gateway`, …)
became **`veil-node-runtime`**. `cfg/` split into **`veil-cfg`**,
`identity_*` into **`veil-identity`**, and `cmd/` (the CLI surface)
into **`veil-cli`**.

### Where we stand

The extraction is **complete**. There are now **53 workspace members**: 51
crates under `crates/`, plus the top-level `veilcore` and `veilclient`.
`veilcore` is now a thin remainder — sim, integration glue, and a few `node/*`
shims — and the extracted node runtime lives in **`veil-node-runtime`**.
Per-crate test counts move quickly, so check `cargo nextest list` for the live
numbers.

```
crates/  (51)
  foundation      veil-error  veil-types  veil-util  veil-memory
                  veil-bloom  veil-bufpool  veil-congestion
                  veil-observability  veil-adaptive
  protocol/crypto veil-proto  veil-crypto  veil-e2e  veil-pending-ack
  transport       veil-transport  veil-transfer  veil-local-transport
                  veil-obfs4  veil-obfs4-smoke  veil-udp-obfs
                  veil-webtunnel  veil-fingerprint
  networking      veil-dht  veil-discovery  veil-mesh  veil-nat
                  veil-pex  veil-routing  veil-anonymity  veil-anycast
                  veil-gateway  veil-bootstrap  veil-invite
                  veil-reputation  veil-proxy
  identity/cfg    veil-identity  veil-cfg  veil-abuse
  app/session     veil-app  veil-session  veil-session-integration-tests
                  veil-dispatcher  veil-dispatcher-state  veil-ipc
                  veil-mailbox  veil-push  veil-update
  runtime/bins    veil-node-runtime  veil-cli  ogate  oproxy  veilclient-ffi
veilcore/      residual: sim + integration glue + a few node/* shims
veilclient/    high-level SDK client
```

**29 separate crates extracted.** Tier 0, 1, and 2 are fully done. Tier 3 covers
every isolated subsystem, including the full sovereign-identity bundle and the
IPC server.

  - **veil-routing** ✅ — 9 modules (cache, vivaldi, probe, score,
    pow, loss_tracker, **discovery_forwarder**, **discovery_initiator**,
    **miss_handler**), 94 unit tests. Once the discovery pair landed,
    `miss_handler` followed via the `FrameBroadcaster` adapter plus two
    new traits — `RoutingLogger` and `RoutingMetrics`. The
    rate-limited route-flooder no longer reaches into veilcore's concrete
    `NodeLogger` / `NodeMetrics` / `SessionTxRegistry`.
    The `NextHopCache for RouteCache` trait impl moved from veilcore's
    `mesh_glue` into veil-routing itself (to satisfy the orphan rule).
    `crates/veil-routing/src/mod.rs` is now a pure re-export shim.

  - **veil-pex** — Peer Exchange: random-walk peer
    discovery with a PoW challenge and a signed response. Three modules
    (top-level lib helpers, `dispatcher`, `initiator`) totalling
    ~1k LOC, 8 unit tests. Three new trait/type surfaces drop the
    coupling to veilcore: `PexLogger` (info + warn), implemented by
    `NodeLogger`; `PexDispatchOutcome` (Response/NoResponse/Violation — a
    strict subset of `DispatchResult`), translated at the boundary
    in `veilcore::node::dispatcher::mod`; and `FrameBroadcaster`
    (already in veil-types), now extended with a 4th method,
    `active_node_ids() -> Vec<[u8; 32]>`, so PEX can enumerate live
    sessions for walk-seed selection and response routing without
    importing `SessionTxRegistry` directly. `cfg::PexConfig` is
    mirrored to veil-types. All 4 PEX message types
    (Walk/Challenge/Response/Result) are covered at the boundary.
    `crates/veil-pex/src/` was deleted.

  - **IPC server → veil-ipc + veil-local-transport** —
    the 3582-line `node::ipc` module lifted into two new crates.
    `veil-local-transport` (≈1057 LOC, 16 unit tests) holds the
    Unix-socket / TCP-loopback / 32-byte-token authentication plumbing
    shared between admin and IPC; admin still reaches it through
    `crate::node::local_transport` (a re-export shim). `veil-ipc`
    (≈3500 LOC) holds the frame protocol, the app-id binding state, and
    the debug-capture / transport-hints / recursive-query handlers.
    Three trait/type surfaces decouple it from veilcore: a new
    [`IpcMetrics`] trait (2 methods — `inc_ipc_delivery_drops` and
    `inc_rt_frames_tx`) implemented in `veil-observability` for
    `NodeMetrics`; [`IpcEndpointError`], which replaces the old
    `crate::node::Result` so the crate stays clear of veilcore's
    error tree; and `Arc<dyn FrameBroadcaster>` in place of
    `Arc<Mutex<SessionTxRegistry>>` (the production runtime wraps it via
    the `SessionTxBroadcaster` adapter). `IpcConfig` is mirrored to
    `veil_types`. `resolve_ipc_endpoint` and `ipc_anchor_path` now
    take an explicit `default_runtime_dir: &Path`, so the crate doesn't
    reach back into `cfg::runtime_veil_dir()`.

  - **Identity bundle → veil-identity** —
    the full sovereign-identity stack lifted out of `veilcore::cfg`
    and `veilcore::node::identity` into a single Tier-3 crate.
    The first lift (commit `305e5c2`, ≈2192 LOC) moved four self-contained
    persistence modules: `master_seed` (BIP39 mnemonic + 32-byte key),
    `master_file` (the Argon2id-encrypted at-rest format), `master_qr`
    (the offline QR backup-share codec), and `instance` (the per-device
    16-byte `instance_id`). It has no veil-internal dependencies, so
    wallet apps and recovery tooling can pull just this slice. 77 unit tests.
    The second lift (≈9700 LOC) moved `cfg::sovereign_flow` (`create_identity` /
    `restore_identity` / `load_identity_sk`) and `node::identity::*`
    (verify, publish, resolver, freshness, mlkem_fanout, pair_runtime,
    pair_transport, sovereign, error, integration_tests).
    Only `publisher_dht.rs` (the production Kademlia adapter)
    stayed in veilcore, because it depends on `KademliaService`
    directly. `veilcore/src/{cfg/sovereign_flow,node/identity/mod}.rs`
    are now re-export shims, so production paths through `cfg::*`
    and `node::identity::*` keep working unchanged.

  - **PendingAckTracker → veil-pending-ack** — the
    at-least-once delivery tracker (~280 LOC, 3 unit tests) lifted out of
    `veilcore::node::dispatcher::pending_ack`. It has no coupling to
    the dispatcher's internals — it depends only on the `veil_proto::budget`
    constants — so it stands as its own crate and unblocks the upcoming
    veil-ipc extraction, whose request handlers call `register`,
    `ack`, and `tick` directly. `crates/veil-dispatcher/src/pending_ack.rs`
    is now a pure re-export shim.

  - **TransportHintRegistry → veil-transport** — the
    per-scheme connect-outcome counter (~200 LOC) lifted from
    `veilcore::node::transport_hints` into `veil-transport::hint_registry`.
    The struct already implemented the `TransportHintSink` trait (also defined
    in veil-transport), so putting the two together removes the orphan-rule
    indirection and closes one of the IPC server's leftover leaks of a
    veilcore concrete type. `crates/veil-transport/src/hint_registry.rs` is now a
    pure re-export shim. All 5 of its unit tests, and all 39 veil-transport
    tests, still pass. This is a prerequisite for the upcoming veil-ipc
    extraction.

  - **veil-proxy** — SOCKS5 ingress, the exit proxy, and the veil-stream
    connector: three modules (`socks5`, `exit`,
    `veil_connector`) totalling ~1.6k LOC, 18 unit tests.
    `socks5.rs` had **zero** veilcore dependencies (it's pure RFC1928 protocol
    plus socket plumbing). `exit.rs` needed only `cfg::NodeRole`
    (already in veil-types) plus a single `inc_exit_proxy_dest_denied`
    metric call, which became the new `ProxyMetrics` trait. `veil_connector.rs`
    used `Arc<Mutex<SessionTxRegistry>>` for APP_OPEN / APP_DATA /
    APP_CLOSE; that became `Arc<dyn FrameBroadcaster>` end to end.
    `crates/veil-node-runtime/src/proxy/` is now a re-export shim plus the
    integration glue `tasks.rs`. (That glue builds the SessionTxBroadcaster
    adapters from the runtime's concrete types, and stays on the veilcore
    side because it needs `cfg::Config`, `FrameDispatcher.role`,
    `AppEndpointRegistry`, and so on.) The heavy end-to-end tests are
    deferred to the veilcore integration suite; the standalone test surface
    uses an in-process `RecordingBroadcaster` mock for trait-level coverage.

What's left — the node runtime, session, dispatcher, identity, cmd, sim, and
cfg-engine, plus the Tier-3 leaves (ipc, gateway-task) — was consolidated
into `veil-node-runtime` and `veil-cli`.

The trait-inversion count comes to **17** (TransportHintSink, BandwidthGuard,
MeshMetrics, BatterySink, NextHopCache, FrameRouter, RttHint,
CoordinateOracle, DhtMetrics, UpdateLogger, AbuseLogger, AppMetrics,
**FrameBroadcaster** [extended w/ active_node_ids], **RoutingLogger**,
**RoutingMetrics**, **PexLogger**, **ProxyMetrics**). `FrameBroadcaster` lives in
`veil-types`; its production adapter, `node::session_glue::SessionTxBroadcaster`,
wraps `Arc<Mutex<SessionTxRegistry>>` and is verified end to end by
`veilcore/tests/frame_broadcaster_adapter.rs`. `RoutingLogger` and
`RoutingMetrics` live next to their consumer in `veil-routing`, and
`PexLogger` likewise in `veil-pex`. Every cross-crate trait impl
for `NodeMetrics` / `NodeLogger` is consolidated into
`veil-observability`, which keeps them orphan-rule compliant.

The config-mirror count comes to 8 enums and structs in veil-types
(SignatureAlgorithm, NodeRole, DiscoveryMode, BootstrapPeer,
UpdateConfig, NatConfig, log/metrics enums, and **PexConfig**), plus
DhtRuntimeConfig in veil-dht.

## Why incremental matters

148 K lines of code. Every cycle-break touches dozens to hundreds of files. The
risk of subtle behavior regressions during a mass edit is high. Testing at each
phase boundary is the only way to hold the quality bar. Doing it incrementally —
one phase per session — is the responsible path.

## Why not "just do all phases in one go"

148 K lines of code. The cycles between cfg, proto, and crypto have to be broken
*before* extraction — that's what moving `SignatureAlgorithm` to a shared types
crate is for. Each cycle-break touches dozens to hundreds of files. The risk of
subtle behavior regressions during a mass edit is high, and testing at each
phase boundary is the only way to hold the quality bar. Doing it incrementally —
one phase per session — is the responsible path.
