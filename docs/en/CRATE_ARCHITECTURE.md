# Crate Architecture (target state)

Goal: split monolithic `veilcore` (148 K LOC) into focused crates,
each independently auditable / testable / future-extractable to its
own repo.  Workspace stays here for now; per-crate repos happen later.

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

Tiers are dependency layers — a tier may only depend on equal-or-lower tiers.

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

Detected cycles:

1. **cfg ↔ proto** — cfg::BootstrapPeer used in proto::bootstrap_bundle;
   proto::identity_document types used in cfg parsing.
2. **cfg ↔ crypto** — cfg::SignatureAlgorithm used by crypto;
   crypto::session_kdf types used in cfg.
3. **cfg → node** (test-only) — cfg/sovereign_flow.rs tests reference
   node::identity::verify::verify_identity_document.

## Migration order (multi-session)

Listed in dependency order — each step only requires prior steps done.

### Step: pure leaves

- **veil-util** — extract `util.rs`.  Zero internal deps; 37 callers
  to update with `s/crate::util/veil_util/`.

### Step: foundational types

- **veil-types** — new crate; receives:
  - `cfg::SignatureAlgorithm` (cycle-breaker for crypto/proto)
  - `cfg::NodeId`, `cfg::PeerId`, `cfg::ListenId`, `cfg::LinkId`
  - common error enums (`cfg::ConfigError` if viable)

  This breaks cycle (1) and (2) at the type level.  Refactor: every
  module that says `use crate::cfg::SignatureAlgorithm` switches to
  `use veil_types::SignatureAlgorithm`.

### Step: middle tier

- **veil-proto** — extract `proto/` once it depends only on
  veil-types + veil-util.
- **veil-crypto** — extract `crypto/` once it depends only on
  veil-types + veil-proto + veil-util.

### Step: identity + cfg

- **veil-cfg** — extract residual `cfg/` (without types now in
  veil-types).
- **veil-identity** — extract:
  - `crypto/identity.rs`
  - `cfg/sovereign_flow.rs`
  - `node/identity/`
  - `proto/identity_document.rs`, `proto/instance_registry.rs`,
    `proto/name_claim_v2.rs`, `proto/mlkem_cert.rs`

  Substantial because identity logic is currently scattered
  across cfg + crypto + proto + node.

### Step: transport + network primitives

- **veil-transport** — extract `transport/` once its 2 callbacks
  (TransportHintRegistry, Config::from_config) become trait-injected
  rather than direct-typed.
- **veil-dht** — extract `node/dht/`.
- **veil-mesh** — extract `node/mesh/` + UDP realm.
- **veil-anonymity** — extract `node/anonymity/`.

### Step: top-level

- **veil-node-runtime** — receives the residual `node/`.
- **veil-cli** — extract `cmd/`.

## Execution log

### Util crate

- `veil-util` extracted.  Workspace member added; 37 call sites
  preserved via re-export shim; build clean; tests green.

### Types crate

- `veil-types` crate created.  Hosts `SignatureAlgorithm` +
  `ParseEnumError`.
- 7 unit tests moved from cfg/model.rs.
- Re-export shim `pub use veil_types::{ParseEnumError, SignatureAlgorithm};`
  in cfg/model.rs preserves all 62 existing call sites.
- The cfg ↔ crypto AND cfg ↔ proto cycles are now broken AT THE
  TYPE LEVEL for SignatureAlgorithm specifically.  Other cfg
  types (NodeId, ConfigError) still create reverse-deps for crypto;
  subsequent steps address those.

### Error crate

Created tiny `veil-error` crate hosting `ConfigError` + `Result`
(the canonical type alias).  External deps `thiserror` + `base64`
+ `toml` + `serde_json` moved from veilcore to veil-error
(versions matched to veilcore's to avoid `?` operator From-trait
mismatches).

`cfg/error.rs` becomes a 7-line re-export shim:

```rust
pub use veil_error::{ConfigError, Result};
```

All callers continue working.  Crypto's 6 files updated to
`use veil_error::{ConfigError, Result}` directly.

### proto → crypto direction cut

Chose **Option A** (lift sign helpers).  Moved orchestration code from
`proto/` to the caller layer `node/`:

  - `proto::discovery::{sign_announcement, verify_announcement_signature}`
    →  `node::discovery::announcement_sig::*`
  - `proto::mesh::MeshBeaconPayload::verify_auth` (method)
    →  `node::mesh::auth::verify_mesh_beacon_auth` (free function)

Production callers (`node::dispatcher::routing`,
`node::dispatcher::discovery`, `node::discovery::directory`,
`node::mesh::beacon`) updated to the new paths.  Build/clippy clean;
touched-area tests green (node::mesh 61/61, node::discovery 33/33,
proto:: 516/516).

### crypto → proto direction cut

Moved three wire-format constants to `veil-types`:

  - `ALGO_ML_KEM_768`         (u8)
  - `ML_KEM_768_EK_LEN`       (usize)
  - `CERTIFY_CONTEXT`         (&[u8])

`proto/{prekey_bundle, identity_document}.rs` now re-export them from
veil-types to preserve existing call sites.  `crypto/{x3dh,
identity}.rs` import directly from veil-types.

After both directions cut:

  - 0 production refs `crypto → proto`
  - 0 production refs `proto → crypto`
  - 1 cfg(test) ref `proto::identity_contact` → `crypto::compute_node_id`
    (test-only — handled when proto becomes its own crate via either
    inlining the test or moving it).

The proto ↔ crypto structural cycle is now broken in production.
Both crates are extractable.

### Final cycle cleanup

Four targeted moves cleared every remaining production cross-ref between
proto/crypto and the rest of veilcore:

  1. Base64 serde helpers (`hex_array`, `serde_bytes_base64`) lifted
     from `node::dht::kademlia` to `proto::serde_base64` — kademlia now
     re-exports them, matching the natural layering.
  2. Legacy domain-identity validation helpers
     (`identity_signature_is_valid`, `identity_nonce_meets_difficulty`)
     moved from `crypto::identity` to `cfg::identity` — they take a
     `DomainIdentity` (cfg type) and orchestrate crypto primitives, so
     they belong at the caller layer.  Unused
     `identity_nonce_has_leading_zero` thin wrapper deleted.
  3. POW policy defaults (`DEFAULT_POW_DIFFICULTY` cfg(test)-aware,
     `DEFAULT_POW_TIMEOUT_SECS`) moved from `identity_policy::IdentityPolicy`
     to `crypto::pow::score`.  identity_policy now re-exports from
     crypto, reversing the prior crypto → identity_policy direction.
  4. `NodeRole` + `DiscoveryMode` enums (with `role_bits` byte
     constants) moved from `cfg::model` to veil-types.  Both are
     pure data and consumed by both cfg and proto::session
     (CapabilitiesPayload constructor).  cfg/model.rs and
     proto/session.rs re-export to preserve all call sites.

After all three direction cuts, the only remaining crate-internal
path refs from inside proto/crypto are in `#[cfg(test)]` test
functions (cross-derivation asserts) and doc-comment links.
Production code has zero deps in either direction.

### veil-proto extracted

`crates/veil-proto/` is now a standalone Tier-1 workspace member.

  - Deps: veil-types, veil-util, veil-error; external: serde,
    blake3, base64, thiserror, chacha20poly1305, ed25519-dalek, rand_core.
  - 30 source files moved (git rename ≥ 90% similarity for every file).
  - `crates/veil-proto/src/lib.rs` is a 1-line re-export shim
    (`pub use veil_proto::*;`) preserving every existing
    `crate::proto::X` import across cfg/, crypto/, node/, cmd/, sim/.
  - Cross-validation test `uri_roundtrips_against_a_real_identity_document`
    relocated to `veilcore/tests/identity_contact_roundtrip.rs`
    (cross-layer integration, doesn't belong inside proto).
  - `veil-proto`: 515/515 lib tests green standalone.

### veil-crypto extracted

`crates/veil-crypto/` is now a standalone Tier-1 workspace member,
sibling to veil-proto.

  - Deps: veil-types, veil-util, veil-error; external:
    ed25519-dalek, pqcrypto-falcon, ml-kem, x25519-dalek, blake3, hkdf,
    chacha20poly1305, sha2, zeroize, rand_core, base64, ctrlc, thiserror.
  - 11 files + the `pow/` submodule moved (≥ 88 % rename similarity).
  - `crates/veil-crypto/src/lib.rs` re-export shim preserves every existing
    `crate::crypto::X` call site.
  - `node_id_matches_cfg_node_id` cross-validation test relocated to
    `veilcore/tests/node_id_consistency.rs`.
  - `veil-crypto`: 64/64 lib tests green standalone.

### `cfg(test)` cross-crate gotcha — addressed

Both `veil-crypto::pow::score::DEFAULT_POW_DIFFICULTY` and
`veil-proto::name_claim_v2::required_difficulty` previously used
plain `cfg(test)` to drop production difficulty (24-28 bits) to test
difficulty (4-16 bits) for ms-per-test runs.  After extraction
`cfg(test)` only fires inside the producing crate, not in downstream
test profiles, so veilcore tests would burn through 20 M PoW attempts
per case (× 18 tests = minutes of timeouts).

Fix: a `test-low-difficulty` cargo feature on each crate, gated as
`cfg(any(test, feature = "test-low-difficulty"))`.  `veilcore`'s
`[dev-dependencies]` re-list both crates with the feature on; cargo's
feature unification means veilcore's test profile compiles with low
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

Util, types, error, and proto/crypto extraction steps — done.

### Tier-2 / Tier-3 extractions

  - **veil-transport** ✅ (`crates/veil-transport`) — TCP, QUIC,
    TLS (rustls + optional BoringSSL via `tls-boring`), WebSocket,
    SOCKS5 proxy, Unix sockets.  Two cross-layer deps inverted:
    `Context::from_config` lifted to `cfg::transport_glue`,
    `TransportHintRegistry` reduced to a `TransportHintSink` trait.
    34/34 lib tests green standalone.

  - **veil-anonymity** ✅ (`crates/veil-anonymity`) — onion
    routing, fixed-size cells, circuits, relay directory, rendezvous
    points, packet wrappers.  Cleanest target — only `cfg::SignatureAlgorithm`
    (already in veil-types) and `crypto::*` deps.  117/117 lib tests
    green standalone.

  - **veil-mesh** ✅ (`crates/veil-mesh`) — beacon discovery,
    realm-scoped UDP broadcast, neighbor table, gateway-bridge.  Four
    trait inversions for cross-layer deps:
    `BandwidthGuard` (PerPeerLimiter), `MeshMetrics` (NodeMetrics),
    `BatterySink` (RttTable), `NextHopCache` (RouteCache).
    `veilcore::node::mesh_glue` collects the concrete adapters.
    59/59 lib tests green standalone.

### Remaining

  - **veil-cfg / veil-identity:** residual `cfg/` and the
    sovereign-identity bundle (`crypto::identity` callers in cfg,
    `node::identity/`).  Both are still entangled with each other
    and with `node::dht`; will need a `DhtPublishSink` trait in
    veil-identity to break the dht-publisher coupling.

### veil-dht extracted

`crates/veil-dht/` is now a standalone Tier-3 workspace member:
Kademlia routing + k-bucket, iterative lookups, tiered key-value
store, transport-resolution cache, lookup LRU, network-querier.

Four cross-layer concrete-type couplings inverted via traits in
`veil_dht::traits`:

  - `FrameRouter` — pre-encoded frame dispatch (was `SessionOutbox`).
    Implemented directly on `SessionOutbox` in `node::dht_glue`.
  - `RttHint` — RTT-aware contact ordering (was `RttTable::get(peer).rtt_ms`).
    `RttHintAdapter` wraps `Arc<Mutex<RttTable>>`.
  - `CoordinateOracle` — Vivaldi distance estimate (was
    `VivaldiCoord::distance_estimate(peer)` + per-peer cache).
    `VivaldiOracle` adapter combines local coord and per-peer cache.
  - `DhtMetrics` — `inc_dht_store` / `inc_dht_lookup` counters
    (implemented directly on `NodeMetrics`).

`cfg::DhtConfig` mirrored as a smaller `DhtRuntimeConfig` in veil-dht
(drops persistence-path fields the DHT internals don't touch);
`runtime_config_from(&cfg)` converts at runtime boundaries.

`veil-dht`: 109/109 lib tests green standalone.

### veil-bootstrap + veil-update extracted

Two more Tier-3 crates extracted, both bootstrappable independently:

  - **veil-bootstrap** — DNS-TXT seed records, signed/encrypted
    invites, HTTPS bundle fetch, builtin seeds.  Zero out-of-base deps;
    only `cfg::BootstrapPeer` lifted to veil-types alongside it.
    82/82 lib tests green standalone.
  - **veil-update** — self-update (signed manifest,
    multi-CDN failover, anti-downgrade timestamp, atomic swap, periodic
    check task).  `cfg::UpdateConfig` lifted to veil-types;
    `NodeLogger` inverted via `UpdateLogger` trait.
    73/73 lib tests green standalone.

### Done (veil-node-runtime + veil-cli)

The residual session runtime (`node/session`, `node/runtime`,
`node/dispatcher`, `node/observability`, `node/abuse`, `node/routing`,
`node/identity`, `node/transfer`, `node/anycast`, `node/gateway`, …)
became **`veil-node-runtime`**; `cfg/` split into **`veil-cfg`**,
`identity_*` into **`veil-identity`**, and `cmd/` (the CLI surface)
into **`veil-cli`**.

### Where we stand

The extraction is **complete**: **53 workspace members** — 51 crates under `crates/`
plus the top-level `veilcore` and `veilclient`. `veilcore` is now a thin
residual (sim + integration glue + a few `node/*` shims); the extracted node runtime
lives in **`veil-node-runtime`**. (Per-crate test counts move quickly — see
`cargo nextest list` for the live numbers.)

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

**29 separate crates extracted.** Tier 0/1/2 fully done.  Tier 3 has
every isolated subsystem including the full sovereign-identity bundle
and the IPC server.

  - **veil-routing** ✅ — 9 modules (cache, vivaldi, probe, score,
    pow, loss_tracker, **discovery_forwarder**, **discovery_initiator**,
    **miss_handler**) — 94 unit tests.  After the discovery pair landed,
    `miss_handler` followed via the `FrameBroadcaster` adapter plus two
    new trait surfaces — `RoutingLogger` and `RoutingMetrics` — so the
    rate-limited route-flooder no longer reaches into veilcore's
    `NodeLogger` / `NodeMetrics` / `SessionTxRegistry` concretes.
    Trait-impl `NextHopCache for RouteCache` moved from veilcore's
    `mesh_glue` to veil-routing itself (orphan-rule fix).
    `crates/veil-routing/src/mod.rs` is now a pure re-export shim.

  - **veil-pex** — Peer Exchange: random-walk peer
    discovery with PoW-challenge + signed-response.  Three modules
    (lib top-level helpers, `dispatcher`, `initiator`) totalling
    ~1k LOC, 8 unit tests.  Three new trait/type surfaces drop the
    veilcore coupling: `PexLogger` (info + warn) implemented by
    `NodeLogger`; `PexDispatchOutcome` (Response/NoResponse/Violation
    — strict subset of `DispatchResult`) translated at the boundary
    in `veilcore::node::dispatcher::mod`; and `FrameBroadcaster`
    (already in veil-types) was extended with a 4th method,
    `active_node_ids() -> Vec<[u8; 32]>`, so PEX can enumerate live
    sessions for walk-seed selection / response routing without
    importing `SessionTxRegistry` concretely.  `cfg::PexConfig`
    mirrored to veil-types.  All 4 PEX message types
    (Walk/Challenge/Response/Result) covered by the boundary.
    `crates/veil-pex/src/` deleted.

  - **IPC server → veil-ipc + veil-local-transport** —
    the 3582-line `node::ipc` module lifted into two new crates.
    `veil-local-transport` (≈1057 LOC, 16 unit tests) holds the
    Unix-socket / TCP-loopback / 32-byte-token authentication plumbing
    shared between admin and IPC; admin still references it through
    `crate::node::local_transport` (re-export shim).  `veil-ipc`
    (≈3500 LOC) holds the frame protocol, app-id binding state, and
    debug-capture / transport-hints / recursive-query handlers.
    Three trait/type surfaces decouple from veilcore: a new
    [`IpcMetrics`] trait (2 methods — `inc_ipc_delivery_drops`,
    `inc_rt_frames_tx`) implemented in `veil-observability` for
    `NodeMetrics`; [`IpcEndpointError`] replacing the old
    `crate::node::Result` so the crate stays free of veilcore's
    error tree; and `Arc<dyn FrameBroadcaster>` instead of
    `Arc<Mutex<SessionTxRegistry>>` (production runtime wraps via
    `SessionTxBroadcaster` adapter).  `IpcConfig` mirrored to
    `veil_types`.  `resolve_ipc_endpoint` / `ipc_anchor_path` now
    take an explicit `default_runtime_dir: &Path` so the crate doesn't
    reach back into `cfg::runtime_veil_dir()`.

  - **Identity bundle → veil-identity** —
    the full sovereign-identity stack lifted out of `veilcore::cfg`
    and `veilcore::node::identity` into a single Tier-3 crate.
    First lift (commit `305e5c2`, ≈2192 LOC): four self-contained
    persistence modules — `master_seed` (BIP39 mnemonic + 32-byte key),
    `master_file` (Argon2id-encrypted at-rest format), `master_qr`
    (offline QR backup share codec), `instance` (per-device 16-byte
    `instance_id`).  Zero veil-internal deps — wallet apps and
    recovery tooling can pull just this slice.  77 unit tests.
    Second lift (≈9700 LOC): `cfg::sovereign_flow` (`create_identity` /
    `restore_identity` / `load_identity_sk`) and `node::identity::*`
    (verify, publish, resolver, freshness, mlkem_fanout, pair_runtime,
    pair_transport, sovereign, error, integration_tests) all moved
    over.  Only `publisher_dht.rs` (the production Kademlia adapter)
    stayed in veilcore because it depends on `KademliaService`
    directly.  `veilcore/src/{cfg/sovereign_flow,node/identity/mod}.rs`
    are now re-export shims; production code paths through `cfg::*`
    and `node::identity::*` keep working unchanged.

  - **PendingAckTracker → veil-pending-ack** — the
    at-least-once delivery tracker (~280 LOC, 3 unit tests) lifted out of
    `veilcore::node::dispatcher::pending_ack`.  Zero coupling to
    dispatcher internals — only depends on `veil_proto::budget`
    constants — so it stands as its own crate and unblocks the upcoming
    veil-ipc extraction whose request handlers call `register` /
    `ack` / `tick` directly.  `crates/veil-dispatcher/src/pending_ack.rs`
    is now a pure re-export shim.

  - **TransportHintRegistry → veil-transport** — the
    per-scheme connect-outcome counter (~200 LOC) lifted from
    `veilcore::node::transport_hints` into `veil-transport::hint_registry`.
    The struct already implemented the `TransportHintSink` trait (also defined
    in veil-transport), so co-locating both removes the orphan-rule
    indirection and eliminates one of the IPC server's residual veilcore
    concrete-type leaks.  `crates/veil-transport/src/hint_registry.rs` is now a
    pure re-export shim.  All 5 unit tests + 39 total veil-transport
    tests still pass.  Prerequisite for the upcoming veil-ipc extraction.

  - **veil-proxy** — SOCKS5 ingress + exit proxy + veil-stream
    connector: three modules (`socks5`, `exit`,
    `veil_connector`) totalling ~1.6k LOC, 18 unit tests.
    `socks5.rs` had **zero** veilcore deps (pure RFC1928 protocol +
    socket plumbing).  `exit.rs` only needed `cfg::NodeRole`
    (already in veil-types) plus a single `inc_exit_proxy_dest_denied`
    metric call → new `ProxyMetrics` trait.  `veil_connector.rs`
    used `Arc<Mutex<SessionTxRegistry>>` for APP_OPEN / APP_DATA /
    APP_CLOSE — replaced by `Arc<dyn FrameBroadcaster>` end-to-end.
    `crates/veil-node-runtime/src/proxy/` is now a re-export shim plus the
    integration glue `tasks.rs` (constructs SessionTxBroadcaster
    adapters from runtime concretes — kept veilcore-side because
    it needs `cfg::Config`, `FrameDispatcher.role`, `AppEndpointRegistry`,
    etc.).  Heavy end-to-end tests deferred to veilcore integration
    suite; standalone test surface uses an in-process
    `RecordingBroadcaster` mock for trait-level coverage.

Residual = node runtime / session / dispatcher / identity / cmd / sim /
cfg-engine + Tier-3 leaves (ipc, gateway-task) → consolidated
into `veil-node-runtime` + `veil-cli`.

Total trait-inversion count: **17** (TransportHintSink, BandwidthGuard,
MeshMetrics, BatterySink, NextHopCache, FrameRouter, RttHint,
CoordinateOracle, DhtMetrics, UpdateLogger, AbuseLogger, AppMetrics,
**FrameBroadcaster** [extended w/ active_node_ids], **RoutingLogger**,
**RoutingMetrics**, **PexLogger**, **ProxyMetrics**).  `FrameBroadcaster` lives in
`veil-types` (production adapter `node::session_glue::SessionTxBroadcaster`
wraps `Arc<Mutex<SessionTxRegistry>>`, verified end-to-end by
`veilcore/tests/frame_broadcaster_adapter.rs`).  `RoutingLogger`,
`RoutingMetrics` live next to their consumer in `veil-routing`;
`PexLogger` similarly in `veil-pex`.  All cross-crate trait impls
for `NodeMetrics` / `NodeLogger` are consolidated into
`veil-observability` (orphan-rule compliant).

Total config-mirror count: 8 enums/structs in veil-types
(SignatureAlgorithm, NodeRole, DiscoveryMode, BootstrapPeer,
UpdateConfig, NatConfig, log/metrics enums, **PexConfig**) +
DhtRuntimeConfig in veil-dht.

## Why incremental matters

148 K LOC.  Every cycle-break touches dozens-to-hundreds of files.
Risk of subtle behavior regressions during mass-edit is high.
Testing at each phase boundary is the only way to maintain quality
bar.  Doing it incrementally — one phase per session — is the
responsible path.

## Why not "just do all phases in one go"

148 K LOC.  Cycles between cfg + proto + crypto require breaking
those cycles BEFORE extraction (move `SignatureAlgorithm` to a
shared types crate).  Each cycle-break touches dozens-to-hundreds
of files.  Risk of subtle behavior regressions during mass-edit is
high; testing at each phase boundary is the only way to keep
quality bar.  Doing it incrementally — one phase per session — is
the responsible path.
