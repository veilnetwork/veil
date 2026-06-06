# veilcore extraction — scope & multi-session plan

> Status: **COMPLETE ✅** — all phases shipped 2026-05-21. `veilcore` is now a
> thin re-export shim + integration-test crate over the `crates/veil-*` family
> (veil-cfg, veil-session, veil-dispatcher, veil-node-runtime,
> veil-cli, …); `veilcore/src/node/*.rs` are re-export facades (kept on
> purpose for `crate::node::X` back-compat paths used by the integration tests).
> This document is retained as the **historical record** of the extraction
> campaign — the Phase / estimate / re-open-trigger sections below describe the
> work as it was *planned*, not as pending.

## Why

`veilcore/` is the last monolith. Roughly 98 KLoC of Rust sit under a
single Cargo target — runtime orchestration, session state machines,
dispatcher routing, CLI and config plumbing, sim infrastructure, and the
built-in service hosts, all in one place. Every new feature makes three
things worse: build time, cyclic dependencies, and the "where does X live?"
problem.

Three concrete pains drive the extraction:

1. **Build amplification.** Touch one file in `node/runtime/services.rs`
   and you recompile the whole 98 KLoC plus the CLI binary. The
   session-runner decomposition campaign (slices 25–28) paid a 60–90 s
   rebuild tax on every single iteration.
2. **Test isolation.** `cargo test -p veilcore` takes 3 min cold, 90 s
   warm — and most of that 90 s is tests that have nothing to do with what
   you changed. Splitting the target gives you focused, per-crate test
   sweeps.
3. **Hidden coupling.** `node/runtime/` imports from `node/dispatcher/`,
   `node/session/`, and `node/routing/` — and they import back. A real
   crate boundary turns each of those tangles into a compile error, so the
   coupling we'd rather break shows itself instead of hiding.

One non-goal: anything that touches the **wire format**, the **on-disk
format**, or the **public CLI surface**. This is a pure refactor —
caller-visible behavior stays byte-identical at every commit.

## Current layout (size survey)

```
veilcore/src/
├── lib.rs          + transport.rs + proto.rs + util.rs + ...   ~ 2 KLoC
├── cfg/                                                        ~ 9 KLoC
├── cmd/                  (CLI command handlers)                ~14 KLoC
├── sim/                  (network simulator)                   ~ 7 KLoC
├── bin/cli.rs            (CLI entry)                           ~ 1 KLoC
└── node/                                                       ~65 KLoC
    ├── runtime/          (orchestrator: lifecycle, services)   19.5 KLoC
    ├── session/          (per-peer state machine)              18.3 KLoC
    ├── dispatcher/       (frame routing, anonymity, delivery)  13.4 KLoC
    ├── gateway/          + builtin/ + proxy/                    2.5 KLoC
    ├── routing/                                                 0.3 KLoC
    ├── identity/                                                0.5 KLoC
    └── admin.rs (4.3K) + outbound_connector.rs (0.8K) + ...   ~11 KLoC
```

Top single-file offenders (worth keeping in mind while planning splits):
- `node/dispatcher/mod.rs` — 5.5 KLoC
- `node/session/runner_tests.rs` — 5.3 KLoC
- `node/runtime/mod.rs` — 5.0 KLoC
- `node/admin.rs` — 4.3 KLoC
- `cmd/sovereign_identity.rs` — 4.0 KLoC
- `cfg/model.rs` — 3.9 KLoC

## Target topology

Five new crates under `crates/`, plus a thin `veilcore` shell that
re-exports them for downstream callers. The shell keeps
`use veilcore::node::NodeRuntime` working through the transition, so
existing call sites don't churn:

| New crate                  | Lifts from           | Approx LoC | Public surface                          |
|----------------------------|----------------------|-----------:|-----------------------------------------|
| `veil-cfg`              | `cfg/`               |       ~9 K | `CoreConfig`, validators, format I/O    |
| `veil-session`          | `node/session/`      |      ~18 K | `SessionRunner`, `Handshake`, ticket    |
| `veil-dispatcher`       | `node/dispatcher/`   |      ~14 K | `FrameDispatcher`, routing, delivery    |
| `veil-node-runtime`     | `node/runtime/` + top-level `node/*.rs` | ~30 K | `NodeRuntime`, lifecycle, services      |
| `veil-cli` (binary)     | `bin/`, `cmd/`       |      ~15 K | `veil-cli` binary, command handlers  |
| `veilcore` (shim)       | `lib.rs`, `sim/`     |       ~9 K | re-exports + sim runner                 |

### Dependency DAG (target)

```
veil-cfg ────────────────────────────────────────────┐
                                                     ↓
veil-session ──→ veil-dispatcher ──→ veil-node-runtime
                                                     │
                                          ┌──────────┘
                                          ↓
                                      veilcore (sim + re-exports)
                                          ↓
                                      veil-cli (binary)
```

Acceptance, three checks: `cargo deps` reports no cycle; each crate
compiles in isolation; and downstream crates (`veil-app`, `veil-ipc`, ...)
import from the new fine-grained crates, reaching for the `veilcore` shim
only when they actually need sim helpers.

## Risk inventory

| Risk                                          | Mitigation                                                                   |
|-----------------------------------------------|------------------------------------------------------------------------------|
| Circular dep `session ↔ dispatcher`          | Phase 1 first reads coupling; trait-extract the seam before splitting        |
| `cfg::model::CoreConfig` referenced everywhere | Pull `veil-cfg` first (fewest inbound edges); freeze its API before next  |
| Test-helpers spread across `test_support.rs` | Move alongside the code under test; mark `pub(crate)` first to find leaks    |
| Feature flags (`rocksdb-cold`, `tls-boring`)  | Each new crate gets its own feature set; root `veilcore` aliases preserve |
| External branches with WIP                    | Schedule splits behind a 3-day merge freeze; coordinate in parallel-sessions |
| sim/* depends on internal node state          | Stays in `veilcore` shim until session/dispatcher publics stabilise       |

## Multi-session execution plan

One session = one crate carved out, CI green, committed. Each session is
designed to be *independently revertible*: if Phase N brings a performance
regression or a subtle behavior shift, `git revert` it and every prior
phase stays put.

### Phase 1 — `veil-cfg` (smallest blast radius) — ✅ SHIPPED 2026-05-21

Commit `4f64f87`.  All 5852 LoC moved in one session (~3 hours) after
pre-Phase-1 cycle-break.  `cargo check --workspace` green, 123/123
`veil-cfg --lib` tests pass, zero external-caller code changes
needed (re-export from veilcore lib.rs).

**Move:** the **entire** `crates/veil-cfg/src/` tree → `crates/veil-cfg/src/`.

> **Pre-Phase-1 prerequisite (shipped 2026-05-21, commit `b728161`)**:
> moved `crates/veil-cfg/src/identity_ops.rs` + `crates/veil-cfg/src/identity_policy.rs`
> into `cfg/` to break the `cfg ↔ identity_ops` cycle.  Backwards-compat
> re-exports preserved in `crate::lib.rs`.  Without this fix, Phase 1
> would hit a circular crate dep (cfg's validators imported identity_ops
> which imported cfg).
>
> **Original plan said**: move only `cfg/{mod, model, format/*, validate/*}.rs`.
> **Issue found**: that subset can't stand alone as a sibling crate. The
> mod.rs that would move declares `pub(crate) mod identity` and friends,
> pointing at files (identity.rs, store.rs, transport_glue.rs, …) that
> stay behind in veilcore — and Rust won't let a module's children live in
> a different crate from the module.
> **Revised scope**: move the **entire** cfg/ tree (~5852 LoC). Still the
> "smallest blast radius," since cfg depends on nothing in `node/*`.

**Why first:** It's pure data and validators — no dependencies on `node/*`,
no async, no sim hooks. That also makes its acceptance test the fastest:
just confirm downstream `use veilcore::cfg::*` still resolves through the
re-export.

**Steps:**
1. `cargo new --lib crates/veil-cfg` ; copy entire `cfg/` tree.
2. Resolve internal `use crate::cfg::*` → bare module paths.
3. Resolve cfg's external deps:
   * `crate::crypto` → `veil-crypto` (already a separate crate).
   * `crate::transport` → `veil-transport` (already a separate crate).
   * `crate::proto` → `veil-proto` (already a separate crate).
4. `veilcore/src/lib.rs` adds `pub use veil_cfg as cfg`.
5. `cargo check --workspace` ; run full test sweep.
6. Single commit. CI green.

**Exit gate:** zero callers in `node/` reference internal cfg paths;
external callers (`veil-ipc`, `veil-app`) compile unchanged.

**Estimated time:** revised to **2 sessions** (was 1) — larger scope plus
external-dep resolution (veil-crypto, veil-transport, veil-proto
typed-imports plumbing).

### Phase 2 — `veil-session` (the state machine)

**Move:** `crates/veil-session/src/` → `crates/veil-session/src/`.

**Pre-work (status as of 2026-05-21)**:

| Cycle break | Status | Commit |
|---|---|---|
| `session → runtime::handoff` (registry + ack waiters + swap registry + RAII guards, ~1110 LoC) | ✅ shipped | `20a015a` — moved to `session/handoff.rs`, runtime keeps thin re-export |
| `session → runtime::hot_standby` (HotStandbyController, ~479 LoC) | ✅ shipped | `20a015a` — same |
| `session → runtime::local_battery_level()` (1 fn) | ✅ shipped | `23025e9` — moved to neutral `node/battery.rs` |
| `session → dispatcher::FrameDispatcher` (11 call sites in runner.rs + 14 in tests) | ✅ shipped | `8f37115` — `DispatcherSink` trait + impl on FrameDispatcher; SessionRunner.dispatcher field type swapped to `Arc<dyn DispatcherSink>` |

**`DispatcherSink` trait design (audit complete, Phase 2 session 1 shipped at `8f37115`)**:

Trait methods needed (one per access point in `runner.rs`):

```rust
pub trait DispatcherSink: Send + Sync {
    // Hot-path (every frame):
    fn dispatch(&self, header: &FrameHeader, body: PooledShared, peer_id: PeerId) -> DispatchResult;
    fn capture_outbound(&self, peer_id: PeerId, frame: &[u8]);
    fn allow_outbound_bandwidth(&self, bytes: usize) -> bool;  // wraps lock!(abuse.outbound_bandwidth)
    fn logger(&self) -> &NodeLogger;

    // Setup / rare-event:
    fn session_tx_registry(&self) -> Option<Arc<RwLock<SessionTxRegistry>>>;
    fn dht_transport_cache(&self) -> Arc<DhtTransportCache>;
    fn rendezvous_weak(&self) -> Mutex<Option<Weak<RendezvousController>>>;
    fn pow_solver_semaphore(&self) -> Arc<Semaphore>;
    fn pow_active_difficulty(&self) -> Arc<AtomicU64>;
}
```

**Layering blocker discovered**: trait return types `RendezvousController`
+ `DispatchResult` currently live in `veilcore::node::*`.  If the
trait moves to `veil-session` crate, those types must move too —
otherwise we get a circular crate dep (veil-session → veilcore
for return-type definitions).

**Phase 2 session 1 (shipped at `8f37115`)**:
* `DispatchResult` + `FrameDispatcher` promoted to `pub` (was `pub(crate)`).
* `DispatcherSink` trait defined in `session/dispatcher_sink.rs` (~200 LoC)
  with 11 typed methods + `arc_sink<T>` unsizing helper.
* `FrameDispatcher` impls `DispatcherSink` (delegation block).
* `SessionRunner.dispatcher: Arc<FrameDispatcher>` swapped to
  `Arc<dyn DispatcherSink>` — all 11 access points in runner.rs use
  trait methods (no direct field access).
* `SessionAliasGuard` updated to hold `Arc<dyn DispatcherSink>`.
* 14 SessionRunner construction sites in tests use `arc_sink` helper.
* 237 tests pass, 1 pre-existing flake unrelated.

**Phase 2 session 2 prep — ALL audit/decoupling shipped 2026-05-21**:

After session 1, session-side production imports went through three
prep-batch commits:

* `72f12f4`: `node::rendezvous` (1391 LoC) moved to `session::rendezvous`
  — session-domain per `dispatcher_sink` module doc.  `node::mod.rs`
  keeps `pub use session::rendezvous` re-export so external callers
  (veilclient, dispatcher routing, runtime services + binder)
  compile unchanged.
* `06b9603`: `DispatchResult` enum moved from `node::dispatcher::mod.rs`
  to `session::dispatcher_sink.rs` — it is the return type of the
  trait method `DispatcherSink::dispatch`, so naturally belongs
  alongside the trait.  `hex_short` helper canonicalized to
  `veil-util` (joins `bytes_to_hex` there) — session crate
  imports it directly without a cycle through veilcore.
* `63a512b`: `runner.rs` drops the stale `FrameDispatcher` import
  (no longer used after Phase 2 session 1 field-type swap).

**Production session-side imports after prep (final state)**:

All `crate::*` paths inside `crates/veil-session/src/*.rs` now
resolve either to (a) self-references (`crate::node::session::*`)
or (b) re-exports of existing sibling crates:

| Import path | Sibling crate |
|---|---|
| `crate::crypto::*` | `veil-crypto` |
| `crate::node::abuse::*` | `veil-abuse` |
| `crate::node::observability::*` | `veil-observability` |
| `crate::node::e2e::*` | `veil-e2e` |
| `crate::node::identity::*` (verify) | `veil-identity` |
| `crate::node::types::NodeIdBytes` | `veil-types` (equivalent alias) |
| `crate::node::util::hex_short` | `veil-util` (`63a512b`) |
| `crate::proto::*` | `veil-proto` |
| `crate::transport::*` | `veil-transport` |
| `crate::cfg::*` | `veil-cfg` (Phase 1 `4f64f87`) |

Conclusion of **surface-level** audit: every top-level external dep
already lives in a sibling crate.  However, see **Deeper-dep discovery
(attempted move 2026-05-21)** below.

**Deeper-dep discovery — attempted-move blockers**:

Session-side production code references several veilcore-private
modules not captured in the surface audit.  Discovered when actually
attempting the move (work reverted; workspace clean):

| Reference | Where it lives | Status |
|---|---|---|
| `crate::node::error::{NodeError, Result}` | `crates/veil-node-runtime/src/error.rs` — `pub enum NodeError` + `pub type Result<T>` | Not yet extracted to a sibling crate.  Used by `session::handshake` and likely others. |
| `crate::node::local_identity::HandshakeIdentity` | `crates/veil-node-runtime/src/local_identity.rs` — `pub(crate) struct` | Veilcore-private struct.  Used by `session::handshake::perform_ovl1_handshake`. |
| Multi-level nested `use crate::{ ... }` blocks | Top-level paths like `node::{ error::*, local_identity::* }` | Mechanical sed insufficient; need a proper Rust-aware import-rewriter. |

**Phase 2 session 2 pre-step — ALL deeper-dep blockers cleared 2026-05-21**:

Five additional pre-step commits decouple session/handshake.rs from
veilcore-private modules:

* `8bdb0c0` — narrow `HandshakeError(String)` defined in session/handshake.rs;
  `impl From<HandshakeError> for NodeError` in veilcore::node::error
  preserves the ergonomic `?` chain.  Replaces 50+ `NodeError::Handshake`
  call sites.
* `aa33c0b` — `LocalHandshakeIdentity: Send + Sync` trait defined in
  session/handshake.rs; `perform_ovl1_handshake` takes `&dyn LocalHand
  shakeIdentity` instead of `&HandshakeIdentity`.  Blanket impl on
  `Arc<T>` avoids surface rewrite at the 3 callers.  `HandshakeIdentity`
  impls the trait in `veilcore::node::local_identity`.
* `653dcb6` — drop the now-unused `HandshakeIdentity` import from
  session/handshake.rs prelude (replaced by the trait).
* `4d4cb9f` — `local_battery_level()` canonicalized to veil-util;
  `bufpool::global()` call sites switched to `veil_bufpool::global()`
  direct.
* `5b3ffa6` — `NetworkAccessGate` (480 LoC module) moved to veil-
  identity (already had all the type dependencies — veil-identity::
  network_ban + network_cert + veil-types).

After these, session/handshake.rs production code references only:
self (`crate::*`), veil-cfg, veil-crypto, veil-proto,
veil-identity (verify::*, network_access::*), veil-transport
(via re-export).  ALL veilcore-private imports cleared.

**Remaining blocker — test fixtures**:

`runner_tests.rs` (5.3 KLoC) and `chaos_sim.rs` import
`crate::node::dispatcher::make_test_dispatcher`, which constructs a
real `FrameDispatcher` (still in veilcore::dispatcher).  Strategies
for Phase 2 session 2:

* **Strategy A (recommended)**: leave tests in veilcore.  Move only
  production code to `veil-session` crate; tests stay in
  `crates/veil-session/src/runner_tests.rs` testing session via
  its public API.  After session moves: tests `use veil_session::SessionRunner`.
  Zero test rewrite; the trait-object pattern already supports this.
* Strategy B: build a `MockDispatcherSink` struct in `veil-session`
  tests.  Massive 5KLoC test rewrite — rejected as overkill.

**Phase 2 session 2 actual move — SHIPPED at `b1d2acb` 2026-05-21**:

* New crate `crates/veil-session/{Cargo.toml, src/lib.rs}` with 14
  sibling deps + standard externals.
* 27 production files moved via `git mv` (chaos_sim + runner_tests +
  integration_tests stay in veilcore per Strategy A).
* Path-rewrite sweep via custom Python balanced-brace parser handled
  multi-line nested `use crate::{ ... }` blocks that sed couldn't.
* `pub(crate)` → `pub` bulk-promote on session items so veilcore
  (now a consumer crate) reaches them.  3 method-level `#[cfg(test)]`
  gates removed for cross-crate test access.
* `impl DispatcherSink for FrameDispatcher` moved to
  `crates/veil-dispatcher/src/sink_impl.rs` (orphan rule —
  FrameDispatcher is veilcore-local).
* `impl veil_dht::FrameRouter for SessionOutbox` moved to
  `crates/veil-session/src/outbox.rs` (orphan rule — SessionOutbox
  is veil-session-local).
* `encode_routing_frame` inlined in session/runner.rs (one call site).
* `crates/veil-session/src/mod.rs` rewritten as a thin re-export
  shim of veil-session — preserves `crate::node::session::X`
  callable paths for all existing veilcore in-tree callers.
* runner_tests.rs gained explicit imports (mpsc, BoxIoStream, NodeIdBytes,
  SessionMsg) for items previously pulled in via `use super::*;`.

cargo check --workspace --tests: clean.  71/71 session tests pass (1
pre-existing flake `phase650b_mutual_rekey_collision_kept_init_when_local
_node_id_lower` unrelated; reproduces on master).

**Pre-work session takeaway**: zero session-side production code now
references `crate::node::runtime::*` directly.  Remaining
dispatcher-trait extraction is a discrete next-session task that
benefits from not being bundled with the cycle-break audit work.

**Tests:** `runner_tests.rs` (5.3 KLoC) moves with the code; isolated
test sweep should drop session-test wall-time from ~40 s to ~15 s.

**Exit gate:** `cargo test -p veil-session` passes; `veilcore`
re-exports `session::*`; downstream sites compile via the re-export.

**Estimated time:** 2 sessions. First session = trait extraction +
green; second = the actual move + downstream fix.

### Phase 3 — `veil-dispatcher`

**Move:** `crates/veil-dispatcher/src/` → `crates/veil-dispatcher/`
(~14 KLoC across 11 files; mod.rs 5534 + routing.rs 3373 + delivery.rs
2272 LoC are the biggest).

**Phase 3 prep shipped 2026-05-21**:

| Commit | Slice |
|---|---|
| `57fa094` | `session_glue::SessionTxBroadcaster` (47 LoC adapter) moved to `veil-session::glue` |
| `af90bbe` | `CongestionMonitor` (273 LoC) → new `veil-congestion` crate |
| `807c0c9` | `ReputationTracker` (369 LoC) → new `veil-reputation` crate |
| `bc9fc56` | 4 generic util helpers (hex_str, unix_secs_now_u32/u64, redact_addr_for_log) canonicalized to `veil-util`; veilcore keeps re-export shim |

After prep, dispatcher's `crate::node::*` references resolve to:
* Sibling-crate re-exports: abuse, anonymity, app, congestion (new),
  dht, discovery, e2e, gateway_list, identity, mesh, nat, proxy,
  rendezvous (via session shim), reputation (new), routing, session
  (via session shim), session_glue (via session shim), transfer.
* Veilcore-local (need handling in actual move): `dispatcher` (self —
  moves to the new crate), `types` (mix of veil-cfg + veil-types
  aliases), `util::build_own_host_candidates` (veilcore-internal —
  could move to veil-nat or stay in veilcore as a runtime helper).

**Phase 3 actual-move SHIPPED 2026-05-21 (`95afe8c`)**:

After 3 deeper-dep pre-work commits (see above), the actual move
landed cleanly:

* `ControlPlaneService` → `veil_routing::control_plane` (`abe6470`)
* `GatewayService` + 4 sub-modules → `veil_gateway` (`543bd6a`)
* `PeerLruCache` + `PeerPubkeysCache` → `veil_types` (`66746d0`)

Then mechanical move (`95afe8c`):

* 11 production files (~14 KLoC) moved to `crates/veil-dispatcher/`
  (anonymity, app, control, delivery, diag, discovery, lib, pending_ack,
  routing, session, sink_impl).
* Path-rewrite sweep via balanced-brace Python parser handled multi-line
  nested `use crate::{...}` blocks correctly.
* `pub(crate)` + `pub(super)` bulk-promoted to `pub`.
* `impl DispatcherSink for FrameDispatcher` moved with rest of dispatcher
  (`sink_impl.rs`) — orphan rule satisfied automatically now, FrameDispatcher
  lives with DispatcherSink-trait's caller-crate boundary.
* `build_own_host_candidates` inlined in veil-dispatcher's lib.rs (still
  sits at awkward proto::NatCandidate + transport::TransportUri intersection).
* `make_test_dispatcher` promoted from `#[cfg(test)]` to public so veilcore
  cross-crate tests (chaos_sim, runner_tests) reach it.
* veilcore re-export shim: `pub use veil_dispatcher as dispatcher;`.

**Verification**: cargo check --workspace --tests clean.
114/114 dispatcher tests pass.

**Exit gate:** `cargo test -p veil-dispatcher` passes in isolation;
routing + delivery tests faster; no `crate::*::runtime::*` references
inside dispatcher.

**Estimated time:** Prep done.  Actual move: 1 dedicated session.

### Phase 4 — `veil-node-runtime`

**Move:** `crates/veil-node-runtime/src/runtime/` + top-level `node/*.rs` files
(admin, metrics_http, outbound_connector, congestion, reputation, etc.)
→ `crates/veil-node-runtime/`.

**Phase 4 audit (2026-05-21)**:

| File / area | LoC | Coupling | Verdict |
|---|---|---|---|
| `runtime/mod.rs` | ~5000 | Central orchestrator | Moves to veil-node-runtime |
| `runtime/<32 sub-modules>` | ~15000 | Runtime-internal | Move with mod.rs |
| `admin.rs` | 4340 | Imports session, dispatcher, runtime | Moves to veil-node-runtime OR veil-admin |
| `admin_transport.rs` | 431 | Admin-IPC adapter | Moves with admin |
| `admin_audit.rs` | 305 | Pure (std+serde) | Could extract to own crate, or stays with admin |
| `outbound_connector.rs` | 826 | Runtime-coupled connect loop | Moves with runtime |
| `metrics_http.rs` | ? | Runtime-coupled HTTP server | Moves with runtime |
| `local_identity.rs` | 56 | HandshakeIdentity + LocalHandshakeIdentity impl | Moves with runtime (constructed by NodeRuntime) |
| `state.rs` | 71 | NodeState struct (NodeRuntime field) | Moves with runtime |
| `task_registry.rs` | 166 | NodeRuntime-specific enum | Moves with runtime |
| `listener_supervisor.rs` | 37 | Runtime types | Moves with runtime |
| `bootstrap_invite_create.rs` | 145 | IPC adapter | Moves with runtime (constructed by runtime) |
| `bootstrap_join.rs` | 256 | Runtime state | Moves with runtime |
| `key_passphrase.rs` | 187 | Uses NodeError + cfg | Moves with runtime |
| `mobile_sink.rs` | 126 | IPC adapter (veil-session::runner refs) | Moves with runtime |
| `mobile_status_provider.rs` | 71 | IPC adapter | Moves with runtime |
| `peer_list_provider.rs` | 184 | Uses veilcore-private types (LinkId, SessionInfo) | Moves with runtime |
| `pairing_forwarder.rs` | 399 | IPC adapter | Moves with runtime |
| `memory.rs` | ? | Memory tier metrics | Check |
| `types.rs` | 210 | Runtime-side types (LinkId, SessionInfo, NodeSummary, etc.) | Moves with runtime |
| `update.rs` | ? | re-export shim, stays |

**Phase 4 prep shipped (2026-05-21)**:
* `07377c6` `ScannerShield` (201 LoC) → `veil-abuse`

**Phase 4 Session 1 audit (2026-05-21)**:

Original plan called for `DispatcherHandle` + `SessionRegistryHandle`
trait abstractions before the move.  Audit shows this is no longer
needed:

* Runtime accesses 59 distinct dispatcher fields/methods (`dispatcher.X`).
  Wrapping all 59 in a trait would be massive surface area.
* After Phase 2/3 bulk-promote, dispatcher and session fields are
  `pub` cross-crate.  Runtime can access them directly through
  `veil_dispatcher::*` and `veil_session::*`.
* The session→dispatcher trait abstraction (`DispatcherSink`) from Phase 2
  remains in place; it solved the orphan-rule problem.  No equivalent
  problem exists for runtime→dispatcher (runtime moves to its own crate;
  dispatcher fields are pub).

**Phase 4 actual-move attempts 2026-05-21 (both reverted)**:

Two attempts this session, both shipped and then reverted. Each pass
sharpened the path-rewrite tool. The second got the error count from 318
down to 130 and then to 12 — before deeper-dep surprises forced a revert.

**Attempt 2 (refined tool) made meaningful progress**:
* Disambiguated `super::X` patterns: SIBLING_MAP (veil-X crates) vs
  INTERNAL set (modules moving with runtime → crate::X) vs leave-alone
  (intra-runtime refs).
* Balanced-brace parser handles multi-line `use super::super::{...}` blocks
  with per-entry classification.
* Macro imports + NodeId mapping + PeerLruCache redirects all working.
* Got to **12 unique errors** before hitting:
  - `crate::cfg::*` leftovers (a few stragglers escaped the sweep)
  - `crate::node::*` leftovers
  - `crate::proto::*` leftovers
  - `super::observability` / `super::dht` / `super::discovery` patterns
    inside runtime/ subdirs that looked like INTERNAL but were actually
    sibling-crate aliases (super = veilcore::node::runtime, super::X
    where X was veilcore::node::X but I treated super:: inside subfile
    as "leave alone")
  - `veil_identity::anonymity_x25519` (anonymity_x25519 isn't there)

**Remaining tooling work**:
* Sub-file (runtime/<sub>/<file>.rs) `super::X` patterns need same
  classification as `super::super::X` from runtime/<sub>/ — both go
  through NODE level.  My disambiguation rule (subfile super = stays)
  was wrong.
* Catch leftover `crate::cfg::*` / `crate::node::*` / `crate::proto::*`
  references that aren't inside `use crate::{...}` blocks.
* Map `anonymity_x25519` to its actual sibling location.

The trajectory (318 → 12 errors) says the move is tractable. The
path-rewrite tool just needs about 30 more minutes of refinement to close
the last gap.

Workspace compiles cleanly post-revert. About 38 commits shipped this
session: Phase 2 and Phase 3 complete, Phase 4 prep, and the 2
attempted-move iterations, all fully documented.

**What worked**:
* Crate skeleton creation + 25-crate dep list — straightforward.
* `git mv` 32 runtime/ files + 21 top-level helpers = 53 file move ✓.
* Path-rewrite via balanced-brace parser drove errors from 318 → 146 quickly.

**What broke**:
* `super::*` patterns inside runtime/<file>.rs are tricky: `super` originally
  meant `veilcore::node`, but the rewrite needed to route entries through
  many different sibling crates (veil-session, veil-dispatcher, etc.).
* Multi-line `use super::super::{...}` blocks with nested sibling-crate refs
  produced ambiguous rewrites.
* Many cross-file refs inside runtime/ use `super::X` to reach types defined
  in sibling runtime/<file>.rs — these need `crate::X` after the move (not
  the sibling-crate rewrite my script applied).
* Aggressive rewrite went from 146 → 350 errors after a too-broad super::
  treatment.

**Lesson**:
* The balanced-brace parser from the Phase 2/3 sweeps trips on ambiguous
  `super::X` cases — the ones where X might be a sibling crate or might be
  a module inside this crate. The fix is either a manual classification
  step, or a more conservative script: only rewrite `super::X` when X is a
  *known* sibling-crate alias. Leave it alone when X could be something
  like `super::types::FooBar`, where `types` might be veil-types or the
  crate-local types.rs.

**Phase 4 revised to 2-3 sessions**:

Session 1 (next session, ~3 hours): refine the path-rewrite tool to handle
super::X disambiguation correctly, then re-attempt the move with the improved
sweeper.

Session 2 (~2 hours): iterate compile errors, handle deeper-dep surprises.

Session 3 (~1 hour): test sweep + finalization.

**Phase 4 simplified plan (1-2 sessions)** (superseded — kept for history):

**Session 1: Mechanical move** (this session/next)
1. Create `crates/veil-node-runtime/{Cargo.toml, src/lib.rs}`.
2. `git mv` runtime/ subdirectory (32 files, ~15 KLoC) + top-level
   helpers that travel with it:
   * Required: admin.rs (4.3 KLoC), admin_audit.rs, admin_transport.rs,
     outbound_connector.rs, metrics_http.rs, local_identity.rs, state.rs,
     task_registry.rs, listener_supervisor.rs, types.rs (runtime-side
     types), key_passphrase.rs, builtin.rs, memory.rs, dht_glue.rs,
     mesh_glue.rs.
   * IPC adapters: bootstrap_invite_create.rs, bootstrap_join.rs,
     mobile_sink.rs, mobile_status_provider.rs, peer_list_provider.rs,
     pairing_forwarder.rs.
   * Proxy glue: proxy/tasks.rs.
   * Error: error.rs (NodeError + Result alias).
3. Path-rewrite sweep via balanced-brace Python parser:
   * `crate::cfg::*` → `veil_cfg::*`
   * `crate::node::abuse::*` → `veil_abuse::*`
   * `crate::node::session::*` → `veil_session::*`
   * `crate::node::dispatcher::*` → `veil_dispatcher::*`
   * etc. for all sibling crates
   * `crate::node::<helper>::*` (that moves with runtime) → `crate::<helper>::*`
   * `crate::lock!`, `crate::rlock!`, `crate::wlock!` → `veil_util::*`
4. Promote any `pub(crate)` items used cross-crate to `pub`.
5. Set up veilcore re-export shim.

**Session 2: Handle inevitable deeper-dep discoveries + test sweep + commit**.

Workspace check + tests; iterate compile errors.

**Exit gate:** `veilcore` becomes the "sim + re-export" shim only;
`node/` defs entirely live in `veil-node-runtime`.

**Estimated time:** 3 sessions (this is the heaviest).

### Phase 5 — `veil-cli` (binary split)

**Move:** `crates/veil-cli/src/bin/`, `crates/veil-cli/src/cmd/` →
`crates/veil-cli/{src,src/bin}`.

**Why last:** CLI imports from everything else. Doing it last lets us
land the four library crates without coordinating binary re-builds.

**Risk:** Cargo `[[bin]]` paths in CI / release recipes. Verify
`scripts/release.sh`, GitHub Actions, ansible deploy unit files (the
ones I've been touching for oproxy) all point to the new binary path.

**Estimated time:** 1 session.

### Phase 6 — cleanup

- Remove `veilcore::node::*` re-exports that turned out to be unused.
- Delete `veilcore/src/node/` entirely (the directory should be
  empty by this point).
- Audit `pub(crate)` markers that became cross-crate-private accidentally.
- Update `docs/en/CRATE_ARCHITECTURE.md` with the new topology diagram.
- Update `CLAUDE.md` (or memory) with the new "where does X live" map.

**Estimated time:** 1 session.

## Total estimate

10 sessions over about 2 working weeks at one per day, with room for CI
iteration and parallel-session coordination. Run two sessions back-to-back
per day and it compresses to roughly a week. Do NOT run them in parallel:
when one phase exposes a cycle, the prior phase has to roll back cleanly,
and that only works if the phases are stacked in order.

**Revised 2026-05-21**: pre-Phase-1 cycle-break (commit `b728161`) +
Phase 1 scope correction (now whole-cfg-tree instead of subset)
pushes Phase 1 from 1 session to 2.  Total estimate now ~11 sessions
over ~2-3 weeks.  Pre-Phase-1 prerequisite is shipped and unblocks
the Phase 1 work whenever a re-open trigger fires.

## Acceptance per phase

Every phase commit must:

1. `cargo check --workspace --all-features` — clean.
2. `cargo test --workspace --no-fail-fast` — green (with the slow-sim
   suite gated behind its existing feature flag).
3. `cargo clippy --workspace --all-features --tests` — zero warnings
   beyond the existing baseline (no regressions; clippy-clean is the
   bar set by previous PRs).
4. `cargo deny check` (license + dup-version) — green.
5. Public API surface diff vs prior commit: only **moves** allowed; no
   signature changes, no new pub items, no removed pub items in this
   refactor.

If any of the five gates fails, the phase doesn't commit. Roll back, fix,
try again — do NOT paper over it with feature flags or `#[allow(dead_code)]`.

## Out of scope (explicit)

- **Wire format changes** — `veil-proto` is untouched.
- **CLI flag changes** — `veil-cli` is a 1:1 move.
- **Feature-flag renames** — `--features rocksdb-cold` etc. keep their
  current names; only their crate boundaries shift.
- **Performance tuning** — measure regressions, but don't take "while
  we're here" shortcuts. Each phase reverts cleanly if needed.
- **Test re-organization** — tests move WITH their code. No
  consolidation, no "move integration tests to a different dir."

## Re-open triggers (signals that motivate starting Phase 1)

- A second incident where touching one `node/runtime/` file forces a
  10-minute full rebuild during dev.
- A second crate that's blocked from depending on a `node/session/`
  type because the dep direction would create a cycle.
- A new contributor reports "I can't find where X lives" after 30+ min
  searching — the layout has outgrown its discoverability budget.

Until one of those fires, this plan stays parked. Run it without a real
motivating constraint and you pay 10 sessions of refactor churn up front,
for benefits that only show up as the codebase keeps growing.
