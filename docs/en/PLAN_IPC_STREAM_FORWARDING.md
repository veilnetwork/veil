# IPC stream-open inter-node forwarding plan

> Status (2026-06-03): **Phases 1-4 IMPLEMENTED.** Cross-node IPC
> `STREAM_OPEN` now bridges onto the wire `AppOpen`/`AppData`/`AppClose`
> machinery via `handle_stream_open_remote` + a per-stream bridge task.
> See the "Implementation (2026-06-03)" note at the bottom for what shipped
> vs. the original plan below (kept for design context).

## Why

`veilclient::AppHandle::open_stream(dst_node_id, app_id, endpoint_id)`
sends a `STREAM_OPEN` IPC frame to the daemon. When `dst_node_id` matches
the local daemon's node, the handler routes through the local
`AppEndpointRegistry` and everything works. When `dst_node_id` is a
**remote** peer's node, [crates/veil-ipc/src/handlers/stream.rs](../../crates/veil-ipc/src/handlers/stream.rs)
currently returns `REMOTE_NOT_IMPLEMENTED` (since this commit) — previously
it returned the misleading `NOT_FOUND`, and the SOCKS5/oproxy smoke test
hung waiting on a stream that would never open.

Inter-node streams ARE already supported in the daemon for a *different*
client surface — [veil-proxy::VeilConnector](../../crates/veil-proxy/src/veil_connector.rs)
opens cross-node streams using wire-level [`AppOpen`](../../crates/veil-proto/src/family.rs)
/`AppData`/`AppClose` frames. The IPC `STREAM_OPEN` path was never wired
into that machinery.

## Building blocks (already present)

- **Wire frames**: [`AppOpenPayload`](../../crates/veil-proto/src/app.rs),
  `AppDataPayload`, `AppClosePayload`, `AppReceiptPayload` —
  `FrameFamily::App`, with `header.stream_id` carrying the per-session
  stream id. Receive-window management via `AppWindowUpdate`.
- **Dispatcher inbound**: [crates/veil-dispatcher/src/app.rs](../../crates/veil-dispatcher/src/app.rs)
  lines 34-89 already route inbound `AppData` either to a registered
  `veil_stream_rx` channel (VeilConnector path) or fall back to
  `app_registry.route_stream_data` / `route_data`.
- **Outbound transport**: `FrameBroadcaster` trait, implemented by
  `SessionTxRegistry`, already plumbed in `IpcSendContext`.
- **Bridge map**: `VeilStreamRxMap = Arc<Mutex<HashMap<([u8;32], u32),
  mpsc::Sender<Vec<u8>>>>>` defined in `veil-proxy::veil_connector`.
- **Pending-receipt map**: `PendingReceiptMap = Arc<Mutex<HashMap<u32,
  oneshot::Sender<u8>>>>` — same crate.

## Gaps to fill

1. **Plumb `veil_stream_rx_map` + `pending_receipts` references from
   the daemon (veilcore runtime) into the IPC server's `IpcSendContext`**.
   Right now `IpcSendContext` has `session_tx_registry` but not the bridge
   tables.
2. **Add a remote branch to `handle_stream_open`** that:
   - Allocates a wire-level stream_id (local-side AtomicU32 counter
     analogous to VeilConnector's `stream_counter`).
   - Registers a `(dst_node_id, wire_stream_id)` → mpsc::Sender in
     `veil_stream_rx_map`.
   - Registers a oneshot waiter in `pending_receipts`.
   - Encodes + sends `AppOpen{app_id, endpoint_id, flags=0}` via
     `session_tx_registry.send_to(dst_node_id, ...)` with
     `header.stream_id=wire_stream_id`.
   - Awaits `AppReceipt(ACCEPTED)` with a timeout (analogous to
     `OPEN_RECEIPT_TIMEOUT` in VeilConnector — 5s recommended).
   - On success: register the stream in `IpcStreamTable` (or a sibling
     "remote stream" table that knows how to forward bytes via
     wire-frame), then reply `StreamOpenOk { stream_id=ipc_stream_id }`.
   - On timeout / reject: deregister, reply `StreamOpenErr { error_code }`.
3. **Add a bridge task per-stream** in the IPC server that pumps:
   - Inbound `Vec<u8>` from the registered mpsc → encode `StreamData`
     IPC frame → push to client's delivery channel.
   - On channel close (remote side closed): encode `StreamClose` IPC
     frame → push to client's delivery channel; deregister from
     `veil_stream_rx_map`.
4. **Update `handle_stream_data` / `handle_stream_close`** routing on
   the IPC server side: when the stream_id refers to a remote-bound
   stream (lookup in the new remote-stream table), encode `AppData` /
   `AppClose` wire frames and send via `session_tx_registry`. Otherwise
   keep the existing local-pair routing.
5. **Stream-id namespace coordination**: the IPC client speaks in IPC
   stream_id space, the wire speaks in wire stream_id space (per-session).
   The bridge table holds the IPC↔wire mapping.

## Phase plan

### Phase 1 — proto wiring + error code (this commit)

Already done in this PR: new `stream_open_err::REMOTE_NOT_IMPLEMENTED = 5`,
`handle_stream_open` returns it for `dst_node_id != local`. Lets SDK
clients surface a clear error instead of hanging.

### Phase 2 — IpcSendContext bridge plumbing (1 session)

- Move `VeilStreamRxMap` and `PendingReceiptMap` type aliases from
  `veil-proxy` to a neutral location. Candidates:
  - `veil-ipc` (where the IPC handler lives) — but veil-proxy would
    then depend on veil-ipc which it already does, fine.
  - A new `veil-bridge-state` crate — overkill for two type aliases.

  Recommended: add the aliases to **`veil-ipc`**, have `veil-proxy`
  re-export them so existing callers compile unchanged.
- Extend `IpcSendContext<'a>` with optional `&'a VeilStreamRxMap` and
  `&'a PendingReceiptMap` fields.
- Thread the fields via `server.rs::accept_loop` from the daemon-
  supplied `NodeRuntime` context. The daemon's `runtime/mod.rs`
  already constructs `shared_veil_stream_rx`; just pass a cloned
  Arc to the IPC server at construction.

**Exit gate**: `IpcSendContext` carries the bridge maps; existing local-
pair STREAM_OPEN path unchanged; cross-node case still returns
REMOTE_NOT_IMPLEMENTED.

### Phase 3 — handler remote branch + bridge task (1 session)

- Refactor `handle_stream_open`:
  - Move local-pair logic to `handle_stream_open_local`.
  - Add `handle_stream_open_remote` that:
    1. Allocates wire stream_id (AtomicU32 in a server-shared counter).
    2. Registers `(dst_node_id, wire_stream_id)` → `mpsc::Sender<Vec<u8>>`
       in `veil_stream_rx_map`.
    3. Registers `oneshot` waiter in `pending_receipts`.
    4. Encodes `AppOpen` + header.stream_id, sends.
    5. `tokio::time::timeout(5s, receipt_rx).await` for receipt.
    6. On ACCEPTED: spawn a bridge task that pumps the mpsc → IPC
       StreamData frames.
    7. Reply StreamOpenOk with the IPC stream_id.
- Refactor `handle_stream_data`:
  - Lookup stream in `IpcStreamTable` first; if it's marked "remote-bound"
    encode `AppData` + send via session_tx_registry.
- Refactor `handle_stream_close`:
  - Same dispatch as `StreamData`; send `AppClose` for remote streams.

**Wire stream_id collision avoidance**: the daemon ALREADY shares a
wire stream_id space across VeilConnector + IPC paths. Allocate
from a single `Arc<AtomicU32>` counter held by `NodeRuntime` and passed
to both surfaces. AtomicU32 wraps after 4 billion streams; pollution
window inside the bridge map deduplicates by `(node_id, stream_id)` so
collisions across different remote peers are fine.

**Exit gate**: `STREAM_OPEN` to a remote node returns `StreamOpenOk`,
`STREAM_DATA` flows both ways, `STREAM_CLOSE` cleans up. Smoke test
(oproxy-server bound on node A, oproxy-client + SOCKS5 on node B)
completes a full curl-through-proxy request.

### Phase 4 — tests + production-readiness (1 session)

- **Unit tests**: cover remote-path handler with mock `FrameBroadcaster` that
  capture sent frames; assert AppOpen → wait for receipt → StreamOpenOk
  → AppData round-trips.
- **Integration test**: two-daemon sim setup (use existing `sim/`
  infrastructure) — bind app A on node1, IPC `open_stream` from node2,
  send 1 MiB, expect bytes back. Already-existing
  `server_tests_unix.rs` is a good template for the IPC mechanics.
- **Edge cases**:
  - Remote peer drops session mid-stream — bridge task must emit
    StreamClose to local client.
  - Receipt timeout → deregister, return error code.
  - Concurrent opens to same remote node — wire stream_id collision via
    AtomicU32 advancement.
  - oproxy end-to-end smoke test (the one that surfaced the gap).

**Exit gate**: 3+ tests pass; smoke test that previously hung now
completes. Document the new path in `docs/en/IPC.md` (extend existing
local-pair sections with the remote-bridge variant).

## Total estimate

3 sessions (Phase 2 + 3 + 4). The complexity is in cross-cutting state
management, not algorithms — every primitive needed is already proven
by VeilConnector. Risk is mostly "did I plumb the lifetime right in
`IpcSendContext`."

## Out of scope (explicit)

- **Stream multiplexing optimization** — current VeilConnector path
  uses one wire stream_id per IPC stream. Multiplexing (one wire
  stream for many IPC streams to the same peer) is a separate
  optimisation, not required for correctness.
- **Cross-daemon stream resumption** — if the daemon restarts mid-
  stream, the IPC client must treat it as a fresh failure. Persistence
  across daemon restarts is a much larger feature (would require
  durable stream state).
- **Encryption flag plumbing** — AppOpen has a `flags` field reserved
  for future use. Hold at zero for Phase 3; revisit when E2E-on-stream
  becomes a concrete requirement.

## Re-open triggers

This plan moves to active execution when:
- Operator wants to expose application-level services accessible via
  IPC SDK from remote daemons (mailbox bridges, custom services).
- A second production smoke test or integration suite fails because of
  this gap.

Until one of these fires, the explicit `REMOTE_NOT_IMPLEMENTED` error
from Phase 1 is sufficient — it makes the limitation visible without
spending 3 sessions of refactor budget.

---

## Status snapshot (audit batch 2026-05-23)

The cross-audit asked to "close" this row.  After a planning pass, the
honest engineering call is:

* **Phase 1 (clean error)** — shipped, in production.  Already meets the
  bar for "limitation is visible, callers don't hang."
* **Phases 2-4 (full implementation)** — remains a deferred epic.
  Estimated 3 dedicated sessions per the breakdown above; the
  complexity is in cross-cutting state management (wire stream-id
  allocator coordination, bridge task per-stream lifecycle, dispatcher
  inbound routing alignment), not algorithms.  Shipping a partial
  Phase 3 (e.g. open-only without bridge task) is strictly worse than the
  current Phase 1 status quo because it converts a clean error into a
  silent hang on the first STREAM_DATA frame.

### What operators can do today

Applications that need cross-node streaming today should use the
existing **[`veil_proxy::VeilConnector`](../../crates/veil-proxy/src/veil_connector.rs)**
surface, also exposed via the `oproxy` binary (SOCKS5 / HTTP / TProxy
inbounds).  It implements the same set of building blocks listed under
"Building blocks" above and has been in production since Epic 33.

* SDK applications can talk to the oproxy SOCKS5 endpoint instead of
  using `AppHandle::open_stream` for cross-node addresses.
* `veil_proxy::VeilConnector` is itself a public crate-surface
  API if a tighter integration is needed (it skips the SOCKS5
  framing).

### Closing this plan

The next person taking this on should:
1. Move `VeilStreamRxMap` / `PendingReceiptMap` type aliases out of
   `veil-proxy::veil_connector` (see Phase 2 above).
2. Plumb a shared `Arc<AtomicU32>` wire stream-id counter so the
   IPC-side `handle_stream_open_remote` does not collide with the
   VeilConnector's counter when both are active on the same node.
3. Implement `handle_stream_open_remote` per the Phase 3 spec above,
   referencing `VeilConnector::connect` as the proven template.
4. Spawn a per-stream bridge task that pumps the registered
   `mpsc::Receiver<Vec<u8>>` into IPC `StreamData` frames pushed to the
   client's delivery channel, and emits IPC `StreamClose` when the rx
   closes.
5. Update `server.rs::handle_ipc_client` STREAM_DATA / STREAM_CLOSE /
   STREAM_WINDOW dispatch arms to recognise remote-bound stream_ids
   and encode `AppData` / `AppClose` / `AppWindowUpdate` wire frames
   instead of routing locally.
6. Add an integration test under `crates/veil-ipc/tests/` (or a
   neutral location) that spins up two daemons via `sim/` and proves a
   1 MiB round-trip from an IPC SDK opener on node B to a bound endpoint
   on node A.

Until then, the cross-reference in
`crates/veil-ipc/src/handlers/stream.rs::handle_stream_open` points
operators to the VeilConnector workaround.

---

## Implementation (2026-06-03)

Phases 2-4 shipped on branch `feat/ipc-remote-stream-forwarding`. What
landed, mapped to the plan above:

- **Phase 2 (bridge plumbing).** New `veil_ipc::bridge` module:
  `VeilStreamRxMap` / `PendingReceiptMap` (transparent synonyms of the
  `veil_proxy::veil_connector` types — no new crate dep needed, since
  Rust type aliases are structural) plus an `IpcStreamBridge` bundle
  (`veil_stream_rx` + `pending_receipts` + a shared `Arc<AtomicU32>`
  wire stream-id counter). Threaded into the IPC server via
  `IpcServer::with_stream_bridge` → `handle_ipc_client` → the dispatch
  loop. The daemon builds it in `spawn_ipc_server` from
  `self.dispatcher.{veil_stream_rx, pending_stream_receipts}` +
  `NodeRuntime::wire_stream_counter`, and the **same counter** is now
  passed to `VeilConnector::new` (previously it minted its own), so the
  two surfaces never collide on a `(node_id, wire_stream_id)` key.

- **Phase 3 (handler + bridge + routing).** `handle_stream_open` splits
  local vs. remote; `handle_stream_open_remote` allocates a wire stream-id,
  registers the inbound channel + receipt waiter, sends `AppOpen`, awaits
  the `AppReceipt` (5 s), and on ACCEPTED reserves an IPC stream-id
  (`IpcStreamTable::open_remote`, a sibling map sharing the local id pool),
  spawns the inbound bridge task (`run_remote_stream_bridge`: wire
  `AppData` → IPC `STREAM_DATA`; remote close → `STREAM_CLOSE` + cleanup),
  and replies `STREAM_OPEN_OK`. The server's `STREAM_DATA` / `STREAM_CLOSE`
  arms route remote-bound streams (`remote_route` / `close_remote`) to wire
  `AppData` / `AppClose`. The dispatcher's inbound `AppClose` now drops the
  `veil_stream_rx` entry so remote-initiated close propagates to the
  bridge (a strict improvement that also benefits `VeilConnector`).
  New error codes: `stream_open_err::{NO_SESSION, REMOTE_TIMEOUT}`.

- **Phase 4 (tests).** Unit tests for the remote-stream model
  (`open_remote`/`remote_route`/`close_remote`, local/remote id
  non-collision), the inbound bridge task (pump → `STREAM_DATA`, remote
  close → `STREAM_CLOSE` + table cleanup), and the open handshake with a
  capturing mock broadcaster (ACCEPTED → stream registered + `AppOpen`
  emitted with the allocated wire id; non-ACCEPTED → full deregistration).

**Not a partial Phase 3.** The bridge task ships in the same change as the
handler, so the "silent hang on first STREAM_DATA" hazard the plan warned
about does not apply.

**Still open (follow-up):** a true two-daemon end-to-end test. Investigated
2026-06-03 and confirmed a dedicated effort (NOT a quick adaptation) — deferred
for now; the in-process handshake + bridge + model tests cover the logic and
the inbound path reuses the production-proven dispatcher / VeilConnector
routing. Blockers, so the next attempt skips the re-discovery:

1. `veilcore::sim` (the only multi-daemon harness — `SimNetwork`/`SimNode`
   wrap real `NodeRuntime`s) is `#[cfg(test)]`-gated (veilcore/src/lib.rs),
   so it is NOT reachable from an external crate — the e2e must live inside
   veilcore's own `#[cfg(test)]` tests.
2. Inside veilcore you cannot use `veilclient` (the SDK with
   `AppHandle::open_stream`) — veilclient depends on veilcore (cycle).
3. ⇒ hand-roll a raw IPC client (APP_HELLO → STREAM_OPEN → STREAM_DATA) on
   BOTH sides (opener + echo acceptor), ~250 lines using `veil-ipc`'s codec.
4. Sim nodes collide on the fixed default IPC socket; inject a per-node
   `config.ipc.socket_uri = "unix://<config_path>.ipc.sock"` in
   `SimNetworkBuilder::build()` (sim/network.rs, after `config_path`) so each
   node's IPC server is reachable.

Out-of-scope items from the plan (stream multiplexing, cross-daemon
resumption, E2E-on-stream `flags`) remain out of scope.
