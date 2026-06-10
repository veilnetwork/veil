# Anonymity-preserving circuit optimisation — consolidated implementation plan

> **Status (2026-06):** ACTIVE. This is the consolidated, anonymity-**pure** plan
> distilled from the three design sketches
> ([anon-preserving alternatives](PLAN_ANON_PRESERVING_CIRCUIT_OPTIMIZATION.md),
> [482.7 stateful](PLAN_STATEFUL_CIRCUITS_482_7.md),
> [A.2 mid-stream](PLAN_RELAY_REPUTATION_A2_MIDSTREAM.md)). Scope rule:
> **keep only work with zero anonymity cost; drop anything that weakens the
> per-message-unlinkability property.**

## ⚠️ Production-wiring status (gates the whole line's priority)

**The onion-routing anonymity path is NOT wired to production.**
`NodeServices::send_anonymous` / `send_via_rendezvous` (→ circuit builder → onion
→ relay forwarding) have **no production callers** — only `veilcore/src/sim/
scenarios.rs` (sim) and benches invoke them. The IPC `send.anonymous` flag uses
**meta-E2E** (`veil_e2e::meta_encrypt` — hides sender identity inside the E2E
ciphertext on the REGULAR delivery path), NOT onion circuits
(`crates/veil-ipc/src/handlers/send.rs`). Evidence: `grep '.send_anonymous('` →
only `scenarios.rs`; `build_outbound_anonymous_cell_*` callers → those two
methods + benches.

**Consequence:** every workstream here optimises a path production doesn't use.
W1 (shipped) still benefits sim/benches and a future wiring; the measurement (W0)
must be done in-process (below), not on a live testnet (which produces zero onion
traffic). **Before investing in W2/W3, decide:** (2) wire onion-send to a
production IPC entry point if onion-grade anonymity is wanted beyond meta-E2E, or
(3) deprioritise this line. W2/W3 are premature until the path is prod-wired.

## Scope decision

**Goal:** recover the "interactive chat overhead" without spending anonymity.

**Kept (zero anonymity cost):**
- **W1 — deterministic nonce (onion v2):** derive the AEAD nonce from the
  per-layer shared secret and stop transmitting it. Safe because the
  anonymity-preserving design ALWAYS uses a fresh per-message ephemeral → unique
  key per layer → no nonce collision. +12 B/hop payload. (← start here)
- **W0 — measurement:** instrument the per-message cost decomposition
  (selection-inputs / pick / onion-wrap / bandwidth). Zero anonymity cost; sizes
  W2/W3.
- **W2 — selection-INPUT caching (fresh path per message):** cache the expensive,
  path-INDEPENDENT selection inputs (AS-diversity map, candidate snapshot, RTT
  snapshot) for a short TTL, but **re-sample a fresh path every message.** Zero
  anonymity cost — each message is a fresh independent onion through fresh
  relays, so NO corridor linkability. Recovers the largest cost.
- **W3 — Sphinx-style onion compression:** one blinded group element instead of
  N ephemerals + a single per-hop MAC; adds free per-message replay protection.
  Zero anonymity cost (same per-message-unlinkable, fixed-size model). Largest
  effort (Ristretto255 migration, vetted construction). Closes the "no replay
  protection on generic cells" gap.

**Explicitly EXCLUDED (anonymity cost — do NOT build):**
- **Epic 482.7 stateful circuits** — a `CircuitId`/cached key links one sender's
  N messages at every middle/exit hop (definitive). Net anonymity regression.
- **Path-REUSE caching** — reusing the same *path* (not just inputs) for N
  messages gives a middle hop corridor-level linkability. We cache INPUTS and
  re-sample a FRESH path instead (W2), which has no such cost.
- **A.2 per-hop ack attribution (§4.3)** — needs stateful circuits; out of scope
  on the anonymity-pure path. (A.2's already-shipped leak-free signals stay.)

## Invariant (enforced across all workstreams)

> Every message is an **independent, fresh-ephemeral onion through a freshly
> sampled path.** No relay can cryptographically link two of a sender's messages.
> Any change that lets a relay link two messages is out of scope by definition.

## Implementation order

1. **W1 — deterministic nonce** (smallest, self-contained, establishes onion v2
   versioning that W3 reuses). ← in progress
2. **W0 — measurement** (gates the sizing of W2/W3).
3. **W2 — selection-input caching** (largest cost recovered, no wire change).
4. **W3 — Sphinx compression** (bandwidth + replay; separate large epic; needs
   Ristretto migration + a vetted Sphinx construction, never hand-rolled).

## Per-workstream notes

### W1 — deterministic nonce (onion v2)
- Files: `crates/veil-anonymity/src/onion.rs` (derive nonce, omit from wire,
  `ONION_LAYER_OVERHEAD` 60→48, `AEAD_DOMAIN` v1→v2); `circuit.rs`/`packet.rs`
  budgets auto-update via the `ONION_LAYER_OVERHEAD` constant.
- Anonymity invariant: unchanged crypto strength — fresh ephemeral per layer →
  unique key → a derived (or even fixed) nonce is safe; nonce reuse only matters
  when the KEY repeats, which never happens.
- Flag-day: the onion layer wire format changes → mixed-version nodes can't
  interop on the anonymity path (the 512 B cell framing is unchanged, so
  non-anonymity traffic is unaffected). Acceptable on testnet; gate by the
  `AEAD_DOMAIN` v2 bump.
- Test: round-trip; envelope is exactly 12 B smaller; tamper test offset updated;
  budget assertion `max_payload(N) == 510 - 81·N`.

### W0 — measurement (shipped: debug-log instrumentation)
- `send_anonymous`/`send_via_rendezvous` now emit a `log::debug!`
  `anonymity.{send,rendezvous}.timing` line per send with `select_us`
  (candidate snapshot + relay discovery/verify + diversity map) vs `build_us`
  (pick + onion wrap) + `payload`, `hops`, `candidates`, `usable`.
- No behaviour/wire change; debug-level (off by default); anonymity-neutral
  (local timing of our own send, nothing transmitted, no peer correlation).
- Decide W2/W3 sizing from the captured ratio. Expectation: `select_us` ≫
  `build_us` (per-candidate signature verify in `discover_relay_hops` vs a few
  ECDH in the wrap) → justifies W2.
- Follow-up (optional): promote to Prometheus sum/count metrics via
  `NodeMetrics` for ongoing dashboards (`self.metrics` is reachable here).

**RESULT (in-process measurement, `directory::tests::w0_measure_selection_vs_build`,
Ed25519 issuers, 3-hop build, release):**

| candidates | select_us | build_us | selection/build |
|---|---|---|---|
| 50  | 1205 | 91 | 13.2× |
| 100 | 1892 | 79 | 23.9× |
| 200 | 3712 | 82 | 45.3× |
| 500 | 9324 | 95 | 98.1× |

Selection scales linearly (~18.6 µs/candidate — the Ed25519 `verify_entry` per
candidate); build is ~constant (~80–95 µs, independent of N — the 3-hop pick +
onion wrap). At a realistic 100–500-candidate routing table, **selection
dominates 24–98×.** Hybrid/Falcon issuers would make selection even more
dominant (slower verify). Conclusion: **W2 (cache the verified relay set, fresh
path per send) is 1–2 orders of magnitude more impactful than W1/W3**, which
touch the small build/bandwidth half. (But see the production-wiring caveat —
W2 is premature until the onion path is prod-wired.)

### W2 — selection-input caching (fresh path)
- Sender-side cache (sibling to `AnonymityState`): `{rtt snapshot, diversity
  map, candidate set}` keyed by a short TTL (e.g. 5–10 s). Re-run only the cheap
  pick per message → fresh path.
- Anonymity invariant: fresh path per message — assert in a test that two
  consecutive sends with a warm cache produce different relay sets (probabilistic
  with enough candidates), i.e. caching inputs must NOT pin the path.

### W3 — Sphinx compression
- Separate epic; see [PLAN_ANON_PRESERVING_CIRCUIT_OPTIMIZATION.md §5](PLAN_ANON_PRESERVING_CIRCUIT_OPTIMIZATION.md).
  Ristretto255 anonymity keys + vetted Sphinx construction + replay seen-set.
- Gate on W0 showing bandwidth matters for the payload mix.
