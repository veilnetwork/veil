# Epic 482.7 — stateful circuits (CircuitId, build-once → send-N) — design sketch

> **Status (2026-06):** DESIGN DRAFT, no code. veil's anonymity layer is today a
> **stateless single-cell source-routed onion** (one onion cell = one message,
> no circuit state, no `CircuitId`, no return path). 482.7 would add a stateful,
> `CircuitId`-tagged circuit so a sender can build a path once and send many
> messages over it cheaply. **Read §0 first** — like A.2, this is a QoS/latency
> optimisation, and it carries a *real anonymity regression* (intra-circuit
> linkability + a longer-lived correlatable flow) that must be weighed and gated,
> not assumed worth it.
>
> Cross-ref: [`PLAN_RELAY_REPUTATION_A2_MIDSTREAM.md`](PLAN_RELAY_REPUTATION_A2_MIDSTREAM.md)
> concluded 482.7 likely precedes A.2 (per-hop attribution needs stateful
> circuits) and is independently useful — this doc scopes that independent value.
>
> **IMPORTANT — read [`PLAN_ANON_PRESERVING_CIRCUIT_OPTIMIZATION.md`](PLAN_ANON_PRESERVING_CIRCUIT_OPTIMIZATION.md)
> first.** It shows most of the "chat overhead" 482.7 targets is recoverable
> WITHOUT the anonymity cost: the *largest* cost (relay selection) via
> path-selection caching at corridor-level cost only, and bandwidth via
> Sphinx-style onion compression at zero cost. 482.7's keyed-state machinery
> amortises only the *smallest* cost (per-message DH) and is the only option that
> requires paying anonymity. Treat 482.7 as a last resort gated on measurement.

Epic: 482.7. Listed in TASKS.md deferred backlog: "Stateful `CircuitId` for
persistent circuits — CircuitId-tagged sessions, build once → send N messages,
anti-replay window per circuit. Perf-driven: interactive chat shows high re-build
overhead vs message latency."

---

## 0. Value vs cost (read first)

### What it buys (QoS, for high-message-count flows only)
The current per-message cost (see §1) is, **per message**: `N` fresh X25519
ephemeral keypairs + `N` ECDH + `N` AEAD ops, and **81 bytes of onion overhead
per hop** (onion v2, post-W1: 48 onion + 32 next-hop id + 1 TTL) — of which
**32 bytes is the next-hop id carried in every layer**. Building once and reusing
the circuit amortises all of that:

- **No per-message ECDH** — derive a symmetric circuit key with each hop once,
  reuse for the circuit's lifetime.
- **The relay caches the next hop** under the `CircuitId`, so data cells no
  longer carry the 32-byte next-hop id per layer.
- A data cell's per-hop overhead drops from **~81 B → ~16 B** (just an AEAD tag;
  nonce derived from the per-circuit sequence number). For a 3-hop circuit,
  usable payload rises from **267 B → ~450 B** (per `packet.rs`: `510 − 81·N` →
  `~510 − 16·N − 8`), plus the CPU saving.

**Break-even:** a circuit must carry **≥ 2** messages to amortise its build. So
482.7 helps **interactive chat / repeated sends to the same peer**, and does
**nothing** for one-shot sends except add cost. It is a targeted optimisation,
not a general win.

### What it costs (anonymity — the load-bearing part)
The current stateless model has a *strong, often-overlooked anonymity property*:
**no relay can link two of a sender's messages.** Each onion cell is independent
(fresh ephemeral pk, fresh nonce), so a middle hop sees unrelated packets.
482.7 deliberately weakens this:

1. **Intra-circuit linkability at every hop.** A `CircuitId` is, by construction,
   a tag that says "these N cells are the same circuit." Every hop on the path
   can now link all N messages to each other (same sender flow), and the
   entry/exit hops can profile the flow over its lifetime. This is a genuine
   regression from the unlinkable single-shot model.
2. **Longer-lived correlatable flow.** A persistent circuit is exactly the
   end-to-end timing-correlation target onion routing is weakest against — a
   global passive adversary correlates entry and exit over the circuit's life,
   which is far easier for a long-lived flow than for one isolated cell.
3. **Loss of per-message forward secrecy.** Reusing one circuit key for N
   messages means a single key compromise decrypts **all** N (the current model
   re-keys every message via a fresh ephemeral). Mitigated only by re-keying or
   short circuits (§4.5), which fights the amortisation.

**The crux tension:** chat wants circuit **reuse** (amortise the build);
anonymity wants circuit **rotation** (bound linkability + correlation). 482.7
must pick a point on that curve — see §4.5 ("stateful but short").

### Priority call
Because 482.7 trades a real anonymity property for a per-flow latency/throughput
win, it needs explicit maintainer buy-in and the §6 gate. It is independently
useful (the A.2 doc relies on it for §4.3), but it is **not** a free perf win.

---

## 1. Current architecture (what 482.7 changes)

| Aspect | Today (stateless) | Anchor |
|---|---|---|
| Cell | 512 B fixed: `[payload_len u16][payload][zero pad]` | `cell.rs:16-22,67-72` |
| Payload budget | `510 − 81·N` (N=3 → 267 B; N≤6 fits, N≥7 rejected) | `packet.rs` |
| Per-hop overhead | 81 B = 48 onion v2 (`32 eph_pk + 16 tag`, nonce derived) + 32 next-hop id + 1 TTL | `onion.rs` `ONION_LAYER_OVERHEAD=48` / `circuit.rs` `PER_HOP_OVERHEAD=81` |
| Key schedule | **per-message** fresh ephemeral DH with each hop's STABLE directory x25519 key; AEAD key = BLAKE3(shared) | `onion.rs:133-260` |
| Relay forwarding | **stateless**: `peel_anonymous_cell` → `Forward{next_hop, outbound_cell}` or `Final`; no per-cell state; silent drop if next hop down | `dispatcher/anonymity.rs:70-196` |
| Replay protection | **none** on generic cells (only Introduce frames at rendezvous have a replay cache) | `onion.rs:84-86`; `rendezvous.rs` IntroduceReplayCache |
| CircuitId | **none** — explicitly deferred | `circuit.rs:57-70` |
| RelayChainMsg | `Hop=0, RegisterRendezvous=1, UnregisterRendezvous=2, ForwardIntroduce=3` | `proto/family.rs` |
| Relay caps | rendezvous: 10k regs, 64/peer; **generic cells: none (no state to cap)** | `rendezvous.rs` |

---

## 2. The two sub-problems

482.7 = **(A) circuit build** (install per-hop circuit state once) + **(B) circuit
data plane** (`CircuitId`-tagged cells using cached keys + anti-replay), plus
**(C) circuit lifecycle** (teardown, timeout, caps).

---

## 3. Circuit build (sub-problem A)

### Option B1 — single-pass key install (recommended)
Reuse the existing onion to deliver, in ONE forward pass, a per-hop install:
each hop's onion plaintext carries `{circuit_id_in, circuit_id_out, circuit_key,
next_hop}` instead of just `{next_hop, inner}`. The relay stores
`(prev_link, circuit_id_in) → CircuitState{key, next_link, circuit_id_out,
replay_window}` and forwards the install inward.

- **Pros:** no return path (veil is fire-and-forget — it has none), no build
  round-trip, reuses the shipped onion crypto.
- **Cons:** the `circuit_key` is sender-chosen and delivered under the hop's
  **stable** directory key, so it has the same forward-secrecy profile as today's
  per-message key *at build time* — but is then reused (§0 cost 3). No per-hop
  ephemeral contribution → a hop can't prove freshness.

### Option B2 — telescoping (Tor CREATE/EXTEND)
Per-hop ephemeral DH with a round-trip per extension → per-circuit forward
secrecy.
- **Pros:** real per-circuit FS; each hop contributes entropy.
- **Cons:** needs a **return path** veil does not have (would have to be built —
  itself a correlation surface, cf. A.2 §2 C1), and a multi-RTT build that
  *increases* setup latency — opposite of the goal for short circuits. Likely not
  worth it for veil's model.

**Recommendation:** B1 single-pass. Accept reused-key FS as a §0 cost, bound it
with rotation (§4.5).

---

## 4. Circuit data plane (sub-problem B)

### 4.1 CircuitId placement
The cell carries **no** CircuitId today. Two viable encodings:
- **D1 — per-link circuit id in a small outer header (Tor-style, recommended):**
  data cell = `[circuit_id u32][seq u32][layered ciphertext]`. Each hop looks up
  `circuit_id` on its inbound link, re-tags to `circuit_id_out` for the next
  link, peels one **symmetric** layer with the cached key. The next hop is
  **cached** (not in the cell) — this is where the 32 B/hop saving comes from.
- **D2 — circuit id in onion plaintext per layer:** no outer header, +4 B/hop.
  Loses the next-hop-caching win (each layer still self-describes). Inferior.

Use **D1.** Note the cell layout change (`cell.rs`, `packet.rs`,
`max_payload_for_hops`) is mechanical but touches the wire format → version-gate
(§9).

### 4.2 Layer crypto for data cells
Each hop holds a cached symmetric `circuit_key`. Data-cell layers use an AEAD
(ChaCha20-Poly1305) keyed by `circuit_key` with the **nonce derived from `seq`**
(`nonce = LE(seq) || direction`), so no per-message nonce/ephemeral is carried —
just the 16 B tag per layer. Forward direction only initially (veil has no return
plane); a return direction needs the same as A.2's ack contract.

### 4.3 Anti-replay window (the epic's named requirement)
Per-circuit, per-direction **sliding window** on `seq`: relay keeps
`highest_seq + bitmap(W)`; rejects `seq` already seen or older than `highest -
W`. This is the per-hop circuit state that the stateless model can't have.
Defaults: `W = 1024`. A replayed/reordered cell is dropped silently (no oracle).

### 4.4 Sequence + ordering
`seq` is per-circuit monotonic from the sender. Out-of-order within the window is
accepted (transport may reorder); duplicates and stale are rejected. The receiver
(final hop's local delivery) may additionally reorder by `seq`.

### 4.5 Rotation policy ("stateful but short") — resolves the §0 crux
To bound intra-circuit linkability + correlation, **rotate circuits aggressively**
even though they're stateful: tear down and rebuild after `K` messages **or** `T`
seconds, whichever first. This keeps the amortisation within a window while
capping the linkable set. Suggested defaults (tunable, must be sim-validated):
`K = 64`, `T = 120 s`. A circuit carrying only 1 message before rotation is pure
cost → the sender should fall back to the stateless single-cell path for
low-volume flows (§9 opt-in).

---

## 5. Circuit lifecycle + relay DoS (sub-problem C)

Stateful circuits introduce a **new relay resource: per-circuit state** — and a
new DoS surface (cheap to ask a relay to allocate state). Mirror the rendezvous
cap pattern (`rendezvous.rs`):

- **Per-relay circuit table** `(prev_link, circuit_id) → CircuitState{key,
  next_link, circuit_id_out, replay_window, last_used, bytes}`.
- **Caps:** `MAX_CIRCUITS_PER_RELAY` (global, ~10k like rendezvous),
  `MAX_CIRCUITS_PER_UPSTREAM_PEER` (fairness, like `MAX_COOKIES_PER_PEER = 64`),
  `MAX_BYTES_PER_CIRCUIT`. At cap → reject build (or LRU-evict idle).
- **Idle timeout** → teardown; explicit `RelayChainMsg::CircuitTeardown` frame
  (new variant) so the sender can release state early; teardown propagates inward.
- **Build cost:** the install (B1) is one onion pass — bound build rate per
  upstream peer (token bucket) so an adversary can't churn circuit allocations.
- **Memory:** ~(`circuit_key 32` + ids `8` + window `~128` + bookkeeping) ≈
  200 B/circuit; 10k ≈ 2 MiB. Acceptable; cap enforces it.

---

## 6. Anonymity threat-model checklist (gate before any wire change)

1. **Intra-circuit linkability (the core regression).** Every hop links N
   messages. Bound by rotation (§4.5); the policy `K/T` IS the anonymity knob and
   must be sim-justified, not guessed.
2. **End-to-end timing correlation over a long flow.** A persistent circuit is a
   better correlation target than isolated cells. Rotation + (optional) cover
   padding bound the window.
3. **Circuit-build fingerprint.** The build cell (B1) must be
   bit-indistinguishable from a data cell / a stateless cell at every hop, or the
   build is a fingerprint (cf. A.2 §4.1). Same `CELL_SIZE`, same outer shape.
4. **CircuitId as a traffic-analysis tag.** Per-link re-tagging (D1) means a
   single hop sees only its two link ids, not a global id — good. Ensure
   `circuit_id` is random per link (not sender-global) so colluding non-adjacent
   hops can't join on it.
5. **Predecessor / long-term intersection over reused circuits.** Reuse raises
   the classic predecessor attack's signal. Rotation is the mitigation; quantify
   in sim.
6. **Reused-key compromise blast radius.** One circuit-key compromise → all N
   messages (§0 cost 3). Bound by `K` and by optional periodic re-key.
7. **State-exhaustion DoS** (§5 caps) — bounded build rate + per-peer circuit cap
   + idle teardown.

Ship only with a bounded, sim-validated answer to each. **Item 1 (linkability)
is the one that can make 482.7 a net anonymity loss if `K/T` are too loose.**

---

## 7. Interaction with A.2 (relay reputation)

Two-way:
- 482.7 **enables** A.2 §4.3 (per-hop authenticated acks → real attribution),
  the only crisp-attribution option.
- 482.7 also **raises A.2's value**: a mid-stream drop on a *reused* circuit kills
  **N** messages, not one — bigger blast radius → downweighting a dropping relay
  matters more. Conversely A.2's reputation feeds 482.7's relay choice at build.

So sequencing 482.7 → A.2 is coherent: build the stateful substrate, then add the
attribution that needs it.

---

## 8. Integration points

- `crates/veil-anonymity/src/cell.rs`, `packet.rs` — D1 outer header
  `[circuit_id][seq]`; update `max_payload_for_hops` (data cells vs build cells
  have different budgets).
- `crates/veil-anonymity/src/onion.rs` — add a symmetric-layer mode (cached
  `circuit_key`, seq-derived nonce) alongside the existing per-message ephemeral
  mode (kept for stateless sends + the build cell).
- New `crates/veil-anonymity/src/circuit_state.rs` — `CircuitState`, the relay
  circuit table, replay window, caps, teardown.
- `crates/veil-dispatcher/src/anonymity.rs` — relay path: on a data cell, look up
  circuit, check replay window, peel symmetric layer, forward under
  `circuit_id_out`; on build, install state; on teardown, release.
- `crates/veil-anonymity/src/sender.rs` — sender-side circuit cache (`peer →
  live CircuitId + keys + seq`), reuse policy (§4.5 rotation), fall back to
  stateless for low-volume.
- `crates/veil-proto/src/family.rs` — new `RelayChainMsg` variants:
  `CircuitBuild`, `CircuitData`, `CircuitTeardown` (keep `Hop` for stateless).
- `crates/veil-node-runtime/src/runtime/mod.rs` — `send_anonymous` picks
  stateful-vs-stateless per flow volume; owns the sender circuit cache (sibling
  to `AnonymityState`).

---

## 9. Migration / compatibility

- **Keep the stateless single-cell path as the default and the fallback.** 482.7
  is **opt-in per flow**: only flows expected to send many messages to the same
  peer (interactive chat) build a circuit; everything else stays stateless
  (unlinkable, no new state).
- Wire-version gate the new `RelayChainMsg` variants + cell header; a relay that
  doesn't support circuits rejects `CircuitBuild` → sender falls back to
  stateless. No flag day.
- Capability advertised in the relay directory entry (a "supports-circuits" bit)
  so the picker only builds through capable relays.

---

## 10. Recommendation (maintainer decision required)

0. **Exhaust the anonymity-preserving path first**
   ([`PLAN_ANON_PRESERVING_CIRCUIT_OPTIMIZATION.md`](PLAN_ANON_PRESERVING_CIRCUIT_OPTIMIZATION.md)):
   measure the overhead decomposition, then path-selection caching (selection
   cost, corridor-level anonymity), Sphinx compression (bandwidth + free replay,
   zero anonymity cost), deterministic nonce. These recover the large + medium
   costs without spending anonymity. Only if per-message DH/CPU is *measured* to
   remain the bottleneck after that does 482.7 have a case.
1. **Decide the anonymity trade (§0/§6 item 1).** Is the per-flow latency/
   throughput win worth losing per-message unlinkability for chat flows? If the
   answer is "only with tight rotation," set `K/T` conservatively and treat them
   as the primary tunable. If "no," **don't build 482.7** — keep stateless and
   accept higher chat overhead.
2. **If yes, build in this order:**
   1. cell header (D1) + symmetric-layer onion mode + per-circuit replay window
      (the data plane), behind a wire-version gate.
   2. relay circuit table + caps + teardown + build-rate limit (the state plane).
   3. sender circuit cache + rotation policy (§4.5) + stateless fallback.
   4. **§6 anonymity review + §8 (A.2's) sim harness** extended with: linkability
      window vs `K/T`, correlation gain of reused circuits, build-rate DoS.
   5. opt-in wiring for interactive chat only.
3. **Then** revisit A.2 §4.3 (per-hop attribution) on top of the stateful
   substrate.

**Net:** 482.7 is a *real* perf win for chat (≈2× payload + no per-message ECDH),
but it spends a strong anonymity property (per-message unlinkability) and adds a
relay-state DoS surface. The mitigation (aggressive rotation) directly fights the
amortisation, so the whole epic lives or dies on the `K/T` rotation point — which
must be chosen from a sim model, not intuition. Sequence it **before A.2** (which
depends on it) but **after** confirming, with data, that chat overhead actually
hurts on the live network.
