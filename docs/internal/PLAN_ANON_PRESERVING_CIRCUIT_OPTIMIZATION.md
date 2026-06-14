# Anonymity-preserving alternatives to stateful circuits (482.7) — design sketch

> **Status (2026-06):** DESIGN DRAFT, no code. Companion to
> [`PLAN_STATEFUL_CIRCUITS_482_7.md`](PLAN_STATEFUL_CIRCUITS_482_7.md). 482.7
> buys per-flow QoS by spending a real anonymity property (per-message
> unlinkability at middle/exit hops — see that doc §0). This document asks: **how
> much of the "interactive chat overhead" can be reclaimed WITHOUT that cost?** —
> and shows that the *expensive* part of the overhead is recoverable at near-zero
> anonymity cost, while 482.7's machinery amortises the *cheapest* part.

Epic: 482.7-alt (anonymity-preserving). Same motivation as 482.7 ("interactive
chat shows high re-build overhead vs message latency"), opposite priority on the
anonymity↔QoS trade.

---

## 0. Decompose the overhead first (measure before building)

"Re-build overhead per message" is three different costs, with three very
different anonymity prices to amortise:

| Cost component | Per message, today | Likely magnitude | Amortise without linkability? |
|---|---|---|---|
| **Relay selection** (candidate fetch, Vivaldi RTT, AS-diversity map, reputation sort) | full pass per message | **largest** (DHT/cache work, map build) | **YES — path-selection caching (§4), corridor-level cost only** |
| **Bandwidth** (per-hop onion overhead eats payload) | 92 B/hop → 234 B usable at 3 hops | medium (matters for larger payloads) | **YES — Sphinx-style compression (§5), zero anonymity cost** |
| **Per-message ECDH + onion wrap** (N X25519 DH + AEAD) | N DH (~tens of µs each) | **smallest** (CPU, negligible at chat rates) | **NO — only cached keyed state (= 482.7) amortises this, and it is linkable** |

**The punchline:** 482.7 spends a strong anonymity property to amortise the
**smallest** cost (per-message DH). The **largest** cost (selection) and the
**medium** cost (bandwidth) are both recoverable at near-zero anonymity cost by
the techniques below. So before funding 482.7:

1. **Measure the decomposition** on the live/sim network — where does the
   per-message latency actually go (selection vs crypto vs bandwidth)? If it's
   selection (most likely), 482.7 is solving the wrong cost.
2. Apply §3–§5 (anonymity-preserving) and re-measure. 482.7 is justified only if
   per-message DH/CPU is *proven* the residual bottleneck AND the §6 anonymity
   trade is accepted.

---

## 1. Current cost (anchors)

- Selection: `runtime/mod.rs` builds `rtt_estimator` (Vivaldi), the AS-diversity
  map (`build_as_diversity_map(&discovered_peers_cache)`), and runs the
  reputation-aware picker — **per `send_anonymous`/`send_via_rendezvous` call**.
- Bandwidth: `packet.rs` `510 - 92·N`; per-hop 92 B = `32 eph_pk + 12 nonce + 16
  tag` (`onion.rs:109`) + 32 next-hop id.
- Crypto: `onion.rs:133-260` — **fresh ephemeral DH per layer per message**.

---

## 2. The anonymity-cost ladder (centrepiece)

From cheapest anonymity cost to most expensive:

1. **Deterministic nonce (§3)** — anonymity cost **none**; saves 12 B/hop.
2. **Path-selection caching, fresh onion per message (§4)** — anonymity cost
   **corridor-level only** (a middle hop sees "same neighbour pair" repeated,
   mixed with every other sender on that corridor — never a definitive
   per-sender grouping); saves the largest cost (selection).
3. **Sphinx-style onion compression (§5)** — anonymity cost **none** (same
   per-message-unlinkable, fixed-size threat model as today); saves bandwidth +
   adds replay protection for free.
4. **Stateful circuits / cached keyed state (= 482.7)** — anonymity cost
   **per-message linkability at every middle/exit hop, definitively** (a
   `CircuitId`/cached key groups one sender's N cells regardless of corridor
   traffic); saves only the smallest cost (per-message DH).

Stop climbing the ladder at the point where the measured bottleneck is gone.
Almost certainly that is rung 2 (+1, +3), not rung 4.

---

## 3. Technique: deterministic nonce (trivial, do anytime)
The per-layer nonce (12 B) is currently random (`onion.rs`). Derive it instead
from the per-layer shared secret / ephemeral (e.g. `nonce =
H(shared_secret)[..12]`), which is already unique per layer (fresh ephemeral).
Saves 12 B/hop with **zero** anonymity or security change (the nonce stays unique
per AEAD key). N=3 → 234 → 270 B payload. Cheap; ship independently.

---

## 4. Technique: path-selection caching (recovers the LARGEST cost, near-zero anon cost)

**Idea:** cache the *relay selection* (the chosen relay node_ids = the path), NOT
any keyed circuit state. Reuse the same path for the next few messages to the
same peer, but build a **fresh independent onion** (fresh ephemerals, fresh
nonces) for every message.

**Why this is anonymity-cheap (the key analysis):**
- The **entry hop** already knows the sender (its OVL1 session) and already saw
  all the sender's cells — stateless or not. Path reuse adds nothing there.
- A **middle hop** with a fresh onion per message **cannot cryptographically
  link** two cells. The only thing it observes is the *link pattern*: it receives
  from prev-hop `A` and forwards to next-hop `C`. Reusing the path means it sees
  the same `(A, C)` neighbour pair repeatedly — but **mixed with every other
  sender using the `A→me→C` corridor.** The anonymity set is "all senders on this
  corridor," not "this one sender's N cells."
- Contrast 482.7: a `CircuitId`/cached key groups one sender's N cells
  **definitively**, regardless of how busy the corridor is. So path-caching is
  **strictly ≥ 482.7 on anonymity** — never worse, and much better when the
  corridor carries other traffic.

**Rotation is cheap here (unlike 482.7).** Re-selecting a path costs only the
selection work we're amortising; there's no keyed state to tear down. So rotate
aggressively (e.g. new path every `K=16` messages or `T=30 s`) to keep the
corridor-pattern window small — *and* rotation does not fight any amortisation
(it just re-pays the selection cost we were skipping). Sweet spot: short reuse
windows, frequent re-selection.

**Caveat (sparse networks):** if a corridor carries only this sender's traffic
(tiny network), the middle hop effectively links by corridor anyway. Bound by
rotation + by preferring busier corridors; document that the anonymity benefit
scales with network traffic (true of all low-latency anonymity systems).

**Cost saved:** the Vivaldi/diversity-map/reputation-sort/candidate-fetch pass,
done once per path instead of once per message — the largest component (§0).

---

## 5. Technique: Sphinx-style onion compression (recovers BANDWIDTH, zero anon cost)

veil's onion is **not** packet-optimal: it carries a **fresh 32-byte
ephemeral_pk in every layer** (`N·32 B`). The Sphinx construction
(Danezis–Goldberg 2009; the basis of Lightning/HORNET/Nym onions) carries **one**
group element re-blinded at each hop, plus a fixed-size header and a single
per-hop MAC.

**Win (anonymity-neutral — same per-message-unlinkable, fixed-size model):**
- `N·32 B` ephemerals → **one 32 B** element (blinding chain).
- per-layer AEAD `nonce(12)+tag(16)` → a stream-cipher header + one **16 B MAC**
  per hop.
- per-hop overhead ≈ `16 (MAC) + 32 (next-hop)` = 48 B vs 92 B; total overhead
  `32 + 48·N` vs `92·N`. **N=3: 234 → ~334 B payload (~+40%); N=5: 50 → ~238 B
  (large).**

**Bonus — free replay protection (the feature 482.7 lists):** each hop derives a
per-message tag from its shared secret `s_i`; a relay keeps a bounded seen-set of
`s_i` and drops replays. This is **per-message and unlinkable** (the tag differs
every message), so it gives 482.7's "anti-replay" requirement **statelessly, at
no linkability cost** — and closes the current "no replay protection on generic
cells" gap (`onion.rs:84-86`).

**Costs / risks (must be in the plan):**
- **Group choice:** Sphinx blinding needs clean scalar multiplication; raw
  X25519 (Montgomery, clamped) is awkward for blinding chains. Switch the
  anonymity-hop keys to **Ristretto255** (prime-order, no cofactor/clamping
  pitfalls). That is a relay-directory key-type migration (advertise a ristretto
  pubkey) — **anonymity-neutral**, but a compat event (§7 of 482.7's migration
  pattern: version-gate, both onions coexist, capability bit).
- **Do NOT hand-roll Sphinx.** It has subtle security preconditions (domain
  separation, the MAC over the right header bytes, padding to a fixed size to
  prevent position leakage). Adapt a vetted implementation + its test vectors;
  align to the published security proof. A bespoke Sphinx is a footgun.
- **Fixed max hop count `r`:** Sphinx headers pad to support up to `r` hops; fix
  `r` (e.g. 5, matching today's cap) and pad shorter paths. Padding is what keeps
  position from leaking — required, not optional.
- **CPU unchanged:** still ~`N` scalar mults sender-side + 1 per relay; Sphinx
  saves bytes, not DH count. (That's fine — DH is the smallest cost, §0.)

---

## 6. What CANNOT be preserved (the honest boundary)

Amortising the **per-message ECDH** (caching a key a relay reuses across N
messages) is logically equivalent to that relay being able to link the N
messages — see 482.7 §0. There is no construction where a relay reuses keyed
state for cheaper processing yet cannot tell the messages apart. So:

- the per-message-DH cost is the **only** component whose amortisation requires
  linkable state (482.7);
- it is also the **smallest** component (§0);
- therefore the anonymity-preserving path recovers the large + medium costs
  (selection, bandwidth) and simply **accepts** the small per-message-DH cost
  rather than paying anonymity to remove it.

---

## 7. Anonymity properties (gate)

| Technique | Per-message unlinkable (middle/exit)? | New correlation surface? | Threat-model change |
|---|---|---|---|
| §3 nonce | yes | none | none |
| §4 path-cache | yes (crypto); corridor-pattern visible, mixed | none beyond link-level corridor observation (already partly visible) | bounded by rotation + corridor traffic |
| §5 Sphinx | **yes** | none | none (same model, smaller packets) + adds replay protection |
| 482.7 stateful | **no** (definitive linkage) | long-lived flow correlation | real regression |

§4 needs the corridor analysis documented + rotation defaults sim-checked; §5
needs the implementation to match Sphinx's proof preconditions; both are
otherwise anonymity-neutral-to-cheap.

---

## 8. Integration points

- §3 nonce: `crates/veil-anonymity/src/onion.rs` (`wrap_for_hop` /
  `unwrap_at_hop`) — derive nonce; bump format version.
- §4 path-cache: `crates/veil-node-runtime/src/runtime/mod.rs` — a sender-side
  `peer → {cached path (relay node_ids), built_at, msg_count}` map (sibling to
  `AnonymityState`); reuse path while within `K/T`, else re-select; **always
  fresh onion** via the existing `build_outbound_anonymous_cell_*`. No relay
  change, no wire change.
- §5 Sphinx: a near-total rewrite of `crates/veil-anonymity/src/onion.rs` +
  `cell.rs`/`packet.rs` budgets; the relay seen-set lives in
  `crates/veil-dispatcher/src/anonymity.rs`; relay-directory key type →
  Ristretto255 (`AnonymityState.x25519_sk` → ristretto); wire-version gate +
  capability bit; both onions coexist during migration.

---

## 9. Recommendation

1. **Measure the §0 decomposition first** (selection vs crypto vs bandwidth per
   message). Cheap, no anonymity cost, decides everything.
2. **Ship §3 (deterministic nonce)** — trivial, independent.
3. **If selection dominates (expected): build §4 path-selection caching** —
   recovers the largest cost at corridor-level anonymity cost only, with cheap
   aggressive rotation. This is the highest value-per-risk step.
4. **If bandwidth matters for the payload mix: build §5 Sphinx compression** —
   anonymity-neutral, adds free replay protection; use a vetted construction,
   plan the Ristretto migration.
5. **Only consider 482.7 (stateful)** if, after §3–§5, per-message DH/CPU is
   *measured* to still be the bottleneck (unlikely at chat rates) AND the
   maintainer explicitly accepts the per-message-unlinkability loss with tight
   rotation.

**Net:** the interactive-chat overhead is almost entirely recoverable **without**
spending anonymity — selection via path-caching (§4), bandwidth + replay via
Sphinx (§5), with a free nonce win (§3). 482.7's linkable machinery targets the
one cost (per-message DH) that is both the smallest and the only one that
*requires* paying anonymity. Go down this path first; treat 482.7 as a last
resort gated on measurement.
