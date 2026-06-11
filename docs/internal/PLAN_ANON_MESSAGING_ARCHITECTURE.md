# Anonymous authenticated messaging — consolidated architecture (for review)

> **⚠️ REVIEW OUTCOME (2026-06): DESCOPE.** Two independent reviews found a
> **verified-critical error** in this draft and recommend NOT building the full
> "Signal-over-Tor" epic now. Corrections + the descoped direction are folded in
> below; the original full-epic prose is kept (struck through in spirit) as the
> reviewed artifact.
>
> **The critical finding (verified against code):** the central claim "Bob
> authenticates Alice (via X3DH)" is **FALSE**. `crates/veil-crypto/src/x3dh.rs`
> is **not** X3DH — `sender_encapsulate` (x3dh.rs:142) does ONE ML-KEM-768
> encapsulation to the recipient's public prekey and mixes `sender_node_id` into
> the HKDF info as a **public label** (x3dh.rs:200), with **no DH contribution
> from Alice's private identity key**. So anyone holding Bob's published EK can
> forge a message claiming any sender → **zero sender authentication.** The
> codebase already documents this for the identical primitive
> (`veil-e2e/src/lib.rs:285` "a KEM proves nothing about the origin"). Sender
> authentication is the ONE genuinely-missing §0 property and it must be **built**
> (per-message identity-subkey signature, OR a real identity-bound AKE: X25519
> IK-DH + ML-KEM hybrid) — it is **independent of circuits and the ratchet.**
>
> **Descoped direction (both reviews):**
> 1. **Auth line (do first, independent of circuits):** add real sender-binding
>    to the EXISTING anonymous payload — identity-subkey signature inside the
>    payload, or an identity-bound AKE. Closes "Bob authenticates Alice" with no
>    telescoped circuits and no Double Ratchet.
> 2. **Transport line (incremental, measured):** W1 (done) + W2 selection-input
>    caching (hits the W0-measured bottleneck — selection, 24–98× build — at zero
>    anonymity cost) + wire the existing onion origination to production. This IS
>    the "exhaust the anonymity-preserving path first" the other plans mandate.
> 3. **Stateful circuits (482.7) + Double Ratchet + return-plane:** DEFER until
>    (i) a post-W2 measurement shows per-message DH is still the bottleneck (W0
>    says it is NOT — selection dominates), and (ii) auth + return-path are
>    designed. Net-anonymity-loss risk (intra-circuit linkability, unjustified
>    K/T) is unresolved.
>
> The rest of this document is the reviewed full-epic architecture; read it with
> the corrections in §3/§5/§8 (below) applied.

> **Status (2026-06):** ARCHITECTURE DRAFT for independent review, no code.
> Supersedes `PLAN_AUTHENTICATED_ONION_DELIVERY.md` (single-cell, source-routed)
> — the budget / hybrid-signature / reply / incoming requirements all pointed
> away from single-cell onion toward **stateful bidirectional circuits**. Target:
> "Signal-over-Tor for veil" — Tor-style telescoped circuits for network
> anonymity + an X3DH/Double-Ratchet E2E session for authentication, confidential-
> ity, forward secrecy, and post-compromise security. This is a large,
> security-critical epic (multi-quarter); recommend a full design review before
> any implementation.

## 0. Goal & threat model

A message from Alice to Bob such that:
- **Relays learn neither the (Alice, Bob) pair nor the content** — no single
  relay knows both ends.
- **Bob authenticates Alice** — Bob cryptographically verifies the message is
  from Alice's identity, NOT forgeable. (Bob may already know Alice as a contact,
  or resolve her identity.)
- **Bob can reply** — the channel is bidirectional.
- **Bob can receive unsolicited anonymous messages** — without a prior session.
- **Forward secrecy + post-compromise security** — compromising a key today
  reveals neither past messages nor (after self-healing) future ones.
- **Bob never learns Alice's network location** — identity ≠ location.

Out of scope (inherent to low-latency anonymity): a global passive adversary
doing end-to-end timing correlation; relay flooding (relay-reputation line,
Epic 482.3/4, already shipped Phase A).

## 1. Two clean layers

```
┌─────────────────────────────────────────────────────────────┐
│ Layer B — E2E security (endpoint ↔ endpoint, over the circuit)│
│   X3DH authenticated key agreement  →  Double Ratchet         │
│   gives: sender AUTH, confidentiality, forward secrecy, PCS    │
├─────────────────────────────────────────────────────────────┤
│ Layer A — anonymous transport (relay anonymity)               │
│   telescoped bidirectional circuits  +  rendezvous (incoming)  │
│   gives: no relay knows both ends; bidirectional; reachable    │
└─────────────────────────────────────────────────────────────┘
```

The layers are independent: Layer A hides *where*, Layer B authenticates *who*
and protects content. Ratchet messages travel as circuit data. This separation
is what makes the design reviewable and each layer individually testable.

## 2. Layer A — anonymous transport

### A1. Telescoped bidirectional circuits (= Epic 482.7, reframed)
Build a circuit through K relays by **telescoping**: Alice does an authenticated
DH with relay 1 (CREATE), then through relay 1 extends to relay 2 (EXTEND), etc.
Each hop ends up with a **per-hop symmetric key**; data cells are onion-wrapped
with those symmetric keys (cheap, no per-message ECDH). The circuit is
**bidirectional** — replies flow back down the same hops.

- Relay anonymity: relay i knows only hop i-1 and i+1, never both ends.
- Budget: data is **circuit-data across many cells**, so a large (hybrid-subkey)
  X3DH first message or a multi-KB message is fine — no single-cell 267 B cap.
- Per-hop forward secrecy at the transport level: the build uses ephemeral DH per
  hop, so a later relay-key compromise doesn't retro-decrypt circuit traffic.
- **Cost (honest):** stateful — each relay holds per-circuit state (keys, next
  hop, replay window); intra-circuit linkability (a hop links the N cells of a
  circuit, but NOT the ends — acceptable under §0). Needs build/teardown, caps,
  DoS bounds, and a rotation policy (the K/T crux from
  `PLAN_STATEFUL_CIRCUITS_482_7.md` §4.5/§5/§6). **This is the bulk of the work.**

veil reuse: the existing single-cell onion (`onion.rs`, post-W1) is the crypto
for the CREATE/EXTEND build cells; relay selection + AS-diversity + relay
reputation (shipped) choose the hops.

### A2. Rendezvous for unsolicited incoming (existing primitive, circuit-integrated)
Bob publishes a `RendezvousAd` (exists) naming a rendezvous relay + an
`auth_cookie` + his receiver key. Alice builds a circuit to the rendezvous relay
and sends an `IntroducePayload` (exists); the rendezvous forwards it to Bob's
side. The Introduce carries Layer-B's X3DH first message (below), so first
contact + key agreement happen in one shot. After that, Bob replies down a
circuit (his own, toward the rendezvous, or a direct bidirectional leg).

veil reuse: `RendezvousAd`, `IntroducePayload`, `register_with_rendezvous`,
`send_via_rendezvous` — extend from single-cell to circuit-data.

## 3. Layer B — E2E security (over the circuit)

### B1. Authenticated key agreement — MUST BE BUILT (the critical gap)
> **CORRECTION (review):** `crates/veil-crypto/src/x3dh.rs` is **NOT X3DH and
> gives NO sender authentication.** `sender_encapsulate` is one ML-KEM-768
> encapsulation to Bob's public prekey; `sender_node_id` is a HKDF **label**, not
> a DH contribution from Alice's private identity key (x3dh.rs:142,200). Anyone
> with Bob's EK forges any sender (identical to meta-E2E, which the code marks
> unauthenticated, `veil-e2e/src/lib.rs:285`). It is a reusable **KEM/confidential-
> ity primitive**, NOT an AKE.
>
> Real sender authentication requires Alice's **private identity key** in the key
> agreement. Two options, both **independent of circuits/ratchet** (Auth line):
> - **(a) Per-message identity-subkey signature** inside the payload (the
>   approach the superseded single-cell spec had — removing it is what removed
>   auth). Gives non-repudiation; +64 B (Ed25519) or +~660 B (Falcon hybrid).
> - **(b) Identity-bound AKE** — a real X3DH = X25519 `DH(IK_Alice, …)` + ML-KEM
>   hybrid, mixing Alice's long-term key. Gives deniability (Signal-style).
>
> Pick one (open question §10-Q3: deniable vs non-repudiation). Bob then verifies
> against Alice's resolved/known identity (contact cache → `resolve_identity_
> verified`). The current `x3dh.rs` provides the ML-KEM half + FS-by-consume, but
> the identity-DH/signature half does not exist yet.

### B2. Double Ratchet (NEW — not in veil today)
After X3DH seeds the root key, a **Double Ratchet** (symmetric-key chain per
message + periodic DH ratchet) gives **per-message forward secrecy AND
post-compromise security** for the ongoing conversation. Persistent per-contact
ratchet state at both ends. This is the piece veil lacks and must build (or
adopt a vetted implementation — do NOT hand-roll the ratchet).

### B3. What Bob learns / verifies
- WHO: Alice's identity (from the authenticated X3DH binding) — verified, not
  forgeable.
- Content: confidential to Bob (ratchet), independent of the circuit.
- NOT where: the circuit delivered the cells from the last relay; Alice's network
  location is never exposed.

## 4. A message's life

1. (first contact) Alice fetches Bob's `RendezvousAd` + prekey bundle from DHT.
2. Alice builds a telescoped circuit to the rendezvous relay (A1), selecting hops
   via the shipped reputation/diversity picker.
3. Alice runs X3DH (B1) → root key; sends `Introduce` carrying the X3DH first
   message + first ratchet message (A2) over the circuit.
4. Rendezvous forwards to Bob; Bob completes X3DH, authenticates Alice, decrypts.
5. Ongoing: both sides Double-Ratchet (B2) messages as circuit data,
   bidirectionally, rotating circuits per the K/T policy (A1) to bound
   linkability.

## 5. veil: have vs build

Three statuses: ✅ usable as-is · ⚠ reusable only with protocol changes · ❌
new/not reusable.

| Piece | Status |
|---|---|
| Onion-layer crypto (build cells) | ✅ `onion.rs` (post-W1 v2; per-hop overhead **81 B**, payload `510−81·N`, N=3 → **267 B**, N≤6 fits) |
| Relay directory + signed publish loop + selection + AS-diversity + reputation | ✅ shipped (the *infrastructure* is wired; only message **origination** — `send_anonymous` — is sim-only) |
| Rendezvous primitive | ⚠ `rendezvous.rs` (single-cell; `IntroducePayload` capped 256 B; ML-KEM CT 1088 B ≫ ~172 B single-cell → "Introduce carries the X3DH first message" needs the not-yet-built circuit data plane) |
| ML-KEM seal + FS-by-consume (`x3dh.rs`) | ⚠ reusable as a **confidentiality** primitive only; it is **NOT** sender-auth (see §B1) |
| **Sender authentication (identity-subkey signature OR identity-bound AKE)** | ❌ NEW — the critical missing §0 property |
| **Telescoped stateful circuit state machine + caps + teardown** | ❌ NEW (the bulk — Epic 482.7) |
| **Return data plane (for replies / bidirectional)** | ❌ NEW — does not exist; building it is itself a correlation surface (A.2 §2 C1) |
| **Double Ratchet** | ❌ NEW (vetted impl, not hand-rolled) |
| **Persistent prekey store** | ❌ `PrekeySecretStore` is an in-memory MVP (tests only); restart loses seeds → undelivered first-contact messages become permanently undecryptable (**data loss**) |
| Production IPC wiring for the anonymous-authenticated mode | ❌ NEW (origination sim-only, `scenarios.rs:5380`) |
| W2 selection-input caching | ❌ NEW but **highest value/risk** (hits the W0-measured bottleneck) — missing from this plan; the descope adds it |

## 6. Security properties (claims — to be reviewed)

| Property | Mechanism | Holds today? |
|---|---|---|
| No relay knows (Alice, Bob) | telescoped circuit (A1) | ❌ circuits not built |
| No relay reads content | circuit layers (A1) + ratchet (B2) | partial (onion content sealed; no ratchet) |
| **Bob authenticates Alice** | ~~X3DH binding~~ → **new auth (§B1)** | ❌ **the critical gap — x3dh.rs is a KEM seal, not auth** |
| Bidirectional reply | return data plane (A1) | ❌ return plane not built; itself a C1 correlation surface |
| Unsolicited incoming | rendezvous (A2) | ⚠ primitive exists; first-contact-in-one-Introduce blocked by budget (needs circuits) |
| Forward secrecy (relay) | per-hop ephemeral DH at build | ⚠ holds only under telescoped B2; the 482.7-recommended single-pass B1 reuses a key under the hop's static key → claim breaks |
| Forward secrecy + PCS (endpoints) | Double Ratchet (B2) | ❌ no ratchet (first-message FS via prekey-consume only) |
| Bob can't learn Alice's location | circuit (A1) | ❌ circuits not built |

**Net: of the §0 properties, only relay-content-confidentiality (onion) and
first-message FS partially hold today; the headline "authenticates WHO" does
NOT.**

## 7. Tradeoffs & costs (honest)

- **Stateful-circuit linkability** — a hop links the N cells of a circuit (not the
  ends). Acceptable under §0; bounded by circuit rotation (K/T). This is the
  property the earlier anonymity-preserving docs protected MORE strongly; §0's
  threat model relaxes it.
- **Relay state + DoS** — per-circuit state is a new resource/attack surface;
  needs caps, build-rate limits, idle teardown (482.7 §5).
- **Complexity** — this is two non-trivial subsystems (Tor-like circuits + Signal-
  like ratchet). Largest line of work in the project; must be phased + reviewed +
  sim-validated.
- **Correlation** — long-lived circuits are better timing-correlation targets;
  rotation + (optional) padding bound it (482.7 §6).

## 8. Anonymity threat-model gate (before any wire change)
Inherit the 482.7 §6 checklist (intra-circuit linkability vs K/T, long-flow
correlation, build fingerprint, CircuitId as a tag, predecessor/intersection,
reused-key blast radius, state-exhaustion DoS) PLUS the E2E layer, PLUS the
review-added items below — each needs a bounded, sim-validated answer:

- **KCI / identity-binding** (root of the verified auth gap) — the sender-auth
  mechanism must bind Alice's private identity key; verify no key-compromise-
  impersonation.
- **Return-path correlation (C1, from A.2 §2)** — any reply/bidirectional channel
  is a confirmable round-trip + a timing edge for the last relay; the §6 checklist
  did NOT inherit this from A.2_MIDSTREAM.
- **Prekey exhaustion + persistence + data loss** — one-time prekeys can be
  drained (first-contact DoS) or forced into reduced-FS reuse; `PrekeySecretStore`
  is in-memory only → restart = permanent loss of undelivered first-contact
  messages (user data loss).
- **Identity-resolution deanon** — "Bob resolves Alice via DHT" can leak, by the
  query pattern, that Bob talks to Alice.
- **Public rendezvous metadata** — `RendezvousAd` is keyed by `receiver_node_id`
  and names the rendezvous node; `auth_cookie` is public in the DHT ad
  (`rendezvous.rs:1668`). Specify exactly what receiver-reachability is hidden,
  from whom, and what the cookie does/doesn't protect.
- **Replay on generic relay cells** — the onion path has none (`onion.rs:94`); the
  E2E layer needs its own replay analysis.

## 9. Phased implementation plan (after review)

1. **Circuit state machine (Layer A1)** — CREATE/EXTEND build (reuse onion crypto),
   per-hop symmetric keys, bidirectional data cells, per-circuit replay window,
   teardown; relay-side circuit table + caps + build-rate limit. Sim-validate
   relay anonymity + DoS bounds.
2. **Circuit-integrated rendezvous (A2)** — extend `RendezvousAd`/`Introduce` to
   ride circuit data; incoming reachability.
3. **X3DH wire-up (B1)** — drive `x3dh.rs` from the messaging flow; add the
   identity-key authentication mix + the contact-cache/resolve verification.
4. **Double Ratchet (B2)** — adopt a vetted ratchet; per-contact state; per-message
   FS + PCS.
5. **Production IPC mode** — `anonymous_authenticated` send/receive.
6. **Optimisations** — circuit rotation policy (K/T), W3 Sphinx for build cells,
   padding/cover if §8 demands.

## 10. Open questions for review

1. **Circuit rotation K/T** — the central anonymity↔perf knob (linkability window
   vs build cost). Default? Must be sim-justified.
2. **Ratchet implementation** — which vetted library/spec to adopt for the
   Double Ratchet (and a PQ-hybrid variant)? Never hand-roll.
3. **X3DH identity-auth** — exact binding of long-term identity keys into the
   shared secret so Bob's authentication of Alice is sound (and deniable if
   wanted — Signal's X3DH is deniable; do we want that or non-repudiation?).
4. **Telescoped vs single-pass build** — telescoping gives per-hop FS + per-hop
   ephemeral contribution but costs a build RTT per hop; is the latency
   acceptable, or do we want a single-pass key install (cheaper, no per-hop
   freshness)?
5. **State/DoS budget** — per-relay circuit caps + build-rate limits sized to the
   testnet hardware.
6. **Migration/coexistence** — keep meta-E2E (current prod anonymity) during
   rollout; gate the new mode behind a capability + flag.
