# Anonymous authenticated messaging — consolidated architecture (for review)

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

### B1. X3DH authenticated key agreement (veil has a one-shot form)
The initiator (Alice) runs X3DH against Bob's published prekey bundle, mixing in
**both parties' long-term identity keys** → a shared secret that (a) authenticates
Alice to Bob (only Alice's identity key produces it) and (b) gives first-message
forward secrecy (prekey consumed). veil already ships an X3DH-style prekey scheme
(`crates/veil-crypto/src/x3dh.rs`: `generate_prekey`, `PrekeyBundle`,
`PrekeySecretStore`, ML-KEM-768, FS-by-consume) — **this is the authentication
mechanism** (replaces the per-message signature from the superseded single-cell
spec; cleaner, and authentication is mutual).

Bob authenticates Alice by checking the handshake binds **Alice's resolved/known
identity** (contact cache → else `resolve_identity_verified`; cache policy per
the earlier §8.2). PQ-hybrid: X25519 + ML-KEM (already ML-KEM in x3dh.rs); add a
classical+PQ identity-key mix.

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

| Piece | Status |
|---|---|
| Onion-layer crypto (build cells) | ✅ `onion.rs` (post-W1 v2) |
| Relay directory + selection + AS-diversity + reputation | ✅ shipped |
| Rendezvous primitive | ✅ `rendezvous.rs` (single-cell — extend to circuits) |
| X3DH prekey handshake (one-shot FS, ML-KEM) | ✅ `x3dh.rs` (wire into the flow; add identity-auth mix) |
| **Telescoped stateful circuit state machine + caps + teardown** | ❌ NEW (the bulk — Epic 482.7) |
| **Double Ratchet** | ❌ NEW (vetted impl, not hand-rolled) |
| Production IPC wiring for the anonymous-authenticated mode | ❌ NEW |

## 6. Security properties (claims — to be reviewed)

| Property | Mechanism |
|---|---|
| No relay knows (Alice, Bob) | telescoped circuit (A1) |
| No relay reads content | circuit symmetric layers (A1) + E2E ratchet (B2) |
| Bob authenticates Alice | X3DH identity-key binding (B1) |
| Bidirectional reply | bidirectional circuit (A1) |
| Unsolicited incoming | rendezvous (A2) |
| Forward secrecy (relay) | per-hop ephemeral DH at build (A1) |
| Forward secrecy + PCS (endpoints) | Double Ratchet (B2) |
| Bob can't learn Alice's location | circuit (A1) |

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
reused-key blast radius, state-exhaustion DoS) PLUS the E2E layer (X3DH identity
binding soundness, ratchet state-compromise semantics, replay). Each needs a
bounded, sim-validated answer.

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
