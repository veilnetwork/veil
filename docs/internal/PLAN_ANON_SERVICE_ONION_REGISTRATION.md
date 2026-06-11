# Anonymous service — onion registration at the rendezvous (design sketch)

Status: **DESIGN SKETCH (not scheduled)**
Depends on: Epic 482.7 stateful circuits (return path) — see
`PLAN_STATEFUL_CIRCUITS_482_7.md`. Builds on the rendezvous machinery shipped in
bricks 1–5 + the reply channel (`PLAN_REPLY_CHANNEL.md`).

Goal: let a node host a **location-anonymous service** — a discoverable,
authenticated endpoint whose network location (IP / transport node_id) is hidden
from **everyone, including its own rendezvous relay**. This is the veil analogue
of a Tor onion (hidden) service.

## 0. The exact gap (why today is NOT an anonymous service)

Today a receiver becomes reachable by:

1. publishing a signed `RendezvousAd` to the DHT (keyed by its node_id), and
2. `register_with_rendezvous` → sending `RegisterRendezvous` to relay R **over a
   direct OVL1 session**.

R stores `(transport_node_id, cookie) → R's session to the receiver` and, on an
inbound introduce, sends `ForwardIntroduce` back **down that direct session**
(`dispatcher/anonymity.rs::handle_final_introduce`).

→ **R has a direct link to the receiver, so R learns the receiver's IP +
transport node_id.** The location is hidden from clients and from onion relays,
but NOT from R. Compromise/observe one relay = deanonymize the service. (The
reply channel has the identical residual leak: A→R registration is direct.)

| Observer | Learns receiver LOCATION today | …after onion registration |
|---|---|---|
| Client / sender | no | no |
| Intermediate onion relay | no | no |
| **Rendezvous relay R** | **YES (direct session)** | **no (only the return circuit's last hop)** |
| Receiver's own circuit entry (guard) | n/a | yes (standard onion exposure) |
| Global passive adversary | partial | partial (482.7 §6 correlation caveat) |

## 1. Core idea

Make the receiver reach R **over an onion circuit it builds itself**, and have R
forward introduces back **down that circuit** — never over a direct session. R
holds a *circuit handle* as the return path, not a session. R's view of the
receiver collapses to "the previous hop on some return circuit" — a relay the
receiver chose, not the receiver.

This is precisely the **return path** that 482.7's intro notes is missing
("send only, no return path"). So:

> **anonymous service = 482.7 circuit-build + a return-path forward at the
> rendezvous + cookie-keyed (not session-keyed) registration.**

We keep ONE rendezvous relay per service (do not split into Tor-style separate
Introduction + Rendezvous points) — the existing single-R model is enough once R
forwards over a circuit.

## 2. Flow (after)

```
Receiver S                Relay chain               Rendezvous R           Client C
   |   build onion circuit (482.7) ───────────────────▶|                      |
   |   RegisterRendezvous {cookie, reg_auth_sig} as circuit payload ─────────▶|
   |                                          R: store (cookie) → CircuitState |
   |                                                                           |
   |                          publish RendezvousAd {R, cookie, x25519, …} to DHT (signed)
   |                                                                  C resolves ad ◀──|
   |                                                       C onion → IntroducePayload ▶|
   |                                          R: lookup cookie → return circuit         |
   |◀── ForwardIntroduce as circuit DATA cell, down S's return circuit ───────|
   S decrypts + verifies C; replies via the reply channel (its own circuit)
```

S never opens a session to R. R only ever talks to the **last hop of S's return
circuit**.

## 3. Sub-problems

### A. Return-path circuit (depends on 482.7)
S builds a CircuitId-tagged onion circuit whose terminus is R (482.7 sub-problem
A, single-pass key install / Option B1). R ends up with a `CircuitState` keyed by
`(prev_link, circuit_id_in)` and can push cells back toward S without knowing S.
**This is the hard dependency** — no anonymous service without 482.7's circuit
build + data plane.

### B. Cookie-keyed registration + anti-squat (the registry change)
Today the registry is namespaced by the registrant's **session peer** (transport
id) — that is exactly what we must stop using (R must not see S's id/location).
Replace with:

- R keys a subscription by **`cookie`** (+ the return `CircuitState`), NOT by
  node_id.
- Anti-squat / hijack defence WITHOUT a session identity: the `RendezvousAd` (a
  signed descriptor) commits to a per-rendezvous **registration auth pubkey**
  `reg_pk`. The `RegisterRendezvous` cell carries a signature by `reg_sk` over
  `(cookie ‖ circuit binding ‖ ts)`. R verifies it matches the ad's `reg_pk`
  before storing. So R authenticates "the legitimate holder of this descriptor
  registered this cookie" while learning only the **sovereign/reg pubkey** (which
  is already public in the ad) — **never the location**.
- The introduce's `receiver_node_id` namespacing (current squat defence) is
  retired for onion-registered cookies; the descriptor-signature replaces it.

### C. Introduce → forward DOWN the circuit (R-side)
`handle_final_introduce` gains a branch: if the matched subscription is
circuit-backed, wrap the introduce ciphertext as a **482.7 data cell** and emit
it on the stored return circuit (instead of `send_relay_chain_msg(session,
ForwardIntroduce)`). Reuses 482.7's data plane verbatim.

### D. Receiver side
S: build + **maintain** the R-ward circuit (re-build on teardown/TTL, same
freshness-window discipline as today's re-registration tick); send
`RegisterRendezvous` as a circuit payload; accept forwarded introduces arriving
as circuit cells (decrypt with anonymity x25519, then the existing
`APP_DELIVER_AUTH` / reassembly / verify path is unchanged).

### E. Lifecycle / DoS (mirror 482.7 §5 + rendezvous caps)
Circuit-backed subscriptions cost state at R. Cap per-relay (≈ rendezvous's 10k /
64-per-peer), TTL, and tear down the subscription when its return circuit closes
or expires. A circuit teardown must GC the cookie entry.

## 4. Scope delta on top of 482.7

1. (dep) 482.7 circuit build + data plane + lifecycle.
2. R: circuit-backed subscription store; `handle_final_introduce` forwards down a
   circuit; cookie-keyed lookup.
3. Registration auth: `RendezvousAd` += `reg_pk`; `RegisterRendezvous` +=
   signature; R verifies (replaces transport-id namespacing for these regs).
4. S: build/maintain R-ward circuit; register over it; receive over it.
5. Wire: either a `RegisterRendezvousViaCircuit` `RelayChainMsg` or carry the
   existing `RegisterRendezvous` as a circuit data payload; introduce forwarding
   as circuit data cells.

Additive + opt-in: the **direct** registration path stays for non-anonymous
receivers (cheaper, no circuit upkeep). A node opts into onion registration only
when it wants location anonymity. R runs both keying modes (session-peer vs
cookie+circuit) side by side.

## 5. Threat-model notes (gate before any wire change)

- **What this fixes:** R no longer learns S's location — only S's return-circuit
  last hop + S's already-public descriptor pubkey.
- **Residual, by design:** S's circuit **entry guard** sees S's IP (standard
  onion exposure, not rendezvous-specific). The sovereign/descriptor identity
  stays public in the DHT (identity ≠ location — that is the point of an
  *authenticated* service). Persistent return circuits are correlatable flows —
  inherit 482.7 §6 (intra-circuit linkability, guard discovery, rotation vs
  reuse tension). The return circuit should rotate on the same policy 482.7
  picks.
- **Anti-squat:** descriptor-signed registration prevents cookie hijack without R
  needing a session identity (§3.B). Without it, cookie-only keying would let any
  node claim any cookie.

## 6. Relationship to the reply channel

The reply channel's A-side registration has the SAME direct-session leak
(`PLAN_REPLY_CHANNEL.md` §13.3). Onion registration closes it for replies too:
A would register its one-time reply cookie over a circuit, so R_a stops learning
A's location. The reply channel is forward-compatible — `ReplyBlock` already
carries the relay + cookie + the transport id R keys on (§12 there); the only
change is HOW A reaches R (circuit vs direct) and how R forwards back.

## 7. Implementation slicing (minimal return-path first)

This needs the **return-path subset** of 482.7 — not the QoS "send-N / amortise"
half. Build only what onion registration requires, in anonymity-safe order
(scaffold → crypto under the §5 + 482.7 §6 gate → integration → e2e):

- **b1 — wire + types (no crypto, no behaviour).** `CircuitId` type;
  `RelayChainMsg` += `CircuitBuild`, `CircuitData`, `CircuitTeardown`; payload
  structs + encode/decode + round-trip tests. Pure additive framing. *(safe to
  land first.)*
- **b2 — circuit build / per-hop key install (482.7 Option B1).** Sender packs
  per-hop `{circuit_id_in, circuit_id_out, circuit_key, next_link}` in onion
  layers; each relay installs `CircuitState` keyed by `(prev_link,
  circuit_id_in)`. Relay install handler. **Gated by §5 + 482.7 §6 threat-model
  review.**
- **b3 — return-path data plane.** A `CircuitData` cell travelling BACK toward
  the originator: each relay re-tags `circuit_id` + adds a layer; the originator
  peels N layers with cached circuit keys. This is the load-bearing new
  direction (482.7 ships send-only). Anti-replay window per circuit.
- **b4 — onion registration at R.** Circuit-backed subscription store
  (cookie-keyed, not session-keyed); `RegisterRendezvous` over a circuit (new
  variant or circuit payload); `RendezvousAd += reg_pk` + registration
  signature (anti-squat, §3.B); `handle_final_introduce` forwards the introduce
  as a return `CircuitData` cell when the sub is circuit-backed.
- **b5 — receiver side.** Build + maintain the R-ward circuit (rebuild on
  teardown/TTL); register over it; receive forwarded introduces over it; opt-in
  config flag (`anonymity.onion_register` or similar).
- **b6 — lifecycle / DoS.** Per-relay circuit caps (≈ rendezvous 10k / 64-peer),
  TTL, teardown-GCs-cookie; rotation policy per 482.7 §4.5.
- **b7 — sim e2e.** Service receives an introduce with R holding NO session/entry
  for the service's transport id; assert R's session table + rendezvous registry
  contain no receiver-identifying entry (the location-anonymity property).

Direct registration stays the default; onion registration is opt-in (§4). b1 is
self-contained and can land independently; b2/b3 are the anonymity-critical core
and must clear the threat-model gate before merge.

## 8. Open questions

1. **One R or Tor-style IP+RP split?** Single-R is simpler and matches today; the
   split buys defence-in-depth (the introduction point never meets the rendezvous
   point) at real complexity. Default: single-R unless a concrete attack motivates
   the split.
2. **reg_pk = sovereign key, or a fresh per-service key?** A fresh per-service
   `reg_pk` (committed in the ad, signed by the sovereign key) avoids exposing the
   sovereign key to R and allows rotation. Leaning fresh-key.
3. **Circuit length for the return path** — same knob as 482.7; 2–3 hops. Trade
   latency vs anonymity; rotate per 482.7 policy.
4. **Descriptor location privacy** — the ad is keyed by sovereign node_id, so
   *enumerating the DHT* reveals "this identity runs a service" (not where).
   Acceptable for an authenticated service; a blinded-descriptor scheme (Tor v3
   style) is a later option if even service *existence* must be unlinkable.
