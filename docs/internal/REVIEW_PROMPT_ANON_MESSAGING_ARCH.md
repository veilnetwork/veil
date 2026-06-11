# Independent design-review prompt — anonymous authenticated messaging architecture

> **Reviewed (2026-06): outcome DESCOPE.** Two independent reviews ran this and
> found a verified-critical error (the "X3DH authenticates the sender" claim is
> false — `x3dh.rs` is a KEM seal, not an AKE) and recommend splitting the epic
> (auth line + transport W1/W2 line, defer stateful circuits + ratchet). The
> corrections are folded into `PLAN_ANON_MESSAGING_ARCHITECTURE.md`. For any
> RE-RUN, apply these prompt fixes first:
> - Reframe "the team chose" → "a proposed, **controversial** direction" (avoid
>   rubber-stamp); add a **Phase 0 — resolve doc conflicts** step before items
>   1–10 (architecture's telescoped build vs 482.7's single-pass; architecture's
>   stateful direction vs the anonymity-preserving plan's "exclude stateful"
>   invariant; rendezvous single-cell vs the assumed circuit data plane;
>   "shipped/wired" vs origination-sim-only).
> - Split the "have vs build" inventory into three statuses: usable as-is /
>   reusable with protocol changes / new-not-reusable.
> - Ask for **top-5 blockers first**, then the full 1–10 matrix.
> - Add questions on public rendezvous metadata (`receiver_node_id` DHT slot,
>   public `auth_cookie`, rendezvous-node correlation, registration TTL) and
>   endpoint abuse (unknown-sender spam, identity-resolution DoS, prekey
>   exhaustion, fallback-prekey reduced FS, prekey-store persistence/data-loss).
> - The "onion-not-prod-wired" reasoning lives in
>   `docs/internal/PLAN_ANON_PRESERVING_IMPL.md` (§ production-wiring) + the
>   project memory note, not a standalone `onion-path-not-prod-wired` file.

Paste the block below to an independent reviewer (a capable model or a human
security/anonymity architect) with read access to the veil repository. It is
self-contained.

---

You are an independent **security & anonymity systems architect** doing an
**adversarial design review** — NOT an implementation. Your job is to find where
the design is wrong, hand-wavy, or anonymity-unsound, and to validate every claim
against the **actual code**, not the prose. Be skeptical; default to "show me in
the code." A polished doc that misstates what the code does is a finding.

## Context

veil is a Rust P2P anonymity network (~57 crates). **Today, production
"anonymous" messaging is meta-E2E** (`veil_e2e::meta_encrypt` — hides the sender
identity inside an ML-KEM-sealed payload on the REGULAR delivery path); the
onion-routing path (`send_anonymous`) is **sim/bench-only, not IPC-wired**
(reasoning in `docs/internal/PLAN_ANON_PRESERVING_IMPL.md` § production-wiring;
verify: `grep -rn '\.send_anonymous(' --include=*.rs .` → only
`veilcore/src/sim/`). NOTE: the relay-directory / publish-loop / reputation
*infrastructure* IS wired and shipped — only message ORIGINATION is sim-only.

A **proposed, controversial** direction (do NOT rubber-stamp it): **"Signal-over-
Tor for veil"** — Tor-style
telescoped bidirectional circuits for network anonymity + an X3DH / Double-Ratchet
E2E session for authentication, confidentiality, forward secrecy, and
post-compromise security. Threat model: relays must not learn the (sender,
recipient) pair or content; the recipient MUST authenticate the sender (know
WHO), but must NOT learn the sender's network location (WHERE); replies and
unsolicited incoming must work.

## Read these (in order)

1. `docs/internal/PLAN_ANON_MESSAGING_ARCHITECTURE.md` — the target architecture
   (the main subject of this review).
2. `docs/internal/PLAN_STATEFUL_CIRCUITS_482_7.md` — the stateful-circuit
   sub-design + its anonymity threat-model checklist (§6).
3. `docs/internal/PLAN_ANON_PRESERVING_CIRCUIT_OPTIMIZATION.md` and
   `PLAN_ANON_PRESERVING_IMPL.md` — the cost decomposition + the
   anonymity-preserving alternatives that were weighed (incl. the W0 measurement:
   selection dominates build 24–98×).
4. `docs/internal/PLAN_AUTHENTICATED_ONION_DELIVERY.md` (SUPERSEDED) — the
   single-cell approach and why it was dropped.
5. `docs/internal/PLAN_RELAY_REPUTATION_A2_MIDSTREAM.md` — the C1 (detection ⇒
   correlation) / C2 (attribution ⇒ path leak) constraints that bound any return
   signal.

## Validate the "have vs build" claims against the code

The architecture leans on existing primitives. Confirm they are what the doc
says (or flag the gap):
- X3DH: `crates/veil-crypto/src/x3dh.rs` — is it a one-shot prekey scheme
  (`generate_prekey`, `PrekeyBundle`, `PrekeySecretStore`, ML-KEM-768, FS by
  consume)? Does it bind LONG-TERM IDENTITY keys (needed for sender auth), or only
  prekeys? Is `PrekeySecretStore` actually wired anywhere, or dead?
- Rendezvous: `crates/veil-anonymity/src/rendezvous.rs` — `RendezvousAd`,
  `IntroducePayload`, the replay cache; `register_with_rendezvous` /
  `send_via_rendezvous` in `crates/veil-node-runtime/src/runtime/mod.rs`. Is it
  single-cell, and can it plausibly carry circuit data + an X3DH first message?
- Onion crypto: `crates/veil-anonymity/src/onion.rs` (post "onion v2" — derived
  nonce). Relay selection + AS-diversity + relay-reputation (shipped Phase A):
  `crates/veil-anonymity/src/{circuit_builder,relay_reputation,directory}.rs`.
- Confirm there is **no** Double Ratchet in the tree
  (`grep -rni 'double.ratchet\|ratchet' crates/`).

## Scrutinise (give a verdict + evidence per item)

1. **Layer separation soundness** — are "Layer A (transport anonymity)" and
   "Layer B (E2E security)" genuinely independent, or do they leak into each
   other (e.g., does the circuit need to see identities; does the ratchet need
   circuit state)? Is "ratchet messages travel as circuit data" actually clean?
2. **Sender authentication via X3DH** — does an X3DH handshake that mixes
   identity keys give the recipient SOUND authentication of the sender
   (unforgeable), and what's the deniability vs non-repudiation property? Is the
   "recipient resolves/knows the sender identity" step (contact cache → DHT
   resolve) sound and non-deanonymising?
3. **Relay anonymity of telescoped circuits** — does "no single hop knows both
   ends" actually hold for the proposed CREATE/EXTEND build + bidirectional data?
   Where can it break (first-hop knowledge, exit knowledge, CircuitId as a join
   tag across colluding hops)?
4. **Intra-circuit linkability vs the threat model** — the design accepts that a
   hop links the N cells of a circuit. Is that truly compatible with §0, and is
   the rotation policy (K/T) a real mitigation or hand-waving? What K/T would you
   require, and on what basis?
5. **Forward secrecy / PCS claims** — does per-hop ephemeral DH (transport FS) +
   Double Ratchet (endpoint FS+PCS) compose to the claimed guarantees? Any gap
   (e.g., the X3DH first message, the prekey-reuse window, ratchet state
   compromise)?
6. **Incoming / rendezvous** — does rendezvous + circuit actually deliver
   "unsolicited anonymous incoming" without deanonymising the receiver or the
   sender? Reuse the existing replay/PoW gating?
7. **State & DoS** — per-relay circuit state is a new attack surface. Are the
   proposed caps / build-rate limits / teardown sufficient? What's the
   memory/CPU amplification a malicious builder can force?
8. **Correlation** — long-lived circuits are timing-correlation targets. Is the
   design honest about what it does NOT defend (global passive adversary), and
   are the mitigations (rotation, padding) credible?
9. **Scope realism** — this is "Tor circuits + Signal ratchet." Is the phased
   plan (§9) buildable and correctly ordered? What is underestimated? Should any
   phase be cut or resequenced?
10. **Priority** — given prod anonymity is currently meta-E2E and the onion path
    is unwired, is this epic worth its cost, or is there a smaller design that
    meets §0's threat model? Give a clear recommendation.

## Deliverable

- Per-item (1–10) verdict: **sound / unsound / hand-wavy**, with code/file:line
  evidence or a concrete counter-scenario.
- A list of **anonymity properties that DON'T hold as claimed** (if any), each
  with an attack sketch.
- **Missed risks** not in the docs' threat-model gates.
- Whether the **"have vs build" inventory** is accurate (which primitives are
  really reusable vs need rework).
- A **go / no-go / descope** recommendation with the single biggest risk and the
  single highest-leverage simplification.
- Be concrete; refuse to rubber-stamp. If something can't be assessed without
  running code, say so and say what you'd run.
