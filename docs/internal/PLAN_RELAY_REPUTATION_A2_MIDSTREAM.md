# Phase A.2 — mid-stream drop detection for anonymity relays (design sketch)

> **Status (2026-06):** DESIGN DRAFT, no code. Phase A (the ledger + selection
> wiring + two leak-free failure signals + time-decay) shipped — see
> `crates/veil-anonymity/src/relay_reputation.rs`. This document scopes the
> *remaining* threat: a relay that ACCEPTS an onion cell then silently fails to
> forward it mid-circuit. It is NOT ready to implement. **Read §0 first** — A.2 is
> an availability/QoS optimisation, not an anonymity fix, and even the
> "just measure it" step is not free (it shares the same C1 limit, §2).
>
> Incorporates an independent design review (2026-06): the two biggest
> corrections were (a) retry does NOT auto-route around a dropping relay because
> the production picker is latency-first *deterministic*, and (b) anonymous-send
> success rate is not locally observable for fire-and-forget sends (C1), so the
> "measurement slice" is itself a small A.2-lite step, not a zero-cost metric.

Epic: 482.3 / 482.4, Phase A.2.

---

## 0. Is this worth doing? (value & priority — read first)

A mid-stream-dropping relay does **not** break anonymity or confidentiality. The
onion stays sealed; a middle hop never sees sender or target. The only
consequence is **the message doesn't arrive** — a QoS/availability problem, not a
security boundary.

But the cheapest mitigation is weaker than the earlier draft claimed. The
production picker
(`circuit_builder::pick_circuit_hops_latency_aware_with_diversity_and_reputation`)
is **latency-first deterministic**: it scores candidates `rtt + reputation
penalty`, sorts ascending, and takes the top distinct-AS picks. So a retry that
rebuilds a circuit from the **same** candidate pool can deterministically
re-select the **same** mid-stream-dropping relay (until its reputation penalty
accrues — which is exactly what A.2 is trying to bootstrap, a chicken-and-egg).

→ The genuinely cheap pre-A.2 mitigation is therefore **retry diversification**,
not "rotation handles it":

- **A.2-pre (cheap, no new signal):** on a retry of a failed anonymous send,
  *diversify the path* — e.g. randomise among the top-k by score (weighted
  sampling), and/or keep a short-lived **retry-exclusion cache** of the previous
  failed path so the rebuild avoids it for a few seconds. This breaks the
  deterministic re-selection without any detection machinery or anonymity cost,
  and is worth doing **before** A.2 regardless.

A.2's added value over A.2-pre is only: *persistently* down-weight relays that
drop at a meaningful rate, so the network as a whole spends fewer retries. That
is a real but bounded win.

**Priority questions a maintainer must answer before funding A.2:**
1. Is the live mid-stream drop rate high enough that A.2-pre (retry
   diversification) is insufficient? (Needs data — see §7 measurement slice, and
   note that measuring it is itself non-trivial, §2/§7.)
2. Is the expected latency win larger than A.2's anonymity cost (§2/§6) and
   engineering cost (§4–§9)?

If unknown, the first work is **A.2-pre + measurement**, not A.2.

---

## 1. The gap

veil's anonymity send is a **stateless, single-cell, source-routed onion**
(`sender::build_outbound_anonymous_cell_*` → fixed `CELL_SIZE` cell → sent to the
first hop over an existing OVL1 session; each hop peels one layer in
`onion::unwrap_at_hop` and forwards over *its* session). No circuit build phase,
no per-circuit state.

**Mid-stream admit-then-drop:** hop 2 of 3 accepts the cell from hop 1 then does
not forward. The sender sent fire-and-forget to hop 1 and waits for nothing, so
it is blind.

Phase A records two leak-free failure signals (first-hop `send_to == false`;
relayed non-anonymous delivery timeout, guarded `next_hop != dst`). Neither sees
the anonymity mid-stream drop. There is **no leak-free inline signal** for it —
that is the whole problem.

---

## 2. Two fundamental constraints

### C1 — Detection needs a return signal, and a return signal enables correlation
The target does not know the sender, so any acknowledgement traverses a return
path → a **confirmable round-trip** a global passive adversary uses for
end-to-end timing correlation, and a timing edge for the last relay.
Fire-and-forget weakens this; any ack restores it. **This also means "just
measure success rate" is not free** — sender-observable success *is* a return
signal.

### C2 — Attribution needs per-hop confirmation, and that leaks the path
A missing ack says "failed somewhere", not which relay. Deterministic
per-relay blame requires per-hop confirmations → path-structure + timing leak,
forgeable by a malicious hop (§6.3). **Best achievable is statistical, never
"this relay dropped it."**

---

## 3. Dependency split: what needs Epic 482.7, what doesn't

- **Statistical / local attribution (§4.1, §4.2):** needs only a **sender-local**
  `local_circuit_id → {relays, deadline}` map (the sender already knows each
  circuit's relay set). No wire CircuitId → **no 482.7 dependency.**
- **Per-hop deterministic attribution (§4.3):** needs a stateful on-the-wire
  circuit (build handshake + per-hop acks) → **that is Epic 482.7.**

---

## 4. Design options

### 4.1 Probabilistic circuit probing (canary) — landable without 482.7, coarse
The sender routes a canary through a fresh circuit and checks a deadline;
outcomes feed §5. Tests the **circuit**, not a relay.

- A canary must return to an anonymous sender → it needs a **return path**, so it
  exercises **forward + return relays** (~6, not 3); a failure implicates the
  larger set, muddying §5. Mitigate by confirming the return path live
  independently, then attributing only to the forward set.
- **Anti-gaming invariant (hard requirement):** the canary MUST be
  indistinguishable from a real send so a relay can't pass canaries and drop real
  traffic. "Indistinguishable" is broader than the earlier draft — it covers
  **all** of: cell size (already fixed `CELL_SIZE`), post-peel family/opcode,
  **next-hop distribution**, **final-hop endpoint** (a canary to a known echo
  node is a fingerprint), inter-send **timing**, **retry behaviour**, and
  **reply latency**. Any of these leaking the canary makes A.2 worse than useless
  (it manufactures false confidence). The echo/return endpoint must not be a
  distinguishable, well-known node.
- This re-opens C1 for probe traffic; cadence must be randomised + cover-shaped.

### 4.2 Piggyback on a delivery ACK — preferred where one exists, but one must be DEFINED
**Correction from review:** there is currently **no** local delivery-ack for the
anonymous/rendezvous path — `send_via_rendezvous` sends the onion cell and
returns `Ok(())` with no pending-ack entry (unlike the non-anonymous delivery
plane, which has content_id + MAC acks in `veil-dispatcher::delivery`). So
"piggyback on real acks" is not free reuse; A.2 must **define an ACK contract**
for anonymous delivery:

- **payload id**: a per-message random token the sender remembers in its local
  circuit tracker (never the content_id, to avoid cross-plane linkage).
- **auth**: receiver MACs the token with a key the sender shares out-of-band /
  via the rendezvous handshake, so a relay can't forge an ack.
- **path**: the ack returns over the receiver's rendezvous (the receiver already
  has that channel), NOT over a per-hop reverse path.
- **timeout**: bounded; absence → a (statistical, set-wide) failure, never a
  hard per-relay blame.
- **privacy note**: the ack is a round-trip (C1) — but for rendezvous flows the
  receiver already replies, so A.2 piggybacking adds little *new* correlation
  surface there. It MUST NOT be added to flows that are currently one-way.

Best as a **success/credit** signal feeding §5, combined with §4.1 for unacked
sends.

### 4.3 Per-hop SENDME-style flow control — needs 482.7, strongest + leakiest
Stateful circuit + per-hop authenticated acks → near-deterministic attribution.
Largest lift + largest anonymity risk; payoff only QoS (§0); gate behind full §6
review **and** 482.7. Likely not worth it.

---

## 5. Attribution math — minimal spec (not just concepts)

Per the review, a concrete default rather than hand-waving. Pick ONE:

**Option S1 — Beta-binomial with a credible lower bound (principled).**
For each relay `r`, maintain decayed counts over circuits it appeared in:
`fail[r]`, `total[r]` (exponentially decayed using the Phase A
`FAILURE_DECAY_INTERVAL` as the time constant; counts are fractional — see ledger
note). Maintain a global baseline success rate `p_base` the same way over all
circuits.
- Posterior failure rate `f[r] ~ Beta(α0 + fail[r], β0 + (total[r]-fail[r]))`,
  prior `α0 = β0 = 1` (Laplace).
- Suspicion fires only when the **lower bound** of `f[r]`'s credible interval
  (Wilson / Beta-quantile, e.g. 90%) exceeds `p_fail_base + δ`, where
  `p_fail_base = 1 - p_base`.
- Defaults: `δ = 0.10`, `MIN_SAMPLES total[r] ≥ 20`, credible level 90%.
- Penalty fed to the ledger ∝ `(LB(f[r]) - (p_fail_base + δ))`, capped (§6.6).

**Option S2 — fixed-point fallback (simple).**
On a failed circuit, `suspicion[r] += weight` with `weight = 1/hop_count` (spread
blame across the path); on a succeeding circuit `suspicion[r] *=` a decay factor.
Penalty applies only when `total[r] ≥ MIN_SAMPLES` AND
`suspicion[r]/total[r] > p_fail_base + δ`. Same defaults.

**Ledger change required (both):** the shipped `RelayReputation` stores
**integer** `u32` failures. Statistical suspicion is **fractional**, so A.2 needs
a fixed-point or `f32` accumulator (and fractional decay), plus the `total[r]`
denominator and `p_base`. `record_failure` cannot be reused verbatim.

Document loudly: convergence needs O(tens) of circuits/relay → **slow,
statistical, not per-event.**

---

## 6. Threat-model checklist (gate before any wire change)

1. **Global passive timing correlation** (C1) — §4.2 adds none beyond an ack the
   flow already has; §4.1 adds probe round-trips; §4.3 the most.
2. **Path-structure disclosure** (C2) — only §4.3.
3. **Malicious-hop lying** — forge "downstream acked/failed". §4.2 authenticates
   the ack end-to-end (MAC), so a relay can't forge the verdict, only influence
   its own appearance stats; §4.3 must authenticate per-hop acks.
4. **Probe / canary fingerprinting** — the §4.1 indistinguishability set (cell
   size, opcode, next-hop dist, final-hop endpoint, timing, retry, reply
   latency, echo-node fingerprint). Double-duty with anti-gaming.
5. **Reputation poisoning** — can one adversarial relay steer the *local* stats
   (no cross-sender sharing — that's Phase B) to bury honest or whitewash bad?
   Baseline-calibration (§5) + decay + `MIN_SAMPLES` bound it.
6. **Active route-steering / selection collapse (load-bearing).** Two linked
   risks:
   - *Selective DoS:* an adversary that drops cells forces the client to retry,
     and if retries shift selection toward a controlled subset, the adversary
     *gains* path probability — a net anonymity LOSS driven by A.2's own
     reactions. (This is also why A.2-pre retry-diversification, §0, must
     randomise rather than deterministically fall to "next best".)
   - *Selection collapse:* "reorder, never exclude" is violated in practice if
     the picker takes a deterministic top-N after sorting — a large penalty
     effectively excludes a relay, shrinking the diverse pool toward whatever the
     adversary hasn't framed.
   **Requirements:** (a) **probabilistic floor** — replace deterministic top-N
   with weighted sampling among the top-k by score so every diverse candidate
   keeps non-zero probability; (b) **cap max penalty** so reputation tilts but
   never dominates RTT+diversity; (c) decide whether the **degraded
   latency-only fallback** in `sender.rs` (currently reputation-unaware) should
   consult reputation — and keep it floor-sampled too; (d) **test**: a penalised
   relay still has non-zero selection probability.

A.2 ships only if every item has a bounded, tested answer.

---

## 7. Slice A.2-0 — measurement (do this first; honestly NOT zero-cost)

The review is right that "measure anonymous-send success rate" was undefined and,
for fire-and-forget `send_anonymous`, **not locally observable without a return
signal (C1)**. Honest options, cheapest first:

- **(a) Acked/rendezvous flows only** — once the §4.2 ack contract exists, count
  success/timeout per circuit for *those* flows. Excludes one-way sends; carries
  the §4.2 (already-existing-ack) privacy note.
- **(b) Recipient-side aggregate** — receivers count anonymous messages received
  per unit time and operators aggregate. Privacy-neutral (no sender correlation)
  but yields a *count*, **not a success rate** (no denominator), so it detects
  gross outages, not per-circuit loss.
- **(c) Synthetic probes** — honestly labelled **A.2-lite**, NOT a zero-cost
  metric: it is §4.1 minus attribution, with the same C1 probe-correlation and
  the same indistinguishability requirement.

**Deliverable spec for (a)/(c):** counter names (`anon_send_total`,
`anon_send_acked`, `anon_send_timeout` by `hop_count`), who writes them
(sender-local on ack/timeout), which flows are excluded (one-way `send_anonymous`
under (a)), the privacy property of each, and a feature flag (§9). No per-relay
attribution at this slice → no §6 surface beyond the chosen ack/probe.

---

## 8. Simulation / adversarial harness (required before trusting §5)

Statistical attribution must be validated in sim before production. Minimum
scenarios (extend the existing `veilcore::sim` harness):

- honest network, ambient random loss only → suspicion stays ≈ 0 (no false
  positives against `p_base`).
- one persistent mid-stream-dropping relay → it accrues penalty and its
  selection probability drops, **without** burying its honest path-mates.
- colluding droppers (2–3 in different ASes) → attribution still concentrates,
  doesn't smear across the pool.
- return-path loss (for §4.1) → does NOT mis-attribute to forward relays.
- Sybil low-latency relays that drop → low RTT must not let them out-run the
  penalty (verifies penalty cap/scale vs RTT).
- selective-DoS route-steering (§6.6) → confirm the probabilistic floor prevents
  the adversary from collapsing selection onto its subset.

Report: convergence time (circuits to flag), false-positive rate vs `p_base`,
and selection-probability of a framed-honest relay (must stay > floor).

---

## 9. Operational gates (ship-readiness)

- **Feature flag** (default off) for the whole A.2 path and separately for the
  measurement slice.
- **Sample rate** for canaries; **max in-flight probes** cap.
- **Kill switch** that reverts to the Phase-A picker (penalty closure → 0) without
  redeploy.
- **Dashboards/alerts:** anon-send success by hop_count, per-relay penalty
  distribution, probe volume, framed-honest selection floor.
- **Rollback criteria:** if framed-honest selection probability dips below floor,
  or false-positive rate exceeds a bound, auto-disable.

---

## 10. Recommendation (maintainer decision required)

1. **A.2-pre first (cheapest, no detection, no anonymity cost):** retry
   diversification — randomise among top-k / short-lived retry-exclusion cache so
   a retry stops deterministically re-selecting a dropping relay. Worth doing
   regardless of A.2.
2. **Then measurement (Slice A.2-0):** honestly scoped per §7 — it is small
   A.2-lite work, not a free metric. Decide from data whether A.2 proper is
   warranted.
3. **Do not** start with §4.3 (per-hop) — largest lift + anonymity risk, QoS-only
   payoff; gate behind §6 *and* 482.7.
4. If data justifies A.2 before 482.7: **§4.2 (with a defined, MAC'd ack
   contract) for ack'd flows + §4.1 for unacked**, with the §4.1
   indistinguishability set as a hard gate, the §5 fractional/baseline ledger, the
   §6.6 probabilistic-floor picker, the §8 sim harness, and the §9 operational
   gates.
5. Otherwise **sequence Epic 482.7 first** (independently useful: build-once→
   send-N), then revisit §4.3-grade attribution.

**Net:** Phase A already extracted the leak-free value. A.2 buys *availability
under adversarial relays, not anonymity*; its cheap alternative (retry
diversification) was undersold in the first draft; its measurement step is not
free; and its detection machinery adds a correlation surface and a route-steering
risk that must be gated and sim-validated. Treat as a data-driven, deliberately
scheduled epic — **likely lower priority than A.2-pre, measurement, and possibly
482.6/482.7.**
