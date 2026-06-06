# Bandwidth-profile mimicry — opt-in design

> **Status (2026-06):** design landing-pad — the output-gating mimicry is **NOT
> implemented**. The config knobs exist only as a fail-closed gate
> (`[transport] bandwidth_mimicry_enabled` + `experimental_allow_noop_mimicry`;
> without both, the daemon refuses to start — see
> `crates/veil-cfg/src/transport_glue.rs`). What *is* shipped is the **byte
> n-gram** model plus pcap ingest in `crates/veil-fingerprint` (used for
> regression validation). That is **not** the timing-shape analyzer
> (`TimingProfile` / `shape_to_profile`) this plan needs. The timing analyzer,
> the reference-profile library, and the output-gating layer are all still future
> work. Until they land, use operator-side tc/qdisc.

Anti-censorship strategy P2 #7. This closes the throughput-shaping vector (#29-31: rating groups, quotas, DSCP) at the **wire level**. It complements the operator-side tc/qdisc option in [`DEPLOYMENT_HARDENING.md`](DEPLOYMENT_HARDENING.md).

## Why opt-in, not default

Bandwidth-profile mimicry shapes veil's outbound traffic to match a reference flow pattern — for example, "looks like a YouTube or Netflix CDN download," which is bursts of data followed by idle gaps. (DPI here means deep packet inspection: a censor's box that watches the shape of your traffic, not just its destination.) The trade-offs:

* **Latency degradation.** Mimicry forces output gating, which adds roughly 50-200 ms of user-facing message latency per flow. That hurts interactive chat the most.
* **Throughput cap.** Matching a "typical browsing" profile caps veil's top throughput at about 5-20 Mbps, no matter how much bandwidth is actually available.
* **Profile-specificity.** Each reference profile fits exactly one DPI threat model. A "Netflix" profile passes Netflix-class classifiers, but it might **fail** a classifier that expects "WhatsApp"-like patterns. Pick the wrong profile and you can make the signal worse, not better.

**Conclusion:** this is an opt-in feature, default OFF. Operators turn it on only after they see production throughput-shaping blocks — that is, DPI tagging veil traffic as "VPN-shaped" and then slowing or dropping it.

## Activation prerequisites

When/if bandwidth mimicry activation is triggered:

### 1. Empirical reference profiles

Build a small library of "what does Chrome look like over time?" reference distributions:

* **Inter-packet interval histogram** — how long between outbound packets during a typical browsing session?
* **Burst-size distribution** — when bytes flow, how big is each individual burst?
* **Idle-gap distribution** — how long are the idle periods between bursts?

Capture the traffic with tcpdump on a baseline machine, then extract it through `veil-fingerprint`'s pcap-ingest path. That path already ships — see [`FINGERPRINT_REGRESSION.md`](FINGERPRINT_REGRESSION.md). The catch: the analyzer currently computes only byte n-grams, so it needs extending to compute **timing distributions** too. Estimated ~300 LoC plus capture infra.

Recommended starting profiles:
* `chrome-browsing` — modeled on ordinary Chrome HTTPS sessions (highest acceptance rate)
* `cdn-download` — Netflix/YouTube-class flow (tolerates high throughput)
* `interactive-chat` — WhatsApp/Telegram-class (low-latency, interactive)

### 2. Timing-shape analyzer (companion to the n-gram analyzer)

A `veil-fingerprint::timing` module — the same API surface as `NGramModel`, but keyed on inter-packet intervals:

```rust
pub struct TimingProfile {
    inter_packet_micros: HashMap<u64, u64>, // bucket → count
    burst_size_bytes: HashMap<u64, u64>,
    idle_gap_millis: HashMap<u64, u64>,
}

impl TimingProfile {
    pub fn observe(&mut self, packet_sizes: &[(usize, std::time::Instant)]);
    pub fn distance_to(&self, reference: &TimingProfile) -> f64; // chi² over the three histograms
}
```

Estimated ~400 LoC plus tests, plus CLI gating through `fp-compare` (extend the existing CLI to accept a `--timing` flag).

### 3. Output gating layer in the session writer

A `veil-transport::session_writer::shape_to_profile()` function. It wraps the writer's `poll_write` to insert delays and coalesce packets so they match the target profile's burst-size distribution. It runs as a per-flow state machine. About 500 LoC.

This hooks into the existing `SessionRunner` outbound paths with no wire-format change — it is purely a timing-layer modification.

### 4. Per-flow vs per-node policy choice

There are two activation models:

* **Per-node global** — shape all outbound traffic to the same profile. Simpler, but every flow pays the latency cost.
* **Per-flow opt-in** — annotate from the application side (`app.send(... shape: Some(Profile::CdnDownload))`). More granular, but it needs API/IPC surface changes.

Recommendation: ship **per-node** first, since it is simpler, and move to per-flow only if operators report they need it.

### 5. Operator config schema

```toml
[transport]
# Default false — feature opt-in.  When true, requires
# `bandwidth_mimicry_profile` to be set.
bandwidth_mimicry_enabled = false

# Profile name from the built-in library (see PLAN_BANDWIDTH_MIMICRY.md).
# Common values: "chrome-browsing", "cdn-download", "interactive-chat".
bandwidth_mimicry_profile = "chrome-browsing"

# Optional: per-flow latency tolerance (ms) above which mimicry is
# temporarily suspended to avoid catastrophic latency degradation.
# Default 500 ms — restore mimicry once flow latency returns below.
bandwidth_mimicry_latency_ceiling_ms = 500
```

When `bandwidth_mimicry_enabled = true` but `bandwidth_mimicry_profile` is unset, the daemon fails fast at startup with a clear error.

### 6. Runtime warning

When bandwidth mimicry is enabled, log a WARN-level message at startup:

```
bandwidth_mimicry.enabled  profile=chrome-browsing
  warning="Output gating active — выходящий traffic latency increased by ~50-200 ms.
  Match the profile к your target jurisdiction's DPI classifier: wrong
  profile choice may degrade censorship resistance.  See PLAN_BANDWIDTH_MIMICRY.md"
```

## Activation triggers

Open the bandwidth-mimicry epic and start the prerequisite analyzer and profile-capture work when ANY of these holds:

1. **Production observation.** Live testnet metrics show a statistically significant dip in connection-success rate tied to specific ISPs or countries, AND the dip pattern matches a "throughput-shaping classifier" — that is, a slow-after-burst pattern rather than an outright block. See the Anomaly Watch section of [`OPERATIONS.md`](../en/OPERATIONS.md) for the baseline signals.
2. **Specific deployment request.** A high-sensitivity threat model (an RU citizen app, an IR dissident network) with DPI shaping rules already known from the operator's security review.
3. **Reference-profile maturity.** An independent project — Tor's Pluggable Transports working group, or an IETF QUIC-bias study — publishes a validated "Chrome bandwidth profile" reference distribution we can adopt without doing the capture work ourselves.

Until one of these fires, the preferred mitigation is the **operator-side tc/qdisc throttle** ([`DEPLOYMENT_HARDENING.md` Option B](DEPLOYMENT_HARDENING.md#29-31---throughput-shaping--rating-group-classifiers)). It needs no code changes and closes the same threat surface for most practical scenarios.

## Estimated scope (when activation triggered)

| Slice | LoC | Sessions |
|---|---|---|
| Timing-shape analyzer module (`veil-fingerprint::timing`) | ~400 LoC | 1 |
| Reference profile capture + serialisation | ~300 LoC + capture infra | 1 |
| Output gating layer (`veil-transport::session_writer`) | ~500 LoC | 1.5 |
| Per-flow IPC API surface (if per-flow path chosen) | ~200 LoC | 0.5 |
| Cross-host integration tests | ~250 LoC | 1 |
| **Total** | **~1450-1650 LoC** | **5 sessions** |

The largest cost is profile capture: operator-side, across multiple hosts under realistic load. A published reference distribution, if one becomes available, would cut that cost.

## How this composes with current anti-censorship layers

| Closes | Layer | Status |
|---|---|---|
| #29-31 (wire-level, opt-in) | Bandwidth mimicry | 🧊 design landing-pad (this doc) |
| #29-31 (operator-side, default) | tc/qdisc per-flow cap | ✅ documented ([`DEPLOYMENT_HARDENING.md`](DEPLOYMENT_HARDENING.md)) |
| Validation infrastructure | `veil-fingerprint` n-gram engine + pcap ingest + fp-compare CLI | ✅ shipped (P2 #5) |

See [`docs/internal/ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md) for the full DPI threat model and roadmap.
