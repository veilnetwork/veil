# Bandwidth-profile mimicry — opt-in design

> **Status (2026-06):** design landing-pad — the output-gating mimicry is **NOT
> implemented**. The config knobs exist only as a fail-closed gate
> (`[transport] bandwidth_mimicry_enabled` + `experimental_allow_noop_mimicry`;
> without both, the daemon refuses to start — see
> `crates/veil-cfg/src/transport_glue.rs`). What *is* shipped is the **byte
> n-gram** model + pcap ingest in `crates/veil-fingerprint` (used for
> regression validation) — this is **not** the timing-shape analyzer
> (`TimingProfile` / `shape_to_profile`) this plan needs. The timing analyzer,
> the reference-profile library, and the output-gating layer are all still future
> work; until then, use operator-side tc/qdisc.

Anti-censorship strategy P2 #7 — closes the throughput-shaping vector (#29-31: rating groups / quotas / DSCP) at the **wire level**, complementing the operator-side tc/qdisc option в [`DEPLOYMENT_HARDENING.md`](DEPLOYMENT_HARDENING.md).

## Why opt-in, not default

Bandwidth-profile mimicry shapes veil's outbound traffic к match а reference flow pattern (e.g., "looks like а YouTube/Netflix CDN download" — bursts followed by idle gaps).  Trade-offs:

* **Latency degradation**: mimicry forces output gating, increasing user-facing message latency by ~50-200 ms per flow (worse for interactive chat).
* **Throughput cap**: matching а "typical browsing" profile caps veil's max throughput к ~5-20 Mbps regardless of available bandwidth.
* **Profile-specificity**: each reference profile fits one DPI threat model — а "Netflix" profile passes Netflix-class classifiers but might **fail** classifiers expecting "WhatsApp"-like patterns.  Wrong profile choice could worsen the signal.

**Conclusion**: opt-in feature, default OFF.  Operators enable only when they observe production throughput-shaping blocks (DPI tagging veil traffic as "VPN-shaped" и slowing/dropping it).

## Activation prerequisites

When/if bandwidth mimicry activation is triggered:

### 1. Empirical reference profiles

Build а small library of "what does Chrome look like over time?" reference distributions:

* **Inter-packet interval histogram** — how long между outbound packets во время а typical browsing session?
* **Burst-size distribution** — when bytes flow, how big are individual bursts?
* **Idle-gap distribution** — how long are the idle periods между bursts?

Capture via tcpdump on а baseline machine, extract через `veil-fingerprint`'s pcap-ingest path (already shipped — see [`FINGERPRINT_REGRESSION.md`](FINGERPRINT_REGRESSION.md)), но extend the analyzer to compute **timing distributions** (currently only byte n-grams).  Estimated ~300 LoC + capture infra.

Recommended initial profiles:
* `chrome-browsing` — modeled от ordinary Chrome HTTPS sessions (highest acceptance rate)
* `cdn-download` — Netflix/YouTube-class flow (high-throughput tolerance)
* `interactive-chat` — WhatsApp/Telegram-class (low-latency interactive)

### 2. Timing-shape analyzer (companion к n-gram analyzer)

`veil-fingerprint::timing` module — same API surface as `NGramModel` но keyed on inter-packet intervals:

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

Estimated ~400 LoC + tests + CLI gating через `fp-compare` (extend the existing CLI к accept а `--timing` flag).

### 3. Output gating layer в session writer

`veil-transport::session_writer::shape_to_profile()` — wraps the writer's `poll_write` к insert delays / coalesce packets matching the target profile's burst-size distribution.  Per-flow state machine.  ~500 LoC.

Hooks into existing `SessionRunner` outbound paths без а wire-format change — purely timing-layer modification.

### 4. Per-flow vs per-node policy choice

Two activation models:

* **Per-node global** — all outbound traffic shaped к the same profile.  Simpler, но every flow inherits the latency cost.
* **Per-flow opt-in** — application-side annotation (`app.send(... shape: Some(Profile::CdnDownload))`).  Granular но requires API/IPC surface changes.

Recommendation: ship **per-node** first (simpler), evolve к per-flow if operators report needing it.

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

When `bandwidth_mimicry_enabled = true` but `bandwidth_mimicry_profile` is unset, the daemon fails-fast at startup с а clear error.

### 6. Runtime warning

When bandwidth mimicry is enabled, log а WARN-level message at startup:

```
bandwidth_mimicry.enabled  profile=chrome-browsing
  warning="Output gating active — выходящий traffic latency increased by ~50-200 ms.
  Match the profile к your target jurisdiction's DPI classifier: wrong
  profile choice may degrade censorship resistance.  See PLAN_BANDWIDTH_MIMICRY.md"
```

## Activation triggers

Open the bandwidth-mimicry epic и start the prerequisite analyzer + profile-capture work when ANY of:

1. **Production observation**: live testnet metrics show а statistically significant connection-success-rate dip correlated с specific ISPs / countries, AND the dip pattern matches "throughput-shaping classifier" (slow-after-burst pattern rather than direct block).  See [`OPERATIONS.md`](../en/OPERATIONS.md) Anomaly Watch section для baseline signals.
2. **Specific deployment request**: high-sensitivity threat model (RU citizen-app, IR dissident network) с known DPI shaping rules per the operator's security review.
3. **Reference-profile maturity**: independent project (Tor's Pluggable Transports working group, IETF QUIC-bias study) publishes а validated "Chrome bandwidth profile" reference distribution что can be adopted without empirical capture work.

Until one of these fires, **operator-side tc/qdisc throttle** ([`DEPLOYMENT_HARDENING.md` Option B](DEPLOYMENT_HARDENING.md#29-31---throughput-shaping--rating-group-classifiers)) is the preferred mitigation — it doesn't require code changes и closes the same threat surface для most practical scenarios.

## Estimated scope (when activation triggered)

| Slice | LoC | Sessions |
|---|---|---|
| Timing-shape analyzer module (`veil-fingerprint::timing`) | ~400 LoC | 1 |
| Reference profile capture + serialisation | ~300 LoC + capture infra | 1 |
| Output gating layer (`veil-transport::session_writer`) | ~500 LoC | 1.5 |
| Per-flow IPC API surface (if per-flow path chosen) | ~200 LoC | 0.5 |
| Cross-host integration tests | ~250 LoC | 1 |
| **Total** | **~1450-1650 LoC** | **5 sessions** |

Largest cost: profile capture (operator-side, multiple hosts under realistic load).  Mitigated если а published reference distribution becomes available.

## Composition с current anti-censorship layers

| Closes | Layer | Status |
|---|---|---|
| #29-31 (wire-level, opt-in) | Bandwidth mimicry | 🧊 design landing-pad (this doc) |
| #29-31 (operator-side, default) | tc/qdisc per-flow cap | ✅ documented ([`DEPLOYMENT_HARDENING.md`](DEPLOYMENT_HARDENING.md)) |
| Validation infrastructure | `veil-fingerprint` n-gram engine + pcap ingest + fp-compare CLI | ✅ shipped (P2 #5) |

See [`docs/internal/ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md) для the full DPI threat-model + roadmap.
