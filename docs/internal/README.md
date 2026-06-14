# Internal — Censorship-Resistance Architecture

> **Scope:** documentation that reveals the project's anti-censorship
> posture. Its contents must NOT be linked from public indexes
> and must NOT be mentioned in outward-facing documents.
>
> **Audience:** core maintainers, operators of bridges/gateways, and
> security researchers with an explicit access agreement.

---

## 0. Threat model in one paragraph

The adversary is well-resourced (state-level or equivalent): they own the
local access network and can run active probing, fingerprint-level DPI
(JA3/JA4/TLS-record-pattern/n-gram analysis), IP-blacklisting,
port-scanning of known veil endpoints, and traffic-correlation analysis.
The goal is to guarantee delivery even when the adversary blocks every
known protocol fingerprint. The goal is NOT anonymity from a
self-hostile network operator — that is a separate threat model in the
anonymity stack, not here.

---

## 1. Multi-layer defense

```
┌─────────────────────────────────────────────────────────┐
│           ADVERSARY: DPI / Active Probe / Block         │
└────────────┬────────────────────────────────────────────┘
             │
   ┌─────────▼──────────────────────────────────────────┐
   │ L7  Transport obfuscation                          │
   │     • obfs4 framing (ScrambleSuit successor)       │
   │     • webtunnel (HTTPS-mimic with reverse proxy)   │
   │     • FakeTLS (per-listener TLS-fingerprint clone) │
   │     • ECH opt-in (encrypted SNI)                   │
   ├────────────────────────────────────────────────────┤
   │ L6  Wire-format kill-switch                        │
   │     • Magic rotation when variant published        │
   │     • Capability negotiation forward-compat        │
   ├────────────────────────────────────────────────────┤
   │ L5  Traffic mimicry                                │
   │     • Bandwidth-shaping profiles (HTTPS-burst, ... │
   │     • Padding frames to MTU                        │
   ├────────────────────────────────────────────────────┤
   │ L4  Listener stealth                               │
   │     • PoW-gated rendezvous (port closed by default)│
   │     • On-demand bind after verified handshake      │
   │     • Stealth visibility (DHT-suppressed)          │
   ├────────────────────────────────────────────────────┤
   │ L3  Bridge / gateway transit                       │
   │     • ogate TUN-bridge for app-agnostic transit    │
   │     • Domain-fronted CDN entry-points              │
   ├────────────────────────────────────────────────────┤
   │ L2  Discovery resistance                           │
   │     • Half-cap DHT FIND_NODE response              │
   │     • Public-only transport disclosure             │
   │     • Out-of-band invite bundles (no DHT presence) │
   ├────────────────────────────────────────────────────┤
   │ L1  Continuous validation                          │
   │     • Fingerprint regression suite (FINGERPRINT_*) │
   │     • n-gram analysis on outgoing wire traces      │
   │     • CI-gated against JA3/JA4 drift               │
   └────────────────────────────────────────────────────┘
```

Each layer is documented separately — see the §3 catalog.

---

## 2. Activation philosophy

**Not everything is enabled at once.** The default config — open, neutral,
TCP-only — delivers baseline functionality. Each feature in L4-L7 is
opt-in through the config:

```toml
[transport.obfs4]      # opt-in
enabled = true
psk = "..."

[transport.webtunnel]  # opt-in
enabled = true
upstream = "https://example.com"

[listen.on_demand]     # opt-in (was: PoW-gated rendezvous)
enabled = true
visibility = "stealth"

[bandwidth_mimicry]    # opt-in
profile = "https-burst"

[fingerprint.regression] # CI-gate only
enabled = true
```

Reason: some layers (e.g. ECH) can actively expose a node in
jurisdictions where their use is tracked. The operator — not the code —
chooses the posture based on the target jurisdiction and risk tolerance.

---

## 3. Document catalog

### Strategy + threat models

| File | Topic |
|------|-------|
| [`ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md) | Full threat model, DPI vendor analysis (VAS Experts SKAT etc), 35 evasion methods, roadmap |
| [`censorship-target.md`](censorship-target.md) | Per-jurisdiction deployment guidance (operator-side) |
| [`dpi-evasion.md`](dpi-evasion.md) | Architecture summary of what's built vs. planned |
| [`DEPLOYMENT_HARDENING.md`](DEPLOYMENT_HARDENING.md) | Operator-side gap closure: CDN, AS-level, hosting choices |

### Transport obfuscation

| File | Topic |
|------|-------|
| [`PLAN_TRANSPORT_OBFUSCATION.md`](PLAN_TRANSPORT_OBFUSCATION.md) | obfs4 + FakeTLS implementation plan |
| [`PLAN_ECH_OPT_IN.md`](PLAN_ECH_OPT_IN.md) | Encrypted Client Hello opt-in |
| [`webtunnel-letsencrypt.md`](webtunnel-letsencrypt.md) | webtunnel-via-Caddy with per-host LE certs |

### Listener / discovery stealth

| File | Topic |
|------|-------|
| [`PLAN_POW_GATED_RENDEZVOUS.md`](PLAN_POW_GATED_RENDEZVOUS.md) | On-demand listener bind after a PoW-verified handshake |
| [`PLAN_WIRE_FORMAT_KILL_SWITCH.md`](PLAN_WIRE_FORMAT_KILL_SWITCH.md) | Magic-rotation mechanism for when a variant is compromised |

### Traffic shaping

| File | Topic |
|------|-------|
| [`PLAN_BANDWIDTH_MIMICRY.md`](PLAN_BANDWIDTH_MIMICRY.md) | Burst/cadence-profile-based traffic mimicry |

### CI / regression

| File | Topic |
|------|-------|
| [`FINGERPRINT_REGRESSION.md`](FINGERPRINT_REGRESSION.md) | n-gram analysis, JA3/JA4 drift detection in CI |

---

## 4. Cross-references to public docs

These public docs describe the building blocks but NOT their
anti-censorship application. When working on a public-facing review:

- [`../en/WIRE_PROTOCOL.md`](../en/WIRE_PROTOCOL.md) — frame format
  and Padding (mentioned as a "passive traffic analysis defense", not
  as DPI evasion).
- [`../en/HOW_IT_WORKS.md`](../en/HOW_IT_WORKS.md) / [`../ru/HOW_IT_WORKS.md`](../ru/HOW_IT_WORKS.md)
  — neutral overview, does not mention obfuscation.
- [`../en/SECURITY.md`](../en/SECURITY.md) — Sybil/eclipse/replay
  defense (generic P2P), not upstream censorship.
- [`../en/p-net.md`](../en/p-net.md) — private networks (membership
  certs), not bypass; but it can be used alongside as a deployment
  compartment.
- [`../en/protocol-spec.md`](../en/protocol-spec.md) / [`../ru/protocol-spec.md`](../ru/protocol-spec.md)
  — half-cap DHT discussion framed as "scanner-resistance", not
  "censorship-resistance".

---

## 5. What NOT to keep in internal/

- Generic security (Sybil/eclipse/replay) — that lives in `../en/SECURITY.md`.
- Identity model (Falcon/Ed25519 hybrid) — public, in
  `../en/identity-model.md`.
- Hot-standby, NAT traversal, route_cache — public, generic
  reliability features.
- Capacity planning, monitoring, troubleshooting — operator concerns,
  public.

Rule of thumb: if a document can be read as "we are building a
distributed P2P" without pointing at a specific adversary, it is
public. If it names the adversary, the DPI signatures it exploits,
specific jurisdictions, or ways to avoid identifiable traffic
patterns, it is internal.

---

## 6. Repository migration note

This subdir was created as part of the 2026-05-23 audit batch in
preparation for a future anonymous repo. The goal is to NOT draw
attention to the anti-censorship functionality through the docs during
the project's first phase of public existence.

The functionality itself stays in the code (transport adapters,
fingerprint module, traffic shaping). The posture is hidden in the
**descriptions**: public-facing documentation describes all features in
neutral terms ("transport adapters", "traffic privacy", "stealth
listeners"). Only the internal docs explain *why* they are built the way
they are.

Future steps once the repo becomes publicly visible:
1. At first, internal/ is not mentioned in the README or index.md.
2. After some initial period, add a link with an honest explanatory
   note about the audience.
3. Operator-side docs (censorship-target.md, DEPLOYMENT_HARDENING.md)
   can be moved into an "operator handbook" — a separate channel with
   restricted access.

---

## 7. Glossary

| Term | Meaning here |
|------|--------------|
| DPI | Deep Packet Inspection — an L7-level traffic classifier |
| JA3 / JA4 | TLS ClientHello fingerprints; identifying TLS stacks |
| obfs4 | Pluggable Transport, ScrambleSuit-successor (Tor project) |
| webtunnel | HTTPS-mimicking transport (Tor project) |
| FakeTLS | Per-listener TLS-fingerprint cloning of legitimate sites |
| ECH | Encrypted Client Hello (RFC 9460); encrypts SNI |
| Active probe | A targeted handshake the adversary sends to confirm a suspected endpoint |
| Half-cap | Capping each DHT FIND_NODE response at ≤ K/2 entries to slow down enumeration |
| Stealth listener | A listener that binds only after a PoW-verified rendezvous, so ss -tlnp shows nothing |
| Variant rotation | Changing the wire-format magic once the current signature has been identified |
