# Internal — Censorship-Resistance Architecture

> **Scope:** documentation что разкрывает анти-censorship посуру
> проекта. Содержимое НЕ должно линковаться из публичных индексов
> и НЕ должно упоминаться в outward-facing документах.
>
> **Audience:** core maintainers, operators of bridges/gateways, и
> security researchers с explicit access agreement.

---

## 0. Threat model в одном абзаце

Adversary — well-resourced (state-level или равноценный): owns the
local access network, может выполнять active probing, DPI на
fingerprint уровне (JA3/JA4/TLS-record-pattern/n-gram analysis),
IP-blacklisting, port-scanning known veil endpoints, и traffic
correlation analysis. Цель — обеспечить delivery даже когда adversary
блокирует все известные fingerprint'ы протокола; цель НЕ —
анонимность от self-hostile network operator (это отдельный threat
model в anonymity stack, не здесь).

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
   │     • webtunnel (HTTPS-mimic с reverse proxy)      │
   │     • FakeTLS (per-listener TLS-fingerprint clone) │
   │     • ECH opt-in (encrypted SNI)                   │
   ├────────────────────────────────────────────────────┤
   │ L6  Wire-format kill-switch                        │
   │     • Magic ротация если variant published         │
   │     • Capability negotiation forward-compat        │
   ├────────────────────────────────────────────────────┤
   │ L5  Traffic mimicry                                │
   │     • Bandwidth-shaping profiles (HTTPS-burst, ... │
   │     • Padding frames до MTU                        │
   ├────────────────────────────────────────────────────┤
   │ L4  Listener stealth                               │
   │     • PoW-gated rendezvous (port closed by default)│
   │     • On-demand bind после verified handshake      │
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
   │     • CI-gated против JA3/JA4 drift                │
   └────────────────────────────────────────────────────┘
```

Каждый слой задокументирован отдельно — см. §3 catalog.

---

## 2. Activation philosophy

**Не всё включается одновременно.** Default config — open, neutral,
TCP-only — отдаёт baseline функциональность. Каждая фича из L4-L7
opt-in через config:

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

Reason: некоторые слои (e.g. ECH) могут активно паливать узел в
jurisdictions где их использование отслеживается. Operator выбирает
posture на основе target jurisdiction и risk tolerance, не код.

---

## 3. Document catalog

### Strategy + threat models

| File | Topic |
|------|-------|
| [`ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md) | Полный threat model, DPI vendor analysis (VAS Experts СКАТ etc), 35 evasion methods, roadmap |
| [`censorship-target.md`](censorship-target.md) | Per-jurisdiction deployment guidance (operator-side) |
| [`dpi-evasion.md`](dpi-evasion.md) | Architecture summary of what's built vs. planned |
| [`DEPLOYMENT_HARDENING.md`](DEPLOYMENT_HARDENING.md) | Operator-side gap closure: CDN, AS-level, hosting choices |

### Transport obfuscation

| File | Topic |
|------|-------|
| [`PLAN_TRANSPORT_OBFUSCATION.md`](PLAN_TRANSPORT_OBFUSCATION.md) | obfs4 + FakeTLS implementation plan |
| [`PLAN_ECH_OPT_IN.md`](PLAN_ECH_OPT_IN.md) | Encrypted Client Hello opt-in |
| [`webtunnel-letsencrypt.md`](webtunnel-letsencrypt.md) | webtunnel-via-Caddy с per-host LE certs |

### Listener / discovery stealth

| File | Topic |
|------|-------|
| [`PLAN_POW_GATED_RENDEZVOUS.md`](PLAN_POW_GATED_RENDEZVOUS.md) | On-demand listener bind после PoW-verified handshake |
| [`PLAN_WIRE_FORMAT_KILL_SWITCH.md`](PLAN_WIRE_FORMAT_KILL_SWITCH.md) | Magic-rotation механизм когда variant скомпрометирован |

### Traffic shaping

| File | Topic |
|------|-------|
| [`PLAN_BANDWIDTH_MIMICRY.md`](PLAN_BANDWIDTH_MIMICRY.md) | Burst/cadence-profile-based traffic mimicry |

### CI / regression

| File | Topic |
|------|-------|
| [`FINGERPRINT_REGRESSION.md`](FINGERPRINT_REGRESSION.md) | n-gram analysis, JA3/JA4 drift detection в CI |

---

## 4. Cross-references к public docs

Эти public docs описывают building blocks но НЕ их анти-censorship
применение. При работе с public-facing review:

- [`../en/WIRE_PROTOCOL.md`](../en/WIRE_PROTOCOL.md) — frame format
  и Padding (упоминается как "passive traffic analysis defense", не
  как DPI evasion).
- [`../en/HOW_IT_WORKS.md`](../en/HOW_IT_WORKS.md) / [`../ru/HOW_IT_WORKS.md`](../ru/HOW_IT_WORKS.md)
  — neutral overview, не упоминает obfuscation.
- [`../en/SECURITY.md`](../en/SECURITY.md) — Sybil/eclipse/replay
  defense (generic P2P), не upstream censorship.
- [`../en/p-net.md`](../en/p-net.md) — private networks (membership
  certs), не bypass; но в качестве deployment compartment может
  использоваться вместе.
- [`../en/protocol-spec.md`](../en/protocol-spec.md) / [`../ru/protocol-spec.md`](../ru/protocol-spec.md)
  — half-cap DHT discussion framed как "scanner-resistance", не
  "censorship-resistance".

---

## 5. Что НЕ держать в internal/

- Generic security (Sybil/eclipse/replay) — это в `../en/SECURITY.md`.
- Identity model (Falcon/Ed25519 hybrid) — public, в
  `../en/identity-model.md`.
- Hot-standby, NAT traversal, route_cache — public, generic
  reliability features.
- Capacity planning, monitoring, troubleshooting — operator concerns,
  public.

Правило большого пальца: если документ может быть прочитан как
"мы строим distributed P2P" без указания на конкретного adversary —
он public. Если он называет adversary, эксплуатируемые DPI signatures,
конкретные jurisdictions, или способы избежать identifiable traffic
patterns — он internal.

---

## 6. Repository migration note

Этот subdir создан в рамках audit batch 2026-05-23 как подготовка к
будущему anonymous repo. Цель — на первом этапе публичного
existence'а проекта НЕ привлекать внимание к анти-censorship
функциональности через docs.

Functionality сама по себе остаётся в коде (transport adapters,
fingerprint module, traffic shaping). Posture скрыта в **descriptions**:
public-facing документация описывает все features в нейтральных
терминах ("transport adapters", "traffic privacy", "stealth
listeners"). Только internal docs объясняют *почему* они построены
именно так.

Future steps когда rep становится publicly visible:
1. Изначально internal/ не упоминается в README или index.md.
2. После некоторого initial period — добавить ссылку с честной
   объяснительной запиской об audience.
3. Operator-side docs (censorship-target.md, DEPLOYMENT_HARDENING.md)
   могут быть переведены в "operator handbook" — отдельный канал с
   restricted access.

---

## 7. Glossary

| Term | Meaning here |
|------|--------------|
| DPI | Deep Packet Inspection — L7-уровневый трафик-классификатор |
| JA3 / JA4 | TLS ClientHello fingerprints; identifying TLS stacks |
| obfs4 | Pluggable Transport, ScrambleSuit-successor (Tor project) |
| webtunnel | HTTPS-mimicking transport (Tor project) |
| FakeTLS | Per-listener TLS-fingerprint cloning of legitimate sites |
| ECH | Encrypted Client Hello (RFC 9460); encrypts SNI |
| Active probe | Adversary's targeted handshake to verify suspected endpoint |
| Half-cap | DHT FIND_NODE response limit ≤ K/2 to slow enumeration |
| Stealth listener | Listener bound only after PoW-verified rendezvous; ss -tlnp shows nothing |
| Variant rotation | Changing wire-format magic when current signature is identified |
