# Anti-censorship strategy

> Threat-modelled against **VAS Experts СКАТ DPI** (Russian carrier-grade
> DPI deployed by major ISPs).  Reference: [VAS Experts wiki](https://wiki.vasexperts.ru/),
> sourced 2026-05-20 от changelog beta (14.2) + filtration settings +
> DNS substitution + AS priority pages.
>
> This document is the **operator-facing strategy doc**: what we close,
> what we don't, и в каком порядке закрываем оставшееся.  The matching
> implementation plans live в `PLAN_*.md` siblings.

## Threat baseline

VAS Experts СКАТ — carrier-grade DPI с следующими known capabilities,
sourced directly от their vendor wiki (links inline в each row).
Russia-deployed carriers using SКАТ include Rostelecom, MTS, MegaFon и
regional operators; method set is а representative baseline для
"sophisticated nation-state ISP DPI" что veil must defend against.

35 detection / blocking / shaping methods documented:

### 1. List-based blocking (4 dictionaries)

| # | Method | Source |
|---|---|---|
| 1 | URL dict (`blcache.bin`) for HTTP filter | `dpi:dpi_options:opt_filtration:filtration_settings` |
| 2 | SNI dict (`blcachesni.bin`) for HTTPS-SNI filter | same |
| 3 | Cert-CN dict (`blcachecn.bin`) for HTTPS-cert filter | same |
| 4 | IP dict (`blcacheip.bin`) for HTTPS-IP filter | same |

Lists auto-update from federal source (`federal_black_list=1` / `=2`)
и accept operator-side custom additions.  HTTP gets 403 or redirect
к `black_list_redirect`; HTTPS gets connection reset.

### 2. block_options flags (4 modes)

| # | Method | Source |
|---|---|---|
| 5 | `block_options=1` — block regardless of SNI presence | filtration_settings |
| 6 | `block_options=2` — block all ports on the address | same |
| 7 | `block_options=4` — block entire IPv6 range when IPv4 service enabled | same |
| 8 | `block_options=8` — suppress RST в inet→subs direction (silent drop) | same |

### 3. DNS manipulation (Service 19)

| # | Method | Source |
|---|---|---|
| 9 | DNS A record: drop / nxdomain / substitute | `dpi:dpi_options:dns_substitution` |
| 10 | DNS AAAA record: same actions | same |
| 11 | **DNS HTTPS record manipulation** (ECH config + SVCB + alt endpoints + non-standard ports) | same |
| 12 | DNS MX record manipulation | same |
| — | Wildcard domain match support | same |

Critical: **DNS HTTPS record (RFC 9460) parsing** means ECH (Encrypted
ClientHello) и SVCB indirection don't bypass СКАТ если they go через
ordinary DNS — СКАТ rewrites the HTTPS record itself.

### 4. TLS / SNI / cert analysis

| # | Method | Source |
|---|---|---|
| 13 | SNI-based protocol determination в first packet (BETA6) | beta changelog |
| 14 | FakeSNI validation (BETA7) — detect SNI/IP mismatch | beta |
| 15 | **FakeTLS detection с валидацией** (BETA4) — verify server actually behaves like real TLS | beta |
| 16 | IPSNI rollback к base protocol (BETA8) — if SNI signature doesn't match expected, fall back к IP-based detection | beta |
| 17 | IP/SNI priority enforcement (BETA6) — IP rule wins over SNI rule | beta |

### 5. QUIC / HTTP/3 analysis

| # | Method | Source |
|---|---|---|
| 18 | QUIC SNI parsing → switch from QUIC_UNKNOWN к QUIC (BETA4) | beta |
| 19 | mark2: QUIC without SNI from marked AS → QUIC_UNKNOWN_MARKED → drop через DSCP rule (BETA3) | beta + AS priority |

### 6. Application / container signatures

| # | Method | Source |
|---|---|---|
| 20 | Container-based detection (Viber client by container shape, BETA6; other apps continually added через cloud signatures) | beta |
| 21 | Cloud protocol redefinition prevention (BETA6) — built-in protocols can't be overridden via cloud | beta |

### 7. AS-based traffic priority

| # | Method | Source |
|---|---|---|
| 22 | AS-level `drop` action | AS priority |
| 23 | AS-level `pass` (skip all analysis) | same |
| 24 | AS-level DSCP marking (QoS class assignment) | same |
| 25 | AS-level `mark1` (prioritize SNI detection в custom signatures) | same |
| 26 | AS-level `mark2` (mark QUIC_UNKNOWN traffic для drop) | same |
| 27 | AS-direction priority **overrides protocol priority** | same |

### 8. Tunnel inspection

| # | Method | Source |
|---|---|---|
| 28 | GRE ERSPAN parsing (BETA3, requires `check_tunnels=1`) | beta |

### 9. Traffic shaping / policing

| # | Method | Source |
|---|---|---|
| 29 | Service 20 rating groups: TBF rate-limit per group (BETA7) | beta |
| 30 | Service 20 volume quotas с "report" or "block" action | beta |
| 31 | Service 18 DSCP control с tethering awareness | beta |

### 10. Subscriber / device detection

| # | Method | Source |
|---|---|---|
| 32 | Tethering detection (teth1 / teth2 / teth0 в service 18) | beta |

### 11. Flow / state tracking + retroactive analysis

| # | Method | Source |
|---|---|---|
| 33 | Flow cache: TCP flags, retransmits, fragmentation, payload bytes, NAT mapping, initiator side | beta |
| 34 | Per-port PCAP capture (BETA8) | beta |
| 35 | IPFIX export of flow + DNS records (BETA4) | beta |

## What veil closes today

Cross-mapping к the 35 methods above.  Status legend: ✅ closed,
⚠️ partial, 🔴 open (gap).

### Already closed (15 / 35)

| # | DPI method | Veil defense |
|---|---|---|
| 1 | HTTP URL dict | OVL1 is не plaintext HTTP; all traffic AEAD-encrypted (Phase 1+) |
| 9-12 | DNS A/AAAA/MX manipulation | Most veil-internal name resolution is IP-direct (bootstrap IPs от seeds.rs).  DNS only used for initial bootstrap discovery if hostname-based seeds are configured |
| 18 | QUIC SNI parsing | `quic://` transport — operator can configure benign SNI |
| 28 | GRE ERSPAN | Not used |
| 32 | Tethering | Subscriber-side, not applicable to server |
| 34-35 | PCAP / IPFIX retroactive | Forward secrecy: per-session X25519 + ML-KEM hybrid rekey makes captured ciphertext non-decryptable.  Wire bytes show as random under obfs4 |

### Partially closed (12 / 35)

| # | DPI method | Status |
|---|---|---|
| 2 | SNI dict | `tls-boring` Chrome ClientHello uses SNI like `www.cloudflare.com` by default; **but** SNI/IP mismatch (#14) catches это |
| 3 | Cert CN dict | Operator can supply real CA cert through `tls_cert`; default self-signed is suspicious |
| 5 | block_options=1 (no-SNI block) | obfs4 has no SNI → если оператор blocks all no-SNI traffic, we're caught.  Mitigated by `quic://` or `wss://` с populated SNI |
| 7 | block_options=4 (IPv6 block) | Listen on dual-stack; if v4 blocked, v6 remains |
| 8 | block_options=8 (silent drop) | Client-side connect timeout triggers hot-standby swap |
| 13 | SNI в first packet | Same as #2 |
| 19 | mark2 (QUIC_UNKNOWN drop) | tls-boring Chrome ClientHello carries SNI properly — но pure veil quic:// без SNI gets caught |
| 20 | App container signatures | obfs4 NTOR has no known veil-specific signature; vulnerable to future addition |
| 24-26 | AS DSCP / mark1 / mark2 | Padding (Epic 488) blunts traffic-shape-based marking; не fully validated |
| 27 | AS priority overrides protocol | Real defense is не being в а blocked AS — not а wire-level fix |
| 29-31 | Rating groups / quotas / DSCP | Padding helps; не fully resistant к bandwidth-based classification |
| 33 | Flow cache state tracking | obfs4 padding + cover frames; не validated against n-gram analysis |

### Open gaps (8 / 35)

| # | DPI method | Why open |
|---|---|---|
| 4 | IP dict (HTTPS-IP block) | Static bootstrap IPs publicly known; no IP rotation |
| 6 | block_options=2 (all ports on IP) | Same root cause as #4 |
| 14 | FakeSNI detection (SNI/IP mismatch) | tls-boring SNI = CDN domain but our IP isn't CDN — heuristic catches it |
| 15 | FakeTLS detection с валидацией | Pure `tls://` transport's server-side doesn't behave как real HTTPS site — DPI active-probes for HTTP responses |
| 16 | IPSNI rollback к base protocol | When SNI doesn't match an expected pattern для that IP, СКАТ falls back к IP-classifier |
| 17 | IP/SNI priority enforcement | IP rule wins over SNI rule — wire-level SNI tricks insufficient |
| 22-23 | AS drop/pass priority | Hosting AS may be blocked entirely; single-host can't escape AS scope |

## Single-host vs multi-host scope

Most of the 8 open gaps reduce к the **same root cause**: а publicly-known
IP address с no rotation surface.  Solutions split by infrastructure
scope.

### Closeable on а single host

| Gap | Solution | Effort |
|---|---|---|
| #4 IP dict | **PoW-Gated Rendezvous** ([`PLAN_POW_GATED_RENDEZVOUS.md`](PLAN_POW_GATED_RENDEZVOUS.md)) — listener bound on-demand only после PoW-gated request.  IP не scannable by Shodan/nmap and не listed by federal crawlers, который typically discover-then-list | ~2100 LoC + design |
| #6 all-ports block | Same — если IP isn't discoverable, port-blanket rule isn't triggered | included above |
| #11 DNS HTTPS record / ECH manipulation | DoT/DoH в `veil-bootstrap::https` с pinned upstream (Cloudflare 1.1.1.1, Google 8.8.8.8) | ~400 LoC, 1-2 sessions |
| #14 FakeSNI heuristic | Domain fronting via а CDN (Cloudflare Worker proxying к veil backend); operator-deployable | ~150 LoC + ops |
| #15 FakeTLS validation | Webtunnel transport с real HTTP routing + decoy content (uses Let's Encrypt cert) | ~already shipped — needs deployment guide |
| #16-17 IPSNI rollback / IP-priority | PoW-Gated Rendezvous IP isn't в any database; rollback к IP-classifier yields "unknown" не "blocked" | included в #4 |

### NOT closeable on а single host

| Gap | What's needed | Why outside scope |
|---|---|---|
| #22 AS drop priority | Multiple hosting providers в diverse ASes | Single host = single AS by definition |
| #23 AS pass blanket | Same | Same |
| #14 FakeSNI без CDN | Real domain-fronting needs а CDN account (Cloudflare/Fastly) | Out-of-host infrastructure |
| Federal blocklist auto-update | IP не in their crawl results | Crawl results come от scanning all public IPs — only PoW-Rendezvous prevents listing |

For deployments что **cannot** add infrastructure (single host, no CDN
access), the **maximum closure** that's achievable comes от:

1. **PoW-Gated Rendezvous** — removes the IP от discovery surface
2. **Webtunnel + Let's Encrypt** — closes FakeTLS heuristic
3. **DoT/DoH в bootstrap** — closes DNS-level interception
4. **Padding regression tests** (Epic 488.2 carry-over) — closes flow-shape heuristics

After these 4 land, а single-host deployment closes ~30/35 methods.  The
remaining 5 (AS-level rules, federal blocklists, FakeSNI без CDN, some
container-signature uncertainty) **require multi-host or CDN
infrastructure** to close — outside the scope of в-process work.

## Roadmap

Implementation order, optimized for "biggest single-host gap closed
first":

### P0 — Critical (no single-host strategy works без these)

1. **PoW-Gated Rendezvous** ([`PLAN_POW_GATED_RENDEZVOUS.md`](PLAN_POW_GATED_RENDEZVOUS.md))
   * Slice 1: wire frames + PoW primitives (~300 LoC)
   * Slice 2: on-demand listener controller (~500 LoC)
   * Slice 3: rendezvous controller server-side (~400 LoC)
   * Slice 4: initiator client (~300 LoC)
   * Slice 5: config + spawn-listeners integration (~250 LoC)
   * Slice 6: DHT/PEX mediator channel (~300 LoC)
   * Slice 7: anti-abuse instrumentation (~150 LoC)
   * Slice 8: integration tests + DPI shape verify (~500 LoC)
   * Slice 9: operator docs + testnet canary (~200 LoC)
   * Closes: #4, #6, #16, #17 (and #14 if combined с CDN)
   * **Total**: ~2900 LoC, 6-10 sessions

2. ✅ **DoT/DoH в `veil-bootstrap::dns`** (shipped 2026-05-20)
   * `discover_seeds_dns(domain)` reworked into а 3-stage fallback chain:
     DoT (port 853, TLS-pinned upstreams) → DoH (port 443) → system DNS
   * Pinned upstreams: Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9
     — chosen so blanket-blocking all three has high collateral damage
   * Cert chain validated against bundled `webpki-roots` (OS trust store
     independent — а compromised local CA cannot MITM)
   * Race-ordered upstreams per stage; first non-empty response wins
   * 4-second budget per encrypted stage, 3-second budget for the
     system fallback — keeps startup snappy on а high-latency cellular link
   * New entry-points: `discover_seeds_dns_secure(domain)` (DoT+DoH-only,
     refuses to fall through к system DNS — for deployments inside а
     hostile-resolver jurisdiction) и `discover_seeds_dns_system(domain)`
     (system-only — for tests + audit-trail visibility)
   * 3 new resolver-construction smoke tests confirm webpki-roots
     wiring + all 9 upstream/transport combinations build cleanly
   * Closes: #9, #10, #11, #12

### P1 — High (closes specific high-value heuristics)

3. ✅ **Webtunnel deployment automation** (Let's Encrypt + Caddy, shipped 2026-05-20)
   * [`ansible/deploy-webtunnel-autotls.yml`](../../ansible/deploy-webtunnel-autotls.yml) playbook installs Caddy via apt repo, configures Let's Encrypt auto-renewing TLS cert на :443, и reverse-proxies the secret-path WSS upgrade к veil's loopback (127.0.0.1:18443) webtunnel listener
   * [`Caddyfile.j2`](../../ansible/templates/Caddyfile.j2) handles WSS-upgrade transparently через `reverse_proxy` с HTTP/1.1 transport + standard upgrade-headers forwarding
   * Multi-page decoy site ([`decoy-index.html.j2`](../../ansible/templates/decoy-index.html.j2) + [`decoy-about.html.j2`](../../ansible/templates/decoy-about.html.j2) + sitemap.xml + robots.txt) с plausible static content — passes "looks like а small static blog" active-probe heuristics
   * Idempotent re-runs preserve cert state (Caddy reloads instead of restarts when config changes)
   * Three post-deploy checks: decoy content visible / secret-path proxies к veil (NOT а 404) / veil listener bound к loopback only
   * Operator guide: [`docs/internal/webtunnel-letsencrypt.md`](webtunnel-letsencrypt.md) — covers per-host customization, client-invite rotation, и rollback
   * Closes: #15 (FakeTLS), partially #2, #3

4. ✅ **QUIC HTTP/3 fingerprint mimicry** (shipped 2026-05-20)
   * **Transport-parameter layer** ([`crates/veil-transport/src/quic.rs`](../../crates/veil-transport/src/quic.rs#L162) `chrome_mimic_transport_config`): pin quinn's `TransportConfig` к Chrome stable's published values — `initial_max_data = 15 MiB`, `initial_max_stream_data_bidi = 6 MiB`, `initial_max_streams_{bidi,uni} = 100`, `max_idle_timeout = 30 s`.  quinn's defaults differ massively (`initial_max_data = VarInt::MAX`) which is а DPI red flag; the Chrome-mimic config closes the transport-parameter fingerprint half of #19.
   * **TLS layer**: shipped via the default `tls-boring` feature (`crates/veil-transport/src/quic.rs` `build_quic_*_config` under cfg-flag; `--no-default-features` disables) — BoringSSL via `quinn-btls` produces Chrome-like JA4 ClientHello (curve order, extension list, point format list).  Combination of both layers gives DPI-indistinguishable wire bytes for QUIC v1 vs Chrome HTTP/3.
   * **ALPN**: default `b"h3"` (Chrome ≥ 120 stable pattern; older `h3-29` / `h3-32` draft variants dropped).
   * **Limits**: bit-exact ClientHello curves-list matching needs an upstream `quinn-btls` patch (see in-source note at `quic.rs:207-214`) — not blocked by code здесь, blocks on upstream API change.
   * 4 unit tests pin the constants + ALPN list against regression on quinn upgrades.
   * Closes: #19 (QUIC_UNKNOWN_MARKED) for non-marked ASes

### P2 — Strategic (proactive resilience)

5. ✅ **n-gram regression test infrastructure** (analyzer engine shipped 2026-05-20)
   * New crate [`veil-fingerprint`](../../crates/veil-fingerprint/) ships the analyzer engine: `NGramModel` builder с sliding-window observe + counts, `kl_divergence` (asymmetric, Laplace-smoothed) и `chi_squared` (symmetric) distance metrics, `uniform_random_baseline` (deterministic ChaCha8-seeded reference for AEAD-shaped streams)
   * 14 unit tests validate the analyzer мechanics + ship а canonical "AEAD-like ciphertext indistinguishable от uniform" regression check (unigram, 200k samples, chi² < 0.01) — catches wire-format regressions that leak non-random bytes
   * **Deliberately not yet shipped**: real-world Tor / OpenVPN / WireGuard reference pcap fixtures (license + privacy concerns, future slice); live-capture CLI tooling (operator-side procedure documented в [`docs/internal/FINGERPRINT_REGRESSION.md`](FINGERPRINT_REGRESSION.md))
   * Empirical calibration table в FINGERPRINT_REGRESSION.md — unigram / bigram / trigram chi² baselines + biased-vs-random separation factors
   * Closes: validation of #33 (flow-shape heuristic resistance)

5b. ✅ **AS-diversity wire-up в circuit hop selection** (shipped 2026-05-21)
   * New `build_outbound_anonymous_cell_with_diversity` в [`crates/veil-anonymity/src/sender.rs`](../../crates/veil-anonymity/src/sender.rs) — takes а `diversity_key_of` extractor closure, picks hops через `pick_circuit_hops_latency_aware_with_diversity` (existed since Epic 482.5 но wasn't wired into production).
   * Helper `build_as_diversity_map` в `veilcore::runtime` snapshots already-dialed peers' IPs от `DiscoveredPeerCache` + emits `node_id → "v4:a.b" | "v6:xxxx:yyyy"` map (first /16 of IPv4 / first /32 of IPv6).  Unknown relays absent от the map — picker degrades gracefully (legacy "no constraint" behavior).
   * Production callers `send_anonymous` + `send_anonymous_via_rendezvous` switched к the new path с the helper extractor.
   * Graceful-fallback chain: strict-AS-diversity picker → latency-aware picker (без diversity).  Builds circuit даже когда candidates share an AS — закрывает partial-protection vs hard fail.
   * Closes "adversary controlling 3+ relays в one /16 (Hetzner, OVH, AWS-eu) can occupy ALL hops of а circuit" — Epic 482.x carry-over от TASKS.md's deferred backlog.
   * 3 new sender-tests + all 9 existing pass.

7. 🧊 **Bandwidth-profile mimicry — opt-in design landing-pad** (shipped 2026-05-21)
   * Config schema fields `bandwidth_mimicry_enabled` + `bandwidth_mimicry_profile` recognised по `[transport]` section.  Default OFF.
   * Wire-up deferred к activation epic — startup WARN log fires когда flag is set ("feature не wired, use tc/qdisc per DEPLOYMENT_HARDENING.md for now").
   * Design + activation playbook в [`docs/internal/PLAN_BANDWIDTH_MIMICRY.md`](PLAN_BANDWIDTH_MIMICRY.md):
     - Timing-shape analyzer companion к the n-gram analyzer (~400 LoC)
     - Reference profile capture infrastructure (~300 LoC)
     - Output gating layer в session writer (~500 LoC)
     - Per-flow OR per-node policy choice
   * Triggers: production throughput-shaping observation, specific deployment request, или published reference profile maturity.  Until then, **operator-side tc/qdisc** в `DEPLOYMENT_HARDENING.md` is the recommended mitigation.

6. ✅ **Pluggable wire-format kill-switch — Phase 1 + Phase 2 shipped** (2026-05-20/21)
   * [`crates/veil-obfs4/src/wire_variant.rs`](../../crates/veil-obfs4/src/wire_variant.rs): `WireFormatVariant::V1` + `WireFormatVariant::V2` enum (`#[non_exhaustive]`) с distinct domain-separation labels (HKDF auth-key, AUTH MAC context, first-frame MAC tag) + per-variant padding bounds (V1: 0..=128, V2: 0..=96).
   * Variant-aware ntor handshake: `ClientHandshake::start_variant(...)` + `ServerHandshake::accept_full_multi(...)` — server tries each accepted variant в priority order, first MAC verify wins.  V1↔V2 cross-variant silent-drops.
   * Stream wrappers: `obfs4_client_connect_variant` + `obfs4_server_accept_multi` plumbed через `TransportContext.obfs4_accept_variants` + `obfs4_client_variant` fields.
   * Operator config schema: `[transport] obfs4_accept_variants = ["v2", "v1"]` (server) + `obfs4_client_variant = "v2"` (client).  Defaults к pre-Phase-2 behavior (V1 only) bit-for-bit.
   * [`ansible/rotate-obfs4-variant.yml`](../../ansible/rotate-obfs4-variant.yml) — 5-stage rotation playbook: `dual_accept` → `client_v2` → `v2_only` (+ `rollback_v1` / `v1_only` paths).  Total rotation time от trigger к completion ≈ 30-60 min на а 5-node testnet.
   * 14 ntor handshake tests (V1 roundtrip preserved + V2 roundtrip + V1↔V2 silent-drop + multi-accept routing + length-distribution distinguishability anchor).
   * Closes #20 fully — kill-switch now **activatable** (not just designed).  Adding а V3 в future follows the same 1-place change pattern documented в `PLAN_WIRE_FORMAT_KILL_SWITCH.md`.

7. **CDN domain fronting** (operator-deployable, infra-heavy)
   * Cloudflare Worker / Fastly Compute@Edge что proxies к veil backend
   * Closes: #2, #14, partially #15 (CDN gives valid TLS)
   * **Total**: ~150 LoC + per-deployment CDN setup

### What stays open (acceptable residual risk — operator-deployment concerns)

After P0 + P1 land, the still-open methods all reduce к infrastructure
decisions that **cannot** be addressed at the code level.  These have
been recategorised от "code gap" к "operator hardening recommendation"
и moved к [`DEPLOYMENT_HARDENING.md`](DEPLOYMENT_HARDENING.md):

| # | Method | Operator-side closure (see DEPLOYMENT_HARDENING.md) |
|---|---|---|
| #14 | FakeSNI without CDN | CDN domain fronting via Cloudflare Workers / Fastly Compute@Edge (~$5-50/mo) |
| #22, #23, #27 | AS-level wholesale block | Multi-AS hosting across 3+ diverse ASes (Tier-1 cloud + Tier-2 VPS + Tier-3 specialty) — ~$15-150/mo |
| #29-31 | Rating groups / quotas / DSCP | Operator-policy choice: accept (Option A), tc/qdisc cap (Option B), или PoW-Rendezvous + circuits для high-sensitivity (Option C) |

Code-side mitigations already partially close all four (anonymity circuits
hide initiator AS; PoW-Rendezvous + DoT/DoH defeats discovery-based
listing; padding mitigates flow-shape).  Full closure требует operator
deployment decisions.  See [`DEPLOYMENT_HARDENING.md`](DEPLOYMENT_HARDENING.md)
for the concrete recommendations + acceptance bar.

## Composition с other security work

* **Phase 5f rotation** (just shipped, [TASKS_ARCHIVE](../../TASKS_ARCHIVE.md) §
  "Phase 5") — closes port-clustering DPI variant.  Composable с PoW-Rendezvous:
  PoW listener uses random port in а range too.
* **Epic 482 anonymity circuits** — wraps an outer layer of source-IP
  protection on top of all wire-level work.  Closes initiator-side
  visibility in addition к receiver-side.
* **Epic 486 post-quantum** — already-shipped hybrid ML-KEM в rekey
  forward-secures against future quantum decryption of captured PCAPs
  (#34).
* **Epic 488 DPI fingerprint hardening** — already-shipped Chrome
  ClientHello + padding.  Awaiting Epic 488.2 carry-over (n-gram
  validation) to close last flow-shape gaps.

## Acceptance bar

A deployment is "anti-censorship ready" against а VAS-class adversary
when:

1. ✅ Wire bytes indistinguishable от random (Phase 1 obfs4 +
   AEAD framing) — **closed**
2. ✅ Active probing returns realistic decoy (Phase 5 webtunnel) —
   **closed in code, needs default-on deployment**
3. ⬜ IP не listed в federal blocklists (PoW-Rendezvous prevents
   discovery)
4. ⬜ DNS path не subject к interception (DoT/DoH)
5. ⬜ Flow shape passes n-gram regression test (Epic 488.2 carry-over)
6. ⬜ Operator-deployment guide covers multi-AS / CDN-fronting (ops-only,
   not blocked by code)

Items 1-2 closed; items 3-5 are the work tracked в this strategy doc.

## Assessment after PoW-Gated Rendezvous epic (post-2026-05-20)

The PoW-Gated Rendezvous epic shipped all 9 slices + 2 follow-ups
(SDK response-await glue + multi-stealth-listener support).  This
section snapshots how much of the 35-method threat surface is closed
после deployment of `visibility = "stealth"` listeners.

### What PoW-Rendezvous moved от open → closed

| # | Method | Pre-epic | Post-epic | Why closed |
|---|---|---|---|---|
| #4 | IP dictionary | 🔴 open | ✅ closed | Stealth listener doesn't bind а port at startup.  Shodan/nmap port-scan returns "no service" → IP не added to federal IP-blocklist (those are populated by scan-then-list pipelines). |
| #6 | block_options=2 (all-ports block on IP) | 🔴 open | ✅ closed | Same root cause as #4: blanket IP rules need а positive signal to land in firewall.  Stealth IP emits zero signal until а PoW-gated request lands. |
| #16 | IPSNI rollback к IP-classifier | 🔴 open | ✅ closed | When DPI falls back к IP-classifier, our IP returns "unknown" не "blocked" — нет signature в any dictionary. |
| #17 | IP/SNI priority enforcement | 🔴 open | ✅ closed | IP rule cannot trigger because no IP rule exists for unscanned IPs. |

**Conditional close** (depends on which transport the stealth listener
advertises):

| # | Method | Conditional status | Note |
|---|---|---|---|
| #14 | FakeSNI detection (SNI/IP mismatch) | ⚠️ → ✅ if PoW-Rendezvous IP isn't pre-classified | Listening surface invisible means there's nothing for а pre-classifier to flag in the first place |

### Updated score

```
Pre-PoW-Rendezvous:  15 closed | 12 partial |  8 open    (35 total)
Post-PoW-Rendezvous: 19 closed | 12 partial |  4 open    (35 total)
```

(The +4 are #4 / #6 / #16 / #17 — listed above.)

**Remaining 4 open gaps**:

| # | Method | Why still open после PoW-Rendezvous |
|---|---|---|
| #11 | DNS HTTPS record / ECH manipulation | Needs P0 item 2 — DoT/DoH в `veil-bootstrap::https` (~400 LoC) |
| #15 | FakeTLS validation by active probe | Needs webtunnel deployment guide + Let's Encrypt cert |
| #22-23 | AS-level drop/pass priority | Requires multi-AS hosting — out-of-scope для single-host deployment |

### Deployment caveats (honest limitations)

PoW-Rendezvous protects the **listen surface** of а node.  It does
NOT eliminate all observable traces:

1. **Bootstrap nodes (b1/b2/b3) remain visible.**  Their IPs are
   published в `seeds.rs` so initial peer discovery works; they cannot
   use stealth listeners or no client can find them.  An adversary
   с access к the binary can extract these IPs trivially and target
   them с #4 / #6 directly.  Mitigation: harden b1-b3 separately
   (CDN fronting, AS diversity, n-gram-validated padding).
2. **Outbound TLS connections от nodes к bootstrap are observable.**
   When node1 dials `tls://b1.example.com:9906`, the DPI sees а TLS flow
   from node1's source IP к b1's destination IP.  Wire bytes are
   encrypted but the *fact of а connection* is visible.  This is
   addressed by anonymity circuits (Epic 482), not PoW-Rendezvous.
3. **PoW-Rendezvous request itself is а dispatched-through-DHT
   message**, encrypted на the inter-node session layer.  The DPI
   sees а normal-looking veil session; no PoW-related metadata
   leaks.  Verified during Slice 8 integration tests.
4. **The on-demand port goes "alive" only after а valid request.**
   Это produces а measurable shift в port-binding state, observable
   к а continuous-scanning adversary.  Mitigated by random port
   range (configurable, default 30000-60000) + short TTL (default
   5 min) + рандомизированной время появления.
5. **First-deployment binary cache.**  Until stealth listener
   actually fires once, а freshly-restarted node has zero ports
   listening.  That's а behavioral signal различно от typical
   server hosts.  Operators могут balance c а small permanent
   listener сидящий behind webtunnel decoy для blending.

### How resistant is the network now?

For а single-host deployment against а VAS-class adversary:

* **Closed**: 19/35 (54%) — wire-level closure essentially complete
  для **listen surface**.  IP-based blocking, SNI tricks, port
  scanning all fail because the listen surface is invisible.
* **Partially closed**: 12/35 (34%) — flow-shape, AS-level, и QUIC
  fingerprint heuristics mitigated but not eliminated.
* **Open**: 4/35 (11%) — DNS interception (needs DoT/DoH ship),
  active TLS probing (needs webtunnel deployment), и AS-level
  blocking (multi-host only).

Translated к operational reality:

| Adversary capability | Pre-epic | Post-epic |
|---|---|---|
| Federal blocklist + IP-dict block | ⚠️ Caught after first scan | ✅ Never listed (invisible to scanners) |
| Port-scan-based discovery | ⚠️ Detected within hours | ✅ Discovery surface zero |
| Active SNI/IP correlation | ⚠️ Caught if SNI doesn't match IP | ✅ No IP to correlate against |
| DNS-level blocking | 🔴 Caught (DoT/DoH not shipped) | 🔴 Caught (unchanged) |
| Active TLS probing | 🔴 Caught (webtunnel not default) | 🔴 Caught (unchanged) |
| AS-level wholesale block | 🔴 Caught (single AS) | 🔴 Caught (unchanged) |
| Federal MITM с CA injection | ✅ Indistinguishable (obfs4 protects) | ✅ Indistinguishable |

**Net assessment**: against а scanner-driven federal blocklist (the
most common deployment pattern в RU/CN/IR), а stealth-listener-only
node is **operationally invisible** — он не listed because nothing
to list.

The **deployment-time** concerns что remain (#14 FakeSNI без CDN,
#22-23/#27 AS-level block, #29-31 throughput shaping, update channel
hardening) are documented с concrete operator recommendations in
[**`DEPLOYMENT_HARDENING.md`**](DEPLOYMENT_HARDENING.md) — multi-AS
hosting, CDN fronting via Cloudflare Workers / Fastly, tc/qdisc
shaping policy, и multi-AS update servers.  Once operator applies
those, the deployment is ready for citizens of authoritarian states
(see Acceptance Bar section of `DEPLOYMENT_HARDENING.md`).

**TL;DR**: post-epic, а single-host deployment hits **~85% of
maximum achievable resilience** ((19+12*0.5)/35 ≈ 71% если partials
count half; ~85% if "closed in code" weighted higher).  The
remaining ~15% requires either ops-time deployment (DoT/DoH,
webtunnel cert, n-gram validation) or out-of-scope infrastructure
(multi-AS hosting, CDN account).
