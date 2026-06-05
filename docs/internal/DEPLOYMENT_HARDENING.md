# Deployment hardening — anti-censorship operator guide

Operator-side recommendations to close the residual DPI / censorship gaps that **cannot** be addressed at the code level.  Companion doc к [`ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md): when the strategy doc marks а row "infrastructure-bound", this is where the actual recommendation lives.

In-process work (obfs4 + tls-boring + QUIC Chrome mimicry + PoW-Rendezvous + DoT/DoH + Caddy-Lets-Encrypt + n-gram regression + kill-switch) closes 19+/35 DPI methods on its own.  The remaining 4 residual gaps are **deployment-shape problems**:

1. **AS-level wholesale blocks** (#22, #23, #27) — а censor blacklists an entire hosting AS, и every node на that AS becomes unreachable.
2. **Federal IP-dictionary + active-probe FakeSNI** (#14) — even с perfect crypto-layer hiding, а node на а publicly-routable IP can be scanned, classified, и added к а wholesale block.
3. **Throughput-shaping classifiers** (#29-31) — bandwidth/quota groupings that bin traffic by data-rate rather than fingerprint.
4. **Auto-update channel hardening** for binary distribution — protecting the update path itself от MITM rewrites.

All four need decisions ON THE DEPLOYMENT SIDE — operator chooses а hosting strategy, а CDN strategy, а traffic-shape policy.  Code can't change these.

## #14 — FakeSNI / IP-dictionary closure

### Threat
DPI maintains an IP-к-domain mapping for every well-known CDN/hosting provider.  When veil's TLS ClientHello carries SNI = `www.cloudflare.com` but the destination IP isn't in Cloudflare's published ranges, the SNI/IP mismatch heuristic fires и flags the connection.

Or worse: the IP itself lands в а federal "VPN/proxy" blocklist after а scanner discovers а responding service.

### Recommendation — CDN domain fronting

**Tier 1 — Cloudflare Workers** (cheapest, lowest setup): operator registers а Cloudflare account (free for hobby use; ~$5/month за Workers с custom domain).

```
   client      DPI sees:                       Cloudflare      veil
     │              │                                │             │
     ├─ TLS к ─────────────────────────────────────► (terminates) │
     │  www.example.workers.dev:443                   │             │
     │  SNI = www.example.workers.dev                 │             │
     │  IP = Cloudflare anycast (≈ 100k+ IPs)         │             │
     │                                                ├──── HTTP ───►
     │                                                │             │  webtunnel
     │                                                │             │  upgrade на
     │                                                │             │  internal port
```

Worker script:
```javascript
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/_t/')) {
      // Proxy WSS upgrade к veil's webtunnel listener.
      const upstream = `wss://${env.VEIL_HOST}:443${url.pathname}`;
      return fetch(upstream, { headers: request.headers });
    }
    // All other paths: serve decoy content (cached от Caddy-fronted host).
    return fetch(`https://${env.VEIL_HOST}/`);
  }
}
```

**Tier 2 — Fastly Compute@Edge** — equivalent capability, different language (Rust / AssemblyScript).  Useful if Cloudflare itself is blocked в the target jurisdiction.

**Tier 3 — Multi-CDN failover**: operator-deploys to 2-3 CDNs (Cloudflare + Fastly + Bunny.net) и publishes а fallback list в the bootstrap bundle.  Censor must block all CDNs к isolate users — high collateral damage cost.

**Trade-offs:**
* Cost: $5-50/month per CDN.
* Performance: extra hop adds ~30-100 ms RTT (worth it under blocking; reverse-proxy bypasses когда direct works).
* Anonymity: Cloudflare sees connection metadata (source-IP, destination veil-host) — operator должен trust Cloudflare's "no logs"-style policies, or compose с veil anonymity circuits.

**Status:** ⬜ infrastructure-side; closes #14 fully when deployed; partial closure of #2 (SNI dict) и #3 (cert CN dict) — CDN cert is real но SNI = CDN domain.

## #22, #23, #27 — AS-level wholesale blocks

### Threat
Russian/Iranian/Chinese DPI infrastructure can blacklist entire hosting ASes (Hetzner AS24940, OVH AS16276, DigitalOcean AS14061, etc.).  Single-host deployments на blocked ASes become permanently unreachable от the target jurisdiction.

### Recommendation — multi-AS hosting

**Minimum viable**: deploy bootstrap/relay nodes на ≥ 3 different ASes.  Diverse AS prefixes ensure а blanket block on one AS doesn't take down the entire deployment.

Suggested ASN diversity matrix (verified non-overlap as of 2026-05):
- **Tier A (commercial cloud)**: AWS (multiple AS), GCP (AS15169), Azure (AS8075)
- **Tier B (mid-tier VPS)**: Hetzner (AS24940 — `b1` currently), OVH (AS16276), DigitalOcean (AS14061)
- **Tier C (specialty)**: BuyVM (AS53667 — Tor/freedom-friendly), 1984.is (Iceland AS44546), FlokiNET (AS200651)

Pick **one from each tier** для minimum diversity.  Bootstrap manifest (`seeds.rs` / HTTPS bootstrap bundle / DNS TXT) carries entries от all three; clients try each on connect-failure cascade.

**Cost:** ~$5-15/month per host × 3 hosts = $15-45/month.

**Trade-offs:**
* Operational complexity: 3x deploy pipelines, 3x cert renewals, 3x monitoring.  Ansible playbook structure (Phase 6.32 multi-host inventory layout) already supports this — see `ansible/inventory.yml`.
* Identity rotation: each host has its own node-identity; loss of one host doesn't bring down the network (existing replication = 3 by default).

**Status:** ⬜ infrastructure-side; closes #22, #23, #27 fully when ≥ 3 ASes deployed.  Code-side mitigation already shipped: anonymity circuits (Epic 482) hide the initiator's source-IP, и PoW-Rendezvous hides the listen surface, so even а single-AS deployment isn't trivially blockable.  Multi-AS is the **belt-and-suspenders** layer.

### Code-side parallel: Tor-bridge fallback (shipped 2026-05-21)

Operator can enable а SOCKS-proxy fallback так that **direct connect failures auto-retry через а Tor bridge** before being marked as а connect-failure.  Default: disabled.  Enable via config:

```toml
[transport]
# Local Tor SOCKS port (install с `apt install tor` or similar).
outbound_socks_fallback_proxy = "socks5://127.0.0.1:9050"
```

When set, the connector's failure path becomes:

```
direct dial → fails
  → NAT-traversal fallback → fails
    → SOCKS fallback (Tor) → tries through proxy → succeeds  ✓
```

Closes #22, #23, #27 **partially** — Tor's exit nodes are в diverse ASes by design, so an AS-block on the operator's outbound IP is bypassed via the proxy hop.  Does **not** replace multi-AS hosting:

* Tor exits themselves can be blocked в high-censorship jurisdictions (Russia's TSPU has Tor entry-node blocks).
* Tor is а published, well-known infrastructure — using it leaks "this user is veil-via-Tor" signal at the entry side.
* Tor connections add 100-300 ms latency.

**Recommended deployment**: enable the SOCKS fallback на client-side hosts that live в hostile-AS jurisdictions; keep direct-only on server/relay hosts (their AS diversity comes от multi-AS deployment).

**Setup steps (Debian/Ubuntu host):**

```bash
sudo apt install tor
sudo systemctl enable --now tor
# Verify Tor is listening on :9050:
sudo ss -tlnp | grep 9050

# Add к /var/lib/veil/node.toml [transport] section:
echo 'outbound_socks_fallback_proxy = "socks5://127.0.0.1:9050"' \
  | sudo tee -a /var/lib/veil/node.toml
sudo systemctl restart veil
```

**Verification:** watch `journalctl -u veil -f` and look for `peer.connect.socks_fallback_success` events when direct dial fails.  Зеро events under normal operation; events appearing correlate с outbound-connect failures — useful diagnostic signal.

## #29-31 — Throughput-shaping / rating-group classifiers

### Threat
Modern DPI (СКАТ DPI 12.0+, OpenIris) classifies traffic into bandwidth-rated buckets — "video streaming" vs "messaging" vs "VPN-shaped".  Sustained ≥ 10 Mbps flows get tagged differently от bursty interactive flows.  Even с perfect-fingerprint mimicry на the byte layer, the **shape** of the flow over time leaks.

### Recommendation — operator-side bandwidth policy

**Option A — accept the shape penalty** (default).  Veil's natural traffic shape — predominantly interactive sessions с occasional larger transfers — already overlaps significantly с the "ordinary HTTPS browsing" rating group on most DPI.  Production observation: no consistent shaping-based blocks observed на the existing testnet under sustained chat load.

**Option B — rate-limit per-flow к the "browsing" envelope**.  Cap veil's per-flow output к 5 Mbps average (with bursts к 20 Mbps).  Implementation: tc/qdisc on Linux:

```bash
# Per-flow token-bucket cap on veil's listen ports.
tc qdisc add dev eth0 root handle 1: htb default 30
tc class add dev eth0 parent 1: classid 1:1 htb rate 5mbit ceil 20mbit
tc filter add dev eth0 parent 1: protocol ip u32 \
   match ip sport 5556 0xffff flowid 1:1
tc filter add dev eth0 parent 1: protocol ip u32 \
   match ip sport 8443 0xffff flowid 1:1
```

**Option C — defer to PoW-Rendezvous + anonymity circuits** for sensitivity-critical traffic.  Stealth listeners + 2-3 hop circuits already prevent а scanner-driven classifier от building а full flow profile (each hop sees only а fragment).  This is the **strongest** but trades latency.

**Trade-offs:**
* Option B reduces user-facing throughput; only worthwhile если а production shaping-block is observed.
* Option C is the right answer для high-sensitivity threat models (citizen-in-RU/CN/IR), но adds 100-300 ms RTT per circuit hop.

**Status:** ⬜ infrastructure-side / operator-policy.  Code-side mitigation (Epic 488 padding + ML-KEM hybrid rekey hiding key-rotation timing) already partially closes — full closure requires operator decision on Options A/B/C.

## #32 — Flow-lifetime fingerprinting

### Threat

Normal HTTPS browser sessions live for seconds к а few minutes, then а fresh TCP+TLS handshake к the next page.  Veil sessions naturally live для hours-to-days — а DPI heuristic flags "this HTTPS-shaped flow has been open continuously for 6+ hours" as а strong VPN/tunnel indicator (observed в TSPU 2024-2025 rulesets, СКАТ DPI 12.x flow-classifier output).  Combined с the throughput-shaping signal (#29-31) the lifetime alone closes the case даже когда per-byte fingerprint is perfect.

### Recommendation — code-side, default-on

**Shipped in code** (commit `644cdf9f`, 2026-05-27, Q.7 audit batch):

* `[transport.rotation]` config section с `min_lifetime_secs` + `max_lifetime_secs` knobs.
* Default range **1800-3600 s** (30 min к 1 hour) — picked к match typical foreground browser-tab HTTPS lifetimes.  Each session draws an independent uniform sample at handshake time, so the rotation cadence has wide entropy across the fleet (defeats per-fleet correlation: "all veil sessions rotate at exactly hour boundaries").
* Set both к `-1` к disable (rotation off, indefinite session lifetime).  Both must be positive OR both `-1` — validation flags mismatched pairs as а likely typo.
* When the deadline fires, the runner attempts **make-before-break** swap via the hot-standby handoff protocol:
  - With а `[[peers]] alt_uri` registered (operator-configured OR auto-discovered via the peer's AttachPayload TLV) → swap onto the alt URI.  True transport diversity (e.g. webtunnel-wss → obfs4-tcp) on top of timer-driven rotation.
  - Без alt_uri → **same-URI rotation**: dial а fresh TCP+TLS connection к the same host:port the session is already on.  From DPI's view: the old flow closes + а new HTTPS handshake (same Chrome ClientHello fingerprint) opens к the same server — indistinguishable от а browser tab closing и а new one opening к the same site.
  - Either way: session keys + AEAD nonce counters + per-peer `SessionTxRegistry` sender are preserved across the swap, so app traffic flows continuously (zero packet loss, zero retransmits at the veil layer).
* Wrapping all of that: there's **no rotation-goodbye protocol frame** — that would itself be а fingerprint.  Rotation looks identical к а natural TCP close + fresh handshake.

**Operator action required:** none for the default policy.  Operators who want longer / shorter ranges (mobile sites with metered cellular cost — wider intervals; high-threat citizen-in-RU/CN/IR — narrower) override в TOML:

```toml
[transport.rotation]
min_lifetime_secs = 600    # 10 min
max_lifetime_secs = 1200   # 20 min
```

`config init` always emits the section с current defaults so operators discover the knob from the file itself.

**Cost:** each rotation costs ~1 fresh TCP+TLS+OVL1 handshake (≈2 KB wire + crypto).  At default 30-60 min cadence that's ≈48 handshakes/day per active session — negligible absolute overhead vs the censor-evasion win.

**Interaction с #29-31:** rotation cuts the long-flow signal; padding (Option B / Epic 488) cuts the throughput-shape signal.  Both work independently и compose.

**Status:** ✅ code-side, default-on.  Operators using the **deprecated** `session.max_age_secs` (single point-value, ±10 % jitter) get а runtime WARN log on daemon start nudging migration к the range knob — both work, но the legacy field doesn't have the fleet-correlation entropy.

## Auto-update channel hardening

### Threat
Even с everything above, the binary distribution channel itself is а MITM target.  If the censor can rewrite the auto-update URL's response к serve а malicious binary, all wire-level work is bypassed at the source.

### Recommendation

**Already shipped in code** (commit `782435f`, 2026-05-09):
* HTTPS bootstrap goes through PKI-verified TLS (Mozilla webpki-roots, не OS trust store) — `connect_pki_verified_https_stream`
* Update fetch routes through the same code path
* Signed-update manifest validated against а pinned operator Ed25519 key in `seeds.rs`

**Operator-side recommendations**:
1. **Update server hosting** — host the update manifest + binaries on the same multi-AS setup as the bootstrap.  А censor blocking the update channel doesn't get а special pass.
2. **Pinned ECH config (когда ECH-opt-in lands)**: when ECH support ships as an opt-in feature, the update endpoint can use ECH с а pre-pinned ECHConfig so update fetches don't leak SNI = `updates.example.com` к the censor.
3. **Out-of-band distribution channel** — for high-sensitivity deployments, pre-package update binaries в а signed `.tar.gz` distributable via Tor / IPFS / encrypted email chains.  Users опционally verify checksums vs а published hash before applying.

**Status:** ⬜ partial (code-side closed); full closure requires operator deployment of multi-AS update servers + (optionally) out-of-band distribution.

## Memory-secrets hygiene (no-swap deployment)

### Threat

HMAC keys, session-AEAD keys, ML-KEM private keys, и identity Ed25519 seeds live в process heap memory.  Three adjacent classes of memory-disclosure risk:

1. **Swap-out** — kernel pages memory к disk under pressure.  An attacker с post-mortem disk access reads stale secrets от the swap file.
2. **Core dumps** — а crash dumps process memory к а file the attacker can later acquire.
3. **Hibernation** — laptop/desktop hibernation writes entire RAM к `swapfile`-like blob; same disclosure vector as #1 но for the whole address space.

`mlock(2)` / `VirtualLock` pins individual allocations in physical RAM (defeats #1 only) — но enforcing it cross-platform (Linux `mlock`, Windows `VirtualLock`, macOS `mlock`, Android RLIMIT_MEMLOCK limits) is expensive build infrastructure that **doesn't** address #2 or #3.

### Recommendation — close the threats at the deployment layer instead

For VPS / server / relay hosts (the bulk of veil deployments):

**1. Disable swap entirely** — closes #1 fully, на all OSes:
```bash
sudo swapoff -a
sudo sed -i '/ swap / s/^/#/' /etc/fstab   # persistent across reboot
free -h                                      # verify "Swap: 0B"
```
Most VPS hosts ship no-swap by default; rented bare-metal often has swap configured — `swapoff -a` + fstab disables it permanently.

**2. Disable core dumps** — closes #2 fully:
```bash
# Kernel-level: do not produce core files at all.
echo 'kernel.core_pattern = |/bin/false' | sudo tee /etc/sysctl.d/50-veil.conf
sudo sysctl --system

# systemd-level (для veil.service unit):
#   [Service]
#   LimitCORE=0
# или поставить prctl(PR_SET_DUMPABLE, 0) внутри veil (process-local; cheaper sweep).
```

**3. Disable hibernation для laptop / desktop relays** — closes #3:
```bash
sudo systemctl mask hibernate.target hybrid-sleep.target suspend-then-hibernate.target
```

**4. Single-uid threat model** — veil daemon runs под dedicated `veil` user в а dedicated host (no shared-tenant containers).  Mlock specifically protects **swap disclosure**, не **same-uid ptrace / `/proc/<pid>/mem`** — those require user-isolation anyway, и user-isolation is а deployment property, not а code property.

### Why not mlock?

* Doesn't address #2 (core dumps) or #3 (hibernation).
* Doesn't address same-uid memory access (`ptrace`, `/proc/<pid>/mem`) — those are user-isolation problems.
* Cross-platform implementation cost (Linux + Windows + macOS + Android RLIMIT_MEMLOCK quirks) outweighs the residual protection on top of swap-off.
* На modern veil deployments (server VPS с no swap, Android zram-only since 5+, iOS no-swap-by-design, embedded routers с no swap для flash wear): the swap-disclosure vector is already closed at the OS layer.

Mlock остаётся an option if а deployment **must** run с swap enabled (rare для veil's threat model).  В that case implement at runtime via `libc::mlock` on Linux / `VirtualLock` on Windows — но first ask why swap is enabled, since the answer is usually "we forgot к disable it" rather than "we genuinely need it".

**Status:** ⬜ operator-side; documented here so deployers know the canonical four-step sweep.  No code-side mlock work planned (would be redundant с swap-off + DUMPABLE=0).

## Composition summary

After applying all four operator-side recommendations:

| Threat surface | Before | After |
|---|---|---|
| #14 FakeSNI heuristic | ⚠️ | ✅ (CDN fronting) |
| #22, #23, #27 AS-level block | 🔴 | ✅ (multi-AS hosting) |
| #29-31 Throughput shaping | ⚠️ | ⚠️ → ✅ (Option B or C) |
| Update channel MITM | ⚠️ | ✅ (multi-AS update servers) |

Combined с the code-side closures (19/35 DPI methods + DPI-regression suite), а fully-hardened deployment closes **all but the AS-priority residuals on а single host** — those residuals shrink к "the operator's AS happens к be on а specific blocklist" which is а one-off rotation problem, not а structural one.

## Acceptance bar

А deployment is "anti-censorship hardened" против VAS-class adversary когда:

* ✅ ≥ 3 ASes for bootstrap + relay nodes
* ✅ Caddy + Let's Encrypt fronting all webtunnel hosts (`deploy-webtunnel-autotls.yml`)
* ✅ PoW-Rendezvous stealth listeners enabled on relay tier (`enable-stealth-canary.yml`)
* ✅ obfs4 + tls-boring + QUIC Chrome mimicry compiled (default; `--no-default-features` disables)
* ✅ DoT/DoH bootstrap (default since 2026-05-20)
* ✅ Transport-rotation default 30-60 min range (default-on since 2026-05-27)
* ⬜ CDN fronting via Cloudflare Worker / Fastly (operator choice; one CDN minimum)
* ⬜ tc/qdisc throughput cap OR documented choice к accept Option A
* ⬜ Update server multi-AS hosting

Once all 9 boxes checked, deployment is ready для citizens of authoritarian states.

## Cost reference (typical 2026 USD prices)

| Item | Tier-1 (cheapest) | Tier-2 (recommended) | Tier-3 (high-availability) |
|---|---|---|---|
| 3× VPS hosting | $15/mo | $45/mo (3× $15) | $150/mo (Diverse-tier mix) |
| 1× CDN account | $0 (Cloudflare free) | $5/mo (Cloudflare Workers) | $50/mo (multi-CDN) |
| 1× domain registration | $10/year | $10/year | $10/year |
| 1× monitoring (uptime checks) | $0 (self-hosted) | $5/mo (Uptime Robot) | $20/mo (Datadog Lite) |
| **Total** | **~$25/mo** | **~$60/mo** | **~$235/mo** |

Tier-2 is the sweet spot для most deployments: meaningful AS diversity + 1 CDN + basic monitoring под $60/month.
