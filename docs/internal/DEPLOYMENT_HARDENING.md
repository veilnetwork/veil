# Deployment hardening — anti-censorship operator guide

Operator-side recommendations for the censorship gaps that code alone **cannot** close. (DPI — deep packet inspection — is the censor reading packet contents, not just headers.) This is the companion to [`ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md): when the strategy doc marks a row "infrastructure-bound", the concrete recommendation lives here.

In-process work (obfs4 + tls-boring + QUIC Chrome mimicry + PoW-Rendezvous + DoT/DoH + Caddy-Lets-Encrypt + n-gram regression + kill-switch) closes 19+/35 DPI methods on its own.  The remaining 4 residual gaps are **deployment-shape problems**:

1. **AS-level wholesale blocks** (#22, #23, #27) — a censor blacklists an entire hosting AS, and every node on that AS becomes unreachable.
2. **Federal IP-dictionary + active-probe FakeSNI** (#14) — even with perfect crypto-layer hiding, a node on a publicly-routable IP can be scanned, classified, and added to a wholesale block.
3. **Throughput-shaping classifiers** (#29-31) — bandwidth/quota groupings that bin traffic by data-rate rather than fingerprint.
4. **Auto-update channel hardening** for binary distribution — protecting the update path itself from MITM rewrites.

All four are decisions made ON THE DEPLOYMENT SIDE. The operator picks a hosting strategy, a CDN strategy, and a traffic-shape policy. Code can't make those calls.

## #14 — FakeSNI / IP-dictionary closure

### Threat
DPI keeps an IP-to-domain map for every well-known CDN and hosting provider. So when veil's TLS ClientHello claims SNI = `www.cloudflare.com` but the destination IP isn't in Cloudflare's published ranges, the SNI/IP mismatch heuristic fires and flags the connection. (SNI, the server name indication, is the hostname a client sends in the clear at the start of a TLS handshake.)

Worse still: the IP itself can land in a federal "VPN/proxy" blocklist once a scanner finds a service answering on it.

### Recommendation — CDN domain fronting

**Tier 1 — Cloudflare Workers** (cheapest, lowest setup): the operator registers a Cloudflare account (free for hobby use; ~$5/month for Workers with a custom domain).

```
   client      DPI sees:                       Cloudflare        veil
     │                                               │             │
     ├─ TLS to ──────────────────────────────────────► (terminates)│
     │  www.example.workers.dev:443                  │             │
     │  SNI = www.example.workers.dev                │             │
     │  IP = Cloudflare anycast (≈ 100k+ IPs)        │             │
     │                                               ├────HTTP─────►
     │                                               │             │  webtunnel
     │                                               │             │  upgrade to
     │                                               │             │  internal port
```

Worker script:
```javascript
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/_t/')) {
      // Proxy WSS upgrade to veil's webtunnel listener.
      const upstream = `wss://${env.VEIL_HOST}:443${url.pathname}`;
      return fetch(upstream, { headers: request.headers });
    }
    // All other paths: serve decoy content (cached from Caddy-fronted host).
    return fetch(`https://${env.VEIL_HOST}/`);
  }
}
```

**Tier 2 — Fastly Compute@Edge** — equivalent capability, different language (Rust / AssemblyScript).  Useful if Cloudflare itself is blocked in the target jurisdiction.

**Tier 3 — Multi-CDN failover**: operator-deploys to 2-3 CDNs (Cloudflare + Fastly + Bunny.net) and publishes a fallback list in the bootstrap bundle.  A censor must block all CDNs to isolate users — high collateral damage cost.

**Trade-offs:**
* Cost: $5-50/month per CDN.
* Performance: extra hop adds ~30-100 ms RTT (worth it under blocking; reverse-proxy is bypassed when direct works).
* Anonymity: Cloudflare sees connection metadata (source-IP, destination veil-host) — the operator must trust Cloudflare's "no logs"-style policies, or compose with veil anonymity circuits.

**Status:** ⬜ infrastructure-side; closes #14 fully when deployed; partial closure of #2 (SNI dict) and #3 (cert CN dict) — CDN cert is real but SNI = CDN domain.

## #22, #23, #27 — AS-level wholesale blocks

### Threat
Russian, Iranian, and Chinese DPI infrastructure can blacklist a whole hosting AS at once (Hetzner AS24940, OVH AS16276, DigitalOcean AS14061, and so on). An AS — autonomous system — is one provider's block of IP space. A single-host deployment on a blocked AS goes permanently dark from the target jurisdiction.

### Recommendation — multi-AS hosting

**Minimum viable**: deploy bootstrap/relay nodes on ≥ 3 different ASes.  Diverse AS prefixes ensure a blanket block on one AS doesn't take down the entire deployment.

Suggested ASN diversity matrix (verified non-overlap as of 2026-05):
- **Tier A (commercial cloud)**: AWS (multiple AS), GCP (AS15169), Azure (AS8075)
- **Tier B (mid-tier VPS)**: Hetzner (AS24940 — `b1` currently), OVH (AS16276), DigitalOcean (AS14061)
- **Tier C (specialty)**: BuyVM (AS53667 — Tor/freedom-friendly), 1984.is (Iceland AS44546), FlokiNET (AS200651)

Pick **one from each tier** for minimum diversity.  The bootstrap manifest (`seeds.rs` / HTTPS bootstrap bundle / DNS TXT) carries entries from all three; clients try each on a connect-failure cascade.

**Cost:** ~$5-15/month per host × 3 hosts = $15-45/month.

**Trade-offs:**
* Operational complexity: 3x deploy pipelines, 3x cert renewals, 3x monitoring.  Ansible playbook structure (Phase 6.32 multi-host inventory layout) already supports this — see `ansible/inventory.yml`.
* Identity rotation: each host has its own node-identity; loss of one host doesn't bring down the network (existing replication = 3 by default).

**Status:** ⬜ infrastructure-side; closes #22, #23, #27 fully when ≥ 3 ASes deployed.  Code-side mitigation already shipped: anonymity circuits (Epic 482) hide the initiator's source-IP, and PoW-Rendezvous hides the listen surface, so even a single-AS deployment isn't trivially blockable.  Multi-AS is the **belt-and-suspenders** layer.

### Code-side parallel: Tor-bridge fallback (shipped 2026-05-21)

The operator can enable a SOCKS-proxy fallback so that **direct connect failures auto-retry through a Tor bridge** before being marked as a connect-failure.  Default: disabled.  Enable via config:

```toml
[transport]
# Local Tor SOCKS port (install with `apt install tor` or similar).
outbound_socks_fallback_proxy = "socks5://127.0.0.1:9050"
```

When set, the connector's failure path becomes:

```
direct dial → fails
  → NAT-traversal fallback → fails
    → SOCKS fallback (Tor) → tries through proxy → succeeds  ✓
```

Closes #22, #23, #27 **partially** — Tor's exit nodes are in diverse ASes by design, so an AS-block on the operator's outbound IP is bypassed via the proxy hop.  Does **not** replace multi-AS hosting:

* Tor exits themselves can be blocked in high-censorship jurisdictions (Russia's TSPU has Tor entry-node blocks).
* Tor is a published, well-known infrastructure — using it leaks a "this user is veil-via-Tor" signal at the entry side.
* Tor connections add 100-300 ms latency.

**Recommended deployment**: enable the SOCKS fallback on client-side hosts that live in hostile-AS jurisdictions; keep direct-only on server/relay hosts (their AS diversity comes from multi-AS deployment).

**Setup steps (Debian/Ubuntu host):**

```bash
sudo apt install tor
sudo systemctl enable --now tor
# Verify Tor is listening on :9050:
sudo ss -tlnp | grep 9050

# Add to /var/lib/veil/node.toml [transport] section:
echo 'outbound_socks_fallback_proxy = "socks5://127.0.0.1:9050"' \
  | sudo tee -a /var/lib/veil/node.toml
sudo systemctl restart veil
```

**Verification:** watch `journalctl -u veil -f` and look for `peer.connect.socks_fallback_success` events when direct dial fails.  Zero events under normal operation; events appearing correlate with outbound-connect failures — a useful diagnostic signal.

## #29-31 — Throughput-shaping / rating-group classifiers

### Threat
Modern DPI (SKAT DPI 12.0+, OpenIris) sorts traffic into bandwidth-rated buckets — "video streaming" vs "messaging" vs "VPN-shaped". A sustained ≥ 10 Mbps flow gets tagged differently from a bursty interactive one. So even with perfect byte-level fingerprint mimicry, the **shape** of the flow over time still leaks.

### Recommendation — operator-side bandwidth policy

**Option A — accept the shape penalty** (default).  Veil's natural traffic shape — predominantly interactive sessions with occasional larger transfers — already overlaps significantly with the "ordinary HTTPS browsing" rating group on most DPI.  Production observation: no consistent shaping-based blocks observed on the existing testnet under sustained chat load.

**Option B — rate-limit per-flow to the "browsing" envelope**.  Cap veil's per-flow output to 5 Mbps average (with bursts to 20 Mbps).  Implementation: tc/qdisc on Linux:

```bash
# Per-flow token-bucket cap on veil's listen ports.
tc qdisc add dev eth0 root handle 1: htb default 30
tc class add dev eth0 parent 1: classid 1:1 htb rate 5mbit ceil 20mbit
tc filter add dev eth0 parent 1: protocol ip u32 \
   match ip sport 5556 0xffff flowid 1:1
tc filter add dev eth0 parent 1: protocol ip u32 \
   match ip sport 8443 0xffff flowid 1:1
```

**Option C — defer to PoW-Rendezvous + anonymity circuits** for sensitivity-critical traffic.  Stealth listeners + 2-3 hop circuits already prevent a scanner-driven classifier from building a full flow profile (each hop sees only a fragment).  This is the **strongest** but trades latency.

**Trade-offs:**
* Option B reduces user-facing throughput; only worthwhile if a production shaping-block is observed.
* Option C is the right answer for high-sensitivity threat models (citizen-in-RU/CN/IR), but adds 100-300 ms RTT per circuit hop.

**Status:** ⬜ infrastructure-side / operator-policy.  Code-side mitigation (Epic 488 padding + ML-KEM hybrid rekey hiding key-rotation timing) already partially closes — full closure requires an operator decision on Options A/B/C.

## #32 — Flow-lifetime fingerprinting

### Threat

A normal HTTPS browser session lives for seconds to a few minutes, then opens a fresh TCP+TLS handshake to the next page. Veil sessions, by contrast, naturally stay up for hours or days. A DPI heuristic reads "this HTTPS-shaped flow has been open continuously for 6+ hours" as a strong VPN/tunnel tell (observed in TSPU 2024-2025 rulesets and SKAT DPI 12.x flow-classifier output). Pair that with the throughput-shaping signal (#29-31) and the lifetime alone gives the censor a case — even when the per-byte fingerprint is perfect.

### Recommendation — code-side, default-on

**Shipped in code** (commit `644cdf9f`, 2026-05-27, Q.7 audit batch):

* `[transport.rotation]` config section with `min_lifetime_secs` + `max_lifetime_secs` knobs.
* Default range **1800-3600 s** (30 min to 1 hour) — picked to match typical foreground browser-tab HTTPS lifetimes.  Each session draws an independent uniform sample at handshake time, so the rotation cadence has wide entropy across the fleet (defeats per-fleet correlation: "all veil sessions rotate at exactly hour boundaries").
* Set both to `-1` to disable (rotation off, indefinite session lifetime).  Both must be positive OR both `-1` — validation flags mismatched pairs as a likely typo.
* When the deadline fires, the runner attempts a **make-before-break** swap via the hot-standby handoff protocol:
  - With a `[[peers]] alt_uri` registered (operator-configured OR auto-discovered via the peer's AttachPayload TLV) → swap onto the alt URI.  True transport diversity (e.g. webtunnel-wss → obfs4-tcp) on top of timer-driven rotation.
  - Without an alt_uri → **same-URI rotation**: dial a fresh TCP+TLS connection to the same host:port the session is already on.  From DPI's view: the old flow closes + a new HTTPS handshake (same Chrome ClientHello fingerprint) opens to the same server — indistinguishable from a browser tab closing and a new one opening to the same site.
  - Either way: session keys + AEAD nonce counters + per-peer `SessionTxRegistry` sender are preserved across the swap, so app traffic flows continuously (zero packet loss, zero retransmits at the veil layer).
* Wrapping all of that: there's **no rotation-goodbye protocol frame** — that would itself be a fingerprint.  Rotation looks identical to a natural TCP close + fresh handshake.

**Operator action required:** none for the default policy.  Operators who want longer / shorter ranges (mobile sites with metered cellular cost — wider intervals; high-threat citizen-in-RU/CN/IR — narrower) override in TOML:

```toml
[transport.rotation]
min_lifetime_secs = 600    # 10 min
max_lifetime_secs = 1200   # 20 min
```

`config init` always emits the section with current defaults so operators discover the knob from the file itself.

**Cost:** each rotation costs ~1 fresh TCP+TLS+OVL1 handshake (≈2 KB wire + crypto).  At default 30-60 min cadence that's ≈48 handshakes/day per active session — negligible absolute overhead vs the censor-evasion win.

**Interaction with #29-31:** rotation cuts the long-flow signal; padding (Option B / Epic 488) cuts the throughput-shape signal.  Both work independently and compose.

**Status:** ✅ code-side, default-on.  Operators using the **deprecated** `session.max_age_secs` (single point-value, ±10 % jitter) get a runtime WARN log on daemon start nudging migration to the range knob — both work, but the legacy field doesn't have the fleet-correlation entropy.

## Auto-update channel hardening

### Threat
Even with everything above in place, the binary distribution channel itself is a MITM target. (MITM — man in the middle — is an attacker who sits on the path and tampers with traffic.) If the censor can rewrite the auto-update URL's response to serve a malicious binary, every wire-level defense is bypassed at the source.

### Recommendation

**Already shipped in code** (commit `782435f`, 2026-05-09):
* HTTPS bootstrap goes through PKI-verified TLS (Mozilla webpki-roots, not the OS trust store) — `connect_pki_verified_https_stream`
* Update fetch routes through the same code path
* Signed-update manifest validated against a pinned operator Ed25519 key in `seeds.rs`

**Operator-side recommendations**:
1. **Update server hosting** — host the update manifest + binaries on the same multi-AS setup as the bootstrap.  A censor blocking the update channel doesn't get a special pass.
2. **Pinned ECH config (once ECH-opt-in lands)**: when ECH support ships as an opt-in feature, the update endpoint can use ECH with a pre-pinned ECHConfig so update fetches don't leak SNI = `updates.example.com` to the censor.
3. **Out-of-band distribution channel** — for high-sensitivity deployments, pre-package update binaries in a signed `.tar.gz` distributable via Tor / IPFS / encrypted email chains.  Users optionally verify checksums vs a published hash before applying.

**Status:** ⬜ partial (code-side closed); full closure requires operator deployment of multi-AS update servers + (optionally) out-of-band distribution.

## Memory-secrets hygiene (no-swap deployment)

### Threat

HMAC keys, session-AEAD keys, ML-KEM private keys, and identity Ed25519 seeds all live in process heap memory. That exposes three related ways for secrets to leak to disk:

1. **Swap-out.** Under memory pressure, the kernel pages memory to disk. An attacker with post-mortem disk access reads stale secrets from the swap file.
2. **Core dumps.** A crash writes process memory to a file the attacker can grab later.
3. **Hibernation.** Laptop or desktop hibernation writes all of RAM to a `swapfile`-like blob — the same leak as #1, but for the entire address space.

`mlock(2)` / `VirtualLock` pins individual allocations in physical RAM, which defeats #1 only. Enforcing it across platforms (Linux `mlock`, Windows `VirtualLock`, macOS `mlock`, Android RLIMIT_MEMLOCK limits) is expensive build infrastructure that still **doesn't** touch #2 or #3.

### Recommendation — close the threats at the deployment layer instead

For VPS / server / relay hosts (the bulk of veil deployments):

**1. Disable swap entirely** — closes #1 fully, on all OSes:
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

# systemd-level (for the veil.service unit):
#   [Service]
#   LimitCORE=0
# or set prctl(PR_SET_DUMPABLE, 0) inside veil (process-local; cheaper sweep).
```

**3. Disable hibernation for laptop / desktop relays** — closes #3:
```bash
sudo systemctl mask hibernate.target hybrid-sleep.target suspend-then-hibernate.target
```

**4. Single-uid threat model** — the veil daemon runs under a dedicated `veil` user on a dedicated host (no shared-tenant containers).  Mlock specifically protects against **swap disclosure**, not **same-uid ptrace / `/proc/<pid>/mem`** — those require user-isolation anyway, and user-isolation is a deployment property, not a code property.

### Why not mlock?

* Doesn't address #2 (core dumps) or #3 (hibernation).
* Doesn't address same-uid memory access (`ptrace`, `/proc/<pid>/mem`) — those are user-isolation problems.
* Cross-platform implementation cost (Linux + Windows + macOS + Android RLIMIT_MEMLOCK quirks) outweighs the residual protection on top of swap-off.
* On modern veil deployments (server VPS with no swap, Android zram-only since 5+, iOS no-swap-by-design, embedded routers with no swap for flash wear): the swap-disclosure vector is already closed at the OS layer.

Mlock remains an option if a deployment **must** run with swap enabled (rare for veil's threat model).  In that case implement at runtime via `libc::mlock` on Linux / `VirtualLock` on Windows — but first ask why swap is enabled, since the answer is usually "we forgot to disable it" rather than "we genuinely need it".

**Status:** ⬜ operator-side; documented here so deployers know the canonical four-step sweep.  No code-side mlock work planned (would be redundant with swap-off + DUMPABLE=0).

## Composition summary

After applying all four operator-side recommendations:

| Threat surface | Before | After |
|---|---|---|
| #14 FakeSNI heuristic | ⚠️ | ✅ (CDN fronting) |
| #22, #23, #27 AS-level block | 🔴 | ✅ (multi-AS hosting) |
| #29-31 Throughput shaping | ⚠️ | ⚠️ → ✅ (Option B or C) |
| Update channel MITM | ⚠️ | ✅ (multi-AS update servers) |

Combined with the code-side closures (19/35 DPI methods + DPI-regression suite), a fully-hardened deployment closes **all but the AS-priority residuals on a single host** — those residuals shrink to "the operator's AS happens to be on a specific blocklist", which is a one-off rotation problem, not a structural one.

## Acceptance bar

A deployment is "anti-censorship hardened" against a VAS-class adversary when:

* ✅ ≥ 3 ASes for bootstrap + relay nodes
* ✅ Caddy + Let's Encrypt fronting all webtunnel hosts (`deploy-webtunnel-autotls.yml`)
* ✅ PoW-Rendezvous stealth listeners enabled on relay tier (`enable-stealth-canary.yml`)
* ✅ obfs4 + tls-boring + QUIC Chrome mimicry compiled (default; `--no-default-features` disables)
* ✅ DoT/DoH bootstrap (default since 2026-05-20)
* ✅ Transport-rotation default 30-60 min range (default-on since 2026-05-27)
* ⬜ CDN fronting via Cloudflare Worker / Fastly (operator choice; one CDN minimum)
* ⬜ tc/qdisc throughput cap OR documented choice to accept Option A
* ⬜ Update server multi-AS hosting

Once all 9 boxes are checked, the deployment is ready for citizens of authoritarian states.

## Cost reference (typical 2026 USD prices)

| Item | Tier-1 (cheapest) | Tier-2 (recommended) | Tier-3 (high-availability) |
|---|---|---|---|
| 3× VPS hosting | $15/mo | $45/mo (3× $15) | $150/mo (Diverse-tier mix) |
| 1× CDN account | $0 (Cloudflare free) | $5/mo (Cloudflare Workers) | $50/mo (multi-CDN) |
| 1× domain registration | $10/year | $10/year | $10/year |
| 1× monitoring (uptime checks) | $0 (self-hosted) | $5/mo (Uptime Robot) | $20/mo (Datadog Lite) |
| **Total** | **~$25/mo** | **~$60/mo** | **~$235/mo** |

Tier-2 is the sweet spot for most deployments: meaningful AS diversity + 1 CDN + basic monitoring under $60/month.
