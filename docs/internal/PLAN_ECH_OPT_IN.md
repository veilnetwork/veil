# ECH (Encrypted Client Hello) — opt-in design

> **Status (2026-06):** the activation prerequisites have largely **shipped** —
> the TLS crypto provider is now `aws-lc-rs` (`crates/veil-transport/src/tls.rs`)
> and client-side ECH is wired (GREASE always-on + real ECH via DNS HTTPS-RR
> lookup, `crates/veil-transport/src/ech_dns.rs::query_https_ech`). **Not yet
> done:** an operator `[transport]` config schema (`ech_enabled` /
> `ech_config_list_file`) and the startup WARN log — ECH is currently hard-wired
> (GREASE + auto-detect), not config-gated. Server-side ECH stays out of scope
> (rustls API). Treat the design below as rationale, not pending work.

Anti-censorship strategy P0-followup — closes DPI method #14 (FakeSNI heuristic) **without** requiring CDN domain fronting.

## Why opt-in, not default

ECH ClientHello is а strong signal к DPI in 2026:

* Adoption is rising (Cloudflare ECH'd ~30% of HTTPS by Q1 2026, Apple/Mozilla shipped client support в 2024-2025) but still а minority of total HTTPS traffic.
* А DPI classifier que sees ECH-marked ClientHello flags the connection как "encrypted-SNI traffic" — distinct category от ordinary HTTPS.
* For deployments в jurisdictions где ECH-marked traffic is itself а target (Russia's TSPU has shipped ECH-blocking rules), enabling ECH may **worsen** the censorship profile rather than improve it.

**Conclusion:** ship ECH as an opt-in feature, default OFF, с clear operator-facing warning что enabling в hostile-DPI environments may degrade censorship resistance.

## Activation prerequisites

When/if ECH activation is triggered:

### 1. rustls crypto provider swap: ring → aws_lc_rs

The `rustls 0.23` ECH API requires HPKE primitives, и those live in the `aws_lc_rs` feature path только (Ring lacks HPKE in rustls 0.23 — checked 2026-05-21).  Activation steps:

* `crates/veil-transport/Cargo.toml`: swap `rustls = { features = ["ring"] }` → `rustls = { features = ["aws_lc_rs"] }` (или dual-feature `["ring", "aws_lc_rs"]` если ring is needed для legacy paths).
* `quinn = { features = ["runtime-tokio", "rustls-ring"] }` → `"rustls-aws-lc-rs"` matching.
* Binary size impact: ~5-7 MB increase от aws-lc-rs C library bundle.  Acceptable but visible in CI artifact sizes.
* Test matrix expansion: all TLS / QUIC unit tests run против the new crypto provider — surface bugs где behaviour differs.

### 2. Server-side ECH support: Caddy 2.10+ in front

rustls 0.23 server-side ECH support is **not exposed** via the high-level `ServerConfig` API; implementing it requires hand-rolled HPKE-decrypt + ClientHello-reassembly.  Out of scope.

Recommended path: deploy Caddy 2.10+ в front of veil's TLS listener (extends the existing `deploy-webtunnel-autotls.yml` pattern):

```caddy
{{ veil_host }} {
    # ... existing webtunnel reverse_proxy ...

    tls {
        # ECH (requires Caddy 2.10.0+).
        ech /etc/caddy/ech-key.pem
    }
}
```

ECH config + private key generation:

```bash
# Generate а HPKE keypair (Caddy 2.10+ ships а helper command).
caddy ech generate-key > /etc/caddy/ech-key.pem
caddy ech show-public-config /etc/caddy/ech-key.pem > /tmp/ech-config.bin

# Base64-encode the public config for the DNS HTTPS RR record.
base64 -w 0 /tmp/ech-config.bin
```

### 3. DNS HTTPS RR record publication

The operator publishes the ECH public config in а DNS `HTTPS` resource record (RFC 9460) for the veil host:

```dns
veil.example.  IN HTTPS  1 . alpn="h2" ech="AEAAAH..."
                                                 ^^^^^^^^
                                          base64-encoded ECH config
```

Most DNS providers (Cloudflare, Route53, deSEC) support HTTPS RR як of 2025-2026.  Rotation: re-run `caddy ech generate-key` quarterly, update the HTTPS record, leave the old key valid для ~24h overlap.

### 4. Client-side rustls wire-up

In `crates/veil-transport/src/tls.rs` (and parallel sites в `context.rs`):

```rust
use rustls::client::{EchConfig, EchMode};
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;

// При построении ClientConfig:
let ech_mode = if let Some(ech_bytes) = ctx.ech_config_list_bytes.as_ref() {
    let ech = EchConfig::new(ech_bytes.as_slice().into(), ALL_SUPPORTED_SUITES)
        .map_err(|e| TransportError::Tls(format!("ECH config invalid: {e}")))?;
    Some(EchMode::Enable(ech))
} else {
    None
};

let builder = ClientConfig::builder();
let builder = if let Some(mode) = ech_mode {
    builder.with_ech(mode)?
} else {
    builder.with_protocol_versions(&[&rustls::version::TLS13][..])?
};
let config = builder.with_root_certificates(roots).with_no_client_auth();
```

`with_ech` pins TLS 1.3 only (ECH requires it).  Existing TLS 1.2 fallback paths must continue к work для non-ECH connections.

### 5. Operator config schema

Add к `Config::transport`:

```toml
[transport]
ech_enabled = false             # default — opt-in only
ech_config_list_file = "/etc/veil/ech-config.bin"  # operator-supplied
```

Where the file contains the raw ECH config list bytes (matches what Caddy emits).  When `ech_enabled = true` but the file is missing или unparseable, daemon fails-fast at startup с а clear error.

### 6. Runtime warning

When ECH is enabled, log а WARN-level message at startup:

```
ech.enabled  warning="ECH is enabled — verify your target jurisdiction's DPI does NOT actively block ECH ClientHellos. See docs/internal/PLAN_ECH_OPT_IN.md for rationale."
```

## Activation triggers

Open the ECH-activation epic and start the prerequisite swap when ANY of:

1. **CDN-fronting unavailable**: operator deploys в а jurisdiction где Cloudflare / Fastly / Bunny.net are blocked, и multi-CDN failover is infeasible.  ECH becomes the most-realistic SNI-hiding option.
2. **ECH adoption rate ≥ 50%**: ECH ClientHello becomes statistically ordinary rather than а minority signal.  Track Cloudflare's published ECH stats; their public dashboard exceeds 50% sustained → trigger.
3. **Specific deployment request**: operator с а high-sensitivity threat model explicitly requests ECH support (e.g., dissident-network with а dedicated security review).

Until one of these fires, **DEPLOYMENT_HARDENING.md's CDN-fronting recommendation is the preferred answer to #14**.  CDN fronting closes #14 без code changes, без crypto-provider swap, без adoption-rate risk.

## Estimated scope (when activation triggered)

| Slice | LoC | Sessions |
|---|---|---|
| Crypto provider swap (ring → aws_lc_rs) | ~50 LoC + test surface re-validation | 1 |
| Config schema + ECH wire-up в TLS / QUIC | ~250 LoC | 1 |
| Caddy 2.10+ playbook (`deploy-webtunnel-autotls-ech.yml`) + cert tooling | ~150 LoC ops + docs | 0.5 |
| Cross-host integration test (live ECH handshake) | ~200 LoC | 0.5-1 |
| **Total** | **~650 LoC** | **3 sessions** |

Plus the test-matrix work for the crypto-provider swap (could expand significantly если behaviour differences surface — track separately).

## Composition с current anti-censorship layers

| Closes | Layer | Status |
|---|---|---|
| #14 без CDN | ECH | 🧊 design landing-pad (this doc) |
| #14 с CDN | CDN fronting | ⬜ operator-side ([`DEPLOYMENT_HARDENING.md`](DEPLOYMENT_HARDENING.md)) |
| #2, #3, #5 | tls-boring Chrome ClientHello | ✅ shipped (Epic 488) |
| #14 partial | Caddy + Let's Encrypt fronting | ✅ shipped (P1 #3) |

ECH и CDN-fronting are **alternatives**, не complements — operator picks whichever fits their threat model (CDN fronting = adopted broadly, ECH = more direct но requires DPI tolerance).

See [`docs/internal/ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md) для the full DPI threat-model + roadmap.
