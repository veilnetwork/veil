# ECH (Encrypted Client Hello) — opt-in design

> **Status (2026-06):** the activation prerequisites have largely **shipped** —
> the TLS crypto provider is now `aws-lc-rs` (`crates/veil-transport/src/tls.rs`)
> and client-side ECH is wired (GREASE + real ECH via DNS HTTPS-RR lookup,
> `crates/veil-transport/src/ech_dns.rs::query_https_ech`). It is gated by ONE
> coarse toggle, `[global] tls_ech_grease` (**default `true`** — GREASE on out
> of the box; set `false` to disable). **Not yet done:** a finer operator
> `[transport]` ECH schema (`ech_enabled` / `ech_config_list_file` for an
> explicit ECHConfigList + per-endpoint control) and the startup WARN log.
> Server-side ECH stays out of scope (rustls API). Treat the design below as
> rationale, not pending work.

Anti-censorship strategy P0-followup. This closes DPI method #14 (the FakeSNI heuristic) **without** requiring CDN domain fronting. ECH means Encrypted Client Hello: it hides the SNI — the website name your client normally sends in the clear during a TLS handshake — so a censor can't read which site you're reaching.

## Why opt-in, not default

To a DPI box in 2026, an ECH ClientHello is itself a strong signal:

* Adoption is rising — Cloudflare ECH'd about 30% of HTTPS by Q1 2026, and Apple and Mozilla shipped client support in 2024-2025 — but it is still a minority of total HTTPS traffic.
* A DPI classifier that sees an ECH-marked ClientHello flags the connection as "encrypted-SNI traffic," a distinct category from ordinary HTTPS.
* In jurisdictions where ECH-marked traffic is itself a target — Russia's TSPU has shipped ECH-blocking rules — enabling ECH may **worsen** your censorship profile rather than improve it.

**Conclusion:** ship ECH as an opt-in feature, default OFF, with a clear operator-facing warning that turning it on in a hostile-DPI environment can degrade censorship resistance.

## Activation prerequisites

When/if ECH activation is triggered:

### 1. rustls crypto provider swap: ring → aws_lc_rs

The `rustls 0.23` ECH API needs HPKE primitives. (HPKE is Hybrid Public Key Encryption, the scheme ECH uses to seal the ClientHello.) Those primitives live only in the `aws_lc_rs` feature path — Ring lacks HPKE in rustls 0.23, checked 2026-05-21. Activation steps:

* `crates/veil-transport/Cargo.toml`: swap `rustls = { features = ["ring"] }` for `rustls = { features = ["aws_lc_rs"] }`. Use the dual feature `["ring", "aws_lc_rs"]` if ring is still needed for legacy paths.
* Match it on the QUIC side: `quinn = { features = ["runtime-tokio", "rustls-ring"] }` becomes `"rustls-aws-lc-rs"`.
* Binary size goes up by roughly 5-7 MB from the aws-lc-rs C library bundle. Acceptable, but it will show in CI artifact sizes.
* The test matrix grows: every TLS and QUIC unit test reruns against the new crypto provider, which surfaces any bug where behaviour differs.

### 2. Server-side ECH support: Caddy 2.10+ in front

The high-level `ServerConfig` API in rustls 0.23 does **not** expose server-side ECH. Implementing it by hand would mean rolling your own HPKE-decrypt plus ClientHello reassembly. Out of scope.

The recommended path is to put Caddy 2.10+ in front of veil's TLS listener. (Caddy is a web server that can terminate TLS and serve as a reverse proxy.) This extends the existing `deploy-webtunnel-autotls.yml` pattern:

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
# Generate a HPKE keypair (Caddy 2.10+ ships a helper command).
caddy ech generate-key > /etc/caddy/ech-key.pem
caddy ech show-public-config /etc/caddy/ech-key.pem > /tmp/ech-config.bin

# Base64-encode the public config for the DNS HTTPS RR record.
base64 -w 0 /tmp/ech-config.bin
```

### 3. DNS HTTPS RR record publication

The operator publishes the ECH public config in a DNS `HTTPS` resource record (RFC 9460) for the veil host:

```dns
veil.example.  IN HTTPS  1 . alpn="h2" ech="AEAAAH..."
                                                 ^^^^^^^^
                                          base64-encoded ECH config
```

Most DNS providers — Cloudflare, Route53, deSEC — support HTTPS RR as of 2025-2026. To rotate: re-run `caddy ech generate-key` quarterly, update the HTTPS record, and leave the old key valid for a ~24h overlap.

### 4. Client-side rustls wire-up

In `crates/veil-transport/src/tls.rs` (and the parallel sites in `context.rs`):

```rust
use rustls::client::{EchConfig, EchMode};
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;

// When building the ClientConfig:
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

`with_ech` pins TLS 1.3 only, because ECH requires it. The existing TLS 1.2 fallback paths must keep working for non-ECH connections.

### 5. Operator config schema

Add to `Config::transport`:

```toml
[transport]
ech_enabled = false             # default — opt-in only
ech_config_list_file = "/etc/veil/ech-config.bin"  # operator-supplied
```

The file holds the raw ECH config list bytes — the same thing Caddy emits. When `ech_enabled = true` but the file is missing or unparseable, the daemon fails fast at startup with a clear error.

### 6. Runtime warning

When ECH is enabled, log a WARN-level message at startup:

```
ech.enabled  warning="ECH is enabled — verify your target jurisdiction's DPI does NOT actively block ECH ClientHellos. See docs/internal/PLAN_ECH_OPT_IN.md for rationale."
```

## Activation triggers

Open the ECH-activation epic and start the prerequisite swap when ANY of:

1. **CDN-fronting unavailable.** The operator deploys in a jurisdiction where Cloudflare, Fastly, and Bunny.net are blocked, and multi-CDN failover is infeasible. ECH then becomes the most realistic way to hide the SNI.
2. **ECH adoption rate ≥ 50%.** The ECH ClientHello becomes statistically ordinary rather than a minority signal. Track Cloudflare's published ECH stats; once their public dashboard holds above 50%, trigger.
3. **Specific deployment request.** An operator with a high-sensitivity threat model explicitly asks for ECH support — for example, a dissident network with a dedicated security review.

Until one of these fires, **the CDN-fronting recommendation in DEPLOYMENT_HARDENING.md is the preferred answer to #14**. CDN fronting closes #14 with no code changes, no crypto-provider swap, and no adoption-rate risk.

## Estimated scope (when activation triggered)

| Slice | LoC | Sessions |
|---|---|---|
| Crypto provider swap (ring → aws_lc_rs) | ~50 LoC + test surface re-validation | 1 |
| Config schema + ECH wire-up in TLS / QUIC | ~250 LoC | 1 |
| Caddy 2.10+ playbook (`deploy-webtunnel-autotls-ech.yml`) + cert tooling | ~150 LoC ops + docs | 0.5 |
| Cross-host integration test (live ECH handshake) | ~200 LoC | 0.5-1 |
| **Total** | **~650 LoC** | **3 sessions** |

Plus the test-matrix work for the crypto-provider swap. That could expand significantly if behaviour differences surface, so track it separately.

## How this composes with current anti-censorship layers

| Closes | Layer | Status |
|---|---|---|
| #14 without CDN | ECH | 🧊 design landing-pad (this doc) |
| #14 with CDN | CDN fronting | ⬜ operator-side ([`DEPLOYMENT_HARDENING.md`](DEPLOYMENT_HARDENING.md)) |
| #2, #3, #5 | tls-boring Chrome ClientHello | ✅ shipped (Epic 488) |
| #14 partial | Caddy + Let's Encrypt fronting | ✅ shipped (P1 #3) |

ECH and CDN-fronting are **alternatives**, not complements. The operator picks whichever fits their threat model: CDN fronting is broadly adopted, while ECH is more direct but requires the local DPI to tolerate it.

See [`docs/internal/ANTICENSORSHIP_STRATEGY.md`](ANTICENSORSHIP_STRATEGY.md) for the full DPI threat model and roadmap.
