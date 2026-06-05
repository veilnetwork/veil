# Deploying veil for censorship-resistant use

> **Audience:** operators running a node in (or for users in) a
> jurisdiction with state-level DPI / IP-blocking of veil-style
> protocols.
>
> **Prerequisites:** you've worked through [`OPERATIONS.md`](../en/OPERATIONS.md)
> and have a node that runs in dev mode.  This doc layers
> censorship-resistance posture on top.
>
> **Related:** [DPI evasion architecture](dpi-evasion.md)
> (what's defended, why) and [Mesh / offline-bridging](../architecture/mesh.md)
> (how leaves behind NAT reach the network).

---

## What you're protecting against

A real adversary looks like this:

| Capability | Examples |
|---|---|
| L7 DPI ("does this look like veil?") | GFW JA3 fingerprinting, Iran's pluggable-transport detector, Russia's Ростелеком DPI |
| L4 port blacklist | "everything except 80/443/53 is dropped" |
| L3 IP blacklist | published intel on veil infrastructure → BGP-level blackhole |
| Active probing | "this IP looks suspicious; let's connect and see if it answers in veil's protocol" |
| Traffic-shape correlation | "user at this IP transfers 12 MB/min in TLS records of size 4096 — that's the veil pattern" |

You can't defend against all of these with config alone — some require
operational hygiene (rotate VPS providers, blend with a real CDN
identity).  But the **wire-protocol defences** are config knobs that
veilcore already implements.

---

## The minimum production-target config

The `tls-boring` (BoringSSL) backend is **on by default** for `veil-cli`, so
you get the Chrome-grade TLS ClientHello fingerprint out of the box. Build with
production seeds plus the C toolchain BoringSSL + RocksDB need:

```bash
sudo apt-get install -y cmake golang-go nasm ninja-build build-essential
cargo build --release -p veil-cli --features production-seeds
```

> **Compile cost:** the default build links BoringSSL (`tls-boring`, via the
> `btls` crate) + RocksDB. Adds ~ 3 MB to the binary, ~doubles compile time, and
> needs `cmake`, `golang-go`, `nasm`, `ninja-build` on the build host. Build for
> your operator's platform from a build server with these tools — DON'T try to
> build on a router. (`--no-default-features` drops `tls-boring`.)

Then your `config.toml`:

```toml
# ── Identity (per-node; standalone-mode is enough for solo operator) ──
[identity]
algo = "ed25519"
public_key = "<your generated pubkey>"
private_key = "<your generated privkey>"
nonce       = "<generated PoW nonce>"
role        = "core"

# ── Listen on 443 (the only port a censor reliably whitelist) ──
[[listen]]
listen_id = 1
transport = "wss://0.0.0.0:443"
# Advertise externally — recipients dial this name, not the bind IP.
# Use a hostname that resolves to your VPS's public IP.
advertise = "wss://node.example.org:443"
tls_cert  = "/etc/veil/server.pem"
tls_key   = "/etc/veil/server.key"

# ── TLS posture: blend with HTTPS to a popular CDN ──
[transport]
# Outbound TLS ClientHello carries this SNI rather than the actual
# veil endpoint hostname.  Pick a hostname that on-path observers
# ROUTINELY see — major CDN, search engine, app store.  The choice
# itself is signalling: "www.cloudflare.com" looks like Cloudflare
# CDN traffic, "www.google.com" looks like Google services, etc.
default_sni = "www.cloudflare.com"

[transport.tls_client]
# Your operator-pinned trust chain ONLY — don't enable webpki-roots
# in adversarial deployment (broader trust = larger MITM surface).
# trusted_ca_file = "/etc/veil/ca.pem"

# ── Mesh: gateway role for leaves behind CGN-NAT ──
[mesh]
bind_addr  = "0.0.0.0:443"          # same port as listen; mesh shares
beacon_addr = "<broadcast addr>"     # depends on your LAN setup
realm_id   = "<32 hex chars>"
autodiscover_gateway = true
autodiscover_max_concurrent = 3      # leaves auto-connect to ≤ 3 of you

# ── Bootstrap: build with `production-seeds` feature, OR provide
# your own seeds out-of-band (recommended for adversarial deployment) ──
[[bootstrap_peers]]
transport  = "wss://seed.partner.example:443"
public_key = "<seed pubkey>"
nonce      = "<seed nonce>"
algo       = "ed25519"
```

Generate the QR / URL invite for new users via:

```bash
veil-cli bootstrap invite --qr
```

Pass that QR through any out-of-band channel (paper, signed email,
in-person) — recipients run `veil-cli bootstrap join --uri ...` to
add you to their `[[bootstrap_peers]]`.  See
[Epic 481.1](https://example.invalid/) for the wire format.

---

## What this defeats

| Censor capability | Mitigation |
|---|---|
| **JA3 fingerprint match** | `tls-boring` ⇒ Chrome 120+ ClientHello byte-for-byte.  Wireshark's JA3 hash equals Chrome's. |
| **JA4 / QUIC fingerprint** | `quic://` URI uses `quinn-btls` under `tls-boring` — same Chrome-grade story for HTTP/3 ports. |
| **SNI-based DPI** | `default_sni = "www.cloudflare.com"` puts a benign CDN name in the cleartext TLS field. Combined with bind on port 443 your traffic looks like CDN traffic at the L4/L7 boundary. |
| **Port whitelist** (only 80/443) | Both `wss://` (443/TCP) and `quic://` (443/UDP) ride on whitelisted ports. |
| **Cell-size correlation** | OVL1's `coalesce_with_padding` rounds outbound TLS records to 1024 / 4096 / 16384 byte boundaries.  No distinctive size pattern. |
| **Active probing** | Server-side TLS handshake completes normally before any OVL1 magic appears.  A probe sees a TLS server — same as opening a TLS connection to any HTTPS endpoint. |
| **IP blacklist** | This is operational, not protocol: rotate VPS providers, use multiple `[[listen]]` entries on different IPs, distribute new bootstrap invites quickly when an IP gets burned.  Mesh layer (Epic 478) handles the failover. |

---

## What this does NOT defeat

- **End-to-end traffic analysis.** A censor with packet captures of
  both endpoints can correlate timing/volume.  This requires
  anonymity at the routing layer (Epic 482, Tor-like circuits).
- **Mass IP harvesting.** If your VPS IPs end up on a public block-list
  (e.g. someone's "Suspected Tor" feed), the censor blocks them
  cheaply.  Domain fronting (Epic 484) puts a CDN edge between you
  and the censor's L3 filter.
- **State-level VPS provider coercion.** If the host country can
  compel your provider to drop traffic, no in-protocol defence helps.
  Diversify across hostile jurisdictions.

---

## Verifying your deployment

1. **Capture your ClientHello with Wireshark.**  Open a connection
   to your veil server from the deploying host, capture the first
   100 packets, decode TLS handshake.  Compare cipher_suites, extensions,
   and supported_groups order against a captured Chrome handshake to
   the same target — they should match exactly under `tls-boring`.
2. **Test against a JA3 calculator.**  Ja3.tools or similar — paste
   the captured ClientHello hex; the hash should equal
   `771,4865-4866-4867-49195-49196,...` (current Chrome 120+ JA3).
3. **Check SNI.**  Same capture, look at the TLS extensions block:
   `server_name` should be the value of `default_sni` in your config,
   NOT your VPS's actual hostname.
4. **Run `veil-cli node mesh-status`** on a leaf node: it should
   list your gateway entry as `ACTIVE` with low RTT.
5. **(Bonus, when 480.6 lands)** Run `cargo test dpi_fingerprint` —
   should green.  CI gate against regressions.

If you can't get the Wireshark capture to look like Chrome's,
**stop** — your build is wrong.  The most common causes:
- Built with `--no-default-features` (dropping `tls-boring`) → rustls fingerprint slipped in.
- `default_sni` not set → ClientHello carries the actual hostname.
- BoringSSL libssl version mismatch (rare) — rebuild with a clean
  `target/` directory.
