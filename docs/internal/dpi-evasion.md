# DPI evasion architecture

> **Audit:** 2026-04-27 · **Code:** master @ `619abfd` · **Epic:** 480

A state-level censor has four ways to block veil traffic:

1. **DPI fingerprinting.** Match the handshake byte pattern (JA3 / JA4
   / OVL1 magic), then block by L7 payload. (DPI is deep packet
   inspection — the censor reads packet contents, not just headers.)
2. **Port blacklisting.** Block the well-known veil port by L4 tuple.
3. **IP blacklisting.** Block known veil nodes by L3 prefix or a
   BGP-level filter.
4. **Traffic-shape correlation.** Even when traffic is encrypted, the
   size and cadence of veil packets differ from typical HTTPS — enough
   to identify a veil flow with decent probability.

This doc covers **what veilcore already ships** to defeat each of those
attacks, and links to the user-facing guide that explains how an
operator turns it on. That deployment guide:
[`docs/internal/censorship-target.md`](censorship-target.md).

---

## Coverage matrix

| Censor capability | Defence |
|---|---|
| **JA3 fingerprint match** (rustls's signature TLS handshake)        | `crates/veil-transport/src/tls_boring.rs` (Epic 409.4) — BoringSSL backend that emits Chrome 120+ ClientHello byte-for-byte.  On by default for `veil-cli` (`--no-default-features` reverts to rustls).  |
| **JA4 fingerprint match** (QUIC transport parameters)               | `transport/quic.rs` with `quinn-btls` (Epic 409) — pulled in by the same `tls-boring` feature.  Chrome HTTP/3 fingerprint. |
| **SNI = "veil.example.com"** in the clear (TLS 1.2 / SNI not encrypted) | `cfg::TransportConfig.default_sni: Option<String>` (Epic 409.3).  Set to `"www.cloudflare.com"` etc. — outbound TLS ClientHello carries that SNI; the actual veil endpoint hides behind your own SNI policy. |
| **Port blacklist** (only 80/443 allowed)                            | `[[listen]] transport = "wss://0.0.0.0:443"` works today; QUIC binds to `udp://...:443`; both blend with normal CDN traffic. |
| **Cell-size correlation** (TLS records of distinctive size)         | `coalesce_with_padding` in `node/session/runner.rs` — outbound frames are coalesced + padded at the OVL1 framing layer (BoringSSL doesn't expose `SSL_set_record_padding_callback`, so OVL1 does it instead). |
| **WebSocket tells** (`Sec-WebSocket-Protocol: veil`)             | `transport/websocket.rs` — WSS handshake configurable via `default_sni` + standard subprotocol naming; for production we use generic `Sec-WebSocket-Protocol` values that mirror common JS clients (TODO: explicit profile in 480.5). |
| **IP blacklist** (known veil IPs distributed by censor's intel)  | Multiple `[[listen]]` entries on different VPS providers + auto-failover via Mesh (Epic 478 mesh-status / gateway-rank).  Operator-side rotation; not currently automated.  Domain fronting / CDN proxying — out of scope for v1 (Epic 484 mobile/deployment). |
| **Active probing** (censor connects to suspected veil endpoint and waits to see if it answers in veil-like way) | `tls-boring` server-side: TLS handshake is indistinguishable from any HTTPS server until the application data starts; OVL1 magic only appears AFTER TLS handshake completes, so a probe that just opens TLS sees a normal-looking server.  Active-probe defence to be hardened in 480.6 (test harness will validate). |
| **Traffic-volume analysis** (veil user has a distinctive total bytes-up/down per minute) | Out of scope for transport-level evasion; addressed at the higher Mesh / E2E layer where multiple peers contribute traffic to the same source IP. |

---

## Wire-level evidence

Here is what an on-path observer sees for a veil connection on
`wss://node.example:443`, with `tls-boring` enabled and
`default_sni = "www.cloudflare.com"`:

```text
[client → server, TCP SYN]      port=443, dst_ip=<our VPS>
[client → server, TLS ClientHello]
    cipher_suites: { 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02C, … }   ← Chrome's order
    extensions:    [server_name="www.cloudflare.com",
                    supported_versions=[TLS 1.3, TLS 1.2],
                    supported_groups=[X25519, secp256r1, secp384r1],
                    signature_algorithms=[…Chrome's order…],
                    application_layer_protocol_negotiation=[h2, http/1.1],
                    …]
    JA3 hash:      771,4865-4866-4867-49195-49196,…              ← matches Chrome 120+
[server → client, TLS ServerHello + Cert]   from a TLS server that
                                            looks like cloudflare to JA3S
[client → server, HTTP/1.1 GET / Upgrade: websocket]
    Headers: User-Agent: …, Sec-WebSocket-Protocol: <neutral>, …
[WebSocket frames, AES-128-GCM-encrypted via TLS]
    Frame sizes: padded to 1300 / 4096 / 16384 boundaries
                 (matches TLS record bucket sizes used by Chrome;
                 no distinctive veil sizes)
```

Compare that to a plain `tcp://node.example:9000` connection without
`tls-boring`:

```text
[client → server, TCP SYN]      port=9000  ← well-known veil-ish
[client → server, OVL1 HELLO]   first 4 bytes = "OVL1" magic
                                ↑ trivial DPI signature
```

The tls-boring + WSS-on-443 combination is the production target.
Plain TCP is for development only.

---

## What's missing (Epic 480 follow-up)

1. **480.5 — Config profile.** `veil-cli config init --profile censorship-target`
   should generate a `config.toml` that flips all the right knobs by
   default. Right now an operator has to read seven docs to assemble
   the right config by hand.
2. **480.6 — DPI-resistance test harness.** Capture our own ClientHello
   bytes through both the rustls and tls-boring code paths. Compare them
   to a golden Chrome ClientHello capture, then assert byte-equivalence
   for tls-boring and assert that rustls is distinguishable. This
   catches regressions if upstream `btls` / `quinn-btls` change their
   defaults.
3. **480.7 — Operator-facing deployment guide.** The doc that pulls all
   this together and tells operators which knob to flip when.
   See [`docs/internal/censorship-target.md`](censorship-target.md).

Out of scope for Epic 480:
- Domain fronting / CDN-fronting (separate Epic 484, needs CDN
  partner integration).
- Port hopping. Marginal value for the added config complexity. If the
  censor blocks the IP, port hopping doesn't help; if the censor
  whitelists ports, just bind to 443 once.

---

## obfs4 transport (`obfs4-tcp://`)

**Status**: implemented, registered в default TransportRegistry.

obfs4 is а pluggable transport originally от Tor's pluggable-transports
project.  Veil's implementation ships in [`crates/veil-obfs4`](../../crates/veil-obfs4)
и is wired as а Transport impl in [`veil-transport::obfs4_tcp`](../../crates/veil-transport/src/obfs4_tcp.rs).

Comparison к tls-boring:

| Property                       | `tls-boring` + `wss://`  | `obfs4-tcp://`             |
|--------------------------------|--------------------------|----------------------------|
| Wire bytes look like           | TLS 1.3 c Chrome JA3     | uniformly random           |
| Wire fingerprint               | matches real HTTPS       | none — no protocol probe   |
| Active-probe resistance        | medium (needs webtunnel) | yes (silent-drop bad MAC)  |
| Needs TLS CA chain             | yes                      | no                         |
| Censor strategy що blocks it   | block ALL TLS port 443?  | block ALL random-byte TCP? |
| Operator cost                  | TLS cert + reasonable SNI | distribute PSK к peers     |

**When к prefer obfs4 over tls-boring:**
- Embedded targets без а TLS stack (resource-constrained routers).
- Environments где TLS itself is heuristically flagged as suspicious
  (some authoritarian networks).
- Test deployments що need anti-DPI без а cert PKI.

**When к prefer tls-boring + wss:**
- Public-internet deployments що can blend с real HTTPS traffic.
- Operator has access к а real domain + cert.
- Production: easier к operate, fewer secrets к distribute.

obfs4 PSK distribution: Phase 3-interim ships а single network-wide
`obfs4_psk` в `TransportContext`.  Per-peer PSKs via signed
`transport_hints` are а follow-up; track в [docs/internal/PLAN_TRANSPORT_OBFUSCATION.md](PLAN_TRANSPORT_OBFUSCATION.md).

## webtunnel anti-probe для `wss://` / `tls://`

**Status**: library complete, transport integration deferred.

webtunnel addresses the **active-probe** gap left by plain TLS.  An
operator що deploys veil на а public server can wrap it с
`veil-webtunnel`: incoming connections що don't carry the secret
path + auth header receive а decoy response (looks like а regular HTTPS
site); only requests с matching credentials trigger а WebSocket upgrade.

Library pieces:
- [`SecretMatcher`](../../crates/veil-webtunnel/src/matcher.rs) —
  constant-time path + auth-header match.
- [`DecoyProvider`](../../crates/veil-webtunnel/src/decoy.rs) trait
  с `StaticStringDecoy` + `StaticDirectoryDecoy` impls.
- [`WebtunnelRouter`](../../crates/veil-webtunnel/src/router.rs) —
  server-side HTTP entry point що runs the matcher + decoy / upgrade.
- [`WebtunnelClient`](../../crates/veil-webtunnel/src/client.rs) —
  client-side connector with realistic browser headers.

Transport-trait integration (а `webtunnel+wss://` URI scheme) is
deferred — operators currently wire webtunnel manually as а pre-WSS
gate.  See `PLAN_TRANSPORT_OBFUSCATION.md` Phase 5d–5e.
