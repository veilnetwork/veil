# Transport obfuscation plan — hide OVL1 + endpoint anti-probing

> Status: **in progress.** Phase 1a/1b/1c complete — UDP stateless
> (`crates/veil-udp-obfs`) + obfs4 TCP framing + NTOR/elligator2 handshake
> (`crates/veil-obfs4/src/{ntor,elligator2}.rs`). Phase 2 (transport
> integration) substantially shipped: **obfs4-tcp** transport landed
> (`veil-transport`), and the **UDP path is integrated into the mesh via
> opt-in `[mesh] realm_psk`** (2026-06-03) — sealing both DATA datagrams and
> discovery beacons with a realm-wide `ObfsKey`, plus beacon size-padding +
> interval jitter (C-03). **NOTE:** the shipped UDP integration deviates from the
> original "`obfs4+udp://` URI scheme" sketch in §2a below — it lives at the mesh
> `UdpRealm`/`UdpLink` layer with a realm-wide key (connectionless recv has no
> per-link demux), not as a transport-URI wrapper. Phases 3–7 remain scheduled.

## Two threat axes

This plan addresses **two distinct DPI/censorship threats**.  Solutions
are independent — а deployment can ship one, both, or neither depending
on its environment:

| Threat                | Solution                              | Applies to                       |
|-----------------------|---------------------------------------|----------------------------------|
| Passive DPI on wire   | obfs4 framing (TCP) / stateless AEAD (UDP) | `tcp://`, `udp://` plaintext   |
| Active probing of endpoint | webtunnel-style decoy + secret-path | `tls://`, `wss://`, `quic://`  |

**Passive DPI**: censor's middle-box reads plaintext bytes, looks for
OVL1 magic or distinctive headers.  TLS-bearing transports already
defeat this (внутренний trafic encrypted), но plaintext TCP/UDP show
OVL1 directly.

**Active probing**: censor scans candidate IPs, connects, sends crafted
probes к detect veil endpoints.  Even on TLS, а server что accepts
veil connections but rejects everything else (or returns
distinctive error pages) is identifiable.  webtunnel-style masking
makes the endpoint look like а regular HTTPS site to anyone без
the secret path/auth.

## Why

OVL1 frame header (magic = `"OVL1"`, version byte, body-length, etc.) is
plaintext **inside the transport channel**.  Session-layer AEAD encrypts
the frame *body*, не the header — see [crates/veil-session/src/runner.rs](../../crates/veil-session/src/runner.rs) and
[crates/veil-proto/src/codec.rs](../../crates/veil-proto/src/codec.rs).

Consequences by transport:

| Transport         | Passive-DPI risk         | Active-probe risk            |
|-------------------|--------------------------|------------------------------|
| `tcp://`          | high (OVL1 magic plain)  | high (responds к anything)   |
| `udp://`          | high (OVL1 в datagrams)  | high                         |
| `ws://` (no TLS)  | high (OVL1 inside WS)    | high                         |
| `tls://`          | low (внутренний enc)     | medium (no decoy on 443)     |
| `wss://`          | low                      | medium                       |
| `quic://`         | low                      | medium                       |

The Phase 1/2/3 work (obfs4 + UDP stateless) addresses the high
passive-DPI column.  Phase 5 webtunnel work addresses the
medium/high active-probe column для TLS-bearing transports.

For deployments що can't ship TLS-bearing transports (embedded routers,
constrained devices, environments где TLS is itself flagged as
suspicious), the plaintext transports remain operational но trivially
DPI-fingerprintable.

The fix: wrap plaintext transports в an obfuscation layer что makes wire
bytes statistically indistinguishable from random.  Two paradigms:

- **TCP** stream-oriented → obfs4-style: NTOR handshake + AEAD framing с
  elligator2-encoded ephemeral pubkeys.
- **UDP** datagram-oriented → stateless AEAD-per-packet: PSK-derived key,
  random IV в each datagram, counter + replay window.

## Scope

In-scope:
- `tcp://` → wrap with obfs4 handshake (new `veil-obfs4` crate).
- `udp://` → wrap with stateless AEAD (new `veil-udp-obfs` crate).
- `ws://` (without TLS) → wrap inner TCP с obfs4 before WebSocket upgrade
  OR adopt the same obfs4 framing **inside** WebSocket binary frames.
  Decision deferred к Phase 4 после obfs4 ядро готово.
- `wss://` / `tls://` → optional webtunnel-style endpoint masking
  (new `veil-webtunnel` crate, Phase 5).  Disguises the endpoint
  as а legitimate HTTPS site; tunnel mode только при правильном
  secret path + auth header.
- New URI schemes:
  - `obfs4+tcp://`, `obfs4+udp://`, optionally `obfs4+ws://` (Phase 2).
  - `webtunnel+wss://path?auth=secret@host:443` (Phase 5).

Out-of-scope:
- `quic://` — already encrypted at transport layer; active-probe
  resistance possible но quinn lacks the HTTP routing surface
  webtunnel needs.  Re-open trigger: quinn HTTP/3 support matures и
  operator needs decoy для QUIC endpoints.
- Unix-domain sockets (local IPC) — DPI is не the threat model там.
- SOCKS5 inbound — operator's local proxy, не network-facing.
- Statistical traffic-analysis defences (packet-timing obfuscation,
  decoy-traffic injection) — separate effort, deferred к а
  follow-up plan if/when needed.

## Wire formats

### UDP stateless (Phase 1a — implemented)

Each datagram:
```
[ 16 byte random nonce-prefix ]
[ 8 byte counter u64 BE       ]
[ ChaCha20-Poly1305 ciphertext (payload || random padding) ]
[ 16 byte AEAD tag             ]
```

Total overhead per datagram: **40 bytes** (16 nonce-prefix + 8 counter
+ 16 tag).

- **AEAD nonce** = `nonce-prefix || counter[..4]` (24-byte XChaCha20-Poly1305
  nonce constructed by HKDF expansion от prefix + counter).
- **AEAD key** = `HKDF-SHA256(PSK, "veil-udp-obfs:v1:" || peer_node_id, 32)`.
- **Replay window** = sliding bitmap по counter, default 1024 slots.
- **Random padding** = 0..256 bytes uniformly random, length encoded in
  body as 1-byte prefix.

Properties:
- Wire bytes uniformly random; no plaintext OVL1 magic visible.
- Tolerant к loss / reorder / duplication.
- Each datagram self-contained — no state machine, no handshake RTT.
- Counter в plaintext но replay-bound; cannot be advanced без the key.

Trade-off (documented в module-level docstring): PSK = long-lived
symmetric secret.  Compromise reveals all past и future traffic
encrypted under this PSK.  Acceptable для discovery / NAT-probe /
diagnostic traffic; sensitive payloads ride session-layer AEAD on TCP.

### TCP obfs4-style (Phases 1b–3)

```
─── Handshake ────────────────────────────────────────
Client → Server:
  [ 32 byte elligator2-encoded Cx (ephemeral X25519 pubkey, MSB cleared) ]
  [ 8 byte timestamp_secs        u64 BE                                  ]
  [ 32 byte HMAC-SHA256(server_node_id_pk || Cx || timestamp, server_id_mac_key) ]
  [ 0..128 byte random padding   ]

Server → Client (silent drop iff MAC bad):
  [ 32 byte elligator2-encoded Sx ]
  [ 8 byte timestamp_secs         ]
  [ 32 byte HMAC(... || AUTH = HKDF(shared, "obfs4-auth-v1"), client_id_mac_key) ]
  [ 0..128 byte random padding    ]

Shared = X25519(Cx, Sx)  // standard ECDH on the Edwards/Montgomery curve

Both sides derive:
  K_c_to_s, K_s_to_c, IV_c_to_s, IV_s_to_c
    = HKDF(shared, "obfs4-stream-keys:v1" || timestamp_pair).

─── Stream framing ───────────────────────────────────
For each frame in each direction:
  [ 2 byte length u16 BE (encrypted via ChaCha20 keystream offset by counter) ]
  [ ChaCha20-Poly1305(payload || random padding 0..1024, K_dir, IV_dir || counter) ]
  [ 16 byte AEAD tag ]
```

Properties (per obfs4 design):
- First 32 bytes от client = uniformly random (elligator2 magic).
- Server replies *only* if MAC verifies → silent drop on active probing.
- Per-session ephemeral X25519 keys → forward secrecy в obfuscation layer.
- Length field encrypted с ChaCha20 keystream — outsider can't read frame
  sizes без the key.

PSK = `server_node_id_pk` (already part of identity infrastructure) +
а dedicated `obfs4_mac_key` (32 bytes random, per-node, published в
`transport_hints` signed by identity_key).

## Phase plan

### Phase 1 — core crypto crates

**1a — UDP stateless (this commit):**
- New crate `crates/veil-udp-obfs`.
- AEAD wrap/unwrap + replay window.
- Pure functions; no transport integration yet.
- Full unit tests (round-trip, replay, tampered nonce, key separation).

**1b — TCP framing (next session, ~1 session):**
- New crate `crates/veil-obfs4`.
- `framing.rs`: AEAD frame wrap/unwrap, length-encryption with ChaCha20
  keystream, padding distribution.
- Pure functions; no NTOR handshake yet (separate Phase 1c).
- Unit tests on framing layer in isolation.

**1c — TCP NTOR handshake + elligator2 (~1-2 sessions):**
- `elligator2.rs`: encode/decode Curve25519 ↔ uniformly-random 32-byte.
  Lift code от а reference Rust impl (lyrebird forks, curve25519-dalek's
  `MontgomeryPoint::from_bytes` + manual elligator math) с careful
  constant-time review.
- `ntor.rs`: client_handshake / server_handshake state machines.
- Timing-safe MAC verification.
- Property tests for elligator2 (encode-decode roundtrip on random
  points, output statistically uniform).

### Phase 2 — transport integration

**2a — UDP integration (~1 session):**
- Add `obfs4+udp://` URI scheme.
- Wrap existing `udp.rs` transport: outbound `dial` calls obfs4-udp
  encrypt before send_to, inbound recv decrypts before delivering к
  session-layer.
- PSK derivation: HKDF от bootstrap-distributed `obfs4_psk` field.
- Config: per-deployment PSK distribution.

**2b — TCP integration (~1 session):**
- Add `obfs4+tcp://` URI scheme.
- `obfs4_tcp_stream` wraps `tcp.rs` `BoxIoStream`: spawns handshake task
  before yielding the stream к session-layer.
- Server-side: bind listens на `obfs4+tcp://` accept loop performs
  server handshake; silent-drops on bad MAC.

### Phase 3 — PSK distribution

- Extend `transport_hints` к carry `obfs4_pubkey` + `obfs4_mac_key`
  fields (signed by identity_key).
- Update bootstrap-bundle format к include obfs4 fields for seed peers.
- Document operator key-rotation procedure.

### Phase 4 — WebSocket variant + dual-stack

- Decide: wrap WS payload bytes with obfs4-stream framing (inside
  binary frames), or wrap underlying TCP with obfs4 before WS upgrade.
- The latter is simpler но breaks WS-aware DPI's expectation of
  HTTP/1.1 Upgrade на the first packet — inconsistent.
- Recommended: inner-WS framing (encrypt-then-base64? or use binary
  frames so obfs4 bytes pass through unchanged).

### Phase 5 — webtunnel anti-probe для WSS / TLS

**Threat addressed:** active probing of TLS-bearing endpoints.  Even
when the transport is TLS-encrypted, а server що:
- responds к ANY connection on port 443 with а distinctive error,
- responds к а custom protocol probe with а recognisable shape,
- has an empty document root (`GET /` → 404 / generic Hyper page),

is identifiable to а scanner crawling all IPs.  Once tagged, the IP
can be blocked or its traffic monitored.

**Solution:** webtunnel-style endpoint masking.  Server presents as а
legitimate HTTPS site by default; switches к veil-tunnel mode только
when the client connects с the configured secret path + auth header.

#### Wire flow

```text
Client → Server (TLS handshake, standard JA3/JA4 fingerprint):
    [ TLS ClientHello, SNI=example.com ]
    [ TLS handshake completes ]

  Within TLS, client sends HTTP/1.1 request:
    GET /SECRET_PATH HTTP/1.1
    Host: example.com
    Upgrade: websocket
    Connection: Upgrade
    Sec-WebSocket-Key: <base64-16-bytes>
    Sec-WebSocket-Version: 13
    X-Veil-Auth: <secret_token>     <-- optional but recommended

Server check (constant-time):
    if path == SECRET_PATH AND X-Veil-Auth == SECRET_TOKEN:
        → HTTP 101 Switching Protocols
        → WebSocket binary frames carry OVL1 от there

    else:
        → serve decoy content as а regular HTTPS site:
            GET /              → cached homepage HTML
            GET /about         → cached /about page
            GET /<anything>    → 404 with distinctive-of-some-real-server page
        Constant-time-equivalent latency profile so timing analysis
        can't tell "valid path" от "404 path" apart.
```

#### Decoy content options (operator chooses)

| Mode             | Realism | Operator cost                         |
|------------------|---------|---------------------------------------|
| Static-string    | low     | zero — single HTML string в config    |
| Static-directory | medium  | low — point к а dir of cached pages   |
| Reverse-proxy    | high    | medium — proxy к а real HTTP backend  |
| Meek-style fetch | high    | high — caches от real sites on demand |

Recommended default: **static-directory**.  Operator deploys а snapshot
of а neutral site (status dashboard, dev blog, etc.) once; subsequent
probes get realistic responses with proper Content-Type, Etag, etc.

#### Components (new `veil-webtunnel` crate)

1. **HTTP routing** (Hyper-based):
   - Accept incoming TLS-decrypted HTTP/1.1 connection.
   - Parse request line + headers.
   - Constant-time compare path и auth header.
   - On match: hand off socket к WebSocket upgrade handler.
   - On miss: serve decoy content; close connection cleanly.

2. **WebSocket upgrade** (existing `veil-transport::websocket` or
   `tokio-tungstenite`): standard RFC 6455 handshake after path match.

3. **Decoy provider** trait:
   ```rust
   trait DecoyProvider: Send + Sync {
       async fn respond(
           &self,
           req: &http::Request<()>,
       ) -> http::Response<Vec<u8>>;
   }
   ```
   - `StaticStringDecoy`, `StaticDirectoryDecoy`, `ReverseProxyDecoy`
     implementations.

4. **Secret distribution**: extends `transport_hints` (Phase 3) с two
   new fields:
   - `webtunnel_secret_path: String` (32+ chars, random),
   - `webtunnel_auth_token: Option<Vec<u8>>` (32 bytes random).

   Both signed by identity_key like other transport hints.

5. **Client side**: extends `websocket.rs` connect path к add
   `X-Veil-Auth` header и use the secret path в the WebSocket
   upgrade URI.

#### Anti-probing properties

What active probing **cannot** do без the secret:
- Distinguish а webtunnel-host от а real HTTPS site.
- Force tunnel mode via crafted probes.
- Use timing-side-channel к infer existence of tunnel mode (constant-
  time compare on path + auth).

What active probing **can** do:
- Identify the IP as running TLS — но `~25%` of public IPs do.
- Identify the TLS fingerprint (mitigated by `tls-boring`).
- Eventually exhaust the IP space и flag specific IPs as "websites
  that never had real users visit them" — а general censorship
  problem, not specific к veil.

What an adversary who **has** the secret can do:
- Verify the endpoint runs veil.  Secret = шibboleth, not
  cryptographic identification.  This is fundamental: any
  PSK-based scheme reveals the endpoint к anyone with the PSK.
- Mitigation: rotate secrets periodically, distribute via
  `transport_hints` що is identity-signed so leaked secrets
  expire at the next rotation.

#### Phase 5 sub-phases

- **5a** — `veil-webtunnel` crate skeleton + decoy trait + static-
  string и static-directory providers (~400 LoC + tests).
- **5b** — HTTP routing + secret-path constant-time match +
  WebSocket upgrade handoff (~500 LoC + tests).
- **5c** — `transport_hints` extension + `webtunnel+wss://` URI scheme
  + client-side path/auth wiring (~300 LoC + tests).
- **5d** — Reverse-proxy decoy provider (optional, ~200 LoC).
- **5e** — Integration test: probe-without-secret returns decoy;
  probe-with-secret upgrades к WebSocket; tunnel carries OVL1 session.

### Phase 6 — tests + production-readiness

- Integration tests: two-node sim with obfs4+tcp transport, full veil
  session roundtrip.
- Integration tests: two-node sim with webtunnel+wss transport,
  scanner-decoy verification.
- Statistical entropy tests on captured handshake bytes (chi-square,
  byte-frequency analysis).
- Anti-probe test: connect c bad MAC (obfs4) / wrong path (webtunnel),
  assert silent drop / decoy response.
- Replay-attack test: capture+replay handshake → server rejects timestamp.
- Documentation: update `dpi-evasion.md` matrix; add operator guides для
  PSK distribution + webtunnel decoy-content setup.

## Acceptance gates (per phase)

1. `cargo check --workspace --all-features` clean.
2. `cargo test -p <new-crate>` green.
3. `cargo clippy --workspace --all-features --tests` zero new warnings.
4. Wire-entropy spot check: capture 1000 handshake bytes от Phase 1c
   implementation, run chi-square test for uniform distribution
   (expected p-value > 0.01).
5. **Phase 1c specifically:** timing-safe MAC compare verified via
   `subtle::ConstantTimeEq` audit.

## Re-open triggers vs out-of-scope items

- **Statistical traffic analysis** (packet timing, volume fingerprinting):
  hold until либо incident в production либо operator request.
- **iat-mode** (inter-arrival timing obfuscation): hold; significant
  complexity, marginal entropy gain.
- **`ws://` integration**: hold до Phase 1c lands (need framing first).
- **`quic+webtunnel`**: hold до quinn surfaces clean HTTP/3 routing
  hook OR operator explicitly needs QUIC anti-probe.
- **Meek-style on-demand decoy caching**: hold; high-realism but
  significant code surface, only justified для high-stakes deployments.

## Total estimate

- Phase 1a: **done** (`a977890` — UDP stateless core).
- Phase 1b: **done** (`a977890` — TCP framing core).
- Phase 1c: 1-2 sessions (NTOR + elligator2, crypto-careful).
- Phase 2: 2 sessions (UDP + TCP transport integration).
- Phase 3: 1 session (PSK distribution через transport_hints).
- Phase 4: 1 session (WebSocket variant).
- Phase 5: 2-3 sessions (webtunnel sub-phases 5a–5e).
- Phase 6: 1 session (integration tests + docs).

**~8-10 sessions total** beyond `a977890` для full deployment.
Granular phases mean each step can be reviewed / paused / re-prioritised
independently.
