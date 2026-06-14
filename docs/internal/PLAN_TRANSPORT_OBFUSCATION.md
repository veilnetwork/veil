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

This plan addresses **two distinct DPI/censorship threats**. (DPI is deep packet inspection: a censor's box that examines packet contents, not just where they're headed.) The two solutions are independent — a deployment can ship one, both, or neither, depending on its environment:

| Threat                | Solution                              | Applies to                       |
|-----------------------|---------------------------------------|----------------------------------|
| Passive DPI on wire   | obfs4 framing (TCP) / stateless AEAD (UDP) | `tcp://`, `udp://` plaintext   |
| Active probing of endpoint | webtunnel-style decoy + secret-path | `tls://`, `wss://`, `quic://`  |

**Passive DPI:** the censor's middle-box reads the plaintext bytes and looks for the OVL1 magic or distinctive headers. TLS-bearing transports already defeat this, since the inner traffic is encrypted, but plaintext TCP and UDP show OVL1 directly.

**Active probing:** the censor scans candidate IPs, connects, and sends crafted probes to detect veil endpoints. Even over TLS, a server that accepts veil connections but rejects everything else — or returns distinctive error pages — is identifiable. webtunnel-style masking makes the endpoint look like a regular HTTPS site to anyone without the secret path and auth.

## Why

The OVL1 frame header (magic = `"OVL1"`, a version byte, a body-length, and so on) is plaintext **inside the transport channel**. Session-layer AEAD encrypts the frame *body*, not the header — see [crates/veil-session/src/runner.rs](../../crates/veil-session/src/runner.rs) and [crates/veil-proto/src/codec.rs](../../crates/veil-proto/src/codec.rs). (AEAD is authenticated encryption with associated data: it both hides and tamper-proofs the bytes it covers.)

The consequences, by transport:

| Transport         | Passive-DPI risk         | Active-probe risk            |
|-------------------|--------------------------|------------------------------|
| `tcp://`          | high (OVL1 magic plain)  | high (responds to anything)  |
| `udp://`          | high (OVL1 in datagrams) | high                         |
| `ws://` (no TLS)  | high (OVL1 inside WS)    | high                         |
| `tls://`          | low (inner enc)          | medium (no decoy on 443)     |
| `wss://`          | low                      | medium                       |
| `quic://`         | low                      | medium                       |

The Phase 1/2/3 work (obfs4 plus stateless UDP) addresses the high passive-DPI column. The Phase 5 webtunnel work addresses the medium/high active-probe column for TLS-bearing transports.

For deployments that can't ship TLS-bearing transports — embedded routers, constrained devices, or environments where TLS is itself flagged as suspicious — the plaintext transports keep working, but they are trivially DPI-fingerprintable.

The fix is to wrap the plaintext transports in an obfuscation layer that makes the wire bytes statistically indistinguishable from random. There are two paradigms:

- **TCP** is stream-oriented, so we use an obfs4-style approach: an NTOR handshake plus AEAD framing, with elligator2-encoded ephemeral pubkeys.
- **UDP** is datagram-oriented, so we use stateless AEAD per packet: a PSK-derived key, a random IV in each datagram, plus a counter and a replay window.

## Scope

In-scope:
- `tcp://` → wrap with obfs4 handshake (new `veil-obfs4` crate).
- `udp://` → wrap with stateless AEAD (new `veil-udp-obfs` crate).
- `ws://` (without TLS) → wrap the inner TCP with obfs4 before the WebSocket
  upgrade, OR adopt the same obfs4 framing **inside** WebSocket binary frames.
  This decision is deferred to Phase 4, once the obfs4 core is ready.
- `wss://` / `tls://` → optional webtunnel-style endpoint masking
  (new `veil-webtunnel` crate, Phase 5). Disguises the endpoint as a
  legitimate HTTPS site; tunnel mode engages only with the correct
  secret path and auth header.
- New URI schemes:
  - `obfs4+tcp://`, `obfs4+udp://`, optionally `obfs4+ws://` (Phase 2).
  - `webtunnel+wss://path?auth=secret@host:443` (Phase 5).

Out-of-scope:
- `quic://` — already encrypted at the transport layer. Active-probe
  resistance is possible, but quinn lacks the HTTP routing surface that
  webtunnel needs. Re-open trigger: quinn's HTTP/3 support matures and an
  operator needs a decoy for QUIC endpoints.
- Unix-domain sockets (local IPC) — DPI is not the threat model there.
- SOCKS5 inbound — the operator's local proxy, not network-facing.
- Statistical traffic-analysis defences (packet-timing obfuscation,
  decoy-traffic injection) — a separate effort, deferred to a follow-up
  plan if and when it's needed.

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

- **AEAD nonce** = `nonce-prefix || counter[..4]` (a 24-byte
  XChaCha20-Poly1305 nonce, built by HKDF expansion of the prefix plus the
  counter).
- **AEAD key** = `HKDF-SHA256(PSK, "veil-udp-obfs:v1:" || peer_node_id, 32)`.
- **Replay window** = a sliding bitmap over the counter, default 1024 slots.
- **Random padding** = 0..256 bytes, uniformly random, with the length
  encoded in the body as a 1-byte prefix.

Properties:
- The wire bytes are uniformly random; no plaintext OVL1 magic is visible.
- Tolerant of loss, reorder, and duplication.
- Each datagram is self-contained — no state machine, no handshake RTT.
- The counter is in plaintext but replay-bound; it cannot be advanced
  without the key.

Trade-off (documented in the module-level docstring): the PSK is a
long-lived symmetric secret. If it leaks, all past and future traffic
encrypted under it is exposed. That is acceptable for discovery, NAT-probe,
and diagnostic traffic; sensitive payloads ride the session-layer AEAD on
TCP instead.

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

Properties (following the obfs4 design):
- The first 32 bytes from the client are uniformly random (the elligator2 magic).
- The server replies *only* if the MAC verifies, so it silently drops active probes.
- Per-session ephemeral X25519 keys give the obfuscation layer forward secrecy.
- The length field is encrypted with the ChaCha20 keystream, so an outsider
  can't read frame sizes without the key.

The PSK is `server_node_id_pk` (already part of the identity infrastructure)
plus a dedicated `obfs4_mac_key` (32 random bytes, per node, published in
`transport_hints` and signed by identity_key).

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
- `elligator2.rs`: encode/decode Curve25519 ↔ a uniformly-random 32-byte
  value. Lift the code from a reference Rust impl (lyrebird forks, or
  curve25519-dalek's `MontgomeryPoint::from_bytes` plus manual elligator
  math), with a careful constant-time review.
- `ntor.rs`: client_handshake / server_handshake state machines.
- Timing-safe MAC verification.
- Property tests for elligator2 (encode-decode roundtrip on random
  points, output statistically uniform).

### Phase 2 — transport integration

**2a — UDP integration (~1 session):**
- Add `obfs4+udp://` URI scheme.
- Wrap the existing `udp.rs` transport: on outbound, `dial` calls the
  obfs4-udp encrypt before send_to; on inbound, recv decrypts before handing
  bytes to the session layer.
- PSK derivation: HKDF from the bootstrap-distributed `obfs4_psk` field.
- Config: per-deployment PSK distribution.

**2b — TCP integration (~1 session):**
- Add `obfs4+tcp://` URI scheme.
- `obfs4_tcp_stream` wraps the `tcp.rs` `BoxIoStream`: it spawns a handshake
  task before yielding the stream to the session layer.
- Server-side: the `obfs4+tcp://` bind accept loop performs the server
  handshake and silently drops on a bad MAC.

### Phase 3 — PSK distribution

- Extend `transport_hints` to carry `obfs4_pubkey` and `obfs4_mac_key`
  fields (signed by identity_key).
- Update the bootstrap-bundle format to include the obfs4 fields for seed peers.
- Document the operator key-rotation procedure.

### Phase 4 — WebSocket variant + dual-stack

- Decide between two options: wrap the WS payload bytes with obfs4-stream
  framing (inside binary frames), or wrap the underlying TCP with obfs4
  before the WS upgrade.
- The latter is simpler, but it breaks WS-aware DPI's expectation of an
  HTTP/1.1 Upgrade on the first packet, which is inconsistent.
- Recommended: inner-WS framing — either encrypt-then-base64, or use binary
  frames so the obfs4 bytes pass through unchanged.

### Phase 5 — webtunnel anti-probe for WSS / TLS

**Threat addressed:** active probing of TLS-bearing endpoints. Even when the
transport is TLS-encrypted, a server that:
- responds to ANY connection on port 443 with a distinctive error,
- responds to a custom protocol probe with a recognisable shape, or
- has an empty document root (`GET /` → a 404 or a generic Hyper page),

is identifiable to a scanner crawling all IPs. Once tagged, the IP can be
blocked or have its traffic monitored.

**Solution:** webtunnel-style endpoint masking. The server presents as a
legitimate HTTPS site by default and switches to veil-tunnel mode only when
the client connects with the configured secret path and auth header.

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
        → WebSocket binary frames carry OVL1 from there

    else:
        → serve decoy content as a regular HTTPS site:
            GET /              → cached homepage HTML
            GET /about         → cached /about page
            GET /<anything>    → 404 with distinctive-of-some-real-server page
        Constant-time-equivalent latency profile so timing analysis
        can't tell "valid path" from "404 path" apart.
```

#### Decoy content options (operator chooses)

| Mode             | Realism | Operator cost                         |
|------------------|---------|---------------------------------------|
| Static-string    | low     | zero — a single HTML string in config |
| Static-directory | medium  | low — point to a dir of cached pages  |
| Reverse-proxy    | high    | medium — proxy to a real HTTP backend |
| Meek-style fetch | high    | high — caches from real sites on demand |

Recommended default: **static-directory**. The operator deploys a snapshot
of a neutral site (a status dashboard, a dev blog, and so on) once; after
that, probes get realistic responses with a proper Content-Type, Etag, and
the rest.

#### Components (new `veil-webtunnel` crate)

1. **HTTP routing** (Hyper-based):
   - Accept the incoming TLS-decrypted HTTP/1.1 connection.
   - Parse the request line and headers.
   - Constant-time compare the path and auth header.
   - On a match: hand the socket off to the WebSocket upgrade handler.
   - On a miss: serve decoy content, then close the connection cleanly.

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

4. **Secret distribution**: extends `transport_hints` (Phase 3) with two
   new fields:
   - `webtunnel_secret_path: String` (32+ chars, random),
   - `webtunnel_auth_token: Option<Vec<u8>>` (32 random bytes).

   Both are signed by identity_key, like the other transport hints.

5. **Client side**: extends the `websocket.rs` connect path to add the
   `X-Veil-Auth` header and use the secret path in the WebSocket upgrade URI.

#### Anti-probing properties

What active probing **cannot** do without the secret:
- Tell a webtunnel host apart from a real HTTPS site.
- Force tunnel mode with crafted probes.
- Use a timing side-channel to infer that tunnel mode exists (the path and
  auth compare is constant-time).

What active probing **can** do:
- Identify the IP as running TLS — but about 25% of public IPs do.
- Identify the TLS fingerprint (mitigated by `tls-boring`).
- Eventually exhaust the IP space and flag specific IPs as "websites that
  never had real users visit them." That is a general censorship problem,
  not specific to veil.

What an adversary who **has** the secret can do:
- Verify the endpoint runs veil. The secret is a shibboleth, not
  cryptographic identification. This is fundamental: any PSK-based scheme
  reveals the endpoint to anyone holding the PSK.
- Mitigation: rotate secrets periodically and distribute them via
  `transport_hints`, which is identity-signed, so leaked secrets expire at
  the next rotation.

#### Phase 5 sub-phases

- **5a** — `veil-webtunnel` crate skeleton + decoy trait + static-string
  and static-directory providers (~400 LoC + tests).
- **5b** — HTTP routing + secret-path constant-time match +
  WebSocket upgrade handoff (~500 LoC + tests).
- **5c** — `transport_hints` extension + `webtunnel+wss://` URI scheme
  + client-side path/auth wiring (~300 LoC + tests).
- **5d** — Reverse-proxy decoy provider (optional, ~200 LoC).
- **5e** — Integration test: a probe without the secret returns the decoy;
  a probe with the secret upgrades to WebSocket; the tunnel carries an OVL1
  session.

### Phase 6 — tests + production-readiness

- Integration tests: two-node sim with obfs4+tcp transport, full veil
  session roundtrip.
- Integration tests: two-node sim with webtunnel+wss transport,
  scanner-decoy verification.
- Statistical entropy tests on captured handshake bytes (chi-square,
  byte-frequency analysis).
- Anti-probe test: connect with a bad MAC (obfs4) or the wrong path
  (webtunnel), and assert a silent drop or a decoy response.
- Replay-attack test: capture and replay a handshake; the server rejects the
  timestamp.
- Documentation: update the `dpi-evasion.md` matrix; add operator guides for
  PSK distribution and webtunnel decoy-content setup.

## Acceptance gates (per phase)

1. `cargo check --workspace --all-features` clean.
2. `cargo test -p <new-crate>` green.
3. `cargo clippy --workspace --all-features --tests` zero new warnings.
4. Wire-entropy spot check: capture 1000 handshake bytes from the Phase 1c
   implementation and run a chi-square test for a uniform distribution
   (expected p-value > 0.01).
5. **Phase 1c specifically:** timing-safe MAC compare verified via
   `subtle::ConstantTimeEq` audit.

## Re-open triggers vs out-of-scope items

- **Statistical traffic analysis** (packet timing, volume fingerprinting):
  on hold until either a production incident or an operator request.
- **iat-mode** (inter-arrival timing obfuscation): on hold; significant
  complexity for a marginal entropy gain.
- **`ws://` integration**: on hold until Phase 1c lands, since it needs the
  framing first.
- **`quic+webtunnel`**: on hold until quinn surfaces a clean HTTP/3 routing
  hook, OR an operator explicitly needs QUIC anti-probe.
- **Meek-style on-demand decoy caching**: on hold; high realism, but a large
  code surface, justified only for high-stakes deployments.

## Total estimate

- Phase 1a: **done** (`a977890` — UDP stateless core).
- Phase 1b: **done** (`a977890` — TCP framing core).
- Phase 1c: 1-2 sessions (NTOR + elligator2, crypto-careful).
- Phase 2: 2 sessions (UDP + TCP transport integration).
- Phase 3: 1 session (PSK distribution via transport_hints).
- Phase 4: 1 session (WebSocket variant).
- Phase 5: 2-3 sessions (webtunnel sub-phases 5a–5e).
- Phase 6: 1 session (integration tests + docs).

**~8-10 sessions total** beyond `a977890` for full deployment. The granular
phases mean each step can be reviewed, paused, or re-prioritised on its own.
