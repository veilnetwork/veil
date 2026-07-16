# Changelog

## v0.3.1 — 2026-07-16

Corrective release. The v0.3.0 tag accidentally omitted a signed feature tail
that xVeil already depended on; this release restores that history while
retaining the Rust 1.97, Windows, and poisoned-lock fixes shipped in v0.3.0.

- Restored direct-P2P/relay call routing, full-frame VP8 transport, latency and
  media diagnostics, voice messages, video notes, and group-media support.
- Restored the iOS media plugin integration and mobile lifecycle fixes.
- Restored sovereign recovery, headless Dart/FFI support, and authenticated
  real-time transport APIs.
- Restored onion-provider isolation, capability negotiation, delivery retries,
  and the associated runtime hardening.

`veilclient-ffi` remains on its independent 0.4.x ABI line and
`veil-onion-stream` remains on its independent 0.1.x line.

## v0.3.0 — 2026-07-15

Feature release covering the signed `main` history after v0.2.0.

- Added the embedded, diskless node lifecycle and mobile FFI configuration
  path used by Flutter on Android, iOS, macOS, and Linux.
- Added authenticated offline mailbox sealing, relay replication, fetch/ACK,
  recovery, and sender verification across the Rust, C, and Dart APIs.
- Added reliable anonymous streams, low-latency media channels, and direct-P2P
  media with policy-controlled relay/onion routing.
- Added sovereign identity operations and cumulative-PoW nickname claim and
  resolution APIs.
- Hardened relay discovery, rendezvous registration, circuit recovery, queue
  pressure, and cold-start behavior; leaf deployments are relay-capable by
  default, with operational playbooks for staged rollout.
- Updated `anyhow` to 1.0.103, `crossbeam-epoch` to 0.9.20, and
  `quinn-proto` to 0.11.15, and aligned Android builds on API 24.
- Restored the zero-warning Rust 1.97 gate and made the Unix-only TCP MSS
  clamp a safe no-op on Windows.

`veilclient-ffi` remains on its independent 0.4.x ABI line and the new
`veil-onion-stream` crate remains on its independent 0.1.x line.

## v0.2.0 — 2026-06-14

Minor release. Bundles everything on `main` since v0.1.1 (≈330 commits) plus the
2026-06-14 audit-remediation batch below. **Breaking** vs v0.1.1 (hence the
minor bump, pre-1.0 semver):

- **FFI ABI** — all caller-supplied text inputs migrated to the explicit
  `(ptr, len)` C ABI; the deprecated NUL-terminated phrase entry-points were
  removed. `veilclient-ffi` is at 0.4.0. Regenerate bindings against the shipped
  `veil_ffi.h`.
- **Config** — the dead `gateway_failover_delay_secs` knob was removed; configs
  that set it must drop the key (strict validation rejects unknown keys).
- **Flutter plugin** — `connect` / `restoreIdentity` / stream `read` now run on
  a worker isolate (ANR fix); Dart bindings moved to the explicit-length ABI.

Auto-update: `min_compatible_version = 0.1.1` (the updater swaps the binary;
any install ≥ 0.1.1 may apply this update).

### Audit-remediation batch 2026-06-14 (full-project audit + external report merge)

A full-project security/quality audit cross-validated against an external
report. Validated findings fixed brick-by-brick (clippy `-D warnings` + tests
each commit); already-handled items and false positives recorded, design-heavy
items deferred with a re-open trigger (see `TASKS.md`).

- **lazy-miner never terminates** (F-CRYPTO-1/2) — the background nonce miner
  ground a core indefinitely toward an unreachable difficulty cap (~40% idle
  CPU). Added a full-2³²-nonce-space exhaustion guard + single-sourced the cap
  default (was a hardcoded 64); testnet idle CPU dropped from ~40% to <1%.
- **DHT dead code + foot-gun** (DHT F1/F2/F3) — deleted three unused network
  methods (one returned an *unverified* value), an always-false replica-store
  disjunct, and corrected iterative-filter doc-drift.
- **introduce decode hardening** (Anon F3) — `IntroducePayload::decode` now
  requires exact length, rejecting smuggled trailing bytes.
- **precise rendezvous logging** (Anon F4) — a known-cookie replay/drop is no
  longer mislabelled `cookie_unknown`; the anti-probe signal fires only on a
  genuinely unrecognised cookie.
- **onion path diversity** (M-1) — onion middle-hops and the non-pinned
  rendezvous relay are now drawn at random (was deterministic, concentrating
  traffic and making paths predictable); operator-pinned relays stay ordered.
- **reload-zombie guard** (M-2) — config reload now dry-runs each listener's
  transport URI + context *before* tearing tasks down, closing an
  online-but-dead state on a malformed listen config.
- **interrupt-flag race** (F-CRYPTO-3) — the Ctrl-C PoW-interrupt flag and its
  handler are now installed atomically (single `get_or_init`), so a concurrent
  first-call can't decouple them.
- **obfs4 handshake over-read** (obfs4 F2) — documented the no-pipeline
  invariant + debug-assert it; the truncate path can no longer silently drop
  bytes if framing ever changes.
- **misc** — FFI test CString leak reclaimed; ticket fast-path
  `verified_membership_cert` comment corrected (IPC-status completeness, not a
  security gap).

## Audit batch 2026-06-02 (workspace security + code-quality)

Full-workspace audit of `veil-*` + `veilcore` + `veilclient`,
cross-referenced with a second independent audit report; the union of confirmed
findings was fixed. **Two wire-format changes this batch** (unlike K–P): the
obfs4 ntor handshake shrank by 8 bytes (C-01) and `DeliveryStatusPayload` grew
from 33 to 65 bytes (C-09) — see the per-finding notes.

- **C-01 obfs4 anti-DPI** (`04332d3`) — removed the plaintext 8-byte timestamp
  from the obfs4 ntor handshake (a static DPI distinguisher) and bound the
  epoch-hour into the handshake MAC instead; the receiver accepts a small window
  of candidate epochs for clock skew. `HANDSHAKE_MIN_BYTES` shrank by 8.
- **C-02 / dead code** (`c438de6`) — deleted unused `veil-obfs4::tls_prefix`
  (200 LOC, wired into no transport) and three doc-only `veilcore::node`
  modules (`e2e` / `util` / `battery`).
- **C-03 mesh beacon secure-by-default** (`c7fc064`) — `require_signed_beacons`
  now defaults **true** (unsigned beacons dropped, closing on-link
  gateway-injection / neighbor-redirect); role flags are no longer advertised
  unless the new `advertise_role_in_beacon` is set (default false), so a passive
  on-link observer can't fingerprint gateways/relays.
- **C-04 exit-proxy SSRF** (`fe462fa`) — `is_forbidden_destination` now also
  rejects IPv4-compatible `::x.x.x.x` and CGNAT `100.64.0.0/10` destinations
  (the `::x.x.x.x` form is non-routable on modern Linux; CGNAT was the routable
  residual).
- **C-06 FIND_VALUE node-ids-only** (`c438de6`) — the closest-nodes fallback no
  longer inlines transports; the requester re-resolves via `ResolveTransport`,
  closing the value-lookup routing-graph leak (matching FIND_NODE V2). Guarded by
  a 64-node linear-chain regression (`dc73958`) proving endpoint discovery still
  converges with node-id-only responses.
- **C-09 authenticated DELIVERED ACK** (`3723371`, `cf766af`) — the recipient
  now MACs the `content_id` under a per-message ACK key derived from the E2E
  ML-KEM shared secret (`veil_e2e::derive_ack_key`); the originator credits
  delivery reputation only when the MAC verifies, so an on-path relay can no
  longer forge ACKs to inflate a peer's reputation. `DeliveryStatusPayload`
  33 → 65 bytes (the 32-byte MAC; all-zero on non-E2E / legacy, which earns no
  reputation).
- **C-10 bootstrap dial cap** (`596eef8`) — `MAX_BOOTSTRAP_SEEDS_PER_SOURCE = 32`
  on both the HTTPS and DNS seed loops (startup-amplification / DoS bound).
- **C-12 secret redaction** (`596eef8`) — `IdentityConfig` / `MetricsConfig`
  `Debug` impls no longer print key material.
- **C-14 PSK at-rest** (`596eef8`) — PSK files written `0600` via atomic
  write-then-rename.
- **C-15 pairing document verification** (`3b30cf2`) — the pairing target now
  runs `verify_identity_document` on the received document (node_id↔master
  binding + the master-cert chain over the appended subkeys), not just a node_id
  match; `PairingTarget` carries `now_unix` for the validity-window check.
- **C-16 hybrid verify** (`fe462fa`) — Ed25519+Falcon hybrid verify arms delegate
  to `veil_crypto::verify_message` instead of an open-coded path.
- **U1 hybrid DELETE** (`fe462fa`) — DHT `handle_delete` accepts all wire algos
  (0–4) via `SignatureAlgorithm::from_wire_byte`; the DeletePayload pubkey cap is
  `MAX_SIGNATURE_PUBKEY_BYTES` (was the ML-KEM cap).
- **U2 durable-snapshot scope** (`59cec93`) — the DHT JSON value snapshot writes
  the hot tier only when the cold tier is durable (RocksDB), avoiding a redundant
  re-dump of already-persisted records; it still takes a full snapshot for the
  in-memory cold tier.
- **U3 IPC stream window** (`fe462fa`) — the initial stream window is clamped to
  `MAX_STREAM_INITIAL_WINDOW = 16 MiB` (peer-driven memory-DoS bound).
- **U4 config round-trip** (`fe462fa`) — fixed `SessionConfig::is_default` so
  non-default session knobs survive a serialize → deserialize cycle.

Docs synced in `ab8de0e` (config-reference, ARCHITECTURE_FULL, protocol-spec;
en + ru).

## Audit batch 2026-05-25 (Phases K — P)

Cross-audit follow-up: 26 findings closed, 10 verified false positives,
2 documented-design choices. No new wire-protocol bumps; all changes
are defensive hardening visible only on adversary-shaped input.

- **Phase K** (`a208737`) — gitignore stend secrets; clippy `await_holding_lock`
  attributes on phase650b serialization tests.
- **Phase L** (`3d698f9`) — DHT `find_value` filter consistency with `find_node`;
  Argon2 product cap `MAX_KDF_PRODUCT_KIB = 256 GiB·iter`; admin request
  DoS cap `MAX_ADMIN_REQUEST_BYTES = 64 KiB`; verified e2e ML-KEM HKDF
  binding already covers `dst_id` (audit FP).
- **Phase M** (`705a9ce`) — 8 medium/low findings: Falcon-512 pk size
  invariant via unconditional check; pair_transport frame-oversized
  runtime guard; cursor `read_array<N>` checked_add; obfs4 compile-time
  invariants + pad-len comment rewrite; lookup_cache TTL operator unify;
  identity/verify tautological magic check removed; AppHandle::into_split
  preserves inbound_streams_rx.
- **Phase N** (`c388b19`) — anycast per-record TTL enforcement on resolve:
  `TieredStore::get_with_meta` exposing inserted_at; `resolve_internal`
  filters expired records.
- **Phase O** (`0a8ff0c`) — signed anycast IPC advertise: daemon auto-signs
  anycast records via `SovereignIdentity::ed25519_signing_key()`.
- **Phase P** (`56a76b1`) — 4 defense-in-depth fixes:
  `MetricsConfig` deny_unknown_fields; bootstrap clock-broken fail-closed;
  FCM `expires_in` clamped to `[60, 7200] s`; update-manifest `issuer_pk`
  per-algorithm caps (Ed25519=128 / Falcon-512=1280 / Hybrid=1408 B).

## Wave 1: Scalable Routing (Epics 294-323)

- **294** DHT-routed forwarding: RecursiveRelay O(log N) hop delivery; gossip TTL reduced to 2
- **300** Adaptive routing parameters: K, TTL, fan-out, cache size derived from estimated network size N
- **301** Gossip suppression: proactive gossip replaced by reactive DHT forwarding
- **302** Session pooling: max_concurrent 65K; tx_queue_depth 1024; session hibernate + LRU eviction
- **303** Tiered DHT store: hot/cold HashMap tiers; configurable max_store_entries (1M default)
- **304** Adaptive PoW: epoch-based difficulty; VDF alternative; backward-compatible priority tiers
- **305** Protocol versioning: forward-compatible dispatch; TLV extension; MIN_CORE_ROUTER_MINOR
- **310** Core role with K=40, full routing table, sketch buckets for far keyspace
- **311** Proximity-aware routing: Vivaldi bias in iterative lookup; RTT-based forward scoring
- **312** Compact routing state: sketch buckets (1 contact) for far k-buckets; Core enables at threshold 128
- **313** Mailbox sharding: shard_key-based replica selection; global 100K message cap
- **320** DHT keyspace sharding: 256 shards, 16 per node; shard-aware STORE filtering; rebalancing on join/leave
- **321** Bandwidth-aware transit: congestion backpressure (>78% → drop); adaptive epidemic fan-out
- **322** Reputation system: uptime + relays + vouches; transit gate (200 points); DHT attestation wire format
- **323** Memory budget manager: 256MB default; priority-based component eviction

## Security Hardening (Epics 172-174)

- **172** Sybil/Eclipse/Flood/Replay/Spoofing mitigations
- **173** Mailbox quota fixes (store_forward bypass, quota release)
- **174** Peer nonce auto-update on re-mine

## Code Quality (Epic 306)

- **306** Full codebase audit: 2 CRITICAL (key leak in Debug output) fixed; 3 MEDIUM accepted
