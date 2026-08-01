# Changelog

## Unreleased

### Breaking

- **`CircuitBuilt` ACKs now carry a terminus proof and grew from 4 to 36 bytes**
  (audit VL-01). The ACK's only field was a circuit id, and every hop knows the
  id of the link it sits on — including the first hop, which knows the very id
  the originator matches on. Any hop could therefore synthesise the ACK and
  have the originator mark a circuit CONFIRMED and freeze that path, without a
  byte having reached the terminus: a black hole that looks healthy.

  The originator already generates a fresh `circuit_key` per hop and delivers
  each one sealed to that hop's X25519 key inside the setup envelope, so the
  terminus key is known to exactly two parties and to nobody in between. The
  ACK now carries `blake3::derive_key(<context>, terminus_circuit_key)`, which
  proves both "this came from the terminus" and "this is that circuit" — the
  key is fresh per circuit — and the originator confirms only on a match,
  compared in constant time so a forwarding hop gets no prefix oracle.
  Intermediate hops re-tag the circuit id and pass the token through untouched.

  There is no version negotiation on relay-chain messages and the decode is
  exact-length, so **this is an unnegotiated wire break**: a node of the old
  shape drops these frames and confirms nothing. That is the pre-existing safe
  state — an unconfirmed circuit is re-selected by path maintenance rather than
  frozen — but it does mean circuits do not confirm across a version boundary.
  **Roll relays before clients.**

### Fixed

- **Inbound frame bodies now share a node-wide memory budget.** The 16 MiB
  per-frame cap and the 30-second slow-loris deadline are both *per frame, per
  session*; nothing summed them. Every authenticated session is an independent
  reader that announces a length, allocates a buffer that big, and waits for
  the bytes — so a node holding a thousand sessions, ordinary for a relay,
  admitted a thousand simultaneous reservations of up to 16 MiB each. The
  peers need not be malicious; a synchronised burst of large legitimate
  transfers has the same shape. What makes it cheap to provoke is that the
  body need never arrive: the header alone reserves the memory. A session now
  reserves against `rx_body_budget` (64 MiB default, `VEIL_RX_BODY_BUDGET`)
  before allocating and holds the reservation until the body is consumed, so
  in-flight body memory is bounded regardless of session count. Demand above
  the budget queues rather than allocating, and cannot deadlock because every
  holder is itself bounded by the body deadline. A configured budget below one
  whole frame is raised to it — otherwise a `MAX_FRAME_BODY` frame would wait
  forever on permits that cannot exist. Giving up on the wait sheds the
  session but deliberately does **not** record a violation: saturation is this
  node's condition, and banning peers for our own congestion would turn memory
  pressure into a mesh-wide disconnect storm.

- **The reply-circuit confirmation wait no longer freezes a current-thread
  runtime.** On a multi-thread runtime the wait runs under `block_in_place`,
  which hands the worker's queue to other threads so the `CircuitBuilt` ACK is
  processed during it. On a current-thread runtime the same wait slept on the
  only worker — parking the executor and with it the inbound dispatch that
  would deliver the very ACK being waited for. It could not succeed by
  construction, and cost a full second of frozen networking to fail. That
  flavour now returns immediately: nothing is lost, since the confirmation
  could not have arrived, and the executor stays live so the ACK lands as soon
  as it can. Off a runtime entirely (the FFI admin client) the sleep is
  harmless and unchanged. The unregistered-cookie race remains open on
  current-thread exactly as it already was — closing it there requires the
  wait to be awaited rather than blocked, i.e. an async caller path, which is
  not done here.

- **A late-exiting session runner tore down the state of the session that
  replaced it.** A session owns two kinds of state. Its registrations are
  keyed by `session_id`, so removing them is unambiguous. Everything else it
  installs is keyed by *peer*: the peer's ML-KEM key and per-session DK, its
  observed address and UDP reflectors, its relay tunnels, its rendezvous
  subscriptions, and the routes that run through it — one set per peer, no
  matter how many sessions have come and gone. The teardown removed the second
  kind unconditionally.

  That is fine until a peer reconnects. A NAT'd client re-dialing evicts the
  stale session's tx entry, installs its own, and repopulates the peer-wide
  state through `on_session_opened`. The *old* runner then notices its channel
  closed and exits — and deleted the live session's ML-KEM key, dropped its
  rendezvous subscriptions and reflectors, and broadcast
  `ROUTE_WITHDRAW`/`RouteUpdate(REMOVE)` to the whole mesh for a peer that was
  at that moment connected. The peer stayed reachable while looking
  unreachable, until something re-announced it.

  All three runner-exit paths (inbound, punched-outbound, outbound connector)
  now go through one `session_guard::release_session`, which runs the
  peer-wide half only after a compare-and-remove of the current owner. The
  predicate is "does anyone still hold this peer after we removed ourselves",
  not "did we remove anything" — the latter also reports true after
  `prune_closed` or `force_reconnect_all_peers` cleared the entry with no
  successor, which would strand exactly the state this is meant to reclaim.
  Two of those paths also notified the dispatcher *before* unregistering the
  tx channel, the ordering the inbound path fixed long ago; they now match.

- **The session-close generation bumps on every runner exit, as documented.**
  It is the signal a long-lived circuit handle samples at open time to notice
  its first-hop relay churned. Only the inbound path bumped it, so a circuit
  whose first hop was an outbound session never learned that session had
  ended and kept enqueueing onto a dead route. It now bumps on all three
  paths — and deliberately outside the owner check above: a replacement is
  precisely the churn the handle is asking about, since the old session's keys
  are gone even though the peer is reachable again through the new one.

- **A rejected peer no longer writes to, or evicts from, the per-peer caches.**
  Completing a handshake proves key ownership; it does not mean the session
  will be kept. The expected-peer check, the listener allowlist, the ban list,
  the concurrency cap, directional dedup and the over-cap re-check all run
  afterwards. The seven per-peer caches were written at handshake completion,
  before any of them — so a peer that every gate rejected still got its
  pubkey, roles, cap-flags, ML-KEM key, battery, Vivaldi coordinate, alt-URI
  and membership cert into node-wide state, and, because each cache is capped,
  evicted an entry belonging to a peer we did accept. An authenticated Sybil
  cannot forge another node's `node_id`, but it can handshake in a loop and
  churn the caches of the nodes we actually talk to. `cache_peer_handshake_state`
  is now split into a `prepare_peer_handshake_state` that mutates nothing and a
  `PendingPeerState::commit` that takes `self` by value — so a reject path
  cannot have committed, because committing consumes the value it drops — with
  the single call sitting past the last gate, beside the session-registry
  insert it already guarded.

## v0.4.2 — 2026-07-29

No Rust code changed: `cargo` builds nothing new here. The work is in the
`veil_media` Flutter plugin, which each platform builds with its own script.

### Added

- **A Windows port of the call media engine** (`veil_media/windows/`), the one
  platform it never had — android, ios, linux and macos were all present, so a
  Windows build started, looked healthy and threw at the first voice message.
  Audio needed no new code: `create_audio_device` already falls through to
  WebRTC's Core Audio ADM, so voice messages and audio calls were one build
  away. What was missing is a camera (`veil_mf_camera.cc`, Media Foundation),
  a screen capturer (`veil_gdi_screen.cc`, deliberately GDI rather than DXGI —
  correctness first), a way to reach the two veilclient datagram symbols
  without linking a Rust artifact (`veil_win_datagram_thunk.cc`, GetProcAddress
  rather than an import), and the plugin plus build script to produce the DLL.

  ⚠️ **None of it has ever been compiled.** It was written on a host that
  cannot build it, and the first compile will be the `webrtc-windows` workflow.
  Expect to fix it before a DLL comes out; the file headers say so too. It
  ships in this tag because it is source-only and outside the cargo workspace —
  nothing in a veil build touches it — so a release carries it without carrying
  any risk to the binaries.

### Documentation

### Documentation

- **The deferred obfuscated-UDP transport is written down** (`TASKS.md`). It
  was parked by operator decision on 2026-07-05 and then disappeared: the
  design note lived in a session scratchpad, no backlog row was ever added, and
  the only trace left is the `veil-udp-obfs` crate — which looks like a
  finished feature because it is used, just for something far smaller than what
  was intended. The row states what the crate is (a per-datagram AEAD wrapper
  for mesh realm DATA), what it is not (no handshake, listener, stream or
  reliability layer), what completing it would cost, why it was parked (the
  failure that prompted it was a PMTU blackhole, not DPI), and what re-opens it.


## v0.4.1 — 2026-07-28

macOS call audio. No Rust code changed: the fix is in the `veil_media` Flutter
plugin, which is built by its own script rather than by cargo.

### Fixed

- **Calls on macOS had no audio in either direction.** The audio device module
  applies the app's stored microphone preference with `setDeviceID:` on the
  input node's `AUAudioUnit`. That property is only settable while the unit
  holds no render resources, and merely READING `engine_.inputNode` a few lines
  earlier already allocates them — so the setter returned -10851
  (`kAudioUnitErr_InvalidPropertyValue`) every single time. The failure was
  logged and ignored, but it left the input unit unable to initialise, and
  because the node stays in the graph the whole engine then failed to start
  with -10875 (`kAudioUnitErr_FailedInitialization`). Playout died with it,
  though playout does not depend on the input device at all, and every API
  still reported success: `mic permission=true`, `startAudio=true`.

  Measured on a Mac↔Android p2p call: 0.2 packets/s of 32-byte DTX comfort
  noise from the Mac against the 50 packets/s of real Opus the phone was
  sending, with the Mac's jitter buffer growing past four seconds. After the
  fix both directions carry 50.6 and 50.7 packets/s with buffers steady at
  53 ms and 49 ms.

  Three parts: deallocate the input unit's render resources before setting the
  device; on failure fall back to the system default rather than insisting on a
  device the unit refused; and if the engine still will not start, rebuild it
  once from scratch, because a poisoned input unit stays in the graph and
  restarting the same engine fails identically.

### Note for macOS builders

`libveil_media.dylib` is gitignored and bundled from
`flutter/veil_media/macos/Frameworks/`, so a checkout that never runs
`macos/build_veil_media_dylib.sh` keeps whatever binary is already sitting
there. The copy on the machine where this was found was four days older than
the sources, and nothing in the build output said so.

## v0.4.0 — 2026-07-28

Feature release with security fixes. Two API changes make this a minor bump on
the 0.x line rather than a patch.

### Security

An audit of the transport, session and mesh layers found six defects. All are
fixed here, each with a regression test verified against the broken code.

- **Media injected into an encrypted call.** `dispatch_inbound_auto` decided
  whether a leg was encrypted from the packet's own leading bytes: anything not
  carrying the seal took the legacy passthrough straight to the receive
  callback. The relay path deliberately does not re-wrap media in a fresh
  ML-KEM envelope, so on that leg the seal is the only thing authenticating the
  sender, and the sender id on the Forward frame is not authenticated — anyone
  on the call path could drop raw RTP into a live call, past both the AEAD and
  the replay window. The cipher is now resolved from the registry before the
  branch, so the decision comes from our own state. Channels with no keys keep
  the legacy ingress unchanged.
- **Unbounded broadcast dedup set.** `BROADCAST_SEEN_CAP` gated the TTL sweep
  but never the insert, so a peer minting distinct keys faster than the 10 s TTL
  expired them grew the map without limit — and the O(n) sweep then ran on every
  frame while holding the dispatcher's route-cache write lock. The cap now
  evicts, batched so the scan amortises to O(1) per frame.
- **Reassembly fairness quota defeated two ways.** The per-sender caps were
  checked only when a transfer was created, so a sender could open its full slot
  allowance with 1-byte chunks and then grow each transfer until it owned the
  whole 64 MiB budget; and the quota was keyed on `sender_node_id`, a cleartext
  field of a relayed envelope. Byte quotas now bind on every insertion, and a
  second, deliberately looser quota is keyed on the authenticated previous hop.
- **Signed beacons were replayable for the skew window.** Accepting a beacon
  ends in an unconditional re-register of the source's link at the datagram's
  source address, and the only guard was a per-source rate window. A
  byte-identical capture re-sent from another address repointed the victim's
  link at the replayer for up to 120 s. Signed beacons now carry their
  authenticated content in a replay set for exactly that window.
- **Beacon per-subnet slot cap could stay stuck.** It refused a new address
  without first sweeping expired slots, unlike the global cap beside it, so an
  attacker holding 64 addresses in one /24 locked out every new address from
  that subnet — on a LAN mesh, that is the legitimate neighbours.
- **FFI handle generation escaped its field.** The slot counter is a `u32` but
  the token carries only 16 generation bits on 32-bit hosts, so after 65535
  reuses of one slot every token that slot issued failed validation for good.

### Added

- Anonymous sends spread a fragmented by-identity transfer across a service's
  own provider slots, and `AuthAppDeliver` can carry several reply blocks so a
  fragmented reply can spread too. Together these lift the single-relay ceiling
  on shared-folder throughput.
- Managed packet tunnels for Android, Apple, Windows and Linux, per-application
  VPN routing on Android, and oproxy failover preserved through the Apple
  tunnel.
- Explicit call-path hole punching with typed outcomes, direct-session
  re-establishment on network change, and tolerance for coordinators that
  predate punch tokens.
- Signed public-space DHT records; macOS window sharing; mid-call video bitrate
  retuning with sender-leg metrics.

### Changed

- **Breaking:** `AuthAppDeliver.reply_block: Option<ReplyBlock>` is now
  `reply_blocks: Vec<ReplyBlock>`. The presence byte became a count, so the
  encodings for zero and one block are byte-identical to before; only a genuine
  multi-block envelope differs. Capped at decode.
- **Breaking:** `EnvelopeChunkReassembler::add` takes the authenticated peer id.
- Relay entry verification and anonymous-send resolution are cached, and a
  stored record's signature is no longer verified twice.
- The Linux VPN helper validates its config by open handle rather than by path,
  and `O_NOFOLLOW` refuses a symlink at that path. It runs as root under pkexec
  while the path lives in a directory the invoking user controls, so the
  previous stat-then-read let that user swap what the two calls saw.

### Fixed

- SOCKS dialing is bounded so a silent proxy cannot wedge peer dialing, and the
  RTT probe table is bounded against growth from inbound frames.
- The Falcon private key is kept out of logs and freed memory.
- A service no longer resolves its own registration when it is the host.
- Assorted media and mobile-lifecycle fixes: ADM capture start failures are
  surfaced on both paths, stale realtime stream fallback is bounded, older
  packet-sizing ABIs are tolerated, dynamic-lookup imports stay out of the macOS
  dylib exports, and the QR scanner moved to Apple Vision.

`veilclient-ffi` remains on its independent 0.4.x ABI line, `veil-onion-stream`
on its 0.1.x line and `veil-vpn-helper` on its 0.1.x line.

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
- Regenerated the feature-gated C header and aligned the restored tail with the
  Rust 1.97 warning policy across the workspace, embedded FFI, and simulations.

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
