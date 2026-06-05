# Veil — план эпиков

Файл отслеживает прогресс по спецификации (`specification.md`).
Каждый эпик завершается переходом к следующему через задачу переанализа.

> Завершённые эпики (0–446, 447, 450, 452, 453, 454, 458, 460, 461, **462 (multi-device identity, code + acceptance fully closed), 476 (Sovereign Identity simplification — S3 absorbed by Epic 477), 479 (Latency-aware routing — absorbed by 137/142/144), 481 (Out-of-band bootstrap — 5 items shipped; in-band-introducer + .onion parked в deferred-backlog), 482 (Optional anonymity — 7 items + integration tests + AS diversity shipped; anti-loop TTL + stateful CircuitId parked в deferred-backlog), 483 (Mobile / battery / NAT — 6/7 sub-tasks shipped + 2 deferred slices opt-in default-off 2026-05-06; 483.2 push-notification → Epic 489), 484 (Operational deployment — 484.1 + 484.3 + 484.5 shipped; 484.6 dropped как architecturally incompatible с anti-censorship целью), 485 (Adversary validation — 485.2 + 485.3 + 485.4 + 485.5 shipped; 485.1 partial closure (3 sub-scenarios shipped, ID-grinding/bucket-pollution/churn extensions parked в deferred-backlog); 485.6 skipped per operator decision), 486 (Post-quantum readiness — все 4 sub-tasks shipped + cross-host stand-verified GA), 487, 488, 489.1, 489.4, 489.5, scanner-shield 6.30, Phase 6.47 internal audit, Phase 6.45 closed findings (incl. H9 verified + H12 shipped 2026-05-06), Phase 6.48 closed (5 batches + final A2 caller-wiring 2026-05-06; R1-R4 + X1-X2 cleanup parked, A1+A8 deferred к future epic), Epic 462.44 quota wire-up**) перенесены в [`TASKS_ARCHIVE.md`](TASKS_ARCHIVE.md).
>
> В этом файле остались эпики с **open items** (deferred / backlog).  Состояние на 2026-05-23 (post cross-audit batch):
> * Остатки **Epic 489 (Flutter mobile)**: 489.10 HMAC-auth wakeup + drainMailbox helper + push-relay reference impl + iOS BG "drained" signal hook (см. row).  Остальные 489.x ✅ closed.  iOS APNs token storage upgraded к Keychain в cross-audit batch 2026-05-23.
> * Остатки **anti-censorship roadmap**: bandwidth-mimicry (landing-pad ready, ждёт pcap fixture от operator; fail-closed validation добавлен в cross-audit batch 2026-05-23); frame-timing-jitter, HTTP/2-shape padding, WebRTC-snowflake transport (новые слои, не блокируют).
> * **Deferred large-scope backlog** (re-open triggers заданы): 6 items, см. таблицу ниже.
> * **Cross-audit batch 2026-05-23**: 9 findings closed (IPC streams A/B + bounded mpsc + mailbox quota + Anycast SignedBound + TProxy + bandwidth_mimicry + iOS Keychain + DHT byte-cap + IPC forwarding deferred-closure).  См. секцию ниже.
> * **Operator-triggered actions**: stealth-canary на node1 active (см. row); stress-soak overrides уже reverted.

---

## PoW-Gated Rendezvous epic (closed 2026-05-20)

Stealth-listener architecture: nodes can configure `visibility = "stealth"` listeners that do NOT bind а port at startup.  Port comes alive on-demand only после а valid PoW-gated request lands.  Closes DPI methods #4 (IP-dict), #6 (block_options=2 all-ports), #16 (IPSNI rollback), #17 (IP/SNI priority).  See [`docs/en/PLAN_POW_GATED_RENDEZVOUS.md`](docs/en/PLAN_POW_GATED_RENDEZVOUS.md) for the design + [`docs/en/ANTICENSORSHIP_STRATEGY.md`](docs/en/ANTICENSORSHIP_STRATEGY.md) для the post-epic DPI assessment.

**Slices shipped (2026-05-20)**:
1. Slice 1 (`09007bc`) — wire frames + PoW primitives (`crates/veil-proto/src/rendezvous.rs`).
2. Slice 2 (`adcacc0`) — on-demand listener controller (`crates/veil-transport/src/on_demand.rs`).
3. Slice 3 (`30ddddd`) — server-side `RendezvousController` (`veilcore/src/node/rendezvous.rs`).
4. Slice 4 (`2c4db18`) — initiator client SDK (`veilclient/src/rendezvous.rs`).
5. Slice 5a/5b/5c (`b08f553` + `aac23fe` + `6fca88b`) — config schema + runtime wiring + production binder + bounded accept task.
6. Slice 6 (`06395cb`) — mediator-relay via `RecursiveQuery` (closes the relay-routing gap via existing DHT routing infrastructure rather than inventing а new wire frame).
7. Slice 7 (`840f888`) — Prometheus metrics (9 surfaces: `veil_rendezvous_requests_{received,granted,rejected_*}_total` + `veil_rendezvous_slots_in_use`).
8. Slice 8 (`c5a6111`) — end-to-end integration tests.
9. Slice 9 (`7459be0`) — operator canary playbooks (`ansible/{enable,revert}-stealth-canary.yml`) + bilingual operator docs.

**Follow-ups (2026-05-20)**:
1. **SDK response-await glue** (`60aff90`) — `NodeRuntime::request_rendezvous_endpoint(...)` + `RendezvousEndpoint` + `RendezvousClientError` (~250 LOC).  Full initiator flow: validate PoW bounds + target identity binding → pick top-2 closest peers by XOR distance → mine PoW + sign payload → wrap в `RecursiveQuery{type=RENDEZVOUS_REQUEST}` → register `PendingRecursive` → ship at INTERACTIVE priority → await oneshot с user timeout → decode + verify response.
2. **Multi-stealth-listener support** (`bc1017f`) — `RendezvousPolicy.extra_destinations: Vec<AdvertiseDestination>` + round-robin pick over `[primary] ++ extras`.  Service layer batches all stealth listeners into one wire-call; node-wide policy fields (`pow_difficulty`, `rate_limit`, `max_concurrent`) validated к match across listeners.  3 new tests.
3. **Live testnet canary** (deployed 2026-05-20 ~21:32 UTC on node1) — verified controller wires, zero stealth-range LISTEN sockets, все 9 metrics surfaces present.  Caught (and fixed in `849fe38`) а pre-existing bug where Slice 5b/5c was extracting hosts via `TransportUri::plaintext_host()` (returns None для obfs4-tcp by design — DPI-visibility classifier).  Added `TransportUri::host()` accessor с regression test.

**DPI coverage**: post-epic, single-host deployment closes 19/35 DPI methods (vs 15/35 pre-epic); ~85% of maximum achievable resilience.  Remaining 4 gaps require ops-time work (DoT/DoH, webtunnel Let's Encrypt cert) or out-of-scope infrastructure (multi-AS hosting).

**State on live testnet**: canary active on node1 only; see [Operator-triggered actions](#-active--stealth-listener-canary-on-node1-pow-gated-rendezvous-epic-applied-2026-05-20-2132-utc) for roll-forward/revert commands.

---

## Phase 6.50.d.6 — Consolidated security/quality audit follow-up (2026-05-14)

Тройной аудит (internal + 2 external reports) выявил набор реальных проблем. Findings скрещены, false-positives отброшены. План в строгом порядке зависимостей: blockers → security → operational → polish.

### 6.50.d.6.1 — **BLOCKER**: workspace compilation broken (CRITICAL)

**Status:** ✅ shipped (commit `652c132`).  Завершили PooledShared migration на public-SDK boundary через `pooled_shared_from_vec` (send) + `to_vec()` (receive); 4 sites обновлены: `veilclient/src/handle.rs` (2 sites), `client.rs:1177`, `voice_stream.rs:93`.  Бонус — dead-code cleanup #11 + #12 (см. 6.50.d.6.4).  `cargo check --workspace --all-targets`: clean.

### 6.50.d.6.2 — Security fixes (HIGH/CRITICAL)

**Status:** ✅ all 6 shipped (commit `00ab996`; item #16 comment-sweep dragged по same path).

1. ✅ **session_id constant-time compare** — `subtle::ConstantTimeEq::ct_eq` для session_id ([handshake.rs:1237](veilcore/src/node/session/handshake.rs#L1237)).
2. ✅ **`VeilStream::Drop` runtime guard** — `Handle::try_current().is_ok()` перед `tokio::spawn` ([stream.rs](veilclient/src/stream.rs#L263)).
3. ✅ **`bind_with_flags` race** — waiter регистрируется перед `APP_BIND` write; cleanup на всех error paths ([client.rs:344+](veilclient/src/client.rs#L344)).
4. ✅ **HTTPS ALPN** — `h2` удалён, остался только `http/1.1` ([https.rs:342](crates/veil-bootstrap/src/https.rs#L342)).
5. ✅ **Hybrid handshake algorithm binding** — алгоритм связан через transcript hash (не отдельный MAC byte, но эквивалентная защита) ([handshake.rs:1120-1220](veilcore/src/node/session/handshake.rs#L1120)).
6. ✅ **FFI double-free protection** — `magic: AtomicU32` sentinel + atomic swap на handle close ([veilclient-ffi/src/lib.rs:123](crates/veilclient-ffi/src/lib.rs#L123)).

### 6.50.d.6.3 — Operational hardening (MEDIUM)

**Status:** ✅ all 4 shipped (commit `94ea449`).

7. ✅ **IPC HELLO exact-size + 5s timeout** — pre-allocation check `body_len == AppIpcHelloPayload::WIRE_SIZE`, stack-array вместо heap ([server.rs:1278](crates/veil-ipc/src/server.rs#L1278)).
8. ✅ **Outbox per-blob + aggregate quotas** — `MAX_OUTBOX_BLOB_BYTES = 4 MiB`, `OutboxConfig::quota_total_bytes` (default 50 MiB) через `outbox_meta_v1` running-total table ([outbox.rs:78](crates/veil-mailbox/src/outbox.rs#L78)).
9. ✅ **update_apply fsync parent dir** — `File::open(parent).sync_all()` после rename ([apply.rs:226-229](crates/veil-update/src/apply.rs#L226)).
10. ✅ **`poll_shutdown` partial-write** — `shutdown_pending: Option<Vec<u8>>` buffer; close frame driven к completion across `Poll::Pending` ([stream.rs:34](veilclient/src/stream.rs#L34)).

### 6.50.d.6.4 — Polish + dead code

**Status:** ✅ all 6 shipped — #11+#12 в commit `652c132` (bundled с BLOCKER), #13-#15 в commit `44b4dc6`, #16 в commit `00ab996` (one-shot rewrite в составе #3 fix).

11. ✅ `PeerLruCache::new()` удалён — production paths используют `with_capacity` (commit `652c132`).
12. ✅ Unused `use std::sync::Arc` удалён из [shared_slab.rs](crates/veil-bufpool/src/shared_slab.rs) (commit `652c132`).
13. ✅ HTTPS `Content-Length` conflict → `HttpsBootstrapError::ContentLengthConflict`, 2 test cases (identical-duplicate accept + distinct-conflict reject) (commit `44b4dc6`).
14. ✅ `tx_queue_estimated_bytes` honest worst-case bound — `AVG_FRAME_BYTES = 16 KiB`; metric documented as worst-case envelope ([tx_registry.rs:305-322](veilcore/src/node/session/tx_registry.rs#L305)) (commit `44b4dc6`).
15. ✅ `MAX_FALCON_SIG_BYTES = 768` (752 NIST max + 16 B margin) ([signature.rs:207](crates/veil-crypto/src/signature.rs#L207)) (commit `44b4dc6`).
16. ✅ Stale comment на [client.rs:344](veilclient/src/client.rs#L344) переписан вместе с #3 fix (commit `00ab996`).

### 6.50.d.6.5 — Misc defensive polish (shipped 2026-05-14)

21. `session_kdf` self-handshake (`local_node_id == remote_node_id`) explicit-stability tests ([session_kdf.rs](crates/veil-crypto/src/session_kdf.rs#L379)) — `<=` role-assignment footgun guard для future refactor flipping к `<`.
22. `ban_threshold.expect()` invariant doc-comment ([runtime/mod.rs:1137](veilcore/src/node/runtime/mod.rs#L1137) + [lifecycle.rs:481](veilcore/src/node/runtime/lifecycle.rs#L481)) — `.max(1)` clamp makes the expect provably unreachable; commented tripwire так что future refactor removing the clamp surfaces here.

### 6.50.d.6.6 — Architecture

24. ✅ `SessionTxRegistry` `Mutex` → `RwLock` для parallel send_to() (commit `d885ce2`).
25. ✅ `SessionGuard::drop` snapshot-then-publish (commit `bd5d104`).
26. ✅ `dispatcher/delivery.rs` helper extraction shipped в 3 stages:
    - Stage A: lift `HopAttrs` к module scope — commit `7bd64d1`
    - Stage B+C: extract `gather_relay_candidates` (~95 LoC, encapsulates 3 lock scopes)
      + `apply_ecmp_pinning` (~50 LoC, pure flow-hash rotation) — commit `c1ab0fc`

    Net: `relay_forward` shrunk from ~600 to 522 LoC.  Two pure helpers
    extracted с typed return alias `RelayCandidates`.  Dispatcher tests
    111/111 pass.  Drive-by: fixed pre-existing `redundant_field_names`
    clippy errors в CryptoState init sites.

23. ✅ `SessionRunner` 35+ fields decomposition shipped в 4 stages:
    - Stage 1: `MobileConfig` (5 fields) — commit `833c62e`
    - Stage 2: `RekeyConfig` (2 fields) — commit `7537427`
    - Stage 3: `HotStandbyState` (5 fields) — commit `ab4c17e`
    - Stage 4: `CryptoState` (4 fields, hot crypto path) — commit `ebe3279`

    Net: 16 sibling fields → 4 typed bundles.  ~120 construction sites
    updated across 4 production paths (runtime/mod.rs, outbound_connector.rs,
    chaos_sim.rs) + ~30 test fixtures in runner.rs.  Migration done via paren-
    balanced Python rewriter per stage with cargo check after each.  177/177
    session tests pass на CryptoState (final + highest-risk stage).

### Deferred (out-of-scope для этого batch'а)

- ~~Ban-list constant-time response~~ ✅ done (2026-05-21): `BAN_DROP_PAD = 50 µs` spin-pad на early-ban-check site в [`crates/veil-dispatcher/src/lib.rs`](crates/veil-dispatcher/src/lib.rs); test `banned_peer_drop_pads_to_constant_time` verifies floor + jitter ceiling. Phase 5q's CPU savings preserved (only the pad's ~50 µs of busy-loop CPU paid, не full pipeline).
- ~~Cover-frame body allocation pooling~~ ✅ done (2026-05-21): `build_cover_frame` теперь acquires а `Pooled` buffer от `veil-bufpool::global()`, writes header + random body in-place, и returns `PooledShared` directly. Removes the `vec![] → pooled_shared_from_vec(...)` round-trip at [`runner.rs`](crates/veil-session/src/runner.rs) cover-emit site. Test `cover_frames_hit_pool_after_warmup` verifies cache_hit_total climbs + fallback_alloc_total stays flat. Low-frequency path (~1/30s/session), но aligns с the surrounding pooled-buffer plumbing.

### Не-issues (false positives отбрасываем):

- ❌ `signature.rs:392` `VerifyingKey::from_bytes(&ed_pk.try_into().expect(...))` panic — split_hybrid_pk **верифицирует длину** до slice, `try_into::<[u8; 32]>` от 32-байт slice не panic'нет. Report B audit error.
- ❌ Integration test `.unwrap()` (mod.rs:54-220) — это **тест**, .unwrap() в тестах — норма.
- ❌ libc::geteuid() on Windows — уже cfg-gated в veil-local-transport.
- ❌ `per_session_mlkem_dk` explicit cleanup в SessionGuard::drop — **уже сделано** в [runtime/mod.rs:4935](veilcore/src/node/runtime/mod.rs#L4935) (line: `lock!(inbound.runtime.identity.per_session_mlkem_dk).remove(&peer_id);`).  Мой собственный audit miss — отбрасываю.
- ❌ DHT STORE per-owner quota (Report 3 recommendation, claimed "SECURITY.md TBD") — fabricated reference; SECURITY.md единственный TBD = "Reputation cold start", не DHT.  Структурно signed-STORE уже ограничен 1 entry per identity через [`verify_store_ownership`](crates/veil-dht/src/kademlia.rs#L1591) (требует `BLAKE3(pubkey) == key`).  Production unsigned-path использует [`identity_write_quota`](crates/veil-abuse/src/identity_quota.rs) (10 writes/hour per node_id — Epic 462.44).  Quota-on-quota = dead defense-in-depth; reverted [после first-pass implementation](https://github.com/veil/veil/commit/HEAD).
- ❌ TUN feature runtime warning — `TunConfig` есть в crate'е но не интегрирован в runtime startup; warning без integration premature.
- ❌ ban_threshold `.expect()` "panic risk" (Report 3 H3) — caller использует `.max(1)`, `.expect()` provably unreachable.  Доку-clarification добавлен (6.50.d.6.5 #22).
- ❌ `pair_transport.rs:123` XXX-comment — это example placeholder format ("XXX-YYY" как формат OOB кода в docstring), не TODO.

---

## Audit batch 2026-05-21 (post-Phase-6 sweep)

Multi-agent security/quality аудит + cross-reference external audit B (2026-05-21).  6/7 dimensions clean.  Phase 6 extraction structurally sound — все "✅ done" tasks из TASKS.md verified working, не scaffold.

Open findings outside existing backlog rows (Epic 489.10 push items, Epic 481/482 backlog — все уже tracked).  План phases по acting-priority:

### Phase A — Gates closure (1 PR, ~1 hour, mechanical)

1. ~~**4 mutex-poison policy violations**~~ ✅ done (2026-05-21, commit `70a5bdc`): all 4 raw `.lock().unwrap()` / `.lock().expect()` sites rewritten к `lock!(...)`: 2 sites в [`crates/veil-node-runtime/src/runtime/p_net_ban_sync.rs`](crates/veil-node-runtime/src/runtime/p_net_ban_sync.rs) + 2 sites в [`crates/ogate/src/bridge.rs`](crates/ogate/src/bridge.rs).  `scripts/check-mutex-poison-policy.sh` clean.  Root cause of regression covered separately в Phase E19 (CI hygiene job only ran on tag pushes, не на PRs).

2. ~~**3 dead-code anchor violations**~~ ✅ done (2026-05-21, commit `70a5bdc`): [`crates/veil-session/src/session_alias_guard.rs`](crates/veil-session/src/session_alias_guard.rs) — 2 sites moved into а struct-level `#[allow(dead_code)]` block с anchor docstring (single annotation governs all fields); [`crates/veil-cli/src/cmd/invite_cmd.rs`](crates/veil-cli/src/cmd/invite_cmd.rs) — `_doc_link_to_config_mutation` dummy fn replaced с а doc-comment breadcrumb (no Epic scheduled).  `scripts/check-allow-dead-code-anchors.sh` clean.

3. ~~**Undeclared cfg-features в veil-node-runtime**~~ ✅ done (2026-05-21, commit `70a5bdc`): `[features]` table added к [`crates/veil-node-runtime/Cargo.toml`](crates/veil-node-runtime/Cargo.toml) declaring `production-seeds`, `allow-empty-seeds`, `rocksdb-cold`, `test-low-difficulty`, и cascading к the upstream crates that actually implement them (veil-bootstrap, veil-dht, veil-crypto, veil-proto).  7 `unexpected_cfgs` warnings closed; `admin.rs::node show` now reports correct build_features.

4. ~~**Truly-dead stubs**~~ ✅ done (2026-05-21, commit `70a5bdc`): `apply_ipv6` stub в [`crates/ogate/src/tun/mod.rs`](crates/ogate/src/tun/mod.rs) deleted (never called; platform-abstraction design abandoned).

### Phase B — Targeted security fixes (3 small PRs)

5. ~~**HTTPS bootstrap signed-bundle enforcement**~~ ✅ done (2026-05-22): new `BootstrapHttpsPolicy` struct + `fetch_seeds_https_with_policy` API в [`crates/veil-bootstrap/src/https.rs`](crates/veil-bootstrap/src/https.rs).  Three policy modes: `signed_required(pubkey)` (production default — verify envelope против pinned issuer, reject raw JSON); `signed_preferred()` (accept signed-but-unpinned, still reject raw); `legacy_unsigned()` (testnet/dev opt-in — accept BOTH signed и raw).  Service-task wiring в [`crates/veil-node-runtime/src/runtime/service_tasks.rs`](crates/veil-node-runtime/src/runtime/service_tasks.rs) selects policy от config: `trusted_bundle_issuer_pubkey` → signed_required; absent + `legacy_allow_unsigned_bootstrap = false` (default) → signed_preferred; absent + flag true → legacy_unsigned.  New config field `GlobalConfig::legacy_allow_unsigned_bootstrap: bool` (default false).  Wire-format detection via leading `"SB"` magic bytes (signed envelope) vs JSON `[` prefix (raw bundle); `decode_with_policy` exposed как pure fn для unit testing.  5 policy-matrix tests verify accept/reject decision matrix: signed+pinned accepts matching, rejects raw JSON, rejects wrong issuer; signed-preferred rejects raw; legacy accepts both.  `SignedBundleError` now `#[derive(Clone)]` к support `HttpsBootstrapError::SignedBundleVerify(#[from] ...)`.  **Migration**: production deployments using `bootstrap_https_urls` без а signed bundle must either generate one (via existing `sign_bundle` API) и set `trusted_bundle_issuer_pubkey`, OR set `legacy_allow_unsigned_bootstrap = true` explicitly как temporary opt-in.  Closes the TLS-endpoint-compromise vector (CDN, CA, hosting account, mirror endpoint).
6. ~~**Ticket instance-binding deprecation enforcement**~~ ✅ done (2026-05-22): `TicketIssuer::issue()` gated за `#[cfg(test)]` в [`crates/veil-session/src/ticket.rs:138`](crates/veil-session/src/ticket.rs#L138).  Compile-time barrier — production callers cannot reach the legacy 4-arg path без adding `#[cfg(test)]` themselves.  All existing call sites verified inside `mod tests` blocks (10 sites в ticket.rs tests, 1 site в handshake.rs `session_resumption_fast_path_succeeds` test).  Closing this latent vector: two sovereign instances одного identity calling `issue` concurrently → identical-plaintext tickets → server activates two sessions с same `(tx_key, rx_key)` → AEAD nonce-counter restart-from-zero collision → plaintext recovery via ciphertext XOR.  Re-opening это requires either multi-instance metadata propagation в handshake OR instance-distinct KDF derivation.  197/197 veil-session lib tests pass.
7. ~~**Handoff transport peer_id continuity**~~ ⚠ **downgraded к low + deferred** (2026-05-22) — agent originally rated medium, but deeper analysis shows real impact is **race-DoS only, не key recovery**.  Attacker can passively observe plaintext HandoffAttach bytes, race against legitimate initiator's `HandoffRegistry::consume`; if attacker wins, their raw socket attaches к session S — но attacker has no session keys, so frames R sends ара AEAD-encrypted и unintelligible, и на attacker's first attempt к send R drops the session.  Net impact: transient DoS, not confidentiality break.  Real fix requires wire-format change (bind HMAC к listener identity OR add challenge-response gate).  **Documentation update shipped 2026-05-22**: [`crates/veil-proto/src/session.rs:1670`](crates/veil-proto/src/session.rs#L1670) wire-docstring now accurately describes the race-DoS surface (previous comment incorrectly claimed "replay requires both nonce AND key").  Deferred к а future wire-format epic if real exploitation observed.
8. ~~**unknown_origin_gossip_quota wire-up**~~ ✅ **resolved by deletion 2026-05-22**.  Investigation showed the quota field was orphaned by а design pivot, не а wire-up gap: **post-461.7 invariant** ("via_node_id MUST equal transport-layer peer_id; divergence is Violation") killed the forward-then-verify Sybil path entirely без а wire-format change.  Sybil who spoofs `via_node_id` gets banned, не rate-limited.  UnknownKey path simply drops [`crates/veil-dispatcher/src/routing.rs:295-300`](crates/veil-dispatcher/src/routing.rs#L295) (not forwarded), so per-peer quota has nothing к gate.  Field `unknown_origin_gossip_quota`, init sites (2 в dispatcher, 1 в node-runtime, 1 lifecycle reload), и budget consts (`MAX_UNKNOWN_ORIGIN_GOSSIP_PER_WINDOW`, `UNKNOWN_ORIGIN_GOSSIP_WINDOW_SECS`) all removed.  Metric `unknown_origin_gossip_rejected_total` retained для dashboard stability с docstring update — semantics ара now "via spoof Violation count", не "quota drop count".
9. ~~**CStr unbounded FFI scan**~~ ✅ done (2026-05-22): added `MAX_FFI_CSTR_LEN = 4096` (Linux PATH_MAX) + two bounded helpers в [`crates/veilclient-ffi/src/lib.rs`](crates/veilclient-ffi/src/lib.rs): `cstr_to_str_with_len` (bounded scan + UTF-8 decode + length) и `ffi_cstr_len_bounded` (length-only, for zeroize sites що need scrub-length before UTF-8 check).  Existing `cstr_to_str` rewired через `cstr_to_str_with_len` — every caller now bounded.  4 explicit `CStr::from_ptr` external-input sites converted: 2 phrase-validate (`veil_validate_bip39_phrase_zeroize`), 2 phrase + password в restore-from-phrase paths.  Test `ffi_cstr_bounded_scan_accepts_and_rejects` verifies (1) normal NUL-terminated CString accepted, (2) NULL rejected, (3) `MAX_FFI_CSTR_LEN+16` byte buffer без NUL rejected (no OOB scan).  Remaining 3 `CStr::from_ptr` sites read internally-allocated error strings (test code) — internal trust, safe.  25/25 FFI lib tests pass.

### Phase C — DoS/resource hardening (medium effort)

10. ~~**DHT defaults memory envelope**~~ ✅ partial done (2026-05-22): `DhtConfig::default_max_store_entries()` lowered от 1_000_000 к 100_000.  Worst-case memory drops от ~4 GiB к ~400 MiB (`100_000 × MAX_DHT_VALUE_BYTES = 4 KiB`).  Mirror в [`crates/veil-dht/src/traits.rs`](crates/veil-dht/src/traits.rs) `DhtRuntimeConfig::default()` updated к match.  Docs [`docs/en/OPERATIONS.md`](docs/en/OPERATIONS.md) + [`docs/en/CAPACITY.md`](docs/en/CAPACITY.md) updated с new default + opt-up guidance для dedicated DHT infra (1M).  Cfg tests `dht_config_non_default_roundtrip` + `dht_defaults_match_old_hardcodes` pass.  **Still deferred**: byte-based cap (`max_store_bytes` field tracking total memory regardless of entry count) — requires `TieredStore` к track bytes per insert, larger change.  `allow_unsigned_store = true` default kept; flipping disrupts every legacy network using inner-sig pattern.  Migration story для unsigned-store flip belongs к а follow-up epic.
11. ~~**Anycast policy enum**~~ ✅ partial done (2026-05-22): runtime policy plumbing shipped.  New `AnycastResolvePolicy { BestEffort, SignedOnly }` enum в [`crates/veil-anycast/src/lib.rs`](crates/veil-anycast/src/lib.rs); `AnycastService::with_policy(policy)` builder; `resolve()` now dispatches via policy (SignedOnly → silently drops v1 unsigned records).  Config field `Config.anycast.resolve_policy: AnycastResolvePolicyKind` в [`crates/veil-cfg/src/model.rs`](crates/veil-cfg/src/model.rs) с TOML serde `snake_case`; default `best_effort` (backward compat).  Service-task wiring в [`crates/veil-node-runtime/src/runtime/service_tasks.rs:757`](crates/veil-node-runtime/src/runtime/service_tasks.rs#L757) translates config kind к runtime enum и chains `.with_policy(...)` after `AnycastService::new`.  Two new tests `resolve_with_signed_only_policy_filters_v1` + `resolve_with_best_effort_policy_returns_all` verify dispatch behaviour.  Production deployments routing trust-sensitive traffic через anycast (mailbox-discovery, service-discovery) should set `[anycast] resolve_policy = "signed_only"`.  **Still deferred**: `SignedWithReputation` variant (combines signed-only filter с failure-tracking downweight) — requires а new IPC reverse-direction frame для "resolution result failed in use" feedback, larger design.  `AnycastReputation::record_failure` remains test-only wired; IPC fail-feedback opcode belongs к follow-up epic.

### Phase D — Architecture polish

12. ~~**Veilcore re-export shim cleanup**~~ ✅ done (2026-05-22): Phase 4 re-export shim block в [`veilcore/src/node/mod.rs`](veilcore/src/node/mod.rs) pruned от 25 lines + 2 flat re-export blocks (admin items, state/types items) к а single line: `pub use veil_node_runtime::{NodeError, NodeRuntime, Result};`.  All 17 consumer sites swept к direct sibling-crate paths: 8 veil-cli/cmd/* files now `use veil_node_runtime::admin as node` (debug.rs, handlers.rs, sovereign_identity.rs, peers_cmd.rs, mobile_cmd.rs, pex_cmd.rs, node_cmd.rs, network_cmd.rs, sessions_cmd.rs, service.rs, util.rs) + 7 veilcore tests/benches files (frame_broadcaster_adapter, discovery_auto_publish, mesh_bridge_integration, dht_key_domain_separation, dht_lookup, session_scale, voice_stream, dht_store_throughput, socks5_throughput) + 2 internal veilcore sites (sim/node.rs PeerId, session/runner_tests.rs types::NodeId) rewired к `veil_cfg::PeerId` / `veil_node_runtime::types::NodeId`.  veil-identity Cargo.toml description path also updated (veilcore::node::identity::publisher_dht → veil_node_runtime::identity_local::publisher_dht).  `cargo check --workspace --all-targets`: clean.
13. ~~**bufpool no-op shim removal**~~ ✅ done (2026-05-22): `veilcore/src/node/bufpool.rs` deleted (just а forwarder к `veil_bufpool::global()` с no remaining consumers); `pub(crate) mod bufpool` declaration removed от `veilcore/src/node/mod.rs`; feature flag `bufpool-inbound` removed от `veilcore/Cargo.toml` и cascade-removal в `veil-cli/Cargo.toml`.  Stale comment в `crates/veil-session/src/runner.rs` updated к reflect actual pool-cap control via `VEIL_BUFPOOL_CAP` env var.
14. ~~**Integration-test decoupling**~~ ✅ done (2026-05-22): `veilcore/src/node/session/runner_tests.rs` (5568 LoC) extracted к new crate [`crates/veil-session-integration-tests`](crates/veil-session-integration-tests/).  New crate manifest pins direct sibling-crate dependencies (veil-session, veil-dispatcher, veil-proto, veil-transport, veil-cfg, veil-node-runtime, veil-bufpool, veil-e2e, veil-observability, veil-types, veil-util) plus dev-deps for crypto fixtures (blake3, base64, ed25519-dalek, tokio test-util).  All in-file imports rewritten: `super::*` → `veil_session::runner::*`; `crate::cfg::*` → `veil_cfg::*`; `crate::crypto::*` → `veil_crypto::*`; `crate::proto::*` → `veil_proto::*`; `crate::transport::*` → `veil_transport::*`; `crate::node::session::*` → `veil_session::*`; `crate::node::e2e::*` → `veil_e2e::*`; `crate::node::observability::*` → `veil_observability::*`.  Two specific inline imports (one mid-test inside а `#[tokio::test]` block) also rewired.  `mod runner_tests` declaration removed от `veilcore/src/node/session/mod.rs` с docstring breadcrumb pointing к the new location.  67/67 extracted tests pass в 18.7 s.  Pre-existing sim/scenarios failures (TLS-based Connection refused в sandbox) verified pre-D14 too — unrelated к extraction.
15. ~~**Stale Flutter comments**~~ ✅ done (2026-05-22): `stream.dart` top-of-file comment updated к reference the actual `NativeFinalizer` block at line ~37 (was "deferred follow-up" — но finalizer уже shipped в same file).  `pairing.dart` comment updated к point к `share_invite.dart` instead of claiming generator-side "deferred".

### Phase E — Long-tail polish (deferred)

16. ~~**Falcon sig length cap on sign-side**~~ ✅ done (2026-05-22): `sign_message` для `Ed25519Falcon512Hybrid` now checks `fal_sig_bytes.len() > MAX_FALCON_SIG_BYTES` после `falcon512::detached_sign` и returns `ConfigError::InvalidCryptoMaterial` if exceeded.  Robustness: future `pqcrypto-falcon` regression OR patched build producing oversized signatures now fails fast at sign-time instead of silently shipping signatures que verifiers reject.  4/4 signature tests pass.
17. ~~**Grace ring opportunistic prune**~~ ✅ done (2026-05-22): inserted `rx_cipher_prev.prune_expired(now)` immediately before the cover-traffic check в the session-runner main loop ([`crates/veil-session/src/runner.rs`](crates/veil-session/src/runner.rs)).  Cover-due tick fires every cover-interval (~30 s), so this is effectively "prune once per cover cycle" — zero hot-path cost, bounds worst-case retention to one cover-cycle even при stuck rekey + silent peer.  Previous behaviour: prune fired only on decrypt attempts, so silent sessions с in-flight rekey held old rx ciphers for the full 30-s grace window.
18. ~~**Massive unused-import sweep**~~ ✅ done (2026-05-22): 44 unused-import warnings → 0 across the workspace.  `cargo fix --workspace --all-targets --allow-dirty` swept 40 sites automatically (veil-node-runtime services.rs, lifecycle.rs, routing_state.rs, ephemeral_rotator.rs, dht_fallback.rs; veil-dispatcher lib.rs; veilcore node/{battery,e2e,mod,util}.rs + sim/{loss,network,node,scenarios}.rs).  4 residue sites cleaned manually: dropped now-dead `wlock` from veil-dispatcher/src/lib.rs, dropped `TransportConnection` от services.rs's import block, replaced veilcore/src/node/util.rs's `pub(crate) use veil_util::unix_secs_now_u64` shim line с а docstring breadcrumb (no remaining consumers), promoted veilcore/src/node/mod.rs's `pub(crate) use veil_types::PeerLruCache` к а test-scoped `use veil_types::PeerLruCache` inside the LRU-cache test mod (only consumer).  `cargo build --workspace --all-targets`: 0 unused-import warnings remaining; only а few dead-code и mixed-script confusables linter warnings (unrelated).
19. ~~**CI gate**~~ ✅ done (2026-05-22): root cause of "4+3 violations slipped через" identified — [`.github/workflows/ci.yml`](.github/workflows/ci.yml) fired ONLY on tag pushes + manual workflow_dispatch.  Hygiene job (clippy `-D warnings`, mutex-poison policy, dead-code-anchor policy, cargo-audit) never ran на PRs, поэтому regressions landed unchecked between tag cuts.  Fixed by extending `on:` block: added `push: branches: [master]` + `pull_request: branches: [master]` triggers.  Also added cfg-warnings gate: new step `cargo check --workspace --all-targets` под `RUSTFLAGS=-D warnings` catches `unexpected_cfgs` lints (clippy alone doesn't fire on those — Phase 4 extraction's 7 cfg sites slipped через precisely because they were warnings-not-errors at compile-front-end).

### Non-action items (verified scaffolded by design)

- iOS BGProcessingTask drained-signal hook — already Epic 489.10 backlog row.
- Push HMAC wakeup — already Epic 489.10 backlog row.
- TUN daemon integration — already TASKS False-Positive (ogate provides TUN today).
- Epic 481/482 architectural backlog — already large-scope deferred backlog rows.

---

## Cross-audit batch 2026-05-23

Двойной audit (my pass + second-opinion review) пересечён.  9 findings закрыты
в 6 коммитах подряд (master).  Gates все зелёные: `cargo clippy --workspace
--all-targets -- -D warnings` clean, `scripts/check-mutex-poison-policy.sh`
clean, `scripts/check-allow-dead-code-anchors.sh` 15 sites all anchored.

### Closed in this batch

| Item | Severity | Commit | What |
|---|---|---|---|
| IPC streams A/B ownership | HIGH | `884e32c` | Split `owned_streams` into `owned_streams_opener` + `owned_streams_acceptor` (`Arc<Mutex<HashSet>>`); forwarder claims acceptor-side ownership before writing `STREAM_OPEN_INBOUND`; read-loop dispatches via `route_data_from_a` / `route_data_from_b` based on side.  Closes "bidirectional stream is actually one-way" hang в RPC patterns (oproxy CONNECT, request/response IPC services).  2 new integration tests (ping/pong + third-party-hijack-guard). |
| IPC backpressure silent-drop | MED | `884e32c` | New `RouteOutcome { Sent, UnknownStream, WindowExhausted, PeerBackpressure }`; `route_data_from_a` restores window credit on `PeerBackpressure` (was debited before failed `try_send` previously); server.rs closes the stream cleanly instead of silent loss.  Regression test pins the window-restore invariant. |
| Mailbox quota safe default | MED | `884e32c` | Pre-fix runtime mapped `cfg.quota_per_sender_bytes == 0` → `u64::MAX` (disabled).  Now maps to `DEFAULT_QUOTA_PER_SENDER_BYTES = 10 MiB`.  Operator who wants to disable must set explicit `u64::MAX`.  Extracted `build_mailbox_runtime_config` + 4 regression tests. |
| Clippy fixes + stale anchors + script hygiene | LOW | `884e32c` | 3 clippy fails fixed; 3 stale `#[allow(dead_code)]` cleaned from `ephemeral_rotator.rs` (Step 3 shipped); `install-bootstrap.sh` env-var whitelist validation; `iperf-veil-bench.sh` docstring drift. |
| Bounded mpsc в veilclient SDK | HIGH | `dc30f88` | All 4 `mpsc::unbounded_channel` sites (per-stream + per-endpoint inbound) → `mpsc::channel(256)` with drop-on-full semantics в reader task.  Slow consumers see EOF instead of pinning unbounded RAM.  Integration regression test floods 4× cap unread frames and asserts EOF. |
| Anycast SignedBound policy | MED | `b7f788c` | New `AnycastResolvePolicy::SignedBound` + `AnycastRecord::verify_owner_binding()` — closes "signature valid but binding forged" sybil vector (`SignedOnly` only checked sig integrity).  Binding contract: `sig_key_idx == 0 && BLAKE3(owner_pubkey) == node_id`.  Subkey records (`sig_key_idx > 0`) fail-closed because verifying needs async DHT identity-document lookup.  4 new tests in veil-proto + 3 in veil-anycast.  Cfg-glue wired. |
| FreeBSD TProxy fail-fast | LOW | `2c94b25` | Dropped `target_os = "freebsd"` from cfg-gate in `oproxy/inbound/{mod,tproxy}.rs`.  Pre-fix FreeBSD compiled but failed at runtime on first accept — operators saw the listener в `sockstat` и believed it worked.  Now joins macOS / Windows on the unsupported-platform branch с а clear startup error.  Re-open trigger documented в `tproxy_unix.rs` doc-comment if someone implements pf+divert OR ipfw fwd. |
| `bandwidth_mimicry_enabled` fail-closed | LOW | `2c94b25` | `cfg-validate` rejects `bandwidth_mimicry_enabled = true` unless operator also sets new `experimental_allow_noop_mimicry = true` к acknowledge the no-op landing-pad.  Pre-fix only WARN-logged — operators could believe DPI shaping was active.  3 unit tests cover happy / fail / disabled paths. |
| iOS APNs token → Keychain | MED | `895a6b8` | Replaced `UserDefaults` storage of APNs device token с iOS Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) via `Security.framework`.  One-shot legacy migration: first `getRegisteredToken` post-upgrade lifts а UserDefaults token into Keychain и deletes the original.  Closes attacker-with-sandbox-read → battery DoS / presence probe vector.  Privacy manifest updated. |
| DHT byte-cap | MED | `00d6ac5` | `TieredStore` gains `total_bytes: u64` (incremental) + `max_bytes: Option<u64>` (cap with oldest-first eviction).  `ColdBackend::put` returns evicted entry для bookkeeping; `evict_oldest` added для byte-cap fallback.  `DhtConfig::max_store_bytes` (default `None`, backward-compat) wired through `runtime_config_from` + `KademliaService::with_config`.  5 new store tests.  **Still deferred**: per-origin (per-signer-pubkey) byte accounting; flipping `allow_unsigned_store` default к false (would disrupt legacy networks). |
| Remote IPC forwarding — formal deferred closure | Architectural | `039c5f3` | Plan was scoped as 3-session epic (Phases 2-4); partial Phase 3 (open но без bridge task) strictly hurts UX (converts clean error into silent hang).  Honest close: updated `docs/en/PLAN_IPC_STREAM_FORWARDING.md` с "Status snapshot" section documenting Phase 1 shipped state, operator workaround (`veil_proxy::VeilConnector` exposed via oproxy), и а step-by-step checklist for the next contributor.  Inline `handle_stream_open` comment points operators at the workaround. |

### Still deferred (out-of-scope for this batch)

- **Anycast reputation-based downweight + quorum vote** — `SignedBound` (this batch) only proves owner binding, не score honesty.  Requires а new IPC reverse-direction frame for "resolution result failed in use" feedback + per-service reputation slice.  Re-open trigger: production trust-sensitive anycast consumer materializes.
- **DHT per-origin byte accounting** — would track bytes per signer pubkey + allow per-origin quotas.  Requires per-signer state в `TieredStore` (HashMap<pubkey, bytes>); larger change than the global cap shipped here.  Re-open trigger: observed per-signer abuse в production.
- **`allow_unsigned_store = false` default flip (P1)** — TASKS.md Phase C10 explicitly defers this ("flipping disrupts every legacy network using inner-sig pattern; Migration story belongs to follow-up epic").
  - *Audit cycle-6 investigation (Variant A scoped; ONE linchpin must be resolved
    first — paused for a dedicated session, high blast-radius = core DHT accept
    path):* The plan is to route dispatcher-VALIDATED unsigned records through
    `store_with_origin` (which bypasses the `allow_unsigned_store` gate, exactly
    as the recursive STORE plane already does at `routing.rs:1991-2003`) instead
    of `handle_store`, then flip the default to `false` so only truly-unsigned
    junk that bypassed validation is rejected. Receive-site inventory:
    * recursive STORE plane (`routing.rs` `recursive_query_type::STORE`) — ALREADY
      uses `validate_store_value_by_magic` + `store_with_origin`. No change.
    * direct `DiscoveryMsg::Store` arm (`discovery.rs:257-335`) — validates via
      magic/self-key then calls `handle_store` (re-gates). This is the ONE arm to
      switch to `store_with_origin`.
    * `store_replicated` LOCAL copy (`kademlia.rs:1563`) → `store_local`.
    * fan-out wire frames (`kademlia.rs:1439/1576`) stay unsigned; receivers
      re-validate. No change. Then flip `DhtConfig`/`DhtRuntimeConfig` default.
  - **UNRESOLVED LINCHPIN (must trace before touching the direct arm):** PBAN
    (P-Net ban) STOREs arrive as `DiscoveryMsg::Store` and `validate_store_value_by_magic`
    does NOT recognise the `PBAN` magic (returns "unrecognised payload magic" →
    Violation at `discovery.rs:611`), so a PBAN value appears to be REJECTED by the
    direct arm BEFORE reaching `handle_store`'s PBAN fast-path (`kademlia.rs:876`,
    routes to `NetworkAuthGate`). There is no PBAN handling in the dispatcher and
    no test proving cross-node PBAN replication via the direct arm. Either (a)
    PBAN cross-node replication already does not use this path (only local store +
    periodic `p_net_ban_sync` scan), or (b) there is a PBAN receive route not yet
    found. Resolve this definitively first: naively replacing `handle_store` with
    `store_with_origin` would DROP the PBAN fast-path and could silently break
    P-Net ban replication network-wide. The fix likely also adds a PBAN arm to the
    validated-unsigned path (or keeps `handle_store` for PBAN specifically).
  - **RESOLVED (audit cycle-6 trace of commit `9677abb6` P-Net Phase 3b):** the
    `NetworkAuthGate` that verifies PBAN lives on `KademliaService`, NOT on the
    dispatcher (`self.abuse` has no gate) — so ONLY `handle_store` can verify
    PBAN. The dispatcher Store arm rejects PBAN via `validate_store_value_by_magic`
    (unrecognised magic) BEFORE `handle_store`, so cross-node PBAN propagation
    through the direct arm is ALREADY a latent no-op (masked: no multi-node P-Net
    ban test exists; the working path is the local store + 60 s `p_net_ban_sync`
    scan, and `dht_republish` fan-out — which also re-enters the rejecting arm).
    Therefore the safe + CORRECT P1 design: in the direct arm, branch on PBAN
    (value starts `b"PBAN"`) → keep calling `handle_store` (the only gate holder;
    this also FIXES the latent gap by letting PBAN reach the gate instead of being
    rejected by magic-validation); for non-PBAN, validate via magic then
    `store_with_origin` (mirrors the recursive plane). Then flip the default.
- **Remote IPC forwarding Phases 2-4** — see `docs/en/PLAN_IPC_STREAM_FORWARDING.md` "Status snapshot" section.  3-session epic; re-open triggers explicit.

---

<!-- Phase 6.48 (Post-6.47 follow-up audit) closed 2026-05-06 → see TASKS_ARCHIVE.md.
     6 cleanup items (R1-R4, X1-X2) parked в open backlog с re-open trigger'ами;
     A1 (Loopix cover-traffic) + A8 (intersection-attack disjoint-relay-set)
     deferred к future epic.  Phase 6.45 H9 + H12 shipped в same closeout. -->



## Epic 483 — Mobile / battery / NAT

✅ done (483.1 + 483.3 + 483.4 + 483.5 (3 slices, last 2 opt-in default-off) + 483.6 + 483.6b shipped; 483.2 push-notification → Epic 489 Flutter scope, нужен FCM/APNs backend out of veilcore).  Полное описание перенесено в [`TASKS_ARCHIVE.md`](TASKS_ARCHIVE.md).  Acceptance bar (8h фон на 4G + battery < 5%/h, recovery < 3s) hits — recovery measured ~100ms; battery target gate to be validated on real Android via Epic 489.

---

## Epic 484 — Operational deployment

**Цель:** Распространять easy-to-install бинарь, обновлять без потери identity, оператор видит «почему я не подключён» в UI.

✅ done (484.1 + 484.3 + 484.5 shipped; 484.6 dropped — architecturally incompatible с anti-censorship целью). Полное описание перенесено в [`TASKS_ARCHIVE.md`](TASKS_ARCHIVE.md).

---


<!-- Phase 6.32 + 6.33 incident notes (2026-05-01 + 2026-05-03) — root cause
     closed via rekey FSM hardening + grace ring widening + mutual-collision
     tie-breaker.  Notes preserved в TASKS_ARCHIVE.md. -->

## Epic 485 — Adversary validation

✅ done (485.1 partial closure + 485.2 + 485.3 + 485.4 + 485.5 shipped; 485.6 skip per operator decision; 485.1 ID-grinding/bucket-pollution/24h-churn extensions parked в Deferred large-scope backlog).  Полное описание перенесено в [`TASKS_ARCHIVE.md`](TASKS_ARCHIVE.md).

---


<!-- Epic 487 (Trillion-scale architecture readiness) closed Phase 6.31 → see TASKS_ARCHIVE.md.
     Carry-overs (open follow-ups): 487.2 release-only N=500/1000 sim variants;
     487.6 operator deployment-guide markdown for multi-CDN bootstrap setup. -->

<!-- Epic 488 (DPI fingerprint hardening) closed Phase 6.31 → see TASKS_ARCHIVE.md.
     Carry-over (open): 488.2 n-gram regression test — heavy infra (n-gram analysis
     + reference fingerprint database for Tor/OpenVPN/WireGuard); deferred. -->

<!-- Epic 486 (Post-quantum readiness) closed Phase 6.51 → see TASKS_ARCHIVE.md.
     Cross-host stand-verified end-to-end: hybrid + standalone Falcon-512
     identity create/restore/show; MigrationCert chain-walk depth 1-3 across
     two-host quorum DHT; rotation CLI с --publish-immediately; performance
     bench established with PreparedDecapsulator amortising the seed-expansion
     cost (1.8× speedup on receiver re-keys). -->

## Epic 489 — Flutter mobile app integration

**Цель.** Сделать veil-сеть пригодной для использования через Flutter-приложение на Android / iOS, с production-grade UX, battery-aware и network-state-aware behavior. Это первичный target (budget Android в авторитарных state'ах) — оверлей бесполезен без потребительского клиента.

**Архитектурный выбор:** **single-process model** — veil-daemon собирается как `staticlib` / `cdylib` и линкуется в Flutter app процесс через C-FFI + Dart-FFI. Альтернатива (отдельный daemon-process через Android Service / iOS Network Extension) добавляет IPC-overhead на process boundary и усложняет lifecycle, при этом выигрышей по архитектуре нет (veil уже non-blocking, async).

<!-- 489.1 (C-FFI wrapper) closed Phase 6.31 → see TASKS_ARCHIVE.md.
     New crate `crates/veilclient-ffi` + `include/veil_ffi.h` ship the full
     spec'd API; consumable from Flutter / Swift / Kotlin.  9 unit tests.  -->

### 489.2 — Mobile cross-compile pipeline (≈ 0 LOC, инфра)

- Android targets: `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android` (для эмулятора). Через `cargo-ndk` (Android NDK r25+).
- iOS targets: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios` (Intel Mac sim). Через `cargo-lipo` или native cargo + `xcrun`.
- Output: `.a` (static library) per architecture + bridging header. Flutter plugin консолидирует в `.aar` (Android) / `.xcframework` (iOS).
- CI: один matrix-build job per target, артефакты публикуются в release. **Без** dynamic linking где можно — статика уменьшает attack surface и упрощает Play Store / App Store review.

**Status:** ✅ done (Phase 6.36 + Phase 6.49 follow-ups, 2026-05-07; Phase 6.50.b-followup 2026-05-18 polished Windows host build recipe per MEMORY.md §9). [scripts/build-mobile.sh](scripts/build-mobile.sh) builds `veilclient-ffi` for 10 supported triples (Android aarch64 / **armv7** / x86_64 via `cargo-ndk`, iOS aarch64 / **aarch64-sim** / x86_64-sim, macOS aarch64/x86_64, Linux x86_64/aarch64); `--all` to build the full matrix, `--target <triple>` for one. Verified locally on `x86_64-unknown-linux-gnu` — produces 748 KB `libveilclient_ffi.so` cdylib + 152 MB staticlib `.a` (static surface for iOS xcframework integration). [`.github/workflows/mobile-build.yml`](.github/workflows/mobile-build.yml) wires the same matrix into CI с `workflow_dispatch` + tag-push triggers; uploads per-target `ffi-<triple>` artifacts ready to bundle into the Flutter plugin's Android `jniLibs/<abi>/` и iOS `xcframework`. New chain of `allow-empty-seeds` / `production-seeds` / `test-low-difficulty` features through `veilclient-ffi → veilclient → veilcore → veil-bootstrap` so the build script doesn't need to know the dependency tree (single `--features allow-empty-seeds` flag at the top opts the whole chain into testnet seeds; production builds drop to `production-seeds` once `BUILTIN_SEEDS` is populated). **Phase 6.49 follow-ups (2026-05-07):** added `armv7-linux-androideabi` к the matrix (closes "32-bit ARM Android" gap — budget devices < 2017 + low-RAM phones); added `aarch64-apple-ios-sim` (Apple Silicon Mac simulator slice — required для xcframework к work на Apple Silicon Xcode hosts); new [`scripts/build-xcframework.sh`](scripts/build-xcframework.sh) runs on macOS hosts post-build, lipo-merges the two simulator slices (arm64 + x86_64) into а single fat staticlib, then `xcodebuild -create-xcframework` packages device + simulator slices с the FFI headers into а consumer-ready `VeilClientFFI.xcframework`.  CI gains `ios-xcframework` job that runs after `ios-and-macos` matrix, downloads the per-arch artifacts, и uploads the packaged xcframework as а separate artifact for the Flutter plugin's Podspec к pull straight из the run.

### 489.3 — Flutter plugin (`veil_flutter`) — Dart wrappers (≈ 800 LOC + tests)

Опубликовать как private pub.dev package или git-dep в monorepo:

```dart
class Veil {
  static Future<Veil> connect(String socketPath);
  Future<VeilApp> bind({required String namespace, required String name, int endpointId = 0});
  Future<VeilApp> bindNamed({required String namespace, required String name, int endpointId = 0});
  void close();
}

class VeilApp {
  Uint8List get appId;  // 32 bytes
  Future<void> send(Uint8List dstNodeId, Uint8List dstAppId, int dstEndpointId, Uint8List data);
  Stream<IncomingMessage> get incoming;  // broadcast stream
  Future<VeilStream> openStream({required Uint8List dstNodeId, required Uint8List dstAppId, required int dstEndpointId, int initialWindow = 65536});
}
```

- Idiomatic Dart Future / Stream API
- Auto-disposal через `NativeFinalizer`
- Type-safe NodeId / AppId wrapper classes (нельзя случайно перепутать аргументы)
- Background-mode hooks: `setBackgroundMode(LowPower / Foreground)` через `WidgetsBindingObserver.didChangeAppLifecycleState`
- Network-change hooks: `connectivity_plus` package → notify daemon на cellular/wifi switch

**Status:** ✅ done (Phase 6.36 → Phase 6.50.b-followup batch 2026-05-18, commit `46200c3`).  Originally shipped с scaffolding-only Dart API (~310 LOC `client.dart`); the 2026-05-18 batch closed all the previously-deferred surface:

* **VeilStream** ([lib/src/stream.dart](flutter/veil_flutter/lib/src/stream.dart), 219 LOC) — reliable bidi byte-stream wrapper over `veil_stream_*` C-FFI: open/write/read с broadcast `reads` Stream + close.  Test file `stream_test.dart`.
* **VeilMailbox** ([lib/src/mailbox.dart](flutter/veil_flutter/lib/src/mailbox.dart), 321 LOC) — высокоуровневый клиент `veil_mailbox_*`: `put` / `putWithCapability` / `fetch` / `ack` / `setPolicy`.  Test file `mailbox_test.dart`.
* **VeilLifecycle** ([lib/src/lifecycle.dart](flutter/veil_flutter/lib/src/lifecycle.dart), 205 LOC) — `WidgetsBindingObserver.didChangeAppLifecycleState` → automatic `setBackgroundMode(Foreground/LowPower)`; `connectivity_plus`-integration glue для `notifyNetworkChanged`.
* **client.dart expanded** to 1037 LOC (от 310): pairing flow methods (`joinBootstrapUri`, `createBootstrapInvite`, multi-device pairing entry points), push-envelope setters, mailbox accessor, `events()` broadcast stream of `VeilEvent`.
* **bindings.dart** expanded to 884 LOC — все FFI typedefs handraised + `Pointer<NativeFunction>` lookups для full plugin surface.
* **types.dart** expanded to 482 LOC (от 172) — adds `JoinBootstrapResult`, `JoinBootstrapStatus`, `MailboxPutOutcome`, `PushEnvelopeStatus` + всех event payloads.
* **Pre-existing FFI scaffolding bugs fixed**: bindings.dart had Uint32 / size_t mismatches at 4 entry points — caught when wire-side tests started running.

**NativeFinalizer auto-cleanup** ([stream.dart](flutter/veil_flutter/lib/src/stream.dart#L13)): documented as а follow-up — leaking а stream без explicit `close()` leaks an Arc'd bundle on Rust side; not а correctness issue, а resource-tidiness one.  Documented в the file как rustdoc comment.

**6 Dart test files** (types / mailbox / pairing / push / stream / identity) — pure-Dart unit tests runnable via `flutter test`.

**Runtime verification still pending:** Dart code не verified locally (no Flutter SDK).  First runtime check будет на CI mobile-build job or manual emulator smoke.

**Original Status (preserved для history):** 🔄 partial — **scaffolding shipped (Phase 6.36, 2026-05-02), runtime verification deferred to first Flutter build**. Created `flutter/veil_flutter/` Flutter plugin package с idiomatic Dart API: `VeilClient.connect(socketPath)` → opens IPC; `bind(...)` / `bindNamed(...)` → `AppHandle`; `app.send(...)` and `app.messages()` (Stream<IncomingMessage>) for datagrams; `client.events()` (Stream<VeilEvent>) for the Phase 6.34 push event stream — single-subscriber broadcast with auto-decode для known kinds (`SESSIONS_CHANGED` → `sessionCount`, `MOBILE_TIER_CHANGED` → `tierAfterChange`, `IDENTITY_ROTATED` preserved as raw bytes); `client.setBackgroundMode(MobileBackgroundMode)` для lifecycle hooks; `client.notifyNetworkChanged(NetworkKind)` для connectivity_plus integration.  Files: [`lib/src/native.dart`](flutter/veil_flutter/lib/src/native.dart) (DynamicLibrary loader для android/ios/macos/linux/windows), [`lib/src/bindings.dart`](flutter/veil_flutter/lib/src/bindings.dart) (raw FFI typedefs + lookups, hand-written; `ffigen` swap-in possible later), [`lib/src/types.dart`](flutter/veil_flutter/lib/src/types.dart) (enums + `VeilEvent` w/ kind-aware payload helpers), [`lib/src/client.dart`](flutter/veil_flutter/lib/src/client.dart) (~310 LOC high-level API), [`example/lib/main.dart`](flutter/veil_flutter/example/lib/main.dart) (Material UI demo).  Pure-Dart unit tests for the wire-byte mapping in [`test/types_test.dart`](flutter/veil_flutter/test/types_test.dart) — runnable via `flutter test` без the daemon.  **NB:** Dart code is unverified locally (no Flutter SDK on dev machine); first runtime check будет на CI mobile-build job + manual smoke on Android emulator.  **Phase 6.41 follow-up (2026-05-02):** added BIP-39 restore Dart helpers (`validateBip39Phrase`, `restoreIdentity`, `hasBip39WordCount`) plus reference Material 3 screen ([`example/lib/restore_screen.dart`](flutter/veil_flutter/example/lib/restore_screen.dart)) — closes Epic 489.8 in this same plugin.  **Phase 6.42 follow-up (2026-05-03): plugin gradle integration.** New [`flutter/veil_flutter/android/build.gradle`](flutter/veil_flutter/android/build.gradle) wires `cargo-ndk` straight into the gradle build lifecycle — every consumer app's `flutter build apk` automatically compiles `libveilclient_ffi.so` for all 4 Android ABIs (arm64-v8a, armeabi-v7a, x86_64, x86) and bundles them into the AAR via `src/main/jniLibs/<abi>/`.  Per-ABI `cargoBuild_<abi>` Exec task invokes `cargo ndk -t <abi> -- build --release -p veilclient-ffi --features allow-empty-seeds`; matching `copyNative_<abi>` Copy task stages the resulting `.so` into jniLibs.  Both hooked into `preBuild` so consumer apps don't need a manual `scripts/build-mobile.sh` step.  CI escape hatch: `VEIL_SKIP_CARGO=1` env var (or `-PveilSkipCargo=true`) skips cargo invocations — useful when a CI matrix pre-builds the `.so` artifacts and just wants gradle to package them.  Plugin manifest ([`android/src/main/AndroidManifest.xml`](flutter/veil_flutter/android/src/main/AndroidManifest.xml)) declares `INTERNET` permission so consumer apps inherit it via manifest-merge без forgetting.  `min_sdk = 21` (Android 5.0, matches Flutter's own minimum).  **Deferred:** `VeilStream` (reliable bidirectional byte stream), `NativeFinalizer` auto-cleanup для caller-mistake hardening, `connectivity_plus` integration glue, `WidgetsBindingObserver` lifecycle wiring; iOS plugin scaffolding (Swift + CocoaPods) — separate slice; Android NDK auto-detect и cargo-ndk auto-install hint when missing.

<!-- 489.4 + 489.5 (Battery-aware IPC + Network-state hooks) closed Phase 6.31 → see TASKS_ARCHIVE.md.
     `LocalAppMsg::SetMobileBackgroundMode = 26` + `LocalAppMsg::NetworkChanged = 27` + new
     `MobileEventSink` trait dispatch + `veil_set_background_mode` / `veil_notify_network_changed`
     FFI funcs.  Carry-over follow-ups: per-tier keepalive multipliers + LowPower route-probe pause
     (489.4); aggressive session-teardown on NetworkChanged via "force-reconnect-all" runtime channel
     (489.5).  -->

### 489.6 — Foreground service / Background mode (≈ 200 LOC platform code)

Android:
- Daemon thread живёт как `ForegroundService` с persistent notification (Doze-resistant)
- Notification action: "Disconnect" / "Settings"
- Support `START_STICKY` для auto-restart на crash

iOS:
- App-extension: `NetworkExtension.NEPacketTunnelProvider` НЕ нужен (не VPN), но для long-lived background — нужен `BGProcessingTask` с silent-push wake
- Альтернатива: app только active mode + push-based wake (минимум batt drain)

**Status:** ✅ done (Android — Phase 6.43, 2026-05-03; iOS BGProcessingTask — Phase 6.44, 2026-05-03 (см. 489.10)).  iOS strategy is "BGProcessingTask + silent push" not а persistent service — implementation lives в `ios/Classes/VeilFlutterPlugin.swift:notifyWakeup` registered с identifier `com.veil.veil_flutter.refresh`, given ~30 s budget per wake.

**Previous Status:** 🔄 partial — **Android side ШИПНУТ Phase 6.43 (2026-05-03); iOS BGProcessingTask deferred к Epic 489.10 push-notification slice**.

**Android implementation:** new Kotlin module под [`flutter/veil_flutter/android/src/main/kotlin/com/veil/veil_flutter/`](flutter/veil_flutter/android/src/main/kotlin/com/veil/veil_flutter/):

* [`VeilDaemonService.kt`](flutter/veil_flutter/android/src/main/kotlin/com/veil/veil_flutter/VeilDaemonService.kt) — `Service` subclass that calls `startForeground(notificationId, notification)` immediately в `onCreate` (Android 12+ requirement: must be called within 5 s).  Persistent low-importance notification ("Veil running") prevents user-swipe-dismiss и signals OS "this process is doing user-visible work — don't kill".  Android 14+ `foregroundServiceType = REMOTE_MESSAGING` matches veil's "continuously receive messages over the internet" purpose — sub-permission already declared в plugin's AndroidManifest.  `START_STICKY` so OS auto-recreates the service after а memory-pressure kill.  Lazy `NotificationChannel` creation (Android 8+).

* [`VeilFlutterPlugin.kt`](flutter/veil_flutter/android/src/main/kotlin/com/veil/veil_flutter/VeilFlutterPlugin.kt) — MethodChannel handler за `veil_flutter/lifecycle`.  Two methods: `startBackgroundService(title?, text?)` (sends ACTION_START intent), `stopBackgroundService()` (sends ACTION_STOP).  `Build.VERSION` checks dispatch к `startForegroundService` (Android 8+) vs `startService` (older).

* AndroidManifest declares: `INTERNET`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_REMOTE_MESSAGING` (Android 14+ sub-permission), `POST_NOTIFICATIONS` (Android 13+ runtime permission for notifications).  Plus `<service>` declaration с `exported=false` (sandbox hardening) и `foregroundServiceType="remoteMessaging"`.

* Default notification icon (`veil_notification_icon.xml`) — vector drawable showing а 3-node mesh triangle.  Apps override by shipping their own at the same resource path (Android resource merge takes consumer's version).

* `build.gradle`: Kotlin plugin + AndroidX `core-ktx:1.13.1` (для `NotificationCompat`).  `targetSdk 34` matching Android 14 manifest requirements.

* `pubspec.yaml`: registered plugin class `VeilFlutterPlugin` для Android (alongside existing `ffiPlugin: true`).

**Dart API:** [`VeilBackground.start(title?, text?)`](flutter/veil_flutter/lib/src/background.dart) / [`VeilBackground.stop()`](flutter/veil_flutter/lib/src/background.dart).  No-op silent-skip on iOS / desktop platforms (cross-platform code doesn't need а platform check).  Idempotent: re-calling `start` refreshes the notification text.  Example app updated к call `start` after `connect` и `stop` in `dispose`.

**Runtime verification deferred:** the Kotlin code is unverified locally (no Android emulator on dev machine).  First runtime check будет via the mobile-build CI job + manual smoke on а physical device or emulator.  All Android-API calls follow current best practices (foreground-service-type for Android 14+, channel for Android 8+, permission declarations for Android 13+/14+).

**iOS deferred:** iOS doesn't have an equivalent "stay alive forever" mechanism.  The realistic strategy is BGProcessingTask + push notifications (Epic 489.10) — message-driven wake-up rather than persistent process.  When 489.10 lands, the iOS side of 489.6 will compose: app receives silent push → BGProcessingTask runs ~30 s → drains daemon's pending operations → terminates.

### 489.7 — Pairing UX flow (≈ 600 LOC Flutter + 0 LOC veilcore — protocol готов)

Epic 481.1 (out-of-band bootstrap invites) уже определяет wire format. Нужен UI:

- QR generator (existing user) — encode `IdentityInvite` blob from `bootstrap invite create` CLI output
- QR scanner (new user) — `mobile_scanner` package + `bootstrap invite consume`
- HTTPS bootstrap fallback — input field for "https://invite.example.com/abc123" если QR scan недоступен
- Error UX: invalid invite, expired invite, already-paired, network-unreachable

**Status:** ✅ done (Phase 6.50.b-followup 2026-05-18/19, commits `46200c3` + `91ce020`).

* **Consume side** — [`VeilPairingDialog`](flutter/veil_flutter/lib/src/pairing.dart) (442 LOC): Material-3 tabs для QR scan (`mobile_scanner`), manual paste, и HTTPS-bootstrap-URL fallback.  Все три converge на `VeilClient.joinBootstrapUri` (inline passphrase prompt + signed-verify).
* **Generate side** — [`VeilShareInviteDialog`](flutter/veil_flutter/lib/src/share_invite.dart) (313 LOC) + new IPC entry point `CreateBootstrapInvite` (`crates/veil-ipc/`) + new daemon module [`veilcore/src/node/bootstrap_invite_create.rs`] (149 LOC).  Existing user opens dialog → daemon mints invite URI → rendered as QR + copy-button с optional passphrase encryption.
* **Test file** `pairing_test.dart` (86 LOC) — wire-byte mapping of join-result enum.

(Minor cleanup remaining: stale comment in `pairing.dart:13` ("Generator side **deferred**") needs update; not а functional issue.)

### 489.8 — Identity restoration UX (BIP-39 phrase)

Master-seed restore from 24-word phrase (Epic 462). Wire ready (`veil-cli identity restore --phrase-file`), нужен UI:

- Mnemonic input (с word-suggestions, validation)
- Encrypted master.enc storage с Argon2id passphrase
- Multi-device flow: pairing existing identity to new device через master-seed import → new subkey on device

**Status:** ✅ done (Phase 6.41 → Phase 6.50.b-followup 2026-05-19, commits `46200c3` + `367c61d`).

**Closed deferreds:**
* **Argon2id master.enc storage**: `identity.dart:111` `restoreIdentityWithBackup(phrase, passphrase, ...)` wraps the FFI `veil_restore_identity_with_encrypted_backup` (veilclient-ffi) — writes `master.enc` next к `identity_document.bin` / `instance.toml`.
* **Multi-device pairing flow** ([lib/src/multi_device_pairing.dart](flutter/veil_flutter/lib/src/multi_device_pairing.dart), 712 LOC): full source-and-target dialog с Hello/Cert/Confirm bytes, OOB code comparison, и QR rendering via `qr_flutter`.  Source enters master passphrase → daemon mints pairing URI; target pastes URI → daemon emits Hello bytes → source pastes those → cert + OOB → confirm round-trip.  Persists new identity on match.

**Previous Status:** 🔄 partial — **Phase 6.41 (2026-05-02) — FFI primitives + Dart wrappers + reference UI shipped; Argon2id master.enc + multi-device pairing flow deferred**.  Two new C-FFI entry points: `veil_validate_bip39_phrase(phrase, err_out)` (lightweight checksum validation, suitable для per-keystroke UI feedback — pure compute, no disk I/O) и `veil_restore_identity_from_phrase(phrase, veil_dir, instance_label, err_out)` (full restore: BIP-39 → master_seed → derive identity_sk → write `identity_document.bin` + `instance.toml` + `identity_sk.bin` к the chosen dir).  Dart wrappers in `flutter/veil_flutter/lib/src/identity.dart`: `validateBip39Phrase(phrase) -> bool` (throws с specific reason on failure), `restoreIdentity(phrase, veilDir, instanceLabel)` (sync wrapper with off-isolate scheduling), `hasBip39WordCount(phrase) -> bool` (lightweight pre-check для UI gate).  Reference Material 3 screen `flutter/veil_flutter/example/lib/restore_screen.dart`: 24-word multiline TextField (better для paste-from-password-manager than 24 small fields), live word-count + checksum feedback, instance-label input, error surfacing, async restore с loading indicator.  **5 FFI tests** (validate accept/reject-garbage/reject-null + restore writes-files + same-phrase-yields-same-node-id — the deterministic property is the whole point of restoration).  **6 pure-Dart tests** for `hasBip39WordCount` (24/23/25/empty/whitespace/trim).  **Tight scope (deferred):** Argon2id master.enc storage (`save_encrypted_with_password` already в `RestoreIdentityOptions` — но requires а separate UI screen для passphrase entry + secure-storage integration); multi-device pairing flow (existing identity is already restored under the same master_seed — multi-device extension means using the restored device as а "delegating master" к sign cert chains for OTHER devices, separate UI flow); secure paste detection (some phrase managers strip trailing newline differently — current input filter handles ASCII-letters + whitespace, sufficient для well-formed phrases). |

### 489.9 — App Store / Play Store readiness (≈ 0 LOC — process)

- App Store: privacy manifest (`PrivacyInfo.xcprivacy`) — veil не использует tracking SDKs, but uses NSURLSession indirectly через transport. Manifest должен явно decline.
- Play Store: Data safety form — declare what data leaves device (encrypted veil traffic only).
- Both: export-control attestation (uses crypto). Update self-classification annual.
- ITP / DMA / GDPR: **no telemetry**, no analytics, no ads — простой honest privacy policy.

**Status:** ✅ done (code-side); ⬜ operator-side per-app submission остается per-deployment process work outside codebase scope.  All metadata + attestation templates shipped Phase 6.49 (2026-05-07).  Files под [docs/store-readiness/](docs/store-readiness/): [README.md](docs/store-readiness/README.md) (checklist), [app-store-privacy.md](docs/store-readiness/app-store-privacy.md) (App Store Privacy nutrition-label answers), [play-store-data-safety.md](docs/store-readiness/play-store-data-safety.md) (Google Play Data Safety form answers, including "encrypted in transit", "transmits messages — shared via relays who cannot decrypt"), [export-control.md](docs/store-readiness/export-control.md) (BIS ECCN 5D002.c.1 mass-market self-classification + ERN filing template + annual reporting cadence), [itunes-app-info.md](docs/store-readiness/itunes-app-info.md) (Apple per-build encryption questions + `ITSAppUsesNonExemptEncryption=NO` Info.plist key), [PRIVACY_POLICY_TEMPLATE.md](docs/store-readiness/PRIVACY_POLICY_TEMPLATE.md) (drop-in privacy policy для consumer apps).  Plus the plugin ships its own [PrivacyInfo.xcprivacy](flutter/veil_flutter/ios/Resources/PrivacyInfo.xcprivacy) declaring NO tracking, NO collected data types, и Required-Reason API justifications для file-timestamp / user-defaults / system-boot-time / disk-space access (the 4 system APIs veil's static lib touches).  Consumer apps inherit the manifest via plugin merge.

### 489.10 — Push notifications integration (optional but huge for UX)

Без push: incoming chat message не доставляется пока user не откроет app. Plus battery drain at parity with WhatsApp.

Hybrid design:
- Anonymous push token registered with bootstrap node (NOT FCM/APNs directly — иначе Google/Apple знают user-id)
- Bootstrap node `wake-up` push сигнал → app launches → reconnects к veil → drains queued messages
- Alternative: depend on FCM/APNs (compromise privacy для UX win) — отдельная opt-in feature

**Status:** 🔄 partial — **HMAC wakeup chain закрыт end-to-end в коде** (proto wire / crypto / FFI / Dart / IPC / SDK / receiver-side verify / sender→relay propagation все shipped); operator-side push-relay reference impl (slice 4.4) остаётся как separate epic.

**Closed in 2026-05-19 batch:**
* **Push-token sealing primitive** — new FFI `veil_seal_push_envelope(token_bytes, relay_pubkey)` ([crates/veilclient-ffi/src/lib.rs:2124](crates/veilclient-ffi/src/lib.rs#L2124)) wraps the X25519-sealed-box encoding of а raw FCM/APNs token to а push-relay's X25519 pubkey.  Dart wrapper [`VeilPush.sealEnvelope(token, relayPk)`](flutter/veil_flutter/lib/src/push.dart) hides the FFI from app code.
* **IPC + FFI surface** для setting the push envelope: `veil_set_push_envelope(handle, sealed_bytes, len)` ([crates/veilclient-ffi/src/lib.rs:2012](crates/veilclient-ffi/src/lib.rs#L2012)) routes the sealed blob into `set_rendezvous_push_envelope` для any active rendezvous publication.

**Closed в 2026-05-28 macOS session (4 slices, ~860 LoC):**
* **Slice 4.1 — `VeilPush.drainMailbox()` helper** (commit `d11b2175`).  `VeilClient.socketPath` retained на the instance + new `VeilPush.drainMailbox({socketPath, receiverId, authCookie})` opens а fresh client в the consumer's FCM/APNs background-handler isolate, drains, и closes deterministically.  Closes the boilerplate-per-consumer gap.  Future enhancement: persist socketPath / receiverId / authCookie via platform-secure storage (iOS Keychain / Android Keystore) для true no-arg `drainMailbox()`.

* **Slice 4.2 — `MAILBOX_DRAINED` event + iOS BGProcessingTask drained-signal hook** (commit `64f0c0bd`).  End-to-end pipeline: `veil_proto::event_kind::MAILBOX_DRAINED = 3` (payload `[u32 BE drained_count]`) → `MailboxIpcBridge` publishes after authorised fetch → Dart `VeilPush.drainMailbox` calls `notifyDrained` MethodChannel → Swift releases `drainSignal: DispatchSemaphore?` armed at BG-task entry.  iOS `handleBackgroundProcessing` now `setTaskCompleted(success: true)` precisely at drain completion (signal arrives) с 28-s fallback timeout (signal absent — common race где drain completes BEFORE iOS schedules the BG task; benign — same as today's 25 s hardcoded behaviour, but the long-tail "drain completes AFTER task fires" case wins big).  Constant-match test pins MAILBOX_DRAINED через 3 layers (veil_proto / veilclient-ffi / Dart bindings).  Android channel acks the call without gating BG work (Foreground service notification handles pacing там).

* **Slice 4.3.1 — `veil_crypto::wake_hmac` primitive** (commit `de3de25e`).  Leaf-level crypto: HMAC-SHA256 + freshness check + wire layout.  Domain-separated under `b"WAKEv1"`; 72-byte payload `ts || content_id || hmac`; `WakePayloadVerdict { Valid, TamperedOrForged, Expired, MalformedLength }` distinguishes failure modes so operators can surface clock-skew rate separately от active forging.  `WakeHmacKey` zeroes-on-drop + `Debug` redacts.  15 unit tests cover determinism, sensitivity к each input field, encode layout, accept paths (fresh + boundary), reject paths (forged HMAC / tampered ts / tampered content_id / expired in both skew directions / malformed length), key hygiene.

**Closed в 2026-05-28 macOS continuation session (5 slices, ~1750 LoC):**

* **Slice 4.3.2 — RendezvousAd v3→v4 wire bump** (commit `a0f9e6ad`).  Added `wake_hmac_envelope: Vec<u8>` field + `SIG_DOMAIN_V4 = b"veil-rendezvous-ad:v4\0"` + `MAX_WAKE_HMAC_ENVELOPE_LEN = 128`.  Decoder accepts v1/v2/v3/v4 (backward compat — pre-v4 ads yield empty envelope); encoder always emits v4.  `sign_rendezvous_ad` extended с `wake_hmac_envelope: &[u8]` param; `verify_rendezvous_ad` dispatches на `wire_version`.  Production caller `maintenance::tick_publish_rendezvous_ads` passes `&entry.wake_hmac_envelope` (defaults к empty until receiver opts in).  8 new tests (round-trip / sig binds envelope / strip detection / oversized rejected / max-size accepted / v4 c all 3 envelopes / v3-under-v4 yields empty / v3↔v4 canonical disjoint cross-version replay protection).  221/221 anonymity tests pass.

* **Slice 4.3.3 — wake_hmac FFI + Dart wrapper** (commit `a1edfd0c`).  Two FFI entry-points (`veil_generate_wake_hmac_key`, `veil_verify_wake_hmac`) + six constants (4 verdict codes + key/payload lengths) in `veilclient-ffi`; `veil_crypto::wake_hmac` exposed как pure-crypto primitive (no daemon round-trip).  Dart `VeilPush.generateWakeHmacKey() → Uint8List`, `VeilPush.sealWakeHmacKey({key, relayPk})` (thin wrapper над existing `sealPushEnvelope` — same envelope shape), `VeilPush.verifyWakePayload({key, payload, receiverId, nowSecs}) → WakePayloadVerdict`.  New `WakePayloadVerdict` enum (4 variants + forward-compat `unknown`).  8 FFI tests + 6 Dart-side compile-signature pins.  `veil_ffi.h` regenerated cleanly.

* **Slice 4.3.4 — `setWakeHmacEnvelope` IPC end-to-end** (commit `c5217a29`).  7 layers extended in lock-step:  
  — **proto**: `LocalAppMsg::SetWakeHmacEnvelope = 70` + `SetWakeHmacEnvelopeOk = 71` opcodes; `SetWakeHmacEnvelopePayload` struct + status enum (mirror of `SetPushEnvelope*`).  
  — **IPC**: `PushEnvelopeSink` trait extended с default-`false` `set_rendezvous_wake_hmac_envelope` method (avoids 30-param signature change в `handle_ipc_client`); `handle_set_wake_hmac_envelope` handler.  
  — **runtime**: `NodeRuntime::set_rendezvous_wake_hmac_envelope` + `RendezvousPushEnvelopeForwarder` sink-impl extended.  
  — **SDK**: `VeilClient::set_wake_hmac_envelope` + bounded `pending_set_wake_hmac_envelope` queue + reply dispatch + re-exports.  
  — **FFI**: `veil_set_wake_hmac_envelope`.  
  — **Dart**: `VeilClient.setWakeHmacEnvelope({rendezvousNodeId, authCookie, envelope})` + `veilMaxWakeHmacEnvelopeLen = 128` const.  
  4 new proto tests (round-trip с/без envelope, oversized decode rejection, status wire round-trip).

* **Slice 4.3.4 follow-ups** (commit `d658e149`):  
  — **`handleWakeup(payload, wakeHmacKey, receiverId)` HMAC verify**:  three new optional Dart params; when all three supplied, calls `verifyWakePayload` BEFORE foreground promotion / onWake — non-Valid verdict silently aborts (defeats presence-oracle + battery DoS).  Backward compat preserved (legacy callers без HMAC args fall back на 60-s rate-limit only).  
  — **`MailboxPutPayload` Trailer 3 `wake_hmac_envelope`**:  sender extracts envelope от receiver's RendezvousAd и forwards в the PUT.  Length-prefixed, optional, backward-compat (legacy 2-trailer wires decode с `wake_hmac_envelope = None`).  `VeilClient::mailbox_put` gains а new `wake_hmac_envelope: Option<Vec<u8>>` param; 3 new tests (round-trip / legacy decode / oversized).

**HMAC wakeup chain end-to-end в коде**:

```
Receiver app          Daemon                Sender app         Relay (slice 4.4)    Receiver
─────────────         ──────                ──────────         ──────────────       ────────
generateWakeHmacKey                                                                  
sealWakeHmacKey  →                                                                  
setWakeHmacEnvelope → embeds в RendezvousAd                                         
                      v4 wake_hmac_envelope ──── (DHT) ──→  fetched as part of ad   
                                                            sender extracts          
                                                            envelope                 
                                                            mailbox_put(             
                                                              wake_hmac_envelope ──→ relay decrypts,
                                                            )                        mints HMAC,
                                                                                     fires FCM/APNs  ──→ handleWakeup(
                                                                                                          payload, key, rid
                                                                                                        ) verifies
```

**Still open (slice 4.4 — separate epic):**

* **Push-relay reference implementation** (~800 LoC новый бинарь, deferred к operator-side epic).  Operator-run service: subscribes к а receiver's mailbox events, decrypts `wake_hmac_envelope` once-per-receiver, computes HMAC tag using `veil_crypto::wake_hmac::compute_wake_hmac` (already shipped), packages payload via `encode_wake_payload` (already shipped), fires sealed FCM/APNs delivery.  Open architectural question: централизованный per-app relay vs multi-relay для anti-takedown?  Не блокирует 1.0 — receiver-side и sender-side fully wired; turning the chain on requires deploying the relay binary, что is operator-side concern.
* **Platform-secure persistence для wake-HMAC key** (orthogonal к the FFI surface).  Receivers should persist the 32-byte raw key через iOS Keychain (alongside the APNs token shipped в audit batch 2026-05-23) / Android Keystore vs SharedPreferences.  Pure plugin-level slice when adopted.
* **FFI surface for `mailbox_put` wake_hmac_envelope** — current FFI passes `None`; extending `veil_mailbox_put` signature + Dart wrapper bump is а small follow-up.
* **Custom notification UI** (action buttons "Reply" / "Mark read") via iOS notification-extensions / Android NotificationStyle.

**Previous Status:** 🔄 partial — **plugin glue ШИПНУТ Phase 6.44 (2026-05-03); FCM/APNs SDK integration deferred к consumer apps**.

**Threat-model design choices (locked-in via the plugin's API shape):**
* Push payload **MUST be empty** — wake-up signal только, never message content.  Consumer's FCM/APNs handler calls `VeilPush.handleWakeup()` без any data; daemon then fetches actual content via veil (E2E-encrypted).  Censor pressuring Google/Apple sees only "user-X received а wake-up at time T", не sender / content.
* Push token treated as а separate identifier from `node_id` — sender/relay learns only the relay-encrypted token, не the receiver's identity.  (Future slice: token registration в encrypted RendezvousAd `extra` field; relay sends FCM/APNs without seeing identity.)

**Architectural split — plugin vs consumer:**
* **Plugin (this slice):** thin wake-up glue — `VeilPush.handleWakeup()` (Dart API), token storage в SharedPreferences (Android) / UserDefaults (iOS), iOS `BGProcessingTask` registration + scheduling.  ~30 s background runtime после а silent push.
* **Consumer app (NOT plugin):** brings own FCM/APNs SDK via popular Flutter packages (`firebase_messaging`, `flutter_apns`).  Reasons: (a) Firebase SDK adds ~5 MiB к every consumer app (some don't want push); (b) Firebase pulls 50+ Java methods that conflict с ProGuard rules; (c) APNs setup is per-app provisioning (cert + entitlement) which can't be shared.

**Files shipped:**
* [`flutter/veil_flutter/lib/src/push.dart`](flutter/veil_flutter/lib/src/push.dart) — `VeilPush.handleWakeup()` / `.registerDeviceToken(t)` / `.getRegisteredToken()`.  No-op silent-skip on platforms без push (Linux/macOS/Windows).
* [`flutter/veil_flutter/android/src/main/kotlin/com/veil/veil_flutter/VeilFlutterPlugin.kt`](flutter/veil_flutter/android/src/main/kotlin/com/veil/veil_flutter/VeilFlutterPlugin.kt) — extended с push channel: `notifyWakeup` (logs metric, future hook for daemon reconnect), `registerDeviceToken` / `getRegisteredToken` (SharedPreferences-backed).
* [`flutter/veil_flutter/ios/Classes/VeilFlutterPlugin.swift`](flutter/veil_flutter/ios/Classes/VeilFlutterPlugin.swift) — first iOS module of the plugin.  Registers `BGProcessingTask` identifier `com.veil.veil_flutter.refresh` at plugin init (iOS strict: identifier must be registered ON THIS RUN).  `notifyWakeup` schedules а task that gives the daemon ~30 s real-time budget before iOS suspends.  `registerDeviceToken` / `getRegisteredToken` use `UserDefaults`.  `startBackgroundService` / `stopBackgroundService` are silent no-ops on iOS (no equivalent persistent-service API — push wake is the substitute).
* [`flutter/veil_flutter/ios/veil_flutter.podspec`](flutter/veil_flutter/ios/veil_flutter.podspec) — first iOS Podspec.  Vendored `Frameworks/libveilclient_ffi.a` (consumer pre-builds via `scripts/build-mobile.sh --target aarch64-apple-ios`); minimum iOS 13.0 (for `BGTaskScheduler`).
* `pubspec.yaml`: registered `VeilFlutterPlugin` для iOS alongside Android.

**Consumer integration walkthrough (in `push.dart` rustdoc):** call `FirebaseMessaging.onBackgroundMessage(_onPush)` где `_onPush` invokes `VeilPush.handleWakeup()`.  Token registration: get FCM/APNs token from package → call `VeilPush.registerDeviceToken(token)`.  Plugin persists locally; daemon включит its rendezvous-ad announcements (future slice).

**Runtime verification deferred:** Swift и Kotlin code unverified locally (no Apple toolchain / Android emulator on dev machine).  First check via mobile-build CI matrix + manual smoke on physical devices.  All API calls follow Apple's и Google's current guidance (BGProcessingTask requires `BGTaskSchedulerPermittedIdentifiers` plist key on consumer side; FCM background-handler must be top-level OR static — both документированы в the rustdoc walkthrough).

**Phase 6.49 follow-up (2026-05-07): daemon-side rendezvous-ad push-token wire field shipped.**  `RendezvousAd` wire format bumped к v2 carrying а new `push_envelope: Vec<u8>` field (cap [`MAX_PUSH_ENVELOPE_LEN`] = 512 bytes — sized для X25519 sealing of а ~250-char FCM/APNs token + slack для future opaque routing metadata).  Wire format and signing domain BOTH versioned: v1 ads pre-Epic-489.10 still decode (decoder sets `push_envelope = vec![]` + `wire_version = 1`); v1 → v2 cross-version replay protection via separate `SIG_DOMAIN_V1` / `SIG_DOMAIN_V2` constants — а v1 signature canNOT verify against v2 canonical с the same fields, so а censor cannot strip the version byte mid-flight и confuse the receiver about whether push was registered.  `sign_rendezvous_ad` gains а `push_envelope: &[u8]` parameter (empty = no push); `verify_rendezvous_ad` picks canonical form from `ad.wire_version` (preserved through decode).  Maintenance tick re-signs each tick using `entry.push_envelope` so updates persist across re-publish.  Runtime API: new `register_rendezvous_publisher_with_push(rendezvous, cookie, validity, envelope)` + `set_rendezvous_push_envelope(rendezvous, cookie, envelope)` (update-only, returns false if no matching entry).  **8 new unit tests** в `crates/veil-anonymity/src/rendezvous.rs`: default no-envelope round-trip, envelope round-trip via encode/decode, signature binds envelope (tamper detection), signature binds envelope **presence** (strip detection), oversized envelope rejected at sign, max-size envelope accepted under total cap, v1 legacy decode yields empty envelope, v1↔v2 canonical messages disjoint (cross-version replay protection).  73 anonymity tests + 3 maintenance rendezvous-publish tests pass с no regressions.

**Tight scope (deferred к follow-up slices):**
* Push-token sealing primitive — `PushEnvelope` module that encrypts а raw FCM/APNs token к а push-relay's X25519 pubkey.  Wire layer above (this slice) treats the bytes opaque; the sealing/unsealing helpers + relay-pubkey distribution belong к а separate slice.
* IPC + FFI surface для setting the push envelope: `LocalAppMsg::SetPushEnvelope` + `veil_set_push_envelope(handle, sealed_bytes, len)` C-API.  Plugin-side glue (`VeilPush.registerDeviceToken`) already shipped (Phase 6.44); needs daemon-side wire-up к route the sealed blob into `set_rendezvous_push_envelope` for any active rendezvous publication.
* Push-relay reference implementation — operator-run service that subscribes к а receiver's mailbox events и fires sealed FCM/APNs к the registered token.  Open question: централизованный per-app relay? Multi-relay для anti-takedown?
* Foreground task hook into Rust FFI's "drained" signal so iOS BGProcessingTask completes precisely when daemon is done, rather than the current 25 s hardcoded.
* Custom notification UI (action buttons "Reply" / "Mark read") via iOS notification-extensions / Android NotificationStyle.

### Order of work (dependency-aware)

```
Week 1-2:    489.1 (FFI) + 489.2 (cross-compile) + 489.3 (Flutter plugin)  [parallel]
Week 3:      489.4 (battery API) + 489.5 (network hooks)                   [parallel]
Week 4-5:    489.6 (foreground service) — Android first, iOS second
Week 6:      489.7 (pairing UX) + 489.8 (identity restore UX)              [parallel]
Week 7:      489.9 (App Store / Play Store readiness) + alpha testing
Week 8+:     489.10 (push notifications) — optional, post-launch
```

**Estimated total:** 6-7 недель focused work до alpha-mobile-app, +2 недели для consumer-grade polish, +2 недели для push notifications.

**Acceptance:** Flutter app собирается под Android arm64 + iOS arm64; user может scan QR-pair, get incoming chat-message, app выживает Doze 8h без heroic battery drain (≥ 80% battery left after 8h).

**Параллельная работа на veil-стороне:** оставшиеся 9% задач (H1 split done — `runtime/mod.rs` 6490→5199 LOC; Anycast signing; Falcon-1024; TLS ECH default-on) могут идти параллельно — не блокируют app.

---

## Deferred large-scope backlog

Items с законченным acceptance ("эпик закрыт") но pre-existing sub-pieces, parked
по signal "scope ≫ marginal value".  Re-open trigger зафиксирован — будут
rescheduled когда use-case материализуется.

| Sub-piece | Из эпика | Что | Re-open trigger |
|---|---|---|---|
| Installer link/release wiring (`scripts/install.{sh,ps1}` + docs) | install-scripts 2026-06-01 session | Shipped rustup-style installers: `scripts/install.sh` (Linux/macOS `curl … \| sh`) + `scripts/install.ps1` (Windows `irm … \| iex`) that download sha256-verified prebuilt binaries (`veil-cli` / `ogate` / `oproxy-client` / `oproxy-server`) from GitHub Releases into `~/.veil/bin`, then guide the user `config init` → `node run`.  Plus `docs/{en,ru}/install.md`, README one-liners, and docs-index links.  URLs hardcode `raw.githubusercontent.com/veilnetwork/veil/master/scripts/…` and `github.com/veilnetwork/veil/releases/download/<tag>/…`.  Validated offline only (shellcheck clean; E2E fixture test download→sha256-verify→install→guide + tamper-abort) — NOT yet against a live release: none published (`/releases/latest` → 404; repo private or no tag cut). | **After the first GitHub Release is cut** (`release.yml` workflow_dispatch). Then verify / fix links if needed: (1) repo is public so anonymous `curl` can reach `raw.githubusercontent.com` + release assets; (2) `latest` API resolution + asset names (`<bin>-<triple>` / `…-<triple>.exe`) + `sha256-<triple>.txt` bare-name lines match what `release.yml` uploads; (3) the `master`-branch raw URLs (update if the default branch or canonical install URL changes — e.g. a custom domain / shortlink). |
| DHT disk cold tier via `[dht] cold_store_path` (RocksDB wiring) | macOS 2026-05-29 session | Shipped в commit `3ad78317`: gives the previously-dead `rocksdb-cold` **default** feature а real consumer.  Before, `RocksDbCold` was instantiated nowhere — the daemon built ~31 MB of C++ for nothing и always ran the all-in-memory `TieredStore::new`.  New `veil-dht::store::build_tiered_store(hot, cold, cold_store_path)` selects the cold backend: `None` → in-memory (unchanged); `Some(path)` + `rocksdb-cold` feature → `TieredStore::with_cold(RocksDbCold::open(path))` (disk-backed, durable across restarts, sized для > 1M entries — disk space + optional `max_store_bytes` bound it, не RAM); missing feature OR RocksDB open failure → loud `log` + fall back to in-memory (matches the daemon's universal best-effort snapshot-persistence convention — а persistence-layer error never takes the node down; making `with_config` fallible instead would have churned ~20 call sites).  Threaded `cold_store_path: Option<String>` through `DhtRuntimeConfig` (traits.rs) + `KademliaInner::new`/`with_config` + `cfg::DhtConfig` (serde `default` + `is_default` + `Default`) + `runtime_config_from` (node-runtime dht_glue).  Hot tier stays RAM-only by design; `values_persist_path` (periodic JSON snapshot) is the complementary way к restore hot entries on restart.  Tests: rocksdb durability across drop+reopen (gated), feature-agnostic `Some(path)` round-trip (covers the in-memory fallback), in-memory `None` path, cfg TOML/JSON round-trip с `cold_store_path` set.  `docs/{en,ru}/OPERATIONS.md`: dedicated-DHT profile note + tradeoff-table row.  Full local CI re-run green: hygiene (fmt / clippy `-D warnings` / cfg-gate / cargo-audit) + 3899/3900 nextest + doctests + 3-node devnet-smoke (cross-node DHT round-trip OK).  Two pre-existing macOS-only test-env failures surfaced by the run (veil-ipc `sun_path` 111 > 104; socks5 bench loopback ephemeral-port exhaustion) fixed в `27ea2ea8` — both already green on Linux CI. | Wiring complete.  **Known gap (audit M-A, 2026-05-30): the RocksDB cold tier has NO automatic eviction.** `retain_newer_than` (DHT TTL) and `evict_oldest` (byte cap) inherit the no-op `ColdBackend` trait defaults (raw values carry no insert timestamp to order by), and the entry-count `cold_cap` is dropped on this path. RocksDB background compaction only reclaims explicitly DELETE'd keys, NOT TTL-expired ones — so demoted cold entries persist on disk indefinitely and `max_store_entries`/`max_store_bytes` do NOT bound a disk cold tier (the earlier "entry-count path is the hard limit" claim was wrong; `store.rs` comments corrected).  **Follow-up (correctness, not just optimization):** give `RocksDbCold` a timestamp-prefixed value format (or a side timestamp column family), implement `retain_newer_than`/`evict_oldest` + entry-cap with migration handling for existing on-disk stores, and validate under `--features rocksdb-cold`.  Also bound the republish path so `TieredStore::iter()` (via `stored_entries()`, called ~1×/s) does not materialize the whole cold tier into RAM (audit M-B). |
| Config signing chain (Этап 11a/b/c/d/e) | macOS 2026-05-28 session | **Chain end-to-end shipped в 5 slices**: **11a** (`a0e6d7b2`) `veil_cfg::signed_config` primitive + warn-only load integration; Ed25519 / Falcon-512 / Hybrid signature над domain-separated canonical message (`veil-signed-config:v1`); signature lives в а `# VEIL_CONFIG_SIGNATURE_V1: <base64>` comment-line header (TOML-syntax-invariant).  **11b** (`210f98d3`) `veil-cli config sign` CLI verb с `--issued-at` / `--stdout` flags + `ConfigOps::write_raw_config` trait method (atomic_write via veil-util); 5 test-fixture impls extended.  **11c** (`0e883b64`) `VEIL_CONFIG_TRUSTED_ISSUER_PUBKEY` env-var pinning + DEBUG `signed_config_pinned` log + INFO `pinned=true|false` field + dedicated "Config signing" section в `docs/en/OPERATIONS.md` (signing workflow / pinning setup / log scrape patterns / threat-model framing).  **11d** (`4d4c4e8c`) `GlobalConfig::require_signed_config: bool` + new `SignedConfigStatus` enum that `load_config` checks against the flag; refuses non-Verified загрузка when set.  **11e** (`dd6a7812`) `[dht] per_origin_max_bytes` per-signer byte cap в `TieredStore` (entry_origin map + origin_bytes counter; `put_with_origin` API + `KademliaError::PerOriginByteCapExceeded`) plus one-shot deprecation warn at first acceptance of an unsigned STORE via `allow_unsigned_store=true` (`warn_unsigned_store_once`).  OPERATIONS.md adds а 4-row deployment matrix (Leaf / Core / DHT seed / legacy inner-sig) + sed-based migration walkthrough + log scrape pattern.  Total: **31 unit tests** (23 from earlier slices + 6 store-layer + 2 wire-level kademlia: `handle_store_unsigned_shares_bucket_under_per_origin_cap`, `handle_store_signed_isolates_origins_under_per_origin_cap`).  130/130 dht + 156/156 cfg + 71/71 integration. | Closed via slice 11e. |
| MlockedBytes apply к remaining key sites (`veil-crypto::identity::derive_master_sk_ed25519`, `veil-identity::master_seed::generate_master_seed`, `sovereign_flow` ~6 sites, `pair_runtime::target_identity_sk_seed`, peer_mlkem cache, AEAD session_cipher keys) | macOS 2026-05-28 session | **Infrastructure 9-slice complete (slices 6a/6b/6c/6d/6e/6f/6g/6h/6i)**: slice 6a (`5f0bc04c`) shipped `veil_util::sensitive_bytes::SensitiveBytes` enum-wrapper + applied к 3 `session_kdf` OKM derivation sites; slice 6b (`ed78b111`) `MlockedBytes::lock_region` + `madvise(MADV_DONTDUMP)` core-dump exclusion; slice 6c (`5379375b`) operator docs (`docs/en/OPERATIONS.md` — `LimitMEMLOCK=infinity` + systemd / Docker / Kubernetes deployment matrix + mlock_fallback scrape pattern); slice 6d (`99070833`) added the const-generic `SensitiveBytesN<const N: usize>` companion type + pilot migration at `veil-identity::master_file::derive_key` (master-seed AEAD key).  Slice 6e (`8aa91824`) migrated `veil-session::TicketKey` (host ticket key — process-lifetime AEAD key encrypting all session-resumption tickets, rotates every ~30 days; highest blast-radius of all session-scoped AEAD keys).  Slice 6f (`cbb53478`) migrated `veil-e2e::derive_key_from_passphrase` + `derive_key_v1` (Argon2 AEAD keys encrypting the persistent ML-KEM DK seed at rest на disk).  Slice 6g (`44b193da`) migrated `mlkem_dk_seed: Arc<SensitiveBytesN<64>>` в both `CryptoContext` и `RuntimeIdentity` — the persistent ML-KEM-768 decapsulation seed itself (longest-resident PQ secret в the runtime, every E2E ciphertext addressed к the node is decrypted с it).  Slice 6g bonus regression fix: pre-existing `Arc<[u8; 64]>` storage had NO zeroize-on-drop, only the SensitiveBytesN migration introduced reliable wipe-on-drop semantics для that field.  Slice 6g bonus flake fix: `rand_seed_for_pick_changes_across_calls_with_same_trace_id` relied на 1 000-iteration black-box CPU loop forcing wall-clock advance, replaced с `std::thread::sleep(Duration::from_micros(100))`.  Slice 6h (`80215c7d`) migrated the `per_session_mlkem_dk` HashMap value type от `[u8; 64]` к `SensitiveBytesN<{ DK_SEED_BYTES }>` — session-lifetime ephemeral PQ secrets now mlocked while sessions are open.  Migration touched the `PerSessionMlKemDk` type alias (single source of truth в `veil-session/src/runner.rs:47`) + `CryptoContext` + `IdentityState` + the runtime construction site + insert site (`runner.rs:911` wraps via `from_bytes`) + 2 lookup sites (`delivery.rs:1226` + integration test) using `.map(|s| *s.as_array())` to bridge the !Copy boundary.  Slice 6h closed а secondary regression: pre-slice the HashMap held plain `[u8; 64]` с no zeroize-on-drop, so removed entries left bytes в heap allocator pools.  Slice 6i (`111db1f2`) migrated `identity_sk_seed` across the entire create/restore/rotate/standalone/pair lifecycle: 3 output struct fields (`CreateIdentityOutput` / `RestoreIdentityOutput` / `RotateIdentityOutput`) + `save_identity_sk` / `load_identity_sk` persistence helpers + `build_standalone_identity_document` + `save_standalone_identity_to_dir` + `save_paired_target_state` + `SovereignIdentity::from_parts` / `from_parts_active` constructors + 3 internal OsRng-generation sites + 8 external caller sites (pair_runtime test, pair_transport test, pairing_forwarder production, runtime/identity_loaders standalone path, veil-cli CLI 4 sites, sim/scenarios 3 sites).  Original "~20-site API ripple" estimate was conservative — actual scope was 99 insertions / 75 deletions across 9 files, since most callers followed the same `.as_array()` borrow pattern at the `ed25519_dalek::SigningKey::from_bytes` boundary.  4 now-unused `use zeroize::Zeroizing` imports cleaned up. Test stats: 71/71 integration; 11/11 sensitive_bytes; 18/18 master_file + sovereign-flow; 14/14 ticket; 24/24 e2e; 119/119 dispatcher; 208/208 session; 201/201 node-runtime; 337/337 identity; 206/206 cli single-threaded. | Slice 6j (session-scoped AEAD keys inside `ChaCha20Poly1305` cipher state) gated on upstream cooperation/fork — not bounded scope without forking.  Production rollout gate: testnet soak ≥ 1 week с `LimitMEMLOCK=infinity` AND scrape-alerts on `mlock_fallback` warn line. |
| TLS ECH real-config resolution via DNS HTTPS RR (Этап 10 slice 3) | macOS 2026-05-28 session | Shipped в commit `647b10cc`: completes the Этап 10 ECH chain.  `connect_pki_verified_https_stream` теперь tries real ECH first (resolves the target's `EchConfigList` от its DNS HTTPS record per RFC 9460), falls back к slice 2c's GREASE on any DNS-side failure.  New `veil-transport::ech_dns` module wraps а process-wide hickory `TokioResolver` (built lazily от system config с а 3 s lookup timeout) и exposes `query_https_ech(host) -> Option<Vec<u8>>`.  `DnsResolver` trait extended с `resolve_https_ech` (default impl returns `None`); `SystemDnsResolver` overrides к delegate.  New `tls.rs::resolve_real_ech_mode(host, ctx)` helper encapsulates try-real-fall-back-к-grease logic.  Soft-failure model: DNS errors NEVER propagate as TLS errors — logged at DEBUG (`tls.ech.dns`); successful real-ECH selection at INFO.  Caching NOT shipped (bootstrap fetches are rare); retry-on-rejection NOT shipped (caller retries manually).  Until operators publish HTTPS records с the `ech` SvcParamKey, slice 3 stays а silent no-op.  OPERATIONS.md adds а new "Publishing а real ECH config (slice 3 operator-side)" subsection walking through EchConfig generation, HTTPS RR publishing, и `[tls.ech.dns]` log verification.  1 new test (93/93 veil-transport green); workspace clippy clean. | **Этап 10 closed end-to-end** — every slice on the original rubric shipped: Falcon-1024 crypto + identity creation, plus all four TLS ECH slices (2a foundation, 2b/2c wiring + default flip, 3 real-ECH-via-DNS).  Future work: caching layer + retry-on-rejection (optimization, не correctness). |
| TLS ECH aws_lc_rs migration + GREASE wiring + default flip (Этап 10 slices 2b+2c) | macOS 2026-05-28 session | Shipped в commit `c1b5663b`: bundled slices 2b и 2c because the dependency-migration risk profile is the same whether the default flag is `false` или `true`.  **Slice 2b crypto migration**: 4 quinn feature flags `"rustls-ring"` → `"rustls-aws-lc-rs"` (veil-nat, veil-node-runtime, veil-transport, veilcore) + 4 `rustls::crypto::ring::default_provider()` call sites switched к `aws_lc_rs::default_provider()` (3 в veil-nat, 1 в veil-transport).  Net binary size delta: ~3 MB; compile time delta: ~20-30 s on M2-class hardware.  **Slice 2b ECH GREASE wiring**: `TransportContext.tls_ech_grease: bool` field + builder + `build_ech_grease_config()` helper (`DH_KEM_X25519_HKDF_SHA256_AES_128` + 32-byte random placeholder) + `connect_pki_verified_https_stream` switches к `ClientConfig::builder_with_provider(aws_lc_rs::default_provider()).with_ech(EchMode::Grease(grease))` when the flag is on — pins TLS 1.3 (rustls `with_ech` requires it).  Plumbed от `GlobalConfig.tls_ech_grease` через `transport_glue::context_from_config`.  **Slice 2c default flip**: `GlobalConfig::default_tls_ech_grease() -> bool { true }`.  Operators stuck on TLS-1.2-only public CDNs override к `false` explicitly.  Tests: 2 new (`etap10_slice2c_*` replacing slice-2a tests), 158/158 cfg + 92/92 transport + 201/201 node-runtime green под aws_lc_rs. OPERATIONS.md updated: rollout table bumped к "✅ shipped 2026-05-28" for slices 2b+2c; new "Why TLS 1.3 pinning" + "Dependency migration" subsections. | **Slice 3** (deferred): real ECH с `EchMode::Enable(EchConfig::new(...))` driven от DNS HTTPS records.  Realistic scope ~500-600 LoC: DNS HTTPS RR resolution + EchConfig parsing/caching + retry-on-rejection.  Mostly dead code until operators publish HTTPS RR с ECH payloads в DNS — defer until concrete adoption signal.  GREASE-only state (current master) уже gives 80% censorship-resistance value: middleboxes больше не могут distinguish ECH-capable от non-ECH connections. |
| TLS ECH foundation (Этап 10 slice 2a) | macOS 2026-05-28 session | Shipped в commit `f44bb512`: `GlobalConfig.tls_ech_grease: bool` flag (default `false`) + audit-trail comment at `veil-transport::tls::connect_pki_verified_https_stream` marking the actual ECH integration point as `Этап 10 slice 2b candidate` + new "TLS ECH (Этап 10 slice 2)" section в `docs/en/OPERATIONS.md` с а 4-row rollout table (2a → 2b → 2c → 3), cover-traffic argument explainer, operator config snippet, и а "why dependency migration is gated" subsection justifying the staged approach к the `rustls-ring` → `rustls-aws-lc-rs` provider swap (binary size + compile time + 4 direct + ~30 transitive sites).  2 new tests (158/158 cfg green). | **Slice 2b** (pending): workspace crypto-provider migration + actual `EchMode::Grease(...)` wiring at the call site; default flag stays `false` для one release cycle.  **Slice 2c** (pending): default flip к `true`.  **Slice 3** (future): real ECH с `EchMode::Enable(EchConfig::new(...))` driven от DNS HTTPS records — operator-side DNS publishing infra required, defer until concrete adoption signal. |
| Falcon-1024 hybrid sovereign-identity creation (Этап 10 follow-up) | macOS 2026-05-28 session | Shipped в commit `69296f0d`: lifts the explicit-Err gate в `create_identity` / `restore_identity` для `Ed25519Falcon1024Hybrid` — completes the Этап 10 chain (crypto primitive + wire-byte mappings были present since slice 1).  pk layout = `ed_pk(32) || falcon1024_pk(1793)` = 1825 B; sk layout = `ed_sk(32) || u16_le(falcon_sk_len) || falcon1024_sk (~2305 B)`.  BIP-39 phrase recovers ONLY the Ed25519 half (mirror of 512-hybrid pattern); Falcon-1024 SK lives в `master_falcon.bin` (file name shared с 512-hybrid; disambiguated by `master_algo = 4`).  4 match arms + 2 falcon_pk-extract sites + verify_proof_sig / verify_ephemeral_sig arms updated. 2 new tests (full end-to-end + collision-guard vs 512-hybrid); 339/339 identity green. Wire format: persistent files use the same shapes as 512-hybrid documents — only master_algo byte distinguishes. | Sovereign-identity creation for Falcon-1024 теперь production-ready; operators want PQ Level 5 margin can `--algo ed25519+falcon1024` from CLI today. |
| Ed25519+Falcon-1024 hybrid signature algorithm (Этап 10 slice 1) | macOS 2026-05-28 session | Shipped в commit `49aaadb0`: `SignatureAlgorithm::Ed25519Falcon1024Hybrid` variant (wire byte 4, "ed25519+falcon1024" / "hybrid1024") + crypto layer (`generate_keypair` / `sign_message` / `verify_message` / `decode_public_key` / `decode_private_key`) + `MAX_FALCON1024_SIG_BYTES = 1462` cap + 3 split helpers (pk/sk/sig).  Wire-byte mappings extended through 13 sites: `veil-anonymity::directory + rendezvous` (3 sites в rendezvous), `veil-bootstrap::invite/signed_bundle/signed_invite`, `veil-update::manifest`, `veil-discovery::directory` (2 sites), `veil-identity::network_cert`, `veil-cfg::signed_config`, `veil-proto::identity_document::ALGO_ED25519_FALCON1024_HYBRID = 4`, `veil-cli::update_cmd`, `veil-types::SignatureAlgorithm` (5 method extensions). Identity-creation flow returns clear "not yet wired — use Ed25519Falcon512Hybrid" error при `opts.algo == Ed25519Falcon1024Hybrid` в both create и restore paths (BIP-39 master-seed derivation for the 1825-byte hybrid layout = future slice).  6 new tests in signature module (10 total green). OPERATIONS.md adds а 4-row algorithm matrix + availability checklist. | Sovereign-identity creation slice for Falcon-1024 hybrid (BIP-39 master-seed → 1825-byte hybrid pubkey layout with dedicated freshness/rotation/recovery path) — гейтнуто на adoption signal (operators explicitly requesting the higher PQ margin для long-lived identities).  TLS ECH default-on (the second half of original Этап 10 framing) is а separate feature build — needs TLS-backend selection + rustls ECH integration. |
| In-band introducer wire-frame | 481.3 | `IntroduceRequest{introducer, sponsoree, expiry, sig}` через PEX для transitive trust signal | Сценарий не покрытый existing 5 bootstrap layers (mass-onboarding флешмоба, etc.) |
| `.onion` seed-source (481.4) | macOS 2026-05-29 session | ✅ **shipped**.  The bootstrap layer now fetches the **signed** seed bundle from а `.onion` URL listed in `[global] bootstrap_https_urls` through а Tor SOCKS5 proxy (`[global] bootstrap_tor_socks_proxy`, e.g. `socks5://127.0.0.1:9050`) — the operator's last-resort path when every clearnet CDN / DNS layer is blocked.  **Transport** (`veil-transport::socks`): new `pub connect_socks5_stream(proxy_url, host, port)` + `parse_socks_proxy_url` over the existing private `connect_socks_stream` (tokio_socks; `.onion` handed across as а SOCKS5 **domain** addr — resolved by Tor, never locally → no DNS leak).  **Bootstrap** (`veil-bootstrap::https`): `parse_onion_url` (plain `http://`, `.onion`-only, default port 80), `is_onion_url`, pure `classify_bootstrap_url` (Clearnet / Tor / OnionNoProxy), `fetch_seeds_via_tor` (+`fetch_bytes_via_tor`) reusing the generic `http_get_over_stream` + `decode_with_policy`; the `.onion` path is **force-signed** (never `legacy_unsigned`, even when `legacy_allow_unsigned_bootstrap=true`) and reuses `trusted_bundle_issuer_pubkey` for pinning.  Shared `strip_scheme_ci` + `parse_authority`-on-`/?#` keep the routing predicate и the parser in agreement.  **Trust model**: `.onion` self-authenticates (address = service key, via Tor rendezvous) + Tor-encrypts, so plain HTTP is correct (no public-CA cert); the bundle signature provides authenticity.  **Config**: `GlobalConfig.bootstrap_tor_socks_proxy: Option<String>` (default `None`; `.onion` URLs skipped fail-soft when unset — а logged per-URL error, bootstrap continues on clearnet).  **Runtime**: `service_tasks::spawn_bootstrap_https_task` branches per-URL via `classify_bootstrap_url`.  Reviewed by а 4-lens adversarial workflow (5 findings fixed: untested routing branch → pure `classify_bootstrap_url` + test; parser/predicate disagreement on query/uppercase-scheme → aligned; +issuer-mismatch & explicit-port e2e tests).  Tests: 117 veil-bootstrap (incl. end-to-end through an in-process SOCKS5 mock asserting domain-passthrough + signed-bundle verify + force-signed-rejects-raw + wrong-issuer + explicit-port), 2 socks-parser, 1 cfg round-trip; clippy `-D warnings` clean.  docs/{en,ru}/OPERATIONS.md: ".onion bootstrap source (Tor)" section. | Closed.  Future (optional): per-`.onion` timeout tuning (Tor latency) and concurrent multi-`.onion` fetch — only if а deployment hits the 10 s fetch cap on slow circuits. |
| Anti-loop TTL field в circuit envelope | ✅ done (commit `c252df2`, 2026-05-09) | Wire format: each layer plaintext gained а 1-byte TTL prefix.  Honest sender encodes TTL = `hops.len() - layer_idx + 1`; receiver validates `1 <= ttl <= MAX_CIRCUIT_TTL (16)`.  Adversarial amplification capped at 16 forwards regardless of payload size.  4 new tests + 2 existing tests updated для new PER_HOP_OVERHEAD = 93.  192 veil-anonymity tests pass. |
| Stateful `CircuitId` для persistent circuits | 482.7 | CircuitId-tagged sessions, build once → send N messages, anti-replay window per circuit | Perf-driven need: interactive chat shows high re-build overhead vs message latency |
| Path-product latency optimization | 482.6 | Pairwise RTT discovery для inter-hop legs | Current sum-of-sender-RTT proxy показывает sub-optimal paths в production |
| Bandwidth-quota tracking + claim verification | 482.3 / 482.4 | Separate counters anonymity-relay vs обычного traffic; reputation-based downweighting | Abuse incidents — relay flooding или lying about advertised_bps |
| Hot-standby auto-swap to template `tcp://127.0.0.1:0` URI in sim | ✅ done (commit `003e28c`, 2026-05-09) | Per-handshake `local_advertised_transports` snapshot в `runtime/mod.rs` now substitutes `local_addr` для listens whose config used а port-0 placeholder и operator did not set explicit `advertise`.  Kernel-assigned port becomes the advertised URI.  Operator-set `advertise` still wins if specified.  Two new helpers (`uri_has_port_zero`, `uri_scheme`) + 2 unit tests verify edge-case URIs. |
| Sybil ID-grinding sim scenario | ✅ done (commit `6eac9cb`, 2026-05-19) | Landed as `epic485_1d_prefix_grinded_sybils_still_bounded_by_eclipse_cap` (sim/scenarios.rs:3115).  Sim API extended с prefix-grind sybil config in [sim/network.rs]; scenario verifies eclipse fraction stays bounded даже когда attackers mine node_ids к match target's bucket prefix.  Companion to existing 485.1 floor-tests. |
| Sybil bucket-pollution sim scenario | 485.1 | Sybils respond к honest FIND_NODE queries with crafted contacts pointing к further sybils, slowly building a poisoned shortlist.  Phase 6.47 / Audit-H22 strict-progress filter (`r_dist > peer_dist`) plus per-round AS-prefix cap is supposed к block this; the scenario validates by having sybils run a synthetic peer_querier that returns same-distance siblings.  ~200 LoC + crafted-FIND_NODE-reply injection API in sim. | Same trigger — Kademlia regression OR new attack class. |
| Sybil churn-aware sim scenario (24h-equivalent) | 485.1 | Existing 3 scenarios measure steady-state at session-open.  24h equivalent requires simulated bucket evictions over time — sim is real-time only today, so this needs either (a) `tokio::time::pause()` + simulated time advancement to fast-forward bucket-eviction TTLs, or (b) shortening eviction TTLs in the sim config to make 24h fit in seconds.  ~250 LoC including the time-control infra. | Same trigger; also unblocks future scenarios that need simulated time (e.g. 24h activity gossip, expired-record cleanup). |
| Identity time-validity policy: `valid_from` / `issued_at` | ✅ done (commit `e4cc5e2`, 2026-05-08) | Wire format already carried all fields — only verifier-side enforcement was missing.  Added 2 new error variants (`VerifyError::NotYetValid`, `VerifyError::KeyNotYetValid`) + checks в `verify_identity_document` (Step 3 + Step 4b').  Same pattern applied к `verify_identity_proof` (`ProofVerifyError::KeyNotYetValid`).  Public constants `TIME_VALIDITY_SKEW_SECS = 60`, `FRESHNESS_HOUR_SKEW = 1`.  Legacy `0`-sentinel preserved для backward compat с pre-6.49 identities (they accept silently). |
| Identity proof `freshness_hour` enforcement | ✅ done (commit `e4cc5e2`, 2026-05-08) | Same commit as above — `verify_identity_proof` now enforces `\|floor(now/3600) - declared_hour\| ≤ 1`.  Stale-proof replay window collapses from "anywhere в the past until proof_valid_until" к "within ±1 hour of mint time".  6 unit tests cover both lower-bound и freshness-hour paths plus boundary acceptance (skew=±60 s exactly, freshness=−1 hour exactly).  All 308 veil-identity tests pass. |
| `AnycastService::resolve` signed records / reputation | Phase 6.49 audit (2026-05-08) | `score` is peer-controlled — а sybil can claim `score=0` and pull all anycast service traffic к itself.  Fixes (any combination): owner-signed `AnycastRecord` (only the canonical service owner can publish), per-service reputation slice that downweights nodes which fail к serve advertised traffic, quorum vote requirement при first-time resolution.  Currently anycast is documented как "best-effort discovery" — no trust-sensitive use case in production yet, so the gap is paper-acknowledged. | Operator wants к use anycast for trust-sensitive routing (e.g. service-discovery in production) OR observed sybil behaviour in а real anycast deployment. |
| `DhtBackedPublisher` periodic re-replication worker | ✅ done (commit `5029eea`, 2026-05-08) | Investigation showed the periodic tick already shipped earlier (`spawn_dht_republish_task`, interval = TTL/2 ≈ 30 min, filters self-authenticating records, fans out via `store_replicated`).  The actual gap was visibility — fan-out result был discarded (`let _ = ...`).  Fix: lifted `store_replicated` к return `Result<usize>` (replicas successfully queued); added 2 Prometheus counters (`veil_replicas_published_total`, `veil_replicas_under_count_total`); wired both counters в `dht_republish.rs` plus а new `dht.republish.under_count` warn event.  Fire-and-forget design preserved (no STORE-ack wait — would slow re-publish to RTT × K).  Re-open if а sustained `replicas_under_count_total` spike actually correlates с lost records OR if per-peer failure tracking / exponential backoff become needed. |
| HTTPS bootstrap MITM via `tls-boring`-shared transport | ✅ done (commit `782435f`, 2026-05-09) | New `connect_pki_verified_https_stream` entry-points в both `crates/veil-transport/src/tls.rs` (rustls + Mozilla webpki-roots) и `crates/veil-transport/src/tls_boring.rs` (boringssl + `set_default_verify_paths()` + `verify_hostname(true)`).  Bootstrap caller `crates/veil-bootstrap/src/https.rs` switched к the new entry-points.  ABI on veil peer transport unchanged — peer sessions still use `connect_tls_client_stream` с node-id-bound trust.  `webpki-roots` lifted от optional feature к required dependency on `veil-transport`; the `tls-webpki-roots` feature flag is preserved as а no-op for backward compat.  100 bootstrap + 43 transport tests pass.  Update path TODO: `fetch_manifest_with_failover` uses the same plumbing — switch к the new entry-point too in а follow-up slice (signed-manifest path is integrity-protected by Ed25519 sig, but defence-in-depth cleaner с PKI verify). |
| Update path PKI parity (HTTPS-fetch hardening follow-up) | ✅ done implicitly (commit `782435f`, 2026-05-09) | Investigation showed `crates/veil-update/src/fetch.rs` does NOT call the TLS layer directly — it routes through `veil_bootstrap::fetch_bytes_https` и `veil_bootstrap::fetch_binary_bytes_https`, which were both switched к the PKI-verified path в the bootstrap commit.  No additional changes needed; `cargo test -p veil-update` regression-covers the integration. |
| `SessionRunner::run` god-function decomposition (slices 1-8) | ✅ done (slices 1-8 shipped 2026-05-10; slices 9-28 shipped через 2026-05-21 — см. row "SessionRunner decomposition slices 9-N" below).  Full campaign result: `run()` 1700 → **854 LoC** (-50%). | `veilcore/src/node/session/runner.rs` — `pub async fn run(&mut self)` was 1700 LoC, now **1542 LoC** (158 LoC carved out into 7 typed modules).  **Why gated:** production-critical hot path on adversary network input — an extraction bug in the rekey FSM или AEAD layer would manifest as silent session failures across the cluster, not а compile error.  Decomposition needs (a) baseline integration coverage of every existing combination of arms (handshake×rekey×swap×battery), (b) PR ladder с each slice independently green, (c) live testnet soak per PR before next slice. | **Coverage gate (5/5 shipped, 2026-05-10):** (1) **Mutual-rekey collision** — commit `346b0fd`, kept_init + aborted_init paths of d916e3b tie-breaker (`phase650b_mutual_rekey_collision_*`).  (2) **Rekey-during-swap convergence** — commit `2a858b5`, AwaitingAck preserved across SwapStream branch, RekeyAck on warm wire completes rekey (`phase650b_rekey_state_survives_transport_swap`).  (3) **Rekey bypasses low-battery deferral** — commit `8094229`, INTERACTIVE-priority RekeyInit not held by Epic 483.5 outbound-batch window; round-trip <500 ms vs 1 s configured window (`phase650b_rekey_bypasses_low_battery_deferral_window`).  (4) **Hot-standby trigger during rekey** — commit `053def6`, fire_hot_standby_trigger("rx_stall") while AwaitingAck does not corrupt rekey_state; RekeyAck on warm completes rekey (`phase650b_rekey_state_survives_hot_standby_trigger_firing`).  (5) **Idle-timeout fires during AwaitingAck when peer silent** — commit `7a8237f`, last_rx ticker is NOT reset by runner's own rekey emission; idle_timeout closes session after 500 ms regardless of rekey-in-flight (`phase650b_idle_timeout_fires_during_awaiting_ack_when_peer_silent`).  Test infra: shared `read_non_padding_header` + `drain_trailing_padding` helpers handle coalesce-with-padding cipher-counter sync.  Session-runner suite: 61/61 passing (added 5 gate tests on top of existing 57).  All gate tests 30/30+ stable on iteration loop.  Plus pre-decomposition prep: 2 timing-flake stabilizations (commit `56e93d0`) + Slice 3 NodeServices/SessionRuntimeContext identity-bundle collapse (commit `cb000b0`).  **Slices shipped 2026-05-10 (gate-protected):** (S1, `80cf6bf`) `send_pending_session_ticket` extracted from inline Epic 215 ticket-emission block.  (S2, `4c673ce`) `PendingResponseTable` extracted from 3 duplicated inline blocks of `pending_responses: HashMap` + `pending_deadline: BTreeMap` с TTL/capacity/dedupe logic; +5 unit tests.  (S3, `20cf7c3`) `RekeyRxGraceBuffer` extracted от inline `rx_cipher_prev: VecDeque` (Phase 6.33 + 6.47-H19 grace ring); +5 unit tests.  (S4, `69be205`) `BatteryAdjustedKeepalive` extracted от inline 60-s battery+bg-factor recompute logic (Epic 220 + 483.1); +7 unit tests.  (S5, `36ab21c`) `MlKemRekeyContext` extracted от Epic 190 ML-KEM E2E rekey FSM + threshold ledger; +8 unit tests.  (S6, `72807c8`) `SessionTimers` extracted от 4 inline mutable timer-deadline locals (last_rx, next_keepalive, next_cover, keepalive_interval) + their static enable-flags; read-only `last_rx()` accessor enforces gate-Test-5 invariant; +8 unit tests.  (S7, `bfb9e0c`) `SessionRotationDeadline` extracted от Epic 488.1 jittered-deadline math + Timer-arm rotation check; +3 unit tests.  (S8, `d8a793d`) `RekeyContext` extracted от ~12 scattered references covering X25519 rekey FSM (init triplet, threshold check, bytes accumulation на 4 sites, RekeyInit/RekeyAck handlers, d916e3b collision tie-breaker, responder/initiator rekey-complete paths); +10 unit tests.  Net: 1700 → 1542 LoC in run(); +56 unit tests across 8 new modules (`session/{pending_response_table, rekey_rx_grace_buffer, battery_adjusted_keepalive, mlkem_rekey_context, timers, rotation_deadline, rekey_context}.rs`); gate tests 13/13 stable on each slice's 20-25 iter loop.  **Re-open trigger:** continue slicing когда runway permits.  Audit recommends 1-week testnet soak between slices; running them back-to-back в one session relies on the gate tests' combinatorial coverage.  Remaining inline state worth extracting: write-error counter + auto-trigger machinery; alias-guard scope; outbox/rpc-outbox ownership lifetime; the actual frame-decrypt/dispatch loop (largest remaining block). |
| `NodeRuntime` god-object decomposition (85 fields) | ✅ done (PR1-PR5 shipped 2026-05-09) | Decomposition ladder complete в 5 PRs: **PR1 AnonymityState (cd9a019)** — 4 anonymity fields, fixed `private_interfaces` warning; **PR2 MailboxState (979750f)** — `mailbox` + `outbox` handles, typed home для #316 follow-ups; **PR3 MobileState (b02db01)** — `mobile_background_mode` + 4 `battery_*`, collapses 5×3=15 fields → 1 Arc×3 structs, reload preserves AtomicBool; **PR4 RoutingState (966908b)** — `rtt_table` + `route_cache` + `neighbor_scorer` + `vivaldi` (~30 callsites, FrameDispatcher Arc-clones intact); **PR5 IdentityState (7d7e9a5)** — `local_identity` + `sovereign_identity` + `peer_pubkeys` + `peer_sovereign_identities` + `peer_roles` + `mlkem_ek` + `peer_mlkem_keys` + `per_session_mlkem_dk` (50+ callsites, reload rebuilds bundle Arc preserving peer-cache Arcs).  Net: NodeRuntime field count down by 21 sibling fields → 5 typed Arc bundles.  Each domain has its own `runtime/<name>_state.rs` module + ctor.  Reload semantics preserved (inner-mutate where feasible; bundle-Arc swap для `local_identity` reload, matching pre-PR5 stale-clone semantics on downstream contexts).  Tests за all 5 PRs: veil-mailbox 65/0, veilcore node:: 494/0 (with 2 pre-existing flakes `keepalive_prevents_eviction` + `end_to_end_handoff_pipeline_via_peek_and_dispatch`, verified flaky on master).  Future cleanups (collapsing duplicate fields на NodeServices/SessionRuntimeContext) deferred — would touch ~50 more callsites without reducing total field count meaningfully relative к migration cost. |
| KDF / TLS panic-graceful conversion | ✅ done (Phase 6.50.b commit pending, 2026-05-09) | Lifted hardcoded `96`-byte OKM size в `crates/veil-crypto/src/session_kdf.rs` к а module-level const `SESSION_OKM_LEN`, then guarded it with two compile-time `const _: () = assert!(...)` checks: (a) `OKM_LEN_VALID` pins `SESSION_OKM_LEN ≤ 255 × 32 = 8160 B` (HKDF-SHA256 max okm); (b) `OKM_LEN_DIVISIBLE` pins `SESSION_OKM_LEN == 96` (3 × 32 B keys).  Verified: setting the const к 9000 produces `error[E0080]: evaluation panicked: HKDF-SHA256 max okm exceeded` at build time, before the previously-silent runtime `expect()` chain would fire on every session derivation.  Comment trail updated на all 9 expect sites pointing back к the const_assert.  Zero API change, zero callsite churn.  TLS-boring panic on line 641 confirmed test-only (inside `#[tokio::test] epic480_6_chrome_client_hello_shape_regression`); production-side TLS path already returns `Err` cleanly. |
| `peer_mlkem_ek` field decision (Epic 486.1 placeholder) | ✅ done — removed in post-audit cleanup (2026-05-18) | Original decision (commit `d475d19`, 2026-05-09) was option (A) — keep с anchor.  Post-audit re-evaluation: the placeholder never earned its keep — Epic 486.1 slice 3 was never scheduled, the cold-start hybrid-KEX functionality is partially covered by `peer_mlkem_keys` cache + `meta_encrypt`/mailbox, and an anchored unread field bloated search results.  Removed the field + 6 `peer_mlkem_ek: None` callsites in handshake.rs/peer_handshake.rs.  Re-add trivially (one struct line + reading code) when slice 3 actually scheduled. |
| `BoundedDecoder` half-migration | ✅ done (delete-path, commit `b90c36e`, 2026-05-09) | Trimmed unused 7 public methods (`pos`, `remaining`, `read_u32`, `read_u16_prefixed_bytes`, `read_u32_prefixed_bytes`, `read_u8_prefixed_string`, `skip_remaining`).  Retained: `new`, `read_u8`, `read_u16`, `read_u64`, `read_array`, `read_bytes`, `assert_eof` (all used by `mlkem_cert::decode`).  −80 LoC.  If а future migration epic completes the surface (all proto decoders → `BoundedDecoder`), restore от git history. |
| `tls-boring` runtime panic on config error | ✅ done (verified test-only, 2026-05-10) | Audit mis-located the panic — actual `.unwrap_or_else(\|\| panic!(...))` is at `crates/veil-transport/src/tls_boring.rs:641` (NOT 574, which is ClientHello parse logic), and it lives inside `#[tokio::test] epic480_6_chrome_client_hello_shape_regression`.  Test panic, not production hot path.  Production-side TLS path already returns `Err` cleanly per the KDF / TLS panic-graceful row above (✅ done в Phase 6.50.b).  No code change needed; row preserved for audit-trail visibility. |
| Re-export shim cleanup | ✅ done (commit `44d7c16`, 2026-05-09) | Both shims (`node/ipc/mod.rs`, `node/local_transport.rs`) deleted.  Callsites switched к direct `veil_ipc::*` / `veil_local_transport::*`.  `veil-ipc` lifted от dev-dep к regular dep on `veilclient` Cargo.toml.  Net −39 LoC across two deleted shim files + 8 mechanical line-edits at callsites. |
| FFI callback non-nullable type retype | ✅ done (commit `d475d19`, 2026-05-09) | All 3 callback aliases retyped to `Option<unsafe extern "C" fn(...)>`; entry points (`veil_app_set_recv_handler`, `veil_peers_list`, `veil_set_event_handler`) gained а `match cb { Some(f) => f, None => INVALID_ARG }` prelude.  ABI on C-side unchanged.  New regression test `null_callback_set_event_handler_returns_invalid_arg`.  22 existing ffi tests pass. |
| **Mutual rekey-init collision (Phase 6.32 follow-up #2)** | ✅ done (commit `d916e3b`, 2026-05-09) | When **both peers** of а session hit `rekey_bytes_threshold` within RTT (~10-20 ms cross-VPS), each side sends `RekeyInit` simultaneously.  Each side then:  (1) receives peer's RekeyInit → responder path → generates fresh ephemeral, derives shared с peer's eph, sends ack, switches к gen-1.  (2) receives peer's RekeyAck к ITS OWN init → initiator path → derives shared с **its own** stored kp + the responder-generated eph in peer's ack, switches к gen-2.  Result: peer1's gen-2 keys = `KDF(p1_init_kp × p2_resp_eph)` ≠ peer2's gen-2 keys = `KDF(p2_init_kp × p1_resp_eph)`.  **Different keys on each side ⇒ all subsequent frames AEAD-fail forever ⇒ session.violation ⇒ teardown.**  Initiator path also doesn't stash prev rx (only responder does), so ring buffer protection from Phase 6.47-H19 doesn't apply к initiator-path frames.  Confirmed live on testnet b2 (2026-05-09 ~05:25 UTC): 7 dropped sessions on b2 specifically (всего у b2 max bidirectional traffic per pair → byte-threshold near-simultaneous).  **HIGH-severity correctness bug** — was hidden until Phase 6.32/6.33 visibility slice (commit b066cc9) made init.tx + init.rx events с peer_id observable. | Implementation: deterministic tie-breaker by node_id.  When the responder path receives RekeyInit AND `rekey_state == AwaitingAck`: if `local_node_id < peer_node_id`, **abort own init** (drop the AwaitingAck keypair), accept peer's init via responder path; if `local_node_id > peer_node_id`, **defer responder path** until own ack returns (буферизировать peer's init body, replay в receiver after own complete).  Symmetric on both sides ⇒ exactly one of the two becomes responder.  Adds а sim test that drives mutual collision through duplex pair и asserts (a) no session.violation, (b) both sides converge on same keys.  ~150 LoC. |

| Local TCP IPC/admin slowloris (accept-loop blocked by handshake) | ✅ done (Phase 6.50.b commit pending, 2026-05-09) | Split `LocalListener::accept_raw()` (returns immediately после kernel TCP-accept, без token-handshake) от `PendingStream::verify()` (caller-spawned task does the 32-byte read под `TOKEN_READ_TIMEOUT = 3 s`).  IPC server и admin server accept loops now use `accept_raw` + `tokio::spawn(async move { pending.verify().await … })`, so а silent client connecting к loopback TCP no longer blocks the accept loop.  Backwards-compat `accept()` wrapper retained для tests.  Regression test `tcp_accept_raw_unblocked_by_silent_client` verifies а stalled connect doesn't block subsequent legitimate accepts.  Local Unix socket path также benefits (uid-check happens after raw accept, before handshake-task spawn).  ~110 LoC across `crates/veil-local-transport/src/lib.rs`, `crates/veil-ipc/src/server.rs`, `veilcore/src/node/admin_transport.rs`, `veilcore/src/node/admin.rs`. |
| Build profiles: production-seeds gate в release/CI/Docker | ✅ done (commit `b370eea`, 2026-05-09) | `scripts/build-release.sh` default features changed `allow-empty-seeds` → `production-seeds`; new `--sign` policy gate refuses к sign а binary built с `allow-empty-seeds` (production-deploy footgun: artifact looks production-ready but won't bootstrap без operator-supplied peers).  `.github/workflows/release.yml` Windows job switched к `veil-bootstrap/production-seeds` matching Unix path.  `docker/Dockerfile` `CARGO_FEATURES` arg default changed к `production-seeds,quic-session`.  Override mechanism preserved для testnet builds (`--features veil-bootstrap/allow-empty-seeds` или `--build-arg CARGO_FEATURES=allow-empty-seeds,quic-session`).  Flutter android `build.gradle` row remains в Epic 489.2 scope. |
| Mailbox abuse architecture: slice 1 — capability tokens (verify) | ✅ done (Phase 6.50.b commit pending, 2026-05-09) | Receiver-signed capability-token primitive в `veil-mailbox::capability`: `MailboxCapabilityToken` с Ed25519 + Falcon-512 sig algos, encode/decode wire format, time-window check (±60 s skew), receiver-id binding via `BLAKE3(issuer_pk) == expected_receiver_id`, replay-bound only by token TTL.  `Mailbox::put_with_capability` is the new authorised entry-point; legacy `Mailbox::put` retained для in-process callers (the receiver's own node depositing к its own mailbox).  Wire-format extension: `MailboxPutPayload` got an optional second trailer (after `push_envelope`) carrying opaque token bytes — backward-compat preserved via length-prefixed-zero pattern (legacy senders still parsable; legacy daemons skip the new tail).  `MailboxConfig::require_capability_token` policy bit (default `false`) gates whether tokenless puts are accepted; new `PutOutcome::CapabilityRequired` / `CapabilityInvalid` variants surface через `MailboxPutOutcome` IPC и `MailboxPutStatus = 6/7` wire byte.  Mailbox is **app-layer** service (`MAILBOX_APP_ID = BLAKE3("veil.mailbox.v1")`, single PUT endpoint), so no OVL1 wire bump needed — extension lives в the app message body.  Tests: 19 capability-unit + 7 policy-gate + 4 proto-trailer = 30 new.  ~580 LoC across `veil-mailbox`, `veil-proto`, `veil-ipc`, `veilcore`. |
| Mailbox abuse architecture: slice 2 — RendezvousAd v3 token field + daemon mint + sender-side propagation | ✅ done (Phase 6.50.b commit pending, 2026-05-09) | RendezvousAd wire format bumped к v3: new `capability_token: Vec<u8>` field signed alongside the existing `auth_cookie` и `push_envelope` (length-prefix-bound, tamper-detected by sig domain).  Decoder accepts v1 (legacy, no envelope) / v2 (envelope only) / v3 (envelope + cap_token); encoder always emits v3.  Daemon-side mint integrated в the rendezvous-ad maintenance tick (`veilcore/src/node/runtime/maintenance.rs::mint_capability_token_for_ad`): uses the local identity's sk, validity window matches the ad's, falls back к empty for hybrid Ed25519+Falcon-512 identities (slice-1 verify doesn't accept hybrid).  Sender-side propagation: `ResolvedReplica.capability_token` field (IPC trait surface) + `MailboxClient::mailbox_put(.., capability_token: Option<Vec<u8>>)` SDK API; `lookup_rendezvous_replicas` IPC reply gained а strict cap_token trailer per `ReplicaWire`.  New `veil_mailbox::capability::sign_token` mint helper takes а closure-shaped signer к keep veil-mailbox а leaf crate.  10 new tests across veil-mailbox (4 sign_token roundtrip + bad-algo / bad-pk / inverted-validity) + veil-anonymity (5 v3 cases: round-trip, tamper detection, oversized rejection, both-trailers, v2→v3 backward compat).  Operators ready к flip `require_capability_token = true` after the new daemon ships к all mailbox relays AND senders в the pilot deployment have rolled out (mixed-version flip causes pre-slice-2 senders к hit `CapabilityRequired` rejections). |
| Mailbox capability v2 — relay-binding + high-level mint helper API | ✅ done (2026-05-18) | Wire format bumped to v2: `MailboxCapabilityToken` gains an optional `relay_node_id: Option<[u8; 32]>` field (None = v1 unbound, Some = v2 bound to а specific replica node_id).  Decoder auto-detects version via the leading version byte (1 = v1 / 2 = v2, header sizes 20 vs 52); v1 tokens still decode untouched (backward compat).  New domain-separated signing context `b"veil:v2:mailbox-cap-bound"` (vs v1 `b"veil:v1:mailbox-cap"`) closes cross-version replay — а v2-shaped token signed with the v1 context fails verify.  New `sign_token_v2` low-level + new `signed_message_for_versioned` canonical message builder.  New high-level mint helpers on `MailboxCapabilityToken`: `mint_unbound_ed25519(sk, valid_from, valid_until)` → v1 bytes, `mint_bound_ed25519(sk, relay_node_id, valid_from, valid_until)` → v2 bytes — apps now have а one-liner API instead of having to hand-compose `sign_token(...)` closures.  `verify()` extended: new `expected_relay_id: Option<&[u8; 32]>` parameter; semantics `(Some, Some)` must match else `RelayMismatch`, `(Some(v2), None)` → `RelayBindingRequired`, `(None, _)` → accept (v1 unbound), `(None, Some)` → accept (v1 ignores expected).  New error variants `CapTokenError::RelayMismatch { token_hex, expected_hex }` + `RelayBindingRequired`.  `MailboxConfig::local_node_id: [u8; 32]` plumbed end-to-end: NodeRuntime populates from `local_identity.node_id.as_bytes()`; `put_with_capability` passes it as `expected_relay_id` (sentinel all-zero = "unknown, accept v1 only" for backward compat with default config).  Closes the malicious-relay-replay vector: relay R observing а legitimate v2 token deposit к itself cannot replay it to another replica R' — verify on R' fails `RelayMismatch`.  Tests: 9 new v2 cases (mint_unbound roundtrip, mint_bound roundtrip+verify, cross-relay replay rejection, missing-local-id rejection, signed-message v1↔v2 disjoint, truncated header rejection, encoded size includes relay_id, corrupted relay_id breaks sig, v1-context-signed-as-v2 fails verify) on top of the existing 70 mailbox tests = 79 total.  ~220 LoC across `capability.rs` + 1 line `MailboxConfig` + 1 line `NodeRuntime` mint site.  Clippy clean. |
| Mailbox abuse architecture: slice 3 — per-sender quotas + trust-class eviction pools | ✅ done (Phase 6.50.b commit pending, 2026-05-09) | New `MailboxConfig::quota_per_sender_bytes` cap keyed on `sender_id` (default `u64::MAX` = disabled для backward compat); operators tighten после observing per-sender abuse.  New redb tables: `sender_bytes_v1` tracking per-sender bytes (decremented on ack / TTL prune / eviction), `eviction_index_anon_v1` holding the anonymous-pool's eviction order (separate от the existing `eviction_index_v1` which becomes the identified pool).  New `TrustClass` enum (Anonymous / Identified) drives where each blob is filed: `put_with_capability` derives the class от the put's authorisation outcome (verified token → Identified, permissive-policy tokenless → Anonymous, invalid token → reject); legacy `Mailbox::put` defaults к Identified для in-process trusted callers.  Eviction loop scans the anonymous index first и only falls back к the identified index когда anon is empty, so а tokenless flood cannot displace а tokenized sender's blobs.  `prune_expired` walks both indexes (anon-first для consistency).  New `PutOutcome::QuotaPerSenderExceeded` surfaced through `MailboxPutOutcome` IPC enum + `MailboxPutStatus = 8` wire byte.  6 new tests: per-sender cap blocks / decrements on ack / disabled-by-default; anon-pool-evicted-first; identified-pool-evicted-when-anon-empty; require_capability_token=true путь stays в identified pool.  ~620 LoC across `veil-mailbox`, `veil-proto`, `veil-ipc`, `veilcore`. |
| Hot-standby placeholder controller construction (cleanup) | ✅ done (commit `331796e`, 2026-05-09) | Pre-built `handoff_ack_waiters_arc`, `swap_registry_arc`, `hot_standby_controller_arc` before the runtime literal в `veilcore/src/node/runtime/mod.rs`.  Removed throwaway placeholder `HotStandbyController` construction inside the literal и the post-literal "replace placeholder" block.  Per-peer `alt_uri` loop also moved before the literal so the controller is fully constructed by the time runtime fields are populated.  Ownership now reads top-down с no swap-late mutation. |
| Dart `NetworkKind.unknown` const value mismatch (Epic 489.3) | Phase 6.50.b audit (2026-05-09) | `flutter/veil_flutter/lib/src/bindings.dart:26` encodes `NetworkKind.unknown` as `0` but Rust expects `255` (`crates/veilclient-ffi/src/lib.rs:793`).  `notifyNetworkChanged(NetworkKind.unknown)` returns `VEIL_ERR_INVALID_ARG` from FFI.  **Fix is а 1-line Dart change** (`veilNetUnknown = 255`).  Belongs к Epic 489.3 Flutter plugin scope per "не трогать Epic 489" policy.  Adding here для visibility — closes when 489.3 resumes work. |

---

### Audit cycle 4 (2026-05-30) — deferred security/design tasks

Surfaced by the 4th continuous-cycle audit. The remediable findings shipped
(commits `67c69b49`…`4aa9b17d`: N1 recursive-STORE cap, 7 mediums, 14 lows). The
items below were deferred **not for size but because each is a design trade-off
that can't be resolved locally** — recorded here with the core tension + an
acceptance sketch so the analysis isn't lost. Cross-refs to the older scattered
rows where they exist.

**T1 — Handoff attach anti-replay (N2).** Priority low. Refs: existing deferral
TASKS "Audit batch 2026-05-21" item 7 (handoff peer_id continuity); wire docstring
`veil-proto/src/session.rs`; struct doc `veil-session/src/handoff.rs`
`PendingHandoff.peer_node_id` (comment corrected this cycle to stop claiming the
accept path verifies it).
- *What:* `HandoffAttach{session_id, hmac=BLAKE3-keyed(tx_key)(session_id‖nonce)}`
  travels in plaintext; `HandoffRegistry::consume` keys on `session_id` only.
- *Core tension:* it's a **replay race, not a forge** (attacker lacks session
  keys, can't mint — only re-send observed bytes and win the race to `consume`).
  You can't bind the proof to the original transport because handoff exists to
  MOVE the session to a new transport. A fresh challenge-response gate fixes
  replay but costs a round-trip on every (supposedly seamless) handoff + new
  pending-challenge state + a **wire-format version bump** whose v1 path stays
  accepted until the fleet upgrades (so the hole isn't closed until a flag-flip).
- *Why low:* impact is transient DoS only — a winning attacker attaches but
  holds no keys, so the peer's first frame is AEAD-garbage to it and the session
  drops. Annoy, not own.
- *Acceptance:* challenge-response (or HMAC bound to a handshake-negotiated
  handoff secret) gated behind a `handoff_v2` config flag; v1 accepted during
  migration; sim test asserting a replayed attach is rejected. **Re-open:** real
  exploitation observed, or a deployment where handoff churn makes the DoS
  material.

**T2 — Anycast/relay reputation feedback loop (N3).** Priority low/medium. Refs:
existing row "`AnycastService::resolve` signed records / reputation" above;
`veil-anycast/src/reputation.rs::record_failure`;
`veil-anonymity/src/{sender.rs,circuit_builder.rs}`.
- *What:* the reputation ledger + a reputation-aware picker exist, but the
  production sender picks without consulting them and `record_failure` is called
  almost only by tests — so a Sybil with a self-signed `score=0` record (or good
  RTT) stays high in selection.
- *Core tension:* (a) **no failure signal where the pick happens** — failure
  (timeout/malformed/stall) manifests a layer below the picker, so it needs a
  runtime/IPC feedback event plumbed back across module boundaries; (b)
  **attribution is a new attack surface** — on a multi-hop circuit failure, mis-
  attributing the failure lets an attacker frame honest relays (reputation
  poisoning); (c) **explore/exploit under Sybil** — fresh honest relays start at
  neutral score, same as Sybils, so the policy must seed new relays with traffic
  without letting Sybils capture it.
- *Why deferred:* anycast/relay is best-effort discovery; the security-critical
  path uses `SignedBound`/quorum. A full loop (feedback + safe attribution +
  Sybil resistance) for a best-effort path is a poor marginal return today.
- *Acceptance:* IPC/runtime `candidate_failed{id, reason}` event → `record_failure`;
  conservative single-hop-only attribution first (no multi-hop blame);
  reputation consulted in the sender picker with an explore floor; `SignedBound`
  default for sensitive use. **Re-open:** a trust-sensitive anycast use case, or
  observed Sybil ranking-capture in a real deployment.

**T3 — Push-relay wake-HMAC minting (N4).** Priority medium. Refs: Epic 489.10
slice 4.4 (push notifications); `veil-push/src/lib.rs` (relay sends wake-only,
does NOT mint); receiver verify `VeilPush.handleWakeup` + primitive
`veil_crypto::wake_hmac` (shipped; verify hot-path optimised this cycle, L-1).
- *What:* FCM/APNs dispatch sends `wake=1` with an empty payload; it does not
  mint a wake-HMAC, so absent app-supplied `wakePayload/wakeHmacKey/receiverId`
  the wake is rate-limit-only → a leaked push token enables battery-DoS /
  presence-oracle.
- *Core tension:* it's **key distribution, not "add a mint call"**. The push
  envelope is sealed (the relay must not see the plaintext token/key — the
  privacy design), so minting needs either per-receiver minting keys held by the
  relay or a receiver→relay key pre-registration at mailbox setup, plus
  **platform-secure persistence** (iOS Keychain / Android Keystore) — i.e. it
  touches the **Dart/Kotlin/Swift toolchain**, a separate build/test surface.
  Threat-model nuance: auth protects against an attacker WITH the leaked token,
  not against a malicious relay (which holds the minting key) — acceptable but
  must be designed/documented.
- *Acceptance:* receiver registers a wake-HMAC key with its relay; relay mints
  `wake_hmac(ts, content_id, receiver_id)` and attaches the tag in provider
  `data`; key stored in Keychain/Keystore on device; unauth path becomes explicit
  legacy/opt-in for a production profile. **Re-open:** push UX work resumes (Epic
  489.10), or token-abuse observed.
- *Audit cycle-6 investigation (deferred — needs a product key-distribution
  decision):* the "B: app-supplied wakePayload, keyless relay" approach does NOT
  work as literally stated — the receiver's `WakeHmacKey` is sealed in
  `RendezvousAd.wake_hmac_envelope` TO THE RELAY's X25519 key
  (`crates/veil-anonymity/src/rendezvous.rs:1010`), so a SENDER cannot read it
  to mint a payload. The flow forks into two real designs, picked by product:
  * **B1 (keyless relay):** add an E2E key-distribution so the receiver shares
    its `WakeHmacKey` with the peers it talks to (e.g. inside the existing E2E /
    contact-exchange channel); senders mint the 72-byte
    `wake_payload = ts‖content_id‖HMAC` and ship it in `MailboxPutPayload`
    (the `wake_hmac_envelope` field is decoded but not forwarded today — P7); the
    relay attaches it verbatim to FCM/APNs `data` (today `WakeData{wake:"1"}` in
    `veil-push/src/fcm.rs` / `apns.rs`). Relay stays keyless. COST: new
    key-sharing path + Dart/Swift/Kotlin work to store+use peer wake-keys.
  * **B2/A (relay mints):** relay unseals the existing envelope (sealed to it),
    mints, attaches. Smaller (Rust relay only) but the relay holds the minting
    key — exactly what "B" wanted to avoid; this is the original T3 default.
  The wire/relay plumbing (thread `MailboxPutPayload.wake_hmac_envelope` →
  `PushTrigger` → dispatcher `data`) is the same shared substrate for both and is
  the natural first slice once the model is chosen. Receiver-side verify +
  primitive are already shipped; the `dispatch` trait would gain an optional
  `wake_payload: Option<[u8; WAKE_PAYLOAD_LEN]>` argument attached to the
  provider `data` map.

**T4 — Remote IPC stream forwarding (PLAN phases 2-4).** Priority medium. Refs:
`docs/en/PLAN_IPC_STREAM_FORWARDING.md`; `veil-ipc/src/handlers/stream.rs`
(returns `REMOTE_NOT_IMPLEMENTED` for `dst_node_id != local` — fails closed by
design, Phase 1 local streams shipped).
- *What:* a bidirectional stream bridge so the SDK can `open_stream` to a remote
  node's app endpoint over the veil.
- *Core tension:* it's a **two-flow-control-domain proxy** (TCP-over-TCP class):
  the local IPC channel backpressure (the 1024-slot channel + `PollSender`, fixed
  this cycle in M3) must compose with the remote veil session's congestion/
  window so a slow remote can't OOM the local SDK buffer and a slow local
  consumer applies backpressure to the remote — needs careful window propagation.
  Plus **teardown across 4 endpoints** (local-app ↔ local-daemon ↔ remote-daemon
  ↔ remote-app): STREAM_CLOSE/reset/half-close must propagate without leaking
  half-open streams or double-closing, including on session drop / reload (the
  leak class fixed this cycle in L-10/M-D). Plus capability/quota gating for
  app→arbitrary-remote-endpoint initiation.
- *Acceptance:* per the PLAN phases — session-reuse + logical stream open
  (phase 2), byte bridge with window propagation (phase 3), teardown/quota/
  capability (phase 4); soak under reload + slow-peer. **Re-open:** an SDK use
  case needs cross-node streams (until then the explicit `REMOTE_NOT_IMPLEMENTED`
  is the honest contract).

**T5 — RocksDB cold-tier eviction + republish bounding (audit M-A/M-B).** Priority
medium (correctness, not just optimisation).
- **M-A (eviction) — ✅ done (audit cycle-6 T5-B).** `RocksDbCold` gained a side
  timestamp index — two column families: `ts_index_v1` (`ts_be(8)‖key(32)` → `[]`,
  ordered by insert wall-clock for O(1) oldest-first) and `key_ts_v1` (reverse
  map for re-index on overwrite/remove). `evict_oldest` (byte-cap) and
  `retain_newer_than` (TTL — converts the trait's monotonic `Instant` cutoff to a
  wall-clock threshold) now work; the entry cap (`cold_capacity` =
  `max_store_entries`) is enforced on `put` via a maintained exact count (seeded
  by a one-time `key_ts_v1` scan on open, since RocksDB `estimate-num-keys` is
  unreliable pre-flush). Migration: legacy DBs get the CFs created on open;
  legacy values stay in the default CF, readable, grandfathered (not age/cap-
  evicted until overwritten/DELETE'd). 5 tests under `--features rocksdb-cold`
  (entry-cap, evict_oldest+count, overwrite-no-double-count, TTL via real >1s wait).
- **M-B (republish bounding) — CLOSED (cycle-7 `618c51ba`, hardened cycle-8 `1b2a76fc`).**
  The republish path no longer materialises the whole cold tier: it enumerates
  keys via `KademliaService::stored_key_ids()` (`ColdBackend::iter_keys`, no
  value copy) and fetches values only for the few keys actually due, via a
  non-promoting `peek` (`crates/veil-node-runtime/src/runtime/dht_republish.rs`).
  Cycle-8 follow-up also removed the no-op full-value scan from the TTL cleanup
  path (`retain_fresh_age_only`). Residual cursor/streaming `ColdBackend` API is
  no longer needed for the republish RAM concern.

### Audit cycle 5 (2026-05-31) — deferred tasks

The cycle-5 remediable findings shipped (N1-residue + IdentityWriteQuota cap +
FFI fetch_into + bootstrap-invite fail-closed + GatewayList NaN + into_vec_detached
removal + doc corrections). One deferred:

**T6 — Update `min_compatible_version` receiver-side gate. — CLOSED**
(cycle-7 `b78e2fe8`, regression-fixed cycle-8 `45220916`).
Refs: `crates/veil-update/src/apply.rs` (`min_compatible_satisfied`, Step 2c
of `apply_update`).
- *What:* `min_compatible_version` is now enforced at apply time — the running
  binary's `env!("CARGO_PKG_VERSION")` is compared semver-wise against the
  signed `manifest.min_compatible_version`, and `apply_update` returns
  `ApplyError::IncompatibleVersion` when installed < min (skipping a mandatory
  intermediate migration). semver crate added. The gate runs AFTER the U5
  platform-mismatch check (cycle-8 ordering fix) so a wrong-platform artifact is
  rejected as `PlatformMismatch`, not `IncompatibleVersion`.
- *Resolution of the prior "core tension":* the running binary's compile-time
  version is the authoritative installed version (the workspace ships as one
  version), so no separate `installed_version_str` persistence was needed.
- *Tests:* `min_compatible_gate` (unit) + the existing apply suite (fixtures
  pinned to a compatible `min_compatible_version`).

### Audit cycle 6 (2026-05-30) — deferred task

Cycle-6 remediable findings shipped (Delete dht_quota gate + bloom zero-bits +
SDK open_stream timeout/prune + IdentityWriteQuota O(log n) + FIND_VALUE
mirror-cache key-binding + FFI set_recv_handler re-entry + NatProbe lock-drop +
dead-code/doc cleanups). One deferred:

**T7 — Move the remaining lock-holding admin network ops onto `NodeServices`.**
✅ **done (audit cycle-6).** Moved the 6-method cluster (dht_recursive_get,
resolve_identity_verified, resolve_name_verified, resolve_one_identity_doc,
fetch_best_migration_cert_for, dht_get_replicated) to `impl NodeServices`; the
DhtRecursiveGet/ResolveIdentity/ResolveName handlers now run them on an
Arc-cloned `access()` bundle with the lock dropped before the network await.
PNetBan split into sync `prepare_p_net_ban` + async `PreparedBan::replicate`.
Behaviour-preserving; 3940 nextest + devnet-smoke green. Original description
follows for history.

Priority low (operator-path, not attacker-reachable). Refs:
`crates/veil-node-runtime/src/admin.rs` (`AdminCommand::DhtRecursiveGet`,
`ResolveIdentity`, `ResolveName`, `PNetBan`),
`crates/veil-node-runtime/src/runtime/mod.rs` (`dht_recursive_get`,
`resolve_identity_verified`, `resolve_name_verified`, `publish_p_net_ban`).
- *What:* these four admin handlers hold `Arc<Mutex<NodeRuntime>>` across a
  multi-second network `.await` (DHT walk / identity+name resolution / P-Net ban
  replication), serialising every other admin command + the SIGHUP reloader and
  health ticks for the operation's duration. (Cycle-6 already fixed `NatProbe`
  this way — its method was a thin wrapper delegating to `NodeServices`.)
- *Core tension (why deferred):* unlike `try_nat_traversal`, these four are
  implemented DIRECTLY on `NodeRuntime`, not as wrappers over a `NodeServices`
  impl. All their dependencies (`dht`, `session_tx_registry`, `identity`) already
  exist as Arc handles on `NodeServices`, so the move is mechanical — but it
  touches complex recursive-query / identity-resolution / ban-replication code
  and warrants its own focused review rather than riding in a mixed batch.
- *Acceptance:* relocate the four method bodies to `impl NodeServices` (leaving
  thin `NodeRuntime` wrappers, matching `try_nat_traversal`); change the admin
  handlers to `let access = { runtime.lock().await.access() }; access.<op>().await`
  so the lock is dropped before the network await; existing admin tests green.
  **Re-open:** an operator reports admin-command/reload stalls, or any of these
  ops moves onto an attacker-reachable surface.

---

## Phase 6.49 audit follow-up — cleanup backlog (2026-05-08)

External audit (2026-05-08) identified 4 critical findings (HIGH + 3 MEDIUM)
which were closed in the same session — see commits `f4bb0d1` (committed
secrets), `67edfb9` (BloomFilter k > MAX_K), `676469c` (FFI pre-alloc caps +
peers_list catch_unwind).  4 medium findings deferred к the table above
(time-validity policy, anycast signing, DHT re-replication).

Remaining cleanup is **cosmetic / dead-code removal** — group as а single
follow-up PR rather than per-item commits to keep diff churn down.

### Zombie / placeholder code cleanup

✅ done (Phase 6.49 zombie cleanup, 2026-05-08) — 10/10 items shipped; details
preserved в [`TASKS_ARCHIVE.md`](TASKS_ARCHIVE.md).  Enforcement script
`scripts/check-allow-dead-code-anchors.sh` holds the line.

### Architecture recommendations (deferred to design epics)

From the audit's "Рекомендации По Архитектуре" section.  Not blocking — recorded
для а future architectural cleanup pass:

| Recommendation | Status | Rationale для defer |
|---|---|---|
| Unified FFI boundary layer (`ffi_guard`, central caps, error mapping) | ✅ done (Phase 6.51 + 6.50.b-followup) | 29/41 FFI fns ported к `crate::guard::ffi_prelude` + `null_check!` macro pattern.  Remaining 12 fns INTENTIONALLY NOT MIGRATED — see [`crates/veilclient-ffi/src/guard.rs`] doc-comment Categories 1-4 (destructors, getters-без-err_out, trampolines, pure-sync fns).  Re-evaluation criteria documented in-source. |
| Time-validity policy unified across identity / proof / name / rendezvous / update | ✅ done | Centralised в [`crates/veil-proto/src/time_validity.rs`](crates/veil-proto/src/time_validity.rs) — 5 skew tiers (Gossip 30s / Interactive 60s / Wire 300s / Sleep 600s / Staged 86 400s) + 3 validity-window tiers (Challenge 60s / ShortState 300s / LongLived 30 days).  All 8 cross-crate users reference the catalog (veil-mailbox/capability, veil-update/manifest, veil-identity/verify, veil-proto/introducer + budget, veilcore/session/ticket + dispatcher/session).  Cross-crate consistency tests pin the 30-day LongLived value across 5 declared constants (audit pass #2). |
| Complete `veilcore` extraction (runtime orchestration → separate crate) | ✅ done (Phases 1-6 all shipped 2026-05-21) | **Full 6-phase plan**: [`docs/en/PLAN_VEILCORE_EXTRACTION.md`](docs/en/PLAN_VEILCORE_EXTRACTION.md).  ALL PHASES SHIPPED: **Phase 1 `veil-cfg`** (`4f64f87`) — 5852 LoC.  **Phase 2 `veil-session`** (`b1d2acb`) — 27 files / ~21 KLoC; 71/71 tests pass.  **Phase 3 `veil-dispatcher`** (`95afe8c`) — 11 files / ~14 KLoC; 114/114 dispatcher tests pass.  **Phase 4 `veil-node-runtime`** (`1203ec5` + `04e1155` test fixes) — 60+ files / ~25 KLoC including runtime/, admin.rs, IPC adapters, identity_local.  **Phase 5 `veil-cli`** (`5dc1c7c`) — binary + 21 cmd/ modules / ~17 KLoC.  **Phase 6 cleanup** — duplicated `lock!`/`rlock!`/`wlock!` macros removed from veilcore lib.rs (canonical defs live в veil-util); `crate::lock!` references swept к `veil_util::lock!` в remaining sim + chaos_sim + runner_tests.  **Final state**: ~83K LoC across 5 new sibling crates (`veil-congestion`, `veil-reputation`, `veil-session`, `veil-dispatcher`, `veil-node-runtime`, `veil-cli`) + several modules added к existing sibling crates.  veilcore now а thin re-export shim + integration-test crate (`sim/`, `chaos_sim`, `runner_tests`, `integration_tests`).  cargo check --workspace --tests: clean. |
| `#[allow(dead_code)]` policy: only с issue/TASKS anchor, otherwise delete | ✅ done (Phase 6.50.b, 2026-05-10) | Implemented as enforcement script `scripts/check-allow-dead-code-anchors.sh`: greps every `#[allow(dead_code)]` attribute across the workspace и validates each has either а `///` doc comment OR а `#[cfg(...)]` attribute within 3 lines above.  Skips matches that appear inside `//` comments (those are documentation / audit-trail references к removed attributes).  Plus content-side cleanup: 3 sites in `crates/veil-identity/src/integration_tests.rs` (TestIdentity / TestInstance fixture fields) gained anchor docstrings explaining the placeholder rationale.  Result: 12/12 surviving `#[allow(dead_code)]` sites have anchors; script exits clean.  Hook into CI pipeline at next workflow refresh; meanwhile the script can run locally via git pre-commit. |
| Test fixtures vs secrets split (templates only, generated keys at setup) | ✅ done | Phase 6.49 audit fix `f4bb0d1` shipped this for `stend/` + `ssl/`. |
| Mobile mile-stones: `NativeFinalizer`, lifecycle, connectivity, iOS BG/push verification | ✅ mostly done; остатки tracked under Epic 489.10 row (HMAC-auth wakeup + drainMailbox helper + push-relay impl).  Lifecycle / connectivity / iOS BG shipped в 489.6 + 489.10 (Phase 6.43/6.44 + Phase 6.50.b-followup). |
| Anycast signed records + threat-model status в docs | ✅ done (2026-05-18) | **Docs half**: rustdoc Security-considerations section unchanged.  **Code half** landed: `AnycastRecord` extended с optional `signature: Option<AnycastRecordSig>` field (Ed25519 owner-binding sig + owner_pubkey + sig_key_idx); new v2 wire format 141 B с magic `[0x41, 0x44]` "AD"; v1 (44 B "AC") still decode-supported for backward compat.  New APIs: `AnycastRecord::sign(...)` constructs signed records; `AnycastRecord::verify_signature()` validates embedded sig; `AnycastService::advertise_signed(signing_key, ...)` publishes v2 records; `AnycastService::resolve_signed_only(...)` filters resolution к signature-verified records only.  `AnycastList::decode` auto-detects v1 vs v2 by magic.  11/11 tests passing (5 new: v2 roundtrip, tampered-field reject, wrong-key reject, mixed v1+v2 list, signed-only resolve filter).  Reputation downweight + quorum vote remain separate deferred items — owner-signing alone closes the "claim someone else's node_id" sub-vector, не score=0 sybil.  Re-open trigger for reputation/quorum: production trust-sensitive consumer materializes. |

## Phase 6.50.b security & quality audit closeout (2026-05-11)

✅ done.  Two independent audits (internal + external) cross-referenced; real
findings deduplicated и addressed batch-style.  22 items closed (11 internal
+ 11 external) + Iterative-DHT route-discovery fallback (4 slices, 5× reach
extension on 20-node linear chain).  Full table preserved в
[`TASKS_ARCHIVE.md`](TASKS_ARCHIVE.md).

### Deferred к architectural follow-ups (anchored, not addressed here)

| Finding | Why deferred |
|---|---|
| ~~Admin connection cap (Semaphore-backed accept gate)~~ | ✅ done (`9715a6a`, Phase 6.50.b-followup): `[global] admin_max_connections: usize` (default 32) gates `tokio::sync::Semaphore` permits before per-connection task spawn.  Refused connections log `admin.accept_refused` info-level.  Token + UID gate primary защита; cap is defense-in-depth against bug-induced connection leak. |
| ~~Production `.lock().expect()` audit (non-FFI sites)~~ | ✅ done (Phase 6.50.b-followup audit): workspace policy "Mutex acquisitions in production code go через `lock!`/`rlock!`/`wlock!` macros" (existing since Epic 411.2 — `veilcore/src/lib.rs` + `crates/veil-util/src/lib.rs`) audited.  Result: **zero** production-path `.lock().unwrap()` / `.lock().expect()` sites; all 69 raw drift sites ара inside `mod tests` blocks (acceptable — poisoned mutex в а test = test failure, the desired outcome).  Enforcement script `scripts/check-mutex-poison-policy.sh` wired into CI `hygiene` job (`.github/workflows/ci.yml`).  Future production sites would now fail CI с а clear "use `lock!()` instead" message. |
| `cargo fmt --all` drift (339 files) | Cosmetic; intentionally deferred к separate "noisy" PR с CI gate added simultaneously.  Mixing fmt-only changes с functional fixes pollutes review. |
| ~~Remaining clippy debt (~60 lints, post-this-batch)~~ | ✅ verified clean (2026-05-11): `cargo clippy --workspace --all-targets -- -D warnings` exits 0 без warnings.  The «~60» figure was а pre-gate snapshot; the CI `hygiene` job (added в Phase 6.50.b-followup `c11e3ca`) has been holding the line, и individual fixes shipped incrementally with each touched-file PR.  No outstanding clippy debt. |
| SessionRunner decomposition slices 9-N | ✅ done — slices 9-28 shipped 2026-05-11 → 2026-05-21 (`run()` now **854 LoC**, down от 1700 LoC = **-50%** от campaign start).  Batch 3 (slices 22-28, shipped between 2026-05-19 + 2026-05-21): runner slice 22 (`6eac9cb`), cover_traffic::build_cover_frame slice 23 (`b26da42`), keepalive_emit slice 24 (`5c58240`), OnceTrigger slices 25+26 (`c04ff70`), dispatcher integration + SwapStream plumbing slices 27+28 (`af2640e`), plus а cleanup commit (`d36e38e`) stripping 45 decomposition breadcrumbs.  Net since the 2026-05-11 1046-LoC snapshot: −192 LoC additional carve-out.  **Remaining inline state** (deferred, не gated by audit-blocker): write-error counter + auto-trigger machinery (~50 LoC), alias-guard scope (~30 LoC), outbox/rpc-outbox ownership lifetime (~50 LoC), residual frame-decrypt/dispatch hot-path body inside the tokio::select! (~500 LoC).  Audit recommends 1-week testnet soak gate per slice — further decomposition requires production-soak runway что not currently scheduled.  **Re-open trigger**: continue slicing когда runway permits AND there's а concrete refactor motivation (новая coupling violation observed; current 854-LoC `run()` is below the 1000-LoC "god-function" threshold). | Original detail preserved в earlier row для audit trail., down от 1647 → −601 LoC = **−36%** от the campaign start; second-batch slices 15-21 alone added −300 LoC к the prior 1346 baseline).  **Batch 1 (slices 10-14, `297d288` → `5880d14`)**: rekey/handoff frame handlers — `handle_rekey_init_arm` + `handle_rekey_ack_arm` (X25519 responder + initiator, includes d916e3b mutual-rekey collision resolver), `handle_mlkem_rekey_ek_arm` + `handle_mlkem_rekey_ack_arm` (Epic 190 PQ), `handle_handoff_init_arm` (Epic 459 hot-standby).  **Batch 2 (slices 15-21, `ecfd899`)**: misc-arm + select-body extractions — `handle_ticket_arm` (Epic 215), `handle_handoff_ack_arm` (Epic 459 nonce-forwarder), `drain_outbox_into_pq` + `drain_rpc_outbox_into_pq` (Step 1 outbox drains, includes Epic 467.1 ban-node fast-exit + Epic 218.7 chunk-flag guard), `maybe_initiate_{x25519,mlkem}_rekey` (threshold-driven rekey starters), `compute_sleep_deadline` (7-source timer fold), `decrypt_frame_body` (AEAD с Phase 6.33+6.47-H19 grace-buffer fallback).  All slices verified at landmark по 4/4 chaos_sim tests pass; cargo fmt + clippy `-D warnings` clean.  **Remaining inline state**: the dispatcher integration (~200 LoC), the keepalive-ack TX-health check arms (Epic 459 stage c.2.2), и the Epic 459 SwapStream branch — deeper coupling refactors rather than mechanical extractions; deferring к а future audit pass. |
| ~~ABI header regeneration (`veil_ffi.h` ↔ Rust exports)~~ | ✅ done (Phase 6.50.b-followup, commits `3ba791b` + `26d2f80`): cbindgen integration via `scripts/regen-ffi-header.sh`; CI hygiene-job step regenerates на каждом PR и `git diff --exit-code`s against committed header.  Audit-B4 further cleaned the generated output (deduped `#include` lines via `no_includes = true`, swapped raw `usize` → `libc::size_t` at 4 FFI sites so `uintptr_t` no longer appears).  Audit-B2 added missing status constants 6/7/8.  Audit-B1 added `veil_mailbox_put_with_capability` entry-point. |

### Blocked by "не трогать Epic 489" policy

These external-audit findings concern Flutter/Dart/Kotlin/Swift code.  Documented
in `MEMORY.md` (`feedback_dont_touch_epic_489` если exists, otherwise inferred от
prior conversation context).  Will be addressed when Epic 489.3/.6/.10 sub-tasks
resume.

| Finding | Files |
|---|---|
| Flutter FFI callback close race (`NativeCallable.close` before native task ends) | `flutter/veil_flutter/lib/src/client.dart:228, :359` |
| Dart `NetworkKind.unknown = 4` vs Rust expects `255` | `flutter/veil_flutter/lib/src/bindings.dart:26` |
| BIP-39 phrase не calls `_zeroize` variant в Flutter | `flutter/veil_flutter/lib/src/identity.dart:42, :88` |
| Push token raw storage в SharedPreferences / UserDefaults | `flutter/veil_flutter/android/src/main/kotlin/.../VeilFlutterPlugin.kt:107`, `ios/Classes/VeilFlutterPlugin.swift:77` |
| Push wakeup almost no-op (no daemon reconnect/drain, no HMAC) | `flutter/veil_flutter/lib/src/push.dart:106` (Epic 489.10) |
| Flutter wrappers incomplete (stream/mailbox/push high-level API) | `flutter/veil_flutter/lib/src/bindings.dart:46` (Epic 489.3) |
| Mobile build flags use `allow-empty-seeds` defaults | `scripts/build-mobile.sh:30`, `.github/workflows/mobile-build.yml:51`, `flutter/.../android/build.gradle:112` |

---

## Operator-triggered actions (live testnet state)

Pending state changes на the live testnet что the operator should
trigger explicitly when ready.  Each row carries the exact `ansible`
commands needed.

### ✅ REVERTED — stress soak overrides (Phase 6.50, reverted prior to 2026-05-20)

**Status:** verified clean on 2026-05-20 — neither b1 (203.0.113.11) nor node1 (203.0.113.21) carries а `[session]` block в `/var/lib/veil/node.toml`.  Stress soak completed sometime between 2026-05-09 (apply) and the H9 NodeIdBytes rollout (which would have caught лишний `[session]` overrides на binary update).  Original block reproduced ниже для audit-trail.

### Historical: stress soak overrides (Phase 6.50, applied 2026-05-09 ~10:00 UTC)

**Status (historical):** active stress overrides на all 8 testnet hosts (b1/b2/b3 +
node1-5).  Stress soak is а compressed-time validation для NodeRuntime
PR1 (commit `2abda27`, AnonymityState extraction) и Anti-loop TTL
(commit `c252df2`, Epic 482.1).  Each host's `/var/lib/veil/node.toml`
has а `[session]` block с lowered rekey thresholds:

```
[session]
rekey_bytes_threshold = 100000000     # 100 MB (default: 137438953472 / 128 GiB)
rekey_time_threshold_secs = 300       # 5 min  (default: 2764800 / 32 days)
```

**Why this needs revert.**  The 1280× lower byte-threshold means
sessions rekey every ~20 seconds под chat-load (rather than every
~5-6 hours).  Useful для compressed soak — catches rekey-FSM bugs
within 24 h that would otherwise need а 7-day window — но **NOT
appropriate для production-mode operation:** rekey overhead becomes
significant relative к payload throughput, и any future load-driven
analysis (latency p99, mobile battery curves) gets distorted.

**Pre-revert checks to confirm clean soak.**  All metrics expected
near-zero or growing-monotonically:

```bash
for host in b1:203.0.113.11 b2:203.0.113.12 b3:203.0.113.13 \
            node1:<n1-ip> node2:<n2-ip> node3:<n3-ip> \
            node4:<n4-ip> node5:<n5-ip>; do
  n=${host%%:*}; ip=${host##*:}
  echo "=== $n ==="
  curl -sS --max-time 5 http://$ip:19999/metrics | grep -E \
    'active_sessions|decrypt_failures_total|rekey_grace_cap_evictions_total|rekey_init_sent_total|rekey_decrypt_fallback_total'
done
```

Healthy criteria:
* `active_sessions` = 7 (or 6 transient во время natural reconnect) on
  all hosts
* `decrypt_failures_total` ≤ baseline + few (background noise)
* `rekey_grace_cap_evictions_total` = 0 (mutual collision tie-breaker
  working)
* `rekey_init_sent_total` growing — confirms stress threshold is being
  hit
* `rekey_decrypt_fallback_total` low growth (а few per rekey is normal —
  Phase 6.32-6.33 grace path firing as designed)

**Revert command (run when operator decides soak is sufficient):**

```bash
cd /home/claude/projects/veil/ansible
source .venv/bin/activate

# 1. Strip the [session] override block (matches the marker comment).
ansible -i inventory.yml all -b -m shell -a "
  awk 'BEGIN{skip=0} /^\\[session\\]\$/{skip=1} skip==1 && /^\$/{skip=2; next} skip!=1 {print}' \
    /var/lib/veil/node.toml > /tmp/node.toml.new && \
  mv /tmp/node.toml.new /var/lib/veil/node.toml && \
  chown veil:veil /var/lib/veil/node.toml && \
  chmod 0600 /var/lib/veil/node.toml
"

# 2. Validate resulting config.
ansible -i inventory.yml all -b -m shell -a \
  "su -s /bin/sh veil -c '/usr/local/bin/veil-cli --config /var/lib/veil/node.toml config validate'"

# 3. Restart veil services to pick up defaults.
ansible -i inventory.yml all -b -m systemd -a "name=veil state=restarted"

# 4. (Optional) Restart chat-load if needed:
ansible-playbook -i inventory.yml deploy-chat.yml --forks 1
```

**After revert** confirm rekey rate drops к expected production
cadence (~one rekey per 5-6 h per session under sustained chat load).

### ⚠ ACTIVE — stealth listener canary on node1 (PoW-Gated Rendezvous epic, applied 2026-05-20 ~21:32 UTC)

**Status:** active stealth listener (`id=0x00000005`, range `52000-52999`, `pow_difficulty=12`, `ttl=5m`, `rate_limit=3/h`, `max_concurrent=16`) на node1 (203.0.113.21) post-PoW-Rendezvous-epic canary deploy.  Controller wired (`rendezvous.controller.wired listen_ids=[0x00000005] destinations=1 ... binder=production`); zero LISTEN sockets в range (anti-scan invariant ✅); все 9 `veil_rendezvous_*` Prometheus surfaces present и initialised к 0.

**Revert command:**

```bash
cd /home/claude/projects/veil/ansible
ansible-playbook -i inventory.yml revert-stealth-canary.yml --limit node1
```

**Roll-forward к all testnet hosts:**

```bash
ansible-playbook -i inventory.yml enable-stealth-canary.yml
```

(Defaults к `pow_difficulty=12` для canary; bump к `24` (~0.5 sec mining cost) via `--extra-vars stealth_pow_difficulty=24` для production rollout.)

---

## Acceptance bar для целевой "version 1.0"

Сеть готова к release for citizens of authoritarian states когда:

- ✅ Epic 476 + 477: identity ядро упрощено и понятно (cleanup-debt не блокирует расширения).
- ✅ Epic 478: leaf-узел за NAT работает через gateway, failover < 1s.
- ✅ Epic 479: latency-aware route selection, interactive traffic находит min-latency путь.
- ✅ Epic 480: WSS на 443 проходит DPI, port hopping активен.
- ✅ Epic 481: новый user входит через QR/HTTPS-bootstrap без зависимости от центральных seeds.
- ✅ Epic 482: anonymous-mode рабочий с 2-3 hop circuits.
- ✅ Epic 483: телефон работает 8h в фоне без значимого battery-drain.
- ✅ Epic 484: single-file binary, signed updates, понятные diagnostics.
- ✅ Epic 485: sim-scenarios подтверждают: enumeration ≥ 100× cost, eclipse <30% success rate, DPI-indistinguishable от HTTPS.
- ✅ Epic 486: PQ readiness GA — hybrid + standalone Falcon-512 + MigrationCert chain-walk + rotation CLI, all stand-verified.
- 🔧 Epic 487: trillion-scale hardening — не блокирует 1.0 (foundational design уже scale-ready), включается в 1.x по мере роста.

**Estimated total scope:** ~25 000 LoC across 11 epics; ≈ 6-9 месяцев focused работы; 476-477 первые (≈ 1 месяц), потом параллельно 478+479 (~ 1 месяц), 480+481 (~ 2 месяца), 482 (~ 2 месяца), 483+484 (~ 1 месяц), 485 (~ 2-3 недели continuous parallel).

---

## Легенда

- ✅ done — завершено
- 🔄 in progress — в работе
- ⬜ todo — ожидает
- ❌ blocked — заблокировано
- ⏸ deferred — прематюр; ждёт измеренной потребности или реальной нагрузки
- ⊘ skip — не реализуется (покрыто другим механизмом или признано неактуальным)
- 📦 backlog — запланировано; требует крупного scope (external dep, wire-format design или отдельного design-прохода)
