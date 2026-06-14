# Brick 5 — Authenticated anonymous delivery to ANY recipient (via rendezvous)

Status: **DESIGN (Path B — rendezvous; reviewed, 7 fixes folded in — see §9)**
Depends on: bricks 1–4 (shipped, merged).

Goal: let an application send an **authenticated anonymous** message to
**any** recipient — including a leaf behind NAT — over IPC. The onion
hides the sender's network location from every relay; the recipient
cryptographically verifies WHO sent it (brick-4 `AuthAppDeliver`).

Decision (from review): the plain onion path (`send_anonymous`) cannot
reliably deliver to leaves — the penultimate relay reaches the target only
by session coincidence, and the failure is a silent drop under an
`AppSendOk`. The honest "any recipient" path is **rendezvous (R2)**: the
onion terminates at a rendezvous *relay* the recipient is registered with,
which forwards the sealed payload to the recipient over its established
session. This is also why `AnonymityKeyCert` is **not** needed — the
recipient's anonymity key travels in the signed `RendezvousAd`.

---

## 0. What already exists (production-wired)

Verified in code — the rendezvous transport is fully built and shipped:

| Piece | Location | Status |
|---|---|---|
| Sender onion→rendezvous, seal to receiver key | `runtime/mod.rs:3327` `send_via_rendezvous` | ✅ prod |
| Receiver→rendezvous registration frame | `runtime/mod.rs:3280` `register_with_rendezvous` | ✅ prod |
| Receiver publisher entry + ad refresh tick | `runtime/mod.rs:3534` `register_rendezvous_publisher`; `maintenance.rs:650` | ✅ prod |
| Rendezvous-node Register/Forward dispatch | `dispatcher/anonymity.rs:346,288` | ✅ prod |
| Receiver decrypt of forwarded introduce | `dispatcher/anonymity.rs:420` `handle_forward_introduce` | ✅ prod |
| `RendezvousAd` sign/encode/decode/verify (v1–v4) | `veil-anonymity/rendezvous.rs:207,356,451,559` | ✅ prod |
| `encrypt_introduce`/`decrypt_introduce_checked` (ECDH+ChaCha20Poly1305, replay cache) | `veil-anonymity/rendezvous.rs:1319,1626` | ✅ prod |

The brick-4 authenticated-delivery verify task (`auth_deliver_tx` →
`spawn_auth_deliver_handler`) also already exists and resolves the sender
identity + verifies + replay-checks + delivers with the verified sender.

So Path B is mostly **connecting wired primitives**, not building crypto.

---

## 1. The four gaps to close

### A. Authenticated inner payload through rendezvous
`send_via_rendezvous` seals a plain `AppDeliverPayload` (zeroed
`src_node_id`), and `handle_forward_introduce` assumes the decrypted
plaintext is exactly that (`dispatcher/anonymity.rs:476`). For
authentication the inner payload must be an `AuthAppDeliver`, and the
receiver must run verification.

- **Inner-payload tag (wire):** **unconditionally** prepend a 1-byte kind
  to the sealed plaintext, reusing the brick-4 `final_hop_kind` values:
  `APP_DELIVER` (0x01) = today's behaviour; `APP_DELIVER_AUTH` (0x03) = a
  **fragment** of a signed `AuthAppDeliver` (see §1.E — fragmentation is
  integral, a small message is just a 1-fragment message). (Review
  correction: `IntroducePayload` has NO inner version field and
  `AppDeliverPayload` has no magic — nothing to version-gate against; the
  network is not live, so just change the inner contract: always tag, and
  switch on it in `handle_forward_introduce`, exactly as the onion
  Final-hop already dispatches on `final_hop_kind`.)
- **Sign-whole-then-fragment.** The sender builds ONE `AuthAppDeliver` over
  the FULL message (`sovereign.sign_auth_deliver`, dst =
  `ad.receiver_node_id`), encodes it to bytes, and splits those bytes into
  fragments. A single signature integrity-protects the whole reassembly:
  any tampered/truncated/reordered reassembly fails `verify_auth_deliver`.
  The receiver reassembles by `msg_id`, then verifies+delivers ONCE.
- **Sender:** new `send_via_rendezvous_authenticated(ad, target_app_id,
  endpoint_id, data, hop_count)` — builds + signs the `AuthAppDeliver`,
  fragments per §1.E, seals each fragment, and sends each via its own onion
  circuit to the rendezvous. Requires a sovereign identity. Enforces a
  `MAX_AUTH_MSG_BYTES` ceiling (→ `PayloadTooLarge`), bounding fragment
  count.
- **Receiver:** in `handle_forward_introduce`, after decrypt, switch on the
  tag: `APP_DELIVER` → current path; `APP_DELIVER_AUTH` → feed the fragment
  to the auth reassembler (§1.E); on the completing fragment, hand the
  reassembled `AuthAppDeliver` bytes to `auth_deliver_tx` (the brick-4b task
  already resolves+verifies+replay-checks+delivers with the verified
  sender). Factor `handle_final_auth_deliver`'s enqueue so the onion
  final-hop and the rendezvous receive path share it.

### B. Production receiver lifecycle (currently sim-only)
Receiving requires: pick a rendezvous relay, dial it, `register_with_
rendezvous`, `register_rendezvous_publisher`, and let the maintenance tick
publish/refresh the ad. Today only the sim orchestrates this manually.

- New opt-in `config.anonymity.receive_anonymous = false` (default).
  When `true`, spawn a `RuntimeService::RendezvousRecipient` task that:
  1. Selects a rendezvous relay **from the relay directory** (so it is
     `relay_capable` AND has published a directory entry — required, else
     the sender silently drops, see §1.E.4): if
     `config.anonymity.rendezvous_relays` is non-empty, pick from that
     operator-pinned list; otherwise auto-pick a dialable published relay.
     (Decision: **auto with optional pin**.)
  2. **Dials the relay and WAITS for a live OVL1 session** before any
     registration — `register_with_rendezvous` sends fire-and-forget and is
     a silent no-op with no session (`mod.rs:3309` drops the send result).
  3. Generates a per-recipient `auth_cookie` (random 16B) and calls, IN
     ORDER, `register_with_rendezvous(relay, cookie)` then
     `register_rendezvous_publisher(relay, cookie, validity)` — register
     with the relay BEFORE the entry that triggers ad publication, to avoid
     the publish-before-register race (a live ad pointing at a relay that
     doesn't yet know the cookie → sender sends → relay drops).
  4. The existing `tick_publish_rendezvous_ads` then publishes/refreshes the
     signed `RendezvousAd` to DHT.
  5. The rendezvous registry is **in-memory on the relay** (lost on relay
     restart). So on ANY of {leaf restart, relay restart, relay-session
     loss, failover}, RE-REGISTER with the relay (step 2–3) **before** the
     next ad refresh. Failover keeps `receiver_x25519_pk`/cookie, changes
     `rendezvous_node_id`, bumps ad validity. Emit a metric on each
     re-register so "ad live but registration stale" is observable.
- Multiple ad replicas already supported (`rendezvous_ad_dht_key_at`, up to
  `MAX_RENDEZVOUS_AD_SLOTS=8`) — can register with >1 relay for resilience
  (v1: 1–2 relays).

### C. Sender-side ad resolution + IPC
The sender needs the recipient's `RendezvousAd` from just its node_id.

- Runtime entry point (`NodeServices`):
  ```rust
  pub async fn send_anonymous_authenticated_to(
      &self, receiver_node_id: [u8;32], target_app_id: [u8;32],
      target_endpoint_id: u32, data: &[u8], hop_count: usize,
  ) -> Result<(), AnonSendError>
  ```
  1. Require sovereign identity → else `NoIdentity`.
  2. Fetch `RendezvousAd` from DHT
     (`rendezvous_ad_dht_key[_at](receiver_node_id, …)`), `decode_
     rendezvous_ad`, `verify_rendezvous_ad`, `is_currently_valid` → else
     `NoRendezvous` (recipient not reachable / hasn't opted in).
  3. Call `send_via_rendezvous_authenticated(&ad, …)`; map
     `SenderError::InsufficientRelayCandidates` → `NoRelays`,
     `PayloadTooLarge` → `PayloadTooLarge`.
- `hop_count`: `config.anonymity.default_hop_count` (default **2** for this
  path — see §1.E), clamped `[1, MAX_HOPS_PER_CELL]`; serde default +
  `is_default` + reload path.

### D. Key gating — receive without becoming a relay (MUST-FIX-1)
The receiver needs `anonymity_x25519_sk` (to unseal forwarded introduces,
`dispatcher/anonymity.rs:427`). Today it's generated only when
`relay_capable=true`, and its mere presence in the dispatcher also enables
the onion **Forward** arm (`anonymity.rs:125-152`) — so naively giving
leaves the key would make them relay others' circuits.

- Generate/persist `anonymity_x25519_sk` when **either** `relay_capable`
  **or** `receive_anonymous` is set — at the single gate `mod.rs:1535`
  (extend `if relay_capable` to `relay_capable || receive_anonymous`).
  All three consumers (`register_with_rendezvous`, the ad publish, the
  dispatcher decrypt) read the same `Arc` (`mod.rs:1933`), so this one
  change keeps them consistent. **Must avoid the throwaway-random ephemeral
  fallback (`mod.rs:1935-1938`) when `receive_anonymous` is set**, else the
  published ad key won't match the decrypt key.
- Add a `relay_capable` boolean to the dispatcher and gate the
  `CellPeelResult::Forward` arm on it: a `receive_anonymous`-only node
  unseals ForwardIntroduce and accepts a `Final` cell addressed to it, but
  **drops `Forward`** cells (never carries others' circuits).
- **(Review fix — CONFIRMED security):** `rendezvous_registry`
  (`mod.rs:1806`) is currently `Some` **iff the SK is `Some`**, NOT iff
  `relay_capable`. Since this fix makes the SK `Some` for receive-only
  nodes, the registry must be **explicitly re-gated on
  `config.anonymity.relay_capable`** — otherwise every `receive_anonymous`
  leaf silently becomes a working rendezvous relay (accepts
  `RegisterRendezvous` + serves `handle_final_introduce` forwards for
  strangers). Add a test: a `receive_anonymous`-only node drops
  `RegisterRendezvous` and no-ops `handle_final_introduce`.

### E. Payload budget + fragmentation (DECIDED: fragment for arbitrary size)

**Why fragmentation is required.** Single-cell onion (`CELL_SIZE=512`) +
the auth signature is tight:

- Innermost Final-hop budget ≈ `510 − 81·N` (`PER_HOP_OVERHEAD=81`):
  N=2 → ~348 B, N=3 → ~267 B.
- Final-hop carries `[1 B onion tag] + IntroducePayload`
  (`FIXED_SIZE = 50 B` + ciphertext). Ciphertext budget ≈ N=2: ~297 B,
  N=3: ~216 B; `MAX_INTRODUCE_CIPHERTEXT = 256` (`rendezvous.rs:1097`) caps
  it. `encrypt_introduce` overhead = `INTRODUCE_OVERHEAD = 60 B`.

So one cell carries only ~110–130 B of signed `AuthAppDeliver` payload
(after the slim form below). To send arbitrary-size authenticated messages
we **fragment** the signed blob across multiple introduces and reassemble
at the receiver. (Decision: add fragmentation; small messages are simply a
1-fragment case — one code path.)

**Slim auth wire form (still applies, reduces fragment count).** For the
rendezvous path, omit `dst_node_id` (32 B) from the on-wire AuthAppDeliver
— the verifier reconstructs it as its own node_id and the *signature still
binds it* (signing_bytes unchanged, so no security loss). → header ~91 B.

**Fragment framing** (the sealed plaintext, after the 1-byte tag):
```
[1B  tag = APP_DELIVER_AUTH]
[16B msg_id]        random; ties a message's fragments together
[2B  frag_count]    total fragments (BE), 1..=MAX_AUTH_FRAGMENTS
[2B  frag_idx]      0-based (BE)
[..  chunk]         slice of the signed AuthAppDeliver bytes
```
~21 B fragment header → ~90–110 B of signed-blob bytes per fragment.
Sender splits `AuthAppDeliver.encode()` into `frag_count` chunks; each
fragment is independently sealed (`encrypt_introduce`, fresh ephemeral key)
and onion-routed to the rendezvous.

**Reassembly (receiver), with hard bounds** — this is the new state +
DoS surface, so:
- Keyed by `msg_id`; buffers fragments until all `0..frag_count` arrive,
  then concatenates → `AuthAppDeliver::decode` → `auth_deliver_tx`
  (verify+replay+deliver ONCE). The single signature integrity-protects the
  whole reassembly (tamper/truncation/reorder → `BadSignature`).
- **Bounds:** `MAX_AUTH_MSG_BYTES` ceiling at the sender (→ `PayloadTooLarge`,
  surfaced) bounding `MAX_AUTH_FRAGMENTS` (e.g. 64 → ~6 KiB); global cap on
  concurrent in-flight reassemblies + total buffered bytes; per-`msg_id`
  cap = its declared `frag_count`; reassembly **timeout** (≤ the brick-4
  freshness window, 300 s) so partials are GC'd. On pressure, evict
  oldest-incomplete. Mirrors the existing `EnvelopeChunkReassembler`
  (`FrameDispatcher.chunk_reassembler`) pattern; reuse or parallel it.
- **DoS note:** the sender is onion-anonymous, so reassembly can't be
  rate-limited per-sender. The bounds above (memory cap + timeout + the
  relay's own forwarding limits) keep worst-case cost bounded; a flood of
  partial msg_ids can at most fill the capped buffer, evicting other
  partials (best-effort, documented). Each fragment independently passes the
  introduce replay cache (`decrypt_introduce_checked`), and frag_idx
  duplicates within a msg_id are ignored.
- **Replay:** whole-message replay is caught by the brick-4
  `AuthDeliverReplayCache` (keyed on sender_node_id + the message's single
  nonce) after reassembly; per-fragment dup by the introduce replay cache.

**hop_count:** default **2** for this path (`config.anonymity.
default_hop_count`), clamped `[1, MAX_HOPS_PER_CELL]`; and raise
`MAX_INTRODUCE_CIPHERTEXT` to the N=2 Final-hop budget (~297 B) so each
fragment carries a useful chunk.

---

## 2. IPC wire contract (STABLE v1 — no version bump)

`AppIpcSendPayload.flags` bit 2:
`IPC_SEND_FLAG_ANONYMOUS_AUTHENTICATED = 0x0000_0004`. New decoded bool
`anonymous_authenticated`. Layout / `FIXED_SIZE` (108) / version unchanged.
`anonymous` (meta-E2E) and `anonymous_authenticated` both set →
`INVALID_FLAGS`. `require_ack` ignored in onion mode (fire-and-forget; §4).

New `ipc_send_err` codes (`ipc.rs:1229`):
```
NO_IDENTITY   = 7   // no sovereign identity → cannot sign
NO_RENDEZVOUS = 8   // no valid RendezvousAd for recipient (not opted in)
INVALID_FLAGS = 9   // both anonymity flags set
```
Daemon handler branch (`veil-ipc/handlers/send.rs`): on
`anonymous_authenticated`, call the runtime via a new
`anon_onion_sender: Option<&dyn AnonOnionSender>` context trait (mirrors
`mlkem_ek_resolver` injection; keeps veil-ipc off veil-node-runtime), map
errors, return.

---

## 3. ACK / delivery semantics (v1)

Fire-and-forget: `AppSendOk` = "circuit built + handed to first hop", not
delivered (no end-to-end ACK in v1). All *surfaced* IPC errors are
local/pre-transmit (no identity, no ad, no relays, payload too large).

**(Review correction)** Delivery is more reliable than plain onion but NOT
guaranteed — it is the same *class* of silent-drop hole, just narrower.
Delivery succeeds only if ALL hold: (1) the leaf has a live session to its
chosen relay; (2) the relay's in-memory cookie registration is current
(does not survive a relay restart); (3) the relay is `relay_capable` +
published in the directory; (4) the circuit can be built. Break any one →
silent drop under an `AppSendOk`. §1.B's register-before-publish +
re-register-on-restart sequencing closes the controllable cases; the rest
are inherent to a no-ACK transport. Mitigations: (a) document the
no-delivery-guarantee on the client method; (b) **add counters at every
silent-drop site** (`mod.rs:3416` relay-entry-not-cached, `anonymity.rs:316`
cookie-unknown, the auth-enqueue-drop) so operators can see "ad live but
messages vanishing"; (c) an app needing confirmation must build its own
ack at the application layer.

---

## 4. Privacy notes

- A `receive_anonymous` node publishes a `RendezvousAd` (already a public,
  signed record) → reveals "this node accepts anonymous messages" + which
  rendezvous relay it uses. That linkage is inherent to rendezvous and
  already part of its threat model (the ad is DHT-public by design).
- The rendezvous relay learns `(receiver_node_id, cookie)` and that
  *someone* sent the receiver a message, but not the sender (onion) nor the
  content (sealed). The sender's identity is revealed only to the receiver,
  after verification — exactly the intended property.
- `cert`-style replay handled by the existing introduce replay cache
  (`rendezvous.rs:1626`) plus the brick-4 `AuthDeliverReplayCache`.

---

## 5. Tests

- `veil-anonymity`/`veil-proto`: IntroducePayload inner-format v2 (tag
  byte) round-trip; v1 (untagged) still decodes as `APP_DELIVER`.
- `veil-dispatcher`: `handle_forward_introduce` routes `APP_DELIVER_AUTH`
  to `auth_deliver_tx` (mock channel, like the brick-4b tests); `APP_DELIVER`
  unchanged.
- `veil-node-runtime`: `send_anonymous_authenticated_to` → `NoIdentity` /
  `NoRendezvous`; recipient-lifecycle task registers + publishes an ad
  (local-shard assertion).
- `veil-ipc`: handler dispatch + error-code mapping + both-flags rejection.
- sim (`#[ignore]`, E20): extend the existing rendezvous scenario
  (`scenarios.rs:5601`) to send via `…_authenticated` and assert the
  receiver app sees the VERIFIED `src_node_id`.

---

## 6. Commit slicing

- **5a** payload format + fragmentation (the biggest slice): unconditional
  inner tag byte; slim auth wire form (omit on-wire `dst_node_id`); raise
  `MAX_INTRODUCE_CIPHERTEXT`; fragment framing (`msg_id`/`frag_count`/
  `frag_idx`); sender split in `send_via_rendezvous_authenticated` (+ hard
  `MAX_AUTH_MSG_BYTES` ceiling → `PayloadTooLarge`); receiver reassembler
  (bounded buffers + timeout + eviction) feeding `auth_deliver_tx` on the
  completing fragment; `handle_forward_introduce` AUTH branch (factor the
  brick-4b enqueue). Tests incl. size math, 1-fragment + N-fragment round
  trips, tamper/truncation/reorder → reject, reassembly bounds.
- **5b** key gating (MUST-FIX-1 + security re-gate): generate
  `anonymity_x25519_sk` for `receive_anonymous` at the single gate (no
  ephemeral fallback); dispatcher `relay_capable` gate on the `Forward`
  arm; **re-gate `rendezvous_registry` on `relay_capable`**; config field.
  Tests: `receive_anonymous`-only node drops `Forward` AND drops
  `RegisterRendezvous`.
- **5c** receiver lifecycle: `RuntimeService::RendezvousRecipient` task
  (pick relay FROM DIRECTORY → dial+await session → register → publisher →
  ad refresh → re-register on restart/failover) + `receive_anonymous` +
  `rendezvous_relays` config + reload/restart semantics + re-register
  metric.
- **5d** sender resolve + runtime: `send_anonymous_authenticated_to`
  (recursive fetch+verify ad, AND pre-resolve the rendezvous relay's
  directory entry recursively to avoid the `mod.rs:3416` silent drop) +
  `default_hop_count` (=2 for this path) + `AnonOnionSender` trait +
  silent-drop counters.
- **5e** ipc: flag bit + error codes + handler branch (return before the
  `require_ack` path) + context wiring.
- **5f** client: SDK `send_anonymous_authenticated` + FFI export +
  `veil_ffi.h` regen + error mapping + no-delivery-guarantee doc.

---

## 7. Out of scope (later)

- Reply channel / stateful circuits / Double-Ratchet (deferred earlier).
- End-to-end delivery ACK over the onion/rendezvous path.
- Per-message hop-count override in the IPC request.
- Auto-selection heuristics for the best rendezvous relay (v1: simple
  pick + failover; smarter selection later).
- Multi-relay (>2) ad replication tuning.

---

## 9. Independent review findings (Path B — all folded in above)

Confirmed-fine: dst-binding (sender uses sovereign node_id for
`sender_node_id`; both ad.receiver_node_id and the verifier's self_node_id
are `local_identity.node_id` → no mismatch); `auth_deliver_tx` reachable
from `handle_forward_introduce`; the single-gate SK keygen fix; IPC flag
bit 2 + err codes 7/8/9 + `AnonOnionSender` injection.

Must-fixes (now in the plan):
1. **[SECURITY]** Re-gate `rendezvous_registry` on `relay_capable`, not SK
   presence (§1.D) — else `receive_anonymous` leaves become relays.
2. **[FEASIBILITY]** Payload budget (§1.E): empty auth msg ≈248 B vs ~216 B
   at N=3 → doesn't fit; slim wire form + raise cap + N=2 + hard ceiling.
3. **[RELIABILITY]** Register-before-publish + re-register on restart/
   failover; pick relay from the directory (§1.B).
4. **[RELIABILITY]** Sender pre-resolves the rendezvous relay's directory
   entry recursively, else silent `Ok(())` (§1.B.1 / §5d / §1.E.4).
5. **[CORRECTNESS]** No IntroducePayload version field / AppDeliver magic —
   just unconditionally prepend the tag (§1.A).
6. **[OBSERVABILITY]** Counters at every silent-drop site (§3).
7. **[SCOPE]** Reload/restart semantics for `receive_anonymous` +
   `rendezvous_relays` (§6-5c).

## 10. Product decision (§1.E) — DECIDED

Single-cell + signature carries only ~110–130 B per cell. **Decision: add
fragmentation** (§1.E) so authenticated messages carry arbitrary size (up
to `MAX_AUTH_MSG_BYTES`, e.g. ~6 KiB / 64 fragments). Small messages remain
a 1-fragment fast path. This makes 5a the largest slice (sender split +
bounded receiver reassembler). Fragmentation beyond the ceiling (streaming
/ very large) stays out of scope.
