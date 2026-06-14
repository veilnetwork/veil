# Reply channel for authenticated anonymous messaging (v2 / #1)

Status: **SHIPPED (r1–r7 in `main`; reply-block model, reviewed — see §10)**
Depends on: bricks 1–5 (authenticated anonymous delivery via rendezvous, shipped).

> **Implemented r1–r7.** Slices `ac59d6b` (design) · `f5c09ef` (r1) · `bbe783c`
> (r2) · `cacc7c4` (r3) · `e236164` (r4a) · `ba89144` (r4b) · `2bdfa4e` (r5) ·
> `611a4a0` (r6) · `0c6c41c` (r7). See §12 for the one non-obvious correctness
> fix (transport- vs sovereign-node_id) and §13 for shipped limitations.

Goal: let a recipient B **reply** to an authenticated anonymous message from A
without learning A's network location — bidirectional authenticated anonymous
messaging — **and without A leaking its presence** in the public DHT.

## 0. Why a reply-BLOCK, not "A publishes an ad"

The naive design (A publishes its own `RendezvousAd`, B replies via
`send_anonymous_authenticated_to(A_node_id, …)`) works, but it forces A to
publish a public, signed, node_id-keyed ad — making A **observably online +
receive-capable + on relay R** to anyone enumerating the DHT. A pure one-way
sender leaks NONE of that. (Decision: **mitigate the presence leak.**)

Instead A embeds a **one-time reply-block** in the request — a Mixminion-style
sealed reply path that B uses to route a reply back, with **no public ad**:

- A registers with a rendezvous relay R under a FRESH one-time `auth_cookie`
  (existing `register_with_rendezvous` — A↔R session, R-local mapping
  `(A_node_id, cookie) → A's session`). A publishes **nothing to the DHT**.
- A embeds a signed `ReplyBlock { rendezvous_node_id: R, auth_cookie,
  x25519_pk: A's anonymity key, reply_app_id, reply_endpoint_id,
  receiver_node_id: A's TRANSPORT node_id }` in the `AuthAppDeliver`. (The last
  field was added in r7 — see §12 for why it is NOT A's sovereign id.)
- B replies by sealing to `ReplyBlock.x25519_pk`, wrapping as an
  `IntroducePayload { receiver_node_id: ReplyBlock.receiver_node_id, auth_cookie,
  ciphertext }`, and onion-routing it to `ReplyBlock.rendezvous_node_id`. R
  forwards by cookie to A's session. A decrypts + verifies B. **Reuses
  `send_sealed_introduce`.**

Only R (transiently, R-local) and B (who holds the inline block) know A's reply
path; the DHT shows nothing. The block is signed inside the `AuthAppDeliver`, so
B knows it genuinely came from A and a relay can't forge/alter it.

## 1. `ReplyBlock` — embedded, signed, optional

New wire type (`crates/veil-proto/src/ipc.rs`), embedded in `AuthAppDeliver`:

```
rendezvous_node_id [32]   // R — onion Final hop for the reply
auth_cookie [16]          // one-time; R maps (A_node_id, cookie) → A's session
x25519_pk [32]            // A's anonymity key — B seals the reply to this
reply_app_id [32]         // A's app that receives the reply
reply_endpoint_id u32     // endpoint on reply_app_id
```
~104 B. Carried as an OPTIONAL trailing section of `AuthAppDeliver` (a 1-byte
`has_reply` flag; absent = one-way, no reply). **Signed** (part of
`signing_bytes_with_dst`). The reply-block bytes grow the message but
fragmentation already chunks by the per-hop cell budget — worst case ~1–2 extra
fragments, well under `MAX_AUTH_DELIVER_FRAGMENTS`.

(Review note: `AuthAppDeliver::decode` uses hand-rolled magic offsets
`ipc.rs:694-696` — every offset after the insertion + `HEADER_SIZE` must be
bumped, and the same field order mirrored in `encode` + `signing_bytes_with_dst`
+ the wire-layout doc comment.)

## 2. A — ephemeral reply registration (no public ad)

A new opt-in send mode "expect reply": when set, before sending, the runtime:
1. Picks a rendezvous relay R (a `relay_capable`, dialable peer — reuse the
   `RendezvousRecipient` relay-selection helper) and ensures an OVL1 session.
2. Generates a fresh one-time `auth_cookie`; `register_with_rendezvous(R,
   cookie)` (R-local only — NO `register_rendezvous_publisher`, NO ad publish).
3. Builds the `ReplyBlock` and embeds it in the signed `AuthAppDeliver`.
4. Keeps the A↔R session + registration alive until a reply arrives or a TTL
   (e.g. the freshness window) expires, then drops the cookie.

A needs a **sovereign identity** (to sign) — already required for any auth send.
A does NOT need `[anonymity].receive_anonymous` / a published ad. The reply
arrives on the same `auth_deliver_tx` path as any inbound auth message
(it's an `AuthAppDeliver` forwarded by R), verified normally.

## 3. B — daemon-stores the block, surfaces a small `reply_id`

The `ReplyBlock` is ~104 B and secret-ish (it's A's reply path); it should NOT
be handed to B's app or pushed over FFI. Instead the daemon **stores it**:
- On delivering an auth message that carries a `ReplyBlock`, the auth-deliver
  task inserts the block into a bounded, TTL'd `ReplyBlockStore` keyed by a
  fresh `reply_id: u64`, and delivers to B's app with that `reply_id` (plus the
  verified `src_node_id` + `src_app_id`).
- B's app replies via `reply_id` — the daemon looks up the block + sends. The
  block never crosses the IPC/FFI boundary; the client surface is just a u64.

Bounds: cap entries + per-sender, TTL = freshness window, FIFO-evict (mirrors
the brick-4 replay cache / reassembler bounds).

## 4. Surfacing `reply_id` (full Path A — extend the generic delivery)

(Decision: extend the generic delivery; accept the FFI ABI break.) Thread a
`reply_id: u64` (0 = no reply) through:
- `veil_app::registry::AppMessage::Deliver` += `reply_id` (`route_ipc_deliver`
  gains a param; the ~25 non-auth callers across veil-dispatcher / veil-ipc /
  veil-node-runtime pass `0`).
- `veil_proto::AppDeliverPayload` += `reply_id` (append a u64). **Note (review):
  `AppDeliverPayload` is ALSO the on-wire inner onion payload of the plain
  `send_anonymous` path** (built `mod.rs:3035`, decoded `anonymity.rs:212,:499`)
  — those sites must set/skip `reply_id=0`. Network not live → no version bump.
- `veilclient::IncomingMessage` += `reply_id`.
- **FFI (ABI break, accepted):** the recv callback's packed buffer
  `[node_id(32)|app_id(32)|data]` + `veil_free_buf(_, 64+len)` contract
  (`veilclient-ffi/src/lib.rs:962,:1117-1128,:946-951`) gains the `reply_id`
  → new layout `[node_id(32)|app_id(32)|reply_id(8)|data]`, free-size `72+len`,
  and `VeilRecvCb` gains a `reply_id` param. Regenerate `veil_ffi.h`. Bump the
  FFI version constant.

## 5. Reply send path

New runtime entry `send_reply(reply_id, data)` on the daemon side:
1. Look up the `ReplyBlock` by `reply_id` (consume or keep per policy).
2. Build B's signed `AuthAppDeliver` (dst = `ReplyBlock` is for A; sender = B);
   optionally include B's OWN reply-block if it wants a reply-to-the-reply.
3. Seal + `IntroducePayload(receiver_node_id = A_node_id, cookie =
   ReplyBlock.auth_cookie)` + onion to `ReplyBlock.rendezvous_node_id` —
   reuses `send_via_rendezvous_authenticated`'s sign+fragment+`send_sealed_
   introduce`, but with an EXPLICIT rendezvous target/cookie/x25519 instead of
   resolving an ad. Factor `send_via_rendezvous_authenticated` to take an
   explicit reply path OR an ad.
- IPC: a new `anonymous_authenticated_reply` flag (or a dedicated request)
  carrying `reply_id` + data. Client/SDK: `IncomingMessage::reply(data)` (uses
  the stored `reply_id`). FFI: `veil_send_reply(reply_id, data, …)`.

## 6. Sender plumbing (review must-fix 3 — enumerate)

"Expect reply" + reply-block threads through: `veil_types::AnonOnionSender`
(trait) + `RuntimeAnonOnionSender` + `send_anonymous_authenticated_to` +
`send_via_rendezvous_authenticated` + `sign_auth_deliver` + a NEW
`AppIpcSendPayload` flag/field ("expect reply") + the IPC handler. The reply
send adds the `send_reply` path + `ReplyBlockStore`.

## 7. Tests

- `veil-proto`: `ReplyBlock` + `AuthAppDeliver` (with/without block) round-trip;
  signing binds the block; `AppDeliverPayload` += `reply_id` round-trip.
- `veil-identity`: sign→verify round-trips with an embedded block.
- `veil-node-runtime`: `ReplyBlockStore` bounds/TTL; `send_reply` builds the
  correct sealed introduce to the block's rendezvous; the auth task stores the
  block + surfaces `reply_id`.
- sim (`#[ignore]` E20, now mostly green): A sends "expect reply" → B replies via
  reply_id → A's app receives the reply with B's verified node_id, **and assert
  A published NO RendezvousAd** (presence-leak mitigation holds).
- `veil-ipc`/`veilclient`/FFI: `reply_id` surfaced; `reply()` round-trip.

## 8. Commit slicing

- **r1** ✅ proto: `ReplyBlock` + embed in `AuthAppDeliver` (signed, optional);
  `AppDeliverPayload` += `reply_id`. Round-trip tests + decode-offset care.
- **r2** ✅ identity: `sign_auth_deliver` / `verify_auth_deliver` carry the block.
- **r3** ✅ A-side: ephemeral reply-registration (relay pick + register, no ad) +
  embed block; "expect reply" config/flag.
- **r4** ✅ B-side: `ReplyBlockStore` + auth task stores block + surfaces
  `reply_id`; `route_ipc_deliver` / `AppMessage::Deliver` += `reply_id`
  (~25 sites) + plain-onion `AppDeliverPayload` sites set 0. (r4a surfacing +
  r4b store/producer.)
- **r5** ✅ reply send: `send_reply(reply_id)` on `NodeServices` +
  `AnonOnionSender::{send_reply, send_authenticated_with_reply}`; IPC
  `is_reply`/`expect_reply` flags + trailing `reply_id`/`reply_endpoint_id`;
  `ipc_send_err::REPLY_UNKNOWN`.
- **r6** ✅ client + FFI: `IncomingMessage` += `reply_id` + `reply()`;
  `veil_send_reply` + `veil_send_anonymous_authenticated_with_reply` + recv-
  callback ABI change (`reply_id` scalar) + `veil_ffi.h` regen + version bump
  (ffi 0.2.0, flutter 0.2.0). Dart recv side updated; **Dart SEND side not bound
  yet** (see §13).
- **r7** ✅ sim reply round-trip (`epic482_reply_channel_end_to_end_round_trip`,
  drop-tolerant retry loop, 12/12) + the transport-id correctness fix (§12) +
  these docs.

## 9. Out of scope

- Reply-to-the-reply chains beyond one hop (apps can embed their own blocks
  recursively; conversation sessions are #2 stateful circuits).
- Framework correlation token (app-level: echo a correlation id in the payload).
- Reusable (multi-use) reply blocks — v1 is one-time per request.

## 10. Review findings (folded in)

Core premise CONFIRMED: a reply reuses the rendezvous send primitives; A's
x25519 key + rendezvous target ride in the signed reply-block (no
AnonymityKeyCert, no ad); signed → unforgeable; fresh nonce per reply →
replay-safe (brick-4 `AuthDeliverReplayCache`). Folded must-fixes: presence-leak
→ **reply-block instead of a public ad** (§0); `AppDeliverPayload` is on-wire
onion, not just IPC → §4 sets 0 at the plain-onion sites; FFI ABI break
acknowledged + versioned (§4); sender plumbing enumerated (§6); decode magic
offsets (§1); `AuthAppDeliver::decode` HEADER_SIZE bump; A needs a sovereign
identity (§2). UX (review #7): a reply still requires A's A↔R session +
registration to be live; if A dropped them (TTL), the reply fails — bounded by
the same freshness window, surfaced as a delivery failure rather than the old
`NO_RENDEZVOUS`.

## 11. Open questions

1. **Block lifetime / TTL** — tie A's registration + the `ReplyBlock` validity
   to the brick-4 freshness window (300s)? Longer for async reply UX?
2. **One-time vs reusable block** — v1 one-time (single reply). A second reply
   needs a new request. Acceptable?
3. **Relay choice for R** — reuse the recipient-lifecycle relay selection
   (dialable published `relay_capable` peer); A may pick the same R it uses for
   its own receiving (if `receive_anonymous`) or a fresh one per request.

## 12. r7 correctness fix — TRANSPORT vs SOVEREIGN node_id (non-obvious)

The first end-to-end sim run failed only on the REPLY leg: the relay's
`(receiver_node_id, cookie)` lookup MISSED and the reply was silently dropped.

Root cause — veil nodes carry **two** identities:

- **transport/link node_id** (`identity.local_identity.node_id`) — the OVL1
  session peer id. The rendezvous relay keys a `RegisterRendezvous` by the
  **session peer**, i.e. by this transport id.
- **sovereign node_id** (`sovereign_identity().node_id`) — the Ed25519/Falcon
  identity used in `AuthAppDeliver` signing and as `auth.sender_node_id`.

The reply was originally addressed with A's **sovereign** id (taken from the
verified `auth.sender_node_id`), but A had registered at R under its
**transport** id — so the lookup keys did not match.

Fix: `ReplyBlock` carries `receiver_node_id` = A's **transport** node_id
(signed + sealed to B, so B can trust it); `send_reply` addresses the reply
introduce with it. `ReplyBlock::WIRE_SIZE` 116 → 148. The daemon-side
`ReplyBlockStore` therefore needs no side-channel id — the signed block
fully self-describes its return path (relay, cookie, x25519_pk, transport id).

Lesson for any future rendezvous/return-path work (incl. 482.7 onion
registration): **the rendezvous registry is keyed by transport id**, not
sovereign id — address the relay accordingly.

## 13. Shipped limitations / follow-ups

1. **Reply leg is single-shot best-effort (no retransmit).** The FORWARD leg
   retransmits on timeout and lands reliably. A one-time reply block is consumed
   on first `send_reply`, so there is **no retransmit-with-fresh-block recourse**
   — a dropped reply cell loses the reply (the app must re-request). The sim test
   masks this with a retry loop over fresh sends; production replies are
   best-effort. *Decision pending:* accept, or wire a bounded retransmit for the
   reply introduce (the block could stay un-consumed until ack/expiry).
2. **Dart SEND side not bound.** `bindings.dart` binds only `veil_send`; the
   authenticated/`veil_send_reply` entry points are exported from the FFI but not
   yet surfaced in Dart. A Flutter host can RECEIVE `reply_id` but cannot send a
   reply (or any authenticated-anonymous message) through the FFI until those are
   bound.
3. **Reply still reveals A's location to R** (same as all rendezvous receiving):
   A registers with R over a DIRECT session, so R learns A's transport address.
   Hiding the service/replier location from its own rendezvous relay is the
   onion-registration capability — see
   `PLAN_ANON_SERVICE_ONION_REGISTRATION.md` (depends on 482.7).
