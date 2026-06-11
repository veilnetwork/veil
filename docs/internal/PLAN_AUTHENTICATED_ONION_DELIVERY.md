# Authenticated-sender onion delivery — v1 design spec (ACTIVE)

> **✅ REINSTATED as the v1 plan (2026-06).** Two independent reviews found the
> X3DH-handshake replacement was wrong (`x3dh.rs` is a KEM seal, not an AKE —
> zero sender auth), and recommended exactly this approach for v1: a **per-message
> identity-subkey signature** inside the onion final payload. v1 scope (confirmed
> with the maintainer): **Ed25519 signature + single-cell onion + one-way
> (sender→recipient) + production-wire the onion origination.** The earlier
> "budget wall" was the FULL 184 B auth envelope; a minimal Ed25519 signature is
> +64 B, which fits the 267 B (onion v2) cell. **Deferred to v2:** hybrid-Falcon
> signature (needs multi-cell circuit data), replies / bidirectional, stateful
> circuits (482.7), Double Ratchet — see
> [`PLAN_ANON_MESSAGING_ARCHITECTURE.md`](PLAN_ANON_MESSAGING_ARCHITECTURE.md)
> (descoped). The §3 envelope / §5 verification below are the v1 blueprint;
> implementation tracks §9.

> **Status (2026-06):** DESIGN DRAFT for review, no code. Chosen direction:
> production onion-routed delivery (relay anonymity) **with the recipient
> authenticating the sender** — the "Signal-over-Tor" model: relays learn
> neither sender↔recipient nor content; the recipient cryptographically verifies
> WHO sent the message but never learns WHERE (the sender's network location).
> This is security-critical crypto/protocol work — recommend an independent
> review pass (as was done for the A.2 sketch) before implementation.

Supersedes the "anonymous-to-recipient" form of `send_anonymous` (which zeroes
`AppDeliverPayload.src_node_id`). Makes the onion path prod-wired, which
re-justifies the W1/W2/W3 optimisations
(`PLAN_ANON_PRESERVING_IMPL.md`).

---

## 1. Requirement & threat model

- **Hide from relays:** no relay on the path learns the (sender, recipient) pair
  or the content. (Onion already gives this: first hop knows the sender's
  *link* but not the destination; middle/exit know neither end's identity;
  content is layer-encrypted.)
- **Recipient authenticates the sender:** the recipient learns the sender's
  identity (`node_id`) and verifies, cryptographically, that the message is
  genuinely from the holder of that identity — NOT forgeable (unlike meta-E2E,
  whose inner `sender_node_id` is unauthenticated).
- **Recipient must NOT learn the sender's network location.** The onion already
  ensures the recipient receives the cell from the last *relay*, not from a
  sender session, so identity ≠ location.

Out of scope (by the onion model, unchanged): a global passive adversary doing
end-to-end timing correlation; relay-flooding (covered separately by the relay
reputation line).

---

## 2. What changes vs today

`send_anonymous` builds `AppDeliverPayload { src_node_id: [0;32], src_app_id,
app_id, endpoint_id, data }`, onion-wraps it, and the final hop
(`handle_final_app_deliver`) routes `src_node_id` to the app. Today `src_node_id`
is zeroed → recipient can't know/trust the sender.

The change: the innermost payload becomes an **authenticated delivery envelope**
carrying the real sender + a signature; the final hop **verifies** it before
routing, and applies **anti-replay**.

---

## 3. Authenticated delivery envelope (wire format)

```text
AuthAppDeliver:
[0]      version u8 (=1)
[1..33]  sender_node_id [32]          sovereign node_id of the sender
[33]     sig_key_idx u8               index of the signing subkey in the
                                      sender's IdentityDocument
[34..42] timestamp u64 BE            unix secs (freshness)
[42..50] nonce u64 BE               fresh random per message (replay)
[50..82] dst_node_id [32]           the recipient (binds the envelope to it)
[82..114] app_id [32]
[114..118] endpoint_id u32 BE
[118..]  data [..]                   application payload
+ trailing: sig_len u16 BE || signature   (Ed25519 = 64 B)
```

**Signed bytes** (domain-separated):
```text
"veil-auth-onion-deliver:v1\0"
  || sender_node_id || sig_key_idx
  || timestamp || nonce
  || dst_node_id || app_id || endpoint_id_be
  || data
```

Auth overhead ≈ 1+32+1+8+8+32+32+4 + (2+64) = **184 B** before `data`. With the
W1 3-hop budget of 267 B, that leaves ~80 B for `data` at 3 hops, ~160 B at
2 hops. (Larger messages chunk, as today; or use 2 hops. W3 Sphinx would widen
this. Falcon/hybrid subkeys are larger — v1 targets Ed25519 subkeys, the active
identity subkey is Ed25519 by construction.)

Why carry `sender_node_id` + `sig_key_idx` (not the full pubkey / IdentityProof):
the recipient resolves/knows the sender's `IdentityDocument` (a messaging contact
is already known; unknown senders resolve via `resolve_identity_verified`), so
the envelope need not carry the pubkey + master-binding (~160 B saved). The
signature is verified against `document.identity_keys[sig_key_idx]`.

---

## 4. Sender side

1. Require a sovereign identity (legacy node_id-only nodes can't authenticate →
   either fall back to the zeroed anonymous form behind an explicit flag, or
   reject — see §8 open question).
2. Build `AuthAppDeliver` with the real `sender_node_id`, the active
   `sig_key_idx`, a fresh `timestamp` + random `nonce`, the `dst_node_id`,
   `app_id`, `endpoint_id`, `data`.
3. Sign the domain-separated bytes with `SovereignIdentity.identity_sk` (the
   active subkey).
4. Onion-wrap (existing path) with the final hop = recipient; send.

---

## 5. Recipient side (final hop)

`handle_final_app_deliver` becomes authenticated:
1. Decode `AuthAppDeliver`; reject malformed.
2. **Freshness:** `|now - timestamp| <= FRESHNESS_WINDOW` (e.g. 5 min) — bounds
   the replay-cache window.
3. **Bind to self:** `dst_node_id == our node_id`, else drop (a relay can't
   re-target an envelope to a different recipient).
4. **Resolve + verify identity:** obtain the sender's `IdentityDocument`
   (`peer_sovereign_identities` cache → else `resolve_identity_verified`);
   verify `BLAKE3(master_pubkey) == sender_node_id` (handled inside the verified
   resolve) and that `identity_keys[sig_key_idx]` is valid/unrevoked.
5. **Verify signature** by `identity_keys[sig_key_idx]` over the domain bytes.
6. **Anti-replay:** per-sender bounded `ExpiryCache` keyed on `nonce` with TTL =
   `FRESHNESS_WINDOW`; reject if seen. (Same shape as the mesh replay nonce +
   the existing `ExpiryCache`.)
7. Only then route to the app with the **verified** `sender_node_id`.

Every failure path drops silently (no oracle), logging at debug.

---

## 6. Production wiring (the path is sim-only today)

- New IPC send mode: `anonymous_authenticated` (distinct from the current
  `anonymous` meta-E2E flag) carrying `hop_count`. The IPC `send` handler routes
  it to `NodeServices::send_anonymous` with the authenticated envelope, instead
  of meta-E2E on the regular path.
- The recipient app receives the message with a **verified** sender id (the IPC
  deliver carries the authenticated `src_node_id`; the app can trust it).
- Capability: only sovereign-identity nodes can send authenticated; the relay
  directory already advertises relay-capable hops for the path.

---

## 7. Security properties (claim — to be reviewed)

| Property | Mechanism |
|---|---|
| Relay can't learn (sender, recipient) | onion layering (unchanged) |
| Relay can't read content | onion layer AEAD (unchanged) |
| Recipient learns + verifies sender | §3 signature + §5 verify against resolved IdentityDocument |
| Sender unforgeable | signature by the sender's identity subkey; node_id↔master↔subkey binding |
| No re-targeting by final relay | `dst_node_id` bound in the signed bytes |
| No replay | `timestamp` freshness + per-sender `nonce` ExpiryCache |
| Recipient still can't learn sender LOCATION | onion: cell arrives from the last relay, not a sender session |

---

## 8. Open questions (for review)

1. **Legacy nodes** (no sovereign identity): reject authenticated send, or allow
   an explicit anonymous-to-recipient fallback? (Recommend reject — the feature
   is "authenticated"; the anonymous form already exists as meta-E2E.)
2. **Identity resolution cost at the recipient:** verifying needs the sender's
   IdentityDocument. Known contacts are cached; unknown senders trigger a DHT
   resolve (latency + the recipient learns it is resolving X — acceptable, the
   recipient is allowed to know X). Cache policy?
3. **Subkey algorithm:** v1 assumes the active identity subkey is Ed25519 (it is
   by construction). Confirm no hybrid-subkey path needs support in v1.
4. **Payload budget:** 184 B auth overhead at 3 hops leaves ~80 B for `data`.
   Acceptable for short chat; otherwise prefer 2 hops or land W3 (Sphinx) first.
5. **Metadata to the recipient:** the recipient learns `app_id`/`endpoint_id` +
   sender — intended. Any field that should be optional/omittable for stronger
   metadata privacy?
6. **Forward secrecy:** the signature authenticates but the content confidential-
   ity is the onion layer to the recipient (fresh per message). Do we also want
   an E2E ratchet inside, or is per-message onion confidentiality enough for v1?

---

## 9. Implementation order (after design review)

1. `AuthAppDeliver` proto type + encode/decode + canonical signed-bytes (proto;
   mechanical, testable in isolation).
2. Sign (sender) + verify (recipient) helpers (veil-identity / veil-anonymity);
   unit tests: round-trip, tamper, wrong-key, wrong-dst, stale, replay.
3. Anti-replay ExpiryCache wiring in the final-hop handler.
4. `send_anonymous` builds + signs the authenticated envelope; final-hop handler
   verifies; integration test (sim) sender→relays→recipient with a verified id.
5. Production IPC wiring (`anonymous_authenticated` mode).
6. Then the optimisation line (W2 selection caching, W3 Sphinx) — now justified
   by a prod-wired path.
