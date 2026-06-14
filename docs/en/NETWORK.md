# How the Veil Network Works

> This is the friendly tour — the big picture, the moving parts, and how a
> message actually gets from one person to another. If you want the full
> source-level detail (wire formats, every constant, locking rules, how the
> subsystems interact), that lives in
> [ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md).
>
> New to Veil entirely? Start with [start-here.md](start-here.md) first — it
> defines the basic words. This page assumes you've met them.

## The big picture

Veil is a network with no company in the middle. It's decentralized (no central
server owns it), every message is end-to-end encrypted (only the sender and the
final recipient can read it), and the network finds people for you even when
they're behind a home router or briefly offline.

A message travels through a small chain of nodes — running copies of Veil — like
this:

```
App ←→ Leaf ←→ Core ←→ Core ←→ Core ←→ Leaf ←→ App
```

Your app talks to a nearby node, that node passes the message along to other
nodes, and the last one hands it to your friend's app.

A few ideas do most of the work, and the rest of this page unpacks each one:

- **End-to-end encryption** seals every message (ML-KEM-768 for the key
  exchange, ChaCha20-Poly1305 for the content), so the nodes in between only
  ever see scrambled bytes.
- **DHT routing** lets the network find anyone in roughly `O(log N)` hops — a
  handful even when there are millions of nodes — using a shared address book
  called a Kademlia DHT (more on that below).
- **NAT traversal** punches through home routers automatically, so two people
  behind firewalls can still reach each other.
- **Local mesh discovery** lets nearby devices find each other directly, even
  without internet.
- **Offline delivery** parks a message in a mailbox when the recipient is away
  and hands it over the moment they return.

## Two kinds of node

There are just two roles, and the difference is simple: how much work a node does
for everyone else.

| Role | DHT | Relay | Mailbox | Gateway | Typical environment |
|------|-----|-------|---------|---------|---------------------|
| **Leaf** | - | - | - | - | Mobile phone, IoT sensor |
| **Core** | yes (K=20) | yes | yes | yes | Server, VPS, home server |

A **leaf** is a light node — your phone, a laptop, a tiny sensor. It joins the
network and sends and receives its own traffic, but it doesn't carry the network
on its back.

A **core** is a full node, and every core pulls its weight equally. Each one
helps with all four shared jobs:

- **DHT** — keeping a slice of the shared address book.
- **Relay** — forwarding messages it isn't the final recipient of.
- **Mailbox** — holding messages for people who are currently offline.
- **Gateway** — keeping *attachment records*, the notes that say which core a
  given leaf is currently reachable through.

Standing up a core takes a little proof of work — at least 24 bits, a quick
one-time puzzle that keeps fake identities expensive (see [Identity and proof of
work](#identity-and-proof-of-work)). If you'd rather a core not act as a gateway,
you can turn just that job off with `[gateway] enabled = false`.

Those are the only two roles. If you come across older names like `Relay`,
`Gateway`, or `CoreRouter`, they're history — they aren't part of the protocol.

## Identity and proof of work

Before a node can join, it gives itself an identity. An **identity** is just a
key pair — a public key everyone may see and a private key only you hold — plus a
small proof that you did a bit of work to make it. From the public key, Veil
computes the node's permanent address (its `node_id`). Here's the recipe:

```
keygen(Ed25519 | Falcon512) → (pubkey, privkey)
mine_nonce(pubkey, privkey, difficulty=24) → nonce
node_id = BLAKE3(pubkey)
identity_proof = (pubkey, nonce, sign(pubkey, nonce))
```

You can sign with either **Ed25519** (small and fast) or **Falcon-512** (larger,
and resistant to future quantum computers). Both are first-class — you pick per
node with `[identity] algo`, which also offers the `ed25519+falcon512` and
`ed25519+falcon1024` hybrids that sign with both at once. Whichever you choose,
hashing the public key with BLAKE3 gives the same 32-byte `node_id`.

The **proof of work** is that small puzzle from the recipe (`mine_nonce`): you
search for a number that makes the hash come out a certain way. It costs a little
CPU time, which is the point — it makes minting throwaway identities expensive
for spammers and trivial for an honest user creating one. The baseline difficulty
is 24 bits (lowered to 16 in debug builds so testing stays fast). As the network
grows it scales itself with `24 + ceil(log2(N / 100K))`, where `N` is the
network size that nodes agree on through epoch-based DHT records.

## The handshake (OVL1)

When two nodes first connect, they go through a **handshake** — a short
back-and-forth where they say hello, prove who they are, agree on what they each
support, and work out a shared secret key. After the handshake, everything they
send is encrypted. The exchange (named OVL1) looks like this:

```
Client → Server: Hello(magic="OVL1", version=1, node_id)
Server → Client: Hello
Client → Server: Identity(algo, pubkey, nonce, node_id, mlkem_ek?)
Server → Client: Identity
Client → Server: Capabilities(role_bits, flags, max_frame, ovl1_minor=1)
Server → Client: Capabilities
Client → Server: KeyAgreement(X25519_pubkey)
Server → Client: KeyAgreement(X25519_pubkey)
  [HKDF-SHA256 → tx_key, rx_key, session_id]   (lex-order swap of tx/rx)
Client → Server: SessionConfirm(session_id, HMAC)
Server → Client: SessionConfirm
  [All subsequent frames: ChaCha20-Poly1305 AEAD encrypted]
```

Reading the steps top to bottom: the two sides greet each other, present their
identities, compare capabilities, then each sends a one-time X25519 public value.
From those two values both sides independently derive the same pair of keys (one
for sending, one for receiving) with HKDF-SHA256, confirm they match, and from
then on every frame is sealed with ChaCha20-Poly1305.

One detail worth calling out: the ML-KEM-768 encapsulation key — the post-quantum
key used for end-to-end encryption — rides along inside the `IdentityPayload`
(1184 bytes; a length of `mlkem_pk_len=0` simply means that peer doesn't publish
one). The keys that protect *this connection*, though, come from the X25519
exchange plus HKDF-SHA256. So ML-KEM is *not* used to protect the link itself
today — only for the end-to-end sealing of message content.

No key is meant to last forever. A connection quietly negotiates fresh keys — a
**rekey** — once any one of three limits is reached: 128 GiB of frames sent, 32
days elapsed, or the nonce counter wrapping around. You can tune the size and
time limits with `[session] rekey_bytes_threshold` and
`rekey_time_threshold_secs`.

## How a frame is handled

Everything on the wire arrives as a **frame** — one self-contained packet with a
small header. When a frame comes in, a node reads the header, decrypts the body,
and then routes it to the right handler based on its *family* — the category it
belongs to. Anything from a family the node doesn't recognize is simply ignored,
which is what lets the protocol grow without breaking older nodes. The families:

```
bytes → FrameHeader decode → AEAD decrypt → family switch:
  Session  → Hello/Identity/Capabilities/KeyAgreement/SessionConfirm, Rekey, Ticket, Padding
  Control  → Ping/Pong, NatProbe*, Keepalive, Backpressure, Epidemic
  Discovery→ FindNode, FindValue, Store, Delete, Attachment, Mailbox/AppEndpoint lookup
  Delivery → Forward, Mailbox PUT/Fetch/Ack, Transit, RecursiveRelay, Chunks
  Routing  → RouteAnnounce/Withdraw (+Aliased), RouteRequest/Response, PoW, RouteDiscover
  App      → AppOpen, AppData, AppRtData, AppReceipt, AppWindowUpdate
  Mesh     → MeshBeacon, MeshForward, MeshAck
  PeerExchange → Walk, Challenge, Response, Result
  Tunnel   → IpPacket (TUN/TAP)
  RelayChain → Hop (onion)
  Diag     → DiagPing/Pong, TraceProbe/Hop
  Unknown  → ignored (forward-compatible)
```

## Finding a route: gossip plus the DHT

To send a message, a node first has to know which neighbor to hand it to.
**Routing** is how it figures that out, and Veil combines two approaches.

The first is **gossip**: when a node learns a route, it tells its immediate
neighbors with a `ROUTE_ANNOUNCE`. These announcements carry a *TTL* (time to
live — a small hop counter that stops them spreading too far), set to 2 here, so
word travels just a step or two and the network isn't flooded.

The second kicks in when gossip didn't already supply the answer — a *cache
miss*. The node falls back to the shared address book, the DHT. It wraps the
message in a `RecursiveRelay` and sends it to the DHT node whose ID is
mathematically closest to the destination (closest by XOR distance, explained in
the DHT section). Each node along the way asks the same question: do I have a
live connection straight to the destination? If yes, it delivers; if not, it
forwards one step closer. If no live path turns up within 20 hops, the message
falls back to a mailbox to wait.

```
A announces → B (TTL=1) → C (TTL=0, stop)
A → route cache miss → RecursiveRelay(dst=D)
  → closest node X → X has session to D? → deliver!
  → X doesn't → forward to closer Y → ... → mailbox fallback
```

One nice touch: when a `RecursiveRelay` delivery succeeds, each node remembers
the way back, caching `originator → peer_id`. So the reply has a route ready and
doesn't have to repeat the search.

## Delivering a message: three paths

When you send something, Veil tries the cheapest route that can work and falls
back as needed. There are three paths, from fastest to most patient.

**Path 1 — Direct** (the route is already known, a *cache hit*). The node looks
up the destination in its route cache, finds the next hop, and the message walks
straight there:
```
Sender → FORWARD(dst) → route_cache.lookup(dst) → next_hop → ... → Recipient
```

**Path 2 — Via the DHT** (the route isn't cached, a *cache miss*). The node asks
the shared address book instead, hopping closer and closer until it reaches a
node that has a live connection to the recipient — up to 20 hops:
```
Sender → FORWARD(dst) → cache miss → RecursiveRelay(dst, hop=20)
  → DHT hop chain → node with live session to dst → deliver
```

**Path 3 — Mailbox** (the recipient is offline). When nobody can be reached
directly, the message is left in a mailbox to be picked up later. This one has a
few more moving parts, so the steps are spelled out below:
```
Sender → MAILBOX_PUT → Primary (recipient's attachment gateway from DHT)
  Primary:
    store locally
    select_quorum_replicas:
      shard_target = BLAKE3("shard" || recipient_id || shard_id)
      pool         = DHT.find_closest_nodes(shard_target, (replica_count-1)*4)
      filter out   self, origin, low-battery, unreliable relays
      take         replica_count - 1 replicas
    MAILBOX_REPLICATE → replicas (envelope encrypted for privacy)
    wait for write_quorum DeliveryStatus::QUEUED → ACK sender

Recipient comes online:
  MAILBOX_FETCH → primary gateway
    local store → DHT fallback → fan-out MAILBOX_FETCH_REPLICA on replicas
    SEC check: recipient_node_id == authenticated peer_id
```

The clever part is that the backup holders (the **replicas**) are chosen by a
formula, not by negotiation — the selection is **deterministic**. Any core node
that can see the DHT computes the same `shard_target` and arrives at the same set
of closest replicas. So the sender and the recipient never have to swap host
addresses or agree on anything in advance; the math points them both at the same
mailboxes.

## The shared address book (DHT)

The **DHT** — distributed hash table — is the network's shared address book. No
single node holds all of it; each one keeps a slice, and together they can answer
"where is this node right now?" Veil uses the Kademlia design, and a few ideas
make it tick.

**Distance is math.** Kademlia measures how "close" two IDs are by **XOR
distance**: line the two IDs up bit for bit and count where they differ. It has
nothing to do with geography — it's just a number, and it gives every node a
consistent sense of who is near a given address.

**Each node keeps a structured contact list.** That list is split into 256
*k-buckets*, each holding up to `K` contacts (`K = 20`, the value from the
original Kademlia paper). Buckets are arranged by distance, so a node knows many
neighbors that are close to it and a few that are far — exactly what you need to
hop efficiently toward any address.

**Looking something up is iterative.** Rather than ask one node and wait, a node
starts with the `K` closest contacts it knows, queries `α = 3` of them at a time,
folds in whatever closer contacts come back, and repeats — each round landing
nearer the target until it converges, within at most `MAX_ROUNDS = 20` rounds.

**Storage is sharded.** The address space is divided into 256 *shards* (a
shard is just the first byte of the key, `shard_id = key[0]`), and each node
takes responsibility for the 16 shards nearest to it. Filtering `STORE`s by shard
is opt-in.

**Storage has two tiers.** Fresh, frequently used entries live in a fast in-memory
*hot* tier; the rest sit in a *cold* tier. Entries get promoted to hot when
they're accessed (least-recently-used order), pushed back down to cold when hot
fills up, and dropped entirely only when cold overflows. By default the cold tier
is also in memory, but you can back it with an on-disk RocksDB store via `[dht]
cold_store_path` (cargo feature `rocksdb-cold`, on by default for `veil-cli`).
That swaps the RAM ceiling for a disk one — comfortably past a million entries —
and keeps the data across restarts. If the feature isn't compiled in, or RocksDB
fails to open, it quietly falls back to the in-memory cold tier and notes it in a
startup log line.

**It defends against being surrounded.** An *eclipse attack* tries to fill your
contact list with nodes the attacker controls, cutting you off from the honest
network. To make that hard, a single bucket accepts at most `K/4 = 5` contacts
from any one `/24` IPv4 (or `/48` IPv6) subnet, so no small corner of the
internet can dominate your view.

**Writes are authenticated**, so nobody can store or delete under your name:
- A `StorePayload` may carry an Ed25519 signature over `key || value`.
- A `DeletePayload` must carry `algo + pubkey + signature` (any identity
  signature algorithm — Ed25519, Falcon-512, or an Ed25519+Falcon hybrid), and
  it's honored only when `BLAKE3(pubkey) == key` — that is, only the key's true
  owner can delete it.

## How a leaf becomes reachable (attachment)

A leaf sits behind a home router, so others can't connect to it directly. To stay
reachable anyway, a leaf **attaches** to a core and asks it to act as its public
contact point. The core publishes a small, signed *attachment record* in the DHT
saying "to reach this leaf, come through me." Anyone who wants the leaf looks that
record up and learns where to route:

```
Leaf starts → attach to Core → AnnounceAttachment(node_id, role, gateways, mailboxes, expires_at)
  → signed → stored in DHT at attachment_key(node_id)
Peer wants to reach Leaf → GetAttachment(node_id) → learns Core gateways/mailboxes → route
```

## End-to-end encryption

This is what keeps your messages private from everyone except the person you're
talking to. The sender seals the message so that only the final recipient can
open it; every node in between just carries a locked box. Veil uses ML-KEM-768 (a
post-quantum scheme) to agree on a one-time shared secret, then ChaCha20-Poly1305
to encrypt the content with it:

```
sender: (ct, ss) = ML-KEM-768.Encaps(recipient_ek)
        plaintext_envelope → ChaCha20-Poly1305(ss, nonce) → ciphertext
        send(E2E_MARKER || ct || ciphertext)

recipient: ss = ML-KEM-768.Decaps(dk, ct)
           plaintext = ChaCha20-Poly1305.open(ss, nonce, ciphertext)
```

Because the secret is established directly between the two endpoints, the relays
in the middle only ever handle ciphertext — the scrambled form. They never see
the plaintext.

## Getting through home routers (NAT traversal)

Most people are behind **NAT** — the address translation a home router does that
lets many devices share one public IP. It's convenient, but it means nobody on
the outside can simply dial in to you. So how do two people who are *both* behind
NAT reach each other? They get a little help from a relay that both can already
talk to. The relay introduces them — telling each side where the other appears to
be — and they open a direct path; if that fails, the relay carries the traffic
itself:

```
A behind NAT → connect to Relay R
A wants to reach B (also behind NAT):
  A → R: NatProbe(B's observed addr)
  R → B: NatProbeRelay(A's observed addr)
  B opens port for A → A connects directly
  Fallback: relay tunnel through R
```

## Finding neighbors nearby (mesh)

Veil can also connect devices on the same local network directly — handy for a
room full of IoT gadgets, or anywhere the wider internet is unavailable. Each
device shouts a small *beacon* — a hello broadcast to everyone on the local
segment — every 10 seconds. A nearby gateway hears it, recognizes a fellow Veil
device, and sets up a session. That gateway then acts as a bridge between the
little local mesh and the wider Veil network:

```
IoT device ← UDP beacon (multicast/broadcast, 10-sec interval) → Gateway
  Gateway sees beacon → auto-discover → establish veil session
  Gateway bridges local mesh ↔ global veil
```

Each beacon carries the sender's `node_id`, a `realm_id` (a UUID naming which
logical network it belongs to), its transport URIs, and a signed algorithm and
public key so listeners can trust it. The `realm_id` lets separate Veil networks
share the same physical wire without mixing: a node simply ignores any beacon
whose `realm_id` isn't its own.

## Learning about more peers (PEX)

A node always wants to know a few more peers — both to stay well-connected and to
discover new ways to reach them. **Peer exchange** (PEX, frame family 11) handles
this with a random walk: a request wanders from node to node, and the node it
lands on answers with a fresh batch of peers and their transport addresses. To
keep it from being abused for spam, the walk includes a small proof-of-work
challenge along the way:

```
Originator → seed:        PexWalk (walk_id, pubkey, nonce, signature, TTL)
Terminator → originator:  PexChallenge (PoW challenge)
Originator → terminator:  PexResponse (solution, origin_sig)
Terminator → originator:  PexResult (peer list with transport URIs)
```

The walk works with either signing algorithm: `crypto::verify_message` checks
`origin_sig` as Ed25519 when the public key is 32 bytes, or Falcon-512 when it's
the longer one.

## Keeping out abuse

An open network needs defenses against floods, spam, and freeloaders. Veil layers
several, and a new inbound connection passes through them in order — each one
cheap to check and quick to reject a bad actor before it can cost much:

```
Inbound connection:
  1. Per-IP session limit (32 max)
  2. PoW challenge (if configured)
  3. Handshake timeout (10s — `HANDSHAKE_TIMEOUT_SECS`)
  4. Per-peer rate limiter (token bucket)
  5. Violation tracker (5 violations → ban)
  6. Ban list (auto-expire after TTL)
  7. Congestion backpressure (>78% → drop transit)
  8. Reputation gate (200 points for transit)
```

## Seeing what's going on (observability)

When you want to know how your node is doing, Veil gives you several windows into
it:

- **Prometheus metrics** — fetch `GET /metrics` for counters and gauges covering
  every subsystem, ready to chart or alert on.
- **Structured logging** — each line is `[timestamp] LEVEL event message`, with
  JSON-L available if you'd rather machines read it.
- **Debug capture** — the `debug capture` CLI command records frames to a file
  as they fly past, for a closer look.
- **DiagPing** — measures round-trip latency all the way through Veil, end to
  end.
- **Trace buffer** — keeps the last N dispatch events in memory, a short flight
  recorder for debugging.
