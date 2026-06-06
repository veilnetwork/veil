# P-Net: Private Veil Networks

By default, a Veil network is public: any node may join. P-Net (Private
Network mode) locks that down. Only nodes holding a **membership
certificate** — a signed credential proving they belong — are let in.
The certificate must be signed by the **network owner**, the person who
controls the network.

The check happens at the OVL1 handshake, the moment two nodes first
establish a secure session. A node without a valid certificate is turned
away before that session opens.

## Trust model

```
Network Owner (offline-stored Ed25519 keypair)
    │  signs
    ▼
Membership Cert (per node, includes node_id + admin flag + valid_until)
    │  presented in HELLO + verified at handshake
    ▼
P-Net Member (admitted to private network)
```

A certificate grants one of two roles:

* **Admin** (`admin: true` in the cert) — can issue network-wide bans.
  These bans replicate over the DHT (the network's shared directory) and
  reach every member. Admins usually run on bootstrap nodes, the
  long-lived nodes others use to join.
* **Member** (`admin: false`) — can connect, nothing more. A member can
  still ban a peer, but the ban stays on that one host and is never
  shared.

## Why bans have two scopes

In public mode, every ban stays on the node that issued it. This is
deliberate: it stops a malicious peer from poisoning the whole cluster's
ban table — a denial-of-service trick that would let one bad actor lock
everyone out.

Private mode can relax this. An admin's network-wide bans are trusted
because admin certificates come from the owner, and the owner is
trusted by definition. So you can ban a node once, from any admin node,
and have it take effect everywhere.

## Operator setup

### 1. Generate the network owner key (one-time)

```bash
veil-cli network gen-owner \
  --pub-out  /etc/veil/owner.pub \
  --priv-out /etc/veil/owner.priv
```

Keep `owner.priv` **offline** — on a USB hardware token or an encrypted
backup, never on a connected machine. Anyone who holds this key can sign
new admin certificates and take over the network.

### 2. Generate the network ID (one-time)

```bash
veil-cli network gen-network-id
# network_id = 948b97b51b...ea87
```

Save this 64-character hex string. Every member needs it in their
config, and it is what binds a certificate to your network specifically.

### 3. Sign a cert per member

```bash
# Admin cert (bootstraps, ops nodes):
veil-cli network sign-member \
  --owner-pub /etc/veil/owner.pub \
  --owner-priv /etc/veil/owner.priv \
  --network-id "$NETWORK_ID" \
  --member-node-id "$NODE_ID_OF_BOOTSTRAP" \
  --admin \
  --valid-days 365 \
  --out /etc/veil/network.cert

# Member cert (regular leaf nodes — drop `--admin`):
veil-cli network sign-member \
  --owner-pub /etc/veil/owner.pub \
  --owner-priv /etc/veil/owner.priv \
  --network-id "$NETWORK_ID" \
  --member-node-id "$NODE_ID_OF_LEAF" \
  --valid-days 365 \
  --out /etc/veil/network.cert
```

#### Expiry options

By default a cert expires after `--valid-days` days (365 if you omit the
flag). Before that day arrives, the member must rotate — get a fresh
cert from the owner — or it will be locked out.

Rotation is a chore for fleet nodes you can't easily reach: embedded
devices, air-gapped backups, and the like. For those, pass `--no-expiry`
to mint a cert that never expires.

```bash
# Never-expiring cert — only revocable via DHT ban or owner-key rotation:
veil-cli network sign-member \
  --owner-pub /etc/veil/owner.pub \
  --owner-priv /etc/veil/owner.priv \
  --network-id "$NETWORK_ID" \
  --member-node-id "$NODE_ID_OF_FLEET_DEVICE" \
  --no-expiry \
  --out /etc/veil/network.cert
```

On the wire, a never-expiring cert is encoded as `valid_until_unix = 0`
(a sentinel value — zero means "no expiry" rather than an actual date).
The `verify-cert` and `inspect-cert` subcommands print `NEVER` in place
of a timestamp.

There is a catch. To revoke one such device, short of rotating the owner
key, you have to ban it over the DHT. If that device is offline or
air-gapped, the ban can't reach it until it re-joins the network — so it
stays trusted in the meantime.

You'll need each member's `node_id` for the steps above. A `node_id` is
`BLAKE3(public_key)` — the BLAKE3 hash of the node's identity public key
(the `public_key` field in the `[identity]` block of `node.toml`).
Compute it with `blake3sum`, or with the helper in the controller's
`build-testnet-configs.py` script.

### 4. Configure the node

Add to `node.toml`:

```toml
[network]
mode = "private"
network_id = "948b97b51b...ea87"
owner_pubkey = "<base64 ed25519 owner pubkey>"  # owner.pub contents
owner_algo = "ed25519"
membership_cert = "/etc/veil/network.cert"

# Optional defense-in-depth — only certs whose member_node_id appears
# here are treated as admin even if cert has admin=true. Empty list
# (the default) trusts the cert's admin flag unconditionally.
admin_node_ids = [
  "<hex node_id of trusted admin 1>",
  "<hex node_id of trusted admin 2>",
]
```

### 5. Restart

The handshake gate — the check that enforces all of this — is built once
when the node starts. So the new settings only take effect after a
restart. From then on, the node demands a cert from every incoming peer
and presents its own cert in the outbound HELLO, the first message of
the handshake.

## Issuing a ban from an admin node

```bash
veil-cli network ban <NODE_ID_HEX> --reason "spam"
```

Here is what that command sets in motion. It travels over the local
admin IPC socket (the private channel between the CLI and the running
daemon) as an `AdminCommand::PNetBan`. The daemon signs a `BanEntry`
with the node's identity key, applies it locally, and fans it out over
the DHT to the K closest peers. Every other member picks the ban up on
its next `p_net_ban_sync` tick, roughly every 60 s.

Confirm it landed on the receiving nodes:
```bash
veil-cli peers banned
```

## App-layer admission (ogate / oproxy)

The daemon's P-Net gate decides whether a peer may open an OVL1 session
at all. Apps that run on top of the daemon face the same question for
their own traffic — ogate (a TUN bridge that carries IP packets) and
oproxy (a SOCKS5/HTTP proxy). Rather than keep their own static
`allowed_node_ids` list, they can reuse the verification the daemon has
already done.

It works like this. Each app sends a `LocalAppMsg::PnetStatusQuery` over
its IPC socket and reads back the `MembershipCert` the daemon cached for
that peer. On the daemon side, the cert is saved at handshake time in a
per-peer `verified_peer_certs` map and served out through
`PnetStatusProvider`. So the app never verifies anything itself — it
just asks the daemon what it already knows.

### oproxy-server

In `server.toml`:

```toml
pnet_required = true
allowed_node_ids = []   # empty + pnet_required=true → "trust any cert-verified peer"
allow_all = false        # not needed when pnet_required is set
```

What happens when a stream comes in:

1. The source `node_id` is checked against `allowed_node_ids`, the
   existing gate.
2. If `pnet_required = true`, oproxy also asks the daemon, via a
   `peer_pnet_status(&src)` IPC query. It rejects the stream with
   `Denied` if the peer is not admitted (`admitted=false`) or has no
   cert (`has_cert=false`).

If that query to the daemon fails, oproxy fails closed — it denies the
stream rather than letting it through. You asked for the strict gate;
defaulting to open on an error would quietly undo it.

### ogate

In `ogate.toml`:

```toml
mode = "authorized"
pnet_required = true

[[peers]]
node_id = "deadbeef..."
addr_v4 = "10.99.0.2"
```

What happens at startup, and again on a SIGHUP reload (the signal that
tells ogate to re-read its config):

1. ogate connects to the daemon.
2. It walks the `[[peers]]` list and calls `peer_pnet_status` for each
   entry.
3. It drops any peer that isn't both cert-bearing and admitted
   (`has_cert && admitted`), logging a warning for each one dropped.
4. It builds its routing table from the peers that survived.

Pair this with `mode = "authorized"` for defence in depth — two
independent checks instead of one. A peer must both carry a verified
cert and appear in the `[[peers]]` list.

### Operator flow

```bash
# 1. Daemon in P-Net mode (operator-side, see sections above).

# 2. Issue cert for the peer that will use oproxy:
veil-cli network sign-member \
  --owner-pub /etc/veil/owner.pub \
  --owner-priv /etc/veil/owner.priv \
  --network-id "$NETWORK_ID" \
  --member-node-id "$PEER_NODE_ID" \
  --no-expiry \
  --out /etc/veil/peer-cert.bin

# 3. Peer side: install cert, restart daemon. Daemon presents cert
#    in HELLO, b1's daemon verifies + caches.

# 4. On b1: configure oproxy-server.toml with pnet_required = true.
sudo oproxy-server --gen-config > /etc/oproxy/server.toml
sudo vim /etc/oproxy/server.toml   # set pnet_required = true
sudo systemctl restart oproxy-server

# 5. Verify: peer opens stream → admitted.  Random unverified peer
#    → Denied + log entry.
```

## What gets rejected

| Scenario | Error message at handshake |
|---|---|
| Public-mode peer connects to private cluster | `peer did not present a membership cert (network is private)` |
| Cert signed by a different owner (wrong network) | `cert verification failed: cert network_id does not match local: expected=... got=...` |
| Cert expired | `cert verification failed: cert expired at unix=...` |
| Cert.member_node_id ≠ peer's authenticated node_id | `cert is not for this peer: cert.member_node_id=... peer_node_id=...` |
| Cert blob malformed | `cert blob decode failed: ...` |

## Ansible rollout

The repo ships two playbooks: `ansible/deploy-pnet.yml` switches a
cluster to private mode, and `ansible/revert-pnet.yml` switches it back
to public. Both run `serial: 1` — one host at a time — so the cluster
keeps a quorum throughout and never goes fully dark.

Before you run them, the controller needs:
- `/tmp/pnet/owner.pub` + `/tmp/pnet/owner.priv` + `/tmp/pnet/network_id.hex`
- One cert per host at `/tmp/pnet/<cfg-name>.cert` (cfg-name = b1/b2/b3 +
  n1..n5 — see the `inv_to_cfg` map in `deploy-pnet.yml`).

```bash
# Roll out:
ansible-playbook -i inventory.yml deploy-pnet.yml

# Revert (drops [network] block + cert, restarts in public mode):
ansible-playbook -i inventory.yml revert-pnet.yml
```

## Architecture notes

* **Cost of verifying a cert**: one Ed25519 signature check, about
  ~30 μs on a modern x86 chip — cheap. The gate runs it on every inbound
  connection. The cert is re-decoded each handshake and never cached, so
  a change to the admin allowlist takes effect the moment you reload, not
  after the next restart.
* **How long a ban takes to spread**: ≤60 s, set by the apply task's
  interval. You could speed it up by having every admin host issue the
  same ban, but the DHT fan-out (to the K=8 closest peers) usually blankets
  the cluster within a single tick anyway.
* **How the DHT key is derived**:
  `BLAKE3(network_id || ":bans:" || banned_node_id)`. A receiver checks
  both the ban's signature **and** that it was filed under the matching
  key. That second check stops anyone from filing a ban under the wrong
  key.

## Related code

* `crates/veil-identity/src/network_cert.rs` — cert blob codec +
  verifier
* `crates/veil-identity/src/network_ban.rs` — `BanEntry` codec +
  chain-of-trust verifier + DHT key
* `crates/veil-identity/src/network_access.rs` — `NetworkAccessGate`
  (the handshake-time verifier wrapper)
* `crates/veil-node-runtime/src/runtime/p_net_ban_sync.rs` —
  `publish_p_net_ban` + periodic apply task
* `crates/veil-node-runtime/src/pnet_status_provider.rs` —
  `DaemonPnetStatus` (IPC handler for `LocalAppMsg::PnetStatusQuery`)
* `crates/veil-cli/src/cmd/network_cmd.rs` — `veil-cli network …`
  subcommand handlers
* `veilclient/src/client.rs` — `peer_pnet_status` SDK helper
* `crates/oproxy/src/bin/server.rs` — `pnet_required` admission check
* `crates/ogate/src/bridge.rs` — `filter_peers_by_pnet` (startup +
  SIGHUP reload filter)

## Limitations / open work

* **No revocation list**: there is no way to cancel a single cert on
  demand. A stolen admin cert stays valid until its `valid_until_unix`
  passes. To retire admin certs early, re-issue them under a new admin
  keypair and redistribute.
* **Losing the owner key is catastrophic**: whoever holds the owner
  private key can mint admin certs that pass the gate anywhere. Guard it
  like a root CA key — the master key of a certificate authority — kept
  air-gapped, in an HSM (a tamper-resistant key device), or on a paper
  backup.
* **No bridging between networks**: an admin on Network A cannot reach
  into Network B. Each network is its own separate trust domain, with no
  overlap.
