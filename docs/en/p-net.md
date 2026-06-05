# P-Net: Private Veil Networks

P-Net (Private Network mode) restricts veil membership to nodes
holding a membership certificate signed by a network owner. Public-mode
(default) accepts any peer; P-Net rejects unauthenticated peers at the
OVL1 handshake gate.

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

Two member roles:

* **Admin** (`admin: true` in cert) — can issue DHT-replicated bans that
  propagate to every member. Typically run on bootstrap nodes.
* **Member** (`admin: false`) — connects only. Local-only bans stay on
  the host (no DHT replication).

## Why two ban scopes

Public mode keeps bans node-local (anti-DoS — a malicious peer can't
poison the cluster's ban table). Private mode trusts admins to author
network-wide bans because admin certs are issued by a trusted owner;
this lets you manage a private cluster from any admin node.

## Operator setup

### 1. Generate the network owner key (one-time)

```bash
veil-cli network gen-owner \
  --pub-out  /etc/veil/owner.pub \
  --priv-out /etc/veil/owner.priv
```

Keep `owner.priv` **OFFLINE** (USB hardware token, encrypted backup).
Anyone holding it can sign new admin certs.

### 2. Generate the network ID (one-time)

```bash
veil-cli network gen-network-id
# network_id = 948b97b51b...ea87
```

Save the 64-char hex string — every member needs it in their config.

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

By default the cert expires after `--valid-days` days (365 if omitted).
Members must rotate before expiry or get a fresh cert from the owner.

For fleet nodes where rotation is a logistical hassle (embedded
devices, air-gapped backups), pass `--no-expiry` to mint a
never-expiring cert:

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

On the wire this is encoded as `valid_until_unix = 0` (sentinel).
The `verify-cert` and `inspect-cert` subcommands show `NEVER` instead
of a unix timestamp. Trade-off: revoking a single device without
rotating the owner key requires DHT-ban propagation; if the device is
offline / air-gapped, the ban won't reach it until it re-joins.

Where to get a node's `node_id`: it's `BLAKE3(public_key)` of the node's
identity keypair (the `public_key` field in `[identity]` block of
`node.toml`). Use `blake3sum` or the helper in the controller's
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

The handshake gate is built at runtime startup. After restart the node
will require certs from incoming peers and will present its own cert in
outbound HELLO.

## Issuing a ban from an admin node

```bash
veil-cli network ban <NODE_ID_HEX> --reason "spam"
```

This goes through the local admin IPC socket → `AdminCommand::PNetBan`
→ signs a `BanEntry` with the node's identity key → fans out to K
closest peers via DHT replication → applies locally too. Other members
pick up the ban on their next `p_net_ban_sync` tick (~60 s).

Verify on receivers:
```bash
veil-cli peers banned
```

## App-layer admission (ogate / oproxy)

The daemon's P-Net gate decides whether a peer can establish an OVL1
session at all.  Apps running atop the daemon — ogate (TUN bridge),
oproxy (SOCKS5/HTTP proxy) — can delegate their own admission decision
to the daemon's already-performed verify, instead of maintaining their
own static `allowed_node_ids` list.

The mechanism: each app queries `LocalAppMsg::PnetStatusQuery` over its
IPC socket and reads the daemon's cached `MembershipCert` for the
peer.  Daemon-side: cert is stored at handshake-time in a per-peer
`verified_peer_certs` map and exposed by `PnetStatusProvider`.

### oproxy-server

In `server.toml`:

```toml
pnet_required = true
allowed_node_ids = []   # empty + pnet_required=true → "trust any cert-verified peer"
allow_all = false        # not needed when pnet_required is set
```

Behaviour on incoming stream:

1. Source `node_id` checked against `allowed_node_ids` (existing gate).
2. If `pnet_required = true`, additional `peer_pnet_status(&src)` IPC
   query.  Rejects with `Denied` if either `admitted=false` or
   `has_cert=false`.

Daemon RPC failure ⇒ fail-closed (the operator opted into the strict
gate; falling back open would defeat the point).

### ogate

In `ogate.toml`:

```toml
mode = "authorized"
pnet_required = true

[[peers]]
node_id = "deadbeef..."
addr_v4 = "10.99.0.2"
```

Behaviour on startup and on SIGHUP reload:

1. ogate connects to daemon.
2. Iterates `[[peers]]`; for each entry, calls `peer_pnet_status`.
3. Filters out peers without `has_cert && admitted` (warns about each drop).
4. Builds routing table from the filtered list.

Combine with `mode = "authorized"` for defence-in-depth — peer must BOTH
have a verified cert AND be in the `[[peers]]` list.

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

The repo ships `ansible/deploy-pnet.yml` (rollout) and
`ansible/revert-pnet.yml` (back to public mode). Both are `serial: 1`
rolling — cluster keeps a quorum during the switch.

Prerequisites on the controller:
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

* **Cert verification cost**: 1 Ed25519 signature verify (~30 μs on
  modern x86). Handshake gate verifies on every inbound; cert is
  re-decoded on every handshake (not cached) so admin-allowlist
  changes take effect immediately on reload.
* **Ban propagation latency**: ≤60 s (apply task interval). For faster
  propagation, every admin host could issue redundant bans, but the DHT
  fan-out (K=8 closest) usually covers the cluster within one tick
  anyway.
* **DHT key derivation**: `BLAKE3(network_id || ":bans:" || banned_node_id)`.
  Receivers verify ban signature **and** that the key matches —
  prevents misfiling a ban under a wrong key.

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

* **No revocation list**: a compromised admin cert remains valid until
  its `valid_until_unix` elapses. Rotate admin certs by re-issuing with
  a new admin keypair and redistributing.
* **Owner-key compromise is catastrophic**: anyone holding the owner
  privkey can mint admin certs that gate-pass everywhere. Treat it
  like a root CA key — air-gapped, HSM, or paper backup.
* **Cross-network connectivity**: an admin on Network A cannot bridge to
  Network B. Each network is a disjoint trust domain.
