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

Add the issuing administrator's node ID to any nonempty
`[network].admin_node_ids` lists on the issuer and the receivers. If
the issuer's own list excludes it, the command returns an error before
applying or publishing the ban.

Here is what that command sets in motion. It travels over the local
admin IPC socket (the private channel between the CLI and the running
daemon) as an `AdminCommand::PNetBan`. The daemon signs a `BanEntry`
with the node's identity key, applies it locally, and replicates it over
the DHT to the K closest peers. A receiving daemon applies the ban as
soon as it verifies and stores the record. Startup and periodic checks
also apply records from the local store. Older daemons use those checks
and may take until their next 60 s scan. Applying a ban retires the
peer's active sender, blocks subsequent session registration and
reports the peer as denied over IPC. A private daemon that knows the
ban also rejects new addressed application datagrams to that peer
before route selection. It checks relayed datagram destinations when
forwarding and checks the sender again before local delivery.
Pending acknowledged datagrams to a revoked recipient stop retrying,
including retries that are waiting for relay queue capacity. The
originating application receives a delivery failure.

When a private node first stores a verified signed ban, it schedules a
background copy for its connected neighbors that accept DHT records.
A newly connected neighbor can also receive bans already held by the
node. Both paths share the same send budget, and duplicate copies for a
stored key do not schedule another pass. The sender rechecks the owner's
key, the administrator's certificate and signature, and the local
allowlist. Regular DHT replication continues on its own schedule.
`replicas_sent` counts peers for which a copy was queued. Verify receipt
on the nodes that enforce access.

With `persist_enabled = true` and `[dht].values_persist_path` set, the
issuer saves its own signed bans in the adjacent `<snapshot-name>.pnet-bans`
directory. `issuer_storage=saved` confirms that the issuer has a disk
copy, including when `replicas_sent=0`. `issuer_storage=volatile` reports
a write failure while the ban still applies in the running process.
`issuer_storage=disabled` means the issuer has no configured persistent
store. The issuer rechecks the network, signer and administrator
allowlist before restoring its records on startup.

With the same settings, a receiver applies a verified ban immediately
and queues it for the background writer. Completed copies are in
`<snapshot-name>.pnet-received-bans`, recorded in the log as
`network.ban.received_storage.saved`. If the write queue is full or a
write fails, the background writer can retry using the matching signed
record in the local DHT. On restart the receiver rechecks the signature
and administrator authorization and uses the original receipt time
for the remaining DHT lifetime. The background writer removes expired
copies. A process crash before the write completes can still lose the
local copy. The receiver can recover it from the DHT snapshot or
another participant.

`veil-cli node reload` also carries live signed bans into the rebuilt
DHT in memory. It preserves their original DHT lifetime. If received-ban
persistence stays enabled, the replacement background writer resumes
unfinished writes using the original receipt times.

Confirm it landed on the receiving nodes:
```bash
veil-cli peers banned
```

## Bootstrap from provisioned peers

Set `[network].mode = "private_configured"` to start from entry points
supplied by the operator. Use the same network ID, owner key and
membership certificate as for `private`. Each provisioned entry needs
its expected public key and transport address.

- For permanent neighbors, add a reciprocal `[[peers]]` entry on each
  node. Veil chooses the dialer based on the two node IDs.
- To join through an inbound-only entry point, add it to
  `[[bootstrap_peers]]` on the joining node. The entry point can leave
  its peer lists empty. Keep the entry in one list on the joining node.
- For a provisioned relay, use `[[pinned_relays]]`.

This profile skips public rendezvous, automatic LAN and mesh discovery,
built-in seeds, DNS and HTTPS seed discovery, and remembered or cached
peers on startup. Hosts named in configured transport addresses still
use normal name resolution. Authenticated private sessions can exchange
DHT and PEX information as they do in `private`. Use more than one
provisioned entry point where the deployment needs independent paths in.

The local membership certificate must pass validation before network
services start. The daemon keeps signed revocations from the current
owner when restoring its configured DHT values snapshot. The legacy DHT
cold database and learned endpoint snapshots stay out of bootstrap.
`veil-cli node bootstrap-status` shows the effective discovery sources.

Use a full daemon restart to change this profile, its local identity or
the configured owner and membership settings. Older binaries require
their existing `private` configuration. A node on such a binary can
join the same network with a valid certificate from the same owner.

## Check local membership before restart

Run the preflight as the daemon user, from its working directory. It
checks the node configuration and verifies that the local certificate
matches the configured network, owner key and node ID, and is currently
valid. The command works with both private modes while the daemon is
stopped or running.

```sh
veil-cli --config /var/lib/veil/node.toml network check-membership
veil-cli --config /var/lib/veil/node.toml network check-membership \
  --certificate /var/lib/veil/staging/replacement.cert
```

The second invocation checks a replacement certificate in memory. For an
owner rotation, pass the candidate config with the new owner pin. The
preflight leaves configuration and certificate files untouched. Use
`--output-format jsonl` before `network` for the
`pnet_membership_verified` event. Its `valid_until_unix` is `null` for a
certificate without expiry. Check live peer admission and reachability
after the restart with `ogate check`.

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

ogate rechecks admission at startup, on SIGHUP, and periodically. A
configured peer gains a route once the daemon reports a live,
certificate-verified session. The route is removed when that peer's
next check fails or times out. A finite certificate stops allowing
traffic at its expiry even between checks.

The refresh starts every five seconds when the previous sweep has
finished. Supported daemons negotiate groups of up to 64 peers on the
local status IPC connection. Each result covers only the requested
peer's private admission and expiry. A failed batch clears the P-Net
routes and triggers a new status connection. Older daemons still use
paced single-peer queries and update routes in groups.

With `pnet_required = true`, both access modes require a configured,
admitted peer. Use `mode = "authorized"` to also enforce the configured
source IP. The daemon still establishes sessions through its own discovery
and connection mechanisms.

If the daemon disconnects while ogate is running, ogate keeps its TUN
interface and retries the IPC binding with backoff. It resumes forwarding
after binding to the same node and named endpoint. P-Net routes are
verified again and ogate discards its pending packet batches from the
old binding. Restart ogate after an intentional change to the local
node identity.

When many gateways start against a freshly started daemon, stagger the
first end-to-end probes in small groups before ramping up UDP traffic.
Concurrent cold peer-key lookups and application traffic can put
pressure on session transmit queues even after routes appear.

On a bandwidth-limited link, ogate can collect packets for the same peer
for a little longer to reduce the number of Veil frames. Set
`[batch].flush_after_us` in the sending node's `ogate.toml` and apply it
with `ogate reload --pid PID`. New batches use the new window and open
batches keep their original deadlines. The default is 200 µs and the
accepted range is 1–32,000 µs. Increasing the interval adds delay to
sparse traffic. Size and packet count limits still trigger an immediate
flush. Older ogate versions that support the setting apply it on restart.

### Diagnose a P-Net gateway

Run `ogate check --config /etc/ogate/ogate.toml` as the ogate service
user. It validates the configured routes and queries the local Veil
daemon over IPC. In signed mode it also checks the
protected policy store, expiry, daemon trust pin, and local address
assignment. You can run it alongside an existing gateway.

Add `--peer NODE_ID` to check the local daemon's current admission for
one route peer or configured mirror. An error prints the reason and
returns a nonzero exit status. Use a tunnel probe to verify packet
delivery.

Use `ogate check --config /etc/ogate/ogate.toml --mirror NODE_ID` to
test snapshot serving directly. The check downloads the signed snapshot
from one configured mirror, verifies its signature and validity, then
compares it with the installed revision in read-only mode. It also works
when the local snapshot has expired or omits the local device's virtual
address. A successful check prints both revisions and the offered expiry.

To count local packet drops by reason, add the following to the gateway's
`ogate.toml` before starting it. The gateway writes `ogate packet drops`
events at info level for reasons that occurred since the previous report.

```toml
[logging]
format = "json"
packet_drop_report_secs = 10
```

Each event has a `reason` and a `count`. For example,
`egress_no_active_route` counts packets without an active route and
`ingress_oversize` counts packets larger than the receiving TUN's MTU.
Reasons ending in `_frames` count whole IPC frames. For drops after the
gateway submits traffic to the daemon, check the daemon's IPC admission
and session counters.

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

### Prepare a signed address policy

Use the existing P-Net owner key to sign a complete address snapshot.
Set the network ID, a positive revision, and the validity window in Unix
seconds. Use the same owner algorithm as for membership certificates.
For example, an unsigned TOML source has this shape. Replace the IDs and
timestamps for your network.

```toml
network_id = "0000000000000000000000000000000000000000000000000000000000000001"
revision = 1
valid_from_unix = 1795530000
valid_until_unix = 1795616400
ipv4_range = "10.99.0.0/24"
ipv6_range = "fd84:99::/64"

[[members]]
node_id = "0000000000000000000000000000000000000000000000000000000000000002"
addr_v4 = "10.99.0.2"
addr_v6 = "fd84:99::2"
```

```sh
veil-cli network route-policy sign --input policy.toml --out policy.bin \
  --owner-pub owner.pub --owner-priv owner.key --network-id "$NETWORK_ID"
veil-cli network route-policy verify --policy policy.bin \
  --owner-pub owner.pub --network-id "$NETWORK_ID"
veil-cli network route-policy install --policy policy.bin \
  --owner-pub owner.pub --network-id "$NETWORK_ID" --state-dir "$STATE_DIR" --initialize
veil-cli network route-policy status --owner-pub owner.pub \
  --network-id "$NETWORK_ID" --state-dir "$STATE_DIR"
```

Keep the signing key offline. On the receiving node, obtain the expected
network ID and public key through the existing P-Net trust configuration.
Use an existing absolute state directory owned by the service account
with mode `0700` and protected ancestry on durable local storage. Use
`--initialize` for the first installation. Subsequent installations use
the existing state to reject a lower revision or conflicting contents
at the accepted revision. Expiry leaves that revision floor intact.

To activate the installed snapshot, use an ogate configuration such as
this one. Use the physical, protected paths for the configuration file
and the state directory.

```toml
network = "engineering"
mode = "authorized"
pnet_required = true
local_addr_v4 = "10.99.0.2"
prefix_v4 = 24
local_addr_v6 = "fd84:99::2"
prefix_v6 = 64

[signed_policy]
state_dir = "/var/lib/ogate/policy"
network_id = "0000000000000000000000000000000000000000000000000000000000000001"
owner_pubkey = "<base64 owner public key>"
owner_algo = "ed25519"
```

Start ogate with this file and an empty manual peer list. Its local
addresses and prefixes must match the node's signed assignment. The
local daemon must support the authority check. After each IPC
connection, ogate verifies the network, owner key, and local membership
before querying private admissions.

Installed revisions are picked up on the next sweep. Use
`ogate reload --pid PID` to request a policy check between admission
batches during a sweep.
Changes to the local TUN addresses or prefixes require updating the
configuration and restarting ogate. When the policy or a membership
expires, the corresponding traffic stops at that deadline.

When a new snapshot applies, addresses removed or reassigned by the
owner lose their previous routes. Routes with the same peer and
addresses can keep their current admission through the transition.
ogate rechecks those peers first. Each existing admission remains
bounded by the previous policy and membership deadlines until the daemon
confirms it again.

### Automatic snapshot delivery

Keep the first installation explicit on every node. To let a node
distribute later revisions, set `publish = true` in its
`[signed_policy]` section. On receiving nodes, list up to eight publisher
device Node IDs under `mirrors` in the same section. This example uses
one publisher.

```toml
mirrors = ["0000000000000000000000000000000000000000000000000000000000000002"]
```

Install new owner-signed snapshots on the publishers. Keep the signing
key offline. Receivers normally check for a higher revision every 15
seconds over direct, authenticated P-Net sessions with the configured
publishers. The first check is staggered across receivers. As the
installed policy expires, receivers move toward staggered 4–6 second
checks. Installing a verified policy locally can bring the next check
forward when the new policy expires sooner. Each receiver runs one
round at a time. If its local daemon connection fails, the receiver
retries that connection every 4–6 seconds. After reconnecting it can
check the configured publishers early when there is time for a
separate check before the regular poll.
Admission of a configured publisher can also advance the next poll.
The receiver can request an early poll on a generic admission event
from an older daemon or a reported event gap.

Each side requires current daemon-certified membership. A receiver
verifies the owner's signature, validity and revision before storing
the snapshot. After storage, ogate wakes the route updater so it can
read the verified snapshot and recheck route admissions. An expired
snapshot contributes zero routes and keeps its revision floor. While
its daemon membership is current, a receiver can fetch a newer snapshot.

Ensure the publishers are reachable over the existing private
transport. A publisher shares the entire signed address map with
current members, including members without a virtual address; route
activation still requires an address assignment and current membership.
If different snapshots at the same highest revision arrive in one
poll, ogate reports the conflict and leaves the installed revision in
place. If the mirrors are unavailable, the cached policy remains
effective until expiry. Restart ogate after changing distribution
settings. With the defaults, distribution is disabled.

## Replace the owner key

Use an authenticated management channel independent of P-Net to
distribute the new public key and its algorithm. Keep the network ID and
the member node IDs. Sign new certificates offline for the devices that
should still have access. Review the admin allowlist and prior revocations
before issuing replacements. For signed ogate routes, sign a current
snapshot with the new owner key at a revision above the highest installed
revision across the fleet.

On a node, check the replacement certificate against its local node ID
and preflight the policy as the account that owns the policy directory.
Use `--algo` for a current owner algorithm other than Ed25519 and
`--next-algo` if the successor uses a different algorithm.
For certificate verification, `--algo` selects the successor's algorithm.

```sh
veil-cli network verify-cert next.cert --owner-pub next.pub \
  --network-id "$NETWORK_ID" --member-node-id "$LOCAL_NODE_ID"
veil-cli network route-policy rotate-owner --check --policy next.bin \
  --owner-pub current.pub --next-owner-pub next.pub \
  --network-id "$NETWORK_ID" --state-dir "$STATE_DIR"
```

1. Schedule a maintenance window and stop ogate and the daemon. Nodes
   with different configured owners cannot authenticate each other.
2. Run the same `rotate-owner` command without `--check`. It replaces the
   snapshot in the existing store and preserves the revision floor. It
   needs only the public key of the previous owner, even if the stored
   policy has expired. Repeat the same command if its result was lost.
3. Configure the new public key and algorithm in `[network]` and
   `[signed_policy]`, and set `[network].membership_cert` to the replacement
   certificate. Restart the daemon, then ogate. Confirm `route-policy
   status` with `--owner-pub next.pub` and verify private reachability.
4. Republish any required network-wide bans from admins authorized by
   the new key. Existing locally applied bans may remain in effect.

For a staged rollout over reciprocal `[[peers]]` links, sort the full
hexadecimal node IDs in descending order and rotate the highest IDs
first. Wait for the updated listeners to come up before starting the
next wave. The lower-ID node initiates these links, so its first dial
after restarting can reach the listener with the new owner key. One-way
bootstrap and pinned relay links have their own dialing direction.

Allow time for scheduled reconnect retries after the last wave. Before
ending maintenance, check private reachability between nodes in
different waves and confirm the current policy revision on mirrors and
subscribers.

Remote mirrors can distribute address snapshots under the configured key.
Only the operator can change the owner pin. Revise daemon trust only on
nodes you can authenticate and manage independently if the owner key is
lost or suspected of compromise.

### Prepare for emergency recovery

Generate a separate recovery key and keep its private half offline,
independent of the owner key. On each Unix node with signed ogate routes,
upgrade the local CLI and ogate to versions that support recovery before
pinning the recovery public key. Pinning records it alongside the policy
in the same protected store. Earlier ogate binaries cannot open an
enrolled store. Membership certificates and peer connections retain
their existing formats.

```sh
veil-cli network route-policy pin-recovery --owner-pub current.pub \
  --recovery-pub recovery.pub --network-id "$NETWORK_ID" --state-dir "$STATE_DIR"
```

In an emergency, generate a fresh owner key and issue new membership
certificates for approved nodes. Sign the initial address policy with
the new owner. It may start at revision 1, even if the old owner reached
the maximum revision. Sign the exact replacement file offline with the
recovery key. Use the existing protected state directory on every node.

```sh
veil-cli network route-policy sign-recovery --policy next.bin \
  --owner-pub current.pub --next-owner-pub next.pub --network-id "$NETWORK_ID" \
  --recovery-pub recovery.pub --recovery-priv recovery.key --out recovery.sig
veil-cli network route-policy recover-owner --check --policy next.bin \
  --owner-pub current.pub --next-owner-pub next.pub --network-id "$NETWORK_ID" \
  --recovery-pub recovery.pub --authorization recovery.sig --state-dir "$STATE_DIR"
```

Once the checks pass, follow the owner replacement procedure above.
Use `recover-owner` without `--check` in place of `rotate-owner`. Keep the
state and its owner history across restart and subsequent updates. After
enrollment, every owner change retires the previous key. The store cannot
reuse retired owner keys or use the recovery key as an owner. The pinned
recovery key itself stays fixed. Only the old owner's public key is
required. Changes to the P-Net trust pin and member certificates still use
an independent management channel.

## What gets rejected

| Scenario | Error message at handshake |
|---|---|
| Public-mode peer connects to private cluster | `peer did not present a membership cert (network is private)` |
| Cert signed by a different owner (wrong network) | `cert verification failed: cert network_id does not match local: expected=... got=...` |
| Cert expired | `cert verification failed: cert expired at unix=...` |
| Cert.member_node_id ≠ peer's authenticated node_id | `cert is not for this peer: cert.member_node_id=... peer_node_id=...` |
| Cert blob malformed | `cert blob decode failed: ...` |

## Ansible rollout

The repo ships two playbooks. `ansible/deploy-pnet.yml` switches a
cluster to private mode, and `ansible/revert-pnet.yml` switches it back
to public. Both process one host at a time. Plan for interrupted
connectivity between hosts in different modes during the rollout.

Before you run them, the controller needs:
- `/tmp/pnet/owner.pub` and `/tmp/pnet/network_id.hex`
- One cert per host at `/tmp/pnet/<cfg-name>.cert` (cfg-name = b1/b2/b3 +
  n1..n5 — see the `inv_to_cfg` role default).

Keep the owner signing key on the issuer.

The first play verifies the candidate configuration and membership
certificate for every selected host, including when using `--limit`.
The second play compares the candidate against its verified fingerprints
and activates it one host at a time. The certificate is installed under
a name containing its SHA-256 before the config points to it. Older
certificate files can remain on disk.

Before continuing to the next host, the playbook confirms that the same
systemd invocation is still running and that the installed configuration and
certificate still match the verified fingerprints. A change during the
readiness check stops the rollout on that host.

Set `pnet_min_membership_remaining_secs` in the inventory to reserve
time on expiring membership certificates for the rollout. The default
`0` checks current validity. For a positive value, the playbook uses
the verified expiry and the managed host clock at fleet preflight and
again just before that host's activation. A verified nonexpiring
certificate satisfies the lifetime check. If the check fails during
activation, the play stops and earlier successful activations stay in
place.

After successful activation, the playbook records the configuration
fingerprint and current systemd invocation in a root-only file under
`/run`. A repeat keeps Veil and the optional chat service running when
the files are unchanged, the receipt matches the running invocation,
and the readiness endpoint responds. Missing or stale receipts trigger
activation, including after an interruption between file publication
and service restart.

The managed hosts need Python 3.11 or later for the TOML check and a CLI
that supports `network check-membership`. Set `pnet_cli` to use a
separately installed verifier. The default role settings describe the
bundled systemd unit. For a customized unit, use its service user,
working directory and config validation environment.

The playbook stops before activation if a candidate needs changes to
a signed config or would replace an existing private authority.
Use the signed-config or owner-rotation procedure for those changes.
`pnet_mode=private_configured` selects configured-only discovery for a
new deployment. Subsequent deployments preserve this discovery mode.

To check the packet path as part of rollout, set `pnet_tunnel_probes` in
the inventory of each gateway you want to test.

```yaml
pnet_tunnel_probes:
  - interface: pnet0
    address: 198.18.23.2
  - interface: pnet0
    address: "fd42:198:23::2"
```

Use remote virtual addresses reachable through the named TUN interface.
The managed gateway needs Linux `ip` from iproute2 and `ping` from
iputils. The first play validates the settings and verifies that the
tools are installed. After all selected hosts finish activation, a
separate play waits for an echo reply through each configured TUN
path. The probes share a timeout per host, which can be set with
`pnet_tunnel_probe_timeout` and defaults to 45 seconds. A timeout reports
the failed paths and leaves the activated configuration in place.

```bash
# Verify the selected hosts without activating the candidates:
ansible-playbook -i inventory.yml deploy-pnet.yml --check

# Roll out:
ansible-playbook -i inventory.yml deploy-pnet.yml

# Recheck the tunnel paths independently
ansible-playbook -i inventory.yml check-pnet-tunnels.yml

# Return to public mode:
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
* **Recovery currently requires management access**. A compromised
  owner key can issue admin certificates until nodes change their pin.
  Normal rotation requires a higher revision. An enrolled recovery key
  can authorize a fresh owner even at the maximum revision.
* **No bridging between networks**: an admin on Network A cannot reach
  into Network B. Each network is its own separate trust domain, with no
  overlap.
