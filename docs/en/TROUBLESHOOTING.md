# Troubleshooting

> Something acting up? Each entry below follows the same shape: symptom →
> likely cause → fix. A companion to [OPERATIONS.md](OPERATIONS.md) and
> [MONITORING.md](MONITORING.md).

## Quick triage

Before you dig in, grab a snapshot of what the node is doing right now. Many of
the fixes below refer back to this output, so it's worth running first:

```bash
veil-cli -c node.toml node show           # version + uptime + counts
veil-cli -c node.toml peers list          # configured peers
veil-cli -c node.toml peers banned        # active bans
veil-cli -c node.toml sessions list       # established sessions
veil-cli -c node.toml node dht routing    # DHT k-buckets
veil-cli -c node.toml node metrics        # counter snapshot
journalctl -u veil-node --since "10 min ago" > /tmp/veil.log
```

---

## Node won't start / crashes immediately

### `compile_error: release build without seeds`
The release build ships with no seed entries, and neither the
`production-seeds` nor the `allow-empty-seeds` feature flag is turned on — so
the node has nowhere to bootstrap from and refuses to compile. See
[OPERATIONS.md → Seed Node Setup](OPERATIONS.md#seed-node-setup). For a testnet
build, the quick fix is `cargo build --release --features allow-empty-seeds`.

### `error: identity validation failed: PoW score N < required 24`
Your configured `[identity]` nonce no longer clears the difficulty floor —
usually because the difficulty was raised in a newer build. Just mine a fresh
one:

```bash
veil-cli config init --force /path/to/config.toml
# or for sovereign identity:
veil-cli identity create --veil-dir /path/to/veil
```

### `error: admin socket already in use`
A previous `veil-cli node run` left a stale socket file behind. As long as no
veil process is actually running, it's safe to delete it and start fresh:

```bash
rm /run/veil/admin.sock
systemctl start veil-node
```

### Node starts then exits silently
The logs will tell you why — start with
`journalctl -u veil-node --since "5 min ago"`. The usual culprit is a missing
`identity_document.bin` after a move or restore. If that's it, restore it from
your BIP-39 phrase as described in
[OPERATIONS.md → Identity loss](OPERATIONS.md#identity-loss--restore-from-bip-39).

---

## Peers don't connect

### `WARN peer.connect.failure ... Connection refused`
The other end either isn't listening or a firewall is in the way. Check the
path from the node doing the dialing:

```bash
nc -vz <remote_host> <remote_port>
# Connection refused → service down, or firewall reset
# Connection timeout → firewall drop or no route
```

If you're on the listening side instead, `veil-cli node show` should report
`listens_active` > 0. If it doesn't, look at the `listen.start` log line for
bind errors.

### `INFO session.banned ... node_id=XXXX — banned peer rejected`
One side has banned the other — either you banned them, or they banned you.
Have a look:

```bash
veil-cli peers banned | grep <node_id_short>
# If found: someone explicitly banned this node, check `reason` column.

# To clear a misapplied ban:
veil-cli peers unban <NODE_ID_HEX>
# Note: bans are persisted in <config-dir>/bans.json — they survive restart.
```

When the ban is symmetric (the ban-script style, where each side bans the
other), both sides have to run `unban` before the link comes back.

### `WARN peer.nonce_mismatch ... old=XXX new=YYY`
The peer on the other end re-mined their identity — say, after a difficulty
bump. Nothing to do here: on reload, the nonce in your `peers[]` config updates
itself from the handshake. Only worth a message to the remote operator if the
change was unexpected.

### Peer connects then immediately drops (handshake.success → session.close)
This usually means an OVL1 protocol-version mismatch, or the session cap has
been hit. Check the logs:

```bash
journalctl -u veil-node | grep -E "handshake|session\.close" | tail -20
# Look for "session limit reached" or "version mismatch"
```

If it's the cap, raise `[session].max_concurrent` (the default is 1000, though
some configs set it lower).

---

## Chat / app messages don't deliver

### `RuntimeError: no active OVL1 session to NNNN…`
This is `IPC_SEND_ERR_NO_ROUTE` coming from your local node: routing couldn't
find any path to the destination at all. Work through these in order — each
step narrows down where the path breaks:

1. **Is there a direct session to the destination?**  
   `veil-cli sessions list -v | grep <dst_node_id>` — if it shows up, the
   trouble is further downstream (banned or broken). If it's absent, keep going.

2. **Does a DHT k-bucket know the destination?**  
   `veil-cli node dht routing | grep <dst_node_id>` — if it's missing, the
   handshake's DHT propagation never landed. A restart clears this up most of
   the time.

3. **Is it banned?**  
   `veil-cli peers banned | grep <dst_node_id>` — if it's listed, there's your
   cause. Lift it with `peers unban`.

4. **Is the mesh fragmented?**  Make sure the two peers share a common
   neighbor. Even in ring topologies (5 nodes, every-other ban), the recursive
   query plus reverse-path response chain should still get through. Confirm
   `veil-cli node show | grep version` matches a current build.

### `RuntimeError: E2E key for NNNN… not yet cached`
This is `IPC_SEND_ERR_NO_E2E_KEY`. The node knows the route, but it hasn't
cached the destination's ML-KEM key yet. That happens when the route_cache was
filled in by plain RouteAnnounce gossip (which carries no ML-KEM key), or when
a piggy-backed RouteResponse never reached you.

The good news is it tends to self-heal: retrying the IPC send fires off a fresh
recursive query, and that one carries a piggy-backed RouteResponse with the
ML-KEM key. If the retries keep failing, restart the destination node — its
`mlkem.key` may have gone corrupt, and it's regenerated automatically on the
next start.

### Messages take a long time to deliver (5+ s)
A few counters usually point to the cause:

- `route_selection_avg_rtt` — a high RTT means a slow upstream.
- `decrypt_failures_total` — replays or key drift.
- `pending_ack` retransmits piling up — check with
  `veil-cli node metrics | grep ack`.
- The chat_client TTL is 30 s by default; lower it if you'd rather fail fast.

### Messages dropped silently (no error, no delivery)
When messages just vanish with no error, the frame is probably larger than
`[session].max_frame_body` — a peer drops oversized frames without telling
anyone. Make sure the sender and receiver agree on the same limit (1 MiB by
default). The other possibility: the message was Chunk'ed, but the sending peer
never negotiated chunking — so confirm both sides are on OVL1 minor ≥ 2.

---

## Bans / abuse

### `INFO session.banned` for a peer that should be allowed
This is most likely an automatic ban from `kill_session`, which installs a
short 30 s temporary ban. You can just wait it out, or clear it right away with
`peers unban`.

If the ban is stickier than that, look in `<config-dir>/bans.json`:

```bash
cat /var/lib/veil/bans.json | jq .
# Edit / delete entries; they reload on next node start
```

### Sudden ban-storm metric spike
A spike usually has a single source behind it. To find it:

- Run `journalctl -u veil-node | grep session.banned` and look at which
  `node_id` patterns are being banned — are they one source-IP cluster?
- Check `peers banned` for a flood of fresh entries.
- If it's real abuse, consider tightening the `[abuse]` rate limits or per-IP
  caps.

### Want to ban an entire /24 subnet
`peers ban` can't do this yet — it works per-`node_id` only. The workaround is a
firewall rule at the host level
(`iptables -A INPUT -s 10.0.0.0/24 -j DROP`).

---

## DHT / routing weirdness

### `node dht routing` shows fewer contacts than expected
If you've just restarted, PEX may not have run yet — it walks the network every
120 s by default. Give it a couple of minutes and check again.

### `WARN recursive.response.relay_dropped`
A response to a recursive query couldn't be routed back to whoever started it:
there's no path through the DHT or cache to `reply_to`. That points to badly
fragmented mesh. Check the banned-pair list, and make sure the originator
shares at least one common neighbor with the responder.

### Loop in `recursive.query` logs (same query_id ttl=40 every 525 ms)
The originator keeps retrying because the recursive response never came back.
Cross-check the responder's logs for `recursive.response.dropped` — if it's
there, the responder couldn't reach back to it. This was fixed before 467.2e,
so make sure your binary is current.

---

## Mailbox

### `WARN mailbox.quota_reject`
A sender hit its per-sender rate limit. First find out who it is:

```bash
journalctl -u veil-node | grep mailbox.quota_reject | tail -20
```

If it's a legitimate burst, raise `[mailbox].max_per_sender`. If it's abuse,
ban the sender.

### Mailbox grows unboundedly
Mailbox pruning is meant to evict expired entries every minute (expired meaning
TTL past `mailbox_ttl_secs`, which defaults to 7 d). If
`veil_storage_evictions_total` isn't ticking up, the cleanup task may have
stalled — confirm `veil-cli node show | grep uptime` lines up with how fresh
the metric counters look. As a last resort, restart the node.

### Sleeping recipient never wakes
Check that the wake-up advertisement was both emitted
(`veil_sleep_advertisements_emitted_total`) and accepted
(`veil_sleep_advertisements_accepted_total`). If it was emitted but not
accepted, the gateway or recipient channel is broken.

---

## IPC / chat client

### `chat_client.py: connection refused on app.sock`
There are three usual reasons: the node isn't running, `[ipc].enabled = false`
in the config, or the socket path the client uses doesn't match the real one.
Start by checking the socket:

```bash
ls -la /path/to/veil/app.sock
# srwxr-xr-x — socket exists with proper permissions
```

If the file is there but the connection is still refused, the node may have
died — check `node show`.

### Client connects, then the connection immediately closes/resets (no daemon log)
The IPC handshake is being dropped before it finishes, and the daemon doesn't
log a thing — which makes this a confusing one. The likely cause is a
**cross-user peer-uid mismatch**. The daemon enforces a kernel-level peer-uid
gate on the app-IPC socket (`SO_PEERCRED` / `getpeereid`): it silently
`drop()`s any connection whose peer uid differs from the daemon's own, and
there's **no exception for root**. The same gate guards the admin socket.

This trips people up when the IPC client (`chat_client`, `ogate`, `oproxy`) or
the admin CLI runs as a different user than the daemon — classically, running
them as **root** against a daemon that runs as the `veil` user.

The fix is to run the IPC client and admin CLI as the **same user** as the
daemon:

```bash
sudo -u veil veil-cli -c node.toml node show
sudo -u veil ogate up
```

So don't run `ogate`, `oproxy`, or the admin CLI as root against a non-root
daemon. If you need a non-root TUN setup, grant `CAP_NET_ADMIN` to the daemon
user rather than running as root. (On TCP and Windows named-pipe IPC the
peer-uid check is a no-op — `uid_matches_local` is always true — so this only
affects Unix-socket transports.)

### `chat_client: timeout waiting for reply`
The send itself may have gone through fine, but the reply got lost on the way
back. Check the sender's `veil_pending_ack_*` counters and the recipient's
`route_miss_total`. To rule out the network entirely and test just the IPC
path, run `chat_server.py` on the same node as the client for a pure echo test.

---

## Performance

### High CPU (`veil-cli` process)
- `veil_decrypt_failures_total` — a high count points to a replay flood or key
  drift; the AEAD-fail path is expensive to walk.
- `veil_active_sessions` — too many of these means it's time to scale up.
- `lazy_miner` running is expected during the initial PoW (the first ~30 s);
  it should quiet down after that.

### High memory
- `veil_storage_evictions_total` should keep advancing. If it's not, eviction
  has stuck — check the mailbox WAL backend and the DHT cap.
- `node dht list | wc -l` — if this is closing in on `max_store_entries`,
  either raise the cap or let eviction do its job.

### High network out
Check the rate of `veil_transport_bytes_tx_total`. For a relay or gateway, high
egress is perfectly normal. On a leaf node it's worth a look — use
`veil-cli sessions list` to spot any unexpected outbound peers.

---

## Privacy / leakage

### Logs contain peer IPs
At INFO level, the default logs include things like
`transport=tcp://1.2.3.4:5678` and `source=inbound(peer-N)` for handshakes. If
you're running a privacy-focused deployment, set
`[global].log_level = "warn"` to drop that INFO chatter — WARN and ERROR logs
only ever reference `node_id`, which is already opaque.

A fuller PII review is still pending, so for now log_level filtering is the
workaround.

### `node show` leaked metrics URL with token
`?token=...` query strings are stripped from the `metrics_endpoint` display. If
you still see a token in the output, your binary is out of date — upgrade to a
current one (check with `node show | grep version`).

---

## When all else fails

When nothing above fits, fall back to the basics:

1. Capture the state: `node show`, `peers list`, `peers banned`,
   `sessions list -v`, `node dht routing`, `node metrics`, and journal logs from
   the last 30 minutes.
2. Restart the node. This preserves your bans, DHT values, and identity while
   clearing out any transient state.
3. If it's still broken, file an issue with the captured state and the relevant
   log excerpt from around when the symptoms began.
