# Troubleshooting

> Symptom → likely cause → fix.  Companion to
> [OPERATIONS.md](OPERATIONS.md) and [MONITORING.md](MONITORING.md).

## Quick triage

Before diving in, capture state:

```bash
veil-cli -c node.toml node show           # version + uptime + counts
veil-cli -c node.toml peers list          # configured peers
veil-cli -c node.toml peers banned        # active bans
veil-cli -c node.toml sessions list       # established sessions
veil-cli -c node.toml node dht routing    # DHT k-buckets
veil-cli -c node.toml node metrics        # counter snapshot
journalctl -u veil-node --since "10 min ago" > /tmp/veil.log
```

Many symptoms below cross-reference these outputs.

---

## Node won't start / crashes immediately

### `compile_error: release build without seeds`
The release build has no seed entries and neither `production-seeds`
nor `allow-empty-seeds` feature flag is enabled.  See
[OPERATIONS.md → Seed Node Setup](OPERATIONS.md#seed-node-setup).  For
testnet builds: `cargo build --release --features allow-empty-seeds`.

### `error: identity validation failed: PoW score N < required 24`
The configured `[identity]` nonce no longer satisfies the difficulty
floor (likely because difficulty was raised in code).  Re-mine:

```bash
veil-cli config init --force /path/to/config.toml
# or for sovereign identity:
veil-cli identity create --veil-dir /path/to/veil
```

### `error: admin socket already in use`
A previous `veil-cli node run` left a stale socket file.  If no
veil process is running:

```bash
rm /run/veil/admin.sock
systemctl start veil-node
```

### Node starts then exits silently
Check `journalctl -u veil-node --since "5 min ago"`.  Common: missing
`identity_document.bin` after move/restore — if so, restore from
BIP-39 phrase per [OPERATIONS.md → Identity loss](OPERATIONS.md#identity-loss--restore-from-bip-39).

---

## Peers don't connect

### `WARN peer.connect.failure ... Connection refused`
The remote endpoint isn't listening or firewall blocks.  Verify from
the dialing node:

```bash
nc -vz <remote_host> <remote_port>
# Connection refused → service down, or firewall reset
# Connection timeout → firewall drop or no route
```

If listing-side: `veil-cli node show` should report `listens_active`
> 0; if not, check `listen.start` log line for bind errors.

### `INFO session.banned ... node_id=XXXX — banned peer rejected`
Either you banned them, or they banned you.  Inspect:

```bash
veil-cli peers banned | grep <node_id_short>
# If found: someone explicitly banned this node, check `reason` column.

# To clear a misapplied ban:
veil-cli peers unban <NODE_ID_HEX>
# Note: bans are persisted in <config-dir>/bans.json — they survive restart.
```

For symmetric ban (ban-script style): both sides need `unban` to fully
recover the link.

### `WARN peer.nonce_mismatch ... old=XXX new=YYY`
The remote peer re-mined their identity (e.g. difficulty bump).
Auto-handled: on reload the nonce in `peers[]` config auto-updates
from the handshake.  Inform the remote operator if unexpected.

### Peer connects then immediately drops (handshake.success → session.close)
Likely OVL1 protocol-version mismatch or session-cap exceeded.  Check:

```bash
journalctl -u veil-node | grep -E "handshake|session\.close" | tail -20
# Look for "session limit reached" or "version mismatch"
```

If `max_concurrent` exceeded: increase `[session].max_concurrent` (default 65536, but lower in some configs).

---

## Chat / app messages don't deliver

### `RuntimeError: no active OVL1 session to NNNN…`
This is `IPC_SEND_ERR_NO_ROUTE` from the local node.  Routing couldn't
find any path to destination.

**Diagnosis chain:**

1. **Direct session to destination?**  
   `veil-cli sessions list -v | grep <dst_node_id>` — if present,
   issue is downstream (banned, broken).  If absent, continue.

2. **DHT k-bucket has destination?**  
   `veil-cli node dht routing | grep <dst_node_id>` — if missing,
   handshake DHT propagation failed.  Restart fixes most cases.

3. **Banned?**  
   `veil-cli peers banned | grep <dst_node_id>` — if found, that's
   the cause.  `peers unban` to lift.

4. **Mesh fragmented?**  Check that two peers have a common neighbor.
   In ring topologies (5 nodes, every-other ban) the recursive query +
   reverse-path response chain should still work.  Verify
   `veil-cli node show | grep version` matches a current build.

### `RuntimeError: E2E key for NNNN… not yet cached`
This is `IPC_SEND_ERR_NO_E2E_KEY`.  Route is known but ML-KEM key for
destination isn't cached yet.

**Cause:** route_cache populated via plain RouteAnnounce gossip (no
ML-KEM), or piggy-back RouteResponse never reached us.

**Fix:** on retry the IPC send triggers a fresh recursive query that
includes piggy-back RouteResponse with the ML-KEM key.

If retries continue to fail, restart the destination node — its
`mlkem.key` may be corrupt; auto-regenerated on next start.

### Messages take long time to deliver (5+ s)
- Check `route_selection_avg_rtt` metric — high RTT = slow upstream.
- Check `decrypt_failures_total` counter — replays / key drift.
- Check that `pending_ack` retransmits aren't accumulating —
  `veil-cli node metrics | grep ack`.
- Check chat_client TTL: default 30 s; lower for fast-fail.

### Messages dropped silently (no error, no delivery)
Frame may be exceeding `[session].max_frame_body` — peer drops oversized
frames without notifying.  Check sender + receiver both have the same
limit (default 1 MiB).  Or the message was Chunk'ed and the sender
peer hasn't negotiated chunking — check both sides have OVL1 minor ≥ 2.

---

## Bans / abuse

### `INFO session.banned` for a peer that should be allowed
Likely auto-banned by `kill_session` (which installs a 30 s temp ban).
Either wait 30 s, or `peers unban` immediately.

For sticky bans, check `<config-dir>/bans.json`:

```bash
cat /var/lib/veil/bans.json | jq .
# Edit / delete entries; they reload on next node start
```

### Sudden ban-storm metric spike
- Check `journalctl -u veil-node | grep session.banned` for the
  `node_id` patterns being banned — same source-IP cluster?
- Inspect `peers banned` for a flood of new entries.
- Consider adjusting `[abuse]` rate limits or per-IP caps.

### Want to ban an entire /24 subnet
Not yet supported by `peers ban` (per-`node_id` only).  Workaround:
firewall rule at host level (`iptables -A INPUT -s 10.0.0.0/24 -j DROP`).

---

## DHT / routing weirdness

### `node dht routing` shows fewer contacts than expected
If on a fresh-restart and PEX hasn't run yet (PEX walks every 120 s by
default), wait 2 minutes and re-check.

### `WARN recursive.response.relay_dropped`
A recursive query response couldn't be forwarded back to the originator
— no path through DHT/cache to `reply_to`.  This indicates severe mesh
fragmentation; check banned-pair list and verify the originator has at
least one common neighbor with the responder.

### Loop in `recursive.query` logs (same query_id ttl=40 every 525 ms)
Originator is retrying because the recursive response never arrived.
Cross-check responder logs for `recursive.response.dropped` — if
present, the responder couldn't reach back.  Pre-467.2e fix; ensure
the binary is current.

---

## Mailbox

### `WARN mailbox.quota_reject`
Per-sender rate-limit hit.  Check who's the sender:

```bash
journalctl -u veil-node | grep mailbox.quota_reject | tail -20
```

If legitimate burst, raise `[mailbox].max_per_sender`; if abuse, ban
the sender.

### Mailbox grows unboundedly
Mailbox pruning is supposed to evict expired (TTL > `mailbox_ttl_secs`,
default 7 d) entries every minute.  If `veil_storage_evictions_total`
isn't ticking, the cleanup task may be stalled — check
`veil-cli node show | grep uptime` matches the
metric-counter freshness.  Restart node as last resort.

### Sleeping recipient never wakes
Verify wake-up advertisement was emitted (`veil_sleep_advertisements_emitted_total`)
AND accepted (`veil_sleep_advertisements_accepted_total`).  If
emitted but not accepted, the gateway / recipient channel is broken.

---

## IPC / chat client

### `chat_client.py: connection refused on app.sock`
Either the node isn't running, or `[ipc].enabled = false` in config,
or the socket path differs from what the client passes.  Check:

```bash
ls -la /path/to/veil/app.sock
# srwxr-xr-x — socket exists with proper permissions
```

If file exists but connect refused: node may be dead; check `node show`.

### Client connects, then connection immediately closes/resets (no daemon log)
The IPC handshake gets dropped before it completes and the daemon logs
nothing.  Most likely a **cross-user peer-uid mismatch**: the daemon
enforces a kernel-level peer-uid gate on the app-IPC socket
(`SO_PEERCRED` / `getpeereid`) and silently `drop()`s any connection
whose peer uid differs from the daemon's own uid — there is **no root
exception**.  The same gate guards the admin socket.

This bites when the IPC client (`chat_client`, `ogate`, `oproxy`) or the
admin CLI runs as a different user than the daemon — classically running
them as **root** against a daemon that runs as the `veil` user.

**Fix:** run the IPC client / admin CLI as the **same user** as the
daemon:

```bash
sudo -u veil veil-cli -c node.toml node show
sudo -u veil ogate up
```

Do **not** run `ogate` / `oproxy` / the admin CLI as root against a
non-root daemon.  A non-root TUN setup needs `CAP_NET_ADMIN` granted to
the daemon user instead of running as root.  (On TCP and Windows
named-pipe IPC the peer-uid check is a no-op — `uid_matches_local` is
always true — so this only affects Unix-socket transports.)

### `chat_client: timeout waiting for reply`
The send may have succeeded but the reply got lost.  Check sender's
`veil_pending_ack_*` counters and recipient's `route_miss_total`.

For pure echo-test debugging, run `chat_server.py` on the same node as
client to isolate IPC vs network.

---

## Performance

### High CPU (`veil-cli` process)
- Check `veil_decrypt_failures_total` — high indicates replay flood
  or key drift; the AEAD-fail path is expensive.
- Check `veil_active_sessions` — too many = scale up.
- If `lazy_miner` is running, it's expected during initial PoW (first
  ~30 s); it should stop afterward.

### High memory
- `veil_storage_evictions_total` should advance — if not, eviction
  is stuck.  Check mailbox WAL backend + DHT cap.
- `node dht list | wc -l` — if approaching `max_store_entries`, raise
  the cap or accept eviction.

### High network out
Check `veil_transport_bytes_tx_total` rate.  If this is a relay /
gateway role, high egress is normal.  If a leaf node, investigate via
`veil-cli sessions list` for unexpected outbound peers.

---

## Privacy / leakage

### Logs contain peer IPs
Default INFO-level logs include `transport=tcp://1.2.3.4:5678` and
`source=inbound(peer-N)` for handshakes.  For privacy-focused
deployments, run with `[global].log_level = "warn"` to drop INFO
chatter.  WARN/ERROR logs reference `node_id` only (already opaque).

PII review pending — currently use log_level filtering as the
workaround.

### `node show` leaked metrics URL with token
`?token=...` query strings are stripped from `metrics_endpoint`
display.  If you see a token in current output, upgrade to a
current binary (per `node show | grep version`).

---

## When all else fails

1. Capture state: `node show`, `peers list`, `peers banned`, `sessions list -v`,
   `node dht routing`, `node metrics`, journal logs from last 30 min.
2. Restart node — preserves bans / DHT values / identity, clears
   transient state.
3. If still broken, file an issue with the captured state and the
   relevant log excerpt around when symptoms started.
