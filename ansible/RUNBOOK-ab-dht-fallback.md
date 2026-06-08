# Runbook — A/B: does the FIND_NODE route-fallback earn its keep?

## Question

The iterative-DHT route-discovery fallback (`try_seed_route_via_find_node`,
`crates/veil-node-runtime/src/dht_fallback.rs`) fires a `RecursiveQuery(FIND_NODE)`
after the `RouteRequest` flood (TTL=7) exhausts, to seed `route_cache`. In ~5h
of testnet steady-state it resolved **0** of 8 triggers while the dispatcher's
always-on `try_recursive_relay_via_dht` (greedy Kademlia relay) handled **100%**
of route-misses (3468/3468). This A/B settles **keep-dormant vs remove** by
measuring end-to-end delivery with the fallback ON vs OFF under chaos.

Steady-state can't answer it (the fallback barely fires), so we need a
chaos/partition window — the regime the fallback was designed for.

## Outcome metric

End-to-end **chat delivery ratio = Σ recv / Σ sent** across all nodes over the
window (`[<-]` / `[->]` lines in `/var/log/veil/chat-node.log`).

- `recursive_relay_{initiated,delivered}` are **diagnostics only** — they count
  different events at different nodes, not a same-node success rate.
- `dht_fallback_resolved` (ON window) is direct evidence: if it stays ~0 under
  chaos, the fallback resolves nothing even when stressed.

**Decision rule:** if Σrecv/Σsent in the OFF window is statistically
indistinguishable from the ON window (expected, since relay covers 100%),
**remove** the fallback. If OFF is meaningfully worse, **keep** it (and revisit
the design — see the `## What this is NOT` note in `dht_fallback.rs`).

## Design — temporal crossover

Per-node traffic is heavily skewed (node2 ~1100 misses/5h vs node4 ~8), so a
between-node split is confounded. Use a **crossover**: every leaf node is its
own control across two equal back-to-back chaos windows.

| window | fallback | leaf nodes      | duration        |
|--------|----------|-----------------|-----------------|
| W1     | **ON**   | node1..node5    | e.g. 2 h chaos  |
| W2     | **OFF**  | node1..node5    | same 2 h chaos  |

Bootstraps (b1–b3) stay ON throughout (infra control). Keep chaos intensity and
chat rate **identical** across both windows.

## Prerequisites — one-time

1. Build the binary that knows the `dht_fallback_enabled` flag, matching the
   deployed feature set (confirm seeds feature — testnet takes bootstraps from
   node.toml, so `allow-empty-seeds`; release uses `production-seeds`):

   ```bash
   FEATURES=rocksdb-cold,tls-boring,allow-empty-seeds \
     scripts/cross-build-linux-musl.sh
   cp target/x86_64-unknown-linux-musl/release/veil-cli target/release/veil-cli
   ```

2. Deploy it everywhere (default `dht_fallback_enabled=true` → behaviour-neutral,
   this IS the W1/ON baseline). Serial, preserves node.toml + state:

   ```bash
   cd ansible && ansible-playbook -i inventory.yml deploy-binary-only.yml
   ```

   (Old binaries ignore the new key — `RoutingConfig` has no
   `deny_unknown_fields` — so the deploy is safe in any order.)

## Run

```bash
cd ansible
# ── W1: fallback ON ──────────────────────────────────────────────
ansible-playbook -i inventory.yml deploy-chaos-ban.yml            # start chaos
../scripts/ab-dht-fallback-snapshot.sh snap w1-on-start
#   ... let W1 run (same duration as W2) ...
../scripts/ab-dht-fallback-snapshot.sh snap w1-on-end

# ── flip to OFF on the leaf nodes ────────────────────────────────
ansible-playbook -i inventory.yml toggle-dht-fallback.yml -e fallback_enabled=false
../scripts/ab-dht-fallback-snapshot.sh snap w2-off-start
#   ... let W2 run, identical chaos intensity ...
../scripts/ab-dht-fallback-snapshot.sh snap w2-off-end

# ── restore + stop chaos ─────────────────────────────────────────
ansible-playbook -i inventory.yml toggle-dht-fallback.yml -e fallback_enabled=true
ansible-playbook -i inventory.yml remove-chaos-ban.yml
```

## Analyse

```bash
scripts/ab-dht-fallback-snapshot.sh diff w1-on-start  w1-on-end   # ON  window
scripts/ab-dht-fallback-snapshot.sh diff w2-off-start w2-off-end  # OFF window
```

Compare the two `NETWORK ... delivery ratio` lines. Also confirm `fb_resolved+`
in the ON window — if it is ~0 even under chaos, that alone is strong evidence.

## Rollback

`toggle-dht-fallback.yml -e fallback_enabled=true` re-enables; the flag defaults
to `true`, so removing the line from node.toml (or redeploying) also restores
the fallback.

## Notes

- The toggle restarts `veil` (serial, one node at a time) and re-starts
  `chat-node` so its IPC session re-binds. Brief per-node session churn.
- Chat throttle is `CHAT_TARGET_KBITS` in `chat-node.service` (200 = throttled).
- If `logrotate` rotates `chat-node.log` mid-window, the `sent`/`recv` deltas
  reset — keep windows shorter than the rotation interval, or rely on the
  counter deltas which are restart-scoped.
