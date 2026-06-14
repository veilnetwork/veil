# Bootstrap node install scripts

This directory ships:

* **`devnet.sh`** / **`devnet.ps1`** — local multi-node devnet manager
  for Linux/macOS (bash) and Windows (PowerShell).  Generates N node
  configs, starts each via `veil-cli node run --foreground`, and
  provides start / stop / status / smoke / logs subcommands.  See
  inline `--help` (bash) or `Get-Help` (PowerShell).
* **`test-hot-standby.sh`** — Epic 459 verification fixture.  Brings up
  two local nodes (each with two TCP listeners), waits for the session
  to establish, then runs four phases: session health, transport
  inventory, runner-swap unit tests, and an end-to-end swap phase that
  auto-skips with a TODO summary until Epic 459 stages (b)/(c)/(d) ship.
  First run mints two PoW-24 identities (minutes); subsequent runs reuse
  the cached configs (seconds).  See `scripts/test-hot-standby.sh help`.
* **`install-bootstrap.sh`** — production bootstrap-node installer
  for a Linux host.  Sets up a system user, builds + installs
  `veil-cli`, generates a long-lived identity, registers a `systemd`
  unit.  Documented below.
* **`iperf-veil-bench.sh`** — veil throughput integration test.
  Measures iperf3 over kernel loopback (baseline), then iperf3 over a
  fresh 2-daemon + 2-ogate netns setup, and asserts veil throughput is
  ≥ `MIN_VEIL_PCT` (default 1) % of loopback.  Catches catastrophic
  regressions (session-flap, batch-encoding bugs) that drop veil below
  1 % of raw kernel throughput.  Requires sudo (NOPASSWD) for TUN +
  netns + ogate.  See header comment for env knobs (`DURATION`, `TRIALS`,
  `OGATE_WORKERS`, etc.).

Quick devnet:

```bash
# Linux / macOS
./scripts/devnet.sh start --nodes 3
./scripts/devnet.sh smoke
./scripts/devnet.sh stop
```

```powershell
# Windows (release build is auto-built on first run if absent)
pwsh .\scripts\devnet.ps1 start -Nodes 3
pwsh .\scripts\devnet.ps1 smoke
pwsh .\scripts\devnet.ps1 stop
```

Each node lives under its own dir (`$env:LOCALAPPDATA\veil-devnet\node-N`
on Windows; `/tmp/veil-devnet/node-N` on Linux).  Admin + IPC sidecars
(`admin.port` / `admin.token` / `ipc.port` / `ipc.token`) are written
**next to the config file** (Epic 451.6c default) so each node is
self-isolated without operator-supplied `runtime_dir` overrides.

## Hot-standby fixture

`test-hot-standby.sh` exercises Epic 459's runner-level stream swap
(stage (a)).  On first invocation it mints two PoW-24 identities
(several minutes on a laptop) and writes node configs to
`/tmp/veil-hot-standby/node-{0,1}/`.  Subsequent runs reuse the
cached configs and complete in seconds.

```bash
./scripts/test-hot-standby.sh run        # full pipeline: start + verify + stop
./scripts/test-hot-standby.sh run --no-stop  # leave fixture up for poking
./scripts/test-hot-standby.sh verify     # against an already-running fixture
./scripts/test-hot-standby.sh logs 0     # tail node-0's log
./scripts/test-hot-standby.sh stop       # kill nodes, keep configs
```

Phases:

1. **session health** — `node show` on both sides shows ≥1 active session.
2. **transport inventory** — snapshot `sessions list` TSV; records the
   primary transport per node as the pre-swap baseline.
3. **runner-swap unit tests** — runs `cargo test swap_` which proves
   `NextInput::SwapStream` preserves AEAD state in isolation (using
   `tokio::io::duplex` streams; no network).
4. **end-to-end swap** — auto-detects `veil-cli node swap-transport`.
   Today that subcommand does not yet exist (Epic 459 stages (b)/(c)/(d)
   add it); phase 4 prints its planned assertions and does not fail.

See `docs/hot-standby.md` + `docs/hot-standby-test-plan-windows.md`
for the wider design and the Windows multi-host manual test plan.

---

# Bootstrap node install script

Minimal tooling to bring up a bootstrap `core` node on a dedicated
Linux host.  Intended for **testnet** deployment — produces a binary built
with `--features allow-empty-seeds`, which is not a production stance.

## Prerequisites

* Linux host with `systemd` (Debian / Ubuntu / RHEL family).
* Root access (the script provisions a system user, writes to
  `/usr/local/bin` and `/etc/systemd/system`).
* A reachable public IP/port that other nodes can dial.  This IP goes into
  the TLV the bootstrap broadcasts in its `ATTACH` payload so clients can
  reconnect after learning about it via DHT gossip.
* Outbound HTTPS to fetch the Rust toolchain on first run.

## One-shot install

```bash
# clone the repo onto the bootstrap host
git clone https://github.com/veilnetwork/veil.git
cd veil

# mandatory: advertised IP; everything else has defaults
sudo PUBLIC_IP=203.0.113.7 ./scripts/install-bootstrap.sh
```

Environment variables (all optional except `PUBLIC_IP`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `PUBLIC_IP` | — (required) | Publicly reachable IP the node advertises |
| `LISTEN_PORT` | `9000` | TCP port to bind |
| `ROLE` | `core` | `core` or `leaf`; Core gets DHT (K=20), relay, gateway |
| `DIFFICULTY` | `24` | PoW difficulty bits for the generated identity (≥24 for core) |
| `VEIL_USER` | `veil` | Unprivileged system user the daemon runs as |
| `DATA_DIR` | `/var/lib/veil` | Holds the config + persist snapshots |
| `CONFIG_PATH` | `${DATA_DIR}/node.toml` | Explicit config path |
| `CARGO_FEATURES` | `allow-empty-seeds` | Feature flag passed to `cargo build` |
| `SRC_DIR` | repo root | Where to build from |

## What the script does

1. Installs `build-essential` + `pkg-config` + the OpenSSL dev headers (`libssl-dev` on apt, `openssl-devel` on dnf/yum).
2. Installs `rustup` if `cargo` isn't already on `$PATH`.
3. Builds `veil-cli --release --features $CARGO_FEATURES` and copies it
   to `/usr/local/bin/veil-cli`.
4. Creates the `veil` system user + `${DATA_DIR}` (0700).
5. Generates a fresh identity (`veil-cli config init --difficulty N`).
6. Patches the config:
   * `identity.role = "${ROLE}"` (sed-patched since `config set` does not
     currently expose the role key).
   * Adds a `[[listen]]` entry via `veil-cli listen add`.
   * Appends a managed block with `persist_enabled = true` and every
     `[routing]` / `[dht]` snapshot path so state survives restart.
7. Installs `/etc/systemd/system/veil-bootstrap.service` with standard
   hardening (`ProtectSystem=strict`, `PrivateTmp`, `NoNewPrivileges`, …),
   plus `LimitNOFILE=65536` for a dedicated bootstrap host.
8. `systemctl enable --now` + prints the TOML snippet other nodes paste
   into their `bootstrap_peers` array.

The script is re-runnable: it checks for existing state before mutating
(`useradd` skipped when the user exists, config preserved if `node.toml`
already present, listener skipped when already configured, managed block
only appended once).

## After install — sharing the advertisement

At the end of the run the script prints something like:

```toml
[[bootstrap_peers]]
transport  = "tcp://203.0.113.7:9000"
public_key = "..."
nonce      = "..."
algo       = "ed25519"
```

Hand that block to every other node that should know about this bootstrap —
they paste it into their own `config.toml` and restart.  At least **three**
bootstrap nodes on different providers is sensible testnet practice so
one outage doesn't break new joiners.

## Operating

```bash
# live status
systemctl status veil-bootstrap
journalctl -u veil-bootstrap -f

# show the node's runtime summary
sudo -u veil veil-cli --config /var/lib/veil/node.toml node show

# list active listeners
sudo -u veil veil-cli --config /var/lib/veil/node.toml listen list

# metrics snapshot
sudo -u veil veil-cli --config /var/lib/veil/node.toml node metrics

# reload config without restart
systemctl kill -s SIGHUP veil-bootstrap
# or:
sudo -u veil veil-cli --config /var/lib/veil/node.toml node reload
```

## Uninstall

```bash
# stop + remove binary + unit, keep ${DATA_DIR}
sudo ./scripts/uninstall-bootstrap.sh

# wipe everything including identity + persist snapshots
sudo PURGE_DATA=1 ./scripts/uninstall-bootstrap.sh
```

## Production hardening (out of scope for this script)

* Move to `--features production-seeds` after populating `BUILTIN_SEEDS`
  with your signed seed set.
* Put the listener behind TLS (`tls://...`) and pin `advertise` to the
  DNS name rather than a raw IP.
* Run on a host with monotonic clock (NTP) — session `created_at` / TTL
  checks assume clock discipline.
* Keep `/var/lib/veil` on a filesystem with `fsync` durability; persist
  snapshots use atomic rename.
* Monitor the Prometheus scrape endpoint (`config set metrics.enabled` +
  a `metrics_http` listener in the config) rather than parsing
  `node metrics` over SSH.
