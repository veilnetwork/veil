# Installation & First Node

This guide takes you from a single `curl` command to a running veil node —
whether you have never touched the project before or you are an operator
standing up a fleet.

The installer downloads **prebuilt, sha256-verified** binaries from GitHub
Releases. No Rust toolchain is required (that is only needed if you
[build from source](#build-from-source)).

---

## TL;DR — one-liners

**Linux / macOS:**

```sh
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/veilnetwork/veil/main/scripts/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/veilnetwork/veil/main/scripts/install.ps1 | iex
```

Then start a node:

```sh
veil-cli config init      # fresh identity + config
veil-cli node run         # start in the background
veil-cli node show        # node id, uptime, peers
```

That's it. Read on to install the gateway/proxy tools, run a public server, or
tune the install.

---

## What gets installed

By default only **`veil-cli`** (the node + self-updater) is installed, into a
per-user directory that needs no `sudo`:

| Platform | Location |
|----------|----------|
| Linux / macOS | `~/.veil/bin` (added to `PATH` via `~/.veil/env`) |
| Windows | `%USERPROFILE%\.veil\bin` (added to your user `PATH`) |

You can install any subset of the four binaries:

| Binary | Role | Side |
|--------|------|------|
| `veil-cli` | The node: join the network, route, DHT, identity, self-update | client **or** server |
| `ogate` | IP-over-veil TUN bridge (virtual LAN) | server / gateway |
| `oproxy-client` | Local SOCKS5 / HTTP / TProxy → veil | client |
| `oproxy-server` | Veil exit / proxy server | server |

Install more than the node:

```sh
# everything (node + ogate + oproxy client & server)
curl -sSf https://raw.githubusercontent.com/veilnetwork/veil/main/scripts/install.sh | sh -s -- --all

# a specific subset
... | sh -s -- --components ogate,oproxy-server
```

On Windows:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/veilnetwork/veil/main/scripts/install.ps1))) -All
```

---

## Running a node

### Client / leaf (default)

A leaf connects *out* to the network; it needs no public address and works
behind NAT.

```sh
veil-cli config init --profile mobile   # battery-aware leaf (or omit --profile for plain dev)
veil-cli node run                        # background daemon
veil-cli node show                       # status
veil-cli node stop                       # graceful stop
```

Useful inspection commands: `node health`, `node bandwidth`, `node metrics`,
`node bootstrap-status` (what fallbacks you have if a seed IP is blocked).

### Server / relay (public listener)

A server advertises a public listener that other nodes bootstrap from. Use the
`censorship-target` profile (binds `wss://0.0.0.0:443`, sets a decoy SNI, enables
mesh) and a higher PoW difficulty:

```sh
veil-cli config init --profile censorship-target --difficulty 24
# edit the generated config (listen address, SNI, [network] mode, persist paths)
veil-cli config show
veil-cli node run
```

For a **hardened, always-on server** (dedicated `veil` user, `/var/lib/veil`
data dir, a `systemd` unit, and the public join blob printed at the end), use the
build-from-source provisioning script instead:

```sh
sudo PUBLIC_IP=203.0.113.10 LISTEN_PORT=443 ROLE=core \
  ./scripts/install-bootstrap.sh
```

See the [Administrator Guide](admin-guide.md) and [Operations](OPERATIONS.md) for
transports, metrics, and fleet management.

> **Censorship-resistant transports.** The default binaries already include the
> `tls-boring` fingerprint-rotation backend. For the strongest unobservability,
> review [p-net.md](p-net.md) and the `censorship-target` notes printed into your
> config.

---

## ogate — IP over veil

`ogate` bridges real IP traffic across the veil (a virtual LAN). It needs a
TUN device, so it runs with `CAP_NET_ADMIN` / root (or Administrator on Windows).

```sh
ogate gen-config -o ogate.toml          # commented template
# fill in: network name, peer node_ids, virtual IPs
sudo ogate up --config ogate.toml
ogate show                              # resolved config, no resources opened
```

Full reference: [ogate.md](ogate.md).

---

## oproxy — proxy client & server

Forward local app traffic through the veil to an exit server.

**Client** (your machine — a local SOCKS5/HTTP proxy):

```sh
oproxy-client --gen-config > oproxy-client.toml   # set server_node_id + [[inbound]] listeners
oproxy-client --config oproxy-client.toml
# now point your browser/app at the SOCKS5/HTTP port you configured
```

**Server** (the exit node):

```sh
oproxy-server --gen-config > oproxy-server.toml
oproxy-server --config oproxy-server.toml
```

Per-target routing (veil / direct / block) and failover are documented in
[oproxy.md](oproxy.md).

---

## Installer options

`install.sh` flags (pass after `sh -s --` when piping):

| Flag | Meaning |
|------|---------|
| `--all` | Install all four binaries |
| `--components a,b` | Install a specific subset |
| `--version X.Y.Z` | Pin a release (default: latest) |
| `--prefix /usr/local` | Install into `<prefix>/bin` (system-wide) |
| `--bin-dir <dir>` | Install straight into `<dir>` |
| `--libc musl\|gnu` | Linux x86_64 libc flavour (default: `musl`, static, runs anywhere) |
| `--no-modify-path` | Don't touch your shell profile |
| `--quickstart` | Init + start a node right after install |
| `-y`, `--yes` | Non-interactive |
| `--no-verify` | Skip sha256 verification (not recommended) |

`install.ps1` exposes the same as PowerShell parameters (`-All`, `-Version`,
`-Components`, `-BinDir`, `-NoModifyPath`, `-Quickstart`, `-NoVerify`). When
piping to `iex`, configure via env vars: `$env:VEIL_COMPONENTS`,
`$env:VEIL_VERSION`, `$env:VEIL_REPO`.

Install from a fork/mirror by setting `VEIL_REPO=owner/repo` (env var) on
either platform.

---

## Updating

`veil-cli` can update itself from the operator's signed manifest:

```sh
veil-cli update check
veil-cli update apply       # verifies the signature before swapping the binary
```

Or just re-run the installer — it always fetches the latest release. For
`ogate` / `oproxy`, re-run the installer (they ship as plain service binaries).

---

## Verifying what you installed

The installer checks each binary's SHA-256 against the published
`sha256-<triple>.txt` before installing. To re-verify by hand:

```sh
sha256sum ~/.veil/bin/veil-cli
# compare against the sha256-<triple>.txt asset on the Release page
```

Releases are also accompanied by a **signed `manifest-<triple>.bin`** (an
`UpdateManifest` signed with a cold-storage release key). Independent verifiers
can rebuild from the tagged commit with `scripts/build-release.sh` and confirm a
byte-identical SHA-256 — see [release.yml](../../.github/workflows/release.yml).

---

## Uninstall

```sh
# Linux / macOS
rm -rf ~/.veil
# then remove the "# veil" line from ~/.profile / ~/.bashrc / ~/.zshrc
```

```powershell
# Windows
Remove-Item -Recurse -Force $env:USERPROFILE\.veil
# then remove the bin dir from PATH (System > Environment Variables)
```

Node data (config + identity + persisted state) lives in the platform config
directory; `veil-cli config locate` prints the path if you also want to wipe it.

---

## Build from source

Needed only for platforms without a prebuilt binary (e.g. **Intel macOS**), or to
develop. The default features pull in **BoringSSL (`tls-boring`)** and
**RocksDB (`rocksdb-cold`)**, so a C/C++ toolchain is required:

```sh
# Debian/Ubuntu prerequisites for the default (BoringSSL + RocksDB) build:
sudo apt-get install -y cmake golang-go nasm ninja-build build-essential

git clone https://github.com/veilnetwork/veil
cd veil
cargo build --release --bin veil-cli --bin ogate --bin oproxy-client --bin oproxy-server \
  --features veil-bootstrap/production-seeds
# binaries land in target/release/
```

For reproducible, signed release builds use `scripts/build-release.sh --target <triple>`.
To cross-compile a static Linux binary from macOS, see `scripts/cross-build-linux-musl.sh`.

---

## Supported platforms

Prebuilt binaries are published for:

| Triple | Notes |
|--------|-------|
| `x86_64-unknown-linux-musl` | **default for Linux x86_64** — static, runs on any distro |
| `x86_64-unknown-linux-gnu` | glibc build (`--libc gnu`) |
| `aarch64-unknown-linux-gnu` | ARM64 Linux |
| `aarch64-apple-darwin` | Apple Silicon macOS |
| `x86_64-pc-windows-msvc` | Windows 10/11 (x64) |

Intel macOS (`x86_64-apple-darwin`) and ARM64 Windows have no prebuilt binary —
[build from source](#build-from-source) or run the x64 build under emulation.

---

## Security of `curl … | sh`

The script is fetched over HTTPS (TLS 1.2+), verifies every binary's SHA-256
before install, never needs root for the default per-user install, and touches
only `~/.veil` plus your shell profile's `PATH` line. If you prefer to read
before running, download it first:

```sh
curl -fsSLO https://raw.githubusercontent.com/veilnetwork/veil/main/scripts/install.sh
less install.sh        # review
sh install.sh
```
