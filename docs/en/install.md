# Installation & First Node

This guide takes you from a single `curl` command to a running veil node. It
works whether this is your first time here or you're an operator standing up a
whole fleet of servers.

The installer downloads ready-made programs from GitHub Releases and checks each
one with **sha256** — a fingerprint that proves the file arrived intact and
unaltered. You don't need a Rust toolchain (the set of tools that compile Rust
source code); that's only for when you [build from source](#build-from-source).

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

That's it — you're on the network. Read on to add the gateway and proxy tools,
run a public server, or fine-tune the install.

---

## What gets installed

By default you get just **`veil-cli`** — the node itself, which can also update
itself. It lands in a folder owned by you, so no `sudo` is needed:

| Platform | Location |
|----------|----------|
| Linux / macOS | `~/.veil/bin` (added to `PATH` via `~/.veil/env`) |
| Windows | `%USERPROFILE%\.veil\bin` (added to your user `PATH`) |

There are four programs in total, and you can install any mix of them:

| Binary | Role | Side |
|--------|------|------|
| `veil-cli` | The node: join the network, route, DHT, identity, self-update | client **or** server |
| `ogate` | IP-over-veil TUN bridge (virtual LAN) | server / gateway |
| `oproxy-client` | Local SOCKS5 / HTTP / TProxy → veil | client |
| `oproxy-server` | Veil exit / proxy server | server |

To install more than the node:

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

A *leaf* is a node that reaches *out* to the network rather than accepting
incoming connections. It needs no public address and works fine behind NAT (the
router that shares one public address among the devices on your home network).

```sh
veil-cli config init --profile mobile   # battery-aware leaf (or omit --profile for plain dev)
veil-cli node run                        # background daemon
veil-cli node show                       # status
veil-cli node stop                       # graceful stop
```

A few commands to look under the hood: `node health`, `node bandwidth`,
`node metrics`, and `node bootstrap-status` — the last one shows your backup
routes into the network in case a seed IP gets blocked.

### Server / relay (public listener)

A server opens a public door — a *listener* — that other nodes use as their way
into the network. Use the `censorship-target` profile (it binds
`wss://0.0.0.0:443`, sets a decoy SNI so the connection looks like a different
website, and turns on mesh mode) together with a higher Proof-of-Work
difficulty:

```sh
veil-cli config init --profile censorship-target --difficulty 24
# edit the generated config (listen address, SNI, [network] mode, persist paths)
veil-cli config show
veil-cli node run
```

For a **hardened, always-on server**, use the build-from-source provisioning
script instead. It sets up a dedicated `veil` user, a `/var/lib/veil` data
directory, and a `systemd` service, then prints the public join blob (the short
string others use to connect to you) at the end:

```sh
sudo PUBLIC_IP=203.0.113.10 LISTEN_PORT=443 ROLE=core \
  ./scripts/install-bootstrap.sh
```

See the [Administrator Guide](admin-guide.md) and [Operations](OPERATIONS.md) for
transports, metrics, and fleet management.

> **Censorship-resistant transports.** The default binaries already ship with
> `tls-boring`, which keeps rotating the connection's fingerprint so it never
> looks the same twice. To make your traffic as hard to spot as possible, read
> [p-net.md](p-net.md) and the `censorship-target` notes written into your
> config.

---

## ogate — IP over veil

`ogate` carries ordinary IP traffic across veil, so a group of machines feels
like one private local network even though they're far apart. To do that it
creates a TUN device (a virtual network card), which is why it needs
`CAP_NET_ADMIN` or root — or Administrator on Windows.

```sh
ogate gen-config -o ogate.toml          # commented template
# fill in: network name, peer node_ids, virtual IPs
sudo ogate up --config ogate.toml
ogate show                              # resolved config, no resources opened
```

Full reference: [ogate.md](ogate.md).

---

## oproxy — proxy client & server

Send the traffic from apps on your machine through veil and out to an exit
server, which makes the requests on your behalf.

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

You can route each destination differently (through veil, straight out, or
blocked) and set up automatic failover — both are covered in
[oproxy.md](oproxy.md).

---

## Installer options

These are the flags `install.sh` understands. When you pipe the script into
`sh`, put them after `sh -s --`:

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

`veil-cli` can update itself. It pulls a *manifest* — a small file the operator
has signed to vouch for the new version — and upgrades from there:

```sh
veil-cli update check
veil-cli update apply       # verifies the signature before swapping the binary
```

Or just run the installer again; it always grabs the latest release. To update
`ogate` or `oproxy`, run the installer again — they're plain service programs
with no self-update of their own.

---

## Verifying what you installed

Before installing anything, the installer compares each binary's SHA-256
fingerprint against the published `sha256-<triple>.txt`. If you'd like to check
again yourself:

```sh
sha256sum ~/.veil/bin/veil-cli
# compare against the sha256-<triple>.txt asset on the Release page
```

Every release also comes with a **signed `manifest-<triple>.bin`** — an
`UpdateManifest` signed with a release key kept in cold storage (offline, so it
can't be stolen over the network). If you want to confirm nothing was tampered
with, you can rebuild from the tagged commit with `scripts/build-release.sh` and
check that you get a byte-for-byte identical SHA-256 — see
[release.yml](../../.github/workflows/release.yml).

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

Your node's data — its config, identity, and saved state — lives in a separate
folder set by your operating system. If you want to wipe that too, run
`veil-cli config locate` to see exactly where it is.

---

## Build from source

You only need this if there's no ready-made binary for your platform (for
example **Intel macOS**), or if you want to work on the code. The default build
pulls in **BoringSSL (`tls-boring`)** and **RocksDB (`rocksdb-cold`)**, both
written in C/C++, so you'll need a C/C++ toolchain to compile them:

```sh
# Debian/Ubuntu prerequisites for the default (BoringSSL + RocksDB) build:
sudo apt-get install -y cmake golang-go nasm ninja-build build-essential

git clone https://github.com/veilnetwork/veil
cd veil
cargo build --release --bin veil-cli --bin ogate --bin oproxy-client --bin oproxy-server \
  --features veil-bootstrap/production-seeds
# binaries land in target/release/
```

For signed, reproducible release builds — ones anyone can rebuild and get the
exact same bytes — use `scripts/build-release.sh --target <triple>`. To build a
static Linux binary on a macOS machine, see `scripts/cross-build-linux-musl.sh`.

---

## Supported platforms

We publish ready-made binaries for these targets (each named by its *triple* —
the CPU + OS + libc combination it's built for):

| Triple | Notes |
|--------|-------|
| `x86_64-unknown-linux-musl` | **default for Linux x86_64** — static, runs on any distro |
| `x86_64-unknown-linux-gnu` | glibc build (`--libc gnu`) |
| `aarch64-unknown-linux-gnu` | ARM64 Linux |
| `aarch64-apple-darwin` | Apple Silicon macOS |
| `x86_64-pc-windows-msvc` | Windows 10/11 (x64) |

There's no ready-made binary for Intel macOS (`x86_64-apple-darwin`) or ARM64
Windows. On those, [build from source](#build-from-source) or run the x64 build
under emulation.

---

## Is `curl … | sh` safe?

Piping a script straight into your shell makes some people nervous, and that's
fair. Here's what this one actually does: it downloads over HTTPS (TLS 1.2 or
newer, so the connection is encrypted), checks every binary's SHA-256 before
installing, never asks for root in the default per-user install, and only
touches `~/.veil` plus the one `PATH` line it adds to your shell profile. If
you'd rather read it first, download it and look before you run it:

```sh
curl -fsSLO https://raw.githubusercontent.com/veilnetwork/veil/main/scripts/install.sh
less install.sh        # review
sh install.sh
```
