# User Guide

## What is Veil (OVL1)?

**Veil** is a decentralized P2P network with cryptographic addressing. Each node in the network is identified by a 32-byte `node_id = BLAKE3(public_key)` — the address does not depend on IP, location, or transport. Applications communicate via veil addresses, and the network itself finds delivery paths.

What OVL1 can do:

- **Message delivery** between nodes through arbitrary intermediate nodes (relay)
- **Mailbox** — storing messages for offline recipients on gateway nodes
- **DHT** (distributed hash table, Kademlia) — node lookup, resource publication
- **Names** — human-readable identifiers with a Proof-of-Work binding to a node
- **Streaming** — bidirectional streams with window control (analogous to TCP over veil)
- **E2E encryption** — message contents are hidden even from relay nodes (ML-KEM + ChaCha20-Poly1305)
- **Local network** — UDP mesh-broadcast for discovering neighbors within a single segment

---

## Installation

The fast path — prebuilt, sha256-verified binaries, no Rust toolchain needed:

**Linux / macOS:**

```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/veilnetwork/veil/master/scripts/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/veilnetwork/veil/master/scripts/install.ps1 | iex
```

This installs `veil-cli` into `~/.veil/bin` (`%USERPROFILE%\.veil\bin` on Windows). Add `--all` to also install `ogate` and the `oproxy` client/server. Components, options, server setup, and uninstall are covered in **[Installation & first node](install.md)**.

> **Windows note:** the node uses TCP loopback for the admin protocol. Unix-specific conveniences (SIGHUP reload, Unix domain sockets) are unavailable, but the admin CLI, the main veil traffic, and foreground mode all work. Set `global.admin_socket = "tcp://127.0.0.1:0"`; the node picks a port from the kernel and writes `admin.port`/`admin.token` to `runtime_dir`, and clients read them when connecting.

### Building from source

Only needed for platforms without a prebuilt binary (e.g. Intel macOS) or for development. The default build links BoringSSL (`tls-boring`) + RocksDB (`rocksdb-cold`), so a C/C++ toolchain is required:

```bash
# Debian/Ubuntu prerequisites:
sudo apt-get install -y cmake golang-go nasm ninja-build build-essential

git clone https://github.com/veilnetwork/veil
cd veil
cargo build --release --features veil-bootstrap/production-seeds
# Binaries: target/release/{veil-cli,ogate,oproxy-client,oproxy-server}
cp target/release/veil-cli ~/.local/bin/
```

See [Installation → Build from source](install.md#build-from-source) for the full matrix.

---

## Quick start

### 1. Create a configuration

```bash
veil-cli config init
```

The command creates `~/.config/veil/config.toml` (the path depends on the OS) and **mines a PoW nonce** for the identity — this may take a few seconds. The nonce protects against node_id collisions.

See where the config is located:

```bash
veil-cli config locate
```

Display the current configuration:

```bash
veil-cli config show
```

### 2. Start the node

```bash
veil-cli node run
```

The node starts in the background. Check its state:

```bash
veil-cli node show
veil-cli node health
```

### 3. View your node_id

```bash
veil-cli node show
```

Example output:

```
node_id:  a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
role:     leaf
listeners: 0
peers:    1 connected
```

### 4. Connect to a known peer

Add a peer to the configuration:

```bash
# PUBLIC_KEY, NONCE, and TRANSPORT are positional arguments
veil-cli peers add \
  --algo ed25519 \
  BASE64_PUBKEY \
  BASE64_POW_NONCE \
  "tls://gateway.example.com:9443"
```

Restart the node:

```bash
veil-cli node restart
```

### 5. Stop the node

```bash
veil-cli node stop
```

---

## CLI — command reference

### `veil-cli config`

| Command | Description |
|---------|----------|
| `config init [PATH]` | Create a config with a new identity and PoW nonce |
| `config init --difficulty N` | Set the PoW difficulty for the generated identity (default `16`; use `24` or higher for production / public nodes) |
| `config init --force` | Overwrite an existing config |
| `config show` | Print the current config (private_key is hidden) |
| `config validate` | Check the config for errors |
| `config validate --fix` | Attempt to fix the errors found |
| `config locate` | Show the path to the config file |
| `config get KEY` | Get the value for a key (for example, `identity.algo`) |
| `config set KEY VALUE` | Set a value |

### `veil-cli key`

| Command | Description |
|---------|----------|
| `key gen` | Generate a new key pair (Ed25519 or Falcon512) |
| `key gen --algo falcon512` | Use the post-quantum algorithm |

### `veil-cli node`

| Command | Description |
|---------|----------|
| `node run` | Start the node |
| `-c PATH node run` | Start with a non-default config (the global `-c`/`--config` flag goes **before** the subcommand) |
| `node stop` | Gracefully stop the node |
| `node restart` | Restart (stop + run) |
| `node show` | Show a summary (node_id, role, sessions) |
| `node health` | Check the liveness of the event loop and the number of sessions |

### `veil-cli listen`

| Command | Description |
|---------|----------|
| `listen add tcp://0.0.0.0:9000` | Add a listener to the config (TRANSPORT is a positional URI; there are `--advertise`/`--relay` options) |
| `listen del LISTEN_ID` | Remove a listener (the ID is positional) |
| `listen list` | List active listeners |

### `veil-cli peers`

| Command | Description |
|---------|----------|
| `peers add [--algo ALGO] PUBLIC_KEY NONCE TRANSPORT [--alt-uri URI]` | Add a peer (PUBLIC_KEY, NONCE, TRANSPORT are positional) |
| `peers del PEER_ID` | Remove a peer from the config (the ID is positional) |
| `peers list` | List the configured peers |

### `veil-cli sessions`

| Command | Description |
|---------|----------|
| `sessions list` | Active OVL1 sessions (peer node_id, role, RTT) |
| `sessions stats` | Aggregated session statistics |

### `veil-cli debug`

| Command | Description |
|---------|----------|
| `debug ping NODE_ID [--count N] [--interval MS] [--timeout MS]` | Veil ping to a node_id (64 hex chars) |
| `debug trace TARGET [--max-hops N]` | Traceroute across the veil network |
| `debug capture [--node-id HEX] [--family N] [--limit N]` | Capture frames for debugging |

`debug ping` / `debug trace` take a 64-character hex `NODE_ID` only. To reach a node by `@name`, resolve it first with `node resolve-name` (see [Names](#names-name-system)).

---

## Names (Name System)

OVL1 supports human-readable names bound to a sovereign identity via PoW. Names belong to the `identity` branch (there is no separate `name` command), and `@name` resolution is performed via `node resolve-name`.

### Claim a name

```bash
veil-cli identity claim-name alice
```

The name is a positional argument; it is normalized to lowercase ASCII (only the characters `[a-z0-9#_-]` are allowed). The command mines a PoW nonce proportional to the rarity of the name, signs a `NameClaim` with the active `identity_sk`, and saves it to `<veil_dir>/name_claims/<name>.bin`. A running daemon publishes the claim to the DHT at the next republish tick (once every 6 hours) or on restart.

The `--veil-dir PATH` option overrides the identity directory (by default `~/.config/veil` or `$VEIL_IDENTITY_DIR`).

### Resolve a name

```bash
veil-cli node resolve-name @alice
```

Accepts both `alice` and `@alice`. It resolves the chain `NameClaim` → `IdentityDocument` with full verification (PoW difficulty, freshness-hour tolerance, and verification of the name binding to the signature of the document's active subkey). The `--timeout-ms N` option limits the total resolution time (5000 by default).

### DHT key of a name

Compute the DHT key under which the `NameClaim` for a given name is published (without network I/O):

```bash
veil-cli identity name-dht-key alice
```

---

## Use from an application (IPC)

If you are writing an application that should work over the veil network:

1. Enable IPC in the config:

```toml
[ipc]
enabled = true
socket_uri = "unix:///home/user/.veil/app.sock"
```

The key is called `socket_uri` and accepts a URI (`unix:///abs/path` on Linux/macOS or `tcp://127.0.0.1:0?runtime_dir=/abs/path` on Windows), not a file path. The tilde `~` in the URI is not expanded — specify an absolute path. If `socket_uri` is not set, on Unix the daemon uses `~/.veil/app.sock` by default.

2. Connect to the socket and perform the handshake:

```python
# Example in Python (simplified)
import socket, struct, json

sock = socket.socket(socket.AF_UNIX)
sock.connect("/home/user/.veil/app.sock")

def send_msg(s, obj):
    body = json.dumps(obj).encode()
    s.sendall(struct.pack(">I", len(body)) + body)

def recv_msg(s):
    n = struct.unpack(">I", s.recv(4))[0]
    return json.loads(s.recv(n))

send_msg(sock, {"command": "hello", "version": 1})
resp = recv_msg(sock)  # {"command": "hello_ok"}

send_msg(sock, {
    "command": "bind",
    "namespace": "myapp",
    "app_name": "main",
    "endpoint_id": 1
})
resp = recv_msg(sock)  # {"command": "bind_ok", "app_id": "...hex..."}
```

For more on the IPC protocol, see the [Protocol Specification](protocol-spec.md#9-ipc-protocol-localapp-family-6).

---

## Typical usage scenarios

### Peer-to-peer messenger

1. Both nodes know each other's node_id (or the names `@alice`, `@bob`)
2. The application opens a `StreamOpen` → receives a bidirectional stream
3. Data is encrypted E2E (ML-KEM + ChaCha20-Poly1305)
4. If the recipient is offline, the message is stored in a mailbox on a gateway

### Publishing a resource to the DHT

Via IPC or the admin API:
```bash
veil-cli node dht put HEX_KEY HEX_VALUE
```

### Network monitoring

```bash
veil-cli sessions list     # Active connections
veil-cli node routes       # Known routes (route cache)
veil-cli node dht list     # Local DHT storage
veil-cli node metrics      # Frame, session, and delivery counters
```
