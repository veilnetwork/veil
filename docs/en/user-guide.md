# User Guide

## What is Veil (OVL1)?

**Veil** is a peer-to-peer network: there's no central server, just many equal computers — **nodes** — passing traffic for each other. Every node has an address built from its cryptographic key, written `node_id = BLAKE3(public_key)`. (BLAKE3 is just a fast hash function — a one-way recipe that turns the key into a short, fixed-size fingerprint.) That address is 32 bytes long and never changes: it doesn't depend on your IP, your location, or how you connect. Apps talk to a veil address, and the network figures out how to deliver the bytes.

OVL1 is the name of Veil's protocol — the shared set of rules every node speaks. Here's what it gives you:

- **Message delivery** between nodes, hopping through other nodes along the way (each forwarding node is a **relay**)
- **Mailbox** — when the person you're writing to is offline, their messages wait for them on a gateway node
- **DHT** — a shared address book spread across all nodes (a *distributed hash table*, using the Kademlia design). Use it to find nodes and to publish things others can look up.
- **Names** — readable handles like `@alice` instead of long hex addresses, tied to a node by a small proof-of-work puzzle
- **Streaming** — two-way data streams with flow control, much like TCP but running over Veil
- **End-to-end encryption** — only you and the recipient can read a message; the relays in between see only scrambled bytes (sealed with ML-KEM + ChaCha20-Poly1305, modern encryption built to resist even future quantum computers)
- **Local network** — a quick UDP broadcast on your LAN to find neighbors on the same network segment

---

## Installation

The fast path: grab a ready-made build. The script downloads a prebuilt program, checks its sha256 fingerprint so you know it wasn't tampered with, and installs it — no compiler or Rust setup required.

**Linux / macOS:**

```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://raw.githubusercontent.com/veilnetwork/veil/main/scripts/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/veilnetwork/veil/main/scripts/install.ps1 | iex
```

This puts `veil-cli` into `~/.veil/bin` (`%USERPROFILE%\.veil\bin` on Windows). Add `--all` to install `ogate` and the `oproxy` client and server too. For the full list of components, options, server setup, and how to uninstall, see **[Installation & first node](install.md)**.

> **Windows note:** on Windows the node talks to the admin CLI over a local TCP connection. A couple of Unix-only conveniences are missing (reloading the config with a SIGHUP signal, and Unix domain sockets), but everything that matters works: the admin CLI, your regular Veil traffic, and running the node in the foreground. Set `global.admin_socket = "tcp://127.0.0.1:0"`; the node lets the operating system pick a free port, writes `admin.port` and `admin.token` into `runtime_dir`, and clients read those when they connect.

### Building from source

You only need this on platforms with no ready-made build (Intel macOS, say), or if you're developing Veil itself. The default build links in two C/C++ libraries — BoringSSL (`tls-boring`) for encryption and RocksDB (`rocksdb-cold`) for storage — so you'll need a C/C++ compiler installed:

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

This writes a config file at `~/.config/veil/config.toml` (the exact path depends on your operating system) and creates your identity — the key pair that *is* your node. As part of that it solves a small proof-of-work puzzle: it searches for a special number (a **nonce**) that makes the puzzle check out. This takes a few seconds of CPU time. The point is to make it costly to mint huge batches of fake identities, so two nodes don't end up fighting over the same address.

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

The node starts up and keeps running in the background. Check how it's doing:

```bash
veil-cli node show
veil-cli node health
```

### 3. View your node_id

Your `node_id` is your address on the network — share it so others can reach you.

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

Here `role: leaf` means your node reaches out to the network but isn't publicly reachable — the right setup for a laptop or phone behind a home router. (A node with a public address others can connect to is a *relay*.) `peers` is how many other nodes you're connected to directly.

### 4. Connect to a known peer

A **peer** is another node yours talks to directly. To connect to one, add it to your config — you'll need its public key, its proof-of-work nonce, and a transport address telling Veil how to reach it:

```bash
# PUBLIC_KEY, NONCE, and TRANSPORT are positional arguments
veil-cli peers add \
  --algo ed25519 \
  BASE64_PUBKEY \
  BASE64_POW_NONCE \
  "tls://gateway.example.com:9443"
```

Restart the node so it picks up the change:

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
| `config init --difficulty N` | Set the PoW difficulty for the generated identity (default `24`; use higher for production / public nodes) |
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
| `node health` | Confirm the node is responsive and report how many sessions are open |

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

### `veil-cli debug`

| Command | Description |
|---------|----------|
| `debug ping NODE_ID [--count N] [--interval MS] [--timeout MS]` | Veil ping to a node_id (64 hex chars) |
| `debug trace TARGET [--max-hops N]` | Traceroute across the veil network |
| `debug capture [--node-id HEX] [--family N] [--limit N]` | Capture frames for debugging |

`debug ping` and `debug trace` only accept a raw `NODE_ID` (64 hex characters). If you have a `@name` instead, turn it into an address first with `node resolve-name` (see [Names](#names-name-system)).

---

## Names (Name System)

A `node_id` is 64 hex characters — fine for a computer, painful for a human. So Veil lets you claim a readable name like `@alice` and bind it to your identity. Nobody can hand out names for you, and nobody can quietly steal yours: a name is locked to your keys, and a small proof-of-work puzzle makes grabbing names in bulk expensive. Names live under the `identity` command (there's no separate `name` command), and you turn a `@name` back into an address with `node resolve-name`.

### Claim a name

```bash
veil-cli identity claim-name alice
```

The name is a positional argument. It's lowercased to plain ASCII, and only the characters `[a-z0-9#_-]` are allowed. The command solves a proof-of-work puzzle — harder for rarer, more desirable names — then signs a `NameClaim` record with your active signing key (`identity_sk`) and saves it to `<veil_dir>/name_claims/<name>.bin`. If your node is running, it announces the claim to the DHT so others can find it: either on restart, or at the next scheduled re-announcement (every 6 hours).

Use `--veil-dir PATH` to point at a different identity directory (the default is `~/.config/veil`, or wherever `$VEIL_IDENTITY_DIR` points).

### Resolve a name

```bash
veil-cli node resolve-name @alice
```

This takes a name and gives you back the address behind it. Both `alice` and `@alice` work. It follows the trail from the `NameClaim` to the full `IdentityDocument` and checks every step — that the proof-of-work is strong enough, that the record is recent, and that the name really is signed by the identity's current key — so you can trust the address you get back. Use `--timeout-ms N` to cap how long resolution may take (5000 ms by default).

### DHT key of a name

Work out the DHT key where a name's `NameClaim` gets stored — purely a local calculation, no network access:

```bash
veil-cli identity name-dht-key alice
```

---

## Use from an application (IPC)

Want your own app to send and receive traffic over Veil? It talks to the local node through IPC (inter-process communication) — a small socket on your own machine that your program connects to. Here's how:

1. Turn IPC on in the config:

```toml
[ipc]
enabled = true
socket_uri = "unix:///home/user/.veil/app.sock"
```

Note the key is `socket_uri`, and it wants a full URI — `unix:///abs/path` on Linux/macOS, or `tcp://127.0.0.1:0?runtime_dir=/abs/path` on Windows — not a plain file path. A `~` in the URI is taken literally, not expanded to your home folder, so write out the absolute path. Leave `socket_uri` unset and, on Unix, the node falls back to `~/.veil/app.sock`.

2. Connect to the socket and do the opening handshake (the short hello-and-acknowledge exchange that sets up the connection):

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

1. Each node knows the other's node_id (or its name, `@alice` or `@bob`)
2. The app sends a `StreamOpen` and gets back a two-way stream to talk over
3. Everything is encrypted end to end (ML-KEM + ChaCha20-Poly1305), so relays in between can't read it
4. If the recipient is offline, the message waits in their mailbox on a gateway until they come back

### Publishing a resource to the DHT

Through IPC, or directly with the admin API:
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
