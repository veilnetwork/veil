# Docker bootstrap node with auto-SSL

Turns an empty Linux host with Docker + Docker Compose into a bootstrap
`core` node serving TCP / TLS / QUIC / WSS on standard ports, with
a Let's Encrypt cert issued and auto-renewed by a sibling container.

## Quick start (pre-built image from Docker Hub)

```bash
# 1. Get the compose file + .env template
git clone https://github.com/veilnetwork/veil.git
cd veil

# 2. Configure (at minimum: HOST and EMAIL).  The .env lives NEXT TO the
#    compose file (docker/.env) — Compose v2 resolves `.env` relative to
#    the compose file's directory, not the current working directory.
cp docker/.env.example docker/.env
$EDITOR docker/.env

# 3. Up — pulls the pre-built image from Docker Hub, no build needed
docker compose -f docker/docker-compose.yml up -d

# 4. Watch the logs until veil-bootstrap comes up healthy
docker compose -f docker/docker-compose.yml logs -f veil-bootstrap
```

To use a locally built image instead, set `VEIL_IMAGE=veil-bootstrap:local`
in `docker/.env` and build first:

```bash
docker build -t veil-bootstrap:local -f docker/Dockerfile .
```

Alternative: run from inside `docker/` (compose finds `.env` automatically):

```bash
cd docker
cp .env.example .env
$EDITOR .env
docker compose up -d
```

If you already have `.env` in the repo root and don't want to duplicate it,
point Compose at it explicitly:

```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d
```

The `certbot` container issues the cert first (HTTP-01 challenge on port 80),
then `veil-bootstrap` starts, generates an identity + config, and begins
serving veil traffic.

## Required before `up`

* **DNS A record** for `${HOST}` pointing at this host's public IP.  Let's
  Encrypt refuses to issue otherwise.
* **Port 80 free** on the host — certbot binds it temporarily for the
  HTTP-01 challenge + renewals.
* **Ports 5555/tcp, 9906/tcp, 8443/tcp, 8443/udp, 6666/udp** reachable
  from peers (open in firewall / security group).

## Default port layout

| Host port | Proto | Listener URI |
| --- | --- | --- |
| 5555 | TCP | `tcp://${HOST}:5555` |
| 9906 | TCP (TLS) | `tls://${HOST}:9906` |
| 8443 | TCP (WSS) | `wss://${HOST}:8443/veil` |
| 8443 | UDP (QUIC) | `quic://${HOST}:8443` |
| 6666 | UDP | mesh beacon (local-LAN autodiscovery) |

WSS (TCP 8443) and QUIC (UDP 8443) coexist on the same port number because
they use different transport protocols — no conflict.

## Overriding defaults

Every port / role / difficulty is an env var in `.env`:

```
ROLE=core              # or leaf
DIFFICULTY=24          # PoW difficulty bits (≥24 for core)
TCP_PORT=5555
TLS_PORT=9906
QUIC_PORT=8443
WSS_PORT=8443
MESH_UDP_PORT=6666
```

For the very first run it's safer to use Let's Encrypt's **staging**
endpoint (no rate limits if you have DNS / firewall issues):

```
STAGING=1
```

Remove `STAGING=1` once the setup works and `docker compose restart certbot`
to get a real cert.

## Sharing the advertisement

On first boot, `entrypoint.sh` prints the TOML snippet other operators paste
into their `config.toml`:

```
docker compose logs veil-bootstrap | grep -A12 "bootstrap_peers snippet"
```

Example output:

```toml
[[bootstrap_peers]]
transport  = "tls://bootstrap.example.com:9906"
public_key = "..."
nonce      = "..."
algo       = "ed25519"
```

You can also use QUIC / WSS / plain TCP instead of TLS — the identity is
the same, only the transport URI differs.  Distribute whichever makes sense
for your client mix.

## Day-to-day operations

```bash
# Runtime summary (node_id, uptime, session count, …)
docker compose exec veil-bootstrap /usr/local/bin/entrypoint.sh show

# Any veil-cli subcommand
docker compose exec veil-bootstrap /usr/local/bin/entrypoint.sh cli node metrics
docker compose exec veil-bootstrap /usr/local/bin/entrypoint.sh cli listen list
docker compose exec veil-bootstrap /usr/local/bin/entrypoint.sh cli config validate

# Config reload without restart (SIGHUP equivalent)
docker compose exec veil-bootstrap /usr/local/bin/entrypoint.sh cli node reload

# Tail logs
docker compose logs -f veil-bootstrap

# Force cert renewal (normally automatic every 12 h)
docker compose exec certbot certbot renew --standalone --force-renewal
```

## Persisted state

Two named Docker volumes survive container recreation:

| Volume | Holds |
| --- | --- |
| `letsencrypt` | `/etc/letsencrypt` — Let's Encrypt private keys + cert chain |
| `veil-data` | `/var/lib/veil` — identity, PoW nonce, DHT snapshot, peer pubkeys, RTT table |

**Back these up.** Losing `veil-data` means losing the node identity —
all peers currently pointing at this bootstrap will have to re-learn the
new public_key + nonce.  Losing `letsencrypt` means next `certbot renew`
will issue a fresh cert (not breaking — peers don't pin the Let's Encrypt
intermediate).

Example backup:

```bash
docker run --rm -v veil_veil-data:/data -v "$PWD":/backup \
    alpine tar czf /backup/veil-data.tgz -C / data
```

## Tear-down

```bash
# Stop + remove containers, keep volumes
docker compose -f docker/docker-compose.yml down

# Wipe everything (identity + cert + persist snapshots)
docker compose -f docker/docker-compose.yml down -v
```

## Building & publishing multi-arch images

The `build-multiarch.sh` script uses `docker buildx` to build for multiple
architectures (amd64 + arm64 by default) and push to Docker Hub:

```bash
# First time: log in to Docker Hub
docker login

# Build + push :latest for amd64 + arm64
./docker/build-multiarch.sh

# Build + push a tagged release
./docker/build-multiarch.sh v0.1.0

# Override the repo name
REPO=veilnetwork/veil ./docker/build-multiarch.sh v0.1.0

# Build only amd64, load locally (no push)
PUSH=0 PLATFORMS=linux/amd64 ./docker/build-multiarch.sh
```

The script creates a `docker-container` buildx builder automatically if one
doesn't exist.

## Production hardening (out of scope for this compose)

* Use `production-seeds` build: populate `builtin_seeds()` in
  `crates/veil-bootstrap/src/seeds.rs` with your own signed seed set
  and rebuild with `CARGO_FEATURES=production-seeds`.
* Run behind a proper reverse proxy / CDN for WSS traffic analysis
  resistance.
* Mount `veil-data` on an encrypted volume so the private identity
  material isn't plaintext on disk.
* Monitor `node metrics` via Prometheus instead of `docker compose logs`.
* Keep the host NTP-synced — session TTL checks assume monotonic clock
  discipline across the network.
