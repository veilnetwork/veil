# Ansible playbooks for veil network

Playbooks for deploying and operating veil nodes.

## Playbook overview

| Playbook | Purpose |
|---|---|
| `deploy-node.yml` | Initial install of veil onto a Debian/Ubuntu/RHEL host (config + service + cert). |
| `deploy-bootstrap.yml` | Same but for bootstrap nodes (b1/b2/b3). |
| `deploy-binary-only.yml` | Roll out a new `/usr/local/bin/veil-cli` binary, preserving config. `serial: 1` rolling restart. |
| `deploy-chat.yml` | Spawn `chat_node` mesh-load workers. Requires `/tmp/testnet-configs/manifest.json` (host → node_id map). |
| `deploy-chaos-ban.yml` | Install `chaos-ban-cycler.service` for stress-testing handshake/auto-ban paths. |
| `deploy-logrotate.yml` | Install logrotate config for `/var/log/veil/*.log`. |
| `deploy-pnet.yml` | **P-Net rollout** — copies a membership cert + adds `[network]` config block + restarts in private mode. See [`docs/en/p-net.md`](../docs/en/p-net.md) or [`docs/ru/p-net.md`](../docs/ru/p-net.md). |
| `revert-pnet.yml` | **P-Net rollback** — removes cert + `[network]` block + restarts in public mode. Inverse of `deploy-pnet.yml`. |
| `deploy-ogate.yml` | **ogate rollout** — TUN-based virtual LAN over the veil. Renders per-host `/etc/ogate/ogate.toml` from `manifest.json` + an in-playbook IP map, installs binary + systemd unit, rolling `serial: 1`. See [`docs/en/ogate.md`](../docs/en/ogate.md) / [`docs/ru/ogate.md`](../docs/ru/ogate.md). |
| `remove-chat.yml` | Stop + disable + remove `chat-node` service + config (inverse of `deploy-chat.yml`; leaves binary). |
| `remove-chaos-ban.yml` | Stop + disable + remove `chaos-ban` service + cycler script (inverse of `deploy-chaos-ban.yml`). |
| `deploy-testnet.yml` | One-shot full testnet build (config + bootstrap + nodes). |

## Prerequisites

- Ansible 2.14+
- `community.docker` collection: `ansible-galaxy collection install community.docker`
- Target hosts: Debian/Ubuntu or RHEL/CentOS/Fedora with SSH access and sudo
- DNS A records pointing to each host's public IP
- Port 80 free for Let's Encrypt HTTP-01 challenge

## Inventory

Edit `inventory.yml`:

```yaml
all:
  children:
    bootstrap:
      hosts:
        b1:
          ansible_host: 203.0.113.10
          veil_host: b1.example.com
          veil_email: admin@example.com

    nodes:
      hosts:
        n1:
          ansible_host: 203.0.113.20
          veil_host: n1.example.com
          veil_email: admin@example.com
          veil_bootstrap_peers:
            - transport: "tls://b1.example.com:9906"
              public_key: "MCowBQYDK2Vw..."
              nonce: "AAAA..."
              algo: "ed25519"
```

## Deploy bootstrap node

```bash
ansible-playbook -i inventory.yml deploy-bootstrap.yml
```

After deploy, grab the `bootstrap_peers` snippet from the output and paste it
into the `veil_bootstrap_peers` list of each node in inventory.

## Deploy regular nodes

```bash
ansible-playbook -i inventory.yml deploy-node.yml
```

## Ports

| Port | Proto | Service |
|------|-------|---------|
| 80 | TCP | Let's Encrypt HTTP-01 (certbot) |
| 5555 | TCP | Veil plain TCP |
| 9906 | TCP | Veil TLS |
| 8443 | TCP | Veil WSS |
| 8443 | UDP | Veil QUIC |
| 6666 | UDP | Mesh beacon |
| 19999 | TCP | Prometheus metrics (`/metrics`) |

## Metrics

Every node exposes Prometheus metrics at `http://<host>:19999/metrics`.
Add to your Prometheus `scrape_configs`:

```yaml
- job_name: veil
  static_configs:
    - targets:
        - b1.example.com:19999
        - n1.example.com:19999
```

## Overriding defaults

Set per-host or in `group_vars/all.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `veil_image` | `veilnetwork/veil:latest` | Docker Hub image |
| `veil_role` | `core` | Node role (`core` or `leaf`) |
| `veil_difficulty` | `24` | PoW difficulty bits |
| `tcp_port` | `5555` | Plain TCP port |
| `tls_port` | `9906` | TLS port |
| `quic_port` | `8443` | QUIC (UDP) port |
| `wss_port` | `8443` | WSS (TCP) port |
| `mesh_udp_port` | `6666` | Mesh beacon port |
| `metrics_port` | `19999` | Prometheus metrics port |
| `veil_staging` | `false` | Use Let's Encrypt staging |

## Updating

To pull a new image and restart:

```bash
ansible-playbook -i inventory.yml deploy-bootstrap.yml
ansible-playbook -i inventory.yml deploy-node.yml
```

The playbooks always pull the latest image before starting.
