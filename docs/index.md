# Veil (OVL1) Documentation

> Decentralized hybrid-veil network in Rust implementing the OVL1 protocol.

## Languages

* 🇬🇧 **[English](en/)** — [`en/index.md`](en/index.md)
* 🇷🇺 **[Russian](ru/)** — [`ru/index.md`](ru/index.md)

Some documents exist in only one language for now. Where a translation is
missing, the stub links to the version that does exist and flags it as
pending. Translations are welcome — fill in a stub and open a PR.

## Quick links

| Topic | EN | RU |
|---|---|---|
| **How it works (tour)** | [en/HOW_IT_WORKS.md](en/HOW_IT_WORKS.md) | [ru/HOW_IT_WORKS.md](ru/HOW_IT_WORKS.md) |
| User guide | [en/user-guide.md](en/user-guide.md) | [ru/user-guide.md](ru/user-guide.md) |
| Admin guide | [en/admin-guide.md](en/admin-guide.md) | [ru/admin-guide.md](ru/admin-guide.md) |
| Protocol spec | [en/protocol-spec.md](en/protocol-spec.md) | [ru/protocol-spec.md](ru/protocol-spec.md) |
| Architecture (full) | [en/ARCHITECTURE_FULL.md](en/ARCHITECTURE_FULL.md) | [ru/ARCHITECTURE_FULL.md](ru/ARCHITECTURE_FULL.md) |
| Network topology | [en/NETWORK.md](en/NETWORK.md) | [ru/NETWORK.md](ru/NETWORK.md) |
| Security model | [en/SECURITY.md](en/SECURITY.md) | [ru/SECURITY.md](ru/SECURITY.md) |
| Operations | [en/OPERATIONS.md](en/OPERATIONS.md) | [ru/OPERATIONS.md](ru/OPERATIONS.md) |
| Monitoring | [en/MONITORING.md](en/MONITORING.md) | [ru/MONITORING.md](ru/MONITORING.md) |
| Troubleshooting | [en/TROUBLESHOOTING.md](en/TROUBLESHOOTING.md) | [ru/TROUBLESHOOTING.md](ru/TROUBLESHOOTING.md) |
| **P-Net (private networks)** | [en/p-net.md](en/p-net.md) | [ru/p-net.md](ru/p-net.md) |
| **ogate (TUN-bridge / virtual LAN)** | [en/ogate.md](en/ogate.md) | [ru/ogate.md](ru/ogate.md) |
| **oproxy (SOCKS5/HTTP/TProxy → veil)** | [en/oproxy.md](en/oproxy.md) | [ru/oproxy.md](ru/oproxy.md) |
| Developer guide | [en/developer-guide.md](en/developer-guide.md) | [ru/developer-guide.md](ru/developer-guide.md) |
| Wire protocol | [en/WIRE_PROTOCOL.md](en/WIRE_PROTOCOL.md) | [ru/WIRE_PROTOCOL.md](ru/WIRE_PROTOCOL.md) |
| Crate architecture | [en/CRATE_ARCHITECTURE.md](en/CRATE_ARCHITECTURE.md) | [ru/CRATE_ARCHITECTURE.md](ru/CRATE_ARCHITECTURE.md) |
| Configuration reference | [en/config-reference.md](en/config-reference.md) | [ru/config-reference.md](ru/config-reference.md) |
| Identity model | [en/identity-model.md](en/identity-model.md) | [ru/identity-model.md](ru/identity-model.md) |
| Multi-device | [en/multi-device.md](en/multi-device.md) | [ru/multi-device.md](ru/multi-device.md) |
| Recovery | [en/recovery.md](en/recovery.md) | [ru/recovery.md](ru/recovery.md) |
| OpSec user guide | [en/opsec-user-guide.md](en/opsec-user-guide.md) | [ru/opsec-user-guide.md](ru/opsec-user-guide.md) |
| Capacity | [en/CAPACITY.md](en/CAPACITY.md) | [ru/CAPACITY.md](ru/CAPACITY.md) |
| Contracts | [en/CONTRACTS.md](en/CONTRACTS.md) | [ru/CONTRACTS.md](ru/CONTRACTS.md) |

## Subdirectories

These are language-neutral, or just haven't been split by language yet:

* [`architecture/`](architecture/) — invariant decisions (foundation, mesh)
* [`rfcs/`](rfcs/) — RFC index (`0001-hybrid-veil-architecture`)
* [`grafana/`](grafana/) — Grafana dashboards
* [`store-readiness/`](store-readiness/) — Store / submission readiness

## Adding a new document

When you add a new doc:

1. Pick the primary language — usually English for technical docs,
   either one for operator guides.
2. Put the primary file in `docs/<lang>/<name>.md`.
3. Add a stub in the other language at `docs/<otherlang>/<name>.md` that
   points back to the primary. For example:
   ```markdown
   # <Title> (translation pending)
   >
   > Available version: **[<other lang>](../<otherlang>/<name>.md)**.
   ```
4. Link from `docs/index.md` Quick-links table.

## Protocol version

Current OVL1 protocol: **v1** (magic `0x4F564C31`, version byte `0x01`).
IPC protocol: version **1** (`IPC_PROTOCOL_VERSION = 1`).
