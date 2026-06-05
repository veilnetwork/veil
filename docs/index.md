# Veil (OVL1) Documentation

> Decentralized hybrid-veil network in Rust implementing the OVL1 protocol.

## Languages / Языки

* 🇬🇧 **[English](en/)** — [`en/index.md`](en/index.md)
* 🇷🇺 **[Русский](ru/)** — [`ru/index.md`](ru/index.md)

Some documents are currently available in only one language; the missing
counterpart links to the available version with а translation-pending
notice. Help with translations is welcome — edit the stub and open а PR.

## Quick links / Быстрые ссылки

| Topic | EN | RU |
|---|---|---|
| **How it works (tour) / Как работает сеть** | [en/HOW_IT_WORKS.md](en/HOW_IT_WORKS.md) | [ru/HOW_IT_WORKS.md](ru/HOW_IT_WORKS.md) |
| User guide / Руководство пользователя | [en/user-guide.md](en/user-guide.md) | [ru/user-guide.md](ru/user-guide.md) |
| Admin guide / Руководство администратора | [en/admin-guide.md](en/admin-guide.md) | [ru/admin-guide.md](ru/admin-guide.md) |
| Protocol spec / Спецификация протокола | [en/protocol-spec.md](en/protocol-spec.md) | [ru/protocol-spec.md](ru/protocol-spec.md) |
| Architecture (full) / Полная архитектура | [en/ARCHITECTURE_FULL.md](en/ARCHITECTURE_FULL.md) | [ru/ARCHITECTURE_FULL.md](ru/ARCHITECTURE_FULL.md) |
| Network topology / Сетевая модель | [en/NETWORK.md](en/NETWORK.md) | [ru/NETWORK.md](ru/NETWORK.md) |
| Security model / Модель безопасности | [en/SECURITY.md](en/SECURITY.md) | [ru/SECURITY.md](ru/SECURITY.md) |
| Operations / Operations | [en/OPERATIONS.md](en/OPERATIONS.md) | [ru/OPERATIONS.md](ru/OPERATIONS.md) |
| Monitoring / Мониторинг | [en/MONITORING.md](en/MONITORING.md) | [ru/MONITORING.md](ru/MONITORING.md) |
| Troubleshooting / Поиск неисправностей | [en/TROUBLESHOOTING.md](en/TROUBLESHOOTING.md) | [ru/TROUBLESHOOTING.md](ru/TROUBLESHOOTING.md) |
| **P-Net (private networks)** | [en/p-net.md](en/p-net.md) | [ru/p-net.md](ru/p-net.md) |
| **ogate (TUN-bridge / virtual LAN)** | [en/ogate.md](en/ogate.md) | [ru/ogate.md](ru/ogate.md) |
| **oproxy (SOCKS5/HTTP/TProxy → veil)** | [en/oproxy.md](en/oproxy.md) | [ru/oproxy.md](ru/oproxy.md) |
| Developer guide / Руководство разработчика | [en/developer-guide.md](en/developer-guide.md) | [ru/developer-guide.md](ru/developer-guide.md) |
| Wire protocol / Wire-протокол | [en/WIRE_PROTOCOL.md](en/WIRE_PROTOCOL.md) | [ru/WIRE_PROTOCOL.md](ru/WIRE_PROTOCOL.md) |

## Subdirectories / Подразделы

These are language-neutral or have not been split yet:

* [`architecture/`](architecture/) — invariant decisions (foundation, mesh)
* [`rfcs/`](rfcs/) — RFC index (`0001-hybrid-veil-architecture`)
* [`grafana/`](grafana/) — Grafana dashboards
* [`store-readiness/`](store-readiness/) — Store / submission readiness

## Adding а new document

When creating new documentation:

1. Decide the primary language (usually English for technical docs,
   either for operator guides).
2. Place the primary in `docs/<lang>/<name>.md`.
3. Create а stub in the other language at `docs/<otherlang>/<name>.md`
   pointing to the primary. Example stub:
   ```markdown
   # <Title> (translation pending)
   >
   > Available version: **[<other lang>](../<otherlang>/<name>.md)**.
   ```
4. Link from `docs/index.md` Quick-links table.

## Protocol version

Current OVL1 protocol: **v1** (magic `0x4F564C31`, version byte `0x01`).
IPC protocol: version **1** (`IPC_PROTOCOL_VERSION = 1`).
