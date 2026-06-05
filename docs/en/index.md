# Veil Documentation (OVL1)

Veil is a decentralized hybrid open-source network written in Rust, implementing the OVL1 protocol.

## Sections

| Document | Audience | Contents |
|----------|----------|------------|
| [**Installation & first node**](install.md) | Everyone | `curl … \| sh` / PowerShell install, components, running a client/server node, ogate/oproxy quickstart, uninstall |
| [**How the network works (tour)**](HOW_IT_WORKS.md) | Engineers new to the project | Overview document with diagrams — stack, identity, sessions, routing, mailbox |
| [User Guide](user-guide.md) | End users | What OVL1 is, installation, quick start, using the CLI |
| [**oproxy (SOCKS5/HTTP → veil)**](oproxy.md) | Proxy operators | Config + per-target routing modes (veil/direct/block) + fallback on veil failure |
| [**ogate (TUN-bridge → veil)**](ogate.md) | Virtual LAN operators | Connecting hosts into a virtual LAN through veil; `[runtime]` + `[logging]` |
| [Administrator Guide](admin-guide.md) | System administrators | Configuration, transports, keys, metrics, administration |
| [Protocol Specification](protocol-spec.md) | Protocol developers, integrators | Wire format, mechanisms, cryptography, node roles |
| [Full Architecture](ARCHITECTURE_FULL.md) | All technical roles | Detailed network design by code: layers, modules, constants |
| [Wire Protocol](WIRE_PROTOCOL.md) | Client implementers | Field-level reference for the header, families, and payloads |
| [Network Model](NETWORK.md) | Onboarding | High-level tour of nodes, handshake, delivery, DHT |
| [Architecture (brief)](ARCHITECTURE.md) | Onboarding | One-page overview of layers, roles, and subsystems |
| [Security Model](SECURITY.md) | Auditors, security engineers | Threat model, cryptography, known risks |
| [Developer Guide](developer-guide.md) | Project developers | Architecture, components, their interaction, extension rules |

## Additional Materials

- [Architectural invariants](../architecture/foundation.md) — foundational decisions that are not revisited
- [RFC-0001: Hybrid architecture](../rfcs/0001-hybrid-veil-architecture.md)
- [Specification (original, RU)](../../specification.md)

## Protocol Version

Current OVL1 version: **v1** (magic `0x4F564C31`, version byte `0x01`).

IPC protocol: version **1** (`IPC_PROTOCOL_VERSION = 1`).
