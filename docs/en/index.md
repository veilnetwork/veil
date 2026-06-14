# Veil Documentation (OVL1)

Veil is a decentralized hybrid open-source network written in Rust, implementing the OVL1 protocol.

## Sections

| Document | Audience | Contents |
|----------|----------|------------|
| [**Start here — plain language**](start-here.md) | Newcomers | What Veil is and why, a glossary of every term, and your first ten minutes |
| [**Installation & first node**](install.md) | Everyone | Installing with `curl … \| sh` or PowerShell, what the pieces are, running a client or server node, a quick start for ogate and oproxy, and how to uninstall |
| [**How the network works (tour)**](HOW_IT_WORKS.md) | Engineers new to the project | A guided tour with diagrams — the stack, identities, sessions, how messages are routed, and the mailbox |
| [User Guide](user-guide.md) | Everyday users | What OVL1 is, how to install it, a quick start, and the commands you'll use day to day |
| [**oproxy (SOCKS5/HTTP → veil)**](oproxy.md) | Proxy operators | Setting it up, choosing per-destination how traffic goes (through veil, straight out, or blocked), and what happens if veil can't reach a target |
| [**ogate (TUN-bridge → veil)**](ogate.md) | Private-network operators | Joining machines into one private network over veil; the `[runtime]` and `[logging]` settings |
| [Administrator Guide](admin-guide.md) | System administrators | Configuration, transports, keys, metrics, and day-to-day administration |
| [Configuration Reference](config-reference.md) | Operators | Every config key, role, transport, and default explained |
| [Operations](OPERATIONS.md) | Operators | Building, running, and operating a node day to day |
| [Monitoring](MONITORING.md) | Operators | Metrics, dashboards, and what to watch |
| [Troubleshooting](TROUBLESHOOTING.md) | Operators | Diagnosing and fixing common problems |
| [P-Net (private networks)](p-net.md) | Private-network operators | Building isolated private networks over veil |
| [Identity Model](identity-model.md) | Everyone | Sovereign identity: master keys, delegations, and auto-reissue |
| [Multi-Device](multi-device.md) | Everyday users | Running one identity across devices; LB vs messenger modes and privacy trade-offs |
| [Recovery](recovery.md) | Everyday users | Compromise recovery, device loss, and BIP39 best practices |
| [OpSec User Guide](opsec-user-guide.md) | Everyday users | Physical-security checklist and phishing warnings |
| [Protocol Specification](protocol-spec.md) | Protocol developers, integrators | The on-the-wire format, how it works, the cryptography, and the roles a node can play |
| [Full Architecture](ARCHITECTURE_FULL.md) | All technical roles | How the network is built, traced through the code: layers, modules, and constants |
| [Wire Protocol](WIRE_PROTOCOL.md) | Client implementers | A field-by-field reference for the header, the message families, and their payloads |
| [Network Model](NETWORK.md) | Getting oriented | The big picture: nodes, the handshake, how messages get delivered, and the DHT |
| [Architecture (brief)](ARCHITECTURE.md) | Getting oriented | A one-page overview of the layers, roles, and subsystems |
| [Security Model](SECURITY.md) | Auditors, security engineers | What we defend against, the cryptography, and the risks we already know about |
| [Developer Guide](developer-guide.md) | Project developers | The architecture, the pieces and how they fit together, and the rules for extending it |
| [Crate Architecture](CRATE_ARCHITECTURE.md) | Project developers | How the workspace crates are split and what each one owns |
| [Capacity](CAPACITY.md) | Operators, engineers | Capacity planning: limits, budgets, and scaling characteristics |
| [Contracts](CONTRACTS.md) | Project developers | Cross-module contracts and invariants that callers rely on |

## Additional Materials

- [Architectural invariants](../architecture/foundation.md) — foundational decisions that are not revisited
- [RFC-0001: Hybrid architecture](../rfcs/0001-hybrid-veil-architecture.md)
- [Specification (original, RU)](../../specification.md)

## Protocol Version

Current OVL1 version: **v1** (magic `0x4F564C31`, version byte `0x01`).

IPC protocol: version **1** (`IPC_PROTOCOL_VERSION = 1`).
