# Архитектура veil-сети

> Для исчерпывающего source-level walkthrough'а см. [ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md).

## Слои

```
Application Layer     App ←→ IPC ←→ AppEndpointRegistry
                         ↓
Dispatch Layer        FrameDispatcher (family switch)
                      ├── Session    (Hello..SessionConfirm, Keepalive, Rekey, Ticket)
                      ├── Control    (Ping/Pong, NatProbe*, Backpressure, Epidemic)
                      ├── Discovery  (FindNode, FindValue, Store, Delete, Attachment)
                      ├── Delivery   (Forward, Mailbox, Transit, RecursiveRelay, Chunks)
                      ├── Routing    (RouteAnnounce/Withdraw, RouteRequest, PoW bootstrap)
                      ├── App        (AppOpen, AppData, AppRtData, AppReceipt)
                      ├── Mesh       (MeshBeacon, MeshForward, MeshAck)
                      ├── PeerExchange (Walk, Challenge, Response, Result)
                      ├── Tunnel     (IpPacket — TUN/TAP)
                      ├── RelayChain (onion hop)
                      └── Diag       (DiagPing/Pong, TraceProbe/Hop)
                         ↓
Session Layer         SessionRunner (AEAD encrypt/decrypt, WRR scheduling, rekey)
                         ↓
Transport Layer       TCP / TLS / QUIC / WebSocket (ws,wss) / Unix / SOCKS5
```

## Роли узлов

| Роль | DHT | Relay | Mailbox | Gateway | Сценарий |
|------|-----|-------|---------|---------|----------|
| Leaf | - | - | - | - | Мобильные клиенты, IoT, лёгкие клиенты |
| Core | да (K=20) | да | да | да (опционально) | Полноценный участник сети |

Все Core-узлы равноправны: DHT, relay/forwarding, mailbox, PoW ≥ 24 бит.
Gateway-функциональность (attachment records для leaf-узлов) включается флагом `CAN_GATEWAY_LOCAL_MESH`
в capabilities; конфигурируется через `[gateway] enabled = false`.
Legacy-роли `Relay / Gateway / CoreRouter` не входят в протокол — в сети ровно
две роли.

## Поток данных: доставка сообщений

```
Sender App
  → DELIVERY_FORWARD
    → Cache hit в route cache?  ──да──→ Forward к next_hop через SessionTxRegistry
    │                                    → ... → Recipient App
    │
    └──нет (cache miss)──→ RecursiveRelay через DHT
                           → find_closest_nodes(dst, 3)
                           → Forward к XOR-closest peer
                           → На каждом hop'е: есть live session к dst? → доставка
                           → Hop exhausted? → Mailbox fallback
```

## Маршрутизация

- **Gossip**: ROUTE_ANNOUNCE с TTL=2 (только локальные соседи)
- **DHT forwarding**: RecursiveRelay O(log N) hop'ов через Kademlia closest nodes
- **Route cache**: TTL-based, адаптивная ёмкость, reverse path caching
- **Scoring**: RTT + Vivaldi + jitter + congestion + battery

## Слои безопасности

1. **Identity**: Ed25519 **или** Falcon-512 signing key + PoW mining (24+ бит, адаптивно)
2. **Handshake**: X25519 + ML-KEM-768 гибридный key exchange
3. **Session**: per-frame шифрование ChaCha20-Poly1305 AEAD (rekey на 128 GiB, 32 дня или wrap'е nonce-counter'а — конфигурируется)
4. **E2E**: ML-KEM-768 encapsulation для непрозрачного для relay'я payload'а (маркеры `0xE2`/`0xE3`)
5. **Anti-abuse**: per-IP session limit (32) → PoW challenge → rate limiter → violation tracker → ban list
6. **Reputation**: uptime + relay success + peer vouches; transit gate 200 points
7. **DHT ownership**: подписанный STORE; подписанный DELETE с BLAKE3(pk)==key

## Threading-модель

- **Tokio runtime**: весь async I/O, управление сессиями, периодические задачи
- **Shared state**: `Arc<Mutex<_>>` для кэшей, `Arc<AtomicU64>` для счётчиков
- **Без вложенных lock'ов**: single-lock-at-a-time соглашение предотвращает deadlock'и
- **Dispatcher**: синхронный dispatch на `FrameHeader` → `DispatchResult` (никакого async в hot path)

## Ключевые подсистемы

| Подсистема | Модуль | Назначение |
|-----------|--------|------------|
| Kademlia DHT | `node/dht/` | Распределённая хэш-таблица, iterative lookup, store/find |
| Mailbox | `node/mailbox/` | Хранение offline-сообщений, WAL-персистентность, шардированные реплики |
| Route Cache | `node/routing/` | Next-hop lookup, multi-path scoring, адаптивная ёмкость |
| Session | `node/session/` | AEAD-сессии, TX registry, WRR scheduling, hibernate |
| Discovery | `node/discovery/` | Attachment records, app endpoints, name service |
| Mesh | `node/mesh/` | UDP beacon, локальное обнаружение, gateway bridge |
| NAT | `node/nat/` | Hole punching, relay-туннели, observed address |
| Transport | `transport/` | TCP, TLS, QUIC, WebSocket, SOCKS5, fingerprint |
| Congestion | `node/congestion.rs` | Real-time мониторинг нагрузки, backpressure (>78% → drop transit) |
| Reputation | `node/reputation.rs` | Per-peer trust score, transit gate |
| Memory | `node/memory.rs` | Глобальный RAM-бюджет, priority-based eviction |
| Adaptive | `cfg/adaptive.rs` | Оценка размера сети, масштабирование параметров |
