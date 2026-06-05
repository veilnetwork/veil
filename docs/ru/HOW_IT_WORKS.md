# Как работает veil-сеть

Обзорный тур по внутренней архитектуре для инженеров, которые хотят
понять систему до погружения в исходники.

Для исчерпывающего source-level описания:
[ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md) (полный walkthrough),
[NETWORK.md](NETWORK.md) (data-plane focus),
[WIRE_PROTOCOL.md](WIRE_PROTOCOL.md) (byte-level wire format).
English: [HOW_IT_WORKS.md](../en/HOW_IT_WORKS.md).

---

## 1. Что это

Распределённая peer-to-peer veil-сеть: узлы образуют Kademlia DHT,
обмениваются шифрованными сообщениями, автоматически проходят NAT,
fallback в mailbox-хранилище для offline-получателей. End-to-end
шифрование пост-квантовое (ML-KEM-768 + AEAD). Только две роли:

- **Leaf** — телефоны, IoT, лёгкие клиенты. Без DHT, без relay, без
  mailbox. Подключается к одному или нескольким Core-узлам через
  configured peers или local mesh.
- **Core** — полноценный участник. K=20 Kademlia bucket, relay'ит
  для других, хостит mailbox'ы, может работать gateway'ем
  (attachment records для Leaf-узлов).

```
              ┌──────────────────────────────────────┐
              │           CORE VEIL                │
              │                                      │
              │   Core ─── Core ─── Core ─── Core    │
              │     │      ╱  ╲      │       │       │
              │     │    ╱     ╲     │       │       │
              │   Core ─ Core ─ Core ─ Core           │
              │    DHT (Kademlia, K=20)              │
              └────┬──────────────────────────┬──────┘
                   │                          │
              ┌────┴────┐                ┌────┴────┐
              │  Leaf   │                │  Leaf   │
              │ (phone) │                │ (phone) │
              └─────────┘                └─────────┘
                  │                          │
              ┌───┴───┐                  ┌───┴───┐
              │  App  │                  │  App  │
              └───────┘                  └───────┘
```

Leaf-к-Core attachment регистрируется через Discovery
(`AttachmentPayload`), чтобы другие узлы могли маршрутизировать
обратно к Leaf'у.

---

## 2. Стек: слои внутри узла

```
┌──────────────────────────────────────────────────────┐
│   APP                                                │
│   ├─ IPC client (Unix / NamedPipe / TCP loopback)    │
│   └─ Veil client library (veilclient)          │
└────────────────────────┬─────────────────────────────┘
                         │ IPC frames
┌────────────────────────┴─────────────────────────────┐
│   APPLICATION LAYER                                  │
│   ├─ AppEndpointRegistry  (endpoint mailbox channels)│
│   ├─ AppStreamTable       (stream FSM, windowing)    │
│   └─ IPC server           (auth, capability gates)   │
├──────────────────────────────────────────────────────┤
│   DISPATCH LAYER                                     │
│   FrameDispatcher — pure-sync family switch:         │
│   Session, Control, Discovery, Delivery, Routing,    │
│   App, Mesh, PeerExchange, Tunnel, RelayChain, Diag  │
├──────────────────────────────────────────────────────┤
│   SESSION LAYER                                      │
│   ├─ SessionRunner (одна на peer; AEAD + WRR sched)  │
│   ├─ Handshake FSM (Hello→Identity→Caps→KEX→Confirm) │
│   ├─ Keepalive / Rekey / Hot-standby                 │
│   └─ Session TX registry (lock-free fan-out)         │
├──────────────────────────────────────────────────────┤
│   ROUTING / DHT                                      │
│   ├─ KademliaService (K=20, iterative lookup)        │
│   ├─ RouteCache (TTL, multi-path scoring)            │
│   ├─ Discovery (Attachment, AppEndpoint, MailboxRef) │
│   └─ MeshForwarder (UDP beacon, gateway bridge)      │
├──────────────────────────────────────────────────────┤
│   TRANSPORT                                          │
│   TCP / TLS / QUIC / WebSocket (ws,wss) / Unix       │
│   ─ pluggable; per-listener + per-peer overrides ─   │
└──────────────────────────────────────────────────────┘
```

Каждый слой **синхронный** если явно не async — dispatcher
возвращает `DispatchResult` (Response | NoResponse | Violation |
RateLimited) и никогда не await'ит. Весь I/O — в `tokio`-тасках выше
или ниже.

---

## 3. Identity

```
keygen(Ed25519 | Falcon-512)  →  (public_key, private_key)
mine(pk, difficulty=24 bits)  →  nonce
node_id                       =  BLAKE3(public_key)
identity_proof                =  (pk, nonce, sign(pk, nonce))
```

- `node_id` — плоский 256-битный идентификатор; **никакого PKI**,
  никаких domain names.
- Два signature algorithm поддерживаются: **Ed25519** (default,
  быстрый) и **Falcon-512** (post-quantum, ключи больше). Выбор
  per-node, через `[identity] algo`. BLAKE3 сжимает все
  формата pubkey в одинаковый 32-байтный node_id.
- PoW сложность: 24 бита baseline (16 в debug); адаптивная:
  `24 + ceil(log2(N / 100K))` по DHT-tracked epoch.

Identity может быть **sovereign** — master Falcon-512 ключ
подписывает delegated Ed25519 device-ключи, что позволяет multi-device
messenger'ам с per-device revocation. См.
[identity-model.md](identity-model.md).

---

## 4. Сессии: handshake → AEAD-кадры

OVL1 handshake (6 round-trips, все OVL1-framed):

```
   Client                                    Server
     │                                         │
     │ ──Hello(OVL1, v1, node_id)──→           │
     │           ←──Hello──                    │
     │ ──Identity(algo, pk, nonce, mlkem_ek?)→ │
     │           ←──Identity──                 │
     │ ──Capabilities(role_bits, flags)──→     │
     │           ←──Capabilities──             │
     │ ──KeyAgreement(X25519 ephemeral pk)──→  │
     │           ←──KeyAgreement──             │
     │   [HKDF-SHA256 → tx_key, rx_key,        │
     │                  session_id]            │
     │ ──SessionConfirm(session_id, HMAC)──→   │
     │           ←──SessionConfirm──           │
     │                                         │
     │  ... все последующие кадры AEAD'd с    │
     │      ChaCha20-Poly1305                 │
```

После `SessionConfirm`:
- Каждый кадр обёрнут: `header || ciphertext`, где `ciphertext =
  ChaCha20-Poly1305(key, nonce=session_id||counter, plaintext,
  AAD=header)`.
- Rekey срабатывает при **128 GiB** кадров, **32 днях**, или wrap'е
  AEAD-counter'а — что наступит раньше.
- Padding-кадры (`SessionMsg::Padding`) выравнивают wire-уровневые
  записи до MTU, чтобы пассивный observer не мог определить длины
  сообщений.

### Hot-standby

Любая сессия может прозрачно мигрировать underlying транспорт
(TCP → TLS, IPv4 → IPv6, порт → порт) без переустановки handshake:
AEAD-state сохраняется, writer-таск меняет сокет между frame
boundaries. См. [hot-standby.md](hot-standby.md).

---

## 5. Маршрутизация: как сообщения находят получателя

Три независимых механизма работают совместно:

### 5.1 Route cache (локальный gossip)

```
A анонсирует route к D → B (TTL=2) → C (TTL=1, re-announce только
                                        к прямо-подключенным) → STOP
```

`ROUTE_ANNOUNCE` отправляется с TTL=2, поэтому популярные routes
распространяются ровно на 2 hop'а. Cache TTL-based (60 с default),
scoring — RTT + jitter + congestion + battery (веса конфигурируются
через `[routing]`). Multi-path: top-K путей хранятся per destination
для load-balancing и failover.

### 5.2 Kademlia DHT (cache miss)

```
Sender A хочет дотянуться до D, нет cached route:

   A находит N3 closest к node_id(D) в своём bucket'е
   A отправляет RecursiveRelay(dst=D, payload) → N3

   N3: есть ли у меня прямая session к D?
       да → forward через session; готово
       нет → найти closest к D от N3, forward → N3'
       ...
   После ≤ 16 hop'ов, либо mailbox fallback если D offline.
```

Это **O(log N)** в expectation. Каждая успешная доставка вставляет
**reverse-path** запись в cache, поэтому следующие сообщения в ту же
сторону пропускают DHT walk.

### 5.3 Source routing (sender задаёт путь)

Когда sender уже знает relay path (operator-supplied trusted relay
chain, инструмент connectivity testing), он может отправить
`DeliveryMsg::RelayPath` кадр с полной цепочкой внутри payload'а.
Каждый hop просто forward'ит к следующей записи — никаких DHT
lookups, никаких cache зависимостей. Max 64 hop'а в одном кадре.

```
A → RelayPath{path=[B,C,D,E,F], next_hop=0, inner=msg}
B принимает, видит path[0]=self, forward к C с next_hop=1
C → D → E → F (terminal): F декодирует inner и доставляет локально
```

Используется для: bridging патологических топологий, детерминированных
relay chains, debug connectivity testing.

### 5.4 Mailbox fallback

Если сообщение нельзя доставить live (recipient спит, hop exhausted)
оно попадает в mailbox replica set:

```
sender → STORE(MailboxRef.put(content_id, payload), 3 replicas)
recipient (на wake): FETCH(MailboxRef.list(my_node_id))
              → FETCH(content_id, ack)
```

Mailbox шардируется по `BLAKE3(node_id)` на 3 реплики, persisted
через WAL, и ACK'ается когда recipient подтвердит.

---

## 6. End-to-end шифрование

Существуют **два** различных слоя шифрования:

| Слой | Алгоритм | Scope | Назначение |
|------|----------|-------|------------|
| Session | X25519 ephemeral + HKDF + ChaCha20-Poly1305 | per-hop | Wire encryption между соседними узлами |
| E2E | ML-KEM-768 + ChaCha20-Poly1305 | sender ↔ recipient | Payload непрозрачен для relay'ев |

Session-ключи ротируются при каждом reconnect. E2E использует
**опубликованный** ML-KEM-768 encapsulation-ключ получателя (в DHT
или piggyback на handshake) — relay'и не могут прочитать payload даже
если кооперируются. Маркеры `0xE2`/`0xE3` помечают E2E-wrapped
envelope'ы внутри `Forward`-payload'ов.

---

## 7. Application-слой

Приложения общаются с node-демоном через IPC (Unix socket / Windows
NamedPipe / TCP loopback). Два основных примитива:

- **AppSend** — fire-and-forget datagram к remote `(node_id, app_id,
  endpoint_id)` triple.
- **Stream** — windowed reliable stream поверх veil; daemon'ская
  `AppStreamTable` хранит per-stream state.

App authentication через `app_id` (32-byte handle, выданный при
регистрации). IPC server гейтит capabilities — Leaf-mode IPC client
не может, например, запросить transit-relay.

---

## 8. Wire-протокол кратко

Каждый кадр на проводе:

```
[0..4]   magic        = "OVL1" (0x4F564C31)
[4..5]   version      = 0x01
[5..6]   family       = u8  (Session, Control, Discovery, Delivery, ...)
[6..8]   msg_type     = u16 BE (variant within family)
[8..12]  reserved     = 0x00000000
[12..16] body_len     = u32 BE
[16..20] trace_id     = u32 BE (sampled tracing)
[20..24] flags+prio   = u8 prio | u8 traffic_class | u16 reserved
[24..]   body         = msg_type-specific payload
```

Header — **24 байта**, без TLV-extension в v1 (kill-switch ротирует
magic к новому значению если потребуется вариант). Body opaque до
dispatch'а. Полная reference: [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md).

---

## 9. NAT traversal

Две фазы: **discovery** + **establishment**.

```
Phase 1 — Discovery:
  Leaf → Core: NatProbeRequest                    "какой адрес ты видишь?"
  Core → Leaf: NatProbeResponse(observed_addr)    "вижу тебя по A.B.C.D:port"
  Leaf сохраняет `observed_addr` и публикует через Discovery.

Phase 2 — Establishment:
  Peer X хочет дотянуться до Peer Y (оба за NAT):
    X публикует свой NatProbe → Y публикует свой
    Каждая сторона одновременно шлёт UDP punch-пакеты
    Первый успешный ответ выигрывает; session establishes
  Fallback: relay tunnel через общий Core node
            (конфигурируется, по умолчанию off для Leaf).
```

Local-network discovery через UDP **mesh beacons** (multicast
239.x.x.x), чтобы два телефона в одной Wi-Fi находили друг друга без
прохода через Core node вообще.

---

## 10. Anti-abuse

Layered defense, всё per-peer:

| Уровень | Действие |
|---------|----------|
| Session limit | Max 32 session per IP source |
| PoW challenge | First-contact PoW (16-bit dev, 24-bit prod) |
| Rate limiter | Per-peer token bucket (конфигурируется) |
| Violation tracker | 5 violations → 1 час ban; ban resets через 1 день |
| Reputation | Long-term per-peer score (uptime + relay success + vouches); transit gate 200 points |
| Memory budget | Global RAM cap с priority-based eviction |
| Congestion monitor | Real-time load; >78% → drop transit frames |

Violations эмитятся каждым dispatch-handler'ом, который детектит
нарушение protocol invariant (bad signature, decode failure,
mis-routed frame и пр.). Подробности в [SECURITY.md](SECURITY.md).

---

## 11. Куда смотреть дальше

| Если нужно ... | Читай |
|---|---|
| Byte-for-byte wire format | [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md) |
| Каждая константа, locking rule, subsystem interaction | [ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md) |
| Запустить node в production | [OPERATIONS.md](OPERATIONS.md) |
| Metrics + alerts | [MONITORING.md](MONITORING.md) |
| Писать app'ы поверх veil | [developer-guide.md](developer-guide.md), [messenger-dev.md](messenger-dev.md) |
| Identity + multi-device | [identity-model.md](identity-model.md), [multi-device.md](multi-device.md) |
| Transport handover | [hot-standby.md](hot-standby.md) |
| Adaptive routing / failover scoring | [adaptive-failover.md](adaptive-failover.md) |
| Private veil networks (membership-controlled) | [p-net.md](p-net.md) |
| Bridge veil traffic поверх TUN/TAP | [ogate.md](ogate.md) |

---

## 12. Версионирование

Версия OVL1, описанная здесь — **OVL1 v1** (magic `0x4F564C31`,
version byte `0x01`). Capability negotiation расширяет protocol
вперёд; старые узлы просто игнорируют неизвестные frame families
(`Unknown → forward-compatible`).
