# Как работает veil-сеть

> Этот документ — high-level тур. Полное source-level описание (wire
> format'ы, каждая константа, locking rules, interactions между
> подсистемами) — в [ARCHITECTURE_FULL.md](ARCHITECTURE_FULL.md).

## Обзор

Децентрализованная veil-сеть с E2E-шифрованием, NAT traversal'ом,
DHT-маршрутизацией доставки и mesh-возможностями.

```
App ←→ Leaf ←→ Core ←→ Core ←→ Core ←→ Leaf ←→ App
```

Ключевые свойства: E2E-шифрование (ML-KEM-768 + ChaCha20-Poly1305),
O(log N) routing через Kademlia DHT, автоматический NAT traversal,
local mesh discovery, offline-доставка через mailbox.

## Роли узлов

| Роль | DHT | Relay | Mailbox | Gateway | Типичная среда |
|------|-----|-------|---------|---------|----------------|
| **Leaf** | - | - | - | - | Мобильный телефон, IoT-сенсор |
| **Core** | yes (K=20) | yes | yes | yes | Сервер, VPS, домашний сервер |

Все Core-узлы — равноправные участники: DHT, relay/forwarding,
mailbox, gateway (attachment records для leaf-узлов). PoW ≥ 24 бита.
Gateway можно выключить per-node через `[gateway] enabled = false`.

Существуют только две роли; legacy-роли `Relay` / `Gateway` /
`CoreRouter` не являются частью протокола.

## Identity & PoW

```
keygen(Ed25519 | Falcon512) → (pubkey, privkey)
mine_nonce(pubkey, privkey, difficulty=24) → nonce
node_id = BLAKE3(pubkey)
identity_proof = (pubkey, nonce, sign(pubkey, nonce))
```

И **Ed25519**, и **Falcon-512** — first-class signing-алгоритмы;
выбор per-node (`[identity] algo`, где также доступны гибриды `ed25519+falcon512` / `ed25519+falcon1024`). `BLAKE3(pubkey)`
одинаково даёт 32-байтный `node_id` для обоих вариантов.

PoW difficulty: 24 бита baseline (16 в debug-сборках); адаптивная
формула = `24 + ceil(log2(N / 100K))` через DHT-записи на эпоху.

## Handshake (OVL1)

```
Client → Server: Hello(magic="OVL1", version=1, node_id)
Server → Client: Hello
Client → Server: Identity(algo, pubkey, nonce, node_id, mlkem_ek?)
Server → Client: Identity
Client → Server: Capabilities(role_bits, flags, max_frame, ovl1_minor=1)
Server → Client: Capabilities
Client → Server: KeyAgreement(X25519_pubkey)
Server → Client: KeyAgreement(X25519_pubkey)
  [HKDF-SHA256 → tx_key, rx_key, session_id]   (lex-order swap of tx/rx)
Client → Server: SessionConfirm(session_id, HMAC)
Server → Client: SessionConfirm
  [Все последующие frame'ы: ChaCha20-Poly1305 AEAD encrypted]
```

ML-KEM-768 encapsulation-ключ передаётся внутри `IdentityPayload`
(1184 байта; `mlkem_pk_len=0` означает, что peer не публикует
такого ключа). Session-ключи получаются из эфемерного X25519 DH
плюс HKDF-SHA256; ML-KEM на session-слое сегодня *не* используется,
только для E2E.

Пороги rekey'я: 128 GiB frame'ов **или** 32 дня **или** wrap-around
nonce-counter'а. И byte-, и time-порог настраиваются через
`[session] rekey_bytes_threshold` / `rekey_time_threshold_secs`.

## Dispatch frame'ов

```
bytes → FrameHeader decode → AEAD decrypt → family switch:
  Session  → Hello/Identity/Capabilities/KeyAgreement/SessionConfirm, Rekey, Ticket, Padding
  Control  → Ping/Pong, NatProbe*, Keepalive, Backpressure, Epidemic
  Discovery→ FindNode, FindValue, Store, Delete, Attachment, Mailbox/AppEndpoint lookup
  Delivery → Forward, Mailbox PUT/Fetch/Ack, Transit, RecursiveRelay, Chunks
  Routing  → RouteAnnounce/Withdraw (+Aliased), RouteRequest/Response, PoW, RouteDiscover
  App      → AppOpen, AppData, AppRtData, AppReceipt, AppWindowUpdate
  Mesh     → MeshBeacon, MeshForward, MeshAck
  PeerExchange → Walk, Challenge, Response, Result
  Tunnel   → IpPacket (TUN/TAP)
  RelayChain → Hop (onion)
  Diag     → DiagPing/Pong, TraceProbe/Hop
  Unknown  → ignored (forward-compatible)
```

## Маршрутизация: gossip + DHT

**Локальный gossip** (TTL=2): ROUTE_ANNOUNCE → ближайшие соседи
узнают маршруты.

**DHT forwarding** (cache miss): RecursiveRelay оборачивает
ForwardPayload → отправляется в XOR-ближайший DHT-узел → каждый hop
проверяет наличие живой сессии до dst → доставляет или forward'ит
ещё ближе → mailbox fallback после 20 hop'ов.

```
A announces → B (TTL=1) → C (TTL=0, stop)
A → route cache miss → RecursiveRelay(dst=D)
  → closest node X → есть ли у X сессия до D? → доставлено!
  → нет → forward в ещё более близкий Y → ... → mailbox fallback
```

Reverse-path caching: успешная доставка через RecursiveRelay
вставляет `originator → peer_id` в route cache.

## Доставка сообщений (3 пути)

**Path 1 — Direct** (route cache hit):
```
Sender → FORWARD(dst) → route_cache.lookup(dst) → next_hop → ... → Recipient
```

**Path 2 — DHT-routed** (cache miss):
```
Sender → FORWARD(dst) → cache miss → RecursiveRelay(dst, hop=20)
  → DHT hop chain → узел с живой сессией до dst → доставлено
```

**Path 3 — Mailbox** (recipient offline):
```
Sender → MAILBOX_PUT → Primary (attachment gateway получателя из DHT)
  Primary:
    хранит локально
    select_quorum_replicas:
      shard_target = BLAKE3("shard" || recipient_id || shard_id)
      pool         = DHT.find_closest_nodes(shard_target, (replica_count-1)*4)
      отфильтровать self, origin, low-battery, unreliable relays
      взять        replica_count - 1 replicas
    MAILBOX_REPLICATE → реплики (envelope encrypted for privacy)
    ждём write_quorum DeliveryStatus::QUEUED → ACK sender'у

Recipient выходит online:
  MAILBOX_FETCH → primary gateway
    локальный store → DHT fallback → fan-out MAILBOX_FETCH_REPLICA на реплики
    SEC check: recipient_node_id == authenticated peer_id
```

Выбор реплик **детерминированный**: любой Core-узел с видом на DHT
может независимо посчитать `shard_target` и найти те же closest
реплики — sender и recipient не должны обмениваться host-адресами.

## DHT (Kademlia)

256 k-bucket'ов × K контактов (K=20 согласно Kademlia paper). Метрика
расстояния — XOR.

**Итеративный lookup**: seed K closest → запрос α=3 за раунд →
merge ответов → сходимость (максимум `MAX_ROUNDS=20`).

**Sharding**: `shard_id = key[0]`; каждый узел покрывает 16
ближайших shard'ов из 256. Shard-aware STORE-фильтрация — opt-in.

**Tiered storage**: hot HashMap + cold-уровень; LRU-промоушн при
обращении; demotion при переполнении hot; eviction при переполнении
cold. По умолчанию cold-уровень — это in-memory HashMap, но он может
быть дисковым хранилищем RocksDB через `[dht] cold_store_path` (cargo-feature
`rocksdb-cold`, включён по умолчанию для `veil-cli`), что поднимает
потолок по числу записей с RAM на диск (>1M записей) и сохраняет данные
между перезапусками. При отсутствии feature или ошибке открытия RocksDB
происходит откат на in-memory cold-уровень — с записью в лог при старте.

**Eclipse defense**: не более `K/4 = 5` контактов на /24 IPv4 (/48
IPv6) подсеть в одном bucket'е.

**Аутентификация STORE / DELETE**:
- `StorePayload` несёт опциональную Ed25519-подпись над `key || value`.
- `DeletePayload` требует `algo + pubkey + signature` (любой алгоритм подписи
  идентичности — Ed25519, Falcon-512 или гибрид Ed25519+Falcon); принимается
  только при `BLAKE3(pubkey) == key`.

## Discovery & Attachment

```
Leaf стартует → attach к Core → AnnounceAttachment(node_id, role, gateways, mailboxes, expires_at)
  → signed → сохранено в DHT по attachment_key(node_id)
Peer хочет достучаться до Leaf → GetAttachment(node_id) → узнаёт Core gateways/mailboxes → route
```

## E2E-шифрование

```
sender: (ct, ss) = ML-KEM-768.Encaps(recipient_ek)
        plaintext_envelope → ChaCha20-Poly1305(ss, nonce) → ciphertext
        send(E2E_MARKER || ct || ciphertext)

recipient: ss = ML-KEM-768.Decaps(dk, ct)
           plaintext = ChaCha20-Poly1305.open(ss, nonce, ciphertext)
```

Relay-узлы видят только ciphertext — никакого доступа к plaintext'у.

## NAT Traversal

```
A за NAT'ом → подключается к Relay R
A хочет достучаться до B (тоже за NAT'ом):
  A → R: NatProbe(observed-адрес B)
  R → B: NatProbeRelay(observed-адрес A)
  B открывает порт для A → A соединяется напрямую
  Fallback: relay-tunnel через R
```

## Mesh-сеть

```
IoT-device ← UDP beacon (multicast/broadcast, интервал 30 с) → Gateway
  Gateway видит beacon → auto-discover → устанавливает veil-сессию
  Gateway мостит local mesh ↔ global veil
```

Beacon'ы несут node_id, realm_id (UUID), transport URI'ы и подписанные
algo/pubkey. На одном физическом сегменте могут сосуществовать
несколько realm'ов — peer'ы игнорируют beacon'ы с чужим `realm_id`.

## Peer Exchange (PEX)

Random-walk-based discovery транспортов (Family 11):

```
Originator → seed:        PexWalk (walk_id, pubkey, nonce, signature, TTL)
Terminator → originator:  PexChallenge (PoW challenge)
Originator → terminator:  PexResponse (solution, origin_sig)
Terminator → originator:  PexResult (peer list with transport URIs)
```

Multi-algo: `origin_sig` верифицируется как Ed25519 (32-байтный pubkey)
или Falcon-512 (более длинный pubkey) через `crypto::verify_message`.

## Защита от abuse'а

```
Inbound-подключение:
  1. Per-IP лимит сессий (max 32)
  2. PoW challenge (если сконфигурирован)
  3. Handshake timeout (10 с — `HANDSHAKE_TIMEOUT_SECS`)
  4. Per-peer rate limiter (token bucket)
  5. Violation tracker (5 violations → ban)
  6. Ban list (авто-expire после TTL)
  7. Congestion backpressure (>78% → drop transit)
  8. Reputation gate (200 баллов для transit'а)
```

## Observability

- **Prometheus-метрики**: `GET /metrics` — counter'ы и gauge'и по всем
  подсистемам
- **Структурированное логирование**: `[timestamp] LEVEL event message`
  (опционально JSON-L)
- **Debug capture**: CLI `debug capture` — live frame capture в файл
- **DiagPing**: end-to-end latency-probe через veil
- **Trace buffer**: последние N dispatch-событий для отладки
