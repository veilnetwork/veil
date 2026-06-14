# Veil — подробное устройство сети

Документ описывает сеть Veil (протокол OVL1) достаточно подробно, чтобы по нему можно было с нуля написать совместимый узел или провести аудит безопасности. Все числовые константы и структуры взяты прямо из `veilcore/src/` по текущему состоянию репозитория.

> Обзорное введение — в [ARCHITECTURE.md](ARCHITECTURE.md). Формат на уровне отдельных полей (wire-формат, то есть раскладка байтов в канале) — в [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md) и [protocol-spec.md](protocol-spec.md).

---

## Содержание

1. [Обзор и принципы](#1-обзор-и-принципы)
2. [Топология: роли узлов](#2-топология-роли-узлов)
3. [Идентификация: node_id, PoW, ключи](#3-идентификация-node_id-pow-ключи)
4. [Транспортный уровень](#4-транспортный-уровень)
5. [Wire-протокол OVL1](#5-wire-протокол-ovl1)
6. [Session plane (handshake и шифрование канала)](#6-session-plane-handshake-и-шифрование-канала)
7. [E2E-шифрование](#7-e2e-шифрование)
8. [Discovery: DHT (Kademlia)](#8-discovery-dht-kademlia)
9. [Discovery: сервисные записи](#9-discovery-сервисные-записи)
10. [Routing](#10-routing)
11. [Delivery](#11-delivery)
12. [Mailbox (offline-доставка)](#12-mailbox-offline-доставка)
13. [Peer Exchange (PEX)](#13-peer-exchange-pex)
14. [Mesh (локальная UDP-сеть)](#14-mesh-локальная-udp-сеть)
15. [NAT traversal](#15-nat-traversal)
16. [Anti-abuse и защита](#16-anti-abuse-и-защита)
17. [Адаптивные параметры](#17-адаптивные-параметры)
18. [App layer и IPC](#18-app-layer-и-ipc)
19. [Наблюдаемость](#19-наблюдаемость)
20. [Runtime и структура процесса](#20-runtime-и-структура-процесса)

---

## 1. Обзор и принципы

Veil — децентрализованная одноранговая (P2P, peer-to-peer) сеть для передачи сообщений между приложениями. Ключевые свойства:

- **Стабильные идентификаторы.** `node_id = BLAKE3(public_key)` — 32 байта, не зависит от IP, NAT и способа передачи (транспорта).
- **Криптография.** Подписи — Ed25519 или Falcon-512 (последний постквантовый, PQ). В рукопожатии (handshake) выполняется эфемерный обмен ключами X25519 по Диффи — Хеллману, затем канал защищается ChaCha20-Poly1305 AEAD; сквозной (E2E) трафик добавляет сверху ML-KEM-768 (см. §7).
- **Сквозное шифрование (E2E).** ML-KEM-768 на прикладном уровне. Ретрансляторы видят только шифртекст.
- **Маршрутизация через DHT.** Kademlia (K=20, α=3) даёт поиск за O(log N) и рекурсивную доставку.
- **Несколько транспортов.** TCP, TLS, QUIC, WebSocket (ws/wss), Unix-сокет и SOCKS5 с обёртками.
- **Обход NAT.** Пробивание соединения (hole-punching) в духе ICE, а если прямой путь не выходит — запасной путь через ретрансляцию на Core-узле.
- **Mailbox (почтовый ящик).** Если получатель офлайн, сообщение откладывается на Core-узлах и реплицируется через журнал упреждающей записи (WAL).
- **Локальная mesh-сеть.** UDP-маяк и мост между realm'ами держат сегмент рабочим даже без интернета.
- **Защита от Sybil-атаки.** Доказательство работы (PoW) не ниже 24 бит, адаптивно, на идентификаторе узла.
- **Защита от флуда.** Корзина токенов (token bucket) на каждого соседа питает трекер нарушений, тот — список банов; при перегрузке включается обратное давление (backpressure).

### Слои

```
Application          App ↔ IPC (Unix socket) ↔ AppEndpointRegistry
                                     │
Dispatch             FrameDispatcher — family-switch по FrameFamily
                                     │
Session              SessionRunner — ChaCha20-Poly1305 AEAD, WRR
                                     │
Transport            TCP / TLS / QUIC / WS / WSS / Unix / SOCKS5
```

---

## 2. Топология: роли узлов

Файл: [`crates/veil-cfg/src/model.rs`](../../crates/veil-cfg/src/model.rs), enum `NodeRole`.

| Роль | DHT | Relay | Mailbox | Gateway | Применение |
|------|-----|-------|---------|---------|------------|
| **Leaf** | нет | нет | нет | нет | Мобильные клиенты, IoT, ограниченная связность |
| **Core** | да (K=20) | да | да | да (по флагу) | Серверы, VPS, постоянно online |

Роль по умолчанию — `Core`. У узла ровно одна роль, и она задаётся в конфиге на всё время работы процесса. В пакетах обмена возможностями она передаётся битовой маской в `CapabilitiesPayload.roles_supported`:

```
bit 0 — LEAF
bit 3 — CORE
```

Биты `1 (RELAY)`, `2 (GATEWAY)` и `4 (CORE_ROUTER)` когда-то были самостоятельными ролями. Их убрали.

### Флаги возможностей

`CapabilitiesPayload.flags` (1 байт) — `cap_flags` из [`proto/session.rs`](../../crates/veil-proto/src/session.rs):

| Бит | Константа | Смысл |
|-----|-----------|-------|
| 0 | `CAN_RELAY` | Готов пересылать чужой трафик |
| 1 | `CAN_MAILBOX` | Готов принимать Mailbox-записи |
| 2 | `CAN_GATEWAY_LOCAL_MESH` | Работает мостом между mesh и Veil |
| 3 | `CAN_PARTICIPATE_DHT` | Участвует в DHT-таблице |
| 4 | `CAN_ACCEPT_APP_STREAMS` | Принимает AppOpen/AppData |
| 5 | `CAN_STORE` | Хранит DHT-значения локально |
| 6 | `SUPPORTS_TRANSIT` | Умеет `DeliveryMsg::Transit` (ретрансляция без состояния) |

У Core-узла по умолчанию: `CAN_RELAY | CAN_PARTICIPATE_DHT | CAN_STORE | CAN_MAILBOX`. У Leaf — всё в ноль: это пассивный потребитель.

---

## 3. Идентификация: node_id, PoW, ключи

### 3.1 node_id

```
node_id = BLAKE3(raw_public_key_bytes)        // 32 байта
```

Хешируются сырые байты открытого ключа, а не base64-строка. В CLI и конфиге результат показан как 64-символьная hex-строка.

### 3.2 Алгоритмы подписи

- **Ed25519** — открытый ключ 32 байта, подпись 64 байта. Быстрый и классический.
- **Falcon-512** — открытый ключ около 897 байт, подпись около 666 байт. Постквантовый, для узлов с требованием PQ.

Выбор задаётся через `[identity] algo = "ed25519" | "falcon512" | "ed25519+falcon512" | "ed25519+falcon1024"`. Перечисление — `veil_types::SignatureAlgorithm`.

В канале `algo` передаётся одним байтом. `IdentityPayload` и mesh-маяк следуют такому соглашению:

```
algo = 0  — Ed25519
algo = 2  — Falcon-512
algo = 3  — Ed25519+Falcon-512 hybrid
algo = 4  — Ed25519+Falcon-1024 hybrid
```

(`DeletePayload` в DHT сейчас принимает только `0` и `2`, поэтому записи с гибридной подписью пока нельзя удалить самостоятельно.)

В рукопожатии сессии по историческим причинам используется `algo = 1 → Ed25519` (см. `handshake::algo_to_u8`).

### 3.3 Proof-of-Work (Sybil-защита)

Каждый `node_id` обязан нести доказательство PoW. Правило — `leading_zero_bits(BLAKE3(pubkey ∥ nonce ∥ sign(pubkey, nonce))) ≥ difficulty`: хеш должен начинаться хотя бы с `difficulty` нулевых битов.

- **Базовая сложность (difficulty):** 24 бита в production, 16 бит в debug-сборках. См. [`identity_policy.rs`](../../crates/veil-cfg/src/identity_policy.rs).
- **Максимум:** `MAX_POW_DIFFICULTY = 24` (из [`proto/budget.rs`](../../crates/veil-proto/src/budget.rs)).
- **Адаптивная сложность:** `24 + ceil(log2(N / 100_000))`, где `N` — оценка размера сети. Публикуется как `EpochDifficultyRecord` в DHT (эпоха — unix-день).
- **Нижняя граница для production:** `RECOMMENDED_PRODUCTION_POW_DIFFICULTY = 16` — минимальная сложность, которую узел в production должен принимать.
- **Параллельные решатели:** `MAX_CONCURRENT_POW_SOLVERS = 4` — ограничивает атаку с ветвлением, когда сразу перебирают много кандидатов.

Майнинг — в `identity_ops.rs` и `cmd/identity/mine.rs`, а также ленивый майнер `node/lazy_miner.rs`.

### 3.4 Ключевые материалы

| Ключ | Размер | Назначение | Хранение |
|------|--------|------------|----------|
| Ed25519 sk | 32 Б seed | Подпись идентичности, DHT DELETE | Конфиг (base64) |
| Ed25519 pk | 32 Б | Верификация | В handshake |
| Falcon-512 sk | 1281 Б | Подпись (альтернатива Ed25519) | Конфиг |
| Falcon-512 pk | 897 Б | Верификация | В handshake |
| ML-KEM-768 ek | 1184 Б | Инкапсуляция для E2E | Опубликовано в DHT |
| ML-KEM-768 dk | seed 64 Б | Декапсуляция E2E | Конфиг |
| X25519 ephemeral | 32 Б × 2 | Сессионный обмен | Генерируется per-session |

Чувствительные типы (`Base64PrivateKey`, `PowParams`, `SessionKeys`) имеют собственный `Debug`, который вырезает содержимое, так что ключ не утечёт в строку лога.

---

## 4. Транспортный уровень

Файл: [`crates/veil-transport/src/`](../../crates/veil-transport/src/).

### 4.1 Поддерживаемые URI-схемы

Парсер — [`transport/uri.rs`](../../crates/veil-transport/src/uri.rs), enum `TransportUri`:

| Схема | Описание |
|-------|----------|
| `tcp://host:port` | Сырой TCP |
| `tls://host:port?sni=...&alpn=...` | TLS поверх TCP (BoringSSL по умолчанию, rustls — запасной путь) |
| `quic://host:port?sni=...&alpn=...` | QUIC через `quinn` |
| `unix:///path` | Unix domain socket |
| `socks://proxy/target` | TCP через SOCKS5 |
| `sockstls://proxy/target` | TLS через SOCKS5 |
| `ws://host:port/path` | WebSocket-обёртка над TCP |
| `wss://host:port/path` | WebSocket + TLS |

Они вкладываются друг в друга через `TransportStack::Wrapped { lower, wrapper }`. Например, `sockstls://` превращается в `Wrapped(Wrapped(Tcp, Socks), Tls)` — TLS поверх SOCKS5 поверх TCP.

### 4.2 Back-ends и отпечатки

- **`TransportBackendKind`**: BoringSSL (feature `tls-boring`) — TLS-бэкенд **по умолчанию** для бинарников `veil-cli`, `ogate` и `oproxy` (`veil-cli` Cargo.toml: `default = ["rocksdb-cold", "tls-boring"]`); **библиотека** `veilcore` по умолчанию использует rustls (`default = ["rocksdb-cold"]`). BoringSSL даёт Chrome-подобный отпечаток ClientHello (JA3/JA4) и ротирует его — основной способ проскользнуть мимо глубокой инспекции пакетов (DPI). Отключается через `--no-default-features`.
- **`TransportFingerprintMode`**: выбирает, какой отпечаток TLS (то есть ClientHello) показывать, — так Veil может спрятаться под шаблон Chrome или Firefox.
- **`TransportOperatingMode`**: Server / Client / Mixed.
- **`WebSocketHandshakeMode`**: legacy / extended.

### 4.3 Discovery транспортов

Узел объявляет свои транспорты в `TransportRegistry`. Сам слушатель (listener) запускается через `listener_supervisor.rs`. Если слушатель падает, супервизор перезапускает его с нарастающей задержкой (backoff).

---

## 5. Wire-протокол OVL1

### 5.1 Заголовок фрейма (24 байта)

[`proto/header.rs`](../../crates/veil-proto/src/header.rs):

```
Offset  Len  Тип    Поле         Описание
------  ---  -----  -----------  -------------------------------------
  0      4   bytes  magic        "OVL1" = 0x4F564C31
  4      1   u8     version      = 1
  5      1   u8     family       FrameFamily (0..11)
  6      2   u16BE  msg_type     тип в рамках family
  8      2   u16BE  flags        битовая маска (см. ниже)
 10      2   u16BE  header_len   24 (или больше при TLV-расширениях)
 12      4   u32BE  body_len     размер payload
 16      4   u32BE  stream_id    мультиплексирование потоков
 20      4   u32BE  request_id   корреляция RPC
```

`body_len` ограничен сверху значением `MAX_FRAME_BODY = 16 MiB`. У каждого слушателя есть ещё настраиваемый мягкий лимит `max_frame_body_bytes` (по умолчанию 1 MiB).

### 5.2 Флаги

Биты в `flags`:

```
0..1  priority       0=RealTime, 1=Interactive, 2=Bulk, 3=Background
```

Остальные биты зарезервированы и должны быть 0. Старая документация называет `encrypted` и `require_ack` флагами канала — это не так: шифрование относится ко всей сессии целиком, а `require_ack` живёт в теле `DeliveryEnvelope`.

### 5.3 Семейства фреймов

[`proto/family.rs`](../../crates/veil-proto/src/family.rs), enum `FrameFamily`:

| ID | Family | Сообщения |
|----|--------|-----------|
| 0 | Session | Hello, Identity, Capabilities, KeyAgreement, SessionConfirm, Attach, Detach, Keepalive, RekeyInit/Ack, MlKemRekeyEk/Ack, Ticket, SleepAdvertisement, Padding, и варианты connection-handoff: HandoffInit(16), HandoffAck(17), HandoffAttach(18), HandoffChallenge(24), HandoffResponse(25). HandoffChallenge=24/HandoffResponse=25 — handoff wire v2 (challenge-response), пришедший на смену старой статичной HMAC поверх HandoffAttach=18 |
| 1 | Control | Ping/Pong, NeighborOffer, RouteProbe/Reply, Error, NatProbeRequest/Reply, NatRelayRequest, Keepalive(0x10)/Ack, EpidemicBroadcast(0x20), Backpressure(0x30) |
| 2 | Discovery | FindValue, Store, Delete, AnnounceAttachment, GetAttachment, GetAppEndpoint, FindValueResponse, FindNodeV2(10)/FindNodeV2Response(11), ResolveTransport(12)/ResolveTransportResponse(13), AnnounceTransport(14) |
| 3 | Delivery | Forward, DeliveryStatus, ChunkManifest, Chunk, Transit(0x10), RecursiveRelay(0x11), RelayPath(0x12) |
| 4 | App | AppOpen, AppData, AppClose, AppSend, AppReceipt, AppWindowUpdate, AppRtData |
| 5 | Mesh | Forward, Beacon, Ack |
| 6 | LocalApp | 79 типов IPC-сообщений (AppHello=0 … SendAnonymousDirectResult=78; см. §18) |
| 7 | Tunnel | IpPacket — TUN/TAP инкапсуляция |
| 8 | Routing | RouteAnnounce/Withdraw, RouteRequest/Response, PowChallenge/Response/Accept, RouteAnnounceAliased/WithdrawAliased, RouteDiscover/Offer, RecursiveQuery/Response(0x10/0x11), RouteUpdate(0x12), VersionVectorSync(0x13) |
| 9 | Diag | Ping/Pong, TraceProbe, TraceHop |
| 10 | RelayChain | Hop(0) — onion-encrypted chain, RegisterRendezvous(1), UnregisterRendezvous(2), ForwardIntroduce(3), CircuitBuild(4)/CircuitData(5)/CircuitTeardown(6)/CircuitBuilt(7) |
| 11 | PeerExchange | Walk, Challenge, Response, Result |

Неизвестная `family` даёт `ProtoError::UnknownFamily`, неизвестный `msg_type` — `UnknownMsgType`. Диспетчер просто игнорирует такие фреймы, и за счёт этого старые узлы остаются совместимыми с более новыми.

### 5.4 Единая minor-версия

`OVL1_MINOR_VERSION = 1` (см. `proto/budget.rs`). Раньше отдельные возможности были закрыты version-gate'ами (проверками версии), но теперь каждая такая проверка открыта безусловно. Поле остаётся в канале на случай, если снова понадобится.

---

## 6. Session plane (handshake и шифрование канала)

### 6.1 Последовательность

Рукопожатие OVL1 начинает клиент. До `SessionConfirm` фреймы идут открытым текстом; после него каждый фрейм в этой сессии шифруется ChaCha20-Poly1305.

```
   Initiator                                                    Responder
   │── Hello (magic "OVL1", version=1, node_id) ──────────────→ │
   │ ←── Hello (responder node_id) ─────────────────────────────│
   │── Identity (algo, pubkey, nonce, node_id, mlkem_ek?) ────→ │
   │ ←── Identity ──────────────────────────────────────────────│
   │── Capabilities (role_bits, flags, frame_size) ───────────→ │
   │ ←── Capabilities ──────────────────────────────────────────│
   │── KeyAgreement (X25519 ephemeral pubkey) ────────────────→ │
   │ ←── KeyAgreement ──────────────────────────────────────────│
   │               [HKDF-SHA256 → session keys]                 │
   │── SessionConfirm (session_id, HMAC) ─────────────────────→ │
   │ ←── SessionConfirm ────────────────────────────────────────│
   │                 [AEAD encrypted from here]                 │
   │── Attach (опционально; leaf → core gateway) ─────────────→ │
```

### 6.2 HelloPayload (34 байта)

```
[0..2]  ovl1_version  u16BE = 1
[2..34] node_id       [u8; 32]
```

### 6.3 IdentityPayload (variable)

```
[0]                  algo         u8 (0/1=Ed25519, 2=Falcon512, 3=Ed25519+Falcon512, 4=Ed25519+Falcon1024)
[1..3]               pk_len       u16BE
[3..3+pk]            public_key   bytes
[3+pk]               nonce_len    u8
[4+pk..4+pk+n]       nonce        bytes   (hex-строка PoW-nonce)
[4+pk+n..4+pk+n+32]  node_id      [u8; 32]
[4+pk+n+32..+2]      mlkem_pk_len u16BE   (0 — нет ключа)
[..]                 mlkem_pk     bytes   (1184 Б для ML-KEM-768)
```

Открытый ключ всегда передаётся в сыром виде. Верификатор проверяет `BLAKE3(public_key) == node_id`.

### 6.4 CapabilitiesPayload (3 байта, wire v3)

```
[0]  roles_supported  u8  (битовая маска role_bits: bit0=leaf, bit3=core)
[1]  flags            u8  (cap_flags: CAN_RELAY=0x01, SUPPORTS_SOVEREIGN_IDENTITY=0x02,
                         ANONYMITY_RELAY=0x04, SUPPORTS_HYBRID_KEX=0x08)
[2]  discovery_mode   u8  (0=Public, 1=ContactsOnly)
```

Wire v3 убрал старую 12-байтную форму (`transports_sup`, `max_frame_size`, `max_streams`,
`ovl1_minor`). Декодер по-прежнему принимает и 2-байтную форму (roles + flags) — тогда
`discovery_mode` берётся равным `Public`.

### 6.5 KeyAgreement + SessionKeys

Payload: `algo(1) + key_len(2) + X25519_pubkey(32)`.

Ключ X25519 — **эфемерный**: на каждое рукопожатие генерируется новый, и он никак
не связан с долговременной личностью (Ed25519 / Falcon-512). Это даёт прямую
секретность (forward secrecy): компрометация личности не раскрывает прошлые сессии.

Оба узла вычисляют одни и те же ключи:

```
shared_secret = X25519(my_ephemeral_sk, peer_ephemeral_pk)

salt = local_node_id XOR remote_node_id     // commutative — обе стороны
                                            // получают одинаковый salt
ikm  = shared_secret
info = "ovl1-session-v1"

[key_a ‖ key_b ‖ session_id] = HKDF-SHA256(salt, ikm, info, L=96)

(tx_key, rx_key) = if local_node_id <= remote_node_id  → (key_a, key_b)
                   else                                 → (key_b, key_a)
```

`tx_key` шифрует исходящие фреймы, `rx_key` расшифровывает входящие.
Лексикографический порядок двух `node_id` гарантирует, что инициатор и отвечающий
получают зеркальные назначения: `alice.tx == bob.rx` и наоборот. Отдельного `mac_key`
нет — целостность обеспечивают тег AEAD (`ChaCha20-Poly1305`) и MAC рукопожатия в `SessionConfirm`.

Реализация: [`crypto/session_kdf.rs::derive_session_keys`](../../crates/veil-crypto/src/session_kdf.rs).

### 6.6 SessionConfirm

```
[0..32]  session_id [u8; 32]
[32..64] mac        [u8; 32]
                    └ BLAKE3("ovl1-session-confirm-v1" ‖ shared_secret
                            ‖ small_node_id ‖ large_node_id)
```

`small` и `large` — пара node_id в лексикографическом порядке, чтобы обе
стороны пришли к одинаковому MAC независимо от того, кто отправил первым.
Реализация: [`node/session/handshake.rs::compute_confirm_mac`](../../crates/veil-session/src/handshake.rs).

MAC фиксирует и shared_secret, и оба node_id. Наблюдатель без секрета X25519 не сможет
подделать MAC, даже дословно повторив сообщения рукопожатия. Получив валидный
`SessionConfirm`, сторона переключает канал на AEAD. Дальше `session_id`
служит ключом для `SessionTxRegistry` и для билета возобновления (resumption ticket).

### 6.7 AEAD-защита

Алгоритм: **ChaCha20-Poly1305**.

- Nonce — 12 байт, счётчик на сессию, который только растёт. Когда он подходит к переполнению, запускается смена ключей (rekey).
- Шифруется тело фрейма (`body`); 24-байтный заголовок остаётся открытым текстом.
- `aad` (дополнительные аутентифицируемые данные) — это и есть тот 24-байтный заголовок.

### 6.8 Rekey

Смена ключей срабатывает при пересечении любого из порогов:

- `REKEY_BYTES_THRESHOLD = 128 GiB` переданных данных, либо
- `REKEY_TIME_THRESHOLD_SECS = 32 дня` (2 764 800 с), либо
- приближение счётчика nonce к переполнению.

Пороги по объёму и времени настраиваются через `[session] rekey_bytes_threshold` и
`rekey_time_threshold_secs` в конфиге узла.

```
Initiator ── RekeyInit (новый ephemeral X25519 pubkey) ──→ Responder
Initiator ← RekeyAck  (ответный ephemeral X25519 pubkey) ── Responder

new_shared = X25519(new_ephemeral_priv, peer_new_ephemeral_pub)
salt       = session_id XOR local_node_id XOR remote_node_id
                       └ chain-salt связывает новые ключи с историей сессии
info       = "ovl1-session-rekey-v1"
[key_a ‖ key_b ‖ new_session_id] = HKDF-SHA256(salt, new_shared, info, L=96)
(tx_key, rx_key) — swap по lex-order node_id, как в §6.5
```

Реализация: [`crypto/session_kdf.rs::derive_rekey_keys`](../../crates/veil-crypto/src/session_kdf.rs).

### 6.9 Возобновление по билету

После успешного рукопожатия сервер выдаёт клиенту зашифрованный `SessionTicket`. Клиент может предъявить его в TLV-расширении (type-length-value, тип-длина-значение) `HelloPayload`, чтобы быстро возобновить сессию без полного рукопожатия.

- `SESSION_TICKET_TTL_SECS = 3600` (1 час) — обычный срок жизни.
- `SESSION_TICKET_MAX_AGE_SECS = 7200` — жёсткий предел по возрасту, с запасом на расхождение часов (clock skew).

### 6.10 Keepalive и hibernation

- `Keepalive` (Control, 0x10) и `KeepaliveAck` (0x11) — пульс (heartbeat), который шлётся каждые `session.keepalive_interval_secs`.
- Сессия, простоявшая без активности дольше `session.idle_timeout_secs`, закрывается.
- `SleepAdvertisement` (Session, 13) — узел предупреждает свои mailbox-хосты, что собирается уйти офлайн, и те продлевают хранение до `expected_wake_ts + grace`.

### 6.11 ML-KEM rekey

`MlKemRekeyEk` и `MlKemRekeyAck` несут новый открытый ключ инкапсуляции для E2E. Они позволяют узлу сменить долгоживущий ключ ML-KEM без перезапуска.

### 6.12 Padding

`SessionMsg::Padding` (14) — пустой (no-op) фрейм со случайным телом. Он дополняет реальные фреймы до MTU на уровне TLS-записей, чем усложняет пассивный анализ трафика.

---

## 7. E2E-шифрование

Файл: [`proto/e2e.rs`](../../crates/veil-proto/src/e2e.rs).

### 7.1 Маркеры в `DeliveryEnvelope.payload`

| Первый байт | Константа | Смысл |
|-------------|-----------|-------|
| `0xE2` | `E2E_MARKER` | Обычное E2E: `sender_node_id` открытым текстом, полезная нагрузка зашифрована |
| `0xE3` | `META_E2E_MARKER` | Meta-E2E (луковичное): отправитель скрыт; в канале `sender_node_id = [0; 32]` |
| любой | (без маркера) | Доставка открытым текстом (только при явном согласии) |

### 7.2 Формат `E2eEnvelope` (после маркерного байта)

```
[0]            version       u8 = 1
[1..3]         kem_ct_len    u16BE  (1088 для ML-KEM-768)
[3..N]         kem_ct        bytes  (ML-KEM ciphertext)
[N..N+12]      nonce         [u8; 12]
[N+12..N+16]   ct_len        u32BE
[N+16..]       ciphertext    bytes  (ChaCha20-Poly1305 ct + 16 Б tag)
```

### 7.3 Алгоритм

```
1. (kem_ct, shared_secret) = ML-KEM-768.Encaps(recipient_ek)
2. key  = HKDF-SHA256(
             ikm  = shared_secret,
             info = "ovl1-e2e-v1" || src_id || dst_id
          )[0..32]
3. nonce = random[12]
4. aad   = src_id || dst_id
5. ct    = ChaCha20-Poly1305.Seal(key, nonce, plaintext, aad)
```

Ретранслятор видит только `E2eEnvelope` — без секретного ключа получателя расшифровать содержимое он не может.

### 7.4 Управление ключами

- **Публикация `ek`:** когда приложение привязывает (bind) эндпоинт, узел публикует `AppEndpointResponse` в DHT (см. §9), и ek встроен в запись.
- **Хранение `dk`:** в конфиге, как 64-байтный base64-seed; ротация — через `MlKemRekeyEk` внутри активной сессии.
- **Кеш ek соседей:** `peer_mlkem_keys` хранит до `MAX_PEER_MLKEM_CACHE = 4096` ключей, у каждого TTL `ipc.e2e_key_ttl_secs` (по умолчанию 3600 с).

### 7.5 Meta-E2E (onion)

В meta-E2E шифруется не только полезная нагрузка, но и сам `DeliveryEnvelope` — поля `sender_node_id`, `src_app_id`, `app_id`, `endpoint_id`. Ретрансляторы тогда видят только `recipient_node_id` и `ttl/created_at`. Подходит для анонимной отправки (`AppIpcSend` с flag=anonymous).

---

## 8. Discovery: DHT (Kademlia)

Файл: [`crates/veil-dht/src/`](../../crates/veil-dht/src/).

### 8.1 Параметры

| Константа | Значение | Источник |
|-----------|----------|----------|
| `K` | 20 | `dht/routing.rs::K` |
| `ALPHA` | 3 | `dht/iterative.rs::ALPHA` |
| `MAX_ROUNDS` | 20 | `dht/iterative.rs::MAX_ROUNDS` |
| MAX per /24 subnet в bucket | K/4 = 5 | `dht/routing.rs` (анти-Eclipse) |

### 8.2 Routing table

- 256 k-bucket'ов, по одному на бит XOR-расстояния.
- Каждый bucket — `VecDeque<Contact>` ёмкостью `K`.
- Порядок LRU (least-recently-used, «дольше всех не использованный»): недавно увиденный контакт уходит в хвост.
- Чтобы вставить контакт в полный bucket, узел пингует самый старый; если тот отвечает, новичок отбрасывается.

### 8.3 XOR-метрика

```
distance(a, b) = a XOR b        // 32 байта
closest_to(target, n) = sort_by(xor(node_id, target)).take(n)
```

### 8.4 Итеративный lookup

`dht::iterative::find_node_iterative`:

```
shortlist = K closest known contacts to target
queried = {}
repeat до max_rounds или пока shortlist не улучшается:
    pick α unqueried nodes from shortlist
    send FindNode(target, k=K) в параллель
    merge respondents → shortlist (top-K по XOR)
    queried ∪= picked
return top-K of shortlist
```

`find_value_iterative` работает так же, но возвращает значение, как только получит `FindValueResponse::Value(v)`.

### 8.5 Sharding и tiered storage

**Шардирование.** `shard_id = key[0]`, и каждый узел покрывает 16 ближайших шардов из 256. При `DhtConfig.shard_filtering = true` узел отбрасывает любой STORE, попавший не в его шарды.

**Многоуровневое хранилище.** Уровней два:
- **Hot (горячий)** — `HashMap<key, value>` ограниченного размера, для быстрого доступа.
- **Cold (холодный)** — по умолчанию больший `HashMap` в памяти, который при обращении к записи поднимает её в горячий уровень. Холодный уровень можно вместо этого держать на диске в RocksDB — включается через `[dht] cold_store_path` (за cargo-feature `rocksdb-cold`, по умолчанию включена для `veil-cli` и `veilcore`). Диск снимает потолок ёмкости с оперативной памяти (более 1M записей) и переживает перезапуски. Если `cold_store_path` не задан, feature отсутствует или RocksDB не открылся, узел откатывается на холодный уровень в памяти и пишет об этом строку в лог.

При переполнении горячего уровня записи опускаются в холодный; при переполнении холодного — вытесняются.

### 8.6 DhtValue envelope (§5.5 спецификации)

Все DHT-записи обёрнуты в `DhtValue`:

```
[0..32]   key       [u8; 32]
[32]      kind      u8  (0=raw, 1=attachment, 2=mailbox, 3=app_endpoint)
[33..37]  epoch     u32BE
[37..41]  ttl_secs  u32BE
[41..49]  seq_no    u64BE
[49..53]  body_len  u32BE
[53..]    body      bytes
[+2]      sig_len   u16BE
[+slen]   signature bytes  (пусто — unsigned)
```

Подпись покрывает префикс `[0..53+body_len]` — всё вплоть до тела включительно.

### 8.7 DHT-операции

Все они обрабатываются в `KademliaService` ([`dht/kademlia.rs`](../../crates/veil-dht/src/kademlia.rs)).

#### Store

`StorePayload`:
```
[0..32]  key        [u8; 32]
[32..36] value_len  u32BE
[36..]   value      bytes
[+]      sig_flag   u8   (0=unsigned, 1=signed)
[+32]    ed25519_pk [u8; 32]      (при signed)
[+64]    ed25519_sig[u8; 64]      (при signed)
```

Подпись — Ed25519 над `key || value`. Core-узел кладёт запись в хранилище; Leaf отклоняет её (`KademliaError::NotAllowed`).

#### Delete

Требует доказательства, что ключ принадлежит вам.

```
DeletePayload:
[0..32]           key         [u8; 32]
[32]              algo        u8  (0=Ed25519, 2=Falcon512)
[33..35]          pk_len      u16BE
[35..35+pk]       public_key  bytes
[+2]              sig_len     u16BE
[+slen]           signature   bytes
```

Верификация в [`verify_store_ownership`](../../crates/veil-dht/src/kademlia.rs#L1524):

1. `algo` ∈ {0, 2}, иначе `NotAllowed`.
2. `crypto::verify_message(algo, pk, key_bytes, sig)` → `Ok`.
3. `BLAKE3(public_key) == key` — удалить можно только своё.

Политика «только своё» покрывает `node_id`-ключи. Для ключей mailbox и app_endpoint DELETE сейчас никто не инициирует.

#### FindNode / FindValue

```
FindNodePayload:     target[32] + k[2]
FindNodeResponse:    count[2] + NodeContact[]
FindValuePayload:    key[32]
FindValueResponse:   либо Value(bytes), либо Nodes(contacts[])
```

`NodeContact` — это `node_id[32] + transport_len[2] + transport_uri[bytes]`.

### 8.8 Защита DHT

| Атака | Что противостоит |
|-------|------------------|
| Sybil на bucket | PoW ≥ 24 на node_id |
| Eclipse /24 | Не более `K/4 = 5` контактов из одной /24 IPv4 (или /48 IPv6) в bucket |
| Отравление записей | `DhtValue.expires_at` + подпись владельцем |
| Злоупотребление DELETE | Подпись + `BLAKE3(pk) == key` |
| Дедуп seed-узлов O(n²) | Дедуп через HashSet в итеративном поиске |
| Флуд STORE | Фильтрация по шардам (опционально) |

---

## 9. Discovery: сервисные записи

Эти записи — надстройка над DHT. Каждая хранится как `DhtValue` и различается по полю `kind`:

### 9.1 AnnounceAttachmentPayload (`kind=1`)

Leaf объявляет, через какие Core-узлы к нему можно обратиться:

```
[0..32]    leaf_node_id
[32..64]   gateway_node_id
[64..72]   epoch
[72..76]   expires_at (unix seconds)
[76..78]   gateways_count
[78..]     GatewayRef[] (node_id[32] + port + weight + flags = 38 Б)
[..]       mailbox_count
[..]       MailboxRef[]
[..]       sig_len
[..]       signature
```

Ключ в DHT — `attachment_key(leaf_node_id)`. Чтобы связаться с Leaf, отправитель сначала вызывает `GetAttachment(leaf_id)` и получает Core-узлы, через которые тот принимает трафик.

### 9.2 GetAttachment / AttachmentResponse

Пара «запрос — ответ»: по node_id вернуть список gateway и mailbox.

### 9.3 MailboxSet и GetMailboxSet

`MailboxSet` — список node_id, хранящих реплики mailbox для узла `X`. Помогает офлайн-доставке.

```
GetMailboxSetPayload:  target_node_id[32] + epoch[4]
MailboxSetResponse:    count[2] + node_id[32][]
```

### 9.4 AppEndpoint и GetAppEndpoint

Привязка `(node_id, app_id, endpoint_id)` к ключу ML-KEM ek. Каждое приложение, объявляющее bind, публикует такую запись:

```
GetAppEndpointPayload:   node_id[32] + app_id[32] + endpoint_id[4]
AppEndpointResponse:     (variable) содержит адрес + ek + срок + подпись
```

### 9.5 Name service

Сопоставляет понятное человеку имя с node_id. Владелец подписывает заявку на имя и записывает её в DHT под ключом `name_key(name)`. Резолвер проверяет подпись и цепочку PoW прямо из DHT — никаких уведомлений `NameContested` нет.

---

## 10. Routing

Файл: [`crates/veil-routing/src/`](../../crates/veil-routing/src/) + [`node/dispatcher/routing.rs`](../../crates/veil-dispatcher/src/routing.rs).

### 10.1 Три уровня

1. **Слухи (gossip)** — `ROUTE_ANNOUNCE/WITHDRAW` с TTL=2, узкий радиус, который доходит только до соседей.
2. **Пересылка через DHT** — `RecursiveRelay`, который проносит сообщения через Kademlia.
3. **По запросу (on-demand)** — `ROUTE_REQUEST/RESPONSE`, чтобы явно запросить транспорты.

### 10.2 Route cache

`RouteCache` ([`routing/cache.rs`](../../crates/veil-routing/src/cache.rs)):

- Ключ: `dst_node_id`.
- Значение: набор путей, в каждом — `next_hop`, score, TTL и hop_count.
- **Адаптивная ёмкость**: базовая `MAX_ROUTE_CACHE_SIZE = 1024`, для больших сетей растёт.
- `MAX_ROUTES_PER_DST = 4`, `MAX_ROUTES_PER_VIA = 256`.
- Вытеснение по TTL, при переполнении — по LRU.

### 10.3 Scoring

Каждый путь получает сводную оценку (`RouteCache::score`):

```
score = w_rtt * rtt_ms
      + w_jitter * jitter
      + w_vivaldi * distance   // virtual coords
      + w_congestion * cong
      - w_battery * battery    // Leaf considerations
      - w_reputation * rep
```

Веса задаются в конфиге, в `routing.weights`.

### 10.4 RouteAnnounce

```
RouteAnnouncePayload:
[0..32]  origin_node_id
[32..64] via_node_id
[64]     hop_count
[65]     ttl (TTL=2 при исходной рассылке)
[66..70] sequence (u32BE монотонно у origin)
[70..72] timestamp_secs
```

**Дедупликация и защита от повтора:**
- `MAX_ROUTE_ANNOUNCE_AGE_SECS = 300` — фреймы старше отклоняются.
- `MAX_ROUTE_ANNOUNCE_SKEW_SECS = 30` — допустимое расхождение часов.
- Дедуп в два слоя: по `(origin, via, seq)` и по `(origin, seq)`.

`RouteWithdraw` устроен так же, но вместо добавления сбрасывает записи. Монотонный `sequence` обязателен — он закрывает повторы (replay).

### 10.5 Aliased announce

`RouteAnnounceAliased` и `RouteWithdrawAliased` используют 8-байтные псевдонимы сессий вместо 32-байтных node_id, что экономит пропускную способность канала слухов на коротких локальных сессиях.

### 10.6 Recursive routing

Включается, когда в route cache промах и прямой сессии до `dst` нет:

```
RecursiveRelayPayload:
[0..32]  dst_node_id
[32..64] originator_id
[64..68] query_id (u32BE — дедуп токен)
[68]     hop_count (убывает каждый hop, старт = 20)
[69..]   wrapped ForwardPayload body
```

Получив RecursiveRelay, узел делает одно из трёх:

1. Если `hop_count == 0`, кладёт сообщение в mailbox `dst_node_id` — это крайняя мера.
2. Если есть живая сессия к `dst`, распаковывает сообщение и доставляет локально.
3. Иначе ищет среди DHT-соседей ближайшего по XOR к `dst` и пересылает с `hop_count - 1`.

**Кеширование обратного пути:** успешная доставка через узел X записывает `originator_id → X` в route cache получателя, и следующие ответы идут напрямую.

### 10.7 Route request/response

Явный запрос: «кто знает транспорт для `target`?» `RouteRequestPayload` несёт ML-KEM ek запрашивающего (чтобы ответ можно было зашифровать E2E), его Ed25519 pk и подпись.

Ответ:

```
RouteResponsePayload:
target[32], requester[32], request_id[4]
transports[] (до 32 URI, MAX_TRANSPORT_ADDRS=32)
relays[]     (до 32 node_id, MAX_RELAY_IDS=32)
mlkem_pk, ed25519_pk, signature
```

### 10.8 PoW bootstrap

`PowChallenge`, `PowResponse` и `PowAccept` — для узлов без общих знакомых:

- Запрашивающий отправляет FindNode, и узел первичного подключения отвечает PoW-задачей.
- Верное решение удовлетворяет `leading_zero_bits(BLAKE3(challenge || solution)) ≥ difficulty`.
- При успехе узел присылает `PowAccept` вместе с транспортом.

### 10.9 Event-driven updates

- `RouteUpdate` (0x12) — рассылается, когда сосед подключается или отключается.
- `VersionVectorSync` (0x13) — периодическая синхронизация вектора версий (VV) для сверки состояния.

---

## 11. Delivery

Файл: [`crates/veil-dispatcher/src/delivery.rs`](../../crates/veil-dispatcher/src/delivery.rs).

### 11.1 DeliveryEnvelope

```
[0..49]    recipient       Recipient (node_id[32] + tag[1] + instance_id[16])
[49..81]   sender_node_id
[81..113]  src_app_id
[113..145] app_id          (получателя)
[145..149] endpoint_id     u32BE
[149..181] content_id      (BLAKE3 of payload)
[181..189] created_at      u64BE  (unix seconds)
[189..193] ttl_secs        u32BE
[193..197] payload_len     u32BE
[197..]    payload         bytes
```

Получатель — это `Recipient` фиксированной длины 49 байт (`encode_fixed_into`): `node_id[32]` + 1-байтный `InstanceTag` (0=Any, 1=All, 2=Specific) + 16-байтный `instance_id` (дополнен нулями для Any/All).

Плюс два 1-битных флага, которые передаются отдельно: `require_ack` и `trace_id`.

### 11.2 Пути доставки

Диспетчер пробует их по порядку:

**Путь A — прямой.** Есть живая сессия к `recipient_node_id`, и сообщение уходит прямо туда.

**Путь B — route cache.** Прямой сессии нет, но в кеше есть запись «для `recipient_node_id`, next_hop = X» — узел пересылает на X.

**Путь C — RecursiveRelay.** Ни сессии, ни записи в кеше. Узел строит `RecursiveRelayPayload` и отправляет ближайшему по XOR узлу из DHT-таблицы.

**Путь D — Mailbox.** Бюджет переходов исчерпан или получатель офлайн — сообщение оседает в почтовом ящике (или нескольких).

### 11.3 Forward

`ForwardPayload` — это просто `DeliveryEnvelope.encode()`. Получатель узнаёт себя по `recipient_node_id` и передаёт сообщение локальному приложению.

### 11.4 Transit

Ретрансляция без состояния: `TransitFramePayload` не держит состояния по каждому потоку. Так пакеты пересылаются быстро, не удерживая сессию до источника. Нужен minor ≥ 5, что сегодня выполняется всегда.

### 11.5 Chunked transfers

Для полезной нагрузки больше размера фрейма:

```
ChunkManifestPayload (92 Б):
  content_id[32], total_size[8], chunk_count[4], chunk_size[4],
  first_chunk_offset[4], sig_len[4], signature[up to 32]

ChunkPayload (20 Б header + data):
  content_id[32 — в hdr], chunk_index[4], offset[8], data_len[2], data[]
```

По манифесту получатель выделяет `ReassemblyState`, накапливает чанки и пересобирает полезную нагрузку.

### 11.6 Delivery status

`DeliveryStatusPayload` (65 байт, фиксированный размер):

```
[0..32]  content_id
[32]     status u8
         0 = ACCEPTED
         1 = DELIVERED
         2 = QUEUED
         3 = NOT_FOUND
         4 = REJECTED
         5 = EXPIRED
         6 = FETCHED
         7 = APP_ACKED
[33..65] mac [u8; 32]   (C-09 — аутентифицированный ACK; см. ниже)
```

**C-09 — аутентифицированный ACK о доставке.** `mac` — это ключевой BLAKE3-MAC от
`content_id` на ключе доставочного ACK, своём для каждого сообщения, который обе стороны выводят из
общего E2E-секрета ML-KEM (`veil_e2e::derive_ack_key`). Транзитный ретранслятор
этот секрет так и не узнаёт, поэтому валидный MAC может построить только
настоящий получатель — и отправитель начисляет репутацию за доставку **только**
при успешной проверке MAC. Если ключ ACK не был установлен (доставка не-E2E или устаревшая), поле нулевое: отправитель снимает запись из очереди ожидания, но репутацию не
начисляет. См. `handle_delivery_status` в
`crates/veil-dispatcher/src/delivery.rs`.

### 11.7 5-stage delivery FSM

На стороне отправителя (IPC-клиент) доставка проходит конечный автомат (FSM) из пяти стадий:

```
Accepted → Stored → Fetched → Delivered → AppAcked
```

Клиент следит за ней через уведомления `LocalAppMsg::DeliveryStage` и может показать статус «в пути», «доставлено» или «прочитано».

---

## 12. Mailbox (offline-доставка)

Файл: [`crates/veil-mailbox/src/`](../../crates/veil-mailbox/src/).

### 12.1 Модель

`MailboxService` принимает от Core-узлов три операции:
- **PUT** — отложить `DeliveryEnvelope` для офлайн-получателя.
- **FETCH** — получатель онлайн и забирает своё, листая с курсора `after_seq`.
- **ACK** — подтвердить, какие seq прочитаны.

Leaf почтовый ящик не хранит (`MailboxError::NotAllowed`).

### 12.2 Backend

Mailbox — фиксированное **redb**-хранилище «ключ — значение» по пути `<veil_dir>/mailbox/blobs.db`, с сериализуемыми транзакциями. Движок не сменить — ключа `backend` нет. Mailbox включается через `[mailbox] enabled = true`. Реализация: [`crates/veil-mailbox/src/lib.rs`](../../crates/veil-mailbox/src/lib.rs).

### 12.3 Квоты и лимиты

Из [`crates/veil-mailbox/src/lib.rs`](../../crates/veil-mailbox/src/lib.rs) и `crates/veil-proto/src/budget.rs`:

| Параметр | Значение |
|----------|----------|
| Global cap | 100 000 записей (абсолютный лимит) |
| Per-recipient cap | конфиг; по умолчанию 1000 |
| Per-sender daily quota | размер множества ограничен `DEFAULT_MAX_MAILBOX_SENDERS` |
| `MAX_MAILBOX_ACK_BATCH` | 256 seq за пакет |
| `MAX_MAILBOXES` | 32 ссылки на mailbox в attachment |

При переполнении новый PUT отклоняется (`status=REJECTED`), а не вытесняет старые записи. Это закрывает атаки на сохранность данных через вытеснение по гонке (race).

### 12.4 Как определяются узлы-хранители

Идея в том, что ни отправителю, ни получателю не нужно заранее знать конкретные
mailbox-хосты. Оба выводят их независимо из `recipient_node_id` через DHT.

#### Primary (attachment gateway)

При подключении получатель объявляет свой набор gateway через
`AnnounceAttachmentPayload`, подписанный ключом его личности. Запись
оседает в DHT под ключом `attachment_key(recipient_node_id)`.

Отправитель, у которого нет прямой сессии до получателя, затем:

1. Вызывает `GetAttachment(recipient_node_id)` и получает список gateway.
2. Открывает сессию к одному из них, в порядке приоритета по weight и flags.
3. Шлёт `MAILBOX_PUT` с `DeliveryEnvelope` внутри.

#### Replicas (детерминированный выбор по DHT)

Приняв PUT, primary выбирает до `replica_count - 1` дополнительных
хранителей через [`select_quorum_replicas`](../../crates/veil-dispatcher/src/delivery.rs):

```text
shard_target = BLAKE3("shard" ‖ recipient_node_id ‖ shard_id_be_bytes)
                                                    └ обычно 0 ┘
pool         = DHT.find_closest_nodes(shard_target, (replica_count - 1) × 4)
candidates   = pool.filter:
                 id != self
                 id != origin_peer (кто прислал PUT)
                 battery_level ≥ 20                  (если известен)
                 relay_success_ema ≥ 0.5             (если relay_attempts > 0)
                 not in circuit_breaker              (трекает подряд
                                                      идущие failures)
replicas     = candidates.take(replica_count - 1)
```

Главное здесь — **детерминизм**: `shard_target` и ближайшие к нему по XOR
узлы не зависят от того, кто смотрит. Любой Core-узел, зная
`recipient_node_id`, вычислит тот же target и через свой DHT выйдет на тот же
набор кандидатов (с точностью до фильтров живости). Поэтому *получатель*
и *любой будущий gateway* найдут те же реплики без дополнительного
обмена адресами.

Шардирование по `shard_id` позволяет разбить очередь одного
получателя на несколько независимых наборов реплик: `shard_id=0, 1, 2 …`
дают разные `shard_target`, а значит, и разные реплики. Это снижает
риск коррелированных отказов для крупных почтовых ящиков. На сегодня используется один шард (`shard_id=0`).

### 12.5 Репликация

`MailboxReplicationConfig`:

```toml
[mailbox.replication]
replica_count = 3         # кол-во реплик, включая primary
write_quorum  = 2         # минимум success-ов для ACK отправителю
replica_timeout_ms = 500  # таймаут на replica-write
```

#### Write-path

```
Sender ── MAILBOX_PUT ──► Primary (attachment gateway получателя)
                          │
                          ├─ сохранить локально (InMemory или WAL backend)
                          ├─ select_quorum_replicas(recipient) → [R1, R2]
                          │   (зашифровать envelope — см. §12.6)
                          ├─ MAILBOX_REPLICATE ──► R1
                          ├─ MAILBOX_REPLICATE ──► R2
                          │   ожидать DeliveryStatus::QUEUED
                          │   timeout = replica_timeout_ms
                          │
                          └─ ≥ write_quorum успехов?
                                да  → DeliveryStatus::QUEUED sender'у
                                нет → DeliveryStatus::REJECTED sender'у
```

При `replica_count = 1` шаг с репликами пропускается, и PUT живёт только на primary.

#### Read-path

```
Recipient онлайн ── MAILBOX_FETCH(after_seq) ──► Primary gateway
                                                 │
                                                 ├ SEC-проверка:
                                                 │  payload.recipient_node_id
                                                 │  == authenticated peer_id
                                                 │  (иначе Violation)
                                                 │
                                                 ├ backend.fetch(recipient, after_seq)
                                                 │   непусто? → вернуть entries
                                                 │
                                                 ├ (пусто) Если mailbox_dht_replication:
                                                 │   DHT.get_local(recipient) → envelope
                                                 │
                                                 └ (всё ещё пусто) try_fetch_from_replicas:
                                                   ├─ те же replica_ids через select_quorum_replicas
                                                   ├─ fan-out: MAILBOX_FETCH_REPLICA на каждую
                                                   ├─ первый непустой ответ → entries
                                                   └─ все пусто / таймаут → empty response
```

После `MAILBOX_FETCH` клиент отправляет `MAILBOX_ACK { recipient, seqs[] }`.
Primary удаляет подтверждённые seq локально; до реплик Ack доходит
лениво, а сами реплики чистятся сборщиком мусора (GC) по TTL.

**Почему это безопасно:**
- Забрать сообщения может только аутентифицированный получатель — за счёт проверки
  `recipient_node_id == peer_id`.
- Исходный `sender_node_id` в конверте знает только первоначальный отправитель —
  это проверяется в `MAILBOX_PUT::handle_put`.
- Реплики держат конверт зашифрованным (см. §12.6), поэтому не могут прочитать
  полезную нагрузку, даже если их скомпрометировать.

### 12.6 Envelope encryption для реплик

Хосту-реплике незачем видеть содержимое, поэтому конверт шифруется прямо перед `MAILBOX_REPLICATE`:

```
encrypted_blob = ChaCha20-Poly1305.Seal(
    key  = HKDF(primary_mlkem_dk, info="replica-v1"),
    aad  = recipient_node_id || seq,
    plaintext = DeliveryEnvelope.encode()
)
```

Реплика хранит blob как есть; при fetch primary расшифровывает его обратно.

### 12.7 WAL-структура

WAL — это последовательность строк, дописываемых только в конец (append-only):

```
magic[4] + version[1] + op_type[1] + len[4] + body[len] + crc32[4]
```

`op_type` — это Put, Ack или Compact. При старте узел проигрывает журнал заново и восстанавливает текущее состояние. Как только `wal_size > compact_threshold` (по умолчанию 64 MiB), запускается уплотнение (compaction): оно делает снимок активных записей и удаляет старый WAL.

---

## 13. Peer Exchange (PEX)

Файл: [`crates/veil-pex/src/`](../../crates/veil-pex/src/). Family 11.

### 13.1 Задача

PEX собирает свежие транспорт-адреса соседей, чтобы узел мог открыть прямое соединение, а не идти в несколько переходов через ретранслятор. Работает по модели **случайного блуждания (random-walk) + PoW**.

### 13.2 Протокол (4 фрейма)

1. **Walk** (инициатор → seed). Содержит `walk_id`, `origin_pubkey`, `origin_nonce`, TTL и подпись.
2. **Challenge** (терминатор → инициатор). PoW-задача с нужной сложностью.
3. **Response** (инициатор → терминатор). Решение PoW и `origin_sig` (Ed25519 или Falcon512 — выбор алгоритма через `verify_message`).
4. **Result** (терминатор → инициатор). Список записей о соседях — node_id и транспортные URI.

### 13.3 Подпись

`verify_origin_sig` поддерживает и Ed25519, и Falcon512:

```rust
let algo = if pubkey.len() == 32 {
    SignatureAlgorithm::Ed25519
} else {
    SignatureAlgorithm::Falcon512
};
verify_message(algo, pubkey_b64, msg, signature)
```

### 13.4 Параметры

- `pex.walk_interval_secs` — как часто узел начинает блуждание.
- `pex.max_hops` — TTL случайного блуждания.
- Сложность PoW — задаётся `AdaptiveParams` и ниже, чем у PoW личности, ведь она на одно блуждание, а не на узел.

---

## 14. Mesh (локальная UDP-сеть)

Файл: [`crates/veil-mesh/src/`](../../crates/veil-mesh/src/). Family 5.

### 14.1 Сценарий

IoT-устройство или любой узел без интернета всё ещё может:
- Найти соседей локально через UDP multicast или broadcast.
- Передать сообщение в глобальный Veil через mesh-мост — Core-узел с `CAN_GATEWAY_LOCAL_MESH`.

### 14.2 MeshBeacon

```
MESH_BEACON_SIZE = 48 + extension
[0..32]  node_id
[32..48] realm_id (UUID)
[48..]   extension (v2):  transport_count + transport_len + transport_uri + algo + pubkey + sig
```

Узел шлёт маяк каждые `DEFAULT_BEACON_INTERVAL` (30 с). Маяк живёт `BEACON_WINDOW = 60 с`; устарев, он удаляется из кеша соседей.

### 14.3 MeshFrame

```
MESH_HEADER_SIZE = 83 Б:
[0..16]  realm_id
[16..48] sender
[48..80] destination
[80]     hop_count
[81..83] payload_len u16BE
[83..]   payload
```

Пересылается в пределах realm'а через `MeshForwarder`.

### 14.4 Realm

`Realm` — логическая группа mesh-узлов, заданная UUID. Один физический сегмент может содержать несколько realm'ов, и узел игнорирует маяки из любого realm'а, кроме своего.

### 14.5 Gateway bridge

Core-узел с `CAN_GATEWAY_LOCAL_MESH`:
- На mesh-стороне слушает UDP-маяки и mesh-фреймы.
- Из mesh в Veil: достаёт `DeliveryEnvelope` из `MeshFrame.payload` и подаёт его в свой диспетчер.
- Из Veil в mesh: когда `recipient_node_id` — известный mesh-сосед, упаковывает сообщение в `MeshFrame` и шлёт по UDP.

---

## 15. NAT traversal

Файл: [`crates/veil-nat/src/`](../../crates/veil-nat/src/).

### 15.1 Шаги

```
Idle → Discovering → Exchanging → Punching ─┬→ Connected (прямое соединение)
                                            ├→ Relaying  (через Core)
                                            └→ Failed
```

### 15.2 Кандидаты ICE

Берутся из `NatCandidate`, по образцу RFC 8445:

- `HOST` — локальный интерфейс (наивысший приоритет: `type_pref=126`).
- `SRFLX` — server-reflexive, полученный из STUN-echo от Core (`type_pref=100`).
- `RELAY` — туннель ретрансляции через Core (`type_pref=0`).

Формула приоритета:
```
priority = (2^24 * type_pref) + (2^8 * local_pref) + (256 - component_id)
```
Используется арифметика с насыщением (saturating) ([`nat/coordinator.rs::ice_priority`](../../crates/veil-nat/src/discovery.rs)).

### 15.3 Обмен

```
Alice → Core:  NatProbeRequest(session_token, Alice_candidates)
Core → Bob:    NatProbeRequest с Alice_candidates
Bob → Core:    NatProbeReply(Bob_candidates)
Core → Alice:  NatProbeReply с Bob_candidates
Alice ↔ Bob:   QUIC connect на все кандидаты параллельно
```

`NatPuncher::punch` параллельно перебирает все пары кандидатов в пределах `punch_timeout_ms`; первое удавшееся рукопожатие становится `PunchResult::Direct(conn)`.

### 15.4 Relay fallback

Если получился `PunchResult::TimedOut`:

```
Alice → Core: NatRelayRequest(Alice, Bob, session_token)
Core opens ForwardTunnel(Alice ↔ Bob, token=session_token)
```

Дальше Core пересылает `DeliveryMsg::Forward` между ними.

### 15.5 Local relay

Если глобального Core нет, но локальный Gateway объявляет `IS_RELAY` во flags своего mesh-маяка, `NatCoordinator::preferred_signal_peer` возвращает именно его:

```
priority: local_relay > global_core > None
```

`LOCAL_RELAY_TIMEOUT_SECS = 3` — сколько узел ждёт локальную ретрансляцию, прежде чем уйти на запасной путь через Core.

---

## 16. Anti-abuse и защита

### 16.1 Стек защиты на inbound-соединении

```
1. IP filter (bans)
2. Per-IP session limit (MAX_SESSIONS_PER_IP = 32)
3. PoW challenge (если configured)
4. Handshake timeout
5. Per-peer token bucket (rate limiter)
6. Violation tracker (5 violations → ban)
7. Ban list (TTL, max 8192)
8. Congestion backpressure (>78% → drop transit)
9. Reputation gate (MIN_REPUTATION_FOR_TRANSIT = 200)
```

### 16.2 Bandwidth / rate limits

[`abuse/bandwidth_gate.rs`](../../crates/veil-abuse/src/bandwidth_gate.rs) + [`abuse/per_peer_limiter.rs`](../../crates/veil-abuse/src/per_peer_limiter.rs):

- Корзина токенов на каждого соседа: скорость пополнения и размер всплеска берутся из конфига.
- Сброс при опустошении увеличивает счётчик нарушений.
- `MAX_PER_PEER_LIMITER_SIZE = 8192` ограничивает, сколько соседей отслеживается одновременно.

### 16.3 Violation tracker

`MAX_VIOLATION_TRACKER_SIZE = 8192`. Категории нарушений, среди прочих:
- `BadFrame` — неверный формат в канале.
- `SenderMismatch` — отправитель в конверте не совпадает с аутентифицированным соседом.
- `PoWFail` — неверное решение.
- `RateExceeded` — корзина токенов пуста.
- и другие.

Как только сосед набирает `VIOLATION_THRESHOLD = 5` в окне `VIOLATION_WINDOW_SECS = 300`, он попадает в бан.

### 16.4 Ban list

`MAX_BAN_LIST_SIZE = 8192`. TTL берётся из конфига (`abuse.default_ban_secs`). Список сохраняется на диск в `bans.json` в каталоге данных.

### 16.5 Congestion backpressure

`node/congestion.rs`:

- Метрика нагрузки: `load_pct = (cpu_usage * 0.5) + (memory_usage * 0.3) + (queue_depth * 0.2)`.
- Выше **50%** узел вдвое урезает адаптивный веер рассылки (fan-out).
- Выше **78%** он отбрасывает фреймы TRANSIT и RECURSIVE_RELAY; обычная доставка идёт дальше.
- Чтобы давить активно, узел шлёт управляющий фрейм `Backpressure` с просьбой к соседу сбавить темп.

### 16.6 Reputation

[`node/reputation.rs`](../../crates/veil-reputation/src/lib.rs):

- Начальный score: 0.
- Uptime: +1 / час.
- Successful relay: +0.1.
- Failed relay: -1.
- Peer vouch (`ReputationAttestation`): +5.
- Transit gate: `MIN_REPUTATION_FOR_TRANSIT = 200.0`.

Свежий узел не может сразу пересылать чужой трафик — это барьер холодного старта (cold-start).

### 16.7 PoW challenge на connection

Опционально, для усиления рукопожатия:

```
Server → Client: PowChallenge(challenge_nonce[32], difficulty)
Client → Server: PowResponse(solution) где BLAKE3(challenge||solution) имеет ≥ difficulty нулевых битов
```

Ограничения:
- `MAX_POW_DIFFICULTY = 24` — сервер не может потребовать больше.
- `MAX_CONCURRENT_POW_SOLVERS = 4` — предел того, сколько клиент решает параллельно.

---

## 17. Адаптивные параметры

Файл: [`crates/veil-cfg/src/adaptive.rs`](../../crates/veil-cfg/src/adaptive.rs).

### 17.1 Оценка размера сети

Узел оценивает `N`, размер сети, по трём признакам:

1. По своей DHT-таблице — числу bucket'ов, где есть хотя бы один контакт.
2. По `EpochDifficultyRecord` из DHT, который публикуют узлы первичного подключения.
3. По ответам FindNode — а именно по размеру возвращаемых списков.

### 17.2 Масштабируемые параметры

| Параметр | Формула | Min | Max |
|----------|---------|-----|-----|
| PoW difficulty | `24 + ceil(log2(N / 100_000))` | 24 | — |
| Fan-out (epidemic) | `ceil(log2(N))` | 2 | 16 |
| DHT α (параллелизм) | 3 при N < 100k, 4 при N ≥ 1M | 3 | 5 |
| Route cache size | `1024 + N / 1000` | 1024 | 65536 |
| Mailbox cap | `100_000` | — | — (жёсткий) |
| Ban TTL | `60 * 60 * (1 + log10(N))` | 1 час | 24 часа |

### 17.3 Синхронизация

`NodeRuntime::tick` периодически обновляет `AdaptiveParams`. Изменения применяются лениво, поэтому никогда не прерывают уже идущую сессию.

---

## 18. App layer и IPC

### 18.1 Модель

Приложение — клиент CLI, пользовательский бот или GUI — работает так:

```
App process ──Unix socket (JSON-L / binary)──► veild (node)
                                                   ↓
                                               OVL1 network
```

Сокет по умолчанию: `/run/veil/ipc.sock` или `$XDG_RUNTIME_DIR/veil/ipc.sock`.

### 18.2 Address: AppAddress

```
AppAddress {
    node_id:     [u8; 32],   // Какой узел держит приложение
    app_id:      [u8; 32],   // derive_key("veil.app_id.v1", node_id || ns_len(4) || ns
                             //            || name_len(4) || name) — см. §1.2 protocol-spec
    endpoint_id: u32,        // "Порт" внутри приложения (1..65535)
}
```

**namespace** и **name** — UTF-8-строки на выбор разработчика (по соглашению — обратный DNS
вида `"com.example.chat"` + `"main"`), до 255 байт каждая. Префикс длины и разделитель доменов
(`"veil.app_id.v1"`) защищают от коллизий со сдвигом при склейке, когда две разные
пары `(namespace, name)` иначе дали бы одинаковый дайджест.

Для IPC-приложений привязка по умолчанию **эфемерная**: узел подмешивает 16-байтный
`client_token` (выдан в `AppHelloOk`) и отдельный разделитель доменов
(`"veil.ephemeral_app_id.v1"`), так что два процесса на одном узле получают
разные `app_id` при одинаковых `(namespace, name)`. Общеизвестные сервисы
(`bind_named`) используют стабильную форму, без токена.

### 18.3 IPC protocol

Family 6 (LocalApp). Последовательность:

```
Client → Node: AppHello (version=1)
Node → Client: AppHelloOk
Client → Node: AppBind(namespace, name, endpoint_id)
Node → Client: AppBindOk(app_id)
  [client listens для AppDeliver]
Client → Node: AppIpcSend(recipient, payload)  или StreamOpen(...)
Node → Client: AppDeliver(envelope)
Client → Node: AppUnbind
```

Типы из `LocalAppMsg`:

| Тип | ID | Направление | Назначение |
|-----|----|-------------|------------|
| AppHello | 0 | → | Hello (версия) |
| AppHelloOk/Err | 1/2 | ← | Ответ |
| AppBind | 3 | → | Привязать эндпоинт |
| AppBindOk/Err | 4/5 | ← | Ответ |
| AppUnbind | 6 | → | Отвязать |
| AppDeliver | 7 | ← | Входящее сообщение |
| AppIpcSend | 8 | → | Однократная посылка |
| AppSendOk | 9 | ← | Накопление отправлено (local) |
| StreamOpen | 10 | → | Открыть двусторонний поток |
| StreamOpenOk/Err | 11/12 | ← | Ответ |
| StreamData | 13 | → / ← | Данные потока |
| StreamClose | 14 | → / ← | Закрыть |
| StreamWindow | 15 | → / ← | Flow-control update |
| StreamRtData | 16 | → / ← | Real-time данные |
| AppSendFailed | 17 | ← | Permanent failure (MAX_DELIVERY_ATTEMPTS) |
| AppRtSend | 18 | → | Real-time отправка |
| DeliveryStage | 19 | ← | 5-stage FSM notification |
| AnycastResolve | 20 | → | Anycast-резолвер |
| AnycastResult | 21 | ← | Ответ anycast |

### 18.4 App messages over wire (Family 4)

На стороне Veil приложения общаются друг с другом через:

- `AppOpen(app_id, endpoint_id, initial_window)` — открыть поток.
- `AppData(data, ack?)` — нести данные.
- `AppWindowUpdate(bytes)` — управление потоком.
- `AppClose(reason)` — закрыть поток.
- `AppRtData` — real-time-фрейм (приоритет REALTIME, без ACK).
- `AppReceipt` — подтвердить доставку.

### 18.5 Anycast

Anycast разрешает имя сервиса в любой node_id, который привязал эндпоинт под этим именем:

```
Client → Node: AnycastResolve(service_name)
Node: ищет в DHT по anycast_key(service_name) → получает candidate-список → выбирает closest
Node → Client: AnycastResult(node_id + endpoint)
```

### 18.6 E2E в IPC

Клиент запрашивает E2E, выставив `encrypt: true` в `AppIpcSend`. Тогда узел:

1. Берёт ML-KEM ek получателя из DHT (`GetAppEndpoint`).
2. Оборачивает полезную нагрузку в `E2eEnvelope` с маркером `0xE2`.
3. Упаковывает это в `DeliveryEnvelope` и отправляет.

Флаг `anonymous: true` переключает на `META_E2E_MARKER (0xE3)`, который скрывает отправителя.

---

## 19. Наблюдаемость

### 19.1 Prometheus metrics

Endpoint: `GET /metrics` на `metrics.listen` из конфига (путь по умолчанию `/metrics`,
переопределяется `metrics.path`).

Каждая метрика лежит в [`observability.rs::render_prometheus`](../../crates/veil-observability/src/lib.rs) и несёт префикс `veil_`.
Ниже основные группы (полный список — см. [admin-guide.md](admin-guide.md#доступные-счётчики)):

- Transport: `veil_active_sessions`, `veil_inbound_sessions_total`,
  `veil_transport_bytes_rx_total`, `veil_transport_bytes_tx_total`.
- Session: `veil_session_handshake_failures_total`, `veil_session_tx_drops_total`.
- Delivery: `veil_delivery_rejects_total`, `veil_chunks_reassembled_total`.
- DHT / Routing: `veil_dht_store_total`, `veil_dht_lookup_total`,
  `veil_route_cache_hits_total`, `veil_route_miss_total`,
  `veil_recursive_relay_initiated_total`.
- Routing quality: `veil_route_selection_avg_rtt_ms`,
  `veil_vivaldi_prediction_error_ms`, `veil_vivaldi_coord_{x,y,height,error}`.
- Abuse: `veil_rate_limit_drops_total`, `veil_ban_actions_total`.
- Real-time: `veil_rt_frames_{rx,tx}_total`, `veil_rt_seq_gaps_total`.

### 19.2 Логи

По умолчанию логи — структурированные текстовые строки:

```
[timestamp] LEVEL event.name field1=val1 field2=val2 ...
```

Чтобы переключиться на JSON-L, задайте в конфиге `logging.format = "json"`.

Уровни: ERROR, WARN, INFO, DEBUG, TRACE. Фильтруются через `RUST_LOG` или `logging.filters`.

### 19.3 Debug capture

`veil-cli debug capture --output FILE` пишет JSON-поток фреймов в том порядке, в каком они идут по каналу. Принимает `--node-id HEX`, `--family N` и `--limit N`, чтобы сузить захват.

### 19.4 DiagPing / TraceRoute

Family 9 (Diag):

- `DiagPing/DiagPong` — сквозной замер времени туда-обратно (RTT) через Veil.
- `TraceProbe/TraceHop` — traceroute по переходам. Каждый переход уменьшает TTL, и при `TTL=0` узел шлёт `TraceHop` обратно со своим `node_id`.

### 19.5 Trace buffer

Кольцевой буфер в памяти на последние `TRACE_BUFFER_SIZE = 1024` событий диспетчеризации. Рантайм использует его внутри себя; отдельной admin-команды на чтение нет. Это состояние наблюдается через метрики и `veil-cli debug capture`.

---

## 20. Runtime и структура процесса

### 20.1 Структура `NodeRuntime`

[`crates/veil-node-runtime/src/lib.rs`](../../crates/veil-node-runtime/src/lib.rs). Основные поля:

```rust
pub struct NodeRuntime {
    config:           Arc<RwLock<cfg::Config>>,
    local_identity:   Arc<LocalIdentity>,
    session_registry: Arc<Mutex<SessionRegistry>>,
    dispatcher:       Arc<FrameDispatcher>,
    dht:              Arc<KademliaService>,
    mailbox:          Arc<MailboxService>,
    route_cache:      Arc<RwLock<RouteCache>>,
    ban_list:         Arc<Mutex<BanList>>,
    metrics:          Option<Arc<NodeMetrics>>,
    // ... ещё ~70 полей (см. `struct NodeServices` в runtime.rs)
}
```

Клонировать дёшево, поскольку всё спрятано за `Arc`.

### 20.2 Жизненный цикл

```
Config::load → ResolvedConfig → NodeRuntime::new
  ├── listener_supervisor запускает TCP/QUIC/WS listeners
  ├── dispatcher регистрирует handlers per-family
  ├── periodic tasks (tokio::spawn):
  │     ├── keepalive_tick (выбор сессии → Keepalive)
  │     ├── mailbox_gc (expire old entries)
  │     ├── dht_refresh (bucket refresh, republish)
  │     ├── route_cache_gc
  │     ├── lazy_miner (PoW mining if enabled)
  │     ├── pex_walker
  │     ├── ban_list_persist
  │     ├── mesh_beacon_send / mesh_beacon_recv
  │     └── metrics_scrape
  └── NodeRuntime::run — main loop (сейчас пустой: всё в tasks)
```

### 20.3 FrameDispatcher

[`crates/veil-dispatcher/src/lib.rs`](../../crates/veil-dispatcher/src/lib.rs):

```rust
pub fn dispatch(&self, hdr: &FrameHeader, body: &[u8], peer: PeerContext) -> DispatchResult {
    match FrameFamily::try_from(hdr.family)? {
        FrameFamily::Session    => self.session.dispatch(...),
        FrameFamily::Control    => self.control.dispatch(...),
        FrameFamily::Discovery  => self.discovery.dispatch(...),
        FrameFamily::Delivery   => self.delivery.dispatch(...),
        FrameFamily::Routing    => self.routing.dispatch(...),
        // ...
    }
}
```

`DispatchResult` бывает одним из:
- `NoResponse` — обработано, отвечать нечем.
- `Reply(bytes)` — отправить ответный фрейм.
- `Violation(reason)` — увеличить счётчик нарушений и, возможно, разорвать соединение.
- `Disconnect(reason)` — закрыть сессию.

### 20.4 SessionRunner

[`node/session/runner.rs`](../../crates/veil-session/src/runner.rs) запускает по одной async-задаче на сессию. Каждая задача:

1. Читает байты из транспорта.
2. Вызывает `decode_header` и получает `FrameHeader`.
3. Если `body_len > MAX_FRAME_BODY`, фиксирует нарушение и разрывает соединение.
4. Расшифровывает тело через AEAD.
5. Передаёт его в `dispatcher.dispatch` — синхронный вызов, без await.
6. Берёт `DispatchResult` и действует по нему (Reply, Disconnect и так далее).

Исходящие фреймы уходят через `SessionTxRegistry`:
- Планировщик **взвешенного кругового обхода (WRR, weighted round-robin)** на сессию, по 4 приоритетам (RealTime w=8, Interactive w=4, Bulk w=2, Background w=1).
- Очередь на отправку защищена от переполнения: как только `len > MAX_QUEUE_DEPTH` (по умолчанию 1000), фрейм отбрасывается или включается обратное давление.

### 20.5 Шаблоны блокировок

- Всё разделяемое состояние спрятано за `Arc<Mutex<_>>` или `Arc<RwLock<_>>`.
- Правило: **никаких вложенных блокировок** — взять блокировку, сделать работу, отпустить. Это не пускает дедлоки.
- Горячие пути вроде диспетчеризации никогда не держат блокировку через `.await`.
- Для метрик — атомарные счётчики (`Arc<AtomicU64>`).

### 20.6 Admin interface

Admin-интерфейс — это Unix-сокет из `global.admin_socket` (конфигурируется как `unix:///path`).
Он говорит на JSON поверх Unix-сокета (UDS), а CLI `veil-cli` оборачивает его. Ключевые подкоманды:

- `node show` — общее состояние (время работы, сессии, роль).
- `node health` — счётчик тиков, число сессий и статус цикла.
- `node metrics` — снимок всех счётчиков и датчиков (gauge).
- `node listens` — активные слушатели; `node routes` — route cache.
- `node dht list / get KEY / put KEY VALUE / routing` — осмотр DHT и ручное изменение.
- `node discovery-list`, `node gateway-list` — записи attachment и gateway.
- `sessions list / kill LINK_ID` — активные сессии.
- `peers list / add / del / ban / unban / banned` — управление соседями и банами.
- `debug ping / trace / capture / peers connect / node accept` — диагностика.
- `node stop / restart / reload` — управление жизненным циклом.

Полный список подкоманд — `veil-cli --help` и [admin-guide.md](admin-guide.md).

### 20.7 Конфигурация

[`docs/config-reference.md`](config-reference.md) — полная таблица опций.

Формат — TOML, а путь к файлу печатает `veil-cli config locate`. Ключевые секции:

- `[global]` — `admin_socket`, `runtime_flavor`, логирование (`logs`, `log_file`, `log_level`, `log_format`).
- `[Identity]` — `algo`, `public_key`, `private_key`, `nonce`, `node_id`, `names[]`.
- `listen = [...]` / `peers = [...]` — на верхнем уровне (не секции): транспортные слушатели и статические соседи.
- `[dht]` — `k`, `alpha`, `vivaldi_weight`, `shard_filtering`, `max_store_entries`, `cold_store_path` (дисковый холодный уровень RocksDB, за feature `rocksdb-cold`).
- `[routing]` — параметры слухов и кеша, включая `vivaldi_persist_path`.
- `[session]` — `keepalive_interval_secs`, `idle_timeout_secs`, `rekey_bytes_threshold`, `rekey_time_threshold_secs`.
- `[mailbox]` — `enabled`, квоты (`quota_per_receiver_bytes`/`quota_global_bytes`/`quota_per_sender_bytes`), `ttl_secs`, `require_capability_token`; хранилище — фиксированный redb-KV (без выбора `backend`).
- `[abuse]` — `rate_limit_fps`, `ban_threshold`, `pow_min_difficulty`.
- `[nat]` — параметры пробивания соединения и STUN.
- `[mesh]` — параметры маяка и realm'а.
- `[pex]` — обнаружение через случайное блуждание.
- `[ipc]` — путь Unix-сокета для локальных приложений.
- `[proxy]` — выходной SOCKS5.
- `[gateway]` — `enabled`, политика attachment.
- `[metrics]` — `listen`, `path`.

Полное описание — [config-reference.md](config-reference.md).

---

## Приложения

### A. Ссылки на ключевые модули

| Подсистема | Модуль | Ключевые типы |
|------------|--------|---------------|
| Wire-протокол | `veil-proto` | `FrameHeader`, `FrameFamily`, `*Msg` enums |
| Session handshake | `veil-session` (`handshake.rs` + `fsm.rs`) | `perform_ovl1_handshake`, `SessionFsm`, `SessionKeys` |
| Session runner | `veil-session` (`runner.rs`) | `SessionRunner`, `SessionTxRegistry` |
| Dispatcher | `veil-dispatcher` | `FrameDispatcher`, `DispatchResult` |
| DHT | `veil-dht` | `KademliaService`, `RoutingTable`, `IterativeParams` |
| Discovery | `veil-discovery` | `DirectoryService`, `AnnounceAttachmentPayload` |
| Routing | `veil-routing` | `RouteCache`, `RouteAnnouncePayload` |
| Mailbox | `veil-mailbox` | `MailboxService` (redb) |
| NAT | `veil-nat` | `NatCoordinator`, `NatPuncher`, `RelayFallback` |
| Mesh | `veil-mesh` | `MeshForwarder`, `BeaconSender` |
| PEX | `veil-pex` | dispatcher, initiator |
| Anti-abuse | `veil-abuse` | `BanList`, `ViolationTracker`, `PerPeerLimiter` |
| Transport | `veil-transport` | `TransportUri`, `TcpTransport`, `QuicTransport` |
| E2E | `veil-e2e` + `veil-crypto` | `E2eEnvelope` |
| Config | `veil-cfg` | `Config`, `SessionConfig`, `DhtConfig`, `MetricsConfig` |
| Runtime | `veil-node-runtime` | `NodeRuntime` |

### B. Ключевые численные константы (по состоянию текущего репозитория)

```text
MAGIC              = "OVL1" (0x4F564C31)
OVL1_MINOR         = 1
FRAME_HEADER_SIZE  = 24
MAX_FRAME_BODY     = 16 MiB (default listener cap 1 MiB)

DHT K              = 20
DHT ALPHA          = 3
DHT MAX_ROUNDS     = 20
MAX_NEIGHBOR_TABLE = 256

POW baseline       = 24 bits (prod), 16 bits (debug)
MAX_POW_DIFFICULTY = 24
POW solvers cap    = 4

REKEY_BYTES        = 128 GiB   (config: [session] rekey_bytes_threshold)
REKEY_TIME         = 32 days   (config: [session] rekey_time_threshold_secs)
TICKET_TTL         = 3600 s / MAX 7200 s

Mailbox global cap = 100 000
Mailbox ACK batch  = 256
Replica default    = 3, quorum 2, timeout 500 ms

Bans max           = 8 192
Violations max     = 8 192
Per-peer limit max = 8 192
MAX_SESSIONS_PER_IP = 32

Congestion thresholds = 50% (halve fan-out), 78% (drop transit)
Reputation transit    = 200
MAX_PEER_PUBKEYS_CACHE = 65 536
MAX_PEER_MLKEM_CACHE   = 4 096
MAX_PEER_VIVALDI_CACHE = 32 768

Local relay timeout = 3 s
Beacon interval     = 30 s / window 60 s
```
