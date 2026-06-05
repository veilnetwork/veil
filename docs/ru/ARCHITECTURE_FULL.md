# Veil — подробное устройство сети

Документ описывает архитектуру сети Veil (протокол OVL1) на уровне, достаточном для самостоятельной реализации совместимого узла или аудита безопасности. Все числовые константы и структуры взяты напрямую из `veilcore/src/` по состоянию репозитория.

> Для обзорного введения см. [ARCHITECTURE.md](ARCHITECTURE.md). Для wire-формата по полям — [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md) и [protocol-spec.md](protocol-spec.md).

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

Veil — децентрализованная P2P-сеть для передачи сообщений между приложениями. Ключевые свойства:

- **Стабильные идентификаторы.** `node_id = BLAKE3(public_key)` — 32 байта, не зависит от IP, NAT, транспорта.
- **Криптография.** Ed25519 или Falcon-512 (опционально PQ) для подписей; X25519 ephemeral DH в handshake → ChaCha20-Poly1305 AEAD на канальном уровне; ML-KEM-768 для E2E поверх (см. §7).
- **E2E-шифрование.** ML-KEM-768 на прикладном уровне; релеи видят только шифртекст.
- **DHT-маршрутизация.** Kademlia (K=20, α=3) обеспечивает O(log N) поиск и рекурсивную доставку.
- **Множественные транспорты.** TCP, TLS, QUIC, WebSocket (ws/wss), Unix-socket, SOCKS5 с обёртками.
- **NAT traversal.** ICE-подобный hole-punching + relay-fallback через Core-узел.
- **Mailbox.** Получатель офлайн → сообщение сохраняется на Core-узлах с WAL-репликацией.
- **Локальная mesh-сеть.** UDP-бакон + realm-bridge для сегментов без интернета.
- **Защита от Sybil.** PoW ≥ 24 бит (адаптивно) на идентификатор узла.
- **Защита от flood.** Per-peer token bucket → violation tracker → ban list; congestion backpressure.

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

По умолчанию — `Core`. Роль фиксируется в конфиге; одна роль на процесс. В обменных пакетах (`CapabilitiesPayload.roles_supported`) фиксируется битовая маска:

```
bit 0 — LEAF
bit 3 — CORE
```

Биты `1 (RELAY)`, `2 (GATEWAY)`, `4 (CORE_ROUTER)` исторически были самостоятельными ролями, удалены.

### Флаги возможностей

`CapabilitiesPayload.flags` (1 байт) — `cap_flags` из [`proto/session.rs`](../../crates/veil-proto/src/session.rs):

| Бит | Константа | Смысл |
|-----|-----------|-------|
| 0 | `CAN_RELAY` | Готов форвардить чужой трафик |
| 1 | `CAN_MAILBOX` | Готов принимать Mailbox-записи |
| 2 | `CAN_GATEWAY_LOCAL_MESH` | Работает как bridge между mesh и veil |
| 3 | `CAN_PARTICIPATE_DHT` | Участвует в DHT-таблице |
| 4 | `CAN_ACCEPT_APP_STREAMS` | Принимает AppOpen/AppData |
| 5 | `CAN_STORE` | Хранит DHT-значения локально |
| 6 | `SUPPORTS_TRANSIT` | Умеет `DeliveryMsg::Transit` (stateless relay) |

Для Core-узла дефолт: `CAN_RELAY | CAN_PARTICIPATE_DHT | CAN_STORE | CAN_MAILBOX`. Для Leaf — всё в ноль (пассивный потребитель).

---

## 3. Идентификация: node_id, PoW, ключи

### 3.1 node_id

```
node_id = BLAKE3(raw_public_key_bytes)        // 32 байта
```

Хешируются сырые байты publickey (не base64-строка). Отображается в CLI/конфиге как 64-символьный hex.

### 3.2 Алгоритмы подписи

- **Ed25519** — 32-байтный pubkey, 64-байтная signature. Быстрый, классический.
- **Falcon-512** — ≈897-байтный pubkey, ≈666-байтная signature. Постквантовый; используется на узлах с требованием PQ.

Конфигурируется через `[identity] algo = "ed25519" | "falcon512" | "ed25519+falcon512" | "ed25519+falcon1024"`. Перечисление — `veil_types::SignatureAlgorithm`.

На wire-уровне `algo` передаётся байтом. Конвенция в `IdentityPayload` / mesh-beacon:

```
algo = 0  — Ed25519
algo = 2  — Falcon-512
algo = 3  — Ed25519+Falcon-512 hybrid
algo = 4  — Ed25519+Falcon-1024 hybrid
```

(DHT `DeletePayload` сейчас принимает только `0`/`2`, поэтому записи с гибридной подписью пока нельзя удалить самостоятельно.)

В session handshake исторически используется `algo = 1 → Ed25519` (см. `handshake::algo_to_u8`).

### 3.3 Proof-of-Work (Sybil-защита)

Каждый `node_id` должен иметь подтверждение PoW: требование `leading_zero_bits(BLAKE3(pubkey ∥ nonce ∥ sign(pubkey, nonce))) ≥ difficulty`.

- **Базовая difficulty:** 24 бита (production) / 16 бит (debug-builds). См. [`identity_policy.rs`](../../crates/veil-cfg/src/identity_policy.rs).
- **Максимум:** `MAX_POW_DIFFICULTY = 24` (из [`proto/budget.rs`](../../crates/veil-proto/src/budget.rs)).
- **Адаптивная difficulty:** `24 + ceil(log2(N / 100_000))`, где `N` — оценка размера сети. Публикуется как `EpochDifficultyRecord` в DHT (эпоха — unix-день).
- **Recommended production:** `RECOMMENDED_PRODUCTION_POW_DIFFICULTY = 16` — минимум на прод-среде.
- **Concurrent solvers:** `MAX_CONCURRENT_POW_SOLVERS = 4` — ограничение fork-атаки через множество кандидатов.

Майнинг — `identity_ops.rs` / `cmd/identity/mine.rs` / ленивый миннер `node/lazy_miner.rs`.

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

Чувствительные типы (`Base64PrivateKey`, `PowParams`, `SessionKeys`) имеют custom `Debug` с редактированием.

---

## 4. Транспортный уровень

Файл: [`crates/veil-transport/src/`](../../crates/veil-transport/src/).

### 4.1 Поддерживаемые URI-схемы

Парсер — [`transport/uri.rs`](../../crates/veil-transport/src/uri.rs), enum `TransportUri`:

| Схема | Описание |
|-------|----------|
| `tcp://host:port` | Сырой TCP |
| `tls://host:port?sni=...&alpn=...` | TLS поверх TCP (BoringSSL по умолчанию, rustls — fallback) |
| `quic://host:port?sni=...&alpn=...` | QUIC через `quinn` |
| `unix:///path` | Unix domain socket |
| `socks://proxy/target` | TCP через SOCKS5 |
| `sockstls://proxy/target` | TLS через SOCKS5 |
| `ws://host:port/path` | WebSocket-обёртка над TCP |
| `wss://host:port/path` | WebSocket + TLS |

Комбинируются через `TransportStack::Wrapped { lower, wrapper }` — например, `sockstls://` → `Wrapped(Wrapped(Tcp, Socks), Tls)`.

### 4.2 Back-ends и отпечатки

- **`TransportBackendKind`**: BoringSSL (feature `tls-boring`) — TLS-бэкенд **по умолчанию** для бинарей `veil-cli` / `ogate` / `oproxy` (`veil-cli` Cargo.toml: `default = ["rocksdb-cold", "tls-boring"]`); **библиотека** `veilcore` по умолчанию использует rustls (`default = ["rocksdb-cold"]`). Даёт Chrome-подобный отпечаток ClientHello (JA3/JA4) + ротацию — основной путь обхода DPI. Отключается через `--no-default-features`.
- **`TransportFingerprintMode`**: контроль TLS-fingerprint (ClientHello) — позволяет скрыть veil под Chrome/Firefox шаблон.
- **`TransportOperatingMode`**: Server / Client / Mixed.
- **`WebSocketHandshakeMode`**: legacy / extended.

### 4.3 Discovery транспортов

Транспорты объявляются в `TransportRegistry`. Реальный listener запускается через `listener_supervisor.rs`. При отказе listener'а supervisor рестартит его с бэкоффом.

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

Максимальный `body_len` = `MAX_FRAME_BODY = 16 MiB`. Конфигурируемый мягкий лимит на listener — `max_frame_body_bytes` (default 1 MiB).

### 5.2 Флаги

Биты в `flags`:

```
0..1  priority       0=RealTime, 1=Interactive, 2=Bulk, 3=Background
```

Другие биты зарезервированы и должны быть 0. Старые доки упоминают `encrypted` и `require_ack` как wire-флаги — это не так: шифрование — свойство сессии целиком; `require_ack` живёт в теле `DeliveryEnvelope`.

### 5.3 Семейства фреймов

[`proto/family.rs`](../../crates/veil-proto/src/family.rs), enum `FrameFamily`:

| ID | Family | Сообщения |
|----|--------|-----------|
| 0 | Session | Hello, Identity, Capabilities, KeyAgreement, SessionConfirm, Attach, Detach, Keepalive, RekeyInit/Ack, MlKemRekeyEk/Ack, Ticket, SleepAdvertisement, Padding, и варианты connection-handoff: HandoffInit(16), HandoffAck(17), HandoffAttach(18), HandoffChallenge(24), HandoffResponse(25). HandoffChallenge=24/HandoffResponse=25 — handoff wire v2 (challenge-response), пришедший на смену старой статичной HMAC поверх HandoffAttach=18 |
| 1 | Control | Ping/Pong, NeighborOffer, RouteProbe/Reply, Error, NatProbeRequest/Reply, NatRelayRequest, Keepalive(0x10)/Ack, EpidemicBroadcast(0x20), Backpressure(0x30) |
| 2 | Discovery | FindNode, FindValue, Store, Delete, AnnounceAttachment, GetAttachment, GetMailboxSet, GetAppEndpoint, FindNodeResponse, FindValueResponse |
| 3 | Delivery | MailboxPut/Fetch/Ack, Forward, DeliveryStatus, MailboxReplicate, MailboxFetchReplica, ChunkManifest, Chunk, Transit(0x10), RecursiveRelay(0x11) |
| 4 | App | AppOpen, AppData, AppClose, AppSend, AppReceipt, AppWindowUpdate, AppRtData |
| 5 | Mesh | Forward, Beacon, Ack |
| 6 | LocalApp | 22 типа IPC-сообщений (см. §18) |
| 7 | Tunnel | IpPacket — TUN/TAP инкапсуляция |
| 8 | Routing | RouteAnnounce/Withdraw, RouteRequest/Response, PowChallenge/Response/Accept, RouteAnnounceAliased/WithdrawAliased, RouteDiscover/Offer, RecursiveQuery/Response(0x10/0x11), RouteUpdate(0x12), VersionVectorSync(0x13) |
| 9 | Diag | Ping/Pong, TraceProbe, TraceHop |
| 10 | RelayChain | Hop — onion-encrypted chain |
| 11 | PeerExchange | Walk, Challenge, Response, Result |

Неизвестная `family` → `ProtoError::UnknownFamily`; неизвестный `msg_type` → `UnknownMsgType`. Диспетчер игнорирует такие фреймы (forward-compat).

### 5.4 Единый minor-версии

`OVL1_MINOR_VERSION = 1` (см. `proto/budget.rs`). Ранее были version-gate'ы на фичи, но все они активированы безусловно. Поле остаётся на wire для будущих нужд.

---

## 6. Session plane (handshake и шифрование канала)

### 6.1 Последовательность

OVL1-handshake инициируется клиентом. Фреймы не шифруются до `SessionConfirm`; после — все последующие фреймы в этой сессии шифруются ChaCha20-Poly1305.

```
Initiator                                        Responder
   │── Hello (magic "OVL1", version=1, node_id) ──→ │
   │ ←───────────── Hello (responder node_id) ──────│
   │── Identity (algo, pubkey, nonce, node_id, mlkem_ek?) ──→ │
   │ ←── Identity ───────────────────────────────────│
   │── Capabilities (role_bits, flags, frame_size) ──→ │
   │ ←── Capabilities ───────────────────────────────│
   │── KeyAgreement (X25519 ephemeral pubkey) ────→ │
   │ ←── KeyAgreement ───────────────────────────────│
   │          [HKDF-SHA256 → session keys]           │
   │── SessionConfirm (session_id, HMAC) ──────→ │
   │ ←── SessionConfirm ─────────────────────────────│
   │          [AEAD encrypted from here]             │
   │── Attach (опционально; leaf → core gateway) ─→ │
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

Pубкey всегда передаётся в сыром виде. Верификатор проверяет `BLAKE3(public_key) == node_id`.

### 6.4 CapabilitiesPayload (3 байта, wire v3)

```
[0]  roles_supported  u8  (битовая маска role_bits: bit0=leaf, bit3=core)
[1]  flags            u8  (cap_flags: CAN_RELAY=0x01, SUPPORTS_SOVEREIGN_IDENTITY=0x02,
                         ANONYMITY_RELAY=0x04, SUPPORTS_HYBRID_KEX=0x08)
[2]  discovery_mode   u8  (0=Public, 1=ContactsOnly)
```

Wire v3 убрал старую 12-байтную форму (`transports_sup`, `max_frame_size`, `max_streams`,
`ovl1_minor`); декодер также принимает 2-байтную форму (roles + flags), подставляя
`discovery_mode = Public`.

### 6.5 KeyAgreement + SessionKeys

Payload: `algo(1) + key_len(2) + X25519_pubkey(32)`.

X25519 — **ephemeral** ключ, генерируется заново на каждый handshake; не имеет
отношения к long-term identity (Ed25519 / Falcon-512). Это даёт forward
secrecy: компрометация identity не раскрывает прошлые сессии.

Оба узла вычисляют:

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

`tx_key` — для шифрования исходящих фреймов; `rx_key` — для расшифровки входящих.
Lex-order по `node_id` гарантирует, что инициатор и респондент получают зеркальные
назначения: `alice.tx == bob.rx` и наоборот. Отдельного `mac_key` нет — целостность
покрыта AEAD-tag'ом (`ChaCha20-Poly1305`) и handshake-MAC в `SessionConfirm`.

Реализация: [`crypto/session_kdf.rs::derive_session_keys`](../../crates/veil-crypto/src/session_kdf.rs).

### 6.6 SessionConfirm

```
[0..32]  session_id [u8; 32]
[32..64] mac        [u8; 32]
                    └ BLAKE3("ovl1-session-confirm-v1" ‖ shared_secret
                            ‖ small_node_id ‖ large_node_id)
```

`small`/`large` — лексикографически упорядоченная пара node_id'ов, чтобы обе
стороны получили одинаковый MAC независимо от того, кто отправил первым.
Реализация: [`node/session/handshake.rs::compute_confirm_mac`](../../crates/veil-session/src/handshake.rs).

MAC коммитит и shared_secret, и оба node_id; observer без X25519-секрета не может
подделать MAC даже при verbatim-replay'е handshake-сообщений. Получив валидный
`SessionConfirm`, обе стороны переключают канал на AEAD. `session_id`
используется дальше для `SessionTxRegistry` и для resumption ticket.

### 6.7 AEAD-защита

Алгоритм: **ChaCha20-Poly1305**.

- Nonce — 12 байт, монотонно возрастающий счётчик per-session. При переполнении (достижении порога) инициируется rekey.
- `body` фрейма шифруется; заголовок (24 Б) — в plaintext.
- `aad` = frame header (24 Б).

### 6.8 Rekey

Инициируется при превышении:

- `REKEY_BYTES_THRESHOLD = 128 GiB` переданных данных, либо
- `REKEY_TIME_THRESHOLD_SECS = 32 дня` (2 764 800 с), либо
- приближение счётчика nonce к переполнению.

Оба порога настраиваются через `[session] rekey_bytes_threshold` и
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

### 6.9 Ticket-резаминг

После успешного handshake сервер выдаёт `SessionTicket` (encrypted). Клиент может использовать его в TLV-расширении `HelloPayload` для быстрого восстановления сессии без полного handshake.

- `SESSION_TICKET_TTL_SECS = 3600` (1 час) — нормальный срок жизни.
- `SESSION_TICKET_MAX_AGE_SECS = 7200` — максимальный допустимый возраст (с grace-окном для clock skew).

### 6.10 Keepalive и hibernation

- `Keepalive` (Control, 0x10) / `KeepaliveAck` (0x11) — heartbeat каждые `session.keepalive_interval_secs`.
- Сессия без активности дольше `session.idle_timeout_secs` закрывается.
- `SleepAdvertisement` (Session, 13) — узел уведомляет mailbox-хосты о намерении уйти оффлайн; хосты продлевают retention до `expected_wake_ts + grace`.

### 6.11 ML-KEM rekey

`MlKemRekeyEk` / `MlKemRekeyAck` — передача новой публичной encapsulation-key для E2E. Позволяет ротировать долгоживущий ML-KEM ключ без перезапуска узла.

### 6.12 Padding

`SessionMsg::Padding` (14) — no-op фрейм со случайным телом. Используется, чтобы на уровне TLS-рекордов реальные фреймы были выровнены до MTU, усложняя passive traffic analysis.

---

## 7. E2E-шифрование

Файл: [`proto/e2e.rs`](../../crates/veil-proto/src/e2e.rs).

### 7.1 Маркеры в `DeliveryEnvelope.payload`

| Первый байт | Константа | Смысл |
|-------------|-----------|-------|
| `0xE2` | `E2E_MARKER` | Обычное E2E: `sender_node_id` в plaintext, payload зашифрован |
| `0xE3` | `META_E2E_MARKER` | Meta-E2E (onion): отправитель скрыт; `sender_node_id = [0; 32]` на wire |
| любой | (без маркера) | Plain-text delivery (только с explicit opt-in) |

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

Релей видит только `E2eEnvelope` — без секретного ключа получателя расшифровать не может.

### 7.4 Управление ключами

- **Публикация `ek`:** при `bind`-е прикладного эндпоинта нода публикует `AppEndpointResponse` в DHT (см. §9), где ek встроен в запись.
- **Хранение `dk`:** в конфиге (base64 seed 64 Б); ротация через `MlKemRekeyEk` в активной сессии.
- **Кеш ек пиров:** `peer_mlkem_keys` хранит до `MAX_PEER_MLKEM_CACHE = 4096` ключей с TTL `ipc.e2e_key_ttl_secs` (default 3600 с).

### 7.5 Meta-E2E (onion)

В meta-E2E шифруется не только payload, но и сам `DeliveryEnvelope` (поля `sender_node_id`, `src_app_id`, `app_id`, `endpoint_id`). Релеи видят только `recipient_node_id` и `ttl/created_at`. Пригодно для анонимной отправки (`AppIpcSend` с flag=anonymous).

---

## 8. Discovery: DHT (Kademlia)

Файл: [`crates/veil-dht/src/`](../../crates/veil-dht/src/).

### 8.1 Параметры

| Константа | Значение | Источник |
|-----------|----------|----------|
| `K` | 20 | `dht/routing.rs::K` |
| `ALPHA` | 3 | `dht/iterative.rs::ALPHA` |
| `MAX_ROUNDS` | 20 | `dht/iterative.rs::MAX_ROUNDS` |
| MAX per /24 subnet в bucket | K/4 = 5 | `dht/routing.rs` (антиEclipse) |

### 8.2 Routing table

- 256 k-buckets (по одному на бит XOR-расстояния).
- Каждый bucket — `VecDeque<Contact>` ёмкостью `K`.
- LRU: недавно viden-ый контакт — в хвосте.
- При попытке вставить контакт в полный bucket выполняется ping самого старого; если тот отвечает — новый отбрасывается.

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

`find_value_iterative` аналогично, но при первом ответе типа `FindValueResponse::Value(v)` сразу возвращает значение.

### 8.5 Sharding и tiered storage

**Sharding.** `shard_id = key[0]`; каждый узел покрывает 16 ближайших шардов из 256. `DhtConfig.shard_filtering = true` отбрасывает STORE'ы, попавшие не в свой shard.

**Tiered storage.** Два уровня:
- **Hot** — `HashMap<key, value>` ограниченного размера, быстрый доступ.
- **Cold** — по умолчанию больший in-memory `HashMap` с LRU-promotion при доступе. Опционально cold-уровень может быть дисковым хранилищем RocksDB — включается через `[dht] cold_store_path` (за cargo-feature `rocksdb-cold`, ON по умолчанию для `veil-cli`/`veilcore`). Это снимает потолок ёмкости с RAM (>1M записей) и переживает рестарты. Если `cold_store_path` не задан, feature отсутствует или RocksDB не открылся — узел откатывается на in-memory cold-уровень (со строкой лога).

Overflow hot → demote в cold; overflow cold → eviction.

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

Подпись покрывает префикс `[0..53+body_len]`.

### 8.7 DHT-операции

Обрабатывается в `KademliaService` ([`dht/kademlia.rs`](../../crates/veil-dht/src/kademlia.rs)).

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

Подпись — Ed25519 над `key || value`. Core-узел вставляет в хранилище; Leaf отклоняет (`KademliaError::NotAllowed`).

#### Delete

Требует подтверждения владения ключом.

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
3. `BLAKE3(public_key) == key` — self-owned only.

Политика «только self-owned» покрывает `node_id`-ключи. Для mailbox/app_endpoint-ключей DELETE сейчас не инициируется.

#### FindNode / FindValue

```
FindNodePayload:     target[32] + k[2]
FindNodeResponse:    count[2] + NodeContact[]
FindValuePayload:    key[32]
FindValueResponse:   либо Value(bytes), либо Nodes(contacts[])
```

`NodeContact`: `node_id[32] + transport_len[2] + transport_uri[bytes]`.

### 8.8 Защита DHT

| Атака | Митигация |
|-------|-----------|
| Sybil на bucket | PoW ≥ 24 на node_id |
| Eclipse /24 | Max `K/4 = 5` контактов из одного /24 IPv4 (или /48 IPv6) в bucket |
| Poisoning | `DhtValue.expires_at` + подпись владельцем |
| DELETE abuse | Signature + `BLAKE3(pk) == key` |
| Seed dedup O(n²) | HashSet-дедуп в итеративном lookup |
| Flooding STORE | Shard-фильтрация (опционально) |

---

## 9. Discovery: сервисные записи

Надстройки над DHT, все хранятся как `DhtValue` с разными `kind`:

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

Ключ в DHT — `attachment_key(leaf_node_id)`. Используется для поиска: чтобы связаться с Leaf, сначала `GetAttachment(leaf_id)` → Core-узлы, через которые он принимает трафик.

### 9.2 GetAttachment / AttachmentResponse

Запрос-ответ: по node_id вернуть список gateway/mailbox.

### 9.3 MailboxSet и GetMailboxSet

`MailboxSet` — список node_id'ов, хранящих реплики mailbox для узла `X`. Помогает offline-доставке.

```
GetMailboxSetPayload:  target_node_id[32] + epoch[4]
MailboxSetResponse:    count[2] + node_id[32][]
```

### 9.4 AppEndpoint и GetAppEndpoint

Привязка `(node_id, app_id, endpoint_id) → ML-KEM ek`. Каждое приложение, объявляющее bind, публикует запись:

```
GetAppEndpointPayload:   node_id[32] + app_id[32] + endpoint_id[4]
AppEndpointResponse:     (variable) содержит адрес + ek + срок + подпись
```

### 9.5 Name service

Пользовательские имена → node_id. Заявка на имя подписывается владельцем и записывается в DHT под ключом `name_key(name)`. Резолвер проверяет подпись и цепочку PoW напрямую из DHT (никаких `NameContested`-уведомлений).

---

## 10. Routing

Файл: [`crates/veil-routing/src/`](../../crates/veil-routing/src/) + [`node/dispatcher/routing.rs`](../../crates/veil-dispatcher/src/routing.rs).

### 10.1 Три уровня

1. **Gossip** — `ROUTE_ANNOUNCE/WITHDRAW` с TTL=2, узкий радиус (соседи).
2. **DHT-forwarding** — `RecursiveRelay` для доставки сообщений через Kademlia.
3. **On-demand** — `ROUTE_REQUEST/RESPONSE` для явного получения транспортов.

### 10.2 Route cache

`RouteCache` ([`routing/cache.rs`](../../crates/veil-routing/src/cache.rs)):

- Ключ: `dst_node_id`.
- Значение: набор путей (`next_hop`, score, TTL, hop_count).
- **Адаптивная ёмкость**: `MAX_ROUTE_CACHE_SIZE = 1024` baseline; при больших сетях масштабируется.
- `MAX_ROUTES_PER_DST = 4`, `MAX_ROUTES_PER_VIA = 256`.
- TTL-based eviction + LRU при переполнении.

### 10.3 Scoring

Комбинированная оценка пути (`RouteCache::score`):

```
score = w_rtt * rtt_ms
      + w_jitter * jitter
      + w_vivaldi * distance   // virtual coords
      + w_congestion * cong
      - w_battery * battery    // Leaf considerations
      - w_reputation * rep
```

Веса параметризуются в конфиге (`routing.weights`).

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

**Дедуп и replay-protection:**
- `MAX_ROUTE_ANNOUNCE_AGE_SECS = 300` — фреймы старше отклоняются.
- `MAX_ROUTE_ANNOUNCE_SKEW_SECS = 30` — допустимый разрыв по часам.
- Двухслойный дедуп: per-`(origin, via, seq)` + per-`(origin, seq)`.

`RouteWithdraw` — аналогично, но сбрасывает записи. Monotonic `sequence` обязателен (anti-replay).

### 10.5 Aliased announce

`RouteAnnounceAliased` / `RouteWithdrawAliased` используют 8-байтные session aliases вместо 32-байтных node_id — экономия ширины канала gossip'a для коротких локальных сессий.

### 10.6 Recursive routing

Когда route cache miss и прямой сессии до `dst` нет:

```
RecursiveRelayPayload:
[0..32]  dst_node_id
[32..64] originator_id
[64..68] query_id (u32BE — дедуп токен)
[68]     hop_count (убывает каждый hop, старт = 20)
[69..]   wrapped ForwardPayload body
```

Узел, получив RecursiveRelay:

1. Если `hop_count == 0` → положить в mailbox `dst_node_id` (fallback).
2. Если есть live-сессия к `dst` → распаковать и доставить локально (deliver).
3. Иначе — найти XOR-ближайшего пира к `dst` среди DHT-соседей, переслать с `hop_count - 1`.

**Reverse-path caching:** успешная доставка через узел X вставляет `originator_id → X` в route cache получателя — следующие ответы идут direct.

### 10.7 Route request/response

Явный запрос: «кто знает транспорт для `target`». `RouteRequestPayload` содержит ML-KEM ek запрашивающего (чтобы ответ можно было зашифровать E2E), Ed25519 pk и signature.

Ответ:

```
RouteResponsePayload:
target[32], requester[32], request_id[4]
transports[] (до 32 URI, MAX_TRANSPORT_ADDRS=32)
relays[]     (до 32 node_id, MAX_RELAY_IDS=32)
mlkem_pk, ed25519_pk, signature
```

### 10.8 PoW bootstrap

`PowChallenge` / `PowResponse` / `PowAccept` — для узлов без общих знакомых:

- Запрашивающий отправляет FindNode, bootstrap отвечает PoW challenge.
- Решение требует `leading_zero_bits(BLAKE3(challenge || solution)) ≥ difficulty`.
- После успеха — `PowAccept` с транспортом.

### 10.9 Event-driven updates

- `RouteUpdate` (0x12) — push при connect/disconnect соседа.
- `VersionVectorSync` (0x13) — периодическая синхронизация VV для сверки состояния.

---

## 11. Delivery

Файл: [`crates/veil-dispatcher/src/delivery.rs`](../../crates/veil-dispatcher/src/delivery.rs).

### 11.1 DeliveryEnvelope

```
[0..32]    recipient_node_id
[32..64]   sender_node_id
[64..96]   src_app_id
[96..128]  app_id          (получателя)
[128..132] endpoint_id     u32BE
[132..164] content_id      (BLAKE3 of payload)
[164..172] created_at      u64BE  (unix seconds)
[172..176] ttl_secs        u32BE
[176..180] payload_len     u32BE
[180..]    payload         bytes
```

Плюс два 1-битных флага (переданных отдельно): `require_ack`, `trace_id`.

### 11.2 Пути доставки

**Путь A — прямой.** Есть живая сессия к `recipient_node_id` — отправляется напрямую.

**Путь B — route cache.** Промах по прямой сессии, но в кеше есть запись «для `recipient_node_id` next_hop = X» → Forward к X.

**Путь C — RecursiveRelay.** Ни сессии, ни кеша — строится `RecursiveRelayPayload`, отправляется XOR-ближайшему из DHT-таблицы.

**Путь D — Mailbox.** Hop exhausted или recipient офлайн → оседает в mailbox(ах).

### 11.3 Forward

`ForwardPayload` = `DeliveryEnvelope.encode()`. Получатель узнаёт себя по `recipient_node_id` и локально доставляет приложению.

### 11.4 Transit

Stateless relay: `TransitFramePayload` без per-flow состояния. Позволяет быстро форвардить пакеты без сохранения сессии до origin. Minor ≥ 5 (сейчас всегда enabled).

### 11.5 Chunked transfers

Большие payload (> frame size):

```
ChunkManifestPayload (92 Б):
  content_id[32], total_size[8], chunk_count[4], chunk_size[4],
  first_chunk_offset[4], sig_len[4], signature[up to 32]

ChunkPayload (20 Б header + data):
  content_id[32 — в hdr], chunk_index[4], offset[8], data_len[2], data[]
```

Получатель алоцирует `ReassemblyState` по manifest, накапливает chunk'и, пересобирает payload.

### 11.6 Delivery status

`DeliveryStatusPayload` (65 байт, фиксированный размер):

```
[0..32]  content_id
[32]     status u8
         0 = OK / QUEUED
         1 = NOT_FOUND
         2 = FAILED / REJECTED
         3 = DUPLICATE
         4 = TTL_EXPIRED
[33..65] mac [u8; 32]   (C-09 — аутентифицированный ACK; см. ниже)
```

**C-09 — аутентифицированный DELIVERED ACK.** `mac` — это BLAKE3 keyed-MAC от
`content_id` под per-message ключом доставки-ACK, который обе стороны выводят из
общего E2E-секрета ML-KEM (`veil_e2e::derive_ack_key`). Транзитный релей
никогда не узнаёт этот секрет, поэтому валидный MAC может построить только
настоящий получатель — и отправитель начисляет репутацию за доставку **только**
при успешной проверке MAC. Если ACK-ключ не был установлен (не-E2E / legacy
доставка), поле нулевое: отправитель снимает pending-запись, но репутацию не
начисляет. См. `handle_delivery_status` в
`crates/veil-dispatcher/src/delivery.rs`.

### 11.7 5-stage delivery FSM

На стороне отправителя (IPC-client):

```
Accepted → Stored → Fetched → Delivered → AppAcked
```

Клиент получает уведомления через `LocalAppMsg::DeliveryStage` — может показать статус «в пути» / «доставлено» / «прочитано».

---

## 12. Mailbox (offline-доставка)

Файл: [`crates/veil-mailbox/src/`](../../crates/veil-mailbox/src/).

### 12.1 Модель

`MailboxService` принимает от Core-узлов:
- **PUT** — положить `DeliveryEnvelope` для офлайн-recipient'а.
- **FETCH** — получатель онлайн, забирает своё (`after_seq` cursor).
- **ACK** — подтверждение прочитанных seq'ов.

Leaf не хранит mailbox (`MailboxError::NotAllowed`).

### 12.2 Backend

Mailbox — фиксированный **redb**-KV по пути `<veil_dir>/mailbox/blobs.db` (сериализуемые транзакции). Движок не выбирается — ключа `backend` нет; mailbox включается через `[mailbox] enabled = true`. Реализация: [`crates/veil-mailbox/src/lib.rs`](../../crates/veil-mailbox/src/lib.rs).

### 12.3 Квоты и лимиты

Из [`crates/veil-mailbox/src/lib.rs`](../../crates/veil-mailbox/src/lib.rs) и `crates/veil-proto/src/budget.rs`:

| Параметр | Значение |
|----------|----------|
| Global cap | 100 000 записей (баномический лимит) |
| Per-recipient cap | конфиг; default 1000 |
| Per-sender daily quota | `DEFAULT_MAX_MAILBOX_SENDERS` обёртывает set |
| `MAX_MAILBOX_ACK_BATCH` | 256 seq'ов за batch |
| `MAX_MAILBOXES` | 32 mailbox-reference в attachment |

При переполнении — новый PUT отклоняется (`status=REJECTED`), а не eviction старых (предотвращает race-based eviction атаки на сохранность данных).

### 12.4 Как определяются узлы-хранители

Идея: ни отправителю, ни получателю не нужно заранее знать конкретные
mailbox-хосты. Оба независимо выводят их из `recipient_node_id` через DHT.

#### Primary (attachment gateway)

Получатель при подключении объявляет свой набор gateway'ев через
`AnnounceAttachmentPayload`, подписанный его identity-ключом. Запись
оседает в DHT под ключом `attachment_key(recipient_node_id)`.

Отправитель, у которого нет прямой сессии до получателя:

1. `GetAttachment(recipient_node_id)` → список gateway'ев.
2. Устанавливает сессию к одному из них (priority-order по weight/flags).
3. Шлёт `MAILBOX_PUT` с `DeliveryEnvelope` внутри.

#### Replicas (детерминированный DHT-выбор)

Primary, приняв PUT, выбирает до `replica_count - 1` дополнительных
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

Ключевое свойство — **детерминизм**: `shard_target` и XOR-ближайшие к нему
узлы не зависят от точки наблюдения. Любой Core-узел в сети, зная
`recipient_node_id`, вычислит тот же target и через свой DHT найдёт тот же
набор кандидатов (с точностью до liveness-фильтров). Поэтому *получатель*
и *произвольный future-gateway* найдут те же реплики без дополнительного
обмена адресами.

Шардирование `shard_id` позволяет разбить backlog одного
получателя на несколько независимых наборов реплик: `shard_id=0, 1, 2 …`
→ разные `shard_target` → разные реплики. Это уменьшает correlated-failure
risk для крупных mailbox'ов. На сегодня используется один shard (`shard_id=0`).

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

При `replica_count = 1` replica-шаг пропускается — PUT живёт только на primary.

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
Primary удаляет подтверждённые seq'ы локально; Ack-шаг на реплики идёт
лениво — реплики GC-ят по TTL.

**Почему это безопасно:**
- Только аутентифицированный получатель может fetch'нуть (проверка
  `recipient_node_id == peer_id`).
- Только первоначальный отправитель знает `sender_node_id` в envelope
  (проверка в `MAILBOX_PUT::handle_put`).
- Реплики видят envelope зашифрованным (см. §12.6) — не могут читать
  payload, даже если их компрометировать.

### 12.6 Envelope encryption для реплик

Replica-хосту не нужно знать содержимое — envelope шифруется прямо перед `MAILBOX_REPLICATE`:

```
encrypted_blob = ChaCha20-Poly1305.Seal(
    key  = HKDF(primary_mlkem_dk, info="replica-v1"),
    aad  = recipient_node_id || seq,
    plaintext = DeliveryEnvelope.encode()
)
```

Replica хранит blob; при fetch primary расшифровывает обратно.

### 12.7 WAL-структура

Строки append-only:

```
magic[4] + version[1] + op_type[1] + len[4] + body[len] + crc32[4]
```

`op_type`: Put, Ack, Compact. При старте — replay в текущее состояние. При `wal_size > compact_threshold` (default 64 MiB) — compaction: снепшот активных записей, старый WAL удаляется.

---

## 13. Peer Exchange (PEX)

Файл: [`crates/veil-pex/src/`](../../crates/veil-pex/src/). Family 11.

### 13.1 Задача

Получить новые транспорт-адреса peers для установления прямых соединений (вместо multi-hop через relay). Работает по модели **random-walk + PoW**.

### 13.2 Протокол (4 фрейма)

1. **Walk** (originator → seed). Содержит `walk_id`, `origin_pubkey`, `origin_nonce`, TTL, signature.
2. **Challenge** (terminator → originator). PoW challenge с требуемой difficulty.
3. **Response** (originator → terminator). Решение PoW + `origin_sig` (Ed25519 или Falcon512 — multi-algo через `verify_message`).
4. **Result** (terminator → originator). Список peer-записей (node_id + transport URIs).

### 13.3 Подпись

Полная поддержка Ed25519 + Falcon512 в `verify_origin_sig`:

```rust
let algo = if pubkey.len() == 32 {
    SignatureAlgorithm::Ed25519
} else {
    SignatureAlgorithm::Falcon512
};
verify_message(algo, pubkey_b64, msg, signature)
```

### 13.4 Параметры

- `pex.walk_interval_secs` — как часто узел инициирует walk.
- `pex.max_hops` — TTL random-walk.
- PoW difficulty — через `AdaptiveParams` (меньше, чем identity PoW — он per-walk, не per-node).

---

## 14. Mesh (локальная UDP-сеть)

Файл: [`crates/veil-mesh/src/`](../../crates/veil-mesh/src/). Family 5.

### 14.1 Сценарий

IoT-устройство / узел без интернета может:
- Обнаружить соседей локально через UDP multicast/broadcast.
- Передать сообщение через mesh-bridge (Core с `CAN_GATEWAY_LOCAL_MESH`) в глобальный veil.

### 14.2 MeshBeacon

```
MESH_BEACON_SIZE = 48 + extension
[0..32]  node_id
[32..48] realm_id (UUID)
[48..]   extension (v2):  transport_count + transport_len + transport_uri + algo + pubkey + sig
```

Отправляется с интервалом `DEFAULT_BEACON_INTERVAL` (30 с). TTL в `BEACON_WINDOW = 60 с` — устаревший beacon удаляется из кеша соседей.

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

Форвардится в пределах realm'а через `MeshForwarder`.

### 14.4 Realm

`Realm` — логическая группа mesh-узлов (UUID). Один физический сегмент может содержать несколько realm'ов; узлы игнорируют чужие beacons.

### 14.5 Gateway bridge

Core с `CAN_GATEWAY_LOCAL_MESH`:
- На mesh-стороне слушает UDP beacons / mesh frames.
- Доставку сообщения из mesh в veil: извлекает `DeliveryEnvelope` из `MeshFrame.payload`, подаёт в свой dispatcher.
- Из veil в mesh: при `recipient_node_id` известного mesh-peer'а упаковывает в `MeshFrame` и шлёт по UDP.

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

Из `NatCandidate` (RFC 8445-подобные):

- `HOST` — локальный интерфейс (high priority: `type_pref=126`).
- `SRFLX` — server-reflexive (STUN-echo от Core: `type_pref=100`).
- `RELAY` — relay-tunnel через Core (`type_pref=0`).

Приоритет:
```
priority = (2^24 * type_pref) + (2^8 * local_pref) + (256 - component_id)
```
С saturating-арифметикой ([`nat/coordinator.rs::ice_priority`](../../crates/veil-nat/src/coordinator.rs)).

### 15.3 Обмен

```
Alice → Core:  NatProbeRequest(session_token, Alice_candidates)
Core → Bob:    NatProbeRequest с Alice_candidates
Bob → Core:    NatProbeReply(Bob_candidates)
Core → Alice:  NatProbeReply с Bob_candidates
Alice ↔ Bob:   QUIC connect на все кандидаты параллельно
```

`NatPuncher::punch` параллельно пробует все пары candidates в течение `punch_timeout_ms`; первый успешный handshake — `PunchResult::Direct(conn)`.

### 15.4 Relay fallback

Если `PunchResult::TimedOut`:

```
Alice → Core: NatRelayRequest(Alice, Bob, session_token)
Core opens ForwardTunnel(Alice ↔ Bob, token=session_token)
```

Core форвардит `DeliveryMsg::Forward` между ними.

### 15.5 Local relay

Если нет global Core, но есть локальный Gateway с `IS_RELAY` во flags mesh-beacon'а, `NatCoordinator::preferred_signal_peer` возвращает его:

```
priority: local_relay > global_core > None
```

`LOCAL_RELAY_TIMEOUT_SECS = 3` — сколько ждать local relay перед fallback на Core.

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

- Token bucket per peer (refill rate, burst size из конфига).
- Drop при exhaustion — инкрементирует violation counter.
- `MAX_PER_PEER_LIMITER_SIZE = 8192` — глобальный cap на трекаемых пиров.

### 16.3 Violation tracker

`MAX_VIOLATION_TRACKER_SIZE = 8192`. Категории violation:
- `BadFrame` — невалидный wire-формат.
- `SenderMismatch` — envelope's sender ≠ authenticated peer.
- `PoWFail` — неверное решение.
- `RateExceeded` — token bucket empty.
- и др.

После `VIOLATION_THRESHOLD = 5` в окне `VIOLATION_WINDOW_SECS = 300` — ban.

### 16.4 Ban list

`MAX_BAN_LIST_SIZE = 8192`. TTL из конфига (`abuse.default_ban_secs`). Persistence — `bans.json` в data-dir.

### 16.5 Congestion backpressure

`node/congestion.rs`:

- Метрика: `load_pct = (cpu_usage * 0.5) + (memory_usage * 0.3) + (queue_depth * 0.2)`.
- **>50%** — halve adaptive fan-out.
- **>78%** — дропать TRANSIT/RECURSIVE_RELAY фреймы; обычная доставка продолжается.
- Активное уведомление: `Backpressure` control-frame — просит пира снизить rate.

### 16.6 Reputation

[`node/reputation.rs`](../../crates/veil-reputation/src/lib.rs):

- Начальный score: 0.
- Uptime: +1 / час.
- Successful relay: +0.1.
- Failed relay: -1.
- Peer vouch (`ReputationAttestation`): +5.
- Transit gate: `MIN_REPUTATION_FOR_TRANSIT = 200.0`.

Новые узлы не могут сразу форвардить чужой трафик (cold-start).

### 16.7 PoW challenge на connection

Опционально для защиты handshake:

```
Server → Client: PowChallenge(challenge_nonce[32], difficulty)
Client → Server: PowResponse(solution) где BLAKE3(challenge||solution) имеет ≥ difficulty нулевых битов
```

Ограничения:
- `MAX_POW_DIFFICULTY = 24` — server не может потребовать больше.
- `MAX_CONCURRENT_POW_SOLVERS = 4` — ограничение client-side параллелизма.

---

## 17. Адаптивные параметры

Файл: [`crates/veil-cfg/src/adaptive.rs`](../../crates/veil-cfg/src/adaptive.rs).

### 17.1 Оценка размера сети

Узел оценивает `N` (кол-во узлов в сети) по:

1. Своей DHT-таблице: количество bucket-ов с ≥ 1 контакт.
2. `EpochDifficultyRecord` из DHT (публикуется bootstrap-узлами).
3. FindNode-ответам (из размера возвращаемых списков).

### 17.2 Масштабируемые параметры

| Параметр | Формула | Min | Max |
|----------|---------|-----|-----|
| PoW difficulty | `24 + ceil(log2(N / 100_000))` | 24 | — |
| Fan-out (epidemic) | `ceil(log2(N))` | 2 | 16 |
| DHT α (параллелизм) | 3 при N < 100k, 4 при N ≥ 1M | 3 | 5 |
| Route cache size | `1024 + N / 1000` | 1024 | 65536 |
| Mailbox cap | `100_000` | — | — (жёсткий) |
| Ban TTL | `60 * 60 * (1 + log10(N))` | 1 час | 24 часа |

### 17.3 Sync

`AdaptiveParams` периодически обновляется в `NodeRuntime::tick`; изменения применяются lazily — текущие сессии не прерываются.

---

## 18. App layer и IPC

### 18.1 Модель

Приложение (клиент CLI, пользовательский бот, GUI) работает:

```
App process ──Unix socket (JSON-L / binary)──► veild (node)
                                                   ↓
                                               OVL1 network
```

Socket по умолчанию: `/run/veil/ipc.sock` или `$XDG_RUNTIME_DIR/veil/ipc.sock`.

### 18.2 Address: AppAddress

```
AppAddress {
    node_id:     [u8; 32],   // Какой узел держит приложение
    app_id:      [u8; 32],   // derive_key("veil.app_id.v1", node_id || ns_len(4) || ns
                             //            || name_len(4) || name) — см. §1.2 protocol-spec
    endpoint_id: u32,        // "Порт" внутри приложения (1..65535)
}
```

**namespace** и **name** — UTF-8 строки выбора разработчика (convention: reverse-DNS
вида `"com.example.chat"` + `"main"`); до 255 байт каждая. Length-prefix + domain
separator (`"veil.app_id.v1"`) — защита от concat-shift коллизий, где разные
`(namespace, name)` давали одинаковый digest.

Для IPC-приложений дефолтный bind — **ephemeral**: нода подмешивает 16-байтный
`client_token` (выдан в `AppHelloOk`) + отдельный domain separator
(`"veil.ephemeral_app_id.v1"`), так что два процесса на одном узле получают
разные `app_id` при одинаковых `(namespace, name)`. Для well-known сервисов
(`bind_named`) — стабильная форма без токена.

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

На veil-стороне приложения общаются через:

- `AppOpen(app_id, endpoint_id, initial_window)` — установить поток.
- `AppData(data, ack?)` — данные.
- `AppWindowUpdate(bytes)` — flow-control.
- `AppClose(reason)` — закрытие.
- `AppRtData` — real-time frame (REALTIME priority, no ACK).
- `AppReceipt` — подтверждение доставки.

### 18.5 Anycast

Разрешение service-name → любой node_id, bind'нувший эндпоинт с таким именем:

```
Client → Node: AnycastResolve(service_name)
Node: ищет в DHT по anycast_key(service_name) → получает candidate-список → выбирает closest
Node → Client: AnycastResult(node_id + endpoint)
```

### 18.6 E2E в IPC

Клиент может флагом `encrypt: true` в `AppIpcSend` запросить E2E. Нода:

1. Получает ML-KEM ek получателя из DHT (`GetAppEndpoint`).
2. Оборачивает payload в `E2eEnvelope` с маркером `0xE2`.
3. Упаковывает в `DeliveryEnvelope` и отправляет.

Флаг `anonymous: true` → `META_E2E_MARKER (0xE3)` — sender скрыт.

---

## 19. Наблюдаемость

### 19.1 Prometheus metrics

Endpoint: `GET /metrics` на `metrics.listen` из конфига (путь по умолчанию `/metrics`,
переопределяется `metrics.path`).

Все метрики — в [`observability.rs::render_prometheus`](../../crates/veil-observability/src/lib.rs) с префиксом `veil_`.
Основные группы (полный список — см. [admin-guide.md](admin-guide.md#доступные-счётчики)):

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

Формат по умолчанию — структурированный text-lines:

```
[timestamp] LEVEL event.name field1=val1 field2=val2 ...
```

JSON-L опционально через конфиг `logging.format = "json"`.

Уровни: ERROR, WARN, INFO, DEBUG, TRACE. Фильтрация через `RUST_LOG` или `logging.filters`.

### 19.3 Debug capture

CLI: `veil-cli debug capture --output FILE` — JSON-поток фреймов в on-the-wire порядке. Поддерживает `--node-id HEX`, `--family N`, `--limit N` для фильтрации.

### 19.4 DiagPing / TraceRoute

Family 9 (Diag):

- `DiagPing/DiagPong` — end-to-end RTT probe через veil.
- `TraceProbe/TraceHop` — hop-by-hop traceroute. Каждый hop декрементирует TTL, при `TTL=0` отправляет `TraceHop` обратно с собственным `node_id`.

### 19.5 Trace buffer

In-memory ring buffer последних `TRACE_BUFFER_SIZE = 1024` dispatch-событий. Используется внутри рантайма; отдельной admin-команды на чтение нет — состояние наблюдается через метрики и `veil-cli debug capture`.

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

Clone-cheap: всё за `Arc`.

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

`DispatchResult`:
- `NoResponse` — обработано, ответ не требуется.
- `Reply(bytes)` — отправить ответный фрейм.
- `Violation(reason)` — инкремент violation counter, возможно disconnect.
- `Disconnect(reason)` — закрыть сессию.

### 20.4 SessionRunner

[`node/session/runner.rs`](../../crates/veil-session/src/runner.rs): одна async-task на сессию. Её задачи:

1. Читать байты из транспорта.
2. `decode_header` → `FrameHeader`.
3. Если `body_len > MAX_FRAME_BODY` → violation, disconnect.
4. AEAD-decrypt body.
5. Передать в `dispatcher.dispatch` (sync call, без await).
6. Получить `DispatchResult`, обработать (Reply/Disconnect/...).

Отправка исходящих — через `SessionTxRegistry`:
- Per-session **WRR scheduler** по 4 приоритетам (RealTime w=8, Interactive w=4, Bulk w=2, Background w=1).
- Out-queue защищён от переполнения: при `len > MAX_QUEUE_DEPTH` (default 1000) — оtherwise frame dropped или backpressure.

### 20.5 Шаблоны блокировок

- Все shared состояния — за `Arc<Mutex<_>>` или `Arc<RwLock<_>>`.
- Конвенция: **никаких nested locks** — замок берётся, обрабатывается, отпускается. Это предотвращает deadlock'и.
- Hot paths (dispatch) не содержат `.await` внутри lock'а.
- Атомарные счётчики (`Arc<AtomicU64>`) для метрик.

### 20.6 Admin interface

Unix socket из `global.admin_socket` (конфигурируется как `unix:///path`).
JSON-over-UDS протокол, обёрнутый в CLI `veil-cli`. Ключевые подкоманды:

- `node show` — общее состояние (uptime, sessions, роль).
- `node health` — tick-счётчик + session count + loop status.
- `node metrics` — снапшот всех счётчиков/gauge'ов.
- `node listens` — активные listener'ы; `node routes` — route cache.
- `node dht list / get KEY / put KEY VALUE / routing` — DHT-интроспекция и ручное изменение.
- `node discovery-list`, `node gateway-list` — attachment / gateway-записи.
- `sessions list / kill LINK_ID` — активные сессии.
- `peers list / add / del / ban / unban / banned` — управление пирами и банами.
- `debug ping / trace / capture / peers connect / node accept` — диагностика.
- `node stop / restart / reload` — управление жизненным циклом.

Полный список подкоманд — `veil-cli --help` и [admin-guide.md](admin-guide.md).

### 20.7 Конфигурация

[`docs/config-reference.md`](config-reference.md) — полная таблица опций.

Формат: TOML (путь из `veil-cli config locate`). Ключевые секции:

- `[global]` — `admin_socket`, `runtime_flavor`, логирование (`logs`, `log_file`, `log_level`, `log_format`).
- `[Identity]` — `algo`, `public_key`, `private_key`, `nonce`, `node_id`, `names[]`.
- `listen = [...]` / `peers = [...]` — на верхнем уровне (не секции), транспортные listeners и статические peers.
- `[dht]` — `k`, `alpha`, `vivaldi_weight`, `shard_filtering`, `max_store_entries`, `cold_store_path` (дисковый RocksDB cold-уровень, за feature `rocksdb-cold`).
- `[routing]` — gossip / cache-параметры, включая `vivaldi_persist_path`.
- `[session]` — `keepalive_interval_secs`, `idle_timeout_secs`, `rekey_bytes_threshold`, `rekey_time_threshold_secs`.
- `[mailbox]` — `enabled`, квоты (`quota_per_receiver_bytes`/`quota_global_bytes`/`quota_per_sender_bytes`), `ttl_secs`, `require_capability_token`; хранилище — фиксированный redb-KV (без выбора `backend`).
- `[abuse]` — `rate_limit_fps`, `ban_threshold`, `pow_min_difficulty`.
- `[nat]` — параметры hole-punch, STUN.
- `[mesh]` — beacon/realm параметры.
- `[pex]` — random-walk discovery.
- `[ipc]` — путь Unix-сокета для локальных приложений.
- `[proxy]` — SOCKS5-exit.
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
